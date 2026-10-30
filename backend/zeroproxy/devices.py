"""客户端设备注册表 (路由器 / 手机 / 电脑)。

面板上「客户端」那一页的背后逻辑: 设备怎么配对、怎么自证身份、怎么报告状态,
以及面板怎么把「总开关」下发给它们。

设计要点
--------
1. **主订阅令牌不上设备**。安装命令里带的是一次性配对码 (30 分钟有效, 用掉即废);
   设备拿它换一个只属于自己的 `device_id + secret`, 之后所有请求都用这对凭据。
   路由器长期在线、命令会留在 shell 历史与终端输出里, 让它持有 master token 等于
   把整个账号交出去 —— 而且泄露之后你无法只吊销那一台。
   secret 只在配对响应里出现一次, 服务端只存 sha256 (state.json 0600, 但备份文件
   会离开这台机器, 明文凭据不该躺在里面)。

2. **开关是"期望状态", 不是按钮动画**。面板写 `desired`, 设备轮询 `/c/report` 拿到
   它并回报 `actual`。面板显示的颜色取自 `actual` —— 所以"显示已连接"永远意味着
   路由器真的连上了, 而不是前端点了一下变绿。

3. **配置版本用内容哈希, 不用计数器**。`config_rev()` 把影响订阅内容的字段做一次
   哈希: 节点启停 / 端口变更 / 分流模板 / 链路变化都会改变它, 心跳写盘不会。
   设备据此判断"要不要重新拉配置" —— 计数器得在每个改动点手动 +1, 迟早漏掉一处。
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import time
from urllib.parse import urlsplit

#: 配对码有效期 (30 分钟)。安装命令会出现在终端回滚、聊天记录、截图里, 所以它必须是
#: 一次性的; 有效期只是给"复制命令 → 去路由器粘贴"这段操作留出余量。
PAIR_TTL = 30 * 60
#: 同时保留的未使用配对码上限 (每点一次「生成安装命令」多一个)
MAX_PAIR_CODES = 6
#: 可接入的设备数上限 (含手机/电脑)。够家用, 又不至于让一台面板被当成公共订阅源。
MAX_DEVICES = 32
#: 超过这个秒数没上报就算离线 (设备默认 15s 轮询一次)
ONLINE_WINDOW = 90
#: 心跳落盘的最小间隔: 面板的在线判断用 90 秒窗口, 没必要每 15 秒写一次 state.json
HEARTBEAT_WRITE_S = 30

#: 设备类型。目前只有路由器端有完整的自动安装, 手机/电脑端走订阅导入。
KINDS = ("router", "phone", "desktop")
DEFAULT_KIND = "router"


def _now() -> int:
    return int(time.time())


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def new_secret() -> str:
    """设备凭据 (URL 安全, 32 字节熵)。只在配对响应里出现一次。"""
    return secrets.token_urlsafe(32)


def new_pair_code() -> str:
    """一次性配对码。十六进制, 因为它要直接嵌进 shell 命令行里。"""
    return secrets.token_hex(16)


def _bucket(state: dict) -> dict:
    bucket = state.get("devices")
    if not isinstance(bucket, dict):
        bucket = {}
        state["devices"] = bucket
    bucket.setdefault("items", [])
    bucket.setdefault("pair_codes", [])
    if not isinstance(bucket["items"], list):
        bucket["items"] = []
    if not isinstance(bucket["pair_codes"], list):
        bucket["pair_codes"] = []
    return bucket


def items(state: dict) -> list[dict]:
    return [d for d in _bucket(state)["items"] if isinstance(d, dict)]


def find(state: dict, device_id: str) -> dict | None:
    for device in items(state):
        if device.get("id") == device_id:
            return device
    return None


# ---------------------------------------------------------------- 配对码

def prune(state: dict) -> None:
    """清掉过期/用掉的配对码。设备侧不需要保留历史。"""
    bucket = _bucket(state)
    now = _now()
    bucket["pair_codes"] = [
        c
        for c in bucket["pair_codes"]
        if isinstance(c, dict) and not c.get("used_at") and int(c.get("expires_at") or 0) > now
    ]


def create_pair_code(state: dict, label: str = "") -> dict:
    """生成一个一次性配对码 (面板上「生成安装命令」按钮)。"""
    bucket = _bucket(state)
    prune(state)
    while len(bucket["pair_codes"]) >= MAX_PAIR_CODES:
        bucket["pair_codes"].pop(0)
    now = _now()
    entry = {
        "code": new_pair_code(),
        "label": (label or "")[:40],
        "created_at": now,
        "expires_at": now + PAIR_TTL,
        "used_at": 0,
        "used_by": "",
    }
    bucket["pair_codes"].append(entry)
    return entry


def pair_code_live(state: dict, code: str) -> dict | None:
    """校验配对码是否可用 (安装脚本被下载时就先挡一次, 免得白跑一遍)。"""
    if not code:
        return None
    now = _now()
    for entry in _bucket(state)["pair_codes"]:
        if not isinstance(entry, dict):
            continue
        if hmac.compare_digest(str(entry.get("code") or ""), code):
            if entry.get("used_at") or int(entry.get("expires_at") or 0) <= now:
                return None
            return entry
    return None


def consume_pair_code(state: dict, code: str) -> dict | None:
    entry = pair_code_live(state, code)
    if entry is None:
        return None
    entry["used_at"] = _now()
    return entry


# ---------------------------------------------------------------- 设备

def default_name(info: dict) -> str:
    """给设备起个顺眼的名字: 优先用型号, 其次主机名, 最后退回类型名。"""
    for key in ("model", "hostname", "sys"):
        value = str(info.get(key) or "").strip()
        if value:
            return value[:40]
    return {"router": "路由器", "phone": "手机", "desktop": "电脑"}.get(
        str(info.get("kind") or ""), "客户端"
    )


def register(state: dict, info: dict) -> tuple[dict | None, str, str]:
    """用配对码换取设备凭据。返回 (device, secret, 错误说明)。

    成功时 secret 只在这里出现一次 —— 调用方必须立刻把它发给设备, 之后服务端
    只有 hash, 再也拿不回来。
    """
    code = str(info.get("code") or "").strip()
    # 先判上限再消费配对码: 设备数满了的时候白烧一个码, 用户只能回面板重新生成
    # (P3-14)。
    if pair_code_live(state, code) is None:
        return None, "", "配对码无效或已过期, 请回面板重新生成安装命令"
    if len(items(state)) >= MAX_DEVICES:
        return None, "", f"设备数已达上限 ({MAX_DEVICES}), 请先移除不用的客户端"
    entry = consume_pair_code(state, code)
    if entry is None:
        return None, "", "配对码无效或已过期, 请回面板重新生成安装命令"

    kind = str(info.get("kind") or DEFAULT_KIND).strip().lower()
    if kind not in KINDS:
        kind = DEFAULT_KIND
    secret = new_secret()
    now = _now()
    device = {
        "id": "dv" + secrets.token_hex(8),
        "secret_hash": _hash(secret),
        "name": default_name({**info, "kind": kind}),
        "kind": kind,
        "model": str(info.get("model") or "")[:64],
        "arch": str(info.get("arch") or "")[:24],
        "os": str(info.get("os") or "")[:64],
        "version": str(info.get("version") or "")[:24],
        "ip": str(info.get("ip") or "")[:64],
        "created_at": now,
        "last_seen": now,
        # 面板的期望状态。新设备默认「开」—— 装完即用, 不用回面板再点一下
        # (用户可在面板上改; 见 README「客户端」一节)
        "desired": True,
        "actual": False,
        "actual_at": 0,
        "template": "",          # 空 = 跟随面板全局分流模板
        "rev": "",               # 设备已生效的配置版本
        "report": {},            # 设备上报的细节 (内核版本 / 运行时长 / 当前节点)
        "deleted": False,
    }
    _bucket(state)["items"].append(device)
    entry["used_by"] = device["id"]
    return device, secret, ""


def check_secret(device: dict | None, secret: str) -> bool:
    """设备自证身份。比对 sha256, 定长比较。"""
    if not isinstance(device, dict) or not secret:
        return False
    stored = str(device.get("secret_hash") or "")
    if not stored:
        return False
    return hmac.compare_digest(stored, _hash(secret))


def touch(state: dict, device: dict, info: dict) -> bool:
    """心跳 + 状态上报 (设备每 15s 调一次 /c/report)。

    返回"这次上报是否带来了需要落盘的变化"。心跳本身每 15 秒就写一次 state.json
    是没必要的: 一台设备一天要写 5760 次, fsync + rename 在 SD 卡/闪存上是要付
    寿命代价的。所以 last_seen 只在超过 HEARTBEAT_WRITE_S 时才更新 (面板判断
    在线用 90 秒窗口, 精度足够), 其余字段变化一律算变化。

    版本语义 (P2-9, 四个版本分开):
      * 面板当前版本 —— `config_rev(state)`, 接口回执里的 `rev`;
      * `downloaded_rev` —— 面板把订阅发出去时写下的版本 (只证明"拿到了");
      * `applied_rev` —— **只有设备显式上报应用成功时才推进**: 新客户端报
        `applied_rev`, 或报 `healthy=true` + `rev` (数据面健康 = 它报的版本在跑);
      * 设备上报的 `rev` 只是它自己的最后一版 (旧客户端字段), 本身不证明已应用。
    下载端点以前把 `heartbeat_rev=panel_rev` 直接喂进来, 于是"下载"被当成"应用" ——
    这正是要拆开的原因。
    """
    now = _now()
    changed = False
    if now - int(device.get("last_seen") or 0) >= HEARTBEAT_WRITE_S:
        device["last_seen"] = now
        changed = True
    for key in ("ip", "version", "arch", "os", "model"):
        value = str(info.get(key) or "").strip()
        if value and device.get(key) != value[:64]:
            device[key] = value[:64]
            changed = True
    if "actual" in info:
        actual = bool(info.get("actual"))
        if bool(device.get("actual")) != actual:
            changed = True
        device["actual"] = actual
        device["actual_at"] = now
    if info.get("rev") and device.get("rev") != str(info["rev"])[:32]:
        device["rev"] = str(info["rev"])[:32]
        changed = True
    # 面板最近一次下发给这台设备的配置版本 (拉订阅时由 routes 写入)
    downloaded = str(info.get("downloaded_rev") or "").strip()[:32]
    if downloaded and device.get("downloaded_rev") != downloaded:
        device["downloaded_rev"] = downloaded
        changed = True
    # 已应用版本: 只认设备的**显式**上报 (applied_rev, 或 healthy + rev), 不再由
    # "下载了" 或 "心跳带了个 rev" 推断 (P2-9)。
    applied = str(info.get("applied_rev") or "").strip()[:32]
    if not applied and info.get("healthy") is True:
        applied = str(info.get("rev") or "").strip()[:32]
    if applied and device.get("applied_rev") != applied:
        device["applied_rev"] = applied
        changed = True
    ui = clean_ui_url(
        info.get("ui"),
        allowed_hosts=(str(state.get("domain") or ""),),
        peer_ip=str(info.get("ip") or ""),
    )
    if ui and device.get("ui") != ui:
        device["ui"] = ui
        changed = True
    report = info.get("report")
    if isinstance(report, dict):
        fresh = {
            # 值放宽到 160 字: 设备上报的 `why` 是"这一级为什么不行"的内核原话, 64 字
            # 常常正好切在关键处 (面板上那枚标签的 tooltip 直接用它)。
            str(k)[:32]: (v if isinstance(v, (int, float, bool)) else str(v)[:160])
            for k, v in list(report.items())[:20]
        }
        if fresh != device.get("report"):
            device["report"] = fresh
            changed = True
    return changed


def remove(state: dict, device_id: str) -> bool:
    """移除设备 (等价于吊销它手里的 secret, 并在已吊销列表中留痕)。

    标记设备为 deleted, 留存审计信息, 便于排查与确认数据面状态。
    """
    bucket = _bucket(state)
    target = None
    for d in bucket["items"]:
        if isinstance(d, dict) and d.get("id") == device_id:
            target = d
            break
    if target is not None:
        target["deleted"] = True
        now = _now()
        revoked = bucket.setdefault("revoked", [])
        revoked.append({
            "id": target.get("id", ""),
            "name": target.get("name", ""),
            "kind": target.get("kind", ""),
            "ip": target.get("ip", ""),
            "deleted_at": now,
        })
        if len(revoked) > 100:
            bucket["revoked"] = revoked[-100:]
        bucket["items"] = [d for d in bucket["items"] if not (isinstance(d, dict) and d.get("id") == device_id)]
        return True
    return False


def online(device: dict, now: int | None = None) -> bool:
    return (_now() if now is None else now) - int(device.get("last_seen") or 0) <= ONLINE_WINDOW


#: 设备自己上报的"管理界面地址"(路由器端 LuCI 页 + 界面令牌)。面板只做展示:
#: 用户在面板上点一下就能进那台路由器的管理界面, 不必回终端敲 `zeroproxy ui`。
#: 校验从严 —— 这个值会进前端 HTML, 只接受 http(s) 且路径里带 zeroproxy 的短地址。
_UI_URL_RE = re.compile(r"^https?://[^\s\"'<>]{1,180}$")


#: 允许的管理界面目标网段。刻意列成显式网段而不是用 `ipaddress.is_private`:
#: 后者按"非 is_global"定义, 连 TEST-NET / 文档保留段 (203.0.113.0/24 等) 也会被
#: 当成 private —— 那些恰恰是"看起来像内网"的外部地址。
_UI_LAN_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",     # IPv6 ULA
        "fe80::/10",    # IPv6 链路本地
    )
)


def _is_lan_host(host: str) -> bool:
    """host 是否是私网/回环/链路本地地址 (IPv4 与 IPv6 都算)。"""
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return any(ip.version == net.version and ip in net for net in _UI_LAN_NETWORKS)


def _same_lan(host: str, peer: str) -> bool:
    """host 与请求来源是否在同一私网网段 (v4 /24, v6 /64)。

    这是"设备上报的是它的 LAN 地址、而面板只看到它 NAT 后的公网地址"场景的兜底:
    同一网段内互访是路由器管理界面的正常用法, 而任意外部主机不是。
    """
    try:
        target = ipaddress.ip_address(host.strip("[]"))
        source = ipaddress.ip_address(str(peer).strip().strip("[]"))
    except ValueError:
        return False
    if target.version != source.version:
        return False
    if not (_is_lan_host(str(target)) and _is_lan_host(str(source))):
        return False
    if target.version == 4:
        return source in ipaddress.ip_network(f"{target}/24", strict=False)
    return source in ipaddress.ip_network(f"{target}/64", strict=False)


def clean_ui_url(
    value: object, *, allowed_hosts: tuple[str, ...] = (), peer_ip: str = ""
) -> str:
    """校验设备上报的管理界面地址, 只放行局域网目标。

    为什么不像以前那样"任意外部主机都行" (P3-15): 这个值会渲染成面板上的一枚
    「打开管理界面」按钮 —— 任何能配对/上报的设备都能把它指向自己的钓鱼页, 管理员
    在面板里点一下就把界面令牌交出去了。所以只接受:
      * localhost / ``*.local`` (mDNS);
      * 私网 / 回环 / 链路本地 IP (含 IPv6 ULA);
      * 面板自己的域名 (``allowed_hosts``, 例如设备经面板域名反代访问本机界面);
      * 与请求来源同私网网段 (v4 /24, v6 /64) 的地址。
    其余 (公网域名、公网 IP、带 userinfo 的 URL) 一律丢弃上报值。
    """
    text = str(value or "").strip()
    if not _UI_URL_RE.match(text) or "/zeroproxy" not in text:
        return ""
    try:
        parsed = urlsplit(text)
    except ValueError:
        return ""
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        return ""
    # userinfo 是典型的"看起来像内网、实际连到别处"的写法 (http://192.168.1.1@evil/)
    if parsed.username or parsed.password:
        return ""
    if host == "localhost" or host.endswith(".local"):
        return text
    if _is_lan_host(host):
        return text
    allowed = {str(item).strip().lower().rstrip(".") for item in allowed_hosts if str(item).strip()}
    if host in allowed:
        return text
    if peer_ip and _same_lan(host, peer_ip):
        return text
    return ""


# ---------------------------------------------------------------- 配置版本

#: 影响订阅内容的字段 (改任何一个, 设备都该重新拉配置)。
#: `updated_at` / `sessions` / `audit` / `devices` 之类的心跳字段**不**在内 ——
#: 否则每 15 秒一次的心跳都会让所有设备以为配置变了, 无限重载。
REV_FIELDS = (
    "domain", "uuid", "ports", "reality", "xhttp", "nodes", "chain",
    "trojan_password", "hysteria_password", "hysteria_hopping", "hysteria_ports",
    "hysteria_masquerade", "routing", "geodata",
)


def config_rev(state: dict) -> str:
    payload = {key: state.get(key) for key in REV_FIELDS}
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


# ---------------------------------------------------------------- 面板视图

def device_view(device: dict, *, now: int | None = None) -> dict:
    now = _now() if now is None else now
    desired = bool(device.get("desired"))
    actual = bool(device.get("actual"))
    is_online = online(device, now)
    return {
        "id": device.get("id", ""),
        "name": device.get("name", ""),
        "kind": device.get("kind", DEFAULT_KIND),
        "model": device.get("model", ""),
        "arch": device.get("arch", ""),
        "os": device.get("os", ""),
        "ip": device.get("ip", ""),
        "version": device.get("version", ""),
        "created_at": int(device.get("created_at") or 0),
        "last_seen": int(device.get("last_seen") or 0),
        "online": is_online,
        "desired": desired,
        "actual": actual,
        "actual_at": int(device.get("actual_at") or 0),
        # 开关点下去到设备回报之间是"同步中": 面板据此显示转圈而不是假装已生效
        "syncing": desired != actual and is_online,
        # 期望开、但设备自己也说开着 → 才是真的"已连接"
        "connected": desired and actual,
        "template": device.get("template", ""),
        # 设备自己上报的最后一版 (旧客户端字段, 不代表已应用)
        "rev": device.get("rev", ""),
        # 面板最近一次把订阅发给它的配置版本 (只证明"已下载")
        "downloaded_rev": device.get("downloaded_rev", ""),
        # 设备显式上报的"已应用"版本 (只有设备说应用成功/数据面健康才推进)
        "applied_rev": device.get("applied_rev", ""),
        # 路由器管理界面地址 (带界面令牌, 只在路由器所在的局域网内可用);
        # 手机/电脑端没有这个值 —— 前端按有没有它决定要不要显示"打开管理界面"。
        "ui": device.get("ui", ""),
        "report": device.get("report", {}),
    }


def view(state: dict, *, now: int | None = None) -> dict:
    """面板「客户端」页的数据源。"""
    prune(state)
    now = _now() if now is None else now
    devices = [device_view(d, now=now) for d in items(state)]
    devices.sort(key=lambda d: (not d["online"], -d["created_at"]))
    bucket = _bucket(state)
    return {
        "items": devices,
        "count": len(devices),
        "online": sum(1 for d in devices if d["online"]),
        "on": sum(1 for d in devices if d["connected"]),
        "max": MAX_DEVICES,
        "kinds": list(KINDS),
        "pair_ttl": PAIR_TTL,
        "online_window": ONLINE_WINDOW,
        "pair_codes": [
            {
                "code": c.get("code", ""),
                "label": c.get("label", ""),
                "expires_at": int(c.get("expires_at") or 0),
            }
            for c in bucket["pair_codes"]
            if isinstance(c, dict) and not c.get("used_at")
        ],
    }
