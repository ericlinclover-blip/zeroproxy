"""运行时状态管理。

所有可变参数集中保存在 $ZP_HOME/data/state.json (权限 0600)。
「修改配置 → 重新生成 → 热重载」闭环完全由这份状态驱动，
订阅 URL 恒定不变 (见 README「自动化逻辑」一节)。

并发模型: 面板是单进程 (uvicorn) + 线程池执行同步端点, 因此 `locked()`
同时提供进程内互斥 (threading) 与跨进程互斥 (fcntl.flock); 读-改-写事务
一律走 `locked()`, 避免并发端点互相覆盖状态。写盘走「临时文件 + fsync +
rename」原子替换, 断电/崩溃不会留下半个 JSON。
"""
from __future__ import annotations

import contextlib
import copy
import json
import os
import threading
import time

try:  # POSIX (Linux/macOS); 其他平台退化为纯进程内锁
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

#: state.json 结构版本 — 新增字段时 +1, `_merge` 会自动补齐缺失键
STATE_VERSION = 4

DEFAULT_HOME = "/opt/zeroproxy"
#: 面板对外端口 (nginx 监听, 默认 8899) — 用于生成订阅/面板链接
PANEL_PORT = int(os.environ.get("ZP_PORT", "8899"))
#: 面板进程 (uvicorn) 自身监听地址 — 默认仅本机回环, 由 nginx 终结 TLS 并反代
PANEL_BIND_HOST = os.environ.get("ZP_BIND_HOST", "127.0.0.1")
PANEL_BIND_PORT = int(os.environ.get("ZP_BIND_PORT", "9900"))

LOCK = threading.RLock()

#: 会话默认有效期 (72h) / 允许同时在线的会话数上限
SESSION_TTL = 72 * 3600
MAX_SESSIONS = 8

#: Reality 默认伪装的 SNI 目标 (技术文档 §7.6.3: 知名度高、TLS1.3、x25519 key_share)。
#: 硬约束 (Xray 26.3 实测 + `xtls/reality` 源码 `size = 8192`): 目标站点发回的
#: Certificate 握手报文必须 ≤ 8192 字节, 超了 REALITY 服务端会直接放弃握手 ——
#: 客户端只看到连接被重置。www.microsoft.com 的证书链是 8273 字节, 必定失败;
#: cloudflare 的 ECDSA 链只有 4KB 出头, 实测握手通过且有 X25519MLKEM768 支持。
#: 注意: 这里只填域名 —— 面板会写成 `<域名>:443`, 且 SNI 与 dest 必须一致。
DEFAULT_REALITY_DEST = "www.cloudflare.com:443"
DEFAULT_REALITY_SNI = "www.cloudflare.com"

#: 历史默认伪装目标 (v2.3.3 及更早)。证书链超过 REALITY 的 8KB 缓冲, 握手必然
#: 失败 → 落地时若发现用户没改过这个默认值, 自动迁移到新默认 (见 apply)。
LEGACY_REALITY_DEST = "www.microsoft.com:443"
LEGACY_REALITY_SNI = "www.microsoft.com"

#: WebSocket 传输路径 (nginx 反代 + 客户端 path 参数共用)
WS_PATH = "/ws/zeroproxy"

#: XHTTP 传输路径 (技术文档 §9) — VLESS + XHTTP + Reality, 免证书且流量特征更接近普通 HTTP
XHTTP_PATH = "/xhttp-zeroproxy"

#: Hysteria 2 伪装目标 (非代理流量会被反代到这里, 技术文档 §4.3)
DEFAULT_MASQUERADE = "https://www.microsoft.com/"

#: GeoIP / GeoSite 数据自动更新的默认周期 (7 天)
GEODATA_TTL = 7 * 86400

#: 节点元数据 — id 与 state["nodes"] 的键一致
NODES = [
    {
        "id": "vless-reality",
        "name": "VLESS Reality",
        "protocol": "VLESS",
        "transport": "TCP + Vision",
        "security": "XTLS-Reality (无证书)",
        "service": "xray",
        "port_key": "reality",
        "desc": "反封锁最强组合, 免证书, 推荐主力节点",
    },
    {
        "id": "vless-xhttp",
        "name": "VLESS XHTTP Reality",
        "protocol": "VLESS",
        "transport": "XHTTP",
        "security": "XTLS-Reality (无证书)",
        "service": "xray",
        "port_key": "xhttp",
        "desc": "新一代 HTTP 形态传输, 特征最接近普通网站 (需 Xray 25+)",
    },
    {
        "id": "vless-ws",
        "name": "VLESS WebSocket",
        "protocol": "VLESS",
        "transport": "WebSocket",
        "security": "TLS 1.3 (Let's Encrypt)",
        "service": "xray",
        "port_key": "ws",
        "desc": "nginx 443 反代, 浏览器/全平台兼容 (可挂 CDN)",
    },
    {
        "id": "trojan",
        "name": "Trojan",
        "protocol": "Trojan",
        "transport": "TCP",
        "security": "TLS 1.3 完美 HTTPS 伪装",
        "service": "xray",
        "port_key": "trojan",
        "desc": "协议层即 HTTPS, 流量整形抗 DPI",
    },
    {
        "id": "hysteria2",
        "name": "Hysteria 2",
        "protocol": "Hysteria 2",
        "transport": "QUIC/UDP",
        "security": "ChaCha20-Poly1305",
        "service": "hysteria2",
        "port_key": "hysteria",
        "desc": "弱网最优, 支持端口跳跃抗封锁",
    },
]
NODE_IDS = [n["id"] for n in NODES]
NODE_BY_ID = {n["id"]: n for n in NODES}
#: 由 Xray 承载的节点 (用于判断是否需要重启 xray)
XRAY_NODE_IDS = ("vless-reality", "vless-xhttp", "vless-ws", "trojan")

DEFAULTS: dict = {
    "version": STATE_VERSION,
    "configured": False,
    "domain": "",
    "admin": {"username": "", "password_hash": ""},
    # 由 用户名+密码 确定性派生的 VLESS UUID (同一凭据始终得到同一 UUID)
    "uuid": "",
    "reality": {
        "private_key": "",   # base64url(32B X25519 私钥, 见 crypto.new_reality_keys)
        "public_key": "",    # base64url(32B 公钥)
        "short_id": "",      # hex, 客户端 sid
        "dest": DEFAULT_REALITY_DEST,
        "server_name": DEFAULT_REALITY_SNI,
    },
    # XHTTP 传输参数 (技术文档 §9): mode=auto 由两端协商
    "xhttp": {"path": XHTTP_PATH, "mode": "auto", "host": ""},
    "trojan_password": "",
    "hysteria_password": "",
    # Hysteria 2 伪装: 非代理流量反向代理到该站点 (技术文档 §4.3)
    "hysteria_masquerade": {"enabled": True, "url": DEFAULT_MASQUERADE},
    "ports": {
        "reality": 8443,        # Xray Reality 直连
        "xhttp": 8445,          # Xray XHTTP + Reality 直连
        "ws_internal": 6000,    # Xray WS 入站 (仅 127.0.0.1, nginx 终结 TLS)
        "trojan": 8444,         # Xray Trojan (复用同一证书)
        "hysteria": 30001,      # Hysteria 2 (UDP)
        "api": 10085,           # Xray Stats API (仅 127.0.0.1)
    },
    "hysteria_hopping": True,   # 端口跳跃 (技术文档 附录 C)
    "hysteria_ports": [30001, 31001, 32001],
    # 客户端分流模板 — 决定订阅里生成的规则 (smart/global/direct, 见 share_links)
    "routing": {"template": "smart"},
    # GeoIP/GeoSite 数据 (Loyalsoldier/v2ray-rules-dat) 与基于它的分流防护。
    # 关键: 只要配置里出现 `geoip:*` / `geosite:*` 规则, 而数据文件不存在,
    # Xray 会直接拒绝启动整份配置 — 因此 `enabled` 只在数据齐备时才允许为真
    # (见 geodata.usable())。
    "geodata": {
        "enabled": False,       # 是否下发 geo 分流规则 (需要数据文件齐备)
        "block_private": True,  # 阻止客户端访问服务器内网/私有地址
        "block_ads": True,      # 按 geosite:category-ads-all 屏蔽广告域名
        "user_set": False,      # 用户是否手动调整过分流开关 (为真则不再自动启用)
        "updated_at": 0,        # 上次成功更新时间
        "source": "",           # 实际生效的数据源
        "files": {},            # 文件名 -> {"size": int, "sha256": str}
    },
    "nodes": {nid: True for nid in NODE_IDS},
    # 链式代理 (中转 → 落地)。两台机器各装一份本程序: 落地端生成配对码, 中转端粘贴即连。
    #   exit    — 本机作为落地端时的专用凭据 (独立 UUID + 独立端口, 可与订阅凭据分开吊销)
    #   entries — 本机作为中转端时已连接的落地端清单 (每条 = 一个入站 + 一个出站 + 一条路由)
    "chain": {
        "exit": {"enabled": False, "port": 8447, "uuid": "", "label": "", "created_at": 0},
        "entries": [],
    },
    "cert": {
        "type": "none",  # none | letsencrypt | selfsigned
        "issuer": "",
        "cert_file": "",
        "key_file": "",
        "not_after": 0,
    },
    "subscription_token": "",
    "sessions": {},
    # 登录失败限流: ip -> {"n": 连续失败次数, "until": 解封时间戳}
    "login_failures": {},
    # 审计日志 (最近 200 条)
    "audit": [],
    "created_at": 0,
    "updated_at": 0,
    "steps": [],
}


def home() -> str:
    return os.environ.get("ZP_HOME", DEFAULT_HOME)


def paths() -> dict:
    h = home()
    return {
        "home": h,
        "data_dir": f"{h}/data",
        "state": f"{h}/data/state.json",
        "lock": f"{h}/data/state.lock",
        # install.sh 生成的一次性引导令牌 (0600): 只有拿到它的人能完成初始化
        "bootstrap_token": f"{h}/data/bootstrap_token",
        "xray_dir": f"{h}/xray",
        "xray_config": f"{h}/xray/config.json",
        "hysteria_dir": f"{h}/hysteria",
        "hysteria_config": f"{h}/hysteria/config.yaml",
        "hysteria_cert": f"{h}/hysteria/cert.pem",
        "hysteria_key": f"{h}/hysteria/key.pem",
        "cert_dir": f"{h}/certs",
        # GeoIP/GeoSite 数据目录 — Xray 通过 XRAY_LOCATION_ASSET 指向它
        "geo_dir": f"{h}/geo",
        "cert_file": f"{h}/certs/cert.pem",
        "cert_key": f"{h}/certs/key.pem",
        # 面板自身的 HTTPS 自签证书 (install.sh 部署时生成; 不存在则面板回退明文 HTTP)
        "panel_dir": f"{h}/panel",
        "panel_cert": os.environ.get("ZP_PANEL_CERT", f"{h}/panel/cert.pem"),
        "panel_key": os.environ.get("ZP_PANEL_KEY", f"{h}/panel/key.pem"),
        "nginx_etc": "/etc/nginx/conf.d/zeroproxy.conf",
        "nginx_home": f"{h}/nginx/zeroproxy.conf",
        "nginx_dir": f"{h}/nginx",
        "www": f"{h}/www",
        # 一键升级: 升级脚本自身、进度文件与备份目录
        "upgrade_script": f"{h}/upgrade.sh",
        "update_status": f"{h}/data/update.json",
        "update_log": f"{h}/data/update.log",
        "backup_dir": f"{h}/data/backups",
    }


def _ensure_dirs() -> None:
    p = paths()
    for key in (
        "data_dir", "xray_dir", "hysteria_dir", "cert_dir", "nginx_dir", "www", "panel_dir", "geo_dir"
    ):
        os.makedirs(p[key], exist_ok=True)


def _merge(base: dict, extra: dict) -> None:
    for key, value in extra.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _merge(base[key], value)
        else:
            base[key] = value


# ---------------------------------------------------------------- 引导令牌

def bootstrap_token() -> str:
    """初始化引导令牌。

    优先级: 环境变量 ZP_BOOTSTRAP_TOKEN > $ZP_HOME/data/bootstrap_token。
    两者都不存在时返回空串 — 本地开发 (dev.sh) 允许无令牌初始化;
    生产环境由 install.sh 必定写入该文件, 从而关闭「谁先打开面板谁就能
    抢注管理员」的时间窗。
    """
    env = os.environ.get("ZP_BOOTSTRAP_TOKEN", "").strip()
    if env:
        return env
    try:
        with open(paths()["bootstrap_token"], "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def write_bootstrap_token(token: str) -> None:
    """写入引导令牌 (0600)。"""
    _ensure_dirs()
    path = paths()["bootstrap_token"]
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(token.strip() + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def clear_bootstrap_token() -> None:
    """作废引导令牌 (初始化成功后调用, 防止重放)。"""
    try:
        os.remove(paths()["bootstrap_token"])
    except OSError:
        pass


# ---------------------------------------------------------------- 状态读写

@contextlib.contextmanager
def locked():
    """读-改-写事务互斥锁。

    进程内 threading.RLock (可重入, 允许嵌套), 进程间 fcntl.flock。
    锁文件独立于 state.json, 避免 rename 让锁失效。「读 → 改 → 写」应整体
    包在 `with locked():` 内。
    """
    with LOCK:
        if fcntl is None:
            yield
            return
        _ensure_dirs()
        fd = os.open(paths()["lock"], os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


def load_state() -> dict:
    with LOCK:
        _ensure_dirs()
        state = copy.deepcopy(DEFAULTS)
        path = paths()["state"]
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    _merge(state, json.load(fh))
            except (json.JSONDecodeError, OSError):
                pass
        # 结构升级: 缺失键由 _merge 自动补齐, 这里统一标注版本号
        state["version"] = STATE_VERSION
        return state


def state_from(data: dict) -> dict:
    """由外部数据构造完整 state (备份恢复用): DEFAULTS 兜底 + 递归合并 + 版本对齐。

    缺失的新字段会被自动补齐, 因此旧版本备份也能恢复。
    """
    state = copy.deepcopy(DEFAULTS)
    if isinstance(data, dict):
        _merge(state, data)
    state["version"] = STATE_VERSION
    return state


def save_state(state: dict) -> None:
    with LOCK:
        _ensure_dirs()
        state["version"] = STATE_VERSION
        state["updated_at"] = int(time.time())
        path = paths()["state"]
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(state, fh, ensure_ascii=False, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def audit(state: dict, action: str, detail: str = "", actor: str = "") -> None:
    """追加一条审计记录 (仅改内存态, 由调用方决定何时 save_state)。"""
    entries = state.setdefault("audit", [])
    entries.append(
        {"ts": int(time.time()), "action": action, "detail": detail[:200], "actor": actor[:64]}
    )
    del entries[:-200]  # 只保留最近 200 条
