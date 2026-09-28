"""链式代理 (中转 → 落地): 把两台服务器接成一条链的最短路径。

用户场景: 香港机器做入口 (离用户近、延迟低), 美国机器做落地 (出口 IP 是美国),
客户端只连香港那个节点, 出网走美国。

角色分工
--------
  - **落地端 / 出口**: 面板里点「生成配对码」。本地生成一份**专用凭据** —— 独立 UUID +
    独立端口, 与订阅里那份凭据分开, 可以单独吊销/轮换; 落地成 `chain-exit` 入站
    (VLESS + TCP + Reality + Vision, 复用本机 Reality 密钥与伪装目标), 免证书、抗封锁。
  - **入口端 / 中转**: 粘贴配对码 → 校验 → 起一个临时 Xray 客户端**真的穿过落地端出网**
    并读回落地出口 IP → 一键落地: 本机新增一个入站 (客户端连它) + 一个出站 (连落地端) +
    一条路由规则 (该入站 → 该出站)。订阅里随即多出一个普通节点, 客户端无需任何改动。

为什么把链式做在服务端
----------------------
Clash 的 relay / sing-box 的 detour 都要求客户端支持并手写配置, 手机上尤其难;
服务端链式对客户端来说只是"多了一个节点", 导入订阅即用, 中转链路对客户端完全透明。

配对码
------
`ZPC1~<base64url(payload)>~<sha256 前 6 位>` —— 一行, 可复制可扫码。
那位校验和只用来挡"复制粘贴被截断/串行", **不是签名**; 配对码本身等同于一份节点凭据,
不要公开发出去。面板里有「重新生成」(作废旧的) 与「关闭落地端」。
"""
from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import uuid as uuid_mod

from . import services

#: 配对码前缀与分隔符 (base64url 字母表是 A-Za-z0-9-_ , 所以 `~` 不会与之冲突)
CODE_PREFIX = "ZPC1"
CODE_SEP = "~"

#: 落地端默认端口 / 入口端新入站端口的起始值。
#: 8443 Reality / 8444 Trojan / 8445 XHTTP 已被主力节点占用, 从这里往后找空闲端口。
DEFAULT_EXIT_PORT = 8447
ENTRY_PORT_BASE = 8446

#: 探测"落地出口 IP"用的回显服务 (纯 HTTP, 逐个尝试)。
#: 顺序按"从中国大陆直连也能到"排: api.ipify.org 在国内多数网络是黑洞 (真机实测
#: 连上却读不到任何字节), 放最后兜底; 前两个任一可用即可。
IP_ECHO = ("http://ip.3322.net", "http://ifconfig.me/ip", "http://api.ipify.org")

#: 出口 IP: 优先 IPv4, 拿不到再认 IPv6 (ifconfig.me 会按线路返回 v6)
_IPV4_RE_FIND = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
_IPV6_RE_FIND = re.compile(r"(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}", re.IGNORECASE)

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.IGNORECASE)
#: QUIC 内层的 SNI —— 证书是我们自己按这个值签的, 只挡明显不合法的输入
_SNI_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$", re.IGNORECASE)
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HEX_RE = re.compile(r"^[0-9a-f]{0,16}$", re.IGNORECASE)
FLOWS = ("", "xtls-rprx-vision")


class CodeError(ValueError):
    """配对码不合法 (信息直接给用户看)。"""


# ---------------------------------------------------------------- 小工具

def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _checksum(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()[:6]


def new_id() -> str:
    """链式条目的短 id (同时用作 Xray 入站 tag: `chain-<id>`)。"""
    return uuid_mod.uuid4().hex[:8]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def is_host(value: str) -> bool:
    """落地地址: 域名或 IPv4 都行 (IPv6 未支持, 面板里也没暴露)。"""
    return bool(_IPV4_RE.match(value) or _DOMAIN_RE.match(value))


def exit_host_error(state: dict) -> str:
    """本机地址能不能当"落地地址"写进配对码 —— 不能就返回给用户看的原因。

    配对码里的地址既要是对方能连的, 也要能通过 `parse_code` 的校验: 本机如果是
    IPv6 (面板允许用 IPv6 初始化), 生成出来的码对方一律解析失败, 不如当场说清。
    """
    host = str(state.get("domain") or "").strip()
    if not host:
        return "本机还没有域名 / IP, 无法生成配对码"
    if not is_host(host):
        return (
            f"本机地址 {host} 不是域名或 IPv4 —— 配对码里放不下 IPv6 地址, "
            "请给落地端一个域名 (或在面板里改用 IPv4 重新初始化)"
        )
    return ""


def node_label(entry: dict) -> str:
    """条目在订阅 / 客户端里的显示名 (没填名称就回退到落地地址)。"""
    return (entry.get("label") or "").strip() or str(entry.get("host") or "")


def unique_label(entries: list[dict], label: str, host: str, keep_id: str = "") -> str:
    """给链式条目挑一个不与其它条目重名的名称。

    客户端把节点名当代理名 / 出站 tag: 两条链同名时 Clash(mihomo) 会丢掉重复项、
    sing-box 直接报 duplicate tag —— 整个订阅都导不进来。所以重名时自动加序号后缀
    (后缀加在 34 字符以内, 保证截断后仍然唯一)。
    """
    base = (label or "").strip()[:40]
    mine = base or host
    taken = {node_label(e) for e in entries if e.get("id") != keep_id}
    if mine not in taken:
        return base
    for n in range(2, 100):
        candidate = f"{mine[:34]} ({n})"
        if candidate not in taken:
            return candidate
    return f"{mine[:36]} ({keep_id or 'x'})"[:40]  # pragma: no cover - 兜底


# ---------------------------------------------------------------- 配对码

def make_code(
    *,
    host: str,
    port: int,
    uuid: str,
    pbk: str,
    sid: str = "",
    sni: str,
    flow: str = "xtls-rprx-vision",
    label: str = "",
    hy_port: int | None = None,
    hy_password: str = "",
    hy_sni: str = "",
) -> str:
    """把落地端的连接参数打包成一行配对码 (字段名压到 1 个字母, 码更短)。

    版本 1: 只有 Reality 内层 (老版本生成的码, 新版本照样认);
    版本 2: 落地端同时开了 QUIC (Hysteria 2) 内层 —— Reality 那组参数挪进 `r`,
    QUIC 那组放进 `y`; 入口端可以逐条选走哪一层。
    """
    reality = {
        "p": int(port),
        "u": uuid,
        "k": pbk,
        "s": sid or "",
        "f": flow,
    }
    if hy_port and hy_password:
        payload = {
            "v": 2,
            "h": host,
            "n": sni,
            "l": label or "",
            "r": reality,
            "y": {"p": int(hy_port), "w": hy_password, "n": hy_sni or sni},
        }
    else:
        payload = {"v": 1, "h": host, "n": sni, "l": label or "", **reality}
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return CODE_SEP.join((CODE_PREFIX, _b64e(raw), _checksum(raw)))


def parse_code(text: str) -> dict:
    """解析 + 严格校验配对码。出错抛 CodeError (中文说明, 直接给用户看)。

    返回的字典里 Reality 那组参数是平铺的 (老代码路径不变), QUIC (v2 才有) 的
    参数挂在 `hy_port` / `hy_pw` / `hy_sni` 上: 为空表示落地端没开 QUIC 内层。
    """
    code = re.sub(r"\s+", "", (text or "").strip())
    if not code:
        raise CodeError("配对码为空: 请到落地服务器面板「链式代理 → 作为落地端」复制配对码")
    parts = code.split(CODE_SEP)
    if len(parts) != 3 or parts[0] != CODE_PREFIX:
        raise CodeError("配对码格式不对 (应以 ZPC1~ 开头); 请整段复制, 别只复制一部分")
    payload_b64, checksum = parts[1], parts[2].lower()
    try:
        raw = _b64d(payload_b64)
    except (ValueError, binascii.Error) as exc:
        raise CodeError("配对码内容损坏 (base64 解不开), 请重新复制一次") from exc
    if _checksum(raw) != checksum:
        raise CodeError("配对码校验和不匹配 (复制时被截断或改动了), 请重新复制")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CodeError("配对码内容损坏 (不是合法 JSON), 请重新复制") from exc
    if not isinstance(payload, dict):
        raise CodeError("配对码内容损坏 (不是一份参数), 请重新复制")
    version = int(payload.get("v") or 0)
    if version not in (1, 2):
        raise CodeError("配对码版本不认识 (可能来自更新版本的面板), 请升级本机程序后重试")

    host = str(payload.get("h") or "").strip()
    sni = str(payload.get("n") or "").strip().lower()
    # v1: Reality 参数平铺在顶层; v2: 挪进 `r`, QUIC 参数在 `y`
    reality = payload.get("r") if version == 2 else payload
    if not isinstance(reality, dict):
        raise CodeError("配对码内容损坏 (缺少落地参数), 请重新复制")
    uid = str(reality.get("u") or "").strip().lower()
    pbk = str(reality.get("k") or "").strip()
    sid = str(reality.get("s") or "").strip().lower()
    flow = str(reality.get("f") or "")
    try:
        port = int(reality.get("p"))
    except (TypeError, ValueError):
        raise CodeError("配对码里的端口不合法") from None

    if not is_host(host):
        raise CodeError(f"配对码里的落地地址不合法: {host or '(空)'}")
    if not 1 <= port <= 65535:
        raise CodeError(f"配对码里的端口不合法: {port}")
    if not _UUID_RE.match(uid):
        raise CodeError("配对码里的 UUID 不合法 (需要标准 UUID 格式)")
    # shortId 是十六进制串, 且长度必须是偶数 —— Xray 会 hex 解码, 奇数长度会让
    # **整份配置**构建失败 (不是这一个入站连不上), 所以必须在粘贴时就挡住。
    if not _HEX_RE.match(sid) or len(sid) % 2:
        raise CodeError("配对码里的 shortId 不合法 (应为不超过 16 位、长度为偶数的十六进制)")
    if not _DOMAIN_RE.match(sni):
        raise CodeError(f"配对码里的伪装 SNI 不合法: {sni or '(空)'}")
    if flow not in FLOWS:
        raise CodeError(f"配对码里的 flow 不支持: {flow or '(空)'}")
    try:
        key = _b64d(pbk)
    except (ValueError, binascii.Error) as exc:
        raise CodeError("配对码里的 Reality 公钥不合法 (base64url 解不开)") from exc
    if len(key) != 32:
        raise CodeError("配对码里的 Reality 公钥长度不对 (应为 32 字节 X25519 公钥)")

    target = {
        "host": host,
        "port": port,
        "uuid": uid,
        "pbk": pbk,
        "sid": sid,
        "sni": sni,
        "flow": flow,
        "label": str(payload.get("l") or "").strip()[:40],
        "hy_port": 0,
        "hy_pw": "",
        "hy_sni": "",
    }

    hy = payload.get("y") if version == 2 else None
    if isinstance(hy, dict) and hy:
        hy_pw = str(hy.get("w") or "")
        hy_sni = str(hy.get("n") or sni).strip().lower()
        try:
            hy_port = int(hy.get("p"))
        except (TypeError, ValueError):
            raise CodeError("配对码里的 QUIC 端口不合法") from None
        if not 1 <= hy_port <= 65535:
            raise CodeError(f"配对码里的 QUIC 端口不合法: {hy_port}")
        if not hy_pw:
            raise CodeError("配对码里的 QUIC 密码为空, 请重新复制")
        # SNI 会原样写进客户端的 TLS 配置, 这里挡一下明显不合法的值
        if not _SNI_RE.match(hy_sni):
            raise CodeError(f"配对码里的 QUIC SNI 不合法: {hy_sni or '(空)'}")
        target.update({"hy_port": hy_port, "hy_pw": hy_pw, "hy_sni": hy_sni})
    return target


def exit_code(state: dict) -> str:
    """本机作为落地端时给对方的配对码 (关闭 / 没生成过凭据就返回空串)。"""
    exit_cfg = (state.get("chain") or {}).get("exit") or {}
    uid = str(exit_cfg.get("uuid") or "")
    if not uid or not exit_cfg.get("enabled"):
        return ""
    reality = state.get("reality") or {}
    # 开了 QUIC 内层就把那组参数一并写进配对码 (v2): 入口端可以逐条选走哪一层
    hy_on = bool(exit_cfg.get("hy_enabled")) and bool(exit_cfg.get("hy_password"))
    return make_code(
        host=state.get("domain") or "",
        port=int(exit_cfg.get("port") or DEFAULT_EXIT_PORT),
        uuid=uid,
        pbk=str(reality.get("public_key") or ""),
        sid=str(reality.get("short_id") or ""),
        sni=str(reality.get("server_name") or ""),
        flow="xtls-rprx-vision",
        label=str(exit_cfg.get("label") or "") or (state.get("domain") or ""),
        hy_port=int(exit_cfg.get("hy_port") or 0) if hy_on else None,
        hy_password=str(exit_cfg.get("hy_password") or "") if hy_on else "",
        hy_sni=str(exit_cfg.get("hy_sni") or "") if hy_on else "",
    )


# ---------------------------------------------------------------- 端口分配

def used_ports(state: dict) -> set[int]:
    """本机已经占用的 TCP 端口 (含面板端口与各链式入站)。"""
    from . import config

    used: set[int] = set()
    for value in (state.get("ports") or {}).values():
        try:
            used.add(int(value))
        except (TypeError, ValueError):
            continue
    chain = state.get("chain") or {}
    exit_cfg = chain.get("exit") or {}
    if exit_cfg.get("port"):
        used.add(int(exit_cfg["port"]))
    if exit_cfg.get("hy_port"):
        used.add(int(exit_cfg["hy_port"]))   # QUIC 内层的 UDP 端口, 别让别的节点撞上
    for entry in chain.get("entries") or []:
        if entry.get("local_port"):
            used.add(int(entry["local_port"]))
    used.update({80, 443, int(config.PANEL_PORT)})
    return used


def pick_port(state: dict, preferred: int | None = None) -> int:
    """挑一个没被占用的入站端口 (指定了就用指定的, 冲突则从 8446 往后找)。"""
    used = used_ports(state)
    if preferred:
        port = int(preferred)
        if not 1 <= port <= 65535:
            raise ValueError("端口需在 1-65535 之间")
        if port in used:
            raise ValueError(f"端口 {port} 已被本机其它节点/链式条目占用, 换一个")
        if not services.port_available(port, "tcp"):
            raise ValueError(f"端口 {port}/tcp 已被系统里其它进程占用, 换一个")
        return port
    for port in range(ENTRY_PORT_BASE, 65535):
        if port in used:
            continue
        if services.port_available(port, "tcp"):
            return port
    raise ValueError("找不到空闲端口, 请手动指定")


# ---------------------------------------------------------------- 真实握手探测

def client_config(target: dict, socks_port: int) -> dict:
    """把落地端参数渲染成一份最小 Xray 客户端 (本地 SOCKS 入站 + Reality 出站)。"""
    return {
        "log": {"loglevel": "error"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": int(socks_port),
                "protocol": "socks",
                "settings": {"udp": False},
            }
        ],
        "outbounds": [
            {
                "protocol": "vless",
                "tag": "chain-out",
                "settings": {
                    "vnext": [
                        {
                            "address": target["host"],
                            "port": int(target["port"]),
                            "users": [
                                {
                                    "id": target["uuid"],
                                    "encryption": "none",
                                    "flow": target.get("flow") or "xtls-rprx-vision",
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "tcpSettings": {"header": {"type": "none"}},
                    "realitySettings": {
                        "serverName": target["sni"],
                        "publicKey": target["pbk"],
                        "shortId": target.get("sid") or "",
                        "fingerprint": "chrome",
                        "spiderX": "/",
                    },
                },
            }
        ],
    }


def _wait_socks(proc: "subprocess.Popen", port: int, timeout: float = 4.0) -> str:
    """等临时客户端的 SOCKS 端口起来; 返回空串表示成功。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if services.tcp_connect_ms("127.0.0.1", port, 0.3)[0]:
            return ""
        if proc.poll() is not None:
            return "临时客户端启动失败 (xray 退出, 详见 journalctl -u xray)"
        time.sleep(0.15)
    return "临时客户端 SOCKS 端口未就绪"


def read_exit_ip(socks_port: int, timeout: float = 10.0) -> tuple[str, str]:
    """经一个已经建好的 SOCKS 隧道逐个试回显服务, 读回出口 IP。

    返回 (ip, 说明)。`ip` 为空表示没读到 —— 说明里带上最后一次的失败原因,
    方便面板直接展示。调用方负责起停那个 SOCKS 客户端。

    `timeout` 是**整段探测的总预算** (不是每个回显服务各给一份): 三个回显服务
    各试 6 秒的话, 面板上一次"测速"最长要等 18 秒, 用户会以为卡死了。
    """
    deadline = time.monotonic() + max(2.0, float(timeout))
    last = "没有可用的出口 IP 回显服务"
    for url in IP_ECHO:
        left = deadline - time.monotonic()
        if left <= 0.5:
            break
        per_try = max(1.5, min(left, 6.0))
        host, _, path = url[len("http://"):].partition("/")
        body, detail = services.socks5_http_get(socks_port, host, 80, "/" + path, per_try)
        last = f"{host}: {detail}"
        found = _IPV4_RE_FIND.search(body or "") or _IPV6_RE_FIND.search(body or "")
        if found:
            return found.group(0), "HTTP 往返成功"
    return "", last


def probe_target(target: dict, timeout: float = 10.0) -> dict:
    """真的穿过落地端出一次网, 并读回落地出口 IP。

    返回 {"ok", "probe_ok", "ms", "tcp_ms", "exit_ip", "detail"}。

    `tcp_ms` 是**入口→落地这一跳的 TCP 握手耗时** (链路本身多出来的那个 RTT),
    面板要单独显示它; `ms` 是整段探测的总耗时 (含起临时客户端、经链出去问一次
    回显服务), 只能当"通不通"的参考 —— 拿它当延迟看会把人吓到。

    `probe_ok=False` 表示"本机环境不允许探测" (没有 xray 二进制等), 与"配错了
    连不通"区分开 —— 前者不该拦住用户, 后者才该拦住 (由调用方决定要不要 force)。

    QUIC 内层 (Hysteria 2) 走 `_probe_quic`: 那边是 UDP, 没有"TCP 握手 RTT"
    可以量, 所以 `tcp_ms` 留空 (面板对应位置显示的是传输方式而不是延迟)。
    """
    if (target.get("transport") or "reality") == "hysteria2":
        return _probe_quic(target, timeout)
    started = time.perf_counter()
    reachable, tcp_ms, tcp_detail = services.tcp_connect_ms(target["host"], target["port"], 5.0)
    if not reachable:
        return {
            "ok": False,
            "probe_ok": True,
            "ms": None,
            "tcp_ms": None,
            "exit_ip": "",
            "detail": f"连不上落地端 {target['host']}:{target['port']} — {tcp_detail} "
            "(落地端安全组/防火墙是否放行该端口?)",
        }

    binary = services.bin_path("xray")
    if not binary:
        return {
            "ok": False,
            "probe_ok": False,
            "ms": None,
            "tcp_ms": round(tcp_ms, 1),
            "exit_ip": "",
            "detail": f"TCP 可达 ({tcp_ms:.0f}ms), 但本机没有 xray 二进制, 无法做链路测试",
        }

    socks_port = free_port()
    workdir = tempfile.mkdtemp(prefix="zp-chain-probe-")
    cfg_path = os.path.join(workdir, "client.json")
    with open(cfg_path, "w", encoding="utf-8") as fh:
        json.dump(client_config(target, socks_port), fh)
    proc = subprocess.Popen(
        [binary, "run", "-c", cfg_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={**os.environ, **services.xray_env()},
    )
    try:
        wait_err = _wait_socks(proc, socks_port)
        if wait_err:
            return {
                "ok": False,
                "probe_ok": True,
                "ms": None,
                "tcp_ms": round(tcp_ms, 1),
                "exit_ip": "",
                "detail": wait_err,
            }
        ip, detail = read_exit_ip(socks_port, timeout)
        if ip:
            return {
                "ok": True,
                "probe_ok": True,
                "ms": round((time.perf_counter() - started) * 1000, 1),
                "tcp_ms": round(tcp_ms, 1),
                "exit_ip": ip,
                "detail": f"链路通, 落地出口 IP {ip}",
            }
        return {
            "ok": False,
            "probe_ok": True,
            "ms": None,
            "tcp_ms": round(tcp_ms, 1),
            "exit_ip": "",
            "detail": f"链路不通 (Reality 公钥 / shortId / SNI 任一不匹配都会这样): {detail}",
        }
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:  # pragma: no cover - 兜底
            proc.kill()
        shutil.rmtree(workdir, ignore_errors=True)


def _probe_quic(target: dict, timeout: float = 10.0) -> dict:
    """QUIC 内层 (Hysteria 2) 的链路探测: 起一个临时客户端, 经它出一次网。

    与 Reality 那条路等价的语义: `ok` 表示真的读到落地出口 IP, `probe_ok=False`
    表示本机没条件测 (没有 hysteria 二进制)。区别是这里量不到"TCP 握手 RTT"
    —— 内层走的是 UDP, 所以 `tcp_ms` 留空。
    """
    from . import chain_quic

    if not target.get("hy_port") or not target.get("hy_pw"):
        return {
            "ok": False,
            "probe_ok": True,
            "ms": None,
            "tcp_ms": None,
            "exit_ip": "",
            "detail": "这条链缺 QUIC 凭据 (落地端的配对码是旧格式), 重新复制一次配对码即可",
        }
    if not chain_quic.binary():
        return {
            "ok": False,
            "probe_ok": False,
            "ms": None,
            "tcp_ms": None,
            "exit_ip": "",
            "detail": "本机没有 hysteria 二进制, 无法测试 QUIC 内层",
        }

    socks_port = free_port()
    started = time.perf_counter()
    proc, workdir, err = chain_quic.start_temp_client(target, socks_port)
    if proc is None:
        return {
            "ok": False,
            "probe_ok": True,
            "ms": None,
            "tcp_ms": None,
            "exit_ip": "",
            "detail": err or "临时 QUIC 客户端启动失败",
        }
    try:
        wait_err = chain_quic.wait_socks(socks_port, timeout=8.0, proc=proc)
        if wait_err:
            return {
                "ok": False,
                "probe_ok": True,
                "ms": None,
                "tcp_ms": None,
                "exit_ip": "",
                "detail": f"{wait_err} (落地端没开 QUIC 内层 / 配对码已作废 / UDP 端口没放行?)",
            }
        ip, detail = read_exit_ip(socks_port, timeout)
        if ip:
            return {
                "ok": True,
                "probe_ok": True,
                "ms": round((time.perf_counter() - started) * 1000, 1),
                "tcp_ms": None,
                "exit_ip": ip,
                "detail": f"QUIC 内层通, 落地出口 IP {ip}",
            }
        return {
            "ok": False,
            "probe_ok": True,
            "ms": None,
            "tcp_ms": None,
            "exit_ip": "",
            "detail": f"QUIC 内层通了但读不到出口 IP (落地端 UDP 端口 / 密码不匹配?): {detail}",
        }
    finally:
        chain_quic.cleanup_temp(proc, workdir)


def as_target(entry: dict) -> dict:
    """从 state 里的条目取出探测 / 出站需要的参数。"""
    return {
        "host": entry["host"],
        "port": int(entry["port"]),
        "uuid": entry["uuid"],
        "pbk": entry["pbk"],
        "sid": entry.get("sid") or "",
        "sni": entry["sni"],
        "flow": entry.get("flow") or "xtls-rprx-vision",
        "transport": entry.get("transport") or "reality",
        "hy_port": int(entry.get("hy_port") or 0),
        "hy_pw": entry.get("hy_pw") or "",
        "hy_sni": entry.get("hy_sni") or "",
        "hy_socks_port": int(entry.get("hy_socks_port") or 0),
        "hy_bw": int(entry.get("hy_bw") or 0),
    }


# ---------------------------------------------------------------- 重启后预热

#: 预热的总预算。够把 3 个入口各穿一次 (第一个要吃掉那 ~5 秒冷启动), 又不会让
#: 后台线程长时间挂着。
WARMUP_BUDGET = 20.0


def warmup_targets(state: dict) -> list[dict]:
    """重启后值得预热的**本机入口** (客户端连的那一侧), 保序去重。

    为什么要预热: Xray 的 Reality 入站在进程刚起来时, **第一次**握手要 ~5 秒才回来
    —— 真机实测连回环都复现, 冷启动过后立刻恢复到毫秒级。这 5 秒以前是算在用户
    头上的: 每次改配置重启完, 第一条连接就是"卡住不动"。

    预热的对象是主力 Reality 入站 + 每条启用中的链式入站。它们共用同一套 Reality
    密钥和伪装目标, 所以第一个入口就把大头吃掉了, 后面几个基本是 0.2 秒级;
    仍然逐个走一遍, 是因为每个端口都是独立的 listener。
    """
    reality = state.get("reality") or {}
    uid = str(state.get("uuid") or "")
    pbk = str(reality.get("public_key") or "")
    if not uid or not pbk:
        return []

    base = {
        "host": "127.0.0.1",  # 回环即可: 冷启动在服务端, 与客户端在哪无关
        "uuid": uid,
        "pbk": pbk,
        "sid": str(reality.get("short_id") or ""),
        "sni": str(reality.get("server_name") or ""),
        "flow": "xtls-rprx-vision",
    }

    ports: list[int] = []
    if (state.get("nodes") or {}).get("vless-reality"):
        try:
            ports.append(int((state.get("ports") or {}).get("reality") or 0))
        except (TypeError, ValueError):
            pass
    for entry in (state.get("chain") or {}).get("entries") or []:
        if not entry.get("enabled", True):
            continue
        try:
            ports.append(int(entry.get("local_port") or 0))
        except (TypeError, ValueError):
            continue

    targets: list[dict] = []
    seen: set[int] = set()
    for port in ports:
        if 1 <= port <= 65535 and port not in seen:
            seen.add(port)
            targets.append({**base, "port": port})
    return targets


def _warm_one(binary: str, target: dict, timeout: float) -> tuple[bool, str, float]:
    """起一个临时客户端穿一次这个入口; 返回 (是否读到出口 IP, 说明, 耗时秒)。"""
    started = time.perf_counter()
    reachable, _ms, detail = services.tcp_connect_ms(target["host"], target["port"], 1.0)
    if not reachable:
        return False, f"入口没在监听 ({detail})", time.perf_counter() - started

    socks_port = free_port()
    workdir = tempfile.mkdtemp(prefix="zp-chain-warmup-")
    cfg_path = os.path.join(workdir, "client.json")
    with open(cfg_path, "w", encoding="utf-8") as fh:
        json.dump(client_config(target, socks_port), fh)
    proc = subprocess.Popen(
        [binary, "run", "-c", cfg_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={**os.environ, **services.xray_env()},
    )
    try:
        wait_err = _wait_socks(proc, socks_port)
        if wait_err:
            return False, wait_err, time.perf_counter() - started
        ip, read_detail = read_exit_ip(socks_port, timeout)
        # 没读到出口 IP 也算"穿过一次" —— 预热只要握手真的走完一遍就达到目的,
        # 回显服务偶发读不到不该被当成失败。
        return bool(ip), (f"读到出口 IP {ip}" if ip else read_detail), time.perf_counter() - started
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:  # pragma: no cover - 兜底
            proc.kill()
        shutil.rmtree(workdir, ignore_errors=True)


def warmup(state: dict, timeout: float = WARMUP_BUDGET) -> tuple[bool, str]:
    """把 Reality 冷启动从用户身上挪走: 自己先穿一遍入口。

    返回 (是否全部走通, 面板/操作记录里显示的一句话)。**永不抛异常** —— 预热是
    锦上添花, 任何失败都不该影响刚落地的那次配置变更。
    """
    targets = warmup_targets(state)
    if not targets:
        return True, "无需预热 (本机没有开着的 Reality 入口)"
    binary = services.bin_path("xray")
    if not binary:
        # 本地开发环境 / 卸载了 xray: 跳过而不是报错
        return True, "本机没有 xray 二进制, 跳过预热"

    deadline = time.monotonic() + max(5.0, float(timeout))
    rows: list[str] = []
    all_ok = True
    for target in targets:
        left = deadline - time.monotonic()
        if left <= 1.5:
            rows.append(f"{target['port']} ↘ 预算用尽")
            break
        ok, detail, cost = _warm_one(binary, target, min(left - 0.5, 12.0))
        all_ok = all_ok and ok
        rows.append(f"{target['port']} {'✓' if ok else '↷'} {cost:.1f}s ({detail})")
    return all_ok, "; ".join(rows)


def warmup_in_background(state: dict) -> None:
    """后台预热: 不阻塞"重载服务"那一步, 也不占用面板的这次请求。

    结果写进操作记录。注意后台线程手里那份 state 是重启前的快照, 直接 save 会把
    预热期间用户在面板上做的改动覆盖掉 —— 所以重新从磁盘读一份再写。
    """
    if not warmup_targets(state) or not services.bin_path("xray"):
        return
    # 预热要跑好几秒, 期间面板可能已经指向了另一个 $ZP_HOME (部署演练 / 测试里
    # 每个用例一个临时目录)。写回前确认还是同一份 state, 免得把结果塞到别处。
    from .config import paths as _paths

    home_state_path = _paths()["state"]

    def run() -> None:
        try:
            ok, detail = warmup(state)
        except Exception as exc:  # noqa: BLE001 - 预热绝不能影响主流程
            ok, detail = False, f"预热异常: {exc}"
        # 留痕失败也不该炸掉线程 (审计是"尽量留痕", 不是主流程)。
        with contextlib.suppress(Exception):
            from .config import audit, load_state, save_state

            if _paths()["state"] != home_state_path:
                return
            fresh = load_state()
            audit(fresh, "chain_warmup" if ok else "chain_warmup_failed", detail, actor="system")
            save_state(fresh)

    threading.Thread(target=run, name="zp-chain-warmup", daemon=True).start()
