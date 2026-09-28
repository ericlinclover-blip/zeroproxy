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
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
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
_IPV6_RE_FIND = re.compile(r"(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}", re.I)

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HEX_RE = re.compile(r"^[0-9a-f]{0,16}$", re.I)
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
) -> str:
    """把落地端的连接参数打包成一行配对码 (字段名压到 1 个字母, 码更短)。"""
    payload = {
        "v": 1,
        "h": host,
        "p": int(port),
        "u": uuid,
        "k": pbk,
        "s": sid or "",
        "n": sni,
        "f": flow,
        "l": label or "",
    }
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return CODE_SEP.join((CODE_PREFIX, _b64e(raw), _checksum(raw)))


def parse_code(text: str) -> dict:
    """解析 + 严格校验配对码。出错抛 CodeError (中文说明, 直接给用户看)。"""
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
    if not isinstance(payload, dict) or int(payload.get("v") or 0) != 1:
        raise CodeError("配对码版本不认识 (可能来自更新版本的面板), 请升级本机程序后重试")

    host = str(payload.get("h") or "").strip()
    sni = str(payload.get("n") or "").strip().lower()
    uid = str(payload.get("u") or "").strip().lower()
    pbk = str(payload.get("k") or "").strip()
    sid = str(payload.get("s") or "").strip().lower()
    flow = str(payload.get("f") or "")
    try:
        port = int(payload.get("p"))
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

    return {
        "host": host,
        "port": port,
        "uuid": uid,
        "pbk": pbk,
        "sid": sid,
        "sni": sni,
        "flow": flow,
        "label": str(payload.get("l") or "").strip()[:40],
    }


def exit_code(state: dict) -> str:
    """本机作为落地端时给对方的配对码 (关闭 / 没生成过凭据就返回空串)。"""
    exit_cfg = (state.get("chain") or {}).get("exit") or {}
    uid = str(exit_cfg.get("uuid") or "")
    if not uid or not exit_cfg.get("enabled"):
        return ""
    reality = state.get("reality") or {}
    return make_code(
        host=state.get("domain") or "",
        port=int(exit_cfg.get("port") or DEFAULT_EXIT_PORT),
        uuid=uid,
        pbk=str(reality.get("public_key") or ""),
        sid=str(reality.get("short_id") or ""),
        sni=str(reality.get("server_name") or ""),
        flow="xtls-rprx-vision",
        label=str(exit_cfg.get("label") or "") or (state.get("domain") or ""),
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
    """
    per_try = max(3.0, min(float(timeout), 6.0))
    last = "没有可用的出口 IP 回显服务"
    for url in IP_ECHO:
        host, _, path = url[len("http://"):].partition("/")
        body, detail = services.socks5_http_get(socks_port, host, 80, "/" + path, per_try)
        last = f"{host}: {detail}"
        found = _IPV4_RE_FIND.search(body or "") or _IPV6_RE_FIND.search(body or "")
        if found:
            return found.group(0), "HTTP 往返成功"
    return "", last


def probe_target(target: dict, timeout: float = 10.0) -> dict:
    """真的穿过落地端出一次网, 并读回落地出口 IP。

    返回 {"ok", "probe_ok", "ms", "exit_ip", "detail"}。`probe_ok=False` 表示
    "本机环境不允许探测" (没有 xray 二进制等), 与"配错了连不通"区分开 ——
    前者不该拦住用户, 后者才该拦住 (由调用方决定要不要 force)。
    """
    started = time.perf_counter()
    reachable, tcp_ms, tcp_detail = services.tcp_connect_ms(target["host"], target["port"], 5.0)
    if not reachable:
        return {
            "ok": False,
            "probe_ok": True,
            "ms": None,
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
            return {"ok": False, "probe_ok": True, "ms": None, "exit_ip": "", "detail": wait_err}
        ip, detail = read_exit_ip(socks_port, timeout)
        if ip:
            return {
                "ok": True,
                "probe_ok": True,
                "ms": round((time.perf_counter() - started) * 1000, 1),
                "exit_ip": ip,
                "detail": f"链路通, 落地出口 IP {ip}",
            }
        return {
            "ok": False,
            "probe_ok": True,
            "ms": None,
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
    }
