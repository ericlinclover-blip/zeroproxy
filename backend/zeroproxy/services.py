"""系统服务适配层: systemctl / certbot / 自签证书 / 服务器信息。

非 Linux 环境 (如 macOS 本地开发) 自动降级为 dry-run:
配置照常生成, 服务操作记录为 "跳过 (无 systemctl)", 保证面板全流程可本地验证。
"""
from __future__ import annotations

import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .config import NODE_BY_ID, paths

# 服务名 → 二进制 (用于版本探测)
SERVICES = {
    "xray": "xray",
    "hysteria2": "hysteria",
    "nginx": "nginx",
}

#: 需要统计流量的 Xray 入站 tag (api 入站本身不计入用户流量)
TRAFFIC_TAGS = ("vless-reality", "vless-xhttp", "vless-ws", "trojan")


def bin_path(name: str) -> str | None:
    """二进制路径。

    默认取 PATH 中的命令; 可用 ZP_XRAY_BIN / ZP_HYSTERIA_BIN / ZP_NGINX_BIN
    指定绝对路径 (自定义安装位置, 或在 macOS 上做真实二进制验证)。
    """
    override = os.environ.get(f"ZP_{name.upper()}_BIN", "").strip()
    if override:
        return override if os.path.exists(override) else None
    return shutil.which(SERVICES.get(name, name))


def is_prod() -> bool:
    """是否在具备 systemd 的 Linux 生产环境。"""
    return sys.platform.startswith("linux") and shutil.which("systemctl") is not None


def run(cmd: list[str], timeout: int = 120, env: dict | None = None) -> tuple[bool, str]:
    """执行外部命令。env 为额外环境变量 (叠加在 os.environ 之上)。"""
    child_env = None
    if env:
        child_env = {**os.environ, **env}
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=child_env)
    except FileNotFoundError:
        return False, f"命令不存在: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return False, f"超时 ({timeout}s): {' '.join(cmd[:3])} ..."
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode == 0, output.strip()


def service_state(name: str) -> str:
    """active / failed / inactive / unavailable / dry-run。"""
    if not is_prod():
        return "dry-run"
    if bin_path(name) is None:
        return "not-installed"
    ok, out = run(["systemctl", "is-active", name], timeout=15)
    state = out.strip().splitlines()[0] if out.strip() else "unknown"
    return state if state else "inactive"


def restart_service(name: str, timeout: int = 90) -> tuple[bool, str]:
    if not is_prod():
        return False, "跳过 (非生产环境, 无 systemctl)"
    ok, out = run(["systemctl", "restart", name], timeout=timeout)
    if ok:
        return True, "已重启"
    return False, f"重启失败: {out[:200]}"


def reload_service(name: str, timeout: int = 60) -> tuple[bool, str]:
    if not is_prod():
        return False, "跳过 (非生产环境, 无 systemctl)"
    ok, out = run(["systemctl", "reload", name], timeout=timeout)
    if not ok:
        ok, out = run(["systemctl", "restart", name], timeout=timeout)  # nginx 某些版本无 reload
    return (ok, "已重载") if ok else (False, f"重载失败: {out[:200]}")


#: 终端颜色等控制序列
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
#: 块字符 / 制表字符 (U+2500-U+259F): Hysteria 2 的 `version` 会先打一段这种 banner
_ART_RE = re.compile(r"[\u2500-\u259f]")
#: `Version:\tv2.12.3` 这种明确带标签的行最可信, 优先取它
_VERSION_LABEL_RE = re.compile(r"^version\s*[:=]\s*(\S+)", re.IGNORECASE)
#: 退而求其次: 行里能找到一个 x.y[.z] 形式的版本号
_VERSION_TOKEN_RE = re.compile(r"v?\d+(?:\.\d+)+[\w.+-]*")


def version_from_output(out: str) -> str:
    """从 `xxx version` 的输出里挑出版本行。

    坑 (真机踩到过): Hysteria 2 的 `hysteria version` 先打一段块字符 banner
    (`░█░█░█░█░█▀▀░▀█▀░█▀▀…`), 旧实现直接取第一行 → 面板的「Hysteria 2 运行中 ·」
    后面挂了一串花屏方块。这里先剥掉控制序列和 banner, 再优先认 `Version: x.y.z`。
    """
    lines = []
    for raw in _ANSI_RE.sub("", out).splitlines():
        line = " ".join(raw.replace("\t", " ").split())
        if line:
            lines.append(line)
    for line in lines:
        match = _VERSION_LABEL_RE.match(line)
        if match:
            return match.group(1)[:80]
    for line in lines:
        if _ART_RE.search(line):
            continue
        if _VERSION_TOKEN_RE.search(line):
            return line[:80]
    # 没有可信的版本行就不要硬凑: 宁可让面板只显示"运行中", 也不把 banner 当版本号
    return lines[0][:80] if lines and not _ART_RE.search(lines[0]) else ""


def service_version(name: str) -> str:
    path = bin_path(name)
    if path is None:
        return ""
    ok, out = run([path, "version"], timeout=15)
    if not ok:
        return ""
    return version_from_output(out)


def server_info() -> dict:
    info = {
        "os": f"{platform.system()} {platform.release()}",
        "arch": _machine(),
        "uptime_s": _uptime(),
        "panel_version": __import__("zeroproxy").__version__,
    }
    if sys.platform.startswith("linux") and os.path.exists("/etc/os-release"):
        try:
            for line in open("/etc/os-release", encoding="utf-8"):
                if line.startswith("PRETTY_NAME="):
                    info["os"] = line.split("=", 1)[1].strip().strip('"')
                    break
        except OSError:
            pass
    return info


def _machine() -> str:
    machine = platform.machine().lower()
    return {"x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(machine, machine)


def _uptime() -> int:
    try:
        with open("/proc/uptime", encoding="utf-8") as fh:
            return int(float(fh.read().split()[0]))
    except (OSError, ValueError, IndexError):
        return 0


def is_domain(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        return True


def generate_self_signed(
    host: str, cert_path: str, key_path: str, days: int = 3650
) -> tuple[bool, str]:
    """生成自签名证书 (域名或 IP)。certbot 不可用时的兜底方案。"""
    try:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if is_domain(host):
            name_attr = x509.NameAttribute(NameOID.COMMON_NAME, host)
            san = [x509.DNSName(host)]
        else:
            name_attr = x509.NameAttribute(NameOID.COMMON_NAME, host)
            san = [x509.IPAddress(ipaddress.ip_address(host))]
        name = x509.Name([name_attr])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .sign(key, hashes.SHA256())
        )
        os.makedirs(os.path.dirname(cert_path), exist_ok=True)
        with open(cert_path, "wb") as fh:
            fh.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as fh:
            fh.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )
        os.chmod(key_path, 0o600)
        return True, f"自签名证书 {host} ({days} 天)"
    except Exception as exc:  # noqa: BLE001
        return False, f"自签证书生成失败: {exc}"


def install_cert(host: str) -> tuple[bool, str, dict]:
    """申请 TLS 证书: 优先 Let's Encrypt (webroot), 失败回退自签。

    返回 (成功, 说明, cert_state)。
    """
    p = paths()
    webroot = p["www"]
    os.makedirs(webroot, exist_ok=True)
    detail = ""

    if is_domain(host) and is_prod() and shutil.which("certbot") and host != "":
        ok, out = run(
            [
                "certbot", "certonly",
                "--webroot", "-w", webroot,
                "-d", host,
                "--non-interactive",
                "--agree-tos",
                "--register-unsafely-without-email",
                # 重复执行 /api/apply 时: 已有证书且未临近过期则复用, 需要时自动扩展域名
                "--keep-until-expiring",
                "--expand",
            ],
            timeout=300,
        )
        if ok:
            live = f"/etc/letsencrypt/live/{host}"
            if os.path.exists(f"{live}/fullchain.pem"):
                run(["systemctl", "enable", "certbot.timer"], timeout=60)  # 自动续期
                not_after = _cert_not_after(f"{live}/fullchain.pem")
                return True, "Let's Encrypt 证书已签发 (90 天, 自动续期)", {
                    "type": "letsencrypt",
                    "issuer": "Let's Encrypt",
                    "cert_file": f"{live}/fullchain.pem",
                    "key_file": f"{live}/privkey.pem",
                    "not_after": not_after,
                }
        detail = "Let's Encrypt 申请失败 (域名未解析? 80 端口未开放?)"

    ok, detail2 = generate_self_signed(host, p["cert_file"], p["cert_key"])
    if ok:
        return True, f"{detail} → 已回退自签证书", {
            "type": "selfsigned",
            "issuer": "ZeroProxy 自签",
            "cert_file": p["cert_file"],
            "key_file": p["cert_key"],
            "not_after": int(time.time()) + 3650 * 86400,
        }
    return False, f"{detail}; {detail2}", {
        "type": "none", "issuer": "", "cert_file": "", "key_file": "", "not_after": 0
    }


def generate_hysteria_cert(host: str) -> tuple[bool, str]:
    """Hysteria 2 自签证书 (客户端 sni + insecure 校验, 无需 CA)。"""
    p = paths()
    return generate_self_signed(host, p["hysteria_cert"], p["hysteria_key"])


def renew_cert(state: dict) -> tuple[bool, str]:
    """续期已有证书; 当前还是自签证书时, 补签一次 Let's Encrypt。

    「部署时申请失败 → 回退自签 → 之后再也没有机会拿到正式证书」是个死角:
    过去这里只要证书不是 letsencrypt 就直接拒绝, 而 /api/setup 又只能跑一次。
    """
    if not is_prod():
        return False, "跳过 (非生产环境, 无 systemd)"
    if not shutil.which("certbot"):
        return False, "certbot 未安装 (apt-get install -y certbot 后重试)"
    if (state.get("cert") or {}).get("type") == "letsencrypt":
        ok, out = run(["certbot", "renew", "--non-interactive", "--quiet"], timeout=300)
        if not ok:
            return False, f"续期失败: {out[:200]}"
        ok2, _ = reload_service("nginx")
        return ok2, "证书已续期"
    ok, detail, cert_state = install_cert(state["domain"])
    state["cert"] = cert_state
    if cert_state.get("type") == "letsencrypt":
        return True, detail
    return False, detail or "Let's Encrypt 申请失败 (域名未解析? 80 端口未开放?)"


def _cert_not_after(cert_file: str) -> int:
    try:
        from cryptography import x509 as _x509

        with open(cert_file, "rb") as fh:
            cert = _x509.load_pem_x509_certificate(fh.read())
        return int(cert.not_valid_after_utc.timestamp())
    except Exception:  # noqa: BLE001
        return 0


# ---------------------------------------------------------------- 流量统计

def xray_stats(state: dict) -> Optional[dict]:
    """通过本机 Stats API 读取流量统计。

    返回 {"uplink", "downlink", "total", "by_node"} (字节); 未安装 xray /
    非生产环境 / API 不可达时返回 None, 调用方应展示「不可用」。
    """
    binary = bin_path("xray")
    if binary is None:
        return None
    api_port = int(state["ports"].get("api", 10085))
    # 先做一次 0.4s 的 TCP 预检: 端口没开时 `xray api` 自己要等 2-3 秒才报错,
    # 而仪表盘每次渲染都会调这里 (20s 轮询), 不预检会白白拖慢整个面板。
    if not _tcp_reachable("127.0.0.1", api_port, timeout=0.4):
        return None
    addr = f"127.0.0.1:{api_port}"
    ok, out = run(
        [binary, "api", "statsquery", f"--server={addr}", "-pattern", ""],
        timeout=20,
        env=xray_env(),
    )
    if not ok:
        return None
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return None

    by_node: dict[str, dict] = {tag: {"uplink": 0, "downlink": 0} for tag in TRAFFIC_TAGS}
    uplink = downlink = 0
    for item in data.get("stat", []):
        name = item.get("name", "")
        parts = name.split(">>>")
        # 形如 inbound>>>vless-reality>>>traffic>>>uplink
        if len(parts) != 4 or parts[0] != "inbound":
            continue
        tag, direction = parts[1], parts[3]
        if tag not in by_node or direction not in ("uplink", "downlink"):
            continue
        value = int(item.get("value", 0) or 0)
        by_node[tag][direction] += value
        if direction == "uplink":
            uplink += value
        else:
            downlink += value
    return {
        "uplink": uplink,
        "downlink": downlink,
        "total": uplink + downlink,
        "by_node": by_node,
        "available": True,
    }


# ---------------------------------------------------------------- 自检 / 诊断

def port_available(port: int, proto: str = "tcp") -> bool:
    """端口是否空闲 (用绑定探测, 不依赖 lsof/ss)。"""
    family = socket.AF_INET
    sock_type = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
    with socket.socket(family, sock_type) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", int(port)))
        except OSError:
            return False
    return True


def journal_tail(name: str, lines: int = 40) -> str:
    """服务日志尾部 (仅 Linux/systemd)。"""
    if not is_prod() or shutil.which("journalctl") is None:
        return "非生产环境, 无 journalctl"
    ok, out = run(["journalctl", "-u", name, "-n", str(int(lines)), "--no-pager"], timeout=20)
    return out if ok else f"读取失败: {out[:200]}"


def xray_config_test() -> tuple[bool, str]:
    """生产环境下用 `xray -test` 校验现网配置。"""
    binary = bin_path("xray")
    if binary is None:
        return True, "跳过 (未安装 xray)"
    ok, out = run(
        [binary, "-test", "-c", paths()["xray_config"]], timeout=60, env=xray_env()
    )
    return ok, " ".join(out.split())[:200]


# ---------------------------------------------------------------- 连通性探测

def _tcp_reachable(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False

def xray_env() -> dict:
    """Xray 进程需要的额外环境变量。

    Xray 只从「可执行文件所在目录」或 `XRAY_LOCATION_ASSET` 找 geoip.dat /
    geosite.dat —— 不设这个变量, 面板生成的 geo 分流规则会让 Xray 直接启动
    失败 (见 geodata.py 顶部说明)。因此所有 xray 调用都统一带上它。
    """
    from .config import paths as _paths

    geo = _paths()["geo_dir"]
    if os.path.isdir(geo):
        return {"XRAY_LOCATION_ASSET": geo}
    return {}


def tcp_connect_ms(host: str, port: int, timeout: float = 3.0) -> tuple[bool, float, str]:
    """TCP 握手耗时 (毫秒)。返回 (可达, ms, 说明)。"""
    start = time.perf_counter()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True, (time.perf_counter() - start) * 1000, "TCP 握手成功"
    except OSError as exc:
        return False, -1.0, f"{type(exc).__name__}: {exc}"


def tls_handshake_ms(
    host: str, port: int, sni: str = "", timeout: float = 5.0
) -> tuple[bool, float, str]:
    """TLS 握手耗时 (毫秒)。

    这是本面板最有价值的节点体检: 对 Reality 入站做一次真实 TLS 握手 — 若
    dest / serverName / 密钥不匹配, 握手会失败; 对 Trojan / WS 则同时验证了
    证书链与 nginx 反代是否通。证书校验关闭 (自签 / Reality 会转发目标站点
    证书, 本机无从建立信任链)。
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])
    start = time.perf_counter()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni or host) as tls:
                tls.version()
        return True, (time.perf_counter() - start) * 1000, "TLS 握手成功"
    except (OSError, ssl.SSLError) as exc:
        return False, -1.0, f"{type(exc).__name__}: {exc}"


def udp_port_listening(port: int) -> bool | None:
    """UDP 端口是否有进程在监听 (Hysteria 2 无法用 TCP 探测)。

    Linux 读 /proc/net/udp*, 其他平台退回 lsof; 都不可用时返回 None (未知)。
    """
    hexed = f"{int(port):04X}"
    for proc_file in ("/proc/net/udp", "/proc/net/udp6"):
        if not os.path.exists(proc_file):
            continue
        try:
            with open(proc_file, "r", encoding="utf-8") as fh:
                next(fh, None)  # 跳过表头
                for line in fh:
                    parts = line.split()
                    if len(parts) > 1 and parts[1].rsplit(":", 1)[-1].upper() == hexed:
                        return True
            return False
        except OSError:
            break
    if shutil.which("lsof"):
        ok, out = run(["lsof", "-nP", f"-iUDP:{int(port)}"], timeout=10)
        if ok and out.strip():
            return True
        return False
    return None


def _probe_target(state: dict, node_id: str) -> tuple[str, str, int, str]:
    """(host, 探测方式, 端口, SNI) — 探测方式 ∈ tcp / tls / udp。"""
    ports = state.get("ports", {})
    if node_id == "vless-ws":
        # WS 入站是明文回环端口, TLS 由 nginx 终结 —— 这里只验证入站存活
        return "127.0.0.1", "tcp", int(ports.get("ws_internal", 6000)), ""
    if node_id == "hysteria2":
        return "127.0.0.1", "udp", int(ports.get("hysteria", 30001)), ""
    key = NODE_BY_ID[node_id]["port_key"]
    sni = state["reality"]["server_name"] if key in ("reality", "xhttp") else state.get("domain", "")
    return "127.0.0.1", "tls", int(ports.get(key, 0)), sni


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """读满 n 字节 (或对端关闭/超时)。"""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


def _socks5_open(sock: socket.socket, host: str, port: int) -> tuple[bool, str]:
    """在已连上的 socket 上完成 SOCKS5 协商 + CONNECT, 返回 (是否成功, 说明)。

    坑 (真机踩到过): 必须把**整个回复**读完 —— Xray 的 SOCKS 入站回的是 10 字节
    (`05 00 00 01` + BND.ADDR `0.0.0.0` + BND.PORT `0`), 只读 4 字节会把剩下的 6 字节
    留在接收缓冲区里, 紧接着的 TLS 记录头就被读成 `000000000000` → 客户端报
    `WRONG_VERSION_NUMBER`, 面板上表现为"节点全部握手失败", 而这 4 个节点其实完全正常。
    """
    sock.sendall(b"\x05\x01\x00")
    greeting = _recv_exact(sock, 2)
    if len(greeting) < 2 or greeting[0] != 5 or greeting[1] != 0:
        return False, "SOCKS5 协商失败"
    addr = host.encode()
    if len(addr) > 255:
        return False, "SOCKS5 目标域名过长"
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(addr)]) + addr + int(port).to_bytes(2, "big"))
    head = _recv_exact(sock, 4)
    if len(head) < 4 or head[0] != 5:
        return False, "SOCKS5 回复不完整"
    if head[1] != 0:
        return False, f"SOCKS5 连接被拒 (code={head[1]})"
    atyp = head[3]
    if atyp == 1:      # IPv4
        tail = 4 + 2
    elif atyp == 4:    # IPv6
        tail = 16 + 2
    else:              # 域名: 1 字节长度 + 域名 + 端口
        n = _recv_exact(sock, 1)
        if not n:
            return False, "SOCKS5 回复不完整"
        tail = n[0] + 2
    if len(_recv_exact(sock, tail)) < tail:
        return False, "SOCKS5 回复不完整"
    return True, "已建立隧道"


def _socks5_tls_probe(proxy_port: int, host: str, port: int, timeout: float = 8.0) -> tuple[bool, float, str]:
    """经本地 SOCKS5 隧道对目标做一次真实 TLS 握手 —— 节点深度体检的判据。

    只做 SOCKS5 CONNECT 是不够的: Xray 的 SOCKS 入站会**先回成功**再尝试dial,
    节点不通时失败发生在之后 (连接被关掉)。因此必须真的跑一次往返 —— 这里让
    TLS 握手穿过隧道直达伪装目标: 通了就说明"客户端→节点→服务器出站→目标"
    整条链路都在工作。
    """
    start = time.perf_counter()
    sock = None
    try:
        sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
        sock.settimeout(timeout)
        ok, detail = _socks5_open(sock, host, port)
        if not ok:
            return False, -1.0, detail
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            tls.version()
        sock = None
        return True, (time.perf_counter() - start) * 1000, f"隧道 + 到 {host} 的 TLS 往返成功"
    except (OSError, ssl.SSLError) as exc:
        return False, -1.0, f"{type(exc).__name__}: {exc}"
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:  # pragma: no cover
                pass


def _cert_sha256_hex(cert_file: str) -> str:
    """叶子证书 DER 的 SHA256 (十六进制) —— Xray 26 的 `pinnedPeerCertSha256` 格式。"""
    try:
        with open(cert_file, "rb") as fh:
            data = fh.read()
        leaf = x509.load_pem_x509_certificate(data)   # fullchain 的第一张就是叶子
        digest = hashes.Hash(hashes.SHA256())
        digest.update(leaf.public_bytes(serialization.Encoding.DER))
        return digest.finalize().hex()
    except (OSError, ValueError):
        return ""


def client_tls_settings(state: dict) -> dict:
    """Xray 26 客户端可用的 TLS 设置。

    坑: Xray 25 起 `allowInsecure` 已被移除 (26.3 上直接拒绝加载配置, 报
    "The feature allowInsecure has been removed and migrated to pinnedPeerCertSha256"),
    自签证书场景必须改成固定对端证书指纹; 真实 CA 证书 (Let's Encrypt) 正常校验即可。
    """
    domain = state.get("domain", "")
    cert = state.get("cert", {})
    cert_file = cert.get("cert_file") or ""
    settings: dict = {"serverName": domain}
    if cert.get("type") != "letsencrypt" and cert_file:
        pin = _cert_sha256_hex(cert_file)
        if pin:
            settings["pinnedPeerCertSha256"] = pin
    return settings


def client_config(state: dict, node_id: str, socks_port: int) -> dict | None:
    """把一个节点渲染成最小可用的 Xray 客户端配置 (含本地 SOCKS 入站)。

    这是面板"深度体检"用的: 客户端 → 节点 → 出站 走完整链路, Reality 的
    密钥 / SNI / 伪装目标 / 传输层任何一处不对都会连不通。Hysteria 2 需要
    hysteria 客户端, 这里不支持 (返回 None)。
    """
    reality = state["reality"]
    ports = state.get("ports", {})
    domain = state.get("domain", "")
    uuid = state.get("uuid", "")
    common = {"serverName": reality["server_name"], "fingerprint": "chrome"}
    outbound: dict | None = None

    if node_id == "vless-reality":
        outbound = {
            "protocol": "vless",
            "settings": {"vnext": [{"address": "127.0.0.1", "port": int(ports["reality"]),
                                    "users": [{"id": uuid, "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
            "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                **common, "publicKey": reality["public_key"], "shortId": reality["short_id"], "spiderX": "/"}},
        }
    elif node_id == "vless-xhttp":
        xhttp = state.get("xhttp", {})
        outbound = {
            "protocol": "vless",
            "settings": {"vnext": [{"address": "127.0.0.1", "port": int(ports["xhttp"]),
                                    "users": [{"id": uuid, "encryption": "none", "flow": ""}]}]},
            "streamSettings": {"network": "xhttp", "security": "reality",
                               "xhttpSettings": {"host": xhttp.get("host") or reality["server_name"],
                                                 "path": xhttp.get("path") or "/",
                                                 "mode": xhttp.get("mode") or "auto"},
                               "realitySettings": {
                                   **common, "publicKey": reality["public_key"],
                                   "shortId": reality["short_id"], "spiderX": "/"}},
        }
    elif node_id == "vless-ws":
        from .config import WS_PATH

        outbound = {
            "protocol": "vless",
            "settings": {"vnext": [{"address": domain, "port": 443,
                                    "users": [{"id": uuid, "encryption": "none", "flow": ""}]}]},
            "streamSettings": {"network": "ws", "security": "tls",
                               "wsSettings": {"path": WS_PATH, "headers": {"Host": domain}},
                               "tlsSettings": client_tls_settings(state)},
        }
    elif node_id == "trojan":
        outbound = {
            "protocol": "trojan",
            "settings": {"servers": [{"address": domain, "port": int(ports["trojan"]),
                                      "password": state.get("trojan_password", "")}]},
            "streamSettings": {"network": "tcp", "security": "tls",
                               "tlsSettings": client_tls_settings(state)},
        }

    if outbound is None:
        return None
    outbound["tag"] = "node"
    return {
        "log": {"loglevel": "error"},
        "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks",
                      "settings": {"udp": False}}],
        "outbounds": [outbound],
    }


def deep_probe_node(state: dict, node_id: str, timeout: float = 9.0) -> dict:
    """节点深度体检: 起一个临时客户端, 真的从节点穿到外网。

    为什么需要它: 只做 TLS 握手的浅探测无法发现 Reality 认证失败 —— 认证失败时
    服务端会**回落到真实伪装站点**, 裸 TLS 握手照样成功 (这正是"面板全绿但节点
    不通"的来源)。这里用真实 Xray 客户端 + 真实数据面, 任何一处不匹配都过不去。
    """
    import tempfile

    from .config import NODE_BY_ID

    if not state.get("nodes", {}).get(node_id, True):
        return {"node": node_id, "ok": None, "kind": "deep", "ms": None, "detail": "节点已关闭"}

    if node_id == "trojan" and not os.path.exists(state["cert"].get("cert_file") or ""):
        return {"node": node_id, "ok": False, "kind": "deep", "ms": None,
                "detail": "证书未就绪, 入站未生效"}

    binary = bin_path("xray")
    if not binary:
        return {"node": node_id, "ok": None, "kind": "deep", "ms": None,
                "detail": "xray 二进制不可用, 无法深度体检"}
    socks_port = _free_port()
    config = client_config(state, node_id, socks_port)
    if config is None:
        return {"node": node_id, "ok": None, "kind": "deep", "ms": None,
                "detail": "该节点不支持深度体检"}

    host, port = state["reality"]["dest"].rsplit(":", 1)
    workdir = tempfile.mkdtemp(prefix="zp-probe-")
    cfg_path = os.path.join(workdir, "client.json")
    with open(cfg_path, "w", encoding="utf-8") as fh:
        json.dump(config, fh)
    proc = subprocess.Popen(
        [binary, "run", "-c", cfg_path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={**os.environ, **xray_env()},
    )
    try:
        deadline = time.time() + 4
        while time.time() < deadline and not _tcp_reachable("127.0.0.1", socks_port, 0.3):
            if proc.poll() is not None:
                return {"node": node_id, "ok": False, "kind": "deep", "ms": None,
                        "detail": "临时客户端启动失败 (xray 退出, 详见 journalctl -u xray)"}
            time.sleep(0.15)
        if not _tcp_reachable("127.0.0.1", socks_port, 0.3):
            return {"node": node_id, "ok": False, "kind": "deep", "ms": None,
                    "detail": "临时客户端 SOCKS 端口未就绪"}
        ok, ms, detail = _socks5_tls_probe(socks_port, host, int(port or 443), timeout=timeout)
        port_label = NODE_BY_ID[node_id]["port_key"]
        shown = 443 if node_id in ("vless-ws",) else state["ports"].get(port_label, "")
        if ok:
            return {"node": node_id, "ok": True, "kind": "deep", "ms": round(ms, 1),
                    "detail": f"{shown} · 深度握手 + 真实出口往返 ({state['reality']['dest']}) 通过"}
        return {"node": node_id, "ok": False, "kind": "deep", "ms": None,
                "detail": f"{shown} · {detail} (Reality 密钥/SNI/伪装目标 或传输层不匹配)"}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:  # pragma: no cover - 兜底
            proc.kill()
        shutil.rmtree(workdir, ignore_errors=True)


def probe_node(state: dict, node_id: str, timeout: float = 4.0) -> dict:
    """单节点体检: 握手耗时 + 结论。"""
    if not state.get("nodes", {}).get(node_id, True):
        return {"node": node_id, "ok": None, "kind": "off", "ms": None, "detail": "节点已关闭"}

    if node_id == "trojan" and not os.path.exists(state["cert"].get("cert_file") or ""):
        return {
            "node": node_id,
            "ok": False,
            "kind": "tls",
            "ms": None,
            "detail": "证书未就绪, 入站未生效",
        }

    host, kind, port, sni = _probe_target(state, node_id)
    if not port:
        return {"node": node_id, "ok": False, "kind": kind, "ms": None, "detail": "端口未配置"}

    if kind == "tcp":
        ok, ms, detail = tcp_connect_ms(host, port, timeout)
    elif kind == "tls":
        ok, ms, detail = tls_handshake_ms(host, port, sni, timeout)
    else:
        listening = udp_port_listening(port)
        if listening is None:
            return {
                "node": node_id,
                "ok": None,
                "kind": "udp",
                "ms": None,
                "detail": f"UDP {port} 无法主动探测 (环境不支持)",
            }
        return {
            "node": node_id,
            "ok": listening,
            "kind": "udp",
            "ms": None,
            "detail": f"UDP {port} {'监听中' if listening else '未监听'}",
        }
    return {
        "node": node_id,
        "ok": bool(ok),
        "kind": kind,
        "ms": round(ms, 1) if ok else None,
        "detail": f"{port} · {detail}",
    }


def deep_probe_all(state: dict, timeout: float = 9.0) -> list[dict]:
    """对 4 个 TCP 节点逐个做深度体检 (串行: 单核小内存 VPS 上别同时起 4 个内核)。"""
    results = []
    for nid in ("vless-reality", "vless-xhttp", "vless-ws", "trojan"):
        try:
            results.append(deep_probe_node(state, nid, timeout))
        except Exception as exc:  # noqa: BLE001 — 体检异常不能让接口 500
            results.append({"node": nid, "ok": False, "kind": "deep", "ms": None,
                            "detail": f"深度体检异常: {exc}"})
    return results


def probe_all(state: dict, timeout: float = 4.0, deep: bool = False) -> dict:
    """全部节点 + 服务器出网 RTT。每个节点独立线程, 最慢一项决定总耗时。

    deep=True 时对 4 个 TCP 节点改用"真实客户端穿一次"的深度体检 (见
    deep_probe_node); 本地开发 / 无 xray 二进制时自动退回浅探测。
    """
    from concurrent.futures import ThreadPoolExecutor

    from .config import NODE_IDS

    nodes = list(NODE_IDS)
    dest_host, dest_port = state["reality"]["dest"].rsplit(":", 1)
    if deep and is_prod() and bin_path("xray") is not None:
        results = deep_probe_all(state, max(timeout, 9.0))
        results.append(probe_node(state, "hysteria2", timeout))
        dest_ok, dest_ms, dest_detail = tcp_connect_ms(dest_host, int(dest_port or 443), max(timeout, 5.0))
    else:
        with ThreadPoolExecutor(max_workers=min(6, len(nodes) + 1)) as pool:
            futures = {nid: pool.submit(probe_node, state, nid, timeout) for nid in nodes}
            dest = pool.submit(tcp_connect_ms, dest_host, int(dest_port or 443), max(timeout, 5.0))
            results = []
            for nid in nodes:
                try:
                    results.append(futures[nid].result())
                except Exception as exc:  # noqa: BLE001
                    results.append(
                        {"node": nid, "ok": False, "kind": "?", "ms": None, "detail": f"探测异常: {exc}"}
                    )
            dest_ok, dest_ms, dest_detail = dest.result()

    ok_count = sum(1 for r in results if r["ok"])
    label = "深度握手" if deep and is_prod() and bin_path("xray") is not None else "握手"
    return {
        "checked_at": int(time.time()),
        "nodes": results,
        "deep": bool(deep),
        "summary": f"{ok_count}/{len(results)} 个节点{label}成功",
        "dest": {
            "address": state["reality"]["dest"],
            "ok": dest_ok,
            "ms": round(dest_ms, 1) if dest_ok else None,
            "detail": dest_detail,
        },
    }
