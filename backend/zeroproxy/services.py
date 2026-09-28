"""系统服务适配层: systemctl / certbot / 自签证书 / 服务器信息。

非 Linux 环境 (如 macOS 本地开发) 自动降级为 dry-run:
配置照常生成, 服务操作记录为 "跳过 (无 systemctl)", 保证面板全流程可本地验证。
"""
from __future__ import annotations

import ipaddress
import os
import platform
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .config import paths

# 服务名 → 二进制 (用于版本探测)
SERVICES = {
    "xray": "xray",
    "hysteria2": "hysteria",
    "nginx": "nginx",
}


def is_prod() -> bool:
    """是否在具备 systemd 的 Linux 生产环境。"""
    return sys.platform.startswith("linux") and shutil.which("systemctl") is not None


def run(cmd: list[str], timeout: int = 120) -> tuple[bool, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
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
    if shutil.which(SERVICES.get(name, name)) is None:
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


def service_version(name: str) -> str:
    binary = SERVICES.get(name, name)
    if shutil.which(binary) is None:
        return ""
    ok, out = run([binary, "version"], timeout=15)
    if not ok:
        return ""
    first = out.strip().splitlines()[0] if out.strip() else ""
    return first[:80]


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
    if state["cert"]["type"] != "letsencrypt" or not is_prod() or not shutil.which("certbot"):
        return False, "无可续期的 Let's Encrypt 证书"
    ok, out = run(["certbot", "renew", "--non-interactive", "--quiet"], timeout=300)
    if ok:
        ok2, _ = reload_service("nginx")
        return ok2, "证书已续期"
    return False, f"续期失败: {out[:200]}"


def _cert_not_after(cert_file: str) -> int:
    try:
        from cryptography import x509 as _x509

        with open(cert_file, "rb") as fh:
            cert = _x509.load_pem_x509_certificate(fh.read())
        return int(cert.not_valid_after_utc.timestamp())
    except Exception:  # noqa: BLE001
        return 0
