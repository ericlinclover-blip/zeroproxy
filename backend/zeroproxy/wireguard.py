"""WireGuard 入站 — 原生 UDP 节点，给官方 WireGuard 客户端直接连接。

WireGuard 不是能挂到 Xray 入站上的代理协议，而是 UDP + 内核接口；官方客户端要的是
标准 `.conf` / 二维码，不是 vless:// 链接。因此这里走「每台设备一份配置」的原生路径，
与 wg-easy / wg-ui 这类成熟面板一致。

设计要点:
  * 服务端密钥只生成一次并持久化；每个 peer 独立密钥 + 独立 PSK；
  * 地址确定性分配，删除后回收；
  * 配置变更用 `wg syncconf` 增量同步，不 down/up 整条隧道；
  * 防火墙规则独立成脚本，iptables 优先（与 ufw 共存），没有 iptables 时退 nftables；
  * 客户端配置、二维码、一次性链接、过期时间、握手/流量都从同一份 state 派生。
"""
from __future__ import annotations

import base64
import copy
import hmac
import ipaddress
import os
import re
import secrets
import shutil
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from . import config, services
from .config import paths

INTERFACE = "wg0"
SERVICE = "zeroproxy-wg"
SERVICE_USERSPACE = "zeroproxy-wg-userspace"

DEFAULT_PORT = 51820
DEFAULT_SUBNET = "10.66.66.0/24"
DEFAULT_IPV6_SUBNET = "fd66:66:66::/64"
DEFAULT_MTU = 1420
DEFAULT_DNS = "1.1.1.1, 8.8.8.8"
DEFAULT_KEEPALIVE = 25
DEFAULT_ALLOWED_IPS = "0.0.0.0/0"

MAX_PEERS = 128
ONE_TIME_TTL = 10 * 60
MAX_ONE_TIME = 32

_NAME_RE = re.compile(r"[\x00-\x1f\x7f]")


def _now() -> int:
    return int(time.time())


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _raw_key(value: str, length: int = 32) -> bytes:
    if not isinstance(value, str):
        raise ValueError("密钥不是字符串")
    text = value.strip()
    if not text:
        raise ValueError("密钥为空")
    try:
        raw = base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("密钥不是合法 base64") from exc
    if len(raw) != length:
        raise ValueError(f"密钥长度应为 {length} 字节")
    return raw


def _clamp(raw: bytes) -> bytes:
    key = bytearray(raw[:32])
    key[0] &= 248
    key[31] &= 127
    key[31] |= 64
    return bytes(key)


def new_private_key() -> str:
    return _b64(_clamp(os.urandom(32)))


def public_key(private_key: str) -> str:
    raw = _raw_key(private_key)
    pub = X25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return _b64(pub)


def new_keypair() -> tuple[str, str]:
    private = new_private_key()
    return private, public_key(private)


def new_preshared_key() -> str:
    return _b64(os.urandom(32))


def key_valid(value: str) -> bool:
    try:
        _raw_key(value)
        return True
    except ValueError:
        return False


def _clean_name(value: str, fallback: str = "设备") -> str:
    name = _NAME_RE.sub("", str(value or "")).strip()
    return (name or fallback)[:40]


def _new_id() -> str:
    return secrets.token_hex(5)


# ---------------------------------------------------------------- 状态 / 参数

def bucket(state: dict) -> dict:
    wg = state.get("wireguard")
    if not isinstance(wg, dict):
        wg = {}
        state["wireguard"] = wg
    for key, value in config.DEFAULTS["wireguard"].items():
        if key not in wg:
            wg[key] = copy.deepcopy(value)
    if not isinstance(wg.get("peers"), list):
        wg["peers"] = []
    if not isinstance(wg.get("one_time_links"), list):
        wg["one_time_links"] = []
    return wg


def peers(state: dict) -> list[dict]:
    return [p for p in bucket(state)["peers"] if isinstance(p, dict)]


def find_peer(state: dict, peer_id: str) -> dict | None:
    for peer in peers(state):
        if peer.get("id") == peer_id:
            return peer
    return None


def enabled(state: dict) -> bool:
    return bool(bucket(state).get("enabled"))


def validate_port(value: int) -> int:
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError("端口必须在 1-65535 之间")
    return port


def validate_subnet(value: str) -> ipaddress.IPv4Network:
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError as exc:
        raise ValueError("网段格式无效 (示例: 10.66.66.0/24)") from exc
    if net.version != 4:
        raise ValueError("WireGuard 隧道网段目前只支持 IPv4")
    if not 16 <= net.prefixlen <= 29:
        raise ValueError("网段前缀需在 /16 - /29 之间")
    return net


def validate_ipv6_subnet(value: str) -> ipaddress.IPv6Network:
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError as exc:
        raise ValueError("IPv6 网段格式无效 (示例: fd66:66:66::/64)") from exc
    if net.version != 6:
        raise ValueError("这里需要 IPv6 网段")
    if not 64 <= net.prefixlen <= 120:
        raise ValueError("IPv6 网段前缀需在 /64 - /120 之间")
    return net


def validate_mtu(value: int) -> int:
    mtu = int(value)
    if not 1280 <= mtu <= 1500:
        raise ValueError("MTU 需在 1280-1500 之间 (WireGuard 默认 1420)")
    return mtu


def validate_keepalive(value: int) -> int:
    keepalive = int(value)
    if not 0 <= keepalive <= 65535:
        raise ValueError("Keepalive 需在 0-65535 秒之间")
    return keepalive


def validate_mode(value: str) -> str:
    mode = str(value or "auto").strip().lower()
    if mode not in ("auto", "kernel", "userspace"):
        raise ValueError("运行方式只能是 auto / kernel / userspace")
    return mode


def normalize_dns(value: str) -> str:
    items = [item.strip() for item in str(value or "").replace(";", ",").split(",")]
    out: list[str] = []
    for item in items:
        if not item:
            continue
        try:
            out.append(str(ipaddress.ip_address(item)))
        except ValueError as exc:
            raise ValueError(f"DNS 不是合法 IP: {item}") from exc
    return ", ".join(dict.fromkeys(out))


def normalize_allowed_ips(value: str, ipv6: bool = False) -> str:
    text = str(value or "").strip()
    if not text:
        text = "0.0.0.0/0, ::/0" if ipv6 else DEFAULT_ALLOWED_IPS
    out: list[str] = []
    for item in text.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            out.append(str(ipaddress.ip_network(item, strict=False)))
        except ValueError as exc:
            raise ValueError(f"AllowedIPs 不是合法网段: {item}") from exc
    if not out:
        raise ValueError("AllowedIPs 不能为空")
    return ", ".join(dict.fromkeys(out))


def server_addresses(state: dict) -> tuple[str, str]:
    wg = bucket(state)
    net = validate_subnet(wg.get("subnet") or DEFAULT_SUBNET)
    v4 = f"{net.network_address + 1}/{net.prefixlen}"
    v6 = ""
    if wg.get("ipv6"):
        net6 = validate_ipv6_subnet(wg.get("ipv6_subnet") or DEFAULT_IPV6_SUBNET)
        v6 = f"{net6.network_address + 1}/{net6.prefixlen}"
    return v4, v6


def endpoint(state: dict) -> tuple[str, int]:
    wg = bucket(state)
    host = str(wg.get("endpoint") or "").strip()
    if not host:
        host = str(state.get("domain") or "").strip()
    if not host:
        host = str(services.public_ip().get("ip") or "")
    return host.strip("[]"), int(wg.get("port") or DEFAULT_PORT)


def endpoint_text(state: dict) -> str:
    host, port = endpoint(state)
    if not host:
        return ""
    try:
        if ipaddress.ip_address(host).version == 6:
            return f"[{host}]:{port}"
    except ValueError:
        pass
    return f"{host}:{port}"


# ---------------------------------------------------------------- 地址池

def _host_iter(net: ipaddress.IPv4Network):
    for offset in range(2, net.num_addresses - 1):
        yield net.network_address + offset


def _host_iter6(net: ipaddress.IPv6Network):
    for offset in range(2, min(net.num_addresses - 1, 4096)):
        yield net.network_address + offset


def allocate_address(state: dict, net: ipaddress.IPv4Network | None = None) -> str:
    net = net or validate_subnet(bucket(state).get("subnet") or DEFAULT_SUBNET)
    used = {str(p.get("address") or "") for p in peers(state)}
    for ip in _host_iter(net):
        if str(ip) not in used:
            return str(ip)
    raise ValueError("隧道地址池已满，请换一个更大的网段")


def allocate_address6(state: dict, net: ipaddress.IPv6Network | None = None) -> str:
    net = net or validate_ipv6_subnet(bucket(state).get("ipv6_subnet") or DEFAULT_IPV6_SUBNET)
    used = {str(p.get("address6") or "") for p in peers(state)}
    for ip in _host_iter6(net):
        if str(ip) not in used:
            return str(ip)
    raise ValueError("IPv6 隧道地址池已满")


def ensure_peer_addresses(state: dict) -> None:
    wg = bucket(state)
    net = validate_subnet(wg.get("subnet") or DEFAULT_SUBNET)
    net6 = validate_ipv6_subnet(wg.get("ipv6_subnet") or DEFAULT_IPV6_SUBNET)
    in_v4 = {str(ip) for ip in _host_iter(net)}
    in_v6 = {str(ip) for ip in _host_iter6(net6)}
    seen_v4: set[str] = set()
    seen_v6: set[str] = set()
    for peer in peers(state):
        addr = str(peer.get("address") or "")
        if addr not in in_v4 or addr in seen_v4:
            peer["address"] = allocate_address(state, net)
        seen_v4.add(str(peer["address"]))
        if wg.get("ipv6"):
            addr6 = str(peer.get("address6") or "")
            if addr6 not in in_v6 or addr6 in seen_v6:
                peer["address6"] = allocate_address6(state, net6)
            seen_v6.add(str(peer["address6"]))
        else:
            peer["address6"] = ""


# ---------------------------------------------------------------- peer 生命周期

def add_peer(
    state: dict,
    name: str = "",
    allowed_ips: str = "",
    expires_days: int = 0,
    compat: bool = False,
) -> dict:
    wg = bucket(state)
    if len(peers(state)) >= MAX_PEERS:
        raise ValueError(f"客户端数量已达上限 ({MAX_PEERS})")
    private, public = new_keypair()
    net = validate_subnet(wg.get("subnet") or DEFAULT_SUBNET)
    now = _now()
    peer = {
        "id": _new_id(),
        "name": _clean_name(name, f"设备 {len(peers(state)) + 1}"),
        "private_key": private,
        "public_key": public,
        "preshared_key": new_preshared_key(),
        "address": allocate_address(state, net),
        "address6": "",
        "allowed_ips": normalize_allowed_ips(allowed_ips, bool(wg.get("ipv6"))),
        "enabled": True,
        # GL.iNet 等路由器固件对 PresharedKey / MTU / 多 DNS 的解析有已知问题。
        # 兼容模式会同时在服务端和客户端省略 PSK, 并生成最保守的字段顺序。
        "compat": bool(compat),
        "created_at": now,
        "expires_at": now + int(expires_days) * 86400 if int(expires_days or 0) > 0 else 0,
        "expired_at": 0,
    }
    if wg.get("ipv6"):
        peer["address6"] = allocate_address6(
            state, validate_ipv6_subnet(wg.get("ipv6_subnet") or DEFAULT_IPV6_SUBNET)
        )
    wg["peers"].append(peer)
    return peer


def remove_peer(state: dict, peer_id: str) -> dict | None:
    wg = bucket(state)
    for index, peer in enumerate(list(wg["peers"])):
        if isinstance(peer, dict) and peer.get("id") == peer_id:
            wg["peers"].pop(index)
            wg["one_time_links"] = [
                link for link in wg["one_time_links"]
                if isinstance(link, dict) and link.get("peer_id") != peer_id
            ]
            return peer
    return None


def rotate_peer(state: dict, peer_id: str) -> dict | None:
    peer = find_peer(state, peer_id)
    if peer is None:
        return None
    private, public = new_keypair()
    peer["private_key"] = private
    peer["public_key"] = public
    peer["preshared_key"] = new_preshared_key()
    return peer


def peer_expired(peer: dict, now: int | None = None) -> bool:
    expires = int(peer.get("expires_at") or 0)
    return bool(expires and expires <= (now or _now()))


def active_peers(state: dict, now: int | None = None) -> list[dict]:
    moment = now or _now()
    return [
        p for p in peers(state)
        if p.get("enabled", True) and not peer_expired(p, moment)
    ]


def reap_expired(state: dict, now: int | None = None) -> bool:
    moment = now or _now()
    changed = False
    for peer in peers(state):
        if peer.get("enabled", True) and peer_expired(peer, moment):
            peer["enabled"] = False
            peer["expired_at"] = moment
            changed = True
    return changed


# ---------------------------------------------------------------- 配置生成

def _peer_allowed(peer: dict, ipv6: bool) -> str:
    parts = [f"{peer.get('address')}/32"]
    if ipv6 and peer.get("address6"):
        parts.append(f"{peer['address6']}/128")
    return ", ".join(parts)


def client_config(state: dict, peer: dict) -> str:
    wg = bucket(state)
    compat = bool(peer.get("compat"))
    # 客户端侧固定用 /32 (/128): GL.iNet 4.9.0 会把 10.x/24 当成 classful /8,
    # 把整个 10.0.0.0/8 路由进隧道 (连上游 DNS/网关一起吞掉), 表现为一直"连接中"。
    # /32 是点对点隧道端点的标准写法, 路由由 AllowedIPs 负责, 不影响全流量/分流。
    address = f"{peer.get('address')}/32"
    if wg.get("ipv6") and peer.get("address6") and not compat:
        address += f", {peer['address6']}/128"
    lines = [
        "[Interface]",
        f"PrivateKey = {peer.get('private_key')}",
        f"Address = {address}",
    ]
    dns = str(wg.get("dns") or "").strip()
    if dns:
        # GL.iNet 的部分固件只接受单个 DNS；兼容模式只写第一个。
        lines.append(f"DNS = {dns.split(',')[0].strip() if compat else dns}")
    if not compat:
        lines.append(f"MTU = {int(wg.get('mtu') or DEFAULT_MTU)}")
    allowed = str(peer.get("allowed_ips") or DEFAULT_ALLOWED_IPS)
    if compat:
        allowed = ", ".join(
            part.strip() for part in allowed.split(",")
            if part.strip() and ":" not in part
        ) or DEFAULT_ALLOWED_IPS
        # 尽量贴近 GL.iNet 自己导出的字段顺序，减少固件解析差异。
        lines += [
            "",
            "[Peer]",
            f"AllowedIPs = {allowed}",
            f"Endpoint = {endpoint_text(state)}",
            f"PersistentKeepalive = {int(wg.get('keepalive') or 0)}",
            f"PublicKey = {wg.get('server_public_key')}",
        ]
    else:
        lines += [
            "",
            "[Peer]",
            f"PublicKey = {wg.get('server_public_key')}",
            f"Endpoint = {endpoint_text(state)}",
            f"AllowedIPs = {allowed}",
        ]
        if peer.get("preshared_key"):
            lines.append(f"PresharedKey = {peer['preshared_key']}")
        lines.append(f"PersistentKeepalive = {int(wg.get('keepalive') or 0)}")
    lines.append("")
    return "\n".join(lines)


def _server_interface(state: dict, runtime: bool = False) -> list[str]:
    wg = bucket(state)
    v4, v6 = server_addresses(state)
    lines: list[str] = []
    if not runtime:
        lines.append(f"Address = {v4}" + (f", {v6}" if v6 else ""))
    lines += [
        f"ListenPort = {int(wg.get('port') or DEFAULT_PORT)}",
        f"PrivateKey = {wg.get('server_private_key')}",
    ]
    if not runtime:
        lines.append(f"MTU = {int(wg.get('mtu') or DEFAULT_MTU)}")
        lines += [
            f'PostUp = "{paths()["wireguard_firewall"]}" up',
            f'PostDown = "{paths()["wireguard_firewall"]}" down',
        ]
    return lines


def server_config(state: dict, runtime: bool = False) -> str:
    wg = bucket(state)
    ipv6 = bool(wg.get("ipv6"))
    lines = [
        "# 由 ZeroProxy 自动生成 — 改动会在下一次应用时被覆盖",
        "[Interface]",
        *_server_interface(state, runtime=runtime),
    ]
    for peer in active_peers(state):
        lines += [
            "",
            f"# {peer.get('name') or peer.get('id')}",
            "[Peer]",
            f"PublicKey = {peer.get('public_key')}",
        ]
        if peer.get("preshared_key") and not peer.get("compat"):
            lines.append(f"PresharedKey = {peer['preshared_key']}")
        lines.append(f"AllowedIPs = {_peer_allowed(peer, ipv6)}")
    lines.append("")
    return "\n".join(lines)


def firewall_script(state: dict) -> str:
    """生成幂等的 NAT / FORWARD 脚本。

    Debian / Ubuntu 上 iptables 与 ufw 共用同一套 nft 后端；把跳转插在 FORWARD 链
    最前面，可以确保 ufw 的默认 drop 不会把 WireGuard 转发一起挡掉。没有 iptables
    二进制时才退回独立的 nftables 表。
    """
    wg = bucket(state)
    net = validate_subnet(wg.get("subnet") or DEFAULT_SUBNET)
    ipv6 = bool(wg.get("ipv6"))
    net6 = validate_ipv6_subnet(wg.get("ipv6_subnet") or DEFAULT_IPV6_SUBNET) if ipv6 else None
    v6_up = ""
    v6_down = ""
    v6_nft_up = ""
    if net6 is not None:
        v6_up = f"""
  ip6tables -w 5 -N ZP_WG_FWD6 2>/dev/null || true
  ip6tables -w 5 -F ZP_WG_FWD6
  ip6tables -w 5 -A ZP_WG_FWD6 -i "$IFACE" -o "$IFACE" -j ACCEPT
  ip6tables -w 5 -A ZP_WG_FWD6 -i "$IFACE" -j ACCEPT
  ip6tables -w 5 -A ZP_WG_FWD6 -o "$IFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  ip6tables -w 5 -C FORWARD -j ZP_WG_FWD6 2>/dev/null || ip6tables -w 5 -I FORWARD 1 -j ZP_WG_FWD6
  ip6tables -w 5 -t nat -N ZP_WG_NAT6 2>/dev/null || true
  ip6tables -w 5 -t nat -F ZP_WG_NAT6
  ip6tables -w 5 -t nat -A ZP_WG_NAT6 -s "{net6}" ! -o "$IFACE" -j MASQUERADE
  ip6tables -w 5 -t nat -C POSTROUTING -j ZP_WG_NAT6 2>/dev/null || ip6tables -w 5 -t nat -I POSTROUTING 1 -j ZP_WG_NAT6
"""
        v6_down = """
  ip6tables -w 5 -D FORWARD -j ZP_WG_FWD6 2>/dev/null || true
  ip6tables -w 5 -F ZP_WG_FWD6 2>/dev/null || true
  ip6tables -w 5 -X ZP_WG_FWD6 2>/dev/null || true
  ip6tables -w 5 -t nat -D POSTROUTING -j ZP_WG_NAT6 2>/dev/null || true
  ip6tables -w 5 -t nat -F ZP_WG_NAT6 2>/dev/null || true
  ip6tables -w 5 -t nat -X ZP_WG_NAT6 2>/dev/null || true
"""
        v6_nft_up = (
            '  nft add rule inet zeroproxy_wg postrouting oifname != "$IFACE" '
            f'ip6 saddr "{net6}" masquerade\n'
        )
    return f"""#!/bin/sh
# 由 ZeroProxy 自动生成 — 改动会在下一次应用时被覆盖
# 用法: firewall.sh up|down
set -eu

IFACE="{INTERFACE}"
SUBNET="{net}"

sysctl -qw net.ipv4.ip_forward=1 2>/dev/null || true
{"sysctl -qw net.ipv6.conf.all.forwarding=1 2>/dev/null || true" if ipv6 else ""}

up_iptables() {{
  iptables -w 5 -N ZP_WG_FWD 2>/dev/null || true
  iptables -w 5 -F ZP_WG_FWD
  iptables -w 5 -A ZP_WG_FWD -i "$IFACE" -o "$IFACE" -j ACCEPT
  iptables -w 5 -A ZP_WG_FWD -i "$IFACE" -j ACCEPT
  iptables -w 5 -A ZP_WG_FWD -o "$IFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -w 5 -C FORWARD -j ZP_WG_FWD 2>/dev/null || iptables -w 5 -I FORWARD 1 -j ZP_WG_FWD
  iptables -w 5 -t nat -N ZP_WG_NAT 2>/dev/null || true
  iptables -w 5 -t nat -F ZP_WG_NAT
  iptables -w 5 -t nat -A ZP_WG_NAT -s "$SUBNET" ! -o "$IFACE" -j MASQUERADE
  iptables -w 5 -t nat -C POSTROUTING -j ZP_WG_NAT 2>/dev/null || iptables -w 5 -t nat -I POSTROUTING 1 -j ZP_WG_NAT
{v6_up}
}}

down_iptables() {{
  iptables -w 5 -D FORWARD -j ZP_WG_FWD 2>/dev/null || true
  iptables -w 5 -F ZP_WG_FWD 2>/dev/null || true
  iptables -w 5 -X ZP_WG_FWD 2>/dev/null || true
  iptables -w 5 -t nat -D POSTROUTING -j ZP_WG_NAT 2>/dev/null || true
  iptables -w 5 -t nat -F ZP_WG_NAT 2>/dev/null || true
  iptables -w 5 -t nat -X ZP_WG_NAT 2>/dev/null || true
{v6_down}
}}

up_nft() {{
  nft list table inet zeroproxy_wg >/dev/null 2>&1 && nft delete table inet zeroproxy_wg || true
  nft add table inet zeroproxy_wg
  nft 'add chain inet zeroproxy_wg forward {{ type filter hook forward priority 0; policy accept; }}'
  nft add rule inet zeroproxy_wg forward iifname "$IFACE" oifname != "$IFACE" accept
  nft add rule inet zeroproxy_wg forward iifname != "$IFACE" oifname "$IFACE" ct state related,established accept
  nft 'add chain inet zeroproxy_wg postrouting {{ type nat hook postrouting priority 100; policy accept; }}'
  nft add rule inet zeroproxy_wg postrouting oifname != "$IFACE" ip saddr "$SUBNET" masquerade
{v6_nft_up}
}}

down_nft() {{
  nft list table inet zeroproxy_wg >/dev/null 2>&1 && nft delete table inet zeroproxy_wg || true
}}

case "${{1:-up}}" in
  up)
    if command -v iptables >/dev/null 2>&1; then
      up_iptables
    elif command -v nft >/dev/null 2>&1; then
      up_nft
    else
      echo "wireguard: 需要 iptables 或 nftables" >&2
      exit 1
    fi
    ;;
  down)
    command -v iptables >/dev/null 2>&1 && down_iptables || true
    command -v nft >/dev/null 2>&1 && down_nft || true
    ;;
  *)
    echo "用法: $0 up|down" >&2
    exit 2
    ;;
esac
"""


def reload_script(state: dict) -> str:
    wg = bucket(state)
    v4, v6 = server_addresses(state)
    lines = [
        "#!/bin/sh",
        "# 由 ZeroProxy 自动生成 — 用 wg syncconf 增量同步, 不打断在线 peer",
        "set -eu",
        f'wg syncconf {INTERFACE} "{paths()["wireguard_runtime"]}"',
        f'want4="{v4}"',
        f'cur4="$(ip -4 addr show dev {INTERFACE} | awk \'/inet /{{print $2; exit}}\')"',
        'if [ "$cur4" != "$want4" ]; then',
        f'  ip -4 addr flush dev {INTERFACE} scope global || true',
        f'  ip -4 addr add "$want4" dev {INTERFACE}',
        "fi",
    ]
    if v6:
        lines += [
            f'want6="{v6}"',
            f'cur6="$(ip -6 addr show dev {INTERFACE} | awk \'/inet6 /{{print $2; exit}}\')"',
            'if [ "$cur6" != "$want6" ]; then',
            f'  ip -6 addr flush dev {INTERFACE} scope global || true',
            f'  ip -6 addr add "$want6" dev {INTERFACE}',
            "fi",
        ]
    lines += [
        f'ip link set dev {INTERFACE} mtu {int(wg.get("mtu") or DEFAULT_MTU)} up',
        f'"{paths()["wireguard_firewall"]}" up',
        "",
    ]
    return "\n".join(lines)


def userspace_up_script(state: dict) -> str:
    """wireguard-go 的 ExecStartPost: 接口建好后把配置与地址灌进去。"""
    wg = bucket(state)
    v4, v6 = server_addresses(state)
    lines = [
        "#!/bin/sh",
        "# 由 ZeroProxy 自动生成 — wireguard-go 用户态接口初始化",
        "set -eu",
        f'IFACE="{INTERFACE}"',
        "i=0",
        'while [ "$i" -lt 50 ]; do',
        '  ip link show dev "$IFACE" >/dev/null 2>&1 && break',
        "  i=$((i+1))",
        "  sleep 0.1",
        "done",
        'ip link show dev "$IFACE" >/dev/null 2>&1 || { '
        'echo "wireguard-go 没有建立 wg0" >&2; exit 1; }',
        f'wg setconf "$IFACE" "{paths()["wireguard_runtime"]}"',
        f'want4="{v4}"',
        f'cur4="$(ip -4 addr show dev {INTERFACE} | awk \'/inet /{{print $2; exit}}\')"',
        'if [ "$cur4" != "$want4" ]; then',
        f'  ip -4 addr flush dev {INTERFACE} scope global || true',
        f'  ip -4 addr add "$want4" dev {INTERFACE}',
        "fi",
    ]
    if v6:
        lines += [
            f'want6="{v6}"',
            f'cur6="$(ip -6 addr show dev {INTERFACE} | awk \'/inet6 /{{print $2; exit}}\')"',
            'if [ "$cur6" != "$want6" ]; then',
            f'  ip -6 addr flush dev {INTERFACE} scope global || true',
            f'  ip -6 addr add "$want6" dev {INTERFACE}',
            "fi",
        ]
    lines += [
        f'ip link set dev {INTERFACE} mtu {int(wg.get("mtu") or DEFAULT_MTU)} up',
        f'"{paths()["wireguard_firewall"]}" up',
        "",
    ]
    return "\n".join(lines)


def userspace_down_script(state: dict) -> str:
    return "\n".join(
        [
            "#!/bin/sh",
            "# 由 ZeroProxy 自动生成 — wireguard-go 停止后的清理",
            f'"{paths()["wireguard_firewall"]}" down || true',
            f"ip link delete dev {INTERFACE} 2>/dev/null || true",
            "",
        ]
    )


def _write(path: str, text: str, mode: int) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _ensure_wireguard_dir() -> None:
    directory = paths()["wireguard_dir"]
    os.makedirs(directory, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass


def generate(state: dict) -> tuple[bool, str]:
    wg = bucket(state)
    if not key_valid(wg.get("server_private_key", "")):
        wg["server_private_key"], wg["server_public_key"] = new_keypair()
    elif not key_valid(wg.get("server_public_key", "")):
        wg["server_public_key"] = public_key(wg["server_private_key"])
    ensure_peer_addresses(state)
    _ensure_wireguard_dir()
    _write(paths()["wireguard_config"], server_config(state), 0o600)
    _write(paths()["wireguard_runtime"], server_config(state, runtime=True), 0o600)
    _write(paths()["wireguard_firewall"], firewall_script(state), 0o700)
    _write(paths()["wireguard_reload"], reload_script(state), 0o700)
    _write(paths()["wireguard_userspace_up"], userspace_up_script(state), 0o700)
    _write(paths()["wireguard_userspace_down"], userspace_down_script(state), 0o700)
    active = len(active_peers(state))
    total = len(peers(state))
    note = f"已生成 · {active}/{total} 个客户端启用 · {endpoint_text(state) or '(尚未确定地址)'}"
    return True, note


# ---------------------------------------------------------------- 运行时

def tools_available() -> bool:
    return bool(shutil.which("wg") and shutil.which("wg-quick"))


def firewall_tool_available() -> bool:
    return bool(shutil.which("iptables") or shutil.which("nft"))


def userspace_available() -> bool:
    """wireguard-go 与 TUN 都在才谈得上用户态回退。"""
    return bool(shutil.which("wireguard-go") and os.path.exists("/dev/net/tun"))


def _apt_install(packages: list[str], timeout: int) -> tuple[bool, str]:
    if not packages:
        return True, ""
    if not shutil.which("apt-get"):
        return False, "本机没有 apt-get, 请手动安装: " + " ".join(packages)
    ok, out = services.run(
        ["apt-get", "install", "-y", *packages],
        timeout=timeout,
        env={"DEBIAN_FRONTEND": "noninteractive"},
    )
    if not ok:
        services.run(
            ["apt-get", "update", "-y"],
            timeout=timeout,
            env={"DEBIAN_FRONTEND": "noninteractive"},
        )
        ok, out = services.run(
            ["apt-get", "install", "-y", *packages],
            timeout=timeout,
            env={"DEBIAN_FRONTEND": "noninteractive"},
        )
    return ok, " ".join(out.split())[:200]


def ensure_tools(timeout: int = 180) -> tuple[bool, str]:
    if not services.is_prod():
        return False, "本地开发环境没有 wg / wg-quick（生产机会自动安装）"
    need: list[str] = []
    if not tools_available() or not shutil.which("ip"):
        need += ["wireguard-tools", "iproute2"]
    if not firewall_tool_available():
        need.append("iptables")
    if need:
        ok, out = _apt_install(need, timeout)
        if not ok or not tools_available():
            return False, f"WireGuard 工具安装失败: {out}"
    detail = "wireguard-tools 已就绪"
    detail += " · wireguard-go 可用" if shutil.which("wireguard-go") else " · wireguard-go 未安装"
    return True, detail


def service_state(name: str = SERVICE) -> str:
    if not services.is_prod():
        return "dry-run"
    if not shutil.which("systemctl"):
        return "unavailable"
    ok, out = services.run(["systemctl", "is-active", name], timeout=10)
    state = (out or "").strip().splitlines()[0] if out.strip() else "unknown"
    return state or "inactive"


def active_service() -> str:
    for name in (SERVICE, SERVICE_USERSPACE):
        if service_state(name) in ("active", "activating"):
            return name
    return ""


def interface_exists() -> bool:
    if not services.is_prod():
        return False
    ok, _ = services.run(["ip", "link", "show", "dev", INTERFACE], timeout=5)
    return ok


def kernel_probe() -> tuple[bool, str]:
    """真正建一个临时 WireGuard 接口再删掉 —— 只看 /sys/module 会误判。

    容器里常见两种情况: 模块根本不存在; 或者宿主机加载了模块, 但容器没有
    NET_ADMIN (`Operation not permitted`)。两者的处理都是改走 wireguard-go。
    """
    probe = "zpwgprobe0"
    services.run(["ip", "link", "delete", "dev", probe], timeout=5)
    ok, out = services.run(
        ["ip", "link", "add", "dev", probe, "type", "wireguard"], timeout=10
    )
    services.run(["ip", "link", "delete", "dev", probe], timeout=5)
    if ok:
        return True, ""
    lines = [line.strip() for line in (out or "").splitlines() if line.strip()]
    return False, (lines[-1] if lines else "ip link add 失败")[:200]


def runtime_mode(state: dict) -> tuple[str, str]:
    """决定这次用内核还是 wireguard-go。返回 (kernel|userspace|none, 说明)。"""
    wg = bucket(state)
    try:
        pref = validate_mode(wg.get("mode") or "auto")
    except ValueError:
        pref = "auto"
    if pref == "kernel":
        if not tools_available():
            return "none", "强制内核模式, 但 wg / wg-quick 未安装"
        ok, err = kernel_probe()
        if not ok:
            return "none", f"强制内核模式, 但内核无法创建 WireGuard 接口: {err}"
        return "kernel", ""
    if pref == "userspace":
        if userspace_available():
            return "userspace", "强制用户态 (wireguard-go)"
        return "none", (
            "强制用户态, 但缺少 wireguard-go 或 /dev/net/tun "
            "(容器需要 --device /dev/net/tun 并允许 TUN)"
        )
    if tools_available():
        ok, err = kernel_probe()
        if ok:
            return "kernel", ""
        if userspace_available():
            return "userspace", f"内核不可用 ({err}); 自动改用 wireguard-go"
        return "none", (
            f"内核不支持 WireGuard ({err}); 且没有可用的 wireguard-go / TUN。"
            "这是容器或受限内核最常见的失败原因。"
        )
    return "none", "wg / wg-quick 未安装"


def _interface_public_key() -> str:
    ok, out = services.run(["wg", "show", INTERFACE, "public-key"], timeout=5)
    return out.strip() if ok else ""


def _runtime_stats() -> dict[str, dict]:
    ok, out = services.run(["wg", "show", INTERFACE, "dump"], timeout=10)
    if not ok:
        return {}
    stats: dict[str, dict] = {}
    for line in out.splitlines()[1:]:
        fields = line.split("\t")
        if len(fields) < 8:
            continue
        public, _psk, endpoint_, allowed, handshake, rx, tx, keepalive = fields[:8]
        try:
            stats[public.strip()] = {
                "endpoint": "" if endpoint_.strip() in ("", "(none)") else endpoint_.strip(),
                "allowed_ips": allowed.strip(),
                "latest_handshake": int(handshake or 0),
                "rx": int(rx or 0),
                "tx": int(tx or 0),
                "keepalive": int(keepalive or 0),
            }
        except ValueError:
            continue
    return stats


def nat_rule_present() -> bool:
    """尽力确认 MASQUERADE 规则在 (iptables 或 nft 任一)。"""
    ok, out = services.run(
        ["iptables", "-w", "5", "-t", "nat", "-S", "ZP_WG_NAT"], timeout=5
    )
    if ok and "MASQUERADE" in out:
        return True
    ok, out = services.run(["nft", "list", "table", "inet", "zeroproxy_wg"], timeout=5)
    return bool(ok and "masquerade" in out)


def journal_tail(name: str = SERVICE, lines: int = 20) -> str:
    """把 systemd 的"control process exited"换成真正的原因。"""
    if not services.is_prod():
        return ""
    ok, out = services.run(
        ["journalctl", "-u", name, "-n", str(int(lines)), "--no-pager"], timeout=15
    )
    if not ok:
        return ""
    rows = [" ".join(line.split()) for line in out.splitlines() if line.strip()]
    return " | ".join(rows[-6:])[:600]


def _stop_unit(name: str, timeout: int) -> tuple[bool, str]:
    if service_state(name) not in ("active", "activating", "reloading"):
        return True, ""
    ok, out = services.run(["systemctl", "disable", "--now", name], timeout=timeout)
    return ok, " ".join(out.split())[:200]


def _teardown_interface(state: dict, timeout: int) -> tuple[bool, str]:
    """拆掉 wg0，兼容内核接口与 wireguard-go 的 TUN 接口。"""
    if not interface_exists():
        return True, ""
    existing = _interface_public_key()
    if existing and existing != str(bucket(state).get("server_public_key") or ""):
        return False, (
            f"{INTERFACE} 已存在且不是本面板管理的接口, 未做改动 "
            f"(公钥 {existing[:12]}…)"
        )
    ok, out = services.run(
        ["wg-quick", "down", paths()["wireguard_config"]], timeout=timeout
    )
    if ok and not interface_exists():
        return True, ""
    services.run(["ip", "link", "delete", "dev", INTERFACE], timeout=timeout)
    services.run(["sh", paths()["wireguard_firewall"], "down"], timeout=timeout)
    if interface_exists():
        return False, f"wg0 无法拆除: {' '.join(out.split())[:160]}"
    return True, ""


def sync(state: dict, timeout: int = 90) -> tuple[bool, str]:
    ok, detail = generate(state)
    if not ok:
        return ok, detail
    wg = bucket(state)
    if not wg.get("enabled"):
        if not services.is_prod():
            return True, detail + " · WireGuard 未启用 (本地开发跳过服务操作)"
        for name in (SERVICE, SERVICE_USERSPACE):
            ok, out = _stop_unit(name, timeout)
            if not ok:
                return False, f"停用 {name} 失败: {out}"
        if interface_exists():
            ok, out = _teardown_interface(state, timeout)
            if not ok:
                return False, out
        wg["active_mode"] = ""
        return True, "已停用 WireGuard (wg0 已拆除)"
    if not services.is_prod():
        return True, detail + " · 本地开发跳过服务操作"

    tools_ok, tools_detail = ensure_tools(timeout=max(timeout, 180))
    if not tools_ok:
        return False, tools_detail

    pref = validate_mode(wg.get("mode") or "auto")
    active_name = active_service()
    mode_detail = ""
    if pref == "auto" and active_name and interface_exists():
        # 已经在跑就不要每次加 peer 都重新探测内核 (探测会建/删临时接口)
        mode = "kernel" if active_name == SERVICE else "userspace"
    else:
        mode, mode_detail = runtime_mode(state)
        if mode == "none" and pref != "kernel" and not shutil.which("wireguard-go"):
            # 只有真的走不通内核时才去装用户态, 不让正常服务器每次同步都碰 apt
            _apt_install(["wireguard-go"], timeout)
            if userspace_available():
                mode, mode_detail = runtime_mode(state)
    if mode == "none":
        return False, mode_detail
    if mode == "userspace" and not userspace_available():
        _apt_install(["wireguard-go"], timeout)
        if not userspace_available():
            return False, (
                "用户态 WireGuard 需要 wireguard-go 与 /dev/net/tun; "
                "容器请确认已映射 /dev/net/tun 并允许 TUN"
            )

    unit = SERVICE if mode == "kernel" else SERVICE_USERSPACE
    other = SERVICE_USERSPACE if mode == "kernel" else SERVICE
    if service_state(other) in ("active", "activating", "reloading"):
        ok, out = _stop_unit(other, timeout)
        if not ok:
            return False, f"切换运行方式时停止 {other} 失败: {out}"
        for _ in range(20):
            if not interface_exists():
                break
            time.sleep(0.1)

    active = service_state(unit) in ("active", "activating", "reloading")
    if active and not interface_exists():
        ok, out = services.run(["systemctl", "restart", unit], timeout=timeout)
        action = "重启"
    elif active:
        ok, out = services.run(["systemctl", "reload", unit], timeout=timeout)
        action = "重载"
    else:
        if interface_exists():
            ok, out = _teardown_interface(state, timeout)
            if not ok:
                return False, out
        ok, out = services.run(["systemctl", "start", unit], timeout=timeout)
        action = "启动"
        if ok:
            # 起得来才写开机自启: 配置/内核不支持时不要留下一个每次开机都失败的单元
            services.run(["systemctl", "enable", unit], timeout=30)
    if not ok:
        tail = journal_tail(unit)
        message = f"{unit} {action}失败: {' '.join(out.split())[:300]}"
        if tail:
            message += f" · 最近日志: {tail}"
        return False, message
    for _ in range(25):
        if interface_exists():
            break
        time.sleep(0.1)
    if not interface_exists():
        tail = journal_tail(unit)
        message = f"{unit} {action}后 wg0 仍未建立"
        if tail:
            message += f" · 最近日志: {tail}"
        return False, message
    wg["active_mode"] = mode
    suffix = f" · {mode_detail}" if mode_detail else ""
    return True, (
        f"WireGuard {action}成功{suffix} · {len(active_peers(state))} 个客户端 · "
        f"{endpoint_text(state)}"
    )


# ---------------------------------------------------------------- 一次性链接

def _prune_links(state: dict, now: int | None = None) -> None:
    wg = bucket(state)
    moment = now or _now()
    live_ids = {str(p.get("id")) for p in peers(state)}
    links = [
        link for link in wg["one_time_links"]
        if isinstance(link, dict)
        and int(link.get("expires_at") or 0) > moment
        and str(link.get("peer_id")) in live_ids
    ]
    wg["one_time_links"] = links[-MAX_ONE_TIME:]


def one_time_create(state: dict, peer_id: str, ttl: int = ONE_TIME_TTL) -> str | None:
    if find_peer(state, peer_id) is None:
        return None
    wg = bucket(state)
    _prune_links(state)
    token = secrets.token_urlsafe(32)
    now = _now()
    wg["one_time_links"].append(
        {
            "token": token,
            "peer_id": peer_id,
            "created_at": now,
            "expires_at": now + max(60, min(int(ttl), 24 * 3600)),
        }
    )
    wg["one_time_links"] = wg["one_time_links"][-MAX_ONE_TIME:]
    return token


def one_time_consume(state: dict, token: str) -> tuple[dict, str] | None:
    wg = bucket(state)
    now = _now()
    for index, link in enumerate(list(wg["one_time_links"])):
        if not isinstance(link, dict) or not hmac.compare_digest(
            str(link.get("token") or "").encode("utf-8"), token.encode("utf-8")
        ):
            continue
        wg["one_time_links"].pop(index)
        if int(link.get("expires_at") or 0) <= now:
            return None
        peer = find_peer(state, str(link.get("peer_id") or ""))
        if peer is None or not peer.get("enabled", True) or peer_expired(peer, now):
            return None
        return peer, client_config(state, peer)
    return None


# ---------------------------------------------------------------- 面板视图 / 诊断

def view(state: dict, now: int | None = None) -> dict:
    """面板用的只读视图 —— 绝不包含任何私钥 / PSK。"""
    wg = bucket(state)
    moment = now or _now()
    prod = services.is_prod()
    is_enabled = bool(wg.get("enabled"))
    stats = _runtime_stats() if is_enabled else {}
    host, _port = endpoint(state)
    online_count = 0
    total_rx = 0
    total_tx = 0
    out_peers: list[dict] = []
    for peer in peers(state):
        runtime = stats.get(str(peer.get("public_key") or ""), {})
        handshake = int(runtime.get("latest_handshake") or 0)
        rx = int(runtime.get("rx") or 0)
        tx = int(runtime.get("tx") or 0)
        expired = peer_expired(peer, moment)
        active = bool(peer.get("enabled", True)) and not expired
        online = bool(active and handshake and moment - handshake < 180)
        if online:
            online_count += 1
        total_rx += rx
        total_tx += tx
        out_peers.append(
            {
                "id": peer.get("id", ""),
                "name": peer.get("name") or "设备",
                "address": peer.get("address") or "",
                "address6": peer.get("address6") or "",
                "allowed_ips": peer.get("allowed_ips") or DEFAULT_ALLOWED_IPS,
                "enabled": bool(peer.get("enabled", True)),
                "compat": bool(peer.get("compat")),
                "expired": expired,
                "expires_at": int(peer.get("expires_at") or 0),
                "created_at": int(peer.get("created_at") or 0),
                "online": online,
                "latest_handshake": handshake,
                "endpoint": runtime.get("endpoint") or "",
                "rx": rx,
                "tx": tx,
                "public_key": peer.get("public_key") or "",
            }
        )
    tools = tools_available()
    running = interface_exists() if is_enabled else False
    active = active_service() if is_enabled else ""
    service = active or ("inactive" if prod else "dry-run")
    try:
        mode_pref = validate_mode(wg.get("mode") or "auto")
    except ValueError:
        mode_pref = "auto"
    reason = ""
    if wg.get("enabled") and not prod:
        reason = "本地开发环境: 配置已生成, 不启动内核接口"
    elif wg.get("enabled") and not tools:
        reason = "未安装 wireguard-tools（启用时会自动尝试安装）"
    elif wg.get("enabled") and not running:
        reason = f"服务未运行（{service}）"
    return {
        "enabled": bool(wg.get("enabled")),
        "mode": mode_pref,
        "active_mode": str(wg.get("active_mode") or ""),
        "userspace_available": userspace_available(),
        "port": int(wg.get("port") or DEFAULT_PORT),
        "subnet": str(wg.get("subnet") or DEFAULT_SUBNET),
        "mtu": int(wg.get("mtu") or DEFAULT_MTU),
        "dns": str(wg.get("dns") or ""),
        "keepalive": int(wg.get("keepalive") or 0),
        "ipv6": bool(wg.get("ipv6")),
        "ipv6_subnet": str(wg.get("ipv6_subnet") or DEFAULT_IPV6_SUBNET),
        "endpoint_input": str(wg.get("endpoint") or ""),
        "endpoint_host": host,
        "endpoint": endpoint_text(state),
        "interface": INTERFACE,
        "service": service,
        "running": running,
        "tools": tools,
        "prod": prod,
        "reason": reason,
        "server_public_key": str(wg.get("server_public_key") or ""),
        "peer_count": len(out_peers),
        "online_count": online_count,
        "enabled_count": sum(1 for p in out_peers if p["enabled"] and not p["expired"]),
        "total_rx": total_rx,
        "total_tx": total_tx,
        "peers": out_peers,
        "one_time_ttl": ONE_TIME_TTL,
        "max_peers": MAX_PEERS,
    }


def diagnose(state: dict) -> tuple[bool, str]:
    wg = bucket(state)
    if not wg.get("enabled"):
        return True, "未启用"
    if not services.is_prod():
        return True, "本地开发环境, 跳过接口检查"
    if not tools_available():
        return False, "未安装 wireguard-tools（wg / wg-quick 不存在）"
    if not firewall_tool_available():
        return False, "未安装 iptables / nftables, 无法建立 NAT 转发"
    if not interface_exists():
        mode, mode_detail = runtime_mode(state)
        states = (
            f"{SERVICE}={service_state(SERVICE)} / "
            f"{SERVICE_USERSPACE}={service_state(SERVICE_USERSPACE)}"
        )
        if mode == "none":
            return False, mode_detail
        message = f"{INTERFACE} 不存在 — {states}; 可用方式: {mode} {mode_detail}".strip()
        tail = journal_tail(SERVICE_USERSPACE if mode == "userspace" else SERVICE)
        if tail:
            message += f" · 最近日志: {tail}"
        return False, message
    port = int(wg.get("port") or DEFAULT_PORT)
    listening = services.udp_port_listening(port)
    if listening is False:
        return False, f"{INTERFACE} 在, 但 UDP {port} 没有监听"
    if not nat_rule_present():
        return False, (
            f"{INTERFACE} 与 UDP {port} 都在, 但未见 NAT/MASQUERADE 规则 — "
            "客户端会显示已连接却上不了网"
        )
    active = len(active_peers(state))
    mode = str(bucket(state).get("active_mode") or "")
    mode_text = f" · {mode}" if mode else ""
    return True, f"{INTERFACE} 运行中{mode_text} · UDP {port} · {active} 个启用客户端"
