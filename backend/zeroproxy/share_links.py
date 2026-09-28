"""客户端分享链接与订阅服务 (技术文档 §6 各协议客户端配置)。

单节点链接均为各客户端 App 可直接导入的标准 URI:
  - vless://     VLESS Reality / XHTTP Reality / WebSocket
  - trojan://    Trojan
  - hysteria2:// Hysteria 2 (含端口跳跃)

订阅输出三种格式 (同一 URL, `?format=` 切换):
  - base64 (默认): 换行拼接后整体 Base64, 通用格式
  - clash         : mihomo / Clash.Meta 可直接加载的完整 YAML 配置
  - singbox       : sing-box 可直接加载的 JSON 配置

字段级依据 (均为上游一手来源):
  - hysteria2 URI: `app/cmd/client.go` 的 parseURI() — `user:pass@` 会把整串
    "user:pass" 当作 auth 发给服务端, 而 `extras/auth/password.go` 是整串比较,
    因此这里**只写密码**; 端口跳跃写在 host 的端口部分 (`host:30001,31001`),
    官方客户端用 isPortHoppingPort() 判定后走 udphop。
  - 订阅 URL 恒定不变 — 配置变化时仅内容更新, 客户端 App 自动拉取。
"""
from __future__ import annotations

import base64
import json
from urllib.parse import quote

import yaml

from . import config
from .config import WS_PATH, XHTTP_PATH

#: 各客户端对 XHTTP 传输的支持情况 — 已用真实二进制验证:
#: mihomo v1.19.31 接受 network: xhttp + xhttp-opts, sing-box 1.14.2 接受
#: transport.type=http, 两者配置校验均通过 (scripts/verify.py 可复现)。
CLASH_XHTTP = True
SINGBOX_XHTTP = True

SUB_FORMATS = ("base64", "clash", "singbox")


# ---------------------------------------------------------------- 通用小工具

def _q(text: str) -> str:
    """URL 组件编码 (分享链接里的名字/路径)。"""
    return quote(text, safe="")


def _pbk(public_key: str) -> str:
    """Reality pbk 参数要求 base64url 无填充 (state 中即该格式, 容错 std 输入)。"""
    if any(c in public_key for c in "+/") or public_key.endswith("="):
        raw = base64.urlsafe_b64decode(
            public_key.replace("-", "+").replace("_", "/") + "=" * (-len(public_key) % 4)
        )
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")
    return public_key


def _insecure(state: dict) -> bool:
    """自签证书 → 客户端需要跳过证书链校验。"""
    return state["cert"]["type"] != "letsencrypt"


def _node_name(node_id: str) -> str:
    meta = config.NODE_BY_ID.get(node_id)
    return f"ZeroProxy {meta['name']}" if meta else node_id


def _hysteria_ports(state: dict) -> list[int]:
    """Hysteria 2 实际监听的 UDP 端口列表。"""
    if state.get("nodes", {}).get("hysteria2") and state.get("hysteria_hopping", False):
        return list(state.get("hysteria_ports") or [state["ports"]["hysteria"]])
    return [state["ports"]["hysteria"]]


def _hysteria_hop_span(state: dict) -> str:
    """端口跳跃的紧凑写法: 连续端口折叠成 `a-b`, 否则逗号列表。"""
    ports = sorted(_hysteria_ports(state))
    if len(ports) > 2 and ports == list(range(ports[0], ports[-1] + 1)):
        return f"{ports[0]}-{ports[-1]}"
    return ",".join(str(p) for p in ports)


# ---------------------------------------------------------------- 单节点链接

def share_links(state: dict) -> dict[str, str]:
    host = state["domain"]
    ports = state["ports"]
    r = state["reality"]
    x = state.get("xhttp") or {}
    uuid = state["uuid"]
    xhttp_host = (x.get("host") or "").strip() or r["server_name"]
    xhttp_path = x.get("path") or XHTTP_PATH

    links: dict[str, str] = {}

    links["vless-reality"] = (
        f"vless://{uuid}@{host}:{ports['reality']}"
        # flow 必须与服务端 xray_config._reality_inbound 的 xtls-rprx-vision 一致,
        # 否则 Reality+Vision 双端不匹配会导致握手失败 (技术文档 §7.2)
        f"?encryption=none&flow=xtls-rprx-vision&security=reality&type=tcp"
        f"&pbk={_pbk(r['public_key'])}&sid={r['short_id']}"
        f"&sni={_q(r['server_name'])}&fp=chrome"
        f"#{_q(_node_name('vless-reality'))}"
    )

    links["vless-xhttp"] = (
        f"vless://{uuid}@{host}:{ports['xhttp']}"
        f"?encryption=none&security=reality&type=xhttp"
        f"&path={_q(xhttp_path)}&host={_q(xhttp_host)}&mode={_q(x.get('mode') or 'auto')}"
        f"&pbk={_pbk(r['public_key'])}&sid={r['short_id']}"
        f"&sni={_q(r['server_name'])}&fp=chrome"
        f"#{_q(_node_name('vless-xhttp'))}"
    )

    links["vless-ws"] = (
        f"vless://{uuid}@{host}:443"
        f"?type=ws&security=tls&path={_q(WS_PATH)}"
        f"&host={_q(host)}&sni={_q(host)}&fp=chrome"
        f"&allowInsecure={1 if _insecure(state) else 0}"
        f"#{_q(_node_name('vless-ws'))}"
    )

    links["trojan"] = (
        f"trojan://{_q(state['trojan_password'])}@{host}:{ports['trojan']}"
        f"?type=tcp&security=tls&sni={_q(host)}"
        f"&allowInsecure={1 if _insecure(state) else 0}"
        f"#{_q(_node_name('trojan'))}"
    )

    # 端口跳跃: 端口写在 host 上 (官方客户端据此启用 udphop), 同时附 mport 供
    # 支持该参数的三方客户端使用; 官方客户端会忽略未知查询参数。
    hop_ports = _hysteria_hop_span(state)
    links["hysteria2"] = (
        f"hysteria2://{_q(state['hysteria_password'])}@{host}:{hop_ports}"
        f"?sni={_q(host)}&insecure=1"
        f"&mport={_q(hop_ports)}"
        f"#{_q(_node_name('hysteria2'))}"
    )

    return links


def enabled_links(state: dict) -> list[tuple[str, str]]:
    """[(node_id, link)] — 仅包含启用中的节点, 顺序与 NODES 一致。"""
    links = share_links(state)
    nodes = state.get("nodes", {})
    order = [n["id"] for n in config.NODES]
    return [(nid, links[nid]) for nid in order if nodes.get(nid, True) and links.get(nid)]


# ---------------------------------------------------------------- 订阅: base64

def subscription_content(state: dict) -> str:
    """仅包含启用节点的链接 (换行分隔)。"""
    return "\n".join(link for _, link in enabled_links(state))


def subscription_b64(state: dict) -> str:
    return base64.b64encode(subscription_content(state).encode("utf-8")).decode("ascii")


# ---------------------------------------------------------------- 订阅: Clash

def _clash_proxy(state: dict, node_id: str) -> dict | None:
    host = state["domain"]
    ports = state["ports"]
    r = state["reality"]
    x = state.get("xhttp") or {}

    if node_id == "vless-reality":
        return {
            "name": _node_name(node_id),
            "type": "vless",
            "server": host,
            "port": ports["reality"],
            "uuid": state["uuid"],
            "udp": True,
            "tls": True,
            "flow": "xtls-rprx-vision",
            "servername": r["server_name"],
            "client-fingerprint": "chrome",
            "network": "tcp",
            "reality-opts": {"public-key": _pbk(r["public_key"]), "short-id": r["short_id"]},
        }
    if node_id == "vless-xhttp":
        if not CLASH_XHTTP:
            return None
        return {
            "name": _node_name(node_id),
            "type": "vless",
            "server": host,
            "port": ports["xhttp"],
            "uuid": state["uuid"],
            "udp": True,
            "tls": True,
            "servername": r["server_name"],
            "client-fingerprint": "chrome",
            "network": "xhttp",
            "xhttp-opts": {
                "path": x.get("path") or XHTTP_PATH,
                "host": (x.get("host") or "").strip() or r["server_name"],
                "mode": x.get("mode") or "auto",
            },
            "reality-opts": {"public-key": _pbk(r["public_key"]), "short-id": r["short_id"]},
        }
    if node_id == "vless-ws":
        return {
            "name": _node_name(node_id),
            "type": "vless",
            "server": host,
            "port": 443,
            "uuid": state["uuid"],
            "udp": True,
            "tls": True,
            "servername": host,
            "skip-cert-verify": _insecure(state),
            "client-fingerprint": "chrome",
            "network": "ws",
            "ws-opts": {"path": WS_PATH, "headers": {"Host": host}},
        }
    if node_id == "trojan":
        return {
            "name": _node_name(node_id),
            "type": "trojan",
            "server": host,
            "port": ports["trojan"],
            "password": state["trojan_password"],
            "udp": True,
            "sni": host,
            "skip-cert-verify": _insecure(state),
            "client-fingerprint": "chrome",
        }
    if node_id == "hysteria2":
        proxy = {
            "name": _node_name(node_id),
            "type": "hysteria2",
            "server": host,
            "password": state["hysteria_password"],
            "sni": host,
            "skip-cert-verify": True,
        }
        hop = _hysteria_hop_span(state)
        if "," in hop or "-" in hop:
            proxy["ports"] = hop
            proxy["hop-interval"] = 30
        else:
            proxy["port"] = int(hop)
        return proxy
    return None


def clash_profile(state: dict) -> str:
    proxies: list[dict] = []
    skipped: list[str] = []
    for node_id, _ in enabled_links(state):
        proxy = _clash_proxy(state, node_id)
        if proxy:
            proxies.append(proxy)
        else:
            skipped.append(_node_name(node_id))

    names = [p["name"] for p in proxies]
    profile = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select", "proxies": ["♻️ 自动选择", *names, "DIRECT"]},
            {
                "name": "♻️ 自动选择",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "proxies": names,
            },
        ],
        "rules": ["GEOIP,LAN,DIRECT,no-resolve", "GEOIP,CN,DIRECT", "MATCH,🚀 节点选择"],
    }
    head = [
        "# ZeroProxy 订阅 — Clash / mihomo",
        "# 直接导入 App 或保存为 config.yaml 使用; 订阅内容会随面板配置自动更新",
    ]
    if skipped:
        head.append(f"# 本客户端不支持的节点已跳过: {', '.join(skipped)} (请用 sing-box / 单节点链接)")
    body = yaml.safe_dump(profile, allow_unicode=True, sort_keys=False, default_flow_style=False)
    return "\n".join(head) + "\n" + body


# ---------------------------------------------------------------- 订阅: sing-box

def _singbox_outbound(state: dict, node_id: str) -> dict | None:
    host = state["domain"]
    ports = state["ports"]
    r = state["reality"]
    x = state.get("xhttp") or {}
    tag = _node_name(node_id)

    if node_id == "vless-reality":
        return {
            "type": "vless",
            "tag": tag,
            "server": host,
            "server_port": ports["reality"],
            "uuid": state["uuid"],
            "flow": "xtls-rprx-vision",
            "packet_encoding": "xudp",
            "tls": {
                "enabled": True,
                "server_name": r["server_name"],
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {
                    "enabled": True,
                    "public_key": _pbk(r["public_key"]),
                    "short_id": r["short_id"],
                },
            },
        }
    if node_id == "vless-xhttp":
        if not SINGBOX_XHTTP:
            return None
        return {
            "type": "vless",
            "tag": tag,
            "server": host,
            "server_port": ports["xhttp"],
            "uuid": state["uuid"],
            "packet_encoding": "xudp",
            "transport": {
                "type": "http",
                "host": [(x.get("host") or "").strip() or r["server_name"]],
                "path": x.get("path") or XHTTP_PATH,
            },
            "tls": {
                "enabled": True,
                "server_name": r["server_name"],
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {
                    "enabled": True,
                    "public_key": _pbk(r["public_key"]),
                    "short_id": r["short_id"],
                },
            },
        }
    if node_id == "vless-ws":
        return {
            "type": "vless",
            "tag": tag,
            "server": host,
            "server_port": 443,
            "uuid": state["uuid"],
            "packet_encoding": "xudp",
            "transport": {"type": "ws", "path": WS_PATH, "headers": {"Host": host}},
            "tls": {
                "enabled": True,
                "server_name": host,
                "insecure": _insecure(state),
                "utls": {"enabled": True, "fingerprint": "chrome"},
            },
        }
    if node_id == "trojan":
        return {
            "type": "trojan",
            "tag": tag,
            "server": host,
            "server_port": ports["trojan"],
            "password": state["trojan_password"],
            "tls": {
                "enabled": True,
                "server_name": host,
                "insecure": _insecure(state),
                "utls": {"enabled": True, "fingerprint": "chrome"},
            },
        }
    if node_id == "hysteria2":
        out = {
            "type": "hysteria2",
            "tag": tag,
            "server": host,
            "password": state["hysteria_password"],
            "tls": {"enabled": True, "server_name": host, "insecure": True},
        }
        ports_list = sorted(_hysteria_ports(state))
        if len(ports_list) == 1:
            out["server_port"] = ports_list[0]
        else:
            out["server_ports"] = [f"{p}:{p}" for p in ports_list]
            out["hop_interval"] = "30s"
        return out
    return None


def singbox_profile(state: dict) -> str:
    outbounds: list[dict] = []
    for node_id, _ in enabled_links(state):
        out = _singbox_outbound(state, node_id)
        if out:
            outbounds.append(out)

    tags = [o["tag"] for o in outbounds]
    outbounds.append({"type": "direct", "tag": "direct"})

    profile = {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 2080,
            }
        ],
        "outbounds": outbounds,
        # sing-box 1.11 起 sniff 等 legacy inbound 字段被移除, 改用路由动作
        "route": {"rules": [{"action": "sniff"}], "final": tags[0] if tags else "direct"},
    }
    return json.dumps(profile, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------- 订阅出口

def subscription_body(state: dict, fmt: str = "base64") -> tuple[str, str]:
    """返回 (响应体, media_type)。"""
    fmt = (fmt or "base64").lower()
    if fmt in ("clash", "mihomo", "yaml", "yml"):
        return clash_profile(state), "text/yaml; charset=utf-8"
    if fmt in ("singbox", "sing-box", "singbox-json", "json"):
        return singbox_profile(state), "application/json; charset=utf-8"
    return subscription_b64(state), "text/plain; charset=utf-8"


def subscription_userinfo(traffic: dict | None) -> str | None:
    """订阅流量头 (客户端据此显示已用流量)。无统计数据时返回 None。"""
    if not traffic:
        return None
    up = int(traffic.get("uplink", 0) or 0)
    down = int(traffic.get("downlink", 0) or 0)
    return f"upload={up}; download={down}; total=0; expire=0"


def panel_base_url(request, state: dict) -> str:
    """面板对外基址。

    已配置域名时优先用域名: 配合面板 TLS 的 SNI 真实证书, https://<域名>:<port>
    即为浏览器可信地址; 否则回退到请求本身 (bootstrap 阶段用 IP:端口)。
    """
    scheme = request.url.scheme
    domain = (state.get("domain") or "").strip()
    if not domain:
        return f"{scheme}://{request.headers.get('host', request.url.netloc)}"
    # 以面板对外端口为准 (经 nginx 反代时 Host 头不含端口)
    port = config.PANEL_PORT
    netloc = domain if port in (80, 443) else f"{domain}:{port}"
    return f"{scheme}://{netloc}"


def subscription_url(request, state: dict) -> str:
    return f"{panel_base_url(request, state)}/sub/{state['subscription_token']}"
