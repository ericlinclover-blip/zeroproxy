"""客户端分享链接与订阅服务 (技术文档 §6 各协议客户端配置)。

链接均为各客户端 App 可直接导入的标准 URI:
  - vless://    VLESS (Reality / WS 两个节点)
  - trojan://   Trojan
  - hysteria2:// Hysteria 2

订阅: 所有启用节点的链接以换行拼接后整体 Base64 (标准订阅格式)。
订阅 URL 恒定不变 — 配置变化时仅内容更新, 客户端 App 自动拉取 (README「自动化逻辑」)。
"""
from __future__ import annotations

import base64
from urllib.parse import quote

from . import config
from .config import WS_PATH


def _name(s: str) -> str:
    return quote(s, safe="")


def _insecure(state: dict) -> str:
    """真实 Let's Encrypt 证书 → 0; 自签 → 1 (客户端跳过证书链校验)。"""
    return "1" if state["cert"]["type"] == "selfsigned" else "0"


def _pbk(public_key: str) -> str:
    """Reality pbk 参数要求 base64url 无填充 (state 中即该格式, 容错处理 std 输入)。"""
    if any(c in public_key for c in "+/") or public_key.endswith("="):
        raw = base64.urlsafe_b64decode(
            public_key.replace("-", "+").replace("_", "/") + "=" * (-len(public_key) % 4)
        )
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")
    return public_key


def share_links(state: dict) -> dict[str, str]:
    host = state["domain"]
    ports = state["ports"]
    r = state["reality"]
    uuid = state["uuid"]

    links: dict[str, str] = {}

    links["vless-reality"] = (
        f"vless://{uuid}@{host}:{ports['reality']}"
        # flow 必须与服务端 xray_config._reality_inbound 的 xtls-rprx-vision 一致,
        # 否则 Reality+Vision 双端不匹配会导致握手失败 (技术文档 §7.2)
        f"?encryption=none&flow=xtls-rprx-vision&security=reality&type=tcp"
        f"&pbk={_pbk(r['public_key'])}&sid={r['short_id']}"
        f"&sni={_name(r['server_name'])}&fp=chrome"
        f"#{_name('ZeroProxy VLESS Reality')}"
    )

    links["vless-ws"] = (
        f"vless://{uuid}@{host}:443"
        f"?type=ws&security=tls&path={_name(WS_PATH)}"
        f"&sni={_name(host)}&fp=chrome&allowInsecure={_insecure(state)}"
        f"#{_name('ZeroProxy VLESS WS')}"
    )

    links["trojan"] = (
        f"trojan://{quote(state['trojan_password'], safe='')}@{host}:{ports['trojan']}"
        f"?type=tcp&security=tls&sni={_name(host)}&allowInsecure={_insecure(state)}"
        f"#{_name('ZeroProxy Trojan')}"
    )

    links["hysteria2"] = (
        f"hysteria2://{quote(state['admin']['username'], safe='')}:"
        f"{quote(state['hysteria_password'], safe='')}@{host}:{ports['hysteria']}"
        f"?sni={_name(host)}&insecure=1"
        f"#{_name('ZeroProxy Hysteria 2')}"
    )

    return links


def subscription_content(state: dict) -> str:
    """仅包含启用节点的链接 (换行分隔)。"""
    links = share_links(state)
    nodes = state.get("nodes", {})
    return "\n".join(v for k, v in links.items() if nodes.get(k, True))


def subscription_b64(state: dict) -> str:
    return base64.b64encode(subscription_content(state).encode("utf-8")).decode("ascii")


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
