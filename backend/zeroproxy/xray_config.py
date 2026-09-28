"""Xray 配置生成器 — 由面板状态驱动, 一键生成 $ZP_HOME/xray/config.json。

四个 Xray 入站 (对应技术文档中的协议组合):
  - vless-reality  VLESS + TCP + XTLS-Reality + Vision   技术文档 §7.3, 反封锁最强, 免证书
  - vless-xhttp    VLESS + XHTTP + XTLS-Reality          技术文档 §9,   HTTP 形态, 特征最像普通流量
  - vless-ws       VLESS + WebSocket                     技术文档 §2.3, TLS 由 nginx 443 终结
  - trojan         Trojan + TLS 1.3                       技术文档 §3,   完美 HTTPS 伪装

另外固定开启 Stats API (仅 127.0.0.1): 面板通过 `xray api statsquery` 读取
上下行流量, 用于仪表盘统计与订阅的 subscription-userinfo 头。

未启用的节点直接从 inbounds 中移除; 重新生成后 systemctl restart xray 生效。
"""
from __future__ import annotations

import json
import os

from . import config
from .config import XHTTP_PATH, WS_PATH, paths


def _is_domain(host: str) -> bool:
    return "." in host


def _sniffing() -> dict:
    # destOverride 的合法取值是 http / tls / quic / fakedns — "dns" 不是,
    # Xray 26.x 遇到未知值会直接拒绝启动整份配置。
    return {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": False}


def _reality_inbound(state: dict) -> dict:
    r = state["reality"]
    return {
        "tag": "vless-reality",
        "listen": "0.0.0.0",
        "port": state["ports"]["reality"],
        "protocol": "vless",
        "settings": {
            # 技术文档写作 "xtls-rp"; xray 各版本官方名称为 xtls-rprx-vision
            "clients": [{"id": state["uuid"], "flow": "xtls-rprx-vision"}],
            "decryption": "none",
        },
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "tcpSettings": {"header": {"type": "none"}},
            "realitySettings": {
                "show": False,
                "xver": 0,
                "dest": r["dest"],
                "serverNames": [r["server_name"]],
                "privateKey": r["private_key"],
                "shortIds": [r["short_id"]],
            },
        },
        "sniffing": _sniffing(),
    }


def _xhttp_inbound(state: dict) -> dict:
    """VLESS + XHTTP + Reality (技术文档 §9)。

    XHTTP 把代理流量伪装成普通 HTTP 请求/响应流, 且可与 Reality 叠加,
    因此同样免证书。注意: Vision flow 只能用于 TCP, 这里 flow 必须为空。
    """
    r = state["reality"]
    x = state.get("xhttp", {})
    host = (x.get("host") or "").strip() or r["server_name"]
    return {
        "tag": "vless-xhttp",
        "listen": "0.0.0.0",
        "port": state["ports"]["xhttp"],
        "protocol": "vless",
        "settings": {
            "clients": [{"id": state["uuid"], "flow": ""}],
            "decryption": "none",
        },
        "streamSettings": {
            "network": "xhttp",
            "security": "reality",
            "xhttpSettings": {
                "host": host,
                "path": x.get("path") or XHTTP_PATH,
                "mode": x.get("mode") or "auto",
            },
            "realitySettings": {
                "show": False,
                "xver": 0,
                "dest": r["dest"],
                "serverNames": [r["server_name"]],
                "privateKey": r["private_key"],
                "shortIds": [r["short_id"]],
            },
        },
        "sniffing": _sniffing(),
    }


def _ws_inbound(state: dict) -> dict:
    return {
        "tag": "vless-ws",
        "listen": "127.0.0.1",
        "port": state["ports"]["ws_internal"],
        "protocol": "vless",
        "settings": {
            "clients": [{"id": state["uuid"], "flow": ""}],
            "decryption": "none",
        },
        "streamSettings": {
            "network": "websocket",
            "security": "none",  # TLS 由 nginx (443 + Let's Encrypt) 终结
            "wsSettings": {"path": WS_PATH},
        },
        "sniffing": _sniffing(),
    }


def _trojan_inbound(state: dict) -> dict:
    cert = state["cert"]
    return {
        "tag": "trojan",
        "listen": "0.0.0.0",
        "port": state["ports"]["trojan"],
        "protocol": "trojan",
        "settings": {
            "clients": [{"password": state["trojan_password"]}],
            # 非代理连接 → 转发到伪装目标 (技术文档 §3.3 模块四: HTTPS 完美伪装)
            "fallbacks": [{"dest": state["reality"]["dest"], "xver": 0}],
        },
        "streamSettings": {
            "network": "tcp",
            "security": "tls",
            "tlsSettings": {
                "serverName": state["domain"] if _is_domain(state["domain"]) else "",
                # Xray 25+ 的 TLSCertConfig 里 `certificate`/`key` 已改为 []string
                # (内联 PEM 内容), 证书路径必须用 certificateFile / keyFile。
                "certificates": [
                    {"certificateFile": cert["cert_file"], "keyFile": cert["key_file"]}
                ],
            },
        },
        "sniffing": _sniffing(),
    }


def _api_inbound(state: dict) -> dict:
    """Stats API 入站 (仅本机回环, 不对公网暴露)。"""
    return {
        "tag": "api",
        "listen": "127.0.0.1",
        "port": state["ports"]["api"],
        "protocol": "dokodemo-door",
        "settings": {"address": "127.0.0.1"},
    }


def cert_usable(state: dict) -> bool:
    """证书是否可用于 Trojan 入站 (文件存在)。"""
    cert = state["cert"]
    return cert.get("type") in ("letsencrypt", "selfsigned") and bool(
        cert.get("cert_file") and cert.get("key_file") and os.path.exists(cert["cert_file"])
    )


def build_xray_config(state: dict) -> dict:
    cfg = {
        "log": {"loglevel": "warning"},
        "stats": {},
        "api": {"tag": "api", "services": ["StatsService"]},
        "policy": {
            "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True,
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True,
            },
        },
        "inbounds": [],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
        "routing": {
            "domainStrategy": "AsIs",
            # API 入站的流量必须交给 tag=api 的内置处理器 (而不是 direct),
            # 否则 `xray api statsquery` 会直接连不上
            "rules": [{"type": "field", "inboundTag": ["api"], "outboundTag": "api"}],
        },
    }
    nodes = state.get("nodes", {})
    if nodes.get("vless-reality") and state["reality"]["private_key"]:
        cfg["inbounds"].append(_reality_inbound(state))
    if nodes.get("vless-xhttp") and state["reality"]["private_key"]:
        cfg["inbounds"].append(_xhttp_inbound(state))
    if nodes.get("vless-ws"):
        cfg["inbounds"].append(_ws_inbound(state))
    if nodes.get("trojan") and cert_usable(state):
        cfg["inbounds"].append(_trojan_inbound(state))
    # API 入站始终存在: 面板靠它读流量, 但如果没有启用的 xray 节点则没必要开
    if cfg["inbounds"]:
        cfg["inbounds"].append(_api_inbound(state))
    return cfg


def write_xray_config(state: dict) -> None:
    p = paths()
    os.makedirs(p["xray_dir"], exist_ok=True)
    with open(p["xray_config"], "w", encoding="utf-8") as fh:
        json.dump(build_xray_config(state), fh, indent=2)
    config.save_state(state)
