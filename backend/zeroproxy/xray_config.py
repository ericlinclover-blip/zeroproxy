"""Xray 配置生成器 — 由面板状态驱动, 一键生成 $ZP_HOME/xray/config.json。

三个 Xray 入站 (对应技术文档中的协议组合):
  - vless-reality  VLESS + TCP + XTLS-Reality  技术文档 §7.3, 反封锁最强, 无需证书
  - vless-ws       VLESS + WebSocket           技术文档 §2.3 模块二, TLS 由 nginx 443 终结
  - trojan         Trojan + TLS 1.3            技术文档 §3, 完美 HTTPS 伪装, 复用 Let's Encrypt 证书

未启用的节点直接从 inbounds 中移除; 重新生成后 systemctl restart xray 即可热生效。
"""
from __future__ import annotations

import json
import os

from . import config
from .config import paths
from .config import WS_PATH


def _reality_inbound(state: dict) -> dict:
    r = state["reality"]
    ports = state["ports"]
    return {
        "tag": "vless-reality",
        "listen": "0.0.0.0",
        "port": ports["reality"],
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
        "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
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
                "certificates": [
                    {"certificate": cert["cert_file"], "key": cert["key_file"]}
                ],
            },
        },
        "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
    }


def _is_domain(host: str) -> bool:
    return "." in host


def cert_usable(state: dict) -> bool:
    """证书是否可用于 Trojan 入站 (文件存在)。"""
    cert = state["cert"]
    return cert.get("type") in ("letsencrypt", "selfsigned") and bool(
        cert.get("cert_file") and cert.get("key_file") and os.path.exists(cert["cert_file"])
    )


def build_xray_config(state: dict) -> dict:
    cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": [],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
        "routing": {"domainStrategy": "AsIs", "rules": []},
    }
    nodes = state.get("nodes", {})
    if nodes.get("vless-reality") and state["reality"]["private_key"]:
        cfg["inbounds"].append(_reality_inbound(state))
    if nodes.get("vless-ws"):
        cfg["inbounds"].append(_ws_inbound(state))
    if nodes.get("trojan") and cert_usable(state):
        cfg["inbounds"].append(_trojan_inbound(state))
    return cfg


def write_xray_config(state: dict) -> None:
    p = paths()
    os.makedirs(p["xray_dir"], exist_ok=True)
    with open(p["xray_config"], "w", encoding="utf-8") as fh:
        json.dump(build_xray_config(state), fh, indent=2)
    config.save_state(state)
