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

from . import config, geodata
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


def geo_rules(state: dict) -> list[dict]:
    """基于 GeoIP/GeoSite 的分流防护规则。

    硬前置: 只要 geo 数据文件不齐备就返回空列表。原因是 Xray 在配置构建阶段
    就要求数据文件存在, 缺文件时**整份配置加载失败**(见 geodata.py 顶部),
    宁可少两条规则也不能让核心起不来。
    """
    if not geodata.usable(state):
        return []
    geo = state.get("geodata", {})
    rules: list[dict] = []
    if geo.get("block_private", True):
        # 阻止客户端借道服务器访问其内网 / 私有网段 (SSRF 面收窄)
        rules.append({"type": "field", "outboundTag": "block", "ip": ["geoip:private"]})
    if geo.get("block_ads", True):
        rules.append(
            {"type": "field", "outboundTag": "block", "domain": ["geosite:category-ads-all"]}
        )
    return rules


# ---------------------------------------------------------------- 链式代理

def chain_exit_enabled(state: dict) -> bool:
    """本机是否作为落地端对外开放 (已生成专用凭据)。"""
    exit_cfg = (state.get("chain") or {}).get("exit") or {}
    return bool(exit_cfg.get("enabled")) and bool(exit_cfg.get("uuid"))


def chain_entries(state: dict) -> list[dict]:
    """本机作为中转端时, 已启用的落地端条目。"""
    return [e for e in (state.get("chain") or {}).get("entries") or [] if e.get("enabled", True)]


def chain_node_id(entry: dict) -> str:
    """链式节点 id —— 同时用作 Xray 入站 tag, 面板/订阅里到处都是这个值。"""
    return f"chain-{entry['id']}"


def _reality_stream(state: dict) -> dict:
    """本机 Reality 入站的 streamSettings (与主力节点共用同一套密钥与伪装目标)。"""
    r = state["reality"]
    return {
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
    }


def _chain_exit_inbound(state: dict) -> dict:
    """落地端入站: 给"别人的中转服务器"用的专用凭据 (独立 UUID / 独立端口)。

    与主力 Reality 节点同样的协议组合 —— 免证书, 且中转服务器的出站正好是
    VLESS Reality 客户端, 两端参数一一对应。
    """
    exit_cfg = state["chain"]["exit"]
    return {
        "tag": "chain-exit",
        "listen": "0.0.0.0",
        "port": int(exit_cfg["port"]),
        "protocol": "vless",
        "settings": {
            "clients": [{"id": exit_cfg["uuid"], "flow": "xtls-rprx-vision"}],
            "decryption": "none",
        },
        "streamSettings": _reality_stream(state),
    }


def _chain_entry_inbound(state: dict, entry: dict) -> dict:
    """中转端入站: 客户端连这里 (地址就是本机), 流量随后交给落地端出网。"""
    return {
        "tag": chain_node_id(entry),
        "listen": "0.0.0.0",
        "port": int(entry["local_port"]),
        "protocol": "vless",
        "settings": {
            "clients": [{"id": state["uuid"], "flow": "xtls-rprx-vision"}],
            "decryption": "none",
        },
        "streamSettings": _reality_stream(state),
    }


def chain_entry_outbound(entry: dict) -> dict:
    """中转端出站: 以 VLESS Reality 客户端身份连落地端。"""
    return {
        "tag": f"chain-out-{entry['id']}",
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": entry["host"],
                    "port": int(entry["port"]),
                    "users": [
                        {
                            "id": entry["uuid"],
                            "encryption": "none",
                            "flow": entry.get("flow") or "xtls-rprx-vision",
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
                "serverName": entry["sni"],
                "publicKey": entry["pbk"],
                "shortId": entry.get("sid") or "",
                "fingerprint": "chrome",
                "spiderX": "/",
            },
        },
    }


def local_inbound_tags(state: dict) -> list[str]:
    """本机主力节点当前启用的入站 tag (链式"设为默认出口"要把它们整体改道)。"""
    nodes = state.get("nodes", {})
    tags: list[str] = []
    if nodes.get("vless-reality") and state["reality"]["private_key"]:
        tags.append("vless-reality")
    if nodes.get("vless-xhttp") and state["reality"]["private_key"]:
        tags.append("vless-xhttp")
    if nodes.get("vless-ws"):
        tags.append("vless-ws")
    if nodes.get("trojan") and cert_usable(state):
        tags.append("trojan")
    return tags


def default_chain_entry(state: dict) -> dict | None:
    """被设为"默认出口"的链式条目 (同时只允许一个)。"""
    for entry in chain_entries(state):
        if entry.get("default_out"):
            return entry
    return None


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
    # geo 分流规则 (数据缺失时为空列表, 不影响核心启动)
    extra_rules = geo_rules(state)
    if extra_rules:
        cfg["outbounds"].append({"protocol": "blackhole", "tag": "block"})
        cfg["routing"]["rules"].extend(extra_rules)

    nodes = state.get("nodes", {})
    if nodes.get("vless-reality") and state["reality"]["private_key"]:
        cfg["inbounds"].append(_reality_inbound(state))
    if nodes.get("vless-xhttp") and state["reality"]["private_key"]:
        cfg["inbounds"].append(_xhttp_inbound(state))
    if nodes.get("vless-ws"):
        cfg["inbounds"].append(_ws_inbound(state))
    if nodes.get("trojan") and cert_usable(state):
        cfg["inbounds"].append(_trojan_inbound(state))

    # 链式代理: 中转端每条落地连接 = 一个入站 + 一个出站 + 一条路由规则
    entries = chain_entries(state)
    if chain_exit_enabled(state):
        cfg["inbounds"].append(_chain_exit_inbound(state))
    for entry in entries:
        cfg["inbounds"].append(_chain_entry_inbound(state, entry))
        cfg["outbounds"].append(chain_entry_outbound(entry))

    # API 入站始终存在: 面板靠它读流量, 但如果没有启用的 xray 节点则没必要开
    if cfg["inbounds"]:
        cfg["inbounds"].append(_api_inbound(state))

    # 路由顺序即优先级: API 处理 → geo 拦截 → 链式默认出口 → 各链式入口。
    # "设为默认出口"会把本机 4 个主力节点的流量整体改道到落地端 —— 这正是
    # "拿香港机器给美国落地加速"的用法; 放在 geo 拦截之后, 保证广告/私有地址
    # 的拦截规则依然优先。
    default_entry = default_chain_entry(state)
    if default_entry is not None:
        tags = local_inbound_tags(state)
        if tags:
            cfg["routing"]["rules"].append(
                {
                    "type": "field",
                    "inboundTag": tags,
                    "outboundTag": f"chain-out-{default_entry['id']}",
                }
            )
    for entry in entries:
        cfg["routing"]["rules"].append(
            {
                "type": "field",
                "inboundTag": [chain_node_id(entry)],
                "outboundTag": f"chain-out-{entry['id']}",
            }
        )
    return cfg


def write_xray_config(state: dict) -> None:
    p = paths()
    os.makedirs(p["xray_dir"], exist_ok=True)
    with open(p["xray_config"], "w", encoding="utf-8") as fh:
        json.dump(build_xray_config(state), fh, indent=2)
    config.save_state(state)
