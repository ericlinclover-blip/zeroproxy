"""Hysteria 2 配置生成器 (技术文档 §4 / 附录 C)。

- 证书: 自签名 (Hysteria 2 客户端通过 sni + insecure 校验), 首次部署生成, 无需公网 CA。
- 端口跳跃 (附录 C 方案 B): 启用时 listen 多个 UDP 端口, 客户端任选其一;
  未启用时仅监听默认端口。节点关闭时监听收敛到 127.0.0.1, 安全且可平滑重启。
"""
from __future__ import annotations

import os

from .config import paths

_TEMPLATE = """\
# 由 ZeroProxy 面板自动生成 — 修改请通过面板
# Hysteria 2 (QUIC/UDP) — 弱网最优, ChaCha20-Poly1305 加密
# 端口跳跃: listen 为逗号分隔端口集合 (当前 hysteria 版本要求字符串)
listen: "@LISTEN@"
tls:
  cert: @CERT@
  key: @KEY@
auth:
  type: password
  password: "@PASSWORD@"
bandwidth:
  down: 1 gbps
  up: 500 mbps
"""


def build_hysteria_config(state: dict) -> str:
    p = paths()
    enabled = state.get("nodes", {}).get("hysteria2", True)
    hopping = state.get("hysteria_hopping", False)

    if enabled and hopping:
        ports = state.get("hysteria_ports") or [state["ports"]["hysteria"]]
    else:
        ports = [state["ports"]["hysteria"]]

    host = "0.0.0.0" if enabled else "127.0.0.1"
    listen = f"{host}:{','.join(str(port) for port in ports)}"

    conf = _TEMPLATE
    for key, value in {
        "LISTEN": listen,
        "CERT": p["hysteria_cert"],
        "KEY": p["hysteria_key"],
        "PASSWORD": state["hysteria_password"].replace('"', '\\"'),
    }.items():
        conf = conf.replace(f"@{key}@", value)
    return conf


def write_hysteria_config(state: dict) -> None:
    p = paths()
    os.makedirs(p["hysteria_dir"], exist_ok=True)
    with open(p["hysteria_config"], "w", encoding="utf-8") as fh:
        fh.write(build_hysteria_config(state))
