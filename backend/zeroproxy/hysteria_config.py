"""Hysteria 2 配置生成器 (技术文档 §4 / 附录 C)。

- 证书: 自签名 (客户端通过 sni + insecure 校验), 首次部署生成, 无需公网 CA。
- 端口跳跃 (附录 C 方案 B): 启用时 listen 为逗号分隔的多端口字符串
  (`0.0.0.0:30001,31001,32001`), 仅 Linux 支持多端口监听 (目标部署系统)。
- 伪装 (masquerade): 非代理流量反代到一个真实网站 (upstream 字段
  `masquerade.proxy.url` / `rewriteHost`, 见 hysteria `app/cmd/server.go`),
  这样探测者用浏览器直接访问 UDP 端口看到的是正常站点。
- 节点关闭时监听收敛到 127.0.0.1, 安全且可平滑重启。
"""
from __future__ import annotations

import os

from .config import paths

_TEMPLATE = """\
# 由 ZeroProxy 面板自动生成 — 修改请通过面板
# Hysteria 2 (QUIC/UDP) — 弱网最优, ChaCha20-Poly1305 加密
# 端口跳跃: listen 为逗号分隔端口集合 (当前 hysteria 版本要求字符串)
listen: @LISTEN@
tls:
  cert: @CERT@
  key: @KEY@
auth:
  type: password
  password: "@PASSWORD@"
@MASQUERADE@bandwidth:
  down: 1 gbps
  up: 500 mbps
"""

_MASQUERADE = """\
masquerade:
  type: proxy
  proxy:
    url: @URL@
    rewriteHost: true
"""


def _yaml_str(value: str) -> str:
    """把值渲染成安全的双引号 YAML 标量。"""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def build_hysteria_config(state: dict) -> str:
    enabled = state.get("nodes", {}).get("hysteria2", True)
    hopping = state.get("hysteria_hopping", False)

    if enabled and hopping:
        ports = state.get("hysteria_ports") or [state["ports"]["hysteria"]]
    else:
        ports = [state["ports"]["hysteria"]]

    host = "0.0.0.0" if enabled else "127.0.0.1"
    listen = f"{host}:{','.join(str(port) for port in ports)}"

    masq = state.get("hysteria_masquerade") or {}
    masq_url = (masq.get("url") or "").strip()
    masquerade = ""
    if enabled and masq.get("enabled", True) and masq_url:
        masquerade = _MASQUERADE.replace("@URL@", _yaml_str(masq_url))

    conf = _TEMPLATE
    for key, value in {
        "LISTEN": _yaml_str(listen),
        "CERT": paths()["hysteria_cert"],
        "KEY": paths()["hysteria_key"],
        "PASSWORD": state["hysteria_password"].replace("\\", "\\\\").replace('"', '\\"'),
        "MASQUERADE": masquerade,
    }.items():
        conf = conf.replace(f"@{key}@", value)
    return conf


def write_hysteria_config(state: dict) -> None:
    p = paths()
    os.makedirs(p["hysteria_dir"], exist_ok=True)
    with open(p["hysteria_config"], "w", encoding="utf-8") as fh:
        fh.write(build_hysteria_config(state))
