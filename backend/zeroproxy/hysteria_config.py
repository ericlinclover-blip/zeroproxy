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
import re

import yaml

from . import config
from .config import paths

#: `listen` 的合法形态: `[地址]:端口[,端口...]` (端口跳跃是逗号分隔的多端口)。
_LISTEN_RE = re.compile(r"^(?:\[[0-9a-fA-F:.]+\]|[0-9A-Za-z.\-]*):(\d{1,5}(?:,\d{1,5})*)$")

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


def validate(config_text: str) -> list[str]:
    """校验一份 Hysteria 2 配置, 返回问题列表 (空列表 = 通过)。

    为什么需要它 (P2-12): 以前 apply 只检查证书文件在不在, 坏 YAML / 缺段会
    顺利写盘 —— systemd 重启后 hysteria2 永远起不来 (Restart 循环), 面板却显示
    "已生成"。这里用 `yaml.safe_load` 真解析一遍, 再逐项核对监听 / 认证 / TLS /
    伪装, 让 apply 在重启前就能判红。对照 Xray 的 `xray -test`、nginx 的 `nginx -t`。

    只做"能不能按结构跑起来"的检查, 不校验业务语义 (伪装站点是否可达等)。
    """
    try:
        data = yaml.safe_load(config_text)
    except yaml.YAMLError as exc:
        detail = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
        return [f"YAML 解析失败: {detail[:160]}"]
    if not isinstance(data, dict):
        return ["配置不是 YAML 映射 (顶层必须是键值对)"]

    problems: list[str] = []

    listen = data.get("listen")
    if not isinstance(listen, str) or not listen.strip():
        problems.append("缺少 listen (监听地址)")
    else:
        match = _LISTEN_RE.match(listen.strip())
        if not match:
            problems.append(f"listen 格式不合法: {listen}")
        else:
            for port in match.group(1).split(","):
                if not 1 <= int(port) <= 65535:
                    problems.append(f"listen 里的端口超出范围: {port}")
                    break

    auth = data.get("auth")
    if not isinstance(auth, dict):
        problems.append("缺少 auth 段")
    else:
        if str(auth.get("type") or "") != "password":
            problems.append("auth.type 必须是 password")
        if not str(auth.get("password") or "").strip():
            problems.append("auth.password 为空")

    tls = data.get("tls")
    if not isinstance(tls, dict):
        problems.append("缺少 tls 段")
    else:
        for key in ("cert", "key"):
            if not str(tls.get(key) or "").strip():
                problems.append(f"tls.{key} 为空")

    # masquerade 是可选功能 (节点停用 / 没配伪装站点时不生成该段), 有就必须完整
    masq = data.get("masquerade")
    if masq is not None:
        if not isinstance(masq, dict):
            problems.append("masquerade 必须是键值对")
        else:
            proxy = masq.get("proxy")
            if not isinstance(proxy, dict):
                problems.append("masquerade.proxy 缺失")
            elif not str(proxy.get("url") or "").strip():
                problems.append("masquerade.proxy.url 为空")
    return problems


def write_hysteria_config(state: dict) -> None:
    """原子落盘 Hysteria 2 配置 (写一半的 YAML 会让 hysteria2 起不来)。"""
    p = paths()
    os.makedirs(p["hysteria_dir"], exist_ok=True)
    config.atomic_write_text(p["hysteria_config"], build_hysteria_config(state), mode=0o600)
