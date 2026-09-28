"""运行时状态管理。

所有可变参数集中保存在 $ZP_HOME/data/state.json (权限 0600)。
「修改配置 → 重新生成 → 热重载」闭环完全由这份状态驱动，
订阅 URL 恒定不变 (见 README「自动化逻辑」一节)。
"""
from __future__ import annotations

import copy
import json
import os
import threading
import time

DEFAULT_HOME = "/opt/zeroproxy"
#: 面板对外端口 (nginx 监听, 默认 8899) — 用于生成订阅/面板链接
PANEL_PORT = int(os.environ.get("ZP_PORT", "8899"))
#: 面板进程 (uvicorn) 自身监听地址 — 默认仅本机回环, 由 nginx 终结 TLS 并反代
PANEL_BIND_HOST = os.environ.get("ZP_BIND_HOST", "127.0.0.1")
PANEL_BIND_PORT = int(os.environ.get("ZP_BIND_PORT", "9900"))

LOCK = threading.RLock()

#: Reality 默认伪装的 SNI 目标 (技术文档 §7.6.3: 知名度高、TLS1.3、x25519 key_share)
DEFAULT_REALITY_DEST = "www.microsoft.com:443"
DEFAULT_REALITY_SNI = "www.microsoft.com"

#: WebSocket 传输路径 (nginx 反代 + 客户端 path 参数共用)
WS_PATH = "/ws/zeroproxy"

#: 节点元数据 — id 与 state["nodes"] 的键一致
NODES = [
    {
        "id": "vless-reality",
        "name": "VLESS Reality",
        "protocol": "VLESS",
        "transport": "TCP",
        "security": "XTLS-Reality (无证书)",
        "service": "xray",
        "desc": "反封锁最强组合, 免证书, 推荐主力节点",
    },
    {
        "id": "vless-ws",
        "name": "VLESS WebSocket",
        "protocol": "VLESS",
        "transport": "WebSocket",
        "security": "TLS 1.3 (Let's Encrypt)",
        "service": "xray",
        "desc": "nginx 443 反代, 浏览器/全平台兼容",
    },
    {
        "id": "trojan",
        "name": "Trojan",
        "protocol": "Trojan",
        "transport": "TCP",
        "security": "TLS 1.3 完美 HTTPS 伪装",
        "service": "xray",
        "desc": "协议层即 HTTPS, 流量整形抗 DPI",
    },
    {
        "id": "hysteria2",
        "name": "Hysteria 2",
        "protocol": "Hysteria 2",
        "transport": "QUIC/UDP",
        "security": "ChaCha20-Poly1305",
        "service": "hysteria2",
        "desc": "弱网最优, 支持端口跳跃抗封锁",
    },
]
NODE_IDS = [n["id"] for n in NODES]

DEFAULTS: dict = {
    "version": 1,
    "configured": False,
    "domain": "",
    "admin": {"username": "", "password_hash": ""},
    # 由 用户名+密码 确定性派生的 VLESS UUID (同一凭据始终得到同一 UUID)
    "uuid": "",
    "reality": {
        "private_key": "",   # base64(32B ed25519 seed)
        "public_key": "",    # base64(32B 公钥)
        "short_id": "",      # hex, 客户端 sid
        "dest": DEFAULT_REALITY_DEST,
        "server_name": DEFAULT_REALITY_SNI,
    },
    "trojan_password": "",
    "hysteria_password": "",
    "ports": {
        "reality": 8443,        # Xray Reality 直连
        "ws_internal": 6000,    # Xray WS 入站 (仅 127.0.0.1, nginx 终结 TLS)
        "trojan": 8444,         # Xray Trojan (复用同一证书)
        "hysteria": 30001,      # Hysteria 2 (UDP)
    },
    "hysteria_hopping": True,   # 端口跳跃 (技术文档 附录 C)
    "hysteria_ports": [30001, 31001, 32001],
    "nodes": {nid: True for nid in NODE_IDS},
    "cert": {
        "type": "none",  # none | letsencrypt | selfsigned
        "issuer": "",
        "cert_file": "",
        "key_file": "",
        "not_after": 0,
    },
    "subscription_token": "",
    "sessions": {},
    "created_at": 0,
    "updated_at": 0,
    "steps": [],
}


def home() -> str:
    return os.environ.get("ZP_HOME", DEFAULT_HOME)


def paths() -> dict:
    h = home()
    return {
        "home": h,
        "data_dir": f"{h}/data",
        "state": f"{h}/data/state.json",
        "xray_dir": f"{h}/xray",
        "xray_config": f"{h}/xray/config.json",
        "hysteria_dir": f"{h}/hysteria",
        "hysteria_config": f"{h}/hysteria/config.yaml",
        "hysteria_cert": f"{h}/hysteria/cert.pem",
        "hysteria_key": f"{h}/hysteria/key.pem",
        "cert_dir": f"{h}/certs",
        "cert_file": f"{h}/certs/cert.pem",
        "cert_key": f"{h}/certs/key.pem",
        # 面板自身的 HTTPS 自签证书 (install.sh 部署时生成; 不存在则面板回退明文 HTTP)
        "panel_dir": f"{h}/panel",
        "panel_cert": os.environ.get("ZP_PANEL_CERT", f"{h}/panel/cert.pem"),
        "panel_key": os.environ.get("ZP_PANEL_KEY", f"{h}/panel/key.pem"),
        "nginx_etc": "/etc/nginx/conf.d/zeroproxy.conf",
        "nginx_home": f"{h}/nginx/zeroproxy.conf",
        "nginx_dir": f"{h}/nginx",
        "www": f"{h}/www",
    }


def _ensure_dirs() -> None:
    p = paths()
    for key in ("data_dir", "xray_dir", "hysteria_dir", "cert_dir", "nginx_dir", "www", "panel_dir"):
        os.makedirs(p[key], exist_ok=True)


def _merge(base: dict, extra: dict) -> None:
    for key, value in extra.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _merge(base[key], value)
        else:
            base[key] = value


def load_state() -> dict:
    with LOCK:
        _ensure_dirs()
        state = copy.deepcopy(DEFAULTS)
        path = paths()["state"]
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    _merge(state, json.load(fh))
            except (json.JSONDecodeError, OSError):
                pass
        return state


def save_state(state: dict) -> None:
    with LOCK:
        _ensure_dirs()
        state["updated_at"] = int(time.time())
        path = paths()["state"]
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(state, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
