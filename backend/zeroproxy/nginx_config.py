"""Nginx 配置生成器。

职责:
  - 80  端口: Let's Encrypt ACME webroot 验证 + 301 跳转 HTTPS
  - 443 端口: 终结 TLS (Let's Encrypt 或自签兜底)
      * /ws/zeroproxy → 127.0.0.1:6000 (Xray VLESS-WS)
      * 其余路径 → 伪造的普通网页 (技术文档 §3.3 模块四: HTTPS 完美伪装)
  - 8899 端口: 面板自身 HTTPS —— 终结 TLS 后反代到本机面板进程:
       * SNI 命中域名 → 真实 Let's Encrypt 证书 (浏览器可信)
       * 其余 (IP / 未知 SNI) → 自签证书 (引导阶段兜底)

模板用 @KEY@ 占位符替换, 避免与 nginx 自身的 $ 变量冲突。
"""
from __future__ import annotations

import os
import time

from . import config
from .config import paths, WS_PATH

_TEMPLATE = """\
# 由 ZeroProxy 面板自动生成 — 修改请通过面板, 本文件会被覆盖
# generated: @TIMESTAMP@

upstream zeroproxy_vless_ws {
    server 127.0.0.1:@WS_PORT@;
}

# 面板进程 (uvicorn, 仅回环监听)
upstream zeroproxy_panel {
    server 127.0.0.1:@PANEL_BIND_PORT@;
}

server {
    listen 80;
    listen [::]:80;
    server_name @DOMAIN@;

    # Let's Encrypt ACME 验证
    location ^~ /.well-known/acme-challenge/ {
        root @WWW@;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name @DOMAIN@;

    ssl_certificate @CERTFILE@;
    ssl_certificate_key @KEYFILE@;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:zeroproxy:10m;
    ssl_session_timeout 1d;

    # VLESS-WebSocket 入站 (Xray 仅监听 127.0.0.1)
    location = @WSPATH@ {
        proxy_pass http://zeroproxy_vless_ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    # 其余一切路径: 返回正常网页, 让陌生访客/扫描器看到"普通网站"
    location / {
        root @WWW@;
        index index.html;
        try_files /index.html =404;
    }
}

# ---------------- 面板 HTTPS (对外 @PANEL_PORT@) ----------------
# 默认 server: 引导阶段 / 用 IP 访问时使用自签证书
server {
    listen @PANEL_PORT@ ssl default_server;
    listen [::]:@PANEL_PORT@ ssl default_server;
    server_name _;

    ssl_certificate @PANEL_SELFCERT@;
    ssl_certificate_key @PANEL_SELFKEY@;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
@PANEL_PROXY@
    }
}
@PANEL_DOMAIN_BLOCK@
"""

# 面板反代公共片段
_PANEL_PROXY = """\
        proxy_pass http://zeroproxy_panel;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 3600s;"""

# 域名命中时的面板 server 块: 用真实证书 (已配置域名才有意义)
_PANEL_DOMAIN_BLOCK = """\

server {
    listen @PANEL_PORT@ ssl;
    listen [::]:@PANEL_PORT@ ssl;
    server_name @DOMAIN@;

    ssl_certificate @CERTFILE@;
    ssl_certificate_key @KEYFILE@;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
@PANEL_PROXY@
    }
}"""

# 伪造主页 (技术文档 §3.3 模块四 fakeHTMLPage): 中性、看似正常的静态页面
_FAKE_INDEX = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Domain Reserved</title>
<style>
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#fafafa;color:#333}
.card{text-align:center;padding:3rem;border:1px solid #eee;border-radius:12px;background:#fff}
h1{font-size:1.4rem;margin:0 0 .5rem}p{color:#888;margin:0}
</style>
</head>
<body><div class="card"><h1>@DOMAIN@</h1><p>This domain is reserved.</p></div></body>
</html>
"""


def build_nginx_conf(state: dict) -> str:
    p = paths()
    cert = state["cert"]
    domain = (state.get("domain") or "").strip()
    # 未配置域名时去掉域名面板块 (只有默认自签块, 供引导阶段用)
    conf = _TEMPLATE.replace("@PANEL_DOMAIN_BLOCK@", _PANEL_DOMAIN_BLOCK if domain else "")
    subs = {
        "TIMESTAMP": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "DOMAIN": domain,
        "WS_PORT": state["ports"]["ws_internal"],
        "WSPATH": WS_PATH,
        "WWW": p["www"],
        "CERTFILE": cert.get("cert_file") or p["cert_file"],
        "KEYFILE": cert.get("key_file") or p["cert_key"],
        "PANEL_PORT": config.PANEL_PORT,
        "PANEL_BIND_PORT": config.PANEL_BIND_PORT,
        "PANEL_SELFCERT": p["panel_cert"],
        "PANEL_SELFKEY": p["panel_key"],
        "PANEL_PROXY": _PANEL_PROXY,
    }
    for key, value in subs.items():
        conf = conf.replace(f"@{key}@", str(value))
    return conf


def build_fake_index(state: dict) -> str:
    return _FAKE_INDEX.replace("@DOMAIN@", state["domain"])


def write_nginx_conf(state: dict) -> tuple[bool, str]:
    """写入 nginx 配置。

    优先写入 /etc/nginx/conf.d/; 无权限时 (本地开发) 落到 $ZP_HOME/nginx/。
    返回 (是否写入 /etc, 实际路径或说明)。
    """
    p = paths()
    conf = build_nginx_conf(state)
    os.makedirs(p["nginx_dir"], exist_ok=True)
    with open(p["nginx_home"], "w", encoding="utf-8") as fh:
        fh.write(conf)
    # 伪造主页 (443 非代理路径返回, 技术文档 §3.3 模块四)
    os.makedirs(p["www"], exist_ok=True)
    with open(os.path.join(p["www"], "index.html"), "w", encoding="utf-8") as fh:
        fh.write(build_fake_index(state))
    try:
        os.makedirs(os.path.dirname(p["nginx_etc"]), exist_ok=True)
        with open(p["nginx_etc"], "w", encoding="utf-8") as fh:
            fh.write(conf)
        return True, p["nginx_etc"]
    except (PermissionError, OSError):
        return False, p["nginx_home"]
