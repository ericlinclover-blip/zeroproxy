"""Nginx 配置生成器。

职责:
  - 80  端口: Let's Encrypt ACME webroot 验证 + 301 跳转 HTTPS
  - 443 端口: 终结 TLS (Let's Encrypt 或自签兜底)
      * /ws/zeroproxy → 127.0.0.1:6000 (Xray VLESS-WS)
      * /panel/ 与前端所需的 /api/、/static/ → 127.0.0.1:9900 (标准面板入口)
      * 其余路径 → 伪造的普通网页 (技术文档 §3.3 模块四: HTTPS 完美伪装)
  - 8899 端口: 面板自身 HTTPS —— 终结 TLS 后反代到本机面板进程:
       * SNI 命中域名 → 真实 Let's Encrypt 证书 (浏览器可信)
       * 其余 (IP / 未知 SNI) → 自签证书 (引导阶段兜底)

模板用 @KEY@ 占位符替换, 避免与 nginx 自身的 $ 变量冲突。
"""
from __future__ import annotations

import ipaddress
import os
import re

from . import config
from .config import paths, WS_PATH

_TEMPLATE = """\
# 由 ZeroProxy 面板自动生成 — 修改请通过面板, 本文件会被覆盖

# 凭据不进访问日志: 设备 secret / 订阅 token / 一次性链接可能出现在 URI 或 query 里。
# 日志字段用 $uri (不含 query string), 并让 /c/、/sub/、/wg/one/ 整条不记录。
map $uri $zeroproxy_loggable {
    default 1;
    ~^/(?:panel/)?c/ 0;
    ~^/(?:panel/)?sub/ 0;
    ~^/(?:panel/)?wg/one/ 0;
}

log_format zeroproxy_safe '$remote_addr - $remote_user [$time_local] '
                          '"$request_method $uri $server_protocol" $status $body_bytes_sent '
                          '"$http_referer" "$http_user_agent"';


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
        return 308 https://$host/panel$request_uri;
    }
}

# 域名之外的入口 (最常见的是 IP): 不落到发行版 nginx 的 default 站点,
# 而是明确告诉用户面板已经从明文初始化页切到 HTTPS。这里用正则兜底而不是
# default_server, 避免和发行版自带的 80 default 站点冲突。
server {
    listen 80;
    listen [::]:80;
    server_name ~^.+$;

    access_log /var/log/nginx/zeroproxy.access.log zeroproxy_safe if=$zeroproxy_loggable;

    location ^~ /.well-known/acme-challenge/ {
        root @WWW@;
    }

    location / {
        return 308 https://@DOMAIN@/panel$request_uri;
    }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name @DOMAIN@;

    access_log /var/log/nginx/zeroproxy.access.log zeroproxy_safe if=$zeroproxy_loggable;
    add_header Strict-Transport-Security "max-age=31536000" always;

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

    # 标准 HTTPS 入口: 云安全组通常只放行 80/443, 用户不应被迫额外放行面板端口。
    # /panel/ 去掉前缀后仍是面板根; 前端使用的 /api 与 /static 也反代到同一进程。
    location = /panel {
        return 308 /panel/;
    }
    location ^~ /panel/ {
        proxy_pass http://zeroproxy_panel/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 3600s;
    }
    location ^~ /api/ {
        proxy_pass http://zeroproxy_panel;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 3600s;
    }
    location ^~ /static/ {
        proxy_pass http://zeroproxy_panel;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 3600s;
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

    access_log /var/log/nginx/zeroproxy.access.log zeroproxy_safe if=$zeroproxy_loggable;
    add_header Strict-Transport-Security "max-age=31536000" always;

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

    access_log /var/log/nginx/zeroproxy.access.log zeroproxy_safe if=$zeroproxy_loggable;
    add_header Strict-Transport-Security "max-age=31536000" always;

    ssl_certificate @CERTFILE@;
    ssl_certificate_key @KEYFILE@;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
@PANEL_PROXY@
    }
}"""

# 初始化证书申请阶段的配置: 域名和用户当前使用的入口都留在 80 端口反代面板。
# 这时还没有 HTTP 入口所用的证书, 所以不能提前生成 443 server 块; 但 ACME
# 挑战必须按用户填写的域名命中 webroot。把域名与当前 Host 都列进去, 既能让
# certbot 工作, 也能在申请失败 / 等待时继续保留可重试的初始化页。
_SETUP_TEMPLATE = """\
# 由 ZeroProxy 初始化流程生成 — 证书完成前保留可重试的初始化入口

# 凭据不进访问日志: 设备 secret / 订阅 token / 一次性链接可能出现在 URI 或 query 里。
# 日志字段用 $uri (不含 query string), 并让 /c/、/sub/、/wg/one/ 整条不记录。
map $uri $zeroproxy_loggable {
    default 1;
    ~^/(?:panel/)?c/ 0;
    ~^/(?:panel/)?sub/ 0;
    ~^/(?:panel/)?wg/one/ 0;
}

log_format zeroproxy_safe '$remote_addr - $remote_user [$time_local] '
                          '"$request_method $uri $server_protocol" $status $body_bytes_sent '
                          '"$http_referer" "$http_user_agent"';

upstream zeroproxy_panel {
    server 127.0.0.1:@PANEL_BIND_PORT@;
}

server {
    listen @PANEL_PORT@ ssl default_server;
    listen [::]:@PANEL_PORT@ ssl default_server;
    server_name _;

    ssl_certificate @PANEL_SELFCERT@;
    ssl_certificate_key @PANEL_SELFKEY@;
    ssl_protocols TLSv1.2 TLSv1.3;

    access_log /var/log/nginx/zeroproxy.access.log zeroproxy_safe if=$zeroproxy_loggable;
    add_header Strict-Transport-Security "max-age=31536000" always;

    location / {
@PANEL_PROXY@
    }
}

server {
    listen 80;
    listen [::]:80;
    server_name @SERVER_NAMES@;

    access_log /var/log/nginx/zeroproxy.access.log zeroproxy_safe if=$zeroproxy_loggable;

    location ^~ /.well-known/acme-challenge/ {
        root @WWW@;
    }

    location / {
@PANEL_PROXY@
    }
}
"""

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


def _valid_server_name(raw: str) -> str:
    value = str(raw or "").strip().strip("[]").lower().rstrip(".")
    if not value or "/" in value or "\x00" in value:
        return ""
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", value):
        return value
    return ""


def build_setup_nginx_conf(state: dict, hosts: list[str] | tuple[str, ...]) -> str:
    """证书申请阶段使用的 nginx 配置, 保留初始化入口且支持域名 ACME。"""
    p = paths()
    names: list[str] = []
    for host in [*hosts, state.get("domain", "")]:
        name = _valid_server_name(host)
        if name and name not in names:
            names.append(name)
    if not names:
        names = ["127.0.0.1"]
    subs = {
        "SERVER_NAMES": " ".join(names),
        "WWW": p["www"],
        "PANEL_PORT": config.PANEL_PORT,
        "PANEL_BIND_PORT": config.PANEL_BIND_PORT,
        "PANEL_SELFCERT": p["panel_cert"],
        "PANEL_SELFKEY": p["panel_key"],
        "PANEL_PROXY": _PANEL_PROXY,
    }
    conf = _SETUP_TEMPLATE
    for key, value in subs.items():
        conf = conf.replace(f"@{key}@", str(value))
    return conf


def write_setup_nginx_conf(
    state: dict, hosts: list[str] | tuple[str, ...]
) -> tuple[bool, str]:
    """写入初始化阶段配置, 返回 (是否写入 /etc, 实际路径或说明)。"""
    from . import services

    p = paths()
    conf = build_setup_nginx_conf(state, hosts)
    os.makedirs(p["nginx_dir"], exist_ok=True)
    with open(p["nginx_home"], "w", encoding="utf-8") as fh:
        fh.write(conf)
    if not services.is_prod():
        return False, p["nginx_home"]
    try:
        os.makedirs(os.path.dirname(p["nginx_etc"]), exist_ok=True)
        with open(p["nginx_etc"], "w", encoding="utf-8") as fh:
            fh.write(conf)
        return True, p["nginx_etc"]
    except (PermissionError, OSError):
        return False, p["nginx_home"]


def write_nginx_conf(state: dict) -> tuple[bool, str]:
    """写入 nginx 配置。

    生产环境 (systemd 在位的 Linux) 才写 /etc/nginx/conf.d/; 其它情况一律落到
    $ZP_HOME/nginx/, 无权限时同样退回那里。
    返回 (是否写入 /etc, 实际路径或说明)。

    为什么按"是不是生产"判断, 而不只看有没有权限: 面板在服务器上是以 root 跑的,
    权限永远是有的 —— 于是一个临时实例 (换 ZP_HOME 起在别的端口上做验证 / 排查)
    也会顺手把**线上**的 /etc/nginx/conf.d/zeroproxy.conf 覆盖成它自己那份
    (指向临时目录的证书 / 端口), 下次 nginx reload 就起不来。v2.6.13 的排查里
    真踩到了这个坑。
    """
    from . import services  # 延迟导入, 避免模块级循环依赖

    p = paths()
    conf = build_nginx_conf(state)
    os.makedirs(p["nginx_dir"], exist_ok=True)
    with open(p["nginx_home"], "w", encoding="utf-8") as fh:
        fh.write(conf)
    # 伪造主页 (443 非代理路径返回, 技术文档 §3.3 模块四)
    os.makedirs(p["www"], exist_ok=True)
    with open(os.path.join(p["www"], "index.html"), "w", encoding="utf-8") as fh:
        fh.write(build_fake_index(state))
    if not services.is_prod():
        return False, p["nginx_home"]
    try:
        os.makedirs(os.path.dirname(p["nginx_etc"]), exist_ok=True)
        with open(p["nginx_etc"], "w", encoding="utf-8") as fh:
            fh.write(conf)
        return True, p["nginx_etc"]
    except (PermissionError, OSError):
        return False, p["nginx_home"]
