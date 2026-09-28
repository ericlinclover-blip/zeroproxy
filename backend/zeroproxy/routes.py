"""ZeroProxy API 路由。

设计要点:
  - POST /api/setup  接收 Domain/User/Pass 三要素 (+ 引导令牌) → 生成全部配置
    → 热加载 → 返回仪表盘。引导令牌来自 install.sh 打印的 URL, 防止面板在
    公网暴露时被他人抢先完成初始化。
  - 修改类接口 (节点开关 / 端口跳跃 / 高级设置 / 重新应用 / 续期) 只改状态,
    随后「重新生成配置 → reload nginx + restart xray/hysteria」。
    订阅 URL 恒定不变, 内容随节点启停变化, 客户端 App 自动拉取新内容。
  - 所有读-改-写都包在 config.locked() 事务里, 避免并发端点互相覆盖状态。
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import io
import ipaddress
import json
import os
import re
import shutil
import socket
import threading
import time

import qrcode
import qrcode.constants
import qrcode.image.pil  # noqa: F401  (PIL 后端需显式导入)
import qrcode.image.svg
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

from . import (
    apply,
    config,
    crypto,
    geodata,
    services,
    share_links,
    update,
    xray_config,
)
from .config import (
    NODES,
    NODE_BY_ID,
    NODE_IDS,
    XRAY_NODE_IDS,
    load_state,
    paths,
    save_state,
    state_from,
)

router = APIRouter()

SESSION_COOKIE = "zp_session"
SESSION_TTL = config.SESSION_TTL

#: 备份文件标识与版本
BACKUP_FORMAT = "zeroproxy-backup"
BACKUP_VERSION = 1
#: 恢复请求体上限 (state.json 只有几 KB, 4 MB 足够且能挡住内存滥用)
RESTORE_MAX_BYTES = 4 * 1024 * 1024

#: 登录限流: 连续失败 3 次后开始封禁, 时长 2^n 秒, 上限 300s
LOGIN_FREE_TRIES = 3
LOGIN_MAX_BLOCK = 300

_DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"
)
_USER_RE = re.compile(r"^[A-Za-z0-9._-]{2,32}$")
_SNI_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)+$")
_URL_RE = re.compile(r"^https?://[^\s\"'<>]+$")


# ---------------------------------------------------------------- 基础工具

def _steps_recorder() -> list[dict]:
    return []


def _add_step(steps: list[dict], name: str, fn, state: dict, timeout: int = 120) -> bool:
    start = time.time()
    try:
        ok, detail = fn(state, timeout)
    except Exception as exc:  # noqa: BLE001
        ok, detail = False, f"异常: {exc}"
    steps.append(
        {"name": name, "ok": ok, "detail": detail, "ms": int((time.time() - start) * 1000)}
    )
    return ok


def _err(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=code)


def _client_ip(request: Request) -> str:
    """经 nginx 反代时取 X-Forwarded-For 首个地址 (面板只信任本机 nginx)。"""
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()[:64]
    return (request.client.host if request.client else "unknown")[:64]


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------- 会话

def _session_of(state: dict, request: Request) -> str | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    session = state.get("sessions", {}).get(token)
    if not session:
        return None
    if session.get("expires", 0) < time.time():
        state["sessions"].pop(token, None)
        return None
    return token


def _require_auth(state: dict, request: Request) -> bool:
    return _session_of(state, request) is not None


def _issue_session(state: dict, request: Request, response: Response) -> None:
    token = crypto.new_token(32)
    sessions = state.setdefault("sessions", {})
    now = int(time.time())
    # 会话数上限: 超出时淘汰最早到期的一个 (防止令牌无限堆积)
    if len(sessions) >= config.MAX_SESSIONS:
        oldest = min(sessions, key=lambda t: sessions[t].get("expires", 0))
        sessions.pop(oldest, None)
    sessions[token] = {
        "username": state["admin"]["username"],
        "created": now,
        "expires": now + SESSION_TTL,
        "ip": _client_ip(request),
    }
    # 直连 https (含面板自签) 或经 https 反代 (X-Forwarded-Proto) 时启用 Secure 标记;
    # 若回退到明文 HTTP 访问则不启用 (否则 Cookie 会被浏览器丢弃)。
    fwd_proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        secure=request.url.scheme == "https" or fwd_proto == "https",
        samesite="lax",
        max_age=SESSION_TTL,
        path="/",
    )


def _clean_sessions(state: dict) -> int:
    now = time.time()
    before = len(state.get("sessions", {}))
    state["sessions"] = {
        t: s for t, s in state.get("sessions", {}).items() if s.get("expires", 0) > now
    }
    return before - len(state["sessions"])


# ---------------------------------------------------------------- 登录限流

def _login_blocked_for(state: dict, ip: str) -> int:
    """返回剩余封禁秒数 (0 = 未封禁), 顺带清理过期记录。"""
    now = time.time()
    failures = state.setdefault("login_failures", {})
    for key in [k for k, v in failures.items() if now - v.get("ts", 0) > 86400]:
        failures.pop(key, None)
    record = failures.get(ip)
    if not record:
        return 0
    return max(0, int(record.get("until", 0) - now))


def _login_failed(state: dict, ip: str) -> int:
    failures = state.setdefault("login_failures", {})
    record = failures.setdefault(ip, {"n": 0, "until": 0})
    record["n"] = int(record.get("n", 0)) + 1
    record["ts"] = int(time.time())
    if record["n"] > LOGIN_FREE_TRIES:
        block = min(2 ** (record["n"] - LOGIN_FREE_TRIES), LOGIN_MAX_BLOCK)
        record["until"] = int(time.time()) + block
        return block
    return 0


def _login_succeeded(state: dict, ip: str) -> None:
    state.setdefault("login_failures", {}).pop(ip, None)


# ---------------------------------------------------------------- 部署流程

class SetupIn(BaseModel):
    domain: str
    username: str
    password: str
    token: str = ""


def _install_cert(state: dict, timeout: int = 0) -> tuple[bool, str]:
    ok, detail, cert_state = services.install_cert(state["domain"])
    state["cert"] = cert_state
    return ok, detail


def _ensure_cert(state: dict, timeout: int = 0) -> tuple[bool, str]:
    """申请证书前的兜底: 先放一张自签证书, 让 nginx -t 一定过。

    `install_cert` 是在 nginx 80 端口 ACME 校验就绪之后才跑的, 而那份 nginx
    配置本身又引用证书文件 —— 没有这步会陷入「证书要 nginx, nginx 要证书」。
    """
    p = paths()
    cert = state.get("cert") or {}
    if cert.get("cert_file") and os.path.exists(cert["cert_file"]):
        return True, "已有证书文件可用"
    ok, detail = services.generate_self_signed(state["domain"], p["cert_file"], p["cert_key"])
    if ok:
        state["cert"] = {
            "type": "selfsigned",
            "issuer": "ZeroProxy 自签",
            "cert_file": p["cert_file"],
            "key_file": p["cert_key"],
            "not_after": int(time.time()) + 3650 * 86400,
        }
    return ok, detail


def _reload_nginx(state: dict, timeout: int = 0) -> tuple[bool, str]:
    """让刚落盘的 nginx 配置生效 (80 端口 ACME 校验路径)。"""
    ok, detail = services.reload_service("nginx", timeout or 60)
    if not ok and "跳过" not in detail:
        return False, f"nginx 重载失败: {detail}"
    if not ok:  # 本地开发 (无 systemctl): 不算失败
        return True, detail
    return True, "已重载 (80 端口 ACME 校验路径已就绪)"


def _reapply(state: dict, request: Request | None = None) -> list[dict]:
    """修改配置后的热更新闭环 (实现见 zeroproxy.apply, 与 upgrade.sh 共用)。"""
    return apply.reapply(state)


@router.post("/api/setup")
def setup(payload: SetupIn, request: Request):
    domain = payload.domain.strip().lower().rstrip(".")
    username = payload.username.strip()
    password = payload.password

    if not domain:
        return _err("请输入域名")
    if not (_DOMAIN_RE.match(domain) or _is_ip(domain)):
        return _err("域名格式无效 (示例: proxy.example.com)")
    if not _USER_RE.match(username):
        return _err("用户名需为 2-32 位字母/数字/_-.")
    if len(password) < 6 or len(password) > 128:
        return _err("密码长度需 6-128 位")

    expected = config.bootstrap_token()
    provided = (payload.token or request.headers.get("x-zp-token", "")).strip()
    if expected and not hmac.compare_digest(provided, expected):
        return _err("引导令牌无效: 请使用安装完成时终端打印的带 ?token= 的链接打开面板", 403)

    with config.locked():
        state = load_state()
        if state["configured"]:
            return _err("已完成配置, 请使用「重新应用」更新", 409)

        steps = _steps_recorder()

        def step_keys(state, t=0):
            # 1. 密钥材料: VLESS UUID 派生 / Reality X25519 密钥对 / 订阅令牌
            r = state["reality"]
            if not crypto.reality_key_valid(r["private_key"], r["public_key"]):
                r["private_key"], r["public_key"], r["short_id"] = crypto.new_reality_keys()
            state["uuid"] = crypto.derive_uuid(username, password)
            state["subscription_token"] = state["subscription_token"] or crypto.new_token()
            state["admin"] = {"username": username, "password_hash": crypto.hash_password(password)}
            return True, "UUID / Reality 密钥对 / 订阅令牌 就绪"

        _add_step(steps, "生成密钥材料", step_keys, state)
        if not steps[0]["ok"]:
            return JSONResponse(
                {"error": f"密钥生成失败: {steps[0]['detail']}", "steps": steps},
                status_code=500,
            )

        def step_state(state, t=0):
            state.update(
                {
                    "configured": True,
                    "domain": domain,
                    "trojan_password": password,
                    "hysteria_password": password,
                    "created_at": state["created_at"] or int(time.time()),
                }
            )
            save_state(state)
            return True, "已持久化"

        _add_step(steps, "写入面板状态", step_state, state)
        # 顺序很关键: 先把 nginx 的 80 端口 ACME 校验路径挂起来, certbot 才可能
        # 通过 webroot 验证拿到 Let's Encrypt 证书; 拿到后再生成引用真实证书的
        # nginx / xray (Trojan) 配置。反过来做只会永远退回自签证书。
        _add_step(steps, "生成 Hysteria 2 证书", lambda s, t: services.generate_hysteria_cert(s["domain"]), state)
        _add_step(steps, "预置自签证书 (引导 nginx)", _ensure_cert, state)
        _add_step(steps, "生成 Nginx 配置 (80 ACME + 面板)", apply.gen_nginx, state)
        _add_step(steps, "重载 Nginx", _reload_nginx, state)
        _add_step(steps, "申请 SSL 证书", _install_cert, state, timeout=360)
        _add_step(steps, "生成 Xray 配置", apply.gen_xray, state)
        _add_step(steps, "生成 Nginx 配置 (真实证书)", apply.gen_nginx, state)
        _add_step(steps, "生成 Hysteria 2 配置", apply.gen_hysteria, state)
        _add_step(steps, "启动/重载服务", apply.restart_services, state, timeout=180)
        _add_step(steps, "验证端口监听", apply.verify_listeners, state, timeout=12)

        _clean_sessions(state)
        failed = apply.failures(steps)
        config.audit(
            state,
            "setup",
            f"domain={domain}" + (f" · {len(failed)} 步失败: {failed[0]['name']}" if failed else ""),
            actor=username,
        )
        state["steps"] = steps
        save_state(state)
        body = _dashboard_body(state, request)
        body["steps"] = steps
        # 步骤结果不回吞: 前端据此显示红色告警, 而不是"全绿但节点不通"
        body["ok"] = not failed
        body["warning"] = (
            f"{failed[0]['name']}: {failed[0]['detail']}" if failed else ""
        )
        response = JSONResponse(body)
        _issue_session(state, request, response)
        save_state(state)
        # 初始化完成后不再接受第二次 setup: 作废引导令牌
        config.clear_bootstrap_token()
    return response


# ---------------------------------------------------------------- 认证

class LoginIn(BaseModel):
    username: str
    password: str


@router.post("/api/login")
def login(payload: LoginIn, request: Request):
    ip = _client_ip(request)
    with config.locked():
        state = load_state()
        if not state["configured"]:
            return _err("系统尚未初始化", 409)

        wait = _login_blocked_for(state, ip)
        if wait:
            response = _err(f"登录尝试过多, 请 {wait} 秒后重试", 429)
            response.headers["Retry-After"] = str(wait)
            return response

        if payload.username != state["admin"]["username"] or not crypto.verify_password(
            payload.password, state["admin"]["password_hash"]
        ):
            block = _login_failed(state, ip)
            config.audit(state, "login_failed", f"user={payload.username[:32]}", actor=ip)
            save_state(state)
            response = _err("用户名或密码错误", 401)
            if block:
                response.headers["Retry-After"] = str(block)
            return response

        _login_succeeded(state, ip)
        _clean_sessions(state)
        response = JSONResponse({"ok": True})
        _issue_session(state, request, response)
        config.audit(state, "login", actor=f"{payload.username}@{ip}")
        save_state(state)
    return response


@router.post("/api/logout")
def logout(request: Request):
    with config.locked():
        state = load_state()
        token = _session_of(state, request)
        if token:
            state["sessions"].pop(token, None)
            config.audit(state, "logout", actor=_client_ip(request))
            save_state(state)
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE)
    return response


@router.post("/api/logout-all")
def logout_all(request: Request):
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        count = len(state.get("sessions", {}))
        state["sessions"] = {}
        config.audit(state, "logout_all", f"cleared={count}", actor=_client_ip(request))
        save_state(state)
    response = JSONResponse({"ok": True, "cleared": count})
    response.delete_cookie(SESSION_COOKIE)
    return response


# ---------------------------------------------------------------- 仪表盘

def _port_for(state: dict, node_id: str) -> int:
    """节点对外端口: vless-ws 固定走 nginx 443, 其余取配置端口。"""
    if node_id == "vless-ws":
        return 443
    return state["ports"][NODE_BY_ID[node_id]["port_key"]]


def _node_view(state: dict, traffic: dict | None) -> dict:
    nodes = state.get("nodes", {})
    links = share_links.share_links(state)
    states = {name: services.service_state(name) for name in ("xray", "hysteria2", "nginx")}
    by_node = (traffic or {}).get("by_node", {})
    out = []
    for meta in NODES:
        nid = meta["id"]
        enabled = bool(nodes.get(nid, True))
        note = None
        if nid == "trojan" and enabled and not xray_config.cert_usable(state):
            note = "待证书: 证书未就绪, 入站未生效"
        out.append(
            {
                **meta,
                "enabled": enabled,
                "host": state["domain"],
                "port": _port_for(state, nid),
                "editable_port": nid != "vless-ws",
                "service_state": states.get(meta["service"], "unknown"),
                "share_link": links.get(nid) if enabled else None,
                "note": note,
                "qr_url": f"/api/nodes/{nid}/qr" if enabled else None,
                "traffic": by_node.get(nid, {"uplink": 0, "downlink": 0}) if traffic else None,
            }
        )
    return out


def _cert_view(state: dict) -> dict:
    cert = state["cert"]
    days_left = max(0, int((cert["not_after"] - time.time()) // 86400)) if cert["not_after"] else 0
    return {**cert, "days_left": days_left}


def _system_view(state: dict) -> dict:
    return {
        "xray": {
            "state": services.service_state("xray"),
            "version": services.service_version("xray"),
        },
        "hysteria2": {
            "state": services.service_state("hysteria2"),
            "version": services.service_version("hysteria2"),
        },
        "nginx": {"state": services.service_state("nginx")},
        "server": services.server_info(),
        "prod": services.is_prod(),
    }


def _dashboard_body(state: dict, request: Request, traffic: dict | None = None) -> dict:
    if traffic is None:
        traffic = services.xray_stats(state)
    sub = share_links.subscription_url(request, state)
    return {
        "configured": state["configured"],
        "domain": state["domain"],
        "admin_user": state["admin"]["username"],
        "panel_url": share_links.panel_base_url(request, state),
        "subscription_url": sub,
        "subscription_formats": {
            "base64": sub,
            "clash": f"{sub}?format=clash",
            "singbox": f"{sub}?format=singbox",
        },
        "cert": _cert_view(state),
        "nodes": _node_view(state, traffic),
        "routing": {
            "template": share_links.template_of(state),
            "templates": [
                {"id": "smart", "name": "智能分流", "desc": "国内直连 + 广告拦截, 其余走代理"},
                {"id": "global", "name": "全局代理", "desc": "除局域网外全部走代理"},
                {"id": "direct", "name": "全部直连", "desc": "不下载 geo 数据, 全部直连 (手动切组)"},
            ],
        },
        "hysteria_hopping": state.get("hysteria_hopping", False),
        "hysteria_ports": state.get("hysteria_ports", []),
        "hysteria_masquerade": state.get("hysteria_masquerade", {}),
        "reality": {
            "server_name": state["reality"]["server_name"],
            "dest": state["reality"]["dest"],
        },
        "geodata": geodata.status(state),
        "xhttp": state.get("xhttp", {}),
        "ports": state.get("ports", {}),
        "traffic": traffic,
        "audit": list(reversed(state.get("audit", [])))[:20],
        "system": _system_view(state),
    }


@router.get("/api/status")
def status(request: Request):
    state = load_state()
    return {
        "configured": state["configured"],
        "authenticated": _require_auth(state, request),
        # 前端据此提示「请用带 token 的链接打开」
        "token_required": bool(config.bootstrap_token()) and not state["configured"],
    }


@router.get("/api/dashboard")
def dashboard(request: Request):
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        if _clean_sessions(state):
            save_state(state)
        body = _dashboard_body(state, request)
        body["steps"] = state.get("steps", [])
    return body


# ---------------------------------------------------------------- 配置修改

@router.post("/api/nodes/{node_id}/toggle")
def toggle_node(node_id: str, request: Request):
    if node_id not in NODE_IDS:
        return _err("未知节点", 404)
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        state["nodes"][node_id] = not state["nodes"].get(node_id, True)
        config.audit(
            state,
            "toggle_node",
            f"{node_id}={'on' if state['nodes'][node_id] else 'off'}",
            actor=_client_ip(request),
        )
        steps = _reapply(state, request)
        body = _dashboard_body(state, request)
        body["steps"] = steps
        return body


@router.post("/api/hysteria/hopping")
def toggle_hopping(request: Request):
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        state["hysteria_hopping"] = not state.get("hysteria_hopping", False)
        config.audit(
            state,
            "toggle_hopping",
            f"enabled={state['hysteria_hopping']}",
            actor=_client_ip(request),
        )
        steps = _reapply(state, request)
        body = _dashboard_body(state, request)
        body["steps"] = steps
        return body


class SettingsIn(BaseModel):
    reality_sni: str | None = None
    masquerade_url: str | None = None
    ports: dict[str, int] | None = None
    # 客户端分流模板 (只影响订阅生成, 不动服务端配置)
    template: str | None = None
    # GeoIP 分流开关 (数据文件缺失时规则不会下发, 见 xray_config.geo_rules)
    geodata_enabled: bool | None = None
    block_private: bool | None = None
    block_ads: bool | None = None


@router.post("/api/settings")
def update_settings(payload: SettingsIn, request: Request):
    """高级设置: Reality 伪装 SNI / Hysteria 伪装站点 / 节点端口。"""
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)

        if payload.reality_sni is not None:
            if not _SNI_RE.match(payload.reality_sni.strip().lower()):
                return _err("伪装 SNI 需为合法域名 (示例: www.microsoft.com)")

        if payload.masquerade_url is not None:
            url = payload.masquerade_url.strip()
            if url and not _URL_RE.match(url):
                return _err("伪装站点需为 http(s) URL (示例: https://www.microsoft.com/)")

        new_template = ""
        if payload.template is not None:
            new_template = payload.template.strip().lower()
            if new_template not in share_links.TEMPLATES:
                return _err(f"分流模板只能是: {', '.join(share_links.TEMPLATES)}")

        new_ports: dict[str, int] = {}
        if payload.ports:
            for node_id, port in payload.ports.items():
                if node_id not in NODE_IDS or node_id == "vless-ws":
                    return _err(f"节点 {node_id} 不支持改端口")
                if not isinstance(port, int) or not (1 <= port <= 65535):
                    return _err(f"端口非法: {port}")
                new_ports[NODE_BY_ID[node_id]["port_key"]] = port

        # 端口冲突检查 (只检查真正要变化的端口; 面板自身端口由 nginx 占用属正常)
        for key, port in new_ports.items():
            if port == state["ports"].get(key):
                continue
            proto = "udp" if key == "hysteria" else "tcp"
            if not services.port_available(port, proto):
                return _err(f"端口 {port}/{proto} 已被占用, 请换一个")

        changed = []
        if payload.reality_sni is not None:
            sni = payload.reality_sni.strip().lower()
            state["reality"]["server_name"] = sni
            state["reality"]["dest"] = f"{sni}:443"
            changed.append(f"sni={sni}")

        if payload.masquerade_url is not None:
            url = payload.masquerade_url.strip()
            state["hysteria_masquerade"]["enabled"] = bool(url)
            state["hysteria_masquerade"]["url"] = url
            changed.append(f"masquerade={url or 'off'}")

        if new_template and new_template != state.get("routing", {}).get("template"):
            state.setdefault("routing", {})["template"] = new_template
            changed.append(f"template={new_template}")

        for key, port in new_ports.items():
            if port != state["ports"].get(key):
                state["ports"][key] = port
                changed.append(f"{key}={port}")
        # 端口跳跃的端口集合跟随主端口平移 (保持 3 个连续区间的间隔)
        if "hysteria" in new_ports and state.get("hysteria_hopping"):
            base = new_ports["hysteria"]
            state["hysteria_ports"] = [base, base + 1000, base + 2000]

        # GeoIP 分流开关
        geo = state.setdefault("geodata", {})
        if payload.geodata_enabled is not None and bool(payload.geodata_enabled) != bool(
            geo.get("enabled")
        ):
            if payload.geodata_enabled and not geodata.present():
                return _err("GeoIP 数据尚未下载, 请先点击「下载/更新 GeoIP 数据」")
            geo["enabled"] = bool(payload.geodata_enabled)
            geo["user_set"] = True
            changed.append(f"geodata={'on' if geo['enabled'] else 'off'}")
        for field, key in (("block_private", "block_private"), ("block_ads", "block_ads")):
            value = getattr(payload, field)
            if value is not None and bool(value) != bool(geo.get(key, True)):
                geo[key] = bool(value)
                geo["user_set"] = True
                changed.append(f"{key}={'on' if value else 'off'}")

        if not changed:
            return _err("没有需要修改的内容")

        config.audit(state, "settings", ", ".join(changed), actor=_client_ip(request))
        # 分流模板只影响订阅输出, 服务端配置一字不变 → 直接保存, 不做无谓的重载
        if all(item.startswith("template=") for item in changed):
            steps = _steps_recorder()
            steps.append(
                {
                    "name": "切换分流模板",
                    "ok": True,
                    "detail": f"{changed[0]} (订阅即刻生效, 未重载服务)",
                    "ms": 0,
                }
            )
            state["steps"] = steps
            save_state(state)
            body = _dashboard_body(state, request)
            body["steps"] = steps
            return body
        steps = _reapply(state, request)
        body = _dashboard_body(state, request)
        body["steps"] = steps
        return body


@router.post("/api/apply")
def apply_endpoint(request: Request):
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        config.audit(state, "apply", actor=_client_ip(request))
        steps = _reapply(state, request)
        body = _dashboard_body(state, request)
        body["steps"] = steps
        return body


@router.post("/api/renew")
def renew(request: Request):
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        before = (state.get("cert") or {}).get("cert_file", "")
        ok, detail = services.renew_cert(state)
        config.audit(state, "renew_cert", detail, actor=_client_ip(request))
        steps: list[dict] = []
        if ok and (state.get("cert") or {}).get("cert_file", "") != before:
            # 首次拿到 Let's Encrypt 证书: nginx / xray 里写的还是自签证书路径,
            # 必须重新生成配置并热重载, 否则浏览器 / 客户端仍看到自签证书。
            steps = _reapply(state, request)
        else:
            save_state(state)
    return {"ok": ok, "detail": detail, "steps": steps}


# ---------------------------------------------------------------- 诊断 / 自愈

def _check_tcp(hostport: str, label: str) -> tuple[bool, str]:
    host, _, port = hostport.partition(":")
    try:
        with socket.create_connection((host, int(port or 443)), timeout=5):
            return True, f"{label} 可连接"
    except Exception as exc:  # noqa: BLE001
        return False, f"{label} 连接失败: {exc}"


def _diagnose(state: dict) -> list[dict]:
    """逐项自检 (只读), 修复动作交给 /api/repair。"""
    checks: list[dict] = []

    def add(name: str, ok: bool, detail: str, fixable: bool = False) -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail, "fixable": fixable})

    prod = services.is_prod()

    # 1. 服务状态
    for service, label in (("xray", "Xray 核心"), ("hysteria2", "Hysteria 2"), ("nginx", "Nginx")):
        st = services.service_state(service)
        if not prod:
            add(label, True, f"{st} (本地开发环境, 跳过服务检查)")
        else:
            add(label, st in ("active", "running"), f"systemd 状态: {st}", fixable=True)

    # 2. 配置合法性
    config_file = paths()["xray_config"]
    if not os.path.exists(config_file):
        add("Xray 配置", False, "配置文件不存在", fixable=True)
    else:
        ok, detail = services.xray_config_test()
        add("Xray 配置", ok, "xray -test 通过" if ok else f"xray -test 失败: {detail}", fixable=True)

    # 3. 入站与节点开关一致
    cfg: dict = {}
    try:
        with open(config_file, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
        tags = {i.get("tag") for i in cfg.get("inbounds", [])}
        want = {
            nid
            for nid in XRAY_NODE_IDS
            if state["nodes"].get(nid) and (nid != "trojan" or xray_config.cert_usable(state))
        }
        missing = want - tags
        add(
            "入站与节点开关一致",
            not missing,
            "一致" if not missing else f"缺少入站: {', '.join(sorted(missing))}",
            fixable=True,
        )
    except (OSError, json.JSONDecodeError) as exc:
        add("入站与节点开关一致", False, f"读取配置失败: {exc}", fixable=True)

    # 3b. GeoIP 数据与分流规则的一致性 (不一致会让 Xray 整体启动失败)
    geo = geodata.status(state)
    rules_text = json.dumps(cfg.get("routing", {}).get("rules", []), ensure_ascii=False)
    rules_use_geo = ("geoip:" in rules_text) or ("geosite:" in rules_text)
    if rules_use_geo and not geodata.present():
        add("GeoIP 数据", False, "配置里有 geo 分流规则但数据文件缺失 — Xray 将无法启动", fixable=True)
    elif not geo["enabled"]:
        add("GeoIP 数据", True, "未启用分流 (下载数据后可开启私有地址防护/广告拦截)")
    else:
        age = geo["age_days"]
        add(
            "GeoIP 数据",
            geo["active"] and (age <= 30 or age < 0),
            f"{geo['source'] or '未知来源'} · {age} 天前更新 · "
            f"{'已启用分流' if geo['active'] else '数据缺失, 规则未下发'}",
        )

    # 4. 证书
    cert = state["cert"]
    if cert["type"] == "none":
        add("TLS 证书", False, "尚未申请证书 (Trojan / WS 节点不可用)", fixable=True)
    else:
        days = max(0, int((cert["not_after"] - time.time()) // 86400)) if cert["not_after"] else 0
        exists = bool(cert["cert_file"]) and os.path.exists(cert["cert_file"])
        add(
            "TLS 证书",
            exists and days > 7,
            f"{cert['type']} · 剩余 {days} 天 · {'文件存在' if exists else '文件缺失'}",
            fixable=True,
        )

    # 5. 端口占用
    if prod:
        busy = []
        for key, proto in (("reality", "tcp"), ("xhttp", "tcp"), ("trojan", "tcp"), ("hysteria", "udp")):
            port = state["ports"].get(key)
            if port and not services.port_available(port, proto):
                busy.append(f"{port}/{proto}")
        add("端口占用", not busy, "无冲突" if not busy else f"被占用: {', '.join(busy)}")

    # 6. 伪装目标可达性 (Reality / Trojan fallback 依赖它)
    ok, detail = _check_tcp(state["reality"]["dest"], f"Reality dest {state['reality']['dest']}")
    add("伪装目标可达性", ok, detail)

    return checks


@router.get("/api/diagnose")
def diagnose(request: Request):
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        checks = _diagnose(state)
    return {
        "ok": all(c["ok"] for c in checks),
        "checks": checks,
        "summary": f"{sum(1 for c in checks if c['ok'])}/{len(checks)} 项通过",
    }


@router.post("/api/repair")
def repair(request: Request):
    """一键自愈: 重新生成全部配置 → 校验 → 重启服务 → 复检。"""
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        config.audit(state, "repair", actor=_client_ip(request))
        steps = _reapply(state, request)
        checks = _diagnose(state)
    return {"ok": all(c["ok"] for c in checks), "steps": steps, "checks": checks}


@router.get("/api/traffic")
def traffic(request: Request):
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        stats = services.xray_stats(state)
    if not stats:
        return {"available": False, "detail": "统计不可用 (需要 Xray 已运行)"}
    return stats


# ---------------------------------------------------------------- 程序更新

@router.get("/api/update")
def update_status(request: Request, force: int = 0):
    """查看当前版本 / 远端最新版本 / 上次升级进度 (只读)。"""
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
    return update.status(force=bool(force))


@router.post("/api/update")
def update_start(request: Request):
    """一键更新: 后台拉起 upgrade.sh, 面板会随之重启。"""
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        ok, detail = update.start(trigger="panel")
        config.audit(state, "update", detail[:190], actor=_client_ip(request))
        save_state(state)
    if not ok:
        return _err(detail, 409)
    return {"ok": True, "detail": detail, "status": update.status()}


@router.get("/api/logs/{service}")
def logs(service: str, request: Request, lines: int = 40):
    if service not in ("xray", "hysteria2", "nginx", "zeroproxy"):
        return _err("未知服务", 404)
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
    return {"service": service, "log": services.journal_tail(service, max(5, min(int(lines), 200)))}


# ---------------------------------------------------------------- 连通性探测

#: 探测缓存 (浅探测 3s / 深度探测 20s 内重复点击直接复用结果)
_PROBE_CACHE: dict = {}
_PROBE_LOCK = threading.Lock()


@router.get("/api/probe")
def probe(request: Request, force: int = 0, deep: int = 0):
    """节点体检: 对每个本地入站做一次真实握手, 并测量服务器到伪装目标的 RTT。

    `?deep=1` 换成深度体检: 起一个临时 Xray 客户端, 真的从每个节点穿一次外网。
    浅探测只能证明端口在监听 —— Reality 认证失败时服务端会回落到真实伪装站点,
    裸 TLS 握手照样成功 (这就是"面板全绿但节点不通"的来源), 因此排查问题应当
    用 deep=1。
    """
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)

    want_deep = bool(deep)
    now = time.time()
    ttl = 20 if want_deep else 3
    key = "deep" if want_deep else "fast"
    with _PROBE_LOCK:
        entry = _PROBE_CACHE.get(key)
        if entry and not force and now - entry["at"] < ttl:
            return entry["body"]

    body = services.probe_all(state, deep=want_deep)
    with _PROBE_LOCK:
        _PROBE_CACHE[key] = {"at": time.time(), "body": body}
    return body


# ---------------------------------------------------------------- 备份 / 恢复

def _canonical(state: dict) -> str:
    """规范化序列化 (排序键 + 紧凑分隔符) — 校验和必须与序列化方式无关。"""
    return json.dumps(state, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _backup_payload(state: dict) -> dict:
    clean = copy.deepcopy(state)
    # 会话与登录限流是纯运行时数据, 备份里没有意义, 且不该被复制到别的机器
    clean.pop("sessions", None)
    clean.pop("login_failures", None)
    return {
        "format": BACKUP_FORMAT,
        "backup_version": BACKUP_VERSION,
        "panel_version": __import__("zeroproxy").__version__,
        "state_version": config.STATE_VERSION,
        "exported_at": int(time.time()),
        "checksum": hashlib.sha256(_canonical(clean).encode("utf-8")).hexdigest(),
        "state": clean,
    }


@router.get("/api/backup")
def backup(request: Request):
    """导出完整状态 (含 Reality 私钥 / 口令哈希 / 订阅令牌) — 需登录。"""
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        config.audit(state, "backup", f"domain={state['domain']}", actor=_client_ip(request))
        save_state(state)
        payload = _backup_payload(state)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime())
    return JSONResponse(
        payload,
        headers={
            "content-disposition": f'attachment; filename="zeroproxy-backup-{stamp}.json"',
            "cache-control": "no-store",
        },
    )


@router.post("/api/restore")
async def restore(request: Request):
    """从备份恢复状态, 然后重新生成全部配置并热重载。

    校验链: 结构 → 校验和 → 必填字段 → 状态版本。任一不过都保持现网不变。
    """
    raw = await request.body()
    if len(raw) > RESTORE_MAX_BYTES:
        return _err("备份文件过大", 413)

    with config.locked():
        current = load_state()
        if not _require_auth(current, request):
            return _err("未登录", 401)

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return _err(f"备份文件不是合法 JSON: {exc}")
    if not isinstance(payload, dict) or payload.get("format") != BACKUP_FORMAT:
        return _err("不是 ZeroProxy 备份文件 (缺少 format 标识)")

    data = payload.get("state")
    if not isinstance(data, dict):
        return _err("备份文件缺少 state 字段")

    expected = payload.get("checksum", "")
    candidate = copy.deepcopy(data)
    candidate.pop("sessions", None)
    candidate.pop("login_failures", None)
    actual = hashlib.sha256(_canonical(candidate).encode("utf-8")).hexdigest()
    if not hmac.compare_digest(str(expected), actual):
        return _err("备份文件校验和不匹配 (文件被修改或损坏)")

    if int(payload.get("state_version", 0) or 0) > config.STATE_VERSION:
        return _err(
            f"备份来自更新的面板 (state v{payload.get('state_version')})，请先升级再恢复"
        )

    restored = state_from(data)
    if not restored.get("configured"):
        return _err("备份不是已初始化状态, 拒绝恢复")
    for key in ("uuid", "subscription_token", "domain"):
        if not restored.get(key):
            return _err(f"备份缺少必填字段: {key}")
    # 只要求密钥存在: 旧备份里的 Ed25519 密钥对会在下面的 _reapply 里被自动换成
    # 合法的 X25519 (见 apply.ensure_reality_keys)
    if not restored["reality"].get("private_key") or not restored["reality"].get("public_key"):
        return _err("备份缺少 Reality 密钥对")
    if not restored["admin"].get("username") or not restored["admin"].get("password_hash"):
        return _err("备份缺少管理员凭据")

    with config.locked():
        # 恢复是"覆盖"操作: 先记审计再落盘 (审计属于新状态的一部分)
        restored["sessions"] = {}
        restored["login_failures"] = {}
        config.audit(
            restored,
            "restore",
            f"from={payload.get('panel_version', '?')} exported_at={payload.get('exported_at', 0)}",
            actor=_client_ip(request),
        )
        save_state(restored)
        steps = _reapply(restored, request)
        body = _dashboard_body(restored, request)
        body["steps"] = steps
        response = JSONResponse(body)
        _issue_session(restored, request, response)
        save_state(restored)
    return response


# ---------------------------------------------------------------- GeoIP 数据

#: 同一时间只允许一个下载任务 (几十 MB, 不做并发)
_GEO_UPDATE_LOCK = threading.Lock()


@router.post("/api/geodata/update")
def geodata_update(request: Request):
    """下载/刷新 GeoIP + GeoSite 数据, 然后重新生成配置并热重载。"""
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)

    if not _GEO_UPDATE_LOCK.acquire(blocking=False):
        return _err("已有更新任务在进行中", 409)
    try:
        ok, detail, _info = geodata.update(state)
    finally:
        _GEO_UPDATE_LOCK.release()

    with config.locked():
        fresh = load_state()
        if ok:
            fresh["geodata"] = state["geodata"]
        config.audit(
            fresh,
            "geodata_update" if ok else "geodata_update_failed",
            detail[:190],
            actor=_client_ip(request),
        )
        save_state(fresh)
        body = _dashboard_body(fresh, request)
        if ok:
            body["steps"] = _reapply(fresh, request)
    body["ok"] = ok
    body["detail"] = detail
    return body


# ---------------------------------------------------------------- 订阅 / 二维码

@router.get("/sub/{token}")
def subscribe(token: str, request: Request, format: str = "base64", rules: str = ""):
    state = load_state()
    if not state["configured"] or not hmac.compare_digest(
        token, state.get("subscription_token", "")
    ):
        return _err("无效订阅", 404)
    # rules 参数可对单个客户端覆盖分流模板 (?rules=smart|global|direct)
    body, media_type = share_links.subscription_body(state, format, rules)
    headers = {
        # 客户端按此周期自动刷新订阅 (小时), 节点启停/端口变更自动同步
        "profile-update-interval": "12",
        "cache-control": "no-store",
    }
    userinfo = share_links.subscription_userinfo(services.xray_stats(state))
    if userinfo:
        headers["subscription-userinfo"] = userinfo
    if format.lower() in ("clash", "mihomo", "yaml", "yml"):
        headers["content-disposition"] = 'attachment; filename="zeroproxy.yaml"'
    return Response(body, media_type=media_type, headers=headers)


class _CrispSvgPathImage(qrcode.image.svg.SvgPathImage):
    """矢量二维码: 关掉边缘抗锯齿, 放大缩小都是硬边方块 (位图缩小会糊成一片)。"""

    QR_PATH_STYLE = {**qrcode.image.svg.SvgPathImage.QR_PATH_STYLE, "shape-rendering": "crispEdges"}


def _qr_response(data: str, size: int = 8, img: str = "png") -> Response:
    """二维码图片。

    `img=png` (默认) 给"保存图片"用; `img=svg` 给屏幕显示用 —— 面板里的二维码是
    矢量缩放的, 位图被 CSS 缩到卡片宽度后会糊成一团, 手机上扫码容易失败。
    """
    size = max(2, min(int(size), 20))
    qc = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=size, border=2)
    qc.add_data(data)
    headers = {"cache-control": "no-store"}
    if (img or "png").lower() == "svg":
        buf = io.BytesIO()
        qc.make_image(image_factory=_CrispSvgPathImage).save(buf)
        return Response(buf.getvalue(), media_type="image/svg+xml", headers=headers)
    png = qc.make_image(image_factory=qrcode.image.pil.PilImage)
    buf = io.BytesIO()
    png.save(buf, format="PNG")
    return Response(buf.getvalue(), media_type="image/png", headers=headers)


def _qr_png(data: str, size: int = 8) -> Response:
    return _qr_response(data, size, "png")


@router.get("/api/nodes/{node_id}/qr")
def qr(node_id: str, request: Request, size: int = 8, img: str = "png"):
    if node_id not in NODE_IDS:
        return _err("未知节点", 404)
    state = load_state()
    if not _require_auth(state, request):
        return _err("未登录", 401)
    link = share_links.share_links(state).get(node_id, "")
    if not link:
        return _err("节点不可用", 409)
    return _qr_response(link, size, img)


@router.get("/api/subscription/qr")
def subscription_qr(request: Request, size: int = 8, format: str = "base64", img: str = "png"):
    """订阅二维码 (前端卡片上的「二维码」按钮; 之前误把 URL 当图片地址)。"""
    state = load_state()
    if not _require_auth(state, request):
        return _err("未登录", 401)
    url = share_links.subscription_url(request, state)
    if (format or "base64").lower() != "base64":
        url = f"{url}?format={format}"
    return _qr_response(url, size, img)
