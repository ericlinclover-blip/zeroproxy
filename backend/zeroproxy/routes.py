"""ZeroProxy API 路由。

对应 Role.md 交付物 3/5 的设计:
  - POST /api/setup  接收 Domain/User/Pass 三要素 → 生成全部配置 → 热加载 → 返回仪表盘
  - 修改类接口 (节点开关 / 端口跳跃 / 重新应用 / 续期) 只改状态,
    随后「重新生成配置 → reload nginx + restart xray/hysteria」。
    订阅 URL 恒定不变, 内容随节点启停变化, 客户端 App 自动拉取新内容。
"""
from __future__ import annotations

import hmac
import io
import re
import shutil
import time

import qrcode
import qrcode.constants
import qrcode.image.pil  # noqa: F401  (PIL 后端需显式导入)
from cryptography.x509.oid import NameOID  # noqa: F401  (预留证书元信息)
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

from . import config, crypto, hysteria_config, nginx_config, services, share_links, xray_config
from .config import NODES, NODE_IDS, load_state, paths, save_state

router = APIRouter()

SESSION_COOKIE = "zp_session"
SESSION_TTL = 72 * 3600

_DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"
)
_USER_RE = re.compile(r"^[A-Za-z0-9._-]{2,32}$")


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
    state["sessions"][token] = {
        "username": state["admin"]["username"],
        "created": int(time.time()),
        "expires": int(time.time()) + SESSION_TTL,
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


def _clean_sessions(state: dict) -> None:
    now = time.time()
    state["sessions"] = {
        t: s for t, s in state.get("sessions", {}).items() if s.get("expires", 0) > now
    }


# ---------------------------------------------------------------- 部署流程

class SetupIn(BaseModel):
    domain: str
    username: str
    password: str


def _gen_xray(state: dict, timeout: int = 0) -> tuple[bool, str]:
    xray_config.write_xray_config(state)
    count = len(xray_config.build_xray_config(state)["inbounds"])
    if services.is_prod() and shutil.which("xray"):
        ok, out = services.run(["xray", "-test", "-c", config.paths()["xray_config"]], timeout=60)
        if not ok:
            return False, f"已生成但 xray -test 未通过: {' '.join(out.split())[:150]}"
        return True, f"已生成 ({count} 个入站, xray -test 通过)"
    return True, f"已生成 ({count} 个入站)"


def _gen_nginx(state: dict, timeout: int = 0) -> tuple[bool, str]:
    ok_etc, actual = nginx_config.write_nginx_conf(state)
    detail = f"已写入 {actual}" if ok_etc else (
        f"无 /etc/nginx 权限 → 已存 {actual} (服务器上由 install.sh 部署)"
    )
    if ok_etc and services.is_prod() and shutil.which("nginx"):
        ok, out = services.run(["nginx", "-t"], timeout=30)
        tail = " ".join(out.split())[:120]
        if not ok:
            return False, f"nginx -t 未通过: {tail}"
        detail += " (nginx -t 通过)"
    return True, detail


def _gen_hysteria(state: dict, timeout: int = 0) -> tuple[bool, str]:
    hysteria_config.write_hysteria_config(state)
    return True, "已生成"


def _install_cert(state: dict, timeout: int = 0) -> tuple[bool, str]:
    ok, detail, cert_state = services.install_cert(state["domain"])
    state["cert"] = cert_state
    return ok, detail


def _restart_services(state: dict, timeout: int = 0) -> tuple[bool, str]:
    results = []

    def run(name: str, fn, timeout: int) -> None:
        ok, detail = fn(timeout)
        mark = "✓" if ok else ("↷" if "跳过" in detail else "✗")
        results.append(f"{name} {mark} {detail}")

    nodes = state.get("nodes", {})
    if any(nodes.get(n) for n in ("vless-reality", "vless-ws", "trojan")):
        run("xray", services.restart_service, timeout or 90)
    if nodes.get("hysteria2"):
        run("hysteria2", services.restart_service, timeout or 90)
    run("nginx", services.reload_service, timeout or 60)
    if not results:
        return True, "无需操作"
    all_skipped = all("↷" in r for r in results)
    failed = any("✗" in r for r in results)
    return (all_skipped or not failed), "; ".join(results)


def _reapply(state: dict, request: Request | None = None) -> list[dict]:
    """修改配置后的热更新闭环: 重新生成 → 写盘 → 重载服务。"""
    steps = _steps_recorder()
    _add_step(steps, "重新生成 Xray 配置", _gen_xray, state)
    _add_step(steps, "重新生成 Nginx 配置", _gen_nginx, state)
    _add_step(steps, "重新生成 Hysteria 2 配置", _gen_hysteria, state)
    _add_step(steps, "重载服务 (nginx/xray/hysteria2)", _restart_services, state, timeout=180)
    state["steps"] = steps
    save_state(state)
    return steps


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

    state = load_state()
    if state["configured"]:
        return _err("已完成配置, 请使用「重新应用」更新", 409)

    steps = _steps_recorder()

    def step_keys(state, t=0):
        # 1. 密钥材料: VLESS UUID 派生 / Reality ed25519 密钥对 / 订阅令牌
        r = state["reality"]
        if not r["private_key"]:
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
    # 证书必须先生成: Trojan 入站 (xray) 与 443 (nginx) 都依赖证书文件,
    # 若在申请证书前生成配置, Trojan 入站会因 cert_usable() 为假而被漏掉。
    _add_step(steps, "申请 SSL 证书", _install_cert, state, timeout=360)
    _add_step(steps, "生成 Hysteria 2 证书", lambda s, t: services.generate_hysteria_cert(s["domain"]), state)
    _add_step(steps, "生成 Xray 配置", _gen_xray, state)
    _add_step(steps, "生成 Nginx 配置", _gen_nginx, state)
    _add_step(steps, "生成 Hysteria 2 配置", _gen_hysteria, state)
    _add_step(steps, "启动/重载服务", _restart_services, state, timeout=180)

    _clean_sessions(state)
    save_state(state)
    body = _dashboard_body(state, request)
    body["steps"] = steps
    response = JSONResponse(body)
    _issue_session(state, request, response)
    save_state(state)
    return response


def _is_ip(host: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------- 认证

class LoginIn(BaseModel):
    username: str
    password: str


@router.post("/api/login")
def login(payload: LoginIn, request: Request):
    state = load_state()
    if not state["configured"]:
        return _err("系统尚未初始化", 409)
    if payload.username != state["admin"]["username"] or not crypto.verify_password(
        payload.password, state["admin"]["password_hash"]
    ):
        return _err("用户名或密码错误", 401)
    response = JSONResponse({"ok": True})
    _issue_session(state, request, response)
    save_state(state)
    return response


@router.post("/api/logout")
def logout(request: Request):
    state = load_state()
    token = _session_of(state, request)
    if token:
        state["sessions"].pop(token, None)
        save_state(state)
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE)
    return response


# ---------------------------------------------------------------- 仪表盘

def _node_view(state: dict) -> dict:
    nodes = state.get("nodes", {})
    links = share_links.share_links(state)
    cert = state["cert"]
    states = {name: services.service_state(name) for name in ("xray", "hysteria2", "nginx")}
    out = []
    for meta in NODES:
        nid = meta["id"]
        enabled = bool(nodes.get(nid, True))
        link = links.get(nid, "")
        note = None
        if nid == "trojan" and enabled and not xray_config.cert_usable(state):
            note = "待证书: 证书未就绪, 入站未生效"
        out.append(
            {
                **meta,
                "enabled": enabled,
                "host": state["domain"],
                "port": _port_for(state, nid),
                "service_state": states.get(meta["service"], "unknown"),
                "share_link": link if enabled else None,
                "note": note,
                "qr_url": f"/api/nodes/{nid}/qr" if enabled else None,
            }
        )
    return out


def _port_for(state: dict, nid: str) -> int:
    """节点对外端口: vless-ws 固定走 nginx 443, 其余取配置端口。"""
    if nid == "vless-ws":
        return 443
    source = {"vless-reality": "reality", "trojan": "trojan", "hysteria2": "hysteria"}[nid]
    return state["ports"][source]


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
    }


def _dashboard_body(state: dict, request: Request) -> dict:
    p = paths()
    return {
        "configured": state["configured"],
        "domain": state["domain"],
        "admin_user": state["admin"]["username"],
        "panel_url": share_links.panel_base_url(request, state),
        "subscription_url": share_links.subscription_url(request, state),
        "cert": _cert_view(state),
        "nodes": _node_view(state),
        "hysteria_hopping": state.get("hysteria_hopping", False),
        "hysteria_ports": state.get("hysteria_ports", []),
        "system": _system_view(state),
    }


@router.get("/api/status")
def status(request: Request):
    state = load_state()
    return {
        "configured": state["configured"],
        "authenticated": _require_auth(state, request),
    }


@router.get("/api/dashboard")
def dashboard(request: Request):
    state = load_state()
    if not _require_auth(state, request):
        return _err("未登录", 401)
    body = _dashboard_body(state, request)
    body["steps"] = state.get("steps", [])
    return body


# ---------------------------------------------------------------- 配置修改 (自动化逻辑)

@router.post("/api/nodes/{node_id}/toggle")
def toggle_node(node_id: str, request: Request):
    if node_id not in NODE_IDS:
        return _err("未知节点", 404)
    state = load_state()
    if not _require_auth(state, request):
        return _err("未登录", 401)
    state["nodes"][node_id] = not state["nodes"].get(node_id, True)
    _reapply(state, request)
    return _dashboard_body(state, request)


@router.post("/api/hysteria/hopping")
def toggle_hopping(request: Request):
    state = load_state()
    if not _require_auth(state, request):
        return _err("未登录", 401)
    state["hysteria_hopping"] = not state.get("hysteria_hopping", False)
    _reapply(state, request)
    return _dashboard_body(state, request)


@router.post("/api/apply")
def apply(request: Request):
    state = load_state()
    if not _require_auth(state, request):
        return _err("未登录", 401)
    steps = _reapply(state, request)
    body = _dashboard_body(state, request)
    body["steps"] = steps
    return body


@router.post("/api/renew")
def renew(request: Request):
    state = load_state()
    if not _require_auth(state, request):
        return _err("未登录", 401)
    ok, detail = services.renew_cert(state)
    if ok:
        save_state(state)
    return {"ok": ok, "detail": detail}


# ---------------------------------------------------------------- 订阅 / 二维码

@router.get("/sub/{token}")
def subscribe(token: str, request: Request):
    state = load_state()
    if not state["configured"] or not hmac.compare_digest(
        token, state.get("subscription_token", "")
    ):
        return _err("无效订阅", 404)
    return Response(share_links.subscription_b64(state), media_type="text/plain; charset=utf-8")


@router.get("/api/nodes/{node_id}/qr")
def qr(node_id: str, request: Request, size: int = 8):
    if node_id not in NODE_IDS:
        return _err("未知节点", 404)
    state = load_state()
    if not _require_auth(state, request):
        return _err("未登录", 401)
    link = share_links.share_links(state).get(node_id, "")
    if not link:
        return _err("节点不可用", 409)
    size = max(2, min(size, 20))
    qc = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=size, border=2)
    qc.add_data(link)
    img = qc.make_image(image_factory=qrcode.image.pil.PilImage)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return Response(buf.getvalue(), media_type="image/png")
