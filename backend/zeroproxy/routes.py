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
import itertools
import json
import os
import re
import secrets
import socket
import threading
import time
import uuid as uuid_mod

import qrcode
import qrcode.constants
import qrcode.image.pil  # noqa: F401  (PIL 后端需显式导入)
import qrcode.image.svg
from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel

from . import (
    account,
    apply,
    chain,
    chain_quic,
    config,
    crypto,
    devices,
    geodata,
    router_client,
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

#: 端口跳跃的偏移量 (主端口 +0/+1000/+2000, 见 config.DEFAULTS["hysteria_ports"])
HOP_OFFSETS = (0, 1000, 2000)

_DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"
)
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


def _hopping_ports(base: int) -> list[int]:
    """端口跳跃的端口集合 —— 始终跟着当前主端口走 (带 1000 间隔的三个区间)。

    主端口被改过之后必须重新对齐: 否则「节点卡显示 40001」而 Hysteria 实际
    监听的还是上一轮的 30001/31001/32001, 端口校验也会误报。
    """
    return [p for p in (base + offset for offset in HOP_OFFSETS) if 1 <= p <= 65535] or [base]


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

    具体实现与「重新应用配置」共用 (见 apply.ensure_cert_files), 所以证书文件
    后来被删掉时, 那条路径也能自己补回来。
    """
    return apply.ensure_cert_files(state)


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


# ---------------------------------------------------------------- 后台落地任务
#
# 为什么要有这一层: 「重新生成配置 → 重启内核 → 验端口」在真机上要 2~4 秒
# (xray -test 0.7s + 重启 xray 0.9s + 端口恢复 0.7s), 而重启 Xray 会掐断
# "走本机链路上网"的浏览器 —— 很多用户就是用自己的节点访问面板的, 于是同步
# 等着干的结果是: 按钮转 4 秒、请求被中断、还可能看不到结果。
#
# 改成: 接口只做"改 state + 落盘 + 立刻回执", 闭环交给后台线程; 前端用
# `GET /api/apply/job?id=` 轮询进度 (400ms 一次), 页面全程可用, 进度条让
# "在动"和"卡住"一眼可分。后台任务自己拿 `config.locked()`, 所以并发点击会
# 自动串行化, 且每次都按最新 state 落地。
#
# `ZP_APPLY_ASYNC=0` 可退回同步返回 (测试 / 本地排查用)。
_APPLY_JOBS: dict[str, dict] = {}
_APPLY_JOBS_LOCK = threading.Lock()
_APPLY_SEQ = itertools.count(1)
#: 最多留几份任务记录 (前端轮询按 id 取; 留够"刚点完那几秒"就够用了)
_APPLY_JOB_KEEP = 8


def _apply_async_enabled() -> bool:
    return os.environ.get("ZP_APPLY_ASYNC", "1").strip() != "0"


def _job_snapshot(job: dict) -> dict:
    """给前端看的任务快照 (不含 state, 也就不需要拿配置锁)。"""
    started = float(job.get("started_at") or 0)
    end = job.get("finished_at")
    return {
        "id": job["id"],
        "kind": job.get("kind", "apply"),      # 前端据此改文案 (下载 GeoIP / 应用配置)
        "state": job["state"],
        "index": int(job.get("index") or 0),
        "total": int(job.get("total") or len(apply.STEP_NAMES)),
        "current": job.get("current", ""),
        "steps": job.get("steps", []),
        "error": job.get("error", ""),
        "elapsed_ms": int(max(0.0, float(end or time.time()) - started) * 1000) if started else 0,
    }


def _job_update(job_id: str, **fields) -> None:
    with _APPLY_JOBS_LOCK:
        job = _APPLY_JOBS.get(job_id)
        if job is not None:
            job.update(fields)


def _new_job(
    request: Request | None, total: int, current: str, kind: str = "apply"
) -> tuple[str, dict]:
    """登记一个后台任务, 返回 (id, 快照)。所有长耗时闭环共用这张表。"""
    with _APPLY_JOBS_LOCK:
        job_id = str(next(_APPLY_SEQ))
        job = {
            "id": job_id,
            "kind": kind,
            "state": "running",
            "index": 0,
            "total": total,
            "current": current,
            "steps": [],
            "error": "",
            "started_at": time.time(),
            "finished_at": None,
            # 只有发起这个任务的会话能查它的进度 (会话令牌本身就是面板的凭据)
            "token": (request.cookies.get(SESSION_COOKIE) if request is not None else "") or "",
        }
        _APPLY_JOBS[job_id] = job
        return job_id, job


def _finish_job(job_id: str, steps: list[dict], error: str = "") -> None:
    with _APPLY_JOBS_LOCK:
        job = _APPLY_JOBS.get(job_id)
        if job is not None:
            job.update(
                state="failed" if error else "done",
                steps=steps,
                error=error,
                finished_at=time.time(),
                index=job.get("index") or job.get("total") or 1,
            )
        stale = sorted(_APPLY_JOBS, key=lambda k: _APPLY_JOBS[k]["started_at"])[:-_APPLY_JOB_KEEP]
        for key in stale:
            _APPLY_JOBS.pop(key, None)


def _running_job(request: Request | None, kind: str | None = None) -> dict | None:
    """这个会话正在跑的任务。`kind` 用来区分"改配置"与"下载 GeoIP 数据" ——
    点 GeoIP 按钮时不能把正在跑的改配置任务当成自己的 (那会变成"下载被跳过")。
    """
    token = (request.cookies.get(SESSION_COOKIE) if request is not None else "") or ""
    with _APPLY_JOBS_LOCK:
        for job in _APPLY_JOBS.values():
            if (
                job.get("state") == "running"
                and job.get("token") == token
                and (kind is None or job.get("kind", "apply") == kind)
            ):
                return _job_snapshot(job)
    return None


def _run_apply_job(job_id: str, after=None) -> None:
    """后台线程: 跑完整闭环 (含"放行端口"这类收尾步骤), 结果写回任务表。"""
    steps: list[dict] = []
    error = ""
    try:
        with config.locked():
            state = load_state()
            steps = apply.reapply(
                state,
                progress=lambda index, total, name: _job_update(
                    job_id, index=index + 1, total=total, current=name
                ),
            )
            if after is not None:
                steps.extend(after())
    except Exception as exc:  # noqa: BLE001 — 后台任务不能把异常吞成"静默失败"
        error = f"{type(exc).__name__}: {exc}"
    _finish_job(job_id, steps, error)


def _reapply_job(
    state: dict, request: Request | None = None, after=None
) -> tuple[list[dict], dict | None]:
    """落地闭环: 生产环境返回 ([], 任务描述) 让前端轮询; 同步模式返回 (steps, None)。

    `after` 是收尾步骤 (如"放行落地端端口"): 它跟配置落地同属一次操作, 放进
    后台一起跑 —— 既省掉一次 `ufw status`, 也不用让用户为它多等。
    """
    if not _apply_async_enabled():
        steps = _reapply(state, request)
        if after is not None:
            steps.extend(after())
        return steps, None
    job_id, job = _new_job(request, len(apply.STEP_NAMES), apply.STEP_NAMES[0])
    # 先把这次改动落盘再放任务: 后台线程是从磁盘读最新 state 的 (load_state),
    # 不先存的话这次改的节点开关 / 链式条目就白改了。
    save_state(state)
    threading.Thread(
        target=_run_apply_job, args=(job_id, after), name=f"zp-apply-{job_id}", daemon=True
    ).start()
    return [], _job_snapshot(job)


@router.get("/api/apply/job")
def apply_job(id: str, request: Request):
    """后台落地任务的进度 (前端 400ms 轮询一次)。

    刻意**不读 state**: 任务正把整个闭环跑在 `config.locked()` 里, 这里再去
    `load_state()` 就会排队等它跑完, 进度条也就白做了。鉴权改为"必须是发起
    这个任务的那个会话" —— 令牌本身就是登录时发的那个。
    """
    with _APPLY_JOBS_LOCK:
        job = _APPLY_JOBS.get(str(id))
        if job is None:
            return _err("任务不存在或已过期", 404)
        token = request.cookies.get(SESSION_COOKIE) or ""
        if job.get("token") and job["token"] != token:
            return _err("未登录", 401)
        return _job_snapshot(job)


def _landing_body(state: dict, request: Request, after=None) -> dict:
    """改配置后的统一回执: 仪表盘数据 + 同步步骤 / 后台任务描述。

    同步模式 (ZP_APPLY_ASYNC=0) 里 `steps` 是完整的六步结果; 异步模式里
    `steps` 为空数组、`job` 有值, 前端据此轮询进度 —— 两种形状前端都认。
    """
    steps, job = _reapply_job(state, request, after=after)
    body = _dashboard_body(state, request)
    body["steps"] = steps
    if job is not None:
        body["job"] = job
    return body


@router.post("/api/setup")
def setup(payload: SetupIn, request: Request):
    domain = payload.domain.strip().lower().rstrip(".")
    username = payload.username.strip()
    password = payload.password

    if not domain:
        return _err("请输入域名")
    if not (_DOMAIN_RE.match(domain) or _is_ip(domain)):
        return _err("域名格式无效 (示例: proxy.example.com)")
    try:   # 与「面板设置」/ 终端 z 命令共用同一份校验 (见 account.py)
        username = account.validate_username(username)
        account.validate_password(password)
    except ValueError as exc:
        return _err(str(exc))

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
        # 初始化是在 IP 页面 (自签证书) 上做的: 真证书到手且域名可达时, 前端会把
        # 用户直接送到域名面板, 而不是让他继续对着"不安全"的地址用
        body["redirect"] = _post_setup_redirect(state, request)
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
    entry = share_links.chain_entry_of(state, node_id)
    if entry is not None:
        return int(entry.get("local_port") or 0)
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
    # 链式中转节点 (客户端连本机, 出网走落地端) —— 对面板就是"多了一张普通节点卡"
    for entry in (state.get("chain") or {}).get("entries") or []:
        nid = f"chain-{entry['id']}"
        enabled = bool(entry.get("enabled", True))
        probe = entry.get("last_probe") or {}
        label = (entry.get("label") or "").strip() or entry.get("host", "")
        out.append(
            {
                "id": nid,
                "name": f"链式 · {label}",
                "protocol": "VLESS",
                "transport": "链式中转 (TCP + Vision)",
                "security": f"经落地 {entry.get('host')}:{entry.get('port')}",
                "service": "xray",
                "desc": (
                    f"客户端连本机 {state['domain']}:{entry.get('local_port')}, "
                    f"出口 IP 是落地服务器 {entry.get('host')}"
                    + (" · 已设为默认出口 (本机所有节点都走它)" if entry.get("default_out") else "")
                ),
                "chain": True,
                "via": f"{entry.get('host')}:{entry.get('port')}",
                "default_out": bool(entry.get("default_out")),
                "last_probe": probe,
                "enabled": enabled,
                "host": state["domain"],
                "port": int(entry.get("local_port") or 0),
                "editable_port": False,
                "service_state": states.get("xray", "unknown"),
                "share_link": links.get(nid) if enabled else None,
                "note": None,
                "qr_url": f"/api/nodes/{nid}/qr" if enabled else None,
                "traffic": by_node.get(nid, {"uplink": 0, "downlink": 0}) if traffic else None,
            }
        )
    return out


def _cert_view(state: dict) -> dict:
    cert = state["cert"]
    days_left = max(0, int((cert["not_after"] - time.time()) // 86400)) if cert["not_after"] else 0
    return {**cert, "days_left": days_left}


def _post_setup_redirect(state: dict, request: Request) -> dict:
    """初始化完成后, 要不要把用户直接送到"真证书 + 域名"的面板。

    必须两个条件都成立才敢跳: 证书是 Let's Encrypt 签的, 并且从本机按浏览器的方式
    访问 `https://<域名>:<面板端口>/api/info` 真的能通 (DNS 已解析 + nginx 已挂真证书)。
    否则跳过去只会把用户扔到一个打不开或证书报错的页面 —— 那还不如留在 IP 页面并说清
    原因。用户是在 IP 页面上初始化的, 所以这一步是"从自签兜底切到正式入口"的唯一机会。
    """
    domain = (state.get("domain") or "").strip()
    url = share_links.panel_base_url(request, state)
    if not services.is_domain(domain):
        return {"ready": False, "url": url, "reason": "填写的是 IP, 没有域名面板可切"}
    if state.get("cert", {}).get("type") != "letsencrypt":
        return {"ready": False, "url": url,
                "reason": "证书不是 Let's Encrypt (域名可能还没解析到本机, 或 80 端口被挡)"}
    ok, detail = services.probe_public_panel(domain, config.PANEL_PORT)
    return {"ready": ok, "url": url, "reason": detail}


def _chain_view(state: dict) -> dict:
    """链式代理卡片的数据: 本机作为落地端的配对码 + 已连接的中转条目。"""
    chain_cfg = state.get("chain") or {}
    exit_cfg = chain_cfg.get("exit") or {}
    code = chain.exit_code(state)
    procs = chain_quic.status(state)
    entries = []
    for entry in chain_cfg.get("entries") or []:
        probe = entry.get("last_probe") or {}
        transport = entry.get("transport") or "reality"
        entries.append(
            {
                "id": entry.get("id", ""),
                "node_id": f"chain-{entry.get('id', '')}",
                "label": entry.get("label", ""),
                "host": entry.get("host", ""),
                "port": entry.get("port", 0),
                "local_port": entry.get("local_port", 0),
                "sni": entry.get("sni", ""),
                "transport": transport,
                # QUIC 内层的本地客户端进程活没活 (面板据此把"链路在跑但内层没起来"
                # 这种情况显示出来, 而不是只显示"运行中")
                "hy_ready": (
                    True
                    if transport != "hysteria2"
                    else bool(procs.get(f"entry-{entry.get('id', '')}"))
                ),
                "hy_bw": int(entry.get("hy_bw") or 0),
                "hy_port": int(entry.get("hy_port") or 0),
                "hy_socks_port": int(entry.get("hy_socks_port") or 0),
                "has_quic": bool(entry.get("hy_port") and entry.get("hy_pw")),
                "enabled": bool(entry.get("enabled", True)),
                "default_out": bool(entry.get("default_out")),
                "created_at": int(entry.get("created_at") or 0),
                "last_probe": probe,
            }
        )
    return {
        "exit": {
            "enabled": bool(exit_cfg.get("enabled")) and bool(exit_cfg.get("uuid")),
            "port": int(exit_cfg.get("port") or chain.DEFAULT_EXIT_PORT),
            "label": exit_cfg.get("label", ""),
            "created_at": int(exit_cfg.get("created_at") or 0),
            "code": code,
            "credential": (exit_cfg.get("uuid") or "")[:8],  # 只给前 8 位, 够用来认"是不是同一份"
            # 内层 QUIC (Hysteria 2) 可选: 给入口端用的 UDP 通道
            "hy_enabled": bool(exit_cfg.get("hy_enabled")),
            "hy_port": int(exit_cfg.get("hy_port") or chain_quic.DEFAULT_PORT),
            "hy_running": bool(procs.get("exit")),
            "hy_available": bool(chain_quic.binary()),
        },
        "entries": entries,
        "default_out": next((e["id"] for e in entries if e["default_out"]), ""),
    }


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
    # 面板首屏要的只有"最近这几条 + 各分类的条数", 更早的走 /api/audit 按需拉
    audit = config.audit_query(state, limit=20)
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
                {
                    "id": "smart",
                    "name": "智能分流",
                    "desc": "国内直连 (含微信/支付宝等 App) + 广告拦截, 其余走代理",
                },
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
        "chain": _chain_view(state),
        # 客户端设备 (路由器/手机/电脑) + 路由器安装脚本的元信息
        "devices": devices.view(state),
        "client": router_client.summary(),
        "xhttp": state.get("xhttp", {}),
        "ports": state.get("ports", {}),
        "traffic": traffic,
        "audit": audit["entries"],
        "audit_facets": audit["facets"],
        "audit_stats": audit["stats"],
        "audit_more": audit["has_more"],
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


@router.get("/api/audit")
def audit_list(
    request: Request,
    limit: int = 50,
    before: int = 0,
    category: str = "",
    q: str = "",
    failed: int = 0,
):
    """操作记录的一页 (新的在前)。

    为什么要有独立接口: 仪表盘每 20 秒拉一次, 把 500 条记录塞进去纯属浪费; 而
    "翻到更早的记录 / 按分类和关键字筛"只有用户真去看的时候才需要。分页用 id 游标
    而不是 offset —— 翻页期间随时会来新记录, offset 会让第二页混进已看过的条目。
    """
    state = load_state()
    if not _require_auth(state, request):
        return _err("未登录", 401)
    return config.audit_query(
        state,
        limit=limit,
        before=before or None,
        category=category.strip(),
        q=q.strip(),
        only_failed=bool(failed),
    )


@router.post("/api/audit/clear")
def audit_clear(request: Request):
    """清空面板保留的操作记录。

    只清 `state.json` 里的环形缓冲 (最近 500 条), **不动服务器上的归档文件**
    (`data/audit.log`): 那是"更早的记录"的唯一副本, 删文件是不可逆的动作, 不该由一个
    按钮顺手做掉 —— 面板上会把这一点写清楚。清空这个动作本身也会记一条, 所以清完不会
    出现"空得可疑、看不出谁动过"的状态。
    """
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        cleared = len(state.get("audit") or [])
        state["audit"] = []
        # 已归档计数跟着归零: 留着它会让面板显示"已归档 N 条", 而用户刚清过
        state["audit_dropped"] = 0
        config.audit(state, "audit_clear", f"cleared={cleared}", actor=_client_ip(request))
        save_state(state)
    body = config.audit_query(state, limit=30)
    body["cleared"] = cleared
    return body


# ---------------------------------------------------------------- 配置修改

@router.post("/api/nodes/{node_id}/toggle")
def toggle_node(node_id: str, request: Request):
    is_chain = node_id.startswith("chain-")
    if not is_chain and node_id not in NODE_IDS:
        return _err("未知节点", 404)
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        if is_chain:
            entry = share_links.chain_entry_of(state, node_id)
            if entry is None:
                return _err("未知的链式节点", 404)
            entry["enabled"] = not entry.get("enabled", True)
            if not entry["enabled"]:
                entry["default_out"] = False   # 停用的节点不能继续当默认出口
            label = f"{node_id}={'on' if entry['enabled'] else 'off'}"
        else:
            state["nodes"][node_id] = not state["nodes"].get(node_id, True)
            label = f"{node_id}={'on' if state['nodes'][node_id] else 'off'}"
        config.audit(state, "toggle_node", label, actor=_client_ip(request))
        return _landing_body(state, request)


@router.post("/api/hysteria/hopping")
def toggle_hopping(request: Request):
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        state["hysteria_hopping"] = not state.get("hysteria_hopping", False)
        if state["hysteria_hopping"]:
            # 打开跳跃时按当前主端口重排区间: 主端口被改过之后, 旧的跳跃区间
            # 会让面板显示的端口与实际监听的端口对不上
            state["hysteria_ports"] = _hopping_ports(int(state["ports"]["hysteria"]))
        config.audit(
            state,
            "toggle_hopping",
            f"enabled={state['hysteria_hopping']}"
            + (f" ports={state['hysteria_ports']}" if state["hysteria_hopping"] else ""),
            actor=_client_ip(request),
        )

        def open_hopping_ports() -> list[dict]:
            if not state["hysteria_hopping"]:
                return []
            return [
                {
                    "name": "放行端口跳跃区间",
                    "ok": True,
                    "detail": services.open_firewall_ports(state["hysteria_ports"], "udp"),
                    "ms": 0,
                }
            ]

        return _landing_body(state, request, after=open_hopping_ports)


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


class UpdateIn(BaseModel):
    """一键更新的可选项。

    `core` 默认 False: 内核 (Xray / Hysteria 2) 升级会改变配置语义, 只由用户在
    面板上显式勾选才会执行 —— 详见 update.start 的说明。
    """

    core: bool = False


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

        # 端口冲突检查。这里查的是"改完之后"的整份端口表, 而不是逐个探测一个端口:
        #   * 一次请求把两个节点改成同一个端口 (或挪到另一个节点正在用的端口、挪到
        #     WS 回环 / Stats API 端口) 当场拦下 —— 以前会一路放行到落地,
        #     由 `xray -test` 报端口重复, 面板上只看到一句含糊的失败;
        #   * 两个节点对调端口 (8443 ⇄ 8444) 必须允许: 它们会一起腾空, 而探测
        #     单个端口时看到的是"自己正在监听"(Linux 上必然 bind 失败), 老写法
        #     会把正常换端口也拦下来。
        proto_of = {"hysteria": "udp"}
        moving = {key for key, port in new_ports.items() if port != state["ports"].get(key)}
        freed = {int(state["ports"][key]) for key in moving if state["ports"].get(key)}
        merged = {**state["ports"], **new_ports}
        seen: dict[tuple[int, str], str] = {}
        for key in ("reality", "xhttp", "ws_internal", "api", "trojan", "hysteria"):
            port = int(merged.get(key) or 0)
            if port <= 0:
                continue
            proto = proto_of.get(key, "tcp")
            if (port, proto) in seen:
                return _err(
                    f"端口 {port}/{proto} 被 {seen[(port, proto)]} 与 {key} 同时占用, 请换一个"
                )
            seen[(port, proto)] = key
        # 链式代理的入站 / 落地端与 nginx 占着的端口也不允许被节点抢走
        chain_cfg = state.get("chain") or {}
        exit_cfg = chain_cfg.get("exit") or {}
        reserved_tcp = {80, 443, config.PANEL_PORT}
        if exit_cfg.get("uuid"):
            reserved_tcp.add(int(exit_cfg.get("port") or chain.DEFAULT_EXIT_PORT))
        reserved_tcp.update(
            int(entry["local_port"]) for entry in chain_cfg.get("entries") or [] if entry.get("local_port")
        )
        for key, port in new_ports.items():
            proto = proto_of.get(key, "tcp")
            if proto == "tcp" and port in reserved_tcp:
                return _err(f"端口 {port}/tcp 已被 nginx / 链式代理占用, 请换一个")
            # 本次会腾空的端口 (互换) 不算被占用; 其余真要变化的端口才做绑定探测
            if key in moving and port not in freed and not services.port_available(port, proto):
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

        moved_ports: list[tuple[str, int]] = []
        for key, port in new_ports.items():
            if port != state["ports"].get(key):
                state["ports"][key] = port
                moved_ports.append((key, port))
                changed.append(f"{key}={port}")
        # 端口跳跃的端口集合跟随主端口平移 (保持 3 个连续区间的间隔)
        if "hysteria" in new_ports and state.get("hysteria_hopping"):
            state["hysteria_ports"] = _hopping_ports(new_ports["hysteria"])

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

        def open_moved_ports() -> list[dict]:
            # 改过端口就得让防火墙跟上: install.sh 只按默认端口写了那几条放行规则,
            # 换了端口而 ufw 还挡着的话, 端口在本机是听的、面板全绿, 外面却连不上。
            out: list[dict] = []
            for key, port in moved_ports:
                if key == "hysteria" and state.get("hysteria_hopping"):
                    name, detail = (
                        "放行 Hysteria 2 端口 + 跳跃区间",
                        services.open_firewall_ports(state["hysteria_ports"], "udp"),
                    )
                else:
                    proto = "udp" if key == "hysteria" else "tcp"
                    name, detail = (
                        f"放行新端口 {port}/{proto}",
                        services.open_firewall_port(port, proto),
                    )
                out.append({"name": name, "ok": True, "detail": detail, "ms": 0})
            return out

        return _landing_body(state, request, after=open_moved_ports)


# ---------------------------------------------------------------- 链式代理

def _random_password(length: int = 24) -> str:
    """给专用凭据用的随机密码 (与面板密码无关, 泄露了只影响这一条链)。"""
    return secrets.token_urlsafe(length)[:length]


class ChainExitIn(BaseModel):
    action: str = "generate"      # generate | rotate | disable
    port: int | None = None
    label: str | None = None
    #: 是否额外开放「内层 QUIC」(Hysteria 2)。None = 不动这一项
    hy_enabled: bool | None = None
    hy_port: int | None = None


@router.post("/api/chain/exit")
def chain_exit(payload: ChainExitIn, request: Request):
    """本机作为落地端: 生成 / 轮换配对码, 改端口, 或直接关闭。

    凭据是**专用的** (独立 UUID + 独立端口), 与订阅里那份完全分开 ——
    所以把配对码给出去、或随时「重新生成」作废旧的, 都不影响自己的用户。
    """
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        if not state.get("configured"):
            return _err("请先完成初始化", 409)
        if not state["reality"].get("private_key"):
            return _err("本机 Reality 密钥未就绪, 请先在「高级设置 → 保存并应用」生成", 409)

        exit_cfg = state.setdefault("chain", {}).setdefault(
            "exit", {"enabled": False, "port": chain.DEFAULT_EXIT_PORT, "uuid": "", "label": "", "created_at": 0}
        )
        action = (payload.action or "generate").strip().lower()
        if action not in ("generate", "rotate", "disable"):
            return _err(f"不支持的操作: {action}")

        if action == "disable":
            if not exit_cfg.get("enabled"):
                return _err("落地端当前就是关闭的")
            exit_cfg["enabled"] = False
            # 关闭 = 连凭据一起作废: 否则重新开启后, 之前发出去的旧配对码会"复活"
            # (端口保留, 所以 _ports_that_must_be_closed 仍会盯着这个端口确认已关闭)
            exit_cfg["uuid"] = str(uuid_mod.uuid4())
            exit_cfg["hy_password"] = ""   # QUIC 内层那半截同样作废
            changed = ["关闭落地端 (入站已下线, 配对码作废且不会复用)"]
        else:
            changed = []
            # 本机地址 (域名 / IPv4) 会被原样写进配对码; IPv6 装不下, 当场说清
            host_error = chain.exit_host_error(state)
            if host_error:
                return _err(host_error)
            port = int(payload.port or exit_cfg.get("port") or chain.DEFAULT_EXIT_PORT)
            if not 1 <= port <= 65535:
                return _err("端口需在 1-65535 之间")
            if port != int(exit_cfg.get("port") or 0):
                occupied = chain.used_ports(state) - {int(exit_cfg.get("port") or 0)}
                if port in occupied:
                    return _err(f"端口 {port} 已被本机其它节点/链式条目占用, 换一个")
                if not services.port_available(port, "tcp"):
                    return _err(f"端口 {port}/tcp 已被系统里其它进程占用, 换一个")
                changed.append(f"落地端端口 {port}")
            if action == "rotate" or not exit_cfg.get("uuid"):
                exit_cfg["uuid"] = str(uuid_mod.uuid4())
                changed.append("生成新的专用凭据" if action != "rotate" else "轮换凭据 (旧配对码立即作废)")
            exit_cfg["port"] = port
            exit_cfg["enabled"] = True
            exit_cfg["created_at"] = int(exit_cfg.get("created_at") or time.time())

            # 内层 QUIC (Hysteria 2): 独立 UDP 端口 + 独立密码 + 按 SNI 自签的证书。
            # 关掉时把密码一并作废 —— 否则重新打开后, 旧配对码里的那半截还能用。
            if payload.hy_enabled is not None:
                want_hy = bool(payload.hy_enabled)
                if want_hy != bool(exit_cfg.get("hy_enabled")) or action == "rotate":
                    changed.append("开放内层 QUIC (Hysteria 2)" if want_hy else "关闭内层 QUIC")
                exit_cfg["hy_enabled"] = want_hy
                if want_hy:
                    exit_cfg["hy_sni"] = chain_quic.exit_sni(state)
                else:
                    # 关掉 = 那半截凭据当场作废: 否则重新打开时旧配对码的 QUIC 部分
                    # 会"复活"(Reality 那半截在关闭落地端时也是这么处理的)
                    exit_cfg["hy_password"] = ""
            if payload.hy_port is not None and int(payload.hy_port) != int(exit_cfg.get("hy_port") or 0):
                hy_port = int(payload.hy_port)
                if not 1 <= hy_port <= 65535:
                    return _err("QUIC 端口需在 1-65535 之间")
                if hy_port != int(exit_cfg.get("port") or 0) and hy_port in chain.used_ports(state):
                    return _err(f"QUIC 端口 {hy_port} 已被本机其它节点/链式条目占用, 换一个")
                if not services.port_available(hy_port, "udp"):
                    return _err(f"端口 {hy_port}/udp 已被系统里其它进程占用, 换一个")
                exit_cfg["hy_port"] = hy_port
                changed.append(f"QUIC 端口 {hy_port}/udp")
            if exit_cfg.get("hy_enabled"):
                if not exit_cfg.get("hy_password") or action == "rotate":
                    exit_cfg["hy_password"] = _random_password()
                    changed.append("QUIC 专用密码已生成" if action != "rotate" else "QUIC 密码已轮换")
                ok_cert, cert_detail = chain_quic.ensure_exit_cert(state)
                if not ok_cert:
                    return _err(f"QUIC 内层证书生成失败: {cert_detail}")
            if payload.label is not None:
                label = payload.label.strip()[:40]
                if label != (exit_cfg.get("label") or ""):
                    exit_cfg["label"] = label
                    changed.append(f"名称改为「{label}」")
            if not changed:
                changed.append("落地端已是最新状态")

        config.audit(state, "chain_exit", "; ".join(changed), actor=_client_ip(request))

        def open_exit_port() -> list[dict]:
            if not exit_cfg.get("enabled"):
                return []
            rows = [
                {
                    "name": "放行落地端端口",
                    "ok": True,
                    "detail": services.open_firewall_port(exit_cfg["port"], "tcp"),
                    "ms": 0,
                }
            ]
            if exit_cfg.get("hy_enabled"):
                # QUIC 内层是 UDP: 与主 Hysteria 2 节点一样, 没放行的话客户端一直超时
                rows.append(
                    {
                        "name": "放行落地端 QUIC 端口 (UDP)",
                        "ok": True,
                        "detail": services.open_firewall_port(exit_cfg["hy_port"], "udp"),
                        "ms": 0,
                    }
                )
            return rows

        return _landing_body(state, request, after=open_exit_port)


class ChainEntryIn(BaseModel):
    code: str = ""
    label: str | None = None
    local_port: int | None = None
    default_out: bool = False
    #: 内层传输: reality (默认) | hysteria2 —— 后者要求配对码里有 QUIC 凭据
    transport: str | None = None
    #: 探测不通时是否仍然强行添加 (面板会二次确认)
    force: bool = False


@router.post("/api/chain/entries")
def chain_entry_add(payload: ChainEntryIn, request: Request):
    """中转端: 粘贴落地端的配对码 → 校验 → 真实握手 → 落地成新节点。"""
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        if not state.get("configured"):
            return _err("请先完成初始化", 409)

        try:
            target = chain.parse_code(payload.code)
        except chain.CodeError as exc:
            return _err(str(exc))

        # 内层传输: 默认 Reality; 选 QUIC 时必须真的有 QUIC 凭据 + 本机有 hysteria
        transport = (payload.transport or "reality").strip().lower()
        if transport not in ("reality", "hysteria2"):
            return _err(f"不支持的内层传输: {transport}")
        if transport == "hysteria2":
            if not target.get("hy_port"):
                return _err(
                    "这份配对码里没有 QUIC 凭据 (落地端还没开「内层 QUIC」); "
                    "请让落地端打开后再复制一次配对码, 或者这次先用 Reality 内层"
                )
            if not chain_quic.binary():
                return _err("本机没有 hysteria 二进制, 用不了 QUIC 内层 (重跑 install.sh 可装上)")
        target["transport"] = transport

        entries = state.setdefault("chain", {}).setdefault("entries", [])
        for entry in entries:
            if (entry.get("host"), int(entry.get("port") or 0)) == (target["host"], target["port"]):
                return _err(
                    f"这个落地端已经连过了 ({target['host']}:{target['port']}); "
                    "要换凭据请先删除那条再重新添加"
                )
        if target["host"] in (state["domain"], "127.0.0.1", "localhost") and target["port"] in (
            chain.used_ports(state)
        ):
            return _err("配对码指向的是本机自己的端口, 落地端应当是另一台服务器")

        try:
            local_port = chain.pick_port(state, payload.local_port)
        except ValueError as exc:
            return _err(str(exc))
        try:
            hy_socks_port = chain_quic.pick_socks_port(state) if transport == "hysteria2" else 0
        except ValueError as exc:
            return _err(f"本机找不到空闲的回环端口给 QUIC 客户端: {exc}")

    # 探测放在锁外面: 起临时客户端 + 真实出网要好几秒, 不该把整个面板卡住
    probe = chain.probe_target(target)
    # probe_ok=False 表示"本机环境没法做这个测试"(没有 xray 二进制), 与"配错了连不通"不是一回事
    probe_ran = bool(probe.get("probe_ok", True))
    if not probe.get("ok") and probe.get("probe_ok", True) and not payload.force:
        return JSONResponse(
            {"error": probe.get("detail") or "链路测试没通过", "probe": probe, "needs_force": True},
            status_code=400,
        )

    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        entries = state.setdefault("chain", {}).setdefault("entries", [])
        # 探测是在锁外跑的 (起临时客户端 + 真实出网, 好几秒), 期间本机状态可能已经
        # 变了。落地这一瞬间必须重新确认当初挑的端口还空着, 否则两条链会撞到同一个
        # 端口, 落地时 `xray -test` 直接失败。
        if int(local_port) in chain.used_ports(state) or not services.port_available(
            int(local_port), "tcp"
        ):
            try:
                local_port = chain.pick_port(state)
            except ValueError as exc:
                return _err(str(exc))
        if transport == "hysteria2" and (
            not hy_socks_port or not services.port_available(int(hy_socks_port), "tcp")
        ):
            try:
                hy_socks_port = chain_quic.pick_socks_port(state)
            except ValueError as exc:
                return _err(str(exc))
        label = chain.unique_label(
            entries, payload.label or target["label"] or target["host"], target["host"]
        )
        entry = {
            "id": chain.new_id(),
            "label": label,
            "host": target["host"],
            "port": target["port"],
            "uuid": target["uuid"],
            "pbk": target["pbk"],
            "sid": target["sid"],
            "sni": target["sni"],
            "flow": target["flow"],
            "transport": transport,
            # QUIC 内层用到的参数 (Reality 内层时为 0/空)
            "hy_port": int(target.get("hy_port") or 0),
            "hy_pw": target.get("hy_pw") or "",
            "hy_sni": target.get("hy_sni") or "",
            "hy_socks_port": int(hy_socks_port or 0),
            "hy_bw": 0,
            "local_port": local_port,
            "enabled": True,
            "default_out": bool(payload.default_out),
            "created_at": int(time.time()),
            "last_probe": {
                "ts": int(time.time()),
                "ok": bool(probe.get("ok")),
                "probe_ok": bool(probe.get("probe_ok", True)),
                "ms": probe.get("ms"),
                "tcp_ms": probe.get("tcp_ms"),
                "exit_ip": probe.get("exit_ip") or "",
                "detail": probe.get("detail") or "",
            },
        }
        if entry["default_out"]:
            for other in entries:
                other["default_out"] = False
        entries.append(entry)
        config.audit(
            state,
            "chain_add",
            f"{label} ({'内层 QUIC' if transport == 'hysteria2' else '内层 Reality'}) "
            f"→ {entry['host']}:{entry['port']}",
            actor=_client_ip(request),
        )

        def after_landing() -> list[dict]:
            return [
                {
                    "name": "链路测试 (真实出口往返)",
                    # 环境不支持探测不算失败 (与 apply 里"跳过"步骤的约定一致)
                    "ok": bool(probe.get("ok")) or not probe_ran,
                    "detail": probe.get("detail") or "",
                    "ms": int(probe.get("ms") or 0),
                    "skipped": not probe_ran,
                },
                {
                    "name": "放行中转入站端口",
                    "ok": True,
                    "detail": services.open_firewall_port(local_port, "tcp"),
                    "ms": 0,
                },
            ]

        return _landing_body(state, request, after=after_landing)


class ChainEntryPatch(BaseModel):
    enabled: bool | None = None
    default_out: bool | None = None
    label: str | None = None
    #: 切换内层传输 (reality / hysteria2); 需要配对码里有 QUIC 凭据
    transport: str | None = None
    #: Brutal 拥塞控制的声明带宽 (Mbps); 0 = 回到 QUIC + BBR 默认
    hy_bw: int | None = None


def _find_chain_entry(state: dict, entry_id: str) -> dict | None:
    for entry in (state.get("chain") or {}).get("entries") or []:
        if entry.get("id") == entry_id:
            return entry
    return None


@router.post("/api/chain/entries/{entry_id}")
def chain_entry_update(entry_id: str, payload: ChainEntryPatch, request: Request):
    """启用/停用某条链式连接、设为默认出口、改名。"""
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        entry = _find_chain_entry(state, entry_id)
        if entry is None:
            return _err("链式条目不存在", 404)

        changed: list[str] = []
        label = entry.get("label") or entry.get("host")
        if payload.enabled is not None and bool(payload.enabled) != bool(entry.get("enabled", True)):
            entry["enabled"] = bool(payload.enabled)
            if not entry["enabled"]:
                entry["default_out"] = False
            changed.append(f"{label} {'启用' if entry['enabled'] else '停用'}")
        if payload.default_out is not None and bool(payload.default_out) != bool(entry.get("default_out")):
            if payload.default_out and not entry.get("enabled", True):
                return _err("该链式节点已停用, 先启用再设为默认出口")
            entry["default_out"] = bool(payload.default_out)
            for other in (state.get("chain") or {}).get("entries") or []:
                if other is not entry:
                    other["default_out"] = False
            changed.append(
                f"{label} 设为默认出口 (本机所有节点改走它)" if entry["default_out"]
                else f"{label} 取消默认出口"
            )
        if payload.label is not None:
            new_label = chain.unique_label(
                (state.get("chain") or {}).get("entries") or [],
                payload.label,
                str(entry.get("host") or ""),
                keep_id=str(entry.get("id") or ""),
            )
            if new_label and new_label != (entry.get("label") or ""):
                entry["label"] = new_label
                changed.append(f"名称改为「{new_label}」")
        if payload.transport is not None:
            want = payload.transport.strip().lower()
            if want not in ("reality", "hysteria2"):
                return _err(f"不支持的内层传输: {want}")
            if want != (entry.get("transport") or "reality"):
                if want == "hysteria2":
                    if not entry.get("hy_port") or not entry.get("hy_pw"):
                        return _err(
                            "这条链的配对码里没有 QUIC 凭据 (落地端当时没开内层 QUIC); "
                            "请让落地端打开后用新配对码重新接一次"
                        )
                    if not chain_quic.binary():
                        return _err("本机没有 hysteria 二进制, 用不了 QUIC 内层")
                    if not entry.get("hy_socks_port"):
                        try:
                            entry["hy_socks_port"] = chain_quic.pick_socks_port(state)
                        except ValueError as exc:
                            return _err(str(exc))
                entry["transport"] = want
                changed.append(
                    "内层改为 QUIC (Hysteria 2)" if want == "hysteria2" else "内层改回 Reality"
                )
        if payload.hy_bw is not None:
            bw = max(0, min(int(payload.hy_bw), 10000))
            if bw != int(entry.get("hy_bw") or 0):
                entry["hy_bw"] = bw
                changed.append(
                    f"Brutal 带宽 {bw} Mbps (重启内核生效)" if bw else "Brutal 已关闭 (回到 BBR)"
                )
        if not changed:
            return _err("没有需要修改的内容")

        action = "chain_update" if payload.transport is None else "chain_transport"
        config.audit(state, action, "; ".join(changed), actor=_client_ip(request))
        return _landing_body(state, request)


@router.post("/api/chain/entries/{entry_id}/probe")
def chain_entry_probe(entry_id: str, request: Request):
    """单条链式连接的测速: 真的穿过落地端出网一次, 读回落地出口 IP。"""
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        entry = _find_chain_entry(state, entry_id)
        if entry is None:
            return _err("链式条目不存在", 404)
        label = entry.get("label") or entry.get("host")
        target = chain.as_target(entry)

    probe = chain.probe_target(target)
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        entry = _find_chain_entry(state, entry_id)
        if entry is None:
            return _err("链式条目不存在", 404)
        entry["last_probe"] = {
            "ts": int(time.time()),
            "ok": bool(probe.get("ok")),
            "probe_ok": bool(probe.get("probe_ok", True)),
            "ms": probe.get("ms"),
            "tcp_ms": probe.get("tcp_ms"),
            "exit_ip": probe.get("exit_ip") or "",
            "detail": probe.get("detail") or "",
        }
        config.audit(state, "chain_probe", f"{label}: {'ok' if probe.get('ok') else 'failed'}", actor=_client_ip(request))
        save_state(state)
        body = _dashboard_body(state, request)
        probe_ran = bool(probe.get("probe_ok", True))
        body["steps"] = [
            {
                "name": f"链路测速 · {label}",
                # 没有 xray 二进制时这一步只是"没测成", 不该在面板上标红
                "ok": bool(probe.get("ok")) or not probe_ran,
                "detail": probe.get("detail") or "",
                "ms": int(probe.get("ms") or 0),
                "skipped": not probe_ran,
            }
        ]
        return body


@router.delete("/api/chain/entries/{entry_id}")
def chain_entry_delete(entry_id: str, request: Request):
    """断开并删除一条链式连接 (落地端的凭据不受影响)。"""
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        entry = _find_chain_entry(state, entry_id)
        if entry is None:
            return _err("链式条目不存在", 404)
        label = entry.get("label") or entry.get("host")
        state["chain"]["entries"] = [
            e for e in state["chain"]["entries"] if e.get("id") != entry_id
        ]
        config.audit(state, "chain_delete", label, actor=_client_ip(request))
        return _landing_body(state, request)


@router.post("/api/apply")
def apply_endpoint(request: Request):
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        config.audit(state, "apply", actor=_client_ip(request))
        return _landing_body(state, request)


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
        job: dict | None = None
        if ok and (state.get("cert") or {}).get("cert_file", "") != before:
            # 首次拿到 Let's Encrypt 证书: nginx / xray 里写的还是自签证书路径,
            # 必须重新生成配置并热重载, 否则浏览器 / 客户端仍看到自签证书。
            steps, job = _reapply_job(state, request)
        else:
            save_state(state)
    body = {"ok": ok, "detail": detail, "steps": steps}
    if job is not None:
        body["job"] = job
    return body


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
        # 链式代理两边都有自己的入站, 漏掉一个就会出现"面板绿了但链路不通"
        chain_cfg = state.get("chain") or {}
        exit_cfg = chain_cfg.get("exit") or {}
        if exit_cfg.get("enabled") and exit_cfg.get("uuid"):
            want.add("chain-exit")
        want.update(
            f"chain-{e['id']}" for e in chain_cfg.get("entries") or [] if e.get("enabled", True)
        )
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
    # 上次下载为什么失败 —— 数据没到位时这是用户唯一能拿到的线索, 别让他只能反复点按钮
    geo_err = f" · 上次更新失败: {geo['last_error'][:90]}" if geo.get("last_error") else ""
    if rules_use_geo and not geodata.present():
        add(
            "GeoIP 数据",
            False,
            f"配置里有 geo 分流规则但数据文件缺失 — Xray 将无法启动{geo_err}",
            fixable=True,
        )
    elif not geo["enabled"]:
        add("GeoIP 数据", True, f"未启用分流 (下载数据后可开启私有地址防护/广告拦截){geo_err}")
    else:
        age = geo["age_days"]
        add(
            "GeoIP 数据",
            geo["active"] and (age <= 30 or age < 0),
            f"{geo['source'] or '未知来源'} · {age} 天前更新 · "
            f"{'已启用分流' if geo['active'] else '数据缺失, 规则未下发'}{geo_err}",
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

    # 5. 端口占用 — 只报"被别的进程抢了"。
    # 不能只看"能不能 bind": 本机核心自己监听的端口在 Linux 上同样 bind 不上
    # (INADDR_ANY 的监听 socket 挡住所有本地地址), 只看 bind 会让健康的生产机
    # 每次都把 4 个节点端口报成冲突。所以还要看占用者是谁。
    if prod:
        busy = []
        for key, proto, node_id, service in (
            ("reality", "tcp", "vless-reality", "xray"),
            ("xhttp", "tcp", "vless-xhttp", "xray"),
            ("trojan", "tcp", "trojan", "xray"),
            ("hysteria", "udp", "hysteria2", "hysteria2"),
        ):
            port = int(state["ports"].get(key) or 0)
            if not port or services.port_available(port, proto):
                continue
            owner = services.port_owner(port, proto)
            if owner in services.OUR_PROCESSES:
                continue
            if not owner and state["nodes"].get(node_id) and services.service_state(service) in (
                "active",
                "running",
            ):
                continue  # 读不到占用者时用"服务正在跑"兜底, 不误报
            busy.append(f"{port}/{proto}" + (f" ({owner})" if owner else ""))
        add("端口占用", not busy, "无冲突" if not busy else f"被占用: {', '.join(busy)}")

    # 6. 伪装目标可达性 (Reality / Trojan fallback 依赖它)
    ok, detail = _check_tcp(state["reality"]["dest"], f"Reality dest {state['reality']['dest']}")
    add("伪装目标可达性", ok, detail)

    # 7. 链式代理: 落地端是否还在 (中转链路断了的话, 客户端那头的节点就是死的)
    entries = (state.get("chain") or {}).get("entries") or []
    if entries:
        down = []
        for entry in entries:
            if not entry.get("enabled", True):
                continue
            reachable, _, _ = services.tcp_connect_ms(entry["host"], int(entry["port"]), 3.0)
            if not reachable:
                down.append(f"{entry.get('label') or entry.get('host')} ({entry['host']}:{entry['port']})")
        add(
            "链式落地端可达性",
            not down,
            f"{len(entries)} 条链式连接全部可达 (已停用的不计)"
            if not down
            else f"连不上: {', '.join(down)} — 客户端连这些节点会失败",
            fixable=False,
        )

    # 8. 链式内层 QUIC (Hysteria 2) 的进程 —— 它们由面板托管、不在 systemd 里, 坏了不会
    #    体现在服务状态上; 而「重载服务」那一步现在只按核心服务判成败 (见 apply.py
    #    的 core_failed): 内层 QUIC 起不来不再让整次落地/升级失败, 所以它的故障必须
    #    在这里单独报出来, 否则这条链悄悄断掉没人知道。
    quic_status = chain_quic.status(state)
    if quic_status:
        down_quic = [key for key, alive in quic_status.items() if not alive]
        add(
            "链式内层 QUIC",
            not down_quic,
            "内层 QUIC 进程全部在运行"
            if not down_quic
            else f"未运行: {', '.join(down_quic)} — 用这条内层的链会不通 "
            "(日志在 data/chain-quic/*.log; 点「一键修复」会重新拉起)",
            fixable=True,
        )

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
def update_start(request: Request, payload: UpdateIn | None = None):
    """一键更新: 后台拉起 upgrade.sh, 面板会随之重启。

    这里**只在本地取值**就回执, 刻意不带 `update.status()` —— 那会顺手做一次远端版本检查
    (国内直连 GitHub 要等 4 个镜像依次超时, 最坏 ~32s), 而面板大约在 34s 后重启:
    结果就是"点了按钮, 界面卡住半分钟, 然后弹一句无法开始升级", 其实升级早在跑了。
    真正的进度由前端 2.5s 一次的 `GET /api/update` 轮询补上。

    `payload.core=true` 时**同时**升级 Xray / Hysteria 2 内核 (见 update.start)。
    """
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        ok, detail = update.start(trigger="panel", core=bool(payload and payload.core))
        config.audit(state, "update", detail[:190], actor=_client_ip(request))
        save_state(state)
    if not ok:
        return _err(detail, 409)
    return {"ok": True, "detail": detail}


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
    # 缓存不能跨状态变更: 刚关掉一个节点就点测速, 命中 20s 内的旧结果会显示
    # "这个节点还在" —— 用 updated_at 当指纹, 任何写操作都会让旧结果立即作废。
    key = f"{'deep' if want_deep else 'fast'}:{int(state.get('updated_at') or 0)}"
    with _PROBE_LOCK:
        for stale in [k for k in _PROBE_CACHE if k != key]:
            _PROBE_CACHE.pop(stale, None)
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
    # 顶层结构校验: 备份是外部输入, "是合法 JSON"不代表字段类型都对。例如 reality
    # 被写成 null 时, 下面的 `restored["reality"].get(...)` 会直接抛异常变成 500;
    # 这里当场给 400, 并保持现网不变。
    for key in ("admin", "reality", "cert", "nodes", "ports", "chain"):
        if key in data and not isinstance(data[key], dict):
            return _err(f"备份结构不合法: {key} 应为对象")

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


# ---------------------------------------------------------------- 面板设置 (账号 / 域名)

#: 换域名后把浏览器带到新地址用的一次性票据: 单次有效, 10 分钟过期。
HANDOFF_TTL = 600
#: 换域名的步骤总数 (进度条用): 证书 → 配置落地 (apply.STEP_NAMES) → 验证新域名


class AccountIn(BaseModel):
    """改面板账号 / 密码 (两个都可选: 只改用户名、只改密码、或一起改)。"""

    current_password: str
    username: str | None = None
    new_password: str | None = None


class DomainIn(BaseModel):
    domain: str


class HandoffIn(BaseModel):
    token: str


def _panel_url_for(domain: str, scheme: str = "https") -> str:
    """某个域名下面板的对外地址 (端口规则与 share_links.panel_base_url 一致)。"""
    port = config.PANEL_PORT
    netloc = domain if port in (80, 443) else f"{domain}:{port}"
    return f"{scheme}://{netloc}/"


def _issue_handoff(state: dict, request: Request) -> str:
    """签一张一次性交接票据 —— 换域名后跳过去不该让用户重新登录一遍。"""
    token = "zph_" + crypto.new_token(24)
    now = int(time.time())
    live = {
        t: v for t, v in (state.get("handoffs") or {}).items() if int(v.get("expires") or 0) > now
    }
    live[token] = {"expires": now + HANDOFF_TTL, "ip": _client_ip(request)}
    state["handoffs"] = live
    return token


@router.post("/api/session/handoff")
def session_handoff(payload: HandoffIn, request: Request):
    """用交接票据换一个会话 (换域名跳转的落地那一步)。

    票据单次有效、10 分钟过期, 且只有已登录的管理员在换域名那一刻才会被签发;
    用完立刻作废, 所以它出现在地址栏里的时间只有一跳。
    """
    token = (payload.token or "").strip()
    with config.locked():
        state = load_state()
        entry = (state.get("handoffs") or {}).pop(token, None)
        if not entry or int(entry.get("expires") or 0) < time.time():
            save_state(state)
            return _err("交接票据已失效, 请在新域名上用账号密码登录", 401)
        _clean_sessions(state)
        response = JSONResponse({"ok": True})
        _issue_session(state, request, response)
        config.audit(
            state, "handoff_login", f"ip={_client_ip(request)}", actor=state["admin"]["username"]
        )
        save_state(state)
    return response


@router.post("/api/account")
def update_account(payload: AccountIn, request: Request):
    """改面板管理员用户名 / 密码。

    刻意**不碰节点凭据** (VLESS UUID / Trojan / Hysteria 口令都是初始化那一刻定下
    并写进订阅的): 改这里只影响"谁能登进面板"。否则改个密码就把所有客户端踢下线,
    用户会以为是改密码改坏了。
    """
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        admin = state["admin"]
        if not crypto.verify_password(payload.current_password, admin["password_hash"]):
            config.audit(state, "account_update_failed", "当前密码不正确", actor=_client_ip(request))
            save_state(state)
            return _err("当前密码不正确", 401)

        # 校验与写入都在 account.py —— 终端快捷管理 (z) 走的是同一份规则, 免得两边漂
        try:
            changed, kicked = account.apply_credentials(
                state,
                username=(payload.username or "").strip() or None,
                new_password=payload.new_password or None,
                keep_session=_session_of(state, request),
            )
        except ValueError as exc:
            return _err(str(exc))

        config.audit(
            state,
            "account_update",
            "; ".join(changed) + (f" (注销其它设备 {kicked} 个)" if kicked else ""),
            actor=_client_ip(request),
        )
        save_state(state)
        body = _dashboard_body(state, request)
    body["ok"] = True
    body["detail"] = "已保存: " + "; ".join(changed)
    body["kicked"] = kicked
    return body


def _normalize_domain(raw: str) -> str:
    """把用户可能粘进来的整条地址收敛成主机名。

    "https://proxy.example.com:8899/panel" / "proxy.example.com/" / "PROXY.example.com."
    都是人能输进来的东西 —— 直接判无效只会让人以为面板在挑刺。端口一律丢掉:
    面板对外端口由配置决定, 不随域名走。
    """
    text = (raw or "").strip().lower()
    text = re.sub(r"^[a-z][a-z0-9+.-]*://", "", text)   # 去协议 (http:// / https://)
    text = text.split("/")[0].split("?")[0].split("#")[0]
    if ":" in text:                                       # 去端口 (IPv6 不支持换域名)
        text = text.split(":")[0]
    return text.rstrip(".")


def _domain_preflight(new_domain: str, current: str) -> tuple[bool, str]:
    """换域名前的预检: 新域名是不是已经指向本机。

    解析不到 / 指向别处就当场说清 —— 否则要白等一次最长 300 秒的 certbot, 而
    Let's Encrypt 一定失败; 失败之后要么回滚 (白折腾) 要么把证书降级成自签 (更糟)。
    只有"本机地址"这个判据本身拿不到时才放行, 让 certbot 去做最终裁决。
    """
    resolved = services.resolve_host(new_domain)
    if not resolved:
        return False, (
            f"域名 {new_domain} 解析不到 —— 先在 DNS 里加一条 A 记录指向本机 IP, 等解析生效再来换"
        )
    known: set[str] = set()
    if current:
        known |= {current} if _is_ip(current) else services.resolve_host(current)
    public = services.public_ip().get("ip") or ""
    if public:
        known.add(public)
    known |= services.local_addresses()
    if known and not (resolved & known):
        return False, (
            f"域名 {new_domain} 解析到 {', '.join(sorted(resolved))}, 这台机器不在其中 —— "
            "先把 DNS 指过来 (用 Cloudflare 的话改成 DNS only / 关掉橙云代理)。换域名要重新签发"
            "证书, 而 Let's Encrypt 必须能从新域名访问到本机的 80 端口"
        )
    return True, ""


def _domain_pipeline(new_domain: str, progress=None) -> tuple[list[dict], str]:
    """换域名的完整闭环。返回 (步骤, 错误)。错误非空 = 已回滚, 域名保持原样。"""
    steps: list[dict] = []
    total = 1 + len(apply.STEP_NAMES) + 1

    def record(name: str, ok: bool, detail: str) -> None:
        steps.append({"name": name, "ok": ok, "detail": detail, "ms": 0})
        if progress is not None:
            progress(len(steps), total, detail)

    # ---- 1) 证书: 放在配置锁**外面** (certbot 最长 300 秒, 不能把整个面板按住) ----
    ok, detail, cert_state = services.install_cert(new_domain)
    if services.is_prod() and cert_state.get("type") != "letsencrypt":
        record("申请 TLS 证书", False, detail)
        return steps, (
            f"新域名没能拿到受信任证书 ({detail}) —— 面板保持原样, 未做任何改动。"
            "多半是 DNS 还没指到本机, 或者 80 端口被防火墙/安全组挡着"
        )
    record("申请 TLS 证书", True, detail)

    # ---- 2) 提交: 写域名 + 重生成配置 + 热重载 (任一步失败都整份退回) ----
    with config.locked():
        state = load_state()
        old_domain = (state.get("domain") or "").strip()
        old_cert = copy.deepcopy(state.get("cert") or {})
        state["domain"] = new_domain
        state["cert"] = cert_state
        save_state(state)
        landed = apply.reapply(
            state,
            progress=lambda index, _t, name: (
                progress(1 + index + 1, total, name) if progress is not None else None
            ),
        )
        steps.extend(landed)
        failed = apply.failures(landed)
        if failed:
            reason = f"{failed[0]['name']}: {failed[0]['detail']}"
            steps.extend(_rollback_domain(old_domain, old_cert))
            return steps, f"配置落地失败 ({reason}) —— 已回滚, 面板仍在 {old_domain}"

    # ---- 3) 验证: 新域名上真的能打开面板吗 (证书受信任 + DNS + 端口) ----
    if services.is_prod():
        reachable, why = services.probe_public_panel(new_domain, config.PANEL_PORT, timeout=15)
        if not reachable:
            with config.locked():
                steps.extend(_rollback_domain(old_domain, old_cert))
            return steps, f"新域名访问不通 ({why}) —— 已回滚, 面板仍在 {old_domain}"
        record("验证新域名", True, why)
    else:
        record("验证新域名", True, "跳过 (非生产环境, 无 nginx / 公网入口)")

    with config.locked():
        fresh = load_state()
        fresh["steps"] = steps
        save_state(fresh)
    return steps, ""


def _rollback_domain(old_domain: str, old_cert: dict) -> list[dict]:
    """把域名 / 证书 / 配置退回换域名之前的样子 (调用方必须已持有配置锁)。"""
    state = load_state()
    state["domain"] = old_domain
    state["cert"] = old_cert
    save_state(state)
    reverted = apply.reapply(state)
    ok = not apply.failures(reverted)
    return [
        {
            "name": "回滚到原域名",
            "ok": ok,
            "detail": (
                f"域名 / 证书 / 配置已退回 {old_domain or '(IP 访问)'}"
                if ok
                else f"回滚后仍有步骤告警, 请到「诊断」看详情: {apply.failures(reverted)[0]['name']}"
            ),
            "ms": 0,
        }
    ]


def _run_domain_job(job_id: str, new_domain: str) -> None:
    steps: list[dict] = []
    error = ""
    try:
        steps, error = _domain_pipeline(
            new_domain,
            progress=lambda index, total, name: _job_update(
                job_id, index=index, total=total, current=name
            ),
        )
        if not error:
            record = {"name": "新域名已生效", "ok": True, "detail": f"面板现在跑在 {new_domain}", "ms": 0}
            steps.append(record)
    except Exception as exc:  # noqa: BLE001 — 后台任务不能把异常吞成"静默失败"
        error = f"{type(exc).__name__}: {exc}"
    _finish_job(job_id, steps, error)


def _domain_change_sync(new_domain: str, request: Request, handoff: str) -> dict:
    """同步落地 (ZP_APPLY_ASYNC=0, 测试 / 本地排查用)。"""
    steps, error = _domain_pipeline(new_domain)
    with config.locked():
        fresh = load_state()
        body = _dashboard_body(fresh, request)
    body["steps"] = steps
    body["ok"] = not error
    body["detail"] = error or f"域名已更换为 {new_domain}"
    if not error:
        body["redirect"] = {
            "url": _panel_url_for(new_domain),
            "handoff": handoff,
            "ready": True,
        }
    return body


@router.post("/api/domain")
def change_domain(payload: DomainIn, request: Request):
    """换面板域名: 预检 DNS → 签发证书 → 重写配置 → 热重载 → 验证 → 自动跳转。

    两件 setup 那次域名流程不需要、这里必须做的事:
      * **先预检**: 新域名解析不到本机就当场拒绝, 别让用户白等一次 certbot;
      * **会回滚**: 只有"新域名上真的能打开面板"才算成功, 否则域名 / 证书 / 配置
        整份退回原样 —— 换域名失败不该让面板彻底进不去。
    """
    new_domain = _normalize_domain(payload.domain)
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        if not state.get("configured"):
            return _err("请先完成初始化", 409)
        current = (state.get("domain") or "").strip()
        if not new_domain:
            return _err("请输入新域名")
        if _is_ip(new_domain) or not _DOMAIN_RE.match(new_domain):
            return _err("请输入域名 (示例: proxy.example.com) —— 换域名要的是能签证书的域名")
        if new_domain == current:
            return _err("与当前域名相同, 无需更换")
        running = _running_job(request, kind="domain")
        if running is not None:
            body = _dashboard_body(state, request)
            body.update({"ok": True, "detail": "已有换域名任务在进行中", "steps": [], "job": running})
            return body

    ok, why = _domain_preflight(new_domain, current)
    if not ok:
        return _err(why, 400)

    with config.locked():
        state = load_state()
        handoff = _issue_handoff(state, request)
        config.audit(
            state, "domain_change", f"{current} → {new_domain}", actor=_client_ip(request)
        )
        save_state(state)

    if not _apply_async_enabled():
        return _domain_change_sync(new_domain, request, handoff)

    job_id, job = _new_job(
        request, 1 + len(apply.STEP_NAMES) + 1, "申请 TLS 证书", kind="domain"
    )
    try:
        threading.Thread(
            target=_run_domain_job,
            args=(job_id, new_domain),
            name=f"zp-domain-{job_id}",
            daemon=True,
        ).start()
    except Exception:
        _finish_job(job_id, [], "换域名任务启动失败")
        raise
    with config.locked():
        body = _dashboard_body(load_state(), request)
    body.update(
        {
            "ok": True,
            "detail": f"已开始更换域名为 {new_domain}",
            "steps": [],
            "job": _job_snapshot(job),
            "redirect": {"url": _panel_url_for(new_domain), "handoff": handoff, "ready": False},
        }
    )
    return body


# ---------------------------------------------------------------- GeoIP 数据

#: 同一时间只允许一个下载任务 (几十 MB, 不做并发); 与后台自动更新线程共用
#: 同一把锁 (定义在 geodata, 避免两条路径同时改写 geo 目录与 state 快照)
_GEO_UPDATE_LOCK = geodata.UPDATE_LOCK


def _geo_steps(detail: str) -> list[dict]:
    """GeoIP 下载这一步本身, 塞进落地步骤列表里 (和改配置共用同一套展示)。"""
    return [{"name": "核对并更新 GeoIP 数据", "ok": True, "detail": detail, "ms": 0}]


def _run_geo_job(job_id: str, actor: str, force: bool = False) -> None:
    """后台线程: 下载 → 校验 → 重新落地配置, 全程把进度写进任务表。

    为什么不能同步等: 28 MB 从镜像拉下来, 国内线路可能几十秒到几分钟; 而且
    数据变了要重启 Xray —— 走本机链路访问面板的浏览器会把这条请求掐断, 用户
    看到的就是"点了半天没反应, 然后好像失败了"。改成立刻回执 + 轮询后, 进度
    是一直可见的, 请求也早就返回了 (和 v2.6.9 改配置那条闭环同一个理由)。
    """
    steps: list[dict] = []
    error = ""
    dl_total = len(geodata.SOURCES) + 1               # 两个文件 + 一次校验
    total = dl_total + len(apply.STEP_NAMES)
    try:
        with config.locked():
            state = load_state()
        ok, detail, _info = geodata.update(
            state,
            progress=lambda index, _total, name: _job_update(
                job_id, index=index, total=total, current=name
            ),
            force=force,
        )
        with config.locked():
            fresh = load_state()
            # 下载在锁外跑了好一会儿, 期间用户可能改过开关 —— 只并回下载写过的字段
            geodata.merge_result(fresh, state, ok)
            config.audit(
                fresh,
                "geodata_update" if ok else "geodata_update_failed",
                detail[:190],
                actor=actor,
            )
            if ok:
                steps = _geo_steps(detail) + apply.reapply(
                    fresh,
                    progress=lambda index, _total, name: _job_update(
                        job_id, index=dl_total + index + 1, total=total, current=name
                    ),
                )
            else:
                steps = _geo_steps(detail)
                steps[0]["ok"] = False
                error = detail
            # 步骤要在 save_state 之前写进去: reapply 内部存过一次, 这里覆盖成完整清单
            fresh["steps"] = steps
            save_state(fresh)
    except Exception as exc:  # noqa: BLE001 — 后台任务不能把异常吞成"静默失败"
        error = f"{type(exc).__name__}: {exc}"
        steps = steps or [{"name": "核对并更新 GeoIP 数据", "ok": False, "detail": error, "ms": 0}]
        # 意外异常 (不是 update 自己 return False 的那种失败) 走不到上面的存档路径,
        # 但失败原因一样要落地: 否则 toast 闪 2.4 秒之后, 卡片上只剩"数据未下载",
        # 用户完全不知道发生了什么。用户的 "OSError: [Errno 18] Invalid
        # cross-device link" 就属于这一类 —— 它没被记进 state, 所以面板上查不到。
        try:
            with config.locked():
                broken = load_state()
                geo = broken.setdefault("geodata", {})
                geo["last_attempt"] = int(time.time())
                geo["last_error"] = error[:300]
                config.audit(broken, "geodata_update_failed", error[:190], actor=actor)
                save_state(broken)
        except Exception:  # noqa: BLE001 — 连原因都存不下来时, 也不能再炸一次
            pass
    finally:
        _GEO_UPDATE_LOCK.release()
    _finish_job(job_id, steps, error)


def _geodata_update_sync(state: dict, request: Request, force: bool = False) -> dict:
    """同步落地 (ZP_APPLY_ASYNC=0, 测试 / 本地排查用) —— 行为与以前一致。"""
    ok, detail, _info = geodata.update(state, force=force)
    with config.locked():
        fresh = load_state()
        geodata.merge_result(fresh, state, ok)
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


@router.post("/api/geodata/update")
def geodata_update(request: Request, force: int = 0):
    """核对上游 → 有变化才下载 GeoIP + GeoSite 数据, 然后重新生成配置并热重载。

    `?force=1` 跳过"内容一致就不下"的短路, 强制重新下载 (数据被怀疑损坏时的兜底)。
    """
    want_force = bool(force)
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        if _apply_async_enabled():
            running = _running_job(request, kind="geodata")
            if running is not None:
                # 已经在跑就直接把那个任务还给前端, 让它接着轮询同一个进度条,
                # 而不是弹一句"已有任务在进行中"让用户再猜一次
                body = _dashboard_body(state, request)
                body["ok"] = True
                body["detail"] = "已有更新任务在进行中"
                body["steps"] = []
                body["job"] = running
                return body

    if not _GEO_UPDATE_LOCK.acquire(blocking=False):
        # 两条路径会撞上这把锁: 后台自动更新线程 (面板启动 90s 后按 6 小时检查一次,
        # 数据过期时下载), 以及上一次还没跑完的手动任务。但"上一次手动任务"前面已经
        # 被 _running_job 接管了, 所以走到这里基本是自动更新 —— 这不是失败, 等它跑完
        # 再点就行, 提示要写成"等一下", 别让用户以为按钮坏了。
        return _err("GeoIP 数据正在更新中 (后台自动更新或上一次任务还没结束), 请稍等再点", 409)
    if not _apply_async_enabled():
        try:
            return _geodata_update_sync(state, request, force=want_force)
        finally:
            _GEO_UPDATE_LOCK.release()

    total = len(geodata.SOURCES) + 1 + len(apply.STEP_NAMES)
    job_id, job = _new_job(request, total, "准备下载", kind="geodata")
    # 任务线程负责在结束时释放 _GEO_UPDATE_LOCK (下载不能占着配置锁)
    try:
        threading.Thread(
            target=_run_geo_job,
            args=(job_id, _client_ip(request), want_force),
            name=f"zp-geo-{job_id}",
            daemon=True,
        ).start()
    except Exception:
        _GEO_UPDATE_LOCK.release()   # 线程没起来就别把锁留着 (否则再也下不了)
        raise
    body = _dashboard_body(state, request)
    body["ok"] = True
    body["detail"] = "已开始下载"
    body["steps"] = []
    body["job"] = _job_snapshot(job)
    return body


@router.get("/api/geodata/check")
def geodata_check(request: Request):
    """核对本地 Geo 数据与上游当前版本 (只下两个几十字节的校验值)。

    「我这份数据到底是不是最新的」以前答不上来: dat 文件里没有版本号, 一天一版
    的更新在体积上也看不出来。这里拿仓库随数据集发布的 `<文件>.sha256sum` 和本地
    文件的 sha256 比一次, 外加 release 分支最新提交的日期 / sha 作为人类可读版本,
    结果落进 state, 面板卡片直接显示。

    刻意**不加下载锁**: 一次核对只读几个 KB, 没理由让用户在一个跑着的下载后面排队。
    数据文件是原子替换的, 读到的要么是旧的完整文件, 要么是新的完整文件。
    """
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
    report = geodata.check_remote()
    _ok, build_info = geodata.dataset_info()
    with config.locked():
        fresh = load_state()
        # 下载期间用户可能动过开关 —— record_check 只写版本相关的字段, 不碰用户设置
        geodata.record_check(fresh, report, build_info or None)
        save_state(fresh)
        geo = geodata.status(fresh)
    return {
        "ok": True,
        "geo": geo,
        "up_to_date": geo.get("up_to_date"),
        "detail": report.get("error", ""),
    }


@router.post("/api/geodata/force-check")
def geodata_force_check(request: Request):
    """强制刷新 Geo 数据版本检查 (绕过 CDN 缓存 TTL)。

    国内 jsdelivr CDN 对 @release 分支缓存极长, 面板 `status()` 的 600s TTL
    可能拉到的还是旧版本号 —— 用户会看到"已是最新"但实际数据已过期。这个接口
    直接调用 `remote_version()` 绕过缓存, 返回最新版号和来源, 供面板"检查更新"
    按钮使用。

    同时也会更新 `update` 模块的缓存, 所以下一次 `status()` 调用不会再出网。
    """
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)

    # 直接刷新缓存
    update_status = update.status(force=True)
    geo_status = geodata.status(state)
    return {
        **update_status,
        "geo": geo_status,
    }


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
    if node_id not in NODE_IDS and not node_id.startswith("chain-"):
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


@router.get("/api/chain/exit/qr")
def chain_exit_qr(request: Request, size: int = 6, img: str = "png"):
    """落地端配对码的二维码 (另一台机器的摄像头直接扫, 省掉手抄 300 字符)。"""
    state = load_state()
    if not _require_auth(state, request):
        return _err("未登录", 401)
    code = chain.exit_code(state)
    if not code:
        return _err("本机还没有作为落地端的凭据, 请先生成配对码", 409)
    return _qr_response(code, size, img)


# ---------------------------------------------------------------- 客户端设备
#
# 两条入口刻意分开:
#   /api/devices*  面板用 (登录会话) —— 生成配对码 / 看设备 / 总开关 / 移除
#   /c/*           设备用 (设备 secret) —— 取安装脚本 / 下内核 / 拉配置 / 报状态
#
# 设备侧不能依赖面板会话: 路由器上没有浏览器也没有 Cookie。它们的身份是配对时
# 换来的 device_id + secret (见 devices.py 顶部)。


class DevicePairIn(BaseModel):
    label: str = ""


class DevicePatchIn(BaseModel):
    name: str | None = None
    template: str | None = None
    desired: bool | None = None


class DeviceProxyIn(BaseModel):
    on: bool = True


class DeviceRegisterIn(BaseModel):
    """设备侧配对请求 (安装脚本构造)。"""

    code: str = ""
    kind: str = "router"
    hostname: str = ""
    model: str = ""
    arch: str = ""
    os: str = ""
    version: str = ""


class DeviceReportIn(BaseModel):
    """设备心跳 + 状态上报。`set_desired` 让路由器本机的 CLI 也能改总开关。"""

    device: str = ""
    k: str = ""
    actual: bool | None = None
    rev: str = ""
    version: str = ""
    arch: str = ""
    os: str = ""
    model: str = ""
    # 路由器端管理界面的地址 (带界面令牌) —— 面板拿它给用户一个"点一下就能进"的入口
    ui: str = ""
    report: dict | None = None
    set_desired: bool | None = None


def _install_command(base: str, code: str) -> str:
    return f"wget -qO- {base}/c/{code} | sh"


@router.post("/api/devices/pair")
def device_pair(payload: DevicePairIn, request: Request):
    """生成一次性配对码 + 可直接粘贴的安装命令。"""
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        if not state["configured"]:
            return _err("面板尚未初始化", 409)
        entry = devices.create_pair_code(state, payload.label)
        base = share_links.panel_base_url(request, state)
        config.audit(state, "device_pair", f"配对码 {entry['code'][:8]}… (30 分钟内有效)")
        save_state(state)
        return {
            "code": entry["code"],
            "expires_at": entry["expires_at"],
            "url": f"{base}/c/{entry['code']}",
            "command": _install_command(base, entry["code"]),
            "ttl": devices.PAIR_TTL,
        }


@router.get("/api/devices")
def device_list(request: Request):
    state = load_state()
    if not _require_auth(state, request):
        return _err("未登录", 401)
    return {"devices": devices.view(state), "client": router_client.summary()}


@router.get("/api/devices/cores")
def device_core_states(request: Request):
    """内核缓存状态 (面板 UI 用: 发安装命令之前先看它准备好没有)。"""
    state = load_state()
    if not _require_auth(state, request):
        return _err("未登录", 401)
    return {"cores": router_client.core_states(), "version": router_client.CORE_VERSION}


@router.post("/api/devices/cores/{arch}/prepare")
def device_core_prepare(arch: str, request: Request):
    """让面板现在就去把某一档内核取回来。

    这是给"我马上要装一台 arm64 路由器"的人准备的一步: 面板先把 20 MB 从上游取好,
    安装命令跑起来的时候就是纯局域网传输, 不会在"下载代理内核"那一行上等。
    """
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        if not state["configured"]:
            return _err("面板尚未初始化", 409)
        if arch not in router_client.ARCHES:
            return _err("不支持的架构", 404)
        before = router_client.core_state(arch)["state"]
        st = router_client.ensure_core_async(arch)
        if before != "downloading" and st.get("state") == "downloading":
            config.audit(state, "client_core", f"开始缓存内核 {arch}")
        save_state(state)
        return {"core": st, "cores": router_client.core_states()}


@router.post("/api/devices/{device_id}/proxy")
def device_proxy(device_id: str, payload: DeviceProxyIn, request: Request):
    """全屋代理总开关。

    只改"期望状态"并立刻落盘: 设备下一轮心跳 (≤15s) 就会拿到它并执行。
    面板显示的开关颜色取自设备回报的 actual, 所以这里不假装已经生效 ——
    前端会把 desired != actual 的那段时间显示成"同步中"。
    """
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        device = devices.find(state, device_id)
        if device is None:
            return _err("设备不存在 (可能已被移除)", 404)
        device["desired"] = bool(payload.on)
        config.audit(
            state, "device_toggle", f"{device['name']} → {'开启' if payload.on else '关闭'}"
        )
        save_state(state)
        return {"device": devices.device_view(device)}


@router.post("/api/devices/{device_id}")
def device_update(device_id: str, payload: DevicePatchIn, request: Request):
    """改名 / 覆盖分流模板 / 直接设定期望开关。"""
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        device = devices.find(state, device_id)
        if device is None:
            return _err("设备不存在 (可能已被移除)", 404)
        notes: list[str] = []
        if payload.name is not None:
            name = payload.name.strip()[:40]
            if not name:
                return _err("设备名不能为空", 400)
            device["name"] = name
            notes.append(f"改名 {name}")
        if payload.template is not None:
            tpl = payload.template.strip().lower()
            if tpl and tpl not in share_links.TEMPLATES:
                return _err("未知分流模板", 400)
            device["template"] = tpl
            notes.append(f"分流 {tpl or '跟随面板'}")
        if payload.desired is not None:
            device["desired"] = bool(payload.desired)
            notes.append("开启" if payload.desired else "关闭")
        if notes:
            action = "device_template" if payload.template is not None else "device_rename"
            config.audit(state, action, f"{device['name']}: {' / '.join(notes)}")
        save_state(state)
        return {"device": devices.device_view(device)}


@router.delete("/api/devices/{device_id}")
def device_delete(device_id: str, request: Request):
    """移除设备 = 立刻吊销它手里的 secret (那台机器上的代理随即失效)。"""
    with config.locked():
        state = load_state()
        if not _require_auth(state, request):
            return _err("未登录", 401)
        device = devices.find(state, device_id)
        if device is None:
            return _err("设备不存在", 404)
        name = device.get("name", "")
        devices.remove(state, device_id)
        config.audit(state, "device_remove", f"{name} ({device_id})")
        save_state(state)
        return {"removed": device_id, "devices": devices.view(state)}


# ---------------------------------------------------------------- 设备侧接口
# 下面四个接口走设备凭据, 不校验面板会话 —— 但要求面板已初始化。


@router.get("/c/install.sh")
def client_install_script_pinned(request: Request):
    """更新用的安装脚本: **不带配对码**。

    已经装过的机器重跑它即可升级客户端 (界面、agent、配置生成逻辑), 不会重新配对、
    不会在面板上多出一台设备 —— 配对码是一次性的, 拿它去更新等于每次都要清一遍设备,
    那是把用户拖进循环。这个地址是固定的, 可以写进笔记里长期用。
    """
    state = load_state()
    if not state["configured"]:
        return _err("面板尚未初始化", 409)
    try:
        body = router_client.render_script(share_links.panel_base_url(request, state), "")
    except (OSError, ValueError) as exc:
        return _err(f"安装脚本不可用: {exc}", 500)
    return Response(
        body,
        media_type="text/x-shellscript; charset=utf-8",
        headers={"cache-control": "no-store"},
    )


@router.get("/c/{code}")
def client_install_script(code: str, request: Request):
    """安装脚本本体 (`wget -qO- <面板>/c/<配对码> | sh` 拉的就是它)。"""
    state = load_state()
    if not state["configured"]:
        return _err("面板尚未初始化", 409)
    if not devices.pair_code_live(state, code):
        return Response(
            "ZeroProxy: 配对码无效或已过期, 请回面板「客户端」重新生成安装命令。\n",
            status_code=404,
            media_type="text/plain; charset=utf-8",
        )
    try:
        body = router_client.render_script(share_links.panel_base_url(request, state), code)
    except (OSError, ValueError) as exc:
        return _err(f"安装脚本不可用: {exc}", 500)
    return Response(
        body,
        media_type="text/x-shellscript; charset=utf-8",
        headers={"cache-control": "no-store"},
    )


@router.get("/c/bin/{arch}")
def client_core_binary(arch: str, request: Request):
    """内核二进制。面板侧缓存 —— 路由器只访问面板, 不用自己翻墙去 GitHub。

    没缓存时**不能把请求挂在这里等** (以前就是这样: 面板同步去上游拉, 最长几分钟,
    路由器端看到的是"下载代理内核"这一行不动 —— 装机的用户分不清是慢还是死)。
    现在立刻回一句能读懂的话 + 503, 同时后台开始取; 路由器端按 Retry-After 重试,
    并可以把真实进度打出来 (见 /c/core/status)。
    """
    state = load_state()
    if not state["configured"]:
        return _err("面板尚未初始化", 409)
    if arch not in router_client.ARCHES:
        return _err("不支持的架构", 404)
    if router_client.core_ready(arch):
        path = router_client.core_file(arch)
        return FileResponse(
            path,
            media_type="application/gzip",
            headers={"cache-control": "no-store"},
            filename=os.path.basename(path),
        )
    router_client.ensure_core_async(arch)
    return Response(
        router_client.core_pending_text(arch) + "\n",
        status_code=503,
        media_type="text/plain; charset=utf-8",
        headers={"retry-after": "5", "cache-control": "no-store"},
    )


@router.get("/c/agent/bin/{arch}")
def client_agent_binary(arch: str, request: Request):
    """本地控制面二进制 (zpcore, .gz)。匿名可达 —— 与内核同一条路。

    装机时路由器还没有任何凭据可用, 而这份东西里不含任何机密 (一个 HTTP 服务 + 一层
    令牌校验), 泄露它拿不到任何东西 —— 与 /c/bin 的内核完全是同一类东西。

    它是**可选件**: 面板没准备某一档时回 404 + 一句人话, 路由器据此走原来的界面路径
    (固件 Web 服务 / busybox httpd), 装机不会因此失败。产物由 scripts/build-agent.sh
    生成到仓库的 client/agent/dist/ (不是 data/ 缓存 —— 它没有上游可下载)。
    """
    arch = (arch or "").strip().lower()
    if arch not in router_client.ARCHES:
        return _err(f"不支持的架构: {arch}", 404)
    if not router_client.agent_ready(arch):
        return _err(
            f"这台面板没有准备 {arch} 这一档本地控制面 (zpcore, 可选件)。"
            "在面板上跑一次 scripts/build-agent.sh 并把 client/agent/dist/ 一起部署即可; "
            "没有它不影响代理 —— 路由器会用原来的界面路径。",
            404,
        )
    path = router_client.agent_file(arch)
    return FileResponse(
        path,
        media_type="application/gzip",
        headers={"cache-control": "no-store"},
        filename=os.path.basename(path),
    )


#: `zeroproxy bench` 的靶子数据。**必须是随机字节**: 面板前面可能有 nginx、链路上还有
#: 运营商, 对可压缩的内容它们都可能压一把 —— 那样量出来的不是链路速度。生成一次复用。
_BENCH_MB = os.urandom(1 << 20)

#: 单次最多给多少 MB。这是个匿名端点, 而面板自己也在那条链路上 —— 不能变成放大器。
BENCH_MAX_MB = int(os.environ.get("ZP_BENCH_MAX_MB", "8"))


@router.get("/c/bench/{mb}")
def client_bench(mb: int, request: Request):
    """给路由器 `zeroproxy bench` 用的定长数据 (测"直连"与"经代理"两条路的吞吐)。

    为什么靶子是面板自己: 它是这台路由器**一定能访问到**的那个地址 (装机时唯一可达的),
    而且两条路跑的是同一段路 —— 一比就知道代理本身吃掉了多少。

    匿名可达, 与 `/c/bin` 同性质: 不给凭据, 也不泄露任何东西 (纯随机字节)。
    """
    # 注意不是 `mb or 4`: 那个写法会把 0 当成"没给"(Python 里 0 是假值), 于是
    # /c/bench/0 返回 4 MB —— 一个看起来"很小"的请求反而拿到最多的数据。钳到 [1, 上限]。
    size = min(max(int(mb), 1), BENCH_MAX_MB)
    return Response(
        _BENCH_MB * size,
        media_type="application/octet-stream",
        headers={"cache-control": "no-store"},
    )


@router.get("/c/core/status")
def client_core_status(request: Request):
    """内核缓存状态 (`?arch=arm64` 只看一档)。

    路由器端在等内核时轮询它, 于是那句 "正在下载" 后面能跟上真实进度; 内容不含
    任何凭据, 所以和 /c/bin 一样匿名可达。
    """
    state = load_state()
    if not state["configured"]:
        return _err("面板尚未初始化", 409)
    want = (request.query_params.get("arch") or "").strip()
    payload = {
        "core_version": router_client.CORE_VERSION,
        "asset": router_client.asset_name(want) if want in router_client.ARCHES else "",
        "cores": router_client.core_states(),
        # 路由器端只在"面板直传太慢"时才会用这些 (见 router-install.sh):
        #   direct       —— 上游官方地址 (日志/排查用)
        #   mirror_urls  —— 面板同款镜像的**完整地址**, 逗号分隔 (客户端不拼模板)
        #   prefer       —— 面板建议先走哪条: panel / mirror (ZP_ROUTER_SOURCE 可改)
        "prefer": router_client.ROUTER_SOURCE,
        # 分流数据库: 与内核同一个病 (面板这条路慢 → "卡在准备分流数据库不动"), 同一副药 ——
        # 把每一份的**体积下限**与**全部可用地址**一起给过去。格式刻意做成浅层可解析的
        # (客户端没有 jq, 只有 sed):
        #   geo_sizes    "geoip.metadb=204800;geosite.dat=2097152"
        #   geo_mirrors  "geoip.metadb <url> <url>|geosite.dat <url> <url>"
        # URL 里既没有空格也没有 `|`, 所以这两个分隔符不会歧义。
        "geo_sizes": ";".join(
            f"{name}={router_client.geo_min_bytes(name)}" for name in router_client.GEO_FILES
        ),
        "geo_mirrors": "|".join(
            name + " " + " ".join(router_client.geo_mirror_urls(name))
            for name in router_client.GEO_FILES
        ),
    }
    # 指定了架构时再把这一档的字段摊平在顶层: 路由器端只做浅层解析 (没有 jq),
    # 嵌套在数组里的 bytes/state 它取不到。
    if want in router_client.ARCHES:
        st = router_client.core_state(want)
        payload.update({
            "state": st["state"],
            "bytes": st["bytes"],
            "detail": st["detail"],
            "ready": st["state"] == "ready",
            "direct": router_client.release_url(want),
            "mirror_urls": ",".join(router_client.mirror_urls(want)),
        })
        if st["state"] == "ready":
            path = router_client.core_file(want)
            payload["size"] = st["bytes"]
            payload["sha256"] = router_client.core_sha256(path)
    return payload


@router.get("/c/geo/{name}")
def client_geo_file(name: str, request: Request):
    """路由器端的分流数据库 (mihomo 的 GeoIP / GeoSite)。

    为什么由面板发: mihomo 缺这两份文件时不是"跳过 geo 规则"而是**整份配置加载失败**,
    而它默认会当场去 GitHub 拉 —— 真机 (GL-MT3000) 上那一步是
    `can't download MMDB: context deadline exceeded`, 装机直接卡死在这里。
    所以和内核二进制同一条思路: 面板下好、缓存好, 路由器只访问面板。

    名字走白名单 (只有 geoip.metadb / geosite.dat), 内容不含任何凭据。

    **不在这里等上游**: 以前是同步去取 (最长 200 秒), 而路由器正挂着等这个响应 ——
    真机上就是"点更新, 卡在「准备分流数据库」不动"。现在手上有数据就立刻给 (哪怕已经
    过期: 分流数据不是越新越好, 陈旧的那份交给后台刷新), 一份都没有才回 503 + 一句人话
    (与 /c/bin 完全同一个协议), 路由器据此先用自己那份, 不会卡住。
    """
    state = load_state()
    if not state["configured"]:
        return _err("面板尚未初始化", 409)
    if name not in router_client.GEO_FILES:
        return _err("没有这个数据文件", 404)
    if router_client.geo_ready(name):
        if router_client.geo_stale(name):
            router_client.ensure_geo_async(name)   # 后台换新的, 这一次先把手上这份给出去
        return FileResponse(
            router_client.geo_file(name),
            media_type="application/octet-stream",
            headers={"cache-control": "no-store"},
            filename=name,
        )
    router_client.ensure_geo_async(name)
    return Response(
        router_client.geo_pending_text(name) + "\n",
        status_code=503,
        media_type="text/plain; charset=utf-8",
        headers={"retry-after": "10", "cache-control": "no-store"},
    )


@router.get("/c/ui/{name}")
def client_ui_file(name: str, request: Request):
    """路由器管理界面的文件 (index.html / app.js / cgi / 菜单 JSON)。

    名字走白名单, 不接受路径 —— 这个端点是匿名可达的 (安装时来取), 不能变成面板上的
    任意文件读取。内容本身不含任何密钥, 是公开的界面代码。
    """
    state = load_state()
    if not state["configured"]:
        return _err("面板尚未初始化", 409)
    got = router_client.ui_file(name)
    if got is None:
        return _err("没有这个界面文件", 404)
    body, media, _filename = got
    return Response(body, media_type=media, headers={"cache-control": "no-store"})


@router.post("/c/pair")
def client_pair(payload: DeviceRegisterIn, request: Request):
    """一次性配对码 → 设备凭据 (只在这次响应里出现, 服务端只存 hash)。"""
    with config.locked():
        state = load_state()
        if not state["configured"]:
            return _err("面板尚未初始化", 409)
        info = {
            "code": payload.code,
            "kind": payload.kind,
            "hostname": payload.hostname,
            "model": payload.model,
            "arch": payload.arch,
            "os": payload.os,
            "version": payload.version,
            "ip": _client_ip(request),
        }
        device, secret, error = devices.register(state, info)
        if device is None:
            return _err(error, 403)
        base = share_links.panel_base_url(request, state)
        # 这台设备马上就会来取内核。面板现在就开始取 —— 等它来的时候多半已经好了,
        # 于是"首次安装卡在下载代理内核"这件事在装机前就消掉了 (取不到也不影响这次
        # 配对: 路由器端会看到 503 + 一句人话, 并按进度重试)。
        router_client.ensure_core_async(str(payload.arch or "").strip())
        config.audit(state, "device_add", f"{device['name']} · {device['arch']} · {device['os']}")
        save_state(state)
        return {
            "id": device["id"],
            "secret": secret,
            "name": device["name"],
            "desired": bool(device["desired"]),
            "rev": devices.config_rev(state),
            # 能力位: 客户端据此判断"这台面板给不给分流数据库"。旧面板没有 /c/geo,
            # 拿到的配置却带 geo 规则 —— 路由器只能去 GitHub 拉并超时, 所以客户端
            # 需要在装机时就发现这一点并当场说清楚 (见 router-install.sh 的 install_geo)。
            "geo": True,
            # 配对这一刻面板上这一档内核是否已经就绪 (信息位, 便于事后核对;
            # 路由器端真正依据的是 /c/bin 回 200 还是 503)。
            "core_ready": router_client.core_ready(device["arch"]),
            "sub": f"{base}/c/sub/{device['id']}?k={secret}&format=clash&rules=smart",
            "report": f"{base}/c/report",
        }


@router.get("/c/sub/{device_id}")
def client_subscription(
    device_id: str,
    request: Request,
    k: str = "",
    format: str = "clash",
    rules: str = "",
    prefix: str = "",
    geo: int = 1,
    tproxy: int = 1,
    datapath: str = "",
    ipv6: int = 0,
    mtu: int = 1500,
):
    """设备专属订阅。设备不该拿到主订阅令牌, 所以它走自己的凭据。

    单个设备可以用 `?rules=` 覆盖分流模板 (面板上那台设备的设置优先)。
    `?geo=0` 表示这台设备现在拿不到分流数据库 (面板暂时取不到, 或路由器上还没有):
    这时不给它任何 geo 规则 —— mihomo 缺数据库不是"跳过规则"而是整份配置加载失败。
    `?tproxy=0` 是设备侧的 nft / tproxy 能力 (路由器装机时自己探出来的): 面板据此
    不写 `auto-redirect` —— 那一项在不支持它固件上会让整个 tun 建不起来 (见
    share_links.router_tun)。默认 1, 老客户端行为不变。
    `?datapath=` 是设备探测出来的数据面 (tun / tproxy / redirect / none): 只有 tun
    才给 `tun` 段 —— 建不出 TUN 设备的机器带着它, mihomo 连启动都起不来 (README 8.45)。
    空值按 tun 处理, 老客户端行为不变。
    `?ipv6=1` 是设备侧探出来的"这一档数据面能一并接管 IPv6"。不能接管时保持 v4-only
    (默认 0, 老客户端行为不变) —— 那时设备的 v6 会直接出去, 这件事由设备如实上报,
    面板上写"IPv6 未接管", 而不是假装接管了。
    `?mtu=` 是设备按自己 WAN 的实际 MTU 算出来的 tun MTU (面板不知道外面是 PPPoE 还是
    以太网; PPPoE 1492 时 tun 仍收 1500 的包, 封装后就是超包)。越界值一律退回 1500。
    三种输出:
      format=clash     整份路由器配置 (单服务器模式, 内联节点)
      format=skeleton  骨架 (多服务器模式: providers 与组的 use 留空, 由路由器填)
      format=provider  只有节点 (给 mihomo 的 proxy-provider 用, 名字带前缀)
    """
    with config.locked():
        state = load_state()
        if not state["configured"]:
            return _err("面板尚未初始化", 409)
        device = devices.find(state, device_id)
        if not devices.check_secret(device, k):
            return _err("设备凭据无效", 403)
        # 设备自己的模板覆盖优先于全局设置
        tpl = (device or {}).get("template") or ""
        fmt = (format or "clash").strip().lower()
        if fmt not in (
            "clash", "mihomo", "yaml", "yml",
            "provider", "nodes", "skeleton", "router-skeleton",
        ):
            fmt = "clash"
        body, media_type = share_links.subscription_body(
            state,
            fmt,
            rules or tpl,
            router=True,
            device=str(device.get("name") or ""),
            prefix=(prefix or "").strip()[:40],
            geo=bool(geo),
            tproxy=bool(tproxy),
            datapath=(datapath or "").strip().lower(),
            ipv6=bool(ipv6),
            mtu=int(mtu),
            # 分流数据库的下载地址指向面板自己 (路由器只需要能访问面板)
            base=share_links.panel_base_url(request, state),
        )
        # 拉配置也算一次"设备还活着": 装完立刻在面板上显示在线, 不用等下一轮心跳
        if devices.touch(state, device, {"ip": _client_ip(request), "rev": devices.config_rev(state)}):
            save_state(state)
    return Response(
        body,
        media_type=media_type,
        headers={"cache-control": "no-store", "profile-update-interval": "12"},
    )


@router.post("/c/report")
def client_report(payload: DeviceReportIn, request: Request):
    """设备心跳: 上报实际状态, 取回期望开关与配置版本。"""
    with config.locked():
        state = load_state()
        if not state["configured"]:
            return _err("面板尚未初始化", 409)
        device = devices.find(state, payload.device)
        if not devices.check_secret(device, payload.k):
            return _err("设备凭据无效", 403)
        assert device is not None  # check_secret 已保证
        changed = False
        if payload.set_desired is not None and bool(device.get("desired")) != payload.set_desired:
            # 路由器本机的 `zeroproxy on|off` 走这里 —— 仍然以面板为唯一事实来源
            device["desired"] = bool(payload.set_desired)
            config.audit(
                state,
                "device_toggle",
                f"{device['name']} → {'开启' if payload.set_desired else '关闭'} (设备端操作)",
                actor="device",
            )
            changed = True
        info = {
            "ip": _client_ip(request),
            "version": payload.version,
            "arch": payload.arch,
            "os": payload.os,
            "model": payload.model,
            "ui": payload.ui,
        }
        if payload.actual is not None:
            info["actual"] = payload.actual
        if payload.report:
            info["report"] = payload.report
        changed = devices.touch(state, device, info) or changed
        if changed:
            save_state(state)
        return {
            "desired": bool(device["desired"]),
            "rev": devices.config_rev(state),
            "name": device["name"],
            "template": share_links.template_of(state),
        }
