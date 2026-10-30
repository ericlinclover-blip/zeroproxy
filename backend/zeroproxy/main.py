"""ZeroProxy 面板入口。

生产: systemd 启动 (见 systemd/zeroproxy.service)。面板进程仅监听本机回环
(默认 127.0.0.1:9900), 正式入口是 nginx 443 的 /panel/, 8899 作为兼容入口
继续保留 (见 nginx_config.py)。

本地: ZP_HOME=... ZP_STATIC=... ZP_BIND_PORT=8899 python -m zeroproxy.main
"""
from __future__ import annotations

import contextlib
import base64
import hashlib
import os
import re
import sys
import threading
from urllib.parse import urlsplit

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import __version__, chain_quic, config, geodata, routes, services, wireguard

#: GeoIP 数据自动更新的检查间隔 (6 小时检查一次; 是否真的下载由 TTL 决定)
GEODATA_CHECK_INTERVAL = 6 * 3600
#: 启动后延迟多久做首次检查 (避开部署时的启动高峰)
GEODATA_FIRST_DELAY = 90
#: 设 ZP_GEODATA_AUTO=0 可关闭后台自动更新 (测试 / 无外网环境)
GEODATA_AUTO_ENV = "ZP_GEODATA_AUTO"

#: WireGuard 到期客户端的回收间隔（秒）。只处理设置了 expires_at 的 peer。
WIREGUARD_CHECK_INTERVAL = 60


def _geodata_once() -> None:
    """一次自动更新: 过期才下载; 数据变化则重启 Xray 使其生效。

    与面板上的「下载 / 更新」按钮共用 geodata.UPDATE_LOCK: 手动下载在跑时就
    不抢 (否则两条路径同时写 geo 目录); 失败原因照旧写进 state, 卡片上能看见。

    并发安全: 下载前记录 state_version, 下载结束后对比版本。若版本在下载期间
    发生变化 (说明有用户操作或另一条线程写入了 state), 则重新 load_state 后
    再用 merge_result 并回 — 此时 merge_result 内的 updated_at 时间戳比较
    会保护"下载期间用户的修改不被旧快照覆盖"。
    """
    with config.locked():
        state = config.load_state()
        if not state.get("configured") or not geodata.wants_update(state):
            return
        version_before = int(state.get("updated_at") or 0)
    if not geodata.UPDATE_LOCK.acquire(blocking=False):
        return
    try:
        ok, detail = geodata.auto_tick(state)
    finally:
        geodata.UPDATE_LOCK.release()
    with config.locked():
        fresh = config.load_state()
        # 若下载期间 state 被修改过 (updated_at 变了), merge_result 会基于
        # 时间戳比较保护目标数据 — 确保下载期间的用户操作不被覆盖
        geodata.merge_result(fresh, state, ok)
        config.audit(fresh, "geodata_auto", detail[:190], actor="scheduler")
        config.save_state(fresh)
    if ok:
        services.restart_service("xray")  # geo 数据在启动时载入, 需重启才生效


def _check_startup_ports() -> None:
    """启动时检查关键端口是否被占用, 避免静默失败。

    端口硬编码在 config.py 中 (可通过环境变量覆盖), 但需要运行时验证。
    若端口冲突, 在日志中打印醒目提示, 不阻断面板启动 — 让用户看到问题,
    而不是面板"正常运行"但端口实际在监听另一份服务。
    """
    import socket

    # PANEL_PORT 由 nginx 持有, 面板启动时看到它被占用是正常状态。旧检查把它也
    # 当成冲突, 每次重启都会留下一条误导性的 "Address already in use"。
    critical_ports = [
        (config.PANEL_BIND_PORT, "tcp", "面板进程绑定端口 (uvicorn)"),
    ]
    conflicts = []
    for port, proto, label in critical_ports:
        family = socket.AF_INET
        sock_type = socket.SOCK_STREAM
        with socket.socket(family, sock_type) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1" if proto == "tcp" and port == config.PANEL_BIND_PORT else "0.0.0.0", port))
            except OSError as exc:
                conflicts.append(f"⚠ {label} (端口 {port}): {exc}")
    if conflicts:
        # 只打印不阻断: 可能是旧进程残留 (reload 场景), 面板自身 bind 后旧进程会释放
        for msg in conflicts:
            print(f"[zeroproxy] {msg}", file=sys.stderr)


def _geodata_loop(stop: threading.Event) -> None:
    if os.environ.get(GEODATA_AUTO_ENV, "1") == "0":
        return
    if stop.wait(GEODATA_FIRST_DELAY):
        return
    while not stop.is_set():
        try:
            _geodata_once()
        except Exception:  # noqa: BLE001 — 后台任务绝不能因异常退出
            pass
        if stop.wait(GEODATA_CHECK_INTERVAL):
            return


def _wireguard_loop(stop: threading.Event) -> None:
    """到期 peer 自动停用：从内核里摘掉，而不是只在面板上标红。"""
    if os.environ.get("ZP_WIREGUARD_AUTO", "1") == "0":
        return
    while not stop.wait(WIREGUARD_CHECK_INTERVAL):
        try:
            with config.locked():
                state = config.load_state()
                if not state.get("configured") or not wireguard.enabled(state):
                    continue
                if not wireguard.reap_expired(state):
                    continue
                ok, detail = wireguard.sync(state)
                config.audit(
                    state,
                    "wireguard_expire",
                    ("自动停用到期客户端 · " if ok else "到期客户端停用失败 · ") + detail[:160],
                    actor="scheduler",
                )
                config.save_state(state)
        except Exception:  # noqa: BLE001 — 后台任务不能因单次异常退出
            pass


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    """后台维护任务: GeoIP/GeoSite 自动更新 + 链式内层 QUIC 进程看门。"""
    stop = threading.Event()
    worker = threading.Thread(target=_geodata_loop, args=(stop,), daemon=True, name="zp-geodata")
    worker.start()
    # 链式内层 QUIC (Hysteria 2) 的进程由面板托管: systemd 重启面板会把子进程一起
    # 收走, 这里在启动时对齐一次 (并把上次崩溃留下的孤儿清掉), 之后由看门线程兜底。
    keeper = threading.Thread(
        target=chain_quic.supervisor_loop, args=(stop,), daemon=True, name="zp-chain-quic"
    )
    keeper.start()
    # WireGuard 到期回收 (每 60 秒看一次; 没有启用或没有到期 peer 时什么也不做)
    threading.Thread(
        target=_wireguard_loop, args=(stop,), daemon=True, name="zp-wireguard"
    ).start()
    # 顶部「出口 IP」卡片要显示本机公网 IP, 而云主机的公网 IP 不在网卡上 (NAT /
    # 弹性 IP), 只能问一次外部回显服务。启动时先读, 免得用户打开面板看到一片"—";
    # 之后由 services 按 TTL 在后台自己刷。ZP_PUBLIC_IP=0 可整体关闭 (测试离线跑)。
    threading.Thread(
        target=services.refresh_public_ip, daemon=True, name="zp-public-ip"
    ).start()
    try:
        yield
    finally:
        stop.set()
        # 面板托管的链式内层 QUIC (Hysteria 2) 子进程: 退出时一并收掉 ——
        # 否则开发环境 Ctrl-C / 重启面板会留下孤儿 hysteria 进程 (P3-6)。
        # stop_all 是幂等的 (第二次调用时 _PROCS 已空), systemd 场景重复调用也安全。
        with contextlib.suppress(Exception):
            chain_quic.stop_all()

#: 内联 <script> 块 (带 src 的外链脚本由 'self' 覆盖, 不参与哈希)
_INLINE_SCRIPT_RE = re.compile(r"<script\b([^>]*)>(.*?)</script>", re.DOTALL | re.IGNORECASE)


def inline_script_hashes(static_dir: str) -> list[str]:
    """index.html 里内联脚本的 sha256 CSP 白名单。

    为什么在启动时按文件算, 而不是把哈希写死在策略里: 写死的话, 以后改一次内联脚本就得
    同步改常量, 忘了改的后果是**主题脚本被浏览器静默拦下** —— 深色模式失效、控制台之外
    看不出来。按实际文件算, 源码与策略永远一致。
    """
    try:
        with open(os.path.join(static_dir, "index.html"), encoding="utf-8") as fh:
            html = fh.read()
    except OSError:
        return []
    hashes = []
    for attrs, body in _INLINE_SCRIPT_RE.findall(html):
        if "src=" in attrs.lower():
            continue
        digest = hashlib.sha256(body.encode("utf-8")).digest()
        hashes.append("'sha256-" + base64.b64encode(digest).decode("ascii") + "'")
    return hashes


#: 写接口的 CSRF 纵深: 浏览器跨源写请求必须带 Origin, 且 Origin 必须与面板同源。
#: 无 Origin 的请求 (curl / 路由器 CLI / 旧客户端) 不是浏览器跨源请求, 照旧放行。
_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
#: 只在 HTTPS 下发的 HSTS (明文响应里浏览器会忽略, 没必要出现)
HSTS_HEADER = "Strict-Transport-Security"
HSTS_VALUE = "max-age=31536000; includeSubDomains"


def _same_origin(origin: str, request: Request) -> bool:
    """Origin 头是否与本次请求同源 (主机名必须一致; 端口在 Host 明确给出时也要一致)。

    nginx 反代时 Host 可能被改写成不带端口的形式 (``$host``), 而浏览器 Origin 里
    带着 8899 这类非默认端口 —— 所以"Host 没写端口"时只比主机名, 避免把正常的
    面板访问误判成跨源。
    """
    try:
        parsed = urlsplit(origin)
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    origin_host = parsed.hostname.lower()
    host_header = (request.headers.get("host") or "").strip()
    if not host_header:
        return False
    host = host_header
    explicit_port = None
    if host.startswith("["):              # IPv6 字面量
        closing = host.find("]")
        if closing != -1:
            host = host[: closing + 1]
            rest = host_header[closing + 1:]
            if rest.startswith(":") and rest[1:].isdigit():
                explicit_port = int(rest[1:])
    else:
        name, sep, port = host_header.rpartition(":")
        if sep and port.isdigit():
            host, explicit_port = name, int(port)
    if host.strip("[]").lower() != origin_host:
        return False
    if explicit_port is not None:
        origin_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return origin_port == explicit_port
    return True


def security_headers(static_dir: str) -> dict:
    """安全响应头。

    `script-src` **不再放 'unsafe-inline'**: JS 已经全部搬进 /static/app/ 的外部模块,
    页面上只剩 head 里那一小段"首屏前应用主题"必须内联 (deferred 的模块跑完已经画过一帧,
    深色模式会先闪一次白)。这一段用 sha256 白名单放行 —— 于是"往页面里注入一个 <script>"
    这条路彻底堵死, 而它原来是开的。
    `style-src` **也不再放 'unsafe-inline'**: 内联 style 属性原本挡着这条路 —— 进度条 /
    延迟条 / 流量条那几处宽度是运行时算的, 一直写在 innerHTML 模板里。现在模板只写
    `data-w` / `data-bg` 两个字面量属性, 插入文档后由 `lib/dom.js` 的 `applyWidths()`
    用 CSSOM 赋值 (`el.style.*` 不受 style-src 约束) —— 于是"往页面里注入一个 <style>
    或一段 style= 属性"同样执行不了, 而条子的宽度一个像素都没变。
    """
    script_src = " ".join(["'self'", *inline_script_hashes(static_dir)])
    return {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Content-Security-Policy": (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            f"script-src {script_src}; connect-src 'self'; form-action 'self'; "
            "base-uri 'none'; frame-ancestors 'none'"
        ),
    }


def _static_dir() -> str:
    candidates = [
        os.environ.get("ZP_STATIC", ""),
        os.path.join(config.home(), "static"),
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static"),
    ]
    for path in candidates:
        if path and os.path.isdir(path):
            return path
    return candidates[2]


def create_app() -> FastAPI:
    static_dir = _static_dir()
    headers = security_headers(static_dir)
    #: 静态资源的版本前缀。资源 URL 里带版本号 = 升级后浏览器面对的是**新地址**,
    #: 不可能命中上一版的缓存 (下面的 index() 会把 index.html 里的 /static/ 改写掉)。
    static_prefix = f"/static/v{__version__}"
    app = FastAPI(
        title="ZeroProxy", version=__version__, docs_url=None, redoc_url=None, lifespan=lifespan
    )

    @app.middleware("http")
    async def add_security_headers(request, call_next):
        """统一附加安全响应头 (面板是同源单页应用, 不需要开放 CORS)。

        顺带做一层 CSRF 纵深 (P3-11): 写接口 (POST/PUT/PATCH/DELETE) 带 Origin 时
        必须与面板同源, 否则 403。无 Origin 的请求放行 —— curl、路由器 CLI、
        同源导航都不发 Origin, 而依赖 SameSite=Lax 之外再加这一道是纯收益。
        """
        if request.method in _WRITE_METHODS and request.url.path.startswith("/api/"):
            origin = (request.headers.get("origin") or "").strip()
            if origin and not _same_origin(origin, request):
                return JSONResponse(
                    {"error": "跨源写请求被拒绝 (Origin 与面板地址不一致)"}, status_code=403
                )
        response = await call_next(request)
        for key, value in headers.items():
            response.headers.setdefault(key, value)
        # HSTS: 只在 https (直连或经 nginx 的 X-Forwarded-Proto) 下发
        fwd_proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
        if request.url.scheme == "https" or fwd_proto == "https":
            response.headers.setdefault(HSTS_HEADER, HSTS_VALUE)
        # 认证 JSON 里含订阅地址 / 配对码 / 审计等, 不允许任何中间层缓存 (P3-9)
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("cache-control", "no-store")
        # 静态资源必须每次回源校验。
        #
        # FastAPI 的 StaticFiles 只发 Last-Modified/ETag, 不发 Cache-Control —— 浏览器
        # 于是按"启发式缓存"处理 (可缓存文件年龄的 10%)。升级后 index.html 会立刻更新
        # (它自己带 no-cache), 但 /static/ 下的 JS/CSS 可能还在用上一版: 表现就是
        # **新加的功能卡片在页面上是空壳, 样式也是旧的**, 而用户完全不知道要强制刷新。
        # 这里给整棵静态树补上 no-cache (命中 ETag 就是 304, 代价极小)。
        if request.url.path.startswith("/static/"):
            response.headers.setdefault("cache-control", "no-cache")
        return response

    app.include_router(routes.router)

    @app.get("/", include_in_schema=False)
    def index(request: Request):
        target = os.path.join(static_dir, "index.html")
        if not os.path.exists(target):
            return JSONResponse(
                {"name": "ZeroProxy", "version": __version__, "hint": "static/index.html 缺失"},
                status_code=200,
            )
        # index.html 每次都由这里渲染, 顺便把静态资源地址改写成带版本前缀的形式。
        # 只改 `"/static/` 这种带引号的引用 (样式表与模块入口), 注释里的路径不动。
        try:
            with open(target, encoding="utf-8") as fh:
                html = fh.read().replace('"/static/', f'"{static_prefix}/')
        except OSError:
            return FileResponse(target, headers={"cache-control": "no-cache"})
        # 前端必须跟随后端一起升级: 只带 Last-Modified/ETag 而没有 Cache-Control 时,
        # 浏览器会做"启发式缓存" (最长可到文件年龄的 10%), 升级后面板可能还在跑几天
        # 前那份 index.html —— 界面是旧的, 于是"明明修了按钮还是卡"。这里强制每次
        # 都用 ETag 回源校验 (命中就是 304, 代价极小); 版本号进 ETag, 升级必然失效。
        etag = f'W/"{__version__}-{int(os.path.getmtime(target))}"'
        if request.headers.get("if-none-match") == etag:
            return Response(status_code=304, headers={"etag": etag, "cache-control": "no-cache"})
        return Response(
            html,
            media_type="text/html; charset=utf-8",
            headers={"etag": etag, "cache-control": "no-cache"},
        )

    if os.path.isdir(static_dir):
        # 先挂带版本号的, 再挂裸 /static: Starlette 按注册顺序匹配, 顺序反了的话
        # /static/v2.7.1/app/main.js 会先命中裸挂载点, 然后去磁盘上找 v2.7.1 目录 → 404。
        app.mount(static_prefix, StaticFiles(directory=static_dir), name="static-versioned")
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/api/info", include_in_schema=False)
    def info():
        # 未认证端点不返回 home 绝对路径 (P3-10); 面板设置卡片用的路径由
        # 已认证的仪表盘数据里给。
        return {"name": "ZeroProxy", "version": __version__}

    @app.exception_handler(config.StateError)
    async def state_error_handler(request: Request, exc: config.StateError):
        """state.json 损坏 → 503 维护态 (而不是回落默认值后让面板"像没初始化过")。"""
        return JSONResponse(
            {"error": str(exc), "maintenance": True, "state_error": True},
            status_code=503,
        )

    return app


app = create_app()

# 启动时端口探测 (非阻塞, 仅打印告警)
_check_startup_ports()

if __name__ == "__main__":
    uvicorn.run(
        app,
        host=config.PANEL_BIND_HOST,
        port=config.PANEL_BIND_PORT,
        log_level="warning",
        proxy_headers=True,               # 信任 nginx 传来的 X-Forwarded-Proto/For
        forwarded_allow_ips="127.0.0.1",
    )
