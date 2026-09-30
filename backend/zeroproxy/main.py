"""ZeroProxy 面板入口。

生产: systemd 启动 (见 systemd/zeroproxy.service)。面板进程仅监听本机回环
(默认 127.0.0.1:9900), 对外由 nginx 在 8899 端口终结 TLS —— 域名命中真实
Let's Encrypt 证书, 其余 SNI 回退自签 —— 再反向代理到面板 (见 nginx_config.py)。

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

import uvicorn
from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__, chain_quic, config, geodata, routes, services

#: GeoIP 数据自动更新的检查间隔 (6 小时检查一次; 是否真的下载由 TTL 决定)
GEODATA_CHECK_INTERVAL = 6 * 3600
#: 启动后延迟多久做首次检查 (避开部署时的启动高峰)
GEODATA_FIRST_DELAY = 90
#: 设 ZP_GEODATA_AUTO=0 可关闭后台自动更新 (测试 / 无外网环境)
GEODATA_AUTO_ENV = "ZP_GEODATA_AUTO"


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

    critical_ports = [
        (config.PANEL_PORT, "tcp", "面板对外端口 (nginx 监听)"),
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
    try:
        yield
    finally:
        stop.set()

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


def security_headers(static_dir: str) -> dict:
    """安全响应头。

    `script-src` **不再放 'unsafe-inline'**: JS 已经全部搬进 /static/app/ 的外部模块,
    页面上只剩 head 里那一小段"首屏前应用主题"必须内联 (deferred 的模块跑完已经画过一帧,
    深色模式会先闪一次白)。这一段用 sha256 白名单放行 —— 于是"往页面里注入一个 <script>"
    这条路彻底堵死, 而它原来是开的。
    `style-src` 仍保留 'unsafe-inline': 进度条 / 流量条 / 速率曲线还有 7 处宽度是运行时算的
    (写在 innerHTML 模板里), 属于内联 style 属性, 收紧它得先把那些改成 CSSOM 赋值。
    """
    script_src = " ".join(["'self'", *inline_script_hashes(static_dir)])
    return {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Content-Security-Policy": (
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
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
    app = FastAPI(
        title="ZeroProxy", version=__version__, docs_url=None, redoc_url=None, lifespan=lifespan
    )

    @app.middleware("http")
    async def add_security_headers(request, call_next):
        """统一附加安全响应头 (面板是同源单页应用, 不需要开放 CORS)。"""
        response = await call_next(request)
        for key, value in headers.items():
            response.headers.setdefault(key, value)
        return response

    app.include_router(routes.router)

    @app.get("/", include_in_schema=False)
    def index():
        target = os.path.join(static_dir, "index.html")
        if os.path.exists(target):
            # 前端必须跟随后端一起升级: 只带 Last-Modified/ETag 而没有 Cache-Control 时,
            # 浏览器会做"启发式缓存" (最长可到文件年龄的 10%), 升级后面板可能还在跑几天
            # 前那份 index.html —— 界面是旧的, 于是"明明修了按钮还是卡"。这里强制每次
            # 都用 ETag 回源校验 (命中就是 304, 代价极小)。
            return FileResponse(target, headers={"cache-control": "no-cache"})
        return JSONResponse(
            {"name": "ZeroProxy", "version": __version__, "hint": "static/index.html 缺失"},
            status_code=200,
        )

    if os.path.isdir(static_dir):
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/api/info", include_in_schema=False)
    def info():
        return {"name": "ZeroProxy", "version": __version__, "home": config.home()}

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
