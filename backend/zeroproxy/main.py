"""ZeroProxy 面板入口。

生产: systemd 启动 (见 systemd/zeroproxy.service)。面板进程仅监听本机回环
(默认 127.0.0.1:9900), 对外由 nginx 在 8899 端口终结 TLS —— 域名命中真实
Let's Encrypt 证书, 其余 SNI 回退自签 —— 再反向代理到面板 (见 nginx_config.py)。

本地: ZP_HOME=... ZP_STATIC=... ZP_BIND_PORT=8899 python -m zeroproxy.main
"""
from __future__ import annotations

import os

import uvicorn
from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__, config, routes

#: 安全响应头。前端是单文件内联 CSS/JS, 因此 CSP 必须允许 'unsafe-inline';
#: 其余指令仍然收紧 (禁止外域脚本/框架嵌入/跨站引用)。
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; connect-src 'self'; form-action 'self'; "
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
    app = FastAPI(title="ZeroProxy", version=__version__, docs_url=None, redoc_url=None)

    @app.middleware("http")
    async def security_headers(request, call_next):
        """统一附加安全响应头 (面板是同源单页应用, 不需要开放 CORS)。"""
        response = await call_next(request)
        for key, value in SECURITY_HEADERS.items():
            response.headers.setdefault(key, value)
        return response

    app.include_router(routes.router)

    static_dir = _static_dir()

    @app.get("/", include_in_schema=False)
    def index():
        target = os.path.join(static_dir, "index.html")
        if os.path.exists(target):
            return FileResponse(target)
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

if __name__ == "__main__":
    uvicorn.run(
        app,
        host=config.PANEL_BIND_HOST,
        port=config.PANEL_BIND_PORT,
        log_level="warning",
        proxy_headers=True,               # 信任 nginx 传来的 X-Forwarded-Proto/For
        forwarded_allow_ips="127.0.0.1",
    )
