#!/usr/bin/env python3
"""路由器安装脚本的端到端演练 (不依赖真路由器)。

为什么要这个脚本
----------------
`router-install.sh` 是本项目里唯一"跑在别人设备上、出错只能靠用户截图"的代码,
而 pytest 只能做静态审计 (断言用了哪些命令、哪些字符串)。上线 2.7.0 后两天内它坏了两次,
两次都只有真跑才会暴露:

  * `od` 判断 gzip —— OpenWrt 的 busybox 没有 od, 于是把 gz 当二进制执行;
  * 凭据在面板上被移除后, 本地文件看不出问题, 直到拉配置 403 才发现。

所以这里真的起一份面板、真的用 shell 跑一遍安装脚本 (在本机模拟 OpenWrt), 覆盖:

  1. 配对 → 下载(压缩的假内核) → 解压 → 可执行校验 → 落配置
  2. 生成的控制 agent 能真的跟面板对话, 并让设备状态在 desired/actual 间正确翻转
  3. 面板上把设备移除后重跑安装命令 → 自动用新配对码重新接入 (自愈)

做法: 起面板 → 把脚本里的 OpenWrt 路径与 root 检查替换成本机临时目录 (本机没有
OpenWrt, 也没有 root), 面板侧用一个几 KB 的**压缩**假内核替代 20 MB 的 mihomo
(`ZP_CORE_MIN_BYTES`), 从而把"下载 → gzip -t → 解压 → 执行校验"整条链路跑通。

用法:
    python3 scripts/router_install_check.py
需要: curl (或 uclient-fetch), sh, 以及 backend 的 venv。
"""
from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, "backend")
AGENT_SRC = os.path.join(BACKEND, "zeroproxy", "client", "agent")
PYTHON = os.environ.get("ZP_PYTHON") or os.path.join(ROOT, ".venv", "bin", "python")
if not os.path.exists(PYTHON):  # 没有 venv 就退回系统 python (可能缺依赖, 会在启动时报出来)
    PYTHON = "python3"

PORT = int(os.environ.get("ZP_CHECK_PORT", "8901"))
BASE = f"http://127.0.0.1:{PORT}"
TOKEN = "router-install-check"

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: object = "") -> None:
    results.append((name, ok, detail))
    print(f"  {'✓' if ok else '✗'} {name}{' — ' + str(detail) if detail else ''}")


def find_go() -> str | None:
    """本机的 Go 工具链 (zpcore 要它来构建)。没有就跳过那一节 —— 面板发不出这一档时,
    装机本来就会退回原来的界面路径, 那正是设计里的降级, 不是失败。"""
    for candidate in (os.environ.get("ZP_GO", ""), "go", "/opt/homebrew/bin/go", "/usr/local/go/bin/go"):
        if candidate and shutil.which(candidate):
            return candidate
    return None


def http(method: str, path: str, body=None, cookie: str | None = None):
    req = urllib.request.Request(BASE + path, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
        req.data = json.dumps(body).encode()
    if cookie:
        req.add_header("Cookie", cookie)
    with urllib.request.urlopen(req, timeout=180) as resp:
        return resp.status, resp.read().decode(), resp.headers


def patch_for_local_run(script: str, root: str) -> str:
    """把脚本改成本机能跑: 换路径、跳过 root/OpenWrt 检查、只跑到写文件那一步。

    这不改变被测逻辑 —— 架构探测、配对、下载、解压、配置拉取、文件生成全都照跑。
    """
    out = script
    out = out.replace("/etc/zeroproxy", root)
    out = out.replace("/etc/init.d/zeroproxy", root + "/initd")
    out = out.replace("/usr/bin/zeroproxy", root + "/cli")
    out = out.replace(
        '[ "$(id -u)" = "0" ] || die "需要 root 权限, 请用 root 账户执行 (OpenWrt 默认就是 root)"',
        "true",
    )
    out = re.sub(r'\[ -r /etc/openwrt_release \] \|\| die "[^"]*"', "true", out, flags=re.S)
    # 固件标识 (DISTRIB_RELEASE 决定包管理器: 25.12 起是 apk) 也换到临时目录里的假文件 ——
    # 25.12 / apk 那一节就是在这上面做文章的 (见 [12])。放在上面那条 re.sub 之后:
    # 先让它按原样匹配掉 "没有 OpenWrt 就 die" 那句, 再改路径。
    out = out.replace("/etc/openwrt_release", os.path.join(root, "openwrt_release"))
    # 内核 BTF 的两条路也要落到临时目录里, 否则 [13] 那一节没法验:
    #   * /sys/kernel/btf/vmlinux —— 内核自带的那份 (真机上由固件决定);
    #   * /usr/lib/debug/boot/vmlinux-<内核版本> —— 补进来的 detached BTF (社区的包装在这)。
    out = out.replace("/sys/kernel/btf/vmlinux", os.path.join(root, "sys/kernel/btf/vmlinux"))
    out = out.replace("/usr/lib/debug", os.path.join(root, "usr/lib/debug"))
    # LuCI 那三件套的落盘路径也落到临时目录里 ([16] 那一节要验"升级不毁好文件"与 `ui fix`)。
    out = out.replace("/usr/share/luci/menu.d", os.path.join(root, "usr/share/luci/menu.d"))
    out = out.replace("/usr/share/rpcd/acl.d", os.path.join(root, "usr/share/rpcd/acl.d"))
    out = out.replace("/www/luci-static", os.path.join(root, "www/luci-static"))
    out = out.replace("[ -d /www ]", "[ -d " + os.path.join(root, "www") + " ]")
    # 本机没有 procd / systemd, 自检那一步 (启动 mihomo + 等控制口) 必然失败 ——
    # 这里停在"文件已落盘", 服务编排由真机验证; 但配置生成与 agent 逻辑照跑。
    out = out.replace(
        '\nmain "$@"\n',
        "\nmain() { detect_env; detect_http; preflight; pair; install_deps; "
        "install_core; write_files; install_zpcore; }\nmain \"$@\"\n",
    )
    return out


class StallUpstream:
    """一个"能连上、永远不说话"的假上游。

    用它复现真机那一刻: 面板去上游取内核时被挂在"正在下载"上 (urllib 的超时只管
    单次 socket 操作, 只要对面不关连接就得靠面板自己的总时限兜底)。
    """

    def __init__(self) -> None:
        import socketserver

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):  # pragma: no cover - 只负责把连接挂住
                time.sleep(120)

        self.srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self.srv.daemon_threads = True
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()


class FakeMirror:
    """一个本地的"直连镜像": 不管请求什么路径, 都返回那份假内核。

    真机上这里是 github.i3.pub / gh-proxy 这类反代 —— 演练里用本地服务器替代,
    于是"面板直传太慢 → 改走直连镜像"这条路可以离线跑、也不会真去下 20 MB。
    """

    def __init__(self, blob: bytes) -> None:
        import http.server

        payload = blob

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                self.send_response(200)
                self.send_header("Content-Type", "application/gzip")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):  # pragma: no cover - 别刷屏
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}/{{url}}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


class Throttle:
    """把面板"包"在一根慢管子后面: 转发一切, 但 /c/bin 的正文按块慢慢吐。

    用它复现真机那一幕: 面板自己有内核, 但用户家宽到海外面板只有几十 KB/s ——
    20 MB 要十几分钟。安装脚本应该发现"这条路太慢"并改走直连镜像。
    """

    def __init__(self, upstream: str, *, chunk: int = 8192, delay: float = 0.25) -> None:
        import http.server
        import urllib.request as _req

        self.chunk, self.delay = chunk, delay
        #: 这些路径"请求进去了但没有回应" —— 用来复现"面板整体是好的, 只有某一段在丢包"。
        self.hang: tuple[str, ...] = ()
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _proxy(self):
                if outer.hang and self.path.startswith(outer.hang):
                    # 一段路在丢包: 请求收下了, 回复**断在半路** (真机上丢包长这样 —— 有时是
                    # 一直等到超时, 有时是中间设备直接把它截断)。关键是这里**没有**一个正常的
                    # HTTP 答复, 客户端不许把这种情况判成"面板拒绝了凭据"。
                    # (用截断而不是"睡到超时": 两者在客户端眼里走的是同一条分支, 而演练要快。)
                    self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                                     b"Content-Length: 4096\r\n\r\n")
                    self.wfile.flush()
                    self.close_connection = True
                    return
                body = None
                if "Content-Length" in self.headers:
                    body = self.rfile.read(int(self.headers["Content-Length"]))
                request = _req.Request(upstream + self.path, data=body, method=self.command)
                for key in ("Content-Type", "Cookie", "Authorization"):
                    if key in self.headers:
                        request.add_header(key, self.headers[key])
                try:
                    with _req.urlopen(request, timeout=30) as resp:
                        data = resp.read()
                        code, headers = resp.status, dict(resp.headers)
                except Exception as exc:  # pragma: no cover - 演练里不该走到
                    self.send_error(502, str(exc))
                    return
                self.send_response(code)
                for key, value in headers.items():
                    if key.lower() in ("content-length", "transfer-encoding", "connection"):
                        continue
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if "/c/bin/" in self.path:
                    for start in range(0, len(data), outer.chunk):
                        self.wfile.write(data[start:start + outer.chunk])
                        self.wfile.flush()
                        time.sleep(outer.delay)       # 慢管子
                else:
                    self.wfile.write(data)

            do_GET = _proxy
            do_POST = _proxy

            def log_message(self, *args):  # pragma: no cover - 别刷屏
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


class Panel:
    """一台演练用的面板 (真起 uvicorn, 真注册设备)。"""

    def __init__(self, port: int, home: str, name: str, extra_env: dict | None = None):
        self.port, self.home, self.name = port, home, name
        self.base = f"http://127.0.0.1:{port}"
        os.makedirs(os.path.join(home, "data"), exist_ok=True)
        with open(os.path.join(home, "data", "bootstrap_token"), "w") as fh:
            fh.write(TOKEN + "\n")
        self.env = {
            **os.environ,
            "ZP_HOME": home,
            "ZP_STATIC": os.path.join(BACKEND, "static"),
            "ZP_BIND_HOST": "127.0.0.1",
            "ZP_BIND_PORT": str(port),
            "ZP_PORT": str(port),
            "ZP_PUBLIC_IP": "0",
            "ZP_GEODATA_AUTO": "0",
            "ZP_APPLY_ASYNC": "0",
            "ZP_CORE_MIN_BYTES": "16",   # 假内核只有几百字节
            "ZP_BTF_MIN_BYTES": "16",    # [13] 的假 BTF 包同理
            # BTF 包的上游资产清单 (api.github.com) 也换掉: 演练必须离线可跑, 而且这一节
            # 验的是"缓存里有匹配的包时面板发不发得出来", 不是"面板能不能访问 GitHub"。
            "ZP_BTF_API": "http://127.0.0.1:9",
            "ZP_GEO_MIN_BYTES": "16",    # 分流数据库同理 (演练不下载真的 4 MB)
            # 分流数据库的镜像表也换掉: 面板那条路万一没走通, 客户端会去够镜像 ——
            # 演练必须离线可跑, 不能因为网络脸色而红 (与 ZP_CORE_MIRRORS 同一个理由)。
            "ZP_GEO_MIRRORS": "http://127.0.0.1:9/{url}",
        }
        self.env.update(extra_env or {})
        self.proc = subprocess.Popen(
            [PYTHON, "-m", "zeroproxy.main"], cwd=BACKEND, env=self.env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        self.cookie = ""
        self.log = ""

    def wait(self) -> bool:
        for _ in range(60):
            time.sleep(0.5)
            try:
                self.req("GET", "/api/info")
                return True
            except (urllib.error.URLError, OSError):
                pass
        self.log = (self.proc.stdout.read() or "") if self.proc.stdout else ""
        return False

    def configure(self, domain: str) -> None:
        self.req("POST", "/api/setup", {
            "domain": domain, "username": "admin", "password": "s3cretpass", "token": TOKEN,
        })
        _, _, headers = self.req("POST", "/api/login", {"username": "admin", "password": "s3cretpass"})
        self.cookie = headers.get("set-cookie", "").split(";")[0]

    def req(self, method: str, path: str, body=None):
        req = urllib.request.Request(self.base + path, method=method)
        if body is not None:
            req.add_header("Content-Type", "application/json")
            req.data = json.dumps(body).encode()
        if self.cookie:
            req.add_header("Cookie", self.cookie)
        with urllib.request.urlopen(req, timeout=180) as resp:
            return resp.status, resp.read().decode(), resp.headers

    def pair_code(self, label: str) -> str:
        _, body, _ = self.req("POST", "/api/devices/pair", {"label": label})
        return json.loads(body)["code"]

    def req_raw(self, method: str, path: str):
        """同 req(), 但不把 4xx/5xx 当异常 —— 要看的就是 503 的正文与头。"""
        req = urllib.request.Request(self.base + path, method=method)
        if self.cookie:
            req.add_header("Cookie", self.cookie)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, resp.read().decode(), resp.headers
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode(), exc.headers

    def stop(self) -> None:
        self.proc.send_signal(signal.SIGTERM)
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def main() -> int:
    import gzip   # 内核与 zpcore 都是 .gz 形态, 这里从头就要用

    tmp = tempfile.mkdtemp(prefix="zp-router-check-")
    fake_root = os.path.join(tmp, "root")
    os.makedirs(fake_root, exist_ok=True)
    env = {**os.environ, "ZP_GEODATA_AUTO": "0", "ZP_PUBLIC_IP": "0"}
    os.environ.update(env)
    sys.path.insert(0, BACKEND)
    from zeroproxy import router_client  # noqa: E402

    print(f"ZeroProxy 路由器安装演练  (PORT={PORT}, 第二台面板 {PORT + 1})")
    # 先把可选件 (zpcore, 本地控制面) 构建出来 —— 它是"界面不再依赖固件 Web 服务器"那条路。
    # 没有 Go 就跳过: 面板发不出这一档, 装机退回原来的界面路径 (设计里的降级, 不是失败)。
    agent_dist = os.path.join(tmp, "agent-dist")
    os.makedirs(agent_dist, exist_ok=True)
    go = find_go()
    agent_env: dict = {}
    if go:
        print("\n[0] 构建本地控制面 zpcore")
        # 真机目标 (linux/arm64) 必须能交叉编译过 —— 这一步证明发到路由器的那一份是构建得出来的
        cross = subprocess.run(
            [go, "build", "-trimpath", "-ldflags", "-s -w", "-o",
             os.path.join(tmp, "zpcore-linux-arm64"), "."],
            cwd=AGENT_SRC, capture_output=True, text=True,
            env={**os.environ, "GOOS": "linux", "GOARCH": "arm64", "CGO_ENABLED": "0"},
        )
        check("zpcore 能交叉编译出真机用的 linux/arm64", cross.returncode == 0, cross.stderr[-200:])
        # 演练里那个"路由器"是本机模拟的, 所以跑的这一份得是本机平台的二进制。文件名仍然按
        # arm64 命名 —— 面板只认文件名里的架构, 而这一节的目的是**真跑一遍接口契约**。
        host_bin = os.path.join(tmp, "zpcore-host")
        # 版本号靠构建时注入 (面板代码里的 AGENT_VERSION 是唯一来源); 演练也照这条走,
        # 否则装出来的二进制会自报 "dev", 下面那条"它自报的版本 == 面板要的那一版"就没意义
        built = subprocess.run(
            [go, "build", "-ldflags", f"-X main.agentVersion={router_client.AGENT_VERSION}",
             "-o", host_bin, "."],
                               cwd=AGENT_SRC, capture_output=True, text=True)
        runs = subprocess.run([host_bin, "version"], capture_output=True, text=True)
        check("zpcore 能在本机构建并运行",
              built.returncode == 0 and runs.returncode == 0 and runs.stdout.startswith("zpcore"),
              (built.stderr or runs.stderr)[-160:])
        if built.returncode == 0 and runs.returncode == 0:
            with open(host_bin, "rb") as fh:
                blob = fh.read()
            with gzip.open(os.path.join(agent_dist, f"zpcore-arm64-{router_client.AGENT_VERSION}.gz"),
                           "wb") as out:
                out.write(blob)
            agent_env["ZP_AGENT_DIR"] = agent_dist

    panels = [Panel(PORT, os.path.join(tmp, "home-a"), "A", extra_env=agent_env),
              Panel(PORT + 1, os.path.join(tmp, "home-b"), "B")]
    try:
        for panel in panels:
            if not panel.wait():
                print(f"面板 {panel.name} 没起来:\n" + panel.log[-2000:])
                return 1
            panel.configure(f"127.0.0.1" if panel.name == "A" else "127.0.0.2")
        panel = panels[0]
        http = panel.req

        # 面板真的发得出来吗? 先自己验一次 —— 否则安装脚本里那句"面板没有准备这一档"
        # 会把"端点坏了"伪装成"没准备", 而两者的下一步完全不同。
        if go:
            try:
                with urllib.request.urlopen(panel.base + "/c/agent/bin/arm64", timeout=30) as resp:
                    served_blob = resp.read()
                check("面板把本地控制面制品发得出来",
                      resp.status == 200 and len(served_blob) > 100000,
                      f"HTTP {resp.status} · {len(served_blob)} 字节")
            except urllib.error.HTTPError as exc:
                check("面板把本地控制面制品发得出来", False,
                      f"HTTP {exc.code} · {exc.read().decode()[:90]}")

        # 面板侧缓存一个"压缩过的假内核": 让安装脚本真的走 gzip 判定 + 解压 + 执行
        cache = os.path.join(panels[0].home, "data", "client", "cores")
        os.makedirs(cache, exist_ok=True)
        stub = (
            '#!/bin/sh\ncase "$*" in\n'
            '  *-v*) echo "Mihomo Meta v1.19.32 (stub)" ;;\n'
            '  *-t*) exit 0 ;;\n'
            '  *) while :; do sleep 60; done ;;\n'
            "esac\nexit 0\n"
        )
        with gzip.open(os.path.join(cache, f"mihomo-arm64-{router_client.CORE_VERSION}.gz"), "wb") as fh:
            fh.write(stub.encode())

        # 面板侧再缓存两份分流数据库: 真机上是面板去 GitHub 取 (多镜像), 路由器只访问
        # 面板 —— 演练里预置好, 于是整条"路由器从面板取 geo"的链路真的跑一遍。
        for panel_ in panels:
            geo_cache = os.path.join(panel_.home, "data", "client", "geo")
            os.makedirs(geo_cache, exist_ok=True)
            for name in ("geoip.metadb", "geosite.dat"):
                with open(os.path.join(geo_cache, name), "wb") as fh:
                    fh.write(f"fake-geo-{panel_.name}-{name}".encode())

        def run_script(script: str, label: str, root: str | None = None,
                       extra: dict | None = None,
                       base: str | None = None,
                       main_extra: str = "",
                       main_only: str = "") -> tuple[bool, str]:
            target = root or fake_root
            path = os.path.join(tmp, f"install-{label}.sh")
            text = patch_for_local_run(script, target)
            if main_only:
                # 只跑指定的那几步 (不看装机全流程) —— [16] 要验的是"面板不可达时,
                # LuCI 那三件套会不会被写坏", 而整条装机命令在面板不可达时会先 die。
                # 同样注意 `}` 前那个分号 (少了它就是语法错, 脚本会什么都没做就退出)。
                only_cmd = main_only.strip().rstrip(";")
                text, n = re.subn(r'\nmain\(\) \{.*?\}\nmain "\$@"\n',
                                  f'\nmain() {{ {only_cmd}; }}\nmain "$@"\n', text, flags=re.S)
                assert n == 1, "没能把 main 换成要跑的那几步"
            if main_extra:
                # 演练默认停在"文件已落盘"(不装界面、不起服务)。需要哪一段就显式接上 ——
                # [16] 要验的就是界面里那一小段 (`luci_install`), 于是把它接进 main。
                # 注意那个分号: `{ ...; cmd }` 的 `}` 前面必须是 `;` 或换行, 否则 `}` 会被
                # 当成参数 (演练里真踩过 —— 脚本语法错, 于是"什么都没发生")。
                extra_cmd = main_extra.strip().rstrip(";")
                text = text.replace("install_zpcore; }", f"install_zpcore; {extra_cmd}; }}", 1)
                assert main_extra in text, "main_extra 没接上 (patch_for_local_run 的 main 拼法变了?)"
            if base:
                # 把脚本里的"面板地址"换成本机的一个慢管子 —— 复现"家宽到海外面板
                # 只有几十 KB/s"那条路 (见 Throttle)
                text = re.sub(r'^ZP_BASE="[^"]*"', f'ZP_BASE="{base}"', text,
                              count=1, flags=re.M)
            with open(path, "w") as fh:
                fh.write(text)
            # ZP_CORE_MIN_BYTES 与面板侧同名: 演练里那个假内核只有几百字节, 真机上
            # 65536 的下限是用来挡"面板返回的是一句话"的 (见 install_core)。
            # ZP_BTF_MIN_BYTES 同理: [13] 那一节的假 BTF 包也只有几百字节。
            env = {**os.environ, "ZP_CORE_MIN_BYTES": "16", "ZP_BTF_MIN_BYTES": "16",
                   **(extra or {})}
            proc = subprocess.run(["sh", path], capture_output=True, text=True, env=env)
            print(f"---- 安装输出 ({label}) ----")
            print(proc.stdout.strip())
            if proc.returncode:
                print(proc.stderr[-800:])
            # stdout + stderr: die/warn 的话都走 stderr, 断言要看得到
            return proc.returncode == 0, proc.stdout + proc.stderr

        def run_install(label: str, panel_=None, root: str | None = None,
                        extra: dict | None = None,
                        base: str | None = None,
                        main_extra: str = "",
                        main_only: str = "") -> tuple[bool, str]:
            panel_ = panel if panel_ is None else panel_
            code = panel_.pair_code(label)
            _, script, _ = panel_.req("GET", f"/c/{code}")
            return run_script(script, label, root=root, extra=extra, base=base,
                              main_extra=main_extra, main_only=main_only)

        print("\n[1] 首次安装")
        ok, out = run_install("first")
        check("安装脚本跑通", ok)
        check("内核经过 gzip 判定与解压后可执行", "内核就绪" in out, "Mihomo Meta" in out and "stub" in out)

        generated = os.path.join(fake_root, "config.yaml")
        config_text = open(generated, encoding="utf-8").read() if os.path.exists(generated) else ""
        # 这份配置必须与**这台机器探出来的数据面**一致: 建不出 tun 的机器不该拿到 tun 段
        # (带着它 mihomo 启动就失败)。演练机 (macOS) 没有 tun/nft/iptables, 所以这里
        # 走的正是"没探到任何一级"那条路 —— 它同样要能生成一份完整、诚实的配置。
        caps_1 = open(os.path.join(fake_root, "caps"), encoding="utf-8").read()
        chosen_1 = (re.search(r"^chosen=(\w+)$", caps_1, re.M) or [None, "?"])[1]
        if chosen_1 == "tun":
            check("生成路由器版配置 (tun + fake-ip)",
                  all(k in config_text for k in ("tun:", "fake-ip", "nameserver-policy")))
        else:
            check(f"数据面={chosen_1}: 配置不含 tun 段, 分流 / DNS 照旧齐全",
                  "tun:" not in config_text and "fake-ip" in config_text
                  and "nameserver-policy" in config_text, chosen_1)
        check("配置里透明代理端口与策略组都在 (与数据面无关)",
              "redir-port" in config_text and "tproxy-port" in config_text
              and "proxy-groups" in config_text)
        for name in ("device.json", "agent.sh", "initd", "initd-agent", "cli", "tproxy.nft"):
            check(f"生成 {name}", os.path.exists(os.path.join(fake_root, name)))
        # 生成的脚本 (agent / init / CLI) 必须真的能被 sh 解析 —— 它们是 heredoc 里
        # 写字写出来的, 外层脚本的 `sh -n` 看不到里面, 只有把文件拿出来才验得到。
        for name in ("agent.sh", "redirect.sh", "initd", "initd-agent", "cli"):
            path_ = os.path.join(fake_root, name)
            check(f"{name} 通过 sh -n (语法)",
                  os.path.exists(path_)
                  and subprocess.run(["sh", "-n", path_], capture_output=True).returncode == 0)
        caps_text = open(os.path.join(fake_root, "caps"), encoding="utf-8").read()
        check("caps 是 schema 2 (chosen / covered / why)",
              "schema=2" in caps_text and "chosen=" in caps_text and "covered=" in caps_text)
        # 性能那一半的现场判据也进了 caps: WAN 的实际 MTU 与转发卸载状态
        check("caps 记下了 WAN / tun 的 MTU 与转发卸载状态",
              "wan_mtu=" in caps_text and "tun_mtu=" in caps_text and "offload=" in caps_text,
              [ln for ln in caps_text.splitlines()
               if ln.startswith(("wan_mtu", "tun_mtu", "offload"))])

        # 分流数据库 (真机上这一步失败 = mihomo 去 GitHub 拉超时, 整份配置校验不过)
        for name in ("geoip.metadb", "geosite.dat"):
            check(f"分流数据库落到路由器 ({name})",
                  os.path.exists(os.path.join(fake_root, name)))
        check("geox-url 指向面板而不是 GitHub",
              "/c/geo/geosite.dat" in config_text and "github.com" not in config_text)
        check("有数据时配置带完整分流 (GEOIP,CN)", "GEOIP,CN" in config_text)
        # 版本号是落盘后 sed 替换的: 既不能残留占位符, 也不能把执行位弄丢 (演练抓到过)
        agent_text = open(os.path.join(fake_root, "agent.sh"), encoding="utf-8").read()
        cli_text = open(os.path.join(fake_root, "cli"), encoding="utf-8").read()
        if go:
            check("本地控制面从面板装到路由器并可执行",
                  "本地控制面就绪" in out
                  and os.access(os.path.join(fake_root, "zpcore"), os.X_OK))
        check("落盘的 agent / CLI 没有残留版本占位符",
              "__ZP_CLIENT_VERSION__" not in agent_text
              and "__ZP_CLIENT_VERSION__" not in cli_text)
        check("agent 与 CLI 仍然可执行 (替换之后要补 chmod)",
              os.access(os.path.join(fake_root, "agent.sh"), os.X_OK)
              and os.access(os.path.join(fake_root, "cli"), os.X_OK))

        import yaml
        profile = yaml.safe_load(config_text)
        check("配置可被 YAML 解析且含全部节点",
              isinstance(profile, dict) and len(profile.get("proxies", [])) == 5)

        print("\n[1b] 更新命令 (/c/install.sh, 不带配对码): 刷新数据, 但不许再多一台设备")
        _, upd_script, _ = http("GET", "/c/install.sh")
        ok_upd, upd_out = run_script(upd_script, "update")
        check("更新命令跑通", ok_upd and "分流数据库就绪" in upd_out)
        _, body, _ = http("GET", "/api/devices")
        check("更新不会在面板上多出设备 (配对码是一次性的, 不该拿它当更新入口)",
              len(json.loads(body)["devices"]["items"]) == 1)

        print("\n[2] 控制 agent 与面板对话")
        agent = open(os.path.join(fake_root, "agent.sh"), encoding="utf-8").read()
        agent = agent.replace("/etc/zeroproxy", fake_root).replace("/etc/init.d/zeroproxy", fake_root + "/initd")
        agent = agent.replace("SLEEP=15", "SLEEP=2")
        agent_path = os.path.join(fake_root, "agent-check.sh")
        with open(agent_path, "w") as fh:
            fh.write(agent)
        check("agent 语法正确", subprocess.run(["sh", "-n", agent_path]).returncode == 0)

        proc = subprocess.Popen(["sh", agent_path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        time.sleep(8)
        proc.kill()
        _, body, _ = http("GET", "/api/devices")
        device = json.loads(body)["devices"]["items"][0]
        check("agent 上报后设备显示在线", device["online"] is True)
        check("总开关默认开启且面板能看到期望状态", device["desired"] is True)
        # 面板上那张卡能一键打开路由器管理界面 (地址带界面令牌, 由 agent 上报) ——
        # 新用户因此不用回终端敲 zeroproxy ui 抄一条长地址
        check("agent 上报的管理界面地址进了面板",
              device.get("ui", "").startswith("http://") and "/cgi-bin/zeroproxy?k=" in device.get("ui", ""),
              device.get("ui", "")[:48])

        print("\n[2b] 面板给不出分流数据库时自动降级 (不留 geo 规则), 数据回来再自动恢复")
        for name in ("geoip.metadb", "geosite.dat"):
            os.remove(os.path.join(fake_root, name))
        degraded = subprocess.run(["sh", agent_path, "config"], capture_output=True, text=True)
        check("没有数据库时不再要 geo 规则",
              degraded.returncode == 0 and "GEOIP,CN" not in degraded.stdout
              and "GEOSITE," not in degraded.stdout)
        # 降级 ≠ 没有国内直连: 国内 App 那一层是纯域名规则, 不依赖数据库, 必须原样保留。
        # 少了它, 全屋流量 (微信 / 支付宝 / 公众号 / 小程序) 全部走节点。
        check("降级后仍保留国内 App 直连 (微信 / 支付宝 …)",
              "DOMAIN-SUFFIX,qq.com,🎯 全球直连" in degraded.stdout
              and "DOMAIN-SUFFIX,alipay.com,🎯 全球直连" in degraded.stdout)
        check("降级配置仍是完整的路由器配置 (策略组 + DNS 都在)",
              "proxy-groups:" in degraded.stdout and "fake-ip" in degraded.stdout)
        again = subprocess.run(["sh", agent_path, "geo"], capture_output=True, text=True)
        check("agent 能把数据自己取回来", again.returncode == 0
              and os.path.exists(os.path.join(fake_root, "geoip.metadb")))
        restored = subprocess.run(["sh", agent_path, "config"], capture_output=True, text=True)
        check("数据回来后又变回完整分流", "GEOIP,CN" in restored.stdout)

        print("\n[3] 加入第二台服务器 (面板 B) → 自动聚合成多个 provider")
        panel_b = panels[1]
        code_b = panel_b.pair_code("第二台")
        cli = os.path.join(fake_root, "cli-check.sh")
        with open(cli, "w") as fh:
            fh.write(
                open(os.path.join(fake_root, "cli"), encoding="utf-8").read()
                .replace("/etc/zeroproxy", fake_root)
                # 本机没有 procd: 把 init 调用换成 true (macOS 自带的 /etc/rc.common 被
                # 当成脚本执行时会真的去跑 launchd 那套, 演练会挂住)
                .replace("/etc/init.d/zeroproxy", "true")
            )
        out = subprocess.run(
            ["sh", cli, "add", f"{panel_b.base}/c/{code_b}"], capture_output=True, text=True
        )
        print(out.stdout.strip() or out.stderr[-400:])
        if "配置更新失败" in out.stdout:
            dbg = subprocess.run(["sh", os.path.join(fake_root, "agent.sh"), "config"],
                                 capture_output=True, text=True)
            print("--- agent config 调试 ---")
            print("rc:", dbg.returncode)
            print("stderr:", dbg.stderr[-600:])
            print("stdout 前几行:", "\n".join(dbg.stdout.splitlines()[:6]))
        merged = open(os.path.join(fake_root, "config.yaml"), encoding="utf-8").read()
        merged_yaml = yaml.safe_load(merged)
        check("第二台服务器接入成功", out.returncode == 0 and "已接入" in out.stdout)
        check("配置改成多 provider 模式",
              "proxy-providers:" in merged and "proxies:" not in merged.split("proxy-groups")[0],
              f"providers={len(merged_yaml.get('proxy-providers', {}))}")
        check("两个 provider 都在", len(merged_yaml.get("proxy-providers", {})) == 2)
        sel = [g for g in merged_yaml["proxy-groups"] if g["name"] == "🚀 节点选择"][0]
        check("节点选择的第一个成员是自动选择 (不是 DIRECT)",
              sel["proxies"][0] == "♻️ 自动选择" and sel["proxies"][-1] == "DIRECT",
              str(sel["proxies"]))
        auto = [g for g in merged_yaml["proxy-groups"] if g["name"] == "♻️ 自动选择"][0]
        check("组的 use 填上了两个 provider 键", len(auto.get("use", [])) == 2, str(auto.get("use")))
        check("节点不再内联 (交给 provider 拉)", "proxies" not in merged_yaml)

        # agent 要同时喂两台: 只喂第一台的话, 第二台面板上永远显示离线 (真机反馈)
        proc = subprocess.Popen(["sh", agent_path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        time.sleep(8)
        proc.kill()
        for p_, label in ((panels[0], "第一台"), (panels[1], "第二台")):
            _, body, _ = p_.req("GET", "/api/devices")
            items = json.loads(body)["devices"]["items"]
            check(f"两台服务器都收到心跳 ({label})",
                  bool(items) and items[0]["online"] is True,
                  f"{len(items)} 台设备")

        out = subprocess.run(["sh", cli, "servers"], capture_output=True, text=True)
        check("zeroproxy servers 列出两台", out.stdout.count("127.0.0.") == 2, out.stdout.strip().splitlines()[0] if out.stdout else "")

        key_b = re.sub(r"[^A-Za-z0-9]", "_", panel_b.base.split("://", 1)[-1])[:32]
        out = subprocess.run(["sh", cli, "drop", key_b], capture_output=True, text=True)
        after = yaml.safe_load(open(os.path.join(fake_root, "config.yaml"), encoding="utf-8").read())
        # 剩一台时退回"面板给整份配置"的老路径 (内联节点), 不再挂 provider —— 这条路径
        # 是真机验证过的, 没必要为了统一形式让它也绕一圈 provider
        check("drop 之后退回单服务器路径 (内联节点)",
              "proxy-providers" not in after and len(after.get("proxies", [])) == 5,
              out.stdout.strip()[:60])

        print("\n[4] 凭据在面板上失效后重跑")
        _, body, _ = http("GET", "/api/devices")
        device = json.loads(body)["devices"]["items"][0]
        old_id = device["id"]
        http("DELETE", f"/api/devices/{old_id}")
        ok, out = run_install("rejoin")
        _, body, _ = http("GET", "/api/devices")
        items = json.loads(body)["devices"]["items"]
        check("旧凭据被拒后自动重新接入", ok and "重新接入" in out, f"旧 {old_id}")
        check("面板上换成一台新设备 (没有卡死在旧凭据)",
              len(items) == 1 and items[0]["id"] != old_id, items[0]["id"] if items else "无")

        print("\n[4b] 只是丢包时**不许**判成\"凭据被拒\": 不重新配对, 也不撒谎")
        # 真机 8.68 (21.02 那台) 的样子: 面板整体是好的 (脚本 / 内核 / 分流数据都取到),
        # 只有"拉配置"那一段一直在丢包 —— 四次超时。老代码把它判成"面板拒绝了这台设备的
        # 凭据", 于是拿同一个配对码又配了一次: 面板上**多出一台设备**, 新凭据随后又被同一个
        # 丢包卡住, 最后丢给用户一句"请回面板确认已有可用节点"。这里就复现这一段。
        drop = Throttle(panels[0].base)
        drop.hang = ("/c/sub",)          # 只有配置那一段会一直不回话
        # 用一份**已经接入过**的机器副本, 并把凭据里的 base 换成压过的地址 —— 这样安装会走
        # "沿用原有凭据"那条路 (不配对), 面板上就不会有"合法的新设备"来干扰计数:
        # 真机 8.68 上多出来的那台, 正是**重新配对**凭空造的。
        cfg_root = os.path.join(tmp, "cfg-drop-root")
        shutil.copytree(fake_root, cfg_root, dirs_exist_ok=True)
        # 两处都要改: pair() 是拿 device.json 里的 base 跟本次的 ZP_BASE 比 (不一样就判成
        # "换了面板、直接重新配对"), 而配置那一侧读的是 servers/*.json。
        cred_files = [os.path.join(cfg_root, "device.json")] + [
            os.path.join(cfg_root, "servers", n) for n in os.listdir(os.path.join(cfg_root, "servers"))
        ]
        for cpath in cred_files:
            with open(cpath, encoding="utf-8") as fh:
                saved = json.load(fh)
            saved["base"] = drop.base
            with open(cpath, "w", encoding="utf-8") as fh:
                json.dump(saved, fh)
        _, body, _ = panels[0].req("GET", "/api/devices")
        n_before = len(json.loads(body)["devices"]["items"])
        ok_drop, out_drop = run_install("cfg-drop", root=cfg_root, base=drop.base)
        check("走的是\"沿用原有凭据\"那条路 (没有重新配对的动作)",
              "已接入过" in out_drop and "已接入:" not in out_drop,
              [ln.strip() for ln in out_drop.splitlines() if "接入" in ln][:2])
        check("拉配置被丢包卡住 → 装不上 (如实失败)", not ok_drop,
              [ln.strip() for ln in out_drop.splitlines() if "安装失败" in ln][:1])
        check("说的是\"面板暂时联系不上\", 不是\"拒绝了凭据\"",
              "面板暂时联系不上" in out_drop and "拒绝了这台设备的凭据" not in out_drop,
              [ln.strip() for ln in out_drop.splitlines() if "凭据" in ln or "联系不上" in ln][:2])
        # 8.67/8.68 两轮真机都把"拉配置失败"一律标成"链路丢包", 于是超时 / DNS / TLS /
        # 面板明确拒绝 这些完全不同的原因长得一模一样, 只能靠猜。这里必须说出是哪一类。
        check("失败信息要说清是哪一类 (不许一律说\"链路丢包\")",
              "收到不完整的数据" in out_drop or "超时" in out_drop or "连接被中断" in out_drop,
              [ln.strip() for ln in out_drop.splitlines() if "面板暂时联系不上" in ln][:1])
        check("**没有**去重新配对 (输出里不该出现\"重新接入\")",
              "重新接入" not in out_drop,
              [ln.strip() for ln in out_drop.splitlines() if "接入" in ln][:2])
        _, body, _ = panels[0].req("GET", "/api/devices")
        n_after = len(json.loads(body)["devices"]["items"])
        check("面板上的设备数没变 (不会平白多出一台)", n_after == n_before,
              f"{n_before} → {n_after}")
        drop.close()

        print("\n[5] 空间预检: 只有真要装内核时才该卡 90 MB"
              " (真机: 首次失败的安装留下内核, 重跑时只剩 89 MB 被判空间不足)")
        # 伪造一个 df: 剩 89 MB (91264 KB), 比首次安装的 90 MB 线低一点 —— 真机就是这个数
        fake_bin = os.path.join(tmp, "fakebin")
        os.makedirs(fake_bin, exist_ok=True)
        with open(os.path.join(fake_bin, "df"), "w") as fh:
            fh.write(
                "#!/bin/sh\n"
                "echo 'Filesystem 1K-blocks Used Available Capacity Mounted on'\n"
                "echo 'overlay 200000 110000 91264 55% /'\n"
            )
        os.chmod(os.path.join(fake_bin, "df"), 0o755)

        def run_low_space(root: str) -> subprocess.CompletedProcess:
            code_ = panel.pair_code("space")
            _, script_, _ = http("GET", f"/c/{code_}")
            path_ = os.path.join(tmp, "space.sh")
            with open(path_, "w") as fh:
                fh.write(patch_for_local_run(script_, root))
            env_ = {**os.environ, "PATH": fake_bin + ":" + os.environ.get("PATH", "")}
            return subprocess.run(["sh", path_], capture_output=True, text=True, env=env_)

        space_root = os.path.join(tmp, "space-root")
        fresh = run_low_space(space_root)
        check("还没有内核时 89 MB 会被挡下, 并说清要多少",
              fresh.returncode != 0 and "可用空间不足" in fresh.stdout + fresh.stderr)
        # 真机上 /etc/zeroproxy 是上一次失败的安装留下的 (里面有内核), 这里补上目录与内核
        os.makedirs(space_root, exist_ok=True)
        with open(os.path.join(space_root, "mihomo"), "w") as fh:
            fh.write('#!/bin/sh\n[ "$1" = "-v" ] && echo "stub"\n')
        os.chmod(os.path.join(space_root, "mihomo"), 0o755)
        again_space = run_low_space(space_root)
        check("已经有可用的内核时, 同样的剩余空间直接放行",
              "可用空间不足" not in again_space.stdout + again_space.stderr,
              again_space.stdout.splitlines()[-1][:60] if again_space.stdout else "")

        # [6] 面板还没准备好内核 —— 真机上这一步的表现就是"卡在下载代理内核上不动"
        print("\n[6] 面板还没准备好内核 (真机: 卡在 '下载代理内核' 上不动)")
        stall = StallUpstream()
        slow = Panel(PORT + 2, os.path.join(tmp, "home-c"), "C", extra_env={
            # 一台"到上游不通"的面板: 镜像指向一个只握手、不说话的本地上游, 面板的
            # 后台取内核会一直停在"正在下载"上直到总时限 —— 正是真机那台面板的处境。
            "ZP_CORE_MIRRORS": f"http://127.0.0.1:{stall.port}/{{url}}",
            "ZP_CORE_SOURCE_TIMEOUT": "10",
            "ZP_CORE_DEADLINE": "6",
        })
        panels.append(slow)
        try:
            if not slow.wait():
                print(f"面板 C 没起来:\n" + slow.log[-2000:])
                return 1
            # 域名用 127.0.0.1: 面板只绑回环, 生成出来的基址必须是它真能连上的那个
            slow.configure("127.0.0.1")
            # 分流数据也预置好: 这一节要是让面板真去 GitHub 取 4 MB, 演练就不再是
            # 离线可跑的了 (而且慢)。
            geo_cache = os.path.join(slow.home, "data", "client", "geo")
            os.makedirs(geo_cache, exist_ok=True)
            for name in ("geoip.metadb", "geosite.dat"):
                with open(os.path.join(geo_cache, name), "wb") as fh:
                    fh.write(f"fake-geo-C-{name}".encode())

            started = time.time()
            status, body, headers = slow.req_raw("GET", "/c/bin/arm64")
            elapsed = time.time() - started
            check("内核没缓存时 /c/bin 立刻回话, 不再把请求挂住", elapsed < 3,
                  f"{elapsed:.2f}s")
            check("回的是 503 + Retry-After (路由器据此重试)",
                  status == 503 and headers.get("retry-after") == "5", f"HTTP {status}")
            check("正文是一句人话, 不是空响应或 HTML", "面板" in body, body.strip()[:40])
            st = json.loads(slow.req_raw("GET", "/c/core/status?arch=arm64")[1])
            check("面板同时在后台取 (状态可见, 不是回一句就走)", st["state"] == "downloading",
                  st["state"])

            # 路由器端: 面板取不到时要有界地失败, 而不是让用户对着一行不动的输出猜
            fresh_root = os.path.join(tmp, "fresh-root")
            ok_slow, slow_out = run_install("no-core", panel_=slow, root=fresh_root,
                                            extra={"ZP_CORE_WAIT": "9",
                                                   "ZP_CORE_MIRROR_BUDGET": "5"})
            check("面板取不到上游时, 安装命令有界地失败 (不是卡死)",
                  (not ok_slow) and "内核下载失败" in slow_out)
            check("等待期间打的是面板的真实进度", "面板正在取内核" in slow_out)
            check("失败时给出可执行的下一步",
                  "准备内核" in slow_out and "data/client/cores" in slow_out)

            # 面板把内核准备好之后, 同一条安装命令一次装完 (先准备再发命令那条路)
            with gzip.open(os.path.join(slow.home, "data", "client", "cores",
                                        f"mihomo-arm64-{router_client.CORE_VERSION}.gz"), "wb") as fh:
                fh.write(stub.encode())
            ok_ready, ready_out = run_install("core-ready", panel_=slow, root=fresh_root)
            check("面板准备好内核后, 同一条命令装完", ok_ready and "内核就绪" in ready_out)
        finally:
            stall.close()

        # [7] 面板直传太慢 → 自动改走直连镜像 (真机: 国内家宽到海外面板只有几十 KB/s)
        print("\n[7] 面板直传太慢时改走直连镜像")
        # 一份"压不小"的假内核: 脚本本体照旧 (解压后真的能跑), 后面缀一大段随机 hex
        # 注释 —— 于是 gzip 之后仍有上百 KB, "慢管子"才真的慢。全是 x 的话只压出几百
        # 字节, 一节就传完, 根本测不到"太慢就换路"这条逻辑。
        big_stub = stub + "# " + os.urandom(160000).hex() + "\n"
        blob = gzip.compress(big_stub.encode())
        mirror = FakeMirror(blob)
        slow_panel = Panel(PORT + 3, os.path.join(tmp, "home-d"), "D", extra_env={
            # 面板自己从**本地镜像**取 (快) —— 于是它有缓存可以直传;
            # 直传那一段会被下面的慢管子拖成十几 KB/s。
            "ZP_CORE_MIRRORS": mirror.base,
        })
        panels.append(slow_panel)
        throttle = None
        try:
            if not slow_panel.wait():
                print(f"面板 D 没起来:\n" + slow_panel.log[-2000:])
                return 1
            slow_panel.configure("127.0.0.1")
            geo_cache = os.path.join(slow_panel.home, "data", "client", "geo")
            os.makedirs(geo_cache, exist_ok=True)
            for name in ("geoip.metadb", "geosite.dat"):
                with open(os.path.join(geo_cache, name), "wb") as fh:
                    fh.write(f"fake-geo-D-{name}".encode())
            # 先让面板把自己那份取好 (真机上就是「准备内核」那一步)
            slow_panel.req_raw("GET", "/c/bin/arm64")      # 触发面板后台取 (这次是 503)
            ready = False
            for _ in range(60):
                payload = json.loads(slow_panel.req_raw("GET", "/c/core/status?arch=arm64")[1])
                if payload["state"] == "ready":
                    ready = True
                    break
                time.sleep(0.5)
            check("面板能先把自己那份内核准备好", ready,
                  f"{(payload or {}).get('state')} / {(payload or {}).get('size')} 字节")

            # 慢管子: 4 KB / 0.3 秒 ≈ 13 KB/s —— 200 KB 要十几秒
            throttle = Throttle(slow_panel.base, chunk=4096, delay=0.3)
            ok_slow, out_slow = run_install(
                "slow-panel", panel_=slow_panel, root=os.path.join(tmp, "slow-root"),
                base=throttle.base,
                extra={"ZP_CORE_PANEL_BUDGET": "3", "ZP_CORE_MIRROR_BUDGET": "60",
                       "ZP_CORE_TOTAL_BUDGET": "300"},
            )
            check("面板直传太慢时, 安装脚本自己换到直连镜像", ok_slow,
                  out_slow.strip().splitlines()[-1][:60] if out_slow.strip() else "")
            check("换路时说清了原因与实测速率",
                  "面板直传太慢" in out_slow and "KB/s" in out_slow)
            check("下载过程一直有速率可看 (不再是一行不动的输出)", out_slow.count("KB/s") >= 2)
            check("用的是面板给的那张镜像表", "直连镜像完成" in out_slow)
        finally:
            if throttle is not None:
                throttle.close()
            mirror.close()

        # [8] 数据面阶梯: 一台"没有 tun、没有 nf_tables、只有 iptables"的机器
        print("\n[8] 数据面阶梯: 只能走 iptables REDIRECT 的机器 (原厂 21.02 / 内核 5.4)")
        # 这正是 README 8.45 那台真机: /dev/net/tun 在但建不出设备, nft 命令在但规则
        # 下不去。以前它只能得到一句"透明代理未生效"; 现在应该自动落到 L3 —— 局域网 TCP
        # 被接管, 而且**面板那边也不再给 tun 段** (带着它 mihomo 启动就失败)。
        fake_tools = os.path.join(tmp, "faketools")
        os.makedirs(fake_tools, exist_ok=True)

        def _tool(name: str, body: str) -> None:
            tool_path = os.path.join(fake_tools, name)
            with open(tool_path, "w") as fh:
                fh.write("#!/bin/sh\n" + body)
            os.chmod(tool_path, 0o755)

        # nft: 命令在, 但往下加规则一律失败 (= 内核里没有 nf_tables)
        _tool("nft", 'echo "Error: Could not process rule: No such file or directory" >&2\n'
                     "exit 1\n")
        # ip: 建不出 tun 设备 (原厂 5.4 那台的表现)
        _tool("ip", 'case "$1 $2" in\n'
                    '  "tuntap add") echo "ip: ioctl(TUNSETIFF): Operation not supported" >&2; exit 1 ;;\n'
                    '  "link show") exit 1 ;;\n'
                    "esac\nexit 0\n")
        # iptables: 能建链、能加 REDIRECT 规则; 并且**带一份真实的计数器表** ——
        # `zeroproxy doctor` 的"规则上真的有流量吗"就是解析它 (接口名写错时规则照样装得上,
        # 却一个包都不命中, 这是唯一能证明"真的接管了"的现场证据)。
        _tool("iptables", 'case "$*" in\n'
                          '  *"-L zp_router -v -n"*)\n'
                          "    echo 'Chain zp_router (1 references)'\n"
                          "    echo ' pkts bytes target     prot opt in     out     source               destination'\n"
                          "    echo '   12   720 RETURN     all  --  *      *       0.0.0.0/8            0.0.0.0/0'\n"
                          "    echo '    3   180 REDIRECT   udp  --  *      *       0.0.0.0/0            0.0.0.0/0  udp dpt:53 redir ports 7874'\n"
                          "    echo '   40  2400 REDIRECT   tcp  --  *      *       0.0.0.0/0            0.0.0.0/0  redir ports 7892'\n"
                          "    exit 0 ;;\n"
                          "esac\nexit 0\n")

        r_root = os.path.join(tmp, "redirect-root")
        ok_r, out_r = run_install(
            "redirect", root=r_root,
            extra={"PATH": fake_tools + os.pathsep + os.environ.get("PATH", "")},
        )
        check("只有 iptables 可用时, 阶梯选中 redirect",
              ok_r and "iptables REDIRECT" in out_r,
              [ln.strip() for ln in out_r.splitlines() if "数据面" in ln][:1])
        r_caps = open(os.path.join(r_root, "caps"), encoding="utf-8").read()
        check("caps 记下选择与覆盖范围 (chosen=redirect / covered=lan_tcp)",
              "chosen=redirect" in r_caps and "covered=lan_tcp" in r_caps)
        check("caps 记下别的几级为什么不行 (面板与 CLI 都读它)",
              "why.tun=" in r_caps and "why.tproxy=" in r_caps,
              [ln for ln in r_caps.splitlines() if ln.startswith("why.")][:2])
        redirect_sh = os.path.join(r_root, "redirect.sh")
        check("redirect 规则文件落盘且语法正确",
              os.path.exists(redirect_sh)
              and subprocess.run(["sh", "-n", redirect_sh], capture_output=True).returncode == 0)
        r_text = open(redirect_sh, encoding="utf-8").read() if os.path.exists(redirect_sh) else ""
        check("redirect 只从局域网接口跳 (绝不接管 WAN 入站)",
              "PREROUTING -i" in r_text and "br-lan" in r_text)
        r_cfg = yaml.safe_load(open(os.path.join(r_root, "config.yaml"), encoding="utf-8").read())
        check("redirect 设备的配置里没有 tun 段 (带着它内核起不来)", "tun" not in r_cfg)
        check("redirect 设备仍拿到 DNS / fake-ip / redir-port",
              r_cfg["dns"]["enhanced-mode"] == "fake-ip" and r_cfg["redir-port"] == 7892)
        # IPv6: 这台"机器"上没有 ip6tables —— 必须如实记成未接管, 而不是假装接管了
        check("没有 ip6tables 时 IPv6 如实记为未接管 (caps.ipv6=0 + 原因)",
              "ipv6=0" in r_caps and "why.ipv6=" in r_caps
              and [ln for ln in r_caps.splitlines() if ln.startswith("why.ipv6=")][0].split("=", 1)[1] != "",
              [ln for ln in r_caps.splitlines() if ln.startswith("why.ipv6=")][:1])
        check("IPv6 未接管时不给双栈配置 (不给内核管不了的东西)",
              r_cfg["ipv6"] is False and r_cfg["dns"]["ipv6"] is False)

        # 真机体检: `zeroproxy doctor` 必须在真机上给出可核对的证据, 而这里验它的判据
        r_cli = os.path.join(r_root, "cli-doctor.sh")
        with open(r_cli, "w") as fh:
            fh.write(open(os.path.join(r_root, "cli"), encoding="utf-8").read()
                     .replace("/etc/init.d/zeroproxy", "true"))
        doctor = subprocess.run(
            ["sh", r_cli, "doctor"], capture_output=True, text=True,
            env={**os.environ, "PATH": fake_tools + os.pathsep + os.environ.get("PATH", "")},
        ).stdout
        check("doctor: 现场与 caps 一致时说'数据面真的在'",
              "数据面真的在（redirect）" in doctor,
              [ln.strip() for ln in doctor.splitlines() if "现场" in ln][:1])
        check("doctor: 从规则计数器算出真的有多少包经过 (12+3+40=55)",
              "55 个包经过" in doctor,
              [ln.strip() for ln in doctor.splitlines() if "包经过" in ln][:1])
        # DNS 那一行**不许**再写成"设备可能没把路由器当 DNS": 局域网设备查的是路由器自己的
        # dnsmasq (本机服务), 计数为 0 本来就正常 —— 真机上它打着"!" 而代理一切正常。
        check("doctor: DNS 那一行不再把'计数为 0'当成故障",
              "按域名分流" in doctor and "不是故障" in doctor
              and "设备可能没把路由器当 DNS" not in doctor,
              [ln.strip() for ln in doctor.splitlines() if "DNS" in ln or "域名分流" in ln][:2])
        # 入口连通性: 面板与内核都只看"这一条连接成没成", 看不到比例 —— 真机上"入口 IP
        # 被按比例丢包"就是这么被漏掉的 (七项全绿, 只报了一句方向相反的"面板不可达")。
        # 演练机上的入口端口 (127.0.0.1:8443 这类) 是关着的 → 必须**如实报 ✗**,
        # 不许因为"探测不出来"就当正常。
        entry_lines = [ln.strip() for ln in doctor.splitlines()
                       if ("次被拒" in ln or "次超时" in ln or "全部成功" in ln)]
        check("doctor: 逐条报出入口的新建连接成功率, 连不上的入口如实判 ✗",
              "入口连通性" in doctor and bool(entry_lines)
              and all("✗" in ln for ln in entry_lines),
              entry_lines[:2])

        # [9] 健康机器: tun / nft 都在的普通 OpenWrt → 阶梯应当仍然选 L1
        print("\n[9] 健康机器 (tun + nftables 都在): 阶梯选 tun, 行为与以前一致")
        good = os.path.join(tmp, "goodtools")
        os.makedirs(good, exist_ok=True)

        def _gtool(name: str, body: str) -> None:
            tool_path = os.path.join(good, name)
            with open(tool_path, "w") as fh:
                fh.write("#!/bin/sh\n" + body)
            os.chmod(tool_path, 0o755)

        _gtool("nft", "exit 0\n")
        _gtool("iptables", "exit 0\n")
        _gtool("ip", "exit 0\n")
        g_root = os.path.join(tmp, "good-root")
        ok_g, out_g = run_install("good", root=g_root, extra={
            "PATH": good + os.pathsep + os.environ.get("PATH", ""),
            # macOS 上没有 /dev/net/tun; 借 /dev/null (真的字符设备) 表示"这台有 tun"。
            # 探测里真正作数的是后面那次"建一个设备再删掉"。
            "ZP_TUN_DEV": "/dev/null",
        })
        check("有 tun 的机器仍然走 L1 (tun)", ok_g and "数据面: TUN" in out_g,
              [ln.strip() for ln in out_g.splitlines() if "数据面" in ln][:1])
        g_text = open(os.path.join(g_root, "caps"), encoding="utf-8").read()
        check("caps: chosen=tun / covered=full",
              "chosen=tun" in g_text and "covered=full" in g_text)
        # tun 这一档天然能覆盖 v6 (mihomo 给 tun 分配 v6 地址, auto-route 一并管)
        check("tun 这一档 IPv6 一并接管 (caps.ipv6=1)", "ipv6=1" in g_text)
        g_cfg = yaml.safe_load(open(os.path.join(g_root, "config.yaml"), encoding="utf-8").read())
        check("tun 配置里 auto-route 与 fake-ip 都在 (默认行为不变)",
              g_cfg["tun"]["auto-route"] is True
              and g_cfg["dns"]["enhanced-mode"] == "fake-ip")
        check("能接管 v6 时配置是双栈 (顶层 ipv6 + dns.ipv6 同时开)",
              g_cfg["ipv6"] is True and g_cfg["dns"]["ipv6"] is True)
        # 同一份 doctor 在 tun 机器上: 现场一致, 但本机没有流量 (演练机没有局域网) ——
        # 这时**不能**说"已接管并正常工作", 只能说"规则在, 还没有流量经过"。
        g_cli = os.path.join(g_root, "cli-doctor.sh")
        with open(g_cli, "w") as fh:
            fh.write(open(os.path.join(g_root, "cli"), encoding="utf-8").read()
                     .replace("/etc/init.d/zeroproxy", "true"))
        g_doctor = subprocess.run(
            ["sh", g_cli, "doctor"], capture_output=True, text=True,
            env={**os.environ, "PATH": good + os.pathsep + os.environ.get("PATH", "")},
        ).stdout
        check("doctor: 没有流量时说'还没有', 不谎报已正常工作",
              "数据面真的在（tun）" in g_doctor and "还没有流量经过" in g_doctor,
              [ln.strip() for ln in g_doctor.splitlines() if "流量" in ln][:1])

        # [10] 本地控制面 (zpcore): 自带的界面服务 —— "界面能不能打开"从此与固件无关
        if go:
            print("\n[10] 本地控制面 zpcore: 自己起界面服务 (不依赖固件 Web 服务器)")
            zpcore_bin = os.path.join(fake_root, "zpcore")
            # 装上去的那一份必须**自报面板要的那一版**。真机上它是 1.0.0 而面板在发 1.1.1 ——
            # 源码里写死过一个版本号, 排查时只能靠"响应里有没有某个字段"反推装的是哪一版。
            zver = subprocess.run([zpcore_bin, "version"], capture_output=True, text=True).stdout.strip()
            check("装上的 zpcore 自报的版本 == 面板要的那一版",
                  zver == f"zpcore {router_client.AGENT_VERSION}",
                  f"{zver!r} vs zpcore {router_client.AGENT_VERSION}")
            # 界面文件由 install_ui 落盘; 演练的 main 停在 write_files, 这里按同一份内容补上
            ui_dir = os.path.join(fake_root, "www", "zeroproxy")
            os.makedirs(ui_dir, exist_ok=True)
            for ui_name in ("index.html", "app.js"):
                _, ui_body, _ = http("GET", f"/c/ui/{ui_name}")
                with open(os.path.join(ui_dir, ui_name), "w") as fh:
                    fh.write(ui_body)
            token = open(os.path.join(fake_root, "ui.token"), encoding="utf-8").read().strip()
            zport = PORT + 20
            zproc = subprocess.Popen(
                [zpcore_bin, "serve", "--dir", fake_root, "--bind", "127.0.0.1",
                 "--port", str(zport), "--cli", os.path.join(fake_root, "cli"),
                 "--init", os.path.join(fake_root, "initd")],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            zbase = f"http://127.0.0.1:{zport}"
            try:
                ready = False
                for _ in range(40):
                    try:
                        with urllib.request.urlopen(zbase + "/", timeout=1) as resp:
                            if b"<title>" in resp.read():
                                ready = True
                                break
                    except Exception:
                        time.sleep(0.25)
                check("zpcore 起得来并把页面发出来 (匿名可读)", ready)

                def zcall(query: str, method: str = "GET", payload=None):
                    req = urllib.request.Request(zbase + "/cgi-bin/zeroproxy" + query, method=method)
                    if payload is not None:
                        req.add_header("Content-Type", "application/json")
                        req.data = json.dumps(payload).encode()
                    try:
                        with urllib.request.urlopen(req, timeout=15) as resp:
                            return resp.status, resp.read().decode()
                    except urllib.error.HTTPError as exc:
                        return exc.code, exc.read().decode()

                status_code, _ = zcall("?a=status")
                check("未带令牌的数据接口一律 403", status_code == 403, status_code)
                status_code, _ = zcall("?a=status&k=wrong")
                check("令牌不对也是 403", status_code == 403, status_code)
                status_code, zbody = zcall(f"?a=status&k={token}")
                zdata = json.loads(zbody)
                check("status 契约与原 cgi 一致 (含新的 mode / covered)",
                      status_code == 200 and zdata.get("ok") is True
                      and "mode" in zdata and "covered" in zdata, zbody.strip()[:80])
                check("status 把服务器清单也带上了", len(zdata.get("servers", [])) >= 1,
                      str(zdata.get("servers"))[:80])
                status_code, zbody = zcall(f"?a=toggle&k={token}", "POST", {"on": True})
                zmsg = json.loads(zbody)
                check("手动动作转发给 CLI 执行 (一处实现, 两个入口)",
                      status_code == 200 and zmsg.get("ok") is True
                      and "已请求面板" in zmsg.get("message", ""), zbody.strip()[:80])
                _, zbody = zcall(f"?a=add&k={token}", "POST", {"url": "ftp://x"})
                check("非法链接在进 CLI 之前就被挡下",
                      json.loads(zbody).get("ok") is False, zbody.strip()[:60])
            finally:
                zproc.terminate()
                try:
                    zproc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    zproc.kill()

            # 绝不把管理界面挂到 WAN 上: 不是局域网地址就拒绝启动
            wan = subprocess.run(
                [zpcore_bin, "serve", "--dir", fake_root, "--bind", "0.0.0.0",
                 "--port", str(zport + 1)],
                capture_output=True, text=True,
            )
            check("拒绝绑 0.0.0.0 (管理界面不该挂到 WAN 上)",
                  wan.returncode != 0 and "拒绝绑定" in (wan.stdout + wan.stderr),
                  (wan.stdout + wan.stderr).strip()[:80])
        else:
            print("\n[10] 本机没有 Go, 跳过本地控制面那一节 "
                  "(面板发不出这一档时装机本来就会退回原来的界面路径)")

        # [11] 本机自治: 面板不可达时的开/关, 以及 revert 的逐条比对
        print("\n[11] 本机覆盖 (面板不可达也能开关) 与 revert 的逐条比对")
        check("装机时拍了防火墙 / 策略路由快照",
              os.path.exists(os.path.join(fake_root, "baseline", "taken_at"))
              and os.path.exists(os.path.join(fake_root, "baseline", "nft.txt"))
              and os.path.exists(os.path.join(fake_root, "baseline", "ip-rule.txt")))

        # 面板答得上时, on|off 仍然只走面板 (它才是唯一事实来源), 并且顺手清掉本机覆盖
        open(os.path.join(fake_root, "local.override"), "w").write("off\n")
        cli_plain = os.path.join(fake_root, "cli-plain.sh")
        with open(cli_plain, "w") as fh:
            fh.write(open(os.path.join(fake_root, "cli"), encoding="utf-8").read()
                     .replace("/etc/init.d/zeroproxy", "true"))
        out = subprocess.run(["sh", cli_plain, "on"], capture_output=True, text=True)
        check("面板可达时 on 仍然走面板, 并清掉本机覆盖",
              "已请求面板" in out.stdout
              and not os.path.exists(os.path.join(fake_root, "local.override")),
              out.stdout.strip()[:70])

        # 面板不可达时, on|off 必须落到本机覆盖并**立刻生效**。
        # "不可达"用**端口 1** 来模拟: 连接立刻被拒 (不像黑洞 IP 那样把 curl 的 -m 20
        # 挂满, 那样测的就变成超时了), 而且服务器清单本身还在 —— 用户看到的就是这台
        # 路由器"接了一台, 但那台联系不上"。
        servers_dir = os.path.join(fake_root, "servers")
        saved = {n: open(os.path.join(servers_dir, n), encoding="utf-8").read()
                 for n in os.listdir(servers_dir)}
        for n in saved:
            with open(os.path.join(servers_dir, n), "w") as fh:
                fh.write(saved[n].replace(f"127.0.0.1:{PORT}", "127.0.0.1:1"))
        open(os.path.join(fake_root, "core.up"), "w").close()
        out = subprocess.run(["sh", cli_plain, "off"], capture_output=True, text=True)
        check("面板不可达时 off 落到本机覆盖并立即生效",
              "面板不可达" in out.stdout
              and open(os.path.join(fake_root, "local.override"), encoding="utf-8").read().strip() == "off"
              and not os.path.exists(os.path.join(fake_root, "core.up")),
              out.stdout.strip().splitlines()[0][:70] if out.stdout.strip() else "")

        # agent 一台面板都联系不上时, 仍然必须执行本机覆盖 (这是它唯一的例外)
        open(os.path.join(fake_root, "core.up"), "w").close()
        proc = subprocess.Popen(["sh", agent_path], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True)
        time.sleep(5)
        proc.kill()
        offline_log = proc.stdout.read() if proc.stdout else ""
        check("面板全不可达时 agent 仍执行本机覆盖",
              not os.path.exists(os.path.join(fake_root, "core.up")), offline_log[-160:])
        for n in saved:
            with open(os.path.join(servers_dir, n), "w") as fh:
                fh.write(saved[n])
        # 面板回来了: 心跳把"本机覆盖=off"如实报上去 (卡片上会写「本机覆盖」而不是「同步中」)
        # 收进文件而不是管道: `sh -x` 的 trace 里带着中文, 进程被 kill 时管道里可能是
        # 截断的多字节字符, 直接 read() 会 UnicodeDecodeError。
        trace_path = os.path.join(tmp, "agent-online-trace.log")
        with open(trace_path, "w") as trace:
            proc = subprocess.Popen(["sh", "-x", agent_path], stdout=trace, stderr=subprocess.STDOUT)
            time.sleep(5)
            proc.kill()
        online_log = open(trace_path, encoding="utf-8", errors="replace").read()
        _, body, _ = http("GET", "/api/devices")
        # 按**设备 id** 取这一台的记录: 演练里每一节都配一次对, 面板上会留下好几台
        # (各用各的 root), items[0] 只是"最新创建的那一台", 不是我们在说的这一台。
        items = json.loads(body)["devices"]["items"]
        current_id = ""
        for n in os.listdir(servers_dir):
            with open(os.path.join(servers_dir, n), encoding="utf-8") as fh:
                found = re.search(r'"id"\s*:\s*"([^"]+)"', fh.read())
            if found:
                current_id = found.group(1)
        item = next((d for d in items if d.get("id") == current_id), items[0])
        check("本机覆盖随心跳到了面板 (卡片上会写「本机覆盖」)",
              str(item.get("report", {}).get("override", "")) == "off",
              f"{current_id} · {item.get('report')}")
        # 一级都没接管时 (这台模拟机就是), why 必须带上**每一级**的原因。
        # 真机截图里选的是 tun, 屏幕上却只有 tproxy 的原因 —— 于是没人知道 iptables
        # 那条路到底为什么也没用上, 而这恰恰是那台机器唯一的出路。
        why_text = str(item.get("report", {}).get("why", ""))
        check("一级都没接管时, why 里带上每一级的原因 (不是只报选中的那条)",
              all(f"{lv}:" in why_text for lv in ("tun", "tproxy", "redirect")),
              why_text[:140])

        # revert: 停用 + 拆数据面 + 与装机前快照逐条比对, 并给出结论
        subprocess.run(["sh", cli_plain, "local-auto"], capture_output=True, text=True)
        out = subprocess.run(["sh", cli_plain, "revert"], capture_output=True, text=True)

        # 基准: 面板当靶子, 直连那一趟必须真的量出数, 并落到 $ZP_DIR/bench
        bench = subprocess.run(["sh", cli_plain, "bench"], capture_output=True, text=True,
                               env={**os.environ, "ZP_BENCH_MB": "1"})
        bench_file = os.path.join(fake_root, "bench")
        check("bench 从面板量到了直连吞吐并落盘",
              "直连" in bench.stdout and os.path.exists(bench_file)
              and "direct_kbps=" in open(bench_file, encoding="utf-8").read(),
              bench.stdout.strip().splitlines()[:3])
        # 代理端口没在监听时, "经代理"那一趟**必须报失败**, 不能拿直连的数字充数 ——
        # curl 默认遵守 NO_PROXY, 而它常常含 127.0.0.1: 于是 -x 被忽略, 量出来的是直连
        # (演练里就这么骗过一次: 7890 上什么都没有, 却报了 921 MB/s)。
        check("经代理那一趟在代理端口没监听时报失败, 不拿直连的数字充数",
              "经代理" in bench.stdout and "失败" in bench.stdout
              and "没量到数" in bench.stdout,
              [ln.strip() for ln in bench.stdout.splitlines() if "经代理" in ln][:1])
        check("revert 给出了逐条比对的结论",
              "结论:" in out.stdout and ("完全回到装机前" in out.stdout or "还有残留" in out.stdout),
              [ln.strip() for ln in out.stdout.splitlines() if "结论" in ln][:1])
        check("revert 保留了配置与凭据 (那是 uninstall 的事)",
              os.path.exists(os.path.join(fake_root, "agent.sh"))
              and os.path.exists(os.path.join(fake_root, "config.yaml")))

        # [12] OpenWrt 25.12: 包管理器从 opkg 换成了 apk (真机 GL-MT3600BE · 25.12.5 ·
        # 内核 6.12.94, README 8.76)。这一节把三件不同的事各跑一遍:
        #   (A) 25.12 + apk: 该用 apk, 且 `apk -U add` 报 UNTRUSTED 时要退到
        #       --allow-untrusted (dae 的家用安装脚本就是这么干的) —— 装上了就不许再喊疼;
        #   (B) 源里没有这个内核的 kmod (厂商固件的常态): 不许再试 --allow-untrusted
        #       (那不是签名问题), 但**必须**把原话与下一步命令说出来;
        #   (C) 固件报 25.x 却只有 opkg (dae 那边叫 QWRT 那类迁移态): 按 opkg 走并说明。
        print("\n[12] OpenWrt 25.12 / apk: 装模块、说清为什么装不上、迁移态固件")
        apk_tools = os.path.join(tmp, "apktools")
        opkg_tools = os.path.join(tmp, "opkgtools")
        os.makedirs(apk_tools, exist_ok=True)
        os.makedirs(opkg_tools, exist_ok=True)

        def _write_tool(where: str, name: str, body: str) -> None:
            path = os.path.join(where, name)
            with open(path, "w") as fh:
                fh.write("#!/bin/sh\n" + body)
            os.chmod(path, 0o755)

        def _fw_release(root: str, release: str) -> None:
            """给这台模拟机写一份 /etc/openwrt_release (路径已被换进临时目录)。"""
            os.makedirs(root, exist_ok=True)
            with open(os.path.join(root, "openwrt_release"), "w") as fh:
                fh.write("DISTRIB_ID='openwrt'\n"
                         f"DISTRIB_RELEASE='{release}'\n"
                         "DISTRIB_ARCH='aarch64_cortex-a53'\n"
                         "DISTRIB_TARGET='mediatek/filogic'\n")

        # (A) 25.12 + apk, 源没有签名密钥 (自建 / 厂商源的常态)
        apk_log_a = os.path.join(tmp, "apk-a.log")
        _write_tool(
            apk_tools, "apk",
            f'echo "apk $*" >> "{apk_log_a}"\n'
            'case "$*" in\n'
            '  "-U add kmod-tun")\n'
            '    echo "ERROR: kmod-tun-6.12.94-r1.apk: UNTRUSTED signature" >&2\n'
            "    exit 3 ;;\n"
            '  "add --allow-untrusted kmod-tun")\n'
            '    echo "OK: 2 MiB in 4 packages"\n'
            "    exit 0 ;;\n"
            "esac\n"
            "exit 0\n",
        )
        a_root = os.path.join(tmp, "apk-root-a")
        _fw_release(a_root, "25.12.5")
        ok_a, out_a = run_install(
            "openwrt-2512-apk", root=a_root,
            extra={"PATH": apk_tools + os.pathsep + os.environ.get("PATH", "")},
        )
        a_caps = open(os.path.join(a_root, "caps"), encoding="utf-8").read()
        check("25.12 上包管理器认成 apk, 固件版本记进 caps",
              ok_a and "pkgmgr=apk" in a_caps and "fw=25.12.5" in a_caps and "fwgen=25" in a_caps,
              [ln for ln in a_caps.splitlines() if ln.split("=")[0] in ("fw", "fwgen", "pkgmgr")])
        check("安装输出里写清用的是 apk (不是让用户去猜)",
              "包管理器 apk" in out_a,
              [ln.strip() for ln in out_a.splitlines() if "apk" in ln][:2])
        a_log = open(apk_log_a, encoding="utf-8").read().splitlines() if os.path.exists(apk_log_a) else []
        check("apk 路径: `apk -U add` 一条命令 (刷新索引 + 安装), 不再多一次 apk update",
              a_log[:1] == ["apk -U add kmod-tun"], a_log)
        check("签名不可信时退到 --allow-untrusted (dae 的做法), 且只退这一步",
              a_log == ["apk -U add kmod-tun", "apk add --allow-untrusted kmod-tun"], a_log)
        a_deps = [ln for ln in a_caps.splitlines() if ln.startswith("deps_why=")]
        check("退一步装上了就不许再喊疼 (没有失败记录, caps 的 deps_why 空着)",
              "内核模块没装上" not in out_a and a_deps == ["deps_why="], a_deps)

        # (B) 25.12 + apk, 但源里没有这台内核的 kmod (厂商固件: 内核与官方源对不上)
        apk_log_b = os.path.join(tmp, "apk-b.log")
        _write_tool(
            apk_tools, "apk",
            f'echo "apk $*" >> "{apk_log_b}"\n'
            'echo "ERROR: unable to select packages: kmod-tun (no such package)" >&2\n'
            "exit 3\n",
        )
        b_root = os.path.join(tmp, "apk-root-b")
        _fw_release(b_root, "25.12.5")
        ok_b, out_b = run_install(
            "openwrt-2512-nokmod", root=b_root,
            extra={"PATH": apk_tools + os.pathsep + os.environ.get("PATH", "")},
        )
        b_log = open(apk_log_b, encoding="utf-8").read().splitlines() if os.path.exists(apk_log_b) else []
        b_caps = open(os.path.join(b_root, "caps"), encoding="utf-8").read()
        check("源里没有这个包时**不再**试 --allow-untrusted (那不是签名问题)",
              b_log == ["apk -U add kmod-tun"] and not any("--allow-untrusted" in ln for ln in b_log),
              b_log)
        check("装不上要说原话, 不是只留一句「缺 kmod-tun」",
              ok_b and "内核模块没装上" in out_b and "no such package" in out_b,
              [ln.strip() for ln in out_b.splitlines() if "内核模块没装上" in ln][:1])
        check("原因一路记进 caps (doctor / 面板读的是同一份)",
              "deps_why=kmod-tun:" in b_caps,
              [ln for ln in b_caps.splitlines() if ln.startswith("deps_why=")][:1])
        check("结尾给的下一步是**这台机器能用**的那条命令",
              "apk -U add kmod-tun kmod-nft-tproxy" in out_b,
              [ln.strip() for ln in out_b.splitlines() if "apk -U add" in ln][:1])
        check("把 25.12 那一层原因说出来: kmod 来自与内核版本绑定的源",
              "与内核版本绑定" in out_b)

        # (C) 固件报 25.x, 里面却还是 opkg (厂商迁移态)
        opkg_log = os.path.join(tmp, "opkg.log")
        _write_tool(
            opkg_tools, "opkg",
            f'echo "opkg $*" >> "{opkg_log}"\n'
            'case "$1" in\n'
            "  update) echo \"Updated list of available packages\"; exit 0 ;;\n"
            "esac\n"
            'echo "pkg_hash_check_unresolved: cannot find dependency kernel for kmod-tun" >&2\n'
            "exit 1\n",
        )
        c_root = os.path.join(tmp, "root-c-25x-opkg")
        _fw_release(c_root, "25.12.5")
        ok_c, out_c = run_install(
            "openwrt-2512-opkg", root=c_root,
            extra={"PATH": opkg_tools + os.pathsep + os.environ.get("PATH", "")},
        )
        c_caps = open(os.path.join(c_root, "caps"), encoding="utf-8").read()
        c_log = open(opkg_log, encoding="utf-8").read().splitlines() if os.path.exists(opkg_log) else []
        check("25.x 但只有 opkg 时按 opkg 走 (不硬套 apk), 并把这件事说出来",
              ok_c and "pkgmgr=opkg" in c_caps and "按 opkg 走" in out_c,
              [ln.strip() for ln in out_c.splitlines() if "opkg" in ln][:2])
        check("走 opkg 时就用 opkg 的命令 (update + install), 一次都不碰 apk",
              c_log[:2] == ["opkg update", "opkg install kmod-tun"]
              and not any("apk" in ln for ln in c_log), c_log)
        check("给用户的下一步也按 opkg 来 (不指一条这台机器上没有的命令)",
              "opkg install kmod-tun kmod-nft-tproxy" in out_c
              and "apk -U add" not in out_c,
              [ln.strip() for ln in out_c.splitlines() if "kmod-tun kmod-nft-tproxy" in ln][:1])

        # 这两条命令是装完之后**唯一的**现场排障入口 —— 它们读的是同一份 caps。
        cli_2512 = os.path.join(c_root, "cli-check-2512.sh")
        with open(os.path.join(c_root, "cli"), encoding="utf-8") as fh:
            cli_text = fh.read().replace("/etc/zeroproxy", c_root).replace("/etc/init.d/zeroproxy", "true")
        with open(cli_2512, "w") as fh:
            fh.write(cli_text)
        st = subprocess.run(["sh", cli_2512, "status"], capture_output=True, text=True)
        doc = subprocess.run(["sh", cli_2512, "doctor"], capture_output=True, text=True)
        check("zeroproxy status 报出固件与包管理器 (出问题时第一眼要看的两项)",
              "包管理器 opkg" in st.stdout and "25.12.5" in st.stdout,
              [ln.strip() for ln in st.stdout.splitlines() if "固件" in ln][:1])
        check("doctor 把「内核模块没装上」连同补装命令一起报出来",
              "内核模块没装上" in doc.stdout and "opkg install kmod-tun kmod-nft-tproxy" in doc.stdout,
              [ln.strip() for ln in doc.stdout.splitlines() if "补装" in ln][:1])

        # [13] 内核 BTF: 缺了就自动补 (真机 GL-MT3600BE · OpenWrt 25.12.5 · 内核 6.12.94)
        # 那台机器缺 /sys/kernel/btf/vmlinux, 而 eBPF 那一档的前提正是它。社区的解法是把
        # 匹配内核的 detached BTF 装到 /usr/lib/debug/boot/vmlinux-<内核版本> ——
        # cilium/ebpf 与 libbpf 在 sysfs 里找不到 BTF 时正好回退到那里。三件事各跑一遍:
        #   (A) 面板手上没有 → 如实说"补不上 + 它影响什么", 不假装 (先跑: 要求缓存是空的);
        #   (B) 面板有这一档 → 自动装上, caps 记 btf=1 + 来源, doctor 也报出来;
        #   (C) 内核自带 BTF 的机器: 一个字节都不动 (不去装包)。
        print("\n[13] 内核 BTF: 检测到缺失就自动补 (eBPF 性能档的前提)")
        btf_tools = os.path.join(tmp, "btftools")
        os.makedirs(btf_tools, exist_ok=True)
        btf_kver = "6.12.94"
        btf_pkg_name = "vmlinux-btf-6.12.103-r1-aarch64_cortex-a53.apk"

        def _btf_apk(root: str, log: str) -> None:
            """假 apk: 软件源里没有 vmlinux-btf (真机上它只在社区 feed 里), 但能把面板
            发来的本地包装上 —— 装上之后像真包那样在 /usr/lib/debug/boot/ 留一份 BTF。"""
            _write_tool(
                btf_tools, "apk",
                f'echo "apk $*" >> "{log}"\n'
                'case "$*" in\n'
                '  *"--allow-untrusted"*)\n'
                '    f="$(echo "$*" | sed "s/.*--allow-untrusted //")"\n'
                f'    mkdir -p "{root}/usr/lib/debug/boot"\n'
                f'    cp "$f" "{root}/usr/lib/debug/boot/vmlinux"\n'
                f'    ln -sf vmlinux "{root}/usr/lib/debug/boot/vmlinux-$ZP_KERNEL"\n'
                "    exit 0 ;;\n"
                "  *kmod-*)\n"
                "    exit 0 ;;\n"     # 别把 [13] 的注意力引到内核模块上
                "esac\n"
                'echo "ERROR: unable to select packages: vmlinux-btf (no such package)" >&2\n'
                "exit 3\n",
            )

        # (A) 面板手上没有这一档 → 如实说"补不上 + 它影响什么", 不假装。
        # 先跑这一条: 它要求面板的 BTF 缓存是空的 (下面那一条会往缓存里放一份)。
        b_root = os.path.join(tmp, "btf-root-b")
        os.makedirs(b_root, exist_ok=True)
        _fw_release(b_root, "25.12.5")
        apk_log_b = os.path.join(tmp, "btf-apk-b.log")
        _btf_apk(b_root, apk_log_b)
        ok_btf_b, out_btf_b = run_install(
            "btf-missing", root=b_root,
            extra={"PATH": btf_tools + os.pathsep + os.environ.get("PATH", ""),
                   "ZP_KERNEL": btf_kver},
        )
        b_caps_b = open(os.path.join(b_root, "caps"), encoding="utf-8").read()
        check("面板没有这一档时: eBPF 挡位如实记成不可用 (btf=0 + 原因)",
              ok_btf_b and "btf=0" in b_caps_b and "why.btf=" in b_caps_b
              and [ln for ln in b_caps_b.splitlines() if ln.startswith("why.btf=")][0] != "why.btf=",
              [ln for ln in b_caps_b.splitlines() if ln.startswith(("btf", "why.btf"))])
        # 面板回的是 502 + 一句人话 —— 那份**错误正文**绝不能被当成"包"装下去
        # (8.75 那次真机就是栽在"闸门比的是错误正文的大小": 状态码要排在体积前面)。
        b_log_b = open(apk_log_b, encoding="utf-8").read().splitlines() if os.path.exists(apk_log_b) else []
        check("面板说没有时不许拿它的错误正文当包来装 (状态码在前, 体积在后)",
              not any("--allow-untrusted" in ln for ln in b_log_b), b_log_b)
        check("并且说清它只影响性能档 (当前数据面不受影响)",
              "只影响未来的" in out_btf_b or "不影响当前的" in out_btf_b,
              [ln.strip() for ln in out_btf_b.splitlines() if "性能档" in ln][:2])

        # (B) 面板缓存里有一份匹配的包 → 路由器应当自动装上并用它
        btf_cache = os.path.join(panels[0].home, "data", "client", "btf")
        os.makedirs(btf_cache, exist_ok=True)
        with open(os.path.join(btf_cache, btf_pkg_name), "wb") as fh:
            fh.write(b"detached-btf-stub" * 8)
        apk_log_a = os.path.join(tmp, "btf-apk-a.log")
        a_root = os.path.join(tmp, "btf-root-a")
        os.makedirs(a_root, exist_ok=True)
        _fw_release(a_root, "25.12.5")     # 固件标识: 包按 DISTRIB_ARCH 挑 (aarch64_cortex-a53)
        _btf_apk(a_root, apk_log_a)
        ok_btf, out_btf = run_install(
            "btf-auto", root=a_root,
            extra={"PATH": btf_tools + os.pathsep + os.environ.get("PATH", ""),
                   "ZP_KERNEL": btf_kver},
        )
        bt_caps = open(os.path.join(a_root, "caps"), encoding="utf-8").read()
        bt_log = open(apk_log_a, encoding="utf-8").read().splitlines() if os.path.exists(apk_log_a) else []
        check("缺 BTF 时自动从面板取包并装上 (caps: btf=1 + 来源=panel)",
              ok_btf and "btf=1" in bt_caps and "btf_how=panel" in bt_caps,
              [ln for ln in bt_caps.splitlines() if ln.startswith(("btf", "why.btf"))])
        check("先试本机软件源 (没有这个包), 再用面板发来的本地包 (--allow-untrusted)",
              any("vmlinux-btf" in ln for ln in bt_log)
              and any("--allow-untrusted" in ln for ln in bt_log), bt_log)
        check("补上之后 eBPF 那一档真的可用了 (探测读的就是同一个路径)",
              "btf=1" in bt_caps and "ebpf=1" in bt_caps)
        check("装完就把话说出来: 补上了 + 来源 + 路径",
              "BTF" in out_btf and "已自动补上" in out_btf,
              [ln.strip() for ln in out_btf.splitlines() if "BTF" in ln][:2])
        # 桩目录里那份 BTF (假包落的盘) 真的在 —— 也就是"补上"不是嘴上说说
        check("detached BTF 真的落在 /usr/lib/debug/boot/vmlinux-<内核版本>",
              os.path.exists(os.path.join(a_root, "usr/lib/debug/boot", f"vmlinux-{btf_kver}")),
              os.listdir(os.path.join(a_root, "usr/lib/debug/boot")))

        # (C) 内核自带 BTF 的机器: 一个字节都不动
        c_root = os.path.join(tmp, "btf-root-c")
        os.makedirs(os.path.join(c_root, "sys/kernel/btf"), exist_ok=True)
        _fw_release(c_root, "25.12.5")
        with open(os.path.join(c_root, "sys/kernel/btf/vmlinux"), "wb") as fh:
            fh.write(b"kernel-provided-btf")
        apk_log_c = os.path.join(tmp, "btf-apk-c.log")
        _btf_apk(c_root, apk_log_c)
        ok_btf_c, _ = run_install(
            "btf-native", root=c_root,
            extra={"PATH": btf_tools + os.pathsep + os.environ.get("PATH", ""),
                   "ZP_KERNEL": btf_kver},
        )
        c_caps = open(os.path.join(c_root, "caps"), encoding="utf-8").read()
        c_log = open(apk_log_c, encoding="utf-8").read() if os.path.exists(apk_log_c) else ""
        check("内核自带 BTF 时不动它 (btf_how=kernel, 不去装任何包)",
              ok_btf_c and "btf_how=kernel" in c_caps and "vmlinux-btf" not in c_log,
              [ln for ln in c_caps.splitlines() if ln.startswith("btf")])

        # 现场入口也要报: doctor 里那一行 (装完之后用户唯一会看的地方)
        cli_btf = os.path.join(a_root, "cli-check-btf.sh")
        with open(os.path.join(a_root, "cli"), encoding="utf-8") as fh:
            cli_text = fh.read().replace("/etc/zeroproxy", a_root).replace("/etc/init.d/zeroproxy", "true")
        with open(cli_btf, "w") as fh:
            fh.write(cli_text)
        doc_btf = subprocess.run(["sh", cli_btf, "doctor"], capture_output=True, text=True)
        check("doctor 报出「BTF 已自动补上」以及它在哪",
              "BTF 已自动补上" in doc_btf.stdout and "usr/lib/debug/boot" in doc_btf.stdout,
              [ln.strip() for ln in doc_btf.stdout.splitlines() if "eBPF" in ln][:1])

        # [15] 性能模式 (eBPF / dae): 能进能出, 进不去就退回来
        # 这一节验的是那个"跑车仪表盘"背后真正的东西: 数据面在 mihomo 与 dae 之间**换过去**。
        # 四样假件: 假 dae (会说 validate / run)、假 mihomo 服务、假 dae 服务、假出口探针
        # (返回 ip=… —— 真机上那是 Cloudflare 的 trace)。
        # 要钉住的三件事: ① 能进 (caps / 服务 / 出口都对得上); ② 出口不通时**自动退回**,
        # 不能把家里留在断网状态; ③ 退出之后回到原来那一档。
        print("\n[15] 性能模式 (eBPF / dae): 能进能出, 进不去就退回来")
        perf_root = os.path.join(tmp, "perf-root")
        os.makedirs(perf_root, exist_ok=True)
        _fw_release(perf_root, "25.12.5")
        # 假 BTF: 这一档的前提 (内核 6.12.94 + BTF 都在)
        os.makedirs(os.path.join(perf_root, "sys/kernel/btf"), exist_ok=True)
        with open(os.path.join(perf_root, "sys/kernel/btf/vmlinux"), "wb") as fh:
            fh.write(b"kernel-provided-btf")

        def _fake_init(path_body: str) -> None:
            with open(path_body, "w") as fh:
                fh.write("#!/bin/sh\n" + (
                    'case "$1" in\n'
                    f'  running) [ -f "{os.path.join(perf_root, "core.running")}" ] && exit 0 || exit 1 ;;\n'
                    f'  start|restart|reload) touch "{os.path.join(perf_root, "core.running")}"; exit 0 ;;\n'
                    f'  stop) rm -f "{os.path.join(perf_root, "core.running")}"; exit 0 ;;\n'
                    "  enable|disable) exit 0 ;;\n"
                    "esac\nexit 0\n"
                ))
            os.chmod(path_body, 0o755)

        perf_tools = os.path.join(tmp, "perftools")
        os.makedirs(perf_tools, exist_ok=True)

        def _write_fake_dae(where: str) -> None:
            """假 dae: 会 validate / run。run 起来之后就一直挂着 (真实 daemon 那样)。"""
            with open(where, "w") as fh:
                fh.write(
                    "#!/bin/sh\n"
                    'case "$1" in\n'
                    "  validate) exit 0 ;;\n"
                    "  run) while :; do sleep 30; done ;;\n"
                    "esac\nexit 0\n"
                )
            os.chmod(where, 0o755)

        # 面板: 缓存一份假 dae (.gz)。真机上面板会去上游取并重新压成 .gz。
        perf_cache = os.path.join(panels[0].home, "data", "client", "perf")
        os.makedirs(perf_cache, exist_ok=True)
        with gzip.open(os.path.join(perf_cache, f"dae-arm64-{router_client.PERF_VERSION}.gz"), "wb") as fh:
            fh.write(b"#!fake-dae\n" + b"x" * 512)

        # 假出口探针: 真机上是 Cloudflare 的 trace, 这里一个本地小服务返回同样的格式
        probe = FakeMirror(b"ip=203.0.113.9\n")
        ok_p, out_p = run_install(
            "perf", root=perf_root,
            extra={"PATH": perf_tools + os.pathsep + os.environ.get("PATH", ""),
                   "ZP_KERNEL": btf_kver, "ZP_ROOT": perf_root,
                   "ZP_PERF_PROBE": f"http://127.0.0.1:{probe.port}/cdn-cgi/trace"},
        )
        p_caps = open(os.path.join(perf_root, "caps"), encoding="utf-8").read()
        check("这台机器被判定为「可以开性能模式」(perf_cap=1)",
              ok_p and "perf_cap=1" in p_caps,
              [ln for ln in p_caps.splitlines() if ln.startswith("perf")])
        check("装机输出里就告诉了用户这一档能不能开",
              "性能模式" in out_p and ("可以开" in out_p or "开不了" in out_p),
              [ln.strip() for ln in out_p.splitlines() if "性能模式" in ln][:1])
        perf_progress = os.path.join(perf_root, "perf", "progress")
        # 两个假服务必须在**装完之后**再写: 安装脚本自己会往 <root>/initd 落一份真的
        # mihomo init 脚本 (带 /etc/rc.common 那种 shebang), 而本机 (macOS) 执行它时退出码
        # 是 0 —— 那会让"标准模式还开着没有"永远为真。所以演练用一份自己控制的:
        # core.running 在 = mihomo 在跑。
        _fake_init(os.path.join(perf_root, "initd"))          # 假 mihomo 服务
        with open(os.path.join(perf_root, "initd-perf"), "w") as fh:
            # 假 dae 服务: start 起一个"daemon", running 看它还活着没有 (真机上是 procd)
            fh.write("#!/bin/sh\n" + (
                'case "$1" in\n'
                f'  start|restart) "$ZP_ROOT/perf/dae" run -c "$ZP_ROOT/perf/dae.dae" & echo $! > "$ZP_ROOT/perf/dae.pid"; exit 0 ;;\n'
                f'  stop) [ -f "$ZP_ROOT/perf/dae.pid" ] && kill "$(cat "$ZP_ROOT/perf/dae.pid")" 2>/dev/null; rm -f "$ZP_ROOT/perf/dae.pid"; exit 0 ;;\n'
                f'  running) [ -f "$ZP_ROOT/perf/dae.pid" ] && kill -0 "$(cat "$ZP_ROOT/perf/dae.pid")" 2>/dev/null && exit 0; exit 1 ;;\n'
                "  enable|disable) exit 0 ;;\n"
                "esac\nexit 0\n"
            ))
        os.chmod(os.path.join(perf_root, "initd-perf"), 0o755)
        # 装机那一刻这台"机器"上标准模式是开着的 (真机上就是 tun 在跑) —— 这样"换过去之后
        # mihomo 停了"才有得比。
        with open(os.path.join(perf_root, "core.running"), "w") as fh:
            fh.write("1\n")

        # 把假 dae 放进 perf 目录, 装一遍 CLI 补丁 (install 里已经写好 perf.sh)
        os.makedirs(os.path.join(perf_root, "perf"), exist_ok=True)
        _write_fake_dae(os.path.join(perf_root, "perf", "dae"))
        cli_perf = os.path.join(perf_root, "cli-perf.sh")
        with open(os.path.join(perf_root, "cli"), encoding="utf-8") as fh:
            cli_text = fh.read().replace("/etc/zeroproxy", perf_root)
        with open(cli_perf, "w") as fh:
            fh.write(cli_text)

        def _run_cli(*args, timeout=120):
            return subprocess.run(
                ["sh", cli_perf, *args], capture_output=True, text=True, timeout=timeout,
                env={**os.environ, "ZP_ROOT": perf_root, "ZP_KERNEL": btf_kver,
                     "ZP_PERF_VERIFY_TRIES": "2",   # 演练里没有真节点, 别干等 45 秒
                     "ZP_PERF_PROBE": f"http://127.0.0.1:{probe.port}/cdn-cgi/trace"},
            )

        # 1) 真正切过去 (CLI 没有 TTY → 后台跑, 进度写文件; 界面就是照它画进度的)
        entered = _run_cli("perf", "on")
        for _ in range(60):                     # 最多等 ~30 秒
            prog = ""
            p_path = os.path.join(perf_root, "perf", "progress")
            if os.path.exists(p_path):
                prog = open(p_path, encoding="utf-8").read()
            if "DONE=" in prog:
                break
            time.sleep(0.5)
        p_caps = open(os.path.join(perf_root, "caps"), encoding="utf-8").read()
        check("切换是后台跑的, 进度落在文件里 (界面据此画动画)",
              "已开始切换" in entered.stdout and "DONE=" in prog,
              prog.strip())
        check("真的切过去了: caps 记 perf=1 且 chosen=ebpf",
              "perf=1" in p_caps and "chosen=ebpf" in p_caps,
              [ln for ln in p_caps.splitlines() if ln.startswith(("perf=", "chosen="))])
        check("dae 真的在跑, mihomo 已经停了 (两个数据面互斥)",
              subprocess.run(["sh", os.path.join(perf_root, "initd-perf"), "running"],
                             env={**os.environ, "ZP_ROOT": perf_root}).returncode == 0
              and not os.path.exists(os.path.join(perf_root, "core.running")))
        exit_file = os.path.join(perf_root, "perf", "exit_ip")
        exit_ip = open(exit_file, encoding="utf-8").read().strip() if os.path.exists(exit_file) else ""
        check("验证用的是**真实出口** (探针给的 IP 被记下来)", exit_ip == "203.0.113.9", exit_ip or "(没记)")
        st = _run_cli("perf", "status")
        check("zeroproxy perf status 说清「已开启」与出口",
              "已开启" in st.stdout and "203.0.113.9" in st.stdout,
              [ln.strip() for ln in st.stdout.splitlines()[:2]])
        doc2 = _run_cli("doctor")
        check("doctor 里有一条「性能模式正在生效」+ 现场证据",
              "性能模式" in doc2.stdout and "正在生效" in doc2.stdout,
              [ln.strip() for ln in doc2.stdout.splitlines() if "性能模式" in ln][:1])

        # 2) 出口不通时必须**自动退回** —— 家里不能被留在断网状态
        probe.close()
        _run_cli("perf", "off")
        p_caps = open(os.path.join(perf_root, "caps"), encoding="utf-8").read()
        check("熄火之后回到原来那一档 (perf=0, chosen 不再是 ebpf)",
              "perf=0" in p_caps and "chosen=ebpf" not in p_caps,
              [ln for ln in p_caps.splitlines() if ln.startswith(("perf=", "chosen="))])
        check("mihomo 又被拉起来了", os.path.exists(os.path.join(perf_root, "core.running")))
        failed_run = _run_cli("perf", "on")   # 探针已经关了 → 出口验证必然失败
        for _ in range(60):
            prog = open(os.path.join(perf_root, "perf", "progress"), encoding="utf-8").read()
            if "DONE=1" in prog:
                break
            time.sleep(0.5)
        p_caps = open(os.path.join(perf_root, "caps"), encoding="utf-8").read()
        check("出口验不过时**自动退回**: perf=0, 并且说明是为什么",
              "DONE=1" in prog and "perf=0" in p_caps and "出不去" in p_caps,
              [ln for ln in p_caps.splitlines() if ln.startswith("perf")])
        check("退回之后 dae 不在了、mihomo 回来了 (没有留在断网状态)",
              not os.path.exists(os.path.join(perf_root, "perf", "dae.pid"))
              and os.path.exists(os.path.join(perf_root, "core.running")))
        check("退回过程写进了进度文件 (界面上看得见)",
              "退回" in prog or "已回到标准模式" in prog,
              [ln.strip() for ln in prog.splitlines() if "退回" in ln or "回到标准" in ln][:1])

        # 3) 看门狗: 说好在用, 而 dae 已经不在了 → 连续三轮之后自动退回
        _run_cli("perf", "on")           # 探针还是关的, 所以先手工把它置成"在用"
        time.sleep(1)
        with open(os.path.join(perf_root, "perf", "state"), "w") as fh:
            fh.write("on\n")
        with open(os.path.join(perf_root, "perf", "dae.pid"), "w") as fh:
            fh.write("999999\n")
        for _ in range(4):
            subprocess.run(["sh", os.path.join(perf_root, "agent.sh"), "once"], capture_output=True,
                           text=True, timeout=60,
                           env={**os.environ, "ZP_ROOT": perf_root})
        p_caps = open(os.path.join(perf_root, "caps"), encoding="utf-8").read()
        check("看门狗: dae 连续几轮不在就自动退回标准模式 (家里不会断着)",
              "perf=0" in p_caps and os.path.exists(os.path.join(perf_root, "core.running")),
              [ln for ln in p_caps.splitlines() if ln.startswith("perf")])

        # [16] LuCI 那三件套: 升级不许毁掉好文件, 坏了要能就地修 (真机事故: 升级之后 403)
        # 现场: 以前是 `http_get ... > /usr/share/rpcd/acl.d/xxx.json || true` —— 重定向先清空
        # 目标, 而 `|| true` 把失败咽掉。面板正好在重启 (nginx 回 502) 的那一次升级, 就把一份
        # 好端端的 ACL 换成 0 字节 → rpcd 读不出来 → LuCI 的菜单依赖检查不过 → 点进去 403。
        print("\n[16] LuCI 集成: 升级不清空好文件, 坏了能就地修")
        luci_root = os.path.join(tmp, "luci-root")
        for sub in ("www/zeroproxy", "www/cgi-bin", "usr/share/luci/menu.d", "usr/share/rpcd/acl.d"):
            os.makedirs(os.path.join(luci_root, sub), exist_ok=True)
        acl_dst = os.path.join(luci_root, "usr/share/rpcd/acl.d/luci-app-zeroproxy.json")
        menu_dst = os.path.join(luci_root, "usr/share/luci/menu.d/luci-app-zeroproxy.json")
        view_dst = os.path.join(luci_root, "www/luci-static/resources/view/zeroproxy/status.js")
        os.makedirs(os.path.dirname(view_dst), exist_ok=True)
        legacy = '{"luci-app-zeroproxy": {"read": {"ubus": {"session": ["get"]}}}}\n'
        for path in (acl_dst, menu_dst):
            with open(path, "w") as fh:
                fh.write(legacy)
        with open(view_dst, "w") as fh:
            fh.write("'use strict';\n// 旧版本\n")

        # 这一节要的正是界面里那一小段 (LuCI 三件套的落盘 + 校验), 所以显式把它接进 main,
        # 否则演练会停在"文件已落盘", 那三件套根本没被写过。
        ok_l, out_l = run_install("luci", root=luci_root, extra={"ZP_KERNEL": btf_kver},
                                  main_extra="luci_install || true")
        check("正常装机: 三件套都就位 (面板给什么就落什么)",
              ok_l and os.path.getsize(acl_dst) > 0
              and open(acl_dst, encoding="utf-8").read().lstrip().startswith("{")
              and os.path.getsize(view_dst) > 0
              and os.path.getsize(acl_dst) > len(legacy),   # 真的被面板那份换过 (比占位的那份大)
              f"acl={os.path.getsize(acl_dst)}B menu={os.path.getsize(menu_dst)}B "
              f"view={os.path.getsize(view_dst)}B")
        cache = os.path.join(luci_root, "luci")
        check("装机时留了一份内置兜底 (离线也能修)",
              os.path.isdir(cache)
              and all(os.path.getsize(os.path.join(cache, f)) > 0
                      for f in ("menu.json", "acl.json", "status.js")),
              sorted(os.listdir(cache)) if os.path.isdir(cache) else "(没有)")
        check("内置兜底与仓库里那份逐字节一致 (两边漂移 = 某个固件上菜单会突然不见)",
              open(os.path.join(cache, "menu.json"), encoding="utf-8").read()
              == open(os.path.join(BACKEND, "zeroproxy", "client", "luci", "menu.json"),
                      encoding="utf-8").read(),
              f"{os.path.getsize(os.path.join(cache, 'menu.json'))}B")

        # 「升级不许毁掉好文件」—— 把面板地址换成死地址 (= 升级时面板正好在重启 / 不可达),
        # 再跑一次同一段: 已经装好的三件套必须**一个字节都不变**。这就是那次 403 的反面。
        srv_files = os.listdir(os.path.join(luci_root, "servers"))
        srv_path = os.path.join(luci_root, "servers", srv_files[0])
        with open(srv_path, encoding="utf-8") as fh:
            creds = fh.read()
        with open(srv_path, "w") as fh:
            fh.write(creds.replace(panels[0].base, "http://127.0.0.1:9"))
        keep = {p: open(p, encoding="utf-8").read() for p in (acl_dst, menu_dst, view_dst)}
        ok_l2, out_l2 = run_install("luci-offline", root=luci_root, extra={"ZP_KERNEL": btf_kver},
                                    base="http://127.0.0.1:9",
                                    main_only="detect_http; luci_install || true")
        check("面板不可达时再装一次: 三件套**一个字节都没被改** (不再清空好文件)",
              ok_l2 and all(open(p, encoding="utf-8").read() == keep[p] for p in keep),
              [ln.strip() for ln in out_l2.splitlines() if "保留本机" in ln][:1])
        check("并且明确说了「面板没给出, 保留本机那份」",
              "保留本机" in out_l2, [ln.strip() for ln in out_l2.splitlines() if "保留本机" in ln][:1])

        # 再把 ACL 弄成 0 字节 (那次事故的现场) 跑 `zeroproxy ui fix`: 内置兜底必须顶上。
        with open(acl_dst, "w") as fh:
            fh.write("")
        cli_luci = os.path.join(luci_root, "cli-luci.sh")
        with open(os.path.join(luci_root, "cli"), encoding="utf-8") as fh:
            cli_text = fh.read().replace("/etc/zeroproxy", luci_root)
        with open(cli_luci, "w") as fh:
            fh.write(cli_text)
        fix_offline = subprocess.run(["sh", cli_luci, "ui", "fix"], capture_output=True, text=True,
                                     timeout=120, env={**os.environ})
        check("面板不可达时 `ui fix` 用内置兜底把空掉的 ACL 补回来 (0 字节 → 合法 JSON)",
              os.path.getsize(acl_dst) > 0
              and open(acl_dst, encoding="utf-8").read().lstrip().startswith("{"),
              fix_offline.stdout.strip().splitlines()[:2])

        # 面板可达时, 弄坏的那一份要**从面板重新取**回来
        with open(srv_path, "w") as fh:
            fh.write(creds)
        with open(menu_dst, "w") as fh:
            fh.write("")
        fix_online = subprocess.run(["sh", cli_luci, "ui", "fix"], capture_output=True, text=True,
                                    timeout=120, env={**os.environ})
        check("面板可达时 `ui fix` 从面板取回最新的一份 (菜单也修好)",
              os.path.getsize(menu_dst) > 0
              and open(menu_dst, encoding="utf-8").read().lstrip().startswith("{"),
              fix_online.stdout.strip().splitlines()[:2])
        check("`ui fix` 说清了它修了几份 (用户能确认)",
              "修好" in fix_online.stdout or "本来就是好的" in fix_online.stdout,
              fix_online.stdout.strip().splitlines()[:1])

        # 已经好的文件不许被"修"动 (幂等)
        before_run = open(acl_dst, encoding="utf-8").read()
        subprocess.run(["sh", cli_luci, "ui", "fix"], capture_output=True, text=True, timeout=120,
                       env={**os.environ})
        check("已经好的文件不会被 `ui fix` 动 (幂等, 内容是逐字节相同)",
              open(acl_dst, encoding="utf-8").read() == before_run)

        # ---------------------------------------------------------------- 第一跳
        #
        # 用户拿到的是面板生成的一行命令, 在**路由器**上跑。真机反馈 (OpenWrt 25.12):
        # "执行面板生成的链接后, 没有任何反馈, 执行失败"。旧写法
        # `wget -qO- <url> | sh` 把这件事变成了可能: `-q` 吞掉所有失败、只试一次、
        # 而且 `| sh` 会把面板 4xx 的正文当脚本喂进去。这一节在**真的 shell + 真的
        # 下载工具 (uclient-fetch 的替身)** 上把那条路走一遍。
        print("\n[17] 第一跳 (面板生成的那一行命令): 丢包 / 自签 / 配对码失效都不许"
              "「什么都没有发生」")
        sys.path.insert(0, BACKEND)
        from zeroproxy import routes as zp_routes  # noqa: E402

        import http.server  # noqa: E402

        MARKER = "#!/bin/sh\necho ZP-FIRST-HOP-OK\n"

        class _Marker(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                body = MARKER.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/x-shellscript")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):  # pragma: no cover
                pass

        # uclient-fetch 的替身: 带 -q 就**什么都不说**, 不带就把失败说出来 (真机的行为),
        # 默认校验证书 (自签会失败), 用 ZP_SHIM_FAILS 模拟"前几次 SYN 被丢掉"。
        shim_dir = os.path.join(tmp, "shim")
        os.makedirs(shim_dir, exist_ok=True)
        shim = os.path.join(shim_dir, "wget")
        with open(shim, "w") as fh:
            fh.write(
                "#!/bin/sh\n"
                "q=0;out=;tmo=900;insecure=0;url=\n"
                "while [ $# -gt 0 ]; do\n"
                "  a=\"$1\"; shift\n"
                "  case \"$a\" in\n"
                "    -q) q=1 ;;\n"
                "    --no-check-certificate) insecure=1 ;;\n"
                "    -O) out=\"$1\"; shift ;;\n"
                "    -T) tmo=\"$1\"; shift ;;\n"
                "    -O*) out=\"${a#-O}\" ;;\n"
                "    -T*) tmo=\"${a#-T}\" ;;\n"
                "    -qO) q=1; out=\"$1\"; shift ;;\n"
                "    -qT) q=1; tmo=\"$1\"; shift ;;\n"
                "    -qO*) q=1; out=\"${a#-qO}\" ;;\n"
                "    -qT*) q=1; tmo=\"${a#-qT}\" ;;\n"
                "    -*) ;;\n"
                "    *) url=\"$a\" ;;\n"
                "  esac\n"
                "done\n"
                "[ -n \"$url\" ] || exit 1\n"
                "[ \"$out\" = \"-\" ] && out=\n"      # -O- = 写到标准输出 (真机上的含义)
                # 真机上的 uclient-fetch 不打 -q 时会把失败原话打出来 (Connection error /
                # SSL error / Download failed) —— 这正是"不许静默"那条判据要看到的东西。
                "[ \"$q\" = 1 ] || echo \"Downloading '$url'\" >&2\n"
                "if [ -n \"$ZP_SHIM_CNT\" ]; then\n"
                "  n=0; [ -f \"$ZP_SHIM_CNT\" ] && n=$(cat \"$ZP_SHIM_CNT\")\n"
                "  if [ \"$n\" -lt \"${ZP_SHIM_FAILS:-0}\" ]; then\n"
                "    echo $((n+1)) > \"$ZP_SHIM_CNT\"\n"
                "    [ \"$q\" = 1 ] || echo \"Connection error\" >&2\n"
                "    exit 1\n"
                "  fi\n"
                "fi\n"
                "if [ \"$q\" = 1 ]; then set -- -s; else set -- -sS; fi\n"
                "[ \"$insecure\" = 1 ] && set -- \"$@\" -k\n"
                "if [ -n \"$out\" ]; then exec curl \"$@\" -f --max-time \"$tmo\" -o \"$out\" \"$url\"; fi\n"
                "exec curl \"$@\" -f --max-time \"$tmo\" \"$url\"\n"
            )
        os.chmod(shim, 0o755)

        def first_hop(cmd: str, fails: int = 0) -> tuple[int, str]:
            cnt = os.path.join(tmp, "shim-cnt")
            if os.path.exists(cnt):
                os.remove(cnt)
            env2 = {**os.environ, "PATH": shim_dir + os.pathsep + os.environ.get("PATH", ""),
                    "ZP_SHIM_CNT": cnt, "ZP_SHIM_FAILS": str(fails)}
            proc = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True,
                                  env=env2, timeout=180)
            return proc.returncode, proc.stdout + proc.stderr

        marker_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Marker)
        threading.Thread(target=marker_srv.serve_forever, daemon=True).start()
        marker_base = f"http://127.0.0.1:{marker_srv.server_address[1]}"

        # 自签的 HTTPS 靶子 (面板在"域名还没签下证书"时就是这个形态)
        tls_srv = None
        tls_base = ""
        cert, key = os.path.join(tmp, "tls.pem"), os.path.join(tmp, "tls.key")
        gen = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
             "-keyout", key, "-out", cert], capture_output=True, text=True)
        if gen.returncode == 0:
            import ssl  # noqa: E402

            tls_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Marker)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            tls_srv.socket = ctx.wrap_socket(tls_srv.socket, server_side=True)
            threading.Thread(target=tls_srv.serve_forever, daemon=True).start()
            tls_base = f"https://127.0.0.1:{tls_srv.server_address[1]}"

        code_probe = "00112233445566778899aabbccddeeff"
        new_cmd = zp_routes._install_command(marker_base, code_probe)
        old_cmd = f"wget -qO- {marker_base}/c/{code_probe} | sh"

        rc_old, out_old = first_hop(old_cmd, fails=2)
        check("对照 (旧写法): 一次丢包就『什么都没有发生』 —— 真机反馈的就是这个形状",
              rc_old == 0 and out_old.strip() == "" and "ZP-FIRST-HOP-OK" not in out_old,
              repr(out_old[:60]))
        rc_new, out_new = first_hop(new_cmd, fails=2)
        check("第一跳: 前两次丢包后自己重试成功 (脚本真的跑起来了)",
              rc_new == 0 and "ZP-FIRST-HOP-OK" in out_new, out_new.strip()[:100])
        check("第一跳: 丢包那两次在屏幕上说了话 (下载工具自己报的, 不是一片空白)",
              "Connection error" in out_new,
              [ln for ln in out_new.splitlines() if "error" in ln.lower()][:2])

        if tls_base:
            # 面板**自己**知道证书状态: 自签/用 IP 打开时, 这一行直接带 --no-check-certificate
            # (让用户去理解"什么时候该加 -k"是错的)。校验证书的那一版在这里必然失败 ——
            # 但那也是**响的**, 不再是一片空白。
            rc_tls, out_tls = first_hop(
                zp_routes._install_command(tls_base, code_probe, insecure=True))
            check("第一跳: 面板还在自签阶段也能装上 (面板按自己的证书状态加 --no-check-certificate)",
                  rc_tls == 0 and "ZP-FIRST-HOP-OK" in out_tls, out_tls.strip()[:100])
            rc_old_tls, out_old_tls = first_hop(f"wget -qO- {tls_base}/c/{code_probe} | sh")
            check("对照 (旧写法): 自签面板上一个字都不说 —— 那个错误以前没人看得见",
                  out_old_tls.strip() == "", repr(out_old_tls[:60]))

        rc_dead, out_dead = first_hop(zp_routes._install_command("http://127.0.0.1:9", code_probe))
        check("第一跳: 面板整个不可达时以非 0 结束, 且终端里有下载工具的原话",
              rc_dead != 0 and ("Failed to connect" in out_dead or "Connection error" in out_dead),
              out_dead.strip()[-160:])

        # 配对码失效: 面板下发的是**能跑的说明** (不是 4xx 正文), 第一跳会把它原样念出来
        _, pair_body, _ = panel.req("POST", "/api/devices/pair", {"label": "first-hop"})
        pair = json.loads(pair_body)
        check("第一跳命令仍然是一行, 不再把面板正文直接喂给 sh, 也不再打 -q",
              "\n" not in pair["command"] and "| sh" not in pair["command"]
              and " -q " not in pair["command"])
        check("第一跳命令够短 (面板上要能读、能贴 —— 上一版 570 字符的『全家桶』在界面上"
              "就是一堵 shell 墙, 用户截图反馈过)",
              len(pair["command"]) < 220, f"{len(pair['command'])} 字符")
        panel.req("POST", "/c/pair", {"code": pair["code"], "kind": "router", "arch": "arm64"})
        rc_used, out_used = first_hop(pair["command"])
        check("第一跳: 配对码已经用过时, 终端里读得到原因 (而不是一片空白)",
              rc_used != 0 and "配对码" in out_used and "生成安装命令" in out_used,
              out_used.strip()[:140])

        marker_srv.shutdown()
        if tls_srv:
            tls_srv.shutdown()
    finally:
        logs = []
        for panel in panels:
            # 先停再读: 反过来会先卡在读管道上 (进程还活着, read() 等不到 EOF)
            panel.stop()
            panel.log = panel.proc.stdout.read() if panel.proc.stdout else ""
            logs.append(panel.log)
        log = "\n".join(logs)
        shutil.rmtree(tmp, ignore_errors=True)

    failed = [r for r in results if not r[1]]
    print(f"\n结论: {len(results) - len(failed)}/{len(results)} 项通过")
    if failed:
        print("未通过: " + ", ".join(r[0] for r in failed))
        print("服务日志尾部:\n" + (log or "")[-1200:])
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
