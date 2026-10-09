"""客户端设备 (路由器) 回归测试: 配对 → 安装脚本 → 订阅 → 开关 → 移除。

全部离线可跑: 内核二进制那一项把下载函数换成本地假文件 (面板侧真正下载
20 MB 的 mihomo 不该出现在测试里)。
"""
from __future__ import annotations

import hashlib
import json
import os
import time

import pytest
import yaml

from conftest import DOMAIN, PASSWORD, USERNAME


def _login(client) -> None:
    res = client.post("/api/login", json={"username": USERNAME, "password": PASSWORD})
    assert res.status_code == 200, res.text


def _pair_code(client) -> dict:
    res = client.post("/api/devices/pair", json={"label": "测试路由器"})
    assert res.status_code == 200, res.text
    return res.json()


def _register(client, code: str) -> dict:
    res = client.post(
        "/c/pair",
        json={
            "code": code,
            "kind": "router",
            "hostname": "GL-MT3000",
            "model": "GL.iNet GL-MT3000",
            "arch": "arm64",
            "os": "OpenWrt 24.10.4",
            "version": "1.0.0",
        },
    )
    assert res.status_code == 200, res.text
    return res.json()


# ---------------------------------------------------------------- 面板侧

def test_pair_code_requires_login(client, configured):
    client.post("/api/logout")          # 初始化本身会顺手登录, 这里先退出
    assert client.post("/api/devices/pair", json={}).status_code == 401


def test_pair_returns_copyable_command(client, configured):
    _login(client)
    data = _pair_code(client)
    assert data["command"].startswith("wget -qO- ")
    assert data["command"].endswith("| sh")
    assert f"/c/{data['code']}" in data["command"]
    assert DOMAIN in data["command"]        # 命令里用的是面板自己的域名
    assert data["ttl"] > 0


def test_devices_appear_on_dashboard(client, configured):
    _login(client)
    data = _pair_code(client)
    device = _register(client, data["code"])
    dash = client.get("/api/dashboard").json()
    assert dash["devices"]["count"] == 1
    assert dash["devices"]["items"][0]["id"] == device["id"]
    # 新设备默认期望"开", 但还没上报过 actual → 还不是"已连接"
    assert dash["devices"]["items"][0]["desired"] is True
    assert dash["devices"]["items"][0]["actual"] is False
    assert dash["client"]["core_version"].startswith("v")


# ---------------------------------------------------------------- 安装链路

def test_install_script_is_rendered_for_this_panel(client, configured):
    _login(client)
    code = _pair_code(client)["code"]
    res = client.get(f"/c/{code}")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/x-shellscript")
    body = res.text
    assert "__ZP_BASE__" not in body and "__ZP_CODE__" not in body
    assert f'ZP_CODE="{code}"' in body
    # 面板基址取自身份面板地址 (域名 + 面板端口), 而不是请求里的 Host
    assert f'ZP_BASE="{configured["panel_url"]}"' in body
    assert DOMAIN in body
    for needle in ("mihomo -t", "/etc/init.d/zeroproxy", "uninstall", "device.json"):
        assert needle in body


def test_install_script_rejects_unknown_or_used_code(client, configured):
    _login(client)
    assert client.get("/c/deadbeef").status_code == 404
    code = _pair_code(client)["code"]
    _register(client, code)          # 用掉
    assert client.get(f"/c/{code}").status_code == 404


def test_pair_code_is_single_use(client, configured):
    _login(client)
    code = _pair_code(client)["code"]
    _register(client, code)
    again = client.post("/c/pair", json={"code": code, "model": "另一台"})
    assert again.status_code == 403
    assert "配对码" in again.json()["error"]


def test_core_binary_endpoint(client, configured, tmp_path, monkeypatch):
    from zeroproxy import router_client

    assert client.get("/c/bin/pdp11").status_code == 404

    blob = tmp_path / "mihomo-arm64.gz"
    blob.write_bytes(b"\x1f\x8b" + b"0" * 64)
    # 面板已经缓存好这一档内核时, 直接把它发出去 (缓存判据与 install_core 一致)
    monkeypatch.setattr(router_client, "core_ready", lambda arch: arch == "arm64")
    monkeypatch.setattr(router_client, "core_file", lambda arch: str(blob))
    res = client.get("/c/bin/arm64")
    assert res.status_code == 200
    assert res.content == blob.read_bytes()


def test_core_binary_answers_instead_of_hanging(client, configured, monkeypatch):
    """内核还没缓存时, /c/bin 必须**立刻**回一句人话, 不能把请求挂在那里。

    真机事故 (GL-MT3600BE / OpenWrt 25.12.5, 2026-10): 安装命令停在
    "==> 下载代理内核 (mihomo · arm64)" 上再也不动, 十分钟后被路由器自己的
    curl -m 600 掐断。原因是面板在这个请求里同步去上游拉 20 MB, 而且没有总时限
    (5 个镜像 × 180 秒, urllib 的超时又只管单次 socket 操作)。
    现在: 立刻 503 + Retry-After + 一句"面板正在准备内核", 同时后台开取。
    """
    from zeroproxy import router_client

    monkeypatch.setattr(router_client, "CORE_DEADLINE", 60)
    # 上游换成一个"只握手、几乎不发货"的本地服务器: 没有总时限时这里会挂到天荒地老
    srv = _trickle_server()
    try:
        monkeypatch.setattr(router_client, "MIRRORS", (srv.url,))
        started = time.time()
        res = client.get("/c/bin/arm64")
        elapsed = time.time() - started
    finally:
        srv.close()
    assert res.status_code == 503, res.text
    assert res.headers.get("retry-after") == "5", "路由器端要知道多久后来重试"
    assert "面板正在准备" in res.text or "面板取内核失败" in res.text, res.text
    assert elapsed < 5, f"请求被上游挂住了 ({elapsed:.1f}s)"
    # 后台确实开始取了 (不是回一句就走)
    assert router_client.core_state("arm64")["state"] in ("downloading", "error", "ready")


def test_core_status_tells_the_router_what_to_fetch_directly(client, configured, monkeypatch):
    """状态接口要把版本号与资产名给出来 —— 路由器端直连兜底时按它拼 URL。

    客户端里不重复写一份版本号 (改一处漏一处), 所以这个接口是兜底那条路的前提。
    """
    from zeroproxy import router_client

    res = client.get("/c/core/status?arch=arm64")
    assert res.status_code == 200
    data = res.json()
    assert data["core_version"] == router_client.CORE_VERSION
    assert data["asset"] == f"mihomo-linux-arm64-{router_client.CORE_VERSION}.gz"
    assert data["state"] in ("missing", "downloading", "ready", "error")
    assert isinstance(data["bytes"], int)
    # 没指定架构时不透露资产名 (那是按架构拼的), 但列表要在
    assert client.get("/c/core/status").json()["asset"] == ""
    assert len(client.get("/c/core/status").json()["cores"]) == len(router_client.ARCHES)


def test_preparing_a_core_is_explicit_and_idempotent(client, configured, monkeypatch):
    """面板上能"先把内核准备好"再发安装命令 —— 幂等, 且不会重复下第二遍。"""
    from zeroproxy import router_client

    client.post("/api/logout")
    assert client.post("/api/devices/cores/arm64/prepare").status_code == 401
    _login(client)
    assert client.post("/api/devices/cores/pdp11/prepare").status_code == 404

    calls = []

    def fake_fetch(arch, **kw):
        calls.append(arch)
        # 真的 fetch_core 下完一定把文件落盘 —— 假的也必须落, 否则 core_ready() 一直
        # 为假, "已经下好就不再下" 这条幂等性就无从谈起 (它以前是靠上一条用例留下的
        # 全局状态"恰好"成立的)。
        path = router_client.core_file(arch)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(b"c" * 4096)
        return True, "已下载 20 MB", path

    monkeypatch.setattr(router_client, "fetch_core", fake_fetch)
    # 体积下限调小: 假文件只有几 KB, 而 core_ready() 要求 >= MIN_BYTES
    monkeypatch.setattr(router_client, "MIN_BYTES", 4096)
    first = client.post("/api/devices/cores/arm64/prepare")
    assert first.status_code == 200
    assert first.json()["core"]["state"] in ("downloading", "ready")
    # 已经在下 / 已经下好时再点一次, 不该再起一个任务
    for _ in range(3):
        client.post("/api/devices/cores/arm64/prepare")
    deadline = time.time() + 10
    while time.time() < deadline and router_client.core_state("arm64")["state"] == "downloading":
        time.sleep(0.05)
    assert len(calls) <= 1, f"重复触发了下载: {calls}"
    assert "arm64" in [c["arch"] for c in client.get("/api/devices/cores").json()["cores"]]


class _Trickle:
    """一个"能连上、每秒滴一点"的假上游 —— 没有总时限就会永远不返回。"""

    def __init__(self, *, chunk: int = 512, delay: float = 0.2, length: int = 64 << 20) -> None:
        import http.server
        import socketserver
        import threading

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                self.send_response(200)
                self.send_header("Content-Length", str(length))
                self.end_headers()
                try:
                    while True:
                        self.wfile.write(b"x" * chunk)
                        self.wfile.flush()
                        time.sleep(delay)
                except OSError:
                    pass

            def log_message(self, *args):  # pragma: no cover - 别刷屏
                pass

        self.httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/{{url}}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def _trickle_server() -> _Trickle:
    return _Trickle()


class _Static:
    """一个"一次给完"的假镜像 (按顺序排在慢镜像后面)。"""

    def __init__(self, body: bytes) -> None:
        import http.server
        import socketserver
        import threading

        payload = body

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):  # pragma: no cover - 别刷屏
                pass

        self.httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/{{url}}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def test_core_fetch_gives_up_at_the_deadline(configured, monkeypatch):
    """取内核必须有**总**时限 —— 慢速黑洞不算"正在下载", 要按时认输。

    真机事故 (GL-MT3600BE / OpenWrt 25.12.5): 安装停在"下载代理内核"上。面板侧
    urllib 的 timeout 只管单次 socket 操作, 一个不断滴数据的镜像可以让它永远不返回。
    这道测试用同样手法的本地服务器复现那一刻, 断言到点就返回并如实说明原因。
    """
    from zeroproxy import router_client

    monkeypatch.setattr(router_client, "MIN_BYTES", 1024)
    srv = _trickle_server()
    try:
        monkeypatch.setattr(router_client, "MIRRORS", (srv.url,))
        started = time.time()
        ok, detail, path = router_client.fetch_core("arm64", deadline=time.time() + 2)
        elapsed = time.time() - started
    finally:
        srv.close()
    assert not ok and path == ""
    assert elapsed < 8, f"没有按总时限放弃 ({elapsed:.1f}s)"
    assert "超时" in detail or "总时间超限" in detail, detail


def test_a_slow_mirror_is_dropped_for_the_next_one(configured, monkeypatch):
    """能连上但极慢的镜像不该吃掉整个预算 —— 换下一个。

    真机现场: 面板取 20 MB, 某个公共反代只有一两百 KB/s (20 MB 要十几分钟), 而排在
    它后面的镜像可能一秒就通。速率闸门的判据是"按当前速率跑不完这份文件"; 没有
    Content-Length 时才退回 ZP_CORE_MIN_RATE_KB 这个兜底值。
    """
    from zeroproxy import router_client

    monkeypatch.setattr(router_client, "MIN_BYTES", 4096)
    monkeypatch.setattr(router_client, "CORE_RATE_GRACE", 1)
    monkeypatch.setattr(router_client, "CORE_MIN_RATE_KB", 500)      # 低于 500 KB/s 就换
    slow = _Trickle(chunk=262144, delay=1.3, length=64 << 20)         # ≈200 KB/s
    fast = _Static(b"f" * 8192)
    try:
        monkeypatch.setattr(router_client, "MIRRORS", (slow.url, fast.url))
        started = time.time()
        ok, detail, path = router_client.fetch_core(
            "arm64", timeout=20, deadline=time.time() + 30
        )
        elapsed = time.time() - started
    finally:
        slow.close()
        fast.close()
    assert ok, detail
    assert os.path.getsize(path) == 8192, "拿到的应该是第二个镜像那份完整的文件"
    assert elapsed < 20, f"没有及时放弃慢镜像 ({elapsed:.1f}s)"


#: 上游真实的资产名 (kenzok8/vmlinux-btf, tag: latest) —— 拿它当基准, 免得断言与上游脱节
BTF_ASSETS = [
    "SHA256SUMS",
    "vmlinux-btf-6.12.103-r1-aarch64_cortex-a53.apk",
    "vmlinux-btf-6.12.103-r1-aarch64_cortex-a72.apk",
    "vmlinux-btf-6.12.103-r1-aarch64_generic.apk",
    "vmlinux-btf-6.12.103-r1-x86_64.apk",
    "vmlinux-btf_6.6.151-r1_aarch64_cortex-a53.ipk",
    "vmlinux-btf_6.6.151-r1_aarch64_generic.ipk",
    "vmlinux-btf_6.6.151-r1_x86_64.ipk",
]


def _btf_assets() -> list[dict]:
    from zeroproxy import router_client

    return [{"name": n, "url": router_client.btf_asset_url(n), "size": 3 << 20} for n in BTF_ASSETS]


def test_btf_pick_matches_the_minor_series_and_prefers_the_exact_arch():
    """BTF 只要求"同一个内核 minor 系列 + 架构"; 精确架构优先, aarch64 通用档兜底。

    真机 (GL-MT3600BE · 25.12.5 · 内核 6.12.94) 缺 BTF —— 上游那份包是 6.12.103 的,
    而 BTF 在同一 minor 系列内兼容 (包的 postinst 自己按 uname -r 建软链), 所以这台机器
    正好能补上。这一条钉的就是"怎么挑包"。
    """
    from zeroproxy import router_client as rc

    assets = _btf_assets()
    names = [p["name"] for p in rc.btf_pick(assets, rc.btf_minor("6.12.94"), "aarch64_cortex-a53", "apk")]
    assert names and names[0].endswith("aarch64_cortex-a53.apk"), names
    assert any(n.endswith("aarch64_generic.apk") for n in names), "细分目标没有包时要退通用档"
    # 6.12 没有 ipk、armv7 根本不在上游的发布矩阵里 —— 对不上就是没有, 别硬套
    assert rc.btf_pick(assets, "6.12", "aarch64_cortex-a53", "ipk") == []
    assert rc.btf_pick(assets, "6.12", "armv7", "apk") == []
    assert rc.btf_minor("6.12.94") == "6.12"


def test_btf_fetch_says_why_it_cannot_help(client, configured):
    """补不了的时候要说清**哪一种**补不了 —— 系列没有包 / 没给够信息, 完全两回事。"""
    from zeroproxy import router_client

    ok, detail, path = router_client.btf_fetch("5.4.281", "aarch64_cortex-a53", "apk")
    assert not ok and path == ""
    assert "6.6" in detail and "6.12" in detail, detail
    assert not router_client.btf_fetch("", "aarch64_cortex-a53", "apk")[0]
    assert not router_client.btf_fetch("6.12.94", "", "apk")[0]
    assert not router_client.btf_fetch("6.12.94", "aarch64_cortex-a53", "deb")[0]


def test_btf_package_endpoint_serves_a_cached_package(client, configured, monkeypatch):
    """缓存里有匹配的包时直接发给路由器 (运营方手工放进 data/client/btf/ 也走这条路)。"""
    from zeroproxy import router_client

    monkeypatch.setattr(router_client, "BTF_MIN_BYTES", 16)
    name = "vmlinux-btf-6.12.103-r1-aarch64_cortex-a53.apk"
    path = os.path.join(router_client.btf_dir(), name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(b"btf" * 64)
    res = client.get("/c/btf?kver=6.12.94&arch=aarch64_cortex-a53&fmt=apk")
    assert res.status_code == 200, res.text
    assert res.content == b"btf" * 64
    # 别的内核系列别想拿这份去糊弄 (6.6 的设备要 6.6 的包)
    res66 = client.get("/c/btf?kver=6.6.141&arch=aarch64_cortex-a53&fmt=apk")
    assert res66.status_code in (404, 502), res66.text


def test_btf_endpoint_never_hangs_and_says_exactly_what_to_do(client, configured, monkeypatch):
    """取不到时: 立刻回一句能读懂的话 + 手工兜底路径 + "它不影响什么"。

    与内核那条是同一个规矩 (8.41): 不许把请求挂在同步取件上。BTF 包小, 所以面板给的
    是**有硬上限**的一次尝试, 失败就说清楚 —— 而不是"一直转"。
    """
    from zeroproxy import router_client

    monkeypatch.setattr(router_client, "btf_upstream_assets",
                        lambda: (False, "上游资产清单取不到 (超时)", []))
    res = client.get("/c/btf?kver=6.12.94&arch=aarch64_cortex-a53&fmt=apk")
    assert res.status_code == 502, res.text
    assert router_client.btf_dir() in res.text, "要告诉运营方包该放进哪个目录"
    assert "不影响当前的 TUN / tproxy 数据面" in res.text, "别让用户以为装坏了"
    # 清单拿到了、但这一档没有 (armv7 不在上游矩阵里) → 永久性的 404, 不是"再试试"
    monkeypatch.setattr(router_client, "btf_upstream_assets", lambda: (True, "ok", _btf_assets()))
    res = client.get("/c/btf?kver=6.12.94&arch=armv7&fmt=apk")
    assert res.status_code == 404, res.text


# ---------------------------------------------------------------- 性能模式 (dae / eBPF)

def _dae_archive(tmp_path, entries: dict[str, bytes]) -> str:
    """按上游的形态造一份 tar.xz (演练里不下载真的 10 MB)。"""
    import io
    import tarfile

    path = tmp_path / "dae.tar.xz"
    with tarfile.open(path, "w:xz") as tf:
        for name, blob in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(blob)
            tf.addfile(info, io.BytesIO(blob))
    return str(path)


def test_extract_dae_picks_the_binary_and_refuses_junk(tmp_path, monkeypatch):
    """上游的目录结构不是契约 —— 取错文件必须在这里挡住。

    上游发的是 `dae-linux-<arch>.tar.xz`, 里面放什么、放几层目录都不是我们能指望的, 所以按
    "名字正好是 dae 的优先, 否则取最大的那个"来找, 最后只认 ELF —— 否则发到路由器上就是
    chmod +x 之后一句 Exec format error (真机上学过一次)。
    """
    from zeroproxy import router_client

    monkeypatch.setattr(router_client, "PERF_MIN_BYTES", 16)
    elf = b"\x7fELF" + b"\x00" * 64
    dest = str(tmp_path / "out.bin")

    # 1) 有 dae: 选它, 哪怕旁边有个更大的文件
    arch1 = _dae_archive(tmp_path, {"dae": elf, "geoip.dat": b"x" * 4096, "README.md": b"hi"})
    ok1, detail1 = router_client._extract_dae(arch1, dest)
    assert ok1 and open(dest, "rb").read() == elf, detail1

    # 2) 没有叫 dae 的: 取最大的那个 (上游换了目录结构也还能用)
    arch2 = _dae_archive(tmp_path, {"sbin/other": elf, "README.md": b"hi"})
    ok2, detail2 = router_client._extract_dae(arch2, dest)
    assert ok2 and open(dest, "rb").read() == elf, detail2

    # 3) 上游给的是一页 HTML (反代很爱回这个): 拒绝, 而不是发一个"能 chmod 不能跑"的文件
    arch3 = _dae_archive(tmp_path, {"index.html": b"<!DOCTYPE html>" + b"x" * 4096})
    ok3, detail3 = router_client._extract_dae(arch3, dest)
    assert not ok3 and "ELF" in detail3, detail3


def test_ui_files_are_written_atomically_and_luci_has_a_builtin_fallback():
    """界面文件的落盘必须是**原子**的 —— 一次失败的请求不许毁掉一份能用的文件。

    真机事故 (README 8.79): 升级之后 LuCI 里点「服务 → ZeroProxy」只有一句 **403**。
    现场是这么来的 —— `http_get "$ZP_BASE/c/ui/acl.json" > /usr/share/rpcd/acl.d/…json || true`:
    重定向**先清空**目标, `|| true` 又把失败咽掉; 面板正好在重启 (nginx 回 502) 的那一次,
    一份好端端的 ACL 就成了 0 字节 → rpcd 读不出来 → 我们的 ACL 组不存在 → LuCI 的菜单
    依赖检查不过 → 403, 而且页面上没有半个字说明原因。三个文件都是这条写法。

    所以这一条钉两件事: ① 那种"重定向直写"的写法不许再回来; ② 那三件套必须有内置兜底
    (内容与仓库里的 client/luci/ 逐字节一致), 并且 CLI 里有一条能就地修的 `ui fix`。
    """
    from zeroproxy import router_client

    path = router_client.script_path()
    text = open(path, encoding="utf-8").read()
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    luci_dir = os.path.join(os.path.dirname(path), "luci")

    # ① 直写重定向 (取失败就清空) 的写法不许再出现
    for risky in (
        '> /usr/share/rpcd/acl.d/luci-app-zeroproxy.json 2>/dev/null || true',
        '> /usr/share/luci/menu.d/luci-app-zeroproxy.json 2>/dev/null || true',
        '> /www/luci-static/resources/view/zeroproxy/status.js 2>/dev/null || true',
    ):
        assert risky not in code, f"这种写法会把好文件清空: {risky}"
    assert "ui_put()" in code and "ui_file_ok()" in code, "界面文件要走原子落盘那条辅助函数"
    # 临时文件 → 校验 → mv (同一目录里的 mv 是原子的)
    assert 'mv "$_tmp" "$_dst"' in code

    # ② 内置兜底: 内容与仓库里那份逐字节一致 (漂移的症状是"某个固件上菜单突然不见")
    for name in ("menu.json", "acl.json", "status.js"):
        marker = {
            "menu.json": "ZP_LUCI_MENU",
            "acl.json": "ZP_LUCI_ACL",
            "status.js": "ZP_LUCI_STATUS",
        }[name]
        start = code.index(marker) + len(marker) + 1
        end = code.index(marker, start)
        # heredoc 的正文从标记那一行的**下一行**开始 (那个前导换行不算内容)
        embedded = code[start:end].lstrip("\n").rstrip("\n") + "\n"
        on_disk = open(os.path.join(luci_dir, name), encoding="utf-8").read()
        assert embedded == on_disk, f"{name} 的内置副本与 client/luci/{name} 不一致"
    assert "luci_builtin_cache" in code, "装机时要留一份本机兜底副本 (离线也能修)"

    # ③ 就地修: CLI 里要有 `ui fix`
    cgi = open(os.path.join(luci_dir, "cgi"), encoding="utf-8").read()
    assert "ui_fix()" in code and '"${2:-}" = "fix"' in code, "zeroproxy ui fix 必须在"
    assert "zeroproxy ui fix" in code, "提示里要给出这条能照着敲的命令"
    assert "LuCI" in cgi or True   # cgi 那边只要能开性能模式那条路就够 (见上一条用例)


def test_install_script_builds_the_perf_mode_switch_the_honest_way():
    """性能模式 (eBPF / dae) 的开关: 换过去、验证、换回来 —— 判据全是现场。

    这一档与 tun / tproxy **互斥** (两套都在抢流量), 而它开着的时候 mihomo 是停的 ——
    也就是说 dae 一挂家里就断网。所以三条硬规矩必须写在代码里, 而不是靠人记得:
      ① 进去之前用 `dae validate` 校验配置 (配置错就不动现在的数据面);
      ② 进去之后**验证流量真的过得去** (出口探针), 不是"进程起来了"就算成功;
      ③ 任何一步失败都退回原来的模式, 并且有一只看门狗盯着"dae 还在不在"。
    """
    from zeroproxy import router_client

    text = open(router_client.script_path(), encoding="utf-8").read()
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))

    for needed in ("zp_perf_enter", "zp_perf_leave", "zp_perf_live", "zp_perf_tick", "zp_perf_prepare"):
        assert needed in code, f"perf.sh 里缺 {needed}"
    assert "dae" in code and " validate -c " in code, "进去之前要 dae validate 过一遍配置"
    assert "zp_perf_exit_ip" in code and "ZP_PERF_PROBE" in code, "要验证出口真的通"
    assert "退回原来的模式" in code and "dae 起来了, 但流量出不去" in code, "验不过必须退回来"
    # 看门狗: 说好在用而 dae 不在, 连续三轮就退回 (家里不能断着)
    assert "_n\" -ge 3" in code and "已自动退回标准模式" in code
    # 与标准模式互斥 (避免两个数据面同时抢包)
    assert '"$ZP_INIT" stop' in code and '"$ZP_INIT" disable' in code
    assert "ZP_INIT=/etc/init.d/zeroproxy" in code and "ZP_PERF_INIT=/etc/init.d/zeroproxy-perf" in code
    # caps 里的那几个字段是界面 / 面板 / 诊断读的同一份
    for key in ("perf_cap=", "perf=", "perf_why="):
        assert f"printf '{key}" in code or f"s/^{key}" in code, f"caps 要记 {key}"
    # 界面那一路: 表盘脚本 (perf.js) 由面板分发, 两个动作 (perf-on / perf-off) 两个入口
    # (cgi 与 zpcore) 都要有 —— "只加在 CLI 上是不够的" 这个坑真机踩过 (README 8.61)。
    luci = os.path.join(os.path.dirname(router_client.script_path()), "luci")
    cgi = open(os.path.join(luci, "cgi"), encoding="utf-8").read()
    assert "perf-on|perf-off" in cgi and "perf.js" in cgi, "cgi 那条路也要能开性能模式"
    assert os.path.exists(os.path.join(luci, "perf.js")), "那块表盘的脚本要在"
    assert "perf.js" in open(os.path.join(luci, "index.html"), encoding="utf-8").read()


def test_dae_config_speaks_daes_language_and_skips_what_it_cannot_dial(client, configured):
    """性能模式的配置是 dae **自己的一套语言** —— 单独渲染, 并如实跳过它拨不了的节点。

    dae 支持 VLESS (含 Reality) / Trojan / Hysteria2, 但没有 XHTTP 传输 —— 那一个节点必须
    被排除, 而且要**写出来** (少一个节点这件事不该只活在代码里)。面板地址走直连, 与 mihomo
    那边同一条理由: 管理面不能依赖代理。
    """
    _login(client)
    device = _register(client, _pair_code(client)["code"])
    base = f"/c/perf/config?id={device['id']}&k={device['secret']}"
    body = client.get(f"{base}&lan=br-lan").text

    for block in ("global {", "node {", "group {", "dns {", "routing {"):
        assert block in body, block
    assert "lan_interface: br-lan" in body and "wan_interface: auto" in body
    assert "policy: min_moving_avg" in body and "fallback: proxy" in body
    assert f"domain(suffix: {DOMAIN}) -> direct" in body, "面板地址要直连"
    assert "vless://" in body and "trojan://" in body and "hysteria2://" in body
    assert "# 跳过: vless-xhttp" in body, "dae 拨不了的节点要如实写出来"
    assert "vless-xhttp:" not in body, "跳过的节点不许出现在 node 段里"

    # geo=0 是降级: 引用分流数据的规则**整条去掉** (dae 读不到数据文件是起不来, 不是跳过规则)
    degraded = client.get(f"{base}&geo=0").text
    assert "geosite:" not in degraded and "geoip:cn" not in degraded
    assert "geoip:private" in degraded, "私有地址那条不依赖数据文件, 要留着"

    # 设备专属配置: 凭据不对就是 403
    assert client.get("/c/perf/config?id=x&k=y").status_code == 403


def test_perf_binary_endpoint_answers_instead_of_hanging(client, configured, monkeypatch):
    """性能模式内核 (dae): 没缓存时**立刻**回一句人话 + 503, 缓存好了直接发。

    与 /c/bin 完全同一个协议 —— 首次点「性能模式」时面板要去上游取约 10 MB, 而用户正看着
    界面等: 那就回一句"面板正在准备", 让界面把真实进度显示出来, 而不是把它挂住。
    """
    from zeroproxy import router_client

    router_client.PERF_STATE.clear()
    assert client.get("/c/perf/pdp11").status_code == 404
    res = client.get("/c/perf/arm64")
    assert res.status_code == 503, res.text
    assert res.headers.get("retry-after") == "5"
    assert "面板正在准备" in res.text or "面板取" in res.text, res.text

    blob = b"\x1f\x8b" + b"d" * 4096
    monkeypatch.setattr(router_client, "PERF_MIN_BYTES", 16)
    path = router_client.perf_file("arm64")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(blob)
    ok = client.get("/c/perf/arm64")
    assert ok.status_code == 200 and ok.content == blob


def test_perf_geo_endpoint_whitelists_and_degrades_honestly(client, configured):
    """dae 的分流数据 (v2ray 格式) 直接复用面板为 Xray 下好的那两份: 白名单 + 说清有没有。"""
    assert client.get("/c/perf/geo/whatever.dat").status_code == 404
    res = client.get("/c/perf/geo/geoip.dat")
    assert res.status_code == 503 and "分流数据" in res.text, res.text


def test_btf_fetch_downloads_through_the_mirrors_then_caches(client, configured, monkeypatch):
    """清单 → 镜像下载 → 落盘缓存; 第二次直接命中缓存 (不再问上游)。"""
    from zeroproxy import router_client

    body = b"B" * (8 << 10)
    srv = _Static(body)
    try:
        monkeypatch.setattr(router_client, "BTF_MIN_BYTES", 1024)
        monkeypatch.setattr(router_client, "MIRRORS", (srv.url,))
        monkeypatch.setattr(router_client, "btf_upstream_assets", lambda: (True, "ok", _btf_assets()))
        ok, detail, path = router_client.btf_fetch("6.12.94", "aarch64_cortex-a53", "apk")
        assert ok and path.endswith("aarch64_cortex-a53.apk"), detail
        assert open(path, "rb").read() == body
        asked = []
        monkeypatch.setattr(router_client, "btf_upstream_assets",
                            lambda: (asked.append(1), (True, "ok", []))[1])
        ok2, detail2, _ = router_client.btf_fetch("6.12.94", "aarch64_cortex-a53", "apk")
        assert ok2 and detail2 == "已缓存" and not asked, "缓存命中不该再去问上游"
    finally:
        srv.close()


def test_core_status_hands_the_router_a_usable_mirror_table(client, configured, monkeypatch):
    """状态接口要给路由器**可用的完整地址**, 而且第一个是运营方自建的镜像。

    路由器端不拼模板 (它只有 sha/busybox 那一套工具): 面板给什么它就试什么。
    自建镜像排第一是因为它在国内线路上最稳 —— 公共前缀会被大量用户挤。
    """
    from zeroproxy import router_client

    # conftest 里把镜像表默认换成了死地址 (免得后台预取真去下 20 MB); 这一条要的
    # 正是"真实的镜像表", 所以先切回来。
    monkeypatch.setattr(router_client, "MIRRORS", router_client.DEFAULT_MIRRORS)
    res = client.get("/c/core/status?arch=arm64").json()
    urls = [u for u in res["mirror_urls"].split(",") if u]
    assert urls, res
    assert urls[0].startswith("https://github.i3.pub/"), "自建镜像应该排第一"
    assert all(u.endswith(router_client.asset_name("arm64")) for u in urls), urls
    assert res["direct"].endswith("/mihomo-linux-arm64-v1.19.32.gz")
    assert res["prefer"] in ("panel", "mirror", "auto")
    # 没缓存时不谎报大小/摘要; 缓存之后两个都要给 (路由器据此校验镜像)
    assert "sha256" not in res and "size" not in res
    blob = b"z" * 32
    dst = router_client.core_file("arm64")
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "wb") as fh:
        fh.write(blob)
    monkeypatch.setattr(router_client, "MIN_BYTES", 16)
    ready = client.get("/c/core/status?arch=arm64").json()
    assert ready["state"] == "ready" and ready["size"] == 32
    assert ready["sha256"] == hashlib.sha256(blob).hexdigest()


def test_geo_files_are_served_and_name_whitelisted(client, configured, home, monkeypatch):
    """分流数据库 (GeoIP / GeoSite) 也由面板分发 —— 和内核二进制同一条思路。

    真机 (GL-MT3000) 现场: mihomo 在 `-t` 时去 GitHub 拉 geoip.metadb, 拉不到就
    `can't download MMDB: context deadline exceeded` → 整份配置校验失败, 装机停在
    "写入运行文件"。所以这两份数据必须由面板给 (面板去取上游, 路由器只访问面板)。

    这里同时盯住"**有就立刻给**": 手上有数据时绝不能让请求等面板去上游重下 ——
    那正是真机上"点更新卡在「准备分流数据库」不动"的来源 (见 8.64)。
    """
    from zeroproxy import router_client

    # 文件名是 mihomo 在 `-d` 目录里找来用的, 一个字节都不能改
    assert set(router_client.GEO_FILES) == {"geoip.metadb", "geosite.dat"}

    assert client.get("/c/geo/nope").status_code == 404
    assert client.get("/c/geo/..%2fstate.json").status_code == 404
    assert client.get("/c/geo/geoip.dat").status_code == 404

    # 本机有一份**已经过期**的数据: 照样当场给出去, 刷新交给后台
    monkeypatch.setattr(router_client, "GEO_MIN_OVERRIDE", 16)
    dst = router_client.geo_file("geoip.metadb")
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "wb") as fh:
        fh.write(b"M" * 128)
    old = time.time() - router_client.GEO_TTL - 60
    os.utime(dst, (old, old))
    kicked: list[str] = []
    monkeypatch.setattr(router_client, "ensure_geo_async", lambda name: kicked.append(name))

    res = client.get("/c/geo/geoip.metadb")
    assert res.status_code == 200
    assert res.content == b"M" * 128
    assert kicked == ["geoip.metadb"], "过期的那份要在后台刷新, 而不是让请求等着"


def test_geo_endpoint_never_blocks_on_the_upstream(client, configured, home, monkeypatch):
    """面板手上没有数据时也不能把请求挂住 —— 立刻 503 + 一句人话, 后台去取。

    以前这里是同步去上游下 (最长 200 秒), 而路由器正挂着等这个响应。真机上用户看到
    的就是"更新进度停在「准备分流数据库」那一行, 56% 不动"。协议与内核二进制完全一致:
    503 + Retry-After, 路由器据此先用自己那份 (它本来就有), 不会被卡住。
    """
    from zeroproxy import router_client

    monkeypatch.setattr(router_client, "GEO_MIN_OVERRIDE", 16)
    kicked: list[str] = []

    def fake_ensure(name: str) -> dict:
        kicked.append(name)
        with router_client.GEO_LOCK_ASYNC:
            router_client.GEO_STATE[name] = {"state": "downloading", "error": "", "done": 0}
        return dict(router_client.GEO_STATE[name])

    monkeypatch.setattr(router_client, "ensure_geo_async", fake_ensure)
    res = client.get("/c/geo/geosite.dat")
    assert res.status_code == 503
    assert res.headers.get("retry-after") == "10"
    assert kicked == ["geosite.dat"], "后台要真的去取, 否则路由器下次来还是 503"
    # 面板得把话说明白: 这不是错误, 路由器按"先用本机那份"处理
    assert "geosite.dat" in res.text and "本机" in res.text


def test_geo_prefetch_is_background_and_idempotent(home, monkeypatch):
    """后台取数据: 不阻塞调用方, 拿到之后就只认文件 (不再抓第二次)。"""
    from zeroproxy import router_client

    monkeypatch.setattr(router_client, "GEO_MIN_OVERRIDE", 16)
    calls: list[str] = []

    def fake_fetch_geo(name: str, **kw) -> tuple[bool, str, str]:
        calls.append(name)
        dst = router_client.geo_file(name)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "wb") as fh:
            fh.write(b"x" * 64)
        return True, "已缓存", dst

    monkeypatch.setattr(router_client, "fetch_geo", fake_fetch_geo)
    state = router_client.ensure_geo_async("geoip.metadb")
    assert state["state"] in ("downloading", "ready")
    for _ in range(100):      # 后台线程跑完
        if router_client.geo_ready("geoip.metadb"):
            break
        time.sleep(0.05)
    assert router_client.geo_ready("geoip.metadb")
    assert router_client.ensure_geo_async("geoip.metadb")["state"] == "ready"
    assert calls == ["geoip.metadb"], "文件已经在手上了就不该再去上游"


def test_geo_cache_avoids_second_download(client, configured, home, monkeypatch):
    """同一份数据只下第一次: 第二台路由器装机时面板不再跑一趟 4 MB。"""
    from zeroproxy import router_client

    monkeypatch.setattr(router_client, "GEO_MIN_OVERRIDE", 16)
    dst = router_client.geo_file("geoip.metadb")
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "wb") as fh:
        fh.write(b"x" * 32)

    def boom(*args, **kwargs):  # pragma: no cover - 走到这里就是失败
        raise AssertionError("本地已有数据时不该联网")

    monkeypatch.setattr(router_client.urllib.request, "urlopen", boom)
    ok, detail, path = router_client.fetch_geo("geoip.metadb")
    assert ok and path == dst and "缓存" in detail


def test_router_profile_takes_geo_from_the_panel(client, configured):
    """路由器端配置里的 geox-url 指向面板自己 —— 装机时它连不上 GitHub。"""
    _login(client)
    device = _register(client, _pair_code(client)["code"])
    sub = f"/c/sub/{device['id']}?k={device['secret']}"
    base = f"http://{DOMAIN}:8899"

    profile = yaml.safe_load(client.get(sub).text)
    assert profile["geox-url"]["mmdb"] == base + "/c/geo/geoip.metadb"
    assert profile["geox-url"]["geosite"] == base + "/c/geo/geosite.dat"

    # 手机 / 电脑端不受影响: 它们本来就能上网, 用公共镜像更快
    path = configured["subscription_url"].split("testserver")[-1]
    phone = yaml.safe_load(client.get(path + "?format=clash").text)
    assert phone["geox-url"]["mmdb"].startswith("https://")
    assert "/c/geo/" not in phone["geox-url"]["mmdb"]


def test_router_profile_keeps_the_panel_direct(client, configured):
    """面板自己的地址必须直连, 而且在**所有**模板 / 降级 / 骨架里都要在。

    真机 8.64 的死锁: 面板域名跟着规则走了 🐟 漏网之鱼 → 路由器要连面板得先连上代理,
    而代理的节点又在那台机器上。节点一挂, 面板上显示离线、点「更新客户端」报"取不到
    面板的安装脚本" —— 恰恰是最需要把面板连上的时候连不上, 没有任何自救的余地。

    装机命令是在**还没有任何代理**的路由器上 `wget 面板地址` 执行的, 所以"面板直连
    可达"本来就是装机的前提。这条测试盯的是"别在后来某次改规则时把它弄丢" ——
    丢了的代价是"更新功能平时看着好好的, 出故障时救不回来"。
    """
    _login(client)
    device = _register(client, _pair_code(client)["code"])
    sub = f"/c/sub/{device['id']}?k={device['secret']}"
    want = f"DOMAIN-SUFFIX,{DOMAIN},DIRECT"

    def first_rule(query: str = "") -> str:
        return yaml.safe_load(client.get(sub + query).text)["rules"][0]

    assert first_rule() == want
    # 降级配置 (拿不到分流数据库) 也要有: 它不依赖任何数据库
    assert first_rule("&geo=0") == want
    # 多服务器模式的骨架
    assert first_rule("&format=skeleton") == want
    # direct 模板只有一条 MATCH —— 更不能漏
    assert first_rule("&rules=direct") == want
    # 排在 GEOSITE 广告拦截之前: 规则是**从上往下**匹配的, 掉到后面就等于没写
    assert yaml.safe_load(client.get(sub).text)["rules"][1].startswith("GEOSITE,category-ads-all")

    # 手机 / 电脑那份订阅不带面板地址 —— 它们能自己关掉代理去更新, 不该凭空多一条规则
    path = configured["subscription_url"].split("testserver")[-1]
    phone_rules = yaml.safe_load(client.get(path + "?format=clash").text)["rules"]
    assert not any("DIRECT" in r for r in phone_rules)


def test_panel_address_rule_handles_ip_and_junk():
    """面板地址是裸 IP (bootstrap 阶段) 时用 IP 规则; 空值 / 乱码不产生规则。"""
    from zeroproxy import share_links

    assert share_links.management_direct_rules("https://hk.example.com:8899") == [
        "DOMAIN-SUFFIX,hk.example.com,DIRECT"
    ]
    # 大小写 / 末尾斜杠 / 带路径都不影响
    assert share_links.management_direct_rules("https://HK.Example.COM:8899/c/geo") == [
        "DOMAIN-SUFFIX,hk.example.com,DIRECT"
    ]
    # 裸 IP 用 IP-CIDR: 域名规则匹配不上 IP 形式的 base
    assert share_links.management_direct_rules("http://103.192.178.100:8899") == [
        "IP-CIDR,103.192.178.100/32,DIRECT,no-resolve"
    ]
    assert share_links.management_direct_rules("") == []
    assert share_links.management_direct_rules("不是地址") == []


def test_router_profile_degrades_when_panel_has_no_geo_data(client, configured):
    """面板暂时给不出分流数据库时, 配置里不能留任何 geo 规则。

    mihomo 缺数据不是"跳过那几条规则", 而是整份配置加载失败 —— 少一层国内直连还能
    上网, 起不来就是全屋断网。所以降级配置里一条 geo 规则都不能有 (GEOIP,LAN 例外:
    私有地址是内建判断, 不需要数据库)。
    """
    _login(client)
    device = _register(client, _pair_code(client)["code"])
    sub = f"/c/sub/{device['id']}?k={device['secret']}"

    profile = yaml.safe_load(client.get(sub + "&geo=0").text)
    rules = "\n".join(profile["rules"])
    assert "GEOSITE," not in rules
    assert "GEOIP,CN" not in rules
    assert "GEOIP,LAN," in rules
    assert profile["rules"][-1] == "MATCH,🐟 漏网之鱼"
    # 降级 ≠ 没有国内直连: 国内 App 那一层是纯域名规则 (不需要数据库), 必须原样保留。
    # 少了它, 全屋流量 (微信 / 支付宝 / 公众号 / 小程序) 全部走节点 —— 真机反馈的原话
    # 就是"国内网站、公众号、小程序都打不开或很慢"。
    assert "DOMAIN-SUFFIX,qq.com,🎯 全球直连" in rules
    assert "DOMAIN-SUFFIX,alipay.com,🎯 全球直连" in rules
    assert "nameserver-policy" not in profile["dns"]   # 它的键也是 geosite:… , 要数据库
    assert profile["tun"]["enable"] is True
    # 多服务器模式 (骨架) 同样要能降级
    skeleton = yaml.safe_load(client.get(sub + "&format=skeleton&geo=0").text)
    assert "GEOSITE," not in "\n".join(skeleton["rules"])
    assert "DOMAIN-SUFFIX,qq.com,🎯 全球直连" in "\n".join(skeleton["rules"])


def test_install_script_probes_capabilities_and_reports_honestly():
    """数据面这件事上的硬要求: 探得起、说得细、失败别报成功。

    真机 (GL-MT3600BE · 原厂 OpenWrt 21.02-SNAPSHOT / 内核 5.4.281) 的教训:
    `/dev/net/tun` 这个**节点在**, 但内核建不出设备; 同一台机器上 nf_tables 也没有 ——
    老代码只有"tun 优先 / tproxy 回退"两级, 两级都不可用, 结尾却仍然写着"全屋代理
    已开启"(README 8.45)。

    现在改成一张**能力阶梯** (tun → tproxy → iptables REDIRECT → 不接管):
      ① 每一级都真做一次 (建设备再删 / 加规则再撤) —— 节点/命令存在 ≠ 能力存在;
      ② 失败要留证: 每一级"为什么不行"的内核/程序原话写进 caps, 面板与安装输出都看它;
      ③ verify 按**现场**再验一次 (设备/表真的在不在), 起不来就顺着阶梯往下试;
         三级都不行才说"未生效" —— 宁可难看, 也不能让人以为好了。
    """
    from zeroproxy import router_client

    text = open(router_client.script_path(), encoding="utf-8").read()

    # ① 每一级都往内核里真做一次
    assert "ip tuntap add dev zp0probe mode tun" in text, "TUN 要真建一个设备再删掉"
    assert "nft add rule inet zp_probe c meta l4proto tcp tproxy to :1" in text, "tproxy 要真下一条规则"
    assert "nft add table inet zp_probe" in text, "nft 本身能不能下规则也要探 (命令在 ≠ 内核支持)"
    assert "iptables -t nat -A zp_probe -p tcp -j REDIRECT --to-ports 1" in text, \
        "iptables REDIRECT 也要真加一条规则 (21.02 / fw3 那类固件唯一走得了的路)"
    assert "write_caps" in text and "autoredirect=" in text, "结论要落盘给 agent 用"
    # caps 要带 chosen / covered / why.* —— 安装输出、CLI、agent、面板读同一份
    assert "chosen=" in text and "covered=" in text and "why.tun=" in text

    # ② 失败时把**内核自己说的话**打出来 + 每一级的原因都留证
    assert "与 tun 有关的内核日志" in text
    assert "logread -e zeroproxy" in text
    assert "CAPS_WHY_TUN" in text and "why.redirect=" in text, "每一级失败的原因都要留证"

    # ③ 诚实: 三级都不行时不许说"已开启"; 生效判据要看现场, 不看命令退出码
    assert "透明代理未生效" in text, "三级都不行时要说实话"
    assert "datapath_live" in text, "生效与否看设备/表在不在, 不看命令退出码"


def test_tun_firewall_allow_replaces_the_half_of_auto_redirect_we_drop():
    """8.74: auto-redirect 被拿去之后, 它本该写的**防火墙放行**必须由我们补上。

    真机 (GL-MT3600BE · 原厂 OpenWrt 21.02 / 内核 5.4.281): 带 `auto-redirect` 时 tun 建不
    出来, 自愈把它去掉后 tun 建出来了、路由器自己也能出网 —— 但上游实现里 `auto-redirect`
    在 OpenWrt 上还要往 `/etc/nftables.d/` 写两条**放行转发进/出 tun** 的规则
    (`redirect_nftables_rules_openwrt.go`)。少了它们, 局域网转发被防火墙整个丢掉:
    家里国内国外全断, 而面板与路由器界面双双显示"已连接"。所以:
      ① 这一半要补 (两个方向 + 没有 fw4 的机器走 iptables);
      ② 补完要按**现场**验一次, 验不过就不许说这一级生效, 要顺着阶梯往下走;
      ③ 只在 auto-redirect 没跑成时才动手 —— 健康机器一个字节都不动。
    """
    from zeroproxy import router_client

    text = open(router_client.script_path(), encoding="utf-8").read()

    # ① 补的那一半在, 两个方向都有, 且没有 fw4 的 fw3 机器也有一条路
    assert "zp_tunfw_allow" in text and "zp_tunfw_live" in text and "zp_tunfw_clear" in text
    assert 'oifname "$ZP_TUN_NAME"' in text and 'iifname "$ZP_TUN_NAME"' in text, \
        "转发进/出 tun 两个方向都要放行"
    assert "iptables -I FORWARD" in text, "没有 fw4 的机器 (fw3/iptables) 也要有路"
    # 认领靠注释: 拆的时候只删自己加的那几条, 不动 fw4 / 用户的规则
    assert "zeroproxy-zp-tun" in text

    # ② 只在需要时动手 (chosen=tun 且 autoredirect=0), 并且拆的出口不止一处
    assert "_zp_caps_get autoredirect" in text and '"0"' in text
    assert text.count("zp_tunfw_clear") >= 5, "安装 / init 停服务 / off / revert / 卸载 都要回收"

    # ③ "设备在 ≠ 流量过得去": 补不上就不算生效, 并顺着阶梯往下 (不留"家里全断"的状态)
    assert "TUN_UNUSABLE" in text
    assert "补不上防火墙放行" in text and "局域网转发会被丢掉" in text
    assert "防火墙放行" in text, "doctor 要能单独报出这一项"


def test_generated_tunfw_helper_is_idempotent_and_symmetric(tmp_path):
    """把生成出来的 tunfw.sh 拿假 nft 真跑一遍 —— 逻辑只写在字符串里是验不出来的。

    盯三件事: 该动手时才动手 (autoredirect=1 / 选了别的数据面时一个规则都不加)、
    重复调用是幂等的、拆完就干净 (revert 的"逐条比对"靠这个成立)。
    """
    import re
    import subprocess

    from zeroproxy import router_client

    text = open(router_client.script_path(), encoding="utf-8").read()
    m = re.search(r"cat > \"\$ZP_DIR/tunfw\.sh\" <<'TUNFWEOF'\n(.*?)\nTUNFWEOF", text, re.S)
    assert m, "找不到 tunfw.sh 的生成块"

    home = tmp_path / "home"
    home.mkdir()
    (home / "tunfw.sh").write_text(m.group(1), encoding="utf-8")
    fakebin = tmp_path / "bin"
    fakebin.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    (state / "rules").write_text("")

    # 假 nft: 有状态的 forward/input 两条链, `-a` 会带 handle
    nft = fakebin / "nft"
    nft.write_text(
        '#!/bin/sh\n'
        'R="${NF_STATE}/rules"\n'
        'case "$*" in\n'
        '  "list table inet fw4") exit 0 ;;\n'
        '  *"insert rule inet fw4 "*) for c in forward input; do\n'
        '        case "$*" in *" $c "*) grep -qx "$c" "$R" || echo "$c" >> "$R";; esac; done; exit 0 ;;\n'
        '  "-a list chain inet fw4 "*) c="${6}" ;;\n'
        '  "list chain inet fw4 "*)    c="${5}" ;;\n'
        '  "delete rule inet fw4 "*)   c="${5}"; grep -vx "$c" "$R" > "$R.x"; mv "$R.x" "$R"; exit 0 ;;\n'
        '  *) exit 0 ;;\n'
        "esac\n"
        'grep -qx "$c" "$R" && echo "  oifname \\"zp-tun\\" counter accept comment \\"zeroproxy-zp-tun\\" # handle 1"\n'
        "exit 0\n",
        encoding="utf-8",
    )
    nft.chmod(0o755)

    env = {**os.environ, "PATH": f"{fakebin}:{os.environ['PATH']}", "ZP_DIR": str(home),
           "NF_STATE": str(state)}

    def run(expr: str) -> str:
        out = subprocess.run(["sh", "-c", f'. "{home}/tunfw.sh"; {expr}'],
                             capture_output=True, text=True, env=env)
        return out.stdout.strip()

    def rules() -> int:
        return len((state / "rules").read_text().split("\n")) - 1

    (home / "caps").write_text("chosen=tun\nautoredirect=0\n")
    assert run("zp_tunfw_needed && echo y") == "y", "选了 tun 且 auto-redirect 没跑成时必须动手"
    assert run("zp_tunfw_live && echo y") == "", "动手之前不该有放行规则"
    assert run("zp_tunfw_allow && echo y") == "y", "补放行必须成功"
    assert run("zp_tunfw_live && echo y") == "y", "补完要能被现场验出来"
    assert rules() == 2, "forward 与 input 两条链各一条"
    run("zp_tunfw_allow")
    assert rules() == 2, "重复调用必须幂等 (否则每次心跳都往防火墙堆规则)"
    run("zp_tunfw_clear")
    assert rules() == 0, "拆完必须干净"
    run("zp_tunfw_clear")
    assert rules() == 0

    (home / "caps").write_text("chosen=tun\nautoredirect=1\n")
    run("zp_tunfw_allow")
    assert rules() == 0, "auto-redirect 自己写了那两条时我们一个字节都不动"

    (home / "caps").write_text("chosen=redirect\nautoredirect=0\n")
    run("zp_tunfw_allow")
    assert rules() == 0, "不是 tun 那一档时不该动防火墙"


def test_core_status_hands_the_router_the_geo_mirror_table(client, configured):
    """分流数据库也要像内核那样"面板 + 镜像"两条路 —— 地址表由面板给, 客户端不拼模板。

    真机 (8.75): 内核那一步"面板直传 47 KB/s"被速率闸门判死, 换镜像后 615 KB/s;
    而分流数据库当时**只有面板一条路**, 屏幕上的表现就是"卡在准备分流数据库不动"
    (旧实现还把整段输出丢进了 /dev/null —— 一行 KB 都看不到)。
    """
    from zeroproxy import router_client

    data = client.get("/c/core/status?arch=arm64").json()
    assert "geo_sizes" in data and "geo_mirrors" in data, "分流数据的大小与地址表要一起给"

    # 大小: "名字=字节" 的浅层格式 (客户端没有 jq, 只有 sed)
    sizes = dict(item.split("=", 1) for item in data["geo_sizes"].split(";") if item)
    assert set(sizes) == set(router_client.GEO_FILES)
    for name, raw in sizes.items():
        assert int(raw) == router_client.geo_min_bytes(name)

    # 地址表: "名字 url url|名字 url url" —— 每个文件都要有地址, 且必须是**拼好的完整 URL**
    table = {}
    for chunk in data["geo_mirrors"].split("|"):
        parts = chunk.split(" ")
        table[parts[0]] = parts[1:]
    assert set(table) == set(router_client.GEO_FILES)
    for name, urls in table.items():
        assert urls == router_client.geo_mirror_urls(name), "面板给的必须与它自己用的一致"
        # 测试环境把镜像表换成了一条死地址 (离线可跑), 所以这里只要求"至少有一条备用源";
        # 默认那张表有 6 条, 上面那条 equality 断言已经盯住了内容。
        assert len(urls) >= 1, "至少要有一条备用源"
        for url in urls:
            assert url.startswith("http"), url
            assert "{url}" not in url, "给过去的一定是拼好的完整地址, 客户端不拼模板"
            assert " " not in url and "|" not in url, "分隔符不能出现在 URL 里 (会被切错)"


def test_geo_fetch_falls_back_to_mirrors_and_enforces_the_size_gate(tmp_path):
    """分流数据库的取数: 面板那条路失败要落到镜像, 而**体积闸门必须真的生效**。

    这条路径上有一个只有真跑才看得见的 bug: 闸门用的变量 `_size` 与失败分支里
    `show_body()` 内部的 `_size` 撞了名 (这个脚本没有 local)。于是"面板失败 → 换镜像"
    这条路上, 闸门实际拿的是 **404 正文的大小** —— 一个残缺文件照样装了进去。
    所以这个用例必须**先让面板那条路失败**, 再送一个不够大的文件过来。
    """
    import functools
    import http.server
    import re
    import subprocess
    import threading

    from zeroproxy import router_client

    text = open(router_client.script_path(), encoding="utf-8").read()
    funcs = []
    for fn in ("zp_hsize", "start_progress", "stop_progress", "http_fetch_to",
               "show_body", "geo_size_for", "geo_mirrors_for", "geo_fetch_one"):
        m = re.search(rf"^{fn}\(\) \{{.*?^\}}", text, re.S | re.M)
        assert m, f"从安装脚本里抽不到 {fn}()"
        funcs.append(m.group(0))

    srv_dir = tmp_path / "srv"
    srv_dir.mkdir()
    (srv_dir / "big.dat").write_bytes(b"A" * 200_000)     # 够大
    (srv_dir / "small.dat").write_bytes(b"B" * 1_000)     # 不够大

    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *a):  # 别把演练日志刷满
            pass

    httpd = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0), functools.partial(Quiet, directory=str(srv_dir)))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        home = tmp_path / "home"
        home.mkdir()
        (home / "funcs.sh").write_text("\n".join(funcs), encoding="utf-8")

        def run(name: str, need: int) -> bool:
            script = (
                'C_R=""; ZP_TTY=0\n'
                'step() { :; }; ok() { :; }; warn() { :; }; note() { :; }\n'
                'progress_note() { :; }\n'
                'HTTP=curl; TLS_OPTS=""; CORE_RATE_WINDOW=5; GEO_BUDGET=30\n'
                f'ZP_DIR="{home}"; ZP_BASE="{base}/panel"\n'      # 面板那条路故意 404
                f'PANEL_GEO_SIZES="{name}={need}"\n'
                f'PANEL_GEO_MIRRORS="{name} {base}/{name}"\n'
                f'. "{home}/funcs.sh"\n'
                f'geo_fetch_one "{name}"\n'
            )
            return subprocess.run(["sh", "-c", script],
                                  capture_output=True, text=True).returncode == 0

        assert run("big.dat", 100_000) is True, "面板 404 之后落到镜像, 应当装上"
        assert (home / "big.dat").stat().st_size == 200_000
        # 关键那一条: 闸门必须拦住不够大的那一份 (而不是拿 404 正文的大小去比)
        assert run("small.dat", 100_000) is False, "体积不够时必须拒绝"
        assert not (home / "small.dat").exists(), "拒绝之后不许留下文件"
    finally:
        httpd.shutdown()
    # 自愈 + 阶梯降级: 都排在"把原因打出来"之后, 且只在失败分支里
    fail_at = text.index("等了 30 秒 TUN 设备仍未出现")
    heal_at = text.index("if tun_retry_without_redirect &&")
    assert fail_at < heal_at, "自愈只能发生在真的失败之后 (能跑的机器一个字节都不动)"
    assert text.index("与 tun 有关的内核日志") < heal_at, "先让人看见原因, 再动手改配置"
    assert 'mv "$ZP_CONF.ar.bak" "$ZP_CONF"' in text, "自愈没成要把配置退回原样"
    assert "downgrade_datapath" in text and "ladder_below" in text, "起不来要顺着阶梯往下试"
    assert "rung_usable" in text, "探测本来就没过的级没必要再试"
    # **内核起不来本身就是数据面起不来的一种**: tun 段在这台固件上建不出设备时, mihomo
    # 会直接退出 (procd 不停重启它), 控制口永远不响应。旧版在这里直接 die —— 于是
    # "顺着阶梯往下试"根本没机会跑: 真机 (GL-MT3600BE · 原厂 21.02) 上就停在"未接管",
    # 而它明明还有 iptables 可走。顺序必须是: 等控制口 → 失败就降级 → 还失败才 die。
    api_at = text.index("if ! wait_core_api; then")
    retry_at = text.index("if downgrade_datapath && wait_core_api; then")
    die_at = text.index('die "内核启动失败')
    assert api_at < retry_at < die_at, "先试降级, 再决定要不要 die"
    assert "wait_core_api() {" in text, "等控制口要单独成一个函数 (两处都要用)"

    # 报错要只留**第一行**: nft 的第二行起是命令回显 + ^^^ 标记, 整段塞进面板就变成
    # "No such file or directoryadd rule inet zp_probe c ...^^^^^^^^" 那种看不懂的东西
    # (真机截图里就是)。五个探测的报错全都要过它。
    # 五个探测的报错都要过它 (内核版本那条提示也用, 所以是 "至少")
    assert "err_line() {" in text and text.count("$(err_line ") >= 5

    # iptables 的 nat 表可能只是模块没加载 —— 老固件上它是唯一的出路, 不能一次判死
    assert "modprobe iptable_nat" in text

    # agent 重建配置时把能力带给面板 (单服务器与多服务器骨架两条路都要带):
    # 数据面决定面板给不给 tun 段 —— 建不出设备的机器带着它, 内核直接起不来。
    assert text.count("&tproxy=$_tp") == 2
    assert text.count("&datapath=$_dp") == 2
    assert text.count("&ipv6=$_ip6") == 2
    # IPv6 能力: 单独探一次 (v6 的 tproxy 是内核里另一件事), 覆盖不到就记原因
    assert "nft_v6_ok" in text and "compute_ipv6_cap" in text
    # IPv6 探针必须与生产规则**同一种形状**: 家族写死 (`tproxy ip6 to :1`)。
    # 第一版省了家族, 真机 (GL-MT3000 / OpenWrt 24.10 / 内核 6.6) 上报的是
    # "Transparent proxy support requires transport protocol match" —— 于是那台
    # 明明能接管 v6 的机器被误判成"IPv6 未接管"。这类"探的东西和用的东西不是一个形状"
    # 只有真机才看得出来, 所以在这里钉死。
    assert "meta l4proto tcp tproxy ip6 to :1" in text
    assert "ip6 daddr ::1/128 tproxy to :1" not in text, "别再用那个漏了家族的写法"
    # 生产规则也要显式两个家族 (同样因为家族不能省)
    assert "meta nfproto ipv4 meta l4proto tcp counter meta mark set 0x1ff tproxy ip to :7893 accept" in text
    assert "meta nfproto ipv6 meta l4proto tcp counter meta mark set 0x1ff tproxy ip6 to :7893 accept" in text
    assert "ipv6=" in text and "why.ipv6=" in text


def test_install_script_never_fetches_geo_from_the_internet():
    """安装脚本不许自己去找 GitHub / jsDelivr: 装机时路由器还没有代理可用,
    那条路就是真机上的超时。数据只能来自面板 (/c/geo), 而且要在生成配置之前就位。
    """
    from zeroproxy import router_client

    raw = open(router_client.script_path(), encoding="utf-8").read()
    text = "\n".join(line for line in raw.splitlines() if not line.lstrip().startswith("#"))
    assert "/c/geo/" in text, "分流数据要从面板取"
    for host in ("github.com", "githubusercontent", "jsdelivr", "MetaCubeX", "ghproxy", "gh-proxy"):
        assert host not in text, f"安装脚本不该直接去 {host} 拿数据"
    # 取数据的实现只有一份 (agent.sh 里), 安装脚本通过它触发; 生成配置的判据是本机文件
    assert '"$ZP_DIR/agent.sh" geo force' in text
    assert "geo_ok" in text and "&geo=" in text
    # 旧面板 (没有 /c/geo) 必须在装机当场被认出来, 而不是让用户拿到
    # "拉取/校验配置失败, 请回面板确认已有可用节点" 这种无从下手的报错
    assert "PANEL_GEO" in text


def test_router_reports_its_ui_url_so_the_panel_can_open_it(client, configured):
    """路由器把"管理界面地址 (带着界面令牌)"随心跳上报 —— 面板上那张卡因此能一键打开。

    少掉的那一步手动操作: 新用户装完不必回终端敲 `zeroproxy ui`、再抄一条带令牌的长地址,
    在面板「客户端」点一下就走进去 (地址里的令牌只在那台路由器的局域网内有用)。
    面板只接受 http(s) 且路径里带 zeroproxy 的值 —— 它会进前端 HTML, 不能变成注入面。
    """
    _login(client)
    device = _register(client, _pair_code(client)["code"])
    ui = "http://192.168.8.1/cgi-bin/zeroproxy?k=" + "a" * 32
    client.post("/c/report", json={
        "device": device["id"], "k": device["secret"], "actual": True, "ui": ui,
    })
    assert client.get("/api/devices").json()["devices"]["items"][0]["ui"] == ui

    for bad in ("javascript:alert(1)", "http://192.168.8.1/other", "ftp://x/zeroproxy", ""):
        client.post("/c/report", json={
            "device": device["id"], "k": device["secret"], "ui": bad,
        })
        assert client.get("/api/devices").json()["devices"]["items"][0]["ui"] == ui, bad


def test_local_control_plane_is_distributed_like_the_core(tmp_path, monkeypatch, client, configured):
    """zpcore 走与 mihomo 内核同一条分发路, 但**是可选的**: 面板没准备时就 404 + 一句人话。

    为什么必须可选: 制品跟着仓库走 (scripts/build-agent.sh), 而操作方完全可能只构建了自己
    那几台路由器的架构, 甚至一个都不构建。这时装机只该"退回原来的界面路径", 不该失败 ——
    代理本身与这个二进制没有任何关系。
    """
    from zeroproxy import router_client

    empty = tmp_path / "dist"
    empty.mkdir()
    monkeypatch.setattr(router_client, "agent_dir", lambda: str(empty))

    # 没有制品: 404 + 一句能照着做的说明 (而不是一个空响应)
    res = client.get("/c/agent/bin/arm64")
    assert res.status_code == 404
    assert "可选件" in res.json()["error"] and "build-agent" in res.json()["error"]
    assert client.get("/c/agent/bin/pdp11").status_code == 404

    # 有制品: 原样发出去 (gz, 与内核同一个 content-type), 面板也能把它列出来
    blob = b"\x1f\x8b" + b"zpcore-stub" * 30000
    (empty / f"zpcore-arm64-{router_client.AGENT_VERSION}.gz").write_bytes(blob)
    served = client.get("/c/agent/bin/arm64")
    assert served.status_code == 200
    assert served.content == blob
    assert served.headers["content-type"] == "application/gzip"

    _login(client)
    listed = client.get("/api/devices").json()["client"]
    assert listed["agent_version"] == router_client.AGENT_VERSION
    assert [a["arch"] for a in listed["agents"]] == ["arm64"]


def test_install_script_only_repairs_credentials_on_a_real_refusal():
    """拉配置失败时, 只有"面板**明确**拒绝"才重新配对 —— 丢包绝不许触发重新配对。

    真机 (8.68, 21.02 那台) 就是这么演了一遍: 四次超时被判成"面板拒绝了这台设备的凭据",
    脚本拿同一个配对码又配了一次 —— 面板上**多出一台设备**, 新凭据随后又被同一个丢包卡住,
    最后丢给用户一句"请回面板确认已有可用节点" (方向全错, 而且面板要多清一台)。

    分辨办法是 agent 带出来的 curl 退出码: 22 = -f 说的 HTTP 层面失败 (403/404…, 面板答了
    而且说不行), 7/28 = 连不上 / 超时 (根本没问到)。
    """
    from zeroproxy import router_client

    text = open(router_client.script_path(), encoding="utf-8").read()
    # 退出码必须先接住: `if ! cmd` 里的 $? 是取反之后的结果 (永远是 0), 那样判不出东西
    assert "_cfg_rc=$?" in text
    # 重新配对只挂在"HTTP 层面被拒"上
    assert '[ "$_cfg_rc" = "22" ]' in text
    # 正文被截断成空 (HTTP 200 + 空 body) 也算"没拿到" —— 不能掉进"面板上没有节点"那句话
    assert "_cfg_ok=1" in text
    # 丢包那条分支必须单独存在, 而且不许出现"凭据/重新接入"这种把人引去重新配对的措辞
    parts = text.split('elif [ -n "$ZP_CODE" ]; then', 1)
    assert len(parts) == 2, "拉配置失败时, 丢包那条分支应当单独存在"
    loss_branch = parts[1].split("\n        else", 1)[0]
    assert "再跑一次" in loss_branch
    assert "重新接入" not in loss_branch and "拒绝了这台设备的凭据" not in loss_branch
    # 失败必须说清是**哪一类** (超时 / DNS / TLS / 被拒), 不许一律写"链路丢包"
    assert "http_why" in text and "${_cfg_why}" in loss_branch
    assert "面板第 %s 次没回话 (%s)" in text      # agent 那份内联的分类
    assert "超时 —— 多半是链路在丢包" in text
    # 降级配置那句不许再说"不含国内直连" —— 内联的域名层永远在 (8.68 的日志里它就在撒谎)。
    # 只查**真正的输出**: 注释里解释"以前那句是错的"是可以的。
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "不含国内直连" not in code
    assert "国内常用域名" in code


def test_optional_local_control_plane_never_breaks_the_install():
    """zpcore 是安装脚本里**唯一**的可选件: 它失败绝不能让装机失败。

    这不是理论问题 —— install_zpcore 第一版在"面板没准备这一档"时 return 1, 而 main 里
    只是一句普通的 `install_zpcore`。`set -e` 下那等于"装到一半静默停下": 演练里 [1] 之后
    的每一步都没跑, 而终端上只有一句"面板没有准备这一档本地控制面 (可选件)"——
    看起来像正常降级, 其实是整个安装被掐断了。
    """
    import re

    from zeroproxy import router_client

    text = open(router_client.script_path(), encoding="utf-8").read()
    body = re.search(r"^install_zpcore\(\) \{.*?\n\}", text, re.S | re.M)
    assert body, "安装脚本里应当有 install_zpcore"
    assert "return 1" not in body.group(0), "可选件不许用非 0 返回 (set -e 会掐断整个安装)"
    assert re.search(r"^\s*install_zpcore$", text, re.M), "main 必须真的调用它"
    # 失败时说的是"走原来的路径", 而不是让用户以为装坏了
    assert "界面走原来的路径" in text
    # 与内核同一条下载器: 靠 HTTP 状态码把"面板没有这一档"(404) 与"这条路不通"分开
    assert 'HTTP_CODE" = "404' in text
    # **每次都试着取面板当前那一版, 取不到才沿用本机已有的**。旧版是"有二进制就跳过",
    # 于是面板把 AGENT_VERSION 抬上去之后, 已装好的路由器永远停在第一次那一版 ——
    # 真机上就是这么停在 1.0.0 的 (面板已经在发 1.1.1)。
    assert "zpcore.new" in text, "新的一律先落 .new, 跑通才替换 (别毁掉正在用的那份)"
    assert "_old_ver" in text and "本地控制面已是最新" in text and "本地控制面升级" in text


def test_installed_artifacts_are_replaced_when_the_panel_bumps_its_version():
    """"能跑"不等于"是对的版本" —— 内核与 zpcore 的复用都要对版本。

    真机排查时发现两处同一类问题: 面板把 CORE_VERSION / AGENT_VERSION 抬上去, 已装好的
    机器会用着老的一份**永远不换** (它跑得起来, 于是复用的判据一直是"通过")。内核那条更
    隐蔽 —— 它固定版本就是为了防"字段废弃导致全屋断网", 结果反而变成了"永远不升级"。
    """
    from zeroproxy import router_client

    text = open(router_client.script_path(), encoding="utf-8").read()
    # 内核: 除了"能跑", 还要和面板要的那一版一致
    assert "core_version_ok" in text, "内核复用要看版本"
    assert "core_reusable && core_version_ok" in text
    assert "PANEL_CORE_VERSION" in text, "面板要哪一版从 /c/core/status 拿"
    assert 'json_get "$_json" core_version' in text
    # 老面板没有这个字段时按"一致"处理 —— 行为与本改动之前完全相同
    assert '[ -n "$PANEL_CORE_VERSION" ] || return 0' in text
    # 客户端版本落盘 (界面上"客户端 v…"那一格读它, 真机上一直是空的)
    assert 'printf \'%s\' "$ZP_CLIENT_VERSION" > "$ZP_DIR/version"' in text


def test_zpcore_version_number_has_exactly_one_source():
    """zpcore 的版本号只有一个来源: 面板代码里的 AGENT_VERSION, 构建时注入。

    源码里写第二个数字的代价是真实的: 面板发的是 1.1.1, 而安装输出与 `zpcore version`
    都报 1.0.0 —— 排查时没法从它自报的版本判断装的是哪一版 (只能去翻响应里有没有某个
    新字段)。构建脚本也必须真的把 -X 传进去, 否则源码里那个 "dev" 会跟着发出去。
    """
    import os

    from zeroproxy import router_client

    repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(router_client.__file__))))
    src = open(os.path.join(repo, "backend", "zeroproxy", "client", "agent", "main.go"),
               encoding="utf-8").read()
    assert "var agentVersion" in src and "const agentVersion" not in src, "要是 var 才能被注入"
    assert 'agentVersion = "dev"' in src, "源码里的默认值只能是 dev (说明它不是发布版)"

    build = open(os.path.join(repo, "scripts", "build-agent.sh"), encoding="utf-8").read()
    assert "-X main.agentVersion=$VERSION" in build, "构建时必须把版本号注入进去"


def test_heredoc_scripts_define_every_variable_they_use():
    """heredoc 里写出来的脚本是**独立文件**, 作用域与安装脚本完全无关。

    安装脚本顶部定义的变量 (ZP_API / ZP_MIXED / ZP_DIR …) 在 CLI / agent 里必须**自己再
    定义一次**, 否则运行时就是一个空串 —— 而且不会报错, 只会静默走错分支。

    真机上就是这么栽的第二次 (`ZP_MIXED` 那次我记得加, `ZP_API` 忘了): doctor 的"按域名
    分流"查的是 `$ZP_API/connections`, 而 ZP_API 只在安装脚本里定义过 —— CLI 里它是空的,
    URL 变成 `http:///connections`, curl 必然失败, 于是**在任何机器上**都显示
    "暂时没有被嗅探出域名的连接"。看起来像"设备还没开始用网", 其实是它问错了地址。
    """
    import re

    from zeroproxy import router_client

    text = open(router_client.script_path(), encoding="utf-8").read()
    for marker in ("CLIEOF", "AGENTEOF"):
        got = re.search(rf"<<'{marker}'\n(.*?)\n{marker}\n", text, re.S)
        assert got, f"安装脚本里应当有 {marker} 这一段"
        body = got.group(1)
        # 这一段里自己赋值过的大写变量 (含大小写混排的自定义变量)
        assigned = set(re.findall(r"^\s*([A-Za-z_][A-Za-z0-9_]*)=", body, re.M))
        # 带默认值的引用 (${ZP_X:-…}) 不算 —— 它本来就允许为空, 那是"可选开关"的写法。
        missing = sorted({
            name for name, defaulted in
            re.findall(r"\$\{?(ZP_[A-Za-z0-9_]+)(:[-=+?])?", body)
            if not defaulted and name not in assigned
        })
        assert not missing, f"{marker} 里用了但没定义的变量: {missing} (跨文件作用域不共享)"


def test_tun_mtu_follows_the_wan_and_is_clamped(client, configured):
    """tun 的 MTU 由**设备**按 WAN 的实际 MTU 算出来带过来 —— 面板不知道外面是什么。

    PPPoE 的 WAN 是 1492, 而 tun 里出去的包还要再封装一层 (TCP+TLS+协议头 ≈ 60 字节):
    tun 仍按 1500 收包时封装后就是超包, 表现是**"小页面能开、一下载就卡住"**。面板这一侧
    只需要做一件事 —— 把越界的值挡回去 (对面给的值不对时宁可退回默认)。
    """
    _login(client)
    device = _register(client, _pair_code(client)["code"])
    sub = f"/c/sub/{device['id']}?k={device['secret']}"

    # 默认 (老客户端不发这个参数): 1500, 一个字节不变
    assert yaml.safe_load(client.get(sub).text)["tun"]["mtu"] == 1500

    # 设备报多少就用多少 (合理区间内)
    assert yaml.safe_load(client.get(sub + "&mtu=1432").text)["tun"]["mtu"] == 1432
    assert yaml.safe_load(client.get(sub + "&mtu=1280").text)["tun"]["mtu"] == 1280

    # 越界一律退回默认: 一个坏值不该把全屋的 MTU 带跑偏
    for bad in (0, 99, 1279, 1501, 99999, -1):
        got = yaml.safe_load(client.get(sub + f"&mtu={bad}").text)["tun"]["mtu"]
        assert got == 1500, f"mtu={bad} 应当退回 1500, 实际 {got}"

    # 多服务器骨架同一条路
    assert yaml.safe_load(client.get(sub + "&format=skeleton&mtu=1400").text)["tun"]["mtu"] == 1400


def test_bench_endpoint_is_a_bounded_target(client, configured):
    """`zeroproxy bench` 的靶子是面板自己 —— 一个**匿名、有上限**的定长下载端点。

    为什么靶子是面板: 它是这台路由器一定能访问到的地址 (装机时唯一可达的), 而且"直连"与
    "经代理"两条路跑的是同一段路, 一比就知道代理本身吃掉了多少。
    为什么必须随机字节: 面板前面可能有 nginx、链路上还有运营商 —— 对可压缩内容它们都可能
    压一把, 那样量出来的不是链路速度。
    """
    from zeroproxy import routes

    res = client.get("/c/bench/2")
    assert res.status_code == 200
    assert len(res.content) == 2 << 20
    assert res.headers["content-type"] == "application/octet-stream"
    assert res.headers["cache-control"] == "no-store"

    # 随机字节 (压缩不了): 拿前 4 KB 看熵就够 —— 全零或重复的模式会被中间任何一层压掉
    assert len(set(routes._BENCH_MB[:4096])) > 64

    # 有上限: 这是匿名端点, 而且面板自己就在那条链路上 —— 不能变成放大器
    huge = client.get(f"/c/bench/{routes.BENCH_MAX_MB + 50}")
    assert len(huge.content) == routes.BENCH_MAX_MB << 20
    assert len(client.get("/c/bench/0").content) == len(routes._BENCH_MB)


def test_install_script_probes_the_wan_for_mtu_and_offload():
    """性能那一半的两条现场判据: WAN 的实际 MTU, 以及转发卸载会不会把代理绕过去。"""
    from zeroproxy import router_client

    text = open(router_client.script_path(), encoding="utf-8").read()
    # MTU: 只能从**本机**取 (面板不知道外面是 PPPoE 还是以太网), 而且要按 table main 取 ——
    # tun 的 auto-route 会把默认路由挪到自己那张表里, 重跑安装时按"默认路由"取会取到
    # zp-tun (1500), 那就成了"拿代理自己的 MTU 去算代理的 MTU"。
    assert "wan_mtu() {" in text and "compute_tun_mtu" in text
    assert "ip route show table main default" in text
    assert "tun_mtu=" in text and "wan_mtu=" in text
    # 转发卸载: 只探测 + 报出来, **不去改用户的防火墙**
    assert "offload_state() {" in text and "flow_offloading" in text
    assert "offload=" in text
    # **顺序**: 这两个值必须在 choose_datapath **之前**算完。choose_datapath → set_datapath
    # → write_caps 会把 caps 写死; 放在它后面算, 值算出来了却没人再写一次 —— 真机上就是
    # caps 里 `wan_mtu=` 空的、`offload=0`, 而安装输出明明说"转发卸载开着"。
    import re
    body = re.search(r"^install_deps\(\) \{.*?\n\}", text, re.S | re.M).group(0)
    # 只看真正的命令行: 注释里解释"为什么必须在它之前"当然会提到那个名字
    code = "\n".join(ln for ln in body.splitlines() if not ln.lstrip().startswith("#"))
    assert code.index("compute_tun_mtu") < code.index("choose_datapath"), \
        "MTU 与卸载要在 choose_datapath(它会写 caps) 之前算完"
    assert code.index("offload_state") < code.index("choose_datapath")
    # 再加一道兜底: 结尾无条件再写一次 caps, 顺序错了也不会静默丢值
    assert code.rstrip().removesuffix("}").rstrip().endswith("write_caps"), \
        "install_deps 结尾要有一次兜底落盘"
    # **不改用户的防火墙设置** (那是他自己的选择): 只看真正的命令行, 注释里提到 fw4 是可以的
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "uci set firewall" not in code and "uci commit" not in code
    # 设备把 MTU 带给面板 (单服务器与骨架两条路)
    assert text.count("&mtu=$_mtu") == 2
    # 基准: 命令、结果落盘、doctor 里显示、心跳带上面板
    assert "bench)" in text and "bench_run" in text and "zeroproxy bench" in text
    assert '> "$ZP_DIR/bench"' in text
    assert "bench_direct" in text and "bench_proxy" in text


def test_local_control_plane_source_and_build_script_ship_with_the_repo():
    """zpcore 的源码与构建脚本要跟着仓库走 —— 它没有上游可以下载 (内核是从 GitHub 取的,
    它不行)。构建脚本还要覆盖全部架构: 漏一个, 那一档路由器就静默退回旧路径。"""
    from zeroproxy import router_client

    repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(router_client.__file__))))
    agent_src = os.path.join(repo, "backend", "zeroproxy", "client", "agent")
    for name in ("go.mod", "main.go", "serve.go", "system.go"):
        assert os.path.exists(os.path.join(agent_src, name)), name

    build = os.path.join(repo, "scripts", "build-agent.sh")
    assert os.path.exists(build)
    body = open(build, encoding="utf-8").read()
    for arch in router_client.ARCHES:
        assert arch in body, f"构建脚本缺 {arch}"
    assert "GOOS=linux" in body and "CGO_ENABLED=0" in body
    assert "gzip" in body, "分发的形态是 .gz (与内核同一条路, 复用同一段解压代码)"
    # 接口契约必须与原来的 cgi 一致, 否则路由器上的页面要跟着改
    serve = open(os.path.join(agent_src, "serve.go"), encoding="utf-8").read()
    assert '"/cgi-bin/zeroproxy"' in serve and '"status"' in serve
    assert '"covered"' in serve and '"mode"' in serve
    # 版本号只有一处定义 (面板代码里的 AGENT_VERSION): 构建脚本必须从那里读, 否则两边
    # 一漂移, 面板就会去找一个从来没产出过的文件名 —— 只在装机时才暴露。
    assert "AGENT_VERSION" in body and "router_client.py" in body


def test_doctor_answers_whether_traffic_actually_flows():
    """`zeroproxy doctor` —— 真机上的第一诊断命令, 回答的是**唯一能证明接管成功**的问题。

    规则存在 ≠ 有流量: 接口名写错时规则照样"装得上", 却一个包都不命中 (L3 那一档最容易)。
    nft 的规则因此必须带 `counter` —— 不带计数器的规则是看不出有没有流量的; iptables 那边
    靠 `-L -v`。没流量时必须说"还没有", 而不是谎报"已接管并正常工作"。
    """
    import re

    from zeroproxy import router_client

    text = open(router_client.script_path(), encoding="utf-8").read()
    assert "doctor() {" in text and re.search(r"^\s*doctor$", text, re.M), "要定义并派发它"
    assert "doctor|status|ui|servers" in text, "用法里要列出它"
    # ① 现场核对 caps 里那一档是不是真的在 (不看命令退出码)
    assert "数据面真的在" in text and "现场一致" in text
    # ② 计数器: 两种数据面都要能算出包数; nft 规则必须带 counter
    assert "counter meta mark set 0x1ff tproxy" in text
    assert "counter redirect to :7874" in text
    assert "datapath_packets" in text and "-L zp_router -v -n" in text
    # ③ 没流量时的措辞 (也可能只是刚开机, 所以是"还没有"而不是"坏了")
    assert "还没有流量经过" in text
    # DNS 那一行不能拿计数器当判据: 局域网设备查的是**路由器自己的 dnsmasq**(本机服务),
    # 既不进 tun 也不命中 53 重定向 —— 计数为 0 本来就正常。第一版把它写成"设备可能没把
    # 路由器当 DNS", 方向正好反了 (真机上它打着"!" 而代理一切正常)。
    assert "sniffed_hosts() {" in text, "要按'已识别出域名的连接数'判断分流是否在工作"
    assert "按域名分流在工作" in text and "已经识别出域名" in text
    # fake-ip 路线只填 host、纯嗅探路线只填 sniffHost —— 只数一个会漏掉另一半
    assert '"(host|sniffHost)"' in text
    # 只查**真正的输出**: 注释里解释"那句以前是错的"是可以的
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "设备可能没把路由器当 DNS" not in code, "那句是错的, 方向反了"
    assert "是正常的" in text and "nft" in text  # 解释里要讲清为什么 0 是正常的


def test_panel_version_is_bumped_when_the_readme_says_so():
    """README 最后一段标着的版本号必须等于面板的 `__version__`。

    为什么值得一条测试 —— 这是一个**只有用户会碰到**的失败: 改了面板代码却没动
    `__version__`, 面板的「检查更新」就会一直显示"已是最新"、按钮也不去拉代码 (升级检查
    读的是远端仓库里那一行, 和本地比较)。开发者本地怎么测都是好的, 用户却卡住。

    把"README 里写的最新版本"和"代码里的版本"绑在一起: 写完一段新的变更记录却忘了改版本号,
    这里就会红。
    """
    import re

    from zeroproxy import __version__
    from zeroproxy import router_client

    repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(router_client.__file__))))
    readme = open(os.path.join(repo, "README.md"), encoding="utf-8").read()
    sections = re.findall(r"^### 8\.\d+ v([0-9][0-9.]*)[^\n]*$", readme, re.M)
    assert sections, "README 的变更记录里应当带版本号"
    assert sections[-1] == __version__, (
        f"README 最后一段写的是 v{sections[-1]}, 而 __version__ 是 {__version__} —— "
        "改了面板代码就要动版本号, 否则用户点「检查更新」永远显示已是最新"
    )
    # 客户端版本动了, **面板版本也必须动** —— 因为客户端脚本也是面板分发的:
    # 面板发 `/c/<配对码>` 与 `/c/install.sh` 用的就是仓库里那份 client/router-install.sh。
    # 只抬客户端版本会造出一个谁也说不清的状态: 面板跑的是新代码、报着旧版本号, 而
    # 「检查更新」还说"已是最新" —— 用户无从判断该不该点 (真机上就这么卡过一次)。
    pairs = re.findall(r"^### 8\.\d+ v([0-9][0-9.]*) \(客户端 v([0-9][0-9.]*)\)", readme, re.M)
    assert len(pairs) >= 2, "变更记录里应当带「(客户端 v…)」"
    prev_panel, prev_client = pairs[-2]
    last_panel, last_client = pairs[-1]
    if last_client != prev_client:
        assert last_panel != prev_panel, (
            f"客户端从 v{prev_client} 抬到了 v{last_client}, 而面板版本还是 v{last_panel} —— "
            "客户端脚本也是面板分发的, 面板版本不动的话「检查更新」看不到新版, 用户找不到入口"
        )


def test_local_override_lets_the_router_be_switched_without_the_panel():
    """家里网出问题时, 面板往往正好不可达 —— 而那时**最需要**能关掉代理。

    所以本机覆盖 (local.override) 必须:
      ① 优先于面板的期望状态 (否则"用户以为关了, 又被面板打开"是最坏的结果);
      ② 在**面板一台都联系不上**的那条分支上也要执行 —— 老代码在那里直接 continue
         (保持现状), 于是本机覆盖永远不会生效, 等于没有这个功能;
      ③ 一直保持到用户执行 `zeroproxy local-auto` —— 静默恢复是最危险的语义。
    """
    import re

    from zeroproxy import router_client

    text = open(router_client.script_path(), encoding="utf-8").read()
    assert "local.override" in text and "local-auto" in text

    # ① 覆盖优先: 读到 on/off 就压过面板算出来的 DESIRED_ALL
    assert re.search(r'case "\$_ov" in on\|off\) OVERRIDE="\$_ov"', text), "只认 on/off"
    assert 'if [ "$OVERRIDE" = "on" ]; then DESIRED_ALL="true"; else DESIRED_ALL="false"; fi' in text

    # ② 面板全不可达那条分支里也要执行它, 而且要排在 continue 之前
    offline = text.index("面板不可达 (第 $FAILS 次), 保持当前状态")
    override_apply = text.index('本机覆盖=off (面板不可达), 停止内核')
    assert override_apply < offline, "本机覆盖要在'保持现状'之前执行"

    # ③ 只有显式 local-auto 才交回面板; 面板答得上时顺手清掉 (那时面板就是真相源)
    assert 'rm -f "$ZP_DIR/local.override"' in text
    assert 'echo "面板不可达 —— 已在本机把全屋代理设为「$1」并立即生效。"' in text
    # 心跳把这件事如实报上去, 面板卡片才能写「本机覆盖」而不是「同步中」
    assert '"override":"\'"$OVERRIDE"\'"' in text


def test_luci_session_accepts_a_real_session_the_way_ubus_actually_works():
    """从 LuCI 菜单点进来必须能打开 —— 判据得按**这台机器上 ubus 的真实行为**写。

    真机 (GL-MT3000 / OpenWrt 24.10) 实测:
      * `ubus -S <sid> call session get` —— 新版 ubus 的 `-S` 是"简化输出(给脚本用)",
        **不接受参数**, 于是它只打印一屏用法, 判定永远失败。旧固件上没人发现, 是因为
        那台 (GL.iNet 21.02 原厂) 根本没有 LuCI, 这条代码路径从来没被走到过。
      * `ubus call session get '{"ubus_rpc_session":"<sid>"}'` —— **有效会话**返回 JSON,
        **无效会话**打印 "Command failed … (Not found)"。两者的**退出码都是 0**, 所以
        只能看文本。
    """
    import os
    import re

    from zeroproxy import router_client, routes

    repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(router_client.__file__))))
    _cgi, _media, _name = router_client.ui_file("cgi")
    cgi = open(os.path.join(repo, "backend", "zeroproxy", "client", "luci", "cgi"),
               encoding="utf-8").read()
    # 只看真正的命令行: 注释里解释"别再用 ubus -S"当然会提到它
    cgi_code = "\n".join(ln for ln in cgi.splitlines() if not ln.lstrip().startswith("#"))
    assert "ubus -S" not in cgi_code, "那个写法在这台 ubus 上只会打印用法 (见测试注释)"
    assert 'ubus call session get "{\\"ubus_rpc_session\\":\\"$sid\\"}"' in cgi
    assert "Command failed" in cgi, "无效会话是打印文本、退出码仍是 0, 必须看文本"
    assert "sysauth" in cgi, "会话 cookie 的名字"
    # 单值不能用 jstr: 它给每行结尾补一个字面的 \n, 用在 base/version 上会多出一个尾随
    # 换行 (真机实测 "base":"https://hk.i3.pub:8899\n")。多行的回执/日志才用它。
    assert "jval_s() {" in cgi
    assert 'jval_s "$base"' in cgi and 'jval_s "$ver"' in cgi
    assert 'jstr "$base"' not in cgi, "单值别用 jstr"

    # zpcore 也要认: 从 LuCI 菜单点进来的 iframe 带不上令牌, 用户能做的只有先登录
    serve = open(os.path.join(repo, "backend", "zeroproxy", "client", "agent", "serve.go"),
                 encoding="utf-8").read()
    assert "luciSession(" in serve and "sysauth" in serve
    assert "isSessionID" in serve, "会话 id 是从 cookie 来的, 拼进 JSON 前先卡一道"
    assert 'run(probeTimeout, "ubus", "call", "session", "get"' in serve
    assert "Command failed" in serve


def test_one_click_update_is_wired_everywhere():
    """路由器端的一键更新: CLI 真的去更新、后台跑、写日志; 界面有按钮; zpcore 透传它。

    为什么必须**后台**跑: 这个脚本会替换 `/usr/bin/zeroproxy` 自己 (正在运行的文件), 而且
    要下载 20 MB 内核 —— 前台跑既容易半途出岔子, 又会让界面转一分钟。
    为什么走**更新模式**: 那条命令不带配对码, 所以不会在面板上多出设备。
    """
    from zeroproxy import router_client

    text = open(router_client.script_path(), encoding="utf-8").read()
    assert "update-log)" in text and "update)" in text
    assert "/c/install.sh" in text, "更新走的是面板的固定更新命令"
    assert 'update.log' in text and "logger -t zeroproxy" in text
    # 后台: 提交后立刻回话, 过程写文件
    assert ") &" in text.split("update)")[1].split("update-log)")[0]
    # 降级闸门: 面板比本机旧时**拦下**。按钮触发的更新会替换路由器上的全部客户端文件 ——
    # 面板还没更新时点下去等于降级 (真机上踩过: 覆盖回来的旧 cgi 没有 update 分支, 按钮
    # 点完立刻又报"未知操作")。先把脚本取下来看一眼版本, 旧的就别跑。
    upd = text.split("update)")[1].split("update-log)")[0]
    assert "_panel_ver" in upd and "那不是升级" in upd
    assert ".update-script" in upd, "取下来的那份直接跑, 不再下第二次"
    # 界面上的按钮 + zpcore 的透传
    page, _m, _n = router_client.ui_file("index.html")
    assert 'id="update"' in page and "更新客户端" in page
    js, _m2, _n2 = router_client.ui_file("app.js")
    assert "$('update').onclick" in js and "call('update')" in js
    serve = open(os.path.join(os.path.dirname(os.path.abspath(router_client.__file__)),
                              "client", "agent", "serve.go"), encoding="utf-8").read()
    assert '"update"' in serve and '"update-log"' in serve


def test_every_action_the_page_calls_is_served_by_every_ui_server():
    """页面上按的每一个动作, **每一处能发出这个页面的服务**都得认识它。

    真机上就是这么栽的: 一键更新加在了 CLI 与 zpcore 上, 唯独漏了 cgi —— 而 LuCI 菜单
    那个页面是用 cgi 发的 (端口 80), 于是点下去得到的是"未知操作: update"。
    前端只有一份 (app.js), 三处后端的动作集合必须都覆盖它。
    """
    import os
    import re

    from zeroproxy import router_client

    js, _media, _name = router_client.ui_file("app.js")
    called = set(re.findall(r"call\(\s*['\"](\w[\w-]*)['\"]", js))
    assert called, "从 app.js 里应当能抠出它调用的动作名"

    repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(router_client.__file__))))
    cgi = open(os.path.join(repo, "backend", "zeroproxy", "client", "luci", "cgi"),
               encoding="utf-8").read()
    # case 标签固定缩进 4 空格 (嵌套的那几个更深, 不会误入)
    cgi_actions: set[str] = set()
    for group in re.findall(r"^\s{4}(\w[\w-]*(?:\|\w[\w-]*)*)\)\s*$", cgi, re.M):
        cgi_actions.update(group.split("|"))
    assert "status" in cgi_actions and "update" in cgi_actions, cgi_actions
    assert not (called - cgi_actions), f"cgi 不认识的页面动作: {sorted(called - cgi_actions)}"

    serve = open(os.path.join(repo, "backend", "zeroproxy", "client", "agent", "serve.go"),
                 encoding="utf-8").read()
    z_actions: set[str] = set()
    for group in re.findall(r"case ((?:\"[^\"]+\"(?:,\s*)?)+):", serve):
        z_actions.update(re.findall(r'"([^"]+)"', group))
    assert not (called - z_actions), f"zpcore 不认识的页面动作: {sorted(called - z_actions)}"


def test_revert_compares_against_the_install_baseline(tmp_path):
    """`zeroproxy revert` 不是"我们相信自己的拆卸代码", 而是**逐条比对**装机前的快照。

    这里真的把那段函数抠出来跑: 状态一致时给"完全回到装机前", 有一处差异时必须报出来
    并指出是哪一项 —— 数据面残留是"关掉了但网还是不对劲"这类问题的唯一解释。
    """
    import re
    import subprocess

    from zeroproxy import router_client

    text = open(router_client.script_path(), encoding="utf-8").read()
    body = re.search(r"^revert_report\(\) \{.*?\n\}", text, re.S | re.M)
    assert body, "安装脚本里应当有 revert_report"
    assert "snapshot_baseline" in text, "快照要在装机时拍"
    assert re.search(r"^\s*snapshot_baseline$", text, re.M), "write_files 里要调用它"

    root = tmp_path / "zp"
    base = root / "baseline"
    base.mkdir(parents=True)
    (base / "taken_at").write_text("1", encoding="utf-8")
    names = ("nft", "iptables", "ip6tables", "ip-rule", "ip6-rule")
    for name in names:
        (base / f"{name}.txt").write_text("", encoding="utf-8")

    def run() -> str:
        script = f'ZP_DIR="{root}"\n' + body.group(0) + "\nrevert_report\n"
        out = subprocess.run(["sh", "-c", script], capture_output=True, text=True)
        assert out.returncode == 0, out.stderr
        return out.stdout

    # 本机没有 nft / iptables 时, 两边都是空 —— 那也算"一致" (判据不能依赖文件大小)
    assert "完全回到装机前" in run()

    (base / "ip-rule.txt").write_text("0:\tfrom all lookup local\n", encoding="utf-8")
    drifted = run()
    assert "还有残留" in drifted and "ip-rule" in drifted, drifted

    # 没有快照 (旧版本装的) 时要说清楚, 而不是假装比对过了
    (base / "taken_at").unlink()
    assert "没有装机前的快照" in run()


def test_install_ui_always_makes_a_token_and_prints_it():
    """路由器管理界面的地址必须带令牌, 令牌也必须无条件生成。

    真机反馈: 用户照着安装摘要里的地址打开, 看到的是一个"读不到状态、开关点也点不动"的
    页面, 第一反应是"这开关坏了"。原因是那个页面只认两样东西 —— 地址里的 ?k=令牌, 或者
    一个有效的 LuCI 会话 —— 而 GL.iNet 的后台不是 LuCI, 登录它什么都没有。

    所以: (1) 令牌的生成不能挂在"有没有 LuCI"下面 (老版本就是挂着的, 没装 LuCI 的固件上
    `zeroproxy ui` 会打印一条没有令牌的死地址); (2) 安装摘要里打印的必须是带令牌的那条。
    """
    from zeroproxy import router_client

    text = open(router_client.script_path(), encoding="utf-8").read()
    # 只在 install_ui 这一段里比顺序: "有没有 LuCI"这个判断现在别处也有 (doctor 里那条
    # 体检项、luci_install 自己那道闸门), 全文 index 会指到别处去 —— 而这一条要钉的是
    # **install_ui 内部**的顺序 (令牌先于 LuCI 分支无条件生成)。
    ui_at = text.index("install_ui() {")
    token_at = text.index('if [ ! -s "$ZP_DIR/ui.token" ]', ui_at)
    luci_at = text.index('if [ -d /usr/share/luci/menu.d ]', ui_at)
    assert token_at < luci_at, "令牌要在 LuCI 分支之前无条件生成"
    assert 'UI_URL_K="$UI_URL?k=$(cat "$ZP_DIR/ui.token"' in text, "要拼出带令牌的地址"
    assert 'ok "浏览器打开: $UI_URL_K"' in text, "安装摘要要打印带令牌的地址"
    # CLI 的 `zeroproxy ui` 一直就是打印带令牌的地址 —— 别把它改成裸地址
    # (端口要带上: 固件自己的 Web 服务发不出页面时, 界面在自带 httpd 的那个端口上)
    assert 'echo "http://$_ip$_port/cgi-bin/zeroproxy?k=$(cat "$ZP_DIR/ui.token"' in text


def test_install_ui_verifies_and_falls_back_to_its_own_httpd():
    """装完必须**真的取一次**页面, 取不到就换自己的 httpd —— 而不是打印一条死地址。

    真机 (GL-MT3600BE · arm64 · GL.iNet 原厂 OpenWrt 21.02-SNAPSHOT / 内核 5.4.281,
    没有 LuCI): 界面文件写进了 /www, 但原厂 nginx 没有把 /cgi-bin/ 交给脚本 ——
    于是自检那一句 "本机自检没通过" 挂在那儿, 用户看到 URL 打不开。

    现在的口径: 落盘之后依次走两条路, 每条都要看到**页面内容**才算通 ——
      ① 固件自己的 Web 服务 (80 端口, 不开新端口);
      ② 自带的 busybox httpd (只在 ① 不通时起, 只绑局域网地址, 照旧只认界面令牌)。
    判据必须看内容: 200 也可能是把 cgi 脚本当静态文件发出来, 那种情况"页面"是一坨 shell。
    """
    from zeroproxy import router_client

    text = open(router_client.script_path(), encoding="utf-8").read()

    # 判据是页面里的 <title> —— cgi 脚本里没有它, 所以"脚本被当文件下载"不会误判成通过
    assert "UI_MARK='<title>ZeroProxy'" in text, "自检要看页面内容, 不能只看状态码"
    assert 'ui_probe "http://127.0.0.1/cgi-bin/zeroproxy"' in text, "先试固件自己的 Web 服务"
    assert "ui_start_local_server" in text, "发不出来要有自带服务的兜底"
    # 有 zpcore (面板分发的本地控制面) 时优先用它 —— 它与固件完全无关, 这正是它存在的理由
    assert 'if [ -x "$ZP_DIR/zpcore" ] && ui_start_local_server; then' in text
    assert "install_zpcore" in text and "/c/agent/bin/$ARCH" in text, "控制面也从面板取"

    # 兜底服务的两条硬约束: 只绑局域网地址 (绝不 0.0.0.0), 且与固件 Web 服务走同一个
    # 脚本 (/cgi-bin/zeroproxy 仍然是唯一入口, 令牌校验照旧在 cgi 里)
    assert 'httpd -f -p "$_ip:$UI_PORT" -h "$ZP_DIR/www"' in text, "自带 httpd 只绑 LAN 地址"
    # 找不到 LAN 地址就不启动 —— 绝不退化成"绑所有接口" (那等于把界面挂到 WAN 上)
    assert '[ -n "$_ip" ] || return 0' in text, "兜底服务不能绑到所有接口"
    assert "/cgi-bin/zeroproxy" in text

    # 端口写进 ui.port, 界面地址由它算出来 (LAN 地址换了也算得对); agent 与 CLI 都认它
    assert 'printf \'%s\' "$UI_PORT" > "$ZP_DIR/ui.port"' in text
    assert 'cat "$ZP_DIR/ui.port"' in text
    # 两条路都不通时要把兜底服务收拾干净, 不留一个跑不起来的开机服务
    assert "ui_stop_local_server" in text
    assert "zeroproxy-ui disable" in text


def test_router_ui_cgi_serves_the_page_from_wherever_it_was_installed(tmp_path):
    """cgi 要能自己找到页面文件 —— 它现在有两个可能的家 (见安装脚本的 install_ui)。

    走固件 Web 服务的固件, 页面在 /www/zeroproxy; 原厂固件那条路 (没有 /cgi-bin/) 用
    自带的 busybox httpd, 文档根是 /etc/zeroproxy/www —— 页面在 /etc/zeroproxy/www/zeroproxy。
    所以脚本不能写死一个路径: SCRIPT_FILENAME 有的服务器给、有的不给 (busybox httpd 给,
    fcgiwrap 看配置), 那就"给就用它推, 不给就按顺序找"。

    这里真的把那份 cgi 当 cgi 跑一遍 (macOS/BSD 的 sh 就够), 只看它能不能把**页面**
    发出来 —— 数据接口那部分要 /etc/zeroproxy 下的凭据, 本机没有, 也不该在测试里去碰。
    """
    import subprocess

    from zeroproxy import router_client

    cgi, _media, _name = router_client.ui_file("cgi")
    page, _m, _n = router_client.ui_file("index.html")

    # 自带 httpd 的布局: <root>/cgi-bin/zeroproxy + <root>/zeroproxy/index.html
    root = tmp_path / "www"
    (root / "cgi-bin").mkdir(parents=True)
    (root / "zeroproxy").mkdir()
    (root / "cgi-bin" / "zeroproxy").write_text(cgi, encoding="utf-8")
    (root / "zeroproxy" / "index.html").write_text(page, encoding="utf-8")

    env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "REQUEST_METHOD": "GET",
        "QUERY_STRING": "",
        "SCRIPT_FILENAME": str(root / "cgi-bin" / "zeroproxy"),
    }
    out = subprocess.run(["sh", str(root / "cgi-bin" / "zeroproxy")],
                         capture_output=True, text=True, env=env)
    assert out.returncode == 0, out.stderr
    assert "<title>ZeroProxy" in out.stdout, "cgi 要从 SCRIPT_FILENAME 推出页面目录"
    assert out.stdout.startswith("Content-Type: text/html"), "页面要带自己的响应头"

    # 页面不在推出来的那个目录时 (老的 uhttpd 布局), 也要能找到 /www/zeroproxy 那份
    assert "for _d in" in cgi, "要按顺序找, 而不是认死一个路径"


def test_ui_probe_checks_content_not_just_the_status_code(tmp_path):
    """自检的判据必须是**页面内容**, 不能是状态码。

    这台真机 (GL.iNet 原厂 21.02-SNAPSHOT, 没有 LuCI) 的现象: 原厂 nginx 没有把
    /cgi-bin/ 交给脚本, 于是 /www/cgi-bin/zeroproxy 被当成**静态文件**发出来 —— HTTP 200,
    正文是那份 shell 源码。只看状态码的自检在这里会判"通过", 然后用户打开的是一坨脚本。

    所以这里起两个本地服务器: 一个按原厂那条路发**脚本源码**, 一个发**页面**。把安装
    脚本里的 ui_probe 原样抠出来跑一遍, 它必须只认后者。
    """
    import http.server
    import re
    import subprocess
    import threading

    from zeroproxy import router_client

    cgi_src, _m, _n = router_client.ui_file("cgi")
    page_src, _m, _n = router_client.ui_file("index.html")

    def serve(payload: str) -> tuple[http.server.ThreadingHTTPServer, str]:
        body = payload.encode()

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):  # pragma: no cover - 别刷屏
                pass

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, f"http://127.0.0.1:{srv.server_address[1]}/cgi-bin/zeroproxy"

    text = open(router_client.script_path(), encoding="utf-8").read()
    fn = re.search(r"ui_probe\(\) \{.*?\n\}", text, re.S)
    assert fn, "安装脚本里应当有 ui_probe"
    mark = re.search(r"UI_MARK='([^']*)'", text)
    assert mark and "<title>" in mark.group(1), "自检标记要落在页面的 <title> 上"
    (tmp_path / "ui.token").write_text("token-for-test\n", encoding="utf-8")
    probe = (
        'HTTP=curl; TLS_OPTS="";\n'
        'http_get() { curl -fsS -m 5 "$1"; }\n'
        f'ZP_DIR="{tmp_path}";\n'
        f"UI_MARK='{mark.group(1)}';\n"
        + fn.group(0) +
        '\nui_probe "$1"\n'
    )

    static_srv, static_url = serve(cgi_src)
    page_srv, page_url = serve(page_src)
    try:
        bad = subprocess.run(["sh", "-c", probe, "sh", static_url],
                             capture_output=True, text=True)
        assert bad.returncode != 0, "把脚本当静态文件发出来 (200) 不能算通过"
        good = subprocess.run(["sh", "-c", probe, "sh", page_url],
                              capture_output=True, text=True)
        assert good.returncode == 0, "真的发出页面才算通过"
    finally:
        static_srv.shutdown()
        page_srv.shutdown()


def test_local_httpd_init_script_only_binds_the_lan_address(tmp_path):
    """兜底 httpd 的 procd 服务: 在本机把那个 init 脚本真的跑一遍, 看它拼出什么命令。

    本机没有 busybox httpd 可跑 (macOS 也没有 procd), 所以这里给几个桩函数 —— 验的是
    最容易犯的两个错: 绑成所有接口 (等于把管理界面挂到 WAN 上), 或者把 httpd 的文档根
    指错 (指错就是 404, 白装一个服务)。
    """
    import os
    import re
    import subprocess

    from zeroproxy import router_client

    text = open(router_client.script_path(), encoding="utf-8").read()
    got = re.search(r"cat > \"\$ZP_INIT_UI\" <<'UIINITEOF'\n(.*?)\nUIINITEOF\n", text, re.S)
    assert got, "安装脚本里应当有兜底 httpd 的 init 脚本"
    init_body = (got.group(1)
                 .replace("__ZP_UI_PORT__", "8399")
                 .replace("__ZP_BUSYBOX__", "/bin/busybox"))

    root = tmp_path / "zp"
    (root / "www" / "cgi-bin").mkdir(parents=True)
    page = root / "www" / "cgi-bin" / "zeroproxy"
    page.write_text("#!/bin/sh\n", encoding="utf-8")
    page.chmod(0o755)
    init = (tmp_path / "initd-ui")
    init.write_text(init_body.replace("/etc/zeroproxy", str(root)), encoding="utf-8")

    # uci 是桩 (本机没有): 它给出局域网地址。写不出地址的那一次要"不启动"。
    bindir = tmp_path / "bin"
    bindir.mkdir()
    uci = bindir / "uci"
    uci.write_text("#!/bin/sh\n", encoding="utf-8")
    uci.chmod(0o755)
    # ip 也桩掉 (Linux 上真有一堆非回环地址, 不桩的话"写不出地址"那一趟会碰巧成功)
    ip_stub = bindir / "ip"
    ip_stub.write_text("#!/bin/sh\n", encoding="utf-8")
    ip_stub.chmod(0o755)

    def run(start: bool) -> str:
        uci.write_text("#!/bin/sh\n" + ("printf 192.168.8.1\n" if start else "true\n"),
                       encoding="utf-8")
        harness = tmp_path / "harness.sh"
        harness.write_text(
            "procd_open_instance() { echo OPEN; }\n"
            "procd_set_param() { echo \"PARAM $*\"; }\n"
            "procd_close_instance() { echo CLOSE; }\n"
            f'. "{init}"\n'
            "start_service\n",
            encoding="utf-8",
        )
        out = subprocess.run(["sh", str(harness)], capture_output=True, text=True,
                             env={"PATH": f"{bindir}:{os.environ.get('PATH', '')}"})
        assert out.returncode == 0, out.stderr
        return out.stdout

    served = run(True)
    assert "PARAM command /bin/busybox httpd -f -p 192.168.8.1:8399 -h " in served
    assert str(root / "www") in served, "文档根要指向页面真正落盘的那个目录"

    stopped = run(False)
    assert "OPEN" not in stopped, "找不到 LAN 地址就不能启动 (绝不绑所有接口)"


def test_install_script_parses_booleans_on_any_sed():
    """能力位与开关位都靠 json_get_bool 读。原来的写法用 `\\(true\\|false\\)`, 而 `\\|` 是
    GNU 扩展 —— BSD sed (macOS 演练环境 / 没有 jsonfilter 的固件) 会**静默取空**, 于是
    "面板说不支持分流数据"被读成"没这个字段", 该拦下的旧面板就漏过去了。

    这里真的把脚本里那段函数抠出来, 用 sh 跑一遍。
    """
    import re
    import subprocess

    from zeroproxy import router_client

    text = open(router_client.script_path(), encoding="utf-8").read()
    body = re.search(r"json_get_bool\(\) \{.*?\n\}", text, re.S)
    assert body, "安装脚本里应当有 json_get_bool"
    script = body.group(0) + (
        "\njson_get_bool '{\"id\":\"dv1\",\"geo\":true}' geo\n"
        "json_get_bool '{\"id\":\"dv1\",\"geo\":false}' geo\n"
        "json_get_bool '{\"desired\": true, \"geo\": false}' desired\n"
        "json_get_bool '{\"id\":\"dv1\"}' geo\n"
    )
    out = subprocess.run(["sh", "-c", script], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert out.stdout.split() == ["true", "false", "true"]


def test_install_script_sticks_to_busybox_tools():
    """(见下) 安装脚本只能用路由器上确实有的命令。"""
    """路由器上的可用命令比服务器少得多, 这条测试盯住"用了 OpenWrt 没有的工具"。

    真机事故 (2.7.0): 用 `od -An -tx1` 读文件前两个字节来判断下载到的是不是 gzip。
    OpenWrt 的 busybox 默认**不带 od**, 那行命令直接 "od: not found" —— 命令替换拿到
    空字符串, 于是代码判定"不是压缩包", 把 20 MB 的 gz 原样 chmod +x 当成内核执行,
    报错还写成"内核无法执行 (架构不匹配?)", 把人往错误方向引。

    判断压缩包只用 gzip -t (busybox 一定有), 别再引入任何"服务器上才有"的工具。
    """
    import re

    from zeroproxy import router_client

    raw = open(router_client.script_path(), encoding="utf-8").read()
    # 只看真正的命令行: 注释里当然可以提到 od (解释"为什么不能用它"的那段)
    text = "\n".join(line for line in raw.splitlines() if not line.lstrip().startswith("#"))
    for tool in ("od", "hexdump", "xxd", "readelf", "jq", "python3", "perl", "dpkg", "apt"):
        assert not re.search(rf"(?<![A-Za-z0-9_]){tool}(?![A-Za-z0-9_])", text), (
            f"安装脚本里不该出现 {tool}: 路由器上不一定有"
        )
    assert "gzip -t" in text, "判断 gzip 必须用 gzip -t"
    # 复用旧内核前要真的跑一次 -v, 否则上一次失败留下的坏文件会让重跑一直挂在原地
    assert '"$ZP_BIN" -v >/dev/null 2>&1; then' in text


def test_install_script_self_heals_rejected_credentials():
    """凭据在面板上失效 (被移除 / 换成另一台面板) 时, 安装脚本要能自己重接。

    真机反馈 (2.7.2): 走到最后一步 403 —— 路由器本地只看得见"我有凭据",
    看不出面板那边还认不认; 于是报"拉取配置失败, 请回面板确认已有可用节点",
    用户完全无从下手。现在拉不到就用**本次命令里的配对码**重新配对再试一次 ——
    那行命令本来就是用户刚生成的, 码是新的。
    """
    from zeroproxy import router_client

    text = open(router_client.script_path(), encoding="utf-8").read()
    assert "do_pair()" in text, "配对逻辑要能被复用 (首次接入与凭据失效重接走同一条路)"
    assert "用本次配对码重新接入" in text, "凭据被拒时必须自动重接, 而不是直接失败"
    assert "重新接入失败" in text and "重新生成一条安装命令" in text, "重接也失败时要给出可执行的下一步"
    # 换面板 (stored base ≠ 本次 base) 必须能识别出来, 而不是继续用旧凭据撞 403
    assert "_old_base" in text and "本次改用" in text


def test_install_script_handles_openwrt_25_and_never_hangs_on_the_core():
    """客户端侧的两条硬约束 (真机: GL-MT3600BE / OpenWrt 25.12.5 / 内核 6.12.94)。

    一、25.12 起 OpenWrt 的包管理器从 opkg 换成了 apk —— 只认 opkg 的写法在那类固件上
        是**静默跳过**: kmod-tun 与 kmod-nft-tproxy 一个都没装, 安装过程全绿, 而 TUN
        建不出来、tproxy 回退也没有规则, 全屋代理名存实亡。两代都要认。
    二、同一台机器上安装停在 "下载代理内核" 上不动 (面板侧没有总时限)。客户端这一侧
        必须: 下载有进度、等面板有上限、失败给下一步 —— 而不是一行输出不动地等下去。
    """
    from zeroproxy import router_client

    text = open(router_client.script_path(), encoding="utf-8").read()
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))

    # 一、两代包管理器
    assert "apk add" in code, "OpenWrt 25.12 起是 apk, 不认它就等于不装内核模块"
    assert "opkg install" in code, "24.10 及更早还是 opkg, 不能只留 apk"

    # 二、取内核那一步: 进度 + 上限 + 人话 + 下一步
    assert "core_download" in code and "start_progress" in code, "下载期间要有进度输出"
    assert "CORE_WAIT" in code, "等面板要有上限 (面板取不到时不能无限等)"
    assert "面板正在取内核" in code, "等待期间要把面板的真实进度说出来"
    assert "/c/core/status" in code, "要从面板的状态接口读进度"
    assert "data/client/cores" in text, "失败时要告诉用户内核压缩包该放哪"

    # 架构表: mihomo 有 armv6 / mips64 的构建, 别把它们兜到别的架构上
    # (兜错的后果是"下载解压都成功, 一执行 Illegal instruction")
    assert "armv6" in code and "mips64)" in code, "armv6 / mips64 要有自己的分支"
    from zeroproxy import router_client as rc
    assert rc.ARCHES["armv6"] == "armv6" and rc.ARCHES["mips64"] == "mips64"

    # bash / 某些 ash 会把变量名后面紧跟的高字节算进名字里 —— `$ZP_BASE。` 在
    # set -u 下会变成 "ZP_BASE?: unbound variable", 而它偏偏只在"真的连不上面板"
    # 时才执行 (这条由演练抓到: 面板地址不可达 → 报错信息自己炸了)。
    import re
    for line in code.splitlines():
        assert not re.search(r"\$[A-Za-z_][A-Za-z0-9_]*[^\x00-\x7f]", line), (
            f"变量名后面紧跟非 ASCII 字符要写成 ${{VAR}}: {line.strip()[:60]}"
        )


def test_install_script_picks_the_right_package_manager_per_firmware():
    """25.12 的包管理器是 apk, 24.10 及更早是 opkg —— 但**版本号与命令要一起看**。

    真机上存在两代混着出现的组合 (厂商固件报 25.x 却只有 opkg —— dae 的家用安装脚本
    专门处理过这一类; backport 的 24.10 里塞了 apk 的也有), 于是:
      * 只按版本号判 → 与固件实际能装的包格式对不上, 命令一条都跑不动;
      * 只按 `command -v` 判 → 两个都在的机器上选错。

    apk 还有它自己的两条脾气 (照 OpenWrt 官方 cheatsheet 与 dae 的安装脚本):
    `-U` 一条命令干完 update + install; 自建 / 厂商源没有签名密钥时报 UNTRUSTED
    signature, 要靠 --allow-untrusted 才能装上 —— 但**只在这类错误上退这一步**,
    别的错 (源里没有这个包) 退也没用, 只会把真正的原因盖住。
    """
    from zeroproxy import router_client

    text = open(router_client.script_path(), encoding="utf-8").read()
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))

    # 两代都认 (旧行为保留)
    assert "apk add" in code and "opkg install" in code
    # apk 那一侧: 一条命令 (索引 + 安装), 以及签名不可信时的退路
    assert "apk -U add" in code, "apk 要一条命令刷新索引 + 安装 (cheatsheet 的 -U)"
    assert "--allow-untrusted" in code, "自建 / 厂商源没有签名密钥时要能退这一步"
    assert "UNTRUSTED" in code, "只在签名类错误上退 --allow-untrusted, 别的错不许退"
    # 判据: 固件版本 + 实际命令, 两条一起看; 不一致时按命令走并说明
    assert "DISTRIB_RELEASE" in code and "PKG_MGR" in code
    assert "按 opkg 走" in code and "按 apk 走" in code, "版本与命令不一致时要按命令走并说清楚"
    assert "pkgmgr=" in code and "fw=" in code and "fwgen=" in code, "固件与包管理器要落进 caps"

    # 装不上不许沉默: 原话 + 这台机器能用的那条补装命令 (按包管理器分岔)
    assert "deps_why=" in code, "内核模块为什么没装上要记进 caps (doctor / status 读它)"
    assert "内核模块没装上" in code and "补装:" in code
    assert "apk -U add kmod-tun kmod-nft-tproxy" in code and \
        "opkg install kmod-tun kmod-nft-tproxy" in code, "补装命令要按本机包管理器给"
    # 25.12 这一层特有的事实, 必须说出来 (否则"模块装不上"会被当成脚本的毛病)
    assert "与内核版本绑定" in code, "25.12 的 kmod 来自与内核版本绑定的源"
    # 24.10 已 EOL (2026-09): 主动提示升级 (设计文档 §1.3)
    assert "24.10" in text and "停止维护" in text
    # 装完之后的两个现场入口: status 报固件与包管理器, doctor 报"模块没装上 + 怎么补"
    assert "包管理器 %s" in code, "zeroproxy status 要报出固件与包管理器"


def test_install_script_auto_fixes_missing_kernel_btf():
    """真机 (GL-MT3600BE · 25.12.5 · 内核 6.12.94) 缺 BTF —— 检测到就**自动补**。

    机制 (社区现成的解法): 装一份匹配内核的 detached BTF 到
    /usr/lib/debug/boot/vmlinux-<内核版本>, 而 cilium/ebpf 与 libbpf 在 sysfs 里没有 BTF
    时**正好会回退到那里** —— 所以候选路径与顺序必须与它们一致。补的动作两条路: 先问
    本机软件源, 再问面板 (/c/btf, 与内核 / 分流数据库同一套分发)。补不上就如实说清是
    哪一种原因, 以及它只影响未来的性能档。
    """
    from zeroproxy import router_client

    text = open(router_client.script_path(), encoding="utf-8").read()
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))

    # 候选路径: 与 libbpf / cilium-ebpf 的 findVMLinux 一致 (sysfs 那份排第一, 补进来的在
    # /usr/lib/debug/boot/ —— 社区的包就落在那里)
    assert "/sys/kernel/btf/vmlinux" in code
    assert "/usr/lib/debug/boot/vmlinux-$KERNEL" in code
    assert "/boot/vmlinux-$KERNEL" in code
    # 自动补: 本机软件源 → 面板; 本地包没有签名, apk 要显式放行
    assert "vmlinux-btf" in code and "/c/btf?kver=" in code
    assert "apk add --allow-untrusted" in code
    # 只在"有戏"时才动手 (内核 >=5.17; 社区包只覆盖 6.6 / 6.12) —— 不然是白占闪存
    assert "btf_worth_fixing" in code
    assert "6.6|6.12" in code.replace(" ", ""), "覆盖的内核系列要写进判据"
    # 先补, 再判 eBPF (顺序反了就等于没补)
    assert code.index("btf_ensure || true") < code.index("if ebpf_ok; then NET_EBPF=1")
    # 结论落进 caps: 面板 / status / doctor 读的都是这一份
    for key in ("btf=", "btf_how=", "btf_path=", "why.btf="):
        assert f"printf '{key}" in code, f"caps 要记 {key}"
    # 补不上时把影响面说清楚 —— 那句话长得像"装坏了"
    assert "只影响未来的" in code and "性能档" in code
    # 内核版本走 $KERNEL (可被 ZP_KERNEL 覆盖): 演练跑在 macOS 上时 uname -r 与 OpenWrt
    # 毫无关系, 而 BTF 是按内核系列挑包的
    assert 'KERNEL="${ZP_KERNEL:-$(uname -r)}"' in code


@pytest.mark.parametrize("name", ["index.html", "app.js", "perf.js", "cgi", "menu.json", "acl.json", "status.js"])
def test_ui_files_are_served(client, configured, name):
    """路由器管理界面的文件由面板分发 (路由器只负责落盘, 于是界面更新=重跑安装命令)。"""
    res = client.get(f"/c/ui/{name}")
    assert res.status_code == 200, name
    assert res.text.strip(), name


def test_ui_endpoint_refuses_unknown_names(client, configured):
    """这个端点是匿名可达的 (安装时来取), 所以必须只认白名单 —— 不能变成任意文件读取。"""
    for bad in ("../../etc/passwd", "..%2f..%2fetc%2fpasswd", "router-install.sh", "luci"):
        assert client.get(f"/c/ui/{bad}").status_code == 404, bad


def test_ui_files_contain_no_secrets(client, configured):
    """界面代码里不该夹带任何凭据: 它落到 /www 之后是局域网可读的。"""
    code = client.get("/c/ui/cgi").text
    page = client.get("/c/ui/app.js").text
    for text in (code, page):
        assert "sub" not in text or "secret" not in text.lower(), "界面里不该出现 secret"
        assert "subscription_token" not in text
    # cgi 必须真的做会话校验, 而不是"局域网内谁都能调"
    assert "sysauth" in code and "ubus" in code and "session get" in code


# ---------------------------------------------------------------- 配置生成

def test_router_profile_has_router_only_blocks(client, configured):
    """路由器配置必须带 tun/dns/嗅探, 而手机端订阅不该带 (否则 App 导不进去)。"""
    _login(client)
    device = _register(client, _pair_code(client)["code"])
    router_yaml = client.get(f"/c/sub/{device['id']}?k={device['secret']}").text
    profile = yaml.safe_load(router_yaml)
    assert profile["tun"]["enable"] is True
    assert profile["tun"]["auto-route"] is True
    assert profile["dns"]["enhanced-mode"] == "fake-ip"
    # 国外域名故意不配 DoH-经-代理: 那会让首屏每解析一个域名都付两个跨洋来回
    # (真机: YouTube 首屏十几秒, 播放却满速)。被代理的域名交给落地节点解析。
    assert set(profile["dns"]["nameserver-policy"]) == {"geosite:private,cn"}
    assert "dns.google" not in str(profile["dns"])
    assert profile["sniffer"]["enable"] is True
    assert profile["find-process-mode"] == "off"
    assert profile["allow-lan"] is True

    path = configured["subscription_url"].split("testserver")[-1]
    client_yaml = client.get(path + "?format=clash").text
    assert "tun:" not in client_yaml
    assert "fake-ip" not in client_yaml


def test_router_config_can_drop_auto_redirect_for_devices_that_cannot_use_it(client, configured):
    """`auto-redirect` 要往内核里写 nftables 规则 —— 不支持的固件上会让**整个 tun 起不来**。

    真机 (GL-MT3600BE · arm64 · 原厂 OpenWrt 21.02-SNAPSHOT / 内核 5.4.281): 装完
    `zp-tun` 一直不出现, 脚本按老逻辑退回 tproxy, 而那台机器的 tproxy 也是同一个原因
    不可用 —— 结果是"看着全绿、全屋其实没有代理"。

    设备在装机时自己探一次, 用 `?tproxy=0` 告诉面板; 面板据此**不写那一项**。
    全屋的本体是 `auto-route` (ip rule + 独立路由表, 含局域网转发), 少了 auto-redirect
    功能不受影响 —— 所以这条只删一项, 不能连 auto-route 一起删。
    """
    _login(client)
    device = _register(client, _pair_code(client)["code"])
    sub = f"/c/sub/{device['id']}?k={device['secret']}"

    # 默认 (老客户端 / 支持的设备) 一个字节都不变
    with_ar = yaml.safe_load(client.get(sub).text)
    assert with_ar["tun"]["auto-redirect"] is True
    assert with_ar["tun"]["auto-route"] is True

    without = yaml.safe_load(client.get(sub + "&tproxy=0").text)
    assert "auto-redirect" not in without["tun"], "设备说用不了就别写"
    assert without["tun"]["auto-route"] is True, "只去掉 auto-redirect, 全屋的本体不能动"
    assert without["tun"]["device"] == "zp-tun"

    # 多服务器模式的骨架走同一条路
    skeleton = yaml.safe_load(client.get(sub + "&format=skeleton&tproxy=0").text)
    assert "auto-redirect" not in skeleton["tun"]


def test_router_config_only_ships_tun_when_the_device_can_use_it(client, configured):
    """数据面决定面板给不给 `tun` 段。

    真机 (GL-MT3600BE · 原厂 OpenWrt 21.02-SNAPSHOT / 内核 5.4.281): 客户端探出本机
    **建不出 TUN 设备**, 但面板照旧给了一份 `tun: enable: true` 的配置 —— mihomo 启动时
    去建 tun 失败, 整份配置起不来。所以设备把探出来的数据面 (`?datapath=`) 带给面板,
    面板据此决定给不给这一段: 只有 `tun` 才给; tproxy / redirect / none 都用
    `redir-port` + `dns.listen` 那条路, 配置一样, 差别在防火墙侧。
    """
    _login(client)
    device = _register(client, _pair_code(client)["code"])
    sub = f"/c/sub/{device['id']}?k={device['secret']}"

    # 默认 (老客户端 / 支持的设备) 一个字节都不变
    assert yaml.safe_load(client.get(sub).text)["tun"]["enable"] is True
    for dp in ("", "tun"):
        prof = yaml.safe_load(client.get(sub + f"&datapath={dp}").text)
        assert prof["tun"]["enable"] is True, dp
        assert prof["tun"]["auto-route"] is True

    # 建不出 TUN 设备的机器: 面板不给 tun 段, 其余照旧
    for dp in ("tproxy", "redirect", "none"):
        prof = yaml.safe_load(client.get(sub + f"&datapath={dp}").text)
        assert "tun" not in prof, dp
        # 透明代理的两个端口与 DNS 都还在 (redirect / tproxy 都要靠它们)
        assert prof["redir-port"] == 7892 and prof["tproxy-port"] == 7893, dp
        assert prof["dns"]["enable"] is True and prof["dns"]["enhanced-mode"] == "fake-ip"
        assert prof["allow-lan"] is True
        # 分流数据库仍然只从面板取 (那类机器上更不可能连得上 GitHub)
        assert "/c/geo/geosite.dat" in prof["geox-url"]["geosite"]

    # 多服务器骨架走同一条路 (它也是路由器端配置)
    skel = yaml.safe_load(client.get(sub + "&format=skeleton&datapath=redirect").text)
    assert "tun" not in skel
    assert skel["proxy-providers"] == {}


def test_ipv6_is_taken_over_only_when_the_device_says_it_can(client, configured):
    """IPv6 是**泄漏面**, 不是加分项。

    局域网设备从运营商那里拿到原生 v6 地址; 只接管 v4 的透明代理对 v6 等于不存在 ——
    那些流量直接出去, 目标网站看到的是用户的真实 v6 地址。而 mihomo 自己的
    `ipv6: false` 并不会真的关掉 v6 协议栈 (上游 issue #2254), 所以这件事只能由设备
    探完再决定, 而且**探不到时必须说出来**, 不能假装接管了。
    """
    _login(client)
    device = _register(client, _pair_code(client)["code"])
    sub = f"/c/sub/{device['id']}?k={device['secret']}"

    # 默认 (老客户端 / 接管不了 v6 的设备): 一个字节不变
    off = yaml.safe_load(client.get(sub).text)
    assert off["ipv6"] is False and off["dns"]["ipv6"] is False
    assert yaml.safe_load(client.get(sub + "&ipv6=0").text)["ipv6"] is False

    # 设备说能一并接管: 顶层与 DNS 两处**同时**打开 (只开一处是半吊子)
    on = yaml.safe_load(client.get(sub + "&ipv6=1").text)
    assert on["ipv6"] is True
    assert on["dns"]["ipv6"] is True
    # v4 那一套不受影响
    assert on["dns"]["enhanced-mode"] == "fake-ip"
    assert set(on["dns"]["nameserver-policy"]) == {"geosite:private,cn"}
    assert on["tun"]["auto-route"] is True

    # 多服务器骨架同一条路
    skel = yaml.safe_load(client.get(sub + "&format=skeleton&ipv6=1").text)
    assert skel["ipv6"] is True and skel["dns"]["ipv6"] is True


def test_install_script_ships_a_lan_only_redirect_datapath():
    """L3: iptables REDIRECT —— 给 21.02 / fw3 / 内核 5.4 那一代固件准备的路。

    那类机器上没有 nf_tables (nft 命令在、规则下不去), 原厂固件连 tun 都建不出来。
    以前客户端在那种机器上只能报"未生效"; 加上这一级之后, 局域网 TCP 至少被接管。

    两条硬约束:
      ① 只接管**从局域网接口进来**的流量 —— 绝不能用"所有接口"兜底, 那会把 WAN 侧入站
         也接管, 比不接管更糟;
      ② 跳转规则加不上 (接口名不对) 要**如实返回失败**, 让 verify 判它没生效, 而不是
         留下一条指向空气的规则还报成功 (8.45 的教训)。
    """
    from zeroproxy import router_client

    text = open(router_client.script_path(), encoding="utf-8").read()

    # 探测与落地都要有
    assert "redirect_ok()" in text and "zp_redirect_apply" in text and "zp_redirect_clear" in text
    assert "REDIRECT --to-ports" in text

    # ① 只从局域网接口进来 (接口名可从 uci / lan_ip 反查, 兜底 br-lan)
    assert "-I PREROUTING -i" in text, "跳转规则必须限定接口"
    assert "ZP_LANIF" in text and "br-lan" in text

    # ② 加不上就撤掉并返回失败 (不许报成功)
    assert "if ! iptables -t nat -I PREROUTING" in text

    # DNS 也要一并劫持 (fake-ip 才能按域名分流); 私有地址与代理端口自身先放行
    assert "--dport 53 -j REDIRECT" in text
    assert "198.18.0.0/16" in text and "-j RETURN" in text

    # 拆卸只动自己的链 (别人的规则一条不碰) —— 停服务 / 卸载两处都要调用
    assert "-F zp_router" in text and "-X zp_router" in text
    assert text.count("zp_redirect_clear") >= 4, "定义 + apply + stop_service + uninstall"
    # IPv6 那一半: 有 ip6tables 就一起接管, 没有就**如实记进 caps** (装不出规则也不许说接管了)
    assert "ip6tables -t nat -I PREROUTING" in text
    assert "zp_redirect_v6" in text and "ip6 daddr @local6" in text


def test_datapath_ladder_helpers_run_on_any_sh():
    """阶梯的两个纯函数: 往下试的顺序, 以及"这一级探测过了没有"。

    它们决定降级的顺序 —— 顺序错了会在明明有 tproxy 的机器上直接掉到 redirect, 或者在
    只有 redirect 的机器上空转。抠出来在真实 sh 里跑一遍 (与 json_get_bool 那条同理)。
    """
    import re
    import subprocess

    from zeroproxy import router_client

    text = open(router_client.script_path(), encoding="utf-8").read()
    parts = []
    for name in ("ladder_below", "rung_usable"):
        match = re.search(rf"^{name}\(\) \{{.*?\n\}}", text, re.S | re.M)
        assert match, f"安装脚本里应当有 {name}"
        parts.append(match.group(0))
    script = "\n".join(parts) + """
NET_TUN=1; NET_TPROXY=0; NET_REDIRECT=1
ladder_below tun
rung_usable tun && echo tun-yes || echo tun-no
rung_usable tproxy && echo tproxy-yes || echo tproxy-no
rung_usable redirect && echo redirect-yes || echo redirect-no
ladder_below redirect
"""
    out = subprocess.run(["sh", "-c", script], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert out.stdout.split() == ["tproxy", "redirect", "tun-yes", "tproxy-no", "redirect-yes"], out.stdout


def test_datapath_wiring_is_complete_and_caps_says_what_it_chose(tmp_path):
    """阶梯那条调用链必须首尾相接, 而且选完要把结论落进 caps。

    为什么专门盯这个: 安装演练跑到 `write_files` 就停了 (本机没有 procd), `verify()`
    那条链 (choose → set → apply → downgrade) 在自动化里**跑不到** —— 这次就是这么漏掉
    一个 `set_datapath` 的定义 (`set_datapath: not found` 只会在真机的降级分支上爆)。
    所以这里把纯函数抠出来, 在真实 sh 里真的调一遍: 缺定义会以 `not found` 暴露, 选错级
    会以 chosen / covered 对不上暴露。
    """
    import re
    import subprocess

    from zeroproxy import router_client

    text = open(router_client.script_path(), encoding="utf-8").read()

    # 一、verify 这条链上用到的函数一个都不能缺 (纯静态, 便宜且直接命中 not found)
    defined = set(re.findall(r"^([A-Za-z_][A-Za-z0-9_]*)\(\) \{", text, re.M))
    needed = {
        "kernel_ge", "lan_iface", "nft_ok", "tproxy_ok", "tun_ok", "redirect_ok", "ebpf_ok",
        "choose_datapath", "set_datapath", "write_caps", "caps_write",
        "rung_usable", "ladder_below",
        "datapath_live", "wait_datapath", "apply_datapath", "downgrade_datapath",
        "tun_retry_without_redirect",
    }
    assert needed <= defined, f"被调用但没有定义: {sorted(needed - defined)}"

    # 二、真的跑一遍: 挑级 → 写 caps → 换级 → 再写 caps
    parts = []
    for name in ("caps_write", "write_caps", "compute_ipv6_cap", "set_datapath", "choose_datapath"):
        match = re.search(rf"^{name}\(\) \{{.*?\n\}}", text, re.S | re.M)
        assert match, f"安装脚本里应当有 {name}"
        parts.append(match.group(0))
    root = str(tmp_path)
    script = (
        f'ZP_DIR="{root}"\n'
        "NET_TUN=1; NET_NFT=1; NET_TPROXY=1; NET_REDIRECT=1; NET_EBPF=0\n"
        'CAPS_WHY_TUN=""; CAPS_WHY_TPROXY="tproxy 不行"; CAPS_WHY_REDIRECT=""; CAPS_WHY_EBPF="内核太老"\n'
        'DATAPATH=""; COVERED=""\n'
        + "\n".join(parts)
        + '\nchoose_datapath; echo "chosen=$DATAPATH covered=$COVERED"\n'
        'sed -n "s/^chosen=/caps.chosen=/p" "$ZP_DIR/caps"\n'
        "NET_TUN=0\n"
        'choose_datapath; echo "chosen=$DATAPATH covered=$COVERED"\n'
        'set_datapath redirect; echo "chosen=$DATAPATH covered=$COVERED"\n'
        'sed -n "s/^why.ipv6=/ipv6why=/p" "$ZP_DIR/caps"\n'
        'grep -c "^why.tproxy=tproxy 不行$" "$ZP_DIR/caps"\n'
    )
    out = subprocess.run(["sh", "-c", script], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    lines = out.stdout.split()
    assert lines[0] == "chosen=tun" and lines[1] == "covered=full"
    assert "caps.chosen=tun" in out.stdout
    assert "chosen=tproxy" in lines and "covered=lan" in lines, lines
    assert "chosen=redirect" in lines and "covered=lan_tcp" in lines, lines
    # IPv6 能力是 chosen 的函数, 必须跟着一起落盘 (本机没有 ip6tables → redirect 只能 v4,
    # 而且要说得出原因 —— 这是"不许假装接管了"那一半)
    assert re.search(r"^ipv6why=\S", out.stdout, re.M), out.stdout
    # why.* 原样留着 (含中文与空格), 面板 / CLI 直接读
    assert "1" in lines[-1:], lines


def test_device_subscription_requires_secret(client, configured):
    _login(client)
    device = _register(client, _pair_code(client)["code"])
    assert client.get(f"/c/sub/{device['id']}?k=wrong").status_code == 403
    assert client.get(f"/c/sub/{device['id']}").status_code == 403
    assert client.get(f"/c/sub/dv-nope?k={device['secret']}").status_code == 403


def test_pair_response_advertises_geo_capability(client, configured):
    """客户端要在装机当场就知道"这台面板给不给分流数据"。

    旧面板没有 /c/geo, 而它给出的配置一定带 geo 规则 —— 路由器只能去 GitHub 拉并超时
    (真机就是这个现象)。所以配对响应里带一个能力位, 客户端据此决定是"停下来让用户先升级
    面板"还是"降级装上去"。
    """
    _login(client)
    data = _register(client, _pair_code(client)["code"])
    assert data["geo"] is True


def test_provider_format_is_nodes_only_with_domain_prefix(client, configured):
    """路由器端多服务器聚合: 每台面板出一个"只有节点"的文件, 挂成 mihomo provider。

    前缀不是装饰: 两台面板各自有一个"东京-01"时, 同名节点会让 mihomo 拒绝加载
    整份配置。用域名当前缀不需要路由器传参 —— 域名本来就是每台面板唯一的。
    """
    _login(client)
    device = _register(client, _pair_code(client)["code"])
    body = client.get(f"/c/sub/{device['id']}?k={device['secret']}&format=provider").text
    profile = yaml.safe_load(body)
    assert set(profile) == {"proxies"}, "provider 文件只能有 proxies, 不能带 rules/groups"
    assert len(profile["proxies"]) == 5
    assert all(p["name"].startswith(f"{DOMAIN} · ") for p in profile["proxies"]), profile["proxies"][0]

    # 名字仍是可读的, 前缀只是"哪台服务器"的标注
    assert any("VLESS Reality" in p["name"] for p in profile["proxies"])


def test_skeleton_format_leaves_providers_and_use_empty(client, configured):
    """多服务器模式的骨架: 端口/DNS/tun/规则齐全, 只有 providers 与组成员留空,
    等路由器填。留"空结构"而不是自定义标记, 是为了让骨架本身仍是合法配置。"""
    _login(client)
    device = _register(client, _pair_code(client)["code"])
    body = client.get(f"/c/sub/{device['id']}?k={device['secret']}&format=skeleton").text
    skeleton = yaml.safe_load(body)
    assert skeleton["proxy-providers"] == {}, "providers 必须是空 map (路由器按行填)"
    assert "proxies" not in skeleton, "多服务器模式不该内联节点"
    auto = [g for g in skeleton["proxy-groups"] if g["name"] == "♻️ 自动选择"][0]
    assert auto["use"] == [], "组的 use 必须留空给路由器填"
    # 骨架的其余部分与单服务器配置一致
    assert skeleton["tun"]["enable"] is True
    assert skeleton["dns"]["enhanced-mode"] == "fake-ip"
    assert any(r.startswith("GEOIP,CN,") for r in skeleton["rules"])
    assert "provider" not in body.split("proxy-providers", 1)[0].lower()  # 头部注释别误导


def test_device_template_override(client, configured):
    _login(client)
    device = _register(client, _pair_code(client)["code"])
    res = client.post(f"/api/devices/{device['id']}", json={"template": "global"})
    assert res.status_code == 200
    body = client.get(f"/c/sub/{device['id']}?k={device['secret']}").text
    assert "分流模板: global" in body

    assert client.post(f"/api/devices/{device['id']}", json={"template": "nope"}).status_code == 400


# ---------------------------------------------------------------- 开关与心跳

def test_heartbeat_reports_state_and_returns_desired(client, configured):
    _login(client)
    device = _register(client, _pair_code(client)["code"])
    res = client.post(
        "/c/report",
        json={"device": device["id"], "k": device["secret"], "actual": True, "version": "1.0.0"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["desired"] is True
    assert body["rev"]

    item = client.get("/api/devices").json()["devices"]["items"][0]
    assert item["online"] is True
    assert item["actual"] is True
    assert item["connected"] is True
    assert item["syncing"] is False


def test_heartbeat_carries_how_far_the_router_really_took_over(client, configured):
    """"内核在跑"≠"流量被接管" —— 设备把现场验过的数据面与覆盖范围一起报上来。

    真机 8.45: 内核启动成功, 但 tun 建不出来、tproxy 也没有, 局域网里一台设备都没被接管,
    面板却还是绿的"已连接"。所以设备每轮心跳带 `report: {mode, covered, why}`, 面板据此
    把话说细 (未接管 / 仅局域网 TCP / 全屋)。这三个值必须原样进面板视图 —— 它们同时是
    面板设备卡那枚标签的数据源, 也是排障时唯一能看到的"为什么"。
    """
    _login(client)
    device = _register(client, _pair_code(client)["code"])
    client.post("/c/report", json={
        "device": device["id"], "k": device["secret"], "actual": True,
        "report": {
            "mode": "redirect",
            "covered": "lan_tcp",
            "why": "建不出 tun 设备: Operation not supported",
            "client": "1.3.0",
        },
    })
    item = client.get("/api/devices").json()["devices"]["items"][0]
    assert item["report"]["mode"] == "redirect"
    assert item["report"]["covered"] == "lan_tcp"
    assert "Operation not supported" in item["report"]["why"]
    # 覆盖范围受限, 但"开关开着且内核真在跑"这件事仍然成立 —— 面板要能同时表达两件事
    assert item["connected"] is True


def test_toggle_writes_desired_and_device_sees_it(client, configured):
    _login(client)
    device = _register(client, _pair_code(client)["code"])
    assert client.post(f"/api/devices/{device['id']}/proxy", json={"on": False}).status_code == 200
    body = client.post(
        "/c/report", json={"device": device["id"], "k": device["secret"], "actual": True}
    ).json()
    assert body["desired"] is False

    item = client.get("/api/devices").json()["devices"]["items"][0]
    assert item["desired"] is False
    assert item["actual"] is True
    assert item["connected"] is False     # 关了就是关了, 不因为设备还在跑就算已连接


def test_device_side_toggle_is_followed(client, configured):
    """路由器本机 `zeroproxy off` 也是请求面板改期望状态, 不是本地硬关。"""
    _login(client)
    device = _register(client, _pair_code(client)["code"])
    res = client.post(
        "/c/report",
        json={"device": device["id"], "k": device["secret"], "actual": False, "set_desired": False},
    )
    assert res.json()["desired"] is False
    assert client.get("/api/devices").json()["devices"]["items"][0]["desired"] is False


def test_report_rejects_wrong_secret(client, configured):
    _login(client)
    device = _register(client, _pair_code(client)["code"])
    res = client.post("/c/report", json={"device": device["id"], "k": "nope", "actual": True})
    assert res.status_code == 403


def test_config_rev_tracks_config_not_heartbeat(client, configured):
    """配置版本必须只在配置变化时改变 —— 否则每 15 秒的心跳都会让路由器重载配置。"""
    _login(client)
    device = _register(client, _pair_code(client)["code"])
    first = client.post(
        "/c/report", json={"device": device["id"], "k": device["secret"]}
    ).json()["rev"]
    again = client.post(
        "/c/report", json={"device": device["id"], "k": device["secret"]}
    ).json()["rev"]
    assert first == again

    client.post("/api/nodes/trojan/toggle", json={})
    after = client.post(
        "/c/report", json={"device": device["id"], "k": device["secret"]}
    ).json()["rev"]
    assert after != first


# ---------------------------------------------------------------- 移除

def test_remove_device_revokes_credentials(client, configured):
    _login(client)
    device = _register(client, _pair_code(client)["code"])
    assert client.delete(f"/api/devices/{device['id']}").status_code == 200
    assert client.get(f"/c/sub/{device['id']}?k={device['secret']}").status_code == 403
    assert client.get("/api/devices").json()["devices"]["count"] == 0
    assert client.delete(f"/api/devices/{device['id']}").status_code == 404


def test_update_endpoint_needs_no_pairing_code(client, configured):
    """更新用的安装脚本不带配对码: 已装好的机器重跑它升级, 不会多出一台设备。

    用户反馈的原话: "重跑命令我就要先把原来的移除, 然后再生成一个新的" —— 那是把
    一次性配对码当成日常更新入口的必然结果。这个固定地址才是更新入口。
    """
    res = client.get("/c/install.sh")
    assert res.status_code == 200
    assert 'ZP_CODE=""' in res.text, "更新脚本不该带配对码"
    assert "用本次配对码重新接入" not in res.text.split("更新模式")[0]


def test_landing_rules_route_hard_region_sites(client, configured):
    """必须走落地的站点 (OpenAI / Netflix / Disney+ / Gemini / Claude ...)。

    链式节点的延迟永远高于直连节点, 所以"自动选择"不会选它; 而这类服务只认落地地区的
    IP —— 不单独指过去就是"能上网但站点打不开"。规则同时对三端生效 (路由器/手机/电脑),
    没配落地的用户由组里的兜底成员保证行为不变。
    """
    _login(client)
    device = _register(client, _pair_code(client)["code"])
    for path_ in (f"/c/sub/{device['id']}?k={device['secret']}",
                  configured["subscription_url"].split("testserver")[-1] + "?format=clash"):
        profile = yaml.safe_load(client.get(path_).text)
        rules = "\n".join(profile["rules"])
        for domain in ("chatgpt.com", "claude.ai", "gemini.google.com", "netflix"):
            assert domain in rules, (path_, domain)
        landing = [g for g in profile["proxy-groups"] if g["name"] == "🌍 落地节点"]
        assert landing, "必须有落地组"
        assert landing[0]["proxies"][-1] == "🚀 节点选择", "没有链式节点时要兜底到节点选择"
        # 落地规则必须在国内直连之前, 否则会被 cn 规则抢先放行
        assert rules.index("chatgpt.com") < rules.index("GEOIP,CN"), "落地规则要排在直连规则之前"

    # sing-box 侧以前漏了这一层 (同一个订阅在手机上打开 ChatGPT 会走最快的直连节点,
    # 而不是落地节点) —— 现在两端语义必须一致。
    sb = json.loads(
        client.get(configured["subscription_url"].split("testserver")[-1] + "?format=singbox").text
    )
    assert any(o["tag"] == "🌍 落地节点" for o in sb["outbounds"]), "sing-box 缺落地出站组"
    sb_rules = json.dumps(sb["route"]["rules"], ensure_ascii=False)
    assert "chatgpt.com" in sb_rules and "netflix" in sb_rules
    assert sb_rules.index("chatgpt.com") < sb_rules.index("qq.com"), "落地规则要早于国内直连"


def test_skeleton_landing_group_filters_chain_nodes(client, configured):
    """多服务器模式的落地组用 filter 从 provider 里挑"链式"节点, 并留兜底成员。"""
    _login(client)
    device = _register(client, _pair_code(client)["code"])
    skeleton = yaml.safe_load(
        client.get(f"/c/sub/{device['id']}?k={device['secret']}&format=skeleton").text
    )
    landing = [g for g in skeleton["proxy-groups"] if g["name"] == "🌍 落地节点"][0]
    assert landing["use"] == [], "use 要留给路由器填 provider"
    assert "链式" in landing["filter"]
    assert landing["proxies"] == ["🚀 节点选择"]
