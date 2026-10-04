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


def test_geo_files_are_served_and_name_whitelisted(client, configured, tmp_path, monkeypatch):
    """分流数据库 (GeoIP / GeoSite) 也由面板分发 —— 和内核二进制同一条思路。

    真机 (GL-MT3000) 现场: mihomo 在 `-t` 时去 GitHub 拉 geoip.metadb, 拉不到就
    `can't download MMDB: context deadline exceeded` → 整份配置校验失败, 装机停在
    "写入运行文件"。所以这两份数据必须由面板给 (面板去取上游, 路由器只访问面板)。
    """
    from zeroproxy import router_client

    # 文件名是 mihomo 在 `-d` 目录里找来用的, 一个字节都不能改
    assert set(router_client.GEO_FILES) == {"geoip.metadb", "geosite.dat"}

    blob = tmp_path / "geoip.metadb"
    blob.write_bytes(b"M" * 128)
    monkeypatch.setattr(router_client, "fetch_geo", lambda name, **kw: (True, "已缓存", str(blob)))

    assert client.get("/c/geo/nope").status_code == 404
    assert client.get("/c/geo/..%2fstate.json").status_code == 404
    assert client.get("/c/geo/geoip.dat").status_code == 404
    res = client.get("/c/geo/geoip.metadb")
    assert res.status_code == 200
    assert res.content == blob.read_bytes()


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
    token_at = text.index('if [ ! -s "$ZP_DIR/ui.token" ]')
    luci_at = text.index('if [ -d /usr/share/luci/menu.d ]')
    assert token_at < luci_at, "令牌要在 LuCI 分支之前无条件生成"
    assert 'UI_URL_K="$UI_URL?k=$(cat "$ZP_DIR/ui.token"' in text, "要拼出带令牌的地址"
    assert 'ok "浏览器打开: $UI_URL_K"' in text, "安装摘要要打印带令牌的地址"
    # CLI 的 `zeroproxy ui` 一直就是打印带令牌的地址 —— 别把它改成裸地址
    assert 'echo "http://$_ip/cgi-bin/zeroproxy?k=$(cat "$ZP_DIR/ui.token"' in text


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


@pytest.mark.parametrize("name", ["index.html", "app.js", "cgi", "menu.json", "acl.json", "status.js"])
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
