"""客户端设备 (路由器) 回归测试: 配对 → 安装脚本 → 订阅 → 开关 → 移除。

全部离线可跑: 内核二进制那一项把下载函数换成本地假文件 (面板侧真正下载
20 MB 的 mihomo 不该出现在测试里)。
"""
from __future__ import annotations

import os

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
    monkeypatch.setattr(router_client, "fetch_core", lambda arch, **kw: (True, "已缓存", str(blob)))
    res = client.get("/c/bin/arm64")
    assert res.status_code == 200
    assert res.content == blob.read_bytes()


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
    assert "nameserver-policy" not in profile["dns"]   # 它的键也是 geosite:… , 要数据库
    assert profile["tun"]["enable"] is True
    # 多服务器模式 (骨架) 同样要能降级
    skeleton = yaml.safe_load(client.get(sub + "&format=skeleton&geo=0").text)
    assert "GEOSITE," not in "\n".join(skeleton["rules"])


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
