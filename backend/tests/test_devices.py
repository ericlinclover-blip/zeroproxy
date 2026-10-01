"""客户端设备 (路由器) 回归测试: 配对 → 安装脚本 → 订阅 → 开关 → 移除。

全部离线可跑: 内核二进制那一项把下载函数换成本地假文件 (面板侧真正下载
20 MB 的 mihomo 不该出现在测试里)。
"""
from __future__ import annotations

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


def test_install_script_sticks_to_busybox_tools():
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
    assert "geosite:geolocation-!cn" in profile["dns"]["nameserver-policy"]
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
