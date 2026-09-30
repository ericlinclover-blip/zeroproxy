"""ZeroProxy 面板回归测试 (dry-run 全流程 + 订阅格式 + 安全边界)。"""
from __future__ import annotations

import base64
import errno
import json
import os
import shutil

import pytest

from conftest import DOMAIN, PASSWORD, USERNAME
from zeroproxy import config, crypto, xray_config


# ---------------------------------------------------------------- 初始化

def test_setup_requires_bootstrap_token(client, token):
    """面板暴露在公网时, 没有引导令牌的人不能抢先完成初始化。"""
    payload = {"domain": DOMAIN, "username": USERNAME, "password": PASSWORD, "token": "wrong"}
    assert client.post("/api/setup", json=payload).status_code == 403

    payload["token"] = token
    assert client.post("/api/setup", json=payload).status_code == 200


def test_setup_pipeline_all_steps_ok(configured):
    steps = configured["steps"]
    assert [s["name"] for s in steps][:2] == ["生成密钥材料", "写入面板状态"]
    assert all(s["ok"] for s in steps), steps
    assert len(configured["nodes"]) == 5
    assert configured["subscription_url"].endswith(configured["subscription_url"].split("/")[-1])


def test_setup_consumes_and_rejects_second_run(client, token, home):
    from zeroproxy import config

    payload = {"domain": DOMAIN, "username": USERNAME, "password": PASSWORD, "token": token}
    assert client.post("/api/setup", json=payload).status_code == 200
    assert config.bootstrap_token() == ""          # 令牌已作废
    assert client.post("/api/setup", json=payload).status_code == 409


def test_setup_validation(client, token):
    base = {"username": USERNAME, "password": PASSWORD, "token": token}
    assert client.post("/api/setup", json={**base, "domain": "not a domain"}).status_code == 400
    assert client.post("/api/setup", json={**base, "domain": DOMAIN, "password": "123"}).status_code == 400
    assert client.post("/api/setup", json={**base, "domain": DOMAIN, "username": "a"}).status_code == 400


def test_setup_tells_frontend_when_domain_panel_is_not_ready(client, token, home, monkeypatch):
    """初始化是在 IP 页面 (自签证书) 上做的。

    dry-run 拿不到真证书时, 后端必须明确说"域名面板还不可用 + 为什么", 前端才不会
    把用户跳到一个打不开、或者证书报错的地址上。
    """
    from zeroproxy import config, services

    monkeypatch.setattr(
        services, "probe_public_panel",
        lambda domain, port, timeout=10.0: (True, f"https://{domain}:{port} 可达且证书受信任"),
    )
    payload = {"domain": DOMAIN, "username": USERNAME, "password": PASSWORD, "token": token}
    body = client.post("/api/setup", json=payload).json()
    redirect = body["redirect"]
    assert redirect["ready"] is False
    assert "Let's Encrypt" in redirect["reason"]
    assert DOMAIN in redirect["url"] and str(config.PANEL_PORT) in redirect["url"]


def test_setup_offers_handoff_when_cert_and_domain_are_ready(client, token, home, monkeypatch):
    """真证书 + 域名真的能按浏览器方式访问到 → 告诉前端可以跳了 (带真实 URL)。"""
    import time as _time

    from zeroproxy import services

    calls = []

    def fake_install_cert(host: str):
        return True, "Let's Encrypt 证书已签发 (测试桩)", {
            "type": "letsencrypt",
            "issuer": "Let's Encrypt",
            "cert_file": str(home / "data" / "fullchain.pem"),
            "key_file": str(home / "data" / "privkey.pem"),
            "not_after": int(_time.time()) + 90 * 86400,
        }

    def fake_probe(domain: str, port: int, timeout: float = 10.0):
        calls.append((domain, port))
        return True, f"https://{domain}:{port} 可达且证书受信任"

    monkeypatch.setattr(services, "install_cert", fake_install_cert)
    monkeypatch.setattr(services, "probe_public_panel", fake_probe)
    payload = {"domain": DOMAIN, "username": USERNAME, "password": PASSWORD, "token": token}
    body = client.post("/api/setup", json=payload).json()

    assert body["redirect"]["ready"] is True, body["redirect"]
    assert DOMAIN in body["redirect"]["url"]
    assert calls and calls[0][0] == DOMAIN          # 真的按域名探过一次, 不是无脑跳


# ---------------------------------------------------------------- 鉴权

def test_dashboard_requires_auth(client, configured):
    client.post("/api/logout")
    assert client.get("/api/dashboard").status_code == 401


def test_login_rate_limit(client, configured):
    client.post("/api/logout")
    bad = {"username": USERNAME, "password": "nope"}
    for _ in range(3):
        assert client.post("/api/login", json=bad).status_code == 401
    fourth = client.post("/api/login", json=bad)
    assert fourth.status_code == 401
    assert int(fourth.headers["Retry-After"]) > 0      # 开始封禁
    blocked = client.post("/api/login", json=bad)
    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) > 0
    # 封禁期间即使密码正确也不放行
    assert client.post("/api/login", json={"username": USERNAME, "password": PASSWORD}).status_code == 429


def test_login_success_and_logout_all(client, configured):
    client.post("/api/logout")
    assert client.post("/api/login", json={"username": USERNAME, "password": PASSWORD}).status_code == 200
    assert client.get("/api/dashboard").status_code == 200
    assert client.post("/api/logout-all").json()["cleared"] >= 1
    assert client.get("/api/dashboard").status_code == 401


def test_security_headers(client):
    response = client.get("/api/status")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_csp_drops_unsafe_inline_but_whitelists_the_theme_bootstrap(client):
    """script-src 不再放行任意内联脚本, 但 head 里那段"首屏前应用主题"必须仍然跑得起来。

    前者是这次收紧的收益 (注入一个 <script> 已经执行不了); 后者是它的代价, 而且失败方式
    很安静 —— 脚本被拦下只会让深色模式退回浅色, 面板上几乎看不出来。所以哈希按 index.html
    的实际内容在启动时算, 并由这条测试盯住。
    """
    import base64
    import hashlib

    from zeroproxy import main as zp_main

    csp = client.get("/api/status").headers["Content-Security-Policy"]
    script_src = csp.split("script-src", 1)[1].split(";", 1)[0]
    assert "'unsafe-inline'" not in script_src, "script-src 不该再放行任意内联脚本"

    with open(os.path.join(zp_main._static_dir(), "index.html"), encoding="utf-8") as fh:
        html = fh.read()
    blocks = [
        body
        for attrs, body in zp_main._INLINE_SCRIPT_RE.findall(html)
        if "src=" not in attrs.lower()
    ]
    assert len(blocks) == 1, f"内联脚本应当只剩主题引导那一段, 实际 {len(blocks)} 段"
    digest = base64.b64encode(hashlib.sha256(blocks[0].encode("utf-8")).digest()).decode()
    assert f"'sha256-{digest}'" in script_src, "内联脚本的哈希必须在白名单里, 否则主题会静默失效"


# ---------------------------------------------------------------- 订阅

def test_subscription_base64_contains_all_enabled_nodes(client, configured):
    body = client.get(configured["subscription_url"].replace("http://testserver", "")).text
    text = base64.b64decode(body).decode()
    links = text.splitlines()
    assert len(links) == 5
    assert links[0].startswith("vless://") and "security=reality" in links[0]
    assert "type=xhttp" in links[1]
    assert "type=ws" in links[2]
    assert links[3].startswith("trojan://")
    assert links[4].startswith("hysteria2://")


def test_hysteria_link_carries_password_only_and_hop_ports(client, configured):
    """官方客户端把 `user:pass@` 整串当作 auth, 而服务端是整串比较口令。"""
    path = configured["subscription_url"].split("testserver")[-1]
    text = base64.b64decode(client.get(path).text).decode()
    hy = [line for line in text.splitlines() if line.startswith("hysteria2://")][0]
    assert f"hysteria2://{PASSWORD}@" in hy               # 只写口令, 没有 admin:
    assert "admin:" not in hy
    assert f":{configured['ports']['hysteria']}" in hy
    assert "30001,31001,32001" in hy                       # 端口跳跃写进 host
    assert "mport=" in hy
    assert "insecure=1" in hy


def test_subscription_clash_is_valid_yaml(client, configured):
    yaml = pytest.importorskip("yaml")
    path = configured["subscription_url"].split("testserver")[-1] + "?format=clash"
    response = client.get(path)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/yaml")
    profile = yaml.safe_load(response.text)
    proxies = profile["proxies"]
    types = {p["type"] for p in proxies}
    assert {"vless", "trojan", "hysteria2"} <= types
    reality = [p for p in proxies if "reality-opts" in p][0]
    assert reality["network"] == "tcp" and reality["flow"] == "xtls-rprx-vision"
    hy = [p for p in proxies if p["type"] == "hysteria2"][0]
    assert hy["ports"] == "30001,31001,32001" and hy["sni"] == DOMAIN
    assert profile["proxy-groups"] and profile["rules"][-1].startswith("MATCH")


def test_subscription_singbox_is_valid_json(client, configured):
    path = configured["subscription_url"].split("testserver")[-1] + "?format=singbox"
    response = client.get(path)
    assert response.status_code == 200
    profile = json.loads(response.text)
    outbounds = profile["outbounds"]
    types = {o["type"] for o in outbounds}
    assert {"vless", "trojan", "hysteria2", "direct"} <= types
    reality = [o for o in outbounds if o.get("tls", {}).get("reality", {}).get("enabled")][0]
    assert reality["flow"] == "xtls-rprx-vision"
    hy = [o for o in outbounds if o["type"] == "hysteria2"][0]
    assert hy["server_ports"] == ["30001:30001", "31001:31001", "32001:32001"]


def test_subscription_headers(client, configured):
    path = configured["subscription_url"].split("testserver")[-1]
    response = client.get(path)
    assert response.headers["profile-update-interval"] == "12"
    assert response.headers["cache-control"] == "no-store"


def test_invalid_token_404(client, configured):
    assert client.get("/sub/definitely-wrong-token").status_code == 404


def test_subscription_survives_all_nodes_disabled(client, configured):
    """节点全关时订阅也必须能被客户端加载。

    策略组只能引用真实存在的组: `♻️ 自动选择` 只在有节点时才生成, 而
    `🚀 节点选择` 曾经无条件引用它 —— mihomo / sing-box 遇到不存在的组会直接
    拒绝整份订阅, 用户看到的是"把节点全关掉之后订阅就坏了"。
    """
    yaml = pytest.importorskip("yaml")

    for node_id in ("vless-reality", "vless-xhttp", "vless-ws", "trojan", "hysteria2"):
        assert client.post(f"/api/nodes/{node_id}/toggle").status_code == 200

    path = configured["subscription_url"].split("testserver")[-1]
    clash = yaml.safe_load(client.get(f"{path}?format=clash").text)
    assert clash["proxies"] == []
    groups = {g["name"] for g in clash["proxy-groups"]}
    for group in clash["proxy-groups"]:
        for member in group["proxies"]:
            assert member in groups or member in ("DIRECT", "REJECT"), (group["name"], member)

    singbox = json.loads(client.get(f"{path}?format=singbox").text)
    tags = {o["tag"] for o in singbox["outbounds"]}
    for out in singbox["outbounds"]:
        for member in out.get("outbounds", []):
            assert member in tags, (out["tag"], member)


def test_panel_index_revalidates(client):
    """面板首页必须每次回源校验。

    只带 Last-Modified/ETag 而不带 Cache-Control 时浏览器会启发式缓存, 升级后
    面板可能还在跑旧版前端 —— 表现就是"明明修了按钮还是卡"。
    """
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-cache"


# ---------------------------------------------------------------- 分流模板

def _sub(client, configured, fmt="clash", extra=""):
    path = configured["subscription_url"].split("testserver")[-1]
    response = client.get(f"{path}?format={fmt}{extra}")
    assert response.status_code == 200, response.text
    return response


def test_routing_template_defaults_to_smart(client, configured):
    """默认即「智能分流」, 面板把三个模板都暴露给前端。"""
    from zeroproxy import share_links

    dash = client.get("/api/dashboard").json()
    assert dash["routing"]["template"] == "smart"
    assert [t["id"] for t in dash["routing"]["templates"]] == list(share_links.TEMPLATES)
    state = config.load_state()
    assert state["routing"]["template"] == "smart"


def test_clash_templates(client, configured):
    yaml = pytest.importorskip("yaml")

    smart = yaml.safe_load(_sub(client, configured).text)
    rules = "\n".join(smart["rules"])
    assert "GEOSITE,category-ads-all" in rules and "GEOSITE,cn," in rules
    assert "GEOIP,LAN," in rules and "GEOIP,CN," in rules
    assert smart["rules"][-1] == "MATCH,🐟 漏网之鱼"
    assert [g["name"] for g in smart["proxy-groups"]] == [
        "♻️ 自动选择",
        "🚀 节点选择",
        "🎯 全球直连",
        "🛑 广告拦截",
        "🐟 漏网之鱼",
    ]
    assert smart["geox-url"]["geoip"].startswith("https://")

    # global: 只拦广告, 其余全走节点
    glob = yaml.safe_load(_sub(client, configured, extra="&rules=global").text)
    grules = "\n".join(glob["rules"])
    assert "GEOSITE,category-ads-all" in grules
    assert "GEOSITE,cn," not in grules and "GEOIP,CN," not in grules
    assert glob["rules"][-1] == "MATCH,🚀 节点选择"

    # direct: 不引用任何 geo 规则 (客户端零下载)
    direct = yaml.safe_load(_sub(client, configured, extra="&rules=direct").text)
    assert direct["rules"] == ["MATCH,🐟 漏网之鱼"]
    assert direct["proxy-groups"][-1]["proxies"][0] == "DIRECT"


def test_singbox_templates_download_rule_set_directly(client, configured):
    """远程 rule-set 必须直连下载 —— 否则节点不可达时 sing-box 直接起不来。

    实测 (见 docs/RESEARCH.md): 不指定 download_detour 时 sing-box 会拿默认出站
    (也就是节点) 去下载 rule-set, 节点不通就 FATAL。
    """
    profile = json.loads(_sub(client, configured, fmt="singbox").text)
    route = profile["route"]
    assert {rs["tag"] for rs in route["rule_set"]} == {"ads", "cn", "cn-ip"}
    assert all(rs["download_detour"] == "direct" for rs in route["rule_set"])
    assert all(rs["url"].startswith("https://") for rs in route["rule_set"])
    assert profile["experimental"]["cache_file"]["enabled"] is True
    # 默认格式面向 1.8~1.15 的通用写法, 不能出现 1.14 才有的字段
    assert "http_clients" not in profile and "default_http_client" not in route
    assert route["final"] == "🚀 节点选择"
    assert {o["tag"] for o in profile["outbounds"]} >= {"direct", "♻️ 自动选择", "🚀 节点选择"}

    glob = json.loads(_sub(client, configured, fmt="singbox", extra="&rules=global").text)
    assert [rs["tag"] for rs in glob["route"]["rule_set"]] == ["ads"]
    assert glob["route"]["final"] == "🚀 节点选择"

    direct = json.loads(_sub(client, configured, fmt="singbox", extra="&rules=direct").text)
    assert "rule_set" not in direct["route"]
    assert "experimental" not in direct                # 无下载也就无需缓存
    assert direct["route"]["final"] == "🐟 漏网之鱼"
    assert direct["route"]["rules"][-1]["outbound"] == "🎯 全球直连"


def test_singbox_next_format_uses_http_client(client, configured):
    """`?format=singbox-next` 面向 sing-box ≥1.14 (download_detour 已废弃)。"""
    from zeroproxy import share_links

    profile = json.loads(_sub(client, configured, fmt="singbox-next").text)
    assert profile["http_clients"] == [{"tag": share_links.DEFAULT_HTTP_CLIENT}]
    assert profile["route"]["default_http_client"] == share_links.DEFAULT_HTTP_CLIENT
    assert "download_detour" not in json.dumps(profile)
    assert profile["experimental"]["cache_file"]["enabled"] is True


def test_routing_template_setting_persists_without_service_restart(client, configured):
    response = client.post("/api/settings", json={"template": "global"})
    assert response.status_code == 200, response.text
    steps = {s["name"]: s for s in response.json()["steps"]}
    assert steps["切换分流模板"]["ok"] is True
    assert "未重载服务" in steps["切换分流模板"]["detail"]
    assert "重载服务 (nginx/xray/hysteria2)" not in steps

    assert config.load_state()["routing"]["template"] == "global"
    assert client.get("/api/dashboard").json()["routing"]["template"] == "global"
    yaml = pytest.importorskip("yaml")
    assert yaml.safe_load(_sub(client, configured).text)["rules"][-1] == "MATCH,🚀 节点选择"


def test_routing_template_validation_and_override(client, configured):
    # 非法模板: 设置接口拒绝, URL 参数则忽略 (回落到已保存的模板)
    assert client.post("/api/settings", json={"template": "turbo"}).status_code == 400
    yaml = pytest.importorskip("yaml")
    fallback = yaml.safe_load(_sub(client, configured, extra="&rules=turbo").text)
    assert "GEOSITE,cn," in "\n".join(fallback["rules"])   # 仍是 smart
    # URL 参数覆盖不改变面板设置
    _sub(client, configured, extra="&rules=direct")
    assert config.load_state()["routing"]["template"] == "smart"


# ---------------------------------------------------------------- 节点操作

def test_toggle_node_updates_subscription(client, configured):
    path = configured["subscription_url"].split("testserver")[-1]
    assert len(base64.b64decode(client.get(path).text).decode().splitlines()) == 5

    body = client.post("/api/nodes/vless-ws/toggle").json()
    assert body["nodes"][2]["enabled"] is False
    text = base64.b64decode(client.get(path).text).decode()
    assert "type=ws" not in text and len(text.splitlines()) == 4

    client.post("/api/nodes/vless-ws/toggle")
    assert len(base64.b64decode(client.get(path).text).decode().splitlines()) == 5


def test_toggle_hysteria_hopping_scales_ports(client, configured, home):
    yaml = pytest.importorskip("yaml")
    conf = (home / "hysteria" / "config.yaml").read_text()
    assert 'listen: "0.0.0.0:30001,31001,32001"' in conf
    assert "masquerade:" in conf and "rewriteHost: true" in conf
    parsed = yaml.safe_load(conf)
    assert parsed["listen"] == "0.0.0.0:30001,31001,32001"
    assert parsed["masquerade"]["proxy"]["url"] == "https://www.microsoft.com/"
    assert parsed["tls"]["cert"].endswith("hysteria/cert.pem")

    body = client.post("/api/hysteria/hopping").json()
    assert body["hysteria_hopping"] is False
    conf = (home / "hysteria" / "config.yaml").read_text()
    assert 'listen: "0.0.0.0:30001"' in conf
    assert yaml.safe_load(conf)["listen"] == "0.0.0.0:30001"
    path = configured["subscription_url"].split("testserver")[-1]
    text = base64.b64decode(client.get(path).text).decode()
    hy = [line for line in text.splitlines() if line.startswith("hysteria2://")][0]
    assert ":30001?" in hy


def test_unknown_node_404(client, configured):
    assert client.post("/api/nodes/nope/toggle").status_code == 404


def test_toggle_hopping_realigns_ports_after_a_port_change(client, configured, monkeypatch):
    """回归: 主端口改过之后再打开端口跳跃, 跳跃区间必须跟着主端口走 ——
    否则面板显示 40002, Hysteria 实际监听的还是上一轮的 40001/41001/42001。"""
    from zeroproxy import services

    monkeypatch.setattr(services, "port_available", lambda port, proto="tcp": True)
    # 先关掉跳跃, 趁它关着改主端口 (关着时不会重排区间)
    assert client.post("/api/hysteria/hopping").json()["hysteria_hopping"] is False
    assert client.post("/api/settings", json={"ports": {"hysteria2": 40001}}).status_code == 200
    assert client.post("/api/settings", json={"ports": {"hysteria2": 40002}}).status_code == 200
    assert config.load_state()["hysteria_ports"] == [30001, 31001, 32001]

    body = client.post("/api/hysteria/hopping").json()
    assert body["hysteria_hopping"] is True
    assert body["hysteria_ports"] == [40002, 41002, 42002]
    assert config.load_state()["ports"]["hysteria"] == 40002


def test_settings_port_change_also_opens_the_firewall(client, configured, monkeypatch):
    """换了端口就要让 ufw 跟上 (install.sh 只放行默认端口), 并把这一步写进结果清单。"""
    from zeroproxy import services

    opened: list[tuple[int, str]] = []
    monkeypatch.setattr(
        services,
        "open_firewall_port",
        lambda port, proto="tcp": opened.append((int(port), proto)) or f"ufw 已放行 {port}/{proto}",
    )
    body = client.post("/api/settings", json={"ports": {"trojan": 9443}}).json()
    assert opened == [(9443, "tcp")]
    step = [s for s in body["steps"] if s["name"] == "放行新端口 9443/tcp"]
    assert step and step[0]["ok"] is True, body["steps"]


def test_settings_update_sni_and_port(client, configured, home):
    response = client.post(
        "/api/settings", json={"reality_sni": "www.cloudflare.com", "ports": {"trojan": 9443}}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["reality"]["server_name"] == "www.cloudflare.com"
    assert body["reality"]["dest"] == "www.cloudflare.com:443"
    trojan = [n for n in body["nodes"] if n["id"] == "trojan"][0]
    assert trojan["port"] == 9443

    from zeroproxy import xray_config
    from zeroproxy.config import load_state

    state = load_state()
    trojan_inbound = [i for i in xray_config.build_xray_config(state)["inbounds"] if i["tag"] == "trojan"][0]
    assert trojan_inbound["port"] == 9443
    assert trojan_inbound["settings"]["fallbacks"][0]["dest"] == "www.cloudflare.com:443"


def test_settings_rejects_bad_input(client, configured):
    assert client.post("/api/settings", json={"reality_sni": "not a host"}).status_code == 400
    assert client.post("/api/settings", json={"masquerade_url": "ftp://x"}).status_code == 400
    assert client.post("/api/settings", json={"ports": {"trojan": 70000}}).status_code == 400
    assert client.post("/api/settings", json={"ports": {"vless-ws": 8443}}).status_code == 400
    assert client.post("/api/settings", json={"ports": {}}).status_code == 400


def test_settings_rejects_duplicate_ports(client, configured):
    """一次请求把两个节点改成同一个端口必须当场拦下。

    以前只看"单个端口能不能 bind" —— 端口还没被任何进程占用时, 两个节点改成
    同一个端口都会通过, 直到落地时 `xray -test` 报重复端口, 面板上只剩一句
    含糊的失败。
    """
    same = client.post(
        "/api/settings", json={"ports": {"vless-reality": 9444, "vless-xhttp": 9444}}
    )
    assert same.status_code == 400, same.text
    assert "同时占用" in same.json()["error"]

    # 挪到别的节点正在用的端口 (对方并没有腾出来) 同样不行 —— dry-run 下没有进程
    # 在监听, 只能靠"改完之后的整张端口表"发现
    assert client.post("/api/settings", json={"ports": {"vless-reality": 8445}}).status_code == 400
    # 也不能抢 WS 回环 / Stats API 的端口
    assert client.post("/api/settings", json={"ports": {"vless-reality": 6000}}).status_code == 400
    assert client.post("/api/settings", json={"ports": {"vless-reality": 10085}}).status_code == 400
    # 失败不能留下半截状态
    state = config.load_state()
    assert state["ports"]["reality"] == 8443 and state["ports"]["xhttp"] == 8445


def test_settings_allows_swapping_two_node_ports(client, configured, monkeypatch):
    """两个节点对调端口必须允许 —— 它们会一起腾空。

    探测单个端口时看到的是"自己正在监听" (Linux 上绑在 INADDR_ANY 的监听 socket
    会挡住任何本地地址的 bind), 老写法会把这种正常换端口也拦下来。这里把
    port_available 换成"本机节点端口都算被占", 模拟生产环境。
    """
    from zeroproxy import services

    listening = {int(port) for port in config.load_state()["ports"].values()}
    monkeypatch.setattr(
        services, "port_available", lambda port, proto="tcp": int(port) not in listening
    )
    response = client.post("/api/settings", json={"ports": {"vless-reality": 8444, "trojan": 8443}})
    assert response.status_code == 200, response.text
    state = config.load_state()
    assert state["ports"]["reality"] == 8444 and state["ports"]["trojan"] == 8443


# ---------------------------------------------------------------- 诊断 / 二维码

def test_diagnose_reports_checks(client, configured):
    body = client.get("/api/diagnose").json()
    names = [c["name"] for c in body["checks"]]
    assert "Xray 配置" in names and "TLS 证书" in names
    assert body["summary"].endswith("项通过")
    xray = [c for c in body["checks"] if c["name"] == "Xray 配置"][0]
    assert xray["ok"] is True


def test_diagnose_does_not_flag_own_listening_ports(client, configured, monkeypatch):
    """生产机上"端口占用"只能报别的进程, 不能把本机核心自己的监听算成冲突。

    Linux 上绑在 INADDR_ANY 的监听 socket 会挡住任何本地地址的 bind, 所以只看
    `port_available` 的话, 健康的生产机每次诊断都会把 4 个节点端口全报成"被占用"。
    """
    from zeroproxy import services

    own_ports = {int(port) for port in config.load_state()["ports"].values()}
    monkeypatch.setattr(services, "is_prod", lambda: True)
    monkeypatch.setattr(
        services, "port_available", lambda port, proto="tcp": int(port) not in own_ports
    )
    monkeypatch.setattr(
        services,
        "port_owner",
        lambda port, proto="tcp": "hysteria" if proto == "udp" else "xray",
    )
    checks = {c["name"]: c for c in client.get("/api/diagnose").json()["checks"]}
    assert checks["端口占用"]["ok"] is True, checks["端口占用"]

    # 端口被别的进程抢走时必须报出来 (带上进程名)
    monkeypatch.setattr(services, "port_owner", lambda port, proto="tcp": "evilproc")
    checks = {c["name"]: c for c in client.get("/api/diagnose").json()["checks"]}
    assert checks["端口占用"]["ok"] is False
    assert "evilproc" in checks["端口占用"]["detail"]


def test_repair_regenerates_configs(client, configured):
    body = client.post("/api/repair").json()
    assert [s["name"] for s in body["steps"]][:2] == [
        "校验 Reality 密钥与伪装目标", "重新生成 Xray 配置"]
    assert all(s["ok"] for s in body["steps"]), body["steps"]


def test_qr_endpoints(client, configured):
    assert client.get("/api/nodes/hysteria2/qr?size=4").headers["content-type"] == "image/png"
    assert client.get("/api/subscription/qr?size=4").headers["content-type"] == "image/png"
    assert client.get("/api/nodes/nope/qr").status_code == 404


def test_qr_endpoints_support_svg_for_screen(client, configured):
    """面板里的二维码走矢量: 位图被 CSS 缩到卡片宽度后会糊, 手机上扫码容易失败。

    同时保留 PNG 后缀行为 (「保存图片」按钮和既有调用方要位图)。
    """
    for url in ("/api/nodes/vless-reality/qr?img=svg",
                "/api/subscription/qr?img=svg&format=clash"):
        resp = client.get(url)
        assert resp.status_code == 200, url
        assert resp.headers["content-type"].startswith("image/svg+xml"), url
        body = resp.content.decode()
        assert "<svg" in body and "viewBox" in body        # 有 viewBox 才能无级缩放
        assert 'shape-rendering="crispEdges"' in body      # 硬边方块, 不做抗锯齿
        assert resp.headers["cache-control"] == "no-store"
    # 未知 img 值退回 PNG (不能让"保存图片"拿到一张坏图)
    assert client.get("/api/nodes/vless-reality/qr?img=bogus").headers["content-type"] == "image/png"


def test_traffic_unavailable_without_xray(client, configured):
    body = client.get("/api/traffic").json()
    assert body.get("available") is not True


# ---------------------------------------------------------------- 状态与产物

def test_state_file_permissions_and_version(configured, home):
    from zeroproxy import config

    state_path = home / "data" / "state.json"
    assert oct(state_path.stat().st_mode)[-3:] == "600"
    state = json.loads(state_path.read_text())
    assert state["version"] == config.STATE_VERSION
    assert "login_failures" in state and "audit" in state


def test_state_migrates_v1_layout(home):
    """v1 的 state.json (缺少 xhttp / masquerade / 统计字段) 必须能平滑升级。"""
    from zeroproxy import config

    (home / "data").mkdir(parents=True, exist_ok=True)
    (home / "data" / "state.json").write_text(
        json.dumps({"version": 1, "configured": True, "domain": "old.example.com",
                    "nodes": {"vless-reality": True, "vless-ws": True, "trojan": False,
                              "hysteria2": True}})
    )
    state = config.load_state()
    assert state["version"] == config.STATE_VERSION
    assert state["ports"]["xhttp"] == 8445
    assert state["nodes"]["vless-xhttp"] is True          # 新节点自动补默认值
    assert state["hysteria_masquerade"]["enabled"] is True
    assert state["reality"]["server_name"] == "www.cloudflare.com"
    # v2 → v3 新增的 GeoIP 分流字段同样自动补齐
    assert state["geodata"]["enabled"] is False
    assert state["geodata"]["block_private"] is True
    # 分流模板是纯增量字段 (补默认值即 smart), 老状态不需要版本迁移
    assert state["routing"]["template"] == "smart"


def test_generated_xray_config_matches_enabled_nodes(client, configured, home):
    from zeroproxy import config, xray_config

    state = config.load_state()
    cfg = xray_config.build_xray_config(state)
    tags = [i["tag"] for i in cfg["inbounds"]]
    assert tags == ["vless-reality", "vless-xhttp", "vless-ws", "trojan", "api"]

    # 关掉一个节点后, 对应入站消失, API 入站保留 (面板靠它读流量)
    state["nodes"]["vless-xhttp"] = False
    tags = [i["tag"] for i in xray_config.build_xray_config(state)["inbounds"]]
    assert tags == ["vless-reality", "vless-ws", "trojan", "api"]

    # 全部关闭时不保留 API 入站
    for nid in state["nodes"]:
        state["nodes"][nid] = False
    assert xray_config.build_xray_config(state)["inbounds"] == []


def test_xray_config_with_real_binary(client, configured, home, monkeypatch):
    """指定 ZP_XRAY_BIN 时, 用真实 Xray 校验生成配置 (含 XHTTP + Stats API)。"""
    import os

    binary = os.environ.get("ZP_XRAY_BIN")
    if not binary or not os.path.exists(binary):
        pytest.skip("未提供 ZP_XRAY_BIN")
    monkeypatch.setenv("ZP_XRAY_BIN", binary)
    from zeroproxy import config, services, xray_config

    xray_config.write_xray_config(config.load_state())
    ok, detail = services.xray_config_test()
    assert ok, detail


# ---------------------------------------------------------------- Reality 密钥体系

def _legacy_ed25519_pair() -> tuple[str, str]:
    """复刻 v2.3.2 及更早版本 crypto.new_reality_keys() 的产物 (Ed25519)。"""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    key = Ed25519PrivateKey.generate()
    private_key = base64.urlsafe_b64encode(
        key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    ).decode().rstrip("=")
    public_key = base64.urlsafe_b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode().rstrip("=")
    return private_key, public_key


def test_reality_keys_are_paired_x25519(home):
    """回归: REALITY 只认 X25519, 且服务端私钥必须与下发客户端的 pbk 是同一对。

    历史 bug: 用 Ed25519 生成密钥 → 服务端与订阅里的 pbk 对不上 → Xray 每次握手
    都失败 (客户端日志 "received real certificate", 疑似 MITM), 而服务一直是
    active、面板显示"运行中" —— 4 个 TCP 节点全不通, 只有 Hysteria 2 可达。
    """
    from zeroproxy import crypto

    private_key, public_key, short_id = crypto.new_reality_keys()
    assert crypto.reality_public_from_private(private_key) == public_key
    assert crypto.reality_key_valid(private_key, public_key)
    assert len(private_key) == 43 and len(public_key) == 43   # base64url 无填充的 32B
    assert len(short_id) == 8

    legacy_private, legacy_public = _legacy_ed25519_pair()
    assert not crypto.reality_key_valid(legacy_private, legacy_public)
    assert not crypto.reality_key_valid(public_key, public_key)      # 公私钥错位
    assert not crypto.reality_key_valid("!!!not-base64!!!", public_key)
    assert not crypto.reality_key_valid("", public_key)
    assert not crypto.reality_key_valid(private_key, "")


def test_apply_migrates_legacy_reality_keys(client, home, configured):
    """旧 state 里的 Ed25519 密钥对必须在落地时被自动换成 X25519 (升级即自愈)。"""
    from zeroproxy import apply, crypto

    state = config.load_state()
    state["reality"]["private_key"], state["reality"]["public_key"] = _legacy_ed25519_pair()
    state["reality"]["short_id"] = "a1b2c3d4"
    config.save_state(state)

    steps = apply.reapply(state)

    assert steps[0]["name"] == "校验 Reality 密钥与伪装目标" and steps[0]["ok"] is True
    assert "X25519" in steps[0]["detail"] and "重新生成" in steps[0]["detail"]
    assert crypto.reality_key_valid(state["reality"]["private_key"], state["reality"]["public_key"])
    assert state["reality"]["short_id"] == "a1b2c3d4"        # sid 本身合法, 保留原值

    # 幂等: 已经是合法密钥时不动它 (否则每次落地都换 pbk, 客户端订阅白拉)
    again = apply.reapply(state)
    assert again[0]["ok"] is True and "有效" in again[0]["detail"]


def test_apply_migrates_legacy_masquerade_target(client, home, configured):
    """旧默认伪装目标 www.microsoft.com 的证书链 8273 字节 > REALITY 的 8KB 缓冲,
    握手必然失败 (真机实测 `REALITY: processed invalid connection ... handshake did
    not complete successfully`) → 落地时自动换成新默认值; 用户自己改过的不动。"""
    from zeroproxy import apply

    state = config.load_state()
    state["reality"]["dest"] = config.LEGACY_REALITY_DEST
    state["reality"]["server_name"] = config.LEGACY_REALITY_SNI
    config.save_state(state)

    steps = apply.reapply(state)

    assert steps[0]["ok"] is True and "8KB" in steps[0]["detail"]
    assert state["reality"]["dest"] == config.DEFAULT_REALITY_DEST
    assert state["reality"]["server_name"] == config.DEFAULT_REALITY_SNI
    assert config.DEFAULT_REALITY_DEST == "www.cloudflare.com:443"   # 实测握手通过

    # 用户自选目标不得被改写 (哪怕它同样有问题, 用户要能看到自己选的)
    state["reality"]["dest"] = state["reality"]["server_name"] = "www.samsung.com"
    state["reality"]["dest"] = "www.samsung.com:443"
    config.save_state(state)
    apply.reapply(state)
    assert state["reality"]["server_name"] == "www.samsung.com"


def test_apply_reapply_leaves_valid_targets_alone(client, home, configured):
    from zeroproxy import apply

    state = config.load_state()
    before = (state["reality"]["dest"], state["reality"]["server_name"])
    detail = apply.reapply(state)[0]["detail"]
    assert (state["reality"]["dest"], state["reality"]["server_name"]) == before
    assert "非已知问题值" in detail


def test_apply_restores_missing_cert_files(client, home, configured):
    """证书文件丢了要能自己补回来 —— 否则 nginx -t 必失败 (换机恢复备份的典型场景)。"""
    from zeroproxy import apply

    state = config.load_state()
    for key in ("cert_file", "key_file"):
        os.remove(state["cert"][key])
    # 备份里留着旧机器的 Let's Encrypt 路径, 但本机没有那份私钥
    state["cert"]["type"] = "letsencrypt"
    config.save_state(state)

    steps = apply.reapply(state)
    assert steps[0]["ok"] is True, steps[0]
    assert "自签" in steps[0]["detail"], steps[0]
    assert state["cert"]["type"] == "selfsigned"
    assert os.path.exists(state["cert"]["cert_file"])
    assert os.path.exists(state["cert"]["key_file"])


@pytest.mark.skipif(not os.environ.get("ZP_XRAY_BIN"), reason="需要真实 xray 二进制 (ZP_XRAY_BIN)")
def test_reality_keys_match_real_xray(home, monkeypatch):
    """最硬的校验: 用真实 `xray x25519 -i <私钥>` 反推公钥, 必须与 state 里的 pbk 一致。"""
    import subprocess

    from zeroproxy import crypto, services

    binary = services.bin_path("xray")
    private_key, public_key, _ = crypto.new_reality_keys()
    proc = subprocess.run(
        [binary, "x25519", "-i", private_key], capture_output=True, text=True, timeout=30
    )
    assert proc.returncode == 0, proc.stderr
    line = next(l for l in proc.stdout.splitlines() if "PublicKey" in l)
    assert line.split(":", 1)[1].strip() == public_key


# ---------------------------------------------------------------- 节点延迟探测

def test_probe_endpoint_reports_every_node(client, configured):
    """测速接口: 即使内核没在跑也要给出每个节点的结论, 而不是 500。"""
    response = client.get("/api/probe?force=1")
    assert response.status_code == 200
    body = response.json()
    assert {n["node"] for n in body["nodes"]} == {
        "vless-reality",
        "vless-xhttp",
        "vless-ws",
        "trojan",
        "hysteria2",
    }
    # 没有真实内核监听时, 结论必须是"失败"而不是"未定义"
    for item in body["nodes"]:
        assert item["ok"] is not None
        assert item["detail"]
    assert body["dest"]["address"] == "www.cloudflare.com:443"


def test_probe_requires_auth(client, configured):
    client.cookies.clear()
    assert client.get("/api/probe").status_code == 401


def test_probe_skips_disabled_nodes(client, configured):
    client.post("/api/nodes/hysteria2/toggle")
    body = client.get("/api/probe?force=1").json()
    hysteria = next(n for n in body["nodes"] if n["node"] == "hysteria2")
    assert hysteria["ok"] is None and "关闭" in hysteria["detail"]


def test_deep_probe_client_config_covers_every_tcp_node(home):
    """深度体检用的客户端配置必须真的带上各节点的关键参数 (否则体检没意义)。"""
    from zeroproxy import config as cfg, services

    state = cfg.load_state()
    state["reality"]["dest"] = "www.cloudflare.com:443"
    state["reality"]["server_name"] = "www.cloudflare.com"

    for node_id, network in (("vless-reality", "tcp"), ("vless-xhttp", "xhttp"),
                             ("vless-ws", "ws"), ("trojan", "tcp")):
        cfg_json = services.client_config(state, node_id, 12345)
        assert cfg_json is not None, node_id
        assert cfg_json["inbounds"][0]["port"] == 12345
        outbound = cfg_json["outbounds"][0]
        assert outbound["streamSettings"]["network"] == network
        if node_id != "trojan":
            user = outbound["settings"]["vnext"][0]["users"][0]
            assert user["id"] == state["uuid"]
            assert user["flow"] == ("xtls-rprx-vision" if node_id == "vless-reality" else "")
        if node_id in ("vless-reality", "vless-xhttp"):
            rs = outbound["streamSettings"]["realitySettings"]
            assert rs["publicKey"] == state["reality"]["public_key"]
            assert rs["shortId"] == state["reality"]["short_id"]
            assert rs["serverName"] == "www.cloudflare.com"

    # Hysteria 2 需要 hysteria 客户端, 深度体检不支持 → 明确返回 None 而不是瞎编
    assert services.client_config(state, "hysteria2", 12345) is None


def test_deep_probe_never_emits_removed_allowinsecure(client, configured, home):
    """Xray 26 已移除 allowInsecure (26.3 上直接拒绝加载配置), 自签场景必须用
    pinnedPeerCertSha256 —— 否则深度体检起不来, 而且真机上没人会去查日志。"""
    from zeroproxy import config as cfg, services

    state = cfg.load_state()
    state["cert"]["type"] = "self-signed"
    assert os.path.exists(state["cert"]["cert_file"])            # fixture 已生成自签证书
    for node_id in ("vless-ws", "trojan"):
        settings = services.client_config(state, node_id, 1)["outbounds"][0]["streamSettings"]["tlsSettings"]
        assert "allowInsecure" not in settings
        assert len(settings["pinnedPeerCertSha256"]) == 64      # 自签 → 固定指纹
        assert settings["serverName"] == state["domain"]
    assert services._cert_sha256_hex(state["cert"]["cert_file"]) == settings["pinnedPeerCertSha256"]

    # 真实 CA 证书 (Let's Encrypt) → 正常校验, 不需要 pinning
    state["cert"]["type"] = "letsencrypt"
    settings = services.client_config(state, "trojan", 1)["outbounds"][0]["streamSettings"]["tlsSettings"]
    assert settings == {"serverName": state["domain"]}


def test_client_tls_settings_survives_missing_cert(home):
    """证书文件缺失时不能抛异常 (体检要给出可读结论)。"""
    from zeroproxy import config as cfg, services

    state = cfg.load_state()
    state["cert"]["cert_file"] = str(home / "nope.crt")
    assert services.client_tls_settings(state) == {"serverName": state["domain"]}


def _fake_socks5_server(reply: bytes, expect_host: bytes = b"example.com"):
    """起一个只做一次握手的假 SOCKS5 服务端, 返回 (端口, 线程, 关闭函数)。"""
    import socket
    import threading

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    seen = []

    def recv_exact(conn, n):
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    def serve():
        conn, _ = server.accept()
        try:
            seen.append(recv_exact(conn, 3))
            conn.sendall(b"\x05\x00")
            seen.append(recv_exact(conn, 4 + 1 + len(expect_host) + 2))
            conn.sendall(reply)
            threading.Event().wait(0.6)   # 保持连接, 让调用方看到"缓冲区还剩什么"
        except OSError:
            pass
        finally:
            conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return server.getsockname()[1], thread, seen, server


def test_socks5_open_consumes_the_whole_reply(home):
    """Xray 的 SOCKS5 成功回复是 10 字节 (`05 00 00 01` + BND `0.0.0.0:0`)。

    真机踩到过: 只读 4 字节时剩下 6 个 0 会被 TLS 当成记录头 → 客户端报
    `WRONG_VERSION_NUMBER`, 面板上表现为"4 个节点全部握手失败", 而节点其实完全正常。
    这里用假服务端钉死"回复必须读干净"。
    """
    import socket

    from zeroproxy import services

    reply = b"\x05\x00\x00\x01" + b"\x7f\x00\x00\x01" + (0x1234).to_bytes(2, "big")
    port, _thread, seen, server = _fake_socks5_server(reply)
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=3)
        sock.settimeout(3)
        ok, detail = services._socks5_open(sock, "example.com", 443)
        assert ok, detail
        assert seen[0] == b"\x05\x01\x00"
        assert seen[1][:4] == b"\x05\x01\x00\x03"        # 用域名 (ATYP=3) 寻址
        assert seen[1][5:] == b"example.com" + (443).to_bytes(2, "big")
        sock.settimeout(0.3)
        with pytest.raises(TimeoutError):                # 缓冲区必须是空的
            sock.recv(16)
        sock.close()
    finally:
        server.close()


def test_socks5_open_handles_domain_reply_and_refusal(home):
    """回复的 ATYP 可能是域名 (变长), 拒绝码要如实转述而不是当成成功。"""
    import socket

    from zeroproxy import services

    domain_reply = b"\x05\x00\x00\x03" + bytes([5]) + b"proxy" + (8080).to_bytes(2, "big")
    port, _thread, _seen, server = _fake_socks5_server(domain_reply)
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=3)
        sock.settimeout(0.3)
        ok, detail = services._socks5_open(sock, "example.com", 443)
        assert ok, detail
        with pytest.raises(TimeoutError):
            sock.recv(16)
        sock.close()
    finally:
        server.close()

    port, _thread, _seen, server = _fake_socks5_server(b"\x05\x05\x00\x01" + b"\x00\x00\x00\x00\x00\x00")
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=3)
        sock.settimeout(3)
        ok, detail = services._socks5_open(sock, "example.com", 443)
        assert ok is False and "code=5" in detail
        sock.close()
    finally:
        server.close()


def test_socks5_tls_probe_reports_tunnel_failure(home):
    """SOCKS5 阶段就失败时, 深度体检要给出可读原因 (而不是 TLS 层的怪错误)。"""
    from zeroproxy import services

    port, _thread, _seen, server = _fake_socks5_server(b"\x05\x02\x00\x01" + b"\x00\x00\x00\x00\x00\x00")
    try:
        ok, ms, detail = services._socks5_tls_probe(port, "www.cloudflare.com", 443, timeout=3)
        assert ok is False and ms == -1.0 and "code=2" in detail
    finally:
        server.close()


# ---------------------------------------------------------------- 服务版本探测

#: 真机 `hysteria version` 的原始输出 (2.12.3): 先一段块字符 banner, 再才是 Version 行
HYSTERIA_VERSION_OUTPUT = (
    "\n"
    "░█░█░█░█░█▀▀░▀█▀░█▀▀░█▀▄░▀█▀░█▀█░░░▀▀▄\n"
    "░█▄█░█░█░▀▀█░░█░░█▀▀░█▀▄░░█░░█▀█░░░▄▀░\n"
    "░▀░▀░▀░▀░▀▀▀░░▀░░▀▀▀░▀░▀░░▀░░▀░▀░░░▀▀▀\n"
    "\n"
    "a powerful, lightning fast and censorship resistant proxy\n"
    "Aperture Internet Laboratory <https://github.com/apernet>\n"
    "\n"
    "Version:\tv2.12.3\n"
    "BuildDate:\t2026-09-16T03:45:59Z\n"
    "BuildType:\trelease\n"
    "Toolchain:\tgo1.26.8 linux/amd64\n"
)


def test_version_from_output_skips_hysteria_banner(home):
    """Hysteria 2 会把块字符 banner 打在第一行, 面板上曾经就挂成"运行中 · ░█░█…"。"""
    from zeroproxy import services

    assert services.version_from_output(HYSTERIA_VERSION_OUTPUT) == "v2.12.3"
    # 带 ANSI 颜色 / 只有 banner 时, 宁可空也不能把花屏当版本号
    assert services.version_from_output("\x1b[1;34mVersion: v2.12.3\x1b[0m\n") == "v2.12.3"
    assert services.version_from_output("░█░█░█░█░█▀▀░▀█▀\n░▀░▀░▀░▀░▀▀▀░░▀░\n") == ""
    assert services.version_from_output("") == ""


def test_version_from_output_keeps_single_line_versions(home):
    """Xray / nginx 这种第一行就是版本的要原样保留 (顺便验证不误伤)。"""
    from zeroproxy import services

    xray_line = "Xray 26.3.27 (Xray, Penetrates Everything.) d2758a0 (go1.26.1 linux/amd64)"
    assert services.version_from_output(xray_line + "\n") == xray_line
    assert services.version_from_output("nginx version: nginx/1.24.0 (Ubuntu)\n") == "nginx version: nginx/1.24.0 (Ubuntu)"
    # Hysteria 1 那种 "Version: v1.3.5" 也要认
    assert services.version_from_output("Hysteria 1.3.5\nVersion: v1.3.5\n") == "v1.3.5"


def test_deep_probe_is_unavailable_without_xray_binary(client, configured, home, monkeypatch):
    """没有 xray 二进制时给出"无法体检"而不是谎报成功/失败。"""
    from zeroproxy import services

    monkeypatch.setattr(services, "bin_path", lambda name: None)
    result = services.deep_probe_node(config.load_state(), "vless-reality")
    assert result["ok"] is None and "无法深度体检" in result["detail"]


def test_deep_probe_reports_failure_when_node_is_dead(client, configured, home, monkeypatch):
    """节点端口没人监听时, 深度体检必须判失败 (而不是像裸 TLS 探测那样误报)。"""
    import socket

    from zeroproxy import services

    fake = os.environ.get("ZP_XRAY_BIN") or services.bin_path("xray")
    if not fake or not os.path.exists(fake):
        pytest.skip("需要真实 xray 二进制 (ZP_XRAY_BIN)")
    monkeypatch.setenv("ZP_XRAY_BIN", fake)

    with socket.socket() as s:                      # 占一个端口后立刻释放 → 必定无监听
        s.bind(("127.0.0.1", 0))
        dead_port = s.getsockname()[1]
    state = config.load_state()
    state["ports"]["reality"] = dead_port
    result = services.deep_probe_node(state, "vless-reality", timeout=4)
    assert result["ok"] is False
    assert "Reality 密钥/SNI/伪装目标" in result["detail"]


def test_probe_deep_flag_falls_back_to_shallow_in_dev(client, configured):
    """本地开发 (无 systemd / 非 Linux) 下 deep=1 也必须能返回, 而不是 500。"""
    body = client.get("/api/probe?deep=1&force=1").json()
    assert len(body["nodes"]) == 5
    assert body["deep"] is True
    assert all(n["kind"] in ("tcp", "tls", "udp", "off", "deep", "?") for n in body["nodes"])


def test_tcp_connect_probe_helper(home):
    """本机自连: 起一个临时监听端口, 探测必须成功且给出正数毫秒。"""
    import socket
    import threading

    from zeroproxy import services

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    port = server.getsockname()[1]
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                server.settimeout(0.2)
                conn, _ = server.accept()
                conn.close()
            except OSError:
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        ok, ms, detail = services.tcp_connect_ms("127.0.0.1", port, timeout=2)
        assert ok and ms >= 0, detail
        ok, ms, _ = services.tcp_connect_ms("127.0.0.1", 1, timeout=1)  # 无人监听
        assert not ok and ms == -1.0
    finally:
        stop.set()
        server.close()
        thread.join(timeout=2)


def test_udp_port_listening_detects_listener(home):
    import socket

    from zeroproxy import services

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    try:
        result = services.udp_port_listening(port)
        # 环境不支持时返回 None (未知), 支持时必须看到监听
        assert result in (True, None), f"UDP {port} 应被判定为监听中, 实际 {result}"
    finally:
        sock.close()


# ---------------------------------------------------------------- 备份 / 恢复

def test_backup_and_restore_roundtrip(client, configured):
    exported = client.get("/api/backup")
    assert exported.status_code == 200
    payload = exported.json()
    assert payload["format"] == "zeroproxy-backup"
    assert len(payload["checksum"]) == 64
    # 会话与登录限流属于运行时数据, 不应进备份
    assert "sessions" not in payload["state"]
    assert "login_failures" not in payload["state"]
    # 私钥必须随备份一起走, 否则恢复后所有客户端都要重新导入
    assert payload["state"]["reality"]["private_key"]

    token = payload["state"]["subscription_token"]
    client.post("/api/nodes/vless-ws/toggle")
    client.post("/api/settings", json={"reality_sni": "www.bing.com"})

    restored = client.post("/api/restore", content=exported.content)
    assert restored.status_code == 200, restored.text
    state = config.load_state()
    assert state["nodes"]["vless-ws"] is True           # 节点开关回到备份点
    assert state["reality"]["server_name"] == "www.cloudflare.com"
    assert state["subscription_token"] == token
    assert state["geodata"]["enabled"] is False
    assert any(a["action"] == "restore" for a in state["audit"])


def test_backup_requires_auth(client, configured):
    client.cookies.clear()
    assert client.get("/api/backup").status_code == 401


def test_restore_rejects_tampered_backup(client, configured):
    payload = client.get("/api/backup").json()
    payload["state"]["domain"] = "evil.example.com"
    response = client.post("/api/restore", json=payload)
    assert response.status_code == 400
    assert "校验和" in response.json()["error"]
    assert config.load_state()["domain"] == "proxy.example.com"


def test_restore_rejects_foreign_file(client, configured):
    assert client.post("/api/restore", json={"hello": "world"}).status_code == 400
    assert client.post("/api/restore", content=b"{not json").status_code == 400
    assert client.post("/api/restore", content=b'{"format":"other","state":{}}').status_code == 400


def test_restore_rejects_malformed_structure(client, configured):
    """备份校验和过了也不代表结构可用 —— 坏结构必须 400, 而不是 500。"""
    import copy
    import hashlib

    payload = client.get("/api/backup").json()
    payload["state"]["reality"] = None
    clean = copy.deepcopy(payload["state"])
    clean.pop("sessions", None)
    clean.pop("login_failures", None)
    canonical = json.dumps(clean, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    payload["checksum"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    response = client.post("/api/restore", json=payload)
    assert response.status_code == 400, response.text
    assert "结构" in response.json()["error"]
    # 现网不能被动过
    assert config.load_state()["reality"]["private_key"]


def test_state_load_ignores_broken_nested_types(client, configured, home):
    """state.json 里某个对象字段被改坏 (null) 时, 保留默认值而不是整块崩掉。"""
    path = config.paths()["state"]
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    data["reality"] = None
    data["admin"] = []
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)

    state = config.load_state()
    assert isinstance(state["reality"], dict) and state["reality"]["dest"]
    assert isinstance(state["admin"], dict)
    # 面板仍然可用 (不是 500)
    assert client.get("/api/dashboard").status_code == 200


# ---------------------------------------------------------------- GeoIP 分流

def test_geodata_is_opt_in_by_default(client, configured):
    """默认不启用: 没有数据文件就绝不能下发 geo 规则 (否则 Xray 起不来)。"""
    state = config.load_state()
    assert state["geodata"]["enabled"] is False
    cfg = xray_config.build_xray_config(state)
    rules = json.dumps(cfg["routing"]["rules"], ensure_ascii=False)
    assert "geoip:" not in rules and "geosite:" not in rules
    assert all(o.get("tag") != "block" for o in cfg["outbounds"])


def test_geodata_rules_dropped_when_files_missing(client, configured, home):
    """开关打开但数据文件被删掉时, 必须自动退化为无 geo 规则 (硬前置)。"""
    from zeroproxy import geodata

    state = config.load_state()
    state["geodata"]["enabled"] = True
    assert geodata.present() is False
    cfg = xray_config.build_xray_config(state)
    assert "geoip:" not in json.dumps(cfg["routing"]["rules"])


def test_geodata_update_from_local_source(client, configured, home, monkeypatch, tmp_path):
    """用 file:// 假数据源走完下载流程 (不依赖网络)。"""
    from zeroproxy import geodata

    source = tmp_path / "geo-src"
    source.mkdir()
    for name in geodata.MIN_BYTES:
        (source / name).write_bytes(b"ZP" * 600_000)  # 1.2 MB, 刚好过体积下限
    monkeypatch.setattr(
        geodata, "SOURCES", {name: [(source / name).as_uri()] for name in geodata.MIN_BYTES}
    )

    state = config.load_state()
    ok, detail, status = geodata.update(state, validate=False)
    assert ok, detail
    assert geodata.present()
    assert state["geodata"]["enabled"] is True
    assert state["geodata"]["files"]["geoip.dat"]["size"] == 1_200_000
    assert status["active"] is True

    # 数据齐备后, 分流规则才会进入 Xray 配置
    rules = json.dumps(xray_config.build_xray_config(state)["routing"]["rules"])
    assert "geoip:private" in rules and "geosite:category-ads-all" in rules


def test_geodata_rejects_too_small_download(client, configured, home, monkeypatch, tmp_path):
    """下载到错误页面 (体积过小) 必须被拒绝, 且不破坏已有数据。"""
    from zeroproxy import geodata

    bogus = tmp_path / "bogus.dat"
    bogus.write_bytes(b"<!doctype html>404")
    monkeypatch.setattr(
        geodata, "SOURCES", {name: [bogus.as_uri()] for name in geodata.MIN_BYTES}
    )
    ok, detail, _ = geodata.update(config.load_state(), validate=False)
    assert not ok and "体积异常" in detail
    assert geodata.present() is False


# ---------------------------------------------------------------- GeoIP 数据版本
#
# 用户的原始问题: "GeoIP 数据应该有个版本信息显示, 不然用户不知道究竟是否已经
# 正确更新了"。dat 文件里没有版本字符串, 所以版本 = 上游发布的 sha256sum 比对
# + release 分支最新提交的日期 / sha。下面用 file:// 假镜像覆盖三条路径:
# 一致 (跳过下载) / 上游换版 (如实报"有新版本") / 问不到上游 (三态里的 None)。

def _geo_sources_with_sums(tmp_path, size: int = 1_200_000, *, sums: str = "match") -> dict:
    """假数据源 + 随数据集一起发布的 `<文件>.sha256sum`。

    `_sum_urls()` 是在数据源 URL 后面接 `.sha256sum`, 所以 file:// 镜像天然可用 ——
    测试不需要任何网络, 走的却是和线上同一段代码。
    """
    import hashlib

    source = tmp_path / "geo-src-sums"
    source.mkdir(exist_ok=True)
    for name in ("geoip.dat", "geosite.dat"):
        (source / name).write_bytes(b"ZP" * (size // 2))
        if sums == "absent":
            continue
        digest = (
            hashlib.sha256((source / name).read_bytes()).hexdigest()
            if sums == "match"
            else "f" * 64                      # 上游换了一版, 本地还是旧的
        )
        (source / f"{name}.sha256sum").write_text(f"{digest}  {name}\n")
    return {name: [(source / name).as_uri()] for name in ("geoip.dat", "geosite.dat")}


def test_geodata_version_visible_and_up_to_date(client, configured, home, monkeypatch, tmp_path):
    """装好数据后, 面板要能说出"数据是哪一版、是不是最新的"。"""
    from zeroproxy import geodata

    monkeypatch.setattr(geodata, "SOURCES", _geo_sources_with_sums(tmp_path))
    state = config.load_state()
    assert geodata.update(state, validate=False)[0] is True
    assert state["geodata"]["up_to_date"] is True

    body = client.get("/api/geodata/check").json()
    assert body["up_to_date"] is True
    # 卡片显示的是每个文件的内容指纹 (sha256 前缀), 更新前后对一眼就知道换没换
    assert body["geo"]["files"]["geoip.dat"]["sha256"]
    assert body["geo"]["checked_at"] > 0

    dash = client.get("/api/dashboard").json()["geodata"]
    for key in ("dataset_build", "dataset_sha", "checked_at", "up_to_date"):
        assert key in dash, key
    assert dash["up_to_date"] is True


def test_geodata_update_skips_download_when_content_unchanged(client, configured, home, monkeypatch, tmp_path):
    """内容一致就不该再下 28 MB —— 但仍要记一次"核对时间"。"""
    from zeroproxy import geodata

    monkeypatch.setattr(geodata, "SOURCES", _geo_sources_with_sums(tmp_path))
    state = config.load_state()
    assert geodata.update(state, validate=False)[0] is True
    written_at = state["geodata"]["updated_at"]
    fingerprint = state["geodata"]["files"]["geoip.dat"]["sha256"]

    ok, detail, _ = geodata.update(state, validate=False)
    assert ok and "已是最新" in detail
    assert state["geodata"]["updated_at"] == written_at          # 文件没有被重写
    assert state["geodata"]["files"]["geoip.dat"]["sha256"] == fingerprint
    assert state["geodata"]["checked_at"] >= written_at          # 但核对记录刷新了


def test_geodata_check_detects_newer_upstream(client, configured, home, monkeypatch, tmp_path):
    """上游换版时要如实说"有新版本", 不能因为本地文件还在就报"已是最新"。"""
    from zeroproxy import geodata

    monkeypatch.setattr(geodata, "SOURCES", _geo_sources_with_sums(tmp_path))
    state = config.load_state()
    assert geodata.update(state, validate=False)[0] is True

    monkeypatch.setattr(geodata, "SOURCES", _geo_sources_with_sums(tmp_path, sums="newer"))
    body = client.get("/api/geodata/check").json()
    assert body["up_to_date"] is False
    assert body["geo"]["up_to_date"] is False
    assert body["geo"]["files"]["geoip.dat"]["expected"][:8] == "ffffffff"


def test_geodata_check_unknown_when_mirror_unreachable(client, configured, home, monkeypatch, tmp_path):
    """问不到上游是 None, 不是 False —— "不知道"和"有新版"在面板上是两句话。"""
    from zeroproxy import geodata

    monkeypatch.setattr(geodata, "SOURCES", _geo_sources_with_sums(tmp_path, sums="absent"))
    state = config.load_state()
    assert geodata.update(state, validate=False)[0] is True
    assert state["geodata"]["up_to_date"] is None

    body = client.get("/api/geodata/check").json()
    assert body["up_to_date"] is None
    assert body["detail"]                     # 面板要能说出为什么核对不了


def test_geodata_ttl_counts_from_last_check(home):
    """核对过 (内容没变) 之后 TTL 从"上次核对"起算, 否则每 6 小时白问一次上游。"""
    import time as _time
    from zeroproxy import config as _config
    from zeroproxy import geodata

    geo_dir = _config.paths()["geo_dir"]
    os.makedirs(geo_dir, exist_ok=True)
    for name, minimum in geodata.MIN_BYTES.items():
        with open(os.path.join(geo_dir, name), "wb") as fh:
            fh.write(b"ZP" * (minimum // 2 + 8))

    now = int(_time.time())
    stale = now - geodata.GEODATA_TTL - 60
    fresh_check = {"geodata": {"enabled": True, "updated_at": stale, "checked_at": now - 5}}
    assert geodata.wants_update(fresh_check, now=now) is False
    stale_check = {"geodata": {"enabled": True, "updated_at": stale, "checked_at": stale}}
    assert geodata.wants_update(stale_check, now=now) is True


# ---------------------------------------------------------------- 内核升级开关


# ---------------------------------------------------------------- 终端快捷管理 (z)


def test_sidebar_order_matches_the_page_order():
    """侧栏菜单的顺序必须与页面板块的顺序一致。

    用户看到的症状: 「链式代理」和「高级 / 分流」两个按钮点下去跑到的板块是反的
    (菜单里链式在前, 页面里高级在前) —— 于是点上一个会滚到下面, 滚动高亮也往回跳。
    这类"两个列表各改一处"的错位在浏览器里才看得出来, 所以在这里钉死。
    """
    import re
    from pathlib import Path

    html = (Path(__file__).resolve().parents[1] / "static" / "index.html").read_text(encoding="utf-8")
    dash = html[html.index('id="view-dash"'):]
    nav = re.findall(r'<a href="#([\w-]+)"', dash)
    assert len(nav) >= 8, nav                                  # 侧栏锚点
    positions = {}
    for match in re.finditer(r'id="([\w-]+)"', dash):
        positions.setdefault(match.group(1), match.start())     # 只记第一次出现
    missing = [name for name in nav if name not in positions]
    assert not missing, f"侧栏指向了不存在的板块: {missing}"
    tops = [positions[name] for name in nav]
    assert tops == sorted(tops), f"菜单顺序与页面顺序不一致: {list(zip(nav, tops))}"
    assert len(set(tops)) == len(tops), "同一个板块被挂到了两个锚点上"
#
# 用户的原始诉求: "预防用户忘记密码 —— SSH 上输入 z 就能进终端管理: 1 改账号密码,
# 2 在线更新, 0 退出"。这里逐条钉住: 菜单真的列出那三件事、改密码不要求旧密码
# (忘了才用这条路) 且旧会话一起作废、更新走的是与面板同一个 upgrade.sh、
# 生成的 z 命令真的能跑起来、安装/升级/卸载脚本都认得它。

def test_cli_menu_lists_what_the_user_asked_for(home, capsys, monkeypatch):
    from zeroproxy import cli

    monkeypatch.setattr(cli, "_ask", lambda prompt="": "0")
    assert cli.main([]) == 0
    text = capsys.readouterr().out
    assert "ZeroProxy 终端管理" in text
    assert "1) 修改面板账号 / 密码" in text
    assert "2) 在线更新到最新版本" in text
    assert "0) 退出" in text


def test_cli_menu_rejects_a_bogus_choice_then_exits(home, capsys, monkeypatch):
    from zeroproxy import cli

    answers = iter(["9", "0"])
    monkeypatch.setattr(cli, "_ask", lambda prompt="": next(answers))
    assert cli.main([]) == 0
    assert "没有这个选项" in capsys.readouterr().out


def test_cli_changes_password_without_the_old_one_and_kills_sessions(
    client, configured, home, capsys, monkeypatch
):
    """忘记密码时的兜底: SSH 里直接改 (不要求旧密码), 且旧会话一起作废。"""
    from zeroproxy import cli, config, crypto

    state = config.load_state()
    state["sessions"] = {
        "stale-token": {"username": "admin", "created": 0, "expires": 9999999999, "ip": "1.2.3.4"}
    }
    config.save_state(state)

    monkeypatch.setattr(cli, "_ask", lambda prompt="": "boss")
    answers = iter(["new-password-1", "new-password-1"])
    monkeypatch.setattr(cli, "_ask_password", lambda prompt="": next(answers))
    assert cli.main(["passwd"]) == 0

    state = config.load_state()
    assert state["admin"]["username"] == "boss"
    assert crypto.verify_password("new-password-1", state["admin"]["password_hash"])
    assert state["sessions"] == {}                       # 改了密码, 旧会话不该继续有效
    assert state["uuid"] == config.load_state()["uuid"]  # 节点凭据没被动过
    assert any(e["action"] == "account_update_cli" for e in state["audit"])
    out = capsys.readouterr().out
    assert "boss" in out and "注销其它 1 个登录会话" in out


def test_cli_rejects_bad_passwords_without_touching_state(
    client, configured, home, capsys, monkeypatch
):
    from zeroproxy import cli, config

    before = config.load_state()["admin"]["password_hash"]
    monkeypatch.setattr(cli, "_ask", lambda prompt="": "")

    answers = iter(["123", "123"])
    monkeypatch.setattr(cli, "_ask_password", lambda prompt="": next(answers))
    assert cli.main(["passwd"]) == 1
    assert "密码长度" in capsys.readouterr().out

    answers = iter(["good-password-1", "good-password-2"])
    monkeypatch.setattr(cli, "_ask_password", lambda prompt="": next(answers))
    assert cli.main(["passwd"]) == 1
    assert "不一致" in capsys.readouterr().out

    assert config.load_state()["admin"]["password_hash"] == before


def test_cli_update_runs_the_same_script_as_the_panel(home, capsys, monkeypatch):
    """终端里的"在线更新"必须与面板「一键更新」是同一条路径 (同一个 upgrade.sh)。"""
    from zeroproxy import cli, config

    script = config.paths()["upgrade_script"]
    os.makedirs(os.path.dirname(script), exist_ok=True)
    with open(script, "w", encoding="utf-8") as fh:
        fh.write("#!/usr/bin/env bash\nexit 0\n")
    monkeypatch.setattr(cli.update, "remote_version", lambda timeout=8: (True, "9.9.9", "test-mirror"))
    monkeypatch.setattr(cli, "_ask", lambda prompt="": "y")
    seen: dict = {}

    def _fake_call(cmd):
        seen["cmd"] = cmd
        return 0

    monkeypatch.setattr(cli.subprocess, "call", _fake_call)

    assert cli.main(["update"]) == 0
    assert seen["cmd"] == ["bash", script]
    out = capsys.readouterr().out
    assert "当前版本" in out and "9.9.9" in out


def test_cli_update_without_script_says_what_to_do(home, capsys, monkeypatch):
    from zeroproxy import cli

    monkeypatch.setattr(cli.update, "remote_version", lambda timeout=8: (False, "", "离线"))
    assert cli.main(["update"]) == 1
    out = capsys.readouterr().out
    assert "没找到升级脚本" in out and "一键升级" in out


def test_installed_z_command_actually_runs(home, tmp_path, monkeypatch):
    """生成的 z 命令真能跑起来 (面板进不去时它是唯一入口, 不能只是"看起来装好了")。

    这里用一个假的 `venv/bin/python` 来验**包装脚本本身**: ZP_HOME / PYTHONPATH 有没有
    注入、参数有没有原样传给 `-m zeroproxy.cli`。真 cli 的行为由上面几条直接调用覆盖
    —— 造真 venv 要装一遍依赖, 不值得 (而且用符号链接假造的 venv 会让解释器以为自己
    不在 venv 里, cryptography 直接 import 失败, 那条路验不出真问题)。
    """
    import subprocess
    from pathlib import Path

    from zeroproxy import cli

    fake_python = tmp_path / "venv" / "bin" / "python"
    fake_python.parent.mkdir(parents=True)
    fake_python.write_text('#!/bin/sh\necho "ARGS:$*"\necho "ZPHOME:$ZP_HOME"\necho "PY:$PYTHONPATH"\n')
    fake_python.chmod(0o755)
    bin_dir = tmp_path / "bin"
    assert cli.install_shortcut(str(bin_dir)) == 0
    for name in ("z", "zeroproxy"):
        text = (bin_dir / name).read_text(encoding="utf-8")
        assert cli.WRAPPER_MARK in text and str(home) in text
    done = subprocess.run([str(bin_dir / "z"), "status"], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    assert "ARGS:-m zeroproxy.cli status" in done.stdout      # 参数原样透传
    assert f"ZPHOME:{home}" in done.stdout                    # ZP_HOME 已注入
    assert f"PY:{home}" in done.stdout                        # 包能被找到


def test_z_is_not_hijacked_when_taken_by_someone_else(home, tmp_path, capsys):
    """`z` 已被别的东西占用 (比如 zoxide) 时不覆盖, 只装长名字并说清楚。"""
    from zeroproxy import cli

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "z").write_text("#!/bin/sh\n# zoxide\n", encoding="utf-8")
    assert cli.install_shortcut(str(bin_dir)) == 0
    assert (bin_dir / "z").read_text(encoding="utf-8") == "#!/bin/sh\n# zoxide\n"
    assert "zeroproxy" in (bin_dir / "zeroproxy").read_text(encoding="utf-8")
    # 面板目录里那份兜底一定会装上: PATH 里没有 /usr/local/bin 时靠它
    assert (home / "z").exists() and os.access(home / "z", os.X_OK)
    out = capsys.readouterr().out
    assert "已存在且不是本程序装的" in out and "zeroproxy" in out


def test_shortcut_warns_when_its_directory_is_not_in_path(home, tmp_path, capsys):
    """装到 PATH 之外的目录时要当场说清 —— 否则用户敲 z 只会看到 command not found。"""
    from zeroproxy import cli

    bin_dir = tmp_path / "somewhere-not-in-path"
    assert cli.install_shortcut(str(bin_dir)) == 0
    out = capsys.readouterr().out
    assert "不在 PATH 里" in out and str(home / "z") in out


def test_shortcut_prefers_a_standard_dir_that_is_in_path(home, monkeypatch, tmp_path):
    """标准目录优先, 但必须是 PATH 里的那个 (否则装了也敲不动)。"""
    from zeroproxy import cli

    custom = f"{tmp_path}/custom-bin"
    monkeypatch.setenv("PATH", f"/usr/local/bin:/usr/bin:{custom}")
    # 可写性单独控制, 免得断言依赖"这台机器上 /usr/bin 能不能写"这种环境事实
    monkeypatch.setattr(cli, "_writable_dir", lambda path, create=False: path == "/usr/local/bin")
    assert cli._pick_bin_dir(None) == "/usr/local/bin"
    monkeypatch.setattr(cli, "_writable_dir", lambda path, create=False: path == "/usr/bin")
    assert cli._pick_bin_dir(None) == "/usr/bin"            # 前者不可写就退到下一个
    monkeypatch.setattr(cli, "_writable_dir", lambda path, create=False: path == custom)
    assert cli._pick_bin_dir(None) == custom                # 标准目录都不可写 → PATH 里第一个可写的
    monkeypatch.setattr(cli, "_writable_dir", lambda path, create=False: True)
    assert cli._pick_bin_dir("/tmp/explicit") == "/tmp/explicit"   # 明确指定就用它
    monkeypatch.setenv("PATH", "/nowhere")
    monkeypatch.setattr(cli, "_writable_dir", lambda path, create=False: False)
    assert cli._pick_bin_dir(None) == "/usr/local/bin"      # 一个可写的都没有 → 交回默认值


def test_installers_wire_up_the_terminal_shortcut():
    """安装 / 升级 / 卸载三条路径都要认得 z (老部署升级完也得有)。"""
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    for name in ("install.sh", "upgrade.sh"):
        text = (root / name).read_text(encoding="utf-8")
        assert "install-shortcut" in text, name
    uninstall = (root / "uninstall.sh").read_text(encoding="utf-8")
    assert "/usr/local/bin/z" in uninstall and cli_wrapper_mark() in uninstall


def test_updaters_fetch_a_fresh_snapshot_not_a_cached_branch():
    """按分支下载会被 CDN 缓存 —— 推送后几分钟内升级会装到**上一个版本**的代码。

    真机上踩到过: 面板显示 "v2.6.28 → v2.6.28", 用户以为没升级。所以两个脚本都要
    (a) 先把分支/tag 解析成提交 SHA 并按 SHA 下载 (不可变快照), (b) 拿不到 SHA 时
    给分支/tag 的地址带上时间戳强制回源。
    """
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    for name in ("install.sh", "upgrade.sh"):
        text = (root / name).read_text(encoding="utf-8")
        assert "repos/$ZP_REPO/commits/$" in text, f"{name}: 没有先解析提交 SHA"
        assert "archive/$sha.tar.gz" in text, f"{name}: 没有按 SHA 下载"
        assert "?t=" in text, f"{name}: 退路没有破缓存 (分支快照会被 CDN 缓存住)"


def cli_wrapper_mark() -> str:
    from zeroproxy import cli

    return cli.WRAPPER_MARK


def test_account_update_requires_current_password(client, configured, home):
    """改账号必须先验证当前密码 —— 面板 cookie 被偷走一个也改不了密码。"""
    body = client.post(
        "/api/account", json={"current_password": "wrong-pass", "username": "hacker"}
    ).json()
    assert "当前密码不正确" in body["error"]
    state = config.load_state()
    assert state["admin"]["username"] == USERNAME
    assert crypto.verify_password(PASSWORD, state["admin"]["password_hash"])


def test_account_update_changes_login_but_keeps_node_credentials(client, configured, home):
    """改用户名 / 密码只影响"谁能登进面板", 节点凭据一律不动。"""
    uuid_before = config.load_state()["uuid"]
    body = client.post(
        "/api/account",
        json={"current_password": PASSWORD, "username": "operator", "new_password": "new-pass-2026"},
    ).json()
    assert body["ok"], body
    assert "用户名" in body["detail"] and "密码" in body["detail"]

    state = config.load_state()
    assert state["admin"]["username"] == "operator"
    assert state["uuid"] == uuid_before           # 客户端凭据不受影响

    client.post("/api/logout")
    assert client.post(
        "/api/login", json={"username": "operator", "password": PASSWORD}
    ).status_code == 401                          # 旧密码立刻失效
    assert client.post(
        "/api/login", json={"username": "operator", "password": "new-pass-2026"}
    ).status_code == 200


def test_account_update_validates_and_kicks_other_devices(client, configured, home):
    """用户名 / 密码格式要校验; 改密码把别的设备踢下线, 当前这台留着。"""
    assert "用户名" in client.post("/api/account", json={
        "current_password": PASSWORD, "username": "x",
    }).json()["error"]
    assert "长度" in client.post("/api/account", json={
        "current_password": PASSWORD, "new_password": "123",
    }).json()["error"]
    assert "相同" in client.post("/api/account", json={
        "current_password": PASSWORD, "new_password": PASSWORD,
    }).json()["error"]

    client.post("/api/login", json={"username": USERNAME, "password": PASSWORD})  # 第二台设备
    assert len(config.load_state()["sessions"]) >= 2
    mine = client.cookies.get("zp_session")
    body = client.post(
        "/api/account", json={"current_password": PASSWORD, "new_password": "kick-everyone-else"}
    ).json()
    assert body["kicked"] >= 1
    assert list(config.load_state()["sessions"]) == [mine]
    # 当前会话仍然有效 (否则用户把自己也踢出去了)
    assert client.get("/api/dashboard").status_code == 200


def test_domain_change_rejects_before_touching_anything(client, configured, home, monkeypatch):
    """预检不过就当场拒绝, 而且一个字节都不改 (包括证书)。"""
    from zeroproxy import services

    before = config.load_state()
    assert client.post("/api/domain", json={"domain": DOMAIN}).status_code == 400       # 同域名
    assert client.post("/api/domain", json={"domain": "1.2.3.4"}).status_code == 400    # IP
    assert client.post("/api/domain", json={"domain": "not a domain"}).status_code == 400

    monkeypatch.setattr(services, "resolve_host", lambda host: set())
    body = client.post("/api/domain", json={"domain": "new.example.com"}).json()
    assert "解析不到" in body["error"]

    # 粘整条地址进来也要认 (人不会只输主机名): 协议 / 端口 / 路径 / 大小写 / 末尾的点
    body = client.post(
        "/api/domain", json={"domain": "  HTTPS://New.Example.com:8899/panel?x=1  "}
    ).json()
    assert "new.example.com" in body["error"], body       # 已归一化后再去解析

    # 新域名解析到别人家, 本机自己的域名照常解析 —— 预检必须能分辨这两者
    monkeypatch.setattr(
        services, "resolve_host",
        lambda host: {"198.51.100.9"} if host == "new.example.com" else {"203.0.113.7"},
    )
    monkeypatch.setattr(services, "public_ip", lambda: {"ip": "203.0.113.7", "at": 1})
    body = client.post("/api/domain", json={"domain": "new.example.com"}).json()
    assert "不在其中" in body["error"]

    after = config.load_state()
    assert after["domain"] == before["domain"]
    assert after["cert"] == before["cert"]


def test_domain_change_deploys_and_hands_off_session(client, configured, home, monkeypatch):
    """换域名走完部署: state / nginx 配置 / 订阅地址全换, 并给一张一次性交接票据。"""
    from zeroproxy import config as _config
    from zeroproxy import services

    monkeypatch.setattr(services, "resolve_host", lambda host: {"203.0.113.7"})
    monkeypatch.setattr(services, "public_ip", lambda: {"ip": "203.0.113.7", "at": 1})

    body = client.post("/api/domain", json={"domain": "proxy2.example.com"}).json()
    assert body["ok"], body.get("detail")
    state = _config.load_state()
    assert state["domain"] == "proxy2.example.com"
    assert "proxy2.example.com" in open(_config.paths()["nginx_home"], encoding="utf-8").read()

    redirect = body["redirect"]
    assert redirect["url"].startswith("https://proxy2.example.com")
    assert redirect["handoff"].startswith("zph_")
    assert redirect["ready"] is True

    dash = client.get("/api/dashboard").json()
    assert "proxy2.example.com" in dash["subscription_url"]
    assert "proxy2.example.com" in dash["nodes"][0]["share_link"]

    # 交接票据: 单次有效 (第二次用就失效), 伪造的当然也不行
    assert client.post("/api/session/handoff", json={"token": "zph_nope"}).status_code == 401
    assert client.post("/api/session/handoff", json={"token": redirect["handoff"]}).status_code == 200
    assert client.post("/api/session/handoff", json={"token": redirect["handoff"]}).status_code == 401
    assert any(e["action"] == "handoff_login" for e in _config.load_state()["audit"])


def test_domain_change_rolls_back_when_landing_fails(client, configured, home, monkeypatch):
    """配置落地失败必须整份退回原域名 —— 换域名失败不该让面板彻底进不去。"""
    from zeroproxy import apply
    from zeroproxy import services

    monkeypatch.setattr(services, "resolve_host", lambda host: {"203.0.113.7"})
    monkeypatch.setattr(services, "public_ip", lambda: {"ip": "203.0.113.7", "at": 1})

    real = apply.reapply
    calls = {"n": 0}

    def flaky(state, timeout=0, progress=None):
        calls["n"] += 1
        if calls["n"] == 1:
            return [{"name": "生成 Nginx 配置", "ok": False, "detail": "写不进去", "ms": 0}]
        return real(state, timeout=timeout, progress=progress)

    monkeypatch.setattr(apply, "reapply", flaky)
    body = client.post("/api/domain", json={"domain": "broken.example.com"}).json()
    assert not body["ok"] and "回滚" in body["detail"]
    assert any(s["name"] == "回滚到原域名" for s in body["steps"])
    assert config.load_state()["domain"] == DOMAIN


def test_remote_version_takes_newest_across_mirrors(home, monkeypatch):
    """镜像之间会有一段时间的 CDN 缓存差 —— 版本检查必须取**最新**的那个。

    以前是"第一个成功的就返回", 而第一个镜像 raw.githubusercontent 的缓存最长:
    v2.6.23 发布后实测 raw 还在吐 2.6.22, gh-proxy 已经是 2.6.23 —— 面板于是显示
    "已是最新", 用户以为没发布成功。现在四个镜像并发问一遍, 谁最新信谁。
    """
    from zeroproxy import update

    class _Resp:
        def __init__(self, body):
            self._body = body

        def read(self, _n=None):
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    def _mirrors(request, timeout=None):
        url = request.full_url
        # 注意顺序: gh-proxy 的地址里也含 raw.githubusercontent, 先判断它
        if "gh-proxy" in url:
            return _Resp(b'__version__ = "2.6.23"\n')      # 已经拿到新版
        if "raw.githubusercontent" in url:
            return _Resp(b'__version__ = "2.6.22"\n')      # CDN 还没刷新
        raise OSError("blocked")

    monkeypatch.setattr(update.urllib.request, "urlopen", _mirrors)
    ok, latest, source = update.remote_version()
    assert ok and latest == "2.6.23" and "gh-proxy" in source

    def _down(*_a, **_k):
        raise OSError("network down")

    monkeypatch.setattr(update.urllib.request, "urlopen", _down)
    ok, latest, source = update.remote_version()
    assert not ok and latest == "" and "down" in source


def test_dashboard_exposes_server_public_ip(client, configured, home):
    """顶部「出口 IP」卡片要能同时拿到本机公网 IP。

    链式代理下"本机 IP"和"落地出口 IP"是两个不同的地址, 而以前面板只给落地那个 ——
    用户要填进客户端的那一个反而无处可查。公网 IP 不在网卡上 (云主机是 NAT /
    弹性 IP), 只能问外部回显服务; 测试必须离线, 所以 conftest 里 ZP_PUBLIC_IP=0
    把整个读取关掉: 这时面板如实给空值 + 空时间戳, 绝不编一个地址出来。
    """
    from zeroproxy import services

    srv = client.get("/api/dashboard").json()["system"]["server"]
    for key in ("public_ip", "public_ip_at"):
        assert key in srv, key
    assert srv["public_ip"] == ""
    assert services.public_ip()["ip"] == ""


def test_public_ip_reads_echo_and_retries_after_failure(home, monkeypatch):
    """读回显服务 → 落进缓存; 失败不清掉上次的好值, 但要安排重试而不是等满一小时。"""
    import time as _time
    from zeroproxy import services

    monkeypatch.setenv("ZP_PUBLIC_IP", "1")
    monkeypatch.setattr(services, "IP_ECHO_DIRECT", ("http://echo.invalid/",))

    class _Resp:
        def read(self, _n=None):
            return b"203.0.113.55\n"

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    monkeypatch.setattr(services.urllib.request, "urlopen", lambda *_a, **_k: _Resp())
    assert services.refresh_public_ip()["ip"] == "203.0.113.55"
    assert services.public_ip()["ip"] == "203.0.113.55"

    def _down(*_a, **_k):
        raise OSError("network down")

    monkeypatch.setattr(services.urllib.request, "urlopen", _down)
    assert services.refresh_public_ip()["ip"] == ""
    snap = services.public_ip()
    assert snap["ip"] == "203.0.113.55"           # 网络抖一下不该让卡片变空
    assert snap["at"] < int(_time.time())         # 时间戳被推回 → 过 PUBLIC_IP_RETRY 秒就重试


def _capture_update_start(monkeypatch, tmp_path) -> dict:
    """让 update.start() 走"没有 systemd-run"的兜底分支, 并抓下它给脚本的环境。"""
    from zeroproxy import services, update

    script = tmp_path / "upgrade.sh"
    script.write_text("#!/usr/bin/env bash\nexit 0\n")
    monkeypatch.setattr(services, "is_prod", lambda: True)
    monkeypatch.setattr(update, "upgrade_script", lambda: str(script))
    monkeypatch.setattr(update.shutil, "which", lambda _name: None)
    seen: dict = {}

    class _FakePopen:
        def __init__(self, cmd, **kwargs):
            seen["cmd"] = cmd
            seen["env"] = kwargs.get("env") or {}

    monkeypatch.setattr(update.subprocess, "Popen", _FakePopen)
    return seen


def test_update_start_passes_core_flag(client, configured, home, monkeypatch, tmp_path):
    """"同时升级内核"必须真的把 ZP_UPDATE_CORE=1 交到 upgrade.sh 手里。

    内核 (Xray / Hysteria 2) 升级会改变配置语义 —— 本项目为 Xray 25 的
    allowInsecure / 证书字段改名、REALITY 密钥换算法都踩过坑, 所以它默认关闭,
    只由用户显式勾选触发。整条链路 (勾选 → /api/update → update.start →
    upgrade.sh) 任何一环静默丢掉这个开关, 都会变成"我勾了却没升 / 它自己升了"。
    """
    from zeroproxy import update

    seen = _capture_update_start(monkeypatch, tmp_path)
    ok, detail = update.start(trigger="panel", core=True)
    assert ok, detail
    assert seen["env"]["ZP_UPDATE_CORE"] == "1"
    assert seen["env"]["ZP_TRIGGER"] == "panel"
    assert update._read_status()["core"] is True


def test_update_start_defaults_to_panel_only(client, configured, home, monkeypatch, tmp_path):
    """不勾选时内核一律不动 (默认路径必须是"只换面板代码")。"""
    from zeroproxy import update

    seen = _capture_update_start(monkeypatch, tmp_path)
    ok, detail = update.start(trigger="panel")
    assert ok, detail
    assert seen["env"]["ZP_UPDATE_CORE"] == "0"
    assert update._read_status()["core"] is False


def _geo_local_sources(tmp_path, size: int = 1_200_000) -> dict:
    """file:// 假数据源 (不依赖网络), 但要是**合法的** geoip/geosite 数据。

    以前这里写的是几 MB 的随机字节 —— 不装 xray 时看不出问题, 一旦带上真实的
    `ZP_XRAY_BIN` 跑 (conftest 里那条推荐命令), `geodata._validate` 会用真 xray
    校验, 结果是"数据可被加载" 直接不成立, 5 个用例一起红。这里手工编一份最小
    的 protobuf: geoip 里带 PRIVATE、geosite 里带 CATEGORY-ADS-ALL (xray 会把
    `geoip:private` / `geosite:category-ads-all` 都转成大写再查表), 再按体积补齐
    无意义但合法的条目。
    """
    source = tmp_path / "geo-src-live"
    source.mkdir()
    (source / "geoip.dat").write_bytes(_fake_geodat(size, kind="geoip"))
    (source / "geosite.dat").write_bytes(_fake_geodat(size, kind="geosite"))
    return {name: [(source / name).as_uri()] for name in ("geoip.dat", "geosite.dat")}


def _fake_geodat(size: int, kind: str) -> bytes:
    """按 V2Ray 的 geoip/geosite protobuf 结构编一份能被真 xray 读进去的数据。"""
    import os as _os

    def varint(value: int) -> bytes:
        out = bytearray()
        while True:
            chunk = value & 0x7F
            value >>= 7
            out.append(chunk | (0x80 if value else 0))
            if not value:
                return bytes(out)

    def f_bytes(field: int, payload: bytes) -> bytes:
        return varint((field << 3) | 2) + varint(len(payload)) + payload

    def f_varint(field: int, value: int) -> bytes:
        return varint(field << 3) + varint(value)

    if kind == "geoip":
        # GeoIP: country_code + repeated CIDR{ip, prefix}
        body = f_bytes(1, b"PRIVATE")
        body += f_bytes(2, f_bytes(1, bytes([10, 0, 0, 0])) + f_varint(2, 8))
        while len(body) < size - 400:
            body += f_bytes(2, f_bytes(1, _os.urandom(4)) + f_varint(2, 24))
    else:
        # GeoSite: country_code + repeated Domain{type, value} (type=0 普通域名后缀)
        body = f_bytes(1, b"CATEGORY-ADS-ALL")
        body += f_bytes(2, f_varint(1, 0) + f_bytes(2, b"doubleclick.net"))
        while len(body) < size - 400:
            body += f_bytes(2, f_varint(1, 0) + f_bytes(2, b"x%d.example" % len(body)))
    out = f_bytes(1, body)
    # 精确补齐到目标体积: 顶层 field 1 是可重复的, 再追加一条只有 code 的条目
    # (没人引用它, 但 protobuf 完全合法), 长度按 1 字节步进调到位。
    for pad in range(400):
        filler = f_bytes(1, f_bytes(1, b"P" * pad))
        if len(out) + len(filler) == size:
            return out + filler
    raise AssertionError("补不齐体积")


def _wait_job(client, job_id: str, timeout: float = 30.0) -> dict:
    import time

    deadline = time.time() + timeout
    snap: dict = {}
    while time.time() < deadline:
        snap = client.get(f"/api/apply/job?id={job_id}").json()
        if snap.get("state") != "running":
            return snap
        time.sleep(0.05)
    return snap


def test_geodata_update_failure_leaves_a_visible_reason(client, configured, home, monkeypatch, tmp_path):
    """下载失败必须留下原因 (state + 仪表盘字段 + 审计), 不能只在 toast 里闪 2 秒。

    以前卡片上永远只有"数据未下载", 用户完全不知道是镜像不可达、被限流,
    还是校验没过 —— 于是只能反复点按钮。
    """
    from zeroproxy import geodata

    bogus = tmp_path / "bogus.dat"
    bogus.write_bytes(b"<!doctype html>404")
    monkeypatch.setattr(
        geodata, "SOURCES", {name: [bogus.as_uri()] for name in geodata.MIN_BYTES}
    )

    body = client.post("/api/geodata/update").json()
    assert body["ok"] is False
    assert "体积异常" in body["detail"]

    state = config.load_state()
    assert "体积异常" in state["geodata"]["last_error"]
    assert state["geodata"]["last_attempt"] > 0
    assert "体积异常" in client.get("/api/dashboard").json()["geodata"]["last_error"]
    assert any(e["action"] == "geodata_update_failed" for e in state["audit"])


def test_diagnose_reports_why_geodata_is_missing(client, configured, home, monkeypatch, tmp_path):
    """自检也要能说出"上次为什么没下下来" —— 否则用户只能反复点按钮。"""
    from zeroproxy import geodata

    bogus = tmp_path / "bogus.dat"
    bogus.write_bytes(b"<!doctype html>404")
    monkeypatch.setattr(
        geodata, "SOURCES", {name: [bogus.as_uri()] for name in geodata.MIN_BYTES}
    )
    client.post("/api/geodata/update")

    checks = {c["name"]: c for c in client.get("/api/diagnose").json()["checks"]}
    assert "上次更新失败" in checks["GeoIP 数据"]["detail"], checks["GeoIP 数据"]


def test_geodata_update_runs_as_background_job(client, configured, home, monkeypatch, tmp_path):
    """下载是长任务: 接口立刻回执 + 后台任务 + 进度轮询 (和 v2.6.9 的改配置一致)。

    以前是同步等: 慢线路上面板只有一句"下载中…", 而且成功后同一条请求还要重启
    Xray —— 走本机链路访问面板的浏览器会被掐断, 用户看到的就是"下载失败"。
    """
    from zeroproxy import apply, geodata

    monkeypatch.setenv("ZP_APPLY_ASYNC", "1")
    monkeypatch.setattr(geodata, "SOURCES", _geo_local_sources(tmp_path))

    body = client.post("/api/geodata/update").json()
    job = body.get("job") or {}
    assert job.get("state") == "running" and body["steps"] == [], body
    assert job["total"] == len(geodata.SOURCES) + 1 + len(apply.STEP_NAMES), job

    snap = _wait_job(client, job["id"])
    assert snap["state"] == "done", snap
    names = [s["name"] for s in snap["steps"]]
    assert names[0] == "核对并更新 GeoIP 数据", names
    assert names[1:] == list(apply.STEP_NAMES), names
    assert all(s["ok"] for s in snap["steps"]), snap

    # 数据真的落地并生效, 且上一次的失败原因被清掉
    state = config.load_state()
    assert state["geodata"]["files"]["geoip.dat"]["size"] == 1_200_000
    assert state["geodata"]["last_error"] == ""
    assert client.get("/api/dashboard").json()["geodata"]["active"] is True


def test_geodata_update_reuses_running_job(client, configured, home, monkeypatch, tmp_path):
    """连点两次不能撞车, 也不该弹"已有任务": 第二次接着第一个任务看同一个进度。"""
    import threading

    from zeroproxy import geodata

    monkeypatch.setenv("ZP_APPLY_ASYNC", "1")
    monkeypatch.setattr(geodata, "SOURCES", _geo_local_sources(tmp_path))

    started = threading.Event()
    release = threading.Event()
    real_update = geodata.update

    def slow_update(state, **kwargs):
        started.set()
        release.wait(20)
        return real_update(state, **kwargs)

    monkeypatch.setattr(geodata, "update", slow_update)

    first = client.post("/api/geodata/update").json()
    job_id = first["job"]["id"]
    assert started.wait(10), "后台任务没起来"
    second = client.post("/api/geodata/update").json()
    assert second["job"]["id"] == job_id, second
    assert "已有更新任务" in second["detail"]

    release.set()
    snap = _wait_job(client, job_id)
    assert snap["state"] == "done", snap


def test_geodata_update_starts_own_job_while_apply_runs(client, configured, home, monkeypatch, tmp_path):
    """正在跑"改配置"任务时点 GeoIP 下载, 不能把那个任务当成下载任务还给前端 ——
    否则界面显示"下载完成", 数据其实一个字节都没下。"""
    import threading

    from zeroproxy import apply, geodata

    monkeypatch.setenv("ZP_APPLY_ASYNC", "1")
    monkeypatch.setattr(geodata, "SOURCES", _geo_local_sources(tmp_path))

    started = threading.Event()
    release = threading.Event()
    real_reapply = apply.reapply

    def slow_reapply(state, timeout=0, progress=None):
        started.set()
        release.wait(20)          # 由定时器放开: 不能让"改配置"任务一直占着配置锁
        return real_reapply(state, timeout=timeout, progress=progress)

    monkeypatch.setattr(apply, "reapply", slow_reapply)

    apply_job = client.post("/api/chain/exit", json={"action": "generate", "port": 8666}).json()["job"]
    assert started.wait(10), "改配置任务没起来"
    threading.Timer(0.5, release.set).start()

    body = client.post("/api/geodata/update").json()
    assert body["job"]["kind"] == "geodata", body["job"]
    assert body["job"]["id"] != apply_job["id"], body["job"]

    snap = _wait_job(client, body["job"]["id"])
    assert snap["state"] == "done", snap
    assert geodata.present() is True
    _wait_job(client, apply_job["id"])          # 让改配置任务也跑完, 不留给下一个用例


def test_geodata_update_has_an_overall_deadline(configured, home, monkeypatch):
    """整体超时: 三个源依次 120s 等下去, 最坏能挂 12 分钟 (面板只能干等)。"""
    import time

    from zeroproxy import geodata

    monkeypatch.setattr(
        geodata, "SOURCES", {name: ["http://127.0.0.1:9/x"] for name in geodata.MIN_BYTES}
    )
    state = config.load_state()
    ok, detail, _ = geodata.update(state, validate=False, deadline=time.time() - 1)
    assert not ok and "总时间超限" in detail
    assert "总时间超限" in state["geodata"]["last_error"]


def test_geodata_merge_result_keeps_user_toggles(configured, home):
    """下载在锁外跑, 期间用户改的开关不能被这份旧快照覆盖。"""
    from zeroproxy import geodata

    stale = config.load_state()
    stale["geodata"]["enabled"] = True
    stale["geodata"]["files"] = {"geoip.dat": {"size": 1234, "sha256": "x"}}

    fresh = config.load_state()
    fresh["geodata"]["enabled"] = False        # 用户在下载期间关掉了分流
    fresh["geodata"]["block_ads"] = False
    fresh["geodata"]["user_set"] = True

    geodata.merge_result(fresh, stale, True)
    assert fresh["geodata"]["files"]["geoip.dat"]["size"] == 1234
    assert fresh["geodata"]["enabled"] is False
    assert fresh["geodata"]["block_ads"] is False


def test_geodata_update_conflicts_with_auto_update(client, configured, home, monkeypatch, tmp_path):
    """后台自动更新正在下载时, 手动点按钮要明确拒绝, 不能两条路径同时写 geo 目录。"""
    from zeroproxy import geodata

    monkeypatch.setattr(geodata, "SOURCES", _geo_local_sources(tmp_path))
    assert geodata.UPDATE_LOCK.acquire(blocking=False)
    try:
        response = client.post("/api/geodata/update")
        assert response.status_code == 409
        # 提示要写成"等一下", 而不是让用户以为按钮坏了 (v2.6.14 改过措辞)
        assert "正在更新中" in response.json()["error"]
        assert "稍等" in response.json()["error"]
    finally:
        geodata.UPDATE_LOCK.release()


def test_settings_reject_enabling_geodata_without_data(client, configured):
    response = client.post("/api/settings", json={"geodata_enabled": True})
    assert response.status_code == 400
    assert "GeoIP" in response.json()["error"]


def test_geodata_staging_stays_on_the_target_filesystem(client, configured, home, monkeypatch, tmp_path):
    """下载的临时文件必须建在 geo 目录里 (同一个文件系统)。

    用户的 "更新失败: OSError: [Errno 18] Invalid cross-device link:
    '/tmp/zp-geo-dl-xxx/geoip.dat' -> '/opt/zeroproxy/geo/geoip.dat'" 就是它 ——
    那台机器的 /tmp 是单独挂载 (tmpfs / 容器 overlay), 从那里 os.replace 到 geo
    目录跨了文件系统, 于是下载成功也一步都落不了地。
    """
    from zeroproxy import config, geodata

    monkeypatch.setattr(geodata, "SOURCES", _geo_local_sources(tmp_path))
    geo = os.path.realpath(str(config.paths()["geo_dir"]))
    staging_dirs: list[str] = []
    real_fetch = geodata._fetch

    def spy(name, dst, *args, **kwargs):
        staging_dirs.append(os.path.dirname(dst))
        return real_fetch(name, dst, *args, **kwargs)

    monkeypatch.setattr(geodata, "_fetch", spy)
    body = client.post("/api/geodata/update").json()
    assert body["ok"] is True, body
    assert staging_dirs, "没抓到下载路径"
    assert all(os.path.dirname(os.path.realpath(d)) == geo for d in staging_dirs), staging_dirs
    # 收工后不留临时目录 (中断过的下载由下一次 update 开头清掉)
    left = [n for n in os.listdir(geo) if n.startswith(".zp-geo-dl-")]
    assert left == [], left


def test_geodata_update_prunes_stale_staging(client, configured, home, monkeypatch, tmp_path):
    """中断的下载 (面板被升级/杀掉) 会留下几十 MB 的临时目录, 下一次下载顺手收掉。"""
    import time as _time

    from zeroproxy import config, geodata

    monkeypatch.setattr(geodata, "SOURCES", _geo_local_sources(tmp_path))
    geo = config.paths()["geo_dir"]
    stale = os.path.join(geo, ".zp-geo-dl-stale")
    os.makedirs(os.path.join(stale, "part"), exist_ok=True)
    old = _time.time() - 7200
    os.utime(stale, (old, old))

    body = client.post("/api/geodata/update").json()
    assert body["ok"] is True, body
    assert not os.path.exists(stale)


def test_geodata_job_records_unexpected_exception_in_state(client, configured, home, monkeypatch):
    """update() 抛异常 (而不是 return False) 时, 失败原因也要落到 state 和诊断里。

    用户的 Errno 18 就属于这一类: 面板当时只弹了一句 toast, 卡片和"一键诊断"
    里都查不到 —— 回头再看只剩"数据未下载"。
    """
    from zeroproxy import geodata

    monkeypatch.setenv("ZP_APPLY_ASYNC", "1")

    def boom(*_args, **_kwargs):
        raise OSError(errno.EXDEV, "Invalid cross-device link", "/tmp/x/geoip.dat", "/opt/zeroproxy/geo/geoip.dat")

    monkeypatch.setattr(geodata, "update", boom)
    body = client.post("/api/geodata/update").json()
    snap = _wait_job(client, body["job"]["id"])
    assert snap["state"] == "failed", snap
    assert "cross-device" in snap["error"], snap

    state = config.load_state()
    assert "cross-device" in state["geodata"]["last_error"], state["geodata"]
    actions = [e["action"] for e in state.get("audit", [])]
    assert "geodata_update_failed" in actions, actions
    checks = {c["name"]: c for c in client.get("/api/diagnose").json()["checks"]}
    assert "上次更新失败" in checks["GeoIP 数据"]["detail"], checks["GeoIP 数据"]


def test_atomic_install_falls_back_when_replace_cannot_cross_devices(tmp_path, monkeypatch):
    """兜底路径: 万一 staging 还是在别的文件系统上, 也要落地成功而不是报 Errno 18。"""
    from zeroproxy import geodata

    src = tmp_path / "other-fs" / "geoip.dat"
    src.parent.mkdir()
    src.write_bytes(b"NEW" * 10)
    dst = tmp_path / "geo" / "geoip.dat"
    dst.parent.mkdir()
    dst.write_bytes(b"OLD")

    real_replace = os.replace

    def fake_replace(old, new, *args, **kwargs):
        if str(old).startswith(str(src.parent)):
            raise OSError(errno.EXDEV, "Invalid cross-device link", str(old), str(new))
        return real_replace(old, new, *args, **kwargs)

    monkeypatch.setattr(geodata.os, "replace", fake_replace)
    geodata.atomic_install(str(src), str(dst))
    assert dst.read_bytes() == b"NEW" * 10
    assert [p.name for p in dst.parent.iterdir()] == ["geoip.dat"]      # 不留临时名


def test_nginx_conf_never_leaves_home_outside_prod(configured, home, monkeypatch, tmp_path):
    """非生产环境 (没有 systemd) 一律只写 $ZP_HOME/nginx/, 绝不碰 /etc/nginx/conf.d/。

    这是 v2.6.13 真机排查踩到的坑: 面板在服务器上以 root 跑, "有没有权限" 永远是
    有 —— 于是一个换 ZP_HOME 起的临时实例也会把线上 nginx 配置覆盖掉 (指向临时
    目录的证书/端口), 下次 reload nginx 就起不来。
    """
    from zeroproxy import nginx_config, services

    monkeypatch.setattr(services, "is_prod", lambda: False)
    # 把 /etc 那份换成一个临时路径: 万一防呆失效, 断言能直接抓到它被写了
    fake_etc = tmp_path / "etc-nginx" / "zeroproxy.conf"
    real_paths = nginx_config.paths
    monkeypatch.setattr(
        nginx_config, "paths",
        lambda: {**real_paths(), "nginx_etc": str(fake_etc)},
    )

    wrote_etc, where = nginx_config.write_nginx_conf(config.load_state())
    assert wrote_etc is False
    assert where == str(home / "nginx" / "zeroproxy.conf")
    assert (home / "nginx" / "zeroproxy.conf").exists()
    assert not fake_etc.exists()


def test_geodata_autoupdate_respects_explicit_opt_out(home, monkeypatch, tmp_path):
    """用户显式关掉分流后, 后台任务不该再自动下载 28MB 数据。"""
    from zeroproxy import config, geodata

    state = config.load_state()
    assert geodata.wants_update(state) is True          # 默认: 数据缺失 → 需要更新
    state["geodata"]["user_set"] = True
    assert geodata.wants_update(state) is False         # 显式关闭 → 不再更新
    state["geodata"]["enabled"] = True
    assert geodata.wants_update(state) is True          # 重新打开 → 恢复更新


needs_xray = pytest.mark.skipif(
    not os.environ.get("ZP_XRAY_BIN"), reason="需要真实 xray 二进制 (ZP_XRAY_BIN)"
)


def _seed_geo_data(monkeypatch, tmp_path):
    """用 file:// 假数据源把 geo 数据备齐 (不依赖网络)。"""
    from zeroproxy import geodata

    source = tmp_path / "geo-src"
    source.mkdir()
    for name in geodata.MIN_BYTES:
        (source / name).write_bytes(b"ZP" * 600_000)
    monkeypatch.setattr(
        geodata, "SOURCES", {name: [(source / name).as_uri()] for name in geodata.MIN_BYTES}
    )
    ok, detail, _ = geodata.update(config.load_state(), validate=False)
    assert ok, detail


def test_geodata_guard_repairs_config_when_data_vanishes(client, configured, home, monkeypatch, tmp_path):
    """启动期漏洞: 配置已落盘、geo 数据随后丢失 → `systemctl restart xray` 会起不来。

    面板路径本来安全 (每次生成都查 usable()), 但磁盘上的旧配置可能失去数据文件
    (磁盘清理 / 手动删 / 恢复到新机器)。guard() 是 systemd ExecStartPre 的兜底。
    """
    from zeroproxy import geodata, xray_config

    _seed_geo_data(monkeypatch, tmp_path)
    state = config.load_state()
    state["geodata"]["enabled"] = True
    xray_config.write_xray_config(state)                 # 模拟"配置已落盘"
    cfg_path = home / "xray" / "config.json"
    assert "geoip:private" in cfg_path.read_text()

    for name in geodata.MIN_BYTES:                       # 数据文件消失
        (home / "geo" / name).unlink()
    assert geodata.present() is False

    fixed, detail = geodata.guard()
    assert fixed is True, detail
    assert "geo 数据文件缺失" in detail and "已移除 geo 规则" in detail
    text = cfg_path.read_text()
    assert "geoip:" not in text and "geosite:" not in text


def test_geodata_guard_is_noop_when_config_is_fine(client, configured, home):
    """正常部署下 guard 不该改动任何文件 (每次启动都跑, 必须是幂等的)。"""
    from zeroproxy import geodata

    cfg_path = home / "xray" / "config.json"
    before = cfg_path.read_text()
    fixed, detail = geodata.guard()
    assert fixed is False, detail
    assert cfg_path.read_text() == before


def test_geodata_guard_skips_before_setup(home):
    """还没初始化时磁盘上只是占位配置, guard 不该擅自生成半成品配置。"""
    from zeroproxy import geodata

    cfg_path = home / "xray" / "config.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text('{"routing": {"rules": [{"domain": ["geoip:private"]}]}}')
    fixed, detail = geodata.guard()
    assert fixed is False and "尚未初始化" in detail


@needs_xray
def test_geodata_guard_self_heals_missing_cert(client, configured, home):
    """同类漏洞: 证书文件"生成后消失"同样会让 Xray 拒绝启动 —— 自检兜底。"""
    from zeroproxy import geodata, services, xray_config

    state = config.load_state()
    cfg_path = home / "xray" / "config.json"
    assert xray_config.cert_usable(state) is True
    assert "trojan" in cfg_path.read_text()

    os.unlink(state["cert"]["cert_file"])                # 证书丢了
    xray = services.bin_path("xray")
    assert services.run([xray, "-test", "-c", str(cfg_path)])[0] is False

    fixed, detail = geodata.guard()
    assert fixed is True and "自检未通过" in detail
    assert "trojan" not in cfg_path.read_text()          # 入站被摘掉, 核心先起来
    assert services.run([xray, "-test", "-c", str(cfg_path)])[0] is True


# ---------------------------------------------------------------- 一键更新

def test_update_endpoints_require_auth(client, home):
    assert client.get("/api/update").status_code == 401
    assert client.post("/api/update").status_code == 401


def test_update_status_reports_version(client, configured, monkeypatch):
    from zeroproxy import __version__, update

    monkeypatch.setattr(update, "_CACHE", {"at": 0.0, "body": None})
    monkeypatch.setattr(update, "remote_version", lambda timeout=8: (True, "9.9.9", "test-mirror"))
    body = client.get("/api/update").json()
    assert body["current"] == __version__
    assert body["latest"] == "9.9.9"
    assert body["check_ok"] is True
    assert body["update_available"] is True
    assert body["prod"] is False and body["can_update"] is False
    assert body["running"] is False


def test_update_status_survives_unreachable_mirrors(client, configured, monkeypatch):
    from zeroproxy import update

    monkeypatch.setattr(update, "_CACHE", {"at": 0.0, "body": None})
    monkeypatch.setattr(update, "remote_version", lambda timeout=8: (False, "", "离线"))
    body = client.get("/api/update").json()
    assert body["check_ok"] is False and body["update_available"] is False
    assert "离线" in body["check_error"]


def test_update_start_refused_outside_production(client, configured):
    """本地开发环境没有 systemd / 面板目录布局, 不允许在面板里触发升级。"""
    resp = client.post("/api/update")
    assert resp.status_code == 409
    assert "本地开发环境" in resp.json()["error"]


def test_update_start_refused_without_script(client, configured, monkeypatch):
    """生产环境但 upgrade.sh 还没装机 (老版本装的): 给出可执行的下一步, 而不是报 500。"""
    from zeroproxy import services

    monkeypatch.setattr(services, "is_prod", lambda: True)
    resp = client.post("/api/update")
    assert resp.status_code == 409
    assert "未找到升级脚本" in resp.json()["error"]


def test_update_start_writes_queued_status(client, configured, home, monkeypatch):
    """触发升级会先把 queued 状态落盘, 面板重启后也能读到"升级在跑"。"""
    from zeroproxy import services, update

    monkeypatch.setattr(services, "is_prod", lambda: True)
    script = home / "upgrade.sh"
    script.write_text("#!/usr/bin/env bash\nexit 0\n")
    monkeypatch.setattr(update.shutil, "which", lambda name: None)  # 走 start_new_session 兜底
    ok, detail = update.start(trigger="panel")
    assert ok is True, detail
    status = json.loads((home / "data" / "update.json").read_text())
    assert status["state"] in ("queued", "running")
    assert status["trigger"] == "panel"
    assert status["from"] == update.current_version()


def test_update_start_reply_is_local_only(client, configured, home, monkeypatch):
    """回归: 触发升级的回执不许出网查远端版本。

    之前 `/api/update` 的 POST 回执里带了 `update.status()`, 于是点一下「一键更新」要等
    4 个镜像依次超时 (国内直连最坏 ~32s) 才拿到响应, 甚至被面板重启掐断 —— 界面上表现为
    "按钮卡住半分钟, 然后弹一句无法开始升级", 其实升级早在跑了 (v2.6.2 真机复现)。
    """
    from zeroproxy import services, update

    monkeypatch.setattr(services, "is_prod", lambda: True)
    (home / "upgrade.sh").write_text("#!/usr/bin/env bash\nexit 0\n")
    monkeypatch.setattr(update, "_CACHE", {"at": 0.0, "body": None})   # 缓存故意是冷的

    class _Proc:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(update.subprocess, "run", lambda cmd, **kw: _Proc())

    def boom(timeout=8):
        raise AssertionError("触发升级不该出网查远端版本")

    monkeypatch.setattr(update, "remote_version", boom)
    body = client.post("/api/update").json()
    assert body["ok"] is True


def test_update_launch_does_not_wait_for_the_unit(client, configured, home, monkeypatch):
    """回归: `systemd-run` 必须带 `--no-block`。

    默认情况下 systemd-run 会把这个 oneshot 单元**跑完**才返回 —— 而升级要 30-40 秒,
    于是 `subprocess.run(timeout=30)` 先超时, 面板回执变成 409「无法启动升级任务」,
    界面上却能看到升级真的在进行 (v2.6.3 在真机上量到: 点按钮 63 秒后才弹这句错,
    同时 update.json 里是一条 8/8 步的成功记录)。
    """
    from zeroproxy import services, update

    monkeypatch.setattr(services, "is_prod", lambda: True)
    (home / "upgrade.sh").write_text("#!/usr/bin/env bash\nexit 0\n")
    captured = {}

    class _Proc:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _Proc()

    monkeypatch.setattr(update.shutil, "which", lambda name: "/usr/bin/systemd-run")
    monkeypatch.setattr(update.subprocess, "run", fake_run)
    ok, detail = update.start(trigger="panel")
    assert ok is True, detail
    assert captured["cmd"][0] == "/usr/bin/systemd-run"
    assert "--no-block" in captured["cmd"]


def test_update_runs_a_staged_copy(client, configured, home, monkeypatch):
    """回归: 面板必须跑 upgrade.sh 的**临时副本**, 不能就地执行 ZP_HOME 里那一份。

    bash 是按文件偏移增量读取脚本的, 而 upgrade.sh 会在「安装新代码」那步把自己就地
    覆盖成新版本 —— 就地执行时 bash 从"新文件"的同一偏移继续读, 直接
    `syntax error near unexpected token` (真机 v2.3.10 → v2.3.11 就是这么炸的)。
    """
    from zeroproxy import services, update

    monkeypatch.setattr(services, "is_prod", lambda: True)
    script = home / "upgrade.sh"
    script.write_text("#!/usr/bin/env bash\nexit 0\n")
    monkeypatch.setattr(update.shutil, "which", lambda name: None)  # 走无 systemd-run 的兜底

    captured = {}

    def fake_popen(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["env"] = kwargs.get("env") or {}
        return None

    # 兜底路径是 Popen: 不能同步等 upgrade.sh 跑完 (30 秒超时会杀掉跑到一半的升级)
    monkeypatch.setattr(update.subprocess, "Popen", fake_popen)
    ok, detail = update.start(trigger="panel")
    assert ok is True, detail

    staged = captured["cmd"][-1]
    assert captured["cmd"][0] == "/bin/bash"
    assert staged != str(script)                       # 不是就地执行
    assert os.path.basename(staged) == "upgrade.sh"
    assert open(staged, encoding="utf-8").read() == script.read_text()   # 内容一致
    assert os.stat(staged).st_mode & 0o777 == 0o755
    assert captured["env"]["ZP_SELF_DIR"] == os.path.dirname(staged)     # 让脚本能自删副本
    shutil.rmtree(os.path.dirname(staged), ignore_errors=True)


def test_version_compare_helpers():
    from zeroproxy import update

    assert update.parse_version("v2.3.10-beta") == (2, 3, 10)
    assert update.parse_version("2.3") == (2, 3)
    assert update.parse_version("") == (0,)
    assert update.is_newer("2.4.0", "2.3.0") is True
    assert update.is_newer("2.3.0", "2.3.0") is False
    assert update.is_newer("v2.2", "2.3.0") is False


def test_update_mirrors_put_authoritative_sources_first():
    """jsDelivr 是 CDN, 缓存未过期时会返回旧版本号 (实测发布后仍报上一版) ——
    权威源必须排在前面, 否则面板会一直说"已是最新"。"""
    from zeroproxy import update

    hosts = [url.split("/")[2] for url in update._MIRRORS]
    assert hosts[0] == "raw.githubusercontent.com"
    assert hosts.index("raw.githubusercontent.com") < hosts.index("cdn.jsdelivr.net")
    assert hosts.index("raw.githubusercontent.com") < hosts.index("fastly.jsdelivr.net")


# ---------------------------------------------------------------- 配置落地闭环

def test_apply_verify_listeners_skips_in_dev(client, configured):
    from zeroproxy import apply

    ok, detail = apply.verify_listeners(config.load_state())
    assert ok is True and "跳过" in detail


def _fake_listener_probe(monkeypatch, tcp_ports, udp_ports=()):
    """把"端口是否在监听"换成固定答案, 好离线验证端口校验的两个方向。"""
    from zeroproxy import apply, services

    monkeypatch.setattr(services, "is_prod", lambda: True)
    monkeypatch.setattr(apply, "_tcp_open", lambda port, timeout=0.6: int(port) in set(tcp_ports))
    monkeypatch.setattr(services, "udp_port_listening", lambda port: int(port) in set(udp_ports))


def test_restart_services_restarts_even_when_all_nodes_are_off(client, configured, monkeypatch):
    """回归: 「关掉节点」曾经只改磁盘上的配置 —— 旧判据是"还有没有节点开着",
    全部停用时直接跳过重启, 于是运行中的进程照旧在旧端口上服务 (面板显示已关闭,
    端口其实还开着)。装了服务, 运行态就必须跟着新配置收敛。"""
    from zeroproxy import apply, services

    calls: list[list[str]] = []
    monkeypatch.setattr(services, "is_prod", lambda: True)
    monkeypatch.setattr(services, "bin_path", lambda name: f"/usr/local/bin/{name}")
    monkeypatch.setattr(
        services, "run", lambda cmd, timeout=120, env=None: (calls.append(list(cmd)), (True, "ok"))[1]
    )

    state = config.load_state()
    for node_id in state["nodes"]:
        state["nodes"][node_id] = False

    ok, detail = apply.restart_services(state, timeout=90)
    assert ok is True, detail
    assert ["systemctl", "restart", "xray"] in calls, detail
    assert ["systemctl", "restart", "hysteria2"] in calls, detail
    assert ["systemctl", "reload", "nginx"] in calls


def test_restart_services_skips_services_that_are_not_installed(client, configured, monkeypatch):
    """没装的服务不要硬重启 —— 那只会多一条无意义的失败步骤。"""
    from zeroproxy import apply, services

    calls: list[list[str]] = []
    monkeypatch.setattr(services, "is_prod", lambda: True)
    monkeypatch.setattr(services, "bin_path", lambda name: None)
    monkeypatch.setattr(services, "service_state", lambda name: "not-installed")
    monkeypatch.setattr(
        services, "run", lambda cmd, timeout=120, env=None: (calls.append(list(cmd)), (True, "ok"))[1]
    )

    state = config.load_state()
    for node_id in state["nodes"]:
        state["nodes"][node_id] = False

    ok, detail = apply.restart_services(state, timeout=90)
    assert ok is True, detail
    assert not any(cmd[:2] == ["systemctl", "restart"] for cmd in calls), calls
    assert ["systemctl", "reload", "nginx"] in calls


def test_verify_listeners_flags_a_disabled_node_that_still_listens(client, configured, monkeypatch):
    """反向校验: 已停用的节点端口必须真的关掉 —— 只查"该开的开了"抓不到
    「面板显示已关闭、端口其实还开着」。"""
    from zeroproxy import apply

    state = config.load_state()
    state["nodes"]["vless-reality"] = False
    # 8443 (刚停用的 Reality) 还在监听 → 必须报失败
    _fake_listener_probe(monkeypatch, {8443, 8445, 8444, 6000, 443}, {30001, 31001, 32001})

    ok, detail = apply.verify_listeners(state, timeout=0.01)
    assert ok is False, detail
    assert "8443" in detail and "已停用却仍在监听" in detail, detail


def test_verify_listeners_accepts_a_converged_state(client, configured, monkeypatch):
    from zeroproxy import apply

    state = config.load_state()
    state["nodes"]["vless-reality"] = False
    state["nodes"]["hysteria2"] = False
    _fake_listener_probe(monkeypatch, {8445, 8444, 6000, 443})

    ok, detail = apply.verify_listeners(state, timeout=0.01)
    assert ok is True, detail
    assert "已停用端口已关闭" in detail, detail
    assert "8443" in detail   # 明确列出被确认关闭的端口


def test_verify_listeners_does_not_require_sockets_for_hopping_ports(client, configured, monkeypatch):
    """回归 (v2.6.5 真机事故): 端口跳跃的额外端口**没有自己的 socket**。

    Linux 上 hysteria 是把它们的 UDP 包用 nftables / iptables REDIRECT 到主端口
    (上游 app/internal/firewall.SetupUDPPortRedirect), 所以按"端口在监听"去验跳跃
    端口, 会把完全正常的跳跃配置判成失败 —— 真机升级就是这么挂在第 6 步的。
    """
    from zeroproxy import apply

    state = config.load_state()
    state["hysteria_hopping"] = True
    state["hysteria_ports"] = [40001, 41001, 42001]
    state["ports"]["hysteria"] = 40001
    # 只有主端口有 socket, 跳跃端口一个都没有 → 仍然必须算通过
    _fake_listener_probe(monkeypatch, {8443, 8445, 8444, 6000, 443}, {40001})

    ok, detail = apply.verify_listeners(state, timeout=0.01)
    assert ok is True, detail


def test_hop_redirect_note_reports_kernel_forwarding(configured, monkeypatch):
    """跳跃端口只能靠内核转发规则来确认: 读得到就说明, 读不到就说读不到。"""
    from zeroproxy import apply, services

    state = config.load_state()
    state["hysteria_hopping"] = True
    state["hysteria_ports"] = [30001, 31001, 32001]
    state["ports"]["hysteria"] = 30001

    rules = "udp dport 31001 redirect to :30001\nudp dport 32001 redirect to :30001"
    monkeypatch.setattr(services, "run", lambda cmd, timeout=120, env=None: (True, rules))
    note = apply._hop_redirect_note(state)
    assert "已由内核转发" in note and "30001" in note, note

    # 规则里缺了 32001 → 如实说"未见转发规则", 但这不是一个失败
    partial = "udp dport 31001 redirect to :30001"
    monkeypatch.setattr(services, "run", lambda cmd, timeout=120, env=None: (True, partial))
    note = apply._hop_redirect_note(state)
    assert "32001" in note and "未见内核转发规则" in note, note

    # 本机问不到 (非 root / 没有 nft 和 iptables) → 返回空串, 不做任何判断
    monkeypatch.setattr(services, "run", lambda cmd, timeout=120, env=None: (False, "命令不存在"))
    assert apply._hop_redirect_note(state) == ""

    # 跳跃关着 → 不插话
    state["hysteria_hopping"] = False
    monkeypatch.setattr(services, "run", lambda cmd, timeout=120, env=None: (True, rules))
    assert apply._hop_redirect_note(state) == ""


def test_apply_gen_nginx_is_hard_failure_without_etc_write(client, configured, home, monkeypatch):
    """生产环境写不进 /etc/nginx 必须算失败 —— 否则「全绿但 443 不监听」。"""
    from zeroproxy import apply, nginx_config, services

    monkeypatch.setattr(services, "is_prod", lambda: True)
    monkeypatch.setattr(nginx_config, "write_nginx_conf", lambda state: (False, str(home / "nginx")))
    ok, detail = apply.gen_nginx(config.load_state())
    assert ok is False and "无法写入" in detail


def test_apply_reapply_persists_steps(client, configured, home):
    from zeroproxy import apply

    state = config.load_state()
    steps = apply.reapply(state)
    assert [s["name"] for s in steps] == [
        "校验 Reality 密钥与伪装目标",
        "重新生成 Xray 配置",
        "重新生成 Nginx 配置",
        "重新生成 Hysteria 2 配置",
        "重载服务 (nginx/xray/hysteria2)",
        "验证端口监听",
    ]
    assert all(s["ok"] for s in steps), steps
    assert config.load_state()["steps"] == steps       # 落盘 → 仪表盘顶部告警
    assert (home / "xray" / "config.json").is_file()


def test_apply_skips_services_whose_config_did_not_change(client, configured, home, monkeypatch):
    """配置一个字节都没变的服务不该被重启 (v2.6.9)。

    链式代理的操作只动 Xray 的入站, nginx / hysteria 的配置一个字符都没变, 却要
    陪着重载一次; 反过来, 服务真的挂了 (不在跑) 时又要照样自愈 —— 两条都要守住。
    """
    from zeroproxy import apply, services

    calls: list[str] = []
    running = {"nginx": True}

    monkeypatch.setattr(services, "is_prod", lambda: True)
    monkeypatch.setattr(
        services, "service_state",
        lambda name: "active" if running.get(name, True) else "inactive",
    )
    monkeypatch.setattr(
        services, "restart_service",
        lambda name, timeout=90: (calls.append(name), (True, "已重启"))[1],
    )
    monkeypatch.setattr(
        services, "reload_service",
        lambda name, timeout=60: (calls.append(name), (True, "已重载"))[1],
    )
    monkeypatch.setattr(apply, "_tcp_open", lambda port, timeout=0.3: True)
    monkeypatch.setattr(services, "udp_port_listening", lambda port: True)
    monkeypatch.setattr(apply, "_hop_redirect_note", lambda state: "")

    state = config.load_state()
    wanted = {int(port) for port, _, _ in apply._wanted_ports(state)}  # noqa: SLF001
    monkeypatch.setattr(apply, "_tcp_open", lambda port, timeout=0.3: int(port) in wanted)

    # 1) 三份配置都变了 → 三个服务都动 (并发执行, 所以只比集合)
    ok, detail = apply.restart_services(state, changed={"xray", "nginx", "hysteria"})
    assert ok is True, detail
    assert sorted(calls) == ["hysteria2", "nginx", "xray"], calls

    # 2) 只有 Xray 变 → 只重启 Xray (链式代理操作的典型场景)
    calls.clear()
    apply.restart_services(state, changed={"xray"})
    assert calls == ["xray"], calls

    # 3) 一份都没变 → 一个服务都不动
    calls.clear()
    ok, detail = apply.restart_services(state, changed=set())
    assert ok is True and "无需重启" in detail, detail
    assert calls == [], calls

    # 4) 配置没变但服务没在跑 → 照样重启 (自愈不能被"跳过"吃掉)
    calls.clear()
    running["nginx"] = False
    apply.restart_services(state, changed=set())
    assert calls == ["nginx"], calls
    running["nginx"] = True

    # 5) 端到端: 第一次配置确实变了才重启, 第二次一模一样 → 一个都不重启
    (home / "xray" / "config.json").write_text("{}\n", encoding="utf-8")
    calls.clear()
    assert apply.reapply(config.load_state())[4]["ok"] is True
    assert calls == ["xray"], calls
    calls.clear()
    again = apply.reapply(config.load_state())
    assert again[4]["ok"] is True and "无需重启" in again[4]["detail"], again
    assert calls == [], calls


def test_apply_verify_listeners_polls_quickly_instead_of_waiting_a_full_round(
    client, configured, monkeypatch
):
    """重启 Xray 后端口要 ~0.7s 才起来, 校验必须快速轮询 (v2.6.9)。

    旧实现固定 `sleep(0.6)`: 端口 0.3 秒后才通也要白等一整轮 —— 这是"关闭落地端"
    那 1 秒的来源之一。这里让端口第 2 轮才通, 断言总耗时 < 0.5s (旧实现 ~1.2s)。
    """
    import time

    from zeroproxy import apply, services

    monkeypatch.setattr(services, "is_prod", lambda: True)
    monkeypatch.setattr(services, "udp_port_listening", lambda port: True)
    monkeypatch.setattr(apply, "_hop_redirect_note", lambda state: "")
    state = config.load_state()
    ports = apply._wanted_ports(state)  # noqa: SLF001
    assert ports, "这个用例需要一个有端口的配置"
    first_port = int(ports[0][0])
    rounds = {"n": 0}

    def round_aware(port, timeout=0.3):
        if int(port) == first_port:
            rounds["n"] += 1
        return rounds["n"] >= 2

    monkeypatch.setattr(apply, "_tcp_open", round_aware)

    started = time.perf_counter()
    ok, detail = apply.verify_listeners(state, timeout=8)
    elapsed = time.perf_counter() - started
    assert ok is True, detail
    assert elapsed < 0.5, f"端口校验白等了 {elapsed:.2f}s"


def test_apply_async_job_reports_progress_and_finishes(client, configured, monkeypatch):
    """链式按钮不再让请求阻塞 4 秒: 立刻回执 + 后台任务 + 进度轮询 (v2.6.9)。"""
    import time

    from zeroproxy import apply

    monkeypatch.setenv("ZP_APPLY_ASYNC", "1")
    body = client.post("/api/chain/exit", json={"action": "generate", "port": 8666}).json()
    job = body.get("job") or {}
    assert job.get("total") == len(apply.STEP_NAMES), body
    assert body["steps"] == []                     # 立刻回执, 步骤稍后从任务里取
    assert body["chain"]["exit"]["enabled"] is True

    deadline = time.time() + 30
    snap: dict = {}
    while time.time() < deadline:
        snap = client.get(f"/api/apply/job?id={job['id']}").json()
        if snap.get("state") != "running":
            break
        time.sleep(0.05)
    assert snap.get("state") == "done", snap
    # 六步闭环 + 这次操作自己的收尾步 (放行落地端端口), 顺序与面板显示一致
    assert [s["name"] for s in snap["steps"]] == list(apply.STEP_NAMES) + ["放行落地端端口"], snap
    assert all(s["ok"] for s in snap["steps"]), snap
    assert snap["elapsed_ms"] >= 0

    # 进度接口只认发起任务的那个会话 (换一个会话就看不到)
    client.cookies.clear()
    assert client.get(f"/api/apply/job?id={job['id']}").status_code == 401


def test_apply_restart_services_uses_correct_systemctl_args(client, configured, monkeypatch):
    """回归: 曾经把 timeout 当服务名传下去 (fn(t) 而不是 fn(name, t)), 生产环境必炸 ——
    本地 dry-run 看不到, 因为非生产环境直接"跳过"。"""
    from zeroproxy import apply, services

    calls: list[list[str]] = []

    def fake_run(cmd, timeout=120, env=None):
        calls.append(list(cmd))
        return True, "ok"

    monkeypatch.setattr(services, "is_prod", lambda: True)
    monkeypatch.setattr(services, "run", fake_run)
    ok, detail = apply.restart_services(config.load_state(), timeout=90)

    assert ok is True, detail
    assert ["systemctl", "restart", "xray"] in calls
    assert ["systemctl", "restart", "hysteria2"] in calls
    assert ["systemctl", "reload", "nginx"] in calls
    # 关键: 命令里不允许出现非字符串 (即被误当成服务名传下去的 timeout)
    assert all(isinstance(arg, str) for cmd in calls for arg in cmd), calls


def test_apply_cli_reports_failure_as_nonzero(configured, home, monkeypatch, capsys):
    from zeroproxy import apply, nginx_config, services

    assert apply._main([]) == 0
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert payload["ok"] is True

    monkeypatch.setattr(services, "is_prod", lambda: True)
    monkeypatch.setattr(apply, "_tcp_open", lambda port, timeout=0.6: True)      # 别真等 12s 轮询
    monkeypatch.setattr(services, "udp_port_listening", lambda port: True)
    monkeypatch.setattr(nginx_config, "write_nginx_conf", lambda state: (False, str(home / "nginx")))
    assert apply._main(["--quiet"]) == 1
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert payload["ok"] is False
    assert any(not s["ok"] for s in payload["steps"])
    assert any(s["name"] == "重新生成 Nginx 配置" and not s["ok"] for s in payload["steps"])


def test_apply_cli_refuses_before_setup(home):
    from zeroproxy import apply

    assert apply._main([]) == 2


# ---------------------------------------------------------------- 证书申请 / 续期

def test_renew_requires_auth(client, home):
    assert client.post("/api/renew").status_code == 401


def test_renew_reports_skip_in_dev(client, configured):
    """非生产环境没有 systemd / certbot, 明确说"跳过", 不假装成功。"""
    body = client.post("/api/renew").json()
    assert body["ok"] is False and "跳过" in body["detail"]
    assert body["steps"] == []


def test_renew_cert_issues_letsencrypt_when_selfsigned(configured, monkeypatch):
    """自签证书的部署再点一次「申请证书」要真的去申请 —— 过去这里只会回一句"无可续期"。"""
    import time

    from zeroproxy import services

    state = config.load_state()
    assert state["cert"]["type"] == "selfsigned"
    monkeypatch.setattr(services, "is_prod", lambda: True)
    monkeypatch.setattr(services.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        services,
        "install_cert",
        lambda host: (
            True,
            "Let's Encrypt 证书已签发 (90 天, 自动续期)",
            {
                "type": "letsencrypt",
                "issuer": "Let's Encrypt",
                "cert_file": f"/etc/letsencrypt/live/{host}/fullchain.pem",
                "key_file": f"/etc/letsencrypt/live/{host}/privkey.pem",
                "not_after": int(time.time()) + 90 * 86400,
            },
        ),
    )
    ok, detail = services.renew_cert(state)
    assert ok is True, detail
    assert state["cert"]["type"] == "letsencrypt"
    assert state["cert"]["cert_file"].startswith("/etc/letsencrypt/live/")


def test_renew_endpoint_reapplies_configs_when_cert_changes(client, home, configured, monkeypatch):
    """拿到正式证书后必须重新生成 nginx / xray 配置, 否则线上仍是自签证书。"""
    from zeroproxy import services

    # 真的造两份证书文件: 换签后的 cert_file 指向一个不存在的路径在现实里不会发生
    # (certbot 会写盘), 而且那种状态会被"证书文件兜底"正确地判为不可用。
    cert_file = home / "letsencrypt" / "fullchain.pem"
    key_file = home / "letsencrypt" / "privkey.pem"
    cert_file.parent.mkdir(parents=True, exist_ok=True)
    assert services.generate_self_signed(DOMAIN, str(cert_file), str(key_file))[0]

    def fake_renew(state):
        state["cert"] = {
            **state["cert"],
            "type": "letsencrypt",
            "issuer": "Let's Encrypt",
            "cert_file": str(cert_file),
            "key_file": str(key_file),
        }
        return True, "Let's Encrypt 证书已签发"

    monkeypatch.setattr(services, "renew_cert", fake_renew)
    body = client.post("/api/renew").json()
    assert body["ok"] is True, body
    assert body["steps"], body
    assert all(s["ok"] for s in body["steps"]), body["steps"]
    assert config.load_state()["cert"]["type"] == "letsencrypt"


# ---------------------------------------------------------------- 操作记录 (审计日志)

def test_audit_ids_are_monotonic_and_repeats_coalesce(home):
    """id 单调递增 (面板按它游标分页); 同一件事在窗口内重复只合并计数。

    合并计数是为被扫描时准备的: 几百条一模一样的 login_failed 会把 500 条的
    环形缓冲刷满, 把真正重要的操作挤出去。
    """
    state = config.load_state()
    config.audit(state, "login", "user=admin", actor="1.2.3.4")
    assert state["audit"][-1]["id"] == 1 and state["audit"][-1]["count"] == 1

    config.audit(state, "login", "user=admin", actor="1.2.3.4")   # 立刻重复 → 合并
    assert len(state["audit"]) == 1, "窗口内的重复不应该新增条目"
    assert state["audit"][-1]["count"] == 2

    # 出了 60 秒窗口 → 另起一条, id 继续递增而不是复用
    state["audit"][-1]["ts"] -= config.AUDIT_COALESCE_S + 5
    config.audit(state, "login", "user=admin", actor="1.2.3.4")
    assert [e["id"] for e in state["audit"]] == [1, 2]

    # 动作/来源不同就不会互相吞掉
    config.audit(state, "login", "user=root", actor="1.2.3.4")
    config.audit(state, "backup", "domain=a.example.com", actor="9.9.9.9")
    assert [e["id"] for e in state["audit"]] == [1, 2, 3, 4]
    assert [e["action"] for e in state["audit"]] == ["login", "login", "login", "backup"]


def test_audit_query_paginates_by_cursor_without_gaps(home):
    """游标分页 (before=上一页最后一条 id) 要又不重又不漏。"""
    state = config.load_state()
    for i in range(7):
        config.audit(state, "login", f"user=u{i}", actor="1.2.3.4")

    page1 = config.audit_query(state, limit=3)
    assert [e["id"] for e in page1["entries"]] == [7, 6, 5]
    assert page1["total"] == 7 and page1["has_more"] is True
    assert page1["next_before"] == 5

    page2 = config.audit_query(state, limit=3, before=page1["next_before"])
    assert [e["id"] for e in page2["entries"]] == [4, 3, 2]

    page3 = config.audit_query(state, limit=3, before=page2["next_before"])
    assert [e["id"] for e in page3["entries"]] == [1]
    assert page3["has_more"] is False

    seen = [e["id"] for page in (page1, page2, page3) for e in page["entries"]]
    assert seen == [7, 6, 5, 4, 3, 2, 1]


def test_audit_query_filters_but_facets_stay_global(home):
    """筛选只影响条目列表; 分类按钮上的数字是存量统计, 不随点击跳来跳去。"""
    state = config.load_state()
    config.audit(state, "login", "user=admin", actor="1.2.3.4")
    config.audit(state, "login_failed", "user=admin", actor="9.9.9.9")
    config.audit(state, "backup", "domain=a.example.com", actor="1.2.3.4")
    config.audit(state, "chain_add", "chain-x", actor="1.2.3.4")

    auth = config.audit_query(state, category="auth")
    assert {e["action"] for e in auth["entries"]} == {"login", "login_failed"}
    counts = {f["id"]: f["count"] for f in auth["facets"]}
    assert counts["auth"] == 2 and counts["data"] == 1 and counts["chain"] == 1

    failed = config.audit_query(state, only_failed=True)
    assert [e["action"] for e in failed["entries"]] == ["login_failed"]

    assert [e["action"] for e in config.audit_query(state, q="domain=")["entries"]] == ["backup"]

    both = config.audit_query(state, category="auth", q="domain=")
    assert both["entries"] == [] and both["total"] == 0, "分类与关键字是叠加的"


def test_audit_overflow_archives_to_log_file(home):
    """超过 AUDIT_MAX 的老记录滚进 data/audit.log, 不再无声丢弃。"""
    state = config.load_state()
    for i in range(config.AUDIT_MAX + 5):
        config.audit(state, "login", f"user=u{i}", actor="1.2.3.4")

    assert len(state["audit"]) == config.AUDIT_MAX
    assert state["audit_dropped"] == 5

    log = config.audit_log_path()
    assert os.path.exists(log)
    with open(log, encoding="utf-8") as fh:
        archived = [json.loads(line) for line in fh]
    assert [e["id"] for e in archived] == [1, 2, 3, 4, 5], "滚出去的按原顺序进归档"

    stats = config.audit_query(state)["stats"]
    assert stats["retained"] == config.AUDIT_MAX and stats["dropped"] == 5
    assert stats["log"] == log


def test_load_state_backfills_ids_for_legacy_audit(home):
    """v2.6.15 之前的老 state 只有 ts/action/detail, 加载时要补 id 才能游标分页。"""
    state = config.load_state()
    state["audit"] = [
        {"ts": 100, "action": "login", "detail": "user=admin", "actor": "1.2.3.4", "count": 1},
        {"ts": 200, "action": "backup", "detail": "domain=a.example.com", "actor": "1.2.3.4", "count": 1},
    ]
    state["audit_seq"] = 0
    config.save_state(state)

    fresh = config.load_state()
    assert [e["id"] for e in fresh["audit"]] == [1, 2]
    assert fresh["audit_seq"] == 2

    config.audit(fresh, "login", "user=admin", actor="1.2.3.4")
    assert fresh["audit"][-1]["id"] == 3, "补号之后新记录要接着往下排"


def test_audit_view_flags_risk_and_failure(home):
    """风险动作单独标一下; 失败判定要认 `_failed` 之外那几个写法不规则的。"""
    risky = config.audit_view({"id": 1, "ts": 0, "action": "restore", "count": 1})
    assert risky["risk"] is True and risky["ok"] is True
    assert risky["label"] == "从备份恢复" and risky["category"] == "data"

    assert config.audit_view({"action": "login_failed"})["ok"] is False
    assert config.audit_view({"action": "geodata_update_failed"})["ok"] is False

    unknown = config.audit_view({"action": "brand_new_thing"})
    assert unknown["category"] == "other" and unknown["label"] == "brand_new_thing"


def test_audit_api_requires_auth(client, configured):
    client.post("/api/logout")
    assert client.get("/api/audit").status_code == 401
    assert client.get("/api/audit?category=auth&q=x&failed=1").status_code == 401


def test_audit_api_and_dashboard_expose_view_shape(client, configured):
    """仪表盘顺带下发首屏的几条 + 分类数字; 更早的走独立接口。"""
    dash = client.get("/api/dashboard").json()
    assert dash["audit"], "初始化本身就该留下一条 setup 记录"
    assert {"retained", "failed", "dropped", "max"} <= set(dash["audit_stats"])
    fields = {"id", "ts", "action", "label", "category", "detail", "actor", "count", "ok", "risk"}
    assert all(set(e) == fields for e in dash["audit"])
    assert all(set(f) == {"id", "label", "count"} for f in dash["audit_facets"])

    page = client.get("/api/audit?limit=5").json()
    assert {"entries", "total", "has_more", "next_before", "facets", "stats"} <= set(page)
    assert page["stats"]["retained"] >= 1


def test_audit_clear_wipes_buffer_but_keeps_one_record(client, configured, home):
    """清空只清面板保留的缓冲, 且必须留下"谁清的"这一条。

    服务器上的归档文件 (data/audit.log) 是"更早的记录"的唯一副本 —— 清空不该
    顺手删掉它, 否则一次误点就永久丢历史。
    """
    from zeroproxy import config

    # 先攒几条, 再手动往归档计数器上加一个数, 验证清空会把它归零
    client.post("/api/nodes/vless-reality/toggle")
    client.post("/api/nodes/vless-reality/toggle")
    # 造一份归档文件 (真实运行时由环形缓冲溢出产生), 清空后它必须原样还在
    archive = os.path.join(str(home), "data", "audit.log")
    with open(archive, "w", encoding="utf-8") as fh:
        fh.write('{"id":1,"ts":0,"action":"setup","detail":"更早的记录","actor":"admin","count":1}\n')
    with config.locked():
        state = config.load_state()
        assert len(state["audit"]) >= 3
        state["audit_dropped"] = 42
        config.save_state(state)

    body = client.post("/api/audit/clear").json()
    assert body["cleared"] >= 3
    # 清完只剩"清空操作记录"本身 —— 面板不会出现"空得看不出谁动过"
    assert [e["action"] for e in body["entries"]] == ["audit_clear"]
    assert body["entries"][0]["risk"] is True          # 影响面大的操作要标出来
    assert body["entries"][0]["actor"] == "testclient"  # TestClient 报的来源
    assert body["stats"]["retained"] == 1
    assert body["stats"]["dropped"] == 0               # 归档计数跟着归零

    # 再清一次: 只剩上一条 audit_clear, 数量如实减少, 不会报错
    again = client.post("/api/audit/clear").json()
    assert again["cleared"] == 1

    # 归档文件一字未动: 它是"更早的记录"的唯一副本, 不该被一个按钮顺手删掉
    with open(archive, encoding="utf-8") as fh:
        assert "更早的记录" in fh.read()


def test_audit_clear_requires_auth(client, configured):
    client.post("/api/logout")
    assert client.post("/api/audit/clear").status_code == 401


# ---------------------------------------------------------------- 升级脚本 / 文档

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _bash_syntax_ok(path: str) -> bool:
    import shutil
    import subprocess

    if not shutil.which("bash"):
        return True
    return subprocess.run(["bash", "-n", path], capture_output=True).returncode == 0


def test_upgrade_script_shipped_and_valid():
    """一键升级脚本必须随仓库发布, 且升级后按 state.json 重新落地配置。"""
    path = os.path.join(REPO_ROOT, "upgrade.sh")
    assert os.path.isfile(path)
    text = open(path, encoding="utf-8").read()
    assert "python\" -m zeroproxy.apply" in text or "-m zeroproxy.apply" in text
    assert "ZP_CHECK_ONLY" in text and "rollback" in text
    assert _bash_syntax_ok(path)


def test_install_script_never_resets_configured_deployment():
    """install.sh 重跑时不能把已初始化的部署打回占位配置 (否则 5 个节点全不通)。"""
    path = os.path.join(REPO_ROOT, "install.sh")
    text = open(path, encoding="utf-8").read()
    assert "PANEL_INITIALIZED" in text
    assert 'cp "$SRC_DIR/upgrade.sh" "$ZP_HOME/upgrade.sh"' in text
    assert "-m zeroproxy.apply" in text
    assert _bash_syntax_ok(path)


def test_upgrade_sim_harness_is_valid():
    """一键升级的回归演练脚本 (macOS/Linux 都能跑, 不需要 root/systemd)。"""
    path = os.path.join(REPO_ROOT, "scripts", "upgrade_sim.sh")
    assert os.path.isfile(path)
    assert _bash_syntax_ok(path)


def test_readme_documents_one_line_upgrade():
    text = open(os.path.join(REPO_ROOT, "README.md"), encoding="utf-8").read()
    assert "upgrade.sh | bash" in text
    assert "一键更新" in text
    assert "/api/update" in text
