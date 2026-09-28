"""ZeroProxy 面板回归测试 (dry-run 全流程 + 订阅格式 + 安全边界)。"""
from __future__ import annotations

import base64
import json
import os

import pytest

from conftest import DOMAIN, PASSWORD, USERNAME
from zeroproxy import config, xray_config


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


# ---------------------------------------------------------------- 诊断 / 二维码

def test_diagnose_reports_checks(client, configured):
    body = client.get("/api/diagnose").json()
    names = [c["name"] for c in body["checks"]]
    assert "Xray 配置" in names and "TLS 证书" in names
    assert body["summary"].endswith("项通过")
    xray = [c for c in body["checks"] if c["name"] == "Xray 配置"][0]
    assert xray["ok"] is True


def test_repair_regenerates_configs(client, configured):
    body = client.post("/api/repair").json()
    assert [s["name"] for s in body["steps"]][0] == "重新生成 Xray 配置"
    assert all(s["ok"] for s in body["steps"]), body["steps"]


def test_qr_endpoints(client, configured):
    assert client.get("/api/nodes/hysteria2/qr?size=4").headers["content-type"] == "image/png"
    assert client.get("/api/subscription/qr?size=4").headers["content-type"] == "image/png"
    assert client.get("/api/nodes/nope/qr").status_code == 404


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
    assert state["reality"]["server_name"] == "www.microsoft.com"
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
    assert body["dest"]["address"] == "www.microsoft.com:443"


def test_probe_requires_auth(client, configured):
    client.cookies.clear()
    assert client.get("/api/probe").status_code == 401


def test_probe_skips_disabled_nodes(client, configured):
    client.post("/api/nodes/hysteria2/toggle")
    body = client.get("/api/probe?force=1").json()
    hysteria = next(n for n in body["nodes"] if n["node"] == "hysteria2")
    assert hysteria["ok"] is None and "关闭" in hysteria["detail"]


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
    client.post("/api/settings", json={"reality_sni": "www.cloudflare.com"})

    restored = client.post("/api/restore", content=exported.content)
    assert restored.status_code == 200, restored.text
    state = config.load_state()
    assert state["nodes"]["vless-ws"] is True           # 节点开关回到备份点
    assert state["reality"]["server_name"] == "www.microsoft.com"
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


def test_settings_reject_enabling_geodata_without_data(client, configured):
    response = client.post("/api/settings", json={"geodata_enabled": True})
    assert response.status_code == 400
    assert "GeoIP" in response.json()["error"]


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


def test_version_compare_helpers():
    from zeroproxy import update

    assert update.parse_version("v2.3.10-beta") == (2, 3, 10)
    assert update.parse_version("2.3") == (2, 3)
    assert update.parse_version("") == (0,)
    assert update.is_newer("2.4.0", "2.3.0") is True
    assert update.is_newer("2.3.0", "2.3.0") is False
    assert update.is_newer("v2.2", "2.3.0") is False


# ---------------------------------------------------------------- 配置落地闭环

def test_apply_verify_listeners_skips_in_dev(client, configured):
    from zeroproxy import apply

    ok, detail = apply.verify_listeners(config.load_state())
    assert ok is True and "跳过" in detail


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
        "重新生成 Xray 配置",
        "重新生成 Nginx 配置",
        "重新生成 Hysteria 2 配置",
        "重载服务 (nginx/xray/hysteria2)",
        "验证端口监听",
    ]
    assert all(s["ok"] for s in steps), steps
    assert config.load_state()["steps"] == steps       # 落盘 → 仪表盘顶部告警
    assert (home / "xray" / "config.json").is_file()


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
