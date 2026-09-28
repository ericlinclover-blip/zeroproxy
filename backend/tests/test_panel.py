"""ZeroProxy 面板回归测试 (dry-run 全流程 + 订阅格式 + 安全边界)。"""
from __future__ import annotations

import base64
import json

import pytest

from conftest import DOMAIN, PASSWORD, USERNAME


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
    assert state["version"] == config.STATE_VERSION == 2
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
    assert state["version"] == 2
    assert state["ports"]["xhttp"] == 8445
    assert state["nodes"]["vless-xhttp"] is True          # 新节点自动补默认值
    assert state["hysteria_masquerade"]["enabled"] is True
    assert state["reality"]["server_name"] == "www.microsoft.com"


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
