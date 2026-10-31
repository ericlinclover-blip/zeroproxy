"""原生 WireGuard 入站的回归测试（dry-run，不需要真实 wg / wg-quick）。"""
from __future__ import annotations

import json
from urllib.parse import urlsplit

from zeroproxy import config, wireguard


def _state(domain: str = "proxy.example.com") -> dict:
    state = config.state_from({})
    state["configured"] = True
    state["domain"] = domain
    return state


def test_keypair_matches_wg_reference_vector():
    private = "GHuMwljFfqd2a7cs6BaUOmHflK23zME8VNvC5B37S3k="
    public = "aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10="
    assert wireguard.public_key(private) == public
    assert wireguard.key_valid(private)
    assert not wireguard.key_valid("not-a-key")


def test_allocate_address_reuses_freed_slot():
    state = _state()
    a = wireguard.add_peer(state, "a")
    b = wireguard.add_peer(state, "b")
    c = wireguard.add_peer(state, "c")
    assert [p["address"] for p in (a, b, c)] == ["10.66.66.2", "10.66.66.3", "10.66.66.4"]
    wireguard.remove_peer(state, b["id"])
    d = wireguard.add_peer(state, "d")
    assert d["address"] == "10.66.66.3"


def test_server_and_client_configs(home):
    state = _state()
    peer = wireguard.add_peer(state, "iPhone", "0.0.0.0/0", 30)
    wireguard.generate(state)
    client = wireguard.client_config(state, peer)
    assert "[Interface]" in client and "[Peer]" in client
    assert f"PrivateKey = {peer['private_key']}" in client
    assert f"PresharedKey = {peer['preshared_key']}" in client
    assert f"PublicKey = {state['wireguard']['server_public_key']}" in client
    assert "Address = 10.66.66.2/32" in client
    assert "Endpoint = proxy.example.com:51820" in client
    assert "AllowedIPs = 0.0.0.0/0" in client
    assert "PersistentKeepalive = 25" in client

    server = wireguard.server_config(state)
    assert "Address = 10.66.66.1/24" in server
    assert f"PrivateKey = {state['wireguard']['server_private_key']}" in server
    assert "AllowedIPs = 10.66.66.2/32" in server
    assert "AllowedIPs = 0.0.0.0/0" not in server
    runtime = wireguard.server_config(state, runtime=True)
    assert "Address =" not in runtime and "PostUp" not in runtime
    assert "ListenPort = 51820" in runtime


def test_disabled_and_expired_peers_are_removed_from_server_config():
    state = _state()
    live = wireguard.add_peer(state, "live")
    off = wireguard.add_peer(state, "off")
    old = wireguard.add_peer(state, "old")
    off["enabled"] = False
    old["expires_at"] = 1
    server = wireguard.server_config(state)
    assert live["public_key"] in server
    assert off["public_key"] not in server
    assert old["public_key"] not in server
    assert wireguard.reap_expired(state) is True
    assert old["enabled"] is False


def test_gl_inet_compat_omits_psk_mtu_and_extra_dns(home):
    state = _state()
    peer = wireguard.add_peer(state, "GL-iNet", "0.0.0.0/0, ::/0", compat=True)
    wireguard.generate(state)
    client = wireguard.client_config(state, peer)
    assert "PresharedKey" not in client
    assert "MTU" not in client
    assert "DNS = 1.1.1.1" in client and "8.8.8.8" not in client
    assert "Endpoint = proxy.example.com:51820" in client
    assert "AllowedIPs = 0.0.0.0/0" in client and "::/0" not in client
    server = wireguard.server_config(state)
    assert peer["public_key"] in server
    assert "PresharedKey" not in server


def test_optional_ipv6_tunnel(home):
    state = _state()
    wireguard.bucket(state)["ipv6"] = True
    peer = wireguard.add_peer(state, "phone")
    assert peer["address6"] == "fd66:66:66::2"
    wireguard.generate(state)
    client = wireguard.client_config(state, peer)
    assert "Address = 10.66.66.2/32, fd66:66:66::2/128" in client
    server = wireguard.server_config(state)
    assert "Address = 10.66.66.1/24, fd66:66:66::1/64" in server
    assert "AllowedIPs = 10.66.66.2/32, fd66:66:66::2/128" in server
    assert "ip6tables" in wireguard.firewall_script(state)


def test_generated_files_have_safe_permissions(client, configured, home):
    from zeroproxy import apply

    state = config.load_state()
    peer = wireguard.add_peer(state, "phone")
    apply.gen_wireguard(state)
    config.save_state(state)

    wg_conf = home / "wireguard" / "wg0.conf"
    firewall = home / "wireguard" / "firewall.sh"
    assert wg_conf.is_file() and firewall.is_file()
    assert oct(wg_conf.stat().st_mode)[-3:] == "600"
    assert oct(firewall.stat().st_mode)[-3:] == "700"
    text = firewall.read_text()
    assert "iptables" in text and "nft" in text
    assert "MASQUERADE" in text and "10.66.66.0/24" in text
    assert peer["public_key"] in wg_conf.read_text()
    up = home / "wireguard" / "userspace-up.sh"
    down = home / "wireguard" / "userspace-down.sh"
    assert up.is_file() and down.is_file()
    assert oct(up.stat().st_mode)[-3:] == "700"
    assert "wg setconf" in up.read_text()


def test_runtime_mode_falls_back_to_userspace(monkeypatch):
    state = _state()
    wireguard.bucket(state)["mode"] = "auto"
    monkeypatch.setattr(wireguard, "tools_available", lambda: True)
    monkeypatch.setattr(wireguard, "kernel_probe", lambda: (False, "Operation not permitted"))
    monkeypatch.setattr(wireguard, "userspace_available", lambda: True)
    mode, detail = wireguard.runtime_mode(state)
    assert mode == "userspace" and "wireguard-go" in detail

    monkeypatch.setattr(wireguard, "userspace_available", lambda: False)
    mode, detail = wireguard.runtime_mode(state)
    assert mode == "none"
    assert "内核不支持" in detail and "TUN" in detail


def test_forced_modes(monkeypatch):
    state = _state()
    wireguard.bucket(state)["mode"] = "kernel"
    monkeypatch.setattr(wireguard, "tools_available", lambda: True)
    monkeypatch.setattr(wireguard, "kernel_probe", lambda: (False, "Protocol not supported"))
    mode, detail = wireguard.runtime_mode(state)
    assert mode == "none" and "强制内核" in detail

    wireguard.bucket(state)["mode"] = "userspace"
    monkeypatch.setattr(wireguard, "userspace_available", lambda: True)
    assert wireguard.runtime_mode(state)[0] == "userspace"


def test_mode_setting_is_validated(client, configured):
    bad = client.post("/api/wireguard/settings", json={"mode": "magic"})
    assert bad.status_code == 400
    ok = client.post("/api/wireguard/settings", json={"enabled": True, "mode": "userspace"})
    assert ok.status_code == 200
    assert ok.json()["wireguard"]["mode"] == "userspace"


def test_sync_selects_userspace_unit(home, monkeypatch):
    from zeroproxy import services

    state = _state()
    wg = wireguard.bucket(state)
    wg["enabled"] = True
    wg["mode"] = "auto"
    wireguard.add_peer(state, "phone")
    calls: list[list[str]] = []
    started = {"ok": False}

    monkeypatch.setattr(services, "is_prod", lambda: True)
    monkeypatch.setattr(wireguard, "ensure_tools", lambda timeout=180: (True, "ok"))
    monkeypatch.setattr(wireguard, "active_service", lambda: "")
    monkeypatch.setattr(wireguard, "runtime_mode", lambda s: ("userspace", "fallback"))
    monkeypatch.setattr(wireguard, "userspace_available", lambda: True)
    monkeypatch.setattr(wireguard, "service_state", lambda name="x": "inactive")
    monkeypatch.setattr(wireguard, "interface_exists", lambda: started["ok"])

    def fake_run(cmd, timeout=120, env=None):
        calls.append(list(cmd))
        if cmd[:2] == ["systemctl", "start"] and cmd[2] == wireguard.SERVICE_USERSPACE:
            started["ok"] = True
        return True, ""

    monkeypatch.setattr(services, "run", fake_run)
    ok, detail = wireguard.sync(state)
    assert ok is True, detail
    assert any(c[:3] == ["systemctl", "start", wireguard.SERVICE_USERSPACE] for c in calls)
    assert any(c[:3] == ["systemctl", "enable", wireguard.SERVICE_USERSPACE] for c in calls)
    assert wg["active_mode"] == "userspace"


def test_sync_failure_surfaces_journal(home, monkeypatch):
    from zeroproxy import services

    state = _state()
    wg = wireguard.bucket(state)
    wg["enabled"] = True
    wg["mode"] = "kernel"
    monkeypatch.setattr(services, "is_prod", lambda: True)
    monkeypatch.setattr(wireguard, "ensure_tools", lambda timeout=180: (True, "ok"))
    monkeypatch.setattr(wireguard, "active_service", lambda: "")
    monkeypatch.setattr(wireguard, "runtime_mode", lambda s: ("kernel", ""))
    monkeypatch.setattr(wireguard, "service_state", lambda name="x": "inactive")
    monkeypatch.setattr(wireguard, "interface_exists", lambda: False)
    monkeypatch.setattr(wireguard, "journal_tail", lambda name="x", lines=20: "protocol not supported")

    def fake_run(cmd, timeout=120, env=None):
        if cmd[:2] == ["systemctl", "start"]:
            return False, "Job for zeroproxy-wg.service failed"
        return True, ""

    monkeypatch.setattr(services, "run", fake_run)
    ok, detail = wireguard.sync(state)
    assert ok is False
    assert "Job for" in detail and "protocol not supported" in detail


def test_api_lifecycle_and_one_time_link(client, configured):
    body = client.post("/api/wireguard/settings", json={"enabled": True}).json()
    assert body["wireguard"]["enabled"] is True

    body = client.post(
        "/api/wireguard/peers",
        json={"name": "iPhone", "allowed_ips": "0.0.0.0/0", "expires_days": 30},
    ).json()
    peer_id = body["peer_id"]
    peer = next(p for p in body["wireguard"]["peers"] if p["id"] == peer_id)
    assert peer["name"] == "iPhone" and peer["address"] == "10.66.66.2"
    assert "PrivateKey" in body["config"]

    got = client.get(f"/api/wireguard/peers/{peer_id}/config")
    assert got.status_code == 200 and got.text == body["config"]
    assert got.headers["content-disposition"].startswith("attachment")

    qr = client.get(f"/api/wireguard/peers/{peer_id}/qr?img=svg")
    assert qr.status_code == 200 and qr.headers["content-type"].startswith("image/svg+xml")

    link = client.post(f"/api/wireguard/peers/{peer_id}/link").json()
    path = urlsplit(link["url"]).path
    first = client.get(path)
    assert first.status_code == 200 and "PrivateKey" in first.text
    assert client.get(path).status_code == 404

    renamed = client.post(f"/api/wireguard/peers/{peer_id}", json={"name": "iPhone 15"}).json()
    assert renamed["wireguard"]["peers"][0]["name"] == "iPhone 15"

    rotated = client.post(f"/api/wireguard/peers/{peer_id}/rotate").json()
    assert rotated["config"] != body["config"]
    assert "PrivateKey" in rotated["config"]

    removed = client.delete(f"/api/wireguard/peers/{peer_id}").json()
    assert removed["wireguard"]["peer_count"] == 0


def test_dashboard_never_contains_private_keys(client, configured):
    client.post("/api/wireguard/settings", json={"enabled": True})
    body = client.post("/api/wireguard/peers", json={"name": "secret-holder"}).json()
    state = config.load_state()
    peer = wireguard.peers(state)[0]

    dashboard = json.dumps(client.get("/api/dashboard").json(), ensure_ascii=False)
    assert peer["private_key"] not in dashboard
    assert peer["preshared_key"] not in dashboard
    assert state["wireguard"]["server_private_key"] not in dashboard
    assert peer["public_key"] in dashboard
    assert body["peer_id"] == peer["id"]


def test_settings_validation_and_locked_subnet(client, configured):
    state = config.load_state()
    hy_port = state["ports"]["hysteria"]
    assert client.post("/api/wireguard/settings", json={"port": hy_port}).status_code == 400
    assert client.post("/api/wireguard/settings", json={"mtu": 1200}).status_code == 400
    assert client.post("/api/wireguard/settings", json={"dns": "not-an-ip"}).status_code == 400
    assert client.post("/api/wireguard/settings", json={"endpoint": "http://x"}).status_code == 400
    assert client.post(
        "/api/wireguard/settings", json={"subnet": "10.10.0.0/24"}
    ).status_code == 200

    client.post("/api/wireguard/settings", json={"enabled": True})
    client.post("/api/wireguard/peers", json={"name": "phone"})
    locked = client.post("/api/wireguard/settings", json={"subnet": "10.20.0.0/24"})
    assert locked.status_code == 400
    assert "不能改隧道网段" in locked.json()["error"]


def test_peer_patch_rejects_bad_allowed_ips(client, configured):
    client.post("/api/wireguard/settings", json={"enabled": True})
    body = client.post("/api/wireguard/peers", json={"name": "phone"}).json()
    peer_id = body["peer_id"]
    bad = client.post(
        f"/api/wireguard/peers/{peer_id}", json={"allowed_ips": "definitely-not-cidr"}
    )
    assert bad.status_code == 400


def test_peer_compat_toggle_updates_both_sides(client, configured):
    client.post("/api/wireguard/settings", json={"enabled": True})
    body = client.post("/api/wireguard/peers", json={"name": "router"}).json()
    peer_id = body["peer_id"]
    assert "PresharedKey" in body["config"]
    changed = client.post(
        f"/api/wireguard/peers/{peer_id}", json={"compat": True}
    ).json()
    assert changed["wireguard"]["peers"][0]["compat"] is True
    assert "PresharedKey" not in changed["config"]
    server = wireguard.server_config(config.load_state())
    assert "PresharedKey" not in server


def test_toggling_ipv6_realigns_full_tunnel_allowed_ips(client, configured):
    client.post("/api/wireguard/settings", json={"enabled": True})
    body = client.post("/api/wireguard/peers", json={"name": "phone"}).json()
    assert body["wireguard"]["peers"][0]["allowed_ips"] == "0.0.0.0/0"
    on = client.post("/api/wireguard/settings", json={"ipv6": True}).json()
    peer = on["wireguard"]["peers"][0]
    assert peer["address6"].startswith("fd66:66:66::")
    assert peer["allowed_ips"] == "0.0.0.0/0, ::/0"
    off = client.post("/api/wireguard/settings", json={"ipv6": False}).json()
    assert off["wireguard"]["peers"][0]["allowed_ips"] == "0.0.0.0/0"


# ---------------------------------------------------------------- 并发: sync 在锁外

def _lock_is_free() -> bool:
    """当前线程能不能立刻拿到 config 锁 (RLock 同线程可重入, 必须开新线程试)。"""
    import threading

    result: list[bool] = []

    def probe() -> None:
        acquired = config.LOCK.acquire(blocking=False)
        result.append(acquired)
        if acquired:
            config.LOCK.release()

    thread = threading.Thread(target=probe)
    thread.start()
    thread.join(timeout=2)
    return bool(result and result[0])


def test_wireguard_sync_runs_outside_the_config_lock(client, configured, monkeypatch):
    """sync() 内部的 apt/systemctl 等 90-180s, 不能持着全局锁跑 (P2-2)。"""
    seen: dict = {}

    def fake_sync(state, timeout=90):
        seen["lock_free"] = _lock_is_free()
        return True, "stub sync"

    monkeypatch.setattr(wireguard, "sync", fake_sync)
    res = client.post("/api/wireguard/settings", json={"enabled": True})
    assert res.status_code == 200, res.text
    assert res.json()["wireguard"]["enabled"] is True
    assert seen.get("lock_free") is True, "wireguard.sync 仍在 config 锁内执行"


def test_wireguard_sync_failure_rolls_state_back_and_audits(client, configured, monkeypatch):
    """落盘失败 → 期望状态回滚 (面板不能显示"改好了"而设备面没变) + 写审计。"""
    monkeypatch.setattr(wireguard, "sync", lambda state, timeout=90: (False, "wg0 起不来"))
    res = client.post("/api/wireguard/settings", json={"enabled": True})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["wireguard"]["enabled"] is False, "失败的改动必须回滚"
    assert body["steps"][0]["ok"] is False
    assert body["steps"][0].get("rolled_back") is True

    state = config.load_state()
    assert state["wireguard"]["enabled"] is False
    failed = [e for e in state["audit"] if e["action"] == "wireguard_settings"]
    assert failed and "失败已回滚" in failed[-1]["detail"]


def test_peer_add_failure_rolls_back_the_peer_list(client, configured, monkeypatch):
    monkeypatch.setattr(wireguard, "sync", lambda state, timeout=90: (True, "ok"))
    client.post("/api/wireguard/settings", json={"enabled": True})
    assert len(wireguard.peers(config.load_state())) == 0

    monkeypatch.setattr(wireguard, "sync", lambda state, timeout=90: (False, "syncconf 失败"))
    res = client.post("/api/wireguard/peers", json={"name": "iPhone"})
    assert res.status_code == 200
    assert res.json()["wireguard"]["peer_count"] == 0, "新增失败要把 peer 回滚掉"


# ---------------------------------------------------------------- AmneziaWG 混淆与抗 DPI 测试

def test_awg_params_generation_and_validation():
    params = wireguard.generate_awg_params()
    assert params["awg_enabled"] is True
    assert 3 <= params["awg_jc"] <= 6
    assert params["awg_jmin"] <= params["awg_jmax"]
    assert 20 <= params["awg_s1"] <= 80
    assert 40 <= params["awg_s2"] <= 100
    headers = [params["awg_h1"], params["awg_h2"], params["awg_h3"], params["awg_h4"]]
    assert len(set(headers)) == 4, "H1~H4 必须互不相同"
    assert all(100_000 <= h <= 2_147_483_647 for h in headers)

    state = _state()
    wireguard.bucket(state)["awg_enabled"] = True
    wireguard.ensure_awg_params(state)
    wg = wireguard.bucket(state)
    assert wg["awg_h1"] > 0 and wg["awg_h2"] > 0 and wg["awg_h3"] > 0 and wg["awg_h4"] > 0


def test_awg_server_and_client_configs(home):
    state = _state()
    wireguard.bucket(state)["awg_enabled"] = True
    wireguard.ensure_awg_params(state)
    wg = wireguard.bucket(state)
    peer = wireguard.add_peer(state, "MacBook")
    compat_peer = wireguard.add_peer(state, "Router", compat=True)
    wireguard.generate(state)

    # 服务端配置包含 AWG 混淆字段
    server = wireguard.server_config(state)
    assert f"Jc = {wg['awg_jc']}" in server
    assert f"H1 = {wg['awg_h1']}" in server
    assert f"H4 = {wg['awg_h4']}" in server

    # 客户端配置: 默认 (awg=None) 应该包含 AWG 参数
    client_awg = wireguard.client_config(state, peer)
    assert f"Jc = {wg['awg_jc']}" in client_awg
    assert f"H1 = {wg['awg_h1']}" in client_awg
    assert f"H4 = {wg['awg_h4']}" in client_awg

    # 强制标准模式 (awg=False): 不应包含 AWG 参数 (给官方 WireGuard App)
    client_std = wireguard.client_config(state, peer, awg=False)
    assert "Jc =" not in client_std
    assert "H1 =" not in client_std

    # 路由器兼容模式设备: 即使开启 AWG 也自动降级为标准模式
    client_compat = wireguard.client_config(state, compat_peer)
    assert "Jc =" not in client_compat
    assert "H1 =" not in client_compat

    # 脚本生成测试
    start_sh = home / "wireguard" / "start.sh"
    stop_sh = home / "wireguard" / "stop.sh"
    assert start_sh.is_file() and stop_sh.is_file()
    assert oct(start_sh.stat().st_mode)[-3:] == "700"
    assert "awg-quick" in start_sh.read_text()


def test_awg_api_settings_and_peer_export(client, configured):
    # 开启 AmneziaWG
    res = client.post("/api/wireguard/settings", json={"enabled": True, "awg_enabled": True})
    assert res.status_code == 200, res.text
    awg_data = res.json()["wireguard"]["awg"]
    assert awg_data["enabled"] is True
    assert awg_data["h1"] > 0
    h1_orig = awg_data["h1"]

    # 重新随机混淆参数 (reseed)
    reseed = client.post("/api/wireguard/settings", json={"awg_regenerate": True})
    assert reseed.status_code == 200
    assert reseed.json()["wireguard"]["awg"]["h1"] != h1_orig

    # 添加 peer
    peer_body = client.post("/api/wireguard/peers", json={"name": "iPad"}).json()
    peer_id = peer_body["peer_id"]

    # 下载配置: 默认带 awg
    conf_awg = client.get(f"/api/wireguard/peers/{peer_id}/config")
    assert conf_awg.status_code == 200
    assert 'filename="zeroproxy-awg-' in conf_awg.headers.get("content-disposition", "")
    assert "H1 =" in conf_awg.text

    # 下载配置: 指定标准格式 (awg=0)
    conf_std = client.get(f"/api/wireguard/peers/{peer_id}/config?awg=0")
    assert conf_std.status_code == 200
    assert 'filename="zeroproxy-wg-' in conf_std.headers.get("content-disposition", "")
    assert "H1 =" not in conf_std.text

