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
    assert "Address = 10.66.66.2/24" in client
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


def test_optional_ipv6_tunnel(home):
    state = _state()
    wireguard.bucket(state)["ipv6"] = True
    peer = wireguard.add_peer(state, "phone")
    assert peer["address6"] == "fd66:66:66::2"
    wireguard.generate(state)
    client = wireguard.client_config(state, peer)
    assert "Address = 10.66.66.2/24, fd66:66:66::2/64" in client
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
