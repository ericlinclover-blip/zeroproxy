"""The connection field checks one route and preserves evidence boundaries."""
from zeroproxy import config, routes, services


def test_field_check_only_starts_selected_client(client, configured, monkeypatch):
    calls = []
    def check(state, node):
        calls.append(node)
        return {"node": node, "ok": True, "kind": "deep", "ms": 12, "detail": "round trip"}
    monkeypatch.setattr(services, "deep_probe_node", check)
    monkeypatch.setattr(services, "probe_all", lambda *a, **k: (_ for _ in ()).throw(AssertionError("all routes")))
    for node in ("vless-reality", "trojan"):
        body = client.get(f"/api/probe?deep=1&node={node}&force=1").json()
        assert body["scope"] == node
        assert [p["node"] for p in body["nodes"]] == [node]
        assert body["checked_at"] and body["chain_revision"]
    assert calls == ["vless-reality", "trojan"]


def test_field_check_rejects_unknown_node_and_requires_login(client, configured, monkeypatch):
    monkeypatch.setattr(services, "probe_node", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not run")))
    assert client.get("/api/probe?node=missing").status_code == 404
    client.cookies.clear()
    assert client.get("/api/probe?node=vless-reality").status_code == 401


def test_field_udp_check_does_not_claim_deep_proof(client, configured, monkeypatch):
    monkeypatch.setattr(services, "probe_node", lambda state, node: {"node": node, "kind": "udp", "ok": True, "ms": None})
    monkeypatch.setattr(services, "deep_probe_node", lambda *a: (_ for _ in ()).throw(AssertionError("unsupported")))
    body = client.get("/api/probe?node=hysteria2&deep=1&force=1").json()
    assert body["nodes"][0]["kind"] == "udp"


def test_field_missing_core_remains_unknown(client, configured, monkeypatch):
    monkeypatch.setattr(services, "bin_path", lambda name: None)
    body = client.get("/api/probe?node=vless-reality&deep=1&force=1").json()
    assert body["nodes"][0]["ok"] is None
    assert "不可用" in body["nodes"][0]["detail"]


def test_field_drops_result_when_config_changes_during_probe(client, configured, monkeypatch):
    def check(state, node):
        with config.locked():
            current = config.load_state()
            current["ports"]["reality"] += 1
            config.save_state(current)
        return {"node": node, "ok": True, "kind": "deep"}
    monkeypatch.setattr(services, "deep_probe_node", check)
    response = client.get("/api/probe?node=vless-reality&deep=1&force=1")
    assert response.status_code == 409
    assert "配置已变化" in response.json()["error"]


def test_field_cache_does_not_cross_credentials_changed_in_same_second(client, configured, monkeypatch):
    calls = []
    monkeypatch.setattr(services, "deep_probe_node", lambda state, node: calls.append(node) or {"node":node,"ok":True,"kind":"deep"})
    routes._PROBE_CACHE.clear()
    assert client.get("/api/probe?node=vless-reality&deep=1").status_code == 200
    with config.locked():
        state = config.load_state()
        state["uuid"] = "11111111-1111-1111-1111-111111111111"
        config.save_state(state)
    assert client.get("/api/probe?node=vless-reality&deep=1").status_code == 200
    assert len(calls) == 2
