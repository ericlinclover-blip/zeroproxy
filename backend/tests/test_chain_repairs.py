"""Regression cases from the chain review, including overlapping operations."""
import copy

import pytest

from zeroproxy import chain, chain_quic, config, routes, xray_config
from test_chain import _fake_code, _ok_probe, _bad_probe, _v3_code


def test_remote_and_local_certificates_are_independent(client, configured, monkeypatch):
    monkeypatch.setattr(chain_quic, "binary", lambda: "/fake/hysteria")
    monkeypatch.setattr(chain, "probe_target", _ok_probe())
    response = client.post("/api/chain/entries", json={"code": _v3_code(config.load_state()), "transport": "hysteria2"})
    assert response.status_code == 200
    state = config.load_state()
    state["chain"]["exit"].update(enabled=True, hy_enabled=True)
    monkeypatch.setattr(routes, "_chain_exit_pin", lambda state: "cd" * 32)
    monkeypatch.setattr(chain, "exit_code", lambda state: "")
    view = routes._chain_view(state)
    assert view["entries"][0]["pin_ok"] and not view["entries"][0]["needs_repair"]
    assert not view["pin_mismatch"]


@pytest.mark.parametrize("flow", ["", "xtls-rprx-vision"])
def test_probe_and_runtime_use_identical_outbound(configured, flow):
    target = chain.parse_code(_fake_code(config.load_state(), flow=flow))
    entry = {**target, "id": "probe"}
    expected = xray_config.chain_entry_outbound(entry)
    expected["tag"] = "chain-out"
    assert chain.client_config(target, 10001)["outbounds"][0] == expected
    assert chain.client_config(chain.as_target(entry), 10001)["outbounds"][0] == expected
    assert chain.as_target({**entry, "flow": ""})["flow"] == ""


def test_overlapping_adds_recheck_duplicate_target(client, configured, monkeypatch):
    code = _fake_code(config.load_state())
    entered = False
    nested = []
    def probe(target, timeout=10, state=None):
        nonlocal entered
        if not entered:
            entered = True
            nested.append(client.post("/api/chain/entries", json={"code": code}).status_code)
        return _ok_probe()(target)
    monkeypatch.setattr(chain, "probe_target", probe)
    response = client.post("/api/chain/entries", json={"code": code})
    assert nested == [200] and response.status_code == 409
    assert len(config.load_state()["chain"]["entries"]) == 1


def test_overlapping_quic_adds_recheck_reserved_socks_ports(client, configured, monkeypatch):
    monkeypatch.setattr(chain_quic, "binary", lambda: "/fake/hysteria")
    monkeypatch.setattr(chain.services, "port_available", lambda *args: True)
    entered = False
    def probe(target, timeout=10, state=None):
        nonlocal entered
        if not entered:
            entered = True
            response = client.post("/api/chain/entries", json={"code": _v3_code(config.load_state(), host="second.example.com"), "transport": "hysteria2"})
            assert response.status_code == 200
        return _ok_probe()(target)
    monkeypatch.setattr(chain, "probe_target", probe)
    response = client.post("/api/chain/entries", json={"code": _v3_code(config.load_state(), host="first.example.com"), "transport": "hysteria2"})
    assert response.status_code == 200
    rows = config.load_state()["chain"]["entries"]
    assert len({e["hy_socks_port"] for e in rows}) == 2
    assert not ({e["hy_socks_port"] for e in rows} & {e["local_port"] for e in rows})


def test_port_allocators_share_reservations(configured, monkeypatch):
    state = config.load_state()
    base = chain_quic.SOCKS_PORT_BASE
    state["chain"]["entries"] = [{"id": "a", "local_port": base, "hy_socks_port": base + 1}]
    monkeypatch.setattr(chain.services, "port_available", lambda *args: True)
    assert chain_quic.pick_socks_port(state) == base + 2
    with pytest.raises(ValueError):
        chain.pick_port(state, base + 1)
    assert chain_quic.pick_socks_port(state, reserved={base + 2}) == base + 3


def test_explicit_port_is_not_silently_reassigned(client, configured, monkeypatch):
    def probe(target, timeout=10, state=None):
        state = config.load_state()
        state["chain"]["entries"].append({"id": "reserved", "local_port": 19001})
        config.save_state(state)
        return _ok_probe()(target)
    monkeypatch.setattr(chain, "probe_target", probe)
    response = client.post("/api/chain/entries", json={"code": _fake_code(config.load_state()), "local_port": 19001})
    assert response.status_code == 409
    assert len(config.load_state()["chain"]["entries"]) == 1


@pytest.mark.parametrize("value,expected", [("999.999.999.999", ""), ("error upstream 1.2.3.4", ""), ("2001:db8::1\n", "2001:db8::1"), ("203.0.113.9\n", "203.0.113.9")])
def test_exit_echo_requires_a_complete_valid_ip(monkeypatch, value, expected):
    monkeypatch.setattr(chain.services, "socks5_http_get", lambda *args: (value, "HTTP 往返成功"))
    assert chain.read_exit_ip(12345)[0] == expected


def add_pair(client, monkeypatch, **payload):
    monkeypatch.setattr(chain, "probe_target", _ok_probe())
    monkeypatch.setattr(chain_quic, "binary", lambda: "/fake/hysteria")
    response = client.post("/api/chain/entries", json={"code": _v3_code(config.load_state()), **payload})
    assert response.status_code == 200
    return response.json()["chain"]["entries"][-1]


def test_transport_changes_invalidate_proof(client, configured, monkeypatch):
    entry = add_pair(client, monkeypatch)
    assert entry["probe_current"] is True
    response = client.post(f"/api/chain/entries/{entry['id']}", json={"transport": "hysteria2"})
    after = response.json()["chain"]["entries"][-1]
    assert after["last_probe"] == {} and after["probe_current"] is False


def test_late_probe_cannot_overwrite_new_configuration(client, configured, monkeypatch):
    entry = add_pair(client, monkeypatch)
    def changed(target, timeout=10, state=None):
        response = client.post(f"/api/chain/entries/{entry['id']}", json={"transport": "hysteria2"})
        assert response.status_code == 200
        return _ok_probe()(target)
    monkeypatch.setattr(chain, "probe_target", changed)
    response = client.post(f"/api/chain/entries/{entry['id']}/probe")
    assert response.status_code == 409
    assert config.load_state()["chain"]["entries"][-1]["last_probe"] == {}


def test_pair_update_preserves_node_identity_and_settings(client, configured, monkeypatch):
    entry = add_pair(client, monkeypatch, transport="hysteria2", default_out=True, label="Keep me", local_port=19005)
    before = copy.deepcopy(config.load_state()["chain"]["entries"][-1])
    code = _v3_code(config.load_state(), pin="cd" * 32, host="new.example.com")
    response = client.post(f"/api/chain/entries/{entry['id']}/pair", json={"code": code})
    assert response.status_code == 200, response.text
    after = config.load_state()["chain"]["entries"][-1]
    for key in ("id", "local_port", "label", "enabled", "default_out", "created_at", "hy_socks_port"):
        assert after[key] == before[key]
    assert after["host"] == "new.example.com" and after["hy_cert_sha256"] == "cd" * 32
    assert response.json()["chain"]["entries"][-1]["probe_current"] is True


def test_pair_failure_preserves_credentials(client, configured, monkeypatch):
    entry = add_pair(client, monkeypatch)
    before = copy.deepcopy(config.load_state()["chain"]["entries"])
    monkeypatch.setattr(chain, "probe_target", _bad_probe())
    response = client.post(f"/api/chain/entries/{entry['id']}/pair", json={"code": _v3_code(config.load_state(), host="new.example.com")})
    assert response.status_code == 400
    assert config.load_state()["chain"]["entries"] == before


def test_pair_update_refuses_stale_snapshot(client, configured, monkeypatch):
    entry = add_pair(client, monkeypatch)
    def mutate(target, timeout=10, state=None):
        changed = client.post(f"/api/chain/entries/{entry['id']}", json={"transport": "hysteria2"})
        assert changed.status_code == 200
        return _ok_probe()(target)
    monkeypatch.setattr(chain, "probe_target", mutate)
    response = client.post(f"/api/chain/entries/{entry['id']}/pair", json={"code": _v3_code(config.load_state(), host="new.example.com")})
    assert response.status_code == 409
    assert config.load_state()["chain"]["entries"][-1]["host"] == entry["host"]


def test_pair_update_auth_and_validation(client, configured, monkeypatch):
    entry = add_pair(client, monkeypatch, transport="hysteria2")
    path = f"/api/chain/entries/{entry['id']}/pair"
    assert client.post(path, json={"code": "broken"}).status_code == 400
    assert client.post(path, json={"code": _fake_code(config.load_state())}).status_code == 400
    client.post("/api/logout")
    assert client.post(path, json={"code": "broken"}).status_code == 401


@pytest.mark.parametrize("async_mode,raises", [(False, False), (False, True), (True, False), (True, True)])
def test_failed_pair_apply_restores_old_credentials(client, configured, monkeypatch, async_mode, raises):
    import time
    from zeroproxy import apply
    entry = add_pair(client, monkeypatch, label="Keep me", local_port=19007)
    old = copy.deepcopy(config.load_state()["chain"]["entries"][-1])
    real_apply = apply.reapply
    def fail_new(state, *args, **kwargs):
        if state["chain"]["entries"][-1]["host"] == "new.example.com":
            if raises:
                raise RuntimeError("simulated restart failure")
            return [{"name": "重启", "ok": False, "detail": "simulated failure", "ms": 0}]
        return real_apply(state, *args, **kwargs)
    monkeypatch.setattr(apply, "reapply", fail_new)
    monkeypatch.setenv("ZP_APPLY_ASYNC", "1" if async_mode else "0")
    response = client.post(f"/api/chain/entries/{entry['id']}/pair", json={"code": _v3_code(config.load_state(), host="new.example.com")})
    assert response.status_code == 200
    result = response.json()
    if async_mode:
        for _ in range(500):
            result = client.get("/api/apply/job", params={"id": result.get("id") or result["job"]["id"]}).json()
            if result["state"] != "running":
                break
            time.sleep(.01)
        assert result["state"] == "failed"
    assert any(not step["ok"] for step in result["steps"]) or result.get("state") == "failed"
    assert any(step["name"] == "恢复原配对参数" and step["ok"] for step in result["steps"])
    assert config.load_state()["chain"]["entries"][-1] == old


def test_pair_compensation_does_not_overwrite_a_newer_edit(client, configured, monkeypatch):
    from zeroproxy import apply
    entry = add_pair(client, monkeypatch)
    def fail_after_another_edit(state, *args, **kwargs):
        fresh = config.load_state()
        fresh["chain"]["entries"][-1]["host"] = "third.example.com"
        config.save_state(fresh)
        return [{"name": "重启", "ok": False, "detail": "failure", "ms": 0}]
    monkeypatch.setattr(apply, "reapply", fail_after_another_edit)
    response = client.post(f"/api/chain/entries/{entry['id']}/pair", json={"code": _v3_code(config.load_state(), host="new.example.com")})
    assert response.status_code == 200
    assert config.load_state()["chain"]["entries"][-1]["host"] == "third.example.com"
    assert any("未覆盖" in step["detail"] for step in response.json()["steps"])


def test_primary_probe_has_a_chain_configuration_revision(client, configured, monkeypatch):
    entry = add_pair(client, monkeypatch)
    from zeroproxy import services
    before = chain.routing_fingerprint(config.load_state())
    monkeypatch.setattr(services, "tcp_connect_ms", lambda *args: (True, 1, "ok"))
    probe = services.probe_all(config.load_state())
    assert probe["chain_revision"] == before
    client.post(f"/api/chain/entries/{entry['id']}", json={"default_out": True})
    assert chain.routing_fingerprint(config.load_state()) != before


@pytest.mark.parametrize("flow", ["", "xtls-rprx-vision"])
def test_local_warmup_keeps_the_inbound_flow(configured, monkeypatch, flow):
    import json
    target = chain.parse_code(_fake_code(config.load_state(), flow=flow))
    observed = []
    class Proc:
        def terminate(self): pass
        def wait(self, timeout=None): return 0
    def spawn(args, **kwargs):
        with open(args[-1], encoding="utf-8") as fh:
            cfg = json.load(fh)
        observed.append(cfg["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"])
        return Proc()
    monkeypatch.setattr(chain.services, "tcp_connect_ms", lambda *args: (True, 1, "ok"))
    monkeypatch.setattr(chain.subprocess, "Popen", spawn)
    monkeypatch.setattr(chain, "_wait_socks", lambda *args: "")
    monkeypatch.setattr(chain, "read_exit_ip", lambda *args: ("203.0.113.1", "ok"))
    assert chain._warm_one("fake", target, .1)[0] is True
    assert observed == [flow]
