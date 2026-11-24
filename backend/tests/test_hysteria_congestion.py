from pathlib import Path

import pytest
import yaml

from zeroproxy import config, hysteria_config, services


@pytest.mark.parametrize("mode", hysteria_config.BBR_PROFILES)
def test_bbr_settings_are_guarded_and_rollback_restores_generated_config(client, configured, mode):
    conf = Path(config.paths()["hysteria_config"])
    original = conf.read_text()
    assert "congestion" not in yaml.safe_load(original)
    initial = client.get("/api/dashboard").json()
    response = client.post("/api/settings", json={"hysteria_congestion": mode})
    assert response.status_code == 200, response.text
    applied = response.json()
    assert applied["pending_change"]["state"] == "awaiting_confirmation"
    assert applied["hysteria_congestion"] == mode
    assert applied["configuration_revision"] != initial["configuration_revision"]
    assert applied["subscription_formats"] == initial["subscription_formats"]
    config_data = yaml.safe_load(conf.read_text())
    assert config_data["congestion"] == {"type": "bbr", "bbrProfile": mode}
    assert config_data["ignoreClientBandwidth"] is True
    rollback = client.post(f'/api/changes/{applied["pending_change"]["id"]}/rollback')
    assert rollback.status_code == 200, rollback.text
    assert rollback.json()["hysteria_congestion"] == "negotiated"
    assert conf.read_text() == original


@pytest.mark.parametrize("version", ["", "v2.7.9", "v2.8.0-beta.1"])
def test_unsupported_core_rejects_bbr_before_mutating_state(client, configured, monkeypatch, version):
    monkeypatch.setattr(services, "is_prod", lambda: True)
    monkeypatch.setattr(services, "service_version", lambda _: version)
    response = client.post("/api/settings", json={"hysteria_congestion": "standard"})
    assert response.status_code == 400
    assert "2.8.0" in response.json()["error"]
    assert config.load_state()["hysteria_congestion"] == "negotiated"


def test_invalid_bbr_mode_is_rejected(client, configured):
    response = client.post("/api/settings", json={"hysteria_congestion": "invalid"})
    assert response.status_code == 400
    assert config.load_state()["hysteria_congestion"] == "negotiated"


def test_legacy_state_keeps_client_bandwidth_negotiation():
    assert config.state_from({})["hysteria_congestion"] == "negotiated"
    assert not hysteria_config.congestion_error("negotiated", "")
    assert not hysteria_config.congestion_error("standard", "v2.8.0")
    assert not hysteria_config.congestion_error("conservative", "v2.14.0")
