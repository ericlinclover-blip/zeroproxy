import pytest

from zeroproxy import share_links as links


def preview(client, *targets, **options):
    response = client.post("/api/routing/preview", json={"targets": targets, **options})
    assert response.status_code == 200, response.text
    return response.json()


def test_batch_preview_keeps_the_saved_template_and_reports_unknown_rules(client, configured):
    initial = client.get("/api/dashboard").json()
    result = preview(client, "ChatGPT.com", "192.168.1.9", "bad domain", tpl="direct")
    ai, local, invalid = result["rows"]
    assert (result["current"], result["candidate"]) == ("smart", "direct")
    assert ai["current"]["group"] == links.G_AI
    assert ai["current"]["certainty"] == "estimated"
    assert "GEOSITE,category-ads-all" in ai["current"]["unresolved_rules"]
    assert ai["candidate"]["action"] == "direct"
    assert ai["candidate"]["matched_rule"] == "MATCH"
    assert local["current"]["action"] == "direct"
    assert invalid["error"]
    after = client.get("/api/dashboard").json()
    assert after["settings_revision"] == initial["settings_revision"]
    assert after["routing"]["template"] == "smart"


def test_router_management_rule_and_geo_degradation_follow_selected_scope(client, configured):
    host = configured["domain"]
    standard = preview(client, host, "chatgpt.com", scope="clash")["rows"]
    router = preview(client, host, "chatgpt.com", scope="router-lite")["rows"]
    assert standard[0]["current"]["group"] != "DIRECT"
    assert router[0]["current"]["group"] == "DIRECT"
    assert router[0]["current"]["rule_index"] == 1
    assert router[0]["current"]["reason"] == "路由器面板管理地址直连"
    assert router[1]["current"]["group"] == standard[1]["current"]["group"]
    assert router[1]["current"]["certainty"] == "rule"


def test_singbox_preview_uses_generated_order_for_block_and_local_rules(client, configured):
    response = client.post("/api/settings", json={"custom_rules": {"block": ["2001:db8::/32"]}})
    assert response.status_code == 200
    result = preview(client, "2001:db8::5", "192.168.1.9", "chatgpt.com", scope="singbox")["rows"]
    assert [row["current"]["backend"] for row in result] == ["sing-box"] * 3
    assert result[0]["current"]["action"] == "reject"
    assert result[0]["current"]["matched_rule"] == "ip_cidr:2001:db8::/32"
    assert result[1]["current"]["action"] == "direct"
    assert result[1]["current"]["matched_rule"] == "ip_is_private"
    assert result[2]["current"]["group"] == links.G_AI
    assert "rule-set:ads" in result[2]["current"]["unresolved_rules"]


@pytest.mark.parametrize("payload", [
    {"targets": ["example.com"] * 13},
    {"targets": ["example.com"], "tpl": "unknown"},
    {"targets": ["example.com"], "scope": "unknown"},
])
def test_rejects_invalid_batch_options(client, configured, payload):
    assert client.post("/api/routing/preview", json=payload).status_code == 400


def test_preview_requires_sign_in(client):
    assert client.post("/api/routing/preview", json={"targets": ["example.com"]}).status_code == 401


def test_basic_protection_and_allowlist_preserve_the_geo_data_preference(client, configured):
    from zeroproxy import config

    initial = config.load_state()["geodata"]
    response = client.post("/api/settings", json={
        "block_tracking": not initial["block_tracking"], "ad_allowlist": ["ads.example.com"],
    })
    assert response.status_code == 200
    updated = config.load_state()["geodata"]
    assert updated["enabled"] == initial["enabled"]
    assert updated.get("user_set") == initial.get("user_set")
    assert updated["ad_allowlist"] == ["ads.example.com"]
