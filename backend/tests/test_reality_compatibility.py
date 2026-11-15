"""Subscription handshake compatibility with the pinned router core."""
import pytest

from zeroproxy import config, share_links


@pytest.mark.parametrize('node', ['vless-reality', 'vless-xhttp', 'chain-hybrid-test'])
def test_mihomo_reality_hybrid_key_share_default_and_legacy_override(configured, node):
    state = config.load_state()
    state.setdefault('chain', {}).setdefault('entries', []).append({
        'id': 'hybrid-test', 'host': '198.51.100.1', 'port': 8447,
        'uuid': state['uuid'], 'local_port': 8446, 'sni': 'exit.example.com',
        'pbk': state['reality']['public_key'], 'sid': state['reality']['short_id'],
        'enabled': True, 'label': 'compatibility test',
    })
    proxy = share_links._clash_proxy(state, node)
    assert proxy['reality-opts'].get('support-x25519mlkem768') is True
    expected_flow = 'xtls-rprx-vision' if node == 'vless-reality' else ''
    assert proxy.get('flow', '') == expected_flow
    state['reality']['support_x25519mlkem768'] = False
    proxy = share_links._clash_proxy(state, node)
    assert proxy['reality-opts']['support-x25519mlkem768'] is False


def test_non_reality_nodes_do_not_receive_reality_options(configured):
    state = config.load_state()
    for node in ['vless-ws', 'trojan', 'hysteria2']:
        assert 'reality-opts' not in share_links._clash_proxy(state, node)


def test_legacy_state_migrates_handshake_option_and_changes_device_revision(configured):
    from zeroproxy import devices

    legacy = config.load_state()
    legacy['reality'].pop('support_x25519mlkem768', None)
    old_rev = devices.config_rev(legacy)
    config.save_state(legacy)
    migrated = config.load_state()
    assert migrated['reality'].get('support_x25519mlkem768') is True
    assert devices.config_rev(migrated) != old_rev
    migrated['reality']['support_x25519mlkem768'] = False
    config.save_state(migrated)
    assert config.load_state()['reality']['support_x25519mlkem768'] is False
