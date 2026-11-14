"""跨请求状态一致性、无数据库防护与规则后端一致性的回归。"""
import copy
import threading

import pytest
import yaml

from zeroproxy import apply, config, dae_config, routes, share_links, wireguard, xray_config


def test_wireguard_concurrent_requests_do_not_overwrite_peers(client, configured, monkeypatch):
    client.post('/api/wireguard/settings', json={'enabled': True})
    entered, release = threading.Event(), threading.Event()
    responses = []

    def slow_sync(state, timeout=90):
        entered.set()
        assert release.wait(5)
        return True, 'synced'

    monkeypatch.setattr(wireguard, 'sync', slow_sync)
    worker = threading.Thread(target=lambda: responses.append(
        client.post('/api/wireguard/peers', json={'name': 'first'})
    ))
    worker.start()
    try:
        assert entered.wait(5)
        second = client.post('/api/wireguard/peers', json={'name': 'second'})
        assert second.status_code == 409, second.text
        assert client.get('/api/status').status_code == 200
    finally:
        release.set()
        worker.join(5)
    assert not worker.is_alive()
    assert responses[0].status_code == 200
    monkeypatch.setattr(wireguard, 'sync', lambda state, timeout=90: (True, 'synced'))
    assert client.post('/api/wireguard/peers', json={'name': 'second'}).status_code == 200
    assert {p['name'] for p in wireguard.peers(config.load_state())} == {'first', 'second'}


def test_wg_reply_never_restores_stale_bucket(client, configured):
    stale = config.load_state()
    fresh = config.load_state()
    fresh['wireguard']['dns'] = '9.9.9.9'
    config.save_state(fresh)
    from starlette.requests import Request
    request = Request({'type': 'http', 'headers': [], 'client': ('127.0.0.1', 1),
                       'scheme': 'http', 'server': ('testserver', 80), 'path': '/'})
    routes._wg_reply(stale, request, [])
    assert config.load_state()['wireguard']['dns'] == '9.9.9.9'


@pytest.mark.parametrize('enabled', [False, True])
def test_xray_basic_protection_survives_missing_geo(home, enabled):
    state = config.load_state()
    state['geodata']['enabled'] = enabled
    rules = xray_config.geo_rules(state)
    private = [r for r in rules if r.get('outboundTag') == 'block' and 'ip' in r]
    assert private and '127.0.0.0/8' in private[0]['ip']
    assert '::1/128' in private[0]['ip']
    assert any('domain:umeng.com' in r.get('domain', []) for r in rules)
    assert 'geoip:' not in str(rules) and 'geosite:' not in str(rules)


def test_basic_protection_change_applies_without_geo(client, configured, monkeypatch):
    calls = []
    monkeypatch.setattr(routes, '_reapply', lambda state, request=None: calls.append(True) or [])
    assert client.post('/api/settings', json={'block_tracking': False}).status_code == 200
    assert calls, '服务端固定域名规则变化必须进入应用流程'


def test_dae_custom_ips_and_precedence(home):
    state = config.load_state()
    state['routing']['custom_rules'].update({
        'block': ['203.0.113.0/24', '2001:db8::/32'],
        'direct': ['2001:db8::1', 'overlap.example'],
        'proxy': ['overlap.example'],
    })
    body, _ = dae_config.render(state, 'https://panel.example', geo=False)
    assert 'dip(203.0.113.0/24) -> block' in body
    assert "dip('2001:db8::/32') -> block" in body
    assert "dip('2001:db8::1/128') -> direct" in body
    assert body.index("domain(suffix: 'overlap.example') -> proxy") < body.index(
        "domain(suffix: 'overlap.example') -> direct")


def test_global_simulation_agrees_with_clash_and_singbox(home):
    state = config.load_state()
    state['routing']['template'] = 'global'
    result = share_links.simulate_match('api.openai.com', state)
    assert result['group'] == share_links.G_AI
    clash = yaml.safe_load(share_links.clash_profile(state, geo=False))
    assert f'DOMAIN-SUFFIX,openai.com,{result["group"]}' in clash['rules']
    import json
    sb = json.loads(share_links.singbox_profile(state))
    assert any('openai.com' in r.get('domain_suffix', []) and r.get('outbound') == result['group']
               for r in sb['route']['rules'])


@pytest.mark.parametrize('raw', ["bad.example') -> direct", 'bad.example,REJECT', 'bad example',
                                 'good.example\nmalicious.example', '999.1.1.1'])
def test_invalid_routing_targets_are_rejected(raw):
    assert share_links.normalize_target(raw) == ''


def test_ipv6_panel_is_an_ip_rule():
    assert share_links.management_direct_rules('https://[2001:db8::1]:8899') == [
        'IP-CIDR6,2001:db8::1/128,DIRECT,no-resolve']


def test_simulator_does_not_invent_geo_matches(home):
    state = config.load_state()
    result = share_links.simulate_match('unlisted-example.cn', state)
    assert result['certainty'] == 'estimated'
    assert result['matched_rule'] != 'GEOSITE,cn'
    result = share_links.simulate_match('admob-unrelated.example', state)
    assert result['action'] != 'reject'


def test_awg_zero_parameters_are_preserved(home):
    state = config.load_state()
    wg = wireguard.bucket(state)
    wireguard.ensure_awg_params(state)
    wg.update(awg_enabled=True, awg_jmin=0, awg_jmax=0, awg_s1=0, awg_s2=0)
    wireguard.ensure_awg_params(state)
    peer = wireguard.add_peer(state, 'client')
    for text in (wireguard.server_config(state), wireguard.client_config(state, peer)):
        assert 'Jmin = 0' in text and 'Jmax = 0' in text
        assert 'S1 = 0' in text and 'S2 = 0' in text


def test_awg_cannot_export_incompatible_standard_config(client, configured):
    client.post('/api/wireguard/settings', json={'enabled': True, 'awg_enabled': True})
    peer = client.post('/api/wireguard/peers', json={'name': 'awg'}).json()['peer_id']
    assert client.get(f'/api/wireguard/peers/{peer}/config?awg=0').status_code == 409
    assert client.get(f'/api/wireguard/peers/{peer}/qr?awg=0').status_code == 409
    assert client.post(f'/api/wireguard/peers/{peer}/link?awg=0').status_code == 409
    assert client.post('/api/wireguard/peers', json={'name': 'router', 'compat': True}).status_code == 409


def test_awg_uses_own_kernel_and_userspace_probe(home, monkeypatch):
    state = config.load_state()
    state['wireguard']['awg_enabled'] = True
    monkeypatch.setattr(wireguard, 'awg_tools_available', lambda: True)
    monkeypatch.setattr(wireguard, 'awg_userspace_available', lambda: False)
    monkeypatch.setattr(wireguard, 'userspace_available', lambda: True)
    calls = []
    monkeypatch.setattr(wireguard, 'kernel_probe', lambda **kwargs: calls.append(kwargs) or (False, 'unsupported'))
    assert wireguard.runtime_mode(state)[0] == 'none'
    assert calls == [{'awg': True}]


def test_expiry_failure_retries_and_does_not_hold_global_lock(client, configured, monkeypatch):
    from zeroproxy.main import _wireguard_once
    from test_wireguard import _lock_is_free
    state = config.load_state()
    state['wireguard']['enabled'] = True
    peer = wireguard.add_peer(state, 'expired')
    peer['expires_at'] = 1
    config.save_state(state)
    calls = []

    def sync(snapshot, timeout=90):
        assert _lock_is_free()
        calls.append(True)
        return len(calls) > 1, 'sync'

    monkeypatch.setattr(wireguard, 'sync', sync)
    _wireguard_once()
    assert wireguard.find_peer(config.load_state(), peer['id'])['enabled'] is True
    _wireguard_once()
    assert wireguard.find_peer(config.load_state(), peer['id'])['enabled'] is False
    assert len(calls) == 2


def test_validation_failure_restores_all_generated_files(client, configured, monkeypatch):
    from pathlib import Path
    apply.reapply(config.load_state())
    p = config.paths()
    tracked = [p['xray_config'], p['hysteria_config'], p['wireguard_config']]
    previous = {name: Path(name).read_bytes() for name in tracked}
    state = config.load_state()
    state['nodes']['trojan'] = False

    def invalid(current, timeout=0):
        Path(p['hysteria_config']).write_text('broken configuration')
        return False, 'invalid'

    monkeypatch.setattr(apply, 'gen_hysteria', invalid)
    steps = apply.reapply(state)
    assert any(not s['ok'] for s in steps)
    for name, content in previous.items():
        assert Path(name).read_bytes() == content


def test_apply_and_expiry_cannot_enter_another_wg_transaction(client, configured):
    from zeroproxy.main import _wireguard_once
    outcomes = []
    state = config.load_state()
    with wireguard.operation():
        def compete():
            outcomes.append(apply.reapply(copy.deepcopy(state)))
            with pytest.raises(wireguard.OperationBusy):
                _wireguard_once()
        worker = threading.Thread(target=compete)
        worker.start()
        worker.join(5)
        assert not worker.is_alive()
    assert outcomes and outcomes[0][0]['ok'] is False


def test_failed_job_does_not_claim_completion():
    job_id, _ = routes._new_job(None, 1, 'validate')
    try:
        routes._finish_job(job_id, [{'name': 'validate', 'ok': False, 'detail': 'invalid'}])
        assert routes._APPLY_JOBS[job_id]['state'] == 'failed'
    finally:
        routes._APPLY_JOBS.pop(job_id, None)


def test_wireguard_lock_covers_separate_apply_process(home):
    import os
    import subprocess
    import sys
    from pathlib import Path
    script = (
        f'import sys; sys.path.insert(0, {str(Path(__file__).resolve().parents[1])!r}); '
        'from zeroproxy import wireguard; '
        'wireguard.operation().__enter__()'
    )
    with wireguard.operation():
        result = subprocess.run([sys.executable, '-c', script], env=os.environ.copy(),
                                capture_output=True, text=True, timeout=5)
    assert result.returncode != 0
    assert 'OperationBusy' in result.stderr
    # 失败的获取不能泄漏锁，同线程也支持嵌套。
    with wireguard.operation():
        with wireguard.operation():
            pass


def test_wireguard_failure_restores_runtime_and_omits_uncommitted_keys(client, configured, monkeypatch):
    client.post('/api/wireguard/settings', json={'enabled': True})
    calls = []

    def sync(state, timeout=90):
        calls.append(len(wireguard.peers(state)))
        return len(calls) > 1, 'sync'

    monkeypatch.setattr(wireguard, 'sync', sync)
    body = client.post('/api/wireguard/peers', json={'name': 'failed'}).json()
    assert calls == [1, 0]
    assert body['steps'][0]['runtime_rolled_back'] is True
    assert 'config' not in body and 'peer_id' not in body


@pytest.mark.parametrize('payload', [
    {'custom_rules': {'block': ["bad.example') -> direct"]}},
    {'ad_allowlist': ['10.0.0.0/8']},
])
def test_invalid_settings_are_not_silently_saved(client, configured, payload):
    before = config.load_state()
    assert client.post('/api/settings', json=payload).status_code == 400
    assert config.load_state() == before


def test_private_domain_resolution_is_checked_before_allowlist(home):
    state = config.load_state()
    state['geodata']['ad_allowlist'] = ['internal.example']
    cfg = xray_config.build_xray_config(state)
    assert cfg['routing']['domainStrategy'] == 'IPOnDemand'
    rules = cfg['routing']['rules']
    private_index = next(i for i, r in enumerate(rules) if r.get('outboundTag') == 'block' and 'ip' in r)
    allow_index = next(i for i, r in enumerate(rules) if 'domain:internal.example' in r.get('domain', []))
    assert private_index < allow_index


def test_bare_ip_rules_use_host_prefixes_in_all_profiles(home):
    state = config.load_state()
    state['routing']['custom_rules']['block'] = ['203.0.113.10', '2001:db8::1']
    rules = share_links.clash_rules(state, geo=False)
    assert f'IP-CIDR,203.0.113.10/32,{share_links.G_ADS},no-resolve' in rules
    assert f'IP-CIDR6,2001:db8::1/128,{share_links.G_ADS},no-resolve' in rules
    custom = share_links._custom_singbox_rules(share_links.custom_rules_of(state))
    assert custom[0]['ip_cidr'] == ['203.0.113.10/32', '2001:db8::1/128']
    assert share_links.simulate_match('2001:db8::1', state)['action'] == 'reject'
