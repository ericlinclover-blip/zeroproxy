"""Behavior regressions from the 2026-11-16 interaction/functional audit."""
import json
import os
import threading
import urllib.error
from pathlib import Path

import pytest
from starlette.requests import Request
from zeroproxy import apply, config, devices, routes, services


def test_domain_failure_and_concurrent_apply_finish_without_lock_inversion(client, configured, monkeypatch):
    probing = threading.Event()
    ordinary_started = threading.Event()
    results = []
    original_lock = routes._APPLY_RUN_LOCK
    monkeypatch.setattr(routes, '_APPLY_RUN_LOCK', threading.RLock())
    monkeypatch.setattr(services, 'install_cert', lambda _: (True, 'certificate', {'type': 'letsencrypt'}))
    monkeypatch.setattr(services, 'is_prod', lambda: True)

    def reapply(state, **kwargs):
        assert not config.lock_held_here(), 'service operations must not hold the configuration lock'
        return [{'name': 'apply', 'ok': True, 'detail': 'ready'}]

    def probe(*args, **kwargs):
        assert not config.lock_held_here()
        probing.set()
        assert ordinary_started.wait(2)
        return False, 'unreachable'

    monkeypatch.setattr(apply, 'reapply', reapply)
    monkeypatch.setattr(services, 'probe_public_panel', probe)

    def domain():
        results.append(routes._domain_pipeline('new.example.com'))

    def ordinary():
        assert probing.wait(2)
        ordinary_started.set()
        routes._run_apply_job('audit-no-job')

    workers = [threading.Thread(target=fn, daemon=True) for fn in (domain, ordinary)]
    for worker in workers: worker.start()
    for worker in workers: worker.join(4)
    assert not any(worker.is_alive() for worker in workers)
    assert results and '已回滚' in results[0][1]
    assert config.load_state()['domain'] == 'proxy.example.com'


def test_domain_does_not_claim_successful_rollback_on_rollback_failure(client, configured, monkeypatch):
    monkeypatch.setattr(services, 'install_cert', lambda _: (True, 'certificate', {'type': 'letsencrypt'}))
    monkeypatch.setattr(apply, 'reapply', lambda *a, **k: [{'name': 'restart', 'ok': False, 'detail': 'broken'}])
    steps, error = routes._domain_pipeline('new.example.com')
    assert '回滚未完成' in error
    assert '已回滚' not in error
    assert steps[-1]['ok'] is False


@pytest.mark.parametrize('online,covered,actual,expected', [
    (False, 'full', True, False), (True, '', True, False),
    (True, 'none', True, False), (True, 'lan_tcp', True, True),
    (True, 'full', False, False), (True, 'lan', True, True),
])
def test_device_connection_requires_fresh_coverage(online, covered, actual, expected):
    view = devices.device_view({'desired': True, 'actual': actual,
                               'last_seen': 1000 if online else 1,
                               'report': {'covered': covered}}, now=1010)
    assert view['connected'] is expected
    assert view['taking_over'] is expected


def test_device_control_owner_survives_matching_desired_value():
    view = devices.device_view({'desired': True, 'actual': True,
                               'last_seen': 1000, 'report': {'override': 'on', 'covered': 'full'}}, now=1010)
    assert view['control'] == 'local'


def test_job_journal_recovers_interrupted_task_without_credentials(client, configured):
    cookie = client.cookies.get(routes.SESSION_COOKIE)
    request = Request({'type': 'http', 'headers': [(b'cookie', f'{routes.SESSION_COOKIE}={cookie}'.encode())]})
    job_id, _ = routes._new_job(request, 7, 'start')
    path = Path(config.paths()['data_dir']) / 'apply-jobs.json'
    contents = path.read_text()
    assert cookie not in contents
    assert os.stat(path).st_mode & 0o777 == 0o600
    with routes._APPLY_JOBS_LOCK:
        routes._APPLY_JOBS.pop(job_id)
    response = client.get(f'/api/apply/job?id={job_id}')
    assert response.status_code == 200
    assert response.json()['state'] == 'interrupted'
    assert '不会自动重复执行' in response.json()['error']
    assert client.get('/api/dashboard').json()['recent_jobs'][0]['id'] == job_id


def test_expired_session_cannot_read_even_its_own_job(client, configured):
    cookie = client.cookies.get(routes.SESSION_COOKIE)
    request = Request({'type': 'http', 'headers': [(b'cookie', f'{routes.SESSION_COOKIE}={cookie}'.encode())]})
    job_id, _ = routes._new_job(request, 1, 'start')
    routes._finish_job(job_id, [], '')
    with config.locked():
        state = config.load_state()
        state['sessions'][cookie]['expires'] = 0
        config.save_state(state)
    assert client.get(f'/api/apply/job?id={job_id}').status_code == 401


def test_explicit_node_state_is_repeat_safe_and_rejects_stale_changes(client, configured, monkeypatch):
    calls = []
    def landed(state, request, **kwargs):
        calls.append(state['nodes']['trojan'])
        config.save_state(state)
        return {'steps': []}
    monkeypatch.setattr(routes, '_landing_body', landed)
    initial = client.get('/api/dashboard').json()['configuration_revision']
    assert client.post('/api/nodes/trojan/enabled', json={'enabled': False, 'expected_revision': initial}).status_code == 200
    assert client.post('/api/nodes/trojan/enabled', json={'enabled': False}).status_code == 200
    assert client.post('/api/nodes/trojan/enabled', json={'enabled': False, 'expected_revision': initial}).status_code == 200
    assert calls == [False]
    stale = client.post('/api/nodes/trojan/enabled', json={'enabled': True, 'expected_revision': initial})
    assert stale.status_code == 409
    assert config.load_state()['nodes']['trojan'] is False


@pytest.mark.parametrize('code,status,ok', [(401, 'auth_required', None), (403, 'restricted', False),
                                          (404, 'unknown', None), (405, 'unknown', None),
                                          (429, 'rate_limited', None), (503, 'error', None)])
def test_endpoint_http_response_never_claims_service_unlock(monkeypatch, code, status, ok):
    def reject(*args, **kwargs):
        raise urllib.error.HTTPError('https://example.com', code, 'response', {}, None)
    monkeypatch.setattr(services.urllib.request, 'urlopen', reject)
    result = services._endpoint_evidence('Test', 'ai', 'https://example.com', 1)
    assert result['http_status'] == code
    assert result['status'] == status
    assert result['ok'] is ok
    assert result['location'] == 'server-direct'


def test_offline_endpoint_checks_are_unknown_not_fake_success(home, monkeypatch):
    monkeypatch.setenv('ZP_PUBLIC_IP', '0')
    result = services.unlock_probe(force=True)
    assert result['simulated'] is True
    assert all(item['ok'] is None and item['status'] == 'unknown' for item in result['items'])


def test_failed_apply_preserves_last_good_revision_and_files(client, configured, monkeypatch):
    for name in ('ensure_reality_settings', 'gen_xray', 'gen_nginx', 'gen_hysteria', 'gen_wireguard', 'restart_services', 'verify_listeners'):
        monkeypatch.setattr(apply, name, lambda *a, **k: (True, 'ready'))
    monkeypatch.setattr(apply, 'ensure_cert_files', lambda *a, **k: (True, 'ready'))
    before = config.load_state()
    assert not apply.failures(apply.reapply(before))
    before = config.load_state()
    good = Path(config.paths()['data_dir']) / 'runtime-last-good.json'
    original = good.read_bytes()
    assert os.stat(good).st_mode & 0o777 == 0o600
    old_revision = before['runtime']['applied_revision']
    before['ports']['reality'] = 12345
    config.save_state(before)
    monkeypatch.setattr(apply, 'gen_xray', lambda *a, **k: (False, 'invalid configuration'))
    assert apply.failures(apply.reapply(before))
    state = config.load_state()
    assert state['runtime']['status'] == 'failed'
    assert state['runtime']['applied_revision'] == old_revision
    assert good.read_bytes() == original
    assert state['runtime']['rollback_state'] == 'unchanged'
    assert apply.subscription_state(state)['ports']['reality'] != 12345
    assert config.configuration_revision(state) != old_revision


def test_configuration_revision_ignores_telemetry_but_tracks_desired(home):
    state = config.load_state()
    original = config.configuration_revision(state)
    state.update(traffic={'total': 123}, updated_at=1234, runtime={'status': 'failed'})
    state['sessions']['irrelevant'] = {'expires': 1234}
    assert config.configuration_revision(state) == original
    state['nodes']['trojan'] = not state['nodes']['trojan']
    assert config.configuration_revision(state) != original


def test_independent_credentials_render_and_revoke_without_panel_process(client, configured, monkeypatch):
    import subprocess
    import sys
    import yaml
    from zeroproxy import device_credentials, hysteria_config, xray_config
    with config.locked():
        state = config.load_state()
        pair = devices.create_pair_code(state)
        device, _, error = devices.register(state, {'code': pair['code'], 'hostname': 'test-router'})
        assert not error
        device_credentials.enable(device)
        credentials = dict(device['dataplane'])
        master = state['hysteria_password']
        config.save_state(state)
    cfg = xray_config.build_xray_config(state)
    ordinary = [i for i in cfg['inbounds'] if i['tag'] in config.XRAY_NODE_IDS]
    assert ordinary
    for inbound in ordinary:
        key = 'password' if inbound['protocol'] == 'trojan' else 'id'
        expected = credentials['trojan_password'] if key == 'password' else credentials['uuid']
        assert any(user.get(key) == expected for user in inbound['settings']['clients'])
    isolated = device_credentials.subscription_state(state, device)
    assert isolated['uuid'] == credentials['uuid'] != state['uuid']
    hysteria_config.write_hysteria_config(state)
    auth_config = yaml.safe_load(Path(config.paths()['hysteria_config']).read_text())['auth']
    assert auth_config['type'] == 'command'
    auth_script = auth_config['command']
    def authenticate(secret):
        return subprocess.run([sys.executable, auth_script, '127.0.0.1:1234', secret, '1'], capture_output=True, text=True)
    assert authenticate(master).stdout.strip() == 'main'
    assert authenticate(credentials['hysteria_password']).stdout.strip() == device['id']
    invalid = authenticate('$(touch /tmp/never-execute-this)')
    assert invalid.returncode != 0 and not invalid.stdout
    devices.remove(state, device['id'])
    hysteria_config.write_hysteria_config(state)
    assert authenticate(credentials['hysteria_password']).returncode != 0
    assert authenticate(master).returncode == 0
    cfg = xray_config.build_xray_config(state)
    assert credentials['uuid'] not in json.dumps(cfg)
    assert credentials['trojan_password'] not in json.dumps(cfg)


def test_runtime_restore_keeps_current_admin_and_devices(client, configured, monkeypatch):
    from zeroproxy import device_credentials
    initial = config.load_state()
    snapshot = {key: initial.get(key) for key in config.RUNTIME_FIELDS}
    snapshot['ports']['reality'] = 12346
    config.atomic_write_json(str(Path(config.paths()['data_dir']) / 'runtime-last-good.json'), snapshot)
    with config.locked():
        state = config.load_state()
        pair = devices.create_pair_code(state)
        device, _, _ = devices.register(state, {'code': pair['code'], 'hostname': 'keep'})
        device_credentials.enable(device)
        config.save_state(state)
    seen = []
    monkeypatch.setattr(apply, 'reapply', lambda state, **kwargs: seen.append(state) or [])
    response = client.post('/api/apply/rollback')
    assert response.status_code == 200 and response.json()['ok']
    assert seen[0]['admin'] == initial['admin']
    assert seen[0]['devices']['items'][0]['id'] == device['id']
    assert seen[0]['ports']['reality'] == 12346


def test_restart_failure_restores_previous_files_but_keeps_failed_desired(client, configured, monkeypatch):
    for name in ('ensure_reality_settings', 'gen_xray', 'gen_nginx', 'gen_hysteria', 'gen_wireguard', 'restart_services', 'verify_listeners'):
        monkeypatch.setattr(apply, name, lambda *a, **k: (True, 'ready'))
    monkeypatch.setattr(apply, 'ensure_cert_files', lambda *a, **k: (True, 'ready'))
    initial = config.load_state()
    assert not apply.failures(apply.reapply(initial))
    desired = config.load_state()
    desired['ports']['reality'] = 12347
    config.save_state(desired)
    calls = []
    def restart(state, *args, **kwargs):
        calls.append(state['ports']['reality'])
        return (False, 'new startup failed') if len(calls) == 1 else (True, 'old configuration restored')
    monkeypatch.setattr(apply, 'restart_services', restart)
    steps = apply.reapply(desired)
    assert apply.failures(steps)
    assert calls == [12347, initial['ports']['reality']]
    after = config.load_state()
    assert after['ports']['reality'] == 12347
    assert after['runtime']['rollback_state'] == 'restored'
    assert apply.subscription_state(after)['ports']['reality'] == initial['ports']['reality']


def test_device_credentials_api_waits_for_successful_application_and_retries(client, configured, monkeypatch):
    import yaml
    from zeroproxy import device_credentials
    with config.locked():
        state = config.load_state()
        pair = devices.create_pair_code(state)
        device, secret, _ = devices.register(state, {'code': pair['code'], 'hostname': 'api-router'})
        config.save_state(state)
    original_gen = apply.gen_xray
    monkeypatch.setattr(apply, 'gen_xray', lambda *a, **k: (False, 'audit invalid candidate'))
    url = f"/api/devices/{device['id']}/credentials"
    failed = client.post(url)
    assert failed.status_code == 200
    assert any(not step['ok'] for step in failed.json()['steps'])
    sub = f"/c/sub/{device['id']}?k={secret}"
    assert client.get(sub).status_code == 503
    monkeypatch.setattr(apply, 'gen_xray', original_gen)
    monkeypatch.setattr(apply, 'ensure_reality_settings', lambda *a, **k: (True, 'ready'))
    success = client.post(url)
    assert success.status_code == 200
    assert not apply.failures(success.json()['steps'])
    state = config.load_state()
    assert state['runtime']['credentials_revision'] == device_credentials.revision(state)
    credentials = devices.find(state, device['id'])['dataplane']
    response = client.get(sub)
    assert response.status_code == 200
    proxies = yaml.safe_load(response.text)['proxies']
    assert any(proxy.get('uuid') == credentials['uuid'] for proxy in proxies)
    assert all(proxy.get('uuid') != state['uuid'] for proxy in proxies)
    performance = client.get(f"/c/perf/config?id={device['id']}&k={secret}")
    assert performance.status_code == 200
    assert credentials['uuid'] in performance.text and state['uuid'] not in performance.text
    removed = client.delete(f"/api/devices/{device['id']}")
    assert removed.status_code == 200 and not apply.failures(removed.json()['steps'])
    assert client.get(sub).status_code == 403
    assert credentials['uuid'] not in Path(config.paths()['xray_config']).read_text()


def test_device_template_changes_revision_and_overrides_install_url(client, configured):
    with config.locked():
        state = config.load_state()
        pair = devices.create_pair_code(state)
        device, secret, _ = devices.register(state, {'code': pair['code'], 'hostname': 'template-router'})
        config.save_state(state)
    previous = devices.config_rev(config.load_state())
    assert client.post(f"/api/devices/{device['id']}", json={'template': 'global'}).status_code == 200
    assert devices.config_rev(config.load_state()) != previous
    response = client.get(f"/c/sub/{device['id']}?k={secret}&rules=smart")
    assert response.status_code == 200 and '分流模板: global' in response.text
    report = client.post('/c/report', json={'device': device['id'], 'k': secret}).json()
    assert report['template'] == 'global'
    performance = client.get(f"/c/perf/config?id={device['id']}&k={secret}&tpl=smart")
    assert performance.status_code == 200
    assert 'global' in performance.text
