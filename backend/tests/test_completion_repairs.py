"""Behavior checks for guarded changes, overlap previews and device evidence."""
import copy
import json
import os
import subprocess
import time
from pathlib import Path

import pytest
from zeroproxy import apply, change_guard, config, device_diagnostics as diagnostics, routes, share_links


def arm(state, timeout=90):
    identity = change_guard.begin(state, copy.deepcopy(state), 'settings', ['ports'], timeout)
    state['ports']['reality'] += 1
    config.save_state(state)
    change_guard.finish(identity, [{'ok': True}])
    return identity


def test_guard_confirmation_is_idempotent_and_does_not_expose_baseline(client, configured):
    identity = arm(config.load_state())
    view = client.get(f'/api/changes/{identity}').json()
    assert view['state'] == 'awaiting_confirmation'
    assert 'before' not in view and 'keys' not in view
    assert client.post('/api/settings', json={'reality_sni':'www.example.org'}).status_code == 409
    assert client.post(f'/api/changes/{identity}/confirm').status_code == 200
    assert client.post(f'/api/changes/{identity}/confirm').status_code == 200
    assert not change_guard.active(config.load_state())
    assert not config.load_state()['pending_change']['before']


def test_expired_change_cannot_be_confirmed_and_restores_only_owned_fields(client, configured, monkeypatch):
    original = config.load_state()
    identity = arm(copy.deepcopy(original))
    state = config.load_state()
    state['pending_change']['deadline'] = time.time() - 1
    state['routing']['template'] = 'global'
    config.save_state(state)
    assert client.post(f'/api/changes/{identity}/confirm').status_code == 409
    def reapply(state):
        assert not config.lock_held_here()
        assert state['ports'] == original['ports']
        return [{'name':'verify', 'ok':True}]
    monkeypatch.setattr(apply, 'reapply', reapply)
    assert routes.rollback_network_change()[-1]['ok']
    fresh = config.load_state()
    assert fresh['routing']['template'] == 'global'
    assert fresh['pending_change']['state'] == 'rolled_back'


def test_restart_immediately_rolls_back_unconfirmed_change(client, configured, monkeypatch):
    identity = arm(config.load_state())
    monkeypatch.setattr(change_guard, 'INSTANCE', 'new-process')
    assert change_guard.due(config.load_state())
    monkeypatch.setattr(apply, 'reapply', lambda state: [{'ok':True}])
    assert client.post(f'/api/changes/{identity}/rollback').json()['ok']
    assert not change_guard.due(config.load_state())


def test_rollback_failure_can_retry_but_preserves_external_drift(client, configured, monkeypatch):
    identity = arm(config.load_state())
    monkeypatch.setattr(apply, 'reapply', lambda state: [{'ok':False, 'detail':'service failed'}])
    assert not client.post(f'/api/changes/{identity}/rollback').json()['ok']
    assert config.load_state()['pending_change']['state'] == 'rollback_failed'
    monkeypatch.setattr(apply, 'reapply', lambda state: [{'ok':True}])
    assert client.post(f'/api/changes/{identity}/rollback').json()['ok']
    identity = arm(config.load_state())
    state = config.load_state(); state['ports']['reality'] += 2; config.save_state(state)
    assert not client.post(f'/api/changes/{identity}/rollback').json()['ok']
    assert config.load_state()['ports'] == state['ports']


def test_settings_guard_arms_after_success_and_stale_rule_revision_is_rejected(client, configured):
    before = config.load_state()
    response = client.post('/api/settings', json={'reality_sni':'www.example.org', 'require_confirmation':True})
    assert response.status_code == 200, response.text
    assert response.json()['pending_change']['state'] == 'awaiting_confirmation'
    identity = response.json()['pending_change']['id']
    assert client.post(f'/api/changes/{identity}/rollback').json()['ok']
    assert config.load_state()['reality'] == before['reality']
    preview = client.post('/api/routing/analyze', json={'custom_rules':{'proxy':['example.com']}}).json()
    assert client.post('/api/settings', json={'custom_rules':{'direct':['new.example.com']}}).status_code == 200
    assert client.post('/api/settings', json={'custom_rules':preview['rules'], 'expected_settings_revision':preview['settings_revision']}).status_code == 409


def analyze(raw, old=None):
    return __import__('zeroproxy.rule_analysis', fromlist=['analyze']).analyze(raw, old or {}, share_links.normalize_target)


def test_rule_analysis_domains_and_networks_follow_first_match_priority():
    result = analyze({'direct':['sub.example.com','10.1.0.0/16','2001:db8:1::/48'],
                      'block':['EXAMPLE.com.','10.0.0.0/8','2001:db8::/32'],
                      'proxy':['sibling.invalid','1.2.3.4']})
    assert result['counts']['shadowed'] == 3
    assert all(c['earlier']['group'] == 'block' for c in result['conflicts'])
    assert result['rules']['proxy'][-1] == '1.2.3.4/32'
    assert not analyze({'proxy':['1.2.3.4/32']}, {'proxy':['1.2.3.4']})['changes']['added']
    assert analyze({'block':['sub.example.com'], 'direct':['example.com']})['counts']['overlap'] == 1
    assert analyze({'block':['1.2.3.4'], 'direct':['example.com']})['total_conflicts'] == 0
    assert analyze({'block':['example.com','example.com']})['counts']['duplicate'] == 1


def test_analysis_bounds_output_and_rejects_unknown_groups():
    result = analyze({'block':['example.com'] * 25})
    assert result['total_conflicts'] == 300 and len(result['conflicts']) == 200
    assert result['details_truncated']
    with pytest.raises(ValueError): analyze({'unknown':['example.com']})
    with pytest.raises(ValueError): analyze({'block':['bad host']})
    with pytest.raises(ValueError): analyze({'block':['example.com'] * 2049})


def test_device_diagnostics_never_accepts_stale_replayed_or_arbitrary_evidence():
    device = {'report':{'diagnostics':'1'}}
    pending = diagnostics.start(device, 100)
    assert diagnostics.start(device, 101)['id'] == pending['id']
    assert not diagnostics.accept(device, {'id':'wrong', 'evidence':{}}, 102)
    evidence = {'device':'passed', 'dns':'failed', 'takeover':['bad'], 'packets':4, 'http_status':204, 'secret':'must-not-copy', 'target':'<script>'}
    assert diagnostics.accept(device, {'id':pending['id'], 'evidence':evidence}, 110)
    assert not diagnostics.accept(device, {'id':pending['id'], 'evidence':{}}, 111)
    public = diagnostics.view(device, 500)
    assert public['stale'] and public['stages']['takeover'] == 'unknown'
    assert public['stages']['target'] == 'unknown' and 'secret' not in json.dumps(public)
    pending = diagnostics.start(device, 501)
    assert not diagnostics.accept(device, {'id':pending['id'], 'evidence':{}}, 622)
    assert diagnostics.view(device, 622)['state'] == 'expired'
    with pytest.raises(ValueError): diagnostics.start({'report':{}})


def test_device_heartbeat_request_and_result_roundtrip(client, configured):
    pair = client.post('/api/devices/pair', json={'label':'test'}).json()
    registration = client.post('/c/pair', json={'code':pair['code'], 'name':'test'}).json()
    identity, secret = registration['id'], registration['secret']
    payload = {'device':identity, 'k':secret, 'report':{'diagnostics':1}}
    assert client.post('/c/report', json=payload).status_code == 200
    queued = client.post(f'/api/devices/{identity}/diagnose').json()
    response = client.post('/c/report', json=payload).json()
    assert response['diagnostic_request'] == queued['id']
    payload['diagnostic'] = {'id':queued['id'], 'evidence':{'device':'passed','target':'passed','packets':3}}
    assert client.post('/c/report', json=payload).json()['diagnostic_request'] == ''
    view = client.get('/api/devices').json()['devices']['items'][0]['diagnostic']
    assert view['state'] == 'completed' and view['stages']['target'] == 'passed'


@pytest.mark.parametrize('mode,http,expected', [('tun','204','passed'),('tun','503','failed'),('ebpf','204','unknown')])
def test_real_cli_structured_probe_uses_fixed_bounded_targets(tmp_path, mode, http, expected):
    source = (Path(__file__).resolve().parents[1] / 'zeroproxy/client/runtime/cli').read_text()
    # Exercise the real function in isolation, with deterministic local commands.
    function = source[source.index('doctor_json() {'):source.index('case "${1:-status}" in')]
    data = tmp_path/'data'; data.mkdir(); (data/'caps').write_text('chosen='+mode+'\n')
    bin_dir = tmp_path/'bin'; bin_dir.mkdir()
    for name, body in {'curl':f'printf "%s" "{http}"\n','timeout':'exit 0\n','nslookup':'exit 0\n'}.items():
        path = bin_dir/name;path.write_text('#!/bin/sh\n'+body);path.chmod(0o700)
    script = f'ZP_DIR="{data}"; ZP_MIXED=7890\nzp_live_mode() {{ echo {mode}; }}\nrunning() {{ echo yes; }}\ndatapath_packets() {{ echo "12 3"; }}\nentry_endpoints() {{ echo "example.com:443"; }}\ntcp_once() {{ echo ok; }}\n'+function+'\ndoctor_json\n'
    result = subprocess.run(['sh','-c',script], env={**os.environ,'PATH':str(bin_dir)+':/usr/bin:/bin'}, capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report['target'] == expected and report['takeover'] == 'observed'
    assert report['entry'] == 'observed'


def test_watchdog_expires_without_browser_and_never_holds_config_lock(client, configured, monkeypatch):
    import threading
    from zeroproxy import main
    monkeypatch.setenv('ZP_CHANGE_GUARD_AUTO', '1')
    identity = arm(config.load_state())
    state = config.load_state(); state['pending_change']['deadline'] = time.time() - 1; config.save_state(state)
    done = threading.Event()
    def reapply(state):
        assert not config.lock_held_here()
        done.set()
        return [{'ok':True}]
    monkeypatch.setattr(apply, 'reapply', reapply)
    stop = threading.Event()
    worker = threading.Thread(target=main._change_guard_loop, args=(stop,config.paths()['home']))
    worker.start()
    try:
        assert done.wait(4)
    finally:
        stop.set();worker.join(3)
    assert config.load_state()['pending_change']['state'] == 'rolled_back'
    assert client.post(f'/api/changes/{identity}/confirm').status_code == 409


def test_applying_change_external_drift_is_never_overwritten(client, configured, monkeypatch):
    state = config.load_state()
    change_guard.begin(state, copy.deepcopy(state), 'settings', ['ports'])
    state['pending_change']['instance'] = 'previous-process'
    state['ports']['reality'] += 2
    config.save_state(state)
    monkeypatch.setattr(apply, 'reapply', lambda state: pytest.fail('must not apply a stale baseline'))
    assert not routes.rollback_network_change()[-1]['ok']
    assert config.load_state()['ports'] == state['ports']


def test_agent_executes_each_request_once_and_reports_result_next_heartbeat(tmp_path):
    source = (Path(__file__).resolve().parents[1] / 'zeroproxy/client/runtime/agent.sh').read_text()
    segment = source[source.index('        _dg_file="$ZP_DIR/diagnostic-'):source.index('        _d="$(json_get_bool "$RESP" desired)"')]
    bin_dir=tmp_path/'bin';bin_dir.mkdir()
    command=bin_dir/'zeroproxy';command.write_text('#!/bin/sh\necho run >> "$ZP_DIR/invocations"\nprintf \'{"device":"passed"}\'\n');command.chmod(0o700)
    helper='''
key_of() { printf 'panel'; }
json_get() { printf '%s' "$1" | sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p'; }
report_fields_json() { printf '{"diagnostics":1}'; }
http_post() { printf '%s\\n' "$2" >> "$ZP_DIR/bodies"; printf '{"diagnostic_request":"%s"}' "$REQUEST"; }
_b=https://panel.invalid;_k=secret
for REQUEST in aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 'invalid;command'; do
BODY='{"device":"test"'
'''
    script='export ZP_DIR="'+str(tmp_path)+'"\n'+helper+segment+'\ndone\n'
    result=subprocess.run(['sh','-c',script],env={**os.environ,'PATH':str(bin_dir)+':/usr/bin:/bin'},text=True,capture_output=True,timeout=5)
    assert result.returncode == 0, result.stderr
    assert (tmp_path/'invocations').read_text().splitlines() == ['run','run']
    bodies=[json.loads(line) for line in (tmp_path/'bodies').read_text().splitlines()]
    assert 'diagnostic' not in bodies[0]
    assert bodies[1]['diagnostic']['id'] == 'a'*32
    assert bodies[3]['diagnostic']['id'] == 'b'*32
    assert (tmp_path/'diagnostic-panel.json').stat().st_mode & 0o777 == 0o600


def test_failed_step_without_detail_never_starts_confirmation(client, configured):
    state = config.load_state()
    identity = change_guard.begin(state, copy.deepcopy(state), 'settings', ['ports'])
    config.save_state(state)
    change_guard.finish(identity, [{'name':'failed', 'ok':False, 'detail':''}])
    assert config.load_state()['pending_change']['state'] == 'rollback_pending'
    assert client.post(f'/api/changes/{identity}/confirm').status_code == 409


def test_async_task_start_failure_arms_immediate_recovery(client, configured, monkeypatch):
    monkeypatch.setenv('ZP_APPLY_ASYNC', '1')
    state=config.load_state()
    identity=change_guard.begin(state, copy.deepcopy(state), 'settings', ['ports'])
    class CannotStart:
        def __init__(self, **kwargs): pass
        def start(self): raise RuntimeError('thread unavailable')
    monkeypatch.setattr(routes.threading, 'Thread', CannotStart)
    with pytest.raises(RuntimeError):
        routes._reapply_job(state, on_result=lambda steps,error: change_guard.finish(identity,steps,error) or [])
    assert change_guard.due(config.load_state())
    assert config.load_state()['pending_change']['state'] == 'rollback_pending'


def test_tcp_diagnostic_formats_ipv6_without_changing_tcp_scope(tmp_path):
    source=(Path(__file__).resolve().parents[1]/'zeroproxy/client/runtime/cli').read_text()
    function=source[source.index('tcp_once() {'):source.index('entry_probe() {')]
    command=tmp_path/'curl';command.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$PROBE_ARGS"\nprintf "0.03"\n');command.chmod(0o700)
    result=subprocess.run(['sh','-c',function+'\ntcp_once 2001:db8::1 443\n'],env={**os.environ,'PATH':str(tmp_path)+':/usr/bin:/bin','PROBE_ARGS':str(tmp_path/'args')},text=True,capture_output=True,timeout=5)
    assert result.stdout == 'ok'
    args=(tmp_path/'args').read_text().splitlines()
    assert 'https://[2001:db8::1]:443/' in args
    assert args[args.index('--connect-timeout')+1] == '2'
    assert args[args.index('-m')+1] == '4'
