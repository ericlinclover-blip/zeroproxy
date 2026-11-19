"""New-router onboarding: bounded preparation, recoverable pairing, honest progress."""
import json
import re
import subprocess

import pytest
from pathlib import Path

from zeroproxy import config, devices

INSTALL = Path(__file__).parents[1] / 'zeroproxy/client/router-install.sh'


def shell_function(name):
    return re.search(rf'^{name}\(\) \{{.*?^\}}', INSTALL.read_text(), re.M | re.S).group(0)


def test_pair_retries_recover_lost_response_without_duplicate_device(client, configured):
    code = client.post('/api/devices/pair', json={}).json()['code']
    request = {'code': code, 'kind': 'router', 'request_id': 'a' * 64, 'arch': 'arm64'}
    first = client.post('/c/pair', json=request)
    assert first.status_code == 200
    # Simulate losing the response after the transaction committed.
    client.get('/api/devices')  # dashboard pruning must not destroy recovery evidence
    second = client.post('/c/pair', json=request)
    assert second.status_code == 200, 'lost pair response consumes the code and makes installation unrecoverable'
    assert second.json()['id'] == first.json()['id']
    assert second.json()['secret'] == first.json()['secret']
    assert client.get('/api/devices').json()['devices']['count'] == 1
    stranger = client.post('/c/pair', json={**request, 'request_id': 'b' * 64})
    assert stranger.status_code == 403


@pytest.mark.parametrize('tproxy_present', [True, False])
def test_existing_capabilities_do_not_contact_package_repositories(tmp_path, tproxy_present):
    script = f'''
set -eu
ZP_DIR={str(tmp_path)!r}
PKG_MGR=opkg
NET_TUN=0; NET_NFT=0; NET_TPROXY=0; NET_REDIRECT=0; NET_EBPF=0; NET_IPV6=1
PROBE_WHY=unavailable; CAPS_WHY_TUN=''; CAPS_WHY_TPROXY=''; CAPS_WHY_REDIRECT=''; DEPS_FAILED=''; WAN_MTU=1500; TUN_MTU=1500
step() {{ :; }}; ok() {{ :; }}; note() {{ :; }}; warn() {{ :; }}
pkg_update() {{ echo update >> "$ZP_DIR/package-calls"; }}
pkg_install() {{ echo "$1" >> "$ZP_DIR/package-calls"; DEPS_WHY=''; }}
modprobe() {{ :; }}
tun_ok() {{ return 0; }}; nft_ok() {{ return 0; }}; tproxy_ok() {{ return {0 if tproxy_present else 1}; }}; redirect_ok() {{ return 0; }}
btf_ensure() {{ :; }}; ebpf_ok() {{ return 0; }}; perf_cap_probe() {{ PERF_CAP=1; }}
_perf_flag() {{ printf 0; }}; compute_tun_mtu() {{ :; }}; offload_state() {{ printf 0; }}
choose_datapath() {{ DATAPATH=tun; }}; write_caps() {{ :; }}; ebpf_detail() {{ :; }}
{shell_function('install_deps')}
install_deps
'''
    result = subprocess.run(['sh', '-c', script], capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stderr
    assert not (tmp_path / 'package-calls').exists(), 'working routers still wait for unnecessary repository update/install'


def test_installation_reports_do_not_fabricate_control_or_running_state(client, configured):
    code = client.post('/api/devices/pair', json={}).json()['code']
    paired = client.post('/c/pair', json={'code': code}).json()
    payload = {'device': paired['id'], 'id': 'c' * 32, 'seq': 1, 'stage': 'core', 'status': 'running'}
    assert client.post('/c/install/report', json=payload).status_code == 403
    response = client.post('/c/install/report', json={**payload, 'k': paired['secret']})
    assert response.status_code == 200
    item = client.get('/api/devices').json()['devices']['items'][0]
    assert item['installation']['stage'] == 'core'
    assert not item['online']
    assert not item['connected']


def test_progress_is_ordered_fenced_and_expires():
    from zeroproxy import device_installation as progress
    device = {}
    first = {'id': 'a' * 32, 'seq': 1, 'stage': 'paired', 'status': 'running'}
    assert progress.accept(device, first, now=100)
    assert progress.accept(device, {**first, 'seq': 2, 'stage': 'core'}, now=110)
    assert not progress.accept(device, first, now=111)
    assert progress.view(device, now=231)['status'] == 'interrupted'
    assert progress.accept(device, {**first, 'id': 'b' * 32}, now=240)
    assert not progress.accept(device, {**first, 'seq': 100}, now=241)
    assert progress.accept(device, {**first, 'id': 'b' * 32, 'seq': 2, 'stage': 'ready', 'status': 'completed'}, now=250)
    assert not progress.accept(device, {**first, 'id': 'b' * 32, 'seq': 3}, now=251)


@pytest.mark.parametrize('supports_range', [True, False])
def test_core_transfer_recovers_a_dropped_stream_without_redownloading_prefix(tmp_path, supports_range):
    import hashlib
    import http.server
    import threading
    payload = b'router-core-payload-' * 65536
    split = len(payload) // 2
    requests = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            resume = self.headers.get('Range', '')
            requests.append(resume)
            if len(requests) == 1:
                self.send_response(200)
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload[:split])
                self.wfile.flush()
                self.close_connection = True
            else:
                start = int(resume.removeprefix('bytes=').removesuffix('-')) if resume and supports_range else 0
                self.send_response(206 if resume and supports_range else 200)
                self.send_header('Content-Length', str(len(payload) - start))
                if resume and supports_range:
                    self.send_header('Content-Range', f'bytes {start}-{len(payload)-1}/{len(payload)}')
                self.end_headers()
                try:
                    self.wfile.write(payload[start:])
                except (BrokenPipeError, ConnectionResetError):
                    pass
        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        dest = tmp_path / 'core.gz'
        script = f'''
HTTP=curl; TLS_OPTS=''; PANEL_SIZE={len(payload)}; PANEL_SHA={hashlib.sha256(payload).hexdigest()}; CORE_RATE_WINDOW=25
start_progress() {{ :; }}; stop_progress() {{ :; }}
{shell_function('http_fetch_to')}
{shell_function('core_download')}
core_download http://127.0.0.1:{server.server_port}/core {str(dest)!r} 10 0
'''
        result = subprocess.run(['sh', '-c', script], capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, 'a dropped stream still aborts the download instead of resuming'
        assert dest.read_bytes() == payload
        expected = ['', f'bytes={split}-'] + ([] if supports_range else [''])
        assert requests == expected
    finally:
        server.shutdown()
        server.server_close()


def test_combined_package_contains_verified_runtime_and_ui(client, configured):
    import hashlib
    import io
    import tarfile
    from zeroproxy import router_client
    response = client.get('/c/rt/bundle?ui=1')
    assert response.status_code == 200
    assert hashlib.sha256(response.content).hexdigest() == response.headers['x-zp-sha256']
    with tarfile.open(fileobj=io.BytesIO(response.content), mode='r:gz') as archive:
        assert set(archive.getnames()) == set(router_client.RUNTIME_FILES) | {'ui/' + name for name in router_client.UI_FILES}
        for name in router_client.UI_FILES:
            assert archive.extractfile('ui/' + name).read().decode() == router_client.ui_file(name)[0]


def test_pair_recovery_is_bounded_and_has_no_stored_plaintext(client, configured, monkeypatch):
    code = client.post('/api/devices/pair', json={}).json()['code']
    request_id = 'd' * 64
    response = client.post('/c/pair', json={'code': code, 'request_id': request_id})
    paired = response.json()
    assert response.status_code == 200
    state = config.load_state()
    text = json.dumps(state)
    assert request_id not in text
    assert paired['secret'] not in text
    script = client.get('/c/' + code).text
    assert 'install_begin' in script
    assert paired['secret'] not in script
    entry = next(c for c in state['devices']['pair_codes'] if c['code'] == code)
    monkeypatch.setattr(devices, '_now', lambda: entry['replay_until'] + 1)
    retry = client.post('/c/pair', json={'code': code, 'request_id': request_id})
    assert retry.status_code == 403


def test_geo_preparation_runs_independent_transfers_concurrently(tmp_path):
    funcs = shell_function('install_geo')
    script = f'''
set -eu
ZP_DIR={str(tmp_path)!r}; GEO_FILE_LIST='geoip.metadb geosite.dat'; DEGRADED=''; PANEL_GEO=true
step() {{ :; }}; ok() {{ :; }}; warn() {{ :; }}; zp_hsize() {{ printf '%s' "$1"; }}
geo_ok() {{ [ -s "$ZP_DIR/geoip.metadb" ] && [ -s "$ZP_DIR/geosite.dat" ]; }}
geo_fetch_one() {{
    touch "$ZP_DIR/started.$1"
    n=0
    while [ "$n" -lt 20 ]; do
        if [ -f "$ZP_DIR/started.geoip.metadb" ] && [ -f "$ZP_DIR/started.geosite.dat" ]; then
            printf 'valid data' > "$ZP_DIR/$1"
            return 0
        fi
        n=$((n + 1)); sleep .05
    done
    return 1
}}
{funcs}
install_geo
[ -z "$DEGRADED" ]
'''
    result = subprocess.run(['sh', '-c', script], capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, 'Geo transfers serialized or lost their individual results: ' + result.stderr


def _lock_script(tmp_path):
    functions = '\n'.join(shell_function(name) for name in ('random_request_id', 'install_begin', 'install_cleanup'))
    return f'''
set -eu
ZP_DIR={str(tmp_path)!r}; HDRS="$ZP_DIR/headers"; DEV_ID=''; DEV_SECRET=''
die() {{ printf '%s\\n' "$*" >&2; exit 1; }}
install_stage() {{ :; }}; install_send() {{ :; }}; install_receipt_save() {{ :; }}
{functions}
install_begin
'''


def test_install_lock_rejects_concurrent_install_and_cleans_up(tmp_path):
    import time
    script = _lock_script(tmp_path)
    owner = subprocess.Popen(['sh', '-c', script + 'touch "$ZP_DIR/acquired"; while :; do sleep .1; done'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        until = time.monotonic() + 3
        while time.monotonic() < until and not (tmp_path / 'acquired').exists():
            time.sleep(.02)
        assert (tmp_path / 'acquired').exists()
        other = subprocess.run(['sh', '-c', script], capture_output=True, text=True, timeout=3)
        assert other.returncode != 0
        assert '已有安装正在运行' in other.stderr
    finally:
        owner.terminate()
        owner.wait(timeout=3)
    assert not (tmp_path / '.install-lock').is_symlink()


def test_install_lock_recovers_a_dead_owner(tmp_path):
    (tmp_path / '.install-lock').symlink_to('99999999:unknown')
    result = subprocess.run(['sh', '-c', _lock_script(tmp_path)], capture_output=True, text=True, timeout=3)
    assert result.returncode == 0, result.stderr
    assert not (tmp_path / '.install-lock').is_symlink()


def test_invalid_new_core_does_not_overwrite_working_executable(tmp_path):
    binary = tmp_path / 'mihomo'
    original = '#!/bin/sh\nprintf working\n'
    binary.write_text(original)
    binary.chmod(0o755)
    script = f'''
ZP_DIR={str(tmp_path)!r}; ZP_BIN="$ZP_DIR/mihomo"; ARCH=arm64
step() {{ :; }}; ok() {{ :; }}; warn() {{ :; }}
core_reusable() {{ return 1; }}; core_read_panel() {{ PANEL_PREFER=panel; }}
core_from_panel() {{ printf '#!/bin/sh\\nexit 42\\n' > "$_tmp"; }}
die() {{ exit 1; }}
{shell_function('install_core')}
install_core
'''
    result = subprocess.run(['sh', '-c', script], capture_output=True, text=True, timeout=3)
    assert result.returncode != 0
    assert binary.read_text() == original


def test_completed_receipt_is_recovered_by_heartbeat(client, configured):
    code = client.post('/api/devices/pair', json={}).json()['code']
    paired = client.post('/c/pair', json={'code': code}).json()
    receipt = {'id': 'e' * 32, 'seq': 9, 'stage': 'ready', 'status': 'completed'}
    body = {'device': paired['id'], 'k': paired['secret'], 'actual': True, 'installation': receipt}
    response = client.post('/c/report', json=body)
    assert response.status_code == 200
    assert response.json()['installation_ack'] == receipt['id']
    replay = client.post('/c/report', json=body)
    assert replay.json()['installation_ack'] == receipt['id']
    item = client.get('/api/devices').json()['devices']['items'][0]
    assert item['installation']['status'] == 'completed'
    # Optional corrupted receipts cannot prevent ordinary control reconciliation.
    invalid = client.post('/c/report', json={**body, 'installation': {'id': '../../bad'}})
    assert invalid.status_code == 200
    assert invalid.json()['installation_ack'] == ''


def test_receipt_payload_and_ack_preserve_newer_attempt(tmp_path):
    source = (INSTALL.parent / 'runtime/agent.sh').read_text()
    functions = '\n'.join(re.search(rf'^{name}\(\) \{{.*?^\}}', source, re.M | re.S).group(0)
                          for name in ('key_of', 'json_get', 'json_escape', 'installation_payload', 'installation_ack'))
    old_id, new_id = 'a' * 32, 'b' * 32
    old = tmp_path / f'install-report-panel-{old_id}.json'
    new = tmp_path / f'install-report-panel-{new_id}.json'
    old.write_text(json.dumps({'id': old_id}))
    new.write_text(json.dumps({'id': new_id, 'seq': 10, 'stage': 'ready', 'status': 'completed', 'error': ''}))
    (tmp_path / 'install-current-panel').write_text(new_id)
    script = f'''
ZP_DIR={str(tmp_path)!r}
{functions}
installation_ack https://panel '{{"installation_ack":"{old_id}"}}'
printf '{{"device":"test"'
installation_payload https://panel
printf '}}'
'''
    result = subprocess.run(['sh', '-c', script], capture_output=True, text=True, timeout=3)
    assert result.returncode == 0, result.stderr
    assert not old.exists()
    assert new.exists()
    assert json.loads(result.stdout)['installation']['id'] == new_id
    new.write_text('corrupt receipt data')
    result = subprocess.run(['sh', '-c', script], capture_output=True, text=True, timeout=3)
    assert json.loads(result.stdout) == {'device': 'test'}


def test_certificate_rejection_does_not_trigger_five_network_retries(tmp_path):
    script = f'''
HTTP=curl; TLS_OPTS=''; HDRS={str(tmp_path / 'headers')!r}
curl() {{
    printf 'call\\n' >> {str(tmp_path / 'calls')!r}
    for arg in "$@"; do [ "$arg" != -fsSk ] || {{ printf '{{}}'; return 0; }}; done
    return 60
}}
sleep() {{ printf 'sleep\\n' >> {str(tmp_path / 'sleeps')!r}; }}
progress_note() {{ :; }}; warn() {{ :; }}; http_why() {{ printf certificate; }}
{shell_function('http_get')}
{shell_function('http_probe')}
http_probe https://panel.invalid/api/status
[ "$TLS_OPTS" = insecure ]
'''
    result = subprocess.run(['sh', '-c', script], capture_output=True, text=True, timeout=3)
    assert result.returncode == 0, result.stderr
    assert not (tmp_path / 'sleeps').exists(), 'certificate rejection still wastes the network retry schedule'
    assert (tmp_path / 'calls').read_text().splitlines() == ['call', 'call']


def test_local_resume_script_survives_failure_and_is_removed_after_success(tmp_path):
    runner = tmp_path / 'runner.sh'
    runner.write_text(_lock_script(tmp_path) + '\nif [ -f "$ZP_DIR/succeed" ]; then INSTALL_STATUS=completed; else exit 17; fi\n')
    first = subprocess.run(['sh', str(runner)], capture_output=True, text=True, timeout=3)
    resume = tmp_path / 'install-resume.sh'
    assert first.returncode == 17
    assert resume.exists()
    assert resume.stat().st_mode & 0o777 == 0o600
    assert '继续安装' in first.stderr
    (tmp_path / 'succeed').touch()
    second = subprocess.run(['sh', str(resume)], capture_output=True, text=True, timeout=3)
    assert second.returncode == 0, second.stderr
    assert not resume.exists()
