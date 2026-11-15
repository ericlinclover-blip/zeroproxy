"""Exercise actual request helpers for certificate vs TLS transport failures."""
import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CLIENT = ROOT / 'backend/zeroproxy/client'


def function(path, name):
    source = path.read_text()
    match = re.search(r'^' + re.escape(name) + r'\(\) \{.*?^\}', source, re.M | re.S)
    assert match, name
    return match.group(0)


def run(script, env=None):
    return subprocess.run(['sh', '-c', script], text=True, capture_output=True,
                          timeout=10, env={**os.environ, **(env or {})})


@pytest.mark.parametrize('script,name', [
    ('runtime/cli', 'zp_tls_error'), ('runtime/agent.sh', 'zp_tls_rc'),
    ('runtime/perf.sh', '_zp_perf_tls_rc'),
])
@pytest.mark.parametrize('rc', [7, 22, 28, 35, 51, 58, 59, 60, 64, 66, 77, 80, 83, 90, 91])
def test_only_peer_certificate_verification_errors_allow_legacy_fallback(script, name, rc):
    proc = run(function(CLIENT / script, name) + f'\n{name} {rc}')
    assert (proc.returncode == 0) is (rc in (51, 60)), (script, rc)


def fake_curl(tmp_path, codes):
    bin_ = tmp_path / 'bin'
    bin_.mkdir()
    log = tmp_path / 'calls'
    count = tmp_path / 'count'
    curl = bin_ / 'curl'
    curl.write_text('''#!/bin/sh
printf '%s\\n' "$*" >> "$CALLS"
n=0; [ ! -f "$COUNT" ] || n=$(cat "$COUNT")
n=$((n + 1)); printf '%s' "$n" > "$COUNT"
case "$n" in
''' + '\n'.join(f'{i}) rc={rc}; code={code} ;;' for i, (rc, code) in enumerate(codes, 1)) + '''
*) rc=0; code=200 ;;
esac
out=''; hdr=''; status=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        -D) hdr="$2"; shift 2 ;;
        -w) status=1; shift 2 ;;
        *) shift ;;
    esac
done
if [ "$rc" = 0 ]; then
    if [ -n "$out" ]; then printf 'body' > "$out"; else printf 'body'; fi
    [ -z "$hdr" ] || printf 'X-ZP-Sha256: 230d8358dc8e8890b4c58deeb62912ee2f20357ae92a5cc861b98e68fe31acb5\\r\\n' > "$hdr"
fi
[ "$status" = 0 ] || printf '%s' "$code"
exit "$rc"
''')
    curl.chmod(0o755)
    return {'PATH': str(bin_) + ':' + os.environ['PATH'], 'CALLS': str(log), 'COUNT': str(count)}, log


def test_agent_retries_handshake_without_disabling_verification(tmp_path):
    env, log = fake_curl(tmp_path, [(35, '000'), (0, '200')])
    path = CLIENT / 'runtime/agent.sh'
    funcs = '\n'.join(function(path, name) for name in ['zp_tls_rc', 'zp_tls_warn', 'http_post'])
    proc = run('ZP_TLS_WARNED=""\nlog() { printf "%s\\n" "$*" >&2; }\nsleep() { :; }\n' + funcs +
               '\nhttp_post https://panel.example/c/report "{}"', env)
    assert proc.returncode == 0, proc.stderr
    calls = log.read_text().splitlines()
    assert len(calls) == 2
    assert all('-fsSk' not in call for call in calls), calls
    assert '证书校验没通过' not in proc.stderr


@pytest.mark.parametrize('rc', [7, 35, 60])
def test_agent_file_download_preserves_failure_code_and_certificate_retry(tmp_path, rc):
    env, log = fake_curl(tmp_path, [(rc, '000'), (0, '200')])
    path = CLIENT / 'runtime/agent.sh'
    funcs = '\n'.join(function(path, name) for name in ['zp_tls_rc', 'zp_tls_warn', 'http_get_file'])
    proc = run('ZP_TLS_WARNED=""\nlog() { :; }\n' + funcs +
               '\nhttp_get_file https://panel.example/c/geo/test 1', env)
    assert proc.returncode == (0 if rc == 60 else rc), proc.stderr
    calls = log.read_text().splitlines()
    assert len(calls) == (2 if rc == 60 else 1), calls
    assert ('-fsSk' in '\n'.join(calls)) is (rc == 60)


def test_perf_handles_curl_000_on_real_certificate_error_and_keeps_headers(tmp_path):
    env, log = fake_curl(tmp_path, [(60, '000'), (0, '200')])
    path = CLIENT / 'runtime/perf.sh'
    funcs = '\n'.join(function(path, name) for name in ['_zp_perf_tls_rc', '_zp_perf_tls_warn', 'zp_perf_get'])
    proc = run('_zp_perf_tls_warned=""\n' + funcs +
               f'\nzp_perf_get https://panel.example/c/config {str(tmp_path / "out")!r} 1 1', env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    calls = log.read_text().splitlines()
    assert len(calls) == 2
    assert '-fsSk' in calls[1] and '-D ' in calls[1], calls


def test_perf_import_does_not_replace_agent_logger():
    path = CLIENT / 'runtime/perf.sh'
    proc = run('logger() { printf "%s\\n" "$*"; }\nlog() { printf "agent:%s\\n" "$*"; }\n' +
               f'. {str(path)!r}\nlog heartbeat\nzp_perf_log performance')
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.splitlines() == ['agent:heartbeat', '-t zeroproxy-perf performance']


@pytest.mark.parametrize('text,want', [
    ('SSL connect error: unexpected eof while reading', False),
    ('TLS handshake failed', False),
    ('TLS alert: unknown ca', False),
    ('x509: certificate signed by unknown authority', True),
    ('certificate file cannot be opened', False),
    ('ERROR: cannot verify panel.example certificate', True),
    ('Invalid SSL certificate', True),
    ('certificate verification failed: unknown authority', True),
])
def test_wget_classifier_requires_certificate_verification_evidence(tmp_path, text, want):
    err = tmp_path / 'err'
    err.write_text(text)
    proc = run(f'ZP_ERR={str(err)!r}\n' + function(CLIENT / 'runtime/cli', 'zp_err_is_tls') + '\nzp_err_is_tls')
    assert (proc.returncode == 0) is want


def test_perf_preserves_legacy_auth_target_across_certificate_retry(tmp_path):
    env, log = fake_curl(tmp_path, [(22, '403'), (60, '000'), (0, '200')])
    path = CLIENT / 'runtime/perf.sh'
    funcs = '\n'.join(function(path, name) for name in ['_zp_perf_tls_rc', '_zp_perf_tls_warn', 'zp_perf_get'])
    proc = run('_zp_perf_tls_warned=""\n' + funcs +
               f'\nzp_perf_get https://panel.example/c/config {str(tmp_path / "out")!r} 1 1 "Authorization: Bearer test-key" "?k=test-key"', env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    calls = log.read_text().splitlines()
    assert len(calls) == 3
    assert 'Authorization: Bearer test-key' in calls[0]
    for call in calls[1:]:
        assert '?k=test-key' in call and 'Authorization:' not in call
    assert '-fsSk' in calls[2] and '-D ' in calls[2]
    assert 'test-key' not in proc.stdout + proc.stderr


def test_persistent_agent_handshake_failure_is_logged_truthfully(tmp_path):
    env, log = fake_curl(tmp_path, [(35, '000')] * 3)
    path = CLIENT / 'runtime/agent.sh'
    funcs = '\n'.join(function(path, name) for name in ['zp_tls_rc', 'zp_tls_warn', 'http_post'])
    proc = run('ZP_TLS_WARNED=""\nlog() { printf "%s\\n" "$*" >&2; }\nsleep() { :; }\n' + funcs +
               '\nhttp_post https://panel.example/c/report "{}"', env)
    assert proc.returncode == 35
    calls = log.read_text().splitlines()
    assert len(calls) == 3 and all('-fsSk' not in call for call in calls)
    assert 'TLS 握手失败' in proc.stderr and 'curl 35' in proc.stderr
    assert '证书校验没通过' not in proc.stderr
