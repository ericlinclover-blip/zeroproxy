"""Regression checks for DNS disclosure and split AI authentication exits."""
import json
import os
from pathlib import Path
import subprocess

import pytest
import yaml

from zeroproxy import config, share_links as links


@pytest.mark.parametrize('template', ['smart', 'precision', 'global'])
@pytest.mark.parametrize('router', [False, True])
def test_google_login_and_ai_share_exit(configured, template, router):
    state = config.load_state()
    profile = yaml.safe_load(links.clash_profile(state, template, router=router, geo=False))
    for domain in ('accounts.google.com', 'oauth2.googleapis.com', 'gemini.google.com',
                   'aistudio.google.com', 'generativelanguage.googleapis.com',
                   'recaptcha.net', 'www.gstatic.com'):
        assert f'DOMAIN-SUFFIX,{domain},{links.G_AI}' in profile['rules']
    groups = {g['name']: g for g in profile['proxy-groups']}
    assert groups[links.G_AI]['type'] == 'select'
    assert groups[links.G_AI]['proxies'] == [links.G_LANDING]
    dns = profile['dns']
    assert all(s.startswith('https://') and '#' in s for s in dns['nameserver'])
    assert dns['nameserver-policy']['+.accounts.google.com'][0].endswith('#' + links.G_AI)
    assert 'proxy-server-nameserver' in dns


@pytest.mark.parametrize('template', ['smart', 'precision', 'global'])
def test_android_auth_dns_precedes_cn_rules(configured, template):
    profile = json.loads(links.singbox_android_profile(config.load_state(), template))
    ai = next(o for o in profile['outbounds'] if o['tag'] == links.G_AI)
    assert ai['outbounds'] == [links.G_LANDING]
    assert ai['default'] == links.G_LANDING
    first = profile['dns']['rules'][0]
    assert 'accounts.google.com' in first['domain_suffix']
    assert first['server'] == 'ai-dns'
    resolver = next(s for s in profile['dns']['servers'] if s['tag'] == 'ai-dns')
    assert resolver['detour'] == links.G_AI


def test_direct_dns_does_not_require_proxy(configured):
    profile = yaml.safe_load(links.clash_profile(config.load_state(), 'direct', router=True, geo=False))
    assert all('#' not in s for s in profile['dns']['nameserver'])


RUNTIME = Path(__file__).resolve().parents[1] / 'zeroproxy/client/runtime'


@pytest.mark.parametrize('fail', ['', 'route', 'nft'])
@pytest.mark.parametrize('ipv6,template', [(False, 'global'), (True, 'global'), (False, 'direct')])
def test_tproxy_installs_routes_before_capture_and_rolls_back(tmp_path, fail, ipv6, template):
    home = tmp_path / 'router'
    home.mkdir()
    (home / 'caps').write_text(f'ipv6={int(ipv6)}\n')
    (home / 'config.yaml').write_text(f'# 分流模板: {template} (test)\n')
    (home / 'tproxy.nft').write_text((RUNTIME / 'tproxy.nft').read_text())
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    log = tmp_path / 'commands'
    for tool in ('ip', 'nft'):
        binary = bindir / tool
        binary.write_text('#!/bin/sh\n'
                          f'echo "{tool} $*" >> "$TRACE"\n'
                          'case "$*" in\n'
                          '  *"rule del"*) exit 1;;\n'
                          '  "-f "*) cp "$2" "$CAPTURE";;\n'
                          'esac\ncase "$*" in\n'
                          '  *"route replace"*) [ "$FAIL" != route ] || exit 1;;\n'
                          '  "-f "*) [ "$FAIL" != nft ] || exit 1;;\n'
                          'esac\nexit 0\n')
        binary.chmod(0o755)
    result = subprocess.run(['/bin/sh', '-c',
                             f'. "{RUNTIME / "tproxy.sh"}"\nzp_tproxy_apply'],
                            env={**os.environ, 'PATH': str(bindir) + ':' + os.environ['PATH'],
                                 'ZP_DIR': str(home), 'TRACE': str(log), 'FAIL': fail,
                                 'CAPTURE': str(tmp_path / 'loaded.nft')},
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == (1 if fail else 0), result.stderr
    commands = log.read_text()
    if not fail:
        assert 'ip -4 route replace local 0.0.0.0/0 dev lo table 20290' in commands
        assert ('ip -6 route replace local ::/0 dev lo table 20290' in commands) == ipv6
        assert 'fwmark 0x1fe/0xffffffff lookup 20290' in commands
        assert commands.index('rule add') < commands.index('nft -f')
        loaded = (tmp_path / 'loaded.nft').read_text()
        assert ('meta nfproto ipv6 counter reject' in loaded) == (not ipv6 and template != 'direct')
        assert ('tproxy ip6 to :7893' in loaded) == ipv6
    else:
        assert commands.rstrip().endswith('ip -6 route del local ::/0 dev lo table 20290')


def test_tproxy_captures_fakeip_and_scopes_lan():
    source = (RUNTIME / 'tproxy.nft').read_text()
    assert '198.18.0.0/16' not in source, 'fake-IP 必须进代理，不能私网放行'
    assert 'iifname != "__ZP_LANIF__" return' in source
    assert 'th dport { 22, 53' not in source, '公网端口不能批量豁免'
    assert 'hook output' in source, 'dnsmasq 的公网查询也必须接管'


@pytest.mark.parametrize('fail', ['', 'guard', 'direct'])
def test_redirect_blocks_public_udp_without_blocking_lan(tmp_path, fail):
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    log = tmp_path / 'commands'
    for tool in ('iptables', 'ip6tables'):
        binary = bindir / tool
        binary.write_text('#!/bin/sh\n'
                          f'echo "{tool} $*" >> "$TRACE"\n'
                          'case "$*" in\n'
                          '  *" -D "*) exit 1;;\n'
                          '  *" -C "*) exit 1;;\n'
                          '  *" -j REJECT"*) [ "$FAIL" != guard ] || exit 1;;\n'
                          'esac\nexit 0\n')
        binary.chmod(0o755)
    source = (RUNTIME / 'redirect.sh').read_text().replace('__ZP_LANIF__', 'br-test')
    if fail == 'direct':
        (tmp_path / 'config.yaml').write_text('# 分流模板: direct (全部直连, 不下载 geo 数据)\n')
    result = subprocess.run(['/bin/sh', '-c', source + '\nzp_redirect_apply'],
                            env={**os.environ, 'PATH': str(bindir) + ':' + os.environ['PATH'],
                                 'TRACE': str(log), 'FAIL': fail, 'ZP_DIR': str(tmp_path)},
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == (1 if fail == 'guard' else 0), result.stderr
    commands = log.read_text().splitlines()
    if fail == 'guard':
        assert any('-X zp_udp_guard' in c for c in commands)
        return
    for tool in ('iptables', 'ip6tables'):
        if fail == 'direct':
            assert not any('-p udp -j REJECT' in c for c in commands)
        else:
            assert f'{tool} -t filter -A zp_udp_guard -p udp -j REJECT' in commands
        assert f'{tool} -t filter -I FORWARD -i br-test -j zp_udp_guard' in commands
        local = '192.168.0.0/16' if tool == 'iptables' else 'fc00::/7'
        if fail != 'direct':
            assert commands.index(f'{tool} -t filter -A zp_udp_guard -d {local} -j RETURN') < commands.index(f'{tool} -t filter -A zp_udp_guard -p udp -j REJECT')
        assert any(c.startswith(f'{tool} -t nat -I OUTPUT') for c in commands)
    assert not any('-d 198.18.0.0/16 -j RETURN' in c for c in commands)


def test_mihomo_dns_never_retries_direct_when_proxy_is_down(configured, tmp_path):
    """A live core must attempt the SOCKS hop and never reach the direct DoH trap."""
    import http.server
    import socket
    import struct
    import threading
    import time

    binary = os.environ.get('ZP_MIHOMO_BIN')
    if not binary:
        pytest.skip('需要真实 mihomo (ZP_MIHOMO_BIN)')

    def free_port():
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            return sock.getsockname()[1]

    hits = []

    class Trap(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            hits.append(self.path)
            self.send_error(502)

        do_GET = do_POST

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Trap)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    profile = yaml.safe_load(links.clash_profile(config.load_state(), 'global', geo=False))
    profile['mixed-port'] = free_port()
    dead_port = free_port()
    profile['proxies'] = [{'name': 'dead-hop', 'type': 'socks5', 'server': '127.0.0.1', 'port': dead_port}]
    profile['proxy-groups'] = [
        {'name': name, 'type': 'select', 'proxies': ['dead-hop']}
        for name in (links.G_SELECT, links.G_LANDING, links.G_AI)
    ]
    # Keep generated DNS detours, replace only the remote DoH target with a local trap.
    dns = profile['dns']
    dns_port = free_port()
    dns['listen'] = f'127.0.0.1:{dns_port}'
    dns['nameserver'] = [f'http://127.0.0.1:{server.server_port}/dns-query#' + links.G_SELECT]
    dns['nameserver-policy'] = {'+.accounts.google.com': [
        f'http://127.0.0.1:{server.server_port}/dns-query#' + links.G_AI]}
    profile['rules'] = [f'MATCH,{links.G_SELECT}']
    candidate = tmp_path / 'config.yaml'
    candidate.write_text(yaml.safe_dump(profile, allow_unicode=True))
    logfile = tmp_path / 'core.log'
    try:
        with logfile.open('w') as log:
            process = subprocess.Popen([binary, '-d', str(tmp_path), '-f', str(candidate)], stdout=log, stderr=log)
            try:
                for _ in range(100):
                    if 'DNS server' in logfile.read_text():
                        break
                    assert process.poll() is None, logfile.read_text()
                    time.sleep(.05)
                else:
                    pytest.fail('DNS listener did not start: ' + logfile.read_text())
                for domain in ('accounts.google.com', 'unknown.example'):
                    name = b''.join(bytes([len(label)]) + label.encode() for label in domain.split('.')) + b'\0'
                    packet = struct.pack('!HHHHHH', 0x1234, 0x100, 1, 0, 0, 0) + name + struct.pack('!HH', 16, 1)
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                        sock.settimeout(3)
                        sock.sendto(packet, ('127.0.0.1', dns_port))
                        try:
                            sock.recvfrom(4096)
                        except socket.timeout:
                            pass
                assert process.poll() is None, logfile.read_text()
            finally:
                process.terminate()
                process.wait(timeout=5)
        assert not hits, '代理不可用时 DoH 不得改走直连'
        assert f'127.0.0.1:{dead_port}' in logfile.read_text(), logfile.read_text()
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)
