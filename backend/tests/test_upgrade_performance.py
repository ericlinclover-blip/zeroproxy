"""End-to-end seams for the 2026-11-17 correctness/performance upgrade."""
from pathlib import Path
import os
import re
import subprocess
import threading

import pytest

ROOT = Path(__file__).resolve().parents[2]
AGENT = ROOT / 'backend/zeroproxy/client/runtime/agent.sh'


def functions(*names):
    source = AGENT.read_text()
    return '\n'.join(re.search(rf'^{name}\(\) \{{.*?^\}}', source, re.M | re.S).group() for name in names)


def shell(text, timeout=10):
    result = subprocess.run(['sh', '-c', text], text=True, capture_output=True, timeout=timeout)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


@pytest.mark.parametrize('restart_rc,ready,expected', [(42,0,1), (0,1,1), (0,0,0)])
def test_router_apply_checks_runtime_and_restores_previous_file(tmp_path, restart_rc, ready, expected):
    (tmp_path/'config.yaml').write_text('proxy-groups: [old]\n')
    validator = tmp_path/'mihomo'
    validator.write_text('#!/bin/sh\nexit 0\n'); validator.chmod(0o755)
    init = tmp_path/'init'
    init.write_text(f'#!/bin/sh\nexit {restart_rc}\n'); init.chmod(0o755)
    source = functions('reload_safe','activate_config','apply_config').replace('/etc/zeroproxy/mihomo',str(validator)).replace('/etc/init.d/zeroproxy',str(init))
    # The real candidate, validation, commit and compensation path; only OS effects are replaced.
    out = shell(f'''ZP_DIR={str(tmp_path)!r}
CONF="$ZP_DIR/config.yaml"
ensure_geo() {{ :; }}
build_config() {{ echo 'proxy-groups: [new]'; }}
core_up() {{ return 0; }}
perf_intending() {{ return 1; }}
local_api_ready() {{ return {ready}; }}
wait_runtime() {{ return {ready}; }}
refresh_state() {{ :; }}
actual_covered() {{ echo full; }}
flush_dns() {{ :; }}
reload_running_config() {{ return 1; }}
sleep() {{ :; }}
log() {{ :; }}
{source}
apply_config
printf 'rc=%s\\n' "$?"
''')
    assert f'rc={expected}' in out
    assert ('[old]' if expected else '[new]') in (tmp_path/'config.yaml').read_text()


def test_agent_follow_template_request_does_not_override_panel():
    for mode in ('single','multi'):
        out = shell('''migrate_servers() { :; }
first_server() { echo /ignored; }
field_of() { echo test; }
count_servers() { echo '''+('1' if mode=='single' else '2')+'''; }
geo_ok() { return 0; }
caps_flag() { echo 1; }
datapath_flag() { echo tun; }
ipv6_flag() { echo 0; }
tun_mtu_flag() { echo 1500; }
http_get() { echo "$1"; return 1; }
'''+functions('build_config')+'\nbuild_config || true\n')
        # Single emits its request; multi's request is captured internally, so inspect that branch too.
        assert 'rules=smart' not in out
    assert 'rules=smart' not in functions('build_config')


def test_local_override_wins_after_panel_aggregation():
    source = AGENT.read_text()
    # Execute the real aggregation boundary, with network response already reduced to panel false.
    start = source.index('    # ---------------------------------------------------------------- 面板可达, 处理指令')
    stop = source.index('    # 性能模式先处理',start)
    body = source[start:stop]
    for override,expected in [('on','true'),('off','false'),('','false')]:
        out = shell(f'DESIRED_ALL=false\nOVERRIDE={override!r}\n'+body+'\necho "$DESIRED"')
        assert out.strip() == expected


def test_dashboard_slow_collection_does_not_block_state_writes(client, configured, monkeypatch):
    from zeroproxy import routes, config
    from conftest import USERNAME,PASSWORD
    client.post('/api/login',json={'username':USERNAME,'password':PASSWORD})
    entered,release,acquired = threading.Event(),threading.Event(),threading.Event()
    original=routes._dashboard_body
    def slow(*args,**kwargs):
        entered.set()
        assert release.wait(3)
        return original(*args,**kwargs)
    monkeypatch.setattr(routes,'_dashboard_body',slow)
    response=[]
    reader=threading.Thread(target=lambda:response.append(client.get('/api/dashboard')))
    reader.start(); assert entered.wait(3)
    def write():
        with config.locked(): acquired.set()
    writer=threading.Thread(target=write); writer.start()
    try:
        assert acquired.wait(.5),'dashboard holds the configuration lock during slow collection'
    finally:
        release.set(); reader.join(5); writer.join(5)
    assert response[0].status_code==200


def run_agent(tmp_path, *, running=True, secondary_change=False):
    import json
    import shlex
    home=tmp_path/'router'; (home/'servers').mkdir(parents=True)
    for name in ('a','b'):
        (home/'servers'/f'{name}.json').write_text(json.dumps({'base':f'https://{name}.example','id':name,'secret':'test-secret'}))
    (home/'config.yaml').write_text('proxy-groups: [old]\n')
    init=tmp_path/'init'; init.write_text('#!/bin/sh\nexit 0\n'); init.chmod(0o755)
    validator=home/'mihomo'; validator.write_text('#!/bin/sh\nexit 0\n'); validator.chmod(0o755)
    (tmp_path/'b.rev').write_text('bbbbbbbbbbbbbbbb')
    source=AGENT.read_text().replace('ZP_DIR=/etc/zeroproxy',f'ZP_DIR={shlex.quote(str(home))}')
    source=source.replace('/etc/zeroproxy/mihomo',str(validator)).replace('/etc/init.d/zeroproxy',str(init))
    overrides={
        'http_post': f'''printf '%s\\n' "$2" >> {shlex.quote(str(tmp_path/'reports'))}
case "$1" in *a.example*) rev=aaaaaaaaaaaaaaaa ;; *) rev="$(cat {shlex.quote(str(tmp_path/'b.rev'))})" ;; esac
printf '{{"rev":"%s","desired":{str(running).lower()}}}' "$rev"''',
        'http_get': '''case "$1" in
*format=skeleton*) printf 'proxy-providers: {}\\nproxy-groups:\\n  - name: choose\\n    type: select\\n    use: []\\n' ;;
*format=provider*) printf 'proxies: [{name: node, type: direct}]\\n' ;;
*) return 1 ;;
esac''',
        'core_up':f'return {0 if running else 1}',
        'proxy_up':f'return {0 if running else 1}',
        'perf_intending':'return 1', 'refresh_state':':', 'geo_ok':'return 0',
        'ensure_geo':'return 0','wait_runtime':'return 0','ui_url':':','reload_running_config':'return 1',
        'caps_flag':'echo 1','datapath_flag':'echo tun','ipv6_flag':'echo 0',
        'tun_mtu_flag':'echo 1500','report_fields_json':"echo '{}'",'log':':',
    }
    for name,body in overrides.items():
        source=re.sub(rf'^{name}\(\) \{{.*?^\}}',lambda m:f'{name}() {{\n{body}\n}}',source,flags=re.M|re.S)
    hook=f'''\nzp_live_mode() {{ echo tun; }}
actual_covered() {{ echo full; }}
turn=0
sleep() {{
 turn=$((turn+1))
 '''+(f"[ \"$turn\" != 1 ] || echo cccccccccccccccc > {shlex.quote(str(tmp_path/'b.rev'))}" if secondary_change else ':')+'''
 [ "$turn" -lt 3 ] || exit 0
}
'''
    source=source.replace('\nwhile true; do',hook+'\nwhile true; do',1)
    script=tmp_path/'agent';script.write_text(source)
    proc=subprocess.run(['sh',str(script)],capture_output=True,text=True,timeout=15)
    assert proc.returncode==0,proc.stdout+proc.stderr
    reports=[json.loads(row) for row in (tmp_path/'reports').read_text().splitlines()]
    return home,reports


def test_secondary_panel_changes_trigger_real_provider_refresh_and_own_ack(tmp_path):
    home,reports=run_agent(tmp_path,secondary_change=True)
    a=[r for r in reports if r['device']=='a'][-1]
    b=[r for r in reports if r['device']=='b'][-1]
    assert a['applied_rev']=='aaaaaaaaaaaaaaaa'
    assert b['applied_rev']=='cccccccccccccccc'
    assert a['healthy'] is False and b['healthy'] is False
    assert 'b_example-cccccccccccccccc.yaml' in (home/'config.yaml').read_text()
    assert (home/'providers/b_example-bbbbbbbbbbbbbbbb.yaml').exists(),'keep previous snapshot for rollback'


def test_disabled_router_stages_without_claiming_running_revision(tmp_path):
    home,reports=run_agent(tmp_path,running=False)
    assert all(not r.get('applied_rev') for r in reports)
    assert reports[-1]['staged_rev']=='bbbbbbbbbbbbbbbb'
    assert not (home/'applied.rev').exists()


@pytest.mark.parametrize('template',['smart','precision','global','direct'])
def test_actual_router_request_follows_global_template(client,configured,template):
    from conftest import USERNAME,PASSWORD
    from zeroproxy import config
    client.post('/api/login',json={'username':USERNAME,'password':PASSWORD})
    pair=client.post('/api/devices/pair',json={}).json()
    # The API returns its one-time code alongside the installation command.
    code=pair['code']
    device=client.post('/c/pair',json={'code':code,'kind':'router'}).json()
    with config.locked():
        state=config.load_state();state['routing']['template']=template;config.save_state(state)
    response=client.get(f"/c/sub/{device['id']}",params={'k':device['secret'],'geo':0})
    assert response.status_code==200,response.text
    from zeroproxy import share_links
    assert response.text==share_links.clash_profile(config.load_state(),template=template,router=True,device=device['name'],geo=False,base='http://proxy.example.com:8899')


def test_revision_change_between_report_and_download_is_rejected(client,configured):
    from conftest import USERNAME,PASSWORD
    client.post('/api/login',json={'username':USERNAME,'password':PASSWORD})
    pair=client.post('/api/devices/pair',json={}).json()
    device=client.post('/c/pair',json={'code':pair['code'],'kind':'router'}).json()
    response=client.get(f"/c/sub/{device['id']}",params={'k':device['secret'],'expected_rev':'0000000000000000'})
    assert response.status_code==409


@pytest.mark.parametrize('changed,expected',[('rules',0),('proxies',0),('mixed-port',1),('dns',1),('tun',1)])
def test_collection_reload_preserves_listener_and_datapath_boundary(tmp_path,changed,expected):
    import yaml
    old={'mixed-port':7890,'dns':{'enable':True},'tun':{'enable':False},'proxies':[],'rules':['MATCH,DIRECT']}
    new={**old,changed:({'enable':False} if changed=='dns' else {'enable':True} if changed=='tun' else 7891 if changed=='mixed-port' else ['changed'])}
    (tmp_path/'config.yaml.previous').write_text(yaml.safe_dump(old))
    (tmp_path/'config.yaml').write_text(yaml.safe_dump(new))
    out=shell(f'CONF={str(tmp_path/"config.yaml")!r}\n'+functions('reload_safe')+'\nreload_safe\necho "rc=$?"')
    assert f'rc={expected}' in out


def test_failed_reload_falls_back_to_restart_and_readiness(tmp_path):
    init=tmp_path/'init'
    init.write_text(f'#!/bin/sh\necho restart >> {str(tmp_path/"calls")!r}\nexit 0\n');init.chmod(0o755)
    source=functions('activate_config').replace('/etc/init.d/zeroproxy',str(init))
    out=shell('reload_safe() { return 0; }\nreload_running_config() { return 1; }\nwait_runtime() { return 0; }\n'+source+'\nactivate_config\necho "rc=$?"')
    assert 'rc=0' in out and (tmp_path/'calls').read_text().strip()=='restart'


def test_successful_collection_reload_does_not_restart(tmp_path):
    source=functions('activate_config').replace('/etc/init.d/zeroproxy',str(tmp_path/'must-not-exist'))
    out=shell('reload_safe() { return 0; }\nreload_running_config() { return 0; }\nwait_runtime() { return 0; }\n'+source+'\nactivate_config\necho "rc=$?"')
    assert 'rc=0' in out


def test_mihomo_short_id_is_explicit_string_in_profiles_and_providers(home):
    from zeroproxy import config,crypto,share_links
    import uuid
    state=config.load_state();state['domain']='test.example';state['uuid']=str(uuid.uuid4())
    private,public,_=crypto.new_reality_keys()
    state['reality'].update(private_key=private,public_key=public,short_id='12345e67')
    for text in (share_links.clash_profile(state,geo=False),share_links.provider_profile(state)):
        assert "short-id: '12345e67'" in text


def test_stats_single_flight_and_failure_cache(home,monkeypatch):
    from zeroproxy import services,config
    entered,release=threading.Event(),threading.Event()
    calls=[]
    monkeypatch.setattr(services,'bin_path',lambda name:'/test/xray')
    def probe(*a,**kw):
        calls.append(1);entered.set();assert release.wait(2);return False
    monkeypatch.setattr(services,'_tcp_reachable',probe)
    state=config.load_state()
    reader=threading.Thread(target=lambda:services.xray_stats(state));reader.start()
    assert entered.wait(2)
    try:assert services.xray_stats(state) is None
    finally:release.set();reader.join(3)
    assert services.xray_stats(state) is None
    assert len(calls)==1,'a failed probe must not be repeated by each page request'
