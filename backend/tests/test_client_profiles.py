"""Client import paths must match the platform, QR URL and downloaded artifact."""
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.responses import Response
from conftest import USERNAME,PASSWORD
from zeroproxy import config,share_links


def login(client):
    assert client.post('/api/login',json={'username':USERNAME,'password':PASSWORD}).status_code==200


def path_of(url):
    parsed=urlsplit(url)
    return parsed.path+'?'+parsed.query


@pytest.mark.parametrize('template',['smart','precision','global','direct'])
def test_android_profile_has_vpn_dns_and_independent_bootstrap(client,configured,template):
    with config.locked():
        state=config.load_state();state['routing']['template']=template;config.save_state(state)
    url=configured['subscription_formats']['singbox_android']
    response=client.get(path_of(url))
    assert response.status_code==200
    profile=response.json()
    tun=profile['inbounds'][0]
    assert tun['type']=='tun' and tun['auto_route'] is True
    assert len(tun['address'])==2 and 'interface_name' not in tun and 'strict_route' not in tun
    assert profile['route']['default_domain_resolver']=='local-dns'
    assert {'protocol':'dns','action':'hijack-dns'} in profile['route']['rules']
    assert profile['dns']['final']==('local-dns' if template=='direct' else 'proxy-dns')
    assert response.headers['content-disposition']=='attachment; filename="zeroproxy-android.json"'
    assert response.headers['cache-control']=='no-store'
    legacy=client.get(path_of(configured['subscription_formats']['singbox'])).json()
    assert legacy['inbounds']==[{'type':'mixed','tag':'mixed-in','listen':'127.0.0.1','listen_port':2080}]


def test_android_deep_link_qr_download_and_copy_share_the_same_url(client,configured,monkeypatch):
    from zeroproxy import routes
    login(client)
    dash=client.get('/api/dashboard').json()
    copied=dash['subscription_formats']['singbox_android']
    deep=urlsplit(dash['deep_links']['singbox_android'])
    assert parse_qs(deep.query)['url']==[copied]
    monkeypatch.setattr(routes,'_qr_response',lambda data,*args:Response(data))
    qr=client.get('/api/subscription/qr?format=singbox&client=android')
    assert qr.status_code==200 and qr.text==copied
    assert client.get(path_of(copied)).json()['inbounds'][0]['type']=='tun'


@pytest.mark.parametrize('fmt',['singbox','sing-box','singbox-json','json','singbox-next','singbox14','singbox-1.14','singbox-new'])
def test_json_downloads_have_reliable_server_filename(client,configured,fmt):
    response=client.get(path_of(configured['subscription_url'])+'&format='+fmt)
    assert response.status_code==200
    assert response.headers['content-disposition']=='attachment; filename="zeroproxy-singbox.json"'
    assert response.headers['content-type'].startswith('application/json')
    assert response.json()['inbounds'][0]['type']=='mixed'


@pytest.mark.parametrize('query',['format=clash&client=android','format=base64&client=android','format=singbox&client=other'])
def test_rejects_incompatible_platform_format_without_falling_back(client,configured,query):
    login(client)
    assert client.get(path_of(configured['subscription_url'])+'&'+query).status_code==400
    assert client.get('/api/subscription/qr?'+query).status_code==400


def test_android_download_preserves_last_working_server_credentials(client,configured):
    from pathlib import Path
    with config.locked():
        state=config.load_state()
        good={key:state.get(key) for key in config.RUNTIME_FIELDS}
        config.atomic_write_json(str(Path(config.paths()['data_dir'])/'runtime-last-good.json'),good)
        state['uuid']='00000000-0000-4000-8000-000000000000'
        state['runtime'].update(status='failed',rollback_state='restored')
        config.save_state(state)
    response=client.get(path_of(configured['subscription_formats']['singbox_android']))
    assert response.status_code==200
    credentials=[out['uuid'] for out in response.json()['outbounds'] if out.get('type')=='vless']
    assert good['uuid'] in credentials and state['uuid'] not in credentials


@pytest.mark.parametrize('template',['smart','precision','global','direct'])
@pytest.mark.parametrize('kind',['android','linux'])
def test_profiles_with_real_singbox(client,configured,tmp_path,template,kind):
    import os,subprocess
    binary=os.environ.get('ZP_SINGBOX_BIN')
    if not binary:pytest.skip('需要真实 sing-box 二进制 (ZP_SINGBOX_BIN)')
    state=config.load_state()
    text=share_links.singbox_android_profile(state,template) if kind=='android' else share_links.singbox_profile(state,template)
    candidate=tmp_path/f'{template}-{kind}.json';candidate.write_text(text)
    result=subprocess.run([binary,'check','-c',str(candidate)],text=True,capture_output=True,timeout=20)
    assert result.returncode==0,(result.stdout+result.stderr)[-1600:]
