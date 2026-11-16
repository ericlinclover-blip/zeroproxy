"""Safety protocol coverage for node, chain and WireGuard mutations."""
import copy
import threading
import time
import uuid

import pytest
from zeroproxy import apply, chain, change_guard, config, routes, wireguard

GUARD = {'X-ZP-Confirm': '90'}


def post(client, path, payload=None):
    response = client.post(path, json=payload or {}, headers=GUARD)
    assert response.status_code == 200, response.text
    return response.json()


def rollback(client):
    item = config.load_state()['pending_change']
    response = client.post(f'/api/changes/{item["id"]}/rollback')
    assert response.status_code == 200, response.text
    assert response.json()['ok'], response.text
    assert response.json()['pending_change']['state'] == 'rolled_back'
    return response.json()


def confirm(client):
    item = config.load_state()['pending_change']
    response = client.post(f'/api/changes/{item["id"]}/confirm')
    assert response.status_code == 200, response.text


def code(host='203.0.113.19'):
    reality = config.load_state()['reality']
    return chain.make_code(host=host, port=8447, uuid=str(uuid.uuid4()),
                           pbk=reality['public_key'], sid=reality['short_id'],
                           sni=reality['server_name'], label='guarded-exit', flow='xtls-rprx-vision')


def stub_probe(monkeypatch):
    monkeypatch.setattr(chain, 'probe_target', lambda *a, **kw: {'ok':True, 'probe_ok':True, 'detail':'local test', 'ms':1})


@pytest.mark.parametrize('path,kind,keys', [
    ('/api/nodes/vless-reality/enabled','nodes',['nodes','chain']),
    ('/api/nodes/chain-a/toggle','nodes',['nodes','chain']),
    ('/api/chain/exit','chain',['chain']),
    ('/api/chain/entries/a/pair','chain',['chain']),
    ('/api/hysteria/hopping','hopping',['hysteria_hopping','hysteria_ports']),
    ('/api/wireguard/settings','wireguard',['wireguard']),
    ('/api/wireguard/peers/a/rotate','wireguard',['wireguard']),
])
def test_guard_protocol_has_explicit_mutation_scope(path,kind,keys):
    assert change_guard.request_keys(path, 'POST') == (kind,keys)
    assert change_guard.request_keys(path, 'GET') is None


@pytest.mark.parametrize('path', ['/api/chain/entries/a/probe','/api/wireguard/peers/a/one-time','/api/wireguard/peers/a/config','/api/changes/a/confirm'])
def test_read_and_probe_actions_never_create_network_safety_snapshots(path):
    assert change_guard.request_keys(path,'POST') is None


def test_node_mutation_arms_and_rollback_restores_only_changed_bucket(client,configured):
    before = config.load_state()
    result = post(client, '/api/nodes/vless-reality/enabled', {'enabled':False})
    assert result['pending_change']['state'] == 'awaiting_confirmation'
    assert config.load_state()['pending_change']['keys'] == ['nodes']
    assert 'before' not in result['pending_change']
    assert client.post('/api/chain/exit', json={}).status_code == 409
    state = config.load_state();state['routing']['template']='global';config.save_state(state)
    rollback(client)
    assert config.load_state()['nodes'] == before['nodes']
    assert config.load_state()['routing']['template'] == 'global'


def test_repeat_safe_node_noop_and_legacy_call_are_compatible(client,configured):
    body = post(client,'/api/nodes/vless-reality/enabled',{'enabled':True})
    assert body['pending_change'] is None
    assert client.post('/api/nodes/vless-reality/toggle').status_code == 200
    assert not config.load_state().get('pending_change')
    assert client.post('/api/nodes/vless-reality/enabled',json={'enabled':True},headers={'X-ZP-Confirm':'bogus'}).status_code == 409


def test_stale_guarded_request_is_rejected_before_mutation(client,configured):
    before=config.load_state()
    response=client.post('/api/nodes/vless-reality/enabled',json={'enabled':False},headers={**GUARD,'X-ZP-Revision':'stale'})
    assert response.status_code == 409
    assert config.load_state()['nodes'] == before['nodes']
    assert not change_guard.active(config.load_state())


def test_async_node_completion_starts_confirmation_only_after_apply(client,configured,monkeypatch):
    monkeypatch.setenv('ZP_APPLY_ASYNC','1')
    entered,release = threading.Event(),threading.Event()
    def reapply(state,**kwargs):
        assert not config.lock_held_here()
        entered.set();assert release.wait(3)
        return [{'ok':True,'name':'test'}]
    monkeypatch.setattr(apply,'reapply',reapply)
    body=post(client,'/api/nodes/vless-reality/enabled',{'enabled':False})
    try:
        assert entered.wait(2)
        assert body['pending_change']['state'] == 'applying'
        assert not body['pending_change']['deadline']
    finally: release.set()
    until=time.time()+3
    while time.time()<until and config.load_state()['pending_change']['state']=='applying': time.sleep(.02)
    assert config.load_state()['pending_change']['state']=='awaiting_confirmation'
    confirm(client)


def test_chain_exit_generation_rotation_disable_and_rollback(client,configured):
    before=copy.deepcopy(config.load_state()['chain'])
    post(client,'/api/chain/exit',{'action':'generate'})
    rollback(client)
    assert config.load_state()['chain']==before
    post(client,'/api/chain/exit',{'action':'generate'});confirm(client)
    original=copy.deepcopy(config.load_state()['chain'])
    post(client,'/api/chain/exit',{'action':'rotate'})
    assert config.load_state()['chain']['exit']['uuid'] != original['exit']['uuid']
    rollback(client)
    assert config.load_state()['chain']==original
    post(client,'/api/chain/exit',{'action':'disable'});rollback(client)
    assert config.load_state()['chain']['exit']['enabled']


def test_chain_add_update_pair_delete_and_compensating_rollback(client,configured,monkeypatch):
    stub_probe(monkeypatch)
    before=copy.deepcopy(config.load_state()['chain'])
    body=post(client,'/api/chain/entries',{'code':code()})
    identity=body['chain']['entries'][0]['id']
    rollback(client)
    assert config.load_state()['chain']==before
    body=post(client,'/api/chain/entries',{'code':code()});confirm(client)
    identity=body['chain']['entries'][0]['id']
    original=copy.deepcopy(config.load_state()['chain'])
    post(client,f'/api/chain/entries/{identity}',{'default_out':True});rollback(client)
    assert config.load_state()['chain']==original
    post(client,f'/api/chain/entries/{identity}/pair',{'code':code('203.0.113.29')});rollback(client)
    assert config.load_state()['chain']==original
    response=client.delete(f'/api/chain/entries/{identity}',headers=GUARD)
    assert response.status_code==200,response.text
    rollback(client)
    assert config.load_state()['chain']==original


def test_chain_probe_concurrency_uses_commit_time_revision_check(client,configured,monkeypatch):
    revision=config.configuration_revision(config.load_state())
    def probe(*a,**kw):
        state=config.load_state();state['nodes']['vless-reality']=False;config.save_state(state)
        return {'ok':True,'probe_ok':True,'detail':'local test','ms':1}
    monkeypatch.setattr(chain,'probe_target',probe)
    response=client.post('/api/chain/entries',json={'code':code()},headers={**GUARD,'X-ZP-Revision':revision})
    assert response.status_code==409,response.text
    assert not config.load_state()['chain']['entries']
    assert not change_guard.active(config.load_state())


def test_hopping_uses_same_confirmation_and_restores_range(client,configured):
    before=config.load_state()
    post(client,'/api/hysteria/hopping');rollback(client)
    state=config.load_state()
    assert state['hysteria_hopping']==before['hysteria_hopping']
    assert state['hysteria_ports']==before['hysteria_ports']


def test_wireguard_enable_and_settings_restored_by_common_apply(client,configured):
    before=copy.deepcopy(config.load_state()['wireguard'])
    body=post(client,'/api/wireguard/settings',{'enabled':True})
    assert body['pending_change']['state']=='awaiting_confirmation'
    rollback(client)
    assert config.load_state()['wireguard']['enabled']==before['enabled']
    post(client,'/api/wireguard/settings',{'enabled':True});confirm(client)
    before=copy.deepcopy(config.load_state()['wireguard'])
    post(client,'/api/wireguard/settings',{'mtu':1320});rollback(client)
    assert config.load_state()['wireguard']['mtu']==before['mtu']


@pytest.mark.parametrize('action',['add','update','rotate','delete'])
def test_wireguard_peer_changes_restore_authorization_and_identity(client,configured,action):
    client.post('/api/wireguard/settings',json={'enabled':True})
    initial=client.post('/api/wireguard/peers',json={'name':'original'}).json()
    peer_id=initial['peer_id']
    before=copy.deepcopy(config.load_state()['wireguard']['peers'])
    if action=='add': result=post(client,'/api/wireguard/peers',{'name':'temporary'})
    elif action=='update': result=post(client,f'/api/wireguard/peers/{peer_id}',{'enabled':False})
    elif action=='rotate': result=post(client,f'/api/wireguard/peers/{peer_id}/rotate')
    else:
        response=client.delete(f'/api/wireguard/peers/{peer_id}',headers=GUARD)
        assert response.status_code==200,response.text
        result=response.json()
    assert result['pending_change']['state']=='awaiting_confirmation'
    rollback(client)
    assert config.load_state()['wireguard']['peers']==before


def test_wireguard_sync_failure_and_exception_queue_recovery(client,configured,monkeypatch):
    def failed(state,**kwargs): return False,'sync failed'
    monkeypatch.setattr(wireguard,'sync',failed)
    result=post(client,'/api/wireguard/settings',{'enabled':True})
    assert result['pending_change']['state']=='rollback_pending'
    assert not result['steps'][0]['ok']
    monkeypatch.setattr(wireguard,'sync',lambda *a,**kw:(True,'restored'))
    rollback(client)
    monkeypatch.setattr(routes.services,'open_firewall_port',lambda *a,**kw: (_ for _ in ()).throw(ValueError('firewall failed')))
    response=client.post('/api/wireguard/settings',json={'enabled':True},headers=GUARD)
    assert response.status_code==409
    assert config.load_state()['pending_change']['state']=='rollback_pending'


def test_rollback_waits_for_wireguard_transaction_before_touching_state(client,configured):
    post(client,'/api/wireguard/settings',{'enabled':True})
    before=copy.deepcopy(config.load_state())
    entered,release=threading.Event(),threading.Event()
    def hold():
        with wireguard.operation(): entered.set();assert release.wait(3)
    worker=threading.Thread(target=hold);worker.start()
    try:
        assert entered.wait(2)
        with pytest.raises(wireguard.OperationBusy): routes.rollback_network_change(force=True)
        assert config.load_state()['wireguard']==before['wireguard']
        assert config.load_state()['pending_change']['state']=='awaiting_confirmation'
        response=client.post(f'/api/changes/{before["pending_change"]["id"]}/rollback')
        assert response.status_code==409,response.text
    finally: release.set();worker.join(2)
    rollback(client)


def test_pending_wireguard_guard_defers_expiry_bookkeeping(client,configured):
    from zeroproxy import main
    client.post('/api/wireguard/settings',json={'enabled':True})
    peer_id=client.post('/api/wireguard/peers',json={'name':'expired'}).json()['peer_id']
    state=config.load_state();wireguard.find_peer(state,peer_id)['expires_at']=1;config.save_state(state)
    post(client,'/api/wireguard/settings',{'mtu':1320})
    before=copy.deepcopy(config.load_state()['wireguard'])
    main._wireguard_once()
    assert config.load_state()['wireguard']==before
    confirm(client)
    main._wireguard_once()
    assert wireguard.find_peer(config.load_state(),peer_id)['enabled'] is False


def test_guard_keeps_existing_pair_failure_compensation(client,configured,monkeypatch):
    stub_probe(monkeypatch)
    added=client.post('/api/chain/entries',json={'code':code()}).json()
    identity=added['chain']['entries'][0]['id']
    original=copy.deepcopy(config.load_state()['chain'])
    calls=[]
    def reapply(state,**kw):
        calls.append(1)
        return [{'name':'apply','ok':len(calls)>1,'detail':'failed first apply' if len(calls)==1 else 'restored'}]
    monkeypatch.setattr(apply,'reapply',reapply)
    result=post(client,f'/api/chain/entries/{identity}/pair',{'code':code('203.0.113.29')})
    assert result['pending_change']['state']=='rollback_pending'
    assert result['steps'][-1]['name']=='恢复原配对参数' and result['steps'][-1]['ok']
    assert config.load_state()['chain']==original
    rollback(client)
    assert config.load_state()['chain']==original


def test_backup_remains_available_during_network_confirmation(client,configured):
    post(client,'/api/nodes/vless-reality/enabled',{'enabled':False})
    response=client.post('/api/backup',json={'encrypt':0})
    assert response.status_code==200,response.text
    assert response.json()['checksum']


def test_explicit_force_keeps_failed_probe_as_warning_not_automatic_revert(client,configured,monkeypatch):
    monkeypatch.setattr(chain,'probe_target',lambda *a,**kw:{'ok':False,'probe_ok':True,'detail':'unreachable'})
    result=post(client,'/api/chain/entries',{'code':code(),'force':True})
    assert result['pending_change']['state']=='awaiting_confirmation'
    assert result['chain']['entries'][0]['last_probe']['ok'] is False
    observation=next(s for s in result['steps'] if s.get('probe_observation'))
    assert observation['warning'] and observation['probe_ok'] is False
    assert observation['ok']  # Accepted add, not a claim that the probe passed.
    confirm(client)
    assert config.load_state()['chain']['entries']


def test_repeated_rollback_attempts_never_override_external_configuration(client,configured):
    post(client,'/api/nodes/vless-reality/enabled',{'enabled':False})
    state=config.load_state();state['nodes']['trojan']=False;config.save_state(state)
    identity=state['pending_change']['id']
    for _ in range(2):
        response=client.post(f'/api/changes/{identity}/rollback')
        assert response.status_code==200,response.text
        assert response.json()['ok'] is False
        assert config.load_state()['nodes']==state['nodes']
    event=config.audit_view(config.load_state()['audit'][-1])
    assert event['action']=='network_rollback_failed'
    assert event['ok'] is False and event['label']=='网络回滚失败'
