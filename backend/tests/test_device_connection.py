"""Control-channel liveness and data-plane evidence expire independently."""
from zeroproxy import devices


def test_subscription_cannot_renew_control_channel(monkeypatch):
    monkeypatch.setattr(devices, '_now', lambda: 1000)
    device = {'actual': True, 'actual_at': 850, 'control_seen': 850,
              'last_seen': 850, 'report': {'covered': 'full'}, 'report_at': 850}
    devices.touch({}, device, {'downloaded_rev': 'new'}, heartbeat=False)
    assert device['last_seen'] == 1000
    assert device['control_seen'] == 850
    assert not devices.online(device)
    view = devices.device_view(device)
    assert view['connection_state'] == 'offline'
    assert not view['connected']
    assert not view['running']


def test_heartbeat_without_evidence_cannot_revalidate_old_state(monkeypatch):
    monkeypatch.setattr(devices, '_now', lambda: 1000)
    device = {'desired': True, 'actual': True, 'actual_at': 850,
              'control_seen': 850, 'report': {'covered': 'full'}, 'report_at': 850}
    devices.touch({}, device, {'version': 'new'})
    view = devices.device_view(device)
    assert view['online']
    assert view['connection_state'] == 'stale'
    assert not view['running']
    assert not view['connected']


def test_recovery_requires_fresh_running_and_coverage_reports(monkeypatch):
    monkeypatch.setattr(devices, '_now', lambda: 1000)
    device = {'desired': True, 'control_seen': 800, 'actual': False}
    devices.touch({}, device, {'actual': True, 'report': {'covered': 'full'}})
    view = devices.device_view(device)
    assert view['connection_state'] == 'online'
    assert view['state_fresh']
    assert view['connected']
    assert devices.device_view(device, now=1091)['connected'] is False


def test_local_override_does_not_claim_panel_is_syncing(monkeypatch):
    monkeypatch.setattr(devices, '_now', lambda: 1000)
    device = {'desired': True}
    devices.touch({}, device, {'actual': False, 'report': {'override': 'off', 'covered': 'none'}})
    view = devices.device_view(device)
    assert view['control'] == 'local'
    assert not view['syncing']


def test_new_registration_waits_for_first_heartbeat(monkeypatch):
    monkeypatch.setattr(devices, '_now', lambda: 1000)
    device = {'last_seen': 1000, 'control_seen': 0, 'actual': False}
    view = devices.device_view(device)
    assert view['connection_state'] == 'waiting'
    assert not view['online']


def test_legacy_subscription_migrates_using_actual_evidence(monkeypatch):
    monkeypatch.setattr(devices, '_now', lambda: 1000)
    device = {'last_seen': 990, 'actual_at': 800, 'actual': True}
    devices.touch({}, device, {'downloaded_rev': 'new'}, heartbeat=False)
    assert device['control_seen'] == 800
    assert not devices.online(device)


def test_subscription_endpoint_cannot_mask_lost_heartbeat(client, configured, monkeypatch):
    from zeroproxy import config
    code = client.post('/api/devices/pair', json={}).json()['code']
    paired = client.post('/c/pair', json={'code': code}).json()
    now = devices._now()
    with config.locked():
        state = config.load_state()
        device = devices.find(state, paired['id'])
        device.update(control_seen=now - 100, actual_at=now - 100,
                      actual=True, report={'covered': 'full'}, report_at=now - 100)
        config.save_state(state)
    response = client.get(f"/c/sub/{paired['id']}", headers={'Authorization': f"Bearer {paired['secret']}"})
    assert response.status_code == 200
    item = client.get('/api/devices').json()['devices']['items'][0]
    assert not item['online']
    assert not item['connected']


def test_fresh_stop_does_not_require_old_coverage_evidence(monkeypatch):
    monkeypatch.setattr(devices, '_now', lambda: 1000)
    device = {'desired': False, 'control_seen': 800, 'actual': True,
              'report_at': 800, 'report': {'covered': 'full'}}
    devices.touch({}, device, {'actual': False})
    view = devices.device_view(device)
    assert view['state_fresh']
    assert view['connection_state'] == 'online'
    assert not view['running']
    assert not view['taking_over']
