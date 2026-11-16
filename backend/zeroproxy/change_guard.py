"""Durable, explicitly confirmed network changes. No service calls under state locks."""
from __future__ import annotations
import copy
import hashlib
import json
import re
import time
import uuid

from . import config

INSTANCE = uuid.uuid4().hex
ACTIVE = {'applying', 'awaiting_confirmation', 'rollback_pending', 'rolling_back'}
DEFAULT_TIMEOUT = 90


class ChangeBusy(RuntimeError):
    pass


def active(state: dict) -> bool:
    return (state.get('pending_change') or {}).get('state') in ACTIVE


def authorize_write(state: dict, path: str, method: str) -> None:
    if method in {'GET', 'HEAD', 'OPTIONS'} or not active(state):
        return
    allowed = {'/api/login', '/api/logout', '/api/logout-all', '/api/session/handoff', '/api/routing/analyze', '/api/backup'}
    if path in allowed or path.startswith('/api/changes/') or path.endswith('/diagnose'):
        return
    raise ChangeBusy('有网络变更等待确认或回滚，请先保留或撤销该变更')


def request_keys(path: str, method: str) -> tuple[str, list[str]] | None:
    """Only explicit network mutations can opt into the confirmation protocol."""
    if method not in {'POST', 'DELETE'}:
        return None
    if re.fullmatch(r'/api/nodes/[^/]+/(enabled|toggle)', path):
        return 'nodes', ['nodes', 'chain']
    if path == '/api/hysteria/hopping':
        return 'hopping', ['hysteria_hopping', 'hysteria_ports']
    if path == '/api/chain/exit' or re.fullmatch(r'/api/chain/entries(?:/[^/]+(?:/pair)?)?', path):
        return 'chain', ['chain']
    if path == '/api/wireguard/settings' or re.fullmatch(r'/api/wireguard/peers(?:/[^/]+(?:/rotate)?)?', path):
        return 'wireguard', ['wireguard']
    return None


def fingerprint(state: dict, keys: list[str]) -> str:
    payload = {key: state.get(key) for key in keys}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


def begin(state: dict, before: dict, kind: str, keys: list[str], timeout: int = DEFAULT_TIMEOUT) -> str:
    if active(state):
        raise ChangeBusy('已有网络变更在处理，请先完成确认或回滚')
    if not 30 <= timeout <= 300:
        raise ValueError('确认时限应在 30–300 秒之间')
    identity = uuid.uuid4().hex
    state['pending_change'] = {'id': identity, 'kind': kind, 'state': 'applying', 'instance': INSTANCE,
                               'created_at': time.time(), 'timeout': timeout, 'deadline': 0,
                               'keys': keys, 'before': {key: copy.deepcopy(before.get(key)) for key in keys},
                               'target': fingerprint(state, keys), 'error': ''}
    return identity


def finish(identity: str, steps: list[dict], error: str = '') -> None:
    with config.locked():
        state = config.load_state()
        pending = state.get('pending_change') or {}
        if pending.get('id') != identity or pending.get('state') != 'applying':
            return
        failed_step = next((item for item in steps if not item.get('ok')), None)
        failed = error or ((failed_step.get('detail') or '应用失败') if failed_step is not None else '')
        if failed:
            pending.update(state='rollback_pending', error=failed)
        else:
            pending.update(state='awaiting_confirmation', deadline=time.time() + pending['timeout'],
                           target=fingerprint(state, pending['keys']))
        config.save_state(state)


def view(state: dict, now: float | None = None) -> dict | None:
    pending = state.get('pending_change')
    if not isinstance(pending, dict):
        return None
    now = time.time() if now is None else now
    result = {key: pending.get(key) for key in ('id', 'kind', 'state', 'deadline', 'error')}
    result['remaining'] = max(0, int((pending.get('deadline') or 0) - now))
    return result


def due(state: dict, now: float | None = None) -> bool:
    pending = state.get('pending_change') or {}
    if not active(state):
        return False
    now = time.time() if now is None else now
    return (pending.get('instance') != INSTANCE or pending['state'] == 'rollback_pending'
            or pending['state'] == 'rolling_back'
            or (pending['state'] == 'awaiting_confirmation' and now >= pending.get('deadline', 0))
            or (pending['state'] == 'applying' and now - pending.get('created_at', 0) > 600))


def confirm(state: dict, identity: str, now: float | None = None) -> None:
    pending = state.get('pending_change') or {}
    if pending.get('id') != identity:
        raise ValueError('变更不存在或已被替换')
    if pending['state'] == 'confirmed':
        return
    now = time.time() if now is None else now
    if pending['state'] != 'awaiting_confirmation' or now >= pending.get('deadline', 0):
        raise ValueError('变更已超时或不再等待确认，请核对回滚结果')
    if fingerprint(state, pending['keys']) != pending.get('target'):
        raise ValueError('待确认配置发生变化，不能确认旧版本')
    pending.update(state='confirmed', before={}, error='')
    config.audit(state, 'network_confirm', f'{identity}: 已保留临时配置')
