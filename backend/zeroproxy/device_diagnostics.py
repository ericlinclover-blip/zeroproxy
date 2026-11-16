"""One-shot, bounded device evidence. Never accepts commands or probe destinations."""
from __future__ import annotations
import copy
import time
import uuid

STAGES = ('device', 'dns', 'takeover', 'entry', 'exit', 'target')
STATUSES = {'passed', 'failed', 'unknown', 'observed'}
TTL = 120


def view(device: dict, now: float | None = None) -> dict | None:
    item = device.get('diagnostic')
    if not isinstance(item, dict):
        return None
    result = copy.deepcopy(item)
    now = time.time() if now is None else now
    if result['state'] == 'queued' and now >= result['expires_at']:
        result['state'] = 'expired'
    result['stale'] = result['state'] == 'completed' and now - result.get('checked_at', 0) > 300
    return result


def start(device: dict, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    if str((device.get('report') or {}).get('diagnostics')) != '1':
        raise ValueError('请先升级路由器客户端至支持分阶段诊断的版本')
    current = view(device, now)
    if current and current['state'] == 'queued':
        return current
    device['diagnostic'] = {'id': uuid.uuid4().hex, 'state': 'queued', 'requested_at': now,
                            'expires_at': now + TTL, 'checked_at': 0, 'stages': {}}
    return view(device, now)


def accept(device: dict, payload: dict | None, now: float | None = None) -> bool:
    now = time.time() if now is None else now
    current = view(device, now)
    if not payload or not current or current['state'] != 'queued' or payload.get('id') != current['id']:
        return False
    evidence = payload.get('evidence')
    if not isinstance(evidence, dict):
        return False
    item = device['diagnostic']
    item['stages'] = {key: evidence.get(key) if isinstance(evidence.get(key), str) and evidence[key] in STATUSES else 'unknown' for key in STAGES}
    item['state'], item['checked_at'] = 'completed', now
    item['scope'] = 'router-proxy'  # A router-local probe does not prove the LAN client path.
    for key in ('packets', 'dns_packets', 'http_status'):
        value = evidence.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 2**53 - 1:
            item[key] = value
    return True


def request_id(device: dict) -> str:
    current = view(device)
    return current['id'] if current and current['state'] == 'queued' else ''
