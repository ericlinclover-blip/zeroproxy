"""Authenticated installation telemetry. It never controls data-plane liveness."""
from __future__ import annotations

import re
import time

STAGES = {
    'paired': '已接入，正在准备环境',
    'dependencies': '检查网络能力与必要模块',
    'core': '准备代理内核',
    'runtime': '安装运行组件与分流数据',
    'controller': '代理已完成基础自检，正在准备本地控制面',
    'verify': '启动并验证代理',
    'ui': '代理已完成基础自检，正在配置管理界面',
    'optional': '代理已完成基础自检，正在完善性能模式',
    'ready': '安装流程已完成，请验证实际出网',
}
STATES = {'running', 'failed', 'completed'}
STALE_AFTER = 120


def accept(device: dict, payload: dict, now: int | None = None) -> bool:
    now = int(time.time()) if now is None else now
    identity = str(payload.get('id') or '')
    stage, status = payload.get('stage'), payload.get('status')
    sequence = payload.get('seq')
    if (not re.fullmatch('[0-9a-f]{32}', identity) or stage not in STAGES or status not in STATES
            or type(sequence) is not int or not 1 <= sequence <= 10000
            or (status == 'completed' and stage != 'ready')):
        raise ValueError('安装进度格式无效')
    previous = device.get('installation') or {}
    retired = list(device.get('installation_history') or [])
    if identity != previous.get('id'):
        if identity in retired:
            return False
        if previous.get('id'):
            retired.append(previous['id'])
            device['installation_history'] = retired[-16:]
        previous = {'id': identity, 'started_at': now}
    elif (sequence < previous.get('seq', 0)
          or previous.get('status') in {'failed', 'completed'}):
        return False
    # A pulse can renew the current stage, but cannot change it with an old seq.
    if sequence == previous.get('seq'):
        if stage != previous.get('stage') or status != previous.get('status'):
            return False
        if now - int(previous.get('updated_at') or 0) < 15:
            return False
    error = str(payload.get('error') or '')[:160] if status == 'failed' else ''
    previous.update(seq=sequence, stage=stage, status=status, updated_at=now, error=error)
    device['installation'] = previous
    return True


def view(device: dict, now: int | None = None) -> dict | None:
    item = device.get('installation')
    if not isinstance(item, dict) or item.get('stage') not in STAGES:
        return None
    now = int(time.time()) if now is None else now
    status = item.get('status')
    if status == 'running' and now - int(item.get('updated_at') or 0) > STALE_AFTER:
        status = 'interrupted'
    return {**item, 'status': status, 'label': STAGES[item['stage']]}
