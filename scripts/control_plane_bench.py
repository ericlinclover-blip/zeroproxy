#!/usr/bin/env python3
"""Isolated lock-contention benchmark; no production paths, services or network.

Compares slow dashboard collection with and without the former state-lock scope.
Numbers describe this fault-injection workload, not production throughput.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import statistics
import sys
import tempfile
import threading
import time
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'backend'))


def run(samples: int, delay: float, legacy_lock: bool) -> dict:
    from fastapi.testclient import TestClient
    from zeroproxy import config, routes
    from zeroproxy.main import create_app
    timings=[]
    with tempfile.TemporaryDirectory(prefix='zp-control-bench-') as directory:
        environment={'ZP_HOME':directory,'ZP_STATIC':str(ROOT/'backend/static'),
                     'ZP_PUBLIC_IP':'0','ZP_GEODATA_AUTO':'0','ZP_WIREGUARD_AUTO':'0',
                     'ZP_CHANGE_GUARD_AUTO':'0'}
        with patch.dict(os.environ,environment),patch.object(routes,'_require_auth',return_value=True):
            state=config.load_state();state['configured']=True;config.save_state(state)
            entered=threading.Event()
            def slow_collection(*args,**kwargs):
                if legacy_lock:
                    with config.locked():
                        entered.set();time.sleep(delay)
                else:
                    entered.set();time.sleep(delay)
                return {}
            with patch.object(routes,'_dashboard_body',side_effect=slow_collection),TestClient(create_app()) as client,ThreadPoolExecutor(max_workers=1) as pool:
                for _ in range(samples):
                    entered.clear()
                    dashboard=pool.submit(client.get,'/api/dashboard')
                    if not entered.wait(3):raise RuntimeError('dashboard did not enter sampling')
                    started=time.perf_counter()
                    response=client.get('/api/audit')
                    timings.append((time.perf_counter()-started)*1000)
                    if response.status_code!=200:raise RuntimeError('foreground request failed')
                    if dashboard.result(timeout=delay+5).status_code!=200:raise RuntimeError('dashboard failed')
    ordered=sorted(timings)
    return {'samples':samples,'p50_ms':round(statistics.median(timings),3),
            'p95_ms':round(ordered[max(0,int(.95*len(ordered)+.999)-1)],3),
            'max_ms':round(max(timings),3)}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--samples',type=int,default=20)
    parser.add_argument('--delay',type=float,default=.2)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if not 2<=args.samples<=100 or not .01<=args.delay<=2:parser.error('samples 2–100, delay .01–2 seconds')
    result={'kind':'isolated fault injection, not WAN benchmark','delay_ms':args.delay*1000,
            'former_lock_scope':run(args.samples,args.delay,True),
            'current_lock_scope':run(args.samples,args.delay,False)}
    text=json.dumps(result,ensure_ascii=False,indent=2)
    print(text)
    if args.output:args.output.write_text(text+'\n')

if __name__=='__main__':main()
