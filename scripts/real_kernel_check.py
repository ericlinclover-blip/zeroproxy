#!/usr/bin/env python3
"""Run real-core acceptance, refusing to turn missing binaries into skipped checks."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CASES = [
    'backend/tests/test_chain.py::test_xray_config_with_real_binary_includes_chain',
    'backend/tests/test_chain.py::test_quic_processes_start_and_stop',
    'backend/tests/test_panel.py::test_xray_config_with_real_binary',
    'backend/tests/test_panel.py::test_reality_keys_match_real_xray',
    'backend/tests/test_panel.py::test_deep_probe_reports_failure_when_node_is_dead',
    'backend/tests/test_panel.py::test_geodata_guard_self_heals_missing_cert',
    'backend/tests/test_real_kernel_policy.py',
]


def cached_binary(cache: Path, kind: str) -> str:
    for item in sorted((cache / kind).glob('*/provenance.json'), key=lambda p:p.stat().st_mtime, reverse=True):
        try:
            path = Path(json.loads(item.read_text())['binary'])
            if path.is_file() and os.access(path, os.X_OK): return str(path)
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return ''


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--all',action='store_true',help='run the complete backend suite with both real cores')
    parser.add_argument('--xray',default=os.environ.get('ZP_XRAY_BIN',''))
    parser.add_argument('--hysteria',default=os.environ.get('ZP_HYSTERIA2_BIN',''))
    parser.add_argument('--cache',type=Path,default=Path.home()/'Library/Caches/ZeroProxy/real-kernels')
    args=parser.parse_args()
    environment=os.environ.copy()
    for kind,override,key in [('xray',args.xray,'ZP_XRAY_BIN'),('hysteria',args.hysteria,'ZP_HYSTERIA2_BIN')]:
        binary=override or cached_binary(args.cache,kind)
        if not binary or not Path(binary).is_file() or not os.access(binary,os.X_OK):
            parser.error(f'{kind}: provide an executable via {key} or --{kind}; acceptance cannot skip missing cores')
        version=subprocess.run([binary,'version'],capture_output=True,text=True,timeout=15)
        if version.returncode:
            parser.error(f'{kind}: version command failed ({version.returncode})')
        environment[key]=str(Path(binary).resolve())
        print(f'{kind}: {environment[key]}',flush=True)
    tests=['backend/tests'] if args.all else CASES
    return subprocess.call([sys.executable,'-m','pytest',*tests,'-q','-rs'],cwd=ROOT,env=environment)


if __name__=='__main__': raise SystemExit(main())
