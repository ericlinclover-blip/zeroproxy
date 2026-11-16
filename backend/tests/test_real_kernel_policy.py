"""Live regression for the private-network fallback rejected by real Xray."""
import http.server
import json
import os
import socket
import subprocess
import threading
import time

import pytest
from zeroproxy import config, services, xray_config


def test_xray_error_reports_the_cause_after_a_long_banner(home, monkeypatch):
    monkeypatch.setattr(services,'bin_path',lambda name:'/isolated/xray')
    reason='CIDR prefix length 96 exceeds max 32'
    monkeypatch.setattr(services,'run',lambda *a,**kw:(False,'version banner ' * 50 + 'Failed to start: '+reason))
    ok,detail=services.xray_config_test()
    assert not ok and reason in detail[:180]
    assert len(detail)<=600


@pytest.mark.skipif(not os.environ.get('ZP_XRAY_BIN'),reason='需要真实 xray 二进制 (ZP_XRAY_BIN)')
def test_real_xray_private_policy_blocks_mapped_ipv4_without_blocking_control(home, tmp_path):
    binary=services.bin_path('xray')
    hits=[]
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            body=b'isolated-real-kernel-control'
            self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        def log_message(self,*args): pass
    target=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    worker=threading.Thread(target=target.serve_forever,daemon=True);worker.start()
    try:
        for block_private in (False,True):
            with socket.socket() as reserve:
                reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1]
            state=config.load_state();state.setdefault('geodata',{})['enabled']=False;state['geodata']['block_private']=block_private
            document={'log':{'loglevel':'error'},'inbounds':[{'listen':'127.0.0.1','port':port,'protocol':'http','settings':{}}],
                      'outbounds':[{'tag':'direct','protocol':'freedom'},{'tag':'block','protocol':'blackhole'}],
                      'routing':{'domainStrategy':'IPOnDemand','rules':xray_config.geo_rules(state)}}
            path=tmp_path/'mapped-policy.json';path.write_text(json.dumps(document))
            process=subprocess.Popen([binary,'run','-c',str(path)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            try:
                deadline=time.monotonic()+5
                while time.monotonic()<deadline:
                    assert process.poll() is None, 'isolated Xray exited before listening'
                    try:
                        with socket.create_connection(('127.0.0.1',port),timeout=.2): break
                    except OSError: time.sleep(.03)
                else: pytest.fail('isolated Xray did not listen')
                before=len(hits)
                result=subprocess.run(['curl','--silent','--show-error','--noproxy','','--proxy',f'http://127.0.0.1:{port}',
                                       '--max-time','3',f'http://[::ffff:127.0.0.1]:{target.server_port}/control'],capture_output=True,timeout=5)
                if block_private:
                    assert b'isolated-real-kernel-control' not in result.stdout
                    assert len(hits)==before, 'mapped IPv4 bypassed private-network policy'
                else:
                    assert result.returncode==0,result.stderr
                    assert result.stdout==b'isolated-real-kernel-control' and len(hits)==before+1
            finally:
                process.terminate()
                try: process.communicate(timeout=3)
                except subprocess.TimeoutExpired: process.kill();process.communicate(timeout=3)
    finally:
        target.shutdown();target.server_close();worker.join(2)
