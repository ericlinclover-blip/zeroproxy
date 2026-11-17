#!/usr/bin/env python3
"""Validate generated profiles and live controller reload on loopback, without TUN/root."""
from __future__ import annotations
import argparse
import http.server
import json
import os
from pathlib import Path
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'backend'))


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));return sock.getsockname()[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',required=True,type=Path)
    parser.add_argument('--rules-experiment',action='store_true',help='compare YAML/MRS for 25k synthetic domain rules')
    args=parser.parse_args();binary=str(args.binary.resolve())
    from zeroproxy import config,crypto,share_links
    import yaml
    checks=[];experiment=None
    with tempfile.TemporaryDirectory(prefix='zp-mihomo-check-') as directory:
        home=Path(directory);os.environ['ZP_HOME']=directory
        state=config.load_state();state.update(configured=True,domain='proxy.example.com',uuid=str(uuid.uuid4()),trojan_password='test-trojan-only',hysteria_password='test-hysteria-only')
        private,public,short=crypto.new_reality_keys()
        state['reality'].update(private_key=private,public_key=public,short_id="12345e67")
        def validate(name,profile):
            path=home/(name+'.yaml');path.write_text(profile)
            proc=subprocess.run([binary,'-t','-d',directory,'-f',str(path)],capture_output=True,text=True,timeout=20)
            if proc.returncode:raise RuntimeError(f'{name}: '+(proc.stdout+proc.stderr)[-1200:])
            checks.append(name)
        for template in ('smart','precision','global','direct'):
            validate(template,share_links.clash_profile(state,template=template,geo=False))
            for datapath in ('tun','tproxy','redirect','none'):
                for ipv6 in (False,True):
                    validate(f'{template}-{datapath}-{ipv6}',share_links.clash_profile(state,template=template,router=True,geo=False,base='https://proxy.example.com',datapath=datapath,ipv6=ipv6))
        # Exercise immutable file providers produced by the new multi-panel path.
        provider=home/'providers';provider.mkdir()
        for name in ('a','b'):(provider/f'{name}-revision.yaml').write_text(share_links.provider_profile(state,prefix=name))
        profile=yaml.safe_load(share_links.clash_profile(state,router=True,skeleton=True,geo=False))
        profile['proxy-providers']={name:{'type':'file','path':f'./providers/{name}-revision.yaml'} for name in ('a','b')}
        for group in profile['proxy-groups']:
            if 'use' in group:group['use']=['a','b']
        validate('multi-panel-file-providers',yaml.safe_dump(profile,allow_unicode=True))
        if args.rules_experiment:
            rules_path=home/'synthetic-rules.yaml'
            rules_path.write_text(yaml.safe_dump({'payload':[f'+.d{i}.example' for i in range(25000)]}))
            mrs_path=home/'synthetic-rules.mrs'
            converted=subprocess.run([binary,'convert-ruleset','domain','yaml',str(rules_path),str(mrs_path)],capture_output=True,text=True,timeout=20)
            if converted.returncode:raise RuntimeError('MRS conversion failed: '+converted.stderr)
            experiment={'kind':'25k synthetic domains; not equivalent to full GeoSite/GeoIP'}
            for kind,target in [('yaml',rules_path),('mrs',mrs_path)]:
                candidate={'mode':'rule','log-level':'error','rule-providers':{'experiment':{'type':'file','behavior':'domain','format':kind,'path':str(target)}},'rules':['RULE-SET,experiment,DIRECT','MATCH,DIRECT']}
                path=home/f'experiment-{kind}.yaml';path.write_text(yaml.safe_dump(candidate))
                durations=[]
                for _ in range(5):
                    started=time.perf_counter()
                    proc=subprocess.run([binary,'-t','-d',directory,'-f',str(path)],capture_output=True,text=True,timeout=20)
                    if proc.returncode:raise RuntimeError(proc.stdout+proc.stderr)
                    durations.append((time.perf_counter()-started)*1000)
                experiment[kind]={'bytes':target.stat().st_size,'validation_p50_ms':round(statistics.median(durations),3),'samples':5}
        class Stream(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200);self.send_header('Content-Length','20');self.end_headers()
                for _ in range(20):self.wfile.write(b'x');self.wfile.flush();time.sleep(.05)
            def log_message(self,*a):pass
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Stream)
        worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
        mixed,controller=port(),port()
        live={'mixed-port':mixed,'external-controller':f'127.0.0.1:{controller}','mode':'rule','log-level':'error','proxies':[{'name':'before','type':'direct'}],'rules':['MATCH,DIRECT']}
        live_path=home/'live.yaml';live_path.write_text(yaml.safe_dump(live))
        process=subprocess.Popen([binary,'-d',directory,'-f',str(live_path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            for _ in range(100):
                try:
                    with opener.open(f'http://127.0.0.1:{controller}/version',timeout=.2):break
                except OSError:time.sleep(.05)
            else:raise RuntimeError('controller did not start')
            with socket.create_connection(('127.0.0.1',mixed),timeout=5) as connection:
                connection.sendall(f'GET http://127.0.0.1:{server.server_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{server.server_port}\r\nConnection: close\r\n\r\n'.encode())
                body=b''
                while b'\r\n\r\n' not in body:body+=connection.recv(4096)
                header,data=body.split(b'\r\n\r\n',1)
                live['proxies']=[{'name':'after','type':'direct'}];live_path.write_text(yaml.safe_dump(live))
                request=urllib.request.Request(f'http://127.0.0.1:{controller}/configs?force=false',data=json.dumps({'path':str(live_path)}).encode(),headers={'Content-Type':'application/json'},method='PUT')
                with opener.open(request,timeout=5) as response:
                    if response.status!=204:raise RuntimeError('reload did not return 204')
                while len(data)<20:
                    chunk=connection.recv(4096)
                    if not chunk:break
                    data+=chunk
                if data!=b'x'*20 or process.poll() is not None:raise RuntimeError(f'reload interrupted stream: header={header!r} data={data!r} process={process.poll()}')
                with opener.open(f'http://127.0.0.1:{controller}/proxies',timeout=2) as response:
                    if 'after' not in json.load(response)['proxies']:raise RuntimeError('new proxy collection not active')
                checks.append('reload-keeps-stream-and-activates-new-proxies')
        finally:
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait()
            server.shutdown();server.server_close();worker.join(2)
    print(json.dumps({'passed':len(checks),'checks':checks,'rules_experiment':experiment,'scope':'local syntax and HTTP stream, no OpenWrt datapath or WAN throughput'},indent=2))

if __name__=='__main__':main()
