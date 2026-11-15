"""Exercise the real router request/render path with the raw CGI/zpcore contract."""
import subprocess
from pathlib import Path


def test_router_raw_proxy_contract_and_group_selection():
    root = Path(__file__).resolve().parents[2]
    script = r'''
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const src = fs.readFileSync(process.argv[1], 'utf8');
const elements = {};
const element = id => elements[id] ||= {
  dataset: {state: 'ready'}, textContent: '', innerHTML: '',
  querySelectorAll: () => [],
};
let response;
const ctx = vm.createContext({
  document: {documentElement: {dataset: {}}, getElementById: element},
  location: {search: ''}, URLSearchParams, Date,
  fetch: async () => ({ok: response.status < 400, status: response.status,
    json: async () => response.body}),
});
vm.runInContext(src.slice(0, src.indexOf('// 一键测速所有节点')), ctx);
const run = code => vm.runInContext(code, ctx);
async function reply(body, code, status = 200) {
  response = {body, status};
  return await run(code);
}
(async () => {
  run("currentState = {core:'running', mode:'tun', routing_mode:'rule'}");
  const proxies = {
    DIRECT: {type:'Direct'},
    GLOBAL: {all:['DIRECT','node-a'], now:'DIRECT'},
    '🚀 节点选择': {all:['node-a','node-b'], now:'node-a'},
    'node-a': {type:'Trojan', history:[{delay:186}]},
    'node-b': {type:'Hysteria2', alive:false, history:[{delay:0}]},
  };
  await reply({proxies}, 'loadProxies()');
  assert.equal(element('cur-node-title').textContent, 'node-a',
    'raw successful proxies must render the rule group even when GLOBAL precedes it');
  assert.match(element('nodes-container').innerHTML, /186 ms/);
  assert.match(element('nodes-container').innerHTML, /探测失败/,
    'a recorded zero-delay failure must not look like an untested node');
  assert.equal(element('rf-route').textContent, 'node-a');
  run("currentState.routing_mode = 'global'");
  await reply({ok:true,proxies}, 'loadProxies()');
  assert.equal(element('cur-node-title').textContent, 'DIRECT');
  run("currentState.routing_mode = 'rule'");
  const noNamedGroup = {DIRECT:proxies.DIRECT, GLOBAL:proxies.GLOBAL};
  await reply({proxies:noNamedGroup}, 'loadProxies()');
  assert.equal(element('cur-node-title').textContent, 'DIRECT');
  for (const delay of [0, 186]) {
    const result = await reply({delay}, "call('test-delay', {name:'node-a'})");
    assert.equal(result.delay, delay);
  }
  for (const body of [{ok:false,proxies}, {proxies:null}, {proxies:[]}, {}, null]) {
    await assert.rejects(reply(body, "call('proxies')"));
  }
  for (const body of [{delay:'186'}, {delay:-1}, {ok:false,delay:186}, {}]) {
    await assert.rejects(reply(body, "call('test-delay', {name:'node-a'})"));
  }
  await assert.rejects(reply({proxies}, "call('proxies')", 401));
  await assert.rejects(reply({message:'done'}, "call('select-node', {name:'node-a'})"));
  await reply({ok:false,error:'控制接口不可用'}, 'loadProxies()');
  assert.equal(element('cur-node-title').textContent, '代理组状态未知');
  assert.equal(element('btn-ping-all').disabled, true);
  await reply({proxies}, 'loadProxies()');
  assert.equal(element('cur-node-title').textContent, 'node-a');
  assert.equal(element('btn-ping-all').disabled, false);
  console.log('PASS: raw proxies, delay, group priority, errors and recovery');
})().catch(e => {console.error(e); process.exitCode=1;});
'''
    result = subprocess.run(
        ['node', '-e', script, str(root / 'backend/zeroproxy/client/luci/app.js')],
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_router_cli_encodes_node_names_without_switching_another_group(tmp_path):
    import os

    root = Path(__file__).resolve().parents[2]
    source = (root / 'backend/zeroproxy/client/runtime/cli').read_text()
    section = source[source.index('    select-node)'):source.index('    mode)')]
    # Include the actual helper if this runtime version defines it.
    import re
    helper = re.search(r'^uri_component\(\) \{.*?^\}', source, re.M | re.S)
    script = tmp_path / 'cli'
    script.write_text('#!/bin/sh\n' + (helper.group(0) if helper else '') + '\ncase "$1" in\n' + section + '\nesac\n')
    calls = tmp_path / 'calls'
    curl = tmp_path / 'curl'
    curl.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALLS"\ncase "$*" in\n*delay*) printf \'{"delay":186}\' ;;\n*) printf "%s" "$HTTP_CODE" ;;\nesac\n')
    curl.chmod(0o755)
    env = {**os.environ, 'PATH': str(tmp_path) + ':' + os.environ['PATH'],
           'CALLS': str(calls), 'HTTP_CODE': '204'}
    for action, name in [('select-node', '🚀 节点选择'), ('test-delay', 'ZeroProxy Hysteria 2'),
                         ('test-delay', '节点/+?#%\\名字\n')]:
        args = [name, 'ZeroProxy Trojan'] if action == 'select-node' else [name]
        result = subprocess.run(['sh', str(script), action, *args], env=env, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        url = calls.read_text().splitlines()[-1].split()[-1]
        from urllib.parse import unquote
        path = url.split('/proxies/')[1].split('/delay')[0]
        assert unquote(path) == name, (name, path)
    calls.write_text('')
    result = subprocess.run(['sh', str(script), 'select-node', '🚀 节点选择', 'ZeroProxy Trojan'],
                            env={**env, 'HTTP_CODE': '404'}, capture_output=True, text=True)
    assert result.returncode != 0
    assert len(calls.read_text().splitlines()) == 1, 'failed selection must not change GLOBAL instead'
