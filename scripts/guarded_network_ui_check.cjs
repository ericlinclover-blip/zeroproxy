/** Isolated behavior checks for the interaction audit. Uses existing Playwright/Chromium. */
const fs = require('fs'), os = require('os'), path = require('path'), net = require('net');
const { spawn } = require('child_process');
for (const extra of (process.env.ZP_NODE_PATH || '').split(path.delimiter)) if(extra) module.paths.push(extra);
const { chromium } = require('playwright');
const ROOT = path.resolve(__dirname,'..');
const check = (name, ok, detail='') => { console.log(`${ok?'✓':'✗'} ${name}${detail?' — '+detail:''}`); if(!ok) throw new Error(name); };
(async()=>{
 const home = fs.mkdtempSync(path.join(os.tmpdir(),'zp-audit-ui-'));
 fs.mkdirSync(home+'/data');fs.writeFileSync(home+'/data/bootstrap_token','audit-ui-token');
 const port = await new Promise(resolve=>{const s=net.createServer();s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>resolve(p));});});
 const base = `http://127.0.0.1:${port}`;
 const server = spawn(process.env.ZP_PYTHON || 'python3',['-m','zeroproxy.main'],{cwd:ROOT+'/backend',env:{...process.env,ZP_HOME:home,ZP_STATIC:ROOT+'/backend/static',ZP_BIND_HOST:'127.0.0.1',ZP_BIND_PORT:String(port),ZP_PORT:String(port),ZP_PUBLIC_IP:'0',ZP_GEODATA_AUTO:'0',ZP_APPLY_ASYNC:'0'},stdio:'ignore'});
 let browser;
 try {
  for(let i=0;i<80;i++){try{if((await fetch(base+'/api/status')).ok)break;}catch{} await new Promise(r=>setTimeout(r,200));}
  browser=await chromium.launch(process.env.ZP_CHROME_PATH?{executablePath:process.env.ZP_CHROME_PATH}:{});
  const page=await browser.newPage({viewport:{width:1440,height:1000}});
  const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto(base+'/?token=audit-ui-token');await page.fill('#in-domain','proxy.example.com');await page.fill('#in-user','admin');await page.fill('#in-pass','audit-ui-password');await page.click('#btn-setup');await page.waitForSelector('#view-dash:not(.hidden)',{timeout:45000});
  const pending = async () => {
    await page.waitForFunction(()=>window.dash?.pending_change?.state==='awaiting_confirmation');
    return page.evaluate(()=>window.dash.pending_change);
  };
  const keep = async () => { await page.click('[data-change-confirm]');await page.waitForFunction(()=>window.dash.pending_change.state==='confirmed'); };
  const cancel = async () => { await page.click('[data-change-rollback]');await page.waitForFunction(()=>window.dash.pending_change.state==='rolled_back'); };
  await page.locator('[data-node="vless-reality"]').locator('..').locator('.slider').click();
  const node=await pending();
  check('节点开关进入统一确认流程',node.kind==='nodes'&&(await page.locator('[data-change-text]').innerText()).includes('节点'));
  check('临时节点状态不冒充最终成功',(await page.locator('#toast').innerText()).includes('临时配置'));
  await keep();
  const dashboard=await (await page.request.get(base+'/api/dashboard')).json();
  check('节点确认后保留目标状态',dashboard.nodes.find(n=>n.id==='vless-reality').enabled===false);
  let reads = 0;
  const reconnect = async (route) => {
    if (++reads === 1) {
      await route.fulfill({json:{...dashboard, pending_change:{...dashboard.pending_change, state:'awaiting_confirmation'}}});
      return;
    }
    await route.continue();
  };
  const drop = async (route) => {
    const applied = await route.fetch();
    check('响应丢失前服务端已应用临时变更',applied.ok() && (await applied.json()).pending_change?.state==='awaiting_confirmation');
    await page.route('**/api/dashboard',reconnect);
    await route.abort();
  };
  await page.route('**/api/chain/exit',drop,{times:1});
  await page.click('#btn-chain-exit-gen');await page.waitForSelector('#chain-exit-code');
  await page.waitForFunction(()=>document.querySelector('#toast').textContent.includes('已核对服务器应用结果'));
  check('断线后跳过其他操作的结果，继续核对本次操作',reads>=2);
  await page.unroute('**/api/dashboard',reconnect);
  const chain=await pending();
  check('落地端生成配对码也需确认',chain.kind==='chain');
  await cancel();
  check('链路回滚恢复关闭状态',(await (await page.request.get(base+'/api/dashboard')).json()).chain.exit.enabled===false);
  await page.click('[data-workspace="devices"]');
  await page.click('#wg-enable');const wg=await pending();
  check('WireGuard 启用进入统一倒计时',wg.kind==='wireguard');
  await keep();
  const add=await page.request.post(base+'/api/wireguard/peers',{data:{name:'guarded-test'}});
  check('准备已有 WireGuard 客户端',add.ok());const peer=await add.json();
  const original=(await (await page.request.get(base+'/api/dashboard')).json()).wireguard.peers.find(p=>p.id===peer.peer_id);
  await page.evaluate(async()=>window.loadDash(true));
  await page.click(`[data-wg-rotate="${peer.peer_id}"]`);await page.click('#confirm-ok');
  await page.waitForSelector('#qr-mask:not(.hidden)');await page.click('#qr-close');await pending();
  check('WireGuard 轮换临时授权有确认提示',(await page.locator('#toast').innerText()).includes('临时配置'));
  await cancel();
  const restored=(await (await page.request.get(base+'/api/dashboard')).json()).wireguard.peers.find(p=>p.id===peer.peer_id);
  check('撤销轮换恢复原客户端公钥',original.public_key===restored.public_key);
  await page.locator('#wg-mtu').evaluate(e=>e.closest('details').open=true);
  const mtu=await page.inputValue('#wg-mtu');await page.fill('#wg-mtu','1320');await page.click('#wg-save');await pending();
  const file=home+'/data/state.json';const state=JSON.parse(fs.readFileSync(file,'utf8'));state.pending_change.deadline=Date.now()/1000-1;fs.writeFileSync(file+'.check',JSON.stringify(state));fs.renameSync(file+'.check',file);
  await page.waitForFunction(()=>window.dash.pending_change.state==='rolled_back',{},{timeout:15000});
  check('WireGuard 未确认由后台自动恢复',(await page.inputValue('#wg-mtu'))===mtu);
  for (const width of [820,390,320]) {await page.setViewportSize({width,height:1000});check(`${width}px 确认面板和 WireGuard 无横向溢出`,await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));}
  check('没有未处理脚本异常',errors.length===0,errors.join('; '));
  await page.setViewportSize({width:1440,height:1000});
  const shot=process.env.ZP_SHOT_DIR||path.join(os.tmpdir(),'zp-audit-shots');fs.mkdirSync(shot,{recursive:true});await page.screenshot({path:path.join(shot,'guarded-network-2151.png'),fullPage:true});
  check('没有未处理的页面异常',errors.length===0,errors.join('; '));
  console.log('网络变更统一保护浏览器回归全部通过');
 }finally{if(browser)await browser.close();server.kill('SIGTERM');await new Promise(r=>{if(server.exitCode!==null)return r();server.once('exit',r);});}
})().catch(e=>{console.error(e);process.exitCode=1;});
