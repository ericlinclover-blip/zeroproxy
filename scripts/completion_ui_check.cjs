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
  const jsonPost = async (url, body) => { const response=await page.request.post(base+url,{data:body}); check(url+' HTTP '+response.status(),response.ok()); return response.json(); };
  await jsonPost('/api/settings',{reality_sni:'www.example.org',require_confirmation:true});
  await page.evaluate(async()=>{await window.loadDash(true);});
  await page.waitForSelector('#network-change-panel:not(.hidden) [data-change-confirm]:not([hidden])');
  check('高级设置提供服务端限时确认',(await page.locator('[data-change-text]').innerText()).includes('临时高级设置配置已应用'));
  await page.click('[data-change-confirm]');
  await page.waitForFunction(()=>document.querySelector('[data-change-text]').textContent==='已保留网络变更。');
  check('确认后展示已保留',true);
  await jsonPost('/api/settings',{reality_sni:'www.cloudflare.com',require_confirmation:true});
  const file=home+'/data/state.json';const state=JSON.parse(fs.readFileSync(file,'utf8'));state.pending_change.deadline=Date.now()/1000-1;fs.writeFileSync(file+'.check',JSON.stringify(state));fs.renameSync(file+'.check',file);
  await page.evaluate(async()=>{await window.loadDash(true);});
  await page.waitForFunction(()=>document.querySelector('[data-change-text]').textContent.includes('已恢复并验证旧配置'),{},{timeout:15000});
  const restored=(await (await page.request.get(base+'/api/dashboard')).json());
  check('无人确认时后台自动回滚',restored.reality.server_name==='www.example.org');
  await page.click('[data-workspace="routing"]');
  await page.selectOption('#adv-hy-congestion','conservative');
  await page.evaluate(async()=>{await window.loadDash(true);});
  check('刷新保留 Hysteria 2 拥塞控制草稿',await page.inputValue('#adv-hy-congestion')==='conservative');
  await page.click('#btn-save-adv');
  check('确认窗显示所选 BBR 档位',(await page.locator('#confirm-body').innerText()).includes('BBR 保守'));
  await page.click('#confirm-ok');
  await page.waitForFunction(()=>window.dash?.hysteria_congestion==='conservative'&&window.dash?.pending_change?.state==='awaiting_confirmation');
  await page.click('[data-change-rollback]');
  await page.waitForFunction(()=>document.querySelector('#adv-hy-congestion').value==='negotiated');
  check('撤销后恢复客户端协商',await page.evaluate(()=>window.dash.hysteria_congestion)==='negotiated');
  await page.click('#btn-toggle-custom-rules');
  await page.fill('#cr-block','example.com\n10.0.0.0/8');await page.fill('#cr-direct','sub.example.com\n10.1.0.0/16');
  await page.click('#btn-save-custom-rules');await page.waitForSelector('#confirm-body li');
  check('保存前显示域名和网段覆盖',(await page.locator('#confirm-body').innerText()).includes('后者被完全覆盖')&&(await page.locator('#confirm-body').innerText()).includes('10.0.0.0/8'));
  await page.click('#confirm-ok');await page.waitForFunction(()=>document.querySelector('#confirm-mask').classList.contains('hidden'));
  const pair=await jsonPost('/api/devices/pair',{label:'browser-test'});
  const device=await jsonPost('/c/pair',{code:pair.code,model:'browser-test',kind:'router'});
  await jsonPost('/c/report',{device:device.id,k:device.secret,actual:true,report:{diagnostics:1,covered:'full'}});
  await page.evaluate(async()=>{await window.loadDash(true);});await page.click('[data-workspace="devices"]');
  await page.locator(`[data-dev-diagnose="${device.id}"]`).click();
  await page.waitForSelector(`[data-dev-diagnose="${device.id}"]:disabled`);
  const request=await jsonPost('/c/report',{device:device.id,k:device.secret});
  check('设备诊断只下发请求标识',/^[0-9a-f]{32}$/.test(request.diagnostic_request));
  await jsonPost('/c/report',{device:device.id,k:device.secret,diagnostic:{id:request.diagnostic_request,evidence:{device:'passed',dns:'failed',takeover:'observed',entry:'observed',exit:'unknown',target:'failed',packets:42}}});
  await page.waitForFunction(()=>[...document.querySelectorAll('[data-device-diagnostic]')].some(e=>e.textContent.includes('设备已回报')),{},{timeout:15000});
  check('诊断展示阶段结果及范围',(await page.locator('[data-device-diagnostic]').innerText()).includes('LAN 终端')&&(await page.locator('[data-device-diagnostic]').innerText()).includes('固定 HTTPS 目标'));
  check('诊断结果标注执行时间',(await page.locator('[data-device-diagnostic]').innerText()).includes(new Date().getFullYear().toString()));
  check('没有页面脚本异常',errors.length===0,errors.join('; '));
  for (const width of [820,390,320]) {
    await page.setViewportSize({width,height:1000});
    check(`${width}px 设备诊断无横向溢出`,await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
  }
  await page.setViewportSize({width:1440,height:1000});
  const shot=process.env.ZP_SHOT_DIR||path.join(os.tmpdir(),'zp-audit-shots');fs.mkdirSync(shot,{recursive:true});await page.screenshot({path:path.join(shot,'completion-215.png'),fullPage:true});
  check('没有未处理的页面异常',errors.length===0,errors.join('; '));
  console.log('剩余修复浏览器回归全部通过');
 }finally{if(browser)await browser.close();server.kill('SIGTERM');await new Promise(r=>{if(server.exitCode!==null)return r();server.once('exit',r);});}
})().catch(e=>{console.error(e);process.exitCode=1;});
