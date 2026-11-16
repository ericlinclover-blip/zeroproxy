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
  const original=await page.evaluate(()=>structuredClone(window.dash));
  const evaluate=fn=>page.evaluate(fn);
  check('首页提供事实摘要与接入下一步',await page.locator('#summary-next').innerText()==='连接第一台设备');
  await page.click('[data-workspace="maintenance"]');
  check('维护输入全部有原生标签',await evaluate(()=>[...document.querySelectorAll('#panel-grid input')].every(e=>e.labels.length>0)));
  check('轮询重画保持按钮焦点',await evaluate(()=>{document.querySelector('#btn-acct-save').focus();window.renderDash(true);return document.activeElement.id==='btn-acct-save';}));
  check('轮询重画保持密码与光标',await evaluate(()=>{const e=document.querySelector('#acct-now');e.value='temporary-unsaved';e.focus();e.setSelectionRange(2,4);window.renderDash(true);const r=document.querySelector('#acct-now');return r.value==='temporary-unsaved'&&r.selectionStart===2&&r.selectionEnd===4;}));
  check('退出入口准确标明所有设备',await page.locator('#btn-logout-others').innerText()==='退出所有设备');
  await page.click('[data-workspace="devices"]');await page.click('[data-client-tab="desktop"]');
  check('Linux sing-box 复制 JSON 订阅',await page.locator('.mini-card',{hasText:'Linux · sing-box'}).locator('[data-sub-copy]').getAttribute('data-sub-copy').then(s=>s.includes('format=singbox')));
  await page.locator('.mini-card',{hasText:'Linux · sing-box'}).locator('[data-sub-qr]').click();
  check('sing-box 二维码与复制地址同格式',(await page.locator('#qr-img').getAttribute('src')).includes('format=singbox'));
  await page.click('#qr-close');await page.click('[data-client-tab="phone"]');
  check('Android 客户端分别列出',await page.locator('#client-body .mini-card').count()===3);
  check('Android sing-box 采用 JSON',await page.locator('.mini-card',{hasText:'Android · sing-box'}).locator('[data-sub-copy]').getAttribute('data-sub-copy').then(s=>s.includes('format=singbox')));
  check('v2rayNG 保留通用格式',await page.locator('.mini-card',{hasText:'v2rayNG'}).locator('[data-sub-copy]').getAttribute('data-sub-copy').then(s=>!s.includes('format=clash')&&!s.includes('format=singbox')));
  await evaluate(async()=>{const m=new URL('views/clients.js',document.querySelector('script[type=module]').src);const{renderClients}=await import(m);window.dash.devices={items:[{id:'audit-local',name:'audit-router',kind:'router',desired:true,actual:true,online:true,connected:true,control:'local',report:{override:'on',covered:'full'}}],count:1,on:1,online:1};renderClients(window.dash);document.querySelector('[data-client-tab="router"]').click();});
  check('本机覆盖与期望相同也可见',(await page.locator('.dev-card .pill').innerText()).includes('本机覆盖'));
  await page.click('[data-dev-remove]');
  check('移除提示缓存代理仍可能可用',(await page.locator('#confirm-body').innerText()).includes('已缓存的代理配置可能仍能使用'));
  await page.click('#confirm-cancel');
  await page.evaluate(d=>{window.dash=d;window.renderDash(true);},original);
  await page.route('**/api/dashboard',r=>r.fulfill({json:{...original,traffic:{...original.traffic,total:7654321}}}));
  check('流量变化不等于操作成功',await evaluate(async()=>{const{syncAfterDrop}=await import(new URL('lib/api.js',document.querySelector('script[type=module]').src));return await syncAfterDrop(JSON.stringify(window.dash),1,1)===false;}));
  await page.unroute('**/api/dashboard');
  await page.route('**/api/apply/job?id=audit-failed',r=>r.fulfill({json:{id:'audit-failed',state:'failed',error:'audit startup failed',steps:[],total:7,index:1}}));
  check('空步骤的失败任务必须抛错',await evaluate(async()=>{const{awaitJob}=await import(new URL('lib/jobs.js',document.querySelector('script[type=module]').src));try{await awaitJob({job:{id:'audit-failed',state:'running',total:7}});return false;}catch(e){return e.message==='audit startup failed';}}));
  await page.route('**/api/nodes/*/enabled',r=>r.fulfill({json:{...original,job:{id:'audit-failed',state:'running',total:7}}}));
  await page.click('[data-workspace="network"]');await page.locator('#node-grid .node-card').first().locator('.switch .slider').click();
  await page.waitForFunction(()=>document.querySelector('#toast').textContent.includes('audit startup failed'));
  check('节点开关失败没有成功提示',!(await page.locator('#toast').innerText()).includes('已热更新'));
  await page.waitForTimeout(4500);
  check('失败进度不会被成功自动收起定时器清除',await page.locator('#apply-strip').isVisible());
  check('失败详情可持续查看和复制',await page.locator('#operation-notice').isVisible());
  await page.click('[data-workspace="diagnostics"]');
  await page.route('**/api/diagnose',r=>r.fulfill({json:{ok:false,summary:'0/1 项通过',checks:[{name:'入口检查',ok:false,fixable:true,detail:'audit failed'}]}}));
  await page.click('#btn-diag');await page.waitForSelector('#diag-actions:not(.hidden)');await page.click('#btn-repair');
  check('修复前可审阅计划',(await page.locator('#confirm-body').innerText()).includes('可能短暂中断'));
  await page.click('#confirm-cancel');await page.click('#btn-unlock-probe');await page.waitForSelector('#unlock-grid .mini-card');
  check('离线检查不冒充解锁',!(await page.locator('#unlock-grid').innerText()).includes('✓ 解锁'));
  check('端点说明检查位置',(await page.locator('#unlock-grid').innerText()).includes('面板服务器直连'));
  const widths=[1440,820,390,320];
  for(const width of widths){await page.setViewportSize({width,height:1000});for(const workspace of ['network','devices','routing','diagnostics','maintenance']){await page.click(`[data-workspace="${workspace}"]`);check(`${width}px ${workspace} 页面不横向溢出`,await evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));}}
  await page.setViewportSize({width:1440,height:1000});await page.click('[data-workspace="network"]');
  const shot=process.env.ZP_SHOT_DIR||path.join(os.tmpdir(),'zp-audit-shots');fs.mkdirSync(shot,{recursive:true});await page.screenshot({path:path.join(shot,'audit-network.png'),fullPage:true});
  check('没有未处理的页面异常',errors.length===0,errors.join('; '));
  console.log('交互审计浏览器回归全部通过');
 }finally{if(browser)await browser.close();server.kill('SIGTERM');await new Promise(r=>{if(server.exitCode!==null)return r();server.once('exit',r);});}
})().catch(e=>{console.error(e);process.exitCode=1;});
