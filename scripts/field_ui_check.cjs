/** Regression and responsive checks for the connection-field UI; isolated dry-run server. */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const net = require('net');
for (const dir of (process.env.ZP_NODE_PATH || '').split(path.delimiter)) if (dir) module.paths.push(dir);
const { chromium } = require('playwright');
const ROOT = path.resolve(__dirname, '..');
const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'zp-field-'));
const SHOTS = process.env.ZP_SHOT_DIR || path.join(ROOT, 'work/field-ui');
let PORT;
let server;
fs.mkdirSync(path.join(HOME, 'data'), { recursive: true });
fs.writeFileSync(path.join(HOME, 'data/bootstrap_token'), 'field-check-token\n', {mode:0o600});
fs.mkdirSync(SHOTS, { recursive: true });
let logs='', browser;
let count=0;
function check(name, ok, detail='') { if(!ok) throw new Error(name+' '+detail); count++; console.log('✓ '+name); }
(async()=>{
  PORT = await new Promise((resolve,reject)=>{
    const probe=net.createServer();probe.once('error',reject);
    probe.listen(Number(process.env.ZP_CHECK_PORT || 0),'127.0.0.1',()=>{
      const port=probe.address().port;probe.close(()=>resolve(String(port)));
    });
  });
  server = spawn(process.env.ZP_PYTHON || 'python3', ['-m','zeroproxy.main'], {
  cwd:path.join(ROOT,'backend'), env:{...process.env,ZP_HOME:HOME,ZP_STATIC:path.join(ROOT,'backend/static'), ZP_BIND_HOST:'127.0.0.1',ZP_BIND_PORT:PORT,ZP_PORT:PORT}, stdio:['ignore','pipe','pipe']
});
server.stdout.on('data', d=>logs+=d); server.stderr.on('data',d=>logs+=d);

  const base='http://127.0.0.1:'+PORT;
  let ready=false;
  for(let i=0;i<100;i++) { try{ if((await fetch(base+'/api/status')).ok){ready=true;break;} }catch{} await new Promise(r=>setTimeout(r,100)); }
  check('隔离开发服务启动',ready);
  browser=await chromium.launch({executablePath:process.env.ZP_CHROME_PATH});
  const page=await browser.newPage({viewport:{width:1440,height:1000}});
  const errors=[]; page.on('pageerror',e=>errors.push(e.message)); page.on('console',m=>{if(m.type()==='error') errors.push(m.text());});
  await page.goto(base+'/?token=field-check-token');
  await page.fill('#in-domain','proxy.example.com'); await page.fill('#in-user','admin'); await page.fill('#in-pass','field-test-password'); await page.click('#btn-setup');
  await page.waitForSelector('#view-dash:not(.hidden)');
  check('首页真实节点进入连接场域',await page.locator('#connection-field').isVisible());
  check('首页只显示网络工作区',!(await page.locator('#sec-clients').isVisible()));
  let writes=0;page.on('request',r=>{if(r.method()!=='GET') writes++;});
  const select=page.locator('#field-object-select');
  await select.selectOption('node:trojan');
  check('选择预览不写入配置', writes===0);
  check('对象详情随选择更新', (await page.locator('#field-object-name').innerText()).includes('Trojan'));
  await page.locator('[data-field-node="vless-reality"]').click();
  check('节点列表可定位到画布',await select.inputValue()==='node:vless-reality');
  await page.locator('[data-workspace="routing"]').click();
  await page.fill('#adv-sni','draft.example.net'); await page.focus('#adv-sni');
  await page.evaluate(()=>renderDash(true));
  check('轮询保留草稿与焦点', await page.inputValue('#adv-sni')==='draft.example.net' && await page.evaluate(()=>document.activeElement.id)==='adv-sni');
  await page.locator('[data-workspace="devices"]').click();await page.locator('[data-workspace="routing"]').click();
  check('工作区往返保留草稿',await page.inputValue('#adv-sni')==='draft.example.net');
  await page.keyboard.press('Control+k'); await page.waitForSelector('#find-mask[open]'); await page.fill('#find-input','WireGuard');
  await page.locator('#find-results a').first().click();
  check('快捷查找定位到设备工作区',await page.locator('#sec-wireguard').isVisible());
  check('导航宣布当前页',await page.locator('[data-workspace="devices"]').getAttribute('aria-current')==='page');
  await page.locator('#btn-find').click();await page.keyboard.press('Escape');
  check('查找弹窗支持 Esc',!(await page.locator('#find-mask').isVisible()));
  await page.locator('[data-workspace="network"]').click();
  await page.click('#btn-diag');await page.waitForSelector('#diag-list .check');
  check('诊断自动打开对应工作区',await page.locator('#diag-card').isVisible());
  for(const width of [1440,1024,820,768,390,320]){
    await page.setViewportSize({width,height:1000});
    for(const key of ['network','devices','routing','diagnostics','maintenance']){
      await page.locator(`[data-workspace="${key}"]`).click();
      const spill=await page.evaluate(()=>({scroll:document.documentElement.scrollWidth,view:innerWidth}));
      check(`${width}px / ${key} 无横向溢出`,spill.scroll<=spill.view+1,JSON.stringify(spill)+" "+JSON.stringify(await page.evaluate(()=>[...document.querySelectorAll("body *")].filter(e=>{const r=e.getBoundingClientRect();return r.width>0&&r.right>innerWidth+1;}).map(e=>({tag:e.tagName,id:e.id,cls:e.className,right:e.getBoundingClientRect().right,html:e.parentElement.outerHTML.slice(0,1000)})).slice(0,15))));
    }
    await page.locator('[data-workspace="network"]').click();
    await page.screenshot({path:path.join(SHOTS,`network-${width}.png`),fullPage:true});
  }
  const originalEntries = await page.evaluate(() => structuredClone(dash.chain.entries));
  await page.evaluate(() => {
    dash.chain.entries = [{id:"ui-repair",label:"更新配对验证",host:"exit.example.com",port:8447,local_port:8446,transport:"reality",enabled:true,pin_ok:true,last_probe:{}}];
    renderChain(dash);
  });
  for (const width of [1440,390]) {
    await page.setViewportSize({width,height:1000});
    await page.click('[data-chain-repair="ui-repair"]');
    await page.waitForSelector('#confirm-mask[open]');
    await page.fill('#chain-repair-code','ZPC1~test-sensitive-value');
    const inside = await page.locator('#confirm-mask .modal').evaluate(el => {
      const r=el.getBoundingClientRect(); const field=el.querySelector('textarea').getBoundingClientRect();
      return r.left>=0 && r.right<=innerWidth+1 && field.left>=r.left && field.right<=r.right+1;
    });
    check(`${width}px / 更新配对窗口与输入框完整可见`,inside);
    await page.locator('#confirm-mask .modal').screenshot({path:path.join(SHOTS,`repair-${width}.png`)});
    await page.click('#confirm-cancel');
    await page.waitForFunction(()=>document.querySelector('#chain-repair-code').value==='');
    check(`${width}px / 关闭配对窗口清除敏感输入`,await page.inputValue('#chain-repair-code')==='');
  }
  await page.evaluate((entries)=>{dash.chain.entries=entries;renderChain(dash);},originalEntries);
  await page.setViewportSize({width:1440,height:1240});
  await page.screenshot({path:path.join(SHOTS,'desktop.png')});
  await page.click('#themeBtn');
  await page.screenshot({path:path.join(SHOTS,'network-dark.png'),fullPage:true});
  check('深色主题可切换',await page.evaluate(()=>document.documentElement.dataset.theme)==='dark');
  await page.emulateMedia({reducedMotion:'reduce'});
  check('减少动态效果生效',await page.locator('.field-canvas').evaluate(el=>getComputedStyle(el).animationName)==='none');
  check('无脚本或 CSP 错误',errors.length===0,errors.join('\n'));
  console.log(`完成: ${count} 项通过，截图 ${SHOTS}`);
})().catch(e=>{console.error(e.stack); console.error(logs.slice(-1800));process.exitCode=1;}).finally(async()=>{
  if(browser)await browser.close();
  await new Promise(r=>{if(!server || server.exitCode!==null)return r();server.once('exit',r);server.kill('SIGTERM');});
});
