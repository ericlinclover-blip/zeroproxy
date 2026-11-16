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
async function measureTopologyAlignment(page) {
  return page.evaluate(() => {
    const topology = document.querySelector('.field-topology');
    const rect = topology.getBoundingClientRect();
    const dots = ['device', 'entry', 'exit'].map(name => {
      const r = document.querySelector(`#field-${name} .field-dot`).getBoundingClientRect();
      return { name, x:r.left+r.width/2, y:r.top+r.height/2 };
    });
    const svg = topology.querySelector('svg');
    let anchors, mode, overlay;
    if (getComputedStyle(svg).display !== 'none') {
      mode = 'curve';
      const device = svg.querySelector('.wire-device'), main = svg.querySelector('.wire-main');
      const point = (path, distance) => path.getPointAtLength(distance).matrixTransform(path.getScreenCTM());
      anchors = [point(device,0), point(main,0), point(main,main.getTotalLength())];
    } else {
      mode = 'vertical';
      const line = getComputedStyle(topology,'::before'), size = getComputedStyle(topology);
      const scaleX = rect.width/parseFloat(size.width), scaleY = rect.height/parseFloat(size.height);
      const shift = line.transform === 'none' ? 0 : new DOMMatrix(line.transform).m41;
      const x = rect.left+(parseFloat(line.left)+shift+parseFloat(line.borderLeftWidth)/2)*scaleX;
      anchors = [{ x, y:rect.top+parseFloat(line.top)*scaleY }, {x,y:dots[1].y}, { x, y:rect.bottom-parseFloat(line.bottom)*scaleY }];
      const main = getComputedStyle(topology,'::after');
      const mainShift = main.transform === 'none' ? 0 : new DOMMatrix(main.transform).m41;
      const mainX = rect.left+(parseFloat(main.left)+mainShift+parseFloat(main.borderLeftWidth)/2)*scaleX;
      const mainY = rect.top+parseFloat(main.top)*scaleY;
      overlay = [{x:mainX,y:mainY}, {x:mainX,y:mainY+parseFloat(main.height)*scaleY}];
    }
    const errors = dots.map((dot,i)=>({name:dot.name,dx:dot.x-anchors[i].x,dy:dot.y-anchors[i].y}));
    if (overlay) errors.push(...dots.slice(1).map((dot,i)=>({name:'main-'+dot.name,dx:dot.x-overlay[i].x,dy:dot.y-overlay[i].y})));
    return { mode, maxError:Math.max(...errors.flatMap(p=>[Math.abs(p.dx),Math.abs(p.dy)])), errors };
  });
}
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
  await page.click('#field-entry');
  check('入口点击保留当前所选路线',await select.inputValue()==='node:trojan');
  await page.click('#field-device');
  check('设备段显示真实证据边界与接入操作',(await page.locator('#field-facts').innerText()).includes('未采集') && !(await page.locator('#field-verify').isVisible()));
  await page.click('#field-manage');
  check('设备段操作打开设备工作区',await page.locator('#sec-clients').isVisible());
  await page.locator('[data-workspace="network"]').click();
  await page.click('#field-exit');
  check('出口段可查看实际分流说明',(await page.locator('#field-evidence').innerText()).includes('分流规则'));
  await page.click('#field-entry');
  let checkedNodes=[];
  let releaseCheck;
  const checkGate=new Promise(resolve=>{releaseCheck=resolve;});
  await page.route('**/api/probe?**',async route=>{
    const node=new URL(route.request().url()).searchParams.get('node');
    if(!node)return route.continue();
    checkedNodes.push(node);await checkGate;
    await route.fulfill({json:{checked_at:Math.floor(Date.now()/1000),chain_revision:await page.evaluate(()=>dash.chain.probe_revision),nodes:[{node,kind:'deep',ok:true,ms:42,detail:'所选节点真实往返通过'}]}});
  });
  await page.click('#field-verify');
  await page.waitForFunction(()=>document.querySelector('#connection-field').getAttribute('aria-busy')==='true');
  await page.evaluate(()=>renderDash(true));
  check('轮询期间保留检查进度且防止重复提交',await page.locator('#field-verify').isDisabled() && (await page.locator('#field-headline').innerText()).includes('正在检查'));
  await select.selectOption('node:vless-reality');
  releaseCheck();
  await page.waitForFunction(()=>document.querySelector('#field-verify').disabled===false);
  check('单节点检查不扫描其它路线',checkedNodes.length===1&&checkedNodes[0]==='trojan');
  check('异步结果不会覆盖当前查看路线',await select.inputValue()==='node:vless-reality' && !(await page.locator('#field-evidence').innerText()).includes('所选节点真实往返通过'));
  await select.selectOption('node:trojan');
  check('返回已检查路线保留其证据',await page.locator('#field-latency').innerText()==='42 ms' && await page.locator('#connection-field').getAttribute('data-state')==='verified');
  await page.unroute('**/api/probe?**');
  await page.route('**/api/probe?**',route=>new URL(route.request().url()).searchParams.has('node') ? route.fulfill({status:503,json:{error:'测试检查暂不可用'}}) : route.continue());
  await page.click('#field-verify');
  await page.waitForFunction(()=>document.querySelector('#field-feedback').textContent.includes('未取得新检查结果'));
  check('请求失败保留旧证据并提供诊断入口',await page.locator('#field-latency').innerText()==='42 ms' && await page.locator('#field-diagnose').isVisible());
  // This console entry is the deliberately injected HTTP failure, not a script error.
  const injected=errors.findIndex(x=>x.includes('503'));if(injected>=0)errors.splice(injected,1);
  await page.unroute('**/api/probe?**');
  await select.selectOption('node:hysteria2');
  check('不支持深度检查的 UDP 节点使用明确操作名称',await page.locator('#field-verify').innerText()==='检查 UDP 监听');
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
    const alignment = await measureTopologyAlignment(page);
    check(`${width}px / 路线圆心与主线精确对齐`,alignment.maxError<=0.1,JSON.stringify(alignment));
    await page.screenshot({path:path.join(SHOTS,`network-${width}.png`),fullPage:true});
    if(width===390)await page.locator("#connection-field").screenshot({path:path.join(SHOTS,"connection-field-mobile.png")});
  }
  let maximumAlignmentError = 0;
  for (const dpr of [1,2]) {
    const context = await browser.newContext({deviceScaleFactor:dpr, viewport:{width:1440,height:1000}, storageState:await page.context().storageState()});
    const probe = await context.newPage();
    try {
      await probe.goto(base);await probe.waitForSelector('#view-dash:not(.hidden)');
      await probe.locator('[data-workspace="network"]').click();
      for (const width of [2560,1440,1024,821,820,601,600,390,320]) {
        await probe.setViewportSize({width,height:1000});
        for (const zoom of [1,1.25,2]) {
          await probe.evaluate(value=>{document.documentElement.style.zoom=String(value);},zoom);
          let worst = 0;
          for (const state of ['unknown','verified','failed','off']) {
            await probe.locator('#connection-field').evaluate((el,value)=>el.dataset.state=value,state);
            const alignment = await measureTopologyAlignment(probe);
            worst = Math.max(worst,alignment.maxError);
          }
          maximumAlignmentError = Math.max(maximumAlignmentError,worst);
          check(`${width}px / DPR ${dpr} / CSS 缩放 ${zoom*100}% / 四种状态圆心对齐`,worst<=0.1,`最大误差 ${worst.toFixed(4)}px`);
        }
      }
      await probe.evaluate(()=>{document.documentElement.style.zoom='1';document.querySelector('#connection-field').dataset.state='verified';});
      await probe.setViewportSize({width:1440,height:1000});
      await probe.evaluate(()=>{document.documentElement.dir='rtl';});
      const rtlAlignment = await measureTopologyAlignment(probe);
      check(`RTL / DPR ${dpr} / 路线圆心对齐`,rtlAlignment.maxError<=0.1,JSON.stringify(rtlAlignment));
      await probe.evaluate(()=>{document.documentElement.removeAttribute('dir');});
      await probe.locator('#connection-field').screenshot({path:path.join(SHOTS,`alignment-desktop-dpr${dpr}.png`)});
    } finally { await context.close(); }
  }
  console.log(`路线几何最大误差 ${maximumAlignmentError.toFixed(4)} CSS px`);
  const originalEntries = await page.evaluate(() => structuredClone(dash.chain.entries));
  await page.evaluate(() => {
    dash.chain.entries = [{id:"ui-repair",label:"更新配对验证",host:"exit.example.com",port:8447,local_port:8446,transport:"reality",enabled:true,pin_ok:true,last_probe:{}}];
    renderDash(true);
  });
  await page.setViewportSize({width:1440,height:1000});
  await select.selectOption('chain:ui-repair');
  await page.click('#field-exit');
  const beforeDefaultWrites=writes;
  await page.click('#field-apply-route');
  await page.waitForSelector('#confirm-mask[open]');
  check('从路径切换默认出口仍需明确确认',writes===beforeDefaultWrites && (await page.locator('#confirm-mask h3').innerText()).includes('默认出口'));
  await page.click('#confirm-cancel');
  let chainChecks=0;
  await page.route('**/api/chain/entries/ui-repair/probe',async route=>{
    chainChecks++;
    const body=await page.evaluate(()=>structuredClone(dash));
    body.chain.entries[0].last_probe={ok:true,probe_ok:true,ts:Math.floor(Date.now()/1000),ms:38,exit_ip:'203.0.113.8',detail:'落地段出网验证通过'};
    body.chain.entries[0].probe_current=true;
    await route.fulfill({json:body});
  });
  await page.click('#field-verify');
  await page.waitForFunction(()=>document.querySelector('#field-headline').textContent.includes('落地段验证通过'));
  check('链式出口检查只调用选中落地段',chainChecks===1 && (await page.locator('#field-facts').innerText()).includes('203.0.113.8'));
  await page.unroute('**/api/chain/entries/ui-repair/probe');
  await page.click('#field-entry');
  check('落地段检查不冒充设备接入验证',(await page.locator('#field-summary').innerText()).includes('设备端验证'));

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
  await page.evaluate((entries)=>{dash.chain.entries=entries;renderDash(true);},originalEntries);
  await select.selectOption('node:vless-reality');
  await page.setViewportSize({width:1440,height:1240});
  await page.locator('[data-workspace="network"]').click();
  await page.evaluate(()=>window.scrollTo(0,0));
  await page.screenshot({path:path.join(SHOTS,'desktop.png')});
  await page.locator('#connection-field').screenshot({path:path.join(SHOTS,'connection-field.png')});
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
