/** Real browser regression for client-card geometry and subscription actions. */
const fs=require('fs'),os=require('os'),path=require('path'),net=require('net');
const {spawn}=require('child_process');
for(const extra of (process.env.ZP_NODE_PATH||'').split(path.delimiter))if(extra)module.paths.push(extra);
const {chromium}=require('playwright');
const ROOT=path.resolve(__dirname,'..');
let passed=0;
function check(name,ok,detail=''){console.log(`${ok?'✓':'✗'} ${name}${detail?' '+detail:''}`);if(!ok)throw new Error(name);passed++;}
(async()=>{
 const home=fs.mkdtempSync(path.join(os.tmpdir(),'zp-client-profiles-'));
 fs.mkdirSync(home+'/data');fs.writeFileSync(home+'/data/bootstrap_token','client-profiles-token');
 const port=await new Promise(resolve=>{const s=net.createServer();s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>resolve(p));});});
 const base=`http://127.0.0.1:${port}`;
 const server=spawn(process.env.ZP_PYTHON||'python3',['-m','zeroproxy.main'],{cwd:ROOT+'/backend',env:{...process.env,ZP_HOME:home,ZP_STATIC:ROOT+'/backend/static',ZP_BIND_HOST:'127.0.0.1',ZP_BIND_PORT:String(port),ZP_PORT:String(port),ZP_PUBLIC_IP:'0',ZP_GEODATA_AUTO:'0',ZP_CHANGE_GUARD_AUTO:'0',ZP_APPLY_ASYNC:'0'},stdio:'ignore'});
 let browser;
 const shot=process.env.ZP_SHOT_DIR||path.join(os.tmpdir(),'zp-client-profile-shots');fs.mkdirSync(shot,{recursive:true});
 try{
  for(let i=0;i<100;i++){try{if((await fetch(base+'/api/status')).ok)break;}catch{}await new Promise(r=>setTimeout(r,100));}
  browser=await chromium.launch(process.env.ZP_CHROME_PATH?{executablePath:process.env.ZP_CHROME_PATH}:{});
  const context=await browser.newContext({viewport:{width:1440,height:1000}});
  await context.addInitScript(()=>{Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async text=>{window.lastCopied=text;}}});});
  const page=await context.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto(base+'/?token=client-profiles-token');await page.fill('#in-domain','proxy.example.com');await page.fill('#in-user','admin');await page.fill('#in-pass','client-test-password');await page.click('#btn-setup');await page.waitForSelector('#view-dash:not(.hidden)',{timeout:45000});
  await page.click('[data-workspace="devices"]');await page.click('[data-client-tab="desktop"]');
  await page.evaluate(()=>document.fonts.ready);await page.waitForTimeout(200);
  check('电脑显示三张客户端卡片',await page.locator('#client-body .mini-card').count()===3);
  await page.screenshot({path:path.join(shot,'desktop-initial.png'),fullPage:true});
  const overflow=()=>page.evaluate(()=>[...document.querySelectorAll('#client-body .mini-card')].flatMap(card=>{
    const c=card.getBoundingClientRect();return [...card.querySelectorAll('button,a')].flatMap(el=>{const r=el.getBoundingClientRect();return r.left<c.left-1||r.right>c.right+1?[`${card.textContent.slice(0,45)}: ${el.textContent} extends ${Math.round(r.right-c.right)}px`]:[];});
  }));
  check('桌面操作按钮位于各自卡片内',(await overflow()).length===0,(await overflow()).join('; '));
  const widths=[1920,1560,1440,1280,1100,1024,820,768,600,390,320];
  for(const theme of ['light','dark']){
    await page.evaluate(theme=>document.documentElement.dataset.theme=theme,theme);
    for(const width of widths){
      await page.setViewportSize({width,height:1000});
      for(const tab of ['phone','desktop']){
        await page.click(`[data-client-tab="${tab}"]`);
        check(`${theme} ${width}px ${tab} 三卡片`,await page.locator('#client-body .mini-card').count()===3);
        check(`${theme} ${width}px ${tab} 按钮不越界`,(await overflow()).length===0,(await overflow()).join('; '));
        check(`${theme} ${width}px ${tab} 页面不横向溢出`,await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
        check(`${theme} ${width}px ${tab} 点击区域至少44px`,await page.locator('#client-body .mini-actions').evaluateAll(rows=>rows.every(row=>[...row.querySelectorAll('button,a')].every(el=>el.getBoundingClientRect().height>=43.9))));
      }
    }
  }
  await page.setViewportSize({width:1280,height:1000});
  await page.evaluate(()=>{document.documentElement.style.zoom='2';});
  for(const tab of ['phone','desktop']){await page.click(`[data-client-tab="${tab}"]`);check(`200%缩放 ${tab} 操作不越界`,(await overflow()).length===0);}
  await page.evaluate(()=>{document.documentElement.style.zoom='';document.documentElement.dir='rtl';});
  await page.locator('#client-tab-phone').focus();await page.keyboard.press('ArrowLeft');
  check('RTL方向键遵循视觉顺序',await page.locator('#client-tab-desktop').getAttribute('aria-selected')==='true');
  check('RTL卡片按钮不越界',(await overflow()).length===0);
  await page.evaluate(()=>{document.documentElement.dir='ltr';});
  await page.locator('#client-tab-router').focus();await page.keyboard.press('ArrowRight');
  check('方向键切换手机并保持焦点',await page.locator('#client-tab-phone').evaluate(el=>el.getAttribute('aria-selected')==='true'&&document.activeElement===el));
  await page.keyboard.press('End');check('End选择电脑',await page.locator('#client-tab-desktop').getAttribute('aria-selected')==='true');
  await page.keyboard.press('ArrowRight');check('方向键可循环',await page.locator('#client-tab-router').getAttribute('aria-selected')==='true');
  await page.keyboard.press('Home');check('仅一个标签进入Tab顺序',await page.locator('#client-tabs [tabindex="0"]').count()===1);
  await page.click('[data-client-tab="phone"]');
  check('面板名称关联选中标签',await page.locator('#client-body').getAttribute('aria-labelledby')==='client-tab-phone');
  await page.setViewportSize({width:320,height:1000});
  for(const tab of ['phone','desktop']){
    await page.click(`[data-client-tab="${tab}"]`);
    await page.evaluate(()=>{window.longLabels=[...document.querySelectorAll('#client-body .mini-actions .btn')].map(el=>[el,el.textContent]);for(const [el] of window.longLabels)el.textContent='用于验证长文本按钮完整显示的操作说明';});
    check(`320px ${tab} 长文本按钮可回流`,(await overflow()).length===0);
    await page.evaluate(()=>{for(const [el,text] of window.longLabels)el.textContent=text;delete window.longLabels;});
  }
  await page.setViewportSize({width:1280,height:1000});
  // Route public subscription navigation back to the isolated server. The body and
  // download headers are the real API response, including Android's separate profile.
  await page.route('**/sub/*',async route=>{
    const url=new URL(route.request().url());
    const response=await page.request.get(base+url.pathname+url.search);
    await route.fulfill({response});
  });
  await page.evaluate(()=>document.addEventListener('click',event=>{if(event.target.closest('[data-client-import]'))event.preventDefault();}));
  for(const tab of ['phone','desktop']){
    await page.click(`[data-client-tab="${tab}"]`);
    for(const card of await page.locator('#client-body [data-client-app]').all()){
      const id=await card.getAttribute('data-client-app');
      const copy=card.locator('[data-sub-copy]');const url=await copy.getAttribute('data-sub-copy');
      check(`${id} 订阅存在`,!!url);
      await copy.click();check(`${id} 复制真实订阅`,await page.evaluate(url=>window.lastCopied===url,url));
      await card.locator('[data-sub-qr]').click();
      check(`${id} 二维码正文与复制一致`,await page.locator('#qr-link').textContent()===url);
      const image=await page.locator('#qr-img').getAttribute('src');
      const parsed=new URL(url);const imageURL=new URL(image,base);
      check(`${id} 二维码保留格式和平台`,['format','client'].every(key=>(imageURL.searchParams.get(key)||'base64')===(parsed.searchParams.get(key)||'base64')));
      check(`${id} 二维码真实生成`,(await page.request.get(base+imageURL.pathname+imageURL.search)).status()===200);
      await page.keyboard.press('Escape');
      check(`${id} 关闭二维码恢复触发按钮焦点`,await card.locator('[data-sub-qr]').evaluate(el=>document.activeElement===el));
      const importer=card.locator('[data-client-import]');
      if(await importer.count()){
        const target=new URL(await importer.getAttribute('href'));
        check(`${id} 导入地址与复制一致`,target.searchParams.get('url')===url);
        await importer.click();check(`${id} 唤起提示不冒充成功`,(await page.locator('#toast').textContent()).includes('若未打开'));
      }
      const downloader=card.locator('a[download]');
      if(await downloader.count()){
        const [download]=await Promise.all([page.waitForEvent('download'),downloader.click()]);
        const saved=path.join(shot,id+'.json');await download.saveAs(saved);
        const config=JSON.parse(fs.readFileSync(saved,'utf8'));
        check(`${id} 下载实际JSON且命名正确`,download.suggestedFilename()===(id==='sfa'?'zeroproxy-android.json':'zeroproxy-singbox.json'));
        check(`${id} 运行方式匹配平台`,config.inbounds[0].type===(id==='sfa'?'tun':'mixed'));
      }
      await card.locator('summary').click();check(`${id} 操作指南可展开`,await card.locator('details').evaluate(el=>el.open));
    }
  }
  // Quiet refreshes must preserve action identity, focus and open instructions.
  const focused=page.locator('#client-copy-singbox-linux');await focused.focus();
  await page.evaluate(()=>window.renderDash(true));
  check('轮询保持动作焦点和指南展开',await focused.evaluate(el=>document.activeElement===el)&&await page.locator('#client-guide-singbox-linux').evaluate(el=>el.open));
  check('外部客户端不显示虚构在线数',(await page.locator('#client-count').textContent()).includes('在线状态由客户端查看'));
  const failure=await page.evaluate(async()=>{
    Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async()=>{throw Error('denied');}}});
    const original=document.execCommand;document.execCommand=()=>false;
    const {copyText}=await import(new URL('lib/dom.js',document.querySelector('script[type=module]').src));
    try{return await copyText('test-copy-failure');}finally{document.execCommand=original;}
  });
  check('剪贴板失败不报成功',failure===false&&(await page.locator('#toast').textContent()).includes('复制失败'));
  check('复制失败清理临时输入框',await page.locator('textarea[aria-label="待复制内容"]').count()===0);
  await page.click('#client-qr-singbox-linux');
  check('对话框内复制回退可使用',await page.evaluate(async()=>{
    const original=document.execCommand;let inside=false;
    document.execCommand=()=>{inside=!!document.activeElement.closest('dialog[open]');return true;};
    const {copyText}=await import(new URL('lib/dom.js',document.querySelector('script[type=module]').src));
    try{return await copyText('dialog-copy-test')&&inside;}finally{document.execCommand=original;}
  }));
  await page.keyboard.press('Escape');
  await page.evaluate(()=>{window.dash.subscription_formats={};window.renderDash(true);});
  check('缺失订阅时按钮不可执行',await page.locator('#client-body [data-sub-copy]').evaluateAll(buttons=>buttons.length===3&&buttons.every(button=>button.disabled)));
  check('缺失订阅时不生成空下载或导入链接',await page.locator('#client-body a').count()===0);
  await page.evaluate(async()=>{await window.loadDash(true);});
  for(const tab of ['phone','desktop']){
    await page.click(`[data-client-tab="${tab}"]`);await page.setViewportSize({width:1440,height:1100});
    await page.evaluate(()=>document.documentElement.dataset.theme='light');await page.waitForTimeout(200);
    await page.locator('#sec-clients').screenshot({path:path.join(shot,tab+'-light.png')});
    await page.evaluate(()=>document.documentElement.dataset.theme='dark');await page.waitForTimeout(200);
    await page.locator('#sec-clients').screenshot({path:path.join(shot,tab+'-dark.png')});
  }
  check('页面无异常',errors.length===0,errors.join('; '));console.log(`结论: ${passed} 项通过`);
 }finally{if(browser)await browser.close();server.kill('SIGTERM');await new Promise(resolve=>{if(server.exitCode!==null)return resolve();server.once('exit',resolve);});}
})().catch(e=>{console.error(e);process.exitCode=1;});
