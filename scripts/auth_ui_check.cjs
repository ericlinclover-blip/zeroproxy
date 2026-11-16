/** Login/setup: isolated dry-run backend, real forms, responsive and failure paths. */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const net = require('net');
for (const dir of (process.env.ZP_NODE_PATH || '').split(path.delimiter)) if (dir) module.paths.push(dir);
const { chromium } = require('playwright');
const ROOT=path.resolve(__dirname,'..'), HOME=fs.mkdtempSync(path.join(os.tmpdir(),'zp-auth-'));
const SHOTS=process.env.ZP_SHOT_DIR || path.join(ROOT,'work/auth-ui');
fs.mkdirSync(path.join(HOME,'data'),{recursive:true});
fs.writeFileSync(path.join(HOME,'data/bootstrap_token'),'auth-test-token\n',{mode:0o600});
fs.mkdirSync(SHOTS,{recursive:true});
let server,browser,logs='',count=0;
function check(name,ok){if(!ok)throw new Error(name);count++;console.log('✓ '+name);}
(async()=>{
 const port=await new Promise(r=>{const s=net.createServer();s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>r(String(p)));});});
 server=spawn(process.env.ZP_PYTHON || 'python3',['-m','zeroproxy.main'],{cwd:path.join(ROOT,'backend'),env:{...process.env,ZP_HOME:HOME,ZP_STATIC:path.join(ROOT,'backend/static'),ZP_BIND_HOST:'127.0.0.1',ZP_BIND_PORT:port,ZP_PORT:port},stdio:['ignore','pipe','pipe']});
 server.stdout.on('data',d=>logs+=d);server.stderr.on('data',d=>logs+=d);
 const base='http://127.0.0.1:'+port;
 let ready=false;for(let i=0;i<100;i++){try{if((await fetch(base+'/api/status')).ok){ready=true;break;}}catch{}await new Promise(r=>setTimeout(r,100));}check('隔离服务启动',ready);
 browser=await chromium.launch({executablePath:process.env.ZP_CHROME_PATH});
 const page=await browser.newPage({viewport:{width:1440,height:900}}),errors=[];
 page.on('pageerror',e=>errors.push(e.message));
 await page.goto(base+'/?token=auth-test-token');await page.waitForSelector('#view-setup:not(.hidden)');
 check('引导令牌从地址栏清除',!page.url().includes('token='));
 async function shots(view){
  for(const theme of ['light','dark']){
   await page.evaluate(t=>{document.documentElement.dataset.theme=t;},theme);
   for(const [w,h] of [[1440,900],[1024,768],[820,1180],[768,1024],[390,844],[320,740]]){
    await page.setViewportSize({width:w,height:h});
    await page.waitForTimeout(300);
    check(`${view}/${theme}/${w}无横向溢出`,await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
    check(`${view}/${theme}/${w}主操作可见`,await page.locator(view==='setup'?'#btn-setup':'#btn-login').isVisible());
    await page.screenshot({path:path.join(SHOTS,`${view}-${theme}-${w}.png`),fullPage:true,animations:'disabled'});
   }
  }
  await page.setViewportSize({width:1440,height:900});await page.evaluate(()=>document.documentElement.dataset.theme='light');
 }
 await shots('setup');
 let setupWrites=0;page.on('request',r=>{if(r.url().endsWith('/api/setup'))setupWrites++;});
 await page.click('#btn-setup');check('空配置不会请求初始化',setupWrites===0);
 await page.fill('#in-domain','proxy.example.com');await page.fill('#in-user','admin');await page.fill('#in-pass','123');
 await page.click('#btn-setup');check('短密码被原生表单拦截',setupWrites===0 && await page.locator('#in-pass').evaluate(e=>!e.validity.valid));
 await page.fill('#in-pass','auth-check-password');await page.fill('#in-user','中文');
 await page.click('#btn-setup');check('用户名规则与服务端一致',setupWrites===0 && await page.locator('#in-user').evaluate(e=>!e.validity.valid));
 await page.fill('#in-user','admin');
 await page.click('[data-password="in-pass"]');check('初始化密码显隐',await page.locator('#in-pass').getAttribute('type')==='text');
 let release;const gate=new Promise(r=>release=r);
 await page.route('**/api/setup',async r=>{await gate;r.fulfill({status:500,contentType:'application/json',body:JSON.stringify({error:'测试部署失败，请重试'})});});
 await page.click('#btn-setup');check('初始化等待锁定表单',await page.locator('#in-domain').isDisabled());
 check('等待状态与步骤一致',await page.locator('.auth-steps li[aria-current]').innerText().then(t=>t.includes('自动部署')));
 await page.screenshot({path:path.join(SHOTS,'setup-pending.png'),fullPage:true,animations:'disabled'});
 release();await page.waitForSelector('#setup-err:not(.hidden)');
 check('失败后可以修改并重试',await page.locator('#in-domain').isEnabled() && await page.locator('#btn-setup').isEnabled());
 check('错误得到键盘焦点',await page.locator('#setup-err').evaluate(e=>e===document.activeElement));
 await page.unroute('**/api/setup');await page.click('#btn-setup');await page.waitForSelector('#view-dash:not(.hidden)',{timeout:20000});
 check('真实初始化进入仪表盘',await page.locator('#workspace-title').isVisible());
 await page.click('#btn-logout');await page.waitForSelector('#view-login:not(.hidden)');
 await shots('login');
 check('退出后隐藏系统账号及主机详情',!(await page.locator('#side-os').isVisible()) && !(await page.locator('#side-user').isVisible()));
 check('跳转链接指向登录表单',await page.locator('.skip-link').getAttribute('href')==='#login-title');
 await page.fill('#login-user','admin');await page.fill('#login-pass','wrong-password');
 await page.click('[data-password="login-pass"]');check('登录密码显隐',await page.locator('#login-pass').getAttribute('type')==='text');
 let loginWrites=0;let releaseLogin;const loginGate=new Promise(r=>releaseLogin=r);
 await page.route('**/api/login',async r=>{loginWrites++;await loginGate;r.fulfill({status:401,contentType:'application/json',body:JSON.stringify({error:'用户名或密码错误'})});});
 await page.locator('#login-user').press('Enter');
 check('用户名回车可提交且显示等待',await page.locator('#btn-login').isDisabled());
 await page.evaluate(()=>document.querySelector('#login-form').requestSubmit());check('等待时不重复提交',loginWrites<=1);
 releaseLogin();await page.waitForSelector('#login-err:not(.hidden)');
 check('登录失败保留输入并可重试',await page.locator('#login-user').inputValue()==='admin' && await page.locator('#btn-login').isEnabled());
 await page.screenshot({path:path.join(SHOTS,'login-error.png'),fullPage:true,animations:'disabled'});
 await page.unroute('**/api/login');await page.fill('#login-pass','auth-check-password');await page.locator('#login-pass').press('Enter');
 await page.waitForSelector('#view-dash:not(.hidden)');
 check('真实登录与回车流程正常',await page.locator('#workspace-title').isVisible());
 check('登录成功清空密码并恢复隐藏',await page.locator('#login-pass').inputValue()==='' && await page.locator('#login-pass').getAttribute('type')==='password');
 check('仪表盘恢复系统信息',await page.locator('#side-os').isVisible());
 check('无前端脚本异常',errors.length===0);
 console.log(`AUTH: ${count} passed; screenshots: ${SHOTS}`);
})().catch(e=>{console.error(e);console.error(logs.slice(-2500));process.exitCode=1;}).finally(async()=>{if(browser)await browser.close();if(server)await new Promise(r=>{if(server.exitCode!==null)return r();server.once('exit',r);server.kill('SIGTERM');});fs.rmSync(HOME,{recursive:true,force:true});});
