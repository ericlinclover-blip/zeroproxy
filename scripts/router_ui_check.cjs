/**
 * 路由器管理界面 (LuCI 页面 + /cgi-bin 接口) 的真实浏览器验证。
 *
 * 界面跑在路由器上, 本机没有 OpenWrt —— 所以这里用一个**模拟路由器**:
 * 一个几十行的 node HTTP 服务, 按 cgi 脚本同样的 JSON 契约应答
 * (GET status / POST add|drop|toggle|refresh / GET log), 并复现"没登录"那条路径。
 * 页面本身是原样加载的仓库文件, 没有任何替换。
 *
 * 验证的是用户会遇到的四件事: 状态渲染、总开关、添加服务器、移除服务器。
 *
 * 用法:
 *   ZP_NODE_PATH=/Applications/ChatGPT.app/Contents/Resources/cua_node/lib/node_modules \
 *   ZP_CHROME_PATH=".../Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing" \
 *   node scripts/router_ui_check.cjs
 */
const http = require("http");
const path = require("path");
const fs = require("fs");

const ROOT = path.resolve(__dirname, "..");
const LUCi_DIR = path.join(ROOT, "backend", "zeroproxy", "client", "luci");
const SHOT_DIR = process.env.ZP_SHOT_DIR || path.join(ROOT, "work", "browser-check");
let PORT = parseInt(process.env.ZP_UI_PORT || "0", 10);

for (const extra of (process.env.ZP_NODE_PATH || "").split(path.delimiter)) {
  if (extra && !module.paths.includes(extra)) module.paths.push(extra);
}

// playwright 必须在起模拟路由器 (makeMock/listen) **之前** require: 本机没有这个模块时,
// 旧写法是先把模拟服务挂上端口再抛 MODULE_NOT_FOUND, 依赖缺失时的退出路径会绕过
// finally 里的 server.close()。先 require 再起服务: 缺依赖就干净退出 1。
let chromium;
try {
  ({ chromium } = require("playwright"));
} catch (e) {
  console.error(
    "缺少 playwright: 本脚本需要 node + playwright + Chromium。\n" +
      "本机没有时请明确跳过 (不能当作\"通过\"), 不要安装到项目里来跑。\n" +
      "原始错误: " + (e && e.message ? e.message : e)
  );
  process.exit(1);
}

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok });
  console.log(`  ${ok ? "✓" : "✗"} ${name}${detail ? " — " + detail : ""}`);
}

/** 模拟路由器: 没有 cookie = 没登录 LuCI (与 cgi 一致)。 */
function makeMock() {
  const state = {
    core: "running",
    mode: "tun",
    covered: "full",
    why: "",
    client: "1.4.57",
    servers: [{ key: "hkk_i3_pub_8899", base: "https://hkk.i3.pub:8899", id: "dv056b52958542564a" }],
    log: "zeroproxy-agent: 配置已更新并重载",
    // 一键更新的模拟: 每问一次 update-log 就"长"一段, 最后一段带 EXIT=0。
    // 真实的日志格式就是安装脚本自己打印的那些 `==>` 小节, 所以这里照抄了一份。
    updAt: 0,
    updGuard: false,
    // 一键更新那条路的另外两种现场 (都来自真机):
    //   updSlow  —— 后端要先去面板取脚本 (会重试三次, 最坏几十秒) 才回话;
    //   updSkip  —— 这次**没有开始** (取不到面板的脚本), 日志里落一个 SKIP=1 终态。
    //   updFail  —— 跑到"拉取配置"那一步失败 (真机上最常见的那次失败, 见 8.66)。
    updSlow: false,
    updSkip: false,
    updFail: false,
    // 路由器上根本没有 update.log 时, CLI 会回一句人话 —— 那句不许被当成"有一次在跑"。
    updNoLog: false,
    updOverride: "",
    // 日志里还躺着**上一次**更新的"更新完成" (真机上点确认那一刻看到的就是这个) ——
    // 界面不许把它当成本次的结果, 否则会假报完成并自动刷新。
    updStale: false,
    // 性能模式那块表盘的现场。默认"能开、没开" —— 与一台 25.12 且已补上 BTF 的机器一致。
    perf: { cap: "1", state: "off", live: "0", why: "", exit_ip: "", busy: "0", progress: "" },
    perfAt: 0,
    //: WAN 口的收+发字节数。表盘的转速就是它算的 —— 打开之后每次轮询往前走一点,
    //: 这样"针跟着真实流量动"这件事在演练里也验得了。
    wan: 0,
  };
  const HEAD = "面板版本 v1.9.9 (本机 v1.9.8) —— 开始更新。\n";
  const UPD_LOG = [
    "",
    HEAD + "==> 检查环境\n  ✓ 设备: GL.iNet GL-MT3000 · arm64 · OpenWrt 24.10.4 (内核 6.6.110)\n  ✓ 面板可达",
    HEAD + "==> 接入账号\n  ✓ 已接入过 (设备 dv056b52958542564a), 先沿用原有凭据",
    HEAD + "==> 探测网络数据面能力\n  ✓ 数据面: TUN (全屋设备 + 路由器自身)\n  · IPv6 一并接管",
    HEAD + "==> 下载代理内核 (mihomo · arm64)\n  … 已下载 8192 KB (930 KB/s)",
    HEAD + "==> 写入运行文件\n==> 准备分流数据库 (GeoIP / GeoSite)\n  ✓ 分流数据库就绪\n" +
          "==> 拉取配置\n  ✓ 配置已写入 /etc/zeroproxy/config.yaml",
    HEAD + "==> 准备本地控制面 (可选件)\n  ✓ 本地控制面已是最新: zpcore 1.2.1\n" +
          "==> 安装网页管理界面\n  ✓ 管理界面已装好\n==> 启动并自检\n  ✓ 内核已启动\n  ✓ TUN 已建立\nEXIT=0",
  ];
  const json = (res, body) => {
    res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
    res.end(JSON.stringify(body));
  };
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://x");
    const action = url.searchParams.get("a") || "";
    const authed = /sysauth/.test(req.headers.cookie || "");
    if (url.pathname === '/luci-host') {
      res.writeHead(200, {'Content-Type':'text/html; charset=utf-8'});
      const legacy = url.searchParams.has('legacy');
      const oldWrapper = "return view.extend({render:function(){return E('iframe',{src:'/cgi-bin/zeroproxy',style:'width:100%;height:78vh;border:0;border-radius:10px;background:transparent',title:'ZeroProxy'});}});";
      const wrapper=JSON.stringify(legacy ? oldWrapper : fs.readFileSync(path.join(LUCi_DIR,'status.js'),'utf8'));
      res.end(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>
        :root{--primary:#5e72e4;--surface:#fff;--host-bg:#f4f5f7;--host-text:#454a54}*{box-sizing:border-box}body{margin:0;background:var(--host-bg);color:var(--host-text);font:14px/1.5 system-ui,sans-serif}body[data-theme=dark]{--surface:#252932;--host-bg:#171b22;--host-text:#e4e7ef;--primary:#93a7ff}.sidebar{position:fixed;inset:0 auto 0 0;width:210px;background:var(--surface);padding:24px 16px}.sidebar h1{color:var(--primary);font-size:24px;margin:0 0 36px}.sidebar a{display:block;padding:14px;margin:4px 0}.sidebar .active{background:var(--primary);color:white;border-radius:5px}.topbar{height:70px;margin-left:210px;background:var(--primary)}main{margin-left:210px;padding:20px}#host-panel{background:var(--surface);padding:16px;border-radius:8px;min-width:0}footer{margin:20px;color:var(--primary);font-size:12px;text-align:right}@media(max-width:700px){.sidebar{display:none}.topbar,main{margin-left:0}main{padding:12px}#host-panel{padding:10px}.topbar{height:48px}}
        body{height:100vh;overflow:hidden}.main{margin-left:210px;height:100vh;overflow:hidden}.main-right{height:100%;overflow:auto}.main .topbar,.main main{margin-left:0}@media(max-width:700px){.main{margin-left:0}}${legacy ? '#host-panel{padding:0}iframe{height:78vh!important;max-height:78vh!important}' : ''}
      </style></head><body><aside class="sidebar"><h1>GL · OpenWrt</h1><a>首页</a><a>状态</a><a>网络</a><a class="active">服务 / ZeroProxy</a><a>系统</a></aside><div class="main"><div class="main-right"><header class="topbar"></header><main id="maincontent"><section id="host-panel" class="container"><div id="view"></div></section><footer>LuCI / 主题嵌入测试环境</footer></main></div></div><script>
      const wrapper=new Function('view','E',${wrapper});
      const view=wrapper({extend:obj=>obj},(tag,attrs)=>{const el=document.createElement(tag);for(const [k,v] of Object.entries(attrs))el.setAttribute(k,v);return el;});
      document.getElementById('view').appendChild(view.render());
      </script></body></html>`); return;
    }
    if (url.pathname.startsWith("/cgi-bin/")) {
      // 与 cgi 一致: 页面与脚本本身不需要登录, 数据接口才要
      const want = url.searchParams.get("file");
      if (want === "app.js" || want === "perf.js") {
        res.writeHead(200, { "Content-Type": "text/javascript; charset=utf-8" });
        res.end(fs.readFileSync(path.join(LUCi_DIR, want))); return;
      }
      if (!action && !want) {
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(fs.readFileSync(path.join(LUCi_DIR, "index.html"))); return;
      }
      if (!authed) return json(res, { ok: false, error: "未登录 LuCI" });
      const mutating = ["add", "drop", "toggle", "refresh", "update", "perf-on", "perf-off"].includes(action);
      if (mutating && req.method !== "POST") {
        res.writeHead(405, { "Content-Type": "application/json; charset=utf-8" });
        return res.end(JSON.stringify({ ok: false, error: "这个操作必须使用 POST" }));
      }
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const payload = body ? JSON.parse(body) : {};
        if (action === "status") {
          // 切换是"分几拍"完成的 (真机上就是一拍一拍来的): 前 ~0.9 秒在取内核, 之后校验+
          // 切换, 大约 2.2 秒后生效。界面必须把这几拍画成进度, 而不是一步跳过 ——
          // 这就是那段"进入中"动画的依据。
          const p = state.perf || {};
          if (p.state === "on" && p.live === "0" && state.perfAt) {
            const dt = Date.now() - state.perfAt;
            if (dt > 900) p.progress = "正在准备性能模式…|  · 取性能模式内核 (dae · arm64)…|  · 配置已校验通过";
            if (dt > 1600) p.progress = "…|  · 切换数据面 (停标准模式 → 起 dae)…|  · dae 在跑, 正在验证流量真的过得去…";
            if (dt >= 2200) {
              state.perf = { ...p, live: "1", busy: "0", exit_ip: "203.0.113.7", progress: "DONE=0" };
              state.mode = "ebpf";
              state.core = "stopped";
            }
          }
          // 开着的时候让"流量"往前走: 每轮询 ~900 KB, 表针就该跟着抬起来
          if ((state.perf || {}).live === "1") state.wan = (state.wan || 0) + 900 * 1024;
          return json(res, { ok: true, ...state });
        }
        if (action === "perf-on") {
          state.perfAt = Date.now();
          state.perf = { cap: "1", state: "on", live: "0", why: "", exit_ip: "", busy: "1",
                         progress: "正在准备性能模式…" };
          return json(res, { ok: true, message: "已开始切换到性能模式 (后台进行, 约一分钟; 界面会显示进度)" });
        }
        if (action === "perf-off") {
          state.perfAt = 0;
          state.perf = { cap: "1", state: "off", live: "0", why: "", exit_ip: "", busy: "0", progress: "DONE=0" };
          state.mode = "tun";
          state.core = "running";
          return json(res, { ok: true, message: "已开始切回标准模式" });
        }
        if (action === "add") {
          if (!/^https?:\/\/.+\/c\/.+/.test(payload.url || "")) {
            return json(res, { ok: false, error: "这看起来不是一个面板链接" });
          }
          const base = payload.url.replace(/\/c\/.*$/, "");
          const key = base.replace(/^https?:\/\//, "").replace(/[^A-Za-z0-9]/g, "_").slice(0, 32);
          state.servers.push({ key, base, id: "dv" + "a".repeat(16) });
          return json(res, { ok: true, message: `已接入: ${key}\n配置已更新并重载` });
        }
        if (action === "drop") {
          state.servers = state.servers.filter((s) => s.key !== payload.key);
          return json(res, { ok: true, message: `已移除 ${payload.key}` });
        }
        if (action === "toggle") {
          state.core = payload.on ? "running" : "stopped";
          return json(res, { ok: true, message: `已请求面板把总开关设为「${payload.on ? "on" : "off"}」` });
        }
        if (action === "refresh") return json(res, { ok: true, message: "完成" });
        const replyUpdate = () => {
          if (state.updSkip) {
            // CLI 在"没有开始"时也会往日志里落一个终态 —— 没有它, 刷新之后进度面板
            // 会一直转下去, 看起来像卡住 (实际是这次根本没开始)。
            state.updOverride = "==> 正在取面板的安装脚本\n" +
              "取不到面板的安装脚本 (面板不可达?) —— 这次没有开始更新。\nSKIP=1";
            return json(res, { ok: true, message:
              "取不到面板的安装脚本 (面板不可达?) —— 稍后再试, 或看 zeroproxy update-log" });
          }
          if (state.updFail) {
            // 真机上最常见的那次失败: 前九步都过去了, 卡在"拉取配置"(面板丢包)。
            // 这份日志是从真机的 update.log 抄下来的, 一字未改 —— 界面必须能把
            // "卡在哪一步"指出来, 而不是九步全绿配一个"失败 56%"。
            state.updOverride = HEAD +
              "==> 检查环境\n  ✓ 设备: GL.iNet GL-MT3000 · arm64 · OpenWrt 24.10.4 (内核 6.6.110)\n" +
              "==> 接入账号\n  ✓ 已接入过 (设备 dv056b52958542564a), 先沿用原有凭据\n" +
              "==> 探测网络数据面能力\n  ✓ 数据面: TUN (全屋设备 + 路由器自身)\n" +
              "==> 下载代理内核 (mihomo · arm64)\n  ✓ 内核已存在且可执行 (版本 v1.19.32), 跳过下载\n" +
              "==> 写入运行文件\n" +
              "==> 准备分流数据库 (GeoIP / GeoSite)\n  ✓ 分流数据库就绪 (397455 + 4254934 字节)\n" +
              "==> 拉取配置\n" +
              "安装失败: 拉取配置失败 —— 面板暂时联系不上 (网络抖动 / 面板正忙), 或它拒绝了这台设备的凭据。\n" +
              "  本机**仍在使用原来的配置**, 现有代理不受影响。\n" +
              "  只有在**反复**失败之后, 才需要回面板「客户端」重新生成一条带配对码的安装命令重新接入。\n" +
              "  现在先做这一件: 再点一次「更新客户端」—— 这条路上掉一个包就长这样, 重试一次通常就过了。\n" +
              "EXIT=1";
            return json(res, { ok: true, message: HEAD + "已开始更新 (后台进行, 约 1 分钟)。" });
          }
          if (state.updGuard) {
            return json(res, { ok: true, message:
              "面板上是 v1.9.7，这台机器已经是 v1.9.8 —— 那不是升级。\n" +
              "  面板那边可能还没更新完: 先在面板点「检查更新 → 一键更新」, 再回来点这个按钮。" });
          }
          state.updAt = 1;
          return json(res, { ok: true, message: HEAD + "已开始更新 (后台进行, 约 1 分钟; 配置与凭据保留)。" });
        };
        if (action === "update") {
          // 真机上的后端不是秒回的: 它先去面板取脚本。界面必须在**回话之前**就有反馈。
          if (state.updSlow) return setTimeout(replyUpdate, 1200);
          return replyUpdate();
        }
        if (action === "update-log") {
          if (state.updNoLog) return json(res, { ok: true, message: "(还没有更新记录)" });
          if (state.updOverride) return json(res, { ok: true, message: state.updOverride });
          if (state.updStale && state.updAt === 0) {
            return json(res, { ok: true, message: UPD_LOG[UPD_LOG.length - 1] });
          }
          // 每问一次就往前走一格, 到最后一格 (带 EXIT=0) 就停在那里
          if (state.updAt > 0 && state.updAt < UPD_LOG.length - 1) state.updAt += 1;
          return json(res, { ok: true, message: UPD_LOG[state.updAt] });
        }
        if (action === "proxies") return json(res, {proxies:{GLOBAL:{all:["DIRECT","香港 Reality"],now:state.globalSelected || "DIRECT"},"🚀 节点选择":{all:["香港 Reality","日本 QUIC"],now:state.selected || "香港 Reality"},"香港 Reality":{type:"VLESS",history:[{delay:42}]},"日本 QUIC":{type:"Hysteria2",history:[]}}});
        if (action === "select-node") { state.selectedGroup=payload.group; if(payload.group==='GLOBAL')state.globalSelected=payload.name;else state.selected=payload.name; return json(res,{ok:true}); }
        if (action === "test-delay") return json(res,{delay:42});
        if (action === "mode") { state.routing_mode=payload.mode; return json(res,{ok:true}); }
        if (action === "clients") return json(res,{ok:true,clients:[{name:"客厅的电视与媒体设备",ip:"2001:db8:abcd:1234::100",mac:"AA:BB:CC:DD:EE:FF"}]});
        if (action === "doctor") return json(res,{ok:true,message:"模拟诊断完成"});
        if (action === "log") return json(res, { ok: true, log: state.log });
        return json(res, { ok: false, error: "未知操作" });
      });
      return;
    }
    // 目录请求按 uhttpd 的规矩回 index.html
    if (/^\/cgi-bin\/zeroproxy$/.test(url.pathname) && url.searchParams.get("file") === "app.js") {
      res.writeHead(200, { "Content-Type": "text/javascript; charset=utf-8" });
      res.end(fs.readFileSync(path.join(LUCi_DIR, "app.js"))); return;
    }
    let rel = url.pathname.replace(/^\/zeroproxy\/?/, "");
    if (!rel || rel.endsWith("/")) rel += "index.html";
    if (rel === "favicon.ico") { res.writeHead(204); res.end(); return; }
    const full = path.join(LUCi_DIR, rel);
    if (!full.startsWith(LUCi_DIR) || !fs.existsSync(full)) {
      res.writeHead(404); res.end("not found"); return;
    }
    const media = rel.endsWith(".js") ? "text/javascript; charset=utf-8" : "text/html; charset=utf-8";
    res.writeHead(200, { "Content-Type": media });
    res.end(fs.readFileSync(full));
  });
  // 让用例能改这一台"路由器"的现场状态 (例如模拟"内核在跑但一级都没接管")
  server.zpState = state;
  return server;
}

async function main() {
  fs.mkdirSync(SHOT_DIR, { recursive: true });
  const server = makeMock();
  await new Promise((resolve,reject) => { server.once("error",reject); server.listen(PORT,"127.0.0.1",resolve); });
  PORT = server.address().port;
  const base = `http://127.0.0.1:${PORT}/cgi-bin/zeroproxy`;
  let browser;
  try {
    browser = await chromium.launch(
      process.env.ZP_CHROME_PATH ? { executablePath: process.env.ZP_CHROME_PATH } : {}
    );
    const ctx = await browser.newContext({ viewport: { width: 460, height: 900 } });
    const page = await ctx.newPage();
    // "日志多久没动就算卡住"那个阈值在真机上是 45 秒 —— 演练把它调小, 这样这一条能在
    // 一两秒内验完 (与 ZP_DOCTOR_PROBES 同一个思路: 只给演练用的旋钮)。
    await page.addInitScript(() => { window.ZP_UPD_SILENT_MS = "800"; });
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });

    console.log("ZeroProxy 路由器界面验证");
    console.log("\n[1] 没登录 LuCI 时");
    await page.goto(base);
    await page.waitForFunction(() => /未登录/.test(document.getElementById("sub").textContent));
    check("未登录时明确提示, 而不是空白页", true, await page.locator("#sub").innerText());
    check("未登录时不显示服务器列表", await page.locator(".srv").count() === 0);
    // 真机反馈: 用户看到一个"关着且点不动"的开关, 以为是 bug (其实是未授权)。所以这里
    // 盯死三件事: 开关禁用、按钮禁用、页面明说下一步该敲什么命令。
    check("未授权时总开关是禁用的 (不再是「看起来能点」)", await page.locator("#toggle").isDisabled());
    check("未授权时添加 / 重新拉取也禁用",
      await page.locator("#add").isDisabled() && await page.locator("#refresh").isDisabled());
    check("未授权时给出可执行的下一步 (zeroproxy ui)",
      /zeroproxy ui/.test(await page.locator("#servers").innerText()),
      (await page.locator("#servers").innerText()).split("\n")[0]);

    console.log("\n[2] 已登录 (带上 LuCI 会话 cookie)");
    await ctx.addCookies([{ name: "sysauth_http", value: "mock-session", url: `http://127.0.0.1:${PORT}` }]);
    await page.reload();
    await page.waitForSelector(".srv", {state:"attached"});
    check("状态卡显示内核与模式", /内核运行中/.test(await page.locator("#sub").innerText())
      && /TUN/.test(await page.locator("#sub").innerText()), await page.locator("#sub").innerText());
    check("总开关按实际状态打开", await page.locator("#toggle").isChecked());
    check("列出一台服务器", (await page.locator(".srv").count()) === 1);
    check("服务器显示地址与设备 id", /hkk\.i3\.pub/.test(await page.locator(".srv").innerText()));
    await page.screenshot({ path: path.join(SHOT_DIR, "router-ui.png") });

    const go = async (tab) => page.locator(`.tab-btn[data-tab="${tab}"]`).click();
    await go("nodes");
    console.log("\n[3] 添加第二台服务器");
    await page.fill("#url", "https://usa.example.com:8899/c/abcdef123456");
    await page.click("#add");
    await page.waitForFunction(() => document.querySelectorAll(".srv").length === 2);
    check("添加后列表变成两台", (await page.locator(".srv").count()) === 2,
      (await page.locator(".srv").nth(1).innerText()).split("\n")[0]);
    check("输入框被清空 (方便接着粘下一个)", (await page.inputValue("#url")) === "");

    console.log("\n[4] 非法链接会被当面拒绝");
    await page.fill("#url", "随便写点什么");
    await page.click("#add");
    await page.waitForFunction(() => /不是一个面板链接/.test(document.getElementById("add-hint").textContent));
    check("乱填时给出可理解的提示", true, await page.locator("#add-hint").innerText());

    console.log("\n[5] 总开关与移除");
    await go("dashboard");
    await page.click("#toggle + .track");
    await page.waitForTimeout(300);
    check("关掉开关后立刻有反馈", /已请求面板/.test(await page.locator("#toast").innerText()));

    page.on("dialog", (d) => d.accept());
    await go("nodes");
    await page.locator(".srv").nth(1).locator("[data-drop]").click();
    await page.waitForFunction(() => document.querySelectorAll(".srv").length === 1);
    check("移除后只剩一台", (await page.locator(".srv").count()) === 1);

    console.log("\n[6] 日志");
    await go("logs");
    await page.locator("#tab-logs details summary").click();
    await page.waitForFunction(() => /zeroproxy-agent/.test(document.getElementById("log").textContent));
    check("日志能展开并显示内容", true);

    // 真机 8.45: 内核启动成功、面板/界面显示"全屋代理已开启", 而 tun 建不出来、tproxy
    // 也没有 —— 局域网里一台设备都没被接管。所以界面必须按**现场**说话。
    console.log("\n[7] 内核在跑但一级都没接管 (不许谎报「全屋」)");
    server.zpState.core = "running";
    server.zpState.mode = "none";
    server.zpState.covered = "none";
    server.zpState.why = "建不出 tun 设备: Operation not supported";
    await page.reload();
    await page.waitForSelector(".srv", {state:"attached"});
    const noneSub = await page.locator("#sub").innerText();
    check("明说未接管, 不说成全屋透明代理",
      /未接管/.test(noneSub) && !/全屋透明代理/.test(noneSub), noneSub);
    check("把探测到的原因一起显示出来 (不用回终端猜)",
      /Operation not supported/.test(noneSub), noneSub);

    console.log("\n[8] 一键更新: 点了就有反馈 → 进度条 → 完成后的跳转");
    // 真机现场是"点了确认之后什么都没发生, 只能刷新页面才看到它其实一直在跑"。两件事一起
    // 凑出这个结果: ① 后端要先去面板取脚本 (重试三次, 丢包的链路上最坏几十秒) 才回话;
    // ② 日志里还躺着上一次更新的"更新完成"。这里把两件事都复现出来。
    server.zpState.updSlow = true;                 // 后端 1.2 秒后才回话
    server.zpState.updStale = true;                // 日志里是上一次的"更新完成"
    const tClick = Date.now();
    await page.click("#update");            // confirm 由上面的 dialog 处理器自动接受
    await page.waitForSelector("#upd:not([hidden])", { timeout: 900 });
    const dtClick = Date.now() - tClick;
    check("确认之后立刻有反馈: 后端还没回话, 进度面板已经亮出来", dtClick < 1100,
      `等了 ${dtClick}ms (后端 1200ms 后才回话)`);
    check("点了更新之后出现进度面板", await page.locator("#upd").isVisible());
    check("启动态是不确定进度, 不编一个百分比", (await page.locator("#upd-pct").innerText()) === "…",
      await page.locator("#upd-pct").innerText());
    check("启动态明说在干什么 (不是一句干等)",
      /取面板的安装脚本/.test(await page.locator("#upd-sub").innerText()),
      await page.locator("#upd-sub").innerText());
    check("不把上一次的'更新完成'当成本次结果",
      !/更新完成/.test(await page.locator("#upd-title").innerText()),
      await page.locator("#upd-title").innerText());
    check("更新中按钮锁住 (再点一下就是第二次更新)",
      await page.locator("#update").isDisabled());
    // 等原生 confirm 那层灰底退完再截图 —— 否则拍到的是"半透明"的一页 (第一次就是这样)。
    await page.waitForTimeout(260);
    await page.screenshot({ path: path.join(SHOT_DIR, "router-update-starting.png") });
    server.zpState.updSlow = false;
    server.zpState.updStale = false;
    await page.waitForFunction(
      () => /v1\.9\.8 → v1\.9\.9/.test(document.getElementById("upd-sub").textContent),
      null, { timeout: 8000 });
    check("后端回话之后接上真实进度 (标题写着老版本 → 新版本)",
      /v1\.9\.8 → v1\.9\.9/.test(await page.locator("#upd-sub").innerText()),
      await page.locator("#upd-sub").innerText());
    // 进度会随日志推进 (模拟器每问一次就长一格)
    await page.waitForFunction(
      () => parseInt(document.getElementById("upd-pct").textContent, 10) >= 30, null, { timeout: 10000 });
    check("进度条随步骤推进 (>=30%)", true, await page.locator("#upd-pct").innerText());
    const stepStates = () => page.$$eval("#upd-steps li", (ls) => ({
      ok: ls.filter((l) => l.className === "ok").length,
      doing: ls.filter((l) => l.className === "doing").length,
      todo: ls.filter((l) => !l.className).length,
    }));
    const mid = await stepStates();
    check("步骤清单同时有 已完成 / 进行中 / 待执行",
      mid.ok > 0 && mid.doing === 1 && mid.todo > 0, JSON.stringify(mid));
    check("实时行显示当前在做什么", (await page.locator("#upd-live").innerText()).length > 0,
      await page.locator("#upd-live").innerText());
    await page.screenshot({ path: path.join(SHOT_DIR, "router-update-progress.png") });

    await page.waitForFunction(
      () => /更新完成/.test(document.getElementById("upd-title").textContent), null, { timeout: 20000 });
    // 等进度条那条 0.55s 的过渡跑完再截图 —— 否则拍到的是"正在填满"的中途,
    // 看起来像没填 (第一次就是这么误判的)。
    await page.waitForTimeout(700);
    await page.screenshot({ path: path.join(SHOT_DIR, "router-update-done.png") });
    check("完成后标题变成「更新完成」", true);
    check("完成后是 100%", (await page.locator("#upd-pct").innerText()) === "100%");
    check("完成后提示正在加载新版本",
      /正在加载新版本/.test(await page.locator("#upd-sub").innerText()));
    check("完成后按钮区隐藏",
      await page.locator("#upd-actions").isHidden());
    check("侧栏步骤全部打勾",
      (await stepStates()).todo === 0 && (await stepStates()).doing === 0);
    // 停一下让人看清"完成", 再整页换新版本: 刷新后进度面板应当收起来
    await page.waitForFunction(
      () => document.getElementById("upd").hidden === true, null, { timeout: 20000 });
    check("约两秒后自动换成新版本页面 (刷新完进度面板收起)", true);

    console.log("\n[9] 被降级闸门拦下时, 不显示假的进度");
    server.zpState.updGuard = true;
    await page.click("#update");
    await page.waitForFunction(
      () => /那不是升级/.test(document.getElementById("update-hint").textContent), null, { timeout: 8000 });
    check("把 CLI 的原话写在提示里", true,
      (await page.locator("#update-hint").innerText()).split("\n")[0]);
    check("没有开始更新就不显示进度条", await page.locator("#upd").isHidden());
    server.zpState.updGuard = false;

    console.log("\n[10] 「没有开始」也是一个终态: 刷新之后不许停在一个假的进度上");
    // 闸门拦下 / 取不到面板的脚本都属于"这次没开始"。它也得在日志里留一个终态 (SKIP=1):
    // 只落一行 "==> 正在取面板的安装脚本" 的话, 刷新之后进度面板会一直转下去 —— 那正是
    // 用户报的"点完没反应, 刷新才看到一个转不完的条"。
    server.zpState.updSkip = true;
    await page.click("#update");
    await page.waitForFunction(
      () => /取不到面板的安装脚本/.test(document.getElementById("update-hint").textContent),
      null, { timeout: 8000 });
    check("没开始时把 CLI 的原话说清楚", true,
      (await page.locator("#update-hint").innerText()).split("\n")[0]);
    check("没开始就不显示进度面板", await page.locator("#upd").isHidden());
    await page.reload();
    await page.waitForSelector(".srv", {state:"attached"});
    await page.waitForTimeout(700);          // 给"刷新后接着显示"那段判断留出时间
    check("刷新之后也不会恢复成一个转不完的假进度",
      await page.locator("#upd").isHidden());
    server.zpState.updSkip = false;

    console.log("\n[11] 失败时要说清卡在哪一步 (真机截图上曾是「九步全绿 + 更新失败 56%」)");
    // 这份日志是从真机的 update.log 抄下来的: 前面几步都过了, 卡在"拉取配置"(面板丢包)。
    server.zpState.updFail = true;
    await page.click("#update");
    await page.waitForFunction(
      () => /更新失败/.test(document.getElementById("upd-title").textContent), null, { timeout: 8000 });
    const stepsNow = await page.$$eval("#upd-steps li",
      (ls) => ls.map((l) => ({ cls: l.className, txt: l.innerText.trim() })));
    const badIdx = stepsNow.findIndex((x) => x.cls === "bad");
    check("卡住的那一步单独标出来, 且正是「拉取配置」",
      badIdx >= 0 && stepsNow.filter((x) => x.cls === "bad").length === 1
      && /拉取配置/.test(stepsNow[badIdx].txt), JSON.stringify(stepsNow[badIdx] || {}));
    check("它前面的步骤是「已完成」, 后面的一步都没打勾 (不再假装全做完了)",
      stepsNow.slice(0, badIdx).every((x) => x.cls === "ok")
      && stepsNow.slice(badIdx + 1).every((x) => x.cls !== "ok" && x.cls !== "bad"),
      JSON.stringify(stepsNow.map((x) => x.cls)));
    check("提示里点名卡在哪一步", /卡在「拉取配置」/.test(await page.locator("#upd-sub").innerText()),
      await page.locator("#upd-sub").innerText());
    check("实时行落在能立刻做的那一句上 (不是吓人的「重新配对」)",
      /再点一次「更新客户端」/.test(await page.locator("#upd-live").innerText()),
      await page.locator("#upd-live").innerText());
    check("失败时给出「重试」", await page.locator("#upd-retry").isVisible());
    // 失败态的三行字都比别处长 (点名步骤 / 该做什么)。手机宽度下最怕的就是它把页面撑宽 ——
    // 撑宽之后整页会横向滚动, 截图里就是"左边被切掉"的样子。
    const overflow = await page.evaluate(() => {
      const w = window.innerWidth;
      const wide = [];
      const nowrap = [];
      document.querySelectorAll("body *").forEach((el) => {
        const r = el.getBoundingClientRect();
        if (r.width > 0 && r.right > w + 1) {
          wide.push(`${el.id || el.className || el.tagName}@${Math.round(r.right)}`);
        }
        const cs = getComputedStyle(el);
        if (cs.whiteSpace === "nowrap" || el.tagName === "PRE") {
          nowrap.push(`${el.id || el.className || el.tagName}:${cs.whiteSpace}:${Math.round(el.scrollWidth)}`);
        }
      });
      return {
        scrollW: document.documentElement.scrollWidth, innerW: w,
        scrollX: window.scrollX, wide: wide.slice(0, 6), nowrap: nowrap.slice(0, 8),
      };
    });
    check("失败态没有把页面撑出横向滚动 (手机上不会左右跑)",
      overflow.scrollW <= overflow.innerW + 1 && overflow.scrollX === 0, JSON.stringify(overflow));
    await page.waitForTimeout(700);          // 等那条 0.55s 的进度条过渡跑完再拍
    await page.screenshot({ path: path.join(SHOT_DIR, "router-update-failed.png") });
    server.zpState.updFail = false;

    console.log("\n[12] 没有更新记录时, 不许凭空长出「正在更新中」(真机 8.70)");
    // 路由器上没有 update.log 时, CLI 会回一句"(还没有更新记录)"。8.66 加的"刷新之后接着
    // 显示"只看"非空 + 没有终态", 于是这句话被当成一次正在跑的更新 —— 每次打开页面都长出
    // 一个进度面板, 连按钮都锁成「更新中…」。用户看到的正是那个"卡住"的假象。
    server.zpState.updOverride = "";
    server.zpState.updNoLog = true;
    await page.reload();
    await page.waitForSelector(".srv", {state:"attached"});
    await page.waitForTimeout(700);          // 让"刷新后接着显示"那段判断跑完
    check("没有更新记录 → 不显示进度面板", await page.locator("#upd").isHidden());
    check("「更新客户端」按钮没被锁住 (还能点)",
      await page.locator("#update").isEnabled(), await page.locator("#update").innerText());
    server.zpState.updNoLog = false;

    console.log("\n[13] 上一次跑到一半断了: 进度条不许一直转 —— 要给「重试」");
    // 日志里留着一次"开始了、但永远没有终态"的运行 (真机: 更新到一半断电/重启/被杀)。
    // 页面必须自己发现"它已经很久没动了", 并把出口摆出来 —— 否则就是那条既没成功
    // 也不停的进度条。
    server.zpState.updOverride = "面板版本 v1.9.9 (本机 v1.9.8) —— 开始更新。\n"
      + "==> 检查环境\n  ✓ 面板可达\n==> 接入账号\n";
    await page.reload();
    await page.waitForSelector(".srv", {state:"attached"});
    await page.waitForFunction(
      () => document.getElementById("upd").hidden === false, null, { timeout: 5000 });
    check("断掉的那次运行照实显示成进度面板", await page.locator("#upd").isVisible());
    await page.waitForFunction(
      () => document.getElementById("upd-retry").hidden === false, null, { timeout: 6000 });
    check("卡住之后「重试」自己出来", await page.locator("#upd-retry").isVisible());
    check("提示里说清是「很久没有新内容」",
      /没有新内容/.test(await page.locator("#update-hint").innerText()),
      await page.locator("#update-hint").innerText());
    check("「更新客户端」按钮也解锁 (不再是点不动的「更新中…」)",
      await page.locator("#update").isEnabled(), await page.locator("#update").innerText());
    server.zpState.updOverride = "";

    await go("dashboard");
    console.log("\n[14] 性能模式: 那块速率表 (真的点一次)");
    // 刻度是 perf.js 用 SVG 画出来的 —— 它存在, 就说明那个脚本真的被加载、被 cgi 发出来了
    // (而不是浏览器把 index.html 当成了 js)。9 根里 5 根长的; 盘面上**不写数字** ——
    // 数字留给中间那个真实速率 (第一版把小刻度 + RPM 数字铺在盘面上, 真读数反而成了脚注)。
    check("仪表盘的刻度是脚本画出来的 (perf.js 真的加载了)",
      (await page.locator("#perf-ticks line").count()) === 9
      && (await page.locator("#perf-ticks line.major").count()) === 5
      && (await page.locator("#perf-ticks text").count()) === 0,
      `${await page.locator("#perf-ticks line").count()} 条刻度 (${await page.locator("#perf-ticks line.major").count()} 长) / ${await page.locator("#perf-ticks text").count()} 个数字`);

    // 开不了的机器: 表盘上要写清"为什么", 而且按钮点不动 —— 不许给一个点了没反应的按钮。
    server.zpState.perf = { cap: "0", state: "off", live: "0", why: "内核 5.4.281 低于 5.17",
                            exit_ip: "", busy: "0", progress: "" };
    await page.reload();
    await page.waitForSelector(".srv", {state:"attached"});
    check("开不了的时候: 表盘写清原因, 按钮点不动",
      /不可用/.test(await page.locator("#perf-pill").innerText())
      && /5\.4\.281/.test(await page.locator("#perf-cap").innerText())
      && await page.locator("#perf-btn").isDisabled(),
      await page.locator("#perf-cap").innerText());

    // 能开的机器: 点一下 "启动引擎", 看那几拍是不是真的被画出来
    server.zpState.perf = { cap: "1", state: "off", live: "0", why: "", exit_ip: "", busy: "0", progress: "" };
    server.zpState.wan = 0;
    await page.reload();
    await page.waitForSelector(".srv", {state:"attached"});
    // SVG <text> 没有 innerText —— 统一走 textContent 读表盘上的数字。
    const rpmText = () => page.locator("#perf-rpm").evaluate((el) => el.textContent);
    const unitText = () => page.locator("#perf-unit").evaluate((el) => el.textContent);
    check("没开的时候: 读数是 0 (真实速率, 不是编出来的刻度)",
      (await rpmText()).trim() === "0", `${await rpmText()} ${await unitText()}`);
    await page.click("#perf-btn");
    await page.waitForFunction(() => /进入中/.test(document.getElementById("perf-pill").textContent), null, { timeout: 5000 });
    check("点击后立刻进入「进入中」并禁用按钮 (不能连点)",
      await page.locator("#perf-btn").isDisabled(), await page.locator("#perf-btn").innerText());
    await page.waitForFunction(() => document.querySelectorAll("#perf-segs i.on").length >= 1, null, { timeout: 5000 });
    const segsMid = await page.locator("#perf-segs i.on").count();
    check("切换过程中五段进度真的在往前走 (取自后端写的进度原话)",
      segsMid >= 1 && segsMid < 5, `${segsMid}/5 段`);
    // 切换中**不许假装速度**: 那一档一个包都还没从节点过, 读数就该是真实的 0。
    check("切换中不编速度 (读数仍是真实速率 0)", (await rpmText()).trim() === "0", await rpmText());

    await page.waitForFunction(() => /已开启/.test(document.getElementById("perf-pill").textContent), null, { timeout: 8000 });
    check("生效后: 状态是「已开启」并报出验证过的出口",
      /203\.0\.113\.7/.test(await page.locator("#perf-cap").innerText()),
      await page.locator("#perf-cap").innerText());
    check("生效后五段收起 (它不是速度条, 开着还亮五条像进度没走完)",
      await page.locator("#perf-segs").evaluate((el) => el.classList.contains("hidden")));
    check("按钮变成「切回标准模式」", /切回标准模式/.test(await page.locator("#perf-btn").innerText()),
      await page.locator("#perf-btn").innerText());
    // 读数必须跟着**真实流量**走: 让模拟器多推一点字节, 数字就该变
    const rpmBefore = parseFloat(await rpmText());
    server.zpState.wan += 6 * 1024 * 1024;
    await page.waitForFunction((prev) => parseFloat(document.getElementById("perf-rpm").textContent) !== prev,
      rpmBefore, { timeout: 8000 });
    const rpmAfter = parseFloat(await rpmText());
    check("读数跟着真实流量走 (WAN 字节数涨了, 数字就变)",
      rpmAfter !== rpmBefore, `${rpmBefore} → ${rpmAfter} ${await unitText()}`);
    check("性能模式不开放标准模式三档策略",await page.locator("#mode-global").isDisabled());
    // 出口探针那次要是从本机直连出去的 (等于面板看到的本机地址), 卡片必须**如实标出来**,
    // 不许把本机地址写成节点出口 —— 真机上用户看到的就是这个 (8.86)。
    server.zpState.perf.exit_ip = "219.133.176.186";
    server.zpState.perf.wan_ip = "219.133.176.186";
    await page.reload();
    await page.waitForSelector(".srv", {state:"attached"});
    await page.waitForFunction(() => /已开启/.test(document.getElementById("perf-pill").textContent), null, { timeout: 8000 });
    check("出口等于本机地址时: 标成 (本机) 并给出警告, 不冒充节点出口",
      /\(本机\)/.test(await page.locator("#perf-cap").innerText())
      && /没走代理/.test(await page.locator("#perf-warn").innerText()),
      `${await page.locator("#perf-cap").innerText()} / ${await page.locator("#perf-warn").innerText()}`);
    await page.screenshot({ path: path.join(SHOT_DIR, "router-ui-perf.png") });

    await page.click("#perf-btn");
    await page.waitForFunction(() => /未开启/.test(document.getElementById("perf-pill").textContent), null, { timeout: 6000 });
    check("切回标准模式后性能模式关闭",
      /未开启/.test(await page.locator("#perf-pill").innerText())
      && /启用性能模式/.test(await page.locator("#perf-btn").innerText()));

    console.log("\n[15] 连接场域与真实数据语义");
    server.zpState.core="running";server.zpState.mode="tun";server.zpState.covered="full";server.zpState.ipv6="1";server.zpState.routing_mode="rule";
    server.zpState.perf={cap:"1",state:"off",live:"0",busy:"0",why:"",progress:""};
    await page.evaluate(()=>load());
    check("五工作区与主题就绪",await page.locator('.tab-btn').count()===5 && await page.locator('#router-field').isVisible());
    check("旧接口不推算上传下载",await page.locator('#stat-down').innerText()==='—' && await page.locator('#stat-up').innerText()==='—');
    check("接管状态不声称出口已验证",/非出网验证/.test(await page.locator('#rf-proof').innerText()));
    const rates=await page.evaluate(()=>{
      const nativeNow=Date.now;let now=100000;Date.now=()=>now;lastWanTime=0;
      try {
        const fixture={...currentState,wan:1200000,wan_rx:1000000,wan_tx:200000};render(fixture);
        now+=1000;render({...fixture,wan:1205120,wan_rx:1004096,wan_tx:201024});
        return {down:document.getElementById('stat-down').textContent,up:document.getElementById('stat-up').textContent,total:document.getElementById('rf-rate').textContent};
      }finally {Date.now=nativeNow;lastWanTime=0;}
    });
    check("WAN 上下行按各自真实字节差计算",rates.down==='4 KB/s' && rates.up==='1 KB/s' && rates.total==='5 KB/s',JSON.stringify(rates));
    await page.evaluate(()=>load());
    await page.focus('#mode-global');await page.keyboard.press('Enter');
    await page.waitForFunction(()=>document.getElementById('mode-global').getAttribute('aria-pressed')==='true');
    check("策略按钮支持键盘并回读实际状态",server.zpState.routing_mode==='global');
    await go('nodes');await page.fill('#url','https://draft.example.com/c/unfinished');await page.focus('#url');await page.evaluate(()=>load());
    check("状态轮询保留接入草稿和焦点",await page.inputValue('#url')==='https://draft.example.com/c/unfinished' && await page.evaluate(()=>document.activeElement.id)==='url');
    await page.locator('[data-sync]').first().focus();await page.evaluate(()=>load());
    check("来源未变化时不重建操作按钮",await page.evaluate(()=>document.activeElement.hasAttribute('data-sync')));
    check("全局模式读取 GLOBAL 而非规则组",await page.locator('#cur-node-title').innerText()==='DIRECT');
    await go('dashboard');await page.click('#mode-rule');
    await page.waitForFunction(()=>document.getElementById('mode-rule').getAttribute('aria-pressed')==='true');
    await go('nodes');await page.locator('[data-ping="日本 QUIC"]').click();
    await page.waitForFunction(()=>document.querySelector('[data-ping="日本 QUIC"]').textContent==='42 ms');
    check("原始 delay 响应无需 ok 字段即可测速",true);
    await page.locator('[data-select="日本 QUIC"]').click();
    await page.waitForFunction(()=>document.getElementById('rf-route').textContent==='日本 QUIC');
    check("切换路线后画布使用实际组选中结果",server.zpState.selected==='日本 QUIC' && server.zpState.selectedGroup==='🚀 节点选择');
    await go('dashboard');server.zpState.mode='redirect';server.zpState.covered='lan_tcp';server.zpState.ipv6='0';await page.evaluate(()=>load());
    check("REDIRECT 明确仅局域网 TCP 且 IPv6 未接管",/仅局域网 TCP/.test(await page.locator('#rf-coverage').innerText()) && /未接管/.test(await page.locator('#rf-ipv6').innerText()));
    server.zpState.mode='none';server.zpState.covered='full';await page.evaluate(()=>load());
    check("没有数据面时不因旧范围字段显示已就绪",await page.locator('#router-field').getAttribute('data-state')==='unknown');
    server.zpState.mode='tun';server.zpState.covered='full';await page.evaluate(()=>load());
    server.zpState.mode='ebpf';server.zpState.perf={cap:'1',state:'on',live:'1',busy:'0'};await page.evaluate(()=>load());await go('nodes');
    check("性能模式路线页明确统一组限制",/统一代理组/.test(await page.locator('#nodes-container').innerText()) && await page.locator('#btn-ping-all').isDisabled());
    server.zpState.mode='tun';server.zpState.perf={cap:'1',state:'off',live:'0',busy:'0'};await page.evaluate(()=>load());await go('nodes');
    await page.waitForSelector('[data-select]');
    check("切回标准模式恢复路线选择",await page.locator('[data-select]').count()>0 && await page.locator('#btn-ping-all').isEnabled());await go('dashboard');
    await page.waitForFunction(()=>!document.getElementById('toast').classList.contains('on'));
    const errMark=errors.length;
    await page.route('**/cgi-bin/zeroproxy?a=status*',route=>route.abort('connectionfailed'));
    await page.evaluate(()=>load());
    check("断线显示状态未知并禁用变更",await page.locator('#router-field').getAttribute('data-state')==='stale' && await page.locator('#toggle').isDisabled());
    await page.unroute('**/cgi-bin/zeroproxy?a=status*');await page.evaluate(()=>load());
    check("重连后读取实际状态并恢复操作",await page.locator('#router-field').getAttribute('data-state')==='ready' && await page.locator('#toggle').isEnabled());
    for(let i=errors.length-1;i>=errMark;i--) if(/ERR_FAILED|ERR_CONNECTION|Failed to fetch/.test(errors[i]))errors.splice(i,1);
    for(const width of [1440,1024,820,768,390,320]){
      await page.setViewportSize({width,height:1000});
      for(const tab of ['dashboard','nodes','clients','diagnostics','logs']){
        await go(tab);
        const box=await page.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth,offenders:[...document.querySelectorAll('body *')].filter(el=>{const r=el.getBoundingClientRect();return r.width && r.right>innerWidth+1;}).slice(0,5).map(el=>({tag:el.tagName,id:el.id,cls:el.className}))}));
        check(`${width}px / ${tab} 无页面横向溢出`,box.scroll<=box.width+1,box.scroll<=box.width+1?'':JSON.stringify(box));
      }
      await go('dashboard');
      await page.screenshot({path:path.join(SHOT_DIR,`router-field-${width}.png`),fullPage:true});
    }
    await page.setViewportSize({width:1440,height:1200});await page.screenshot({path:path.join(SHOT_DIR,'router-field-desktop.png')});
    await page.click('#router-theme');
    check("深浅主题可切换",await page.evaluate(()=>document.documentElement.dataset.theme)==='dark');
    await page.screenshot({path:path.join(SHOT_DIR,'router-field-dark.png')});
    await page.reload();await page.waitForSelector('.srv',{state:'attached'});
    check("重载保留主题偏好",await page.evaluate(()=>document.documentElement.dataset.theme)==='dark');
    await page.emulateMedia({reducedMotion:'reduce'});
    check("减少动态效果生效",await page.locator('#status-dot').evaluate(el=>getComputedStyle(el).animationName)==='none');

    console.log("\n[16] LuCI 实际承载页、主题与尺寸");
    const host=await ctx.newPage();
    await host.setViewportSize({width:1440,height:1000});
    host.on('pageerror',e=>errors.push(e.message));
    await host.goto(`http://127.0.0.1:${PORT}/luci-host`);
    const embedded=host.frameLocator('iframe');
    await embedded.locator('#sub').filter({hasText:'内核运行中'}).waitFor();
    await host.waitForFunction(()=>document.querySelector('iframe').contentDocument.documentElement.style.getPropertyValue('--host-font'));
    const frame=host.frames().find(f=>f.url().includes('/cgi-bin/zeroproxy'));
    const embedState=()=>frame.evaluate(()=>({theme:document.documentElement.dataset.theme,embedded:document.documentElement.dataset.embedded,bg:getComputedStyle(document.body).backgroundColor,accent:getComputedStyle(document.documentElement).getPropertyValue('--accent'),heading:parseFloat(getComputedStyle(document.getElementById('router-heading')).fontSize),scroll:document.documentElement.scrollHeight,viewport:innerHeight,height:document.body.getBoundingClientRect().height}));
    let details=await embedState();
    check('LuCI 嵌入覆盖独立页主题偏好',details.theme==='light'&&details.embedded==='1');
    check('嵌入页跟随宿主白底与蓝色强调',details.bg==='rgb(255, 255, 255)'&&details.accent.replaceAll(' ','')==='rgb(94,114,228)',JSON.stringify(details));
    check('嵌入工作区使用紧凑标题',details.heading<=22);
    check('嵌入页跟随系统主题且不提供冲突的独立开关',!(await embedded.locator('#router-theme').isVisible()));
    check('首次进入网络页就初始化紧凑标题',await embedded.locator('#router-heading').innerText()==='网络接管');
    check('桌面连接视图保持紧凑',await embedded.locator('#router-field').evaluate(el=>el.getBoundingClientRect().height)<360);
    await frame.evaluate(()=>{const extra=document.createElement('div');extra.id='resize-fixture';extra.style.height='600px';document.getElementById('tab-dashboard').appendChild(extra);});
    await host.waitForFunction(()=>{const f=document.querySelector('iframe');return Math.abs(f.getBoundingClientRect().height-f.contentDocument.body.getBoundingClientRect().height)<=4;});
    const longHeight=await host.locator('iframe').evaluate(el=>el.getBoundingClientRect().height);
    await embedded.locator('[data-tab="nodes"]').click();
    await embedded.locator('[data-select]').first().waitFor();
    await host.waitForFunction(()=>{const f=document.querySelector('iframe');return Math.abs(f.getBoundingClientRect().height-f.contentDocument.body.getBoundingClientRect().height)<=4;});
    details=await embedState();
    const routeHeight=await host.locator('iframe').evaluate(el=>el.getBoundingClientRect().height);
    check('切换较短工作区时承载高度会缩回',routeHeight<longHeight,`${Math.round(longHeight)} → ${Math.round(routeHeight)}`);
    check('只有 LuCI 外层页面滚动、内容不被 78vh 裁切',details.scroll<=details.viewport+2&&Math.abs(details.viewport-details.height)<=4,JSON.stringify(details));
    check('路线列表在标题后直接可见',await embedded.locator('#nodes-container').evaluate(el=>el.getBoundingClientRect().top)<400);
    await host.screenshot({path:path.join(SHOT_DIR,'router-luci-light.png'),fullPage:true});
    await host.evaluate(()=>document.getElementById('host-panel').style.backgroundColor='#edf2ff');
    await host.waitForFunction(()=>getComputedStyle(document.querySelector('iframe').contentDocument.body).backgroundColor==='rgb(237, 242, 255)');
    check('宿主内容面板单独换色也会同步',true);
    await host.evaluate(()=>{document.getElementById('host-panel').style.removeProperty('background-color');document.body.dataset.theme='dark';});
    await host.waitForFunction(()=>document.querySelector('iframe').contentDocument.documentElement.dataset.theme==='dark');
    details=await embedState();
    check('宿主切换深色后嵌入页自动跟随',details.bg==='rgb(37, 41, 50)'&&details.accent.replaceAll(' ','')==='rgb(147,167,255)',JSON.stringify(details));
    const darkContrast=await frame.evaluate(()=>{
      const parse=c=>c.match(/[\d.]+/g).slice(0,3).map(Number);
      const lum=c=>{const v=c.map(n=>{n/=255;return n<=0.04045?n/12.92:((n+0.055)/1.055)**2.4;});return v[0]*.2126+v[1]*.7152+v[2]*.0722;};
      const node=document.querySelector('.node-card.active .node-name');
      const fg=lum(parse(getComputedStyle(node).color)),bg=lum(parse(getComputedStyle(node.closest('.node-card')).backgroundColor));
      return (Math.max(fg,bg)+.05)/(Math.min(fg,bg)+.05);
    });
    check('深色选中路线文字保持可读对比度',darkContrast>=4.5,String(darkContrast));
    await host.screenshot({path:path.join(SHOT_DIR,'router-luci-dark.png'),fullPage:true});
    await host.evaluate(()=>{document.body.dataset.theme='light';document.documentElement.style.setProperty('--primary','#0f766e');});
    await host.waitForFunction(()=>document.querySelector('iframe').contentDocument.documentElement.style.getPropertyValue('--accent').replaceAll(' ','')==='rgb(15,118,110)');
    check('自定义主题强调色也可跟随',true);
    const widths=[1440,1024,820,768,390,320];
    for(const width of widths){
      await host.setViewportSize({width,height:1000});
      for(const tab of ['dashboard','nodes','clients','diagnostics','logs']){
        await embedded.locator(`[data-tab="${tab}"]`).click();
        await host.waitForFunction(()=>{const f=document.querySelector('iframe');return Math.abs(f.getBoundingClientRect().height-f.contentDocument.body.getBoundingClientRect().height)<=4;});
        const spill=await frame.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1);
        check(`LuCI ${width}px / ${tab} 无内部横向溢出`,spill);
        const spacing=await frame.evaluate(()=>{
          const rect=el=>el.getBoundingClientRect();const main=rect(document.querySelector('.app-wrap')),foot=rect(document.querySelector('.router-footer'));
          const body=document.body,style=getComputedStyle(body);
          return{width:innerWidth,left:main.left,right:innerWidth-main.right,top:main.top,bottom:parseFloat(style.paddingBottom),footerLeft:foot.left,footerRight:innerWidth-foot.right};
        });
        const gutter=spacing.width<=600?16:spacing.width<=1024?24:32;
        check(`LuCI ${width}px / ${tab} 四周留白与页脚对齐`,spacing.left>=gutter&&spacing.right>=gutter&&spacing.top>=16&&spacing.bottom>=24&&Math.abs(spacing.left-spacing.footerLeft)<1&&Math.abs(spacing.right-spacing.footerRight)<1,JSON.stringify(spacing));
      }
    }
    await embedded.locator('[data-tab="nodes"]').click();
    await host.setViewportSize({width:390,height:1000});
    await host.screenshot({path:path.join(SHOT_DIR,'router-luci-mobile.png'),fullPage:true});
    await host.setViewportSize({width:1440,height:1000});
    await embedded.locator('[data-tab="dashboard"]').click();
    await host.evaluate(()=>{document.documentElement.style.removeProperty('--primary');});
    await host.waitForFunction(()=>document.querySelector('iframe').contentDocument.documentElement.style.getPropertyValue('--accent').replaceAll(' ','')==='rgb(94,114,228)');
    await host.screenshot({path:path.join(SHOT_DIR,'router-luci-network.png'),fullPage:true});
    // A failed proxy read must not leave an optimistic static banner behind.
    await host.route('**/cgi-bin/zeroproxy?a=proxies*',route=>route.fulfill({json:{ok:false,error:'控制接口不可用'}}));
    await embedded.locator('[data-tab="nodes"]').click();
    await embedded.locator('#cur-node-title').filter({hasText:'未知'}).waitFor();
    check('节点读取失败不再残留自动选择或就绪',await embedded.locator('#cur-node-delay').innerText()==='未取得状态'&&await embedded.locator('#btn-ping-all').isDisabled());
    await host.unroute('**/cgi-bin/zeroproxy?a=proxies*');
    await embedded.locator('#refresh').click();
    await embedded.locator('[data-select]').first().waitFor();
    check('节点接口恢复后重新读取实际选组',!(await embedded.locator('#cur-node-title').innerText()).includes('未知'));
    await host.close();
    const legacy=await ctx.newPage();
    legacy.on('pageerror',e=>errors.push(e.message));
    await legacy.setViewportSize({width:1728,height:1028});
    await legacy.goto(`http://127.0.0.1:${PORT}/luci-host?legacy=1`);
    const oldFrame=legacy.frameLocator('iframe');
    await oldFrame.locator('#sub').filter({hasText:'内核运行中'}).waitFor();
    await legacy.waitForFunction(()=>document.querySelector('iframe').contentDocument.documentElement.dataset.hostBridge==='child');
    const legacySize=await legacy.evaluate(()=>{const f=document.querySelector('iframe');return{height:f.getBoundingClientRect().height,body:f.contentDocument.body.getBoundingClientRect().height,viewport:innerHeight,priority:f.style.getPropertyPriority('height'),src:f.getAttribute('src'),max:getComputedStyle(f).maxHeight};});
    check('缓存的旧 78vh 承载页也由内页自动修复',legacySize.src==='/cgi-bin/zeroproxy'&&legacySize.height>legacySize.viewport*.78+50&&Math.abs(legacySize.height-legacySize.body)<=4,JSON.stringify(legacySize));
    check('宿主强制高度与上限不会再裁切内容',legacySize.priority==='important'&&legacySize.max==='none');
    check('旧外框下首访标题仍初始化正确',await oldFrame.locator('#router-heading').innerText()==='网络接管');
    await legacy.evaluate(()=>{const shell=document.querySelector('.main-right');shell.scrollTop=shell.scrollHeight;});
    check('真实样式的外层滚动区域能到达内页底部',await legacy.evaluate(()=>{const f=document.querySelector('iframe'),shell=document.querySelector('.main-right');const foot=f.contentDocument.querySelector('.router-footer').getBoundingClientRect();const y=f.getBoundingClientRect().top+foot.bottom;return y<=shell.getBoundingClientRect().bottom&&y>0;}));
    await legacy.evaluate(()=>document.querySelector('.main-right').scrollTop=0);
    await legacy.screenshot({path:path.join(SHOT_DIR,'router-luci-legacy-fixed.png'),fullPage:true});
    await oldFrame.locator('[data-tab="logs"]').click();
    await legacy.waitForFunction(()=>{const f=document.querySelector('iframe');return Math.abs(f.getBoundingClientRect().height-f.contentDocument.body.getBoundingClientRect().height)<=4;});
    check('旧承载页下切换短页面同样可以缩回',await legacy.locator('iframe').evaluate(el=>el.getBoundingClientRect().height)<legacySize.height);
    await legacy.evaluate(()=>document.body.dataset.theme='dark');
    await legacy.waitForFunction(()=>document.querySelector('iframe').contentDocument.documentElement.dataset.theme==='dark');
    check('旧承载页也能跟随真实宿主主题',true);
    await Promise.all([
      legacy.waitForResponse(r=>r.url().includes('file=app.js')),
      legacy.evaluate(()=>document.querySelector('iframe').contentWindow.location.reload()),
    ]);
    await legacy.waitForFunction(()=>{const f=document.querySelector('iframe');return f.contentDocument.documentElement.dataset.hostBridge==='child'&&f.contentDocument.documentElement.dataset.theme==='dark'&&Math.abs(f.getBoundingClientRect().height-f.contentDocument.body.getBoundingClientRect().height)<=4;});
    check('仅重载内页后仍可重新建立宿主适配',await oldFrame.locator('#router-heading').innerText()==='维护与日志');
    await legacy.close();

    // 浏览器自己会请求 /favicon.ico 之类, 那是模拟器的事, 不算页面问题
    const real = errors.filter((e) => !/favicon|404 \(Not Found\)/.test(e));
    check("无 JS 报错", real.length === 0, real.slice(0, 2).join(" | "));
  } finally {
    if (browser) await browser.close();
    server.close();
  }
  const failed = results.filter((r) => !r.ok);
  console.log(`\n结论: ${results.length - failed.length}/${results.length} 项通过 · 截图 ${SHOT_DIR}`);
  if (failed.length) console.log("未通过: " + failed.map((f) => f.name).join(", "));
  return failed.length ? 1 : 0;
}

main().then((c) => process.exit(c)).catch((e) => { console.error("验证失败:", e); process.exit(1); });
