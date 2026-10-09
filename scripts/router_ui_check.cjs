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
const PORT = parseInt(process.env.ZP_UI_PORT || "8907", 10);

for (const extra of (process.env.ZP_NODE_PATH || "").split(path.delimiter)) {
  if (extra && !module.paths.includes(extra)) module.paths.push(extra);
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
    client: "1.0.0",
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
    if (url.pathname.startsWith("/cgi-bin/")) {
      // 与 cgi 一致: 页面与脚本本身不需要登录, 数据接口才要
      if (url.searchParams.get("file") === "app.js") {
        res.writeHead(200, { "Content-Type": "text/javascript; charset=utf-8" });
        res.end(fs.readFileSync(path.join(LUCi_DIR, "app.js"))); return;
      }
      if (!action && url.searchParams.get("file") !== "app.js") {
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(fs.readFileSync(path.join(LUCi_DIR, "index.html"))); return;
      }
      if (!authed) return json(res, { ok: false, error: "未登录 LuCI" });
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const payload = body ? JSON.parse(body) : {};
        if (action === "status") return json(res, { ok: true, ...state });
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
  await new Promise((r) => server.listen(PORT, "127.0.0.1", r));
  const base = `http://127.0.0.1:${PORT}/cgi-bin/zeroproxy`;
  const { chromium } = require("playwright");
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
    await page.waitForSelector(".srv");
    check("状态卡显示内核与模式", /内核运行中/.test(await page.locator("#sub").innerText())
      && /TUN/.test(await page.locator("#sub").innerText()), await page.locator("#sub").innerText());
    check("总开关按实际状态打开", await page.locator("#toggle").isChecked());
    check("列出一台服务器", (await page.locator(".srv").count()) === 1);
    check("服务器显示地址与设备 id", /hkk\.i3\.pub/.test(await page.locator(".srv").innerText()));
    await page.screenshot({ path: path.join(SHOT_DIR, "router-ui.png") });

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
    await page.click("#toggle + .track");
    await page.waitForTimeout(300);
    check("关掉开关后立刻有反馈", /已请求面板/.test(await page.locator("#toast").innerText()));

    page.on("dialog", (d) => d.accept());
    await page.click(".srv >> nth=1 >> button");
    await page.waitForFunction(() => document.querySelectorAll(".srv").length === 1);
    check("移除后只剩一台", (await page.locator(".srv").count()) === 1);

    console.log("\n[6] 日志");
    await page.click("details summary");
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
    await page.waitForSelector(".srv");
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
    await page.waitForSelector(".srv");
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
    await page.waitForSelector(".srv");
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
    await page.waitForSelector(".srv");
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
