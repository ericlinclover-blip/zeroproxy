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
    client: "1.0.0",
    servers: [{ key: "hkk_i3_pub_8899", base: "https://hkk.i3.pub:8899", id: "dv056b52958542564a" }],
    log: "zeroproxy-agent: 配置已更新并重载",
  };
  const json = (res, body) => {
    res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
    res.end(JSON.stringify(body));
  };
  return http.createServer((req, res) => {
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
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });

    console.log("ZeroProxy 路由器界面验证");
    console.log("\n[1] 没登录 LuCI 时");
    await page.goto(base);
    await page.waitForFunction(() => /未登录/.test(document.getElementById("sub").textContent));
    check("未登录时明确提示, 而不是空白页", true, await page.locator("#sub").innerText());
    check("未登录时不显示服务器列表", await page.locator(".srv").count() === 0);

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
