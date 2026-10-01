/**
 * 「客户端」卡片的真实浏览器验证 (Playwright + Chromium)。
 *
 * 验证的是用户实际会看到的那条链路, 而不是接口:
 *   1. 空状态: 点「生成安装命令」→ 出现可复制的一行命令;
 *   2. 配对一台假路由器 (直接调 /c/pair, 模拟安装脚本) → 卡片出现;
 *   3. 设备上报 actual=true → 卡片变「已连接」且开关是开着的 (绿色);
 *   4. 点开关关掉 → 面板写期望状态, 卡片立刻进入「同步中」而不是假装已关闭;
 *   5. 设备再上报 actual=false → 卡片落到「已关闭」。
 *
 * 用法 (需要 node + playwright; 默认用 Codex 内置运行时):
 *   ZP_PYTHON=<venv>/bin/python \
 *   ZP_NODE_PATH=/Applications/ChatGPT.app/Contents/Resources/cua_node/lib/node_modules \
 *   ZP_CHROME_PATH=".../Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing" \
 *   node scripts/clients_check.cjs
 */
const net = require("net");
const path = require("path");
const fs = require("fs");
const os = require("os");
const { spawn } = require("child_process");

const ROOT = path.resolve(__dirname, "..");
const PYTHON = process.env.ZP_PYTHON || "python3";
const PORT = parseInt(process.env.ZP_CHECK_PORT || "8899", 10);
const TOKEN = "clients-check-token";
const SHOT_DIR = process.env.ZP_SHOT_DIR || path.join(ROOT, "work", "browser-check");

for (const extra of (process.env.ZP_NODE_PATH || "").split(path.delimiter)) {
  if (extra && !module.paths.includes(extra)) module.paths.push(extra);
}

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok, detail });
  console.log(`  ${ok ? "✓" : "✗"} ${name}${detail ? " — " + detail : ""}`);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitFor(url, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.ok) return true;
    } catch (e) { /* 还没起来 */ }
    await sleep(300);
  }
  throw new Error(`服务未在 ${timeoutMs}ms 内就绪: ${url}`);
}

async function main() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "zp-clients-"));
  fs.mkdirSync(path.join(home, "data"), { recursive: true });
  fs.writeFileSync(path.join(home, "data", "bootstrap_token"), TOKEN + "\n", { mode: 0o600 });
  fs.mkdirSync(SHOT_DIR, { recursive: true });

  const server = spawn(PYTHON, ["-m", "zeroproxy.main"], {
    cwd: path.join(ROOT, "backend"),
    env: {
      ...process.env,
      ZP_HOME: home,
      ZP_STATIC: path.join(ROOT, "backend", "static"),
      ZP_PORT: String(PORT),
      ZP_BIND_HOST: "127.0.0.1",
      ZP_BIND_PORT: String(PORT),
      ZP_GEODATA_AUTO: "0",
      ZP_PUBLIC_IP: "0",
      ZP_APPLY_ASYNC: "0",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let serverLog = "";
  server.stdout.on("data", (d) => (serverLog += d));
  server.stderr.on("data", (d) => (serverLog += d));

  const { chromium } = require("playwright");
  const base = `http://127.0.0.1:${PORT}`;
  let browser;
  try {
    console.log(`ZeroProxy 客户端卡片验证  (ZP_HOME=${home}, PORT=${PORT})`);
    try {
      await waitFor(`${base}/api/status`);
    } catch (e) {
      throw new Error(`${e.message}\n子进程输出:\n${serverLog.split("\n").slice(-10).join("\n").trim() || "(空)"}`);
    }

    browser = await chromium.launch(
      process.env.ZP_CHROME_PATH ? { executablePath: process.env.ZP_CHROME_PATH } : {}
    );
    const page = await browser.newPage({ viewport: { width: 1280, height: 1000 } });
    const consoleErrors = [];
    page.on("console", (m) => { if (m.type() === "error") consoleErrors.push(m.text()); });
    page.on("pageerror", (e) => consoleErrors.push("pageerror: " + e.message));

    console.log("\n[1] 初始化 + 空状态");
    await page.goto(`${base}/?token=${TOKEN}`);
    await page.fill("#in-domain", "proxy.example.com");
    await page.fill("#in-user", "admin");
    await page.fill("#in-pass", "s3cretpass");
    await page.click("#btn-setup");
    await page.waitForSelector("#view-dash:not(.hidden)", { timeout: 60000 });

    check("侧栏出现「客户端」入口", (await page.locator('#dash-nav a[href="#sec-clients"]').count()) === 1);
    check("客户端卡片默认停在路由器 tab", await page.locator('#client-tabs .tab.on[data-client-tab="router"]').count() === 1);
    check("空状态先介绍价值" , /全屋|每台设备/.test(await page.locator("#client-body").innerText()));

    await page.click("#btn-pair");
    await page.waitForSelector(".cmd-box code", { timeout: 10000 });
    const cmd = await page.locator(".cmd-box code").innerText();
    check("生成安装命令", /^wget -qO- .+\/c\/[0-9a-f]{32} \| sh$/.test(cmd.trim()), cmd.trim().slice(0, 60) + "…");
    await page.locator("#sec-clients").scrollIntoViewIfNeeded();
    await page.screenshot({ path: path.join(SHOT_DIR, "clients-install.png") });

    console.log("\n[2] 配对一台路由器 (模拟安装脚本)");
    const cookie = (await page.context().cookies()).find((c) => c.name === "zp_session");
    const api = async (p, opts = {}) =>
      (await fetch(base + p, {
        ...opts,
        headers: { "Content-Type": "application/json", Cookie: `zp_session=${cookie.value}`, ...(opts.headers || {}) },
      })).json();

    const pair = await api("/api/devices/pair", { method: "POST", body: JSON.stringify({ label: "客厅路由器" }) });
    const device = await api("/c/pair", {
      method: "POST",
      body: JSON.stringify({
        code: pair.code, kind: "router", hostname: "GL-MT3000", model: "GL.iNet GL-MT3000",
        arch: "arm64", os: "OpenWrt 24.10.4", version: "1.0.0",
      }),
    });
    check("配对码换到设备凭据", Boolean(device.id && device.secret), device.name);
    check("设备默认期望开启 (装完即用)", device.desired === true);

    await api("/c/report", {
      method: "POST",
      body: JSON.stringify({ device: device.id, k: device.secret, actual: true, version: "1.0.0" }),
    });
    await page.click("#btn-apply");           // 触发一次面板刷新 (等同 20s 轮询)
    await page.waitForSelector(".dev-card", { timeout: 20000 });

    const name = await page.locator(".dev-card .dev-name").innerText();
    check("设备卡片出现且带型号名", /GL-MT3000/.test(name), name.trim());
    check("已连接时卡片是绿色状态", await page.locator(".dev-card.on").count() === 1);
    check("状态文案是「已连接」", /已连接/.test(await page.locator(".dev-card .pill").innerText()));
    check("开关处于打开状态", await page.locator(".bigswitch input").isChecked());
    const glow = await page.locator(".bigswitch input:checked + .track").count();
    check("开关打开时有发光样式", glow === 1);
    check("卡片写明分流模板与内核状态",
      /分流 · /.test(await page.locator(".dev-card").innerText()) &&
      /内核运行中/.test(await page.locator(".dev-card").innerText()));
    await page.locator("#sec-clients").scrollIntoViewIfNeeded();
    await page.screenshot({ path: path.join(SHOT_DIR, "clients-connected.png") });

    console.log("\n[3] 点开关关闭 → 同步中 → 已关闭");
    // 真正的 checkbox 是 opacity:0 的 (视觉全在 .track/.knob 上), 所以点它的标签
    await page.click(".bigswitch .track");
    await sleep(600);
    check("点开关立刻显示「同步中…」(不假装已生效)",
      /同步中/.test(await page.locator(".dev-card .pill").innerText()),
      (await page.locator(".dev-card .pill").innerText()).trim());
    const desiredOff = await api("/api/devices");
    check("面板已写入关闭这个期望状态", desiredOff.devices.items[0].desired === false);

    await api("/c/report", {
      method: "POST",
      body: JSON.stringify({ device: device.id, k: device.secret, actual: false }),
    });
    await page.click("#btn-apply");
    await page.waitForTimeout(1200);
    check("设备回报后落到「已关闭」",
      /已关闭/.test(await page.locator(".dev-card .pill").innerText()),
      (await page.locator(".dev-card .pill").innerText()).trim());
    check("关闭后卡片不再是绿色", await page.locator(".dev-card.on").count() === 0);

    console.log("\n[4] 手机 / 电脑 tab");
    await page.click('[data-client-tab="phone"]');
    await page.waitForSelector(".mini-card");
    check("手机 tab 给出扫码与复制订阅", (await page.locator(".mini-card").count()) >= 2);
    await page.click('[data-client-tab="desktop"]');
    await page.waitForTimeout(200);
    check("电脑 tab 给出三个平台", (await page.locator(".mini-card").count()) === 3);
    await page.click('[data-client-tab="router"]');

    console.log("\n[5] 深色模式");
    await page.click("#themeBtn");
    await page.waitForTimeout(500);
    await page.locator("#sec-clients").scrollIntoViewIfNeeded();
    await page.screenshot({ path: path.join(SHOT_DIR, "clients-dark.png") });
    check("深色下卡片仍然渲染", await page.locator(".dev-card").count() === 1);

    check("无 console / page 错误", consoleErrors.length === 0, consoleErrors.slice(0, 2).join(" | "));
  } finally {
    if (browser) await browser.close();
    server.kill("SIGTERM");
    await new Promise((r) => server.once("exit", r));
  }

  const failed = results.filter((r) => !r.ok);
  console.log(`\n结论: ${results.length - failed.length}/${results.length} 项通过 · 截图 ${SHOT_DIR}`);
  if (failed.length) {
    console.log("未通过: " + failed.map((f) => f.name).join(", "));
    console.log("服务日志尾部:\n" + serverLog.split("\n").slice(-12).join("\n"));
  }
  return failed.length ? 1 : 0;
}

main().then((code) => process.exit(code)).catch((err) => {
  console.error("验证失败:", err);
  process.exit(1);
});
