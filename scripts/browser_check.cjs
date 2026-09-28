/**
 * 真实浏览器 UI 验证 (Playwright + Chromium)。
 *
 * 做四件事:
 *   1. 用带 ?token= 的链接打开面板, 走完「初始化 → 仪表盘」全流程;
 *   2. 断言 5 张节点卡、三种订阅格式、系统卡片都渲染出来;
 *   3. 交互验证: 节点开关热更新、订阅二维码出图、一键诊断出结果;
 *   4. 收集 console 错误与失败请求, 截图留证 (深浅色各一张)。
 *
 * 用法 (需要 node + playwright, 默认用 Codex 内置运行时):
 *   ZP_NODE=/Applications/ChatGPT.app/Contents/Resources/cua_node/bin/node \
 *   ZP_NODE_PATH=/Applications/ChatGPT.app/Contents/Resources/cua_node/lib/node_modules \
 *   node scripts/browser_check.cjs
 */
const path = require("path");
const fs = require("fs");
const os = require("os");
const { spawn } = require("child_process");

const ROOT = path.resolve(__dirname, "..");
const PYTHON = process.env.ZP_PYTHON || "python3";
const PORT = parseInt(process.env.ZP_CHECK_PORT || "8899", 10);
const TOKEN = "browser-check-token";
const SHOT_DIR = process.env.ZP_SHOT_DIR || path.join(ROOT, "work", "browser-check");

// 允许用随应用打包的 Node 运行时 (其 node_modules 不在默认解析路径里)。
// 用法见文件头: ZP_NODE_PATH=<...>/lib/node_modules node scripts/browser_check.cjs
for (const extra of (process.env.ZP_NODE_PATH || "").split(path.delimiter)) {
  if (extra && !module.paths.includes(extra)) module.paths.push(extra);
}

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok, detail });
  console.log(`  ${ok ? "✓" : "✗"} ${name}${detail ? " — " + detail : ""}`);
}

async function waitFor(url, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.ok) return true;
    } catch (e) { /* 还没起来 */ }
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error(`服务未在 ${timeoutMs}ms 内就绪: ${url}`);
}

async function main() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "zp-browser-"));
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
    console.log(`ZeroProxy 浏览器验证  (ZP_HOME=${home})`);
    await waitFor(`${base}/api/status`);

    // 允许指定 Chromium 可执行文件 (本机 Playwright 版本与已缓存浏览器版本不一致时使用)
    browser = await chromium.launch(
      process.env.ZP_CHROME_PATH ? { executablePath: process.env.ZP_CHROME_PATH } : {}
    );
    const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
    const consoleErrors = [];
    const failedRequests = [];
    page.on("console", (m) => { if (m.type() === "error") consoleErrors.push(m.text()); });
    page.on("requestfailed", (r) => failedRequests.push(`${r.url()} ${r.failure()?.errorText}`));

    console.log("\n[1] 初始化流程");
    await page.goto(`${base}/?token=${TOKEN}`);
    await page.waitForSelector("#view-setup:not(.hidden)");
    check("打开初始化视图", true);
    check("URL 中的引导令牌被消费", !page.url().includes("token="), page.url());

    await page.fill("#in-domain", "proxy.example.com");
    await page.fill("#in-user", "admin");
    await page.fill("#in-pass", "s3cretpass");
    await page.click("#btn-setup");
    await page.waitForSelector("#view-dash:not(.hidden)", { timeout: 60000 });
    check("一键生成 → 进入仪表盘", true);

    console.log("\n[2] 仪表盘渲染");
    const nodeCards = await page.locator("#node-grid .node-card").count();
    check("5 张节点卡片", nodeCards === 5, `实际 ${nodeCards}`);
    const names = await page.locator("#node-grid .node-card .name").allInnerTexts();
    check(
      "节点类型齐全",
      ["VLESS Reality", "VLESS XHTTP Reality", "VLESS WebSocket", "Trojan", "Hysteria 2"]
        .every((n) => names.join("|").includes(n)),
      names.map((n) => n.trim().split("\n").pop()).join(" / ")
    );
    for (const fmt of ["base64", "clash", "singbox"]) {
      const text = await page.locator(`#sub-${fmt}`).innerText();
      check(`订阅地址 ${fmt}`, text.startsWith("http"), text.slice(0, 46) + "…");
    }
    const certText = await page.locator("#sys-grid").innerText();
    check("证书卡片", certText.includes("TLS 证书"), certText.split("\n").slice(0, 4).join(" "));

    console.log("\n[3] 交互");
    // 开关的 input 是视觉隐藏的 (opacity:0), 要点它的滑块
    const firstSlider = page.locator("#node-grid .node-card").first().locator(".switch .slider");
    await firstSlider.click();
    await page.waitForSelector("#toast.show", { timeout: 15000 });
    check("节点开关热更新 (Toast 提示)", true, (await page.locator("#toast").innerText()).trim());
    await page.locator("#node-grid .node-card").first().locator(".switch .slider").click();
    await page.waitForTimeout(1200);
    const enabledLabels = await page.locator("#node-grid .switch input:checked").count();
    check("开关状态可往返切换", enabledLabels === 5, `启用中 ${enabledLabels}/5`);

    await page.locator("[data-qr-fmt='singbox']").click();
    await page.waitForSelector("#qr-mask:not(.hidden)");
    await page.waitForFunction(() => {
      const img = document.querySelector("#qr-img");
      return img && img.complete && img.naturalWidth > 0;
    }, { timeout: 15000 });
    check("订阅二维码出图", true, await page.locator("#qr-sub").innerText());
    await page.click("#qr-close");

    await page.click("#btn-diag");
    await page.waitForSelector("#diag-list .check", { timeout: 30000 });
    const checks = await page.locator("#diag-list .check").count();
    const summary = await page.locator("#diag-list .muted").first().innerText();
    check("一键诊断出结果", checks >= 5, `${checks} 项 · ${summary}`);

    console.log("\n[3b] 新增能力 (测速 / GeoIP / 备份)");
    // 自动测速在进入仪表盘时就跑了一次, 这里等结果落到节点卡片上
    await page.waitForSelector("#probe-summary .ping", { timeout: 30000 });
    const probeSummary = (await page.locator("#probe-summary").innerText()).trim();
    check("节点测速出结果", /出口|握手/.test(probeSummary), probeSummary.slice(0, 60));
    const pingCount = await page.locator("#node-grid .ping").count();
    check("节点卡片显示握手结果", pingCount === 5, `${pingCount}/5 张卡片带结果`);
    await page.click("#btn-probe");
    await page.waitForFunction(
      () => !document.querySelector("#btn-probe").disabled, { timeout: 40000 }
    );
    check("手动重新测速", true, (await page.locator("#probe-summary").innerText()).trim().slice(0, 60));

    check("GeoIP 分流开关存在", (await page.locator("#geo-private").count()) === 1
      && (await page.locator("#geo-ads").count()) === 1);
    const geoStatus = (await page.locator("#geo-status").innerText()).trim();
    check("GeoIP 数据状态可见", geoStatus.length > 0, geoStatus);

    const backup = await page.request.get(`${base}/api/backup`);
    const backupBody = await backup.json();
    check("备份可下载", backup.ok() && !!backupBody.checksum,
      `${backupBody.format} v${backupBody.backup_version} · ${backupBody.checksum.slice(0, 12)}`);
    check("恢复入口存在", (await page.locator("#btn-restore").count()) === 1
      && (await page.locator("#restore-file").count()) === 1);

    await page.screenshot({ path: path.join(SHOT_DIR, "dashboard-light.png"), fullPage: true });
    await page.click("#themeBtn");
    await page.waitForTimeout(400);
    await page.screenshot({ path: path.join(SHOT_DIR, "dashboard-dark.png"), fullPage: true });
    check("深浅色切换 + 截图留存", true, SHOT_DIR);

    console.log("\n[4] 控制台与请求");
    check("无 console 错误", consoleErrors.length === 0, consoleErrors.slice(0, 3).join(" | "));
    check("无失败请求", failedRequests.length === 0, failedRequests.slice(0, 3).join(" | "));
  } finally {
    if (browser) await browser.close();
    server.kill("SIGTERM");
    await new Promise((r) => server.once("exit", r));
  }

  const failed = results.filter((r) => !r.ok);
  console.log(`\n结论: ${results.length - failed.length}/${results.length} 项通过`);
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
