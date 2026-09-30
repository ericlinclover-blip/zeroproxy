/**
 * 验证 v2.6.14 的头号修复: GeoIP 下载耗时超过 2 分钟时, 前端不能"提前报成功
 * 并把进度条收起来"。
 *
 * 旧行为 (v2.6.13): watchApply 的上限是 300×400ms ≈ 2 分钟。超时那轮拿到的任务
 * 状态是 running —— 既不是成功也不是失败 —— 旧代码照样报"GeoIP 数据已更新并生效",
 * 4 秒后把进度条收起。用户回头看卡片还是旧数据, 只能说"出错了"。
 *
 * 新行为 (v2.6.14): GeoIP 任务给 8 分钟预算, 且还在跑就不收起进度条。
 *
 * 做法: 起一个"下载要 ZP_SLOW_SECS 秒"的本地面板 (scripts/geo_slow_panel.py),
 * 点按钮后在第 135 秒采样 —— 此时旧代码早就收工了, 新代码应该还在跑。
 * ZP_SLOW_SECS 给小值 (如 5) 时只看收尾, 跑得快。
 *
 * 用法 (与 browser_check.cjs 同一套环境变量):
 *   ZP_NODE_PATH=<…>/lib/node_modules ZP_CHROME_PATH=<chromium> \
 *   ZP_PYTHON=<python> node scripts/geo_slow_check.cjs        # 默认 150s, 约 3 分钟
 *   ZP_SLOW_SECS=5 … node scripts/geo_slow_check.cjs          # 只看收尾, 约 15 秒
 */
const path = require("path");
const fs = require("fs");
const os = require("os");
const { spawn } = require("child_process");

const ROOT = path.resolve(__dirname, "..");
const BACKEND = path.join(ROOT, "backend");
const PYTHON = process.env.ZP_PYTHON || "python3";
const PORT = parseInt(process.env.ZP_CHECK_PORT || "8897", 10);
const TOKEN = "geo-slow-token";
const SLOW = process.env.ZP_SLOW_SECS || "150";

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
      if ((await fetch(url)).ok) return true;
    } catch (e) { /* 还没起来 */ }
    await sleep(300);
  }
  throw new Error(`服务未在 ${timeoutMs}ms 内就绪: ${url}`);
}

async function main() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "zp-geo-slow-"));
  fs.mkdirSync(path.join(home, "data"), { recursive: true });
  fs.writeFileSync(path.join(home, "data", "bootstrap_token"), TOKEN + "\n", { mode: 0o600 });

  const server = spawn(PYTHON, [path.join(__dirname, "geo_slow_panel.py")], {
    cwd: BACKEND,
    env: {
      ...process.env,
      PYTHONPATH: BACKEND,
      ZP_HOME: home,
      ZP_STATIC: path.join(BACKEND, "static"),
      ZP_PORT: String(PORT),
      ZP_BIND_HOST: "127.0.0.1",
      ZP_BIND_PORT: String(PORT),
      ZP_SLOW_SECS: SLOW,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  server.stdout.on("data", (d) => process.stdout.write(`[panel] ${d}`));
  server.stderr.on("data", (d) => process.stderr.write(`[panel] ${d}`));

  const { chromium } = require("playwright");
  const base = `http://127.0.0.1:${PORT}`;
  let browser;
  try {
    console.log(`GeoIP 长任务前端验证 (慢速桩 ${SLOW}s, ZP_HOME=${home})`);
    await waitFor(`${base}/api/status`);
    browser = await chromium.launch(
      process.env.ZP_CHROME_PATH ? { executablePath: process.env.ZP_CHROME_PATH } : {}
    );
    const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
    await page.goto(`${base}/?token=${TOKEN}`);
    await page.waitForSelector("#view-setup:not(.hidden)");
    await page.fill("#in-domain", "proxy.example.com");
    await page.fill("#in-user", "admin");
    await page.fill("#in-pass", "s3cretpass");
    await page.click("#btn-setup");
    await page.waitForSelector("#view-dash:not(.hidden)", { timeout: 60000 });

    // 记下每一次 toast 内容 (2.4 秒就消失, 定时采样会漏, 用 MutationObserver 抓)
    await page.evaluate(() => {
      window.__toasts = [];
      const el = document.querySelector("#toast");
      new MutationObserver(() => {
        if (el.classList.contains("show")) {
          const t = el.textContent.trim();
          if (t && window.__toasts[window.__toasts.length - 1] !== t) window.__toasts.push(t);
        }
      }).observe(el, { childList: true, characterData: true, subtree: true, attributes: true });
    });

    await page.click("#btn-geo-update");
    const t0 = Date.now();
    console.log("  点了「下载 / 更新 GeoIP 数据」, 开始计时");

    const LONG = parseInt(SLOW, 10) >= 130;   // 短跑模式只验"收尾", 不验 2 分钟那条线
    let stripAt135 = null;
    let earlySuccess = null;
    const seenStates = [];
    while (LONG && Date.now() - t0 < 135000) {
      await sleep(1000);
      const snap = await page.evaluate(() => ({
        stripHidden: document.querySelector("#apply-strip").classList.contains("hidden"),
        strip: document.querySelector("#apply-strip").innerText.replace(/\s+/g, " ").trim(),
        btn: document.querySelector("#btn-geo-update").innerText.trim(),
        disabled: document.querySelector("#btn-geo-update").disabled,
        toasts: (window.__toasts || []).slice(),
      }));
      if ((Date.now() - t0) % 15000 < 1200) {
        seenStates.push(`t=${((Date.now() - t0) / 1000).toFixed(0)}s ${snap.btn} | ${snap.strip.slice(0, 40)}`);
      }
      stripAt135 = snap;
      const premature = (snap.toasts || []).find((t) => /已更新并生效/.test(t));
      if (premature) { earlySuccess = premature; break; }
    }
    if (LONG) console.log("  观测到的中间状态:\n    " + seenStates.join("\n    "));

    if (LONG) {
      check("下载超过 2 分钟后进度条仍在 (旧版这时早就收起了)",
        !!stripAt135 && stripAt135.stripHidden === false, stripAt135 ? stripAt135.strip.slice(0, 70) : "无采样");
      check("下载未完成时不提前报「已更新并生效」",
        !earlySuccess, earlySuccess || "无");
      check("下载期间按钮保持「下载中…」不可重复点",
        !!stripAt135 && stripAt135.disabled === true && /下载中/.test(stripAt135.btn),
        stripAt135 ? stripAt135.btn : "");
    }

    // 等任务真的跑完 (慢速桩 SLOWs + 收尾)
    await page.waitForFunction(
      () => !document.querySelector("#btn-geo-update").disabled, { timeout: 180000 }
    );
    const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
    await sleep(5000);            // 结论条刻意留 4 秒再收起, 等它收完再看
    const final = await page.evaluate(() => ({
      toasts: (window.__toasts || []).slice(),
      status: document.querySelector("#geo-status").innerText.trim(),
      stripHidden: document.querySelector("#apply-strip").classList.contains("hidden"),
      btn: document.querySelector("#btn-geo-update").innerText.trim(),
    }));
    check("跑完后给的是成功结论 (不是「更新失败」)",
      final.toasts.some((t) => /已更新并生效/.test(t)) && !final.toasts.some((t) => /更新失败/.test(t)),
      `${final.toasts.join(" / ")} (共 ${elapsed}s)`);
    check("卡片状态跟着刷新成已就绪", /更新|就绪/.test(final.status), final.status);
    check("收工后进度条自己收起 + 按钮复位",
      final.stripHidden === true && /下载 \/ 更新/.test(final.btn),
      `${final.stripHidden} / ${final.btn}`);

    await page.screenshot({ path: path.join(ROOT, "work", "geo-slow-final.png") });
  } finally {
    if (browser) await browser.close();
    server.kill("SIGTERM");
  }

  const failed = results.filter((r) => !r.ok);
  console.log(`\n结论: ${results.length - failed.length}/${results.length} 项通过`);
  if (failed.length) {
    console.log("未通过: " + failed.map((f) => f.name).join(", "));
    process.exitCode = 1;
  }
}

main().catch((e) => {
  console.error("验证失败:", e);
  process.exit(1);
});
