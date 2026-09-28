/**
 * 真实浏览器 UI 验证 (Playwright + Chromium)。
 *
 * 做四件事:
 *   1. 用带 ?token= 的链接打开面板, 走完「初始化 → 仪表盘」全流程;
 *   2. 断言 5 张节点卡、三种订阅格式、系统卡片都渲染出来;
 *   3. 交互验证: 节点开关热更新、订阅二维码出图、一键诊断出结果;
 *   4. 收集 console 错误与失败请求, 截图留证 (深浅色各一张 + 升级交互各状态一张)。
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

/**
 * 把本机生成的配对码改成"另一台服务器"的 (校验和按新内容重算)。
 * 验证链路要两台机器, 这里只有一台, 所以借本机的密钥造一个指向测试网段
 * (203.0.113.0/24, 永远连不上) 的配对码 —— 正好用来验证"探测不通要拦一下"这条路径。
 */
function retargetCode(code, host) {
  const crypto = require("crypto");
  const [prefix, payload] = code.split("~");
  const raw = JSON.parse(Buffer.from(payload.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
  raw.h = host;
  raw.p = 8447;
  raw.l = "美国落地";
  const raw2 = Buffer.from(JSON.stringify(raw), "utf8");
  const b64 = raw2.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const sum = crypto.createHash("sha256").update(raw2).digest("hex").slice(0, 6);
  return `${prefix}~${b64}~${sum}`;
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
    const qrSvg = await page.evaluate(() => {
      const img = document.querySelector("#qr-img");
      const box = document.querySelector(".qr-frame").getBoundingClientRect();
      const card = document.querySelector(".qr-modal").getBoundingClientRect();
      const link = document.querySelector("#qr-link");
      return {
        svg: img.getAttribute("src").includes("img=svg"),
        fits: box.left >= card.left - 1 && box.right <= card.right + 1,
        clipped: link.scrollWidth > link.clientWidth + 1,   // 长链接要省略号, 不能顶出卡片
        overflowRight: card.right > document.documentElement.clientWidth,
        hasButtons: ["#qr-copy", "#qr-save", "#qr-close"].every((s) => !!document.querySelector(s)),
      };
    });
    check("二维码走 SVG (缩放不糊)", qrSvg.svg, "");
    check("二维码完整落在卡片内", qrSvg.fits && !qrSvg.overflowRight, "");
    check("长链接不撑破卡片 (省略号截断)", qrSvg.clipped, "");
    check("弹窗有复制 / 保存 / 关闭", qrSvg.hasButtons, "");
    await page.click("#qr-close");
    check("关闭后不残留二维码", await page.evaluate(() => !document.querySelector("#qr-img").getAttribute("src")), "");

    await page.locator("[data-qr='vless-xhttp']").click();
    await page.waitForSelector("#qr-mask:not(.hidden)");
    await page.waitForFunction(() => {
      const img = document.querySelector("#qr-img");
      return img && img.complete && img.naturalWidth > 0;
    }, { timeout: 15000 });
    const nodeQr = await page.evaluate(() => {
      const card = document.querySelector(".qr-modal").getBoundingClientRect();
      return {
        sub: document.querySelector("#qr-sub").innerText,
        title: document.querySelector("#qr-title").innerText,
        inside: card.left >= 0 && card.right <= document.documentElement.clientWidth + 1,
      };
    });
    check("节点二维码副标题是人话不是长链接", /:8445/.test(nodeQr.sub) && !nodeQr.sub.includes("://"), nodeQr.sub);
    check("节点二维码卡片不出屏", nodeQr.inside, nodeQr.title);
    await page.screenshot({ path: path.join(SHOT_DIR, "qr-modal.png") });
    await page.keyboard.press("Escape");
    check("Esc 可关二维码弹窗", await page.locator("#qr-mask.hidden").count() === 1, "");

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

    console.log("\n[3c] 分流模板");
    const tplCount = await page.locator("#adv-template option").count();
    check("分流模板选择器有三个选项", tplCount === 3, `实际 ${tplCount}`);
    await page.selectOption("#adv-template", "direct");
    await page.waitForFunction(
      () => (document.querySelector("#adv-template") || {}).value === "direct",
      { timeout: 20000 }
    );
    const dash = await (await page.request.get(`${base}/api/dashboard`)).json();
    check("切换模板写入面板状态", dash.routing.template === "direct", dash.routing.template);
    const subPath = new URL(dash.subscription_url).pathname;
    const subText = await (await page.request.get(`${base}${subPath}?format=clash`)).text();
    check("订阅按新模板生成 (direct 不引用 geo 规则)",
      !subText.includes("GEOSITE,cn") && subText.includes("MATCH,"),
      `${subText.length} 字节`);
    await page.selectOption("#adv-template", "smart");
    await page.waitForFunction(
      () => (document.querySelector("#adv-template") || {}).value === "smart",
      { timeout: 20000 }
    );
    const subSmart = await (await page.request.get(`${base}${subPath}?format=clash`)).text();
    check("切回 smart 后恢复国内直连规则", subSmart.includes("GEOSITE,cn"), "");

    const backup = await page.request.get(`${base}/api/backup`);
    const backupBody = await backup.json();
    check("备份可下载", backup.ok() && !!backupBody.checksum,
      `${backupBody.format} v${backupBody.backup_version} · ${backupBody.checksum.slice(0, 12)}`);
    check("恢复入口存在", (await page.locator("#btn-restore").count()) === 1
      && (await page.locator("#restore-file").count()) === 1);

    console.log("\n[3d] 程序更新");
    check("程序更新卡片存在", (await page.locator("#update-card").count()) === 1);
    // 首次 /api/update 要出网查远端版本 (开发机上多半要等镜像超时, 最坏 ~30s),
    // 卡片上的版本行与提示语是它回来之后才填的 —— 这里等它填好再断言, 别测出假阴性。
    await page.waitForFunction(
      () => /当前 v\d/.test(document.querySelector("#update-status-line").innerText),
      { timeout: 60000 }
    );
    const updLine = (await page.locator("#update-status-line").innerText()).trim();
    check("版本行显示当前版本", /当前 v\d/.test(updLine), updLine.replace(/\n/g, " ").slice(0, 60));
    const updHint = (await page.locator("#update-hint").innerText()).trim();
    check("本地开发环境明确提示不可面板内升级", /本地开发环境/.test(updHint), updHint.slice(0, 60));
    check("检查更新按钮存在", (await page.locator("#btn-update-check").count()) === 1);
    check("非生产环境不显示一键更新按钮",
      await page.locator("#btn-update-run").isHidden());
    check("自签证书下可点「申请证书」(不再禁用到没机会补签)",
      (await page.locator("#btn-renew").innerText()).trim() === "申请证书"
      && !(await page.locator("#btn-renew").isDisabled()));

    console.log("\n[3d-2] 升级交互闭环 (确认 → 进度 → 完成/失败)");
    // 真机上点「一键更新」就是这个弹窗; 本地没有 can_update, 所以直接把 info 摆成可升级再调
    await page.evaluate(() => {
      updateInfo = { ...updateInfo, current: "2.3.10", latest: "2.3.11",
        update_available: true, can_update: true, running: false };
      renderUpdate();
      askUpgrade();
    });
    const confirmBox = await page.evaluate(() => {
      const m = document.querySelector("#confirm-mask");
      return {
        open: !m.classList.contains("hidden"),
        title: document.querySelector("#confirm-title").innerText,
        steps: [...m.querySelectorAll(".confirm-list .ustep")].map((e) => e.innerText.replace(/\s+/g, " ").trim()),
        keeps: document.querySelector(".confirm-keep").innerText,
        ok: document.querySelector("#confirm-ok").innerText,
      };
    });
    check("「一键更新」先弹确认框 (不再是浏览器原生 confirm)",
      confirmBox.open && /确认升级到 v2\.3\.11/.test(confirmBox.title), confirmBox.title);
    check("确认框逐条列出会做什么",
      confirmBox.steps.length === 6 && /备份/.test(confirmBox.steps[0]), `共 ${confirmBox.steps.length} 条`);
    check("确认框写清不会动什么",
      /节点密钥/.test(confirmBox.keeps) && /订阅令牌/.test(confirmBox.keeps), "");
    check("确认按钮写清版本跨度",
      /v2\.3\.10 → v2\.3\.11/.test(confirmBox.ok.replace(/\s+/g, " ")), confirmBox.ok);
    await page.locator("#confirm-mask").screenshot({ path: path.join(SHOT_DIR, "update-confirm.png") });
    await page.click("#confirm-cancel");
    check("取消后弹窗关闭且不会开始升级",
      (await page.locator("#confirm-mask.hidden").count()) === 1
      && (await page.locator("#btn-update-run").innerText()).includes("2.3.11"), "");

    const runningView = await page.evaluate(() => {
      const plan = ["备份代码与 state.json", "下载新版本代码", "安装新代码", "同步 Python 依赖",
        "重载 systemd 单元", "按 state.json 重新生成配置并热重载", "重启面板进程", "面板已就绪"];
      updateInfo = {
        ...updateInfo, running: true, current: "2.3.10",
        last: {
          state: "running", from: "2.3.10", to: "2.3.11", trigger: "panel",
          started_at: Math.round(Date.now() / 1000) - 12, finished_at: 0,
          current: "同步 Python 依赖", plan,
          steps: [
            { name: plan[0], ok: true, detail: "code-20260928-165700" },
            { name: plan[1], ok: true, detail: "v2.3.10 → v2.3.11" },
            { name: plan[2], ok: true, detail: "完成" },
          ],
        },
      };
      renderUpdate();
      const rows = [...document.querySelectorAll("#update-body .ustep")];
      return {
        done: rows.filter((r) => r.classList.contains("done")).length,
        now: rows.filter((r) => r.classList.contains("now")).length,
        todo: rows.filter((r) => r.classList.contains("todo")).length,
        nowName: (rows.find((r) => r.classList.contains("now")) || { innerText: "" }).innerText.replace(/\s+/g, " ").trim(),
        bar: (document.querySelector("#update-body .bar > i") || { style: {} }).style.width || "",
        summary: [...document.querySelectorAll("#update-body .muted")].map((e) => e.innerText.trim()).join(" | "),
      };
    });
    check("升级中显示逐步清单 (1 进行中 / 4 待执行)",
      runningView.done === 3 && runningView.now === 1 && runningView.todo === 4,
      `✓${runningView.done} ⟳${runningView.now} ○${runningView.todo}`);
    check("正在执行的那步被标出来", /同步 Python 依赖/.test(runningView.nowName), runningView.nowName);
    check("进度条按已完成步数推进", /43%/.test(runningView.bar), runningView.bar);
    check("显示完成步数与已用时间", /已完成 3\/8 步 · 已用 \d+ 秒/.test(runningView.summary),
      (runningView.summary.match(/已完成[^|]*/) || [""])[0].trim());
    await page.locator("#update-card").screenshot({ path: path.join(SHOT_DIR, "update-running.png") });

    const successView = await page.evaluate(() => {
      const plan = ["备份代码与 state.json", "下载新版本代码", "安装新代码"];
      const t = Math.round(Date.now() / 1000);
      pageVersion = "2.3.10";   // 假装本页 JS 还是旧版, 好验证「重新加载面板」是否出现
      updateInfo = {
        ...updateInfo, running: false, current: "2.3.11", latest: "2.3.11", update_available: false,
        last: { state: "success", from: "2.3.10", to: "2.3.11", trigger: "panel", started_at: t - 9,
          finished_at: t, current: "", plan,
          steps: plan.map((n) => ({ name: n, ok: true, detail: "完成" })), message: "" },
      };
      renderUpdate();
      const banner = document.querySelector("#update-body .banner");
      return {
        cls: banner.className,
        text: banner.innerText.replace(/\s+/g, " ").trim(),
        reloadVisible: !document.querySelector("#btn-update-reload").classList.contains("hidden"),
        hint: document.querySelector("#update-hint").innerText.trim(),
        stepsFolded: !!document.querySelector("#update-body details"),
      };
    });
    check("升级完成给出结论卡 (版本跨度 / 用时 / 触发方式)",
      successView.cls.includes("good") && /v2\.3\.10 → v2\.3\.11/.test(successView.text)
      && /用时 9 秒/.test(successView.text), successView.text.slice(0, 70));
    check("完成态把步骤详情收进折叠区 (卡片不臃肿)", successView.stepsFolded, "");
    check("本页 JS 落后于服务器时给出「重新加载面板」",
      successView.reloadVisible && /重新加载后生效/.test(successView.hint), successView.hint);
    await page.locator("#update-card").screenshot({ path: path.join(SHOT_DIR, "update-success.png") });

    const failedView = await page.evaluate(() => {
      const plan = ["备份代码与 state.json", "下载新版本代码", "安装新代码"];
      updateInfo = {
        ...updateInfo, running: false, current: "2.3.10", latest: "2.3.11", update_available: true,
        log_tail: "== 安装新代码\ncp: 无法写入",
        last: { state: "failed", from: "2.3.10", to: "2.3.11", trigger: "panel",
          started_at: Math.round(Date.now() / 1000) - 5, finished_at: Math.round(Date.now() / 1000),
          current: "", plan, message: "",
          steps: [{ name: plan[0], ok: true, detail: "完成" },
            { name: plan[1], ok: true, detail: "完成" },
            { name: plan[2], ok: false, detail: "命令执行失败, 详见日志" }] },
      };
      renderUpdate();
      const banner = document.querySelector("#update-body .banner");
      return {
        cls: banner.className,
        text: banner.innerText.replace(/\s+/g, " ").trim(),
        hasLog: !!document.querySelector("#update-body .log-box"),
        failedRow: document.querySelectorAll("#update-body .ustep.failed").length,
        barBad: !!document.querySelector("#update-body .bar > i.bad"),
        summary: (document.querySelector("#update-body .bar + .muted") || { innerText: "" }).innerText.trim(),
      };
    });
    check("升级失败给出失败步骤 + 自动回滚说明",
      failedView.cls.includes("bad") && /升级失败: 安装新代码/.test(failedView.text)
      && /自动回滚/.test(failedView.text), failedView.text.slice(0, 70));
    check("失败时带日志尾巴", failedView.hasLog && failedView.failedRow === 1, "");
    check("失败态标出在第几步断的 (进度条转红)", failedView.barBad && /在第 3 步失败/.test(failedView.summary),
      failedView.summary);
    await page.locator("#update-card").screenshot({ path: path.join(SHOT_DIR, "update-failed.png") });

    await page.evaluate(() => loadUpdate(false));   // 恢复成真实状态, 不影响后面的检查
    check("恢复真实状态后卡片回到版本对比",
      await page.evaluate(() => !document.querySelector("#update-body .banner")), "");

    console.log("\n[3e] 初始化 → 域名面板 交接到位");
    // 真机上部署成功后后端会返回 redirect.ready, 前端弹这张"3 秒后跳转"的卡。
    // 本地拿不到真证书, 所以直接调用页面里的交接函数来验证渲染与出口。
    // 切回初始化视图再渲染这张卡 (真机上它本来就是初始化完成后出现的);
    // 倒计时给长一点, 免得验证过程中真的跳走 (真机上默认 3 秒)
    await page.evaluate(() => {
      show("view-setup");
      showSetupHandoff(
        { ready: true, url: "https://panel.example.com:8899", reason: "https://panel.example.com:8899 可达且证书受信任" },
        "admin",
        60,
      );
    });
    const handoff = await page.evaluate(() => {
      const box = document.querySelector("#setup-done");
      const go = document.querySelector("#handoff-go");
      return {
        visible: !box.classList.contains("hidden"),
        countText: (document.querySelector("#handoff-count") || {}).innerText || "",
        hasGo: !!go,
        hasStay: !!document.querySelector("#handoff-stay"),
      };
    });
    check("部署成功给出跳转卡片", handoff.visible && /正在跳转到/.test(handoff.countText), handoff.countText.replace(/\n/g, " "));
    check("跳转卡片带「立即前往 / 留在本页」", handoff.hasGo && handoff.hasStay, "");
    await page.screenshot({ path: path.join(SHOT_DIR, "setup-handoff.png"), fullPage: true });
    await page.click("#handoff-stay");
    await page.waitForSelector("#view-dash:not(.hidden)", { timeout: 20000 });
    check("「留在本页」取消跳转并回到仪表盘",
      (await page.locator("#setup-done.hidden").count()) === 1
      && (await page.locator("#view-dash:not(.hidden)").count()) === 1, "");

    // 「你正在用 IP 访问」横幅只在生产显示, 本地把 prod 标记临时打开来验证文案与语气
    const ipBanner = await page.evaluate(() => {
      const prev = { prod: dash.system.prod, cert: dash.cert.type };
      const el = document.querySelector("#dash-banner");
      const cls = () => ((el.querySelector(".banner") || {}).className || "");
      dash.system.prod = true;
      dash.cert.type = "letsencrypt";
      renderDashboardBanner();
      const info = { cls: cls(), hasBtn: /切到域名面板/.test(el.innerHTML), url: dash.panel_url };
      dash.cert.type = "self-signed";
      renderDashboardBanner();
      const selfSigned = cls();
      dash.system.prod = prev.prod;
      dash.cert.type = prev.cert;
      renderDashboardBanner();
      return { ...info, selfSigned, restored: el.classList.contains("hidden") };
    });
    check("用 IP 访问时提示切到域名面板", ipBanner.cls.includes("info") && ipBanner.hasBtn, ipBanner.url);
    check("证书不是真证书时改成告警语气",
      ipBanner.selfSigned.includes("bad") && ipBanner.restored, ipBanner.selfSigned);

    console.log("\n[3f] 链式代理 (入口 → 落地)");
    check("链式代理区有说明 + 两张卡 (落地端 / 入口端)",
      (await page.locator("#chain-intro").count()) === 1
      && (await page.locator("#chain-exit-card").count()) === 1
      && (await page.locator("#chain-peer-card").count()) === 1,
      (await page.locator("#chain-intro").innerText()).split("\n")[0].trim().slice(0, 40));
    check("未开启时落地端卡片给出「生成配对码」入口",
      (await page.locator("#btn-chain-exit-gen").count()) === 1
      && /未开启/.test(await page.locator("#chain-exit-card").innerText()));

    // 落地端: 生成配对码 (专用凭据 = 独立 UUID + 独立端口)
    await page.fill("#chain-exit-port", "8666");
    await page.fill("#chain-exit-label", "香港落地");
    await page.click("#btn-chain-exit-gen");
    await page.waitForSelector("#chain-exit-code", { timeout: 30000 });
    const exitCard = await page.evaluate(() => ({
      code: document.querySelector("#chain-exit-code").textContent.trim(),
      text: document.querySelector("#chain-exit-card").innerText,
      hasQr: !!document.querySelector("#btn-chain-exit-qr"),
    }));
    check("落地端生成配对码 (ZPC1~ 一行, 可复制可扫码)",
      exitCard.code.startsWith("ZPC1~") && exitCard.hasQr, `${exitCard.code.length} 字符`);
    check("落地端卡片写清端口 / 凭据隔离 / 泄露风险",
      /8666/.test(exitCard.text) && /专用凭据/.test(exitCard.text)
      && /配对码等同凭据/.test(exitCard.text) && /重新生成/.test(exitCard.text), "");
    await page.locator("#chain-exit-card").screenshot({ path: path.join(SHOT_DIR, "chain-exit.png") });

    await page.click("#btn-chain-exit-qr");
    await page.waitForSelector("#qr-mask:not(.hidden)");
    await page.waitForFunction(() => {
      const img = document.querySelector("#qr-img");
      return img && img.complete && img.naturalWidth > 0;
    }, { timeout: 15000 });
    check("配对码二维码出图 (SVG)",
      await page.evaluate(() => document.querySelector("#qr-img").getAttribute("src").includes("/api/chain/exit/qr")));
    await page.keyboard.press("Escape");

    // 入口端: 粘贴"另一台服务器"的配对码 → 真实链路探测失败 → 二次确认 → 强行添加
    const peerHost = "203.0.113.9";
    const peerCode = retargetCode(exitCard.code, peerHost);
    await page.fill("#chain-code", peerCode);
    await page.fill("#chain-label", "美国落地");
    const errMark = consoleErrors.length;
    await page.click("#btn-chain-connect");
    await page.waitForSelector("#confirm-mask:not(.hidden)", { timeout: 60000 });
    // 这个 400 是"探测失败先拦一下"的约定信号 (后端带 needs_force), 不是缺陷 ——
    // 浏览器会照例往控制台打一条红字, 这里把它从噪声里摘掉, 免得掩盖真正的报错。
    for (let i = consoleErrors.length - 1; i >= errMark; i -= 1) {
      if (/400 \(Bad Request\)/.test(consoleErrors[i])) consoleErrors.splice(i, 1);
    }
    const probeConfirm = await page.evaluate(() => ({
      title: document.querySelector("#confirm-title").innerText,
      body: document.querySelector("#confirm-body").innerText.replace(/\s+/g, " "),
      ok: document.querySelector("#confirm-ok").innerText,
    }));
    check("探测不通时先拦一下并说清原因 (而不是静默落地)",
      /链路测试没通过/.test(probeConfirm.title) && /安全组|超时|连不上/.test(probeConfirm.body),
      probeConfirm.title);
    check("确认框给出「仍然添加」的出口", probeConfirm.ok === "仍然添加", probeConfirm.ok);
    await page.locator("#confirm-mask .modal").screenshot({ path: path.join(SHOT_DIR, "chain-confirm.png") });
    await page.click("#confirm-ok");
    await page.waitForSelector("#chain-entries .node-card", { timeout: 40000 });
    const entryCard = await page.evaluate(() => {
      const card = document.querySelector("#chain-entries .node-card");
      const text = card.innerText;
      return {
        text,
        id: (card.querySelector("[data-chain-probe]") || {}).dataset?.chainProbe || "",
        hasToggle: !!card.querySelector(".switch .slider"),
        hasDefault: !!card.querySelector("[data-chain-default]"),
        hasDelete: !!card.querySelector("[data-chain-del]"),
        toggled: !!card.querySelector("input:checked"),
      };
    });
    check("入口端落地成一张链式卡片 (经落地地址 + 本机端口)",
      /203\.0\.113\.9:8447/.test(entryCard.text) && /运行中/.test(entryCard.text)
      && entryCard.hasToggle && entryCard.hasDefault && entryCard.hasDelete && entryCard.toggled,
      entryCard.text.split("\n").slice(0, 3).join(" · "));
    check("链式节点同时出现在「节点」网格里 (客户端就是一个普通节点)",
      (await page.locator("#node-grid .node-card").count()) === 6
      && /链式/.test(await page.locator("#node-grid .node-card").last().innerText()),
      `${await page.locator("#node-grid .node-card").count()} 张节点卡`);
    const chainSubPath = new URL(await page.evaluate(() => dash.subscription_formats.clash)).pathname;
    const clashText = await (await page.request.get(`${base}${chainSubPath}?format=clash`)).text();
    check("订阅立即多出这个节点 (Clash 里看得见)",
      /ZeroProxy 链式 · 美国落地/.test(clashText)
      && /port: 8446|port: 8447|port: 8448/.test(clashText),
      `${clashText.length} 字节`);
    await page.locator("#chain-entries").screenshot({ path: path.join(SHOT_DIR, "chain-entry.png") });

    // 设为默认出口: 本机 4 个主力节点整体改道 (客户端不用换节点)
    await page.click(`[data-chain-default='${entryCard.id}']`);
    await page.waitForSelector("#confirm-mask:not(.hidden)");
    const defaultConfirm = await page.evaluate(() => document.querySelector("#confirm-body").innerText.replace(/\s+/g, " "));
    check("设为默认出口前说清会改道什么",
      /主力节点/.test(defaultConfirm) && /改道/.test(defaultConfirm), defaultConfirm.slice(0, 50));
    await page.click("#confirm-ok");
    await page.waitForFunction(
      () => /默认出口/.test(document.querySelector("#chain-entries").innerText), { timeout: 30000 });
    check("默认出口标记上卡片", /默认出口/.test(await page.locator("#chain-entries").innerText()), "");

    // 测速 (落地端是测试网段, 必然不通 → 卡片上要显示"不通"而不是假装成功)
    const [probeResp] = await Promise.all([
      page.waitForResponse(
        (r) => r.url().includes(`/api/chain/entries/${entryCard.id}/probe`), { timeout: 60000 }),
      page.click(`[data-chain-probe='${entryCard.id}']`),
    ]);
    check("链式测速失败会如实标红 (不假装成功)",
      probeResp.status() === 200 && /不通/.test(await page.locator("#chain-entries").innerText()),
      `HTTP ${probeResp.status()}`);

    // 断开 → 卡片与订阅里的节点一起消失
    await page.click(`[data-chain-del='${entryCard.id}']`);
    await page.waitForSelector("#confirm-mask:not(.hidden)");
    await page.click("#confirm-ok");
    await page.waitForFunction(() => !document.querySelector("#chain-entries .node-card"), { timeout: 30000 });
    check("断开后链式卡片消失、节点网格回到 5 张",
      (await page.locator("#chain-entries .node-card").count()) === 0
      && (await page.locator("#node-grid .node-card").count()) === 5, "");
    const clashAfter = await (await page.request.get(`${base}${chainSubPath}?format=clash`)).text();
    check("断开后订阅里不再有这个节点", !/ZeroProxy 链式/.test(clashAfter), "");

    await page.click("#btn-logout");
    await page.waitForSelector("#view-login:not(.hidden)", { timeout: 15000 });
    await page.goto(`${base}/?user=admin`, { waitUntil: "domcontentloaded" });
    await page.waitForSelector("#view-login:not(.hidden)", { timeout: 15000 });
    const loginPrefill = await page.evaluate(() => ({
      user: document.querySelector("#login-user").value,
      hint: (document.querySelector("#login-hint") || {}).innerText || "",
      cleanUrl: !location.search.includes("user="),   // 用户名不该留在地址栏
      focused: document.activeElement === document.querySelector("#login-pass"),
    }));
    check("域名面板登录页预填用户名并聚焦密码框", loginPrefill.user === "admin" && loginPrefill.focused, loginPrefill.user);
    check("登录页给出「已切换到域名面板」提示", /已切换到域名面板/.test(loginPrefill.hint), loginPrefill.hint.slice(0, 40));
    check("用户名不留在地址栏", loginPrefill.cleanUrl, new URL(page.url()).search || "(无查询串)");
    // 继续用同一套凭据登录, 后面的检查 (深浅色 / 控制台) 仍要有仪表盘
    await page.fill("#login-pass", "s3cretpass");
    await page.click("#btn-login");
    await page.waitForSelector("#view-dash:not(.hidden)", { timeout: 20000 });
    check("用刚设置的凭据可登录", (await page.locator("#node-grid .node-card").count()) === 5, "");

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
