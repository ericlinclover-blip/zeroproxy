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
 *
 * 可选环境变量:
 *   ZP_CHROME_PATH  指定 Chromium 可执行文件 (Playwright 期望的浏览器版本与本地
 *                   缓存 (如 chromium_headless_shell-1200 vs chromium-1243) 对不上时用)
 *   ZP_PYTHON       起面板用的解释器 (默认 python3)
 *   ZP_CHECK_PORT   面板监听端口 (默认 8899)
 *   ZP_SHOT_DIR     截图目录 (默认 work/browser-check)
 */
const net = require("net");
const path = require("path");
const fs = require("fs");
const os = require("os");
const { spawn } = require("child_process");

const ROOT = path.resolve(__dirname, "..");
const PYTHON = process.env.ZP_PYTHON || "python3";
let PORT = parseInt(process.env.ZP_CHECK_PORT || "8899", 10);
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
  raw.l = "美国落地";
  // v2 配对码把 Reality 那组参数 (含端口) 挪进了 r, 端口要改在 r.p 上;
  // 落地地址 h 与名称 l 仍在顶层 (v1 的端口就是顶层 p)。
  if (raw.r && typeof raw.r === "object") {
    raw.r.p = 8447;
  } else {
    raw.p = 8447;
  }
  const raw2 = Buffer.from(JSON.stringify(raw), "utf8");
  const b64 = raw2.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const sum = crypto.createHash("sha256").update(raw2).digest("hex").slice(0, 6);
  return `${prefix}~${b64}~${sum}`;
}

/** 端口现在是否空闲 (bind 一次看看)。 */
function portFree(port) {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.once("error", () => resolve(false));
    srv.once("listening", () => srv.close(() => resolve(true)));
    srv.listen(port, "127.0.0.1");
  });
}

/** 让系统分一个空闲端口 (listen 0 之后读回来)。 */
function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
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

/** 等某个板块被"带到眼前" —— 头部的按钮点完, 结果卡片应当自己出现, 而不是让用户往下翻。
 *  判据是"卡片顶边落在视口内, 至少露出 100px", 不是"顶到最上面": 最后一张卡片下面
 *  没有内容可滚, 它只能停在页面底部, 但它确实已经被完整看见了。
 *  另外平滑滚动要几百毫秒才停, 所以必须等它, 不能点完立刻量。 */
async function waitCardInView(page, sel, timeout = 8000) {
  try {
    await page.waitForFunction((s) => {
      const r = document.querySelector(s).getBoundingClientRect();
      return r.top >= 0 && r.top < innerHeight - 100;
    }, sel, { timeout });
    return true;
  } catch (e) {
    return false;
  }
}

async function main() {
  // 先把端口确认空闲。否则本机若已经跑着一个面板 (例如你自己开着 ./dev.sh), 这里
  // spawn 的新面板会因为端口被占而退出, 而 waitFor 却会连上**那个**面板 —— 全部断言
  // 跑在别人身上, 最后静默退出、exit 0, 给出一份"看起来通过、其实什么都没验证"的结果
  // (本机踩到过)。被占用就自动换一个空闲端口, 并明说换到了哪里。
  if (!(await portFree(PORT))) {
    const fallback = await freePort();
    console.log(`⚠ 端口 ${PORT} 已被占用 (可能是你自己开着的面板) → 本次改用 ${fallback}`);
    PORT = fallback;
  }

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
    console.log(`ZeroProxy 浏览器验证  (ZP_HOME=${home}, PORT=${PORT})`);
    try {
      await waitFor(`${base}/api/status`);
    } catch (e) {
      // 面板没起来时把子进程的输出带出来 —— 否则只能看到一句"未就绪", 不知道是端口
      // 被占、依赖缺失还是代码报错
      throw new Error(`${e.message}\n子进程输出:\n${serverLog.split("\n").slice(-10).join("\n").trim() || "(空)"}`);
    }

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

    // 侧栏菜单的顺序必须与页面板块的顺序一致 —— 否则会出现"点上一个却滚到下面",
    // 滚动高亮也会往回跳。曾经 链式代理 与 高级/分流 在菜单里是正序、页面里是反序。
    const navOrder = await page.evaluate(() => {
      const hrefs = [...document.querySelectorAll("#dash-nav a[href^='#']")]
        .map((a) => a.getAttribute("href").slice(1));
      const tops = hrefs.map((id) => {
        const el = document.getElementById(id);
        return el ? Math.round(el.getBoundingClientRect().top + window.scrollY) : -1;
      });
      return { hrefs, tops };
    });
    check("侧栏顺序 = 页面板块顺序 (点哪去哪, 高亮不往回跳)",
      !navOrder.tops.includes(-1)
      && navOrder.tops.every((top, i) => i === 0 || top > navOrder.tops[i - 1]),
      navOrder.hrefs.map((h, i) => `${h}@${navOrder.tops[i]}`).join(" "));

    console.log("\n[3] 交互");
    // 开关的 input 是视觉隐藏的 (opacity:0), 要点它的滑块
    // 关掉之前先记下这排灯的颜色: 关掉的那颗必须变成"灰 (off)", 其余保持原样
    const dotsBefore = await page.evaluate(() =>
      [...document.querySelectorAll("#kpi-nodes-sub .dot")].map((d) => d.className));
    const firstSlider = page.locator("#node-grid .node-card").first().locator(".switch .slider");
    await firstSlider.click();
    await page.waitForSelector("#toast.show", { timeout: 15000 });
    check("节点开关热更新 (Toast 提示)", true, (await page.locator("#toast").innerText()).trim());
    // 关掉一个协议的节点之后, 它的状态灯必须熄灭变灰 —— 顶部「健康节点」那排点
    // 和节点卡自己的灯之前都直接取 service_state (Xray 还在跑), 所以关掉之后灯还是绿的。
    await page.waitForFunction(
      () => document.querySelector("#kpi-nodes-sub .dot.off"), { timeout: 20000 });
    const offState = await page.evaluate(() => {
      const card = document.querySelector("#node-grid .node-card");
      const dots = [...document.querySelectorAll("#kpi-nodes-sub .dot")];
      return {
        classes: dots.map((d) => d.className),
        off: dots.filter((d) => d.classList.contains("off")).length,
        count: document.querySelector("#kpi-nodes").innerText.replace(/\s/g, ""),
        cardDot: (card.querySelector(".nc-addr .dot") || {}).className || "",
        cardTxt: (card.querySelector(".nc-addr .state") || {}).innerText.trim() || "",
        sub: document.querySelector("#kpi-nodes-sub").innerText.trim(),
      };
    });
    // 灯的颜色按服务状态给 (生产是绿, 本地开发是黄), 所以这里比的是"关掉的那一颗
    // 从原状态变成了 off, 其余一颗都没动" —— 不写死颜色, 两种环境都成立。
    check("关掉的节点在顶部「健康节点」里熄灭成灰灯, 其余不受影响",
      dotsBefore.length === 5 && !dotsBefore.some((c) => c.includes("off"))
      && offState.classes[0].includes("off") && offState.off === 1
      && JSON.stringify(offState.classes.slice(1)) === JSON.stringify(dotsBefore.slice(1))
      && offState.count === "4/5",
      `${dotsBefore.length} 颗灯 → 灰 ${offState.off} 颗 · ${offState.count} · ${offState.sub}`);
    check("节点卡自己的状态灯也一起熄灭, 文案是「已停用」",
      /off/.test(offState.cardDot) && offState.cardTxt === "已停用",
      `${offState.cardDot} · ${offState.cardTxt}`);
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
    // 等到淡入动画 (zp-fade 0.18s / zp-pop 0.24s) 结束再截图: 动画途中拍照,
    // 遮罩只有半透明, 底下的仪表盘会透上来, 留证图看起来像"弹窗被内容盖住"。
    await page.waitForTimeout(350);
    await page.screenshot({ path: path.join(SHOT_DIR, "qr-modal.png") });
    await page.keyboard.press("Escape");
    check("Esc 可关二维码弹窗", await page.locator("#qr-mask.hidden").count() === 1, "");

    await page.click("#btn-diag");
    await page.waitForSelector("#diag-list .check", { timeout: 30000 });
    const checks = await page.locator("#diag-list .check").count();
    const summary = await page.locator("#diag-list .muted").first().innerText();
    check("一键诊断出结果", checks >= 5, `${checks} 项 · ${summary}`);
    // 头部的按钮离「诊断」卡片很远: 点完必须把卡片带到眼前, 否则用户只看到按钮文字变了
    check("点头部的「一键诊断」会把诊断卡片带到眼前 (不用自己翻)",
      await waitCardInView(page, "#diag-card"), "");

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
    // 数据版本: dat 文件里没有版本号, 卡片要能说出"上游数据集是哪天构建的 + 内容指纹
    // + 是不是最新的", 否则用户点完更新根本无从判断到底有没有生效
    const geoVersion = (await page.locator("#geo-version").innerText()).trim();
    check("GeoIP 数据版本行存在", /^数据版本: /.test(geoVersion), geoVersion.slice(0, 80));
    const nowSec = Math.floor(Date.now() / 1000);
    const geoFile = (sha) => ({ exists: true, size: 1, mtime: 0, sha256: sha, expected: sha });
    await page.route("**/api/geodata/check", (route) => route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        ok: true, up_to_date: true, detail: "",
        geo: {
          enabled: true, block_private: true, block_ads: true, active: true,
          updated_at: nowSec - 86400, age_days: 1,
          dataset_build: "2026-09-29", dataset_sha: "ef3bc79", checked_at: nowSec,
          up_to_date: true, last_error: "",
          files: { "geoip.dat": geoFile("3cf2236c1906"), "geosite.dat": geoFile("51211fde2169") },
        },
      }),
    }));
    await page.evaluate(() => document.querySelector("#toast").classList.remove("show"));
    await page.click("#btn-geo-check");
    await page.waitForSelector("#toast.show", { timeout: 10000 });
    const checkToast = (await page.locator("#toast").innerText()).trim();
    check("核对数据版本: 结论进 toast", /已是最新/.test(checkToast), checkToast);
    const geoVersion2 = (await page.locator("#geo-version").innerText()).trim();
    check("数据版本行显示数据集构建日期与内容指纹",
      /数据集 2026-09-29 \(ef3bc79\)/.test(geoVersion2)
      && /geoip\.dat 3cf2236c/.test(geoVersion2) && /已是最新/.test(geoVersion2),
      geoVersion2.slice(0, 120));
    await page.unroute("**/api/geodata/check");

    // v2.6.14: 后台自动更新正占着下载锁时, 手动点按钮以前会弹一句"更新失败: 已有更新任务在进行中",
    // 用户以为按钮坏了。现在要明确说"等一下", 并且按钮自己恢复 (不能卡在"下载中…")。
    await page.evaluate(() => document.querySelector("#toast").classList.remove("show"));
    const lockErrMark = consoleErrors.length;
    await page.route("**/api/geodata/update", (route) => route.fulfill({
      status: 409,
      contentType: "application/json",
      body: JSON.stringify({ error: "GeoIP 数据正在更新中 (后台自动更新或上一次任务还没结束), 请稍等再点" }),
    }));
    await page.click("#btn-geo-update");
    await page.waitForSelector("#toast.show", { timeout: 10000 });
    // 这个 409 是脚本自己伪造的约定信号, 浏览器照例会往控制台打条红字 —— 摘掉, 别掩盖真报错
    for (let i = consoleErrors.length - 1; i >= lockErrMark; i -= 1) {
      if (/409 \(Conflict\)/.test(consoleErrors[i])) consoleErrors.splice(i, 1);
    }
    const busyToast = (await page.locator("#toast").innerText()).trim();
    check("下载撞上后台自动更新时提示「等一下」而不是「更新失败」",
      /先等一下/.test(busyToast) && /稍等/.test(busyToast), busyToast);
    check("下载失败后按钮自己恢复可用",
      !(await page.locator("#btn-geo-update").isDisabled())
      && /下载 \/ 更新/.test(await page.locator("#btn-geo-update").innerText()), "");
    await page.unroute("**/api/geodata/update");

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

    console.log("\n[3c-2] 自动刷新不吞掉正在填的内容");
    // 仪表盘每 20s 整块重画 DOM (节点表 / 高级设置 / 链式代理都是 innerHTML):
    // 以前会把用户填到一半的 SNI / 端口 / 配对码覆盖回服务器值。
    await page.fill("#adv-sni", "cdn.example.net");
    await page.focus("#adv-sni");
    await page.evaluate(() => renderDash(true));      // 等价于一次 20s 自动刷新
    check("轮询后正在编辑的 SNI 还在", (await page.inputValue("#adv-sni")) === "cdn.example.net",
      await page.inputValue("#adv-sni"));
    check("重画后光标仍停在输入框里",
      (await page.evaluate(() => document.activeElement.id)) === "adv-sni", "");
    await page.fill("[data-port-node='trojan']", "9443");
    await page.evaluate(() => renderDash(true));
    check("轮询后正在填的端口还在",
      (await page.inputValue("[data-port-node='trojan']")) === "9443",
      await page.inputValue("[data-port-node='trojan']"));
    // 收尾: 解除草稿保护 → 回到服务器值, 不影响后面的检查
    await page.evaluate(() => {
      clearDraft("#adv-sni, [data-port-node]");
      if (document.activeElement && document.activeElement.blur) document.activeElement.blur();
      renderDash(true);
    });
    check("放弃未提交的修改后回到服务器值",
      (await page.inputValue("#adv-sni")) === "www.cloudflare.com"
      && (await page.inputValue("[data-port-node='trojan']")) === "8444",
      `${await page.inputValue("#adv-sni")} / ${await page.inputValue("[data-port-node='trojan']")}`);

    console.log("\n[3c-3] Hysteria 2 端口跳跃开关");
    const hopBefore = await page.evaluate(() => ({ on: dash.hysteria_hopping, ports: dash.hysteria_ports }));
    check("端口跳跃开关在位并写明当前区间",
      (await page.locator("#adv-hopping").count()) === 1
      && (await page.locator("#adv-hopping-note").innerText()).includes(String(hopBefore.ports[0])),
      await page.locator("#adv-hopping-note").innerText());
    await page.click("#adv-hopping");
    await page.waitForFunction(() => dash && dash.hysteria_hopping === false, { timeout: 30000 });
    check("关掉端口跳跃可写入状态", await page.evaluate(() => dash.hysteria_hopping) === false, "");
    await page.click("#adv-hopping");
    await page.waitForFunction(() => dash && dash.hysteria_hopping === true, { timeout: 30000 });
    const hopAfter = await page.evaluate(() => dash.hysteria_ports);
    check("重新打开后区间跟着主端口走",
      hopAfter.length === 3 && hopAfter[0] === 30001 && hopAfter[2] === 32001, hopAfter.join(" / "));

    const backup = await page.request.get(`${base}/api/backup`);
    const backupBody = await backup.json();
    check("备份可下载", backup.ok() && !!backupBody.checksum,
      `${backupBody.format} v${backupBody.backup_version} · ${backupBody.checksum.slice(0, 12)}`);
    check("恢复入口存在", (await page.locator("#btn-restore").count()) === 1
      && (await page.locator("#restore-file").count()) === 1);
    // 恢复是覆盖操作: 选完文件要先弹自定义确认框 (原来是浏览器原生 confirm, 长得像系统
    // 警告、讲不清"哪些东西会被替换")。这里不真的恢复, 只验证这一步与取消路径。
    const notABackup = path.join(os.tmpdir(), "zp-not-a-backup.json");
    fs.writeFileSync(notABackup, "{}");
    await page.setInputFiles("#restore-file", notABackup);
    await page.waitForSelector("#confirm-mask:not(.hidden)", { timeout: 10000 });
    const restoreTitle = (await page.locator("#confirm-title").innerText()).trim();
    check("从备份恢复先弹自定义确认框 (不再是浏览器原生 confirm)",
      /覆盖当前配置/.test(restoreTitle), restoreTitle);
    check("确认框写清会被替换的东西与订阅会变",
      /密钥/.test(await page.locator("#confirm-body").innerText())
      && /重新导入订阅/.test(await page.locator("#confirm-body").innerText()), "");
    await page.click("#confirm-cancel");
    check("取消后弹窗关闭", (await page.locator("#confirm-mask.hidden").count()) === 1, "");

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
    // 同上: 头部那颗「检查更新」也走这条路径, 结果卡片要自动滚到眼前
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.waitForTimeout(300);
    await page.click("#btn-update");
    check("点头部的「检查更新」会把更新卡片带到眼前",
      await waitCardInView(page, "#update-card", 20000), "");
    // 这次点击会真的去查一次远端版本 (处理期间「检查更新」按钮是禁用的)。必须等它收工:
    // 否则它返回时会用真实状态重画一遍, 把下面几行刚摆好的"可升级"假状态冲掉,
    // 让后面几条断言莫名其妙地失败 (本机踩到过 —— 这就是个竞态)。
    await page.waitForFunction(
      () => !document.querySelector("#btn-update-check").disabled, { timeout: 60000 });
    check("非生产环境不显示一键更新按钮",
      await page.locator("#btn-update-run").isHidden());
    // 内核升级只由用户显式勾选触发: 开关必须在卡片里, 但非生产环境没有一键更新按钮,
    // 所以整行是收起的 (露出一个升不了级的勾选框只会让人以为自己漏了什么)
    check("内核升级开关存在且在不能升级时收起",
      (await page.locator("#update-core").count()) === 1
      && (await page.locator("#update-core-row").isHidden()), "");
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
    await page.waitForTimeout(350);   // 同上: 等淡入结束, 免得留证图是半透明的
    await page.locator("#confirm-mask").screenshot({ path: path.join(SHOT_DIR, "update-confirm.png") });
    await page.click("#confirm-cancel");
    check("取消后弹窗关闭且不会开始升级",
      (await page.locator("#confirm-mask.hidden").count()) === 1
      && (await page.locator("#btn-update-run").innerText()).includes("2.3.11"), "");

    // 升级完成后的自动重新加载: 判据必须是「本页 JS 的版本 vs 服务器版本」。
    // 旧判据是 `last.to !== current` —— 面板重启之后这两个值本来就相等 (都等于新版本),
    // 于是它恒为假, 自动重载永远不发生, 用户只能自己去点「重新加载面板」(真机踩到)。
    const reloadRule = await page.evaluate(() => {
      const savedInfo = updateInfo, savedPage = pageVersion;
      updateInfo = { ...updateInfo, current: "2.3.11", last: { state: "success", from: "2.3.10", to: "2.3.11" } };
      pageVersion = "2.3.10";                      // 本页还是升级前那份 JS
      const needsReload = updateNeedsReload();
      const oldRule = updateInfo.last.to !== updateInfo.current;   // 旧的错误判据
      pageVersion = "2.3.11";                      // 本页已经是新版本 (比如刚打开就在新版上)
      const freshPage = updateNeedsReload();
      updateInfo = savedInfo; pageVersion = savedPage;
      return { needsReload, oldRule, freshPage };
    });
    check("升级完成后会自动重新加载 (旧判据在这种情况下恒为假)",
      reloadRule.needsReload === true && reloadRule.oldRule === false,
      `需要重载=${reloadRule.needsReload} 旧判据=${reloadRule.oldRule}`);
    check("本页已经是新版本时不无谓刷新",
      reloadRule.freshPage === false, "");

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
    // v2.6.17: 落地端可以额外开放一条 QUIC (Hysteria 2) 内层 —— 跨洋链路走 UDP
    // 没有 TCP over TCP, 是这一版提速的主开关。控件要能选, 且要写清要放行 UDP。
    check("落地端卡片能选「内层 QUIC」(端口 + 开关 + 说明) (v2.6.17)",
      (await page.locator("#chain-exit-hyport").count()) === 1
      && (await page.locator("#chain-exit-hy").count()) === 1
      && /内层 QUIC/.test(await page.locator("#chain-exit-card").innerText()),
      await page.inputValue("#chain-exit-hyport"));
    // 没有 hysteria 二进制时, 这个勾选了也起不来 —— 卡片要先把这件事说出来, 别让用户
    // 对着一个"开了却没反应"的落地端排查。装了 hysteria 的机器上不该出现这句。
    const hyReady = (await (await page.request.get(`${base}/api/dashboard`)).json())
      .chain.exit.hy_available;
    const exitText = await page.locator("#chain-exit-card").innerText();
    check("落地端说清本机有没有 hysteria (没有就别让用户白勾)",
      hyReady ? !/还没装/.test(exitText) : /还没装/.test(exitText),
      hyReady ? "本机已有 hysteria" : "本机没有 hysteria → 卡片已标注");

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

    // v2.6.17: 入口端多了一个「内层传输」下拉。能不能选 QUIC 由配对码决定 (v2 带
    // QUIC 凭据才放行), 前端只做"预览", 真正校验仍在服务端。
    check("入口端有「内层传输」下拉 (Reality / QUIC) (v2.6.17)",
      (await page.locator("#chain-transport").count()) === 1
      && (await page.locator("#chain-transport option").count()) === 2,
      await page.locator("#chain-transport-hint").innerText());
    // 还没粘配对码时 QUIC 也是置灰的 —— 这里以前**一个字都不显示**, 用户点开下拉
    // 看到灰选项, 只能以为"下拉坏了"。现在选项文字与提示都要说清: 得先让落地端开内层 QUIC。
    const emptyGate = await page.evaluate(() => ({
      disabled: document.querySelector("#chain-transport-quic").disabled,
      opt: document.querySelector("#chain-transport-quic").innerText.trim(),
      hint: document.querySelector("#chain-transport-hint").innerText.trim(),
    }));
    check("没粘配对码时也写清 QUIC 为什么点不了 (选项文字 + 提示, 不再是空白)",
      emptyGate.disabled && /落地端/.test(emptyGate.opt) && emptyGate.hint.length > 10
      && /QUIC/.test(emptyGate.hint),
      `${emptyGate.opt} | ${emptyGate.hint.slice(0, 44)}`);
    await page.fill("#chain-code", exitCard.code);   // 这份是 v1 码 (没勾内层 QUIC)
    const v1Gate = await page.evaluate(() => ({
      disabled: document.querySelector("#chain-transport-quic").disabled,
      value: document.querySelector("#chain-transport").value,
      hint: document.querySelector("#chain-transport-hint").innerText,
    }));
    check("v1 配对码下 QUIC 选项置灰, 并说清是落地端没开 (v2.6.17)",
      v1Gate.disabled && v1Gate.value === "reality" && /没有 QUIC 凭据/.test(v1Gate.hint),
      v1Gate.hint.slice(0, 34));
    const detect = await page.evaluate(() => {
      const b64 = (o) => btoa(JSON.stringify(o)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      const v1 = chainCodeInfo(`ZPC1~${b64({ v: 1, h: "1.2.3.4", p: 8447, l: "x" })}~abc123`);
      const v2 = chainCodeInfo(
        `ZPC1~${b64({ v: 2, h: "1.2.3.4", n: "sni.example.com", l: "x", r: { p: 8447 }, y: { p: 8448, w: "pw", n: "sni.example.com" } })}~abc123`);
      return {
        v1: !!(v1 && v1.v === 1), v2: !!(v2 && v2.v === 2 && v2.y && v2.y.p === 8448),
        junk: chainCodeInfo("粘贴一坨不是配对码的东西") === null,
      };
    });
    check("前端能解出配对码版本 (v1 无 QUIC / v2 带 QUIC 凭据 / 非码返回 null) (v2.6.17)",
      detect.v1 && detect.v2 && detect.junk, JSON.stringify(detect));
    await page.evaluate(() => {
      const b64 = (o) => btoa(JSON.stringify(o)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      const box = document.querySelector("#chain-code");
      box.value = `ZPC1~${b64({ v: 2, h: "1.2.3.4", n: "sni.example.com", l: "x", r: { p: 8447 }, y: { p: 8448, w: "pw", n: "sni.example.com" } })}~abc123`;
      box.dispatchEvent(new Event("input", { bubbles: true }));
    });
    const v2Gate = await page.evaluate(() => ({
      disabled: document.querySelector("#chain-transport-quic").disabled,
      hint: document.querySelector("#chain-transport-hint").innerText,
    }));
    check("v2 配对码下 QUIC 可选, 且提示「跨洋建议选它」 (v2.6.17)",
      !v2Gate.disabled && /QUIC|UDP/.test(v2Gate.hint), v2Gate.hint.slice(0, 34));
    await page.fill("#chain-code", "");   // 清掉, 下面走真实那条(不通的)配对码

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
    await page.waitForTimeout(350);
    await page.locator("#confirm-mask .modal").screenshot({ path: path.join(SHOT_DIR, "chain-confirm.png") });
    await page.click("#confirm-ok");
    await page.waitForSelector("#chain-entries .chain-entry", { timeout: 40000 });
    const entryCard = await page.evaluate(() => {
      const card = document.querySelector("#chain-entries .chain-entry");
      const text = card.innerText;
      return {
        text,
        id: (card.querySelector("[data-chain-probe]") || {}).dataset?.chainProbe || "",
        hasToggle: !!card.querySelector(".switch .slider"),
        hasDefault: !!card.querySelector("[data-chain-default]"),
        hasDelete: !!card.querySelector("[data-chain-del]"),
        hasTransportBtn: !!card.querySelector("[data-chain-transport]"),
        meta: (card.querySelector(".meta") || {}).innerText || "",
        toggled: !!card.querySelector("input:checked"),
      };
    });
    check("入口端落地成一张链式卡片 (经落地地址 + 本机端口)",
      /203\.0\.113\.9:8447/.test(entryCard.text) && /运行中/.test(entryCard.text)
      && entryCard.hasToggle && entryCard.hasDefault && entryCard.hasDelete && entryCard.toggled,
      entryCard.text.split("\n").slice(0, 3).join(" · "));
    // v1 配对码 = 落地端没开内层 QUIC → 没有 QUIC 凭据, 不该出现「改用 QUIC 内层」
    // 这个按了也没用的按钮。
    check("内层传输标在卡片上 (Reality/TCP), v1 码不给 QUIC 切换按钮 (v2.6.17)",
      /内层 Reality\/TCP/.test(entryCard.meta) && !entryCard.hasTransportBtn, entryCard.meta);

    // v2.6.13: 这张卡原来复用节点表的 .node-card (5 列固定列宽), 结果"出口 IP …· …ms"
    // 那个药丸在 116px 的列里折成三行, 三个按钮塞不进 176px 的列往左压到结果文字上。
    const entryLayout = await page.evaluate(() => {
      const card = document.querySelector("#chain-entries .chain-entry");
      const r = (el) => el.getBoundingClientRect();
      const box = r(card);
      const pill = card.querySelector(".ping");
      const probe = card.querySelector(".ce-probe");
      const actions = card.querySelector(".actions");
      const hit = (a, b) =>
        Math.min(a.right, b.right) - Math.max(a.left, b.left) > 2 &&
        Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top) > 2;
      const parts = [".ping", ".btn", ".meta", ".addr", ".ce-probe", ".actions"]
        .map((s) => card.querySelector(s)).filter(Boolean);
      return {
        display: getComputedStyle(card).display,
        pillLines: Math.round(r(pill).height / 16),
        probeVsActions: hit(r(probe), r(actions)),
        insideCard: parts.every((el) => {
          const b = r(el);
          return b.left >= box.left - 1 && b.right <= box.right + 1;
        }),
      };
    });
    check("链式卡片自己竖排 (不再套节点表的 5 列网格)",
      entryLayout.display === "flex", `display=${entryLayout.display}`);
    check("出口 IP 药丸不折行 (单行) ", entryLayout.pillLines === 1, `${entryLayout.pillLines} 行`);
    check("按钮不压到探测结果上 (各自成块)",
      !entryLayout.probeVsActions && entryLayout.insideCard, "");
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

    // v2.6.17: 面板原来只显示"整段探测耗时" (含起临时客户端 + 经链问一次回显服务,
    // 天然是秒级), 用户会把几秒当成延迟。现在把「链路 RTT (入口→落地这一次 TCP
    // 握手)」单独拎出来 —— 这条链不通时量不到 tcp_ms, 所以这里直接喂一份探测结果
    // 渲染, 单独钉住这两个数字不会再混成一个。
    const splitProbe = await page.evaluate(() => {
      dash.chain.entries[0].last_probe = {
        ts: Math.floor(Date.now() / 1000), ok: true, probe_ok: true,
        exit_ip: "198.51.100.7", tcp_ms: 187.4, ms: 3120.5, detail: "经链路读回出口 IP",
      };
      renderChain(dash);
      const card = document.querySelector("#chain-entries .chain-entry");
      const pills = Array.from(card.querySelectorAll(".ping")).map((n) => n.textContent.trim());
      return { pills, text: card.innerText.replace(/\s+/g, " ") };
    });
    check("链路 RTT 与探测总耗时分开显示 (不再拿秒级数字当延迟) (v2.6.17)",
      splitProbe.pills.some((t) => /^出口 IP 198\.51\.100\.7$/.test(t))
      && splitProbe.pills.some((t) => /链路 187ms/.test(t))
      && /探测用时 3\.1s/.test(splitProbe.text), splitProbe.pills.join(" / "));

    // 断开 → 卡片与订阅里的节点一起消失
    await page.click(`[data-chain-del='${entryCard.id}']`);
    await page.waitForSelector("#confirm-mask:not(.hidden)");
    await page.click("#confirm-ok");
    await page.waitForFunction(() => !document.querySelector("#chain-entries .chain-entry"), { timeout: 30000 });
    check("断开后链式卡片消失、节点网格回到 5 张",
      (await page.locator("#chain-entries .chain-entry").count()) === 0
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
    // 这个页面只有"已经初始化过"的人才会看到 (没初始化的走初始化页), 所以副标题里
    // 再写一句"ZeroProxy 已初始化"是废话; 真正要说的情况由 #login-hint 按需显示
    const loginHero = await page.evaluate(() => {
      const el = document.querySelector("#view-login .hero");
      return { text: el.innerText.replace(/\s+/g, " ").trim(), ps: el.querySelectorAll("p").length };
    });
    check("登录页不再有「已初始化」这种废话副标题",
      loginHero.ps === 0 && !/已初始化/.test(loginHero.text), loginHero.text);
    // 继续用同一套凭据登录, 后面的检查 (深浅色 / 控制台) 仍要有仪表盘
    await page.fill("#login-pass", "s3cretpass");
    await page.click("#btn-login");
    await page.waitForSelector("#view-dash:not(.hidden)", { timeout: 20000 });
    check("用刚设置的凭据可登录", (await page.locator("#node-grid .node-card").count()) === 5, "");

    await page.waitForTimeout(500);   // 等入场动画走完 (stagger 最多 400ms), 否则整页还是透明的
    const themeA = await page.evaluate(() => ({
      theme: document.documentElement.dataset.theme,
      bg: getComputedStyle(document.body).backgroundColor,
      card: getComputedStyle(document.querySelector("#sec-audit")).backgroundColor,
    }));
    await page.screenshot({ path: path.join(SHOT_DIR, "dashboard-light.png"), fullPage: true });
    await page.click("#themeBtn");
    await page.waitForTimeout(600);
    const themeB = await page.evaluate(() => ({
      theme: document.documentElement.dataset.theme,
      bg: getComputedStyle(document.body).backgroundColor,
      card: getComputedStyle(document.querySelector("#sec-audit")).backgroundColor,
    }));
    await page.screenshot({ path: path.join(SHOT_DIR, "dashboard-dark.png"), fullPage: true });
    check("深浅色切换真的换了主题与配色 (页面底色 + 卡片底色都变)",
      themeA.theme !== themeB.theme && themeA.bg !== themeB.bg && themeA.card !== themeB.card,
      `${themeA.theme} ${themeA.bg} → ${themeB.theme} ${themeB.bg} · 截图 ${SHOT_DIR}`);

    // CSP 收紧之后的两条: 一是"该放行的确实跑起来了", 二是"该拦的确实拦住了"。
    // 第一条失败起来很安静 (主题退回浅色, 面板上几乎看不出来), 所以必须显式盯住。
    await page.evaluate(() => localStorage.setItem("zp-theme", "dark"));
    await page.reload();
    await page.waitForSelector("#view-dash:not(.hidden)", { timeout: 30000 });
    const bootTheme = await page.evaluate(() => ({
      theme: document.documentElement.dataset.theme,
      bg: getComputedStyle(document.body).backgroundColor,
    }));
    check("CSP 收紧后内联的主题引导脚本仍然生效 (预置深色, 首屏即深色不闪白)",
      bootTheme.theme === "dark" && /rgb\(10, 12, 17\)/.test(bootTheme.bg),
      `${bootTheme.theme} ${bootTheme.bg}`);
    const injectedBlocked = await page.evaluate(() => {
      const s = document.createElement("script");
      s.textContent = "window.__zp_injected = 1";
      document.body.appendChild(s);
      s.remove();
      return window.__zp_injected === undefined;
    });
    check("注入的 <script> 执行不了 (script-src 不再放行 unsafe-inline)",
      injectedBlocked, "");
    // style-src 也收紧了: 收益同样是"注入执行不了", 代价是条状进度 / 延迟 / 流量的宽度
    // 必须走 CSSOM —— 漏掉一处的样子是那条子永远停在 CSS 默认的 width:0, 页面上不报错。
    const styleBlocked = await page.evaluate(() => {
      const target = document.querySelector("#sec-audit") || document.body;
      const s = document.createElement("style");
      s.textContent = "#sec-audit{outline:5px solid rgb(1,2,3)}";
      document.head.appendChild(s);
      s.remove();
      return getComputedStyle(target).outlineStyle;
    });
    check("注入的 <style> 也执行不了 (style-src 不再放行 unsafe-inline)",
      styleBlocked === "none", styleBlocked);
    // 反面: 该落上的必须真的落上 —— 所有带 data-w 的条子都得已经由 applyWidths 赋过宽度
    // (没赋值时 el.style.width 是空串, 计算宽度退回 0)。
    const barState = await page.evaluate(() => {
      const els = [...document.querySelectorAll("[data-w]")];
      return {
        n: els.length,
        unapplied: els.filter((el) => !el.style.width).length,
        nonZero: els.filter((el) => parseFloat(getComputedStyle(el).width) > 0).length,
      };
    });
    check("带 data-w 的条子都真的落上了宽度 (CSSOM 赋值不受 style-src 约束)",
      barState.n > 0 && barState.unapplied === 0 && barState.nonZero > 0,
      `${barState.n} 条 · 未落宽度 ${barState.unapplied} · 非零宽 ${barState.nonZero}`);
    // 上面那次注入是故意的, 浏览器必然记一条 CSP 违规 —— 和"故意输错密码"一样,
    // 把它从待检查的 console 错误里摘掉, 否则「无 console 错误」会稳挂。
    for (let i = consoleErrors.length - 1; i >= 0; i -= 1) {
      if (/Content Security Policy|Refused to execute|violates the following/.test(consoleErrors[i])) {
        consoleErrors.splice(i, 1);
      }
    }

    console.log("\n[3h] 后台落地任务的实时进度 (v2.6.9)");
    // 改配置 = 重新生成三份配置 → 重启内核 → 验端口, 真机上 2~4 秒, 而重启 Xray 会
    // 掐断"走本机链路上网"的浏览器。现在接口立刻回执 + 后台任务 + 进度条轮询。
    await page.click("#btn-apply");
    await page.waitForSelector("#apply-strip .bar", { timeout: 20000 });
    const stripText = (await page.locator("#apply-strip").innerText()).replace(/\s*\n\s*/g, " · ");
    check(
      "点改配置立刻出现实时进度 (接口不再阻塞)",
      /正在应用配置|配置已应用/.test(stripText) && /\/6 步/.test(stripText),
      stripText
    );
    await page.waitForFunction(
      () => {
        const s = document.querySelector("#apply-strip .banner");
        return !!s && /配置已应用/.test(s.innerText);
      },
      { timeout: 30000 }
    );
    check("任务跑完给出结论", /配置已应用/.test(await page.locator("#apply-strip").innerText()), "");
    await page.waitForTimeout(4600);
    check(
      "结论留几秒后自动收起",
      await page.evaluate(() => document.querySelector("#apply-strip").classList.contains("hidden")),
      ""
    );

    console.log("\n[3i] 操作记录");
    check("操作记录卡片渲染出条目",
      (await page.locator("#audit-list .audit-row").count()) > 0,
      `${await page.locator("#audit-list .audit-row").count()} 条`);
    const auditText = (await page.locator("#audit-list").innerText()).trim();
    check("动作显示成「中文名 + 代号」而不是一串英文",
      /初始化部署/.test(auditText) && /setup/.test(auditText), auditText.split("\n").slice(0, 2).join(" / "));
    check("记录按天分组", (await page.locator("#audit-list .audit-day").count()) > 0,
      (await page.locator("#audit-list .audit-day").first().innerText()).trim());

    // 造两条一模一样的失败: 错密码登录 —— 面板要记 login_failed, 并且 **合并计数**
    // (被扫登录失败时, 几百条重复记录会把环形缓冲刷满, 把真正的操作挤出去)
    const loginErrMark = consoleErrors.length;
    const badLogin = () => page.evaluate(() => fetch("/api/login", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "admin", password: "definitely-wrong" }),
    }).then((r) => r.status));
    const firstBad = await badLogin();
    await badLogin();
    for (let i = consoleErrors.length - 1; i >= loginErrMark; i -= 1) {
      if (/401 \(Unauthorized\)/.test(consoleErrors[i])) consoleErrors.splice(i, 1);   // 故意的错误密码
    }
    check("错密码被拒绝 (401)", firstBad === 401, `HTTP ${firstBad}`);

    await page.click("#btn-audit-refresh");
    await page.waitForFunction(
      () => document.querySelector("#audit-list").innerText.includes("登录失败"),
      { timeout: 10000 }
    );
    check("失败的动作合并计数 (×2) 而不是刷满列表",
      /×2/.test(await page.locator("#audit-list").innerText()), "");

    await page.check("#audit-failed");
    await page.waitForFunction(() => {
      const rows = [...document.querySelectorAll("#audit-list .audit-row")];
      return rows.length > 0 && rows.every((r) => r.classList.contains("bad"));
    }, { timeout: 10000 });
    check("「只看失败」只剩失败项, 且都标红",
      /登录失败/.test(await page.locator("#audit-list").innerText()),
      `${await page.locator("#audit-list .audit-row").count()} 条`);
    await page.uncheck("#audit-failed");

    await page.click('#audit-chips .chip[data-cat="auth"]');
    await page.waitForFunction(() => {
      const rows = [...document.querySelectorAll("#audit-list .audit-row")];
      return rows.length > 0 && rows.every((r) => /login|logout/.test(r.innerText));
    }, { timeout: 10000 });
    check("按分类筛选 (安全) 只留认证类动作",
      /安全/.test(await page.locator("#audit-chips .chip.on").innerText()), "");

    // 关键字搜索要穿过详情: 先回到「全部」—— 分类和搜索是叠加的, 停在"安全"分类
    // 时 "domain=" 只在 setup/backup 的详情里, 永远搜不到 (这是面板本来的语义)。
    await page.click('#audit-chips .chip[data-cat=""]');
    await page.fill("#audit-q", "domain=");
    await page.waitForFunction(() => {
      const rows = [...document.querySelectorAll("#audit-list .audit-row")];
      return rows.length > 0 && rows.every((r) => r.innerText.includes("domain="));
    }, { timeout: 10000 });
    check("关键字搜索能穿透到详情", true,
      (await page.locator("#audit-list .audit-row").first().innerText()).replace(/\s+/g, " ").slice(0, 70));

    await page.click("#btn-audit-refresh");     // 有筛选时它是「回到最近」
    await page.waitForFunction(() => {
      const on = document.querySelector("#audit-chips .chip.on");
      return on && !on.dataset.cat && document.querySelector("#audit-q").value === "";
    }, { timeout: 10000 });
    check("「回到最近」清掉筛选并恢复默认视图",
      (await page.locator("#audit-list .audit-row").count()) > 0, "");

    console.log("\n[3i-2] 记录管理 (清空) 与回到顶部");
    const beforeClear = await page.locator("#audit-list .audit-row").count();
    await page.click("#btn-audit-clear");
    await page.waitForSelector("#confirm-mask:not(.hidden)");
    const clearBody = (await page.locator("#confirm-body").innerText()).replace(/\s+/g, " ");
    check("清空记录先弹确认, 并写清归档文件不受影响",
      /清空/.test(await page.locator("#confirm-title").innerText()) && /归档文件不会被删除/.test(clearBody),
      clearBody.slice(0, 60));
    await page.click("#confirm-ok");
    await page.waitForFunction(() => {
      const rows = [...document.querySelectorAll("#audit-list .audit-row")];
      return rows.length === 1 && /清空操作记录/.test(rows[0].innerText);
    }, { timeout: 15000 });
    check("清空后只剩「清空操作记录」这一条 (不会空得看不出谁清过)",
      beforeClear > 1, `清空前 ${beforeClear} 条`);
    check("清空这个动作本身带风险标记",
      (await page.locator("#audit-list .audit-row .risk").count()) === 1, "");

    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
    await page.waitForFunction(
      () => document.querySelector("#to-top").classList.contains("on"), { timeout: 5000 });
    check("滚到下方后出现「回到顶部」", true, "");
    await page.click("#to-top");
    await page.waitForFunction(() => window.scrollY < 40, { timeout: 8000 });
    check("点它真的回到顶部, 且自己隐藏",
      !(await page.evaluate(() => document.querySelector("#to-top").classList.contains("on"))), "");

    console.log("\n[3i-3] 顶部「出口 IP」卡片: 落地 IP 与本机 IP 都在, 都能点复制");
    // 以前这张卡只显示落地出口 IP, 本机公网 IP (用户要填进客户端的那个) 面板里无处可查,
    // 也没有任何"点一下复制"的入口。这里把 /api/dashboard 拦下来塞一个本机 IP + 一条
    // 启用的链, 验两个 IP 同时渲染且都是可复制的芯片。
    const nowSec2 = Math.floor(Date.now() / 1000);
    await page.route("**/api/dashboard", async (route) => {
      const res = await route.fetch();
      const body = await res.json();
      body.system.server.public_ip = "203.0.113.9";
      body.system.server.public_ip_at = nowSec2;
      body.chain.entries = [{
        id: "zz-egress", label: "美国落地", host: "198.51.100.7", port: 8666,
        local_port: 8447, transport: "reality", sni: "www.microsoft.com",
        enabled: true, default_out: true, has_quic: false,
        last_probe: {
          ok: true, probe_ok: true, exit_ip: "198.51.100.7", tcp_ms: 152.4,
          ms: 3120.5, ts: nowSec2, detail: "经链路读回出口 IP",
        },
      }];
      await route.fulfill({ response: res, json: body });
    });
    await page.reload();
    await page.waitForSelector("#view-dash:not(.hidden)", { timeout: 30000 });
    await page.waitForFunction(
      () => document.querySelectorAll("#kpi-egress .copy-ip, #kpi-egress-sub .copy-ip").length === 2,
      { timeout: 20000 });
    const ipCard = await page.evaluate(() => ({
      label: document.querySelector("#kpi-egress").closest(".k").querySelector(".k-lab").innerText.trim(),
      main: document.querySelector("#kpi-egress").innerText.trim(),
      chips: [...document.querySelectorAll("#kpi-egress .copy-ip, #kpi-egress-sub .copy-ip")]
        .map((el) => el.dataset.copyIp),
      sub: document.querySelector("#kpi-egress-sub").innerText.replace(/\s+/g, " ").trim(),
    }));
    check("出口 IP 卡片同时给出落地 IP 和本机 IP",
      ipCard.main === "198.51.100.7" && ipCard.chips.join(",") === "198.51.100.7,203.0.113.9"
      && /本机 203\.0\.113\.9/.test(ipCard.sub) && /链路 152ms/.test(ipCard.sub),
      `${ipCard.label} · ${ipCard.sub}`);
    await page.evaluate(() => document.querySelector("#toast").classList.remove("show"));
    await page.click("#kpi-egress-sub .copy-ip");
    await page.waitForSelector("#toast.show", { timeout: 8000 });
    const copyToast = (await page.locator("#toast").innerText()).trim();
    check("点本机 IP 就能复制", /已复制/.test(copyToast), copyToast);
    await page.unroute("**/api/dashboard");

    console.log("\n[3j] 面板设置 (管理员账号 / 面板域名)");
    check("侧栏有「面板设置」入口",
      (await page.locator("#dash-nav a[href='#sec-panel']").count()) === 1);
    const panelText = await page.locator("#panel-grid").innerText();
    check("设置里同时有账号与域名两块",
      /管理员账号/.test(panelText) && /面板域名/.test(panelText)
      && /更换域名并部署/.test(panelText), panelText.split("\n")[0].slice(0, 40));
    check("用户名按当前账号预填", (await page.inputValue("#acct-user")) === "admin",
      await page.inputValue("#acct-user"));
    // 忘记密码的兜底入口要写在卡片上, 否则用户根本不知道有这条路
    check("账号卡片写明「忘记密码 → SSH 输入 z」这条兜底路",
      /(忘记|忘了)密码/.test(panelText) && /SSH/.test(panelText) && /\bz\b/.test(panelText),
      (panelText.match(/忘了密码[^\n]*/) || [""])[0].slice(0, 60));
    // 当前密码不对: 明确报错, 而且什么都不改 (要带上一处真实改动才会打到后端 ——
    // 没有任何改动时前端本来就该拦住, 那是另一条路径)
    await page.fill("#acct-now", "definitely-wrong");
    await page.fill("#acct-user", "operator");
    await page.evaluate(() => document.querySelector("#toast").classList.remove("show"));
    // 这个 401 是我们自己故意撞的, 浏览器照例会往控制台打条红字 —— 摘掉, 别掩盖真报错
    const acctErrMark = consoleErrors.length;
    await page.click("#btn-acct-save");
    await page.waitForSelector("#toast.show", { timeout: 10000 });
    check("改账号必须先验证当前密码",
      /当前密码不正确/.test(await page.locator("#toast").innerText()),
      (await page.locator("#toast").innerText()).trim());
    for (let i = consoleErrors.length - 1; i >= acctErrMark; i -= 1) {
      if (/401 \(Unauthorized\)/.test(consoleErrors[i])) consoleErrors.splice(i, 1);
    }
    await page.waitForFunction(
      () => document.querySelector("#side-user").innerText.trim() === "admin", { timeout: 5000 });
    // 密码填对了才真的改; 改完再改回来 (密码不动 —— 后面的登录断言还要用 s3cretpass)
    await page.fill("#acct-now", "s3cretpass");
    await page.click("#btn-acct-save");
    await page.waitForFunction(
      () => document.querySelector("#side-user").innerText.trim() === "operator", { timeout: 15000 });
    check("改用户名立即生效 (侧栏同步)", true, "admin → operator");
    await page.fill("#acct-now", "s3cretpass");
    await page.fill("#acct-user", "admin");
    await page.click("#btn-acct-save");
    await page.waitForFunction(
      () => document.querySelector("#side-user").innerText.trim() === "admin", { timeout: 15000 });
    check("用户名能改回来", true, "operator → admin");

    // 域名: 这一格只收域名, IP 当场拒绝
    await page.fill("#dom-new", "1.2.3.4");
    await page.evaluate(() => document.querySelector("#toast").classList.remove("show"));
    await page.click("#btn-dom-save");
    await page.waitForSelector("#toast.show", { timeout: 8000 });
    check("换域名那一格只收域名 (填 IP 当场拒绝)",
      /域名/.test(await page.locator("#toast").innerText()),
      (await page.locator("#toast").innerText()).trim());
    // 确认弹窗要把"做什么 / 会变什么 / 失败怎么办"写清 (真按下去会跳到新域名, 所以这里只验弹窗)
    await page.fill("#dom-new", "proxy2.example.com");
    await page.click("#btn-dom-save");
    await page.waitForSelector("#confirm-mask:not(.hidden)");
    const domBody = (await page.locator("#confirm-body").innerText()).replace(/\s+/g, " ");
    check("换域名的确认弹窗列出步骤与回滚保证",
      /申请 TLS 证书/.test(domBody) && /回滚/.test(domBody) && /自动跳转/.test(domBody)
      && /订阅地址/.test(domBody), domBody.slice(0, 80));
    await page.click("#confirm-cancel");
    check("取消后弹窗关闭且域名没变",
      (await page.locator("#confirm-mask.hidden").count()) === 1
      && (await page.locator("#dash-domain").innerText()).trim() === "proxy.example.com", "");
    // 本地开发环境没有 nginx / 公网入口: 部署完**不能**把浏览器扔到 https://新域名:端口
    // (那是打不开的地址)。这里把 /api/domain 的响应换成一个"已完成"的假任务来验这条保护。
    await page.route("**/api/domain", (route) => route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        ok: true,
        detail: "已开始更换域名",
        steps: [],
        job: { id: "999999", kind: "domain", state: "done", index: 5, total: 8, current: "验证新域名", steps: [], error: "" },
        redirect: { url: "https://proxy2.example.com:8899/", handoff: "zph_test", ready: false },
      }),
    }));
    const beforeJump = page.url();
    // 假任务 id 查不到 → 轮询会撞一次 404, 浏览器照例打红字: 这是脚本自己造的, 摘掉
    const jumpErrMark = consoleErrors.length;
    await page.fill("#dom-new", "proxy2.example.com");
    await page.click("#btn-dom-save");
    await page.waitForSelector("#confirm-mask:not(.hidden)");
    await page.click("#confirm-ok");
    await page.waitForFunction(
      () => /本地开发环境/.test(document.querySelector("#panel-jump-hint").innerText),
      { timeout: 20000 });
    for (let i = consoleErrors.length - 1; i >= jumpErrMark; i -= 1) {
      if (/404 \(Not Found\)/.test(consoleErrors[i])) consoleErrors.splice(i, 1);
    }
    check("本地开发环境不把浏览器扔到打不开的新地址",
      page.url() === beforeJump
      && /本地开发环境/.test(await page.locator("#panel-jump-hint").innerText()),
      (await page.locator("#panel-jump-hint").innerText()).trim());
    await page.unroute("**/api/domain");
    await page.locator("#sec-panel").screenshot({ path: path.join(SHOT_DIR, "panel-settings.png") });

    console.log("\n[3k] 节点卡的说明文字不再被省略号截断");
    // 用户反馈: 每个节点下面那句"这个协议是干什么的"被单行省略号切掉, 又难看又看不清。
    // 这里量的是**真的没被切**: -webkit-line-clamp 生效时 scrollHeight 会超过 clientHeight。
    const descStats = () => page.evaluate(() => {
      return [...document.querySelectorAll("#node-grid .node-card")].map((card) => {
        const d = card.querySelector(".nc-desc");
        const info = card.querySelector(".nc-info");
        return {
          text: d.textContent.trim(),
          clipped: d.scrollHeight > d.clientHeight + 1,
          infoRatio: info.getBoundingClientRect().width / card.getBoundingClientRect().width,
        };
      });
    });
    const wideDesc = await descStats();
    check("宽屏: 每个节点的说明文字都完整可见",
      wideDesc.length >= 5 && wideDesc.every((d) => !d.clipped && d.text.length > 4),
      `${wideDesc.length} 张卡片, 被截断 ${wideDesc.filter((d) => d.clipped).length} 个`);
    // 窄屏 (手机 / 分屏): 五列塞不下 → 改成堆叠式, 说明文字拿到整卡宽度
    await page.setViewportSize({ width: 719, height: 900 });
    await page.waitForTimeout(400);
    const narrowDesc = await descStats();
    check("窄屏: 节点卡改成堆叠式, 说明文字依然完整",
      narrowDesc.every((d) => !d.clipped) && narrowDesc.every((d) => d.infoRatio > 0.85),
      `说明块占卡宽 ${narrowDesc.map((d) => Math.round(d.infoRatio * 100) + "%").join(" ")}`);
    await page.locator("#node-grid").screenshot({ path: path.join(SHOT_DIR, "nodes-narrow.png") });
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.waitForTimeout(250);

    console.log("\n[4] 控制台与请求");
    check("无 console 错误", consoleErrors.length === 0, consoleErrors.slice(0, 3).join(" | "));
    check("无失败请求", failedRequests.length === 0, failedRequests.slice(0, 3).join(" | "));

    console.log("\n[3g] 断线不跳登录 (改配置要重启内核, 会掐断走本机链路的浏览器)");
    // 面板重启内核时, "走本机这条链路"的浏览器会先断再通; 之前这里任何一次
    // /api/dashboard 失败都会把人踢回登录页 —— 点一次「生成配对码」就跳登录。
    let droppedOnce = 0;
    await page.route("**/api/dashboard", (route) => {
      if (droppedOnce++ === 0) return route.abort("connectionreset");
      return route.continue();
    });
    await page.evaluate(() => loadDash(true));
    const duringDrop = await page.evaluate(() => ({
      dash: !document.querySelector("#view-dash").classList.contains("hidden"),
      login: !document.querySelector("#view-login").classList.contains("hidden"),
      pill: (document.querySelector("#dash-state") || {}).textContent || "",
    }));
    check("连接中断时不跳登录页", duringDrop.dash && !duringDrop.login, `dash=${duringDrop.dash} login=${duringDrop.login}`);
    check("断线期间给出「正在重连」提示", /重连/.test(duringDrop.pill), duringDrop.pill.trim());
    await page.unroute("**/api/dashboard");
    await page.waitForTimeout(2600);
    const afterDrop = await page.evaluate(() => ({
      dash: !document.querySelector("#view-dash").classList.contains("hidden"),
      pill: (document.querySelector("#dash-state") || {}).textContent || "",
      cards: document.querySelectorAll("#node-grid .node-card").length,
    }));
    check("重连后仪表盘自动恢复", afterDrop.dash && afterDrop.cards === 5 && !/重连/.test(afterDrop.pill), afterDrop.pill.trim());

    await page.route("**/api/dashboard", (route) =>
      route.fulfill({ status: 401, contentType: "application/json", body: JSON.stringify({ error: "未登录" }) })
    );
    await page.evaluate(() => loadDash(true));
    await page.waitForTimeout(300);
    check(
      "真正的 401 才回登录页",
      await page.evaluate(() => !document.querySelector("#view-login").classList.contains("hidden")),
      ""
    );
    await page.unroute("**/api/dashboard");
    await page.goto(base);
    await page.waitForSelector("#view-dash:not(.hidden)", { timeout: 20000 });
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
