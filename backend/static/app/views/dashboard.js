/** 仪表盘: 拉取 / 重画 / 侧栏滚动高亮, 以及"装配"那一步。
 *
 *  这是唯一 import 其他视图的模块 —— 它负责编排 (各区块彼此不认识)。反过来, 其他
 *  视图要重画仪表盘只能走 lib/state.js 的 redrawDash / reloadDash 钩子, 循环依赖
 *  在这里被切断 (否则 dashboard ↔ traffic 会互相 import)。
 */
import { $, toast, copyText, show } from "../lib/dom.js";
import { api, sessionState, markDisconnected } from "../lib/api.js";
import { snapshotDraftInputs, restoreDraftInputs } from "../lib/drafts.js";
import { openQr, SUB_FMT_LABEL } from "../lib/dialog.js";
import { S, setDashRenderers } from "../lib/state.js";
import { renderAudit } from "./audit.js";
import { renderNodes, renderKpis, renderDashboardBanner, runProbe } from "./status.js";
import { renderTraffic, renderAdvanced, renderSystem } from "./traffic.js";
import { renderChain } from "./chain.js";
import { loadUpdate, renderUpdate } from "./update.js";
import { renderPanel } from "./panel.js";

/* ---------------- 仪表盘 ---------------- */
export async function loadDash(quiet) {
  try {
    S.dash = await api("/api/dashboard");
    renderDash(quiet);
    show("view-dash");
  } catch (e) {
    // 只有"面板明确说未登录"才回登录页。连接中断 (内核/面板重启, 浏览器又正好
    // 走本机链路时必然发生) 不该把人踢出去 —— 否则点一次「生成配对码」就跳登录。
    if (!e.dropped && e.status === 401) {
      show("view-login");
      return;
    }
    markDisconnected();
    if (!quiet) toast("连接中断, 正在重连…");
    const alive = await sessionState();
    if (alive === false) { show("view-login"); return; }   // 真的掉登录了
    setTimeout(() => { if (S.dash && !S.opBusy) loadDash(true); else if (!S.dash) boot(); }, 1200);
    return;
  }
  clearInterval(S.refreshTimer);
  // 链式连接 / 热更新这类操作可能跑十几秒: 期间别整块重绘, 否则按钮的"进行中"
  // 状态会被冲掉, 用户还能再点一次 (连接落地端会重复落地)
  // 后台落地任务同理: 任务跑着的时候重绘会跟进度条抢屏, 而且这次刷新还得排队等锁
  S.refreshTimer = setInterval(() => {
    if (S.dash && !S.opBusy && !S.applyJobId) loadDash(true);
  }, 20000);
  // 首次进入仪表盘自动测一次速 (之后由用户点「节点测速」触发)
  if (!S.probeRan) { S.probeRan = true; runProbe(false); }
}

export function renderDash(quiet) {
  if (!S.dash) return;
  revealBlocks();   // 先挂入场动画, 万一后面某块渲染抛错也不会留下"整页透明"
  // 重渲染会重建节点表 / 高级设置 / 链式代理的 DOM: 先把用户正在填的输入存下来
  const drafts = snapshotDraftInputs();
  $("#dash-domain").textContent = S.dash.domain;
  $("#dash-sub").textContent = `面板 ${S.dash.panel_url} · 管理用户 ${S.dash.admin_user}`;

  /* 订阅三种格式 */
  ["base64", "clash", "singbox"].forEach((fmt) => {
    $("#sub-" + fmt).textContent = S.dash.subscription_formats[fmt];
  });

  /* 节点卡片 */
  renderNodes();
  document.querySelectorAll("[data-copy-fmt]").forEach((el) =>
    (el.onclick = () => copyText(S.dash.subscription_formats[el.dataset.copyFmt]))
  );
  document.querySelectorAll("[data-qr-fmt]").forEach((el) =>
    (el.onclick = () => {
      const fmt = el.dataset.qrFmt;
      const q = `format=${encodeURIComponent(fmt)}`;
      openQr({
        title: "订阅二维码",
        sub: `${SUB_FMT_LABEL[fmt] || fmt} 订阅 · 手机 App 扫码导入`,
        link: S.dash.subscription_formats[fmt],
        svg: `/api/subscription/qr?img=svg&${q}`,
        png: `/api/subscription/qr?size=8&${q}`,
        file: `zeroproxy-sub-${fmt}.png`,
      });
    })
  );

  renderTraffic(S.dash.traffic);
  renderAdvanced(S.dash);
  renderChain(S.dash);
  renderSystem(S.dash);
  renderPanel(S.dash);
  renderAudit(S.dash.audit, S.dash.audit_facets, S.dash.audit_stats, S.dash.audit_more);
  renderKpis();
  renderDashboardBanner();
  // 内核版本行取自仪表盘数据, 所以已有 updateInfo 时也要重画一次 (纯 DOM, 不出网)
  if (!S.updateInfo) loadUpdate(false);
  else renderUpdate();
  if (!quiet) { $("#diag-list").innerHTML = ""; $("#diag-actions").classList.add("hidden"); }
  restoreDraftInputs(drafts);
}

/* 首次进入仪表盘时, 各区块按 40ms 逐个淡入 (只在第一次跑;
 * 20s 轮询重绘不再触发, 免得页面一直在闪)。 */
function revealBlocks() {
  if (S.revealed) return;
  S.revealed = true;
  document.querySelectorAll("#view-dash .reveal").forEach((el, i) => {
    setTimeout(() => el.classList.add("in"), Math.min(i * 40, 400));
  });
  setupScrollSpy();
}

/* 侧栏: 点击平滑滚动 + 滚动时高亮当前区块 (吸顶栏高度用 scroll-margin 让开) */
function setupScrollSpy() {
  const nav = $("#dash-nav");
  if (!nav) return;
  const links = [...nav.querySelectorAll("a")];
  const secs = links
    .map((a) => document.querySelector(a.getAttribute("href")))
    .filter(Boolean);
  links.forEach((a) => {
    a.addEventListener("click", (e) => {
      const target = document.querySelector(a.getAttribute("href"));
      if (!target) return;
      e.preventDefault();
      target.scrollIntoView({ behavior: "smooth", block: "start" });
      history.replaceState(null, "", a.getAttribute("href"));
    });
  });
  if (!("IntersectionObserver" in window) || !secs.length) return;
  const visible = new Map();
  const io = new IntersectionObserver(
    (entries) => {
      entries.forEach((en) => visible.set(en.target.id, en.isIntersecting ? en.intersectionRatio : 0));
      let best = "", bestRatio = 0;
      visible.forEach((ratio, id) => {
        if (ratio > bestRatio) { bestRatio = ratio; best = id; }
      });
      if (!best) return;
      links.forEach((a) => a.classList.toggle("on", a.getAttribute("href") === "#" + best));
    },
    { rootMargin: "-84px 0px -55% 0px", threshold: [0, 0.15, 0.4, 0.75, 1] }
  );
  secs.forEach((s) => io.observe(s));
}

/* 回到顶部: 滚动超过一屏才出现, 平滑滚回。
 * 滚动监听用 passive —— 它只读 scrollY, 不阻止默认行为, 别拖累滚动帧率。
 * 「减少动态效果」下改成瞬时跳转: behavior:"smooth" 不看 prefers-reduced-motion。 */
(function bindBackToTop() {
  const btn = $("#to-top");
  if (!btn) return;
  const sync = () => btn.classList.toggle("on", window.scrollY > 400);
  window.addEventListener("scroll", sync, { passive: true });
  sync();
  btn.onclick = () =>
    window.scrollTo({
      top: 0,
      behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
    });
})();

/* 入口: 决定进"初始化 / 登录 / 仪表盘"哪一个视图。
 * 放在这个模块里而不是 main.js, 是因为它要用 loadDash —— 反过来 loadDash 的连接
 * 异常分支也要回调 boot(), 两者必须同处一个模块才不会变成循环依赖。 */
export async function boot() {
  // 引导令牌来自 install.sh 打印的链接 (?token=...), 初始化时必须带上
  const params = new URLSearchParams(location.search);
  S.bootstrapToken = params.get("token") || "";
  // 初始化完成后会把用户送到域名面板, 顺手带上刚设的用户名 (?user=...), 省一次输入
  // (会话 Cookie 是按 host 存的, 跨到域名必须重新登录 —— 密码绝不会出现在 URL 里)
  const presetUser = params.get("user") || "";
  if (S.bootstrapToken || presetUser) history.replaceState(null, "", location.pathname);
  // 换域名后跳过来的那一跳带着一次性交接票据 (?handoff=…): 先换成会话, 用户就
  // 不用在新域名上再登一次。票据从地址栏里立刻抹掉, 只在历史里留下一跳的时间。
  const handoff = params.get("handoff") || "";
  if (handoff) {
    history.replaceState(null, "", location.pathname);
    try {
      await api("/api/session/handoff", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: handoff }),
      });
    } catch (e) {
      // 票据过期 / 用过了都走这里: 下面照常走登录页, 不该卡住
    }
  }
  try {
    const st = await api("/api/status");
    if (!st.configured) {
      show("view-setup");
      if (st.token_required && !S.bootstrapToken) {
        const hint = $("#setup-hint");
        hint.textContent = "本面板已启用引导令牌保护。请使用安装完成时终端打印的、带 ?token= 的链接打开本页, 否则无法完成初始化。";
        hint.classList.remove("hidden");
      }
      return;
    }
    if (st.authenticated) return loadDash();
    if (presetUser) {
      $("#login-user").value = presetUser;
      const hint = $("#login-hint");
      hint.textContent = "已切换到域名面板 (真实证书)。用刚设置的账号密码登录即可, 用户名已填好。";
      hint.classList.remove("hidden");
    }
    show("view-login");
    if (presetUser) $("#login-pass").focus();
  } catch (e) {
    // /api/status 都连不上 = 面板或内核正在重启 (改配置后的正常现象), 别急着把人
    // 扔到"初始化"页 —— 先重试, 拿到答复再决定是回仪表盘还是真去登录。
    markDisconnected();
    const alive = await sessionState(8, 1500);
    if (alive) return loadDash();
    show("view-login");
    if (alive === null) {
      const hint = $("#login-hint");
      hint.textContent = "面板暂时连不上 (可能正在重启内核)。稍等几秒刷新本页即可, 不需要重新初始化。";
      hint.classList.remove("hidden");
    }
  }
}

// 装配: 把"重画 / 重新拉取"注册到 lib/state.js 的钩子上, 供 jobs 与其他视图回调。
setDashRenderers(renderDash, loadDash);
