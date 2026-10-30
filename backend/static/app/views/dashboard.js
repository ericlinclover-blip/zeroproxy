/** 仪表盘: 拉取 / 重画 / 侧栏滚动高亮, 以及"装配"那一步。
 *
 *  改动:
 *    1) 使用后端 fingerprint 做智能轮询间隔
 *    2) 渲染用 rAF 批次合并
 */
import { $, toast, copyText, show } from "../lib/dom.js";
import { api, sleep, sessionState, markDisconnected } from "../lib/api.js";
import { readToken, rememberToken } from "../lib/bootstrap.js";
import { snapshotDraftInputs, restoreDraftInputs } from "../lib/drafts.js";
import { openQr, SUB_FMT_LABEL } from "../lib/dialog.js";
import { S, setDashRenderers, pollInterval } from "../lib/state.js";
import { renderAudit } from "./audit.js";
import { renderNodes, renderKpis, renderDashboardBanner, runProbe } from "./status.js";
import { renderTraffic, renderAdvanced, renderSystem } from "./traffic.js";
import { renderChain } from "./chain.js";
import { renderClients } from "./clients.js";
import { renderWireguard } from "./wireguard.js";
import { loadUpdate, renderUpdate } from "./update.js";
import { renderPanel } from "./panel.js";

/* ---------------- 仪表盘 ---------------- */
export async function loadDash(quiet) {
  try {
    S.dash = await api("/api/dashboard");
    renderDash(quiet);
    show("view-dash");
  } catch (e) {
    if (!e.dropped && e.status === 401) {
      show("view-login");
      return;
    }
    markDisconnected();
    if (!quiet) toast("连接中断, 正在重连…");
    const alive = await sessionState();
    if (alive === false) { show("view-login"); return; }
    setTimeout(() => { if (S.dash && !S.opBusy) loadDash(true); else if (!S.dash) boot(); }, 1200);
    return;
  }
  clearInterval(S.refreshTimer);
  // 智能轮询: 操作期间 10s, 正常 20s, 连续无变化 60s
  const fp = S.dash && S.dash.fingerprint;
  const interval = pollInterval(fp, S.opBusy > 0 || S.applyJobId);
  S.refreshTimer = setInterval(() => {
    if (S.dash && !S.opBusy && !S.applyJobId) loadDash(true);
  }, interval);
  if (!S.probeRan) { S.probeRan = true; runProbe(false); }
}

export function renderDash(quiet) {
  if (!S.dash) return;
  revealBlocks();
  const drafts = snapshotDraftInputs();
  $("#dash-domain").textContent = S.dash.domain;
  $("#dash-sub").textContent = `面板 ${S.dash.panel_url} · 管理用户 ${S.dash.admin_user}`;

  ["base64", "clash", "singbox"].forEach((fmt) => {
    $("#sub-" + fmt).textContent = S.dash.subscription_formats[fmt];
  });

  renderNodes();
  document.querySelectorAll("[data-copy-fmt]").forEach((el) =>
    (el.onclick = () => copyText(S.dash.subscription_formats[el.dataset.copyFmt]))
  );
  document.querySelectorAll("[data-import-app]").forEach((el) =>
    (el.onclick = () => {
      const app = el.dataset.importApp;
      const links = S.dash.deep_links || {};
      const url = links[app];
      if (!url) {
        toast("未生成该客户端的导入链接");
        return;
      }
      toast(`正在唤起 ${app} 客户端…`);
      window.location.href = url;
    })
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
  renderClients(S.dash);
  renderWireguard(S.dash);
  renderSystem(S.dash);
  renderPanel(S.dash);
  renderAudit(S.dash.audit, S.dash.audit_facets, S.dash.audit_stats, S.dash.audit_more);
  renderKpis();
  renderDashboardBanner();
  if (!S.updateInfo) loadUpdate(false);
  else renderUpdate();
  if (!quiet) { $("#diag-list").innerHTML = ""; $("#diag-actions").classList.add("hidden"); }
  restoreDraftInputs(drafts);
}

function revealBlocks() {
  if (S.revealed) return;
  S.revealed = true;
  document.querySelectorAll("#view-dash .reveal").forEach((el, i) => {
    setTimeout(() => el.classList.add("in"), Math.min(i * 40, 400));
  });
  setupScrollSpy();
}

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

async function waitForStatus(tries = 8, delay = 1500) {
  for (let i = 0; i < tries; i++) {
    try { return await api("/api/status"); }
    catch (e) { if (i < tries - 1) await sleep(delay); }
  }
  return null;
}

function routeByStatus(st, presetUser) {
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
}

export async function boot() {
  const params = new URLSearchParams(location.search);
  const urlToken = params.get("token") || "";
  if (urlToken) rememberToken(urlToken);
  S.bootstrapToken = urlToken || readToken();
  const presetUser = params.get("user") || "";
  if (urlToken || presetUser) history.replaceState(null, "", location.pathname);
  const handoff = params.get("handoff") || "";
  if (handoff) {
    history.replaceState(null, "", location.pathname);
    try {
      await api("/api/session/handoff", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: handoff }),
      });
    } catch (e) { /* 票据过期/用过了, 照常走登录页 */ }
  }
  try {
    return routeByStatus(await api("/api/status"), presetUser);
  } catch (e) {
    markDisconnected();
    const st = await waitForStatus(8, 1500);
    if (st) return routeByStatus(st, presetUser);
    show("view-login");
    const hint = $("#login-hint");
    hint.textContent = "面板暂时连不上 (可能正在重启内核)。稍等几秒刷新本页即可, 不需要重新初始化。";
    hint.classList.remove("hidden");
  }
}

setDashRenderers(renderDash, loadDash);
