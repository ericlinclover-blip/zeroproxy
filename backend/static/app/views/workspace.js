/** Workspaces keep existing forms mounted, so navigation never destroys drafts. */
import { $, esc, escAttr } from "../lib/dom.js";
import { openDialog, closeDialog } from "../lib/dialog.js";
import { S } from "../lib/state.js";

const WORKSPACES = {
  network: { title: "你的连接，尽在此处。", description: "从入口到出口，沿着路径管理你的网络。", ids: ["connection-field", "sec-nodes", "sec-traffic", "chain-intro"] },
  devices: { title: "让每台设备，就位。", description: "接入设备、导入订阅，核对实际应用状态。", ids: ["sec-clients", "sec-subs", "sec-wireguard"] },
  routing: { title: "每一程，都有方向。", description: "调整分流与防护，保存后核对配置应用结果。", ids: ["sec-adv"] },
  diagnostics: { title: "找到连接的断点。", description: "服务状态、深度握手与出口检测，分别提供证据。", ids: ["diag-card", "unlock-card"] },
  maintenance: { title: "照顾网络的每一天。", description: "管理系统、账号、备份、操作记录与更新。", ids: ["sec-sys", "sec-panel", "sec-audit", "update-card"] },
};
let current = "network";
let initialized = false;

export function activateWorkspace(key, focus = false) {
  if (!WORKSPACES[key]) key = "network";
  current = key;
  const group = WORKSPACES[key];
  Object.entries(WORKSPACES).forEach(([name, value]) => value.ids.forEach((id) => {
    $("#" + id)?.classList.toggle("workspace-hidden", name !== key);
  }));
  $(".kpi")?.classList.toggle("workspace-hidden", key !== "network");
  document.querySelectorAll("[data-workspace]").forEach((a) => {
    const on = a.dataset.workspace === key;
    a.classList.toggle("on", on);
    if (on) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  });
  $("#workspace-title").textContent = group.title;
  $("#workspace-description").textContent = group.description;
  document.title = `ZeroProxy · ${{ network: "网络", devices: "设备", routing: "分流", diagnostics: "诊断", maintenance: "维护" }[key]}`;
  if (focus) $("#workspace-title").focus({ preventScroll: true });
}

export function revealWorkspaceFor(el) {
  const section = el?.closest(".main > section");
  if (!section) return;
  const key = Object.keys(WORKSPACES).find((key) => WORKSPACES[key].ids.includes(section.id));
  if (key && key !== current) activateWorkspace(key);
}

export function initWorkspace() {
  if (initialized) return;
  initialized = true;
  const target = document.getElementById(location.hash.slice(1));
  activateWorkspace("network");
  if (target) revealWorkspaceFor(target);
  // Event delegation also covers anchors emitted by the existing renderers.
  document.addEventListener("click", (event) => {
    const a = event.target.closest('a[href^="#"]');
    if (!a || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.button !== 0) return;
    const target = document.getElementById(a.hash.slice(1));
    if (!target || !target.closest(".main")) return;
    event.preventDefault();
    revealWorkspaceFor(target);
    if (a.dataset.workspace) {
      activateWorkspace(a.dataset.workspace, true);
      window.scrollTo({ top: 0, behavior: "auto" });
    } else {
      target.scrollIntoView({ behavior: "auto", block: "start" });
      const heading = target.querySelector("h2");
      if (heading) { heading.tabIndex = -1; heading.focus({ preventScroll: true }); }
    }
    history.replaceState(null, "", a.hash);
  });
  window.addEventListener("hashchange", () => {
    const target = document.getElementById(location.hash.slice(1));
    if (target) { revealWorkspaceFor(target); target.scrollIntoView({ block: "start" }); }
  });
  document.addEventListener("zp:reveal-section", (event) => revealWorkspaceFor(event.detail));
  $("#btn-find").onclick = () => {
    $("#find-input").value = "";
    renderFind(); openDialog("#find-mask"); $("#find-input").focus();
  };
  $("#find-close").onclick = () => closeDialog("#find-mask");
  $("#find-input").oninput = renderFind;
  document.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k" && !$("#view-dash").classList.contains("hidden") && !document.querySelector("dialog[open]")) {
      event.preventDefault(); $("#btn-find").click();
    }
  });
}

function renderFind() {
  const entries = [
    ["connection-field", "网络 · 连接路径"], ["sec-nodes", "节点 · 分享与启停"],
    ["chain-intro", "链式代理 · 落地与默认出口"], ["sec-clients", "设备 · 路由器、手机、电脑"],
    ["sec-subs", "订阅 · Clash / sing-box"], ["sec-wireguard", "WireGuard / AWG"],
    ["sec-traffic", "流量统计"], ["sec-adv", "分流 · 高级设置 · 广告防护"],
    ["diag-card", "一键诊断与修复"], ["unlock-card", "出口质量与解锁检测"],
    ["sec-sys", "系统 · 备份与恢复"], ["sec-panel", "面板设置 · 管理员与域名"],
    ["sec-audit", "操作记录"], ["update-card", "程序更新"],
    ...(S.dash?.nodes || []).map((n) => ["sec-nodes", n.name]),
    ...((S.dash?.chain || {}).entries || []).map((e) => ["chain-intro", e.label || e.host]),
  ];
  const q = $("#find-input").value.trim().toLowerCase();
  const hits = entries.filter(([, name]) => String(name).toLowerCase().includes(q));
  $("#find-results").innerHTML = hits.length ? hits.map(([id, name]) => `<a href="#${escAttr(id)}">${esc(name)}<span aria-hidden="true">↗</span></a>`).join("") : '<p class="muted">没有找到，试试“设备”或“分流”。</p>';
  $("#find-results").querySelectorAll("a").forEach((a) => a.addEventListener("click", () => closeDialog("#find-mask")));
}
