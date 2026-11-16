/** 一键诊断 / 一键修复 / 重新应用配置。 */
import { $, esc, toast, revealSection } from "../lib/dom.js";
import { openConfirm } from "../lib/dialog.js";
import { api } from "../lib/api.js";
import { S, reloadDash } from "../lib/state.js";
import { waitPendingApply, settleApply, assertApplyResult } from "../lib/jobs.js";
import { renderSteps } from "../lib/render.js";
import { renderSidebar } from "./status.js";

/* ---------------- 诊断 / 修复 ---------------- */
$("#btn-diag").onclick = async () => {
  const btn = $("#btn-diag");
  btn.disabled = true;
  btn.textContent = "诊断中…";
  // 结果落在下方「诊断」卡片里: 先把用户带过去, 再放一句"正在跑"的占位 ——
  // 否则他只会看到按钮文字变了一下, 还得自己翻下去才知道发生了什么。
  revealSection("#diag-card");
  $("#diag-list").innerHTML =
    '<div class="note">正在检查服务状态 / 配置合法性 / 证书 / 端口 / 链式落地端…</div>';
  try {
    const res = await api("/api/diagnose", { timeoutMs: 90000 });
    renderChecks(res);
  } catch (e) {
    toast("诊断失败: " + e.message);
    $("#diag-list").innerHTML = "";
  }
  btn.disabled = false;
  btn.textContent = "一键诊断";
};
export function renderChecks(res) {
  S.diagRes = res;
  $("#btn-restore-runtime").disabled = !S.dash?.runtime?.can_restore;
  $("#diag-list").innerHTML =
    `<div class="muted fs-sm mb-1">${esc(res.summary)} · 面板服务器检查</div><p class="note">设备 → DNS → 路由器接管需在设备端验证；以下只检查服务器入口、配置与链式落地。目标网站可另行运行端点检查。</p>` +
    (res.checks || [])
      .map(
        (c) => `<div class="check">
          <span class="ico ${c.ok ? "ok" : "bad"}">${c.ok ? "✓" : "✗"}</span>
          <span class="name">${esc(c.name)}</span>
          <span class="detail">${esc(c.detail)}${!c.ok ? `<br><b>下一步：</b>${esc(c.next_step || (c.fixable ? "预览修复计划，执行后复检" : "检查对应网络或服务后重新诊断"))}` : ""}</span></div>`
      )
      .join("");
  $("#diag-actions").classList.toggle("hidden", !!res.ok);
  renderSidebar();
}
$("#btn-repair").onclick = () => openConfirm({
  title: "确认修复计划", okLabel: "执行并复检",
  html: "将按当前期望配置重新生成并校验 Xray、Hysteria、nginx 与启用的 WireGuard 配置，重载有变化的服务，再运行诊断。可能短暂中断代理连接；不会主动轮换账号或节点凭据。DNS、设备接管和目标服务问题可能仍需分别处理。",
  onOk: runRepair,
});
async function runRepair() {
  const btn = $("#btn-repair");
  btn.disabled = true;
  btn.textContent = "修复中…";
  try {
    const res = await api("/api/repair", { method: "POST", timeoutMs: 240000 });
    assertApplyResult(res);
    renderSteps(res.steps || [], $("#diag-list"));
    const detail = document.createElement("div");
    detail.style.marginTop = "12px";
    detail.innerHTML =
      `<div class="note">修复后复检: ${esc(res.checks ? res.checks.filter((c) => c.ok).length + "/" + res.checks.length : "—")} 项通过</div>` +
      (res.checks || [])
        .map(
          (c) => `<div class="check"><span class="ico ${c.ok ? "ok" : "bad"}">${c.ok ? "✓" : "✗"}</span>
            <span class="name">${esc(c.name)}</span><span class="detail">${esc(c.detail)}${!c.ok ? `<br><b>下一步：</b>${esc(c.next_step || (c.fixable ? "预览修复计划，执行后复检" : "检查对应网络或服务后重新诊断"))}` : ""}</span></div>`
        )
        .join("");
    $("#diag-list").appendChild(detail);
    $("#diag-actions").classList.add("hidden");
    toast(res.ok ? "修复完成, 全部检查通过" : "已重新生成配置, 仍有项目需要人工检查");
    reloadDash(true);
  } catch (e) {
    toast("修复失败: " + e.message);
  }
  btn.disabled = false;
  btn.textContent = "一键修复 (重新生成 + 重启)";
}

$("#btn-export-diag").onclick = () => {
  if (!S.diagRes) return toast("请先运行诊断");
  // Explicit allowlist: never export raw dashboard, check details, hostnames,
  // share links, credentials or backend exception text.
  const payload = { format: "zeroproxy-diagnostic-summary", checked_at: new Date().toISOString(),
    version: S.pageVersion || "unknown", scope: "server-checks",
    counts: { total: (S.diagRes.checks || []).length, passed: (S.diagRes.checks || []).filter((c) => c.ok).length },
    checks: (S.diagRes.checks || []).map((c, index) => ({ index: index + 1, stage: c.stage || "server", passed: !!c.ok, fixable: !!c.fixable })),
    boundaries: ["device-egress-unverified", "device-dns-unverified"] };
  const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }));
  const a = document.createElement("a"); a.href = url; a.download = "zeroproxy-diagnostic-summary.json"; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
};
$("#btn-restore-runtime").onclick = () => openConfirm({
  title: "恢复最近成功配置？", okLabel: "恢复并验证",
  html: "将恢复最近一次完整应用成功的服务器配置并重载服务，可能中断连接。管理员、会话和设备登记会保留；设备授权仍以当前登记为准。",
  onOk: async () => {
    await waitPendingApply();
    try {
      await settleApply(await api("/api/apply/rollback", { method: "POST", timeoutMs: 240000 }));
      toast("最近成功配置已恢复并验证");
    } catch (e) { toast("恢复未完成: " + e.message); }
  },
});

/* ---------------- 重新应用 ---------------- */
$("#btn-apply").onclick = async () => {
  const btn = $("#btn-apply");
  await waitPendingApply();
  btn.disabled = true; btn.textContent = "应用中…";
  try {
    const steps = await settleApply(await api("/api/apply", { method: "POST" }));
    const failed = steps.filter((s) => !s.ok);
    toast(failed.length ? `已重载, 但 ${failed.length} 步失败: ${failed[0].name}` : "配置已重新生成并热重载");
  } catch (e) { toast("应用失败: " + e.message); }
  btn.disabled = false; btn.textContent = "重新应用配置";
};

/* ---------------- AI / 流媒体解锁与出口纯净度检测 ---------------- */
const unlockBtn = $("#btn-unlock-probe");
if (unlockBtn) {
  unlockBtn.onclick = async () => {
    unlockBtn.disabled = true;
    unlockBtn.textContent = "检测中…";
    $("#unlock-summary").textContent = "正在从面板服务器直连检查目标端点；不验证设备当前路线…";
    try {
      const res = await api("/api/probe/unlock?force=1");
      renderUnlock(res);
      toast(res.summary || "检测完成");
    } catch (e) {
      toast("检测失败: " + e.message);
      $("#unlock-summary").textContent = "检测失败: " + e.message;
    } finally {
      unlockBtn.disabled = false;
      unlockBtn.textContent = "刷新检测";
    }
  };
}

export function renderUnlock(res) {
  if (!res) return;
  const summaryEl = $("#unlock-summary");
  if (summaryEl) {
    summaryEl.textContent = `${res.summary || "检测完成"} · 服务器直连 IP: ${res.ip || "—"} · ${res.checked_at ? new Date(res.checked_at * 1000).toLocaleString("zh-CN") : "检查时间未知"}`;
  }
  const grid = $("#unlock-grid");
  if (!grid) return;
  const items = res.items || [];
  grid.innerHTML = items
    .map(
      (item) => `
        <div class="mini-card">
          <div class="row-between mb-1">
            <span class="fs-sm fw-bold">${esc(item.name)}</span>
            <span class="pill ${item.status === "reachable" ? "ok" : item.status === "restricted" ? "bad" : "warn"}">${esc(({ reachable: "端点可达", auth_required: "需要身份验证", restricted: "访问被拒绝", rate_limited: "受到限流", error: "目标错误" })[item.status] || "结果未知")}</span>
          </div>
          <div class="muted fs-xs">${esc(item.detail)}</div>
          <div class="muted fs-xs mt-2">${esc(item.target || "目标未提供")} · 面板服务器直连</div>
        </div>
      `
    )
    .join("");
}

