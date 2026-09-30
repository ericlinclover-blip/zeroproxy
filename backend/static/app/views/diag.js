/** 一键诊断 / 一键修复 / 重新应用配置。 */
import { $, esc, toast, revealSection } from "../lib/dom.js";
import { api } from "../lib/api.js";
import { S, reloadDash } from "../lib/state.js";
import { waitPendingApply, settleApply } from "../lib/jobs.js";
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
    const res = await api("/api/diagnose");
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
  $("#diag-list").innerHTML =
    `<div class="muted fs-sm mb-1">${esc(res.summary)}</div>` +
    (res.checks || [])
      .map(
        (c) => `<div class="check">
          <span class="ico ${c.ok ? "ok" : "bad"}">${c.ok ? "✓" : "✗"}</span>
          <span class="name">${esc(c.name)}</span>
          <span class="detail">${esc(c.detail)}</span></div>`
      )
      .join("");
  $("#diag-actions").classList.toggle("hidden", !!res.ok);
  renderSidebar();
}
$("#btn-repair").onclick = async () => {
  const btn = $("#btn-repair");
  btn.disabled = true;
  btn.textContent = "修复中…";
  try {
    const res = await api("/api/repair", { method: "POST" });
    renderSteps(res.steps || [], $("#diag-list"));
    const detail = document.createElement("div");
    detail.style.marginTop = "12px";
    detail.innerHTML =
      `<div class="note">修复后复检: ${esc(res.checks ? res.checks.filter((c) => c.ok).length + "/" + res.checks.length : "—")} 项通过</div>` +
      (res.checks || [])
        .map(
          (c) => `<div class="check"><span class="ico ${c.ok ? "ok" : "bad"}">${c.ok ? "✓" : "✗"}</span>
            <span class="name">${esc(c.name)}</span><span class="detail">${esc(c.detail)}</span></div>`
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
};

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
