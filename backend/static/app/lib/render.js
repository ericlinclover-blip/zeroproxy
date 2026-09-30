/** 通用渲染片段: 告警横幅 + 步骤清单。
 *
 *  两者都被多处使用 (横幅给仪表盘, 步骤清单给初始化 / 一键修复 / 升级链路),
 *  所以放在 lib 而不是某个视图里; 只依赖 dom 的转义工具。
 */
import { $, esc, escAttr } from "./dom.js";

export function renderBanner(el, kind, title, detail, action) {
  if (!el) return;
  if (!title) { el.classList.add("hidden"); el.innerHTML = ""; return; }
  el.innerHTML = `<div class="banner ${kind}">
      <span class="ico">${kind === "bad" ? "✗" : kind === "good" ? "✓" : "i"}</span>
      <span><b>${esc(title)}</b>${detail ? `<br><span class="muted">${esc(detail)}</span>` : ""}${
        action
          ? `<br><a class="btn ghost small banner-link" href="${escAttr(action.href)}">${esc(action.label)}</a>`
          : ""
      }</span>
    </div>`;
  el.classList.remove("hidden");
}

export function renderSteps(steps, container) {
  (container || $("#setup-progress")).innerHTML = steps
    .map(
      (s) => `<div class="pstep">
        <span class="ico ${s.ok ? "ok" : "bad"}">${s.ok ? "✓" : "✗"}</span>
        <span>${esc(s.name)} <span class="muted">(${s.ms}ms)</span></span>
        <div class="detail">${esc(s.detail || "")}</div></div>`
    )
    .join("");
}
