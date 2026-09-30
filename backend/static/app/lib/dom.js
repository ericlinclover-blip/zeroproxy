/** 基础 DOM / 文案工具 —— 无依赖, 其余模块都从这里取。
 *  `$` 只做 querySelector; `esc`/`escAttr` 是模板串里唯一的转义出口
 *  (所有 innerHTML 模板都必须经过它, 这是这个项目的前端 XSS 边界)。 */
export const $ = (s) => document.querySelector(s);
export const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
export const escAttr = esc;

export function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(t._h);
  t._h = setTimeout(() => t.classList.remove("show"), 2400);
}

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast("已复制");
  } catch (e) {
    const ta = document.createElement("textarea");
    ta.value = text; document.body.appendChild(ta);
    ta.select(); document.execCommand("copy"); ta.remove();
    toast("已复制");
  }
}

/* ---------------- 视图路由 ---------------- */
export function show(id) {
  ["view-setup", "view-login", "view-dash"].forEach((v) => $("#" + v).classList.add("hidden"));
  $("#" + id).classList.remove("hidden");
}

/** 把某个板块滚到眼前, 并短暂高亮一下。
 *
 *  头部的「一键诊断」「检查更新」结果都落在下方卡片里 —— 不滚过去的话, 用户只看到
 *  按钮文字变了一下, 得自己翻找。这一步替他带路。
 *  已经完整可见的板块不动页面 (例如卡片自己的按钮触发时), 只高亮, 免得白跳一下。
 *  平滑滚动尊重 prefers-reduced-motion —— 该媒体查询管不到 behavior:"smooth"。 */
export function revealSection(sel) {
  const el = typeof sel === "string" ? document.querySelector(sel) : sel;
  if (!el) return;
  const box = el.getBoundingClientRect();
  const fullyVisible = box.top >= 0 && box.bottom <= window.innerHeight;
  if (!fullyVisible) {
    el.scrollIntoView({
      behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
      block: "start",
    });
  }
  el.classList.remove("flash");
  void el.offsetWidth;          // 强制重排, 让动画被连续触发时也能重放
  el.classList.add("flash");
  setTimeout(() => el.classList.remove("flash"), 1500);
}
