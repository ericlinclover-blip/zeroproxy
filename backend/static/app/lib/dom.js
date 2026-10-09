/** 基础 DOM / 文案工具 —— 无依赖, 其余模块都从这里取。
 *  `$` 只做 querySelector; `esc`/`escAttr` 是模板串里唯一的转义出口
 *  (所有 innerHTML 模板都必须经过它, 这是这个项目的前端 XSS 边界)。 */
export const $ = (s) => document.querySelector(s);
export const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
export const escAttr = esc;

/** 把模板里的 `data-w` / `data-bg` 落成真实样式 (CSSOM)。
 *
 *  为什么不能直接写 `style="width:42%"`: 面板的 `style-src` 已经不再放行
 *  `unsafe-inline`, 模板里的内联 style **会被浏览器拦掉** —— 而失败方式是安静的:
 *  进度条 / 流量条只会停在 CSS 默认的 `width:0` 上, 页面上看不出报错, 得开控制台
 *  才知道。所以宽度与数据驱动的底色改走 CSSOM: 模板只写字面量 (data-w / data-bg),
 *  插入文档后由这里逐个赋值 —— `el.style.*` 是脚本操作样式对象, 不受 style-src 管。
 *
 *  传进来的 root 必须**已经在文档里**, 否则 querySelectorAll 找不到那些条子, 它们
 *  会永远停在 0 宽。 */
export function applyWidths(root) {
  if (!root) return;
  root.querySelectorAll("[data-w]").forEach((el) => {
    el.style.width = el.dataset.w + "%";
    if (el.dataset.bg) el.style.setProperty("background", el.dataset.bg);
  });
}

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
