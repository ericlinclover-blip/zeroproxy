/** 主题切换。
 *
 *  首屏那一步不在这里 —— 它在 index.html 的 <head> 里内联执行, 因为模块脚本是
 *  deferred 的, 等它跑完页面已经画过一帧, 深色模式用户会先看到一次白闪。
 *  这里只负责"用户点按钮"这一条路径 (以及把值写回 localStorage)。 */
import { $ } from "./dom.js";

/* ---------------- 主题 ---------------- */
export function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  localStorage.setItem("zp-theme", t);
}
$("#themeBtn").onclick = () =>
  applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
