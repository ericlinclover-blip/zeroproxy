/** 弹窗层: 确认框 + 二维码。不再有 .modal-mask 的显隐开关 —— 两个 <dialog> 由
 *  浏览器托管, 这里只同步 `.hidden` 状态并处理各自的清理 (二维码不留在内存里,
 *  待确认动作不残留)。openConfirm / openQr 供其余视图调用。 */
import { $, copyText } from "./dom.js";

/* ---------------- 原生 <dialog> 开关 ----------------
 * showModal() / close() 把焦点陷阱、Esc 关闭、关闭后焦点回到原处、背景 inert 都交给浏览器,
 * 不再需要手写的 keydown 监听和 div 遮罩。
 * `.hidden` 与 [open] 双向同步: 回归脚本按 `.hidden` 断言, 同时它是 CSS 的兜底状态
 * (dialog 一旦被写成 display:grid 就盖掉了 UA 的 display:none, 靠它收口)。 */
export function openDialog(sel) {
  const el = $(sel);
  if (!el || el.open) return;
  el.classList.remove("hidden");
  el.showModal();
}
export function closeDialog(sel) {
  const el = $(sel);
  if (!el) return;
  if (el.open) el.close();
  el.classList.add("hidden");     // 同步收口, 不等 close 事件
}

/* 通用确认弹窗: 代替浏览器原生 confirm(), 好把"会做什么 / 不动什么"写清楚 */
let confirmAction = null;
export function openConfirm({ title, html, okLabel, onOk }) {
  $("#confirm-title").textContent = title;
  $("#confirm-body").innerHTML = html;
  $("#confirm-ok").textContent = okLabel || "确定";
  confirmAction = onOk;
  openDialog("#confirm-mask");
}
export function closeConfirm() {
  closeDialog("#confirm-mask");
  confirmAction = null;
}
$("#confirm-cancel").onclick = closeConfirm;
$("#confirm-ok").onclick = async () => {
  const fn = confirmAction;
  closeConfirm();
  if (fn) await fn();
};

/* ---------------- 二维码弹窗 ----------------
 * 以前的弹窗把整条 vless:// 链接当副标题铺在卡片里: 长链接不换行, 直接顶出卡片
 * 右边被裁掉, 位图二维码被缩到 260px 又糊成一团。现在: 标题下只放一句人话摘要,
 * 二维码走 SVG (无级缩放), 完整链接单独一行截断显示 + 一键复制, 另配保存 PNG。 */
export const SUB_FMT_LABEL = { base64: "Base64", clash: "Clash", singbox: "sing-box" };
let qrState = { link: "", png: "", file: "" };

export function openQr({ title, sub, link, svg, png, file }) {
  $("#qr-title").textContent = title;
  $("#qr-sub").textContent = sub || "手机 App 扫码导入";
  $("#qr-img").src = svg;
  $("#qr-link").textContent = link;
  $("#qr-link").title = link;
  qrState = { link, png, file: file || "zeroproxy-qr.png" };
  openDialog("#qr-mask");
}

export function closeQr() {
  closeDialog("#qr-mask");
  $("#qr-img").removeAttribute("src");   // 关闭后别把二维码留在内存里
}

$("#qr-copy").onclick = () => copyText(qrState.link);
$("#qr-save").onclick = () => {
  const a = document.createElement("a");
  a.href = qrState.png;
  a.download = qrState.file;
  document.body.appendChild(a);
  a.click();
  a.remove();
};
$("#qr-close").onclick = closeQr;

/* 两个弹窗共用的收尾: Esc / 点遮罩 / close() 都会触发 close 事件 —— 统一把 .hidden
 * 补回去并做各自的清理 (二维码不留在内存里, 待确认动作不残留)。原来这两件事各由一段
 * 全局 keydown + 一段遮罩 onclick 完成, 现在浏览器负责 Esc 与遮罩, 只留这一处。 */
[["#qr-mask", () => $("#qr-img").removeAttribute("src")],
 ["#confirm-mask", () => { confirmAction = null; }]].forEach(([sel, cleanup]) => {
  const el = $(sel);
  // cancel 在 Esc 的按键处理里同步触发, close 是随后排队的一个任务 —— 两个都挂上:
  // 前者保证"按下 Esc 的那一刻状态就已经对", 后者覆盖 close() 与点遮罩。
  el.addEventListener("cancel", () => { el.classList.add("hidden"); cleanup(); });
  el.addEventListener("close", () => { el.classList.add("hidden"); cleanup(); });
  el.addEventListener("click", (e) => { if (e.target === el) el.close(); });   // 点遮罩 = 关闭
});
