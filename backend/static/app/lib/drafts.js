/* ---------------- 重渲染时的"草稿保护" ----------------
 * 仪表盘每 20s 自动刷新一次, 而刷新是整块重画 DOM 的 (节点表 / 高级设置 /
 * 链式代理全是 innerHTML)。没有这层保护时, 用户正在填的 SNI、端口、配对码
 * 会在下一次刷新被服务器值覆盖 —— 填到一半的内容几分钟后自己变回去。
 * 这里在重渲染前把"正在编辑的输入"记下来, 重渲染后原样放回 (含光标位置),
 * 直到用户提交为止。 */
const DRAFT_KEY_ATTRS = ["data-port-node", "data-node", "data-chain-toggle"];

export function inputKey(el) {
  if (el.id) return "#" + el.id;
  for (const attr of DRAFT_KEY_ATTRS) {
    const value = el.getAttribute(attr);
    if (value) return `[${attr}="${value}"]`;
  }
  return "";
}

//: 只保护"打字"类控件: 开关 / 勾选框是即时生效的, 交给服务器状态回灌才不会
//: 出现"界面显示开着、后端其实没开"。
export function isDraftInput(el) {
  if (el.tagName === "TEXTAREA") return true;
  return ["text", "number", "url", "search", "tel", "email", "password"].includes(el.type);
}

export function snapshotDraftInputs() {
  const drafts = [];
  document.querySelectorAll("#view-dash input, #view-dash textarea").forEach((el) => {
    if (!isDraftInput(el)) return;
    const focused = document.activeElement === el;
    if (!focused && el.dataset.draft !== "1") return;
    const key = inputKey(el);
    if (!key) return;
    let start = null, end = null;
    try { start = el.selectionStart; end = el.selectionEnd; } catch (e) { /* 不支持选区的类型 */ }
    drafts.push({ key, value: el.value, focused, start, end });
  });
  return drafts;
}

export function restoreDraftInputs(drafts) {
  drafts.forEach((d) => {
    const el = document.querySelector(d.key);
    if (!el || !isDraftInput(el)) return;
    if (el.value !== d.value) el.value = d.value;
    el.dataset.draft = "1";          // 还没提交 → 下次刷新继续保护
    if (d.focused) {
      el.focus();
      try { if (d.start != null) el.setSelectionRange(d.start, d.end); } catch (e) { /* 忽略 */ }
    }
  });
}

document.addEventListener("input", (e) => {
  const el = e.target;
  if (el && el.dataset && isDraftInput(el)) el.dataset.draft = "1";
});

//: 提交成功后放行: 之后服务器值可以直接回灌 (含后端做的规范化, 如 SNI 转小写)
export function clearDraft(selector) {
  document.querySelectorAll(selector).forEach((el) => delete el.dataset.draft);
}
