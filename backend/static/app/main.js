/** ZeroProxy 面板前端入口。
 *
 *  零构建的原生 ES 模块: index.html 只留标记, 样式分三层 (tokens / base / components),
 *  逻辑从这里进入并装配各视图。刻意不用打包器 —— 面板要在没有 Node 的服务器上直接
 *  提供服务, /static/app/*.js 由 FastAPI 的 StaticFiles 原样送出去。
 *
 *  模块划分:
 *    lib/     dom (工具 + 转义) · format (格式化) · api (含 e.dropped 语义) ·
 *             state (跨模块共享状态 + 重画钩子) · jobs (后台落地闭环) ·
 *             drafts (草稿保护) · dialog (原生 <dialog>) · render (横幅/步骤) · theme
 *    views/   dashboard (编排者) · status (节点/指标/横幅) · traffic (流量/高级/系统) ·
 *             chain (链式) · update (程序更新) · diag (诊断/修复) · audit (操作记录) · setup
 */
import { show } from "./lib/dom.js";
import { clearDraft } from "./lib/drafts.js";
import { S } from "./lib/state.js";
import { boot, renderDash, loadDash } from "./views/dashboard.js";
import { renderChain, chainCodeInfo } from "./views/chain.js";
import { renderUpdate, loadUpdate, askUpgrade, updateNeedsReload } from "./views/update.js";
import { renderDashboardBanner } from "./views/status.js";
import { showSetupHandoff } from "./views/setup.js";
// 两个只有副作用的模块 (import 即绑定各自按钮), 名字列出来是为了让 grep 找得到:
import "./lib/theme.js";     // 主题切换按钮
import "./views/diag.js";    // 一键诊断 / 一键修复 / 重新应用

/* ---------------- 回归脚本入口 ----------------
 * 页面逻辑现在是 ES 模块, 默认不污染 window。但 scripts/browser_check.cjs 会直接调用
 * 这几个函数 (模拟一次 20s 自动刷新、清草稿、重画链式卡片、走升级确认弹窗、解配对码),
 * 所以显式挂出来。这是与回归脚本的契约, 不是随手泄漏的全局 —— 新增能力时按需追加。 */
Object.assign(window, {
  renderDash, renderChain, renderUpdate, renderDashboardBanner,
  loadDash, loadUpdate, clearDraft, askUpgrade, chainCodeInfo, show, showSetupHandoff,
  updateNeedsReload,   // 「升级完成后是否要自动重新加载」的判据 (回归脚本直接验它)
});
// 这几个是被反复重新赋值的模块内变量 (每次刷新都换一个新对象, 测试还会临时改它们来
// 造"本页 JS 落后于服务器"这类场景): 必须用访问器暴露。直接挂上去的只是某一刻的快照,
// 测试随后读到的会是旧状态。
[
  ["dash", () => S.dash, (v) => { S.dash = v; }],
  ["updateInfo", () => S.updateInfo, (v) => { S.updateInfo = v; }],
  ["pageVersion", () => S.pageVersion, (v) => { S.pageVersion = v; }],
].forEach(([name, get, set]) => Object.defineProperty(window, name, { get, set, configurable: true }));

boot();
