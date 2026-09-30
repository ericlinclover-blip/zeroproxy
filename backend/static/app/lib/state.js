/** 跨模块共享的可变状态。
 *
 *  单独成一层是为了打断循环依赖: 视图模块只依赖它, 彼此之间不互相 import。
 *
 *  为什么是一个对象 `S`, 而不是一堆 `export let`:
 *    读取点远多于写入点 (`dash` 就有 70+ 处读取、9 处写入)。`export let` 的实时绑定
 *    虽然能让读取处一字不改, 但每一处写入都得改成 `setXxx()` —— 而把 `x = expr`
 *    机械改写成 `setX(expr)` 需要配对括号, 是文本替换的雷区。统一 `S.x` 读写同形,
 *    一次替换即可, 且声明只有这一处。
 *
 *  注意 `dash` 这类对象是**整体替换**的 (每次 /api/dashboard 回来都换一个新对象),
 *  所以别在别处长期持有它的旧引用。
 */
export const S = {
  // --- 仪表盘数据 ---
  dash: null,             // 最近一次 /api/dashboard 的响应: 所有区块的渲染数据源
  refreshTimer: null,     // 20s 自动刷新定时器
  revealed: false,        // 入场动画只在第一次进入仪表盘时跑
  // --- 登录 / 初始化 ---
  bootstrapToken: "",     // URL 里的引导令牌 (初始化时必须带上)
  // --- 测速 / 诊断 ---
  probeData: null,        // /api/probe 的结果
  probeRan: false,        // 首次进入仪表盘自动测速只跑一次
  diagRes: null,          // 最近一次「一键诊断」结果 (侧栏角标用)
  // --- 程序更新 ---
  updateInfo: null,       // /api/update 的结果
  updateTimer: null,      // 升级进度轮询定时器 (2.5s)
  updatePollFailures: 0,  // 升级期间面板会重启: 轮询失败容忍计数
  pageVersion: "",        // 本页 JS 的版本 (与服务器不一致时提示重新加载)
  // --- 落地闭环 ---
  opBusy: 0,              // 长耗时操作计数: >0 时暂停自动刷新
  applyJobId: null,       // 正在落地的后台任务 id
  applyJobWait: null,     // 该任务结束的 Promise (并发点击排队, 而不是被丢掉)
  lastApplyJob: null,     // 最后一次任务快照 (失败原因要说给用户听)
};

/** 实时速率采样窗口 (约 8 分钟): 只 push / splice, 不整体重新赋值, 所以用常量导出。 */
export const rateHist = [];

/* ---------------- 仪表盘重画钩子 ----------------
 * `settleApply` / `syncAfterDrop` 以及好几个视图都需要"重画一次仪表盘", 而仪表盘本身
 * (views/dashboard.js) 要 import 这些模块 —— 直接互相 import 就是循环依赖, 加载顺序
 * 稍微一变就炸。所以反过来: 由 dashboard 在装配时把实现注册进来, 其余模块只调用钩子。
 * 名字里带 Dash 是为了和 views/dashboard 里的同名函数区分开 (那个才是实现)。 */
export let redrawDash = () => {};
export let reloadDash = async () => {};
export function setDashRenderers(redraw, reload) {
  redrawDash = redraw;
  reloadDash = reload;
}
