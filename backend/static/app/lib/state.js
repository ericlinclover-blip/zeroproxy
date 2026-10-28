/** 跨模块共享的可变状态。
 *
 *  改动:
 *    1) 使用后端返回的 fingerprint 字段做智能轮询判断
 *    2) 无变化时自动拉长轮询间隔到 60s
 */
export const S = {
  dash: null,
  refreshTimer: null,
  revealed: false,
  bootstrapToken: "",
  probeData: null,
  probeRan: false,
  diagRes: null,
  updateInfo: null,
  updateTimer: null,
  updatePollFailures: 0,
  pageVersion: "",
  opBusy: 0,
  applyJobId: null,
  applyJobWait: null,
  lastApplyJob: null,
  // 智能轮询
  _lastFingerprint: "",     // 后端返回的 fingerprint
  _pollCount: 0,            // 连续无变化次数
};

export const rateHist = [];

export let redrawDash = () => {};
export let reloadDash = async () => {};
export function setDashRenderers(redraw, reload) {
  redrawDash = redraw;
  reloadDash = reload;
}

/* ---------------- 智能轮询间隔 ---------------- */
const NORMAL_INTERVAL = 20000;
const QUIET_INTERVAL  = 60000;
const BUSY_INTERVAL   = 10000;
const QUIET_THRESHOLD = 3;

/** 计算下一次轮询间隔。在 dashboard.js 的 loadDash 里调用。 */
export function pollInterval(fingerprint, isBusy) {
  if (isBusy) { S._pollCount = 0; return BUSY_INTERVAL; }

  if (fingerprint === S._lastFingerprint) {
    S._pollCount = Math.min(S._pollCount + 1, 10);
  } else {
    S._pollCount = 0;
    S._lastFingerprint = fingerprint;
  }

  if (S._pollCount >= QUIET_THRESHOLD) return QUIET_INTERVAL;
  return NORMAL_INTERVAL;
}
