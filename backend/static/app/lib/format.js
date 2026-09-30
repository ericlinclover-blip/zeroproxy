/** 展示用的格式化: 字节 / 时长 / 时间 / 服务状态文案。
 *  纯函数, 不碰 DOM, 所以可以单独测试, 也不怕在渲染之外被复用。 */
/** 协议 → 徽标配色类名 (节点卡片用)。 */
export const PROTO_BADGE = { VLESS: "vless", Trojan: "trojan", "Hysteria 2": "hysteria" };

export const fmtBytes = (n) => {
  n = Number(n) || 0;
  if (n < 1024) return n + " B";
  const units = ["KB", "MB", "GB", "TB", "PB"];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < units.length - 1);
  return n.toFixed(n >= 100 ? 0 : 1) + " " + units[i];
};
export const fmtUptime = (s) => {
  if (!s) return "—";
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return d ? `${d}天 ${h}小时` : h ? `${h}小时 ${m}分` : `${m}分钟`;
};
export const fmtTime = (ts) => (ts ? new Date(ts * 1000).toLocaleString("zh-CN", { hour12: false }) : "—");
export const STATE_TXT = { active: "运行中", running: "运行中", "dry-run": "本地开发", "not-installed": "未安装", failed: "异常", inactive: "已停止" };
export const stateClass = (s) => (["active", "running"].includes(s) ? "running" : ["failed", "err"].includes(s) ? "failed" : "other");
