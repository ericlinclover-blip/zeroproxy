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

/** 节点自己的状态 (看的是"这个协议现在能不能用", 不是"服务在不在跑")。
 *
 *  以前两者混为一谈: 灯的颜色直接取 `service_state`, 于是把某个协议的节点开关
 *  关掉之后, Xray 照样在跑 → 灯还是绿的, 顶部"健康节点"那排点也还是绿的。用户
 *  按灯判断就会以为它还活着 —— 而那个端口其实早就没人监听了。
 *  关掉的节点一律灰 (off), 启用中的才按服务状态给绿/红/黄。 */
export function nodeStateClass(n) {
  if (!n || n.enabled === false) return "off";
  if (["failed", "err", "inactive", "not-installed"].includes(n.service_state)) return "failed";
  return ["active", "running"].includes(n.service_state) ? "running" : "other";
}

export function nodeStateText(n) {
  if (!n || n.enabled === false) return "已停用";
  return STATE_TXT[n.service_state] || n.service_state || "未知";
}
