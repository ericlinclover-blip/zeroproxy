//: 改配置会重启 xray / hysteria2。如果这个浏览器正好是"走本机这条链路"上网的
//: (很常见: 装完就用自己的节点), 重启会把自己那条隧道一起断掉 —— 请求以"连接中断"
//: 告终, 但面板其实已经把活干完了。所以两类失败必须分开:
//:   业务失败 → 有 HTTP 状态码 + 中文 error, 照实报给用户;
//:   连接中断 → fetch 抛错 / 502 / 504, 属于"重启内核的副作用", 该自动重连。
export async function api(path, opts = {}) {
  let res;
  try {
    res = await fetch(path, { credentials: "same-origin", ...opts });
  } catch (err) {
    const e = new Error("与面板的连接中断 (重启内核时会短暂断开)");
    e.dropped = true;
    throw e;
  }
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    const e = new Error((body && body.error) || `HTTP ${res.status}`);
    e.status = res.status;
    // 502/504 = 上游(面板)正在重启, 和"网络断了"同样处理
    e.dropped = res.status === 502 || res.status === 504;
    e.body = body || {};
    throw e;
  }
  if (body === null) throw new Error("面板返回了无法解析的内容");
  return body;
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
/** 面板 API 客户端。
 *
 *  这里最重要的不是 fetch, 而是把两类失败分开 —— 面板重启内核时会掐断"走本机链路
 *  上网"的浏览器(很常见: 装完就用自己的节点访问面板), 那种连接中断不是业务失败,
 *  调用方据此走"重连并核对真实状态"而不是弹错误。凡是 502/504 与 fetch 抛错,
 *  一律带上 `e.dropped = true`; 带 HTTP 状态码 + 中文 error 的才是真失败。
 */
import { $, show } from "./dom.js";
import { S, redrawDash } from "./state.js";

/** 面板重启时自己的连接是先断再通的: 轮询 /api/status 直到拿到答复。
 *  返回 true=在线且已登录, false=在线但登录已失效, null=一直连不上 (纯网络问题)。 */
export async function sessionState(tries = 6, delay = 1200) {
  for (let i = 0; i < tries; i++) {
    try {
      const st = await api("/api/status");   // 只有 200 会走到这里
      return !!st.authenticated;
    } catch (e) { /* 还没回来 / 面板 5xx: 继续等, 不当成"掉登录" */ }
    if (i < tries - 1) await sleep(delay);
  }
  return null;
}

/** 重连期间的状态提示: 复用顶部那颗状态药丸, 不整页重画 (草稿与按钮状态都还在)。 */
export function markDisconnected(msg) {
  const st = $("#dash-state");
  if (!st) return;
  st.className = "pill warn";
  st.innerHTML = `<span class="dot other"></span>${msg || "连接中断, 正在重连…"}`;
}

/** 重启内核会掐断"走本机链路上网"的浏览器请求 —— 但面板那边已经把活干完了。
 *  这里等连接回来、用 /api/dashboard 对齐真实状态, 并回答"界面变了没有":
 *  true=变了 (操作确实生效), false=没变 (没生效/本就是空操作), null=一直没连上。 */
export async function syncAfterDrop(before, tries = 10, delay = 1200) {
  for (let i = 0; i < tries; i++) {
    await sleep(delay);
    try {
      S.dash = await api("/api/dashboard");
      redrawDash(true);
      show("view-dash");
      return JSON.stringify(S.dash) !== before;
    } catch (e) { /* 隧道/面板还没回来, 继续等 */ }
  }
  markDisconnected("连接中断 — 稍后会自动重试, 期间状态可能不是最新的");
  return null;
}
