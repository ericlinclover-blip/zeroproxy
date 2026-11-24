//: 改配置会重启 xray / hysteria2。如果这个浏览器正好是"走本机这条链路"上网的
//: (很常见: 装完就用自己的节点), 重启会把自己那条隧道一起断掉 —— 请求以"连接中断"
//: 告终, 但面板其实已经把活干完了。所以两类失败必须分开:
//:   业务失败 → 有 HTTP 状态码 + 中文 error, 照实报给用户;
//:   连接中断 → fetch 抛错 / 502 / 504, 属于"重启内核的副作用", 该自动重连。
export async function api(path, opts = {}) {
  if (opts.method && opts.method.toUpperCase() !== "GET") S.dashEpoch += 1;
  const longWrite = opts.method && opts.method !== "GET" && /^\/api\/(wireguard|renew|repair)/.test(path);
  const { timeoutMs = longWrite ? 240000 : 30000, signal, ...options } = opts;
  if (path === "/api/settings" && typeof options.body === "string" && S.dash?.configuration_revision) {
    const payload = JSON.parse(options.body);
    options.body = JSON.stringify({ expected_revision: S.dash.configuration_revision, expected_settings_revision: S.dash.settings_revision, ...payload });
  }
  let operation;
  if (options.method && ["POST", "DELETE"].includes(options.method.toUpperCase()) &&
      (/^\/api\/nodes\/[^/]+\/(enabled|toggle)$/.test(path) || path === "/api/hysteria/hopping" ||
       path === "/api/chain/exit" || /^\/api\/chain\/entries(?:\/[^/]+(?:\/pair)?)?$/.test(path) ||
       path === "/api/wireguard/settings" || /^\/api\/wireguard\/peers(?:\/[^/]+(?:\/rotate)?)?$/.test(path))) {
    options.headers = new Headers(options.headers || {});
    options.headers.set("X-ZP-Confirm", "90");
    operation = Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) => byte.toString(16).padStart(2, "0")).join("");
    options.headers.set("X-ZP-Operation", operation);
    if (S.dash?.configuration_revision) options.headers.set("X-ZP-Revision", S.dash.configuration_revision);
  }
  const controller = new AbortController();
  const abort = () => controller.abort();
  if (signal?.aborted) abort();
  signal?.addEventListener("abort", abort, { once: true });
  const timer = setTimeout(abort, timeoutMs);
  try {
    const res = await fetch(path, { credentials: "same-origin", ...options, signal: controller.signal });
    const body = await res.json().catch((err) => {
      if (controller.signal.aborted) throw err;
      return null;
    });
    if (!res.ok) {
      const e = new Error(body?.error || `HTTP ${res.status}`);
      e.status = res.status;
      e.dropped = res.status === 502 || res.status === 504;
      e.body = body || {};
      e.operation = operation;
      throw e;
    }
    if (body === null) throw new Error("面板返回了无法解析的内容");
    return body;
  } catch (err) {
    if (err.status || (err instanceof Error && !controller.signal.aborted && err.message === "面板返回了无法解析的内容")) throw err;
    const e = new Error(controller.signal.aborted ? "请求超时或已取消，操作结果待确认" : "与面板的连接中断，操作结果待确认");
    e.dropped = true;
    e.unknown = true;
    e.operation = operation;
    throw e;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", abort);
  }
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

/** Reconnect and refresh observations. Only an operation-specific predicate
 * may confirm success; changed telemetry is never evidence of completion. */
export async function syncAfterDrop(verify, tries = 10, delay = 1200) {
  let latest;
  let matched = false;
  for (let i = 0; i < tries; i++) {
    await sleep(delay);
    const epoch = S.dashEpoch;
    let dash;
    try {
      dash = await api("/api/dashboard", { timeoutMs: 3000 });
    } catch (e) {
      if (e.status === 401) return null;
      continue;
    }
    if (epoch !== S.dashEpoch) continue;
    latest = { dash, epoch };
    matched = typeof verify === "function" && verify(dash);
    if (matched || typeof verify !== "function") break;
  }
  if (!latest) {
    markDisconnected("连接中断 — 稍后会自动重试, 期间状态可能不是最新的");
    return null;
  }
  if (latest.epoch !== S.dashEpoch) return false;
  S.dash = latest.dash;
  redrawDash(true);
  show("view-dash");
  return matched;
}
