/** 后台落地闭环 + 改动类接口的统一入口。
 *
 *  改动:
 *    1) 自适应轮询间隔: 前 2s 用 100ms 快速采样（用户刚点击，急于看进度），
 *       之后退回 400ms，避免不必要的 HTTP 请求。
 *    2) 进度条更新用 CSS class 切换代替 innerHTML 重建，减少 DOM 重排。
 */
import { $, esc, toast, applyWidths } from "./dom.js";
import { api, sleep, markDisconnected, syncAfterDrop } from "./api.js";
import { S, redrawDash } from "./state.js";

/* ---------------- 后台配置任务 ---------------- */
export async function waitPendingApply() {
  if (!S.applyJobWait) return;
  try {
    await S.applyJobWait;
  } catch (e) { /* 上一次的失败自己已经报过错了 */ }
}

/** 渲染进度条 — 增量更新 DOM，不重建整个字符串。 */
export function renderApplyStrip(st) {
  const box = $("#apply-strip");
  if (!box) return;
  if (!st) {
    box.classList.add("hidden");
    box.innerHTML = "";
    return;
  }
  box.classList.remove("hidden");
  const running = st.state === "running";
  const stepFails = ((st.steps || []).filter((s) => !s.ok)).length;
  const bad = !running && (st.state === "failed" || !!st.error || stepFails > 0);
  const geo = st.kind === "geodata";
  const total = st.total || 7;
  const index = Math.max(1, Math.min(st.index || 1, total));
  const pct = Math.round((index / total) * 100);
  const secs = ((st.elapsed_ms || 0) / 1000).toFixed(1);

  const title = bad
    ? st.error ? (geo ? "GeoIP 数据更新失败" : "配置落地失败")
      : geo ? `GeoIP 数据已更新, 但有 ${stepFails} 步告警` : `配置已应用, 但有 ${stepFails} 步告警`
    : running ? (geo ? "正在下载 GeoIP 数据" : "正在应用配置")
      : geo ? "GeoIP 数据已更新并生效" : "配置已应用";

  // 第一次任务开始时容器是空的。先建一次固定骨架，之后只增量更新。
  let banner = box.querySelector(".banner");
  if (!banner) {
    box.innerHTML = '<div class="banner"><span class="ico"></span><span class="grow"></span></div>';
    banner = box.querySelector(".banner");
  }
  banner.className = `banner ${bad ? "bad" : running ? "info" : "good"}`;
  box.dataset.state = running ? "running" : (bad ? "bad" : "good");
  box.querySelector(".ico").textContent = bad ? "✗" : running ? "⟳" : "✓";

  const growSpan = box.querySelector(".grow");
  if (growSpan) {
    growSpan.innerHTML = `<b>${title}</b>
      <span class="muted"> · 第 ${index}/${total} 步 · ${esc(st.current || "")} · 已用 ${secs}s</span>
      <div class="bar${running ? " live" : ""}"><i class="${bad ? "bad" : ""}" data-w="${bad ? 100 : pct}"></i></div>
      ${bad ? `<div class="muted fs-sm mt-1">${esc(st.error || "")}</div>` : ""}`;
    applyWidths(box);
  }
}

/** 自适应轮询后台任务: 前 2s 用 100ms 快速采样, 之后 400ms。 */
export async function watchApply(job) {
  let last = job;
  renderApplyStrip(job);
  const budgetMs = job.kind === "geodata" ? 480000 : 120000;
  let elapsed = 0;
  const fastPoll = 100;  // 快速轮询: 前 2 秒
  const normalPoll = 400;

  while (elapsed < budgetMs) {
    // 动态决定轮询间隔
    const pollInterval = elapsed < 2000 ? fastPoll : normalPoll;
    await sleep(pollInterval);
    elapsed += pollInterval;

    try {
      last = await api(`/api/apply/job?id=${encodeURIComponent(job.id)}`);
    } catch (e) {
      if (e.status === 404 || e.status === 401) break;
      continue;
    }
    if (last.state !== "running") break;
    renderApplyStrip(last);
  }
  renderApplyStrip(last);
  S.lastApplyJob = last;
  if (last.state !== "running") setTimeout(() => renderApplyStrip(null), 4000);
  return last.steps || [];
}

/** 只等后台任务 (响应不是完整仪表盘时用, 如 /api/renew)。 */
export async function awaitJob(body) {
  S.lastApplyJob = null;
  if (!body || !body.job) return (body && body.steps) || [];
  S.applyJobId = body.job.id;
  S.applyJobWait = watchApply(body.job);
  try {
    return await S.applyJobWait;
  } finally {
    S.applyJobId = null;
    S.applyJobWait = null;
  }
}

/** 改配置接口的统一收尾。 */
export async function settleApply(body) {
  S.dash = body;
  redrawDash(true);
  const steps = await awaitJob(body);
  if (body && body.job) {
    try {
      S.dash = await api("/api/dashboard");
      redrawDash(true);
    } catch (e) { /* 断线: 保持现有界面, 下次刷新会补上 */ }
  }
  return steps;
}

/* 改动类接口的统一入口 */
export async function applyAction(method, path, payload, btn, busyText, okText) {
  await waitPendingApply();
  const original = btn ? btn.textContent : "";
  const before = S.dash ? JSON.stringify(S.dash) : "";
  if (btn) { btn.disabled = true; if (busyText) btn.textContent = busyText; }
  S.opBusy += 1;
  try {
    const opts = { method };
    if (payload !== undefined) {
      opts.headers = { "Content-Type": "application/json" };
      opts.body = JSON.stringify(payload);
    }
    const steps = await settleApply(await api(path, opts));
    const failed = steps.filter((s) => !s.ok);
    if (S.lastApplyJob && S.lastApplyJob.state === "failed") {
      toast("应用失败: " + (S.lastApplyJob.error || "后台任务异常"));
    } else {
      toast(
        failed.length
          ? `已应用, 但有 ${failed.length} 步告警: ${failed[0].name}`
          : (okText || "已应用, 订阅内容已刷新")
      );
    }
  } catch (e) {
    if (e.dropped) {
      markDisconnected("重启内核中, 正在确认结果…");
      const changed = await syncAfterDrop(before);
      if (changed === true) toast("已应用 (重启内核时连接短暂中断, 已自动恢复)");
      else if (changed === false) toast("连接已恢复, 但界面没有变化 — 需要的话请再点一次");
    } else {
      toast("操作失败: " + e.message);
      redrawDash(true);
    }
  } finally {
    S.opBusy -= 1;
  }
  if (btn && document.body.contains(btn)) {
    btn.disabled = false;
    if (busyText) btn.textContent = original;
  }
}
