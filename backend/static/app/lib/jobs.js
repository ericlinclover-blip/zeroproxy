/** 后台落地闭环 + 改动类接口的统一入口。
 *
 *  改动:
 *    1) 自适应轮询间隔: 前 2s 用 250ms 快速采样（用户刚点击，急于看进度），
 *       之后退回 1–2s，避免不必要的 HTTP 请求。
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
  box.dataset.jobId = st.id || "";
  const running = st.state === "running" || st.state === "queued";
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

/** 自适应轮询后台任务: 前 2s 用 250ms 快速采样, 之后 400ms。 */
export async function watchApply(job) {
  let last = job;
  renderApplyStrip(job);
  const budgetMs = job.kind === "geodata" ? 480000 : 120000;
  const started = Date.now();
  let elapsed = 0;

  while (elapsed < budgetMs) {
    // 动态决定轮询间隔
    const pollInterval = elapsed < 2000 ? 250 : elapsed < 15000 ? 1000 : 2000;
    await sleep(pollInterval);
    elapsed = Date.now() - started;

    try {
      last = await api(`/api/apply/job?id=${encodeURIComponent(job.id)}`, { timeoutMs: Math.min(10000, Math.max(1, budgetMs - elapsed)) });
    } catch (e) {
      if (e.status === 404 || e.status === 401) {
        last = { ...last, state: "unknown", error: e.status === 401 ? "会话已失效，请登录后核对任务结果" : "任务记录不可用，请核对实际状态" };
        break;
      }
      continue;
    }
    if (!["running", "queued"].includes(last.state)) break;
    renderApplyStrip(last);
  }
  if (["running", "queued"].includes(last.state)) last = { ...last, state: "unknown", error: "尚未取得任务完成结果，请刷新面板确认实际状态" };
  S.lastApplyJob = last;
  renderApplyStrip(last);
  assertApplyResult(last);
  setTimeout(() => {
    const box = $("#apply-strip");
    if (box?.dataset.jobId === String(last.id) && box.dataset.state === "good") renderApplyStrip(null);
  }, 4000);
  return last.steps || [];
}

/** One result contract for asynchronous and synchronous operations. */
export function assertApplyResult(result) {
  const failed = (result?.steps || []).find((step) => !step.ok);
  if (result?.ok === false || result?.error || failed || ["failed", "unknown", "interrupted"].includes(result?.state)) {
    const error = new Error(result.error || failed?.detail || result.detail || "配置未能应用");
    error.result = result;
    error.unknown = ["unknown", "interrupted"].includes(result.state);
    throw error;
  }
}

/** 只等后台任务 (响应不是完整仪表盘时用, 如 /api/renew)。 */
export async function awaitJob(body) {
  S.lastApplyJob = null;
  if (!body || !body.job) { assertApplyResult(body); return body?.steps || []; }
  recovered.add(body.job.id);
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

export function renderTaskHistory(jobs = [], runtime = {}) {
  const box = $("#task-history");
  if (!box) return;
  const status = { done: "已完成", running: "执行中", queued: "排队中", failed: "失败", interrupted: "结果待确认", unknown: "结果待确认" };
  const summary = $("#runtime-status");
  const matches = runtime.applied_revision && runtime.applied_revision === S.dash?.configuration_revision;
  summary.textContent = `${runtime.verification === "dry-run" ? "本地演练记录" : "服务器配置记录"} · ${matches && runtime.status === "applied" ? "期望与应用版本一致" : runtime.status === "failed" ? "上次应用失败，需核对运行状态" : "应用版本待核对"}`;
  box.innerHTML = jobs.length ? jobs.map((job) => `<details id="task-${esc(job.id)}" class="task-record"><summary>${esc(status[job.state] || "结果待确认")} · ${esc(job.kind || "apply")} · ${esc(job.current || "配置任务")}</summary><p>${esc(job.error || "未记录错误")}</p><p class="mono">期望版本 ${esc(job.desired_revision || "未记录")} / 应用版本 ${esc(job.applied_revision || "未记录")}</p></details>`).join("") : '<p class="muted">本会话还没有后台任务记录。</p>';
}

const recovered = new Set();
export function resumeApplyJobs(jobs = []) {
  if (S.applyJobWait) return;
  const job = jobs.find((item) => !recovered.has(item.id));
  if (!job) return;
  recovered.add(job.id);
  if (["failed", "unknown", "interrupted"].includes(job.state)) {
    renderApplyStrip(job);
    toast(job.error || "上次操作需要核对结果", { kind: "error" });
  } else if (["running", "queued"].includes(job.state)) {
    awaitJob({ job }).then(async () => {
      S.dash = await api("/api/dashboard"); redrawDash(true);
      toast("后台任务已完成，已核对最新状态");
    }).catch((error) => toast(error.message, { kind: "error" }));
  }
}

export function confirmationNotice(message) {
  return S.dash?.pending_change?.state === "awaiting_confirmation"
    ? `${message}；当前为临时配置，请在顶部倒计时内测试并保留变更，超时自动回滚`
    : message;
}

/* 改动类接口的统一入口 */
export async function applyAction(method, path, payload, btn, busyText, okText) {
  await waitPendingApply();
  const original = btn ? btn.textContent : "";
  const before = S.dash ? JSON.stringify(S.dash) : "";
  if (btn) { btn.disabled = true; if (busyText) btn.textContent = busyText; }
  S.opBusy += 1;
  let succeeded = false;
  try {
    const opts = { method };
    if (payload !== undefined) {
      opts.headers = { "Content-Type": "application/json" };
      opts.body = JSON.stringify(payload);
    }
    const steps = await settleApply(await api(path, opts));
    succeeded = true;
    const failed = steps.filter((s) => !s.ok);
    if (S.lastApplyJob && S.lastApplyJob.state === "failed") {
      toast("应用失败: " + (S.lastApplyJob.error || "后台任务异常"));
    } else {
      toast(
        failed.length
          ? `已应用, 但有 ${failed.length} 步告警: ${failed[0].name}`
          : confirmationNotice(okText || "已应用, 订阅内容已刷新")
      );
    }
  } catch (e) {
    if (e.dropped) {
      markDisconnected("重启内核中, 正在确认结果…");
      const changed = await syncAfterDrop(before);
      if (changed === true) toast("已应用 (重启内核时连接短暂中断, 已自动恢复)");
      else if (changed === false) toast("连接已恢复，操作结果待确认。请核对目标状态，勿重复提交", { kind: "error" });
    } else {
      toast("操作失败: " + e.message, { kind: "error" });
      redrawDash(true);
    }
  } finally {
    S.opBusy -= 1;
  }
  if (btn && document.body.contains(btn)) {
    btn.disabled = false;
    if (busyText) btn.textContent = original;
  }
  return succeeded;
}
