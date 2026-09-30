/** 后台落地闭环 + 改动类接口的统一入口。
 *
 *  包含两件事:
 *    1) 后台任务 (v2.6.9): 改配置 = 重新生成三份配置 → 重启内核 → 验端口, 真机上要
 *       2~4 秒, 而重启 Xray 会掐断"走本机链路上网"的浏览器。接口立刻回执 (body.job),
 *       这里轮询 /api/apply/job 把进度画成一条实时进度条, 页面全程可用;
 *    2) `applyAction`: 端口跳跃 / 链式代理这类"改一下再看结果"的按钮共用的收尾
 *       (等上一次落地 → 发请求 → 渲染 → 断线核对)。放在这里而不是某个视图里,
 *       是因为链式、高级设置、分流模板都要用它。
 */
import { $, esc, toast } from "./dom.js";
import { api, sleep, markDisconnected, syncAfterDrop } from "./api.js";
import { S, redrawDash } from "./state.js";

/* ---------------- 后台配置任务 (v2.6.9) ----------------
 * 改配置 = 重新生成三份配置 → 重启内核 → 验端口, 真机上要 2~4 秒; 而重启 Xray
 * 会掐断"走本机链路上网"的浏览器 —— 很多用户就是用自己的节点访问面板的
 * (v2.6.7 真机实测: 面板把请求当成了"登录失效"直接跳登录页)。
 * 现在这条闭环由面板后台任务跑, 接口立刻回执 (body.job), 这里轮询
 * /api/apply/job 把进度画成一条实时进度条: 页面全程可用, "在动"和"卡住"一眼可分。
 */
/** 上一次改动还在落地就等它跑完 —— 直接拒绝会让用户觉得"点了没反应"。 */
export async function waitPendingApply() {
  if (!S.applyJobWait) return;
  try {
    await S.applyJobWait;
  } catch (e) { /* 上一次的失败自己已经报过错了 */ }
}

export function renderApplyStrip(st) {
  const box = $("#apply-strip");
  if (!box) return;
  if (!st) {
    box.classList.add("hidden");
    box.innerHTML = "";
    return;
  }
  const running = st.state === "running";
  const stepFails = ((st.steps || []).filter((s) => !s.ok)).length;
  const bad = !running && (st.state === "failed" || !!st.error || stepFails > 0);
  // GeoIP 下载和"改配置落地"共用这条进度条, 文案要跟着任务类型走
  const geo = st.kind === "geodata";
  const total = st.total || 6;
  const index = Math.max(1, Math.min(st.index || 1, total));
  const pct = Math.round((index / total) * 100);
  const secs = ((st.elapsed_ms || 0) / 1000).toFixed(1);
  const title = bad
    ? st.error ? (geo ? "GeoIP 数据更新失败" : "配置落地失败")
      : geo ? `GeoIP 数据已更新, 但有 ${stepFails} 步告警` : `配置已应用, 但有 ${stepFails} 步告警`
    : running ? (geo ? "正在下载 GeoIP 数据" : "正在应用配置")
      : geo ? "GeoIP 数据已更新并生效" : "配置已应用";
  box.classList.remove("hidden");
  box.innerHTML = `<div class="banner ${bad ? "bad" : running ? "info" : "good"}">
    <span class="ico">${bad ? "✗" : running ? "⟳" : "✓"}</span>
    <span class="grow">
      <b>${title}</b>
      <span class="muted"> · 第 ${index}/${total} 步 · ${esc(st.current || "")} · 已用 ${secs}s</span>
      <div class="bar${running ? " live" : ""}"><i class="${bad ? "bad" : ""}" style="width:${bad ? 100 : pct}%"></i></div>
      ${bad ? `<div class="muted fs-sm mt-1">${esc(st.error || "")}</div>` : ""}
    </span></div>`;
}

/** 轮询后台任务直到跑完; 返回最终 steps (拿不到就返回 [])。
 *
 * 预算按任务类型给: 改配置 2~4 秒 (给 2 分钟), GeoIP 要下 ~28 MB 且后端自己的
 * 上限是 180s (给 8 分钟) —— 以前统一按 2 分钟掐表, 超时后既不报错也不报进度,
 * 还会把"其实还在下载"当成成功, 用户回头看到卡片还是旧的, 只能说"出错了"。 */
export async function watchApply(job) {
  let last = job;
  renderApplyStrip(job);
  const budgetMs = job.kind === "geodata" ? 480000 : 120000;
  for (let waited = 0; waited < budgetMs; waited += 400) {
    await sleep(400);
    try {
      last = await api(`/api/apply/job?id=${encodeURIComponent(job.id)}`);
    } catch (e) {
      if (e.status === 404 || e.status === 401) break;   // 任务表被清 / 会话过期
      continue;                            // 重启内核掐断了隧道: 连接回来接着轮询
    }
    if (last.state !== "running") break;
    renderApplyStrip(last);
  }
  renderApplyStrip(last);
  S.lastApplyJob = last;
  // 还在跑就别收起进度条 (收起等于"没了", 用户会以为卡住/失败)
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

/** 改配置接口的统一收尾: 渲染返回的仪表盘 → 等后台任务 → 再用最新数据对齐一次。 */
export async function settleApply(body) {
  S.dash = body;
  redrawDash(true);
  const steps = await awaitJob(body);
  if (body && body.job) {
    // 任务期间面板可能重启过 / 界面被 20s 自动刷新顶掉, 对齐一次真实状态
    try {
      S.dash = await api("/api/dashboard");
      redrawDash(true);
    } catch (e) { /* 断线: 保持现有界面, 下次刷新会补上 */ }
  }
  return steps;
}

/* 改动类接口的统一入口 (端口跳跃 / 链式代理): 回来后用服务器返回的完整仪表盘
 * 数据整体重渲染, 并把落地的步骤结果转成提示 */
export async function applyAction(method, path, payload, btn, busyText) {
  await waitPendingApply();   // 上一次还在落地: 排队等它, 别把这次点了没反应
  const original = btn ? btn.textContent : "";
  const before = S.dash ? JSON.stringify(S.dash) : "";   // 用于"断线后其实已经生效"的比对
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
      toast("应用失败: " + (S.lastApplyJob.error || "后台任务异常"));   // 步骤清单没有, 至少别报"已应用"
    } else {
      toast(failed.length ? `已应用, 但有 ${failed.length} 步告警: ${failed[0].name}` : "已应用, 订阅内容已刷新");
    }
  } catch (e) {
    if (e.dropped) {
      // 面板其实已经把活干完了, 断的只是"浏览器 → 本机链路 → 面板"这条路
      markDisconnected("重启内核中, 正在确认结果…");
      const changed = await syncAfterDrop(before);
      if (changed === true) toast("已应用 (重启内核时连接短暂中断, 已自动恢复)");
      else if (changed === false) toast("连接已恢复, 但界面没有变化 —— 需要的话请再点一次");
    } else {
      toast("操作失败: " + e.message);
      redrawDash(true);   // 失败时按最后一次拿到的状态回灌, 别把界面留在"看起来改成功了"的样子
    }
  } finally {
    S.opBusy -= 1;
  }
  // 控件可能已经被整体重渲染掉, 只有还留在页面上时才恢复
  if (btn && document.body.contains(btn)) {
    btn.disabled = false;
    if (busyText) btn.textContent = original;
  }
}
