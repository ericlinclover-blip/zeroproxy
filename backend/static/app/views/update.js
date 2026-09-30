/** 程序更新: 版本对比 → 确认弹窗 → 逐步进度 → 结果卡。 */
import { $, esc, toast, revealSection } from "../lib/dom.js";
import { fmtTime } from "../lib/format.js";
import { openConfirm } from "../lib/dialog.js";
import { api } from "../lib/api.js";
import { S, reloadDash } from "../lib/state.js";
import { renderSidebar } from "./status.js";

/* ---------------- 一键更新 ----------------
 * 升级由服务器上的 upgrade.sh 完成; 面板只负责按按钮 + 回读进度。
 * 面板进程会在升级过程中重启, 因此轮询要能容忍请求失败。
 *
 * 交互闭环 (之前只有一句 confirm + 一个跳动的徽标):
 *   检查更新 → 版本对比 → 一键更新 (确认弹窗, 写清会做什么/不动什么)
 *   → 升级中 (逐步清单: 待执行 ○ / 进行中 ⟳ / 已完成 ✓ + 进度条 + 已用时间)
 *   → 完成 (绿色结论 + 用时 + 一键重新加载) / 失败 (红 + 失败步骤 + 日志 + 重试)。
 * 步骤清单来自 upgrade.sh 自己写的 plan/steps, 不是前端猜的。 */
export async function loadUpdate(force) {
  try {
    const path = force ? "/api/update?force=1" : "/api/update";
    S.updateInfo = await api(path);
  } catch (e) {
    return; // 未登录 / 升级中, 静默处理
  }
  if (!S.pageVersion && S.updateInfo.current) S.pageVersion = S.updateInfo.current;
  renderUpdate();
  if (S.updateInfo.running && !S.updateTimer) startUpdatePolling();
}

export function renderUpdate() {
  const u = S.updateInfo || {};
  const last = u.last || {};
  const cur = u.current || "—";
  const latest = u.latest || "";
  const badge =
    u.check_ok === false
      ? `<span class="badge hysteria">检查失败</span>`
      : u.update_available
        ? `<span class="badge trojan">有新版本 v${esc(latest)}</span>`
        : `<span class="badge vless">已是最新</span>`;
  $("#update-status-line").innerHTML =
    // 远端版本只由徽标表达: raw.githubusercontent 有 ~5 分钟 CDN 缓存, 刚发布完会拿到旧号,
    // 那时「当前 v2.6.1 · 最新 v2.6.0」这种自相矛盾的写法比不写更糟
    `${badge} <span class="muted">当前 v${esc(cur)}` +
    `${u.checked_at ? " · " + esc(fmtTime(u.checked_at)) + " 检查" : ""}</span>`;

  const lines = [];
  if (u.check_ok === false) {
    lines.push(
      `<div class="banner info"><span class="ico">i</span><span>无法访问远端版本源 (${esc(
        String(u.check_error || "").slice(0, 120)
      )})。<br><span class="muted">面板本身仍可用; 需要升级时可在服务器上执行 README 里的一键升级命令。</span></span></div>`
    );
  }
  if (last.state) lines.push(updateResultHtml(u, last));
  else if (!u.check_ok) {
    lines.push(`<div class="note">还没跑过升级。</div>`);
  }
  lines.push(
    `<div class="muted fs-sm mt-3">更新源 github.com/${esc(u.repo || "")} @ ${esc(u.ref || "main")}</div>`
  );

  const running = !!u.running;
  const stale = updateNeedsReload();   // 本页 JS 落后于服务器 (自动重载用的是同一个判据)
  if (running) {
    $("#update-hint").textContent = "升级进行中: 面板会在最后重启一次, 本页会在几秒内自动恢复";
  } else if (stale) {
    $("#update-hint").textContent = `服务器已是 v${u.current}, 本页还是 v${S.pageVersion} 的界面 — 重新加载后生效`;
  } else if (!u.can_update) {
    $("#update-hint").textContent = u.prod
      ? "服务器上还没有 upgrade.sh — 先执行 README 里的一键升级命令装好它, 之后就能在面板里一键更新"
      : "本地开发环境不支持面板内升级, 请在服务器上运行 upgrade.sh";
  } else {
    $("#update-hint").textContent = "升级只替换程序代码, 密钥 / 订阅令牌 / 节点配置全部保留";
  }
  $("#update-body").innerHTML = lines.join("");

  const runBtn = $("#btn-update-run");
  const topBtn = $("#btn-update");
  runBtn.classList.toggle("hidden", !u.update_available || !u.can_update || running);
  runBtn.disabled = running;
  runBtn.textContent = running ? "升级中…" : `一键更新到 v${latest}`;
  $("#btn-update-reload").classList.toggle("hidden", !stale || running);
  topBtn.textContent = running ? "升级中…" : u.update_available ? `一键更新 v${latest}` : "检查更新";

  // 「同时升级内核」只在能升级、且没在升级时才有意义。旁边的注释顺带把**当前**
  // 内核版本摆出来 —— 用户要判断"要不要升内核", 至少得先看见自己在跑什么版本。
  const coreRow = $("#update-core-row");
  if (coreRow) {
    const usable = !!u.can_update && !running;
    coreRow.classList.toggle("hidden", !usable);
    const box = $("#update-core");
    if (box && !usable) box.checked = false;   // 藏起来时不留一个"已勾选"的隐形开关
    const note = $("#update-core-note");
    if (note && usable) {
      const sys = (S.dash || {}).system || {};
      const ver = (svc) => (svc && svc.version ? svc.version : "未知");
      note.textContent = `当前: Xray ${ver(sys.xray)} · Hysteria 2 ${ver(sys.hysteria2)}`;
    }
  }
  renderSidebar();   // 侧栏「程序更新」角标跟着变
}

/* 升级中的实时清单: 待执行 ○ / 进行中 ⟳ / 已完成 ✓ / 失败 ✗。
 * 清单来自 upgrade.sh 写的 plan + steps (前端不猜步骤), 每 2.5s 刷新一次。 */
function updateStepsHtml(last) {
  const done = last.steps || [];
  const plan = last.plan || [];
  if (!plan.length && !done.length) return "";
  const byName = new Map(done.map((s) => [s.name, s]));
  const current = last.current || "";
  // 兜底步骤 (如「升级中断」) 不在 plan 里, 追加到清单尾部, 免得失败原因看不见
  const names = plan.concat(done.filter((s) => !plan.includes(s.name)).map((s) => s.name));
  const rows = names
    .map((name) => {
      const s = byName.get(name);
      if (s) {
        const cls = s.ok ? "done" : "failed";
        return `<div class="ustep ${cls}"><span class="ico">${s.ok ? "✓" : "✗"}</span>
          <span class="uname">${esc(name)}</span><span class="udetail">${esc(s.detail || "")}</span></div>`;
      }
      if (name === current) {
        return `<div class="ustep now"><span class="ico">⟳</span><span class="uname">${esc(name)}</span>
          <span class="udetail">进行中…</span></div>`;
      }
      return `<div class="ustep todo"><span class="ico">○</span><span class="uname">${esc(name)}</span></div>`;
    })
    .join("");
  const pending = current && !byName.has(current) ? 0.45 : 0;
  // "已完成"只数真正成功的步骤: 失败的那一步和"升级中断"兜底步不该算成已完成
  const okCount = done.filter((s) => s.ok).length;
  const failCount = done.filter((s) => !s.ok).length;
  const pct = Math.min(100, Math.round(((okCount + pending) / names.length) * 100));
  const failedAt = names.findIndex((n) => (byName.get(n) || {}).ok === false);
  const summary = failedAt >= 0
    ? `在第 ${failedAt + 1} 步失败 · 已完成 ${okCount}/${names.length} 步${
        failCount > 1 ? ` · ${failCount} 步未成功` : ""}`
    : `已完成 ${okCount}/${names.length} 步`;
  // 升级进行中给进度条加 `.live` (斜纹跑马), 停下来了就恢复静态 —— 一眼区分"在动"和"卡住"
  const live = last.state === "running" || last.state === "queued";
  return `<div class="ustep-wrap">${rows}</div>
    <div class="bar${live ? " live" : ""}"><i class="${failedAt >= 0 ? "bad" : ""}" style="width:${pct}%"></i></div>
    <div class="muted fs-sm mt-1">${summary}${
      last.started_at ? ` · 已用 ${fmtDuration(Math.max(0, updateNow() - last.started_at))}` : ""
    }</div>`;
}

function updateResultHtml(u, last) {
  const state = last.state;
  const steps = updateStepsHtml(last);
  const elapsed = last.started_at && last.finished_at
    ? `用时 ${fmtDuration(Math.max(0, last.finished_at - last.started_at))} · ` : "";
  const trigger = `触发方式: ${last.trigger === "panel" ? "面板按钮" : "命令行"}`;
  if (state === "running" || state === "queued") {
    const title = state === "queued" ? "升级任务已排队, 正在准备…" : `正在升级: v${esc(last.from || "")} → v${esc(last.to || "…")}`;
    return `<div class="banner info"><span class="ico">⟳</span><span><b>${title}</b>
      <br><span class="muted">别关这个页面; 面板重启期间本页会自动重连。</span></span></div>
      ${steps ? `<div class="mt-3">${steps}</div>` : ""}`;
  }
  if (state === "success") {
    const failed = (last.steps || []).filter((s) => !s.ok);
    return `<div class="banner good"><span class="ico">✓</span><span><b>升级完成: v${
      esc(last.from || "?")} → v${esc(last.to || "?")}</b>
      <br><span class="muted">${esc(elapsed)}结束于 ${esc(fmtTime(last.finished_at))} · ${esc(trigger)}${
        failed.length ? ` · ${failed.length} 步有告警` : ""}</span></span></div>
      <details class="mt-3"><summary class="muted fs-sm pointer">查看步骤详情</summary>
      <div class="mt-2">${steps || "<span class='muted'>—</span>"}</div></details>`;
  }
  const first = (last.steps || []).find((s) => !s.ok) || {};
  return `<div class="banner bad"><span class="ico">✗</span><span><b>升级失败: ${esc(first.name || last.message || "未知步骤")}</b>
    <br><span class="muted">${esc(first.detail || last.message || "")} · 代码已自动回滚到升级前版本 · ${esc(trigger)}</span></span></div>
    ${steps ? `<div class="mt-3">${steps}</div>` : ""}
    ${u.log_tail ? `<details class="mt-3" open><summary class="muted fs-sm pointer">升级日志</summary>
      <div class="log-box">${esc(u.log_tail)}</div></details>` : ""}`;
}

const updateNow = () => Math.round(Date.now() / 1000);
const fmtDuration = (s) => (s >= 60 ? `${Math.floor(s / 60)} 分 ${s % 60} 秒` : `${s} 秒`);

/** 升级完成后是否要自动重新加载本页。
 *
 *  判据是「**本页 JS 的版本**」和「服务器现在的版本」不一致 —— 升级前打开的这个页面,
 *  它加载的 JS 还是旧的, 必须重新加载才会换成新界面。
 *
 *  别用 `last.to !== current`: 面板重启之后这两个值本来就相等 (都等于新版本), 那条判据
 *  永远为假 —— 自动重载永远不会发生, 用户只能自己去点「重新加载面板」(真机踩到)。
 */
export function updateNeedsReload() {
  const u = S.updateInfo || {};
  return !!(S.pageVersion && u.current && S.pageVersion !== u.current);
}


function startUpdatePolling() {
  clearInterval(S.updateTimer);
  S.updatePollFailures = 0;
  S.updateTimer = setInterval(async () => {
    try {
      S.updateInfo = await api("/api/update");
      S.updatePollFailures = 0;
      renderUpdate();
      if (!S.updateInfo.running && S.updateInfo.last && S.updateInfo.last.state === "success") {
        clearInterval(S.updateTimer); S.updateTimer = null;
        toast(`升级完成: v${S.updateInfo.last.from} → v${S.updateInfo.last.to}`);
        if (updateNeedsReload()) {
          // 本页跑的还是升级前的 JS: 自动重新加载, 省掉"再点一下"。
          // 留 2.5 秒是为了让上面那条 toast 看得见 —— 面板刚重启完, 这会儿也没有正在进行的操作。
          const hint = $("#update-hint");
          if (hint) hint.textContent = "升级完成 — 正在自动重新加载面板…";
          setTimeout(() => location.reload(), 2500);
        } else {
          reloadDash(true);   // 本页已经是新版本 (比如刚打开就在新版上): 重画即可, 不必刷新
        }
      } else if (!S.updateInfo.running && S.updateInfo.last && S.updateInfo.last.state === "failed") {
        clearInterval(S.updateTimer); S.updateTimer = null;
        toast("升级失败, 详情见「程序更新」卡片");
        reloadDash(true);
      }
    } catch (e) {
      // 允许失败: 升级过程中面板会重启, 这里静默重试
      S.updatePollFailures += 1;
      if (S.updatePollFailures > 60) { clearInterval(S.updateTimer); S.updateTimer = null; }
    }
  }, 2500);
}

/* 升级确认: 一步步写清会做什么, 以及什么不会被碰 */
/** 「同时升级内核」勾选状态 (内核升级只由用户显式勾选触发, 见后端 update.start)。 */
const coreWanted = () => {
  const box = $("#update-core");
  return !!(box && box.checked && !box.disabled);
};

export function askUpgrade() {
  const u = S.updateInfo || {};
  const from = u.current || "当前版本";
  const to = u.latest || "最新版";
  const core = coreWanted();
  const plan = [
    ["1", "备份当前代码与 state.json", "异常自动回滚"],
    ["2", `从 GitHub 下载 v${esc(to)} 代码`, esc(u.repo || "")],
    ["3", "替换面板程序代码", "只换代码, 不动数据"],
    ["4", "同步 Python 依赖 + 重载 systemd 单元", ""],
    ["5", "按 state.json 重新生成配置并热重载", "xray / nginx / hysteria"],
  ];
  if (core) plan.push(["6", "升级 Xray / Hysteria 2 内核", "下载失败则保留现有版本"]);
  plan.push([core ? "7" : "6", "重启面板进程", "本页失联约 10 秒后自动恢复"]);
  openConfirm({
    title: `确认升级到 v${to}?`,
    okLabel: `开始升级 v${esc(from)} → v${to}`,
    html: `<div class="qr-sub">当前 v${esc(from)} → 最新 v${esc(to)}</div>
      <div class="confirm-list">${plan
        .map(
          ([n, name, detail]) => `<div class="ustep"><span class="n">${n}</span>
            <span class="uname">${name}</span>${detail ? `<span class="udetail">${detail}</span>` : ""}</div>`
        )
        .join("")}</div>
      ${core
        ? `<div class="banner info mt-3"><span class="ico">!</span><span>已勾选内核升级: Xray / Hysteria 2 会被替换成上游最新版。
           <br><span class="muted">内核大版本可能改变配置语义 (例如 Xray 25 移除 allowInsecure、改证书字段名),
           升级后若节点异常, 在「运行状态 → 一键诊断」能直接看出是哪一项不一致。</span></span></div>`
        : ""}
      <div class="confirm-keep">不会动的部分: 节点密钥 / 订阅令牌 / 管理员账号 / 节点开关与端口设置。
      升级过程中面板会重启一次, 页面会在几秒内自动恢复。</div>`,
    onOk: doUpdate,
  });
}

async function doUpdate() {
  const btn = $("#btn-update-run");
  const core = coreWanted();
  btn.disabled = true;
  btn.textContent = "启动中…";
  try {
    await api("/api/update", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ core }),
    });
    toast("升级已开始, 正在执行…");
    // 后端只回执"已开始"(刻意不查远端版本, 那会让按钮卡住半分钟); 这里先把状态标成"已排队",
    // 免得这 2.5 秒的空窗里按钮还能再点一次 (再点会撞上 409)。真实进度由轮询补上。
    S.updateInfo = {
      // 这里曾写成 `...updateInfo` —— 一个不存在的变量, 于是每次点「一键更新」都会在
      // POST 成功后抛 ReferenceError, 轮询根本没启动: 用户看到的是一句"无法开始升级",
      // 实际升级在跑, 页面却再也不会自己刷新。
      ...(S.updateInfo || {}),
      running: true,
      last: {
        ...((S.updateInfo || {}).last || {}),
        state: "queued",
        from: (S.updateInfo || {}).current,
        to: (S.updateInfo || {}).latest,
        trigger: "panel",
        core,
        started_at: Math.floor(Date.now() / 1000),
        finished_at: 0,
        steps: [],
        plan: [],
      },
    };
    startUpdatePolling();
    renderUpdate();
  } catch (e) {
    toast("无法开始升级: " + e.message);
    btn.disabled = false;
    loadUpdate(true);
  }
}

$("#btn-update-check").onclick = async () => {
  const btn = $("#btn-update-check");
  btn.disabled = true; btn.textContent = "检查中…";
  // 头部的「检查更新」也走这条路径 —— 把结果卡片带到眼前, 不用用户自己翻
  revealSection("#update-card");
  await loadUpdate(true);
  btn.disabled = false; btn.textContent = "检查更新";
  if (S.updateInfo && S.updateInfo.check_ok === false) toast("检查失败: 无法访问远端版本源");
  else if (S.updateInfo && S.updateInfo.update_available) toast(`发现新版本 v${S.updateInfo.latest}`);
  else toast("已是最新版本");
};
$("#btn-update-run").onclick = askUpgrade;
$("#btn-update-reload").onclick = () => location.reload();
$("#btn-update").onclick = () => {
  if (S.updateInfo && S.updateInfo.update_available && S.updateInfo.can_update && !S.updateInfo.running) askUpgrade();
  else $("#btn-update-check").click();
};
