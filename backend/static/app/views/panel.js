/** 面板设置: 管理员账号 / 面板域名 (换域名 = 一次带自动跳转的自动化部署)。
 *
 *  为什么单独一块: 这两件事动的是"面板本身"而不是节点配置 —— 改账号只影响谁能
 *  登进面板 (节点凭据一律不动); 换域名则是一次真正的部署: 重签证书 → 重写
 *  nginx / xray 配置 → 热重载 → 验证 → 把浏览器带到新地址。
 */
import { $, esc, escAttr, toast } from "../lib/dom.js";
import { openConfirm } from "../lib/dialog.js";
import { api, sleep, markDisconnected } from "../lib/api.js";
import { S, reloadDash, redrawDash } from "../lib/state.js";
import { renderApplyStrip, waitPendingApply, assertApplyResult } from "../lib/jobs.js";

/** 把用户可能粘进来的整条地址收敛成主机名 (与后端 _normalize_domain 同一套规则)。 */
function normalizeDomain(raw) {
  let text = String(raw || "").trim().toLowerCase();
  text = text.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  text = text.split("/")[0].split("?")[0].split("#")[0];
  if (text.includes(":")) text = text.split(":")[0];
  return text.replace(/\.+$/, "");
}

const isIpHost = (h) => /^\d{1,3}(\.\d{1,3}){3}$/.test(String(h || ""));

export function renderPanel(d) {
  const grid = $("#panel-grid");
  if (!grid) return;
  const note = $("#panel-note");
  if (note) note.textContent = `面板地址 ${d.panel_url || ""}`;
  grid.innerHTML = accountCard(d) + domainCard(d);
  bindAccount(d);
  bindDomain(d);
}

/* ---------------- 管理员账号 ---------------- */
function accountCard(d) {
  const home = ((d.system || {}).server || {}).panel_home || "/opt/zeroproxy";
  return `<div class="card">
    <div class="row-between">
      <span class="badge vless">管理员账号</span>
      <button class="btn ghost small" id="btn-logout-others" title="把所有已登录的设备踢下线">退出所有设备</button>
    </div>
    <div class="field mt-3"><label for="acct-user">用户名</label>
      <input id="acct-user" value="${escAttr(d.admin_user || "")}" spellcheck="false" autocomplete="username"></div>
    <div class="field"><label for="acct-now">当前密码 (改任何一项都要先验证)</label>
      <input type="password" id="acct-now" autocomplete="current-password" placeholder="当前登录密码"></div>
    <div class="adv-grid">
      <div class="field"><label for="acct-new">新密码 (留空则不改)</label>
        <input type="password" id="acct-new" autocomplete="new-password" placeholder="至少 6 位"></div>
      <div class="field"><label for="acct-new2">确认新密码</label>
        <input type="password" id="acct-new2" autocomplete="new-password" placeholder="再输一遍"></div>
    </div>
    <div class="note">改密码会把<b>其它设备</b>踢下线 (当前这台保持登录)。节点凭据 (UUID / Trojan 与 Hysteria 口令)
      完全不受影响 —— 客户端不用重新导入订阅。</div>
    <div class="note">忘了密码也不怕: SSH 到服务器输入 <b>z</b> 就能改账号密码 / 在线更新
      (终端快捷管理, 面板登不进去时的兜底入口)。<br>
      <span class="muted">敲 z 提示 command not found 时, 用 <b>${esc(home)}/z</b> —— 同一支命令。</span></div>
    <div class="row mt-3">
      <button class="btn small" id="btn-acct-save">保存账号</button>
      <span class="muted fs-sm" id="acct-hint">用户名 2-32 位字母/数字/_-.</span>
    </div>
  </div>`;
}

function bindAccount(d) {
  const btn = $("#btn-acct-save");
  if (btn) btn.onclick = async () => {
    const username = $("#acct-user").value.trim();
    const current = $("#acct-now").value;
    const next = $("#acct-new").value;
    const again = $("#acct-new2").value;
    if (!current) return toast("请先填当前密码");
    if (next && next !== again) return toast("两次输入的新密码不一致");
    if (username === (d.admin_user || "") && !next) return toast("没有需要修改的内容");
    btn.disabled = true;
    btn.textContent = "保存中…";
    try {
      const res = await api("/api/account", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ current_password: current, username, new_password: next || null }),
      });
      ["#acct-now", "#acct-new", "#acct-new2"].forEach((id) => { $(id).value = ""; delete $(id).dataset.draft; });
      S.dash = res;
      redrawDash(true);        // 整个仪表盘重画: 侧栏的管理员名也跟着换
      toast(res.detail || "已保存" + (res.kicked ? ` (注销其它设备 ${res.kicked} 个)` : ""));
    } catch (e) {
      toast("保存失败: " + e.message);
    }
    const again2 = $("#btn-acct-save");
    if (again2) { again2.disabled = false; again2.textContent = "保存账号"; }
  };
  const out = $("#btn-logout-others");
  if (out) out.onclick = () => openConfirm({
    title: "把所有设备踢下线?",
    okLabel: "全部退出 (含本机)",
    html: `<div class="qr-sub">所有已登录的浏览器 / 手机都会立即失效, 包括当前这一台 —— 之后需要用账号密码重新登录。</div>`,
    onOk: async () => {
      try {
        const r = await api("/api/logout-all", { method: "POST" });
        toast(`已退出全部设备 (${r.cleared || 0} 个会话)`);
        setTimeout(() => location.reload(), 800);
      } catch (e) {
        toast("操作失败: " + e.message);
      }
    },
  });
}

/* ---------------- 面板域名 ---------------- */
function domainCard(d) {
  const current = d.domain || "";
  const curLabel = current
    ? `${esc(current)}${isIpHost(current) ? " <span class=\"muted fs-xs\">(IP 直连, 还没绑域名)</span>" : ""}`
    : "—";
  return `<div class="card">
    <div class="row-between">
      <span class="badge trojan">面板域名</span>
      <span class="muted fs-sm">当前 ${curLabel}</span>
    </div>
    <div class="note mt-3 mb-3">
      换域名会<b>重新签发证书、重写 nginx / xray 配置并热重载</b>, 完成后自动把你带到新地址。<br>
      前提: 新域名的 A 记录已经指向本机, 并且 80 端口能从公网访问 (Let's Encrypt 要验证)。
      失败会尝试恢复原域名与配置，回滚结果会单独显示。
    </div>
    <div class="field"><label for="dom-new">新域名</label>
      <input id="dom-new" placeholder="proxy2.example.com" spellcheck="false" autocapitalize="off"></div>
    <div class="note">换完之后: 订阅地址与节点地址都会变成新域名 (客户端重新导入订阅即可);
      已经发给别的机器的链式配对码里写的是旧域名, 需要在「链式代理」里重新生成。</div>
    <div class="row mt-3">
      <button class="btn small" id="btn-dom-save">更换域名并部署</button>
      <span class="muted fs-sm" id="panel-jump-hint"></span>
    </div>
  </div>`;
}

function bindDomain(d) {
  const btn = $("#btn-dom-save");
  if (!btn) return;
  btn.onclick = () => {
    const next = normalizeDomain($("#dom-new").value);
    if (!next) return toast("请先填新域名");
    if (next === (d.domain || "").toLowerCase()) return toast("与当前域名相同");
    if (isIpHost(next)) return toast("这里要填域名 (示例: proxy2.example.com), 不是 IP");
    openConfirm({
      title: `把面板换到 ${next}?`,
      okLabel: "开始部署",
      html: `<div class="qr-sub">当前 ${esc(d.domain || "(IP)")} → <b>${esc(next)}</b></div>
        <div class="confirm-list">
          <div class="ustep"><span class="n">1</span><span class="uname">申请 TLS 证书</span>
            <span class="udetail">Let's Encrypt 从新域名验证本机 (要 80 端口通)</span></div>
          <div class="ustep"><span class="n">2</span><span class="uname">重写 nginx / xray 配置</span>
            <span class="udetail">新域名的证书、订阅地址、节点地址一起换</span></div>
          <div class="ustep"><span class="n">3</span><span class="uname">热重载并验证新域名</span>
            <span class="udetail">验证失败尝试回滚，并核对恢复结果</span></div>
          <div class="ustep"><span class="n">4</span><span class="uname">自动跳转到新地址</span>
            <span class="udetail">已登录状态一起带过去, 不用重新输密码</span></div>
        </div>
        <div class="confirm-keep">不会动的部分: 节点密钥 / 客户端凭据 / 端口设置 / 订阅令牌本身
          (只是订阅地址里的域名变了)。</div>`,
      onOk: () => deployDomain(next),
    });
  };
}

/** 换域名的整条前端闭环: 发起 → 盯进度 → 等新地址可达 → 跳过去。 */
async function deployDomain(next) {
  const btn = $("#btn-dom-save");
  const fallbackUrl = `https://${next}${location.port ? ":" + location.port : ""}/`;
  if (btn) { btn.disabled = true; btn.textContent = "部署中…"; }
  await waitPendingApply();
  let target = fallbackUrl;
  let handoff = "";
  // 整个部署期间不要开 20 秒自动刷新: 那会跟进度条抢屏, 也会在切换那一刻白刷一次
  S.opBusy += 1;
  try {
    const res = await api("/api/domain", {
      timeoutMs: 360000,
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: next }),
    });
    assertApplyResult(res);
    target = (res.redirect || {}).url || fallbackUrl;
    handoff = (res.redirect || {}).handoff || "";
    const verdict = await watchDomainJob(res.job);
    if (verdict === "failed") {
      await reloadDash(true);
      if (btn) { btn.disabled = false; btn.textContent = "更换域名并部署"; }
      return;
    }
  } catch (e) {
    if (!e.dropped) {
      toast("域名部署未完成: " + e.message, { kind: "error" });
      await reloadDash(true);
      const current = $("#btn-dom-save");
      if (current) { current.disabled = false; current.textContent = "更换域名并部署"; }
      return;
    }
    markDisconnected("连接中断，正在核对新入口…");
  } finally {
    S.opBusy -= 1;   // 失败提前 return 时也要还回去, 否则自动刷新再也回不来
  }
  // 本地开发环境面板是直连的 (没有 nginx, 也没有公网入口): 跳到 https://新域名:端口
  // 只会把用户扔到一个打不开的地址。配置照常落盘, 但这里不跳。
  if (!(((S.dash || {}).system || {}).prod)) {
    await reloadDash(true);
    if (btn) { btn.disabled = false; btn.textContent = "更换域名并部署"; }
    const local = $("#panel-jump-hint");
    if (local) local.textContent = "本地开发环境: 配置已更新, 不跳转 (没有 nginx / 公网入口)";
    toast("域名已写入配置 (本地开发环境不跳转)");
    return;
  }
  await jumpTo(target, handoff, (S.dash || {}).admin_user || "");
}

/** 盯后台任务的进度。返回 "done" | "failed" | "gone"(老地址已经不通 = 正在切换)。 */
async function watchDomainJob(job) {
  if (!job) return "gone";
  let last = job;
  renderApplyStrip(job);
  let missed = 0;
  // 一步 certbot 最长 300 秒, 再留一点余量
  const deadline = Date.now() + 360000;
  while (Date.now() < deadline) {
    await sleep(600);
    try {
      last = await api(`/api/apply/job?id=${encodeURIComponent(job.id)}`, { timeoutMs: Math.max(1, Math.min(10000, deadline - Date.now())) });
      missed = 0;
    } catch (e) {
      if (e.status === 404 || e.status === 401) break;
      missed += 1;
      if (missed >= 3) return "gone";     // 连续三次连不上: nginx 已经换过去了
      continue;
    }
    renderApplyStrip(last);
    if (last.state !== "running") break;
  }
  renderApplyStrip(last);
  S.lastApplyJob = last;
  if (last.state === "failed" || last.error) {
    toast("换域名失败: " + String(last.error || "未知原因").slice(0, 150));
    return "failed";
  }
  if (last.state === "running") {
    // 还在跑 (比如 certbot 慢): 老地址仍然可用, 让用户自己决定要不要等
    toast("新域名还在部署中, 顶部进度条会继续走; 完成后卡片会自己刷新");
    await reloadDash(true);
    return "failed";
  }
  return "done";
}

/** 新地址能打开了就跳过去 (跳之前把一次性票据带上, 免去重新登录)。 */
async function jumpTo(target, handoff, username) {
  const hint = $("#panel-jump-hint");
  // handoff: 一张一次性票据, 换过去就是登录态 (不用重新输密码);
  // user: 万一票据过期, 登录页至少把用户名填好 —— 密码绝不会出现在 URL 里。
  const q = new URLSearchParams();
  if (handoff) q.set("handoff", handoff);
  if (username) q.set("user", username);
  const query = q.toString();
  const url = query ? `${target}${target.includes("?") ? "&" : "?"}${query}` : target;
  if (hint) hint.textContent = `正在验证新入口 ${target}`;
  const deadline = Date.now() + 60000;
  while (Date.now() < deadline) {
    if (await reachable(target, Math.min(5000, deadline - Date.now()))) {
      if (hint) hint.textContent = `新入口可达，正在跳转到 ${target}`;
      location.replace(url);
      return;
    }
    await sleep(1500);
  }
  if (hint) hint.textContent = `未能确认新入口，请保留本页并核对域名、证书与部署结果：${target}`;
  toast("新入口尚未验证可达，已保留当前页面，请核对部署结果", { kind: "error" });
}

/** 新地址通不通 (no-cors: 只关心网络层有没有响应, 不需要读内容)。 */
async function reachable(target, timeoutMs = 5000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    await fetch(target + "api/status", { mode: "no-cors", cache: "no-store", signal: controller.signal });
    return true;
  } catch (e) {
    return false;
  } finally { clearTimeout(timer); }
}
