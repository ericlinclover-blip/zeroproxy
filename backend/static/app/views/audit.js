/* ---------------- 操作记录 ----------------
 * 谁 · 什么时候 · 做了什么 · 结果。这块的状态独立维护, 因为仪表盘每 20 秒会整块重画:
 *   - 默认视图 (没筛选、没翻页) 直接用仪表盘顺带下发的那 20 条 + 各分类条数, 零额外请求;
 *     自动刷新时跟着一起更新。
 *   - 一旦筛选 / 搜索 / 翻页, 就切成"自己按 id 游标拉 /api/audit", 并且不再让仪表盘的重画
 *     覆盖它 (清空筛选或点「刷新」即回到默认视图)。
 *   - 分页用 id 游标而不是 offset: 翻页期间随时会来新记录, offset 会让第二页混进已看过的条目。
 */
const AUDIT_LIMIT = 30;
let auditSt = {
  category: "", q: "", failed: false, paged: false, userDriven: false,
  before: 0, entries: [], facets: [], stats: {}, more: false,
};

function auditWhen(ts) {
  const d = Math.max(0, Math.floor(Date.now() / 1000) - ts);
  if (d < 60) return "刚刚";
  if (d < 3600) return `${Math.floor(d / 60)} 分钟前`;
  if (d < 86400) return `${Math.floor(d / 3600)} 小时前`;
  if (d < 86400 * 7) return `${Math.floor(d / 86400)} 天前`;
  return fmtTime(ts).slice(0, 10);
}

const auditClock = (ts) => new Date(ts * 1000).toLocaleTimeString("zh-CN", { hour12: false });

function auditDay(ts) {
  const d = new Date(ts * 1000), now = new Date();
  const same = (a, b) =>
    a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
  if (same(d, now)) return "今天";
  if (same(d, new Date(now.getTime() - 86400000))) return "昨天";
  return d.toLocaleDateString("zh-CN", { year: "numeric", month: "long", day: "numeric" });
}

function auditRow(e) {
  const times = e.count > 1
    ? `<span class="times" title="短时间内重复 ${e.count} 次, 已合并计数">×${e.count}</span>` : "";
  const risk = e.risk ? '<span class="risk" title="影响面较大的操作">◆</span>' : "";
  const who = e.actor
    ? `<span class="who" title="来源: ${escAttr(e.actor)}">${esc(e.actor)}</span>`
    : '<span class="who">—</span>';
  const tip = escAttr(`${fmtTime(e.ts)} · ${auditWhen(e.ts)} · ${e.ok ? "成功" : "失败"}`);
  return `<div class="audit-row${e.ok ? "" : " bad"}">
    <span class="dot ${e.ok ? "running" : "failed"}" title="${e.ok ? "成功" : "失败"}"></span>
    <span class="t" title="${tip}">${esc(auditClock(e.ts))}</span>
    <span class="what"><b>${esc(e.label)}</b>${risk}${times}<span class="code">${esc(e.action)}</span></span>
    <span class="detail" title="${escAttr(e.detail)}">${esc(e.detail) || "—"}</span>
    ${who}
  </div>`;
}

function renderAuditView() {
  const chips = $("#audit-chips");
  const list = $("#audit-list");
  if (!chips || !list) return;
  const st = auditSt.stats || {};
  const opts = [`<button class="chip${auditSt.category ? "" : " on"}" data-cat="">全部<span class="n">${st.retained || 0}</span></button>`]
    .concat((auditSt.facets || []).map(
      (f) => `<button class="chip${auditSt.category === f.id ? " on" : ""}" data-cat="${escAttr(f.id)}">${esc(f.label)}<span class="n">${f.count}</span></button>`
    ));
  chips.innerHTML = opts.join("");
  chips.querySelectorAll(".chip").forEach((b) => {
    b.onclick = () => {
      auditSt.category = b.dataset.cat || "";
      auditSt.paged = false;
      auditMark();
      auditLoad(true);
    };
  });

  if (!auditSt.entries.length) {
    list.innerHTML = `<div class="audit-empty">${auditSt.userDriven
      ? "没有匹配的记录 (换个分类或关键字试试)"
      : "还没有操作记录 — 登录、改配置、升级这些动作都会记在这里"}</div>`;
  } else {
    let html = "", day = "";
    auditSt.entries.forEach((e) => {
      const key = auditDay(e.ts);
      if (key !== day) { day = key; html += `<div class="audit-day">${esc(key)}</div>`; }
      html += auditRow(e);
    });
    list.innerHTML = html;
  }

  const parts = [];
  if (st.retained) parts.push(`保留 ${st.retained} 条`);
  if (st.failed) parts.push(`失败 ${st.failed}`);
  if (st.dropped) parts.push(`已归档 ${st.dropped} 条`);
  $("#audit-summary").textContent = parts.join(" · ") || "—";
  $("#audit-note").textContent = st.dropped && st.log
    ? `更早的记录滚动保存在服务器 ${st.log}` : "";
  $("#btn-audit-more").classList.toggle("hidden", !auditSt.more);
  const refresh = $("#btn-audit-refresh");
  if (refresh) refresh.textContent = auditSt.userDriven ? "回到最近" : "刷新";
}

function auditMark() {
  auditSt.userDriven = !!(auditSt.category || auditSt.q || auditSt.failed || auditSt.paged);
}

function bindAudit() {
  if (bindAudit.done) return;
  const q = $("#audit-q");
  if (!q) return;
  bindAudit.done = true;
  let timer = null;
  q.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      auditSt.q = q.value.trim();
      auditSt.paged = false;
      auditMark();
      auditLoad(true);
    }, 260);
  });
  $("#audit-failed").addEventListener("change", (e) => {
    auditSt.failed = e.target.checked;
    auditSt.paged = false;
    auditMark();
    auditLoad(true);
  });
  $("#btn-audit-more").addEventListener("click", () => {
    auditSt.paged = true;
    auditMark();
    auditLoad(false);
  });
  /* 清空: 记录会一直堆积 (面板保留最近 500 条, 更早的滚进归档文件), 得给一个出口。
   * 确认框里写清"只清面板保留的这部分, 服务器上的归档文件不动" —— 后者不可逆,
   * 不该由一个按钮顺手做掉。 */
  $("#btn-audit-clear").addEventListener("click", () => {
    const kept = (auditSt.stats || {}).retained || 0;
    openConfirm({
      title: "清空操作记录?",
      okLabel: `清空这 ${kept} 条`,
      html: `<div class="qr-sub">面板保留的 <b>${kept}</b> 条记录会被清掉, 只留下"清空操作记录"
        这一条, 方便回看是谁清的。<br><br>
        <b>服务器上的归档文件不会被删除</b> —— 更早滚出缓冲区的记录一直在
        <span class="mono">data/audit.log</span> 里, 需要时可以直接下载查看。</div>`,
      onOk: async () => {
        try {
          const body = await api("/api/audit/clear", { method: "POST" });
          // 清完回到默认视图 (筛选 / 搜索 / 翻页全部复位), 否则会停在一个空列表上
          auditSt.category = ""; auditSt.q = ""; auditSt.failed = false;
          auditSt.paged = false; auditSt.userDriven = false;
          q.value = "";
          $("#audit-failed").checked = false;
          auditSt.entries = body.entries || [];
          auditSt.facets = body.facets || [];
          auditSt.stats = body.stats || {};
          auditSt.more = !!body.has_more;
          auditSt.before = auditSt.entries.length ? auditSt.entries[auditSt.entries.length - 1].id : 0;
          renderAuditView();
          toast(`已清空 ${body.cleared || 0} 条记录`);
        } catch (e) {
          toast("清空失败: " + e.message);
        }
      },
    });
  });
  $("#btn-audit-refresh").addEventListener("click", () => {
    if (!auditSt.userDriven) { auditSt.paged = false; auditMark(); auditLoad(true); return; }
    // 有筛选时它是"回到最近": 清掉筛选与搜索框, 回到默认视图
    auditSt.category = ""; auditSt.q = ""; auditSt.failed = false; auditSt.paged = false;
    q.value = "";
    $("#audit-failed").checked = false;
    auditMark();
    auditLoad(true);
  });
}

async function auditLoad(reset) {
  const qs = new URLSearchParams({ limit: String(AUDIT_LIMIT) });
  if (auditSt.category) qs.set("category", auditSt.category);
  if (auditSt.q) qs.set("q", auditSt.q);
  if (auditSt.failed) qs.set("failed", "1");
  if (!reset && auditSt.before) qs.set("before", String(auditSt.before));
  try {
    const body = await api("/api/audit?" + qs.toString());
    auditSt.entries = reset ? (body.entries || []) : auditSt.entries.concat(body.entries || []);
    auditSt.facets = body.facets || [];
    auditSt.stats = body.stats || {};
    auditSt.more = !!body.has_more;
    auditSt.before = body.next_before || 0;
    renderAuditView();
  } catch (e) {
    toast("读操作记录失败: " + e.message);
  }
}

/** 仪表盘下发的那 20 条 (默认视图)。用户在用筛选时不要覆盖他的结果。 */
export function renderAudit(entries, facets, stats, more) {
  bindAudit();
  if (auditSt.userDriven) return;
  auditSt.entries = entries || [];
  auditSt.facets = facets || [];
  auditSt.stats = stats || {};
  auditSt.more = !!more;
  auditSt.before = auditSt.entries.length ? auditSt.entries[auditSt.entries.length - 1].id : 0;
  renderAuditView();
}
/** 操作记录视图 (谁 · 什么时候 · 做了什么 · 结果)。
 *
 *  这块的状态独立维护, 因为仪表盘每 20 秒会整块重画:
 *    - 默认视图 (没筛选、没翻页) 直接用仪表盘顺带下发的 20 条 + 各分类条数, 零额外请求;
 *    - 一旦筛选 / 搜索 / 翻页, 就切成"自己按 id 游标拉 /api/audit", 并且不再让仪表盘的
 *      重画覆盖它 (清空筛选或点「刷新」即回到默认视图);
 *    - 分页用 id 游标而不是 offset: 翻页期间随时会来新记录, offset 会让第二页混进
 *      已看过的条目。
 */
import { $, esc, escAttr, toast } from "../lib/dom.js";
import { openConfirm } from "../lib/dialog.js";
import { fmtTime } from "../lib/format.js";
import { api } from "../lib/api.js";
