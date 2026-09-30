/** 节点表 + 顶部指标条 + 顶部告警横幅。
 *
 *  合在一个模块里是因为它们互相调用得很紧: 节点表 → renderProbe → renderKpis →
 *  renderSidebar, 拆开就得来回 import。对外只暴露 renderNodes / renderKpis /
 *  renderDashboardBanner / runProbe。
 */
import { $, esc, escAttr, toast, copyText } from "../lib/dom.js";
import {
  fmtBytes, fmtUptime, fmtTime, STATE_TXT, stateClass, nodeStateClass, nodeStateText, PROTO_BADGE,
} from "../lib/format.js";
import { api } from "../lib/api.js";
import { openQr } from "../lib/dialog.js";
import { S } from "../lib/state.js";
import { settleApply } from "../lib/jobs.js";
import { renderBanner } from "../lib/render.js";

export function renderDashboardBanner() {
  const steps = (S.dash && S.dash.steps) || [];
  const failed = steps.filter((s) => !s.ok);
  if (failed.length) {
    const first = failed[0];
    return renderBanner(
      $("#dash-banner"),
      "bad",
      `上次配置落地有 ${failed.length} 步失败, 节点可能不可用`,
      `${first.name}: ${first.detail} —— 点右上角「一键诊断」查看, 或点「一键修复」重试`
    );
  }
  // 用 IP 打开面板时会一直看到"证书不受信任", 这里给一条能点过去的出口
  const onIp = S.dash.system && S.dash.system.prod && location.hostname !== S.dash.domain;
  if (onIp) {
    const certOk = (S.dash.cert || {}).type === "letsencrypt";
    return renderBanner(
      $("#dash-banner"),
      certOk ? "info" : "bad",
      "你正在用 IP 地址访问面板 (证书不受浏览器信任)",
      certOk
        ? `正式入口是 ${S.dash.panel_url}, 证书由 Let's Encrypt 签发。切换过去后需要重新登录一次。`
        : `正式入口是 ${S.dash.panel_url}, 但它现在还是自签证书 (域名未解析到本机 / 80 端口被挡), ` +
          "切过去仍会提示证书问题 —— 先点右上角「一键诊断」, 再到「系统 → 申请证书」重试。",
      { label: "切到域名面板", href: S.dash.panel_url }
    );
  }
  renderBanner($("#dash-banner"), "bad", "");
}

/* ---------------- 节点卡片 + 测速 ---------------- */
function pingOf(nodeId) {
  if (!S.probeData) return null;
  return (S.probeData.nodes || []).find((p) => p.node === nodeId) || null;
}

function pingHtml(nodeId) {
  const p = pingOf(nodeId);
  if (!p) return "";
  const text = p.ok === true ? (p.ms ? p.ms + "ms" : "可达") : p.ok === false ? "握手失败" : "未知";
  const cls = p.ok === true ? "ok" : p.ok === false ? "bad" : "other";
  return ` <span class="ping ${cls}" title="${escAttr(p.detail || "")}">${esc(text)}</span>`;
}

/* 延迟条宽度: 最快的节点画满, 最慢的画到 40% —— 一眼看出谁快谁慢。
 * 只有 1 个结果 (或全部相等) 时直接画满, 免得所有条都退化成同一长度。 */
function latPct(ms, min, max) {
  if (!(max > min)) return 100;
  return Math.round(40 + 60 * ((max - ms) / (max - min)));
}

export function renderNodes() {
  const nodes = S.dash.nodes || [];
  const on = nodes.filter((n) => n.enabled).length;
  const ms = ((S.probeData && S.probeData.nodes) || []).filter((p) => p.ok === true && p.ms).map((p) => p.ms);
  const minMs = ms.length ? Math.min(...ms) : 0;
  const maxMs = ms.length ? Math.max(...ms) : 0;
  // 流量双轨按"全节点单向上行/下行的最大值"归一化, 全是 0 时不会除零
  const peak = Math.max(
    1,
    ...nodes.map((n) => (n.traffic ? Math.max(n.traffic.uplink || 0, n.traffic.downlink || 0) : 0))
  );
  const barPct = (v) => (v > 0 ? Math.max(6, Math.round((v / peak) * 100)) : 0);

  const count = $("#node-count");
  if (count) count.textContent = nodes.length ? `${on} 启用 / 共 ${nodes.length}` : "—";

  $("#node-grid").innerHTML = nodes
    .map((n) => {
      const p = pingOf(n.id);
      // 左侧: 名称 / 传输 / 说明 / 链式出口 / 告警
      const left = `<div>
          <div class="top">
            <span class="name">${
              n.chain
                ? '<span class="badge hysteria" title="链式中转: 客户端连本机, 出口 IP 是落地服务器">链式</span>'
                : `<span class="badge ${PROTO_BADGE[n.protocol] || "vless"}">${esc(n.protocol)}</span>`
            }<span class="nm">${esc(n.name)}</span>${
              n.default_out ? '<span class="badge trojan">默认出口</span>' : ""
            }</span>
          </div>
          <div class="meta">${esc(n.transport)} · ${esc(n.security)}</div>
          <div class="muted nc-desc" title="${escAttr(n.desc || "")}">${esc(n.desc || "")}</div>
          ${
            n.chain && n.last_probe && n.last_probe.exit_ip
              ? `<div class="muted fs-xs mt-1">落地出口 IP ${esc(n.last_probe.exit_ip)}${
                  n.last_probe.tcp_ms ? " · 链路 " + Math.round(n.last_probe.tcp_ms) + "ms" : ""
                }</div>`
              : ""
          }
          ${n.note ? `<div class="note">${esc(n.note)}</div>` : ""}
        </div>`;

      // 第二列: 地址 + 服务状态
      const addr = `<div class="nc-addr">
          <div class="addr mono" title="${escAttr(n.host + ":" + n.port)}">${esc(n.host)}:${n.port}</div>
          <div class="state"><span class="dot ${nodeStateClass(n)}" title="${escAttr(n.service || "")}"></span>
            <span class="muted">${esc(nodeStateText(n))}</span></div>
        </div>`;

      // 第三列: 握手延迟 (徽标 + 长度条)
      let lat = `<div class="nc-lat"><span class="muted fs-xs">未测速</span></div>`;
      if (p) {
        const cls = p.ok === true ? "ok" : p.ok === false ? "bad" : "other";
        const text = p.ok === true ? (p.ms ? p.ms + "ms" : "可达") : p.ok === false ? "握手失败" : "未知";
        const bar =
          p.ok === true && p.ms
            ? `<span class="latbar"><i class="${p.ms <= 120 ? "ok" : p.ms <= 250 ? "warn" : "bad"}"
                 style="width:${latPct(p.ms, minMs, maxMs)}%"></i></span>`
            : "";
        lat = `<div class="nc-lat"><span class="ping ${cls}" title="${escAttr(p.detail || "")}">${esc(text)}</span>${bar}</div>`;
      }

      // 第四列: 该节点上下行 (数字 + 双轨条)
      const tr = n.traffic || null;
      const traffic = tr
        ? `<div class="nc-traffic">
             <div class="vals">↑${fmtBytes(tr.uplink)} · ↓${fmtBytes(tr.downlink)}</div>
             <div class="duo">
               <span class="rail up" title="上行 ${fmtBytes(tr.uplink)}"><i style="width:${barPct(tr.uplink)}%"></i></span>
               <span class="rail dn" title="下行 ${fmtBytes(tr.downlink)}"><i style="width:${barPct(tr.downlink)}%"></i></span>
             </div>
           </div>`
        : `<div class="nc-traffic"><span class="muted fs-xs">—</span></div>`;

      return `<div class="card node-card">
        ${left}
        ${addr}
        ${lat}
        ${traffic}
        <div class="actions">
          ${n.share_link
            ? `<button class="btn ghost small" data-copy="${escAttr(n.id)}" title="复制 ${escAttr(n.name)} 的分享链接">复制</button>
               <button class="btn ghost small" data-qr="${escAttr(n.id)}" title="显示 ${escAttr(n.name)} 的二维码">二维码</button>`
            : `<span class="muted fs-sm">已关闭</span>`}
          <label class="switch" title="${n.enabled ? "点击停用" : "点击启用"}">
            <input type="checkbox" data-node="${escAttr(n.id)}" ${n.enabled ? "checked" : ""}>
            <span class="slider"></span></label>
        </div>
      </div>`;
    })
    .join("");

  document.querySelectorAll("[data-node]").forEach((el) =>
    (el.onchange = async () => {
      el.disabled = true;
      try {
        const steps = await settleApply(
          await api(`/api/nodes/${el.dataset.node}/toggle`, { method: "POST" })
        );
        const failed = steps.filter((s) => !s.ok);
        toast(failed.length ? `已应用, 但 ${failed.length} 步告警: ${failed[0].name}`
                            : "已热更新, 订阅内容已刷新");
      } catch (e) {
        el.disabled = false;
        toast("操作失败: " + e.message);
      }
    })
  );
  document.querySelectorAll("[data-copy]").forEach((el) =>
    (el.onclick = () => copyText(S.dash.nodes.find((n) => n.id === el.dataset.copy).share_link))
  );
  document.querySelectorAll("[data-qr]").forEach((el) => {
    const n = S.dash.nodes.find((x) => x.id === el.dataset.qr);
    el.onclick = () =>
      openQr({
        title: `${n.name} 二维码`,
        sub: `${n.transport} · ${n.host}:${n.port}`,
        link: n.share_link,
        svg: `${n.qr_url}?img=svg`,
        png: `${n.qr_url}?size=8`,
        file: `zeroproxy-${n.id}.png`,
      });
  });
  renderProbe();
}

function renderProbe() {
  const el = $("#probe-summary");
  if (!el) return;
  if (!S.probeData) {
    el.innerHTML = `<span class="note">点「节点测速」用真实客户端从每个节点穿一次外网 (深度握手, 能查出 Reality 密钥 / SNI / 伪装目标不匹配), 并测量服务器到伪装目标的出口延迟。本地开发环境下自动降级为裸握手。</span>`;
    return;
  }
  const when = fmtTime(S.probeData.checked_at);
  const dest = S.probeData.dest || {};
  el.innerHTML =
    `<span class="ping ${dest.ok ? "ok" : "bad"}">出口 ${dest.ms ? dest.ms + "ms" : "不可达"}</span>` +
    `<span class="note">${esc(S.probeData.summary)} · 伪装目标 ${esc(dest.address || "")} · ${esc(when)}</span>`;
  renderKpis();
}

/* ---------------- 顶部指标条 ----------------
 * 全部数据都来自已经拉到的 /api/dashboard 与 /api/probe, 不额外发请求。 */
function chainEgress() {
  // 只看启用中的链路, 且优先"默认出口": 停用的那条还留着上次的探测结果,
  // 拿它当"当前出口 IP"就是假的
  const entries = (((S.dash || {}).chain || {}).entries || []).filter((e) => e.enabled);
  const hit =
    entries.find((e) => e.default_out && ((e.last_probe || {}).exit_ip || "").trim()) ||
    entries.find((e) => ((e.last_probe || {}).exit_ip || "").trim());
  if (!hit) return null;
  const p = hit.last_probe || {};
  // tcp_ms 才是"入口→落地"这一跳的链路延迟; ms 是整段探测的总耗时 (起临时客户端 +
  // 问一次回显服务), 拿它当延迟显示会把人吓到 (跨洋实测能到 1 秒以上)。
  return { ip: p.exit_ip, label: hit.label || hit.host, ms: p.ms || 0, tcp_ms: p.tcp_ms || 0 };
}

/** 可点击复制的 IP。CSP 不允许内联事件, 所以渲染完统一用 bindIpCopy 绑。 */
function ipChip(ip, title, prefix = "") {
  return `${prefix}<span class="copy-ip" data-copy-ip="${escAttr(ip)}" title="${escAttr(title)}">${esc(ip)}</span>`;
}

function bindIpCopy(root) {
  root.querySelectorAll("[data-copy-ip]").forEach((el) => {
    el.onclick = () => copyText(el.dataset.copyIp);
  });
}

export function renderKpis() {
  if (!S.dash) return;
  const nodes = S.dash.nodes || [];
  const on = nodes.filter((n) => n.enabled).length;
  const probes = ((S.probeData && S.probeData.nodes) || []).filter((p) => p.ok === true && p.ms);
  const ms = probes.map((p) => p.ms);

  const kn = $("#kpi-nodes");
  if (kn) {
    kn.innerHTML = `${on}<small> / ${nodes.length}</small>`;
    $("#kpi-nodes-sub").innerHTML = nodes.length
      ? nodes.slice(0, 14).map((n) => `<span class="dot ${nodeStateClass(n)}" title="${escAttr(
          n.name + " · " + nodeStateText(n))}"></span>`).join("") +
        (on === nodes.length ? " 全部启用" : ` 已停用 ${nodes.length - on} 个`)
      : "—";
  }
  const eg = $("#kpi-egress");
  if (eg) {
    const e = chainEgress();
    const srv = ((S.dash.system || {}).server || {});
    const localIp = srv.public_ip || "";
    // 不挂链时"出口"就是本机; 挂了链才是落地端 —— 但本机 IP 两个场景下都要能看见,
    // 那才是用户要填进客户端的地址 (以前卡片只显示落地 IP, 本机 IP 无处可查)。
    const exitIp = e ? e.ip : localIp;
    eg.innerHTML = exitIp ? ipChip(exitIp, "点击复制出口 IP") : "—";
    const sub = [];
    if (e && localIp) sub.push(ipChip(localIp, "点击复制本机 IP", "本机 "));
    if (e) sub.push(`链式 · ${esc(e.label)}${e.tcp_ms ? " · 链路 " + Math.round(e.tcp_ms) + "ms" : ""}`);
    else if (localIp) sub.push("本机公网 IP · 点击可复制");
    else if (srv.public_ip_at) sub.push("本机公网 IP 读取失败 (回显服务不可达)");
    else sub.push(
      (S.dash.chain && S.dash.chain.exit && S.dash.chain.exit.enabled)
        ? "本机是落地端, 等对方接入"
        : "正在读取本机公网 IP…"
    );
    $("#kpi-egress-sub").innerHTML = sub.join(" · ");
    bindIpCopy(eg.parentElement || document);
  }
  const kl = $("#kpi-lat");
  if (kl) {
    kl.innerHTML = ms.length ? `${Math.round(ms.reduce((a, b) => a + b, 0) / ms.length)}<small> ms</small>` : "—";
    $("#kpi-lat-sub").textContent = ms.length
      ? `最快 ${Math.min(...ms)} – 最慢 ${Math.max(...ms)}ms · ${ms.length}/${on} 个节点有结果`
      : "点「节点测速」后更新";
    renderLatSpark(ms);
  }
  const ku = $("#kpi-uptime");
  if (ku) {
    const srv = (S.dash.system && S.dash.system.server) || {};
    ku.textContent = srv.uptime_s ? fmtUptime(srv.uptime_s) : "—";
    $("#kpi-uptime-sub").textContent = srv.os ? `${srv.os} · ${srv.arch || ""}` : "—";
  }
  // 顶部状态药丸: 三个服务都正常才算"面板运行中"; 本地开发 (dry-run) 只是提示, 不算故障
  const st = $("#dash-state");
  if (st && S.dash.system) {
    const states = [S.dash.system.xray, S.dash.system.hysteria2, S.dash.system.nginx].map((s) => (s || {}).state);
    const bad = states.filter((s) => ["failed", "inactive"].includes(s)).length;
    const dev = !bad && states.some((s) => s === "dry-run");
    st.className = "pill " + (bad ? "bad" : dev ? "warn" : "ok");
    st.innerHTML = `<span class="dot ${bad ? "failed" : dev ? "other" : "running"}"></span>` +
      (bad ? `${bad} 个服务异常` : dev ? "本地开发模式" : "面板运行中");
  }
  renderSidebar();
}

/* 侧栏: 管理员 / 主机 / 在线 / 版本 + 各锚点的计数与告警角标 */
export function renderSidebar() {
  if (!S.dash) return;
  const srv = (S.dash.system && S.dash.system.server) || {};
  const set = (sel, text) => { const el = $(sel); if (el) el.textContent = text; };
  set("#side-user", S.dash.admin_user || "—");
  const os = $("#side-os");
  if (os) {
    os.textContent = srv.os ? `${srv.os} · ${srv.arch || ""}` : "—";
    os.title = srv.os ? `${srv.os} · ${srv.arch || ""}` : "";
  }
  set("#side-uptime", srv.uptime_s ? fmtUptime(srv.uptime_s) : "—");
  set("#side-ver", srv.panel_version ? `v${srv.panel_version}` : "—");

  const nodes = S.dash.nodes || [];
  const on = nodes.filter((n) => n.enabled).length;
  set("#nav-nodes", nodes.length ? `${on}/${nodes.length}` : "—");
  const entries = ((S.dash.chain || {}).entries) || [];
  set("#nav-chain", entries.length ? String(entries.length) : "");
  const up = S.updateInfo || {};
  set("#nav-update", up.update_available ? "新" : up.running ? "…" : "");

  const diag = $("#nav-diag");
  if (diag) {
    const r = S.diagRes;
    diag.textContent = !r ? "" : r.ok ? "✓" : `${(r.checks || []).filter((c) => !c.ok).length}`;
    diag.style.color = !r ? "" : r.ok ? "var(--ok)" : "var(--err)";
  }

  // 操作记录: 有失败就标红并只显示失败数, 否则显示保留的条数
  const au = S.dash.audit_stats || {};
  const navAudit = $("#nav-audit");
  if (navAudit) {
    const bad = au.failed || 0;
    navAudit.textContent = bad ? String(bad) : (au.retained ? String(au.retained) : "");
    navAudit.style.color = bad ? "var(--err)" : "";
    navAudit.title = bad
      ? `${bad} 条失败 / 共保留 ${au.retained || 0} 条`
      : `共保留 ${au.retained || 0} 条操作记录`;
  }
}

/* 延迟迷你折线 (KPI 第 3 格): 每个有结果的节点一个采样点。
 * 用 polyline 而不是曲线, 峰值一眼可读; 只有 1 个点时画一段平线。 */
function renderLatSpark(ms) {
  const svg = $("#kpi-lat-spark");
  if (!svg) return;
  if (!ms.length) { svg.innerHTML = ""; return; }
  const W = 120, H = 22, pad = 3;
  const max = Math.max(...ms), min = Math.min(...ms);
  const span = max - min || 1;
  const pts = ms.map((v, i) => {
    const x = ms.length === 1 ? W : (i / (ms.length - 1)) * W;
    const y = H - pad - ((max - v) / span) * (H - pad * 2);
    return [x, y];
  });
  const line = pts.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  const area = `${pts[0][0].toFixed(1)},${H} ${line} ${pts[pts.length - 1][0].toFixed(1)},${H}`;
  svg.innerHTML =
    `<polygon points="${area}" fill="var(--accent)" opacity="0.13"></polygon>` +
    `<polyline points="${line}" fill="none" stroke="var(--accent)" stroke-width="1.6"
       stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke"></polyline>` +
    `<circle cx="${pts[pts.length - 1][0].toFixed(1)}" cy="${pts[pts.length - 1][1].toFixed(1)}" r="2"
       fill="var(--accent)"></circle>`;
}

export async function runProbe(force) {
  const btn = $("#btn-probe");
  if (!btn || btn.disabled) return;
  btn.disabled = true;
  const original = btn.textContent;
  btn.textContent = "测速中…";
  const grid = $("#node-grid");
  if (grid) grid.classList.add("probing");   // 逐行呼吸, 提示"正在重新握手"
  try {
    S.probeData = await api("/api/probe?deep=1" + (force ? "&force=1" : ""));
    renderNodes();
  } catch (e) {
    toast("测速失败: " + e.message);
  }
  if (grid) grid.classList.remove("probing");
  btn.disabled = false;
  btn.textContent = original;
}

$("#btn-probe").onclick = () => runProbe(true);
