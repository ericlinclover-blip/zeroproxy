/** 流量可视化 + 高级设置 + 系统卡片。
 *
 *  三块放在一起是因为它们共用同一个"改设置 → 落地 → 回灌"的收尾 (settleApply),
 *  且系统卡片里的证书 / 服务状态与仪表盘其它部分没有交叉。
 */
import { $, esc, escAttr, toast } from "../lib/dom.js";
import { fmtBytes, fmtUptime, fmtTime, STATE_TXT, stateClass } from "../lib/format.js";
import { clearDraft } from "../lib/drafts.js";
import { api, markDisconnected, syncAfterDrop } from "../lib/api.js";
import { S, rateHist, redrawDash, reloadDash } from "../lib/state.js";
import { awaitJob, settleApply, applyAction } from "../lib/jobs.js";
import { openConfirm } from "../lib/dialog.js";

/* ---------------- 流量可视化 ----------------
 * 三块:
 *   1. 双弧圆环 (上/下行占比, stroke-dasharray 驱动, 值变化时 CSS 自己补间)
 *   2. 逐节点上下行双轨条 (归一化到全节点峰值, 带流光扫过)
 *   3. 实时速率曲线 —— 面板自己没有历史数据, 所以由本页每 20s 采一次样,
 *      在内存里留 24 个点 (≈8 分钟) 画出来; 刷新页面会重新开始采样。 */
const RING_C = 2 * Math.PI * 50;   // r=50 的周长, 与 <circle r="50"> 对应

export function renderTraffic(traffic) {
  const empty = $("#traffic-empty");
  const main = $("#traffic-main");
  if (!empty || !main) return;
  const available = !!traffic && traffic.available !== false && !!S.dash.traffic;
  empty.classList.toggle("hidden", available);
  main.classList.toggle("hidden", !available);
  const note = $("#traffic-note");
  if (note) note.textContent = available ? `更新于 ${fmtTime(Math.floor(Date.now() / 1000))}` : "Xray 未运行";
  if (!available) { rateHist.length = 0; return; }

  const up = Number(traffic.uplink) || 0;
  const dn = Number(traffic.downlink) || 0;
  const total = Math.max(1, Number(traffic.total) || 0);
  const upLen = (up / total) * RING_C;
  const dnLen = (dn / total) * RING_C;

  const arcUp = $("#tr-arc-up"), arcDn = $("#tr-arc-dn");
  if (arcUp) arcUp.setAttribute("stroke-dasharray", `${upLen.toFixed(2)} ${(RING_C - upLen).toFixed(2)}`);
  if (arcDn) {
    arcDn.setAttribute("stroke-dasharray", `${dnLen.toFixed(2)} ${(RING_C - dnLen).toFixed(2)}`);
    arcDn.setAttribute("stroke-dashoffset", (-upLen).toFixed(2));   // 接在上行弧后面, 不重叠
  }
  const tt = $("#tr-total");
  if (tt) tt.textContent = fmtBytes(up + dn);
  const tv = (id, v) => { const el = $(id); if (el) el.textContent = v; };
  tv("#tr-up", fmtBytes(up));
  tv("#tr-down", fmtBytes(dn));

  const rows = (S.dash.nodes || []).filter((n) => n.traffic);
  tv("#tr-nodes", rows.length ? `${rows.length} 个` : "—");

  // 每条 = 一根"上下行分色"的条: 蓝=上行, 青=下行, 灰=剩余。
  // 归一化基准取"最忙节点的合计流量", 所以蓝+青正好等于该节点占最忙节点的比例 (不虚高)。
  const peak = Math.max(1, ...rows.map((n) => (n.traffic.uplink || 0) + (n.traffic.downlink || 0)));
  const bars = $("#tr-bars");
  if (bars) {
    bars.innerHTML = rows
      .map((n) => {
        const u = n.traffic.uplink || 0, d = n.traffic.downlink || 0;
        const sum = u + d;
        const share = Math.round((sum / (Number(traffic.total) || 1)) * 100);
        const w = (v) => (v > 0 ? Math.max(1.5, Math.round((v / peak) * 1000) / 10) : 0);
        return `<div class="trow">
          <span class="nm">${esc(n.name)}</span>
          <span class="val">↑${fmtBytes(u)} ↓${fmtBytes(d)} · ${share}%</span>
          <span class="rail" title="上行 ${fmtBytes(u)} / 下行 ${fmtBytes(d)}">
            <i class="up" style="width:${w(u)}%"></i><i class="dn" style="width:${w(d)}%"></i>
          </span>
        </div>`;
      })
      .join("");
  }
  sampleRate();
}

/* 采样一次累计流量 → 画实时速率曲线 (本页内存, 不落盘) */
function sampleRate() {
  const t = S.dash && S.dash.traffic;
  if (!t || t.available === false) return;
  const now = Date.now();
  const total = Math.max(0, Number(t.total) || 0);
  const last = rateHist[rateHist.length - 1];
  if (last && total < last.total) rateHist.length = 0;        // Xray 重启, 计数器归零
  const tail = rateHist[rateHist.length - 1];
  const sample = { t: now, total, up: Math.max(0, Number(t.uplink) || 0), dn: Math.max(0, Number(t.downlink) || 0) };
  if (tail && now - tail.t < 12000) Object.assign(tail, sample);   // 12s 内的重复渲染只更新最新值
  else rateHist.push(sample);
  if (rateHist.length > 24) rateHist.splice(0, rateHist.length - 24);
  renderRate();
}

function renderRate() {
  const nowEl = $("#rate-now"), hintEl = $("#rate-hint");
  const lineEl = $("#rate-line"), areaEl = $("#rate-area");
  if (!nowEl || !lineEl) return;
  const W = 320, H = 46, padTop = 4, base = H - 3;

  // 相邻两点的差值就是这一段的平均速率 (总 / 上 / 下各一条)
  const rates = [], ups = [], dns = [];
  for (let i = 1; i < rateHist.length; i += 1) {
    const a = rateHist[i - 1], b = rateHist[i];
    const dt = Math.max(1, (b.t - a.t) / 1000);
    rates.push(Math.max(0, (b.total - a.total) / dt));
    ups.push(Math.max(0, ((b.up || 0) - (a.up || 0)) / dt));
    dns.push(Math.max(0, ((b.dn || 0) - (a.dn || 0)) / dt));
  }
  if (!rates.length) {
    nowEl.textContent = "—";
    if (hintEl) hintEl.textContent = "本页打开后开始采样, 每 20s 一点";
    // 一个采样点也画不出趋势 —— 宁可空着, 也不画一条假的平线
    lineEl.setAttribute("d", "");
    if (areaEl) areaEl.setAttribute("d", "");
    const cur = $("#rate-cursor"), head = $("#rate-head");
    // 用 inline style 而不是 opacity 属性: CSS 规则 (.spark .cursor{opacity:.6}) 会盖掉属性
    if (cur) cur.style.opacity = "0";
    if (head) head.style.opacity = "0";
    return;
  }
  const peak = Math.max(...rates, 1);
  // 只用过一个采样点时画成一条平线 (表示"当前就是这个速率"), 而不是一个看不见的点
  const series = rates.length === 1 ? [rates[0], rates[0]] : rates;
  const pts = series.map((v, i) => {
    const x = (i / (series.length - 1)) * W;
    return [x, base - (v / peak) * (base - padTop)];
  });
  const d = pts.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)}`).join(" ");
  lineEl.setAttribute("d", d);
  if (areaEl) {
    areaEl.setAttribute("d", `M${pts[0][0].toFixed(1)} ${base} ${d.slice(1)} L${pts[pts.length - 1][0].toFixed(1)} ${H} L${pts[0][0].toFixed(1)} ${H} Z`);
  }
  const lastPt = pts[pts.length - 1];
  const cur = $("#rate-cursor"), head = $("#rate-head");
  if (cur) {
    cur.style.opacity = "0.6";
    cur.setAttribute("x1", lastPt[0].toFixed(1)); cur.setAttribute("x2", lastPt[0].toFixed(1));
    cur.setAttribute("y1", "0"); cur.setAttribute("y2", String(H));
  }
  if (head) {
    head.style.opacity = "1";
    head.setAttribute("cx", lastPt[0].toFixed(1)); head.setAttribute("cy", lastPt[1].toFixed(1));
  }
  nowEl.textContent = `↑${fmtBytes(ups[ups.length - 1])}/s · ↓${fmtBytes(dns[dns.length - 1])}/s`;
  if (hintEl) {
    hintEl.textContent = `${rateHist.length} 点 · 峰值合计 ${fmtBytes(peak)}/s`;
  }
}

export function renderAdvanced(d) {
  $("#adv-sni").value = d.reality.server_name || "";
  $("#adv-masq").value = (d.hysteria_masquerade && d.hysteria_masquerade.url) || "";
  // 端口这一格只在"节点集合变了"时重建 DOM: 每 20s 整块重画会把正在输入的数字
  // 连同光标一起冲掉 (草稿保护能救回值, 但没必要每次都重画)
  const portNodes = d.nodes.filter((n) => n.editable_port);
  const grid = $("#port-grid");
  const signature = portNodes.map((n) => `${n.id}`).join(",");
  if (grid.dataset.signature !== signature) {
    grid.dataset.signature = signature;
    grid.innerHTML = portNodes
      .map(
        (n) => `<div class="field">
        <label>${esc(n.name)}</label>
        <input class="mono" data-port-node="${escAttr(n.id)}" inputmode="numeric">
      </div>`
      )
      .join("");
  }
  portNodes.forEach((n) => {
    const input = grid.querySelector(`[data-port-node="${n.id}"]`);
    if (input && input.value !== String(n.port) && input.dataset.draft !== "1") input.value = n.port;
  });
  const hop = $("#adv-hopping");
  if (hop) {
    hop.checked = !!d.hysteria_hopping;
    hop.onchange = () =>
      applyAction("POST", "/api/hysteria/hopping", undefined, null);
    const ports = (d.hysteria_ports || []).join(" / ");
    $("#adv-hopping-note").textContent = d.hysteria_hopping
      ? `${ports} · 同时监听 3 个 UDP 端口, 封锁单个端口不影响使用 (仅 Linux 生效)`
      : "关闭后只监听主端口 (同一端口被反复封锁时再打开)";
  }
  $("#btn-save-adv").onclick = saveAdvanced;
  renderRouting(d);
  renderGeo(d);
}

function renderRouting(d) {
  const r = d.routing || {};
  const templates = r.templates || [];
  const sel = $("#adv-template");
  if (!sel) return;
  sel.innerHTML = templates
    .map((t) => `<option value="${escAttr(t.id)}">${esc(t.name)}</option>`)
    .join("");
  sel.value = r.template || "smart";
  const showDesc = () => {
    const t = templates.find((x) => x.id === sel.value);
    $("#adv-template-desc").textContent = t ? t.desc : "";
  };
  showDesc();
  const previous = sel.value;
  sel.onchange = async () => {
    try {
      await settleApply(
        await api("/api/settings", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ template: sel.value }),
        })
      );
      toast("分流模板已切换, 订阅即刻生效");
    } catch (e) {
      sel.value = previous;
      showDesc();
      toast("切换失败: " + e.message);
    }
  };
}

function renderGeo(d) {
  const g = d.geodata || {};
  const files = g.files || {};
  const ready = Object.values(files).filter((f) => f.exists).length;
  $("#geo-private").checked = g.block_private !== false;
  $("#geo-ads").checked = g.block_ads !== false;
  let text;
  if (!ready) text = "数据未下载 (分流暂不生效)";
  else if (g.active) text = `${g.age_days >= 0 ? g.age_days + " 天前更新" : "已就绪"} · 分流已启用`;
  else text = `${g.age_days >= 0 ? g.age_days + " 天前更新" : "已就绪"} · 分流已关闭`;
  $("#geo-status").textContent = text;
  // 上次为什么没下下来 —— 以前只在 toast 里闪 2.4 秒, 用户回头再看就只剩
  // "数据未下载"这几个字, 完全不知道是镜像不可达还是校验没过
  const note = $("#geo-note");
  if (note) {
    const why = String(g.last_error || "");
    note.textContent = why ? `上次更新失败: ${why}` : "";
    note.classList.toggle("hidden", !why);
  }

  const save = async (payload, revert) => {
    try {
      await settleApply(
        await api("/api/settings", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        })
      );
      toast("分流设置已应用");
    } catch (e) {
      toast("设置失败: " + e.message);
      revert();
    }
  };
  // 打开任一开关时顺带启用分流 (数据缺失时后端会明确报错)
  const withEnable = (extra) => (g.enabled ? extra : { ...extra, geodata_enabled: true });
  $("#geo-private").onchange = () =>
    save(withEnable({ block_private: $("#geo-private").checked }), () => renderGeo(S.dash));
  $("#geo-ads").onchange = () =>
    save(withEnable({ block_ads: $("#geo-ads").checked }), () => renderGeo(S.dash));
  $("#btn-geo-update").onclick = async () => {
    const btn = $("#btn-geo-update");
    btn.disabled = true;
    btn.textContent = "下载中… (约 28 MB)";
    const before = S.dash ? JSON.stringify(S.dash) : "";       // 断线后比对"到底更新了没"
    const stamp = ((S.dash || {}).geodata || {}).updated_at || 0;
    try {
      const res = await api("/api/geodata/update", { method: "POST" });
      S.dash = res;
      redrawDash(true);
      // 下载 + 校验 + 重新落地是后台任务 (真机上十几秒到几分钟), 这里等它跑完,
      // 期间顶部的进度条会显示"第几步 / 在做什么 / 已用多久"
      await awaitJob(res);
      const job = S.lastApplyJob;
      if (job && job.state === "running") {
        // 还没跑完 (慢线路), 不能报成功也不能报失败 —— 说清它还在后台跑
        toast("还在后台下载 GeoIP 数据, 顶部进度条会继续走; 完成后卡片会自己刷新");
      } else if (!res.ok || (job && (job.state === "failed" || job.error))) {
        const stepFail = job && (job.steps || []).find((s) => !s.ok);
        const why = (job && (job.error || (stepFail && stepFail.detail))) || res.detail || "";
        toast("更新失败: " + String(why).slice(0, 120));
      } else {
        toast("GeoIP 数据已更新并生效");
      }
      await reloadDash(true);   // 重新拉一次: 卡片要把数据状态 / 失败原因显示出来
    } catch (e) {
      if (e.dropped) {
        // 重启内核 (下载完要热重载) 会掐断"走本机链路访问面板"的浏览器 ——
        // 请求断了不等于更新失败, 数据很可能已经落好了。等连接回来再看真相。
        markDisconnected("重启内核中, 正在确认更新结果…");
        await syncAfterDrop(before);
        const now = ((S.dash || {}).geodata || {}).updated_at || 0;
        toast(now > stamp ? "GeoIP 数据已更新并生效" : "连接已恢复, 更新结果请以卡片状态为准");
      } else if (e.status === 409) {
        // 后台自动更新正在跑 (或上一次还没结束): 这不是"失败", 等一下再点就行
        toast("先等一下: " + e.message);
      } else {
        toast("更新失败: " + e.message);
      }
    }
    btn.disabled = false;
    btn.textContent = "下载 / 更新 GeoIP 数据";
  };
}

async function saveAdvanced() {
  const btn = $("#btn-save-adv");
  const ports = {};
  document.querySelectorAll("[data-port-node]").forEach((el) => {
    const value = parseInt(el.value, 10);
    const nodeId = el.dataset.portNode;
    const current = (S.dash.nodes.find((n) => n.id === nodeId) || {}).port;
    if (!Number.isNaN(value) && value !== current) ports[nodeId] = value;
  });
  const payload = {
    reality_sni: $("#adv-sni").value.trim(),
    masquerade_url: $("#adv-masq").value.trim(),
  };
  if (Object.keys(ports).length) payload.ports = ports;
  if (payload.reality_sni === S.dash.reality.server_name
      && payload.masquerade_url === ((S.dash.hysteria_masquerade || {}).url || "")
      && !payload.ports) {
    toast("没有需要修改的内容");
    return;
  }
  btn.disabled = true;
  btn.textContent = "应用中…";
  try {
    const steps = await settleApply(
      await api("/api/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      })
    );
    // 提交成功 → 解除草稿保护, 让服务器值 (含后端规范化, 如 SNI 转小写) 正常回灌
    clearDraft("#adv-sni, #adv-masq, [data-port-node]");
    const failed = steps.filter((s) => !s.ok);
    toast(failed.length ? `已应用, 但 ${failed.length} 步告警: ${failed[0].name}`
                        : "设置已应用, 订阅内容已刷新");
  } catch (e) {
    toast("保存失败: " + e.message);
  }
  btn.disabled = false;
  btn.textContent = "保存并应用";
}

export function renderSystem(d) {
  const c = d.cert;
  const certName = c.type === "letsencrypt" ? "Let's Encrypt" : c.type === "selfsigned" ? "自签名证书" : "无证书";
  const days = c.days_left;
  const barPct = days > 90 ? 100 : days > 30 ? Math.round((days / 90) * 100) : Math.round((days / 30) * 100);
  const barColor = days > 30 ? "var(--ok)" : days > 14 ? "var(--warn)" : "var(--err)";
  const sys = d.system;
  const svcRow = (k, v) =>
    `<div class="kv"><span class="k">${esc(k)}</span><span><span class="dot ${stateClass(v.state)}"></span> ${STATE_TXT[v.state] || esc(v.state)}${v.version ? " · " + esc(v.version) : ""}</span></div>`;

  $("#sys-grid").innerHTML = `
    <div class="card">
      <div class="row-between">
        <span class="badge ${c.type === "letsencrypt" ? "vless" : "hysteria"}">TLS 证书</span>
        <button class="btn ghost small" id="btn-renew">${c.type === "letsencrypt" ? "续期" : "申请证书"}</button>
      </div>
      <div class="kv mt-3"><span class="k">类型</span><span>${certName}</span></div>
      <div class="kv"><span class="k">剩余有效期</span><span>${days} 天</span></div>
      <div class="bar"><i style="width:${barPct}%;background:${barColor}"></i></div>
      ${c.type === "selfsigned" ? '<div class="note">自签证书: 客户端已带 allowInsecure, 不影响使用; 点「申请证书」可再试一次 Let\'s Encrypt (需域名已解析、80 端口可达)</div>' : ""}
    </div>
    <div class="card">
      ${svcRow("Xray 核心", sys.xray)}
      ${svcRow("Hysteria 2", sys.hysteria2)}
      <div class="kv"><span class="k">Nginx</span><span><span class="dot ${stateClass(sys.nginx.state)}"></span> ${STATE_TXT[sys.nginx.state] || esc(sys.nginx.state)}</span></div>
      <div class="kv"><span class="k">服务器</span><span>${esc(sys.server.os)} · ${esc(sys.server.arch)} · 在线 ${fmtUptime(sys.server.uptime_s)}</span></div>
      <div class="kv"><span class="k">端口跳跃</span><span>${d.hysteria_hopping ? "已启用 (" + d.hysteria_ports.join(" / ") + ")" : "未启用"}</span></div>
      <div class="kv"><span class="k">面板版本</span><span>v${esc(sys.server.panel_version)}</span></div>
    </div>
    <div class="card">
      <div class="row-between">
        <span class="badge vless">备份 / 恢复</span>
      </div>
      <div class="note mt-3 mb-3">
        导出含全部密钥、口令与订阅令牌, 请妥善保管; 换机 / 重装时可一键还原。
      </div>
      <div class="row">
        <button class="btn ghost small" id="btn-backup">下载备份</button>
        <button class="btn ghost small" id="btn-restore">从备份恢复</button>
        <input type="file" id="restore-file" class="hidden" accept="application/json,.json">
      </div>
    </div>`;
  const renewBtn = $("#btn-renew");
  if (renewBtn) renewBtn.onclick = async () => {
    const label = renewBtn.textContent;
    renewBtn.disabled = true; renewBtn.textContent = "处理中…";
    try {
      const r = await api("/api/renew", { method: "POST" });
      const failed = (await awaitJob(r)).filter((s) => !s.ok);
      toast(
        r.ok
          ? failed.length ? `证书已更新, 但 ${failed.length} 步配置落地失败` : r.detail || "证书已更新"
          : r.detail
      );
      reloadDash(true);
    } catch (e) { toast("操作失败: " + e.message); }
    renewBtn.disabled = false; renewBtn.textContent = label;
  };

  // 备份 / 恢复
  const backupBtn = $("#btn-backup");
  if (backupBtn) backupBtn.onclick = () => { window.location.href = "/api/backup"; };
  const restoreBtn = $("#btn-restore");
  const fileInput = $("#restore-file");
  if (restoreBtn && fileInput) {
    restoreBtn.onclick = () => fileInput.click();
    fileInput.onchange = () => {
      const file = fileInput.files && fileInput.files[0];
      fileInput.value = "";        // 立刻清掉: 同一个文件再选一次也要能再次触发 change
      if (!file) return;
      // 与升级确认、链式开关一致: 走自定义弹窗而不是浏览器原生 confirm ——
      // 原生弹窗长得像系统警告、有几行纯文本的容量, 也没法把"哪些东西会被替换"排版讲清。
      // 文件名来自用户的磁盘, 拼进 innerHTML 前必须转义。
      openConfirm({
        title: "用备份覆盖当前配置?",
        okLabel: "覆盖并恢复",
        html: `<div class="qr-sub">将用 <b>${esc(file.name)}</b> 覆盖当前配置:<br>
          节点开关 / 端口 / <b>密钥</b> / 管理员口令都会被备份里的内容替换。<br><br>
          恢复后会按备份重新生成全部配置并热重载; 订阅地址也会跟着变成备份里的那一个
          —— 客户端需要重新导入订阅。</div>`,
        onOk: async () => {
          restoreBtn.disabled = true;
          restoreBtn.textContent = "恢复中…";
          try {
            S.dash = await api("/api/restore", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: await file.text(),
            });
            redrawDash(true);
            toast("备份已恢复, 配置已重新生成");
          } catch (e) {
            toast("恢复失败: " + e.message);
          }
          restoreBtn.disabled = false;
          restoreBtn.textContent = "从备份恢复";
        },
      });
    };
  }
}
