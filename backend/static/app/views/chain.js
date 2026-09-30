/** 链式代理 (入口 → 落地)。
 *
 *  落地端生成配对码, 入口端粘贴即连; 对客户端只是一个普通节点。这块交互最多
 *  (生成 / 轮换 / 关闭 / 连接探测 / 切换内层传输 / 设为默认出口 / 断开), 所以单独成模块。
 */
import { $, esc, escAttr, toast, copyText } from "../lib/dom.js";
import { fmtTime } from "../lib/format.js";
import { openConfirm, openQr } from "../lib/dialog.js";
import { api, markDisconnected, syncAfterDrop } from "../lib/api.js";
import { S } from "../lib/state.js";
import { waitPendingApply, settleApply, applyAction } from "../lib/jobs.js";

/* ---------------- 链式代理 ----------------
 * 两台机器各装一份本程序, 接成一条链 (入口 → 落地):
 *   落地端: 生成专用凭据 (独立 UUID + 独立端口, 与订阅凭据分开, 可单独作废) → 配对码
 *   入口端: 粘贴配对码 → 真实握手探测 → 新增入站 + 出站 + 路由规则, 订阅里随即多一个节点
 * 对客户端只是"多了一个普通节点", 链式链路完全透明 (不用手写 Clash relay / sing-box detour)。
 * 可选「设为默认出口」: 本机 4 个主力节点的流量整体改道到落地端 —— 这才是"链式加速"。 */
export function renderChain(d) {
  const grid = $("#chain-grid");
  if (!grid) return;
  const c = d.chain || {};
  const ex = c.exit || {};
  const entries = c.entries || [];
  renderChainPath(d);
  grid.innerHTML = chainExitCard(d, ex) + chainPeerCard(d, entries);
  $("#chain-entries").innerHTML = entries.length
    ? `<div class="section-title mb-0">已连接的落地端 (${entries.length})</div>` +
      entries.map((e) => chainEntryCard(d, e)).join("")
    : "";
  bindChainExit(ex);
  bindChainPeer();
  bindChainEntries(entries);
}

/* 链式代理卡片顶部的三段式拓扑: 客户端 → 本机入口 → 落地端。
 * 没接链时画成虚线空位, 让"还没连上"这件事一眼可见。 */
function renderChainPath(d) {
  const el = $("#chain-path");
  if (!el) return;
  const c = d.chain || {};
  const ex = c.exit || {};
  const all = c.entries || [];
  // 拓扑只画"活着"的那条链: 优先默认出口, 其次是第一条启用中的; 全停用就别画成通的
  const live = all.filter((x) => x.enabled);
  const e = live.find((x) => x.default_out) || live[0];
  const probe = (e && e.last_probe) || {};
  const onCount = (d.nodes || []).filter((n) => n.enabled && !n.chain).length;
  const emptyMeta = all.length
    ? `已连接的 ${all.length} 条链都处于停用状态 — 在下面打开开关即可恢复`
    : ex.enabled
      ? "本机开着落地端, 等另一台机器接进来"
      : "还没接入落地端 — 在下面粘贴配对码";

  const client = `<div class="hop">
      <span class="who">你的设备</span><span class="id">Clash / sing-box / 手机 App</span>
      <span class="meta">订阅里自动多出链式节点, 不用手写 relay / detour</span></div>`;
  const entry = e
    ? `<div class="hop accent"><span class="who">入口 · 就近加速</span><span class="id">${esc(d.domain)}:${e.local_port}</span>
        <span class="meta">${onCount} 个主力节点在这台机器上 · 客户端连它</span></div>`
    : `<div class="hop empty"><span class="who">入口 · 就近加速</span><span class="id">${esc(d.domain)}</span>
        <span class="meta">${emptyMeta}</span></div>`;
  const exitHop = e
    ? `<div class="hop"><span class="who">落地 · ${esc(e.label || "出口")}</span><span class="id">${esc(e.host)}:${e.port}</span>
        <span class="meta">出口 IP ${esc(probe.exit_ip || "未探测")}${
          probe.tcp_ms ? " · 链路 " + Math.round(probe.tcp_ms) + "ms" : ""
        } · 内层 ${e.transport === "hysteria2" ? "QUIC" : "Reality"}${e.default_out ? " · 已设为默认出口" : ""}</span></div>`
    : `<div class="hop empty"><span class="who">落地 · 出口</span><span class="id">—</span>
        <span class="meta">${ex.enabled ? "本机可当别人的出口, 端口 " + ex.port : "本机既没接入也没开启落地端"}</span></div>`;

  el.innerHTML =
    client +
    `<div class="wire${e ? "" : " off"}"><i></i><span>${e ? "VLESS Reality" : "未接链"}</span><span class="mono">${e ? e.local_port + "/tcp" : ""}</span></div>` +
    entry +
    `<div class="wire${e ? "" : " off"}"><i></i><span>${
      e && e.transport === "hysteria2" ? "QUIC/UDP" : "专用凭据"
    }</span><span class="mono">${
      e ? (e.transport === "hysteria2" ? e.hy_port + "/udp" : e.port + "/tcp") : ""
    }</span></div>` +
    exitHop;
}

function chainExitCard(d, ex) {
  const head = `<div class="row-between">
      <span class="name card-title">
        <span class="badge trojan">落地端</span>本机对外当出口</span>
      ${ex.enabled ? '<span class="badge vless">已开启</span>' : '<span class="badge hysteria">未开启</span>'}
    </div>`;
  if (!ex.enabled) {
    return `<div class="card" id="chain-exit-card">${head}
      <div class="note mt-3 mb-3">
        开启后本机会多一个<b>专用入站</b> (独立凭据, 与订阅里那份互不影响), 供另一台机器把本机当出口用。
        客户端最终看到的出口 IP 就是这台服务器。</div>
      <div class="adv-grid">
        <div class="field"><label>落地端口 (TCP)</label>
          <input class="mono" id="chain-exit-port" value="${ex.port || 8447}" inputmode="numeric"></div>
        <div class="field"><label>名称 (给对方看, 可留空)</label>
          <input id="chain-exit-label" value="${escAttr(ex.label || "")}"
            placeholder="${escAttr(d.domain)}" spellcheck="false"></div>
      </div>
      <div class="adv-grid">
        <div class="field"><label>内层 QUIC 端口 (UDP, 可留空)</label>
          <input class="mono" id="chain-exit-hyport" value="${ex.hy_port || 8448}" inputmode="numeric"></div>
        <div class="field"><label>内层传输</label>
          <label class="chk m-0"><input type="checkbox" id="chain-exit-hy"
            ${ex.hy_enabled ? "checked" : ""}> 同时开放内层 QUIC (Hysteria 2)</label></div>
      </div>
      <div class="note mb-3">
        内层 QUIC 是给跨洋链路的: 默认的 Reality 内层是 TCP over TCP, 长肥管道上
        拥塞窗口爬得慢; 换 UDP 后没有双层重传互相拖累 (需要在安全组放行这个 UDP 端口)。</div>
      <div class="row mt-1">
        <button class="btn small" id="btn-chain-exit-gen">生成配对码</button>
        <span class="muted fs-sm">生成后把配对码贴到入口端服务器</span>
      </div>
    </div>`;
  }
  const code = ex.code || "";
  return `<div class="card" id="chain-exit-card">${head}
    <div class="note mt-3 mb-3">
      把这行配对码贴到入口端服务器的「连接到落地服务器」里, 它就会把本机的出口当自己的出口。</div>
    <div class="qr-link mono" id="chain-exit-code" title="${escAttr(code)}">${esc(code)}</div>
    <div class="row mt-3">
      <button class="btn ghost small" id="btn-chain-exit-copy">复制配对码</button>
      <button class="btn ghost small" id="btn-chain-exit-qr">二维码</button>
      <button class="btn ghost small" id="btn-chain-exit-rotate">重新生成</button>
      <button class="btn ghost small danger" id="btn-chain-exit-off">关闭落地端</button>
    </div>
    <div class="divider"></div>
    <div class="kv"><span class="k">落地端口</span><span class="mono">${ex.port} / tcp</span></div>
    <div class="kv"><span class="k">内层 QUIC</span><span class="mono">${
      ex.hy_enabled
        ? ex.hy_port + " / udp · " + (ex.hy_running ? "监听中" : "未在监听")
        : "未开启 (内层走 Reality/TCP)"
    }${ex.hy_enabled ? ` <button class="btn ghost small" id="btn-chain-exit-hy-off">关闭</button>` : ""}</span></div>
    <div class="kv"><span class="k">专用凭据</span><span class="mono">${esc(ex.credential || "")}… <span class="muted">与订阅凭据分开, 可单独作废</span></span></div>
    ${ex.label ? `<div class="kv"><span class="k">名称</span><span>${esc(ex.label)}</span></div>` : ""}
    <div class="kv"><span class="k">开启时间</span><span>${esc(fmtTime(ex.created_at))}</span></div>
    ${
      ex.hy_enabled
        ? ""
        : `<div class="row mt-3">
      <input class="mono w-110" id="chain-exit-hyport" value="${ex.hy_port || 8448}" inputmode="numeric">
      <button class="btn ghost small" id="btn-chain-exit-hy-on">开放内层 QUIC (UDP)</button>
      <span class="muted fs-sm">开启后要重新把配对码贴到入口端</span>
    </div>`
    }
    <div class="note">配对码等同凭据: 谁拿到都能把本机当出口用, 别公开发布; 万一泄露点「重新生成」即可
      (旧码立即作废, 你自己的订阅完全不受影响)。对方连不上, 多半是云安全组没放行
      <span class="mono">${ex.port}/tcp</span>${ex.hy_enabled ? ` 或 <span class="mono">${ex.hy_port}/udp</span>` : ""}。</div>
  </div>`;
}

function chainPeerCard(d, entries) {
  return `<div class="card" id="chain-peer-card">
    <div class="row-between">
      <span class="name card-title">
        <span class="badge vless">入口端</span>连接到落地服务器</span>
      <span class="note">已连接 ${entries.length} 条</span>
    </div>
    <div class="field mt-3">
      <label>配对码 (在落地服务器面板「链式代理 → 落地端」里生成)</label>
      <textarea class="mono" id="chain-code" rows="3" spellcheck="false"
        placeholder="ZPC1~… 整段粘贴, 别只复制一部分"></textarea>
    </div>
    <div class="adv-grid">
      <div class="field"><label>名称 (可留空, 默认用落地地址)</label>
        <input id="chain-label" placeholder="例如 美国落地" spellcheck="false"></div>
      <div class="field"><label>本机对外端口 (留空自动分配)</label>
        <input class="mono" id="chain-local-port" placeholder="自动" inputmode="numeric"></div>
    </div>
    <div class="field"><label>内层传输 (两台服务器之间那一跳)</label>
      <select id="chain-transport">
        <option value="reality">Reality / TCP (默认, 免证书抗封锁)</option>
        <option value="hysteria2" id="chain-transport-quic">QUIC / Hysteria 2 (UDP, 跨洋更快)</option>
      </select>
      <div class="muted fs-xs mt-1" id="chain-transport-hint">
        粘贴配对码后这里会告诉你能不能选 QUIC。</div>
    </div>
    <label class="chk mt-1"><input type="checkbox" id="chain-default-out">
      设为默认出口: 本机所有节点整体改走这条链 (客户端不用换节点)</label>
    <div class="row mt-4">
      <button class="btn small" id="btn-chain-connect">连接并测试</button>
      <span class="muted fs-sm">会真的穿过去出一次网并读回落地出口 IP (约 3-10 秒)</span>
    </div>
  </div>`;
}

function chainEntryCard(d, e) {
  const p = e.last_probe || {};
  let probe;
  if (!p.ts && !p.detail) {
    probe = `<span class="note">还没测过这条链 —— 点「测速」跑一次真实出口往返。</span>`;
  } else if (p.probe_ok === false) {
    // 环境不允许探测 (本机没有 xray 二进制): 这不是"链不通", 别标成红的
    probe = `<span class="ping other">未测得</span>
      <span class="muted fs-sm">${esc(p.detail || "")}${
        p.ts ? " · " + esc(fmtTime(p.ts)) : ""
      }</span>`;
  } else {
    const cls = p.ok ? "ok" : "bad";
    const head = p.ok ? `出口 IP ${esc(p.exit_ip || "?")}` : "不通";
    // 链路 RTT (入口→落地这一次 TCP 握手) 与"整段探测耗时"分开: 前者才是用户
    // 体感的那一跳, 后者含起临时客户端 + 经链问一次回显服务, 天然是秒级。
    const rtt = p.tcp_ms
      ? `<span class="ping other" title="入口→落地这一跳的 TCP 握手耗时">链路 ${Math.round(p.tcp_ms)}ms</span>`
      : "";
    const cost = p.ms ? ` · 探测用时 ${(p.ms / 1000).toFixed(1)}s` : "";
    probe = `<span class="ping ${cls}">${esc(head)}</span>${rtt}
      <span class="muted fs-sm">${esc(p.detail || "")}${cost}${
        p.ts ? " · " + esc(fmtTime(p.ts)) : ""
      }</span>`;
  }
  return `<div class="card chain-entry">
    <div class="top">
      <span class="name"><span class="badge hysteria">链式</span><span class="nm">${esc(
        e.label || e.host
      )}</span>${e.default_out ? '<span class="badge trojan">默认出口</span>' : ""}</span>
      <label class="switch"><input type="checkbox" data-chain-toggle="${escAttr(e.id)}" ${
        e.enabled ? "checked" : ""
      }><span class="slider"></span></label>
    </div>
    <div class="meta">经落地 ${esc(e.host)}:${e.port} · 内层 ${
      e.transport === "hysteria2"
        ? `QUIC/UDP ${e.hy_port}${e.hy_bw ? " · Brutal " + e.hy_bw + "M" : ""}`
        : "Reality/TCP"
    } · SNI ${esc(e.sni || "")}</div>
    ${
      e.enabled && e.transport === "hysteria2" && e.hy_ready === false
        ? `<div class="note">内层 QUIC 客户端没在跑 —— 点「重新应用」或看程序日志; 这条链现在多半是断的。</div>`
        : ""
    }
    <div class="addr mono">${esc(d.domain)}:${e.local_port} <span class="dot ${
      e.enabled ? "running" : "other"
    }"></span> <span class="muted">${e.enabled ? "运行中" : "已停用"}</span>${
      e.enabled ? ` <span class="badge hysteria fs-xs">订阅里有它</span>` : ""
    }</div>
    <div class="ce-foot">
      <div class="ce-probe">${probe}</div>
      <div class="actions">
        <button class="btn ghost small" data-chain-probe="${escAttr(e.id)}">测速</button>
        ${
          e.has_quic || e.transport === "hysteria2"
            ? `<button class="btn ghost small" data-chain-transport="${escAttr(e.id)}">${
                e.transport === "hysteria2" ? "改回 Reality 内层" : "改用 QUIC 内层"
              }</button>`
            : ""
        }
        <button class="btn ghost small" data-chain-default="${escAttr(e.id)}" data-on="${
          e.default_out ? "1" : "0"
        }">${e.default_out ? "取消默认出口" : "设为默认出口"}</button>
        <button class="btn ghost small danger" data-chain-del="${escAttr(e.id)}">断开</button>
      </div>
    </div>
  </div>`;
}


function bindChainExit(ex) {
  if (!ex.enabled) {
    const btn = $("#btn-chain-exit-gen");
    if (btn) btn.onclick = () => applyAction("POST", "/api/chain/exit", {
      action: "generate",
      port: parseInt($("#chain-exit-port").value, 10) || undefined,
      label: $("#chain-exit-label").value.trim(),
      hy_enabled: $("#chain-exit-hy").checked,
      hy_port: parseInt($("#chain-exit-hyport").value, 10) || undefined,
    }, btn, "生成中…");
    return;
  }
  // 已经开着落地端时, 内层 QUIC 可以单独开关 (不轮换凭据, 只是多一个 UDP 监听 /
  // 少一个 UDP 监听)。开了之后配对码会从 v1 变 v2, 得重新贴到入口端才生效。
  const hyOn = $("#btn-chain-exit-hy-on");
  if (hyOn)
    hyOn.onclick = () =>
      applyAction(
        "POST",
        "/api/chain/exit",
        { action: "generate", hy_enabled: true, hy_port: parseInt($("#chain-exit-hyport").value, 10) || undefined },
        hyOn,
        "开启中…"
      );
  const hyOff = $("#btn-chain-exit-hy-off");
  if (hyOff)
    hyOff.onclick = () =>
      openConfirm({
        title: "关闭内层 QUIC?",
        okLabel: "关闭 (QUIC 密码作废)",
        html: `<div class="qr-sub">落地端的 UDP 监听会下线, 用 QUIC 内层的入口端
          会立刻断链 (改回 Reality 内层即可恢复)。<br>本机的 Reality 落地入站与自己的订阅完全不受影响。</div>`,
        onOk: () =>
          applyAction("POST", "/api/chain/exit", { action: "generate", hy_enabled: false }, hyOff, "关闭中…"),
      });
  const code = ex.code || "";
  $("#btn-chain-exit-copy").onclick = () => copyText(code);
  $("#btn-chain-exit-qr").onclick = () =>
    openQr({
      title: "落地端配对码",
      sub: `在入口端服务器面板粘贴, 端口 ${ex.port}/tcp`,
      link: code,
      svg: "/api/chain/exit/qr?img=svg",
      png: "/api/chain/exit/qr?size=8",
      file: "zeroproxy-chain-exit.png",
    });
  $("#btn-chain-exit-rotate").onclick = () =>
    openConfirm({
      title: "重新生成配对码?",
      okLabel: "重新生成 (旧的作废)",
      html: `<div class="qr-sub">已经连上本机的入口服务器会<b>立刻断链</b>,
        需要拿新配对码重新连接一次。<br>本机自己的订阅凭据 / 节点 / 客户端配置完全不受影响。</div>`,
      onOk: () => applyAction("POST", "/api/chain/exit", { action: "rotate" }, $("#btn-chain-exit-rotate"), "生成中…"),
    });
  $("#btn-chain-exit-off").onclick = () =>
    openConfirm({
      title: "关闭落地端?",
      okLabel: "关闭 (配对码作废)",
      html: `<div class="qr-sub">本机的落地入站会下线, 配对码同时作废;
        已连接的入口服务器那条链会不通。<br>随时可以再点「生成配对码」重新开启 —— 端口沿用原来的,
        凭据会重新生成 (旧配对码永久失效, 不会复活)。</div>`,
      onOk: () => applyAction("POST", "/api/chain/exit", { action: "disable" }, $("#btn-chain-exit-off"), "关闭中…"),
    });
}

/* 连接: 400 + needs_force 表示"链路测试没通过", 让用户看清楚原因再决定要不要硬加 */
async function connectChain(force) {
  const btn = $("#btn-chain-connect");
  await waitPendingApply();
  const code = $("#chain-code").value.trim();
  if (!code) { toast("先把落地端的配对码粘进来"); return; }
  const localPort = parseInt($("#chain-local-port").value, 10);
  const payload = {
    code,
    label: $("#chain-label").value.trim(),
    local_port: Number.isNaN(localPort) ? null : localPort,
    transport: $("#chain-transport") ? $("#chain-transport").value : "reality",
    default_out: $("#chain-default-out").checked,
    force: !!force,
  };
  btn.disabled = true;
  btn.textContent = force ? "强制连接中…" : "连接并测试中…";
  const before = S.dash ? JSON.stringify(S.dash) : "";
  S.opBusy += 1;
  try {
    let res;
    try {
      res = await fetch("/api/chain/entries", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
    } catch (err) {
      // 连接中断: 落地本身可能已经写好了 (新增入站要重启 xray, 正好掐断自己这条路)
      markDisconnected("重启内核中, 正在确认结果…");
      const changed = await syncAfterDrop(before);
      if (changed === true) toast("已添加 (重启内核时连接短暂中断, 已自动恢复)");
      else if (changed === false) toast("连接已恢复, 但没看到新节点 —— 请再点一次「连接并测试」");
      if (document.body.contains(btn)) { btn.disabled = false; btn.textContent = "连接并测试"; }
      return;
    }
    const body = await res.json().catch(() => ({}));
    if (!res.ok) {
      const detail = body.error || `HTTP ${res.status}`;
      if (body.needs_force) {
        btn.disabled = false;
        btn.textContent = "连接并测试";
        openConfirm({
          title: "链路测试没通过, 仍然添加?",
          okLabel: "仍然添加",
          html: `<div class="qr-sub">真实握手 / 出口往返失败:<br>
            <span class="mono">${esc(detail)}</span><br><br>
            常见原因: 落地端安全组或防火墙没放行配对码里的端口; 落地端已关闭 / 配对码被轮换过;
            配对码复制不完整。<br>
            仍然添加的话, 这条链在客户端那边多半连不通 (但可以稍后修好落地端再点「测速」复验)。</div>`,
          onOk: () => connectChain(true),
        });
        return;
      }
      throw new Error(detail);
    }
    // 先把表单清空再重绘: 草稿保护会把"正在编辑的输入"原样放回来, 不清就成了"粘进去的码还在"
    $("#chain-code").value = "";
    $("#chain-label").value = "";
    $("#chain-local-port").value = "";
    $("#chain-default-out").checked = false;
    const steps = await settleApply(body);
    const probe = steps.find((s) => s.name.indexOf("链路测试") === 0) || {};
    if (probe.skipped) {
      toast("已添加; 本机缺少 xray 二进制, 没能做链路测试 —— 可稍后点「测速」复验");
    } else if (probe.ok === false) {
      toast("已添加, 但链路测试没通过: " + String(probe.detail || "").slice(0, 60));
    } else {
      toast("链路已接通, 订阅里已多出这个节点");
    }
  } catch (e) {
    toast("连接失败: " + e.message);
    if (document.body.contains(btn)) { btn.disabled = false; btn.textContent = "连接并测试"; }
  } finally {
    S.opBusy -= 1;
  }
}

function bindChainPeer() {
  const btn = $("#btn-chain-connect");
  if (btn) btn.onclick = () => connectChain(false);
  const box = $("#chain-code");
  if (box) {
    box.addEventListener("input", updateChainTransportHint);
    updateChainTransportHint();
  }
}

/* 配对码的前端"预览": 只用来判断落地端有没有开内层 QUIC, 决定下拉框能不能选。
 * 真正的校验仍然在服务端 (checksum / 字段合法性)。 */
export function chainCodeInfo(code) {
  const parts = (code || "").trim().split("~");
  if (parts.length !== 3 || parts[0] !== "ZPC1") return null;
  try {
    const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    const bytes = Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
    const info = JSON.parse(new TextDecoder().decode(bytes));
    return info && typeof info === "object" ? info : null;
  } catch (e) {
    return null;
  }
}

function updateChainTransportHint() {
  const sel = $("#chain-transport");
  const hint = $("#chain-transport-hint");
  const opt = $("#chain-transport-quic");
  if (!sel || !hint || !opt) return;
  const info = chainCodeInfo($("#chain-code").value);
  const quic = !!(info && info.y && info.y.p && info.y.w);
  opt.disabled = !quic;
  if (quic) {
    hint.textContent = "落地端开了内层 QUIC —— 跨洋链路建议选它 (UDP, 没有 TCP over TCP)。";
  } else {
    if (sel.value === "hysteria2") sel.value = "reality";
    hint.textContent = info
      ? "这份配对码里没有 QUIC 凭据 (落地端没开内层 QUIC), 只能走 Reality。"
      : "";
  }
}

function bindChainEntries(entries) {
  document.querySelectorAll("[data-chain-toggle]").forEach((el) =>
    (el.onchange = () =>
      applyAction("POST", `/api/chain/entries/${el.dataset.chainToggle}`, { enabled: el.checked }, null))
  );
  document.querySelectorAll("[data-chain-probe]").forEach((el) =>
    (el.onclick = () =>
      applyAction("POST", `/api/chain/entries/${el.dataset.chainProbe}/probe`, {}, el, "测速中…"))
  );
  document.querySelectorAll("[data-chain-transport]").forEach((el) =>
    (el.onclick = () => {
      const entry = entries.find((e) => e.id === el.dataset.chainTransport) || {};
      const toQuic = entry.transport !== "hysteria2";
      const doIt = () =>
        applyAction(
          "POST",
          `/api/chain/entries/${el.dataset.chainTransport}`,
          { transport: toQuic ? "hysteria2" : "reality" },
          el,
          "切换中…"
        );
      openConfirm({
        title: toQuic ? `把「${entry.label || entry.host}」的内层换成 QUIC?` : `把内层换回 Reality?`,
        okLabel: toQuic ? "改用 QUIC 内层" : "改回 Reality 内层",
        html: toQuic
          ? `<div class="qr-sub">这两台机器之间那一跳改成 <b>Hysteria 2 (QUIC/UDP)</b>:
              跨洋链路上不再有两层 TCP 互相拖累, 单流速度通常明显好于 Reality 内层。<br>
              落地端要放行配对码里的那个 UDP 端口; 切换会重启内核, 客户端连接会瞬断。</div>`
          : `<div class="qr-sub">换回 <b>Reality (TCP)</b> 内层: 免证书、
              抗封锁更强, 但跨洋长链路上单流速度不如 QUIC。切换会重启内核。</div>`,
        onOk: doIt,
      });
    })
  );
  document.querySelectorAll("[data-chain-default]").forEach((el) =>
    (el.onclick = () => {
      const on = el.dataset.on !== "1";
      const entry = entries.find((e) => e.id === el.dataset.chainDefault) || {};
      const doIt = () =>
        applyAction("POST", `/api/chain/entries/${el.dataset.chainDefault}`, { default_out: on }, el);
      if (!on) return doIt();
      openConfirm({
        title: `把「${entry.label || entry.host}」设为默认出口?`,
        okLabel: "设为默认出口",
        html: `<div class="qr-sub">本机 4 个主力节点 (Reality / XHTTP / WS / Trojan) 的流量会整体改道,
          从这台落地服务器出网 —— 客户端不用换节点。<br>
          分流模板里的广告 / 私有地址拦截规则优先级更高, 不受影响。</div>`,
        onOk: doIt,
      });
    })
  );
  document.querySelectorAll("[data-chain-del]").forEach((el) =>
    (el.onclick = () => {
      const entry = entries.find((e) => e.id === el.dataset.chainDel) || {};
      openConfirm({
        title: `断开「${entry.label || entry.host}」?`,
        okLabel: "断开并删除",
        html: `<div class="qr-sub">本机的链式入站 / 出站 / 路由规则都会删掉,
          订阅里这个节点同时消失。<br>落地端服务器上的凭据不受影响 (需要时重新贴一次配对码即可)。</div>`,
        onOk: () => applyAction("DELETE", `/api/chain/entries/${el.dataset.chainDel}`, undefined, el, "断开中…"),
      });
    })
  );
}
