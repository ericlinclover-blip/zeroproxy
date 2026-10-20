/** WireGuard — 原生 UDP 入站。
 *
 *  与「客户端」页的区别: 这里管理的是**每台设备一份的 WireGuard 凭据**。官方
 *  WireGuard App 不认 vless:// / Clash 订阅，只认标准 .conf 或二维码；所以面板
 *  为每台设备生成独立私钥 + PSK，并提供下载 / 扫码 / 一次性链接。
 *
 *  服务端只下发公钥；私钥只在“下载配置 / 二维码 / 一次性链接”这三个动作里出现。
 */
import { $, esc, escAttr, toast, copyText } from "../lib/dom.js";
import { api } from "../lib/api.js";
import { S } from "../lib/state.js";
import { fmtBytes, fmtTime } from "../lib/format.js";
import { openConfirm, openQr } from "../lib/dialog.js";
import { applyAction, settleApply } from "../lib/jobs.js";
import { clearDraft } from "../lib/drafts.js";

const EXPIRES = [
  [0, "永久"],
  [7, "7 天"],
  [30, "30 天"],
  [90, "90 天"],
  [365, "1 年"],
];

function ago(ts) {
  if (!ts) return "从未";
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (s < 60) return `${s} 秒前`;
  if (s < 3600) return `${Math.floor(s / 60)} 分钟前`;
  if (s < 86400) return `${Math.floor(s / 3600)} 小时前`;
  return `${Math.floor(s / 86400)} 天前`;
}

function safeFile(name) {
  return String(name || "device").replace(/[^\w\u4e00-\u9fa5.-]+/g, "-").slice(0, 40);
}

export function renderWireguard(dash) {
  const box = $("#wg-body");
  if (!box || !dash) return;
  const wg = dash.wireguard || {};
  const nav = $("#nav-wg");
  if (nav) nav.textContent = wg.enabled ? `${wg.online_count}/${wg.peer_count}` : "—";
  const count = $("#wg-count");
  if (count) {
    count.textContent = wg.enabled
      ? `${wg.enabled_count} 台启用 · ${wg.online_count} 台在线`
      : "未启用";
  }
  box.innerHTML = wg.enabled ? enabledView(wg) : disabledView(wg);
  bind(wg);
}

function disabledView(wg) {
  return `
  <div class="client-hint">
    <b>给官方 WireGuard 客户端用。</b>
    iOS / Android / Windows / macOS 的 WireGuard App 都可以直接扫码或导入
    <code class="mono">.conf</code>。每台设备独立密钥，单独停用 / 删除，互不影响。
    它与订阅是两条路径：WireGuard 客户端不解析 vless:// 链接。
  </div>
  <div class="dev-grid">
    <div class="mini-card">
      <b>默认监听</b>
      <div class="wg-peer-ip mt-1">${esc(wg.port)}/udp</div>
      <div class="muted fs-xs mt-1">云厂商安全组需要放行同一个 UDP 端口</div>
    </div>
    <div class="mini-card">
      <b>隧道网段</b>
      <div class="wg-peer-ip mt-1">${esc(wg.subnet)}</div>
      <div class="muted fs-xs mt-1">服务端占 .1，客户端从 .2 开始分配</div>
    </div>
    <div class="mini-card">
      <b>全流量 / 分流</b>
      <div class="muted fs-xs mt-1">
        默认 <code class="mono">0.0.0.0/0</code> 全流量走 WireGuard；
        添加设备时也可以只把隧道网段塞进去。
      </div>
    </div>
  </div>
  <div class="client-actions mt-3">
    <button class="btn primary" id="wg-enable">启用 WireGuard</button>
    <span class="muted fs-xs">
      ${!wg.prod ? "本地开发只生成配置, 不启动内核接口"
        : wg.tools ? "wg / wg-quick 已就绪"
        : "首次启用会自动安装 wireguard-tools（需要 root）"}
    </span>
  </div>
  <div class="muted fs-xs mt-2">
    提示: 标准 WireGuard 的握手特征比较明显, 在强干扰网络下可能被识别/阻断;
    这种情况请用上面的 Reality / Hysteria 2 节点, 两者互不影响。
  </div>
  ${howTo()}`;
}

function statusPill(wg) {
  if (!wg.prod) return `<span class="pill other"><i class="dot other"></i>本地开发 (未启动)</span>`;
  if (!wg.tools) return `<span class="pill bad"><i class="dot err"></i>缺少 WireGuard 工具</span>`;
  if (!wg.running) return `<span class="pill warn"><i class="dot warn"></i>服务未运行</span>`;
  return `<span class="pill ok"><i class="dot running"></i>运行中</span>`;
}

function enabledView(wg) {
  const hasPeers = (wg.peers || []).length > 0;
  return `
  <div class="row-between top">
    <div>
      <div class="row">
        ${statusPill(wg)}
        <span class="wg-endpoint">${esc(wg.endpoint || "尚未确定地址")}</span>
        <span class="muted fs-xs">接口 ${esc(wg.interface)} · MTU ${esc(wg.mtu)}</span>
        ${wg.active_mode ? `<span class="tag-chip">${wg.active_mode === "userspace" ? "用户态 (wireguard-go)" : "内核"}</span>` : ""}
      </div>
      ${wg.reason ? `<div class="muted fs-xs mt-1">${esc(wg.reason)}</div>` : ""}
    </div>
    <button class="btn ghost small danger" id="wg-disable">停用</button>
  </div>

  <details class="client-help mt-2" ${hasPeers ? "" : "open"}>
    <summary>端口 / 网段 / MTU / DNS</summary>
    <div class="wg-form mt-2">
      <div class="field">
        <label>监听端口 (UDP)</label>
        <input id="wg-port" class="mono" inputmode="numeric" value="${escAttr(wg.port)}">
      </div>
      <div class="field">
        <label>运行方式</label>
        <select id="wg-mode">
          <option value="auto" ${wg.mode === "auto" ? "selected" : ""}>自动 (内核优先, 失败退用户态)</option>
          <option value="kernel" ${wg.mode === "kernel" ? "selected" : ""}>仅内核</option>
          <option value="userspace" ${wg.mode === "userspace" ? "selected" : ""}>仅用户态 (wireguard-go)</option>
        </select>
        <div class="muted fs-xs mt-1">
          ${wg.userspace_available ? "wireguard-go 与 /dev/net/tun 已就绪" : "未检测到 wireguard-go 或 /dev/net/tun"}
        </div>
      </div>
      <div class="field">
        <label>隧道网段${hasPeers ? " (有客户端时锁定)" : ""}</label>
        <input id="wg-subnet" class="mono" value="${escAttr(wg.subnet)}" ${hasPeers ? "disabled" : ""}>
      </div>
      <div class="field">
        <label>MTU</label>
        <input id="wg-mtu" class="mono" inputmode="numeric" value="${escAttr(wg.mtu)}">
      </div>
      <div class="field">
        <label>DNS (逗号分隔, 留空不下发)</label>
        <input id="wg-dns" class="mono" value="${escAttr(wg.dns || "")}" placeholder="1.1.1.1, 8.8.8.8">
      </div>
      <div class="field">
        <label>Endpoint (留空 = 面板域名)</label>
        <input id="wg-endpoint" class="mono" value="${escAttr(wg.endpoint_input || "")}" placeholder="${escAttr(wg.endpoint_host || "wg.example.com")}">
      </div>
      <div class="field">
        <label>Keepalive (秒)</label>
        <input id="wg-keepalive" class="mono" inputmode="numeric" value="${escAttr(wg.keepalive)}">
      </div>
    </div>
    <div class="row mt-2">
      <label class="chk"><input type="checkbox" id="wg-ipv6" ${wg.ipv6 ? "checked" : ""}> 同时分配 IPv6 隧道地址</label>
      <span class="muted fs-xs">关闭后已有客户端需要重新下载配置</span>
    </div>
    <div class="row mt-2">
      <button class="btn small" id="wg-save">保存并应用</button>
      <span class="muted fs-xs">改端口 / MTU / DNS 用 <code class="mono">wg syncconf</code> 增量生效，不会踢掉在线设备</span>
    </div>
    ${wg.server_public_key ? `<div class="muted fs-xs mt-2">服务端公钥 <code class="mono">${esc(wg.server_public_key)}</code></div>` : ""}
  </details>

  <div class="client-actions mt-3">
    <button class="btn primary" id="wg-add">＋ 添加设备</button>
    <span class="muted fs-xs">每台设备一条独立密钥；二维码直接给官方 WireGuard App 扫</span>
  </div>
  ${hasPeers ? `
    <div class="wg-grid mt-3">${wg.peers.map(peerCard).join("")}</div>
    <div class="muted fs-xs mt-3">
      一次性链接默认 ${Math.round((wg.one_time_ttl || 600) / 60)} 分钟内有效，取一次即作废。
      删除或轮换密钥后，旧配置立刻失效。
    </div>` : `
    <div class="client-hint mt-3">
      还没有客户端。点「添加设备」生成第一份配置；面板会同时给出二维码与
      <code class="mono">.conf</code> 下载。
    </div>`}
  ${howTo()}`;
}

function howTo() {
  return `<details class="client-help">
    <summary>官方客户端怎么导入？</summary>
    <div class="muted fs-sm mt-2">
      <b>iOS / Android</b>: 安装官方 WireGuard App → 右上角 <b>+</b> → 从二维码创建 / 扫描二维码。<br>
      <b>Windows / macOS</b>: 安装官方 WireGuard → 左下角「导入隧道」→ 选择下载的
      <code class="mono">.conf</code> 文件。<br>
      <b>一次给多台设备</b>: 每台单独添加一条 peer；不要把同一份配置复制到多台设备
      (它们会争用同一个隧道地址)。
    </div>
  </details>`;
}

function peerCard(p) {
  const state = p.expired
    ? `<span class="pill bad"><i class="dot err"></i>已过期</span>`
    : !p.enabled
      ? `<span class="pill other"><i class="dot other"></i>已停用</span>`
      : p.online
        ? `<span class="pill ok"><i class="dot running"></i>在线</span>`
        : `<span class="pill other"><i class="dot other"></i>等待连接</span>`;
  const expiry = p.expires_at
    ? `<span class="tag-chip">到期 ${esc(fmtTime(p.expires_at))}</span>`
    : `<span class="tag-chip">永久</span>`;
  return `
  <div class="wg-peer ${p.enabled && !p.expired ? "on" : "off"}">
    <div class="wg-peer-top">
      <b>${esc(p.name)}</b>
      ${state}
    </div>
    <div class="wg-peer-ip">${esc(p.address)}${p.address6 ? ` · ${esc(p.address6)}` : ""}</div>
    <div class="wg-peer-stats">
      <span>握手 <b>${esc(p.latest_handshake ? ago(p.latest_handshake) : "从未")}</b></span>
      <span>↑ <b>${fmtBytes(p.rx)}</b></span>
      <span>↓ <b>${fmtBytes(p.tx)}</b></span>
    </div>
    <div class="wg-peer-meta">
      <span class="tag-chip" title="客户端侧 AllowedIPs">${esc(p.allowed_ips)}</span>
      ${expiry}
      ${p.endpoint ? `<span class="tag-chip mono">${esc(p.endpoint)}</span>` : ""}
    </div>
    <div class="wg-peer-actions">
      <button class="btn small" data-wg-qr="${escAttr(p.id)}">二维码</button>
      <button class="btn ghost small" data-wg-download="${escAttr(p.id)}">下载 .conf</button>
      <button class="btn ghost small" data-wg-link="${escAttr(p.id)}">一次性链接</button>
      <button class="btn ghost small" data-wg-edit="${escAttr(p.id)}">编辑</button>
      <button class="btn ghost small" data-wg-toggle="${escAttr(p.id)}">${p.enabled ? "停用" : "启用"}</button>
      <button class="btn ghost small" data-wg-rotate="${escAttr(p.id)}">轮换密钥</button>
      <button class="btn ghost small danger" data-wg-remove="${escAttr(p.id)}">删除</button>
    </div>
  </div>`;
}

/* ---------------- 事件 ---------------- */

function peerById(wg, id) {
  return (wg.peers || []).find((p) => p.id === id) || null;
}

function bind(wg) {
  const enable = $("#wg-enable");
  if (enable) {
    enable.onclick = () => applyAction(
      "POST", "/api/wireguard/settings", { enabled: true }, enable, "启用中…", "WireGuard 已启用"
    );
  }
  const disable = $("#wg-disable");
  if (disable) {
    disable.onclick = () => openConfirm({
      title: "停用 WireGuard？",
      html: `所有已下发的 <code class="mono">.conf</code> 会立刻失效（接口 wg0 被拆除）。<br>
             <span class="muted">客户端配置不会被删除，重新启用后原配置可以继续用。</span>`,
      okLabel: "停用",
      onOk: () => applyAction(
        "POST", "/api/wireguard/settings", { enabled: false }, $("#wg-disable"), "停用中…",
        "WireGuard 已停用"
      ),
    });
  }
  const save = $("#wg-save");
  if (save) save.onclick = () => saveSettings(wg, save);
  const add = $("#wg-add");
  if (add) add.onclick = () => addPeer(wg);

  document.querySelectorAll("[data-wg-qr]").forEach((el) => {
    el.onclick = () => showQr(wg, el.dataset.wgQr);
  });
  document.querySelectorAll("[data-wg-download]").forEach((el) => {
    el.onclick = () => download(wg, el.dataset.wgDownload);
  });
  document.querySelectorAll("[data-wg-link]").forEach((el) => {
    el.onclick = () => oneTime(wg, el.dataset.wgLink);
  });
  document.querySelectorAll("[data-wg-edit]").forEach((el) => {
    el.onclick = () => editPeer(wg, el.dataset.wgEdit);
  });
  document.querySelectorAll("[data-wg-toggle]").forEach((el) => {
    el.onclick = () => {
      const peer = peerById(wg, el.dataset.wgToggle);
      if (!peer) return;
      updatePeer(peer.id, { enabled: !peer.enabled }, el, "切换中…");
    };
  });
  document.querySelectorAll("[data-wg-rotate]").forEach((el) => {
    el.onclick = () => {
      const peer = peerById(wg, el.dataset.wgRotate);
      if (!peer) return;
      openConfirm({
        title: `轮换「${peer.name}」的密钥？`,
        html: `<b>旧配置会立刻失效</b>，这台设备需要重新扫码或导入新的 .conf。<br>
               <span class="muted">已经连上的隧道会在下一次握手时断开。</span>`,
        okLabel: "轮换",
        onOk: async () => {
          try {
            const body = await api(`/api/wireguard/peers/${encodeURIComponent(peer.id)}/rotate`, {
              method: "POST",
            });
            await settleApply(body);
            toast("密钥已轮换，旧配置已失效");
            if (body.config) showConfigQr(peer.name, body.config, peer.id);
          } catch (e) {
            toast("轮换失败: " + e.message);
          }
        },
      });
    };
  });
  document.querySelectorAll("[data-wg-remove]").forEach((el) => {
    el.onclick = () => {
      const peer = peerById(wg, el.dataset.wgRemove);
      if (!peer) return;
      openConfirm({
        title: `删除「${peer.name}」？`,
        html: `这台设备的 WireGuard 访问权限会立刻被撤销。删除后地址会被回收，
               下次添加设备可能用到同一个地址。`,
        okLabel: "删除",
        onOk: async () => {
          try {
            await settleApply(
              await api(`/api/wireguard/peers/${encodeURIComponent(peer.id)}`, { method: "DELETE" })
            );
            toast("已删除");
          } catch (e) {
            toast("删除失败: " + e.message);
          }
        },
      });
    };
  });
}

async function saveSettings(wg, btn) {
  const port = parseInt($("#wg-port").value, 10);
  const mode = $("#wg-mode").value;
  const subnetEl = $("#wg-subnet");
  const mtu = parseInt($("#wg-mtu").value, 10);
  const dns = $("#wg-dns").value.trim();
  const endpoint = $("#wg-endpoint").value.trim();
  const keepalive = parseInt($("#wg-keepalive").value, 10);
  const ipv6 = $("#wg-ipv6").checked;
  const payload = {};
  if (mode !== (wg.mode || "auto")) payload.mode = mode;
  if (port !== wg.port) payload.port = port;
  if (subnetEl && !subnetEl.disabled && subnetEl.value.trim() !== wg.subnet) {
    payload.subnet = subnetEl.value.trim();
  }
  if (mtu !== wg.mtu) payload.mtu = mtu;
  if (dns !== (wg.dns || "")) payload.dns = dns;
  if (endpoint !== (wg.endpoint_input || "")) payload.endpoint = endpoint;
  if (keepalive !== wg.keepalive) payload.keepalive = keepalive;
  if (ipv6 !== wg.ipv6) payload.ipv6 = ipv6;
  if (!Object.keys(payload).length) {
    toast("没有需要修改的内容");
    return;
  }
  await applyAction(
    "POST", "/api/wireguard/settings", payload, btn, "应用中…", "WireGuard 设置已应用"
  );
  clearDraft("#wg-port, #wg-subnet, #wg-mtu, #wg-dns, #wg-endpoint, #wg-keepalive");
}

function addPeer(wg) {
  openConfirm({
    title: "添加 WireGuard 设备",
    html: `
      <label>设备名</label>
      <input id="wg-new-name" maxlength="40" placeholder="例如 iPhone / MacBook" autocomplete="off">
      <label class="mt-2">有效期</label>
      <select id="wg-new-expires">
        ${EXPIRES.map(([d, t]) => `<option value="${d}">${t}</option>`).join("")}
      </select>
      <label class="mt-2">AllowedIPs (客户端把哪些流量塞进隧道)</label>
      <select id="wg-new-mode">
        <option value="0.0.0.0/0">全流量 (0.0.0.0/0)</option>
        <option value="vpn">只走隧道网段 (${esc(wg.subnet)})</option>
      </select>
      <div class="muted fs-xs mt-1">全流量 = 这台设备的默认路由改到服务器；只走网段 = 普通上网不变。</div>`,
    okLabel: "生成配置",
    onOk: async () => {
      const name = ($("#wg-new-name") || {}).value || "";
      const days = parseInt(($("#wg-new-expires") || {}).value || "0", 10);
      const mode = ($("#wg-new-mode") || {}).value || "0.0.0.0/0";
      const allowed = mode === "vpn" ? wg.subnet : "0.0.0.0/0";
      try {
        const body = await api("/api/wireguard/peers", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name, allowed_ips: allowed, expires_days: days }),
        });
        await settleApply(body);
        toast("设备已添加");
        if (body.peer_id && body.config) {
          const peer = ((S.dash || {}).wireguard || {}).peers || [];
          const item = peer.find((p) => p.id === body.peer_id);
          showConfigQr(item ? item.name : name || "设备", body.config, body.peer_id);
        }
      } catch (e) {
        toast("添加失败: " + e.message);
      }
    },
  });
  setTimeout(() => { const el = $("#wg-new-name"); if (el) el.focus(); }, 30);
}

function editPeer(wg, id) {
  const peer = peerById(wg, id);
  if (!peer) return;
  const days = peer.expires_at
    ? Math.max(0, Math.ceil((peer.expires_at - Date.now() / 1000) / 86400))
    : 0;
  openConfirm({
    title: `编辑「${peer.name}」`,
    html: `
      <label>设备名</label>
      <input id="wg-edit-name" maxlength="40" value="${escAttr(peer.name)}">
      <label class="mt-2">剩余有效期 (天, 0 = 永久)</label>
      <input id="wg-edit-days" class="mono" inputmode="numeric" value="${days}">
      <label class="mt-2">AllowedIPs</label>
      <input id="wg-edit-allowed" class="mono" value="${escAttr(peer.allowed_ips)}">
      <div class="muted fs-xs mt-1">多个网段用逗号分隔；这是客户端侧路由，不是服务端 ACL。</div>`,
    okLabel: "保存",
    onOk: async () => {
      const name = ($("#wg-edit-name") || {}).value || "";
      const d = parseInt(($("#wg-edit-days") || {}).value || "0", 10);
      const allowed = ($("#wg-edit-allowed") || {}).value || "";
      await updatePeer(id, { name, expires_days: d, allowed_ips: allowed }, null, "保存中…");
    },
  });
}

async function updatePeer(id, payload, btn, busyText) {
  const original = btn ? btn.textContent : "";
  if (btn) { btn.disabled = true; if (busyText) btn.textContent = busyText; }
  try {
    const body = await api(`/api/wireguard/peers/${encodeURIComponent(id)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    await settleApply(body);
    toast("已更新");
  } catch (e) {
    toast("更新失败: " + e.message);
  } finally {
    if (btn && document.body.contains(btn)) {
      btn.disabled = false;
      btn.textContent = original;
    }
  }
}

async function fetchConfig(id, inline = 1) {
  const res = await fetch(
    `/api/wireguard/peers/${encodeURIComponent(id)}/config?inline=${inline}`,
    { credentials: "same-origin", cache: "no-store" }
  );
  if (!res.ok) {
    let message = `HTTP ${res.status}`;
    try { const body = await res.json(); if (body && body.error) message = body.error; } catch (e) { /* 非 JSON */ }
    throw new Error(message);
  }
  return res.text();
}

function showConfigQr(name, config, id) {
  openQr({
    title: `WireGuard · ${name}`,
    sub: "用官方 WireGuard App 扫码导入",
    link: config,
    svg: `/api/wireguard/peers/${encodeURIComponent(id)}/qr?img=svg`,
    png: `/api/wireguard/peers/${encodeURIComponent(id)}/qr?size=8`,
    file: `zeroproxy-wg-${safeFile(name)}.png`,
  });
}

async function showQr(wg, id) {
  const peer = peerById(wg, id);
  if (!peer) return;
  try {
    const config = await fetchConfig(id, 1);
    showConfigQr(peer.name, config, id);
  } catch (e) {
    toast("读取配置失败: " + e.message);
  }
}

function download(wg, id) {
  const peer = peerById(wg, id);
  if (!peer) return;
  const a = document.createElement("a");
  a.href = `/api/wireguard/peers/${encodeURIComponent(id)}/config`;
  a.download = `zeroproxy-wg-${safeFile(peer.name)}.conf`;
  document.body.appendChild(a);
  a.click();
  a.remove();
}

async function oneTime(wg, id) {
  const peer = peerById(wg, id);
  if (!peer) return;
  try {
    const body = await api(`/api/wireguard/peers/${encodeURIComponent(id)}/link`, { method: "POST" });
    openConfirm({
      title: `一次性配置链接 · ${peer.name}`,
      html: `
        <div class="muted fs-sm">把这个链接发给这台设备，打开即下载 .conf；</div>
        <div class="muted fs-sm"><b>取一次即作废</b>，${Math.round((body.ttl || 600) / 60)} 分钟后过期。</div>
        <div class="cmd-box mt-2"><code class="mono">${esc(body.url)}</code></div>`,
      okLabel: "复制链接",
      onOk: () => copyText(body.url),
    });
  } catch (e) {
    toast("生成失败: " + e.message);
  }
}
