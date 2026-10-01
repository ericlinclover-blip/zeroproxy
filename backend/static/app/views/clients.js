/** 客户端 (路由器 / 手机 / 电脑)。
 *
 *  路由器端的设计原则: **面板是唯一事实来源**。
 *    - 「全屋代理」开关点下去写的只是服务器上的期望状态, 路由器每 15 秒取一次;
 *    - 卡片上的颜色取自设备回报的 actual —— 所以"显示已连接"永远是真的连上了,
 *      而不是前端点了一下变绿。desired ≠ actual 的那段时间显示「同步中…」。
 *
 *  手机 / 电脑端不做自己的 App: 给出扫码与一键导入, 复用已有的订阅接口。
 */
import { $, esc, escAttr, toast, copyText } from "../lib/dom.js";
import { api } from "../lib/api.js";
import { S } from "../lib/state.js";
import { openConfirm, openQr } from "../lib/dialog.js";

/** 当前 tab / 本页的临时状态 (不放进 S.dash: 它属于视图, 不属于服务器数据) */
let tab = "router";
let pairInfo = null;      // 刚生成的配对码 (含命令与有效期)
let busy = false;         // 生成命令 / 切换开关期间禁用按钮
let syncTimers = {};      // device_id -> 轮询定时器

const KIND_LABEL = { router: "路由器", phone: "手机", desktop: "电脑" };
const TPL_LABEL = { "": "跟随面板", smart: "智能分流", global: "全局代理", direct: "全部直连" };

export function renderClients(dash) {
  const box = $("#client-body");
  if (!box || !dash) return;
  const dev = dash.devices || { items: [], count: 0, online: 0, on: 0 };
  const routers = dev.items.filter((d) => d.kind === "router");

  const nav = $("#nav-clients");
  if (nav) nav.textContent = dev.count ? `${dev.on}/${dev.count}` : "—";
  $("#client-count").textContent = dev.count
    ? `${dev.on} 台已连接 · 共 ${dev.count} 台`
    : "还没有客户端";

  document.querySelectorAll("[data-client-tab]").forEach((btn) => {
    btn.classList.toggle("on", btn.dataset.clientTab === tab);
    btn.onclick = () => { tab = btn.dataset.clientTab; renderClients(S.dash); };
  });

  if (tab === "router") box.innerHTML = routerTab(dash, routers);
  else box.innerHTML = mobileTab(dash, tab);
  bind(dash, routers);
}

/* ---------------- 路由器 */

function statusPill(d) {
  if (!d.online) return `<span class="pill other"><i class="dot other"></i>离线</span>`;
  if (d.syncing) return `<span class="pill warn"><i class="dot warn"></i>同步中…</span>`;
  if (d.connected) return `<span class="pill ok"><i class="dot running"></i>已连接</span>`;
  return `<span class="pill other"><i class="dot other"></i>已关闭</span>`;
}

function ago(ts) {
  if (!ts) return "从未";
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (s < 60) return `${s} 秒前`;
  if (s < 3600) return `${Math.floor(s / 60)} 分钟前`;
  if (s < 86400) return `${Math.floor(s / 3600)} 小时前`;
  return `${Math.floor(s / 86400)} 天前`;
}

function routerTab(dash, routers) {
  if (!routers.length) return installCard(dash);
  return `
    <div class="client-hint">
      开启后, 连在这台路由器上的<b>所有设备</b> (手机 / 电脑 / 电视) 直接就能用, 不需要每台各装客户端。
    </div>
    ${routers.map(deviceCard).join("")}
    <div class="client-foot">
      <button class="btn ghost small" id="btn-add-device">＋ 再接入一台路由器</button>
      <span class="muted fs-xs">换节点 / 改分流请在面板改 —— 路由器会自动同步, 不用再登上去。</span>
    </div>
    ${pairInfo ? pairCard() : ""}`;
}

function deviceCard(d) {
  const tpl = TPL_LABEL[d.template ?? ""] || d.template || "跟随面板";
  const meta = [d.os, d.arch, d.ip].filter(Boolean).join(" · ");
  return `
  <div class="dev-card ${d.connected ? "on" : ""} ${d.online ? "" : "off"}">
    <div class="dev-body">
      <div class="dev-top">
        <b class="dev-name">${esc(d.name || "路由器")}</b>
        ${statusPill(d)}
      </div>
      <div class="dev-sub">${esc(meta || "已接入")}${d.online ? ` · ${ago(d.last_seen)}同步` : ` · 最后在线 ${ago(d.last_seen)}`}</div>
      <div class="dev-tags">
        <span class="tag-chip">分流 · ${esc(tpl)}</span>
        <span class="tag-chip">${d.actual ? "内核运行中" : "内核已停止"}</span>
        ${d.version ? `<span class="tag-chip">客户端 v${esc(d.version)}</span>` : ""}
      </div>
    </div>
    <div class="dev-switch">
      <label class="bigswitch" title="${d.desired ? "点击关闭全屋代理" : "点击开启全屋代理"}">
        <input type="checkbox" data-dev-toggle="${escAttr(d.id)}" ${d.desired ? "checked" : ""}>
        <span class="track"><span class="knob"></span></span>
      </label>
      <div class="dev-switch-label">全屋代理</div>
    </div>
    <div class="dev-actions">
      <label class="dev-tpl">
        <select data-dev-tpl="${escAttr(d.id)}">
          ${Object.entries(TPL_LABEL).map(([v, t]) =>
            `<option value="${escAttr(v)}" ${(d.template || "") === v ? "selected" : ""}>${esc(t)}</option>`).join("")}
        </select>
      </label>
      <button class="btn ghost small" data-dev-rename="${escAttr(d.id)}">改名</button>
      <button class="btn ghost small danger" data-dev-remove="${escAttr(d.id)}">移除</button>
    </div>
  </div>`;
}

function installCard(dash) {
  return `
  <div class="client-hero">
    <div class="hero-ic">📶</div>
    <div>
      <b>把代理装进路由器</b>
      <div class="muted fs-sm">
        在路由器终端里粘贴一行命令, 剩下的它自己做完。装好之后, 连在这台路由器上的
        手机 / 电脑 / 电视全部自动走分流代理 —— 不用在每台设备上装客户端、也不用填任何参数。
      </div>
    </div>
  </div>
  ${pairInfo ? pairCard() : `
  <div class="client-actions">
    <button class="btn primary" id="btn-pair">生成安装命令</button>
    <span class="muted fs-xs">命令里带一个一次性的配对码 (30 分钟内有效, 用过即废)。</span>
  </div>`}
  <details class="client-help">
    <summary>怎么打开路由器的终端？</summary>
    <div class="muted fs-sm mt-2">
      <b>GL.iNet</b>: 后台 → 系统 → 高级设置 → 启用 SSH, 然后用终端连 <code class="mono">root@192.168.8.1</code><br>
      <b>OpenWrt 原版</b>: 后台 → 系统 → 管理权 → 已默认开启 SSH, <code class="mono">ssh root@192.168.1.1</code><br>
      <b>小米 / 红米</b>: 需先刷成 OpenWrt, 之后同上<br>
      <b>软路由</b>: 直接在控制台或 SSH 里执行
    </div>
    <div class="muted fs-xs mt-2">
      支持 OpenWrt / GL.iNet / 小米 / 华硕等基于 OpenWrt 的设备; 需要 ≥ 90 MB 可用空间
      (内核约占 57 MB)。装完后每台路由器在面板上是一张卡片, 可以单独开关和移除。
    </div>
  </details>`;
}

function pairCard() {
  const left = Math.max(0, Math.floor((pairInfo.expires_at - Date.now() / 1000) / 60));
  return `
  <div class="cmd-card">
    <div class="cmd-head">
      <b>在路由器终端里粘贴这一行</b>
      <span class="muted fs-xs">约 ${left} 分钟内有效</span>
    </div>
    <div class="cmd-box">
      <code class="mono">${esc(pairInfo.command)}</code>
      <button class="btn small" id="btn-copy-cmd">复制</button>
    </div>
    <div class="muted fs-xs mt-2">
      安装过程约 1 分钟 (含 20 MB 内核下载); 结束后终端会告诉你是 TUN 还是 tproxy 模式。
      刷新本页即可看到设备卡片。
    </div>
  </div>`;
}

/* ---------------- 手机 / 电脑 */

function mobileTab(dash, kind) {
  const sub = (dash.subscription_formats || {}).base64 || "";
  const clash = (dash.subscription_formats || {}).clash || "";
  const rows = kind === "phone"
    ? [["iOS · Shadowrocket", "App Store 搜索 Shadowrocket, 扫码即导入", sub],
       ["Android · sing-box / v2rayNG", "应用商店或 GitHub 下载, 扫码即导入", sub]]
    : [["Windows · Clash Verge Rev", "下载后点「订阅」粘贴下面的地址", clash],
       ["macOS · Mihomo Party", "下载后导入订阅链接", clash],
       ["Linux · sing-box", "保存订阅文件后直接加载", clash]];
  return `
  <div class="client-hint">
    手机 / 电脑端用现成的客户端导入订阅即可 —— 订阅地址恒定不变, 面板上换节点 / 改分流会自动生效。
  </div>
  <div class="dev-grid">
    ${rows.map(([name, tip, url]) => `
      <div class="mini-card">
        <b>${esc(name)}</b>
        <div class="muted fs-xs mt-1">${esc(tip)}</div>
        <div class="mini-actions">
          <button class="btn ghost small" data-sub-qr="${escAttr(url)}">二维码</button>
          <button class="btn ghost small" data-sub-copy="${escAttr(url)}">复制订阅</button>
        </div>
      </div>`).join("")}
  </div>
  <div class="muted fs-xs mt-3">
    路由器端是唯一"全自动"的形态: 装一次, 全屋生效, 之后连开关都不用点。
  </div>`;
}

/* ---------------- 事件绑定 ---------------- */

function bind(dash, routers) {
  const pairBtn = $("#btn-pair");
  if (pairBtn) pairBtn.onclick = makePairCode;
  const copy = $("#btn-copy-cmd");
  if (copy) copy.onclick = () => copyText(pairInfo.command);
  const add = $("#btn-add-device");
  if (add) add.onclick = makePairCode;

  document.querySelectorAll("[data-sub-copy]").forEach((el) => {
    el.onclick = () => copyText(el.dataset.subCopy);
  });
  document.querySelectorAll("[data-sub-qr]").forEach((el) => {
    el.onclick = () => {
      const fmt = el.dataset.subQr === (dash.subscription_formats || {}).base64 ? "base64" : "clash";
      const q = `format=${encodeURIComponent(fmt)}`;
      openQr({
        title: "订阅二维码",
        sub: "用对应客户端的扫码导入功能扫描",
        link: el.dataset.subQr,
        svg: `/api/subscription/qr?img=svg&${q}`,
        png: `/api/subscription/qr?size=8&${q}`,
        file: `zeroproxy-sub-${fmt}.png`,
      });
    };
  });

  document.querySelectorAll("[data-dev-toggle]").forEach((el) => {
    el.onchange = () => toggleDevice(el.dataset.devToggle, el.checked);
  });
  document.querySelectorAll("[data-dev-tpl]").forEach((el) => {
    el.onchange = async () => {
      try {
        await api(`/api/devices/${encodeURIComponent(el.dataset.devTpl)}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ template: el.value }),
        });
        toast("分流模板已更新, 路由器将于 15 秒内生效");
        await refreshDevices();
      } catch (e) {
        toast(e.message || "修改失败");
      }
    };
  });
  document.querySelectorAll("[data-dev-rename]").forEach((el) => {
    el.onclick = () => renameDevice(el.dataset.devRename);
  });
  document.querySelectorAll("[data-dev-remove]").forEach((el) => {
    el.onclick = () => removeDevice(el.dataset.devRemove);
  });
}

async function makePairCode() {
  if (busy) return;
  busy = true;
  try {
    pairInfo = await api("/api/devices/pair", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ label: "" }),
    });
    renderClients(S.dash);
    const box = $("#btn-copy-cmd");
    if (box) box.focus();
  } catch (e) {
    toast(e.message || "生成失败");
  } finally {
    busy = false;
  }
}

async function refreshDevices() {
  const data = await api("/api/devices");
  S.dash.devices = data.devices;
  S.dash.client = data.client;
  renderClients(S.dash);
  return data.devices;
}

async function toggleDevice(id, on) {
  try {
    await api(`/api/devices/${encodeURIComponent(id)}/proxy`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ on }),
    });
  } catch (e) {
    toast(e.message || "操作失败");
    renderClients(S.dash);
    return;
  }
  // 立刻把本地状态改成"同步中", 再短轮询等设备回报 —— 不做假绿: 变绿的条件是
  // 设备真的回报了 actual == desired。
  const item = (S.dash.devices.items || []).find((d) => d.id === id);
  if (item) { item.desired = on; item.syncing = item.online; }
  renderClients(S.dash);

  clearInterval(syncTimers[id]);
  let tries = 0;
  syncTimers[id] = setInterval(async () => {
    tries += 1;
    let devices;
    try {
      devices = await refreshDevices();
    } catch (e) {
      return;
    }
    const now = (devices.items || []).find((d) => d.id === id);
    if (!now || !now.online || now.actual === now.desired || tries >= 12) {
      clearInterval(syncTimers[id]);
      delete syncTimers[id];
      if (now && now.online && now.actual !== now.desired) {
        toast("路由器还没按要求切换 —— 可在设备端执行 zeroproxy log 查看原因");
      }
    }
  }, 3000);
}

function renameDevice(id) {
  const item = (S.dash.devices.items || []).find((d) => d.id === id);
  openConfirm({
    title: "重命名设备",
    html: `<label>设备名</label><input id="dev-rename-input" value="${escAttr(item ? item.name : "")}" maxlength="40">`,
    okLabel: "保存",
    onOk: async () => {
      const value = ($("#dev-rename-input") || {}).value || "";
      try {
        await api(`/api/devices/${encodeURIComponent(id)}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name: value }),
        });
        await refreshDevices();
      } catch (e) {
        toast(e.message || "改名失败");
      }
    },
  });
  const input = $("#dev-rename-input");
  if (input) { input.focus(); input.select(); }
}

function removeDevice(id) {
  const item = (S.dash.devices.items || []).find((d) => d.id === id);
  openConfirm({
    title: "移除这台设备？",
    html: `<b>${esc(item ? item.name : "")}</b> 会立刻失去访问权限, 上面正在运行的代理随之失效。<br>
           <span class="muted">设备上的程序不会自动卸载 —— 需要在路由器上执行 <code class="mono">zeroproxy uninstall</code> 才会清干净。</span>`,
    okLabel: "移除",
    onOk: async () => {
      try {
        await api(`/api/devices/${encodeURIComponent(id)}`, { method: "DELETE" });
        toast("已移除");
        await refreshDevices();
      } catch (e) {
        toast(e.message || "移除失败");
      }
    },
  });
}
