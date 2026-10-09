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
let coreTimer = null;     // "准备内核"期间的轮询定时器

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
  // 本机覆盖优先说。面板不可达时用户能在路由器上直接开关 (zeroproxy on|off), 那之后
  // 面板改不动它 —— 这时显示"同步中…"会让人以为再等等就好, 而其实要回路由器上
  // 执行 zeroproxy local-auto 才会交回面板。
  const override = String((d.report || {}).override || "").toLowerCase();
  if ((override === "on" || override === "off") && (override === "on") !== !!d.desired) {
    const want = override === "on" ? "开" : "关";
    return `<span class="pill warn" title="这台路由器在面板不可达时被本机设成了「${want}」。面板的开关现在改不动它, 直到在路由器上执行 zeroproxy local-auto"><i class="dot warn"></i>本机覆盖 (${want})</span>`;
  }
  if (d.syncing) return `<span class="pill warn"><i class="dot warn"></i>同步中…</span>`;
  if (!d.connected) return `<span class="pill other"><i class="dot other"></i>已关闭</span>`;
  // "内核在跑" ≠ "流量被接管": 真机 8.45 上内核启动成功, 但 tun 建不出来、tproxy 也
  // 没有, 局域网里一台设备都没被接管 —— 面板当时还是绿的。设备把现场验过的覆盖范围
  // 一起报上来 (report.covered), 这里据此把话说细。
  const cov = coveredOf(d);
  if (cov === "none") return `<span class="pill bad"><i class="dot err"></i>未接管</span>`;
  if (cov === "lan_tcp") return `<span class="pill warn"><i class="dot warn"></i>已连接 (仅 TCP)</span>`;
  return `<span class="pill ok"><i class="dot running"></i>已连接</span>`;
}

/** 设备上报的数据面与它真正覆盖到的范围。
 *
 *  这两个值由路由器**现场验证**后写进 caps 再随心跳上报 (不是面板猜的, 也不是"命令
 *  跑过了"就算): full=全屋+本机 / lan=全屋(本机除外) / lan_tcp=仅局域网 TCP / none=未接管。
 */
const COVERED_LABEL = {
  full: "全屋 (含路由器自身)",
  lan: "全屋 (路由器自身除外)",
  lan_tcp: "仅局域网 TCP",
  none: "未接管",
};
const MODE_LABEL = {
  // 性能模式: 内核态 eBPF 分流 (dae), 直连流量真旁路。它也是 covered=full 的一档,
  // 所以这里必须单独标出来 —— 否则面板上看起来和 TUN 没区别, 而用户是特意点开它的。
  ebpf: "性能模式 (eBPF)",
  tun: "TUN",
  tproxy: "tproxy",
  redirect: "iptables REDIRECT",
  none: "未接管",
};

function coveredOf(d) {
  return String((d.report || {}).covered || "").toLowerCase();
}

/** 设备卡上的那一枚"接管到哪"的标签 (带原因 tooltip)。 */
function coverageChip(d) {
  const r = d.report || {};
  const cov = coveredOf(d);
  if (!d.online || !d.actual || !cov) return "";
  const why = r.why ? ` title="${escAttr(r.why)}"` : "";
  // 覆盖范围是 none 时**不挂模式标签**: "TUN · 未接管" 自相矛盾 (真机截图里就是这么显示
  // 的), 而它正是这一整套改动要消灭的那种"看起来接管了"。要说就说一句"未接管"。
  if (cov === "none") return `<span class="tag-chip"${why}>未接管</span>`;
  const mode = MODE_LABEL[String(r.mode || "").toLowerCase()] || "";
  const txt = COVERED_LABEL[cov] || cov;
  // IPv6 是单独一格: 局域网设备从运营商那里拿到原生 v6, 而只接管 v4 的透明代理对 v6
  // 等于不存在 —— 那些流量直接出去, 目标网站看到的是真实 v6 地址。设备探得到就不标,
  // 探不到必须写出来 (它比"全屋已接管"更值得一眼看见)。
  const v6 = String(r.ipv6 ?? "") === "0" && cov !== "none"
    ? `<span class="tag-chip" title="这台设备的数据面覆盖不到 IPv6: 局域网设备的 v6 流量会直接出去, 目标网站能看到真实的 v6 地址">IPv6 未接管</span>`
    : "";
  // 实测吞吐: **这台机器**能跑多快, 不是节点好坏。同一个节点在手机上能跑 200 Mbps、
  // 在这台双核 A53 上可能只有 40 —— 它决定了"换协议 / 换节点还有没有意义"。
  // 数字来自设备上的 `zeroproxy bench` (靶子是面板, 两条路跑同一段路)。
  const dp = Number(r.bench_direct || 0);
  const pp = Number(r.bench_proxy || 0);
  const mb = (n) => Math.round((n / 1024) * 10) / 10;
  const bench = pp > 0
    ? `<span class="tag-chip" title="zeroproxy bench 实测: 直连 ${mb(dp)} MB/s · 经代理 ${mb(pp)} MB/s">实测 ${mb(pp)} MB/s</span>`
    : "";
  return `<span class="tag-chip"${why}>${esc(mode ? `${mode} · ${txt}` : txt)}</span>${v6}${bench}`;
}

/** 内核缓存这一行 —— 回答"现在发这条安装命令, 会不会卡在下载内核上"。
 *
 *  真机反馈 (GL-MT3600BE / OpenWrt 25.12.5): 安装停在「下载代理内核」上不动。
 *  根因在面板侧 (没有缓存 + 没有总时限), 但用户看到的只有路由器终端里那行不动的
 *  输出。所以面板这里要**提前**说清楚: 面板有没有这一档内核、正在取还是取失败了,
 *  并且给一个"先把内核取回来"的按钮 —— 取一次, 之后所有路由器都复用。
 */
function coreRow(dash) {
  const client = (dash && dash.client) || {};
  const cores = client.cores || [];
  if (!cores.length) return "";
  const ver = client.core_version ? `mihomo ${esc(client.core_version)}` : "mihomo";
  const main = cores.find((c) => c.arch === "arm64") || cores[0];
  if (main.state === "ready") {
    return `<div class="client-hint">
      内核已就绪 (${ver} · ${esc(main.label || main.arch)}) —— 安装命令跑到下载那一步
      是面板直传, 不会卡在"面板去上游取"上。
      ${restArches(cores)}
    </div>`;
  }
  if (main.state === "downloading") {
    const mb = Math.round((main.bytes || 0) / 1048576);
    return `<div class="client-hint">
      面板正在取内核 (${ver} · ${esc(main.label || main.arch)})${mb ? `, 已取 ${mb} MB` : ""}…
      <span class="muted fs-xs">取好后所有路由器复用同一份</span>
      <button class="btn ghost small" data-core-refresh>刷新状态</button>
    </div>`;
  }
  const bad = main.state === "error";
  return `<div class="client-hint">
    <b>面板还没有 ${esc(main.label || main.arch)} 这一档内核</b> (${ver})。
    先让面板取回来, 安装命令就不会卡在"下载代理内核"那一步 (取一次, 之后所有路由器复用):
    <button class="btn small" data-core-prepare="${escAttr(main.arch)}">准备内核</button>
    ${bad && main.error ? `<div class="muted fs-xs mt-1">上次失败: ${esc(main.error)}</div>` : ""}
    <div class="muted fs-xs mt-1">
      面板自己取不到时 (到上游的线路不通), 可以把压缩包手动放进面板的
      <code class="mono">data/client/cores/</code> 目录, 文件名:
      <code class="mono">mihomo-${esc(main.arch)}-${esc(client.core_version || "")}.gz</code>
    </div>
    ${restArches(cores)}
  </div>`;
}

/** 其它架构 (MIPS / x86 / 老 ARM): 折叠起来, 但让用小众设备的人也能自己准备。 */
function restArches(cores) {
  const rest = cores.filter((c) => c.arch !== "arm64" && c.arch !== "armv7");
  if (!rest.length) return "";
  const ready = rest.filter((c) => c.state === "ready").map((c) => c.label || c.arch);
  const todo = rest.filter((c) => c.state !== "ready");
  return `<details class="client-help">
    <summary>其它 CPU 架构的小设备 (${ready.length ? `已就绪 ${ready.length} 种` : "都没准备"})</summary>
    <div class="muted fs-xs mt-2">
      ${todo.map((c) => `<span class="tag-chip">${esc(c.label || c.arch)}</span>
        <button class="btn ghost small" data-core-prepare="${escAttr(c.arch)}">准备</button>`).join(" ")}
      ${todo.length ? "" : `<span class="tag-chip">全都准备好了</span>`}
    </div>
  </details>`;
}

/** 本地控制面 (zpcore) —— 面板分发的可选件。
 *
 *  为什么值得单独说一句: 管理界面原来是三条路 (固件 Web 服务 / 它的 cgi / 退回 busybox
 *  httpd), 三种固件三种坏法, 用户改不了。装上这个静态二进制之后, 路由器自己起服务、
 *  自己校验令牌、只绑局域网地址 —— "界面能不能打开"就不再是变量。
 *
 *  它是可选的: 没准备时装机照常完成, 只是走原来的界面路径。所以这里的口气是"可做",
 *  不是"缺了会坏"。
 */
function agentRow(dash) {
  const client = (dash && dash.client) || {};
  const agents = client.agents || [];
  if (!agents.length) {
    return `<div class="client-hint">
      <b>本地控制面 (zpcore) 还没准备</b> —— 这是可选件, 装上之后路由器不再依赖固件的
      Web 服务器就能打开管理界面; 不装不影响代理。
      在面板上跑一次 <code class="mono">scripts/build-agent.sh</code>, 把
      <code class="mono">client/agent/dist/</code> 一起部署即可 (只构建自己那几种架构也行)。
    </div>`;
  }
  const labels = agents.map((a) => esc(a.label || a.arch)).join(" · ");
  return `<div class="client-hint">
    本地控制面 zpcore 已准备 <b>${agents.length} 档</b> (${labels}) —— 这些架构的路由器
    装机时会自动装上, 管理界面由它自己发, 不再依赖固件 Web 服务器。
  </div>`;
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
    <div class="muted fs-xs mt-2">
      升级路由器上的客户端 (界面 / agent) 用这条固定的更新命令, <b>不需要配对码, 也不会多出一台设备</b>:
      <code class="mono">wget -qO- &lt;面板地址&gt;/c/install.sh | sh</code>
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
        ${coverageChip(d)}
        ${d.version ? `<span class="tag-chip">客户端 v${esc(d.version)}</span>` : ""}
      </div>
      ${d.ui ? `
      <div class="dev-sub">
        <a class="btn ghost small" href="${escAttr(d.ui)}" target="_blank" rel="noreferrer"
           title="只在路由器所在的局域网内可用; 打不开就在路由器上执行 zeroproxy ui">打开路由器管理界面</a>
        <span class="muted fs-xs">同一局域网内可直接打开 (地址里带着这台路由器的界面令牌)</span>
      </div>` : ""}
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
  ${pairInfo ? "" : coreRow(dash)}
  ${pairInfo ? "" : agentRow(dash)}
  ${pairInfo ? pairCard(dash) : `
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
      支持 OpenWrt / GL.iNet / 小米 / 华硕等基于 OpenWrt 的设备。首次安装需要 ≥ 90 MB 可用
      空间 (内核约 57 MB + 分流数据约 5 MB); **已经装过内核的机器**重跑安装命令只需要
      十几 MB —— 它只更新客户端与分流数据。内核与分流数据都由面板分发, 路由器只需要能
      连上面板: 装机时它还没有代理可用, 不该去 GitHub 拉任何东西。<br>
      装完后每台路由器在面板上是一张卡片, 可以单独开关和移除。
    </div>
  </details>`;
}

function pairCard(dash) {
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
    ${coreRow(dash)}
    ${agentRow(dash)}
    <div class="muted fs-xs mt-2">
      安装过程约 1 分钟 (含 20 MB 内核 + 4 MB 分流数据下载); 结束后终端会告诉你是 TUN
      还是 tproxy 模式, 以及分流是否已就绪; 数据面的覆盖范围 (全屋 / 仅局域网 TCP) 会
      跟着设备回报显示在卡片上。刷新本页即可看到设备卡片。
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
  document.querySelectorAll("[data-core-prepare]").forEach((el) => {
    el.onclick = () => prepareCore(el.dataset.corePrepare);
  });
  const coreRefresh = $("[data-core-refresh]");
  if (coreRefresh) coreRefresh.onclick = () => { refreshDevices().catch(() => {}); };

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

/** 让面板现在就去把这一档内核取回来 (取一次, 之后所有路由器复用)。
 *
 *  为什么要这一步: 面板没缓存时, 第一次安装要等面板从上游拉 20 MB —— 那段时间
 *  路由器那边只是在等 (真机上表现为"卡在下载代理内核上不动")。提前取好, 安装就是
 *  纯局域网传输。
 */
async function prepareCore(arch) {
  try {
    await api(`/api/devices/cores/${encodeURIComponent(arch)}/prepare`, { method: "POST" });
  } catch (e) {
    toast(e.message || "无法开始下载");
    return;
  }
  toast("面板开始取内核 (约 1 分钟), 取好后所有路由器复用同一份");
  await refreshDevices().catch(() => {});
  clearInterval(coreTimer);
  let tries = 0;
  coreTimer = setInterval(async () => {
    tries += 1;
    try {
      await refreshDevices();
    } catch (e) {
      return;
    }
    const st = ((S.dash.client || {}).cores || []).find((c) => c.arch === arch) || {};
    if (st.state === "downloading" && tries < 40) return;
    clearInterval(coreTimer);
    coreTimer = null;
    if (st.state === "ready") toast("内核已就绪 —— 现在发安装命令不会卡在下载那一步");
    else if (st.state === "error") toast(`面板没取到内核: ${st.error || "未知原因"}`);
  }, 3000);
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
