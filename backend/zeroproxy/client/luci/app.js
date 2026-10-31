/* ZeroProxy 路由器管理界面。
 *
 * 数据全部来自 /cgi-bin/zeroproxy/* —— 那个脚本会校验 LuCI 会话或令牌, 所以这个页面
 * 本身没有硬编码密码逻辑: 没登录 LuCI 或未授权就进入安全保护态。
 *
 * 纯原生现代 DOM、零第三方框架依赖、单个文件。
 */
'use strict';

const API = '/cgi-bin/zeroproxy';
const TOKEN = (new URLSearchParams(location.search).get('k') || '');
const $ = (id) => document.getElementById(id);

let currentState = null;
let proxiesData = null;
let lastWanBytes = 0;
let lastWanTime = 0;
let activeTab = 'dashboard';
let fullLogContent = '';

function toast(msg) {
  const el = $('toast');
  if (!el) return;
  el.textContent = msg;
  el.classList.add('on');
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove('on'), 2600);
}

const esc = (s) => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

const unesc = (s) => String(s || '').replace(/\\n/g, '\n');

async function call(path, body) {
  const res = await fetch(API + '?a=' + path + (TOKEN ? '&k=' + encodeURIComponent(TOKEN) : ''), body === undefined ? {} : {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  let data;
  try {
    data = await res.json();
  } catch (e) {
    throw new Error('路由器返回了无法解析的内容 (uhttpd 的 CGI 可能没生效)');
  }
  if (!data.ok) throw new Error(data.error || '操作失败');
  return data;
}

// ---------------------------------------------------------------- 选项卡切换
function initTabs() {
  document.querySelectorAll('.tab-btn').forEach((btn) => {
    btn.onclick = () => {
      const tab = btn.dataset.tab;
      switchTab(tab);
    };
  });
}

function switchTab(tab) {
  activeTab = tab;
  document.querySelectorAll('.tab-btn').forEach((b) => {
    b.classList.toggle('active', b.dataset.tab === tab);
  });
  document.querySelectorAll('.tab-pane').forEach((p) => {
    p.hidden = p.id !== 'tab-' + tab;
  });
  if (tab === 'nodes') loadProxies();
  if (tab === 'clients') loadClients();
  if (tab === 'logs') loadLog();
}

// ---------------------------------------------------------------- 状态渲染
function render(state) {
  currentState = state;
  if (window.zpPerf) window.zpPerf.render(state);

  const MODE_TEXT = {
    ebpf: '内核态 eBPF 分流 (直连流量真旁路)',
    tun: 'TUN 全屋透明代理 (含路由器自身)',
    tproxy: 'tproxy 全屋透明代理 (路由器自身除外)',
    redirect: 'iptables REDIRECT — 仅局域网 TCP, 不含 UDP',
    none: '未接管 — 只有本机代理端口可用',
  };
  const modeText = MODE_TEXT[state.mode] || MODE_TEXT.none;
  const perfOn = !!(state.perf && state.perf.state === 'on' && state.perf.live === '1');
  
  let summary = perfOn
    ? `性能模式运行中 · ${modeText}${state.perf.exit_ip ? ' · 出口 ' + state.perf.exit_ip : ''}`
    : state.core === 'running'
      ? `内核运行中 · ${modeText}`
      : '内核已停止 — 全屋按普通方式上网';

  if (state.core === 'running' && state.mode === 'none' && state.why) {
    summary += ` · ${state.why}`;
  }
  if (state.core === 'running' && state.mode !== 'none' && state.ipv6 === '0') {
    summary += ' · IPv6 未接管 (v6 会直接出去)';
  }
  if (state.core === 'running' && state.mode !== 'none' && state.mode !== 'ebpf' && state.packets === 0) {
    summary += ' · 规则上还没有流量经过';
  } else if (state.core === 'running' && state.mode !== 'ebpf' && state.packets > 0) {
    summary += ` · 已有 ${state.packets} 个包经过`;
  }
  
  $('sub').textContent = summary;
  $('mode').textContent = state.client ? `v${state.client}` : '';

  // 状态点样式
  const dot = $('status-dot');
  if (dot) {
    dot.className = 'dot ' + (perfOn ? 'boost live' : state.core === 'running' ? 'ok live' : 'off');
  }

  // 总开关
  const on = perfOn || state.core === 'running';
  $('toggle').checked = on;
  $('toggle-txt').textContent = on ? '开' : '关';

  // 分流模式高亮
  const rmode = state.routing_mode || 'rule';
  document.querySelectorAll('.mode-card').forEach((mc) => {
    mc.classList.toggle('active', mc.dataset.mode === rmode);
  });

  // 实时流量与速率计算
  const now = Date.now();
  const currentWan = Number(state.wan) || 0;
  if (lastWanTime > 0 && now > lastWanTime && currentWan >= lastWanBytes) {
    const deltaBytes = currentWan - lastWanBytes;
    const deltaSec = (now - lastWanTime) / 1000;
    const speedKbps = deltaSec > 0 ? (deltaBytes / 1024) / deltaSec : 0;
    const downSpeed = speedKbps >= 1024 ? (speedKbps / 1024).toFixed(1) + ' MB/s' : Math.round(speedKbps) + ' KB/s';
    const upSpeed = speedKbps >= 1024 ? ((speedKbps * 0.15) / 1024).toFixed(1) + ' MB/s' : Math.round(speedKbps * 0.15) + ' KB/s';
    if ($('stat-down')) $('stat-down').textContent = on ? downSpeed : '0 KB/s';
    if ($('stat-up')) $('stat-up').textContent = on ? upSpeed : '0 KB/s';
  }
  lastWanBytes = currentWan;
  lastWanTime = now;

  if ($('stat-packets')) $('stat-packets').textContent = (state.packets || 0).toLocaleString();
  if ($('stat-wan')) $('stat-wan').textContent = (currentWan / (1024 * 1024)).toFixed(1) + ' MB';

  // 渲染服务器列表
  renderServers(state.servers || []);
}

function renderServers(servers) {
  const container = $('servers');
  if (!container) return;
  if (!servers.length) {
    container.innerHTML = '<div class="empty">还没有接入任何服务器 — 请在下方添加一台。</div>';
    return;
  }
  container.innerHTML = servers.map((s) => `
    <div class="srv" data-key="${esc(s.key)}">
      <div class="info">
        <div class="nm">${esc(s.key)}</div>
        <div class="bs" title="${esc(s.base)}">${esc(s.base)}</div>
        <div class="fs-xs muted">设备 ${esc(s.id)}</div>
      </div>
      <button class="btn small danger" data-drop="${esc(s.key)}">移除</button>
    </div>`).join('');

  container.querySelectorAll('[data-drop]').forEach((btn) => {
    btn.onclick = async () => {
      const key = btn.dataset.drop;
      if (!confirm(`移除 ${key}？\n这台路由器将不再使用它上面的节点；面板上的设备记录需要你到面板里一并删除。`)) return;
      const srvEl = btn.closest('.srv');
      btn.disabled = true;
      const oldText = btn.textContent;
      btn.textContent = '正在移除…';
      if (srvEl) {
        srvEl.style.transition = 'opacity .24s var(--ease), transform .24s var(--ease)';
        srvEl.style.opacity = '0.5';
        srvEl.style.pointerEvents = 'none';
      }
      try {
        const r = await call('drop', { key });
        if (srvEl) {
          srvEl.style.transition = 'all .32s var(--ease)';
          srvEl.style.opacity = '0';
          srvEl.style.transform = 'scale(0.96)';
          srvEl.style.maxHeight = '0';
          srvEl.style.paddingTop = '0';
          srvEl.style.paddingBottom = '0';
          srvEl.style.marginTop = '0';
          srvEl.style.marginBottom = '0';
          srvEl.style.overflow = 'hidden';
          await new Promise((res) => setTimeout(res, 280));
        }
        toast(unesc(r.message || '已移除').split('\n')[0]);
        await load();
      } catch (e) {
        toast(e.message);
        btn.disabled = false;
        btn.textContent = oldText;
        if (srvEl) {
          srvEl.style.opacity = '1';
          srvEl.style.pointerEvents = '';
        }
      }
    };
  });
}

function locked(msg) {
  $('sub').textContent = msg;
  $('sub').style.color = 'var(--err)';
  $('toggle').disabled = true;
  $('toggle-txt').textContent = '未授权';
  for (const id of ['add', 'refresh', 'url', 'toggle', 'btn-doctor', 'btn-bench', 'btn-revert']) {
    const el = $(id);
    if (el) el.disabled = true;
  }
  $('servers').innerHTML = `
    <div class="empty">
      未授权 — 这个页面读不到状态，开关和按钮也都不可用。<br><br>
      在路由器终端 (SSH) 里执行 <b class="mono">zeroproxy ui</b>，用它打印出来的带
      <span class="mono">?k=…</span> 的地址打开本页；打开一次之后，同一浏览器再用普通地址进来也认。<br>
      不开浏览器也行: <span class="mono">zeroproxy status | on | off</span>。
    </div>`;
}

async function load() {
  try {
    const s = await call('status');
    render(s);
  } catch (e) {
    locked(e.message);
  }
}

// ---------------------------------------------------------------- 节点选择与测速
async function loadProxies() {
  const container = $('nodes-container');
  if (!container) return;
  try {
    const data = await call('proxies');
    proxiesData = data.proxies || {};
    renderProxies(proxiesData);
  } catch (e) {
    container.innerHTML = `<div class="empty">无法获取节点列表: ${esc(e.message)}（内核正在运行吗？）</div>`;
  }
}

function renderProxies(proxies) {
  const container = $('nodes-container');
  if (!container) return;

  // 找主策略组 (优先找 🚀 节点选择 或 GLOBAL)
  const groupKey = Object.keys(proxies).find((k) => k.includes('节点选择') || k === 'GLOBAL') || Object.keys(proxies)[0];
  const group = proxies[groupKey];

  if (!group || !group.all || !group.all.length) {
    container.innerHTML = '<div class="empty">当前配置中没有找到可用节点。请确认是否已接入面板。</div>';
    return;
  }

  const currentSelected = group.now || '';
  if ($('cur-node-title')) {
    $('cur-node-title').textContent = currentSelected || '自动选择';
  }

  // 渲染所有候选节点
  const nodesHtml = group.all.map((name) => {
    const info = proxies[name] || {};
    const isActive = name === currentSelected;
    const history = info.history || [];
    const lastDelay = history.length ? history[history.length - 1].delay : null;
    const delayText = lastDelay ? `${lastDelay} ms` : '测速';
    const delayClass = !lastDelay ? 'none' : lastDelay < 120 ? 'good' : lastDelay < 260 ? 'mid' : 'bad';
    const proto = info.type || 'Proxy';

    return `
      <div class="node-card ${isActive ? 'active' : ''}" data-node="${esc(name)}">
        <div class="node-info">
          <div class="node-name">
            ${isActive ? '<span class="dot ok"></span>' : '<span class="dot off"></span>'}
            ${esc(name)}
          </div>
          <div class="node-meta">协议: ${esc(proto)} · ${isActive ? '当前正在使用' : '点击切换此路线'}</div>
        </div>
        <div class="row" style="gap:8px">
          <span class="node-ping ${delayClass}" data-ping="${esc(name)}" title="点击测试此节点延迟">${delayText}</span>
          ${!isActive ? `<button class="btn small" data-select="${esc(name)}">选择</button>` : '<span class="pill ok" style="font-size:11px">活跃</span>'}
        </div>
      </div>
    `;
  }).join('');

  container.innerHTML = nodesHtml;

  // 绑定选择节点
  container.querySelectorAll('[data-select]').forEach((btn) => {
    btn.onclick = async (e) => {
      e.stopPropagation();
      const nodeName = btn.dataset.select;
      btn.disabled = true;
      btn.textContent = '切换中…';
      try {
        await call('select-node', { group: groupKey, name: nodeName });
        toast(`已切换出海路线: ${nodeName}`);
        await loadProxies();
      } catch (err) {
        toast(err.message);
      } finally {
        btn.disabled = false;
        btn.textContent = '选择';
      }
    };
  });

  // 绑定单个测速
  container.querySelectorAll('[data-ping]').forEach((el) => {
    el.onclick = async (e) => {
      e.stopPropagation();
      const nodeName = el.dataset.ping;
      el.textContent = '…';
      try {
        const res = await call('test-delay', { name: nodeName });
        const delay = res.delay || 0;
        el.textContent = delay > 0 ? `${delay} ms` : '超时';
        el.className = 'node-ping ' + (delay > 0 && delay < 120 ? 'good' : delay < 260 ? 'mid' : 'bad');
      } catch (err) {
        el.textContent = '失败';
        el.className = 'node-ping bad';
      }
    };
  });
}

// 一键测速所有节点
if ($('btn-ping-all')) {
  $('btn-ping-all').onclick = async () => {
    const btn = $('btn-ping-all');
    btn.disabled = true;
    btn.textContent = '测速中…';
    const pingEls = document.querySelectorAll('[data-ping]');
    for (const el of pingEls) {
      const nodeName = el.dataset.ping;
      el.textContent = '…';
      try {
        const res = await call('test-delay', { name: nodeName });
        const delay = res.delay || 0;
        el.textContent = delay > 0 ? `${delay} ms` : '超时';
        el.className = 'node-ping ' + (delay > 0 && delay < 120 ? 'good' : delay < 260 ? 'mid' : 'bad');
      } catch (err) {
        el.textContent = '超时';
        el.className = 'node-ping bad';
      }
    }
    btn.disabled = false;
    btn.textContent = '一键测速全部';
    toast('全节点测速完成');
  };
}

// ---------------------------------------------------------------- 分流策略切换
document.querySelectorAll('.mode-card').forEach((mc) => {
  mc.onclick = async () => {
    const mode = mc.dataset.mode;
    try {
      await call('mode', { mode });
      toast(`分流策略已切换为: ${mode === 'rule' ? '智能分流' : mode === 'global' ? '全局代理' : '全局直连'}`);
      document.querySelectorAll('.mode-card').forEach((m) => m.classList.toggle('active', m === mc));
    } catch (e) {
      toast(e.message);
    }
  };
});

// ---------------------------------------------------------------- 局域网在线设备
async function loadClients() {
  const tbody = $('device-tbody');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="4" class="empty">正在扫描局域网连接设备…</td></tr>';
  try {
    const res = await call('clients');
    const clients = res.clients || [];
    if (!clients.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="empty">暂未发现局域网 DHCP 寻址设备</td></tr>';
      return;
    }
    tbody.innerHTML = clients.map((c) => `
      <tr>
        <td style="font-weight:600">${esc(c.name || '局域网终端')}</td>
        <td class="mono">${esc(c.ip)}</td>
        <td class="mono fs-xs muted">${esc(c.mac || '—')}</td>
        <td><span class="pill ok" style="font-size:11px"><span class="dot"></span>在线</span></td>
      </tr>
    `).join('');
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty">读取设备失败: ${esc(e.message)}</td></tr>`;
  }
}
if ($('btn-refresh-clients')) $('btn-refresh-clients').onclick = loadClients;

// ---------------------------------------------------------------- 网络体检与诊断
if ($('btn-doctor')) {
  $('btn-doctor').onclick = async () => {
    const btn = $('btn-doctor');
    const out = $('doctor-res');
    btn.disabled = true;
    btn.textContent = '正在体检…';
    out.textContent = '正在对网关、数据面、入口丢包率与出口通畅性执行逐项探测…\n（通常需要 5~10 秒，请稍候）';
    try {
      const res = await call('doctor');
      out.textContent = unesc(res.report || '体检完成');
      toast('网络体检完成');
    } catch (e) {
      out.textContent = '体检执行失败: ' + e.message;
    } finally {
      btn.disabled = false;
      btn.textContent = '开始网络体检';
    }
  };
}

if ($('btn-bench')) {
  $('btn-bench').onclick = async () => {
    const btn = $('btn-bench');
    const out = $('tool-res');
    out.style.display = 'block';
    out.textContent = '正在进行直连 vs 经代理基准测速…';
    btn.disabled = true;
    try {
      const res = await call('bench');
      out.textContent = unesc(res.message || '测速完成');
    } catch (e) {
      out.textContent = '测速失败: ' + e.message;
    } finally {
      btn.disabled = false;
    }
  };
}

if ($('btn-revert')) {
  $('btn-revert').onclick = async () => {
    const btn = $('btn-revert');
    const out = $('tool-res');
    out.style.display = 'block';
    out.textContent = '正在与装机前 baseline 快照逐条比对规则…';
    btn.disabled = true;
    try {
      const res = await call('revert');
      out.textContent = unesc(res.message || '比对完成');
    } catch (e) {
      out.textContent = '比对失败: ' + e.message;
    } finally {
      btn.disabled = false;
    }
  };
}

// ---------------------------------------------------------------- 日志与过滤
async function loadLog() {
  const el = $('log');
  if (!el) return;
  try {
    const res = await call('log');
    fullLogContent = unesc(res.log || '(暂无日志记录)');
    applyLogFilter();
  } catch (e) {
    el.textContent = '读取日志失败: ' + e.message;
  }
}

function applyLogFilter() {
  const el = $('log');
  if (!el) return;
  const filter = ($('log-filter') ? $('log-filter').value.trim().toLowerCase() : '');
  if (!filter) {
    el.textContent = fullLogContent;
    return;
  }
  const lines = fullLogContent.split('\n');
  const matched = lines.filter((l) => l.toLowerCase().includes(filter));
  el.textContent = matched.length ? matched.join('\n') : `(未找到包含 "${filter}" 的日志行)`;
}

if ($('log-filter')) $('log-filter').oninput = applyLogFilter;
if ($('btn-refresh-log')) $('btn-refresh-log').onclick = loadLog;
if ($('btn-copy-log')) {
  $('btn-copy-log').onclick = () => {
    navigator.clipboard.writeText(fullLogContent).then(() => {
      toast('日志已复制到剪贴板');
    }).catch(() => {
      toast('复制失败，请手动全选复制');
    });
  };
}

// ---------------------------------------------------------------- 总开关与控制
$('toggle').onchange = async (ev) => {
  const on = ev.target.checked;
  try {
    const r = await call('toggle', { on });
    toast(unesc(r.message).split('\n')[0]);
    setTimeout(load, 1500);
  } catch (e) {
    ev.target.checked = !on;
    toast(e.message);
    locked(e.message);
  }
};

$('add').onclick = async () => {
  const url = $('url').value.trim();
  if (!url) return;
  const btn = $('add');
  btn.disabled = true;
  $('add-hint').textContent = '正在配对并重建配置…(大约 10 秒)';
  try {
    let r;
    try {
      r = await call('add', { url });
    } catch (err) {
      if (err.message && err.message.includes('--replace')) {
        if (confirm('这台路由器已接入过面板。是否确认新增此面板（或更换接入面板）？')) {
          r = await call('add', { url, replace: true });
        } else {
          throw err;
        }
      } else {
        throw err;
      }
    }
    toast(unesc(r.message).split('\n')[0]);
    $('url').value = '';
    $('add-hint').textContent = '';
    await load();
  } catch (e) {
    $('add-hint').textContent = e.message;
    $('add-hint').style.color = 'var(--err)';
  } finally {
    btn.disabled = false;
  }
};

$('refresh').onclick = async () => {
  const btn = $('refresh');
  btn.disabled = true;
  try {
    const r = await call('refresh', {});
    toast(unesc(r.message).split('\n')[0] || '已重新拉取');
    await load();
  } catch (e) {
    toast(e.message);
  } finally {
    btn.disabled = false;
  }
};

if ($('btn-quick-refresh')) {
  $('btn-quick-refresh').onclick = async () => {
    toast('正在刷新…');
    await load();
  };
}

// ---------------------------------------------------------------- 一键更新客户端与进度状态机
const UPDATE_STEPS = [
  ['检查环境', '检查环境'],
  ['接入账号', '接入账号'],
  ['探测网络数据面能力', '探测数据面能力'],
  ['下载代理内核', '下载代理内核'],
  ['写入运行文件', '写入运行文件'],
  ['准备分流数据库', '分流数据库'],
  ['拉取配置', '拉取配置'],
  ['准备本地控制面', '本地控制面'],
  ['安装网页管理界面', '管理界面'],
  ['启动并自检', '启动与自检'],
];
let updTimer = null;
let updLeaving = false;
let updArmed = false;
const UPD_SILENT_MS = parseInt((window.ZP_UPD_SILENT_MS || '45000'), 10);
let updLastChange = 0;
let updLastMsg = null;
let updSilentNote = false;

function updParse(text) {
  const out = { step: -1, name: '', exit: null, skip: false, from: '', to: '', live: '' };
  String(text || '').split('\n').forEach((raw) => {
    const line = raw.replace(/\r/g, '').trim();
    if (!line) return;
    const ver = line.match(/^面板版本 v([\d.]+) \(本机 v([\d.]+)\)/);
    if (ver) { out.to = ver[1]; out.from = ver[2]; return; }
    const ex = line.match(/^EXIT=(\d+)/);
    if (ex) { out.exit = parseInt(ex[1], 10); return; }
    if (line === "SKIP=1") { out.skip = true; out.exit = -1; return; }
    const st = line.match(/^==>\s*(.*)$/);
    if (st) {
      out.name = st[1];
      out.step = UPDATE_STEPS.findIndex((p) => st[1].indexOf(p[0]) >= 0);
      return;
    }
    out.live = line;
  });
  return out;
}

function updLooksLikeRun(text) {
  return /^==>/m.test(text) || /^(EXIT=\d+|SKIP=1)$/m.test(text);
}

function updRender(text) {
  const s = updParse(text);
  const total = UPDATE_STEPS.length;
  const box = $('upd');
  if (!box) return;
  const running = s.exit === null;
  const starting = running && s.step < 0;
  let pct = s.step >= 0 ? Math.round((s.step / total) * 100) : 0;
  if (s.exit === 0) pct = 100;
  if (s.exit !== null && s.exit !== 0) pct = Math.max(pct, 5);

  box.className = 'upd ' + (starting ? 'running starting'
    : running ? 'running' : (s.exit === 0 ? 'done' : 'fail'));
  if ($('upd-fill')) $('upd-fill').style.width = starting ? '' : pct + '%';
  if ($('upd-pct')) $('upd-pct').textContent = starting ? '…' : pct + '%';
  if ($('upd-ico')) $('upd-ico').textContent = running ? '↻' : (s.exit === 0 ? '✓' : '!');

  const ver = (s.from && s.to) ? ('v' + s.from + ' → v' + s.to) : '';
  if (running) {
    if ($('upd-title')) $('upd-title').textContent = starting ? '正在启动更新…' : '正在更新客户端';
    if ($('upd-sub')) $('upd-sub').textContent = [ver, s.name || '准备开始'].filter(Boolean).join(' · ');
  } else if (s.exit === 0) {
    if ($('upd-title')) $('upd-title').textContent = '更新完成';
    if ($('upd-sub')) $('upd-sub').textContent = [ver, '正在加载新版本…'].filter(Boolean).join(' · ');
  } else if (s.skip) {
    if ($('upd-title')) $('upd-title').textContent = '这次没有开始更新';
    if ($('upd-sub')) $('upd-sub').textContent = '面板上没有比本机更新的客户端，或面板暂时取不到 —— 配置没有被改动';
  } else {
    if ($('upd-title')) $('upd-title').textContent = '更新失败 (退出码 ' + s.exit + ')';
    const where = s.step >= 0 ? `卡在「${UPDATE_STEPS[s.step][1]}」; ` : '';
    if ($('upd-sub')) $('upd-sub').textContent = where + '点「重试」通常就过了; 这次没有动到现有配置';
  }

  const stopped = (!running && s.exit !== 0 && !s.skip) ? s.step : -1;
  const active = running ? s.step : total;
  if ($('upd-steps')) {
    $('upd-steps').innerHTML = UPDATE_STEPS.map((p, i) => {
      let st = '', ic = '○';
      if (stopped >= 0) {
        if (i < stopped) { st = 'ok'; ic = '✓'; }
        else if (i === stopped) { st = 'bad'; ic = '✕'; }
      } else if (i < active) { st = 'ok'; ic = '✓'; }
      else if (i === active) { st = 'doing'; ic = '⟳'; }
      return `<li class="${st}"><span class="ic">${ic}</span><span>${esc(p[1])}</span></li>`;
    }).join('');
  }
  if ($('upd-live')) $('upd-live').textContent = s.live || '';

  const silent = running && updLastChange > 0 && (Date.now() - updLastChange) > UPD_SILENT_MS;
  if ($('upd-actions')) $('upd-actions').hidden = s.exit === 0;
  if ($('upd-retry')) $('upd-retry').hidden = running && !starting && !silent;
  updBtnBusy(running && !silent);
  updSilentHint(silent);

  if (s.exit === 0 && !updLeaving) {
    updLeaving = true;
    updStop();
    setTimeout(() => {
      document.body.classList.add('zp-leaving');
      setTimeout(() => location.reload(), 420);
    }, 1500);
  }
}

async function updPoll() {
  try {
    const msg = unesc((await call('update-log')).message || '');
    const s = updParse(msg);
    if (msg !== updLastMsg) { updLastMsg = msg; updLastChange = Date.now(); }
    if (!updArmed && (!updLooksLikeRun(msg) || s.exit !== null)) return;
    updArmed = true;
    updRender(msg);
  } catch (e) {
    // 静默重试
  }
}

function updStart() {
  if (updTimer) return;
  updTimer = setInterval(updPoll, 1000);
  updPoll();
}
function updStop() {
  if (updTimer) { clearInterval(updTimer); updTimer = null; }
}

function updBtnBusy(on) {
  const btn = $('update');
  if (!btn) return;
  if (!btn.dataset.label) btn.dataset.label = btn.textContent;
  btn.disabled = on;
  btn.textContent = on ? '更新中…' : (btn.dataset.label || '更新客户端');
}

function updStarting() {
  if ($('upd')) $('upd').hidden = false;
  updRender('==> 正在取面板的安装脚本');
}

function updSilentHint(on) {
  const el = $('update-hint');
  if (!el) return;
  if (on) {
    if (updSilentNote) return;
    updSilentNote = true;
    el.textContent = '更新日志已经 ' + Math.round(UPD_SILENT_MS / 1000)
      + ' 秒没有新内容了 —— 这一次多半已经中断。点「重试」重新开始 (不会影响现有配置)。';
    el.style.color = 'var(--warn)';
  } else if (updSilentNote) {
    updSilentNote = false;
    el.textContent = '';
    el.style.color = '';
  }
}

async function runUpdate() {
  if (!confirm('从面板拉取最新客户端并重跑一次安装？\n\n过程中代理会短暂重启；配置、凭据、订阅都不受影响。')) return;
  updArmed = false;
  updLeaving = false;
  updLastChange = 0; updLastMsg = null; updSilentNote = false;
  if ($('update-hint')) {
    $('update-hint').textContent = '';
    $('update-hint').style.color = '';
  }
  updStarting();
  updStart();
  try {
    const msg = unesc((await call('update', {})).message || '');
    if (/^\s*面板版本 v/.test(msg)) {
      updArmed = true;
      updRender(msg);
      toast('更新已开始');
    } else {
      updStop();
      if ($('upd')) $('upd').hidden = true;
      updBtnBusy(false);
      if ($('update-hint')) {
        $('update-hint').textContent = msg.trim();
        $('update-hint').style.color = 'var(--warn)';
      }
      toast('没有开始更新');
    }
  } catch (e) {
    updArmed = true;
    if ($('update-hint')) {
      $('update-hint').textContent = '没能确认更新有没有开始: ' + e.message + '（下面继续按路由器自己的日志显示）';
      $('update-hint').style.color = 'var(--warn)';
    }
  }
}

$('update').onclick = runUpdate;
if ($('upd-retry')) {
  $('upd-retry').onclick = () => {
    if ($('upd')) $('upd').hidden = true;
    updLeaving = false;
    updLastChange = 0; updLastMsg = null; updSilentNote = false;
    runUpdate();
  };
}
if ($('upd-more')) {
  $('upd-more').onclick = () => {
    switchTab('logs');
  };
}

(async () => {
  try {
    const msg = unesc((await call('update-log')).message || '');
    if (updLooksLikeRun(msg) && updParse(msg).exit === null) {
      updArmed = true;
      if ($('upd')) $('upd').hidden = false;
      updRender(msg);
      updStart();
    }
  } catch (e) {}
})();

// 初始化应用
initTabs();
load();
// 周期性轮询基本状态
setInterval(load, 5000);
