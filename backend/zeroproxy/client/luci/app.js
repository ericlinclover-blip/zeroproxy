/* ZeroProxy 路由器管理界面。
 *
 * 数据全部来自 /cgi-bin/zeroproxy/* —— 那个脚本会校验 LuCI 会话, 所以这个页面
 * 本身没有登录逻辑: 没登录 LuCI 就只会看到一句"请先登录"。
 *
 * 这里是路由器上跑的页面, 所以刻意保持朴素: 原生 DOM、零依赖、一个文件。
 */
'use strict';

const API = '/cgi-bin/zeroproxy';
/* 令牌直接从地址栏带过来, 每个请求都附上 (?k=…)。
   原本靠第一次响应种的 cookie, 但真机上 fcgiwrap 那条路上 cookie 没落地 —— 与其查它,
   不如不去依赖它: 这个地址本来就是 `zeroproxy ui` 打印给用户看的。 */
const TOKEN = (new URLSearchParams(location.search).get('k') || '');
/* 接口一律走 query (?a=status): GL.iNet 固件的 80 端口是 nginx + fcgiwrap,
   PATH_INFO 不保证传给脚本, 而 query 一定会到。 */
const $ = (id) => document.getElementById(id);

function toast(msg) {
  const el = $('toast');
  el.textContent = msg;
  el.classList.add('on');
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove('on'), 2600);
}

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

function render(state) {
  // 说的是**现场验过的**模式与覆盖范围, 不是"我们打算用什么": 内核在跑但一级都没接管
  // 时, 这里要明确写"未接管", 而不是含混地写"全屋透明代理" (真机 8.45 的教训)。
  const MODE_TEXT = {
    tun: 'TUN 全屋透明代理 (含路由器自身)',
    tproxy: 'tproxy 全屋透明代理 (路由器自身除外)',
    redirect: 'iptables REDIRECT — 仅局域网 TCP, 不含 UDP',
    none: '未接管 — 只有本机代理端口可用',
  };
  const modeText = MODE_TEXT[state.mode] || MODE_TEXT.none;
  $('sub').textContent = state.core === 'running'
    ? `内核运行中 · ${modeText}`
    : '内核已停止 — 全屋按普通方式上网';
  if (state.core === 'running' && state.mode === 'none' && state.why) {
    $('sub').textContent += ` · ${state.why}`;
  }
  // IPv6 是泄漏面, 单独说一句: 局域网设备的 v6 会直接出去 (目标网站看得到真实地址)。
  // 探不到时后端给 "0"; 老版本没有这一位时是 undefined, 那时不说 (不能凭空断言)。
  if (state.core === 'running' && state.mode !== 'none' && state.ipv6 === '0') {
    $('sub').textContent += ' · IPv6 未接管 (v6 会直接出去)';
  }
  // 规则在 ≠ 有流量: 接口名写错时规则照样装得上, 却一个包都不命中。0 包要写出来,
  // 但那也可能只是"刚开机" —— 所以措辞是"还没有", 不是"坏了"。
  if (state.core === 'running' && state.mode !== 'none' && state.packets === 0) {
    $('sub').textContent += ' · 规则上还没有流量经过';
  } else if (state.core === 'running' && state.packets > 0) {
    $('sub').textContent += ` · 已有 ${state.packets} 个包经过`;
  }
  $('mode').textContent = state.client ? `客户端 v${state.client}` : '';

  const on = state.core === 'running';
  $('toggle').checked = on;
  $('toggle-txt').textContent = on ? '开' : '关';

  if (!state.servers.length) {
    $('servers').innerHTML = '<div class="empty">还没有接入任何服务器 — 用下面那张卡添加一台。</div>';
    return;
  }
  $('servers').innerHTML = state.servers.map((s) => `
    <div class="srv" data-key="${esc(s.key)}">
      <div class="info">
        <div class="nm">${esc(s.key)}</div>
        <div class="bs" title="${esc(s.base)}">${esc(s.base)}</div>
        <div class="fs-xs muted">设备 ${esc(s.id)}</div>
      </div>
      <button class="btn small danger" data-drop="${esc(s.key)}">移除</button>
    </div>`).join('');

  $('servers').querySelectorAll('[data-drop]').forEach((btn) => {
    btn.onclick = async () => {
      const key = btn.dataset.drop;
      if (!confirm(`移除 ${key}？\n这台路由器将不再使用它上面的节点；面板上的设备记录需要你到面板里一并删除。`)) return;
      btn.disabled = true;
      try {
        const r = await call('drop', { key });
        toast((r.message || '已移除').split('\n')[0]);
        await load();
      } catch (e) {
        toast(e.message);
        btn.disabled = false;
      }
    };
  });
}

const esc = (s) => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

const unesc = (s) => String(s || '').replace(/\\n/g, '\n');

/* 读不到状态时 (没有令牌 / 没有 LuCI 会话): 这个页面既显示不了任何真实状态, 也改不了
   任何东西 —— 那就把控件全部禁用并明确说清楚, 而不是留一个"看起来关着、点了没反应"的
   开关让用户猜 (真机反馈: "那个开关是关闭的, 而且也无法打开, 是 bug 吗?")。
   令牌从哪来: 路由器终端里 `zeroproxy ui` 打印的那条带 ?k=… 的地址。 */
function locked(msg) {
  $('sub').textContent = msg;
  $('sub').style.color = 'var(--err)';
  $('toggle').disabled = true;
  $('toggle-txt').textContent = '未授权';
  for (const id of ['add', 'refresh', 'url', 'toggle']) {
    const el = $(id);
    if (el) el.disabled = true;
  }
  $('servers').innerHTML = `
    <div class="empty">
      未授权 — 这个页面读不到状态, 开关和按钮也都不可用。<br><br>
      在路由器终端 (SSH) 里执行 <b class="mono">zeroproxy ui</b>, 用它打印出来的带
      <span class="mono">?k=…</span> 的地址打开本页; 打开一次之后, 同一浏览器再用普通地址
      进来也认。<br>
      不开浏览器也行: <span class="mono">zeroproxy status | on | off</span>。
    </div>`;
}

async function load() {
  try {
    render(await call('status'));
  } catch (e) {
    // status 拿不到 = 这个页面看不到任何真实状态, 于是进入"未授权"的只读说明态
    locked(e.message);
  }
}

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
    const r = await call('add', { url });
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
    const r = await call('refresh');
    toast(unesc(r.message).split('\n')[0] || '已重新拉取');
    await load();
  } catch (e) {
    toast(e.message);
  } finally {
    btn.disabled = false;
  }
};

/* ---------------- 一键更新 + 进度 ----------------
 *
 * 步骤清单**来自安装脚本自己打印的 `==>` 小节** —— 前端只数走到第几段, 不猜、也不编一个
 * 假的百分比 (面板上那张"升级进度"卡片是同一个思路)。状态一律从 `update-log` 里读:
 * 有 `EXIT=` 就是跑完了, 没有就是在跑 —— 所以刷新页面也能接着显示。
 */
const UPDATE_STEPS = [
  ['检查环境', '检查环境'],
  ['接入账号', '接入账号'],
  ['探测网络数据面能力', '探测数据面能力'],
  ['下载代理内核', '下载代理内核'],
  ['写入运行文件', '写入运行文件'],
  ['准备分流数据库', '分流数据库'],
  ['准备本地控制面', '本地控制面'],
  ['安装网页管理界面', '管理界面'],
  ['启动并自检', '启动与自检'],
];
let updTimer = null;
let updLeaving = false;

function updParse(text) {
  const out = { step: -1, name: '', exit: null, from: '', to: '', live: '' };
  String(text || '').split('\n').forEach((raw) => {
    const line = raw.replace(/\r/g, '').trim();
    if (!line) return;
    const ver = line.match(/^面板版本 v([\d.]+) \(本机 v([\d.]+)\)/);
    if (ver) { out.to = ver[1]; out.from = ver[2]; return; }
    const ex = line.match(/^EXIT=(\d+)/);
    if (ex) { out.exit = parseInt(ex[1], 10); return; }
    const st = line.match(/^==>\s*(.*)$/);
    if (st) {
      out.name = st[1];
      out.step = UPDATE_STEPS.findIndex((p) => st[1].indexOf(p[0]) >= 0);
      return;
    }
    out.live = line;   // 最后一行有内容的输出 —— 就是"此刻在做什么"
  });
  return out;
}

function updRender(text) {
  const s = updParse(text);
  const total = UPDATE_STEPS.length;
  const box = $('upd');
  const running = s.exit === null;
  // 正在第 k 段 = 前 k 段已完成; 起步给一点点, 免得一动不动像卡住
  let pct = s.step >= 0 ? Math.round((s.step / total) * 100) : 0;
  if (running) pct = Math.max(pct, 3);
  if (s.exit === 0) pct = 100;
  if (s.exit !== null && s.exit !== 0) pct = Math.max(pct, 5);

  box.className = 'upd ' + (running ? 'running' : (s.exit === 0 ? 'done' : 'fail'));
  $('upd-fill').style.width = pct + '%';
  $('upd-pct').textContent = pct + '%';
  $('upd-ico').textContent = running ? '↻' : (s.exit === 0 ? '✓' : '!');

  const ver = (s.from && s.to) ? ('v' + s.from + ' → v' + s.to) : '';
  if (running) {
    $('upd-title').textContent = '正在更新客户端';
    $('upd-sub').textContent = [ver, s.name || '准备开始'].filter(Boolean).join(' · ');
  } else if (s.exit === 0) {
    $('upd-title').textContent = '更新完成';
    $('upd-sub').textContent = [ver, '正在加载新版本…'].filter(Boolean).join(' · ');
  } else {
    $('upd-title').textContent = '更新失败 (退出码 ' + s.exit + ')';
    $('upd-sub').textContent = '点「看完整日志」能看到卡在哪一步; 重试不会影响现有配置';
  }

  const active = running ? s.step : total;
  $('upd-steps').innerHTML = UPDATE_STEPS.map((p, i) => {
    const st = i < active ? 'ok' : (i === active ? 'doing' : '');
    const ic = i < active ? '✓' : (i === active ? '⟳' : '○');
    return `<li class="${st}"><span class="ic">${ic}</span><span>${esc(p[1])}</span></li>`;
  }).join('');
  $('upd-live').textContent = s.live || '';
  // 「重试 / 看完整日志」只在**失败**时出现: 跑得好好的时候摆一个"重试"只会让人手痒,
  // 而跑完就更不需要了。
  $('upd-actions').hidden = !(s.exit !== null && s.exit !== 0);

  if (s.exit === 0 && !updLeaving) {
    // 先让人看清"完成了", 再整页淡出换新版 —— 那一跳不该是"啪"地闪一下
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
    updRender(unesc((await call('update-log')).message));
  } catch (e) {
    /* 更新期间界面文件正在被替换, 偶尔取不到是正常的 —— 下一轮再问 */
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

$('update').onclick = async () => {
  if (!confirm('从面板拉取最新客户端并重跑一次安装？\n\n过程中代理会短暂重启；配置、凭据、订阅都不受影响。')) return;
  const btn = $('update');
  btn.disabled = true;
  $('update-hint').textContent = '';
  $('update-hint').style.color = '';
  try {
    const msg = unesc((await call('update')).message || '');
    if (/^\s*面板版本 v/.test(msg)) {
      $('upd').hidden = false;
      updRender(msg);
      updStart();
      toast('更新已开始');
    } else {
      // 闸门拦下 (面板还是旧版) 之类的"没有开始": 如实说, 不显示进度条
      $('update-hint').textContent = msg.trim();
      $('update-hint').style.color = 'var(--warn)';
      toast('没有开始更新');
    }
  } catch (e) {
    $('update-hint').textContent = e.message;
    $('update-hint').style.color = 'var(--err)';
  } finally {
    btn.disabled = false;
  }
};
$('upd-retry').onclick = () => { $('upd').hidden = true; updLeaving = false; $('update').click(); };
$('upd-more').onclick = () => { document.querySelector('details').open = true; };

// 刷新页面 / 换设备打开时, 如果更新还在跑, 接着显示进度 (不依赖"点过那个按钮")
(async () => {
  try {
    const msg = unesc((await call('update-log')).message || '');
    if (updParse(msg).exit === null && msg.indexOf('==>') >= 0) {
      $('upd').hidden = false;
      updRender(msg);
      updStart();
    }
  } catch (e) { /* 老固件上没有这个动作时静默 */ }
})();

document.querySelector('details').addEventListener('toggle', async (ev) => {
  if (!ev.target.open) return;
  $('log').textContent = '加载中…';
  try {
    $('log').textContent = unesc((await call('log')).log) || '(没有日志)';
  } catch (e) {
    $('log').textContent = e.message;
  }
});

load();
