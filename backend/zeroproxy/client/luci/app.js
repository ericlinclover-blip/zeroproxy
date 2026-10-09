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
  // 拉配置要连面板, 是整条安装里最容易卡住的一步 —— 以前它没有 `==>`, 于是清单里没有
  // 它, 失败时就变成"九步全绿 + 失败 56%"那一幕, 谁看都对不上。
  ['拉取配置', '拉取配置'],
  ['准备本地控制面', '本地控制面'],
  ['安装网页管理界面', '管理界面'],
  ['启动并自检', '启动与自检'],
];
let updTimer = null;
let updLeaving = false;
/* 已经看见**本次**更新的输出了。在那之前, 日志里可能还躺着上一次更新留下的 "EXIT=0" ——
 * 拿它当真, 页面就会在刚点完确认时跳去"更新完成"并自动刷新, 而实际上什么都没开始。 */
let updArmed = false;

function updParse(text) {
  const out = { step: -1, name: '', exit: null, skip: false, from: '', to: '', live: '' };
  String(text || '').split('\n').forEach((raw) => {
    const line = raw.replace(/\r/g, '').trim();
    if (!line) return;
    const ver = line.match(/^面板版本 v([\d.]+) \(本机 v([\d.]+)\)/);
    if (ver) { out.to = ver[1]; out.from = ver[2]; return; }
    const ex = line.match(/^EXIT=(\d+)/);
    if (ex) { out.exit = parseInt(ex[1], 10); return; }
    // "这次没有开始更新" (面板比本机旧 / 取不到面板的脚本) 也是终态, 但**不是**更新失败。
    // 没有这个第二终态, 日志会停在一行 "==>" 上, 刷新之后进度面板永远转不完。
    if (line === "SKIP=1") { out.skip = true; out.exit = -1; return; }
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
  // 还停在第一个已知小节之前 (最常见的就是"正在取面板的安装脚本"): 这一段**没有可报的
  // 百分比**, 报个 3% 是编的。改用"来回跑"的不确定进度条, 老实说"在启动"。
  const starting = running && s.step < 0;
  // 正在第 k 段 = 前 k 段已完成; 起步给一点点, 免得一动不动像卡住
  let pct = s.step >= 0 ? Math.round((s.step / total) * 100) : 0;
  if (s.exit === 0) pct = 100;
  if (s.exit !== null && s.exit !== 0) pct = Math.max(pct, 5);

  box.className = 'upd ' + (starting ? 'running starting'
    : running ? 'running' : (s.exit === 0 ? 'done' : 'fail'));
  $('upd-fill').style.width = starting ? '' : pct + '%';   // 不确定态交给 CSS 的动画
  $('upd-pct').textContent = starting ? '…' : pct + '%';
  $('upd-ico').textContent = running ? '↻' : (s.exit === 0 ? '✓' : '!');

  const ver = (s.from && s.to) ? ('v' + s.from + ' → v' + s.to) : '';
  if (running) {
    $('upd-title').textContent = starting ? '正在启动更新…' : '正在更新客户端';
    $('upd-sub').textContent = [ver, s.name || '准备开始'].filter(Boolean).join(' · ');
  } else if (s.exit === 0) {
    $('upd-title').textContent = '更新完成';
    $('upd-sub').textContent = [ver, '正在加载新版本…'].filter(Boolean).join(' · ');
  } else if (s.skip) {
    // 闸门拦下 / 取不到面板的脚本: 这次**没有开始**。写成"更新失败"是另一种错 ——
    // 什么都没跑, 配置一个字节也没被动过。
    $('upd-title').textContent = '这次没有开始更新';
    $('upd-sub').textContent = '面板上没有比本机更新的客户端, 或面板暂时取不到 —— 配置没有被改动';
  } else {
    $('upd-title').textContent = '更新失败 (退出码 ' + s.exit + ')';
    // 说清**卡在哪一步**: 十有八九是面板那条链路掉了个包, 而重试一次就过了 —— 这句话
    // 比"更新失败"本身有用得多 (真机上用户就是靠它才不用去重新配对)。
    const where = s.step >= 0 ? `卡在「${UPDATE_STEPS[s.step][1]}」; ` : '';
    $('upd-sub').textContent = where + '点「重试」通常就过了; 这次没有动到现有配置';
  }

  // 失败 / 没有开始时**不把后面几步也打勾** —— 那正是真机截图上那一幕: 九步全绿配一个
  // "更新失败 56%"。停在哪个已知小节就把它标成失败, 后面的老实显示"还没做"。
  const stopped = (!running && s.exit !== 0 && !s.skip) ? s.step : -1;
  const active = running ? s.step : total;
  $('upd-steps').innerHTML = UPDATE_STEPS.map((p, i) => {
    let st = '', ic = '○';
    if (stopped >= 0) {
      if (i < stopped) { st = 'ok'; ic = '✓'; }
      else if (i === stopped) { st = 'bad'; ic = '✕'; }
    } else if (i < active) { st = 'ok'; ic = '✓'; }
    else if (i === active) { st = 'doing'; ic = '⟳'; }
    return `<li class="${st}"><span class="ic">${ic}</span><span>${esc(p[1])}</span></li>`;
  }).join('');
  $('upd-live').textContent = s.live || '';
  // 跑完之后收起按钮区; 但**更新中**也要留一个「看完整日志」的口子 —— 真卡住时那是唯一
  // 能自救的入口。「重试」则只在没在跑的时候出现: 跑得好好的摆一个"重试"只会让人手痒。
  $('upd-actions').hidden = s.exit === 0;
  $('upd-retry').hidden = running;
  updBtnBusy(running);

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
    const msg = unesc((await call('update-log')).message || '');
    const s = updParse(msg);
    // 还没看到**本次**的输出之前, 日志里那句可能是上一次留下的 —— 尤其是一份带 EXIT=0
    // 的"更新完成": 照它渲染, 页面会在刚点完确认时就假报完成并自动刷新。CLI 一动手就会
    // 先清空日志并落一行, 所以这里等到"有内容且没有终态"再认。
    if (!updArmed && (!msg.trim() || s.exit !== null)) return;
    updArmed = true;
    updRender(msg);
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

/* 更新在跑的时候按钮必须锁住: 进度条转着而按钮还能点, 一点就是第二次更新 —— 两次抢同一个
 * 日志、抢同一份文件替换, 结果是哪一次的都说不清。 */
function updBtnBusy(on) {
  const btn = $('update');
  if (!btn) return;
  if (!btn.dataset.label) btn.dataset.label = btn.textContent;
  btn.disabled = on;
  btn.textContent = on ? '更新中…' : (btn.dataset.label || '更新客户端');
}

/* "先给反馈, 再等后端": 按下确认之后立刻把进度面板亮成不确定态 —— 后端那一步要先去面板
 * 取脚本 (会重试三次, 丢包的链路上最坏几十秒), 干等正是用户看到的"点了没反应"。 */
function updStarting() {
  $('upd').hidden = false;
  updRender('==> 正在取面板的安装脚本');
}

$('update').onclick = async () => {
  if (!confirm('从面板拉取最新客户端并重跑一次安装？\n\n过程中代理会短暂重启；配置、凭据、订阅都不受影响。')) return;
  updArmed = false;
  updLeaving = false;
  $('update-hint').textContent = '';
  $('update-hint').style.color = '';
  // 先给反馈: 进度面板立刻亮出来 (不确定态), 之后由 update-log 驱动成真实进度。
  updStarting();
  updStart();
  try {
    const msg = unesc((await call('update')).message || '');
    if (/^\s*面板版本 v/.test(msg)) {
      // 后端确认"已经开始"了 —— 从这一刻起日志就是这个进程的: CLI 一动手就会先清空
      // 日志再落一行, 所以此刻那份旧内容已经被覆盖, 可以放心认了。
      updArmed = true;
      updRender(msg);
      toast('更新已开始');
    } else {
      // 闸门拦下 (面板还是旧版) 之类的"没有开始": 如实说, 不显示进度条
      updStop();
      $('upd').hidden = true;
      updBtnBusy(false);
      $('update-hint').textContent = msg.trim();
      $('update-hint').style.color = 'var(--warn)';
      toast('没有开始更新');
    }
  } catch (e) {
    // 进度面板**不收起**, 也先不说"失败了": 面板那条路会重试, 而 agent 的动作超时是 90
    // 秒 —— "报错了但更新其实在跑"在真机上出现过。让它继续按日志说话, 同时把这句实情
    // 写在上面, 用户至少知道现在是什么状态、该看哪里。
    // 也arm: 请求本身出错不等于它没动手, 而日志才是唯一的事实来源。
    updArmed = true;
    $('update-hint').textContent = '没能确认更新有没有开始: ' + e.message + '（下面继续按路由器自己的日志显示）';
    $('update-hint').style.color = 'var(--warn)';
  }
};
$('upd-retry').onclick = () => { $('upd').hidden = true; updLeaving = false; $('update').click(); };
$('upd-more').onclick = () => { document.querySelector('details').open = true; };

// 刷新页面 / 换设备打开时, 如果更新还在跑, 接着显示进度 (不依赖"点过那个按钮")
(async () => {
  try {
    const msg = unesc((await call('update-log')).message || '');
    // 判据是"日志里有一次**没有终态**的运行": CLI 一动手就往日志里落一行, 所以连"正在取
    // 面板的安装脚本"那一段也能接着显示; 而跑完 / 没开始 / 失败都带终态, 刷新之后就不会
    // 停在一个假的进度上。
    if (msg.trim() && updParse(msg).exit === null) {
      updArmed = true;
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
