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
  $('sub').textContent = state.core === 'running'
    ? `内核运行中 · ${state.mode === 'tun' ? 'TUN 全屋透明代理' : 'tproxy 全屋透明代理'}`
    : '内核已停止 — 全屋按普通方式上网';
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

async function load() {
  try {
    render(await call('status'));
  } catch (e) {
    $('sub').textContent = e.message;
    $('sub').style.color = 'var(--err)';
  }
}

$('toggle').onchange = async (ev) => {
  const on = ev.target.checked;
  try {
    const r = await call('toggle', { on });
    toast(unesc(r.message).split('\n')[0]);
    setTimeout(load, 1500);
  } catch (e) {
    toast(e.message);
    ev.target.checked = !on;
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
