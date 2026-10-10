/* ZeroProxy 性能模式 (内核态 eBPF / dae) —— 路由器本机界面上的那块仪表盘。
 *
 * 为什么值得做一块表盘: 这一档的收益是"直连流量不再经过用户态", 用户看不见也摸不着 ——
 * 那就给一个**看得见**的东西, 但每一帧都必须对应一个真实的事实:
 *   · 表针的转速 = 这台机器此刻 WAN 口上的真实流量 (没有流量就贴着怠速, 不假装在飙);
 *   · 五段进度   = 切换真的走到哪一步了 (取自 CLI 写下的进度文件, 不由前端猜);
 *   · 红灯区     = 已经验证过"流量真的从节点出去了"(出口 IP 是那一刻记下来的);
 *   · 点不动的时候, 表盘上写的是**为什么**点不动。
 *
 * 约定: app.js 画状态时会调用 window.zpPerf.render(state); 这里自己按需要轮询 /cgi-bin/zeroproxy,
 * 因为"切换中"和"看得见的转速"都要比页面其它部分更勤快地刷新。
 */
'use strict';

(function () {
  const $ = (id) => document.getElementById(id);
  const REDUCED = !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  const NS = 'http://www.w3.org/2000/svg';
  const CX = 130;             // 表盘圆心
  const CY = 118;
  const R = 96;               // 弧半径
  const ARC = Math.PI * R;    // 半圆弧长 (301.6)
  const CAP_KBPS = 12500;     // 满弧 = 12.5 MB/s ≈ 100 Mbps (家用宽带里已经很快了)
  const PHASES = 5;

  //: 弧与值点都从**同一个** p 算出来 —— 这样"点在哪"和"弧到哪"永远不会打架
  //: (第一版是指针 + 弧各算各的, 加上旋转方向算反了, 于是针会掉到刻度线下面)。
  const anim = { value: 0, target: 0, vel: 0, raf: 0 };
  const last = { at: 0, wan: 0, kbps: 0, live: false, state: '' };
  let timer = 0;
  let busyUntil = 0;

  // ---------------------------------------------------------------- 表盘

  function polar(deg, r) {
    const a = (deg * Math.PI) / 180;
    return [CX + r * Math.cos(a), CY - r * Math.sin(a)];
  }

  /** 刻度: 半圈 9 根, 每 25% 一根长的。**不写数字** —— 数字留给中间那个真实速率
   *  (第一版把小刻度 + RPM 数字铺在盘面上, 反而把真读数挤成了脚注)。 */
  function buildTicks() {
    const g = $('perf-ticks');
    if (!g || g.childNodes.length) return;
    for (let i = 0; i <= 8; i++) {
      const major = i % 2 === 0;
      const deg = 180 - (i / 8) * 180;
      const [x1, y1] = polar(deg, R + 7);
      const [x2, y2] = polar(deg, R + (major ? 15 : 11));
      const line = document.createElementNS(NS, 'line');
      line.setAttribute('x1', x1.toFixed(1));
      line.setAttribute('y1', y1.toFixed(1));
      line.setAttribute('x2', x2.toFixed(1));
      line.setAttribute('y2', y2.toFixed(1));
      line.setAttribute('class', 'pg-tick' + (major ? ' major' : ''));
      g.appendChild(line);
    }
  }

  /** 弧与值点都由 p (0..1) 画出来 —— 一处几何, 不可能互相打架。 */
  function paintValue(p) {
    const q = Math.max(0, Math.min(1, p));
    const arc = $('perf-arc');
    if (arc) {
      // 圆头线帽会沿切线多伸出去半个线宽 (5px), 减掉它, 弧的**尖端**才是真正的值。
      arc.style.strokeDashoffset = String(ARC * (1 - q) + 5);
    }
    const ring = $('perf-mark-ring');
    const dot = $('perf-mark');
    const show = q > 0.004;
    const [x, y] = polar(180 - q * 180, R);
    [ring, dot].forEach((el) => {
      if (!el) return;
      el.setAttribute('cx', x.toFixed(1));
      el.setAttribute('cy', y.toFixed(1));
      el.setAttribute('opacity', show ? '1' : '0');
    });
  }

  /** 读数: 真实速率 + 真实单位 (KB/s 与 MB/s 都按 1024 算)。 */
  function formatSpeed(kbps) {
    const v = Math.max(0, Number(kbps) || 0);
    if (v >= 1024) return [String(Math.round(v / 1024 * 10) / 10), 'MB/s'];
    if (v >= 10) return [String(Math.round(v)), 'KB/s'];
    return [String(Math.round(v * 10) / 10), 'KB/s'];
  }

  function paintRead(kbps, textOverride, unitOverride) {
    const [num, unit] = formatSpeed(kbps);
    const read = $('perf-rpm');
    const unitEl = $('perf-unit');
    if (read) {
      read.textContent = textOverride !== undefined ? textOverride : num;
      read.classList.toggle('off', textOverride === '—');
    }
    if (unitEl) unitEl.textContent = unitOverride !== undefined ? unitOverride : unit;
  }

  // 临界阻尼弹簧 —— 弧和点"甩过去、稳下来", 而不是数字在跳。读数本身不做平滑:
  // 它就是刚量到的那个速率 (平滑过的数字看着舒服, 但它不是"现在有多快")。
  function springTick() {
    const k = 0.17, damp = 0.74;
    const delta = anim.target - anim.value;
    anim.vel = (anim.vel + delta * k) * damp;
    anim.value += anim.vel;
    if (Math.abs(anim.target - anim.value) < 0.004 && Math.abs(anim.vel) < 0.004) {
      anim.value = anim.target;
      anim.vel = 0;
      anim.raf = 0;
      paintValue(anim.value);
      return;
    }
    paintValue(anim.value);
    anim.raf = requestAnimationFrame(springTick);
  }

  function to(target) {
    anim.target = Math.max(0, Math.min(1, target));
    if (REDUCED) {
      anim.value = anim.target;
      anim.vel = 0;
      paintValue(anim.value);
      return;
    }
    if (!anim.raf) anim.raf = requestAnimationFrame(springTick);
  }

  function paintSegs(n, failed) {
    document.querySelectorAll('#perf-segs i').forEach((el, i) => {
      el.classList.toggle('on', i < n && !(failed && i === n - 1));
      el.classList.toggle('bad', !!failed && i === n - 1);
    });
  }

  // ---------------------------------------------------------------- 状态 → 画面

  /** 切换走到第几段了 —— 取自 CLI 写下的进度原话, 不由前端猜。 */
  function phaseOf(perf) {
    if (perf.state === 'on' && perf.live === '1') return PHASES;
    const t = String(perf.progress || '');
    let n = perf.busy === '1' ? 1 : 0;
    if (/dae|内核/.test(t)) n = Math.max(n, 2);
    if (/分流数据/.test(t)) n = Math.max(n, 3);
    if (/配置|校验/.test(t)) n = Math.max(n, 4);
    if (/切换|验证/.test(t)) n = Math.max(n, 5);
    if (/DONE=[1-9]/.test(t)) return n;   // 失败: 最后亮着的那一段标红
    return n;
  }

  function lastLine(text) {
    const lines = String(text || '').split('|').map((s) => s.trim()).filter(Boolean);
    return lines.length ? lines[lines.length - 1] : '';
  }

  function render(state) {
    const card = $('perf-card');
    const btn = $('perf-btn');
    if (!card || !btn) return;
    buildTicks();

    const perf = (state && state.perf) || {};
    const cap = perf.cap === '1';
    const live = perf.live === '1';
    const on = perf.state === 'on';
    const busy = perf.busy === '1';
    const failed = /DONE=[1-9]/.test(String(perf.progress || ''));

    // 转速来源: WAN 口的**真实**字节数增量 (state.wan 由 cgi / zpcore 给出)。
    // 拿不到就算了 —— 那时表针贴着怠速, 绝不假装在飙。
    const now = Date.now();
    if (state && state.wan !== undefined && last.at) {
      const dt = (now - last.at) / 1000;
      const db = Number(state.wan) - last.wan;
      if (dt > 0.2 && db >= 0) last.kbps = (db / 1024) / dt;
    }
    last.at = now;
    last.wan = Number((state && state.wan) || 0);

    // 弧与点 = 当前速率占上限的比例。**切换中不许假装速度**: 那一档读数照旧是真实速率,
    // 进度由下面那五段说 (第一版让指针按进度乱走, 看起来像在飙, 其实一个包都没过)。
    const frac = Math.min(1, last.kbps / CAP_KBPS);
    if (on && live) {
      to(Math.pow(frac, 0.6));    // 低速率也要看得出动静 (开方一点的观感)
    } else {
      to(0);
    }
    paintRead(on && live ? last.kbps : 0);

    card.classList.toggle('idle', !live);
    card.classList.toggle('live', live);
    card.classList.toggle('booting', busy && !live);
    // 五段只说"切换走到哪一步": 切换中/失败时出现, 平时收起来 (开着还亮着五条, 像进度条没走完)。
    const segsEl = $('perf-segs');
    const showSegs = busy || failed;
    if (segsEl) segsEl.classList.toggle('hidden', !showSegs);
    if (showSegs) paintSegs(phaseOf(perf), failed && !live);

    const pill = $('perf-pill');
    const capEl = $('perf-cap');
    const warnEl = $('perf-warn');
    const sub = $('perf-sub');
    if (warnEl) warnEl.textContent = '';

    if (!cap) {
      pill.className = 'pill warn';
      pill.innerHTML = '<span class="dot"></span>不可用';
      capEl.textContent = '这台机器开不了: ' + (perf.why || '内核条件不满足');
      sub.textContent = '需要内核 ≥5.17 且带 BTF。缺 BTF 时重跑一次安装命令会自动补上。';
      paintRead(0, '—', '不可用');
      btn.textContent = '不可用';
      btn.disabled = true;
    } else if (busy && !live) {
      pill.className = 'pill warn';
      pill.innerHTML = '<span class="dot"></span>进入中…';
      capEl.textContent = lastLine(perf.progress) || '正在准备…';
      sub.textContent = '正在取内核 / 校验配置 / 验证出口 —— 任何一步失败都会自动退回原来的模式。';
      btn.textContent = '切换中…';
      btn.disabled = true;
      busyUntil = now + 90000;
    } else if (on && !live) {
      pill.className = 'pill warn';
      pill.innerHTML = '<span class="dot"></span>异常';
      capEl.textContent = 'dae 不在 —— 正在自动退回标准模式 (约 45 秒内)';
      sub.textContent = perf.why || '这一档下标准模式的内核是停着的, 所以必须退回去, 不能停在这里。';
      btn.textContent = '等待回退';
      btn.disabled = true;
    } else if (on && live) {
      pill.className = 'pill ok';
      pill.innerHTML = '<span class="dot"></span>已开启';
      // 出口这一个是探针**从这台路由器自己**测到的。它要是正好等于本机 WAN 地址 (面板那条
      // 心跳看到的就是它), 那这条流量根本没走代理 —— 如实标出来, 不把它写成"节点出口"(8.86)。
      const own = String(perf.exit_ip || '') !== '' && String(perf.exit_ip) === String(perf.wan_ip || '');
      capEl.textContent = (perf.exit_ip ? '出口 ' + perf.exit_ip + (own ? ' (本机)' : '') + ' · ' : '') +
        '内核态 eBPF 分流 · 上限约 100 Mbps';
      if (own && warnEl) {
        warnEl.textContent = '探针走的是本机出口: 路由器自身的流量没走代理 (局域网设备不受影响)';
      }
      sub.textContent = '直连流量不再经过用户态 (eBPF 在内核里分流)。' +
        (failed || perf.why ? ' 上次的结论: ' + (perf.why || '') : '');
      btn.textContent = '熄火 (回到标准模式)';
      btn.disabled = false;
    } else {
      pill.className = 'pill off';
      pill.innerHTML = '<span class="dot"></span>未开启';
      capEl.textContent = '就绪 — 可以切到内核态 eBPF';
      sub.textContent = perf.why
        ? '上次的结论: ' + perf.why
        : '直连流量将不再经过用户态; 切换过程中会验证出口, 失败自动退回。';
      btn.textContent = '启动引擎';
      btn.disabled = false;
    }

    schedule(live, busy, now);
  }

  // ---------------------------------------------------------------- 轮询
  // 为什么自己轮询而不是等 app.js: ① "切换中"要一秒级刷新才顺滑; ② 开着的时候表针要跟着
  // 真实流量动, 而 app.js 平时不轮询。两处都只读同一个 status 接口, 不额外增加后端负担。
  function schedule(live, busy, now) {
    const want = busy || live;
    if (!want) {
      if (timer) { clearTimeout(timer); timer = 0; }
      return;
    }
    if (timer) return;
    const period = busy ? 1200 : 4000;
    timer = setTimeout(async () => {
      timer = 0;
      if (busyUntil && now > busyUntil) busyUntil = 0;
      try {
        if (typeof window.load === 'function') await window.load();
      } catch (e) { /* 页面其余部分会自己报错 */ }
    }, period);
  }

  async function fire(on) {
    const btn = $('perf-btn');
    btn.classList.remove('done');
    btn.classList.add('firing');
    setTimeout(() => btn.classList.remove('firing'), 460);
    btn.disabled = true;
    try {
      const r = await window.call(on ? 'perf-on' : 'perf-off');
      if (window.toast) window.toast(String((r && r.message) || '已提交').split('\n')[0]);
      if (on) {
        // 点火: 立刻把五段亮起来 (切换进度就归它说), 读数与弧照旧是真实速率 —— 不假装在飙。
        const segs = $('perf-segs');
        if (segs) segs.classList.remove('hidden');
        paintSegs(1);
        to(0);
      }
      busyUntil = Date.now() + 90000;
      if (typeof window.load === 'function') await window.load();
    } catch (e) {
      btn.disabled = false;
      if (window.toast) window.toast(e.message);
    }
  }

  function init() {
    const btn = $('perf-btn');
    if (!btn || btn.dataset.zpBound) return;
    btn.dataset.zpBound = '1';
    buildTicks();
    paintSegs(0);
    to(0);
    btn.addEventListener('click', () => {
      const perf = (window.zpPerfState || {}).perf || {};
      const isOn = perf.state === 'on' && perf.live === '1';
      fire(!isOn);
    });
  }

  window.zpPerf = {
    render: function (state) {
      init();
      window.zpPerfState = state || {};
      render(state);
    },
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
