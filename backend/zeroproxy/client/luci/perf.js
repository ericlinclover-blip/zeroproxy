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
  const MAX = 8;          // 满刻度 8 (RPM ×1000)
  const ARC = Math.PI * 100;  // 半圆弧长, r = 100
  const FULL_KBPS = 12500;    // 100 Mbps 顶到红区 (家庭宽带里已经很快了)
  const PHASES = 5;

  const needle = { value: 0, target: 0, vel: 0, raf: 0 };
  const last = { at: 0, wan: 0, kbps: 0, live: false, state: '' };
  let timer = 0;
  let busyUntil = 0;

  // ---------------------------------------------------------------- 表盘

  function polar(deg, r) {
    const a = (deg * Math.PI) / 180;
    return [130 + r * Math.cos(a), 130 - r * Math.sin(a)];
  }

  function buildTicks() {
    const g = $('perf-ticks');
    if (!g || g.childNodes.length) return;
    for (let v = 0; v <= MAX; v++) {
      const deg = 180 - (v / MAX) * 180;
      const major = v % 2 === 0;
      const [x1, y1] = polar(deg, major ? 84 : 88);
      const [x2, y2] = polar(deg, 96);
      const line = document.createElementNS(NS, 'line');
      line.setAttribute('x1', x1.toFixed(1));
      line.setAttribute('y1', y1.toFixed(1));
      line.setAttribute('x2', x2.toFixed(1));
      line.setAttribute('y2', y2.toFixed(1));
      line.setAttribute('class', 'pg-tick' + (major ? ' major' : ''));
      line.dataset.v = String(v);
      g.appendChild(line);
      if (major) {
        const [tx, ty] = polar(deg, 68);
        const t = document.createElementNS(NS, 'text');
        t.setAttribute('x', tx.toFixed(1));
        t.setAttribute('y', (ty + 3).toFixed(1));
        t.setAttribute('text-anchor', 'middle');
        t.setAttribute('class', 'pg-num');
        t.textContent = String(v);
        g.appendChild(t);
      }
    }
  }

  function paintNeedle() {
    const el = $('perf-needle');
    if (!el) return;
    const v = Math.max(0, Math.min(MAX, needle.value));
    el.setAttribute('transform', 'rotate(' + (180 - (v / MAX) * 180).toFixed(2) + ' 130 130)');
    const read = $('perf-rpm');
    if (read) read.textContent = String(Math.round(v * 10) / 10);
    document.querySelectorAll('#perf-ticks .pg-tick').forEach((t) => {
      t.classList.toggle('lit', Number(t.dataset.v) <= Math.round(v));
    });
  }

  // 临界阻尼弹簧 —— 真表的针是"甩过去、稳下来", 线性插值看着像在数数。
  function springTick() {
    const k = 0.17, damp = 0.74;
    const delta = needle.target - needle.value;
    needle.vel = (needle.vel + delta * k) * damp;
    needle.value += needle.vel;
    if (Math.abs(needle.target - needle.value) < 0.004 && Math.abs(needle.vel) < 0.004) {
      needle.value = needle.target;
      needle.vel = 0;
      needle.raf = 0;
      paintNeedle();
      return;
    }
    paintNeedle();
    needle.raf = requestAnimationFrame(springTick);
  }

  function to(target) {
    needle.target = Math.max(0, Math.min(MAX, target));
    if (REDUCED) {
      needle.value = needle.target;
      needle.vel = 0;
      paintNeedle();
      return;
    }
    if (!needle.raf) needle.raf = requestAnimationFrame(springTick);
  }

  function setArc(pct) {
    const el = $('perf-arc');
    if (!el) return;
    const p = Math.max(0, Math.min(1, pct));
    el.style.strokeDashoffset = String(ARC * (1 - p));
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

    // 表针: 切换中按进度走, 生效后按真实流量走, 其余贴着 0。
    if (busy && !live) {
      const p = phaseOf(perf) / PHASES;
      to(0.6 + p * 4.6);          // 起步抖一下, 然后随进度一路上扬
      setArc(p);
    } else if (on && live) {
      const rpm = MAX * Math.sqrt(Math.min(1, last.kbps / FULL_KBPS));
      to(Math.max(0.7, rpm));     // 怠速 0.7: 引擎在转, 只是没在飙
      setArc(1);
    } else {
      to(0);
      setArc(0);
    }

    card.classList.toggle('idle', !live);
    card.classList.toggle('live', live);
    card.classList.toggle('booting', busy && !live);
    paintSegs(live ? PHASES : phaseOf(perf), failed && !live);

    const pill = $('perf-pill');
    const capEl = $('perf-cap');
    const sub = $('perf-sub');

    if (!cap) {
      pill.className = 'pill warn';
      pill.innerHTML = '<span class="dot"></span>不可用';
      capEl.textContent = '这台机器开不了: ' + (perf.why || '内核条件不满足');
      sub.textContent = '需要内核 ≥5.17 且带 BTF。缺 BTF 时重跑一次安装命令会自动补上。';
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
      capEl.textContent = (perf.exit_ip ? '出口 ' + perf.exit_ip + ' · ' : '') +
        '内核态分流 · 当前 ' + Math.round(last.kbps) + ' KB/s';
      sub.textContent = '直连流量不再经过用户态 (eBPF 在内核里分流)。' +
        (failed ? ' 上次的结论: ' + (perf.why || '') : '');
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

    // 进入过程中: 一旦真的生效, 给一次"起压"反馈 (闪一下 + 报出口)
    if (live && !last.live) {
      const b = $('perf-btn');
      b.classList.remove('done');
      void b.offsetWidth;           // 让动画能重放
      b.classList.add('done');
      if (window.toast && perf.exit_ip) window.toast('性能模式已开启 · 出口 ' + perf.exit_ip);
    }
    last.live = live;
    last.state = String(perf.state || '');

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
      if (on) { phaseOf({ busy: '1' }); to(1.4); paintSegs(1); }   // 点火: 表针先抖一下
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
