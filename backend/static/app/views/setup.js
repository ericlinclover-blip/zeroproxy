/** 初始化 (三输入框 → 一键生成 → 交接到域名面板) 与登录页。
 *
 *  这一层只做"页面级"交互: 仪表盘的事一律通过 reloadDash() 钩子回调,
 *  免得和 views/dashboard.js 互相 import。模块被 import 时即绑定各按钮。
 */
import { $, esc, toast, show } from "../lib/dom.js";
import { api } from "../lib/api.js";
import { forgetToken } from "../lib/bootstrap.js";
import { S, reloadDash } from "../lib/state.js";
import { renderSteps } from "../lib/render.js";

/* ---------------- 部署 ---------------- */
$("#btn-setup").onclick = async () => {
  const payload = {
    domain: $("#in-domain").value.trim(),
    username: $("#in-user").value.trim(),
    password: $("#in-pass").value,
    token: S.bootstrapToken,
  };
  const errBox = $("#setup-err");
  errBox.classList.add("hidden");
  const prog = $("#setup-progress");
  prog.classList.add("hidden");
  prog.innerHTML = "";
  const btn = $("#btn-setup");
  btn.disabled = true;
  btn.textContent = "部署中, 证书申请约需 30-60 秒…";
  $("#setup-bar").classList.remove("hidden");
  try {
    const res = await api("/api/setup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    renderSteps(res.steps || [], prog);
    prog.classList.remove("hidden");
    $("#setup-bar").classList.add("hidden");
    // 拿到 2xx = 服务端已经收下这次初始化 (并作废了引导令牌), 本标签页不用再留着它
    forgetToken();
    const failed = (res.steps || []).filter((s) => !s.ok);
    const dest = res.redirect || {};
    if (!failed.length && dest.ready) {
      // 部署顺利 + 域名已带真证书可达 → 直接把用户送到正式入口
      // (留在这个 IP 页面上只会一直看到"不安全"的证书警告)
      btn.textContent = "完成 ✓";
      showSetupHandoff(dest, payload.username);
      return;
    }
    if (res.ok === false || failed.length) {
      // 不再假装成功: 失败步骤留在页面上, 让用户先看到再进面板
      btn.textContent = "完成 (有步骤失败)";
      errBox.textContent =
        `有 ${failed.length} 步失败: ${failed[0].name} — ${failed[0].detail}` +
        "\n面板已进入仪表盘, 可用「一键诊断」/「一键修复」重试。";
      errBox.classList.remove("hidden");
      toast(`部署完成但有 ${failed.length} 步失败`);
    } else {
      btn.textContent = "完成 ✓";
      // 初始化是在 **HTTP** 页面上做的 (引导阶段面板同时挂在 80 端口, 这样点开
      // 终端给的链接就是初始化页, 不用先跟"您的连接不是私密连接"打交道)。而配置
      // 一落进 nginx, 80 端口就只剩 ACME 与跳转 —— 这一页的后续请求会立刻失效
      // (拿到的是伪装主页), 所以主动把人送到 HTTPS 面板。域名面板就绪就跳域名,
      // 否则回到 IP 的 HTTPS 入口 (那一次证书提示躲不掉, 但已经初始化完了)。
      if (dest.secure_url && location.protocol === "http:") {
        showSetupHandoff({ url: dest.secure_url }, payload.username, 0, {
          stay: false,
          note: "面板已切到 HTTPS。IP 地址用的是自签证书, 浏览器会提示一次\"不安全\", " +
            "点「继续访问」即可; 之后请改用你的域名访问面板 (真实证书, 无警告)。",
        });
        return;
      }
      if (dest.url && !dest.ready) {
        // 证书/域名这一步没成: 说清原因, 别让用户以为该用域名却打不开
        const hint = $("#setup-hint");
        hint.textContent =
          `本页面走的是 IP + 自签证书 (浏览器会提示"不安全")。域名面板暂时还不可用: ` +
          `${dest.reason}。修好 DNS / 证书后到「高级设置 → 重新应用」重试, 或直接点下面的「重新应用配置」。`;
        hint.classList.remove("hidden");
      }
    }
    setTimeout(() => { reloadDash(); }, 1400);
  } catch (e) {
    $("#setup-bar").classList.add("hidden");
    errBox.textContent = "部署失败: " + e.message;
    errBox.classList.remove("hidden");
    btn.disabled = false;
    btn.textContent = "一键生成";
  }
};

/* 部署完成 → 交接到新的面板入口。默认 3 秒后自动跳, 也给"留在本页"的出口
 * (opts.stay === false 时不提供它: 那种情况下本页已经不再提供面板, 留下来只会
 *  看到"连接中断" —— 例如初始化是在 80 端口的 HTTP 页面上做的)。 */
export function showSetupHandoff(dest, user, seconds, opts = {}) {
  const url = `${String(dest.url || "").replace(/\/+$/, "")}/?user=${encodeURIComponent(user || "")}`;
  const total = Number(seconds) > 0 ? Number(seconds) : 3;
  const note = opts.note || `该地址用的是真实证书, 不会再报"不安全"; 用户名已预填, 输入密码即可登录。`;
  const stay = opts.stay === false ? "" : `<button class="btn ghost small" id="handoff-stay">留在本页</button>`;
  const box = $("#setup-done");
  box.classList.remove("hidden");
  box.innerHTML = `
    <div class="progress mt-0">
      <div class="pstep"><span class="ico ok">✓</span><span>部署完成</span>
        <div class="detail">${esc(dest.reason || "域名面板已就绪")}</div></div>
    </div>
    <div class="hint-box">
      <div id="handoff-count">正在跳转到 <b>${esc(url)}</b> · ${total} 秒</div>
      <div class="row center mt-3">
        <button class="btn small" id="handoff-go">立即前往</button>
        ${stay}
      </div>
      <div class="muted fs-sm mt-2">${note}</div>
    </div>`;
  let left = total;
  const go = () => { location.href = url; };
  const timer = setInterval(() => {
    left -= 1;
    const el = $("#handoff-count");
    if (el) el.innerHTML = `正在跳转到 <b>${esc(url)}</b> · ${left} 秒`;
    if (left <= 0) { clearInterval(timer); go(); }
  }, 1000);
  $("#handoff-go").onclick = go;
  const stayBtn = $("#handoff-stay");
  if (stayBtn) stayBtn.onclick = () => {
    clearInterval(timer);
    box.classList.add("hidden");
    box.innerHTML = "";
    reloadDash();
  };
}

/* ---------------- 登录 ---------------- */
$("#btn-login").onclick = async () => {
  const errBox = $("#login-err");
  errBox.classList.add("hidden");
  try {
    await api("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: $("#login-user").value.trim(), password: $("#login-pass").value }),
    });
    reloadDash();
  } catch (e) {
    errBox.textContent = e.message;
    errBox.classList.remove("hidden");
  }
};
$("#in-pass").addEventListener("keydown", (e) => { if (e.key === "Enter") $("#btn-setup").click(); });
$("#login-pass").addEventListener("keydown", (e) => { if (e.key === "Enter") $("#btn-login").click(); });
$("#btn-logout").onclick = async () => {
  await api("/api/logout", { method: "POST" });
  S.dash = null;
  show("view-login");
};

$("#protoRow").innerHTML = [
  ["vless", "VLESS Reality"], ["vless", "VLESS XHTTP"], ["vless", "VLESS WS"],
  ["trojan", "Trojan TLS"], ["hysteria", "Hysteria 2"],
].map(([c, n]) => `<span class="badge ${c}">${n}</span>`).join("");
