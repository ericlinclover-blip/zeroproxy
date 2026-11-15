/** Inspect each hop and run checks for the selected route without changing routing. */
import { $, esc, escAttr } from "../lib/dom.js";
import { fmtTime, nodeStateText, chainHealth, probeMatchesRouting } from "../lib/format.js";
import { S, redrawDash } from "../lib/state.js";
import { api } from "../lib/api.js";
let selection = "", activeHop = "entry", probing = "";
const checks = new Map();
const notices = new Map();

// Pure model: selected, enabled and verified are deliberately separate states.
export function connectionModel(dash, probeData, selected = "", now = Date.now() / 1000) {
  const nodes = dash.nodes || [];
  const entries = (dash.chain || {}).entries || [];
  const options = [...nodes.map((n) => ({ key: `node:${n.id}`, kind: "node", object: n })),
    ...entries.map((e) => ({ key: `chain:${e.id}`, kind: "chain", object: e }))];
  const hit = options.find((o) => o.key === selected) || options.find((o) => o.kind === "node" && o.object.enabled) || options[0];
  if (!hit) return { options, title: "尚未配置节点。", summary: "先在节点列表或链式连接中添加配置。", state: "unknown" };
  const n = hit.object;
  const chain = hit.kind === "chain" ? n : n.chain ? entries.find((e) => e.id === n.id || e.local_port === n.port) : entries.find((e) => e.enabled && e.default_out && n.service !== "hysteria2" && n.protocol !== "Hysteria 2");
  const nodeProbe = (probeMatchesRouting(dash, probeData) ? probeData?.nodes || [] : []).find((p) => p.node === n.id);
  const p = hit.kind === "chain" ? n.last_probe : nodeProbe || (n.chain ? n.last_probe : null);
  const checked = !p ? null : hit.kind === "chain" || (!nodeProbe && n.chain) ? p.ts : p.checked_at || probeData?.checked_at;
  const stale = !checked || now - checked > 300 || ((hit.kind === "chain" || n.chain) && (hit.kind === "chain" ? n : chain)?.probe_current === false);
  const broken = !!chain && (chain.needs_repair === true || chain.pin_ok === false);
  const unavailable = hit.kind === "node" && ["failed", "inactive", "not-installed"].includes(n.service_state);
  const innerDown = !!chain && chain.transport === "hysteria2" && chain.hy_ready === false;
  let state = "unknown", title = "连接，等待验证。";
  if (!n.enabled) { state = "off"; title = "这条连接已停用。"; }
  else if (broken || unavailable || innerDown || p?.ok === false) { state = "failed"; title = "连接需要检查。"; }
  else if (p?.ok === true && p.kind === "deep" && p.probe_ok !== false && !stale) { state = "verified"; title = "探测已通过。"; }
  else if (p?.ok === true) title = stale ? "检查结果已过期。" : p.kind === "udp" ? "UDP 监听，出网待验证。" : "端口可达，出网待验证。";
  if (hit.kind === "chain" || (n.chain && !nodeProbe)) {
    const health = chainHealth(hit.kind === "chain" ? n : { ...chain, enabled: n.enabled, service_state: n.service_state }, now);
    state = n.chain && hit.kind === "node" && health.state === "verified" ? "unknown" : health.state;
    title = health.state === "verified" ? "探测已通过。" : health.state === "off" ? "这条连接已停用。" : health.state === "failed" ? "连接需要检查。" : "连接，等待验证。";
  }
  if (n.chain && !nodeProbe && state === "unknown" && p?.ok) title = "落地段通过，入口待验证。";
  if (hit.kind === "chain" && state === "verified") title = "落地段验证通过。";
  const issue = broken ? "落地端证书指纹需要修复，请重新配对后验证。" : innerDown ? "QUIC 内层进程尚未就绪，请检查链式连接。" : unavailable ? "节点服务当前不可用，请检查服务状态。" : "";
  return { options, ...hit, chain, issue, probe: p, checked, stale, state, title,
    summary: hit.kind === "chain" ? "正在查看落地端。实际出口由设备分流与默认出口共同决定。" : "正在查看节点。服务器探测结果不等于设备端的连接质量。" };
}

function jump(id, objectId) {
  const anchor = document.createElement("a");
  anchor.href = "#" + id; document.body.appendChild(anchor); anchor.click(); anchor.remove();
  const candidates = objectId ? [...document.querySelectorAll("[data-field-node], [data-chain-probe]")] : [];
  const target = candidates.find((el) => el.dataset.fieldNode === objectId || el.dataset.chainProbe === objectId);
  if (target) { target.scrollIntoView({ block: "center", behavior: "auto" }); target.focus({ preventScroll: true }); }
}

function currentModel() {
  let m = connectionModel(S.dash, S.probeData, selection);
  const saved = checks.get(m.key);
  // A result belongs to the route and configuration that was actually tested.
  if (saved && saved.signature === routeSignature(m) && (!m.checked || saved.body.checked_at >= m.checked)) {
    m = connectionModel(S.dash, saved.body, m.key);
  }
  return m;
}
function routeSignature(m) {
  const n = m.object || {};
  return JSON.stringify([S.dash.chain?.probe_revision, m.key, S.dash.domain,
    n.enabled, n.host, n.port, n.transport, n.protocol, n.service_state, n.share_link,
    m.chain?.pin_ok, m.chain?.hy_ready]);
}

export async function checkFieldRoute() {
  const m = currentModel();
  if (!m.object?.enabled || probing || S.opBusy || S.applyJobId) return;
  const key = m.key, signature = routeSignature(m);
  probing = key; S.opBusy += 1; notices.delete(key); renderField();
  try {
    if (m.kind === "chain") {
      S.dash = await api(`/api/chain/entries/${encodeURIComponent(m.object.id)}/probe`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: "{}",
      });
      redrawDash(true);
    } else {
      const body = await api(`/api/probe?deep=1&force=1&node=${encodeURIComponent(m.object.id)}`);
      checks.set(key, { signature, body });
    }
  } catch (e) {
    // Keep the last evidence and label a failed request separately from a failed route.
    notices.set(key, "未取得新检查结果：" + e.message + "。可重试或打开完整诊断。");
  } finally {
    probing = ""; S.opBusy -= 1; renderField();
  }
}

export function renderField() {
  if (!S.dash || !$("#connection-field")) return;
  const m = currentModel(); selection = m.key || "";
  const root = $("#connection-field"); root.dataset.state = m.state;
  root.setAttribute("aria-busy", String(probing === selection));
  $("#field-device").dataset.state = "unknown";
  $("#field-entry").dataset.state = m.state === "off" ? "off" : m.object?.service_state === "failed" ? "failed" : "unknown";
  $("#field-exit").dataset.state = m.chain ? chainHealth(m.chain).state : "unknown";
  $("#field-headline").textContent = probing === selection ? "正在检查当前路线。" : m.title;
  $("#field-summary").textContent = m.kind === "chain" ? "检查入口服务器到落地端的连接；设备到入口仍需设备端验证。" : "选择路线，再点击任一段查看证据。检查不会切换设备出口。";
  const select = $("#field-object-select");
  const options = m.options.map((o) => `<option value="${escAttr(o.key)}">${esc(o.kind === "chain" ? "落地 · " : "节点 · ")}${esc(o.object.name || o.object.label || o.object.host)}${o.object.enabled ? "" : "（停用）"}</option>`).join("");
  if (select.innerHTML !== options) select.innerHTML = options;
  select.value = selection; select.disabled = !m.options.length;
  select.onchange = () => { selection = select.value; activeHop = "entry"; renderField(); };
  const chain = m.chain, p = m.probe;
  const chainSelected = m.kind === "chain";
  $("#field-entry-name").textContent = m.object?.name || (chainSelected ? S.dash.domain : "尚无节点") || "本机入口";
  $("#field-entry-host").textContent = m.kind === "node" ? `${m.object.transport || m.object.protocol || "—"} / ${m.object.port}` : S.dash.domain || "当前服务器";
  $("#field-exit-name").textContent = chain ? (chain.label || "链式落地") : "本机直接出网";
  $("#field-exit-host").textContent = chain?.host || S.dash.system?.server?.public_ip || "公网 IP 未知";
  $("#field-device-status").textContent = "设备端待验证 · 点击接入";
  const entryStatus = !m.object ? "尚未配置" : !m.object.enabled ? "已停用" : chainSelected ? "仅检查服务器间连接" : nodeStateText(m.object);
  $("#field-entry-status").textContent = entryStatus;
  $("#field-exit-status").textContent = chain ? chainHealth(chain).text : "按分流规则出网";
  $("#field-proof").textContent = { verified: "服务器验证通过", failed: "检查发现异常", off: "路线已停用", unknown: "证据待补齐" }[m.state];
  const deep = p?.kind === "deep" || ((chainSelected || m.object?.chain) && p?.probe_ok === true);
  const level = !p ? "尚未检查" : deep ? "真实出网" : p.kind === "udp" ? "UDP 监听" : "端口 / TLS";
  $("#field-latency").textContent = p?.ms != null ? `${Math.round(p.ms)} ms` : "—";
  $("#field-level").textContent = p && (p.ok == null || p.probe_ok === false) ? "未完成检查" : level;
  $("#field-age").textContent = m.checked ? m.stale ? "已过期 · 请重查" : `${Math.max(0, Math.floor((Date.now() / 1000 - m.checked) / 60))} 分钟内` : "尚无结果";
  $("#field-age").title = m.checked ? fmtTime(m.checked) : "";
  $("#field-feedback").textContent = notices.get(selection) || (probing ? probing === selection ? "仅检查所选路线，请稍候；不会重启或切换出口。" : "另一条路线正在检查，完成后可检查当前路线。" : "");
  const proof = !p ? "尚无结果" : p.ok == null || p.probe_ok === false ? "未完成验证" : `${p.ok ? "通过" : "失败"}${m.stale ? "（已过期）" : ""}`;
  let facts, evidence, name, manageText;
  if (activeHop === "device") {
    name = "设备到入口"; manageText = "接入与管理设备 ↗";
    facts = [["检查范围", "设备 → 当前入口"], ["设备端连接", "未采集"], ["实际设备出口", "需在设备端确认"], ["所选路线", m.object?.name || m.object?.label || "尚未配置"]];
    evidence = "服务器无法替设备证明连通。先导入订阅或配对路由器，在设备上选中此节点并检查出口；路由器应用状态可在设备工作区核对。";
  } else if (activeHop === "exit") {
    name = chain?.label || chain?.host || "本机直接出网"; manageText = chain ? "管理此落地端 ↗" : "查看分流规则 ↗";
    facts = [["出口方式", chain ? chain.default_out ? "默认链式出口" : "独立链式节点" : "服务器本机出口"], ["目标地址", chain?.host || S.dash.system?.server?.public_ip || "未知"], ["传输方式", chain ? chain.transport === "hysteria2" ? "QUIC / Hysteria 2" : "TCP / Reality" : "按分流规则"], ["落地段证据", chain ? chainHealth(chain).text : "没有独立出口段探测"], ["实测出口 IP", (chain?.last_probe?.exit_ip) || "未采集"]];
    evidence = chain ? (m.issue || chain.last_probe?.detail || "可单独验证所选落地端；它不等于设备到入口的完整验证。") : "这是服务器配置的出网方式。广告、私网和其它分流规则仍可能走不同出口；公网 IP 是服务器信息，不是此节点实测出口。";
  } else {
    name = m.object?.name || m.object?.label || m.object?.host || "尚无节点"; manageText = "管理此入口 ↗";
    facts = [["配置状态", m.object?.enabled ? "已启用" : "已停用"], ["入口服务", entryStatus], ["服务器检查", `${level} · ${proof}`], ["检查时间", m.checked ? fmtTime(m.checked) : "尚未验证"]];
    evidence = m.issue || p?.detail || "先检查当前路线。服务运行不等于凭据、传输和出口均可用；检查结果会显示实际验证层级。";
  }
  $("#field-selection-kind").textContent = {device:"01 / 设备段",entry:"02 / 入口段",exit:"03 / 出口段"}[activeHop];
  $("#field-object-name").textContent = name;
  $("#field-facts").innerHTML = facts.map(([k,v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join("");
  $("#field-evidence").textContent = evidence;
  const verify = $("#field-verify");
  verify.disabled = !m.object?.enabled || !!probing || !!S.opBusy || !!S.applyJobId;
  verify.textContent = probing === selection ? "检查中…" : chainSelected ? "检查这条落地连接" : "检查当前节点出网";
  if (m.object?.id === "hysteria2") verify.textContent = probing === selection ? "检查中…" : "检查 UDP 监听";
  verify.onclick = checkFieldRoute;
  if (activeHop === "exit" && chain && !chainSelected) {
    verify.textContent = probing ? "检查中…" : "单独检查落地段";
    verify.onclick = async () => {
      if (probing || S.opBusy || S.applyJobId) return;
      selection = `chain:${chain.id}`; activeHop = "exit"; await checkFieldRoute();
    };
  }
  verify.classList.toggle("hidden", activeHop === "device");
  const apply = $("#field-apply-route");
  apply.classList.toggle("hidden", activeHop !== "exit" || !chain?.enabled || !!chain.default_out);
  apply.disabled = !!m.issue || !!probing || !!S.opBusy || !!S.applyJobId;
  apply.onclick = () => {
    const btn = [...document.querySelectorAll("[data-chain-default]")].find((el) => el.dataset.chainDefault === chain?.id);
    if (btn && !btn.disabled) btn.onclick();
  };
  $("#field-manage").textContent = manageText;
  $("#field-manage").onclick = () => activeHop === "device" ? jump("sec-clients") : activeHop === "exit" ? jump(chain ? "chain-intro" : "sec-adv", chain?.id) : jump(chainSelected ? "chain-intro" : "sec-nodes", m.object?.id);
  $("#field-diagnose").classList.toggle("hidden", m.state !== "failed" && !notices.has(selection));
  for (const hop of ["device", "entry", "exit"]) {
    const btn = $("#field-" + hop); btn.setAttribute("aria-pressed", String(activeHop === hop));
    btn.onclick = () => { activeHop = hop; renderField(); };
  }
  document.querySelectorAll("[data-field-node]").forEach((btn) => {
    btn.setAttribute("aria-pressed", String(selection === `node:${btn.dataset.fieldNode}`));
    btn.onclick = () => {
      selection = `node:${btn.dataset.fieldNode}`; activeHop = "entry"; renderField();
      root.scrollIntoView({ block: "start", behavior: "auto" }); select.focus({ preventScroll: true });
    };
  });
}
