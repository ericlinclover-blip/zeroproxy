/** Read-only connection preview. Verification and edits reuse existing task flows. */
import { $, esc, escAttr } from "../lib/dom.js";
import { fmtTime, nodeStateText, chainHealth, probeMatchesRouting } from "../lib/format.js";
import { S } from "../lib/state.js";
let selection = "";

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
  const checked = hit.kind === "chain" || (!nodeProbe && n.chain) ? p?.ts : probeData?.checked_at;
  const stale = !checked || now - checked > 300 || ((hit.kind === "chain" || n.chain) && (hit.kind === "chain" ? n : chain)?.probe_current === false);
  const broken = !!chain && (chain.needs_repair === true || chain.pin_ok === false);
  const unavailable = hit.kind === "node" && ["failed", "inactive", "not-installed"].includes(n.service_state);
  const innerDown = !!chain && chain.transport === "hysteria2" && chain.hy_ready === false;
  let state = "unknown", title = "连接，等待验证。";
  if (!n.enabled) { state = "off"; title = "这条连接已停用。"; }
  else if (broken || unavailable || innerDown || p?.ok === false) { state = "failed"; title = "连接需要检查。"; }
  else if (p?.ok === true && p.probe_ok !== false && !stale) { state = "verified"; title = "探测已通过。"; }
  else if (p?.ok === true && p.probe_ok !== false) title = "上次探测已通过。";
  if (hit.kind === "chain" || n.chain) {
    const health = chainHealth(hit.kind === "chain" ? n : { ...chain, enabled: n.enabled }, now);
    state = health.state;
    title = health.state === "verified" ? "探测已通过。" : health.state === "off" ? "这条连接已停用。" : health.state === "failed" ? "连接需要检查。" : "连接，等待验证。";
  }
  const issue = broken ? "落地端证书指纹需要修复，请重新配对后验证。" : innerDown ? "QUIC 内层进程尚未就绪，请检查链式连接。" : unavailable ? "节点服务当前不可用，请检查服务状态。" : "";
  return { options, ...hit, chain, issue, probe: p, checked, stale, state, title,
    summary: hit.kind === "chain" ? "正在查看落地端。实际出口由设备分流与默认出口共同决定。" : "正在查看节点。服务器探测结果不等于设备端的连接质量。" };
}

export function renderField() {
  if (!S.dash || !$("#connection-field")) return;
  const m = connectionModel(S.dash, S.probeData, selection);
  selection = m.key || "";
  const root = $("#connection-field"); root.dataset.state = m.state;
  $("#field-headline").textContent = m.title;
  $("#field-summary").textContent = m.summary;
  const select = $("#field-object-select");
  const options = m.options.map((o) => `<option value="${escAttr(o.key)}">${esc(o.kind === "chain" ? "落地 · " : "节点 · ")}${esc(o.object.name || o.object.label || o.object.host)}</option>`).join("");
  if (select.innerHTML !== options) select.innerHTML = options;
  select.value = selection;
  select.onchange = () => { selection = select.value; renderField(); };
  $("#field-entry-name").textContent = S.dash.domain || "本机入口";
  $("#field-entry-host").textContent = m.kind === "node" ? `${m.object.transport || m.object.protocol} / ${m.object.port}` : "当前服务器";
  $("#field-exit-name").textContent = m.chain ? (m.chain.label || "链式落地") : "本机直接出网";
  $("#field-exit-host").textContent = m.chain?.host || S.dash.system?.server?.public_ip || "公网 IP 未知";
  $("#field-selection-kind").textContent = m.kind === "chain" ? "落地端预览" : "节点预览";
  $("#field-object-name").textContent = m.object?.name || m.object?.label || m.object?.host || "尚无节点";
  $("#field-proof").textContent = { verified: "探测通过 / PREVIEW", failed: "探测异常 / PREVIEW", off: "已停用 / PREVIEW", unknown: "待验证 / PREVIEW" }[m.state];
  const p = m.probe;
  const facts = m.object ? [
    ["配置状态", m.object.enabled ? "已启用" : "已停用"],
    ["协议 / 传输", m.object.transport || m.object.protocol || "—"],
    ["服务 / 路线", m.kind === "node" ? nodeStateText(m.object) : m.object.default_out ? "默认出口" : "独立链式节点"],
    ["服务器探测", p?.ok === true ? `${p.ms ? Math.round(p.ms) + " ms · " : ""}${p.probe_ok === false ? "未完成出网验证" : "通过"}${m.stale ? "（结果已过期）" : ""}` : p?.ok === false ? "失败" : "尚无结果"],
    ["验证时间", m.checked ? fmtTime(m.checked) : "尚未验证"],
  ] : [];
  $("#field-facts").innerHTML = facts.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join("");
  $("#field-evidence").textContent = m.issue || p?.detail || (m.state === "failed" ? "连接未通过验证，请查看节点与链路诊断。" : "验证从服务器发起；路径高亮只表达选中对象的探测结果。");
  $("#field-verify").disabled = !m.object || !m.object.enabled;
  $("#field-verify").textContent = m.kind === "chain" ? "验证这条链路" : "验证节点连接";
  $("#field-verify").onclick = async () => {
    if (m.kind === "chain") {
      const btn = [...document.querySelectorAll("[data-chain-probe]")].find((el) => el.dataset.chainProbe === m.object.id);
      if (!btn || btn.disabled) return;
      $("#field-verify").disabled = true;
      $("#field-verify").textContent = "验证中…";
      try { await btn.onclick(); } finally { renderField(); }
    } else {
      const btn = $("#btn-probe");
      if (btn.disabled) return;
      $("#field-verify").disabled = true;
      $("#field-verify").textContent = "验证中…";
      try { await btn.onclick(); } finally { renderField(); }
    }
  };
  const apply = $("#field-apply-route");
  apply.classList.toggle("hidden", m.kind !== "chain" || !m.object?.enabled || !!m.object?.default_out);
  apply.disabled = !!m.issue;
  apply.onclick = () => {
    const btn = [...document.querySelectorAll("[data-chain-default]")].find((el) => el.dataset.chainDefault === m.object?.id);
    if (btn && !btn.disabled) btn.onclick();
  };
  const manage = () => { const a = document.createElement("a"); a.href = m.kind === "chain" ? "#chain-intro" : "#sec-nodes"; document.body.appendChild(a); a.click(); a.remove(); };
  $("#field-manage").onclick = manage;
  $("#field-entry").onclick = () => {
    const node = m.options.find((o) => o.kind === "node" && o.object.enabled);
    if (node) { selection = node.key; renderField(); select.focus(); }
  };
  $("#field-exit").onclick = () => {
    const entry = m.options.find((o) => o.kind === "chain" && o.object.id === m.chain?.id);
    if (entry) { selection = entry.key; renderField(); select.focus(); } else manage();
  };
  document.querySelectorAll("[data-field-node]").forEach((btn) => {
    btn.setAttribute("aria-pressed", String(selection === `node:${btn.dataset.fieldNode}`));
    btn.onclick = () => {
      selection = `node:${btn.dataset.fieldNode}`; renderField();
      root.scrollIntoView({ block: "start", behavior: "auto" }); select.focus({ preventScroll: true });
    };
  });
}
