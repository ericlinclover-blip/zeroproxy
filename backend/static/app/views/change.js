import { $, toast } from "../lib/dom.js";
import { api } from "../lib/api.js";
import { S, redrawDash } from "../lib/state.js";
import { assertApplyResult } from "../lib/jobs.js";

let timer, polling = false, deadline = 0, identity = "", busy = false, lastState = "";
const active = new Set(["applying", "awaiting_confirmation", "rollback_pending", "rolling_back"]);
export function renderChangePanel() {
  const box = $("#network-change-panel"), change = S.dash?.pending_change;
  if (!box) return;
  clearInterval(timer);
  if (!change) { box.classList.add("hidden"); identity = ""; return; }
  box.classList.remove("hidden");
  box.classList.toggle("operation-notice", active.has(change.state) || change.state === "rollback_failed");
  if (!box.querySelector("[data-change-text]")) {
    box.innerHTML = '<p data-change-text></p><div class="row"><button class="btn small" data-change-confirm>保留变更</button><button class="btn ghost small" data-change-rollback>立即回滚</button></div>';
    box.querySelector("[data-change-confirm]").onclick = () => act("confirm");
    box.querySelector("[data-change-rollback]").onclick = () => act("rollback");
  }
  identity = change.id;
  lastState = change.state;
  deadline = Date.now() + change.remaining * 1000;
  const tick = () => {
    const remaining = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
    const texts = { applying: "网络变更正在应用；验证成功后开始确认倒计时。", awaiting_confirmation: `临时配置已应用：请测试连接，${remaining} 秒内保留变更；超时将自动恢复旧配置。`, rollback_pending: "应用失败，正在等待自动回滚。", rolling_back: "正在恢复并验证旧配置…", rolled_back: "临时变更已回滚，已恢复并验证旧配置。", confirmed: "已保留网络变更。", rollback_failed: `自动回滚未完成：${change.error || "请查看诊断并重试回滚"}` };
    box.querySelector("[data-change-text]").textContent = texts[change.state] || change.state;
    const confirm = box.querySelector("[data-change-confirm]"), rollback = box.querySelector("[data-change-rollback]");
    confirm.hidden = change.state !== "awaiting_confirmation";
    confirm.disabled = busy || remaining <= 0;
    rollback.hidden = !active.has(change.state) && change.state !== "rollback_failed";
    rollback.disabled = busy || ["applying", "rolling_back"].includes(change.state);
  };
  tick();
  if (active.has(change.state)) timer = setInterval(() => { tick(); poll(); }, 1000);
}
async function poll() {
  if (polling || busy) return;
  polling = true;
  const id = identity;
  try {
    const change = await api(`/api/changes/${encodeURIComponent(id)}`);
    if (id !== identity || !S.dash) return;
    if (change.state !== lastState) {
      S.dash = await api("/api/dashboard");
      redrawDash(true);
    } else { S.dash.pending_change = change; }
  } catch (e) { /* The server watchdog remains responsible during disconnection. */ }
  finally { polling = false; }
}
async function act(action) {
  if (busy) return;
  busy = true;
  renderChangePanel();
  try {
    const result = await api(`/api/changes/${encodeURIComponent(identity)}/${action}`, { method: "POST", timeoutMs: 240000 });
    assertApplyResult(result);
    S.dash = result;
    redrawDash(true);
  } catch (e) { toast(e.message, { kind: "error", persistent: true }); }
  finally { busy = false; renderChangePanel(); }
}
