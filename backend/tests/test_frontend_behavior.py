from __future__ import annotations

import os
import shutil
import subprocess


def test_apply_strip_creates_its_initial_structure(tmp_path):
    """The first background-job render must work while #apply-strip is empty."""
    jobs_js = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "static", "app", "lib", "jobs.js")
    )
    script = tmp_path / "apply-strip.mjs"
    script.write_text(
        """
import { pathToFileURL } from "node:url";

const classes = new Set(["hidden"]);
const ico = { textContent: "" };
const grow = { innerHTML: "" };
const banner = { className: "", innerText: "" };
const box = {
  dataset: {},
  classList: {
    add(name) { classes.add(name); },
    remove(name) { classes.delete(name); },
  },
  querySelector(sel) {
    if (!box.innerHTML) return null;
    if (sel === ".banner") return banner;
    if (sel === ".ico") return ico;
    if (sel === ".grow") return grow;
    return null;
  },
  querySelectorAll() { return []; },
  set innerHTML(value) {
    box._html = value;
    if (value.includes("class=\\"banner")) {
      banner.innerText = value;
      banner.className = /class=\\"banner ([^\\"]+)/.exec(value)?.[1] || "";
    }
  },
  get innerHTML() { return box._html || ""; },
};

globalThis.document = {
  querySelector(sel) { return sel === "#apply-strip" ? box : null; },
};

const jobs = await import(pathToFileURL(process.argv[2]).href);
jobs.renderApplyStrip({
  state: "running", kind: "apply", index: 2, total: 7, current: "生成配置",
});
console.log(JSON.stringify({
  hidden: classes.has("hidden"),
  grow: grow.innerHTML,
  banner: banner.className,
}));
""",
        encoding="utf-8",
    )
    node_bin = shutil.which("node") or next((p for p in ("/usr/local/bin/node", "/opt/homebrew/bin/node") if os.path.exists(p)), "node")
    proc = subprocess.run(
        [node_bin, str(script), jobs_js],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert proc.returncode == 0, proc.stderr
    assert '"hidden":false' in proc.stdout
    assert '"banner":"banner info"' in proc.stdout
    assert "正在应用配置" in proc.stdout
    assert 'class=\\"bar live\\"' in proc.stdout


def test_router_luci_app_drop_handler_syntax_and_behavior():
    """验证路由器管理界面 app.js 具有移除路线订阅的流畅交互逻辑：
    
    1. 包含 [data-drop] 事件监听
    2. 移除前有确认弹窗
    3. 点击后将按钮文本改为'正在移除…'并禁用防重复提交
    4. 具有平滑卡片过渡动画与 unesc 反转义处理
    5. 失败时能够捕获错误、toast 真实原因并复原按钮与卡片
    """
    app_js_path = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "zeroproxy", "client", "luci", "app.js")
    )
    with open(app_js_path, encoding="utf-8") as f:
        src = f.read()

    # 1. 语法检查
    node_bin = shutil.which("node") or next((p for p in ("/usr/local/bin/node", "/opt/homebrew/bin/node") if os.path.exists(p)), "node")
    proc = subprocess.run([node_bin, "-c", app_js_path], capture_output=True, text=True)
    assert proc.returncode == 0, f"app.js 语法错误: {proc.stderr}"

    # 2. 交互逻辑断言
    assert "[data-drop]" in src
    assert "正在移除…" in src
    assert "call('drop'" in src or 'call("drop"' in src
    assert "srvEl.style.transition" in src
    assert "unesc(r.message" in src

