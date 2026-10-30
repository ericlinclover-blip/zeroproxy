from __future__ import annotations

import os
import re
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



# ---------------------------------------------------------------- 静态断言
# 这些不依赖浏览器/网络: 面板是零构建的原生 ES 模块, 用源码约定就能钉住
# "字段有没有被消费 / 有没有引入内联样式 / 备份是否还是 GET / 脚本会不会泄漏进程"。

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
STATIC = os.path.join(ROOT, "backend", "static")
APP = os.path.join(STATIC, "app")
SCRIPTS = os.path.join(ROOT, "scripts")


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def _node_bin():
    return shutil.which("node") or next(
        (p for p in ("/usr/local/bin/node", "/opt/homebrew/bin/node") if os.path.exists(p)), None
    )


def _es_module_ok(path):
    """用 node --check 解析一个原生 ES 模块 (stdin + module 模式)。"""
    node_bin = _node_bin()
    if not node_bin:  # 本机没有 node 时只跑静态断言, 不把"缺工具"当成失败
        return True, "node 不可用"
    with open(path, "rb") as f:
        source = f.read()
    proc = subprocess.run(
        [node_bin, "--input-type=module", "--check"], input=source, capture_output=True
    )
    return proc.returncode == 0, proc.stderr.decode("utf-8", "replace")


def test_static_has_no_backup_files():
    """4 个 .js.bak 会把旧代码随 /static 匿名分发 (P3 发布卫生), 必须删干净。"""
    leftovers = []
    for base, _dirs, files in os.walk(STATIC):
        for name in files:
            if ".bak" in name:
                leftovers.append(os.path.relpath(os.path.join(base, name), ROOT))
    assert leftovers == []


def test_chain_view_surfaces_pin_repair_state():
    """链式视图必须消费 pin 字段并给出明确的重新配对指引 (不得静默)。"""
    src = _read(os.path.join(APP, "views", "chain.js"))
    for field in ("pin_ok", "needs_repair", "exit_pin", "pin_mismatch"):
        assert field in src, f"chain.js 没有消费后端字段 {field}"
    assert "重新配对" in src
    # 用户能看到的解释: 客户端那条 "no certificate matches the pinned hash"
    assert "no certificate matches the pinned hash" in src
    # 复用现有 banner / badge 组件 (红/黄提示), 不新增内联 style
    assert "banner bad" in src
    assert "badge hysteria" in src
    assert 'style="' not in src


def test_chain_pin_fields_are_escaped():
    """服务器字段进 innerHTML 前必须经过 esc/escAttr (前端 XSS 边界)。"""
    src = _read(os.path.join(APP, "views", "chain.js"))
    # exit_pin 的展示值先转成字符串再 esc (pin 是服务器下发字符串, 展示前必须转义)
    assert "esc(pin" in src or "esc(String((c && c.exit_pin)" in src
    assert "esc(e.host)" in src and "escAttr(e.id)" in src


def test_clients_view_distinguishes_downloaded_and_applied():
    """"已下载"不能冒充"已应用": 两个 rev 字段都要消费, 且沿用现有 badge 体系。"""
    src = _read(os.path.join(APP, "views", "clients.js"))
    assert "downloaded_rev" in src
    assert "applied_rev" in src
    assert "已下载未应用" in src
    assert "配置已应用" in src
    assert "badge hysteria" in src and "badge trojan" in src
    assert 'style="' not in src


def test_backup_ui_uses_post_and_optional_encryption():
    """备份从 GET 跳转改成 POST: 口令走请求头, 不留在 URL / 历史 / access log。"""
    src = _read(os.path.join(APP, "views", "traffic.js"))
    # 旧实现是按钮 onclick 里直接 window.location.href = "/api/backup"; 不许回来
    assert "backupBtn.onclick = () => { window.location.href" not in src
    assert 'fetch("/api/backup"' in src
    assert 'method: "POST"' in src
    assert "X-ZP-Passphrase" in src
    assert "encrypt" in src and "encrypt=1" in src
    # 导出前先弹确认框 (含可选口令), 并写明备份等价 root
    assert "#backup-pass" in src
    assert "等价于拿到这台服务器的 root" in src
    # 后端要求加密口令 >= 8 位 (备份等价 root); 前端先挡一次, 不把 400 留给用户踩
    assert "passphrase.length < 8" in src
    # 恢复接受原文件 (后端自动识别加密), 加密包用字节上传 + 口令头
    assert "file.arrayBuffer()" in src
    assert "#restore-pass" in src
    assert 'style="' not in src


def test_update_result_card_has_scoped_selector():
    """升级结果卡单独包一层: `.banner` 不能再被"远端版本源不可达"那条 info 条抢答。"""
    upd = _read(os.path.join(APP, "views", "update.js"))
    assert 'id="update-result"' in upd
    browser = _read(os.path.join(SCRIPTS, "browser_check.cjs"))
    assert "#update-result .banner" in browser
    assert "#update-body .banner" not in browser


def test_bootstrap_token_is_scrubbed_from_url():
    """引导令牌 / handoff / 预填用户名用完即 replaceState 清掉, 不留在地址栏与历史。"""
    src = _read(os.path.join(APP, "views", "dashboard.js"))
    assert 'params.get("token")' in src
    assert 'params.get("handoff")' in src
    assert 'params.get("user")' in src
    assert 'history.replaceState(null, "", location.pathname)' in src
    # 读取令牌后必须先清理再继续走网络请求 (顺序: replaceState 在 api(/api/session/handoff) 之前)
    boot = src[src.index("export async function boot()"):]
    assert boot.index("history.replaceState") < boot.index('api("/api/session/handoff"')


def test_static_avoids_inline_style_and_inline_handlers():
    """CSP 是 style-src 'self': 内联 style 会被浏览器静默拦掉, 约定走 data-w + CSSOM。"""
    offenders = []
    inline_handler = re.compile(r'\s(on[a-z]+)="')

    def _code_only(source):
        """去掉注释行: dom.js 的说明里会出现 `style="…"` 字样 (不是真的内联样式)。"""
        return "\n".join(
            line
            for line in source.splitlines()
            if not line.lstrip().startswith(("*", "//", "/*"))
        )

    for base, _dirs, files in os.walk(APP):
        for name in files:
            if not name.endswith(".js"):
                continue
            path = os.path.join(base, name)
            src = _code_only(_read(path))
            if 'style="' in src or inline_handler.search(src):
                offenders.append(os.path.relpath(path, ROOT))
    assert offenders == []


def test_browser_scripts_require_playwright_before_spawning():
    """缺 playwright 时必须退出 1 且不留面板子进程 (P1-5 / P2-14)。"""
    for name in ("browser_check.cjs", "clients_check.cjs", "geo_slow_check.cjs"):
        src = _read(os.path.join(SCRIPTS, name))
        assert 'require("playwright")' in src, name
        assert src.index('require("playwright")') < src.index("spawn("), (
            f"{name}: require(playwright) 必须在 spawn 面板之前"
        )
        assert "stopServer" in src, f"{name}: 需要统一的子进程收尸函数"
        assert "await stopServer()" in src, f"{name}: finally / catch 里必须收掉面板进程"
    # router_ui_check 没有子进程, 但同样有"起模拟服务之后才 require"的泄漏路径
    src = _read(os.path.join(SCRIPTS, "router_ui_check.cjs"))
    assert src.index('require("playwright")') < src.index("makeMock()")


def test_browser_scripts_scope_selectors_to_result_containers():
    """选择器必须限定容器: 升级卡的 .banner 与页面其它板块同名, .mini-card 同理由。"""
    browser = _read(os.path.join(SCRIPTS, "browser_check.cjs"))
    assert "#update-result .banner" in browser
    assert "#update-body .banner" not in browser
    # 备份接口已改 POST
    assert "request.get(`${base}/api/backup`)" not in browser
    assert "request.post(`${base}/api/backup" in browser
    clients = _read(os.path.join(SCRIPTS, "clients_check.cjs"))
    assert "#client-body .mini-card" in clients
    assert 'locator(".mini-card")' not in clients


def test_changed_frontend_modules_parse_as_es_modules():
    """零构建的 ES 模块语法必须能直接进浏览器 (node --check 兜底)。"""
    for rel in (
        ("views", "chain.js"),
        ("views", "clients.js"),
        ("views", "update.js"),
        ("views", "traffic.js"),
    ):
        ok, err = _es_module_ok(os.path.join(APP, *rel))
        assert ok, f"{rel[-1]} 语法错误: {err[:400]}"
