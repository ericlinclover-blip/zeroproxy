from __future__ import annotations

import os
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
    proc = subprocess.run(
        ["node", str(script), jobs_js],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert proc.returncode == 0, proc.stderr
    assert '"hidden":false' in proc.stdout
    assert '"banner":"banner info"' in proc.stdout
    assert "正在应用配置" in proc.stdout
    assert 'class=\\"bar live\\"' in proc.stdout
