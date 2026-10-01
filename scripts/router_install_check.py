#!/usr/bin/env python3
"""路由器安装脚本的端到端演练 (不依赖真路由器)。

为什么要这个脚本
----------------
`router-install.sh` 是本项目里唯一"跑在别人设备上、出错只能靠用户截图"的代码,
而 pytest 只能做静态审计 (断言用了哪些命令、哪些字符串)。上线 2.7.0 后两天内它坏了两次,
两次都只有真跑才会暴露:

  * `od` 判断 gzip —— OpenWrt 的 busybox 没有 od, 于是把 gz 当二进制执行;
  * 凭据在面板上被移除后, 本地文件看不出问题, 直到拉配置 403 才发现。

所以这里真的起一份面板、真的用 shell 跑一遍安装脚本 (在本机模拟 OpenWrt), 覆盖:

  1. 配对 → 下载(压缩的假内核) → 解压 → 可执行校验 → 落配置
  2. 生成的控制 agent 能真的跟面板对话, 并让设备状态在 desired/actual 间正确翻转
  3. 面板上把设备移除后重跑安装命令 → 自动用新配对码重新接入 (自愈)

做法: 起面板 → 把脚本里的 OpenWrt 路径与 root 检查替换成本机临时目录 (本机没有
OpenWrt, 也没有 root), 面板侧用一个几 KB 的**压缩**假内核替代 20 MB 的 mihomo
(`ZP_CORE_MIN_BYTES`), 从而把"下载 → gzip -t → 解压 → 执行校验"整条链路跑通。

用法:
    python3 scripts/router_install_check.py
需要: curl (或 uclient-fetch), sh, 以及 backend 的 venv。
"""
from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, "backend")
PYTHON = os.environ.get("ZP_PYTHON") or os.path.join(ROOT, ".venv", "bin", "python")
if not os.path.exists(PYTHON):  # 没有 venv 就退回系统 python (可能缺依赖, 会在启动时报出来)
    PYTHON = "python3"

PORT = int(os.environ.get("ZP_CHECK_PORT", "8901"))
BASE = f"http://127.0.0.1:{PORT}"
TOKEN = "router-install-check"

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: object = "") -> None:
    results.append((name, ok, detail))
    print(f"  {'✓' if ok else '✗'} {name}{' — ' + str(detail) if detail else ''}")


def http(method: str, path: str, body=None, cookie: str | None = None):
    req = urllib.request.Request(BASE + path, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
        req.data = json.dumps(body).encode()
    if cookie:
        req.add_header("Cookie", cookie)
    with urllib.request.urlopen(req, timeout=180) as resp:
        return resp.status, resp.read().decode(), resp.headers


def patch_for_local_run(script: str, root: str) -> str:
    """把脚本改成本机能跑: 换路径、跳过 root/OpenWrt 检查、只跑到写文件那一步。

    这不改变被测逻辑 —— 架构探测、配对、下载、解压、配置拉取、文件生成全都照跑。
    """
    out = script
    out = out.replace("/etc/zeroproxy", root)
    out = out.replace("/etc/init.d/zeroproxy", root + "/initd")
    out = out.replace("/usr/bin/zeroproxy", root + "/cli")
    out = out.replace(
        '[ "$(id -u)" = "0" ] || die "需要 root 权限, 请用 root 账户执行 (OpenWrt 默认就是 root)"',
        "true",
    )
    out = re.sub(r'\[ -r /etc/openwrt_release \] \|\| die "[^"]*"', "true", out, flags=re.S)
    # 本机没有 procd / systemd, 自检那一步 (启动 mihomo + 等控制口) 必然失败 ——
    # 这里停在"文件已落盘", 服务编排由真机验证; 但配置生成与 agent 逻辑照跑。
    out = out.replace(
        '\nmain "$@"\n',
        "\nmain() { detect_env; detect_http; preflight; pair; install_deps; "
        "install_core; write_files; }\nmain \"$@\"\n",
    )
    return out


class Panel:
    """一台演练用的面板 (真起 uvicorn, 真注册设备)。"""

    def __init__(self, port: int, home: str, name: str):
        self.port, self.home, self.name = port, home, name
        self.base = f"http://127.0.0.1:{port}"
        os.makedirs(os.path.join(home, "data"), exist_ok=True)
        with open(os.path.join(home, "data", "bootstrap_token"), "w") as fh:
            fh.write(TOKEN + "\n")
        self.env = {
            **os.environ,
            "ZP_HOME": home,
            "ZP_STATIC": os.path.join(BACKEND, "static"),
            "ZP_BIND_HOST": "127.0.0.1",
            "ZP_BIND_PORT": str(port),
            "ZP_PORT": str(port),
            "ZP_PUBLIC_IP": "0",
            "ZP_GEODATA_AUTO": "0",
            "ZP_APPLY_ASYNC": "0",
            "ZP_CORE_MIN_BYTES": "16",   # 假内核只有几百字节
        }
        self.proc = subprocess.Popen(
            [PYTHON, "-m", "zeroproxy.main"], cwd=BACKEND, env=self.env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        self.cookie = ""
        self.log = ""

    def wait(self) -> bool:
        for _ in range(60):
            time.sleep(0.5)
            try:
                self.req("GET", "/api/info")
                return True
            except (urllib.error.URLError, OSError):
                pass
        self.log = (self.proc.stdout.read() or "") if self.proc.stdout else ""
        return False

    def configure(self, domain: str) -> None:
        self.req("POST", "/api/setup", {
            "domain": domain, "username": "admin", "password": "s3cretpass", "token": TOKEN,
        })
        _, _, headers = self.req("POST", "/api/login", {"username": "admin", "password": "s3cretpass"})
        self.cookie = headers.get("set-cookie", "").split(";")[0]

    def req(self, method: str, path: str, body=None):
        req = urllib.request.Request(self.base + path, method=method)
        if body is not None:
            req.add_header("Content-Type", "application/json")
            req.data = json.dumps(body).encode()
        if self.cookie:
            req.add_header("Cookie", self.cookie)
        with urllib.request.urlopen(req, timeout=180) as resp:
            return resp.status, resp.read().decode(), resp.headers

    def pair_code(self, label: str) -> str:
        _, body, _ = self.req("POST", "/api/devices/pair", {"label": label})
        return json.loads(body)["code"]

    def stop(self) -> None:
        self.proc.send_signal(signal.SIGTERM)
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="zp-router-check-")
    fake_root = os.path.join(tmp, "root")
    os.makedirs(fake_root, exist_ok=True)
    env = {**os.environ, "ZP_GEODATA_AUTO": "0", "ZP_PUBLIC_IP": "0"}
    os.environ.update(env)
    sys.path.insert(0, BACKEND)
    from zeroproxy import router_client  # noqa: E402

    print(f"ZeroProxy 路由器安装演练  (PORT={PORT}, 第二台面板 {PORT + 1})")
    panels = [Panel(PORT, os.path.join(tmp, "home-a"), "A"),
              Panel(PORT + 1, os.path.join(tmp, "home-b"), "B")]
    try:
        for panel in panels:
            if not panel.wait():
                print(f"面板 {panel.name} 没起来:\n" + panel.log[-2000:])
                return 1
            panel.configure(f"127.0.0.1" if panel.name == "A" else "127.0.0.2")
        panel = panels[0]
        http = panel.req

        # 面板侧缓存一个"压缩过的假内核": 让安装脚本真的走 gzip 判定 + 解压 + 执行
        import gzip
        cache = os.path.join(panels[0].home, "data", "client", "cores")
        os.makedirs(cache, exist_ok=True)
        stub = (
            '#!/bin/sh\ncase "$*" in\n'
            '  *-v*) echo "Mihomo Meta v1.19.32 (stub)" ;;\n'
            '  *-t*) exit 0 ;;\n'
            '  *) while :; do sleep 60; done ;;\n'
            "esac\nexit 0\n"
        )
        with gzip.open(os.path.join(cache, f"mihomo-arm64-{router_client.CORE_VERSION}.gz"), "wb") as fh:
            fh.write(stub.encode())

        def run_install(label: str) -> tuple[bool, str]:
            code = panel.pair_code(label)
            _, script, _ = http("GET", f"/c/{code}")
            path = os.path.join(tmp, f"install-{label}.sh")
            with open(path, "w") as fh:
                fh.write(patch_for_local_run(script, fake_root))
            proc = subprocess.run(["sh", path], capture_output=True, text=True)
            print(f"---- 安装输出 ({label}) ----")
            print(proc.stdout.strip())
            if proc.returncode:
                print(proc.stderr[-800:])
            return proc.returncode == 0, proc.stdout

        print("\n[1] 首次安装")
        ok, out = run_install("first")
        check("安装脚本跑通", ok)
        check("内核经过 gzip 判定与解压后可执行", "内核就绪" in out, "Mihomo Meta" in out and "stub" in out)

        generated = os.path.join(fake_root, "config.yaml")
        config_text = open(generated, encoding="utf-8").read() if os.path.exists(generated) else ""
        check("生成路由器版配置 (tun + fake-ip)",
              all(k in config_text for k in ("tun:", "fake-ip", "nameserver-policy")))
        for name in ("device.json", "agent.sh", "initd", "initd-agent", "cli", "tproxy.nft"):
            check(f"生成 {name}", os.path.exists(os.path.join(fake_root, name)))

        import yaml
        profile = yaml.safe_load(config_text)
        check("配置可被 YAML 解析且含全部节点",
              isinstance(profile, dict) and len(profile.get("proxies", [])) == 5)

        print("\n[2] 控制 agent 与面板对话")
        agent = open(os.path.join(fake_root, "agent.sh"), encoding="utf-8").read()
        agent = agent.replace("/etc/zeroproxy", fake_root).replace("/etc/init.d/zeroproxy", fake_root + "/initd")
        agent = agent.replace("SLEEP=15", "SLEEP=2")
        agent_path = os.path.join(fake_root, "agent-check.sh")
        with open(agent_path, "w") as fh:
            fh.write(agent)
        check("agent 语法正确", subprocess.run(["sh", "-n", agent_path]).returncode == 0)

        proc = subprocess.Popen(["sh", agent_path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        time.sleep(8)
        proc.kill()
        _, body, _ = http("GET", "/api/devices")
        device = json.loads(body)["devices"]["items"][0]
        check("agent 上报后设备显示在线", device["online"] is True)
        check("总开关默认开启且面板能看到期望状态", device["desired"] is True)

        print("\n[3] 加入第二台服务器 (面板 B) → 自动聚合成多个 provider")
        panel_b = panels[1]
        code_b = panel_b.pair_code("第二台")
        cli = os.path.join(fake_root, "cli-check.sh")
        with open(cli, "w") as fh:
            fh.write(
                open(os.path.join(fake_root, "cli"), encoding="utf-8").read()
                .replace("/etc/zeroproxy", fake_root)
                # 本机没有 procd: 把 init 调用换成 true (macOS 自带的 /etc/rc.common 被
                # 当成脚本执行时会真的去跑 launchd 那套, 演练会挂住)
                .replace("/etc/init.d/zeroproxy", "true")
            )
        out = subprocess.run(
            ["sh", cli, "add", f"{panel_b.base}/c/{code_b}"], capture_output=True, text=True
        )
        print(out.stdout.strip() or out.stderr[-400:])
        if "配置更新失败" in out.stdout:
            dbg = subprocess.run(["sh", os.path.join(fake_root, "agent.sh"), "config"],
                                 capture_output=True, text=True)
            print("--- agent config 调试 ---")
            print("rc:", dbg.returncode)
            print("stderr:", dbg.stderr[-600:])
            print("stdout 前几行:", "\n".join(dbg.stdout.splitlines()[:6]))
        merged = open(os.path.join(fake_root, "config.yaml"), encoding="utf-8").read()
        merged_yaml = yaml.safe_load(merged)
        check("第二台服务器接入成功", out.returncode == 0 and "已接入" in out.stdout)
        check("配置改成多 provider 模式",
              "proxy-providers:" in merged and "proxies:" not in merged.split("proxy-groups")[0],
              f"providers={len(merged_yaml.get('proxy-providers', {}))}")
        check("两个 provider 都在", len(merged_yaml.get("proxy-providers", {})) == 2)
        auto = [g for g in merged_yaml["proxy-groups"] if g["name"] == "♻️ 自动选择"][0]
        check("组的 use 填上了两个 provider 键", len(auto.get("use", [])) == 2, str(auto.get("use")))
        check("节点不再内联 (交给 provider 拉)", "proxies" not in merged_yaml)

        out = subprocess.run(["sh", cli, "servers"], capture_output=True, text=True)
        check("zeroproxy servers 列出两台", out.stdout.count("127.0.0.") == 2, out.stdout.strip().splitlines()[0] if out.stdout else "")

        key_b = re.sub(r"[^A-Za-z0-9]", "_", panel_b.base.split("://", 1)[-1])[:32]
        out = subprocess.run(["sh", cli, "drop", key_b], capture_output=True, text=True)
        after = yaml.safe_load(open(os.path.join(fake_root, "config.yaml"), encoding="utf-8").read())
        # 剩一台时退回"面板给整份配置"的老路径 (内联节点), 不再挂 provider —— 这条路径
        # 是真机验证过的, 没必要为了统一形式让它也绕一圈 provider
        check("drop 之后退回单服务器路径 (内联节点)",
              "proxy-providers" not in after and len(after.get("proxies", [])) == 5,
              out.stdout.strip()[:60])

        print("\n[4] 凭据在面板上失效后重跑")
        _, body, _ = http("GET", "/api/devices")
        device = json.loads(body)["devices"]["items"][0]
        old_id = device["id"]
        http("DELETE", f"/api/devices/{old_id}")
        ok, out = run_install("rejoin")
        _, body, _ = http("GET", "/api/devices")
        items = json.loads(body)["devices"]["items"]
        check("旧凭据被拒后自动重新接入", ok and "重新接入" in out, f"旧 {old_id}")
        check("面板上换成一台新设备 (没有卡死在旧凭据)",
              len(items) == 1 and items[0]["id"] != old_id, items[0]["id"] if items else "无")
    finally:
        logs = []
        for panel in panels:
            # 先停再读: 反过来会先卡在读管道上 (进程还活着, read() 等不到 EOF)
            panel.stop()
            panel.log = panel.proc.stdout.read() if panel.proc.stdout else ""
            logs.append(panel.log)
        log = "\n".join(logs)
        shutil.rmtree(tmp, ignore_errors=True)

    failed = [r for r in results if not r[1]]
    print(f"\n结论: {len(results) - len(failed)}/{len(results)} 项通过")
    if failed:
        print("未通过: " + ", ".join(r[0] for r in failed))
        print("服务日志尾部:\n" + (log or "")[-1200:])
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
