#!/usr/bin/env python3
"""端到端验证: 用真实 Xray / Hysteria 2 二进制校验面板生成的配置。

它做的事情 (全程 dry-run, 不碰 systemd / nginx / 现网):
  1. 在临时 $ZP_HOME 里跑完整 setup 流水线 (走 FastAPI TestClient);
  2. 用真实 `xray -test` 校验生成的 config.json;
  3. 真实启动 xray, 检查端口监听, 并通过面板 /api/traffic 读回流量统计;
  4. 真实启动 hysteria server, 确认配置能被上游解析并正常监听;
  5. (可选) 用真实 mihomo / sing-box 校验 Clash / sing-box 订阅文件能否被解析;
  6. 打印订阅三种格式、诊断结果与产物清单。

用法:
    ZP_XRAY_BIN=/path/to/xray ZP_HYSTERIA_BIN=/path/to/hysteria \
    ZP_MIHOMO_BIN=/path/to/mihomo ZP_SINGBOX_BIN=/path/to/sing-box \
        python3 scripts/verify.py

环境变量全部可选: 缺少哪个就跳过对应步骤 (面板本身的流程仍然会跑)。
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

DOMAIN = "proxy.example.com"
USERNAME = "admin"
PASSWORD = "s3cretpass"
TOKEN = "verify-token"

results: list[tuple[str, bool, str]] = []


def record(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    print(f"  {'✓' if ok else '✗'} {name}{(' — ' + detail) if detail else ''}")


def last_line(text: str, fallback: str = "无输出") -> str:
    lines = (text or "").strip().splitlines()
    return lines[-1][:150] if lines else fallback


def port_open(port: int, timeout: float = 1.0, host: str = "127.0.0.1") -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def udp_port_open(port: int) -> bool:
    """粗略判断 UDP 端口是否已被占用 (bind 失败 = 已监听)。"""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return True
    return False


def main() -> int:
    home = Path(tempfile.mkdtemp(prefix="zp-verify-home-"))
    os.environ["ZP_HOME"] = str(home)
    os.environ["ZP_STATIC"] = str(BACKEND / "static")
    os.environ["ZP_PORT"] = "8899"
    os.environ["ZP_BIND_PORT"] = "9900"

    xray_bin = os.environ.get("ZP_XRAY_BIN", "")
    hy_bin = os.environ.get("ZP_HYSTERIA_BIN", "")
    if xray_bin:
        os.environ["ZP_XRAY_BIN"] = xray_bin
    if hy_bin:
        os.environ["ZP_HYSTERIA_BIN"] = hy_bin

    from fastapi.testclient import TestClient

    from zeroproxy import config
    from zeroproxy.main import create_app

    print(f"ZeroProxy 端到端验证  (ZP_HOME={home})")
    print(f"  xray={xray_bin or '未提供'}  hysteria={hy_bin or '未提供'}")
    print("\n[1] setup 流水线")
    config.write_bootstrap_token(TOKEN)
    client = TestClient(create_app())
    assert client.post(
        "/api/setup",
        json={"domain": DOMAIN, "username": USERNAME, "password": PASSWORD, "token": "wrong"},
    ).status_code == 403
    response = client.post(
        "/api/setup",
        json={"domain": DOMAIN, "username": USERNAME, "password": PASSWORD, "token": TOKEN},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    for step in body["steps"]:
        record(f"setup: {step['name']}", step["ok"], step["detail"][:110])
    sub_path = body["subscription_url"].split("testserver")[-1]

    print("\n[2] 订阅格式")
    for fmt, marker in (("base64", "vless://"), ("clash", "proxies:"), ("singbox", '"outbounds"')):
        text = client.get(f"{sub_path}?format={fmt}").text
        if fmt == "base64":  # base64 订阅需要先解码再检查内容
            import base64

            text = base64.b64decode(text).decode("utf-8")
        record(f"订阅格式 {fmt}", marker in text, f"{len(text)} 字节")

    # 可选: 用真实客户端二进制校验订阅文件能否被解析 (字段名写错会在这里暴露)
    mihomo_bin = os.environ.get("ZP_MIHOMO_BIN", "")
    singbox_bin = os.environ.get("ZP_SINGBOX_BIN", "")
    if mihomo_bin or singbox_bin:
        print("\n[2b] 客户端解析校验")
    if mihomo_bin:
        path = home / "clash.yaml"
        path.write_text(client.get(f"{sub_path}?format=clash").text, encoding="utf-8")
        proc = subprocess.run(
            [mihomo_bin, "-t", "-f", str(path), "-d", str(home)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        ok = proc.returncode == 0 or "test is successful" in output
        record("mihomo 解析 Clash 订阅", ok, last_line(output))
    if singbox_bin:
        path = home / "singbox.json"
        path.write_text(client.get(f"{sub_path}?format=singbox").text, encoding="utf-8")
        proc = subprocess.run(
            [singbox_bin, "check", "-c", str(path)], capture_output=True, text=True, timeout=60
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        record("sing-box 解析订阅", proc.returncode == 0, "check PASS" if proc.returncode == 0 else last_line(output))

    print("\n[3] 生成产物")
    artifacts = {
        "xray/config.json": home / "xray" / "config.json",
        "hysteria/config.yaml": home / "hysteria" / "config.yaml",
        "nginx/zeroproxy.conf": home / "nginx" / "zeroproxy.conf",
        "www/index.html (伪装主页)": home / "www" / "index.html",
        "data/state.json": home / "data" / "state.json",
    }
    for label, path in artifacts.items():
        record(label, path.exists(), f"{path.stat().st_size} 字节" if path.exists() else "缺失")
    record("state.json 权限 0600", oct((home / "data" / "state.json").stat().st_mode)[-3:] == "600")

    print("\n[4] Xray")
    if xray_bin:
        check = subprocess.run(
            [xray_bin, "-test", "-c", str(home / "xray" / "config.json")],
            capture_output=True,
            text=True,
            timeout=60,
        )
        record("xray -test", check.returncode == 0, (check.stdout + check.stderr).strip().splitlines()[-1])

        proc = subprocess.Popen(
            [xray_bin, "run", "-c", str(home / "xray" / "config.json")],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            time.sleep(3)
            for port in (8443, 8445, 8444, 10085):
                record(f"xray 监听 {port}/tcp", port_open(port))
            stats = client.get("/api/traffic").json()
            record("面板读取流量统计 (Stats API)", stats.get("available") is True, str(stats)[:110])
        finally:
            proc.terminate()
            proc.wait(timeout=10)
    else:
        print("  - 跳过 (未提供 ZP_XRAY_BIN)")

    print("\n[5] Hysteria 2")
    if hy_bin:
        # macOS 不支持多端口监听, 先关掉端口跳跃以验证配置本体
        client.post("/api/hysteria/hopping")
        proc = subprocess.Popen(
            [hy_bin, "server", "-c", str(home / "hysteria" / "config.yaml")],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            time.sleep(3)
            alive = proc.poll() is None
            output = ""
            if alive:
                record("hysteria server 启动", True, "进程存活")
                record("hysteria 监听 UDP 30001", udp_port_open(30001))
            else:
                output = proc.stdout.read() if proc.stdout else ""
                record("hysteria server 启动", False, output.strip().splitlines()[-1][:160])
        finally:
            proc.terminate()
            proc.wait(timeout=10)
        # 恢复端口跳跃, 确认多端口配置也能生成 (Linux 上才是有效监听)
        client.post("/api/hysteria/hopping")
        conf = (home / "hysteria" / "config.yaml").read_text()
        record("端口跳跃多端口配置", '"0.0.0.0:30001,31001,32001"' in conf)
    else:
        print("  - 跳过 (未提供 ZP_HYSTERIA_BIN)")

    print("\n[6] 诊断与自愈")
    diag = client.get("/api/diagnose").json()
    record("自检", bool(diag["checks"]), diag["summary"])
    repair = client.post("/api/repair").json()
    record("一键修复", all(s["ok"] for s in repair["steps"]), f"{len(repair['steps'])} 步")

    failed = [name for name, ok, _ in results if not ok]
    print(f"\n结论: {len(results) - len(failed)}/{len(results)} 项通过")
    if failed:
        print("未通过: " + ", ".join(failed))

    if os.environ.get("ZP_KEEP_VERIFY_HOME") != "1":
        shutil.rmtree(home, ignore_errors=True)
    else:
        print(f"临时目录保留: {home}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
