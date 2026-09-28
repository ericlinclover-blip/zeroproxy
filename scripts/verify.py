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

import json
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

    print("\n[7] GeoIP 数据与分流防护")
    # 数据来源: 显式指定 ZP_GEODATA_DIR (已有 dat 文件的目录), 否则尝试真实下载
    geo_src = os.environ.get("ZP_GEODATA_DIR", "")
    geo_dir = home / "geo"
    geo_dir.mkdir(parents=True, exist_ok=True)
    have_geo = False
    if geo_src and (Path(geo_src) / "geoip.dat").exists():
        for name in ("geoip.dat", "geosite.dat"):
            shutil.copyfile(Path(geo_src) / name, geo_dir / name)
        have_geo = True
        record("准备 GeoIP 数据", True, f"来自 {geo_src}")
    else:
        res = client.post("/api/geodata/update").json()
        have_geo = bool(res.get("ok"))
        record("下载 GeoIP 数据", have_geo, str(res.get("detail"))[:110])

    if have_geo:
        from zeroproxy import geodata

        # 数据就绪后开启分流 (设置接口会触发重新生成 + 热重载)
        client.post("/api/settings", json={"geodata_enabled": True})
        state = config.load_state()
        cfg_path = home / "xray" / "config.json"
        cfg = json.loads(cfg_path.read_text())
        rules_text = json.dumps(cfg.get("routing", {}).get("rules", []))
        record("配置含 geoip:private 规则", "geoip:private" in rules_text)
        record("配置含 geosite:category-ads-all 规则", "geosite:category-ads-all" in rules_text)
        record("存在 blackhole 出站", any(o.get("tag") == "block" for o in cfg["outbounds"]))
        record("分流状态 active", geodata.usable(state))

        if xray_bin:
            # 带 XRAY_LOCATION_ASSET 才能加载数据; 不带则整份配置构建失败
            ok_env = subprocess.run(
                [xray_bin, "-test", "-c", str(cfg_path)],
                capture_output=True,
                text=True,
                timeout=60,
                env={**os.environ, "XRAY_LOCATION_ASSET": str(geo_dir)},
            )
            record("有数据 + XRAY_LOCATION_ASSET 时 xray -test 通过", ok_env.returncode == 0)
            # 注意: xray 也会从"可执行文件所在目录"找 geo 文件, 因此必须把二进制
            # 复制到隔离目录再测, 否则会因 /tmp 里恰好有 dat 文件而误判。
            iso_dir = home / "xray-isolated"
            iso_dir.mkdir(exist_ok=True)
            iso_bin = iso_dir / "xray"
            if not iso_bin.exists():
                shutil.copy2(xray_bin, iso_bin)
            no_env = subprocess.run(
                [str(iso_bin), "-test", "-c", str(cfg_path)],
                capture_output=True,
                text=True,
                timeout=60,
            )
            record(
                "未设 XRAY_LOCATION_ASSET 时 xray 拒绝启动 (证明该变量必需)",
                no_env.returncode != 0,
                last_line(no_env.stdout + no_env.stderr),
            )

        # 反向用例: 数据缺失时 geo 规则必须被丢弃 (否则 Xray 整体起不来)
        backup_dir = home / "geo-bak"
        shutil.move(str(geo_dir), str(backup_dir))
        client.post("/api/apply")
        cfg2 = json.loads(cfg_path.read_text())
        record(
            "数据缺失时不再下发 geo 规则 (硬前置)",
            "geoip:" not in json.dumps(cfg2.get("routing", {}).get("rules", [])),
        )
        if xray_bin:
            proc = subprocess.run(
                [str(iso_bin), "-test", "-c", str(cfg_path)],
                capture_output=True,
                text=True,
                timeout=60,
            )
            record("无数据时 xray -test 仍通过", proc.returncode == 0)
        shutil.move(str(backup_dir), str(geo_dir))
        client.post("/api/apply")

    print("\n[8] 备份 / 恢复")
    exported = client.get("/api/backup")
    payload = exported.json()
    record("备份导出", exported.status_code == 200, f"{len(exported.content)} 字节")
    record("备份含校验和", bool(payload.get("checksum")), payload.get("checksum", "")[:16])
    record(
        "备份不含会话",
        "sessions" not in payload.get("state", {}) and "login_failures" not in payload.get("state", {}),
    )
    token_before = payload["state"]["subscription_token"]

    # 改点东西, 再用备份覆盖回去
    client.post("/api/nodes/vless-ws/toggle")
    assert config.load_state()["nodes"]["vless-ws"] is False
    restore = client.post("/api/restore", content=exported.content)
    record("恢复备份", restore.status_code == 200, f"HTTP {restore.status_code}")
    after = config.load_state()
    record("恢复后节点开关回到备份点", after["nodes"]["vless-ws"] is True)
    record("恢复后订阅令牌不变", after["subscription_token"] == token_before)

    tampered = dict(payload)
    tampered["state"] = {**payload["state"], "domain": "evil.example.com"}
    bad = client.post("/api/restore", json=tampered)
    record("校验和不匹配时拒绝恢复", bad.status_code == 400, bad.json().get("error", "")[:60])

    print("\n[9] 连通性探测 (真实握手)")
    # 需要真实内核在跑: 启一个 xray (+ hysteria) 再探
    procs: list[subprocess.Popen] = []
    try:
        if xray_bin:
            env = {**os.environ, "XRAY_LOCATION_ASSET": str(geo_dir)}
            procs.append(
                subprocess.Popen(
                    [xray_bin, "run", "-c", str(home / "xray" / "config.json")],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=env,
                )
            )
        if hy_bin and config.load_state().get("hysteria_hopping"):
            client.post("/api/hysteria/hopping")  # macOS 不支持多端口监听
        if hy_bin:
            procs.append(
                subprocess.Popen(
                    [hy_bin, "server", "-c", str(home / "hysteria" / "config.yaml")],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            )
        time.sleep(3)
        probe = client.get("/api/probe?force=1").json()
        for item in probe["nodes"]:
            record(
                f"探测 {item['node']}",
                bool(item["ok"]) or item["ok"] is None,
                f"{item['detail']}" + (f" · {item['ms']}ms" if item["ms"] else ""),
            )
        record("出站 RTT (Reality dest)", bool(probe["dest"]["ok"]), f"{probe['dest']['ms']}ms")
        if xray_bin:
            reality = next(n for n in probe["nodes"] if n["node"] == "vless-reality")
            record("Reality 真实 TLS 握手成功", bool(reality["ok"]), f"{reality['ms']}ms")
    finally:
        for proc in procs:
            proc.terminate()
        for proc in procs:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()

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
