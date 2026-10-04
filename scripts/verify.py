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


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _run_singbox(binary: str, profile: dict, home: Path, port: int, label: str) -> tuple[bool, str]:
    """跑一次 sing-box, 返回 (是否存活, 说明)。远程 rule-set 指向本地镜像。"""
    for rule_set in profile["route"].get("rule_set", []):
        rule_set["url"] = f"http://127.0.0.1:{port}/{rule_set['tag']}.srs"
    profile["inbounds"][0]["listen_port"] = free_port()
    profile["experimental"] = {"cache_file": {"enabled": True, "path": str(home / f"cache-{label}.db")}}
    path = home / f"singbox-{label}.json"
    path.write_text(json.dumps(profile, ensure_ascii=False), encoding="utf-8")
    proc = subprocess.Popen(
        [binary, "run", "-c", str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        time.sleep(4)
        if proc.poll() is None:
            return True, "启动成功 (rule-set 直连下载)"
        return False, last_line(proc.stdout.read() if proc.stdout else "")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def _live_singbox(binary: str, client, sub_path: str, home: Path) -> None:
    """用真实 sing-box 实跑三个模板 —— 全程不发外网请求。

    节点的 server 是不可解析的 proxy.example.com: 任何"借默认出站 (节点) 下载
    rule-set"的写法都会让 sing-box 直接 FATAL, 所以进程能活下来就等价于证明
    rule-set 走的是直连下载。rule-set 内容用真实二进制编译, 由本地 HTTP 服务提供。
    """
    import functools
    import http.server
    import threading

    version_line = subprocess.run(
        [binary, "version"], capture_output=True, text=True, timeout=30
    ).stdout.strip().splitlines()[0]

    fixtures = home / "rule-set"
    fixtures.mkdir(exist_ok=True)
    # 要编译哪些 rule-set 由**配置自己**说了算: 直接读三个模板里出现的 tag。
    # 不然以后新增一个分类 (geolocation-cn / tencent / …), 演练这边会少编译一个,
    # 于是"配置没问题"被误报成"实跑失败"。
    tags: set[str] = set()
    for tpl in ("smart", "global", "direct"):
        body = json.loads(client.get(f"{sub_path}?format=singbox&rules={tpl}").text)
        tags |= {rs["tag"] for rs in body["route"].get("rule_set", [])}
    if not tags:
        record("编译测试用 rule-set", False, "三个模板都没有引用任何 rule-set")
        return
    for tag in sorted(tags):
        body = {"version": 1, "rules": [{"domain_suffix": [f"{tag}.example"]}]}
        src = fixtures / f"{tag}.json"
        src.write_text(json.dumps(body), encoding="utf-8")
        proc = subprocess.run(
            [binary, "rule-set", "compile", str(src), "-o", str(fixtures / f"{tag}.srs")],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if proc.returncode != 0:
            record(f"编译测试用 rule-set {tag}", False, last_line(proc.stdout + proc.stderr))
            return

    port = free_port()
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(fixtures))
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    httpd.RequestHandlerClass.log_message = lambda *args, **kwargs: None
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    record("sing-box 版本", True, version_line)

    def supports_next() -> bool:
        try:  # "sing-box version 1.14.2"
            parts = version_line.split()[-1].split("-")[0].split(".")
            return (int(parts[0]), int(parts[1])) >= (1, 14)
        except (IndexError, ValueError):
            return False

    try:
        formats = [("singbox", "通用写法")]
        if supports_next():
            formats.append(("singbox-next", "1.14+ 写法"))
        for fmt, label in formats:
            for tpl in ("smart", "global", "direct"):
                body = client.get(f"{sub_path}?format={fmt}&rules={tpl}").text
                ok, detail = _run_singbox(binary, json.loads(body), home, port, f"{fmt}-{tpl}")
                record(f"实跑 {label} / {tpl}", ok, detail)

        # 反例: 去掉 download_detour → 下载改走节点 → 节点不可达 → 起不来
        raw = json.loads(client.get(f"{sub_path}?format=singbox&rules=global").text)
        for rule_set in raw["route"]["rule_set"]:
            rule_set.pop("download_detour", None)
        ok, detail = _run_singbox(binary, raw, home, port, "negative")
        record("反例: 不指定下载出口则起不来 (证明修复必要)", not ok, detail)
    finally:
        httpd.shutdown()


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

    def apply_post(path: str, **kwargs):
        """改动类请求 + 等后台落地任务跑完 (v2.6.9)。

        面板从 v2.6.9 起把"重新生成配置 → 重启内核 → 验端口"放到后台任务里, 接口
        立刻回执 (响应里带 `job`), 前端靠轮询 `/api/apply/job` 看进度。这个脚本是
        直接读磁盘上的配置来断言的, 所以每个改动类请求都要等任务结束 —— 面板的
        前端也是这么做的, 两边行为一致。
        """
        res = client.request("POST", path, **kwargs)
        try:
            job = (res.json() or {}).get("job")
        except Exception:  # noqa: BLE001 — 非 JSON 响应 (如 4xx 文本) 就没有任务
            job = None
        if job:
            deadline = time.time() + 120
            while time.time() < deadline:
                snap = client.get(f"/api/apply/job?id={job['id']}").json()
                if snap.get("state") != "running":
                    break
                time.sleep(0.2)
        return res

    assert apply_post(
        "/api/setup",
        json={"domain": DOMAIN, "username": USERNAME, "password": PASSWORD, "token": "wrong"},
    ).status_code == 403
    response = apply_post(
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
        for tpl in ("smart", "global", "direct"):
            path = home / f"clash-{tpl}.yaml"
            path.write_text(client.get(f"{sub_path}?format=clash&rules={tpl}").text, encoding="utf-8")
            proc = subprocess.run(
                # -d 复用同一个工作目录: geo 数据只下载一次
                [mihomo_bin, "-t", "-f", str(path), "-d", str(home / "mihomo-data")],
                capture_output=True,
                text=True,
                timeout=180,
            )
            output = (proc.stdout or "") + (proc.stderr or "")
            ok = proc.returncode == 0 or "test is successful" in output
            record(f"mihomo 解析 Clash 订阅 ({tpl})", ok, last_line(output))
    if singbox_bin:
        path = home / "singbox.json"
        path.write_text(client.get(f"{sub_path}?format=singbox").text, encoding="utf-8")
        proc = subprocess.run(
            [singbox_bin, "check", "-c", str(path)], capture_output=True, text=True, timeout=60
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        record("sing-box 解析订阅", proc.returncode == 0, "check PASS" if proc.returncode == 0 else last_line(output))

    print("\n[2c] 分流模板 (smart / global / direct)")
    templates = {
        "smart": ("GEOSITE,cn", "GEOSITE,category-ads-all"),
        "global": (None, "GEOSITE,category-ads-all"),
        "direct": (None, None),
    }
    for tpl, (must, ads) in templates.items():
        clash = client.get(f"{sub_path}?format=clash&rules={tpl}").text
        ok = (must in clash if must else "GEOSITE,cn" not in clash) and (
            ads in clash if ads else "GEOSITE" not in clash and "GEOIP," not in clash
        )
        record(f"clash 模板 {tpl}", ok, f"{len(clash)} 字节")
        profile = json.loads(client.get(f"{sub_path}?format=singbox&rules={tpl}").text)
        rule_sets = profile["route"].get("rule_set", [])
        if tpl == "direct":
            ok = not rule_sets and "experimental" not in profile
        else:
            ok = bool(rule_sets) and all(
                rs.get("download_detour") == "direct" for rs in rule_sets
            )
        record(f"singbox 模板 {tpl} (rule-set 直连下载)", ok, f"{len(rule_sets)} 条 rule-set")

    print("\n[2c-2] 国内 App 直连层 (微信 / 支付宝 / 银联 …) 与 geosite 分类白名单")
    from zeroproxy import share_links

    smart_clash = client.get(f"{sub_path}?format=clash&rules=smart").text
    for probe in ("qq.com", "servicewechat.com", "qpic.cn", "alipay.com",
                  "alipayobjects.com", "cup62.cn"):
        record(f"国内 App 直连 {probe}", f"DOMAIN-SUFFIX,{probe}," in smart_clash)
    # 分类名拼错 = 整份配置加载失败 (实测 mihomo: list … not found in geosite.dat),
    # 所以只允许白名单里的分类出现在订阅里。
    allowed = (
        {"category-ads-all", "private"}
        | set(share_links.CN_DIRECT_GEOSITES)
        | set(share_links.LANDING_GEOSITES)
    )
    used = {chunk.split(",")[0] for chunk in smart_clash.split("GEOSITE,")[1:]}
    record("GEOSITE 分类都在白名单内", bool(used) and used <= allowed,
           f"{len(used)} 个分类" + (f", 越界: {sorted(used - allowed)}" if used - allowed else ""))
    # 降级 (拿不到分流数据库) 时国内 App 那一层必须还在 —— 真机反馈的
    # "国内网站 / 公众号 / 小程序都走代理" 就是这一层缺失造成的。
    degraded = share_links.clash_profile(config.load_state(), "smart", geo=False)
    ok = ("GEOSITE," not in degraded and "GEOIP,CN" not in degraded
          and "DOMAIN-SUFFIX,qq.com," in degraded and "DOMAIN-SUFFIX,alipay.com," in degraded)
    record("降级配置保留国内 App 直连 (不含任何 geo 规则)", ok)

    if singbox_bin:
        print("\n[2d] 用真实 sing-box 实跑订阅 (节点不可达也必须起得来)")
        _live_singbox(singbox_bin, client, sub_path, home)

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

            # 「关掉节点」必须真的把端口关掉。这里手动重启内核, 等价于生产里
            # systemd 那一步 —— 旧版本在"节点全关/只剩镜像"时压根不重启服务,
            # 于是面板显示已停用, 端口却还开着。
            apply_post("/api/nodes/vless-reality/toggle")
            check = subprocess.run(
                [xray_bin, "-test", "-c", str(home / "xray" / "config.json")],
                capture_output=True,
                text=True,
                timeout=60,
            )
            record(
                "停用后配置仍通过 xray -test",
                check.returncode == 0,
                (check.stdout + check.stderr).strip().splitlines()[-1],
            )
            proc.terminate()
            proc.wait(timeout=10)
            proc = subprocess.Popen(  # 模拟 systemctl restart xray
                [xray_bin, "run", "-c", str(home / "xray" / "config.json")],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            time.sleep(3)
            record("停用的 Reality 端口 8443 真的关闭", not port_open(8443))
            record("仍在启用的 XHTTP 端口 8445 照常监听", port_open(8445))

            apply_post("/api/nodes/vless-reality/toggle")   # 还原成全部启用
        finally:
            proc.terminate()
            proc.wait(timeout=10)
    else:
        print("  - 跳过 (未提供 ZP_XRAY_BIN)")

    print("\n[5] Hysteria 2")
    if hy_bin:
        # macOS 不支持多端口监听, 先关掉端口跳跃以验证配置本体
        apply_post("/api/hysteria/hopping")
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
        apply_post("/api/hysteria/hopping")
        conf = (home / "hysteria" / "config.yaml").read_text()
        record("端口跳跃多端口配置", '"0.0.0.0:30001,31001,32001"' in conf)
    else:
        print("  - 跳过 (未提供 ZP_HYSTERIA_BIN)")

    print("\n[6] 诊断与自愈")
    diag = client.get("/api/diagnose").json()
    record("自检", bool(diag["checks"]), diag["summary"])
    repair = apply_post("/api/repair").json()
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
        res = apply_post("/api/geodata/update").json()
        have_geo = bool(res.get("ok"))
        record("下载 GeoIP 数据", have_geo, str(res.get("detail"))[:110])

    if have_geo:
        from zeroproxy import geodata, xray_config

        # 数据文件级"搬走 / 搬回" (目录级 move 会撞上被自动重建的空目录)
        stash = home / "geo-stash"
        stash.mkdir(exist_ok=True)

        def geo_out() -> None:
            for name in geodata.MIN_BYTES:
                shutil.move(str(geo_dir / name), str(stash / name))

        def geo_back() -> None:
            for name in geodata.MIN_BYTES:
                shutil.move(str(stash / name), str(geo_dir / name))

        # 数据就绪后开启分流 (设置接口会触发重新生成 + 热重载)
        apply_post("/api/settings", json={"geodata_enabled": True})
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
        geo_out()
        apply_post("/api/apply")
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
        geo_back()
        apply_post("/api/apply")

        # 启动期漏洞: 配置已落盘、数据随后消失 (磁盘清理 / 手动删 / 恢复到新机),
        # 此时 `systemctl restart xray` 会让整个 Xray 起不来。guard 是 ExecStartPre 兜底。
        print("\n[7b] 启动前自愈 (systemd ExecStartPre: python -m zeroproxy.geodata guard)")
        cfg_path = home / "xray" / "config.json"
        iso_bin = home / "xray-isolated" / "xray"
        # 前置: 让磁盘上的配置确实带着 geo 规则 (等价于面板正常运行过)
        fresh = config.load_state()
        fresh["geodata"]["enabled"] = True
        xray_config.write_xray_config(fresh)
        record("前置: 配置里已下发 geo 规则", "geoip:private" in cfg_path.read_text())
        geo_out()
        if xray_bin:
            broken = subprocess.run(
                [str(iso_bin), "-test", "-c", str(cfg_path)],
                capture_output=True,
                text=True,
                timeout=60,
            )
            record(
                "无 guard 时 Xray 拒绝启动 (漏洞复现)",
                broken.returncode != 0,
                last_line(broken.stdout + broken.stderr),
            )
        guard = subprocess.run(
            [sys.executable, "-m", "zeroproxy.geodata", "guard"],
            cwd=str(BACKEND),
            env={**os.environ},
            capture_output=True,
            text=True,
            timeout=120,
        )
        record("guard 执行", guard.returncode == 0, last_line(guard.stdout + guard.stderr))
        text = cfg_path.read_text()
        record(
            "guard 后配置不再引用 geo 规则",
            "geoip:" not in text and "geosite:" not in text,
            "auto-degraded",
        )
        if xray_bin:
            fixed = subprocess.run(
                [str(iso_bin), "-test", "-c", str(cfg_path)],
                capture_output=True,
                text=True,
                timeout=60,
            )
            record("guard 后 Xray 可通过自检 (启动不再被卡死)", fixed.returncode == 0)
        geo_back()
        apply_post("/api/apply")

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
    apply_post("/api/nodes/vless-ws/toggle")
    assert config.load_state()["nodes"]["vless-ws"] is False
    restore = apply_post("/api/restore", content=exported.content)
    record("恢复备份", restore.status_code == 200, f"HTTP {restore.status_code}")
    after = config.load_state()
    record("恢复后节点开关回到备份点", after["nodes"]["vless-ws"] is True)
    record("恢复后订阅令牌不变", after["subscription_token"] == token_before)

    tampered = dict(payload)
    tampered["state"] = {**payload["state"], "domain": "evil.example.com"}
    bad = apply_post("/api/restore", json=tampered)
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
            apply_post("/api/hysteria/hopping")  # macOS 不支持多端口监听
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

    print("\n[10] 链式代理 (两台「机器」真跑: 客户端 → 中转 → 落地 → 外网)")
    # 只有一台机器, 就用两份独立的 state + 两个真实 Xray 进程扮演两台服务器:
    #   A = 落地端 (面板生成 `chain-exit` 入站, 专用 UUID + 独立端口)
    #   B = 中转端 (另一套 Reality 密钥, 只有 `chain-<id>` 入站 + 指向 A 的出站)
    # 客户端拿 B 的入站凭据连进去, 只有三跳全通才能读到出口 IP —— 任何一跳坏了
    # (Reality 密钥 / shortId / 专用 UUID / 路由规则) 都会变成"读不到 IP"。
    if not xray_bin:
        print("  - 跳过 (未提供 ZP_XRAY_BIN)")
    else:
        import uuid as uuid_mod

        from zeroproxy import chain, crypto, services, xray_config

        exit_port = 8666
        entry_port = 8667
        apply_post("/api/chain/exit", json={"action": "generate", "port": exit_port, "label": "落地A"})
        code = chain.parse_code(client.get("/api/dashboard").json()["chain"]["exit"]["code"])
        record("落地端生成专用凭据 + 配对码", code["port"] == exit_port and bool(code["uuid"]),
               f"端口 {code['port']}")

        asset = str(geo_dir) if geo_dir.is_dir() else ""
        env_a = {**os.environ, **({"XRAY_LOCATION_ASSET": asset} if asset else {})}
        chain_procs: list[subprocess.Popen] = []
        try:
            # ---- A: 落地端 (直接用面板生成的配置, 含 chain-exit 入站)
            chain_procs.append(subprocess.Popen(
                [xray_bin, "run", "-c", str(home / "xray" / "config.json")],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env_a,
            ))
            deadline = time.time() + 20
            while time.time() < deadline and not port_open(exit_port):
                time.sleep(0.5)
            record(f"落地端 xray 监听 {exit_port}/tcp (chain-exit 入站)", port_open(exit_port))

            # ---- B: 中转端 (另一台机器: 独立 UUID + 独立 Reality 密钥, 只开链式入站)
            state_a = config.load_state()
            state_b = json.loads(json.dumps(state_a))
            state_b["uuid"] = str(uuid_mod.uuid4())
            state_b["reality"]["private_key"], state_b["reality"]["public_key"], state_b["reality"]["short_id"] = (
                crypto.new_reality_keys()
            )
            state_b["nodes"] = {nid: False for nid in config.NODE_IDS}
            state_b["geodata"] = {**state_b.get("geodata", {}), "enabled": False}
            state_b["ports"] = {**state_b["ports"], "api": free_port()}
            state_b["chain"]["exit"] = {"enabled": False, "port": 8668, "uuid": "", "label": "", "created_at": 0}
            entry = {
                "id": "e2e00001",
                "label": "落地A",
                "host": "127.0.0.1",
                "port": code["port"],
                "uuid": code["uuid"],
                "pbk": code["pbk"],
                "sid": code["sid"],
                "sni": code["sni"],
                "flow": code["flow"],
                "local_port": entry_port,
                "enabled": True,
                "default_out": False,
                "created_at": int(time.time()),
                "last_probe": {},
            }
            state_b["chain"]["entries"] = [entry]
            cfg_b = xray_config.build_xray_config(state_b)
            cfg_b_path = home / "chain-b.json"
            cfg_b_path.write_text(json.dumps(cfg_b), encoding="utf-8")
            tags_b = [i["tag"] for i in cfg_b["inbounds"]]
            record("中转端配置只含链式入站 + Stats API", tags_b == [f"chain-{entry['id']}", "api"], str(tags_b))
            out_b = next(o for o in cfg_b["outbounds"] if o["tag"] == f"chain-out-{entry['id']}")
            record("中转端出站指向落地端",
                   out_b["settings"]["vnext"][0]["address"] == "127.0.0.1"
                   and out_b["settings"]["vnext"][0]["port"] == exit_port,
                   f"127.0.0.1:{exit_port} → 客户端端口 {entry['local_port']}")

            chain_procs.append(subprocess.Popen(
                [xray_bin, "run", "-c", str(cfg_b_path)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env_a,
            ))
            deadline = time.time() + 20
            while time.time() < deadline and not port_open(entry_port):
                time.sleep(0.5)
            record(f"中转端 xray 监听 {entry_port}/tcp (客户端连它)", port_open(entry_port))

            # ---- 客户端: 用中转端的入站凭据起一个真 SOCKS, 穿过整条链读出口 IP
            def through_chain(state: dict, node_id: str, label: str, timeout: float = 20) -> str:
                socks_port = free_port()
                cfg_path = home / f"client-{label}.json"
                cfg_path.write_text(
                    json.dumps(services.client_config(state, node_id, socks_port)), encoding="utf-8"
                )
                proc = subprocess.Popen(
                    [xray_bin, "run", "-c", str(cfg_path)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env_a,
                )
                chain_procs.append(proc)
                try:
                    deadline = time.time() + 15
                    while time.time() < deadline and not port_open(socks_port):
                        time.sleep(0.3)
                    ip, _ = chain.read_exit_ip(socks_port, timeout)
                    return ip
                finally:
                    proc.terminate()

            node_id = f"chain-{entry['id']}"
            ip = through_chain(state_b, node_id, "chain")
            record("客户端 → 中转 → 落地 → 外网 真实出网", bool(ip), f"出口 IP {ip}" if ip else "读不到出口 IP")

            # 面板「连接并测试」走的就是这个: 入口端起临时客户端, 直连落地端的
            # chain-exit 入站出一次网, 读回出口 IP 之后才允许落地。
            probe = chain.probe_target(chain.as_target(entry))
            record("入口端「连接并测试」真实探测落地端", bool(probe["ok"]),
                   f"{probe['detail']} · {probe['ms']}ms" if probe["ok"] else str(probe["detail"]))

            # 反向用例: 把落地端的专用 UUID 换掉 (等价于配对码被轮换过),
            # 链路必须立刻断 —— 证明上一步的成功不是"随便走哪条路都能出网"。
            broken = json.loads(json.dumps(state_b))
            broken["chain"]["entries"][0]["uuid"] = str(uuid_mod.uuid4())
            broken["chain"]["entries"][0]["local_port"] = 8668
            broken["ports"] = {**broken["ports"], "api": free_port()}   # 两个 Xray 进程不能抢同一个端口
            bad_cfg = xray_config.build_xray_config(broken)
            bad_cfg_path = home / "chain-b-broken.json"
            bad_cfg_path.write_text(json.dumps(bad_cfg), encoding="utf-8")
            chain_procs.append(subprocess.Popen(
                [xray_bin, "run", "-c", str(bad_cfg_path)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env_a,
            ))
            deadline = time.time() + 20
            while time.time() < deadline and not port_open(8668):
                time.sleep(0.5)
            bad_ip = through_chain(broken, node_id, "chain-broken", timeout=10)
            record("落地端凭据被换掉后链路立即失效 (反向用例)", not bad_ip, f"出口 IP {bad_ip or '读不到'}")
        finally:
            for proc in chain_procs:
                proc.terminate()
            for proc in chain_procs:
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
