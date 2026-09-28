"""配置落地闭环: 「生成 → 真实校验 → 重载服务」, 面板与命令行共用。

为什么单独抽一层: `/api/apply`、`/api/settings`、`/api/repair`、初始化流程,
以及服务器上的 `upgrade.sh` / `install.sh`, 要做的都是同一件事 —— 按当前
`state.json` 重新生成 Xray / Nginx / Hysteria 2 配置、用真实二进制校验、再
重载服务。放在这里可以保证「面板点一下」与「服务器上跑一条命令」结果一致。

生产环境下的严格语义 (v2.3 起, 修复「全绿但节点不通」的假成功):
  * 写不进 `/etc/nginx/conf.d/zeroproxy.conf` → 该步失败, 不再回退到本地路径
    后算成功;
  * `xray -test` / `nginx -t` 不过 → 失败;
  * 服务重启失败 → 失败;
  * 重启后端口没监听 → 失败 (verify 步骤, 带短暂重试)。

任何一步失败都会原样出现在返回的 steps 里, 面板据此显示红色告警。
"""
from __future__ import annotations

import json
import os
import sys
import time

from . import config, hysteria_config, nginx_config, services, xray_config
from .config import XRAY_NODE_IDS, load_state, paths, save_state


def steps_recorder() -> list[dict]:
    return []


def add_step(steps: list[dict], name: str, fn, state: dict, timeout: int = 120) -> bool:
    """执行一步并记录结果。fn 抛异常也算失败, 不向外扩散。"""
    start = time.time()
    try:
        ok, detail = fn(state, timeout)
    except Exception as exc:  # noqa: BLE001
        ok, detail = False, f"异常: {exc}"
    steps.append(
        {"name": name, "ok": bool(ok), "detail": detail, "ms": int((time.time() - start) * 1000)}
    )
    return bool(ok)


# ---------------------------------------------------------------- 各步实现

def gen_xray(state: dict, timeout: int = 0) -> tuple[bool, str]:
    """写 Xray 配置, 并在有二进制时用真实 `xray -test` 校验。"""
    xray_config.write_xray_config(state)
    count = len(xray_config.build_xray_config(state)["inbounds"])
    binary = services.bin_path("xray")
    if binary:
        ok, out = services.run(
            [binary, "-test", "-c", paths()["xray_config"]],
            timeout=60,
            env=services.xray_env(),
        )
        if not ok:
            return False, f"已生成但 xray -test 未通过: {' '.join(out.split())[:150]}"
        return True, f"已生成 ({count} 个入站, xray -test 通过)"
    return True, f"已生成 ({count} 个入站)"


def gen_nginx(state: dict, timeout: int = 0) -> tuple[bool, str]:
    """写 Nginx 配置并 `nginx -t` 校验。

    生产环境下写不进 `/etc/nginx` 属硬失败 —— 否则面板会显示成功, 而 nginx
    实际仍在跑旧配置 (443 不监听 / WS 节点不通)。
    """
    ok_etc, actual = nginx_config.write_nginx_conf(state)
    prod = services.is_prod()
    if not ok_etc and prod:
        return False, (
            f"无法写入 {paths()['nginx_etc']} (面板进程需要 root 权限) → "
            f"仅暂存 {actual}, nginx 未生效"
        )
    detail = f"已写入 {actual}" if ok_etc else f"无 /etc/nginx 权限 → 已存 {actual} (本地开发)"
    binary = services.bin_path("nginx")
    if ok_etc and binary:
        ok, out = services.run([binary, "-t"], timeout=30)
        if not ok:
            return False, f"nginx -t 未通过: {' '.join(out.split())[:150]}"
        detail += " (nginx -t 通过)"
    return True, detail


def gen_hysteria(state: dict, timeout: int = 0) -> tuple[bool, str]:
    hysteria_config.write_hysteria_config(state)
    if state["nodes"].get("hysteria2"):
        cert, key = paths()["hysteria_cert"], paths()["hysteria_key"]
        if not (os.path.exists(cert) and os.path.exists(key)):
            return False, "已生成但证书缺失 (客户端将无法连接)"
    return True, "已生成"


def restart_services(state: dict, timeout: int = 0) -> tuple[bool, str]:
    results: list[str] = []

    def run(name: str, fn, t: int) -> None:
        # 注意参数顺序: restart_service(name, timeout) / reload_service(name, timeout)。
        # 曾经的写法是 fn(t) —— 把 timeout 当服务名传下去, 生产环境下 systemctl 直接抛
        # "expected str, bytes or os.PathLike object, not int", 而面板当时把失败吞掉了。
        ok, detail = fn(name, t)
        mark = "✓" if ok else ("↷" if "跳过" in detail else "✗")
        results.append(f"{name} {mark} {detail}")

    nodes = state.get("nodes", {})
    if any(nodes.get(n) for n in XRAY_NODE_IDS):
        run("xray", services.restart_service, timeout or 90)
    if nodes.get("hysteria2"):
        run("hysteria2", services.restart_service, timeout or 90)
    run("nginx", services.reload_service, timeout or 60)
    if not results:
        return True, "无需操作"
    all_skipped = all("↷" in r for r in results)
    failed = any("✗" in r for r in results)
    return (all_skipped or not failed), "; ".join(results)


def _tcp_open(port: int, timeout: float = 0.6) -> bool:
    return services._tcp_reachable("127.0.0.1", int(port), timeout)  # noqa: SLF001


def _wanted_ports(state: dict) -> list[tuple[int, str, str]]:
    """落地后应当处于监听状态的 (端口, 协议, 名称)。"""
    ports = state.get("ports", {})
    nodes = state.get("nodes", {})
    want: list[tuple[int, str, str]] = []
    if nodes.get("vless-reality") and ports.get("reality"):
        want.append((int(ports["reality"]), "tcp", "VLESS Reality"))
    if nodes.get("vless-xhttp") and ports.get("xhttp"):
        want.append((int(ports["xhttp"]), "tcp", "VLESS XHTTP"))
    if nodes.get("trojan") and ports.get("trojan") and xray_config.cert_usable(state):
        want.append((int(ports["trojan"]), "tcp", "Trojan"))
    if nodes.get("vless-ws") and ports.get("ws_internal"):
        want.append((int(ports["ws_internal"]), "tcp", "VLESS WebSocket (回环)"))
    if nodes.get("hysteria2") and ports.get("hysteria"):
        want.append((int(ports["hysteria"]), "udp", "Hysteria 2"))
    if state.get("domain"):
        want.append((443, "tcp", "Nginx 443 (WS 入口)"))
    return want


def verify_listeners(state: dict, timeout: int = 0) -> tuple[bool, str]:
    """重启后确认端口真的起来了 —— 这是「服务活着但节点不通」的照妖镜。"""
    if not services.is_prod():
        return True, "跳过 (本地开发)"
    want = _wanted_ports(state)
    if not want:
        return True, "没有启用的节点"
    deadline = time.time() + (timeout or 8)
    missing: list[str] = []
    while True:
        missing = []
        for port, proto, label in want:
            if proto == "tcp":
                alive = _tcp_open(port)
            else:
                alive = services.udp_port_listening(port) is True
            if not alive:
                missing.append(f"{label} {port}/{proto}")
        if not missing or time.time() >= deadline:
            break
        time.sleep(0.6)
    if missing:
        return False, "以下端口未监听: " + ", ".join(missing)
    return True, f"{len(want)} 个端口全部在监听"


# ---------------------------------------------------------------- 对外入口

def reapply(state: dict, timeout: int = 0) -> list[dict]:
    """完整闭环: 重新生成三份配置 → 校验 → 重载服务 → 验证端口。"""
    steps = steps_recorder()
    add_step(steps, "重新生成 Xray 配置", gen_xray, state)
    add_step(steps, "重新生成 Nginx 配置", gen_nginx, state)
    add_step(steps, "重新生成 Hysteria 2 配置", gen_hysteria, state)
    add_step(steps, "重载服务 (nginx/xray/hysteria2)", restart_services, state, timeout=180)
    add_step(steps, "验证端口监听", verify_listeners, state, timeout=12)
    state["steps"] = steps
    save_state(state)
    return steps


def failures(steps: list[dict]) -> list[dict]:
    return [s for s in steps if not s.get("ok")]


def _main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    quiet = "--quiet" in argv
    with config.locked():
        state = load_state()
        if not state.get("configured"):
            print("[zeroproxy-apply] 面板尚未初始化, 没有可落地的配置", file=sys.stderr)
            return 2
        steps = reapply(state)
    failed = failures(steps)
    if not quiet:
        for step in steps:
            print(f"  {'OK  ' if step['ok'] else 'FAIL'} {step['name']} | {step['detail']}")
    print(json.dumps({"ok": not failed, "steps": steps}, ensure_ascii=False))
    return 0 if not failed else 1


if __name__ == "__main__":  # pragma: no cover - CLI 入口
    raise SystemExit(_main())
