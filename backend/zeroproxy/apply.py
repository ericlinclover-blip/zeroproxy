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
  * 重启后端口没监听 → 失败 (verify 步骤, 带短暂重试);
  * **反向同样成立**: 已经停用的节点/链路, 对应端口必须真的不再监听 ——
    「关掉节点」只改磁盘配置而不重启服务时, 端口照样开着, 面板却显示已关闭。

任何一步失败都会原样出现在返回的 steps 里, 面板据此显示红色告警。
"""
from __future__ import annotations

import json
import os
import sys
import time

from . import config, crypto, hysteria_config, nginx_config, services, xray_config
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


def ensure_reality_settings(state: dict, timeout: int = 0) -> tuple[bool, str]:
    """落地前校验两件会让 REALITY 必然失败的东西: 密钥对 与 伪装目标。

    1. 密钥对: v2.3.2 及更早的 `new_reality_keys()` 误用 Ed25519, 而 REALITY 只认
       X25519 → 服务端私钥与订阅下发的 `pbk` 对不上, 四个 TCP 节点全部握手失败
       (服务却一直是 active, 面板显示"运行中")。
    2. 伪装目标: 目标站点的 Certificate 握手报文必须 ≤ 8192 字节 (REALITY 服务端
       缓冲区), 旧默认值 www.microsoft.com 的证书链是 8273 字节 → 握手被放弃,
       客户端只看到连接重置。用户自己改过目标时不动。

    两处修复都只改 state, 订阅 URL 不变 (UUID / 令牌都没动), 客户端重新拉一次
    订阅即可。
    """
    reality = state["reality"]
    notes: list[str] = []

    if not crypto.reality_key_valid(reality.get("private_key", ""), reality.get("public_key", "")):
        private_key, public_key, short_id = crypto.new_reality_keys()
        reality["private_key"] = private_key
        reality["public_key"] = public_key
        reality["short_id"] = reality.get("short_id") or short_id
        notes.append("密钥对无效 (旧版 Ed25519, REALITY 需要 X25519) → 已重新生成")

    if (
        reality.get("dest") == config.LEGACY_REALITY_DEST
        and reality.get("server_name") == config.LEGACY_REALITY_SNI
    ):
        reality["dest"] = config.DEFAULT_REALITY_DEST
        reality["server_name"] = config.DEFAULT_REALITY_SNI
        notes.append(
            f"伪装目标仍是旧默认值 (证书链超过 REALITY 的 8KB 缓冲, 握手必然失败) → "
            f"已换成 {config.DEFAULT_REALITY_SNI}"
        )

    if notes:
        return True, "; ".join(notes) + " (客户端需重新拉取订阅)"
    return True, (
        f"密钥对有效 (X25519); 伪装目标 {reality.get('dest') or '(未设置)'} 非已知问题值"
    )


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

    def installed(name: str) -> bool:
        """该服务是否"在本机存在" (装了二进制, 或 systemd 里已经跑着)。

        存在就必须按新配置收敛 —— 哪怕节点已经全部停用; 不存在就没必要去重启
        一个不存在的单元 (那只会多一条无意义的失败步骤)。
        """
        if services.bin_path(name) is not None:
            return True
        return services.service_state(name) in ("active", "running")

    nodes = state.get("nodes", {})
    # 关键: 判据不能是"还有没有节点开着"。全部停用时也要重启一次, 否则变更只落在
    # 磁盘上 (config.json 里入站没了), 运行中的进程照旧在旧端口上服务 ——
    # 面板显示"已停用", 端口其实还开着。重启到"零入站配置"是安全的 (xray -test
    # 与真实启动都验证过), Hysteria 2 同理 (停用时 listen 收敛到 127.0.0.1)。
    if any(nodes.get(n) for n in XRAY_NODE_IDS) or installed("xray"):
        run("xray", services.restart_service, timeout or 90)
    if nodes.get("hysteria2") or installed("hysteria2"):
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
        # 只验主端口。端口跳跃的另外几个端口**没有自己的 socket**: Linux 上
        # hysteria 是把它们的 UDP 包用 nftables / iptables REDIRECT 到主端口
        # (上游 app/internal/firewall.SetupUDPPortRedirect), 所以拿"端口在不在监听"
        # 去验跳跃端口, 会把正常的跳跃配置判成失败 —— v2.6.5 真机升级就是这么挂在
        # 第 6 步的。转发规则另用 `_hop_redirect_note` 尽力确认, 只作说明不影响成败。
        want.append((int(ports["hysteria"]), "udp", "Hysteria 2"))
    # 链式代理的两端都是真实对外端口, 同样要验证真的起来了
    chain_cfg = state.get("chain") or {}
    exit_cfg = chain_cfg.get("exit") or {}
    if exit_cfg.get("enabled") and exit_cfg.get("uuid") and exit_cfg.get("port"):
        want.append((int(exit_cfg["port"]), "tcp", "链式落地端入站"))
    for entry in chain_cfg.get("entries") or []:
        if entry.get("enabled", True) and entry.get("local_port"):
            want.append((int(entry["local_port"]), "tcp", f"链式中转入站 ({entry.get('label') or entry.get('id')})"))
    if state.get("domain"):
        want.append((443, "tcp", "Nginx 443 (WS 入口)"))
    return want


def _ports_that_must_be_closed(state: dict) -> list[tuple[int, str, str]]:
    """落地后应当**不再**监听的对外 TCP 端口 (节点停用 / 证书缺失 / 链路断开)。

    和 `_wanted_ports` 是同一枚硬币的两面: 只检查"该开的开了", 就发现不了
    「面板显示已关闭、端口其实还开着」—— 那正是"停用不生效"的表现。

    只检查 TCP: Hysteria 2 停用后仍会绑定 127.0.0.1 (平滑重启的中间态),
    UDP 端口有没有在监听无法区分回环与公网, 因此不在这里判。
    """
    ports = state.get("ports", {})
    nodes = state.get("nodes", {})
    out: list[tuple[int, str, str]] = []
    if not nodes.get("vless-reality") and ports.get("reality"):
        out.append((int(ports["reality"]), "tcp", "VLESS Reality"))
    if not nodes.get("vless-xhttp") and ports.get("xhttp"):
        out.append((int(ports["xhttp"]), "tcp", "VLESS XHTTP"))
    if ports.get("trojan") and not (nodes.get("trojan") and xray_config.cert_usable(state)):
        out.append((int(ports["trojan"]), "tcp", "Trojan"))
    if not nodes.get("vless-ws") and ports.get("ws_internal"):
        out.append((int(ports["ws_internal"]), "tcp", "VLESS WebSocket (回环)"))
    chain_cfg = state.get("chain") or {}
    exit_cfg = chain_cfg.get("exit") or {}
    # 只在"确实开过落地端"时才要求它关闭: 从没生成过凭据时这个端口本来就没被用过,
    # 别人占着也不该算到我们头上
    if exit_cfg.get("uuid") and not exit_cfg.get("enabled"):
        out.append((int(exit_cfg["port"]), "tcp", "链式落地端入站"))
    for entry in chain_cfg.get("entries") or []:
        if entry.get("local_port") and not entry.get("enabled", True):
            out.append(
                (
                    int(entry["local_port"]),
                    "tcp",
                    f"链式中转入站 ({entry.get('label') or entry.get('id')})",
                )
            )
    return out


def _hop_redirect_note(state: dict) -> str:
    """尽力确认「端口跳跃」的额外 UDP 端口有没有被内核转发到主端口。

    为什么不能按端口监听来验: Linux 上 hysteria 端口跳跃是把额外端口的 UDP 包
    用 nftables (优先) 或 iptables REDIRECT 到首个端口 (上游
    `app/internal/firewall.SetupUDPPortRedirect`), 内核里根本没有这些端口的
    socket —— 只有主端口在 listen。

    这里读一下本机 NAT 规则, 能读到就给出结论; 读不到 (非 root / 没有 nft 与
    iptables) 就返回空串 —— 只作说明, 绝不因此判失败。
    """
    ports = [int(p) for p in state.get("hysteria_ports") or []]
    base = int((state.get("ports") or {}).get("hysteria") or 0)
    hops = [p for p in ports if p != base]
    if not state.get("hysteria_hopping") or not hops or not base:
        return ""
    dump = ""
    for cmd in (
        ["nft", "list", "ruleset"],
        ["iptables", "-t", "nat", "-S"],
        ["ip6tables", "-t", "nat", "-S"],
    ):
        ok, out = services.run(cmd, timeout=10)
        if ok:
            dump += out + "\n"
    if not dump:
        return ""
    missing = [p for p in hops if str(p) not in dump]
    if missing:
        return (
            "跳跃端口 " + "/".join(str(p) for p in missing) + " 未见内核转发规则"
            "(不影响配置落地, 但请用客户端实测跳跃是否生效)"
        )
    return f"跳跃端口 {'/'.join(str(p) for p in hops)} 已由内核转发到 {base}"


def verify_listeners(state: dict, timeout: int = 0) -> tuple[bool, str]:
    """重启后确认端口状态真的和新配置一致 —— 「服务活着但节点不通」的照妖镜。

    两个方向都要查: 该监听的端口必须真的在监听; 已停用的节点/链路对应的端口
    必须真的关掉了 (否则"关闭节点"只是改了文件, 端口还开着)。
    """
    if not services.is_prod():
        return True, "跳过 (本地开发)"
    want = _wanted_ports(state)
    want_ports = {port for port, _, _ in want}
    # 同一个端口既在"该开"里就不算"该关" (例如 Reality 与已停用的 Trojan 换了端口)
    closed = [item for item in _ports_that_must_be_closed(state) if item[0] not in want_ports]
    if not want and not closed:
        return True, "没有启用的节点"
    deadline = time.time() + (timeout or 8)
    while True:
        missing = []
        for port, proto, label in want:
            if proto == "tcp":
                alive = _tcp_open(port)
            else:
                alive = services.udp_port_listening(port) is True
            if not alive:
                missing.append(f"{label} {port}/{proto}")
        still_open = [f"{label} {port}/tcp" for port, _, label in closed if _tcp_open(port)]
        if (not missing and not still_open) or time.time() >= deadline:
            break
        time.sleep(0.6)
    problems: list[str] = []
    if missing:
        problems.append("以下端口未监听: " + ", ".join(missing))
    if still_open:
        problems.append(
            "以下端口已停用却仍在监听 (内核没按新配置重启, 或被其它进程占用): "
            + ", ".join(still_open)
        )
    if problems:
        return False, "; ".join(problems)
    detail = f"{len(want)} 个端口全部在监听"
    if closed:
        detail += "; 已停用端口已关闭: " + ", ".join(
            f"{port}/{proto}" for port, proto, _ in closed
        )
    note = _hop_redirect_note(state)
    if note:
        detail += "; " + note
    return True, detail


# ---------------------------------------------------------------- 对外入口

def reapply(state: dict, timeout: int = 0) -> list[dict]:
    """完整闭环: 重新生成三份配置 → 校验 → 重载服务 → 验证端口。"""
    steps = steps_recorder()
    add_step(steps, "校验 Reality 密钥与伪装目标", ensure_reality_settings, state)
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
