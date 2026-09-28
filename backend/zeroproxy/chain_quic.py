"""链式代理的 QUIC 内层 —— 用 Hysteria 2 (QUIC/UDP) 承载「入口 → 落地」那一跳。

为什么要有它
------------
默认的链式内层是 VLESS + TCP + Reality: 客户端的 TCP 被装进两段 TCP 里
(客户端→入口 一段, 入口→落地 一段), 也就是 **TCP over TCP**。跨洋链路的 RTT
有 170-200ms, 内层 TCP 的拥塞窗口爬升本来就慢, 一旦丢包两层各自重传、互相等对方
—— 真机实测香港→美东单流只有 ~62 Mbps, 4 并发才 147 Mbps, 而同一台机器上单层
Reality 转发能跑到 200+ MB/s (瓶颈在网络路径, 不在 CPU)。

换成 QUIC/UDP (Hysteria 2) 后: 没有 TCP 队头阻塞, 没有双层重传的互相拖累,
UDP 传输也不受运营商对长肥管道 TCP 的整形影响。

为什么用面板托管进程, 而不是再加 systemd 单元
----------------------------------------------
落地端要开一个**独立**的 UDP 监听 (独立密码, 可单独吊销), 入口端要跑一个本地
hysteria 客户端把 SOCKS5 交给 Xray 当出站 —— 两个角色都是"按需存在"的。做成面板
的子进程有三个好处:

  * 本地开发环境与生产走**同一条代码路径** (都能起、都能测), 不需要 systemd;
  * 老部署「面板内升级」完就能用, 不依赖 install.sh / upgrade.sh 再跑一遍;
  * 面板进程 (systemd, Restart=always) 在启动时与每次落地后各 sync 一次, 还有
    看门线程兜底 —— 子进程被一起收走也能自动拉回来。

拓扑 (以入口端视角)
------------------
  客户端 ──VLESS/Reality──▶ 入口 Xray ──routing──▶ socks 出站
                                                     │
                                     127.0.0.1:<hy_socks_port>
                                                     ▼
                                            hysteria client (本地)
                                                     │ QUIC/UDP
                                                     ▼
                                            hysteria server (落地端) ──▶ 外网

落地端那一侧只需要跑 server; 入口端那一侧只需要跑 client。两端都不跑时不留进程。
"""
from __future__ import annotations

import contextlib
import hashlib
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time

from . import services
from .config import paths

#: 落地端 QUIC 内层的默认 UDP 端口 (8447 是 Reality 内层的 TCP 端口)
DEFAULT_PORT = 8448
#: 入口端本地 SOCKS5 端口的起始值 (面板自动往后找空闲的)
SOCKS_PORT_BASE = 8470

#: 看门线程的巡检间隔: 子进程意外退出后最多这么久被拉回来
SUPERVISE_INTERVAL = 20.0

_LOCK = threading.Lock()
#: 我们拉起来的进程: key -> (Popen, 配置指纹)
_PROCS: dict[str, tuple[subprocess.Popen, str]] = {}

#: 一个 YAML 双引号标量的安全转义 (密码里可能有引号/反斜杠)
_YAML_UNSAFE = str.maketrans({"\\": "\\\\", '"': '\\"'})


def binary() -> str | None:
    """hysteria 二进制路径 (没有就说明这台机器上还没装, 所有功能静默降级)。"""
    return services.bin_path("hysteria2")


def work_dir() -> str:
    return paths()["chain_quic_dir"]


def _yq(value: str) -> str:
    return '"' + str(value).translate(_YAML_UNSAFE) + '"'


# ---------------------------------------------------------------- 落地端 (server)

def exit_sni(state: dict) -> str:
    """QUIC 内层使用的 SNI。

    hysteria 服务端会按 SNI 选证书, SNI 与证书 SAN 对不上会直接 TLS 告警
    (真机实测: 留空 / 用 IP 字面量都会失败), 所以证书是我们自己按这个值自签的,
    入口端拿配对码里的同一个值来连 —— 两端由构造保证一致。

    有域名就用域名 (看起来就是普通 TLS); 只有 IP 的部署退回本机 Reality 的伪装
    SNI, 反正证书在我们手上。
    """
    domain = str(state.get("domain") or "")
    if services.is_domain(domain):
        return domain
    fallback = str((state.get("reality") or {}).get("server_name") or "")
    return fallback or "www.microsoft.com"


def ensure_exit_cert(state: dict) -> tuple[bool, str]:
    """确保 QUIC 内层的自签证书存在, 且 SAN 与当前 SNI 一致。"""
    sni = exit_sni(state)
    cert, key = _cert_paths()
    if os.path.exists(cert) and os.path.exists(key) and _cert_sans(cert) == {sni}:
        return True, ""
    ok, detail = services.generate_self_signed(sni, cert, key)
    return ok, detail


def _cert_paths() -> tuple[str, str]:
    base = work_dir()
    return os.path.join(base, "cert.pem"), os.path.join(base, "key.pem")


def _cert_sans(cert_file: str) -> set[str]:
    """读证书里现有的 SAN (只用于判断"要不要重签")。"""
    try:
        from cryptography import x509

        with open(cert_file, "rb") as fh:
            cert = x509.load_pem_x509_certificate(fh.read())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        return {str(name.value) for name in san}
    except Exception:  # noqa: BLE001 - 读不出来就当作"需要重签"
        return set()


def server_config(state: dict) -> str:
    """落地端的 QUIC 监听配置 (独立端口 + 独立密码 + 同样的伪装站点)。"""
    exit_cfg = (state.get("chain") or {}).get("exit") or {}
    masq = (state.get("hysteria_masquerade") or {}).get("url") or ""
    masqr = (
        "masquerade:\n"
        "  type: proxy\n"
        "  proxy:\n"
        f"    url: {_yq(masq)}\n"
        "    rewriteHost: true\n"
        if masq
        else ""
    )
    return (
        "# 由 ZeroProxy 面板自动生成 — 链式代理的内层 QUIC 监听 (Hysteria 2)\n"
        "# 只给「入口端」用: 独立端口 + 独立密码, 与主 Hysteria 2 节点互不影响\n"
        f"listen: :{int(exit_cfg.get('hy_port') or DEFAULT_PORT)}\n"
        "tls:\n"
        f"  cert: {paths()['chain_quic_cert']}\n"
        f"  key: {paths()['chain_quic_key']}\n"
        "auth:\n"
        "  type: password\n"
        f"  password: {_yq(exit_cfg.get('hy_password') or '')}\n"
        f"{masqr}"
        "bandwidth:\n"
        "  down: 1 gbps\n"
        "  up: 500 mbps\n"
    )


# ---------------------------------------------------------------- 入口端 (client)

def client_config(entry: dict) -> str:
    """入口端的本地 hysteria 客户端 (SOCKS5 只监听 127.0.0.1, 给 Xray 当出站用)。"""
    lines = [
        "# 由 ZeroProxy 面板自动生成 — 链式代理的内层 QUIC 客户端",
        "# 只监听回环: 出口是 Xray 的 socks 出站, 不对局域网暴露",
        f"server: {entry['host']}:{int(entry.get('hy_port') or DEFAULT_PORT)}",
        f"auth: {_yq(entry.get('hy_pw') or '')}",
        "tls:",
        f"  sni: {entry.get('hy_sni') or ''}",
        "  insecure: true",
        "socks5:",
        f"  listen: 127.0.0.1:{int(entry.get('hy_socks_port') or 0)}",
    ]
    bw = int(entry.get("hy_bw") or 0)
    if bw > 0:
        # 显式声明带宽 = 打开 hysteria2 的 Brutal 拥塞控制。填的必须是链路真实
        # 能跑到的值: 填高了会疯狂重传把链路打烂, 填低了跑不满 —— 所以默认不开,
        # 留空走 QUIC + BBR (已经能解决 TCP-over-TCP 的主要问题)。
        lines += [
            "bandwidth:",
            f"  up: {bw} mbps",
            f"  down: {bw} mbps",
        ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- 进程管理

def _log_path(key: str) -> str:
    return os.path.join(work_dir(), f"{key}.log")


def _pid_path(key: str) -> str:
    return os.path.join(work_dir(), f"{key}.pid")


def _fingerprint(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _terminate(proc: subprocess.Popen, timeout: float = 4.0) -> None:
    if proc.poll() is not None:
        return
    try:
        proc.terminate()          # hysteria 收到 SIGTERM 会自己收尾
    except OSError:
        return
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:  # pragma: no cover - 兜底
        try:
            proc.kill()
        except OSError:
            pass


def _cmdline(pid: int) -> str:
    """读一个 pid 的命令行 (用来确认"这个进程确实是我们起的")。"""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            return fh.read().decode("utf-8", "replace").replace("\0", " ")
    except OSError:
        pass
    try:
        out = subprocess.run(
            ["ps", "-o", "command=", "-p", str(pid)],
            capture_output=True, text=True, timeout=5, check=False,
        )
        return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def _reap_stale() -> None:
    """清掉上一次面板留下的孤儿进程。

    systemd 重启面板时会连带收走子进程, 但面板自身崩溃 / 手工 kill 时不会 ——
    孤儿还占着 UDP 端口, 新的起不来。这里按 pid 文件把它们收掉, 判据是命令行里
    确实包含我们的配置路径 (绝不误杀别的 hysteria)。
    """
    base = work_dir()
    if not os.path.isdir(base):
        return
    with _LOCK:
        ours = {proc.pid for proc, _ in _PROCS.values()}
    for name in os.listdir(base):
        if not name.endswith(".pid"):
            continue
        try:
            with open(os.path.join(base, name), encoding="utf-8") as fh:
                pid = int(fh.read().strip())
        except (OSError, ValueError):
            continue
        if pid <= 1 or pid in ours:
            continue
        cmdline = _cmdline(pid)
        if cmdline and base in cmdline:
            try:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.4)
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass


def _write_config(key: str, text: str) -> str:
    base = _ensure_dir()
    path = os.path.join(base, f"{key}.yaml")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    try:
        os.chmod(path, 0o600)   # 里面有密码
    except OSError:
        pass
    return path


def _spawn(key: str, mode: str, cfg_path: str) -> subprocess.Popen:
    binary_path = binary()
    # Popen 会自己复制一份 fd, 所以 with 块结束就把句柄关掉 (子进程照写不误)。
    with open(_log_path(key), "a", encoding="utf-8") as log:
        proc = subprocess.Popen(
            [binary_path, mode, "-c", cfg_path, "--disable-update-check"],
            stdout=log,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
        )
    try:
        with open(_pid_path(key), "w", encoding="utf-8") as fh:
            fh.write(str(proc.pid))
    except OSError:
        pass
    with _LOCK, open(cfg_path, encoding="utf-8") as fh:
        _PROCS[key] = (proc, _fingerprint(fh.read()))
    return proc


def _stop(key: str) -> None:
    with _LOCK:
        item = _PROCS.pop(key, None)
    if item:
        _terminate(item[0])
    for path in (_pid_path(key),):
        try:
            os.remove(path)
        except OSError:
            pass


def running(key: str) -> bool:
    """这个 key 的进程现在是不是活着 (面板据此显示状态)。"""
    with _LOCK:
        item = _PROCS.get(key)
    return bool(item and item[0].poll() is None)


def desired(state: dict) -> list[dict]:
    """按当前配置推导"应该跑哪些 hysteria 进程"。"""
    out: list[dict] = []
    exit_cfg = (state.get("chain") or {}).get("exit") or {}
    if exit_cfg.get("enabled") and exit_cfg.get("hy_enabled"):
        out.append(
            {"key": "exit", "mode": "server", "yaml": server_config(state), "label": "落地端 QUIC"}
        )
    for entry in (state.get("chain") or {}).get("entries") or []:
        if not entry.get("enabled", True) or entry.get("transport") != "hysteria2":
            continue
        if not entry.get("hy_port"):
            continue
        out.append(
            {
                "key": f"entry-{entry.get('id')}",
                "mode": "client",
                "yaml": client_config(entry),
                "label": f"内层 QUIC · {entry.get('label') or entry.get('host')}",
            }
        )
    return out


def sync(state: dict, restart_changed: bool = True) -> tuple[bool, str]:
    """让实际进程与配置对齐: 缺的起、变的重启、多的停掉。

    返回 (是否顺利, 给面板看的一句话)。**不说话** 代表"这台机器根本没用 QUIC
    内层" —— 那种情况下不该往步骤里塞一句废话。
    """
    if not binary():
        specs = desired(state)
        if specs:
            return False, "内层 QUIC 需要 hysteria 二进制, 本机没装 —— 这条链会不通"
        return True, ""

    _reap_stale()
    specs = desired(state)
    wanted = {spec["key"] for spec in specs}
    # 先停掉不该跑的 (链路被删掉 / 落地端关了 / 切回了 Reality)
    with _LOCK:
        alive = set(_PROCS)
    for key in alive - wanted:
        _stop(key)

    failed: list[str] = []
    for spec in specs:
        key = spec["key"]
        if spec["mode"] == "server":
            # 证书按 SNI 现签 (换域名 / 从备份恢复 / 文件被删掉都要能自愈)。
            # hysteria 服务端在 SNI 与证书 SAN 对不上时会直接 TLS 告警, 客户端
            # 看到的只有一句 "tls: internal error", 所以这里失败必须说出来。
            cert_ok, cert_detail = ensure_exit_cert(state)
            if not cert_ok:
                failed.append(f"{spec['label']} 证书不可用: {cert_detail}")
                continue
        cfg_path = _write_config(key, spec["yaml"])
        fingerprint = _fingerprint(spec["yaml"])
        with _LOCK:
            item = _PROCS.get(key)
        if item and item[0].poll() is None:
            if item[1] == fingerprint or not restart_changed:
                continue
            _stop(key)
        proc = _spawn(key, spec["mode"], cfg_path)
        time.sleep(0.35)   # 端口是真占上了还是立刻退出, 让它先跑起来再说
        if proc.poll() is not None:
            failed.append(f"{spec['label']} 启动失败 (见 {_log_path(key)})")

    if failed:
        return False, "; ".join(failed)
    if not specs:
        return True, ""
    clients = sum(1 for s in specs if s["mode"] == "client")
    servers = len(specs) - clients
    parts = []
    if servers:
        parts.append(f"{servers} 个落地 UDP 监听")
    if clients:
        parts.append(f"{clients} 个入口 QUIC 客户端")
    return True, "内层 QUIC 已就绪 (" + " / ".join(parts) + ")"


def stop_all() -> None:
    """面板退出时收尾 (开发环境 / 手工调试用)。"""
    with _LOCK:
        keys = list(_PROCS)
    for key in keys:
        _stop(key)


def supervisor_loop(stop: threading.Event) -> None:
    """看门线程: 定期确认"该跑的还在跑"。

    子进程被 OOM / 崩溃带走时, 面板不会立刻知道 —— 这条链会一直不通用到用户
    下次点"重新应用"。每 20 秒对一次账, 代价可以忽略。
    """
    from . import config as _config

    while True:
        # 看门线程绝不能因异常退出 —— 挂了就再没人把掉线的子进程拉回来。
        with contextlib.suppress(Exception):
            with _config.locked():
                state = _config.load_state()
            sync(state)
        if stop.wait(SUPERVISE_INTERVAL):
            return


def status(state: dict) -> dict:
    """面板显示用的状态: 每个应由我们托管的进程现在活没活。"""
    return {
        spec["key"]: running(spec["key"])
        for spec in desired(state)
    }


def pick_socks_port(state: dict, preferred: int | None = None) -> int:
    """给入口端的本地 hysteria 客户端挑一个回环端口。"""
    used = {
        int(entry.get("hy_socks_port") or 0)
        for entry in (state.get("chain") or {}).get("entries") or []
    }
    used.update(int(v) for v in (state.get("ports") or {}).values() if str(v).isdigit())
    if preferred:
        port = int(preferred)
        if not 1 <= port <= 65535:
            raise ValueError("端口需在 1-65535 之间")
        if port in used or not services.port_available(port, "tcp"):
            raise ValueError(f"端口 {port} 已被占用, 换一个")
        return port
    for port in range(SOCKS_PORT_BASE, 65535):
        if port in used:
            continue
        if services.port_available(port, "tcp"):
            return port
    raise ValueError("找不到空闲端口")


def temp_client_config(entry: dict, socks_port: int) -> str:
    """测速用的临时客户端配置 (与正式那份同源, 只换 socks 端口)。"""
    return client_config({**entry, "hy_socks_port": socks_port})


def wait_socks(port: int, timeout: float = 6.0, proc: subprocess.Popen | None = None) -> str:
    """等本地 SOCKS5 端口起来; 返回空串表示成功。"""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if services.tcp_connect_ms("127.0.0.1", port, 0.3)[0]:
            return ""
        if proc is not None and proc.poll() is not None:
            return "内层 QUIC 客户端启动失败 (缺少 hysteria 二进制? 端口被占?)"
        time.sleep(0.15)
    return "内层 QUIC 客户端的 SOCKS 端口没就绪"


def start_temp_client(entry: dict, socks_port: int) -> tuple[subprocess.Popen | None, str, str]:
    """起一个临时 hysteria 客户端 (测速 / 添加条目时的真实握手)。

    返回 (进程, 配置目录, 错误说明)。调用方负责收尾 (用 `cleanup_temp`)。
    """
    if not binary():
        return None, "", "本机没有 hysteria 二进制, 无法测试 QUIC 内层"
    # 每次探测一个独立目录: 两次测速撞在一起时不会互相覆盖配置
    base = tempfile.mkdtemp(prefix="probe-", dir=_ensure_dir())
    cfg_path = os.path.join(base, "probe.yaml")
    with open(cfg_path, "w", encoding="utf-8") as fh:
        fh.write(temp_client_config(entry, socks_port))
    try:
        os.chmod(cfg_path, 0o600)
    except OSError:
        pass
    with open(os.path.join(base, "probe.log"), "a", encoding="utf-8") as probe_log:
        proc = subprocess.Popen(
            [binary(), "client", "-c", cfg_path, "--disable-update-check"],
            stdout=probe_log,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
        )
    return proc, base, ""


def _ensure_dir() -> str:
    base = work_dir()
    os.makedirs(base, exist_ok=True)
    return base


def cleanup_temp(proc: subprocess.Popen | None, base: str) -> None:
    if proc is not None:
        _terminate(proc, timeout=2.0)
    if base and os.path.isdir(base):
        shutil.rmtree(base, ignore_errors=True)


def client_log_tail(key: str, lines: int = 12) -> str:
    path = _log_path(key)
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return "".join(fh.readlines()[-lines:])
    except OSError:
        return ""
