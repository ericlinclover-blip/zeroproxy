"""面板自更新: 远端版本检查 + 触发 `upgrade.sh` + 回读升级进度。

设计要点:
  * 升级动作本身由仓库里的 `upgrade.sh` 完成 —— 面板只是「按一下按钮」,
    所以面板内升级与 README 里那条 curl 命令走的是**同一条代码路径**;
  * 升级脚本会重启面板进程, 因此不能在请求线程里同步执行: 用 systemd 的
    瞬时单元 (`systemd-run --no-block`) 把它放到独立 cgroup 里跑, 面板重启不会杀掉它。
    `--no-block` 是必须的 —— 不加的话 systemd-run 会把这个 oneshot 单元**等完**
    (升级要 30-40 秒), 请求线程撞上 30 秒超时, 回执变成"无法启动升级任务",
    而升级其实已经跑起来了 (`--no-block` 让 systemd-run 入队即返回);
  * 脚本永远**从临时副本**启动而不是就地执行 —— 见 `stage_script()`;
  * 进度落在 `$ZP_HOME/data/update.json` + `data/update.log`, 面板重启后照常
    能读到「上次升级做了什么、结果是成功还是失败」。
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from . import __version__, services
from .config import paths

#: 远端代码来源 (可用 ZP_REPO / ZP_REF 覆盖; 与 install.sh 保持一致)
DEFAULT_REPO = os.environ.get("ZP_REPO", "ericlinclover-blip/zeroproxy")
DEFAULT_REF = os.environ.get("ZP_UPDATE_REF", "main")

#: 版本号检查的多个镜像 (国内直连 GitHub 经常不通, 按顺序回退)。
#: 顺序很重要: jsDelivr 是 CDN, 命中缓存时会把旧版本号当"最新"返回 (实测发布后
#: fastly.jsdelivr 仍返回上一版的号), 而 raw / gh-proxy 拿到的是仓库当前内容 ——
#: 所以权威源在前, CDN 只作最后兜底。
#: **自建反代排第一** (8.72): 运营方自己的反代最稳, 而且更新是用户唯一的自救通道 ——
#: 面板停在旧版本时, 这一条是它能把新版本号读回来的唯一机会。
_MIRRORS = (
    "https://github.i3.pub/https://raw.githubusercontent.com/{repo}/{ref}/backend/zeroproxy/__init__.py",
    "https://raw.githubusercontent.com/{repo}/{ref}/backend/zeroproxy/__init__.py",
    "https://gh-proxy.com/https://raw.githubusercontent.com/{repo}/{ref}/backend/zeroproxy/__init__.py",
    "https://cdn.jsdelivr.net/gh/{repo}@{ref}/backend/zeroproxy/__init__.py",
    "https://fastly.jsdelivr.net/gh/{repo}@{ref}/backend/zeroproxy/__init__.py",
)

_VERSION_RE = re.compile(r"""__version__\s*=\s*["']([0-9][^"']*)["']""")

#: 版本检查结果缓存 (避免每次打开面板都出网)
CHECK_TTL = 600
_CACHE: dict = {"at": 0.0, "body": None}

#: 允许面板内升级的最长运行时间 (超过视为上次任务已死, 允许重开)
UPDATE_STALE_SECONDS = 3600


def current_version() -> str:
    return __version__


def parse_version(text: str) -> tuple[int, ...]:
    """把 "2.3.0" / "v2.3.1-beta" 解析成可比较的元组。"""
    parts: list[int] = []
    for chunk in re.split(r"[._\-+]", str(text).strip().lstrip("vV")):
        match = re.match(r"^(\d+)", chunk)
        if not match:
            break
        parts.append(int(match.group(1)))
    return tuple(parts) or (0,)


def is_newer(candidate: str, base: str) -> bool:
    return parse_version(candidate) > parse_version(base)


def remote_version(timeout: int = 8) -> tuple[bool, str, str]:
    """读取远端最新版本号。返回 (成功, 版本号, 来源或错误说明)。

    为什么是"**问遍所有镜像, 取版本号最高的那个**", 而不是"第一个成功就返回":
    raw.githubusercontent 的 CDN 缓存约 5 分钟 —— 刚发完版它会继续吐上一版号,
    面板于是显示"已是最新", 用户以为没发布 (v2.6.23 发布当时实测: raw 说 2.6.22,
    gh-proxy 已经是 2.6.23)。四个镜像并发问一遍, 谁给的最新就信谁; 全部失败才算失败。
    并发(而不是依次)是为了让总耗时 ≈ 最慢的那个镜像, 而不是四个之和。
    """
    from concurrent.futures import ThreadPoolExecutor

    def _one(template: str) -> tuple[str, str]:
        url = template.format(repo=DEFAULT_REPO, ref=DEFAULT_REF)
        host = url.split("/")[2]
        try:
            request = urllib.request.Request(
                url, headers={"User-Agent": f"ZeroProxy/{__version__}"}
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:
                text = response.read(8192).decode("utf-8", "replace")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return "", f"{host}: {exc}"
        match = _VERSION_RE.search(text)
        return (match.group(1).strip(), host) if match else ("", f"{host}: 未找到 __version__")

    seen: list[tuple[str, str]] = []
    errors: list[str] = []
    with ThreadPoolExecutor(max_workers=len(_MIRRORS)) as pool:
        for version, note in pool.map(_one, _MIRRORS):
            if version:
                seen.append((version, note))
            else:
                errors.append(note)
    if not seen:
        return False, "", "; ".join(errors)[:200]
    return True, *max(seen, key=lambda item: parse_version(item[0]))


def _read_status() -> dict:
    try:
        with open(paths()["update_status"], "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _write_status(payload: dict) -> None:
    path = paths()["update_status"]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def _log_tail(lines: int = 40) -> str:
    try:
        with open(paths()["update_log"], "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError:
        return ""
    return "\n".join(content.splitlines()[-max(1, int(lines)):])[-4000:]


def upgrade_script() -> str:
    path = paths()["upgrade_script"]
    if os.path.isfile(path):
        return path
    return ""


def stage_script(script: str) -> str:
    """把 upgrade.sh 复制到一个私有临时目录, 返回副本路径 (面板执行的是副本)。

    bash 是**按文件偏移增量读取**脚本的, 而 upgrade.sh 会在「安装新代码」那步把自己
    就地覆盖成新版本 (同一个 inode) —— 覆盖之后 bash 从"新文件"的同一偏移继续读, 读到的
    是另一段代码, 于是 `syntax error near unexpected token` 把整次升级打断
    (真机 v2.3.10 → v2.3.11 就是这么炸的, 靠自动回滚兜住)。

    从副本启动就完全没有这个问题 (副本是另一个 inode, 谁来覆盖 ZP_HOME 里那份都无所谓),
    于是**连还没打补丁的旧 upgrade.sh 也能被面板安全升级** —— 用户不必先去命令行换脚本。
    注: `bash -s < 原文件` 不算数, 那个 fd 指向的还是同一个 inode。新版本脚本自己也做了
    一份「先整份读进内存」的兜底 (命令行就地执行时靠它), 见仓库里的 upgrade.sh。
    """
    staged_dir = tempfile.mkdtemp(prefix="zeroproxy-update-")
    staged = os.path.join(staged_dir, "upgrade.sh")
    shutil.copyfile(script, staged)
    os.chmod(staged, 0o755)
    return staged


def prune_staged(max_age: float = 86400.0) -> None:
    """清掉过期的暂存目录 (老脚本不会自己删, 正常路径由新脚本的 ZP_SELF_DIR 收尾)。"""
    root = tempfile.gettempdir()
    try:
        entries = os.listdir(root)
    except OSError:
        return
    now = time.time()
    for name in entries:
        if not name.startswith("zeroproxy-update-"):
            continue
        path = os.path.join(root, name)
        try:
            if now - os.path.getmtime(path) > max_age:
                shutil.rmtree(path, ignore_errors=True)
        except OSError:
            continue


def is_running() -> bool:
    status = _read_status()
    if status.get("state") not in ("queued", "running"):
        return False
    started = int(status.get("started_at") or 0)
    return (time.time() - started) < UPDATE_STALE_SECONDS


def status(force: bool = False, timeout: int = 8) -> dict:
    """给面板用的只读快照: 版本 + 上次升级结果 + 日志尾部。

    `force=True` 时绕过缓存立即刷新 (用户手动点击"检查更新"时使用)。
    返回的 `cached` 字段标注是否命中缓存, 方便面板显示"上次检查: X 分钟前"
    和"已过期, 正在刷新"等不同状态。
    """
    now = time.time()
    cached = _CACHE.get("body")
    hit_cache = bool(cached) and now - float(_CACHE.get("at") or 0) <= CHECK_TTL
    if force or not hit_cache:
        ok, latest, source = remote_version(timeout=timeout)
        cached = {
            "ok": ok,
            "latest": latest,
            "source": source if ok else "",
            "error": "" if ok else source,
            "checked_at": int(now),
        }
        _CACHE["body"] = cached
        _CACHE["at"] = now

    current = current_version()
    latest = str(cached.get("latest") or "")
    script = upgrade_script()
    return {
        "current": current,
        "latest": latest,
        "update_available": bool(latest) and is_newer(latest, current),
        "check_ok": bool(cached.get("ok")),
        "check_error": str(cached.get("error") or ""),
        "checked_at": int(cached.get("checked_at") or 0),
        "source": str(cached.get("source") or ""),
        "repo": DEFAULT_REPO,
        "ref": DEFAULT_REF,
        "upgrade_script": script,
        "can_update": bool(script) and services.is_prod(),
        "prod": services.is_prod(),
        "cache_hit": hit_cache,  # 命中缓存 = 刚检查过, 前端可显示"上次检查时间"
        "running": is_running(),
        "last": _read_status(),
        "log_tail": _log_tail(),
    }


def start(trigger: str = "panel", timeout: int = 30, core: bool = False) -> tuple[bool, str]:
    """在后台启动 upgrade.sh。返回 (是否已开始, 说明)。

    `core=True` 时同时把 Xray / Hysteria 2 二进制升到最新 (upgrade.sh 的
    `ZP_UPDATE_CORE=1`)。**默认关闭, 且只由用户显式勾选触发**: 内核升级会改变
    配置语义 —— 本项目已经为此踩过好几次 (Xray 25 去掉 allowInsecure、证书字段
    改名、REALITY 密钥从 Ed25519 换 X25519、geo 数据加载策略收紧)。这种风险不该
    由"程序更新"按钮顺手替用户承担, 但也不该完全不给出路: 勾选框把选择权交回用户。
    """
    if not services.is_prod():
        return False, "本地开发环境不支持面板内升级, 请在服务器上运行 upgrade.sh"
    # 回执与 update.json 都要写清这次动没动内核 —— 面板的成功提示只说"升级完成",
    # 事后回看"那次到底升没升内核"必须能从记录里读出来
    core_note = " (含 Xray / Hysteria 2 内核)" if core else ""
    script = upgrade_script()
    if not script:
        return False, (
            f"未找到升级脚本 {paths()['upgrade_script']}; 请先执行一次 README 里的"
            "「一键升级」命令 (它会随代码把 upgrade.sh 装到面板目录)"
        )
    if is_running():
        return False, "已有升级任务在进行中"

    os.makedirs(os.path.dirname(paths()["update_log"]), exist_ok=True)
    prune_staged()
    staged = stage_script(script)
    _write_status(
        {
            "state": "queued",
            "from": current_version(),
            "to": "",
            "trigger": trigger,
            "started_at": int(time.time()),
            "finished_at": 0,
            "core": bool(core),
            "message": f"升级任务已排队{core_note}",
            "steps": [],
        }
    )

    unit = f"zeroproxy-update-{int(time.time())}"
    homedir = os.path.dirname(script)
    # 把面板自己的仓库 / 分支设置透传给升级脚本, fork 或指定 tag 部署的机器升级时不会跑偏
    runner_env = {
        **os.environ,
        "ZP_HOME": homedir,
        "ZP_TRIGGER": trigger,
        "ZP_REPO": DEFAULT_REPO,
        "ZP_REF": DEFAULT_REF,
        "ZP_SELF_DIR": os.path.dirname(staged),
        "ZP_UPDATE_CORE": "1" if core else "0",
    }
    runner = shutil.which("systemd-run")
    if runner:
        cmd = [
            runner,
            f"--unit={unit}",
            # 必须 --no-block: 默认 systemd-run 会等这个 oneshot 单元**跑完**才返回,
            # 而升级要 30-40 秒 —— 于是 subprocess 的 30 秒超时先到, 面板回执变成
            # "无法启动升级任务" (409), 界面上却看到升级真的在跑 (v2.6.3 真机复现)。
            "--no-block",
            "--collect",
            "--property=Type=oneshot",
            "--property=StandardOutput=null",
            "--property=StandardError=null",
            f"--setenv=ZP_HOME={homedir}",
            f"--setenv=ZP_TRIGGER={trigger}",
            f"--setenv=ZP_REPO={DEFAULT_REPO}",
            f"--setenv=ZP_REF={DEFAULT_REF}",
            f"--setenv=ZP_SELF_DIR={os.path.dirname(staged)}",
            f"--setenv=ZP_UPDATE_CORE={'1' if core else '0'}",
            "/bin/bash",
            staged,
        ]
    else:  # pragma: no cover - 极老系统兜底 (面板重启可能打断升级)
        cmd = ["/bin/bash", staged]

    if not runner:
        # 没有 systemd-run 时不能同步等 (要等 30-40 秒, 而且 30 秒超时会**杀掉**
        # 跑到一半的升级) —— 只能脱离进程组先跑起来, 剩下的交给脚本自己。
        try:
            subprocess.Popen(   # noqa: S603 - 参数固定, 走私有临时副本
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=runner_env,
                start_new_session=True,
            )
        except OSError as exc:
            _write_status(
                {
                    "state": "failed",
                    "from": current_version(),
                    "trigger": trigger,
                    "started_at": int(time.time()),
                    "finished_at": int(time.time()),
                    "message": f"无法启动升级任务: {exc}",
                    "steps": [],
                }
            )
            return False, f"无法启动升级任务: {exc}"
        return True, "升级已开始, 面板会自动重启, 完成后本页会自动刷新"

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=runner_env,
            start_new_session=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        _write_status(
            {
                "state": "failed",
                "from": current_version(),
                "trigger": trigger,
                "started_at": int(time.time()),
                "finished_at": int(time.time()),
                "message": f"无法启动升级任务: {exc}",
                "steps": [],
            }
        )
        return False, f"无法启动升级任务: {exc}"

    if proc.returncode != 0:
        detail = " ".join(((proc.stderr or "") + (proc.stdout or "")).split())[:200]
        _write_status(
            {
                "state": "failed",
                "from": current_version(),
                "trigger": trigger,
                "started_at": int(time.time()),
                "finished_at": int(time.time()),
                "message": f"systemd-run 启动失败: {detail}",
                "steps": [],
            }
        )
        return False, f"升级任务启动失败: {detail}"
    return True, "升级已开始, 面板会自动重启, 完成后本页会自动刷新"
