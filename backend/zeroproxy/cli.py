"""终端快捷管理 (`z`) —— 面板进不去时那条一定走得通的路。

为什么要有它: 面板密码只能从面板里改, **忘了就彻底进不去**; 而"在线更新"那颗按钮
也在面板里。SSH 是最后一条兜底通道, 所以这里只做那两件事 —— 而且**走与面板同一条
代码路径** (同一个 state.json、同一份 account.apply_credentials、同一个 upgrade.sh),
不另起一套逻辑, 免得两边行为漂移。

用法 (安装脚本会把 `z` 放到 /usr/local/bin):

    z              交互式菜单 (1 改账号密码 / 2 在线更新 / 0 退出)
    z passwd       直接改账号密码
    z update       直接在线更新
    z status       看当前域名 / 账号 / 版本 / 服务状态
"""
from __future__ import annotations

import getpass
import os
import subprocess
import sys

from . import __version__, account, config, update
from .config import paths

USAGE = """用法:
  z              进入交互式菜单 (修改账号密码 / 在线更新版本)
  z passwd       修改面板账号 / 密码
  z update       在线更新到最新版本
  z status       查看当前域名 / 账号 / 版本 / 服务状态

面板登不进去 (忘记密码) 时: SSH 到服务器, 敲 z 即可进这个菜单。"""


# ---------------------------------------------------------------- 输入输出
#: 这三件小事都单独抽出来: 测试里替换掉它们就能非交互地跑完整个菜单。


def _out(msg: str = "") -> None:
    print(msg)


def _ask(prompt: str) -> str:
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        _out("")
        return ""


def _ask_password(prompt: str) -> str:
    """密码不回显 (管道 / 非 TTY 下 getpass 会自动退化成普通读取)。"""
    try:
        return getpass.getpass(prompt)
    except (EOFError, KeyboardInterrupt):
        _out("")
        return ""


def _confirm(prompt: str) -> bool:
    return _ask(prompt).strip().lower() in ("y", "yes", "是", "1")


def _writable_or_warn() -> bool:
    """state.json 写不写得进去 —— 写不进去多半是忘了 sudo, 那就别往下走了。"""
    path = paths()["state"]
    if os.path.exists(path) and not os.access(path, os.W_OK):
        _out(f"× 没有写入权限: {path}")
        _out("  请用 root 运行: sudo z")
        return False
    return True


# ---------------------------------------------------------------- 状态读取

def _panel_url(state: dict) -> str:
    domain = (state.get("domain") or "").strip()
    if not domain:
        return "(还没配置域名)"
    port = config.PANEL_PORT
    return f"https://{domain}" + ("" if port in (80, 443) else f":{port}")


def _service_state() -> str:
    """面板服务在不在跑 (没有 systemd 的环境如实说"无法判断")。"""
    if not os.path.exists("/run/systemd/system"):
        return "未使用 systemd"
    try:
        proc = subprocess.run(
            ["systemctl", "is-active", "zeroproxy"],
            capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return "无法判断"
    return {"active": "运行中", "inactive": "已停止", "failed": "启动失败"}.get(
        proc.stdout.strip(), proc.stdout.strip() or "未知"
    )


def status_lines() -> list[str]:
    state = config.load_state()
    admin = (state.get("admin") or {}).get("username") or "(未初始化)"
    return [
        f" 面板   {_panel_url(state)}",
        f" 账号   {admin}",
        f" 版本   v{__version__}",
        f" 服务   zeroproxy {_service_state()}",
    ]


# ---------------------------------------------------------------- 1) 改账号密码

def change_credentials(*, username: str | None, password: str) -> int:
    """改管理员凭据。SSH 里不再要求旧密码 —— 这条路本来就是给"忘了密码"用的。"""
    if not _writable_or_warn():
        return 1
    with config.locked():
        state = config.load_state()
        if not state.get("configured"):
            _out("× 面板还没初始化 —— 先在浏览器里打开面板完成初始化, 再来这里改账号")
            return 1
        try:
            changed, kicked = account.apply_credentials(
                state, username=username, new_password=password
            )
        except ValueError as exc:
            _out(f"× {exc}")
            return 1
        config.audit(
            state,
            "account_update_cli",
            "; ".join(changed) + (f" (注销其它会话 {kicked} 个)" if kicked else ""),
            actor="terminal",
        )
        config.save_state(state)
        url = _panel_url(state)
        admin = (state.get("admin") or {}).get("username") or ""
    _out("✓ " + "; ".join(changed))
    if kicked:
        _out(f"  已注销其它 {kicked} 个登录会话 (改密码后旧会话不该继续有效)")
    _out(f"  现在可以用 {admin} / 新密码登录面板: {url}")
    return 0


def _menu_passwd() -> int:
    state = config.load_state()
    current = (state.get("admin") or {}).get("username") or ""
    _out("")
    _out(f"  当前用户名: {current or '(未初始化)'}   (直接回车保持不变)")
    name = _ask("  新用户名: ").strip() or None
    password = _ask_password("  新密码 (至少 6 位): ")
    if not password:
        _out("× 密码为空, 已取消")
        return 1
    if password != _ask_password("  再输一遍确认: "):
        _out("× 两次输入不一致, 已取消")
        return 1
    return change_credentials(username=name, password=password)


# ---------------------------------------------------------------- 2) 在线更新

def run_update() -> int:
    """在线更新 —— 与面板「一键更新」用的是同一个 upgrade.sh。"""
    script = paths()["upgrade_script"]
    if not os.path.exists(script):
        _out(f"× 没找到升级脚本: {script}")
        _out("  先执行一次 README 里的一键升级命令, 它会随代码把 upgrade.sh 装到面板目录")
        return 1
    _out(f"  当前版本: v{__version__}")
    ok, latest, source = update.remote_version()
    if ok:
        _out(f"  远端最新: v{latest}   (来源 {source})")
        if not update.is_newer(latest, __version__):
            _out("  已经是最新版 —— 继续执行就等于原地重装一次 (可用于修复被改坏的文件)")
    else:
        _out(f"  远端版本检查没成功 ({source})")
        _out("  仍然可以继续: 升级脚本自己会按镜像顺序再试一遍")
    if not _confirm("现在执行升级? [y/N] "):
        _out("已取消")
        return 1
    _out("")
    # 直接把脚本交给用户看: 升级的每一步、失败原因、回滚结果都在它的输出里
    return subprocess.call(["bash", script])


# ---------------------------------------------------------------- 菜单

def _print_menu() -> None:
    _out("")
    _out("=" * 62)
    _out(" ZeroProxy 终端管理")
    for line in status_lines():
        _out(line)
    _out("-" * 62)
    _out(" 1) 修改面板账号 / 密码")
    _out(" 2) 在线更新到最新版本  (与面板「一键更新」同一条路径)")
    _out(" 0) 退出")
    _out("=" * 62)


def menu() -> int:
    while True:
        _print_menu()
        choice = _ask("请选择 [0-2]: ").strip().lower()
        if choice in ("0", "q", "quit", "exit"):
            _out("再见。")
            return 0
        if choice == "1":
            _menu_passwd()
        elif choice == "2":
            run_update()
        elif not choice:
            continue                      # 空回车只是重画一次, 不当成退出
        else:
            _out(f"× 没有这个选项: {choice} (输入 0 / 1 / 2)")


# ---------------------------------------------------------------- 入口

#: `z` / `zeroproxy` 这两个命令的内容 (由安装脚本调用本模块生成 —— 一份实现,
#: 免得 shell 里再抄一遍; 上面那行注释就是"这是我们装的"的判据)。
WRAPPER_MARK = "ZeroProxy 终端快捷管理"
#: 用替换而不是 str.format: 里面全是 shell 的 ${...}, 用 format 得把每个花括号都转义
WRAPPER = f"""#!/usr/bin/env bash
# {WRAPPER_MARK} —— 由 install.sh / upgrade.sh 生成, 手改会在下次升级时被覆盖
export ZP_HOME="__ZP_HOME__"
export PYTHONPATH="__ZP_HOME__${{PYTHONPATH:+:$PYTHONPATH}}"
cd "__ZP_HOME__" 2>/dev/null || true
exec "__ZP_HOME__/venv/bin/python" -m zeroproxy.cli "$@"
"""


def _is_ours(path: str) -> bool:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return WRAPPER_MARK in fh.read(400)
    except OSError:
        return False


def install_shortcut(bin_dir: str | None = None) -> int:
    """装 `z` 命令 (顺带装一个好记的长名字 `zeroproxy`)。

    如果 `z` 已经被别人的程序占用 (比如 zoxide), **不覆盖** —— 装长名字并说清楚,
    免得把用户环境里别的东西踩掉。

    安装目录默认 `/usr/local/bin`, 可用 `ZP_BIN_DIR` 指定 (少数发行版用 `/usr/bin`;
    升级演练也用它把命令装进沙箱, 免得动到真机的 /usr/local/bin)。
    """
    bin_dir = bin_dir or os.environ.get("ZP_BIN_DIR") or "/usr/local/bin"
    home = paths()["home"]
    target = os.path.join(bin_dir, "z")
    if os.path.exists(target) and not _is_ours(target):
        _out(f"! {target} 已存在且不是本程序装的, 保持不变")
        _out("  请改用 `zeroproxy` 命令 (本次也会一并装好)")
        target = ""
    try:
        os.makedirs(bin_dir, exist_ok=True)
        body = WRAPPER.replace("__ZP_HOME__", home)
        for path in filter(None, (target, os.path.join(bin_dir, "zeroproxy"))):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(body)
            os.chmod(path, 0o755)
            _out(f"✓ 终端快捷命令: {path}")
    except OSError as exc:
        _out(f"× 安装快捷命令失败: {exc}")
        _out(f"  需要 root 权限 (sudo), 或手动把命令指向 {home}/venv/bin/python -m zeroproxy.cli")
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    cmd = args[0].strip().lower() if args else ""
    if cmd in ("", "menu", "m"):
        return menu()
    if cmd in ("passwd", "password", "pw", "1"):
        return _menu_passwd()
    if cmd in ("update", "upgrade", "2"):
        return run_update()
    if cmd in ("status", "show", "info", "3"):
        _out("ZeroProxy 终端管理")
        for line in status_lines():
            _out(line)
        return 0
    if cmd == "install-shortcut":
        # 安装脚本用: cli install-shortcut [bin_dir]
        return install_shortcut(args[1] if len(args) > 1 else None)
    if cmd in ("-h", "--help", "help", "-?"):
        _out(USAGE)
        return 0
    _out(f"× 未知命令: {args[0]}")
    _out(USAGE)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
