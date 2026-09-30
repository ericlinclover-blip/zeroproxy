"""管理员凭据的**唯一**一处实现。

面板 (`POST /api/account`) 与终端快捷管理 (`z` → `zeroproxy.cli`) 都要改账号密码,
两边必须完全同规则: 用户名格式、密码长度、新旧密码不能相同、以及"改了密码要把别的
会话踢下线"。规则写两遍迟早会漂, 所以这里只放一份, 两边都调它。

注意这里**不碰节点凭据** (VLESS UUID / Trojan 与 Hysteria 口令): 那些是初始化那刻
定下并写进订阅的, 改面板账号不该让所有客户端掉线。
"""
from __future__ import annotations

import re

from . import crypto

#: 面板用户名 (与初始化时的校验完全一致)
USER_RE = re.compile(r"^[A-Za-z0-9._-]{2,32}$")
#: 密码长度区间 (与初始化时的校验完全一致)
PASSWORD_MIN = 6
PASSWORD_MAX = 128


def validate_username(name: str) -> str:
    name = (name or "").strip()
    if not USER_RE.match(name):
        raise ValueError("用户名需为 2-32 位字母/数字/_-.")
    return name


def validate_password(password: str) -> str:
    if len(password) < PASSWORD_MIN or len(password) > PASSWORD_MAX:
        raise ValueError(f"密码长度需 {PASSWORD_MIN}-{PASSWORD_MAX} 位")
    return password


def apply_credentials(
    state: dict,
    *,
    username: str | None = None,
    new_password: str | None = None,
    keep_session: str | None = None,
) -> tuple[list[str], int]:
    """把新的用户名 / 密码写进 state。返回 (改动清单, 踢掉几个其它会话)。

    当前密码的校验由**调用方**负责: 面板必须验 (cookie 可能被偷走一个), 而 SSH 里
    的 root 本来就有 state.json 的完全控制权 —— 那条路正是"忘了密码"的兜底, 再要
    一次旧密码纯属自找麻烦。

    校验失败抛 `ValueError`, 消息直接给用户看。
    """
    admin = state.setdefault("admin", {"username": "", "password_hash": ""})
    changed: list[str] = []

    if username is not None:
        name = validate_username(username)
        if name != admin.get("username"):
            admin["username"] = name
            changed.append(f"用户名改为 {name}")

    kicked = 0
    if new_password:
        validate_password(new_password)
        if crypto.verify_password(new_password, admin.get("password_hash") or ""):
            raise ValueError("新密码不能和当前密码相同")
        admin["password_hash"] = crypto.hash_password(new_password)
        changed.append("密码已更新")
        # 改密码就把别的设备踢下线; `keep_session` 是"当前这台" (面板路径会传)
        for token in list(state.get("sessions", {})):
            if token != keep_session:
                state["sessions"].pop(token, None)
                kicked += 1

    if not changed:
        raise ValueError("没有需要修改的内容")
    return changed, kicked
