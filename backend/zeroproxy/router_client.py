"""路由器客户端的服务端部分: 安装脚本渲染 + 内核二进制分发。

为什么由面板分发内核二进制
------------------------
路由器要自己从 GitHub 拉 20 MB 的 mihomo, 在国内宽带上是**最脆弱的一环**:
release 域名经常不可达, 用户看到的是"装到一半卡住"。所以面板来做这件事 ——
它在服务器侧, 可以多镜像重试, 并且只成功下载一次就缓存下来。
路由器因此只需要访问**一个地址** (面板自己的域名), 一条防火墙规则、一张证书。

二进制不入库、不进备份, 缓存在 `data/client/cores/` (见 paths), 可随时删掉重下。
"""
from __future__ import annotations

import os
import time
import urllib.error
import urllib.request

from .config import paths

#: 路由器端脚本版本 (会显示在面板的设备卡上; 改了脚本就 +1)
SCRIPT_VERSION = "1.0.0"

#: 固定的 mihomo 版本。固定而不是跟随最新, 是因为路由器端配置文件 (tun/dns/sniffer)
#: 是按某一版的行为写的; 内核升级可能带来字段废弃, 那种问题在用户家里"全屋断网"
#: 才暴露出来。要升级: 改这里 → 面板重新生成 → 路由器重跑一次安装命令。
CORE_VERSION = os.environ.get("ZP_CORE_VERSION", "v1.19.32")

#: CPU 架构 → mihomo release 资产后缀。
#: armv7 兜底 armv6 (mihomo 没有单独的 armv6 构建, armv7 构建在 armv6 上跑不了 ——
#: 但这类设备 (老款百兆路由) 本来也带不动, 让它在 preflight 就报空间不足更诚实)。
ARCHES: dict[str, str] = {
    "arm64": "arm64",
    "armv7": "armv7",
    "amd64": "amd64-v1",       # x86-64 v1 基线: 兼容所有 x86_64 机器
    "mips": "mips-softfloat",
    "mipsle": "mipsle-softfloat",
    "mips64le": "mips64le",
}

#: 面板上展示用的中文名
ARCH_LABEL = {
    "arm64": "ARM64 (aarch64)",
    "armv7": "ARMv7 (arm)",
    "amd64": "x86_64",
    "mips": "MIPS (大端)",
    "mipsle": "MIPSel (小端)",
    "mips64le": "MIPS64el",
}

#: 下载镜像。第一个是 GitHub 官方, 后面是国内可用的加速前缀 ——
#: 这些前缀的可用性会随时间变化, 所以是"挨个试"而不是"选一个最好的"。
MIRRORS = (
    "{url}",
    "https://ghfast.top/{url}",
    "https://gh-proxy.com/{url}",
    "https://ghproxy.net/{url}",
    "https://hk.gh-proxy.com/{url}",
)

UA = "zeroproxy-panel"
#: 低于这个大小一律视为下载失败 (一个正常的 mihomo 压缩包 ≈ 20 MB)
MIN_BYTES = 4 << 20


def asset_name(arch: str) -> str:
    suffix = ARCHES.get(arch)
    if not suffix:
        raise ValueError(f"不支持的架构: {arch}")
    return f"mihomo-linux-{suffix}-{CORE_VERSION}.gz"


def release_url(arch: str) -> str:
    return (
        f"https://github.com/MetaCubeX/mihomo/releases/download/"
        f"{CORE_VERSION}/{asset_name(arch)}"
    )


def core_dir() -> str:
    return os.path.join(paths()["data_dir"], "client", "cores")


def core_file(arch: str) -> str:
    return os.path.join(core_dir(), f"mihomo-{arch}-{CORE_VERSION}.gz")


def core_ready(arch: str) -> bool:
    path = core_file(arch)
    try:
        return os.path.getsize(path) >= MIN_BYTES
    except OSError:
        return False


def cached_arches() -> list[dict]:
    """面板上「已缓存架构」列表。"""
    out = []
    for arch in ARCHES:
        path = core_file(arch)
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        if size >= MIN_BYTES:
            out.append({"arch": arch, "label": ARCH_LABEL.get(arch, arch), "size": size})
    return out


def fetch_core(arch: str, *, timeout: int = 180) -> tuple[bool, str, str]:
    """按镜像顺序下载内核。返回 (ok, 说明, 本地路径)。

    已缓存就直接返回 —— 路由器重装/多台设备复用时不再重复下载。
    """
    if arch not in ARCHES:
        return False, f"不支持的架构: {arch}", ""
    dst = core_file(arch)
    if core_ready(arch):
        return True, "已缓存", dst

    os.makedirs(core_dir(), exist_ok=True)
    tmp = dst + ".part"
    url = release_url(arch)
    errors: list[str] = []
    for template in MIRRORS:
        source = template.format(url=url)
        try:
            request = urllib.request.Request(source, headers={"User-Agent": UA})
            with urllib.request.urlopen(request, timeout=timeout) as resp:
                status = getattr(resp, "status", 200)
                if status is not None and status != 200:
                    errors.append(f"{source} HTTP {status}")
                    continue
                size = 0
                with open(tmp, "wb") as fh:
                    while True:
                        chunk = resp.read(1 << 18)
                        if not chunk:
                            break
                        fh.write(chunk)
                        size += len(chunk)
            if size < MIN_BYTES:
                errors.append(f"{source} 体积异常 ({size} 字节)")
                continue
            os.replace(tmp, dst)
            return True, f"已下载 {size // 1024 // 1024} MB", dst
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            errors.append(f"{source} {exc}")
        finally:
            if os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass
    return False, "; ".join(errors)[-300:], ""


# ---------------------------------------------------------------- 安装脚本

def script_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "client", "router-install.sh")


def render_script(base: str, code: str) -> str:
    """把面板地址与配对码烘进安装脚本。

    两个值都只出现在脚本头部被双引号包住的赋值里; `base` 来自面板自己的配置
    (域名 + 端口), `code` 是我们自己生成的十六进制串, 所以不存在注入面 ——
    但仍然在这里挡一道: 出现双引号/反引号/换行就直接拒绝渲染。
    """
    for value in (base, code):
        if any(ch in value for ch in '"`$\n\\'):
            raise ValueError("安装脚本参数包含非法字符")
    with open(script_path(), "r", encoding="utf-8") as fh:
        text = fh.read()
    return (
        text.replace("__ZP_BASE__", base)
        .replace("__ZP_CODE__", code)
        .replace("__ZP_CLIENT_VERSION__", SCRIPT_VERSION)
    )


def summary() -> dict:
    """面板卡片要展示的元信息。"""
    return {
        "script_version": SCRIPT_VERSION,
        "core_version": CORE_VERSION,
        "arches": [{"id": a, "label": ARCH_LABEL.get(a, a)} for a in ARCHES],
        "cached": cached_arches(),
        "cached_at": int(time.time()),
    }
