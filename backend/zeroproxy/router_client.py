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
import threading
import time
import urllib.error
import urllib.request

from .config import paths

#: 路由器端脚本版本 (会显示在面板的设备卡上; 改了脚本就 +1)
SCRIPT_VERSION = "1.1.0"

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
#: 低于这个大小一律视为下载失败 (一个正常的 mihomo 压缩包 ≈ 20 MB)。
#: 可用 ZP_CORE_MIN_BYTES 调低 —— 自动化演练里用一个几 KB 的假内核就能把
#: "下载 → 解压 → 可执行校验"这条路整条跑通, 不必真的下 20 MB。
MIN_BYTES = int(os.environ.get("ZP_CORE_MIN_BYTES", str(4 << 20)))


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


# ---------------------------------------------------------------- 分流数据库
# mihomo 加载 GEOSITE / GEOIP 规则时**必须**有分流数据库: 缺文件不是"跳过这条规则",
# 而是整份配置直接加载失败。它自己的默认行为是当场去 GitHub 拉 (geox-url 的默认值),
# 真机上那一步就是"安装卡住"的来源:
#
#     level=error msg="can't initial GeoIP: can't download MMDB: context deadline exceeded"
#     level=error msg="rules[38] [GEOIP,CN,🎯 全球直连] error: ... context deadline exceeded"
#     configuration file /etc/zeroproxy/config.yaml.new test failed
#
# 路由器端的网络正好是最难访问 GitHub 的那一类 (装机时它还没有任何代理可用)。所以和
# 内核二进制一样: **面板去下, 路由器只访问面板一个地址**。路由器把文件放进自己的工作
# 目录, mihomo 看到文件就不再下载 —— 整条装机链路不再需要外网。
#
# 选文件的原则是"路由器闪存要小": 规则真正用到的只有 CN 的 IP 段和几个域名分类, 上游
# 为此专门出了 lite 版 (geoip-lite.metadb, 0.4 MB)。再配一份完整的 geosite.dat
# (4 MB, 含 cn / private / category-ads-all / netflix / disney / hbo / primevideo /
# youtube), 一共 4.4 MB —— 是面板自己那两份 (Loyalsoldier, 28 MB) 的六分之一。
#
# 文件名不能改: mihomo 在 `-d` 目录里按名字找 (大小写不敏感) —— GEOIP 认
# Country.mmdb / geoip.db / geoip.metadb, GEOSITE 认 geosite.dat。
GEO_FILES: dict[str, tuple[str, int]] = {
    "geoip.metadb": (
        "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip-lite.metadb",
        200 << 10,
    ),
    "geosite.dat": (
        "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
        2 << 20,
    ),
}

#: 数据过期时间: 超过就从上游重取 (分流数据不是"越新越好", 但也不能永远不更新 —— 一周
#: 一次足够, 而且只在路由器安装/重装时才下载)。
GEO_TTL = int(os.environ.get("ZP_GEO_TTL", str(7 * 86400)))

#: 单个镜像的超时 (4 MB 的文件, 90 秒足够; 与 mihomo 自己的下载超时同量级)。
GEO_SOURCE_TIMEOUT = 90

#: 分流数据库的镜像顺序: 与内核不同, 把国内可用的反代放前面。GitHub 直连在受限出口上
#: 是"卡满超时再失败", 排第一会白吃掉整个时间预算 (真机网络就是这样: 直连与 ghfast
#: 都超时, 只有 gh-proxy 通)。
GEO_MIRRORS = (
    "https://gh-proxy.com/{url}",
    "https://hk.gh-proxy.com/{url}",
    "{url}",
    "https://ghfast.top/{url}",
    "https://ghproxy.net/{url}",
)

#: 一次下载的总时间上限。5 个镜像各 90 秒最坏是 7 分钟, 而路由器正在**同步等**这份
#: 数据 —— 它不可能给一台面板几分钟去翻墙。到点就如实报错, 让路由器先降级装上。
GEO_DEADLINE = int(os.environ.get("ZP_GEO_DEADLINE", "200"))

#: 体积下限 (挡 404 页面 / 限流提示)。演练里用 ZP_GEO_MIN_BYTES 调低: 一个几百字节的
#: 假文件就能把"路由器从面板取数据"这条路整条跑通。
GEO_MIN_OVERRIDE = int(os.environ.get("ZP_GEO_MIN_BYTES", "0") or 0)

#: 同一时间只允许一个下载任务: 两台路由器同时装机时不该把 4 MB 的文件拉两遍。
GEO_LOCK = threading.Lock()


def geo_min_bytes(name: str) -> int:
    if GEO_MIN_OVERRIDE > 0:
        return GEO_MIN_OVERRIDE
    return GEO_FILES[name][1]


def geo_dir() -> str:
    return os.path.join(paths()["data_dir"], "client", "geo")


def geo_file(name: str) -> str:
    return os.path.join(geo_dir(), name)


def geo_ready(name: str) -> bool:
    try:
        return os.path.getsize(geo_file(name)) >= geo_min_bytes(name)
    except (OSError, KeyError):
        return False


def geo_stale(name: str) -> bool:
    try:
        return (time.time() - os.path.getmtime(geo_file(name))) > GEO_TTL
    except OSError:
        return True


def cached_geo() -> list[dict]:
    """面板上「路由器分流数据」的展示信息。"""
    out = []
    for name in GEO_FILES:
        try:
            size = os.path.getsize(geo_file(name))
        except OSError:
            continue
        out.append({
            "name": name,
            "size": size,
            "fresh": not geo_stale(name),
            "mtime": int(os.path.getmtime(geo_file(name))),
        })
    return out


def fetch_geo(
    name: str, *, timeout: int = GEO_SOURCE_TIMEOUT, force: bool = False
) -> tuple[bool, str, str]:
    """按镜像顺序取一份分流数据库。返回 (ok, 说明, 本地路径)。

    已缓存且没过期就直接返回 —— 路由器重装 / 多台设备复用时不再重复下载 (4 MB 也是流量)。
    """
    if name not in GEO_FILES:
        return False, f"未知的数据文件: {name}", ""
    dst = geo_file(name)
    if not force and geo_ready(name) and not geo_stale(name):
        return True, "已缓存", dst

    url, _default_min = GEO_FILES[name]
    minimum = geo_min_bytes(name)
    errors: list[str] = []
    with GEO_LOCK:
        # 等锁期间别的请求可能已经下好了
        if not force and geo_ready(name) and not geo_stale(name):
            return True, "已缓存", dst
        os.makedirs(geo_dir(), exist_ok=True)
        tmp = dst + ".part"
        deadline = time.time() + GEO_DEADLINE
        for template in GEO_MIRRORS:
            source = template.format(url=url)
            left = deadline - time.time()
            if left <= 1:
                errors.append("总时间超限, 放弃剩余镜像")
                break
            try:
                request = urllib.request.Request(source, headers={"User-Agent": UA})
                per_try = max(5, min(timeout, int(left)))
                with urllib.request.urlopen(request, timeout=per_try) as resp:
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
                if size < minimum:
                    errors.append(f"{source} 体积异常 ({size} 字节)")
                    continue
                os.replace(tmp, dst)
                return True, f"已下载 {size // 1024} KB", dst
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


#: 路由器管理界面会用到的文件 (由面板分发, 路由器只负责落盘 —— 于是界面的更新
#: 只要重跑一次安装命令, 不需要重新打包客户端)。
#: 键 = URL 里的名字, 值 = (相对 client/luci 的路径, media_type)
UI_FILES: dict[str, tuple[str, str]] = {
    "index.html": ("index.html", "text/html; charset=utf-8"),
    "app.js": ("app.js", "text/javascript; charset=utf-8"),
    "cgi": ("cgi", "text/plain; charset=utf-8"),
    "menu.json": ("menu.json", "application/json; charset=utf-8"),
    "acl.json": ("acl.json", "application/json; charset=utf-8"),
    "status.js": ("status.js", "text/javascript; charset=utf-8"),
}


def ui_file(name: str) -> tuple[str, str, str] | None:
    """读取一个界面文件。返回 (正文, media_type, 文件名), 未登记的名字返回 None。

    只允许白名单里的名字 —— 这个端点是匿名可达的 (路由器安装时来取), 所以绝不能
    接受任意路径 (否则就是给面板开了个任意文件读取)。
    """
    entry = UI_FILES.get(name)
    if not entry:
        return None
    rel, media = entry
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "client", "luci", rel)
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read(), media, os.path.basename(rel)


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
        "geo": cached_geo(),
        "geo_names": list(GEO_FILES),
        "cached_at": int(time.time()),
    }
