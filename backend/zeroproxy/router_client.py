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
import hashlib
import threading
import time
import urllib.error
import urllib.request

from .config import paths

#: 路由器端脚本版本 (会显示在面板的设备卡上; 改了脚本就 +1)
SCRIPT_VERSION = "1.2.3"

#: 固定的 mihomo 版本。固定而不是跟随最新, 是因为路由器端配置文件 (tun/dns/sniffer)
#: 是按某一版的行为写的; 内核升级可能带来字段废弃, 那种问题在用户家里"全屋断网"
#: 才暴露出来。要升级: 改这里 → 面板重新生成 → 路由器重跑一次安装命令。
CORE_VERSION = os.environ.get("ZP_CORE_VERSION", "v1.19.32")

#: CPU 架构 → mihomo release 资产后缀。
#: armv6 有独立构建 (mihomo-linux-armv6-*), 老款百兆路由 (bcm27xx / arm1176) 直接用它;
#: 以前把 armv6 兜到 armv7 上 —— 结果是一台内核能下载、能解压、跑起来就 "Illegal
#: instruction" 的机器, 比一开始就说清楚难查得多。
#: mips 大端 / 小端都取 softfloat 构建: OpenWrt 的 mips_24kc / mipsel_24kc 目标
#: (绝大多数 MIPS 路由) 的 24Kc 核没有 FPU, hardfloat 构建在上面同样跑不了。
ARCHES: dict[str, str] = {
    "arm64": "arm64",
    "armv6": "armv6",
    "armv7": "armv7",
    "amd64": "amd64-v1",       # x86-64 v1 基线: 兼容所有 x86_64 机器
    "mips": "mips-softfloat",
    "mipsle": "mipsle-softfloat",
    "mips64": "mips64",
    "mips64le": "mips64le",
}

#: 面板上展示用的中文名
ARCH_LABEL = {
    "arm64": "ARM64 (aarch64)",
    "armv6": "ARMv6 (arm1176 等老设备)",
    "armv7": "ARMv7 (arm)",
    "amd64": "x86_64",
    "mips": "MIPS (大端)",
    "mipsle": "MIPSel (小端)",
    "mips64": "MIPS64 (大端)",
    "mips64le": "MIPS64el",
}

#: 下载镜像。顺序 = "谁最可能在国内线路上跑得快"。
#: 第一个是**运营方自建的 GitHub 反代** (github.i3.pub, 写法同 gh-proxy: 把原始地址
#: 整个拼在后面, 支持 Range), 它比公共前缀稳; 后面是几个公共前缀; 官方直连排最后 ——
#: 面板自己也在国内时, 直连 GitHub 基本是"挂到超时", 排前面只会白吃掉整个时间预算
#: (2.6.23 那条教训)。
#: 前缀的可用性会随时间变化, 所以是"挨个试"; 试的过程中有速率闸门 (见 fetch_core):
#: 慢到"按这个速率跑不完"就立刻换下一个, 而不是把预算耗在一个数学上不可能完成的源上。
#: 想换掉整张表: ZP_CORE_MIRRORS=https://自己的镜像/{url},…
DEFAULT_MIRRORS = (
    "https://github.i3.pub/{url}",
    "https://gh-proxy.com/{url}",
    "https://hk.gh-proxy.com/{url}",
    "https://ghfast.top/{url}",
    "https://ghproxy.net/{url}",
    "{url}",
)


def _mirror_list() -> tuple[str, ...]:
    """实际使用的镜像表。

    `ZP_CORE_MIRRORS=https://my.mirror/{url},…` 可以整体替换 (自建反代 / 内网缓存的人
    需要这个: 他们的镜像比任何公共前缀都可靠)。留空就用默认那一串。
    """
    raw = os.environ.get("ZP_CORE_MIRRORS", "").strip()
    if not raw:
        return DEFAULT_MIRRORS
    custom = tuple(item.strip() for item in raw.split(",") if item.strip())
    return custom or DEFAULT_MIRRORS


MIRRORS = _mirror_list()

UA = "zeroproxy-panel"
#: 低于这个大小一律视为下载失败 (一个正常的 mihomo 压缩包 ≈ 20 MB)。
#: 可用 ZP_CORE_MIN_BYTES 调低 —— 自动化演练里用一个几 KB 的假内核就能把
#: "下载 → 解压 → 可执行校验"这条路整条跑通, 不必真的下 20 MB。
MIN_BYTES = int(os.environ.get("ZP_CORE_MIN_BYTES", str(4 << 20)))

#: 单个镜像的连接/读取超时。注意 urllib 的 timeout 是"每次 socket 操作"的上限,
#: 不是整段传输的上限 —— 一个每秒滴一点数据的镜像可以让它永远不超时 (真机现场:
#: 安装命令停在"下载代理内核"上不动, 就是这种慢速黑洞)。
CORE_SOURCE_TIMEOUT = int(os.environ.get("ZP_CORE_SOURCE_TIMEOUT", "60"))

#: 一次取内核的**总**时间上限。超过就如实报错, 让路由器端拿到一句能读懂的话
#: (以前这里没有上限: 5 个镜像 × 180 秒, 用户看到的就是"卡住", 不是"失败")。
#: 240 秒是量出来的: 一条 170 KB/s 的镜像线路取 20 MB 要 115 秒, 150 秒会把它
#: 卡在门口; 而路由器端等的是 CORE_WAIT=360 秒, 比这里长, 所以它总能等到一个
#: 明确的结果 (ready 或 error), 不会两边一起超时。
CORE_DEADLINE = int(os.environ.get("ZP_CORE_DEADLINE", "240"))

#: 官方直连那一档的最长等待 (秒)。黑洞掉的直连不值得花掉整个预算。
CORE_DIRECT_BUDGET = int(os.environ.get("ZP_CORE_DIRECT_BUDGET", "25"))

#: 速率闸门: 观察期过后, 若某个镜像的实测速率低于这个值, 就认定它**按当前速率
#: 跑不完这 20 MB**, 立刻换下一个镜像。
#: 为什么需要它: 一个"能连上、但在国内线路上只有 30 KB/s"的镜像会把整个 CORE_DEADLINE
#: 吃掉却什么也拿不到 (20 MB / 30 KB/s = 11 分钟), 而排在后面的镜像可能一秒就通了。
#: 有 Content-Length 时用"剩余字节 / 剩余时间"精确判断, 没有时才用这个兜底值。
CORE_MIN_RATE_KB = int(os.environ.get("ZP_CORE_MIN_RATE_KB", "32"))

#: 速率闸门的观察期 (秒): 前几秒的抖动不做数。
CORE_RATE_GRACE = int(os.environ.get("ZP_CORE_RATE_GRACE", "8"))

#: 路由器端的取内核顺序: panel (默认, 面板直传) / mirror (先直连镜像) / auto (同 panel)。
#: 面板自建镜像的人可以用它做 A/B: 哪条快就固定哪条。
ROUTER_SOURCE = os.environ.get("ZP_ROUTER_SOURCE", "panel").strip().lower()


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


# ---------------------------------------------------------------- 取内核 (带总时限)
# 真机事故 (GL-MT3600BE / OpenWrt 25.12, 2026-10): 安装命令停在 "下载代理内核" 上,
# 十分钟后被路由器自己的 curl -m 600 掐断, 用户看到的既不是成功也不是失败, 而是
# "卡住"。面板侧的原因在这里: 原本**没有总时限** —— 5 个镜像各 180 秒, 而且
# urllib 的 timeout 只管单次 socket 操作, 一个"能连上、每秒滴几 KB"的镜像可以让它
# 拖到天荒地老。
#
# 现在三道闸门一起上:
#   1. 每个镜像有自己的连接/读取超时;
#   2. 官方直连只给 CORE_DIRECT_BUDGET 秒 (被黑洞时 connect 会一直挂着, 不能让它
#      吃掉整个预算 —— GEO 那边早就踩过: "直连排第一会白吃掉整个时间预算");
#   3. 读循环里检查总时限 CORE_DEADLINE, 到点就中断并如实报错。
#
# 另外, 路由器端**不再同步等**这个下载 (见 ensure_core_async 与 routes 的 503)。

#: 后台预取的状态: arch → {state, detail, bytes, started, done, error}
CORE_LOCK = threading.Lock()
CORE_STATE: dict[str, dict] = {}
#: 一次失败之后的冷静时间: 路由器每几秒问一次, 不能让面板一直捶上游。
CORE_RETRY_AFTER = int(os.environ.get("ZP_CORE_RETRY_AFTER", "20"))


#: "官方直连"那一档的写法 —— 只有它需要短预算 (被墙时 connect 会一直挂着)。
DIRECT_TEMPLATE = "{url}"


def _budget_for(template: str, remaining: float, timeout: int) -> int:
    """这一个镜像最多能花多少秒。"""
    cap = min(timeout, CORE_DIRECT_BUDGET) if template == DIRECT_TEMPLATE else timeout
    return max(5, int(min(cap, remaining)))


def core_state(arch: str) -> dict:
    """这一档内核现在的状态。面板 UI 与路由器端轮询都读它。"""
    if core_ready(arch):
        try:
            size = os.path.getsize(core_file(arch))
        except OSError:
            size = 0
        return {
            "arch": arch,
            "state": "ready",
            "detail": "面板已缓存",
            "bytes": size,
            "error": "",
            "updated": int((CORE_STATE.get(arch) or {}).get("done") or 0),
        }
    entry = CORE_STATE.get(arch) or {}
    return {
        "arch": arch,
        "state": entry.get("state") or "missing",
        "detail": entry.get("detail") or "",
        "bytes": int(entry.get("bytes") or 0),
        "error": entry.get("error") or "",
        "updated": int(entry.get("done") or entry.get("started") or 0),
    }


def core_states() -> list[dict]:
    """全部架构的状态 (面板 UI 用)。"""
    out = []
    for arch in ARCHES:
        st = core_state(arch)
        st["label"] = ARCH_LABEL.get(arch, arch)
        out.append(st)
    return out


#: 缓存文件的 sha256 记忆 (path, mtime, size) → 摘要。20 MB 每次请求重算太浪费。
_SHA_CACHE: dict[tuple, str] = {}


def core_sha256(path: str) -> str:
    """缓存内核的 sha256。路由器端拿到直连镜像时会用它校验 —— 镜像再多一层也不怕。"""
    try:
        st = os.stat(path)
    except OSError:
        return ""
    key = (path, int(st.st_mtime), st.st_size)
    hit = _SHA_CACHE.get(key)
    if hit:
        return hit
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
    except OSError:
        return ""
    value = digest.hexdigest()
    _SHA_CACHE.clear()
    _SHA_CACHE[key] = value
    return value


def mirror_urls(arch: str) -> list[str]:
    """这一档内核的全部镜像地址 (完整 URL, 路由器端直接拿去用)。

    下载地址只有这一份实现: 路由器不需要自己拼模板, 换镜像表时两边不会走偏。
    """
    url = release_url(arch)
    return [template.format(url=url) for template in MIRRORS]


def core_pending_text(arch: str) -> str:
    """给路由器端看的一句人话 (它会原样打印出来)。

    路由器端需要知道的是"现在该等还是该重跑", 不是一句 HTTP 状态码。
    """
    st = core_state(arch)
    if st["state"] == "downloading":
        got = st["bytes"] // (1 << 20)
        extra = f", 已取 {got} MB" if got else ""
        return (
            f"面板正在准备 {arch} 内核 (首次安装时面板要先从上游取约 20 MB{extra})。"
            f"这不是错误 —— 稍后会自动重试。"
        )
    if st["state"] == "error":
        return f"面板取内核失败: {st['error'] or st['detail']}"
    return "面板正在准备内核, 稍后会自动重试。"


def ensure_core_async(arch: str) -> dict:
    """确保有一份内核正在下载, **不阻塞**调用方。返回当前状态。

    为什么不在请求里同步下: 这是一段几十秒到两分钟的活, 而路由器那边正在等一个
    HTTP 响应。把请求挂住的结果就是用户看到的"装到一半卡住"; 改成"立刻回一句能
    读懂的话 + 后台去取", 同一段时间里路由器还能打印真实进度。
    """
    if arch not in ARCHES:
        return {"arch": arch, "state": "unknown", "detail": f"不支持的架构: {arch}",
                "bytes": 0, "error": f"不支持的架构: {arch}", "updated": 0}
    if core_ready(arch):
        return core_state(arch)
    with CORE_LOCK:
        entry = CORE_STATE.setdefault(arch, {})
        if entry.get("state") == "downloading":
            return core_state(arch)
        failed_at = int(entry.get("done") or 0)
        if entry.get("state") == "error" and time.time() - failed_at < CORE_RETRY_AFTER:
            return core_state(arch)
        entry.update({
            "state": "downloading",
            "detail": "正在从上游下载",
            "bytes": 0,
            "error": "",
            "started": int(time.time()),
            "done": 0,
        })
    threading.Thread(target=_prefetch, args=(arch,), daemon=True, name=f"zp-core-{arch}").start()
    return core_state(arch)


def _prefetch(arch: str) -> None:
    def note(size: int) -> None:
        with CORE_LOCK:
            CORE_STATE.setdefault(arch, {})["bytes"] = size

    try:
        ok, detail, _path = fetch_core(arch, progress=note)
    except Exception as exc:  # 后台线程不能死得无声无息: 那会让状态永远停在"下载中"
        ok, detail = False, f"取内核时出错了: {exc}"
    with CORE_LOCK:
        entry = CORE_STATE.setdefault(arch, {})
        entry["state"] = "ready" if ok else "error"
        entry["detail"] = detail
        entry["error"] = "" if ok else detail
        entry["done"] = int(time.time())


def fetch_core(
    arch: str,
    *,
    timeout: int | None = None,
    deadline: float | None = None,
    progress=None,
) -> tuple[bool, str, str]:
    """按镜像顺序下载内核。返回 (ok, 说明, 本地路径)。

    已缓存就直接返回 —— 路由器重装/多台设备复用时不再重复下载。
    `deadline` 是这一轮的绝对时间上限 (time.time() 口径), 到点就放弃剩余镜像。
    """
    if arch not in ARCHES:
        return False, f"不支持的架构: {arch}", ""
    dst = core_file(arch)
    if core_ready(arch):
        return True, "已缓存", dst

    timeout = timeout or CORE_SOURCE_TIMEOUT
    if deadline is None:
        deadline = time.time() + CORE_DEADLINE
    os.makedirs(core_dir(), exist_ok=True)
    tmp = dst + ".part"
    url = release_url(arch)
    errors: list[str] = []
    for template in MIRRORS:
        left = deadline - time.time()
        if left <= 2:
            errors.append(f"总时间超限 ({CORE_DEADLINE}s), 放弃剩余镜像")
            break
        source = template.format(url=url)
        try:
            request = urllib.request.Request(source, headers={"User-Agent": UA})
            with urllib.request.urlopen(request, timeout=_budget_for(template, left, timeout)) as resp:
                status = getattr(resp, "status", 200)
                if status is not None and status != 200:
                    errors.append(f"{source} HTTP {status}")
                    continue
                size = 0
                started = time.time()
                try:
                    total = int(resp.headers.get("content-length") or 0)
                except (TypeError, ValueError):
                    total = 0
                next_note = 1 << 20          # 每 1 MB 回一次进度
                with open(tmp, "wb") as fh:
                    while True:
                        # 关键的一行: urllib 的 timeout 管不住"一直有数据但极慢"的
                        # 连接, 只有墙钟管得住。
                        if time.time() > deadline:
                            raise TimeoutError(f"总时间超限 ({CORE_DEADLINE}s)")
                        chunk = resp.read(1 << 18)
                        if not chunk:
                            break
                        fh.write(chunk)
                        size += len(chunk)
                        if size >= next_note:
                            next_note = size + (1 << 20)
                            if progress is not None:
                                progress(size)
                            # 速率闸门: 慢到"按当前速率跑不完"就换下一个镜像。20 MB 的
                            # 文件上, 这不只是优化 —— 一个 30 KB/s 的镜像能把整个预算
                            # 吃掉却什么都给不了, 而排在后面的镜像可能一秒就通了。
                            elapsed = time.time() - started
                            if elapsed >= CORE_RATE_GRACE:
                                rate = size / elapsed
                                left_now = deadline - time.time()
                                if total > size and left_now > 0:
                                    needed = (total - size) / left_now
                                else:
                                    needed = rate
                                if rate < needed or rate < CORE_MIN_RATE_KB * 1024:
                                    raise TimeoutError(
                                        f"太慢: {rate / 1024:.0f} KB/s (换下一个镜像)"
                                    )
            if size < MIN_BYTES:
                errors.append(f"{source} 体积异常 ({size} 字节)")
                continue
            os.replace(tmp, dst)
            if progress is not None:
                progress(size)
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

#: 分流数据库的镜像顺序: 与内核同一套思路 —— 运营方自建的镜像第一, 公共反代随后,
#: GitHub 直连最后。直连在受限出口上是"卡满超时再失败", 排第一会白吃掉整个预算
#: (真机网络就是这样: 直连与 ghfast 都超时, 只有 gh-proxy 通)。
GEO_MIRRORS = (
    "https://github.i3.pub/{url}",
    "https://gh-proxy.com/{url}",
    "https://hk.gh-proxy.com/{url}",
    "https://ghfast.top/{url}",
    "https://ghproxy.net/{url}",
    "{url}",
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
                    started = time.time()
                    with open(tmp, "wb") as fh:
                        while True:
                            if time.time() > deadline:
                                raise TimeoutError(f"总时间超限 ({GEO_DEADLINE}s)")
                            chunk = resp.read(1 << 18)
                            if not chunk:
                                break
                            fh.write(chunk)
                            size += len(chunk)
                            # 与内核那条一样: 慢到跑不完就换下一个镜像, 别把预算全吃掉
                            # (4 MB 在 45 KB/s 上要 90 秒 —— 排在后面的镜像可能几秒就完)。
                            # 判据用"还要多快才来得及", 而不是一个拍出来的固定值:
                            # 慢但能在时限内跑完的镜像不该被踢掉。
                            elapsed = time.time() - started
                            if elapsed >= CORE_RATE_GRACE and size >= (1 << 18):
                                rate = size / elapsed
                                left_now = deadline - time.time()
                                needed = rate if left_now <= 0 else (minimum - size) / left_now
                                if rate < needed:
                                    raise TimeoutError(
                                        f"太慢: {rate / 1024:.0f} KB/s (换下一个镜像)"
                                    )
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
        # 每一档内核现在的状态 (missing / downloading / ready / error):
        # 面板上那张卡片要能回答"现在发这条安装命令, 会不会卡在下载内核上"。
        "cores": core_states(),
        "geo": cached_geo(),
        "geo_names": list(GEO_FILES),
        "cached_at": int(time.time()),
    }
