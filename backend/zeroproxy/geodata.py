"""GeoIP / GeoSite 数据管理与基于它的分流防护。

为什么需要它 (上游实测结论, 见 docs/RESEARCH.md 第 3 节):
  Xray 在**解析配置阶段**就要把 geoip / geosite 规则编译成匹配器, 数据文件
  (geoip.dat / geosite.dat) 缺失时不是"跳过该规则", 而是**整份配置构建失败**:

      Failed to start: failed to build routing configuration
      > invalid field rule > failed to load GeoIP: private
      > failed to open file: geoip.dat

  也就是说, 一条 geo 规则用错就能让 Xray 完全起不来。因此本项目把数据文件的
  "存在性" 做成硬前置: 只有开关打开**且**数据齐备 (usable) 才下发 geo 规则,
  见 xray_config.build_xray_config。

数据来源: Loyalsoldier/v2ray-rules-dat (每日构建, 社区事实标准)。
GitHub Release 资产在国内网络常不可达, 因此按"多镜像顺序回退"下载, 并做
体积校验 + 用真实 xray -test 校验数据可被加载, 全部通过才原子替换。
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

from .config import GEODATA_TTL, paths

#: 同一时间只允许一个下载任务 (几十 MB 的下载 + 校验, 不做并发)。
#: 面板的「下载 / 更新」按钮与后台自动更新线程共用这一把锁 —— 否则两条路径
#: 会同时往 geo 目录里写, 而它们各自持有的 state 快照又是旧的那一份。
UPDATE_LOCK = threading.Lock()

#: 每个数据文件的候选下载源 (按顺序回退)。
#: jsdelivr 的 @release 指向仓库的 release 分支, 内容与 Release 资产一致。
#: 同一个 jsdelivr 挂在不同 CDN 后面 (Fastly / Gcore / Cloudflare), 走的是完全不同的
#: 网络路径 —— 某一条被墙 / 被限速时另外几条往往还通, 所以按 CDN 边缘逐个回退。
SOURCES: dict[str, list[str]] = {
    "geoip.dat": [
        "https://fastly.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat",
        "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat",
        "https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat",
        "https://testingcf.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat",
        "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
    ],
    "geosite.dat": [
        "https://fastly.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat",
        "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat",
        "https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat",
        "https://testingcf.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat",
        "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
    ],
}

#: 体积下限 — 低于此值说明下载到了错误页面 (404 HTML / 镜像限流提示)
MIN_BYTES = {"geoip.dat": 1_000_000, "geosite.dat": 1_000_000}

#: 单个下载源的超时 (连接 + 单次读取)。以前是 120s —— 三个源依次超时、两个文件
#: 就是最坏 ~12 分钟, 面板上只有一句"下载中…", 用户看到的就是"点了没反应"。
SOURCE_TIMEOUT = 30

#: 一次更新的总时间上限: 下载加速到国内线路可能很慢, 但不能无限等。
#: 超时后放弃剩余源并如实报错 (现有数据保持不变)。
UPDATE_DEADLINE = 180

#: 校验用的最小配置片段所引用的规则 (必须同时覆盖两个数据文件)
PROBE_RULES = [
    {"type": "field", "outboundTag": "block", "ip": ["geoip:private"]},
    {"type": "field", "outboundTag": "block", "domain": ["geosite:category-ads-all"]},
]

#: 上游校验值 (.sha256sum) 的取用超时 —— 只有几十字节, 但它决定"要不要下 28 MB"。
SUMS_TIMEOUT = 6

#: 一次"核对上游"的总时间上限 (两个校验文件 + 构建信息), 防止镜像卡住拖死请求。
CHECK_DEADLINE = 20

#: 取数据集构建信息 (发布时间 / 提交 sha) 的超时。
META_TIMEOUT = 6

#: 数据集的构建信息来源: 仓库 release 分支的最新提交 —— 它自带日期和 sha,
#: 是"这份数据是哪天构建的"唯一权威答案 (dat 文件本身不带任何版本字符串)。
#: gh-proxy 是国内可用的 GitHub 反代, 与 update.py 用的是同一套思路。
META_SOURCES = (
    "https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/commits/release",
    "https://gh-proxy.com/https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/commits/release",
)

#: sha256sum 文件里那一串 64 位十六进制
_SHA256_RE = re.compile(r"\b([0-9a-fA-F]{64})\b")

UA = "ZeroProxy/2.0 (geodata)"


def geo_dir() -> str:
    return paths()["geo_dir"]


def file_path(name: str) -> str:
    return os.path.join(geo_dir(), name)


def sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def present() -> bool:
    """两个数据文件是否都在 (且体积合理)。"""
    for name, minimum in MIN_BYTES.items():
        try:
            if os.path.getsize(file_path(name)) < minimum:
                return False
        except OSError:
            return False
    return True


def usable(state: dict) -> bool:
    """是否允许下发 geo 分流规则 — 开关打开**且**数据齐备。"""
    return bool(state.get("geodata", {}).get("enabled")) and present()


def wants_update(state: dict, now: int | None = None) -> bool:
    """数据是否缺失或已超过 TTL (自动更新线程据此判断)。"""
    geo = state.get("geodata", {})
    # 用户显式关掉分流后不再自动下载 (约 28 MB), 尊重其选择
    if geo.get("user_set") and not geo.get("enabled"):
        return False
    if not present():
        return True
    # 用"最后一次和上游核对"而不是"最后一次写文件": 内容没变时我们不会重写文件,
    # 若只看 updated_at, 数据明明核对过也会被反复判为过期, 每 6 小时白问一次上游。
    checked = max(int(geo.get("updated_at", 0) or 0), int(geo.get("checked_at", 0) or 0))
    return (now or int(time.time())) - checked > GEODATA_TTL


def status(state: dict) -> dict:
    """给面板 / 诊断用的只读快照。"""
    recorded = state.get("geodata", {}).get("files", {}) or {}
    expected = state.get("geodata", {}).get("expected", {}) or {}
    files: dict[str, dict] = {}
    for name in SOURCES:
        try:
            stat = os.stat(file_path(name))
            files[name] = {
                "exists": True,
                "size": stat.st_size,
                "mtime": int(stat.st_mtime),
                "sha256": str(recorded.get(name, {}).get("sha256", ""))[:12],
                # 上游当前的 sha256 前缀 (仅在核对过之后才有) —— 面板拿它做对比
                "expected": str(expected.get(name, ""))[:12],
            }
        except OSError:
            files[name] = {"exists": False, "size": 0, "mtime": 0, "sha256": "", "expected": ""}
    geo = state.get("geodata", {})
    updated = int(geo.get("updated_at", 0) or 0)
    dataset = geo.get("dataset") or {}
    return {
        "enabled": bool(geo.get("enabled")),
        "block_private": bool(geo.get("block_private", True)),
        "block_ads": bool(geo.get("block_ads", True)),
        "active": usable(state),
        "dir": geo_dir(),
        "updated_at": updated,
        "age_days": int((time.time() - updated) // 86400) if updated else -1,
        "source": geo.get("source", ""),
        # ---- 数据版本 (用户要的"到底更新成功没有", 见本文件"数据版本"一节) ----
        #: 上游数据集的构建日期 / 提交短 sha, 例如 2026-09-29 / ef3bc79
        "dataset_build": str(dataset.get("build", "") or ""),
        "dataset_sha": str(dataset.get("sha", "") or ""),
        #: 最后一次和上游核对校验值的时间
        "checked_at": int(geo.get("checked_at", 0) or 0),
        #: True 与上游一致 / False 上游有新内容 / None 还没核对过或问不到
        "up_to_date": geo.get("up_to_date"),
        # 上次尝试的结果 —— 卡片上要能说出"为什么没数据", 不能只显示"数据未下载"
        "last_attempt": int(geo.get("last_attempt", 0) or 0),
        "last_error": str(geo.get("last_error", "") or ""),
        "files": files,
    }


def merge_result(target: dict, source: dict, ok: bool) -> None:
    """把一次更新的结果并回**最新**的 state。

    下载跑在配置锁外 (28 MB, 不能把整个面板卡住), 期间用户可能改了开关 —-
    那些字段属于用户操作, 不能被这份旧快照覆盖, 所以只并回"这次下载真的写了"
    的字段。

    并发安全: 如果 `target` 是在下载**之后**新加载的快照 (version 更高), 但
    `source` 是下载**之前**持有的旧快照, 则旧快照的 `updated_at` 可能比
    `target` 里已经存在的值更早 — 此时跳过并回, 避免"旧数据覆盖新数据"。
    """
    geo = target.setdefault("geodata", {})
    src = source.get("geodata", {}) or {}
    safe_keys = (
        "files",
        "updated_at",
        "checked_at",
        "up_to_date",
        "expected",
        "dataset",
        "source",
        "last_attempt",
        "last_error",
    )
    #: 这两个是"只许前进"的时间戳: 下载/核对是在配置锁外跑的, 期间用户可能手动
    #: 又更新过一次 —— 旧快照不许把新的时间戳覆盖回去。
    monotonic = ("updated_at", "checked_at")
    for key in safe_keys:
        if key not in src:
            continue
        if key in monotonic:
            target_ts = int(geo.get(key) or 0)
            source_ts = int(src.get(key) or 0)
            if target_ts > source_ts:
                continue
        geo[key] = src[key]
    if ok and not geo.get("user_set"):
        geo["enabled"] = True


def _validate(geo_dir_path: str) -> tuple[bool, str]:
    """用真实 xray 校验数据可被加载。

    xray -test 在配置构建阶段就会读 geo 数据, 因此这一步能真正验证 dat 文件
    是否可用 (而不是只看体积)。未安装 xray 时跳过 (返回 True)。
    """
    from . import services  # 延迟导入, 避免模块级循环依赖

    binary = services.bin_path("xray")
    if not binary:
        return True, "跳过校验 (未安装 xray)"

    cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "api",
                "listen": "127.0.0.1",
                "port": 1,
                "protocol": "dokodemo-door",
                "settings": {"address": "127.0.0.1"},
            }
        ],
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
        ],
        "routing": {"rules": PROBE_RULES},
    }
    with tempfile.TemporaryDirectory(prefix="zp-geo-check-") as tmp:
        cfg_path = os.path.join(tmp, "probe.json")
        with open(cfg_path, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh)
        ok, out = services.run(
            [binary, "-test", "-c", cfg_path],
            timeout=60,
            env={"XRAY_LOCATION_ASSET": geo_dir_path},
        )
    tail = " ".join(out.split())[:160]
    return ok, ("数据可被 xray 加载" if ok else f"xray 拒绝加载该数据: {tail}")


def _fetch(
    name: str,
    dst: str,
    timeout: int,
    *,
    deadline: float | None = None,
    on_source=None,
    on_bytes=None,
) -> tuple[bool, str, int, str]:
    """按候选源顺序下载到 dst。返回 (ok, 说明, 字节数, 生效源)。

    `on_source(index, count)` / `on_bytes(n)` 是给面板画进度用的回调: 一个
    28 MB 的下载在慢线路上要几十秒, 没有进度用户只会看到"卡住了"。
    """
    errors: list[str] = []
    count = len(SOURCES[name])
    for index, url in enumerate(SOURCES[name], 1):
        if on_source is not None:
            on_source(index, count)
        remaining = None if deadline is None else deadline - time.time()
        if remaining is not None and remaining <= 1:
            errors.append("总时间超限")
            break
        budget = timeout if remaining is None else max(2, int(min(timeout, remaining)))
        try:
            request = urllib.request.Request(url, headers={"User-Agent": UA})
            size = 0
            next_tick = 1 << 20        # 每 1 MB 回报一次, 进度条才是真的在动
            with urllib.request.urlopen(request, timeout=budget) as resp:
                # file:// 等非 HTTP 源的 status 为 None (测试用), 视为成功
                status = getattr(resp, "status", 200)
                if status is not None and status != 200:
                    errors.append(f"{url} HTTP {status}")
                    continue
                with open(dst, "wb") as out:
                    while True:
                        chunk = resp.read(1 << 18)
                        if not chunk:
                            break
                        out.write(chunk)
                        size += len(chunk)
                        if on_bytes is not None and size >= next_tick:
                            on_bytes(size)
                            next_tick = size + (1 << 20)
            if size < MIN_BYTES[name]:
                errors.append(f"{url} 体积异常 ({size} 字节)")
                continue
            return True, f"{size} 字节", size, url
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            errors.append(f"{url} {exc}")
    return False, "; ".join(errors)[-300:], 0, ""


def _source_label(url: str) -> str:
    if "/gh/" in url:
        return f"jsdelivr:{url.split('/gh/')[-1].split('@')[0]}"
    if "/releases/" in url:
        return "github-release"
    return url.split("/")[2] if "//" in url else url


# ---------------------------------------------------------------- 数据版本
#
# 用户的原始问题: "GeoIP 数据到底更新成功没有?" —— geoip.dat / geosite.dat
# 里**没有任何版本字符串**, 光看文件只有体积和修改时间, 而一天一版的日常更新
# 在体积上完全看不出来。所以版本必须从上游取, 分两层:
#
#   1. 内容身份: 仓库随数据集一起发布的 `<文件>.sha256sum` (几十字节), 走的是
#      和数据本身**同一批镜像** —— 拿它和本地文件的 sha256 比对, 就能在不下载
#      28 MB 的前提下回答"我这份是不是上游当前那一份";
#   2. 人类可读版本: 仓库 release 分支最新提交的日期 + sha, 面板显示成
#      「数据集 2026-09-29 (ef3bc79)」, 用户一眼能看出数据是哪天的。


def _sum_urls(name: str) -> list[str]:
    """该文件校验值小文件的候选地址 (与 SOURCES 同序、同镜像)。"""
    return [f"{url}.sha256sum" for url in SOURCES[name]]


def fetch_expected(name: str, *, timeout: int = SUMS_TIMEOUT) -> tuple[bool, str, str]:
    """取上游该文件的 sha256。返回 (是否拿到, 哈希, 生效源)。

    拿到的是仓库自己发布的校验值, 不写 state、不碰数据文件 —— 怎么用由调用方决定。
    """
    for url in _sum_urls(name):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(request, timeout=timeout) as resp:
                status = getattr(resp, "status", 200)
                if status is not None and status != 200:
                    continue
                text = resp.read(4096).decode("utf-8", "replace")
        except (urllib.error.URLError, OSError, TimeoutError):
            continue
        match = _SHA256_RE.search(text)
        if match:
            return True, match.group(1).lower(), url
    return False, "", ""


def local_sha256(name: str) -> str:
    """本地数据文件的 sha256 (文件不在就返回空串)。"""
    try:
        return sha256(file_path(name))
    except OSError:
        return ""


def dataset_info(*, timeout: int = META_TIMEOUT) -> tuple[bool, dict]:
    """取数据集的构建信息: {"build": "2026-09-29", "sha": "ef3bc79"}。"""
    for url in META_SOURCES:
        try:
            request = urllib.request.Request(
                url, headers={"User-Agent": UA, "Accept": "application/vnd.github+json"}
            )
            with urllib.request.urlopen(request, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8", "replace"))
        except (urllib.error.URLError, OSError, TimeoutError, ValueError):
            continue
        sha = str(payload.get("sha") or "")
        date = str(((payload.get("commit") or {}).get("author") or {}).get("date") or "")
        if sha:
            return True, {"build": date[:10], "sha": sha[:7]}
    return False, {}


def check_remote(*, deadline: float | None = None) -> dict:
    """只下两个几十字节的校验值, 和本地文件比一次。不写 state, 不碰数据文件。

    返回的 `up_to_date` 是三态: True 一致 / False 上游有新内容 / None 问不到上游
    (镜像不可达)。None 必须和 False 分得开 —— "不知道"和"有新版"在面板上是
    完全不同的两句话。
    """
    started = time.time()
    if deadline is None:
        deadline = started + CHECK_DEADLINE
    report: dict = {"checked_at": int(started), "files": {}, "up_to_date": None, "error": ""}
    known: list[bool] = []
    for name in SOURCES:
        remaining = deadline - time.time()
        if remaining <= 1:
            break
        budget = max(2, int(min(SUMS_TIMEOUT, remaining)))
        ok, expected, _source = fetch_expected(name, timeout=budget)
        local = local_sha256(name)
        matched = bool(expected) and expected == local
        report["files"][name] = {"expected": expected, "local": local, "match": matched}
        if ok:
            known.append(matched)
    report["ok"] = bool(known) and len(known) == len(SOURCES)
    if report["ok"]:
        report["up_to_date"] = all(known)
    elif known:
        report["error"] = "部分数据文件的校验值不可用"
    else:
        report["error"] = "无法获取上游校验值 (镜像不可达)"
    return report


def record_check(state: dict, report: dict, meta: dict | None = None) -> None:
    """把一次核对的结果写进 state (纯本地操作, 由调用方负责 save_state)。"""
    geo = state.setdefault("geodata", {})
    geo["checked_at"] = int(report.get("checked_at") or time.time())
    geo["up_to_date"] = report.get("up_to_date")
    geo["expected"] = {
        name: str(entry.get("expected") or "")
        for name, entry in (report.get("files") or {}).items()
    }
    # 核对时刚刚算过每个本地文件的 sha256, 顺手把指纹记下来: 面板显示的内容标识
    # 因此永远来自**磁盘上现在的文件**, 而不是某次下载时的旧记录 (老版本装的数据
    # 甚至根本没有这条记录, 卡片上就只能显示空白)。
    files = geo.setdefault("files", {})
    for name, entry in (report.get("files") or {}).items():
        local = str(entry.get("local") or "")
        if not local:
            continue
        slot = files.setdefault(name, {})
        slot["sha256"] = local
        if not slot.get("size"):
            try:
                slot["size"] = os.path.getsize(file_path(name))
            except OSError:
                pass
    if meta:
        geo["dataset"] = meta


def atomic_install(src: str, dst: str) -> None:
    """把一个临时文件换到 dst 的位置 (同名覆盖, 不会留半个文件)。

    同盘时 `os.replace` 就是原子的 rename(2)。但**跨文件系统**时它直接报
    `OSError: [Errno 18] Invalid cross-device link` —— 这正是 v2.6.14 用户报的
    "更新失败: OSError: [Errno 18] ... '/tmp/zp-geo-dl-xxx/geoip.dat' ->
    '/opt/zeroproxy/geo/geoip.dat'": 那台机器的 /tmp 是另一套挂载 (tmpfs /
    容器 overlay), 于是每次下载都卡在最后一步 —— 下载明明成功了, 却一步都落不了地。

    现在 staging 目录就建在目标目录里 (见 `update`), 正常根本走不到这条分支;
    这里再兜一层: 跨盘时改成"先拷到同目录的临时名, 再 rename"。拷贝过程中 dst
    始终是旧文件, rename 之后才是新文件 —— 对读方 (Xray) 依然是原子的。
    """
    try:
        os.replace(src, dst)
        return
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise
    tmp = f"{dst}.zp-new-{os.getpid()}"
    try:
        shutil.copyfile(src, tmp)
        os.replace(tmp, dst)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def _prune_stale_staging(target: str, max_age: float = 3600.0) -> None:
    """清掉上一次被中断的下载留在 geo 目录里的 staging 目录。

    面板在下载途中被重启 (升级 / 崩溃 / 用户重启服务) 时, TemporaryDirectory 的
    清理不会执行, 一个 28 MB 的临时目录就留在那儿了。这里在下一次下载开始时顺手
    收掉 (UPDATE_LOCK 保证不会有别的下载正在用, 1 小时也远超 180s 的总超时)。
    """
    now = time.time()
    try:
        names = os.listdir(target)
    except OSError:
        return
    for name in names:
        if not name.startswith(".zp-geo-dl-"):
            continue
        path = os.path.join(target, name)
        try:
            if now - os.path.getmtime(path) > max_age:
                shutil.rmtree(path, ignore_errors=True)
        except OSError:
            continue


def update(
    state: dict,
    *,
    timeout: int = SOURCE_TIMEOUT,
    validate: bool = True,
    deadline: float | None = None,
    progress=None,
    force: bool = False,
) -> tuple[bool, str, dict]:
    """核对上游 → (有变化才) 下载两个数据文件并原子替换。

    先全部落到临时目录, 校验通过后才 rename 到位 —— 任一步失败都保持现有文件
    不变, 不会出现"半个数据集"导致 Xray 起不来。

    `progress(index, total, name)` 每进入一步回调一次 (面板据此画实时进度);
    `deadline` 是这次更新的绝对时间上限 (超时放弃剩余源, 而不是无限等下去)。
    结果会写进 `state["geodata"]` 的 `last_attempt` / `last_error` —— 失败原因
    要留在状态里, 面板才有东西可显示。

    为什么先核对: 数据集一天一版, 但**绝大多数日子里内容并没有变**。以前每 7 天
    无条件重下 28 MB, 用户得到的只有一句"已更新" —— 既费流量又印证不了什么。
    现在先取两个几十字节的校验值, 一致就直接返回 (force=True 可跳过这一步强制重下)。
    """
    target = geo_dir()
    os.makedirs(target, exist_ok=True)
    _prune_stale_staging(target)
    geo = state.setdefault("geodata", {})
    geo["last_attempt"] = int(time.time())
    geo["last_error"] = ""

    # ---- 第 0 步: 核对上游 (不下载数据本体) ----
    remote = {"files": {}, "up_to_date": None, "checked_at": int(time.time())}
    if not force:
        remote = check_remote(deadline=time.time() + CHECK_DEADLINE)
    expected = {name: str(e.get("expected") or "") for name, e in remote["files"].items()}
    geo["checked_at"] = int(remote["checked_at"])
    geo["up_to_date"] = remote.get("up_to_date")
    geo["expected"] = expected
    # 构建信息 (哪天构建的 / 哪个提交) 每次都顺手刷一次: 它只有几百字节, 而且
    # 用户看的就是它。拿不到就保留上次的值, 不能因为 GitHub 不通就把已有信息抹掉。
    info_ok, build_info = dataset_info()
    if info_ok:
        geo["dataset"] = build_info
    if not force and remote.get("up_to_date") and present():
        detail = "数据已是最新 (与上游校验值一致, 未重新下载)"
        if progress is not None:
            progress(1, 1, detail)
        return True, detail, status(state)

    if deadline is None:
        deadline = time.time() + UPDATE_DEADLINE

    names = list(SOURCES)
    total = len(names) + (1 if validate else 0)

    def step(index: int, name: str) -> None:
        if progress is not None:
            progress(index, total, name)

    def failed(detail: str) -> tuple[bool, str, dict]:
        geo["last_error"] = detail[:300]
        return False, detail, {}

    details: list[str] = []
    meta: dict[str, dict] = {}

    # staging 建在**目标目录里** (而不是 /tmp): 最后一步是把文件 rename 到位, 而
    # rename 不能跨文件系统。有些机器的 /tmp 是单独挂载 (tmpfs / 容器 overlay),
    # 从那里搬过来就是 Errno 18 (见 atomic_install 的说明)。
    with tempfile.TemporaryDirectory(prefix=".zp-geo-dl-", dir=target) as staging:
        for index, name in enumerate(names, 1):
            dst = os.path.join(staging, name)

            def announce(source_index: int, source_count: int, _name: str = name, _i: int = index) -> None:
                step(_i, f"下载 {_name} (源 {source_index}/{source_count})")

            def report(size: int, _name: str = name, _i: int = index) -> None:
                step(_i, f"下载 {_name} {size / 1048576:.1f} MB")

            announce(1, len(SOURCES[name]))
            ok, detail, size, source = _fetch(
                name,
                dst,
                timeout,
                deadline=deadline,
                on_source=announce,
                on_bytes=report,
            )
            if not ok:
                return failed(f"{name} 下载失败: {detail}")
            meta[name] = {"size": size, "sha256": sha256(dst), "source": source}
            details.append(f"{name} {size // 1024} KiB")

        if validate:
            step(total, "校验数据 (真实 xray -test)")
            ok, detail = _validate(staging)
            if not ok:
                return failed(detail)
            details.append(detail)

        for name in names:
            atomic_install(os.path.join(staging, name), file_path(name))

    geo["files"] = {name: {"size": m["size"], "sha256": m["sha256"]} for name, m in meta.items()}
    geo["updated_at"] = int(time.time())
    geo["source"] = _source_label(meta[list(meta)[0]]["source"]) if meta else ""
    # 下载完再对一次账: 镜像的 CDN 边缘可能还在吐上一版 (jsDelivr 对 @release 的
    # 缓存是 12 小时)。这不是失败, 但必须如实反映在"是否最新"上, 否则用户点完
    # 更新看到"已是最新", 其实拿到的还是旧数据 —— 正是要修掉的那种"说不清"。
    compared = [expected.get(name) for name in names if expected.get(name)]
    if compared:
        geo["up_to_date"] = all(expected[name] == meta[name]["sha256"] for name in names
                                if expected.get(name))
    else:
        geo["up_to_date"] = None     # 问不到上游校验值 → 不知道, 不是"有新版"
    # 首次下载自动启用分流; 用户手动关过 (user_set) 则尊重其选择
    if not geo.get("user_set"):
        geo["enabled"] = True
    summary = "; ".join(details)
    if geo.get("up_to_date") is False:
        summary += " (提示: 与上游校验值不一致, 镜像可能仍在吐缓存版本)"
    return True, summary, status(state)


def auto_tick(state: dict, *, validate: bool = False) -> tuple[bool, str]:
    """自动更新线程的一次 tick: 只在数据过期时下载, 且只在内容变化时报需要重启。"""
    if not wants_update(state):
        return False, "数据仍在有效期内"
    before = {}
    for name in SOURCES:
        try:
            before[name] = sha256(file_path(name))
        except OSError:
            before[name] = ""
    ok, detail, _ = update(state, validate=validate)
    if not ok:
        return False, detail
    after = {name: sha256(file_path(name)) for name in SOURCES}
    if after == before:
        return False, "数据无变化"
    return True, "数据已更新"


# ---------------------------------------------------------------- 启动前自愈

def _xray_test(cfg_path: str) -> tuple[bool | None, str]:
    """用真实 xray 自检磁盘上的配置。返回 (是否通过, 说明)。

    二进制不可用时返回 (None, ...) —— 这时不做任何自作主张的重写。
    """
    from . import services

    binary = services.bin_path("xray")
    if not binary:
        return None, "xray 二进制不可用"
    ok, out = services.run(
        [binary, "-test", "-c", cfg_path], timeout=60, env={"XRAY_LOCATION_ASSET": geo_dir()}
    )
    return ok, (out.strip().splitlines() or [""])[-1][:160]


def guard() -> tuple[bool, str]:
    """启动前自愈: 保证磁盘上的 Xray 配置不会因为缺 geo 数据而起不来。

    为什么需要它: 面板每次重新生成配置时都会检查 `usable()`, 因此**面板路径**
    是安全的; 但磁盘上已经写好的配置可能在之后失去数据文件 —— 例如磁盘清理、
    手动删除、恢复备份到新机器 —— 此时 `systemctl restart xray` 或重启机器会
    让 Xray 直接停止服务 (配置构建阶段就会失败, 不是运行期降级)。

    由 systemd 的 `ExecStartPre` 调用 (xray.service), 每次启动前跑一遍:
    1. 配置里有 geo 规则但数据文件不在 → 直接重新生成 (usable() 为假时自动
       不下发 geo 规则);
    2. 否则用真实 `xray -test` 自检 —— 证书文件丢失等"生成后文件消失"的情况
       同样会让 Xray 起不来, 自检不过就按当前状态重新生成一次。

    无论哪种路径, 都保证核心能起来 (先可用, 再追求分流完整)。
    """
    from . import xray_config
    from .config import load_state

    cfg_path = paths()["xray_config"]
    if not os.path.exists(cfg_path):
        return False, "无配置文件, 跳过"
    try:
        with open(cfg_path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        return False, f"读取配置失败: {exc}"

    used_geo = "geoip:" in text or "geosite:" in text
    reasons: list[str] = []
    if used_geo and not present():
        reasons.append("geo 数据文件缺失")
    else:
        ok, detail = _xray_test(cfg_path)
        if ok is True:
            return False, "配置自检通过, 无需修复"
        if ok is None:
            return False, f"跳过自检 ({detail})"
        reasons.append(f"配置自检未通过 ({detail})")

    # 还没走完初始化时磁盘上只有 install.sh 的占位配置, 不在这里擅自生成
    if not load_state().get("configured"):
        return False, "面板尚未初始化, 跳过修复"

    try:
        xray_config.write_xray_config(load_state())
    except Exception as exc:  # 自愈失败不能让 systemd 卡住 (ExecStartPre 前缀 '-')
        return False, f"重新生成配置失败: {exc}"

    with open(cfg_path, "r", encoding="utf-8") as fh:
        after = fh.read()
    stripped = "geoip:" not in after and "geosite:" not in after
    again, detail = _xray_test(cfg_path)
    verdict = {True: "重新自检通过", False: f"重新自检仍未通过 ({detail})", None: "已跳过重新自检"}[again]
    return True, (
        f"{'; '.join(reasons)} → 已按当前状态重新生成配置"
        f"{' (已移除 geo 规则)' if stripped else ''}; {verdict}"
    )


def _main(argv: list[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else "guard"
    if cmd == "guard":
        _fixed, detail = guard()
        print(f"[zeroproxy-geodata] {detail}")
        return 0
    if cmd == "check":
        # 服务器上肉眼核对数据版本: 本地 / 上游校验值比对 + 数据集构建日期与提交
        report = check_remote()
        ok_meta, meta = dataset_info()
        _persist_check(report, meta if ok_meta else None)
        if ok_meta:
            print(f"[zeroproxy-geodata] 数据集: {meta.get('build', '')} ({meta.get('sha', '')})")
        else:
            print("[zeroproxy-geodata] 数据集构建信息不可用 (GitHub API 不可达)")
        for name, entry in report["files"].items():
            verdict = "未知"
            if entry["expected"]:
                verdict = "一致" if entry["match"] else "不一致"
            print(
                f"[zeroproxy-geodata] {name}: 本地 {entry['local'][:12] or '(缺失)'}"
                f" / 上游 {entry['expected'][:12] or '(不可用)'} → {verdict}"
            )
        if report["up_to_date"] is None:
            print(f"[zeroproxy-geodata] 结论: 无法判断 ({report['error']})")
            return 2
        print("[zeroproxy-geodata] 结论: 已是最新" if report["up_to_date"]
              else "[zeroproxy-geodata] 结论: 上游有新版本, 执行 update 即可")
        return 0
    if cmd == "update":
        from .config import load_state, locked, save_state

        state = load_state()
        ok, detail, _status = update(state, force="--force" in argv)
        # 命令行跑完也要落盘 —— 面板读的是 state.json。以前这里只在内存里改,
        # 命令行升级完面板上什么变化都看不到 (失败原因同样会消失)。
        with locked():
            fresh = load_state()
            merge_result(fresh, state, ok)
            save_state(fresh)
        print(f"[zeroproxy-geodata] {'OK' if ok else 'FAIL'}: {detail}")
        return 0 if ok else 1
    print("用法: python -m zeroproxy.geodata [guard|check|update [--force]]", file=sys.stderr)
    return 2


def _persist_check(report: dict, meta: dict | None) -> None:
    """把一次命令行核对的结果落进 state, 让面板卡片跟着变。

    面板目录不存在时 (纯 CLI 环境) 静默跳过 —— 核对结果已经打到 stdout 了。
    """
    try:
        from .config import load_state, locked, save_state

        with locked():
            state = load_state()
            record_check(state, report, meta)
            save_state(state)
    except Exception:  # noqa: BLE001 — 落不了盘不该让一次成功的核对变成失败
        pass


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
