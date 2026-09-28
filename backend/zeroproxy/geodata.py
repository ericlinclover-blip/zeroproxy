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

import hashlib
import json
import os
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
    updated = int(geo.get("updated_at", 0) or 0)
    return (now or int(time.time())) - updated > GEODATA_TTL


def status(state: dict) -> dict:
    """给面板 / 诊断用的只读快照。"""
    recorded = state.get("geodata", {}).get("files", {}) or {}
    files: dict[str, dict] = {}
    for name in SOURCES:
        try:
            stat = os.stat(file_path(name))
            files[name] = {
                "exists": True,
                "size": stat.st_size,
                "mtime": int(stat.st_mtime),
                "sha256": str(recorded.get(name, {}).get("sha256", ""))[:16],
            }
        except OSError:
            files[name] = {"exists": False, "size": 0, "mtime": 0, "sha256": ""}
    geo = state.get("geodata", {})
    updated = int(geo.get("updated_at", 0) or 0)
    return {
        "enabled": bool(geo.get("enabled")),
        "block_private": bool(geo.get("block_private", True)),
        "block_ads": bool(geo.get("block_ads", True)),
        "active": usable(state),
        "dir": geo_dir(),
        "updated_at": updated,
        "age_days": int((time.time() - updated) // 86400) if updated else -1,
        "source": geo.get("source", ""),
        # 上次尝试的结果 —— 卡片上要能说出"为什么没数据", 不能只显示"数据未下载"
        "last_attempt": int(geo.get("last_attempt", 0) or 0),
        "last_error": str(geo.get("last_error", "") or ""),
        "files": files,
    }


def merge_result(target: dict, source: dict, ok: bool) -> None:
    """把一次更新的结果并回**最新**的 state。

    下载跑在配置锁外 (28 MB, 不能把整个面板卡住), 期间用户可能改了开关 ——
    那些字段属于用户操作, 不能被这份旧快照覆盖, 所以只并回"这次下载真的写了"
    的字段。
    """
    geo = target.setdefault("geodata", {})
    src = source.get("geodata", {}) or {}
    for key in ("files", "updated_at", "source", "last_attempt", "last_error"):
        if key in src:
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


def update(
    state: dict,
    *,
    timeout: int = SOURCE_TIMEOUT,
    validate: bool = True,
    deadline: float | None = None,
    progress=None,
) -> tuple[bool, str, dict]:
    """下载两个数据文件并原子替换。

    先全部落到临时目录, 校验通过后才 rename 到位 —— 任一步失败都保持现有文件
    不变, 不会出现"半个数据集"导致 Xray 起不来。

    `progress(index, total, name)` 每进入一步回调一次 (面板据此画实时进度);
    `deadline` 是这次更新的绝对时间上限 (超时放弃剩余源, 而不是无限等下去)。
    结果会写进 `state["geodata"]` 的 `last_attempt` / `last_error` —— 失败原因
    要留在状态里, 面板才有东西可显示。
    """
    target = geo_dir()
    os.makedirs(target, exist_ok=True)
    geo = state.setdefault("geodata", {})
    geo["last_attempt"] = int(time.time())
    geo["last_error"] = ""
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

    with tempfile.TemporaryDirectory(prefix="zp-geo-dl-") as staging:
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
            os.replace(os.path.join(staging, name), file_path(name))

    geo["files"] = {name: {"size": m["size"], "sha256": m["sha256"]} for name, m in meta.items()}
    geo["updated_at"] = int(time.time())
    geo["source"] = _source_label(meta[list(meta)[0]]["source"]) if meta else ""
    # 首次下载自动启用分流; 用户手动关过 (user_set) 则尊重其选择
    if not geo.get("user_set"):
        geo["enabled"] = True
    return True, "; ".join(details), status(state)


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
    if cmd == "update":
        from .config import load_state

        state = load_state()
        ok, detail, _status = update(state)
        print(f"[zeroproxy-geodata] {'OK' if ok else 'FAIL'}: {detail}")
        return 0 if ok else 1
    print("用法: python -m zeroproxy.geodata [guard|update]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
