"""起一个"GeoIP 下载要 150 秒"的本地面板, 给 geo_slow_check.cjs 用。

为什么需要它: v2.6.14 修的头号问题就是"前端轮询 2 分钟就放弃" —— 而正常下载只要
2 秒, browser_check.cjs 打不到这条路径。这里把 geodata.update 包一层: 先睡
ZP_SLOW_SECS 秒 (分 20 次回报进度, 进度条才是真的在动), 再用**本地 file:// 假数据**
(1.5 MB, 满足 MIN_BYTES) 走一遍真正的 update 收尾 —— 不依赖外网, 状态 / 文件 /
卡片都和真实下载一致。

用法: ZP_HOME=<tmp> ZP_SLOW_SECS=150 python scripts/geo_slow_panel.py
"""
import os
import tempfile
import time

from zeroproxy import geodata

SLOW = float(os.environ.get("ZP_SLOW_SECS", "150"))

_src = tempfile.mkdtemp(prefix="zp-slow-src-")
for _name in ("geoip.dat", "geosite.dat"):
    with open(os.path.join(_src, _name), "wb") as _fh:
        _fh.write(b"\0" * (1500 * 1024))

geodata.MIN_BYTES = {name: 1000 for name in geodata.MIN_BYTES}
geodata.SOURCES = {name: [f"file://{_src}/{name}"] for name in ("geoip.dat", "geosite.dat")}

_orig = geodata.update


def slow_update(state, *, timeout=geodata.SOURCE_TIMEOUT, validate=True, deadline=None, progress=None):
    ticks = 20
    for i in range(ticks):
        time.sleep(SLOW / ticks)
        if progress is not None:
            progress(2 if i % 2 else 1, 3, "下载 geosite.dat" if i % 2 else "下载 geoip.dat")
    _orig(state, timeout=timeout, validate=False, deadline=deadline, progress=progress)
    return True, f"本地慢速桩 ({SLOW:.0f}s): 已就绪", geodata.status(state)


geodata.update = slow_update

if __name__ == "__main__":
    import uvicorn
    from zeroproxy import config, main

    uvicorn.run(
        main.app,
        host=config.PANEL_BIND_HOST,
        port=config.PANEL_BIND_PORT,
        log_level="warning",
    )
