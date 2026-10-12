"""守门测试: 面板源码必须能被**受支持的最旧 Python** 解析。

为什么需要它: 开发机是 Python 3.14, 面板却要装到 Debian 12 (Python 3.11) / Ubuntu 22.04
(3.10) 这类机器上。语言版本一高一低, "本机全绿"就说明不了服务器上能跑 —— v2.11.42 里
`services.py` 有一行 f-string 在表达式里用了反斜杠, 那是 Python 3.12 才允许的写法
(PEP 701): 开发机上 326 项测试全绿, 而 Debian 12 上**整个模块 import 就 SyntaxError**,
面板进程起不来 (用户看到的现象只是"面板打不开")。

`ast.parse(feature_version=...)` 让当前解释器按目标版本的语法重新解析源码, 于是不需要
第二个解释器就能挡住这类回退。下限与 `install.sh` 里那道版本闸门是同一个数 —— 改一处
必须改另一处。
"""
from __future__ import annotations

import ast
from pathlib import Path

#: 面板支持的 Python 下限: Debian 12 = 3.11 / Debian 13 = 3.13 / Ubuntu 22.04 = 3.10 /
#: Ubuntu 24.04 = 3.12 —— 3.10 是这条线里最低的那个 (Debian 11 / Ubuntu 20.04 的 3.9 不支持)。
PY_FLOOR = (3, 10)

PACKAGE = Path(__file__).resolve().parents[1] / "zeroproxy"


def test_panel_sources_parse_on_supported_python_floor() -> None:
    """每个面板模块都要过得了 Python 3.10 的语法 (与 install.sh 的闸门同一条线)。"""
    files = sorted(p for p in PACKAGE.rglob("*.py") if "__pycache__" not in p.parts)
    assert files, f"没有找到面板源码: {PACKAGE}"
    offenders: list[str] = []
    for path in files:
        source = path.read_text(encoding="utf-8")
        try:
            ast.parse(source, filename=str(path), feature_version=PY_FLOOR)
        except SyntaxError as exc:
            offenders.append(f"{path.relative_to(PACKAGE.parent)}:{exc.lineno}: {exc.msg}")
    assert not offenders, (
        f"下面这些文件用了 Python {PY_FLOOR[0]}.{PY_FLOOR[1]} 不支持的语法 —— "
        "面板要装在 Debian 12 / Ubuntu 22.04 上, 那样会在 import 阶段就崩掉 "
        "(见 install.sh 里的版本闸门与 README 8.94):\n  " + "\n  ".join(offenders)
    )
