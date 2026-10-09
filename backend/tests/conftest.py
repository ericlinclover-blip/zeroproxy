"""测试夹具: 每个用例一个独立的 $ZP_HOME, 全程 dry-run (不碰 systemd/nginx)。

跑法:
    cd backend && python -m pytest tests -q
可选: 指定真实 Xray 二进制, 让生成的配置被真实 `xray -test` 校验
    ZP_XRAY_BIN=/path/to/xray python -m pytest tests -q
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

# 必须在导入 zeroproxy 之前设置: 面板端口在模块导入时读取
os.environ.setdefault("ZP_PORT", "8899")
os.environ.setdefault("ZP_BIND_PORT", "9900")

# 关闭后台 GeoIP 自动更新线程: 测试必须离线可跑, 不能偷偷发网络请求
os.environ.setdefault("ZP_GEODATA_AUTO", "0")

# 同理关掉"本机公网 IP"的回显请求 (顶部出口 IP 卡片用): 测试环境不该出网
os.environ.setdefault("ZP_PUBLIC_IP", "0")

# 内核镜像换成一个永远连不上的本地地址 —— 两个作用, 都是"测试必须离线可跑":
#   1. 测试里不会真的去下那 20 MB 内核 (开发机上到镜像站几秒就能下完);
#   2. 面板的"预取内核"后台线程 (由 /c/pair 触发) 会**活过用例**: 它的下载地址在
#      每次调用时现读, 写盘时用的又是**当时**的 $ZP_HOME —— 也就是说, 它会往下一个
#      用例的目录里写数据。真下完过一次之后, 下一条用例的前置条件 ("什么都没缓存")
#      就不成立, 断言莫名其妙地红。死地址让它立刻失败, 泄漏的线程什么都留不下。
# 需要真实镜像表的用例自己 monkeypatch 回 router_client.DEFAULT_MIRRORS。
os.environ.setdefault("ZP_CORE_MIRRORS", "http://127.0.0.1:9/{url}")
# 分流数据库的镜像表同理: 面板那条路没走通时, 客户端会去够镜像 —— 而这里说的是
# "测试一个包都不许出网"。死地址让它立刻失败 (见 router_client._geo_mirror_list)。
os.environ.setdefault("ZP_GEO_MIRRORS", "http://127.0.0.1:9/{url}")

# 改配置默认走后台任务 (v2.6.9): 接口立刻回执 + 前端轮询 /api/apply/job。
# 测试里必须同步执行 —— 后台线程活过用例就会踩到下一个用例的 $ZP_HOME
# (每个用例一个临时目录), 所以默认关掉; 专门验证后台任务的用例自己打开。
os.environ.setdefault("ZP_APPLY_ASYNC", "0")

DOMAIN = "proxy.example.com"
USERNAME = "admin"
PASSWORD = "s3cretpass"


@pytest.fixture()
def home(tmp_path, monkeypatch) -> Path:
    monkeypatch.setenv("ZP_HOME", str(tmp_path))
    monkeypatch.setenv("ZP_STATIC", str(BACKEND / "static"))
    return tmp_path


@pytest.fixture(autouse=True)
def _clean_router_core_state():
    """`router_client.CORE_STATE` 是**模块级全局**, 用例之间必须清。

    面板的"预取内核"后台线程会往它里面写状态; 线程活过用例是常态 (它在下一个用例里
    才收尾)。一个残留的 `error` 加退避时间, 会让下一条用例的 `/prepare` 直接跳过下载,
    于是它看到的状态永远不是它期待的那个 —— 断言莫名其妙地红。
    """
    from zeroproxy import router_client

    router_client.CORE_STATE.clear()
    yield


@pytest.fixture()
def token(home) -> str:
    from zeroproxy import config

    value = "bootstrap-token-for-tests"
    config.write_bootstrap_token(value)
    return value


@pytest.fixture()
def client(home):
    from fastapi.testclient import TestClient

    from zeroproxy.main import create_app

    with TestClient(create_app()) as test_client:
        yield test_client


@pytest.fixture()
def configured(client, token) -> dict:
    """完成一次初始化, 返回 setup 响应体。"""
    response = client.post(
        "/api/setup",
        json={"domain": DOMAIN, "username": USERNAME, "password": PASSWORD, "token": token},
    )
    assert response.status_code == 200, response.text
    return response.json()
