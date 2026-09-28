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
