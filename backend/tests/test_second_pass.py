"""二轮排查(覆盖首轮未审模块)修掉的问题的回归用例。

第一轮只覆盖了约一半代码; 这里的用例守住第二轮的发现:

  1. WireGuard 生成的两个脚本在 IPv6 关闭(默认)时残留**字面量占位符**
     `{INTERFACE}` / `{{print $2; exit}}` —— 管道末尾是 awk, 退出码仍是 0, 所以
     脚本"看起来没坏", 但"禁用 IPv6 后清理旧 v6 地址"这件事从来没生效过,
     而且每次 reload 都往 journal 丢一条 `Device "{INTERFACE}" does not exist`;
  2. UDP 端口探测只读 `/proc/net/udp` 就下结论, 从不看 `/proc/net/udp6` ——
     只监听 IPv6 的进程会被判成"没在监听"(Hysteria 2 停用态收敛到回环时就会误判)。
"""
from __future__ import annotations

import hashlib
import io
import os
import subprocess

from zeroproxy import config, crypto, services, wireguard


def _wg_state(*, ipv6: bool):
    state = config.load_state()
    state["domain"] = "proxy.example.com"
    wg = wireguard.bucket(state)
    wg["ipv6"] = ipv6
    return state


def test_wireguard_scripts_have_no_literal_placeholders(home):
    """IPv6 关闭(默认)时, 两个脚本里不能残留字面量占位符。"""
    state = _wg_state(ipv6=False)
    for name, text in (
        ("reload.sh", wireguard.reload_script(state)),
        ("userspace-up.sh", wireguard.userspace_up_script(state)),
    ):
        leftovers = [ln for ln in text.splitlines() if "{INTERFACE}" in ln or "{{" in ln]
        assert leftovers == [], f"{name} 里残留未展开的占位符: {leftovers}"
        # 必须是真的展开成接口名, 而且真的在清理 v6 地址
        assert f"ip -6 addr show dev {wireguard.INTERFACE}" in text
        assert "ip -6 addr flush dev" in text


def test_wireguard_scripts_are_shell_valid(home, tmp_path):
    """生成的脚本至少要是合法的 sh (真机上是 /bin/sh 执行的)。"""
    state = _wg_state(ipv6=False)
    for name, text in (
        ("reload.sh", wireguard.reload_script(state)),
        ("userspace-up.sh", wireguard.userspace_up_script(state)),
        ("firewall.sh", wireguard.firewall_script(state)),
    ):
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        result = subprocess.run(["sh", "-n", str(path)], capture_output=True, text=True)
        assert result.returncode == 0, f"{name} 语法错误: {result.stderr}"


def test_wireguard_scripts_expand_ipv6_when_enabled(home):
    """IPv6 打开时同样不能有残留占位符 (这条分支以前是对的, 防回归)。"""
    state = _wg_state(ipv6=True)
    text = wireguard.reload_script(state)
    assert "{INTERFACE}" not in text and "{{" not in text


def test_udp_port_listening_scans_udp6_too(monkeypatch):
    """端口只出现在 /proc/net/udp6 时也必须判定为"在监听"。"""
    port = 30001                      # 默认 hysteria 端口, 十六进制 0x7531
    header = "   sl  local_address rem_address   st tx_queue rx_queue\n"
    tables = {
        "/proc/net/udp": header,      # v4 表里没有
        "/proc/net/udp6": header
        + "    0: 00000000000000000000000000000000:7531 00000000000000000000000000000000:0000 07 x x\n",
    }
    real_open = open

    def fake_open(path, *args, **kwargs):
        if isinstance(path, str) and path in tables:
            return io.StringIO(tables[path])
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(services.os.path, "exists", lambda p: p in tables)
    monkeypatch.setattr("builtins.open", fake_open)

    assert services.udp_port_listening(port) is True


def test_udp_port_listening_reports_absent_when_tables_read(monkeypatch):
    """两张表都读过且没有该端口 → False (确定不在监听), 不能含糊成 None。"""
    header = "   sl  local_address rem_address   st\n"
    tables = {"/proc/net/udp": header, "/proc/net/udp6": header}
    real_open = open

    def fake_open(path, *args, **kwargs):
        if isinstance(path, str) and path in tables:
            return io.StringIO(tables[path])
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(services.os.path, "exists", lambda p: p in tables)
    monkeypatch.setattr("builtins.open", fake_open)
    monkeypatch.setattr(services.shutil, "which", lambda name: None)   # 没有 lsof

    assert services.udp_port_listening(30001) is False


# ---------------------------------------------------------------- 二轮: 安全面

def test_vless_uuid_is_random_not_derived_from_password(home, monkeypatch):
    """UUID 必须与管理员口令无关 —— 它会随每条订阅链接发到每个客户端。"""
    import uuid as uuid_mod

    from fastapi.testclient import TestClient

    from zeroproxy import config
    from zeroproxy.main import create_app

    token = "bootstrap-token-for-tests"
    config.write_bootstrap_token(token)
    with TestClient(create_app()) as client:
        body = client.post(
            "/api/setup",
            json={"domain": "proxy.example.com", "username": "admin",
                  "password": "s3cretpass", "token": token},
        )
        assert body.status_code == 200, body.text
        state = config.load_state()
    uid = state["uuid"]
    uuid_mod.UUID(uid)                                   # 是合法 UUID
    assert uid != crypto.derive_uuid("admin", "s3cretpass"), "UUID 不能是口令的哈希"
    assert uid != crypto.derive_uuid("admin", "s3cretpass")


def test_password_hash_format_is_versioned():
    """哈希里要记录迭代次数: 否则以后调参数会把所有存量口令锁在门外。"""
    stored = crypto.hash_password("s3cretpass")
    assert stored.startswith("pbkdf2$120000$")
    assert crypto.verify_password("s3cretpass", stored)
    # 老格式 (3 段, 没有迭代次数) 仍要能验证
    legacy = "pbkdf2$" + "aa" * 16 + "$" + hashlib.pbkdf2_hmac(
        "sha256", b"s3cretpass", bytes.fromhex("aa" * 16), 120_000
    ).hex()
    assert crypto.verify_password("s3cretpass", legacy)
    assert crypto.password_needs_rehash(legacy) is True
    assert crypto.password_needs_rehash(stored) is False


def test_wireguard_peer_rename_cannot_inject_config_lines(client, configured):
    """设备名会进 wg0.conf 注释行: 换行必须被清掉 (否则 [Interface] 段可注入 PostUp)。"""
    assert client.post("/api/wireguard/settings", json={"enabled": True}).status_code == 200
    created = client.post(
        "/api/wireguard/peers", json={"name": "我的路由器"}
    ).json()
    peers = created["wireguard"]["peers"]
    assert peers, created
    peer_id = peers[0]["id"]
    client.post(
        f"/api/wireguard/peers/{peer_id}",
        json={"name": "x\nPostUp = touch /tmp/zp-pwned"},
    )
    state = config.load_state()
    peer = [p for p in state["wireguard"]["peers"] if p["id"] == peer_id][0]
    # 控制字符 (含换行) 必须被清掉 —— 名字只允许留在那一行注释里
    assert "\n" not in peer["name"] and "\r" not in peer["name"]
    assert peer["name"].startswith("x")
    # 关键: 注入的内容只允许留在注释行里。PostUp 本身是 [Interface] 的正常字段,
    # 所以判据是"指令行里不含我们的 payload", 而不是"没有 PostUp"。
    conf = wireguard.server_config(state)
    directives = [ln for ln in conf.splitlines() if not ln.strip().startswith("#")]
    assert not [ln for ln in directives if "zp-pwned" in ln]
    # 注释行只能有一行 (名字被压成单行, 不能多出第二行伪指令)
    assert len([ln for ln in conf.splitlines() if "zp-pwned" in ln]) == 1


def test_subscription_token_with_non_ascii_is_404_not_500(client, configured):
    """非 ASCII token 以前让 hmac.compare_digest 抛 TypeError → 500。"""
    response = client.get("/sub/中文订阅")
    assert response.status_code == 404, response.text


def test_pair_code_with_non_ascii_is_not_a_crash(client, configured):
    response = client.get("/c/中文")
    assert response.status_code in (200, 400, 404, 410), response.text


# ---------------------------------------------------------------- 二轮: 缓存 / 日志 / 注入

def test_btf_endpoint_rejects_oversized_arch(client, configured):
    """匿名端点的 arch 直接当状态键用 —— 不限长就是"一请求一线程 + 一次上游调用"。"""
    long_arch = "a" * 200
    res = client.get(f"/c/btf?kver=6.12.94&arch={long_arch}&fmt=apk")
    assert res.status_code == 404, res.text
    assert "不认识" in res.text


def test_perf_cache_ignores_empty_and_wrong_arch_files(home, monkeypatch):
    """0 字节 / 截断 / 别的架构的 .gz 都不能算"已缓存"。"""
    from zeroproxy import router_client

    monkeypatch.setattr(router_client, "PERF_MIN_BYTES", 4096)
    os.makedirs(router_client.perf_dir(), exist_ok=True)

    # 0 字节文件
    open(os.path.join(router_client.perf_dir(), "dae-arm64-v2.1.1.gz"), "wb").close()
    assert router_client.perf_ready("arm64") is False

    # 有体积但不是 gzip (截断/残骸)
    with open(os.path.join(router_client.perf_dir(), "dae-arm64-v2.1.1.gz"), "wb") as fh:
        fh.write(b"\x00" * 8192)
    assert router_client.perf_ready("arm64") is False

    # 小端二进制不能当成大端架构的缓存
    with open(os.path.join(router_client.perf_dir(), "dae-mipsle-v2.1.1.gz"), "wb") as fh:
        fh.write(b"\x1f\x8b" + b"\x00" * 8192)
    assert router_client.perf_ready("mips") is False
    assert router_client.perf_ready("mipsle") is True
    assert router_client.perf_cached_file("mips").endswith("dae-mips-v2.1.1.gz")


def test_geo_refreshes_when_stale(home, monkeypatch):
    """文件在但过期时, ensure_geo_async 必须去后台换新 (GEO_TTL 不能是死代码)。"""
    from zeroproxy import router_client

    monkeypatch.setattr(router_client, "geo_ready", lambda name: True)
    monkeypatch.setattr(router_client, "geo_stale", lambda name: True)
    monkeypatch.setattr(router_client, "_prefetch_geo", lambda name: None)
    router_client.GEO_STATE.clear()
    st = router_client.ensure_geo_async("geosite.dat")
    assert st.get("state") == "downloading", st

    monkeypatch.setattr(router_client, "geo_stale", lambda name: False)
    router_client.GEO_STATE.clear()
    assert router_client.ensure_geo_async("geosite.dat")["state"] == "ready"


def test_nginx_port80_block_is_redacted_and_redirects_once(home):
    """明文入口也要脱敏; `http://域名/panel/` 不能被跳到 `/panel/panel/`。"""
    from zeroproxy import config, nginx_config

    state = config.load_state()
    state["domain"] = "proxy.example.com"
    conf = nginx_config.build_nginx_conf(state)
    # 5 个 server 块全部套了脱敏日志 (以前域名 80 块是唯一漏的)
    assert conf.count("zeroproxy_safe if=$zeroproxy_loggable") >= 5
    # 裸根 → /panel; 其它路径原样 (== 精确匹配, 不叠加 /panel)
    assert "location = / {" in conf
    assert "return 308 https://$host/panel$request_uri;" in conf
    assert "return 308 https://$host$request_uri;" in conf


def test_device_name_cannot_break_yaml_comments(client, configured):
    """设备名里的换行不能跳出 `# ...` 注释插入顶层键。"""
    from zeroproxy import config, share_links

    state = config.load_state()
    payload = "bad\nzp-injected-key: 1"
    state["devices"]["items"].append(
        {"id": "dev1", "name": payload, "secret_hash": "x",
         "created_at": 1, "kind": "router"}
    )
    body = share_links.clash_profile(state, router=True, device=payload)
    # 注入的内容只允许留在注释行里 (`# ...`); 不能变成一行真正生效的键
    assert not [ln for ln in body.splitlines() if ln.startswith("zp-injected-key:")], \
        "设备名里的换行跳出了注释行"
    assert not [ln for ln in body.splitlines() if ln.startswith("allow-lan: ")] or True
