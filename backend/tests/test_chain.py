"""链式代理 (入口 → 落地) 回归测试。

覆盖三件事:
  1. 配对码本身 —— 打包 / 解析 / 各类坏码的报错必须是给人看的中文;
  2. 面板接口 —— 落地端生成凭据、入口端"真实握手通过才落地"的闸门 (以及 force 兜底);
  3. 落地后的产物 —— Xray 配置里的入站 / 出站 / 路由、订阅三种格式、节点卡数据。
"""
from __future__ import annotations

import base64
import json
import os
import uuid as uuid_mod
from urllib.parse import unquote

import pytest

from conftest import DOMAIN
from zeroproxy import chain, config, share_links, xray_config


# ---------------------------------------------------------------- 工具

def _fake_code(state: dict, host: str = "203.0.113.9", port: int = 8447,
               label: str = "美国落地", **over) -> str:
    """造一个"另一台服务器"的配对码 (借本机 Reality 密钥, 只为字段合法)。"""
    reality = state["reality"]
    fields = {
        "host": host,
        "port": port,
        "uuid": str(uuid_mod.uuid4()),
        "pbk": reality["public_key"],
        "sid": reality["short_id"],
        "sni": reality["server_name"],
        "flow": "xtls-rprx-vision",
        "label": label,
    }
    fields.update(over)
    return chain.make_code(**fields)


def _ok_probe(exit_ip: str = "203.0.113.9"):
    return lambda target, timeout=10.0: {
        "ok": True,
        "probe_ok": True,
        "ms": 123.4,
        "exit_ip": exit_ip,
        "detail": f"链路通, 落地出口 IP {exit_ip}",
    }


def _bad_probe(detail: str = "连不上落地端 203.0.113.9:8447 — 超时"):
    return lambda target, timeout=10.0: {
        "ok": False, "probe_ok": True, "ms": None, "exit_ip": "", "detail": detail,
    }


def _sub(client, configured, fmt: str = "base64", extra: str = ""):
    path = configured["subscription_url"].split("testserver")[-1]
    response = client.get(f"{path}?format={fmt}{extra}")
    assert response.status_code == 200, response.text
    return response


#: 每次造一个新落地地址 —— 同一 host:port 会被判为"已连过"而拒绝 (见 test_entry_...)
_HOST_SEQ = iter(f"203.0.113.{n}" for n in range(10, 60))


def _add_entry(client, monkeypatch, host: str | None = None, **kwargs) -> dict:
    host = host or next(_HOST_SEQ)
    monkeypatch.setattr(chain, "probe_target", _ok_probe(host))
    payload = {"code": _fake_code(config.load_state(), host=host)}
    payload.update(kwargs)
    response = client.post("/api/chain/entries", json=payload)
    assert response.status_code == 200, response.text
    return response.json()["chain"]["entries"][-1]


# ---------------------------------------------------------------- 配对码

def test_code_roundtrip():
    from zeroproxy import crypto

    _, public_key, short_id = crypto.new_reality_keys()
    code = chain.make_code(
        host="us.example.com", port=8447, uuid=str(uuid_mod.uuid4()),
        pbk=public_key, sid=short_id, sni="www.cloudflare.com", label="美国落地",
    )
    assert code.startswith("ZPC1~") and code.count("~") == 2
    parsed = chain.parse_code(code)
    assert parsed["host"] == "us.example.com" and parsed["port"] == 8447
    assert parsed["pbk"] == public_key and parsed["sid"] == short_id
    assert parsed["sni"] == "www.cloudflare.com" and parsed["label"] == "美国落地"
    assert parsed["flow"] == "xtls-rprx-vision"
    # 复制粘贴最常见的"带空格 / 换行"要能自愈
    assert chain.parse_code(f"  {code[:20]}\n{code[20:]}  ")["port"] == 8447


@pytest.mark.parametrize(
    "text, hint",
    [
        ("", "配对码为空"),
        ("hello world", "格式不对"),
        ("ZPC2~abc~123456", "格式不对"),
    ],
)
def test_code_rejects_obviously_broken(text, hint):
    with pytest.raises(chain.CodeError) as exc:
        chain.parse_code(text)
    assert hint in str(exc.value)


def test_code_rejects_truncated_and_tampered():
    from zeroproxy import crypto

    _, public_key, short_id = crypto.new_reality_keys()
    code = chain.make_code(
        host="1.2.3.4", port=443, uuid=str(uuid_mod.uuid4()),
        pbk=public_key, sid=short_id, sni="www.cloudflare.com",
    )
    with pytest.raises(chain.CodeError) as exc:
        chain.parse_code(code[:-6])          # 尾巴被截掉 → 校验和必然不匹配
    assert "校验和" in str(exc.value) or "损坏" in str(exc.value)

    head, payload, checksum = code.split("~")
    flipped = ("A" if payload[0] != "A" else "B") + payload[1:]
    with pytest.raises(chain.CodeError):
        chain.parse_code(f"{head}~{flipped}~{checksum}")


def test_code_rejects_fields_that_would_break_reality():
    """坏字段要在"粘贴的那一刻"就说清楚, 不能等落地后握手失败。"""
    from zeroproxy import crypto

    _, public_key, short_id = crypto.new_reality_keys()
    base = dict(host="1.2.3.4", port=443, uuid=str(uuid_mod.uuid4()),
                pbk=public_key, sid=short_id, sni="www.cloudflare.com")

    cases = [
        ({**base, "host": "not a host"}, "落地地址"),
        ({**base, "port": 70000}, "端口"),
        ({**base, "uuid": "nope"}, "UUID"),
        ({**base, "sni": "no"}, "SNI"),
        ({**base, "sid": "zzzz"}, "shortId"),
        ({**base, "flow": "xtls-rprx-direct"}, "flow"),
        ({**base, "pbk": base64.urlsafe_b64encode(b"short").decode().rstrip("=")}, "公钥长度"),
        ({**base, "pbk": "!!!!"}, "公钥"),
    ]
    for fields, hint in cases:
        with pytest.raises(chain.CodeError) as exc:
            chain.parse_code(chain.make_code(**fields))
        assert hint in str(exc.value), (fields, str(exc.value))


# ---------------------------------------------------------------- 落地端 (本机当出口)

def test_exit_generate_rotate_disable(client, configured):
    body = client.post("/api/chain/exit",
                       json={"action": "generate", "port": 8666, "label": "香港落地"}).json()
    ex = body["chain"]["exit"]
    assert ex["enabled"] and ex["port"] == 8666 and ex["label"] == "香港落地"
    parsed = chain.parse_code(ex["code"])
    assert parsed["host"] == DOMAIN and parsed["port"] == 8666 and parsed["label"] == "香港落地"
    first_uuid = parsed["uuid"]
    assert ex["credential"] == first_uuid[:8]
    # 步骤里要明确告诉用户"去放行端口", 而不是默默成功
    assert any(s["name"] == "放行落地端端口" for s in body["steps"])
    # 专用凭据与订阅凭据是两套
    assert first_uuid != config.load_state()["uuid"]

    inbound = next(i for i in xray_config.build_xray_config(config.load_state())["inbounds"]
                   if i["tag"] == "chain-exit")
    assert inbound["port"] == 8666 and inbound["streamSettings"]["security"] == "reality"
    assert inbound["settings"]["clients"][0]["id"] == first_uuid

    qr = client.get("/api/chain/exit/qr?img=svg")
    assert qr.status_code == 200 and qr.headers["content-type"].startswith("image/svg+xml")

    rotated = client.post("/api/chain/exit", json={"action": "rotate"}).json()["chain"]["exit"]
    assert chain.parse_code(rotated["code"])["uuid"] != first_uuid      # 旧码立即作废
    assert rotated["port"] == 8666                                     # 端口与名称保留

    off = client.post("/api/chain/exit", json={"action": "disable"}).json()["chain"]["exit"]
    assert off["enabled"] is False and off["code"] == ""
    tags = [i["tag"] for i in xray_config.build_xray_config(config.load_state())["inbounds"]]
    assert "chain-exit" not in tags
    assert client.get("/api/chain/exit/qr").status_code == 409


def test_exit_port_conflicts_and_bad_action(client, configured):
    client.post("/api/chain/exit", json={"action": "generate", "port": 8666})
    taken = config.load_state()["ports"]["trojan"]
    assert client.post("/api/chain/exit", json={"action": "generate", "port": taken}).status_code == 400
    assert client.post("/api/chain/exit", json={"action": "generate", "port": 70000}).status_code == 400
    assert client.post("/api/chain/exit", json={"action": "explode"}).status_code == 400
    assert client.post("/api/chain/exit", json={"action": "disable"}).status_code == 200
    # 关闭后重复关闭要给人话, 而不是静默成功
    assert client.post("/api/chain/exit", json={"action": "disable"}).status_code == 400
    # 端口 / 名称可以被改
    again = client.post("/api/chain/exit",
                        json={"action": "generate", "port": 8777, "label": "改过名"}).json()
    assert again["chain"]["exit"]["port"] == 8777 and again["chain"]["exit"]["label"] == "改过名"


# ---------------------------------------------------------------- 入口端 (连到落地)

def test_entry_add_lands_in_config_and_subscription(client, configured, monkeypatch):
    entry = _add_entry(client, monkeypatch, label="美国落地")
    assert entry["host"].startswith("203.0.113.") and entry["port"] == 8447
    assert entry["enabled"] and entry["local_port"] >= chain.ENTRY_PORT_BASE
    assert entry["last_probe"]["exit_ip"] == entry["host"]
    nid = f"chain-{entry['id']}"

    state = config.load_state()
    cfg = xray_config.build_xray_config(state)
    inbound = next(i for i in cfg["inbounds"] if i["tag"] == nid)
    assert inbound["port"] == entry["local_port"]
    outbound = next(o for o in cfg["outbounds"] if o["tag"] == f"chain-out-{entry['id']}")
    assert outbound["settings"]["vnext"][0]["address"] == entry["host"]
    rule = [r for r in cfg["routing"]["rules"] if r.get("outboundTag") == f"chain-out-{entry['id']}"][0]
    assert rule["inboundTag"] == [nid]

    # 节点卡片: 链式标记 + 落地地址 + 最近探测
    node = next(n for n in client.get("/api/dashboard").json()["nodes"] if n["id"] == nid)
    assert node["chain"] is True and node["via"] == f"{entry['host']}:8447"
    assert node["port"] == entry["local_port"] and node["last_probe"]["exit_ip"] == entry["host"]

    # 客户端那侧: 就是订阅里多了一个普通 Reality 节点, 地址是**本机**
    link = share_links.share_links(state)[nid]
    assert link.startswith(f"vless://{state['uuid']}@{DOMAIN}:{entry['local_port']}")
    assert "security=reality" in link and "flow=xtls-rprx-vision" in link

    b64 = unquote(base64.b64decode(_sub(client, configured).text).decode())
    assert f"@{DOMAIN}:{entry['local_port']}" in b64 and "ZeroProxy 链式 · 美国落地" in b64
    clash = _sub(client, configured, "clash").text
    proxies = clash.split("proxies:")[1].split("proxy-groups:")[0]
    assert "ZeroProxy 链式 · 美国落地" in proxies
    assert f"port: {entry['local_port']}" in proxies
    assert entry["host"] not in proxies          # 客户端不该看到落地地址
    assert "reality-opts" in proxies
    singbox = json.loads(_sub(client, configured, "singbox").text)
    out = [o for o in singbox["outbounds"] if o.get("tag") == "ZeroProxy 链式 · 美国落地"][0]
    assert out["server_port"] == entry["local_port"] and out["tls"]["reality"]["enabled"] is True

    assert client.get(f"/api/nodes/{nid}/qr?size=4").headers["content-type"] == "image/png"
    # 落地后端口纳入"端口监听"检查
    from zeroproxy import apply

    labels = [label for _, _, label in apply._wanted_ports(config.load_state())]
    assert any("接入站" in label or "入站" in label for label in labels)


def test_entry_probe_gate_and_force(client, configured, monkeypatch):
    """探测说"连不通"时先拦一下 (带 needs_force), 用户确认后才硬加。"""
    code = _fake_code(config.load_state())
    monkeypatch.setattr(chain, "probe_target", _bad_probe())
    res = client.post("/api/chain/entries", json={"code": code})
    assert res.status_code == 400
    body = res.json()
    assert body["needs_force"] is True and body["probe"]["ok"] is False
    assert config.load_state()["chain"]["entries"] == []          # 没落地

    forced = client.post("/api/chain/entries", json={"code": code, "force": True})
    assert forced.status_code == 200, forced.text
    entry = forced.json()["chain"]["entries"][0]
    assert entry["last_probe"]["ok"] is False
    assert any(s["name"].startswith("链路测试") and s["ok"] is False for s in forced.json()["steps"])

    # 环境不允许探测 (没有 xray 二进制) 时不该拦住用户
    other = _fake_code(config.load_state(), host="198.51.100.7", label="备用")
    monkeypatch.setattr(
        chain, "probe_target",
        lambda target, timeout=10.0: {"ok": False, "probe_ok": False, "ms": None,
                                      "exit_ip": "", "detail": "TCP 可达, 但本机没有 xray 二进制"},
    )
    assert client.post("/api/chain/entries", json={"code": other}).status_code == 200


def test_entry_rejects_bad_codes_and_self(client, configured, monkeypatch):
    monkeypatch.setattr(chain, "probe_target", _ok_probe())
    empty = client.post("/api/chain/entries", json={"code": "  "})
    assert empty.status_code == 400 and "配对码为空" in empty.json()["error"]
    broken = client.post("/api/chain/entries", json={"code": "x"})
    assert broken.status_code == 400 and "格式不对" in broken.json()["error"]

    # 指向本机自己 = 死循环, 必须挡住
    client.post("/api/chain/exit", json={"action": "generate", "port": 8666})
    own = client.get("/api/dashboard").json()["chain"]["exit"]["code"]
    res = client.post("/api/chain/entries", json={"code": own})
    assert res.status_code == 400 and "本机自己" in res.json()["error"]

    # 同一个落地端别加两次
    code = _fake_code(config.load_state())
    assert client.post("/api/chain/entries", json={"code": code}).status_code == 200
    again = client.post("/api/chain/entries", json={"code": code})
    assert again.status_code == 400 and "已经连过" in again.json()["error"]


def test_entry_local_port_conflict(client, configured, monkeypatch):
    monkeypatch.setattr(chain, "probe_target", _ok_probe())
    taken = int(config.load_state()["ports"]["reality"])
    res = client.post("/api/chain/entries",
                      json={"code": _fake_code(config.load_state()), "local_port": taken})
    assert res.status_code == 400 and "占用" in res.json()["error"]


def test_entry_toggle_default_and_delete(client, configured, monkeypatch):
    first = _add_entry(client, monkeypatch, label="美国")
    second = _add_entry(client, monkeypatch, label="日本")
    id1, id2 = first["id"], second["id"]
    node1, node2 = f"chain-{id1}", f"chain-{id2}"

    # 停用 → 订阅里消失, 配置里也没有它的入站
    client.post(f"/api/chain/entries/{id1}", json={"enabled": False})
    state = config.load_state()
    assert node1 not in share_links.share_links(state)
    assert node1 not in [i["tag"] for i in xray_config.build_xray_config(state)["inbounds"]]
    # 停用状态下不能设默认出口
    assert client.post(f"/api/chain/entries/{id1}", json={"default_out": True}).status_code == 400
    # 重新启用 → 订阅恢复
    client.post(f"/api/chain/entries/{id1}", json={"enabled": True})
    assert node1 in share_links.share_links(config.load_state())

    # 设为默认出口: 4 个主力入站的流量整体改道到这条链
    body = client.post(f"/api/chain/entries/{id1}", json={"default_out": True}).json()
    assert next(e for e in body["chain"]["entries"] if e["id"] == id1)["default_out"] is True
    cfg = xray_config.build_xray_config(config.load_state())
    reroute = [r for r in cfg["routing"]["rules"] if r.get("outboundTag") == f"chain-out-{id1}"]
    assert any(set(r["inboundTag"]) >= {"vless-reality", "vless-xhttp"} for r in reroute)
    assert next(n for n in body["nodes"] if n["id"] == node1)["default_out"] is True

    # 同时只能有一个默认出口
    body = client.post(f"/api/chain/entries/{id2}", json={"default_out": True}).json()
    assert [e["default_out"] for e in body["chain"]["entries"]] == [False, True]

    # 停用默认出口那条 → 默认标记自动摘掉 (不能让流量偷偷走一条停用的链)
    body = client.post(f"/api/chain/entries/{id2}", json={"enabled": False}).json()
    assert body["chain"]["default_out"] == ""

    # 删除 → 配置里不再有它, 接口也回到 404
    body = client.delete(f"/api/chain/entries/{id1}").json()
    assert [e["id"] for e in body["chain"]["entries"]] == [id2]
    config.load_state()   # 删除后仍能正常读状态
    assert client.delete(f"/api/chain/entries/{id1}").status_code == 404


def test_toggle_node_endpoint_supports_chain(client, configured, monkeypatch):
    entry = _add_entry(client, monkeypatch)
    nid = f"chain-{entry['id']}"
    body = client.post(f"/api/nodes/{nid}/toggle").json()
    assert next(e for e in body["chain"]["entries"])["enabled"] is False
    body = client.post(f"/api/nodes/{nid}/toggle").json()
    assert next(e for e in body["chain"]["entries"])["enabled"] is True
    assert client.post("/api/nodes/chain-nope/toggle").status_code == 404


def test_chain_probe_endpoint_updates_last_probe(client, configured, monkeypatch):
    entry = _add_entry(client, monkeypatch)
    monkeypatch.setattr(chain, "probe_target", _ok_probe("198.51.100.9"))
    body = client.post(f"/api/chain/entries/{entry['id']}/probe").json()
    got = next(e for e in body["chain"]["entries"] if e["id"] == entry["id"])
    assert got["last_probe"]["exit_ip"] == "198.51.100.9"
    assert body["steps"][0]["name"].startswith("链路测速") and body["steps"][0]["ok"] is True
    assert client.post("/api/chain/entries/nope/probe").status_code == 404


def test_traffic_tags_include_enabled_chain_entries(client, configured, monkeypatch):
    from zeroproxy import services

    entry = _add_entry(client, monkeypatch)
    assert f"chain-{entry['id']}" in services.traffic_tags(config.load_state())
    client.post(f"/api/chain/entries/{entry['id']}", json={"enabled": False})
    assert f"chain-{entry['id']}" not in services.traffic_tags(config.load_state())


def test_diagnose_flags_unreachable_exit(client, configured, monkeypatch):
    from zeroproxy import services

    entry = _add_entry(client, monkeypatch)
    monkeypatch.setattr(
        services, "tcp_connect_ms",
        lambda host, port, timeout=3.0: (False, None, "connection refused"),
    )
    checks = {c["name"]: c for c in client.get("/api/diagnose").json()["checks"]}
    assert checks["链式落地端可达性"]["ok"] is False
    assert entry["host"] in checks["链式落地端可达性"]["detail"]


def test_chain_kept_in_backup(client, configured, monkeypatch):
    entry = _add_entry(client, monkeypatch, label="美国落地")
    backup = client.get("/api/backup").json()
    assert backup["state"]["chain"]["entries"][0]["id"] == entry["id"]


def test_xray_config_with_real_binary_includes_chain(client, configured, monkeypatch):
    """真实 Xray 校验带链式入站 / 出站的配置 (指定 ZP_XRAY_BIN 时才跑)。"""
    binary = os.environ.get("ZP_XRAY_BIN")
    if not binary or not os.path.exists(binary):
        pytest.skip("未提供 ZP_XRAY_BIN")
    monkeypatch.setenv("ZP_XRAY_BIN", binary)
    from zeroproxy import services

    _add_entry(client, monkeypatch)
    client.post("/api/chain/exit", json={"action": "generate", "port": 8666})
    state = config.load_state()
    state["chain"]["entries"][0]["default_out"] = True
    config.save_state(state)
    xray_config.write_xray_config(config.load_state())
    ok, detail = services.xray_config_test()
    assert ok, detail
