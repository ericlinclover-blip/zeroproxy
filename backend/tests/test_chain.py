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
import time
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
        ({**base, "sid": "abc"}, "shortId"),        # 奇数长度: Xray hex 解码必失败
        ({**base, "flow": "xtls-rprx-direct"}, "flow"),
        ({**base, "pbk": base64.urlsafe_b64encode(b"short").decode().rstrip("=")}, "公钥长度"),
        ({**base, "pbk": "!!!!"}, "公钥"),
    ]
    for fields, hint in cases:
        with pytest.raises(chain.CodeError) as exc:
            chain.parse_code(chain.make_code(**fields))
        assert hint in str(exc.value), (fields, str(exc.value))


def test_code_accepts_even_length_short_ids():
    """奇数长度 shortId 会让整份 Xray 配置构建失败, 偶数长度 (含空) 都是合法的。"""
    from zeroproxy import crypto

    _, public_key, _ = crypto.new_reality_keys()
    for sid in ("", "ab", "abcdef12"):
        code = chain.make_code(host="1.2.3.4", port=443, uuid=str(uuid_mod.uuid4()),
                               pbk=public_key, sid=sid, sni="www.cloudflare.com")
        assert chain.parse_code(code)["sid"] == sid


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


def test_exit_rejects_ipv6_host(client, configured):
    """本机用 IPv6 初始化时, 配对码装不下这个地址 —— 生成时就该拦下说清楚。

    parse_code 只认域名 / IPv4, 否则生成出来的码对方一律解析失败; 与其发出去一条
    "看着成功、粘过去报格式不对"的码, 不如当场提示换域名 / IPv4。
    """
    state = config.load_state()
    state["domain"] = "2001:db8::1"
    config.save_state(state)

    response = client.post("/api/chain/exit", json={"action": "generate", "port": 8666})
    assert response.status_code == 400, response.text
    assert "IPv6" in response.json()["error"]
    # 没生成成功 → 不能留下"看起来已开启"的落地端
    assert client.get("/api/dashboard").json()["chain"]["exit"]["enabled"] is False


def test_exit_disable_revokes_code_for_good(client, configured):
    """关闭落地端 = 配对码永久作废: 重新开启不会让旧码复活 (端口与名称沿用)。

    面板上「关闭」的确认框写着"配对码作废 / 凭据会重新生成"; 如果重新开启时复用
    同一份 UUID, 泄露出去的旧码就会在开关一次之后重新能用 —— 与承诺不符。
    """
    first = client.post("/api/chain/exit",
                        json={"action": "generate", "port": 8666, "label": "香港落地"}).json()
    first_uuid = chain.parse_code(first["chain"]["exit"]["code"])["uuid"]

    off = client.post("/api/chain/exit", json={"action": "disable"}).json()["chain"]["exit"]
    assert off["enabled"] is False and off["code"] == ""
    assert off["port"] == 8666 and off["label"] == "香港落地"   # 端口与名称留着, 方便原样重开

    # 前端重新开启时会把回填的端口 / 名称一起发回来
    again = client.post("/api/chain/exit",
                        json={"action": "generate", "port": off["port"], "label": off["label"]}).json()
    ex = again["chain"]["exit"]
    assert ex["enabled"] is True and ex["port"] == 8666 and ex["label"] == "香港落地"
    assert chain.parse_code(ex["code"])["uuid"] != first_uuid          # 旧码永久失效
    # 停用期间端口必须真的处于"该关闭"清单里 (重启后要复查它不再监听)
    from zeroproxy import apply

    client.post("/api/chain/exit", json={"action": "disable"})
    closed = [label for _, _, label in apply._ports_that_must_be_closed(config.load_state())]
    assert "链式落地端入站" in closed


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
    untested = client.post("/api/chain/entries", json={"code": other})
    assert untested.status_code == 200
    # "没测成"不是"没通过": 这一步不该在面板上标红, 但要留下 skipped 说明
    step = next(s for s in untested.json()["steps"] if s["name"].startswith("链路测试"))
    assert step["ok"] is True and step["skipped"] is True
    got = next(e for e in untested.json()["chain"]["entries"] if e["host"] == "198.51.100.7")
    assert got["last_probe"]["probe_ok"] is False and got["last_probe"]["ok"] is False
    # 同一个判断也要用在「测速」按钮上
    probed = client.post(f"/api/chain/entries/{got['id']}/probe")
    assert probed.status_code == 200
    assert probed.json()["steps"][0]["skipped"] is True
    assert probed.json()["steps"][0]["ok"] is True


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


def test_entry_revalidates_local_port_after_the_probe(client, configured, monkeypatch):
    """握手探测跑在锁外 (好几秒), 期间端口可能被别的操作占走。

    构造: 第一次挑端口时挑中 8446, 探测期间"另一条链"落地抢走了 8446;
    落地前必须重新校验, 最终条目不能落在 8446 上, 否则 `xray -test` 会撞端口失败。
    """
    real_pick_port = chain.pick_port
    picks: list[int] = []

    def fake_pick_port(state, preferred=None):
        if not picks:  # 第一次挑端口: 假装 8446 当时还空着
            picks.append(chain.ENTRY_PORT_BASE)
            return chain.ENTRY_PORT_BASE
        port = real_pick_port(state, preferred)
        picks.append(port)
        return port

    monkeypatch.setattr(chain, "pick_port", fake_pick_port)

    def stealing_probe(target, timeout=10.0):
        # 模拟探测期间另一条链落地, 抢走 8446
        with config.locked():
            state = config.load_state()
            state.setdefault("chain", {}).setdefault("entries", []).append(
                {"id": "intruder", "label": "抢端口", "local_port": chain.ENTRY_PORT_BASE}
            )
            config.save_state(state)
        return _ok_probe()(target, timeout)

    monkeypatch.setattr(chain, "probe_target", stealing_probe)

    res = client.post("/api/chain/entries", json={"code": _fake_code(config.load_state())})
    assert res.status_code == 200, res.text
    entry = res.json()["chain"]["entries"][-1]
    assert entry["local_port"] != chain.ENTRY_PORT_BASE, entry["local_port"]
    assert len(picks) == 2, picks  # 第一次挑中 8446, 落地前又重挑了一次


def test_entry_names_stay_unique_in_subscriptions(client, configured, monkeypatch):
    """两条链取同一个名字时, 订阅里的节点名必须自动区分开。

    客户端把节点名当代理名 / 出站 tag: Clash 会丢掉重名项、sing-box 直接报
    duplicate tag, 整份订阅都导不进来 —— 所以落地时就要把名字去重。
    """
    monkeypatch.setattr(chain, "probe_target", _ok_probe())
    ids = []
    for host in ("203.0.113.70", "203.0.113.71"):
        res = client.post("/api/chain/entries",
                          json={"code": _fake_code(config.load_state(), host=host, label="美国落地")})
        assert res.status_code == 200, res.text
        ids.append(res.json()["chain"]["entries"][-1]["id"])

    state = config.load_state()
    names = [share_links.chain_node_name(e) for e in state["chain"]["entries"]]
    assert len(set(names)) == 2, names
    assert names[0] == "ZeroProxy 链式 · 美国落地" and names[1].startswith("ZeroProxy 链式 · 美国落地 (")

    # 三种订阅里都不能出现重名
    import yaml

    clash = yaml.safe_load(_sub(client, configured, "clash").text)
    clash_names = [p["name"] for p in clash["proxies"]]
    assert len(set(clash_names)) == len(clash_names), clash_names
    singbox = json.loads(_sub(client, configured, "singbox").text)
    tags = [o["tag"] for o in singbox["outbounds"]]
    assert len(set(tags)) == len(tags), tags
    b64 = unquote(base64.b64decode(_sub(client, configured).text).decode())
    assert names[0] in b64 and names[1] in b64

    # 改名撞上已有名称时同样要自动区分
    body = client.post(f"/api/chain/entries/{ids[1]}", json={"label": "日本落地"}).json()
    assert [e["label"] for e in body["chain"]["entries"]][1] == "日本落地"
    body = client.post(f"/api/chain/entries/{ids[1]}", json={"label": "美国落地"}).json()
    assert [e["label"] for e in body["chain"]["entries"]] == ["美国落地", "美国落地 (2)"]


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


def _fake_http_over_socks5(parts: list[bytes], expect_host: bytes = b"echo.test"):
    """假 SOCKS5 + 分片 HTTP 响应 (每段之间隔 50ms, 模拟真实 TCP 分段)。"""
    import socket
    import threading
    import time

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)

    def recv_exact(conn, n):
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    def serve():
        conn, _ = server.accept()
        conn.settimeout(3)
        try:
            recv_exact(conn, 3)
            conn.sendall(b"\x05\x00")
            recv_exact(conn, 4 + 1 + len(expect_host) + 2)
            conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            try:
                conn.recv(4096)          # 读掉 HTTP 请求
            except OSError:
                pass
            for index, part in enumerate(parts):
                if index:
                    time.sleep(0.05)
                conn.sendall(part)
            time.sleep(0.2)
        except OSError:
            pass
        finally:
            conn.close()

    threading.Thread(target=serve, daemon=True).start()
    return server.getsockname()[1], server


def test_socks5_http_get_reads_full_body():
    """出口 IP 的正文可能被拆成多个 TCP 分段 —— 只凭"正文非空"收工会把 IP 截断。

    真机踩到过: 落地服务器的 IPv6 出口地址被读成 `2401:1fe0:6` 这样的半截, 面板上
    显示的"落地出口 IP"就是错的 (看起来像格式怪异的地址, 实际是被截断)。
    """
    from zeroproxy import services

    body = b"2401:1fe0:600:1234:5678:9abc:def0:1234"
    head = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n"
    port, server = _fake_http_over_socks5([head + body[:12], body[12:]])
    try:
        text, detail = services.socks5_http_get(port, "echo.test", 80, "/", 3)
    finally:
        server.close()
    assert text == body.decode(), (text, detail)


def test_socks5_http_get_handles_chunked_body():
    """分块传输的回显服务 (ifconfig.me/ip 就是) 也要还原成完整 IP, 不能带 chunk 头。"""
    from zeroproxy import services

    body = b"2401:1fe0:600:1234:5678:9abc:def0:1234"
    chunked = b"".join(
        f"{len(part):x}\r\n".encode() + part + b"\r\n" for part in (body[:10], body[10:])
    ) + b"0\r\n\r\n"
    head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    port, server = _fake_http_over_socks5([head + chunked[:18], chunked[18:]])
    try:
        text, detail = services.socks5_http_get(port, "echo.test", 80, "/", 3)
    finally:
        server.close()
    assert text == body.decode(), (text, detail)


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


# ---------------------------------------------------------------- TCP 层调优 (v2.6.17)

def test_inbound_and_outbound_carry_tcp_sockopt(client, configured, monkeypatch):
    """TFO / tcpNoDelay / keepAlive 必须真的落到配置里。

    链式那条出站是整条链的瓶颈 (每条新连接都要跨洋握手一次), 少一个 sockopt
    就等于把 TFO 省下的那一个 RTT 又丢回去。
    """
    _add_entry(client, monkeypatch)
    cfg = xray_config.build_xray_config(config.load_state())
    inbound = next(i for i in cfg["inbounds"] if i["tag"] == "vless-reality")
    sockopt = inbound["streamSettings"]["sockopt"]
    assert sockopt["tcpFastOpen"] is True
    assert sockopt["tcpNoDelay"] is True
    assert sockopt["tcpKeepAliveInterval"] == 15
    outbound = next(o for o in cfg["outbounds"] if str(o["tag"]).startswith("chain-out-"))
    assert outbound["streamSettings"]["sockopt"]["tcpFastOpen"] is True


def test_probe_uses_one_total_budget(monkeypatch):
    """三个回显服务不能各给一份超时 —— 那样面板上一次测速最长要等 18 秒。"""
    from zeroproxy import chain as chain_mod
    from zeroproxy import services

    calls: list[float] = []

    def slow(*args, **kwargs):
        calls.append(timeout := args[4] if len(args) > 4 else 6.0)
        time.sleep(timeout)          # 每个回显服务都"用满"自己的那份
        return "", "超时"

    monkeypatch.setattr(services, "socks5_http_get", slow)
    started = time.monotonic()
    ip, detail = chain_mod.read_exit_ip(1080, timeout=3.0)
    cost = time.monotonic() - started
    assert ip == "" and detail
    assert cost < 6.0, f"总耗时 {cost:.1f}s, 说明超时没有被当成整段预算"
    assert len(calls) <= 2, f"试了 {len(calls)} 个回显服务, 预算没生效"


def test_warmup_targets_cover_main_and_enabled_entries(client, configured, monkeypatch):
    """预热要盖住"客户端连的那一侧": 主力 Reality 入站 + 每条启用中的链式入站。"""
    from zeroproxy import chain as chain_mod

    entry = _add_entry(client, monkeypatch)
    state = config.load_state()
    ports = [t["port"] for t in chain_mod.warmup_targets(state)]
    assert state["ports"]["reality"] in ports
    assert entry["local_port"] in ports
    # 目标是回环: 冷启动在服务端, 与客户端在哪无关
    assert {t["host"] for t in chain_mod.warmup_targets(state)} == {"127.0.0.1"}

    state["chain"]["entries"][0]["enabled"] = False
    assert entry["local_port"] not in [t["port"] for t in chain_mod.warmup_targets(state)]
    # 主力节点也关掉时就没有可预热的东西
    state["nodes"]["vless-reality"] = False
    assert chain_mod.warmup_targets(state) == []


def test_warmup_records_result_in_audit(client, configured, monkeypatch):
    """预热在后台线程里跑, 结果落进操作记录 (不能默默失败)。"""
    from zeroproxy import chain as chain_mod
    from zeroproxy import services

    monkeypatch.setattr(services, "bin_path", lambda name: "/fake/xray" if name == "xray" else None)
    monkeypatch.setattr(chain_mod, "warmup", lambda state, timeout=0: (True, "8443 ✓ 0.1s (读到出口 IP)"))
    chain_mod.warmup_in_background(config.load_state())
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        rows = config.load_state()["audit"]
        if rows and rows[-1]["action"] == "chain_warmup":
            break
        time.sleep(0.05)
    assert rows[-1]["action"] == "chain_warmup"
    assert "8443" in rows[-1]["detail"]


# ---------------------------------------------------------------- 内层 QUIC (Hysteria 2)

def _v2_code(state: dict, host: str = "203.0.113.9", **over) -> str:
    reality = state["reality"]
    fields = {
        "host": host,
        "port": 8447,
        "uuid": str(uuid_mod.uuid4()),
        "pbk": reality["public_key"],
        "sid": reality["short_id"],
        "sni": reality["server_name"],
        "flow": "xtls-rprx-vision",
        "label": "美国落地",
        "hy_port": 8448,
        "hy_password": "quic-secret-1234",
        "hy_sni": "us.example.com",
    }
    fields.update(over)
    return chain.make_code(**fields)


def test_code_v2_carries_quic_credentials(client, configured):
    code = _v2_code(config.load_state())
    parsed = chain.parse_code(code)
    assert parsed["hy_port"] == 8448 and parsed["hy_pw"] == "quic-secret-1234"
    assert parsed["hy_sni"] == "us.example.com"
    assert parsed["port"] == 8447 and parsed["label"] == "美国落地"
    payload = json.loads(base64.urlsafe_b64decode(code.split("~")[1] + "=="))
    assert payload["v"] == 2 and payload["y"]["p"] == 8448 and payload["r"]["p"] == 8447

    # v1 (老版本生成的码) 照样认, QUIC 字段为空 —— 面板据此把选项置灰
    v1 = chain.parse_code(_fake_code(config.load_state()))
    assert v1["hy_port"] == 0 and v1["hy_pw"] == "" and v1["hy_sni"] == ""


@pytest.mark.parametrize(
    "bad, hint",
    [
        ({"p": 0, "w": "x", "n": "us.example.com"}, "QUIC 端口"),
        ({"p": 70000, "w": "x", "n": "us.example.com"}, "QUIC 端口"),
        ({"p": 8448, "w": "", "n": "us.example.com"}, "QUIC 密码"),
        ({"p": 8448, "w": "x", "n": "not a sni!"}, "QUIC SNI"),
    ],
)
def test_code_v2_rejects_broken_quic_fields(client, configured, bad, hint):
    """坏字段要在粘贴的那一刻说清楚, 不能等落地后客户端一直超时。"""
    reality = config.load_state()["reality"]
    payload = {
        "v": 2,
        "h": "203.0.113.9",
        "n": reality["server_name"],
        "l": "",
        "r": {
            "p": 8447,
            "u": str(uuid_mod.uuid4()),
            "k": reality["public_key"],
            "s": reality["short_id"],
            "f": "xtls-rprx-vision",
        },
        "y": bad,
    }
    raw = json.dumps(payload, separators=(",", ":")).encode()
    code = chain.CODE_SEP.join((chain.CODE_PREFIX, chain._b64e(raw), chain._checksum(raw)))
    with pytest.raises(chain.CodeError) as exc:
        chain.parse_code(code)
    assert hint in str(exc.value)


def test_exit_quic_toggle(client, configured):
    """落地端可以单独开关内层 QUIC; 配对码随之从 v1 变 v2, 关掉时密码一并作废。"""
    from zeroproxy import chain_quic

    body = client.post(
        "/api/chain/exit",
        json={"action": "generate", "port": 8666, "hy_enabled": True, "hy_port": 8667},
    ).json()
    ex = body["chain"]["exit"]
    assert ex["enabled"] and ex["hy_enabled"] and ex["hy_port"] == 8667
    assert ex["hy_available"] is (chain_quic.binary() is not None)
    first = chain.parse_code(ex["code"])
    assert first["hy_port"] == 8667 and first["hy_pw"]
    # 证书按配对码里的 SNI 现签: 两端对不上时 hysteria 服务端会直接 TLS 告警
    assert first["hy_sni"] == chain_quic.exit_sni(config.load_state())
    assert os.path.exists(paths_of()["chain_quic_cert"])
    # 放行步骤里要有 UDP 端口, 否则用户会一直以为是别的问题
    assert any("UDP" in s["name"] for s in body["steps"])

    off = client.post("/api/chain/exit", json={"action": "generate", "hy_enabled": False}).json()
    assert off["chain"]["exit"]["hy_enabled"] is False
    assert chain.parse_code(off["chain"]["exit"]["code"])["hy_port"] == 0

    again = client.post("/api/chain/exit", json={"action": "generate", "hy_enabled": True}).json()
    assert chain.parse_code(again["chain"]["exit"]["code"])["hy_pw"] != first["hy_pw"]


def paths_of():
    from zeroproxy.config import paths

    return paths()


def test_entry_quic_transport_wiring(client, configured, monkeypatch):
    """选 QUIC 内层: 入口出站变成本地 socks (交给面板托管的 hysteria 客户端)。"""
    from zeroproxy import chain_quic

    monkeypatch.setattr(chain_quic, "binary", lambda: "/usr/local/bin/hysteria")
    monkeypatch.setattr(chain, "probe_target", _ok_probe("203.0.113.9"))
    response = client.post(
        "/api/chain/entries",
        json={"code": _v2_code(config.load_state()), "transport": "hysteria2"},
    )
    assert response.status_code == 200, response.text
    entry = response.json()["chain"]["entries"][-1]
    assert entry["transport"] == "hysteria2" and entry["hy_socks_port"] > 0

    cfg = xray_config.build_xray_config(config.load_state())
    outbound = next(o for o in cfg["outbounds"] if o["tag"] == f"chain-out-{entry['id']}")
    assert outbound["protocol"] == "socks"
    assert outbound["settings"]["servers"][0]["port"] == entry["hy_socks_port"]
    assert outbound["settings"]["servers"][0]["address"] == "127.0.0.1"
    # 入口入站照旧是 VLESS Reality (客户端那一段不变)
    inbound = next(i for i in cfg["inbounds"] if i["tag"] == f"chain-{entry['id']}")
    assert inbound["streamSettings"]["security"] == "reality"

    # 切回 Reality: 出站变回 VLESS, 本地 socks 端口不再被引用
    back = client.post(
        f"/api/chain/entries/{entry['id']}", json={"transport": "reality"}
    ).json()
    same = back["chain"]["entries"][-1]
    assert same["transport"] == "reality"
    outbound = next(
        o for o in xray_config.build_xray_config(config.load_state())["outbounds"]
        if o["tag"] == f"chain-out-{entry['id']}"
    )
    assert outbound["protocol"] == "vless"


def test_entry_quic_needs_credentials_and_binary(client, configured, monkeypatch):
    from zeroproxy import chain_quic

    monkeypatch.setattr(chain, "probe_target", _ok_probe())
    # 配对码是 v1 (落地端没开 QUIC) → 明确拒绝, 而不是落一条注定不通的链
    no_creds = client.post(
        "/api/chain/entries",
        json={"code": _fake_code(config.load_state(), host="203.0.113.20"), "transport": "hysteria2"},
    )
    assert no_creds.status_code == 400 and "QUIC" in no_creds.json()["error"]

    monkeypatch.setattr(chain_quic, "binary", lambda: None)
    no_binary = client.post(
        "/api/chain/entries",
        json={"code": _v2_code(config.load_state(), host="203.0.113.21"), "transport": "hysteria2"},
    )
    assert no_binary.status_code == 400 and "hysteria" in no_binary.json()["error"]


HAVE_HYSTERIA = bool(os.environ.get("ZP_HYSTERIA2_BIN"))


@pytest.mark.skipif(not HAVE_HYSTERIA, reason="需要真实 hysteria 二进制 (ZP_HYSTERIA2_BIN)")
def test_quic_processes_start_and_stop(client, configured, monkeypatch):
    """真机路径: 面板托管的两个 hysteria 进程按配置起来 / 按配置停掉。"""
    from zeroproxy import chain_quic

    monkeypatch.setattr(chain, "probe_target", _ok_probe("203.0.113.9"))
    client.post("/api/chain/exit", json={"action": "generate", "port": 8666, "hy_enabled": True, "hy_port": 8667})
    entry = client.post(
        "/api/chain/entries",
        json={"code": _v2_code(config.load_state()), "transport": "hysteria2"},
    ).json()["chain"]["entries"][-1]
    try:
        ok, note = chain_quic.sync(config.load_state())
        assert ok, note
        assert chain_quic.running("exit") and chain_quic.running(f"entry-{entry['id']}")
        # 端口没被占: 落地端的证书也应该已经按 SNI 生成
        assert os.path.exists(paths_of()["chain_quic_cert"])

        client.post(f"/api/chain/entries/{entry['id']}", json={"enabled": False})
        ok, _ = chain_quic.sync(config.load_state())
        assert ok
        assert not chain_quic.running(f"entry-{entry['id']}")
        assert chain_quic.running("exit")          # 落地端不受影响
    finally:
        chain_quic.stop_all()
