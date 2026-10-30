"""状态健壮性 / 落地闭环并发语义的回归测试。

这些用例对应一次 BUG 排查里修掉的几类问题, 每一条都曾经能"静默地"坏事:

  1. state.json 被外部改坏 (字段类型不对) → 之前会让**每个**已登录请求 500,
     现在退化成"该字段用默认值";
  2. 同一个线程嵌套 `with config.locked():` → flock 是**按文件描述符**上锁的,
     第二次 open 再 LOCK_EX 会自己把自己阻塞死 (RLock 可重入骗了我们);
  3. 配置生成器直接 `open(path, "w")` 写盘 → 写一半崩溃就留下半个 config.json,
     Xray 从此起不来, 而这台机器往往是用户唯一能连出去的路;
  4. 后台落地任务的收尾落盘 → 整份旧快照写回, 把这几秒里用户改的开关覆盖掉。
"""
from __future__ import annotations

import copy
import json
import os
import threading

from zeroproxy import apply, chain_quic, config, routes


# ---------------------------------------------------------------- 1. 坏 state


def test_wrong_typed_fields_fall_back_to_defaults(home):
    """类型被改坏的字段必须保留默认值, 而不是把面板打挂。"""
    p = config.paths()
    os.makedirs(p["data_dir"], exist_ok=True)
    corrupted = {
        "configured": True,
        "domain": "proxy.example.com",
        "sessions": "not-a-dict",      # 之前: 每个已登录请求 AttributeError → 500
        "ports": [1, 2, 3],            # 之前: state["ports"]["reality"] → TypeError
        "nodes": "all-on",             # 之前: nodes.get(...) → AttributeError
        "audit": "oops",               # 之前: 审计分页遍历字符串
        "hysteria_ports": "30001",
        "uuid": 12345,                 # 之前: 拼订阅链接时 int.startswith → 500
        "configured_gate": None,
    }
    with open(p["state"], "w", encoding="utf-8") as fh:
        json.dump(corrupted, fh)

    state = config.load_state()

    assert isinstance(state["sessions"], dict)
    assert isinstance(state["ports"], dict) and state["ports"]["reality"] == 8443
    assert isinstance(state["nodes"], dict) and state["nodes"]["trojan"] is True
    assert isinstance(state["audit"], list)
    assert isinstance(state["hysteria_ports"], list)
    assert isinstance(state["uuid"], str)
    # 类型正常的字段照常恢复: 不能因为修坏字段就把好数据一起丢掉
    assert state["domain"] == "proxy.example.com"
    assert state["configured"] is True


def test_corrupted_state_does_not_break_authenticated_requests(client, configured):
    """sessions 被改坏之后, 仪表盘必须还能给出 401/200, 而不是 500。"""
    p = config.paths()
    state = config.load_state()
    state["sessions"] = "broken-on-purpose"
    with open(p["state"], "w", encoding="utf-8") as fh:
        json.dump(state, fh)

    response = client.get("/api/dashboard")
    assert response.status_code == 401, response.text


def test_deeply_nested_state_is_dropped_not_fatal(home):
    """上万层嵌套的 JSON 不能被收进 state: 否则之后每次 save_state 都在
    json.dump 里 RecursionError, 面板从此一次都存不了盘。"""
    p = config.paths()
    os.makedirs(p["data_dir"], exist_ok=True)
    with open(p["state"], "w", encoding="utf-8") as fh:
        fh.write('{"chain":' * 8000 + "{}" + "}" * 8000)

    state = config.load_state()          # 不抛异常
    assert isinstance(state["chain"], dict)
    assert "exit" in state["chain"], "过深的垃圾数据不能覆盖默认结构"
    config.save_state(state)             # 关键: 还能写回
    assert config.load_state()["chain"]["exit"]["enabled"] is False


# ---------------------------------------------------------------- 2. 锁可重入


def test_nested_locked_does_not_deadlock(home):
    """同一线程嵌套进入 locked() 不能死锁 (flock 不能重入)。"""
    config.save_state(config.load_state())
    done = threading.Event()
    error: list[BaseException] = []

    def worker() -> None:
        try:
            with config.locked():
                config.save_state(config.load_state())
                with config.locked():      # 以前这里会永久阻塞
                    state = config.load_state()
                    state["domain"] = "nested.example.com"
                    config.save_state(state)
        except BaseException as exc:  # noqa: BLE001 - 线程里要如实回报
            error.append(exc)
        done.set()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    assert done.wait(10), "嵌套 locked() 死锁了"
    assert not error, error
    assert config.load_state()["domain"] == "nested.example.com"


def test_lock_held_here_reports_nesting(home):
    assert config.lock_held_here() is False
    with config.locked():
        assert config.lock_held_here() is True
        with config.locked():
            assert config.lock_held_here() is True
        assert config.lock_held_here() is True
    assert config.lock_held_here() is False


# ---------------------------------------------------------------- 3. 原子写盘


def test_atomic_write_text_leaves_no_partial_file(home):
    target = os.path.join(config.paths()["xray_dir"], "atomic.txt")
    config.atomic_write_text(target, "hello", mode=0o600)
    with open(target, encoding="utf-8") as fh:
        assert fh.read() == "hello"
    assert os.stat(target).st_mode & 0o777 == 0o600
    leftovers = [n for n in os.listdir(os.path.dirname(target)) if n.startswith(".zp-")]
    assert leftovers == []


def test_generated_configs_are_valid_json(home):
    """真正走一遍生成器: 落盘的 config.json 必须是完整可解析的。"""
    from zeroproxy import xray_config

    state = config.load_state()
    state["uuid"] = "11111111-2222-3333-4444-555555555555"
    xray_config.write_xray_config(state)
    path = config.paths()["xray_config"]
    with open(path, encoding="utf-8") as fh:
        parsed = json.load(fh)
    assert "inbounds" in parsed
    # write_xray_config 不再自己保存 state —— 落盘由 apply.reapply 统一负责
    assert os.path.exists(path)


# ---------------------------------------------------------------- 4. 落地收尾


def test_apply_save_keeps_concurrent_changes(client, configured):
    """后台闭环收尾时, 不能用旧快照覆盖这几秒里别人写进 state 的改动。"""
    baseline = config.load_state()
    in_flight = copy.deepcopy(baseline)
    # 本次闭环自己的改动
    in_flight["nodes"]["trojan"] = False

    # 与此同时, 另一个请求 (例如用户点了「启停节点」) 已持锁落盘
    with config.locked():
        fresh = config.load_state()
        fresh["nodes"]["vless-ws"] = False
        config.save_state(fresh)

    # 闭环收尾 (此刻未持锁 → 后台任务路径, 只合并自己改过的字段)
    apply._save_merged(in_flight, baseline)

    final = config.load_state()
    assert final["nodes"]["trojan"] is False, "本次闭环的改动必须生效"
    assert final["nodes"]["vless-ws"] is False, "并发的改动不能被旧快照覆盖"


# ---------------------------------------------------------------- 5. 其它防御


def test_unknown_node_id_does_not_crash_dashboard(client, configured):
    """未知节点 id 不该让仪表盘 500 —— 少一个端口号比整页打不开好。"""
    state = config.load_state()
    assert routes._port_for(state, "no-such-node") == 0
    assert routes._port_for(state, "vless-ws") == 443
    assert routes._port_for(state, "vless-reality") == state["ports"]["reality"]


def test_running_claims_process_recorded_in_pid_file(home, monkeypatch):
    """apply 由别的进程拉起时, 面板内存里没有 Popen —— 要按 pid 文件认领。"""
    base = chain_quic.work_dir()
    os.makedirs(base, exist_ok=True)
    chain_quic._PROCS.clear()
    with open(os.path.join(base, "exit.pid"), "w", encoding="utf-8") as fh:
        fh.write(f"{os.getpid()} fingerprint-abc")
    monkeypatch.setattr(
        chain_quic, "_cmdline",
        lambda pid: f"/usr/local/bin/hysteria server -c {base}/exit.yaml",
    )
    assert chain_quic.running("exit") is True

    # pid 文件里是 0 / 不存在的进程 → 必须报"没在跑", 不能凭空乐观
    with open(os.path.join(base, "entry-x.pid"), "w", encoding="utf-8") as fh:
        fh.write("0 ")
    assert chain_quic.running("entry-x") is False
