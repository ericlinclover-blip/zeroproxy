# ZeroProxy v2.12.17 — BUG 修复执行报告

> 输入: `BUG_REPORT.md` 的 23 条结论 (P0×2 / P1×4 / P2×9 / P3×8)
> 执行方式: **逐条回到源码复核 → 属实的修 → 不属实的给出证据**: 不为了让报告"看起来都被采纳"而改代码。
> 验证: `pytest backend/tests` — **476 passed / 6 skipped**(原 466 条 + 新增 10 条回归用例)

---

## 一、已修复(按报告顺序)

### P0-1 `_merge()` 坏 state 防护 — 已修(问题本质与报告不同)

报告说"递归无上限会 `RecursionError`"。复核结论: 递归**只在 `key in base and isinstance(base[key], dict)` 时发生**,
而 DEFAULTS 只有 4 层, 所以递归深度天然有界 —— 这条本身不成立。但同一段代码里有一个**更严重**的真实缺陷:

```python
for key, value in extra.items():
    if key in base and isinstance(base[key], dict):
        ...; continue
    base[key] = value      # ← 只保护了 base 是 dict 的情况
```

即"默认值是标量 / 列表, 文件里却是别的类型"时会被**直接覆盖**。实测后果:

| 被改坏的字段 | 后果 |
|---|---|
| `"sessions": "not-a-dict"` | `_session_of` 里 `str.get()` → **每个已登录请求 500** |
| `"ports": [1,2,3]` | `state["ports"]["reality"]` → TypeError, 仪表盘 500 |
| `"nodes": "all-on"` | `nodes.get(...)` → AttributeError |
| `"configured": "no"` | 非空字符串在布尔判断里恒为真 → **初始化门禁失效** |

**修法** (`config.py`): 新增 `_kind()` 只接受与默认值同种类的值(区分 bool/number),
`_too_deep()` 丢弃深到 `json.dump` 会炸的嵌套, `_MERGE_MAX_DEPTH` 兜底递归;
`routes._session_of` 再加一层 `isinstance` 防御 (纵深防御: 内层 map 的 value 类型
`_merge` 管不到)。

### P0-2 配置落盘不是原子的 — 已修(报告说的"漂移"不成立)

报告说"`write_xray_config` 先写配置再写 state, 中间崩溃会漂移"。复核: `reapply()`
结尾本来就 `save_state()`, 且 `save_state` 是 tmpfile+fsync+rename, 所以**没有漂移**。
真正的缺陷是**配置本身不是原子写的**:

```python
with open(p["xray_config"], "w") as fh:   # 写一半崩溃/断电/磁盘满
    json.dump(...)                        # → 半个 config.json
```

半个 `config.json` / `config.yaml` 会让 Xray、Hysteria 2 **拒绝启动** —— 这台机器
往往就是用户唯一能连出去的路。nginx 有 snapshot 回滚, 这两个没有。

**修法**: `config.atomic_write_text()` / `atomic_write_json()`(同目录 mkstemp + fsync +
rename, 避开 `/tmp` 跨盘 `EXDEV`), 用于 `xray_config` / `hysteria_config` / `nginx_config`;
顺带去掉 `write_xray_config` 里那句"顺手 `save_state`"(它正是下面 P1-1 的 lost update 来源)。

### P1-1 落地闭环收尾覆盖并发改动 — 已修(属实, 且比报告更严重)

报告只提到"并发 apply 时快照过时"。实际更普遍: 后台闭环在锁外跑 2-4 秒, 收尾时
`save_state(state)` 把**几秒前的整份快照**写回 —— 这期间用户在面板上点的任何开关
(各自持锁落了盘) 都被静默覆盖。此前 `write_xray_config` 里那次提前 `save_state` 更早
就埋了同一个坑。

**修法** (`apply._save_merged`): 收尾重新 `load_state()`, **逐层**只覆盖"本次真正改过的叶子"。
粒度是关键 —— 两次节点开关改的都是 `state["nodes"]` 这一个字典, 按顶层整块覆盖仍会互相抹掉;
`audit` 单独按 id 求并集 (否则并发的登录/心跳记录被冲掉)。同时区分两条路径(见下条)。

### P1-4 `_port_for()` KeyError — 已修(仅防御价值)

复核: 唯一调用点 `_node_view` 的 node_id 来自 `NODES`, 正常路径不可达; 只有"前端缓存旧 id /
state 被改坏"才会触发, 一旦触发整个 `/api/dashboard` 500。改成取不到返回 0。

### P2-2 `chain_quic` 进程状态误报 — 已修(问题与报告不同)

报告说"`_PROCS` 存在退出竞态"。复核: `poll()` 本身就会回收子进程, 该竞态不成立。
真实缺陷是**反向漏报**: `apply` 由 `upgrade.sh` 拉起时是另一个进程, 它起的 QUIC 进程
只在 pid 文件里; `running()` 只看内存里的 `_PROCS` → 「一键诊断」把健康的链报成"未运行",
用户点「一键修复」再去抢同一个 UDP 端口。`running()` 现在会按 pid 文件认领。

### P2-8 `_ppid()` 非 Linux 恒为 0 — 已修

`/proc/<pid>/status` 只有 Linux 有。macOS/BSD 上 `_ppid` 恒 0 → `_reap_stale` 永远认不出
孤儿进程 → 面板崩溃后残留的 hysteria 一直占着 UDP 端口。补 `ps -o ppid=` 回退。

### P2-3 → 由 P0-1 的 `_MERGE_MAX_DEPTH` + `_too_deep` 一并覆盖

---

## 二、修复过程中新发现的真实缺陷(报告未提)

### N-1 `locked()` 嵌套会自死锁 — 已修

`threading.RLock` 可重入, 但 **flock 是按打开文件描述符上锁的**: 同一线程第二次
`os.open()` 同一锁文件再 `LOCK_EX` 会**永久阻塞自己**。而确实存在这条路径:
`apply` 命令行入口 `with config.locked(): reapply(...)`, reapply 收尾还要再进一次
`locked()`。此前没炸只是因为收尾用的是 `save_state`(不上 flock) —— 属于"随时会被下次改动引爆"的雷。

**修法**: `config._LOCK_DEPTH` (threading.local) 记录嵌套层数, 嵌套时复用外层锁;
公开 `config.lock_held_here()` 给收尾落盘判断"此刻有没有别的写入者"(见 P1-1 两条路径)。

### N-2 超深嵌套的 state.json 会让面板**再也存不了盘** — 已修

`{"a":{"a":…}}` 8000 层: `json.load` 能过, `_merge` 把它当"未知字段"整段收进 state,
之后每次 `save_state` 都在 `json.dump` 里 `RecursionError`。现在 `_too_deep()` 在收下
任何值之前量深度, 过深直接丢弃; `load_state` 同时把 `RecursionError` 归入 `StateError`(503 维护态)。

---

## 三、复核后**不成立**的结论(未改代码, 附证据)

| 结论 | 复核结果 |
|---|---|
| P1-2 `auto_tick` 双重写盘 | `update()`/`auto_tick()` 只改内存 state, **不 write**; 落盘只在 `_geodata_once` 一次, 且用 `merge_result` 保护 → 成立 |
| P1-3 WireGuard 地址冲突 | `allocate_address` 的 `used` 取自**全部** peer(含 disabled/expired), 地址不会被重复分配; `ensure_peer_addresses` 还会去重 |
| P2-1 公网 IP 首次失败要等 5 分钟 | 就是 `PUBLIC_IP_RETRY=300` 的设计意图(部署瞬间网络常未就绪), 非缺陷 |
| P2-4 镜像全缓存时显示"已是最新" | 已取 5 源**最大值**且权威源在前, 已是该场景的最优解 |
| P2-5 未初始化时 `_landing_body` 500 | `DEFAULTS` 恒有 `"domain": ""`, 不存在 KeyError 路径 |
| P2-6 自签证书 pin 为空 | Xray 26.3 已移除 `allowInsecure`, pin 读不到时"体检失败"是**fail-closed 的正确行为**, 不能改成放行 |
| P2-7 端口跳跃越界 | `_hopping_ports` 早已过滤 `if 1 <= p <= 65535`, 不存在 66000 |
| P2-9 心跳间隔 >90s 被误判离线 | `ONLINE_WINDOW=90` 与 `HEARTBEAT_WRITE_S=30` 组合是"写入降频 + 在线窗口"的正常设计 |
| P3-1 ANSI 颜色码 | `version_from_output` 开头就 `_ANSI_RE.sub("")` 剥掉了 |
| P3-2 `_log` 未 flush | `with open(...)` 退出即 flush+close |
| P3-3 异常时 steps 不完整 | `add_step` 捕获异常并记录, `reapply` 校验失败会置 `abort` 标记后 break —— 是设计 |
| P3-4 `total` 为 0 | `int(job.get("total") or len(...))` 已经兜住 |
| P3-5 `template_of` fallback | `(None or {})` 链是安全的 |
| P3-6 `bucket()` deepcopy | DEFAULTS["wireguard"] 只有十几个标量, 开销可忽略 |
| P3-7 `locked()` 父目录 | `locked()` 内先 `_ensure_dirs()` |
| P3-8 ufw 重复放行 | `ufw allow` 对已存在规则返回 0(`Rule already present`), 判成功正确 |

---

## 四、改动清单

| 文件 | 改动 |
|---|---|
| `backend/zeroproxy/config.py` | `_kind` / `_too_deep` / `_MERGE_MAX_DEPTH`; `_merge` 类型+深度防护; `_LOCK_DEPTH` + `locked()` 可重入 + `lock_held_here()`; `atomic_write_text/json`; `load_state` 捕获 `RecursionError` |
| `backend/zeroproxy/apply.py` | `_apply_changes` / `_merge_audit` / `_save_merged`(逐层合并 + 锁内/锁外两种权威语义) |
| `backend/zeroproxy/xray_config.py` | 原子写; 不再 `save_state` |
| `backend/zeroproxy/hysteria_config.py` | 原子写 |
| `backend/zeroproxy/nginx_config.py` | 原子写(含 fake index) |
| `backend/zeroproxy/chain_quic.py` | `running()` 按 pid 文件认领; `_ppid()` 补 `ps` 回退 |
| `backend/zeroproxy/routes.py` | `_session_of` 类型防御; `_port_for` 不再 KeyError |
| `backend/tests/test_state_robustness.py` | **新增** 10 条回归用例 |

## 五、回归用例覆盖

1. 类型被改坏的字段回落到默认值, 好字段照常恢复;
2. `sessions` 被改坏后 `/api/dashboard` 返回 401(而非 500);
3. 8000 层嵌套 state 不致命且**仍能 save_state**;
4. 嵌套 `locked()` 不死锁(10s 内完成) + `lock_held_here()` 语义;
5. `atomic_write_text` 无残留临时文件、权限正确;
6. 生成的 `config.json` 是完整可解析 JSON;
7. 后台闭环收尾**不覆盖**并发改动(同一 `nodes` 字典里两个不同键分别生效);
8. 未知节点 id 不再让仪表盘崩;
9. `running()` 能认领 pid 文件记录的进程、pid=0 时如实报"没在跑"。

## 六、验证边界(如实说明)

本机没有 `xray` / `hysteria` / `nginx` 二进制, 因此 **`scripts/verify.py` 的真实内核校验段
无法在本机执行**(它要求 `ZP_XRAY_BIN` / `ZP_HYSTERIA_BIN` 等), 本次验证全部走 dry-run 测试。
上线前建议在目标机执行一次:

```bash
ZP_XRAY_BIN=$(command -v xray) ZP_HYSTERIA_BIN=$(command -v hysteria) \
  python3 scripts/verify.py
```

重点确认: 原子写之后的 `config.json` 仍能通过 `xray -test`; `nginx -t` 通过(权限 0644 不受影响);
`python -m zeroproxy.apply` 在**持锁**状态下不再卡死(本次新增的嵌套锁路径)。
