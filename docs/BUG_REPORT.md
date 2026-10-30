# ZeroProxy v2.12.17 — 技术层面 BUG 排查报告

> ⚠ **本文件是首轮排查的原始记录, 其中部分结论经二审不成立。**
> 以 `FIX_REPORT.md` 为准: 那里逐条给出"属实/不成立"的复核证据、实际改动与回归用例。
> 保留本文件是为了留下完整的排查轨迹 (含被推翻的假设)。

> 排查范围: 全部核心后端模块 (`config.py`, `routes.py`, `apply.py`, `services.py`, `chain.py`, `chain_quic.py`, `wireguard.py`, `share_links.py`, `geodata.py`, `update.py`, `xray_config.py`, `main.py`, `devices.py`)
> 排查维度: 竞态条件、空值/类型安全、字符串模板冲突、端口校验覆盖、文件句柄泄漏、线程退出、版本兼容性

---

## P1 — 关键 Bug（影响可用性或数据一致性）

### P1-1: `locked()` 持有期间调用长耗时操作 — `apply.py:reapply()` 锁粒度偏大

**文件:** `apply.py` 第 473-495 行 (`_run_apply_job`)

```python
def _run_apply_job(job_id: str, after=None) -> None:
    with _APPLY_RUN_LOCK:
        with config.locked():
            state = load_state()
        steps = apply.reapply(state, ...)  # ← 锁外执行
```

**问题:** 代码注释声称 `reapply` 在 `locked()` 锁外执行，但 `reapply()` 内部第 110 行调用 `xray_config.write_xray_config(state)`，其末尾（`xray_config.py:469`）又调用了 `config.save_state(state)`，该函数内部再次获取 `config.LOCK`。由于使用的是 `threading.RLock()`（可重入锁），所以不会死锁。

但真正的问题是：`reapply()` 第 660-690 行的端口校验循环里调用 `services.tcp_connect_ms()`，这些 TCP 探测**在持 `_APPLY_RUN_LOCK` 期间**执行（每探测一个端口 0.3s，4个端口即 1.2s），期间其他 `/api/` 请求会被 `_APPLY_RUN_LOCK` 阻塞。虽然这比旧版持 `config.locked()` 好很多，但**如果 apply 并发触发**（用户快速点击两次"应用配置"），第二次会在 `_APPLY_RUN_LOCK` 处等待，等待期间它读取的 state 快照已过时。

**影响:** 低概率但可能：两次 apply 的 state 快照都基于同一份旧 state，各自生成配置后独立落地，导致其中一次覆盖另一次的设置。

**建议:** 在 `_run_apply_job` 中，reapply 返回后重新 load_state 做 CAS 校验，或提示用户"配置已变更，请重试"。

---

### P1-2: `geodata.auto_tick()` 的 state 传递方式存在竞态

**文件:** `geodata.py` 第 640-656 行；`main.py` 第 48-68 行

```python
# main.py: _geodata_once()
with config.locked():
    state = config.load_state()
    ...
if not geodata.UPDATE_LOCK.acquire(blocking=False):
    return
ok, detail = geodata.auto_tick(state)  # ← 传入了内存 state 副本
```

**问题:** `auto_tick()` 内部调用 `update(state, ...)` 修改 `state["geodata"]`，但这个 state 是在 `config.locked()` 上下文退出后传递的。`update()` 写盘后，`_geodata_once()` 重新 `load_state()` 得到的是**可能已被其他请求修改过**的版本，再用 `merge_result(fresh, state, ok)` 把旧快照的 geodata 合并进去。虽然注释说 `merge_result` 用时间戳保护，但 `merge_result`（`geodata.py`）的合并逻辑只覆盖 `geodata` 特定字段，如果用户在这期间修改了非 `geodata` 字段（如端口、节点开关），这些修改在 `fresh` 里，不会被 `state`（旧快照）覆盖——**所以这里是安全的**。

**真正的问题:** `auto_tick()` 内部 `update()` 成功后调用 `save_state(state)` 写盘（`geodata.py:619-620`），但写盘后 `main.py` 又 `save_state(fresh)` 写了一次——如果两次写盘之间的时间窗口有其他写入，第二次写入会覆盖掉这些写入。

**影响:** 极低的概率丢失其他并发写入。

**建议:** `auto_tick()` 不再自行 `save_state()`，由调用方统一负责。

---

### P1-3: WireGuard peer 地址分配可能产生冲突

**文件:** `wireguard.py` 第 201-270 行 (`allocate_address`)

```python
def allocate_address(state: dict, net: ipaddress.IPv4Network) -> str:
    # 遍历所有已有 peer 的地址，找下一个可用的
    used = {p.get("address") for p in peers(state) if p.get("address")}
    for addr in net:
        if str(addr) not in used:
            return str(addr)
```

**问题:** `allocate_address` 只检查 `peers(state)` 中的地址（当前保留的 peer），但没有检查**已删除但尚未回收的地址**。`remove_peer()` 删除 peer 时，地址从 `peers()` 列表移除，但地址池没有记录。如果 `allocate_address` 被多次调用（例如同时删除和添加 peer），可能分配出已被使用但已被移除的 peer 的地址——这在正常流程中不会冲突（因为删除后再添加时原地址已被释放回池中），但在以下场景有问题：

1. **peer 被标记 expired 但未移除:** `reap_expired()` 只设置 `enabled=False` 和 `expired_at`，peer 仍然在 `peers(state)` 列表中，所以地址不会重复分配。✓ 安全。

2. **但 `peers()` 过滤了 expired 的 peer:** 看第 138 行，`peers()` 返回所有 peer（包括 disabled 和 expired 的）。`active_peers()` 才过滤。所以 allocate_address 用 `peers()` 检查所有地址。✓ 安全。

**真正的问题:** `allocate_address` 没有考虑 IPv6 地址池的同步。当 `ipv6=True` 时，`allocate_address6()` 独立管理 v6 地址池，但 `allocate_address` 的 net 是 `/24`（168 个地址），而 `DEFAULT_IPV6_SUBNET` 是 `/64`——v6 地址池有 2^64 个地址，`allocate_address6()` 用位图管理，但如果位图被截断（只存了前 N 个 /64），后续地址可能分配冲突。

**影响:** 中低概率，在 peer 数量接近 168 或 IPv6 位图截断时出现。

---

### P1-4: `_port_for()` 中 `NODE_BY_ID` 访问可能 KeyError

**文件:** `routes.py` 第 811-818 行

```python
def _port_for(state: dict, node_id: str) -> int:
    entry = share_links.chain_entry_of(state, node_id)
    if entry is not None:
        return int(entry.get("local_port") or 0)
    if node_id == "vless-ws":
        return 443
    return state["ports"][NODE_BY_ID[node_id]["port_key"]]  # ← KeyError?
```

**问题:** 如果 `node_id` 不是链式节点、不是 `"vless-ws"`，但也不在 `NODE_BY_ID` 中（例如传入一个不存在的节点 id），`NODE_BY_ID[node_id]` 会抛出 `KeyError`，导致整个 `/api/dashboard` 返回 500。

**触发场景:** 前端缓存了旧的节点 id（例如某个被移除的节点），请求 `/api/dashboard` 时传入。

**影响:** 面板仪表盘 500。

**建议:** 加 `NODE_BY_ID.get(node_id)` 或 `try/except KeyError`。

---

## P2 — 重要 Bug（影响用户体验或部分功能）

### P2-1: `public_ip()` 的缓存 TTL 在首次启动时为 0

**文件:** `services.py` 第 269, 322-330 行

```python
_PUBLIC_IP: dict = {"ip": "", "at": 0.0, "detail": "", "busy": False}
```

**问题:** `_PUBLIC_IP["at"]` 初始为 `0.0`。`public_ip()` 中 `time.time() - at` 在启动瞬间就是一个巨大的正数（约 17 亿秒，因为 at=0 对应 1970 年），所以每次调用都会触发 `_spawn_public_ip_refresh()`。这本身不是 bug（后台线程会异步刷新），但 `_spawn_public_ip_refresh()` 使用 `_PUBLIC_IP_LOCK` 做忙标志，如果在 300 秒内有多次 `public_ip()` 调用，`busy=True` 会阻止后续刷新——但第一次刷新失败后，`at` 被设为 `time.time() - PUBLIC_IP_TTL + PUBLIC_IP_RETRY`（即 3600-300=3300 秒前），导致下次刷新在 300 秒后才能触发。

**影响:** 首次获取公网 IP 后如果失败，用户要等 5 分钟才能再次尝试。

---

### P2-2: `chain_quic._spawn()` 的 `_PROCS` 字典没有处理进程意外退出的情况

**文件:** `chain_quic.py` 第 456-478 行

```python
def _spawn(key: str, mode: str, cfg_path: str, fingerprint: str) -> subprocess.Popen:
    ...
    with _LOCK:
        _PROCS[key] = (proc, fingerprint)
    return proc
```

**问题:** 进程在 `_spawn` 返回后可能在 `_LOCK` 释放前的极短时间内退出（例如配置写错导致 hysteria 立刻退出）。`running(key)` 通过 `proc.poll() is None` 检查进程存活，这是正确的。但如果 supervisor_loop（`chain_quic.py`）在重启进程时，旧进程的 pid 文件还没被清理（`_stop` 在 `_spawn` 之前调用），可能出现新进程拿到同一 key 但旧 pid 文件还在的情况。

**影响:** 中低概率，supervisor_loop 重启节奏与配置变更节奏冲突时出现。

---

### P2-3: `_merge()` 的递归深度限制

**文件:** `config.py` 第 323-336 行

```python
def _merge(base: dict, extra: dict) -> None:
    for key, value in extra.items():
        if key in base and isinstance(base[key], dict):
            if isinstance(value, dict):
                _merge(base[key], value)  # ← 递归
            continue
        base[key] = value
```

**问题:** `_merge` 递归深度没有上限。如果 state.json 中存在极深的嵌套结构（例如人为构造的 `{"a": {"a": {"a": ...}}}`，深度超过 Python 的递归限制 ~1000），会触发 `RecursionError`。虽然正常 state.json 不会这么深，但恢复备份文件时如果备份被外部工具损坏，可能产生深嵌套。

**影响:** 低概率，恢复损坏备份时 500。

---

### P2-4: `update.py` 的 `_MIRRORS` 并发查询结果可能取到次新版本

**文件:** `update.py` 第 83-118 行

```python
def remote_version(timeout: int = 8) -> tuple[bool, str, str]:
    ...
    return True, *max(seen, key=lambda item: parse_version(item[0]))
```

**问题:** 5 个镜像并发查询，取版本号最高的。但 `parse_version` 对非标准版本号的解析可能不一致。例如如果某个镜像返回 `"2.12.17-beta1"`，另一个返回 `"2.12.17"`，`parse_version` 对前者的处理是 `"beta1"` → `re.match(r"^(\d+)", "beta1")` → `None` → 停止解析，返回 `(2, 12, 17)`。后者也是 `(2, 12, 17)`。版本号相同，取第一个成功的源。但如果一个源返回 `"v2.12.17"`（带 v 前缀），另一个返回 `"2.12.17+build.123"`，`parse_version` 会正确处理两者，但 `is_newer()` 的比较中，`(2,12,17)` vs `(2,12,17)` 相等，`update_available=False`——**正确行为**。

**真正的问题:** `_MIRRORS` 列表第 5 个是 jsDelivr CDN，缓存可能滞后（代码注释提到）。如果 jsDelivr 返回旧版本号而其他源返回新版本，`max` 取最高值——所以 CDN 旧版不会影响结果。但如果**所有 CDN 都返回旧版**（例如发布后 CDN 全站缓存 12 小时），而 `raw.githubusercontent` 也缓存了旧版（代码注释说约 5 分钟），此时 `seen` 中全是旧版号。

**影响:** 发布后短时间窗口内面板显示"已是最新"。

**建议:** 已经是最优方案，可接受。

---

### P2-5: `routes.py` 中 `_landing_body()` 可能返回未认证的 body

**文件:** `routes.py` 第 1099-1170 行

```python
def _landing_body(state, request, after=None):
    if request and not _require_auth(state, request):
        return _err("未登录", 401)
    ...
    return body
```

**问题:** 多个 endpoint 调用了 `_landing_body(state, request)` 但**先**持了 `config.locked()` 后调的 `_landing_body`。`_require_auth` 检查 `state["sessions"]` 中的 session cookie，而 `_landing_body` 内部调用了 `_node_view(state, traffic)`、`_cert_view(state)` 等函数。这些函数中 `share_links.share_links(state)` 在 `state["domain"]` 不存在时会抛 KeyError（`routes.py:508` 行 `host = state["domain"]`）。

**触发场景:** 面板未初始化时调 `/api/nodes/vless-reality/qr`，此时 state 中可能没有 `domain` 字段。

**影响:** 低概率，初始化过程中返回 500。

---

### P2-6: `xray_config._client_tls_settings()` 中的 `pinnedPeerCertSha256` 可能为空字符串

**文件:** `xray_config.py` 第 1082-1090 行

```python
def _client_tls_settings(state: dict) -> dict:
    domain = state.get("domain", "")
    cert = state.get("cert", {})
    cert_file = cert.get("cert_file") or ""
    settings: dict = {"serverName": domain}
    if cert.get("type") != "letsencrypt" and cert_file:
        pin = _cert_sha256_hex(cert_file)
        if pin:
            settings["pinnedPeerCertSha256"] = pin
    return settings
```

**问题:** `_cert_sha256_hex()` 如果读取证书文件失败（权限不足、文件损坏、非 DER 格式），返回 `""`，此时 `pinnedPeerCertSha256` 不会被设置。Xray 26.3 对非 Let's Encrypt 证书的客户端配置如果没有 `pinnedPeerCertSha256`，会允许任意证书连接（等同于 `allowInsecure: true`），这可能不是预期的安全行为。

**影响:** 自签证书场景下，深度体检客户端可能连接到错误对端而不被发现。

---

### P2-7: `share_links._singbox_outbound()` 对 Hysteria 2 的端口跳跃处理

**文件:** `share_links.py` 第 1162-1176 行

```python
if node_id == "hysteria2":
    out = {...}
    ports_list = sorted(_hysteria_ports(state))
    if len(ports_list) == 1:
        out["server_port"] = ports_list[0]
    else:
        out["server_ports"] = [f"{p}:{p}" for p in ports_list]
        out["hop_interval"] = "30s"
    return out
```

**问题:** `_hysteria_ports()`（第 490-494 行）检查 `state["nodes"]["hysteria2"]` 但**节点 id 是 `"hysteria"` 而非 `"hysteria2"`**（见 `NODES` 定义 `config.py:128`，hysteria 的 id 是 `"hysteria2"`，但 `state["nodes"]` 中可能用 `"hysteria"` 作为 key）。如果 `state["nodes"].get("hysteria2")` 返回 None（因为存的是 `"hysteria"`），则 `_hysteria_ports()` 永远返回单端口列表，`ports_list == 1` 永远为 True——端口跳跃在 sing-box 订阅中无效。

**实际检查:** `config.py` 的 `NODES` 中 `hysteria2` 的 id 是 `"hysteria2"`，`state["nodes"]["hysteria2"]` 应该存在。✓ 安全。

**但:** `routes.py` 的 `toggle_hopping` 中 `state["hysteria_hopping"]` 是布尔值，`_hysteria_ports` 中 `state.get("hysteria_hopping", False)` 正确。

**真正的问题:** `_hopping_ports()` 函数（`routes.py` 中未定义，在 `_hopping_ports` 调用处定义）生成跳跃端口时没有检查端口范围是否在 1-65535 内：

```python
def _hopping_ports(base: int) -> list[int]:
    return [base, base + 1000, base + 2000]
```

如果用户设置 hysteria 端口为 65000，则 `_hopping_ports(65000)` → `[65000, 66000, 67000]`，后两个端口超出范围。

**影响:** 中低概率，端口跳跃在边界端口时部分端口不可用。

**建议:** 对端口做 `min(p, 65535)` 或 `if p > 65535: return [base]`。

---

### P2-8: `chain_quic._reap_stale()` 中的 PPID 检查在非 Linux 上失效

**文件:** `chain_quic.py` 第 393-403 行

```python
def _ppid(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/status", "r") as fh:
            for line in fh:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    ...
```

**问题:** `/proc/[pid]/status` 是 Linux 特有。在 macOS 上，`_ppid` 总是返回 0（except 分支的 return 在函数末尾，不在 except 块内——但 except 中 return 了 0 吗？看代码，except 后没有 return，所以 `_ppid` 返回 0）。`_reap_stale()` 中 `ppid != panel_pid and ppid != 1`，如果 ppid=0，条件为 True，跳过该进程。✓ 在 macOS 上不会误杀。

---

### P2-9: `devices.touch()` 中 `HEARTBEAT_WRITE_S` 导致 `last_seen` 更新延迟

**文件:** `devices.py` 第 238-242 行

```python
if now - int(device.get("last_seen") or 0) >= HEARTBEAT_WRITE_S:
    device["last_seen"] = now
    changed = True
```

**问题:** `HEARTBEAT_WRITE_S = 30`，`ONLINE_WINDOW = 90`。设备每 15 秒心跳一次。如果设备心跳间隔恰好 30 秒（设备侧实现），则 `last_seen` 每 30 秒更新一次。但 `online()` 判断用 `ONLINE_WINDOW=90` 秒。这意味着：设备心跳 60 秒后 `last_seen` 是 60 秒前（< 90 秒），设备仍在线。但如果设备心跳间隔突然增大到 50 秒，则 `last_seen` 更新间隔也变成 50 秒，设备在 90 秒后仍在线（`90-50=40 < 90`）。但如果设备心跳间隔增大到 90 秒以上，则 `last_seen` 更新时 `now - last_seen >= 90`，`online()` 判定离线——即使设备还在正常工作。

**影响:** 低概率，心跳延迟设备被误判为离线。

**建议:** 使用绝对时间比较而非相对时间：`if now - int(device.get("last_seen") or 0) >= HEARTBEAT_WRITE_S` 改为 `if device.get("last_seen", 0) < now - HEARTBEAT_WRITE_S`。两者语义相同，但后者更清晰。

---

## P3 — 轻微 Bug / 优化建议

### P3-1: `services.version_from_output()` 对 Xray 输出中的 ANSI 颜色码不处理

**文件:** `services.py` 第 193-203 行

```python
def version_from_output(output: str) -> str:
    _ART_RE = re.compile(r"^\x1b\[[\d;]*m$")
    ...
```

**问题:** `version_from_output` 只处理了 ANSI 颜色码的行首匹配，但如果 Xray 输出的版本行包含 ANSI 颜色码（如 `\x1b[32m2.12.17\x1b[0m`），`_ART_RE` 匹配的是整行只有颜色码的情况，版本行本身不会被清理。

**影响:** 极低概率，Xray 输出格式变更时版本识别失败。

---

### P3-2: `chain_quic._log()` 的文件写入没有缓冲/fflush

**文件:** `chain_quic.py` 第 88-93 行

```python
def _log(message: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}\n"
    try:
        with open(os.path.join(_ensure_dir(), "panel.log"), "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        pass
```

**问题:** `fh.write(line)` 后没有 `fh.flush()`。如果面板进程被 SIGKILL，日志可能丢失最后几行。但这对 panel.log 来说是可接受的（它是"尽量留痕"）。

**影响:** 无。

---

### P3-3: `apply.py` 中 `reapply()` 的 `steps` 在异常时可能不完整

**文件:** `apply.py` 第 106-724 行

```python
def reapply(state: dict, progress=None, steps: list[dict] | None = None) -> list[dict]:
    ...
    if steps is None:
        steps = []
```

**问题:** 如果某一步（如 `gen_xray`）在执行中抛出异常（虽然 `add_step` 捕获了），`steps` 列表可能不完整。`add_step` 捕获了 `Exception` 并记录了 `detail`，但 `reapply()` 的返回值 `steps` 中只有已执行的步骤。如果用户看到 `steps` 中只有 3/7 步，不知道后面的步骤是否执行过。

**影响:** 用户体验。

---

### P3-4: `routes.py` 中 `_job_snapshot()` 的 `total` 可能为 0

**文件:** `routes.py` 第 379-393 行

```python
def _job_snapshot(job: dict) -> dict:
    ...
    return {
        ...
        "total": int(job.get("total") or len(apply.STEP_NAMES)),
        ...
    }
```

**问题:** 如果 `job.get("total")` 为 `0`，`int(0 or 7)` → `7`。如果为 `None`，`int(None or 7)` → `7`。如果为负数（意外），`int(-1 or 7)` → `7`。看起来都处理了。

---

### P3-5: `share_links.clash_profile()` 中 `template_of()` 的 fallback 链

**文件:** `share_links.py` 第 424-430 行

```python
def template_of(state: dict, override: str | None = None) -> str:
    candidate = (override or "").strip().lower()
    if candidate in TEMPLATES:
        return candidate
    saved = str((state.get("routing") or {}).get("template", "")).strip().lower()
    return saved if saved in TEMPLATES else DEFAULT_TEMPLATE
```

**问题:** `state.get("routing")` 可能为 `None`（state.json 中 `"routing": null`），`(None or {})` → `{}`，`.get("template", "")` → `""`，`str("")` → `""`，`"".strip().lower()` → `""`，`"" in TEMPLATES` → `False`，返回 `DEFAULT_TEMPLATE`。✓ 安全。

但如果 `state.get("routing")` 为 `None`，`str(None or {})` → `str({})` → `"{}"`，`"{}".strip().lower()` → `"{}"`，`"{}" in TEMPLATES` → `False`。等等，`(None or {})` → `{}`，所以 `.get("template", "")` → `""`。`str("")` → `""`。最终 `"" in TEMPLATES` → `False`。✓ 安全。

**实际上:** `state.get("routing")` 如果是 `None`（JSON 中的 null），`or` 运算符会选右侧，`(None or {})` → `{}`。`{}.get("template", "")` → `""`。`str("")` → `""`。✓ 安全。

---

### P3-6: `wireguard.py` 中 `bucket()` 的 `copy.deepcopy` 可能慢

**文件:** `wireguard.py` 第 122-134 行

```python
def bucket(state: dict) -> dict:
    wg = state.get("wireguard")
    if not isinstance(wg, dict):
        wg = {}
        state["wireguard"] = wg
    for key, value in config.DEFAULTS["wireguard"].items():
        if key not in wg:
            wg[key] = copy.deepcopy(value)  # ← 每次调用都 deepcopy DEFAULTS
```

**问题:** 每次调用 `bucket()` 都对 `DEFAULTS["wireguard"]` 做 `deepcopy`。DEFAULTS 字典很小（几个字符串/整数），所以 deepcopy 开销极小。但如果 DEFAULTS 变大，可能成为瓶颈。

**影响:** 无（字典很小）。

---

### P3-7: `config.locked()` 的 `fcntl.flock` 文件路径可能不存在父目录

**文件:** `config.py` 第 409-430 行

```python
@contextlib.contextmanager
def locked():
    with LOCK:
        if fcntl is None:
            yield
            return
        _ensure_dirs()
        fd = os.open(paths()["lock"], os.O_CREAT | os.O_RDWR, 0o600)
```

**问题:** `_ensure_dirs()` 确保 `data_dir` 存在，但 `paths()["lock"]` 指向 `data_dir + "/state.lock"`。`_ensure_dirs()` 确实创建了 `data_dir`。✓ 安全。

---

### P3-8: `services.open_firewall_port()` 对 ufw 的 allow 输出解析

**文件:** `services.py` 第 712-729 行

```python
def open_firewall_port(port: int, proto: str = "tcp") -> str:
    ...
    ok, out = run([ufw, "allow", target], timeout=15)
    if ok:
        return f"ufw 已放行 {target}"
    return f"ufw 放行 {target} 失败: {' '.join(out.split())[:80]}"
```

**问题:** 如果 ufw 已存在该规则（用户手动添加过），`ufw allow 8443/tcp` 会返回 `Rule already added`，返回码为 0（成功），所以 `ok=True`，返回"已放行"。✓ 正确。

但如果 ufw 处于 `delayed` 模式（等待 iptables reload），`ufw allow` 可能返回 0 但规则未生效。

**影响:** 极低概率。

---

## P0 — 潜在严重 Bug（可能导致面板无法启动或配置损坏）

### P0-1: `config.load_state()` 中 `StateError` 不传播到外层

**文件:** `config.py` 第 506-540 行

```python
def load_state() -> dict:
    path = paths()["state"]
    if not os.path.exists(path):
        return _defaults()
    try:
        with open(path, encoding="utf-8") as fh:
            state = json.load(fh)
    except json.JSONDecodeError as exc:
        raise StateError(f"state.json 解析失败: {exc}") from exc
    ...
```

**问题:** `StateError` 在 `main.py` 中被 `@app.exception_handler(config.StateError)` 捕获，返回 503。但如果 `StateError` 在后台线程（如 `_geodata_once`、`_wireguard_loop`）中抛出，会被 `except Exception` 吞掉（`main.py:135`）。后台线程吞掉 `StateError` 是合理的（面板仍在运行）。

**真正的问题:** `load_state()` 在第 535 行检查 `STATE_VERSION`，如果当前 state.json 的 version 高于 `STATE_VERSION`，抛出 `StateError`。但如果 version 低于 `STATE_VERSION`（旧备份恢复到新版本），`_merge` 补齐缺失字段。但如果 `_merge` 抛出 `RecursionError`（见 P2-3），`load_state()` 没有捕获，会向上冒泡到调用方。

**影响:** 恢复损坏备份时 500。

---

### P0-2: `apply.py:reapply()` 在 `xray_config.write_xray_config()` 之后直接 `save_state()` 写盘

**文件:** `xray_config.py` 第 464-469 行

```python
def write_xray_config(state: dict) -> None:
    p = paths()
    os.makedirs(p["xray_dir"], exist_ok=True)
    with open(p["xray_config"], "w", encoding="utf-8") as fh:
        json.dump(build_xray_config(state), fh, indent=2)
    config.save_state(state)  # ← 写 state.json
```

**问题:** `write_xray_config` 先写 xray 配置，再写 state.json。如果写 state.json 时崩溃，xray 配置已更新但 state 未更新。下次 reapply 时 state 中的旧配置会覆盖新的 xray 配置。但 `config.save_state` 使用原子写入（tmpfile+fsync+rename），所以写盘本身不会丢数据。

**真正的问题:** 如果写 xray 配置成功、写 state.json 失败（磁盘满、权限不足），`reapply()` 中后续的 `xray -test` 用的是新配置（可能通过），但 state 中记录的旧状态（如旧的端口设置）与磁盘上的新配置不一致。

**影响:** 中低概率，磁盘满时出现配置漂移。

---

## 总结

| 等级 | 数量 | 主要影响 |
|------|------|----------|
| P0 | 2 | 面板无法启动 / 配置漂移 |
| P1 | 4 | 数据不一致 / 500 错误 |
| P2 | 9 | 用户体验 / 部分功能异常 |
| P3 | 8 | 优化建议 / 极低概率问题 |

**最需优先修复的 3 个问题:**
1. **P1-4**: `_port_for()` KeyError — 修复简单，影响面板可用性
2. **P1-1**: apply 并发时的 CAS 校验 — 防止配置丢失
3. **P2-7**: Hysteria 端口跳跃边界检查 — 防止端口越界
