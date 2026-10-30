# ZeroProxy v2.12.17 — 二轮排查报告（首轮未覆盖面）

> 范围: 首轮未审/半审的约 5.5k 行 —— `router_client.py`(1881, 首轮完全没进范围)、
> `routes.py` 2200 行之后(设备/订阅/备份/路由/维护端点)、`cli.py`、`dae_config.py`、
> `crypto.py`、`account.py`, 外加首轮半审模块的补齐复核。
> 方法: 三路并行只读审计(子代理) + 我自己复核每一条结论**再决定改不改**。
> 验证: `pytest backend/tests` → **486 passed / 6 skipped**(首轮结束时 476)。

---

## 一、已修复(复核属实, 15 条)

### 安全面

| # | 问题 | 影响 | 修法 |
|---|---|---|---|
| 1 | `crypto.derive_uuid` 把**管理员口令**做单轮 SHA-256 当 VLESS UUID, 而 UUID 随每条订阅链接发给每个客户端 | 任何拿到订阅的人可按 SHA-256 速率离线爆破口令, PBKDF2-120k 被完全绕过(口令下限仅 6 位) | `setup` 改用随机 `uuid4`; `derive_uuid` 标注废弃 |
| 2 | `wireguard_peer_update` 改名**绕过** `_clean_name`, 换行原样进 `wg0.conf` 注释行 | 首个 peer 时注入的 `PostUp = …` 落在 `[Interface]` 段, `wg-quick up` 以 root 执行 → 面板管理员 → root | 改名走新的 `wireguard.clean_name()` |
| 3 | 口令哈希串不记录迭代次数, `verify` 永远用硬编码 120k 重算 | 以后调高迭代次数 → **所有存量口令验证失败**, 面板登录全挂 | 格式改 `pbkdf2$<iters>$<salt>$<digest>`, 兼容老 3 段 + `password_needs_rehash()` |
| 4 | `/sub/{token}` 与 `/c/{code}` 用 `hmac.compare_digest` 比对 **str** | 非 ASCII 输入(`/sub/中文`)抛 TypeError → 500 | 先 encode 成字节再比 |

> 第 2 条我复核了完整链路才确认: 名字确实进 `server_config()` 的 `# {name}` 行,
> 且 `wg-quick up` 的 `PostUp` 以 root 执行。新增 peer 的路径本来就走净化, 只有"改名"漏了。

### 配置/流程正确性

| # | 问题 | 影响 | 修法 |
|---|---|---|---|
| 5 | 分流数据下载**不比对 Content-Length** | 中途断流的半个 `geosite.dat`(真实 4 MB、闸门 2 MB)会被当成新鲜缓存用满 7 天 → 每台路由器的 mihomo 配置都起不来 | 声明了长度就必须收满, 否则换镜像 |
| 6 | `perf_ready`/`perf_cached_file` 用**子串**匹配架构 | 请求 `mips` 命中 `dae-mipsle`; `perf_ready` 永远为真 → 再也不会去下正确那份, 路由器执行报 Illegal instruction | 改为 `^dae-<arch>-…\.gz$` 整段锚定 |
| 7 | dae 的 `.gz` 直接写最终路径 | 中断留下的半个文件高于 `perf_ready` 门槛(1.5 MB vs 真实 8 MB)→ 判"已缓存", 永不自愈 | 改 `tmp + os.replace` |
| 8 | `dae_config` 在 `geo=False` 降级分支**仍引用 `geoip:private`** | 降级分支存在的唯一场景就是"面板还没有数据文件", 而 dae 读不到 geoip.dat 是**整份配置校验失败** → 性能模式永远切不过去 | 降级时改用显式私网 CIDR(10/8、172.16/12、192.168/16、127/8、169.254/16、fc00::/7、fe80::/10); 并**改掉了把错误假设固化的那条测试断言** |
| 9 | `restore` 的"失败回滚"是**死代码** | `apply.reapply` 用 `add_step` 把每步异常都吞成 `ok=False`, 自己从不抛 → except 永不触发, 坏配置留在盘上 | 改成按步骤结果判断: 生成/校验类步骤失败即回滚 |
| 10 | `restore` 只校验 `chain` 是对象, `entries=[{}]` 也能过 | 落盘后 `_dash_fingerprint` 取 `e['id']` → 仪表盘/诊断**永久 500** 且已无法回退 | 逐项校验 entries(dict + id + local_port 整数); `_dash_fingerprint` 也加防御 |
| 11 | `_wg_reply` 在锁外整份 `save_state` 旧快照 | 前面的 `ufw` 调用最长 25 秒, 期间登录会话/设备心跳/配对码的写入**被静默覆盖** | 重新读最新 state, 只并回"步骤记录 + WireGuard 段" |
| 12 | WireGuard 两个脚本的 IPv6 分支漏了 `f` 前缀(首轮遗留自查) | 生成脚本里是字面量 `{INTERFACE}`: 管道给 awk 后退出码仍是 0, 所以**"禁用 IPv6 后清理旧 v6 地址"从来没生效过**, 且每次 reload 往 journal 丢一条设备不存在 | 补 `f` 前缀; 新增"脚本无占位符 + `sh -n` 通过"回归用例 |
| 13 | `udp_port_listening` 读完 `/proc/net/udp` 就下结论(自查) | 只监听 IPv6 的进程被判"没在监听" | 两张表都看完; 都读过且没有才返回 False |
| 14 | `cli` 菜单在 EOF/Ctrl-C 下**死循环** | `z </dev/null`、管道调用、或菜单里按 Ctrl-C: 每圈跑一次 `load_state` + `systemctl`, 退不出去 | EOF 用哨兵值与"空回车"区分 |
| 15 | `cli` 不处理 `StateError` | state.json 损坏时 `z status` / `z` 直接打 traceback —— 这恰恰是"最后的兜底通道" | `main` 统一兜成一句人话 + 退出码 1 |

---

## 二、确认属实、但**本轮没改**(需单独排期)

| 优先级 | 问题 | 为什么先不动 |
|---|---|---|
| **P1** | `/c/btf` 匿名端点在请求线程里同步跑最长 ~110s 上游抓取, 无并发合并/负缓存; 40 并发即可饿死整个同步端点池(`/c/bin`、`/c/geo`、`/c/perf` 都是"503 + 后台取"的正确写法) | 要对齐成 `ensure_btf_async` + 状态机, 还要处理客户端 180s 超时重试; 与下面三条 BTF 问题一起改才不返工 |
| P2 | `btf_fetch` 是唯一无锁/无状态机的下载路径, 并发共享同一个 `.part`, 一个线程的 `finally: remove(tmp)` 会删掉另一个线程正在写的文件 | 同上 |
| P2 | `btf_sums_lookup` 在"开始下载前"就写时间戳, 并发调用拿到空串后 `btf_verify` 按"上游没给摘要"**放行**(供应链闸门 fail-open) | 同上 |
| P2 | BTF 宣称的 90s 硬上限不覆盖摘要清单查询(6 镜像×25s), 最坏 240s 挂住请求线程 | 同上 |
| P2 | `repair`/`diagnose` 在 `config.locked()` 内跑 `_reapply` + `_diagnose`(5s TCP / 每条链 3s / `xray -test` / wg 诊断) → 按死全站 | 需要改成 `_run_apply_job` 同款后台任务 + 前端轮询, 属接口形状变更 |
| P2 | 换域名在锁内 `reapply` 且**绕开** `_APPLY_RUN_LOCK`; 双击还会起两条管道(两次 certbot 触发签发限额 + 互相回滚) | 与上一条同一类改造(异步 + 门控), 建议一起做 |
| P3 | `downloading` 中间态没有看门狗(线程起不来就永久 503) | 只影响"面板正在准备内核"的文案, 重启即恢复 |
| P3 | `core_sha256` 的 memo 键是秒级 mtime + size(同秒同尺寸改写命中旧值) | 需要本地写权限才能触发; 不能直接删 memo(每次 `xray -test`/下发都要重算 20 MB) |
| P3 | `btf_cached` 版本优先级压过架构精确度 | 只影响多份 BTF 包共存时的挑选 |
| P3 | 模块级 21 处 `int(os.environ.get(...))` 无兜底 | 写错 env 才炸; 建议统一抽 `_env_int()`, 属代码卫生 |
| P3 | `dae_config`: 节点池为空仍输出空 `group`+`fallback`; `host.replace(".","").isdigit()` 判 IPv4(v6 静默失效) | 需要产品语义决定(全关节点时要不要拒绝启用性能模式); IPv6 入口本身在链式代理里也不支持 |
| P3 | 备份未剔除 `wireguard.one_time_links` | 备份里本来就含 WG 私钥, 多这一项不改变泄漏面 |
| P3 | `cli` 的 `z` wrapper 用 `replace("__ZP_HOME__")` 拼接, 路径含 `$`/`"` 会坏 | 正常安装路径 `/opt/zeroproxy` 不受影响; 改安装器生成逻辑风险大于收益 |
| 已知取舍 | `PERF_VERSION` 抬高后, 旧版 `dae-*.gz` 仍算"已缓存" | 这**是**文件里写明的"手工放兜底件"设计; 我保留了它, 只修了架构错配。若要改成严格版本, 需同时改运维兜底流程 |

### 复核后**否掉**的结论

- `check_secret` / `account.apply_credentials` 的"会话键混用"、"口令未 Unicode 归一化" —— 当前所有调用方都传 `load_state()` 的完整 state, 不可达。
- `crypto.reality_key_valid` 的 base64 规范化 —— 代码里没有任何路径写入标准 base64/带填充的公钥。
- `_extract_dae` 解压炸弹 —— 上游资产有固定摘要闸门, 只有上游自己能构造; 保持现状。
- `agent_sha256()`(仓库内 `SHA256SUMS` 锚点)**没有任何调用方** —— 不是 bug, 但"面板这一跳被换掉也能抓住"这句话在代码里确实没落地, 属**能力缺口**(见下)。

---

## 三、覆盖边界(如实)

- 本轮我亲自读过的: `router_client.py` 供应链/下载/渲染/白名单/状态机主要段落(未逐行读完 755–1650 的四个下载循环内部),
  `routes.py` 2228–2750、3230–3260、3354–3690、3915–4215、2497–2660(restore 全段), `cli.py` 全文, `crypto.py`/`account.py` 全文,
  `dae_config.py` 生成段, `wireguard.py` 脚本与地址池, `services.py` 探测与流量, `share_links.py` 链接/组/singbox 输出, `chain.py` 配对码/诊断。
- **仍未逐行覆盖**: `routes.py` 4215–4707(`/c/ui`、`/c/rt`、`/c/sub`、`/c/bench` 等设备侧端点), `router_client.py` 755–1650 的下载循环内部, `nginx_config.py` 模板正文。
- 本机仍**没有** `xray`/`hysteria`/`nginx`/`dae` 二进制: `scripts/verify.py` 的真实内核校验段无法在这台机器上跑。**上线前必须在目标机跑一次**, 重点看:
  1. `dae validate` 能接受新的降级分支(显式 CIDR);
  2. 原子写之后的 `config.json` 仍过 `xray -test`;
  3. 面板内升级 / `python -m zeroproxy.apply` 在持锁状态下不卡死(嵌套 flock 修复)。

---

## 四、本轮改动文件

| 文件 | 改动 |
|---|---|
| `backend/zeroproxy/crypto.py` | `new_vless_uuid()`; `derive_uuid` 标废弃; 版本化口令哈希 + `password_needs_rehash` + 兼容老格式 |
| `backend/zeroproxy/routes.py` | setup 用随机 UUID; `/sub` 字节比对; peer 改名走 `clean_name`; restore 结构校验 + 按步骤结果回滚; `_dash_fingerprint` 防御; `_wg_reply` 合并式落盘 |
| `backend/zeroproxy/devices.py` | 配对码字节比对(非 ASCII 不再 500) |
| `backend/zeroproxy/wireguard.py` | `clean_name()` 公开为注入边界; IPv6 分支 f-string 修复 |
| `backend/zeroproxy/services.py` | `udp_port_listening` 看两张表 |
| `backend/zeroproxy/router_client.py` | geo 完整性(Content-Length); `_perf_candidates` 架构锚定; `fetch_perf` 原子写 |
| `backend/zeroproxy/dae_config.py` | 降级分支改用显式私网 CIDR |
| `backend/zeroproxy/cli.py` | EOF 哨兵; `_guarded` 统一处理 `StateError` |
| `backend/tests/test_second_pass.py` | 10 条回归用例(WG 脚本占位符/`sh -n`、UDP 双表、随机 UUID、哈希版本化、peer 注入、非 ASCII token、dae 降级) |
| `backend/tests/test_devices.py` | 修正"降级分支可以引用 geoip"的错误断言 |
