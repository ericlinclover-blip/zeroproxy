# v2.16.0 / 客户端 v1.4.60：同步正确性与控制面性能

日期：2026-11-17。基于 v2.15.3；本轮实施上一轮分析中可在本机验证的正确性、控制面与内核升级。验收均在本地隔离环境执行，未部署生产环境。

## 已实施

1. **配置运行确认**：路由器配置通过真实校验后才替换文件。运行中的内核必须重载/重启成功、控制 API 就绪、现场有接管路径，才推进应用版本。失败恢复旧文件并再次尝试恢复旧服务；恢复失败明确记日志并清除启动标记。关闭或 dae 性能模式下的 mihomo 配置只暂存，不能冒充正在运行。
2. **模板传递**：移除路由器请求里写死的 smart；设备独立模板仍优先，其次显式请求，再次面板全局模板。四个全局模板均经真实请求和生成配置对照。
3. **本机控制权**：先聚合面板开关，再以本机 on/off 覆盖最终期望；面板离线时原有本机自治继续有效。
4. **多面板独立版本**：`revisions/<panel>.desired|staged|applied` 分别原子记录；聚合版本只在本机用于变化检测，不再向不同面板上报同一哈希。第二面板更新能够触发下一轮配置重建。
5. **一致的节点快照**：多面板 provider 改为 file 类型的不可变版本快照。心跳更新替代 provider 的一小时刷新；完整配置校验引用这些同一份字节。拉取时传 expected_rev，面板在版本变化或实际回退配置与期望不一致时拒绝，避免把旧内容标成新版本。旧快照保留用于恢复；首次迁移需要各面板可达，缺资源时保留原配置。
6. **控制面锁与采样**：仪表盘鉴权、状态快照和会话清理用短锁，系统采集在锁外；返回前再次检查会话。节点与系统共用同次服务状态。流量采集 single-flight、5 秒缓存（含失败），命令超时由 20 秒缩至 3 秒，未取得数据保持不可用。
7. **页面更新**：串行完成后调度下一次刷新；写操作使旧刷新响应失效。隐藏标签页降低采样，恢复可见时刷新；静默刷新跳过隐藏工作区，切换时补渲染，保留草稿与焦点保护。任务采样由 100/400ms 改为 250ms→1s→2s。
8. **受限热重载**：配置只改变 proxies / proxy-providers / proxy-groups / rules，且其他生成内容相同时，尝试 mihomo controller PUT /configs?force=false，必须返回 204 且现场就绪。监听、DNS、TUN 或其他内容变化继续走完整重启；重载失败也回退到完整重启，再失败才恢复旧配置。没有 curl/cmp 等工具时保守使用重启。
9. **内核与兼容**：固定 mihomo v1.19.34，更新八种 Linux 架构官方 Release digest；新增 REALITY short-id 强制字符串引号，修正 `12345e67` 被 Go YAML 误读为科学记数数字的问题。

API/进程/规则存在仍不等于 LAN 或目标网站验证通过。新心跳不再仅因进程存在就报告 healthy=true；真实业务验证继续由设备诊断和深探测单独提供。

## 升级顺序与兼容

先升级服务器面板，再更新路由器客户端；仅升级面板不会替换路由器运行脚本或 mihomo。新客户端使用 expected_rev 版本约束，升级面板后约束才能完整生效。

已有设备凭据、订阅 URL 和 WG peer 不轮换。新增 staged_rev 是可选字段，旧客户端仍兼容。第一次运行不把旧的单一 applied.rev 当作每台面板的真实应用记录，而是重新同步验证。稳定心跳间隔最长 30 秒，不能承诺指令总在 15 秒内完成；弱网会增加等待。

file provider 快照由面板心跳驱动，失联时继续使用最后可用版本。旧快照没有在本次升级中自动删除，确保原配置可恢复；长周期磁盘保留策略可在取得实际变更量后另定。

当前热重载边界针对本项目生成器的顶层 YAML；未知变更保守重启。它不构成任意用户 YAML 的通用语义差分。Xray 服务端动态用户 API 暂不启用，先保留已验证的服务端生成、校验与回滚路径。

## 可复现验证

```sh
./.venv/bin/python -m pytest backend/tests/test_upgrade_performance.py -q
./.venv/bin/python scripts/real_kernel_check.py --all
./.venv/bin/python scripts/control_plane_bench.py --output /tmp/zp-control-bench.json
./.venv/bin/python scripts/mihomo_acceptance.py --binary /path/to/mihomo --rules-experiment
bash scripts/gen_sha256sums.sh
bash scripts/upgrade_sim.sh
./.venv/bin/python scripts/router_install_check.py
```

`control_plane_bench.py` 在临时状态目录运行真实 FastAPI 请求，只给仪表盘采集注入等待，对照旧锁范围和新锁范围。它不会修改生产目录或执行生产服务命令。

本机 20 次、注入采集延迟 200ms 的结果：旧范围前台请求 p50 205.987ms / p95 207.540ms，新范围 p50 1.641ms / p95 2.334ms。前台请求是 `/api/audit`；这里只证明该故障注入场景的锁竞争降低，不是线上延迟或 WAN 带宽提升。

`mihomo_acceptance.py` 使用已核对官方压缩资产 SHA256 的 macOS ARM64 v1.19.34，完成 38 项：四模板普通配置、四数据面×双栈配置（不加载 Geo 的语法矩阵）、多面板 file provider、真实本地 HTTP 流跨 controller reload 保持且新节点集合启用。TUN 仅做配置校验，未在 macOS 创建透明接管。

MRS 独立实验：25,000 条合成域名规则，YAML 463,899 bytes，MRS 4,300 bytes；各 5 次进程校验中位时间为 9.163ms / 8.864ms。合成域名可压缩性很强，不能把比例外推到完整 Geo 数据。解析时间改善很小，因此本轮不据此替换现有生产规则系统。后续应对真实同语义规则、DNS 依赖与设备内存做对照。

## 尚需现场证据

- Linux/OpenWrt 真机验证 TUN、TPROXY、REDIRECT、IPv6、fw4 reload、WAN 重拨、面板离线及恢复。
- 同硬件同线路比较数据面吞吐、CPU/RSS、DNS 冷热缓存、UDP 丢包、重载中断及 24–72 小时长稳。
- QUIC / WG / AWG 的 MTU、缓冲和拥塞参数在测量前保持原值。
- Hysteria 常驻认证服务目前无瓶颈测量，继续保持面板离线也可用的 command 认证。
- 本地已有 `.github/workflows/check.yml` 尚未纳入提交；不能据文件存在声称远端 CI 已启用。

最终回归与演练结果在本文件验收记录段补充。

## 本轮最终验收记录

- 真实 Xray v26.11.9 / Hysteria app/v2.14.0 全套后端：**743 passed，0 skipped**，162.29 秒。
- 新增升级与性能回归：**22 passed**；最终 provider 文件权限收紧后再次通过，3.39 秒。
- 主面板 Chromium：**173/173**；交互审计与新增过期响应／暂存显示检查：**43/43**；路由器模拟界面：**197/197**。
- 官方 mihomo v1.19.34 macOS ARM64：**38 项通过**，另完成 YAML/MRS 合成规则实验。
- 路由器完整安装演练：**201/201**，包含慢下载、失败、模式切换和多入口状态；故意中断慢下载时的 BrokenPipe 是测试场景输出，最终退出成功。
- 服务器升级模拟：成功、应用校验失败、下载失败与回滚路径全部通过。
- Go 测试通过；29 个 JS 文件语法通过；Shell 语法与 Git whitespace 检查通过；SHA256SUMS **98/98**。

以上均为本地隔离环境。没有部署或修改真实服务器、路由器；没有将模拟接管、语法验证、本地 HTTP 流或合成规则实验标为真实 WAN 性能。
