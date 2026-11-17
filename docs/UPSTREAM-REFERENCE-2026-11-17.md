# ZeroProxy 上游技术参照与适用性（2026-11-17）

本报告服务于 ZeroProxy 的技术审计，研究可借鉴的工程机制。它不是产品排名，也没有执行上游吞吐量对比。研究日期采用用户环境的 **2026-11-17**；Release 日期采用 GitHub REST API 的 `published_at`（UTC）。实际读取官方 Release、固定版本源码与官方文档，未采用二手评测。Release API 查询与复核发生于 2026-11-17，本次收尾时间为 **2026-11-17T13:07:09Z**。对 ZeroProxy 的观察来自本次工作树，不能替代部署机运行证据。

## 1. 范围与版本边界

先读本仓库 `README.md` 和项目结构：维护版本 v2.15.3 / 路由器客户端 v1.4.59；功能包含 Xray 的 Reality/XHTTP/WS/Trojan、Hysteria 2、原生 WireGuard/AWG、链式代理、mihomo 路由器接管、多面板聚合、本机控制面和 dae 性能模式。本次重点研究这些功能直接依赖或可参照的上游，不把新增协议数量当作改造目标。

通过 `gh api repos/{owner}/{repo}/releases/latest` 与 Release 列表交叉核验，得到本次可获取的最新稳定版本：

| 项目 | 稳定版本 | 发布时间 UTC | 官方证据与边界 |
|---|---|---|---|
| Xray-core | v26.11.9 | 2026-11-09 05:31:16 | [Release](https://github.com/XTLS/Xray-core/releases/tag/v26.11.9)；新增功能不等于 ZeroProxy 已支持 |
| mihomo | v1.19.34 | 2026-11-11 07:01:35 | [Release](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.34)；`Prerelease-Alpha` 为滚动预发布，不能据列表位置当作稳定版 |
| sing-box | v1.14.4 | 2026-10-24 01:04:25 | [Release](https://github.com/SagerNet/sing-box/releases/tag/v1.14.4)；同时观察到 v1.15.0-alpha.13，未纳入稳定基线 |
| 3x-ui | v3.11.0 | 2026-10-25 19:09:16 | [Release](https://github.com/MHSanaei/3x-ui/releases/tag/v3.11.0)；`dev-latest` 排除 |
| Headscale | v0.29.7 | 2026-10-30 09:55:40 | [Release](https://github.com/juanfont/headscale/releases/tag/v0.29.7)；作为控制面参照，非代理内核替代品 |
| firewall4 | commit `3722eadc088c3ab81389596ca9796112b436583a` | 2026-11-08 16:27:23 | [固定提交](https://github.com/openwrt/firewall4/commit/3722eadc088c3ab81389596ca9796112b436583a)；仓库无 GitHub Release，不能称作某个 OpenWrt 固件已包含 |
| procd | commit `3ab8f5cc388564f94fa1af81e6c3ec0d52f6937e` | 2026-11-05 14:36:11 | [固定提交](https://github.com/openwrt/procd/commit/3ab8f5cc388564f94fa1af81e6c3ec0d52f6937e)；同样不能推断旧固件能力 |

版本信息是本次 API 返回的快照。官方文档站会随主分支更新，报告涉及版本差异时优先链接固定 tag 的源码/文档；HTTP 页面更新时间不当作功能首次发布日。

## 2. 配置事务：借鉴分阶段提交，不夸大原子性

**mihomo 的 API 先解析、后应用。** v1.19.34 的 `updateConfigs` 对 payload 或安全路径进行解析，解析错误返回 400；只有解析成功后才调用 `executor.ApplyConfig` 并返回 204。这是“无效候选配置不进入应用阶段”的直接范例，但该函数并未提供跨文件、跨服务的持久事务，也不能用 204 推断 LAN 流量已接管。[固定源码](https://github.com/MetaCubeX/mihomo/blob/v1.19.34/hub/route/configs.go)

**firewall4 使用锁及批量提交。** 固定提交的 `fw4` 脚本在 start/reload 中持有 `flock`，把渲染后的规则一次交给 `nft -f`；`check` 使用 `nft -c -f`，`restart` 在 stop 前先检查。其 script includes 是另一阶段，因此不能把整个 fw4 操作描述成覆盖所有外部 shell 动作的单一事务；restart 的 stop/start 也不能宣传为零窗口。[固定源码](https://github.com/openwrt/firewall4/blob/3722eadc088c3ab81389596ca9796112b436583a/root/sbin/fw4)

**对 ZeroProxy 的建议（工程推导）：**

- 统一采用“生成候选 → 真实内核校验 → 提交 → 局部重载 → 现场验证 → 标记 applied”的闭环；失败保留用户期望配置、恢复上次成功运行配置，并分别记录“应用失败”和“回退成功/失败”。
- 把 revision/hash 绑定到全部配置产物和一次操作，设备上报 `applied_revision` 与实际运行内核身份。任务完成、配置写入、端口监听和业务连通分别计量。
- 在多个内核、nginx、WG、防火墙之间采用可恢复的分阶段流程，描述为有补偿的事务；不要承诺操作系统没有提供的跨进程原子性。
- nft 路径先检查完整候选、以单批次更新自有规则。锁定自有变更，避免“删除旧规则 → 新规则验证失败”扩大故障窗口；旧 iptables 固件保留独立兼容实现。

本次工作树 `backend/zeroproxy/apply.py` 已可见配置快照、按 digest 判断变更、失败回退、`runtime-last-good.json` 与 applied revision。审计应核验它们的故障覆盖和凭据保护，避免把已有机制重复列作待开发功能；仅静态阅读不能证明断电恢复及真实运行回退均通过。

## 3. 热重载：按变更范围选机制

**Xray 提供有边界的动态管理。** v26.11.9 `HandlerService` 有 Add/Remove/Alter inbound/outbound 和用户查询操作，`AddUserOperation` / `RemoveUserOperation` 支持增删用户；官方文档列出可动态增删用户的 VMess、VLESS、Trojan、Shadowsocks，并提供 StatsService、RoutingService。动态 API 不意味着任意 TLS、端口、传输或全局配置都能无损更新。[固定 proto](https://github.com/XTLS/Xray-core/blob/v26.11.9/app/proxyman/command/command.proto)、[官方 API 文档](https://xtls.github.io/config/api.html)

**mihomo 的操作粒度不只“重启”。** 官方 API 分别提供 `PATCH /configs`、`PUT /configs`、策略选择、单个 proxy-provider 更新，以及 provider 健康检查；`/traffic`、`/memory`、`/connections` 可读取运行信息。配置整体 reload 与 provider 刷新是不同操作，不应把刷新订阅等同于重新创建全部监听器。[官方 API](https://wiki.metacubex.one/api/)、[v1.19.34 配置实现](https://github.com/MetaCubeX/mihomo/blob/v1.19.34/hub/route/configs.go)

**3x-ui 提供真实的范围收敛案例。** v3.11.0 发布记录明确修复 TUIC 客户增删触发 Xray 重启的问题，并列出复用 gRPC 连接、缓存订阅体、减少冗余数据库写入等改进。这里只把它作为发布说明层面的工程案例，未独立复现其性能收益。[发布记录](https://github.com/MHSanaei/3x-ui/releases/tag/v3.11.0)

**适用建议：** ZeroProxy 保持 WG 的增量同步；对用户凭据变更、provider 更新、规则/策略选择、传输监听器变更建立明确的 reload/restart 矩阵。先证明持久状态与动态运行状态一致，再引入 Xray 用户热更新；如果只改内存而未落盘，重启会恢复旧用户。验收应包含持续 TCP 流、UDP 会话与撤销凭据三个维度，不能只看 API 成功或 PID 未变化。

## 4. 控制面、数据面与本机自治

Headscale v0.29.7 README 将自身定位为 Tailscale 控制服务：交换 WireGuard 公钥、分配地址、管理用户边界和发布路由。它说明了控制面职责如何与承载流量的端点职责分开，不能据此认定 Headscale 自身就是 ZeroProxy 的替代数据面。[固定 README](https://github.com/juanfont/headscale/blob/v0.29.7/README.md)

Headscale v0.29.7 的发布记录还有两个可操作案例：指标只在配置的 metrics listener 上提供；待注册/认证请求及客户端上报数据受到容量和大小限制。其安全修复分别存在于控制服务与端点 tailscaled，升级其中一侧不能自动替另一侧安装修复。[官方发布记录](https://github.com/juanfont/headscale/releases/tag/v0.29.7)

**适用建议：** ZeroProxy 的本地 agent、代理内核和网页控制入口继续保持生命周期独立。代理关闭或云面板不可达时，仍应能本地查看现场与执行停用/还原；设备 desired、actual、applied revision、last seen 与 stale 状态分开显示。限制每设备报告体积、任务队列和事件历史，指标入口与公网业务入口分开。借鉴这些边界不要求引入 Headscale、Tailscale 或新的数据库。

当前 `client/router-install.sh` 已包含控制服务和内核拆分、本机自治及真实接管复查；下一步更适合检验弱网、面板重启、路由器重启与断电中的一致性，而非再次拆分同一职责。

## 5. OpenWrt 生命周期与防火墙共存

OpenWrt 官方文档规定 fw4 可通过 nftables include 在 ruleset/table/chain 的前后位置注入规则，`/etc/nftables.d/*.nft` 默认位于 fw4 table 的前部；旧 fw3 的部分 include 选项不能原样搬到 fw4。[官方配置文档](https://openwrt.org/docs/guide-user/firewall/firewall_configuration#includes_2203_and_later_with_fw4)

procd 固定源码支持实例参数中的 respawn、file、triggers、reload_signal 等，并对 crash loop 施加重试边界。较新代码中的更多 respawn 策略不能直接假定 21.02 或厂商裁剪固件具备。[固定 instance.c](https://github.com/openwrt/procd/blob/3ab8f5cc388564f94fa1af81e6c3ec0d52f6937e/service/instance.c)

**适用建议：**

- 首选进程前台运行并由 procd 负责监督，避免后台 shell 叠加监督导致重复实例；保留非 OpenWrt 固件的能力探测。
- 明确规则归属与唯一名称，覆盖 fw4 reload、WAN 重拨、LAN 地址变动、上游 DNS 变化和代理 crash/restart。自有 table 是否被 fw4 保留、何时需要重新挂接必须实测。
- 配置检查通过后再触发 reload。不能向没有实现相应信号处理的内核发送通用 SIGHUP 并称为热重载。
- 快照/还原只回收 ZeroProxy 所有的规则、路由、DNS 与服务项，避免把用户运行期间新增的其他配置整体覆盖；还原验收记录对象差异，而非仅打印命令退出码。

## 6. 健康检查、观测与性能

mihomo 的 provider 提供独立的 `interval`（订阅更新）和 `health-check.interval`（健康探测），以及 timeout、lazy、expected-status 等参数；lazy 默认开启意味着未使用集合可能不被主动测试。“无近期样本”不应标成“健康”。[官方 provider 文档](https://wiki.metacubex.one/config/proxy-providers/)

sing-box URLTest 提供测试间隔、容差、空闲超时和是否中断已有连接等控制项。容差与连接处理是可借鉴的防抖机制；不同代理协议或业务站点的可用性仍需独立验证。[官方 URLTest 文档](https://sing-box.sagernet.org/configuration/outbound/urltest/)

3x-ui v3.11.0 引入节点 down 告警失败次数门槛，并修复监控中无法测量的值显示为 0 的问题。这适合 ZeroProxy 的“未知/失联/不支持/失败”状态区分，也能减少短暂网络抖动造成的告警翻转。[官方发布记录](https://github.com/MHSanaei/3x-ui/releases/tag/v3.11.0)

sing-box v1.14.4 的固定版本文档说明 Linux TUN 的 `auto_redirect` 使用 nftables 改善路由，处理 fw4 兼容规则，并指出它与部分 routing mark 配置冲突，以及通过绑定出口接口避免回环。文档作者称其性能好于 tproxy，这属于上游自身描述，**不是本报告在 ZeroProxy 设备上的测量结论**。[固定版本 TUN 文档](https://github.com/SagerNet/sing-box/blob/v1.14.4/docs/configuration/inbound/tun.md)

当前在线 TUN 文档还列出 sing-box 1.15.0 才增加的字段，例如 `auto_redirect_tproxy_mark`，不可复制到 1.14.4 稳定配置；这也说明“照抄最新文档”必须先检查目标版本。[滚动文档](https://sing-box.sagernet.org/configuration/inbound/tun/)

**适用建议（未实施或基准测量）：**

| 方向 | ZeroProxy 可采取的具体措施 | 必要验收 |
|---|---|---|
| 健康分层 | 分别报告进程、配置、监听、DNS、规则命中、真实握手、出口 IP、目标业务可达性与样本时间 | 监听正常但认证失败；DNS失败但IP可达；IPv4正常IPv6未接管 |
| 抖动控制 | 连续失败门槛、恢复门槛、退避与随机抖动；订阅轮询和探针分别调度 | 面板短时不可达不清空最后成功配置；节点不会频繁来回切换 |
| 性能定位 | 记录各阶段耗时、API p95、探针并发、CPU/RSS/FD/conntrack与丢包，指标避免包含令牌和完整目标域名 | 能区分下载慢、解析慢、落地慢与数据面瓶颈 |
| 节约控制开销 | 复用 HTTP/gRPC 连接；相同 revision 复用订阅产物；合并重复 probe；缓存按凭据/配置/模板版本失效 | 轮换凭据后旧订阅体不再命中；失败不会缓存成健康 |
| 数据面比较 | 在代表性设备对现有 mihomo TUN/tproxy/redirect 与 dae 做同条件实验，sing-box auto_redirect 可作为后续实验参照 | 相同协议/MTU/路由/规则/内核/CPU频率；报告吞吐、延迟p50/p95、CPU/RSS、UDP丢包、IPv6与重载中断 |

这些来源没有建立“所有设备使用 TUN/dae/sing-box 必然最快”的结论。硬件 offload、软件 flowtable、策略路由和代理可见性的关系尤其应在实际固件上测量；fw4 最新提交本身就涉及 WG/容器 flowtable 设备覆盖修正，不能只按规则存在判断路径是否被接管。[fw4 提交](https://github.com/openwrt/firewall4/commit/3722eadc088c3ab81389596ca9796112b436583a)

### 6.1 mihomo MRS：压缩规则产物与按集合更新

官方 rule-provider 文档支持 `yaml`、`text`、`mrs`；MRS 的 behavior 只支持 `domain` / `ipcidr`，可通过 `mihomo convert-ruleset` 从 YAML/text 转换，不能把 mixed classical 规则直接换个扩展名。[官方规则集合文档](https://wiki.metacubex.one/config/rule-providers/)

**适用建议：** 对规模较大的域名/IP规则分别生成并分发 MRS，规则策略引用关系和人工兜底规则保留；使用 controller 的 `PUT /providers/rules/{name}` 更新对应集合，需要全局修改才采用配置 reload。[官方控制器 API](https://wiki.metacubex.one/api/)

MRS 是否减少 ZeroProxy 当前设备的下载体积、解析时间、峰值内存，应对同一规则语义做测量，不能据格式名称承诺倍数提升。下发前以项目固定 mihomo **v1.19.32** 实际校验，验证旧固件可读、损坏产物保留最后成功规则、IPv4/IPv6与优先级等价。当前数据面已经使用 system TUN 与 auto-redirect，不重复建议“切换 system”作为优化。

### 6.2 Hysteria：认证成本、拥塞控制与 UDP 缓冲分别处理

官方 server config 明确：command 认证在客户端尝试连接时执行外部命令，按退出码和 stdout 判定结果；HTTP 认证向后端 POST，HTTP 200 加 JSON 结果构成认证响应。二者是连接认证路径，不能说每个业务包都会启动 Python。[官方认证文档](https://v2.hysteria.network/docs/advanced/Full-Server-Config/#authentication)

当前 ZeroProxy 的 `hysteria_config.py` 下发本机 `auth.py` command，并限制校验器只接受 password/command；若引入 HTTP 认证，需要一并修改生成器、校验器、服务生命周期和故障测试。**工程推导：** 长驻的本地 HTTP 认证服务可避免每次连接启动解释器和重复读JSON，适用于大量设备重连/认证突发；实际收益应测认证 p95、CPU与成功率，不能当作提高已建立连接吞吐量的保证。它会引入一个运行依赖，需设计只监听 loopback、凭据/版本同步、超时、容量边界、拒绝优先和最后成功状态读取；控制面升级过程中不能无意中断所有新连接认证。

官方解释 BBR 不需要带宽目标，Brutal 按固定速率补偿丢包；带宽填写高于线路能力可能导致慢、不稳定和浪费流量。server/client bandwidth 和 `ignoreClientBandwidth` 共同影响选择，不能只看主机 TCP BBR 开关判断 Hysteria QUIC 的算法。[官方拥塞与带宽说明](https://v2.hysteria.network/docs/advanced/Full-Server-Config/#bandwidth)

官方性能指南给出 Linux `net.core.rmem_max` / `wmem_max` 16 MiB 的示例，并强调 QUIC 用户态处理的 CPU、网络和内存约束。[官方性能指南](https://v2.hysteria.network/docs/advanced/Performance/)

**适用建议：** 测量当前 UDP socket 缓冲、drop/error 计数、QUIC日志、CPU和连接重建频率，再决定缓冲或流控窗口；先核查项目部署脚本是否已经配置，避免重复写 sysctl。16 MiB 是文档示例而非所有路由器的最优值。低内存设备按并发与带宽时延积评估，设置后验证真实 socket 行为和丢包，而非只读 sysctl 成功。上述 Hysteria 网页为滚动文档，本次未核验其具体 release 基线，部署前必须对项目安装的真实 Hysteria 版本再次验证配置。

## 7. 优先级与验证顺序

1. **先完成运行正确性闭环。** 当前工作树已有不少事务与观测机制，审计重点应是失效模式：校验失败不动当前服务、部分重启失败可恢复、撤销凭据不会继续下发、设备确认的 revision 对应真实运行配置。通过后才能把“配置已保存”升级为“实际生效”。
2. **对固定依赖做有依据的更新。** `router_client.py` 当前 `CORE_VERSION`/`PINNED_CORE_VERSION` 为 mihomo v1.19.32；上游 v1.19.34 发布记录包含 TUN 自动路由和 SOCKS 域名长度算术溢出等修复。建议作为单独升级项，重做多架构 digest/资产校验及代表性固件、协议兼容验证，不在调研阶段静默改版本。[上游证据](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.34)
3. **收敛变更范围后再追求无中断。** 先按产物 hash 和能力矩阵只重载受影响部分，再评估 Xray HandlerService 用户热更新；保持持久状态可重建运行态。
4. **最后进行性能实验。** 没有同条件长流、并发短流、UDP、IPv6和故障恢复证据时，避免用上游宣传或短连接探针给数据面排绝对顺序。

## 8. 获取方法与限制

互联网获取遵循 agent-reach：GitHub 走 `gh api`，网页走其推荐的 Jina Reader 路径，只使用官方拥有的内容。初次 gh 请求因当前环境失效的本地代理 `127.0.0.1:10808` 失败；后续仅在请求子进程中移除代理环境变量后成功，未改用户全局网络设置。工具临时材料保存在 `/tmp/zp-upstream-reference/`，仓库仅新增本报告。

两个尝试的入口（旧 OpenWrt `procd-scripts` wiki 路径、Headscale `/stable/about/`）分别返回不存在页面与 404，未作为证据；对应结论改用固定版本源码/README。未运行上游或生产机器、不证明各上游机制可直接适配 ZeroProxy，也未按 stars、下载数或无可比基准宣称“最强”。
