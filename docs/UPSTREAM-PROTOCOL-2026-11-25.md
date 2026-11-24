# ZeroProxy 上游协议兼容性与发布验证

核对日期 2026-11-25。仓库基线为面板 2.17.1、路由器客户端 1.4.63，HEAD 为 `e462712`。版本取自 GitHub Releases 官方 API 的 latest 记录。以下为改造前的公开资料与源码核对，性能数字来自上游。改造与实核验证记录见末节。

## 稳定版本

| 项目 | 官方 latest | 发布时间（UTC） | 与 ZeroProxy 的关系 |
| --- | --- | --- | --- |
| Xray-core | [v26.11.9](https://github.com/XTLS/Xray-core/releases/tag/v26.11.9) | 2026-11-09 | 面板服务端候选基线 |
| Mihomo | [v1.19.34](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.34) | 2026-11-11 | 路由器客户端已固定此版与摘要 |
| sing-box | [v1.14.4](https://github.com/SagerNet/sing-box/releases/tag/v1.14.4) | 2026-10-24 | 1.14 配置测试基线。另有 [1.15 alpha.13](https://github.com/SagerNet/sing-box/releases/tag/v1.15.0-alpha.13) |
| Hysteria 2 | [app/v2.14.0](https://github.com/HyNetworks/hysteria/releases/tag/app/v2.14.0) | 2026-11-15 | 面板 QUIC/UDP 服务端候选基线 |
| OpenWrt | [25.12.6](https://github.com/openwrt/openwrt/releases/tag/v25.12.6) | 2026-10-18 | 稳定固件验收基线 |
| Hiddify App | [v5.9.15](https://github.com/hiddify/hiddify-app/releases/tag/v5.9.15) | 2026-11-19 | 客户端展示与故障恢复参照 |
| Marzban | [v0.8.4](https://github.com/Gozargah/Marzban/releases/tag/v0.8.4) | 2025-01-09 | Xray 面板参照，当前 latest 发布较早 |

## 安装与升级

- **Xray 和 Hysteria 首次安装仍依赖滚动版本。** `install.sh` 默认从 latest 解析 Xray 包，解析失败会尝试 `24.11.30`。显式 Xray 版本的 API 路径在去掉 `v` 前构造，带 `v` 输入会先请求 `vv…`，随后才走拼接地址。Hysteria 的 GitHub API 与下载备用地址都指向 latest。两条安装路径的 SHA-256 校验均依赖手动提供环境变量。建议发布时记录每个服务端内核的 tag、架构、资产文件名与 SHA-256，并让镜像、备用下载和回滚引用同一份已验收记录。部署时先完成下载和校验，再替换运行文件。两个官方 API 均已提供 Linux amd64 和 arm64 目标产物的 digest。 [ZeroProxy 安装器](../install.sh#L423) · [Xray 资产元数据](https://api.github.com/repos/XTLS/Xray-core/releases/tags/v26.11.9) · [Hysteria 资产元数据](https://api.github.com/repos/HyNetworks/hysteria/releases/tags/app%2Fv2.14.0)
- **Mihomo 已采用稳定版固定策略。** 当前 `CORE_VERSION` 和 `PINNED_CORE_VERSION` 均为 v1.19.34，版本不匹配时固定摘要查询会拒绝。此版修复 TUN 自动路由、HTTP CONNECT 响应后紧随的字节处理及 SOCKS 域名长度算术问题。下一步应在真实 LAN 对 TUN 自动路由、经 HTTP CONNECT 的首段 payload、IPv4/IPv6、DNS、fw4 reload 和恢复旧配置进行验收。 [ZeroProxy 路由器版本](../backend/zeroproxy/router_client.py#L184) · [固定摘要与校验](../backend/zeroproxy/router_client.py#L498) · [Mihomo 发布记录](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.34)
- **OpenWrt 验收至少覆盖目标设备在用版本和 25.12。** 25.12 已用 apk 替代 opkg，并默认集成 Attended Sysupgrade。25.12.6 发布说明列出默认服务的安全修复。ZeroProxy 安装器和升级脚本的能力探测可按设备实测覆盖 apk/opkg、fw4、防火墙重载、启动后恢复；固件升级与代理内核升级各自保留独立验证。 [OpenWrt 25.12 公告](https://lists.openwrt.org/pipermail/openwrt-devel/2026-March/044621.html) · [25.12.6 发布说明](https://github.com/openwrt/openwrt/releases/tag/v25.12.6)

## 配置与互通

| 组件 | 已有路径 | 发布验收 |
| --- | --- | --- |
| Xray | ZeroProxy 通过内核 `-test -c` 检查生成配置。 [应用流程](../backend/zeroproxy/apply.py#L118) | 用固定的新旧服务端版本检查实际存量配置。服务启动后再用现有客户端测试握手、TCP 数据、启用的 UDP 路径，以及服务版本和回滚后的恢复。 [稳定版本资产](https://github.com/XTLS/Xray-core/releases/tag/v26.11.9) |
| Mihomo | 路由器运行 `mihomo -t`，项目测试覆盖轻量路由器配置拒绝后保留前版。 [运行脚本](../backend/zeroproxy/client/runtime/agent.sh#L571) · [回归用例](../backend/tests/test_runtime_scripts.py#L55) | 上游提供完整配置更新、单独 provider 更新和 provider 健康检查。可分别观察配置是否加载、规则资源是否拉取、流量是否走预期出站，避免把一次控制 API 成功当作 LAN 生效。 [Mihomo 官方 API](https://wiki.metacubex.one/api/) |
| sing-box | 当前保留通用格式，面向 1.14+ 的格式则使用 `http_clients` 和 `route.default_http_client`。Android 为单独的 VPN profile。 [订阅差异](../backend/zeroproxy/share_links.py#L67) · [Android 生成器](../backend/zeroproxy/share_links.py#L1804) | 用 1.13.21 和 1.14.4 跑对应的 `sing-box check -c`，再启动配置验证规则下载、DNS 与实际出站。Android 另测导入、VPN 授权、切网和恢复。1.15 的 TUN 选项变化适合预检，稳定模板继续以固定版文档为准。 [内核配置说明](https://sing-box.sagernet.org/configuration/) · [版本迁移](https://sing-box.sagernet.org/migration/) · [v1.14.4 TUN 文档](https://github.com/SagerNet/sing-box/blob/v1.14.4/docs/configuration/inbound/tun.md) |
| Hysteria 2 | 项目有本地 YAML 结构验证。 [ZeroProxy 验证器](../backend/zeroproxy/hysteria_config.py#L88) | 用 v2.14.0 在隔离环境启动原生服务，检查 TLS、认证和 UDP。若使用 ACL，可通过 `hysteria acl test` 固定目的地址、端口和期望出站，特别核对从 0 开始的旧端口范围。v2.14.0 保留旧语法，也提供转换工具。 [发布说明](https://github.com/HyNetworks/hysteria/releases/tag/app/v2.14.0) · [ACL 测试文档](https://hysteria.network/docs/advanced/ACL/#testing-rules) |

## 性能实验

Hysteria v2.14.0 发布说明报告小包上传每秒包数约提高 30%，同时升级 quic-go 到 v0.65.0。这个数字适合作为复验方向。其拥塞控制按方向协商，带宽目标会影响是否选 Brutal，未选 Brutal 时默认使用 BBR。先测默认 BBR，再用实测链路容量设置固定目标做对照。分开报告上下行 goodput、UDP PPS/丢包、负载下 p95 时延，以及端点 CPU、RSS 与 UDP socket 错误。 [v2.14.0 发布说明](https://github.com/HyNetworks/hysteria/releases/tag/app/v2.14.0) · [Hysteria 客户端配置](https://v2.hysteria.network/docs/advanced/Full-Client-Config/) · [性能文档](https://v2.hysteria.network/docs/advanced/Performance/)

同一固件和物理设备上，用相同服务端、规则、MTU、IP 族和链路条件比较直连、项目现有代理路径和候选升级。每次重复测量冷连接、长连接、并发小流、小包 UDP、满负载、重载中断时间及回滚恢复时间。Linux TUN 对照可参考 sing-box 的 nftables/fw4 集成文档，并检查路由标记冲突与出口回环。 [sing-box v1.14.4 TUN 文档](https://github.com/SagerNet/sing-box/blob/v1.14.4/docs/configuration/inbound/tun.md)

## 发布顺序与状态呈现

1. 保存已知可用的版本、配置与摘要。先用候选版本做配置和服务启动检查，在一台代表性路由器及对应客户端上实际跑流量。收集配置生成、内核接受、服务就绪、LAN 路径验证各步骤的结果。 [本项目已有实核验证记录](VALIDATION.md)
2. 故障注入覆盖下载内容错误、配置拒绝、端口占用、单服务启动失败、路由器断线、固件防火墙重载以及回滚。通过标准至少包括现有连接影响可量化、上一版可恢复，面板显示的运行版本与真实二进制一致。 [Mihomo 配置应用入口](https://github.com/MetaCubeX/mihomo/blob/v1.19.34/hub/route/configs.go) · [OpenWrt Attended Sysupgrade](https://openwrt.org/docs/guide-user/installation/attended.sysupgrade)
3. Hiddify v5.9.15 将桌面代理引擎放入独立进程，并暴露引擎崩溃原因及节点传输/安全状态。ZeroProxy 可借鉴状态表达，让维护者直接看到失败发生在导入、内核、握手或数据路径中的哪一步。 [Hiddify v5.9.15 发布说明](https://github.com/hiddify/hiddify-app/releases/tag/v5.9.15)


## ZeroProxy 2.18.0 落地与验证

- 高级设置增加 Hysteria 2 拥塞控制，支持客户端协商、BBR 标准、保守和激进档位。默认沿用之前的协商行为。开启 BBR 档位后，服务端忽略客户端提供的带宽值，使用配置的控制器处理服务器发送方向。客户端仍使用其自身支持的非 Brutal 控制器。这个变更仅影响 ZeroProxy 的 Hysteria 2 节点服务。订阅和链式内部传输无需更新。 [Hysteria 2 服务端配置](https://v2.hysteria.network/docs/advanced/Full-Server-Config/#congestion) · [参数首次提供的版本 2.8.0](https://github.com/HyNetworks/hysteria/releases/tag/app/v2.8.0) · [同类 H UI 档位设置](https://github.com/jonssonyan/h-ui/releases/tag/v0.0.23)
- 设置写入走现有版本校验与临时变更流程。界面默认提供 90 秒确认，直接走设置 API 切换档位同样需要确认。旧内核或无法识别的版本会被拒绝。应用前还会检查版本，避免从备份恢复带进不支持的配置。现有 Xray 安装版本参数现接受带或不带 `v` 前缀。 [应用步骤](../backend/zeroproxy/apply.py#L258) · [设置入口](../backend/zeroproxy/routes.py#L1569) · [安装器](../install.sh#L423)
- 真实内核测试使用官方 Hysteria 2.14.0 macOS ARM64 发行物，SHA-256 为 `c68aa6677f15e572f997b346bcdf193b45a9dc9071b7e9555efffc8694c5ec05`。对客户端协商及全部三个 BBR 档位都启动独立的服务端与客户端进程，客户端配置了带宽值，均通过 SOCKS5 和 QUIC 隧道取回本机 HTTP 响应。测试将生成配置的监听绑定在回环地址，未模拟公网丢包、验证 Linux 多端口监听，或比较拥塞档位吞吐。 [官方资产元数据](https://api.github.com/repos/HyNetworks/hysteria/releases/tags/app%2Fv2.14.0)
- 专项 API 测试覆盖三个档位的临时设置、版本变化、订阅地址保持、撤销后配置恢复，以及旧内核拒绝。浏览器回归覆盖草稿保留、确认提示与撤销回灌。 [API 回归](../backend/tests/test_hysteria_congestion.py) · [浏览器回归](../scripts/completion_ui_check.cjs)
- 另外按官方资产摘要校验并使用 macOS ARM64 的 Xray 26.11.9、Mihomo 1.19.34 与 sing-box 1.14.4。Xray/Hysteria 实核验收 8 项通过，携带 Mihomo 实核的防泄漏测试组 24 项通过，携带 sing-box 实核的客户端配置测试组 25 项通过。这些验收覆盖实际内核配置检查，Mihomo 和 Xray 的 REALITY 跨内核公网握手以及 OpenWrt LAN 接管仍需分别验证。 [实核验收入口](../scripts/real_kernel_check.py) · [Mihomo 发布资产](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.34) · [sing-box 发布资产](https://github.com/SagerNet/sing-box/releases/tag/v1.14.4)
