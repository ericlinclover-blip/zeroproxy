# v2.15.2：真实内核与路由器现场验证

日期：2026-11-16。面板 v2.15.2；客户端保持 v1.4.59。

## 内核来源与隔离环境

本机为 macOS ARM64。测试内核保存在用户缓存 `~/Library/Caches/ZeroProxy/real-kernels/`；项目测试继续使用独立临时 `ZP_HOME`。下载资产的 SHA256 与官方发布 API 的 digest 一致，版本命令实际执行成功。

| 内核 | 官方发布与资产 | 资产 SHA256 |
|---|---|---|
| Xray 26.11.9 | [官方发布](https://github.com/XTLS/Xray-core/releases/tag/v26.11.9)，`Xray-macos-arm64-v8a.zip` | `233f0c66681cd0726f81a6b2b6ed6a5710869e312047b522e46ed53035bebd26` |
| Hysteria app/v2.14.0 | [官方发布](https://github.com/HyNetworks/hysteria/releases/tag/app/v2.14.0)，`hysteria-darwin-arm64` | `c68aa6677f15e572f997b346bcdf193b45a9dc9071b7e9555efffc8694c5ec05` |

Xray 的 digest 对应下载 ZIP；解压仅取其中的 `xray`。Hysteria 的 digest 对应直接执行的二进制。缓存中另存 `provenance.json`，记录版本、发布页、资产 URL、摘要和本地路径。

## 真实内核暴露并修复的问题

无 Geo 数据时，备用私网规则包含 `::ffff:0:0/96`。真实 Xray v26.11.9 拒绝该规则：

```text
illegal ip rule: ::ffff:0:0/96
CIDR prefix length 96 exceeds max 32
```

该版本将 IPv4 映射地址识别为 IPv4，不能把 96 位前缀作为 IPv4 CIDR 编译。原规则会导致初始化的 Xray 配置校验失败，不能仅凭替身测试断言可用。相关解析实现见 [官方 rule_parser.go](https://github.com/XTLS/Xray-core/blob/v26.11.9/common/geodata/rule_parser.go)。

修复移除这一不兼容规则，保留已有 IPv4 私网范围及其它 IPv6 本地范围。新增真实流量回归：在本机启动隔离 HTTP 服务和真实 Xray HTTP 入站，通过代理访问 IPv4 映射地址 `::ffff:127.0.0.1`；关闭私网防护时实际收到预期响应，开启时目标服务没有收到请求，验证映射私网地址不能绕过防护。

配置校验原来只保留输出前 200 字符，版本横幅和长配置路径可能遮住根因。现在失败摘要优先保留最后一级原因，使上层再次截取前 180 字符时仍能看见实际错误。

## 原 6 项的结果

| 测试 | 结果 |
|---|---|
| `test_xray_config_with_real_binary_includes_chain` | 真实 Xray 接受链式入站/出站和默认出口配置 |
| `test_xray_config_with_real_binary` | 真实 Xray 接受基础配置、XHTTP 与 Stats API |
| `test_reality_keys_match_real_xray` | 真实 Xray 从私钥导出的公钥与项目生成值一致 |
| `test_deep_probe_reports_failure_when_node_is_dead` | 使用真实 Xray 的深度探针正确报告无监听节点失败 |
| `test_geodata_guard_self_heals_missing_cert` | 真实 Xray 拒绝丢证书配置，自检修复后接受配置 |
| `test_quic_processes_start_and_stop` | 真实 Hysteria 落地/入口进程启动、停用条目和停止清理符合预期 |

原 6 项单独执行 **6 passed**；原 6 项加新增私网策略/错误摘要回归合计 **8 passed**。真实内核完整后端回归 **721 passed，0 skipped**。

这里的 Hysteria 进程生命周期测试证明启动和停止，不把它单独等同于真实远端握手；现场协议探测另列如下。

## 已连接路由器的现场证据

用户确认这是另一台路由器并提供登录方式后，使用独立 SSH 主机记录登录，保留原路由器记录。

- 系统报告 OpenWrt 24.10.4 / Linux 6.6.110 / aarch64。
- ZeroProxy 客户端 v1.4.59；Mihomo Meta v1.19.32；zpcore v1.3.2。
- 现场数据面报告 `tun` / `full`。
- `zeroproxy doctor-json`：设备与本机 DNS 通过，接管计数和 TCP 入口有观测证据，固定 HTTPS 目标返回 204。
- 通过现有 Mihomo 控制器逐个节点请求固定 HTTPS 目标，未切换选组或修改设备配置。

| 节点 | HTTPS 往返 | 单次 delay |
|---|---|---:|
| Hysteria 2 | 成功 | 697 ms |
| Trojan | 成功 | 434 ms |
| VLESS Reality | 成功 | 1175 ms |
| VLESS WebSocket | 成功 | 1145 ms |
| VLESS XHTTP Reality | 成功 | 485 ms |

目标为 `https://www.gstatic.com/generate_204`，控制器每次指定相应节点，超时预算 10 秒。这证明这次探测中的协议出网可用；这些单次延迟不是吞吐/线路性能基准。

本轮现场只进行了读取和探测。TUN/full 与计数是接管观测，节点延迟探测来自路由器本机，不把它写成所有 LAN 终端流量都已验证。未进行长时间稳定性、真实双服务器链路、生产服务器回滚或 WireGuard/AmneziaWG 真机验收。

## 可重复执行

同一本机缓存准备好后：

```sh
.venv/bin/python scripts/real_kernel_check.py
.venv/bin/python scripts/real_kernel_check.py --all
```

其它环境显式提供匹配平台的真实二进制：

```sh
.venv/bin/python scripts/real_kernel_check.py \
  --xray /absolute/path/to/xray \
  --hysteria /absolute/path/to/hysteria --all
```

脚本设置 `ZP_XRAY_BIN` / `ZP_HYSTERIA2_BIN`，缓存缺失或指定的可执行文件无效时直接失败，不用跳过掩盖环境不完整。普通离线 pytest 仍保留可选真实内核测试的跳过规则；验收应使用上述入口。
