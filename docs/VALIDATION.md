# 验证与发布

本地回归（在仓库根目录运行）：

```sh
./.venv/bin/python -m pytest backend/tests -q -rs
(cd backend/zeroproxy/client/agent && go test ./...)
```

`test_audit_fixes.py` 覆盖跨请求/跨进程 WireGuard 事务、失败补偿、到期重试、配置文件恢复、无 Geo 防护、IPv6/CIDR、非法规则输入和分流一致性。

Python 测试中的真实 Xray/Hysteria 用例在没有二进制时明确跳过。本地准备的 GitHub Actions Checks 工作流覆盖 Python 3.10/3.12、Go 测试和 JS 语法检查；当前仓库写入凭据缺少 `workflow` 权限，工作流文件暂未推送。这些检查不是实际流量或真机验收。

修改完发布代码后运行：

```sh
bash scripts/gen_sha256sums.sh
bash scripts/upgrade_sim.sh
./.venv/bin/python scripts/router_install_check.py
```

后两个脚本使用临时目录和替身模拟升级、安装环境。它们不能替代 Linux/OpenWrt 真机验收。

真实内核验证使用 `scripts/verify.py`，按该文件头部说明设置 Xray、Hysteria、mihomo、sing-box 路径及 Geo 数据目录。不带 `--allow-skip` 时，关键内核校验缺失应返回非零；发布验收不能把跳过写成通过。

AWG 需要匹配的工具与协议：

- 内核模式探测 `amneziawg` 接口类型；用户态必须使用 `amneziawg-go`。
- 混淆开启后，同一接口不提供标准 WG/GL.iNet 兼容配置。先关闭服务端混淆，才能导出标准配置；切换协议会重建接口，已有连接需要重连。
- 自定义头 H1~H4 必须互不相同；Jc/Jmin/Jmax/S1/S2 的合法零值原样保存。
- 当前生成的是项目已有的基础 AWG 参数子集，不宣称覆盖上游所有新版本功能。

上述兼容边界依据 [AmneziaWG 官方文档](https://docs.amnezia.org/documentation/amnezia-wg/)：只有关闭混淆参数时才兼容标准 WireGuard。依赖安装与内核模块说明见 [官方 Linux 安装指南](https://docs.amnezia.org/documentation/instructions/install-amneziawg-kernel-module-linux/)。本机回归不等同 AWG 真实握手通过。

分流测试器现在标注为 **Clash 规则预估**，与 Clash 渲染共享有序规则。未加载 Geo 数据、DNS 信息或客户端手动选组时，不证明实际流量出口。dae 目前使用统一代理组，其降级行为会显示在路由器界面和配置注释中。


## v2.13.0 连接场域界面（2026-11-15）

- Python：536 passed, 6 skipped（115.88s）。
- 既有浏览器回归：170/170，通过真实开发服务与 Chromium 执行。
- 新界面回归：45 项通过，覆盖五工作区在 1440/1024/820/768/390/320px 的页面宽度，以及选择无写入、草稿、焦点、查找、主题与诊断定位。
- 状态模型：16 项断言通过。25 个前端模块语法检查通过，202 个 HTML ID 无重复。
- `SHA256SUMS`：92/92 文件校验通过。
- 本轮浏览器测试采用隔离的本地 dry-run 数据，没有升级线上服务器；真实代理流量与人工读屏验收不在本轮已验证范围。

详见 [UI-UPGRADE-2.13.0.md](UI-UPGRADE-2.13.0.md)。
