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


## v2.13.1 链式代理修复（2026-11-15）

- Python 全套：561 passed, 6 skipped（118.46 秒）；新增 25 个修复回归用例。
- 浏览器：173/173 项通过；工作区与新配对窗口：49 项通过，覆盖桌面、手机布局与敏感输入清理。
- 连接模型：16 项断言；链式健康与路由模型：12 项断言，均通过。
- 25 个前端模块语法检查通过，`git diff --check` 通过，SHA256SUMS 92/92 文件校验通过。
- 验证使用隔离的本机 dry-run/mock，未升级线上服务器；真实双服务器握手、吞吐与生产恢复尚未验证。

详见 [CHAIN-REPAIRS-2.13.1.md](CHAIN-REPAIRS-2.13.1.md)。


## v2.13.2 / 路由器 v1.4.52 配套界面（2026-11-15）

- Python 全套：562 passed, 6 skipped（121.79 秒）；运行脚本、前端契约与发布清单定向复验：42 项通过。
- 路由器 Chromium 回归：111/111 项通过，包含五工作区、六种宽度、主题、键盘、真实计数计算、断线恢复与性能模式往返。
- 路由器安装模拟：201/201 项通过；服务器升级及失败回滚模拟全部通过。
- JS 语法、HTML 标签与唯一 ID、`git diff --check` 通过，SHA256SUMS 92/92 校验通过。
- 验证使用本机模拟服务与临时安装环境；未升级线上服务，真实 OpenWrt 接管与流量尚需真机验收。

详见 [ROUTER-UI-1.4.52.md](ROUTER-UI-1.4.52.md)。服务器与路由器分别保存界面文件，须先升级服务器，再更新路由器客户端。


### v2.13.2 连接图操作与证据补齐

- Python 全套：568 passed, 6 skipped（126.57 秒）；新增 6 个单路线探测 API 回归用例。
- 连接图浏览器回归：62 项通过，覆盖分段操作、单路线检查、重复提交、异步切换、请求失败保留证据、落地段出口 IP、默认出口确认及六种宽度。
- 连接模型：22 项断言通过，包括浅握手不冒充真实出网、落地段不冒充链式入口和无结果不显示检查时间。
- 既有完整浏览器回归：173/173 项通过。不可达测试地址改用本机未监听地址，避免本机代理接受 TEST-NET 的握手而改变失败场景。
- JS 语法、唯一 HTML ID、`git diff --check` 和 SHA256SUMS 92/92 校验通过。
- 全部检查使用隔离本机环境，尚未推送或升级真实服务。细节见 [CONNECTION-FIELD-2.13.2.md](CONNECTION-FIELD-2.13.2.md)。


## v2.13.3 / 路由器 v1.4.53：LuCI 宿主适配（2026-11-15）

- Python 全套：570 passed, 6 skipped（122.45 秒）。
- 路由器 Chromium 回归：154/154 项通过；保留独立页原有流程，并通过真实 LuCI 承载脚本新增宿主主题与尺寸检查。
- 覆盖宿主蓝白/深色、自定义强调色、内容面板单独换色、深色选中路线文字对比度、六种宽度与五工作区、iframe 增高和缩回、节点接口失败及恢复。
- 离线缓存新增正常替换与移动失败保护的实际 shell 回归；运行脚本及版本契约定向复验 31 项通过。
- JS / shell 语法、`git diff --check` 与 SHA256SUMS 92/92 校验通过。
- 截图为本机模拟 LuCI 外壳中的真实 iframe 渲染，尚未在用户真实 OpenWrt / Argon 固件部署；无线上服务改动。

详见 [LUCI-HOST-1.4.53.md](LUCI-HOST-1.4.53.md)。


## v2.13.4 / 路由器 v1.4.54：旧 LuCI 外框兼容（2026-11-15）

- 在用户已打开的 Chrome 页面进行只读检查，确认旧 iframe 仍为 78vh：外框约 802px，内页约 1307px；未修改真实路由器或现场 DOM。
- Python 全套：570 passed, 6 skipped（123.56 秒）。
- 路由器浏览器回归：163/163 项通过。新增旧外框、重要高度/最大高度限制、固定视口外层滚动、首次工作区初始化、底部可达、短页缩回、旧框主题同步与仅重载内页的适配恢复。
- 保留独立页、现代承载页、五工作区和六种宽度验证；发布清单 92/92、JS/shell 语法及 `git diff --check` 通过。
- 新版本只在本机模拟外壳中验证，未升级用户真实设备。详见 [LUCI-LEGACY-1.4.54.md](LUCI-LEGACY-1.4.54.md)。
