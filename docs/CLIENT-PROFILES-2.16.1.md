# v2.16.1：设备页手机／电脑客户端修复

日期：2026-11-17。面板 v2.16.1，路由器客户端维持 v1.4.60；本次更新面板即可。

## 根因与修复

原布局将卡片缩至 220px，却用禁止换行的 flex 行放置三个或四个按钮。`auto-fill` 还会保留空列，使三个客户端卡片只能占一部分宽度。页面整体未必横向滚动，因此此前仅检查页面 scrollWidth 没有发现卡片内部越界。

修复前已用真实 Chromium 在 1440px 复现：Windows、macOS、Linux 卡片末尾操作分别越过卡片边界约 4px；字体放大或四按钮场景更明显。新的检查直接比较每个按钮和其所属卡片的矩形，不能再用“页面没溢出”代替“操作没被遮挡”。

| 级别 | 位置 | 原行为 | 修复后 |
|---|---|---|---|
| HIGH | components.css / clients.js：客户端操作行 | nowrap 挤出卡片，邻卡可能遮盖按钮 | 按钮采用两列网格，允许文字回流，奇数末项占满一行，点击高度至少 44px |
| MEDIUM | components.css：卡片网格 | auto-fill 空列占位，内容未利用全部空间 | auto-fit＋内容宽度断点，现代浏览器用 subgrid 对齐标题、说明、操作和使用步骤；旧浏览器保留 flex 回退 |
| MEDIUM | index.html / clients.js：设备类型标签 | 仅视觉选中，没有完整键盘与状态关联 | tablist/tab/tabpanel、aria-selected、roving tabindex、方向键循环、Home/End，兼容 RTL 方向 |
| MEDIUM | clients.js：静默刷新 | 手机／电脑卡片重复创建，易丢焦点和展开状态 | 相同订阅与导入目标复用 DOM，稳定动作 ID；刷新与键盘交互已验证 |
| HIGH | dom.js：复制 | 两种复制方式都失败仍显示“已复制” | 检查实际结果、反馈失败并允许重试；弹窗内回退输入放入当前 dialog，清理后恢复焦点 |
| HIGH | 手机 sing-box 配置 | 通用 JSON 只有 mixed 127.0.0.1:2080，不会提供手机 VPN 接管 | 新增 Android 1.14+ 专用 TUN/DNS 配置；Linux 通用 JSON 的本机代理语义保留 |
| MEDIUM | routes.py：JSON 下载 | 跨域时浏览器可能忽略 download 属性 | 服务器提供固定附件名称和 JSON 类型，浏览器实际下载与解析已验证 |

## 用户实际操作逻辑

- **iOS Shadowrocket / Android v2rayNG**：复制或扫码得到通用 Base64 订阅；用户更新订阅、选节点、启动 VPN，并自行验证目标网站。
- **Android sing-box for Android 1.14+**：复制、二维码、导入和下载均指向同一个 `?format=singbox&client=android` 地址。专用 JSON 含双栈 TUN、Android 支持的自动路由、DNS 劫持、本机节点域名引导解析及代理 DNS。系统接口名称和不支持的 strict_route 不下发。
- **Windows Clash Verge Rev / macOS Mihomo Party**：使用 Clash YAML；导入 URI 复用后端统一生成器，唤起已注册的兼容客户端。点击只提示正在请求打开，不宣称导入成功；失败时可复制地址手动添加。用户仍需选中配置、节点并开启系统代理或 TUN。
- **Linux sing-box**：下载 `zeroproxy-singbox.json`，先 `sing-box check -c zeroproxy-singbox.json`，再 `sing-box run -c zeroproxy-singbox.json`；应用代理指向 `127.0.0.1:2080`。此配置不会自动接管整机。
- **缺少订阅数据**：按钮禁用，删除空导入／下载链接，显示刷新重试提示。
- **外部客户端状态**：不把手机／电脑订阅导入当成已登记、已在线或已接管。页面显示“在线状态由客户端查看”。

Android 旧通用订阅地址保持兼容，不自动改成 TUN，以免影响 Linux 及原有本机代理用法。Android 用户需从新手机卡片重新复制并导入专用地址；原通用地址不必为其他客户端重新导入。

## 配置依据与兼容边界

- [sing-box v1.14.4 Android 平台文档](https://github.com/SagerNet/sing-box/blob/v1.14.4/docs/clients/android/features.md)：SFA 的 VpnService 提供无特权 TUN；接口名由 Android 管理；strict_route 未实现。新配置排除了这些不适用选项。
- [sing-box v1.14.4 TUN 文档](https://github.com/SagerNet/sing-box/blob/v1.14.4/docs/configuration/inbound/tun.md)：使用 address / auto_route / stack 等已支持项，不采用文档中标为后续版本的 dns_mode、dns_address 等新字段。
- [SFA 官方导入实现](https://github.com/SagerNet/sing-box-for-android/blob/dev/app/src/main/java/io/nekohasekai/sfa/compose/screen/configuration/ProfileImportHandler.kt)：本次读取的 dev 快照支持 `sing-box://import-remote-profile` 以及 HTTP/HTTPS 地址的二维码导入；该引用用于核对当前导入形态，不证明每个旧版本都有同样功能。
- 真实配置检查使用官方 [sing-box v1.14.4](https://github.com/SagerNet/sing-box/releases/tag/v1.14.4) macOS ARM64 制品，压缩资产 SHA256：`0d8c7f5ed5d587b0f1a5e9772a708ec3bfa4ac4c9329604b01d8d9c2ba406838`，下载后已核验。

Android 专用配置要求核心 1.14+，不会把未知或不相容的平台／格式组合静默回落成 Base64。配置生成继续使用服务器最近成功配置的回退路径，避免把失败的凭据发布给客户端。普通 Base64、Clash、通用 sing-box 订阅地址与生成语义保留。

## 验证

新增 `scripts/client_profiles_check.cjs` 与 `backend/tests/test_client_profiles.py`。

```sh
ZP_SINGBOX_BIN=/path/to/sing-box ./.venv/bin/python -m pytest backend/tests/test_client_profiles.py -q
ZP_SINGBOX_BIN=/path/to/sing-box ./.venv/bin/python scripts/real_kernel_check.py --all
# 浏览器脚本需按已有脚本惯例提供 ZP_NODE_PATH、ZP_CHROME_PATH、ZP_PYTHON
node scripts/client_profiles_check.cjs
```

- 带真实 Xray / Hysteria / sing-box 的后端全套：**768 passed，0 skipped**，168.50 秒。
- 新增后端：**25 passed**，包括四模板×Android/Linux 的 **8 组真实 sing-box check**；它验证配置语法与核心接受性，没有启动 Android VpnService。
- 新增浏览器：**249/249**，覆盖明暗主题、320/390/600/768/820/1024/1100/1280/1440/1560/1920px、200% CSS 缩放、RTL、长按钮文字、逐卡复制、二维码实际生成与焦点恢复、真实下载内容/文件名、导入 URI、缺失数据、复制失败与 dialog 内回退。
- 原客户端交互：**31/31**；主面板：**173/173**；交互审计：**43/43**。
- 升级与失败回滚演练通过；发布清单 **98/98**，Git whitespace 与前端语法检查通过。

截图保存在本机 `work/client-profiles-2.16.1/`，该目录沿用仓库忽略规则，不作为发布制品推送。

## 现场边界

本轮没有修改真实服务器、路由器或用户的客户端配置；浏览器测试使用临时面板与测试订阅。200% 检查采用 CSS 缩放与窄视口回流，未执行所有操作系统的原生浏览器缩放或 VoiceOver 实机读屏。原生 App 的系统 URI 注册、用户 VPN 授权、实际协议握手与出网仍需对应设备验收，不能据本机配置检查宣称“所有客户端绝对最优”。

本轮已检查的卡片布局与键盘交互：Approve。
