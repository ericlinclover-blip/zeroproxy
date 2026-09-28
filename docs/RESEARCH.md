# ZeroProxy 竞品与技术调研

> 调研时间: **2026-09-28** · 方法: GitHub API 实测取数 + 上游源码逐条核对 + 真实二进制端到端验证
> 取数口径: 星标/活跃度来自 GitHub REST API `/repos/{owner}/{repo}` 实时返回, 非二手文章转述。
> 结论先行: 现有生态里**没有第二个产品**把「0 配置 + 1 行部署」当成核心目标。竞品全是多用户
> 商业面板 (要数据库、要建用户、要域名证书、要向导), 本项目占据的是一个真实存在的空位。

---

## 1. 竞品全景

| 项目 | ★ | 语言 | 许可 | 最近推送 | 定位 |
|---|---:|---|---|---|---|
| [MHSanaei/3x-ui](https://github.com/MHSanaei/3x-ui) | 47,067 | Go | GPL-3.0 | 2026-09-28 | 事实标准: 多协议多用户面板 |
| [XTLS/Xray-core](https://github.com/XTLS/Xray-core) | 41,818 | Go | MPL-2.0 | 2026-09-27 | 内核 (Reality/Vision/XHTTP 发源地) |
| [SagerNet/sing-box](https://github.com/SagerNet/sing-box) | 38,368 | Go | GPL-3.0+附加 | 2026-09-28 | 通用内核 + 出站协议最全 |
| [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) | 34,470 | Go | MIT | 2026-09-27 | Clash.Meta 内核, 客户端解析基准 |
| [233boy/v2ray](https://github.com/233boy/v2ray) | 29,679 | Shell | GPL-3.0 | 2026-01-15 | 一键脚本 (无面板) |
| [apernet/hysteria](https://github.com/apernet/hysteria) | 22,577 | Go | MIT | 2026-09-27 | QUIC 内核, 弱网 + 端口跳跃 |
| [vaxilu/x-ui](https://github.com/vaxilu/x-ui) | 19,093 | JS/Go | GPL-3.0 | **2024-08-19** | 3x-ui 的前身, 已实质停更 |
| [tindy2013/subconverter](https://github.com/tindy2013/subconverter) | 17,079 | C++ | GPL-3.0 | 2026-07-09 | 订阅格式转换器 |
| [sub-store-org/Sub-Store](https://github.com/sub-store-org/Sub-Store) | 10,560 | JS | AGPL-3.0 | 2026-09-28 | 高级订阅管理器 |
| [hiddify/Hiddify-Manager](https://github.com/hiddify/Hiddify-Manager) | 9,304 | Python | GPL-3.0 | 2026-09-26 | 多用户反审查面板, 20+ 协议 |
| [Gozargah/Marzban](https://github.com/Gozargah/Marzban) | 7,398 | Python | AGPL-3.0 | 2026-06-08 | API 优先的 Xray 面板 |
| [remnawave/panel](https://github.com/remnawave/panel) | 5,137 | TypeScript | AGPL-3.0 | 2026-09-12 | 新一代订阅制面板 |
| [cedar2025/Xboard](https://github.com/cedar2025/Xboard) | 4,737 | PHP | MIT | 2026-08-29 | v2board 活跃分支 |
| [v2board/v2board](https://github.com/v2board/v2board) | 5,062 | PHP | MIT | **2024-03-19** | 商业化计费面板, 已停更 |

> 注: `MetaCubeX/mihomo` 的 GitHub 描述字段被污染 (显示成一句星铁 Pydantic 模型文案), 语言字段也
> 误报为 Python。真实身份是 Go 写的 Clash.Meta 内核。这是 GitHub 侧元数据问题, 星标数真实。

---

## 2. 分类剖析

### 2.1 多用户商业面板: 3x-ui / Hiddify / Marzban / Remnawave / Xboard

这一类是生态主体, 星标最高, 但它们的**共同成本结构**正是本项目的切入点:

1. **必有数据库**: 3x-ui 用 SQLite, Marzban 用 SQLAlchemy, Remnawave 用 PostgreSQL。部署后第一件事是迁移。
2. **必有多用户模型**: 用户名/密码/配额/到期时间/流量重置日。哪怕只有自己一个人用, 也要走一遍。
3. **必有部署向导**: 装完要登面板 → 改默认口令 → 配域名 → 申请证书 → 建入站 → 配 SNI 域名 → 才能拿到订阅链接。
   其中「证书」是最容易卡住的一步, 需要域名解析已生效 + 80 端口可达。
4. **大量选项**: 3x-ui 的入站面板有几十个字段。对追求"现在就通"的人, 这是**认知税**。

结论: 它们的「一键」只覆盖**安装**, 不覆盖**配置**。这正是本项目「0 配置」要抢的位。

### 2.2 订阅转换: subconverter / Sub-Store

- `subconverter` (C++): 把一种订阅转成另一种。部署需自建服务 + 上传配置, 是独立组件。
- `Sub-Store` (JS): 功能最强 (脚本化重写、节点筛选), 但活在客户端/云端, 需要 Node 运行时。

它们解决的是「**已有节点, 想换格式**」; 本项目解决的是「**还没有节点**」。本项目把三种订阅格式
**内建在面板里** (见 §4), 不走外部转换器, 少一个部署单元。

### 2.3 一键脚本: 233boy/v2ray

纯 Shell, 无面板, `bash <(curl ...)` 装完直接给链接。它最接近「1 行部署」, 但:

- 无面板、无流量统计、无可视化、改配置要重新跑菜单。
- 只覆盖单一内核 (Xray), 没有 Hysteria/端口跳跃。

本项目的野心正是: **保留脚本的"1 行", 补上面板的"看得见"**。

### 2.4 内核实测 (`2026-09-28` 真实二进制)

本项目直接调用上游内核, 因此内核行为即契约。下载并实跑验证:

| 内核 | 版本 | 用途 |
|---|---|---|
| Xray-core | 26.3.27 | Reality / XHTTP / WS / Trojan / Stats API |
| Hysteria | v2.12.3 | QUIC 节点 + 端口跳跃 |
| mihomo | v1.19.31 | 校验 Clash 订阅可被真实客户端解析 |
| sing-box | 1.14.2 | 校验 sing-box 订阅可被真实客户端解析 |
| sing-box | 1.13.21 | 同一份订阅在"上一个稳定大版本"上复测 (1.14 才加入的字段会在这里暴露兼容性代价) |

---

## 3. 一手证据: 本项目采信的上游事实

以下每条都从上游源码或真实二进制中得到, 并已在 `scripts/verify.py` 里端到端复现。这些是"新闻稿
式文章"不会写、但会让面板直接启动失败的东西。

| # | 事实 | 证据 | 影响 |
|---|---|---|---|
| 1 | Xray 26.x TLS 证书字段是 `certificateFile` / `keyFile`; `certificate` / `key` 已变为 **PEM 内容数组** | `infra/conf/transport_security.go` `TLSCertConfig` | 用旧字段名会导致 Xray 拒绝启动 |
| 2 | `sniffing.destOverride` 合法值仅 `http` / `tls` / `quic` / `fakedns` | Xray 配置校验 | 写 `dns` 直接报配置错误 |
| 3 | Stats API 的路由规则 `outboundTag` 必须指向 **API 入站的 tag** (本项目为 `api`) | `infra/conf/api.go` `APIConfig{Tag,Listen,Services}` | 指 `direct` 则统计读数为空 |
| 4 | Hysteria 服务端口令是**整串比较** | `extras/auth/password.go` `auth == a.Password` | 决定订阅链接怎么写 |
| 5 | 端口跳跃判定: 端口串含 `-` 或 `,` 即视为跳跃端口 | `app/cmd/client.go` `isPortHoppingPort` | `mport` 参数必须与多端口监听一致 |
| 6 | Hysteria 伪装支持 `type: proxy` + `url` / `rewriteHost` / `xForwarded` / `insecure` | `app/cmd/server.go` `serverConfigMasqueradeProxy` | 非代理流量可反代到真实网站 |
| 7 | sing-box 1.13+ 移除入站 legacy 字段 `sniff: true` | 1.14.2 实测 `check PASS/FAIL` | 旧模板会导致订阅校验失败 |
| 8 | Clash 的 `ws-opts.headers` 必须是 **map**, 不是字符串 | mihomo `-t` 实测 | 手写序列化会产出非法 YAML |
| 9 | Xray 在**配置构建阶段**就要加载 geo 数据: 写了 `geoip:` / `geosite:` 规则而 `geoip.dat` 缺失时, 不是"跳过该规则", 而是**整份配置加载失败** (`failed to load GeoIP: cn > failed to open file: geoip.dat`) | 隔离目录实测 (26.3.27): 无 dat → 启动失败; `XRAY_LOCATION_ASSET` 指向含 dat 的目录 → 正常启动 | geo 规则绝不能"无条件下发", 必须与数据文件存在性绑定 |
| 10 | `geoip:private` 也依赖 `geoip.dat`, **不是**内置常量 | 同上 (隔离目录 + 仅 private 规则 → 同样启动失败) | 连"私有地址防护"这种基础规则都有前置条件 |
| 11 | Xray 找 geo 文件的顺序: 可执行文件所在目录 → `XRAY_LOCATION_ASSET` | 把二进制复制到空目录后立即失败, 加环境变量后恢复 | 生产必须在 systemd 单元里设置该变量, 面板调用 `xray` 时也要带上 |
| 12 | mihomo 加载含 `GEOIP` 规则的订阅时会下载 `geoip.metadb`, 默认源是 GitHub | 实测: `GEOIP,CN,DIRECT` → `can't download MMDB ... operation timed out` → 整个订阅 `test failed` | 订阅应内置 `geox-url` 指向可用镜像, 否则受限网络下用户首次导入直接失败 |
| 13 | sing-box 1.12 起**内置** `geoip` / `geosite` 规则字段被彻底移除, 分流只能改用远程 `rule_set` | 1.14.2 实测报错原文: `geosite database is deprecated in sing-box 1.8.0 and removed in 1.12.0` | 面向 sing-box 的分流模板必须用远程 rule-set, 不能再写 `route.geosite` |
| 14 | 远程 rule-set 若**不指定下载出口**, sing-box 会拿**默认出站 (即节点组)** 去下载; 节点不可达时直接 `FATAL` 起不来 (引导期死锁) | 1.14.2 + 1.13.21 双版本实测: 节点写不可解析域名时 `FATAL ... Get "http://…/ads.srs": lookup proxy.example.com: empty result`; 日志显示下载确实走了 `outbound/vless[node-A]` | 分流模板必须把下载指向直连, 否则"节点没通 → 客户端整个起不来" |
| 15 | `route.rule_set[].download_detour` (1.8~1.15 可用, 1.14 起标记废弃, **1.16 移除**) 与 1.14 新增的 `http_clients` + `route.default_http_client` 是**两代互斥写法** | 上游 `option/route.go` v1.14.2 源码 + docs「Changes in sing-box 1.14.0」; 实测 1.13.21 遇到 `http_clients` 直接 `decode config: http_clients: json: unknown field` (Options 解码用 `DisallowUnknownFields`) | v1.14.0 发布于 2026-08-31 (不到一个月), 绝大多数在用的客户端仍是 1.13 —— 默认订阅只能用 `download_detour`, 新版写法做成可选格式 |
| 16 | 写 `detour: "direct"` 的 HTTP 客户端会被拒绝: `detour to an empty direct outbound makes no sense`; **留空 detour 才是直连** | 1.14.2 实测 (http_clients 写法) | 生成 `http_clients` 时不能画蛇添足地写 `detour` |
| 17 | 证书文件"生成后消失"同样会让 Xray 拒绝启动 (`failed to parse certificate > open …: no such file or directory`) | 隔离二进制 + 指向不存在证书的 Trojan 入站 → `xray -test` exit 23 | 与 geo 数据同一个漏洞面, 启动前自检应一并兜底 |
| 18 | 远程 rule-set 的下载结果会被 `experimental.cache_file` 缓存, 第二次启动零下载 | 1.13.21 实测: 4 次启动只发出 3 次 GET (首轮各 3 次, 第二轮 0 次), 断网也能用上次数据启动 | 订阅应默认开启缓存, 启动速度和离线可用性都受益 |

### 3.1 一个反直觉的口令陷阱

Xray 的 VLESS/Trojan 用 `user:pass@` 是 **HTTP Basic 风格的 URI 语法糖**; 但 Hysteria2 的
`hy2://` URI 里, 客户端会把 `user:pass` **整串**当作 auth 发给服务端, 而服务端做的是整串比较
(见证据 #4/#5)。因此生成 Hysteria2 链接时**只能写密码, 不能写 `user:pass`**, 否则认证必然失败。
这一点在 `backend/zeroproxy/share_links.py` 中已固化, 并由真实客户端解析测试守护。

### 3.2 sing-box 分流模板: 三种写法的实测定档

证据 #14~#16 凑在一起, 就变成一道必须做选择的兼容题。三种候选写法在**两个真实版本**上的表现:

| 写法 | sing-box 1.13.21 | sing-box 1.14.2 | 结论 |
|---|---|---|---|
| 不指定下载出口 (改版前) | 下载走节点; 节点不可达 → `FATAL` | 同上, 且多一条废弃警告 | ✗ 引导期死锁 |
| `rule_set[].download_detour: "direct"` | **启动成功**, 下载走 `outbound/direct` | **启动成功**, 走直连, 有废弃警告 (1.16 移除) | ✓ 默认采用 |
| `http_clients` + `route.default_http_client` | ✗ `unknown field "http_clients"` | **启动成功**, 零警告 | ✓ 作为可选格式 |

因此本项目默认订阅 (面向**当前在用的 1.13 / 1.14**) 统一写 `download_detour: "direct"`, 并额外提供
`?format=singbox-next` 给 1.14+ 客户端生成 `http_clients` 写法。两者都由 `scripts/verify.py`
每天用"本地 rule-set 镜像 + 不可解析节点"实跑验证: 只有下载确实走了直连, 进程才能活下来。

---

## 4. 本项目的技术取舍 (吸收了什么, 拒绝什么)

**吸收自竞品**:

| 能力 | 来源参考 | 本项目实现 |
|---|---|---|
| VLESS + Vision + Reality 主力节点 | 3x-ui / Xray 社区默认推荐 | 默认节点, 免证书, 端口 8443 |
| VLESS + XHTTP + Reality | Xray 25+ 新传输 | 新增节点, 端口 8445 (特征最接近普通 HTTP) |
| Hysteria2 + 端口跳跃 | Hiddify / hysteria 官方 `mport` | UDP 30001 + 跳跃段 31001/32001 |
| Clash / sing-box / 通用 三格式订阅 | subconverter / Sub-Store | 内建生成, 无外部转换器 |
| 流量统计 (Stats API) | 3x-ui / Marzban | gRPC StatsService, 每节点上下行 |
| 订阅链接恒定 | 3x-ui `subId` / Sub-Store | 状态驱动, URL 永不随配置变更而变 |
| 证书自动续期 | 通用 | certbot `--keep-until-expiring --expand` |
| 私有地址防护 / 广告拦截 | 3x-ui 的路由模板、Hiddify 的 ACL | `geoip:private` + `geosite:category-ads-all` → `blackhole` |
| 分流数据库分发 | 商业面板自带 geo 同步 | 多镜像下载 + 真实 `xray -test` 校验 + 原子替换 + 每周自动更新 |
| 配置备份/迁移 | Marzban / 3x-ui 的备份功能 | 单文件 JSON + SHA-256 校验 + 一键还原 |

**刻意拒绝** (为了守住「0 配置」):

| 不做 | 理由 |
|---|---|
| 数据库 | 状态是一个 `data/state.json`, 无迁移、无依赖 |
| 多用户 / 配额 / 计费 | 目标是个人与小团队; 引入即成商业面板复杂度 |
| 强制域名 + 证书 | Reality 免证书是默认主力, 证书只在 WS/Trojan 分支可选 |
| 安装后配置向导 | 首次访问用引导令牌一键生成全部 5 个可用节点 |
| 外部订阅转换器 | 三格式内建, 少一个部署单元和故障点 |

**安全模型对标**: 竞品多为"安装即监听公网 + 默认口令"。本项目改为: 面板仅 127.0.0.1 回环,
由 nginx 终结 TLS; 首次初始化需一次性引导令牌 (`data/bootstrap_token`, 0600, 用后即删),
登录带 `2^n` 秒递增封禁, 并下发 CSP / X-Frame-Options / nosniff 等安全响应头。

---

## 5. 差距与后续路线 (诚实清单)

本项目**当前不如**竞品的地方:

1. **无多用户/配额** — 3x-ui / Marzban / Remnawave 的主战场, 本项目不覆盖 (定位差异, 非缺陷)。
2. **分流规则可定制性** — 已有三档模板 (智能/全局/直连), 但不支持用户自定义规则集
   (Sub-Store 在这一层更强)。
3. **无 Docker 交付** — 目前是 Shell 一行部署, 未提供镜像。
4. **无多域名/多证书** — 单域名单证书。
5. **IPv6 未专门处理** — 双栈环境需手动确认。
6. **核心二进制更新非自动 (opt-in)** — 面板「一键更新」只换面板代码; 要连 Xray / Hysteria 2
   一起升到最新, 需显式给 `upgrade.sh` 加 `ZP_UPDATE_CORE=1` (默认不执行, 避免动到正在跑的内核)。

### 已补齐 (本轮)

| 原差距 | 现状 |
|---|---|
| 无节点健康/延迟探测 | `GET /api/probe`: Reality/Trojan 走**完整 TLS 握手**, WS 走 TCP, Hysteria 走 UDP 监听检测, 另测出口 RTT |
| 无分流数据自动更新 | GeoIP/GeoSite 多镜像下载 + `xray -test` 真机校验 + 原子替换, 面板后台每 6 小时检查、7 天 TTL |
| 无备份/恢复 | `GET /api/backup` / `POST /api/restore`, 带 SHA-256 校验和与三重校验 |
| 订阅只有一条硬编码规则 | 三档**客户端分流模板** (智能分流 / 全局代理 / 全部直连), 面板切换或 `?rules=` 覆盖; Clash 侧带 5 个策略组, sing-box 侧带 selector/urltest 出站组 |
| 启动期可能被 geo 数据卡死 | `systemd ExecStartPre` 调用 `python -m zeroproxy.geodata guard`: 数据缺失或配置自检不过就按当前状态重新生成, 保证核心先起来 (证书丢失同路径兜底) |

---

## 6. 引用

- GitHub REST API `GET /repos/{owner}/{repo}` — 星标/语言/许可/推送时间, 取数于 2026-09-28。
- Xray-core 源码: `infra/conf/transport_security.go`, `infra/conf/api.go`,
  `transport/internet/splithttp/config.go` (版本 26.3.27)。
- Hysteria 源码: `app/cmd/client.go` (`isPortHoppingPort`, `fillServerAddr`),
  `app/cmd/server.go` (`serverConfigMasquerade*`), `extras/auth/password.go` (v2.12.3)。
- GeoIP/GeoSite 数据: [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat)
  release 分支 (每日构建); 客户端侧数据源 [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)。
- sing-box 源码: `option/route.go` / `option/options.go` / `option/http.go` (v1.14.2),
  `docs/configuration/route/*` 与 `docs/configuration/shared/http-client*` (字段版本号与语义)。
- 端到端复现: 见仓库 `scripts/verify.py` (真实内核 **74/74**) 与 `backend/tests/` (**149 项**: 144 通过 / 5 跳过, 跳过多为 Linux 专属校验)。

原始取数结果保存在开发机的 `/tmp/zp-bin/competitors.json` (临时文件, 不入库)。
