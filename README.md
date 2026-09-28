# ZeroProxy

> **0 配置, 1 行部署** 的智能科学上网代理面板。
> 不需要懂 Linux, 不写配置文件, 不手动申请 SSL, 不需要客户端折腾。

一条命令从空服务器到可用节点:

```bash
curl -fsSL https://raw.githubusercontent.com/ericlinclover-blip/zeroproxy/main/install.sh | bash
```

网络受限时可用镜像源 (内容相同), 或指定分支 / 版本:

```bash
# jsDelivr 镜像 (国内通常更快)
curl -fsSL https://cdn.jsdelivr.net/gh/ericlinclover-blip/zeroproxy@main/install.sh | bash

# 指定版本或分支, 或改用 fork / 自建镜像
ZP_REF=v2.2 bash -c "$(curl -fsSL https://raw.githubusercontent.com/ericlinclover-blip/zeroproxy/main/install.sh)"
ZP_REPO=your-name/zeroproxy ZP_REF=main bash -c "$(curl -fsSL https://raw.githubusercontent.com/your-name/zeroproxy/main/install.sh)"
```

已经 clone 了仓库的话, 直接跑本地脚本即可 (会自动走「本地代码目录」路径, 不再下载仓库):

```bash
sudo bash install.sh
```

终端会输出形如 `https://<服务器IP>:8899/?token=xxxx` 的地址 (引导阶段自签证书) →
浏览器打开 (首次提示不安全, 点「继续访问」) → 填 **域名 / 用户名 / 密码** 三个信息
→ 点「一键生成」→ 得到 5 个节点、三种格式的订阅链接与二维码。
之后改用 `https://<你的域名>:8899`, 即为 **Let's Encrypt 真实可信证书**。

### 升级 (已经部署过)

面板右上角有「程序更新 → 一键更新」(先弹确认框列出会做什么, 升级中逐步显示进度与已用时间,
结束给出成功 / 失败结论并提示重新加载面板, 见 8.2); 命令行等价的一条命令:

```bash
curl -fsSL https://raw.githubusercontent.com/ericlinclover-blip/zeroproxy/main/upgrade.sh | bash
```

升级只替换程序代码, `data/state.json`(密钥 / 口令 / 订阅令牌 / 节点开关) 原样保留,
订阅地址不变, 客户端不用重新导入。

---

## 1. 能力总览

| 能力 | 说明 |
|---|---|
| **一条命令部署** | `install.sh` 自动完成 BBR、依赖、Xray/Hysteria 2 二进制、venv、nginx 引导配置、systemd、防火墙 |
| **一键更新** | 面板「程序更新」按钮, 或服务器上 `upgrade.sh` 一条命令: 自动备份代码与 `state.json` → 替换 → 按现有 `state.json` 重新落地配置 → 失败自动回滚; 面板内更新由 systemd 瞬时单元托管, 面板自身重启不会打断升级 |
| **配置落地可验证** | 每次应用配置都用真实二进制校验 (`xray -test` / `nginx -t`) 并**复查端口是否真的在监听**; 任一步失败会在面板顶部标红, 不再出现「服务全绿但节点全不通」 |
| **5 个节点** | VLESS Reality (TCP+Vision)、VLESS XHTTP Reality、VLESS WebSocket、Trojan TLS、Hysteria 2 (QUIC+端口跳跃) |
| **链式代理 (中转 → 落地)** | 两台机器各装一份本面板, 在面板里用一行**配对码**把它们接成一条链: 近的机器做入口 (延迟低), 远的机器做落地 (出口 IP 换成它)。对客户端只是「订阅里多了一个普通节点」——不用手写 Clash relay / sing-box detour, 手机也能用; 落地凭据是**独立 UUID + 独立端口**, 可单独轮换 / 吊销, 不影响自己的订阅 |
| **3 种订阅格式** | 同一订阅地址 `?format=` 切换: Base64 通用 / Clash(mihomo) YAML / sing-box JSON |
| **3 档分流模板** | 智能分流 (国内直连+广告拦截) / 全局代理 / 全部直连; 面板一键切换或 `?rules=` 单客户端覆盖, 切换不重启服务 |
| **引导令牌保护** | 初始化必须带 `?token=`, 公网暴露时别人抢不走你的面板; 初始化成功即作废 |
| **一键自检自愈** | `/api/diagnose` 检查 8 项 (服务、配置、入站一致性、GeoIP 一致性、证书、端口、伪装目标可达性) + `/api/repair` 重新生成并重启 |
| **节点测速** | `/api/probe` 对每个节点做**真实握手** (Reality / Trojan 走完整 TLS, 失败即说明配置不对), 并测服务器到伪装目标的出口延迟 |
| **GeoIP 分流防护** | 私有地址防护 (阻止客户端借道访问服务器内网) + 广告域名拦截; 数据每周自动更新, 缺失时自动不下发规则 |
| **备份 / 恢复** | 一键导出含全部密钥与令牌的备份, 换机或重装后一键还原 (校验和校验, 篡改即拒绝) |
| **流量统计** | 内置 Xray Stats API (仅 127.0.0.1), 仪表盘按节点展示上下行, 并写入订阅的 `subscription-userinfo` 头 |
| **订阅恒定, 内容动态** | 订阅 URL 永不变; 节点启停 / 端口变更 / 伪装设置都会自动同步到客户端 |
| **安全默认值** | 登录限流、会话上限与过期清理、PBKDF2-SHA256(12 万轮)、`state.json` 0600 原子写、CSP 等安全响应头、无 CORS 通配 |
| **一键卸载** | `uninstall.sh`, 与安装对称 (可保留数据或证书) |
| **启动期自愈** | systemd `ExecStartPre` 跑 `geodata guard`: geo 数据丢失或配置自检不过时, 按当前状态重新生成配置, 保证 Xray 一定能起来 (证书丢失同一路径兜底) |
| **可回归验证** | `pytest` 116 项 (111 passed + 5 skipped; 带 `ZP_XRAY_BIN` 时 116 全通过) + `scripts/verify.py` (74 项, 含**两台机器真跑一条链**) + `scripts/browser_check.cjs` (81 项) + `scripts/upgrade_sim.sh` (21 项), 全部用真实二进制 / 真实浏览器 / 真实升级脚本 |
| **看得见的升级** | 面板内升级是一条完整闭环: 版本对比 → 确认弹窗 (逐条列出会做什么 / 不动什么) → 逐步进度 (待执行 ○ / 进行中 ⟳ / 已完成 ✓ + 进度条 + 已用时间) → 完成或失败结论卡 (失败标出断在第几步 + 日志 + 自动回滚说明) → 一键重新加载面板; 步骤清单由 `upgrade.sh` 自己写进 `update.json`, 前端不猜 |
| **看得懂的界面 (v2.6.0)** | 控制台布局: 左侧锚点导航 (带计数角标 + 滚动高亮) + 顶部指标条 (健康节点 / 落地出口 IP / 平均延迟 + 迷你折线 / 运行时长) + 节点密集表格 (名称 / 地址状态 / **握手延迟条** / **上下行双轨** / 开关与复制) + **流量卡 (双弧圆环 + 实时速率曲线 + 逐节点双色流量条)** + 链式链路拓扑 (你的设备 → 本机入口 → 落地端) + 程序更新闭环; 动效全部走 `transform`/自绘 rAF 并受 `prefers-reduced-motion` 约束 |

竞品与技术调研见 `docs/RESEARCH.md`。

---

## 2. 项目结构

```
zeroproxy/
├── install.sh                     # 一键部署 (BBR / 依赖 / 二进制 / venv / nginx 引导 / systemd / ufw / 引导令牌)
├── upgrade.sh                     # 一键升级 (备份 → 换代码 → 按 state.json 重新落地配置 → 失败回滚)
├── uninstall.sh                   # 一键卸载 (停服务 / 清单元 / 删 nginx 配置 / 回收 ufw / 可选保留数据)
├── dev.sh                         # 本地开发启动 (macOS 可跑, 无 systemd 自动 dry-run)
├── backend/
│   ├── requirements.txt           # fastapi / uvicorn / qrcode / cryptography / pyyaml
│   ├── requirements-dev.txt       # + pytest / httpx
│   ├── tests/                     # pytest 回归测试 (dry-run 全流程 + 安全边界 + 状态迁移)
│   ├── static/
│   │   └── index.html             # Apple 风格单文件 UI (零构建, 深浅色, 无 CDN)
│   └── zeroproxy/
│       ├── main.py                # FastAPI 入口 + 安全响应头中间件
│       ├── config.py              # 状态模型 (state.json v4) / 文件锁 / 引导令牌 / 审计日志 / 备份还原
│       ├── crypto.py              # VLESS UUID 派生 / Reality X25519 密钥对 / PBKDF2
│       ├── xray_config.py         # Xray 配置生成 (Reality / XHTTP / WS / Trojan + Stats API)
│       ├── chain.py               # 链式代理 (配对码打包 / 解析 / 落地端口分配 / 真实出口 IP 探测)
│       ├── geodata.py             # GeoIP/GeoSite 下载与校验 + 分流规则 (硬前置: 数据缺失不下发) + 启动前自愈 CLI
│       ├── nginx_config.py        # Nginx 生成 (ACME + 443 WS 反代 + 伪装主页 + 8899 面板 TLS)
│       ├── hysteria_config.py     # Hysteria 2 配置生成 (端口跳跃 + masquerade 伪装)
│       ├── apply.py               # 配置落地闭环 (生成 → xray -test / nginx -t → 重载 → 复查端口监听), 面板与 upgrade.sh 共用
│       ├── update.py              # 面板自更新 (远端版本检查 + 触发 upgrade.sh + 回读升级进度)
│       ├── services.py            # systemctl / certbot / 自签证书 / 流量统计 / 节点握手探测 / 诊断
│       ├── share_links.py         # 单节点链接 + Base64 / Clash / sing-box 订阅 + 三档分流模板
│       └── routes.py              # API: setup / login / dashboard / settings / diagnose / probe / backup / sub / qr / update / chain
├── docs/
│   └── RESEARCH.md                # 竞品与技术调研 (含上游源码一手证据)
├── scripts/
│   ├── verify.py                  # 端到端验证: 真实二进制跑通配置生成 / 订阅解析 / 探测 / 备份 / GeoIP
│   ├── browser_check.cjs          # 真实浏览器 (Playwright) UI 验证与截图
│   └── upgrade_sim.sh             # 一键升级演练: 真跑 upgrade.sh (桩掉 root/systemd), 覆盖成功与回滚两条路径
└── systemd/
    ├── zeroproxy.service          # 面板 (仅监听 127.0.0.1:9900, nginx 在 8899 终结 TLS)
    ├── xray.service
    └── hysteria2.service
```

运行时布局 (服务器):

```
/opt/zeroproxy/
├── zeroproxy/ static/ venv/       # 面板代码与虚拟环境
├── data/state.json                # 全部可变状态 (0600)
├── data/bootstrap_token           # 引导令牌 (0600, 初始化成功后自动删除)
├── geo/geoip.dat geosite.dat      # GeoIP/GeoSite 分流数据 (由 XRAY_LOCATION_ASSET 指向)
├── panel/cert.pem key.pem         # 面板 HTTPS 引导自签证书
├── xray/config.json               # 由面板生成
├── hysteria/config.yaml + cert.pem/key.pem
├── certs/                         # 自签兜底证书
├── www/                           # ACME webroot + 443 伪装主页
└── nginx/zeroproxy.conf           # 配置副本 (同一份也会写入 /etc/nginx/conf.d/)
```

---

## 3. 协议组合

一键生成 5 个节点, 覆盖《vless-trojan-hysteria2-technical-principles.md》中的全部协议组合:

| 节点 | 组合 | 端口 | 原理 (文档章节) | 定位 |
|------|------|------|------------------|------|
| VLESS Reality | VLESS + TCP + XTLS-Reality + `xtls-rprx-vision` | 8443/tcp | §7 | 主力, 反封锁最强, 免证书 |
| VLESS XHTTP Reality | VLESS + XHTTP + XTLS-Reality | 8445/tcp | §9 | 流量形态最接近普通 HTTP, 免证书 |
| VLESS WebSocket | VLESS + WS, TLS 由 nginx 443 终结 | 443/tcp | §2.3 | 全平台/浏览器兼容, 可挂 CDN |
| Trojan | Trojan + TLS 1.3, fallback 伪装 | 8444/tcp | §3 | 经典 HTTPS 伪装 |
| Hysteria 2 | QUIC/UDP + ChaCha20-Poly1305 | 30001/udp (+31001/32001 跳跃) | §4 + 附录 C | 弱网最优, 端口跳跃抗封锁 |

设计决策:

- **凭据统一**: 用户只输入一次密码 — Trojan / Hysteria 2 直接使用该口令, VLESS UUID 由
  `SHA256(用户名+密码)` 确定性派生, 重新生成配置时 UUID 恒定, 客户端无需重新导入。
- **Reality 免证书**: 部署时生成 X25519 密钥对 (REALITY 只认 X25519, 用 Ed25519 生成的
  密钥对会让每一次握手都失败 —— 服务端 active、面板全绿、节点却不通), `pbk`/`sid` 随订阅
  分发; 面板可随时改伪装目标 (自动改成 `sni:443`)。
- **伪装目标的硬约束 (实测 + `xtls/reality` 源码)**: 目标站点发回的 Certificate 握手报文
  必须 ≤ **8192 字节** (REALITY 服务端缓冲上限), 超了服务端直接放弃握手、客户端只看到连接
  被重置。默认值因此从 `www.microsoft.com` (证书链 **8273** 字节, 必定失败) 换成
  `www.cloudflare.com` (ECDSA 链 4KB 出头, 实测通过); 换目标后请点「节点测速」验证 ——
  它现在用真实客户端穿一次外网, 而不是只看端口是否监听。
- **XHTTP**: Vision flow 只能用于 TCP, 因此 XHTTP 入站 `flow` 为空; 与 Reality 叠加后同样免证书。
- **端口跳跃默认开启**: Hysteria 2 同时监听 3 个 UDP 端口, 封锁单端口不影响服务; 订阅链接把端口
  写在 host 位置 (`host:30001,31001,32001`), 官方客户端据此启用 udphop。
- **Hysteria masquerade**: 非代理流量反代到一个真实网站 (`type=proxy` + `rewriteHost`),
  复用 QUIC 端口, 不额外占用 TCP 端口。
- **443 伪装主页**: nginx 对非代理路径返回中性网页。
- **面板走真实可信证书**: 面板进程只监听 `127.0.0.1:9900`, 对外由 nginx 在 **8899** 终结 TLS —
  SNI 命中域名用 Let's Encrypt 证书, 其余 (IP / 未知 SNI) 回退自签。
- **流量统计**: Xray 配置内置 `stats`/`policy`/`api`, API 入站只监听 `127.0.0.1:10085`,
  路由规则把 API 入站交给 `tag=api` 处理器 (写成 `direct` 时 `xray api statsquery` 连不上)。
- **GeoIP 分流是"硬前置"的**: Xray 在配置构建阶段就要求 `geoip.dat` / `geosite.dat` 存在,
  缺文件时不是跳过规则而是**整份配置加载失败**。因此本项目把"数据齐备"作为下发 geo 规则的前提
  (`geodata.usable()`), 数据被删也只会退化成"没有这两条规则", 不会让核心起不来。

---

## 4. 订阅: 一个地址, 三种格式, 三档分流

```
GET /sub/{token}                   → Base64 (通用: Shadowrocket / v2box / NekoBox / Streisand ...)
GET /sub/{token}?format=clash      → mihomo / Clash.Meta 完整 YAML (含 proxy-groups 与 rules)
GET /sub/{token}?format=singbox    → sing-box 完整 JSON (mixed 入站 + 嗅探 + 自动选择出口)
GET /sub/{token}?format=singbox-next  → 同上, 但用 1.14+ 的 http_clients 写法 (无废弃警告)
任意格式可叠加 ?rules=smart|global|direct  → 只为这一个客户端覆盖分流模板
```

**分流模板** (面板「高级设置 → 分流模板」切换, 或在 URL 上加 `?rules=`):

| 模板 | 规则 | 适用 |
|---|---|---|
| `smart` (默认) | 广告拦截 + 国内域名/IP 直连 + 私有地址直连, 其余走节点 | 日常: 国内网站直连, 国外走代理 |
| `global` | 只拦广告, 其余全部走节点 | 需要全部流量走代理 |
| `direct` | 全部直连 (策略组手动选节点) | 排障 / 不需要分流, **零 geo 下载** |

两端的策略组是一套语义: `♻️ 自动选择` / `🚀 节点选择` / `🎯 全球直连` / `🛑 广告拦截` / `🐟 漏网之鱼`。
切换模板只影响订阅输出, **不重载任何服务** (前端即时生效)。

- 三种格式**内容一致、地址恒定**; 客户端按 `profile-update-interval: 12` 自动刷新, 节点启停 /
  端口变更 / 伪装设置变化自动同步, 用户侧零操作。
- 响应带 `subscription-userinfo` 头 (有统计数据时), 客户端可直接显示已用流量。
- **sing-box 分流的关键细节** (双版本实测, 见 `docs/RESEARCH.md` §3.2):
  sing-box 不指定下载出口时会**拿节点去下载 rule-set**, 节点没通就 `FATAL` 起不来 —— 因此订阅
  统一写 `download_detour: "direct"` 让 geo 数据走直连, 并默认开启 `experimental.cache_file`
  (第二次启动零下载, 断网也能用上次数据)。1.14 起该字段标记废弃, 所以另给
  `?format=singbox-next` 走新的 `http_clients` 写法 (1.13 及更早**不支持**, 会报 unknown field)。
- **凭据格式经过源码级核对**: Hysteria 2 官方客户端把 `hysteria2://user:pass@host` 整串 `user:pass`
  当作 auth 发送, 而服务端 `extras/auth/password.go` 是整串比较口令 —— 因此本面板只写
  `hysteria2://<password>@host`; 端口跳跃同样按官方实现写在 host 的端口位置 (并附带 `mport`
  供支持该参数的三方客户端使用)。
- XHTTP 支持情况已用真实客户端验证: mihomo v1.19.31 (`network: xhttp` + `xhttp-opts`) 与
  sing-box 1.14.2 (`transport.type: http`) 都能通过配置校验。

---

## 5. 安全模型

| 面 | 措施 |
|---|---|
| 初始化抢注 | `install.sh` 生成一次性引导令牌 (`data/bootstrap_token`, 0600), 打印带 `?token=` 的链接; `/api/setup` 常量时间比对, 成功后立即删除令牌 |
| 面板暴露面 | 面板进程只监听 `127.0.0.1:9900`; 对外只有 nginx 的 8899, 可由安全组限制来源 IP |
| 登录爆破 | 连续失败 3 次起按 2^n 秒封禁 (上限 300s), 返回 `429` + `Retry-After`; 封禁状态持久化, 重启不重置 |
| 会话 | HttpOnly + SameSite=Lax, HTTPS 下自动加 Secure, 72h 过期, 最多 8 个会话 (超出淘汰最旧), 支持「全部登出」 |
| 口令存储 | PBKDF2-SHA256, 16 字节随机盐, 12 万轮, 常量时间比较 |
| 文件 | `state.json` / 私钥 / 令牌均 0600; 状态写盘走「临时文件 + fsync + rename」原子替换 |
| 并发 | `config.locked()` = 进程内 RLock + `fcntl.flock`, 读-改-写事务化 |
| HTTP 头 | CSP (禁外域脚本与 iframe 嵌入)、`X-Content-Type-Options`、`X-Frame-Options: DENY`、`Referrer-Policy`、`Permissions-Policy`; 不开放 CORS 通配 |
| 审计 | 最近 200 条操作记录 (setup / login / login_failed / settings / toggle / apply / repair / renew) |

---

## 6. 智能自检与自愈

`GET /api/diagnose` (仪表盘「一键诊断」) 逐项检查:

1. Xray / Hysteria 2 / Nginx systemd 状态
2. `xray -test` 配置合法性
3. 入站与节点开关是否一致 (改完设置忘记重启会被抓到)
4. TLS 证书类型、剩余天数、文件是否存在
5. GeoIP 数据与分流规则是否一致 (配置里有 geo 规则但数据缺失 = Xray 必然起不来)
6. 对外端口是否被其他进程占用
7. Reality 伪装目标 (dest) 是否真的可连接
8. 本地开发环境自动跳过系统级检查

`POST /api/repair` 一键自愈: 重新生成 Xray + Nginx + Hysteria 配置 → 重载服务 → 复检并回传结果。

### 6.1 启动期自愈 (systemd `ExecStartPre`)

「面板生成配置时检查过数据」并不等于「磁盘上的配置永远可启动」: 数据文件或证书可能在之后
消失 (磁盘清理、手动删除、恢复到新机器)。此时 `systemctl restart xray` / 重启机器会让
**整个 Xray 起不来** —— geo 数据和证书都在配置构建阶段就要读。

所以 `systemd/xray.service` 在 `ExecStart` 之前跑一次:

```bash
/opt/zeroproxy/venv/bin/python -m zeroproxy.geodata guard    # ExecStartPre, 前缀 '-' 不阻塞启动
```

逻辑: ① 配置里有 geo 规则但数据文件不在 → 按当前状态重新生成 (自动不下发 geo 规则);
② 否则用真实 `xray -test` 自检, 不过同样重新生成 (证书丢失走的就是这条路)。修完还会**再自检一次**
并把结论写进日志 (只是"先保证能用", 面板会继续提示数据/证书需要修复)。

### 6.2 节点测速 (真实握手, 不是 ICMP ping)

`GET /api/probe` (仪表盘「节点测速」, 进入仪表盘时自动跑一次):

| 节点 | 探测方式 | 说明 |
|---|---|---|
| VLESS Reality / XHTTP | **完整 TLS 握手** | Reality 会代答握手并转发目标站点证书; 密钥 / SNI / dest 任一不匹配都会失败 |
| Trojan | **完整 TLS 握手** | 同时验证证书文件与 8444 入站 |
| VLESS WebSocket | TCP 握手 | TLS 由 nginx 终结, 这里验证回环入站存活 |
| Hysteria 2 | UDP 监听检测 | QUIC 无法用 TCP 探测; Linux 读 `/proc/net/udp`, macOS 走 `lsof` |

同时测量**服务器到伪装目标的出口 RTT** (真实网络往返)。注意: 客户端到服务器的 RTT
只能由客户端测量, 服务端自测的数字没有意义 —— 所以这里给的是「握手是否真的成功 + 出口质量」,
这恰好是判断「节点到底能不能用」最直接的证据。

---

## 7. 自动化逻辑 (配置变更 → 订阅同步)

```
用户操作 (开关节点 / 改端口 / 改伪装 / 续期证书)
        │  POST /api/...   (config.locked() 事务)
        ▼
state.json (唯一事实来源, schema v4, 旧版本自动升级)
        │
        ├──► 重新生成 xray/config.json + hysteria/config.yaml + nginx conf
        │            │
        │            ▼
        │     systemctl reload nginx; systemctl restart xray/hysteria2
        │
        └──► 订阅内容 = f(state) 重新计算 (URL 不变)
                     ▼
        GET /sub/{token}[?format=clash|singbox]
```

- 节点关闭 = 订阅中移除该行 + 入站从 Xray 配置移除 + Hysteria 监听收敛回 `127.0.0.1`。
- 证书续期只换文件 + `reload nginx`; 重复 `/api/apply` 使用 `--keep-until-expiring --expand`, 不会重复签发。
- state.json 结构升级: 新增字段在读取时由 `_merge` 自动补齐 (v1 → v2 → v3 → v4 已覆盖测试)。
- 链式代理的落地链路同样走「改 state → 重新生成配置 → 热重载 → 复查端口监听」这条闭环:
  中转端多一个入站 (客户端连它) + 一个出站 (连落地端) + 一条路由规则, 订阅里随即多一个节点。
- GeoIP 数据每 7 天自动更新: 面板后台线程每 6 小时检查一次, 只在数据真的变化时重启 Xray;
  下载先落到临时目录并通过真实 `xray -test` 校验后才原子替换, 所以不会出现"半个数据集"。

---

## 8. 前端 UI

单文件 `backend/static/index.html` (原生 JS + CSS, 零构建零 CDN, 离线可用; 设计系统见 17):

- **设计令牌**: 一套 CSS 变量管深浅色 (背景 / 卡片 / 描边 / 阴影 / 圆角 / 语义色),
  SF 字体栈 + 等宽数字, 吸顶品牌栏带毛玻璃; 深浅色自动跟系统 + 手动切换。
- **三步交互**: 初始化 (三输入框 + 部署进度逐步打钩) → 登录 → 仪表盘, 每 20s 静默轮询。
- **控制台骨架 (v2.6.0)**: 左侧锚点导航 (节点 / 订阅 / 流量 / 链式代理 / 高级 / 诊断 / 系统 /
  程序更新) + 右侧主列; 导航带**计数角标** (启用节点数、已接落地端数、诊断结果、有新版本)
  与**滚动高亮** (IntersectionObserver), 点击平滑滚动到对应区块, 底部常驻
  管理员 / 主机 / 在线 / 版本; ≤1180px 自动落成顶部横滚导航, 主列吃满宽度。
- **顶部指标条**: 健康节点 (带逐节点状态点) / 落地出口 IP / 平均握手延迟 (**附各节点延迟迷你折线**) /
  运行时长 —— 四张一眼看完, 数据全部来自已拉到的 `/api/dashboard` + `/api/probe`, 不额外发请求。
- **节点密集表格**: 五列 —— 节点 (协议徽标 / 名称 / 传输 / 说明 / 链式落地出口 IP) ·
  地址 / 状态 · **握手** (结果徽标 + 按快慢映射的延迟条, 颜色阈值 120 / 250ms) ·
  **流量** (↑↓ 数值 + 上下行双轨条, 按全节点峰值归一化) · 操作 (复制 / 二维码 / 启停开关)。
  悬停整行高亮并在左侧浮出渐变竖条; 测速期间每行呼吸闪烁。一屏能看完 5–6 个节点。
- **流量卡 (v2.6.0 重做)**: 双弧圆环 (上行蓝 / 下行青, `stroke-dasharray` 驱动, 数值变化时
  CSS 自动补间) + 总上行 / 总下行 / 计费节点 + **实时速率曲线** (本页每 20s 采一点, 内存留
  24 点 ≈ 8 分钟, 带渐变面积、末端游标与峰值提示) + **逐节点双色流量条** (蓝=上行 青=下行
  灰=剩余, 归一化到最忙节点, 带流光扫过)。
- 其余区块: 订阅三格式 → 高级设置 (Reality SNI / Hysteria 伪装站点 / 各节点端口 /
  **GeoIP 分流开关与数据更新**) → **链式代理 (带三段式链路拓扑: 你的设备 → 本机入口 → 落地端;
  落地端生成配对码 / 入口端粘贴配对码 → 真实握手测试 → 一键落地; 链式节点带 "链式" 徽标与
  落地出口 IP, 支持设为默认出口 / 单条测速 / 断开, 见 16)** → 诊断 → 系统
  (**含证书申请 / 续期, 备份下载与恢复**) → **程序更新 (完整升级闭环, 见 8.2)**。
- **动效 (可关)**: 状态点呼吸、开关回弹、按钮上浮、卡片悬停抬升、导航竖条、链路虚线流动、
  流量条流光、升级进度条斜纹跑马、区块入场 stagger (40ms 递增)。全部只走 `transform` /
  `opacity` / 自绘 SVG, 并整体受 `prefers-reduced-motion: reduce` 约束 (系统关了动效就全静态)。
- **失败不装成功**: 「一键生成」「保存并应用」「一键修复」的每一步失败都会顶到仪表盘顶部标红
  (含具体原因), 而不是只弹一句「完成」。

### 8.1 初始化 → 域名面板 的交接

初始化是在 **IP 页面**上做的 (`https://<IP>:8899/?token=...`, 自签证书, 浏览器会提示不安全),
而正式入口是 `https://<域名>:8899`。这一步过去只把域名当文字显示在副标题里, 用户初始化完就
一直留在那个"不安全"的 IP 页面上 —— 所以现在把它做成交接:

- 后端在 `/api/setup` 的响应里带上 `redirect`: 只有**证书是 Let's Encrypt 签发的**,
  并且**从服务器本机按浏览器的方式访问 `https://<域名>:8899/api/info` 真的能通**
  (证书链按系统 CA 校验) 时, `ready` 才是 `true`。真实服务器上这一步实测通过。
- `ready` 为真 → 前端显示「部署完成 · 正在跳转到 `https://<域名>:8899/?user=<用户名>` · 3 秒」,
  3 秒后自动跳转, 也可以点「立即前往」; 域名面板的登录页会**预填用户名、聚焦密码框**并提示
  「已切换到域名面板」。会话 Cookie 是按 host 存的, 所以跨到域名必须重新登录一次 ——
  密码不会进 URL, 用户名用完即从地址栏去掉 (`history.replaceState`)。
- `ready` 为假 → **不跳**, 留在 IP 页面并说清原因 (「证书不是 Let's Encrypt (域名可能还没解析到
  本机, 或 80 端口被挡)」), 引导用户去「高级设置 → 重新应用」重试; 避免把人送到一个打不开的地址。
- 事后用 IP 打开面板也一样: 仪表盘顶部会有一条蓝色提示「你正在用 IP 地址访问面板 (证书不受
  浏览器信任)」, 并附「切到域名面板」按钮。

### 8.2 面板内一键升级的交互闭环

早期版本点「一键更新」只弹一个浏览器原生 `confirm`, 点完之后卡片上没有任何反馈: 不知道有没有
真的开始、现在做到哪一步、还剩几步、失败了没有 —— 因为 `upgrade.sh` 只在脚本结束那一刻写一次
`update.json`, 面板根本拿不到中间状态。现在把这条链路补成五段:

1. **版本对比**: 卡片顶部显示「当前 vX · 最新 vY · 检查时间」, 有新版才出现「一键更新 vY」按钮。
2. **确认**: 弹窗逐条列出这次会做的 6 件事 (备份 → 下载 → 替换代码 → 同步依赖 → 重新落地配置 →
   重启面板), 并明确「不会动的部分: 节点密钥 / 订阅令牌 / 管理员账号 / 节点开关与端口设置」;
   确认按钮上再写一遍版本跨度 (`开始升级 v2.3.10 → v2.3.11`)。Esc / 点遮罩 / 取消都能退出且不会开始。
3. **进度**: 面板每 2.5s 回读一次 `update.json`, 卡片上是一条逐步清单 —— 待执行 `○`、
   进行中 `⟳` (转圈动画)、已完成 `✓`, 右侧带每步的真实结果 (备份目录名、版本跨度、`完成`),
   下面是进度条与「已完成 n/N 步 · 已用 X 秒」。
4. **结论**: 成功给绿色横幅 (版本跨度 + 用时 + 触发方式), 步骤详情折叠收起, 卡片不臃肿;
   失败给红色横幅, 直接点出**断在第几步**、失败原因、「代码已自动回滚到升级前版本」,
   进度条转红, 并展开升级日志 —— 按钮回到「一键更新 vY」, 可以原地重试。
5. **收尾**: 面板进程在最后一步会重启, 前端的轮询能容忍请求失败; 重启完成后前端 JS 与服务器
   版本可能已经不一致, 卡片会提示「服务器已是 vY, 本页还是 vX 的界面」并露出「重新加载面板」
   按钮, 同时自动重载一次。

进度数据完全来自脚本自己: `upgrade.sh` 会先算出这次的步骤清单 (`plan`), 每进入一步写
`current`, 每完成一步追加到 `steps` —— 面板只负责把这些字段渲染出来, 不猜步骤、不造进度
(踩过的坑: 前端自己 `setTimeout` 假装进度, 一旦脚本卡住就变成骗人)。

---

## 9. API

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/api/status` | 无 | `{configured, authenticated, token_required}` 视图路由 |
| POST | `/api/setup` | 引导令牌 | `{domain, username, password, token}` → 完整部署流水线 |
| POST | `/api/login` / `/api/logout` / `/api/logout-all` | — / 会话 | 会话 Cookie (72h, 登录限流) |
| GET | `/api/dashboard` | 会话 | 节点 / 证书 / 系统 / 订阅 / 流量 / 审计 全量视图 |
| POST | `/api/nodes/{id}/toggle` | 会话 | 节点启停 → 热重载 |
| POST | `/api/hysteria/hopping` | 会话 | 端口跳跃开关 → 热重载 |
| POST | `/api/settings` | 会话 | 改 Reality SNI / Hysteria 伪装站点 / 节点端口 / 分流模板 (含端口占用校验; 只改模板时不重载服务) |
| GET | `/api/probe` | 会话 | 节点探测 + 服务器出口 RTT (`?deep=1` 用临时 Xray 客户端真的从每个节点穿一次外网, 生产环境面板默认走它; 3s / 20s 缓存) |
| POST | `/api/geodata/update` | 会话 | 下载/刷新 GeoIP + GeoSite 数据并热重载 (互斥, 并发时 409) |
| GET | `/api/backup` | 会话 | 导出备份 JSON (含密钥与令牌, 带 SHA-256 校验和, 不含会话) |
| POST | `/api/restore` | 会话 | 从备份恢复并热重载 (校验和/必填字段/版本三重校验) |
| POST | `/api/apply` | 会话 | 重新生成全部配置并热重载 |
| POST | `/api/renew` | 会话 | `certbot renew` + reload nginx |
| GET | `/api/update` | 会话 | 当前版本 / 远端最新版本 (600s 缓存, `?force=1` 强刷) / 上次升级进度与日志尾部; `last` 里含 `plan` (这次要做哪几步) 与 `current` (正在做哪一步), 面板据此渲染实时清单 |
| POST | `/api/update` | 会话 | 一键更新: 后台拉起 `upgrade.sh` (systemd 瞬时单元, 面板重启不打断); 已有任务或本地开发环境返回 409 |
| GET | `/api/diagnose` / POST `/api/repair` | 会话 | 自检 / 一键自愈 |
| GET | `/api/traffic` | 会话 | 流量统计 (Stats API) |
| GET | `/api/logs/{service}` | 会话 | 服务日志尾部 (journalctl) |
| GET | `/sub/{token}?format=&rules=` | 订阅令牌 | Base64 / Clash / sing-box / sing-box-next 订阅内容, `rules=smart\|global\|direct` 单客户端覆盖分流模板 |
| GET | `/api/nodes/{id}/qr` / `/api/subscription/qr` | 会话 | 节点 / 订阅二维码 PNG |
| POST | `/api/chain/exit` | 会话 | 本机作为**落地端**: `action=generate\|rotate\|disable`, 可带 `port` / `label`; 生成的是独立 UUID + 独立端口的专用凭据 |
| GET | `/api/chain/exit/qr` | 会话 | 配对码二维码 (另一台机器扫码即得, 不用手抄) |
| POST | `/api/chain/entries` | 会话 | 本机作为**入口端**: `{code, label, local_port, default_out, force}` → 解析配对码 → **真实握手探测** → 落地成入站/出站/路由; 探测不通时返回 400 + `{probe, needs_force}`, 由前端二次确认后带 `force=1` 重试 |
| POST | `/api/chain/entries/{id}` | 会话 | 启用 / 停用某条链式连接、设为默认出口 (同时只允许一条)、改名 |
| POST | `/api/chain/entries/{id}/probe` | 会话 | 单条链式连接的测速: 真的穿过落地端出一次网并读回落地出口 IP |
| DELETE | `/api/chain/entries/{id}` | 会话 | 断开并删除 (落地端的凭据不受影响) |

---

## 10. 上游兼容性 (实测)

| 组件 | 实测版本 | 兼容要点 |
|---|---|---|
| Xray Core | **26.3.27** (macOS arm64) | 含 XHTTP + Reality + Stats API 的生成配置通过 `xray -test`, 真实启动后监听 8443 / 8445 / 8444 / 10085 |
| Xray TLS 字段 | — | 25+ 的 `tlsSettings.certificates[]` 只接受 `certificateFile` / `keyFile`; 旧写法 `certificate` / `key` 会导致启动失败 |
| Xray sniffing | — | `destOverride` 合法值只有 `http` / `tls` / `quic` / `fakedns`, 写 `dns` 会被拒绝启动 |
| Xray Stats API | — | 路由必须把 api 入站的 `outboundTag` 指向 `api`; 指向 `direct` 时 `xray api statsquery` 连不上 |
| Xray GeoIP/GeoSite | — | geo 数据在**配置构建阶段**就要读: 写了 `geoip:`/`geosite:` 规则而 `geoip.dat` 缺失时, Xray 不是"跳过规则"而是**整份配置加载失败**。查找路径为可执行文件所在目录或 `XRAY_LOCATION_ASSET` (本项目在 systemd 单元里指向 `/opt/zeroproxy/geo`) |
| Hysteria 2 | **v2.12.3** | 生成的配置 (含 `masquerade.proxy.url` / `rewriteHost`) 能被真实二进制启动; 多端口 `listen` 仅 Linux 支持 (macOS 会明确报错) |
| mihomo | **v1.19.31** | Clash 订阅 (含 `network: xhttp` + `xhttp-opts`、hysteria2 `ports` / `hop-interval`) 通过 `mihomo -t` |
| mihomo geox | — | 订阅里的 `GEOIP` 规则会让 mihomo 首次加载时下载 `geoip.metadb`; 默认指向 GitHub, 受限网络下会超时**导致订阅加载失败**。订阅已内置 `geox-url` 指向可用镜像 |
| sing-box | **1.14.2 / 1.13.21** | 订阅 JSON 双版本通过 `check` 且能被真实 `run` 起来; 1.13 起 legacy inbound 字段 (`sniff: true`) 被移除, 已改用 `route.rules[].action: sniff` |
| sing-box 分流 | — | 1.12 起内置 `geoip`/`geosite` 字段被移除, 只能用远程 rule-set; 不指定下载出口时会**借节点下载** (节点不通即 FATAL), 因此订阅写 `download_detour: "direct"`。1.14 起该字段废弃 (1.16 移除), 另提供 `?format=singbox-next` 用 `http_clients` 写法 —— 它只适用于 1.14+, 1.13 会报 unknown field |
| sing-box 缓存 | — | 订阅默认带 `experimental.cache_file`, 实测第二次启动零下载 |
| certbot | 系统包 | webroot 签发, `--keep-until-expiring --expand` 保证重复应用不重复签发; 失败自动回退自签 (10 年) |

---

## 11. 本地开发 / 验证

```bash
# 启动面板 (本地无 nginx, 直接明文 HTTP; 无 systemctl 自动 dry-run)
cd zeroproxy && ZP_PORT=8899 ./dev.sh           # → http://127.0.0.1:8899

# 回归测试 (dry-run, 不碰系统)
cd backend && python -m pytest tests -q

# 回归测试 + 用真实 Xray 校验生成的配置
ZP_XRAY_BIN=/path/to/xray python -m pytest tests -q

# 端到端验证: 真实启动 Xray / Hysteria, 并用真实客户端解析订阅
ZP_XRAY_BIN=/path/to/xray ZP_HYSTERIA_BIN=/path/to/hysteria \
ZP_MIHOMO_BIN=/path/to/mihomo ZP_SINGBOX_BIN=/path/to/sing-box \
python3 scripts/verify.py

# 真实浏览器 UI 验证 (Playwright; 需 node + playwright)
ZP_NODE_PATH=/path/to/node_modules node scripts/browser_check.cjs

# 一键升级演练: 造一台"已部署的假机器", 用桩二进制真跑 upgrade.sh
# (不需要 root / systemd; 覆盖正常升级 + 下载失败自动回滚两条路径)
ZP_PYTHON=$PWD/.venv/bin/python bash scripts/upgrade_sim.sh
```

开发环境可用 `ZP_XRAY_BIN` / `ZP_HYSTERIA_BIN` / `ZP_NGINX_BIN` 指定二进制绝对路径
(自定义安装位置, 或在 macOS 上做真实二进制验证)。

---

## 12. 开发验证记录

在 macOS (Apple Silicon, Python 3.14) 上实测通过:

- `python -m pytest tests -q` → **111 passed, 5 skipped** (带 `ZP_XRAY_BIN` 时 **116 passed**, 约 37 秒);
  含 `/api/update` 鉴权与版本比较、`apply` 的"写不进 /etc/nginx 即失败"语义、CLI 退出码、以及
  `install.sh` 重跑不覆盖已初始化配置 / `upgrade.sh` 随包发布 / 自签证书可补签 Let's Encrypt /
  `systemctl` 参数顺序的回归断言 / Reality 密钥必须是成对的 X25519 (Ed25519 必须判无效) /
  旧默认伪装目标 (证书链超 8KB) 自动迁移 / 深度体检客户端配置真的带齐各节点参数 /
  深度体检客户端在自签场景下不发已被 Xray 26 移除的 `allowInsecure` (改用 `pinnedPeerCertSha256`) /
  深度体检必须把 SOCKS5 回复读满 (只读 4 字节会让 TLS 报 `WRONG_VERSION_NUMBER`) /
  服务版本探测要跳过 Hysteria 2 的块字符 banner (否则面板挂一串花屏方块)。
  链式代理另有 21 项 (`tests/test_chain.py`): 配对码往返与 8 类坏码的中文报错 /
  落地端生成-轮换-关闭与端口冲突 / **探测不通必须拦一下 (400 + needs_force), 只有 `force=1` 才硬加** /
  环境不支持探测 (无 xray 二进制) 时不该拦住用户 / 拒绝"配对码指向本机自己"与重复添加 /
  入站与出站/路由规则落在生成配置里、订阅三种格式都带上它、默认出口会把 4 个主力入站整体改道、
  停用即从订阅与配置里消失、删除后 `share_links` 里也没有 / 链路诊断与流量标签。
  **升级脚本必须从临时副本启动** (脚本会在运行中覆盖自己, 就地执行会被 bash 读出语法错)。
- `scripts/verify.py` (Xray 26.3.27 + Hysteria 2.12.3 + mihomo 1.19.31 + sing-box 1.14.2) → **74/74 项通过**:
  setup 8 步全绿 / 三种订阅格式可被真实客户端解析 / 三档分流模板分别被 `mihomo -t` 与
  `sing-box check` 通过 / **用真实 sing-box 实跑** 5 份订阅 (通用 + 1.14+ 写法 × 智能/全局/直连) 全部启动成功,
  并留下反例: 去掉 `download_detour` 即 `FATAL` / Xray 真实监听 8443, 8445, 8444, 10085 /
  面板成功读取 Stats API / Hysteria 真实启动并监听 UDP 30001 / 8 项自检全过 / 一键修复 4 步完成 /
  GeoIP 分流规则被真实 Xray 接受 / 反向证明缺数据或缺 `XRAY_LOCATION_ASSET` 时 Xray 拒绝启动 /
  **启动期自愈闭环**: 配置带 geo 规则 + 数据文件消失 → 原样启动被 Xray 拒绝 (复现) → `geodata guard`
  重新生成 (已移除 geo 规则) → 再自检通过 / 备份-恢复往返一致且篡改被拒 /
  5 个节点握手探测全部成功 (Reality TLS 136ms, 出口 RTT 54ms)。
  **[10] 链式代理: 两台「机器」真跑一条链** —— 用两份独立 state + 三个真实 Xray 进程扮演
  「客户端 → 中转端 → 落地端」: 落地端生成专用凭据后, 中转端配置只含 `chain-<id>` 入站 + Stats API,
  出站指向落地端 `127.0.0.1:8666`; 客户端拿中转端凭据连进去, **真的从落地端出网并读回出口 IP**;
  反向用例: 把落地端的专用 UUID 换掉 (等价于配对码被轮换) 后同一条链立刻读不到 IP —— 证明确实是
  链路上的每一跳在起作用, 而不是"随便走哪条路都能出网"。
- `scripts/browser_check.cjs` → **81/81 项通过**: 初始化→仪表盘全流程、5 张节点卡、三种订阅、
  诊断 8/8、节点测速结果落到卡片、GeoIP 开关与状态、**分流模板选择器 (切换 → 订阅内容
  真的变化 → 切回)**、备份下载、**程序更新卡片 (版本行 / 检查更新 / 非生产环境隐藏一键更新)**、
  **二维码弹窗 (走 SVG 缩放不糊 / 图案完整落在卡片内 / 长链接省略号截断而不顶破卡片 /
  复制·保存·关闭三个按钮 / 节点卡片副标题是人话不是长链接 / Esc 可关闭)**、
  **初始化→域名面板交接 (跳转卡片 / 立即前往 / 留在本页回到仪表盘 / 登录页预填用户名并聚焦密码框 /
  用户名不留在地址栏 / 用刚设置的凭据可登录 / 用 IP 访问时的「切到域名面板」横幅, 且证书不是真证书时
  自动改成功告警语气)**、
  **升级交互闭环 (确认弹窗逐条列出会做什么与不动什么 / 取消不开始 / 升级中 ✓○⟳ 清单与正在执行的
  那一步 / 进度条按已完成步数推进 / 「已完成 n/N 步 · 已用 X 秒」/ 完成态版本跨度与用时并折叠步骤 /
  本页 JS 落后时给出「重新加载面板」/ 失败态标出断在第几步 + 进度条转红 + 日志尾巴)**;
  **链式代理 (落地端生成配对码 + 说明端口/凭据隔离/泄露风险 / 配对码二维码出图 /
  粘贴配对码后"探测不通先拦一下"的二次确认 / 落地成链式卡片 + 节点网格变 6 张 + 订阅里看得见 /
  设为默认出口的确认与标记 / 测速失败如实标红 / 断开后卡片与订阅节点一起消失)**;
  无 console 错误、无失败请求。
  **v2.5.0 → v2.6.0 的两次界面改版 (Bento → 控制台侧栏 + 密集表格 + 流量可视化) 都只动布局与样式,
  这 81 条断言一条没改**: 节点表格从磁贴换成五列 grid 行、延迟与流量改成条形/双轨、
  流量卡整块重写成圆环 + 速率曲线之后, 仍然 81/81 全绿 —— 改版守住的是 id / class 契约。
- `scripts/upgrade_sim.sh` → **21/21 项通过**: 在模拟的"已部署机器"上真跑 `upgrade.sh` ——
  备份 → 换代码 → 按 `state.json` 重新落地配置 (把占位配置修回真实配置) → 写 `update.json` /
  `update.log`; 并覆盖失败路径: 下载失败时非 0 退出、代码自动回滚到升级前版本、状态记为 failed、
  现有部署与 `state.json` 的密钥 / 订阅令牌一字未动。
  还专门断言**进度是边跑边写的** (50ms 采样 `update.json`: 观察到 12 种中间快照、17 次
  `running` 态, 完成步数从 1 一路涨到 8), 以及 `plan` 与 `steps` 同序对齐、收尾 `current` 为空 ——
  面板的逐步清单就靠这两条。
  另外演练现在**从 `ZP_HOME` 里那份脚本启动** (原来跑的是工作区里的副本, 于是漏掉了"脚本把自己
   覆盖掉"这条真机才炸的路径), 并分三种起法各跑一遍: 面板起法 (从私有临时副本启动 → 连旧脚本也不炸)、
  就地起法 (脚本先整份读进内存再跑)、新脚本再走一次面板起法 (断言临时副本会自己清掉)。
- API 边界: 无令牌 setup 403、重复 setup 409、非法域名 / 弱密码 / 非法用户名 400、
  无 Cookie dashboard 401、错密码 401 且第 4 次起 429、错误订阅令牌 404、未知节点 404、
  备份/探测/GeoIP 接口未登录一律 401、备份校验和不匹配 400。
- 前端: 三视图渲染、节点开关热更新、订阅三种格式复制与二维码、诊断面板、高级设置保存、测速与备份。

### 12.1 真实服务器验证 (2026-09-28, Ubuntu 24.04 / 1 vCPU / 1GB, Xray 26.3.27 + Hysteria 2.12.3)

这一轮把"只能在 Linux 上验证"的部分全部跑通, 也把四个**只在真机上才会暴露**的根因抓了出来
(本地 `pytest` / `verify.py` 全绿却救不了它们 —— 见下面第 3、4、6、11 条):

1. **部署链路**: `install.sh` → 面板初始化 → certbot 签发 `hkk.i3.pub` 的 Let's Encrypt 证书
   (有效期至 2026-12-27, `certbot.timer` enabled, 证书出现后 `/api/renew` 会自动重新生成
   nginx/xray 配置并热重载) → nginx 监听 80/443/8899、xray 监听 8443/8445/8444 +
   127.0.0.1:6000、hysteria2 监听 30001/31001/32001 (UDP 端口跳跃)。
2. **一键升级真机实测**: `upgrade.sh` 连升 v2.3.2 → … → v2.3.7, 每次 6 步全绿
   (备份 → 换代码 → 按 `state.json` 重新落地三份配置 → 重载服务 → 复查端口监听),
   `data/update.json` 记 success, 旧代码 + `state.json` 备份保留最近 5 份;
   面板「程序更新 → 一键更新」走 systemd 瞬时单元, 面板自身重启不打断升级。
   v2.3.11 又连升一次 (v2.3.10 → v2.3.11): 8 步全绿 (备份 → 下载 → 装代码 → 同步依赖 →
   重载 systemd 单元 → 按 `state.json` 重新落地 xray/nginx/hysteria 配置 → 重启面板 →
   面板就绪), `update.json` 里 `plan` / `current` / `steps` 三个字段齐全;
   升级后 4 个 TCP 节点用真实 Xray 客户端实测 `http=200`、出口 IP = 服务器 IP,
   hysteria2 同样出口一致 (这一轮踩到的"脚本覆盖自己"见第 11 条)。
3. **根因一: Reality 密钥用错曲线**。`crypto.new_reality_keys()` 从第一版起用 Ed25519 生成,
   而 REALITY 只认 X25519 → 服务端私钥与订阅下发的 `pbk` 对不上, 每次握手都被判为
   "收到真证书 (疑似 MITM)", 客户端回落到伪装站点。证据链: `xray x25519 -i <服务器私钥>`
   反推的公钥与 `state.json` 里的 `public_key` 不一致 (前者 `1DJGvr…`, 后者 `J0k9Dm…`)。
   修复: X25519 + `reality_key_valid()` 逐对校验, 落地时自动迁移。
4. **根因二: 伪装目标的证书链超过 REALITY 的 8KB 缓冲**。`xtls/reality` 的服务端握手把目标
   站点的握手报文读进固定 8192 字节缓冲 (`tls.go: size = 8192`, `if handshakeLen > size { break f }`),
   而旧默认目标 `www.microsoft.com` 的 Certificate 报文是 **8273** 字节 → 服务端直接放弃握手,
   客户端只看到 `Connection reset by peer`。真机 `show: true` 实拍: 读到 `Certificate: 8273`
   后 `isHandshakeComplete: false`; 服务端日志 `REALITY: processed invalid connection from …:
   handshake did not complete successfully`。筛选实测 (本机 + 服务器各跑一遍):
   `www.microsoft.com` 8273 ✗ / `www.bing.com` ServerHello 9876 ✗ / `www.cloudflare.com` ✓ /
   `dl.google.com` ✓ / `www.python.org` 4352 ✓ / `www.samsung.com` 4700 ✓ / `cdn.jsdelivr.net` ✓。
   修复: 默认目标换成 `www.cloudflare.com` + 落地时自动迁移旧默认值。
5. **端到端 (真实客户端, 不是面板自测)**: 用本机 Xray 26.3.27 客户端拉面板订阅, 4 个 TCP 节点
   全部 `http 200`, 出口 IP = 服务器 IP (8443 Reality / 8445 XHTTP Reality / 443 WS+TLS /
   8444 Trojan TLS); hysteria2 用官方 hysteria 2.12.3 客户端 (订阅里的端口跳跃写法) 同样出口 IP 一致。
6. **根因三: 深度体检只读了 SOCKS5 回复的前 4 字节**。Xray 的 SOCKS 入站成功回复是 10 字节
   (`05 00 00 01` + BND.ADDR `0.0.0.0` + BND.PORT `0`), 而探测代码 `recv(4)` 只取头部,
   剩下 6 个 `00` 留在接收缓冲区 → 紧接着 TLS 客户端把它们当成记录头, 报
   `SSLError: WRONG_VERSION_NUMBER`。这个 bug 只在**生产环境**生效 (`?deep=1` 仅在 Linux
   生产路径启用, 本地 `pytest` / `verify.py` 走的是浅探测), 真机上的表现就是
   "面板 4 个节点全部握手失败" —— 于是没人再敢信面板的结论。
   修复: `_socks5_open()` 按 ATYP 把回复**读满** (IPv4 / IPv6 / 域名三种都覆盖) 再进 TLS;
   回归测试用一个只回 10 字节的假 SOCKS5 服务端钉死"缓冲区必须是空的"。
7. **面板自测能力补强**: 旧 `/api/probe` 只做裸 TLS 握手 —— Reality 认证失败时服务端会**回落到
   真实伪装站点**, 裸握手照样成功, 这正是"面板 1/5 通、服务全绿"的来源。现在 `?deep=1` 会用临时
   Xray 客户端经 SOCKS5 隧道对伪装目标做一次真实 TLS 往返 (生产环境面板默认走它), 并把
   `allowInsecure` 换成 Xray 26 要求的 `pinnedPeerCertSha256` (Xray 25 起 `allowInsecure` 已移除,
   26.3 上直接拒绝加载配置 —— 这一点也是真机联调时才踩到的)。
8. **杂项 (真机才看得到)**: 面板「系统」卡片读的是各服务的 `xxx version`, 而 Hysteria 2 会在
   第一行先打一段块字符 banner (`░█░█░█░█░█▀▀░▀█▀…`) → 面板上显示成"Hysteria 2 运行中 · ░█░█…"
   一串花屏方块。修复: 剥掉 ANSI / 块字符后优先认 `Version: v2.12.3` 这类带标签的行, banner-only
   的输出宁可显示为空也不当版本号。
9. **二维码弹窗 (界面)**: 旧版把整条 `vless://…` 当副标题铺在卡片里 —— 长链接不换行, 直接把
   文字顶出卡片右侧被裁掉; 位图二维码被 CSS 缩到 260px 后又糊成一团, 手机上难扫。
  修复: 副标题改成 `XHTTP · hkk.i3.pub:8445` 这种人话摘要, 二维码改走 `?img=svg`
  (矢量 + `shape-rendering="crispEdges"`, 缩放到任何尺寸都是硬边方块), 完整链接单独一行
  省略号截断 + 一键复制, 并补上"保存图片"(PNG) 与 Esc 关闭。
10. **一键升级的交互 (体验)**: 真机上点完「一键更新」后卡片只剩一个跳动的徽标 —— 不知道有没有
    真的开始、做到哪一步、还要多久, 失败时也只多一句红字。根因不在前端: `upgrade.sh` 的
    `write_status()` 只在脚本**结束那一刻**调用一次, `update.json` 里从头到尾只有"最后写的那个
    状态", 面板即使想显示进度也无从读起 (前端一度用 `setTimeout` 假装进度条, 脚本卡住就成了骗人)。
    修复: 脚本先算 `plan`、每进入一步写 `current`、每完成一步就落盘, 前端把这几个字段渲染成
    ✓/⟳/○ 清单 + 进度条 + 已用时间; 确认弹窗、完成/失败结论卡与"重新加载面板"补成完整闭环
    (详见 8.2)。回归上同时钉住两件事: `browser_check.cjs` 断言各状态的渲染, `upgrade_sim.sh`
    用 50ms 采样证明进度确实是边跑边写的。
11. **根因四: 升级脚本在运行中把自己覆盖掉**。`upgrade.sh` 的「安装新代码」那步会把新版本的
    `upgrade.sh` 拷到 `$ZP_HOME/upgrade.sh` —— 也就是**正在执行的那个文件**。bash 是**按文件偏移
    增量读取**脚本的: 覆盖之后它继续从"新文件"的同一偏移往下读, 读到的是另一段代码, 于是
    `upgrade.sh: line 233: syntax error near unexpected token 'then'` 直接把整次升级打断
    (v2.3.10 → v2.3.11 真机就是这样, 靠自动回滚保住了部署)。这个坑在本机永远复现不了 ——
    演练脚本跑的是工作区里的副本, 线上跑的是 `$ZP_HOME` 里那份。修复分两层: 面板改成先把脚本
    复制到私有临时目录 (`stage_script()`) 再执行, 于是**连没打补丁的旧脚本也能被面板安全升级**;
    新脚本自己再兜一层 (开头把整份脚本读进内存, 命令行就地执行时也炸不了)。回归: `pytest` 断言
    面板跑的是副本, `upgrade_sim.sh` 直接从 `$ZP_HOME` 起脚本、三种起法各跑一遍并检查日志里
    没有 `syntax error` / `unexpected token` (注: `bash -s < 原文件` 不算修好, 那个 fd 指向的
    仍是会被覆盖的同一个 inode)。

macOS 上仍无法覆盖的只有: ufw/云安全组规则、systemd 单元里的 `XRAY_LOCATION_ASSET` 生效细节
(单元文件已写入该变量, 真机 `xray -test` 与启动均通过) 与不同客户端 App 的导入行为。

---

## 13. 运维

```bash
# 查看服务日志
journalctl -u xray -n 50 --no-pager         # 也可用面板 GET /api/logs/xray

# 一键升级 (推荐; 面板「程序更新 → 一键更新」等价)
#   只换程序代码, state.json / 密钥 / 订阅令牌 / 节点开关原样保留, 订阅地址不变
#   升级前自动备份代码与 state.json, 任一步失败自动回滚
curl -fsSL https://raw.githubusercontent.com/ericlinclover-blip/zeroproxy/main/upgrade.sh | bash

# 指定分支 / tag, 或改用 fork / 镜像仓库 (默认 main)
ZP_REPO=your-name/zeroproxy ZP_REF=main bash -c "$(curl -fsSL https://raw.githubusercontent.com/ericlinclover-blip/zeroproxy/main/upgrade.sh)"

# 顺带把 Xray / Hysteria 2 二进制升到最新版 (默认不动)
ZP_UPDATE_CORE=1 bash /opt/zeroproxy/upgrade.sh

# 只看版本, 不做任何改动
ZP_CHECK_ONLY=1 bash /opt/zeroproxy/upgrade.sh

# 已经 clone 了仓库: 直接跑本地脚本
sudo bash upgrade.sh

# 升级后的进度与日志 (面板「程序更新」卡片读同一份文件)
cat /opt/zeroproxy/data/update.json
tail -n 40 /opt/zeroproxy/data/update.log

# 重装 / 修复整机环境 (install.sh 可重复执行: 已初始化时不会再动 data/ 里的配置,
# 而是按 state.json 重新落地一次配置; 首次部署才写占位配置)
curl -fsSL https://raw.githubusercontent.com/ericlinclover-blip/zeroproxy/main/install.sh | bash

# 指定 Xray 版本 (回退), 或指定面板分支 / tag
XRAY_VERSION=24.11.30 ZP_REF=main bash -c "$(curl -fsSL https://raw.githubusercontent.com/ericlinclover-blip/zeroproxy/main/install.sh)"

# 万一升级后有问题: 手动回滚到上一份代码与 state.json
# (备份目录保留最近 5 份 —— 成功与失败各留一份回滚点; 步骤失败时脚本还会自动回滚一次)
BK="$(ls -1dt /opt/zeroproxy/data/backups/code-* 2>/dev/null | head -1)"
rm -rf /opt/zeroproxy/zeroproxy /opt/zeroproxy/static
cp -r "$BK/zeroproxy" /opt/zeroproxy/zeroproxy && cp -r "$BK/static" /opt/zeroproxy/static
cp -f "$BK/state.json" /opt/zeroproxy/data/state.json
systemctl restart xray hysteria2 nginx zeroproxy

# 备份 / 恢复 (两种方式任选)
#   1) 面板「系统 → 下载备份」得到 JSON (带校验和, 换机可一键还原)
#   2) 命令行: 备份整个数据目录即可 (含全部密钥与订阅令牌)
tar czf zp-backup.tgz -C /opt/zeroproxy data

# GeoIP 数据手动刷新 (面板也会每 7 天自动做)
#   面板「高级设置 → 下载/更新 GeoIP 数据」, 或直接调用:
curl -X POST --cookie 'zp_session=...' https://<域名>:8899/api/geodata/update
ls -la /opt/zeroproxy/geo/            # geoip.dat / geosite.dat

# 卸载 (保留数据: ZP_KEEP_DATA=1; 保留证书: ZP_KEEP_CERT=1)
bash /opt/zeroproxy/uninstall.sh            # 安装时已随面板一起放到 $ZP_HOME
curl -fsSL https://raw.githubusercontent.com/ericlinclover-blip/zeroproxy/main/uninstall.sh | bash
```

---

## 14. FAQ

- **打不开面板 / 提示不安全?** 引导阶段用自签证书, 点「继续访问」即可; 完成 setup 且 certbot
  签发成功后, 面板会自动跳到 `https://<域名>:8899` (登录页已预填用户名); 也可以手动用它访问,
  那时就是可信证书。用 IP 访问时仪表盘顶部也会给一条「切到域名面板」的提示。
- **提示「引导令牌无效」?** 必须用安装完成时终端打印的、带 `?token=` 的链接打开面板。令牌文件在
  `/opt/zeroproxy/data/bootstrap_token`, 初始化成功后自动删除。
- **certbot 申请失败?** 面板自动回退自签证书, WS / Trojan 节点带 `allowInsecure=1` 仍可用;
  确认域名解析与 80 端口后, 在「系统 → TLS 证书」点「申请证书」再试一次 —— 自签状态下面板
  也会真的去申请 (成功后会重新生成引用正式证书的 nginx / xray 配置并热重载, 不用重装)。
- **Hysteria 2 连不上?** 检查 UDP 30001-32001 是否放行; 部分网络封 UDP, 改用前四个 TCP 节点。
- **XHTTP 节点连不上?** 需要客户端支持 (mihomo 1.19+ / sing-box 1.11+ / 较新 v2rayN 系列);
  老客户端可用其他节点, 或在面板里关掉该节点。
- **换了域名?** 删除 `/opt/zeroproxy/data/state.json` 后重新运行 `install.sh`, 再走一遍 setup。
- **想改端口 / 伪装站点?** 仪表盘「高级设置」直接改, 保存后自动重新生成配置并热重载。
- **「广告域名拦截」打开了但没效果?** 先确认 GeoIP 数据已下载 (高级设置里显示「数据未下载」时,
  分流规则不会下发); 点「下载 / 更新 GeoIP 数据」即可。
- **想换分流策略 (国内直连 / 全局 / 直连)?** 高级设置「分流模板」一键切换, 订阅立刻生效且不重启服务;
  只想给某一个客户端用别的策略, 就在它的订阅地址后加 `?rules=global` (或 `smart` / `direct`)。
- **sing-box 报 `unknown field "http_clients"`?** 说明用了 `?format=singbox-next`, 而客户端低于 1.14;
  换回默认 `?format=singbox` 即可 (它同时兼容 1.13 与 1.14)。
- **sing-box 启动报 `lookup ... : empty result` / 卡在下载?** 那是 rule-set 下载走了节点而节点不通;
  本项目生成的订阅已固定走直连下载, 若是自己改过配置, 请保留 `download_detour: "direct"`。
- **节点测速显示「握手失败」?** 说明该入站真的不可用 (Reality 密钥/SNI/dest 不匹配, 或内核没在跑);
  点「一键诊断」看具体哪一项不过, 再点「一键修复」。
- **换服务器怎么迁移?** 新机跑 `install.sh` → 打开面板 → 「系统 → 从备份恢复」→ 选旧机的备份
  JSON, 密钥、订阅令牌、节点开关全部原样回来。
- **面板加了新功能, 怎么升级?** 面板「程序更新 → 一键更新」, 或服务器上
  `curl -fsSL .../upgrade.sh | bash`。升级只换程序代码, 配置与订阅地址不变, 客户端不用重新导入;
  升级前自动备份代码与 `state.json`, 失败自动回滚, 进度与日志写进 `data/update.json` / `data/update.log`。
- **为什么升级完节点还是不通?** 升级只负责「把新代码装上去, 再按 `state.json` 重新落地配置」。
  如果 `state.json` 本身是错的 (比如域名没解析), 升级不会替你修好 —— 点「一键诊断」看是哪一项,
  或直接看升级卡片里的失败步骤; 必要时重新走一次「一键生成」。
- **面板卡片一直显示「有步骤失败」?** 那是配置落地真的没成功 (写不进 `/etc/nginx`、`xray -test`
  不过、端口没起来都会这样报)。展开卡片或看 `data/update.log` 的具体原因, 修掉后点「重新应用配置」。

---

## 15. 已知限制与后续方向

- 单用户设计: 没有多用户 / 配额 / 到期时间 (那是 Marzban、3x-ui 的战场); 若要多人共享,
  建议保留本面板做「节点与订阅的自动化底座」, 由上游面板做用户管理。
- 流量统计依赖 Xray Stats API; Hysteria 2 的流量暂未计入 (上游无同等查询接口)。
- Hysteria 2 端口跳跃仅 Linux 生效 (上游限制), 非 Linux 环境自动退化为单端口。
- 订阅文件由面板实时生成, 未做 CDN 缓存与 ETag 协商 (单用户场景无影响)。
- 节点测速给的是「入站握手是否成功 + 出口 RTT」; 客户端到服务器的 RTT 服务端无法自测。
- Hysteria 2 无法用 TCP 探测, 只能检测 UDP 端口是否被监听 (Windows 上可能显示「无法主动探测」)。
- GeoIP 数据自动更新依赖 jsdelivr / GitHub 至少一个可达; 全部不可达时保留旧数据并记录审计。
- 分流模板是三档预设 (智能/全局/直连), 暂不支持用户自定义规则集; `?rules=` 只能选这三档。
- 面向 sing-box ≥1.14 的 `?format=singbox-next` 是**手选格式**: 面板无法识别客户端版本,
  默认格式 (`download_detour`) 才能同时兼容 1.13 与 1.14。等 1.16 发布 (该字段移除) 后默认值会切到新版写法。
- 尚未内置: 用户自定义分流规则、多域名与多证书、多用户与配额。(核心二进制升级已可选:
  面板「程序更新」只换面板代码, 需要连 Xray / Hysteria 2 一起升级时用 `ZP_UPDATE_CORE=1`)。
- 面板内「一键更新」依赖 `systemd-run` 把升级脚本放到独立单元里跑; 极老系统没有它时会退化为
  直接后台执行 (面板重启可能打断升级), 这种情况下建议改用命令行 `upgrade.sh`。
- 升级脚本按 `ZP_HOME`(默认 `/opt/zeroproxy`) 布局工作, 只覆盖 `zeroproxy/` `static/`
  `requirements.txt` `systemd/*.service` 与 `upgrade.sh`, 不碰 `data/`、`certs/`、`geo/`。

---

## 16. 链式代理 (两台机器接成一条链)

**要解决的问题**: 你有一台香港机器和一台美国机器 —— 香港离你近 (延迟低)、美国出口才是你要的 IP。
想让客户端连香港、出口走美国。

Clash 的 `relay` / sing-box 的 `detour` 都能做这件事, 但都要**在客户端手写配置** (手机上尤其难受),
而且每加一台机器就要改一次客户端。本面板把链式做在**服务端**: 对你手机 / 电脑上的客户端来说,
它只是订阅里多出来的一个普通节点。

### 16.1 三步接完

1. **落地端** (美国机器): 面板「链式代理 → 落地端」→ 填端口 (默认 8447) 与名称 → 「生成配对码」。
   本机随即多一个**专用入站** (`chain-exit`), 与订阅里那份凭据完全分开。
2. **入口端** (香港机器): 面板「链式代理 → 入口端」→ 粘贴配对码 (可扫码) → 需要的话勾「设为默认出口」
   → 「连接并测试」。面板会起一个**临时 Xray 客户端真的穿过落地端出一次网**, 读回落地出口 IP:
   - 通 → 一键落地: 新增入站 (`chain-<短id>`, 客户端连它) + 出站 (`chain-out-<短id>`, 连落地端) +
     一条路由规则, **订阅里立刻多出这个节点**;
   - 不通 → 弹确认框说明原因 (安全组没放行? 配对码轮换过?) —— 你可以选择仍然添加, 稍后修好再测速。
3. 客户端重新拉一次订阅 (或等它自动刷新), 直接选这个节点即可。**不用改任何客户端配置**。

### 16.2 落地凭据是专用的

配对码里装的是落地端**专门生成**的一份凭据: 独立 UUID + 独立端口 (默认 8447, 走 VLESS + TCP +
Reality + Vision, 复用本机 Reality 密钥与伪装目标, 免证书)。

| 操作 | 效果 |
|---|---|
| 「重新生成」 | 旧配对码**立即作废**, 已经连上的入口端会断链 (拿新码重连即可); 你自己的订阅、节点、客户端**完全不受影响** |
| 「关闭落地端」 | 入站下线 + 配对码作废; 随时可再生成 |
| 「断开」(入口端) | 删掉本机的入站 / 出站 / 路由规则, 订阅里该节点消失; 落地端那边毫发无损 |

> 配对码等同凭据: 谁拿到都能把你的机器当出口用。别公开发布; 万一泄露点「重新生成」即可
> (配对码末尾的 6 位校验和只用来挡"复制粘贴被截断", 不是签名)。

### 16.3 「设为默认出口」: 真正的链式加速

某条链可以设为**默认出口**: 本机 4 个主力节点 (Reality / XHTTP / WS / Trojan) 的流量整体改道到那条链 ——
客户端**不用换节点**, 但出口 IP 变成落地服务器。同时只允许一条默认出口; 停用某条链会自动摘掉它的默认标记。
GeoIP 分流 (广告拦截 / 私有地址防护) 的优先级高于默认出口, 该拦的照拦。

### 16.4 端口与安全组 (最容易卡住的地方)

链式要用到两个**主力节点之外**的新端口, `install.sh` 里那几条放行规则覆盖不到:

| 端口 | 在哪台机器 | 干什么 |
|---|---|---|
| 配对码里的端口 (默认 `8447/tcp`) | 落地端 | 给别的中转服务器接入 |
| 自动分配的入站端口 (从 `8446/tcp` 往后找) | 入口端 | 客户端连它 (也可以在面板里手动指定) |

面板在启用时会尽力 `ufw allow` 并把这个动作作为一步写进结果清单; **云厂商的安全组要你自己去控制台放行**
(面板管不到)。对方连不上, 九成是这里没放行。

### 16.5 实现要点 (排障时有用)

- 配对码是 `ZPC1~<base64url(JSON)>~<sha256 前 6 位>` 一行, 可复制可扫码; 解析阶段就把
  "地址 / 端口 / UUID / SNI / shortId / Reality 公钥长度 / flow" 逐项校验, 坏码当场给出中文原因,
  不会等落地后才握手失败 (`backend/zeroproxy/chain.py: parse_code`)。
- 探测用的是**真实数据面**: 起一个最小 Xray 客户端 + 本地 SOCKS5, 经隧道发一次 HTTP GET 读回出口 IP
  (回显服务按"国内也能直连"的顺序试: `ip.3322.net` → `ifconfig.me/ip` → `api.ipify.org`)。
  因此"探测通过"= 整条链真的能出网, 而不是"端口开着"。
- 环境不允许探测时 (比如没有 xray 二进制) 面板会明确说明并**不拦**用户 —— 把差异留给「测速」按钮去补。
- 进 `state.json` 的 `chain` 段 (schema v4), 随备份 / 恢复一起走; 流量统计按节点展开到链式入站。

---

## 17. 界面改版 (v2.5.0 → v2.6.0)

### 17.1 怎么挑的 (v2.5.0)

改版前先在**同一路由上做了三套结构完全不同的方案** (`backend/static/proto-dashboard.html`,
一次性原型, 数据写死, `?variant=A|B|C` + 底部悬浮条切换, 键盘 `←` `→` 也能翻), 而不是
直接改颜色 —— 三套之间的差别是**信息层级**, 不是配色:

| 方案 | 结构 | 适合什么 | 结论 |
|---|---|---|---|
| **A · Ops Console** | 固定左侧导航 + 密集表格 + 右侧信息栏 | 天天盯指标、节点几十个 | 单机面板只有 5–6 个节点, 侧栏 7 个锚点显得空 |
| **B · Bento** | 无侧栏, 12 列非对称磁贴 | 模块少而"重"、每个模块内容都不一样 | **采用** —— 正好是这台面板的样子 |
| **C · Topology** | 链路拓扑当主角, 深色控制台风 | 链式 / 多跳是核心卖点 | 拓扑本身很好, 但整页 1400px 太高, 左右栏容易失衡 |

最终落地的是**合成方案**: B 的 Bento 骨架 + C 的链路拓扑 (放进链式磁贴) + A 的顶部指标条。
三套原型留在分支 `proto/dashboard-ui`, 不进 main —— 变体代码从写下来那天就在腐坏,
留在主干只会让下一个读代码的人困惑。

### 17.2 v2.5.0 落地后的结构

```
吸顶品牌栏 (logo + 深浅色)
仪表盘头部 (域名 + 状态药丸 + 5 个动作按钮)
告警横幅 (失败步骤 / IP 访问提示, 有才出现)
指标条    健康节点 · 落地出口 IP · 平均握手延迟 · 运行时长
────────────────────────────────────────────────
节点      全宽 · 密集行 (5–6 个节点一屏看完)
订阅 s5 | 流量 s7
高级设置  全宽 (SNI / 伪装站点 / 端口 / 分流模板 / GeoIP)
链式代理  全宽 (三段式拓扑 + 落地端卡 + 入口端卡 + 已连接列表)
诊断 s6 | 系统 s6
程序更新  全宽
```

窄屏 (≤940px) 所有磁贴自动落成单列; 拓扑 (≤840px) 也会从横排变竖排。

### 17.3 改版时守住的三条

1. **不改 id / class 契约**: `#node-grid .node-card`、`.switch`、`.ping`、`#diag-list .check`、
   `#diag-list .muted`、`#update-body .ustep`、`#update-body .bar + .muted`、`#chain-*` …
   这些都是 `scripts/browser_check.cjs` 的断言锚点。改版只动布局与样式, 81 项断言一条没改。
2. **不新增网络请求**: 指标条的四个数字全部由已拉到的 `/api/dashboard` + `/api/probe` 算出来。
3. **开发环境不误报**: 指标条右上角的状态药丸把 `dry-run` (本地开发) 显示成黄色提示,
   只有 `failed` / `inactive` 才算"服务异常" —— 免得开发机上满屏红色。

### 17.4 复现

```bash
ZP_PORT=8899 ./dev.sh                       # 起面板
# 三套原型 (仅分支 proto/dashboard-ui 上有这个文件):
open http://127.0.0.1:8899/static/proto-dashboard.html?variant=B
```

### 17.5 v2.6.0: 为什么又从 Bento 回到 A

v2.5.0 的 Bento 磁贴解决了"信息层级", 但用下来暴露了三个具体问题:

1. **一眼看不到"快慢"**: 延迟只是一个徽标文字 (`136ms`), 5 个节点之间谁比谁快要靠读数字,
   没有可比较的形状。
2. **流量没有美感**: 整块流量区就是一个数字加一条 `i` 宽度条, 上下行混在一起, 也看不到"现在多快";
   面板自己又没有历史数据 (Xray Stats 只给累计值), 所以速率一直是空白。
3. **页面太长**: 磁贴两列铺开要滚很久, 想看"系统"要先越过链式代理和诊断;
   没有导航锚点, 全靠手滚。

于是这一版做了**三件事**, 而不是换一套配色:

1. **回到 A 方案的骨架**: 左侧锚点导航(带计数角标与滚动高亮) + 主列堆叠; 节点区从磁贴改成
   **五列密集表格**, 一屏吃完 5–6 个节点的名称 / 地址状态 / 握手 / 流量 / 操作。
   当初不选 A 是因为"单机只有 5–6 个节点, 侧栏 7 个锚点显得空" —— 现在侧栏承担了
   角标与状态汇总 (启用节点数 / 落地端数 / 诊断结果 / 有新版本 / 管理员 / 主机 / 在线 / 版本),
   本身成了信息位, 不再是空壳。
2. **把"快慢"画出来**: 每个节点一条延迟条, 宽度按「最快 = 满格, 最慢 = 40%」映射,
   颜色阈值 120ms 绿 / 250ms 橙 / 以上红; 顶部指标条的"平均握手延迟"下面补一条各节点
   延迟迷你折线 (峰值肉眼可读)。
3. **重做流量可视化**: 双弧圆环 (上行蓝 / 下行青) + 逐节点双色条 + **实时速率曲线**。
   速率曲线是这版唯一"自己造数据"的地方, 而且刻意做成**只在本页内存里采样**
   (每次 `/api/dashboard` 刷新记一个 `{t, total}`, 留 24 点), 刷新页面就重新开始 ——
   面板不落盘、不假装有历史, 折线旁边直接写「N 点 · 峰值合计 X/s」, 有几笔数据就说几笔。
   计数器被重置 (Xray 重启) 时会把采样窗口清空重来, 不画出一条假的负速率。
   (v2.6.1 / v2.6.2 补: 只有一个采样点时画成一条平线表示"当前速率", 采样点不足时留空 ——
   不画假的趋势线, 游标与端点也要真的隐藏 (CSS 的 opacity 会盖掉 SVG 的 opacity 属性, 得用 inline style);
   版本行不再写"最新 vX" —— `raw.githubusercontent` 有约 5 分钟 CDN 缓存, 刚发完版会拿到旧号,
   「当前 v2.6.1 · 最新 v2.6.0」这种自相矛盾的写法比不写更糟, 远端版本只由徽标表达。)

另外给"升级中"的进度条加了斜纹跑马 (`bar.live`), 只表示"在动", 不谎报百分比;
初始化页那条长请求 (证书签发 30–60s) 也补了同样的不定量进度条。

**动效清单** (全部可被 `prefers-reduced-motion: reduce` 一次性关掉):
状态点呼吸 · 开关回弹 (`cubic-bezier(0.34,1.56,0.64,1)`) · 按钮/卡片 hover 上浮 ·
导航左侧竖条展开 · 链路拓扑虚线流动 · 流量条流光扫过 · 升级进度条斜纹 ·
KPI 顶部渐变线 · 区块入场 stagger (40ms 递增) · 弹窗 `zp-pop`。

### 17.6 v2.6.0 的结构

```
吸顶品牌栏 (logo + 深浅色)
┌ 侧栏 (sticky) ────────┬ 主列 ──────────────────────────────┐
│ 节点        6/6        │ 仪表盘头部 (域名 + 状态药丸 + 5 按钮) │
│ 订阅                   │ 告警横幅 (失败步骤 / IP 访问提示)      │
│ 流量                   │ 指标条 ×4 (节点 / 出口 IP / 延迟+折线 / 运行时长) │
│ 链式代理    1          │ 节点   全宽 · 五列密集表格            │
│ 高级 / 分流            │ 订阅   三格式同源                    │
│ 诊断        ✓          │ 流量   圆环 + 实时速率曲线 + 逐节点双色条 │
│ 系统                   │ 高级设置 (SNI / 伪装 / 端口 / 分流 / GeoIP) │
│ 程序更新    新          │ 链式代理 (拓扑 + 落地端 + 入口端 + 列表) │
│ ─────────────          │ 诊断   服务 / 配置 / 证书 / 端口 / 落地端 │
│ 管理员 / 主机           │ 系统   证书 / 服务 / 备份恢复           │
│ 在线 / 版本             │ 程序更新 版本对比 → 确认 → 进度 → 结果   │
└───────────────────────┴────────────────────────────────────┘
```

≤1180px: 侧栏落成顶部横滚导航 (锚点变成胶囊), 主列吃满宽度;
≤620px: 流量卡的圆环与数字改成上下堆叠。
