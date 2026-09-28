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

面板右上角有「程序更新 → 一键更新」; 命令行等价的一条命令:

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
| **可回归验证** | `pytest` 85 项 (81 passed + 4 skipped; 带 `ZP_XRAY_BIN` 时 85 全通过) + `scripts/verify.py` (74 项) + `scripts/browser_check.cjs` (33 项) + `scripts/upgrade_sim.sh` (13 项), 全部用真实二进制 / 真实浏览器 / 真实升级脚本 |

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
│   └── zeroproxy/
│       ├── main.py                # FastAPI 入口 + 安全响应头中间件
│       ├── config.py              # 状态模型 (state.json v3) / 文件锁 / 引导令牌 / 审计日志 / 备份还原
│       ├── crypto.py              # VLESS UUID 派生 / Reality X25519 密钥对 / PBKDF2
│       ├── xray_config.py         # Xray 配置生成 (Reality / XHTTP / WS / Trojan + Stats API)
│       ├── geodata.py             # GeoIP/GeoSite 下载与校验 + 分流规则 (硬前置: 数据缺失不下发) + 启动前自愈 CLI
│       ├── nginx_config.py        # Nginx 生成 (ACME + 443 WS 反代 + 伪装主页 + 8899 面板 TLS)
│       ├── hysteria_config.py     # Hysteria 2 配置生成 (端口跳跃 + masquerade 伪装)
│       ├── apply.py               # 配置落地闭环 (生成 → xray -test / nginx -t → 重载 → 复查端口监听), 面板与 upgrade.sh 共用
│       ├── update.py              # 面板自更新 (远端版本检查 + 触发 upgrade.sh + 回读升级进度)
│       ├── services.py            # systemctl / certbot / 自签证书 / 流量统计 / 节点握手探测 / 诊断
│       ├── share_links.py         # 单节点链接 + Base64 / Clash / sing-box 订阅 + 三档分流模板
│       └── routes.py              # API: setup / login / dashboard / settings / diagnose / probe / backup / sub / qr / update
├── docs/
│   └── RESEARCH.md                # 竞品与技术调研 (含上游源码一手证据)
├── scripts/
│   ├── verify.py                  # 端到端验证: 真实二进制跑通配置生成 / 订阅解析 / 探测 / 备份 / GeoIP
│   ├── browser_check.cjs          # 真实浏览器 (Playwright) UI 验证与截图
│   └── upgrade_sim.sh             # 一键升级演练: 真跑 upgrade.sh (桩掉 root/systemd), 覆盖成功与回滚两条路径
├── static/
│   └── index.html                 # Apple 风格单文件 UI (零构建, 深浅色, 无 CDN)
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
state.json (唯一事实来源, schema v3, 旧版本自动升级)
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
- state.json 结构升级: 新增字段在读取时由 `_merge` 自动补齐 (v1 → v2 → v3 已覆盖测试)。
- GeoIP 数据每 7 天自动更新: 面板后台线程每 6 小时检查一次, 只在数据真的变化时重启 Xray;
  下载先落到临时目录并通过真实 `xray -test` 校验后才原子替换, 所以不会出现"半个数据集"。

---

## 8. 前端 UI

单文件 `static/index.html` (原生 JS + CSS, 零构建零 CDN, 离线可用):

- **Apple 风格**: SF 字体栈、18px 圆角卡片、柔和阴影、深浅色自动 + 手动切换。
- **三步交互**: 初始化 (三输入框 + 部署进度逐步打钩) → 登录 → 仪表盘, 每 20s 静默轮询。
- **仪表盘卡片**: 订阅三种格式 (各自复制 / 二维码)、5 张节点卡 (协议徽标 / 传输 / 加密 / 状态灯 /
  开关 / 单节点流量 / **握手延迟徽标** / 复制链接 / 二维码)、流量总览与节点占比、
  高级设置 (Reality SNI / Hysteria 伪装站点 / 各节点端口 / **GeoIP 分流开关与数据更新**)、
  诊断与一键修复、证书与系统状态 (**含证书申请 / 续期, 备份下载与恢复**)、
  **程序更新 (版本 / 一键更新 / 进度日志)**、操作审计。
- **失败不装成功**: 「一键生成」「保存并应用」「一键修复」的每一步失败都会顶到仪表盘顶部标红
  (含具体原因), 而不是只弹一句「完成」。

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
| GET | `/api/update` | 会话 | 当前版本 / 远端最新版本 (600s 缓存, `?force=1` 强刷) / 上次升级进度与日志尾部 |
| POST | `/api/update` | 会话 | 一键更新: 后台拉起 `upgrade.sh` (systemd 瞬时单元, 面板重启不打断); 已有任务或本地开发环境返回 409 |
| GET | `/api/diagnose` / POST `/api/repair` | 会话 | 自检 / 一键自愈 |
| GET | `/api/traffic` | 会话 | 流量统计 (Stats API) |
| GET | `/api/logs/{service}` | 会话 | 服务日志尾部 (journalctl) |
| GET | `/sub/{token}?format=&rules=` | 订阅令牌 | Base64 / Clash / sing-box / sing-box-next 订阅内容, `rules=smart\|global\|direct` 单客户端覆盖分流模板 |
| GET | `/api/nodes/{id}/qr` / `/api/subscription/qr` | 会话 | 节点 / 订阅二维码 PNG |

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

- `python -m pytest tests -q` → **81 passed, 4 skipped** (带 `ZP_XRAY_BIN` 时 **85 passed**, 约 20 秒);
  含 `/api/update` 鉴权与版本比较、`apply` 的"写不进 /etc/nginx 即失败"语义、CLI 退出码、以及
  `install.sh` 重跑不覆盖已初始化配置 / `upgrade.sh` 随包发布 / 自签证书可补签 Let's Encrypt /
  `systemctl` 参数顺序的回归断言 / Reality 密钥必须是成对的 X25519 (Ed25519 必须判无效) /
  旧默认伪装目标 (证书链超 8KB) 自动迁移 / 深度体检客户端配置真的带齐各节点参数 /
  深度体检客户端在自签场景下不发已被 Xray 26 移除的 `allowInsecure` (改用 `pinnedPeerCertSha256`)。
- `scripts/verify.py` (Xray 26.3.27 + Hysteria 2.12.3 + mihomo 1.19.31 + sing-box 1.14.2) → **74/74 项通过**:
  setup 8 步全绿 / 三种订阅格式可被真实客户端解析 / 三档分流模板分别被 `mihomo -t` 与
  `sing-box check` 通过 / **用真实 sing-box 实跑** 5 份订阅 (通用 + 1.14+ 写法 × 智能/全局/直连) 全部启动成功,
  并留下反例: 去掉 `download_detour` 即 `FATAL` / Xray 真实监听 8443, 8445, 8444, 10085 /
  面板成功读取 Stats API / Hysteria 真实启动并监听 UDP 30001 / 8 项自检全过 / 一键修复 4 步完成 /
  GeoIP 分流规则被真实 Xray 接受 / 反向证明缺数据或缺 `XRAY_LOCATION_ASSET` 时 Xray 拒绝启动 /
  **启动期自愈闭环**: 配置带 geo 规则 + 数据文件消失 → 原样启动被 Xray 拒绝 (复现) → `geodata guard`
  重新生成 (已移除 geo 规则) → 再自检通过 / 备份-恢复往返一致且篡改被拒 /
  5 个节点握手探测全部成功 (Reality TLS 136ms, 出口 RTT 54ms)。
- `scripts/browser_check.cjs` → **33/33 项通过**: 初始化→仪表盘全流程、5 张节点卡、三种订阅、
  二维码出图、诊断 8/8、节点测速结果落到卡片、GeoIP 开关与状态、**分流模板选择器 (切换 → 订阅内容
  真的变化 → 切回)**、备份下载、**程序更新卡片 (版本行 / 检查更新 / 非生产环境隐藏一键更新)**;
  无 console 错误、无失败请求。
- `scripts/upgrade_sim.sh` → **13/13 项通过**: 在模拟的"已部署机器"上真跑 `upgrade.sh` ——
  备份 → 换代码 → 按 `state.json` 重新落地配置 (把占位配置修回真实配置) → 写 `update.json` /
  `update.log`; 并覆盖失败路径: 下载失败时非 0 退出、代码自动回滚到升级前版本、状态记为 failed、
  现有部署与 `state.json` 的密钥 / 订阅令牌一字未动。
- API 边界: 无令牌 setup 403、重复 setup 409、非法域名 / 弱密码 / 非法用户名 400、
  无 Cookie dashboard 401、错密码 401 且第 4 次起 429、错误订阅令牌 404、未知节点 404、
  备份/探测/GeoIP 接口未登录一律 401、备份校验和不匹配 400。
- 前端: 三视图渲染、节点开关热更新、订阅三种格式复制与二维码、诊断面板、高级设置保存、测速与备份。

### 12.1 真实服务器验证 (2026-09-28, Ubuntu 24.04 / 1 vCPU / 1GB, Xray 26.3.27 + Hysteria 2.12.3)

这一轮把"只能在 Linux 上验证"的部分全部跑通, 也把两个**只在真机上才会暴露**的根因抓了出来
(本地 `pytest` / `verify.py` 全绿却救不了它们 —— 见下面第 3、4 条):

1. **部署链路**: `install.sh` → 面板初始化 → certbot 签发 `hkk.i3.pub` 的 Let's Encrypt 证书
   (有效期至 2026-12-27, `certbot.timer` enabled, 证书出现后 `/api/renew` 会自动重新生成
   nginx/xray 配置并热重载) → nginx 监听 80/443/8899、xray 监听 8443/8445/8444 +
   127.0.0.1:6000、hysteria2 监听 30001/31001/32001 (UDP 端口跳跃)。
2. **一键升级真机实测**: `upgrade.sh` 连升 v2.3.2 → v2.3.3 → v2.3.4 → v2.3.5, 每次 6 步全绿
   (备份 → 换代码 → 按 `state.json` 重新落地三份配置 → 重载服务 → 复查端口监听),
   `data/update.json` 记 success, 旧代码 + `state.json` 备份保留最近 5 份;
   面板「程序更新 → 一键更新」走 systemd 瞬时单元, 面板自身重启不打断升级。
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
6. **面板自测能力补强**: 旧 `/api/probe` 只做裸 TLS 握手 —— Reality 认证失败时服务端会**回落到
   真实伪装站点**, 裸握手照样成功, 这正是"面板 1/5 通、服务全绿"的来源。现在 `?deep=1` 会用临时
   Xray 客户端经 SOCKS5 隧道对伪装目标做一次真实 TLS 往返 (生产环境面板默认走它), 并把
   `allowInsecure` 换成 Xray 26 要求的 `pinnedPeerCertSha256` (Xray 25 起 `allowInsecure` 已移除,
   26.3 上直接拒绝加载配置 —— 这一点也是真机联调时才踩到的)。

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
  签发成功后, 用 `https://<域名>:8899` 访问即为可信证书。
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
