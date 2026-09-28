# ZeroProxy

> **0 配置, 1 行部署** 的智能科学上网代理面板。
> 不需要懂 Linux, 不写配置文件, 不手动申请 SSL, 不需要客户端折腾。

一条命令从空服务器到可用节点:

```bash
curl -fsSL https://<raw-host>/install.sh | bash
```

终端会输出形如 `https://<服务器IP>:8899/?token=xxxx` 的地址 (引导阶段自签证书) →
浏览器打开 (首次提示不安全, 点「继续访问」) → 填 **域名 / 用户名 / 密码** 三个信息
→ 点「一键生成」→ 得到 5 个节点、三种格式的订阅链接与二维码。
之后改用 `https://<你的域名>:8899`, 即为 **Let's Encrypt 真实可信证书**。

---

## 1. 能力总览

| 能力 | 说明 |
|---|---|
| **一条命令部署** | `install.sh` 自动完成 BBR、依赖、Xray/Hysteria 2 二进制、venv、nginx 引导配置、systemd、防火墙 |
| **5 个节点** | VLESS Reality (TCP+Vision)、VLESS XHTTP Reality、VLESS WebSocket、Trojan TLS、Hysteria 2 (QUIC+端口跳跃) |
| **3 种订阅格式** | 同一订阅地址 `?format=` 切换: Base64 通用 / Clash(mihomo) YAML / sing-box JSON |
| **引导令牌保护** | 初始化必须带 `?token=`, 公网暴露时别人抢不走你的面板; 初始化成功即作废 |
| **一键自检自愈** | `/api/diagnose` 检查 7 项 (服务、配置、入站一致性、证书、端口、伪装目标可达性) + `/api/repair` 重新生成并重启 |
| **流量统计** | 内置 Xray Stats API (仅 127.0.0.1), 仪表盘按节点展示上下行, 并写入订阅的 `subscription-userinfo` 头 |
| **订阅恒定, 内容动态** | 订阅 URL 永不变; 节点启停 / 端口变更 / 伪装设置都会自动同步到客户端 |
| **安全默认值** | 登录限流、会话上限与过期清理、PBKDF2-SHA256(12 万轮)、`state.json` 0600 原子写、CSP 等安全响应头、无 CORS 通配 |
| **一键卸载** | `uninstall.sh`, 与安装对称 (可保留数据或证书) |
| **可回归验证** | `pytest` 27 项 + `scripts/verify.py` 用真实 Xray / Hysteria / mihomo / sing-box 二进制校验 |

竞品与技术调研见 `docs/RESEARCH.md`。

---

## 2. 项目结构

```
zeroproxy/
├── install.sh                     # 一键部署 (BBR / 依赖 / 二进制 / venv / nginx 引导 / systemd / ufw / 引导令牌)
├── uninstall.sh                   # 一键卸载 (停服务 / 清单元 / 删 nginx 配置 / 回收 ufw / 可选保留数据)
├── dev.sh                         # 本地开发启动 (macOS 可跑, 无 systemd 自动 dry-run)
├── backend/
│   ├── requirements.txt           # fastapi / uvicorn / qrcode / cryptography / pyyaml
│   ├── requirements-dev.txt       # + pytest / httpx
│   ├── tests/                     # pytest 回归测试 (dry-run 全流程 + 安全边界 + 状态迁移)
│   └── zeroproxy/
│       ├── main.py                # FastAPI 入口 + 安全响应头中间件
│       ├── config.py              # 状态模型 (state.json v2) / 文件锁 / 引导令牌 / 审计日志
│       ├── crypto.py              # VLESS UUID 派生 / Reality ed25519 / PBKDF2
│       ├── xray_config.py         # Xray 配置生成 (Reality / XHTTP / WS / Trojan + Stats API)
│       ├── nginx_config.py        # Nginx 生成 (ACME + 443 WS 反代 + 伪装主页 + 8899 面板 TLS)
│       ├── hysteria_config.py     # Hysteria 2 配置生成 (端口跳跃 + masquerade 伪装)
│       ├── services.py            # systemctl / certbot / 自签证书 / 流量统计 / 诊断 适配层
│       ├── share_links.py         # 单节点链接 + Base64 / Clash / sing-box 三种订阅
│       └── routes.py              # API: setup / login / dashboard / settings / diagnose / sub / qr
├── scripts/
│   └── verify.py                  # 端到端验证: 真实二进制跑通配置生成与订阅解析
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
- **Reality 免证书**: 部署时生成 ed25519 密钥对, SNI 默认伪装 `www.microsoft.com`,
  `pbk`/`sid` 随订阅分发; 面板可随时改伪装目标 (自动改成 `sni:443` 并做可达性检查)。
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

---

## 4. 订阅: 一个地址, 三种格式

```
GET /sub/{token}                   → Base64 (通用: Shadowrocket / v2box / NekoBox / Streisand ...)
GET /sub/{token}?format=clash      → mihomo / Clash.Meta 完整 YAML (含 proxy-groups 与 rules)
GET /sub/{token}?format=singbox    → sing-box 1.14 完整 JSON (mixed 入站 + 嗅探 + 自动选择出口)
```

- 三种格式**内容一致、地址恒定**; 客户端按 `profile-update-interval: 12` 自动刷新, 节点启停 /
  端口变更 / 伪装设置变化自动同步, 用户侧零操作。
- 响应带 `subscription-userinfo` 头 (有统计数据时), 客户端可直接显示已用流量。
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
5. 对外端口是否被其他进程占用
6. Reality 伪装目标 (dest) 是否真的可连接
7. 本地开发环境自动跳过系统级检查

`POST /api/repair` 一键自愈: 重新生成 Xray + Nginx + Hysteria 配置 → 重载服务 → 复检并回传结果。

---

## 7. 自动化逻辑 (配置变更 → 订阅同步)

```
用户操作 (开关节点 / 改端口 / 改伪装 / 续期证书)
        │  POST /api/...   (config.locked() 事务)
        ▼
state.json (唯一事实来源, schema v2, 旧版本自动升级)
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
- state.json 结构升级: 新增字段在读取时由 `_merge` 自动补齐 (v1 → v2 已覆盖测试)。

---

## 8. 前端 UI

单文件 `static/index.html` (原生 JS + CSS, 零构建零 CDN, 离线可用):

- **Apple 风格**: SF 字体栈、18px 圆角卡片、柔和阴影、深浅色自动 + 手动切换。
- **三步交互**: 初始化 (三输入框 + 部署进度逐步打钩) → 登录 → 仪表盘, 每 20s 静默轮询。
- **仪表盘卡片**: 订阅三种格式 (各自复制 / 二维码)、5 张节点卡 (协议徽标 / 传输 / 加密 / 状态灯 /
  开关 / 单节点流量 / 复制链接 / 二维码)、流量总览与节点占比、高级设置 (Reality SNI /
  Hysteria 伪装站点 / 各节点端口)、诊断与一键修复、证书与系统状态、操作审计。

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
| POST | `/api/settings` | 会话 | 改 Reality SNI / Hysteria 伪装站点 / 节点端口 (含端口占用校验) |
| POST | `/api/apply` | 会话 | 重新生成全部配置并热重载 |
| POST | `/api/renew` | 会话 | `certbot renew` + reload nginx |
| GET | `/api/diagnose` / POST `/api/repair` | 会话 | 自检 / 一键自愈 |
| GET | `/api/traffic` | 会话 | 流量统计 (Stats API) |
| GET | `/api/logs/{service}` | 会话 | 服务日志尾部 (journalctl) |
| GET | `/sub/{token}?format=` | 订阅令牌 | Base64 / Clash / sing-box 订阅内容 |
| GET | `/api/nodes/{id}/qr` / `/api/subscription/qr` | 会话 | 节点 / 订阅二维码 PNG |

---

## 10. 上游兼容性 (实测)

| 组件 | 实测版本 | 兼容要点 |
|---|---|---|
| Xray Core | **26.3.27** (macOS arm64) | 含 XHTTP + Reality + Stats API 的生成配置通过 `xray -test`, 真实启动后监听 8443 / 8445 / 8444 / 10085 |
| Xray TLS 字段 | — | 25+ 的 `tlsSettings.certificates[]` 只接受 `certificateFile` / `keyFile`; 旧写法 `certificate` / `key` 会导致启动失败 |
| Xray sniffing | — | `destOverride` 合法值只有 `http` / `tls` / `quic` / `fakedns`, 写 `dns` 会被拒绝启动 |
| Xray Stats API | — | 路由必须把 api 入站的 `outboundTag` 指向 `api`; 指向 `direct` 时 `xray api statsquery` 连不上 |
| Hysteria 2 | **v2.12.3** | 生成的配置 (含 `masquerade.proxy.url` / `rewriteHost`) 能被真实二进制启动; 多端口 `listen` 仅 Linux 支持 (macOS 会明确报错) |
| mihomo | **v1.19.31** | Clash 订阅 (含 `network: xhttp` + `xhttp-opts`、hysteria2 `ports` / `hop-interval`) 通过 `mihomo -t` |
| sing-box | **1.14.2** | 订阅 JSON 通过 `sing-box check`; 1.13 起 legacy inbound 字段 (`sniff: true`) 被移除, 已改用 `route.rules[].action: sniff` |
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
```

开发环境可用 `ZP_XRAY_BIN` / `ZP_HYSTERIA_BIN` / `ZP_NGINX_BIN` 指定二进制绝对路径
(自定义安装位置, 或在 macOS 上做真实二进制验证)。

---

## 12. 开发验证记录

在 macOS (Apple Silicon, Python 3.14) 上实测通过:

- `python -m pytest tests -q` → **27 passed** (含 `ZP_XRAY_BIN` 真实 `xray -test` 校验)。
- `scripts/verify.py` (Xray 26.3.27 + Hysteria 2.12.3 + mihomo 1.19.31 + sing-box 1.14.2) → **30/30 项通过**:
  setup 8 步全绿 / 三种订阅格式可被真实客户端解析 / Xray 真实监听 8443, 8445, 8444, 10085 /
  面板成功读取 Stats API / Hysteria 真实启动并监听 UDP 30001 / 7 项自检全过 / 一键修复 4 步完成。
- API 边界: 无令牌 setup 403、重复 setup 409、非法域名 / 弱密码 / 非法用户名 400、
  无 Cookie dashboard 401、错密码 401 且第 4 次起 429、错误订阅令牌 404、未知节点 404。
- 前端: 三视图渲染、节点开关热更新、订阅三种格式复制与二维码、诊断面板、高级设置保存。

**尚未在真实 Linux 服务器验证的环节** (交付后建议首测): certbot 签发 → nginx 反代 →
Xray / Hysteria 生产启动 (systemd) → 客户端 App 实连。macOS 无法验证的部分: Hysteria 2
多端口 listen (Linux 专属)、systemd 服务重载、ufw 规则。

---

## 13. 运维

```bash
# 查看服务日志
journalctl -u xray -n 50 --no-pager         # 也可用面板 GET /api/logs/xray

# 升级核心 (也可指定版本回退)
XRAY_VERSION=24.11.30 bash install.sh       # install.sh 可重复执行

# 备份 / 恢复: 备份整个数据目录即可 (含全部密钥与订阅令牌)
tar czf zp-backup.tgz -C /opt/zeroproxy data

# 卸载 (保留数据: ZP_KEEP_DATA=1; 保留证书: ZP_KEEP_CERT=1)
bash /opt/zeroproxy/uninstall.sh
```

---

## 14. FAQ

- **打不开面板 / 提示不安全?** 引导阶段用自签证书, 点「继续访问」即可; 完成 setup 且 certbot
  签发成功后, 用 `https://<域名>:8899` 访问即为可信证书。
- **提示「引导令牌无效」?** 必须用安装完成时终端打印的、带 `?token=` 的链接打开面板。令牌文件在
  `/opt/zeroproxy/data/bootstrap_token`, 初始化成功后自动删除。
- **certbot 申请失败?** 面板自动回退自签证书, WS / Trojan 节点带 `allowInsecure=1` 仍可用;
  确认域名解析与 80 端口后点「续期」可切回 Let's Encrypt。
- **Hysteria 2 连不上?** 检查 UDP 30001-32001 是否放行; 部分网络封 UDP, 改用前四个 TCP 节点。
- **XHTTP 节点连不上?** 需要客户端支持 (mihomo 1.19+ / sing-box 1.11+ / 较新 v2rayN 系列);
  老客户端可用其他节点, 或在面板里关掉该节点。
- **换了域名?** 删除 `/opt/zeroproxy/data/state.json` 后重新运行 `install.sh`, 再走一遍 setup。
- **想改端口 / 伪装站点?** 仪表盘「高级设置」直接改, 保存后自动重新生成配置并热重载。

---

## 15. 已知限制与后续方向

- 单用户设计: 没有多用户 / 配额 / 到期时间 (那是 Marzban、3x-ui 的战场); 若要多人共享,
  建议保留本面板做「节点与订阅的自动化底座」, 由上游面板做用户管理。
- 流量统计依赖 Xray Stats API; Hysteria 2 的流量暂未计入 (上游无同等查询接口)。
- Hysteria 2 端口跳跃仅 Linux 生效 (上游限制), 非 Linux 环境自动退化为单端口。
- 订阅文件由面板实时生成, 未做 CDN 缓存与 ETag 协商 (单用户场景无影响)。
- 尚未内置: 核心二进制自动更新、DNS/ACL 分流订阅、节点延迟测速、多域名与多证书。
