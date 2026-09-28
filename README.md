# ZeroProxy

> **0 配置, 1 行部署** 的下一代极简科学上网代理面板。
> 区别于 V2Board / NginxProxyManager: 不需要懂 Linux, 不写配置文件, 不手动申请 SSL。

一条命令从空服务器到可用节点:

```bash
curl -fsSL https://<raw-host>/install.sh | bash
```

终端输出 `https://<服务器IP>:8899` (引导阶段自签证书) → 浏览器打开 (首次提示不安全, 点「继续访问」) → 输入 **域名 / 用户名 / 密码** 三个信息 → 点击「一键生成」→ 得到全部节点、订阅链接与二维码。之后改用 `https://<你的域名>:8899` 访问面板与订阅, 即为 **真实可信证书** (Let's Encrypt, 无警告)。

---

## 1. 项目结构

```
zeroproxy/
├── install.sh                     # 一键部署: BBR / 依赖 / Xray / Hysteria2 / systemd / SSL 前置
├── dev.sh                         # 本地开发启动 (macOS 可跑, 无 systemd 自动 dry-run)
├── backend/
│   ├── requirements.txt           # fastapi / uvicorn / qrcode / cryptography
│   ├── zeroproxy/
│   │   ├── main.py                # FastAPI 入口, 静态资源挂载, uvicorn 运行
│   │   ├── config.py              # 状态模型: $ZP_HOME/data/state.json 单一事实来源
│   │   ├── crypto.py              # VLESS UUID 派生 / Reality ed25519 密钥对 / PBKDF2 / 令牌
│   │   ├── xray_config.py         # Xray 配置生成 (Reality / WS / Trojan 三入站)
│   │   ├── nginx_config.py        # Nginx 生成 (ACME + 443 WS 反代 + 伪造主页)
│   │   ├── hysteria_config.py     # Hysteria 2 配置生成 (含端口跳跃)
│   │   ├── services.py            # systemctl / certbot / 自签证书 适配层
│   │   ├── share_links.py         # vless:// trojan:// hysteria2:// + Base64 订阅
│   │   └── routes.py              # API: setup / login / dashboard / toggle / sub / qr
│   └── static/
│       └── index.html             # Apple 风格卡片 UI (单文件, 零构建, 深浅色)
└── systemd/
    ├── zeroproxy.service          # 面板 (Python venv + uvicorn)
    ├── xray.service
    └── hysteria2.service
```

运行时布局 (服务器):

```
/opt/zeroproxy/
├── zeroproxy/        # 面板 Python 包
├── static/           # 前端
├── venv/             # Python 虚拟环境 (单目录, 无全局污染)
├── panel/cert.pem + key.pem  # 面板 HTTPS 引导/兜底自签证书 (install.sh 生成)
├── xray/config.json  # 由面板生成
├── hysteria/config.yaml + cert.pem/key.pem
├── certs/            # 自签兜底证书
├── www/              # ACME webroot + 443 伪造主页
└── data/state.json   # 全部可变状态 (权限 0600)
```

## 2. 协议组合 (依据《vless-trojan-hysteria2-technical-principles.md》)

一键生成 4 个节点, 覆盖技术文档全部三大协议 + Reality:

| 节点 | 组合 | 端口 | 原理 (文档章节) | 定位 |
|------|------|------|------------------|------|
| VLESS Reality | VLESS + TCP + XTLS-Reality + `xtls-rprx-vision` | 8443/tcp | §7 免证书, ed25519 密钥对 + SNI 伪装 + 四层反封锁 | 主力, 反封锁最强 |
| VLESS WS | VLESS + WebSocket, TLS 由 nginx 443 终结 | 443/tcp | §2.3 模块二, Let's Encrypt 真实证书 | 全平台/浏览器兼容 |
| Trojan | Trojan + TLS 1.3, 复用同一证书 + fallback 伪装 | 8444/tcp | §3 协议层即 HTTPS, SHA256 密码校验, 完美伪装 | 经典 HTTPS 伪装 |
| Hysteria 2 | QUIC/UDP, ChaCha20-Poly1305, 口令认证 | 30001/udp (+31001/32001 端口跳跃) | §4 + 附录 C, 弱网最优, 端口跳跃抗封锁 | 弱网/高延迟场景 |

设计决策:
- **凭据统一**: 用户只输入一次密码 — Trojan 直接用口令, Hysteria 2 用口令, VLESS UUID 由 `SHA256(用户名+密码)` 确定性派生 (`crypto.derive_uuid`), 重新生成配置时 UUID 恒定, 客户端无需重新导入。
- **Reality 无需证书**: 部署时生成 ed25519 密钥对, SNI 默认伪装 `www.microsoft.com` (文档 §7.6.3 选取策略: 知名度高 + TLS 1.3 + x25519 key_share), `pbk`/`sid` 随订阅分发。
- **端口跳跃默认开启** (附录 C 方案 B): Hysteria 2 同时监听 3 个 UDP 端口, 封锁单端口不影响服务; 面板可一键关闭。
- **443 伪造主页**: nginx 对非代理路径返回中性网页 (文档 §3.3 模块四), 陌生扫描器看到的是普通网站。
- **面板走真实可信证书**: 面板进程只监听 `127.0.0.1:9900`, 对外由 nginx 在 **8899** 端口终结 TLS —— SNI 命中域名时用该域名的 Let's Encrypt 证书, 其余 (IP / 未知 SNI) 回退自签。因此引导阶段用 `https://<IP>:8899` (自签), 完成 setup 后改 `https://<域名>:8899` 即为浏览器可信地址, 订阅链接同样可信; 全程无需重启面板, 也不影响 443 的伪装站。

## 3. 一键部署脚本 (install.sh)

| 步骤 | 内容 |
|------|------|
| 系统检测 | Ubuntu/Debian (兼容 kali/mint), amd64/arm64 自动识别 |
| 内核优化 | 写 `/etc/sysctl.d/99-zeroproxy.conf`: `fq` qdisc + **BBR** + 大缓冲区 + 大 `fs.file-max`, `sysctl --system` 生效 |
| 依赖 | `nginx` `certbot` `python3-venv` `unzip` `openssl` … |
| Xray Core | GitHub latest release (`Xray-linux-64/arm64.zip`), 失败回退 pin 版本 |
| Hysteria 2 | GitHub latest release, 失败则跳过该节点不影响其余协议 |
| 面板 | 装到 `/opt/zeroproxy`, `python3 -m venv` + pip, 零全局污染; 面板进程仅监听 `127.0.0.1:9900`, 由 nginx 在 8899 终结 TLS 后反代 (域名走真实证书, 其余 SNI 回退自签) |
| systemd | `xray` / `hysteria2` / `zeroproxy` 三服务 `enable --now`, 崩溃自动拉起 |
| SSL 前置 | 启用 `certbot.timer` 自动续期 (证书本体现在才申请, 等用户给域名) |
| 防火墙 | ufw 激活时自动放行 80/443/8899/8443/8444/tcp + 30001-32001/udp |
| 输出 | 终端打印 `https://<IP>:8899` 访问链接; 提示完成后改用 `https://<域名>:8899` (真实证书) |

## 3.1 上游版本兼容 (实测)

| 组件 | install.sh 默认 | 兼容要点 |
|------|----------------|----------|
| Xray Core | 最新稳定版 (可用 `XRAY_VERSION=24.11.30` 回退) | 配置中 `flow` 使用官方常量 `xtls-rprx-vision` (技术文档中的 "xtls-rp" 为旧名, 24.11+/26.x 均只接受该写法); 面板生成配置后在生产环境自动 `xray -test` 校验, 不通过会阻断并提示 |
| Hysteria 2 | 最新稳定版 (v2.12.x) | 当前版本 `listen` 只接受字符串, 多端口跳跃写作 `:30001,31001,32001`; 多端口监听仅 Linux 支持 (目标部署系统, 无影响) |
| Reality 密钥 | — | ed25519 密钥统一采用 base64url 无填充格式 (Xray 与客户端 pbk 的共同格式) |
| certbot | 系统包 | webroot 方式签发, 失败自动回退自签 (10 年), 节点不中断 |

## 4. Backend API 设计

| 方法 | 路径 | 鉴权 | 说明 |
|------|------|------|------|
| GET | `/api/status` | 无 | `{configured, authenticated}` 前端视图路由 |
| POST | `/api/setup` | 无 (仅未初始化时) | `{domain, username, password}` → 走完整部署流水线 (见下) |
| POST | `/api/login` / `/api/logout` | — | PBKDF2 校验 → HttpOnly 会话 Cookie (72h) |
| GET | `/api/dashboard` | 会话 | 节点/证书/系统/订阅 全量视图 |
| POST | `/api/nodes/{id}/toggle` | 会话 | 节点启停 → 热重载 |
| POST | `/api/hysteria/hopping` | 会话 | 端口跳跃开关 → 热重载 |
| POST | `/api/apply` | 会话 | 重新生成全部配置并热重载 |
| POST | `/api/renew` | 会话 | `certbot renew` + reload nginx |
| GET | `/sub/{token}` | 订阅令牌 | Base64 订阅内容 (客户端 App 导入) |
| GET | `/api/nodes/{id}/qr?size=N` | 会话 | 节点二维码 PNG |

`/api/setup` 流水线 (每步记录耗时与结果, 前端逐步展示):

```
生成密钥材料 (UUID/ed25519/订阅令牌) → 写状态 → 生成 Xray 配置
→ 生成 Nginx 配置 → 申请 SSL (certbot webroot, 失败回退自签)
→ 生成 Hysteria 2 配置 → systemctl reload nginx + restart xray/hysteria2
→ 自动登录, 进入仪表盘
```

核心生成逻辑 (节选自 `xray_config.py`):

```python
def build_xray_config(state) -> dict:
    inbounds = []
    if state["nodes"]["vless-reality"]:
        inbounds.append({                     # §7.3: VLESS + TCP + Reality
            "protocol": "vless", "port": 8443,
            "settings": {"clients": [{"id": state["uuid"], "flow": "xtls-rprx-vision"}]},
            "streamSettings": {"network": "tcp", "security": "reality",
                "realitySettings": {"dest": "www.microsoft.com:443",
                    "serverNames": ["www.microsoft.com"],
                    "privateKey": state["reality"]["private_key"],
                    "shortIds": [state["reality"]["short_id"]]}},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "dns"]},
        })
    if state["nodes"]["vless-ws"]:
        inbounds.append({                     # §2.3: WS 仅回环监听, TLS 由 nginx 终结
            "protocol": "vless", "listen": "127.0.0.1", "port": 6000,
            "streamSettings": {"network": "websocket", "security": "none",
                "wsSettings": {"path": "/ws/zeroproxy"}},
        })
    if state["nodes"]["trojan"] and cert_usable(state):
        inbounds.append({                     # §3: Trojan + TLS1.3, 非代理流量 fallback 到伪装目标
            "protocol": "trojan", "port": 8444,
            "settings": {"clients": [{"password": state["trojan_password"]}],
                          "fallbacks": [{"dest": "www.microsoft.com:443"}]},
            "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {...}},
        })
    return {"log": {"loglevel": "warning"}, "inbounds": inbounds,
            "outbounds": [{"protocol": "freedom"}]}
```

## 5. 前端 UI

单文件 `backend/static/index.html` (原生 JS + CSS, 零构建零 CDN, 离线可用):

- **Apple 风格**: SF 字体栈、18px 圆角卡片、柔和阴影、`-apple-system` 深色模式 + 手动切换 (localStorage 记忆)。
- **三步交互** (Role.md 用户旅程):
  1. **Init** — 三输入框 (域名/用户名/密码) + 「一键生成」, 部署进度逐步打钩展示;
  2. **Result** — 订阅卡片 (一键复制 + 二维码)、4 张节点卡片 (协议徽标/传输/加密/状态灯/开关/复制链接/二维码)、证书卡片 (有效期进度条 + 续期)、系统卡片 (各服务状态/版本/在线时长/端口跳跃);
  3. 每 20s 静默轮询刷新状态。

## 6. 自动化逻辑 (配置变更 → 订阅同步)

关键设计: **订阅 URL 恒定, 内容动态**。

```
用户操作 (面板开关节点/改配置/续期证书)
        │
        ▼
state.json 更新 (唯一事实来源)
        │
        ├──► 重新生成 xray/config.json + hysteria/config.yaml + nginx conf
        │            │
        │            ▼
        │     systemctl reload nginx; systemctl restart xray/hysteria2
        │     (Xray 重新加载入站, 新端口/新凭据秒级生效; 旧连接不受影响)
        │
        └──► 订阅内容 = f(state) 重新计算
                     │
                     ▼
        GET /sub/{token}  → Base64(启用节点的 vless:// + trojan:// + hysteria2:// 链接)
```

- 订阅 URL 含一次性随机令牌, **地址永不变化** — 客户端 App (Shadowrocket / Hiddify / v2box / Streisand 等) 导入后按自身策略自动刷新, 感知节点启停与凭据变化, 用户侧零操作。
- 节点关闭 = 从订阅内容中移除该行 + 入站从 Xray 配置移除 + Hysteria 监听收敛回 127.0.0.1, 服务平滑重启。
- 证书续期 (`certbot renew`) 只换文件 + `reload nginx`, 不触碰 Xray (Trojan 入站引用 `/etc/letsencrypt/live/` 软链, 续期后 Xray 下次重载自然生效)。

## 7. 安全要点

- 面板对外仅 8899 端口, 由 nginx 终结 TLS (域名走 **Let's Encrypt 真实证书**, 其余回退 `panel/cert.pem` 自签); 面板进程本身只监听 `127.0.0.1:9900`, 不对公网直接暴露。HTTPS 访问下会话 Cookie 自动带 `Secure` 标记 + HttpOnly + 72h 过期; 管理密码 PBKDF2-SHA256 (12 万轮) 存储。
- `state.json` 权限 0600, 含全部私钥/口令, 由 systemd 以 root 运行。
- Reality 节点无证书指纹可抓 (文档 §7.6.2 第 2 层); 非代理访问 8443 被 Reality `show:false` 拒绝, 443 非代理路径返回伪装网页。
- 建议: 云安全组仅放行必要端口; 域名使用独立二级域; 定期用「重新应用配置」检查服务健康。

## 8. 本地开发 / 验证

```bash
cd zeroproxy
ZP_PORT=8899 ./dev.sh     # 面板: http://127.0.0.1:8899 (本地无 nginx, 直接明文)
```

非 Linux 环境自动 dry-run: 配置/证书/订阅照常生成, 服务重载记录为「跳过」, 全流程可验证。
本地开发面板直接监听 `127.0.0.1:8899` 明文 (无 nginx); 生产环境由 nginx 在 8899 终结 TLS。

## 9. FAQ

- **certbot 申请失败?** 面板自动回退自签证书, WS/Trojan 节点带 `allowInsecure=1` 仍可用; 80 端口开放、域名解析生效后点「续期」可切回 Let's Encrypt。
- **面板/订阅提示证书不受信?** 引导阶段 (`https://<IP>:8899`, 或 certbot 尚未成功) 用的是自签证书, 点「继续访问」/在客户端允许自签即可。完成 setup 且 certbot 签发成功后, 用 `https://<域名>:8899` 访问面板与订阅, 即为 Let's Encrypt **真实可信证书**, 无任何警告。
- **换了域名?** 重新运行 `install.sh` 前请删除 `/opt/zeroproxy/data/state.json` (或在面板退出前记录凭据), 然后走一遍 setup。
- **Hysteria 2 连不上?** 检查 UDP 30001/31001/32001 放行; 部分网络封 UDP 时改用前三个 TCP 节点。

## 10. 开发验证记录

在 macOS 本地以 dry-run 模式 (无 systemd) 实测通过:

- 面板 API 全流程: setup 流水线 8 步全绿 → 自动登录 → 仪表盘 → 节点开关节点订阅 3 行 ↔ 4 行 → 端口跳跃单端口 ↔ 三端口 → 二维码 PNG → 登出/登录 → 非法输入 400/401/404 防护;
- 生成的 `xray/config.json` 通过真实 Xray 24.11.30 二进制 `xray -test`, 实际启动后绑定 `*:8443` 与 `127.0.0.1:6000`;
- 生成的 `hysteria/config.yaml` 通过真实 Hysteria 2 v2.12.3 二进制, 实际监听 `UDP *:30001`;
- 前端浏览器实测: 登录视图 → 仪表盘卡片渲染 → 二维码模态 → 节点开关热更新 Toast (见交付截图);
- `install.sh` / `dev.sh` 通过 `bash -n`, 全部 Python 模块通过 `py_compile`; GitHub 资产解析逻辑对 XTLS/Xray-core 与 apernet/hysteria 当前 release 实测命中。

尚未在真实 Linux 服务器验证的环节 (交付后建议首测): certbot 签发 → nginx 反代 → Xray/Hysteria 生产启动 → 客户端 App 实连。
