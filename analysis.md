# ZeroProxy 架构现状

> 快照: **2026-10-10** · 面板 **v2.11.27** · 路由器客户端 **v1.4.26** · `state.json` schema **v5**
> 本文回答"**现在是什么样**"。另外两份文档分工不同, 不要混读:
> `README.md` 是逐版开发日志 (4000+ 行, 每一版为什么这么改、哪次真机踩的坑);
> `docs/RESEARCH.md` 与 `docs/ROUTER-CLIENT-REDESIGN.md` 是竞品调研与设计依据。
> 改面板代码时**必须同时更新这篇与 README 的版本号章节** (见 §14)。

---

## 1. 定位

把「买一台服务器 → 拿到可用订阅」压成**一条命令**的自托管代理面板。

它不是 3x-ui / Marzban / Hiddify 那一类多用户计费面板: 没有数据库, 没有用户模型, 没有部署向导。
面板只服务**单一运营方**, 初始化只收三样东西 (域名 / 管理用户名 / 管理密码), 其余——Xray / Hysteria 2 /
Nginx / Let's Encrypt 证书 / 订阅链接 / 防火墙——全部由面板按状态生成并热重载。

技术栈:

| 层 | 选型 | 为什么 |
|---|---|---|
| 面板后端 | Python + FastAPI + uvicorn (单进程) | 状态集中在 `state.json`, 不需要数据库 |
| 代理内核 | Xray (Reality / XHTTP / WS / Trojan) + Hysteria 2 (QUIC) | 上游内核即契约, 面板只生成配置不改内核 |
| 入口 | Nginx (TLS 终结 + 反代 + 伪装主页) | 一个 443 端口同时承载 WS 节点、面板与伪装 |
| 面板前端 | 原生 ES 模块 + 分层 CSS, **零构建零 CDN** | 目标机不可能装 Node; 断网也要能开面板 |
| 路由器端 | mihomo (内核) + Go 静态二进制 `zpcore` (控制面) + Shell (装机) | 兼容原厂精简固件; 不依赖固件自带的 Web 服务器 |

---

## 2. 目录与产物

仓库共 87 个跟踪文件。代码分布:

| 部分 | 位置 | 规模 |
|---|---|---|
| 后端 Python | `backend/zeroproxy/` (19 个 `.py`) | ~12 400 行 |
| 前端 JS / CSS | `backend/static/app/` | ~3 900 / ~820 行 |
| 回归测试 | `backend/tests/` | ~6 600 行 |
| 部署 / 客户端 Shell | `install.sh` `upgrade.sh` `uninstall.sh` `client/router-install.sh` | ~4 700 行 |
| 验证脚本 | `scripts/` | ~5 000 行 |
| 路由器控制面 | `backend/zeroproxy/client/agent/` (Go) | ~790 行 |

```
zeroproxy/
├── install.sh / upgrade.sh / uninstall.sh / dev.sh
├── README.md                       # 逐版开发日志 (权威, 但长)
├── analysis.md                     # 本文件: 当前架构快照
├── docs/
│   ├── RESEARCH.md                 # 竞品与上游事实调研 (源码级证据)
│   └── ROUTER-CLIENT-REDESIGN.md   # 路由器客户端重设计方案
├── backend/
│   ├── requirements.txt / requirements-dev.txt
│   ├── tests/                      # pytest: conftest + test_panel/test_devices/test_chain
│   ├── static/
│   │   ├── index.html              # 只有页面标记
│   │   └── app/
│   │       ├── main.js             # 装配层 (import 各模块 + 暴露回归脚本入口 + boot)
│   │       ├── lib/                # dom · format · api · state · jobs · drafts · dialog · render · theme
│   │       ├── views/              # dashboard · status · traffic · chain · clients · update · diag · audit · panel · setup
│   │       └── style/              # tokens.css → base.css → components.css
│   └── zeroproxy/
│       ├── main.py                 # FastAPI 入口 + 安全响应头中间件 + 后台线程
│       ├── config.py               # 状态模型 / 文件锁 / 引导令牌 / 审计日志
│       ├── routes.py               # 全部 API (56 条路由)
│       ├── apply.py                # 配置落地闭环 (面板与 upgrade.sh 共用)
│       ├── services.py             # systemctl / certbot / 自签 / 流量 / 握手探测 / 诊断
│       ├── xray_config.py          # Xray 配置生成
│       ├── hysteria_config.py      # Hysteria 2 配置生成
│       ├── nginx_config.py         # Nginx 配置生成 (ACME + 443 + 面板)
│       ├── share_links.py          # 单节点链接 + 三种订阅 + 三档分流模板
│       ├── chain.py                # 链式代理: 配对码 / 端口分配 / 真实出口探测
│       ├── chain_quic.py           # 链式内层 QUIC (Hysteria 2 子进程托管)
│       ├── geodata.py              # GeoIP/GeoSite 下载校验 + 分流规则 + 自动更新
│       ├── devices.py              # 客户端设备注册表 (配对码 / 凭据 / 期望状态)
│       ├── router_client.py        # 路由器安装脚本渲染 + mihomo 内核缓存分发
│       ├── crypto.py               # VLESS UUID 派生 / Reality X25519 / PBKDF2
│       ├── account.py              # 管理员凭据规则的唯一实现 (面板与 z 共用)
│       ├── cli.py                  # 终端快捷管理 z
│       ├── update.py               # 面板自更新 (版本检查 / 拉起 upgrade.sh / 回读进度)
│       └── client/                 # 路由器端制品
│           ├── router-install.sh   # 路由器装机脚本 (~4 220 行, 面板渲染后下发)
│           ├── agent/              # zpcore: Go 控制面 (源码 + dist/ 制品)
│           └── luci/               # 路由器管理界面 (页面 + cgi; zpcore 复用同一套页面)
├── scripts/                        # 验证脚本 (见 §15)
└── systemd/                        # zeroproxy.service / xray.service / hysteria2.service
```

运行时布局 (`$ZP_HOME`, 默认 `/opt/zeroproxy`): `data/state.json` (0600) · `data/audit.log` ·
`data/backups/` · `geo/` (geoip.dat + geosite.dat) · `xray/config.json` · `hysteria/config.yaml` ·
`certs/` · `panel/` (面板自签证书) · `www/` (ACME webroot + 伪装主页) · `nginx/` · `venv/`。

---

## 3. 运行时进程拓扑

```
            客户端 ──TLS──┐
                          ▼
                    ┌───────────────────────────────┐
                    │ Nginx                         │
                    │  :80   ACME webroot + 301     │
                    │  :443  /ws/zeroproxy → Xray    │  其余路径 → 伪装主页
                    │  :8899 面板 (SNI 命中域名给真证书 / 否则自签) │
                    └───────┬───────────────┬───────┘
                            │ 反代          │
                            ▼               │
              ┌──────────────────────┐      │
              │ uvicorn 面板          │◀─────┘
              │ 127.0.0.1:9900       │
              │ REST + 静态 SPA + 后台线程 │
              └───┬──────────┬───────┘
                  │          │ 托管子进程 (按需启停)
     ┌────────────▼──┐  ┌────▼─────────────┐
     │ Xray (systemd)│  │ Hysteria 2        │
     │  8443 Reality │  │  (systemd) 30001/udp (+31001,32001 跳跃)
     │  8445 XHTTP   │  └───────────────────┘
     │  8444 Trojan  │  ┌───────────────────┐
     │  6000 WS(内部) │  │ hysteria 子进程    │  ← 链式内层 QUIC (面板托管)
     │  10085 API(内部)│ └───────────────────┘
     └───────────────┘
```

面板进程自身只绑回环。对外只有 Nginx 的 8899, 可由安全组限制来源。后台线程三个:
GeoIP 自动更新 (6 小时检查一次)、链式 QUIC 看门、公网 IP 回显刷新。

---

## 4. 后端模块 (backend/zeroproxy/)

| 模块 | 行数 | 职责 |
|---|---:|---|
| `routes.py` | 3293 | 全部 API: 初始化 / 认证 / 仪表盘 / 设置 / 订阅 / 二维码 / 备份 / 诊断 / 探测 / 升级 / 链式 / 设备 / 设备侧 `/c/*`。含异步落地任务表与会话管理 |
| `services.py` | 1248 | 系统适配层: systemctl / certbot / 自签证书 / 流量统计 (Stats API) / 真实握手探测 / 诊断; 非 Linux 自动 dry-run |
| `share_links.py` | 1398 | 单节点分享链接 + 三种订阅格式 + 三档分流模板 + 设备专属订阅 |
| `router_client.py` | 854 | 路由器安装脚本渲染 (`__ZP_BASE__`/`__ZP_CODE__` 占位替换) + mihomo 内核多镜像缓存分发 |
| `geodata.py` | 800 | GeoIP/GeoSite 多镜像下载 + 体积/SHA/真实 `xray -test` 三重校验 + 原子替换 + 上游版本核对 |
| `chain.py` | 775 | 链式代理: 配对码打包解析 / 端口分配 / 真实出口 IP 探测 / 预热 |
| `config.py` | 639 | 状态模型 (schema v5) / `locked()` 事务 / 引导令牌 / 审计日志 / 备份还原 |
| `chain_quic.py` | 593 | 链式内层 QUIC: hysteria 子进程托管 / 配置同步 / 看门线程 |
| `apply.py` | 574 | 配置落地闭环 (生成 → 真实校验 → 重载 → 复查端口); 面板与 `upgrade.sh` 共用 |
| `xray_config.py` | 437 | Xray 配置生成 (4 个入站 + 链式入站/出站/路由 + Stats API + geo 规则) |
| `update.py` | 381 | 面板自更新: 远端版本检查 + `systemd-run --no-block` 拉起 `upgrade.sh` + 回读进度 |
| `devices.py` | 363 | 客户端设备注册表: 配对码 / 设备凭据 (只存 sha256) / 期望状态 / 配置版本哈希 |
| `cli.py` | 339 | 终端快捷管理 `z` (改账号 / 在线更新 / 看状态), 与面板同一条代码路径 |
| `main.py` | 278 | 入口: FastAPI 装配 / 安全响应头 (含按文件算的内联脚本哈希) / 启动端口探测 / 后台线程 |
| `nginx_config.py` | 208 | Nginx 配置生成 (ACME + 443 WS 反代 + 面板 TLS + 伪装主页) |
| `crypto.py` | 95 | VLESS UUID 确定性派生 / Reality X25519 密钥对 / PBKDF2-SHA256 |
| `hysteria_config.py` | 82 | Hysteria 2 配置生成 (端口跳跃 + masquerade) |
| `account.py` | 75 | 管理员凭据规则的**唯一**实现 (用户名格式 / 密码长度 / 踢下线), 面板与 `z` 共用 |
| `__init__.py` | 6 | `__version__` —— 升级检查读的就是这一行 |

---

## 5. 状态与并发 (`config.py`)

单一事实来源是 `$ZP_HOME/data/state.json` (0600, schema **v5**)。

* **原子写**: 临时文件 → `fsync` → `rename`; 崩溃/断电不会留下半个 JSON。
* **事务**: `config.locked()` = 进程内 `threading.RLock` + 进程间 `fcntl.flock`。所有「读 → 改 → 写」
  整体包在里面, 并发端点不会互相覆盖。
* **结构升级**: `_merge` 递归补齐缺失键; 已是对象的字段只接受对象——坏数据 (`"reality": null`)
  退化成「字段缺失」由接口给 400, 而不是把面板打成 500。旧版备份也能恢复 (`state_from`)。
* **引导令牌**: `install.sh` 写 `data/bootstrap_token` (0600) 并打印带 `?token=` 的链接;
  `POST /api/setup` 常量时间比对, 成功后立即删除——关闭「谁先打开面板谁就能抢注管理员」的时间窗。
* **审计日志**: 最近 500 条留在 state 里 (每条带**单调递增 id**, 面板按游标分页);
  更老的滚动到 `data/audit.log` (NDJSON, 1 MB 轮转)。动作名与分类在**服务端**登记 (`AUDIT_ACTIONS`),
  面板只负责画中文名; 同一件事 60 秒内重复只**合并计数** (被扫登录失败时不会刷满缓冲)。

state 顶层字段 (v5): `configured` `domain` `admin` `uuid` `reality` `xhttp` `trojan_password`
`hysteria_password` `hysteria_masquerade` `ports` `hysteria_hopping` `hysteria_ports` `routing`
`geodata` `nodes` `chain` `devices` `cert` `subscription_token` `sessions` `login_failures`
`audit` `audit_seq` `steps` `created_at` `updated_at`。

---

## 6. 配置落地闭环 (`apply.py`)

面板点按钮与服务器跑 `upgrade.sh` 走的是**同一条**路径, 六步:

1. **校验 Reality 密钥与伪装目标** —— 前置修正: v2.3.2 及更早误用的 Ed25519 密钥对、
   以及证书链超过 REALITY 8 KB 缓冲的旧默认伪装目标 (`www.microsoft.com`), 在这里就地改正。
   这两者都会造成「服务全绿、四个 TCP 节点全不通」。
2. 重新生成 Xray 配置 (+ 真实 `xray -test`)
3. 重新生成 Nginx 配置 (+ `nginx -t`)
4. 重新生成 Hysteria 2 配置
5. **并发**重载服务——按三份配置的 sha256 比对, 只有真变了的服务才重启
6. 复查端口监听——**双向**: 该开的必须在听, 该关的必须真的不在了

严格语义 (v2.3 起): 写不进 `/etc/nginx/conf.d/` 算失败、`nginx -t`/`xray -test` 不过算失败、
重启后端口没监听算失败。任一步失败都会出现在返回的 `steps` 里, 面板据此标红, 不再出现
「全绿但节点不通」。长任务走异步: 接口立刻回执带 `job`, 前端每 400 ms 轮询 `/api/apply/job`
(`ZP_APPLY_ASYNC=0` 时同步返回 `steps`, 测试用)。

---

## 7. 订阅 (`share_links.py`)

**一个地址, 三种格式, 三档分流**, 地址恒定不变:

```
GET /sub/{token}                      → Base64 (通用)
GET /sub/{token}?format=clash         → mihomo / Clash.Meta 完整 YAML
GET /sub/{token}?format=singbox       → sing-box JSON (download_detour 写法)
GET /sub/{token}?format=singbox-next  → 同上, 1.14+ 的 http_clients 写法
任意格式可叠加 ?rules=smart|global|direct
```

分流模板: `smart` (默认; 广告拦截 + **国内 App 直连层** + 国内域名/IP 直连 + 私有地址, 其余走节点) /
`global` (只拦广告, 其余全代理) / `direct` (全直连, 零 geo 下载)。两端的策略组是一套语义:
`♻️ 自动选择` / `🚀 节点选择` / `🎯 全球直连` / `🛑 广告拦截` / `🐟 漏网之鱼`。切换模板**不重载任何服务**。

硬约束 (上游实测, 详见 `docs/RESEARCH.md` §3): geo 规则与数据文件存在性**绑定** (数据缺失则整份配置
加载失败)、Hysteria 2 口令整串比较 (所以只写密码)、sing-box 的 rule-set 必须指定 `download_detour: direct`
(否则「节点没通 → 客户端起不来」的引导期死锁)。响应带 `subscription-userinfo` 头。

**设备专属订阅** (路由器用) 与主订阅是两套凭据: 见 §10。

---

## 8. 链式代理 (`chain.py` / `chain_quic.py`)

用户场景: 香港机器做入口 (延迟低), 美国机器做落地 (出口 IP 是美国), 客户端只连香港那个节点。
对客户端来说只是「订阅里多了一个普通节点」——不需要手写 Clash relay / sing-box detour, 手机也能用。

* **落地端**: 面板生成一行**配对码** `ZPC1~base64url(payload)~sha256(payload)[:6]`。
  凭据是**独立 UUID + 独立端口**, 可与自己的订阅凭据分开轮换/吊销。内层传输两种:
  `reality` (VLESS + TCP + Reality + Vision, 默认) 与 `hysteria2` (QUIC; 跨洋链路上 TCP-over-TCP
  会互相拖累, 换 UDP 能绕开——见 `chain_quic.py` 顶部)。
* **入口端**: 粘贴配对码 → 校验 → **起一个临时 Xray 客户端真的穿过落地端出网并读回落地出口 IP**
  → 一键落地: 新增一个入站 (客户端连它) + 一个出站 (连落地端) + 一条路由规则。
* 端口约定: 落地 8447/tcp (Reality)、8448/udp (QUIC 内层); 入口侧从 8446 起顺序找空位; QUIC 客户端 SOCKS 从 8470 起。
* QUIC 内层的 hysteria 进程由**面板托管** (不是 systemd): 本地开发与生产同一条路径,
  老部署面板内升级完即能用, 由看门线程兜底。

---

## 9. GeoIP 分流数据 (`geodata.py`)

数据源 `Loyalsoldier/v2ray-rules-dat` (每日构建); 国内网络常连不上 GitHub, 因此**多镜像顺序回退**。

* **硬前置**: 只有开关打开**且**数据齐备 (`usable()`) 才下发 `geoip:` / `geosite:` 规则——
  Xray 在配置**构建**阶段就要读 dat 文件, 缺文件不是「跳过规则」而是**整份配置加载失败**。
* **下载校验**: 先取上游两个几十字节的 `.sha256sum` 核对 (一致就返回「已是最新」, 省掉 ~28 MB) →
  内容变了才下载 → 体积校验 + SHA256 交叉核对 + 真实 `xray -test` → 同文件系统内原子替换。
* **自动更新**: lifespan 线程每 6 小时检查一次 (TTL 7 天, 从**上次检查**算); 手动按钮与自动更新
  共用一把锁 (`UPDATE_LOCK`), 真正冲突才 409。
* 启动前自愈 `geodata guard` 挂在 systemd `ExecStartPre`: 数据丢失或配置自检不过时按当前状态重建,
  保证 Xray 一定能起来。

---

## 10. 客户端注册表与内核分发 (`devices.py` / `router_client.py`)

面板上的「客户端」页背后: 让路由器/手机/电脑**各自持有一份独立凭据**。

* **主订阅令牌永不下发**。安装命令里带的是一次性**配对码** (30 分钟有效, 用掉即废); 设备拿它换
  `device_id + secret`, 之后所有请求用这对凭据。secret 只在配对响应里出现一次, 服务端只存 **sha256**
  (备份文件会离开这台机器, 明文凭据不该躺在里面)。单台设备因此可单独吊销/改名/换模板。
* **开关是「期望状态」不是按钮动画**: 面板写 `desired`, 设备轮询 `/c/report` (约 15 秒一次) 拿到它
  并回报 `actual`; 面板显示的颜色取自 `actual`——「显示已连接」永远意味着路由器真的连上了。
* **配置版本用内容哈希**: `config_rev()` 把影响订阅内容的字段做一次哈希 (节点启停 / 端口 / 模板 /
  链路), 心跳写盘不会改变它。设备据此判断「要不要重新拉配置」。计数器方案迟早漏掉一处, 故不用。
* **内核由面板分发**: 路由器装机时还没有代理可用, 连不上 GitHub。面板在服务器侧多镜像重试、
  只成功下载一次就缓存 (`data/client/cores/`), 路由器因此只需要访问面板**一个地址**。

设备侧接口 (`/c/*`): `GET /c/{code}` 安装脚本 · `POST /c/pair` 配对码换凭据 ·
`GET /c/bin/{arch}` 内核 · `GET /c/agent/bin/{arch}` zpcore 制品 · `GET /c/sub/{id}?k=…` 该设备的配置 ·
`POST /c/report` 心跳 · `GET /c/core/status` · `GET /c/geo/{name}` 分流数据库 · `GET /c/ui/{name}` 本地界面资源 ·
`GET /c/bench/{mb}` 内建基准 · `GET /c/btf?kver=&arch=&fmt=` 内核 BTF 包 (按内核 minor 系列 +
架构挑, 缓存后分发; 上游 `kenzok8/vmlinux-btf`, 也可手工放进 `data/client/btf/`)。
性能模式 (eBPF / dae): `GET /c/perf/{arch}` 内核 (匿名, 与 `/c/bin` 同性质) ·
`GET /c/perf/config?id=&k=` 设备专属 dae 配置 · `GET /c/perf/geo/{name}` 那份 v2ray 格式的
分流数据 (与 Xray 复用同一份; 白名单两个名字)。

---

## 11. 路由器端 (`client/`)

用户拿到的是面板生成的一行命令: `wget -qO- https://<面板>/c/<配对码> | sh`。

* **`client/router-install.sh`** (~4 220 行) 做四件事, 顺序不能变:
  ① 用一次性配对码换设备凭据 → ② 装内核 (按架构取 mihomo 静态二进制 + kmod-tun) →
  ③ 落四个文件 (config.yaml / init 脚本 / 控制 agent / 运维 CLI) → ④ 起服务并**自检**
  (自检不过就退回 tproxy 方案, 而不是假装成功)。幂等: 重复执行 = 重装/升级。
* **数据面五级能力阶梯**: `tun` → `tproxy` → **`iptables REDIRECT`** → 不接管 (eBPF 只探不选)。
  每一级都**真做一次**再判定 (建个设备再删、加条规则再撤), 结论连同「为什么不行」的内核原话写进
  `caps`; 起不来的自动往下让位。这让 OpenWrt 21.02 / 内核 5.4 那一代原厂精简固件第一次有了可用的路
  (局域网 TCP), 而不是只能报「未生效」。
* **两代包管理器**: OpenWrt 25.12 起是 `apk`, 24.10 及更早是 `opkg` —— 判据是**固件世代 +
  实际命令**两条一起看 (厂商固件报 25.x 却只有 opkg 的迁移态也走对), apk 一侧用 `apk -U add`
  一条命令, 只在签名类错误上退 `--allow-untrusted` (dae 的家用安装脚本的做法)。内核模块没装成时
  把命令**原话**与这台机器能用的补装命令一起说出来, `fw` / `pkgmgr` / `deps_why` 落进 `caps` ——
  于是 `zeroproxy status|doctor` 报的就是同一份现场。25.12 官方镜像里 tun / nft-tproxy 两个 kmod
  **都不预装**, 而它们来自与内核版本绑定的源 (厂商内核常对不上), 这条事实在输出里写明。
  24.10 已 EOL (2026-09): 装机时主动提示升级。
* **`client/agent/` = `zpcore`** (Go 静态二进制): 自带 HTTP 服务、自己校验令牌、**只绑局域网地址**
  (找不到局域网地址就拒绝启动而不是退成 `0.0.0.0`)。存在的原因是「能不能打开管理界面」取决于固件
  (uhttpd / nginx+fcgiwrap / 无 cgi / busybox 缺 httpd applet, 四种各踩过一次真机), 而用户改不了固件。
  接口契约与原 cgi 完全一致, 所以 `client/luci/` 那个页面一个字节没改。
* **本机自治**: 面板不可达时, 路由器上 `zeroproxy on|off` 写一份**本机覆盖**并立即生效
  (家里网出问题时恰恰是面板最容易联系不上的时候); `zeroproxy revert` 停用后与装机前的防火墙/策略路由
  **快照逐条比对**, 给出「一致 / 还有残留 + 差在哪一项」的结论。`zeroproxy doctor` 用带 `counter` 的规则
  回答「规则存在 ≠ 有流量经过」。
* **IPv6 一并接管**: 设备装机时探一次这一档数据面能否覆盖 v6, 能就给双栈配置, 接不了如实上报。
* **性能模式 (L0 · eBPF / dae)**: 数据面换给 dae (内核态分流, 直连流量真旁路), 与
  tun / tproxy **互斥** —— 进去时停 mihomo 并 disable, 出来时反之。开关逻辑只有一份
  (`/etc/zeroproxy/perf.sh`), 三个入口共用: CLI 的 `zeroproxy perf on|off|status`、本机管理页
  那块跑车仪表盘、以及 agent 心跳里的**看门狗** (说好在用而 dae 不在, 连续 3 轮自动退回)。
  三条硬规矩: 进去前 `dae validate` 校验配置、进去后用**出口探针**验证流量真的过得去、
  任何一步失败都退回原来的模式。dae 与它的配置由面板分发 (`/c/perf/*`, 与内核 / 分流数据
  同一套); 节点内联成分享链接, dae 不支持的 XHTTP 被排除并写进配置头部。`caps` 记
  `perf_cap` / `perf` / `perf_why`; `ZP_PERF=0` 可关。
* **内核 BTF 自动补齐**: 不带 `CONFIG_DEBUG_INFO_BTF` 的固件没有 `/sys/kernel/btf/vmlinux`,
  CO-RE eBPF (dae 那一类, 也是"性能档"的候选) 就用不了。检测到缺失时自动补: 先问本机软件源
  (`vmlinux-btf`), 再问面板 (`/c/btf` —— 面板按 minor 系列 + 架构挑包、缓存、发下来, 与内核
  二进制同一套分发), 装上后用 **cilium/ebpf 与 libbpf 的候选路径表**验证真的就位, 结论
  (`btf` / `btf_how` / `btf_path` / `why.btf`) 落进 `caps`, `status` 与 `doctor` 读同一份。
  只在"有戏"时动手 (内核 ≥5.17 且系列在 6.6 / 6.12 内), 补不上就说清原因与影响面 (只影响
  性能档, 不影响当前数据面)。上游是 `kenzok8/vmlinux-btf` 的 release, 也可手工放进
  `data/client/btf/`。

---

## 12. 前端 (`backend/static/`)

零构建、零 CDN 的原生 ES 模块 SPA——目标服务器上没有 Node, 浏览器直接加载 `/static/app/main.js`。

* `index.html` 只留标记; 样式三层: `tokens.css` (设计令牌) → `base.css` (元素默认 + 尺度工具类) →
  `components.css` (组件)。改主题只动 tokens。
* `lib/` 是底座: `dom` (含唯一的转义出口 `esc`/`escAttr`, 以及把 `data-w`/`data-bg` 落成 CSSOM 的
  `applyWidths`) · `format` · `api` (含「连接中断 ≠ 业务失败」的 `e.dropped` 语义) · `state` (跨模块共享状态 +
  重画钩子) · `jobs` (后台落地闭环轮询) · `drafts` (重渲染时的输入草稿保护) · `dialog` (原生 `<dialog>`) ·
  `render` · `theme`。`views/` 每个文件一个板块, `dashboard.js` 是唯一编排者。
* 交互: 初始化 (三输入框 + 部署进度逐步打钩) → 登录 → 仪表盘 (每 20 秒静默轮询);
  左侧锚点导航 (计数角标 + 滚动高亮) + 顶部指标条 + 节点密集表格 + 流量卡 + 链式拓扑 + 程序更新闭环。
* 静态资源 URL 带版本前缀 + `no-cache` 强制回源校验: 升级后不会出现「新功能卡片是空壳、样式是旧的」。
  首屏主题在 `<head>` 内联同步应用 (避免深色模式闪白), 这一段用 sha256 白名单放行 (见 §13)。
* `main.js` 显式把若干函数挂到 `window`, 那是与回归脚本 (`scripts/browser_check.cjs`) 的契约, 不是随手泄漏的全局。

---

## 13. 安全模型

| 面 | 措施 |
|---|---|
| 初始化抢注 | 一次性引导令牌, 常量时间比对, 成功后立即删除 |
| 暴露面 | 面板进程只绑 `127.0.0.1:9900`; 对外只有 Nginx 的 8899 |
| 登录爆破 | 连败 3 次起按 2^n 秒封禁 (上限 300 s), 返回 429 + `Retry-After`, 状态持久化 |
| 会话 | HttpOnly + SameSite=Lax (HTTPS 自动加 Secure), 72 h 过期, 最多 8 个 (超出淘汰最旧), 支持全部登出 |
| 口令 | PBKDF2-SHA256, 16 字节随机盐, 12 万轮, 常量时间比较 |
| 文件 | `state.json` / 私钥 / 令牌均 0600; 写盘原子替换 |
| 并发 | `config.locked()` = 进程内 RLock + `fcntl.flock`, 读-改-写事务化 |
| HTTP 头 | CSP 的 `script-src` **与 `style-src` 都不放行 `unsafe-inline`**; 页面仅剩的 head 内联主题脚本用启动时按 `index.html` 实际内容算出的 sha256 白名单放行。另有 `X-Content-Type-Options` / `X-Frame-Options: DENY` / `Referrer-Policy` / `Permissions-Policy`; 不开放 CORS 通配 |
| 数据驱动样式 | 进度条 / 延迟条 / 流量条的宽度与底色在模板里只写 `data-w` / `data-bg`, 插入文档后由 `lib/dom.js` 的 `applyWidths()` 用 **CSSOM** 赋值 (`el.style.*` 不受 `style-src` 约束) |
| 设备凭据 | 主令牌不下发; 每台设备独立 secret, 服务端只存 sha256 |
| 审计 | 最近 500 条 + 归档; 不可逆动作带风险标记 |

---

## 14. 部署与升级

* **`install.sh`** (Ubuntu/Debian): BBR + 内核参数 → 依赖 (git/curl/wget/unzip/nginx/certbot) →
  Xray + Hysteria 2 二进制 → venv → nginx 引导配置 → systemd → 防火墙 → 引导令牌 → 打印 `https://<IP>:8899/?token=…`。
  GitHub 取文件走**多前缀表** (自建反代排第一, 最后才直连; 拿到的必须是非空文件)。
  识别到 OpenWrt 会**当场停下**并说明「面板装在服务器上, 路由器端用面板生成的那一行命令」——
  在路由器上跑它以前只会留下一句 `dpkg: command not found` (真机截图)。
* **`upgrade.sh`**: 备份代码与 `state.json` → 换代码 → 按现有 `state.json` 重新落地配置 → 任一步失败**自动回滚**。
  只换程序代码, 密钥 / 订阅令牌 / 节点开关原样保留, **订阅地址不变**。
  面板内升级由 `systemd-run --no-block` 放进独立 cgroup (面板自身重启不打断), 进度落在
  `data/update.json` + `data/update.log`, 面板重启后照常能读。
* **`uninstall.sh`**: 与安装对称, 可选保留数据 / 证书。
* **`dev.sh`**: 本地开发启动 (macOS 可跑, 无 systemd 时自动 dry-run)。`cli.py` 提供终端兜底入口 `z`。
* systemd 单元: `zeroproxy.service` (面板, `Restart=always`) / `xray.service` / `hysteria2.service`;
  Xray 单元里设 `XRAY_LOCATION_ASSET` 指向 `$ZP_HOME/geo`。

> **改面板代码必须同时做两件事**: ① 动 `backend/zeroproxy/__init__.py` 的 `__version__`
> (升级检查读的就是这一行, 不动它用户点多少次都升不上来); ② 在 README 末尾追加一节版本号章节。

---

## 15. 验证体系

全部用**真实二进制 / 真实浏览器 / 真实升级脚本**, 不只跑 mock:

| 脚本 | 覆盖 |
|---|---|
| `backend/tests/` (pytest) | **309 通过 + 6 skip** (无真实内核二进制时跳过)。dry-run 全流程 + 安全边界 + 状态迁移 |
| `scripts/verify.py` | 用真实 Xray/Hysteria/mihomo/sing-box 校验生成的配置与订阅 (含**两台机器真跑一条链**) |
| `scripts/router_install_check.py` | **149 项**。真的用 shell 跑一遍路由器安装脚本: 七类机器 (含 OpenWrt 25.12 / apk 三态 / BTF 两种现场 / 性能模式的进-出-回退) / 本机覆盖 / revert 比对 / zpcore 真跑 |
| `scripts/browser_check.cjs` | **157 项**, 真 Chromium 走「初始化 → 仪表盘」全流程 + 交互 + CSP + 截图 |
| `scripts/clients_check.cjs` | 真实浏览器点客户端开关 |
| `scripts/router_ui_check.cjs` | **62 项**。路由器本地界面 (含「没有更新记录时不许凭空长出进度面板」这类判据, 以及性能模式那块表盘: 真实浏览器里点一次, 看刻度/进度/表针/出口/熄火) |
| `scripts/geo_slow_check.cjs` | 长任务前端行为 (默认约 3 分钟的真下载) |
| `scripts/upgrade_sim.sh` | 真跑 `upgrade.sh` (桩掉 root/systemd), 覆盖成功与回滚两条路径 |
| `scripts/build-agent.sh` | 构建 `zpcore` 并注入版本号到 `client/agent/dist/` |

（各脚本的用例数以脚本自身运行输出为准; 上面标数字的是已核对的。）

---

## 16. 已知技术债 / 待办

* **超长单文件**: `routes.py` (3293 行) / `router-install.sh` (~4 220 行) / `scripts/browser_check.cjs` (~82 KB)。
  注释密度很高、内部有分区, 但单文件到这个体量, 后续定位成本会持续上升。
* **文档重叠**: README (逐版日志) 与本文、`docs/` 三份之间有信息重叠; README 面向历史, 本文面向现状,
  长期需要保持本文随代码更新 (否则又会退回「过期快照」)。
* **eBPF 数据面 (性能模式)**: 已实现 (L0 = dae, 见 §11 那条), 仍然是**用户按需开启**的一档 ——
  它与 tun/tproxy 互斥、开着时没有第二个数据面兜底, 所以默认不动它。真机上还没有验过
  (dae 真的加载 eBPF / 出口验证 / 回退后的连通性), 这一点写在 README 8.78 的最后一段。
* **真机回归**: 自动化能覆盖的都覆盖了, 但「每种固件一台真机」仍然只能人工做 (见 `docs/ROUTER-CLIENT-REDESIGN.md` Phase 5)。
