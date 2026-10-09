# ZeroProxy 路由器客户端 · 重设计方案

> 调研时间: **2026-10-08** · 方法: GitHub API 实测取数 + 上游源码/官方文档逐条核对 + 本项目七次真机记录复盘
> 结论先行: 现有客户端**架构方向是对的** (面板下发 + 设备回报 + 内核与 agent 分离), 但它把两件事
> 混在了一起 —— **"这台机器支持什么"** 和 **"我们现在怎么用它"**。于是每遇到一种新固件就补一个
> 分支, 补到第七次真机时, 客户端已经是一个 2045 行的 shell。本方案要做的不是再补一个分支, 而是
> 把"支持"从布尔值改造成**能力协商**, 把"生效"从"命令跑成功"改造成**端到端验证**。

---

## 0. 执行状态 (2026-10-09 更新)

| 阶段 | 状态 | 落在哪 |
|---|---|---|
| **Phase 1** 数据面阶梯 + 诚实状态 | ✅ 已实现 | 五级阶梯 (ebpf 只探不选 → tun → tproxy → **iptables REDIRECT** → 不接管)、`caps` v2 (`chosen`/`covered`/`why.*`)、按现场验证 + 自动降级、`desired × actual × covered` 三元显示 —— 见 README 8.46 |
| **Phase 2** 控制面 zpcore + 本地自治 | ✅ 已实现 | `client/agent/` (Go, 自带 HTTP 服务 + 令牌校验 + 只绑 LAN, 接口契约与原 cgi 一致)、面板分发 (`.gz`, 与内核同一条路)、**面板不可达时的本机覆盖**、**`revert` 与装机前快照逐条比对** —— 见 README 8.47 / 8.48 |
| **Phase 3** IPv6 + 性能 | 🟡 大部分完成 | **IPv6 已接管** (数据面 v6 规则 + 能力探测 + 能接管才给双栈、接不了如实标注); **MTU 按 WAN 实算** (PPPoE 不再出超包)、**转发卸载探测** (它会绕过 netfilter 让 tproxy/redirect 静默失效)、**`zp bench` 内建基准** (直连 vs 经代理, 结果回报面板)、**缺 BTF 自动补齐** (README 8.77: 装上匹配内核的 detached BTF, 这一档的前提从此有确定答案) —— 见 README 8.48 / 8.57; 只剩 **eBPF (dae) 数据面本身**: 刻意不做 (换内核 = 另一套配置语言与 geo 格式), 现在由 `doctor` 报出这一档的可用性 |
| **Phase 4** 抗封锁与协议透传 | ✅ 对账完成 | 指纹 / UDP / 端口跳跃**已经做了**; AnyTLS / Finalmask / ECH **不适用** (面板不生成那几种节点, "透传"没有来源); spec 化 + 本地重渲染与 shell 侧 mixin **不做** (路由器上没有渲染器, shell 拼 YAML 正是这两年一直在删的那类代码) —— 逐项对账见 README 8.49 |
| **Phase 5** 兼容矩阵真机回归 | 🟡 能自动化的都自动化了 | 四类机器的安装/开关/覆盖/revert/本地界面都进了 `router_install_check.py` (94 项); **真机 (每种固件一台)** 仍然只有你能做 |

> 另外补上了设计里没写、但实现中暴露出来的一个验证缺口: 路由器端整机配置现在也过**真 mihomo**
> (四档数据面 × IPv6 共 8 种组合), 见 README 8.49。在这之前它只被演练里的桩内核放行。

> 本文档保留为**设计依据**: 为什么这么改、每一步对应哪次真机教训, 都在下面。
> 实现细节与逐条回归见 README 的 8.46 / 8.47 / 8.48。

---

## 目录

1. [调研: 同类项目全景](#1-调研-同类项目全景)
2. [从每个项目学到的一条](#2-从每个项目学到的一条)
3. [现状诊断: 七个真机问题的共同根因](#3-现状诊断-七个真机问题的共同根因)
4. [设计原则](#4-设计原则)
5. [目标架构](#5-目标架构)
6. [数据面: 五级能力阶梯](#6-数据面-五级能力阶梯)
7. [控制面: 常驻 agent + 本地自治 UI](#7-控制面-常驻-agent--本地自治-ui)
8. [配置模型](#8-配置模型)
9. [DNS 与 IPv6](#9-dns-与-ipv6)
10. [性能: 把每一分算力用在正确的地方](#10-性能-把每一分算力用在正确的地方)
11. [抗封锁: 路由器端要负责的那一半](#11-抗封锁-路由器端要负责的那一半)
12. [兼容性矩阵](#12-兼容性矩阵)
13. [易用性与"永不撒谎"](#13-易用性与永不撒谎)
14. [自愈与可观测](#14-自愈与可观测)
15. [安全模型](#15-安全模型)
16. [交付路线图](#16-交付路线图)
17. [与现有实现的迁移](#17-与现有实现的迁移)
18. [附录: 取数明细](#18-附录-取数明细)

---

## 1. 调研: 同类项目全景

取数口径: 星标 / 活跃度来自 GitHub REST API `/repos/{owner}/{repo}` 实时返回 (2026-10-08), 非二手转述。

### 1.1 路由器端"整机接管"类 (与本项目正面竞争的形态)

| 项目 | ★ | 内核 | 数据面 | 前提 | 定位 |
|---|---:|---|---|---|---|
| [vernesong/OpenClash](https://github.com/vernesong/OpenClash) | 27,721 | Clash / mihomo | redirect / tproxy / tun | LuCI + 大 ROM | Clash 系事实标准, 但臃肿、维护放缓 |
| [juewuy/ShellCrash](https://github.com/juewuy/ShellCrash) | 13,566 | mihomo / sing-box / xray | 自建 iptables / nft / tun | 只要 shell + root | **无 LuCI 也能跑**, 兼容面最广, 但全手动 |
| [Openwrt-Passwall/openwrt-passwall](https://github.com/Openwrt-Passwall/openwrt-passwall) | 9,948 | Xray / sing-box | tproxy / tun | LuCI + 依赖链重 | 功能最全, 完整安装 >50 MB |
| [nikkinikki-org/OpenWrt-nikki](https://github.com/nikkinikki-org/OpenWrt-nikki) | 5,337 | mihomo | Redirect / TPROXY / TUN | **OpenWrt ≥24.10 + 内核 ≥5.13 + firewall4** | 现代化 Mihomo 前端, OpenClash 的继任者 |
| [Openwrt-Passwall/openwrt-passwall2](https://github.com/Openwrt-Passwall/openwrt-passwall2) | 3,662 | Xray | tproxy | LuCI, ROM 紧张 | passwall 的轻量分支 |
| [immortalwrt/homeproxy](https://github.com/immortalwrt/homeproxy) | 1,088 | sing-box | tproxy / tun | 仅 ARM64 / AMD64 | 官方源直装, 配置逻辑最清晰 |

### 1.2 内核 / 协议侧 (决定路由器端能跑出什么)

| 项目 | ★ | 说明 |
|---|---:|---|
| [XTLS/Xray-core](https://github.com/XTLS/Xray-core) | 42,000 | Reality / XHTTP / **Finalmask** / ECH 的发源地, v26.3.27 新增 header-custom / Sudoku / fragment |
| [SagerNet/sing-box](https://github.com/SagerNet/sing-box) | 38,672 | 出站协议最全, 1.14.2 (2026-09-24), WireGuard endpoint / rule_set |
| [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) | 34,728 | Clash.Meta, 本项目使用的内核, 最新 v1.19.32 (2026-09-30) |
| [HyNetworks/hysteria](https://github.com/HyNetworks/hysteria) | 22,628 | QUIC + Brutal + 端口跳跃, 弱网吞吐最强 |
| [daeuniverse/dae](https://github.com/daeuniverse/dae) | 6,297 | **eBPF 数据面**, 直连流量真旁路, 性能天花板 |
| [daeuniverse/daed](https://github.com/daeuniverse/daed) | 2,062 | dae 的 Web 面板, 有 OpenWrt 25.12 打包版 |

### 1.3 三个关键前提条件 (2026-10 现状)

* **OpenWrt 25.12 已是当前稳定版**, 内核 6.12.74, 包管理器从 `opkg` 换成 **`apk`**;
  **24.10 的 EOL 是 2026-09** —— 也就是说本项目"24.10 及更早用 opkg"的措辞已经过期, 现在是
  "25.12 用 apk, 24.10 及更早用 opkg", 且 24.10 用户应当被**主动提示升级**。
  客户端这一侧已落地 (README 8.76): 判据取"固件世代 + 实际命令"两条 (厂商固件报 25.x 却只有
  opkg 的迁移态也走对), apk 用 `-U` 一条命令、只在签名类错误上退 `--allow-untrusted`;
  两个 kmod 在 25.12 官方镜像里**都不预装**, 且来自与内核版本绑定的源 —— 装不上时输出里
  会说明是哪一种原因, 24.10 则在装机预检时就提示升级。
  ([release notes](https://openwrt.org/releases/25.12/notes-25.12.0), [announce](https://lists.openwrt.org/pipermail/openwrt-announce/2026-March/000081.html))
* **Nikki 把门槛写死成 `OpenWrt ≥24.10 + 内核 ≥5.13 + firewall4`** —— 它放弃兼容, 换取实现干净。
  这是"现代方案"的代价: 原厂 GL.iNet (21.02 / 内核 5.4) 这类机器直接不在支持范围。
* **dae 绑定 LAN 要求内核 ≥5.17 + 一整套 `CONFIG_BPF_*` / BTF**, 且 OpenWrt 默认精简内核往往关掉。
  **BTF 这一条已有自动解法** (README 8.77): 缺 BTF 时装一份匹配内核的 detached BTF
  (`/usr/lib/debug/boot/vmlinux-<内核版本>`, cilium/ebpf 与 libbpf 会自动回退到那里),
  客户端检测到就自动补 —— 于是"这一档到底能不能用"变成一个有确定答案的探测, 而不是看固件脸色。
  ([dae docs](https://github.com/daeuniverse/dae/blob/main/docs/en/README.md)) —— eBPF 是"性能上限",
  不是"通用数据面": 它只能作为**可选的高性能档**, 不能作为默认。

---

## 2. 从每个项目学到的一条

| 项目 | 学到的那条 |
|---|---|
| **Nikki** | 把前提条件写死、把选择权交给用户, 实现就能干净。**但**我们比它多一个约束: 面板已经承诺"一条命令装完", 所以前提不能"拒绝", 只能"降级"。 |
| **homeproxy** | 窄架构 + 官方源 = 稳定; 但 21.02/5.4 的老机器被排除在外。我们要的是"同一套逻辑覆盖它"。 |
| **ShellCrash** | 无 LuCI 也能跑, 兼容面最广 —— **它的兼容性来自自建数据面 (iptables/nft/手写 tun), 而不是来自固件**。这正是我们缺的那一层。 |
| **OpenClash** | 功能堆到极致后, 依赖链和 ROM 占用就成了它自己的敌人 (完整安装 >50 MB)。我们不能再走这条路。 |
| **dae / daed** | 数据面选型带来的性能差距是**量级**的, 但前提同样苛刻。结论: eBPF 做成"探测到就给, 探测不到不假装"。 |
| **Xray 26.3.27** | 抗封锁的前沿已经移到 **Finalmask (自定义流量外观) + ECH + uTLS 指纹**。路由器端要做的不是实现它们, 而是**原样透传**这些参数, 并在嗅探/分流上不漏。 |
| **mihomo issue #2584 / #1866** | **tun + auto-route 在 OpenWrt 网关模式下会打断局域网 UDP 转发** (除路由器自身外, 局域网的 UDP 全挂)。这是一个真实的、上游尚未默认修复的坑 —— 任何"无脑用 tun 接管全屋"的方案都必须显式处理它。 |

---

## 3. 现状诊断: 七个真机问题的共同根因

把 README 8.23 → 8.45 的七次真机记录摊开, 每一个"现象"都能映射到一个**结构性缺陷**:

| 真机现象 (README 章节) | 直接原因 | 结构缺陷 |
|---|---|---|
| 8.25 `od: not found` | busybox 没有 od | 用宿主工具做饭, 而不是问内核要答案 |
| 8.26 403 / 凭据已作废 | 本地看不出服务端有效性 | 本地状态与服务端状态没有显式同步协议 |
| 8.29 TUN 没建起来 / LuCI 菜单不出现 / 403 | 节点在 ≠ 内核能建设备; 菜单索引有缓存 | **能力 ≠ 存在** (布尔化的"支持") |
| 8.32 界面卡在"未登录 LuCI" | GL.iNet 后台不是 LuCI | 把"整机接管"押在固件的 Web 服务器上 |
| 8.41 装到"下载内核"不动 | 面板侧没有总时限 | 分布式流程缺一个端到端的时间契约 |
| 8.44 原厂固件 `kmod-nft-tproxy` 装不上 / cgi 被当静态文件发 | 固件源与自编内核不匹配 | 把"包能装上"当成"能力存在" |
| 8.45 "全屋代理已开启"但一台设备都没被接管 | tun 与 tproxy 都失败, 结尾仍报成功 | **没有任何一环验证"流量真的过去了"** |

三条根因, 归成一句话:

> **客户端把"这台机器支持什么"当成编译期常量, 把"生效没生效"当成命令返回值。**

于是每遇到一种新固件就补一个分支; 分支越多, 越没人敢保证任一分支真的对。

---

## 4. 设计原则

新的客户端围绕六条原则重建, 后面每一节都是它们的推论。

1. **能力协商, 不是版本假设。**
   不问"你是 OpenWrt 几点几", 只问"这条规则你现在加得上吗" —— 探测只做**副作用可撤销**的真实动作
   (建一个设备再删、加一条规则再撤), 结果写进 `caps`, 全链路共用同一份。

2. **闭环验证, 永不撒谎。**
   任何"已开启"必须由**一次真实的局域网侧端到端流量**证明。证不出来就说"未生效", 并给出**它自己**
   报出的失败原因 (`logread` 里内核原话), 而不是一句猜测。

3. **可逆。**
   停掉内核 / 卸载 = 网络逐字节回到原样。不写死 dnsmasq、不写死 `/etc/config/network`、
   nft/iptables 规则只增删自己那张表 (以固定前缀命名, 便于整体回收)。

4. **单一真相源 + 本地自治。**
   面板是策略的真相源, **路由器是状态的真相源**, 两者靠显式的期望/实际协议对齐。
   面板不可达时路由器必须维持可用, 并且**本地就能查看与操作** (不依赖面板、不依赖固件 Web 服务)。

5. **少写 shell, 多写可测逻辑。**
   shell 只做"引导" (下载、落盘、起服务); 有状态、要重试、要解析、要原子写的部分交给静态二进制。

6. **默认安全。**
   只在 LAN 监听; 凭据 0600 且只存 sha256; 分发包带签名与哈希; 内核版本固定不跟最新。

---

## 5. 目标架构

```
                        ┌────────────────────────── 面板 (服务器侧) ──────────────────────────┐
                        │  策略真相源: 节点/链路/分流模板/开关                                 │
                        │  spec 渲染 (版本化 JSON + mihomo YAML)                              │
                        │  制品分发: zpcore(agent) / mihomo / geo  (签名 + 哈希)              │
                        └───────────────▲──────────────────────────┬──────────────────────────┘
                      期望/实际 (HTTPS, 设备凭据)                     │ 引导命令 (一次性配对码)
                                        │                            ▼
   ┌────────────────────────────────────┴───────────────────────────────────────────────────┐
   │                            路由器: 两层                                              │
   │                                                                                       │
   │  ① 引导层  bootstrap.sh (一次性, ~300 行, 只依赖 busybox)                             │
   │     探测环境 → 取 zpcore → 交给它 → 自己退出 (失败也把话说清楚)                       │
   │                                                                                       │
   │  ② 常驻层  zpcore (静态 Go, 每架构一个 ~4-6 MB)                                       │
   │     ┌────────────┬────────────┬────────────┬────────────┬────────────┐               │
   │     │ 能力探测   │ 数据面管理 │ 配置获取   │ 看门狗     │ 本地 UI    │               │
   │     │ caps.json  │ 阶梯+验证  │ 原子+回滚  │ 自愈       │ + CLI      │               │
   │     └────────────┴────────────┴────────────┴────────────┴────────────┘               │
   │                                    │                                                  │
   │                                    ▼                                                  │
   │  ③ 内核层  mihomo (固定版本, 面板分发)  ·  可选: dae (性能模式)                        │
   └───────────────────────────────────────────────────────────────────────────────────────┘
```

三层的边界刻意划在"谁最容易出问题"上:

* **引导层越小越好** —— 它运行的时机最糟 (路由器还没有代理、可能没有可用工具), 所以它只做三件事:
  探测架构、取一份 `zpcore`、把控制权交出去。所有"聪明"的逻辑都不在这里。
* **常驻层用静态二进制** —— 因为 shell 在 busybox 上的三个真实教训 (`od` 缺失、BSD `sed` 不认 `\?`、
  `awk -v` 遇换行报错) 都是"语言/工具不可移植", 而不是"逻辑难"。换一个没有这些坑的运行时就消失了。
* **内核层保持单一版本** —— mihomo 的字段废弃会在用户家里以"全屋断网"的形式暴露, 固定版本 + 显式升级
  这条既有决定是对的, 保留。

---

## 6. 数据面: 五级能力阶梯

这是整个重设计的核心。**不再有"tun 优先, tproxy 回退"两条路, 而是一张有序阶梯**; 每一级都要有四个
动作 (探测 / 应用 / 验证 / 拆卸), 四个都成功才算这一级可用。装机时从 L0 往下试, 第一级通过验证的就用;
全都不通过时, 落到 L4 并**明确说"未接管"**。

| 级 | 名称 | 需要的条件 | 覆盖范围 | 性能 | 备注 |
|---|---|---|---|---|---|
| **L0** | `ebpf` | 内核 ≥5.17 + `CONFIG_BPF_*` + BTF + `tc` | 全屋 + 本机, 直连真旁路 | ★★★★★ | 可选"性能模式", 用 dae; 探测不到就跳过 |
| **L1** | `tun` | `kmod-tun` + `ip tuntap` 真能建设备 | 全屋 + 本机, 内核接管路由与 DNS | ★★★★ | 首选; **但必须处理 LAN UDP 坑 (见 6.2)** |
| **L2** | `tproxy` | `nft` 命令 + 内核里真有 `nf_tables` + `nft_tproxy` | 全屋 (不含路由器自身) | ★★★ | 现代 OpenWrt 的默认回退 |
| **L3** | `redirect` | `iptables` + `nat` 表 + `REDIRECT` | 全屋 TCP (不含 UDP) | ★★ | **新增**: 21.02 / 内核 5.4 / fw3 固件唯一可用的路 |
| **L4** | `manual` | `mixed-port` 能监听 | 只有显式配置了代理的设备 | ★ | 不做透明接管, 但**功能可用、状态诚实** |

### 6.1 探测 (`caps.json`)

探测的产物是一份结构化能力清单, **一次探测, 全链路复用** (安装脚本、agent、内核 init、CLI、面板都读它):

```json
{
  "schema": 2,
  "probed_at": 1791500000,
  "system": {
    "os": "openwrt", "release": "21.02-SNAPSHOT", "vendor": "glinet",
    "kernel": "5.4.281", "pkgmgr": "opkg", "init": "procd",
    "arch": "arm64", "lan_ip": "192.168.8.1", "free_mb": 412
  },
  "datapath": {
    "ebpf":     {"ok": false, "why": "kernel 5.4 < 5.17 / 无 BTF"},
    "tun":      {"ok": false, "why": "ip tuntap add 失败: Operation not supported"},
    "tproxy":   {"ok": false, "why": "nft add rule ... tproxy 失败: No such file or directory"},
    "redirect": {"ok": true,  "why": "iptables -t nat 探针成功"}
  },
  "chosen": "redirect",
  "covered": "lan_tcp",
  "notes": ["本机为原厂固件: nf_tables 未编入内核", "tun 节点存在但建不出设备"]
}
```

要点:

* `why` 必须是**内核/程序的原话**, 不是转述。8.45 的教训就是"只有一句未出现, 只能靠截图猜"。
* `chosen` 与 `covered` 分开: 选了 `redirect` 时 `covered` 就是 `lan_tcp` —— 面板与 UI 要用这个显示
  "谁被接管了", 而不是笼统的"已开启"。
* 探测**只做可撤销的动作**: `ip tuntap add / del`、`nft add table / delete table`、
  `iptables -N zp_probe / -X zp_probe`。不落任何持久规则。
* 探测结果**带有效期**: mihomo/固件升级、重启、`fw4 reload` 之后重探。旧结果不能当永久事实。

### 6.2 每一级的"验证"必须是真的端到端

这是"永不撒谎"原则的落地点。**验证不是"规则加上了", 是"流量过去了"**:

| 级 | 验证方式 | 判定 |
|---|---|---|
| L0/L1/L2/L3 | 在**路由器自己**上做一次受控出网 (用一个只回显出口 IP 的探针域名, 经代理端口), 再看本地规则的**命中计数是否增长** | 出口 IP == 面板记录的落地 IP |
| L1 tun | `ip route show table all` 里出现内核路由表; `ip rule` 出现 tun 的规则; `/dev/` 上真的有设备; 且 LAN UDP 探针能通 | 四项都过 |
| L2 tproxy | `nft list table inet zp_router` 有条目; 且 `nft` 计数器在流量经过后**增长** | 计数增长 |
| L3 redirect | `iptables -t nat -L zp_router -v` 命中计数增长 | 计数增长 |

**关于 LAN UDP (mihomo #2584)**: tun + `auto-route` 作为网关时, 局域网设备的 UDP 会被误路由到内核而
丢包。方案是:

1. 装机时跑一次 **UDP 探针** (局域网侧发一个 UDP 包到已知回显服务);
2. 探针失败 → 不放弃 tun, 而是**自动补两条 `ip rule` 豁免 UDP** (`ip rule add prio 8000 ipproto udp goto 9010`,
   v4/v6 各一条), 再验一次;
3. 仍失败 → 降级到 L2, 并在 `caps.notes` 里记下"tun 因 LAN UDP 不可用被降级"。

这套顺序把上游那个坑从"用户家里全屋 UDP 挂掉"变成"装机时自动绕过"。

### 6.3 拆卸 = 一键回到原样

每一级都实现 `teardown`, 且只能回收**自己那张表 / 那几条 rule**:

* nft: `nft delete table inet zp_router` (只此一张, 前缀固定);
* iptables: `iptables -t nat -D ...` 精确删除, 或 `iptables -t nat -F zp_router && -X zp_router`;
* ip rule: 按 `prio` 精确删, 不用 `flush` 一刀切;
* tun: 进程退出即回收 (`auto-route` 的规则随内核退出消失);
* dnsmasq: **从不写入**, 只在开关时 `HUP` 一次让它丢掉缓存。

验收标准: 执行 `zp revert` 后, `iptables-save` / `nft list ruleset` / `ip rule` / `ip -6 rule`
与装机前**逐字节一致** (回归测试用真实快照对比)。

---

## 7. 控制面: 常驻 agent + 本地自治 UI

### 7.1 为什么是 Go 静态二进制

| 现有 shell 的痛点 | 换静态二进制的收益 |
|---|---|
| 三个真机 bug 都源于 busybox 工具差异 (`od` / `sed` / `awk`) | 同一份 ELF 在每台机器上行为一致 |
| JSON 解析靠 `sed` 正则, 已出过"边界布尔读空"的静默错误 | 真正的 JSON 解析 + 单元测试 |
| 原子写、重试、超时、并发都要手搓 | 标准库直接给 |
| 每加一个固件分支就是几十行 shell, 无法单测 | 逻辑可单测, 平台差异收敛到少量适配函数 |
| 热更新只能替换整个脚本 | 版本化二进制 + 本地回滚, 哈希校验 |

代价是面板要多分发一个每架构 4–6 MB 的二进制、CI 要多一条构建链。**这个代价与已有的 mihomo 分发
完全同构** (同一个下载器、同一套镜像、同一个缓存目录), 所以增量很小。

> 备选: 若坚持不引入 Go, 则退一步 —— 保留 shell, 但**必须**把阶梯探测/验证/拆卸写成独立的
> `zp-probe` / `zp-apply` / `zp-verify` 三个脚本并各自单测。设计原则不变, 只是"可测性"的提升小一截。

### 7.2 职责清单

`zpcore` 常驻, 一个进程, 五个内部模块 (独立 goroutine, 各自可单测):

1. **能力探测**: 产出/刷新 `caps.json` (6.1)。
2. **数据面管理**: 按阶梯应用/验证/拆卸 (第 6 节), 维护 `ip rule` / nft / iptables / tun 生命周期。
3. **配置同步**: 向每一台面板要 `spec`, 本地渲染 mihomo YAML, 原子替换 + `mihomo -t` 校验 + 失败回滚 (沿用现有机制)。
4. **看门狗**: 检测"数据面被外力破坏" (fw4 reload 清了规则、内核被 OOM 杀、开机后规则没恢复) 并自动重建。
5. **本地 UI + CLI**: 见 7.3。

### 7.3 本地自治 UI (本次最大的易用性改动)

现状: 路由器界面**寄生于固件的 Web 服务器** (先试 nginx/uhttpd + `/cgi-bin/`, 不行再自带 busybox httpd),
鉴权寄生 LuCI 或令牌 —— 三种固件三种走法, 8.32/8.30/8.44 三次真机都卡在这里。

新方案: **`zpcore` 自己起一个 HTTP 服务**, 不依赖固件任何 Web 组件:

* 监听**固定的 LAN 地址** `http://<lan-ip>:8399/` (端口可配; 找不到 LAN 地址就不启动, 绝不退化成 `0.0.0.0`);
* 鉴权只认**设备令牌** (安装时生成, `0600`), 也接受 `?k=` 一次性入口; 不再尝试 LuCI 会话;
* 页面自带, 离线可用: 状态 / 模式 (显示 `caps.chosen` 与 `covered`) / 总开关 / 服务器列表 / 节点与延迟 /
  实时连接数 / 日志 / **自检与自愈按钮** / `zp` 命令提示;
* 与面板**功能对齐**: 面板能做的, 本地也能做 (面板挂了也能自救); 面板不在时改动进"本地覆盖"层,
  面板回来后以面板为准 (可配);
* 同时保留 **UCI 配置 + LuCI 插件**作为可选集成 (给喜欢 LuCI 的用户), 但**不再是唯一入口**。

这样一来, "界面能不能打开"与"这台固件是什么"彻底解耦 —— 8.30 / 8.32 / 8.44 那一整类问题不再存在。

### 7.4 CLI 契约 (稳定、可脚本化)

```
zp status [--json]        # 机器可读的完整状态 (含 caps / datapath / covered / 失败原因)
zp probe [--json]         # 重新探测能力 (用于排障)
zp on | off               # 开关
zp add <链接> | drop <键> | servers | refresh
zp doctor                 # 逐项自检 + 每条失败的具体判决与下一步命令
zp revert                 # 回到装机前状态 (逐字节校验)
zp log [-f]               # 结构化日志
zp ui                     # 打印本地界面地址 (带一次性令牌)
```

所有命令都支持 `--json`, 于是面板、CI、回归脚本共用同一份输出。

---

## 8. 配置模型

### 8.1 面板下发的是"规格", 不只是 YAML

现状: 面板直接渲染一份 mihomo YAML 给路由器。问题: 一旦面板不可达 (域名被封、面板宕机), 路由器
既拿不到新配置, 也不知道"当前这份是什么策略"。

新方案: 面板下发**两层**:

1. **spec (版本化 JSON)**: `{schema, rev, policy{preset, landing, ads}, datapath_hints, dns{...}, nodes[] | providers[], landing_ip, health_url}` ——
   一份与内核无关、可读、可缓存的策略描述;
2. **渲染结果 (mihomo YAML)**: 面板渲染好的最终配置, 用于"不信任本地渲染"的场景。

路由器侧缓存 spec (最近 N 版), 于是: 面板不可达时仍能本地重渲染 (例如内核升级后字段需要调整);
也能在面板恢复后做差异比对而不是整份覆盖。

### 8.2 本地覆盖层 (mixin)

借鉴 Nikki 的 Profile Mixin: 允许本地对最终配置做**声明式覆盖** (`/etc/zeroproxy/mixin.yaml`),
但只允许白名单字段 (日志级别 / DNS 上游 / 额外直连域名 / MTU / 额外规则), 不允许改凭据与开关语义。
面板 UI 里也能编辑这一层 (通过本地 API), 于是"高级用户想微调"不需要手改下发文件。

### 8.3 统一单/多服务器

现状有两条路径: 单服务器 (内联节点) 与多服务器 (`proxy-providers`)。**统一为 providers**: 单服务器
就是"一个 provider"。收益是少一条分支、少一类回归 (README 里那条"单/多两次代码路径都出过 bug"),
且天然支持"再加一台不用重装"。

---

## 9. DNS 与 IPv6

### 9.1 DNS

现有决定里有两处是对的、要保留: **fake-ip + dns-hijack** 与 **不给国外域名配 DoH** (8.33 的教训:
首屏慢是因为每个新域名都往节点上绕一次 DoH)。要补的是**泄漏面与 IPv6**:

* 给局域网设备下发 DNS 的路径要**唯一** (要么全走 hijack, 要么明确写一条 `dhcp-option` 提示),
  当前"不改 dnsmasq"是对的, 但要**验证**设备真的把 DNS 发给了路由器 (否则部分设备会走运营商 DNS),
  验证方式: hijack 计数器 + 一个解析探针;
* `nameserver-policy` 保持"只给国内/私有域名指定国内 DNS"; 但补一句 `direct-nameserver-follow-policy`
  之类的显式策略, 避免"直连域名用了代理侧 DNS"这类隐蔽拖慢;
* 提供**可选的加密上游** (DoT / DoH) 作为"路由器自身解析"的档位 —— 但要放在 `proxy-server-nameserver`
  之外的独立开关里, 默认关 (默认关的理由就是 8.33);
* DNS 缓存算法、TTL 下限、`respect-rules` 显式化, 并写进 spec (便于面板做"A/B 两套 DNS 策略")。

### 9.2 IPv6 (现状是硬编码关闭)

2026 年关掉 IPv6 会有两个后果: 一是部分 App/服务不可用, 二是**IPv6 泄漏** (设备直接走原生 v6 出去,
绕过代理)。方案:

* `ipv6: true`, 全套双栈: tun 的 `auto-route` v6、tproxy / redirect 的 v6 规则、`ip -6 rule`;
* fake-ip v6 段 (`fake-ip-range6`), 并显式处理 AAAA (避免"v6 不可达导致回落慢");
* **泄漏防护**: 若设备拿到原生 v6 地址, 必须被 `ip -6 rule` 接管或显式丢弃 (REJECT 到"未接管"提示),
  不能静默泄漏;
* 对"运营商 IPv6 质量差"的家庭, 提供 **IPv6 直连优先** 与 **IPv6 关闭** 两档, 由面板选择。

---

## 10. 性能: 把每一分算力用在正确的地方

性能的排序 (从收益最大到最小):

1. **数据面选型** —— 这是量级差。dae 的 eBPF "real direct" 让直连流量**根本不经用户态**, 对 BT / 大流量
   直连场景 (本项目目标用户的常见场景: 下载、局域网 NAS) 的收益是有/无的差别。所以:
   L0 探测通过就默认用, 探测不过就用内核原生转发 (tun system / tproxy)。
2. **协议与 CPU 的匹配** —— 路由器 CPU 弱, Hysteria2 的加密开销高于 TCP 类。客户端要在 UI 里**如实标注**
   每次握手探测的实测吞吐/延迟, 让用户知道"这台机器跑这个协议能到多少", 而不是让他在手机上猜。
3. **栈的选择** —— tun `stack: system` (已改对); 保留 `gvisor` 作为"某些固件唯一的兜底"。
4. **MTU 与 GSO/GRO** —— 现状固定 1500; PPPoE / 部分光猫要给 **PPPoE 上限 (1492/1452)**, QUIC 要给
   **≤1440**。方案: 按 WAN 类型自动选 MTU, 并把 `gso` / `gso-max-size` 纳入探测 (支持才开)。
5. **进程与调度** —— 双核 A53 上把 agent 与内核分到不同核 (可选), `nice` 内核, 避免与面板心跳争抢。
6. **避开硬件卸载冲突** —— mt7621 / mt7981 的 HNAT 流卸载与透明代理数据面经常打架 (表现为"直连快, 代理慢,
   但 CPU 不高")。方案: 探测 → 若启用 HNAT 且选 L1/L2, 提示或为代理路径加豁免。
7. **内核算力友好** —— `find-process-mode: off` (已有)、`log-level: warning` (已有)、
   `dns-cache` 用 `arc`、`tcp-concurrent` + `unified-delay` (已有), 再加 `geodata-loader: standard`
   与按需的 `rule-set` (减少每次重载的解析量)。
8. **可测量** —— 提供**内建基准测试** (`zp bench`): 路由器自己跑"直连吞吐 / 代理吞吐 / 握手延迟 / UDP 可用性",
   结果回报面板。没有实测数字的"性能优化"都是猜。

---

## 11. 抗封锁: 路由器端要负责的那一半

抗封锁是**面板节点侧 + 路由器侧**共同完成的。路由器侧要做的是"不拖后腿 + 不泄漏"。

### 11.1 协议透传: 面板出什么, 路由器就原样带什么

2026 年的前沿已经明确: **Reality (TCP 完美伪装) + Hysteria2 (UDP 物理突破) + AnyTLS (无侧信道的 TLS 承载) +
XHTTP (可叠 CDN) + Finalmask (自定义流量外观) + ECH + uTLS 指纹**。其中 Reality / Hysteria2 / XHTTP /
Trojan 本项目已有; 需要补的是:

* **AnyTLS**: mihomo 自 v1.19 起支持, 面板若输出 AnyTLS 节点, 路由器端配置必须能透传其参数
  (`idle-session-*` / `client-fingerprint` / `padding-scheme`)。它的价值在于**没有 TLS-in-TLS 侧信道泄漏**,
  是目前对"主动探测 + 流量分析"最均衡的一档 ([mihomo PR #1844](https://github.com/MetaCubeX/mihomo/pull/1844))。
* **Xray 26 的 Finalmask / ECH**: 这些是**服务端/节点参数**, 路由器端必须确保客户端的 `uTLS`
  指纹与节点期望一致 (`global-client-fingerprint`), 且嗅探不破坏 ECH (ECH 下 SNI 被加密, 嗅探拿不到域名 →
  规则要能退化成按 IP/握手信息分流, 不能让流量卡在"等一个永远不来的 SNI")。
* **端口跳跃**: Hysteria2 的 `udphop` 写法要逐节点透传 (项目已做), 并在 UI 里标出"这个节点支持端口跳跃"。

### 11.2 不泄漏

抗封锁的一大半失败来自泄漏, 而不是协议被破:

* DNS 泄漏 → 9.1 的验证;
* IPv6 泄漏 → 9.2 的强制接管或显式丢弃;
* **STUN / WebRTC** 泄漏真实 IP → `fake-ip-filter` 里对 STUN/TURN 域名给真实 IP (已有), 但要让"应走代理的
  STUN"也走代理 (现在是被直连, 反而泄漏);
* NTP / 时间同步 → 已有过滤器, 保留;
* 路由器自身的流量 (tproxy 模式下不被接管) → L2 的 `covered` 必须如实显示, 面板据此提示。

### 11.3 控制链路 (面板 ↔ 路由器) 的抗封锁

安装/更新通道是这个项目**最脆弱的一环** (装机时路由器没有任何代理)。现有做法 (面板分发内核 + 镜像)
是对的, 要补:

* **多域名多通道 + 顺序 + 速率闸门** 已具备, 把"面板地址"本身也做成可轮换 (面板侧提供备用域名/IP);
* **断联自治** 已具备 (面板不可达保持现状), 补一条: 长期断联时用本地 spec 重渲染, 并允许本地开关;
* **订阅变更的幂等与回滚**: 任何下发都先本地校验 + 备份上一份, 失败自动回滚 (已有, 保持并推广到 spec 层)。

---

## 12. 兼容性矩阵

目标: **从 OpenWrt 19.07 一直到 25.12, 以及原厂 GL.iNet / Padavan / Merlin / x86 软路由 / 容器**。

| 固件 / 系统 | 内核 | 包管理 | init | 可用数据面 | UI 路径 | 备注 |
|---|---|---|---|---|---|---|
| OpenWrt 25.12 | 6.12 | apk | procd | L0/L1/L2 | 本地 UI + LuCI | 默认目标; kmod 不预装, 由 `apk` 从**与内核版本绑定**的源装 |
| OpenWrt 24.10 | 6.6 | opkg | procd | L0(部分)/L1/L2 | 本地 UI + LuCI | **EOL, 装机时主动提示升级** |
| OpenWrt 23.05 | 5.15 | opkg | procd | L1/L2 | 本地 UI + LuCI | |
| OpenWrt 22.03 | 5.10 | opkg | procd | L1/L2 | 本地 UI + LuCI | firewall4 起点 |
| OpenWrt 21.02 | 5.4 | opkg | procd | **L3/L4** | 本地 UI | fw3 + iptables, 无 nf_tables |
| OpenWrt 19.07 | 4.14 | opkg | procd | **L3/L4** | 本地 UI | shell 兼容性最差, 靠静态二进制兜住 |
| GL.iNet 原厂 (21.02-SNAPSHOT) | 5.4 | opkg | procd | **L3/L4** | 本地 UI (自有端口) | 无 LuCI、无 nf_tables、kmod 与内核不匹配 |
| ImmortalWrt | 5.4–6.12 | opkg/apk | procd | 按内核 | 本地 UI + LuCI | |
| Padavan | 3.x–4.x | 自有 | 自有 | L3/L4 | 本地 UI | 无 procd, 用 init.d 兜底 |
| ASUS Merlin / Koolshare | 4.x | 自有 | 自有 | L3/L4 | 本地 UI | 依赖 entware, 可选 |
| x86 软路由 (Debian/Ubuntu/OpenWrt) | ≥5.15 | apt/apk | systemd/procd | L0–L4 | 本地 UI | 性能模式首选 |
| Docker / LXC | ≥6.1 | — | — | L1/L2 | 本地 UI | 需要 NET_ADMIN + /dev/net/tun |

架构矩阵 (mihomo 与 zpcore 各一份, 面板分发): `arm64` / `armv7` / `armv6` / `mips` / `mipsle` /
`mips64` / `mips64le` / `amd64`。**mips/mipsle 必须用 softfloat 构建**, armv6 必须有独立构建 —— 这两条
现有代码已经踩过, 保留。

---

## 13. 易用性与"永不撒谎"

### 13.1 装机流程 (目标: 一条命令, 然后全程面板/本地 UI)

```
面板点击生成 → 复制一行 → 路由器终端粘贴 → 结束
```

命令行之外的一切都在 UI 里。**装机过程本身要可恢复**:

* 断点续跑: `bootstrap.sh` 可重复执行, 已下载的制品跳过, 半截文件清掉 (已有);
* 失败必须**说出下一步**: 不再出现"卡住"这种状态, 每一步都有超时与明确结论 (已有总时限, 保留);
* 装机失败时**不留残留**: 起不来的服务收掉、写不进的文件删掉、探测用的规则撤掉。

### 13.2 状态显示 (诚实是最高优先级)

面板与本地 UI 都遵守同一条:**显示的是 `desired × actual × covered` 三元组**, 而不是一个开关颜色。

| desired | actual | covered | 显示 |
|---|---|---|---|
| on | on | full (L0/L1) | 已连接 (全屋 + 本机) |
| on | on | lan_tcp (L3) | **已连接 (仅局域网 TCP)** |
| on | on | none (L4) | **未接管** —— 只有显式配置代理的设备可用 |
| on | off | — | 同步中 / 失败 (带 `caps.why`) |
| off | off | — | 已关闭 |

### 13.3 排障与恢复

* `zp doctor`: 逐项自检, 每项给"判决 + 原始证据 + 下一步命令";
* **安全模式**: 若启用后检测到"局域网整体不可用" (连续 N 次外网探针失败 + 用户设备 ARP 掉落),
  自动降级或关掉, 并在 UI 里说明"我们做了什么、怎么恢复";
* **一键回滚**: 配置回滚 (已有) + 数据面回滚 + 内核版本回滚 (多留一版 mihomo);
* 所有失败路径都要能在**没有外网**的情况下完成 (这是路由器最容易处于的状态)。

---

## 14. 自愈与可观测

现状: 只有 procd `respawn` 与开机 `ExecStartPre` 兜底。要补三层:

1. **进程级** (已有): procd respawn + agent 独立服务。
2. **数据面级** (新): 看门狗每 30–60s 校验"路由规则 / nft 表 / tun 设备 / DNS 劫持"是否还在 ——
   `fw4 reload`、网卡重连、内核重载都会把它们清掉, 而现在没有任何东西会把它们加回来。
3. **策略级** (新): 节点健康 (url-test / fallback) 由内核负责; 面板侧补"整机健康": CPU / 内存 / 闪存 /
   温度 / 连接数 / 数据面模式 / 最近错误。**面板要能回答"这台路由器现在为什么慢/断"**, 而不是只能看"在线/离线"。

日志走**结构化** (JSON 行), 面板采集最近 N 条, 按 `datapath` / `config` / `panel` / `dns` 分频道。

---

## 15. 安全模型

| 面 | 现状 | 重设计 |
|---|---|---|
| 凭据 | 设备专属 (面板只存 sha256), 一次性配对码 | 保留; 增加**轮换** (面板可让某设备换凭据而不重装) |
| 本地 UI | 令牌 + LuCI 会话, 走固件 Web 服务器 | 自有端口 + 令牌, **只绑 LAN**; 令牌可轮换 |
| 分发包 | 面板直连 + sha256 | 增加**签名** (面板私钥), 路由器校验后才落盘; 内核版本固定 + 哈希 |
| 端口暴露 | `external-controller` 绑 127.0.0.1 (好) | 保留; 本地 UI 与控制器分离, 控制器永不外露 |
| 配置机密 | `state.json` 0600 | 保留; 路由器端凭据 0600, 内存中不落明文日志 |
| 卸载 | `uninstall.sh` | 与装机对称的 `zp revert` + `uninstall.sh`, 证明"逐字节还原" |

---

## 16. 交付路线图

每一阶段都有**可验收的判据**, 与现有回归体系 (pytest / `router_install_check.py` / `browser_check.cjs`)
对齐。新增一个 **`scripts/router_matrix_check.py`**: 用容器/命名空间模拟 6 类固件栈
(fw3+iptables / fw4+nft / 无 nft 无 tun / 有 tun / 有 eBPF / 无 procd), 断言"探测 → 选级 → 验证 → 状态文案"全对。

### Phase 0 · 冻结规格 (1 天)
* 产出 `caps.json` schema v2 + `spec` schema v1 + 五级阶梯接口定义;
* 交付: 本文档 + schema 文件 + 现有行为→新行为的映射表。

### Phase 1 · 数据面阶梯 + 诚实状态 (核心止血, 最高优先级)
* 实现 L1/L2/L3/L4 的 probe/apply/verify/teardown; L3 (iptables REDIRECT) 是新增, 直接解决 21.02 / 5.4 那一类机器;
* 加入端到端验证与三元组状态 (`desired/actual/covered`);
* 加入 LAN UDP 探针与 `ip rule` 豁免;
* 验收: 六类固件栈全部"要么真接管、要么明说未接管", 且 **没有任何一条路径会误报成功**; 现有真机场景在矩阵里复现为绿。

### Phase 2 · 控制面 zpcore + 本地 UI (易用性翻盘)
* Go agent (探测/数据面/同步/看门狗/本地 UI/CLI) + 引导脚本瘦身;
* 本地 UI 取代固件 Web 服务器依赖;
* 验收: 装机后**不打开固件后台**也能完成全部日常操作; 面板宕机时本地仍可开关与切换; `zp revert` 逐字节还原。

### Phase 3 · IPv6 + 性能模式
* 双栈数据面 + 泄漏防护;
* L0 (dae) 性能模式 (探测通过才启用) + `zp bench` 内建基准 + MTU/GSO/HNAT 自动适配;
* 验收: 有/无 IPv6 的宽带上都能证明"无泄漏"; 基准数据回报面板。

### Phase 4 · 抗封锁与协议透传收官
* AnyTLS / Finalmask 相关参数的透传; ECH 场景下的嗅探降级; 端口跳跃标注;
* 订阅 spec 化 + 本地重渲染 + mixin;
* 验收: 面板输出的每一种节点类型, 在路由器端都被真实客户端验证过 (沿用 verify.py 的方法学)。

### Phase 5 · 兼容矩阵真机回归
* 每类固件至少一台真机跑一遍装机 → 开关 → 断网 → 重启 → 卸载;
* 验收: 矩阵全绿或每条红都有"为什么不支持 + 用户该做什么"。

---

## 17. 与现有实现的迁移

* **不破坏现有装机**: 面板按 `?profile=router&schema=2` 下发; 老客户端不认识 `schema` 参数, 拿到的是 v1 行为。
  agent 首次上报时带 `schema`, 面板据此决定给 v1 还是 v2 (这比"一刀切"安全)。
* **老装机自动升级**: 固定地址的更新命令 (`/c/install.sh`) 不变 —— 下一次 `refresh` 时自动换成 zpcore 形态,
  数据 (`/etc/zeroproxy/servers/*.json`) 与设备凭据沿用, 面板上不多出设备 (8.31 的教训)。
* **保留不动**: 内核版本固定策略、设备凭据模型、`desired/actual` 语义、面板分发内核与 geo、
  订阅地址恒定、多面板聚合 (`proxy-providers`)。
* **删除/合并**: 单服务器与多服务器两条渲染路径 (统一为 providers); cgi + LuCI 会话鉴权路径 (换成 zpcore 本地 UI,
  LuCI 只作为可选插件); "tun 优先 tproxy 回退" 的二元判断 (换成阶梯)。

---

## 18. 附录: 取数明细

星标 / 推送时间取自 GitHub REST API, 时间 2026-10-08:

| 仓库 | ★ | 最近推送 |
|---|---:|---|
| XTLS/Xray-core | 42,000 | 2026-10-08 |
| SagerNet/sing-box | 38,672 | 2026-10-07 |
| MetaCubeX/mihomo | 34,728 | 2026-10-08 |
| vernesong/OpenClash | 27,721 | 2026-10-08 |
| HyNetworks/hysteria | 22,628 | 2026-10-05 |
| juewuy/ShellCrash | 13,566 | 2026-10-07 |
| Openwrt-Passwall/openwrt-passwall | 9,948 | 2026-10-08 |
| daeuniverse/dae | 6,297 | 2026-09-30 |
| nikkinikki-org/OpenWrt-nikki | 5,337 | 2026-10-08 |
| Openwrt-Passwall/openwrt-passwall2 | 3,662 | 2026-10-03 |
| daeuniverse/daed | 2,062 | 2026-09-24 |
| immortalwrt/homeproxy | 1,088 | 2026-10-02 |

内核版本: mihomo v1.19.32 / sing-box 1.14.2 / Xray-core 26.3.27 (含 Finalmask、ECH、uTLS 更新) / Hysteria2 (HyNetworks)。

关键上游事实 (已核对官方文档/源码):

* Nikki 前提: OpenWrt ≥24.10、内核 ≥5.13、firewall4 ([README](https://github.com/nikkinikki-org/OpenWrt-nikki));
* dae 绑定 LAN/WAN 需内核 ≥5.17, 且需 `CONFIG_BPF_SYSCALL` / `CONFIG_DEBUG_INFO_BTF` 等
  ([docs](https://github.com/daeuniverse/dae/blob/main/docs/en/README.md));
* mihomo 在 OpenWrt 网关模式下 tun + auto-route 会打断局域网 UDP 转发, 官方建议以 `ip rule` 豁免 UDP
  ([issue #2584](https://github.com/MetaCubeX/mihomo/issues/2584), [#1866](https://github.com/MetaCubeX/mihomo/issues/1866));
* OpenWrt 25.12 使用 kernel 6.12 / **apk**, 24.10 于 2026-09 EOL
  ([25.12 notes](https://openwrt.org/releases/25.12/notes-25.12.0));
* AnyTLS 在 mihomo 自 v1.19 支持, 设计目标是消除 TLS-in-TLS 的包长侧信道
  ([PR #1844](https://github.com/MetaCubeX/mihomo/pull/1844)).
