"""路由器客户端的服务端部分: 安装脚本渲染 + 内核二进制 / 分流数据 / 内核 BTF 分发。

为什么由面板分发内核二进制
------------------------
路由器要自己从 GitHub 拉 20 MB 的 mihomo, 在国内宽带上是**最脆弱的一环**:
release 域名经常不可达, 用户看到的是"装到一半卡住"。所以面板来做这件事 ——
它在服务器侧, 可以多镜像重试, 并且只成功下载一次就缓存下来。
路由器因此只需要访问**一个地址** (面板自己的域名), 一条防火墙规则、一张证书。

二进制不入库、不进备份, 缓存在 `data/client/cores/` 与 `data/client/btf/` (见 paths),
可随时删掉重下。
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import tarfile
import threading
import time
import urllib.error
import urllib.request

from .config import paths

#: 路由器端脚本版本 (会显示在面板的设备卡上; 改了脚本就 +1)
#: 1.3.0: 数据面从"tun 优先 / tproxy 回退"两级改成五级能力阶梯
#:        (ebpf 只探不选 → tun → tproxy → iptables REDIRECT → 不接管),
#:        每一级都真探测 + 现场验证; caps 记下 chosen / covered / why,
#:        面板与路由器界面显示的都是"真的接管到哪", 不再出现"报成功其实没接管"。
#: 1.4.0: 本机覆盖 (面板不可达时也能开关) + `revert` 逐条比对装机前快照 +
#:        IPv6 能力探测 (能接管才给双栈配置, 接不了就在面板上写"IPv6 未接管")。
#: 1.4.1: `zeroproxy doctor` 真机体检 + 规则计数器 (规则存在 ≠ 有流量经过)。
#: 1.4.2: 内核起不来时**先顺着阶梯降级再 die** (旧版在这里直接死, 于是有 iptables
#:        可走的老固件停在"没接管"); 探测报错只留第一行; 没接管时报出每一级的原因。
#: 1.4.3: 内核与 zpcore 的"复用"都要对版本 —— 面板抬版本号, 已装好的路由器以前#:        永远换不了; zpcore 版本号只有一处 (构建时注入), 不再自报错的版本。
#: 1.4.4: doctor 的 DNS 那一行改按"嗅探出域名的连接数"判断 —— 拿 DNS 计数当判据
#:        方向是反的 (局域网设备查的是路由器自己的 dnsmasq, 计数为 0 本来就正常)。
#: 1.4.5: CLI 里补上 ZP_API (它只定义在安装脚本里, CLI 是独立文件 —— 变量为空时
#:        那条检查会静默变成"没有连接"); 有流量却嗅探不出域名时才报 !。
#: 1.4.6: "已知域名"按 host **或** sniffHost 数 (fake-ip 路线只有前者、纯嗅探只有后者);
#:        doctor 的说明改准 —— 设备的 DNS 有 dnsmasq 与运营商两条路, 两条都按域名分流。
#: 1.4.7: 性能那一半 —— tun MTU 按 WAN 的实际 MTU 算 (PPPoE 1494 之类不再出超包);
#:        转发卸载探测 (它会绕过 netfilter 让 tproxy/redirect 失效); zp bench。
#: 1.4.8: 真机 (OpenWrt 24.10 / 内核 6.6) 抓到探针形状错了 —— v6 tproxy 要传输层匹配、
#:        家族要写死; 生产规则改成显式 tproxy ip / tproxy ip6 各两条。
#: 1.4.9: 真机 (GL-MT3000) 上抓到 caps 里 wan_mtu 空着 / offload=0 —— 这两个值在
#:        choose_datapath(它会写 caps) 之后才算, 算完没人再落盘; 出口测试加重试。
#: 1.4.10: LuCI 会话判定修好 (旧写法在这台 ubus 上只会打印用法 —— 于是"从 LuCI 菜单
#:         点进来"一直是未授权); zpcore 也认 LuCI 会话; 路由器端加一键更新。
#: 1.4.11: update 动作补进 cgi —— 页面由 cgi 发, 只加 CLI 与 zpcore 是不够的。
#: 1.4.12: update 加降级闸门 —— 面板比本机旧就停下, 不把机器降级覆盖回去。
#: 1.4.13: 一键更新带进度条 —— 步骤清单来自安装脚本自己打印的 `==>` 小节; 完成后整页
#:         淡出换成新版本, 不再"啪"地闪一下。
#: 1.4.14: 面板接口的取数加两次重试 (真机实测四成 SYN 被丢), 心跳同理; 刷新本机已有的
#:         分流数据只等 2 分钟; 更新模式下拉不到配置时的话不再把人引向"重新配对"。
#: 1.4.15: `doctor` 多一项"入口连通性" —— 按比例丢包从此看得见 (内核与面板都只看单条
#:         连接的结果, 这一项是唯一量得出比例的地方); 分组带上健康判定: 自动选择 300 → 60
#:         秒且不再"不选中就不测", 有两条以上链时落地组也改成探速选择。
#: 1.4.16: 点「更新客户端」之后的反馈不再等后端 —— 进度面板立刻亮 (不确定态), 后端回话
#:         再接上真实进度; 日志一动手就先落一行 (取面板脚本那几十秒也有东西可显示, 刷新
#:         能接着显示); "没有开始"也留终态 (SKIP=1), 否则刷新之后会停在一个转不完的假进度上。
#: 1.4.17: 更新那条路"每次丢包白等 30 秒"改成等 10 秒、重试 3 次改成 5 次, 并把重试写进
#:         日志 (看得见的等); 拉配置这一步给了自己的 `==>` 小节; 失败时不再把没做的步骤
#:         也打勾, 而是标出卡在哪一步、最后一行留"再点一次就过了"。
#: 1.4.18: 拉配置失败时**只有面板明确拒绝 (HTTP 层, 退出码 22) 才重新配对** —— 丢包不再
#:         把自己装扮成"凭据被拒"(真机上因此平白多出一台设备); 空的/截断的正文也算没拿到;
#:         丢包时整轮再多试两次; 降级配置那句"不含国内直连"改成说实话。
#: 1.4.19: 失败要**说清是哪一类** (超时 / DNS / 连不上 / TLS / 被截断 / 面板明确拒绝),
#:         不许再一律写"链路丢包" —— 8.67/8.68 两轮真机就是因为它们长得一样而查了两遍。
#: 1.4.20: "刷新之后接着显示进度"的判据收紧成"**像一次运行**" (有 `==>` 或带终态) ——
#:         否则 CLI 那句"(还没有更新记录)"会凭空造出一个"正在更新中"的面板, 还把按钮锁住。
#: 1.4.21: 断了的那次运行也要有出口 —— 日志 45 秒没有新内容就把「重试」放出来、按钮解锁;
#:         「重试」不再去"点"那个按钮 (它在看起来在跑时是禁用的, 点了等于没点)。
#: 1.4.22: auto-redirect 被去掉之后, 它本该写的**防火墙放行**由 tunfw.sh 补上, 并且装完
#:         必须验证到位才敢说这一级生效 —— 少了这一步, 局域网被整个丢掉, 而面板与路由器
#:         双双显示"已连接" (8.74, GL-MT3600BE)。doctor 也把这一项单独报出来。
#: 1.4.23: 分流数据库与内核走同一条路 —— 面板 + 镜像, 带进度条、速率闸门与体积闸门;
#:         输出不再丢进 /dev/null (旧实现最长 600 秒/份、一个字都不打, 看起来就是"卡住")。
#:         顺手修掉一个撞名 bug: 体积闸门和 show_body 都写 `_size`, 于是"面板失败→换镜像"
#:         这条路上闸门拿的是 404 正文的大小 (8.75)。
#: 1.4.24: OpenWrt 25.12 的包管理器是 apk (24.10 及更早是 opkg) —— 判据改成"固件世代 +
#:         实际命令"两条一起看 (厂商固件报 25.x 却只有 opkg 的迁移态也能走对), apk 一侧
#:         用 `-U` 一条命令 + 签名不可信时才退 --allow-untrusted; 内核模块没装成时把原话
#:         与**这台机器能用**的补装命令一起说出来, 固件 / 包管理器 / 失败原因落进 caps,
#:         status 与 doctor 都报它们 (8.76)。
#: 1.4.25: 真机 (GL-MT3600BE · 25.12.5) 那句"内核没有 BTF"不再是终点 —— 检测到就**自动补**:
#:         先问本机软件源 (`vmlinux-btf`), 再问面板 (/c/btf, 与内核 / 分流数据库同一套分发),
#:         装上后按 cilium/ebpf 与 libbpf 的那张候选表**验证真的就位**才算数。
#:         只在"内核 >=5.17 且系列在 6.6 / 6.12 内"时才动手 (不然白占闪存);
#:         补不上就说清哪一种原因, 以及它只影响未来的性能档 (8.77)。
#: 1.4.26: **性能模式真的能开**: 数据面换给 dae (eBPF 内核态分流), 与 tun / tproxy 互斥;
#:         进去前 `dae validate` 校验、进去后探针验出口、任何一步失败都退回原来的模式,
#:         另有一只看门狗盯着"dae 还在不在"。本机界面上那块跑车仪表盘就是它的入口 (8.78)。
#: 1.4.27: 升级之后 LuCI 里点「服务 → ZeroProxy」只回一句 **403** —— 界面文件以前是
#:         `http_get … > 目标 || true` 这种直写重定向, 一次失败的请求 (面板正好在重启) 就能把
#:         一份好的 ACL 清成 0 字节。现在: 原子写 (临时文件 → 校验 → mv) + 面板给不出就用内置
#:         的那一份 + `zeroproxy ui fix` 一条命令就地修 (见 README 8.79)。
#: 1.4.28: 性能模式在真机上第一次被真正跑通 —— 两处错都在"准备阶段", 而且都是
#:         **配置本身**的问题, 不是环境: ① 配置落盘是 0644, 而 dae 的 merger 硬性拒绝
#:         "组可写 / 别人可读"的配置 (原话 `permissions 0644 … are too open`), 于是
#:         `dae validate` 永远失败; ② 面板渲染的 node 段键名带引号, 而 dae 的语法里键是
#:         **裸标识符** (`'a': 'link'` 是解析错误)。两处一起修, 顺带把"准备阶段失败 (见上)"
#:         换成**真原因** —— 那句"见上"在手机界面上等于什么都没说 (8.83)。
#: 1.4.29: 准备过了, 卡在**切换**: dae 起来了, 出口验证却判了失败 —— 而 revisit 现场发现
#:         探针那次其实是**通**的, 拦下它的是"mihomo 还在跑"。于是把这条判据按证据收干净:
#:         ① mihomo 在不在以**进程**为准 (`init running` 在固件上不可靠, 它一旦永远为真,
#:         这一档就永远进不去); ② 停完再看一眼进程, 没走就再送一次 TERM (不用 -9: tun 设备
#:         与路由是 mihomo 在退出路径里收的); ③ agent 在切换的空档里不许替用户把标准模式
#:         拉回来 (它每 15 秒一轮心跳, 撞上那几秒就会造出"两个数据面同时在");
#:         ④ 失败原因写进界面读的那份文件并带上 dae 日志的原话 —— 卡片以前一直挂着上一次的
#:         旧结论, 于是这次失败看起来像上次那个原因 (8.84)。
#: 1.4.30: 真机上性能模式**已经开起来了** (dae 真在分流), 但用户看到的是"不能用":
#:         ① 80 端口那条 cgi 的 status 少了 `perf.live` —— 界面要它才画"性能模式运行中/总开关开",
#:         于是从 LuCI 菜单进来那一页永远写着"内核已停止 · 全屋代理关 · 性能模式异常/回退中";
#:         ② 那次"已开启"记下来的出口是**本机自己的 WAN 地址** (CN 电信的 v6) —— curl 默认优先
#:         v6, 而路由器自身的 v6 出口没被 dae 接管, 于是探针走直连也算"通"。现在探针只探 v4,
#:         且出口等于本机 WAN 地址即判失败; ③ 总开关「on」在性能模式在用时不碰 mihomo
#:         (界面骗人的时候, 用户照着点一下就会造出两个数据面抢包); ④ 进出这一档都刷 dnsmasq,
#:         dae 的 DNS 关掉 stale 缓存 (8.85)。
#: 1.4.31: 性能模式那块表盘重做 —— 真机上用户一眼看出"显示有问题": 指针的旋转方向算反了
#:         (0.7 的针掉到 0 刻度线下面), 大数是编出来的 "RPM ×1000" 而真实速率挤在脚注里,
#:         开着的时候整条弧永远填满 (看着像进度条走完了)。现在: 弧=当前速率占上限的比例、
#:         点=当前值 (两者由同一个 p 画出来, 不可能打架)、读数=真实速率 + 真实单位、
#:         刻度不写数字、五段只在切换时出现。出口也诚实了: 面板回传它看到的本机公网地址,
#:         探针出口等于它就标成 (本机) 并警告"路由器自身的流量没走代理"(8.86)。
#: 1.4.32: 性能模式**正在用**的时候重跑安装命令, 那个"数据面能力探测"把 TUN / tproxy /
#:         redirect 三条全探成不通 (数据面正被 dae 接着), 然后摘要给出"去补内核模块 / 换固件"
#:         —— 一句误诊, 用户会截图当成故障 (真机上就这么发生了)。三处修: DATAPATH 的 case 与
#:         摘要的「模式」那一行都补 `ebpf` 那一支、verify() 在性能模式分支里要设 ACTIVE_MODE、
#:         探测结论不采信 (回填 caps 里空机探测过的能力位, 否则那台机器的底子会被这次探测
#:         冲掉); 装机输出里那个"出口"也照 8.86 的口径标 (本机) (8.87)。
#: 1.4.33: "现在哪一级真的在接管"这个判据以前被四处各写一遍 (安装脚本 / agent 心跳 / CLI
#:         的 status 与 doctor / 本地界面 zpcore), 靠注释里的"必须一致"维持 —— 真机上它漂了:
#:         性能模式 (eBPF / dae) 下 mihomo 是停的, CLI 的 status 只看 zp-tun / nft / iptables,
#:         于是报"未生效"; doctor 也把在跑的 dae 说成"服务没在跑"。现在收敛到一份单独的
#:         live.sh (zp_live_mode / zp_live_covered / zp_level_live), 四个消费者都从它取;
#:         心跳报的 mode 也改成**现场** (以前报的是 caps 里的意图, 与 covered 会打架) (8.88)。
#: 1.4.34: 运行时装机件 (live.sh / nft 规则 / 数据面脚本 / agent / CLI / init 脚本) 从安装
#:         脚本的 heredoc 里搬出来, 变成仓库里版本化的文件 (client/runtime/), 随面板分发
#:         (`/c/rt/<name>`)。安装脚本因此从 5578 行缩到 3040 行, 而每个装机件终于能单独
#:         shellcheck / 单测; 取不到时保留本机已有的那份 (升级不许毁掉能用的东西) (8.89)。
#: 1.4.35: 状态收进唯一的生产者 (zpcore 1.3.0 的 `state`): live.sh 与 agent.sh 都从它取
#:         现场 (取不到才用各自那份等价的内联判据) —— 于是"谁在接管"这台机器上只有一个
#:         地方算 (8.91)。
#: 1.4.36: 面板直传**一个字节都没拿到**时不再当成"面板还在准备"干等 (真机 GL-MT3000:
#:         每 5 秒刷一行 `can't open …: no such file`, 一直等到 CORE_WAIT 360 秒, 既不换路
#:         也没说清在等什么)。现在连着两次 0 字节就换直连镜像, 并把那句话说出来; 顺带把
#:         三处 `wc -c < 可能不存在的文件` 的**重定向噪音**按 start_progress 里那条规矩收掉 (8.92)。
#: 1.4.37: 装机件改成**一次取回** (`/c/rt/bundle`, 一份 tar.gz): 十几次往返在丢包的线路上
#:         就是十几次失败机会 (真机卡在"落运行时装机件"好几分钟), 一次取回把它压成一次;
#:         包取不到时退回逐个取, 单件失败仍不拖垮其余 (8.93)。
#: 1.4.39: 配置校验保留真实退出码; 心跳恢复 IPv6/MTU/卸载/原因/吞吐字段;
#:         本地 API 就绪探测不再叠加 HTTP 重试; 校验超时快速返回; bench 带设备凭据。
#: 1.4.40: 修复单服务器 drop 回滚死锁与 device.json 僵尸复活; CGI 如实汇报退出码; 路由页面动效与防重优化。
#: 1.4.41: 修复高纯净度网站连接失败: GEOIP,CN 增加 no-resolve 杜绝国内 DNS 污染; 扩展落地风控域名; fake-ip-filter 移除 STUN 杜绝 WebRTC 泄漏。
#: 1.4.42: 修复 VLESS Reality 与链式代理在 Clash Verge 等客户端超时: 补齐 packet-encoding: xudp, support-x25519mlkem768, fingerprint: chrome; 修复 Xray 顶层 DNS 与 UseIPv4 出站协同; 根除链式中转入站二次 Vision splice 冲突。
#: 1.4.43: 公网入站禁用 TFO, 出站保留 TFO; 链式 Reality 全链路统一 flow=""。
#: 1.4.44: 路由器有副作用动作只允许 POST, 页面同步改为 POST。
#: 1.4.45: 供应链与鉴权收口 —— ① CLI 恢复证书校验 (只在证书错误时降级一次并告警);
#:         ② add 只在未配对/显式 --replace 时更换面板, update 的 base 固定为已配对面板;
#:         ③ 设备凭据优先走 `Authorization: Bearer` (?k= 只作旧面板回退);
#:         ④ 更新的 install.sh、内核/性能内核/运行时件按面板下发的 sha256 校验后再落盘;
#:         ⑤ zpcore 1.3.2: LuCI 会话校验 username=root (或 ACL)、安全响应头、PATH_INFO 动作。
#: 1.4.46: 修复路由器端更新客户端时无法识别 servers/ 目录凭据导致接入账号失败的问题 (兼容 servers/*.json 与 device.json.migrated)。
SCRIPT_VERSION = "1.4.46"

#: 固定的 mihomo 版本。固定而不是跟随最新, 是因为路由器端配置文件 (tun/dns/sniffer)
#: 是按某一版的行为写的; 内核升级可能带来字段废弃, 那种问题在用户家里"全屋断网"
#: 才暴露出来。要升级: 改这里 → 面板重新生成 → 路由器重跑一次安装命令。
CORE_VERSION = os.environ.get("ZP_CORE_VERSION", "v1.19.32")

#: CPU 架构 → mihomo release 资产后缀。
#: armv6 有独立构建 (mihomo-linux-armv6-*), 老款百兆路由 (bcm27xx / arm1176) 直接用它;
#: 以前把 armv6 兜到 armv7 上 —— 结果是一台内核能下载、能解压、跑起来就 "Illegal
#: instruction" 的机器, 比一开始就说清楚难查得多。
#: mips 大端 / 小端都取 softfloat 构建: OpenWrt 的 mips_24kc / mipsel_24kc 目标
#: (绝大多数 MIPS 路由) 的 24Kc 核没有 FPU, hardfloat 构建在上面同样跑不了。
ARCHES: dict[str, str] = {
    "arm64": "arm64",
    "armv6": "armv6",
    "armv7": "armv7",
    "amd64": "amd64-v1",       # x86-64 v1 基线: 兼容所有 x86_64 机器
    "mips": "mips-softfloat",
    "mipsle": "mipsle-softfloat",
    "mips64": "mips64",
    "mips64le": "mips64le",
}

#: 面板上展示用的中文名
ARCH_LABEL = {
    "arm64": "ARM64 (aarch64)",
    "armv6": "ARMv6 (arm1176 等老设备)",
    "armv7": "ARMv7 (arm)",
    "amd64": "x86_64",
    "mips": "MIPS (大端)",
    "mipsle": "MIPSel (小端)",
    "mips64": "MIPS64 (大端)",
    "mips64le": "MIPS64el",
}

#: 下载镜像。顺序 = "谁最可能在国内线路上跑得快"。
#: 第一个是**运营方自建的 GitHub 反代** (github.i3.pub, 写法同 gh-proxy: 把原始地址
#: 整个拼在后面, 支持 Range), 它比公共前缀稳; 后面是几个公共前缀; 官方直连排最后 ——
#: 面板自己也在国内时, 直连 GitHub 基本是"挂到超时", 排前面只会白吃掉整个时间预算
#: (2.6.23 那条教训)。
#: 前缀的可用性会随时间变化, 所以是"挨个试"; 试的过程中有速率闸门 (见 fetch_core):
#: 慢到"按这个速率跑不完"就立刻换下一个, 而不是把预算耗在一个数学上不可能完成的源上。
#: 想换掉整张表: ZP_CORE_MIRRORS=https://自己的镜像/{url},…
DEFAULT_MIRRORS = (
    "https://github.i3.pub/{url}",
    "https://gh-proxy.com/{url}",
    "https://hk.gh-proxy.com/{url}",
    "https://ghfast.top/{url}",
    "https://ghproxy.net/{url}",
    "{url}",
)


def _mirror_list() -> tuple[str, ...]:
    """实际使用的镜像表。

    `ZP_CORE_MIRRORS=https://my.mirror/{url},…` 可以整体替换 (自建反代 / 内网缓存的人
    需要这个: 他们的镜像比任何公共前缀都可靠)。留空就用默认那一串。
    """
    raw = os.environ.get("ZP_CORE_MIRRORS", "").strip()
    if not raw:
        return DEFAULT_MIRRORS
    custom = tuple(item.strip() for item in raw.split(",") if item.strip())
    return custom or DEFAULT_MIRRORS


MIRRORS = _mirror_list()

UA = "zeroproxy-panel"
#: 低于这个大小一律视为下载失败 (一个正常的 mihomo 压缩包 ≈ 20 MB)。
#: 可用 ZP_CORE_MIN_BYTES 调低 —— 自动化演练里用一个几 KB 的假内核就能把
#: "下载 → 解压 → 可执行校验"这条路整条跑通, 不必真的下 20 MB。
def _env_int(name: str, default) -> int:
    """读一个整数环境变量; 写错就退默认值, 绝不让 import 期抛异常。

    这些常量全部在**模块导入时**求值: 运维把 `ZP_CORE_MIN_BYTES=4M` 写进 unit 的
    `Environment=`, 后果不是"这个值被忽略", 而是 `ValueError` 让 `import zeroproxy.main`
    直接失败 —— 面板起不来, systemd 一直 Restart 循环, 人只看到 502。
    """
    raw = os.environ.get(name)
    if raw is None:
        raw = default
    try:
        return int(raw)
    except (TypeError, ValueError):
        try:
            return int(default)
        except (TypeError, ValueError):
            return 0


MIN_BYTES = _env_int("ZP_CORE_MIN_BYTES", str(4 << 20))

#: 单个镜像的连接/读取超时。注意 urllib 的 timeout 是"每次 socket 操作"的上限,
#: 不是整段传输的上限 —— 一个每秒滴一点数据的镜像可以让它永远不超时 (真机现场:
#: 安装命令停在"下载代理内核"上不动, 就是这种慢速黑洞)。
CORE_SOURCE_TIMEOUT = _env_int("ZP_CORE_SOURCE_TIMEOUT", "60")

#: 一次取内核的**总**时间上限。超过就如实报错, 让路由器端拿到一句能读懂的话
#: (以前这里没有上限: 5 个镜像 × 180 秒, 用户看到的就是"卡住", 不是"失败")。
#: 240 秒是量出来的: 一条 170 KB/s 的镜像线路取 20 MB 要 115 秒, 150 秒会把它
#: 卡在门口; 而路由器端等的是 CORE_WAIT=360 秒, 比这里长, 所以它总能等到一个
#: 明确的结果 (ready 或 error), 不会两边一起超时。
CORE_DEADLINE = _env_int("ZP_CORE_DEADLINE", "240")

#: 官方直连那一档的最长等待 (秒)。黑洞掉的直连不值得花掉整个预算。
CORE_DIRECT_BUDGET = _env_int("ZP_CORE_DIRECT_BUDGET", "25")

#: 速率闸门: 观察期过后, 若某个镜像的实测速率低于这个值, 就认定它**按当前速率
#: 跑不完这 20 MB**, 立刻换下一个镜像。
#: 为什么需要它: 一个"能连上、但在国内线路上只有 30 KB/s"的镜像会把整个 CORE_DEADLINE
#: 吃掉却什么也拿不到 (20 MB / 30 KB/s = 11 分钟), 而排在后面的镜像可能一秒就通了。
#: 有 Content-Length 时用"剩余字节 / 剩余时间"精确判断, 没有时才用这个兜底值。
CORE_MIN_RATE_KB = _env_int("ZP_CORE_MIN_RATE_KB", "32")

#: 速率闸门的观察期 (秒): 前几秒的抖动不做数。
CORE_RATE_GRACE = _env_int("ZP_CORE_RATE_GRACE", "8")

#: 路由器端的取内核顺序: panel (默认, 面板直传) / mirror (先直连镜像) / auto (同 panel)。
#: 面板自建镜像的人可以用它做 A/B: 哪条快就固定哪条。
ROUTER_SOURCE = os.environ.get("ZP_ROUTER_SOURCE", "panel").strip().lower()


def asset_name(arch: str) -> str:
    suffix = ARCHES.get(arch)
    if not suffix:
        raise ValueError(f"不支持的架构: {arch}")
    return f"mihomo-linux-{suffix}-{CORE_VERSION}.gz"


def release_url(arch: str) -> str:
    return (
        f"https://github.com/MetaCubeX/mihomo/releases/download/"
        f"{CORE_VERSION}/{asset_name(arch)}"
    )


def core_dir() -> str:
    return os.path.join(paths()["data_dir"], "client", "cores")


def core_file(arch: str) -> str:
    return os.path.join(core_dir(), f"mihomo-{arch}-{CORE_VERSION}.gz")


def core_ready(arch: str) -> bool:
    path = core_file(arch)
    try:
        return os.path.getsize(path) >= MIN_BYTES
    except OSError:
        return False


def cached_arches() -> list[dict]:
    """面板上「已缓存架构」列表。"""
    out = []
    for arch in ARCHES:
        path = core_file(arch)
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        if size >= MIN_BYTES:
            out.append({"arch": arch, "label": ARCH_LABEL.get(arch, arch), "size": size})
    return out


# ---------------------------------------------------------------- 取内核 (带总时限)
# 真机事故 (GL-MT3600BE / OpenWrt 25.12, 2026-10): 安装命令停在 "下载代理内核" 上,
# 十分钟后被路由器自己的 curl -m 600 掐断, 用户看到的既不是成功也不是失败, 而是
# "卡住"。面板侧的原因在这里: 原本**没有总时限** —— 5 个镜像各 180 秒, 而且
# urllib 的 timeout 只管单次 socket 操作, 一个"能连上、每秒滴几 KB"的镜像可以让它
# 拖到天荒地老。
#
# 现在三道闸门一起上:
#   1. 每个镜像有自己的连接/读取超时;
#   2. 官方直连只给 CORE_DIRECT_BUDGET 秒 (被黑洞时 connect 会一直挂着, 不能让它
#      吃掉整个预算 —— GEO 那边早就踩过: "直连排第一会白吃掉整个时间预算");
#   3. 读循环里检查总时限 CORE_DEADLINE, 到点就中断并如实报错。
#
# 另外, 路由器端**不再同步等**这个下载 (见 ensure_core_async 与 routes 的 503)。

#: 后台预取的状态: arch → {state, detail, bytes, started, done, error}
CORE_LOCK = threading.Lock()
CORE_STATE: dict[str, dict] = {}
#: 一次失败之后的冷静时间: 路由器每几秒问一次, 不能让面板一直捶上游。
CORE_RETRY_AFTER = _env_int("ZP_CORE_RETRY_AFTER", "20")


#: "官方直连"那一档的写法 —— 只有它需要短预算 (被墙时 connect 会一直挂着)。
DIRECT_TEMPLATE = "{url}"


def _part_path(dst: str) -> str:
    """给这次下载一个**唯一**的临时文件名 (`<dst>.part-<pid>-<tid>`)。

    以前所有线程共用 `<dst>.part`: 看门狗判定"卡死"后重起一轮、或两个入口同时要同一份
    资产时, 先结束的那个在 finally 里 `os.remove(tmp)` 会把另一个正在写的文件删掉,
    后者 `os.replace` 直接 FileNotFoundError。
    """
    return f"{dst}.part-{os.getpid()}-{threading.get_ident()}"


def _prune_parts(directory: str, max_age: float = 6 * 3600.0) -> None:
    """清掉崩溃/断电留下的 `.part-*` 残骸。"""
    now = time.time()
    try:
        names = os.listdir(directory)
    except OSError:
        return
    for name in names:
        if ".part-" not in name:
            continue
        path = os.path.join(directory, name)
        try:
            if now - os.path.getmtime(path) > max_age:
                os.remove(path)
        except OSError:
            continue


def _budget_for(template: str, remaining: float, timeout: int) -> int:
    """这一个镜像最多能花多少秒。"""
    cap = min(timeout, CORE_DIRECT_BUDGET) if template == DIRECT_TEMPLATE else timeout
    return max(5, int(min(cap, remaining)))


def core_state(arch: str) -> dict:
    """这一档内核现在的状态。面板 UI 与路由器端轮询都读它。"""
    if core_ready(arch):
        try:
            size = os.path.getsize(core_file(arch))
        except OSError:
            size = 0
        return {
            "arch": arch,
            "state": "ready",
            "detail": "面板已缓存",
            "bytes": size,
            "error": "",
            "updated": int((CORE_STATE.get(arch) or {}).get("done") or 0),
        }
    entry = CORE_STATE.get(arch) or {}
    return {
        "arch": arch,
        "state": entry.get("state") or "missing",
        "detail": entry.get("detail") or "",
        "bytes": int(entry.get("bytes") or 0),
        "error": entry.get("error") or "",
        "updated": int(entry.get("done") or entry.get("started") or 0),
    }


def core_states() -> list[dict]:
    """全部架构的状态 (面板 UI 用)。"""
    out = []
    for arch in ARCHES:
        st = core_state(arch)
        st["label"] = ARCH_LABEL.get(arch, arch)
        out.append(st)
    return out


#: 缓存文件的 sha256 记忆 (path, mtime, size) → 摘要。20 MB 每次请求重算太浪费。
_SHA_CACHE: dict[tuple, str] = {}


def core_sha256(path: str) -> str:
    """缓存内核的 sha256。路由器端拿到直连镜像时会用它校验 —— 镜像再多一层也不怕。"""
    try:
        st = os.stat(path)
    except OSError:
        return ""
    # 键用**纳秒**时间戳 + ctime: 秒级 mtime 下,"同一秒内被写成另一份同尺寸内容"
    # 会命中缓存, 返回已不在盘上那份的摘要 —— 而它正是 verify_asset / X-ZP-Sha256 的依据。
    key = (path, st.st_mtime_ns, st.st_ctime_ns, st.st_size)
    hit = _SHA_CACHE.get(key)
    if hit:
        return hit
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
    except OSError:
        return ""
    value = digest.hexdigest()
    # 保留最近几条而不是"只留一条": 四个匿名端点 (/c/bin、/c/geo、/c/perf/geo、
    # /c/agent/bin) 共用这份缓存, 交替请求会让单条缓存永远不命中 —— 于是每个请求都在
    # 请求线程里把 2-20 MB 重读一遍重算一次 sha256。
    if len(_SHA_CACHE) >= 8:
        _SHA_CACHE.pop(next(iter(_SHA_CACHE)), None)
    _SHA_CACHE[key] = value
    return value


# ---------------------------------------------------------------- 供应链摘要
# 面板是路由器的**信任根**: /c/bin、/c/agent/bin、/c/perf、/c/btf 发出去的字节会被路由器
# 以 root 落盘/执行, 而它们的上游是 GitHub + 一串公共反代 —— 反代 / CDN 被投毒、自建反代
# 失守, 就能把任意二进制送进用户家里 (P1-2)。只校验体积 (以前的 MIN_BYTES) 挡不住这个:
# 换一份体积相同的二进制就绕过去了。所以每个上游资产都要有一个**独立于传输通道**的期望
# 摘要:
#
#   * mihomo / dae: 固定值 —— 逐资产取自对应 GitHub release 发布页的官方 digest
#     (v1.19.32 / v2.1.1, 2026-10 核对)。反代只能骗传输, 骗不了发布页上的期望值;
#     版本一换就必须同步改表, 表里没有的版本走"警告 + 记录", 不假装校验过。
#   * zpcore: 仓库里的 client/agent/dist/SHA256SUMS (scripts/build-agent.sh 生成),
#     没有网络依赖 —— 它是我们自己的产物, 摘要跟着制品一起进仓库。
#   * BTF: 上游 tag 是 latest (没有可固定的版本号), 用 release 附带的 SHA256SUMS / API
#     资产的 digest 校验; 两者都拿不到时只放行并如实记录 (见 btf_fetch)。
#
# 不一致就**拒绝下发**: 路由器端看到的是"面板还没准备好", 而不是一份被替换过的 root 二进制。
PINNED_SHA256: dict[str, str] = {
    # ---- mihomo v1.19.32 (CORE_VERSION) · 官方 release 页面的 sha256 digest ----
    "mihomo-linux-arm64-v1.19.32.gz":
        "9dd862e28b46ff7d775f169cceebc28deccaa0a9e804237d421cd2571e0caba0",
    "mihomo-linux-armv6-v1.19.32.gz":
        "efa575b877b1c177e261492f994e4ec0d9bd6b92deed2015e25612396a9ce487",
    "mihomo-linux-armv7-v1.19.32.gz":
        "f622cbe903ba1a11d30e9071d1c5373929c675b854856ff3e7f977255a25bb66",
    "mihomo-linux-amd64-v1-v1.19.32.gz":
        "306f81e723e60ce6b828899a6fe83e1d00e9ecefb2dc8d4d849312a5bc00efdc",
    "mihomo-linux-mips-softfloat-v1.19.32.gz":
        "8b6c0e437ca388d7849db5343ef24304a9b4cf63f12e926eb75d4c7251cd6ab1",
    "mihomo-linux-mipsle-softfloat-v1.19.32.gz":
        "69b10ecd1db5244ab2bf1fac3c629a2e0f9b19f84728fe51b043a9767832d38c",
    "mihomo-linux-mips64-v1.19.32.gz":
        "992fba903e55c1d9ac60c88356744eec059e9568d5743374f6c2edfd784a4321",
    "mihomo-linux-mips64le-v1.19.32.gz":
        "f692484a0e924acaf603a58502d66c930a9d592dd36e310990591da81da9035b",
    # ---- dae v2.1.1 (PERF_VERSION) · 官方 release 页面的 sha256 digest ----
    "dae-linux-arm64.tar.xz":
        "bd84b6770cb335b8a45d8b1e16a95f68cf940b3edaaeeb449c187ce4b1058d0b",
    "dae-linux-armv6.tar.xz":
        "1b400b973e01bd4269b2c06d300879040b02c3410a26c62bbc9cb0410b1977c1",
    "dae-linux-armv7.tar.xz":
        "3875281543fcb3d4bbed38c7f2c11c6daa47ce845ec385033689d0c2ed99ca99",
    "dae-linux-x86_64.tar.xz":
        "c550af580dc97cc90986260da78c4bf72917f3213c2b5d8b79c45199d9c3dc90",
    "dae-linux-mips32.tar.xz":
        "77c6231627aa314ccaac99f03fe36c2fdf86b597a82c1ba6c3f12f19ba44dcdb",
    "dae-linux-mips32le.tar.xz":
        "b03d7bbc1be05305208c1bd0cb846c21c27a4a3a05c441acf47a4361d085cdb2",
    "dae-linux-mips64.tar.xz":
        "3c4d4524a160709d51626004b08ad0943b060e3ef1bf9cc18efba99000f2bc0f",
    "dae-linux-mips64le.tar.xz":
        "49028e34f48b57fafa60dbb2702b5bb27ec63ef29543eac1f7dea141fd215bff",
}

#: 关闭摘要比对的口子: **只给演练 / 测试夹具用** (它们把几 KB 的假内核塞进下载链路,
#: 不可能匹配官方摘要)。生产不设这个变量 = 严格校验。用 "0" 关闭。
SUPPLY_VERIFY = os.environ.get("ZP_SUPPLY_VERIFY", "1").strip() != "0"

#: 供应链事件的落盘位置 (与内核缓存同一个 data/client 下): "为什么这份我没校验/为什么
#: 拒了"必须在事后查得到, 不能只活在这一次 HTTP 请求的返回值里。
SUPPLY_LOG_NAME = "supply.log"


def supply_log(message: str) -> None:
    """记一条供应链事件: 落 data/client/supply.log + 打 stderr (面板日志里也看得到)。"""
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} [supply] {message}"
    try:
        os.makedirs(os.path.join(paths()["data_dir"], "client"), exist_ok=True)
        with open(os.path.join(paths()["data_dir"], "client", SUPPLY_LOG_NAME), "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass
    try:
        import sys

        print(line, file=sys.stderr)
    except Exception:  # pragma: no cover - 打日志不能反过来把请求打挂
        pass


def sha256_hex(data: bytes) -> str:
    """一段字节的 sha256 小写 hex (响应头 X-ZP-Sha256 / X-ZP-Install-Sha256 用它)。"""
    return hashlib.sha256(data).hexdigest()


#: 固定摘要表是**按版本**抄的。用 `ZP_PERF_VERSION` / `ZP_CORE_VERSION` 换了版本之后,
#: 表里那些值对新字节不成立: 以前拿旧摘要比新字节, 每个镜像都被判"摘要不一致 (可能被
#: 替换了)" —— 新版本永远取不到, 而且和真投毒长得一模一样。现在按"这一档没有可信锚点"
#: 处理 (如实记日志), 完整性交给体积 + Content-Length 闸门。
PINNED_PERF_VERSION = "v2.1.1"
PINNED_CORE_VERSION = "v1.19.32"


def expected_sha256(asset: str) -> str:
    """固定摘要表里的期望值; 没登记返回空串 (= 这一档还没有可信锚点)。"""
    if asset.startswith("dae-linux-") and PERF_VERSION != PINNED_PERF_VERSION:
        supply_log(
            f"{asset}: PERF_VERSION={PERF_VERSION} 与固定摘要表 ({PINNED_PERF_VERSION}) 不一致"
            " —— 这一档没有可信锚点, 只过体积 / 完整性闸门"
        )
        return ""
    if asset.startswith("mihomo-linux-") and CORE_VERSION != PINNED_CORE_VERSION:
        supply_log(
            f"{asset}: CORE_VERSION={CORE_VERSION} 与固定摘要表 ({PINNED_CORE_VERSION}) 不一致"
            " —— 这一档没有可信锚点, 只过体积 / 完整性闸门"
        )
        return ""
    return PINNED_SHA256.get(asset, "")


def verify_asset(path: str, asset: str, *, kind: str = "上游资产") -> tuple[bool, str]:
    """校验一个刚下载完的上游资产。返回 (ok, 说明)。

    * 表里有期望值 → 必须完全一致, 不一致即拒绝 (调用方丢弃文件并报错);
    * 表里没有 → 记一条警告后放行, 但把"未校验"说出来 —— 绝不静默当成功;
    * `ZP_SUPPLY_VERIFY=0` (演练 / 夹具用假制品) → 跳过比对, 仍记一条。
    """
    if not SUPPLY_VERIFY:
        supply_log(f"{kind} {asset}: 本次关闭了摘要比对 (ZP_SUPPLY_VERIFY=0), 只过了体积闸门")
        return True, ""
    expected = expected_sha256(asset)
    actual = core_sha256(path)
    if not expected:
        supply_log(
            f"{kind} {asset} 没有固定摘要可校验 (sha256={actual or '?'}), 按未校验放行"
        )
        return True, "未校验 (没有固定摘要)"
    if not actual:
        return False, f"{asset} 读不出摘要 (文件损坏?)"
    if actual != expected:
        supply_log(f"{kind} {asset} 摘要不一致: 期望 {expected} 实际 {actual} —— 已拒绝下发")
        return False, f"{asset} 的 sha256 与官方发布值不一致 (镜像/链路可能被替换了)"
    return True, ""


def _sha256_file_cached(path: str) -> str:
    """文件摘要 (带缓存)。与 core_sha256 同一个实现, 这里是给"非内核"路径的别名。"""
    return core_sha256(path)


# ---------------------------------------------------------------- 本地控制面摘要
# zpcore 的期望摘要在仓库里 (client/agent/dist/SHA256SUMS, 由 scripts/build-agent.sh 生成),
# 不依赖网络: 它本来就是我们自己的产物, 摘要跟着制品一起进仓库。路由器端拿到面板下发的
# X-ZP-Sha256 后比对 —— 面板这一跳被换掉也会被抓住。
def agent_sums_path() -> str:
    return os.path.join(agent_dir(), "SHA256SUMS")


def agent_sha256(arch: str) -> str:
    """dist/SHA256SUMS 里 zpcore-<arch>-<AGENT_VERSION>.gz 的摘要 (没有则空串)。"""
    if arch not in ARCHES:
        return ""
    name = f"zpcore-{arch}-{AGENT_VERSION}.gz"
    try:
        with open(agent_sums_path(), "r", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[-1].lstrip("*") == name:
                    digest = parts[0].strip().lower()
                    return digest if re.fullmatch(r"[0-9a-f]{64}", digest) else ""
    except OSError:
        return ""
    return ""


def mirror_urls(arch: str) -> list[str]:
    """这一档内核的全部镜像地址 (完整 URL, 路由器端直接拿去用)。

    下载地址只有这一份实现: 路由器不需要自己拼模板, 换镜像表时两边不会走偏。
    """
    url = release_url(arch)
    return [template.format(url=url) for template in MIRRORS]


def core_pending_text(arch: str) -> str:
    """给路由器端看的一句人话 (它会原样打印出来)。

    路由器端需要知道的是"现在该等还是该重跑", 不是一句 HTTP 状态码。
    """
    st = core_state(arch)
    if st["state"] == "downloading":
        got = st["bytes"] // (1 << 20)
        extra = f", 已取 {got} MB" if got else ""
        return (
            f"面板正在准备 {arch} 内核 (首次安装时面板要先从上游取约 20 MB{extra})。"
            f"这不是错误 —— 稍后会自动重试。"
        )
    if st["state"] == "error":
        return f"面板取内核失败: {st['error'] or st['detail']}"
    return "面板正在准备内核, 稍后会自动重试。"


def ensure_core_async(arch: str) -> dict:
    """确保有一份内核正在下载, **不阻塞**调用方。返回当前状态。

    为什么不在请求里同步下: 这是一段几十秒到两分钟的活, 而路由器那边正在等一个
    HTTP 响应。把请求挂住的结果就是用户看到的"装到一半卡住"; 改成"立刻回一句能
    读懂的话 + 后台去取", 同一段时间里路由器还能打印真实进度。
    """
    if arch not in ARCHES:
        return {"arch": arch, "state": "unknown", "detail": f"不支持的架构: {arch}",
                "bytes": 0, "error": f"不支持的架构: {arch}", "updated": 0}
    if core_ready(arch):
        return core_state(arch)
    with CORE_LOCK:
        entry = CORE_STATE.setdefault(arch, {})
        wedged = (
            entry.get("state") == "downloading"
            and time.time() - float(entry.get("started") or 0) > max(120, CORE_DEADLINE * 3)
        )
        if entry.get("state") == "downloading" and not wedged:
            return core_state(arch)
        failed_at = int(entry.get("done") or 0)
        if entry.get("state") == "error" and time.time() - failed_at < CORE_RETRY_AFTER:
            return core_state(arch)
        entry.update({
            "state": "downloading",
            "detail": "正在从上游下载",
            "bytes": 0,
            "error": "",
            "started": int(time.time()),
            "done": 0,
        })
    try:
        threading.Thread(
            target=_prefetch, args=(arch,), daemon=True, name=f"zp-core-{arch}"
        ).start()
    except Exception as exc:  # noqa: BLE001 — 线程起不来不能让状态永远停在"下载中"
        with CORE_LOCK:
            CORE_STATE.setdefault(arch, {}).update(
                {"state": "error", "error": f"无法启动后台任务: {exc}", "done": int(time.time())}
            )
    return core_state(arch)


def _prefetch(arch: str) -> None:
    def note(size: int) -> None:
        with CORE_LOCK:
            CORE_STATE.setdefault(arch, {})["bytes"] = size

    try:
        ok, detail, _path = fetch_core(arch, progress=note)
    except Exception as exc:  # 后台线程不能死得无声无息: 那会让状态永远停在"下载中"
        ok, detail = False, f"取内核时出错了: {exc}"
    with CORE_LOCK:
        entry = CORE_STATE.setdefault(arch, {})
        entry["state"] = "ready" if ok else "error"
        entry["detail"] = detail
        entry["error"] = "" if ok else detail
        entry["done"] = int(time.time())


def fetch_core(
    arch: str,
    *,
    timeout: int | None = None,
    deadline: float | None = None,
    progress=None,
) -> tuple[bool, str, str]:
    """按镜像顺序下载内核。返回 (ok, 说明, 本地路径)。

    已缓存就直接返回 —— 路由器重装/多台设备复用时不再重复下载。
    `deadline` 是这一轮的绝对时间上限 (time.time() 口径), 到点就放弃剩余镜像。
    """
    if arch not in ARCHES:
        return False, f"不支持的架构: {arch}", ""
    dst = core_file(arch)
    if core_ready(arch):
        return True, "已缓存", dst

    timeout = timeout or CORE_SOURCE_TIMEOUT
    if deadline is None:
        deadline = time.time() + CORE_DEADLINE
    os.makedirs(core_dir(), exist_ok=True)
    _prune_parts(core_dir())
    tmp = _part_path(dst)
    url = release_url(arch)
    errors: list[str] = []
    for template in MIRRORS:
        left = deadline - time.time()
        if left <= 2:
            errors.append(f"总时间超限 ({CORE_DEADLINE}s), 放弃剩余镜像")
            break
        source = template.format(url=url)
        try:
            request = urllib.request.Request(source, headers={"User-Agent": UA})
            with urllib.request.urlopen(request, timeout=_budget_for(template, left, timeout)) as resp:
                status = getattr(resp, "status", 200)
                if status is not None and status != 200:
                    errors.append(f"{source} HTTP {status}")
                    continue
                size = 0
                started = time.time()
                try:
                    total = int(resp.headers.get("content-length") or 0)
                except (TypeError, ValueError):
                    total = 0
                # total 以前只喂速率闸门; 这里再当完整性闸门用: 中途断流留下的半截
                # .gz 仍可能过 MIN_BYTES, 而它会被路由器**以 root 执行**。
                next_note = 1 << 20          # 每 1 MB 回一次进度
                with open(tmp, "wb") as fh:
                    while True:
                        # 关键的一行: urllib 的 timeout 管不住"一直有数据但极慢"的
                        # 连接, 只有墙钟管得住。
                        if time.time() > deadline:
                            raise TimeoutError(f"总时间超限 ({CORE_DEADLINE}s)")
                        chunk = resp.read(1 << 18)
                        if not chunk:
                            break
                        fh.write(chunk)
                        size += len(chunk)
                        if size >= next_note:
                            next_note = size + (1 << 20)
                            if progress is not None:
                                progress(size)
                            # 速率闸门: 慢到"按当前速率跑不完"就换下一个镜像。20 MB 的
                            # 文件上, 这不只是优化 —— 一个 30 KB/s 的镜像能把整个预算
                            # 吃掉却什么都给不了, 而排在后面的镜像可能一秒就通了。
                            elapsed = time.time() - started
                            if elapsed >= CORE_RATE_GRACE:
                                rate = size / elapsed
                                left_now = deadline - time.time()
                                if total > size and left_now > 0:
                                    needed = (total - size) / left_now
                                else:
                                    needed = rate
                                if rate < needed or rate < CORE_MIN_RATE_KB * 1024:
                                    raise TimeoutError(
                                        f"太慢: {rate / 1024:.0f} KB/s (换下一个镜像)"
                                    )
            if size < MIN_BYTES:
                errors.append(f"{source} 体积异常 ({size} 字节)")
                continue
            if total and size != total:
                errors.append(f"{source} 传输不完整 ({size}/{total} 字节)")
                continue
            # 供应链闸门: 官方发布页上的摘要必须对得上 —— 反代/CDN 只能骗传输。
            good, why = verify_asset(tmp, asset_name(arch), kind="mihomo 内核")
            if not good:
                errors.append(f"{source} {why}")
                continue
            os.replace(tmp, dst)
            if progress is not None:
                progress(size)
            return True, f"已下载 {size // 1024 // 1024} MB", dst
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            errors.append(f"{source} {exc}")
        finally:
            if os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass
    return False, "; ".join(errors)[-300:], ""


# ---------------------------------------------------------------- 分流数据库
# mihomo 加载 GEOSITE / GEOIP 规则时**必须**有分流数据库: 缺文件不是"跳过这条规则",
# 而是整份配置直接加载失败。它自己的默认行为是当场去 GitHub 拉 (geox-url 的默认值),
# 真机上那一步就是"安装卡住"的来源:
#
#     level=error msg="can't initial GeoIP: can't download MMDB: context deadline exceeded"
#     level=error msg="rules[38] [GEOIP,CN,🎯 全球直连] error: ... context deadline exceeded"
#     configuration file /etc/zeroproxy/config.yaml.new test failed
#
# 路由器端的网络正好是最难访问 GitHub 的那一类 (装机时它还没有任何代理可用)。所以和
# 内核二进制一样: **面板去下, 路由器只访问面板一个地址**。路由器把文件放进自己的工作
# 目录, mihomo 看到文件就不再下载 —— 整条装机链路不再需要外网。
#
# 选文件的原则是"路由器闪存要小": 规则真正用到的只有 CN 的 IP 段和几个域名分类, 上游
# 为此专门出了 lite 版 (geoip-lite.metadb, 0.4 MB)。再配一份完整的 geosite.dat
# (4 MB, 含 cn / private / category-ads-all / netflix / disney / hbo / primevideo /
# youtube), 一共 4.4 MB —— 是面板自己那两份 (Loyalsoldier, 28 MB) 的六分之一。
#
# 文件名不能改: mihomo 在 `-d` 目录里按名字找 (大小写不敏感) —— GEOIP 认
# Country.mmdb / geoip.db / geoip.metadb, GEOSITE 认 geosite.dat。
GEO_FILES: dict[str, tuple[str, int]] = {
    "geoip.metadb": (
        "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip-lite.metadb",
        200 << 10,
    ),
    "geosite.dat": (
        "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
        2 << 20,
    ),
}

#: 数据过期时间: 超过就从上游重取 (分流数据不是"越新越好", 但也不能永远不更新 —— 一周
#: 一次足够, 而且只在路由器安装/重装时才下载)。
GEO_TTL = _env_int("ZP_GEO_TTL", str(7 * 86400))

#: 单个镜像的超时 (4 MB 的文件, 90 秒足够; 与 mihomo 自己的下载超时同量级)。
GEO_SOURCE_TIMEOUT = 90

#: 分流数据库的镜像顺序: 与内核同一套思路 —— 运营方自建的镜像第一, 公共反代随后,
#: GitHub 直连最后。直连在受限出口上是"卡满超时再失败", 排第一会白吃掉整个预算
#: (真机网络就是这样: 直连与 ghfast 都超时, 只有 gh-proxy 通)。
DEFAULT_GEO_MIRRORS = (
    "https://github.i3.pub/{url}",
    "https://gh-proxy.com/{url}",
    "https://hk.gh-proxy.com/{url}",
    "https://ghfast.top/{url}",
    "https://ghproxy.net/{url}",
    "{url}",
)


def _geo_mirror_list() -> tuple[str, ...]:
    """实际使用的分流数据镜像表 (与 `_mirror_list` 同一个口子)。

    `ZP_GEO_MIRRORS=https://my.mirror/{url},…` 可以整体替换。**测试必须能关掉它**:
    否则演练里一旦面板那条路没走通, 客户端就会去够真实的 GitHub 反代 —— 一个"离线可跑"
    的回归会变成"看网络脸色"。
    """
    raw = os.environ.get("ZP_GEO_MIRRORS", "").strip()
    if not raw:
        return DEFAULT_GEO_MIRRORS
    custom = tuple(item.strip() for item in raw.split(",") if item.strip())
    return custom or DEFAULT_GEO_MIRRORS


GEO_MIRRORS = _geo_mirror_list()

#: 一次下载的总时间上限。5 个镜像各 90 秒最坏是 7 分钟, 而路由器正在**同步等**这份
#: 数据 —— 它不可能给一台面板几分钟去翻墙。到点就如实报错, 让路由器先降级装上。
GEO_DEADLINE = _env_int("ZP_GEO_DEADLINE", "200")

#: 体积下限 (挡 404 页面 / 限流提示)。演练里用 ZP_GEO_MIN_BYTES 调低: 一个几百字节的
#: 假文件就能把"路由器从面板取数据"这条路整条跑通。
GEO_MIN_OVERRIDE = _env_int("ZP_GEO_MIN_BYTES", "0")

#: 同一时间只允许一个下载任务: 两台路由器同时装机时不该把 4 MB 的文件拉两遍。
GEO_LOCK = threading.Lock()


def geo_min_bytes(name: str) -> int:
    if GEO_MIN_OVERRIDE > 0:
        return GEO_MIN_OVERRIDE
    return GEO_FILES[name][1]


def geo_mirror_urls(name: str) -> list[str]:
    """这一份分流数据库的全部可用地址 (完整 URL, 路由器端直接拿去用)。

    与内核那条路**同一个理由、同一副药**: 面板这条路在有些线路上只有几十 KB/s
    (真机 8.75: 面板直传 47 KB/s, 直连镜像 615 KB/s)。分流数据库比内核小, 但慢起来
    一样是"卡在准备分流数据库不动"—— 而它跟内核一样, 是装机必须过的坎。
    把地址表连同体积下限一起给它, 它就能像取内核那样先试面板、太慢就换镜像;
    换源用的还是**面板这一份**地址表, 两边不会各写一套而走偏。
    """
    url = GEO_FILES[name][0]
    return [template.format(url=url) for template in GEO_MIRRORS]


def geo_dir() -> str:
    return os.path.join(paths()["data_dir"], "client", "geo")


def geo_file(name: str) -> str:
    return os.path.join(geo_dir(), name)


def geo_ready(name: str) -> bool:
    try:
        return os.path.getsize(geo_file(name)) >= geo_min_bytes(name)
    except (OSError, KeyError):
        return False


def geo_stale(name: str) -> bool:
    try:
        return (time.time() - os.path.getmtime(geo_file(name))) > GEO_TTL
    except OSError:
        return True


#: 后台取分流数据库的状态。与内核 (CORE_STATE) 同一套思路, 因为踩的是同一个坑:
#: **不能在请求里同步去上游下** —— 面板那边最长要 200 秒, 而路由器正挂着等一个响应。
#: 真机表现就是"点更新, 卡在「准备分流数据库」那一行动也不动"。现在: 有就立刻给,
#: 没有就立刻回一句能读懂的话 + 503, 后台去取。
GEO_LOCK_ASYNC = threading.Lock()
GEO_STATE: dict[str, dict] = {}

#: 上一轮取失败了就等一会儿再试 —— 免得路由器每 5 秒重试一次、把上游刷成攻击。
GEO_RETRY_AFTER = _env_int("ZP_GEO_RETRY_AFTER", "60")


def geo_pending_text(name: str) -> str:
    """给路由器端看的一句人话 (它会原样打印出来, 用户在终端/界面上读到的就是它)。"""
    with GEO_LOCK_ASYNC:
        entry = dict(GEO_STATE.get(name) or {})
    if entry.get("state") == "downloading":
        return (
            f"面板正在从上游取 {name} (首次安装要先下约 4 MB)。这不是错误 —— "
            "路由器先用本机已有的那份, 数据到位后会自动换回完整分流, 不用再登录路由器。"
        )
    if entry.get("state") == "error":
        return f"面板取 {name} 失败: {entry.get('error') or '上游不可达'}"
    return f"面板正在准备 {name}, 稍后再取。"


def ensure_geo_async(name: str) -> dict:
    """确保有一份分流数据库正在后台下载, **不阻塞**调用方。返回当前状态。"""
    if name not in GEO_FILES:
        return {"state": "unknown", "error": f"未知的数据文件: {name}"}
    # 有文件但**过期**时不能直接返回 ready: 那样 GEO_TTL 永远不生效, 数据会一直停在
    # 装机那天的快照 (routes 里那句"后台换新的"也就成了空操作)。
    if geo_ready(name) and not geo_stale(name):
        return {"state": "ready"}
    with GEO_LOCK_ASYNC:
        entry = GEO_STATE.setdefault(name, {})
        wedged = (
            entry.get("state") == "downloading"
            and time.time() - float(entry.get("started") or 0) > max(120, GEO_DEADLINE * 3)
        )
        if entry.get("state") == "downloading" and not wedged:
            return dict(entry)
        failed_at = int(entry.get("done") or 0)
        if entry.get("state") == "error" and time.time() - failed_at < GEO_RETRY_AFTER:
            return dict(entry)
        entry.update(
            {"state": "downloading", "error": "", "started": int(time.time()), "done": 0}
        )
    try:
        threading.Thread(
            target=_prefetch_geo, args=(name,), daemon=True, name=f"zp-geo-{name}"
        ).start()
    except Exception as exc:  # noqa: BLE001
        with GEO_LOCK_ASYNC:
            GEO_STATE.setdefault(name, {}).update(
                {"state": "error", "error": f"无法启动后台任务: {exc}", "done": int(time.time())}
            )
    with GEO_LOCK_ASYNC:
        return dict(GEO_STATE.get(name) or {})


def _prefetch_geo(name: str) -> None:
    try:
        ok, detail, _path = fetch_geo(name)
    except Exception as exc:  # 后台线程不能死得无声无息: 状态会永远停在"下载中"
        ok, detail = False, f"取 {name} 时出错了: {exc}"
    with GEO_LOCK_ASYNC:
        GEO_STATE.setdefault(name, {}).update(
            {
                "state": "ready" if ok else "error",
                "error": "" if ok else detail,
                "done": int(time.time()),
            }
        )


def cached_geo() -> list[dict]:
    """面板上「路由器分流数据」的展示信息。"""
    out = []
    for name in GEO_FILES:
        try:
            size = os.path.getsize(geo_file(name))
        except OSError:
            continue
        out.append({
            "name": name,
            "size": size,
            "fresh": not geo_stale(name),
            "mtime": int(os.path.getmtime(geo_file(name))),
        })
    return out


def fetch_geo(
    name: str, *, timeout: int = GEO_SOURCE_TIMEOUT, force: bool = False
) -> tuple[bool, str, str]:
    """按镜像顺序取一份分流数据库。返回 (ok, 说明, 本地路径)。

    已缓存且没过期就直接返回 —— 路由器重装 / 多台设备复用时不再重复下载 (4 MB 也是流量)。
    """
    if name not in GEO_FILES:
        return False, f"未知的数据文件: {name}", ""
    dst = geo_file(name)
    if not force and geo_ready(name) and not geo_stale(name):
        return True, "已缓存", dst

    url, _default_min = GEO_FILES[name]
    minimum = geo_min_bytes(name)
    errors: list[str] = []
    with GEO_LOCK:
        # 等锁期间别的请求可能已经下好了
        if not force and geo_ready(name) and not geo_stale(name):
            return True, "已缓存", dst
        os.makedirs(geo_dir(), exist_ok=True)
        tmp = _part_path(dst)
        deadline = time.time() + GEO_DEADLINE
        for template in GEO_MIRRORS:
            source = template.format(url=url)
            left = deadline - time.time()
            if left <= 1:
                errors.append("总时间超限, 放弃剩余镜像")
                break
            try:
                request = urllib.request.Request(source, headers={"User-Agent": UA})
                per_try = max(5, min(timeout, int(left)))
                with urllib.request.urlopen(request, timeout=per_try) as resp:
                    status = getattr(resp, "status", 200)
                    if status is not None and status != 200:
                        errors.append(f"{source} HTTP {status}")
                        continue
                    size = 0
                    started = time.time()
                    # 声明了长度就必须收满: 中途断流留下的"半个 geosite.dat"体积仍可能
                    # 过 minimum 闸门 (真实 4 MB, 闸门 2 MB), 一旦落盘就会被当成新鲜
                    # 缓存用满 GEO_TTL(7 天) —— 而 mihomo 读不了数据文件是**整份配置
                    # 起不来**, 不是跳过规则。
                    try:
                        expect_len = int(resp.headers.get("content-length") or 0)
                    except (TypeError, ValueError):
                        expect_len = 0
                    with open(tmp, "wb") as fh:
                        while True:
                            if time.time() > deadline:
                                raise TimeoutError(f"总时间超限 ({GEO_DEADLINE}s)")
                            chunk = resp.read(1 << 18)
                            if not chunk:
                                break
                            fh.write(chunk)
                            size += len(chunk)
                            # 与内核那条一样: 慢到跑不完就换下一个镜像, 别把预算全吃掉
                            # (4 MB 在 45 KB/s 上要 90 秒 —— 排在后面的镜像可能几秒就完)。
                            # 判据用"还要多快才来得及", 而不是一个拍出来的固定值:
                            # 慢但能在时限内跑完的镜像不该被踢掉。
                            elapsed = time.time() - started
                            if elapsed >= CORE_RATE_GRACE and size >= (1 << 18):
                                rate = size / elapsed
                                left_now = deadline - time.time()
                                needed = rate if left_now <= 0 else (minimum - size) / left_now
                                if rate < needed:
                                    raise TimeoutError(
                                        f"太慢: {rate / 1024:.0f} KB/s (换下一个镜像)"
                                    )
                if size < minimum:
                    errors.append(f"{source} 体积异常 ({size} 字节)")
                    continue
                if expect_len and size != expect_len:
                    errors.append(f"{source} 传输不完整 ({size}/{expect_len} 字节)")
                    continue
                os.replace(tmp, dst)
                return True, f"已下载 {size // 1024} KB", dst
            except (urllib.error.URLError, OSError, TimeoutError) as exc:
                errors.append(f"{source} {exc}")
            finally:
                if os.path.exists(tmp):
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass
    return False, "; ".join(errors)[-300:], ""


# ---------------------------------------------------------------- 内核 BTF (CO-RE 类型信息)
# 为什么要有这一段 (2026-10 真机: GL-MT3600BE · OpenWrt 25.12.5 · 内核 6.12.94):
# 不带 CONFIG_DEBUG_INFO_BTF 编译的固件没有 /sys/kernel/btf/vmlinux, CO-RE eBPF 程序
# (dae / daed 这一类, 也是本项目"性能档"的候选) 就加载不起来 —— 路由器端探测到的正是
# 这种情况。**这件事在固件上能补, 不必重刷**: 社区 (kenzok8/vmlinux-btf) 拿同一份内核
# 源码再编一个带 BTF 的影子内核, 用 pahole 导出 detached BTF, 装到
# /usr/lib/debug/boot/vmlinux-<内核版本>; 而 cilium/ebpf 与 libbpf 在 sysfs 里找不到
# BTF 时**正好会回退到这个路径** (候选顺序与路由器端的 btf_find 一致)。
#
# 包名里带内核版本 (vmlinux-btf-6.12.103-r1-aarch64_cortex-a53.apk), 而 BTF 在**同一
# minor 系列内兼容** (6.12.x 的包装在别的 6.12.y 上也行 —— 包的 postinst 自己按
# uname -r 建软链)。所以路由器把自己 uname -r 报上来, 面板按 minor 系列 + 架构挑包。
#
# 分发方式与内核二进制 / 分流数据库完全一致: **面板去取, 路由器只访问面板一个地址**
# (装机时那台路由器还没有任何代理可用, 让它自己去 GitHub 是 2.9.2 的教训)。
BTF_REPO = os.environ.get("ZP_BTF_REPO", "kenzok8/vmlinux-btf").strip()
BTF_API = os.environ.get("ZP_BTF_API", "https://api.github.com").rstrip("/")
#: 社区包覆盖的内核系列 (它的支持矩阵: 24.10 的 6.6 + 25.12 的 6.12)。别的系列没有包
#: —— 那就如实说"这一档补不了", 而不是让路由器挂在那里等。
BTF_SERIES = ("6.6", "6.12")
#: 取 BTF 包的总时限 (秒)。文件只有几 MB, 但装机时路由器正挂在请求上等 —— 所以它有
#: **硬上限**, 到点就回一句人话 (与内核那条路同一个原则: 不许"一直转").
BTF_DEADLINE = _env_int("ZP_BTF_DEADLINE", "90")
BTF_SOURCE_TIMEOUT = _env_int("ZP_BTF_SOURCE_TIMEOUT", "45")
#: 低于这个大小一律当下载失败 (正常的 BTF blob 几 MB; 反代回的 HTML 页面只有几十 KB)。
BTF_MIN_BYTES = _env_int("ZP_BTF_MIN_BYTES", str(256 << 10))
#: 手上已经放好包 (data/client/btf/) 的人可以把它钉死, 跳过上游资产清单那一步。
BTF_VERSION = os.environ.get("ZP_BTF_VERSION", "").strip()


def btf_dir() -> str:
    return os.path.join(paths()["data_dir"], "client", "btf")


def btf_minor(kver: str) -> str:
    """6.12.94 → '6.12'。BTF 只在这个粒度上要求匹配。"""
    parts = (kver or "").strip().split(".")
    if len(parts) < 2 or not parts[0].isdigit() or not parts[1].isdigit():
        return ""
    return f"{parts[0]}.{parts[1]}"


def btf_asset_pattern(ext: str) -> "re.Pattern[str]":
    """包名 → (内核版本, 架构)。两种包的命名不一样 (与上游发布件一致):
         apk: vmlinux-btf-6.12.103-r1-aarch64_cortex-a53.apk
         ipk: vmlinux-btf_6.6.151-r1_aarch64_cortex-a53.ipk
    """
    if ext == "apk":
        return re.compile(r"^vmlinux-btf-(\d+\.\d+\.\d+)-r\d+-([A-Za-z0-9_.+-]+)\.apk$")
    return re.compile(r"^vmlinux-btf_(\d+\.\d+\.\d+)-r\d+_([A-Za-z0-9_.+-]+)\.ipk$")


def btf_arch_fallbacks(arch: str) -> list[str]:
    """架构候选 (按优先级)。aarch64 的细分目标常常没有包, 但通用档能跑同一份 BTF。"""
    arch = (arch or "").strip()
    if not arch:
        return []
    out = [arch]
    if arch.startswith("aarch64_") and arch != "aarch64_generic":
        out.append("aarch64_generic")
    return out


def btf_version_key(version: str) -> tuple[int, ...]:
    try:
        return tuple(int(p) for p in version.split("."))
    except ValueError:
        return (0,)


def btf_arch_of(name: str, ext: str) -> str:
    """包名 → 架构 (只在给用户列"上游有哪些架构"时用)。"""
    m = btf_asset_pattern(ext).match(name)
    return m.group(2) if m else ""


def btf_cached(minor: str, arch: str, ext: str) -> str:
    """缓存里有没有匹配的包 (支持手工放进去 —— 面板取不到上游时的兜底)。

    先按架构精确匹配, 再退到通用档; 同一个架构有多份时取版本最高的那一份。
    缓存里只有别的内核系列的包时返回空 —— 那对这台机器没有意义, 别发出去。
    """
    pattern = btf_asset_pattern(ext)
    best_key: tuple[int, ...] = (0,)
    best_rank = 999
    best_path = ""
    try:
        names = os.listdir(btf_dir())
    except OSError:
        return ""
    for rank, want in enumerate(btf_arch_fallbacks(arch)):
        for name in names:
            m = pattern.match(name)
            if not m or m.group(2) != want:
                continue
            if minor and btf_minor(m.group(1)) != minor:
                continue
            key = btf_version_key(m.group(1))
            # 先比架构精确度 (rank 小的优先), 同档再比版本。反过来会让"通用档的新版本"
            # 压过"精确架构的旧版本", 与 btf_pick 的分组顺序相反。
            if rank < best_rank or (rank == best_rank and key > best_key):
                best_key, best_rank, best_path = key, rank, os.path.join(btf_dir(), name)
    if not best_path:
        return ""
    try:
        if os.path.getsize(best_path) < BTF_MIN_BYTES:
            return ""
    except OSError:
        return ""
    return best_path


def btf_asset_url(name: str) -> str:
    return f"https://github.com/{BTF_REPO}/releases/download/latest/{name}"


#: 上游 release 里那份摘要清单的名字 (kenzok8/vmlinux-btf 的资产列表里确实有它)。
BTF_SUMS_NAME = "SHA256SUMS"
#: SHA256SUMS 很小; 但"解析失败就重下一次"也不该把装机拖住, 所以只试一轮镜像。
BTF_SUMS_MAX_BYTES = 512 << 10

#: 解析过的摘要清单缓存: (取到的时间, 名字 → 摘要)。一份清单覆盖全部架构, 一次装机
#: 只需要取一次 (BTF 的 tag 是 latest, 没有版本号可固定, 这是它能拿到的最好锚点)。
_BTF_SUMS_CACHE: dict[str, str] = {}
_BTF_SUMS_AT = 0.0
#: 清单缓存多久 (秒)。取不到时也按同一个间隔退避, 免得每台设备装机都去撞一次上游。
BTF_SUMS_TTL = _env_int("ZP_BTF_SUMS_TTL", "600")


def _parse_sha256sums(text: str) -> dict[str, str]:
    """解析 `sha256sum` 风格的清单: 每行 `<64hex>␣␣<名字>` (也认 `SHA256 (name) = hex`)。"""
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
            out[parts[-1].lstrip("*")] = parts[0].lower()
            continue
        m = re.match(r"^SHA256\s*\((.+)\)\s*=\s*([0-9a-fA-F]{64})$", line)
        if m:
            out[m.group(1).strip()] = m.group(2).lower()
    return out


#: 摘要清单的取用串行化。以前"开始取"和"取失败"共用一个时间戳: 一个线程正在取时,
#: 另一个线程立刻拿到空串 → btf_verify 按"上游没给摘要"**放行** (供应链闸门 fail-open)。
_BTF_SUMS_LOCK = threading.Lock()


def btf_sums_lookup(asset: str, *, timeout: int = 25, deadline: float | None = None) -> str:
    """从上游 release 的 SHA256SUMS 里取一个资产的摘要 (取不到返回空串)。

    只走默认镜像表 (与资产本身同一条路): 它挡不住"整条链路一起被换", 但能挡住
    "某个反代回了一份别的字节 / 半截文件"。真正的固定锚点还是要靠上游发布版本号 ——
    BTF 的 tag 是 latest, 这一档只能做到这里 (残余风险已在报告里写明)。

    并发语义: 同一时刻只有一个线程去取, 其它线程**等它取完**再读缓存 —— 而不是
    直接拿到空串当成"上游没有摘要"。
    """
    global _BTF_SUMS_AT
    if asset == BTF_SUMS_NAME:
        return ""
    if _BTF_SUMS_CACHE:
        return _BTF_SUMS_CACHE.get(asset, "")
    with _BTF_SUMS_LOCK:
        if asset in _BTF_SUMS_CACHE:             # 等锁期间别人可能已经取到了
            return _BTF_SUMS_CACHE[asset]
        if (time.time() - _BTF_SUMS_AT) < BTF_SUMS_TTL:
            # 两种"缓存里没有它": 清单一整份都没取到 (上一轮失败), 或者清单是旧快照
            # (上游刚发了新内核包)。TTL 内先按"没有锚点"放行, 到点后强制刷新一次。
            return ""
        budget = int(timeout)
        if deadline is not None:
            budget = max(5, min(budget, int(deadline - time.time())))
        fetched: dict[str, str] = {}
        url = btf_asset_url(BTF_SUMS_NAME)
        for template in MIRRORS:
            if deadline is not None and time.time() > deadline:
                break
            source = template.format(url=url)
            try:
                request = urllib.request.Request(source, headers={"User-Agent": UA})
                with urllib.request.urlopen(request, timeout=budget) as resp:
                    status = getattr(resp, "status", 200)
                    if status is not None and status != 200:
                        continue
                    raw = resp.read(BTF_SUMS_MAX_BYTES)
            except (urllib.error.URLError, OSError, TimeoutError):
                continue
            parsed = _parse_sha256sums(raw.decode("utf-8", "replace"))
            if parsed:
                fetched = parsed
                break
        _BTF_SUMS_AT = time.time()               # 成败都记, 但只在**尝试结束之后**
        _BTF_SUMS_CACHE.update(fetched)
    return _BTF_SUMS_CACHE.get(asset, "")


def btf_verify(
    path: str, asset: str, digest: str = "", deadline: float | None = None
) -> tuple[bool, str]:
    """BTF 包的摘要校验: 资产 digest > SHA256SUMS > (都没有) 如实记录后放行。"""
    if not SUPPLY_VERIFY:
        supply_log(f"BTF {asset}: 本次关闭了摘要比对 (ZP_SUPPLY_VERIFY=0)")
        return True, ""
    want = (digest or "").strip().lower()
    if want.startswith("sha256:"):
        want = want[len("sha256:"):].strip()
    if not want:
        want = btf_sums_lookup(asset, deadline=deadline)
    if not want:
        supply_log(f"BTF {asset}: 上游没有给 digest / SHA256SUMS 也取不到, 只过了体积闸门")
        return True, "未校验 (上游没有摘要)"
    actual = core_sha256(path)
    if actual != want:
        supply_log(f"BTF {asset} 摘要不一致: 期望 {want} 实际 {actual} —— 已拒绝下发")
        return False, f"{asset} 的 sha256 与上游发布值不一致"
    return True, ""


def _safe_int(value, default: int = 0) -> int:
    """上游给的数字字段: 解析不了就退默认值 (别让它变成一次 500)。"""
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return default


def btf_upstream_assets(
    timeout: int = 20, *, use_cache: bool = True
) -> tuple[bool, str, list[dict]]:
    """问一次上游 release 的资产清单。返回 (ok, 说明, [{name, url, size}])。

    只在缓存里没有时才问, 而且**只问一次** (装机时路由器挂在请求上等, 这里不能反复
    重试上游)。ZP_BTF_VERSION 钉了版本的人直接跳过这一步 (仍然要过镜像下载)。
    """
    if BTF_VERSION:
        return True, "已钉版本", [{"version": BTF_VERSION}]
    if use_cache and _BTF_ASSETS_CACHE["assets"] and (
        time.time() - float(_BTF_ASSETS_CACHE["at"] or 0) < BTF_ASSETS_TTL
    ):
        return True, _BTF_ASSETS_CACHE["detail"], list(_BTF_ASSETS_CACHE["assets"])
    url = f"{BTF_API}/repos/{BTF_REPO}/releases/tags/latest"
    headers = {"User-Agent": UA, "Accept": "application/vnd.github+json"}
    try:
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(request, timeout=max(5, int(timeout))) as resp:
            payload = json.loads(resp.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return False, f"上游资产清单取不到 ({exc})", []
    if not isinstance(payload, dict):
        # 上游被反代换成数组/字符串时, 以前是 `payload.get` 抛 AttributeError 变成 500
        return False, "上游资产清单格式不对 (不是对象)", []
    assets = []
    for item in payload.get("assets", []) or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        if not name:
            continue
        assets.append({
            "name": name,
            "url": str(item.get("browser_download_url") or btf_asset_url(name)),
            "size": _safe_int(item.get("size")),
            # GitHub 给每个 release 资产算了 digest (`sha256:…`)。有它就不必再取
            # SHA256SUMS —— 它是发布侧给出的期望值, 与下载链路无关。
            "digest": str(item.get("digest") or ""),
        })
    if not assets:
        return False, "上游 release 里一个资产都没有", []
    _BTF_ASSETS_CACHE.update(
        {"at": time.time(), "ok": True, "detail": "ok", "assets": list(assets)}
    )
    return True, "ok", assets


def btf_pick(assets: list[dict], minor: str, arch: str, ext: str) -> list[dict]:
    """按 (minor 系列 + 架构) 挑候选: 精确架构优先、通用档兜底, 版本高的优先。"""
    pattern = btf_asset_pattern(ext)
    picked: list[dict] = []
    for rank, want in enumerate(btf_arch_fallbacks(arch)):
        group: list[tuple[tuple[int, ...], dict]] = []
        for item in assets:
            name = str(item.get("name") or "")
            m = pattern.match(name) if name else None
            if not m:
                # 钉版本时清单里只有版本号, 资产名要按架构拼
                version = str(item.get("version") or "")
                if not version or btf_minor(version) != minor:
                    continue
                sep = "-" if ext == "apk" else "_"
                name = f"vmlinux-btf{sep}{version}-r1{sep}{want}.{ext}"
                m = pattern.match(name)
                if not m:
                    continue
                item = {"name": name, "url": btf_asset_url(name), "size": 0}
            if m.group(2) != want or btf_minor(m.group(1)) != minor:
                continue
            group.append((btf_version_key(m.group(1)), {**item, "rank": rank}))
        group.sort(key=lambda pair: pair[0], reverse=True)
        picked.extend(item for _, item in group)
    return picked


# ---------------------------------------------------------------- BTF 异步取用
# `/c/btf` 是**匿名可达**的: 以前它在请求线程里同步跑最长 ~110 秒 (90 秒下载 + 摘要清单
# 最多 6×25 秒), 而 FastAPI 的同步端点跑在 40 线程的池子里 —— 40 个并发请求就能把
# /c/report、/sub、/api/* 全部排队排死。这里与 /c/bin、/c/geo、/c/perf 对齐成
# "立刻回一句人话 + 后台去取"。
BTF_LOCK = threading.Lock()
BTF_STATE: dict[str, dict] = {}
BTF_RETRY_AFTER = _env_int("ZP_BTF_RETRY_AFTER", "60")
#: 同一时刻只允许一个 BTF 抓取: 两个线程共享同一个 `<name>.part` 时, 一个线程的 finally
#: 清理会删掉另一个正在写的文件, 对方随后 os.replace 就是 FileNotFoundError。
_BTF_FETCH_LOCK = threading.Lock()
#: 一次抓取最多允许"在跑"多久 (超过就当那一轮线程已经死了)
_BTF_WEDGE = max(120, BTF_DEADLINE * 3)


def btf_key(kver: str, arch: str, ext: str) -> str:
    return f"{btf_minor(kver)}|{(arch or '').strip()}|{(ext or 'apk').strip().lower()}"


def btf_state(kver: str, arch: str, ext: str) -> dict:
    key = btf_key(kver, arch, ext)
    minor = btf_minor(kver)
    if minor and btf_cached(minor, (arch or "").strip(), (ext or "apk").strip().lower()):
        return {"key": key, "state": "ready", "detail": "面板已缓存", "error": "", "started": 0, "done": 0}
    with BTF_LOCK:
        entry = dict(BTF_STATE.get(key) or {})
    entry["key"] = key
    entry.setdefault("state", "missing")
    return entry


def btf_wait_text(kver: str, arch: str, ext: str) -> str:
    """等取时给路由器端看的一句话 (客户端会把正文第一行当原因打印出来)。"""
    st = btf_state(kver, arch, ext)
    if st.get("state") == "error":
        return btf_pending_text(kver, arch, ext, str(st.get("error") or "上游不可达"))
    if st.get("state") == "downloading":
        return (
            f"面板正在准备内核 BTF 包 (内核 {kver or '?'} · {arch or '?'} · {ext})… "
            "这不是错误 —— 稍后会自动重试。这一档只影响 eBPF 性能模式, "
            "不影响当前的 TUN / tproxy 数据面。"
        )
    return btf_pending_text(kver, arch, ext, "面板正在准备")


def ensure_btf_async(kver: str, arch: str, ext: str) -> dict:
    """确保有一份 BTF 包正在后台准备, **不阻塞**调用方。返回当前状态。"""
    key = btf_key(kver, arch, ext)
    spawn = False
    with BTF_LOCK:
        entry = BTF_STATE.setdefault(key, {})
        wedged = (
            entry.get("state") == "downloading"
            and time.time() - float(entry.get("started") or 0) > _BTF_WEDGE
        )
        if entry.get("state") == "downloading" and not wedged:
            out = dict(entry)
            out["key"] = key
            return out
        if (
            entry.get("state") == "error"
            and time.time() - float(entry.get("done") or 0) < BTF_RETRY_AFTER
            and not wedged
        ):
            out = dict(entry)
            out["key"] = key
            return out
        entry.update(
            {"state": "downloading", "detail": "正在从上游取", "error": "",
             "started": int(time.time()), "done": 0}
        )
        spawn = True
    if spawn:
        if not _BTF_CONCURRENCY.acquire(blocking=False):
            # 后台已经在取别的档了: 先把状态退回"未知", 让调用方稍后重试,
            # 而不是再起一个线程去打上游。
            with BTF_LOCK:
                BTF_STATE.setdefault(key, {}).update({"state": "", "detail": "", "error": ""})
            return btf_state(kver, arch, ext)
        try:
            threading.Thread(
                target=_prefetch_btf, args=(kver, arch, ext), daemon=True,
                name=f"zp-btf-{key}",
            ).start()
        except Exception as exc:  # noqa: BLE001 — 线程起不来不能让状态停在"下载中"
            _BTF_CONCURRENCY.release()
            with BTF_LOCK:
                BTF_STATE.setdefault(key, {}).update(
                    {"state": "error", "error": f"无法启动后台任务: {exc}",
                     "done": int(time.time())}
                )
        with BTF_LOCK:
            _btf_trim_locked()
    return btf_state(kver, arch, ext)


def _prefetch_btf(kver: str, arch: str, ext: str) -> None:
    key = btf_key(kver, arch, ext)
    try:
        ok, detail, _path = btf_fetch(kver, arch, ext)
    except Exception as exc:  # noqa: BLE001 — 后台线程不能死得无声无息
        ok, detail = False, f"取 BTF 包时出错了: {exc}"
    with BTF_LOCK:
        BTF_STATE.setdefault(key, {}).update(
            {"state": "ready" if ok else "error", "detail": detail,
             "error": "" if ok else detail, "done": int(time.time())}
        )
    _BTF_CONCURRENCY.release()


#: `arch` / `kver` 来自**匿名**请求, 直接当状态键用: 不限长就是一个"一请求一线程 +
#: 一次未认证 GitHub API 调用"的放大面 (60 次/小时配额打满 → 真实装机全 503)。
_ARCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]{0,47}$")
_KVER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}$")
#: 状态表上限: 只保留仍需要回答的那几档 (超出时丢最旧的已结束项)
BTF_STATE_MAX = 32
#: 同一时刻最多允许几个后台抓取 (再多就回 503 让它稍后重试)
_BTF_CONCURRENCY = threading.Semaphore(2)
#: 上游资产清单的 TTL 缓存 —— 原来每个不同 key 都会直连一次 api.github.com
_BTF_ASSETS_CACHE: dict = {"at": 0.0, "ok": False, "detail": "", "assets": []}
BTF_ASSETS_TTL = _env_int("ZP_BTF_ASSETS_TTL", "600")


def _btf_trim_locked() -> None:
    """状态表超限时丢掉最旧的"已结束"项 (调用方必须已持 BTF_LOCK)。"""
    if len(BTF_STATE) <= BTF_STATE_MAX:
        return
    done = [
        (float(v.get("done") or v.get("started") or 0), k)
        for k, v in BTF_STATE.items()
        if v.get("state") != "downloading"
    ]
    for _, key in sorted(done)[: max(0, len(BTF_STATE) - BTF_STATE_MAX)]:
        BTF_STATE.pop(key, None)


def btf_prepare(kver: str, arch: str, ext: str) -> tuple[bool, str, str]:
    """端点用的入口。返回 (是否**永久**不可用, 给用户的一句话, 本地路径)。

    永久不可用 (400/404 语义): 参数不认识、内核系列社区没有现成件 —— 重试也没用。
    其余情况一律"后台去取", 端点回 503 + Retry-After。
    """
    kver = (kver or "").strip()
    arch = (arch or "").strip()
    ext = (ext or "apk").strip().lower()
    if ext not in ("apk", "ipk"):
        return True, f"不认识的包格式: {ext}", ""
    minor = btf_minor(kver)
    if not kver or not minor:
        return True, f"没给出可识别的内核版本 (收到 {kver!r})", ""
    if not arch:
        return True, "没给出设备架构", ""
    if not _KVER_RE.match(kver) or not _ARCH_RE.match(arch):
        return True, f"内核版本或架构写法不认识 (kver={kver[:24]!r} arch={arch[:24]!r})", ""
    path = btf_cached(minor, arch, ext)
    if path:
        return False, "已缓存", path
    if minor not in BTF_SERIES:
        return True, (
            f"这台内核是 {minor} 系列 —— 社区的 BTF 包只覆盖 {' / '.join(BTF_SERIES)} "
            "(补 BTF 要有对应系列的影子内核, 别的系列没有现成件)"
        ), ""
    ensure_btf_async(kver, arch, ext)
    return False, btf_wait_text(kver, arch, ext), ""


def btf_pending_text(kver: str, arch: str, ext: str, why: str) -> str:
    """取不到时给路由器端的一句人话 —— 要说清"怎么办", 以及"它到底影响什么"。"""
    return (
        f"面板没能给这台设备准备内核 BTF 包 (内核 {kver or '?'} · {arch or '?'} · {ext}): {why}\n"
        f"1) 面板自己取不到上游时, 手动把匹配的包 (vmlinux-btf*{btf_minor(kver)}*{arch}*.{ext}) "
        "放进面板数据目录下的 client/btf/ (面板日志里有绝对路径) 再重跑安装命令 —— "
        "面板会直接把它发给路由器;\n"
        f"2) 上游: https://github.com/{BTF_REPO}/releases (tag: latest)。\n"
        "这一档只关系到 eBPF 性能档 (dae 那一类), **不影响当前的 TUN / tproxy 数据面**。"
    )


def btf_fetch(kver: str, arch: str, ext: str, *, deadline: float | None = None) -> tuple[bool, str, str]:
    """准备这台设备要的 BTF 包。返回 (ok, 说明, 本地路径)。

    顺序: 缓存 (含手工放进去的) → 上游资产清单 → 按镜像下载。
    """
    kver = (kver or "").strip()
    arch = (arch or "").strip()
    ext = (ext or "apk").strip().lower()
    if ext not in ("apk", "ipk"):
        return False, f"不认识的包格式: {ext}", ""
    if not btf_minor(kver):
        return False, f"没给出内核版本 (收到 {kver!r})", ""
    if not arch:
        return False, "没给出设备架构", ""

    minor = btf_minor(kver)
    cached = btf_cached(minor, arch, ext)
    if cached:
        return True, "已缓存", cached
    if deadline is None:
        deadline = time.time() + BTF_DEADLINE
    if minor not in BTF_SERIES:
        return False, (
            f"这台内核是 {minor} 系列 —— 社区的 BTF 包只覆盖 {' / '.join(BTF_SERIES)} "
            "(补 BTF 要有对应系列的影子内核, 别的系列没有现成件)"
        ), ""

    # 清单查询与摘要查询**都**要算进这一轮的时限: 它们各自最多几十秒, 加起来能顶掉
    # 一整个 90 秒预算, 却原来完全不受 deadline 约束。
    ok, detail, assets = btf_upstream_assets(
        timeout=max(5, min(BTF_SOURCE_TIMEOUT, int(deadline - time.time())))
    )
    if not ok:
        return False, detail, ""
    picks = btf_pick(assets, minor, arch, ext)
    if not picks:
        available = sorted({a for item in assets if (a := btf_arch_of(item.get("name") or "", ext))})
        return False, (
            f"上游没有 (内核 {minor} 系列 · {arch} · {ext}) 这一档的包; "
            f"该格式上游有的架构: {', '.join(available) or '无'}"
        ), ""

    os.makedirs(btf_dir(), exist_ok=True)
    # 同一时刻只允许一个 BTF 抓取: 两个线程共享同一个 `<name>.part` 时, 一个线程的
    # finally 清理会删掉另一个正在写的文件, 对方随后 os.replace 直接 FileNotFoundError。
    with _BTF_FETCH_LOCK:
        return _btf_download(picks, deadline)


def _btf_download(picks: list[dict], deadline: float) -> tuple[bool, str, str]:
    """(持锁的) 实际下载循环, 从 btf_fetch 里拆出来。"""
    errors: list[str] = []
    for pick in picks:
        name = str(pick["name"])
        dst = os.path.join(btf_dir(), name)
        url = str(pick.get("url") or btf_asset_url(name))
        tmp = _part_path(dst)
        for template in MIRRORS:
            left = deadline - time.time()
            if left <= 2:
                errors.append(f"总时间超限 ({BTF_DEADLINE}s)")
                break
            source = template.format(url=url)
            try:
                request = urllib.request.Request(source, headers={"User-Agent": UA})
                with urllib.request.urlopen(request, timeout=_budget_for(template, left, BTF_SOURCE_TIMEOUT)) as resp:
                    status = getattr(resp, "status", 200)
                    if status is not None and status != 200:
                        errors.append(f"{source} HTTP {status}")
                        continue
                    size = 0
                    try:
                        total = int(resp.headers.get("content-length") or 0)
                    except (TypeError, ValueError):
                        total = 0
                    with open(tmp, "wb") as fh:
                        while True:
                            # 与内核那条一样: 只有墙钟管得住"一直有数据但极慢"的连接
                            if time.time() > deadline:
                                raise TimeoutError(f"总时间超限 ({BTF_DEADLINE}s)")
                            chunk = resp.read(1 << 17)
                            if not chunk:
                                break
                            fh.write(chunk)
                            size += len(chunk)
                if size < BTF_MIN_BYTES:
                    errors.append(f"{source} 体积异常 ({size} 字节)")
                    continue
                if total and size != total:
                    errors.append(f"{source} 传输不完整 ({size}/{total} 字节)")
                    continue
                # 摘要闸门: 上游 release 的资产 digest / SHA256SUMS 对得上才发出去。
                good, why = btf_verify(
                    tmp, name, str(pick.get("digest") or ""), deadline=deadline
                )
                if not good:
                    errors.append(f"{source} {why}")
                    continue
                os.replace(tmp, dst)
                return True, f"已下载 {size // 1024} KB", dst
            except (urllib.error.URLError, OSError, TimeoutError) as exc:
                errors.append(f"{source} {exc}")
            finally:
                if os.path.exists(tmp):
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass
    return False, "; ".join(errors)[-300:], ""


# ---------------------------------------------------------------- 性能模式内核 (dae)
# 性能模式 (L0) 用 dae 做数据面: eBPF 在内核里分流, 直连流量真旁路, 不走用户态。
# 它的前提是内核 >=5.17 + BTF (缺 BTF 时客户端会自己补, 见 README 8.77), 所以面板这一侧
# 只负责**把 dae 发下去** —— 与 mihomo 内核完全同一套: 面板去上游取、缓存好, 路由器只访问
# 面板一个地址 (装机时它还没有任何代理可用)。
#
# 上游发布的是 `dae-linux-<arch>.tar.xz` (里面是 dae 二进制 + 它的示例配置)。**面板负责
# 解包并重新压成 .gz** —— 因为路由器那边只有 busybox: gzip 一定有, 而 xz / unzip 不保证
# (mihomo 内核走的就是 .gz 那条路, 客户端一个字节都不用改)。
PERF_VERSION = os.environ.get("ZP_PERF_VERSION", "v2.1.1")

#: 我们的架构键 → 上游资产名。dae 的命名与 mihomo 不同 (x86_64 / mips32 / mips32le …)。
PERF_ASSET: dict[str, str] = {
    "arm64": "dae-linux-arm64.tar.xz",
    "armv6": "dae-linux-armv6.tar.xz",
    "armv7": "dae-linux-armv7.tar.xz",
    "amd64": "dae-linux-x86_64.tar.xz",
    "mips": "dae-linux-mips32.tar.xz",
    "mipsle": "dae-linux-mips32le.tar.xz",
    "mips64": "dae-linux-mips64.tar.xz",
    "mips64le": "dae-linux-mips64le.tar.xz",
}

#: 解出来的 dae 二进制至少这么大 (真实的约 25-30 MB)。挡"上游给了一层错误页"这类事故。
PERF_MIN_BYTES = _env_int("ZP_PERF_MIN_BYTES", str(6 << 20))
#: 一次取 dae 的总时限。它比内核小 (10 MB 的 tar.xz), 但同样是"有上限的等待"。
PERF_DEADLINE = _env_int("ZP_PERF_DEADLINE", "300")
PERF_SOURCE_TIMEOUT = _env_int("ZP_PERF_SOURCE_TIMEOUT", "60")
PERF_DIRECT_BUDGET = _env_int("ZP_PERF_DIRECT_BUDGET", "25")

PERF_LOCK = threading.Lock()
PERF_STATE: dict[str, dict] = {}
PERF_RETRY_AFTER = _env_int("ZP_PERF_RETRY_AFTER", "20")


def perf_dir() -> str:
    return os.path.join(paths()["data_dir"], "client", "perf")


def perf_file(arch: str) -> str:
    return os.path.join(perf_dir(), f"dae-{arch}-{PERF_VERSION}.gz")


def _perf_candidates(names: list[str], arch: str) -> list[str]:
    """手工兜底文件的候选: 架构必须**整段**命中。

    以前是子串判断 (`arch in name`), 于是请求 `mips` 会命中 `dae-mipsle-v2.1.1.gz` ——
    `perf_ready` 因此永远为真, `ensure_perf_async` 再也不会去下正确的那一份, 路由器
    拿到的是小端二进制, 执行时报 Illegal instruction (本文件 ARCHES 的注释正是讲这个)。
    """
    pattern = re.compile(rf"^dae-{re.escape(arch)}-[^/]+\.gz$")
    return [name for name in sorted(names) if pattern.match(name)]


def perf_ready(arch: str) -> bool:
    """缓存里有没有一份能用的 dae (.gz)。

    手工放进去的也算 (运维在面板取不到上游时的兜底): 只要文件名里带 `dae` 与这个架构,
    体积过关就用它 —— 与内核那个"手动放压缩包"的兜底同款。
    """
    if _perf_file_ok(perf_file(arch)):
        return True
    try:
        names = os.listdir(perf_dir())
    except OSError:
        return False
    return any(_perf_file_ok(os.path.join(perf_dir(), name)) for name in _perf_candidates(names, arch))


def _perf_min_size() -> int:
    return max(1, PERF_MIN_BYTES // 4)


def _perf_file_ok(path: str) -> bool:
    """这一份 .gz 能不能发出去: 体积过门槛 + gzip 魔数对。

    只看 `os.path.exists` 会把 0 字节 / 半截 / 旧版本的文件发出去 —— 路由器
    `gunzip` 失败, 而 `perf_ready` 那边又会认为"已缓存", 于是一直不重下。
    """
    try:
        if os.path.getsize(path) < _perf_min_size():
            return False
        with open(path, "rb") as fh:
            return fh.read(2) == b"\x1f\x8b"
    except OSError:
        return False


def perf_cached_file(arch: str) -> str:
    """返回实际要发出去的那一份 (优先精确版本号那个文件名)。"""
    path = perf_file(arch)
    if _perf_file_ok(path):
        return path
    try:
        names = os.listdir(perf_dir())
    except OSError:
        return path
    for name in _perf_candidates(names, arch):
        candidate = os.path.join(perf_dir(), name)
        if _perf_file_ok(candidate):
            return candidate
    return path


def perf_asset_url(arch: str) -> str:
    name = PERF_ASSET.get(arch)
    if not name:
        raise ValueError(f"不支持的架构: {arch}")
    return f"https://github.com/daeuniverse/dae/releases/download/{PERF_VERSION}/{name}"


def cached_perf() -> list[dict]:
    return [
        {"arch": arch, "label": ARCH_LABEL.get(arch, arch), "size": os.path.getsize(perf_cached_file(arch))}
        for arch in PERF_ASSET
        if perf_ready(arch)
    ]


def _extract_dae(archive_path: str, dest_bin: str) -> tuple[bool, str]:
    """从上游的 tar.xz 里取出 dae 二进制。

    上游的目录结构**不是**契约 (它自己也可能改), 所以按"文件名正好是 dae 的优先, 否则取
    最大的那个文件"来找, 并且最后只认 ELF —— 取错文件在这里挡住, 总比发到路由器上
    "chmod +x 后一执行就报 Exec format error"要好 (真机上学过一次)。
    """
    import tarfile

    #: 单个成员解出来最多这么大: 压缩炸弹 (高压缩比 tar.xz, 或 tar 头虚报 size) 能把
    #: data 盘写满, 而那目录里有面板的全部状态。
    limit = 256 << 20
    written = 0
    member = None
    try:
        with tarfile.open(archive_path, "r:xz") as tf:
            for item in tf:
                if not item.isfile():
                    continue
                if os.path.basename(item.name) == "dae":
                    member = item
                    break
                if member is None or item.size > member.size:
                    member = item
            if member is None:
                return False, "压缩包里没有文件"
            if member.size and member.size > limit:
                return False, (
                    f"压缩包里的 {member.name} 解出来有 {member.size // 1048576} MB, "
                    "超过上限 (不像一个 dae 二进制)"
                )
            handle = tf.extractfile(member)
            if handle is None:
                return False, f"读不到压缩包里的 {member.name}"
            with open(dest_bin, "wb") as fh:
                while True:
                    chunk = handle.read(1 << 20)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > limit:
                        return False, "解出来的内容超过上限 (疑似压缩炸弹)"
                    fh.write(chunk)
    except (tarfile.TarError, OSError, EOFError) as exc:
        return False, f"解包失败: {exc}"
    size = os.path.getsize(dest_bin)
    if size < PERF_MIN_BYTES:
        return False, f"解出来的文件只有 {size // 1024} KB (不像 dae)"
    with open(dest_bin, "rb") as fh:
        if fh.read(4) != b"\x7fELF":
            return False, "解出来的不是 ELF 可执行文件"
    return True, f"{os.path.basename(member.name)} · {size // 1024 // 1024} MB"


def fetch_perf(arch: str, *, deadline: float | None = None) -> tuple[bool, str, str]:
    """取 dae: 上游 tar.xz → 解出二进制 → 压成 .gz 落盘。返回 (ok, 说明, 路径)。"""
    if arch not in PERF_ASSET:
        return False, f"不支持的架构: {arch}", ""
    dst = perf_file(arch)
    if perf_ready(arch):
        return True, "已缓存", perf_cached_file(arch)

    if deadline is None:
        deadline = time.time() + PERF_DEADLINE
    os.makedirs(perf_dir(), exist_ok=True)
    tar_path = dst + ".tar.xz"
    bin_path = dst + ".bin"
    url = perf_asset_url(arch)
    errors: list[str] = []
    try:
        downloaded = False
        for template in MIRRORS:
            left = deadline - time.time()
            if left <= 2:
                errors.append(f"总时间超限 ({PERF_DEADLINE}s)")
                break
            source = template.format(url=url)
            tmp = tar_path + ".part"
            try:
                request = urllib.request.Request(source, headers={"User-Agent": UA})
                with urllib.request.urlopen(request, timeout=_budget_for(template, left, PERF_SOURCE_TIMEOUT)) as resp:
                    status = getattr(resp, "status", 200)
                    if status is not None and status != 200:
                        errors.append(f"{source} HTTP {status}")
                        continue
                    size = 0
                    with open(tmp, "wb") as fh:
                        while True:
                            if time.time() > deadline:
                                raise TimeoutError(f"总时间超限 ({PERF_DEADLINE}s)")
                            chunk = resp.read(1 << 18)
                            if not chunk:
                                break
                            fh.write(chunk)
                            size += len(chunk)
                if size < (PERF_MIN_BYTES // 2):
                    errors.append(f"{source} 体积异常 ({size} 字节)")
                    continue
                # 与 mihomo 内核同一条闸门: 上游 tar.xz 的官方摘要必须对得上。
                good, why = verify_asset(tmp, PERF_ASSET.get(arch, ""), kind="dae 性能内核")
                if not good:
                    errors.append(f"{source} {why}")
                    continue
                os.replace(tmp, tar_path)
                downloaded = True
                break
            except (urllib.error.URLError, OSError, TimeoutError) as exc:
                errors.append(f"{source} {exc}")
            finally:
                if os.path.exists(tmp):
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass
        if not downloaded:
            return False, "; ".join(errors)[-300:], ""

        ok, detail = _extract_dae(tar_path, bin_path)
        if not ok:
            return False, detail, ""
        # 重新压成 .gz: 路由器上只有 busybox, gzip 一定有而 xz 不保证。
        # 落盘必须是 tmp + rename: 直接写 dst 时, 中断/ENOSPC 留下的半个 .gz 体积
        # 仍高于 perf_ready 的门槛 (PERF_MIN_BYTES//4 = 1.5 MB, 真实约 8 MB),
        # 于是它被当成"已缓存", fetch_perf 永远返回"已缓存", 路由器再也拿不到好内核。
        import gzip

        part = dst + ".part"
        try:
            with open(bin_path, "rb") as src, gzip.open(part, "wb") as out:
                while True:
                    chunk = src.read(1 << 20)
                    if not chunk:
                        break
                    out.write(chunk)
            os.replace(part, dst)
        finally:
            if os.path.exists(part):
                try:
                    os.remove(part)
                except OSError:
                    pass
        return True, f"已就绪 ({detail})", dst
    finally:
        for leftover in (tar_path, bin_path):
            if os.path.exists(leftover):
                try:
                    os.remove(leftover)
                except OSError:
                    pass


def perf_state(arch: str) -> dict:
    if perf_ready(arch):
        try:
            size = os.path.getsize(perf_cached_file(arch))
        except OSError:
            size = 0
        return {"arch": arch, "state": "ready", "detail": "面板已缓存", "bytes": size, "error": ""}
    entry = PERF_STATE.get(arch) or {}
    return {
        "arch": arch,
        "state": entry.get("state") or "missing",
        "detail": entry.get("detail") or "",
        "bytes": int(entry.get("bytes") or 0),
        "error": entry.get("error") or "",
    }


def perf_pending_text(arch: str) -> str:
    st = perf_state(arch)
    if st["state"] == "error":
        return f"面板取性能模式内核失败: {st['error'] or st['detail']}"
    if st["state"] == "downloading":
        return (
            f"面板正在准备 {arch} 的性能模式内核 (dae {PERF_VERSION}, 首次要从上游取约 10 MB)。"
            f"这不是错误 —— 稍后会自动重试。"
        )
    return "面板正在准备性能模式内核, 稍后会自动重试。"


def ensure_perf_async(arch: str) -> dict:
    """确保有一份 dae 正在取, **不阻塞**调用方 (与内核那条路同一个理由)。"""
    if arch not in PERF_ASSET:
        return {"arch": arch, "state": "unknown", "detail": f"不支持的架构: {arch}",
                "bytes": 0, "error": f"不支持的架构: {arch}"}
    if perf_ready(arch):
        return perf_state(arch)
    with PERF_LOCK:
        entry = PERF_STATE.setdefault(arch, {})
        wedged = (
            entry.get("state") == "downloading"
            and time.time() - float(entry.get("started") or 0) > max(120, PERF_DEADLINE * 3)
        )
        if entry.get("state") == "downloading" and not wedged:
            return perf_state(arch)
        if entry.get("state") == "error" and time.time() - float(entry.get("done") or 0) < PERF_RETRY_AFTER:
            return perf_state(arch)
        entry.update({"state": "downloading", "detail": "正在从上游下载", "bytes": 0,
                      "error": "", "started": int(time.time()), "done": 0})
    try:
        threading.Thread(
            target=_prefetch_perf, args=(arch,), daemon=True, name=f"zp-perf-{arch}"
        ).start()
    except Exception as exc:  # noqa: BLE001
        with PERF_LOCK:
            PERF_STATE.setdefault(arch, {}).update(
                {"state": "error", "error": f"无法启动后台任务: {exc}", "done": int(time.time())}
            )
    return perf_state(arch)


def _prefetch_perf(arch: str) -> None:
    try:
        ok, detail, _path = fetch_perf(arch)
    except Exception as exc:  # 后台线程不能死得无声无息
        ok, detail = False, f"取性能模式内核时出错了: {exc}"
    with PERF_LOCK:
        entry = PERF_STATE.setdefault(arch, {})
        entry["state"] = "ready" if ok else "error"
        entry["detail"] = detail
        entry["error"] = "" if ok else detail
        entry["done"] = int(time.time())


# ---------------------------------------------------------------- 安装脚本
def script_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "client", "router-install.sh")


#: 路由器管理界面会用到的文件 (由面板分发, 路由器只负责落盘 —— 于是界面的更新
#: 只要重跑一次安装命令, 不需要重新打包客户端)。
#: 键 = URL 里的名字, 值 = (相对 client/luci 的路径, media_type)
UI_FILES: dict[str, tuple[str, str]] = {
    "index.html": ("index.html", "text/html; charset=utf-8"),
    "app.js": ("app.js", "text/javascript; charset=utf-8"),
    # 性能模式那块仪表盘 (跑车表盘 + 进入动画)。单独一个文件: 那是一整段独立的动画与
    # 状态机, 塞进 app.js 只会让两个都难读。
    "perf.js": ("perf.js", "text/javascript; charset=utf-8"),
    "cgi": ("cgi", "text/plain; charset=utf-8"),
    "menu.json": ("menu.json", "application/json; charset=utf-8"),
    "acl.json": ("acl.json", "application/json; charset=utf-8"),
    "status.js": ("status.js", "text/javascript; charset=utf-8"),
}


def ui_file(name: str) -> tuple[str, str, str] | None:
    """读取一个界面文件。返回 (正文, media_type, 文件名), 未登记的名字返回 None。

    只允许白名单里的名字 —— 这个端点是匿名可达的 (路由器安装时来取), 所以绝不能
    接受任意路径 (否则就是给面板开了个任意文件读取)。
    """
    entry = UI_FILES.get(name)
    if not entry:
        return None
    rel, media = entry
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "client", "luci", rel)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read(), media, os.path.basename(rel)
    except OSError:
        return None      # 白名单里有、但包里没这个文件 → 404, 不是 500


# ---------------------------------------------------------------- 运行时装机件 (client/runtime/)
# 这些是安装脚本**以前用 heredoc 现场生成**的文件: live.sh / nft 规则 / 数据面脚本
# (redirect / tunfw / perf) / 控制 agent / 运维 CLI / 三个 init 脚本。它们一直是客户端里
# 最要命的那部分, 却因为"长在 heredoc 里"而没法单独 shellcheck、没法单测, 安装脚本自己
# 也长成一个 5000 行的单体。现在它们是仓库里版本化的文件, 跟着面板分发 —— 与内核 / 分流
# 数据 / zpcore 同一条路 (路由器只访问面板一个地址)。
#
# 名字走白名单: 这个端点匿名可达 (装机时路由器还没有凭据), 不能变成任意文件读取。
# 内容不含任何机密 —— 就是脚本本身。
RUNTIME_FILES = (
    "live.sh",
    "tproxy.nft",
    "redirect.sh",
    "tunfw.sh",
    "perf.sh",
    "agent.sh",
    "cli",
    "zeroproxy.init",
    "zeroproxy-agent.init",
    "zeroproxy-perf.init",
)


def runtime_dir() -> str:
    # ZP_RUNTIME_DIR 是给演练用的 (与 ZP_AGENT_DIR 同一个用法): 真机上是 client/runtime/;
    # 演练要把整套东西装到临时根目录里跑, 所以它会指到一份"路径已改写"的副本上。
    explicit = os.environ.get("ZP_RUNTIME_DIR", "").strip()
    if explicit:
        return explicit
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "client", "runtime")


def runtime_file(name: str) -> tuple[str, str] | None:
    """读一份运行时装机件。返回 (正文, 文件名), 未登记的名字返回 None。

    `__ZP_CLIENT_VERSION__` 在这里替换成真实版本 (与 render_script 对安装脚本做的是同一步),
    于是客户端拿到的就是能直接落盘的正文; 机器相关的 `__ZP_LANIF__` 留给客户端替换 ——
    面板不知道对面是哪一台机器、它的局域网接口叫什么。
    """
    if name not in RUNTIME_FILES:
        return None
    path = os.path.join(runtime_dir(), name)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            body = fh.read()
    except OSError:
        return None
    return body.replace("__ZP_CLIENT_VERSION__", SCRIPT_VERSION), name


#: 装机件的落盘模式: 要执行的那几个 755, 其余 644。
def _runtime_mode(name: str) -> int:
    return 0o755 if (name.endswith(".sh") or name.endswith(".init") or name == "cli") else 0o644


def runtime_bundle() -> bytes | None:
    """整套运行时装机件打成一个 tar.gz —— 装机时**一次取回**, 而不是十几次。

    为什么要有它: 这些文件有十几个, 而用户到面板的线路会丢包 (真机实测: 同一条命令里
    第一跳就超时过一次)。每多一次往返就多一次失败机会, 十几次串起来 (每次还带 5 次重试)
    在丢包的线上能耗掉好几分钟 —— 真机上就是卡在 `落运行时装机件` 那一行不动。
    打成一个包, "面板这条路"从十几次失败机会压成一次。

    取不到任何一份就返回 None (面板侧不完整), 客户端会退回"逐个取"。
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name in RUNTIME_FILES:
            got = runtime_file(name)
            if got is None:
                return None
            raw = got[0].encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            info.mode = _runtime_mode(name)
            info.mtime = 0
            tar.addfile(info, io.BytesIO(raw))
    return buf.getvalue()


def render_script(base: str, code: str) -> str:
    """把面板地址与配对码烘进安装脚本。

    两个值都只出现在脚本头部被双引号包住的赋值里; `base` 来自面板自己的配置
    (域名 + 端口), `code` 是我们自己生成的十六进制串, 所以不存在注入面 ——
    但仍然在这里挡一道: 出现双引号/反引号/换行就直接拒绝渲染。
    """
    for value in (base, code):
        if any(ch in value for ch in '"`$\n\\'):
            raise ValueError("安装脚本参数包含非法字符")
    with open(script_path(), "r", encoding="utf-8") as fh:
        text = fh.read()
    return (
        text.replace("__ZP_BASE__", base)
        .replace("__ZP_CODE__", code)
        .replace("__ZP_CLIENT_VERSION__", SCRIPT_VERSION)
    )


def install_script_sha256(base: str, code: str) -> str:
    """面板要下发的安装脚本文本的 sha256 (响应头 `X-ZP-Install-Sha256`)。

    路由器端 (CLI 的 update) 拿到之后**执行前**比对: 面板这一跳被换掉、正文传了一半,
    都会在这里暴露。必须与正文逐字节对应 —— 所以这里走的是同一条 render_script。
    """
    return sha256_hex(render_script(base, code).encode("utf-8"))


def summary() -> dict:
    """面板卡片要展示的元信息。"""
    return {
        "script_version": SCRIPT_VERSION,
        "core_version": CORE_VERSION,
        "arches": [{"id": a, "label": ARCH_LABEL.get(a, a)} for a in ARCHES],
        "cached": cached_arches(),
        # 每一档内核现在的状态 (missing / downloading / ready / error):
        # 面板上那张卡片要能回答"现在发这条安装命令, 会不会卡在下载内核上"。
        "cores": core_states(),
        # 本地控制面 (zpcore) —— 可选件: 有它时路由器自己起界面服务, 不再依赖固件的
        # Web 服务器; 没有它只是回到原来的路径, 不影响代理。
        "agent_version": AGENT_VERSION,
        "agents": cached_agents(),
        "geo": cached_geo(),
        "geo_names": list(GEO_FILES),
        "cached_at": int(time.time()),
    }


# ---------------------------------------------------------------- 本地控制面 (zpcore)
#
# 路由器管理界面原来有三条路 (固件 Web 服务 / 它的 cgi / 退回 busybox httpd), 三种坏法各
# 踩过一次真机。zpcore 把这一段收回自己手里: 一个静态二进制, 自己起服务、自己校验令牌、
# 自己只绑局域网地址 —— "界面能不能打开"从此与固件无关。
#
# 分发方式与 mihomo 内核**刻意做成同一种形态**: 面板直传一个 .gz, 路由器端 gzip -t 判定
# → 解压 → 跑一次 `version` 校验 → 落盘。那段代码刚在内核那条路上跑过七次真机, 直接复用。
#
# 与内核唯一的区别: zpcore 是我们自己的东西, 没有上游可下载, 所以产物跟着**仓库**走
# (scripts/build-agent.sh 生成到 client/agent/dist/), 不是 data/ 缓存。它是可选件 ——
# 面板没准备某一档时, 那台路由器自动退回原来的界面路径, 装机不会失败。
#: 本地控制面 (zpcore) 的版本。**改了 agent/ 下的 Go 就必须抬它** (并重跑
#: scripts/build-agent.sh 把 dist/ 里的制品换掉): 面板按版本号挑文件, 不换版本的话
#: 路由器会一直拿到旧二进制, 而"界面少了一块表盘 / 少一种模式"这种问题在真机上极难看出来。
#: 1.2.2: 认性能模式 (dae) 这一档 —— mode=ebpf / covered=full, status 多一组 perf 字段
#:        与 WAN 字节数, 并多分发一个 perf.js (那块跑车仪表盘)。
#: 1.3.0: zpcore 成了**状态的唯一生产者** (`zpcore state`): 一处解析 caps、一处探现场、
#:        一处算覆盖, 本地界面与 shell (live.sh / agent.sh) 都从它取 —— 以前这份状态被
#:        四处各拼一遍, 真机上漂过 (8.88)。新增 `state [--json]` 子命令与 --dir/--cli/--init
#:        通用选项; `serve` 的 status 与 `state` 由同一份 snapshot 组装 (8.91)。
#: 1.3.1: 接受真实 ubus 的有效会话响应 `{"values":{}}`; 修改动作拒绝 GET。
#: 1.3.2: LuCI 会话再验一层身份 —— `username` 必须是 root 或该会话的 ACL 放行
#:        (多账号固件上, 被 ACL 限制的账号以前能借用 root 的 cgi 执行 update/perf);
#:        两个入口 (cgi / zpcore) 都补 X-Frame-Options / CSP frame-ancestors / nosniff;
#:        cgi status 补 packets 字段; zpcore 认 PATH_INFO 里的动作名 (与 cgi 对齐)。
AGENT_VERSION = os.environ.get("ZP_AGENT_VERSION", "1.3.2")

#: 小于这个大小的一律不当二进制 (一份正常的 zpcore.gz 约 2.5 MB)。演练里可以用
#: ZP_AGENT_MIN_BYTES 调低。
AGENT_MIN_BYTES = _env_int("ZP_AGENT_MIN_BYTES", str(256 << 10))


def agent_dir() -> str:
    explicit = os.environ.get("ZP_AGENT_DIR", "").strip()
    if explicit:
        return explicit
    return os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "client", "agent", "dist"
    )


def agent_file(arch: str) -> str:
    return os.path.join(agent_dir(), f"zpcore-{arch}-{AGENT_VERSION}.gz")


def agent_ready(arch: str) -> bool:
    if arch not in ARCHES:
        return False
    try:
        return os.path.getsize(agent_file(arch)) >= AGENT_MIN_BYTES
    except OSError:
        return False


def cached_agents() -> list[dict]:
    """面板上有哪几档 zpcore 制品 (面板卡片展示用)。"""
    out = []
    for arch in ARCHES:
        try:
            size = os.path.getsize(agent_file(arch))
        except OSError:
            continue
        if size < AGENT_MIN_BYTES:
            continue
        out.append({"arch": arch, "label": ARCH_LABEL.get(arch, arch), "size": size})
    return out
