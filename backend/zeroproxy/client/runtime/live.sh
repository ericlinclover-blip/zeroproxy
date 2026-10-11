#!/bin/sh
# ZeroProxy · 数据面"现场"的唯一判据 (谁在接管 / 覆盖到哪)。
#
# 为什么单独一个文件: "现在哪一级真的在接管"这个问题, 安装脚本 / 控制 agent (心跳) /
# 运维 CLI (status / doctor) / 本地界面 (zpcore) 都要回答一次。以前它们各写一遍同样的
# 判据, 靠注释里的"必须一致"维持 —— 真机上已经漂了: 性能模式 (eBPF / dae) 下 mihomo 是
# 停的, 而 CLI 的 status 只看 zp-tun / nft / iptables, 于是报"未生效"; doctor 也把在跑的
# dae 说成"服务没在跑"。现在只有这一份: 改判据改这里, 四处一起变, 谁都不许再抄一遍。
#
# 判据一律是**现场** (进程在不在 / 设备在不在 / 表在不在), 不是 caps 里的意图 —— 这是
# "永不撒谎"的那一半。
ZP_LL_DIR="${ZP_DIR:-/etc/zeroproxy}"

# 从"唯一的生产者" (zpcore state) 取一个字段。两处来源, 按优先级:
#   1. 调用方已经把整份状态取下来了 (agent 每轮取一次, 存进 $ZP_STATE) —— 直接读文件,
#      不额外 fork;
#   2. zpcore 在 → 问它 (`zpcore state`)。它一处解析 caps、一处探现场、一处算覆盖;
# 都拿不到 (zpcore 不在的机器 / 装机中途) 才用下面的内联判据 —— zpcore 仍是可选件。
zp_state_field() {  # $1 = 键名
    if [ -n "${ZP_STATE:-}" ] && [ -r "$ZP_STATE" ]; then
        sed -n "s/^$1=//p" "$ZP_STATE" | head -n1
        return 0
    fi
    _zc="${ZP_DIR:-/etc/zeroproxy}/zpcore"
    if [ -x "$_zc" ]; then
        "$_zc" state --dir "${ZP_DIR:-/etc/zeroproxy}" --init /etc/init.d/zeroproxy 2>/dev/null \
            | sed -n "s/^$1=//p" | head -n1
        return 0
    fi
    return 1
}

# dae (性能模式内核) 现在在不在。判据复用性能模式自己那一份 (perf.sh 的 zp_perf_live:
# 进程优先, 服务兜底) —— 不在这里另写一遍; 用**子 shell** source, 免得它的函数名/变量
# 污染调用方 (agent.sh 自己也定义了 log())。perf.sh 不在就退回 pidof。
zp_dae_running() {
    if [ -r "$ZP_LL_DIR/perf.sh" ]; then
        if ( . "$ZP_LL_DIR/perf.sh" 2>/dev/null; zp_perf_live ); then return 0; fi
        return 1
    fi
    pidof dae >/dev/null 2>&1
}

# 某一级现在真的在不在 (安装脚本的 wait_datapath / datapath_live 读它)。
zp_level_live() {
    case "$1" in
        ebpf)     zp_dae_running ;;
        tun)      ip link show zp-tun >/dev/null 2>&1 ;;
        tproxy)   command -v nft >/dev/null 2>&1 && nft list table inet zp_router >/dev/null 2>&1 ;;
        redirect) command -v iptables >/dev/null 2>&1 && iptables -t nat -L zp_router >/dev/null 2>&1 ;;
        *)        return 1 ;;
    esac
}

# 现在哪一级在接管 (从优到劣)。输出 ebpf|tun|tproxy|redirect|none。
# 先问唯一的生产者; 问不到才用内联判据 (zpcore 不在的机器 / 装机中途)。
zp_live_mode() {
    _m="$(zp_state_field mode 2>/dev/null)"
    if [ -n "$_m" ]; then printf '%s' "$_m"; return 0; fi
    if zp_dae_running; then printf 'ebpf'; return 0; fi
    if ip link show zp-tun >/dev/null 2>&1; then printf 'tun'; return 0; fi
    if command -v nft >/dev/null 2>&1 && nft list table inet zp_router >/dev/null 2>&1; then
        printf 'tproxy'; return 0
    fi
    if command -v iptables >/dev/null 2>&1 && iptables -t nat -L zp_router >/dev/null 2>&1; then
        printf 'redirect'; return 0
    fi
    printf 'none'
}

# 上面那一级**覆盖到哪**: full (含本机) / lan (全屋, 本机除外) / lan_tcp / none。
# 同样先问生产者 (它一处算); 问不到才在本地做那份映射。
zp_live_covered() {
    _c="$(zp_state_field covered 2>/dev/null)"
    if [ -n "$_c" ]; then printf '%s' "$_c"; return 0; fi
    case "$(zp_live_mode)" in
        ebpf|tun) printf 'full' ;;
        tproxy)   printf 'lan' ;;
        redirect) printf 'lan_tcp' ;;
        *)        printf 'none' ;;
    esac
}
