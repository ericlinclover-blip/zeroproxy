#!/bin/sh
# ZeroProxy iptables REDIRECT 数据面 (局域网 TCP 透明代理)。
# 由安装脚本生成, 请勿手改 —— 重跑安装命令会覆盖。
ZP_REDIR_PORT=7892
ZP_DNS_PORT=7874
ZP_LANIF="__ZP_LANIF__"

# 局域网接口名。装机时确定不下来 (没有 uci / 接口还没起来) 就退回 br-lan —— 但绝不
# 退化成"所有接口": 那会把 WAN 侧入站也接管, 是比不接管更糟的结果。
zp_redirect_iface() {
    if [ -n "$ZP_LANIF" ]; then printf '%s' "$ZP_LANIF"; return 0; fi
    _d="$(uci -q get network.lan.device 2>/dev/null || uci -q get network.lan.ifname 2>/dev/null || true)"
    [ -n "$_d" ] || _d=br-lan
    printf '%s' "$_d"
}

# 只撤自己的那条链 (zp_router): 别人的规则一条不碰。
zp_redirect_clear() {
    _if="$(zp_redirect_iface)"
    _n=0
    while [ "$_n" -lt 8 ] && iptables -t nat -D PREROUTING -i "$_if" -j zp_router 2>/dev/null; do _n=$((_n + 1)); done
    iptables -t nat -F zp_router 2>/dev/null || true
    iptables -t nat -X zp_router 2>/dev/null || true
    if command -v ip6tables >/dev/null 2>&1; then
        _n=0
        while [ "$_n" -lt 8 ] && ip6tables -t nat -D PREROUTING -i "$_if" -j zp_router 2>/dev/null; do _n=$((_n + 1)); done
        ip6tables -t nat -F zp_router 2>/dev/null || true
        ip6tables -t nat -X zp_router 2>/dev/null || true
    fi
    for _guard_tool in iptables ip6tables; do
        command -v "$_guard_tool" >/dev/null 2>&1 || continue
        _n=0
        while [ "$_n" -lt 8 ] && "$_guard_tool" -t filter -D FORWARD -i "$_if" -j zp_udp_guard 2>/dev/null; do _n=$((_n + 1)); done
        "$_guard_tool" -t filter -F zp_udp_guard 2>/dev/null || true
        "$_guard_tool" -t filter -X zp_udp_guard 2>/dev/null || true
        _n=0
        while [ "$_n" -lt 8 ] && "$_guard_tool" -t nat -D OUTPUT -j zp_dns_out 2>/dev/null; do _n=$((_n + 1)); done
        "$_guard_tool" -t nat -F zp_dns_out 2>/dev/null || true
        "$_guard_tool" -t nat -X zp_dns_out 2>/dev/null || true
    done
}

# TCP-only 数据面不能转发公网 UDP：明确拒绝，防止 QUIC/STUN 绕过代理。
# 局域网 UDP（DHCP、发现、投屏等）不受影响；语音/游戏需要 TUN/TPROXY。
zp_redirect_guard() {
    for _guard_tool in iptables ip6tables; do
        command -v "$_guard_tool" >/dev/null 2>&1 || continue
        if [ "$_guard_tool" = iptables ]; then
            _guard_nets="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4"
        else
            _guard_nets="::1/128 fc00::/7 fe80::/10 ff00::/8"
        fi
        "$_guard_tool" -t filter -N zp_udp_guard || return 1
        "$_guard_tool" -t nat -N zp_dns_out || return 1
        "$_guard_tool" -t nat -A zp_dns_out -m mark --mark 0x1ff -j RETURN || return 1
        for _guard_net in $_guard_nets; do
            "$_guard_tool" -t filter -A zp_udp_guard -d "$_guard_net" -j RETURN || return 1
            "$_guard_tool" -t nat -A zp_dns_out -d "$_guard_net" -j RETURN || return 1
        done
        if ! grep -q '^# 分流模板: direct ' "${ZP_DIR:-/etc/zeroproxy}/config.yaml" 2>/dev/null; then
            "$_guard_tool" -t filter -A zp_udp_guard -p udp -j REJECT || return 1
        fi
        "$_guard_tool" -t filter -I FORWARD -i "$_if" -j zp_udp_guard || return 1
        "$_guard_tool" -t nat -A zp_dns_out -p udp --dport 53 -j REDIRECT --to-ports "$ZP_DNS_PORT" || return 1
        "$_guard_tool" -t nat -A zp_dns_out -p tcp --dport 53 -j REDIRECT --to-ports "$ZP_DNS_PORT" || return 1
        "$_guard_tool" -t nat -I OUTPUT -j zp_dns_out || return 1
    done
}

zp_redirect_apply() {
    command -v iptables >/dev/null 2>&1 || return 1
    _if="$(zp_redirect_iface)"
    zp_redirect_clear
    iptables -t nat -N zp_router 2>/dev/null || return 1
    # 私有 / 保留地址直连: 局域网互访、管理页面、以及 mihomo 自己都不该被绕一圈。
    for _net in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16                 172.16.0.0/12 192.0.0.0/24 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4; do
        iptables -t nat -A zp_router -d "$_net" -j RETURN || { zp_redirect_clear; return 1; }
    done
    # 已标记的 (mihomo 自己的出站) 直连 —— 否则会成环。
    iptables -t nat -A zp_router -m mark --mark 0x1ff -j RETURN || { zp_redirect_clear; return 1; }
    # 本机代理监听已由目的地址放行；不能按端口豁免公网目的地址。
    # DNS 先劫持 (fake-ip 才能按域名分流; TCP 53 也一起)。
    iptables -t nat -A zp_router -p udp --dport 53 -j REDIRECT --to-ports "$ZP_DNS_PORT" || { zp_redirect_clear; return 1; }
    iptables -t nat -A zp_router -p tcp --dport 53 -j REDIRECT --to-ports "$ZP_DNS_PORT" || { zp_redirect_clear; return 1; }
    # 其余 TCP 进 redir-port。
    iptables -t nat -A zp_router -p tcp -j REDIRECT --to-ports "$ZP_REDIR_PORT" || { zp_redirect_clear; return 1; }
    # 只从局域网接口进来 —— 路由器自身与 WAN 入站不接管。
    # 接口名不对 (设备上没有这个接口) 时这一步会失败: 那就把刚建的链撤掉并**如实返回
    # 失败** —— 让装机时的验证判它"没生效", 而不是留下一条指向空气的规则。
    if ! iptables -t nat -I PREROUTING -i "$_if" -j zp_router 2>/dev/null; then
        zp_redirect_clear
        return 1
    fi
    # IPv6 那一半 (同一套规则, 换 ip6tables)。**没有 ip6tables 就不做** —— 那一档会被
    # 如实记进 caps (ipv6=0), 面板上会写"IPv6 未接管", 而不是假装全接管了。
    if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -t nat -N zp_router 2>/dev/null || { zp_redirect_clear; return 1; }
        for _net6 in ::1/128 fc00::/7 fe80::/10 ff00::/8; do
            ip6tables -t nat -A zp_router -d "$_net6" -j RETURN || { zp_redirect_clear; return 1; }
        done
        ip6tables -t nat -A zp_router -m mark --mark 0x1ff -j RETURN || { zp_redirect_clear; return 1; }
        ip6tables -t nat -A zp_router -p udp --dport 53 -j REDIRECT --to-ports "$ZP_DNS_PORT" || { zp_redirect_clear; return 1; }
        ip6tables -t nat -A zp_router -p tcp --dport 53 -j REDIRECT --to-ports "$ZP_DNS_PORT" || { zp_redirect_clear; return 1; }
        ip6tables -t nat -A zp_router -p tcp -j REDIRECT --to-ports "$ZP_REDIR_PORT" || { zp_redirect_clear; return 1; }
        if ! ip6tables -t nat -I PREROUTING -i "$_if" -j zp_router 2>/dev/null; then
            zp_redirect_clear
            return 1
        fi
    fi
    if ! zp_redirect_guard; then
        zp_redirect_clear
        return 1
    fi
    return 0
}

zp_redirect_live() { iptables -t nat -L zp_router >/dev/null 2>&1; }

# 这一档能不能一并接管 IPv6 (没有 ip6tables 的老固件不行)。给安装脚本写 caps 用。
zp_redirect_v6() { command -v ip6tables >/dev/null 2>&1 && return 0 || return 1; }
