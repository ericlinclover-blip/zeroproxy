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
    while iptables -t nat -D PREROUTING -i "$_if" -j zp_router 2>/dev/null; do :; done
    iptables -t nat -F zp_router 2>/dev/null || true
    iptables -t nat -X zp_router 2>/dev/null || true
    if command -v ip6tables >/dev/null 2>&1; then
        while ip6tables -t nat -D PREROUTING -i "$_if" -j zp_router 2>/dev/null; do :; done
        ip6tables -t nat -F zp_router 2>/dev/null || true
        ip6tables -t nat -X zp_router 2>/dev/null || true
    fi
}

zp_redirect_apply() {
    command -v iptables >/dev/null 2>&1 || return 1
    _if="$(zp_redirect_iface)"
    zp_redirect_clear
    iptables -t nat -N zp_router 2>/dev/null || return 1
    # 私有 / 保留地址直连: 局域网互访、管理页面、以及 mihomo 自己都不该被绕一圈。
    for _net in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16                 172.16.0.0/12 192.0.0.0/24 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4                 198.18.0.0/16; do
        iptables -t nat -A zp_router -d "$_net" -j RETURN
    done
    # 已标记的 (mihomo 自己的出站) 直连 —— 否则会成环。
    iptables -t nat -A zp_router -m mark --mark 0x1ff -j RETURN
    # 代理端口本身的入站不再被劫持 (否则内核与内核自己绕圈)。
    iptables -t nat -A zp_router -p tcp --dport 7890 -j RETURN
    iptables -t nat -A zp_router -p tcp --dport "$ZP_REDIR_PORT" -j RETURN
    # DNS 先劫持 (fake-ip 才能按域名分流; TCP 53 也一起)。
    iptables -t nat -A zp_router -p udp --dport 53 -j REDIRECT --to-ports "$ZP_DNS_PORT"
    iptables -t nat -A zp_router -p tcp --dport 53 -j REDIRECT --to-ports "$ZP_DNS_PORT"
    # 其余 TCP 进 redir-port。
    iptables -t nat -A zp_router -p tcp -j REDIRECT --to-ports "$ZP_REDIR_PORT"
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
        ip6tables -t nat -N zp_router 2>/dev/null || return 0
        for _net6 in ::1/128 fc00::/7 fe80::/10 ff00::/8; do
            ip6tables -t nat -A zp_router -d "$_net6" -j RETURN
        done
        ip6tables -t nat -A zp_router -m mark --mark 0x1ff -j RETURN
        ip6tables -t nat -A zp_router -p tcp --dport 7890 -j RETURN
        ip6tables -t nat -A zp_router -p tcp --dport "$ZP_REDIR_PORT" -j RETURN
        ip6tables -t nat -A zp_router -p udp --dport 53 -j REDIRECT --to-ports "$ZP_DNS_PORT"
        ip6tables -t nat -A zp_router -p tcp --dport 53 -j REDIRECT --to-ports "$ZP_DNS_PORT"
        ip6tables -t nat -A zp_router -p tcp -j REDIRECT --to-ports "$ZP_REDIR_PORT"
        if ! ip6tables -t nat -I PREROUTING -i "$_if" -j zp_router 2>/dev/null; then
            ip6tables -t nat -F zp_router 2>/dev/null || true
            ip6tables -t nat -X zp_router 2>/dev/null || true
        fi
    fi
    return 0
}

zp_redirect_live() { iptables -t nat -L zp_router >/dev/null 2>&1; }

# 这一档能不能一并接管 IPv6 (没有 ip6tables 的老固件不行)。给安装脚本写 caps 用。
zp_redirect_v6() { command -v ip6tables >/dev/null 2>&1 && return 0 || return 1; }
