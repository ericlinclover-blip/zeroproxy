#!/bin/sh
# TPROXY 需要策略路由将标记包送回 lo；代理出站使用不同标记 0x1ff。
# 20290 为 ZeroProxy 专用表/优先级，只回收自己的精确规则与路由。
zp_tproxy_clear() {
    nft delete table inet zp_router 2>/dev/null || true
    for _zp_family in 4 6; do
        _zp_n=0
        while [ "$_zp_n" -lt 8 ]; do
            ip -"$_zp_family" rule del priority 20290 fwmark 0x1fe/0xffffffff lookup 20290 2>/dev/null || break
            _zp_n=$((_zp_n + 1))
        done
    done
    ip -4 route del local 0.0.0.0/0 dev lo table 20290 2>/dev/null || true
    ip -6 route del local ::/0 dev lo table 20290 2>/dev/null || true
    return 0
}

zp_tproxy_apply() {
    _zp_dir="${ZP_DIR:-/etc/zeroproxy}"
    zp_tproxy_clear
    if ! ip -4 route replace local 0.0.0.0/0 dev lo table 20290 ||
       ! ip -4 rule add priority 20290 fwmark 0x1fe/0xffffffff lookup 20290; then
        zp_tproxy_clear
        return 1
    fi
    _zp_v6="$(sed -n 's/^ipv6=//p' "$_zp_dir/caps" 2>/dev/null | head -n1)"
    if [ "$_zp_v6" = 1 ]; then
        if ! ip -6 route replace local ::/0 dev lo table 20290 ||
           ! ip -6 rule add priority 20290 fwmark 0x1fe/0xffffffff lookup 20290; then
            zp_tproxy_clear
            return 1
        fi
    fi
    _zp_rules="$_zp_dir/.tproxy.$$.nft"
    if [ "$_zp_v6" = 1 ]; then
        cp "$_zp_dir/tproxy.nft" "$_zp_rules" || { zp_tproxy_clear; return 1; }
    else
        # 没有 IPv6 TPROXY 时拒绝公网 IPv6 转发，让双栈应用回落 IPv4；不改系统 IPv6。
        _zp_v6_guard='meta nfproto ipv6 counter reject'
        if grep -q '^# 分流模板: direct ' "$_zp_dir/config.yaml" 2>/dev/null; then
            _zp_v6_guard='# ZP_BLOCK_IPV6'
        fi
        sed -e '/meta nfproto ipv6.*tproxy ip6/d' \
            -e "s/# ZP_BLOCK_IPV6/$_zp_v6_guard/" \
            "$_zp_dir/tproxy.nft" > "$_zp_rules" || { zp_tproxy_clear; return 1; }
    fi
    if ! nft -f "$_zp_rules"; then
        rm -f "$_zp_rules"
        zp_tproxy_clear
        return 1
    fi
    rm -f "$_zp_rules"
    return 0
}
