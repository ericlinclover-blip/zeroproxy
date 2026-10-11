#!/bin/sh
# ZeroProxy · TUN 数据面的防火墙放行 —— auto-redirect 被拿掉之后, 这一半必须由我们补上。
#
# 为什么需要它 (8.74 · 真机: GL-MT3600BE / 原厂 OpenWrt 21.02 / 内核 5.4.281):
#   sing-tun 在 OpenWrt(fw4) 上实现 auto-redirect 时, 除了自己那张 nft 表, 还会往
#   /etc/nftables.d/ 落一份 drop-in, 内容是:
#       chain forward { ... iifname "<tun>" counter accept; oifname "<tun>" counter accept; }
#   也就是**转发进/出 tun 的流量靠它放行** (上游 redirect_nftables_rules_openwrt.go)。
#   这台固件上带 auto-redirect 时 tun 根本建不出来, 于是安装脚本走自愈把它去掉 (8.45) ——
#   去掉之后 tun 能建出来、路由器自己也能出网, 但**局域网转发到 zp-tun 的包全部被防火墙的
#   forward 策略丢掉**。现象正是"面板与路由器都显示已连接, 家里所有设备国内国外全断":
#   设备在 ≠ 流量过得去。所以 auto-route 接管了局域网, 不等于它能把包送出去。
#
# 只在 autoredirect=0 时动手 —— 健康的机器 (upstream 自己落了那两条) 一个字节都不动。
# 认领靠注释: 只删自己加的那几条, fw4 / 用户 / upstream 的规则一个不碰。
ZP_TUN_NAME="${ZP_TUN_NAME:-zp-tun}"
ZP_TUNFW_TAG="zeroproxy-zp-tun"

_zp_tunfw_dir() { printf '%s' "${ZP_DIR:-/etc/zeroproxy}"; }
_zp_caps_get() { sed -n "s/^$1=//p" "$(_zp_tunfw_dir)/caps" 2>/dev/null | head -n1; }

# 该不该动手: 数据面选中了 tun, 而 upstream 的 auto-redirect 没跑成。
zp_tunfw_needed() {
    [ "$(_zp_caps_get chosen)" = "tun" ] || return 1
    [ "$(_zp_caps_get autoredirect)" = "0" ] || return 1
    return 0
}

_zp_tunfw_fw4() { command -v nft >/dev/null 2>&1 && nft list table inet fw4 >/dev/null 2>&1; }

# 放行规则真的在不在 (按注释认领, 不看退出码)
zp_tunfw_live() {
    if _zp_tunfw_fw4; then
        nft list chain inet fw4 forward 2>/dev/null | grep -q "$ZP_TUNFW_TAG"
    elif command -v iptables >/dev/null 2>&1; then
        iptables -C FORWARD -o "$ZP_TUN_NAME" -m comment --comment "$ZP_TUNFW_TAG" -j ACCEPT 2>/dev/null
    else
        return 1
    fi
}

# 确保放行。返回 0 = 现在真的在; 调用方据此决定能不能说"全屋生效"。
zp_tunfw_allow() {
    zp_tunfw_needed || return 0
    if _zp_tunfw_fw4; then
        zp_tunfw_live && return 0
        nft insert rule inet fw4 forward oifname "$ZP_TUN_NAME" counter accept comment "\"$ZP_TUNFW_TAG\"" 2>/dev/null
        nft insert rule inet fw4 forward iifname "$ZP_TUN_NAME" counter accept comment "\"$ZP_TUNFW_TAG\"" 2>/dev/null
        nft insert rule inet fw4 input   iifname "$ZP_TUN_NAME" counter accept comment "\"$ZP_TUNFW_TAG\"" 2>/dev/null
        zp_tunfw_live
        return $?
    fi
    if command -v iptables >/dev/null 2>&1; then
        zp_tunfw_live && return 0
        iptables -I FORWARD -o "$ZP_TUN_NAME" -m comment --comment "$ZP_TUNFW_TAG" -j ACCEPT 2>/dev/null
        iptables -I FORWARD -i "$ZP_TUN_NAME" -m comment --comment "$ZP_TUNFW_TAG" -j ACCEPT 2>/dev/null
        iptables -I INPUT   -i "$ZP_TUN_NAME" -m comment --comment "$ZP_TUNFW_TAG" -j ACCEPT 2>/dev/null
        zp_tunfw_live
        return $?
    fi
    return 1
}

# 拆掉 —— 与 allow 严格对称, 只回收自己加的那几条 (revert 的"逐条比对"靠它成立)
zp_tunfw_clear() {
    if _zp_tunfw_fw4; then
        for _x in $(nft -a list chain inet fw4 forward 2>/dev/null \
                   | sed -n "s/.*$ZP_TUNFW_TAG.*handle \([0-9][0-9]*\).*/\1/p"); do
            nft delete rule inet fw4 forward handle "$_x" 2>/dev/null || true
        done
        for _x in $(nft -a list chain inet fw4 input 2>/dev/null \
                   | sed -n "s/.*$ZP_TUNFW_TAG.*handle \([0-9][0-9]*\).*/\1/p"); do
            nft delete rule inet fw4 input handle "$_x" 2>/dev/null || true
        done
    fi
    if command -v iptables >/dev/null 2>&1; then
        # 有界循环: 每次删掉一条, 最多删 8 条就收手。正常写法是 `while iptables -D …; do :; done`
        # —— 它靠"删不到时 iptables 返回非 0"退出, 但那是**惯例不是契约**: 万一某个固件的
        # iptables 删不到也回 0, 这个循环就永远转下去 (安装/卸载都会卡死在这里)。
        _k=0
        while [ "$_k" -lt 8 ]; do
            iptables -D FORWARD -o "$ZP_TUN_NAME" -m comment --comment "$ZP_TUNFW_TAG" -j ACCEPT 2>/dev/null || break
            _k=$((_k + 1))
        done
        _k=0
        while [ "$_k" -lt 8 ]; do
            iptables -D FORWARD -i "$ZP_TUN_NAME" -m comment --comment "$ZP_TUNFW_TAG" -j ACCEPT 2>/dev/null || break
            _k=$((_k + 1))
        done
        _k=0
        while [ "$_k" -lt 8 ]; do
            iptables -D INPUT -i "$ZP_TUN_NAME" -m comment --comment "$ZP_TUNFW_TAG" -j ACCEPT 2>/dev/null || break
            _k=$((_k + 1))
        done
    fi
    return 0
}
