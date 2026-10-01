#!/bin/sh
# ZeroProxy 路由器客户端安装脚本。
#
# 用户拿到的是面板生成的一行命令:
#     wget -qO- https://<面板>/c/<配对码> | sh
# 占位符 __ZP_BASE__ / __ZP_CODE__ 由面板在响应时替换 (见 router_client.render_script)。
#
# 这个脚本做四件事, 顺序不能变:
#   1. 用一次性配对码换设备凭据 (之后面板随时可以单独吊销这台路由器)
#   2. 装内核: 按 CPU 架构取 mihomo 静态二进制 + kmod-tun (TUN 全屋透明代理)
#   3. 落四个文件: config.yaml / init 脚本 / 控制 agent / 运维 CLI
#   4. 起服务并**自检** —— 自检不过就退回去看 tproxy 方案, 而不是假装成功
#
# 幂等: 重复执行 = 重装/升级, 设备凭据与配置保留 (配对码已作废也没关系)。
set -eu

ZP_BASE="__ZP_BASE__"
ZP_CODE="__ZP_CODE__"
ZP_CLIENT_VERSION="__ZP_CLIENT_VERSION__"

ZP_DIR=/etc/zeroproxy
ZP_CONF="$ZP_DIR/config.yaml"
ZP_DEV="$ZP_DIR/device.json"
ZP_BIN="$ZP_DIR/mihomo"
ZP_INIT=/etc/init.d/zeroproxy
ZP_AGENT_INIT=/etc/init.d/zeroproxy-agent
ZP_CLI=/usr/bin/zeroproxy
ZP_SVC=zeroproxy

# 内核健康检查用的本机控制口 (与 config.yaml 的 external-controller 一致)
ZP_API=127.0.0.1:9090
# 代理端口 (config.yaml 的 mixed-port)
ZP_MIXED=7890

TLS_OPTS=""
ARCH=""
DEPENDENCY_NOTE=""

# ---------------------------------------------------------------- 输出
# 全部输出走 stderr 之外的标准输出, 但用颜色区分层级 —— 用户是在 SSH 里看,
# 一段没有层级的大段英文输出等于没有输出。
if [ -t 1 ]; then
    C_R="$(printf '\033[0m')"; C_B="$(printf '\033[1m')"; C_G="$(printf '\033[32m')"
    C_Y="$(printf '\033[33m')"; C_E="$(printf '\033[31m')"
else
    C_R=""; C_B=""; C_G=""; C_Y=""; C_E=""
fi
step() { printf '%s==>%s %s\n' "$C_B" "$C_R" "$*"; }
ok()   { printf '%s  ✓%s %s\n' "$C_G" "$C_R" "$*"; }
warn() { printf '%s  !%s %s\n' "$C_Y" "$C_R" "$*" >&2; }
die()  { printf '\n%s安装失败:%s %s\n' "$C_E" "$C_R" "$*" >&2; exit 1; }

# ---------------------------------------------------------------- HTTP
# 路由器上不一定有 curl (OpenWrt 默认只有 uclient-fetch, 它同时提供 wget 名字)。
# 三种客户端都试一遍: curl → uclient-fetch → wget。
HTTP=""
detect_http() {
    for c in curl uclient-fetch wget; do
        command -v "$c" >/dev/null 2>&1 && { HTTP="$c"; return 0; }
    done
    return 1
}

# 面板默认用真实证书 (Let's Encrypt); 若用户还在 IP/自签阶段, 第一次请求会因
# 证书校验失败 —— 这时回退到"跳过校验"并明确告警, 而不是让安装卡在一个
# 用户看不懂的 SSL 错误上。
http_probe() {
    _url="$1"
    if http_get "$_url" >/dev/null 2>&1; then return 0; fi
    TLS_OPTS="insecure"
    http_get "$_url" >/dev/null 2>&1
}

http_get() {
    case "$HTTP" in
        curl)
            if [ "$TLS_OPTS" = "insecure" ]; then curl -fsSk -m 30 "$1"
            else curl -fsS -m 30 "$1"; fi ;;
        *)
            if [ "$TLS_OPTS" = "insecure" ]; then "$HTTP" -q --no-check-certificate -O - "$1"
            else "$HTTP" -q -O - "$1"; fi ;;
    esac
}

http_post() {
    _url="$1"; _body="$2"
    case "$HTTP" in
        curl)
            if [ "$TLS_OPTS" = "insecure" ]; then
                curl -fsSk -m 30 -H 'Content-Type: application/json' --data "$_body" "$_url"
            else
                curl -fsS -m 30 -H 'Content-Type: application/json' --data "$_body" "$_url"
            fi ;;
        *)
            if [ "$TLS_OPTS" = "insecure" ]; then
                "$HTTP" -q --no-check-certificate -O - --post-data "$_body" "$_url"
            else
                "$HTTP" -q -O - --post-data "$_body" "$_url"
            fi ;;
    esac
}

json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\r\n'; }

# 取一个扁平 JSON 字段 (busybox 里没有 jq, 好在面板返回的都是浅结构)。
json_get() {
    _json="$1"; _key="$2"
    if command -v jsonfilter >/dev/null 2>&1; then
        printf '%s' "$_json" | jsonfilter -e "@.$_key" 2>/dev/null | head -n1
    else
        printf '%s' "$_json" | sed -n 's/.*"'"$_key"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1
    fi
}

json_get_bool() {
    _json="$1"; _key="$2"
    if command -v jsonfilter >/dev/null 2>&1; then
        printf '%s' "$_json" | jsonfilter -e "@.$_key" 2>/dev/null | head -n1
    else
        printf '%s' "$_json" | sed -n 's/.*"'"$_key"'"[[:space:]]*:[[:space:]]*\(true\|false\).*/\1/p' | head -n1
    fi
}

# ---------------------------------------------------------------- 环境探测
detect_env() {
    [ "$(id -u)" = "0" ] || die "需要 root 权限, 请用 root 账户执行 (OpenWrt 默认就是 root)"
    [ -r /etc/openwrt_release ] || die "没有检测到 OpenWrt (/etc/openwrt_release 不存在)。
  本客户端面向 OpenWrt / GL.iNet / 基于 OpenWrt 的软路由; 原厂固件请先在后台
  刷成 OpenWrt, 或改用手机/电脑客户端的订阅导入。"

    case "$(uname -m)" in
        aarch64|arm64)     ARCH=arm64 ;;
        armv7l|armv7)      ARCH=armv7 ;;
        armv6l)            ARCH=armv7 ;;
        x86_64|amd64)      ARCH=amd64 ;;
        mips64el)          ARCH=mips64le ;;
        mipsel|mipsle)     ARCH=mipsle ;;
        mips)              ARCH=mips ;;
        *) die "暂不支持的 CPU 架构: $(uname -m) (可到面板把该设备标记为不支持, 或反馈这个架构)" ;;
    esac

    MODEL="$(cat /tmp/sysinfo/model 2>/dev/null || true)"
    [ -n "$MODEL" ] || MODEL="$(cat /proc/device-tree/model 2>/dev/null | tr -d '\0' || true)"
    [ -n "$MODEL" ] || MODEL="$(uname -m)"
    HOSTNAME_NOW="$(uci get system.@system[0].hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null || echo router)"
    # 注意 `|| true`: 在 `set -e` 下, 带命令替换的赋值会继承子命令的退出码 ——
    # sed 读不到文件 (测试机/非标准环境) 会把整个脚本静默干掉, 一行输出都没有。
    OS_NAME="OpenWrt $(sed -n "s/^DISTRIB_RELEASE=['\"]\(.*\)['\"].*/\1/p" /etc/openwrt_release 2>/dev/null || true)"
    [ "$OS_NAME" != "OpenWrt " ] || OS_NAME="OpenWrt"
    KERNEL="$(uname -r)"
}

preflight() {
    step "检查环境"
    ok "设备: $MODEL · $ARCH · $OS_NAME (内核 $KERNEL)"

    # 空间: mihomo 解压后约 57 MB。小于 90 MB 剩余空间的机器装到一半会 ENOSPC,
    # 那是所有失败里最难排查的一种, 所以提前挡。
    _free="$(df -k /overlay 2>/dev/null | awk 'NR==2{print $4}' || true)"
    [ -n "$_free" ] || _free="$(df -k / | awk 'NR==2{print $4}' || true)"
    if [ -n "$_free" ] && [ "$_free" -lt 92160 ]; then
        die "可用空间不足: 需要约 90 MB, 当前只有 $((_free / 1024)) MB。
  请先在路由器后台释放空间 (卸载不用的插件 / 清理 /tmp), 或换一台闪存更大的设备。"
    fi

    # 面板可达性 (顺带确定 TLS 策略)
    http_probe "$ZP_BASE/api/status" || die "连不上面板 $ZP_BASE。
  请确认路由器能上网, 且面板地址可以从外网访问。"
    if [ "$TLS_OPTS" = "insecure" ]; then
        warn "面板证书校验未通过, 已改用不校验模式继续 (面板可能还在自签证书阶段)"
    fi
    ok "面板可达: $ZP_BASE"
}

# ---------------------------------------------------------------- 配对
pair() {
    step "接入账号"
    if [ -f "$ZP_DEV" ] && grep -q '"id"' "$ZP_DEV" 2>/dev/null; then
        DEV_ID="$(sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$ZP_DEV" | head -n1)"
        DEV_SECRET="$(sed -n 's/.*"secret"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$ZP_DEV" | head -n1)"
        if [ -n "$DEV_ID" ] && [ -n "$DEV_SECRET" ]; then
            ok "已接入过 (设备 $DEV_ID), 沿用原有凭据"
            return 0
        fi
    fi

    _body='{"code":"'"$(json_escape "$ZP_CODE")"'","kind":"router"'
    _body="$_body"',"hostname":"'"$(json_escape "$HOSTNAME_NOW")"'"'
    _body="$_body"',"model":"'"$(json_escape "$MODEL")"'"'
    _body="$_body"',"arch":"'"$(json_escape "$ARCH")"'"'
    _body="$_body"',"os":"'"$(json_escape "$OS_NAME")"'"'
    _body="$_body"',"version":"'"$(json_escape "$ZP_CLIENT_VERSION")"'"}'

    _resp="$(http_post "$ZP_BASE/c/pair" "$_body" || true)"
    DEV_ID="$(json_get "$_resp" id)"
    DEV_SECRET="$(json_get "$_resp" secret)"
    if [ -z "$DEV_ID" ] || [ -z "$DEV_SECRET" ]; then
        _msg="$(json_get "$_resp" error)"
        [ -n "$_msg" ] || _msg="面板没有返回设备凭据"
        die "接入失败: $_msg"
    fi

    mkdir -p "$ZP_DIR"
    umask 077
    cat > "$ZP_DEV" <<EOF
{
  "id": "$DEV_ID",
  "secret": "$DEV_SECRET",
  "base": "$ZP_BASE",
  "name": "$(json_get "$_resp" name)"
}
EOF
    umask 022
    chmod 600 "$ZP_DEV"
    ok "已接入: $(json_get "$_resp" name) ($DEV_ID)"
}

# ---------------------------------------------------------------- 依赖
# TUN 模式只需要 kmod-tun; tproxy 回退需要 kmod-nft-tproxy。
# opkg 源不可用 (改过源的机器很常见) 不算致命 —— 内核模块可能已经装好了。
install_deps() {
    step "准备网络内核模块"
    if command -v opkg >/dev/null 2>&1; then
        # kmod-nft-tproxy 是 mihomo auto-redirect / tproxy 回退的前提;
        # kmod-tun 是主方案 (TUN 全屋透明代理) 的前提。两个都小, 一起装。
        _pkgs=""
        [ -c /dev/net/tun ] || _pkgs="kmod-tun"
        _pkgs="${_pkgs:+$_pkgs }kmod-nft-tproxy"
        opkg update >/dev/null 2>&1 || warn "opkg update 失败 (软件源可能不可用), 继续尝试安装已缓存的包"
        # shellcheck disable=SC2086
        opkg install $_pkgs >/dev/null 2>&1 || warn "内核模块安装未全部成功 ($_pkgs)"
    fi
    if [ -c /dev/net/tun ]; then
        ok "TUN 可用 (kmod-tun 已就绪)"
    else
        warn "TUN 不可用, 稍后会自动改用 tproxy 模式 (全屋主要设备仍然覆盖)"
        DEPENDENCY_NOTE="tun-missing"
    fi
    # nft 是 tproxy 回退与 auto-redirect 的前提 (fw4 自带, 这里只确认)
    command -v nft >/dev/null 2>&1 || warn "没有 nft 命令: 若 TUN 也不可用, 透明代理将无法生效"
}

# ---------------------------------------------------------------- 内核二进制
install_core() {
    step "下载代理内核 (mihomo · $ARCH)"
    if [ -x "$ZP_BIN" ]; then
        ok "内核已存在, 跳过下载"
        return 0
    fi
    _tmp="$ZP_DIR/.mihomo.gz"
    mkdir -p "$ZP_DIR"
    http_get "$ZP_BASE/c/bin/$ARCH" > "$_tmp" || die "下载内核失败 (面板上该架构的二进制没有缓存成功, 请稍后重试)"
    [ -s "$_tmp" ] || die "下载到的内核是空文件"
    case "$(head -c 2 "$_tmp" | od -An -tx1 | tr -d ' \n')" in
        1f8b) gzip -dc "$_tmp" > "$ZP_BIN" || die "解压内核失败" ;;
        *)    mv "$_tmp" "$ZP_BIN" ;;   # 面板直接给了未压缩的二进制
    esac
    rm -f "$_tmp"
    chmod 755 "$ZP_BIN"
    "$ZP_BIN" -v >/dev/null 2>&1 || die "内核无法执行 (架构不匹配?), 请把上面这一行反馈给面板"
    ok "内核就绪: $("$ZP_BIN" -v 2>/dev/null | head -n1)"
}

# ---------------------------------------------------------------- 配置
fetch_config() {
    _dest="${1:-$ZP_CONF}"
    _url="$ZP_BASE/c/sub/$DEV_ID?k=$DEV_SECRET&format=clash&rules=smart"
    _tmp="$_dest.new"
    http_get "$_url" > "$_tmp" || return 1
    grep -q '^proxies:' "$_tmp" || { rm -f "$_tmp"; return 1; }
    # 先用内核自己校验再替换 —— 配置写坏就等于全屋断网, 必须先测后换
    if ! "$ZP_BIN" -t -d "$ZP_DIR" -f "$_tmp" >/dev/null 2>&1; then
        "$ZP_BIN" -t -d "$ZP_DIR" -f "$_tmp" 2>&1 | tail -n3 >&2
        rm -f "$_tmp"
        return 1
    fi
    mv "$_tmp" "$_dest"
    return 0
}

# ---------------------------------------------------------------- 落文件
write_files() {
    step "写入运行文件"
    mkdir -p "$ZP_DIR"

    fetch_config "$ZP_CONF" || die "拉取/校验配置失败, 请回面板确认已有可用节点"
    ok "配置已写入 $ZP_CONF"

    # tproxy 回退方案用的 nft 规则 (只在 TUN 不可用时由 init 脚本加载)。
    # 优先级用数字而不是符号名 (dstnat/mangle): 数字在各版本 nft 上行为一致。
    # 局域网/私有地址先放行, 再看 mark —— 否则代理自己的出站连接会被再次抓回来成环。
    cat > "$ZP_DIR/tproxy.nft" <<'NFTEOF'
table inet zp_router {
    set local4 {
        type ipv4_addr
        flags interval
        elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8,
                     169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16,
                     224.0.0.0/4, 240.0.0.0/4, 198.18.0.0/16 }
    }
    chain pre {
        type filter hook prerouting priority -150; policy accept;
        ip daddr @local4 return
        meta mark 0x1ff return
        meta l4proto { tcp, udp } th dport { 22, 53, 7890, 7874, 9092, 9090 } return
        meta l4proto tcp meta mark set 0x1ff tproxy to :7893 accept
        meta l4proto udp meta mark set 0x1ff tproxy to :7893 accept
    }
    chain dns {
        type nat hook prerouting priority -105; policy accept;
        ip daddr @local4 return
        udp dport 53 redirect to :7874
        tcp dport 53 redirect to :7874
    }
}
NFTEOF

    # 控制 agent: 每 15 秒向面板上报一次状态并取回"期望开关 + 配置版本"。
    # 面板是唯一的事实来源 —— 路由器本地改开关也是请求面板去改 (见 CLI)。
    cat > "$ZP_DIR/agent.sh" <<'AGENTEOF'
#!/bin/sh
# ZeroProxy 路由器控制 agent (由 procd 常驻)。
SLEEP=15
ZP_DIR=/etc/zeroproxy
DEV="$ZP_DIR/device.json"
CONF="$ZP_DIR/config.yaml"
STATE="$ZP_DIR/state"

log() { logger -t zeroproxy-agent "$*"; }

get() { sed -n 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$DEV" | head -n1; }
json_get() {
    if command -v jsonfilter >/dev/null 2>&1; then
        printf '%s' "$1" | jsonfilter -e "@.$2" 2>/dev/null | head -n1
    else
        printf '%s' "$1" | sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1
    fi
}
json_get_bool() { printf '%s' "$1" | sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*\(true\|false\).*/\1/p' | head -n1; }

http_post() {
    _url="$1"; _body="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSk -m 20 -H 'Content-Type: application/json' --data "$_body" "$_url" 2>/dev/null
    else
        uclient-fetch -q --no-check-certificate -O - --post-data "$_body" "$_url" 2>/dev/null \
            || wget -q --no-check-certificate -O - --post-data "$_body" "$_url" 2>/dev/null
    fi
}
http_get() {
    if command -v curl >/dev/null 2>&1; then curl -fsSk -m 30 "$1" 2>/dev/null
    else uclient-fetch -q --no-check-certificate -O - "$1" 2>/dev/null \
        || wget -q --no-check-certificate -O - "$1" 2>/dev/null
    fi
}

# 内核是否在跑 —— 这是要上报给面板的 actual。
# 不能用 `/etc/init.d/zeroproxy running`: 控制 agent 是另一个常驻服务, 用服务名
# 判断会把"只有 agent 活着"也算成内核在跑, 于是面板永远显示"已连接"。
# 这里看两件事: 我们的开关意图 (core.up 标记) + 进程真的在。
core_up() {
    [ -f "$ZP_DIR/core.up" ] || return 1
    pgrep -f "$ZP_DIR/mihomo" >/dev/null 2>&1
}

flush_dns() { killall -HUP dnsmasq 2>/dev/null || /etc/init.d/dnsmasq reload 2>/dev/null || true; }

switch_core() {
    if [ "$1" = "on" ]; then
        /etc/init.d/zeroproxy start >/dev/null 2>&1 || true
        sleep 2
        touch "$ZP_DIR/core.up"
        flush_dns
    else
        rm -f "$ZP_DIR/core.up"
        /etc/init.d/zeroproxy stop >/dev/null 2>&1 || true
        nft delete table inet zp_router 2>/dev/null || true
        flush_dns
    fi
}

apply_config() {
    # 原子替换: 新配置先落 .new, 校验通过才替换, 失败保留旧配置继续用。
    _url="$(get base)/c/sub/$(get id)?k=$(get secret)&format=clash&rules=smart"
    http_get "$_url" > "$CONF.new" 2>/dev/null || return 1
    grep -q '^proxies:' "$CONF.new" || { rm -f "$CONF.new"; return 1; }
    /etc/zeroproxy/mihomo -t -d "$ZP_DIR" -f "$CONF.new" >/dev/null 2>&1 \
        || { rm -f "$CONF.new"; log "新配置校验失败, 保留原配置"; return 1; }
    mv "$CONF.new" "$CONF"
    /etc/init.d/zeroproxy restart >/dev/null 2>&1 || true
    log "配置已更新并重载"
    return 0
}

LAST_REV=""
FAILS=0
while true; do
    BODY='{"device":"'"$(get id)"'","k":"'"$(get secret)"'","version":"1.0.0"'
    if core_up; then BODY="$BODY"',"actual":true'; else BODY="$BODY"',"actual":false'; fi
    [ -n "$LAST_REV" ] && BODY="$BODY"',"rev":"'"$LAST_REV"'"'
    BODY="$BODY"'}'

    RESP="$(http_post "$(get base)/c/report" "$BODY" || true)"
    if [ -z "$RESP" ]; then
        FAILS=$((FAILS + 1))
        # 面板不可达时保持现状 (而不是把代理关掉) —— 断网时"维持可用"比"忠于面板"重要
        [ $((FAILS % 20)) -eq 1 ] && log "面板不可达 (第 $FAILS 次), 保持当前状态"
        sleep "$SLEEP"
        continue
    fi
    FAILS=0

    DESIRED="$(json_get_bool "$RESP" desired)"
    REV="$(json_get "$RESP" rev)"
    [ -n "$DESIRED" ] || DESIRED=true

    if [ "$DESIRED" = "true" ] && ! core_up; then
        log "面板要求开启, 启动内核"
        switch_core on
    elif [ "$DESIRED" = "false" ] && core_up; then
        log "面板要求关闭, 停止内核"
        switch_core off
    fi

    if [ -n "$REV" ] && [ "$REV" != "$LAST_REV" ]; then
        if apply_config; then LAST_REV="$REV"; fi
    fi
    sleep "$SLEEP"
done
AGENTEOF
    chmod 755 "$ZP_DIR/agent.sh"

    # 两个独立的 procd 服务, 分开是有原因的: 关代理 = 停内核, 而控制 agent 必须
    # 继续活着 —— 否则关了之后就再也没人去把它开回来 (面板下发再多次也没人接)。
    # 所以从设计上就不允许把两者放进同一个 init 脚本。
    cat > "$ZP_INIT" <<'INITEOF'
#!/bin/sh /etc/rc.common
# ZeroProxy 代理内核 (mihomo)
START=99
STOP=05
USE_PROCD=1

ZP_DIR=/etc/zeroproxy
CONF="$ZP_DIR/config.yaml"

start_service() {
    [ -x "$ZP_DIR/mihomo" ] || return 0
    [ -f "$CONF" ] || return 0

    # TUN 模式: 由内核接管路由与 DNS, 不需要动防火墙。
    # 若机器没有 /dev/net/tun, agent 会自动切到 tproxy 规则 (见 tproxy.nft)。
    if [ -c /dev/net/tun ]; then
        nft delete table inet zp_router 2>/dev/null || true
    else
        nft -f "$ZP_DIR/tproxy.nft" 2>/dev/null || true
    fi
    killall -HUP dnsmasq 2>/dev/null || true

    procd_open_instance
    procd_set_param command "$ZP_DIR/mihomo" -d "$ZP_DIR" -f "$CONF"
    procd_set_param respawn 3600 5 5
    procd_set_param file "$CONF"
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}

stop_service() {
    nft delete table inet zp_router 2>/dev/null || true
    killall -HUP dnsmasq 2>/dev/null || true
}

service_triggers() { procd_add_reload_trigger zeroproxy; }
INITEOF
    chmod 755 "$ZP_INIT"

    # 控制 agent 单独一个服务: 只受开机与卸载影响, 不受面板开关影响。
    cat > "$ZP_AGENT_INIT" <<'AGENTINITEOF'
#!/bin/sh /etc/rc.common
# ZeroProxy 控制 agent (常驻: 上报状态 + 接收开关与配置变更)
START=99
STOP=04
USE_PROCD=1

ZP_DIR=/etc/zeroproxy

start_service() {
    [ -x "$ZP_DIR/agent.sh" ] || return 0
    procd_open_instance
    procd_set_param command "$ZP_DIR/agent.sh"
    procd_set_param respawn 3600 5 5
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
AGENTINITEOF
    chmod 755 "$ZP_AGENT_INIT"

    # 运维 CLI: 在路由器上直接看状态 / 开关 / 更新 / 卸载。
    cat > "$ZP_CLI" <<'CLIEOF'
#!/bin/sh
# ZeroProxy 路由器客户端运维命令
ZP_DIR=/etc/zeroproxy
BASE="$(sed -n 's/.*"base"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$ZP_DIR/device.json" 2>/dev/null | head -n1)"

running() { /etc/init.d/zeroproxy running >/dev/null 2>&1 && echo yes || echo no; }

case "${1:-status}" in
    status)
        echo "内核:  $( [ "$(running)" = yes ] && echo 运行中 || echo 已停止 )"
        echo "设备:  $(sed -n 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$ZP_DIR/device.json" 2>/dev/null | head -n1)"
        echo "面板:  $BASE"
        [ -c /dev/net/tun ] && echo "模式:  TUN (全屋透明)" || echo "模式:  tproxy (全屋透明, 本机自身流量除外)"
        if command -v curl >/dev/null 2>&1; then
            curl -fsS -m 8 "http://127.0.0.1:9090/version" 2>/dev/null | head -c 200 && echo
        fi
        ;;
    on|off)
        # 本地开关同样以面板为准: 告诉面板改期望状态, agent 下一轮生效
        ON=$([ "$1" = on ] && echo true || echo false)
        ID="$(sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$ZP_DIR/device.json" | head -n1)"
        KEY="$(sed -n 's/.*"secret"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$ZP_DIR/device.json" | head -n1)"
        BODY='{"device":"'"$ID"'","k":"'"$KEY"'","set_desired":'"$ON"'}'
        if command -v curl >/dev/null 2>&1; then
            curl -fsSk -m 15 -H 'Content-Type: application/json' --data "$BODY" "$BASE/c/report" >/dev/null
        else
            uclient-fetch -q --no-check-certificate -O - --post-data "$BODY" "$BASE/c/report" >/dev/null
        fi
        echo "已请求面板把总开关设为「$1」, 约 15 秒内生效 (zeroproxy status 查看)"
        ;;
    log)        logread -e zeroproxy | tail -n "${2:-40}" ;;
    update)
        echo "重新执行面板上的安装命令即可升级 (配置与凭据会保留)"
        ;;
    uninstall)
        # 先停 agent 再停内核: 反过来的话 agent 会在内核停掉后立刻把它拉起来
        /etc/init.d/zeroproxy-agent stop >/dev/null 2>&1 || true
        /etc/init.d/zeroproxy-agent disable >/dev/null 2>&1 || true
        /etc/init.d/zeroproxy stop >/dev/null 2>&1 || true
        /etc/init.d/zeroproxy disable >/dev/null 2>&1 || true
        nft delete table inet zp_router 2>/dev/null || true
        killall -HUP dnsmasq 2>/dev/null || true
        rm -rf "$ZP_DIR" /etc/init.d/zeroproxy /etc/init.d/zeroproxy-agent /usr/bin/zeroproxy
        echo "已卸载。这台设备在面板上仍然存在, 请在面板「客户端」里一并移除。"
        ;;
    *) echo "用法: zeroproxy [status|on|off|log|uninstall]" ;;
esac
CLIEOF
    chmod 755 "$ZP_CLI"
    ok "已写入 $ZP_INIT / $ZP_AGENT_INIT / $ZP_DIR/agent.sh / $ZP_CLI"
}

# ---------------------------------------------------------------- 启动与自检
verify() {
    step "启动并自检"
    /etc/init.d/zeroproxy enable >/dev/null 2>&1 || true
    /etc/init.d/zeroproxy-agent enable >/dev/null 2>&1 || true
    # 先起控制 agent (它会立刻上报, 面板上马上就能看到这台设备), 再起内核
    /etc/init.d/zeroproxy-agent restart >/dev/null 2>&1 || true
    touch "$ZP_DIR/core.up"
    /etc/init.d/zeroproxy restart >/dev/null 2>&1 || true

    _i=0
    while [ "$_i" -lt 15 ]; do
        sleep 1
        _i=$((_i + 1))
        if http_get "http://$ZP_API/version" >/dev/null 2>&1; then break; fi
    done
    if ! http_get "http://$ZP_API/version" >/dev/null 2>&1; then
        warn "内核控制口没有响应, 最近日志:"
        logread -e zeroproxy 2>/dev/null | tail -n 8 >&2 || true
        die "内核启动失败。把上面的日志发给面板即可定位 (通常是节点配置或内存不足)。"
    fi
    ok "内核已启动"

    if [ -c /dev/net/tun ]; then
        if ip link show zp-tun >/dev/null 2>&1; then
            ok "TUN 已建立: 全屋设备 (含路由器自身) 透明代理生效"
        else
            warn "TUN 设备未出现, 改用 tproxy 模式 (全屋设备生效, 路由器自身流量除外)"
            nft -f "$ZP_DIR/tproxy.nft" 2>/dev/null || true
        fi
    else
        warn "本机没有 TUN, 使用 tproxy 模式 (全屋设备生效, 路由器自身流量除外)"
        nft -f "$ZP_DIR/tproxy.nft" 2>/dev/null || true
    fi

    # 真实出口测试: 经代理端口请求一次, 只作为信息展示 —— 节点全关时失败是正常的。
    # 用 curl 是因为 busybox 的 wget 不支持 -x (代理), 没有 curl 就跳过这一步。
    if command -v curl >/dev/null 2>&1; then
        if curl -fsS -m 12 -x "http://127.0.0.1:$ZP_MIXED" -o /dev/null \
            "http://www.gstatic.com/generate_204" 2>/dev/null; then
            ok "出口连通性正常"
        else
            warn "出口测试未通过 (节点可能全部关闭, 或节点本身不通) — 不影响安装"
        fi
    fi
}

report_up() {
    _body='{"device":"'"$DEV_ID"'","k":"'"$DEV_SECRET"'","version":"'"$ZP_CLIENT_VERSION"'","actual":true'
    _body="$_body"',"arch":"'"$ARCH"'","os":"'"$OS_NAME"'","model":"'"$(json_escape "$MODEL")"'"}'
    http_post "$ZP_BASE/c/report" "$_body" >/dev/null 2>&1 || true
}

finish() {
    printf '\n%s────────────────────────────────────────────%s\n' "$C_B" "$C_R"
    ok "全屋代理已开启 —— 手机 / 电脑 / 电视连上这台路由器即可用"
    printf '  设备名   %s\n' "$MODEL"
    printf '  模式     %s\n' "$( [ -c /dev/net/tun ] && echo 'TUN 全屋透明代理' || echo 'tproxy 全屋透明代理' )"
    printf '  分流     智能分流 (国内直连 + 广告拦截, 其余走代理)\n'
    printf '  管理     面板「客户端」页可看状态、开关、改分流、移除设备\n'
    printf '  本机命令 zeroproxy status | on | off | log | uninstall\n'
    printf '\n  以后换节点 / 改分流不用再登录路由器, 面板改完自动同步。\n'
    printf '%s────────────────────────────────────────────%s\n' "$C_B" "$C_R"
}

main() {
    printf '\n%sZeroProxy 路由器客户端%s v%s\n\n' "$C_B" "$C_R" "$ZP_CLIENT_VERSION"
    detect_env
    detect_http || die "路由器上没有任何可用的下载工具 (curl / uclient-fetch / wget)"
    preflight
    pair
    install_deps
    install_core
    write_files
    verify
    report_up
    finish
}

main "$@"
