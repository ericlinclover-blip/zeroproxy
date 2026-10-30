#!/bin/sh
# ZeroProxy 路由器控制 agent (由 procd 常驻)。
#
# 修复摘要 (2026-10-28):
#   1. 心跳间隔从固定15秒改为自适应 (不稳定时5秒, 稳定后最长30秒)
#   2. switch_core start 后等 mihomo API 真正就绪再设 core.up, 避免"假启动"触发重启风暴
#   3. 多服务器心跳: 至少一台成功才算可达; 失败计数只在连续失败时累积
#   4. 配置拉取去重: 同一轮心跳内只拉一次; apply_config 成功时更新 LAST_REV/LAST_PULL
#   5. 配置校验超时限制: mihomo -t 最长等 30 秒, 防止阻塞心跳循环
#   6. 配置重载时只在核心运行时才 restart, 关闭状态不重启 (已在原代码中, 此处加强)
#   7. 心跳状态机: 稳定/不稳定两态, 稳定态延长心跳间隔降低开销

SLEEP=15              # 基础心跳间隔
SLEEP_UNSTABLE=5      # 不稳定时的心跳间隔 (配置变更/刚启动)
SLEEP_STABLE=30       # 稳定后的最长心跳间隔
ZP_DIR=/etc/zeroproxy

#: 每台面板一条凭据。多服务器模式下路由器把它们挂成多个 mihomo proxy-provider,
#: 由 mihomo 自己合并节点并做健康检查 —— 面板之间不需要互相认识。
SERVERS="$ZP_DIR/servers"
#: 老版本只有一个 device.json; 首次运行时迁移成 servers/ 下的一条。
DEV="$ZP_DIR/device.json"
CONF="$ZP_DIR/config.yaml"
STATE="$ZP_DIR/state"
#: 分流数据库 (mihomo 的 GEOSITE / GEOIP 规则要用)。缺了**不是**跳过那几条规则, 而是
#: 整份配置加载失败 —— 而 mihomo 会当场去 GitHub 拉, 装机时这台路由器还没有任何代理
#: 可用, 真机上就是 `can't download MMDB: context deadline exceeded`。所以和内核一样
#: 由面板分发: 面板去取上游, 路由器只访问面板。文件名是 mihomo 认死的, 不能改。
GEO_FILES="geoip.metadb geosite.dat"
#: 客户端版本 (占位符在落盘后被替换成真实版本号, 见安装脚本 write_files 里的 sed)
ZP_VERSION="__ZP_CLIENT_VERSION__"
#: 这一轮的状态快照 (zpcore state 的输出)。状态只有一份生产者 —— caps 的读取与现场判断
#: 都从这里来 (见 live.sh); 取不到就退回直接读 caps 文件, 行为与以前一致。
ZP_STATE="$ZP_DIR/.state"

# 数据面"现场"的判据只有一份 (live.sh) —— 心跳报的 mode/covered、CLI、本地界面读的都是它。
[ -r "$ZP_DIR/live.sh" ] && . "$ZP_DIR/live.sh"

log() { logger -t zeroproxy-agent "$*"; }

# 拼 JSON 字符串 (原因里可能有引号/反斜杠 —— 内核原话什么都可能有)
json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\r\n'; }

# 内核现在**真的**接管到哪 (覆盖范围)。判据是 live.sh 的 zp_live_covered —— 与 CLI 的
# status / doctor、本地界面 (zpcore) 是同一份, 不再各写一遍 (真机上已经漂过)。
# 面板上显示的是这个值, 不是"我们打算用什么"。
#   full     tun 在   → 全屋设备 + 路由器自身
#   full     dae 在   → 性能模式 (eBPF): 局域网与路由器自身都接管, 且直连流量不走用户态
#   lan      nft 表在 → 全屋设备 (路由器自身流量除外)
#   lan_tcp  iptables 链在 → 只有局域网 TCP
#   none     内核停着, 或规则被外 force 清了 → 未接管
actual_covered() {
    if [ -r "$ZP_DIR/live.sh" ]; then zp_live_covered; return 0; fi
    # live.sh 不在 (升级中途的极短窗口) 才走下面这份等价的内联判据。
    if [ -n "$(pidof dae 2>/dev/null)" ]; then printf 'full'; return 0; fi
    if ip link show zp-tun >/dev/null 2>&1; then printf 'full'; return 0; fi
    if command -v nft >/dev/null 2>&1 && nft list table inet zp_router >/dev/null 2>&1; then
        printf 'lan'; return 0
    fi
    if command -v iptables >/dev/null 2>&1 && iptables -t nat -L zp_router >/dev/null 2>&1; then
        printf 'lan_tcp'; return 0
    fi
    printf 'none'
}

# ---------------------------------------------------------------- 服务器清单

# 从任意一份凭据文件里取字段 (文件是扁平 JSON, 用 sed 取足够且不依赖 jq)
field_of() { sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$1" | head -n1; }
get() { field_of "$DEV" "$1"; }

server_files() { ls "$SERVERS"/*.json 2>/dev/null; }
count_servers() { server_files | wc -l | tr -d ' '; }
first_server() { server_files | head -n1; }

# 面板地址 → provider 键 (合法 YAML 键 + 文件名): https://hkk.i3.pub:8899 → hkk_i3_pub
key_of() {
    printf '%s' "$1" | sed -e 's#^https*://##' -e 's/[^A-Za-z0-9]/_/g' | cut -c1-32
}

# 老版本只写了一份 device.json: 首次运行补成 servers/ 下的一条, 之后统一走多服务器路径
migrate_servers() {
    mkdir -p "$SERVERS"
    [ -s "$DEV" ] || return 0
    [ -n "$(server_files)" ] && return 0
    _b="$(get base)"; _i="$(get id)"; _k="$(get secret)"
    [ -n "$_b" ] && [ -n "$_i" ] && [ -n "$_k" ] || return 0
    _name="$(get name)"
    cat > "$SERVERS/$(key_of "$_b").json" <<EOF
{
  "base": "$_b",
  "id": "$_i",
  "secret": "$_k",
  "name": "${_name:-$_b}"
}
EOF
    chmod 600 "$SERVERS/$(key_of "$_b").json"
    mv "$DEV" "$DEV.migrated" 2>/dev/null || true
    log "已把原来的单服务器凭据迁移到 servers/"
}

# 所有 provider 的键, 逗号分隔 (填进策略组的 use)
provider_keys() {
    _out=""
    for _f in $(server_files); do
        _k="$(key_of "$(field_of "$_f" base)")"
        _out="${_out:+$_out, }$_k"
    done
    printf '%s' "$_out"
}

# proxy-providers 段落 (YAML, 缩进两格)
providers_yaml() {
    for _f in $(server_files); do
        _b="$(field_of "$_f" base)"; _i="$(field_of "$_f" id)"; _k="$(field_of "$_f" secret)"
        _key="$(key_of "$_b")"
        printf '  %s:\n' "$_key"
        printf '    type: http\n'
        printf '    url: "%s/c/sub/%s?k=%s&format=provider"\n' "$_b" "$_i" "$_k"
        printf '    interval: 3600\n'
        printf '    path: ./providers/%s.yaml\n' "$_key"
        printf '    health-check:\n      enable: true\n      url: http://www.gstatic.com/generate_204\n      interval: 300\n'
    done
}

# 分流数据库是否就位 (两份都要): 配置里的 GEOSITE / GEOIP,CN 规则靠它
geo_ok() { [ -s "$ZP_DIR/geoip.metadb" ] && [ -s "$ZP_DIR/geosite.dat" ]; }

# 管理界面的地址 (带界面令牌)。上报给面板, 用户就能在面板的设备卡上直接点开 ——
# 不必回终端敲 `zeroproxy ui` (那一步是"这个页面要授权"的唯一门槛)。
# 令牌文件不在 (极少数固件上没生成) 就返回空, 面板那边自然不显示这个入口。
#
# 端口从 ui.port 读 (安装时写下的): 空 = 走固件自己的 Web 服务 (80), 有值 = 界面由
# 自带的 httpd 在那个端口发。存端口而不是整个 URL, 是为了 LAN 地址换了之后还算得对。
ui_url() {
    _port="$(cat "$ZP_DIR/ui.port" 2>/dev/null || true)"
    [ -n "$_port" ] && _port=":$_port"
    _ip="$(uci get network.lan.ipaddr 2>/dev/null || true)"
    [ -n "$_ip" ] || _ip="$(ip -4 addr show 2>/dev/null | sed -n 's/.*inet \([0-9.]*\).*/\1/p' | grep -v '^127\.' | head -n1)"
    [ -n "$_ip" ] || _ip="192.168.8.1"
    _tok="$(cat "$ZP_DIR/ui.token" 2>/dev/null)"
    [ -n "$_tok" ] || return 0
    printf 'http://%s%s/cgi-bin/zeroproxy?k=%s' "$_ip" "$_port" "$_tok"
}

# 这一档数据面能不能一并接管 IPv6 (装机时探的)。面板据此决定给不给双栈配置 ——
# 覆盖不到还给双栈, 等于让内核去管它管不了的东西。老 caps 没有这一位时按 0 报:
# 宁可在面板上显示"IPv6 未接管", 也不能说成接管了。
ipv6_flag() {
    _v="$(caps_get ipv6)"
    case "$_v" in
        0|1) printf '%s' "$_v" ;;
        *) printf '0' ;;
    esac
}

build_config() {
    migrate_servers
    _first="$(first_server)"
    [ -n "$_first" ] || return 1
    _b="$(field_of "$_first" base)"; _i="$(field_of "$_first" id)"; _k="$(field_of "$_first" secret)"
    _n="$(count_servers)"
    # 没有分流数据库就不能要 geo 规则 (面板知道这件事, 会给一份降级配置)。判据必须是
    # 本机文件: 数据库在路由器上, 面板看不到它。
    _geo="1"; geo_ok || _geo="0"
    # 本机没有 nft / tproxy 时别让面板写 auto-redirect: 那一项会让整个 tun 建不起来
    # (真机现象: 装完 zp-tun 一直不出现, 脚本退回 tproxy, 而那台机器的 tproxy 也是
    # 同一个原因不可用 —— 全屋透明代理名存实亡)。判据同样只能是本机。
    _tp="$(caps_flag)"
    # 数据面本身也由本机决定: 面板看到 redirect 就不给 tun 段 (这台固件建不出设备,
    # 带上它内核直接起不来)。
    _dp="$(datapath_flag)"
    _ip6="$(ipv6_flag)"
    _mtu="$(tun_mtu_flag)"
    if [ "$_n" -le 1 ]; then
        http_get "$_b/c/sub/$_i?k=$_k&format=clash&rules=smart&geo=$_geo&tproxy=$_tp&datapath=$_dp&ipv6=$_ip6&mtu=$_mtu"
        return $?
    fi
    _skel="$(http_get "$_b/c/sub/$_i?k=$_k&format=skeleton&rules=smart&geo=$_geo&tproxy=$_tp&datapath=$_dp&ipv6=$_ip6&mtu=$_mtu")" || return 1
    [ -n "$_skel" ] || return 1
    # provider 段落走临时文件而不是 `awk -v block=...`: -v 的值里带换行时, BSD awk
    # 直接报 "newline in string", busybox awk 的转义处理也不一致 (本机演练抓到的)。
    # `getline < file` 是 POSIX, 各版本 awk 都按字面读。
    _block="$ZP_DIR/.providers.$$.block"
    providers_yaml > "$_block" || return 1
    printf '%s\n' "$_skel" | awk -v keys="$(provider_keys)" -v blockfile="$_block" '
        /^proxy-providers: \{\}[[:space:]]*$/ {
            print "proxy-providers:"
            while ((getline line < blockfile) > 0) print line
            close(blockfile)
            next
        }
        /use: \[\]/ { sub(/use: \[\]/, "use: [" keys "]"); print; next }
        { print }
    '
    _rc=$?
    rm -f "$_block"
    return $_rc
}
json_get() {
    if command -v jsonfilter >/dev/null 2>&1; then
        printf '%s' "$1" | jsonfilter -e "@.$2" 2>/dev/null | head -n1
    else
        printf '%s' "$1" | sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1
    fi
}
# 布尔位解析 (面板回的 desired / geo)。与安装脚本里那份同理: `\|` 是 GNU 扩展, BSD sed
# 会静默取空, 于是"面板要求关"被读成"没要求" —— 这是本机演练会踩到的坑。
json_get_bool() {
    _json="$1"; _key="$2"
    if printf '%s' "$_json" | grep -q "\"$_key\"[[:space:]]*:[[:space:]]*true"; then
        printf 'true\n'
    elif printf '%s' "$_json" | grep -q "\"$_key\"[[:space:]]*:[[:space:]]*false"; then
        printf 'false\n'
    fi
}

# curl/uclient-fetch 的"证书类错误"判据 (与 CLI 里那一份同一个口径)。
zp_tls_rc() {
    case "${1:-}" in
        35|51|58|59|60|64|66|77|80|83|90|91) return 0 ;;
        *) return 1 ;;
    esac
}
# 证书降级告警: 只做一次, 且必须说清是降级 —— 旧版这里对 uclient-fetch 直接
# `--no-check-certificate`, 等于把 TLS 从信任锚降成"尽力而为" (P1-3)。
ZP_TLS_WARNED=""
zp_tls_warn() {
    [ "$ZP_TLS_WARNED" = "1" ] && return 0
    ZP_TLS_WARNED=1
    log "面板证书校验没通过 ($2) —— 本次改为不校验继续 (降级, 不是正常路径)"
}

http_post() {
    # 心跳 (/c/report) 专用。它是**幂等**的 —— 报两次"我还活着"没有任何副作用, 所以丢包
    # 值得重试: 真机上这条路的四成 SYN 是被丢掉的, 只发一次的话面板上这台设备会一直在
    # "在线/离线"之间闪 (真机日志里那一串 `面板不可达 (第 1 次), 保持当前状态`)。
    #
    # 装机时那个 POST (/c/pair) **故意不在这里**: 它要用掉一个一次性配对码, 重放等于赌
    # "第一次其实没生效" —— 那条路见安装脚本里的 http_post (不重试)。
    #
    # 第 3 个参数是设备 secret: 给了就先发 `Authorization: Bearer` (新面板路径,
    # secret 不进 URL); 旧面板不认头 (4xx) 时自动退回"只发正文" (正文里的 k 旧面板要)。
    _url="$1"; _body="$2"; _sec="${3:-}"
    _tries=0
    while :; do
        _tries=$((_tries + 1))
        _rc=1
        if command -v curl >/dev/null 2>&1; then
            _hdr=""; [ -n "$_sec" ] && _hdr="Authorization: Bearer $_sec"
            if [ -n "$_hdr" ]; then
                if curl -fsS -m 20 -H 'Content-Type: application/json' -H "$_hdr" \
                    --data "$_body" "$_url" 2>/dev/null; then _rc=0; else _rc=$?; fi
            elif curl -fsS -m 20 -H 'Content-Type: application/json' \
                --data "$_body" "$_url" 2>/dev/null; then
                _rc=0
            else
                _rc=$?
            fi
            if [ "$_rc" != "0" ] && zp_tls_rc "$_rc"; then
                zp_tls_warn "$_url" "curl $_rc"
                if [ -n "$_hdr" ]; then
                    if curl -fsSk -m 20 -H 'Content-Type: application/json' -H "$_hdr" \
                        --data "$_body" "$_url" 2>/dev/null; then _rc=0; fi
                elif curl -fsSk -m 20 -H 'Content-Type: application/json' \
                    --data "$_body" "$_url" 2>/dev/null; then
                    _rc=0
                fi
            fi
            # 旧面板: 不认 Bearer 时把正文原样再发一次 (正文里带 k)
            if [ "$_rc" = "22" ] && [ -n "$_sec" ]; then
                if curl -fsS -m 20 -H 'Content-Type: application/json' \
                    --data "$_body" "$_url" 2>/dev/null; then _rc=0; fi
            fi
        else
            _errf="$(mktemp /tmp/.zp-agent-tls.XXXXXX 2>/dev/null || echo /tmp/.zp-agent-tls.$$)"
            for _tool in uclient-fetch wget; do
                command -v "$_tool" >/dev/null 2>&1 || continue
                if "$_tool" -q -T 20 -O - --post-data "$_body" "$_url" 2>"$_errf"; then
                    _rc=0
                elif grep -Eqi 'ssl|tls|certificate|cert verify|x509' "$_errf" 2>/dev/null; then
                    # 只有 stderr 明确是 TLS/证书类时才降级一次
                    zp_tls_warn "$_url" "$_tool 证书校验失败"
                    if "$_tool" -q --no-check-certificate -T 20 -O - \
                        --post-data "$_body" "$_url" 2>/dev/null; then
                        _rc=0
                    fi
                fi
                break
            done
            rm -f "$_errf"
        fi
        [ "$_rc" = "0" ] && return 0
        [ "$_rc" != "22" ] || return "$_rc"     # HTTP 层面失败 (403/404…): 面板已明确答复
        [ "$_tries" -lt 3 ] || return "$_rc"
        sleep 1
    done
}
http_get() {
    # 面板那条路会偶尔丢一个包就整条挂住 (真机实测: 直连同一个地址, 6 次里 3 次 SYN 石沉
    # 大海, 通的那几次是 0.15 秒)。只拉一次的话, 一次丢包就等于"拉配置失败" —— 而更新
    # 模式下那句话会说成"面板可能拒绝了这台设备的凭据", 把人引到重新配对上, 方向全错。
    # 所以这里重试 (秒级, 比让用户去查凭据便宜得多)。次数与超时和安装脚本里的那份对齐:
    # 每次 10 秒、最多 5 次 —— 丢包时那一次会白等到超时, 30 秒 × 几次就是用户看到的
    # "更新非常慢"; 而拉配置这份正文只有十几 KB, 10 秒已经是二十倍余量。
    #
    # 唯一的例外是 HTTP 层面的失败 (404 / 502 …): curl -f 会以 22 退出 —— 那是"面板明确
    # 说没有", 重试没有意义, 也不该把等待加到一次真正的错误上。
    _tries=0
    while :; do
        _tries=$((_tries + 1))
        _rc=1
        _out=""
        if command -v curl >/dev/null 2>&1; then
            if _out="$(curl -fsS -m 10 "$1" 2>/dev/null)"; then
                _rc=0
            else
                _rc=$?
                # 只有证书类错误才降级一次 (旧版只认 60, 而 35/51/58/77 同样是 TLS 层失败)
                if zp_tls_rc "$_rc"; then
                    zp_tls_warn "$1" "curl $_rc"
                    if _out="$(curl -fsSk -m 10 "$1" 2>/dev/null)"; then _rc=0; fi
                fi
            fi
        else
            # 没有 curl: 先按默认 (校验) 跑, 只有 stderr 明确是证书类才降级一次。
            _egt="$(mktemp /tmp/.zp-agent-tls.XXXXXX 2>/dev/null || echo /tmp/.zp-agent-tls.$$)"
            for _tool in uclient-fetch wget; do
                command -v "$_tool" >/dev/null 2>&1 || continue
                if _out="$("$_tool" -q -O - "$1" 2>"$_egt")"; then
                    _rc=0
                elif grep -Eqi 'ssl|tls|certificate|cert verify|x509' "$_egt" 2>/dev/null; then
                    zp_tls_warn "$1" "$_tool 证书校验失败"
                    if _out="$("$_tool" -q --no-check-certificate -O - "$1" 2>/dev/null)"; then _rc=0; fi
                fi
                break
            done
            rm -f "$_egt"
        fi
        if [ "$_rc" = "0" ]; then printf '%s' "$_out"; return 0; fi
        [ "$_rc" != "22" ] || return "$_rc"
        [ "$_tries" -lt 5 ] || return "$_rc"
        # 走 stderr: 这个函数的 stdout 是配置正文本身。
        # **别再说"链路丢包"**: 拉配置失败可能是超时 / DNS / TLS / 面板明确拒绝 —— 这几类
        # 完全不是一回事 (8.67/8.68 两轮真机都因为它们长得一样而查了两遍), 说出来才查得动。
        case "$_rc" in
            6)  _why='域名解析不了 (DNS)' ;;
            7)  _why='连不上 (被拒 / 不可达)' ;;
            18) _why='收到不完整的数据 (被截断)' ;;
            22) _why='面板明确拒绝 (HTTP 4xx / 5xx)' ;;
            28) _why='超时 —— 多半是链路在丢包' ;;
            35|60) _why='TLS / 证书错误' ;;
            52|56) _why='连接被中断' ;;
            *)  _why="其它错误 (curl $_rc)" ;;
        esac
        printf '  · 面板第 %s 次没回话 (%s), 正在重试…\n' "$_tries" "$_why" >&2
        sleep "$_tries"
    done
}
# 大文件下载 (分流数据库 4 MB)。**不重试**: 这一个是几 MB 的传输, 重试的代价远大于收益,
# 而调用方 (ensure_geo) 本来就有"用本机已有的那份"这条退路。
#
# 第 2 个参数是超时秒数, 默认 600 —— 30 秒的接口超时对 4 MB 太紧, 慢宽带会直接失败。
# 「刷新一份本机已经有的数据」时调用方会给一个短得多的值: 那种情况下超时只是"这次不刷了",
# 不是"装不上"。
http_get_file() {
    _tmo="${2:-600}"
    if command -v curl >/dev/null 2>&1; then
        # 先校验证书; 只有证书类错误 (curl 35/51/…/60) 才降级一次并说出来。
        if curl -fsS -m "$_tmo" "$1" 2>/dev/null; then return 0; fi
        _rgf=$?
        if zp_tls_rc "$_rgf"; then
            zp_tls_warn "$1" "curl $_rgf"
            curl -fsSk -m "$_tmo" "$1" 2>/dev/null && return 0
        fi
        return "$_rgf"
    fi
    # 没有 curl: 先按默认 (校验) 跑, 只有 stderr 明确是证书类才降级一次。
    _egf="$(mktemp /tmp/.zp-agent-get.XXXXXX 2>/dev/null || echo /tmp/.zp-agent-get.$$)"
    for _tool in uclient-fetch wget; do
        command -v "$_tool" >/dev/null 2>&1 || continue
        if "$_tool" -q -T "$_tmo" -O - "$1" 2>"$_egf"; then rm -f "$_egf"; return 0; fi
        if grep -Eqi 'ssl|tls|certificate|cert verify|x509' "$_egf" 2>/dev/null; then
            zp_tls_warn "$1" "$_tool 证书校验失败"
            if "$_tool" -q --no-check-certificate -T "$_tmo" -O - "$1" 2>/dev/null; then
                rm -f "$_egf"; return 0
            fi
        fi
        break
    done
    rm -f "$_egf"
    return 1
}

# 内核是否在跑 —— 这是要上报给面板的 actual。
# 看两件事: 我们的开关意图 (core.up 标记) + procd 说这个服务在跑。
# 注意 `/etc/init.d/zeroproxy` 是**只含内核**的服务 (控制 agent 是另一个服务
# zeroproxy-agent): 两个实例合在一个服务里的时候 `running` 会把"只有 agent 活着"
# 也算成内核在跑, 面板于是永远显示"已连接" —— 拆开之后这里才能用它。
core_up() {
    [ -f "$ZP_DIR/core.up" ] || return 1
    /etc/init.d/zeroproxy running >/dev/null 2>&1 && return 0
    # 兜底: 老版本 rc.common 没有 running 子命令时看进程 (busybox 不一定有 pgrep,
    # 命令不存在时这里只是返回非 0, 不会因为 set -e 把 agent 打死)
    pgrep -f "$ZP_DIR/mihomo" >/dev/null 2>&1
}

# "这台机器现在有没有在提供代理" —— 标准模式下是 mihomo 在跑, 性能模式下是 dae 在跑。
# 为什么单列一个: 它是**语义**上的总闸, 两个数据面都要算进来 —— 否则开了性能模式之后,
# 面板上会显示"已关闭"(心跳里的 actual 取自 core_up), 而家里其实好好的。
proxy_up() {
    core_up && return 0
    [ -n "$(pidof dae 2>/dev/null)" ] && return 0
    return 1
}

# 性能模式的**意图** (说好在用)。为什么要单列: 切换过程中有一小段"mihomo 已停、dae 还没
# 起来"的空档, 那个空档里 proxy_up 是假 —— 而 agent 每 15 秒一轮心跳, 撞上就会替用户把
# 标准模式拉回来, 于是两个数据面同时在, 出口验证必然判失败 (真机上就是这么失败的: 探针是
# 通的, 拦下它的是"mihomo 还在跑")。用户已经明确进了那一档, 这几秒该等它 —— 而 dae 真挂了
# 有看门狗在 45 秒内退回标准模式, 退回来之后这里自然会再接管。
perf_intending() {
    [ -f "$ZP_DIR/perf/state" ] || return 1
    [ "$(sed -n '1p' "$ZP_DIR/perf/state" 2>/dev/null | tr -d '\r\n')" = "on" ]
}

flush_dns() { killall -HUP dnsmasq 2>/dev/null || /etc/init.d/dnsmasq reload 2>/dev/null || true; }

# 本地控制口只用单次、短超时探测。这里不能复用 http_get: 后者面向面板网络，
# 自带 5 次重试；套进外层轮询会把 15 秒放大成几分钟。
local_api_ready() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsS --connect-timeout 1 --max-time 1 \
            "http://127.0.0.1:9090/version" >/dev/null 2>&1
    elif command -v uclient-fetch >/dev/null 2>&1; then
        uclient-fetch -q -T 1 -O /dev/null "http://127.0.0.1:9090/version" >/dev/null 2>&1
    elif command -v wget >/dev/null 2>&1; then
        wget -q -T 1 -O /dev/null "http://127.0.0.1:9090/version" >/dev/null 2>&1
    else
        return 1
    fi
}

# ---------------------------------------------------------------- 修复1: switch_core 等 mihomo API 真正就绪再设 core.up
# 原来的实现: start → sleep 2 → touch core.up
# 问题: mihomo 从 start 到 API 9090 可用通常需要 3~8 秒, sleep 2 秒太短, 下一轮心跳
# (最多 5 秒后) 看到 proxy_up=true 但内核还没完全启动, 如果面板要求关闭就会再停掉,
# 形成 "起→停→起→停" 的震荡。修复: start 后轮询 API, 真正就绪后才设 core.up。
switch_core() {
    if [ "$1" = "on" ]; then
        /etc/init.d/zeroproxy start >/dev/null 2>&1 || true
        # 等 mihomo API 真正就绪 (最多等 15 秒), 而不是固定等 2 秒
        _wait=0
        while [ "$_wait" -lt 15 ]; do
            if local_api_ready; then
                touch "$ZP_DIR/core.up"
                flush_dns
                return 0
            fi
            sleep 1
            _wait=$((_wait + 1))
        done
        rm -f "$ZP_DIR/core.up"
        log "内核启动后 API 未就绪 (15 秒), 不标记为已启动"
        return 1
    else
        rm -f "$ZP_DIR/core.up"
        /etc/init.d/zeroproxy stop >/dev/null 2>&1 || true
        nft delete table inet zp_router 2>/dev/null || true
        flush_dns
    fi
}

# ---------------------------------------------------------------- 修复2: apply_config 增加超时限制与去重
# 原来: mihomo -t 可能卡很久 (配置大/文件系统慢), 阻塞心跳循环
# 修复: 限制超时 30 秒; 增加本轮已拉配置的标记, 防止同一轮心跳多次拉取
APPLY_CONFIG_LOCK=""

apply_config() {
    # 分流数据库不在就先补一次: 上一次装机降级 (面板取不到上游) 或被人清过时, 这里
    # 自动回到完整分流 —— 用户不用再登录路由器做任何事。
    ensure_geo >/dev/null 2>&1 || true
    # 原子替换: 新配置先落 .new, 校验通过才替换, 失败保留旧配置继续用。
    build_config > "$CONF.new" 2>/dev/null || { rm -f "$CONF.new"; return 1; }
    # 单服务器模式带内联 proxies, 多服务器模式带 proxy-providers —— 唯一共同的锚点是
    # 策略组, 所以用它判断"这看起来像一份配置"。
    grep -q '^proxy-groups:' "$CONF.new" || { rm -f "$CONF.new"; return 1; }
    # 配置校验超时: 用 timeout 命令 or 背景执行 + 超时 detection.
    # `_config_ok` starts as failure (1) and is only cleared to 0 when the validator
    # **exits 0** -- never on a non-zero/timeout result. (Previously the `timeout`
    # branch only assigned `$?` on failure, so a successful validation left
    # `_config_ok=1` and a good config was rejected -- F01.)
    _config_ok=1
    if command -v timeout >/dev/null 2>&1; then
        timeout 30 /etc/zeroproxy/mihomo -t -d "$ZP_DIR" -f "$CONF.new" >/dev/null 2>&1
        _config_ok=$?
    else
        # 没有 timeout: 背景执行, 15 秒后检查
        /etc/zeroproxy/mihomo -t -d "$ZP_DIR" -f "$CONF.new" >/dev/null 2>&1 &
        _cfg_pid=$!
        _cfg_wait=0
        while [ "$_cfg_wait" -lt 15 ]; do
            if ! kill -0 "$_cfg_pid" 2>/dev/null; then
                if wait "$_cfg_pid" 2>/dev/null; then
                    _config_ok=0
                else
                    _config_ok=$?
                fi
                break
            fi
            sleep 1
            _cfg_wait=$((_cfg_wait + 1))
        done
        if [ "$_cfg_wait" -ge 15 ]; then
            kill "$_cfg_pid" 2>/dev/null || true
            wait "$_cfg_pid" 2>/dev/null || true
            _config_ok=28  # 超时
            log "配置校验超时 (15秒), 保留旧配置"
        fi
    fi
    
    if [ "$_config_ok" != "0" ]; then
        rm -f "$CONF.new"
        log "新配置校验失败 (退出码 $_config_ok), 保留原配置"
        return 1
    fi
    mkdir -p "$ZP_DIR/providers"
    mv "$CONF.new" "$CONF"
    # 只在"该开"的时候重启内核。关闭状态下也重启的话, 内核会被反复拉起来又被下一轮
    # 心跳关掉 —— 真机日志里就是这样刷屏的 (面板上表现为"同步中"来回跳)。
    if core_up; then
        /etc/init.d/zeroproxy restart >/dev/null 2>&1 || true
    fi
    log "配置已更新并重载"
    return 0
}

# ---------------------------------------------------------------- 心跳逻辑

# 从面板取分流数据库 (参数 force 时即使本地已有也重取)。返回 0 = 两份都齐了。
# 一份都取不到时返回非 0: 调用方据此输出"不含 geo 规则"的降级配置 —— 能上网, 而且
# 面板恢复后下一次重建配置会自动换回完整分流。
ensure_geo() {
    _force="${1:-}"
    _need=""
    for _g in $GEO_FILES; do
        if [ "$_force" = "force" ] || [ ! -s "$ZP_DIR/$_g" ]; then _need="$_need $_g"; fi
    done
    [ -n "$_need" ] || return 0
    # 刷新一份**本机已经有**的数据时, 只给面板 2 分钟: 它不是"拿不到就装不上" —— 本机
    # 那份还在用, 到点就继续往下走 (install_geo 会照实说"本次刷新失败")。本机没有副本时
    # 才值得等满: 面板首次要去上游取 4 MB, 那是它的正常工作量。
    _tmo=600
    _have_all=1
    for _g in $_need; do [ -s "$ZP_DIR/$_g" ] || _have_all=0; done
    [ "$_have_all" = "1" ] && _tmo=120
    for _f in $(server_files); do
        _b="$(field_of "$_f" base)"
        [ -n "$_b" ] || continue
        _got=1
        for _g in $_need; do
            _tmp="$ZP_DIR/.geo-$$.part"
            if http_get_file "$_b/c/geo/$_g" "$_tmo" > "$_tmp" 2>/dev/null && [ -s "$_tmp" ]; then
                mv "$_tmp" "$ZP_DIR/$_g"
            else
                rm -f "$_tmp"
                _got=0
                break
            fi
        done
        [ "$_got" = "1" ] && return 0
    done
    geo_ok
}

# caps 里的一个键 (一行一个 key=value)。老版本 (schema 1) 的 caps 没有 chosen,
# 那时按 tun 报 —— 升级上来的机器行为不变。
# 取一个能力位。**优先从这一轮的状态快照里读** (zpcore state 是唯一的生产者); 快照不在
# (zpcore 没装 / 还没取下来) 才直接读 caps 文件 —— 两种来源的键名与语义完全一样。
caps_get() {
    if [ -r "$ZP_STATE" ]; then
        _cv="$(sed -n "s/^$1=//p" "$ZP_STATE" 2>/dev/null | head -n1)"
        if [ -n "$_cv" ]; then printf '%s' "$_cv"; return 0; fi
    fi
    sed -n "s/^$1=//p" "$ZP_DIR/caps" 2>/dev/null | head -n1
}

# 把这一轮的状态取下来 (zpcore 是唯一的生产者)。取不到就删掉快照 —— 于是 caps_get 会
# 退回直接读 caps 文件, 而不是拿着一份陈旧的。
refresh_state() {
    [ -x "$ZP_DIR/zpcore" ] || return 0
    "$ZP_DIR/zpcore" state --dir "$ZP_DIR" --init /etc/init.d/zeroproxy > "$ZP_STATE" 2>/dev/null \
        || rm -f "$ZP_STATE"
}

# 这台设备现在走的数据面。面板据此决定要不要给 tun 段 (redirect/tproxy 模式下带 tun
# 段会让内核起不来)。判据是本机 caps 里的 chosen —— 装机时探的, 并且可能已被降级。
datapath_flag() {
    _v="$(caps_get chosen)"
    case "$_v" in
        tun|tproxy|redirect|none) printf '%s' "$_v" ;;
        *) printf 'tun' ;;
    esac
}

# tun 该用的 MTU (装机时按 WAN 的实际 MTU 算的)。面板据此写 tun.mtu —— 它自己不知道
# 这台机器外面是 PPPoE 还是以太网。老 caps 没有这一位时按 1500 报 (行为不变)。
tun_mtu_flag() {
    _v="$(caps_get tun_mtu)"
    case "$_v" in
        ''|*[!0-9]*) printf '1500' ;;
        *) printf '%s' "$_v" ;;
    esac
}

report_fields_json() {
    _ipv6="$(ipv6_flag)"
    _mtu="$(tun_mtu_flag)"
    _offload="$(caps_get offload)"
    _bench_direct="$(sed -n 's/^direct_kbps=//p' "$ZP_DIR/bench" 2>/dev/null | head -n1)"
    _bench_proxy="$(sed -n 's/^proxy_kbps=//p' "$ZP_DIR/bench" 2>/dev/null | head -n1)"
    case "$_bench_direct" in ''|*[!0-9]*) _bench_direct=0 ;; esac
    case "$_bench_proxy" in ''|*[!0-9]*) _bench_proxy=0 ;; esac
    _why=""
    if [ "$COV_REPORT" = "none" ]; then
        for _lv in tun tproxy redirect; do
            _reason="$(caps_get "why.$_lv")"
            if [ -n "$_reason" ]; then
                _why="${_why:+$_why · }$_lv: $_reason"
            fi
        done
    fi
    printf '{"mode":"%s","covered":"%s","why":"%s","client":"%s","override":"%s","ipv6":"%s","mtu":"%s","offload":"%s","bench_direct":"%s","bench_proxy":"%s"}' \
        "$DP_REPORT" "$COV_REPORT" "$(json_escape "$_why")" "$ZP_VERSION" "$OVERRIDE" \
        "$_ipv6" "$_mtu" "$(json_escape "$_offload")" "$_bench_direct" "$_bench_proxy"
}

# 从面板取配置 (config 模式: 打印到 stdout; 默认模式: 拉取并落盘)。
# 配置只在内容变化 (或距上次拉取超过 6 小时) 时更新。

# caps_flag 返回面板配置里的 auto-redirect 开关。
caps_flag() {
    # 面板配置里能不能写 auto-redirect。装机时默认 1 (与面板默认一致), 只有**真的因为
    # 它起不来 tun** 时才会被学成 0 (见安装脚本的 tun_retry_without_redirect)。
    # 文件不在 = 老版本升级上来的, 按 1 报 —— 行为不变。
    _v="$(caps_get autoredirect)"
    case "$_v" in
        0|1) printf '%s' "$_v" ;;
        *)   printf '1' ;;
    esac
}

# ---------------------------------------------------------------- 主循环: 心跳 + 配置拉取 + 状态切换
#
# 修复3: 心跳间隔自适应
#   - 不稳定态 (SLEEP_UNSTABLE=5秒): 配置变更/刚启动/面板不可达 → 快速反应
#   - 稳定态 (SLEEP_STABLE=30秒): 连续 3 轮无变更 → 降低开销
#
# 修复4: 多服务器心跳容错
#   - 至少一台成功应答就算"面板可达"
#   - FAILS 连续计数: 只有全部失败才累加, 有成功就清零
#
# 修复5: 配置拉取去重
#   - LAST_REV 只在 apply_config 成功时更新
#   - LAST_PULL 记录时间戳, 避免频繁拉取
#
# 修复6: 重启去重
#   - SWITCH_PENDING 标记: 本轮已执行 switch_core 就不再做

LAST_REV=""
LAST_PULL=0
FAILS=0
#: "已应用版本" (面板的 applied_rev)。**只有 apply_config 成功** (配置校验通过 + 落盘)
#: 才写它 —— 下载 ≠ 应用。面板据此区分"已下载未应用/已应用" (P2-9): 以前面板把
#: "把订阅发给了设备"当成"设备已经在用", 于是升级后界面永远显示已应用。
#: 落盘是为了 agent 重启后还能如实回答, 不必等下一次配置变更。
APPLIED_REV="$(cat "$ZP_DIR/applied.rev" 2>/dev/null | tr -d '\r\n')"
# 修复3: 心跳状态机 —— 稳定/不稳定
HEARTBEAT_STATE="unstable"  # unstable | stable
# 稳定计数: 连续 N 轮无变更才进入稳定态
STABLE_COUNT=0
STABLE_THRESHOLD=3          # 连续3轮无变更才进入稳定态
# 修复6: 本轮是否已触发过核心开关切换
SWITCH_PENDING=""

# 命令行模式: agent.sh config 打印一份合并后的配置 (安装脚本与 CLI 都用);
# agent.sh geo 只拉取/更新指定分流数据库;
# agent.sh once 只跑一轮心跳 (排查用)。默认无参数 = 常驻循环。
case "${1:-}" in
    config)  migrate_servers; refresh_state; build_config; exit $? ;;
    geo)     migrate_servers; ensure_geo "${2:-}"; exit $? ;;
    migrate) migrate_servers; exit $? ;;
    once)    RUN_ONCE=1 ;;
esac

while true; do
    migrate_servers
    refresh_state
    if [ "$(count_servers)" -eq 0 ]; then
        if proxy_up; then
            switch_core off
        fi
        refresh_state
        [ -n "${RUN_ONCE:-}" ] && exit 0
        sleep "$SLEEP_STABLE"
        continue
    fi
    # 性能模式 (eBPF / dae) 的看门狗 —— **必须在算心跳之前**: 那一档下 mihomo 是停着的,
    # dae 一死家里就断网, 而用户不会知道去关掉它。连续 3 轮看不到进程就自动退回标准模式,
    # 于是这一轮上报出去的 mode/covered 已经是从现场读到的真实状态。
    if [ -f "$ZP_DIR/perf.sh" ]; then
        . "$ZP_DIR/perf.sh"
        zp_perf_tick >/dev/null 2>&1 || true
    fi
    # 多服务器: **每一台都要收到心跳**。
    # 早期版本只向第一台上报, 于是"没被上报的那台"在面板上永远显示离线 —— 用户加完
    # 第二台服务器, 看到的正是第二台一直是同步中 / 离线 (真机反馈)。
    #
    # 总开关取"任一为关则关": 任一面板把它关掉, 全屋就断; 在那台上再打开即恢复。
    # 新设备默认就是"开", 所以只有"没人碰过"的面板不会干扰。
    DESIRED_ALL="true"
    REV=""
    # 本机覆盖 (面板不可达时的开/关, 见 CLI 的 on|off)。它优先于面板的期望状态 ——
    # 否则"家里网出问题时连关都关不掉"这件事永远解决不了: 面板不可达时 CLI 写的就是它。
    # 一旦写了就**一直生效** (面板恢复也不会自动改回去), 想交回面板执行
    # `zeroproxy local-auto` —— 静默恢复是最坏的结果 (用户以为关了, 其实又被打开)。
    OVERRIDE=""
    if [ -f "$ZP_DIR/local.override" ]; then
        _ov="$(tr -d '\r\n ' < "$ZP_DIR/local.override" 2>/dev/null || true)"
        case "$_ov" in on|off) OVERRIDE="$_ov" ;; esac
    fi
    if [ -n "$OVERRIDE" ]; then
        if [ "$OVERRIDE" = "on" ]; then DESIRED_ALL="true"; else DESIRED_ALL="false"; fi
    fi
    # 管理界面地址 (带令牌) 只算一次 —— 每台面板都收到同一份, 面板据此给一个可点的入口
    UI_URL_REPORT="$(ui_url 2>/dev/null || true)"
    # 数据面: 这台设备现在走哪条路、真的接管到哪。面板据此把"已连接"说细 ——
    # 只接管了局域网 TCP 就不该显示成全屋 (真机 8.45 的教训)。
    # mode 报的是**现场** (与 covered、本地界面、CLI 同一份判据): 以前这里报 caps 里的意图
    # (chosen), 于是"选了 A、其实是 B"时面板上模式与覆盖两栏会自相矛盾。面板要"该渲染哪份
    # 配置"时另问 datapath_flag (那才是意图)。
    DP_REPORT="$(zp_live_mode 2>/dev/null)"
    [ -n "$DP_REPORT" ] || DP_REPORT="$(datapath_flag)"
    COV_REPORT="$(actual_covered)"
    # TUN + auto-redirect 没跑成时, "转发进/出 tun" 的放行规则是**易失**的 (直接插在 fw4
    # 的链上, 一次 `fw4 reload` 就没了)。内核在跑就顺手补一次 —— 幂等, 而且**按需**:
    # 健康机器 (autoredirect=1) 在这里一个 nft 都不会调用。少了它, 家里会静默地再断一次。
    if [ "$DP_REPORT" = "tun" ] && core_up && [ -f "$ZP_DIR/tunfw.sh" ]; then
        . "$ZP_DIR/tunfw.sh"
        if [ "$DP_REPORT" = "tun" ]; then zp_tunfw_allow 2>/dev/null || true; fi
    fi

    # ---------------------------------------------------------------- 心跳上报 (多服务器)
    # 修复4: 多服务器心跳容错 —— 至少一台成功才算面板可达
    FAILS=0
    RESP_OK=0
    for _f in $(server_files); do
        _b="$(field_of "$_f" base)"
        _i="$(field_of "$_f" id)"
        _k="$(field_of "$_f" secret)"
        [ -n "$_b" ] || continue
        BODY='{"device":"'"$_i"'","k":"'"$_k"'","version":"'"$ZP_VERSION"'"'
        # actual = "这台机器现在真的在提供代理" —— 性能模式下 dae 在跑也算 (proxy_up)
        if proxy_up; then BODY="$BODY"',"actual":true'; else BODY="$BODY"',"actual":false'; fi
        [ -n "$UI_URL_REPORT" ] && BODY="$BODY"',"ui":"'"$UI_URL_REPORT"'"'
        [ -n "$LAST_REV" ] && BODY="$BODY"',"rev":"'"$LAST_REV"'"'
        # 已应用版本 + 数据面健康 (P2-9): 面板只在设备**显式**报这两个时才推进
        # applied_rev (下载不算应用)。applied 由 apply_config 成功时写下; healthy 只在
        # 代理真的在提供 (core/dae 在跑) 时为 true —— 不拿"配置写好了"冒充健康。
        [ -n "$APPLIED_REV" ] && BODY="$BODY"',"applied_rev":"'"$APPLIED_REV"'"'
        if proxy_up; then BODY="$BODY"',"healthy":true'; fi
        BODY="$BODY"',"report":'"$(report_fields_json)"'}'
        RESP="$(http_post "$_b/c/report" "$BODY" "$_k" || true)"
        if [ -z "$RESP" ]; then
            FAILS=$((FAILS + 1))
            continue
        fi
        # 修复4: 只要有一台成功应答, 就标记面板可达
        RESP_OK=1
        _d="$(json_get_bool "$RESP" desired)"
        [ -n "$_d" ] || _d=true
        [ "$_d" = "false" ] && DESIRED_ALL="false"
        # 配置版本取第一台能应答的 (配置内容各台不同, 用哪台的 rev 都只是"变了就重拉")
        [ -z "$REV" ] && REV="$(json_get "$RESP" rev)"
        # 面板看到的本机公网地址 (那条心跳走直连)。性能模式的出口探针用它判断"是不是其实
        # 从本机直连出去的" —— 界面据此如实标注, 不把本机地址写成节点出口 (8.86)。
        _wip="$(json_get "$RESP" ip)"
        if [ -n "$_wip" ] && [ "$_wip" != "$(cat "$ZP_DIR/wan_ip" 2>/dev/null)" ]; then
            umask 077
            printf '%s\n' "$_wip" > "$ZP_DIR/wan_ip"
            umask 022
        fi
    done

    # ---------------------------------------------------------------- 处理面板不可达
    if [ "$RESP_OK" = "0" ]; then
        # 一台都没应答: 保持现状而不是把代理关掉 —— 断网时"维持可用"比"忠于面板"重要
        # (本机覆盖是唯一的例外: 那是用户**明确**表达的意图, 必须执行 —— 它存在的理由
        #  正是"面板挂了也要能开关"。)
        if [ -n "$OVERRIDE" ]; then
            if [ "$OVERRIDE" = "on" ] && ! proxy_up; then
                log "本机覆盖=on (面板不可达), 启动内核"
                SWITCH_PENDING="1"
                switch_core on
            elif [ "$OVERRIDE" = "off" ] && [ -f "$ZP_DIR/perf.sh" ]; then
                . "$ZP_DIR/perf.sh"
                if [ "$(zp_perf_state)" = "on" ]; then
                    log "本机覆盖=off (面板不可达), 退回标准模式并停止内核"
                    zp_perf_leave "本机覆盖关闭"
                fi
            fi
            if [ "$OVERRIDE" = "off" ] && core_up; then
                log "本机覆盖=off (面板不可达), 停止内核"
                SWITCH_PENDING="1"
                switch_core off
            fi
        fi
        [ $((FAILS % 20)) -eq 1 ] && log "面板不可达 (第 $FAILS 次), 保持当前状态"
        # 修复3: 面板不可达 → 不稳定态
        HEARTBEAT_STATE="unstable"
        STABLE_COUNT=0
        sleep "$SLEEP_UNSTABLE"
        SWITCH_PENDING=""
        continue
    fi

    # ---------------------------------------------------------------- 面板可达, 处理指令
    FAILS=0
    DESIRED="$DESIRED_ALL"

    # 性能模式先处理"面板要求关闭"这一条: 那一档下 mihomo 本来就是停的, 只停 mihomo 等于
    # 什么都没关 —— 面板上的总开关关掉就必须真的关掉 (把 dae 也退出来)。
    if [ "$DESIRED" = "false" ] && [ -f "$ZP_DIR/perf.sh" ]; then
        . "$ZP_DIR/perf.sh"
        if [ "$(zp_perf_state)" = "on" ]; then
            log "面板要求关闭 (性能模式), 退回标准模式并停止内核"
            zp_perf_leave "面板总开关关闭"
        fi
    fi

    # 修复6: 核心开关切换去重 —— 本轮已做过就不再做
    if [ "$DESIRED" = "true" ] && ! proxy_up && ! perf_intending; then
        if [ -z "$SWITCH_PENDING" ]; then
            SWITCH_PENDING="1"
            log "面板要求开启, 启动内核"
            switch_core on
        fi
    elif [ "$DESIRED" = "false" ] && proxy_up; then
        if [ -z "$SWITCH_PENDING" ]; then
            SWITCH_PENDING="1"
            log "面板要求关闭, 停止内核"
            switch_core off
        fi
    fi

    # ---------------------------------------------------------------- 配置拉取
    _now="$(date +%s)"
    _config_changed=0
    if { [ -n "$REV" ] && [ "$REV" != "$LAST_REV" ]; } || [ $((_now - LAST_PULL)) -ge 21600 ]; then
        if apply_config; then
            LAST_REV="$REV"
            LAST_PULL="$_now"
            _config_changed=1
            # 配置已校验通过并落盘 —— 这才是"已应用"。下次心跳把它显式报给面板
            # (applied_rev), 面板才把设备卡从"已下载未应用"推进到"已应用" (P2-9)。
            if [ -n "$REV" ]; then
                APPLIED_REV="$REV"
                umask 077
                printf '%s\n' "$APPLIED_REV" > "$ZP_DIR/applied.rev" 2>/dev/null || true
                umask 022
            fi
        fi
    fi

    # ---------------------------------------------------------------- 心跳状态机自适应
    if [ "$_config_changed" = "1" ] || [ -n "$SWITCH_PENDING" ]; then
        # 有配置变更或刚做过切换 → 不稳定态
        HEARTBEAT_STATE="unstable"
        STABLE_COUNT=0
    else
        # 无变更 → 稳定计数 +1
        STABLE_COUNT=$((STABLE_COUNT + 1))
        if [ "$STABLE_COUNT" -ge "$STABLE_THRESHOLD" ]; then
            HEARTBEAT_STATE="stable"
        fi
    fi

    # ---------------------------------------------------------------- 确定本轮 sleep
    if [ "$HEARTBEAT_STATE" = "stable" ]; then
        _sleep="$SLEEP_STABLE"
    else
        _sleep="$SLEEP_UNSTABLE"
    fi

    SWITCH_PENDING=""
    [ -n "${RUN_ONCE:-}" ] && exit 0
    sleep "$_sleep"
done
