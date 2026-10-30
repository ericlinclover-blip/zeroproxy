#!/bin/sh
# ZeroProxy 性能模式 (eBPF / dae)。
#
# 这一档与 tun / tproxy **互斥**: 两套都在抢同一批流量, 所以这里是"换过去 / 换回来",
# 不是"叠一层"。进去之后 mihomo 是停着的 —— 这一点也是验证的关键: 这时候流量还能通,
# 就只能是通过 dae 通的。
ZP_DIR=/etc/zeroproxy
ZP_PERF_DIR="$ZP_DIR/perf"
ZP_PERF_BIN="$ZP_PERF_DIR/dae"
ZP_PERF_CONF="$ZP_PERF_DIR/dae.dae"
ZP_PERF_LOG="$ZP_PERF_DIR/dae.log"
ZP_PERF_STATE="$ZP_PERF_DIR/state"
ZP_PERF_WHY="$ZP_PERF_DIR/why"
ZP_PERF_EXIT="$ZP_PERF_DIR/exit_ip"
ZP_PERF_PREV="$ZP_PERF_DIR/prev_chosen"
ZP_PERF_INIT=/etc/init.d/zeroproxy-perf
ZP_INIT=/etc/init.d/zeroproxy
#: 出口探测目标: 必须是一个"只有走代理才回得来"的境外地址 (用它证明流量真的过了节点)。
#: 可以在环境里覆盖 (比如换成自己的地址)。
ZP_PERF_PROBE="${ZP_PERF_PROBE:-https://www.cloudflare.com/cdn-cgi/trace}"

log() { logger -t zeroproxy-perf "$*"; }

zp_perf_state() { sed -n '1p' "$ZP_PERF_STATE" 2>/dev/null | tr -d '\r\n'; }
zp_perf_set_state() { mkdir -p "$ZP_PERF_DIR"; printf '%s\n' "$1" > "$ZP_PERF_STATE"; }
zp_perf_why() { sed -n '1p' "$ZP_PERF_WHY" 2>/dev/null | tr -d '\r\n'; }
zp_perf_why_set() { mkdir -p "$ZP_PERF_DIR"; printf '%s\n' "$1" | tr -d '\r\n' > "$ZP_PERF_WHY"; }

# dae **现在**在不在 —— 判据是现场 (进程), 不是"我们下过一条命令"。
#
# 与 mihomo 那边同一个道理 (见 zp_perf_mihomo_live): 固件上的 `init running` 不可靠, 而这一档
# "说好在用而 dae 已经不在"是要立刻退回的 (家里断着不能被看门狗漏掉)。所以进程判据能用时
# 只认它; 只有这台机器连 pidof 都没有, 才回落到服务状态。
zp_perf_live() {
    pidof dae >/dev/null 2>&1 && return 0
    command -v pidof >/dev/null 2>&1 && return 1
    "$ZP_PERF_INIT" running >/dev/null 2>&1
}

# mihomo 在不在 —— 这一步是"这条连通性到底是谁挣来的"的判据, 必须准。
#
# 判据以**进程**为准 (dae 那边用的也是进程): 固件上的 `/etc/init.d/<svc> running`
# 不可靠, 而它一旦"永远为真", 每次都会被判成"两个数据面同时在, 不能算换成功" ——
# 性能模式就永远进不去, 而且报出来的原因是错的 (看起来像"流量出不去", 其实那天探针是通的,
# 真机 8.84)。两个进程判据 (pidof / pgrep) 都没有的机器才回落到服务状态。
zp_perf_mihomo_live() {
    pidof mihomo >/dev/null 2>&1 && return 0
    if command -v pgrep >/dev/null 2>&1; then
        pgrep -f "$ZP_DIR/mihomo" >/dev/null 2>&1 && return 0
        return 1
    fi
    "$ZP_INIT" running >/dev/null 2>&1
}

# 局域网接口。dae 不会自己猜局域网口 (只有 wan 能 auto), 所以这个值必须问出来。
zp_perf_lan() {
    _d="$(uci -q get network.lan.device 2>/dev/null || uci -q get network.lan.ifname 2>/dev/null || true)"
    [ -n "$_d" ] || _d=br-lan
    printf '%s' "$_d"
}

# 刷本机 DNS 缓存。进出这一档时解析路径整个换了 (dae 接管 DNS / 又交回 mihomo), 而 dnsmasq
# 还揣着上一条路径上拿到的答案 —— 真机上就有一个被污染的域名在里面躺了很久 (8.85)。
# 动作与 mihomo init 里那一步一致。
zp_perf_flush_dns() { killall -HUP dnsmasq 2>/dev/null || /etc/init.d/dnsmasq reload 2>/dev/null || true; }

# 面板凭据 (第一个面板)。dae 的节点是**面板渲染好**的, 所以这里只需要地址与设备凭据。
zp_perf_panel() {
    _f="$(ls "$ZP_DIR/servers"/*.json 2>/dev/null | head -n1)"
    [ -n "$_f" ] || _f="$ZP_DIR/device.json"
    [ -f "$_f" ] || return 1
    _b="$(sed -n 's/.*"base"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$_f" | head -n1)"
    _id="$(sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$_f" | head -n1)"
    _sec="$(sed -n 's/.*"secret"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$_f" | head -n1)"
    [ -n "$_b" ] && [ -n "$_id" ] && [ -n "$_sec" ] || return 1
    printf '%s %s %s' "$_b" "$_id" "$_sec"
}

# ---------------------------------------------------------------- 面板请求 (TLS)
# 与 CLI / agent.sh 同一个口径: **先校验证书, 只有确实是证书/TLS 错误时才降级一次**。
# 旧版这里一律 `-k` / `--no-check-certificate` —— 性能模式要更新的 dae 内核与配置同样
# 以 root 落盘/执行, 无条件关掉证书校验等于把分发权交给链路上的任何人 (P1-3)。
_zp_perf_tls_rc() {
    case "${1:-}" in
        35|51|58|59|60|64|66|77|80|83|90|91) return 0 ;;
        *) return 1 ;;
    esac
}
_zp_perf_tls_warned=""
_zp_perf_tls_warn() {
    [ "$_zp_perf_tls_warned" = "1" ] && return 0
    _zp_perf_tls_warned=1
    printf '  · %s 的证书校验没通过 (%s) —— 本次改为不校验继续 (降级, 不是正常路径)\n' "$1" "$2"
}

# 取一个地址存成文件。503 是"面板正在准备" (它要先去上游取), 按它的意思等一会儿再来 ——
# 与内核 / 分流数据那条协议完全一样。返回 0 = 拿到了 200。
# 第 5 个参数可选: 请求头 (新面板用 `Authorization: Bearer` 认设备凭据, 旧面板不认头时
# 自动退回 URL 里带的 ?k=)。
zp_perf_get() {  # $1=url $2=目标 $3=超时 $4=最多试几次 [$5=请求头] [$6=旧面板回退 query]
    _url="$1"; _dst="$2"; _tmo="${3:-60}"; _tries="${4:-10}"; _hdr="${5:-}"; _fb="${6:-}"; _i=0
    while [ "$_i" -lt "$_tries" ]; do
        _i=$((_i + 1))
        _code=""; _rc=0
        if command -v curl >/dev/null 2>&1; then
            if [ -n "$_hdr" ]; then
                _code="$(curl -fsSL -D "$_dst.hdr" -H "$_hdr" -m "$_tmo" -o "$_dst" \
                    -w '%{http_code}' "$_url" 2>/dev/null)" || _rc=$?
                # 旧面板不认 Bearer → 去掉头、把 secret 拼回 URL 再来一次 (回退, 不是主路径)
                if { [ "${_code:-000}" = "403" ] || [ "${_code:-000}" = "401" ]; } && [ -n "$_fb" ]; then
                    _code="$(curl -fsSL -D "$_dst.hdr" -m "$_tmo" -o "$_dst" \
                        -w '%{http_code}' "${_url}${_fb}" 2>/dev/null || true)"
                fi
            else
                _code="$(curl -fsSL -D "$_dst.hdr" -m "$_tmo" -o "$_dst" \
                    -w '%{http_code}' "$_url" 2>/dev/null)" || _rc=$?
            fi
            # 证书错误: 只降级这一次
            if [ -z "$_code" ] && _zp_perf_tls_rc "$_rc"; then
                _zp_perf_tls_warn "$_url" "curl $_rc"
                if [ -n "$_hdr" ]; then
                    _code="$(curl -fsSkL -H "$_hdr" -m "$_tmo" -o "$_dst" \
                        -w '%{http_code}' "$_url" 2>/dev/null || true)"
                else
                    _code="$(curl -fsSkL -m "$_tmo" -o "$_dst" \
                        -w '%{http_code}' "$_url" 2>/dev/null || true)"
                fi
            fi
        else
            _errf="$(mktemp /tmp/.zp-perf-tls.XXXXXX 2>/dev/null || echo /tmp/.zp-perf-tls.$$)"
            for _tool in uclient-fetch wget; do
                command -v "$_tool" >/dev/null 2>&1 || continue
                if "$_tool" -q -T "$_tmo" -O "$_dst" "$_url" 2>"$_errf"; then _code=200
                elif grep -Eqi 'ssl|tls|certificate|cert verify|x509' "$_errf" 2>/dev/null; then
                    _zp_perf_tls_warn "$_url" "$_tool 证书校验失败"
                    "$_tool" -q --no-check-certificate -T "$_tmo" -O "$_dst" "$_url" >/dev/null 2>&1 || true
                    [ -s "$_dst" ] && _code=200
                fi
                break
            done
            rm -f "$_errf"
        fi
        case "$_code" in
            200)
                # 面板下发的 X-ZP-Sha256 必须比对 (拿不到响应头的旧面板只告警, 不静默)。
                _want="$( [ -s "$_dst.hdr" ] && tr -d '\r' < "$_dst.hdr" \
                    | grep -i '^[[:space:]]*X-ZP-Sha256[[:space:]]*:' | head -n1 \
                    | sed 's/^[^:]*:[[:space:]]*//' )"
                if [ -n "$_want" ]; then
                    if command -v sha256sum >/dev/null 2>&1; then
                        _have="$(sha256sum "$_dst" 2>/dev/null | cut -d' ' -f1)"
                    else
                        _have="$(shasum -a 256 "$_dst" 2>/dev/null | cut -d' ' -f1)"
                    fi
                    if [ -n "$_have" ] && [ "$_have" != "$_want" ]; then
                        printf '  ! 下载到的内容 sha256 与面板下发值不一致 (%s != %s) —— 丢弃\n' "$_have" "$_want"
                        rm -f "$_dst" "$_dst.hdr"
                        return 1
                    fi
                fi
                rm -f "$_dst.hdr"
                return 0 ;;
            503) printf '  · 面板正在准备这一档 (第 %s 次)…\n' "$_i"; sleep 5 ;;
            *)   return 1 ;;
        esac
    done
    return 1
}

# 出口 IP —— **唯一**能证明"流量真的过去了"的东西。
# 注意它必须是境外地址: 国内地址按分流规则走直连, dae 通不通都是直连的答案。
#
# 两个坑都在真机上踩过 (8.85):
#   ① **IPv6 会骗人**: 这台机器上路由器自身的 v6 出口没被 dae 接管, 而 curl 默认优先 v6 ——
#      于是探针"通"了, 出口却是本机自己的 240e:… (CN 电信的地址)。所以这里只探 v4: 走的是
#      与局域网设备同一条被接管的路径, 答案才有意义。
#   ② **出口等于本机 WAN 地址**就说明这条流量根本没走代理 —— 那不算成功, 要说出来。
#
# 本机 WAN 上的地址 (出口等于它 = 直连)。拿不到 `ip` 命令时就跳过这一步 (老固件也还有
# 前半条判据: 至少它得是个能解析的出口)。
zp_perf_own_addrs() {
    _dev="$(ip route show table main default 2>/dev/null | sed -n 's/.*dev \([^ ]*\).*/\1/p' | head -n1)"
    [ -n "$_dev" ] || _dev="$(ip route show default 2>/dev/null | sed -n 's/.*dev \([^ ]*\).*/\1/p' | head -n1)"
    [ -n "$_dev" ] || return 0
    # 两条 -e 分开写: `inet6\?` 不是"可选的 6" —— GNU sed 认, BSD sed (演练机) 与部分
    # busybox sed 不认。这种"聪明"的正则一写就把判据悄悄变成空 (踩过)。
    ip -o addr show dev "$_dev" 2>/dev/null \
        | sed -n -e 's/.*[ ]inet6[ ]\([0-9a-fA-F:]*\)\/.*/\1/p' \
                 -e 's/.*[ ]inet[ ]\([0-9.][0-9.]*\)\/.*/\1/p'
}

zp_perf_exit_ip() {
    _body=""
    _err=""
    if command -v curl >/dev/null 2>&1; then
        _body="$(curl -4 -fsSk -m 8 "$ZP_PERF_PROBE" 2>&1)" || _err="$(printf '%s' "$_body" | head -n1 | cut -c1-120)"
    else
        _body="$(uclient-fetch -q --no-check-certificate -O - "$ZP_PERF_PROBE" 2>&1)" \
            || _err="$(printf '%s' "$_body" | head -n1 | cut -c1-120)"
    fi
    _ip="$(printf '%s' "$_body" | sed -n 's/^ip=\([0-9a-fA-F:.]*\)$/\1/p' | head -n1)"
    if [ -n "$_ip" ] && zp_perf_own_addrs | grep -qx "$_ip"; then
        # 出口就是本机 WAN 的地址: 这条流量压根没进代理。**不能算通** —— 之前正是这一条
        # 让"性能模式已开启"带着一个本机地址记了下来, 而用户在意的境外站点其实没走代理。
        printf '出口是本机自己的地址 (%s) —— 这条流量没走代理\n' "$_ip" > "$ZP_PERF_DIR/probe_err" 2>/dev/null || true
        return 1
    fi
    if [ -z "$_ip" ]; then
        # 把"为什么没验成"记下来: 这句话要出现在失败提示里 —— 真机上"流量出不去"可能是
        # 节点不通 / DNS 没起来 / 探针地址被墙, 三者下一步完全不同, 不能只留一句猜测。
        printf '%s\n' "${_err:-探针没有返回可解析的出口地址}" > "$ZP_PERF_DIR/probe_err" 2>/dev/null || true
        return 1
    fi
    rm -f "$ZP_PERF_DIR/probe_err" 2>/dev/null || true
    printf '%s' "$_ip"
}

# 记下 caps 里的两个字段 (界面读的就是它们)。**只改这两行**, 别的字段一个字节都不碰。
zp_perf_caps() {  # $1=0/1  $2=原因
    [ -f "$ZP_DIR/caps" ] || : > "$ZP_DIR/caps"
    _tmp="$ZP_DIR/caps.perf"
    grep -v '^perf=\|^perf_why=' "$ZP_DIR/caps" > "$_tmp" 2>/dev/null || : > "$_tmp"
    printf 'perf=%s\n' "$1" >> "$_tmp"
    printf 'perf_why=%s\n' "$(printf '%s' "$2" | tr -d '\r\n')" >> "$_tmp"
    mv "$_tmp" "$ZP_DIR/caps"
}

# 把 caps 里的 chosen / covered 换成另一档 (进去 / 出来都要用)。覆盖范围的映射只有这一处。
zp_perf_set_chosen() {
    _c="$1"
    case "$_c" in
        tun)      _cov=full ;;
        tproxy)   _cov=lan ;;
        redirect) _cov=lan_tcp ;;
        ebpf)     _cov=full ;;
        *)        _cov=none ;;
    esac
    [ -f "$ZP_DIR/caps" ] || return 0
    _tmp="$ZP_DIR/caps.chosen"
    grep -v '^chosen=\|^covered=' "$ZP_DIR/caps" > "$_tmp" 2>/dev/null || : > "$_tmp"
    printf 'chosen=%s\n' "$_c" >> "$_tmp"
    printf 'covered=%s\n' "$_cov" >> "$_tmp"
    mv "$_tmp" "$ZP_DIR/caps"
}

# 准备 (取二进制 / 分流数据 / 配置, 并校验配置)。幂等: 已经有的不重复取。
# 返回 0 = 一切都齐了 (接下来可以切数据面); 非 0 = 别动现在的数据面。
zp_perf_prepare() {
    mkdir -p "$ZP_PERF_DIR"
    _panel="$(zp_perf_panel)" || { printf '  没有面板凭据 (device.json / servers)\n'; return 1; }
    set -- $_panel
    _base="$1"; _id="$2"; _sec="$3"
    _n="$(ls "$ZP_DIR/servers"/*.json 2>/dev/null | wc -l | tr -d ' ')"
    if [ "${_n:-0}" -gt 1 ]; then
        printf '  · 多面板: 性能模式用第一台 (%s) 的节点\n' "$_base"
    fi

    # 1) dae 二进制 (点按钮时才取 —— 用不到的人不该为它占 30 MB 闪存)
    if [ ! -x "$ZP_PERF_BIN" ]; then
        _arch="$(sed -n '1p' "$ZP_DIR/arch" 2>/dev/null | tr -d '\r\n')"
        [ -n "$_arch" ] || _arch=arm64
        printf '  · 取性能模式内核 (dae · %s)…\n' "$_arch"
        if zp_perf_get "$_base/c/perf/$_arch" "$ZP_PERF_DIR/dae.gz" 300 12; then
            # 判定"是不是 gzip"只用 gzip -t (busybox 一定有) —— 与内核那一步同一条路
            if gzip -t "$ZP_PERF_DIR/dae.gz" >/dev/null 2>&1; then
                gzip -dc "$ZP_PERF_DIR/dae.gz" > "$ZP_PERF_BIN" 2>/dev/null || true
            fi
            rm -f "$ZP_PERF_DIR/dae.gz"
            chmod 755 "$ZP_PERF_BIN" 2>/dev/null || true
        fi
        if [ ! -x "$ZP_PERF_BIN" ]; then
            printf '  面板没能给出性能模式内核 (dae) —— 到面板上确认它取得到上游\n'
            printf '%s\n' "取 dae 失败"
            return 1
        fi
    fi

    # 2) 分流数据 (v2ray 格式的 geoip.dat / geosite.dat)。取不到不是失败: 退回一份不含 geo
    #    规则的配置 (少一层分流优化, 但能用) —— 与 mihomo 那边的降级同一个道理。
    _geo=1
    for _g in geoip.dat geosite.dat; do
        if [ ! -s "$ZP_PERF_DIR/$_g" ]; then
            printf '  · 取分流数据 (%s)…\n' "$_g"
            zp_perf_get "$_base/c/perf/geo/$_g" "$ZP_PERF_DIR/$_g" 180 4 || _geo=0
        fi
        [ -s "$ZP_PERF_DIR/$_g" ] || _geo=0
    done
    if [ "$_geo" != "1" ]; then
        rm -f "$ZP_PERF_DIR/geoip.dat" "$ZP_PERF_DIR/geosite.dat"
        printf '  · 面板还没有分流数据 —— 用降级配置 (国内直连与广告拦截这一档先不要)\n'
    fi

    # 3) 配置 (由面板渲染: 节点 / 分流模板 / 面板直连都在它手里)
    _lan="$(zp_perf_lan)"
    # 设备凭据优先走 `Authorization: Bearer` (secret 不进 URL/访问日志); 旧面板不认头时
    # zp_perf_get 会把 $_perf_fb 拼回 URL 再试一次 (P2-6 / 向后兼容)。
    _url="$_base/c/perf/config?id=$_id&lan=$_lan&geo=$_geo"
    _perf_fb="&k=$_sec"
    printf '  · 取 dae 配置 (局域网口: %s)…\n' "$_lan"
    # 权限是这一档的**硬门槛**, 不是"讲究": dae 的配置合并器自己会拒绝一份"组可写 / 别人
    # 可读"的配置 —— 原话是 `permissions %04o for '%v' are too open; ... suggest 0640 or
    # 0600`。而 curl -o 建文件是跟着 umask 走的 (固件默认 022 → 0644), 于是 `dae validate`
    # 的第一句话永远是权限错, 性能模式在真机上就卡死在这一步 (8.83 之前就是这样)。
    # 两条一起做: 建的时候就按 077 建 (子 shell 里改 umask, 不影响调用方), 落盘后再 chmod
    # 一次 —— 后者管的是"上一版留下的 0644 那份配置/ mv 覆盖"这两种情况。
    if ! ( umask 077; zp_perf_get "$_url" "$ZP_PERF_CONF.new" 30 2 \
            "Authorization: Bearer $_sec" "$_perf_fb" ) \
        || [ ! -s "$ZP_PERF_CONF.new" ]; then
        printf '  面板没有给出 dae 配置\n'; return 1
    fi
    # 拿到的东西必须像一份 dae 配置 (不是一页错误页)
    if ! grep -q '^global {' "$ZP_PERF_CONF.new" 2>/dev/null; then
        printf '  面板给回来的不是 dae 配置 (第一行: %s)\n' "$(sed -n '1p' "$ZP_PERF_CONF.new" 2>/dev/null | cut -c1-60)"
        rm -f "$ZP_PERF_CONF.new"
        return 1
    fi
    mv "$ZP_PERF_CONF.new" "$ZP_PERF_CONF"
    chmod 600 "$ZP_PERF_CONF" 2>/dev/null || true

    # 4) 校验 (`dae validate` 会把路由规则与 DNS 路由都跑一遍) —— 校验不过就不动数据面
    if ! _out="$("$ZP_PERF_BIN" validate -c "$ZP_PERF_CONF" 2>&1)"; then
        printf '  配置没通过 dae 的校验, 不动现在的数据面:\n'
        printf '%s\n' "$_out" | head -n 3 | sed 's/^/    /'
        printf '%s\n' "配置校验失败: $(printf '%s' "$_out" | head -n 1)"
        return 1
    fi
    printf '  · 配置已校验通过\n'
    return 0
}

# 进性能模式。成功 = 数据面真的换过去了 (daemon 在跑 + 流量真的出得去)。
zp_perf_enter() {
    if [ "$(zp_perf_state)" = "on" ] && zp_perf_live; then
        printf '性能模式已经开着 (出口 %s)\n' "$(cat "$ZP_PERF_EXIT" 2>/dev/null)"
        return 0
    fi
    _cap="$(sed -n 's/^perf_cap=//p' "$ZP_DIR/caps" 2>/dev/null | head -n1)"
    if [ "$_cap" != "1" ]; then
        printf '这台机器进不了性能模式: %s\n' "$(sed -n 's/^perf_why=//p' "$ZP_DIR/caps" 2>/dev/null | head -n1)"
        printf '  (需要内核 >=5.17 且带 BTF —— BTF 缺了重跑安装命令会自动补上)\n'
        return 1
    fi
    printf '准备性能模式…\n'
    # 准备的输出**收下来再原样打出去**: 终端里的样子一个字节都不变, 但界面那条"上次的结论"
    # 拿到了真正的原因。为什么必须这么做: 失败原因以前只活在终端的滚动里, 而界面只写
    # "准备阶段失败 (见上)" —— 在手机上点这个按钮的人根本看不到那个"上" (真机反馈就是这个
    # 形状: 一句话把人挡在门外, 还得再跑一次带 TTY 的命令才能问出为什么)。
    if ! _prep="$(zp_perf_prepare 2>&1)"; then
        printf '%s\n' "$_prep"
        # 最后一行就是原因: 失败路径都是以一句人话结尾的 (取 dae 失败 / 配置校验失败: xx …),
        # 而中间的 `· 取 …` 是进度。取最后一条非进度行, 去掉缩进并截断 —— 界面那一格放不下
        # 一屏日志, 而原因的头一句就够定位了。
        _why_line="$(printf '%s\n' "$_prep" | grep -v '^ *·' | sed -e 's/^[[:space:]]*//' -e '/^$/d' | tail -n 1 | cut -c1-160)"
        [ -n "$_why_line" ] || _why_line="准备阶段失败"
        zp_perf_why_set "$_why_line"
        zp_perf_caps 0 "$_why_line"
        return 1
    fi
    printf '%s\n' "$_prep"

    # 记下"原来那一档": 退出来的时候要回到它 (而不是回到"默认")
    _prev="$(sed -n 's/^chosen=//p' "$ZP_DIR/caps" 2>/dev/null | head -n1)"
    [ -n "$_prev" ] || _prev=none
    printf '%s\n' "$_prev" > "$ZP_PERF_PREV"

    printf '切换数据面 (停标准模式 → 起 dae)…\n'
    zp_perf_set_state on
    "$ZP_INIT" stop >/dev/null 2>&1 || true
    "$ZP_INIT" disable >/dev/null 2>&1 || true
    # 停完再看一眼**进程**真的走了没有。两个数据面同时抢包是这一档最坏的形状 (现象是
    # "时通时不通"), 而 stop 与进程退出之间有一拍 —— 没走就再送一次 TERM。
    # 不用 -9: tun 设备与它加的路由是 mihomo 自己**在退出路径里**收的, 硬杀容易留下
    # 指向一个已经消失的设备的黑洞路由, 那比"多等两秒"危险得多。
    _k=0
    while zp_perf_mihomo_live && [ "$_k" -lt 5 ]; do
        [ "$_k" = "0" ] && printf '  · 标准模式还占着 (mihomo 进程还在), 再送它一次 TERM…\n'
        killall mihomo 2>/dev/null || true
        sleep 1
        _k=$((_k + 1))
    done
    zp_perf_set_chosen ebpf
    rm -f "$ZP_PERF_EXIT"
    "$ZP_PERF_INIT" enable >/dev/null 2>&1 || true
    "$ZP_PERF_INIT" start >/dev/null 2>&1 || true

    # 等 daemon 起来 (最多 20 秒)
    _i=0
    while [ "$_i" -lt 20 ]; do
        zp_perf_live && break
        sleep 1
        _i=$((_i + 1))
    done
    if ! zp_perf_live; then
        _why="dae 没能起来"
        [ -s "$ZP_PERF_LOG" ] && _why="dae 没能起来: $(tail -n 1 "$ZP_PERF_LOG" 2>/dev/null | cut -c1-120)"
        printf '  %s —— 退回原来的模式\n' "$_why"
        zp_perf_leave "$_why"
        return 1
    fi
    printf '  · dae 在跑, 正在验证流量真的过得去…\n'
    # 解析路径换了 (dnsmasq → dae), 先把缓存丢掉再探 —— 否则探针可能拿到上一条路径上的答案
    zp_perf_flush_dns

    # 等"真的通" (最多 45 秒)。判据是境外地址够得到 —— 而且此刻 mihomo 是停着的,
    # 所以这条连接只可能是 dae 挣来的 (这就是"不撒谎"的那一步)。
    _i=0
    _ip=""
    _mihomo_bad=""
    # 等多久: 默认 15 次 × 3 秒 = 45 秒 (真机上节点建连 + DNS 都要时间)。
    # ZP_PERF_VERIFY_TRIES 只给演练用 (那里没有真节点, 干等 45 秒纯属浪费)。
    _tries="${ZP_PERF_VERIFY_TRIES:-15}"
    while [ "$_i" -lt "$_tries" ]; do
        # 先探出口, 再排除"这条通路其实是 mihomo 给的"。
        # 顺序是这么定的: **探针才是证据**, mihomo 在不在只是要排除的干扰项 —— 反过来先
        # 看 mihomo, 一旦那个判断本身不可靠 (init 脚本坏了 / 固件上的 running 子命令没有),
        # 就会永远走不到探针那一步, 于是"通的"被误判成"不通"(反过来也会撒谎)。
        if _ip="$(zp_perf_exit_ip)"; then
            if zp_perf_mihomo_live; then
                printf '  mihomo 还在跑 —— 两个数据面同时在, 不能算换成功\n'
                _mihomo_bad="标准模式没停下来 (mihomo 进程还在) —— 两个数据面同时在, 不能算换成功"
                _ip=""
                break
            fi
            break
        fi
        _i=$((_i + 1))
        sleep 3
    done
    if [ -z "$_ip" ]; then
        _perr="$(sed -n '1p' "$ZP_PERF_DIR/probe_err" 2>/dev/null | tr -d '\r\n')"
        if [ -n "$_mihomo_bad" ]; then
            # 这一种**不是**"流量出不去": 探针那天是通的 (所以 probe_err 是空的), 拦下它的
            # 是"两个数据面同时在"。分开说 —— 否则界面把原因指错方向, 人也跟着查错地方 (8.84)。
            _why="$_mihomo_bad"
        else
            _why="dae 起来了, 但流量出不去 (节点不通 / 分流数据不全, 或标准模式没停下来)"
            [ -n "$_perr" ] && _why="$_why —— 探针说: $_perr"
        fi
        # dae 自己那句原话往往就是答案 (节点不通 / DNS 起不来 / eBPF 加载失败)。附在原因后面:
        # 界面那一格与终端里的滚动说的是同一件事, 不用再让人去 tail 一个文件 (8.84)。
        _dae_err="$(grep -a -E 'level=(error|fatal|warning)' "$ZP_PERF_LOG" 2>/dev/null | tail -n 1 | tr -d '\r' | cut -c1-140)"
        [ -n "$_dae_err" ] || _dae_err="$(tail -n 1 "$ZP_PERF_LOG" 2>/dev/null | tr -d '\r' | cut -c1-140)"
        [ -n "$_dae_err" ] && _why="$_why —— dae 日志: $_dae_err"
        printf '  %s —— 退回原来的模式\n' "$_why"
        zp_perf_leave "$_why"
        return 1
    fi
    printf '%s\n' "$_ip" > "$ZP_PERF_EXIT"
    zp_perf_why_set ""
    zp_perf_caps 1 ""
    printf '性能模式已开启 —— 出口 %s (内核态分流: 直连流量不再经过用户态)\n' "$_ip"
    log "性能模式开启, 出口 $_ip"
    return 0
}

# 退出性能模式, 回到原来那一档。$1 = 为什么 (空 = 用户自己关的)。
# 幂等: dae 没在跑的时候也能调 (进入失败的回滚路径会调它)。
zp_perf_leave() {
    _why="${1:-}"
    zp_perf_set_state off
    # 界面那条"上次的结论"读的就是这个文件 —— 只写 caps 是不够的: 真机上卡片一直显示着
    # 上一次的旧结论 (比如早就修掉的"准备阶段失败"), 于是这次失败看起来像上次那个原因。
    # 一句真话比一句旧话重要 (8.84)。
    zp_perf_why_set "$_why"
    rm -f "$ZP_PERF_DIR/bad"
    "$ZP_PERF_INIT" stop >/dev/null 2>&1 || true
    "$ZP_PERF_INIT" disable >/dev/null 2>&1 || true
    _prev="$(sed -n '1p' "$ZP_PERF_PREV" 2>/dev/null | tr -d '\r\n')"
    [ -n "$_prev" ] || _prev=none
    zp_perf_set_chosen "$_prev"
    zp_perf_caps 0 "$_why"
    "$ZP_INIT" enable >/dev/null 2>&1 || true
    "$ZP_INIT" restart >/dev/null 2>&1 || true
    zp_perf_flush_dns
    printf '已回到标准模式 (数据面: %s)\n' "$_prev"
    [ -n "$_why" ] || log "性能模式关闭 (用户操作)"
    return 0
}

# 看门狗: 由 agent 每轮调用。说好"在用性能模式", 而 dae 已经不在了 → 自动退回标准模式。
# 为什么要它: 性能模式下 mihomo 是停着的, dae 一死家里就断网 —— 而用户不会知道去关掉它。
# 连续 3 轮 (~45 秒) 都看不到进程才算 (重启 / 短暂抖动不误判)。
zp_perf_tick() {
    [ "$(zp_perf_state)" = "on" ] || return 0
    zp_perf_live && { rm -f "$ZP_PERF_DIR/bad"; return 0; }
    _n=0
    [ -f "$ZP_PERF_DIR/bad" ] && _n="$(sed -n '1p' "$ZP_PERF_DIR/bad" 2>/dev/null | tr -d '\r\n')"
    _n=$(( ${_n:-0} + 1 ))
    printf '%s\n' "$_n" > "$ZP_PERF_DIR/bad"
    [ "$_n" -ge 3 ] || return 0
    log "dae 连续 $_n 次检查都不在, 自动退回标准模式"
    zp_perf_leave "dae 不在了 (连续 3 次没看到进程) —— 已自动退回标准模式"
    return 0
}

# 给人看的状态 (界面不看这个 —— 它读的是同一个文件, 见 cgi / zpcore 的 status)。
zp_perf_status() {
    _cap="$(sed -n 's/^perf_cap=//p' "$ZP_DIR/caps" 2>/dev/null | head -n1)"
    if [ "$(zp_perf_state)" = "on" ] && zp_perf_live; then
        printf '性能模式: 已开启 (出口 %s)\n' "$(sed -n '1p' "$ZP_PERF_EXIT" 2>/dev/null)"
        printf '  数据面      内核态 eBPF (dae): 直连流量不再经过用户态\n'
        printf '  局域网接口  %s\n' "$(zp_perf_lan)"
    elif [ "$(zp_perf_state)" = "on" ]; then
        printf '性能模式: 说好在用, 但 dae 不在 (agent 会在 45 秒内自动退回标准模式)\n'
        [ -s "$ZP_PERF_DIR/progress" ] && tail -n 3 "$ZP_PERF_DIR/progress"
    else
        printf '性能模式: 未开启'
        if [ "$_cap" = "1" ]; then
            printf ' (这台机器可以开: zeroproxy perf on)\n'
        else
            printf ' —— 这台机器开不了: %s\n' "$(sed -n 's/^perf_why=//p' "$ZP_DIR/caps" 2>/dev/null | head -n1)"
        fi
    fi
    if [ -n "$(zp_perf_why)" ]; then printf '  上次的结论  %s\n' "$(zp_perf_why)"; fi
    if [ -s "$ZP_PERF_CONF" ]; then
        printf '  已备好的节点 %s 个 (dae 初始配置)\n' \
            "$(sed -n '/^node {/,/^}/p' "$ZP_PERF_CONF" | grep -c '://')"
    fi
}
