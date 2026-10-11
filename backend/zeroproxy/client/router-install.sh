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
#: 性能模式内核 (dae) 自己的服务 —— 与 mihomo 分成两个服务, 因为两者互斥 (见 perf.sh)
ZP_PERF_INIT=/etc/init.d/zeroproxy-perf
# 固件自己的 Web 服务发不出页面时用的兜底 httpd (见 install_ui)
ZP_INIT_UI=/etc/init.d/zeroproxy-ui
ZP_CLI=/usr/bin/zeroproxy
ZP_SVC=zeroproxy

# 内核健康检查用的本机控制口 (与 config.yaml 的 external-controller 一致)
ZP_API=127.0.0.1:9090
# 代理端口 (config.yaml 的 mixed-port)
ZP_MIXED=7890
#: TUN 设备节点。Linux 上是 /dev/net/tun; 少数系统 (FreeBSD) 用 /dev/tun ——
#: 用 ZP_TUN_DEV 指过去即可。真正的判据仍然是"能不能建出设备", 这个值只决定去哪找。
TUN_DEV="${ZP_TUN_DEV:-/dev/net/tun}"

TLS_OPTS=""
ARCH=""
#: 最近一次带状态码的请求结果 (http_fetch_to 会写它)
HTTP_CODE=""
DEPENDENCY_NOTE=""
ACTIVE_MODE=""
#: 固件版本与包管理器。OpenWrt 25.12 起包管理器从 opkg 换成了 apk, 而真机上存在**两代
#: 混着出现**的组合 (厂商固件报 25.x 却只有 opkg; backport 的 24.10 里塞了 apk) ——
#: 版本号与"命令在不在"两条判据都要留。选错的后果是整段依赖安装静默跳过: 安装过程全绿,
#: 而 TUN 建不出来、tproxy 回退也没有 nft 规则 (README 8.76)。
FW_RELEASE=""
FW_GEN=""
#: 固件自己的目标名 (DISTRIB_ARCH): BTF 包是按它挑的, 比 uname -m 细一档
FW_ARCH=""
PKG_MGR=""
PKG_MGR_NOTE=""
#: 内核模块没装上的原因。pkg_install 把命令**第一行原话**记进 DEPS_WHY, 调用方攒进
#: DEPS_FAILED (一行一条 `包名: 原因`) —— 结尾摘要与 doctor 都读它, 于是"为什么没装成"
#: 有现场证据, 而不是只留一句"缺 kmod-tun"让人去猜。
DEPS_WHY=""
DEPS_FAILED=""
#: 性能模式 (eBPF / dae): cap=能不能进 (装机时探的), why=不能进的原因
PERF_CAP=""
PERF_WHY=""
# 面板是否提供分流数据库接口 (/c/geo)。空 = 没问过 (更新模式), true = 有
PANEL_GEO=""
# 面板给来的分流数据库元信息 (core_read_panel 填): 体积下限与全部可用地址。
# 没有它们也能装 —— 退回"只走面板"的老路, 行为与本改动之前相同。
PANEL_GEO_SIZES=""
PANEL_GEO_MIRRORS=""
# 非空 = 这次只能装降级配置 (面板暂时给不出分流数据库), 结尾要如实说明
DEGRADED=""
# 非空 = 这次靠自愈才把 TUN 建起来 (值说明改了哪一项), 结尾要告诉用户
TUN_HEALED=""
# 1 = TUN 设备建起来了、但**局域网根本过不去** (auto-redirect 缺席又补不上防火墙放行) ——
# 这一级不能算生效, 必须顺着阶梯往下走, 而不是留一个"家里全断"的状态
TUN_UNUSABLE=""
# 设备凭据与配对结果 (set -u 下必须预置: 只有在真的走过那条分支时才会被赋值)
DEV_ID=""
DEV_SECRET=""
DEV_NAME=""
PAIR_ERROR=""

# ---------------------------------------------------------------- 输出
# 全部输出走 stderr 之外的标准输出, 但用颜色区分层级 —— 用户是在 SSH 里看,
# 一段没有层级的大段英文输出等于没有输出。
if [ -t 1 ]; then
    ZP_TTY=1
    C_R="$(printf '\033[0m')"; C_B="$(printf '\033[1m')"; C_G="$(printf '\033[32m')"
    C_Y="$(printf '\033[33m')"; C_E="$(printf '\033[31m')"
else
    # 非 TTY (输出被重定向 / 进管道 / 落日志): 不打进度条 —— `\r` 原地刷新在文件里会
    # 堆成一坨, 而"每 5 秒一行"那种写法在日志里照样读得出来。
    ZP_TTY=0
    C_R=""; C_B=""; C_G=""; C_Y=""; C_E=""
fi
step() { printf '%s==>%s %s\n' "$C_B" "$C_R" "$*"; }
ok()   { printf '%s  ✓%s %s\n' "$C_G" "$C_R" "$*"; }
warn() { printf '%s  !%s %s\n' "$C_Y" "$C_R" "$*" >&2; }
# 说明性的一行 (既不是成功, 也不是警告)。什么时候用它: 某条**用不到**的回退路径不可用时
# —— 例如有 TUN 的机器上 tproxy 模块装不上。那件事是真的, 但把它写成 "!" 会让人以为
# 安装出了问题 (真机反馈里就是这么被读的)。
note() { printf '  · %s\n' "$*"; }
# "还在等"的那句话 —— **必须走 stderr**: http_get 的 stdout 是被调用方用 $(…) 接走的
# (那是配置/接口的正文), 往 stdout 多写一个字就把正文弄坏了。
progress_note() { printf '  · %s\n' "$*" >&2; }
# curl 退出码 → 人话。写这句是因为**不许再一律说"链路丢包"**: 8.67/8.68 两轮真机都把
# "拉配置失败"标成丢包, 于是 DNS 解析不了 / TLS 挂了 / 面板明确拒绝 这些完全不同的原因
# 长得一模一样 —— 排查时只能靠猜。这里一旦分出来, 日志自己会说是哪一类。
http_why() {
    case "${1:-}" in
        0)  printf '正常' ;;
        6)  printf '域名解析不了 (DNS)' ;;
        7)  printf '连不上 (被拒 / 不可达)' ;;
        18) printf '收到不完整的数据 (被截断)' ;;
        22) printf '面板明确拒绝 (HTTP 4xx / 5xx)' ;;
        28) printf '超时 —— 多半是链路在丢包' ;;
        35|60) printf 'TLS / 证书错误' ;;
        52|56) printf '连接被中断' ;;
        *)  printf '其它错误 (curl %s)' "${1:-?}" ;;
    esac
}
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

# 取一个接口 (文本 / JSON)。真机实测直连面板 6 次里 3 次 SYN 石沉大海 —— 一次丢包不该
# 变成"配对失败""拉不到配置"这种很贵的结论, 所以要重试。只有 GET 重试 (它是幂等的):
# POST 可能是"用掉一个一次性配对码", 重放等于赌第一次没生效。
#
# 两个参数的选择都是有依据的, 别再往回调:
#   * **每次超时 10 秒** (原来是 30): 丢包时那一次会一直等到超时 —— 30 秒 × 几次就是
#     用户看到的"更新非常慢"。这里的正文都很小 (配置 ~17 KB、脚本 ~19 KB、界面文件
#     ~10-24 KB), 面板实测 63 KB/s 也就 0.4 秒, 10 秒留了二十倍余量。
#   * **重试到 5 次** (原来是 3): 一次更新要拉好几个接口, 每次都有失败概率 —— 3 次在
#     五成的丢包率下单次就要失败 12.5%, 几个接口乘起来"这次更新又失败"的概率接近一半。
#     5 次把它压到 3%。
http_get() {
    _tries=0
    while :; do
        _tries=$((_tries + 1))
        _rc=1
        _out=""
        case "$HTTP" in
            curl)
                if [ "$TLS_OPTS" = "insecure" ]; then
                    if _out="$(curl -fsSk -m 10 "$1")"; then _rc=0; else _rc=$?; fi
                else
                    if _out="$(curl -fsS -m 10 "$1")"; then _rc=0; else _rc=$?; fi
                fi ;;
            *)
                if [ "$TLS_OPTS" = "insecure" ]; then
                    if _out="$("$HTTP" -q --no-check-certificate -O - "$1")"; then _rc=0; fi
                else
                    if _out="$("$HTTP" -q -O - "$1")"; then _rc=0; fi
                fi ;;
        esac
        if [ "$_rc" = "0" ]; then printf '%s' "$_out"; return 0; fi
        # 22 = curl -f 说的"HTTP 层面失败" (403/404/502…): 面板已经明确答复, 重试没意义
        [ "$_rc" != "22" ] || return "$_rc"
        [ "$_tries" -lt 5 ] || return "$_rc"
        # 让"在等"看得见: 丢包时这一次是白等到超时的, 界面上要有句话说明在干什么。
        progress_note "面板第 ${_tries} 次没回话 ($(http_why "$_rc")), 正在重试…"
        sleep "$_tries"
    done
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

# 把下载结果存进文件, 并且**尽量**带回 HTTP 状态码 (放进 HTTP_CODE)。
#
# 内核这一步必须分得清三件事, 它们的下一步完全不同:
#   200 → 拿到二进制, 继续装;
#   503 → 面板还没准备好 (正在从上游取), 该等 + 轮询进度;
#   502 → 面板自己取不到上游, 该换条路或明确报错。
# curl 有 -w 能直接给出状态码; uclient-fetch / wget 没有这个能力, 那里只能退化成
# "拿到的东西像不像一个内核" —— 所以下面还留了一条按内容识别的兜底。
#
# 第 4/5 个参数是"速率闸门" (KB/s, 观察窗口秒数): curl 在这条线上**平均速率**低于它
# 超过窗口时间就自己掐断。这不是优化, 是"这条路根本跑不完"的判定 —— 真机上面板直传
# 63 KB/s, 20 MB 要五分钟, 而我们只给它 CORE_PANEL_BUDGET 秒: 与其把那 90 秒耗完,
# 不如 20 秒就认清、让位给直连镜像 (那次镜像 931 KB/s)。uclient-fetch / wget 没有
# 这个能力, 那边只能靠 -T 到点失败。
http_fetch_to() {
    _url="$1"; _dest="$2"; _tmo="${3:-900}"; _min_kbps="${4:-0}"; _win="${5:-25}"
    HTTP_CODE=""
    _speed=""
    if [ "${_min_kbps:-0}" -gt 0 ] 2>/dev/null; then
        _speed="--speed-limit $((_min_kbps * 1024)) --speed-time $_win"
    fi
    # -L 不能少: GitHub 官方直链会 302 到 objects.githubusercontent.com, 有的反代也会跳。
    # 不跟随重定向的话, 拿到的只是那几十字节的跳转页 —— 大小闸门会把它当"面板的一句话"。
    case "$HTTP" in
        curl)
            if [ "$TLS_OPTS" = "insecure" ]; then
                # shellcheck disable=SC2086
                if HTTP_CODE="$(curl -sSkL -m "$_tmo" $_speed -o "$_dest" -w '%{http_code}' "$_url" 2>/dev/null)"; then _rc=0; else _rc=1; fi
            else
                # shellcheck disable=SC2086
                if HTTP_CODE="$(curl -sSL -m "$_tmo" $_speed -o "$_dest" -w '%{http_code}' "$_url" 2>/dev/null)"; then _rc=0; else _rc=1; fi
            fi
            [ -n "$HTTP_CODE" ] || HTTP_CODE="000"
            # curl 自己的退出码也要认: `-m` 到点被掐断时它**照样会打出 200** (响应头早
            # 就收到了), 只看状态码会把"下了一半"当成"下完了", 然后拿半个文件去比
            # sha256 —— 报出来就是"镜像不干净", 完全指错方向 (演练抓到过)。
            if [ "$_rc" != "0" ]; then
                return 1
            fi
            [ "$HTTP_CODE" = "200" ]
            ;;
        *)
            rm -f "$_dest"
            if [ "$TLS_OPTS" = "insecure" ]; then
                "$HTTP" -q --no-check-certificate -T "$_tmo" -O "$_dest" "$_url" >/dev/null 2>&1
            else
                "$HTTP" -q -T "$_tmo" -O "$_dest" "$_url" >/dev/null 2>&1
            fi
            ;;
    esac
}

# 下载失败时把面板那句话原样带出来 —— 面板的 503/502 正文就是写给用户看的中文,
# 藏在文件里不给任何人看就等于没有。只对"小文件"这么做: 内核是 20 MB, 不可能是话。
show_body() {
    # 名字带 sb_ 前缀: 这个脚本没有 local, `_size` 这种大众名会**静默**污染调用方
    # (调用方往往正好也在比大小 —— 真事, 见 geo_fetch_one 顶部的注释)。
    _sb_f="$1"
    [ -s "$_sb_f" ] || return 0
    _sb_size="$(wc -c < "$_sb_f" 2>/dev/null | tr -d ' ' || true)"
    [ "${_sb_size:-0}" -lt 4096 ] || return 0
    sed -n '1,4p' "$_sb_f" 2>/dev/null | sed 's/^/      /' >&2 || true
}

# 下载进度: 路由器上没有任何工具会替你打这个 (uclient-fetch 全程静默), 而 20 MB 在
# 4 Mbps 的线路上要 40 秒。中间一行输出都没有, 用户就会以为卡死了 —— 真机反馈里
# "一直卡在下载代理内核"就是这么来的。后台小循环每 5 秒读一次文件大小, 有增长才报。
PROGRESS_PID=""
# 人读的字节数 (19.9 MB / 412 KB)。只用于进度条那几行, 不参与任何判断。
zp_hsize() {
    _b="${1:-0}"
    if [ "$_b" -ge 1048576 ] 2>/dev/null; then
        printf '%s.%s MB' "$((_b / 1048576))" "$(( (_b % 1048576) * 10 / 1048576 ))"
    elif [ "$_b" -ge 1024 ] 2>/dev/null; then
        printf '%s KB' "$((_b / 1024))"
    else
        printf '%s B' "$_b"
    fi
}

# 一条会原地刷新的进度条:
#     [██████████░░░░░░░░░░░░░░]  47%  9.4 MB / 19.9 MB  615 KB/s
# 只在已知总量、且在 TTY 上时用它 (未知总量画不出百分比, 非 TTY 会把 \r 堆成垃圾)。
# 宽度固定 24 格 —— 行尾不会随数字位数抖动。
zp_bar() {
    _label="$1"; _now="$2"; _total="$3"; _kbps="$4"
    _pct=$(( _now * 100 / _total )) 2>/dev/null || _pct=0
    [ "$_pct" -gt 100 ] 2>/dev/null && _pct=100
    [ "$_pct" -lt 0 ] 2>/dev/null && _pct=0
    _full=$(( _pct * 24 / 100 ))
    _bar=""; _i=0
    while [ "$_i" -lt 24 ]; do
        if [ "$_i" -lt "$_full" ]; then _bar="${_bar}█"; else _bar="${_bar}░"; fi
        _i=$((_i + 1))
    done
    printf '\r  %s [%s] %3s%%  %s / %s  %s KB/s   ' \
        "$_label" "$_bar" "$_pct" "$(zp_hsize "$_now")" "$(zp_hsize "$_total")" "$_kbps"
}

start_progress() {
    _file="$1"; _label="${2:-下载中}"; _total="${3:-0}"
    stop_progress
    (
        _ticks=0
        while :; do
            # 文件可能还没被 curl 创建 (或者上一次下载刚被删掉): 直接 `wc -c < 不存在的`
            # 是**重定向**失败, 那句 "No such file or directory" 由 shell 自己打到 stderr,
            # `2>/dev/null` 挡不住它 —— 装机会莫名其妙多出几行这种噪音。先判断存在性。
            if [ -f "$_file" ]; then
                _now="$(wc -c < "$_file" 2>/dev/null | tr -d ' ' || true)"
            else
                _now=0
            fi
            [ -n "$_now" ] || _now=0
            _ticks=$((_ticks + 1))
            _kbps=$((_now / 1024 / (_ticks * 5)))
            # 已知总量 + TTY: 画条。否则退回"每 5 秒一行"—— 每 5 秒无条件报一次, 速率
            # 掉下来 (或一直是 0) 也看得见, 这正是"卡住"与"慢"的区别所在。
            if [ "$ZP_TTY" = "1" ] && [ "${_total:-0}" -gt 0 ] 2>/dev/null; then
                zp_bar "$_label" "$_now" "$_total" "$_kbps"
            else
                printf '  … %s %s KB (%s KB/s)\n' "$_label" "$((_now / 1024))" "$_kbps"
            fi
            sleep 5
        done
    ) &
    PROGRESS_PID=$!
}
stop_progress() {
    [ -n "$PROGRESS_PID" ] || return 0
    kill "$PROGRESS_PID" 2>/dev/null || true
    wait "$PROGRESS_PID" 2>/dev/null || true
    PROGRESS_PID=""
    # 进度条是 `\r` 原地刷的: 不清掉的话, 紧接着那句「✓ 完成」会叠在条子尾巴上。
    [ "$ZP_TTY" = "1" ] && printf '\r\033[K'
    return 0
}

json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\r\n'; }

# 面板地址 → 服务器清单里的键 (与 agent 里的 key_of 一致): hkk.i3.pub:8899 → hkk_i3_pub
srv_key() {
    printf '%s' "$1" | sed -e 's#^https*://##' -e 's/[^A-Za-z0-9]/_/g' | cut -c1-32
}

# 取一个扁平 JSON 字段 (busybox 里没有 jq, 好在面板返回的都是浅结构)。
json_get() {
    _json="$1"; _key="$2"
    if command -v jsonfilter >/dev/null 2>&1; then
        printf '%s' "$_json" | jsonfilter -e "@.$_key" 2>/dev/null | head -n1
    else
        printf '%s' "$_json" | sed -n 's/.*"'"$_key"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1
    fi
}

# 数字字段 (bytes / 进度这类): 上面的 json_get 只认带引号的值。
json_get_num() {
    _json="$1"; _key="$2"
    printf '%s' "$_json" | sed -n 's/.*"'"$_key"'"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n1
}

json_get_bool() {
    _json="$1"; _key="$2"
    if command -v jsonfilter >/dev/null 2>&1; then
        printf '%s' "$_json" | jsonfilter -e "@.$_key" 2>/dev/null | head -n1
        return 0
    fi
    # 不用 `sed -n 's/...\(true\|false\).../\1/p'`: `\|` 是 GNU 扩展, BSD sed (macOS) 不认,
    # 会**静默取到空值** —— 能力位读成空, 旧面板该被拦下的就拦不下 (本机演练抓到过)。
    # 两次固定串匹配在 busybox / BSD / GNU 上行为一致。
    if printf '%s' "$_json" | grep -q "\"$_key\"[[:space:]]*:[[:space:]]*true"; then
        printf 'true\n'
    elif printf '%s' "$_json" | grep -q "\"$_key\"[[:space:]]*:[[:space:]]*false"; then
        printf 'false\n'
    fi
}

# ---------------------------------------------------------------- 环境探测
# OpenWrt 自己的架构名 (/etc/openwrt_release 的 DISTRIB_ARCH) → 内核资产架构。
# 它是权威的: uname -m 在个别固件上会给模棱两可的值 (32 位用户态 / 厂商改过的串),
# 而 DISTRIB_ARCH 是这份固件真正编译出来的目标 (aarch64_cortex-a53 / mipsel_24kc /
# arm_cortex-a7_neon-vfpv4 / x86_64 …)。
arch_from_openwrt() {
    _da="$(sed -n "s/^DISTRIB_ARCH=['\"]\(.*\)['\"].*/\1/p" /etc/openwrt_release 2>/dev/null | head -n1 || true)"
    [ -n "$_da" ] || return 1
    case "$_da" in
        aarch64*)              printf 'arm64\n' ;;
        arm_arm1176*|arm_arm11*) printf 'armv6\n' ;;
        arm*)                  printf 'armv7\n' ;;
        mips64el*)             printf 'mips64le\n' ;;
        mips64*)               printf 'mips64\n' ;;
        mipsel*|mipsle*)       printf 'mipsle\n' ;;
        mips*)                 printf 'mips\n' ;;
        x86_64*|i386*)         printf 'amd64\n' ;;
        *) return 1 ;;
    esac
}

detect_env() {
    [ "$(id -u)" = "0" ] || die "需要 root 权限, 请用 root 账户执行 (OpenWrt 默认就是 root)"
    [ -r /etc/openwrt_release ] || die "没有检测到 OpenWrt (/etc/openwrt_release 不存在)。
  本客户端面向 OpenWrt / GL.iNet / 基于 OpenWrt 的软路由; 原厂固件请先在后台
  刷成 OpenWrt, 或改用手机/电脑客户端的订阅导入。"

    case "$(uname -m)" in
        aarch64|arm64)     ARCH=arm64 ;;
        armv7l|armv7)      ARCH=armv7 ;;
        armv6l)            ARCH=armv6 ;;
        x86_64|amd64)      ARCH=amd64 ;;
        mips64el)          ARCH=mips64le ;;
        mips64)            ARCH=mips64 ;;
        mipsel|mipsle)     ARCH=mipsle ;;
        mips)              ARCH=mips ;;
        # uname -m 认不出来时用 OpenWrt 自己的目标名兜底 (两者都没有才报错)
        *)                 ARCH="$(arch_from_openwrt 2>/dev/null || true)"
                           [ -n "$ARCH" ] || die "暂不支持的 CPU 架构: $(uname -m) (可到面板把该设备标记为不支持, 或反馈这个架构)" ;;
    esac
    # armv7l 也可能是 arm1176 (ARMv6) 的固件报出来的: OpenWrt 的目标名更可信。
    if [ "$ARCH" = "armv7" ]; then
        _da_arch="$(arch_from_openwrt 2>/dev/null || true)"
        if [ "$_da_arch" = "armv6" ]; then ARCH=armv6; fi
    fi

    MODEL="$(cat /tmp/sysinfo/model 2>/dev/null || true)"
    [ -n "$MODEL" ] || MODEL="$(cat /proc/device-tree/model 2>/dev/null | tr -d '\0' || true)"
    [ -n "$MODEL" ] || MODEL="$(uname -m)"
    HOSTNAME_NOW="$(uci get system.@system[0].hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null || echo router)"
    # 注意 `|| true`: 在 `set -e` 下, 带命令替换的赋值会继承子命令的退出码 ——
    # sed 读不到文件 (测试机/非标准环境) 会把整个脚本静默干掉, 一行输出都没有。
    FW_RELEASE="$(sed -n "s/^DISTRIB_RELEASE=['\"]\(.*\)['\"].*/\1/p" /etc/openwrt_release 2>/dev/null || true)"
    # 固件自己的目标名 (aarch64_cortex-a53 / mipsel_24kc …)。**BTF 包按这个挑** ——
    # 它比 uname -m 细一档, 而社区的包正是按它来命名的 (与 dae 那边同一个理由:
    # apk 的 --print-arch 只给到 CPU 家族, 会把子目标丢掉)。
    FW_ARCH="$(sed -n "s/^DISTRIB_ARCH=['\"]\(.*\)['\"].*/\1/p" /etc/openwrt_release 2>/dev/null || true)"
    if [ -n "$FW_RELEASE" ]; then OS_NAME="OpenWrt $FW_RELEASE"; else OS_NAME="OpenWrt"; fi
    #: 内核版本。默认就是 uname -r; ZP_KERNEL 只在"演练 / 特殊环境"里覆盖 —— 本机演练
    #: 跑在 macOS 上时 uname -r 是个与 OpenWrt 毫无关系的版本号, 而 BTF 那一档是按**内核
    #: 系列**挑包的 (6.6 / 6.12), 没有这个旋钮那一节就没法验。
    KERNEL="${ZP_KERNEL:-$(uname -r)}"
    detect_pkgmgr
}

# ---------------------------------------------------------------- 固件世代 / 包管理器
# 固件世代 = 主版本号 (21.02 → 21, 24.10 → 24, 25.12.5 → 25)。要区分的是"哪一代" ——
# 它同时决定包管理器与内核模块从哪个源来 (25.12 起 kmod 在"与内核版本绑定"的源里);
# 补丁号对这两件事没有帮助, 所以只取主版本。
fw_generation() {
    printf '%s' "$1" | sed -n 's/^\([0-9][0-9]*\)\..*/\1/p'
}

# 该用哪个包管理器。**版本号给倾向, 命令给事实** —— 两条一起看, 缺一不可:
#   * 只按版本号: 厂商固件的迁移态会把包格式判错 (dae 的安装脚本专门处理过这一类:
#     固件报 25.x, 里面却还是 opkg), 于是命令行一条都跑不动;
#   * 只按 command -v: 两个都在的机器上会选错 (为了迁移把 opkg 留成 shim 的固件确实存在)。
# 所以 25.x 优先 apk、24.10 及更早优先 opkg; 不一致时**按命令走并把这件事说出来**;
# 一个都没有就如实记 none —— 依赖装不了, 但后面每一级的探测照做 (模块可能本来就在)。
detect_pkgmgr() {
    FW_GEN="$(fw_generation "$FW_RELEASE" || true)"
    PKG_MGR_NOTE=""
    if [ -n "$FW_GEN" ] && [ "$FW_GEN" -ge 25 ] 2>/dev/null; then
        if command -v apk >/dev/null 2>&1; then
            PKG_MGR=apk
        elif command -v opkg >/dev/null 2>&1; then
            PKG_MGR=opkg
            PKG_MGR_NOTE="固件是 ${FW_RELEASE:-25.x}, 但本机只有 opkg (厂商固件的迁移态) —— 按 opkg 走"
        else
            PKG_MGR=none
            PKG_MGR_NOTE="固件是 ${FW_RELEASE:-25.x}, 但 apk / opkg 都不在"
        fi
    elif command -v opkg >/dev/null 2>&1; then
        PKG_MGR=opkg
    elif command -v apk >/dev/null 2>&1; then
        PKG_MGR=apk
        PKG_MGR_NOTE="固件是 ${FW_RELEASE:-未知}, 但本机只有 apk (backport / 自编译) —— 按 apk 走"
    else
        PKG_MGR=none
        PKG_MGR_NOTE="精简固件?"
    fi
}

# 本机是否已经有一个**跑得起来**的内核? 判据要和 install_core 的复用判据一致:
# 只看 `-x` 会把上一次留下的坏文件 (比如没解开的 gz) 当成已装好, 于是预检这边放行、
# 那边又去重下一次, 空间算错。
core_reusable() { [ -x "$ZP_BIN" ] && "$ZP_BIN" -v >/dev/null 2>&1; }

# 局域网地址。三处要用它 (安装摘要 / 自带 httpd / agent 上报), 而且**不能**拿它当
# "随便一个本机地址": 兜底 httpd 只绑这个地址, 猜错就绑不上, 猜成 0.0.0.0 则等于把
# 管理界面挂到 WAN 上。所以先问 uci (权威), 再从接口地址里取第一个非回环 IPv4。
lan_ip() {
    _lan="$(uci get network.lan.ipaddr 2>/dev/null || true)"
    [ -n "$_lan" ] || _lan="$(ip -4 addr show 2>/dev/null \
        | sed -n 's/.*inet \([0-9.]*\).*/\1/p' | grep -v '^127\.' | head -n1 || true)"
    [ -n "$_lan" ] || _lan="192.168.1.1"
    printf '%s' "$_lan"
}

preflight() {
    step "检查环境"
    # 包管理器与固件世代一起报 —— 它决定了后面"内核模块能不能补上", 而这一句是用户
    # 出问题时最先会截图的那一行。
    ok "设备: $MODEL · $ARCH · $OS_NAME · ${PKG_MGR:-?} (内核 $KERNEL)"

    # 固件世代决定了这台机器的软件源能不能用, 两代的坑不一样:
    #   24.10 及更早: 官方 24.10 已于 2026-09 EOL, 源随时可能下线 —— 主动提示升级
    #     (设计文档 §1.3 要求的那一条)。
    #   25.12 及更新: 内核模块在"与内核版本绑定"的源里, 厂商固件常常对不上 —— 先说清楚,
    #     免得"模块装不上"被当成安装脚本的毛病。
    case "$PKG_MGR" in
        apk)
            note "包管理器 apk (OpenWrt 25.12 起)。内核模块 (kmod-tun / kmod-nft-tproxy) 来自"
            note "  与内核版本绑定的那个源 —— 厂商固件的内核常与它不符, 那时会如实告诉你" ;;
        opkg)
            case "${FW_GEN:-}" in
                24) warn "OpenWrt 24.10 已于 2026-09 停止维护 (EOL): 官方源随时可能下线, 补内核模块
  会越来越靠运气。有条件请升到 25.12 后重跑这条安装命令 (设备凭据与配置都保留)。" ;;
            esac ;;
        none) warn "本机没有 apk / opkg (${PKG_MGR_NOTE:-两个都不在}) —— 缺的内核模块只能手动补" ;;
    esac
    # 版本号与命令不一致时 (厂商迁移态 / backport), 那句话在这里落地 —— 上面已经按事实选了。
    if [ -n "$PKG_MGR_NOTE" ] && [ "$PKG_MGR" != "none" ]; then
        note "$PKG_MGR_NOTE"
    fi

    # 空间: 只有"这一轮真的要装内核"时才需要 90 MB (20 MB 的 gz + 解压后约 57 MB);
    # 内核已经在而且能跑时, 本轮只多写几 MB 的分流数据库 —— 重跑安装命令 (= 升级客户端
    # / 更新分流数据) 的机器正是这种。拿 90 MB 去卡一台"内核就在那儿"的设备, 只会把用户
    # 挡在门外: 真机上第一次失败的安装已经把 57 MB 的内核解压在那儿了, 于是重跑时
    # "需要约 90 MB, 当前只有 89 MB" —— 明明什么都不缺。
    _need_mb=20
    core_reusable || _need_mb=90
    _free="$(df -k /overlay 2>/dev/null | awk 'NR==2{print $4}' || true)"
    [ -n "$_free" ] || _free="$(df -k / | awk 'NR==2{print $4}' || true)"
    if [ -n "$_free" ] && [ "$_free" -lt $((_need_mb * 1024)) ]; then
        if core_reusable; then
            die "可用空间不足: 更新分流数据需要约 ${_need_mb} MB, 当前只有 $((_free / 1024)) MB。
  请先清理 /tmp 或不用的插件 (内核已经在位, 不需要重装)。"
        fi
        die "可用空间不足: 首次安装需要约 ${_need_mb} MB (20 MB 内核压缩包 + 解压后约 57 MB),
  当前只有 $((_free / 1024)) MB。请先在路由器后台释放空间 (卸载不用的插件 / 清理 /tmp),
  或换一台闪存更大的设备。"
    fi

    # 面板可达性 (顺带确定 TLS 策略)
    # `${ZP_BASE}` 的花括号不能省: 后面紧跟一个中文字符时, 有的 shell (bash/某些
    # ash 构建) 会把高字节也算进变量名, 于是这句本该说"连不上面板"的话变成
    # "ZP_BASE?: unbound variable" —— 偏偏只在**真的连不上**的时候才触发。
    http_probe "$ZP_BASE/api/status" || die "连不上面板 ${ZP_BASE}。
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
        _old_base="$(sed -n 's/.*"base"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$ZP_DEV" | head -n1)"
        DEV_ID="$(sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$ZP_DEV" | head -n1)"
        DEV_SECRET="$(sed -n 's/.*"secret"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$ZP_DEV" | head -n1)"
        if [ -n "$DEV_ID" ] && [ -n "$DEV_SECRET" ]; then
            if [ -n "$_old_base" ] && [ "$_old_base" != "$ZP_BASE" ]; then
                # 换了面板: 这台路由器之前接的是别人。凭据在这里一定不认, 直接重新配对。
                warn "这台路由器原来接的是 $_old_base, 本次改用 $ZP_BASE"
            else
                ok "已接入过 (设备 $DEV_ID), 先沿用原有凭据"
                return 0
            fi
        fi
    fi

    # 更新模式 (`/c/install.sh`, 不带配对码): 已经装过的机器只是来升级客户端的,
    # 绝不能再配一次 —— 每次配对都会在面板上多出一台设备, 用户就得反复清设备。
    if [ -z "$ZP_CODE" ]; then
        if [ -f "$ZP_DEV" ]; then
            die "本机上的设备凭据不完整, 更新命令无法自救。
  请到面板「客户端」重新生成一条**带配对码**的安装命令 (首次安装那种)。"
        fi
        die "这台路由器还没有接入过任何面板 —— 更新命令只用于已装好的机器。
  请到面板「客户端」生成安装命令 (带配对码的那条)。"
    fi

    do_pair || die "接入失败: $PAIR_ERROR"
    ok "已接入: $DEV_NAME ($DEV_ID)"
}

# 用本次命令里的配对码换一份新凭据 (写进 device.json)。失败时把面板的话放进
# PAIR_ERROR —— 用户看到的必须是"配对码过期了, 回面板重新生成", 不是一句无解的报错。
do_pair() {
    _body='{"code":"'"$(json_escape "$ZP_CODE")"'","kind":"router"'
    _body="$_body"',"hostname":"'"$(json_escape "$HOSTNAME_NOW")"'"'
    _body="$_body"',"model":"'"$(json_escape "$MODEL")"'"'
    _body="$_body"',"arch":"'"$(json_escape "$ARCH")"'"'
    _body="$_body"',"os":"'"$(json_escape "$OS_NAME")"'"'
    _body="$_body"',"version":"'"$(json_escape "$ZP_CLIENT_VERSION")"'"}'

    _resp="$(http_post "$ZP_BASE/c/pair" "$_body" || true)"
    DEV_ID="$(json_get "$_resp" id)"
    DEV_SECRET="$(json_get "$_resp" secret)"
    # 面板的能力位: 有没有 /c/geo 分流数据库接口。旧面板没有 —— 那种面板给出的配置
    # 一定带 geo 规则, 而这台路由器上没有数据库, 内核会去 GitHub 拉并超时。所以这个
    # 标记是"要不要当场拦住用户"的唯一依据 (见 install_geo)。
    PANEL_GEO="$(json_get_bool "$_resp" geo)"
    if [ -z "$DEV_ID" ] || [ -z "$DEV_SECRET" ]; then
        PAIR_ERROR="$(json_get "$_resp" error)"
        [ -n "$PAIR_ERROR" ] || PAIR_ERROR="面板没有返回设备凭据 (配对码可能已过期)"
        return 1
    fi
    DEV_NAME="$(json_get "$_resp" name)"

    mkdir -p "$ZP_DIR"
    umask 077
    cat > "$ZP_DEV" <<EOF
{
  "id": "$DEV_ID",
  "secret": "$DEV_SECRET",
  "base": "$ZP_BASE",
  "name": "$DEV_NAME"
}
EOF
    # 多服务器清单: 每台面板一条。device.json 保留是为了让老版本的 agent 与
    # CLI 不至于读不到东西 (首次运行会把它迁移成 servers/ 下的一条)。
    mkdir -p "$ZP_DIR/servers"
    cat > "$ZP_DIR/servers/$(srv_key "$ZP_BASE").json" <<EOF
{
  "base": "$ZP_BASE",
  "id": "$DEV_ID",
  "secret": "$DEV_SECRET",
  "name": "${DEV_NAME:-$ZP_BASE}"
}
EOF
    chmod 600 "$ZP_DIR/servers/$(srv_key "$ZP_BASE").json"
    umask 022
    chmod 600 "$ZP_DEV"
    return 0
}

# ---------------------------------------------------------------- 依赖
# 主方案是 TUN (kmod-tun), tproxy (kmod-nft-tproxy) 只是"没有 TUN 时"的回退。
#
# 两台真机把这段代码的坑都踩出来了:
#   * OpenWrt 25.12 起包管理器从 opkg 换成了 apk (Alpine 那套)。只认 opkg 的写法在这类
#     固件上是**静默跳过**: 两个 kmod 一个都没装, 安装过程看着全绿, 而 TUN 建不出来、
#     tproxy 回退也没有 nft 规则 —— 全屋代理名存实亡。所以两套都认。
#   * 原厂固件 (GL.iNet 21.02-SNAPSHOT / 内核 5.4.281) 的软件源和它自己那个内核**对不上**,
#     `opkg install kmod-nft-tproxy` 必然失败。但这台机器有 TUN, 那个模块一次都用不到 ——
#     把它写成 "内核模块安装未全部成功" 的警告, 用户读到的就是"安装坏了"。
#
# 所以判据不是"安装命令成没成功", 而是**能力到底在不在**: 两个都试着装 (装不上就算了),
# 各自验证一次, 再按"这件事到底重要不重要"决定用什么口气说话。
#
# 两代包管理器的脾气不一样, 各按各的来 (apk 一侧的写法照 OpenWrt 官方的 opkg→apk
# cheatsheet 与 dae 的家用安装脚本, 见 README 8.76):
#   * apk (25.12+): `apk -U add` = 刷新索引 + 安装, 一条命令干完 opkg 的两条 (索引不新鲜
#     时 `apk add` 会拿一份过期的 packages.adb 去找包)。
#   * apk **要求包签名可验证**; 自建 / 厂商源常常没有签名密钥, 于是报 "UNTRUSTED
#     signature" —— dae 那边就是在这里退一步用 --allow-untrusted。**只在报错确实是
#     签名类时**退这一步: 别的错 (源里没有这个包 / 依赖不满足) 退也没用, 只会盖住真原因。
#   * opkg (24.10 及更早): 老样子。源对不上内核时它会失败 —— 那是源的事, 不是语法的事。
pkg_install() {
    _pkg="$1"
    DEPS_WHY=""
    case "$PKG_MGR" in
        apk)
            _apk_err="$(apk -U add "$_pkg" 2>&1)" && return 0
            case "$_apk_err" in
                *UNTRUSTED*|*untrusted*|*signature*|*Signature*|*BAD*SIGN*|*BADCKSUM*)
                    _apk_err2="$(apk add --allow-untrusted "$_pkg" 2>&1)" && return 0
                    DEPS_WHY="签名不可信, 退到 --allow-untrusted 也没成: $(err_line "${_apk_err2:-$_apk_err}")" ;;
                *) DEPS_WHY="$(err_line "${_apk_err:-apk 没说话}")" ;;
            esac
            return 1 ;;
        opkg)
            _opkg_err="$(opkg install "$_pkg" 2>&1)" && return 0
            DEPS_WHY="$(err_line "${_opkg_err:-opkg 没说话}")"
            return 1 ;;
        *)
            DEPS_WHY="本机没有包管理器"
            return 127 ;;
    esac
}
pkg_update() {
    case "$PKG_MGR" in
        apk)  apk update >/dev/null 2>&1 ;;
        opkg) opkg update >/dev/null 2>&1 ;;
        *)    return 127 ;;
    esac
}

# 一条"这个包没装成 + 为什么"的流水 (一行一条, 攒进 DEPS_FAILED)。
# 装不上照样继续 —— 但**不许悄悄过去**: 结尾摘要与 doctor 会把这一串原样带出来,
# 于是"这台机器缺内核模块"和"为什么缺"不再需要用户截图去猜。
deps_fail() {  # $1=包名, $2=原因
    _df="$1: ${2:-未知原因}"
    if [ -n "$DEPS_FAILED" ]; then DEPS_FAILED="$DEPS_FAILED; $_df"; else DEPS_FAILED="$_df"; fi
}

# 补内核模块该敲哪条命令 —— 按这台机器真正的包管理器来。
deps_hint() {
    case "$PKG_MGR" in
        apk)  printf 'apk -U add kmod-tun kmod-nft-tproxy   (报了 UNTRUSTED 就再加 --allow-untrusted)' ;;
        opkg) printf 'opkg install kmod-tun kmod-nft-tproxy' ;;
        *)    printf '本机没有 apk / opkg —— 内核模块只能从固件里补' ;;
    esac
}

# 数据面能力阶梯, 装机时**每一级都真做一次**, 结论写进 /etc/zeroproxy/caps。
#
# 为什么是一张阶梯而不是一对布尔值: "这台机器支持什么"不是编译期常量。真机上见过
# 太多反例 —— /dev/net/tun 在但建不出设备、nft 命令在但内核没有 nf_tables、原厂固件
# 的 kmod 和它自己那个内核不匹配。老代码只有"tun 优先 / tproxy 回退"两级, 于是那台
# 原厂 21.02 机器两级都不可用, 结尾却还写着"全屋代理已开启"(见 README 8.45)。
#
# 阶梯 (从优到劣):
#   L0 ebpf      eBPF, 直连真旁路 (内核 >=5.17 + BTF) —— 本版本只探不选, 留给性能模式
#   L1 tun       内核接管路由与 DNS, 覆盖全屋 + 路由器自身
#   L2 tproxy    nftables, 覆盖全屋 (路由器自身流量除外)
#   L3 redirect  iptables nat REDIRECT, 覆盖局域网 TCP —— 21.02 / fw3 那类固件的唯一路
#   L4 none      不接管; 只有显式配了代理的设备能用 (状态照实说, 不假装)
#
# caps 里还有 chosen (实际选中的一级) 与 covered (这一级覆盖到哪) —— 安装输出、CLI、
# agent 上报、面板显示都读同一份, 于是"谁被接管了"只有一处定义。
NET_TUN=0
NET_NFT=0
NET_TPROXY=0
NET_REDIRECT=0
NET_EBPF=0
#: 这一档数据面能不能**一并接管 IPv6**。局域网设备从运营商那里拿到的是原生 v6 地址,
#: 只接管 v4 的透明代理对 v6 等于不存在 —— 那些流量直接出去, 目标网站看到的是用户的
#: 真实 v6 地址 (看起来一切正常, 代理却等于没装)。而 mihomo 自己的 `ipv6: false` 并不
#: 真的关掉 v6 协议栈 (上游 issue #2254), 所以这件事只能由我们在数据面这一层回答。
NET_IPV6=0
#: WAN 的 MTU 与 tun 该用的 MTU。PPPoE 的 WAN 是 1492, 而 tun 里出去的包还要再被封装
#: 一层 (TCP + TLS + 协议头 ≈ 60 字节) —— tun 仍按 1500 收包时封装后就是超包, 表现是
#: **"小页面能开、一下载就卡住"**。按 WAN 的实际 MTU 收着点, 别让大包死在路上。
WAN_MTU=""
TUN_MTU=1500
#: 转发卸载 (软件 flow offloading / 硬件 HNAT) 开着时, 已建立连接的转发会**绕过
#: netfilter** —— tproxy / redirect 那两档的代理规则就在 netfilter 里, 被绕过的后果是
#: "局域网设备上网正常, 但流量根本没走代理"。tun 那一档走的是路由, 不受影响。
NET_OFFLOAD=0
#: 最近一次探测的失败原因 (内核/程序的原话优先)。写进 caps, 面板与 UI 都要看得见 ——
#: 8.45 的真机就是只有一句"未出现", 只能靠用户截图才拼出原因。
PROBE_WHY=""
CAPS_WHY_TUN=""
CAPS_WHY_TPROXY=""
CAPS_WHY_REDIRECT=""
CAPS_WHY_EBPF=""
CAPS_WHY_IPV6=""
#: 生效的数据面与它覆盖的范围 (choose_datapath 填, verify 可能再降级)
DATAPATH=""
COVERED=""

# 外部命令的报错往往是**多行** (nft 的第一行才是内核说的话, 第二行开始是命令回显 +
# `^^^` 标记)。整段塞进面板/界面就成了一坨看不懂的东西 —— 真机截图里正是
# "No such file or directoryadd rule inet zp_probe c ...^^^^^^^^"。只留第一行。
err_line() { printf '%s' "$1" | head -n1 | tr -d '\r' | cut -c1-120; }

# 内核主次版本是否 >= 给定值 (dae 那一级要看内核, 5.17 是它绑定 LAN 的下限)。
kernel_ge() {
    _k="${KERNEL:-$(uname -r 2>/dev/null || true)}"
    _maj="$(printf '%s' "$_k" | sed -n 's/^\([0-9][0-9]*\)\..*/\1/p')"
    _min="$(printf '%s' "$_k" | sed -n 's/^[0-9][0-9]*\.\([0-9][0-9]*\).*/\1/p')"
    [ -n "$_maj" ] || return 1
    [ -n "$_min" ] || _min=0
    if [ "$_maj" -gt "$1" ] 2>/dev/null; then return 0; fi
    if [ "$_maj" -eq "$1" ] 2>/dev/null && [ "$_min" -ge "$2" ] 2>/dev/null; then return 0; fi
    return 1
}

# 局域网接口名。redirect 那一级只接管从它进来的流量 —— 所以这个值必须是**局域网**的:
# 猜成 0.0.0.0/所有接口等于把 WAN 侧入站也接管, 比不接管更糟。
#
# 依次问: uci 的 lan.device / lan.ifname → 拿 lan_ip 反查 → br-lan。候选要真的存在
# (/sys/class/net 或 ip link) 才用它; 存在性也判不出来时退回 br-lan (OpenWrt 上局域网
# 桥的固定名字), 运行时 zp_redirect_iface 还会再用 uci 校正一次。
lan_iface() {
    _cand="$(uci -q get network.lan.device 2>/dev/null || true)"
    [ -n "$_cand" ] || _cand="$(uci -q get network.lan.ifname 2>/dev/null || true)"
    if [ -z "$_cand" ]; then
        _ip="$(lan_ip 2>/dev/null || true)"
        if [ -n "$_ip" ]; then
            _cand="$(ip -o -4 addr show 2>/dev/null \
                | sed -n "s/^[0-9][0-9]*: \([^ ]*\) *inet $_ip\/.*/\1/p" | head -n1)"
        fi
    fi
    for _d in "$_cand" br-lan; do
        [ -n "$_d" ] || continue
        if [ -d "/sys/class/net/$_d" ]; then
            printf '%s' "$_d"; return 0
        fi
        if ip link show "$_d" >/dev/null 2>&1; then
            printf '%s' "$_d"; return 0
        fi
    done
    printf '%s' "${_cand:-br-lan}"
}

# nft 能不能真的下规则。有 nft 命令 ≠ 内核里有 nf_tables —— 原厂精简固件上见过
# "命令在、规则下不去"的组合, 而那一项正是 auto-redirect 依赖的东西。
nft_ok() {
    PROBE_WHY=""
    if ! command -v nft >/dev/null 2>&1; then
        PROBE_WHY="本机没有 nft 命令"
        return 1
    fi
    if ! _nft_err="$(nft add table inet zp_probe 2>&1)"; then
        PROBE_WHY="nft 规则下不去 (内核里没有 nf_tables): $(err_line "${_nft_err:-命令失败}")"
        return 1
    fi
    nft delete table inet zp_probe 2>/dev/null || true
    return 0
}

# tproxy 能不能用 —— 不看包装没装上, 直接问内核: 加一条 tproxy 规则成不成。
# 为什么不用"模块在不在": tproxy 有可能被编进内核 (那时 /sys/module 里没有它), 而
# `nft` 会把模块按需加载 —— 真加一条规则才是这件事的最终判据。探针用完就撤掉。
tproxy_ok() {
    PROBE_WHY=""
    if ! nft_ok; then
        PROBE_WHY="${PROBE_WHY:-nft 不可用}"
        return 1
    fi
    if ! nft add table inet zp_probe 2>/dev/null; then
        PROBE_WHY="nft 表建不起来"
        return 1
    fi
    if ! nft add chain inet zp_probe c '{ type filter hook prerouting priority -150; policy accept; }' 2>/dev/null; then
        nft delete table inet zp_probe 2>/dev/null || true
        PROBE_WHY="内核不接受 prerouting 链 (nf_tables 不完整)"
        return 1
    fi
    if _tp_err="$(nft add rule inet zp_probe c meta l4proto tcp tproxy to :1 2>&1)"; then
        nft delete table inet zp_probe 2>/dev/null || true
        return 0
    fi
    nft delete table inet zp_probe 2>/dev/null || true
    PROBE_WHY="tproxy 规则下不去 (内核里没有 nft_tproxy): $(err_line "${_tp_err:-命令失败}")"
    return 1
}

# TUN 能不能真的建出设备。**节点存在 ≠ 能建**: /dev/net/tun 是装包时创建的, 而模块
# 可能没编进这个内核、或者加载失败 —— 原厂 5.4.281 那台就是"节点在, 建不出来", 于是
# mihomo 起 tun 失败、脚本却一直以为 TUN 没问题。判据: 真建一个再删掉; `ip` 不带
# tuntap 子命令时, 退化成"模块在不在"。
tun_ok() {
    PROBE_WHY=""
    if [ ! -c "$TUN_DEV" ]; then
        PROBE_WHY="$TUN_DEV 不存在 (缺 kmod-tun)"
        return 1
    fi
    if _tun_err="$(ip tuntap add dev zp0probe mode tun 2>&1)"; then
        ip link del zp0probe 2>/dev/null || ip tuntap del dev zp0probe mode tun 2>/dev/null || true
        return 0
    fi
    if [ -d /sys/module/tun ]; then return 0; fi
    if grep -q '^tun ' /proc/modules 2>/dev/null; then return 0; fi
    PROBE_WHY="建不出 tun 设备: $(err_line "${_tun_err:-Operation not supported}")"
    return 1
}

# iptables nat + REDIRECT —— 阶梯上最老、也最抗造的一级。
#
# 为什么必须有它: OpenWrt 21.02 / 内核 5.4 / fw3 那一代固件没有 nf_tables (nft 命令在、
# 规则下不去), 原厂 GL.iNet 更狠 —— 连 tun 都建不出来。8.45 那台机器上 TUN 与 tproxy
# 双双不可用, 结尾只能写"未生效"。而 iptables 从 2.4 内核起就在, 那条路它一定能走。
# 代价是只能接管 TCP (REDIRECT 不适用于 UDP), 所以这一级的 covered 是 lan_tcp ——
# 覆盖到哪就说到哪, 不夸大。
#
# 判据同样是"真做一次": 建一条自己的链、加一条 REDIRECT 规则、再整体撤掉。
redirect_ok() {
    PROBE_WHY=""
    if ! command -v iptables >/dev/null 2>&1; then
        PROBE_WHY="本机没有 iptables 命令"
        return 1
    fi
    if ! iptables -t nat -N zp_probe 2>/dev/null; then
        # nat 表可能只是**模块没加载** —— 老固件 (原厂 21.02 那类) 上 iptables 是唯一的
        # 路, 不能因为一个模块没加载就把它判死 (真机上这一级本该救场)。试一把再判。
        modprobe iptable_nat 2>/dev/null || true
        modprobe nf_nat 2>/dev/null || true
        modprobe nf_conntrack 2>/dev/null || true
        if ! iptables -t nat -N zp_probe 2>/dev/null; then
            PROBE_WHY="iptables 的 nat 表不可用 (试过加载 iptable_nat 也没成)"
            return 1
        fi
    fi
    if _rd_err="$(iptables -t nat -A zp_probe -p tcp -j REDIRECT --to-ports 1 2>&1)"; then
        iptables -t nat -F zp_probe 2>/dev/null || true
        iptables -t nat -X zp_probe 2>/dev/null || true
        return 0
    fi
    iptables -t nat -F zp_probe 2>/dev/null || true
    iptables -t nat -X zp_probe 2>/dev/null || true
    PROBE_WHY="REDIRECT 规则下不去: $(err_line "${_rd_err:-命令失败}")"
    return 1
}

# ---------------------------------------------------------------- 内核 BTF (CO-RE 类型信息)
# 不带 CONFIG_DEBUG_INFO_BTF 编译的固件没有 /sys/kernel/btf/vmlinux, 于是 CO-RE eBPF
# (dae / daed 那一类, 也是"性能档"的候选) 加载不起来 —— 真机 (GL-MT3600BE · 25.12.5)
# 上探测到的正是这个。
#
# **这件事在固件上能补, 不必重刷**: 社区 (kenzok8/vmlinux-btf) 拿同一份内核源码再编一个
# 带 BTF 的影子内核, 用 pahole 导出 detached BTF, 装到
# /usr/lib/debug/boot/vmlinux-<内核版本> —— cilium/ebpf 与 libbpf 在 sysfs 里找不到 BTF
# 时**正好会回退到这个路径** (下面 BTF_CANDIDATES 的顺序就是它们那份候选表), 所以补上它
# 之后 eBPF 那一档就真的可用了。包名里带内核版本, BTF 在**同一 minor 系列内兼容**
# (6.12.x 的包装在别的 6.12.y 上 —— 包的 postinst 会按 uname -r 自己建软链), 所以这里
# 只要把 uname -r 告诉面板, 由它挑包。
#
# 补的动作有三条路, 顺序即优先级:
#   1. 本机软件源 (有些固件/feed 里就有这个包) —— 一条命令, 最省事;
#   2. 面板 (/c/btf): 与内核二进制 / 分流数据库完全同一个协议 —— 面板去取, 路由器只访问
#      面板一个地址 (装机时这台路由器还没有任何代理可用, 让它自己去 GitHub 是 2.9.2 的教训);
#   3. 补不上就如实说清楚: 是"这个内核系列没有现成件"还是"这次没取到", 以及**它到底
#      影响什么** (只影响性能档; 当前的 TUN / tproxy 数据面一个字节都不受影响)。
#
# 只在"这一档本来就可能有戏"时才动手 —— 内核低于 5.17 (dae 绑定 LAN 的下限) 或内核系列
# 不在社区包覆盖范围内时, 装了也没用, 那就别去占人家的闪存。
BTF_PATH=""
BTF_HOW=""
BTF_WHY=""

# 候选路径: 与 libbpf / cilium/ebpf 的查找顺序一致 (findVMLinux)。
# 顺序有意义: sysfs 里那份是内核自带的, 排第一; 后面的都是"补进来的"。
btf_candidates() {
    printf '%s\n' \
        "/sys/kernel/btf/vmlinux" \
        "/boot/vmlinux-$KERNEL" \
        "/lib/modules/$KERNEL/vmlinux-$KERNEL" \
        "/lib/modules/$KERNEL/build/vmlinux" \
        "/usr/lib/modules/$KERNEL/kernel/vmlinux" \
        "/usr/lib/debug/boot/vmlinux-$KERNEL" \
        "/usr/lib/debug/boot/vmlinux-$KERNEL.debug" \
        "/usr/lib/debug/lib/modules/$KERNEL/vmlinux"
}

# 按上面那个顺序找第一个**可读**的 BTF。找不到就什么都不输出。
btf_find() {
    for _b in $(btf_candidates); do
        [ -r "$_b" ] && { printf '%s' "$_b"; return 0; }
    done
    return 1
}

# 这个文件像不像一份 BTF? 只用来**验证我们刚装上去的那一份**, 不用来否定内核自带的。
# 判据是"够大 + 不是一页 HTML/文本" —— 真实的 vmlinux BTF 是几 MB 的二进制, 而失败的
# 下载往往是几十 KB 的网页或错误页 (面板/反代很爱回这种东西)。
# 下限可用 ZP_BTF_MIN_BYTES 调低: 演练里的假包只有几百字节 (与 ZP_CORE_MIN_BYTES 同一个
# 用法 —— 真机上的判据不该被演练的方便改掉)。
btf_plausible() {
    [ -s "$1" ] || return 1
    _bs="$(wc -c < "$1" 2>/dev/null | tr -d ' ' || true)"
    [ "${_bs:-0}" -ge "${ZP_BTF_MIN_BYTES:-65536}" ] 2>/dev/null || return 1
    if head -c 8 "$1" 2>/dev/null | grep -qi '<!doc\|<html'; then return 1; fi
    return 0
}

# 这一档值不值得补: 内核 >=5.17 (dae 绑定 LAN 的下限) + 内核系列在社区包的覆盖范围内
# (6.6 / 6.12) + 闪存放得下 (几 MB)。不满足时把理由记进 BTF_WHY —— 结论照实说。
btf_worth_fixing() {
    if ! kernel_ge 5 17; then
        BTF_WHY="内核 $KERNEL 低于 5.17 —— 这一档本来就用不上"
        return 1
    fi
    _series="$(printf '%s' "$KERNEL" | sed -n 's/^\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')"
    case "$_series" in
        6.6|6.12) ;;
        *)
            BTF_WHY="社区 BTF 包只覆盖 6.6 / 6.12 两个内核系列 (这台是 ${_series:-未知})"
            return 1 ;;
    esac
    _bfree="$(df -k /overlay 2>/dev/null | awk 'NR==2{print $4}' || true)"
    [ -n "$_bfree" ] || _bfree="$(df -k / 2>/dev/null | awk 'NR==2{print $4}' || true)"
    # 上游那份包是 1.2~1.7 MB (压缩), 解开后是几 MB 的 BTF; 再留一倍余量。
    if [ -n "$_bfree" ] && [ "$_bfree" -lt 12288 ] 2>/dev/null; then
        BTF_WHY="可用空间不足 ($((_bfree / 1024)) MB) —— 这个包连下载带解开要几 MB"
        return 1
    fi
    return 0
}

# 从面板取匹配的 BTF 包并装上。返回值: 0 = 现在真的有了。
btf_from_panel() {
    _ext=ipk
    [ "$PKG_MGR" = "apk" ] && _ext=apk
    [ "$PKG_MGR" = "none" ] && { BTF_WHY="本机没有包管理器, 装不了 BTF 包"; return 1; }
    _tmp="$ZP_DIR/btf.pkg"
    _err=""
    #: 只有"面板明确给了 200 **而且**文件像那么回事"才算拿到。
    #: 为什么两个都要: 体积闸门单独做判据时, 一份 502 的错误正文 (几百字节) 也可能过闸 ——
    #: 8.75 那次真机就是栽在"闸门比的是错误正文的大小"上。这里状态码在前、体积在后,
    #: 于是"面板说没有"永远不会被当成"拿到了一个包"。
    _got=0
    for _a in $(btf_arch_list); do
        _url="$ZP_BASE/c/btf?kver=$KERNEL&arch=$_a&fmt=$_ext"
        progress_note "面板正在准备内核 BTF 包 (内核 $KERNEL · $_a)…"
        # 面板那一侧有硬上限 (ZP_BTF_DEADLINE, 默认 90 秒); 这里给足余量。
        if http_fetch_to "$_url" "$_tmp" 180 0 && btf_plausible "$_tmp"; then
            _got=1
            break
        fi
        # 面板失败时正文的第一行就是写给人看的原因 (404/502 的 body) —— 直接拿它当原因。
        # 不能用 show_body: 它是往 stderr 打的 (那是给人看的), 这里要的是字符串。
        _body="$(sed -n '1p' "$_tmp" 2>/dev/null | tr -d '\r' | cut -c1-160 || true)"
        _err="${_body:-面板没有这一档的包 (HTTP ${HTTP_CODE:-?})}"
    done
    if [ "$_got" != "1" ]; then
        BTF_WHY="${_err:-面板没有这一档的包}"
        rm -f "$_tmp"
        return 1
    fi
    # 本地包一律没有签名 (自建件), apk 必须显式放行 —— 与上一轮 kmod 那条同一个道理。
    if [ "$PKG_MGR" = "apk" ]; then
        apk add --allow-untrusted "$_tmp" >/dev/null 2>&1 || true
    else
        opkg install "$_tmp" >/dev/null 2>&1 || true
    fi
    rm -f "$_tmp"
    if BTF_PATH="$(btf_find)"; then
        BTF_HOW=panel
        return 0
    fi
    BTF_WHY="面板给的包装上了, 但 $KERNEL 还是没有 BTF (包与内核不匹配?)"
    return 1
}

# 架构候选: OpenWrt 的目标名 (aarch64_cortex-a53 这种), 细分的没有就退通用档。
btf_arch_list() {
    [ -n "$FW_ARCH" ] || return 0
    printf '%s\n' "$FW_ARCH"
    case "$FW_ARCH" in
        aarch64_*) [ "$FW_ARCH" = "aarch64_generic" ] || printf '%s\n' aarch64_generic ;;
    esac
}

# 缺 BTF 时**自动补**。补上就把结论写进 BTF_PATH / BTF_HOW, 补不上写 BTF_WHY。
btf_ensure() {
    BTF_PATH=""
    BTF_HOW=""
    BTF_WHY=""
    if BTF_PATH="$(btf_find)"; then
        # 内核自带的 (sysfs) 与"以前补进来的"都算就绪 —— 后者用 detached 路径
        case "$BTF_PATH" in
            /sys/kernel/btf/vmlinux) BTF_HOW=kernel ;;
            *)                       BTF_HOW=detached ;;
        esac
        return 0
    fi
    [ "${ZP_BTF:-1}" = "0" ] && { BTF_WHY="已按 ZP_BTF=0 跳过自动补齐"; return 1; }
    btf_worth_fixing || return 1

    # 1) 本机软件源里就有这个包
    if pkg_install vmlinux-btf; then
        if BTF_PATH="$(btf_find)"; then BTF_HOW=feed; return 0; fi
    fi
    # 2) 面板分发 (与内核 / 分流数据库同一条协议)
    if btf_from_panel; then return 0; fi
    return 1
}

# eBPF (dae) 能不能用 —— 本版本**只探不选**。
# 它的性能收益是量级的 (直连流量真旁路, 不过用户态), 但前提苛刻 (内核 >=5.17 + BTF) 且
# 多一个二进制要面板分发, 所以先把结论记进 caps, 让面板知道这台机器有没有性能模式的底子。
# 这一级不做任何实际改动 (只读内核版本与 BTF), 所以探测本身没有副作用。
ebpf_ok() {
    PROBE_WHY=""
    if ! kernel_ge 5 17; then
        PROBE_WHY="内核 $KERNEL 低于 5.17"
        return 1
    fi
    if ! btf_ok; then
        PROBE_WHY="内核没有 BTF (${BTF_WHY:-/sys/kernel/btf/vmlinux 不存在, 也没有补进来})"
        return 1
    fi
    return 0
}

btf_ok() { [ -n "$(btf_find)" ]; }

# ---------------------------------------------------------------- 性能模式 (eBPF / dae)
# L0 那一档: 数据面交给 dae, eBPF 在内核里分流, 直连流量**真旁路** (不过用户态)。
# 它与 tun / tproxy 是**互斥**的 —— 两套都在抢同一批流量, 所以它是一个"能进能出"的开关,
# 而不是叠在现有数据面上的一层 (进去 = 停 mihomo, 出来 = 起 mihomo)。
#
# 只在真的能进时才让按钮可点 (界面据此显示"能"或"为什么不能"):
#   * 内核 >=5.17 且带 BTF —— 正是 ebpf_ok 在判的事 (BTF 缺了会自动补, 见 btf_ensure);
#   * ZP_PERF=0 可以整个关掉这一档 (给"我就想用 tun"的人一个开关)。
# 取 dae 与它的配置是**点按钮时**才做的事 (不占闪存, 也不用为用不到的人下载 10 MB)。
perf_cap_probe() {
    PERF_CAP=0
    PERF_WHY=""
    if [ "${ZP_PERF:-1}" = "0" ]; then
        PERF_WHY="已按 ZP_PERF=0 关闭"
    elif [ "$NET_EBPF" = "1" ]; then
        PERF_CAP=1
    else
        PERF_WHY="${CAPS_WHY_EBPF:-内核条件不满足}"
    fi
}

#: 性能模式现在**是不是在用** (读它自己的状态文件)。注意这是"意图 + 上次结论", 现场由
#: agent 与本地界面另判 (dae 进程还在不在) —— 与 tun/tproxy 那套 chosen/covered 同一个分工。
_perf_flag() {
    if [ "$(sed -n '1p' "$ZP_DIR/perf/state" 2>/dev/null)" = "on" ]; then printf '1'; else printf '0'; fi
}

#: 为什么进不去 / 为什么退回来了。优先用 perf 自己记下的原话 (那才是现场), 其次用探测结论。
perf_why_now() {
    _pw="$(sed -n '1p' "$ZP_DIR/perf/why" 2>/dev/null || true)"
    if [ -n "$_pw" ]; then printf '%s' "$_pw"; else printf '%s' "${PERF_WHY:-}"; fi
}

# 内核能不能按 IPv6 目标做 tproxy (nft 的 inet 表天然同时看 v4/v6, 但"支持 v6 的 tproxy"
# 是内核里的另一件事 —— 老内核上有过只编了 v4 的情况)。探针同样用完就撤。
nft_v6_ok() {
    PROBE_WHY=""
    nft_ok || { PROBE_WHY="${PROBE_WHY:-nft 不可用}"; return 1; }
    if ! nft add table inet zp_probe6 2>/dev/null; then
        PROBE_WHY="nft 表建不起来"
        return 1
    fi
    if ! nft add chain inet zp_probe6 c '{ type filter hook prerouting priority -150; policy accept; }' 2>/dev/null; then
        nft delete table inet zp_probe6 2>/dev/null || true
        PROBE_WHY="内核不接受 prerouting 链"
        return 1
    fi
    # 探针写成与生产规则**同一种形状** (`meta nfproto ipv6 … tproxy ip6 to :1`):
    # 探的必须是真正要下发给内核的那条规则。第一版漏了家族, 在真机上直接是
    # "Transparent proxy support requires transport protocol match" —— 那台机器会被
    # 误判成"IPv6 接管不了", 而它明明能 (真机 GL-MT3000 / OpenWrt 24.10 / 内核 6.6 实测)。
    if _v6_err="$(nft add rule inet zp_probe6 c meta nfproto ipv6 meta l4proto tcp tproxy ip6 to :1 2>&1)"; then
        nft delete table inet zp_probe6 2>/dev/null || true
        return 0
    fi
    nft delete table inet zp_probe6 2>/dev/null || true
    PROBE_WHY="IPv6 tproxy 规则下不去: $(err_line "${_v6_err:-内核不支持}")"
    return 1
}

# 这一档数据面能不能一并接管 IPv6。判据是"数据面本身能覆盖 v6 吗":
#   tun     能 —— mihomo 给 tun 分配 v6 地址, auto-route 一并管 v6
#   tproxy  要看内核支不支持 v6 的 tproxy (探一次)
#   redirect 只有本机有 ip6tables 才行
#   none    谈不上
# 覆盖不了时**不做静默处理**: 记进 caps 并一路报到面板 —— 卡片上会写"IPv6 未接管",
# 用户至少知道自己暴露在哪。
# WAN 接口的 MTU。**用默认路由 + table main**: tun 的 auto-route 会把默认路由挪到它自己
# 的独立路由表里, 重跑安装时按"默认路由"取很容易取到 zp-tun (MTU 1500) —— 那就成了
# "拿代理自己的 MTU 去算代理的 MTU"。table main 里留着的是真实的 WAN 出口。
wan_mtu() {
    _dev="$(ip route show table main default 2>/dev/null \
        | sed -n 's/.*dev \([^ ]*\).*/\1/p' | head -n1)"
    if [ -z "$_dev" ]; then
        _dev="$(uci -q get network.wan.device 2>/dev/null \
            || uci -q get network.wan.ifname 2>/dev/null || true)"
    fi
    [ -n "$_dev" ] || return 1
    _m="$(ip link show "$_dev" 2>/dev/null | sed -n 's/.*mtu \([0-9][0-9]*\).*/\1/p' | head -n1)"
    [ -n "$_m" ] || return 1
    printf '%s' "$_m"
}

# tun 的 MTU 取多少。只有一个出发点: **封装之后不能超过 WAN 的 MTU**。
#   WAN = 1500 (以太网直连 / 大多数 DHCP): 保持 1500 —— 今天跑得好好的机器不去动它;
#   WAN < 1500 (PPPoE 1492 / PPTP / 部分 4G): 按 WAN 减去封装开销, 否则大包被丢或分片,
#   表现是"网页能开, 一下载就卡住"。下界 1280 是 IPv6 的最小 MTU。
compute_tun_mtu() {
    TUN_MTU=1500
    WAN_MTU="$(wan_mtu 2>/dev/null || true)"
    [ -n "$WAN_MTU" ] || { WAN_MTU=""; return 0; }
    if [ "$WAN_MTU" -lt 1500 ] 2>/dev/null; then
        TUN_MTU=$((WAN_MTU - 60))
        [ "$TUN_MTU" -lt 1280 ] && TUN_MTU=1280
    fi
}

# 转发卸载开着吗 (软件 flow offloading 或硬件 HNAT)。探测而已 —— **不去改用户的防火墙
# 设置** (那是他自己的选择), 但必须报出来: 在 tproxy / redirect 那两档下它会让流量绕过代理。
offload_state() {
    _sw="$(uci -q get firewall.@defaults[0].flow_offloading 2>/dev/null || true)"
    _hw="$(uci -q get firewall.@defaults[0].flow_offloading_hw 2>/dev/null || true)"
    case "${_sw}${_hw}" in
        *1*) printf '1' ;;
        *)   printf '0' ;;
    esac
}

# eBPF 那一档 (dae) 到底差什么 —— 只在探测失败时给一句能看懂的话。
# 它要的不只是内核版本: BTF (CONFIG_DEBUG_INFO_BTF) 才是真门槛, 而 OpenWrt 官方内核
# 默认**不带**它 (为了省体积), 所以绝大多数路由器上这一档永远是"看得见、吃不着"。
ebpf_detail() {
    if [ "$NET_EBPF" = "1" ]; then
        case "${BTF_HOW:-}" in
            kernel)   printf '内核 %s + BTF 都在 —— 这一档技术上可用' "$KERNEL" ;;
            detached) printf '内核 %s + BTF 就绪 (detached: %s)' "$KERNEL" "${BTF_PATH:-?}" ;;
            feed|panel) printf '内核 %s + BTF 已自动补上 (%s: %s)' \
                            "$KERNEL" \
                            "$( [ "$BTF_HOW" = "feed" ] && printf '软件源' || printf '面板分发' )" \
                            "${BTF_PATH:-?}" ;;
            *)        printf '内核 %s + BTF 就绪' "$KERNEL" ;;
        esac
    else
        printf '%s' "${CAPS_WHY_EBPF:-内核条件不满足}"
    fi
}

compute_ipv6_cap() {
    NET_IPV6=0
    CAPS_WHY_IPV6=""
    case "$DATAPATH" in
        tun)    NET_IPV6=1 ;;
        tproxy) if nft_v6_ok; then NET_IPV6=1; else CAPS_WHY_IPV6="$PROBE_WHY"; fi ;;
        redirect)
            if command -v ip6tables >/dev/null 2>&1; then NET_IPV6=1
            else CAPS_WHY_IPV6="本机没有 ip6tables (老固件), 局域网 IPv6 会直接出去"; fi
            ;;
        *)      CAPS_WHY_IPV6="透明代理没有生效, IPv6 自然也谈不上接管" ;;
    esac
    if [ "$NET_IPV6" = "0" ] && [ -z "$CAPS_WHY_IPV6" ]; then
        CAPS_WHY_IPV6="这一档数据面覆盖不到 IPv6"
    fi
}

# 能力落盘 (agent 读它决定给面板报 ?tproxy=)。格式极简: 一行一个 key=value,
# 用 sed 取就够 —— 路由器上没有 jq。
#
# `autoredirect` 是**学出来的**, 不是探出来的: 面板配置里的 auto-redirect 会让某些
# 固件上的 tun 整个起不来 (见 tun_retry_without_redirect)。那次自愈成功后把它记成 0,
# 于是以后每轮重建配置都不再要它。想重新试一次: 删掉 /etc/zeroproxy/caps 或把这一行
# 改成 1, 再重跑安装命令。
write_caps() {
    _ar="$(sed -n 's/^autoredirect=//p' "$ZP_DIR/caps" 2>/dev/null | head -n1)"
    case "$_ar" in 0) ;; *) _ar=1 ;; esac
    caps_write "$_ar"
}

# 落一份 caps (schema 2)。自愈那一步要单独改 autoredirect, 所以单独抽出来。
#
# 格式仍是一行一个 key=value (路由器上没有 jq, 用 sed 取就够)。新增的 chosen / covered
# 回答的是"这台机器现在到底走哪条路、覆盖到哪", 而 why.* 回答"别的路为什么不行" ——
# 安装输出、CLI、agent 上报、面板显示读的都是这一份, 不允许各处各写一遍。
# fw / fwgen / pkgmgr / deps_why 是 25.12 那一轮加的: 固件世代决定包管理器与内核模块
# 从哪个源来, deps_why 是"内核模块为什么没装上"的原话 —— doctor 与安装摘要都读它们,
# 于是"这台固件缺什么"不必再靠用户截图去猜。
caps_write() {
    _ar="${1:-1}"
    mkdir -p "$ZP_DIR" 2>/dev/null || true
    _oneline() { printf '%s' "$1" | tr -d '\r\n'; }
    {
        printf 'schema=2\n'
        printf 'fw=%s\n' "$(_oneline "$FW_RELEASE")"
        printf 'fwgen=%s\n' "$(_oneline "$FW_GEN")"
        printf 'pkgmgr=%s\n' "$PKG_MGR"
        printf 'deps_why=%s\n' "$(_oneline "$DEPS_FAILED")"
        # BTF: 内核类型信息 (eBPF 性能档的前提)。how = kernel(自带) / detached(以前补的) /
        # feed(软件源补的) / panel(面板分发的) —— 面板与 doctor 都读这三个值。
        printf 'btf=%s\n' "$NET_EBPF"
        printf 'btf_how=%s\n' "$BTF_HOW"
        printf 'btf_path=%s\n' "$(_oneline "$BTF_PATH")"
        printf 'why.btf=%s\n' "$(_oneline "$BTF_WHY")"
        # 性能模式 (eBPF / dae): cap=能不能进 (装机时探的), perf=现在是不是在用它,
        # why=为什么进不去 (或为什么退回来了)。界面上的那个开关读的就是这三个。
        printf 'perf_cap=%s\n' "${PERF_CAP:-0}"
        printf 'perf=%s\n' "$(_perf_flag)"
        printf 'perf_why=%s\n' "$(_oneline "$(perf_why_now)")"
        printf 'tun=%s\n' "$NET_TUN"
        printf 'nft=%s\n' "$NET_NFT"
        printf 'tproxy=%s\n' "$NET_TPROXY"
        printf 'redirect=%s\n' "$NET_REDIRECT"
        printf 'ebpf=%s\n' "$NET_EBPF"
        printf 'ipv6=%s\n' "$NET_IPV6"
        printf 'wan_mtu=%s\n' "$WAN_MTU"
        printf 'tun_mtu=%s\n' "$TUN_MTU"
        printf 'offload=%s\n' "$NET_OFFLOAD"
        printf 'autoredirect=%s\n' "$_ar"
        printf 'chosen=%s\n' "${DATAPATH:-none}"
        printf 'covered=%s\n' "${COVERED:-none}"
        printf 'why.tun=%s\n' "$(_oneline "$CAPS_WHY_TUN")"
        printf 'why.tproxy=%s\n' "$(_oneline "$CAPS_WHY_TPROXY")"
        printf 'why.redirect=%s\n' "$(_oneline "$CAPS_WHY_REDIRECT")"
        printf 'why.ebpf=%s\n' "$(_oneline "$CAPS_WHY_EBPF")"
        printf 'why.ipv6=%s\n' "$(_oneline "$CAPS_WHY_IPV6")"
    } > "$ZP_DIR/caps"
}

# 换一级数据面: 设 DATAPATH / COVERED 并落进 caps。**"哪一级覆盖到哪"只有这一处映射** ——
# 安装输出、CLI、agent 上报、面板显示都从 caps 读, 不允许各处各写一遍。
set_datapath() {
    case "$1" in
        tun)      DATAPATH="tun"; COVERED="full" ;;
        tproxy)   DATAPATH="tproxy"; COVERED="lan" ;;
        redirect) DATAPATH="redirect"; COVERED="lan_tcp" ;;
        # 性能模式 (eBPF / dae): 核心里分流, 局域网与路由器自身都接管 —— 覆盖是 full,
        # 但它**不是 mihomo 的一档** (进去时 mihomo 是停着的, 见 perf.sh)。
        ebpf)     DATAPATH="ebpf"; COVERED="full" ;;
        *)        DATAPATH="none"; COVERED="none" ;;
    esac
    # IPv6 能力是"选中哪一级"的函数 (tun 天然能覆盖 v6, redirect 要看有没有 ip6tables),
    # 所以跟着一起算、一起落盘 —— 降级换级时它也会跟着重算。
    compute_ipv6_cap
    write_caps
}

# 从已探到的能力里挑一级 (顺序即优先级)。注意"探到"不等于"起得来" —— 8.45 那台机器
# 探测说 TUN 可用, 实际建不出设备, 所以 verify() 还会再验一次并按阶梯往下降。
choose_datapath() {
    # 性能模式在用的时候, "选哪一级"这个问题已经由 dae 回答了 (而且是用户点的) —— 重跑
    # 安装命令 (= 升级客户端) 不该把它悄悄换回 tun。
    if [ "$(_perf_flag)" = "1" ]; then set_datapath ebpf
    elif [ "$NET_TUN" = "1" ]; then set_datapath tun
    elif [ "$NET_TPROXY" = "1" ]; then set_datapath tproxy
    elif [ "$NET_REDIRECT" = "1" ]; then set_datapath redirect
    else set_datapath none
    fi
}

# 这一级的能力探测过了没有 (verify 降级时只试探通的级)
rung_usable() {
    case "$1" in
        tun)      [ "$NET_TUN" = "1" ] ;;
        tproxy)   [ "$NET_TPROXY" = "1" ] ;;
        redirect) [ "$NET_REDIRECT" = "1" ] ;;
        *)        return 1 ;;
    esac
}

# 阶梯上排在某一级后面的几级 (从优到劣)
ladder_below() {
    case "$1" in
        tun)    printf '%s\n' tproxy redirect ;;
        tproxy) printf '%s\n' redirect ;;
        *)      : ;;
    esac
}

install_deps() {
    step "探测网络数据面能力"
    # 软件源不可用 / 源对不上内核, 在路由器上都很常见, 不算致命 —— 模块可能本来就在。
    # 但**为什么装不上要说出来**: 25.12 的内核模块来自"与内核版本绑定"的那个源
    # (.../kmods/<内核版本>-<构建哈希>/), 厂商固件的内核与它对不上时, 这条记录是唯一
    # 能解释"模块怎么都装不上"的现场证据。
    if [ "$PKG_MGR" = "none" ]; then
        note "本机没有包管理器 (${PKG_MGR_NOTE:-apk / opkg 都不在}) —— 缺的内核模块只能手动补"
    elif [ "$PKG_MGR" = "opkg" ]; then
        # opkg 要"先更新索引再装"两条命令; apk 那边不需要 —— `apk -U add` 自己会刷新
        # (官方 cheatsheet 就是拿它替代 `opkg update && opkg install` 那两条的),
        # 少一次索引往返在慢线路上是实打实的时间。
        pkg_update || true
    fi
    # 装包失败先记在手边, **等探测完了再决定要不要报** —— 模块本来就在 (或已编进内核) 时,
    # "apk add 没成功"是无关紧要的 (源离线 / 架构的 kmod 不在源里都可能), 说出来只会吓人。
    if pkg_install kmod-tun; then _tun_why=""; else _tun_why="$DEPS_WHY"; fi
    modprobe tun 2>/dev/null || true

    # 每一级都真做一次。探测只做可撤销的动作 (建设备再删 / 加规则再撤), 不改任何东西。
    if tun_ok; then NET_TUN=1; else
        CAPS_WHY_TUN="$PROBE_WHY"
        # 这一级真的不行、而包也没装上 → 这条记录才有意义 (它就是根因)
        [ -z "$_tun_why" ] || deps_fail kmod-tun "$_tun_why"
    fi
    if nft_ok; then NET_NFT=1; else CAPS_WHY_TPROXY="$PROBE_WHY"; fi
    if [ "$NET_NFT" = "1" ]; then
        if tproxy_ok; then
            NET_TPROXY=1
        else
            CAPS_WHY_TPROXY="$PROBE_WHY"
            # 模块可能只是没装/没加载: 补一次再试 (装不上就算了, 不算致命)
            if pkg_install kmod-nft-tproxy; then _tp_why=""; else _tp_why="$DEPS_WHY"; fi
            modprobe nft_tproxy 2>/dev/null || true
            if tproxy_ok; then
                NET_TPROXY=1; CAPS_WHY_TPROXY=""
            else
                [ -z "$_tp_why" ] || deps_fail kmod-nft-tproxy "$_tp_why"
            fi
        fi
    fi
    if redirect_ok; then NET_REDIRECT=1; else CAPS_WHY_REDIRECT="$PROBE_WHY"; fi
    # eBPF 那一档的前提是"内核 BTF (CO-RE 类型信息)" —— 缺了就**自动补** (社区有现成包,
    # 见 btf_ensure 顶部): 先问本机软件源, 再问面板, 两个都拿不到就把原因说清楚。
    btf_ensure || true
    if ebpf_ok; then NET_EBPF=1; else CAPS_WHY_EBPF="$PROBE_WHY"; fi
    # 性能模式 (eBPF / dae) 能不能进 —— 只看 eBPF 那一档的前提是否齐; 真正的切换在
    # `zeroproxy perf on` (点界面上的按钮) 时做, 这里只探能力。
    perf_cap_probe

    # 性能模式**正在用**的时候, 上面那几探探的是"数据面已被 dae 接着的机器", 结论不可用 ——
    # 真机上三条全报不通, 然后摘要给出"TUN 都用不了, 去补内核模块 / 换固件"这种误诊
    # (用户会截图当成故障)。所以这里把 caps 里**上一次空机探测**的能力位回填回去:
    # 那些值才代表这台机器的底子, 而"现在走哪一档"由 chosen=ebpf 说话 (8.87)。
    if [ "$(_perf_flag)" = "1" ]; then
        note "性能模式正在用 (内核态 eBPF): 标准模式那三级的探测这次不采信, 沿用上次的记录"
        for _f in tun nft tproxy redirect ebpf; do
            _old="$(sed -n "s/^$_f=//p" "$ZP_DIR/caps" 2>/dev/null | head -n1)"
            [ -n "$_old" ] || continue
            case "$_f" in
                tun)      NET_TUN="$_old" ;;
                nft)      NET_NFT="$_old" ;;
                tproxy)   NET_TPROXY="$_old" ;;
                redirect) NET_REDIRECT="$_old" ;;
                ebpf)     NET_EBPF="$_old" ;;
            esac
        done
        for _l in tun tproxy redirect; do
            _ow="$(sed -n "s/^why.$_l=//p" "$ZP_DIR/caps" 2>/dev/null | head -n1)"
            case "$_l" in
                tun)      CAPS_WHY_TUN="$_ow" ;;
                tproxy)   CAPS_WHY_TPROXY="$_ow" ;;
                redirect) CAPS_WHY_REDIRECT="$_ow" ;;
            esac
        done
    fi

    # WAN 的 MTU 与转发卸载 (性能那一半: 大包别死在路上 / 别让卸载把代理绕过去)。
    # **必须在 choose_datapath 之前算完**: choose_datapath → set_datapath → write_caps,
    # 那一刻就把 caps 写死了。放在它后面算, 值算出来了却没人再写一次 —— 真机上表现为
    # caps 里 `wan_mtu=` 是空的、`offload=0`, 而安装输出明明说"转发卸载开着"。
    compute_tun_mtu
    NET_OFFLOAD="$(offload_state)"
    # 选中哪一级, 并把 chosen / covered / ipv6 / wan_mtu / tun_mtu / offload / why.* 一起
    # 落进 caps (全链路共用这一份)
    choose_datapath

    case "$DATAPATH" in
        tun)
            ok "数据面: TUN (全屋设备 + 路由器自身)"
            # 用不到的那几级: 只说一句说明, 不用警告 —— 那是"少一条用不到的回退", 不是问题。
            if [ "$NET_TPROXY" = "0" ]; then
                if [ "$NET_NFT" = "0" ]; then
                    note "tproxy 回退不可用 (内核里没有 nf_tables) —— TUN 模式下用不到它"
                else
                    note "tproxy 回退不可用 (内核 / 软件源里没有 nft_tproxy) —— TUN 模式下用不到它, 不影响任何功能"
                fi
            fi
            ;;
        tproxy)
            ok "数据面: tproxy (全屋设备; 路由器自身流量除外)"
            note "本机建不出 TUN 设备: ${CAPS_WHY_TUN:-未知原因}"
            ;;
        redirect)
            ok "数据面: iptables REDIRECT (局域网 TCP)"
            note "这台固件没有 nf_tables、也建不出 tun —— 用最老也最抗造的一条路接管局域网"
            if [ -n "$CAPS_WHY_TUN" ]; then note "tun 不可用: $CAPS_WHY_TUN"; fi
            if [ -n "$CAPS_WHY_TPROXY" ]; then note "tproxy 不可用: $CAPS_WHY_TPROXY"; fi
            ;;
        ebpf)
            # 性能模式 (dae) 就是这一档: 它不是 mihomo 的一级, 但它**在接管** ——
            # 以前这里没有这一支, 于是性能模式正常工作时反而落进下面那个"三条路都不通"
            # 的分支, 报出一句误诊 (真机上用户截了图, 8.87)。
            ok "数据面: 内核态 eBPF (dae) —— 性能模式正在用, 局域网与路由器自身都由它接管"
            note "标准模式那三级 (TUN / tproxy / redirect) 的判定要等熄火之后再跑安装命令才准"
            ;;
        *)
            DEPENDENCY_NOTE="no-datapath"
            warn "TUN / tproxy / iptables REDIRECT 三条路都没探通 —— 全屋透明代理这次不会生效"
            if [ -n "$CAPS_WHY_TUN" ]; then note "tun: $CAPS_WHY_TUN"; fi
            if [ -n "$CAPS_WHY_TPROXY" ]; then note "tproxy: $CAPS_WHY_TPROXY"; fi
            if [ -n "$CAPS_WHY_REDIRECT" ]; then note "redirect: $CAPS_WHY_REDIRECT"; fi
            # 三条路都没通, 而内核模块又没装成 —— 那就是根因, 原话摆出来 (结尾还会给命令)
            if [ -n "$DEPS_FAILED" ]; then
                note "内核模块没装上: $DEPS_FAILED"
                # 就在看到"未生效"的同一屏里给出这台机器能用的那条命令 —— 用户要截图时
                # 这一行才是能被照着执行的东西。
                note "  补装: $(deps_hint)"
            fi
            note "本机的代理端口一直可用 (局域网设备手动把代理填成 $(lan_ip):$ZP_MIXED)"
            ;;
    esac
    if [ "$NET_EBPF" = "1" ]; then
        note "eBPF 性能档前提就绪: $(ebpf_detail)"
        note "  数据面仍是 ${DATAPATH:-当前这一档}; eBPF 那一档 (直连旁路) 留给后续版本 (设计文档 Phase 3)"
    else
        note "eBPF 性能档不可用: $(ebpf_detail)"
        # 把影响面说清楚: 这句话长得像"装坏了", 而它其实只关系到未来的性能模式。
        note "  这一档只影响未来的「直连旁路」性能模式 —— 当前的 ${DATAPATH:-数据面} 不受影响"
    fi
    # 性能模式 (eBPF / dae) 一句话: 能不能开。开关在面板 / 本机界面上, 装机这一步只报告
    # 这台机器有没有那个底子 —— 免得用户找了一圈才发现"这台固件根本开不了"。
    if [ "${PERF_CAP:-0}" = "1" ]; then
        note "性能模式: 可以开 (内核态 eBPF / dae) —— 面板与本机界面上那个开关一键切换"
    else
        note "性能模式: 这台机器开不了 (${PERF_WHY:-内核条件不满足})"
    fi
    if [ -n "$WAN_MTU" ] && [ "$TUN_MTU" != "1500" ]; then
        note "WAN 的 MTU 是 $WAN_MTU (PPPoE?), tun 按 $TUN_MTU 收包 —— 免得封装之后成超包"
    fi
    if [ "$NET_OFFLOAD" = "1" ]; then
        if [ "$DATAPATH" = "tun" ]; then
            note "转发卸载开着 (flow offloading / HNAT) —— tun 这一档走路由, 不受它影响"
        else
            note "转发卸载开着: 它会绕过 netfilter, 而当前这一档 ($DATAPATH) 的代理规则就在那里"
            note "  → 已建立的连接可能直接走 WAN 而不经代理; 要稳就把 flow offloading 关掉"
        fi
    fi
    if [ "$NET_IPV6" = "1" ]; then
        note "IPv6 一并接管 (局域网设备的 v6 流量也走代理, 不会漏出去)"
    else
        note "IPv6 未接管: ${CAPS_WHY_IPV6:-这一档数据面覆盖不到 v6}"
        note "  这台机器上, 局域网设备的 IPv6 会直接出去 —— 面板上也会这么标"
    fi
    # 兜底再写一次: 上面任何一步新加的探测值都在这一下落地。**顺序错了也不会静默丢值**
    # —— 真机上吃过一次亏 (算完没落盘, caps 里空着, 而输出里是对的)。
    write_caps
}

# ---------------------------------------------------------------- 内核二进制
#: 面板说"还没准备好内核"时最多等多久 (秒)。面板侧取内核的总时限是 240 秒
#: (ZP_CORE_DEADLINE) —— 这里必须比它长, 否则两边一起超时、谁都不知道到底怎么了;
#: 但不无限等: 到点就把话说清楚, 而不是让用户对着一行不动的输出猜。
CORE_WAIT="${ZP_CORE_WAIT:-360}"
#: 小于这个大小的一律不当内核 —— 面板的 502/503 正文只有几十到几百字节, 而一个
#: 正常的 mihomo 压缩包 ≈ 20 MB。(自检演练里用几 KB 的假内核, 那时调小这个值。)
CORE_MIN_BYTES="${ZP_CORE_MIN_BYTES:-65536}"
#: 面板直传的观察窗口 (秒)。国内家宽到海外面板常常只有几十 KB/s —— 20 MB 要十几分钟,
#: 而面板会把**它自己那张镜像表 + 官方直链**一起给出来 (见 /c/core/status), 直连往往
#: 快得多。超过这个窗口还没下完, 就让位给直连镜像。设 0 = 不看这个窗口, 一直等面板。
CORE_PANEL_BUDGET="${ZP_CORE_PANEL_BUDGET:-90}"
#: 每条直连镜像最多花多久 (秒)。
CORE_MIRROR_BUDGET="${ZP_CORE_MIRROR_BUDGET:-240}"
#: 整轮取内核的总上限 (秒): 面板 + 全部镜像加起来, 到点就报清楚。
CORE_TOTAL_BUDGET="${ZP_CORE_TOTAL_BUDGET:-900}"

#: 面板给来的这一档内核的元信息 (core_read_panel 填)
PANEL_DIRECT=""
PANEL_MIRRORS=""
PANEL_SHA=""
PANEL_SIZE=""
PANEL_PREFER="panel"
PANEL_CORE_VERSION=""
#: 面板最近一次状态回执的原文 (进度显示用)
PANEL_STATUS_JSON=""
#: 最近一次下载的实测结果 (core_download 填)
DL_BYTES=0
DL_KBPS=0
DL_SECONDS=1
#: 这一轮取内核的开始时间 (总预算用)
CORE_STARTED=0

# 整轮取内核还剩多少秒 (面板 + 全部镜像共用这一个预算)。
core_budget_left() {
    _now="$(date +%s 2>/dev/null || echo "$CORE_STARTED")"
    _left=$((CORE_TOTAL_BUDGET - (_now - CORE_STARTED)))
    if [ "$_left" -lt 0 ]; then _left=0; fi
    printf '%s\n' "$_left"
}

#: 速率闸门的观察窗口 (秒): 低于闸门持续这么久才掐断, 免得被几秒钟的抖动误伤。
CORE_RATE_WINDOW="${ZP_CORE_RATE_WINDOW:-25}"

# 这一条路"能不能在预算内跑完"的最低速率 (KB/s)。面板知道文件多大时, 它就是
# 大小/预算 —— 低于它意味着**数学上跑不完**, 那就不该把整段预算耗在这条路上
# (真机: 面板直传 63 KB/s, 预算 90 秒 → 20 MB 需要 5 分钟, 90 秒纯属白等, 而直连
# 镜像 931 KB/s)。不知道大小时退回一个保守值: 20 MB 在这个速度下也要七分钟, 同样跑不完。
core_min_rate() {
    _sec="${1:-240}"
    [ "$_sec" -gt 0 ] 2>/dev/null || _sec=1
    if [ -n "$PANEL_SIZE" ] && [ "$PANEL_SIZE" -gt 0 ] 2>/dev/null; then
        _r=$((PANEL_SIZE / 1024 / _sec))
        [ "$_r" -ge 8 ] || _r=8
        printf '%s\n' "$_r"
    else
        printf '48\n'
    fi
}

# 下载一份文件到 $2, 最多花 $3 秒 (可选的 $4 = 最低速率 KB/s), 带进度与实测速率。
# 成功返回 0。速率是给"这条线值不值得等"用的 —— 以前这里只有一行不动的输出,
# 用户分不出"慢"和"死"。
core_download() {
    rm -f "$2"
    DL_START="$(date +%s 2>/dev/null || echo 0)"
    # 面板给了大小就画带百分比的条; 没给 (老面板) 就退回每 5 秒一行 —— 两种都比"不动"强。
    start_progress "$2" "已下载" "${PANEL_SIZE:-0}"
    if http_fetch_to "$1" "$2" "${3:-900}" "${4:-0}" "$CORE_RATE_WINDOW"; then
        _rc=0
    else
        _rc=1
    fi
    stop_progress
    DL_SECONDS=$(( $(date +%s 2>/dev/null || echo 0) - DL_START ))
    [ "$DL_SECONDS" -gt 0 ] 2>/dev/null || DL_SECONDS=1
    # 文件可能压根没建起来 (连都没连上) —— 那是**重定向**失败, 那句 "No such file" 由
    # shell 自己打到 stderr, `2>/dev/null` 挡不住 (与 start_progress 里同一条规矩)。
    if [ -f "$2" ]; then
        DL_BYTES="$(wc -c < "$2" 2>/dev/null | tr -d ' ' || true)"
    else
        DL_BYTES=0
    fi
    [ -n "$DL_BYTES" ] || DL_BYTES=0
    DL_KBPS=$((DL_BYTES / 1024 / DL_SECONDS))
    return "$_rc"
}

# 问面板要这一档内核的元信息: 官方直链 / 面板同款镜像表 / 期望大小 / sha256 / 建议顺序。
# 旧面板没有这些字段 —— 那就退回"只有面板直传"的老路, 不影响安装。
core_read_panel() {
    PANEL_STATUS_JSON="$(http_get "$ZP_BASE/c/core/status?arch=$ARCH" 2>/dev/null || true)"
    _json="$PANEL_STATUS_JSON"
    PANEL_DIRECT="$(json_get "$_json" direct)"
    PANEL_MIRRORS="$(json_get "$_json" mirror_urls)"
    PANEL_SHA="$(json_get "$_json" sha256)"
    PANEL_SIZE="$(json_get_num "$_json" size)"
    PANEL_PREFER="$(json_get "$_json" prefer)"
    [ -n "$PANEL_PREFER" ] || PANEL_PREFER="panel"
    # 面板要的那一版内核 —— 用来判断本机这份是不是该换了 (见 install_core)
    PANEL_CORE_VERSION="$(json_get "$_json" core_version)"
    # 分流数据库的元信息 (见 install_geo)。老面板没有这两个字段 —— 那时它们为空,
    # install_geo 自动退回"只走面板"的老路。
    PANEL_GEO_SIZES="$(json_get "$_json" geo_sizes)"
    PANEL_GEO_MIRRORS="$(json_get "$_json" geo_mirrors)"
}

# 本机内核是不是面板要的那一版。**只看"能不能跑"是不够的**: 面板把 CORE_VERSION 抬上去
# 之后, 已装好的路由器会一直用着老内核 (它跑得起来, 于是永远不换)。
# 面板版本较旧、没给这个字段时按"一致"处理 —— 行为与本改动之前完全相同。
core_version_ok() {
    [ -n "$PANEL_CORE_VERSION" ] || return 0
    case "$("$ZP_BIN" -v 2>/dev/null | head -n1)" in
        *"$PANEL_CORE_VERSION"*) return 0 ;;
    esac
    return 1
}

# 落盘前的校验: 大小像内核, 且 (面板给了摘要时) sha256 对得上。
# 为什么还要哈希: 直连镜像是第三方 —— 它们中间任何一跳都可能给你别的东西。
core_verify() {
    if [ -f "$_tmp" ]; then
        _size="$(wc -c < "$_tmp" 2>/dev/null | tr -d ' ' || true)"
    else
        _size=0
    fi
    if [ "${_size:-0}" -lt "$CORE_MIN_BYTES" ]; then
        return 1
    fi
    # 面板知道这份文件多大时先比大小: 传了一半的正文过不了这一关, 而且这句
    # "期望多少 / 拿到多少"比一句 sha256 对不上好懂得多 (busybox 上也不一定
    # 有 sha256sum)。
    if [ -n "$PANEL_SIZE" ] && [ "$PANEL_SIZE" -gt 0 ] && [ "${_size:-0}" -ne "$PANEL_SIZE" ]; then
        warn "下载到的文件大小不对: 期望 ${PANEL_SIZE} 字节, 拿到 ${_size} 字节 (丢弃重来)"
        rm -f "$_tmp"
        return 1
    fi
    if [ -n "$PANEL_SHA" ] && command -v sha256sum >/dev/null 2>&1; then
        _sum="$(sha256sum "$_tmp" 2>/dev/null | cut -d' ' -f1)"
        if [ "$_sum" != "$PANEL_SHA" ]; then
            warn "下载到的文件 sha256 与面板给的不一致 (镜像这一跳不干净?), 丢弃重来"
            rm -f "$_tmp"
            return 1
        fi
    fi
    return 0
}

# 等面板把内核取回来时, 拿面板的真实进度说一句人话 (而不是干等)。
core_wait_note() {
    _b="$(json_get_num "$PANEL_STATUS_JSON" bytes)"
    [ -n "$_b" ] || _b=0
    _mb=$((_b / 1048576))
    if [ "$_mb" -gt 0 ]; then
        printf '\r  面板正在取内核… 已取 %s MB   ' "$_mb"
    else
        printf '\r  面板正在取内核…            '
    fi
}

# 面板直传。面板没缓存时它会回 503 + 一句人话 (它自己去上游取), 这里带着进度等;
# 拿到 200 之后如果传得太慢 (预算内没下完), 让位给直连镜像。
core_from_panel() {
    _waited=0
    _conn_fail=0
    while [ "$_waited" -lt "$CORE_WAIT" ]; do
        _min="$(core_min_rate "$CORE_PANEL_BUDGET")"
        if core_download "$ZP_BASE/c/bin/$ARCH" "$_tmp" "$CORE_PANEL_BUDGET" "$_min"; then
            if core_verify; then
                ok "面板直传完成 ($((DL_BYTES / 1048576)) MB, ${DL_KBPS} KB/s)"
                return 0
            fi
            # 下完了但校验没过 (原因 core_verify 已经说过): 换条路
            warn "面板给的这份没通过校验, 换条路再试"
            return 1
        fi
        if [ -f "$_tmp" ]; then
            _size="$(wc -c < "$_tmp" 2>/dev/null | tr -d ' ' || true)"
        else
            _size=0
        fi
        [ -n "$_size" ] || _size=0
        # 200 = 拿到了正文却没下完 (线太慢或中途断) → 换条路;
        # 503/502/000 = 面板给的是一句话 → 按那句话处理 (等待或报错)。
        # uclient-fetch 拿不到状态码, 那时才用"文件大小像不像内核"兜底。
        if [ "$HTTP_CODE" = "200" ] || [ "$_size" -ge 262144 ]; then
            # 下了一半就断了 / 太慢被掐断 / 到预算: 面板这条线要么慢、要么不稳, 换条路。
            # 说"用了多久"而不是"没能在 N 秒内完成" —— 被速率闸门掐断时那句会自相矛盾。
            warn "面板直传太慢 (${DL_SECONDS} 秒只下到 $((_size / 1024)) KB, ${DL_KBPS} KB/s) —— 换直连镜像"
            return 1
        fi
        # 一个字节都没拿到 (文件根本没建起来) = **连都没连上** (丢包 / 超时), 不是
        # "面板给了一句话"。这一档以前会掉进下面那个「面板还在准备, 等它」的分支: 真机
        # (GL-MT3000 到面板的线路丢包) 上就表现为每 5 秒刷一行 `can't open …: no such file`,
        # 一直等到 CORE_WAIT (360 秒) —— 既不换路, 也没说清在等什么。它该按"这条路这次不通"
        # 处理: 立刻让位给直连镜像 (镜像表里不止一个地址, 那边有自己的重试)。
        if [ "$_size" = "0" ]; then
            # 一次 0 字节可能是丢包打个嗝, 再给它一次机会 (但不按"面板在准备"那样长等);
            # 连着两次就是这条路这次不通 —— 换直连镜像, 别耗 CORE_WAIT。
            _conn_fail=$((_conn_fail + 1))
            if [ "$_conn_fail" -ge 2 ]; then
                warn "面板直传连不上 (${_conn_fail} 次 0 字节, ${DL_KBPS} KB/s) —— 换直连镜像"
                return 1
            fi
            warn "面板直传没连上 (${DL_SECONDS} 秒 0 字节), 再试一次…"
            sleep 2
            continue
        fi
        # 不是内核 = 面板给了一句话 (503 正在准备 / 502 取不到)
        _body="$(cat "$_tmp" 2>/dev/null || true)"
        if [ -n "$_body" ]; then
            show_body "$_tmp"
        fi
        case "$_body" in
            *取内核失败*)
                warn "面板自己取不到这份内核 (它到上游的线路不通)"
                return 1 ;;
        esac
        _waited=$((_waited + 5))
        if [ "$_waited" -ge "$CORE_WAIT" ]; then
            warn "等了 ${CORE_WAIT} 秒, 面板还是没把内核准备好"
            return 1
        fi
        core_read_panel            # 刷新进度与摘要 (面板可能刚好取好了)
        core_wait_note
        sleep 5
    done
    return 1
}

# 直连镜像 (面板把整张表 + 官方直链一起给出来)。只在面板那条路太慢或走不通时才用。
core_from_mirrors() {
    if [ -z "$PANEL_MIRRORS" ] && [ -z "$PANEL_DIRECT" ]; then
        warn "面板没有给出直连镜像 (面板版本较旧?), 只能走面板直传"
        return 1
    fi
    warn "改走直连镜像 (与面板同一份文件, 校验方式不变)"
    for _url in $(printf '%s' "$PANEL_MIRRORS" | tr ',' ' '); do
        [ -n "$_url" ] || continue
        _left="$(core_budget_left)"
        if [ "$_left" -le 5 ]; then
            warn "总时间预算用完了 (${CORE_TOTAL_BUDGET} 秒), 不再试剩下的镜像"
            break
        fi
        _tmo="$CORE_MIRROR_BUDGET"
        [ "$_left" -lt "$_tmo" ] && _tmo="$_left"
        _min="$(core_min_rate "$_tmo")"
        if core_download "$_url" "$_tmp" "$_tmo" "$_min" && core_verify; then
            ok "直连镜像完成 ($((DL_BYTES / 1048576)) MB, ${DL_KBPS} KB/s)"
            return 0
        fi
        warn "这个镜像没成: $(printf '%s' "$_url" | sed -e 's#^[a-z]*://##' -e 's#/.*##') (${DL_KBPS} KB/s)"
    done
    return 1
}

install_core() {
    step "下载代理内核 (mihomo · $ARCH)"
    # 清掉上一次中断留下的半截下载: 路由器闪存很小, 20 MB 的临时文件不该长期躺着
    # (.geo-*.part 是分流数据库的; 中断后重跑会重新下, 旧的没必要留着占地方)
    rm -f "$ZP_DIR/.mihomo.gz" "$ZP_DIR"/*.new "$ZP_DIR"/.geo-*.part 2>/dev/null || true
    # 复用旧文件前必须确认它真的跑得起来: 上一次失败可能留下一个没解开的 gz
    # (chmod 是成功的, 只看 -x 会以为装好了, 于是每次重跑都在同一个地方再挂一次)。
    # (预检那边算空间用的是同一个判据, 见 core_reusable。)
    #
    # 但"跑得起来"还不够 —— **还要和面板要的那一版一致**。旧版只看能不能跑, 于是面板把
    # CORE_VERSION 抬上去之后 (安全修复 / 字段变更), 已经装好的路由器会一直用着老内核:
    # 它跑得起来, 于是永远不换。真机上排查内核问题时才发现这条。
    CORE_STARTED="$(date +%s 2>/dev/null || echo 0)"
    core_read_panel
    if core_reusable && core_version_ok; then
        ok "内核已存在且可执行 (版本 $PANEL_CORE_VERSION), 跳过下载"
        return 0
    fi
    if core_reusable; then
        note "本机内核是 $(err_line "$("$ZP_BIN" -v 2>/dev/null | head -n1)"), 面板要的是 $PANEL_CORE_VERSION —— 换一版"
    fi
    rm -f "$ZP_BIN"
    _tmp="$ZP_DIR/.mihomo.gz"
    mkdir -p "$ZP_DIR"

    # 取内核两条路: ① 面板直传 (面板把内核缓存好再给, 只访问一个地址);
    #              ② 直连镜像 (面板把它自己那张镜像表 + 官方直链一起给出来)。
    # 默认先走 ① —— 但国内家宽到面板可能只有几十 KB/s, 而直连镜像往往快得多,
    # 所以 ① 有一个观察窗口 (CORE_PANEL_BUDGET), 太慢就让位给 ②。
    # 面板说 prefer=mirror (ZP_ROUTER_SOURCE) 时顺序反过来。
    _ok=0
    if [ "$PANEL_PREFER" = "mirror" ]; then
        warn "面板建议先走直连镜像 (ZP_ROUTER_SOURCE=mirror)"
        if core_from_mirrors; then _ok=1; fi
        if [ "$_ok" = "0" ]; then
            step "改回面板直传"
            if core_from_panel; then _ok=1; fi
        fi
    else
        if core_from_panel; then
            _ok=1
        else
            if core_from_mirrors; then _ok=1; fi
        fi
    fi
    if [ "$_ok" = "0" ]; then
        die "内核下载失败: 面板直传与直连镜像都没成 (共用了 $(core_budget_left) 秒的预算)。
  下一步任选一条:
    1) 到面板「客户端」页面点一次「准备内核」, 看它给出的失败原因 (面板侧可以换镜像:
       ZP_CORE_MIRRORS=https://你的镜像/{url} 后重启面板);
    2) 或把内核压缩包手动放进面板的 data/client/cores/ (文件名在该页面写着);
    3) 过几分钟重跑这条安装命令 —— 面板取到一次就会一直缓存, 之后所有路由器复用。"
    fi
    [ -s "$_tmp" ] || die "下载到的内核是空文件"
    # 判断"是不是 gzip"只能用 gzip -t, 不能用 `od -An -tx1` 看魔数 ——
    # OpenWrt 的 busybox 默认不带 od, 命令不存在时那一行会静默失败, 于是 gz 被当成
    # 二进制直接 chmod +x, 直到"无法执行"才暴露 (2.7.0 上线后的真机反馈)。
    if gzip -t "$_tmp" >/dev/null 2>&1; then
        gzip -dc "$_tmp" > "$ZP_BIN" || die "解压内核失败 (下载到的文件可能不完整, 请重试)"
    else
        cp "$_tmp" "$ZP_BIN"     # 面板直接给了未压缩的二进制
    fi
    rm -f "$_tmp"
    chmod 755 "$ZP_BIN"
    if ! "$ZP_BIN" -v >/dev/null 2>&1; then
        _size="$(wc -c < "$ZP_BIN" 2>/dev/null | tr -d ' ')"
        die "内核无法执行: $ZP_BIN (${_size:-?} 字节)。
  可能原因: 架构不匹配 ($ARCH) / 下载不完整 / 闪存空间不足 / 缺动态库。
  请把这一行连同 'uname -m' 的输出一起发回面板。"
    fi
    ok "内核就绪: $("$ZP_BIN" -v 2>/dev/null | head -n1)"
}

# ---------------------------------------------------------------- 配置
fetch_config() {
    _dest="${1:-$ZP_CONF}"
    _tmp="$_dest.new"
    # 配置怎么生成只有一份实现: agent 的 `config` 模式 (单服务器用面板给的整份配置,
    # 多服务器用骨架 + 本地挂 provider)。安装脚本不再自己拼配置, 免得两处走偏。
    # stderr **放行** (不再 2>/dev/null): agent 重试时那句"面板第 N 次没回话"要能落到更新
    # 日志里 —— 卡在这一步时用户至少看得见它在重试, 而不是一条不动的进度条。
    #
    # 退出码要**先接住**再判断 (`if ! cmd` 的 `$?` 是取反之后的结果, 永远是 0)。
    _cfg_try=0
    while :; do
        _cfg_try=$((_cfg_try + 1))
        "$ZP_DIR/agent.sh" config > "$_tmp"
        _cfg_rc=$?
        # 内容不像一份配置 (空的 / 没有策略组) 也算"没拿到": 丢包把正文截断成空的时候,
        # 请求本身是成功的 (HTTP 200) —— 只看退出码会漏掉这一种, 然后掉进 config_failure
        # 那句"请回面板确认已有可用节点", 又拿一次丢包去说"面板上没有节点"。
        _cfg_ok=1
        [ "$_cfg_rc" = "0" ] || _cfg_ok=0
        grep -q '^proxy-groups:' "$_tmp" 2>/dev/null || _cfg_ok=0
        [ "$_cfg_ok" != "1" ] || break
        # 被"面板明确拒绝"是定论, 不用再试 (下面按凭据处理); 丢包才值得整轮再来一次。
        # 这一份正文只有十几 KB, 而**整轮**最多再试两次 —— 与其失败让人回面板重生成命令,
        # 不如当场多试 (每一轮内部本来就有 5 次重试, 所以这里只补两轮)。
        [ "$_cfg_rc" != "22" ] || break
        [ "$_cfg_try" -lt 3 ] || break
        rm -f "$_tmp"
        progress_note "拉配置没成 ($(http_why "$_cfg_rc")), 整轮再试一次…"
        sleep 5
    done
    # 失败时要知道**是哪一类**: 真机日志里每次都被写成"链路丢包", 于是两轮排查都在猜。
    _cfg_why="$(http_why "$_cfg_rc")"
    if [ "$_cfg_ok" != "1" ]; then
        rm -f "$_tmp"
        # 只有"面板**明确答复**不接受这台设备"才值得重新配对。区分办法就是 agent 带出来的
        # curl 退出码: 22 = -f 说的 HTTP 层面失败 (403 / 404…) → 面板答了, 而且说不行;
        # 7 / 28 / 其他 = 连不上 / 超时 → **根本没问到**, 重新配对解决不了任何事。
        #
        # 为什么必须分开 (真机 8.68, 21.02 那台): 不分的时候, 四次超时被判成"面板拒绝了
        # 凭据", 脚本于是拿同一个配对码又配了一次 —— 面板上**多出一台设备**, 新凭据随后
        # 又被同一个丢包卡住, 最后丢给用户一句"请回面板确认已有可用节点", 方向全错。
        if [ -n "$ZP_CODE" ] && [ "$_cfg_rc" = "22" ]; then
            # 凭据被拒 (403) 是最"看起来莫名其妙"的失败: 面板上把这台设备移除过, 或者
            # 路由器上留的是另一台面板发的凭据。本地文件看不出问题, 只能真的去拉一次。
            warn "面板明确拒绝了这台设备的凭据 (HTTP 层失败) —— 用本次配对码重新接入"
            step "用本次配对码重新接入"
            if ! do_pair; then
                die "重新接入失败: $PAIR_ERROR
  请回面板「客户端」重新生成一条安装命令, 再在路由器上跑一次。"
            fi
            ok "已重新接入: $DEV_NAME ($DEV_ID)"
            "$ZP_DIR/agent.sh" config > "$_tmp" \
                || die "重新接入后仍然拉不到配置 (这次不是丢包: 面板明确拒绝了新凭据)。
  请回面板「客户端」确认这台设备还在, 并且至少有一个可用节点。"
        elif [ -n "$ZP_CODE" ]; then
            # 措辞很要紧 (8.64): 一开口就说"面板可能拒绝了凭据"会把一次丢包引到"重新配对"
            # 上去。先讲事实, 最后一行留成**能立刻做的事** —— 界面上的"实时行"显示的就是它。
            die "拉取配置失败 —— 面板暂时联系不上 (${_cfg_why})。
  这次**没有改动机器上的任何东西**, 面板上也没有多出设备。
  现在先做这一件: 把上面那条安装命令**再跑一次** —— 凭据本机已经存下了, 重跑不会重复配对。"
        else
            # 更新模式 (没有配对码): 无论如何都不重配, 那会在面板上多出一台设备。
            die "拉取配置失败 —— 面板暂时联系不上 (${_cfg_why})。
  本机**仍在使用原来的配置**, 现有代理不受影响。
  只有在**反复**失败之后, 才需要回面板「客户端」重新生成一条带配对码的安装命令重新接入。
  现在先做这一件: 再点一次「更新客户端」—— 这条路上掉一个包就长这样, 重试一次通常就过了。"
        fi
    fi
    # 单服务器模式带内联 proxies, 多服务器模式带 proxy-providers: 共同锚点是策略组
    grep -q '^proxy-groups:' "$_tmp" || { rm -f "$_tmp"; return 1; }
    mkdir -p "$ZP_DIR/providers"
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
# ---------------------------------------------------------------- 分流数据库
# mihomo 缺 GeoIP / GeoSite 时**不是**跳过那几条规则, 而是整份配置加载失败 —— 它自己
# 会当场去 GitHub 拉, 而路由器装机时还没有任何代理可用。真机 (GL-MT3000) 上就是:
#
#     level=error msg="can't initial GeoIP: can't download MMDB: context deadline exceeded"
#     configuration file /etc/zeroproxy/config.yaml.new test failed
#     安装失败: 拉取/校验配置失败, 请回面板确认已有可用节点
#
# 所以数据由面板分发 (和内核二进制同一条思路): 面板去取上游, 路由器只访问面板一个地址。
# 取不到时**不装死**: 装一份不含 geo 规则的降级配置 (能上网), 面板恢复后 agent 自动换回。
# (agent.sh 里有一个同名函数 —— 两边是不同进程, 判据只能是"这两个文件在不在"。)
geo_ok() { [ -s "$ZP_DIR/geoip.metadb" ] && [ -s "$ZP_DIR/geosite.dat" ]; }

#: 两份数据的文件名 (与面板 GEO_FILES 一一对应; 名字是 mihomo 认死的, 不能改)
GEO_FILE_LIST="geoip.metadb geosite.dat"
#: 单份数据的总预算 (秒)。按面板给的体积算出来的"最低可接受速率"就来自它 ——
#: 低于那个速度说明这份在预算内跑不完, 那就不该把整段预算耗在一条跑不完的路上。
GEO_BUDGET="${ZP_GEO_BUDGET:-180}"

# 面板给的 "geoip.metadb=204800;geosite.dat=2097152" 里取一份的体积下限
geo_size_for() {
    printf '%s' "$PANEL_GEO_SIZES" | tr ';' '\n' | sed -n "s/^$1=//p" | head -n1
}

# 面板给的 "geoip.metadb <url> <url>|geosite.dat <url> <url>" 里取一份的地址表
geo_mirrors_for() {
    printf '%s' "$PANEL_GEO_MIRRORS" | tr '|' '\n' | sed -n "s/^$1 //p" | head -n1
}

# 取一份分流数据库 (先试面板, 太慢就换面板同款的那份镜像表)。
#
# 为什么要给分流数据库也做这一套 —— 它和内核是**同一道坎**, 而原来只有一条路:
#   真机 8.75: 内核那一步"面板直传 47 KB/s"被速率闸门判死, 换镜像后 615 KB/s;
#   而分流数据库当时没有镜像可换, 只能干等 —— 屏幕上就是"卡在准备分流数据库不动"
#   (旧实现还把整段输出丢进了 /dev/null, 连一行 KB 都看不到)。13 倍的差距, 不该只在
#   内核那条路上享受。
geo_fetch_one() {
    # 变量名一律带 _g 前缀: 这个脚本没有 local, 而这些名字会被一遍遍复用 ——
    # 撞名是**静默**的 (真事: show_body 里也写 _size, 于是"面板 404 → 换镜像"这条路上
    # 体积闸门会拿 404 正文的大小去比, 一个残缺文件照样装了进去)。前缀让它撞不上。
    _gname="$1"
    _gtmp="$ZP_DIR/.geo.$_gname.part"
    rm -f "$_gtmp"
    _gneed="$(geo_size_for "$_gname")"
    [ -n "$_gneed" ] || _gneed=1
    # 速率闸门 (与 core_min_rate 同源): 面板知道文件多大, 于是"跑不完"是能算出来的。
    _gmin=$(( _gneed / 1024 / GEO_BUDGET ))
    [ "$_gmin" -ge 8 ] || _gmin=8
    for _gurl in "$ZP_BASE/c/geo/$_gname" $(geo_mirrors_for "$_gname"); do
        [ -n "$_gurl" ] || continue
        start_progress "$_gtmp" "下载 $_gname" "$_gneed"
        _ggot=0
        if http_fetch_to "$_gurl" "$_gtmp" "$GEO_BUDGET" "$_gmin" "$CORE_RATE_WINDOW"; then
            _ggot="$(wc -c < "$_gtmp" 2>/dev/null | tr -d ' ' || true)"
        fi
        stop_progress
        # 体积闸门: 挡 404 页面 / 面板那句"还在准备"的人话 / 下了一半的文件
        if [ "${_ggot:-0}" -ge "$_gneed" ] 2>/dev/null; then
            mv "$_gtmp" "$ZP_DIR/$_gname"
            ok "$_gname 就绪 ($(zp_hsize "$_ggot"))"
            return 0
        fi
        # 有的是**面板写给人看的一句话** (503 正文): 原样带出来, 别让人对着空文件猜
        show_body "$_gtmp"
        rm -f "$_gtmp"
    done
    return 1
}

install_geo() {
    step "准备分流数据库 (GeoIP / GeoSite)"
    _gfail=""
    for _gfile in $GEO_FILE_LIST; do
        geo_fetch_one "$_gfile" || _gfail="$_gfail $_gfile"
    done
    if geo_ok; then
        [ -z "$_gfail" ] || warn "这次没取到$_gfail —— 继续用本机已有的那一份"
        _ggsz="$(wc -c < "$ZP_DIR/geoip.metadb" 2>/dev/null | tr -d ' ' || true)"
        _gssz="$(wc -c < "$ZP_DIR/geosite.dat" 2>/dev/null | tr -d ' ' || true)"
        ok "分流数据库就绪 (geoip $(zp_hsize "${_ggsz:-0}") · geosite $(zp_hsize "${_gssz:-0}"))"
        return 0
    fi
    # 面板明说自己没有这个接口 = 这台面板比客户端旧。这种情况下它的配置一定带 geo 规则,
    # 而这台路由器上没有数据 —— 与其让人对着"拉取/校验配置失败"发呆, 不如当场说清楚。
    # (更新模式没有配对回执, 这里未知 —— 交给 config_failure 收尾。)
    if [ -n "$PANEL_GEO" ] && [ "$PANEL_GEO" != "true" ]; then
        die "这台面板没有提供分流数据库 (它的程序版本比路由器客户端旧)。
  配置里的国内直连 / 广告拦截依赖 GeoIP / GeoSite, 缺了内核起不来, 所以这里停住 ——
  请先在面板上点「程序更新」升级, 再重跑这条安装命令。"
    fi
    # 面板说有, 但这次没取到 (面板自己访问不了上游 / 网络抖动): 先让它能上网。
    warn "这次没取到分流数据库 (面板暂时取不到上游数据?)"
    # 说清楚**少了什么**、**什么还在**: 降级配置少的是靠数据库的那两段 (分类直连 /
    # 广告拦截), 而"国内常用域名"与"落地域名"两层是内联在配置里的, 照样生效 ——
    # 以前那句"不含国内直连"是错的, 会让人以为国内站点全要去绕节点 (真机 8.68 的日志里
    # 就是这么写的, 用户完全没法判断自己现在是什么状态)。
    warn "按降级配置安装: 少了「分类直连」与「广告拦截」两段 (它们要数据库);
  国内常用域名 / 落地域名那两层是内联的, 仍然生效, 其余照常走节点"
    warn "数据到位后这台路由器会自动换回完整分流, 不用再登录路由器"
    DEGRADED="geo"
    return 0
}

# 配置落不下去时给一句对症的话。旧面板是这里最常见的坑: 它给的配置带 geo 规则, 而它
# 没有 /c/geo 接口 —— 路由器只能去 GitHub 拉, 于是表现为"拉取/校验配置失败"。
config_failure() {
    if ! geo_ok; then
        die "配置校验失败: 本机没有分流数据库 (GeoIP / GeoSite)。
  这台面板的程序版本可能比路由器客户端旧 (没有 /c/geo 分流数据接口)。请先在面板上
  点「程序更新」升级到最新版, 再重跑这条安装命令。"
    fi
    # 走到这里只剩两种可能: 面板给的正文用不了 (多是链路丢包把它截断了), 或者面板上确实
    # 没有可用节点。以前只有后一句"请回面板确认已有可用节点" —— 把前者也说成后者, 用户
    # 就会去面板上白找一圈。两种都要说, 并给出能立刻做的那一件事。
    if [ -n "$ZP_CODE" ]; then
        die "拉取/校验配置失败 —— 拿到的东西不是一份可用配置 (${_cfg_why:-没拿到}); 也可能是面板上没有可用节点。
  这次**没有改动机器上已有的东西**。
  现在先做这一件: 把上面那条安装命令**再跑一次**。"
    fi
    die "拉取/校验配置失败 —— 拿到的东西不是一份可用配置 (${_cfg_why:-没拿到}); 也可能是面板上没有可用节点。
  本机**仍在使用原来的配置**, 现有代理不受影响。
  现在先做这一件: 再点一次「更新客户端」。"
}

# 装机前的"地面真相"快照 (防火墙规则 / 策略路由)。`zeroproxy revert` 靠它回答一个具体
# 问题: 停掉内核、拆掉数据面之后, 这台机器**是不是真的**回到了装机前 —— 逐条比对, 而不是
# 靠我们相信自己的拆卸代码。这台机器的每一台都可能不一样 (固件/HNAT/运营商), 所以"原状"
# 只能自己拍。
#
# 只在第一次安装时拍: 重跑安装命令时我们自己的规则可能正在生效, 那时候拍等于把残渣当原状。
snapshot_baseline() {
    _dir="$ZP_DIR/baseline"
    # 判据用 taken_at 而不是某个快照文件的大小: 有些机器上 nft / iptables-save 本来就
    # 输出为空 (没有 nftables), 用大小判会"每次都当成没拍过"。
    [ -f "$_dir/taken_at" ] && return 0
    mkdir -p "$_dir" 2>/dev/null || return 0
    (nft list ruleset 2>/dev/null || true) > "$_dir/nft.txt"
    (iptables-save 2>/dev/null || true) > "$_dir/iptables.txt"
    (ip6tables-save 2>/dev/null || true) > "$_dir/ip6tables.txt"
    (ip rule show 2>/dev/null || true) > "$_dir/ip-rule.txt"
    (ip -6 rule show 2>/dev/null || true) > "$_dir/ip6-rule.txt"
    (date +%s 2>/dev/null || true) > "$_dir/taken_at"
}

# ---------------------------------------------------------------- 运行时装机件
# live.sh / tproxy.nft / redirect.sh / tunfw.sh / perf.sh / agent.sh / cli / 三个 init 脚本
# 以前是**这个脚本用 heredoc 现场捏出来**的 —— 于是每一个都改不动、也单测不了, 而本脚本
# 自己长到 5000 行。现在它们是仓库里版本化的文件 (client/runtime/), 跟着面板分发; 安装脚本
# 只做三件事: 取回来 → 按本机替换占位符 → 落盘。与内核 / 分流数据 / zpcore 完全同一条路
# (路由器只访问面板一个地址)。
#
# 两个占位符: `__ZP_CLIENT_VERSION__` (面板那边已经替过, 这里再替一次兜底) 与
# `__ZP_LANIF__` (局域网接口名 —— 面板看不到, 只能本机算)。
#
# 升级安全: 取不到时**保留本机已有的那一份** (一次失败的请求不许毁掉能用的文件, 8.79);
# 本机也没有 (首次安装) 才 die, 并说清是哪一个。
runtime_put() {  # $1=名字  $2=落盘路径  $3=期望的首字符 ('' = 只要非空)  $4=可执行 (1=是)
    _name="$1"; _dst="$2"; _want="$3"; _exec="$4"
    _tmp="$ZP_DIR/.rt.$$.$_name"
    if http_get "$ZP_BASE/c/rt/$_name" > "$_tmp" && [ -s "$_tmp" ]; then
        # 只替两个占位符: 版本号 (面板那边已经替过, 这里兜底) 与局域网接口名 (机器相关)。
        # 装机件里写的安装目录 (/etc/zeroproxy 那几个) 就是这台机器要用的那一个 —— 不在这里
        # 再改一次。
        sed -e "s/__ZP_CLIENT_VERSION__/$ZP_CLIENT_VERSION/g" \
            -e "s/__ZP_LANIF__/$LAN_IFACE/g" "$_tmp" > "$_tmp.new" 2>/dev/null \
            && mv "$_tmp.new" "$_tmp"
        if [ -z "$_want" ] || [ "$(head -c 1 "$_tmp" 2>/dev/null)" = "$_want" ]; then
            mv "$_tmp" "$_dst"
            if [ "$_exec" = "1" ]; then chmod 755 "$_dst"; else chmod 644 "$_dst"; fi
            return 0
        fi
        warn "装机件 $_name 的内容不像它 (首字符不是 '$_want') —— 不落盘"
    fi
    rm -f "$_tmp" "$_tmp.new"
    # 取不到: 本机已有可用的一份就保留 (升级不许毁掉能用的东西; 8.79 的规矩)
    if [ -s "$_dst" ]; then
        note "面板没给出 $_name —— 保留本机已有的那份"
        return 0
    fi
    die "取不到装机件 $_name ($ZP_BASE/c/rt/$_name 没有回话), 而本机也没有 —— 无法继续"
}

install_runtime() {
    step "落运行时装机件"
    LAN_IFACE="$(lan_iface 2>/dev/null || true)"
    runtime_put live.sh              "$ZP_DIR/live.sh"   '#' 1
    runtime_put tproxy.nft           "$ZP_DIR/tproxy.nft" ''  0
    runtime_put redirect.sh          "$ZP_DIR/redirect.sh" '#' 1
    runtime_put tunfw.sh             "$ZP_DIR/tunfw.sh"   '#' 1
    runtime_put perf.sh              "$ZP_DIR/perf.sh"    '#' 1
    runtime_put agent.sh             "$ZP_DIR/agent.sh"   '#' 1
    runtime_put cli                  "$ZP_CLI"            '#' 1
    runtime_put zeroproxy.init       "$ZP_INIT"           '#' 1
    runtime_put zeroproxy-agent.init "$ZP_AGENT_INIT"     '#' 1
    runtime_put zeroproxy-perf.init  "$ZP_PERF_INIT"      '#' 1
}

write_files() {
    step "写入运行文件"
    mkdir -p "$ZP_DIR"
    # 装机前的"地面真相"快照。`zeroproxy revert` 用它证明"停掉内核即完全恢复原状"是真的,
    # 而不是靠我们相信自己的拆卸代码 —— 拆干净没拆干净, 比对说了算。
    # 只在**规则还没被我们改过**的时候拍 (write_files 早于 verify 落数据面规则); 已经拍过
    # 就不覆盖: 重跑安装时我们自己的规则可能正生效, 那时候拍会把残渣当成"原状"。
    snapshot_baseline
    # 客户端版本落盘: 本地控制面 (/cgi-bin/zeroproxy 的 status) 与 CLI 都会读它。
    # 不写这一行的话界面上"客户端 v…"那一格永远是空的 —— 真机上就是这样, 无害但会让人
    # 以为版本没装上。
    printf '%s' "$ZP_CLIENT_VERSION" > "$ZP_DIR/version"
    # 架构也落盘: CLI 的 `zeroproxy perf on` 要按它去面板取性能模式内核 (dae)。
    printf '%s' "$ARCH" > "$ZP_DIR/arch"
    # 运行时装机件 (live.sh / nft 规则 / 数据面脚本 / agent / CLI / init) 由面板分发 ——
    # 见 install_runtime。以前它们在这里用 heredoc 现场生成, 于是改不动也测不了。
    install_runtime

    # tproxy 回退方案用的 nft 规则 (只在 TUN 不可用时由 init 脚本加载)。
    # 优先级用数字而不是符号名 (dstnat/mangle): 数字在各版本 nft 上行为一致。
    # 局域网/私有地址先放行, 再看 mark —— 否则代理自己的出站连接会被再次抓回来成环。

    # redirect 数据面 (iptables nat)。只在 TUN 与 tproxy 都不可用时启用 (chosen=redirect)。
    #
    # 为什么单独抽成一个能 source 的文件: 装 / 开 / 关 / 卸载四个地方都要用它, 而它们
    # 分别是三个进程 (安装脚本 / init 脚本 / CLI) —— 一处实现, 四处同一份。tproxy.nft
    # 是"数据" (nft -f 直接读), 这里是"动作" (要按 LAN 接口名增删), 所以写成函数。
    #
    # 只接管**从局域网接口进来**的 TCP: REDIRECT 不适用于 UDP, 所以 covered=lan_tcp;
    # 路由器自身出站与 WAN 侧入站一个字节都不碰。UDP 那部分要 TUN 或 tproxy 才做得到,
    # 这台固件给不了 —— 那就如实少给, 而不是假装给全了。

    # TUN 数据面的**防火墙放行**。只在 auto-redirect 没能跑成 (caps: autoredirect=0) 时才用。

    # 性能模式 (eBPF / dae) 的开关逻辑。**一处实现, 三个入口**: CLI 的 `zeroproxy perf ...`、
    # agent 的看门狗 (dae 挂了要自动退回)、以及本机界面 (它把按钮动作转发给 CLI)。
    #
    # 三条硬规矩 (为什么值得单独一个文件):
    #   1. 进去之前先把配置校验一遍 (`dae validate`) —— 配置是错的, 就不该动现在的数据面;
    #   2. 进去之后必须**验证流量真的过得去** (境外地址够得到), 而不是"进程起来了"就算成功;
    #   3. 任何一步失败都**退回原来的模式** —— 家里不能因为点了一个按钮就断网。

    # 性能模式内核 (dae) 自己的 init 脚本。与 mihomo 分成两个服务是必须的: 两者**互斥**,
    # "谁在跑"必须能被单独开关 (换模式 = 停一个、起另一个), 而不是靠一个服务里的分支。

    # 控制 agent: 每 15 秒向面板上报一次状态并取回"期望开关 + 配置版本"。
    # 面板是唯一的事实来源 —— 路由器本地改开关也是请求面板去改 (见 CLI)。

    # 两个独立的 procd 服务, 分开是有原因的: 关代理 = 停内核, 而控制 agent 必须
    # 继续活着 —— 否则关了之后就再也没人去把它开回来 (面板下发再多次也没人接)。
    # 所以从设计上就不允许把两者放进同一个 init 脚本。

    # 控制 agent 单独一个服务: 只受开机与卸载影响, 不受面板开关影响。

    # 运维 CLI: 在路由器上直接看状态 / 开关 / 更新 / 卸载。
    # 界面令牌 (0600): 数据接口要么认它 (地址里带 ?k=…, 打开一次种成一年期的 cookie),
    # 要么认一个有效的 LuCI 会话。GL.iNet 的后台不是 LuCI, 所以这个令牌是那类固件上唯一
    # 能授权的方式 —— 它在**这里**生成而不是在"有没有 LuCI"那个分支里: 令牌属于客户端凭据
    # (agent 每轮心跳把它报给面板, 用户在面板上就能一键打开), 与有没有网页界面无关。
    if [ ! -s "$ZP_DIR/ui.token" ]; then
        umask 077
        head -c 16 /dev/urandom | md5sum | cut -c1-32 > "$ZP_DIR/ui.token" 2>/dev/null || \
            printf '%s' "$(date +%s)$$" > "$ZP_DIR/ui.token"
        umask 022
        chmod 600 "$ZP_DIR/ui.token"
    fi
    # 分流数据库要在生成配置**之前**就位: 配置里要不要带 geo 规则, 由本机有没有数据决定。
    install_geo
    # 配置在所有运行文件就位之后才生成 (agent 的 config 模式要用到 agent.sh 自己);
    # 生成失败时那条自愈路径还能用本次命令里的配对码重新接入。
    #
    # 这一步**单独报一节**: 拉配置要连面板, 是整条安装里最容易卡住的地方 (真机上就是
    # 卡在这里失败的), 而它原来没有任何 `==>` —— 界面上的进度清单里没有这一步, 于是
    # 用户看到的是"九步全绿 + 失败 56%", 完全对不上。
    step "拉取配置"
    fetch_config "$ZP_CONF" || config_failure
    ok "配置已写入 $ZP_CONF"
    ok "已写入 $ZP_INIT / $ZP_AGENT_INIT / $ZP_DIR/agent.sh / $ZP_CLI"
}

# ---------------------------------------------------------------- 网页界面
# ---------------------------------------------------------------- 本地控制面 (zpcore)
# 可选件: 面板准备了这一档就装, 没准备就退回原来的界面路径 —— **任何失败都不该让装机失败**,
# 所以这里全部是 note 而不是 warn/die。
#
# 注意它**永远返回 0**: 这是脚本里唯一的"可选件", 而 `set -e` 下任何非 0 的返回都会把
# 整个安装掐断 (真机意义上的"装到一半停下")。调用方要看结果就查 $ZP_DIR/zpcore 在不在。
#
# 形态与 mihomo 内核**刻意一样**: 面板直传一个 .gz, 路由器端 gzip -t 判定 → 解压 →
# 跑一次 `version` 确认它真能执行 → 落盘。那段代码刚在内核那条路上跑过七次真机。
# 区别只有分发位置: zpcore 是我们自己的东西, 没有上游可下, 产物跟着仓库走
# (scripts/build-agent.sh 生成), 所以面板读的是仓库目录而不是 data/ 缓存。
ZPCORE_MIN_BYTES="${ZP_AGENT_MIN_BYTES:-65536}"

install_zpcore() {
    step "准备本地控制面 (可选件)"
    # **每次都试着取面板当前那一版**, 取不到才沿用本机已有的。
    #
    # 不能"有二进制就跳过": 面板把 AGENT_VERSION 抬上去之后, 已经装好的路由器会永远停在
    # 第一次装上的那一版 —— 真机上就是这么停在 1.0.0 的, 而面板已经在发 1.1.1 (然后
    # 因为源码里还写着一个版本号, 连它自报的版本都是错的)。新的一律先落到 .new, 跑通了
    # 才替换 —— 正在用的那一份不能被一个坏下载毁掉。
    _have=0
    if [ -x "$ZP_DIR/zpcore" ] && "$ZP_DIR/zpcore" version >/dev/null 2>&1; then
        _have=1
        _old_ver="$("$ZP_DIR/zpcore" version 2>/dev/null | head -n1)"
    fi
    # 上一次留下的坏文件 (没解开 / 架构不对) 会让每次重跑都死在同一个地方: 先清掉。
    rm -f "$ZP_DIR/.zpcore.gz" "$ZP_DIR/zpcore.new" 2>/dev/null || true
    _tmp="$ZP_DIR/.zpcore.gz"
    # 用与内核同一条下载器 (http_fetch_to): 它带 HTTP 状态码, 于是"面板说没有这一档"
    # (404) 与"这条路走不通"能分开说 —— 以前两者都是同一句"没准备", 排障时指错方向。
    if ! http_fetch_to "$ZP_BASE/c/agent/bin/$ARCH" "$_tmp" 300 0; then
        if [ "$HTTP_CODE" = "404" ]; then
            note "面板没有准备这一档本地控制面 (可选件) —— 界面走原来的路径"
        else
            note "这次没取到本地控制面 (HTTP ${HTTP_CODE:-?}) —— 界面走原来的路径"
        fi
        rm -f "$_tmp"
        if [ "$_have" = "1" ]; then ok "沿用本机已有的: $_old_ver"; fi
        return 0
    fi
    _size="$(wc -c < "$_tmp" 2>/dev/null | tr -d ' ' || true)"
    if [ "${_size:-0}" -lt "$ZPCORE_MIN_BYTES" ]; then
        rm -f "$_tmp"
        note "面板没有准备 $ARCH 这一档本地控制面 (可选件) —— 界面走原来的路径"
        if [ "$_have" = "1" ]; then ok "沿用本机已有的: $_old_ver"; fi
        return 0
    fi
    # gzip 判定只用 gzip -t (busybox 一定有) —— 与内核那一步同一条路, 同一套理由。
    if gzip -t "$_tmp" >/dev/null 2>&1; then
        if ! gzip -dc "$_tmp" > "$ZP_DIR/zpcore.new" 2>/dev/null; then
            rm -f "$_tmp" "$ZP_DIR/zpcore.new"
            note "本地控制面解压失败 —— 界面走原来的路径"
            if [ "$_have" = "1" ]; then ok "沿用本机已有的: $_old_ver"; fi
            return 0
        fi
    else
        cp "$_tmp" "$ZP_DIR/zpcore.new"
    fi
    rm -f "$_tmp"
    chmod 755 "$ZP_DIR/zpcore.new"
    if ! "$ZP_DIR/zpcore.new" version >/dev/null 2>&1; then
        rm -f "$ZP_DIR/zpcore.new"
        note "本地控制面在这台机器上跑不起来 (架构不匹配?) —— 界面走原来的路径"
        if [ "$_have" = "1" ]; then ok "沿用本机已有的: $_old_ver"; fi
        return 0
    fi
    _new_ver="$("$ZP_DIR/zpcore.new" version 2>/dev/null | head -n1)"
    if [ "$_have" = "1" ] && [ "$_old_ver" = "$_new_ver" ]; then
        rm -f "$ZP_DIR/zpcore.new"
        ok "本地控制面已是最新: $_new_ver"
        return 0
    fi
    if [ "$_have" = "1" ]; then
        mv "$ZP_DIR/zpcore.new" "$ZP_DIR/zpcore"
        ok "本地控制面升级: $_old_ver → $_new_ver"
    else
        mv "$ZP_DIR/zpcore.new" "$ZP_DIR/zpcore"
        ok "本地控制面就绪: $_new_ver"
    fi
    return 0
}

# 界面文件 (一个页面 + 一个 cgi) 落盘只是第一步; 第二步 —— "让本机的 Web 服务真的把它
# 发出去" —— 在固件之间差别很大, 真机踩过三种:
#   * uhttpd (OpenWrt 默认): 文档根 /www, /cgi-bin/ 会执行脚本 —— 落盘即通;
#   * nginx + fcgiwrap (GL.iNet 部分固件): /www 是文档根, /cgi-bin/ 走 fcgiwrap (LuCI
#     自己就走它), 也通;
#   * nginx 原厂界面 (GL.iNet 21.02-SNAPSHOT 原厂, 没有 LuCI): /www 照发静态文件, 但
#     /cgi-bin/ 没有对应的 location —— 我们那个脚本会被当成**文本文件**发出去 (浏览器
#     打开是一坨 shell 源码), 数据接口全废。
# 所以落盘之后必须真的取一次, 而且**判据要看内容**: 200 也可能是把脚本当静态文件发了。
# 页面里有 <title>, 那个 cgi 脚本里没有 —— 用它区分"页面被发出来了"和"脚本被下载了"。
#
# 两条路都不通也不影响代理: 命令行 (zeroproxy) 一直是可用的兜底。
UI_MARK='<title>ZeroProxy'
#: 兜底 httpd 的端口 (只在固件自己的 Web 服务发不出页面时才用, 且只绑局域网地址)。
UI_PORT="${ZP_UI_PORT:-8399}"

# 这个基地址能不能把**页面**发出来 (返回 0 = 能)。
ui_probe() {
    _t="$(cat "$ZP_DIR/ui.token" 2>/dev/null)"
    _body="$(http_get "$1?k=$_t" 2>/dev/null | head -c 600)"
    case "$_body" in *"$UI_MARK"*) return 0 ;; esac
    return 1
}

# 界面基地址 (不带令牌)。端口写在 ui.port 里: 空 = 固件自己的 Web 服务 (80),
# 有值 = 界面由自带的 httpd 发。存端口而不是整个 URL —— LAN 地址换了也得算得对。
ui_base() {
    _port="$(cat "$ZP_DIR/ui.port" 2>/dev/null || true)"
    [ -n "$_port" ] && _port=":$_port"
    printf 'http://%s%s/cgi-bin/zeroproxy' "$(lan_ip)" "$_port"
}

ui_busybox() {
    # 返回**绝对路径**: 这个值会被写进 procd 的服务定义, 那里不保证有 PATH。
    _c="$(command -v busybox 2>/dev/null || true)"
    if [ -n "$_c" ]; then printf '%s' "$_c"; return 0; fi
    for _c in /bin/busybox /usr/bin/busybox; do
        if [ -x "$_c" ]; then printf '%s' "$_c"; return 0; fi
    done
    return 1
}

ui_stop_local_server() {
    /etc/init.d/zeroproxy-ui stop >/dev/null 2>&1 || true
    /etc/init.d/zeroproxy-ui disable >/dev/null 2>&1 || true
    rm -f "$ZP_INIT_UI"
}

# 自带的界面服务 —— 不依赖固件的 Web 服务器。两条路, 一个 init 服务:
#   * 有 zpcore (面板分发的本地控制面): 静态二进制自己起 HTTP 服务、自己校验令牌、
#     自己只绑局域网地址。"界面能不能打开"从此与固件无关 —— 这才是它存在的理由。
#   * 没有 zpcore: 退回 busybox httpd (约定只有一条 "url 以 /cgi-bin/ 开头就当 cgi 执行")。
# 两条路都只绑**局域网地址**: 每多一个监听口都是事实, 所以绝不退化成 0.0.0.0 (那等于把
# 管理界面挂到 WAN 上)。授权两者共用同一个 ui.token 文件, 与走固件 Web 服务时同一条路。
#
# 参数 `busybox` 可以强制走第二条 (zpcore 存在但起不来时, 还有一次机会)。
ui_start_local_server() {
    _force_bb="${1:-}"
    _have_zp=0
    if [ "$_force_bb" != "busybox" ] && [ -x "$ZP_DIR/zpcore" ]; then _have_zp=1; fi
    _bb=""
    if [ "$_have_zp" = "0" ]; then
        _bb="$(ui_busybox 2>/dev/null || true)"
        [ -n "$_bb" ] || return 1
        # --list 不是所有 busybox 都给; 给的话就顺手确认 httpd 这个 applet 编进去了。
        if "$_bb" --list >/dev/null 2>&1; then
            "$_bb" --list | grep -qx httpd || return 1
        fi
        [ -s "$ZP_DIR/www/cgi-bin/zeroproxy" ] || return 1
    fi
    cat > "$ZP_INIT_UI" <<'UIINITEOF'
#!/bin/sh /etc/rc.common
# ZeroProxy 网页管理界面 (自带的, 不依赖固件的 Web 服务器)。
# 只绑局域网地址: 找不到 LAN 地址就不启动, 绝不退化成 0.0.0.0。
START=98
USE_PROCD=1

ZP_DIR=/etc/zeroproxy
UI_PORT=__ZP_UI_PORT__
BB=__ZP_BUSYBOX__

lan_ip() {
    _ip="$(uci get network.lan.ipaddr 2>/dev/null || true)"
    [ -n "$_ip" ] || _ip="$(ip -4 addr show 2>/dev/null | sed -n 's/.*inet \([0-9.]*\).*/\1/p' | grep -v '^127\.' | head -n1)"
    printf '%s' "$_ip"
}

start_service() {
    # 有 zpcore 就用它, 否则用 busybox httpd; 两样都没有就不启动
    if [ -x "$ZP_DIR/zpcore" ]; then
        :
    elif [ -x "$ZP_DIR/www/cgi-bin/zeroproxy" ] && [ -n "$BB" ]; then
        :
    else
        return 0
    fi
    _ip="$(lan_ip)"
    [ -n "$_ip" ] || return 0
    procd_open_instance
    if [ -x "$ZP_DIR/zpcore" ]; then
        procd_set_param command "$ZP_DIR/zpcore" serve \
            --dir "$ZP_DIR" --bind "$_ip" --port "$UI_PORT" \
            --cli /usr/bin/zeroproxy --init /etc/init.d/zeroproxy
    else
        procd_set_param command "$BB" httpd -f -p "$_ip:$UI_PORT" -h "$ZP_DIR/www"
    fi
    procd_set_param respawn 3600 5 5
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}

service_triggers() { procd_add_reload_interface_trigger lan; }
UIINITEOF
    # 端口与 busybox 路径用占位符写 (带引号的 heredoc 不做变量替换), 落盘后再替一次 ——
    # 与 agent/CLI 的版本号同一个手法。chmod 要在 mv 之后: 新文件是默认权限。
    sed -e "s#__ZP_UI_PORT__#$UI_PORT#" -e "s#__ZP_BUSYBOX__#$_bb#" "$ZP_INIT_UI" > "$ZP_INIT_UI.ver" \
        && { chmod 755 "$ZP_INIT_UI.ver"; mv "$ZP_INIT_UI.ver" "$ZP_INIT_UI"; } || rm -f "$ZP_INIT_UI.ver"
    /etc/init.d/zeroproxy-ui enable >/dev/null 2>&1 || true
    /etc/init.d/zeroproxy-ui restart >/dev/null 2>&1 || true
    _w=0
    while [ "$_w" -lt 12 ]; do
        sleep 1
        ui_probe "http://$(lan_ip):$UI_PORT/cgi-bin/zeroproxy" && return 0
        _w=$((_w + 1))
    done
    # 起不来就收干净, 不留一个跑不起来的服务 (调用方还有别的路可以试)。
    ui_stop_local_server
    return 1
}

# ---------------------------------------------------------------- 界面文件的落盘 (原子 + 兜底)
# 真机事故 (README 8.79): 升级之后 LuCI 里点「服务 → ZeroProxy」直接 **403**。
#
# 现场是这么来的: 那三个小文件以前是这么写的 ——
#     http_get "$ZP_BASE/c/ui/acl.json" > /usr/share/rpcd/acl.d/luci-app-zeroproxy.json || true
# 重定向**先把目标文件清空**, 而 `|| true` 把失败咽掉。面板正好在重启的那一次 (nginx 回
# 502, 或者链路抖了一下), 一份好端端的 ACL 就被换成了 0 字节 —— rpcd 读不了它, 我们的
# ACL 组等于不存在, LuCI 的菜单依赖检查不过, 于是那个页面**只回一个 403**, 谁也不告诉
# "为什么"。三个文件都走这条写法, 所以 menu.json 与承载页也可能一起坏掉。
#
# 修法两条, 缺一不可:
#   1. **原子写**: 先下到临时文件, 验过 (非空 / 像个 JSON) 再 mv 过去; 取不到就**保留
#      本机原来那一份**, 绝不让一次失败的请求毁掉一个能用的文件;
#   2. **内置兜底**: 这三份一共几百字节、且很稳定 —— 让"点不点得开"依赖一次网络请求,
#      等于把它押在链路脸色上。面板能给就用面板的 (方便以后改样式), 给不出就用内置的
#      那一份 (同时留一份在 $ZP_DIR/luci/, 离线也能修 —— 见 CLI 的 `zeroproxy ui fix`)。
ui_file_ok() {  # $1=文件 $2=期望的首字符 ('' = 只要非空)
    [ -s "$1" ] || return 1
    [ -z "$2" ] && return 0
    [ "$(head -c 1 "$1" 2>/dev/null)" = "$2" ]
}

# 原子取一个界面文件。返回 0 = 目标文件现在是好的 (新下的 / 原来的 / 内置的)。
ui_put() {  # $1=url $2=目标 $3=期望首字符 $4=内置兜底的名字 ('' = 没有)
    _u="$1"; _dst="$2"; _want="$3"; _builtin="${4:-}"
    _tmp="$_dst.new.$$"
    if http_get "$_u" > "$_tmp" 2>/dev/null && ui_file_ok "$_tmp" "$_want"; then
        mv "$_tmp" "$_dst"
        chmod 644 "$_dst" 2>/dev/null || true
        return 0
    fi
    rm -f "$_tmp"
    # 本机这一份还好好的 → 一个字节都不动 (升级不拿能用的东西冒险)
    ui_file_ok "$_dst" "$_want" && { note "面板没给出 $(basename "$_dst") —— 保留本机已有的那份"; return 0; }
    [ -n "$_builtin" ] || return 1
    luci_builtin "$_builtin" > "$_dst" 2>/dev/null || return 1
    chmod 644 "$_dst" 2>/dev/null || true
    note "面板没给出 $_builtin —— 用内置的那一份"
    return 0
}

# 内置的 LuCI 三件套 (菜单 / 权限 / 承载页)。**内容与仓库里的 client/luci/ 逐字节一致** ——
# pytest 里有一条断言钉着这件事, 免得两边漂移 (漂移的症状是"某个固件上的菜单突然不见了")。
# 用法: luci_builtin <menu.json|acl.json|status.js>  (写到 stdout)
luci_builtin() {
    case "$1" in
        menu.json) cat <<'ZP_LUCI_MENU'
{
	"admin/services/zeroproxy": {
		"title": "ZeroProxy",
		"order": 60,
		"action": {
			"type": "view",
			"path": "zeroproxy/status"
		},
		"depends": {
			"acl": [ "luci-app-zeroproxy" ]
		}
	}
}
ZP_LUCI_MENU
            ;;
        acl.json) cat <<'ZP_LUCI_ACL'
{
	"luci-app-zeroproxy": {
		"description": "ZeroProxy 路由器客户端 (管理页面 + 会话校验)",
		"read": {
			"ubus": {
				"session": [ "get" ]
			}
		},
		"write": {}
	}
}
ZP_LUCI_ACL
            ;;
        status.js) cat <<'ZP_LUCI_STATUS'
'use strict';
/* LuCI 菜单里的那一页。
 *
 * 真正的界面是 /www/zeroproxy/ 下的静态页面 (原生 JS, 与面板同一套卡片风格)。
 * 这里只做一件事: 用 LuCI 自己的登录态把它框进来 —— 于是"能不能打开这个管理面"
 * 由 LuCI 的 root 登录决定, 我们不用也不该再发明一套认证。
 */
'require view';

return view.extend({
	render: function () {
		return E('iframe', {
			src: '/cgi-bin/zeroproxy',
			style: 'width:100%;height:78vh;border:0;border-radius:10px;background:transparent',
			title: 'ZeroProxy'
		});
	},
	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
ZP_LUCI_STATUS
            ;;
        *) return 1 ;;
    esac
}

# 把内置的三件套放一份到 $ZP_DIR/luci/ (CLI 的 `zeroproxy ui fix` 离线修的就是它)。
luci_builtin_cache() {
    mkdir -p "$ZP_DIR/luci" 2>/dev/null || true
    for _f in menu.json acl.json status.js; do
        if ! ui_file_ok "$ZP_DIR/luci/$_f" "$( [ "$_f" = status.js ] && printf "'" || printf '{' )"; then
            luci_builtin "$_f" > "$ZP_DIR/luci/$_f" 2>/dev/null || true
        fi
    done
}

# LuCI 那一整套落盘 + 收尾 (rpcd 要重新读 ACL, LuCI 要清菜单索引缓存)。返回 0 = 三件套都在。
luci_install() {
    [ -d /usr/share/luci/menu.d ] || return 1
    mkdir -p /www/luci-static/resources/view/zeroproxy /usr/share/rpcd/acl.d 2>/dev/null || true
    luci_builtin_cache
    # 顺序: 先承载页与菜单 (点不点得开), 再 ACL (点得动点不动)。三个都走原子写。
    ui_put "$ZP_BASE/c/ui/status.js" /www/luci-static/resources/view/zeroproxy/status.js "'" status.js || true
    ui_put "$ZP_BASE/c/ui/menu.json" /usr/share/luci/menu.d/luci-app-zeroproxy.json '{' menu.json || true
    ui_put "$ZP_BASE/c/ui/acl.json" /usr/share/rpcd/acl.d/luci-app-zeroproxy.json '{' acl.json || true
    # 两道缓存都要清: rpcd 缓存 ACL, LuCI 把菜单索引缓存在 /tmp/luci-indexcache*
    # (只 reload rpcd 不够 —— 菜单是 LuCI 自己缓存的那份索引, 这是"菜单不出现"最常见的原因)
    /etc/init.d/rpcd reload >/dev/null 2>&1 || /etc/init.d/rpcd restart >/dev/null 2>&1 || true
    rm -f /tmp/luci-indexcache* /tmp/luci-modulecache/* 2>/dev/null || true
    # 最后**验一遍**: 三个都在、而且 ACL 与菜单是能读的 JSON —— 这是"点进去 403"的直接判据。
    _ok=1
    ui_file_ok /www/luci-static/resources/view/zeroproxy/status.js "'" || _ok=0
    ui_file_ok /usr/share/luci/menu.d/luci-app-zeroproxy.json '{' || _ok=0
    ui_file_ok /usr/share/rpcd/acl.d/luci-app-zeroproxy.json '{' || _ok=0
    return $(( 1 - _ok ))
}

install_ui() {
    step "安装网页管理界面"
    # 界面令牌在 write_files 里就生成好了 (agent 的心跳要拿它上报"管理界面地址")。
    # 万一被谁删了, 这里补一个 —— 没有令牌的地址等于打不开。
    if [ ! -s "$ZP_DIR/ui.token" ]; then
        umask 077
        head -c 16 /dev/urandom | md5sum | cut -c1-32 > "$ZP_DIR/ui.token" 2>/dev/null || \
            printf '%s' "$(date +%s)$$" > "$ZP_DIR/ui.token"
        umask 022
        chmod 600 "$ZP_DIR/ui.token"
    fi

    # 界面文件先落到 /etc/zeroproxy/www (兜底 httpd 的文档根就是它), 再复制一份到 /www
    # —— 固件自己的 Web 服务那条路走的是 /www, 而"能用它就不开新端口"是首选。
    _stage="$ZP_DIR/www"
    mkdir -p "$_stage/zeroproxy" "$_stage/cgi-bin"
    # perf.js 是性能模式那块仪表盘 (跑车表盘 + 进入动画)。它与 app.js 分开, 因为那是一整段
    # 独立的动画 / 状态机 —— 塞进 app.js 只会让两个都难读。
    for f in index.html app.js perf.js; do
        if ! http_get "$ZP_BASE/c/ui/$f" > "$_stage/zeroproxy/$f" 2>/dev/null; then
            # 老面板没有 perf.js (2.11.26 之前): 页面照发, 那块表盘不存在而已 ——
            # 代理本身一个字节都不受影响, 所以这里不整条放弃界面。
            if [ "$f" = "perf.js" ]; then
                rm -f "$_stage/zeroproxy/$f"
                note "面板上没有 perf.js (面板版本较旧?) —— 本机界面没有性能模式那块表盘"
                continue
            fi
            warn "面板没有提供界面文件 (面板版本较旧?), 跳过网页界面"
            rm -rf "$_stage"
            return 0
        fi
    done
    # cgi 脚本: 与 LuCI 那三件套同一个道理 —— 取不到就**别动**已经装好的那一份。以前这里是
    # `http_get … > 目标 || true`, 一次失败的请求会把一个能用的 cgi 换成 0 字节, 于是
    # 页面(iframe 指向 /cgi-bin/zeroproxy)直接空掉 (README 8.79 那次事故的同类)。
    _cgi_tmp="$_stage/cgi-bin/zeroproxy.new.$$"
    if http_get "$ZP_BASE/c/ui/cgi" > "$_cgi_tmp" 2>/dev/null && [ -s "$_cgi_tmp" ]; then
        mv "$_cgi_tmp" "$_stage/cgi-bin/zeroproxy"
    else
        rm -f "$_cgi_tmp"
        [ -s /www/cgi-bin/zeroproxy ] && cp /www/cgi-bin/zeroproxy "$_stage/cgi-bin/zeroproxy" 2>/dev/null || true
        note "面板没给出 cgi 脚本 —— 保留本机已有的那份"
    fi
    chmod 755 "$_stage/cgi-bin/zeroproxy" 2>/dev/null || true
    if [ ! -s "$_stage/zeroproxy/index.html" ]; then
        warn "面板没有提供界面文件 (面板版本较旧?), 跳过网页界面"
        rm -rf "$_stage"
        return 0
    fi
    if [ -d /www ]; then
        mkdir -p /www/zeroproxy /www/cgi-bin 2>/dev/null || true
        cp "$_stage/zeroproxy/index.html" "$_stage/zeroproxy/app.js" /www/zeroproxy/ 2>/dev/null || true
        [ -s "$_stage/zeroproxy/perf.js" ] && cp "$_stage/zeroproxy/perf.js" /www/zeroproxy/ 2>/dev/null || true
        cp "$_stage/cgi-bin/zeroproxy" /www/cgi-bin/zeroproxy 2>/dev/null || true
        chmod 755 /www/cgi-bin/zeroproxy 2>/dev/null || true
    fi

    # LuCI 菜单 / 权限 / 承载页 —— 只有装了 LuCI 才写, 否则上面那个地址一样能用
    _luci=0
    if [ -d /usr/share/luci/menu.d ]; then
        _luci=1
        if luci_install; then
            ok "LuCI 菜单 / 权限 / 承载页就位 (服务 → ZeroProxy)"
        else
            # 三件套缺一件, 那个页面就可能打不开 (最典型: ACL 读不出来 → 403)。所以这不是
            # "小问题", 要明说 —— 而且给出下一步: `zeroproxy ui fix` 能就地修 (离线也行)。
            warn "LuCI 那三件套没有全部就位 —— 菜单里点「服务 → ZeroProxy」可能报 403。
  在路由器上执行 zeroproxy ui fix 可以就地修好 (内置了一份兜底, 不需要面板)。"
        fi
    fi

    # 谁把页面发出去? 三条路, 按"与固件的关系"从松到紧:
    #   ① 自带的本地控制面 (zpcore, 面板分发的可选件) —— 与固件完全无关;
    #   ② 固件自己的 Web 服务 (80 端口, 不开新端口) —— 能用就不折腾;
    #   ③ 自带的 busybox httpd —— 只在 ② 发不出来时用。
    # 每一条都要**当场验过**才算数 (8.44 的教训: HTTP 200 也可能是把脚本当文本发出来)。
    : > "$ZP_DIR/ui.port"
    if [ -x "$ZP_DIR/zpcore" ] && ui_start_local_server; then
        printf '%s' "$UI_PORT" > "$ZP_DIR/ui.port"
        ok "管理界面已装好 (自带控制面 zpcore · 端口 $UI_PORT — 不依赖固件的 Web 服务器)"
    elif [ -d /www ] && { ui_probe "http://127.0.0.1/cgi-bin/zeroproxy" || ui_probe "http://$(lan_ip)/cgi-bin/zeroproxy"; }; then
        if [ "$_luci" = "1" ]; then
            ok "管理界面已装好 (LuCI 菜单: 服务 → ZeroProxy)"
        else
            ok "管理界面已装好"
        fi
        # 上一次可能是靠自带服务发的 (固件升级后 /cgi-bin/ 又能用了): 收掉它,
        # 不留一个多余的监听口。
        if [ -f "$ZP_INIT_UI" ]; then
            ui_stop_local_server
        fi
    elif ui_start_local_server busybox; then
        printf '%s' "$UI_PORT" > "$ZP_DIR/ui.port"
        ok "管理界面已装好 (这台固件没有把 /cgi-bin/ 交给脚本, 已用自带 httpd 在 $UI_PORT 端口发出)"
    else
        rm -f "$ZP_DIR/ui.port"
        warn "本机自检没通过 —— 浏览器打开下面的地址可能看到 403/404。
  这台设备的 Web 服务 (nginx?) 没把 /cgi-bin/ 交给脚本, 自带的 busybox httpd 也没能起来。
  请把下面四行的输出发回, 就能给这台固件补上对应的一条:
    pidof nginx uhttpd; nginx -v 2>&1; uci -q get uhttpd.main.home
    grep -rn 'root \|cgi\|fastcgi' /etc/nginx/conf.d/*.conf 2>/dev/null | head -10
    ls -ld /www /www/zeroproxy /www/cgi-bin 2>/dev/null
    busybox --list 2>/dev/null | grep -c httpd"
    fi

    UI_URL="$(ui_base)"
    UI_URL_K="$UI_URL?k=$(cat "$ZP_DIR/ui.token" 2>/dev/null)"
    # 打印出来的一定是**带令牌**的那条: 不带令牌打开就是一个"读不到状态、开关也点不动"的
    # 页面 (真机反馈: 用户照着打印的地址打开, 看到开关是关的、点不开, 以为是 bug)。
    ok "浏览器打开: $UI_URL_K"
    ok "  (令牌只用来授权这一个页面, 打开一次即可; 忘了就用 zeroproxy ui 再打印)"
    ok "  面板「客户端」那张设备卡上也有一键入口 (同一局域网内点它就行)"
}

# ---------------------------------------------------------------- 启动与自检
# 数据面是否真的在生效 —— 判据是现场 (设备在不在 / 表在不在), 不是"我们用命令下过一次"。
# 这是"永不撒谎"的落点: 8.45 那台机器上 nft -f 退出码是 0, 表却没建起来。
datapath_live() {
    # 判据只有一份 (live.sh 的 zp_level_live): 与 agent 心跳 / CLI / 本地界面是同一份,
    # 免得又多一处要同步。live.sh 由 write_files 落盘, verify (它才用这个函数) 在其后。
    if [ -r "$ZP_DIR/live.sh" ]; then
        . "$ZP_DIR/live.sh"
        if zp_level_live "$1"; then return 0; fi
        return 1
    fi
    case "$1" in
        tun)      ip link show zp-tun >/dev/null 2>&1 ;;
        tproxy)   nft list table inet zp_router >/dev/null 2>&1 ;;
        redirect) iptables -t nat -L zp_router >/dev/null 2>&1 ;;
        *)        return 1 ;;
    esac
}

# 等某一级真的生效。30 秒是量出来的: mihomo 启动到 zp-tun 出现之间有十几秒 ——
# 只查一次会误判成"没建出来", 于是错误地退回下一级并把两套规则叠在一起 (真机踩过)。
wait_datapath() {
    _w=0
    while [ "$_w" -lt 30 ]; do
        if datapath_live "$1"; then return 0; fi
        sleep 1
        _w=$((_w + 1))
    done
    return 1
}

# 内核控制口在不在 (mihomo 真起来了没有)。冷启动到监听 9090 通常 2~5 秒, 给 15 秒。
wait_core_api() {
    _i=0
    while [ "$_i" -lt 15 ]; do
        if http_get "http://$ZP_API/version" >/dev/null 2>&1; then return 0; fi
        sleep 1
        _i=$((_i + 1))
    done
    return 1
}

# 换一级数据面: 改 caps → 让面板按新能力重发配置 (有没有 tun 段由它决定: 建不出设备的
# 机器带着 tun 段, 内核直接起不来) → 校验 → 替换 → 重启内核。
# 任一步失败就把配置与 caps **一起**回滚 —— 两件事必须一起回, 否则下一轮重建配置又会
# 拿一份不一致的配置去覆盖。
apply_datapath() {
    _want="$1"
    _prev_dp="$DATAPATH"; _prev_cov="$COVERED"
    _bak=""
    if [ -f "$ZP_CONF" ]; then
        if cp "$ZP_CONF" "$ZP_CONF.dp.bak" 2>/dev/null; then _bak="$ZP_CONF.dp.bak"; fi
    fi
    set_datapath "$_want"
    if ! "$ZP_DIR/agent.sh" config > "$ZP_CONF.new" 2>/dev/null \
        || ! grep -q '^proxy-groups:' "$ZP_CONF.new" 2>/dev/null \
        || ! "$ZP_BIN" -t -d "$ZP_DIR" -f "$ZP_CONF.new" >/dev/null 2>&1; then
        rm -f "$ZP_CONF.new"
        DATAPATH="$_prev_dp"; COVERED="$_prev_cov"; write_caps
        if [ -n "$_bak" ]; then mv "$_bak" "$ZP_CONF" 2>/dev/null || true; fi
        return 1
    fi
    mv "$ZP_CONF.new" "$ZP_CONF"
    if [ -n "$_bak" ]; then rm -f "$_bak"; fi
    /etc/init.d/zeroproxy restart >/dev/null 2>&1 || true
    return 0
}

# 当前这一级真的起不来时, 顺着阶梯往下试 —— 每级都真的等它生效, 全都不行才认"未接管"。
# 能力探测没过的级直接跳过 (没必要装一个已经知道不行的)。
downgrade_datapath() {
    for _next in $(ladder_below "$ACTIVE_MODE"); do
        if ! rung_usable "$_next"; then
            note "$_next 这一级的能力探测本来就没过, 跳过"
            continue
        fi
        note "改用 $_next …"
        if apply_datapath "$_next" && wait_datapath "$_next"; then
            ACTIVE_MODE="$_next"
            return 0
        fi
        # 探测说行、现场说不行 (典型: 接口名不对 / 权限) → 把原因写进 caps,
        # 结尾与面板显示的都是它, 而不是一句"没生效"。
        case "$_next" in
            tun)      CAPS_WHY_TUN="规则/设备没有真正生效 (探测通过、运行时失败)" ;;
            tproxy)   CAPS_WHY_TPROXY="规则没有真正生效 (nft 表没建起来)" ;;
            redirect) CAPS_WHY_REDIRECT="规则没有真正生效 (iptables 链没建起来 / 接口名不对)" ;;
        esac
        write_caps
    done
    set_datapath none
    ACTIVE_MODE="none"
    return 1
}

# TUN 起不来时的一次自愈 —— 只在真的失败过之后才做, 能跑的机器一个字节都不动。
#
# 怀疑对象是 auto-redirect: 它是 sing-tun 往内核里写 nftables 规则的开关 (OpenWrt 上
# 还要往 /etc/nftables.d/ 写文件再 `fw4 reload`), 某些固件上那一步会失败 —— 而那是
# **致命**的: 整个 tun 都起不来, 现象就是"zp-tun 一直不出现"。
#
# ⚠ 去掉 auto-redirect **不等于**"功能不受影响" —— 这里原先就是这么以为的, 结果是 8.74
# 那台机器上"全屋断网": auto-route 确实用 ip rule + 独立路由表把局域网转发也拖进了 tun
# (这点没错), 但 **auto-redirect 在 OpenWrt 上还负责写那两条"放行转发进/出 tun"的防火墙
# 规则** (见 tunfw.sh 顶部引的上游源码)。只去掉它, 包进得来、出不去 —— 局域网被整个丢掉,
# 而路由器自己走的是另一条链, 所以自检一切正常。现在这一半由 tunfw.sh 补上, 且必须验证到位。
#
# 做法是让面板给一份不带 auto-redirect 的配置再试一次 (?tproxy=0 那条路)。跑通就把
# 这个结论记进 caps (以后每轮重建配置都不再要它); 跑不通就原样回滚, 免得留一个没用的
# 改动在人家机器上。
tun_retry_without_redirect() {
    [ -x "$ZP_DIR/agent.sh" ] || return 1
    [ -f "$ZP_CONF" ] || return 1
    _ar="$(sed -n 's/^autoredirect=//p' "$ZP_DIR/caps" 2>/dev/null | head -n1)"
    case "$_ar" in 1) ;; *) return 1 ;; esac
    cp "$ZP_CONF" "$ZP_CONF.ar.bak" 2>/dev/null || return 1
    caps_write 0
    if ! "$ZP_DIR/agent.sh" config > "$ZP_CONF.new" 2>/dev/null; then
        rm -f "$ZP_CONF.new"
        caps_write 1
        return 1
    fi
    # 与 fetch_config 同一道闸门: 拿到的必须像一份配置, 而且要能被内核自己校验通过
    if ! grep -q '^proxy-groups:' "$ZP_CONF.new" 2>/dev/null \
        || ! "$ZP_BIN" -t -d "$ZP_DIR" -f "$ZP_CONF.new" >/dev/null 2>&1; then
        rm -f "$ZP_CONF.new"
        caps_write 1
        return 1
    fi
    mv "$ZP_CONF.new" "$ZP_CONF"
    /etc/init.d/zeroproxy restart >/dev/null 2>&1 || true
    _w=0
    while [ "$_w" -lt 20 ]; do
        if ip link show zp-tun >/dev/null 2>&1; then
            rm -f "$ZP_CONF.ar.bak"
            TUN_HEALED="no-auto-redirect"
            return 0
        fi
        sleep 1
        _w=$((_w + 1))
    done
    # 还是不行: 配置与 caps 都退回原样 (这两件事必须一起回, 否则下次重建配置又会
    # 拿一份不一样的配置去覆盖)
    mv "$ZP_CONF.ar.bak" "$ZP_CONF" 2>/dev/null || true
    caps_write 1
    /etc/init.d/zeroproxy restart >/dev/null 2>&1 || true
    return 1
}

verify() {
    step "启动并自检"
    /etc/init.d/zeroproxy enable >/dev/null 2>&1 || true
    /etc/init.d/zeroproxy-agent enable >/dev/null 2>&1 || true
    # 先起控制 agent (它会立刻上报, 面板上马上就能看到这台设备), 再起内核
    /etc/init.d/zeroproxy-agent restart >/dev/null 2>&1 || true

    # 性能模式正在用的时候**不许**顺手把 mihomo 拉起来 —— 两个数据面互斥, 一起跑就是互相
    # 抢包。重跑安装命令 (= 升级客户端) 不该把用户点的那个模式悄悄换掉。
    if [ "$(_perf_flag)" = "1" ]; then
        . "$ZP_DIR/perf.sh"
        if zp_perf_live; then
            /etc/init.d/zeroproxy disable >/dev/null 2>&1 || true
            /etc/init.d/zeroproxy stop >/dev/null 2>&1 || true
            touch "$ZP_DIR/core.up"
            # 现场验过的数据面就是 eBPF 这一档 —— 摘要与"模式/覆盖"两行读的都是它,
            # 漏了这一句就会落进"未生效"那一支 (8.87)。
            ACTIVE_MODE="ebpf"
            ok "性能模式在用 (内核态 eBPF / dae): 标准模式的内核保持停用"
            _eip="$(sed -n '1p' "$ZP_PERF_DIR/exit_ip" 2>/dev/null || true)"
            _wip="$(sed -n '1p' "$ZP_DIR/wan_ip" 2>/dev/null || true)"
            if [ -n "$_eip" ] && [ "$_eip" = "$_wip" ]; then
                note "  出口 $_eip (本机): 路由器自身的流量没走代理 —— 局域网设备不受影响"
            elif [ -n "$_eip" ]; then
                ok "  出口 $_eip (上次验证时记下的)"
            fi
            return 0
        fi
        note "性能模式说好在用, 但 dae 已经不在 —— 自动退回标准模式"
        zp_perf_leave "重跑安装命令时发现 dae 不在"
    fi
    touch "$ZP_DIR/core.up"
    /etc/init.d/zeroproxy restart >/dev/null 2>&1 || true

    # 数据面: 从 caps 里那一级开始, **真的等它生效** (不是"命令跑过就算")。
    ACTIVE_MODE="${DATAPATH:-none}"

    # 内核起不来**本身就是数据面起不来的一种**: tun 段在这台固件上建不出设备时, mihomo
    # 会直接退出 (procd 不停重启它), 控制口永远不响应。旧版在这里直接 die —— 于是
    # "顺着阶梯往下试"那条路根本没机会跑: 真机 (GL-MT3600BE · 原厂 21.02 固件) 上就
    # 停在"未接管", 而它明明还有 iptables 可走。所以先试降级, 再决定要不要 die。
    if ! wait_core_api; then
        warn "内核控制口没有响应, 最近日志:"
        logread -e zeroproxy 2>/dev/null | tail -n 8 >&2 || true
        if [ "$ACTIVE_MODE" != "none" ]; then
            note "先换一级数据面再试 —— 这类失败多半是 tun 段在这台固件上建不出来"
            if downgrade_datapath && wait_core_api; then
                ok "换成 $ACTIVE_MODE 之后内核起来了"
            fi
        fi
        if ! wait_core_api; then
            die "内核启动失败。把上面的日志发给面板即可定位 (通常是节点配置或内存不足)。"
        fi
    fi
    ok "内核已启动"
    if [ "$ACTIVE_MODE" = "tun" ]; then
        if ! wait_datapath tun; then
            # 把**内核自己说的原因**打出来: 一台设备一种原因 (没有 tun 模块 / nft 不支持
            # auto-redirect / 权限), 光看"没建出来"没法定位 —— 上一版只有一句警告,
            # 于是只能靠用户截图猜。
            warn "等了 30 秒 TUN 设备仍未出现, 与 tun 有关的内核日志:"
            logread -e zeroproxy 2>/dev/null \
                | grep -iE 'tun|tproxy|nft|permission|denied|not permitted|no such|error' \
                | tail -n 6 >&2 || true
            # 一次自愈: 去掉 auto-redirect 重建配置再试 (只在失败之后才做)
            if tun_retry_without_redirect && wait_datapath tun; then
                ok "TUN 已建立 (已按这台固件去掉 auto-redirect)"
            fi
        fi
        # **设备在 ≠ 流量过得去** (8.74)。auto-redirect 被拿掉之后, upstream 原本会写的那两条
        # "放行转发进/出 tun" 的防火墙规则就没人写了 —— 少了它们, 局域网转发被整个丢掉, 而
        # 路由器自己与面板都一切正常: 现象是"两边都显示已连接, 家里的设备国内国外全断"。
        # 这里补上, 并且**必须真的在** (按注释认领地查一次现场) 才敢说这一级生效。
        if datapath_live tun && [ -f "$ZP_DIR/tunfw.sh" ]; then
            . "$ZP_DIR/tunfw.sh"
            if zp_tunfw_needed; then
                if zp_tunfw_allow; then
                    ok "已补上防火墙放行 (auto-redirect 缺席时, 转发进/出 tun 靠它)"
                else
                    warn "补不上防火墙放行 —— 局域网转发会被丢掉, 这一级不能算生效"
                    CAPS_WHY_TUN="auto-redirect 缺席, 且补不上防火墙放行 (局域网会被丢包)"
                    TUN_UNUSABLE=1
                fi
            fi
        fi
    elif [ "$ACTIVE_MODE" != "none" ]; then
        wait_datapath "$ACTIVE_MODE" || true
    fi

    # 这一级真的没起来 → 顺着阶梯往下试。降级成功时会顺带重建配置 (不再带 tun 段),
    # 于是"这台固件建不出设备"这件事不会再拖垮整条链路。
    if [ "$ACTIVE_MODE" != "none" ] && { ! datapath_live "$ACTIVE_MODE" || [ "$TUN_UNUSABLE" = "1" ]; }; then
        warn "当前数据面 ($ACTIVE_MODE) 没有生效 —— 顺着阶梯往下试"
        downgrade_datapath || true
    fi

    case "$ACTIVE_MODE" in
        tun)      ok "TUN 已建立: 全屋设备 (含路由器自身) 透明代理生效" ;;
        tproxy)   ok "已启用 tproxy: 全屋设备生效 (路由器自身流量除外)" ;;
        redirect) ok "已启用 iptables REDIRECT: 局域网 TCP 生效 (不含 UDP 与本机自身)" ;;
        *)        warn "全屋透明代理这次没有生效 —— 本机代理端口仍然可用" ;;
    esac

    # 等节点就绪再测: provider 是内核启动后异步拉的, 立刻测一定失败 —— 那句
    # "出口测试未通过" 于是变成一条误导 (真机反馈里它一直挂着, 让人以为代理坏了)。
    # 判据是 mihomo 自己说 🚀 节点选择 现在选的是谁: 还是 DIRECT 就再等。
    if command -v curl >/dev/null 2>&1; then
        _w=0
        while [ "$_w" -lt 30 ]; do
            _now="$(curl -s -m 3 "http://127.0.0.1:9090/proxies/%F0%9F%9A%80%20%E8%8A%82%E7%82%B9%E9%80%89%E6%8B%A9" 2>/dev/null | sed -n 's/.*"now":"\([^"]*\)".*/\1/p')"
            # 写成 if 而不是 `a && b && break`: 后者的失败态会留在 while 体末尾,
            # 在 `set -e` 下是一颗定时炸弹 (busybox ash 与 dash 的处理还不完全一样)。
            if [ -n "$_now" ] && [ "$_now" != "DIRECT" ]; then break; fi
            sleep 2
            _w=$((_w + 1))
        done
        if [ -n "$_now" ]; then ok "节点已就绪 (当前选中: $_now)"; fi
    fi
    # 真实出口测试: 经代理端口请求一次, 只作为信息展示 —— 节点全关时失败是正常的。
    # 用 curl 是因为 busybox 的 wget 不支持 -x (代理), 没有 curl 就跳过这一步。
    #
    # **要重试**: provider 是内核启动后异步拉的, 第一次连接常常赶在节点健康检查之前 ——
    # 装完立刻测就是"未通过", 而一分钟后再手动测是好的 (GL-MT3000 与 GL-MT3600BE 两台
    # 真机都这样)。第一次失败就警告, 用户看到的是"装完报错"。
    if command -v curl >/dev/null 2>&1; then
        _t=0
        _exit_ok=0
        while [ "$_t" -lt 3 ]; do
            if curl -fsS -m 12 -x "http://127.0.0.1:$ZP_MIXED" -o /dev/null \
                "http://www.gstatic.com/generate_204" 2>/dev/null; then
                _exit_ok=1
                break
            fi
            _t=$((_t + 1))
            if [ "$_t" -lt 3 ]; then sleep 3; fi
        done
        if [ "$_exit_ok" = "1" ]; then
            ok "出口连通性正常"
        else
            warn "出口测试连续 3 次未通过 (节点可能全部关闭, 或节点本身不通) — 不影响安装"
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
    # 说什么话, 取决于**真的生效到哪** (ACTIVE_MODE 是现场验过的, 不是探测的意图)。
    # 之前这里只看"tun 有没有建出来", 于是 tproxy 也没装上的机器照样报"已开启"(8.45)。
    case "${ACTIVE_MODE:-none}" in
        ebpf)
            ok "性能模式已开启 —— 手机 / 电脑 / 电视连上这台路由器即可用 (数据面: 内核态 eBPF)"
            printf '  %s\n' "（这一档下标准模式的内核是停用的; 要回到 TUN 模式请在界面点「熄火」）" ;;
        tun)
            ok "全屋代理已开启 —— 手机 / 电脑 / 电视连上这台路由器即可用" ;;
        tproxy)
            ok "全屋代理已开启 —— 手机 / 电脑 / 电视连上这台路由器即可用"
            printf '  %s\n' "（路由器自身的流量不经代理: 这台固件建不出 TUN 设备）" ;;
        redirect)
            ok "局域网代理已开启 —— 手机 / 电脑 / 电视的 TCP 流量已接管"
            printf '  %s\n' "（UDP / QUIC 与本机自身流量不在覆盖范围 —— 这是这台固件上能做到的最大范围）" ;;
        *)
            printf '%s透明代理未生效%s —— 这台设备上 TUN / tproxy / iptables REDIRECT 都用不了\n' "$C_E" "$C_R"
            printf '  原因 (探测时记下的原话, 面板上也能看到):\n'
            for _lv in tun tproxy redirect; do
                _w="$(sed -n "s/^why.$_lv=//p" "$ZP_DIR/caps" 2>/dev/null | head -n1)"
                if [ -n "$_w" ]; then printf '    %-9s %s\n' "$_lv" "$_w"; fi
            done
            printf '  下一步任选一条:\n'
            printf '    1) 补内核模块后重跑这条安装命令:\n'
            printf '         %s\n' "$(deps_hint)"
            if [ -n "$DEPS_FAILED" ]; then
                printf '       上次装的时候它是这么说的 (原话): %s\n' "$DEPS_FAILED"
            fi
            if [ "$PKG_MGR" = "apk" ]; then
                printf '       25.12 起内核模块在**与内核版本绑定**的源里: 厂商固件的内核与它不符时,\n'
                printf '       源里根本没有这台机器的 kmod —— 那就只能等固件更新或刷官方固件。\n'
            fi
            printf '    2) 换成带 TUN / nftables 支持的固件 (原厂精简固件常常都缺)\n'
            printf '  路由器本机的代理端口一直可用 (http://%s:%s), 只是没有接管局域网设备。\n' "$(lan_ip)" "$ZP_MIXED"
            ;;
    esac
    printf '  设备名   %s\n' "$MODEL"
    printf '  固件     %s · 包管理器 %s\n' "$OS_NAME" "${PKG_MGR:-未知}"
    # BTF 是这次装机**自动补上**的时候要专门说一句 (用户没做任何事, 但机器上多装了几 MB):
    # 不补上就写清"还是不能用, 为什么", 以及它只关系到未来的性能档。
    if [ "$BTF_HOW" = "feed" ] || [ "$BTF_HOW" = "panel" ]; then
        printf '  性能档   已自动补上内核 BTF (%s: %s)\n' \
            "$( [ "$BTF_HOW" = "feed" ] && printf '本机软件源' || printf '面板分发' )" "$BTF_PATH"
    elif [ "${NET_EBPF:-0}" != "1" ]; then
        printf '  性能档   eBPF 那一档还不能用: %s\n' "${CAPS_WHY_EBPF:-内核条件不满足}"
        printf '           %s\n' "(只影响未来的直连旁路性能模式; 当前数据面一个字节都不受影响)"
    fi
    # 性能模式 (eBPF / dae) 一句话: 能不能开。开关在面板 / 本机界面上, 这里只报告这台机器
    # 有没有那个底子 —— 免得用户找了一圈才发现"这台固件根本开不了"。
    if [ "${PERF_CAP:-0}" = "1" ]; then
        printf '  性能模式 可以开 (内核态 eBPF / dae): 面板与本机界面上的开关一键切换\n'
    else
        printf '  性能模式 这台机器开不了: %s\n' "${PERF_WHY:-内核条件不满足}"
    fi
    case "${ACTIVE_MODE:-none}" in
        ebpf)     printf '  模式     内核态 eBPF (性能模式, dae) —— 含路由器自身\n' ;;
        tun)      printf '  模式     TUN 全屋透明代理 (含路由器自身)\n' ;;
        tproxy)   printf '  模式     tproxy 全屋透明代理 (本机自身流量除外)\n' ;;
        redirect) printf '  模式     iptables REDIRECT 局域网 TCP (不含 UDP 与本机自身)\n' ;;
        *)        printf '  模式     未生效 (只有本机代理端口可用)\n' ;;
    esac
    case "${COVERED:-none}" in
        full)    _cov_text="全屋设备 + 路由器自身" ;;
        lan)     _cov_text="全屋设备 (路由器自身除外)" ;;
        lan_tcp) _cov_text="局域网 TCP (不含 UDP)" ;;
        *)       _cov_text="未接管" ;;
    esac
    printf '  覆盖     %s\n' "$_cov_text"
    if [ "$NET_IPV6" = "1" ]; then
        printf '  IPv6     已一并接管 (局域网设备的 v6 流量也走代理)\n'
    else
        printf '  IPv6     %s未接管%s —— %s\n' "$C_Y" "$C_R" "${CAPS_WHY_IPV6:-这一档数据面覆盖不到 v6}"
    fi
    if [ -n "$TUN_HEALED" ]; then
        printf '  调整     这台固件上 auto-redirect 会让 tun 起不来, 已去掉, 并补上它本该写的防火墙放行\n'
        printf '           %s\n' "要重新试它: 把 /etc/zeroproxy/caps 里的 autoredirect 改成 1 后重跑安装命令"
    fi
    if [ -n "$DEGRADED" ]; then
        printf '  分流     降级模式 (未拿到 GeoIP/GeoSite 数据): 全部流量走节点\n'
        printf '           %s\n' "面板恢复后会自动切回「智能分流」(国内直连 + 广告拦截)"
    else
        printf '  分流     智能分流 (国内直连 + 广告拦截, 其余走代理)\n'
    fi
    printf '  管理     面板「客户端」页可看状态、开关、改分流、移除设备\n'
    printf '  网页管理 在路由器上执行 zeroproxy ui, 用打印出来的地址打开\n'
    printf '  本机命令 zeroproxy status | on | off | ui | geo | log | uninstall\n'
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
    install_zpcore
    install_ui
    verify
    report_up
    finish
}

main "$@"
