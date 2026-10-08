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
# 固件自己的 Web 服务发不出页面时用的兜底 httpd (见 install_ui)
ZP_INIT_UI=/etc/init.d/zeroproxy-ui
ZP_CLI=/usr/bin/zeroproxy
ZP_SVC=zeroproxy

# 内核健康检查用的本机控制口 (与 config.yaml 的 external-controller 一致)
ZP_API=127.0.0.1:9090
# 代理端口 (config.yaml 的 mixed-port)
ZP_MIXED=7890

TLS_OPTS=""
ARCH=""
#: 最近一次带状态码的请求结果 (http_fetch_to 会写它)
HTTP_CODE=""
DEPENDENCY_NOTE=""
ACTIVE_MODE=""
# 面板是否提供分流数据库接口 (/c/geo)。空 = 没问过 (更新模式), true = 有
PANEL_GEO=""
# 非空 = 这次只能装降级配置 (面板暂时给不出分流数据库), 结尾要如实说明
DEGRADED=""
# 设备凭据与配对结果 (set -u 下必须预置: 只有在真的走过那条分支时才会被赋值)
DEV_ID=""
DEV_SECRET=""
DEV_NAME=""
PAIR_ERROR=""

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
# 说明性的一行 (既不是成功, 也不是警告)。什么时候用它: 某条**用不到**的回退路径不可用时
# —— 例如有 TUN 的机器上 tproxy 模块装不上。那件事是真的, 但把它写成 "!" 会让人以为
# 安装出了问题 (真机反馈里就是这么被读的)。
note() { printf '  · %s\n' "$*"; }
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
    _f="$1"
    [ -s "$_f" ] || return 0
    _size="$(wc -c < "$_f" 2>/dev/null | tr -d ' ' || true)"
    [ "${_size:-0}" -lt 4096 ] || return 0
    sed -n '1,4p' "$_f" 2>/dev/null | sed 's/^/      /' >&2 || true
}

# 下载进度: 路由器上没有任何工具会替你打这个 (uclient-fetch 全程静默), 而 20 MB 在
# 4 Mbps 的线路上要 40 秒。中间一行输出都没有, 用户就会以为卡死了 —— 真机反馈里
# "一直卡在下载代理内核"就是这么来的。后台小循环每 5 秒读一次文件大小, 有增长才报。
PROGRESS_PID=""
start_progress() {
    _file="$1"; _label="${2:-下载中}"
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
            # 每 5 秒无条件报一次: 速率掉下来 (或一直是 0) 也看得见 —— 这正是
            # "卡住"与"慢"的区别所在。
            printf '  … %s %s KB (%s KB/s)\n' "$_label" "$((_now / 1024))" "$_kbps"
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
    OS_NAME="OpenWrt $(sed -n "s/^DISTRIB_RELEASE=['\"]\(.*\)['\"].*/\1/p" /etc/openwrt_release 2>/dev/null || true)"
    [ "$OS_NAME" != "OpenWrt " ] || OS_NAME="OpenWrt"
    KERNEL="$(uname -r)"
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
    ok "设备: $MODEL · $ARCH · $OS_NAME (内核 $KERNEL)"

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
pkg_install() {
    if command -v apk >/dev/null 2>&1; then
        apk add "$1" >/dev/null 2>&1
    elif command -v opkg >/dev/null 2>&1; then
        opkg install "$1" >/dev/null 2>&1
    else
        return 127
    fi
}
pkg_update() {
    if command -v apk >/dev/null 2>&1; then
        apk update >/dev/null 2>&1
    elif command -v opkg >/dev/null 2>&1; then
        opkg update >/dev/null 2>&1
    else
        return 127
    fi
}

# tproxy 到底能不能用 —— 不看包装没装上, 直接问内核: 加一条 tproxy 规则成不成。
# 为什么不用"模块在不在": tproxy 有可能被编进内核 (那时 /sys/module 里没有它), 而
# `nft` 会把模块按需加载 —— 真加一条规则才是这件事的最终判据。探针用完就撤掉。
tproxy_ok() {
    # 模块已经在 (内核里编进去的用前两个都查不到, 但那极少见) —— 这条路直接算有。
    [ -d /sys/module/nft_tproxy ] && return 0
    grep -q '^nft_tproxy ' /proc/modules 2>/dev/null && return 0
    command -v nft >/dev/null 2>&1 || return 1
    nft add table inet zp_probe 2>/dev/null || return 1
    if ! nft add chain inet zp_probe c '{ type filter hook prerouting priority -150; policy accept; }' 2>/dev/null; then
        nft delete table inet zp_probe 2>/dev/null || true
        return 1
    fi
    if nft add rule inet zp_probe c meta l4proto tcp tproxy to :1 2>/dev/null; then
        nft delete table inet zp_probe 2>/dev/null || true
        return 0
    fi
    nft delete table inet zp_probe 2>/dev/null || true
    return 1
}

install_deps() {
    step "准备网络内核模块"
    # 软件源不可用 / 源对不上内核, 在路由器上都很常见, 不算致命 —— 模块可能本来就在。
    pkg_update || true
    pkg_install kmod-tun || true
    modprobe tun 2>/dev/null || true
    _tun=0
    if [ -c /dev/net/tun ]; then _tun=1; fi

    _tproxy=0
    if tproxy_ok; then _tproxy=1; fi
    if [ "$_tproxy" = "0" ]; then
        pkg_install kmod-nft-tproxy || true
        modprobe nft_tproxy 2>/dev/null || true
        if tproxy_ok; then _tproxy=1; fi
    fi
    # nft 是 tproxy 回退与 auto-redirect 的前提 (fw4 自带, 这里只确认)
    command -v nft >/dev/null 2>&1 || warn "没有 nft 命令: 若 TUN 也不可用, 透明代理将无法生效"

    if [ "$_tun" = "1" ]; then
        ok "TUN 可用 (kmod-tun 已就绪)"
        # 有 TUN 就不需要 tproxy。装不上只是"少了一条用不到的回退", 说清楚即可。
        [ "$_tproxy" = "1" ] || note "tproxy 回退不可用 (这台固件的内核 / 软件源里没有 nft_tproxy) —— TUN 模式下用不到它, 不影响任何功能"
        return 0
    fi
    # 没有 TUN: tproxy 就是唯一的路, 它不可用才是真问题。
    DEPENDENCY_NOTE="tun-missing"
    if [ "$_tproxy" = "1" ]; then
        warn "本机没有 TUN 设备, 稍后改用 tproxy 模式 (全屋设备生效, 路由器自身流量除外)"
    else
        warn "TUN 与 tproxy 都不可用 —— 透明代理可能无法生效
  手动补一次: kmod 这两个包 (apk add kmod-tun kmod-nft-tproxy; 24.10 及更早用 opkg install)"
        DEPENDENCY_NOTE="tun-tproxy-missing"
    fi
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
    start_progress "$2" "已下载"
    if http_fetch_to "$1" "$2" "${3:-900}" "${4:-0}" "$CORE_RATE_WINDOW"; then
        _rc=0
    else
        _rc=1
    fi
    stop_progress
    DL_SECONDS=$(( $(date +%s 2>/dev/null || echo 0) - DL_START ))
    [ "$DL_SECONDS" -gt 0 ] 2>/dev/null || DL_SECONDS=1
    DL_BYTES="$(wc -c < "$2" 2>/dev/null | tr -d ' ' || true)"
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
}

# 落盘前的校验: 大小像内核, 且 (面板给了摘要时) sha256 对得上。
# 为什么还要哈希: 直连镜像是第三方 —— 它们中间任何一跳都可能给你别的东西。
core_verify() {
    _size="$(wc -c < "$_tmp" 2>/dev/null | tr -d ' ' || true)"
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
        _size="$(wc -c < "$_tmp" 2>/dev/null | tr -d ' ' || true)"
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
    if core_reusable; then
        ok "内核已存在且可执行, 跳过下载"
        return 0
    fi
    rm -f "$ZP_BIN"
    _tmp="$ZP_DIR/.mihomo.gz"
    mkdir -p "$ZP_DIR"

    # 取内核两条路: ① 面板直传 (面板把内核缓存好再给, 只访问一个地址);
    #              ② 直连镜像 (面板把它自己那张镜像表 + 官方直链一起给出来)。
    # 默认先走 ① —— 但国内家宽到面板可能只有几十 KB/s, 而直连镜像往往快得多,
    # 所以 ① 有一个观察窗口 (CORE_PANEL_BUDGET), 太慢就让位给 ②。
    # 面板说 prefer=mirror (ZP_ROUTER_SOURCE) 时顺序反过来。
    CORE_STARTED="$(date +%s 2>/dev/null || echo 0)"
    core_read_panel
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
    if ! "$ZP_DIR/agent.sh" config > "$_tmp" 2>/dev/null; then
        rm -f "$_tmp"
        # 没有配对码 (更新模式) 时不要试图重配: 那会在面板上多出一台设备
        [ -n "$ZP_CODE" ] || die "拉取配置失败 —— 面板拒绝了这台设备的凭据, 或面板暂时不可达。
  请到面板「客户端」重新生成一条带配对码的安装命令来完成重新接入。"
        # 凭据被拒 (403) 是最常见的"看起来莫名其妙"的失败: 面板上把这台设备移除过,
        # 或者路由器上留的是另一台面板发的凭据。本地文件看不出问题, 只有真的去拉一次
        # 才知道 —— 所以不在这里猜, 直接用本次命令里的配对码重新接入再试。
        warn "面板拒绝了这台设备的凭据 (可能已在面板上移除, 或凭据来自另一台面板)"
        step "用本次配对码重新接入"
        if ! do_pair; then
            die "重新接入失败: $PAIR_ERROR
  请回面板「客户端」重新生成一条安装命令, 再在路由器上跑一次。"
        fi
        ok "已重新接入: $DEV_NAME ($DEV_ID)"
        "$ZP_DIR/agent.sh" config > "$_tmp" 2>/dev/null \
            || die "重新接入后仍然拉不到配置, 请回面板确认已有可用节点"
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

install_geo() {
    step "准备分流数据库 (GeoIP / GeoSite)"
    if "$ZP_DIR/agent.sh" geo force >/dev/null 2>&1; then
        ok "分流数据库就绪 ($(wc -c < "$ZP_DIR/geoip.metadb" 2>/dev/null | tr -d ' ') + $(wc -c < "$ZP_DIR/geosite.dat" 2>/dev/null | tr -d ' ') 字节)"
        return 0
    fi
    if geo_ok; then
        warn "本次刷新失败, 继续用本机已有的分流数据库"
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
    warn "按降级配置安装: 不含国内直连与广告拦截, 其余照常走节点"
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
    die "拉取/校验配置失败, 请回面板确认已有可用节点"
}

write_files() {
    step "写入运行文件"
    mkdir -p "$ZP_DIR"

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

log() { logger -t zeroproxy-agent "$*"; }

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
    for _f in $(server_files); do
        _b="$(field_of "$_f" base)"
        [ -n "$_b" ] || continue
        _got=1
        for _g in $_need; do
            _tmp="$ZP_DIR/.geo-$$.part"
            if http_get_file "$_b/c/geo/$_g" > "$_tmp" 2>/dev/null && [ -s "$_tmp" ]; then
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

# 生成最终配置并打到标准输出。
#   单服务器: 直接用面板给的整份配置 (已验证的老路径)
#   多服务器: 取第一台的骨架, 把 providers 与组的 use 填上 (按行替换, 不做 YAML 解析)
build_config() {
    migrate_servers
    _first="$(first_server)"
    [ -n "$_first" ] || return 1
    _b="$(field_of "$_first" base)"; _i="$(field_of "$_first" id)"; _k="$(field_of "$_first" secret)"
    _n="$(count_servers)"
    # 没有分流数据库就不能要 geo 规则 (面板知道这件事, 会给一份降级规则)。判据必须是
    # 本机文件: 数据库在路由器上, 面板看不到它。
    _geo="1"; geo_ok || _geo="0"
    if [ "$_n" -le 1 ]; then
        http_get "$_b/c/sub/$_i?k=$_k&format=clash&rules=smart&geo=$_geo"
        return $?
    fi
    _skel="$(http_get "$_b/c/sub/$_i?k=$_k&format=skeleton&rules=smart&geo=$_geo")" || return 1
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
# 大文件下载 (分流数据库 4 MB): 30 秒的接口超时对它是太紧了, 慢宽带会直接失败
http_get_file() {
    if command -v curl >/dev/null 2>&1; then curl -fsSk -m 600 "$1" 2>/dev/null
    else uclient-fetch -q --no-check-certificate -T 600 -O - "$1" 2>/dev/null \
        || wget -q --no-check-certificate -T 600 -O - "$1" 2>/dev/null
    fi
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
    # 分流数据库不在就先补一次: 上一次装机降级 (面板取不到上游) 或被人清过时, 这里
    # 自动回到完整分流 —— 用户不用再登录路由器做任何事。
    ensure_geo >/dev/null 2>&1 || true
    # 原子替换: 新配置先落 .new, 校验通过才替换, 失败保留旧配置继续用。
    build_config > "$CONF.new" 2>/dev/null || { rm -f "$CONF.new"; return 1; }
    # 单服务器模式带内联 proxies, 多服务器模式带 proxy-providers —— 唯一共同的锚点是
    # 策略组, 所以用它判断"这看起来像一份配置"。
    grep -q '^proxy-groups:' "$CONF.new" || { rm -f "$CONF.new"; return 1; }
    /etc/zeroproxy/mihomo -t -d "$ZP_DIR" -f "$CONF.new" >/dev/null 2>&1 \
        || { rm -f "$CONF.new"; log "新配置校验失败, 保留原配置"; return 1; }
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

# 命令行模式: agent.sh config 打印一份合并后的配置 (安装脚本与 CLI 都用它);
# agent.sh once 只跑一轮心跳 (排查用)。默认无参数 = 常驻循环。
case "${1:-}" in
    config) migrate_servers; build_config; exit $? ;;
    geo)    migrate_servers; ensure_geo "${2:-}"; exit $? ;;
    once)   RUN_ONCE=1 ;;
esac

LAST_REV=""
LAST_PULL=0
FAILS=0
while true; do
    migrate_servers
    # 多服务器: **每一台都要收到心跳**。
    # 早期版本只向第一台上报, 于是"没被上报的那台"在面板上永远显示离线 —— 用户加完
    # 第二台服务器, 看到的正是第二台一直是同步中 / 离线 (真机反馈)。
    #
    # 总开关取"任一为关则关": 任一面板把它关掉, 全屋就断; 在那台上再打开即恢复。
    # 新设备默认就是"开", 所以只有"没人碰过"的面板不会干扰。
    DESIRED_ALL="true"
    REV=""
    # 管理界面地址 (带令牌) 只算一次 —— 每台面板都收到同一份, 面板据此给一个可点的入口
    UI_URL_REPORT="$(ui_url 2>/dev/null || true)"
    for _f in $(server_files); do
        _b="$(field_of "$_f" base)"; _i="$(field_of "$_f" id)"; _k="$(field_of "$_f" secret)"
        [ -n "$_b" ] || continue
        BODY='{"device":"'"$_i"'","k":"'"$_k"'","version":"'"$ZP_VERSION"'"'
        if core_up; then BODY="$BODY"',"actual":true'; else BODY="$BODY"',"actual":false'; fi
        [ -n "$UI_URL_REPORT" ] && BODY="$BODY"',"ui":"'"$UI_URL_REPORT"'"'
        [ -n "$LAST_REV" ] && BODY="$BODY"',"rev":"'"$LAST_REV"'"'
        BODY="$BODY"'}'
        RESP="$(http_post "$_b/c/report" "$BODY" || true)"
        if [ -z "$RESP" ]; then
            FAILS=$((FAILS + 1))
            continue
        fi
        _d="$(json_get_bool "$RESP" desired)"
        [ -n "$_d" ] || _d=true
        [ "$_d" = "false" ] && DESIRED_ALL="false"
        # 配置版本取第一台能应答的 (配置内容各台不同, 用哪台的 rev 都只是"变了就重拉")
        [ -z "$REV" ] && REV="$(json_get "$RESP" rev)"
    done

    if [ -z "$REV" ]; then
        # 一台都没应答: 保持现状而不是把代理关掉 —— 断网时"维持可用"比"忠于面板"重要
        [ $((FAILS % 20)) -eq 1 ] && log "面板不可达 (第 $FAILS 次), 保持当前状态"
        sleep "$SLEEP"
        continue
    fi
    FAILS=0
    DESIRED="$DESIRED_ALL"

    if [ "$DESIRED" = "true" ] && ! core_up; then
        log "面板要求开启, 启动内核"
        switch_core on
    elif [ "$DESIRED" = "false" ] && core_up; then
        log "面板要求关闭, 停止内核"
        switch_core off
    fi

    _now="$(date +%s)"
    if { [ -n "$REV" ] && [ "$REV" != "$LAST_REV" ]; } || [ $((_now - LAST_PULL)) -ge 21600 ]; then
        if apply_config; then LAST_REV="$REV"; LAST_PULL="$_now"; fi
    fi
    [ -n "${RUN_ONCE:-}" ] && exit 0
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
ZP_VERSION="__ZP_CLIENT_VERSION__"
SERVERS="$ZP_DIR/servers"
FIRST="$(ls "$SERVERS"/*.json 2>/dev/null | head -n1)"

field_of() { sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$1" | head -n1; }
key_of() {
    printf '%s' "$1" | sed -e 's#^https*://##' -e 's/[^A-Za-z0-9]/_/g' | cut -c1-32
}
servers() { ls "$SERVERS"/*.json 2>/dev/null; }

running() { /etc/init.d/zeroproxy running >/dev/null 2>&1 && echo yes || echo no; }

case "${1:-status}" in
    status)
        echo "内核:  $( [ "$(running)" = yes ] && echo 运行中 || echo 已停止 )"
        echo "服务器 ($(servers | wc -l | tr -d ' ') 台):"
        for _f in $(servers); do
            printf '  %-16s %s\n' "$(key_of "$(field_of "$_f" base)")" "$(field_of "$_f" base)"
        done
        [ -c /dev/net/tun ] && echo "模式:  TUN (全屋透明)" || echo "模式:  tproxy (全屋透明, 本机自身流量除外)"
        if command -v curl >/dev/null 2>&1; then
            curl -fsS -m 8 "http://127.0.0.1:9090/version" 2>/dev/null | head -c 200 && echo
        fi
        ;;
    servers)
        echo "服务器清单 ($ZP_DIR/servers):"
        for _f in $(servers); do
            printf '  %-16s %s  (设备 %s)\n' "$(key_of "$(field_of "$_f" base)")" \
                "$(field_of "$_f" base)" "$(field_of "$_f" id)"
        done
        ;;
    add)
        # 从面板复制一行 (安装命令里的那个 URL), 粘进来即可 —— 不用再走一次完整安装。
        _url="${2:-}"
        [ -n "$_url" ] || { echo "用法: zeroproxy add https://面板:8899/c/<配对码>"; exit 2; }
        case "$_url" in
            http*://*/c/*) ;;
            *) echo "这看起来不是一个面板链接。请到面板「客户端」生成安装命令, 复制其中 https://…/c/… 这一段。"; exit 2 ;;
        esac
        _base="${_url%/c/*}"
        _code="${_url##*/c/}"
        _key="$(key_of "$_base")"
        mkdir -p "$SERVERS"
        echo "正在与 $_base 配对…"
        _model="$(cat /tmp/sysinfo/model 2>/dev/null || uname -m)"; _hn="$(cat /proc/sys/kernel/hostname 2>/dev/null || echo router)"
        _model="$(printf %s "$_model" | tr -d '"')"
        _body='{"code":"'"$_code"'","kind":"router","model":"'"$_model"'","hostname":"'"$_hn"'","arch":"'"$(uname -m)"'","os":"OpenWrt","version":"'"$ZP_VERSION"'"}'
        if command -v curl >/dev/null 2>&1; then
            _resp="$(curl -fsSk -m 30 -H 'Content-Type: application/json' --data "$_body" "$_base/c/pair" 2>/dev/null)"
        else
            _resp="$(uclient-fetch -q --no-check-certificate -O - --post-data "$_body" "$_base/c/pair" 2>/dev/null)"
        fi
        _id="$(printf '%s' "$_resp" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
        _sec="$(printf '%s' "$_resp" | sed -n 's/.*"secret"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
        if [ -z "$_id" ] || [ -z "$_sec" ]; then
            echo "配对失败: $(printf '%s' "$_resp" | sed -n 's/.*"error"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
            echo "配对码是一次性的, 请回面板重新生成一条安装命令后复制其中的链接。"
            exit 1
        fi
        cat > "$SERVERS/$_key.json" <<EOF
{
  "base": "$_base",
  "id": "$_id",
  "secret": "$_sec",
  "name": "$_base"
}
EOF
        chmod 600 "$SERVERS/$_key.json"
        echo "已接入: $_key ($_base)"
        # 注意把"重建配置"与"重启内核"分开判断: 重启失败不该把已经写好的配置撤掉
        # (内核本来就是 procd 常驻的, 它自己会重启)。
        if "$ZP_DIR/agent.sh" config > "$ZP_DIR/config.yaml.new" 2>/dev/null \
            && "$ZP_DIR/mihomo" -t -d "$ZP_DIR" -f "$ZP_DIR/config.yaml.new" >/dev/null 2>&1; then
            mv "$ZP_DIR/config.yaml.new" "$ZP_DIR/config.yaml"
            /etc/init.d/zeroproxy restart >/dev/null 2>&1 || true
            echo "配置已更新并重载 (现在共 $(servers | wc -l | tr -d ' ') 台服务器)"
        else
            rm -f "$ZP_DIR/config.yaml.new"
            echo "配置更新失败, 旧配置仍在运行 (看 zeroproxy log)"
        fi
        ;;
    drop)
        _key="${2:-}"
        _file="$SERVERS/$_key.json"
        [ -f "$_file" ] || { echo "没有这台服务器: $_key (用 zeroproxy servers 看清单)"; exit 2; }
        mv "$_file" "$_file.removed"
        echo "已移除 $_key, 正在重建配置…"
        if "$ZP_DIR/agent.sh" config > "$ZP_DIR/config.yaml.new" 2>/dev/null \
            && "$ZP_DIR/mihomo" -t -d "$ZP_DIR" -f "$ZP_DIR/config.yaml.new" >/dev/null 2>&1; then
            mv "$ZP_DIR/config.yaml.new" "$ZP_DIR/config.yaml"
            /etc/init.d/zeroproxy restart >/dev/null 2>&1
            rm -f "$_file.removed"
            echo "完成 (剩余 $(servers | wc -l | tr -d ' ') 台服务器)"
        else
            mv "$_file.removed" "$_file"
            rm -f "$ZP_DIR/config.yaml.new"
            echo "重建失败, 已回滚 —— 这台服务器还在用"
        fi
        echo "提示: 面板上的设备记录不会自动删除, 需要的话在那边一并移除。"
        ;;
    refresh)
        echo "重新拉取全部服务器的节点…"
        if "$ZP_DIR/agent.sh" config > "$ZP_DIR/config.yaml.new" 2>/dev/null \
            && "$ZP_DIR/mihomo" -t -d "$ZP_DIR" -f "$ZP_DIR/config.yaml.new" >/dev/null 2>&1; then
            mv "$ZP_DIR/config.yaml.new" "$ZP_DIR/config.yaml"
            /etc/init.d/zeroproxy restart >/dev/null 2>&1
            echo "完成"
        else
            rm -f "$ZP_DIR/config.yaml.new"
            echo "拉取失败, 旧配置仍在运行 (看 zeroproxy log)"
            exit 1
        fi
        ;;
    on|off)
        # 本地开关同样以面板为准: 告诉面板改期望状态, agent 下一轮生效
        ON=$([ "$1" = on ] && echo true || echo false)
        [ -n "$FIRST" ] || { echo "还没有接入任何服务器"; exit 1; }
        ID="$(field_of "$FIRST" id)"
        KEY="$(field_of "$FIRST" secret)"
        BODY='{"device":"'"$ID"'","k":"'"$KEY"'","set_desired":'"$ON"'}'
        if command -v curl >/dev/null 2>&1; then
            curl -fsSk -m 15 -H 'Content-Type: application/json' --data "$BODY" "$(field_of "$FIRST" base)/c/report" >/dev/null
        else
            uclient-fetch -q --no-check-certificate -O - --post-data "$BODY" "$(field_of "$FIRST" base)/c/report" >/dev/null
        fi
        echo "已请求面板把总开关设为「$1」, 约 15 秒内生效 (zeroproxy status 查看)"
        ;;
    ui)
        # 端口在 ui.port 里 (安装时定下的): 空 = 固件自己的 Web 服务, 有值 = 自带 httpd。
        _port="$(cat "$ZP_DIR/ui.port" 2>/dev/null)"
        [ -n "$_port" ] && _port=":$_port"
        _ip="$(uci get network.lan.ipaddr 2>/dev/null || echo 192.168.1.1)"
        echo "http://$_ip$_port/cgi-bin/zeroproxy?k=$(cat "$ZP_DIR/ui.token" 2>/dev/null)"
        [ -s "$ZP_DIR/ui.token" ] || echo "(令牌文件不见了 —— 重跑一次安装命令会重新生成)"
        echo "(打开一次即可; 之后同一浏览器不用再带令牌)"
        ;;
    log)        logread -e zeroproxy | tail -n "${2:-40}" ;;
    geo)
        # 重新取分流数据库 (面板换了 / 数据更新了, 不用重跑安装)
        "$ZP_DIR/agent.sh" geo force && echo "分流数据库已更新" \
            || echo "取分流数据库失败 (面板不可达, 或面板自己取不到上游数据)"
        ;;
    update)
        echo "重新执行面板上的安装命令即可升级 (配置与凭据会保留)"
        ;;
    uninstall)
        # 先停 agent 再停内核: 反过来的话 agent 会在内核停掉后立刻把它拉起来
        /etc/init.d/zeroproxy-agent stop >/dev/null 2>&1 || true
        /etc/init.d/zeroproxy-agent disable >/dev/null 2>&1 || true
        /etc/init.d/zeroproxy-ui stop >/dev/null 2>&1 || true
        /etc/init.d/zeroproxy-ui disable >/dev/null 2>&1 || true
        /etc/init.d/zeroproxy stop >/dev/null 2>&1 || true
        /etc/init.d/zeroproxy disable >/dev/null 2>&1 || true
        nft delete table inet zp_router 2>/dev/null || true
        killall -HUP dnsmasq 2>/dev/null || true
        rm -rf "$ZP_DIR" /etc/init.d/zeroproxy /etc/init.d/zeroproxy-agent /etc/init.d/zeroproxy-ui /usr/bin/zeroproxy
        echo "已卸载。这台设备在面板上仍然存在, 请在面板「客户端」里一并移除。"
        ;;
    *) echo "用法: zeroproxy [status|ui|servers|add <链接>|drop <键>|refresh|geo|on|off|log|uninstall]" ;;
esac
CLIEOF
    chmod 755 "$ZP_CLI"
    # 版本号在 heredoc 里是占位符 (带引号的 heredoc 不做变量替换), 落盘后再替换一次 ——
    # 免得"agent 上报的版本"和"面板显示的客户端版本"各写一个常量, 改一处漏一处。
    # 用临时文件 + mv 而不是 sed -i: BSD sed 的 -i 要跟备份后缀, 演练时跑在 macOS 上。
    # 注意 chmod 要在替换之后: mv 过来的是一个新文件, 权限是新建时的默认值 (0644) ——
    # 少这一步 agent 与 CLI 就不可执行, 安装会以 "Permission denied" 结束 (演练抓到过)。
    for _f in "$ZP_DIR/agent.sh" "$ZP_CLI"; do
        sed "s/__ZP_CLIENT_VERSION__/$ZP_CLIENT_VERSION/g" "$_f" > "$_f.ver" \
            && { chmod 755 "$_f.ver"; mv "$_f.ver" "$_f"; } || rm -f "$_f.ver"
    done
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
    fetch_config "$ZP_CONF" || config_failure
    ok "配置已写入 $ZP_CONF"
    ok "已写入 $ZP_INIT / $ZP_AGENT_INIT / $ZP_DIR/agent.sh / $ZP_CLI"
}

# ---------------------------------------------------------------- 网页界面
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

ui_stop_local_httpd() {
    /etc/init.d/zeroproxy-ui stop >/dev/null 2>&1 || true
    /etc/init.d/zeroproxy-ui disable >/dev/null 2>&1 || true
    rm -f "$ZP_INIT_UI"
}

# 固件的 Web 服务发不出页面时的兜底: 自带的 busybox httpd —— 它的约定很简单
# ("url 以 /cgi-bin/ 开头就当 cgi 执行"), 与固件自己那套 nginx/uhttpd 无关, 所以在哪台
# 机器上都一样。只绑**局域网地址**: 每多一个监听口都是事实, 所以绝不退化成 0.0.0.0
# (那等于把管理界面挂到 WAN 上)。授权照旧只认界面令牌, 与走固件 Web 服务时同一条路。
ui_start_local_httpd() {
    _bb="$(ui_busybox 2>/dev/null || true)"
    [ -n "$_bb" ] || return 1
    # --list 不是所有 busybox 都给; 给的话就顺手确认 httpd 这个 applet 编进去了。
    if "$_bb" --list >/dev/null 2>&1; then
        "$_bb" --list | grep -qx httpd || return 1
    fi
    _root="$ZP_DIR/www"
    [ -s "$_root/cgi-bin/zeroproxy" ] || return 1
    cat > "$ZP_INIT_UI" <<'UIINITEOF'
#!/bin/sh /etc/rc.common
# ZeroProxy 网页管理界面 (固件没有把 /cgi-bin/ 交给脚本时用的兜底 httpd)。
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
    [ -x "$ZP_DIR/www/cgi-bin/zeroproxy" ] || return 0
    _ip="$(lan_ip)"
    [ -n "$_ip" ] || return 0
    procd_open_instance
    procd_set_param command "$BB" httpd -f -p "$_ip:$UI_PORT" -h "$ZP_DIR/www"
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
    # 起不来说明这台设备上没有可用的 busybox httpd —— 收干净, 不留一个跑不起来的服务。
    ui_stop_local_httpd
    return 1
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
    for f in index.html app.js; do
        if ! http_get "$ZP_BASE/c/ui/$f" > "$_stage/zeroproxy/$f" 2>/dev/null; then
            warn "面板没有提供界面文件 (面板版本较旧?), 跳过网页界面"
            rm -rf "$_stage"
            return 0
        fi
    done
    http_get "$ZP_BASE/c/ui/cgi" > "$_stage/cgi-bin/zeroproxy" 2>/dev/null || true
    chmod 755 "$_stage/cgi-bin/zeroproxy"
    if [ ! -s "$_stage/zeroproxy/index.html" ]; then
        warn "面板没有提供界面文件 (面板版本较旧?), 跳过网页界面"
        rm -rf "$_stage"
        return 0
    fi
    if [ -d /www ]; then
        mkdir -p /www/zeroproxy /www/cgi-bin 2>/dev/null || true
        cp "$_stage/zeroproxy/index.html" "$_stage/zeroproxy/app.js" /www/zeroproxy/ 2>/dev/null || true
        cp "$_stage/cgi-bin/zeroproxy" /www/cgi-bin/zeroproxy 2>/dev/null || true
        chmod 755 /www/cgi-bin/zeroproxy 2>/dev/null || true
    fi

    # LuCI 菜单 / 权限 / 承载页 —— 只有装了 LuCI 才写, 否则上面那个地址一样能用
    _luci=0
    if [ -d /usr/share/luci/menu.d ]; then
        _luci=1
        mkdir -p /www/luci-static/resources/view/zeroproxy /usr/share/rpcd/acl.d
        http_get "$ZP_BASE/c/ui/status.js" > /www/luci-static/resources/view/zeroproxy/status.js 2>/dev/null || true
        http_get "$ZP_BASE/c/ui/menu.json" > /usr/share/luci/menu.d/luci-app-zeroproxy.json 2>/dev/null || true
        http_get "$ZP_BASE/c/ui/acl.json" > /usr/share/rpcd/acl.d/luci-app-zeroproxy.json 2>/dev/null || true
        # 两道缓存都要清: rpcd 缓存 ACL, LuCI 把菜单索引缓存在 /tmp/luci-indexcache*
        # (只 reload rpcd 不够 —— 菜单是 LuCI 自己缓存的那份索引, 这是"菜单不出现"
        # 最常见的原因)
        /etc/init.d/rpcd reload >/dev/null 2>&1 || /etc/init.d/rpcd restart >/dev/null 2>&1 || true
        rm -f /tmp/luci-indexcache* /tmp/luci-modulecache/* 2>/dev/null || true
    fi

    # 谁把页面发出去? 先试固件自己的 Web 服务 (80 端口, 不开新端口), 发不出来再起自带
    # 的 httpd。两条路都要**当场验过**才算数。
    : > "$ZP_DIR/ui.port"
    if [ -d /www ] && { ui_probe "http://127.0.0.1/cgi-bin/zeroproxy" || ui_probe "http://$(lan_ip)/cgi-bin/zeroproxy"; }; then
        if [ "$_luci" = "1" ]; then
            ok "管理界面已装好 (LuCI 菜单: 服务 → ZeroProxy)"
        else
            ok "管理界面已装好"
        fi
        # 上一次可能是靠自带 httpd 发的 (固件升级后 /cgi-bin/ 又能用了): 收掉它,
        # 不留一个多余的监听口。
        if [ -f "$ZP_INIT_UI" ]; then
            ui_stop_local_httpd
        fi
    elif ui_start_local_httpd; then
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

    ACTIVE_MODE="tproxy"
    if [ -c /dev/net/tun ]; then
        # 等内核把设备建出来: mihomo 启动到 zp-tun 出现之间有十几秒 —— 只查一次会
        # 误判成"没建出来", 于是错误地退回 tproxy 并把那套 nft 规则也加上
        # (真机上就是这么发生的: tun 明明是好的, 却又叠了一层 tproxy)。
        _wait=0
        while [ "$_wait" -lt 30 ]; do
            ip link show zp-tun >/dev/null 2>&1 && break
            sleep 1
            _wait=$((_wait + 1))
        done
        if ip link show zp-tun >/dev/null 2>&1; then
            ACTIVE_MODE="tun"
            # 清掉可能被误加上的 tproxy 规则 (两者同时生效会互相打架)
            nft delete table inet zp_router 2>/dev/null || true
            ok "TUN 已建立: 全屋设备 (含路由器自身) 透明代理生效"
        else
            warn "等了 30 秒 TUN 设备仍未出现 (内核模块/权限问题), 改用 tproxy 模式"
            killall -HUP dnsmasq 2>/dev/null || true
            nft -f "$ZP_DIR/tproxy.nft" 2>/dev/null || true
        fi
    else
        warn "本机没有 TUN, 使用 tproxy 模式 (全屋设备生效, 路由器自身流量除外)"
        nft -f "$ZP_DIR/tproxy.nft" 2>/dev/null || true
    fi

    # 等节点就绪再测: provider 是内核启动后异步拉的, 立刻测一定失败 —— 那句
    # "出口测试未通过" 于是变成一条误导 (真机反馈里它一直挂着, 让人以为代理坏了)。
    # 判据是 mihomo 自己说 🚀 节点选择 现在选的是谁: 还是 DIRECT 就再等。
    if command -v curl >/dev/null 2>&1; then
        _w=0
        while [ "$_w" -lt 30 ]; do
            _now="$(curl -s -m 3 "http://127.0.0.1:9090/proxies/%F0%9F%9A%80%20%E8%8A%82%E7%82%B9%E9%80%89%E6%8B%A9" 2>/dev/null | sed -n 's/.*"now":"\([^"]*\)".*/\1/p')"
            [ -n "$_now" ] && [ "$_now" != "DIRECT" ] && break
            sleep 2
            _w=$((_w + 1))
        done
        [ -n "$_now" ] && ok "节点已就绪 (当前选中: $_now)"
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
    printf '  模式     %s\n' "$( [ "${ACTIVE_MODE:-tproxy}" = "tun" ] && echo 'TUN 全屋透明代理' || echo 'tproxy 全屋透明代理 (本机自身流量除外)' )"
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
    install_ui
    verify
    report_up
    finish
}

main "$@"
