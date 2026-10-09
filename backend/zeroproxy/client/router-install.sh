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
#: TUN 设备节点。Linux 上是 /dev/net/tun; 少数系统 (FreeBSD) 用 /dev/tun ——
#: 用 ZP_TUN_DEV 指过去即可。真正的判据仍然是"能不能建出设备", 这个值只决定去哪找。
TUN_DEV="${ZP_TUN_DEV:-/dev/net/tun}"

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
# 非空 = 这次靠自愈才把 TUN 建起来 (值说明改了哪一项), 结尾要告诉用户
TUN_HEALED=""
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
    _k="$(uname -r 2>/dev/null || true)"
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

# eBPF (dae) 能不能用 —— 本版本**只探不选**。
# 它的性能收益是量级的 (直连流量真旁路, 不过用户态), 但前提苛刻 (内核 >=5.17 + BTF) 且
# 多一个二进制要面板分发, 所以先把结论记进 caps, 让面板知道这台机器有没有性能模式的底子。
# 这一级不做任何实际改动 (只读内核版本与 BTF 节点), 所以探测本身没有副作用。
ebpf_ok() {
    PROBE_WHY=""
    if ! kernel_ge 5 17; then
        PROBE_WHY="内核 $(uname -r 2>/dev/null) 低于 5.17"
        return 1
    fi
    if [ ! -r /sys/kernel/btf/vmlinux ]; then
        PROBE_WHY="内核没有 BTF (/sys/kernel/btf/vmlinux 不存在)"
        return 1
    fi
    return 0
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
        printf '内核 %s + BTF 都在 —— 这一档技术上可用' "$(uname -r 2>/dev/null)"
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
caps_write() {
    _ar="${1:-1}"
    mkdir -p "$ZP_DIR" 2>/dev/null || true
    _oneline() { printf '%s' "$1" | tr -d '\r\n'; }
    {
        printf 'schema=2\n'
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
    if [ "$NET_TUN" = "1" ]; then set_datapath tun
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
    pkg_update || true
    pkg_install kmod-tun || true
    modprobe tun 2>/dev/null || true

    # 每一级都真做一次。探测只做可撤销的动作 (建设备再删 / 加规则再撤), 不改任何东西。
    if tun_ok; then NET_TUN=1; else CAPS_WHY_TUN="$PROBE_WHY"; fi
    if nft_ok; then NET_NFT=1; else CAPS_WHY_TPROXY="$PROBE_WHY"; fi
    if [ "$NET_NFT" = "1" ]; then
        if tproxy_ok; then
            NET_TPROXY=1
        else
            CAPS_WHY_TPROXY="$PROBE_WHY"
            # 模块可能只是没装/没加载: 补一次再试 (装不上就算了, 不算致命)
            pkg_install kmod-nft-tproxy || true
            modprobe nft_tproxy 2>/dev/null || true
            if tproxy_ok; then NET_TPROXY=1; CAPS_WHY_TPROXY=""; fi
        fi
    fi
    if redirect_ok; then NET_REDIRECT=1; else CAPS_WHY_REDIRECT="$PROBE_WHY"; fi
    if ebpf_ok; then NET_EBPF=1; else CAPS_WHY_EBPF="$PROBE_WHY"; fi

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
        *)
            DEPENDENCY_NOTE="no-datapath"
            warn "TUN / tproxy / iptables REDIRECT 三条路都没探通 —— 全屋透明代理这次不会生效"
            if [ -n "$CAPS_WHY_TUN" ]; then note "tun: $CAPS_WHY_TUN"; fi
            if [ -n "$CAPS_WHY_TPROXY" ]; then note "tproxy: $CAPS_WHY_TPROXY"; fi
            if [ -n "$CAPS_WHY_REDIRECT" ]; then note "redirect: $CAPS_WHY_REDIRECT"; fi
            note "本机的代理端口一直可用 (局域网设备手动把代理填成 $(lan_ip):$ZP_MIXED)"
            ;;
    esac
    if [ "$NET_EBPF" = "1" ]; then
        note "eBPF 数据面可用: $(ebpf_detail) —— 性能模式留给后续版本 (见设计文档 Phase 3)"
    else
        note "eBPF 数据面不可用: $(ebpf_detail)"
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
    # 面板要的那一版内核 —— 用来判断本机这份是不是该换了 (见 install_core)
    PANEL_CORE_VERSION="$(json_get "$_json" core_version)"
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
    # IPv6 那一半。**不能只做 v4**: 局域网设备从运营商那里拿到原生 v6, 而只接管 v4 的
    # 透明代理对 v6 是不存在的 —— 那些流量会直接出去 (真机上看起来一切正常, 但目标网站
    # 看到的是你的真实 v6 地址, 代理等于没装)。mihomo 自己的 `ipv6: false` 也挡不住它
    # (上游 issue #2254: "TUN interface does not disable IPv6 protocol stack"), 所以这里
    # 必须显式接管: 私有地址与链路本地先放行 (局域网互访 / 邻居发现), 其余进代理。
    set local6 {
        type ipv6_addr
        flags interval
        elements = { ::1/128, fc00::/7, fe80::/10, ff00::/8 }
    }
    chain pre {
        type filter hook prerouting priority -150; policy accept;
        ip daddr @local4 return
        ip6 daddr @local6 return
        meta mark 0x1ff return
        meta l4proto { tcp, udp } th dport { 22, 53, 7890, 7874, 9092, 9090 } return
        # counter 不是可有可无的装饰: **规则存在 ≠ 有流量经过**。接口名写错时规则照样
        # "装上", 却一个包都不命中 —— 这个计数是唯一能证明"真的接管了"的现场证据,
        # `zeroproxy doctor` 读的就是它。
        #
        # **家族必须写出来** (`tproxy ip` / `tproxy ip6`), 不能省成 `tproxy to :7893`。
        # 省掉之后它在 inet 表里是"未指定家族", 而这条规则要同时管 v4 与 v6 —— 真机上
        # 试过: 加了 `ip6` 限定再省家族, nft 直接报 "conflicting protocols specified:
        # ip6 vs. unknown. You must specify ip or ip6 family in tproxy statement"。
        # 与其推断"未指定是不是等于两个都管", 不如写死两条 (代价是各多一条规则)。
        meta nfproto ipv4 meta l4proto tcp counter meta mark set 0x1ff tproxy ip to :7893 accept
        meta nfproto ipv4 meta l4proto udp counter meta mark set 0x1ff tproxy ip to :7893 accept
        meta nfproto ipv6 meta l4proto tcp counter meta mark set 0x1ff tproxy ip6 to :7893 accept
        meta nfproto ipv6 meta l4proto udp counter meta mark set 0x1ff tproxy ip6 to :7893 accept
    }
    chain dns {
        type nat hook prerouting priority -105; policy accept;
        ip daddr @local4 return
        ip6 daddr @local6 return
        # DNS 单独计数: "局域网设备真的把 DNS 发给了路由器吗"这个问题只有它能回答
        # (dnsmasq 我们一个字节都没改, 所以这件事必须验, 不能假设)。
        udp dport 53 counter redirect to :7874
        tcp dport 53 counter redirect to :7874
    }
}
NFTEOF

    # redirect 数据面 (iptables nat)。只在 TUN 与 tproxy 都不可用时启用 (chosen=redirect)。
    #
    # 为什么单独抽成一个能 source 的文件: 装 / 开 / 关 / 卸载四个地方都要用它, 而它们
    # 分别是三个进程 (安装脚本 / init 脚本 / CLI) —— 一处实现, 四处同一份。tproxy.nft
    # 是"数据" (nft -f 直接读), 这里是"动作" (要按 LAN 接口名增删), 所以写成函数。
    #
    # 只接管**从局域网接口进来**的 TCP: REDIRECT 不适用于 UDP, 所以 covered=lan_tcp;
    # 路由器自身出站与 WAN 侧入站一个字节都不碰。UDP 那部分要 TUN 或 tproxy 才做得到,
    # 这台固件给不了 —— 那就如实少给, 而不是假装给全了。
    _lanif="$(lan_iface 2>/dev/null || true)"
    cat > "$ZP_DIR/redirect.sh" <<REDIRECTEOF
#!/bin/sh
# ZeroProxy iptables REDIRECT 数据面 (局域网 TCP 透明代理)。
# 由安装脚本生成, 请勿手改 —— 重跑安装命令会覆盖。
ZP_REDIR_PORT=7892
ZP_DNS_PORT=7874
ZP_LANIF="$_lanif"

# 局域网接口名。装机时确定不下来 (没有 uci / 接口还没起来) 就退回 br-lan —— 但绝不
# 退化成"所有接口": 那会把 WAN 侧入站也接管, 是比不接管更糟的结果。
zp_redirect_iface() {
    if [ -n "\$ZP_LANIF" ]; then printf '%s' "\$ZP_LANIF"; return 0; fi
    _d="\$(uci -q get network.lan.device 2>/dev/null || uci -q get network.lan.ifname 2>/dev/null || true)"
    [ -n "\$_d" ] || _d=br-lan
    printf '%s' "\$_d"
}

# 只撤自己的那条链 (zp_router): 别人的规则一条不碰。
zp_redirect_clear() {
    _if="\$(zp_redirect_iface)"
    while iptables -t nat -D PREROUTING -i "\$_if" -j zp_router 2>/dev/null; do :; done
    iptables -t nat -F zp_router 2>/dev/null || true
    iptables -t nat -X zp_router 2>/dev/null || true
    if command -v ip6tables >/dev/null 2>&1; then
        while ip6tables -t nat -D PREROUTING -i "\$_if" -j zp_router 2>/dev/null; do :; done
        ip6tables -t nat -F zp_router 2>/dev/null || true
        ip6tables -t nat -X zp_router 2>/dev/null || true
    fi
}

zp_redirect_apply() {
    command -v iptables >/dev/null 2>&1 || return 1
    _if="\$(zp_redirect_iface)"
    zp_redirect_clear
    iptables -t nat -N zp_router 2>/dev/null || return 1
    # 私有 / 保留地址直连: 局域网互访、管理页面、以及 mihomo 自己都不该被绕一圈。
    for _net in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 \
                172.16.0.0/12 192.0.0.0/24 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4 \
                198.18.0.0/16; do
        iptables -t nat -A zp_router -d "\$_net" -j RETURN
    done
    # 已标记的 (mihomo 自己的出站) 直连 —— 否则会成环。
    iptables -t nat -A zp_router -m mark --mark 0x1ff -j RETURN
    # 代理端口本身的入站不再被劫持 (否则内核与内核自己绕圈)。
    iptables -t nat -A zp_router -p tcp --dport 7890 -j RETURN
    iptables -t nat -A zp_router -p tcp --dport "\$ZP_REDIR_PORT" -j RETURN
    # DNS 先劫持 (fake-ip 才能按域名分流; TCP 53 也一起)。
    iptables -t nat -A zp_router -p udp --dport 53 -j REDIRECT --to-ports "\$ZP_DNS_PORT"
    iptables -t nat -A zp_router -p tcp --dport 53 -j REDIRECT --to-ports "\$ZP_DNS_PORT"
    # 其余 TCP 进 redir-port。
    iptables -t nat -A zp_router -p tcp -j REDIRECT --to-ports "\$ZP_REDIR_PORT"
    # 只从局域网接口进来 —— 路由器自身与 WAN 入站不接管。
    # 接口名不对 (设备上没有这个接口) 时这一步会失败: 那就把刚建的链撤掉并**如实返回
    # 失败** —— 让装机时的验证判它"没生效", 而不是留下一条指向空气的规则。
    if ! iptables -t nat -I PREROUTING -i "\$_if" -j zp_router 2>/dev/null; then
        zp_redirect_clear
        return 1
    fi
    # IPv6 那一半 (同一套规则, 换 ip6tables)。**没有 ip6tables 就不做** —— 那一档会被
    # 如实记进 caps (ipv6=0), 面板上会写"IPv6 未接管", 而不是假装全接管了。
    if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -t nat -N zp_router 2>/dev/null || return 0
        for _net6 in ::1/128 fc00::/7 fe80::/10 ff00::/8; do
            ip6tables -t nat -A zp_router -d "\$_net6" -j RETURN
        done
        ip6tables -t nat -A zp_router -m mark --mark 0x1ff -j RETURN
        ip6tables -t nat -A zp_router -p tcp --dport 7890 -j RETURN
        ip6tables -t nat -A zp_router -p tcp --dport "\$ZP_REDIR_PORT" -j RETURN
        ip6tables -t nat -A zp_router -p udp --dport 53 -j REDIRECT --to-ports "\$ZP_DNS_PORT"
        ip6tables -t nat -A zp_router -p tcp --dport 53 -j REDIRECT --to-ports "\$ZP_DNS_PORT"
        ip6tables -t nat -A zp_router -p tcp -j REDIRECT --to-ports "\$ZP_REDIR_PORT"
        if ! ip6tables -t nat -I PREROUTING -i "\$_if" -j zp_router 2>/dev/null; then
            ip6tables -t nat -F zp_router 2>/dev/null || true
            ip6tables -t nat -X zp_router 2>/dev/null || true
        fi
    fi
    return 0
}

zp_redirect_live() { iptables -t nat -L zp_router >/dev/null 2>&1; }

# 这一档能不能一并接管 IPv6 (没有 ip6tables 的老固件不行)。给安装脚本写 caps 用。
zp_redirect_v6() { command -v ip6tables >/dev/null 2>&1 && return 0 || return 1; }
REDIRECTEOF
    chmod 755 "$ZP_DIR/redirect.sh"

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

# 拼 JSON 字符串 (原因里可能有引号/反斜杠 —— 内核原话什么都可能有)
json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\r\n'; }

# 内核现在**真的**接管到哪。不看 caps 里的意图, 看现场 —— 这正是"永不撒谎"那一半:
# 面板上显示的是这个值, 不是"我们打算用什么"。
#   full     tun 在   → 全屋设备 + 路由器自身
#   lan      nft 表在 → 全屋设备 (路由器自身流量除外)
#   lan_tcp  iptables 链在 → 只有局域网 TCP
#   none     内核停着, 或规则被外 force 清了 → 未接管
actual_covered() {
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
caps_flag() {
    # 面板配置里能不能写 auto-redirect。装机时默认 1 (与面板默认一致), 只有**真的因为
    # 它起不来 tun** 时才会被学成 0 (见安装脚本的 tun_retry_without_redirect)。
    # 文件不在 = 老版本升级上来的, 按 1 报 —— 行为不变。
    _v="$(sed -n 's/^autoredirect=//p' "$ZP_DIR/caps" 2>/dev/null | head -n1)"
    case "$_v" in
        0|1) printf '%s' "$_v" ;;
        *)   printf '1' ;;
    esac
}

# caps 里的一个键 (一行一个 key=value)。老版本 (schema 1) 的 caps 没有 chosen,
# 那时按 tun 报 —— 升级上来的机器行为不变。
caps_get() { sed -n "s/^$1=//p" "$ZP_DIR/caps" 2>/dev/null | head -n1; }

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
    # 没有分流数据库就不能要 geo 规则 (面板知道这件事, 会给一份降级规则)。判据必须是
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
    DP_REPORT="$(datapath_flag)"
    COV_REPORT="$(actual_covered)"
    IPV6_REPORT="$(ipv6_flag)"
    # 性能那一半 (面板卡片上要能回答"这台机器跑这个能到多少")
    MTU_REPORT="$(tun_mtu_flag)"
    OFFLOAD_REPORT="$(caps_get offload)"
    BENCH_D="$(sed -n 's/^direct_kbps=//p' "$ZP_DIR/bench" 2>/dev/null | head -n1)"
    BENCH_P="$(sed -n 's/^proxy_kbps=//p' "$ZP_DIR/bench" 2>/dev/null | head -n1)"
    WHY_REPORT=""
    if [ "$COV_REPORT" = "none" ]; then
        # 一级都没接管时, 把**每一级为什么不行**都带上。只报"选中的那一级"会漏掉关键信息:
        # 真机截图里选的是 tun, 而屏幕上只有 tproxy 的原因, 于是没人知道 iptables 那条路
        # 到底为什么也没用上。
        for _lv in tun tproxy redirect; do
            _w="$(caps_get "why.$_lv")"
            if [ -n "$_w" ]; then
                WHY_REPORT="${WHY_REPORT:+$WHY_REPORT · }$_lv: $_w"
            fi
        done
    fi
    for _f in $(server_files); do
        _b="$(field_of "$_f" base)"; _i="$(field_of "$_f" id)"; _k="$(field_of "$_f" secret)"
        [ -n "$_b" ] || continue
        BODY='{"device":"'"$_i"'","k":"'"$_k"'","version":"'"$ZP_VERSION"'"'
        if core_up; then BODY="$BODY"',"actual":true'; else BODY="$BODY"',"actual":false'; fi
        [ -n "$UI_URL_REPORT" ] && BODY="$BODY"',"ui":"'"$UI_URL_REPORT"'"'
        [ -n "$LAST_REV" ] && BODY="$BODY"',"rev":"'"$LAST_REV"'"'
        BODY="$BODY"',"report":{"mode":"'"$DP_REPORT"'","covered":"'"$COV_REPORT"'"'
        BODY="$BODY"',"why":"'"$(json_escape "$WHY_REPORT")"'"'
        BODY="$BODY"',"client":"'"$ZP_VERSION"'","override":"'"$OVERRIDE"'"'
        BODY="$BODY"',"ipv6":"'"$IPV6_REPORT"'","mtu":"'"$MTU_REPORT"'"'
        BODY="$BODY"',"offload":"'"$OFFLOAD_REPORT"'"'
        BODY="$BODY"',"bench_direct":"'"${BENCH_D:-0}"'","bench_proxy":"'"${BENCH_P:-0}"'"}}'
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
        # (本机覆盖是唯一的例外: 那是用户**明确**表达的意图, 必须执行 —— 它存在的理由
        #  正是"面板挂了也要能开关"。)
        if [ -n "$OVERRIDE" ]; then
            if [ "$OVERRIDE" = "on" ] && ! core_up; then
                log "本机覆盖=on (面板不可达), 启动内核"
                switch_core on
            elif [ "$OVERRIDE" = "off" ] && core_up; then
                log "本机覆盖=off (面板不可达), 停止内核"
                switch_core off
            fi
        fi
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

# 按 caps 里的 chosen 落数据面规则。三件事要一起做: 撤掉**别的**模式的规则 (昨天 tun、
# 今天 redirect 时不留残渣), 落当前这一套, 再刷一次 dnsmasq 让它丢掉旧缓存。
zp_apply_datapath() {
    _mode="$(sed -n 's/^chosen=//p' "$ZP_DIR/caps" 2>/dev/null | head -n1)"
    case "$_mode" in
        tun|tproxy|redirect) ;;
        *)
            # 老版本升级上来的 caps 没有 chosen: 保留原来的判据 (tun 能力位 + 设备节点)
            if [ -f "$ZP_DIR/caps" ]; then
                if grep -q '^tun=1' "$ZP_DIR/caps" 2>/dev/null; then _mode=tun; else _mode=tproxy; fi
            elif [ ! -c /dev/net/tun ]; then
                _mode=tproxy
            else
                _mode=tun
            fi
            ;;
    esac

    # 撤掉不用的那两套 (只动我们自己的表/链)
    if [ "$_mode" != "tproxy" ]; then
        nft delete table inet zp_router 2>/dev/null || true
    fi
    if [ "$_mode" != "redirect" ] && [ -f "$ZP_DIR/redirect.sh" ]; then
        . "$ZP_DIR/redirect.sh"
        zp_redirect_clear 2>/dev/null || true
    fi

    # 落当前这一套
    if [ "$_mode" = "tproxy" ]; then
        nft -f "$ZP_DIR/tproxy.nft" 2>/dev/null || true
    elif [ "$_mode" = "redirect" ] && [ -f "$ZP_DIR/redirect.sh" ]; then
        . "$ZP_DIR/redirect.sh"
        zp_redirect_apply 2>/dev/null || true
    fi
    killall -HUP dnsmasq 2>/dev/null || true
}

start_service() {
    [ -x "$ZP_DIR/mihomo" ] || return 0
    [ -f "$CONF" ] || return 0

    # TUN 模式: 由内核接管路由与 DNS, 不需要动防火墙。
    # 走哪一级由 caps 里的 chosen 决定 (装机时探测 + 必要时降级), 而不是"节点在不在":
    # 原厂固件上 /dev/net/tun 存在但内核建不出设备, 那时该走 tproxy / redirect 而不是空转。
    zp_apply_datapath

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
    if [ -f "$ZP_DIR/redirect.sh" ]; then
        . "$ZP_DIR/redirect.sh"
        zp_redirect_clear 2>/dev/null || true
    fi
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
# 本机代理端口与内核控制口 —— doctor 用它们做出口测试与"按域名分流"检查。
# 注意这两个必须在**这里**定义: CLI 是独立的文件, 与安装脚本不共享作用域 (漏掉一个的
# 症状是变量为空、URL 变成 http:///connections、然后静默显示"没有连接")。
ZP_MIXED=7890
ZP_API=127.0.0.1:9090
SERVERS="$ZP_DIR/servers"
FIRST="$(ls "$SERVERS"/*.json 2>/dev/null | head -n1)"

field_of() { sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$1" | head -n1; }
key_of() {
    printf '%s' "$1" | sed -e 's#^https*://##' -e 's/[^A-Za-z0-9]/_/g' | cut -c1-32
}
servers() { ls "$SERVERS"/*.json 2>/dev/null; }

running() { /etc/init.d/zeroproxy running >/dev/null 2>&1 && echo yes || echo no; }

# 数据面上真的有流量经过吗 —— **规则存在 ≠ 有流量**。接口名写错 (L3 那一档最容易) 时
# 规则照样"装得上", 却一个包都不命中; 而这是唯一能证明"真的接管了"的现场证据。
# 输出两个数字: "总包数 DNS包数" (拿不到就给 0 0)。
datapath_packets() {
    _mode="$(sed -n 's/^chosen=//p' "$ZP_DIR/caps" 2>/dev/null | head -n1)"
    case "$_mode" in
        tun)
            _rx="$(cat /sys/class/net/zp-tun/statistics/rx_packets 2>/dev/null | head -n1)"
            printf '%s 0\n' "${_rx:-0}"
            ;;
        tproxy)
            _dump="$(nft list table inet zp_router 2>/dev/null || true)"
            _tot="$(printf '%s\n' "$_dump" | sed -n 's/.*counter packets \([0-9][0-9]*\).*/\1/p' \
                | awk '{s+=$1} END{print s+0}')"
            _dns="$(printf '%s\n' "$_dump" | grep 'dport 53' \
                | sed -n 's/.*counter packets \([0-9][0-9]*\).*/\1/p' \
                | awk '{s+=$1} END{print s+0}')"
            printf '%s %s\n' "${_tot:-0}" "${_dns:-0}"
            ;;
        redirect)
            _dump="$(iptables -t nat -L zp_router -v -n 2>/dev/null || true)"
            _tot="$(printf '%s\n' "$_dump" | awk 'NR>2 {s+=$1} END{print s+0}')"
            _dns="$(printf '%s\n' "$_dump" | awk '$0 ~ /dpt:53/ {s+=$1} END{print s+0}')"
            printf '%s %s\n' "${_tot:-0}" "${_dns:-0}"
            ;;
        *) printf '0 0\n' ;;
    esac
}

# 有多少条连接**已经被识别出域名** —— 这是"按域名分流真的在工作"的证据, 三种数据面都成立。
#
# 域名从哪来, 两条路都有:
#   * 设备的 DNS 走到内核 (查运营商 DNS 的查询会被 dns-hijack 接住, 给出 fake-ip) →
#     mihomo 手里有 fake-ip → 域名 的映射, 连接一进来就知道域名;
#   * DNS 没进内核 (设备查的是路由器自己的 dnsmasq, 那是本机服务) → 连接是真实 IP, 靠
#     **嗅探**从 TLS SNI / HTTP Host 里把域名认回来。
# 所以"host 或 sniffHost 任一非空"才算数 —— 只数 host 会漏掉纯嗅探的那一半。
#
# 为什么不拿 DNS 计数器当判据: 它只统计"设备直接查外部 DNS"的那一部分, 为 0 是正常状态。
# 第一版 doctor 把它写成"设备可能没把路由器当 DNS", 方向正好反了 (真机上那一行打着"!",
# 而代理其实一切正常)。
sniffed_hosts() {
    command -v curl >/dev/null 2>&1 || return 1
    _conn="$(curl -s -m 5 "http://$ZP_API/connections" 2>/dev/null || true)"
    [ -n "$_conn" ] || return 1
    printf '%s' "$_conn" | grep -oE '"(host|sniffHost)"[ ]*:[ ]*"[^"]{1,}"' | wc -l | tr -d ' '
}

# curl 的 speed_download (字节/秒) → 人话。分开写是因为 doctor 与 bench 都要用。
bench_kbps() { awk -v s="${1:-0}" 'BEGIN{ if (s+0 < 0) s=0; printf "%d", s/1024 }'; }
bench_text() {
    if [ -z "${1:-}" ]; then printf '失败'; return 1; fi
    _kb="$(bench_kbps "$1")"
    if [ "${_kb:-0}" -le 0 ] 2>/dev/null; then printf '失败'; return 1; fi
    if [ "${_kb:-0}" -ge 1024 ] 2>/dev/null; then
        awk -v k="$_kb" 'BEGIN{printf "%.1f MB/s", k/1024}'
    else
        printf '%s KB/s' "$_kb"
    fi
}

# 真机基准: 用面板当靶子, 量"直连"与"经代理"两条路的吞吐。
#   为什么要用面板当靶子: 它是这台路由器**一定能访问到**的地址 (装机时唯一可达的), 而
#   两条路跑的是同一段路 —— 一比就知道代理本身吃掉了多少。测别的公网地址要么连不上,
#   要么两边不是一个终点, 数字没有可比性。
#   为什么只测 4 MB: 路由器是 CPU 瓶颈, 4 MB 足够把上限顶出来, 又不至于烧掉用户的流量
#   (经代理的那一趟是要算节点流量的)。
BENCH_MB="${ZP_BENCH_MB:-4}"
bench_run() {
    _url="$1"; _proxy="$2"
    if [ "$_proxy" = "proxy" ]; then
        # `--noproxy ""` 是**必须**的: curl 默认遵守 NO_PROXY, 而多数环境里那个变量含
        # 127.0.0.1 / localhost —— 于是"经代理"这一趟会**绕过代理直连**, 量出一个跟直连
        # 一样漂亮的数字 (演练环境里就这么骗过一次: 代理端口根本没在监听, 却报了 921 MB/s)。
        # 这一趟必须是真经代理, 不然这个数字比不测更糟。
        curl -s -o /dev/null -m 120 --noproxy "" -x "http://127.0.0.1:$ZP_MIXED" \
            -w '%{speed_download}' "$_url" 2>/dev/null || true
    else
        # 反过来: "直连"这一趟必须**真的不走代理** —— 环境里若设了 HTTP_PROXY, curl 会用它。
        curl -s -o /dev/null -m 120 --noproxy '*' -w '%{speed_download}' "$_url" 2>/dev/null || true
    fi
}

# 真机体检。它问的每一句都是"到底行不行", 每一条都给证据 —— 装机之后、出问题时第一个
# 应该跑的命令。设计上它只能在真机上给出完整答案 (本机没有"局域网侧"这回事), 所以
# 演练只验它的判据与输出格式。
doctor() {
    echo "ZeroProxy 路由器端体检"
    echo "────────────────────────────────────────────"
    echo
    echo "内核"
    if [ "$(running)" = yes ]; then
        printf '  ✓ 服务在跑：%s\n' "$("$ZP_DIR/mihomo" -v 2>/dev/null | head -n1)"
    else
        printf '  ✗ 服务没在跑 — 面板上打开总开关，或本机执行 zeroproxy on\n'
    fi

    echo
    echo "数据面"
    _chosen="$(sed -n 's/^chosen=//p' "$ZP_DIR/caps" 2>/dev/null | head -n1)"
    _covered="$(sed -n 's/^covered=//p' "$ZP_DIR/caps" 2>/dev/null | head -n1)"
    printf '  选择：%s（覆盖 %s）\n' "${_chosen:-未知}" "${_covered:-未知}"
    # 现场 vs 意图: caps 里的是"我们打算用什么", 这里问的是"现在真的在不在"
    if [ "$(running)" = yes ]; then
        _live="none"
        if ip link show zp-tun >/dev/null 2>&1; then _live="tun"
        elif nft list table inet zp_router >/dev/null 2>&1; then _live="tproxy"
        elif iptables -t nat -L zp_router >/dev/null 2>&1; then _live="redirect"
        fi
        if [ "$_live" = "$_chosen" ] && [ "$_live" != "none" ]; then
            printf '  ✓ 现场一致：数据面真的在（%s）\n' "$_live"
        elif [ "$_live" = "none" ]; then
            printf '  ✗ 数据面没有生效 — 局域网里没有人被接管\n'
            for _lv in tun tproxy redirect; do
                _w="$(sed -n "s/^why.$_lv=//p" "$ZP_DIR/caps" 2>/dev/null | head -n1)"
                [ -n "$_w" ] && printf '      %s: %s\n' "$_lv" "$_w"
            done
        else
            printf '  ! caps 说 %s、现场是 %s — 重跑一次安装命令让它对齐\n' "$_chosen" "$_live"
        fi
        _pk="$(datapath_packets)"
        _pkts="${_pk%% *}"; _dnspkts="${_pk##* }"
        if [ "$_live" != "none" ]; then
            if [ "${_pkts:-0}" -gt 0 ] 2>/dev/null; then
                printf '  ✓ 规则上真的有流量：%s 个包经过\n' "$_pkts"
            else
                printf '  ! 规则在，但还没有流量经过 — 刚刚开机/刚重启就是这样；\n'
                printf '      如果局域网设备已经在用网还是 0，多半是接口名不对（redirect 那一档最常见）\n'
            fi
        fi
    fi

    echo
    echo "DNS 与按域名分流"
    # 判据是"嗅探出域名的连接数", 不是 DNS 计数器 —— 见 sniffed_hosts() 上面那段的理由:
    # 局域网设备查的是路由器自己的 dnsmasq (本机服务), DNS 计数为 0 是正常的。
    _sniffed="$(sniffed_hosts 2>/dev/null || true)"
    if [ -n "$_sniffed" ] && [ "${_sniffed:-0}" -gt 0 ] 2>/dev/null; then
        printf '  ✓ 按域名分流在工作：%s 条连接已经识别出域名\n' "$_sniffed"
    elif [ "${_pkts:-0}" -gt 0 ] 2>/dev/null; then
        # 有流量经过却一条域名都没嗅探出来 —— 这才可疑: 分流会退化成"按 IP 判断",
        # 国内/国外那套规则基本失效 (TLS 之外还有一大半流量是靠 SNI 认出来的)。
        printf '  ! 有流量经过, 但一条都没嗅探出域名 —— 分流在按 IP 判断\n'
        printf '      看一下 /etc/zeroproxy/config.yaml 里 sniffer.enable 是不是 true\n'
    else
        printf '  · 这一刻没有活跃的"已知域名"的连接（刚开机 / 刚好空闲 / 设备还没开始用网）\n'
    fi
    if [ "$(running)" = yes ] && [ "${_dnspkts:-0}" -gt 0 ] 2>/dev/null; then
        printf '  · 另有 %s 个查询是设备直接查外部 DNS 的，已被内核接管\n' "$_dnspkts"
    fi
    if [ -s "$ZP_DIR/bench" ]; then
        _bkd="$(sed -n 's/^direct_kbps=//p' "$ZP_DIR/bench" 2>/dev/null | head -n1)"
        _bkp="$(sed -n 's/^proxy_kbps=//p' "$ZP_DIR/bench" 2>/dev/null | head -n1)"
        _bka="$(sed -n 's/^at=//p' "$ZP_DIR/bench" 2>/dev/null | head -n1)"
        if [ -n "$_bkp" ]; then
            printf '  · 上次实测（zeroproxy bench，%s）: 直连 %s KB/s · 经代理 %s KB/s\n' \
                "$(date -d "@${_bka:-0}" '+%m-%d %H:%M' 2>/dev/null || echo '?')" \
                "${_bkd:-?}" "$_bkp"
        fi
    fi
    printf '    设备的 DNS 有两条路: 查路由器自己的 dnsmasq（本机服务, 不进内核, 于是连接靠嗅探认出域名），\n'
    printf '    或查运营商 DNS（IPv6 上很常见, 它会进内核并被 dns-hijack 成 fake-ip）—— 两条路都按域名分流。\n'
    printf '    所以"DNS 计数为 0"只说明这一刻没人直接查外部 DNS, 不是故障; 要证明的是上面那条。\n'

    echo
    echo "IPv6"
    _v6="$(sed -n 's/^ipv6=//p' "$ZP_DIR/caps" 2>/dev/null | head -n1)"
    if [ "$_v6" = "1" ]; then
        printf '  ✓ 已一并接管（局域网设备的 v6 也走代理）\n'
    else
        printf '  ! 未接管 — %s\n' "$(sed -n 's/^why.ipv6=//p' "$ZP_DIR/caps" 2>/dev/null | head -n1)"
        printf '      这台机器上局域网设备的 IPv6 会直接出去\n'
    fi

    echo
    echo "性能"
    _wan="$(sed -n 's/^wan_mtu=//p' "$ZP_DIR/caps" 2>/dev/null | head -n1)"
    _tun="$(sed -n 's/^tun_mtu=//p' "$ZP_DIR/caps" 2>/dev/null | head -n1)"
    if [ -n "$_tun" ]; then
        if [ -n "$_wan" ] && [ "$_wan" != "1500" ]; then
            printf '  ✓ WAN MTU %s（PPPoE?）→ tun 按 %s 收包，封装后不会成超包\n' "$_wan" "$_tun"
        elif [ -z "$_wan" ]; then
            # 取不到 ≠ 以太网。老实说取不到, 别替它下结论 (真机上就是这么显示成"以太网直连"的)
            printf '  · 取不到 WAN 的 MTU（这台机器上没有默认路由?）→ tun 保持 %s\n' "$_tun"
        else
            printf '  · WAN MTU %s → tun %s（以太网直连, 用默认值）\n' "$_wan" "$_tun"
        fi
    fi
    _off="$(sed -n 's/^offload=//p' "$ZP_DIR/caps" 2>/dev/null | head -n1)"
    if [ "$_off" = "1" ]; then
        if [ "$_live" = "tun" ]; then
            printf '  · 转发卸载开着（flow offloading / HNAT）—— tun 走路由, 不受影响\n'
        else
            printf '  ! 转发卸载开着, 而数据面是 %s —— 它绕过 netfilter, 连接可能不走代理\n' "${_live:-?}"
        fi
    fi
    _ebpf="$(sed -n 's/^ebpf=//p' "$ZP_DIR/caps" 2>/dev/null | head -n1)"
    if [ "$_ebpf" = "1" ]; then
        printf '  · eBPF 挡位可用（内核 + BTF 都在）—— 性能模式尚未实现\n'
    else
        printf '  · eBPF 挡位不可用: %s\n' "$(sed -n 's/^why.ebpf=//p' "$ZP_DIR/caps" 2>/dev/null | head -n1)"
    fi
    printf '    想测这台机器自己能跑多快: zeroproxy bench\n'

    echo
    echo "出口"
    if command -v curl >/dev/null 2>&1; then
        if curl -fsS -m 12 -x "http://127.0.0.1:$ZP_MIXED" -o /dev/null \
            "http://www.gstatic.com/generate_204" 2>/dev/null; then
            printf '  ✓ 经本机代理端口能出网\n'
        else
            printf '  ! 经本机代理端口出不去（节点可能全关着，或节点本身不通）\n'
        fi
    else
        printf '  · 这台固件上没有 curl，跳过出口测试\n'
    fi

    echo
    echo "面板"
    for _f in $(servers); do
        _b="$(field_of "$_f" base)"
        _key="$(key_of "$_b")"
        if command -v curl >/dev/null 2>&1 \
            && curl -fsSk -m 8 -o /dev/null "$_b/api/status" 2>/dev/null; then
            printf '  ✓ %s 可达\n' "$_key"
        else
            printf '  ! %s 不可达（代理照常工作；本机开关会自动落到本机覆盖）\n' "$_key"
        fi
    done
    if [ -s "$ZP_DIR/local.override" ]; then
        printf '  ! 本机覆盖生效中：%s（交回面板：zeroproxy local-auto）\n' \
            "$(tr -d '\r\n ' < "$ZP_DIR/local.override")"
    fi

    echo
    echo "────────────────────────────────────────────"
    echo "下一步：以上有 ✗ 或 ! 时，把这一整段发回面板即可定位。"
}

# 与装机前的快照逐条比对。**逐行**, 不是"看起来差不多" —— 数据面残留是"关掉了但网还是
# 不对劲"这一类问题的唯一解释, 必须能直接指出来。左右两边: 左=现在, 右=装机前。
revert_report() {
    _dir="$ZP_DIR/baseline"
    # 同上: 判断"拍过没有"看 taken_at。机器上没有 nftables 时 nft.txt 本来就是空的,
    # 用大小判会把"拍过了、而且现在也对得上"误报成"没有快照"。
    if [ ! -f "$_dir/taken_at" ]; then
        echo "本机没有装机前的快照 (旧版本装的, 或者快照被删了) —— 无法逐条比对。"
        echo "  自己看一眼: nft list ruleset | grep -i zp_ ; iptables -t nat -L zp_router ; ip rule"
        return 0
    fi
    _drift=0
    for _pair in "nft:nft list ruleset" "iptables:iptables-save" "ip6tables:ip6tables-save" "ip-rule:ip rule show" "ip6-rule:ip -6 rule show"; do
        _name="${_pair%%:*}"
        _cmd="${_pair#*:}"
        _base="$_dir/$_name.txt"
        [ -f "$_base" ] || continue
        _cur="$(eval "$_cmd" 2>/dev/null || true)"
        if [ "$_cur" = "$(cat "$_base" 2>/dev/null || true)" ]; then
            printf '  ✓ %-9s 与装机前一致\n' "$_name"
            continue
        fi
        _drift=1
        printf '  ! %-9s 与装机前**不一致** (左=现在, 右=装机前):\n' "$_name"
        _now_file="$ZP_DIR/.revert.$_name"
        printf '%s\n' "$_cur" > "$_now_file"
        if command -v diff >/dev/null 2>&1; then
            diff "$_now_file" "$_base" 2>/dev/null | head -n 8 | sed 's/^/      /'
        fi
        rm -f "$_now_file"
    done
    if [ "$_drift" = "0" ]; then
        echo "结论: 已完全回到装机前的状态 (防火墙与策略路由逐条一致)。"
    else
        echo "结论: 还有残留 —— 上面标 ! 的那几项; 把这段发回面板可以定位。"
    fi
    return 0
}

case "${1:-status}" in
    doctor)
        # 真机体检: 逐项问"到底行不行", 每项给证据 (判据与输出格式在 doctor() 里)
        doctor
        ;;
    status)
        echo "内核:  $( [ "$(running)" = yes ] && echo 运行中 || echo 已停止 )"
        echo "服务器 ($(servers | wc -l | tr -d ' ') 台):"
        for _f in $(servers); do
            printf '  %-16s %s\n' "$(key_of "$(field_of "$_f" base)")" "$(field_of "$_f" base)"
        done
        # 模式按"现在到底是什么在生效"报, 不看 /dev/net/tun 这个节点 —— 它在某些固件上
        # 存在但建不出设备 (真机: 原厂 5.4.281), 那时报 TUN 就是骗人。能力是装机时探的。
        if ip link show zp-tun >/dev/null 2>&1; then
            echo "模式:  TUN (全屋透明, 含路由器自身)"
        elif nft list table inet zp_router >/dev/null 2>&1; then
            echo "模式:  tproxy (全屋透明, 本机自身流量除外)"
        elif iptables -t nat -L zp_router >/dev/null 2>&1; then
            echo "模式:  redirect (局域网 TCP 透明代理; 不含 UDP 与本机自身流量)"
        else
            echo "模式:  未生效 (只有本机代理端口可用)"
        fi
        if [ -f "$ZP_DIR/caps" ]; then
            printf '能力:  tun=%s nft=%s tproxy=%s redirect=%s ebpf=%s (装机时探测)\n' \
                "$(sed -n 's/^tun=//p' "$ZP_DIR/caps" | head -n1)" \
                "$(sed -n 's/^nft=//p' "$ZP_DIR/caps" | head -n1)" \
                "$(sed -n 's/^tproxy=//p' "$ZP_DIR/caps" | head -n1)" \
                "$(sed -n 's/^redirect=//p' "$ZP_DIR/caps" | head -n1)" \
                "$(sed -n 's/^ebpf=//p' "$ZP_DIR/caps" | head -n1)"
            _chosen="$(sed -n 's/^chosen=//p' "$ZP_DIR/caps" | head -n1)"
            _covered="$(sed -n 's/^covered=//p' "$ZP_DIR/caps" | head -n1)"
            [ -n "$_chosen" ] && printf '选择:  %s (覆盖 %s)\n' "$_chosen" "${_covered:-?}"
            # 另外几级为什么不行 —— 面板上显示的就是这一份, 排障时不用再猜
            for _lv in tun tproxy redirect; do
                _why="$(sed -n "s/^why.$_lv=//p" "$ZP_DIR/caps" | head -n1)"
                [ -n "$_why" ] && printf '原因:  %s: %s\n' "$_lv" "$_why"
            done
        fi
        # 本机覆盖: 面板不可达时用 zeroproxy on|off 写下的那份意图 (它优先于面板)
        if [ -s "$ZP_DIR/local.override" ]; then
            printf '覆盖:  本机覆盖「%s」—— 面板说了不算, 直到你执行 zeroproxy local-auto\n' \
                "$(tr -d '\r\n ' < "$ZP_DIR/local.override")"
        fi
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
        # 先按"面板是唯一事实来源"走: 告诉面板改期望状态, agent 下一轮生效。
        # 面板**不可达**时才退回本机覆盖 —— 家里网出问题时连"关掉代理"都做不到, 是最坏
        # 的结果; 而这时恰恰是面板最容易不可达的时候。
        ON=$([ "$1" = on ] && echo true || echo false)
        [ -n "$FIRST" ] || { echo "还没有接入任何服务器"; exit 1; }
        _base="$(field_of "$FIRST" base)"
        ID="$(field_of "$FIRST" id)"
        KEY="$(field_of "$FIRST" secret)"
        BODY='{"device":"'"$ID"'","k":"'"$KEY"'","set_desired":'"$ON"'}'
        _sent=0
        if command -v curl >/dev/null 2>&1; then
            curl -fsSk -m 15 -H 'Content-Type: application/json' --data "$BODY" "$_base/c/report" >/dev/null 2>&1 && _sent=1
        else
            uclient-fetch -q --no-check-certificate -O - --post-data "$BODY" "$_base/c/report" >/dev/null 2>&1 && _sent=1
        fi
        if [ "$_sent" = "1" ]; then
            # 面板答上了 —— 它是唯一事实来源, 顺手清掉本机覆盖 (否则面板以后改不动它)
            rm -f "$ZP_DIR/local.override" 2>/dev/null || true
            echo "已请求面板把总开关设为「$1」, 约 15 秒内生效 (zeroproxy status 查看)"
            exit 0
        fi
        umask 077
        printf '%s\n' "$1" > "$ZP_DIR/local.override"
        umask 022
        if [ "$1" = "on" ]; then
            /etc/init.d/zeroproxy start >/dev/null 2>&1 || true
            touch "$ZP_DIR/core.up"
        else
            rm -f "$ZP_DIR/core.up"
            /etc/init.d/zeroproxy stop >/dev/null 2>&1 || true
            nft delete table inet zp_router 2>/dev/null || true
            if [ -f "$ZP_DIR/redirect.sh" ]; then
                . "$ZP_DIR/redirect.sh"
                zp_redirect_clear 2>/dev/null || true
            fi
        fi
        killall -HUP dnsmasq 2>/dev/null || true
        echo "面板不可达 —— 已在本机把全屋代理设为「$1」并立即生效。"
        echo "  这是**本机覆盖**: 面板恢复后也不会自动改回去。交回面板: zeroproxy local-auto"
        ;;
    local-auto)
        if [ -s "$ZP_DIR/local.override" ]; then
            rm -f "$ZP_DIR/local.override"
            echo "已清除本机覆盖 —— 总开关重新由面板决定 (agent 下一轮生效, 约 15 秒)。"
        else
            echo "本来就没有本机覆盖 —— 总开关一直由面板决定。"
        fi
        ;;
    bench)
        # 真机基准。**它量的是"这台路由器自己"的能力**, 不是节点好坏: 同一个节点在手机上
        # 能跑 200 Mbps, 在这台双核 A53 上可能只有 40 —— 这个数字决定了"换协议/换节点
        # 还有没有意义"。结果落在 $ZP_DIR/bench, agent 会随心跳带给面板。
        [ -n "$FIRST" ] || { echo "还没有接入任何服务器"; exit 1; }
        command -v curl >/dev/null 2>&1 || { echo "这台固件上没有 curl —— 跑不了基准"; exit 1; }
        _url="$(field_of "$FIRST" base)/c/bench/$BENCH_MB"
        echo "路由器基准测试 (靶子是面板, ${BENCH_MB} MB —— 经代理那一趟会算节点流量)"
        printf '  直连   … '
        _dr="$(bench_run "$_url" direct)"
        _dk="$(bench_kbps "$_dr")"
        printf '%s\n' "$(bench_text "$_dr")"
        printf '  经代理 … '
        _pr="$(bench_run "$_url" proxy)"
        _pk="$(bench_kbps "$_pr")"
        printf '%s\n' "$(bench_text "$_pr")"
        if [ "${_dk:-0}" -gt 0 ] 2>/dev/null && [ "${_pk:-0}" -gt 0 ] 2>/dev/null; then
            # 别写"代理开销 -10%": 负的开销读起来像 bug。经代理比直连还快是**正常**的 ——
            # 差的是两条线的走向 (经代理那趟是"到节点再到面板"), 节点到面板的线路好的时候
            # 就会更快 (GL-MT3000 实测: 直连 7.7 MB/s, 经代理 8.6 MB/s, 面板与节点都在香港)。
            if [ "$_pk" -lt "$_dk" ] 2>/dev/null; then
                printf '  经代理比直连慢 %s%%\n' \
                    "$(awk -v a="$_pk" -v b="$_dk" 'BEGIN{printf "%d", (1-a/b)*100}')"
            else
                printf '  经代理比直连快 %s%%（节点到面板的线路比直连好, 不是异常）\n' \
                    "$(awk -v a="$_pk" -v b="$_dk" 'BEGIN{printf "%d", (a/b-1)*100}')"
            fi
        fi
        if [ "${_pk:-0}" -le 0 ] 2>/dev/null; then
            printf '    （经代理那一趟没量到数 —— 内核在跑吗? 看 zeroproxy status）\n'
        fi
        {
            printf 'at=%s\n' "$(date +%s)"
            printf 'direct_kbps=%s\n' "${_dk:-0}"
            printf 'proxy_kbps=%s\n' "${_pk:-0}"
        } > "$ZP_DIR/bench" 2>/dev/null || true
        echo "  已记下 —— 面板设备卡上会显示这两个数字 (agent 下一轮心跳带过去)"
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
    revert)
        # 停用代理并拆掉数据面, 然后**证明**拆干净了 —— 与装机前快照逐条比对。
        # 保留配置与凭据 (那是 uninstall 的事): 想恢复只要再跑一次面板上的更新命令
        # (`wget -qO- <面板>/c/install.sh | sh`), 它会按现有 state 重新落地并重新启用。
        echo "正在停服务并拆掉数据面…"
        /etc/init.d/zeroproxy-agent stop >/dev/null 2>&1 || true
        /etc/init.d/zeroproxy-agent disable >/dev/null 2>&1 || true
        /etc/init.d/zeroproxy stop >/dev/null 2>&1 || true
        /etc/init.d/zeroproxy disable >/dev/null 2>&1 || true
        /etc/init.d/zeroproxy-ui stop >/dev/null 2>&1 || true
        /etc/init.d/zeroproxy-ui disable >/dev/null 2>&1 || true
        rm -f "$ZP_DIR/core.up"
        nft delete table inet zp_router 2>/dev/null || true
        if [ -f "$ZP_DIR/redirect.sh" ]; then
            . "$ZP_DIR/redirect.sh"
            zp_redirect_clear 2>/dev/null || true
        fi
        # tun 的 auto-route 规则随内核退出自动回收; 这里只兜我们自己加过的东西
        killall -HUP dnsmasq 2>/dev/null || true
        revert_report
        echo "配置与凭据都还在。重新启用: 跑一次面板上的更新命令 (wget -qO- <面板>/c/install.sh | sh)"
        ;;
    update)
        # 一键更新: 从面板拉最新的安装脚本并重跑 (走**更新模式** —— 不带配对码, 不会在面板上
        # 多出设备)。界面上那个按钮调的就是它。
        #
        # **后台跑**两个理由: ① 它会替换 /usr/bin/zeroproxy 这个正在运行的文件, 前台跑容易
        # 半途出岔子; ② 它要下载 20 MB 内核, 与其让界面转一分钟, 不如"提交后立刻回话、
        # 稍后刷新"。过程写进 $ZP_DIR/update.log, 结束时往 syslog 丢一句结论 (界面上的
        # 「最近日志」读的就是 syslog)。
        [ -n "$FIRST" ] || { echo "还没有接入任何服务器"; exit 1; }
        _base="$(field_of "$FIRST" base)"
        _log="$ZP_DIR/update.log"
        : > "$_log" 2>/dev/null || true
        # 先把面板要发的那份脚本取下来, **看一眼它的版本** —— 比本机旧就停下。
        #
        # 为什么需要这道闸门: 按钮触发的更新会把路由器上的**全部客户端文件**换成面板那一版。
        # 面板还没更新时点下去 = 把机器**降级**, 而且会覆盖掉本机刚拿到的东西。真机上踩过:
        # 面板 2.11.9 / 本机 1.4.11, 点按钮之后页面报"未知操作: update" —— 因为覆盖回来的
        # 旧 cgi 里没有那个动作分支。
        _tmp="$ZP_DIR/.update-script"
        # 面板那条路会**偶尔丢一个包就整条挂住**: 真机上同一个地址连 6 次, 3 次是 0.15 秒,
        # 3 次 SYN 石沉大海、一直挂到我给的超时 (40% 左右)。只拉一次的话, 用户按下按钮、
        # 界面上什么都没发生, 最后报出来却是"面板不可达" —— 而实际情况是"再试一次就行"。
        # 所以这里试三次 (每次 25 秒上限, 与原来 60 秒的总预算同量级)。半个文件也要清掉:
        # 下一轮若还失败, 留着上一轮的残片会让"脚本有没有拿到"的判断失真。
        _try=0; _got=0
        while [ "$_try" -lt 3 ]; do
            _try=$((_try + 1))
            rm -f "$_tmp"
            _rc=1
            if command -v curl >/dev/null 2>&1; then
                if curl -fsSk -m 25 "$_base/c/install.sh" -o "$_tmp" 2>/dev/null; then _rc=0; fi
            else
                if uclient-fetch -q --no-check-certificate -T 25 -O "$_tmp" "$_base/c/install.sh" 2>/dev/null; then _rc=0; fi
            fi
            # 只有 curl/uclient-fetch 自己说"传完了"才算拿到 —— 被掐断的那次也会留下
            # 半个文件, 而半份脚本里的版本号照样能被 sed 抠出来, 拿去跑就是另一回事了。
            if [ "$_rc" = "0" ] && [ -s "$_tmp" ]; then _got=1; break; fi
            sleep 1
        done
        [ "$_got" = "1" ] || rm -f "$_tmp"
        _panel_ver=""
        if [ -s "$_tmp" ]; then
            _panel_ver="$(sed -n 's/^ZP_CLIENT_VERSION="\(.*\)"/\1/p' "$_tmp" | head -n1)"
        fi
        if [ -z "$_panel_ver" ]; then
            rm -f "$_tmp"
            echo "取不到面板的安装脚本 (面板不可达?) —— 稍后再试, 或看 zeroproxy update-log"
            exit 1
        fi
        # 版本比较 (a<b → -1, = → 0, > → 1)。只看前三位, 够用。
        _cmp="$(awk -v a="$_panel_ver" -v b="$ZP_VERSION" 'BEGIN{
            n=split(a,x,"."); m=split(b,y,".");
            for(i=1;i<=3;i++){ x[i]+=0; y[i]+=0;
                if (x[i]>y[i]) { print 1; exit }
                if (x[i]<y[i]) { print -1; exit } }
            print 0 }')"
        if [ "$_cmp" = "-1" ]; then
            rm -f "$_tmp"
            # 变量名后面紧跟中文时必须写 ${VAR}: 有的 shell 会把高字节算进变量名,
            # `set -u` 下就变成 "unbound variable" —— 偏偏只在真的走到这一行时才炸。
            echo "面板上是 v${_panel_ver}，这台机器已经是 v${ZP_VERSION} —— 那不是升级。"
            echo "  面板那边可能还没更新完: 先在面板点「检查更新 → 一键更新」, 再回来点这个按钮。"
            exit 0
        fi
        echo "面板版本 v$_panel_ver (本机 v$ZP_VERSION) —— 开始更新。"
        (
            # 用刚取下来的那一份跑 —— 不再下第二次 (版本也已经核对过了)
            sh "$_tmp" >>"$_log" 2>&1
            _rc=$?
            rm -f "$_tmp"
            echo "EXIT=$_rc" >> "$_log"
            if [ "$_rc" = "0" ]; then
                logger -t zeroproxy "客户端更新完成 (刷新本页看版本号)"
            else
                logger -t zeroproxy "客户端更新失败 (退出码 $_rc), 详情: zeroproxy update-log"
            fi
        ) &
        echo "已开始更新 (后台进行, 约 1 分钟; 配置与凭据保留)。"
        echo "  完成后刷新本页看客户端版本号; 详情: zeroproxy update-log 或本页「最近日志」"
        ;;
    update-log) cat "$ZP_DIR/update.log" 2>/dev/null || echo "(还没有更新记录)" ;;
    uninstall)
        # 先停 agent 再停内核: 反过来的话 agent 会在内核停掉后立刻把它拉起来
        /etc/init.d/zeroproxy-agent stop >/dev/null 2>&1 || true
        /etc/init.d/zeroproxy-agent disable >/dev/null 2>&1 || true
        /etc/init.d/zeroproxy-ui stop >/dev/null 2>&1 || true
        /etc/init.d/zeroproxy-ui disable >/dev/null 2>&1 || true
        /etc/init.d/zeroproxy stop >/dev/null 2>&1 || true
        /etc/init.d/zeroproxy disable >/dev/null 2>&1 || true
        nft delete table inet zp_router 2>/dev/null || true
        if [ -f "$ZP_DIR/redirect.sh" ]; then
            . "$ZP_DIR/redirect.sh"
            zp_redirect_clear 2>/dev/null || true
        fi
        killall -HUP dnsmasq 2>/dev/null || true
        rm -rf "$ZP_DIR" /etc/init.d/zeroproxy /etc/init.d/zeroproxy-agent /etc/init.d/zeroproxy-ui /usr/bin/zeroproxy
        echo "已卸载。这台设备在面板上仍然存在, 请在面板「客户端」里一并移除。"
        ;;
    *) echo "用法: zeroproxy [doctor|status|ui|servers|add <链接>|drop <键>|refresh|geo|on|off|local-auto|revert|bench|update|update-log|log|uninstall]" ;;
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
# **致命**的: 整个 tun 都起不来, 现象就是"zp-tun 一直不出现"。全屋的本体是 auto-route
# (ip rule + 独立路由表接管全部流量, 含局域网转发), 少了 auto-redirect 功能不受影响。
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
    elif [ "$ACTIVE_MODE" != "none" ]; then
        wait_datapath "$ACTIVE_MODE" || true
    fi

    # 这一级真的没起来 → 顺着阶梯往下试。降级成功时会顺带重建配置 (不再带 tun 段),
    # 于是"这台固件建不出设备"这件事不会再拖垮整条链路。
    if [ "$ACTIVE_MODE" != "none" ] && ! datapath_live "$ACTIVE_MODE"; then
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
            printf '         opkg install kmod-tun kmod-nft-tproxy    (OpenWrt 25.12 及更新: apk add ...)\n'
            printf '    2) 换成带 TUN / nftables 支持的固件 (原厂精简固件常常都缺)\n'
            printf '  路由器本机的代理端口一直可用 (http://%s:%s), 只是没有接管局域网设备。\n' "$(lan_ip)" "$ZP_MIXED"
            ;;
    esac
    printf '  设备名   %s\n' "$MODEL"
    case "${ACTIVE_MODE:-none}" in
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
        printf '  调整     这台固件上 auto-redirect 会让 tun 起不来, 已自动去掉 (功能不受影响)\n'
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
