#!/usr/bin/env bash
# ============================================================
#  ZeroProxy 一键部署脚本  —  Ubuntu 22.04+ / Debian 12+
#
#  支持面就是上面这一行, 判据是**系统自带的 Python**: 面板要求 Python ≥ 3.10
#  (Debian 12 = 3.11 / Debian 13 = 3.13 / Ubuntu 22.04 = 3.10 / Ubuntu 24.04 = 3.12)。
#  Debian 11 与 Ubuntu 20.04 自带 3.9, 面板在 import 阶段就会崩 (见下面的版本闸门)。
#
#  用法 (服务器上, root):
#    curl -fsSL https://raw.githubusercontent.com/ericlinclover-blip/zeroproxy/main/install.sh | bash
#  受限网络上,**拿脚本这第一跳**也会被卡 —— 用自建反代把原始地址整个拼在后面:
#    curl -fsSL https://github.i3.pub/https://raw.githubusercontent.com/ericlinclover-blip/zeroproxy/main/install.sh | bash
#
#  可覆盖的变量:
#    ZP_REPO=owner/repo      改用 fork / 镜像仓库 (默认 ericlinclover-blip/zeroproxy)
#    ZP_REF=main|v2.2        指定分支或 tag (默认取最新 release, 仓库无 release 时用 main)
#    ZP_PORT=8899            面板端口
#    XRAY_VERSION=24.11.30   指定 Xray 版本 (默认 latest)
#
#  完成后终端输出初始化页地址 http://<IP>/ (80 端口, 打开即初始化页, 没有证书警告;
#  同一页也挂在 https://<IP>:8899, 那是自签证书 —— 打不开 80 时用它, 浏览器需点一次
#  "继续访问"), 浏览器打开 → 输入 域名/用户名/密码 → 一键生成全部配置。
# ============================================================
set -Eeuo pipefail

# ---------------- 常量 ----------------
ZP_HOME="/opt/zeroproxy"
PANEL_PORT="${ZP_PORT:-8899}"
XRAY_BIN="/usr/local/bin/xray"
HYSTERIA_BIN="/usr/local/bin/hysteria"
GH="https://github.com"
GH_API="https://api.github.com"
#: GitHub 反代前缀。**自建的反代排第一** —— 与面板那边内核 / 分流数据两张表同一套策略
#: (运营方自己的反代比任何公共前缀都稳)。写法同 gh-proxy: 把原始地址整个拼在前缀后面。
#: 受限线路上直连 GitHub 是"卡满超时再失败", 排前面只会白吃整个部署的时间预算 ——
#: 这正是"服务器端部署卡在网络限制"的来源 (8.72)。
GH_PROXIES=(
  "https://github.i3.pub"
  "https://gh-proxy.com"
  "https://hk.gh-proxy.com"
  "https://ghfast.top"
)
# 前缀 + 原始地址 (空前缀 = 直连)。
zp_url() { if [ -z "$1" ]; then printf '%s' "$2"; else printf '%s/%s' "$1" "$2"; fi; }
# 从一个 GitHub 地址取文件: 反代依次试, 最后才直连。$1=完整 GitHub 地址, $2=落地文件。
# 拿到的必须是**非空文件**才算成 —— 反代有时会回一页 HTML (200), 那不是我们想要的东西。
# 注意 api.github.com 不走反代 (这类反代只透传 release / archive / raw), 版本号那几次
# 查询仍然是直连: 它们本来就带 --max-time 20, 失败可容忍 (有兜底地址)。
fetch_github_file() {
  local url="$1" out="$2" p
  for p in "${GH_PROXIES[@]}" ""; do
    rm -f "$out"
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL --connect-timeout 10 --max-time 300 -o "$out" "$(zp_url "$p" "$url")" 2>/dev/null \
        && [ -s "$out" ] && return 0
    else
      wget -q --timeout=90 --tries=1 -O "$out" "$(zp_url "$p" "$url")" 2>/dev/null \
        && [ -s "$out" ] && return 0
    fi
  done
  rm -f "$out"
  return 1
}
# 面板核心来源: 默认官方仓库; 远程安装时从这里拉取 tarball。
ZP_REPO="${ZP_REPO:-ericlinclover-blip/zeroproxy}"
ZP_DEFAULT_REF="${ZP_DEFAULT_REF:-main}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

info() { printf '\033[1;34m[ZeroProxy]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ZeroProxy]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[ZeroProxy]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[ZeroProxy]\033[0m %s\n' "$*"; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "请以 root 运行 (sudo bash install.sh)"

# --- ZP_SESSION_GUARD (断线自保; 下面 ---- 之间的两行标记给回归脚本取这一段) ---
# 真机反馈: 在 SSH 里跑 `curl … | bash`, 走到"创建 Python 虚拟环境并安装依赖"那一步会话
# 断了 (`[session closed (code 0)]`), 安装就停在那儿 —— **没有报错**, 用户也不知道为什么。
# 那一步要下几十 MB 的 wheel (整条安装最慢的一段), 而这条路本来就容易抖。所以: 只要是在
# SSH 会话里、从**远程脚本**跑的, 就把活交给一个**独立会话** (setsid) 去做, 前台只 tail
# 日志 —— 断线不再影响安装; 回来 `tail -f` 一下就知道装到哪、装完没有。
#   * 想留在前台原地跑:  ZP_NO_DETACH=1
#   * 已经在独立会话里:  ZP_DETACHED=1 (子进程自己带着这个标记重跑, 不再套娃)
#   * tmux / screen 里本来就不怕断线 —— 不动
#   * 本地代码目录里跑 (开发 / 复现) —— 不动, 免得把本地改动换成了远端那份
if [ -z "${ZP_DETACHED:-}" ] && [ -z "${ZP_NO_DETACH:-}" ] && [ -n "${SSH_CONNECTION:-}" ] \
   && [ -z "${TMUX:-}" ] && [ ! -f "$SCRIPT_DIR/backend/zeroproxy/main.py" ] \
   && command -v setsid >/dev/null 2>&1; then
  mkdir -p "$ZP_HOME/data"
  ZP_LOG="$ZP_HOME/data/install.log"
  ZP_SELF="/tmp/zp-install-$$.sh"
  ZP_SELF_OK=0
  # 取一份自己: 与用户手上这份同源 (同一仓库 / 同一 ref), 走同一张镜像表
  for _p in "${GH_PROXIES[@]}" ""; do
    if fetch_github_file "$(zp_url "$_p" "$GH/$ZP_REPO/${ZP_REF:-$ZP_DEFAULT_REF}/install.sh")" "$ZP_SELF" \
       && grep -q "ZP_DETACHED" "$ZP_SELF"; then
      ZP_SELF_OK=1
      break
    fi
  done
  if [ "$ZP_SELF_OK" = "1" ]; then
    printf '\n[ZeroProxy] ===== %s 这次安装放到独立会话里跑 (SSH 断线不影响) =====\n' \
      "$(date '+%F %T')" >>"$ZP_LOG"
    info "检测到 SSH 会话: 安装改在**独立会话**里继续 —— 中途断线也不会中断"
    info "实时看进度: tail -f $ZP_LOG   (Ctrl-C 只停这个 tail, 安装继续)"
    setsid env ZP_DETACHED=1 bash "$ZP_SELF" >>"$ZP_LOG" 2>&1 </dev/null &
    ZP_CHILD=$!
    tail -n 1 -f "$ZP_LOG" &
    ZP_TAIL=$!
    ZP_RC=0
    wait "$ZP_CHILD" || ZP_RC=$?
    kill "$ZP_TAIL" 2>/dev/null || true
    rm -f "$ZP_SELF"
    if [ "$ZP_RC" = "0" ]; then
      ok "安装结束 (退出码 0); 全文日志: $ZP_LOG"
    else
      warn "安装以退出码 $ZP_RC 结束 —— 原因在日志里: $ZP_LOG"
    fi
    exit "$ZP_RC"
  fi
  warn "取不到自己的副本 (镜像都不通?) —— 就在当前会话里继续; 中途断线会中断安装, 重跑本脚本即可 (已装的部分会保留)"
fi
# --- /ZP_SESSION_GUARD ---

# ---------------- 1. 系统检测 ----------------
. /etc/os-release
DISTRO="${ID:-unknown}"
case "$DISTRO" in
  ubuntu|debian|kali|linuxmint) info "系统: $PRETTY_NAME" ;;
  openwrt|immortalwrt|lede|*wrt*|*openwrt*)
    # 这台机器是**路由器**, 而这个脚本装的是**面板** (服务器侧: nginx / systemd / certbot /
    # Python venv) —— 路由器上装不了, 也没有意义 (面板要一台有公网地址的服务器)。
    # 不说清楚的话, 用户在这一步拿到的是 "dpkg: command not found" 这种句子 (真机截图里
    # 就有), 然后以为程序坏了。路由器那一侧要装的是**客户端**, 由面板生成一行命令。
    fail "这台机器是 OpenWrt 路由器 (${PRETTY_NAME:-$DISTRO}), 而 install.sh 是**面板 (服务器端)**的部署脚本。
  面板要装在服务器上 (Ubuntu / Debian, 有公网 IP 或域名), 不是装在路由器上。
  路由器端 (客户端) 请用面板「客户端」页「生成安装命令」给出的那一行 —— 它带着一次性的
  配对码、并且自带重试与证书兜底, 直接复制到路由器终端里跑即可。
  还没有面板就先在服务器上跑这条命令把它装好, 然后回面板生成那条安装命令。"
    ;;
  *) warn "未测试的发行版: $DISTRO, 继续尝试 (apt 系)..." ;;
esac
# 2>/dev/null + || true: 少数 (非 apt 系) 系统上没有 dpkg, 而 set -e 下命令替换失败会
# 直接把脚本干掉 —— 那时用户看到的是一行 `dpkg: command not found`, 看不出是哪一步、
# 也不知道该换什么命令 (真机截图里就是这一句)。
ARCH="$(dpkg --print-architecture 2>/dev/null || true)"   # amd64 / arm64
[ -n "$ARCH" ] || ARCH="$(uname -m)"

# ---------------- 2. 内核优化: BBR + 拥塞控制 (Role.md 交付物 2) ----------------
info "配置内核参数: 开启 Google BBR ..."
cat > /etc/sysctl.d/99-zeroproxy.conf <<'SYSCTL'
# ZeroProxy 内核优化
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fastopen = 3
fs.file-max = 1000000
# 有 swap 时 (见下面 2a) 也别急着往盘上倒: 内存尖峰照旧能用, 平时优先留在内存里
vm.swappiness = 10
SYSCTL
sysctl --system >/dev/null 2>&1 || true
if [ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)" = "bbr" ]; then
  ok "BBR 已启用"
else
  warn "BBR 不可用 (旧内核?), 使用默认拥塞控制"
fi

# ---------------- 2a. 小内存机器补一块 swap ----------------
# 为什么做这件事: 这类面板大多装在 512 MB / 1 GB 的小机上, 而 `pip install` 解 wheel、以及
# 面板自己合并 30 MB 的分流数据, 都是内存尖峰。内存打满时 Linux 的 OOM killer 会挑一个进程
# 杀 —— 在"大内存进程"里 **sshd 常常中选**: 用户看到的现象就是"SSH 会话突然断了, 安装停在
# 装依赖那一步, 一点报错都没有" (真机反馈: 走到"创建 Python 虚拟环境并安装依赖"就
# `[session closed]`)。一块 swap 是最便宜的兜底。
# 只在"真的小 + 本来就没有 swap + 磁盘放得下"时做; 任何一步失败都不影响安装;
# 不想动: ZP_NO_SWAP=1。
if [ -z "${ZP_NO_SWAP:-}" ]; then
  MEM_MB="$(awk '/^MemTotal:/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || true)"
  SWAP_MB="$(awk '/^SwapTotal:/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || true)"
  FREE_MB="$(df -Pm / 2>/dev/null | awk 'NR==2 {print int($4)}' || true)"
  MEM_MB="${MEM_MB:-0}"
  SWAP_MB="${SWAP_MB:-0}"
  FREE_MB="${FREE_MB:-0}"
  if [ "$MEM_MB" -gt 0 ] && [ "$MEM_MB" -lt 1024 ] && [ "$SWAP_MB" -lt 128 ] \
     && [ ! -e /swapfile ] && [ "$FREE_MB" -ge 3072 ]; then
    info "内存只有 ${MEM_MB} MB 且没有 swap: 加一块 1 GB swap (装依赖与合并分流数据时的尖峰有地方去)"
    if fallocate -l 1G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none 2>/dev/null; then
      chmod 600 /swapfile
      if mkswap /swapfile >/dev/null 2>&1 && swapon /swapfile 2>/dev/null; then
        grep -q '^/swapfile ' /etc/fstab 2>/dev/null || printf '/swapfile none swap sw 0 0\n' >>/etc/fstab
        ok "swap 已启用 (1 GB; 想撤掉: swapoff /swapfile, 删掉 /swapfile 与 /etc/fstab 里那一行)"
      else
        rm -f /swapfile
        warn "swap 启用失败 (不影响安装; 内存吃紧时装依赖可能被 OOM 杀掉 —— 查: dmesg | grep -i oom)"
      fi
    else
      warn "swap 文件建不出来 (磁盘空间不够?) —— 不影响安装"
    fi
  fi
fi

# ---------------- 3. 依赖 ----------------
info "安装依赖 (nginx / certbot / python3) ..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y >/dev/null
apt-get install -y curl wget unzip git nginx openssl python3 python3-pip python3-venv cron >/dev/null
# 原生 WireGuard 节点需要 wg / wg-quick；装不上不让整个部署失败 (面板会显示缺少工具)
apt-get install -y wireguard-tools iptables >/dev/null 2>&1 \
  || warn "wireguard-tools 安装失败 (WireGuard 节点需手动安装; 其余协议不受影响)"
# 用户态回退 (容器 / 内核没有 WireGuard 模块时)。装不上不影响内核模式。
apt-get install -y wireguard-go >/dev/null 2>&1 \
  || warn "wireguard-go 安装失败 (内核没有 WireGuard 模块的容器将无法启用 WireGuard)"
apt-get install -y certbot 2>/dev/null || warn "certbot 安装失败 (面板将回退自签证书)"
systemctl enable --now nginx

# ---------------- 3a. Python 版本闸门 ----------------
# 面板代码的语法下限是 **Python 3.10** (Debian 12 = 3.11 / Debian 13 = 3.13 /
# Ubuntu 22.04 = 3.10 / Ubuntu 24.04 = 3.12 都在这条线之上; Debian 11 与 Ubuntu 20.04
# 自带 3.9)。低于这条线时坏掉的不是"某个功能", 而是**整个面板**: 进程在 import 阶段就
# SyntaxError, systemd 反复重启, 用户看到的现象只是"面板打不开", 而那条日志没人会读。
# v2.11.42 真的踩到了 (一行 f-string 用了 3.12 才允许的写法): 开发机是 3.14, 326 项
# 回归全绿, 而 Debian 12 上装完就是起不来。所以拦在这里, 一句话说清是哪一类问题,
# 而不是把一堆 SyntaxError 留给用户 (见 README 8.94)。
# 挑解释器: 从新到旧看一遍, 取**第一个够版本**的。为什么不是直接用 `python3` ——
# "装一个 3.10+" 这条建议在 Debian 11 / Ubuntu 20.04 上通常意味着再装一个 python3.11,
# 而那时 `python3` 还是 3.9: 死认 python3 会把这类机器永远挡在门外 (装了解释器也没用)。
# 注: Debian 12 自带 `python3.11` 与 `python3` 两个名字, Ubuntu 22.04 自带 `python3.10`。
PY=""
for _cand in python3.13 python3.12 python3.11 python3.10 python3; do
  command -v "$_cand" >/dev/null 2>&1 || continue
  if "$_cand" -c 'import sys; sys.exit(0 if sys.version_info[:2] >= (3, 10) else 1)' 2>/dev/null; then
    PY="$_cand"
    break
  fi
done
if [ -z "$PY" ]; then
  fail "本机没有 Python 3.10+ (python3 是 $(python3 -V 2>&1 || echo '不存在')).
  面板要求 Python >= 3.10, 支持的系统: Debian 12+ / Ubuntu 22.04+。
  Debian 11 与 Ubuntu 20.04 自带的 Python 3.9 装不了面板 (代码里的类型写法在那上面
  直接 TypeError)。请先升级系统, 或装一个 3.10+ 的解释器 (Debian/Ubuntu:
  apt-get install -y python3.11 python3.11-venv) 后重跑本脚本 —— 脚本会自己挑最高的那个。"
fi
info "Python: $("$PY" -V 2>&1)"

# ---------------- 4. Xray Core (VLESS Reality / WS / Trojan) ----------------
# 资产命名历代不一致 (64 / arm64-v8a), 统一从 release JSON 解析下载地址
info "下载 Xray Core ..."
# 默认安装最新稳定版; 如未来版本改动配置格式, 可用 XRAY_VERSION=24.11.30 bash install.sh 回退
XRAY_VERSION="${XRAY_VERSION:-latest}"
# 回退版本: 当上面的 latest 无法从 API 解析出下载地址时使用 (latest 无法直接拼出 URL)
XRAY_PINNED="${XRAY_PINNED:-24.11.30}"
if [ "$XRAY_VERSION" = "latest" ]; then
  XRAY_REL="releases/latest"
  XRAY_DL_VERSION="$XRAY_PINNED"
else
  XRAY_REL="releases/tags/v${XRAY_VERSION}"
  XRAY_VERSION="${XRAY_VERSION#v}"
  XRAY_DL_VERSION="$XRAY_VERSION"
fi
XRAY_JSON="$(curl -fsSL --max-time 20 "$GH_API/repos/XTLS/Xray-core/$XRAY_REL" || true)"
case "$ARCH" in
  arm64) XRAY_ASSET_PAT="Xray-linux-arm64(-v8a)?\\.zip$" ;;
  *)     XRAY_ASSET_PAT="Xray-linux-64\\.zip$" ;;
esac
# 注意: 这里是单引号包裹的 sed 脚本, 必须写 \1; 写成 \\1 会替换成字面量 "\1",
# 后面的 grep 一个都匹配不到 → 在 pipefail 下静默退出, 连"下载失败"提示都打不出来。
XRAY_URL="$(printf '%s' "$XRAY_JSON" | grep -oE '"browser_download_url": *"[^"]+"' | sed -E 's/.*"([^"]+)"$/\1/' | grep -E "$XRAY_ASSET_PAT" | head -1 || true)"
[ -n "$XRAY_URL" ] || XRAY_URL="$GH/XTLS/Xray-core/releases/download/v${XRAY_DL_VERSION}/Xray-linux-$( [ "$ARCH" = "arm64" ] && echo arm64-v8a || echo 64 ).zip"
rm -f /tmp/xray.zip
fetch_github_file "$XRAY_URL" /tmp/xray.zip \
  || fail "Xray 下载失败 (反代与直连都没成): $XRAY_URL"
unzip -oq /tmp/xray.zip -d /usr/local/bin \
  || fail "Xray 压缩包解不开 (反代可能回了一页 HTML): $XRAY_URL"
chmod +x /usr/local/bin/xray
rm -f /tmp/xray.zip
ok "Xray $(/usr/local/bin/xray version 2>/dev/null | head -1 || echo installed)"

# ---------------- 5. Hysteria 2 (QUIC/UDP) ----------------
info "下载 Hysteria 2 ..."
HY_JSON="$(curl -fsSL --max-time 20 "$GH_API/repos/apernet/hysteria/releases/latest" || true)"
HY_TAG="$(printf '%s' "$HY_JSON" | grep -oP '"tag_name":\\s*"\\Kv?[^"]+' | head -1 || true)"
HY_URL="$(printf '%s' "$HY_JSON" | grep -oE '"browser_download_url": *"[^"]+"' | sed -E 's/.*"([^"]+)"$/\1/' | grep -E "hysteria-linux-${ARCH}(-v[0-9]+(\\.[0-9]+)*)?(\\.tar\\.gz)?$" | head -1 || true)"
[ -n "$HY_URL" ] || HY_URL="$GH/apernet/hysteria/releases/download/${HY_TAG:-v1.1.5}/hysteria-linux-${ARCH}.tar.gz"
HY_TAG="${HY_TAG#v}"; HY_TAG="${HY_TAG:-1.1.5}"
if fetch_github_file "$HY_URL" /tmp/hysteria-dl; then
  case "$HY_URL" in
    *.tar.gz)
      tar -xzf /tmp/hysteria-dl -C /tmp
      install -m 755 /tmp/hysteria "$HYSTERIA_BIN" ;;
    *)
      install -m 755 /tmp/hysteria-dl "$HYSTERIA_BIN" ;;
  esac
  ok "Hysteria $HY_TAG"
else
  warn "Hysteria 下载失败 (Hysteria 2 节点不可用, 其余协议正常)"
fi
rm -f /tmp/hysteria-dl /tmp/hysteria

# ---------------- 6. 面板核心 ----------------
info "安装面板核心 → $ZP_HOME ..."
mkdir -p "$ZP_HOME"/{xray,hysteria,data,www,certs,nginx,panel,geo,wireguard}

# 解析要安装的版本: ZP_REF 优先; 否则取最新 release tag; 仓库没有 release 时退回默认分支。
resolve_zp_ref() {
  if [ -n "${ZP_REF:-}" ]; then
    printf '%s' "$ZP_REF"
    return 0
  fi
  local tag=""
  tag="$(curl -fsSL --max-time 20 "$GH_API/repos/$ZP_REPO/releases/latest" 2>/dev/null \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1 || true)"
  printf '%s' "${tag:-$ZP_DEFAULT_REF}"
}

# 下载并校验仓库 tarball: tag → 分支 → API tarball 三级兜底。
# 用 curl (-f 让 404 立刻失败): 实测 wget 遇到 404 会重试到超时, 失败时要多等好几分钟。
# GitHub 对 tag 会剥掉前导 v 且不同 ref 的顶层目录名不同, 所以统一用 tar 列表定位目录。
fetch_zp_tarball() {
  local out="$1" ref="$2" url err sha bust
  err="$(mktemp)"
  # 先把分支 / tag 解析成提交 SHA: `archive/refs/heads/<分支>.tar.gz` 在推送后被 CDN
  # 缓存住时会**装到上一个版本** (真机上遇到过"刚发版, 装完还是旧号"); 按 SHA 下的是
  # 不可变快照, 永远是我们要的那一份。拿不到 SHA (API 被挡) 就退回原来的三级兜底,
  # 并给分支/tag 的地址带上时间戳强制回源。
  sha="$(curl -fsSL --max-time 20 "$GH_API/repos/$ZP_REPO/commits/$ref" 2>/dev/null \
        | sed -n 's/.*"sha": *"\([0-9a-f]\{40\}\)".*/\1/p' | head -1 || true)"
  bust="?t=$(date +%s)"
  # 每个反代前缀依次试 (自建的反代在前), 最后才是 GitHub 直连与 API tarball —— 与
  # upgrade.sh 的 fetch_tarball 同一套顺序。这两处一旦走偏, 就会出现"能升级却装不上"
  # 这种最难查的组合。
  local -a urls=() p
  for p in "${GH_PROXIES[@]}" ""; do
    [ -n "$sha" ] && urls+=("$(zp_url "$p" "$GH/$ZP_REPO/archive/$sha.tar.gz")")
    urls+=(
      "$(zp_url "$p" "$GH/$ZP_REPO/archive/refs/tags/$ref.tar.gz$bust")"
      "$(zp_url "$p" "$GH/$ZP_REPO/archive/refs/heads/$ref.tar.gz$bust")"
    )
  done
  urls+=("$GH_API/repos/$ZP_REPO/tarball/$ref")
  for url in "${urls[@]}"; do
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL --connect-timeout 10 --max-time 120 -o "$out" "$url" 2>"$err" || { rm -f "$out"; continue; }
    else
      wget -q --timeout=30 --tries=1 -O "$out" "$url" 2>"$err" || { rm -f "$out"; continue; }
    fi
    if tar -tzf "$out" >/dev/null 2>&1; then
      rm -f "$err"
      return 0
    fi
    rm -f "$out"
  done
  # 三级都失败: 只把最后一次的真实报错留给调用方打印, 避免满屏 404/重定向噪声
  ZP_DL_ERR="$(tail -1 "$err" 2>/dev/null || true)"
  rm -f "$err"
  return 1
}

if [ -f "$SCRIPT_DIR/backend/zeroproxy/main.py" ] && [ -d "$SCRIPT_DIR/systemd" ]; then
  info "检测到本地代码目录, 直接安装: $SCRIPT_DIR"
  SRC_DIR="$SCRIPT_DIR"
else
  # 远程安装 (curl | bash): 下载仓库 tarball, 需服务器能访问 GitHub
  ZP_REF_RESOLVED="$(resolve_zp_ref)"
  info "从 GitHub 下载面板核心 ($ZP_REPO @ $ZP_REF_RESOLVED) ..."
  rm -f /tmp/zp.tar.gz
  rm -rf /tmp/zp-src
  if ! fetch_zp_tarball /tmp/zp.tar.gz "$ZP_REF_RESOLVED"; then
    fail "面板核心下载失败: $ZP_REPO @ $ZP_REF_RESOLVED
       原因: ${ZP_DL_ERR:-无法访问 GitHub}
       可指定镜像或版本后重试: ZP_REPO=owner/repo ZP_REF=main bash install.sh"
  fi
  mkdir -p /tmp/zp-src
  tar -xzf /tmp/zp.tar.gz -C /tmp/zp-src
  SRC_DIR="$(find /tmp/zp-src -mindepth 1 -maxdepth 1 -type d | head -1)"
  [ -n "$SRC_DIR" ] || fail "解压失败: /tmp/zp.tar.gz"
fi

[ -f "$SRC_DIR/backend/zeroproxy/main.py" ] || fail "代码目录不完整 (缺少 backend/zeroproxy/main.py): $SRC_DIR"

# 先清掉旧代码再拷贝, 保证脚本可重复执行 (否则 cp -r 会套出 zeroproxy/zeroproxy)
rm -rf "$ZP_HOME/zeroproxy" "$ZP_HOME/static"
cp -r "$SRC_DIR/backend/zeroproxy" "$ZP_HOME/zeroproxy"
cp -r "$SRC_DIR/backend/static" "$ZP_HOME/static"
cp "$SRC_DIR/backend/requirements.txt" "$ZP_HOME/requirements.txt"
rm -rf "$ZP_HOME/zeroproxy/__pycache__" "$ZP_HOME/zeroproxy"/*/__pycache__
cp "$SRC_DIR"/systemd/*.service /etc/systemd/system/
# 一键升级脚本: 随代码装到面板目录, 供「程序更新」按钮与命令行共用
if [ -f "$SRC_DIR/upgrade.sh" ]; then
  cp "$SRC_DIR/upgrade.sh" "$ZP_HOME/upgrade.sh"
  chmod +x "$ZP_HOME/upgrade.sh"
fi
if [ -f "$SRC_DIR/uninstall.sh" ]; then
  cp "$SRC_DIR/uninstall.sh" "$ZP_HOME/uninstall.sh"
fi
rm -rf /tmp/zp.tar.gz /tmp/zp-src
ok "面板核心已就位 ($(basename "$ZP_REPO") @ ${ZP_REF_RESOLVED:-本地目录})"

info "创建 Python 虚拟环境并安装依赖 ..."
# 用上面那道闸门挑出来的解释器 ($PY)。venv 建好之后 python3 是多少就无关了 ——
# 面板进程、apply、geodata 走的都是这个 venv 里的 python。
"$PY" -m venv "$ZP_HOME/venv"
"$ZP_HOME/venv/bin/pip" install -q --upgrade pip
"$ZP_HOME/venv/bin/pip" install -q -r "$ZP_HOME/requirements.txt"

# ---------------- 6a. 终端快捷管理 (z) ----------------
# 面板密码只能在面板里改 —— 忘了就彻底进不去; 在线更新按钮也在面板里。SSH 是最后
# 一条一定走得通的路, 所以这里装一个 `z` 命令 (菜单: 改账号密码 / 在线更新 / 退出)。
# 生成逻辑在 Python 侧 (zeroproxy.cli install-shortcut), shell 里不再抄一遍;
# `z` 已被别的东西占用时不覆盖, 只装长名字 zeroproxy 并说明。
if [ -x "$ZP_HOME/venv/bin/python" ]; then
  if ZP_HOME="$ZP_HOME" PYTHONPATH="$ZP_HOME" "$ZP_HOME/venv/bin/python" -m zeroproxy.cli install-shortcut; then
    info "面板登不进去时: SSH 到本机输入 z 即可改账号密码 / 在线更新"
  else
    warn "终端快捷命令 z 安装失败 (不影响面板, 可用 $ZP_HOME/venv/bin/python -m zeroproxy.cli)"
  fi
fi

# ---------------- 6b. GeoIP / GeoSite 分流数据 ----------------
# Xray 在配置构建阶段就要读 geoip.dat / geosite.dat, 配置里有 geo 规则而数据
# 缺失会让整个 xray 服务起不来。这里预下载, 失败也不阻塞部署; 面板检测到数据
# 缺失时不会下发 geo 规则, 之后可在面板「高级设置」里一键补齐。
#

info "下载 GeoIP / GeoSite 分流数据 (约 28 MB) ..."
GEO_OK=0
for GEO_MIRROR in \
  "https://github.i3.pub/https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download" \
  "https://fastly.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release" \
  "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release" \
  "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download"
do
  wget -q --timeout=60 --tries=2 -O "$ZP_HOME/geo/geoip.dat" "$GEO_MIRROR/geoip.dat" || continue
  wget -q --timeout=60 --tries=2 -O "$ZP_HOME/geo/geosite.dat" "$GEO_MIRROR/geosite.dat" || continue
  GEO_SIZE_IP="$(stat -c%s "$ZP_HOME/geo/geoip.dat" 2>/dev/null || echo 0)"
  GEO_SIZE_ST="$(stat -c%s "$ZP_HOME/geo/geosite.dat" 2>/dev/null || echo 0)"
  if [ "$GEO_SIZE_IP" -gt 1000000 ] && [ "$GEO_SIZE_ST" -gt 1000000 ]; then
    GEO_OK=1
    ok "GeoIP/GeoSite 就绪 ($(( (GEO_SIZE_IP + GEO_SIZE_ST) / 1048576 )) MB)"
    break
  fi
done
if [ "$GEO_OK" != "1" ]; then
  warn "GeoIP 数据下载失败 — 不影响核心功能, 可稍后在面板里重试"
fi

# ---------------- 7. 初始配置 ----------------
# 首次部署: 写占位配置, 让 xray/hysteria 在面板 setup 之前也能正常启动。
# 已经初始化过的机器 (存在 data/state.json) 绝不能走这一步 —— 覆写会把已经生成的
# Reality 密钥 / 端口 / 订阅令牌打回占位状态, 结果是「服务全绿但 5 个节点全不通」。
PANEL_INITIALIZED=0
[ -f "$ZP_HOME/data/state.json" ] && PANEL_INITIALIZED=1

if [ "$PANEL_INITIALIZED" = "1" ]; then
  info "检测到已初始化的部署, 保留现有密钥与节点配置 (稍后按 state.json 重新落地)"
else
  info "首次部署: 写入占位配置 (面板完成 setup 后自动覆盖) ..."
  cat > "$ZP_HOME/xray/config.json" <<'JSON'
{"log": {"loglevel": "warning"}, "inbounds": [], "outbounds": [{"protocol": "freedom"}]}
JSON
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=zeroproxy.local" \
    -keyout "$ZP_HOME/hysteria/key.pem" -out "$ZP_HOME/hysteria/cert.pem" 2>/dev/null
  cat > "$ZP_HOME/hysteria/config.yaml" <<YAML
# 占位配置, 面板完成部署后会被自动覆盖
listen: "127.0.0.1:30001"
tls:
  cert: $ZP_HOME/hysteria/cert.pem
  key: $ZP_HOME/hysteria/key.pem
auth:
  type: password
  password: "changeme"
YAML
  chmod 600 "$ZP_HOME/hysteria/key.pem"
fi

# 引导令牌 (0600): 面板初始化时必须提供它, 防止公网暴露时被别人抢先完成部署。
# 已经初始化过的机器 (存在 state.json) 不重新签发, 避免把令牌重新暴露出来。
if [ ! -f "$ZP_HOME/data/state.json" ]; then
  openssl rand -hex 16 > "$ZP_HOME/data/bootstrap_token"
  chmod 600 "$ZP_HOME/data/bootstrap_token"
  ZP_TOKEN="$(cat "$ZP_HOME/data/bootstrap_token")"
else
  ZP_TOKEN=""
fi

# 面板自身 HTTPS: 生成自签证书 (含服务器 IP/localhost 的 SAN)。
# 浏览器首次访问会提示证书不受信任, 点「继续」即可; 目的是让面板登录/会话走 TLS。
SERVER_IP="$(curl -4 -fsSL --max-time 10 https://api.ipify.org 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}' || true)"
SERVER_IP="${SERVER_IP:-127.0.0.1}"
mkdir -p "$ZP_HOME/panel"
if [ -f "$ZP_HOME/panel/cert.pem" ] && [ -f "$ZP_HOME/panel/key.pem" ]; then
  info "面板自签证书已存在, 保留 ($ZP_HOME/panel/cert.pem)"
else
  info "生成面板自签证书 (CN=zeroproxy-panel, IP=$SERVER_IP) ..."
  if ! openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=zeroproxy-panel" \
        -addext "subjectAltName=IP:${SERVER_IP},IP:127.0.0.1,DNS:localhost" \
        -keyout "$ZP_HOME/panel/key.pem" -out "$ZP_HOME/panel/cert.pem" 2>/dev/null; then
    # 老版本 openssl 不支持 -addext 时的兜底
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=zeroproxy-panel" \
      -keyout "$ZP_HOME/panel/key.pem" -out "$ZP_HOME/panel/cert.pem" 2>/dev/null
  fi
  chmod 600 "$ZP_HOME/panel/key.pem"
fi

# 面板对外由 nginx 在 $PANEL_PORT 终结 TLS 并反代到本机面板进程。
# 这里只是引导配置 (用自签证书); 面板完成 setup 后会重新生成, 改用真实证书。
if [ "$PANEL_INITIALIZED" = "1" ]; then
  info "已初始化部署: 保留面板现有的 nginx 配置 (稍后由 zeroproxy.apply 重新落地)"
else
NGINX_PANEL_BIND="${ZP_BIND_PORT:-9900}"
info "配置 nginx 面板反向代理 (:$PANEL_PORT → 127.0.0.1:$NGINX_PANEL_BIND) ..."

# 引导期"面板还没起来"时返回的那一页 (下面两个 server 块共用这一份)。
# 为什么需要它: install.sh 打印链接的那一刻, 面板可能还在 import fastapi / cryptography
# (1 核小机上要几秒), 也可能刚崩过、正在被 systemd 拉起来 —— 那时 nginx 回的是它自己的
# **502 页**, 用户以为装坏了, 于是对着它一遍遍手动刷新 ("要刷新很多次页面才会跳出",
# 真机反馈)。这一页自己每 3 秒重试一次, 并把 `?token=` 原样带回去 (不带回去的话, 重试
# 之后初始化页会提示"请用带 ?token= 的链接打开本页")。
# 用 quoted heredoc 生成: 里面的 HTML 一个 shell 变量都不展开, 于是引号一个都不用转义。
ZP_BOOTING_BLOCK="$(cat <<'ZPBOOTING'
    # 面板正在启动 (冷启动 / 崩了正在重启): 给一页自己会重试的话, 而不是 nginx 的 502
    error_page 502 503 504 = @zp_booting;
    location @zp_booting {
        default_type text/html;
        return 200 '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>ZeroProxy · 面板正在启动</title></head><body style="font-family:-apple-system,Segoe UI,sans-serif;max-width:34rem;margin:12vh auto;padding:0 1.4rem;text-align:center;color:#333"><h2 style="font-weight:650">面板正在启动…</h2><p style="color:#666">这一页每 3 秒自动重试一次, 不需要手动刷新, 也不用重新打开链接。</p><p id="zpwait" style="color:#999;font-size:.9rem"></p><p style="color:#999;font-size:.85rem">停在这里超过一分钟: SSH 到本机执行 journalctl -u zeroproxy -n 30 看面板为什么没起来。</p><script>var n=0;var el=document.getElementById("zpwait");setInterval(function(){n+=3;el.textContent="已等待 "+n+" 秒";},1000);setTimeout(function(){location.replace(location.pathname+location.search);},3000);</script></body></html>';
    }
ZPBOOTING
)"

cat > /etc/nginx/conf.d/zeroproxy.conf <<NGINX
# 由 ZeroProxy install.sh 生成的引导配置 — 面板完成 setup 后会覆盖本文件
upstream zeroproxy_panel {
    server 127.0.0.1:$NGINX_PANEL_BIND;
}
server {
    listen $PANEL_PORT ssl default_server;
    listen [::]:$PANEL_PORT ssl default_server;
    server_name _;
    ssl_certificate $ZP_HOME/panel/cert.pem;
    ssl_certificate_key $ZP_HOME/panel/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
${ZP_BOOTING_BLOCK}
    location / {
        proxy_pass http://zeroproxy_panel;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 3600s;
    }
}

# 初始化页同时挂在 **80 端口的明文 HTTP** 上。
# 为什么: 引导阶段面板用的是自签证书, 浏览器打开 https://<IP>:$PANEL_PORT 会先拦一页
# "您的连接不是私密连接" —— 用户点开终端给的那条链接, 想看的是初始化页, 不是证书警告。
# 而 80 是 ACME 必须放行的端口 (几乎不存在没开的情况), 所以让第一跳走它:
# 点链接 → 直接就是初始化页。
# 只按 IP 匹配 server_name (不用 default_server): 这样不必去动发行版自带的 default
# 站点, 也就不会撞上"duplicate default server"。
# 面板完成 setup 后, 这份引导配置会被 apply 生成的那份整体覆盖 —— 那时 80 端口只剩
# ACME 与跳 HTTPS, 面板不再以明文对外 (明文只存在于"还没有管理员账号"的引导期)。
server {
    listen 80;
    listen [::]:80;
    server_name $SERVER_IP;
    location ^~ /.well-known/acme-challenge/ {
        root $ZP_HOME/www;
    }
${ZP_BOOTING_BLOCK}
    location / {
        proxy_pass http://zeroproxy_panel;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 3600s;
    }
}
NGINX
if nginx -t >/dev/null 2>&1; then
  systemctl reload nginx 2>/dev/null || systemctl restart nginx
  ok "初始化页已就绪 (http://<IP>/ 与 https://<IP>:$PANEL_PORT)"
else
  warn "nginx 引导配置校验失败, 请检查 /etc/nginx/conf.d/zeroproxy.conf"
fi
fi

# ---------------- 8. systemd ----------------
systemctl daemon-reload
systemctl enable xray hysteria2 zeroproxy
if [ "$PANEL_INITIALIZED" = "1" ]; then
  # 已初始化: 按 state.json 重新生成 xray / nginx / hysteria 配置并热重载,
  # 顺带校验端口真的在监听 (避免"服务活着但节点不通")。
  APPLY_LOG="$ZP_HOME/data/install-apply.log"
  info "按现有 state.json 重新落地配置并热重载 ..."
  if env ZP_HOME="$ZP_HOME" PYTHONPATH="$ZP_HOME" "$ZP_HOME/venv/bin/python" -m zeroproxy.apply --quiet >>"$APPLY_LOG" 2>&1; then
    ok "配置已重新落地 (密钥 / 节点 / 订阅令牌均未改动)"
  else
    warn "重新落地有步骤失败 — 打开面板「程序更新」或点「一键诊断」查看; 日志: $APPLY_LOG"
    tail -n 5 "$APPLY_LOG" 2>/dev/null | sed 's/^/    /' >&2 || true
  fi
fi
systemctl restart xray hysteria2 zeroproxy || true
systemctl enable certbot.timer 2>/dev/null || true

# ---------------- 9. 防火墙 ----------------
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow 80/tcp >/dev/null
  ufw allow 443/tcp >/dev/null
  ufw allow "$PANEL_PORT/tcp" >/dev/null
  ufw allow 8443/tcp >/dev/null
  ufw allow 8444/tcp >/dev/null
  ufw allow 8445/tcp >/dev/null          # VLESS XHTTP + Reality
  ufw allow 30001:32001/udp >/dev/null   # Hysteria 2 + 端口跳跃
  ufw allow 51820/udp >/dev/null         # 原生 WireGuard
  ok "防火墙已放行 80/443/$PANEL_PORT/8443/8444/8445/tcp, 30001-32001/udp, 51820/udp"
else
  warn "请确认防火墙/安全组放行: 80,443,$PANEL_PORT,8443,8444,8445 (TCP) 与 30001-32001,51820 (UDP)"
fi

# ---------------- 9b. 第一跳自检 (链接现在就通吗) ----------------
# 打印链接之前先确认**那条链接此刻真的通**。以前这里 `systemctl restart` 完就直接打印 ——
# 而面板冷启动 (import uvicorn / fastapi / cryptography) 在一台 1 核小机上要几秒, 用户
# 正好在那几秒点开链接, 拿到的是 nginx 的 502 (引导配置里现在会回"面板正在启动"的重试页,
# 见上面的 ZP_BOOTING_BLOCK); 而用户不知道那是"等几秒就好", 只知道要一遍遍刷新。
# 这里做两件事: ① 等面板进程真的回话 (最多 30 秒); ② 经 nginx 按**用户那一跳**取一次
# 面板自己报的版本 —— 两条入口各判一次, 判据是 JSON 里的 "name" (那页启动页里没有这个
# 串, 所以 502 的重试页不会被误判成"通了")。自检不过就把该查哪里印在终端上。
BIND_PORT="${NGINX_PANEL_BIND:-${ZP_BIND_PORT:-9900}}"
PANEL_READY=0
for _try in $(seq 1 30); do
  if curl -fsS --max-time 3 "http://127.0.0.1:$BIND_PORT/api/info" 2>/dev/null | grep -q '"name"'; then
    PANEL_READY=1
    break
  fi
  sleep 1
done
HOP_HTTP="no"
HOP_TLS="no"
if curl -fsS --max-time 8 -H "Host: $SERVER_IP" "http://127.0.0.1/api/info" 2>/dev/null | grep -q '"name"'; then
  HOP_HTTP="yes"
fi
# TLS 那一跳从本机回环打 (-k: 自签证书, 且 SNI 是 127.0.0.1): 只确认 nginx → 面板这一段
if curl -fsSk --max-time 8 -H "Host: $SERVER_IP" "https://127.0.0.1:$PANEL_PORT/api/info" 2>/dev/null | grep -q '"name"'; then
  HOP_TLS="yes"
fi
if [ "$HOP_HTTP" = "yes" ] || [ "$HOP_TLS" = "yes" ]; then
  ok "初始化页自检: 80 端口 $HOP_HTTP · $PANEL_PORT TLS $HOP_TLS (nginx 到面板这一段是通的)"
  [ "$PANEL_READY" = "1" ] || info "面板进程那条直连探测没通 (端口被自定义过时会这样), 但经 nginx 的入口是通的"
elif [ "$PANEL_READY" = "0" ]; then
  warn "面板 30 秒内没有回话 —— 打开链接会看到「面板正在启动」, 那一页会自己重试。查原因: journalctl -u zeroproxy -n 30"
else
  warn "初始化页自检没过 (nginx 到面板这一段不通): journalctl -u zeroproxy -n 30 · tail -20 /var/log/nginx/error.log"
fi

# ---------------- 10. 完成 ----------------
echo
if [ -n "$ZP_TOKEN" ]; then
  PANEL_URL="http://${SERVER_IP}/?token=${ZP_TOKEN}"
  PANEL_URL_TLS="https://${SERVER_IP}:$PANEL_PORT/?token=${ZP_TOKEN}"
else
  PANEL_URL="http://${SERVER_IP}/"
  PANEL_URL_TLS="https://${SERVER_IP}:$PANEL_PORT/"
fi
ok "=============================================="
ok "  ZeroProxy 部署完成!"
ok "  初始化页:  $PANEL_URL"
ok "  (80 端口明文 HTTP —— 打开就是初始化页, 没有证书警告, 也不需要额外放行端口)"
ok "  备用地址:  $PANEL_URL_TLS"
ok "  (面板自签证书, 浏览器会提示不安全, 点「继续访问」; 80 被占用 / 被拦时用它)"
ok "  打开链接 → 输入 域名/用户名/密码 → 一键生成"
ok "  完成后请改用 https://<你的域名>:$PANEL_PORT 访问面板 (真实证书, 无警告)"
ok "=============================================="
if [ -n "$ZP_TOKEN" ]; then
  echo "  ⚠ 上面的 ?token=... 是初始化引导令牌, 只可使用一次;"
  echo "    请勿转发给他人 — 拿到它的人可以先完成初始化。"
  echo "    令牌文件: $ZP_HOME/data/bootstrap_token (初始化成功后自动删除)"
fi
echo "  之后: 浏览器打开上面链接, 输入你的域名 (已 A 记录解析到本服务器),"
echo "  管理用户名与密码, 点击「一键生成」, 即可得到全部节点 + 订阅 + 二维码。"
echo "  链式代理 (两台机器接成一条链) 在面板「链式代理」里配置: 落地端生成配对码, 入口端粘贴即用;"
echo "  它用到的额外端口 (默认 8447/tcp 与自动分配的入站端口) 会在面板里自动 ufw 放行,"
echo "  云厂商安全组需自行放行 —— 云端没放行是链式连不通最常见的原因。"
echo "  WireGuard 在面板「WireGuard」卡片里一键启用; 每个客户端扫码或下载 .conf 即可,"
echo "  默认 51820/udp, 云厂商安全组同样要放行该 UDP 端口。"
echo "  卸载: bash $ZP_HOME/uninstall.sh  (或重新下载仓库里的 uninstall.sh)"
echo "  提示: 这次安装如果中途断过 SSH —— 重跑本脚本是安全的 (已装的部分会保留), 日志在"
echo "        $ZP_HOME/data/install.log"
echo
