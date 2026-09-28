#!/usr/bin/env bash
# ============================================================
#  ZeroProxy 一键部署脚本  —  Ubuntu / Debian
#
#  用法 (服务器上, root):
#    curl -fsSL https://raw.githubusercontent.com/ericlinclover-blip/zeroproxy/main/install.sh | bash
#
#  可覆盖的变量:
#    ZP_REPO=owner/repo      改用 fork / 镜像仓库 (默认 ericlinclover-blip/zeroproxy)
#    ZP_REF=main|v2.2        指定分支或 tag (默认取最新 release, 仓库无 release 时用 main)
#    ZP_PORT=8899            面板端口
#    XRAY_VERSION=24.11.30   指定 Xray 版本 (默认 latest)
#
#  完成后终端输出面板地址 https://<IP>:8899 (自签证书, 浏览器需点一次"继续访问"),
#  浏览器打开 → 输入 域名/用户名/密码 → 一键生成全部配置。
# ============================================================
set -Eeuo pipefail

# ---------------- 常量 ----------------
ZP_HOME="/opt/zeroproxy"
PANEL_PORT="${ZP_PORT:-8899}"
XRAY_BIN="/usr/local/bin/xray"
HYSTERIA_BIN="/usr/local/bin/hysteria"
GH="https://github.com"
GH_API="https://api.github.com"
# 面板核心来源: 默认官方仓库; 远程安装时从这里拉取 tarball。
ZP_REPO="${ZP_REPO:-ericlinclover-blip/zeroproxy}"
ZP_DEFAULT_REF="${ZP_DEFAULT_REF:-main}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

info() { printf '\033[1;34m[ZeroProxy]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ZeroProxy]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[ZeroProxy]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[ZeroProxy]\033[0m %s\n' "$*"; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "请以 root 运行 (sudo bash install.sh)"

# ---------------- 1. 系统检测 ----------------
. /etc/os-release
DISTRO="${ID:-unknown}"
case "$DISTRO" in
  ubuntu|debian|kali|linuxmint) info "系统: $PRETTY_NAME" ;;
  *) warn "未测试的发行版: $DISTRO, 继续尝试 (apt 系)..." ;;
esac
ARCH="$(dpkg --print-architecture)"   # amd64 / arm64
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
SYSCTL
sysctl --system >/dev/null 2>&1 || true
if [ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)" = "bbr" ]; then
  ok "BBR 已启用"
else
  warn "BBR 不可用 (旧内核?), 使用默认拥塞控制"
fi

# ---------------- 3. 依赖 ----------------
info "安装依赖 (nginx / certbot / python3) ..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y >/dev/null
apt-get install -y curl wget unzip git nginx openssl python3 python3-pip python3-venv cron >/dev/null
apt-get install -y certbot 2>/dev/null || warn "certbot 安装失败 (面板将回退自签证书)"
systemctl enable --now nginx

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
wget -q -O /tmp/xray.zip "$XRAY_URL" || fail "Xray 下载失败: $XRAY_URL"
unzip -oq /tmp/xray.zip -d /usr/local/bin
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
if wget -q -O /tmp/hysteria-dl "$HY_URL"; then
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
mkdir -p "$ZP_HOME"/{xray,hysteria,data,www,certs,nginx,panel,geo}

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
  local out="$1" ref="$2" url err
  err="$(mktemp)"
  for url in \
    "$GH/$ZP_REPO/archive/refs/tags/$ref.tar.gz" \
    "$GH/$ZP_REPO/archive/refs/heads/$ref.tar.gz" \
    "$GH_API/repos/$ZP_REPO/tarball/$ref"
  do
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
python3 -m venv "$ZP_HOME/venv"
"$ZP_HOME/venv/bin/pip" install -q --upgrade pip
"$ZP_HOME/venv/bin/pip" install -q -r "$ZP_HOME/requirements.txt"

# ---------------- 6b. GeoIP / GeoSite 分流数据 ----------------
# Xray 在配置构建阶段就要读 geoip.dat / geosite.dat, 配置里有 geo 规则而数据
# 缺失会让整个 xray 服务起不来。这里预下载, 失败也不阻塞部署; 面板检测到数据
# 缺失时不会下发 geo 规则, 之后可在面板「高级设置」里一键补齐。
#

info "下载 GeoIP / GeoSite 分流数据 (约 28 MB) ..."
GEO_OK=0
for GEO_MIRROR in \
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
  ok "面板反向代理已就绪 (https://<IP>:$PANEL_PORT)"
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
  ok "防火墙已放行 80/443/$PANEL_PORT/8443/8444/8445/tcp, 30001-32001/udp"
else
  warn "请确认防火墙/安全组放行: 80,443,$PANEL_PORT,8443,8444,8445 (TCP) 与 30001-32001 (UDP)"
fi

# ---------------- 10. 完成 ----------------
echo
if [ -n "$ZP_TOKEN" ]; then
  PANEL_URL="https://${SERVER_IP}:$PANEL_PORT/?token=${ZP_TOKEN}"
else
  PANEL_URL="https://${SERVER_IP}:$PANEL_PORT/"
fi
ok "=============================================="
ok "  ZeroProxy 部署完成!"
ok "  面板地址:  $PANEL_URL"
ok "  (引导阶段用自签证书, 浏览器首次提示不安全, 点「继续访问」)"
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
echo "  卸载: bash $ZP_HOME/uninstall.sh  (或重新下载仓库里的 uninstall.sh)"
echo
