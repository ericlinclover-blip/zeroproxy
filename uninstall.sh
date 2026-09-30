#!/usr/bin/env bash
# ============================================================
#  ZeroProxy 卸载脚本 — 与 install.sh 对称
#
#  用法 (服务器上, root):
#    bash uninstall.sh           # 停服务 + 删除 /opt/zeroproxy + systemd 单元 + nginx 配置
#    ZP_KEEP_DATA=1 bash uninstall.sh   # 保留 /opt/zeroproxy/data (含密钥/口令/订阅令牌)
#    ZP_KEEP_CERT=1 bash uninstall.sh   # 保留 Let's Encrypt 证书 (不执行 certbot delete)
# ============================================================
set -Eeuo pipefail

ZP_HOME="${ZP_HOME:-/opt/zeroproxy}"
PANEL_PORT="${ZP_PORT:-8899}"

info() { printf '\033[1;34m[ZeroProxy]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ZeroProxy]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[ZeroProxy]\033[0m %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "请以 root 运行 (sudo bash uninstall.sh)"; exit 1; }

info "停止并禁用服务 ..."
for unit in zeroproxy xray hysteria2; do
  systemctl disable --now "$unit" 2>/dev/null || true
  rm -f "/etc/systemd/system/${unit}.service"
done
systemctl daemon-reload 2>/dev/null || true

info "移除 nginx 面板配置 ..."
rm -f /etc/nginx/conf.d/zeroproxy.conf
if command -v nginx >/dev/null && nginx -t >/dev/null 2>&1; then
  systemctl reload nginx 2>/dev/null || systemctl restart nginx 2>/dev/null || true
fi

info "移除终端快捷命令 (z / zeroproxy) ..."
# 只删我们装的那两个: 万一 `z` 是用户自己/别的东西的, 别替人做主
for cmd in /usr/local/bin/z /usr/local/bin/zeroproxy; do
  if [ -f "$cmd" ] && grep -q "ZeroProxy 终端快捷管理" "$cmd" 2>/dev/null; then
    rm -f "$cmd" && ok "已移除 $cmd"
  fi
done

if [ "${ZP_KEEP_CERT:-0}" != "1" ]; then
  DOMAIN="$(python3 -c "import json;print(json.load(open('$ZP_HOME/data/state.json')).get('domain',''))" 2>/dev/null || true)"
  if [ -n "$DOMAIN" ] && command -v certbot >/dev/null; then
    info "删除 Let's Encrypt 证书 ($DOMAIN) ..."
    certbot delete --cert-name "$DOMAIN" --non-interactive >/dev/null 2>&1 || warn "证书删除失败 (可手动 certbot delete)"
  fi
else
  warn "按 ZP_KEEP_CERT=1 保留证书"
fi

if [ "${ZP_KEEP_DATA:-0}" = "1" ]; then
  warn "按 ZP_KEEP_DATA=1 保留数据目录: $ZP_HOME/data"
  find "$ZP_HOME" -mindepth 1 -maxdepth 1 ! -name data -exec rm -rf {} + 2>/dev/null || true
else
  info "删除 $ZP_HOME ..."
  rm -rf "$ZP_HOME"
fi

if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  info "回收 ufw 放行规则 ..."
  ufw delete allow "$PANEL_PORT/tcp" >/dev/null 2>&1 || true
  ufw delete allow 8443/tcp >/dev/null 2>&1 || true
  ufw delete allow 8444/tcp >/dev/null 2>&1 || true
  ufw delete allow 8445/tcp >/dev/null 2>&1 || true
  ufw delete allow 30001:32001/udp >/dev/null 2>&1 || true
fi

echo
ok "ZeroProxy 已卸载。"
echo "  未触碰: nginx / certbot / BBR 内核参数 (如需还原: 删除 /etc/sysctl.d/99-zeroproxy.conf 后 sysctl --system)"
if [ "${ZP_KEEP_DATA:-0}" = "1" ]; then
  echo "  数据保留在: $ZP_HOME/data"
fi
