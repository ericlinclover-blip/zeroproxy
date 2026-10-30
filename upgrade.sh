#!/usr/bin/env bash
# ============================================================
#  ZeroProxy 一键升级  —  Ubuntu / Debian
#
#  用法 (服务器上, root):
#    curl -fsSL https://raw.githubusercontent.com/ericlinclover-blip/zeroproxy/main/upgrade.sh | bash
#  受限网络上换成自建反代 (把原始地址整个拼在后面):
#    curl -fsSL https://github.i3.pub/https://raw.githubusercontent.com/ericlinclover-blip/zeroproxy/main/upgrade.sh | bash
#
#  面板里「程序更新 → 一键更新」调用的就是这个脚本, 两者行为完全一致。
#
#  特性:
#    - 只替换程序代码, state.json (密钥 / 口令哈希 / 订阅令牌 / 节点配置) 原样保留
#    - 升级前自动备份 state.json 与旧代码, 任何一步失败都自动回滚
#    - 升级后按 state.json 重新生成 xray / nginx / hysteria 配置并热重载
#      (不会像重跑 install.sh 那样把配置打回占位状态)
#    - 结束时用真实端口监听 + 面板接口做验证, 结果写进 data/update.json
#
#  可覆盖变量:
#    ZP_REF=main|v2.3        指定分支或 tag (默认 main)
#    ZP_REPO=owner/repo      改用 fork / 镜像仓库
#    ZP_UPDATE_CORE=1        同时把 Xray / Hysteria 2 二进制升到最新版
#    ZP_CHECK_ONLY=1         只检查版本, 不做任何改动
#    ZP_NO_RESTART=1         不重启面板进程 (仅命令行调试用)
#    ZP_ALLOW_UNVERIFIED=1   跳过代码包 SHA256SUMS 校验 (默认严格)
#
#  供应链校验: 下载代码包后用**同一 ref 的原始 raw 地址**另取一份仓库根 SHA256SUMS,
#  逐文件比对后才会替换代码 (镜像只承担传输); 不一致立即中止并回滚。
#  回滚是完整的运行版本回滚: 代码 + requirements.txt + systemd 单元 + 脚本自身 + state.json,
#  回滚后 daemon-reload、重新落地配置并复验 /api/info; pip 已装依赖只前进不后退。
# ============================================================
set -Eeuo pipefail

# ---------- 先把自己整份读进内存, 再开始干活 ----------
# bash 是**按文件偏移增量读取**脚本的, 而这个脚本在「安装新代码」那步会把自己覆盖成新版本:
# 覆盖之后 bash 继续从"新文件"的同一偏移往下读, 读到的就是另一段代码 → 解析错乱。
# 真机上的样子 (v2.3.10 升 v2.3.11): 打完「安装新代码」就
#   upgrade.sh: line 233: syntax error near unexpected token `then'
# 然后整次升级白跑 (好在有自动回滚)。这里先用内存里的那份继续执行, 从根上免疫覆盖自己。
# 只有"以文件方式执行"时才重入; `curl | bash` (脚本走 stdin) 和 `source` 都不受影响。
if [ "${ZP_SELF_IN_MEMORY:-0}" != "1" ] && [ -f "$0" ] && [ "${BASH_SOURCE[0]:-}" = "$0" ]; then
  ZP_SELF_IN_MEMORY=1 exec bash -c "$(<"$0")" "$0" "$@"
fi

ZP_HOME="${ZP_HOME:-/opt/zeroproxy}"
ZP_REPO="${ZP_REPO:-ericlinclover-blip/zeroproxy}"
ZP_REF="${ZP_REF:-main}"
GH="https://github.com"
GH_API="https://api.github.com"
#: 代码下载的反代前缀 (按顺序回退)。内核二进制、分流数据库、版本号检查都有镜像, 只有
#: **升级脚本自己**以前只认 GitHub 直连 —— 受限网络上面板会卡在"下载新版本代码", 而
#: 更新通道恰恰是用户唯一的自救手段 (真机上就是这样: 面板停在旧版本, 点更新没反应)。
#: gh-proxy 这类反代对 /archive/<sha>.tar.gz 与分支 tarball 都直接透传。
#: **自建的反代排第一**, 与面板那边内核 / 分流数据两张表的策略一致 (运营方自己的反代
#: 比任何公共前缀都稳; README 8.52 那条)。受限线路上直连 GitHub 是"卡满超时再失败",
#: 排前面只是白吃预算 —— 而且升级是用户唯一的自救通道, 更不能卡在这一步。
GH_MIRRORS=("https://github.i3.pub/$GH" "$GH" "https://gh-proxy.com/$GH" "https://hk.gh-proxy.com/$GH")
VENV="$ZP_HOME/venv"
STATE_FILE="$ZP_HOME/data/state.json"
STATUS_FILE="$ZP_HOME/data/update.json"
LOG_FILE="$ZP_HOME/data/update.log"
BACKUP_DIR="$ZP_HOME/data/backups"
# 演练 / 容器环境可覆盖; 默认就是系统目录
SYSTEMD_DIR="${ZP_SYSTEMD_DIR:-/etc/systemd/system}"
LETSENCRYPT_DIR="${ZP_LETSENCRYPT_DIR:-/etc/letsencrypt}"
ZP_TRIGGER="${ZP_TRIGGER:-cli}"
ZP_UPDATE_CORE="${ZP_UPDATE_CORE:-0}"
ZP_CHECK_ONLY="${ZP_CHECK_ONLY:-0}"
ZP_NO_RESTART="${ZP_NO_RESTART:-0}"
#: 代码包校验总开关: 默认严格 (取不到/对不上 SHA256SUMS 就回滚); 只有明确知情才跳过。
ZP_ALLOW_UNVERIFIED="${ZP_ALLOW_UNVERIFIED:-0}"
# 日志与状态文件不含机密, 但统一收紧权限 (升级由 root 跑; 面板也是 root 读)
umask 022
# 带 PID: 同一秒内跑两次也不会撞名 (撞名会让 cp -r 把新代码套进旧备份, 回滚就退错版本)
STAMP="$(date +%Y%m%d-%H%M%S)-$$"

info() { printf '\033[1;34m[ZeroProxy]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ZeroProxy]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[ZeroProxy]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[ZeroProxy]\033[0m %s\n' "$*"; exit 1; }

# ---------- 供应链完整性 (P1-2) ----------
# 期望摘要来自同一 ref 的**原始 raw 地址** (独立于 tarball; 镜像只承担传输), 逐文件比对。
# 清单没有签名, 残余风险是"镜像同时伪造清单"; 但单个镜像投毒/坏缓存会被这里挡下。
sha256_file() { # sha256_file <文件> → 打印小写 hex; 没有可用工具时返回 1
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$1" | sed 's/^.*= *//'
  else
    return 1
  fi
}

# verify_sums_file <清单> <根目录> [只校验的相对路径]
#   0 = 全部一致   2 = 有不一致/缺失   3 = 清单无效或没有可用条目
verify_sums_file() {
  local sums="$1" root="$2" only="${3:-}" line hash path actual n=0 bad=0 ok_n=0
  [ -s "$sums" ] || return 3
  while IFS= read -r line; do
    case "$line" in ""|"#"*) continue ;; esac
    hash="${line%% *}"
    path="${line#"$hash"}"
    path="${path# }"
    path="${path# }"
    path="${path#\*}"
    case "$hash" in *[!0-9a-fA-F]*) continue ;; esac
    [ "${#hash}" -eq 64 ] || continue
    [ -n "$only" ] && [ "$path" != "$only" ] && continue
    n=$((n + 1))
    if [ ! -f "$root/$path" ]; then
      printf '  缺少文件: %s\n' "$path" >&2
      bad=$((bad + 1))
      continue
    fi
    actual="$(sha256_file "$root/$path" 2>/dev/null || true)"
    [ -n "$actual" ] || continue
    ok_n=$((ok_n + 1))
    if [ "$actual" != "$hash" ]; then
      printf '  摘要不一致: %s\n' "$path" >&2
      bad=$((bad + 1))
    fi
  done < "$sums"
  [ "$n" -gt 0 ] || return 3
  [ "$bad" -eq 0 ] || return 2
  [ "$ok_n" -eq "$n" ] || return 3
  return 0
}

# fetch_zp_sums <输出文件> <ref>: 同一 ref 的原始 raw 地址取 SHA256SUMS (镜像只作传输)
fetch_zp_sums() {
  local out="$1" ref="$2" url p
  url="https://raw.githubusercontent.com/$ZP_REPO/$ref/SHA256SUMS"
  for p in "https://github.i3.pub/" "" "https://gh-proxy.com/" "https://hk.gh-proxy.com/"; do
    rm -f "$out"
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL --connect-timeout 10 --max-time 120 -o "$out" "$p$url" 2>/dev/null \
        && [ -s "$out" ] && return 0
    else
      wget -q --timeout=60 --tries=1 -O "$out" "$p$url" 2>/dev/null \
        && [ -s "$out" ] && return 0
    fi
  done
  rm -f "$out"
  return 1
}

# fetch_gh_asset <github.com 之后的路径> <输出>: 内核 / 复核产物走 GH_MIRRORS (自建反代优先)
fetch_gh_asset() {
  local path="$1" out="$2" prefix
  for prefix in "${GH_MIRRORS[@]}"; do
    rm -f "$out"
    if curl -fsSL --connect-timeout 10 --max-time 180 -o "$out" "$prefix/$path" 2>/dev/null \
       && [ -s "$out" ]; then
      return 0
    fi
  done
  rm -f "$out"
  return 1
}

# install_units <源码目录>: 落 systemd 单元; ZP_HOME 非默认值时同步替换单元里的路径
install_units() {
  local src="$1" f base repl
  repl="$(printf '%s' "$ZP_HOME" | sed -e 's/[\\&|]/\\&/g')"
  for f in "$src"/systemd/*.service; do
    [ -f "$f" ] || continue
    base="$(basename "$f")"
    if [ "$ZP_HOME" = "/opt/zeroproxy" ]; then
      cp -f "$f" "$SYSTEMD_DIR/$base"
    else
      sed "s|/opt/zeroproxy|$repl|g" "$f" > "$SYSTEMD_DIR/$base"
    fi
    chmod 644 "$SYSTEMD_DIR/$base" 2>/dev/null || true
  done
}

# 证书续期钩子 (P2-1): 与 install.sh / 面板 services.install_cert 落的是同一个文件, 内容一致
install_le_hook() {
  local dir="$LETSENCRYPT_DIR/renewal-hooks/deploy"
  local f="$LETSENCRYPT_DIR/renewal-hooks/deploy/zeroproxy-reload.sh"
  mkdir -p "$dir" || return 1
  cat > "$f" <<'HOOK'
#!/bin/sh
# ZeroProxy: Let's Encrypt 续期成功后让 nginx / Xray 用上新证书。
# 由 install.sh / upgrade.sh / 面板 services.install_cert 落盘, 内容保持一致。
# (--webroot 签发不会自动 reload, 没有这个钩子就要等到下一次手动续期/apply)
set -u
systemctl reload nginx 2>/dev/null || systemctl restart nginx 2>/dev/null || true
systemctl restart xray 2>/dev/null || true
HOOK
  chmod 755 "$f" || return 1
  [ -x "$f" ]
}

# 升级失败不留半成品: /tmp 里的下载物与解压目录统一清掉
cleanup_tmp() {
  rm -f /tmp/zp-upgrade.tar.gz /tmp/zp.SHA256SUMS /tmp/xray.zip /tmp/hysteria.tar.gz /tmp/hysteria /tmp/zp-shortcut.log 2>/dev/null || true
  rm -rf /tmp/zp-upgrade-src 2>/dev/null || true
  return 0
}

# ---------- 进度文件 (面板「程序更新」卡片读它) ----------
STEPS=()
PLAN=()
CURRENT=""
STATUS_STATE="running"
STATUS_MSG="升级进行中"
FROM_VERSION="unknown"
TO_VERSION="unknown"
STARTED_AT="$(date +%s)"
FINISHED_AT=0
CODE_BACKUP=""

json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\000'; }

steps_json() {
  local IFS=,
  printf '[%s]' "${STEPS[*]-}"
}

json_array() { # json_array <字符串...> → ["a","b"]
  local out="" it
  for it in "$@"; do
    [ -n "$it" ] || continue          # bash 3.2 下空数组会展开成一个空串, 这里挡掉
    out="${out:+$out,}\"$(json_escape "$it")\""
  done
  printf '[%s]' "$out"
}

#: 这次升级会依次做哪些事 —— 面板拿它渲染"待执行 / 进行中 / 已完成"的步骤清单。
#: 名字必须和下面 add_step 用的一字不差, 否则面板对不上号。
build_plan() {
  PLAN=("备份代码与 state.json" "下载新版本代码" "安装新代码" "同步 Python 依赖" "重载 systemd 单元" "安装证书续期钩子")
  # 终端快捷命令: 只有 root 装得了 (/usr/local/bin) —— 条件必须与下面执行处**完全一致**,
  # 否则计划清单与实际步骤对不上 (面板的"待执行/已完成"清单就会错位)
  if [ "$(id -u)" -eq 0 ] && [ -x "$VENV/bin/python" ]; then
    PLAN+=("安装终端快捷命令 (z)")
  fi
  [ "$ZP_UPDATE_CORE" = "1" ] && PLAN+=("升级 Xray Core" "升级 Hysteria 2")
  if [ -f "$STATE_FILE" ]; then
    PLAN+=("按 state.json 重新生成配置并热重载")
  else
    PLAN+=("跳过配置落地")
  fi
  if [ "$ZP_NO_RESTART" = "1" ]; then
    PLAN+=("重启面板")
  else
    PLAN+=("重启面板进程" "面板已就绪")
  fi
  return 0
}

write_status() {
  [ -d "$ZP_HOME/data" ] || return 0
  {
    printf '{\n'
    printf '  "state": "%s",\n' "$STATUS_STATE"
    printf '  "from": "%s",\n' "$(json_escape "$FROM_VERSION")"
    printf '  "to": "%s",\n' "$(json_escape "$TO_VERSION")"
    printf '  "trigger": "%s",\n' "$(json_escape "$ZP_TRIGGER")"
    printf '  "started_at": %s,\n' "$STARTED_AT"
    printf '  "finished_at": %s,\n' "$FINISHED_AT"
    printf '  "current": "%s",\n' "$(json_escape "$CURRENT")"
    printf '  "message": "%s",\n' "$(json_escape "$STATUS_MSG")"
    printf '  "plan": %s,\n' "$(json_array "${PLAN[@]-}")"
    printf '  "steps": %s\n' "$(steps_json)"
    printf '}\n'
  } > "$STATUS_FILE.tmp" 2>/dev/null && mv -f "$STATUS_FILE.tmp" "$STATUS_FILE" 2>/dev/null || true
}

add_step() { # add_step <true|false> <名称> <说明>
  STEPS+=("{\"name\":\"$(json_escape "$2")\",\"ok\":$1,\"detail\":\"$(json_escape "$3")\"}")
  printf '%s %s | %s\n' "$([ "$1" = "true" ] && echo '  OK  ' || echo ' FAIL ')" "$2" "$3" >> "$LOG_FILE"
  write_status          # 面板每 2.5s 轮询一次, 每完成一步就落盘, 进度才是真的在动
}

begin_step() { # begin_step <名称>: 标记"正在做这一步"
  STATUS_MSG="$1"
  CURRENT="$1"
  write_status
}

step() { info "$1"; }
step_log() { info "$1"; printf '== %s\n' "$1" >> "$LOG_FILE"; }

read_version() { # read_version <文件>
  sed -n 's/^__version__ *= *"\([^"]*\)".*/\1/p' "$1" 2>/dev/null | head -1
}

parse_version() { # 输出 "002 003 000" 便于字符串比较
  printf '%s' "$1" | awk -F. '{printf "%03d %03d %03d", $1+0, $2+0, $3+0}'
}

#: 只在「意外退出」时兜底 (正常路径会自己把状态写成 success / failed)
#: 面板升级时脚本是从私有临时副本起的 (update.py 的 stage_script), 收尾要把那份副本删掉。
#: 只认自己的目录名样式, 免得环境变量被写坏时误删别的东西。
cleanup_self_dir() {
  [ -n "${ZP_SELF_DIR:-}" ] || return 0
  case "$ZP_SELF_DIR" in
    /tmp/zeroproxy-update-*|"${TMPDIR:-/tmp}"/zeroproxy-update-*) rm -rf "$ZP_SELF_DIR" 2>/dev/null || true ;;
  esac
  return 0
}

SKIP_STATUS="${SKIP_STATUS:-0}"
on_exit() {
  local code=$?
  cleanup_self_dir
  cleanup_tmp
  if [ "$SKIP_STATUS" = "1" ] || [ "$STATUS_STATE" != "running" ]; then
    return 0
  fi
  FINISHED_AT="$(date +%s)"
  STATUS_STATE="failed"
  STATUS_MSG="升级中断 (退出码 $code), 已尝试回滚到升级前版本"
  add_step false "升级中断" "退出码 $code; 详见 $LOG_FILE"
  rollback
  write_status
  warn "升级失败, 详见 $LOG_FILE"
}

#: 回滚必须是**完整的运行版本回滚** (P2-10): 代码 + 依赖清单 + systemd 单元 + 脚本自身
#: + state.json 一起退回去, 然后 daemon-reload、重新落地配置、再验一次面板 readiness。
#: 之前只回滚代码与 state, 于是"旧代码 + 新依赖 + 新单元"照样起不来, 而且失败得静悄悄。
#: pip 已装依赖只前进不后退 (没有可靠的通用回退办法), 会在报告里明确写出来。
rollback() {
  if [ -z "$CODE_BACKUP" ] || [ ! -d "$CODE_BACKUP" ]; then
    return 0
  fi
  warn "回滚到升级前的代码与运行版本 ..."
  rm -rf "$ZP_HOME/zeroproxy" "$ZP_HOME/static"
  if [ -d "$CODE_BACKUP/zeroproxy" ]; then cp -r "$CODE_BACKUP/zeroproxy" "$ZP_HOME/zeroproxy"; fi
  if [ -d "$CODE_BACKUP/static" ]; then cp -r "$CODE_BACKUP/static" "$ZP_HOME/static"; fi
  if [ -f "$CODE_BACKUP/state.json" ]; then
    cp -f "$CODE_BACKUP/state.json" "$STATE_FILE"
  fi
  # 依赖清单与脚本自身
  if [ -f "$CODE_BACKUP/requirements.txt" ]; then
    cp -f "$CODE_BACKUP/requirements.txt" "$ZP_HOME/requirements.txt"
  fi
  if [ -f "$CODE_BACKUP/upgrade.sh" ]; then
    cp -f "$CODE_BACKUP/upgrade.sh" "$ZP_HOME/upgrade.sh"
    chmod +x "$ZP_HOME/upgrade.sh" 2>/dev/null || true
  fi
  if [ -f "$CODE_BACKUP/uninstall.sh" ]; then
    cp -f "$CODE_BACKUP/uninstall.sh" "$ZP_HOME/uninstall.sh" 2>/dev/null || true
  fi
  # systemd 单元 (升级覆盖过 /etc/systemd/system, 这里按备份逐份换回)
  if [ -d "$CODE_BACKUP/systemd" ] && [ -d "$SYSTEMD_DIR" ]; then
    for _u in "$CODE_BACKUP"/systemd/*.service; do
      [ -f "$_u" ] || continue
      cp -f "$_u" "$SYSTEMD_DIR/$(basename "$_u")" 2>/dev/null || true
    done
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  systemctl restart xray hysteria2 nginx zeroproxy >/dev/null 2>&1 || true
  # 回滚后复验: 先按 state.json 重新落地 (旧代码 + 旧配置), 再等面板接口就绪
  ROLLBACK_APPLY="ok"
  if [ -f "$STATE_FILE" ] && [ -x "$VENV/bin/python" ]; then
    if ! env ZP_HOME="$ZP_HOME" PYTHONPATH="$ZP_HOME" "$VENV/bin/python" -m zeroproxy.apply --quiet \
         >>"$LOG_FILE" 2>&1; then
      ROLLBACK_APPLY="apply 失败 (详见 $LOG_FILE)"
    fi
  fi
  ROLLBACK_READY=0
  for _ in $(seq 1 20); do
    if curl -fsS --max-time 3 "http://127.0.0.1:${ZP_BIND_PORT:-9900}/api/info" >/dev/null 2>&1; then
      ROLLBACK_READY=1
      break
    fi
    sleep 1
  done
  if [ "$ROLLBACK_READY" = "1" ]; then
    ok "已回滚 (备份保留在 $BACKUP_DIR); 面板接口已恢复"
  else
    warn "已回滚代码 / 单元 / 依赖清单, 但面板 20 秒内仍未就绪。可操作提示:"
    warn "  1) journalctl -u zeroproxy -n 50   看进程为什么起不来"
    warn "  2) $VENV/bin/pip install -r $ZP_HOME/requirements.txt   重装依赖 (pip 只前进不后退)"
    warn "  3) 备份在 $BACKUP_DIR; state.json 未被升级覆盖 (密钥/令牌原样保留)"
    warn "回滚后 apply: $ROLLBACK_APPLY"
  fi
}

run_step() { # run_step <名称> <命令...>
  local name="$1"; shift
  begin_step "$name"
  printf '== %s\n' "$name" >> "$LOG_FILE"
  local out rc
  if out="$("$@" 2>&1)"; then
    rc=0
  else
    rc=$?
  fi
  printf '%s\n' "$out" >> "$LOG_FILE"
  if [ "$rc" -eq 0 ]; then
    add_step true "$name" "完成"
    return 0
  fi
  # 命令内部往往还会再分几步 (apply 的 生成 → 校验 → 重载 → 端口复查)。失败时把
  # 第一条 `FAIL ...` 行挑出来写进 update.json —— 面板的失败横幅就能直接说清卡在
  # 哪一步、为什么, 不用让人去日志里翻那行 JSON。
  local reason
  reason="$(printf '%s\n' "$out" | sed -n 's/^ *FAIL *\(.*\)$/\1/p' | head -1 | cut -c1-200)"
  [ -n "$reason" ] || reason="命令执行失败 (退出码 $rc), 详见日志"
  add_step false "$name" "$reason"
  tail -n 5 "$LOG_FILE" | sed 's/^/    /' >&2
  return 1
}

# ============================================================
step_log "ZeroProxy 一键升级 (触发方式: $ZP_TRIGGER)"
[ "$(id -u)" -eq 0 ] || fail "请以 root 运行 (sudo bash upgrade.sh)"
[ -d "$ZP_HOME" ] || fail "未发现 $ZP_HOME — 这台机器还没有部署 ZeroProxy, 请先跑 install.sh"

FROM_VERSION="$(read_version "$ZP_HOME/zeroproxy/__init__.py")"
FROM_VERSION="${FROM_VERSION:-unknown}"
TO_VERSION="$FROM_VERSION"
mkdir -p "$ZP_HOME/data" "$BACKUP_DIR"
: > "$LOG_FILE"

if [ -n "${ZP_REF_OVERRIDE:-}" ]; then ZP_REF="$ZP_REF_OVERRIDE"; fi

if [ ! -f "$STATE_FILE" ]; then
  warn "未发现 $STATE_FILE (面板尚未初始化)。升级会保留占位配置, 初始化请走面板页面。"
fi

# ---------- 0. 只检查版本 ----------
if [ "$ZP_CHECK_ONLY" = "1" ]; then
  SKIP_STATUS=1
  REMOTE_JSON="$(curl -fsSL --max-time 20 "$GH_API/repos/$ZP_REPO/commits/$ZP_REF" 2>/dev/null || true)"
  REMOTE_SHA="$(printf '%s' "$REMOTE_JSON" | sed -n 's/.*"sha": *"\([0-9a-f]\{7,\}\)".*/\1/p' | head -1)"
  info "当前版本: v$FROM_VERSION"
  info "远端分支: $ZP_REPO@$ZP_REF ${REMOTE_SHA:+(${REMOTE_SHA:0:7})}"
  info "面板内也可直接查看: 仪表盘 → 程序更新"
  cleanup_self_dir
  exit 0
fi

# ---------- 1. 备份 ----------
build_plan
begin_step "备份代码与 state.json"
CODE_BACKUP="$BACKUP_DIR/code-$STAMP"
rm -rf "$CODE_BACKUP"          # 保证目录不存在: 否则 cp -r 会套出 zeroproxy/zeroproxy
mkdir -p "$CODE_BACKUP"
cp -r "$ZP_HOME/zeroproxy" "$CODE_BACKUP/zeroproxy"
cp -r "$ZP_HOME/static" "$CODE_BACKUP/static"
if [ -f "$STATE_FILE" ]; then
  cp -f "$STATE_FILE" "$CODE_BACKUP/state.json"
fi
# P2-10: 升级会改的**运行版本组成**全部一起备份 —— 只备份代码与 state 的话,
# 回滚出来可能变成"旧代码 + 新依赖 + 新 systemd 单元", 面板照样起不来。
[ -f "$ZP_HOME/requirements.txt" ] && cp -f "$ZP_HOME/requirements.txt" "$CODE_BACKUP/requirements.txt"
[ -f "$ZP_HOME/upgrade.sh" ] && cp -f "$ZP_HOME/upgrade.sh" "$CODE_BACKUP/upgrade.sh"
[ -f "$ZP_HOME/uninstall.sh" ] && cp -f "$ZP_HOME/uninstall.sh" "$CODE_BACKUP/uninstall.sh"
if [ -d "$SYSTEMD_DIR" ]; then
  mkdir -p "$CODE_BACKUP/systemd"
  for _u in "$SYSTEMD_DIR"/zeroproxy.service "$SYSTEMD_DIR"/xray.service \
            "$SYSTEMD_DIR"/hysteria2.service "$SYSTEMD_DIR"/zeroproxy-wg.service \
            "$SYSTEMD_DIR"/zeroproxy-wg-userspace.service; do
    [ -f "$_u" ] && cp -f "$_u" "$CODE_BACKUP/systemd/" 2>/dev/null || true
  done
fi
# pip 依赖只前进不后退: 记一份升级前的 freeze, 失败时至少能对照/手工装回
"$VENV/bin/pip" freeze > "$CODE_BACKUP/pip-freeze.txt" 2>/dev/null || true
# 只保留最近 5 次备份, 避免长期占盘
if ls -1dt "$BACKUP_DIR"/code-* >/dev/null 2>&1; then
  ls -1dt "$BACKUP_DIR"/code-* 2>/dev/null | tail -n +6 | while read -r old; do rm -rf "$old"; done
fi
ok "已备份当前代码 / 依赖清单 / systemd 单元 / state.json → $CODE_BACKUP"
add_step true "备份代码与 state.json" "$(basename "$CODE_BACKUP") (最近 5 份自动保留; 含单元与依赖清单)"

trap on_exit EXIT

# ---------- 2. 下载新代码 ----------
step_log "从 GitHub 下载面板代码 ($ZP_REPO @ $ZP_REF) ..."
begin_step "下载新版本代码"
fetch_tarball() { # fetch_tarball <输出文件>
  local out="$1" url err sha prefix
  err="$(mktemp)"
  ZP_TARBALL_SHA=""
  # 先把分支 / tag 解析成提交 SHA, 再按 SHA 下载 —— `archive/refs/heads/<分支>.tar.gz`
  # 在推送后会被 CDN 缓存一小会儿, 刚发完版就升级会**装到上一个版本的代码**
  # (面板上显示成 "v2.6.28 → v2.6.28", 用户以为没升级)。SHA 是不可变快照, 没有这个问题;
  # 拿不到 SHA (API 被挡) 就退回原来的三级兜底, 并给分支/tag 地址带时间戳强制回源。
  sha="$(curl -fsSL --max-time 20 "$GH_API/repos/$ZP_REPO/commits/$ZP_REF" 2>/dev/null \
        | sed -n 's/.*"sha": *"\([0-9a-f]\{40\}\)".*/\1/p' | head -1 || true)"
  # 每个前缀 (直连 / gh-proxy / hk.gh-proxy) 依次试 SHA 快照与带时间戳的分支、tag:
  # 直连不通的机器靠反代照样能升级 —— 这是用户唯一的自救通道。
  local -a urls=() stamp
  stamp="$(date +%s)"
  for prefix in "${GH_MIRRORS[@]}"; do
    [ -n "$sha" ] && urls+=("$prefix/$ZP_REPO/archive/$sha.tar.gz")
    urls+=(
      "$prefix/$ZP_REPO/archive/refs/heads/$ZP_REF.tar.gz?t=$stamp"
      "$prefix/$ZP_REPO/archive/refs/tags/$ZP_REF.tar.gz?t=$stamp"
    )
  done
  urls+=("$GH_API/repos/$ZP_REPO/tarball/$ZP_REF")
  for url in "${urls[@]}"; do
    curl -fsSL --connect-timeout 10 --max-time 180 -o "$out" "$url" 2>"$err" || { rm -f "$out"; continue; }
    if tar -tzf "$out" >/dev/null 2>&1; then ZP_TARBALL_SHA="$sha"; rm -f "$err"; return 0; fi
    rm -f "$out"
  done
  DL_ERR="$(tail -1 "$err" 2>/dev/null || true)"
  rm -f "$err"
  return 1
}

rm -f /tmp/zp-upgrade.tar.gz
rm -rf /tmp/zp-upgrade-src
if ! fetch_tarball /tmp/zp-upgrade.tar.gz; then
  fail "代码下载失败: ${DL_ERR:-无法访问 GitHub} (可用 ZP_REPO / ZP_REF 指定镜像仓库)"
fi
mkdir -p /tmp/zp-upgrade-src
tar -xzf /tmp/zp-upgrade.tar.gz -C /tmp/zp-upgrade-src
SRC_DIR="$(find /tmp/zp-upgrade-src -mindepth 1 -maxdepth 1 -type d | head -1)"
[ -f "$SRC_DIR/backend/zeroproxy/main.py" ] || fail "下载的代码不完整: $SRC_DIR"

# ---- 供应链校验 (P1-2): 逐文件比对同一 ref 的 SHA256SUMS ----
# 清单从原始 raw 地址独立取 (镜像只作传输); 任一条不一致就中止 → trap 回滚。
if [ "${ZP_ALLOW_UNVERIFIED:-0}" = "1" ]; then
  warn "ZP_ALLOW_UNVERIFIED=1: 跳过代码包 SHA256SUMS 校验 (不推荐)"
else
  _sums_ref="${ZP_TARBALL_SHA:-$ZP_REF}"
  rm -f /tmp/zp.SHA256SUMS
  if ! fetch_zp_sums /tmp/zp.SHA256SUMS "$_sums_ref"; then
    fail "取不到代码包校验清单 (SHA256SUMS): $ZP_REPO@$_sums_ref
       升级通道必须能独立取到清单; 应急可显式跳过 (不推荐): ZP_ALLOW_UNVERIFIED=1 bash upgrade.sh"
  fi
  if [ -f "$SRC_DIR/SHA256SUMS" ]; then
    _in_pkg="$(sha256_file "$SRC_DIR/SHA256SUMS" 2>/dev/null || true)"
    _raw="$(sha256_file /tmp/zp.SHA256SUMS 2>/dev/null || true)"
    if [ -n "$_in_pkg" ] && [ -n "$_raw" ] && [ "$_in_pkg" != "$_raw" ]; then
      fail "代码包内的 SHA256SUMS 与同 ref 的原始清单不一致 —— 镜像可能被篡改, 已中止升级"
    fi
  fi
  if ! verify_sums_file /tmp/zp.SHA256SUMS "$SRC_DIR"; then
    fail "代码包 SHA256SUMS 校验失败 (文件被改动 / 不完整) —— 已中止升级并回滚
       镜像可能被投毒; 换一个 ref 或镜像重试, 确认无风险时才用 ZP_ALLOW_UNVERIFIED=1。"
  fi
  ok "代码包已按 SHA256SUMS 逐文件校验通过 ($ZP_REPO@$_sums_ref)"
fi

TO_VERSION="$(read_version "$SRC_DIR/backend/zeroproxy/__init__.py")"
TO_VERSION="${TO_VERSION:-unknown}"
ok "代码已就绪 (v$FROM_VERSION → v$TO_VERSION)"
add_step true "下载新版本代码" "v$FROM_VERSION → v$TO_VERSION ($ZP_REPO @ $ZP_REF)"

# ---------- 3. 替换代码 ----------
step_log "安装新代码 → $ZP_HOME ..."
begin_step "安装新代码"
rm -rf "$ZP_HOME/zeroproxy" "$ZP_HOME/static"
cp -r "$SRC_DIR/backend/zeroproxy" "$ZP_HOME/zeroproxy"
cp -r "$SRC_DIR/backend/static" "$ZP_HOME/static"
cp "$SRC_DIR/backend/requirements.txt" "$ZP_HOME/requirements.txt"
rm -rf "$ZP_HOME/zeroproxy/__pycache__" "$ZP_HOME/zeroproxy"/*/__pycache__
# systemd 单元目录可被 ZP_SYSTEMD_DIR 覆盖 (容器 / 演练环境用; 默认就是系统目录)。
# ZP_HOME 不是 /opt/zeroproxy 时, install_units 会同步替换单元里的路径。
if [ -d "$SYSTEMD_DIR" ]; then
  install_units "$SRC_DIR"
else
  warn "未发现 $SYSTEMD_DIR, 跳过 systemd 单元安装 (非 systemd 环境)"
fi
cp "$SRC_DIR/upgrade.sh" "$ZP_HOME/upgrade.sh"
if [ -f "$SRC_DIR/uninstall.sh" ]; then
  cp "$SRC_DIR/uninstall.sh" "$ZP_HOME/uninstall.sh"
fi
chmod +x "$ZP_HOME/upgrade.sh" "$ZP_HOME/uninstall.sh" 2>/dev/null || true
rm -rf /tmp/zp-upgrade.tar.gz /tmp/zp-upgrade-src /tmp/zp.SHA256SUMS
add_step true "安装新代码" "v$FROM_VERSION → v$TO_VERSION ($ZP_HOME)"

# ---------- 4. 依赖 ----------
run_step "同步 Python 依赖" "$VENV/bin/pip" install -q -r "$ZP_HOME/requirements.txt"
run_step "重载 systemd 单元" systemctl daemon-reload
# 证书续期钩子 (P2-1): 老部署升级后也要有 —— 自动续期成功但 nginx / Xray 继续用旧证书
# 是"证书突然过期"的根因。内容与 install.sh / services.install_cert 保持一致。
begin_step "安装证书续期钩子"
if install_le_hook; then
  add_step true "安装证书续期钩子" "$LETSENCRYPT_DIR/renewal-hooks/deploy/zeroproxy-reload.sh"
else
  add_step false "安装证书续期钩子" "写入 $LETSENCRYPT_DIR 失败; 续期后需手动 reload nginx / restart xray"
fi
# 终端快捷管理 (z): 老部署升级完也要有 —— 它是"忘记面板密码"时的唯一兜底入口。
# 幂等, 内容随本版本刷新。条件与 build_plan 里那条一模一样 (清单要对得上号)。
if [ "$(id -u)" -eq 0 ] && [ -x "$VENV/bin/python" ]; then
  begin_step "安装终端快捷命令 (z)"
  if ZP_HOME="$ZP_HOME" PYTHONPATH="$ZP_HOME" "$VENV/bin/python" \
      -m zeroproxy.cli install-shortcut >/tmp/zp-shortcut.log 2>&1; then
    add_step true "安装终端快捷命令 (z)" "$(tail -1 /tmp/zp-shortcut.log | cut -c1-120)"
  else
    add_step false "安装终端快捷命令 (z)" "$(tail -1 /tmp/zp-shortcut.log | cut -c1-120)"
  fi
  rm -f /tmp/zp-shortcut.log
fi

# ---------- 5. 可选: 升级内核二进制 ----------
if [ "$ZP_UPDATE_CORE" = "1" ]; then
  ARCH="$(dpkg --print-architecture 2>/dev/null || uname -m)"
  XRAY_ASSET="Xray-linux-$( [ "$ARCH" = "arm64" ] && echo arm64-v8a || echo 64 ).zip"
  HY_ASSET="hysteria-linux-$ARCH.tar.gz"
  step_log "升级 Xray / Hysteria 2 二进制 (ZP_UPDATE_CORE=1) ..."
  # 内核下载复用 GH_MIRRORS (F-08): 受限网络下"升级面板能过、升级内核卡死"就是这里
  # 只走 GitHub 直连造成的。镜像只作传输, 摘要仍用可选的固定常量校验。
  begin_step "升级 Xray Core"
  if fetch_gh_asset "XTLS/Xray-core/releases/latest/download/$XRAY_ASSET" /tmp/xray.zip; then
    case "$ARCH" in
      arm64) _xray_sha_env="ZP_XRAY_SHA256_ARM64" ;;
      *)     _xray_sha_env="ZP_XRAY_SHA256_AMD64" ;;
    esac
    _xray_expect="${!_xray_sha_env:-}"
    _xray_sha="$(sha256_file /tmp/xray.zip 2>/dev/null || true)"
    if [ -n "$_xray_expect" ] && [ "$(printf '%s' "$_xray_expect" | tr 'A-F' 'a-f')" != "$_xray_sha" ]; then
      warn "Xray 压缩包 SHA256 与 $_xray_sha_env 不一致, 保留现有版本"
      add_step false "升级 Xray Core" "SHA256 校验失败, 已保留现有版本"
    elif unzip -t /tmp/xray.zip >/dev/null 2>&1 \
         && unzip -oq /tmp/xray.zip -d /usr/local/bin && chmod +x /usr/local/bin/xray; then
      add_step true "升级 Xray Core" "$(/usr/local/bin/xray version 2>/dev/null | head -1)"
    else
      add_step false "升级 Xray Core" "压缩包解不开, 已保留现有版本"
    fi
    [ -n "$_xray_expect" ] || warn "未固定 Xray SHA256 (设 $_xray_sha_env=<hex> 可钉死; 实际 ${_xray_sha:-未知})"
  else
    warn "Xray 下载失败 (镜像与直连都不通), 保留现有版本"
    add_step false "升级 Xray Core" "下载失败, 已保留现有版本"
  fi
  rm -f /tmp/xray.zip
  begin_step "升级 Hysteria 2"
  if fetch_gh_asset "apernet/hysteria/releases/latest/download/$HY_ASSET" /tmp/hysteria.tar.gz; then
    case "$ARCH" in
      arm64) _hy_sha_env="ZP_HYSTERIA_SHA256_ARM64" ;;
      *)     _hy_sha_env="ZP_HYSTERIA_SHA256_AMD64" ;;
    esac
    _hy_expect="${!_hy_sha_env:-}"
    _hy_sha="$(sha256_file /tmp/hysteria.tar.gz 2>/dev/null || true)"
    if [ -n "$_hy_expect" ] && [ "$(printf '%s' "$_hy_expect" | tr 'A-F' 'a-f')" != "$_hy_sha" ]; then
      warn "Hysteria 压缩包 SHA256 与 $_hy_sha_env 不一致, 保留现有版本"
      add_step false "升级 Hysteria 2" "SHA256 校验失败, 已保留现有版本"
    elif tar -tzf /tmp/hysteria.tar.gz >/dev/null 2>&1 \
         && tar -xzf /tmp/hysteria.tar.gz -C /tmp hysteria \
         && install -m 755 /tmp/hysteria /usr/local/bin/hysteria; then
      add_step true "升级 Hysteria 2" "$(/usr/local/bin/hysteria version 2>/dev/null | head -1)"
    else
      add_step false "升级 Hysteria 2" "压缩包解不开, 已保留现有版本"
    fi
    [ -n "$_hy_expect" ] || warn "未固定 Hysteria SHA256 (设 $_hy_sha_env=<hex> 可钉死; 实际 ${_hy_sha:-未知})"
  else
    warn "Hysteria 2 下载失败 (镜像与直连都不通), 保留现有版本"
    add_step false "升级 Hysteria 2" "下载失败, 已保留现有版本"
  fi
  rm -f /tmp/hysteria.tar.gz /tmp/hysteria
fi

# ---------- 6. 按现有配置重新落地 ----------
if [ -f "$STATE_FILE" ]; then
  # 不加 --quiet: 日志里留下逐步骤的 OK / FAIL 行 (失败时面板横幅直接引用 FAIL 行)
  run_step "按 state.json 重新生成配置并热重载" \
    env ZP_HOME="$ZP_HOME" PYTHONPATH="$ZP_HOME" "$VENV/bin/python" -m zeroproxy.apply
else
  begin_step "跳过配置落地"
  add_step true "跳过配置落地" "面板尚未初始化"
fi

# ---------- 7. 重启面板 ----------
if [ "$ZP_NO_RESTART" = "1" ]; then
  begin_step "重启面板"
  add_step true "重启面板" "已按 ZP_NO_RESTART=1 跳过"
else
  run_step "重启面板进程" systemctl restart zeroproxy
  step_log "等待面板就绪 ..."
  begin_step "面板已就绪"
  PANEL_READY=0
  for _ in $(seq 1 30); do
    if curl -fsS --max-time 3 "http://127.0.0.1:${ZP_BIND_PORT:-9900}/api/info" >/dev/null 2>&1; then PANEL_READY=1; break; fi
    sleep 1
  done
  if [ "$PANEL_READY" = "1" ]; then
    add_step true "面板已就绪" "http://127.0.0.1:${ZP_BIND_PORT:-9900}/api/info 可访问"
  else
    add_step false "面板已就绪" "等待 30s 仍无法访问面板接口"
    # 面板未就绪 → 回滚到升级前版本, 避免面板永久不可用
    STATUS_STATE="failed"
    STATUS_MSG="面板升级后未就绪, 已回滚到 v$FROM_VERSION"
    rollback
  fi
fi

# ---------- 8. 收尾 ----------
FINISHED_AT="$(date +%s)"
CURRENT=""
if printf '%s' "$(steps_json)" | grep -q '"ok":false'; then
  STATUS_STATE="failed"
  STATUS_MSG="升级完成但有步骤失败, 详见面板「程序更新」卡片"
else
  STATUS_STATE="success"
  STATUS_MSG="升级完成: v$FROM_VERSION → v$TO_VERSION"
fi
write_status

echo
if [ "$STATUS_STATE" = "success" ]; then
  ok "=============================================="
  ok "  ZeroProxy 升级完成: v$FROM_VERSION → v$TO_VERSION"
  ok "  日志: $LOG_FILE"
  ok "  备份: $CODE_BACKUP (最近 5 份会自动保留)"
  ok "=============================================="
else
  warn "升级过程中有步骤失败, 请在面板「程序更新 → 一键更新」里查看详情, 或看 $LOG_FILE"
  exit 1
fi
