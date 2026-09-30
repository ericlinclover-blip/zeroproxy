#!/usr/bin/env bash
# ============================================================
#  ZeroProxy 一键升级  —  Ubuntu / Debian
#
#  用法 (服务器上, root):
#    curl -fsSL https://raw.githubusercontent.com/ericlinclover-blip/zeroproxy/main/upgrade.sh | bash
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
VENV="$ZP_HOME/venv"
STATE_FILE="$ZP_HOME/data/state.json"
STATUS_FILE="$ZP_HOME/data/update.json"
LOG_FILE="$ZP_HOME/data/update.log"
BACKUP_DIR="$ZP_HOME/data/backups"
ZP_TRIGGER="${ZP_TRIGGER:-cli}"
ZP_UPDATE_CORE="${ZP_UPDATE_CORE:-0}"
ZP_CHECK_ONLY="${ZP_CHECK_ONLY:-0}"
ZP_NO_RESTART="${ZP_NO_RESTART:-0}"
# 带 PID: 同一秒内跑两次也不会撞名 (撞名会让 cp -r 把新代码套进旧备份, 回滚就退错版本)
STAMP="$(date +%Y%m%d-%H%M%S)-$$"

info() { printf '\033[1;34m[ZeroProxy]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ZeroProxy]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[ZeroProxy]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[ZeroProxy]\033[0m %s\n' "$*"; exit 1; }

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
  PLAN=("备份代码与 state.json" "下载新版本代码" "安装新代码" "同步 Python 依赖" "重载 systemd 单元")
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

rollback() {
  if [ -z "$CODE_BACKUP" ] || [ ! -d "$CODE_BACKUP" ]; then
    return 0
  fi
  warn "回滚到升级前的代码与状态 ..."
  rm -rf "$ZP_HOME/zeroproxy" "$ZP_HOME/static"
  cp -r "$CODE_BACKUP/zeroproxy" "$ZP_HOME/zeroproxy"
  cp -r "$CODE_BACKUP/static" "$ZP_HOME/static"
  if [ -f "$CODE_BACKUP/state.json" ]; then
    cp -f "$CODE_BACKUP/state.json" "$STATE_FILE"
  fi
  systemctl restart xray hysteria2 nginx zeroproxy >/dev/null 2>&1 || true
  ok "已回滚 (备份保留在 $BACKUP_DIR)"
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
# 只保留最近 5 次备份, 避免长期占盘
if ls -1dt "$BACKUP_DIR"/code-* >/dev/null 2>&1; then
  ls -1dt "$BACKUP_DIR"/code-* 2>/dev/null | tail -n +6 | while read -r old; do rm -rf "$old"; done
fi
ok "已备份当前代码与 state.json → $CODE_BACKUP"
add_step true "备份代码与 state.json" "$(basename "$CODE_BACKUP") (最近 5 份自动保留)"

trap on_exit EXIT

# ---------- 2. 下载新代码 ----------
step_log "从 GitHub 下载面板代码 ($ZP_REPO @ $ZP_REF) ..."
begin_step "下载新版本代码"
fetch_tarball() { # fetch_tarball <输出文件>
  local out="$1" url err
  err="$(mktemp)"
  for url in \
    "$GH/$ZP_REPO/archive/refs/heads/$ZP_REF.tar.gz" \
    "$GH/$ZP_REPO/archive/refs/tags/$ZP_REF.tar.gz" \
    "$GH_API/repos/$ZP_REPO/tarball/$ZP_REF"
  do
    curl -fsSL --connect-timeout 10 --max-time 180 -o "$out" "$url" 2>"$err" || { rm -f "$out"; continue; }
    if tar -tzf "$out" >/dev/null 2>&1; then rm -f "$err"; return 0; fi
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
# systemd 单元目录可被 ZP_SYSTEMD_DIR 覆盖 (容器 / 演练环境用; 默认就是系统目录)
SYSTEMD_DIR="${ZP_SYSTEMD_DIR:-/etc/systemd/system}"
if [ -d "$SYSTEMD_DIR" ]; then
  cp "$SRC_DIR"/systemd/*.service "$SYSTEMD_DIR/"
else
  warn "未发现 $SYSTEMD_DIR, 跳过 systemd 单元安装 (非 systemd 环境)"
fi
cp "$SRC_DIR/upgrade.sh" "$ZP_HOME/upgrade.sh"
if [ -f "$SRC_DIR/uninstall.sh" ]; then
  cp "$SRC_DIR/uninstall.sh" "$ZP_HOME/uninstall.sh"
fi
chmod +x "$ZP_HOME/upgrade.sh" "$ZP_HOME/uninstall.sh" 2>/dev/null || true
rm -rf /tmp/zp-upgrade.tar.gz /tmp/zp-upgrade-src
add_step true "安装新代码" "v$FROM_VERSION → v$TO_VERSION ($ZP_HOME)"

# ---------- 4. 依赖 ----------
run_step "同步 Python 依赖" "$VENV/bin/pip" install -q -r "$ZP_HOME/requirements.txt"
run_step "重载 systemd 单元" systemctl daemon-reload
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
  step_log "升级 Xray / Hysteria 2 二进制 (ZP_UPDATE_CORE=1) ..."
  begin_step "升级 Xray Core"
  if curl -fsSL --max-time 120 -o /tmp/xray.zip \
      "$GH/XTLS/Xray-core/releases/latest/download/Xray-linux-$( [ "$ARCH" = "arm64" ] && echo arm64-v8a || echo 64 ).zip"; then
    unzip -oq /tmp/xray.zip -d /usr/local/bin && chmod +x /usr/local/bin/xray
    add_step true "升级 Xray Core" "$(/usr/local/bin/xray version 2>/dev/null | head -1)"
  else
    warn "Xray 下载失败, 保留现有版本"
    add_step false "升级 Xray Core" "下载失败, 已保留现有版本"
  fi
  rm -f /tmp/xray.zip
  begin_step "升级 Hysteria 2"
  if curl -fsSL --max-time 120 -o /tmp/hysteria.tar.gz \
      "$GH/apernet/hysteria/releases/latest/download/hysteria-linux-$ARCH.tar.gz"; then
    tar -xzf /tmp/hysteria.tar.gz -C /tmp hysteria && install -m 755 /tmp/hysteria /usr/local/bin/hysteria
    add_step true "升级 Hysteria 2" "$(/usr/local/bin/hysteria version 2>/dev/null | head -1)"
  else
    warn "Hysteria 2 下载失败, 保留现有版本"
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
