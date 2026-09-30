#!/usr/bin/env bash
# ============================================================
#  一键升级 (upgrade.sh) 的可回归验证 —— 不需要 Linux / systemd / root。
#
#  做法: 先造一台"已部署的假机器" ($SIM/opt/zeroproxy):
#          * 旧代码 (git HEAD, 即升级前的版本) + 真实的 state.json (跑一次面板 setup 生成);
#          * 配置故意打回 install.sh 的占位状态 —— 复刻"服务全绿但节点全不通"的现场。
#        再用桩二进制顶掉本机没有的东西:
#          id        → 返回 0 (脚本要求 root)
#          systemctl → 直接成功 (本机没有 systemd)
#          curl      → fetch_tarball 时把"新代码 tarball"复制到 -o 指定的文件,
#                      探测 127.0.0.1:9900/api/info 时直接成功
#        然后跑**真实的 upgrade.sh**, 检查两条路径:
#          正常升级: 新代码就位 / state.json 密钥与节点配置原样保留 /
#                    配置按 state.json 重新落地 (占位配置被覆盖) / update.json = success
#          下载失败: 非 0 退出 / 代码回滚到升级前版本 / update.json = failed / 现有部署没被破坏
#
#  用法:
#      bash scripts/upgrade_sim.sh                # 默认用 .venv/bin/python
#      ZP_PYTHON=python3 bash scripts/upgrade_sim.sh
# ============================================================
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${ZP_PYTHON:-$ROOT/.venv/bin/python}"
SIM="$(mktemp -d "${TMPDIR:-/tmp}/zp-upgrade-sim.XXXXXX")"
HOME_DIR="$SIM/opt/zeroproxy"
BIN_DIR="$SIM/bin"
FAILURES=0

ok()      { printf '  \033[1;32m✓\033[0m %s\n' "$1"; }
bad()     { printf '  \033[1;31m✗\033[0m %s\n' "$1"; FAILURES=$((FAILURES + 1)); }
section() { printf '\n\033[1;34m%s\033[0m\n' "$1"; }

trap 'rm -rf "$SIM"' EXIT

[ -x "$PYTHON" ] || PYTHON="$(command -v python3 || true)"
[ -n "$PYTHON" ] || { echo "找不到可用的 python3 (可用 ZP_PYTHON 指定)"; exit 2; }
"$PYTHON" -c 'import fastapi, yaml, cryptography' 2>/dev/null || {
  echo "缺少面板依赖 (fastapi / pyyaml / cryptography), 请用项目 venv: ZP_PYTHON=$ROOT/.venv/bin/python"
  exit 2
}

mkdir -p "$HOME_DIR"/{data,xray,hysteria,nginx,www,certs,geo,panel} "$BIN_DIR" "$SIM/systemd-units"

# ---------- 1. 旧代码 (git HEAD = 升级前的版本) ----------
section "[1] 造机器: 旧代码 + 真实 state.json"
OLD_SRC="$SIM/oldsrc"
mkdir -p "$OLD_SRC"
git -C "$ROOT" archive HEAD backend | tar -x -C "$OLD_SRC"
mkdir -p "$HOME_DIR/zeroproxy" "$HOME_DIR/static"
cp -r "$OLD_SRC/backend/zeroproxy/." "$HOME_DIR/zeroproxy/"
cp -r "$OLD_SRC/backend/static/." "$HOME_DIR/static/"
cp "$OLD_SRC/backend/requirements.txt" "$HOME_DIR/requirements.txt"
# 线上机器上 upgrade.sh 是装在 ZP_HOME 里、就地从那儿被拉起来的 —— 演练必须照做,
# 否则测不出「脚本在运行中把自己覆盖掉」这类只在真机上炸的坑 (v2.3.11 就是这么炸的)
git -C "$ROOT" show HEAD:upgrade.sh > "$HOME_DIR/upgrade.sh"
chmod +x "$HOME_DIR/upgrade.sh"
[ "$(git -C "$ROOT" show HEAD:uninstall.sh 2>/dev/null | head -c 2)" = "#!" ] \
  && git -C "$ROOT" show HEAD:uninstall.sh > "$HOME_DIR/uninstall.sh" || true
# 假机器也要有 venv: 优先直接借用项目 venv (依赖齐全); 否则造一个假的 venv/bin
if [ -d "$ROOT/.venv" ]; then
  ln -s "$ROOT/.venv" "$HOME_DIR/venv"
else
  mkdir -p "$HOME_DIR/venv/bin"
  printf '#!/bin/sh\nexit 0\n' > "$HOME_DIR/venv/bin/pip"
  ln -sf "$PYTHON" "$HOME_DIR/venv/bin/python"
  chmod +x "$HOME_DIR/venv/bin/pip"
fi
echo "    升级前版本: v$(sed -n 's/^__version__ *= *"\([^"]*\)".*/\1/p' "$HOME_DIR/zeroproxy/__init__.py")"

# ---------- 2. 真实 state.json (用当前代码跑一次面板 setup) ----------
ZP_HOME="$HOME_DIR" ZP_SIM_ROOT="$ROOT" "$PYTHON" - <<'PY'
import os
import sys
from pathlib import Path

ROOT = Path(os.environ["ZP_SIM_ROOT"])
sys.path.insert(0, str(ROOT / "backend"))
os.environ["ZP_STATIC"] = str(ROOT / "backend" / "static")
os.environ.setdefault("ZP_PORT", "8899")
os.environ.setdefault("ZP_BIND_PORT", "9900")
os.environ.setdefault("ZP_GEODATA_AUTO", "0")

from fastapi.testclient import TestClient  # noqa: E402

from zeroproxy import config  # noqa: E402
from zeroproxy.main import create_app  # noqa: E402

config.write_bootstrap_token("sim-token")
with TestClient(create_app()) as client:
    resp = client.post(
        "/api/setup",
        json={"domain": "proxy.example.com", "username": "admin", "password": "s3cretpass", "token": "sim-token"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["ok"] is True, resp.text
print("    state.json 已生成 (setup 全绿)")
PY

# 复刻线上现场: 配置被打回占位状态 (xray 无入站 / hysteria 用 changeme)
cat > "$HOME_DIR/xray/config.json" <<'JSON'
{"log": {"loglevel": "warning"}, "inbounds": [], "outbounds": [{"protocol": "freedom"}]}
JSON
cat > "$HOME_DIR/hysteria/config.yaml" <<'YAML'
# 占位配置, 面板完成部署后会被自动覆盖
listen: "127.0.0.1:30001"
auth:
  type: password
  password: "changeme"
YAML
cp "$HOME_DIR/data/state.json" "$SIM/state-before.json"
INBOUNDS_BEFORE="$(grep -c '"tag"' "$HOME_DIR/xray/config.json" || true)"
echo "    占位状态: xray 入站 $INBOUNDS_BEFORE 个, hysteria 口令 changeme"

# ---------- 3. "远端新代码" tarball (当前工作区) ----------
NEW_SRC="$SIM/newsrc/zeroproxy-main"
mkdir -p "$NEW_SRC"
cp -r "$ROOT/backend" "$ROOT/systemd" "$NEW_SRC/"
cp "$ROOT/upgrade.sh" "$NEW_SRC/"
[ -f "$ROOT/uninstall.sh" ] && cp "$ROOT/uninstall.sh" "$NEW_SRC/"
rm -rf "$NEW_SRC/backend/zeroproxy/__pycache__" "$NEW_SRC/backend/zeroproxy"/*/__pycache__
tar -czf "$SIM/new.tar.gz" -C "$SIM/newsrc" zeroproxy-main

# ---------- 4. 桩二进制 ----------
cat > "$BIN_DIR/id" <<'SH'
#!/bin/sh
[ "${1:-}" = "-u" ] && { echo 0; exit 0; }
exec /usr/bin/id "$@"
SH
cat > "$BIN_DIR/systemctl" <<'SH'
#!/bin/sh
exit 0
SH
cat > "$BIN_DIR/curl" <<'SH'
#!/bin/bash
out=""
url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
if [ -n "$out" ]; then
  if [ -n "${ZP_SIM_TARBALL:-}" ]; then cp "$ZP_SIM_TARBALL" "$out"; exit 0; fi
  exit 22                                  # 模拟 GitHub 不可达
fi
case "$url" in *127.0.0.1*/api/info*) exit 0 ;; esac
exit 0
SH
chmod +x "$BIN_DIR"/*

run_upgrade() { # run_upgrade <trigger> [tarball] [panel|file]
  # 跑的一律是 ZP_HOME 里那份 (线上就是它); 输出留档, 好在断言里查"脚本有没有报语法错"
  #   panel = 面板的起法 (脚本从 stdin 喂给 bash)
  #   file  = 命令行就地起法 (bash /opt/zeroproxy/upgrade.sh)
  local trigger="$1" tarball="${2:-}" mode="${3:-file}"
  local -a runner
  local self_dir=""
  if [ "$mode" = "panel" ]; then
    # 面板起法 (update.py stage_script): 先把脚本复制到私有临时目录, 再跑那份副本。
    # 副本必须换个 inode —— 就地执行 / `bash -s < 原文件` 都会因为脚本覆盖自己而读出语法错。
    STAGE="$(mktemp -d "${TMPDIR:-/tmp}/zeroproxy-update-sim.XXXXXX")"
    cp "$HOME_DIR/upgrade.sh" "$STAGE/upgrade.sh"
    chmod +x "$STAGE/upgrade.sh"
    runner=(/bin/bash "$STAGE/upgrade.sh")
    self_dir="$STAGE"
  else
    runner=(/bin/bash "$HOME_DIR/upgrade.sh")
  fi
  PATH="$BIN_DIR:$PATH" ZP_HOME="$HOME_DIR" ZP_TRIGGER="$trigger" \
    ZP_SIM_TARBALL="$tarball" ZP_SYSTEMD_DIR="$SIM/systemd-units" ZP_SELF_DIR="$self_dir" \
    "${runner[@]}" 2>&1 | tee "$SIM/upgrade-$trigger-$mode.log"
  return "${PIPESTATUS[0]}"
}

#: 跑完一次升级后, 机器上的 upgrade.sh 已经是新版本了 —— 用来断言"脚本覆盖自己也不会炸"
no_script_error() { # no_script_error <日志>
  ! grep -qE "syntax error|unexpected token" "$1"
}

# 升级过程中每 50ms 采一次进度文件 —— 用来证明"进度是边跑边写的", 而不是跑完才写一次
watch_progress() { # watch_progress <间隔秒> <日志文件>
  ( while :; do
      if [ -f "$HOME_DIR/data/update.json" ]; then
        "$PYTHON" - "$HOME_DIR/data/update.json" >> "$2" 2>/dev/null <<'PY' || true
import json
import sys

try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    raise SystemExit(0)
print(f'{d.get("state")}|{d.get("current")}|{len(d.get("steps") or [])}|{len(d.get("plan") or [])}')
PY
      fi
      sleep "$1"
    done ) &
  WATCH_PID=$!
}

# ---------- 5. 正常升级 ----------
section "[2] 正常升级 (真实 upgrade.sh, 面板起法: 从私有临时副本启动)"
WATCH_LOG="$SIM/progress-samples.txt"
: > "$WATCH_LOG"
watch_progress 0.05 "$WATCH_LOG"
set +e; run_upgrade sim "$SIM/new.tar.gz" panel; UPGRADE_RC=$?; set -e
kill "$WATCH_PID" 2>/dev/null || true
wait "$WATCH_PID" 2>/dev/null || true
echo "    退出码 $UPGRADE_RC"

section "[断言]"
[ "$UPGRADE_RC" = "0" ] && ok "upgrade.sh 退出码 0" || bad "upgrade.sh 退出码 $UPGRADE_RC (期望 0)"
SAMPLES="$(sort -u "$WATCH_LOG" | wc -l | tr -d ' ')"
MID="$(grep -c '^running|' "$WATCH_LOG" || true)"
STEPS_SEEN="$(sort -u "$WATCH_LOG" | sed -n 's/^running|.*|\([0-9]*\)|[0-9]*$/\1/p' | sort -n | tr '\n' ' ')"
if [ "${SAMPLES:-0}" -ge 3 ] && [ "${MID:-0}" -ge 2 ]; then
  ok "升级进度是边跑边写的 (采样到 $SAMPLES 种快照, $MID 次进行中; 完成步数依次为 ${STEPS_SEEN:-无})"
else
  bad "进度没有渐进写入 (只有 $SAMPLES 种状态, running 快照 $MID 次)"
fi
[ -f "$HOME_DIR/zeroproxy/apply.py" ] && ok "新代码已就位 (apply.py 存在)" || bad "新代码缺失 (没有 apply.py)"
[ -x "$HOME_DIR/upgrade.sh" ] && ok "upgrade.sh 随升级装到 ZP_HOME 且可执行" || bad "ZP_HOME/upgrade.sh 缺失或不可执行"
no_script_error "$SIM/upgrade-sim-panel.log" \
  && ok "升级全程无脚本错误 (老机器上的旧 upgrade.sh 也不炸 —— 跑的是副本, 不是会被覆盖的那份)" \
  || bad "升级过程里脚本报错: $(grep -m1 -E 'syntax error|unexpected token' "$SIM/upgrade-sim-panel.log")"

# ---------- 5b. 再就地升一次 (脚本会在运行中覆盖自己) ----------
section "[2b] 就地再升级一次 (bash /opt/zeroproxy/upgrade.sh)"
set +e; run_upgrade sim "$SIM/new.tar.gz" file; INPLACE_RC=$?; set -e
echo "    退出码 $INPLACE_RC"

section "[断言]"
[ "$INPLACE_RC" = "0" ] && ok "就地升级退出码 0" || bad "就地升级退出码 $INPLACE_RC (期望 0)"
no_script_error "$SIM/upgrade-sim-file.log" \
  && ok "就地执行也没被「覆盖自己」打断 (脚本先整份读进内存再跑)" \
  || bad "就地执行被自我覆盖打断: $(grep -m1 -E 'syntax error|unexpected token' "$SIM/upgrade-sim-file.log")"
if "$PYTHON" - "$HOME_DIR/data/update.json" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
assert data["state"] == "success", data
assert data["current"] == "", data
assert data["plan"] == [s["name"] for s in data["steps"]], (data["plan"], data["steps"])
PY
then
  ok "就地升级后状态是 success 且 plan 与 steps 同序对齐"
else
  bad "就地升级后 update.json 内容不符合预期"
fi

# ---------- 5c. 新脚本再走一次面板方式 (验证临时副本会自己收尾) ----------
section "[2c] 面板方式再升一次 (新脚本: 副本应自己清掉)"
set +e; run_upgrade sim "$SIM/new.tar.gz" panel; PANEL2_RC=$?; set -e
echo "    退出码 $PANEL2_RC"

section "[断言]"
[ "$PANEL2_RC" = "0" ] && ok "面板方式升级退出码 0" || bad "面板方式升级退出码 $PANEL2_RC (期望 0)"
no_script_error "$SIM/upgrade-sim-panel.log" \
  && ok "新脚本走面板方式也无脚本错误" \
  || bad "新脚本走面板方式报错: $(grep -m1 -E 'syntax error|unexpected token' "$SIM/upgrade-sim-panel.log")"
[ ! -d "$STAGE" ] && ok "临时副本已随升级收尾清掉 ($STAGE)" \
  || bad "临时副本残留: $STAGE"

cp "$HOME_DIR/data/state.json" "$SIM/state-after.json"
if "$PYTHON" - "$SIM/state-before.json" "$SIM/state-after.json" <<'PY'
import json
import sys

before = json.load(open(sys.argv[1], encoding="utf-8"))
after = json.load(open(sys.argv[2], encoding="utf-8"))
# steps (面板进度) 与 updated_at (写盘时间戳) 每次保存都会变; 其余字段必须一字不差
strip = lambda d: {k: v for k, v in d.items() if k not in ("steps", "updated_at")}
b, a = strip(before), strip(after)
if a != b:
    raise SystemExit("字段发生变化: " + ", ".join(sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))))
assert after.get("steps") and all(s["ok"] for s in after["steps"]), after.get("steps")
PY
then
  ok "state.json 的密钥 / 令牌 / 节点配置原样保留 (只有 steps 进度被刷新)"
else
  bad "state.json 的关键字段被改动"
fi

INBOUNDS_AFTER="$(grep -c '"tag"' "$HOME_DIR/xray/config.json" || true)"
[ "${INBOUNDS_AFTER:-0}" -ge 4 ] && ok "xray 配置按 state.json 重新落地 (入站 $INBOUNDS_AFTER 个, 升级前 $INBOUNDS_BEFORE 个)" \
  || bad "xray 配置没落地 (入站 $INBOUNDS_AFTER 个)"
grep -q "proxy.example.com" "$HOME_DIR/nginx/zeroproxy.conf" && ok "nginx 配置按 state.json 重新落地" \
  || bad "nginx 配置没落地"
if grep -q 'password: "changeme"' "$HOME_DIR/hysteria/config.yaml"; then
  bad "hysteria 仍是占位配置 (没被重新落地)"
else
  ok "hysteria 配置按 state.json 重新落地 (占位口令已被真实口令覆盖)"
fi

if "$PYTHON" - "$HOME_DIR/data/update.json" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
assert data["state"] == "success", data
assert data["trigger"] == "sim", data
names = [s["name"] for s in data["steps"]]
assert any("安装新代码" in n for n in names), names
assert any("重新生成配置" in n for n in names), names
assert all(s["ok"] for s in data["steps"]), data["steps"]
# 面板靠 plan 渲染"待执行 / 进行中 / 已完成", 名字必须和实际步骤一一对应且同序,
# 否则步骤清单会永远停在"待执行"。收尾时 current 也要清空。
plan = data.get("plan") or []
assert plan == names, f"plan 与 steps 对不上:\nplan={plan}\nsteps={names}"
assert data.get("current") == "", data.get("current")
print(f"    update.json: {data['message']} · {len(names)} 步全部成功 · plan 与 steps 同序对齐")
PY
then
  ok "升级进度写进 data/update.json (面板「程序更新」卡片读它)"
else
  bad "update.json 内容不符合预期"
fi

BACKUP="$(ls -1dt "$HOME_DIR"/data/backups/code-* 2>/dev/null | head -1 || true)"
if [ -n "$BACKUP" ] && [ -f "$BACKUP/state.json" ] && [ -d "$BACKUP/zeroproxy" ]; then
  ok "备份留存: $(basename "$BACKUP") (旧代码 + state.json)"
else
  bad "备份目录不符合预期: ${BACKUP:-无}"
fi

# ---------- 5d. apply 步骤内部失败: 失败原因必须写进 update.json ----------
# apply 自己还会再分几步 (生成 / 校验 / 重载 / 端口复查)。它失败时, 面板横幅引用的是
# update.json 里那一步的 detail —— 如果这里只写"命令执行失败, 详见日志", 用户就得去
# 翻日志里的那行 JSON。造一个坏 state 让 apply 内部某一步失败, 断言 detail 说得清。
section "[2c] apply 内部失败时, 失败原因写进 update.json"
cp -f "$HOME_DIR/data/state.json" "$SIM/state-keep.json"
"$PYTHON" - "$HOME_DIR/data/state.json" <<'PY'
import json
import sys

path = sys.argv[1]
data = json.load(open(path, encoding="utf-8"))
data["hysteria_password"] = 12345      # 非字符串 → 生成 Hysteria 2 配置必然抛异常
json.dump(data, open(path, "w", encoding="utf-8"), ensure_ascii=False)
PY
set +e; run_upgrade sim-applyfail "$SIM/new.tar.gz" panel >/dev/null 2>&1; APPLYFAIL_RC=$?; set -e
echo "    退出码 $APPLYFAIL_RC"

section "[断言]"
[ "$APPLYFAIL_RC" != "0" ] && ok "apply 内部失败时升级返回非 0 ($APPLYFAIL_RC)" || bad "apply 内部失败却返回 0"
APPLYFAIL_REASON="$("$PYTHON" - "$HOME_DIR/data/update.json" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
assert data["state"] == "failed", data
for step in data["steps"]:
    if not step["ok"] and step["name"] == "按 state.json 重新生成配置并热重载":
        print(step.get("detail") or "")
        break
PY
)"
case "$APPLYFAIL_REASON" in
  *重新生成*|*校验*|*重载*|*端口*)
    ok "失败原因写进 update.json (面板横幅直接引用): $APPLYFAIL_REASON" ;;
  *)
    bad "update.json 没带内部失败步骤, detail='${APPLYFAIL_REASON:-空}'" ;;
esac
cp -f "$SIM/state-keep.json" "$HOME_DIR/data/state.json"   # 还原, 不影响后面的演练

# ---------- 6. 故障演练: 下载失败 ----------
section "[3] 故障演练: 代码下载失败 (桩 curl 返回 22)"
VERSION_BEFORE_FAIL="$(sed -n 's/^__version__ *= *"\([^"]*\)".*/\1/p' "$HOME_DIR/zeroproxy/__init__.py")"
set +e; run_upgrade sim-fail "" >/dev/null 2>&1; FAIL_RC=$?; set -e

section "[断言]"
[ "$FAIL_RC" != "0" ] && ok "下载失败时返回非 0 ($FAIL_RC)" || bad "下载失败却返回 0"
VERSION_AFTER_FAIL="$(sed -n 's/^__version__ *= *"\([^"]*\)".*/\1/p' "$HOME_DIR/zeroproxy/__init__.py")"
[ "$VERSION_BEFORE_FAIL" = "$VERSION_AFTER_FAIL" ] && ok "代码自动回滚到升级前版本 (v$VERSION_AFTER_FAIL)" \
  || bad "代码没回滚: v$VERSION_BEFORE_FAIL → v$VERSION_AFTER_FAIL"
if "$PYTHON" - "$HOME_DIR/data/update.json" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
assert data["state"] == "failed", data
assert data["trigger"] == "sim-fail", data
assert any(not s["ok"] for s in data["steps"]), data["steps"]
PY
then
  ok "update.json 记为 failed 并带上失败步骤"
else
  bad "失败状态没落盘"
fi
NODES_AFTER_FAIL="$(grep -c '"tag"' "$HOME_DIR/xray/config.json" || true)"
[ "${NODES_AFTER_FAIL:-0}" -ge 4 ] && ok "失败的升级没有破坏现有部署 (入站仍有 $NODES_AFTER_FAIL 个)" \
  || bad "失败的升级把配置弄坏了 (入站 $NODES_AFTER_FAIL 个)"

echo
if [ "$FAILURES" = "0" ]; then
  echo "结论: 全部通过 — 成功与失败两条路径都符合预期"
else
  echo "结论: $FAILURES 项失败"
fi
exit "$FAILURES"
