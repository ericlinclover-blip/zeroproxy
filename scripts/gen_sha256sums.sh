#!/usr/bin/env bash
# ============================================================
#  生成仓库根的 SHA256SUMS（随代码分发的关键文件清单）
#
#  为什么要有它: install.sh / upgrade.sh 下载代码包之后, 会用**同一 ref 的原始
#  raw 地址**独立取一份 SHA256SUMS 逐文件比对 —— 镜像只承担传输, 不再能决定
#  装进来的字节。清单本身必须能在发布前一条命令重建, 否则改完代码忘了更新清单,
#  安装就会在"校验不符"上直接中止。
#
#  用法:
#    bash scripts/gen_sha256sums.sh                  # 生成仓库根 SHA256SUMS
#    bash scripts/gen_sha256sums.sh <代码树> [输出]   # 给任意代码树生成 (upgrade_sim 用)
#
#  发布流程 (必须): 改完所有代码 → 跑本脚本 → 提交代码与 SHA256SUMS (同一个 commit)。
#  install.sh / upgrade.sh 取的是**同一个 ref** 的清单, 两者不同步就会校验失败。
# ============================================================
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-$ROOT}"
OUT="${2:-$ROOT/SHA256SUMS}"

[ -d "$TARGET" ] || { echo "代码树不存在: $TARGET" >&2; exit 1; }
cd "$TARGET"

#: sha256 的实现按可用性回退 (Debian/Ubuntu 有 sha256sum; macOS 只有 shasum)
sha256_file() {
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

#: 随代码分发、需要被校验的文件。与 install.sh / upgrade.sh 里的信任边界一致:
#:   * 以 root 执行的脚本 (install / upgrade / uninstall / dev)
#:   * 面板 Python 代码与前端静态资源 (面板以 root 跑)
#:   * 依赖清单、systemd 单元
#:   * 路由器侧整套分发物 (router-install.sh / runtime / luci / agent 制品)
#: 顺序统一由 LC_ALL=C sort 决定, 保证同一棵树每次生成的结果完全一样。
list_files() {
  printf '%s\n' install.sh upgrade.sh uninstall.sh dev.sh backend/requirements.txt
  find systemd -maxdepth 1 -type f -name '*.service' 2>/dev/null || true
  find backend/zeroproxy -maxdepth 1 -type f -name '*.py' 2>/dev/null || true
  find backend/static -type f 2>/dev/null || true
  find backend/zeroproxy/client -type f 2>/dev/null || true
}

TMP="$OUT.tmp.$$"
: > "$TMP"
trap 'rm -f "$TMP"' EXIT

count=0
while IFS= read -r f; do
  case "$f" in
    ""|*__pycache__*|*.pyc|*.pyo|*.bak|*.bak.*|*/.DS_Store) continue ;;
  esac
  [ -f "$f" ] || continue
  hash="$(sha256_file "$f")" || { echo "无法计算 sha256: $f" >&2; exit 1; }
  printf '%s  %s\n' "$hash" "$f" >> "$TMP"
  count=$((count + 1))
done < <(list_files | LC_ALL=C sort -u)

[ "$count" -gt 0 ] || { echo "清单为空 (代码树不完整?): $TARGET" >&2; exit 1; }
mv -f "$TMP" "$OUT"
trap - EXIT
echo "已生成 $OUT ($count 个文件)"
