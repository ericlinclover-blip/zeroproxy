#!/usr/bin/env bash
# 本地开发/验证 (macOS / Linux 均可, 无 systemd 时自动 dry-run)
#   ZP_PORT=8899 ./dev.sh
set -euo pipefail
cd "$(dirname "$0")"

export ZP_HOME="${ZP_HOME:-$PWD/data}"
export ZP_STATIC="${ZP_STATIC:-$PWD/backend/static}"
export ZP_PORT="${ZP_PORT:-8899}"
# 本地开发无 nginx: 面板进程直接监听该端口 (明文 HTTP)
export ZP_BIND_HOST="${ZP_BIND_HOST:-127.0.0.1}"
export ZP_BIND_PORT="${ZP_BIND_PORT:-$ZP_PORT}"

if [ ! -d .venv ]; then
  python3 -m venv .venv
  ./.venv/bin/pip install --upgrade pip -q
  ./.venv/bin/pip install -r backend/requirements.txt -q
fi

echo "ZeroProxy 面板: http://$ZP_BIND_HOST:$ZP_BIND_PORT  (ZP_HOME=$ZP_HOME)"
cd backend
exec "$PWD/../.venv/bin/python" -m zeroproxy.main
