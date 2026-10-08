#!/bin/sh
# 构建 zpcore (路由器本地控制面), 产出面板要分发的那几个架构。
#
# 为什么制品要**进仓库**: 面板的分发模型是"面板缓存制品, 路由器只访问面板一个地址"
# (与 mihomo 内核同一条路)。zpcore 是我们自己的东西, 没有上游可以下载 —— 所以它得跟着
# 代码一起到服务器上。跑一次这个脚本, 把 dist/ 提交上去, 之后每台路由器装机时取自己
# 那一个架构的二进制 (面板直传)。
#
# 产出是 **.gz** (与 mihomo 内核同一种形态): Go 二进制压一下大约剩 45%, 而路由器端
# 判断/解压/校验那段代码已经在 mihomo 那条路上跑过七次真机 —— 直接复用, 不写第二套。
#
# 用法:
#   scripts/build-agent.sh                 # 常用的六个架构
#   scripts/build-agent.sh arm64 amd64     # 只构建指定的
#   scripts/build-agent.sh all             # 全部八个
#   ZP_AGENT_VERSION=1.0.1 scripts/build-agent.sh   # 换个版本号 (面板要跟着改)
#
# 本机没有 Go 时只提示、不失败 —— 没构建就等于"这台面板没有本地界面二进制", 路由器端
# 会自动退回原来的界面路径 (固件 Web 服务 / busybox httpd), 装机不会因此失败。
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/backend/zeroproxy/client/agent"
DIST="$SRC/dist"
# 版本号只有一处定义: 面板代码里的 AGENT_VERSION。**不许在这里再写一个字面量** ——
# 两边一旦漂移, 面板会去找一个 build 从来没产出过的文件名, 结果就是"某一天开始所有
# 路由器都装不上本地控制面", 而且只在装机时才暴露。这里直接把它读出来。
VERSION="${ZP_AGENT_VERSION:-$(sed -n \
    's/^AGENT_VERSION = os.environ.get("ZP_AGENT_VERSION", "\(.*\)")$/\1/p' \
    "$ROOT/backend/zeroproxy/router_client.py" | head -n1)}"
if [ -z "$VERSION" ]; then
    echo "读不到 router_client.py 里的 AGENT_VERSION —— 两边的版本号必须一致, 停在这里。" >&2
    exit 1
fi

GO=""
for candidate in "${GO:-}" go /usr/local/go/bin/go /opt/homebrew/bin/go; do
    [ -n "$candidate" ] || continue
    if command -v "$candidate" >/dev/null 2>&1; then GO="$candidate"; break; fi
done
if [ -z "$GO" ]; then
    echo "本机没有 Go 工具链 —— 跳过 zpcore 构建。"
    echo "这不会让装机失败: 路由器端会自动退回原来的界面路径。"
    echo "要构建请先装 Go (https://go.dev/dl/ 或 brew install go), 再跑一次本脚本。"
    exit 0
fi

COMMON="arm64 armv7 armv6 amd64 mips mipsle"
ALL="arm64 armv7 armv6 amd64 mips mipsle mips64 mips64le"

if [ "$#" -eq 0 ]; then
    TARGETS="$COMMON"
elif [ "$1" = "all" ]; then
    TARGETS="$ALL"
else
    TARGETS="$*"
fi

# 我们自己的架构名 → Go 的 GOARCH/GOARM/GOMIPS。
go_env() {
    case "$1" in
        arm64)    printf 'GOARCH=arm64' ;;
        armv7)    printf 'GOARCH=arm GOARM=7' ;;
        armv6)    printf 'GOARCH=arm GOARM=6' ;;
        amd64)    printf 'GOARCH=amd64' ;;
        mips)     printf 'GOARCH=mips GOMIPS=softfloat' ;;
        mipsle)   printf 'GOARCH=mipsle GOMIPS=softfloat' ;;
        mips64)   printf 'GOARCH=mips64' ;;
        mips64le) printf 'GOARCH=mips64le' ;;
        *)        return 1 ;;
    esac
}

mkdir -p "$DIST"
cd "$SRC" || exit 1

echo "zpcore v$VERSION → $DIST"
FAILED=0
for arch in $TARGETS; do
    envs="$(go_env "$arch")" || { echo "  ? 不认识的架构: $arch"; FAILED=1; continue; }
    out="$DIST/zpcore-$arch-$VERSION"
    # -trimpath: 不要把本机路径写进二进制 (别人反查得到你的目录结构, 也没必要)
    # -s -w:     去掉符号表, 路由器闪存寸土寸金
    # shellcheck disable=SC2086
    if env GOOS=linux CGO_ENABLED=0 $envs "$GO" build -trimpath -ldflags "-s -w" -o "$out" . ; then
        gzip -9 -c "$out" > "$out.gz" && rm -f "$out"
        printf '  ✓ %-9s %s KB (压缩后)\n' "$arch" "$(( $(wc -c < "$out.gz") / 1024 ))"
    else
        printf '  ✗ %-9s 构建失败\n' "$arch"
        FAILED=1
    fi
done

if [ "$FAILED" = "1" ]; then
    echo "有架构没构建成功 —— 上面标 ✗ 的那几个上, 路由器会退回原来的界面路径。"
    exit 1
fi
echo "完成。记得把 $DIST 一起提交, 面板才发得出去。"
echo "只需要部分架构的话, 直接删掉对应的 zpcore-<架构>-<版本>.gz —— 装了那一档的路由器会自动退回原来的界面路径。"
