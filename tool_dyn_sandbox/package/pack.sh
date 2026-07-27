#!/bin/bash
# package/pack.sh — 打源码 tarball (Source0)
#
# 用法:
#   ./package/pack.sh                   # 打 tar 到 dist/
#
# 说明:
#   - 源码 tarball 用 tar + 排除规则生成(不依赖 git)，在 NFS 挂载、无 .git 的
#     环境(如 openEuler VM)上也能工作。
#   - 输出到 dist/，与编译产物同目录；tarball 自身在打包时被 dist 排除。
#   - 只打 tar，不构建 RPM；构建请在装好 rpmbuild 的机器上单独执行。
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"      # package/
ROOT="$(dirname "$DIR")"                  # 仓库根
SPEC="$DIR/dyn-sandbox.spec"

VERSION="$(sed -n 's/^Version:[[:space:]]*//p' "$SPEC")"
[ -n "$VERSION" ] || { echo "error: cannot read Version from $SPEC" >&2; exit 1; }

PKG="dyn-sandbox-$VERSION"
cd "$ROOT"

# 用 make clean 清理子目录构建产物(.o/.ko/二进制)。
# 驱动 clean 需要内核头; 失败说明源码不干净, 直接报错而不是打出脏包。
make clean >/dev/null

# 打 Source0 tarball。make clean 已清掉编译产物, 这里只排除它清不掉的:
#   - dist/       编译产物输出目录; tarball 也在这里, 排除避免自包含
#   - package/    发布工具与 spec, 构建不需要
#   - test/       测试脚本与用例, 构建不需要
#   - *.log       test/ 的日志, make clean 不删
#   - demo        演示目录, 留作保险
mkdir -p dist
TARBALL="dist/$PKG.tar.gz"
tar -czf "$TARBALL" \
    --exclude='dist' --exclude='package' --exclude='test' \
    --exclude='*.log' --exclude='demo' \
    --transform="s,^,$PKG/," \
    * .gitignore
echo "==> source tarball: $TARBALL ($(du -h "$TARBALL" | cut -f1))"
