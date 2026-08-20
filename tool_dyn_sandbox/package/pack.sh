#!/bin/bash
# package/pack.sh — 打源码 tarball (Source0)；--bump 单独递增 Release 并插入 %changelog
#
# 用法:
#   ./package/pack.sh                      # 纯打包: make clean + 打 tarball, 不碰 spec
#   ./package/pack.sh --bump ["消息"]      # 仅递增 spec: Release +1、插入 %changelog(最新在前), 不打 tarball
#
# --bump 消息取值优先级: 位置参数 > 环境变量 CHANGELOG_MSG > git 推导。
#   git 推导要求工作树干净 (git diff 与 --cached 均无修改, 未跟踪文件不计),
#   取最近一次提交的主题行; 不满足时报错退出。打包人可用 PACKAGER 覆盖 (缺省 dyn-sandbox team)。
#
# 说明:
#   - --bump 与打包完全隔离: 只改 spec, 不产生构建产物。
#   - tarball 用 tar + 排除规则生成 (不依赖 git), NFS/无 .git 环境 (openEuler VM) 也能用。
#   - tarball 文件名带 Release 号 dyn-sandbox-<ver>-<rel>.tar.gz, 与 spec 的
#     Source0 对应; 内层目录仍为 dyn-sandbox-<ver>, %setup -q 默认即可解包。
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"      # package/
ROOT="$(dirname "$DIR")"                  # 仓库根
SPEC="$DIR/dyn-sandbox.spec"

# ---- 通用助手 ----

die() { echo "error: $*" >&2; exit 1; }

# 读取 spec 中 "Key:" 行的值 (去掉前导空白)。用法: spec_value Version
spec_value() { sed -n "s/^$1:[[:space:]]*//p" "$SPEC"; }

# 解析 Release 行, 设置全局 RELEASE_NUM / RELEASE_SUFFIX
# (如 "3%{?dist}" -> RELEASE_NUM=3, RELEASE_SUFFIX=%{?dist})。
read_release() {
    local raw
    raw="$(spec_value Release)"
    raw="${raw%"${raw##*[![:space:]]}"}"          # 去尾部空白
    RELEASE_NUM="${raw%%[^0-9]*}"
    [[ "$RELEASE_NUM" =~ ^[0-9]+$ ]] || die "cannot parse Release '$raw' (expect numeric prefix)"
    RELEASE_SUFFIX="${raw#"$RELEASE_NUM"}"
}

# Release 行的值补齐空格, 与其它 preamble 行对齐 (参照 Version 行的值起始列, 如列 12)。
release_pad() {
    local val_col
    val_col="$(awk -F: '/^Version:/{ s=substr($0,index($0,":")+1); if (match(s,/[^ ]/)) print index($0,":")+RSTART }' "$SPEC")"
    if [ -n "$val_col" ] && [ "$val_col" -gt 9 ]; then
        printf '%*s' "$(( val_col - 9 ))" ""    # "Release:" 占 8 字符
    else
        printf '%s' "   "                       # 参照行缺失/不可解析时退化为 3 空格
    fi
}

# 从 git 推导 changelog 消息: 要求工作树干净, 取最近一次提交的主题行。
git_message() {
    git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 || \
        die "--bump 未带消息且当前不在 git 仓库内, 无法从提交推导; 请显式传消息"
    git -C "$ROOT" diff --quiet 2>/dev/null || \
        die "--bump 未带消息要求工作树干净, 但存在未提交修改 (git diff)"
    git -C "$ROOT" diff --cached --quiet 2>/dev/null || \
        die "--bump 未带消息要求工作树干净, 但存在已暂存修改 (git diff --cached)"
    MESSAGE="$(git -C "$ROOT" log -1 --format=%s 2>/dev/null || true)"
    [ -n "$MESSAGE" ] || die "无法读取 git 最近一次提交的消息"
}

# 在 %changelog 行后插入新条目 (rpm 约定: 最新在前)。
# 用法: insert_changelog "<日期>" "<打包人>" "<版本>" "<新Release号>"
insert_changelog() {
    local date="$1" packager="$2" version="$3" release="$4"
    local cl_line tmp
    cl_line="$(grep -n '^%changelog' "$SPEC" | head -1 | cut -d: -f1 || true)"
    if [ -z "$cl_line" ]; then
        printf '\n%%changelog\n' >> "$SPEC"
        cl_line="$(grep -n '^%changelog' "$SPEC" | head -1 | cut -d: -f1)"
    fi
    tmp="$(mktemp)"
    {
        head -n "$cl_line" "$SPEC"
        printf '* %s %s - %s-%s\n' "$date" "$packager" "$version" "$release"
        echo "- ${MESSAGE}"
        echo
        tail -n +$((cl_line + 1)) "$SPEC"
    } > "$tmp"
    mv "$tmp" "$SPEC"
}

# ---- 参数解析 ----

parse_args() {
    BUMP=0
    MESSAGE=""
    MSG_EXPLICIT=0
    case "${1:-}" in
        '') ;;                                        # 默认: 打包
        --bump)
            BUMP=1; shift
            [ $# -le 1 ] || die "too many arguments for --bump"
            if [ $# -eq 1 ]; then
                MESSAGE="$1"; MSG_EXPLICIT=1
            elif [ -n "${CHANGELOG_MSG:-}" ]; then
                MESSAGE="$CHANGELOG_MSG"; MSG_EXPLICIT=1
            fi
            ;;
        *) die "unknown argument '$1' (only --bump is supported)" ;;
    esac
}

# ---- --bump: Release +1、插入 %changelog, 不打 tarball ----

cmd_bump() {
    local line own date
    VERSION="$(spec_value Version)"
    [ -n "$VERSION" ] || die "cannot read Version from $SPEC"

    [ "$MSG_EXPLICIT" -eq 1 ] || git_message   # 位置参数/CHANGELOG_MSG 未给时从 git 推导

    read_release
    local old_release="${RELEASE_NUM}${RELEASE_SUFFIX}"
    RELEASE_NUM=$((RELEASE_NUM + 1))
    local new_release="${RELEASE_NUM}${RELEASE_SUFFIX}"

    # 整行替换 Release (按行号, 避免把 %{?dist} 当 sed 模式解析), 值对齐其它 preamble 行。
    line="$(grep -n '^Release:' "$SPEC" | head -1 | cut -d: -f1 || true)"
    [ -n "$line" ] || die "no Release: line in $SPEC"
    own="$(stat -c '%u:%g' "$SPEC")"           # 保留原属主 (NFS/VM root 场景)
    sed -i "${line}s/.*/Release:$(release_pad)${new_release}/" "$SPEC"

    date="$(LC_ALL=C date +'%a %b %d %Y')"
    insert_changelog "$date" "${PACKAGER:-dyn-sandbox team}" "$VERSION" "$RELEASE_NUM"

    chown "$own" "$SPEC" 2>/dev/null || true
    echo "==> Release: ${old_release} -> ${new_release}"
    echo "==> changelog: ${date} ${PACKAGER:-dyn-sandbox team} - ${VERSION}-${RELEASE_NUM} - ${MESSAGE}"
}

# ---- 纯打包: make clean + 打 tarball, 不碰 spec ----

cmd_pack() {
    local pkg tarball
    VERSION="$(spec_value Version)"
    [ -n "$VERSION" ] || die "cannot read Version from $SPEC"

    read_release    # 只取数字前缀; %{?dist} 等宏后缀放不进文件名

    # 内层目录只带 version: %setup -q 默认按 %{name}-%{version} 找解包目录。
    pkg="dyn-sandbox-$VERSION"
    cd "$ROOT"

    make clean >/dev/null

    # 打 Source0 tarball。make clean 已清编译产物, 这里排除它清不掉的:
    #   dist/     编译产物输出目录, tarball 也在此, 排除避免自包含
    #   package/  发布工具与 spec, 构建不需要
    #   test/     测试脚本与用例, 构建不需要
    #   *.log     test/ 的日志, make clean 不删
    #   demo      演示目录, 留作保险
    mkdir -p dist
    tarball="dist/${pkg}-${RELEASE_NUM}.tar.gz"
    tar -czf "$tarball" \
        --exclude='dist' --exclude='package' --exclude='test' \
        --exclude='*.log' --exclude='demo' \
        --transform="s,^,$pkg/," \
        * .gitignore
    echo "==> source tarball: $tarball ($(du -h "$tarball" | cut -f1))"
}

# ---- 入口 ----

main() {
    parse_args "$@"
    if [ "$BUMP" -eq 1 ]; then cmd_bump; else cmd_pack; fi
}
main "$@"
