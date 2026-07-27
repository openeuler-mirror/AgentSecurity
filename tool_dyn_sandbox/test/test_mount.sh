#!/bin/bash
# test_mount.sh — /dev 挂载功能验证 (bind-mount 宿主设备节点)
#
# 用例间解耦: 每个用例 = 一次独立的 dyn-sandbox 调用, 沙箱内只执行一条指令,
#   各用例互不影响 —— 单个用例失败不连坐其他用例, 失败也便于单独定位/重跑。
#   断言方式统一为: 用例表第 2 列 expect — 0=须退出 0, NZ=须退出非 0 (故意失败用例)。
#
# 回归保护: 审查项 #13 — userns 沙箱里 mknod 建不出真设备节点, 早期实现用
#   mknod 缺 S_IFMT 的写法, /dev/zero 等变成 0 字节普通空文件 (dd 读 0 字节),
#   现改为 bind-mount 宿主设备节点。本套件通过 null/zero/full/random/urandom/tty
#   的类型与读写语义, 间接确认 setup_virtual_fs 里的 bind-mount 挂载生效。
#
# 在默认 Landlock base 规则下运行 (base 规则已预授权 6 节点 read+write+truncate,
# 见 dyn-sandbox.c setup_landlock_base), 因此既验证 bind-mount 出来的节点本身,
# 也顺带覆盖 base 规则对 /dev 的授权路径。
#
# 依赖: 模块已加载 + dyn-sandbox 已安装 (test_all.sh 在运行本套件前已 test_setup)。
# 环境就绪时可独立运行: ./test_mount.sh
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
SANDBOX_RUN="/usr/bin/dyn-sandbox"
LOGFILE="test_mount.log"
PASS=0; FAIL=0; SKIP=0
TIMEOUT=20

log() { echo "--- $*"; }
pass() { echo "PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }
skip() { echo "SKIP: $1"; SKIP=$((SKIP+1)); }

PW="111111"
sudo_run() { echo "$PW" | sudo -S "$@"; }

source "$DIR/test_common.sh"

: > "$LOGFILE"
{
    echo "=============================================="
    echo "  Mount Tests (/dev bind-mount)"
    echo "  start: $(date +%T.%N)"
    echo "=============================================="
} >> "$LOGFILE"

# run_case NAME EXPECT CMD — 沙箱内执行单条指令 CMD。
#   EXPECT=0  须退出 0;  EXPECT=NZ  须退出非 0 (故意失败用例)。
# timeout 兜底: 若意外触发 AUTH_REQ 导致子进程 SIGSTOP, 防止整套挂死。
run_case() {
    local name="$1" expect="$2" cmd="$3" rc
    {
        echo ""
        echo "=== $name: /bin/sh -c '$cmd' ==="
        echo "=== expect: $expect ==="
        echo "=== start: $(date +%T.%N) ==="
    } >> "$LOGFILE"

    # < /dev/null 关键: monitor 会把父进程 stdin 转发给 child (dyn-sandbox.c
    # forward_fd), 若继承 while 循环的 heredoc 会吃光后续用例行。EOF 时
    # decide_file_action 对 AUTH_REQ 一律 DENY, 用例干净失败而非挂死。
    timeout "$TIMEOUT" ${SANDBOX_RUN} --mount /usr:ro --mount /lib:ro --mount /lib64:ro \
        -- /bin/sh -c "$cmd" < /dev/null >> "$LOGFILE" 2>&1
    rc=$?

    {
        echo "=== exit=$rc ==="
        echo "=== end: $(date +%T.%N) ==="
    } >> "$LOGFILE"

    if [ "$rc" -eq 124 ]; then
        fail "dev $name (timeout ${TIMEOUT}s — 可能 AUTH_REQ 挂起, /dev 未放行?)"
    elif [ "$expect" = "0" ] && [ "$rc" -eq 0 ]; then
        pass "dev $name"
    elif [ "$expect" = "NZ" ] && [ "$rc" -ne 0 ]; then
        pass "dev $name (exit=$rc, 预期非0)"
    else
        fail "dev $name (exit=$rc, 预期 expect=$expect)"
    fi
}

# 用例表: "name|expect|沙箱内单条指令"。heredoc 引号定界, 内容原样传给 run_case,
# 不做宿主展开 (命令替换/管道在沙箱内 /bin/sh 里求值)。
# 前两个 | 切分 name/expect, 其余 (含 od ... | tr 里的 |) 原样保留给 cmd。
while IFS='|' read -r name expect cmd; do
    [ -z "$name" ] && continue            # 跳过空行
    case "$name" in \#*) continue ;; esac  # 跳过 # 注释行
    run_case "$name" "$expect" "$cmd"
done <<'CASES_EOF'
# 基线: 沙箱本身可启动 (模块未加载时 exit=6, 先在此暴露)
sandbox_boot|0|/usr/bin/true
# 6 节点都必须是字符设备
type_null|0|test -c /dev/null
type_zero|0|test -c /dev/zero
type_full|0|test -c /dev/full
type_random|0|test -c /dev/random
type_urandom|0|test -c /dev/urandom
type_tty|0|test -c /dev/tty
# /dev/null: 写成功, 读为空
null_write|0|echo x > /dev/null 2>/dev/null
null_read_empty|0|[ -z "$(cat /dev/null)" ]
# /dev/zero: 读 8 字节全零 (od 每字节 2 hex 字符 -> 16 字符), 写成功丢弃
zero_read_zeros|0|[ "$(od -An -tx1 -N8 /dev/zero | tr -d ' \n')" = 0000000000000000 ]
zero_write_ok|0|echo x > /dev/zero 2>/dev/null
# /dev/full: 写必须失败 (ENOSPC, 退出码非 0), 读全零
full_write_enospc|NZ|echo x > /dev/full 2>/dev/null
full_read_zeros|0|[ "$(od -An -tx1 -N4 /dev/full | tr -d ' \n')" = 00000000 ]
# /dev/random & /dev/urandom: 读非空
random_nonempty|0|[ -n "$(od -An -tx1 -N8 /dev/random)" ]
urandom_nonempty|0|[ -n "$(od -An -tx1 -N8 /dev/urandom)" ]
# 故意失败负向用例: 沙箱 /dev 只含 bind-mount 的 6 节点, 宿主设备 (如 /dev/kmsg)
# 必须不可达 -> test -e 退出非 0。若 /dev 被整棵 bind-mount 泄漏则此用例失败。
host_dev_isolated|NZ|test -e /dev/kmsg
CASES_EOF

{
    echo ""
    echo "=============================================="
    echo "  end: $(date +%T.%N)"
    echo "=============================================="
} >> "$LOGFILE"

echo ""
echo "=========================================="
echo "Results: $PASS passed, $FAIL failed, $SKIP skipped"
echo "=========================================="
echo "Log: $LOGFILE"

[ "$FAIL" -gt 0 ] && exit 1 || exit 0
