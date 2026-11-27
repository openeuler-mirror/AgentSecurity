#!/bin/bash
# test_seccomp.sh — seccomp 测试用例
# 使用 seccomp_test 二进制精确验证各 profile 的 syscall 访问控制
# 可独立运行:  ./test_seccomp.sh
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
SANDBOX_RUN="/usr/bin/dyn-sandbox"
KO_DIR="$DIR/../dist"
# seccomp_test lives in the (NFS) test dir, which the child's mount namespace
# cannot see unless bind-mounted; the --mount /usr:ro covers /usr/bin instead.
TEST_BIN="/usr/bin/seccomp_test"
LOGFILE="test_seccomp.log"
PASS=0; FAIL=0; SKIP=0

log() { echo "--- $*"; }
pass() { echo "PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }
skip() { echo "SKIP: $1"; SKIP=$((SKIP+1)); }

PW="111111"
sudo_run() { echo "$PW" | sudo -S "$@"; }

# Make the test binary visible to the sandbox child under --mount /usr:ro.
# Primary source is dist/ (make all 后产物收敛于此); 未跑 make all 时回退到 test/ 源树.
SRC="$DIR/../dist/seccomp_test"
[ -f "$SRC" ] || SRC="$DIR/seccomp_test"
sudo_run install -m 0755 "$SRC" /usr/bin/seccomp_test 2>/dev/null

: > "$LOGFILE"
{
    echo "=============================================="
    echo "  Seccomp Tests"
    echo "  start: $(date +%T.%N)"
    echo "=============================================="
    echo ""
} >> "$LOGFILE"

run_test() {
    local name="$1"; shift
    local desc="$1"; shift
    local start end elapsed rc

    start=$(date +%s.%N)
    {
        echo ""
        echo "=== $name: $desc ==="
        echo "=== start: $(date +%T.%N) ==="
    } >> "$LOGFILE"

    "$@" >> "$LOGFILE" 2>&1
    rc=$?

    end=$(date +%s.%N)
    elapsed=$(echo "$end - $start" | bc)
    {
        echo "=== exit=$rc ==="
        echo "=== end: $(date +%T.%N) elapsed=${elapsed}s ==="
    } >> "$LOGFILE"

    printf "  [%7.3fs] %s\n" "$elapsed" "$name"
    return $rc
}

MOUNT_RO="--mount /usr:ro --mount /lib:ro --mount /lib64:ro"

T=0

# ============================================================
# T1-T3: 命名 profile 完整验证
# ============================================================
# 每个 profile 测试: 白名单内 syscall 能放行, 白名单外的能拦住

T=$((T+1)); log "Test $T: default profile 完整验证"
run_test "T$T" "seccomp default" \
    timeout 30 ${SANDBOX_RUN} ${MOUNT_RO} \
        --seccomp default -- \
        ${TEST_BIN} \
            --allow read,write,openat,close,mmap,mprotect,munmap,brk,exit_group,exit,\
newfstatat,lseek,pread64,pwrite64,access,faccessat,getdents64,dup,dup2,\
nanosleep,rt_sigaction,rt_sigprocmask,ioctl,writev,execve \
            --block socket,connect,clone,pipe2,fcntl,getpid,getuid,uname,getcwd,\
chdir,clock_gettime,mkdir,statx,readlink,wait4,getrandom \
&& pass "T$T default profile" || fail "T$T default profile"

T=$((T+1)); log "Test $T: file_access profile 完整验证"
run_test "T$T" "seccomp file_access" \
    timeout 30 ${SANDBOX_RUN} ${MOUNT_RO} \
        --seccomp file_access -- \
        ${TEST_BIN} \
            --allow read,write,openat,close,mmap,mprotect,munmap,brk,exit_group,exit,\
newfstatat,lseek,pread64,pwrite64,access,rt_sigaction,rt_sigprocmask,ioctl,\
writev,execve \
            --block faccessat,getdents64,dup,dup2,nanosleep,socket,connect,clone,\
pipe2,fcntl,getpid,getuid,uname,getcwd,chdir,clock_gettime,mkdir,statx,\
readlink,wait4,getrandom \
&& pass "T$T file_access profile" || fail "T$T file_access profile"

T=$((T+1)); log "Test $T: script profile 完整验证"
run_test "T$T" "seccomp script" \
    timeout 30 ${SANDBOX_RUN} ${MOUNT_RO} \
        --seccomp script -- \
        ${TEST_BIN} \
            --allow read,write,openat,close,mmap,mprotect,munmap,brk,exit_group,exit,\
newfstatat,lseek,pread64,pwrite64,access,faccessat,getdents64,dup,dup2,\
nanosleep,rt_sigaction,rt_sigprocmask,ioctl,writev,execve,clone,pipe2,\
socket,connect,fcntl,getpid,getuid,uname,getcwd,chdir,clock_gettime,mkdir,\
statx,readlink,wait4,getrandom \
&& pass "T$T script profile" || fail "T$T script profile"

# ============================================================
# T4-T5: 自定义 syscall 集合验证
# ============================================================
# 注意: --seccomp-syscalls 会自动注入 mandatory syscall (execve, prctl,
# capset, chdir, rt_sigaction, close, openat, read, fstat, prlimit64),
# 这些也会被 seccomp 放行, 因此在 --allow 中也需列出。

T=$((T+1)); log "Test $T: custom syscall — write+exit_group"
run_test "T$T" "custom syscall write+exit_group" \
    timeout 30 ${SANDBOX_RUN} ${MOUNT_RO} \
        --seccomp-syscalls write,exit_group -- \
        ${TEST_BIN} \
            --allow write,exit_group,read,openat,close \
            --block socket,connect,clone,mkdir,getpid,getuid,uname,getcwd,chdir,\
clock_gettime,nanosleep,mmap,mprotect,munmap,brk,newfstatat,lseek,dup,dup2,\
fcntl,ioctl,pipe2,statx,readlink,wait4,getrandom \
&& pass "T$T custom syscall write+exit_group" || fail "T$T custom syscall write+exit_group"

T=$((T+1)); log "Test $T: custom syscall — 仅 write, exit_group 被拦"
run_test "T$T" "custom syscall only write" \
    timeout 30 ${SANDBOX_RUN} ${MOUNT_RO} \
        --seccomp-syscalls write -- \
        ${TEST_BIN} \
            --allow write,read,openat,close \
            --block exit_group,socket,connect,clone,mkdir,getpid,getuid,uname,\
getcwd,chdir,clock_gettime,nanosleep,mmap,mprotect,munmap,brk,newfstatat,\
lseek,dup,dup2,fcntl,ioctl,pipe2,statx,readlink,wait4,getrandom \
&& pass "T$T custom syscall only write" || fail "T$T custom syscall only write"

# ============================================================
# T6-T10: 异常处理 + 互斥检查 (保留原测试逻辑)
# ============================================================

T=$((T+1)); log "Test $T: unknown profile name"
run_test "T$T" "unknown profile" \
    timeout 5 ${SANDBOX_RUN} --seccomp nosuch -- /usr/bin/true
rc=$?
[ "$rc" = "1" ] && pass "T$T unknown profile (exit=$rc)" \
    || fail "T$T unknown profile: expected exit=1, got exit=$rc"

T=$((T+1)); log "Test $T: unknown syscall name"
run_test "T$T" "unknown syscall name" \
    timeout 5 ${SANDBOX_RUN} --seccomp-syscalls foo,bar -- /usr/bin/true
rc=$?
[ "$rc" = "3" ] && pass "T$T unknown syscall name (exit=$rc)" \
    || fail "T$T unknown syscall name: expected exit=3, got exit=$rc"

T=$((T+1)); log "Test $T: no seccomp"
run_test "T$T" "no seccomp" \
    timeout 10 ${SANDBOX_RUN} ${MOUNT_RO} \
        -- /usr/bin/true \
&& pass "T$T no seccomp" || fail "T$T no seccomp"

T=$((T+1)); log "Test $T: --seccomp --seccomp-syscalls 互斥 (正序)"
run_test "T$T" "mutual exclusive (forward)" \
    timeout 5 ${SANDBOX_RUN} --seccomp script --seccomp-syscalls write,exit_group \
        -- ${TEST_BIN}
rc=$?
[ "$rc" = "1" ] && pass "T$T mutual exclusive forward" \
    || fail "T$T mutual exclusive forward: expected exit=1, got exit=$rc"

T=$((T+1)); log "Test $T: --seccomp-syscalls --seccomp 互斥 (逆序)"
run_test "T$T" "mutual exclusive (reverse)" \
    timeout 5 ${SANDBOX_RUN} --seccomp-syscalls write,exit_group --seccomp script \
        -- ${TEST_BIN}
rc=$?
[ "$rc" = "1" ] && pass "T$T mutual exclusive reverse" \
    || fail "T$T mutual exclusive reverse: expected exit=1, got exit=$rc"

# ============================================================
# 汇总
# ============================================================
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
