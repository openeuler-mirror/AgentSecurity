#!/bin/bash
# test_file.sh — 文件隔离测试用例
# 可独立运行:  ./test_file.sh
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
SANDBOX_RUN="/usr/bin/dyn-sandbox"
KO_DIR="$DIR/../dist"
SANDBOX_DATA="$HOME/sandbox-data"
mkdir -p "$SANDBOX_DATA" 2>/dev/null || true
LOGFILE="test_file.log"
PASS=0; FAIL=0; SKIP=0

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
    echo "  File Isolation Tests"
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

# run_dyn_test — 通过 coproc 自动响应 AUTH_REQ
run_dyn_test() {
    local name="$1"; shift
    local desc="$1"; shift
    local start end elapsed rc

    start=$(date +%s.%N)
    {
        echo ""
        echo "=== $name: $desc ==="
        echo "=== start: $(date +%T.%N) ==="
    } >> "$LOGFILE"

    # 启动 dyn-sandbox 并通过 coproc 双向通信
    coproc DYN { "$@" 2>&1; }
    local dyn_in="${DYN[0]:-}" dyn_out="${DYN[1]:-}"
    if [ -z "$dyn_in" ]; then
        echo "ERROR: coproc DYN failed" >> "$LOGFILE"
        return 1
    fi
    # 把 dyn_in 重定向到 fd 10 (避免每个 read 都重新 open)
    eval "exec 10<&${dyn_in}"
    while IFS= read -r line <&10; do
        if [[ "$line" == AUTH_REQ:* ]]; then
            echo "ALLOW" >&"$dyn_out"
        fi
        echo "$line" >> "$LOGFILE"
    done 2>/dev/null
    eval "exec 10<&-"
    # $DYN_PID 也可能被 bash 清理, 用 $! 兜底
    local cp_pid="${DYN_PID:-$!}"
    wait "$cp_pid" 2>/dev/null; rc=$?

    end=$(date +%s.%N)
    elapsed=$(echo "$end - $start" | bc)
    {
        echo "=== exit=$rc ==="
        echo "=== end: $(date +%T.%N) elapsed=${elapsed}s ==="
    } >> "$LOGFILE"

    printf "  [%7.3fs] %s\n" "$elapsed" "$name"
    return $rc
}

# run_dyn_test_custom — 按文件名白名单决策 ALLOW/DENY
# 用法: run_dyn_test_custom name desc "path1 path2 ..." -- cmd...
# allow_list 为空则全部 DENY
run_dyn_test_custom() {
    local name="$1"; shift
    local desc="$1"; shift
    local allow_list="$1"; shift
    local start end elapsed rc

    start=$(date +%s.%N)
    {
        echo ""
        echo "=== $name: $desc ==="
        echo "=== start: $(date +%T.%N) ==="
    } >> "$LOGFILE"

    coproc DYN { "$@" 2>&1; }
    local dyn_in="${DYN[0]:-}" dyn_out="${DYN[1]:-}"
    if [ -z "$dyn_in" ]; then
        echo "ERROR: coproc DYN failed" >> "$LOGFILE"
        return 1
    fi
    eval "exec 10<&${dyn_in}"
    while IFS= read -r line <&10; do
        if [[ "$line" == AUTH_REQ:* ]]; then
            local req_path="${line#AUTH_REQ:}"
            req_path="${req_path%%:*}"
            local matched=0
            for allowed in $allow_list; do
                if [[ "$req_path" == "$allowed" ]]; then
                    matched=1
                    break
                fi
            done
            if [[ "$matched" == "1" ]]; then
                echo "ALLOW" >&"$dyn_out"
            else
                echo "DENY" >&"$dyn_out"
            fi
        fi
        echo "$line" >> "$LOGFILE"
    done 2>/dev/null
    eval "exec 10<&-"
    local cp_pid="${DYN_PID:-$!}"
    wait "$cp_pid" 2>/dev/null; rc=$?

    end=$(date +%s.%N)
    elapsed=$(echo "$end - $start" | bc)
    {
        echo "=== exit=$rc ==="
        echo "=== end: $(date +%T.%N) elapsed=${elapsed}s ==="
    } >> "$LOGFILE"

    printf "  [%7.3fs] %s\n" "$elapsed" "$name"
    return $rc
}

# run_concurrent_test — 并发 Landlock 动态授权竞态回归 (#5)
# 宿主当前用户 (非 sudo) 预创建 N 个独立子目录 d1..dN 各 1 个 644 文件, 沙箱内
# 并发 N 进程各自 truncate d$i/f$i。每个子目录在 Landlock 基础规则之外且各自独立
# 未授权 -> N 进程同时 EACCES -> 同时触发动态授权, 互不共享规则。
# 判定: 授权请求 >= N 且路径互不串扰, child 全成功, 全部结束无死锁, dyn-sandbox rc=0。
# 构造说明: 宿主当前用户预创建避免 ① 宿主 root:644 (沙箱内映射为用户后 VFS ugo 检查
# 即拒, 非 Landlock) ② /tmp (Landlock 基础规则已放行写, 不触发动态授权)。
# 用后 rm -rf 清理。
run_concurrent_test() {
    local name="$1"
    local N="${2:-10}"
    local CONC_DIR="$SANDBOX_DATA/cd_conc"
    local start end elapsed rc AUTH_COUNT DONE_SEEN line p i
    local dyn_in dyn_out cp_pid

    # 宿主当前用户预创建 (非 sudo)
    rm -rf "$CONC_DIR"
    mkdir -p "$CONC_DIR"
    for i in $(seq 1 "$N"); do
        mkdir -p "$CONC_DIR/d$i"
        echo "seed$i" > "$CONC_DIR/d$i/f$i"
        chmod 644 "$CONC_DIR/d$i/f$i"
    done

    start=$(date +%s.%N)
    {
        echo ""
        echo "=== $name: 并发 $N 进程 truncate 独立子目录 ==="
        echo "=== start: $(date +%T.%N) ==="
    } >> "$LOGFILE"

    coproc DYN { timeout 90 ${SANDBOX_RUN} --mount /usr:ro --mount /lib:ro --mount /lib64:ro \
        --mount "$SANDBOX_DATA":rw --landlock /:execute \
        -- /usr/bin/bash -c '
            set -u
            for i in $(seq 1 '"$N"'); do
                ( /usr/bin/truncate -s 0 '"$CONC_DIR"'/d$i/f$i; echo "child$i rc=$?" ) &
            done
            wait
            echo "ALL_CONCURRENT_DONE"
        ' 2>&1; }
    dyn_in="${DYN[0]:-}"
    if [ -z "$dyn_in" ]; then
        echo "ERROR: coproc DYN failed" >> "$LOGFILE"
        rm -rf "$CONC_DIR"
        return 1
    fi
    dyn_out="${DYN[1]:-}"
    eval "exec 10<&${dyn_in}"
    AUTH_COUNT=0
    DONE_SEEN=0
    local -A AUTH_PATHS
    local -A CHILD_RC
    while IFS= read -r line <&10; do
        if [[ "$line" == AUTH_REQ:* ]]; then
            echo "ALLOW" >&"$dyn_out"
            AUTH_COUNT=$((AUTH_COUNT+1))
            p="${line#AUTH_REQ:}"; p="${p%%:*}"
            AUTH_PATHS["$p"]=1
            echo "$line" >> "$LOGFILE"
        elif [[ "$line" == ALL_CONCURRENT_DONE ]]; then
            DONE_SEEN=1
            echo "$line" >> "$LOGFILE"
        elif [[ "$line" == child*rc=* ]]; then
            local cr="${line##*rc=}"
            CHILD_RC["$cr"]=$(( ${CHILD_RC["$cr"]:-0} + 1 ))
            echo "$line" >> "$LOGFILE"
        elif [[ "$line" != dyn-sandbox:* ]]; then
            echo "$line" >> "$LOGFILE"
        fi
    done 2>/dev/null
    eval "exec 10<&-"
    cp_pid="${DYN_PID:-$!}"
    wait "$cp_pid" 2>/dev/null; rc=$?

    # 用完清理 (宿主当前用户即可删)
    rm -rf "$CONC_DIR"

    end=$(date +%s.%N)
    elapsed=$(echo "$end - $start" | bc)
    {
        echo "AUTH_REQ=$AUTH_COUNT unique_paths=${#AUTH_PATHS[@]} done=$DONE_SEEN child_ok=${CHILD_RC[0]:-0}"
        echo "=== exit=$rc ==="
        echo "=== end: $(date +%T.%N) elapsed=${elapsed}s ==="
    } >> "$LOGFILE"

    printf "  [%7.3fs] %s\n" "$elapsed" "$name"

    if [ "$rc" -eq 0 ] \
       && [ "$AUTH_COUNT" -ge "$N" ] \
       && [ "${#AUTH_PATHS[@]}" -ge "$N" ] \
       && [ "${CHILD_RC[0]:-0}" -eq "$N" ] \
       && [ "$DONE_SEEN" -eq 1 ]; then
        return 0
    fi
    return 1
}

# 清空 dmesg，避免环形缓冲区满导致行号偏移失效
sudo_run dmesg -c > /dev/null 2>&1 || true

T=0

# === T1: basic isolation ===
T=$((T+1)); log "Test $T: basic isolation"
run_test "T1" "basic isolation" \
    timeout 10 ${SANDBOX_RUN} --mount /usr:ro --mount /lib:ro --mount /lib64:ro -- /usr/bin/true \
&& pass "basic isolation" || fail "basic isolation"

# === T2: Landlock exec ===
T=$((T+1)); log "Test $T: Landlock exec"
run_test "T2" "Landlock exec" \
    timeout 10 ${SANDBOX_RUN} --mount /usr:ro --mount /lib:ro --mount /lib64:ro \
        --landlock '/:read+execute' -- /usr/bin/true \
&& pass "Landlock exec" || fail "Landlock exec"

# === T3: seccomp default ===
T=$((T+1)); log "Test $T: seccomp default"
run_test "T3" "seccomp default" \
    timeout 10 ${SANDBOX_RUN} --mount /usr:ro --mount /lib:ro --mount /lib64:ro \
        --seccomp default -- /usr/bin/true \
&& pass "seccomp default" || fail "seccomp default"

# === T4: seccomp script ===
T=$((T+1)); log "Test $T: seccomp script"
run_test "T4" "seccomp script" \
    timeout 10 ${SANDBOX_RUN} --mount /usr:ro --mount /lib:ro --mount /lib64:ro \
        --seccomp script -- /usr/bin/true \
&& pass "seccomp script" || fail "seccomp script"

# === T5: Landlock + seccomp ===
T=$((T+1)); log "Test $T: Landlock + seccomp"
run_test "T5" "Landlock + seccomp" \
    timeout 10 ${SANDBOX_RUN} --mount /usr:ro --mount /lib:ro --mount /lib64:ro \
        --landlock '/:read+execute' --seccomp default -- /usr/bin/true \
&& pass "Landlock + seccomp" || fail "Landlock + seccomp"

# === T6: tmpfs write ===
T=$((T+1)); log "Test $T: tmpfs write"
run_test "T6" "tmpfs write" \
    timeout 10 ${SANDBOX_RUN} --mount /usr:ro --mount /lib:ro --mount /lib64:ro \
        --mount-tmpfs /tmp:16 -- /usr/bin/sh -c 'echo ok > /tmp/test && cat /tmp/test' \
&& pass "tmpfs write" || fail "tmpfs write"

# === T7: fork monitor mode ===
T=$((T+1)); log "Test $T: fork monitor mode"
run_test "T7" "fork monitor mode (run 1)" \
    timeout 15 ${SANDBOX_RUN} --mount /usr:ro --mount /lib:ro --mount /lib64:ro \
        --landlock '/:read+execute' -- /usr/bin/true
has_monitor=$?
# run_test already appended to LOGFILE; check latest lines for "monitor pid"
grep -v "^TIMING" "$LOGFILE" | tail -20 | grep -q "monitor pid" && has_monitor=0 || has_monitor=1
[ "$has_monitor" = "0" ] && pass "fork monitor mode" || fail "fork monitor mode"

# === T8: no module exit=6 ===
T=$((T+1)); log "Test $T: no module error exit=6"
test_cleanup
run_test "T8" "no module exit=6" \
    timeout 5 ${SANDBOX_RUN} --mount /usr:ro -- /usr/bin/true
rc=$?
[ "$rc" = "6" ] && pass "no module exit=6" || fail "no module exit=$rc (expected 6)"
test_setup

# === T9: non-root execution ===
T=$((T+1)); log "Test $T: non-root execution"
run_test "T9" "non-root execution" \
    timeout 10 ${SANDBOX_RUN} --mount /usr:ro --mount /lib:ro --mount /lib64:ro -- /usr/bin/true \
&& pass "non-root execution" || fail "non-root execution"

# === T10: Landlock read_file ===
T=$((T+1)); log "Test $T: Landlock read_file"
run_test "T10" "Landlock read_file" \
    timeout 10 ${SANDBOX_RUN} --mount /usr:ro --mount /lib:ro --mount /lib64:ro \
        -- /usr/bin/cat /usr/bin/true \
&& pass "Landlock read_file" || fail "Landlock read_file"

# === T11: kprobe SIGSTOP 动态放权 ===
T=$((T+1)); log "Test $T: kprobe SIGSTOP dynamic allow"
run_dyn_test "T11" "kprobe SIGSTOP dynamic allow" \
    timeout 15 ${SANDBOX_RUN} --mount /usr:ro --mount /lib:ro --mount /lib64:ro \
        --mount-tmpfs /mnt:16 --landlock '/:read+execute' \
        -- /usr/bin/sh -c 'echo ok > /mnt/testwrite && echo "ALL dynamic allow tests passed"'
rc=$?
# 验证 child stdout 被 coproc 捕获
grep -q "ALL dynamic allow tests passed" "$LOGFILE" \
&& pass "kprobe SIGSTOP dynamic allow (stdout captured)" \
|| fail "kprobe SIGSTOP dynamic allow (stdout MISSING, exit=$rc)"

# ------------------------------------------------------------------
#  动态放权覆盖测试（T12-T18）
#  验证每个 Landlock 权限位的 kretprobe → SIGSTOP → ALLOW 流程
# ------------------------------------------------------------------

# dmesg 行号快照辅助
dmesg_save() {
    DMESG_BASE=$(sudo_run dmesg 2>/dev/null | wc -l)
}
dmesg_has() {
    local pattern="$1"
    sudo_run dmesg 2>/dev/null | tail -n +$((DMESG_BASE + 1)) | grep "$pattern" > /dev/null
}
# log_save/log_has — 在 LOGFILE 中按行号范围搜索
log_save() {
    LOG_BASE=$(wc -l < "$LOGFILE")
}
log_has() {
    local pattern="$1"
    tail -n +$((LOG_BASE + 1)) "$LOGFILE" | grep "$pattern" > /dev/null
}

# 基础参数：所有动态放权测试共享
# 只用 :execute，让 /mnt 下的所有文件操作都被 Landlock 阻断
DYN_ACT="--mount /usr:ro --mount /lib:ro --mount /lib64:ro --mount-tmpfs /mnt:16 --landlock /:execute"

# === T12: MAKE_REG（创建文件） ===
T=$((T+1)); log "Test $T: dynamic auth MAKE_REG"
dmesg_save
run_dyn_test "T12" "MAKE_REG (touch)" \
    timeout 15 ${SANDBOX_RUN} $DYN_ACT -- /usr/bin/touch /mnt/newfile
rc=$?
[ "$rc" -eq 0 ] && dmesg_has "BLOCKED.*MAKE_REG" \
&& pass "T12 MAKE_REG" || fail "T12 MAKE_REG"

# === T13: MAKE_DIR（创建目录） ===
T=$((T+1)); log "Test $T: dynamic auth MAKE_DIR"
dmesg_save
run_dyn_test "T13" "MAKE_DIR (mkdir)" \
    timeout 15 ${SANDBOX_RUN} $DYN_ACT -- /usr/bin/mkdir /mnt/newdir
rc=$?
[ "$rc" -eq 0 ] && dmesg_has "BLOCKED.*MAKE_DIR" \
&& pass "T13 MAKE_DIR" || fail "T13 MAKE_DIR"

# === T14: REMOVE_FILE（删除文件） ===
# 通过两次 dyn-sandbox 共享宿主 ${SANDBOX_DATA}（无默认 Landlock 规则）
T=$((T+1)); log "Test $T: dynamic auth REMOVE_FILE"
dmesg_save
# Step 1: 创建文件（触发 MAKE_REG 放权）
# (coproc 自动响应 ALLOW)
run_dyn_test "T14-S1" "create file" \
    timeout 15 ${SANDBOX_RUN} --mount /usr:ro --mount /lib:ro --mount /lib64:ro \
    --mount ${SANDBOX_DATA}:rw --landlock /:execute \
    -- /usr/bin/touch ${SANDBOX_DATA}/sandbox_t14_file
rc1=$?
# Step 2: 删除文件（触发 REMOVE_FILE 放权）
run_dyn_test "T14-S2" "remove file" \
    timeout 15 ${SANDBOX_RUN} --mount /usr:ro --mount /lib:ro --mount /lib64:ro \
    --mount ${SANDBOX_DATA}:rw --landlock /:execute \
    -- /usr/bin/rm ${SANDBOX_DATA}/sandbox_t14_file
rc2=$?
[ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ] && dmesg_has "BLOCKED.*REMOVE_FILE" \
&& pass "T14 REMOVE_FILE" || fail "T14 REMOVE_FILE"

# === T15: REMOVE_DIR（删除目录） ===
# 通过两次 dyn-sandbox 共享宿主 ${SANDBOX_DATA}（无默认 Landlock 规则）
T=$((T+1)); log "Test $T: dynamic auth REMOVE_DIR"
dmesg_save
# Step 1: 创建目录（触发 MAKE_DIR 放权）
run_dyn_test "T15-S1" "create dir" \
    timeout 15 ${SANDBOX_RUN} --mount /usr:ro --mount /lib:ro --mount /lib64:ro \
    --mount ${SANDBOX_DATA}:rw --landlock /:execute \
    -- /usr/bin/mkdir ${SANDBOX_DATA}/sandbox_t15_dir
rc1=$?
# Step 2: 删除目录（触发 REMOVE_DIR 放权）
run_dyn_test "T15-S2" "remove dir" \
    timeout 15 ${SANDBOX_RUN} --mount /usr:ro --mount /lib:ro --mount /lib64:ro \
    --mount ${SANDBOX_DATA}:rw --landlock /:execute \
    -- /usr/bin/rmdir ${SANDBOX_DATA}/sandbox_t15_dir
rc2=$?
[ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ] && dmesg_has "BLOCKED.*REMOVE_DIR" \
&& pass "T15 REMOVE_DIR" || fail "T15 REMOVE_DIR"

# === T16: TRUNCATE（截断文件） ===
# 通过两次 dyn-sandbox 共享宿主 ${SANDBOX_DATA}（无默认 Landlock 规则）
T=$((T+1)); log "Test $T: dynamic auth TRUNCATE"
dmesg_save
# Step 1: 创建文件（触发 MAKE_REG 放权）
run_dyn_test "T16-S1" "create file" \
    timeout 15 ${SANDBOX_RUN} --mount /usr:ro --mount /lib:ro --mount /lib64:ro \
    --mount ${SANDBOX_DATA}:rw --landlock /:execute \
    -- /usr/bin/touch ${SANDBOX_DATA}/sandbox_t16_file
rc1=$?
# Step 2: 截断文件（触发 TRUNCATE 放权）
run_dyn_test "T16-S2" "truncate file" \
    timeout 15 ${SANDBOX_RUN} --mount /usr:ro --mount /lib:ro --mount /lib64:ro \
    --mount ${SANDBOX_DATA}:rw --landlock /:execute \
    -- /usr/bin/truncate -s 0 ${SANDBOX_DATA}/sandbox_t16_file
rc2=$?
[ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ] && dmesg_has "BLOCKED.*TRUNCATE" \
&& pass "T16 TRUNCATE" || fail "T16 TRUNCATE"

# === T17: READ_FILE（读文件） ===
# 通过两次 dyn-sandbox 共享宿主 ${SANDBOX_DATA}（无默认 Landlock 规则）
T=$((T+1)); log "Test $T: dynamic auth READ_FILE"
dmesg_save
# Step 1: 创建文件（触发 MAKE_REG 放权）
run_dyn_test "T17-S1" "create file" \
    timeout 15 ${SANDBOX_RUN} --mount /usr:ro --mount /lib:ro --mount /lib64:ro \
    --mount ${SANDBOX_DATA}:rw --landlock /:execute \
    -- /usr/bin/touch ${SANDBOX_DATA}/sandbox_t17_file
rc1=$?
# Step 2: 读文件（触发 READ_FILE 放权）
run_dyn_test "T17-S2" "read file" \
    timeout 15 ${SANDBOX_RUN} --mount /usr:ro --mount /lib:ro --mount /lib64:ro \
    --mount ${SANDBOX_DATA}:rw --landlock /:execute \
    -- /usr/bin/cat ${SANDBOX_DATA}/sandbox_t17_file
rc2=$?
[ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ] && dmesg_has "BLOCKED.*READ_FILE" \
&& pass "T17 READ_FILE" || fail "T17 READ_FILE"

# === T18: READ_DIR（列出目录） ===
T=$((T+1)); log "Test $T: dynamic auth READ_DIR"
dmesg_save
run_dyn_test "T18" "READ_DIR (ls)" \
    timeout 15 ${SANDBOX_RUN} $DYN_ACT -- /usr/bin/sh -c 'ls /mnt'
rc=$?
[ "$rc" -eq 0 ] && dmesg_has "BLOCKED.*READ_DIR" \
&& pass "T18 READ_DIR" || fail "T18 READ_DIR"


# === T19: DENY all（空白名单，退出码非 0 + dmesg 验证） ===
T=$((T+1)); log "Test $T: DENY all"
dmesg_save
run_dyn_test_custom "T19" "DENY all (empty allow_list)" "" \
    timeout 15 ${SANDBOX_RUN} --mount /usr:ro --mount /lib:ro --mount /lib64:ro \
        --mount-tmpfs /mnt:16 --landlock '/:execute' \
        -- /usr/bin/touch /mnt/testdeny
rc=$?
[ "$rc" -ne 0 ] && dmesg_has "BLOCKED.*MAKE_REG" \
&& pass "T19 DENY all (exit=$rc, MAKE_REG blocked)" \
|| fail "T19 DENY all (rc=$rc)"

# === T20: ALLOW — 路径在白名单中，退出码 0 + 日志 ALLOW ===
T=$((T+1)); log "Test $T: ALLOW path (in allow list)"
log_save
run_dyn_test_custom "T20a" "ALLOW /mnt" "/mnt" \
    timeout 15 ${SANDBOX_RUN} --mount /usr:ro --mount /lib:ro --mount /lib64:ro \
        --mount-tmpfs /mnt:16 --landlock '/:execute' \
        -- /usr/bin/touch /mnt/allowed
rc=$?
[ "$rc" -eq 0 ] && log_has "dyn-sandbox: ALLOW" \
&& pass "T20a ALLOW path (exit=$rc, ALLOW in log)" \
|| fail "T20a ALLOW path (exit=$rc)"

# === T21: DENY — 路径不在白名单中，退出码非 0 + 日志 DENY ===
T=$((T+1)); log "Test $T: DENY path (not in allow list)"
log_save
run_dyn_test_custom "T21" "DENY /mnt (not allowed)" "/nonexistent" \
    timeout 15 ${SANDBOX_RUN} --mount /usr:ro --mount /lib:ro --mount /lib64:ro \
        --mount-tmpfs /mnt:16 --landlock '/:execute' \
        -- /usr/bin/touch /mnt/denied
rc=$?
[ "$rc" -ne 0 ] && log_has "dyn-sandbox: DENY" \
&& pass "T21 DENY path (exit=$rc, DENY in log)" \
|| fail "T21 DENY path (exit=$rc)"
# === T22: fork 子进程动态放权 ===
# bash -c 会 fork 出子进程（PID 不在 inst_list 中），验证 pid_ns 查找
T=$((T+1)); log "Test $T: fork child dynamic auth"
dmesg_save
# Step 1: 通过 bash -c fork+exec 创建文件
run_dyn_test "T22-S1" "fork+exec create file" \
    timeout 15 ${SANDBOX_RUN} --mount /usr:ro --mount /lib:ro --mount /lib64:ro \
    --mount ${SANDBOX_DATA}:rw --landlock /:execute \
    -- /usr/bin/bash -c "/usr/bin/touch ${SANDBOX_DATA}/sandbox_t22_file"
rc1=$?
# Step 2: 通过 bash -c fork+exec 截断文件
run_dyn_test "T22-S2" "fork+exec truncate file" \
    timeout 15 ${SANDBOX_RUN} --mount /usr:ro --mount /lib:ro --mount /lib64:ro \
    --mount ${SANDBOX_DATA}:rw --landlock /:execute \
    -- /usr/bin/bash -c "/usr/bin/truncate -s 0 ${SANDBOX_DATA}/sandbox_t22_file"
rc2=$?
[ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ] && dmesg_has "BLOCKED.*TRUNCATE" \
&& pass "T22 fork child TRUNCATE" || fail "T22 fork child TRUNCATE"

# === T23: 并发 Landlock 动态授权竞态 (#5) ===
# 10 进程并发 truncate 各自独立子目录文件 -> 并发 EACCES 全部独立触发、无串扰
T=$((T+1)); log "Test $T: 并发 10 进程 truncate 独立子目录"
run_concurrent_test "T23" 10 \
&& pass "T23 并发动态授权无丢失无串扰" || fail "T23 并发动态授权"

# === 日志结尾 ===
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
