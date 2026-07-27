#!/bin/bash
# test_landlock_switch.sh — landlock_enable 三态模块参数测试（仅加载时指定）
#
# 参数取值: -1 = 未指定(自动探测, 优雅降级); 0 = 关闭(纯网络); 1 = 开启(严格)
#
# 场景(本套件在支持 Landlock 的内核上运行, 默认 -1 自动探测即启用):
#   本套件只验证开关状态(参数值 + kretprobe 注册 + 加载成败), 不做功能断言;
#   动态放权的功能覆盖由 test_file.sh(T11-T22) 承担, test_all.sh 中先于本套件运行
#   T1     默认加载(未指定): 参数=-1
#   T2     默认加载: 13 条 kretprobe 注册 + enabled 日志
#   T3     sysfs 只读: 参数 0444, echo 0 被拒 (Permission denied), 参数仍 -1
#   T4     加载时指定 landlock_enable=0: 参数=0 且模块仍加载, 0 条 kretprobe
#   T5     加载时指定 landlock_enable=1: 参数=1, 13 条 kretprobe + enabled
#   T6     非法值(landlock_enable=2): 配置错误 → 模块加载失败(不再静默当 auto)
#   T7     恢复默认加载: 参数=-1, 模块恢复默认
#
# 可独立运行:  ./test_landlock_switch.sh
# 也可经 test_all.sh 复用; 结束后恢复默认加载, 不影响后续套件
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
LOGFILE="test_landlock_switch.log"
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
    echo "  Landlock load-time param Tests"
    echo "  start: $(date +%T.%N)"
    echo "=============================================="
    echo ""
} >> "$LOGFILE"

# landlock_param — 读取 sysfs 参数当前值 (-1/0/1)
landlock_param() {
    cat "/sys/module/dyn_sandbox/parameters/landlock_enable" 2>/dev/null
}

# 卸载模块 (停服务释放 /dev/dyn-sandbox, 清残留 proxy, rmmod), 清空 dmesg
module_unload_all() {
    sudo_run systemctl stop dyn-sandbox.service 2>/dev/null || true
    sudo_run pkill -9 dyn-sandbox-dns 2>/dev/null || true
    sudo_run rmmod dyn_sandbox 2>/dev/null || true
    sudo_run dmesg -c > /dev/null 2>&1 || true
}

# 加载默认 (未指定, landlock_enable=-1 自动探测)
module_load_default() {
    module_unload_all
    sudo_run modprobe dyn_sandbox
    sleep 1
}

# 加载并指定 landlock_enable=0
module_load_param0() {
    module_unload_all
    sudo_run modprobe dyn_sandbox landlock_enable=0
    sleep 1
}

# 加载并指定 landlock_enable=1
module_load_param1() {
    module_unload_all
    sudo_run modprobe dyn_sandbox landlock_enable=1
    sleep 1
}

# 加载并指定非法 landlock_enable=2 (配置错误 → 模块加载失败)
module_load_invalid() {
    module_unload_all
    sudo_run modprobe dyn_sandbox landlock_enable=2 2>/dev/null
    sleep 1
}

# 全新加载默认
module_load_default

T=0

# === T1: 默认加载(未指定) — 参数 = -1 ===
T=$((T+1)); log "Test $T: default (unspecified) landlock_enable=-1"
param=$(landlock_param)
[ "$param" = "-1" ] \
&& pass "default landlock_enable=-1" \
|| fail "default landlock_enable=$param (expected -1)"

# === T2: 默认加载 — 13 条 kretprobe 注册 + enabled 日志 ===
# module_load_default 已 dmesg -c, 当前 dmesg 即为本次加载日志
T=$((T+1)); log "Test $T: default kretprobes + enabled"
kprobe_count=$(sudo_run dmesg 2>/dev/null | grep -c 'dyn-sandbox: kretprobe on .* registered')
if [ "$kprobe_count" -eq 13 ] && sudo_run dmesg 2>/dev/null | grep -q "file runtime authorization enabled"; then
    pass "default kretprobes=13 + enabled log"
else
    fail "default kretprobes=$kprobe_count (expected 13) + enabled log"
fi

# === T3: sysfs 只读 (0444) — echo 0 被拒, 参数仍 -1 ===
T=$((T+1)); log "Test $T: sysfs param read-only (0444)"
if echo 0 | sudo_run tee /sys/module/dyn_sandbox/parameters/landlock_enable 2>/dev/null; then
    fail "sysfs read-only: echo 0 unexpectedly succeeded (param=$(landlock_param))"
else
    param=$(landlock_param)
    [ "$param" = "-1" ] \
    && pass "sysfs read-only (echo denied, param still -1)" \
    || fail "sysfs read-only (echo denied but param=$param)"
fi

# === T4: 加载时指定 landlock_enable=0 — 参数=0, 模块仍加载, 0 kretprobe ===
T=$((T+1)); log "Test $T: load with landlock_enable=0"
module_load_param0
param=$(landlock_param)
kprobe_count=$(sudo_run dmesg 2>/dev/null | grep -c 'dyn-sandbox: kretprobe on .* registered')
if [ "$param" = "0" ] && [ -d /sys/module/dyn_sandbox ] && [ "$kprobe_count" -eq 0 ] \
   && ! sudo_run dmesg 2>/dev/null | grep -q "file runtime authorization enabled"; then
    pass "load param=0 (param=0, module alive, ${kprobe_count} kretprobes)"
else
    fail "load param=0 (param=$param, alive=$([ -d /sys/module/dyn_sandbox ] && echo yes || echo no), kprobes=$kprobe_count)"
fi

# === T5: 加载时指定 landlock_enable=1 — 参数=1, 13 条 kretprobe + enabled ===
T=$((T+1)); log "Test $T: load with landlock_enable=1 (strict)"
module_load_param1
param=$(landlock_param)
kprobe_count=$(sudo_run dmesg 2>/dev/null | grep -c 'dyn-sandbox: kretprobe on .* registered')
if [ "$param" = "1" ] && [ "$kprobe_count" -eq 13 ] \
   && sudo_run dmesg 2>/dev/null | grep -q "file runtime authorization enabled"; then
    pass "load param=1 (param=1, module alive, ${kprobe_count} kretprobes + enabled)"
else
    fail "load param=1 (param=$param, alive=$([ -d /sys/module/dyn_sandbox ] && echo yes || echo no), kprobes=$kprobe_count)"
fi

# === T6: 非法 landlock_enable 值 — 模块加载失败, 不再静默当 auto ===
T=$((T+1)); log "Test $T: invalid landlock_enable value fails load"
module_load_invalid
if [ ! -d /sys/module/dyn_sandbox ] \
   && sudo_run dmesg 2>/dev/null | grep -q "invalid landlock_enable=2"; then
    pass "invalid landlock_enable=2 (module not loaded, dmesg diagnostic)"
else
    fail "invalid landlock_enable=2 (module loaded=$([ -d /sys/module/dyn_sandbox ] && echo yes || echo no))"
fi

# === T7: 恢复默认加载 — 参数=-1, 模块恢复默认 (供后续套件使用) ===
T=$((T+1)); log "Test $T: restore default load"
module_load_default
param=$(landlock_param)
kprobe_count=$(sudo_run dmesg 2>/dev/null | grep -c 'dyn-sandbox: kretprobe on .* registered')
if [ "$param" = "-1" ] && [ -d /sys/module/dyn_sandbox ] && [ "$kprobe_count" -eq 13 ]; then
    pass "restore default (param=-1, module alive, ${kprobe_count} kretprobes)"
else
    fail "restore default (param=$param, alive=$([ -d /sys/module/dyn_sandbox ] && echo yes || echo no), kprobes=$kprobe_count)"
fi

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
