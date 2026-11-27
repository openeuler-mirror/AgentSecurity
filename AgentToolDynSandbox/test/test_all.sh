#!/bin/bash
# test_all.sh — 沙箱全量集成测试 (文件隔离 + 网络 + seccomp)
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
KO_DIR="$DIR/../dist"
PW="111111"
sudo_run() { echo "$PW" | sudo -S "$@"; }

source "$DIR/test_common.sh"

PASS=0; FAIL=0

test_setup
export _SANDBOX_SYSTEMD

echo "=========================================="
echo "  沙箱全量集成测试"
echo "=========================================="
echo ""

# ── 参数解析测试（本地，无需模块）──
echo "=== 参数解析测试 ==="
"$DIR/test_param_parse.sh"
RC0=$?
[ "$RC0" -eq 0 ] && PASS=$((PASS+1)) || FAIL=$((FAIL+1))
echo ""

# ── 文件隔离测试 ──
echo "=== 文件隔离测试 ==="
"$DIR/test_file.sh"
RC1=$?
[ "$RC1" -eq 0 ] && PASS=$((PASS+1)) || FAIL=$((FAIL+1))
echo ""

# ── 挂载测试 ──
echo "=== 挂载测试 ==="
"$DIR/test_mount.sh"
RC_DEV=$?
[ "$RC_DEV" -eq 0 ] && PASS=$((PASS+1)) || FAIL=$((FAIL+1))
echo ""

# ── 网络测试 ──
echo "=== 网络测试 ==="
"$DIR/test_net.sh"
RC2=$?
[ "$RC2" -eq 0 ] && PASS=$((PASS+1)) || FAIL=$((FAIL+1))
echo ""

# ── seccomp 测试 ──
echo "=== Seccomp 测试 ==="
"$DIR/test_seccomp.sh"
RC3=$?
[ "$RC3" -eq 0 ] && PASS=$((PASS+1)) || FAIL=$((FAIL+1))
echo ""

# ── landlock 开关测试 ──
echo "=== Landlock 开关测试 ==="
"$DIR/test_landlock_switch.sh"
RC4=$?
[ "$RC4" -eq 0 ] && PASS=$((PASS+1)) || FAIL=$((FAIL+1))
echo ""

# ── 汇总 ──
echo "=========================================="
echo "  Sub-suite: $PASS passed, $FAIL failed"
echo "=========================================="

test_cleanup

[ "$FAIL" -gt 0 ] && exit 1 || exit 0
