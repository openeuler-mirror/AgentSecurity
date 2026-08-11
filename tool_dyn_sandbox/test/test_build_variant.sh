#!/bin/bash
# test_build_variant.sh — CONFIG_LANDLOCK_ENABLE 构建变体编译测试
#
# 最轻量版: 只验证两个构建变体都能编译通过, 且 driver 的 landlock_enable
# 参数按宏存在与否正确注册 (modinfo -p)。这是该特性的真实回归风险点——
# param_parse.c / policy_parser.c / sandbox_file.c 里 8 处 #ifdef/#ifndef
# 一旦配平错误, LANDLOCK_ENABLE=0 变体将编译失败; 而顶层 make 默认恰为
# no-Landlock 构建, 需要有人真编过才能发现。
#
# 行为差异 (CLI 拒绝 --landlock / policy 忽略 landlock 段 / 默认 no_landlock=1 /
# driver 参数缺失) 在移植时已一次性验证并写入 docs/, 不作常驻断言。
#
# 纯本地运行 (无需 sudo、不加载模块、不触碰已部署的 /lib/modules 安装副本)。
# 构建会临时改写源码树产物, 脚本结束 (含失败路径) 通过 trap 恢复完整构建。
# 用法: bash test/test_build_variant.sh
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
BIN="$ROOT/dyn-sandbox/dyn-sandbox"
KO="$ROOT/driver/dyn_sandbox.ko"

PASS=0; FAIL=0

restore_full_build() {
	echo "--- 恢复完整构建 (make clean && make LANDLOCK_ENABLE=1) ---"
	( cd "$ROOT" && make clean >/dev/null 2>&1 && make LANDLOCK_ENABLE=1 >/dev/null 2>&1 ) \
		&& echo "恢复完成" || echo "!! 恢复失败, 请手动 make clean && make LANDLOCK_ENABLE=1"
}
trap restore_full_build EXIT

# check NAME PASSED — PASSED=1 通过, 0 失败
check() {
	local name="$1" passed="$2"
	if [ "$passed" -eq 1 ]; then echo "PASS: $name"; ((PASS++));
	else echo "FAIL: $name"; ((FAIL++)); fi
}

# ------------------------------------------------------------------
#  Part A — 无 Landlock 构建 (LANDLOCK_ENABLE=0): 编译 + 参数未注册
# ------------------------------------------------------------------
echo "=== 构建 LANDLOCK_ENABLE=0 ==="
passed=0
( cd "$ROOT" && make clean >/dev/null 2>&1 && make LANDLOCK_ENABLE=0 kmod user >/dev/null 2>&1 ) \
	&& [ -x "$BIN" ] && [ -f "$KO" ] && passed=1
check "A1 无 Landlock 构建编译通过 (dyn-sandbox + dyn_sandbox.ko)" "$passed"

passed=0
modinfo -p "$KO" 2>/dev/null | grep -q "landlock_enable" || passed=1
check "A2 driver 未注册 landlock_enable 参数" "$passed"

# ------------------------------------------------------------------
#  Part B — 完整构建 (LANDLOCK_ENABLE=1): 编译 + 参数已注册
# ------------------------------------------------------------------
echo "=== 构建 LANDLOCK_ENABLE=1 ==="
passed=0
( cd "$ROOT" && make clean >/dev/null 2>&1 && make LANDLOCK_ENABLE=1 kmod user >/dev/null 2>&1 ) \
	&& [ -x "$BIN" ] && [ -f "$KO" ] && passed=1
check "B1 完整构建编译通过 (dyn-sandbox + dyn_sandbox.ko)" "$passed"

passed=0
modinfo -p "$KO" 2>/dev/null | grep -q "landlock_enable" && passed=1
check "B2 driver 注册 landlock_enable 参数" "$passed"

echo
echo "=========================================="
echo "  构建变体编译测试完成  通过: $PASS  失败: $FAIL"
echo "=========================================="
[ "$FAIL" -eq 0 ]
