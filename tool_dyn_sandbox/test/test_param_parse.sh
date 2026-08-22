#!/bin/bash
# test_param_parse.sh — 参数解析本地测试（无需 VM）
#
# 所有用例通过 --dump-config / -D 在本地验证，不启动沙箱。
# G 组通过 CLI 和 Policy 两条路径的 -D 输出 diff 验证等价性。
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
SANDBOX_RUN="$DIR/../dyn-sandbox/dyn-sandbox"

PASS=0; FAIL=0; TOTAL=0
TMPDIR="/tmp/test_param_parse_$$"
mkdir -p "$TMPDIR"

cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT

# ------------------------------------------------------------------
#  Helpers
# ------------------------------------------------------------------

# Grep-based: run command, grep output for pattern, check exit code
# Usage: test_case NAME CMD GREP_PATTERN [EXPECTED_EXIT]
test_case() {
	local name="$1" cmd="$2" pattern="$3" exp_rc="${4:-0}"
	((TOTAL++))
	local out rc
	out=$(eval "$cmd" 2>&1); rc=$?
	if [ "$rc" -ne "$exp_rc" ]; then
		echo "FAIL: $name (exit $rc, expected $exp_rc)"
		echo "  cmd: $cmd" | head -3
		((FAIL++))
		return
	fi
	if echo "$out" | grep -q "$pattern"; then
		echo "PASS: $name"
		((PASS++))
	else
		echo "FAIL: $name (pattern not found: $pattern)"
		echo "  cmd: $cmd" | head -3
		echo "  out: $(echo "$out" | head -5 | tr '\n' ';')"
		((FAIL++))
	fi
}

# Exit-code-only check
test_exit() {
	local name="$1" cmd="$2" exp_rc="$3"
	((TOTAL++))
	local rc
	eval "$cmd" >/dev/null 2>&1; rc=$?
	if [ "$rc" -eq "$exp_rc" ]; then
		echo "PASS: $name"
		((PASS++))
	else
		echo "FAIL: $name (exit $rc, expected $exp_rc)"
		echo "  cmd: $cmd"
		((FAIL++))
	fi
}

# CLI vs Policy diff: build two -D outputs, strip header, diff
# Usage: test_diff NAME CLI_ARGS YAML_FILE
test_diff() {
	local name="$1" cli_args="$2" yaml="$3"
	((TOTAL++))
	local cli_out pol_out
	cli_out=$($SANDBOX_RUN $cli_args -D 2>&1 | grep -v '^===')
	pol_out=$($SANDBOX_RUN --dump-config --policy "$yaml" 2>&1 | grep -v '^===')
	if diff -q <(echo "$cli_out") <(echo "$pol_out") >/dev/null 2>&1; then
		echo "PASS: $name"
		((PASS++))
	else
		echo "FAIL: $name (CLI vs Policy mismatch)"
		diff <(echo "$cli_out") <(echo "$pol_out") | head -20
		((FAIL++))
	fi
}

# Create temp YAML
put_yaml() { echo "$2" > "$TMPDIR/$1"; }

# ------------------------------------------------------------------
#  A. 冒烟测试
# ------------------------------------------------------------------
echo "=== A. 冒烟测试 ==="

test_case "A2 -D 空配置" "$SANDBOX_RUN -D" "workdir: /"

# ------------------------------------------------------------------
#  B. CLI 基础解析
# ------------------------------------------------------------------
echo "=== B. CLI 基础解析 ==="

B_D="$SANDBOX_RUN"

test_case "B1 mount bind 默认 ro" "$B_D --mount /usr -D" 'rw=0'
test_case "B2 mount bind rw"      "$B_D --mount /data:rw -D" 'rw=1'
test_case "B3 mount bind 多个"    "$B_D --mount /a:ro --mount /b:rw -D" 'mounts (2)'
test_case "B4 mount-tmpfs"        "$B_D --mount-tmpfs /data:128 -D" 'size=128'
test_case "B5 mount-tmpfs /tmp"   "$B_D --mount-tmpfs /tmp:512 -D" 'tmpfs_size_mb: 512'
test_case "B6 mount-tmpfs /tmp 默认" "$B_D --mount-tmpfs /tmp -D" 'tmpfs_size_mb: 256'
test_case "B7 landlock 含权限"    "$B_D --landlock '/usr:read+execute' -D" 'perms=read+execute'
test_case "B8 landlock 无权限"    "$B_D --landlock '/usr' -D" 'landlock, nolandlock 0, rules (1)'
test_case "B9 domain 单值"       "$B_D --domain example.com -D" 'example.com'
test_case "B10 domain 多值"      "$B_D --domain a.com,b.com,c.com -D" 'domains (3)'
test_case "B11 cidr 单值"        "$B_D --cidr 10.0.0.0/8 -D" '10.0.0.0/8'
test_case "B12 cidr 多值"        "$B_D --cidr 10.0.0.0/8,192.168.0.0/16 -D" 'cidrs (2)'
test_case "B13 seccomp profile"  "$B_D --seccomp default -D" 'profile: default'
test_case "B14 seccomp syscalls" "$B_D --seccomp-syscalls read,write,openat -D" 'syscalls: read,write,openat'
test_case "B15 -c 工作目录"      "$B_D -c /tmp -D" 'workdir: /tmp'
test_case "B16 --tmpfs-size"     "$B_D --tmpfs-size 512 -D" 'tmpfs_size_mb: 512'

# ------------------------------------------------------------------
#  C. CLI 组合场景
# ------------------------------------------------------------------
echo "=== C. CLI 组合场景 ==="

test_case "C1 mount-tmpfs + tmpfs-size" \
	"$B_D --mount-tmpfs /tmp --tmpfs-size 512 -D" 'tmpfs_size_mb: 512'
test_case "C2 mount-tmpfs /tmp + /data" \
	"$B_D --mount-tmpfs /tmp:128 --mount-tmpfs /data:64 -D" 'mounts (1)'
test_case "C3 domain + cidr → network_mode" \
	"$B_D --domain a.com --cidr 10.0.0.0/8 -D" 'network_mode: filter'
test_case "C4 seccomp 互斥错误" \
	"$B_D --seccomp script --seccomp-syscalls read -D" \
	'are mutually exclusive' 1
test_case "C5 全选所有选项" \
	"$B_D --mount /usr:ro --mount-tmpfs /data:64 --landlock '/usr:read' --seccomp default --domain a.com --cidr 10.0.0.0/8 -c /tmp --tmpfs-size 256 -D" \
	'network_mode: filter'
test_case "C6 -D 放最后（无需 command）" \
	"$B_D --mount /usr --domain a.com -D" 'mounts (1)'

# ------------------------------------------------------------------
#  D. CLI 错误场景
# ------------------------------------------------------------------
echo "=== D. CLI 错误场景 ==="

test_case "D1 无命令" "$B_D --mount /usr" 'no command specified' 1
# D2 就是 A2（-D 豁免），不再重复
test_case "D3 未知选项" "$B_D --hello" 'unrecognized option' 1

# D4-D7 用函数内建数组构造超限参数（test_case 的 eval 不支持数组传参）
test_overflow() {
	local name="$1" pat="$2" exp_rc="$3"; shift 3
	((TOTAL++))
	local out rc
	out=$("$@" 2>&1); rc=$?
	if [ "$rc" -ne "$exp_rc" ]; then
		echo "FAIL: $name (exit $rc, expected $exp_rc)"; ((FAIL++)); return
	fi
	if echo "$out" | grep -q "$pat"; then
		echo "PASS: $name"; ((PASS++))
	else
		echo "FAIL: $name (pattern not found: $pat)"; echo "  out: $out" | head -3; ((FAIL++))
	fi
}

D4_ARGS=()
for i in $(seq 1 33); do D4_ARGS+=("--mount" "/x:ro"); done
test_overflow "D4 mount 超限" 'too many --mount entries' 1 "$B_D" "${D4_ARGS[@]}"

D5_ARGS=()
for i in $(seq 1 65); do D5_ARGS+=("--landlock" "/x"); done
test_overflow "D5 landlock 超限" 'too many --landlock entries' 1 "$B_D" "${D5_ARGS[@]}"

D6_ARGS=()
for i in $(seq 1 17); do D6_ARGS+=("--domain" "x$i.com"); done
test_overflow "D6 domain 超限" 'too many --domain entries' 1 "$B_D" "${D6_ARGS[@]}"

D7_ARGS=()
for i in $(seq 1 17); do D7_ARGS+=("--cidr" "10.0.0.$i/8"); done
test_overflow "D7 cidr 超限" 'too many --cidr entries' 1 "$B_D" "${D7_ARGS[@]}"

test_case "D8 CIDR 无前缀" "$B_D --cidr 10.0.0.0 -D" 'need /prefix' 1
test_case "D9 CIDR 无效前缀33" "$B_D --cidr 10.0.0.0/33 -D" 'invalid prefix' 1
test_case "D10 CIDR 前缀负数" "$B_D --cidr '10.0.0.0/-1' -D" 'invalid prefix' 1
test_case "D11 seccomp 互斥(profile先)" \
	"$B_D --seccomp default --seccomp-syscalls read" 'mutually exclusive' 1
test_case "D12 seccomp 互斥(syscalls先)" \
	"$B_D --seccomp-syscalls read --seccomp default" 'mutually exclusive' 1

test_case "D13 mount 无效后缀" "$B_D --mount /x:invalid -D" "invalid mount option" 1
test_case "D14 mount-tmpfs 负数" "$B_D --mount-tmpfs /x:-1" "invalid tmpfs size" 1
test_case "D15 domain 空字符串" "$B_D --domain '' -D" "empty domain" 1
test_case "D16 seccomp 未知profile" "$B_D --seccomp unknown -- echo hello" "unknown seccomp profile" 1
test_case "D17 seccomp-syscalls 空串" "$B_D --seccomp-syscalls '' -D" "cannot be empty" 1

# ------------------------------------------------------------------
#  E. 互斥检查
# ------------------------------------------------------------------
echo "=== E. 互斥检查 ==="

# 需要一个存在但不合法的 YAML 文件来触发 policy 解析，但互斥检查在解析之前
# 所以文件不存在也可以 — 互斥先于 parse_policy_file 返回
FAKE="/nonexist/policy.yaml"

test_case "E1 mount → policy" "$B_D --mount /usr --policy $FAKE -- echo" 'mutually exclusive' 1
# 反向互斥：对于 policy → mount，用 -D 豁免，所以需要用实际存在的文件来验证
# 但反过来 mount 在 policy 之后会被前向检查拦截
put_yaml e2.yaml "seccomp: {profile: default}"
test_case "E2 policy → mount" "$B_D --policy $TMPDIR/e2.yaml --mount /usr -- echo" 'mutually exclusive' 1
test_case "E3 domain → policy" "$B_D --domain a.com --policy $FAKE -- echo" 'mutually exclusive' 1
test_case "E4 seccomp → policy" "$B_D --seccomp default --policy $FAKE -- echo" 'mutually exclusive' 1
test_case "E5 cidr → policy" "$B_D --cidr 10.0.0.0/8 --policy $FAKE -- echo" 'mutually exclusive' 1
test_case "E6 -c → policy" "$B_D -c /tmp --policy $FAKE -- echo" 'mutually exclusive' 1

# -D 豁免：需要真实 YAML 文件才能通过 parse_policy_file
put_yaml e7.yaml "seccomp: {profile: default}"
test_case "E7 -D → policy（豁免）" "$B_D -D --policy $TMPDIR/e7.yaml" 'profile: default'
test_case "E8 policy → -D（豁免）" "$B_D --policy $TMPDIR/e7.yaml -D" 'profile: default'

# ------------------------------------------------------------------
#  F. YAML Policy 解析
# ------------------------------------------------------------------
echo "=== F. YAML Policy 解析 ==="

put_yaml f1.yaml "mount:
  - {type: bind, src: /usr}"
test_case "F1 mount bind ro" "$B_D -D --policy $TMPDIR/f1.yaml" 'rw=0'

put_yaml f2.yaml "mount:
  - {type: bind, src: /data, readonly: false}"
test_case "F2 mount bind rw" "$B_D -D --policy $TMPDIR/f2.yaml" 'rw=1'

put_yaml f3.yaml "mount:
  - {type: tmpfs, dest: /data, size: 128}"
test_case "F3 mount tmpfs" "$B_D -D --policy $TMPDIR/f3.yaml" 'size=128'

put_yaml f4.yaml "landlock:
  - {path: /usr, access: [read, execute]}"
test_case "F4 landlock access 列表" "$B_D -D --policy $TMPDIR/f4.yaml" 'perms=read+execute'

put_yaml f5.yaml "landlock:
  - {path: /usr}"
test_case "F5 landlock 无 access" "$B_D -D --policy $TMPDIR/f5.yaml" 'landlock, nolandlock 0, rules (1)'

put_yaml f6.yaml "network:
  mode: filter
  domains: [a.com]
  cidrs: [10.0.0.0/8]"
test_case "F6 network" "$B_D -D --policy $TMPDIR/f6.yaml" 'network_mode: filter'

put_yaml f9.yaml "network:
  mode: filter
  domains: [a.com]"
test_case "F9 network mode: filter" "$B_D -D --policy $TMPDIR/f9.yaml" 'network_mode: filter'

put_yaml f10.yaml "network:
  mode: isolate"
test_case "F10 network mode: isolate" "$B_D -D --policy $TMPDIR/f10.yaml" 'network_mode: isolate'

put_yaml f11.yaml "network:
  mode: share"
test_case "F11 network mode: share" "$B_D -D --policy $TMPDIR/f11.yaml" 'network_mode: share'

put_yaml f12.yaml "network:
  mode: bogus"
test_case "F12 network mode 非法" "$B_D -D --policy $TMPDIR/f12.yaml" 'invalid network mode' 1

put_yaml f13.yaml "network:
  mode: isolate
  domains: [a.com]"
test_case "F13 isolate + domains 互斥" "$B_D -D --policy $TMPDIR/f13.yaml" 'mutually exclusive with domains/cidrs' 1

put_yaml f14.yaml "network:
  mode: share
  cidrs: [10.0.0.0/8]"
test_case "F14 share + cidrs 互斥" "$B_D -D --policy $TMPDIR/f14.yaml" 'mutually exclusive with domains/cidrs' 1

put_yaml f15.yaml "network:
  domains: [a.com]"
test_case "F15 无 mode + domains → filter" "$B_D -D --policy $TMPDIR/f15.yaml" 'network_mode: filter'

put_yaml f16.yaml "network:
  cidrs: [10.0.0.0/8]"
test_case "F16 无 mode + cidrs → filter" "$B_D -D --policy $TMPDIR/f16.yaml" 'network_mode: filter'

put_yaml f17.yaml "seccomp:
  profile: default"
test_case "F17 无 network 段 → isolate" "$B_D -D --policy $TMPDIR/f17.yaml" 'network_mode: isolate'

put_yaml f7.yaml "seccomp:
  profile: default"
test_case "F7 seccomp profile" "$B_D -D --policy $TMPDIR/f7.yaml" 'profile: default'

put_yaml f8.yaml "seccomp:
  syscalls: [read, write, openat]"
test_case "F8 seccomp syscalls" "$B_D -D --policy $TMPDIR/f8.yaml" 'syscalls: read,write,openat'

# ------------------------------------------------------------------
#  G. CLI vs Policy 等价性对比
# ------------------------------------------------------------------
echo "=== G. CLI vs Policy 等价性对比 ==="

put_yaml g1.yaml "mount:
  - {type: bind, src: /usr}"
test_diff "G1 mount bind" "--mount /usr:ro" "$TMPDIR/g1.yaml"


put_yaml g8.yaml "mount:
  - {type: tmpfs, dest: /data, size: 128}"
test_case "G8 mount tmpfs" "$B_D -D --policy $TMPDIR/g8.yaml" "type=tmpfs"

put_yaml g3.yaml "landlock:
  - {path: /usr, access: [read, execute]}"
test_diff "G3 landlock" "--landlock /usr:read+execute" "$TMPDIR/g3.yaml"

put_yaml g4.yaml "network:
  domains: [a.com, b.com]"
test_diff "G4 domain 多值" "--domain a.com,b.com" "$TMPDIR/g4.yaml"

put_yaml g5.yaml "network:
  cidrs: [10.0.0.0/8, 192.168.0.0/16]"
test_diff "G5 cidr 多值" "--cidr 10.0.0.0/8,192.168.0.0/16" "$TMPDIR/g5.yaml"

put_yaml g6.yaml "seccomp:
  profile: default"
test_diff "G6 seccomp profile" "--seccomp default" "$TMPDIR/g6.yaml"

put_yaml g7.yaml "seccomp:
  syscalls: [read, write]"
test_diff "G7 seccomp syscalls" "--seccomp-syscalls read,write" "$TMPDIR/g7.yaml"

put_yaml g9.yaml "network:
  mode: share"
test_diff "G9 share-net" "--share-net" "$TMPDIR/g9.yaml"

# ------------------------------------------------------------------
#  H. YAML Policy 错误场景
# ------------------------------------------------------------------
echo "=== H. YAML Policy 错误场景 ==="

test_exit "H1 文件不存在" "$B_D --policy /nonexist_xyz.yaml -- echo" 1

put_yaml h2.yaml "mount: [broken: yaml: trailing"
test_case "H2 YAML 语法错误" "$B_D --policy $TMPDIR/h2.yaml -- echo" 'parse error' 1

put_yaml h3.yaml "network:
  cidrs: [10.0.0.0]"
test_case "H3 CIDR 无前缀" "$B_D --policy $TMPDIR/h3.yaml -- echo" 'invalid CIDR' 1

H4_DOMAINS=""
for i in $(seq 1 17); do
	[ -n "$H4_DOMAINS" ] && H4_DOMAINS+=", "
	H4_DOMAINS+="\"x$i.com\""
done
put_yaml h4.yaml "network:
  domains: [$H4_DOMAINS]"
test_case "H4 domain 超限" "$B_D --policy $TMPDIR/h4.yaml -- echo" 'too many domains' 1

H5_CIDRS=""
for i in $(seq 1 17); do
	[ -n "$H5_CIDRS" ] && H5_CIDRS+=", "
	H5_CIDRS+="\"10.0.0.$i/8\""
done
put_yaml h5.yaml "network:
  cidrs: [$H5_CIDRS]"
test_case "H5 cidr 超限" "$B_D --policy $TMPDIR/h5.yaml -- echo" 'too many CIDRs' 1

H6_MOUNTS=""
for i in $(seq 1 33); do
	[ -n "$H6_MOUNTS" ] && H6_MOUNTS+=$'\n'
	H6_MOUNTS+="  - {type: bind, src: /m$i}"
done
put_yaml h6.yaml "mount:
$H6_MOUNTS"
test_case "H6 mount 超限" "$B_D --policy $TMPDIR/h6.yaml -- echo" 'too many mounts' 1

# ------------------------------------------------------------------
#  I. 特殊边界场景
# ------------------------------------------------------------------
echo "=== I. 特殊边界场景 ==="

# I1: domain 127 字符 + .com（共 131 → 截断到 127）
LONG_DOMAIN="$(python3 -c "print('a'*127 + '.com')" 2>/dev/null || echo "a...long.com")"
test_case "I1 domain 长字符串" "$B_D --domain '$LONG_DOMAIN' -D" 'domains (1)'

# I2: 同名 mount 重复，两条都加入（当前无去重）
test_case "I3 同名 mount 重复" \
	"$B_D --mount /usr:ro --mount /usr:rw -D" 'mounts (2)'

# I4: 多个 -D
test_case "I4 多个-D" "$B_D -D -D -D" 'workdir: /'

# ------------------------------------------------------------------
#  汇总
# ------------------------------------------------------------------
echo ""
echo "=========================================="
echo "  参数解析测试完成"
echo "  总计: $TOTAL  通过: $PASS  失败: $FAIL"
echo "=========================================="

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
