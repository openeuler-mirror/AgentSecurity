#!/bin/bash
# test_param_parse.sh — 参数解析本地测试（无需 VM）
#
# 所有用例通过 --dump-config / -D 在本地验证，不启动沙箱。
# G 组通过 CLI 和 Policy 两条路径的 -D 输出 diff 验证等价性。
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
SANDBOX_RUN="$DIR/../dist/dyn-sandbox"

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
test_case "B17 mount-tmpfs :0 默认(用户挂载)" "$B_D --mount-tmpfs /data:0 -D" 'dest=/data rw=0 size=0'
test_case "B18 mount-tmpfs /tmp:0 默认" "$B_D --mount-tmpfs /tmp:0 -D" 'tmpfs_size_mb: 256'
test_case "B19 mount-tmpfs 逗号多值" "$B_D --mount-tmpfs '/d1:100,/d2:200' -D" 'mounts (2)'
test_case "B19b mount-tmpfs 多值第二条解析" "$B_D --mount-tmpfs '/d1:100,/d2:200' -D" 'dest=/d2 rw=0 size=200'
test_case "B20 mount bind 逗号多值" "$B_D --mount '/a:ro,/b:rw' -D" 'mounts (2)'
test_case "B20b mount bind 多值 rw 生效" "$B_D --mount '/a:ro,/b:rw' -D" 'dest=/b rw=1'
# B21-B26: 空段 (前导 / 中间连续 / 尾逗号) 一律拒绝 — 逗号必须严格分隔非空挂载
test_case "B21 tmpfs 连续逗号空段拒绝" "$B_D --mount-tmpfs '/d1:100,,/d2:200' -D" 'empty --mount-tmpfs entry' 1
test_case "B22 tmpfs 尾逗号空段拒绝" "$B_D --mount-tmpfs '/d1:100,/d2:200,' -D" 'empty --mount-tmpfs entry' 1
test_case "B23 mount 逗号含 /tmp 段(改大小+普通段混用)" "$B_D --mount-tmpfs '/tmp:64,/data:128' -D" 'tmpfs_size_mb: 64'
test_case "B24 tmpfs 前导逗号空段拒绝" "$B_D --mount-tmpfs ',/d1:100,/d2:200' -D" 'empty --mount-tmpfs entry' 1
test_case "B25 bind 前导逗号空段拒绝" "$B_D --mount ',/a:ro,/b:rw' -D" 'empty --mount entry' 1
test_case "B26 bind 尾逗号空段拒绝" "$B_D --mount '/a:ro,/b:rw,' -D" 'empty --mount entry' 1
test_case "B26b bind 连续逗号空段拒绝" "$B_D --mount '/a:ro,,/b:rw' -D" 'empty --mount entry' 1
test_case "B27 tmpfs 中段非法整串拒绝" "$B_D --mount-tmpfs '/d1:100,/x:abc,/d2:200' -D" 'invalid tmpfs size' 1
test_case "B28 bind 中段非法整串拒绝" "$B_D --mount '/a:ro,/x:bad,/b:rw' -D" 'invalid mount option' 1
# B29-B32: domain/cidr 空段与 --mount 同规 — 空段(前导/连续/尾逗号)一律拒绝,
#          不再像旧版同 strtok 那样静默跳过 (对齐 --mount/--mount-tmpfs 多值形式)
test_case "B29 domain 前导逗号空段拒绝" "$B_D --domain ',a.com,b.com' -D" 'empty --domain entry' 1
test_case "B30 domain 尾逗号空段拒绝"   "$B_D --domain 'a.com,b.com,' -D" 'empty --domain entry' 1
test_case "B31 cidr 连续逗号空段拒绝"   "$B_D --cidr '10.0.0.0/8,,192.168.0.0/16' -D" 'empty --cidr entry' 1
test_case "B32 cidr 前导逗号空段拒绝"   "$B_D --cidr ',10.0.0.0/8' -D" 'empty --cidr entry' 1
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

# C1/C1b: --mount-tmpfs /tmp 与 --tmpfs-size 是同一 /tmp 大小旋钮, 任一重复/混用都冲突 (S4)
test_case "C1 /tmp 两拼写混用冲突" \
	"$B_D --mount-tmpfs /tmp --tmpfs-size 512 -D" 'may be set only once' 1
test_case "C1b /tmp 两拼写混用(反向顺序)冲突" \
	"$B_D --tmpfs-size 512 --mount-tmpfs /tmp:128 -D" 'may be set only once' 1
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

# C7-C10: S4 — /tmp 大小旋钮 at-most-once: 任一拼写重复/混用都报冲突; 0 物化默认256
test_case "C7 重复 --tmpfs-size 冲突" "$B_D --tmpfs-size 64 --tmpfs-size 128 -D" 'may be set only once' 1
test_case "C8 重复 --tmpfs-size 同值也冲突" "$B_D --tmpfs-size 128 --tmpfs-size 128 -D" 'may be set only once' 1
test_case "C9 --tmpfs-size 0 物化默认256" "$B_D --tmpfs-size 0 -D" 'tmpfs_size_mb: 256' 0
test_case "C10 重复含 0 也冲突" "$B_D --tmpfs-size 128 --tmpfs-size 0 -D" 'may be set only once' 1

# C11-C17: S5/S6/S7 — 标量旋钮重复冲突 (-c / --seccomp); --seccomp-syscalls 重复=追加 union
test_case "C11 S5 重复 -c 冲突" "$B_D -c /tmp -c /usr -D" 'conflicting -c workdir (/tmp): -c may be set only once' 1
# C12: 默认 "/" 与显式 "-c /" 撞车边界 — 单次 -c / 必须放行 (重复检测靠 workdir_set 标记而非内容)
test_case "C12 S5 单次 -c / 放行" "$B_D -c / -D" 'workdir: /' 0
test_case "C13 S6 重复 --seccomp 冲突" "$B_D --seccomp default --seccomp script -D" 'conflicting --seccomp profile (default): --seccomp may be set only once' 1
test_case "C14 S6 同值重复也冲突" "$B_D --seccomp script --seccomp script -D" 'conflicting --seccomp profile (script): --seccomp may be set only once' 1
test_case "C15 S7 重复 syscalls 追加" "$B_D --seccomp-syscalls read,write --seccomp-syscalls openat,close -D" 'syscalls: read,write,openat,close' 0
test_case "C16 S7 三段追加" "$B_D --seccomp-syscalls read --seccomp-syscalls exit_group --seccomp-syscalls openat -D" 'syscalls: read,exit_group,openat' 0
test_case "C17 S7 累计超 511 拒绝" "$B_D --seccomp-syscalls read,write,openat --seccomp-syscalls $(printf 'a%.0s' {1..510}) -D" 'too long' 1
test_case "C17b S7 单段超 511 拒绝(旧 strncpy 截断 bug)" "$B_D --seccomp-syscalls $(printf 'a%.0s' {1..520}) -D" 'too long' 1

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
# D11: 前缀非数字曾被 atoi 静默当作 0 -> /0 放行全部流量 (fail-open), 必须拒绝
test_case "D11 CIDR 前缀非数字" "$B_D --cidr '10.0.0.0/abc' -D" 'invalid prefix' 1
# D12: 前缀0 (/0) 会让白名单变成 0.0.0.0/0 -> 放行全部流量, 必须拒绝
test_case "D12 CIDR 前缀0" "$B_D --cidr '10.0.0.0/0' -D" 'invalid prefix' 1
# D12b-D12e: 地址段 inet_pton 严格校验 — 旧 inet_addr 对畸形输入静默返回
# INADDR_NONE(255.255.255.255) 落入白名单 fail-open; 且合法 255.255.255.255
# 与错误哨兵同值无法区分 — 现畸形显式拒绝, 真 255.255.255.255 照常放行
test_case "D12b CIDR 地址越界段999" "$B_D --cidr '10.0.0.999/8' -D" 'invalid CIDR address' 1
test_case "D12c CIDR 地址非数字" "$B_D --cidr 'abc/8' -D" 'invalid CIDR address' 1
test_case "D12d CIDR 地址简写被拒" "$B_D --cidr '10/8' -D" 'invalid CIDR address' 1
test_case "D12e CIDR 255.255.255.255/32 放行" "$B_D --cidr 255.255.255.255/32 -D" '255.255.255.255/32' 0
test_case "D13 seccomp 互斥(profile先)" \
	"$B_D --seccomp default --seccomp-syscalls read" 'mutually exclusive' 1
test_case "D14 seccomp 互斥(syscalls先)" \
	"$B_D --seccomp-syscalls read --seccomp default" 'mutually exclusive' 1

test_case "D15 mount 无效后缀" "$B_D --mount /x:invalid -D" "invalid mount option" 1
test_case "D16 mount-tmpfs 负数" "$B_D --mount-tmpfs /x:-1" "invalid tmpfs size" 1
test_case "D17 domain 空字符串" "$B_D --domain '' -D" "empty --domain argument" 1
test_case "D17b cidr 空字符串" "$B_D --cidr '' -D" "empty --cidr argument" 1
test_case "D18 seccomp 未知profile" "$B_D --seccomp unknown -- echo hello" "unknown seccomp profile" 1
test_case "D19 seccomp-syscalls 空串" "$B_D --seccomp-syscalls '' -D" "cannot be empty" 1
# D20: mount 路径超长(≥256) 曾因 strncpy 静默截断成错误路径, 现在必须显式拒绝
test_case "D20 mount 路径超长" "$B_D --mount '/$(printf 'a%.0s' {1..300})' -D" 'mount path too long' 1
# D21: mount 路径段恰为 255 合法 + ":rw" (总长>256) 应放行: memchr 按冒号分界,
#      只限路径段长, 不以 arg 总长一刀切
test_case "D21 mount 边界255+option" "$B_D --mount '/$(printf 'a%.0s' {1..254}):rw' -D" 'mounts (1)' 0
# D22: landlock 路径超长(≥256) 曾被静默截断成错误路径授权, 现在必须显式拒绝
test_case "D22 landlock 路径超长" "$B_D --landlock '/$(printf 'a%.0s' {1..300}):read' -D" 'landlock path too long' 1

# D23-D27: 同 dest 重复挂载一律拒绝 (parse_args 收尾统一去重)
test_case "D23 同 dest 重复(选项重复)" "$B_D --mount /usr:ro --mount /usr:rw -D" 'duplicate mount destination: /usr' 1
test_case "D24 同 dest 重复(逗号撞车)" "$B_D --mount-tmpfs '/d1:100,/d1:200' -D" 'duplicate mount destination: /d1' 1
test_case "D25 同 dest 重复(bind+tmpfs 撞车)" "$B_D --mount /usr:ro --mount-tmpfs /usr:64 -D" 'duplicate mount destination: /usr' 1
test_case "D26 同 dest 重复(重复 tmpfs 选项)" "$B_D --mount-tmpfs /d:100 --mount-tmpfs /d:200 -D" 'duplicate mount destination: /d' 1
test_case "D27 /tmp 拼写重复冲突" "$B_D --mount-tmpfs /tmp:64 --mount-tmpfs /tmp:128 -D" 'may be set only once' 1
# D28: 逗号展开逐段计上限 (33 段, 第 33 段撞 MAX_MOUNTS=32, dup 检查在超限之后不会先触发)
MV_OVER=""
for i in $(seq 1 33); do MV_OVER+="/mv$i:$i,"; done
MV_OVER="${MV_OVER%,}"
test_overflow "D28 mount-tmpfs 逗号超限" 'too many --mount entries' 1 "$B_D" --mount-tmpfs "$MV_OVER" -D

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

# H2: 语法错误用未闭合引号触发 — 流式解析会先撞未知键门禁再达 stream 尾,
# 故换 tokenizer 阶段即报 parse error 的输入 (见 S13 unknown-key 门禁)
put_yaml h2.yaml 'seccomp: "unclosed'
test_case "H2 YAML 语法错误" "$B_D --policy $TMPDIR/h2.yaml -- echo" 'parse error' 1

put_yaml h3.yaml "network:
  cidrs: [10.0.0.0]"
test_case "H3 CIDR 无前缀" "$B_D --policy $TMPDIR/h3.yaml -- echo" 'invalid CIDR' 1

# H3b-H3d: 地址段 inet_pton 严格校验 (对齐 CLI D12b-); H3d 即 #6 场景 —
# 超长地址段(≥63) 旧实现 strncpy 进 buf[64] 不补 NUL 致 strchr 越读栈
put_yaml h3b.yaml "network:
  cidrs: ['10.0.0.999/8']"
test_case "H3b CIDR 地址越界段999" "$B_D --policy $TMPDIR/h3b.yaml -- echo" 'invalid CIDR address' 1

put_yaml h3c.yaml "network:
  cidrs: ['255.255.255.255/32']"
test_case "H3c CIDR 255.255.255.255/32 放行" "$B_D -D --policy $TMPDIR/h3c.yaml" '255.255.255.255/32' 0

H3D_LONG="$(printf 'a%.0s' $(seq 1 70))"
put_yaml h3d.yaml "network:
  cidrs: ['${H3D_LONG}/8']"
test_case "H3d CIDR 超长地址拒绝(#6 回归)" "$B_D --policy $TMPDIR/h3d.yaml -- echo" 'invalid CIDR' 1

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

# H7/H8: S11/S12 — policy 侧漏校验补上 (对齐 CLI 与 usage-guide schema)
put_yaml h7.yaml "seccomp:
  profile: default
  syscalls: [read, write]"
test_case "H7 YAML profile+syscalls 互斥" "$B_D --policy $TMPDIR/h7.yaml -- echo" "'profile' and 'syscalls' are mutually exclusive" 1

put_yaml h8.yaml "mount:
  - {type: invalid_type, src: /usr}"
test_case "H8 YAML mount type 非法" "$B_D --policy $TMPDIR/h8.yaml -- echo" "invalid mount type 'invalid_type'" 1
# H8b: type 省略 = 缺省 bind (usage-guide), 仍放行
put_yaml h8b.yaml "mount:
  - {src: /usr}"
test_case "H8b YAML mount type 省略缺省 bind" "$B_D --policy $TMPDIR/h8b.yaml -D" 'type=bind' 0

# H9: S13 — 未知键一律报错 (拼错/design-doc 遗留不再静默空跑)
put_yaml h9.yaml "foo: bar"
test_case "H9 顶层未知键" "$B_D --policy $TMPDIR/h9.yaml -- echo" "unknown key 'foo'" 1
put_yaml h9b.yaml "network:
  enabled: 'yes'"
test_case "H9b network.enabled 遗留键被拒" "$B_D --policy $TMPDIR/h9b.yaml -- echo" "unknown key 'enabled'" 1
put_yaml h9c.yaml "seccomp:
  profiel: default"
test_case "H9c 拼错字段被拒" "$B_D --policy $TMPDIR/h9c.yaml -- echo" "unknown key 'profiel'" 1
# H9d: 完整合法 YAML (usage-guide 完整格式) 不受白名单门禁误伤
put_yaml h9d.yaml "name: demo
version: 1
mount:
  - {type: bind, src: /usr, readonly: true}
landlock:
  - {path: /usr, access: [read]}
network:
  mode: filter
  domains: [a.com]
  cidrs: [10.0.0.0/8]
seccomp:
  profile: default"
test_case "H9d 完整合法 YAML 放行" "$B_D --policy $TMPDIR/h9d.yaml -D" 'network_mode: filter' 0

# ------------------------------------------------------------------
#  I. 特殊边界场景
# ------------------------------------------------------------------
echo "=== I. 特殊边界场景 ==="

# I1: domain 127 字符 + .com（共 131 → 截断到 127）
LONG_DOMAIN="$(python3 -c "print('a'*127 + '.com')" 2>/dev/null || echo "a...long.com")"
# I1: 域名超长(≥128) 曾被 strncpy 静默截断成另一个域名, 现在必须显式拒绝
test_case "I1 domain 超长被拒" "$B_D --domain '$LONG_DOMAIN' -D" 'domain too long' 1

# I2/I3: 同 dest 重复挂载 = 歧义配置, parse_args 收尾统一去重拒绝 (2026-09-03 决策,
# 不再走 bwrap 内核叠挂; 见 usage-guide "同一 dest 只能挂载一次")
test_case "I3 同名 mount 重复报错" \
	"$B_D --mount /usr:ro --mount /usr:rw -D" 'duplicate mount destination: /usr' 1

# I4: 多个 -D
test_case "I4 多个-D" "$B_D -D -D -D" 'workdir: /'

# ------------------------------------------------------------------
#  J. bind/tmpfs 挂载安全限制 (bind 只收 src + 禁 '..' 逃逸停泊根 /oldroot)
# ------------------------------------------------------------------
echo ""
echo "=== J. bind/tmpfs 挂载安全限制 ==="

# J1: CLI 路径含 '..' 被拒 (--mount /../oldroot 曾可叠回停泊根逃逸)
test_case "J1 CLI --mount 含 .. 被拒" \
	"$B_D --mount /../oldroot:rw -D" "invalid --mount path" 1

# J2: CLI 路径含 '.'/'//' 被拒
test_case "J2 CLI --mount 含 . 被拒" \
	"$B_D --mount /usr/./bin:ro -D" "invalid --mount path" 1

# J3: CLI 正常同路径仍放行
test_case "J3 CLI --mount 正常放行" \
	"$B_D --mount /usr:ro -D" "mounts (1)" 0

# J4: YAML bind 显式 dest (src!=dest, 曾指向 /oldroot 逃逸) 被拒
put_yaml j4.yaml "mount:
  - type: bind
    src: /tmp
    dest: /oldroot"
test_case "J4 YAML bind dest 被拒" \
	"$B_D -D --policy $TMPDIR/j4.yaml" "takes only 'src'" 1

# J5: YAML bind 即使 dest==src 也不允许 dest 字段
put_yaml j5.yaml "mount:
  - type: bind
    src: /usr
    dest: /usr"
test_case "J5 YAML bind dest==src 仍拒" \
	"$B_D -D --policy $TMPDIR/j5.yaml" "takes only 'src'" 1

# J6: YAML bind 路径含 '..' 被拒
put_yaml j6.yaml "mount:
  - type: bind
    src: /../oldroot"
test_case "J6 YAML bind 含 .. 被拒" \
	"$B_D -D --policy $TMPDIR/j6.yaml" "invalid mount path" 1

# J7: YAML bind 只给 src 放行 (dest 恒 = src)
put_yaml j7.yaml "mount:
  - type: bind
    src: /usr
    readonly: true"
test_case "J7 YAML bind 只收 src 放行" \
	"$B_D -D --policy $TMPDIR/j7.yaml" "mounts (1)" 0

# J8: YAML tmpfs 出现 src 被拒
put_yaml j8.yaml "mount:
  - type: tmpfs
    src: /tmp
    dest: /data"
test_case "J8 YAML tmpfs 带 src 被拒" \
	"$B_D -D --policy $TMPDIR/j8.yaml" "takes only 'dest'" 1

# J9: YAML bind 缺 src 被拒
put_yaml j9.yaml "mount:
  - type: bind"
test_case "J9 YAML bind 缺 src 被拒" \
	"$B_D -D --policy $TMPDIR/j9.yaml" "requires 'src'" 1

# J10: CLI bind/tmpfs 命中 /oldroot 被拒 (bind 字面叠层也逃逸, tmpfs 更直接)
test_case "J10 CLI --mount /oldroot 被拒" \
	"$B_D --mount /oldroot:rw -D" "invalid --mount path" 1
test_case "J10b CLI --mount-tmpfs /oldroot 被拒" \
	"$B_D --mount-tmpfs /oldroot:64 -D" "invalid --mount-tmpfs path" 1

# J11: YAML bind src=/oldroot 被拒
put_yaml j11.yaml "mount:
  - type: bind
    src: /oldroot"
test_case "J11 YAML bind /oldroot 被拒" \
	"$B_D -D --policy $TMPDIR/j11.yaml" "invalid mount path" 1

# J12: YAML tmpfs dest=/oldroot 被拒
put_yaml j12.yaml "mount:
  - type: tmpfs
    dest: /oldroot"
test_case "J12 YAML tmpfs /oldroot 被拒" \
	"$B_D -D --policy $TMPDIR/j12.yaml" "invalid mount path" 1

# J13: YAML tmpfs 正常路径放行
put_yaml j13.yaml "mount:
  - type: tmpfs
    dest: /data"
test_case "J13 YAML tmpfs 正常放行" \
	"$B_D -D --policy $TMPDIR/j13.yaml" "mounts (1)" 0

# ------------------------------------------------------------------
#  汇总
# ------------------------------------------------------------------
echo ""
echo "=========================================="
echo "  参数解析测试完成"
echo "  总计: $TOTAL  通过: $PASS  失败: $FAIL"
echo "=========================================="

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
