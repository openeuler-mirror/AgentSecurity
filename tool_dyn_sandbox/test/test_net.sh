#!/bin/bash
# test_net.sh — 网络隔离测试 (veth/netns + CIDR + 域名白名单)
# 可独立运行:  ./test_net.sh
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
SANDBOX_RUN="/usr/bin/dyn-sandbox"
KO_DIR="$DIR/../dist"
LOGFILE="test_net.log"
PASS=0; FAIL=0; SKIP=0

PW="111111"
sudo_run() { echo "$PW" | sudo -S "$@"; }

log() { echo "--- $*"; }
pass() { echo "PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }
skip() { echo "SKIP: $1"; SKIP=$((SKIP+1)); }

: > "$LOGFILE"
{
    echo "=============================================="
    echo "  网络隔离测试"
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

BASE_MOUNT="--mount /usr:ro --mount /lib:ro --mount /lib64:ro"

# ────────────────────────────────────────────────
# 预解析测试站点 IP，供后续用例使用
# （避免硬编码 IP，消除因站点 IP 变更或不可达导致的假阳性）
# ────────────────────────────────────────────────
RESOLVED_SITES=()
RESOLVED_IPS=()
for dom in baidu.com bilibili.com taobao.com jd.com 163.com \
           zhihu.com weibo.com douyin.com meituan.com xiaohongshu.com; do
    ip=$(getent ahosts "$dom" 2>/dev/null | grep '^[0-9.]' | awk '{print $1; exit}')
    if [ -n "$ip" ]; then
        RESOLVED_SITES+=("${dom}:${ip}")
        RESOLVED_IPS+=("$ip")
    fi
done
echo "resolved ${#RESOLVED_SITES[@]} sites: ${RESOLVED_IPS[*]}"

T=0

# ────────────────────────────────────────────────
# N1: network veth/netns
# ────────────────────────────────────────────────
T=$((T+1)); log "Test N$T: network veth/netns"
run_test "N$T" "network veth/netns" \
    timeout 10 ${SANDBOX_RUN} --cidr 110.242.74.102/32 \
        --mount /usr:ro --mount /lib:ro --mount /lib64:ro --landlock '/sbin:read+execute' -- ip addr show
tail -20 "$LOGFILE" | grep -q "inet 10\.99\." \
&& pass "N$T network veth/netns" || fail "N$T network veth/netns"

# ────────────────────────────────────────────────
# N2: Landlock + seccomp + network
# ────────────────────────────────────────────────
T=$((T+1)); log "Test N$T: Landlock + seccomp + network"
run_test "N$T" "Landlock + seccomp + network" \
    timeout 10 ${SANDBOX_RUN} --cidr 110.242.74.102/32 ${BASE_MOUNT} \
        --landlock '/:read+execute' --landlock '/sbin:read+execute' --seccomp script -- ip link show lo
tail -20 "$LOGFILE" | grep -q LOOPBACK \
&& pass "N$T Landlock + seccomp + network" || fail "N$T Landlock + seccomp + network"

# ────────────────────────────────────────────────
# N3: isolated mode (no veth)
# ────────────────────────────────────────────────
T=$((T+1)); log "Test N$T: isolated mode (no veth)"
run_test "N$T" "isolated mode (no veth)" \
    timeout 10 ${SANDBOX_RUN} ${BASE_MOUNT} --landlock '/sbin:read+execute' -- ip link show
tail -20 "$LOGFILE" | grep -q "LOOPBACK" \
&& pass "N$T isolated mode (no veth)" || fail "N$T isolated mode (no veth)"

# ────────────────────────────────────────────────
# N4: default route via gateway
# ────────────────────────────────────────────────
T=$((T+1)); log "Test N$T: default route"
run_test "N$T" "default route" \
    timeout 10 ${SANDBOX_RUN} --cidr 110.242.74.102/32 ${BASE_MOUNT} --landlock '/sbin:read+execute' -- ip route show
tail -20 "$LOGFILE" | grep -q ^default \
&& pass "N$T default route" || fail "N$T default route"

# ────────────────────────────────────────────────
# N5: whitelisted CIDR reachable
# ────────────────────────────────────────────────
T=$((T+1)); log "Test N$T: whitelisted CIDR reachable"
allow_ip="${RESOLVED_IPS[0]:-110.242.74.102}"
run_test "N$T" "whitelisted CIDR reachable" \
    timeout 15 ${SANDBOX_RUN} --cidr ${allow_ip}/32 ${BASE_MOUNT} \
        -- curl -s --connect-timeout 10 http://${allow_ip}/ > /dev/null
[ $? -eq 0 ] && pass "N$T whitelisted CIDR reachable" || fail "N$T whitelisted CIDR reachable"

# ────────────────────────────────────────────────
# N6: non-whitelisted IP blocked
#   whitelist 一个已知可达的 IP，curl 另一个已知可达但未白名单的 IP
#   避免使用外部不可控 IP 导致的假阳性
# ────────────────────────────────────────────────
T=$((T+1)); log "Test N$T: non-whitelisted IP blocked"
allow_ip="${RESOLVED_IPS[0]:-110.242.74.102}"
block_ip="${RESOLVED_IPS[1]:-59.82.122.140}"
run_test "N$T" "non-whitelisted IP blocked" \
    timeout 12 ${SANDBOX_RUN} --cidr ${allow_ip}/32 ${BASE_MOUNT} \
        -- curl -s --connect-timeout 4 http://${block_ip}/
[ $? -ne 0 ] && pass "N$T non-whitelisted IP blocked" || fail "N$T non-whitelisted IP blocked"

# ────────────────────────────────────────────────
# N7: isolated network (no access)
# ────────────────────────────────────────────────
T=$((T+1)); log "Test N$T: isolated network (no access)"
test_ip="${RESOLVED_IPS[0]:-110.242.74.102}"
run_test "N$T" "isolated network (no access)" \
    timeout 12 ${SANDBOX_RUN} ${BASE_MOUNT} \
        -- curl -s --connect-timeout 4 http://${test_ip}/
[ $? -ne 0 ] && pass "N$T isolated network blocked" || fail "N$T isolated network blocked"

# ────────────────────────────────────────────────
# N8-N13: dyn-sandbox-dns required
# ────────────────────────────────────────────────

# ---
# N8: domain whitelist (dyn-sandbox-dns)
#   domain访问通过dyn-sandbox-dns域名白名单放行
# ---
T=$((T+1)); log "Test N$T: domain whitelist (dyn-sandbox-dns)"
run_test "N$T" "domain whitelist (dyn-sandbox-dns)" \
    timeout 25 ${SANDBOX_RUN} --domain baidu.com ${BASE_MOUNT} \
        -- sh -c \
        'c=0; curl -s -o /dev/null --connect-timeout 10 http://baidu.com/ && c=$((c+1)); [ "$c" = "1" ]' \
&& pass "N$T domain whitelist (dyn-sandbox-dns)" || fail "N$T domain whitelist (dyn-sandbox-dns)"

# ────────────────────────────────────────────────
# N9: domain + CIDR (both traffic)
# ────────────────────────────────────────────────
allow_ip="${RESOLVED_IPS[0]:-110.242.74.102}"
T=$((T+1)); log "Test N$T: domain + CIDR (both traffic)"
run_test "N$T" "domain + CIDR (both traffic)" \
    timeout 25 ${SANDBOX_RUN} --domain baidu.com --cidr ${allow_ip}/32 \
        ${BASE_MOUNT} -- bash -c \
        "c=0; curl -s -o /dev/null --connect-timeout 10 http://${allow_ip}/ && c=\$((c+1)); curl -s --connect-timeout 10 http://baidu.com/ >/dev/null && c=\$((c+1)); [ \"\$c\" = \"2\" ]" \
&& pass "N$T domain + CIDR (both traffic)" || fail "N$T domain + CIDR (both traffic)"

# ────────────────────────────────────────────────
# N10: multiple domains + multiple CIDRs
# ────────────────────────────────────────────────
allow_ip="${RESOLVED_IPS[0]:-110.242.74.102}"
allow_ip2="${RESOLVED_IPS[1]:-59.82.122.140}"
T=$((T+1)); log "Test N$T: multiple domains + multiple CIDRs"
run_test "N$T" "multiple domains + multiple CIDRs" \
    timeout 30 ${SANDBOX_RUN} --domain baidu.com --domain taobao.com \
        --cidr ${allow_ip}/32 --cidr ${allow_ip2}/32 ${BASE_MOUNT} \
        -- bash -c \
        "c=0; curl -s -o /dev/null --connect-timeout 10 http://${allow_ip}/ && c=\$((c+1)); curl -s --connect-timeout 10 http://baidu.com/ >/dev/null && c=\$((c+1)); curl -s --connect-timeout 10 http://${allow_ip2}/ >/dev/null && c=\$((c+1)); [ \"\$c\" = \"3\" ]" \
&& pass "N$T multiple domains + multiple CIDRs" || fail "N$T multiple domains + multiple CIDRs"

# ────────────────────────────────────────────────
# N11: domain + CIDR + Landlock + seccomp
# ────────────────────────────────────────────────
allow_ip="${RESOLVED_IPS[0]:-110.242.74.102}"
T=$((T+1)); log "Test N$T: domain + CIDR + Landlock + seccomp"
run_test "N$T" "domain + CIDR + Landlock + seccomp" \
    timeout 20 ${SANDBOX_RUN} --domain baidu.com --cidr ${allow_ip}/32 \
        ${BASE_MOUNT} --landlock '/:read+execute' --seccomp script \
        -- curl -s -o /dev/null --connect-timeout 8 http://${allow_ip}/ \
&& pass "N$T domain + CIDR + Landlock + seccomp" || fail "N$T domain + CIDR + Landlock + seccomp"

# ────────────────────────────────────────────────
# N12: domain only (no CIDR)
# ────────────────────────────────────────────────
T=$((T+1)); log "Test N$T: domain only (no CIDR)"
run_test "N$T" "domain only (no CIDR)" \
    timeout 25 ${SANDBOX_RUN} --domain baidu.com ${BASE_MOUNT} \
        -- bash -c \
        'c=0; curl -s --connect-timeout 10 http://baidu.com/ >/dev/null && c=$((c+1)); [ "$c" = "1" ]' \
&& pass "N$T domain only (no CIDR)" || fail "N$T domain only (no CIDR)"

# ────────────────────────────────────────────────
# N13: 多网站白名单随机验证 (10 轮)
# 复用脚本顶部预解析的站点 IP
# ────────────────────────────────────────────────
SITES=("${RESOLVED_SITES[@]}")
N_SITES=${#SITES[@]}
if [ "$N_SITES" -lt 5 ]; then
    echo "ERROR: only $N_SITES sites resolved, need >= 5"
    fail "N12 multi-site traversal (insufficient sites: ${N_SITES}/5)"
else
    T=$((T+1)); N12_BASE=$T
    N12_PASS=0; N12_FAIL=0

    for round in $(seq 1 10); do
        # 随机选择 4~7 个白名单站点
        n_wl=$(( (RANDOM % 4) + 4 ))
        wl_idxs=()
        while [ ${#wl_idxs[@]} -lt $n_wl ]; do
            idx=$(( RANDOM % N_SITES ))
            skip=0
            for w in "${wl_idxs[@]}"; do [ "$w" = "$idx" ] && skip=1; done
            [ $skip -eq 0 ] && wl_idxs+=($idx)
        done

        # 构建白名单参数
        cidr_args=""; domain_args=""
        declare -A is_cidr_wl is_domain_wl
        for ((i=0; i<N_SITES; i++)); do is_cidr_wl[$i]=0; is_domain_wl[$i]=0; done

        for idx in "${wl_idxs[@]}"; do
            site="${SITES[$idx]}"
            dom="${site%%:*}"
            ip="${site##*:}"
            if [ $((RANDOM % 2)) -eq 0 ]; then
                cidr_args="$cidr_args --cidr ${ip}/32"
                is_cidr_wl[$idx]=1
            else
                domain_args="$domain_args --domain $dom"
                is_domain_wl[$idx]=1
            fi
        done

        # 构建内部测试命令
        # CIDR 白名单：只测 IP；域名白名单：只测域名；非白名单：两者都测（预期失败）
        inner="r=0; "
        for ((i=0; i<N_SITES; i++)); do
            site="${SITES[$i]}"
            dom="${site%%:*}"
            ip="${site##*:}"
            if [ ${is_cidr_wl[$i]} -eq 1 ]; then
                inner+="curl -s -o /dev/null -H \"Host: $dom\" \"http://$ip/\" --connect-timeout 3 2>/dev/null; rc=\$?; [ \$rc -eq 0 ] || { echo \"FAIL:${dom}:cidr\"; r=1; }; "
            elif [ ${is_domain_wl[$i]} -eq 1 ]; then
                inner+="curl -s -o /dev/null \"http://$dom/\" --connect-timeout 3 2>/dev/null; rc=\$?; [ \$rc -eq 0 ] || { echo \"FAIL:${dom}:domain\"; r=1; }; "
            else
                inner+="curl -s -o /dev/null -H \"Host: $dom\" \"http://$ip/\" --connect-timeout 3 2>/dev/null; rc=\$?; [ \$rc -ne 0 ] || { echo \"FAIL:${dom}:cidr\"; r=1; }; "
                inner+="curl -s -o /dev/null \"http://$dom/\" --connect-timeout 3 2>/dev/null; rc=\$?; [ \$rc -ne 0 ] || { echo \"FAIL:${dom}:domain\"; r=1; }; "
            fi
        done
        inner+="exit \$r"

        run_test "N${N12_BASE}-R${round}" "round $round/$n_wl wl" \
            timeout 70 ${SANDBOX_RUN} $cidr_args $domain_args ${BASE_MOUNT} \
                -- bash -c "$inner"

        if [ $? -eq 0 ]; then
            N12_PASS=$((N12_PASS+1))
        else
            N12_FAIL=$((N12_FAIL+1))
        fi
    done

    # N12 整体判据：10 轮全部通过才 PASS
    [ "$N12_FAIL" -eq 0 ] && pass "N${N12_BASE} multi-site traversal (${N12_PASS}/${N12_PASS}/${N12_FAIL})" \
        || fail "N${N12_BASE} multi-site traversal (${N12_PASS}/10 passed, ${N12_FAIL} failed)"
fi

{


    echo ""
    echo "=============================================="
    echo "  end: $(date +%T.%N)"
    echo "=============================================="
} >> "$LOGFILE"

echo ""
echo "=========================================="
echo "Network: $PASS passed, $FAIL failed, $SKIP skipped"
echo "=========================================="
echo "Log: $LOGFILE"

[ "$FAIL" -gt 0 ] && exit 1 || exit 0
