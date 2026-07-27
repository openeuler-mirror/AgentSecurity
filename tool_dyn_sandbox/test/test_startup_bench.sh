#!/bin/bash
# Startup performance baseline (看护点测量脚本)
#
# 用法: 在目标 VM 上以 testuser 运行: bash test/test_startup_bench.sh
#   - NFS 根目录 = /home/testuser/sandbox (即仓库根)
#   - sudo 仅用于 systemctl (模块 + DNS 代理)
#   - 目标命令 /usr/bin/true; bash 内置 time, TIMEFORMAT=%R (real, 秒)
#   - 每档默认 30 次 (服务启动 5 次)
#
# 前置准备 (一次性, 自行创建的测试目录):
#   sudo mkdir -p /bench/m{1..10}; chmod 755 /bench /bench/m*
#   sudo mkdir -p /usr/local/dynsb_bench/ll{1..10}; chmod -R a+rx /usr/local/dynsb_bench
#
# 注:
#   - --landlock 规则路径在子进程 namespace 里解析, 沙箱内仅有
#     /usr /etc /proc /sys /dev /tmp, 故规则路径须用 /usr /etc 下自建目录
#   - --cidr 必须非重叠 (nft interval set 拒绝 overlap -> ioctl EIO)
#
# 结果与绝对阈值见 test/bench_startup_baseline.md
set -u
cd /home/testuser/sandbox || exit 1
export PATH=/usr/bin:/bin

SANDBOX=/usr/bin/dyn-sandbox
TARGET=/usr/bin/true
RUNS=30
SRUNS=5   # service start runs

echo "=== [0] sanity: module/service state ==="
echo 111111 | sudo -S systemctl start dyn-sandbox.service 2>/dev/null
systemctl is-active dyn-sandbox.service
ls -la /dev/dyn-sandbox 2>&1 | head -1

# ---- measurement helpers ----
# run_one: run cmd once with stdin=/dev/null, print real seconds (bash builtin time)
run_one() {
  local out rc
  out=$(TIMEFORMAT='%R'; { time "$@" </dev/null >/dev/null 2>&1; } 2>&1)
  rc=$?
  [ $rc -eq 0 ] || { echo "ERR rc=$rc: $*" >&2; return 1; }
  echo "$out"
}

# bench: label runs cmd... -> prints label + sorted-ms stats
bench() {
  local label="$1" n="$2"; shift 2
  local i t ms
  local vals=()
  for ((i=0;i<n;i++)); do
    t=$(run_one "$@") || return 1
    ms=$(awk -v s="$t" 'BEGIN{printf "%.3f", s*1000}')
    vals+=("$ms")
  done
  echo "--- $label (n=$n) ---"
  printf '%s\n' "${vals[@]}" | sort -n | awk '
    {a[NR]=$1; s+=$1}
    END{
      n=NR; med=(n%2)? a[int(n/2)+1] : (a[n/2]+a[n/2+1])/2;
      pi=int(n*0.95)+1; if (pi>n) pi=n;
      printf "  mean=%.2fms median=%.2fms p95=%.2fms min=%.2fms max=%.2fms\n",
             s/n, med, a[pi], a[1], a[n];
    }'
}

LL5=(); LL10=()
for i in 1 2 3 4 5;           do LL5+=(--landlock "/usr/local/dynsb_bench/ll$i:read+write+truncate"); done
for i in 1 2 3 4 5 6 7 8 9 10; do LL10+=(--landlock "/usr/local/dynsb_bench/ll$i:read+write+truncate"); done

M5=(); M10=()
for i in 1 2 3 4 5;            do M5+=(--mount "/bench/m$i:ro"); done
for i in 1 2 3 4 5 6 7 8 9 10; do M10+=(--mount "/bench/m$i:ro"); done

CIDR5="10.1.0.0/16,10.2.0.0/16,10.3.0.0/16,10.4.0.0/16,10.5.0.0/16"
CIDR10="$CIDR5,10.6.0.0/16,10.7.0.0/16,10.8.0.0/16,10.9.0.0/16,10.10.0.0/16"

echo
echo "=== [1] native /usr/bin/true ==="
bench "native true" $RUNS "$TARGET" || exit 1

echo
echo "=== [2] empty config (isolated, landlock default) ==="
bench "empty-config" $RUNS "$SANDBOX" "$TARGET" || exit 1

echo
echo "=== [3] landlock switch: --no-landlock ==="
bench "no-landlock" $RUNS "$SANDBOX" --no-landlock "$TARGET" || exit 1

echo
echo "=== [4] mount scaling (--no-landlock 隔离 mount 成本, source /bench/mN) ==="
bench "mount-x5" $RUNS "$SANDBOX" --no-landlock "${M5[@]}" "$TARGET" || exit 1
bench "mount-x10" $RUNS "$SANDBOX" --no-landlock "${M10[@]}" "$TARGET" || exit 1

echo
echo "=== [5] landlock rule scaling (defaults + N user rules) ==="
bench "landlock-x5" $RUNS "$SANDBOX" "${LL5[@]}" "$TARGET" || exit 1
bench "landlock-x10" $RUNS "$SANDBOX" "${LL10[@]}" "$TARGET" || exit 1

echo
echo "=== [6] network whitelist scaling (--cidr, non-overlapping /16) ==="
bench "cidr-x5" $RUNS "$SANDBOX" --cidr "$CIDR5" "$TARGET" || exit 1
bench "cidr-x10" $RUNS "$SANDBOX" --cidr "$CIDR10" "$TARGET" || exit 1

echo
echo "=== [7] service start (stop -> start, full: modprobe + dns-proxy) ==="
v=()
for ((i=0;i<SRUNS;i++)); do
  echo 111111 | sudo -S systemctl stop dyn-sandbox.service >/dev/null 2>&1
  t=$(run_one sudo systemctl start dyn-sandbox.service) || exit 1
  ms=$(awk -v s="$t" 'BEGIN{printf "%.3f", s*1000}')
  v+=("$ms")
done
echo "--- service-start (n=$SRUNS) ---"
printf '%s\n' "${v[@]}" | sort -n | awk '
  {a[NR]=$1; s+=$1}
  END{
    n=NR; med=(n%2)? a[int(n/2)+1] : (a[n/2]+a[n/2+1])/2;
    pi=int(n*0.95)+1; if (pi>n) pi=n;
    printf "  mean=%.2fms median=%.2fms p95=%.2fms min=%.2fms max=%.2fms\n",
           s/n, med, a[pi], a[1], a[n];
  }'

echo
echo "=== done ==="
