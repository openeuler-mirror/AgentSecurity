# dyn-sandbox 启动性能基线记录

**日期:** 2026-08-03
**机器:** VM36 (openEuler x86_64)
**内核:** 6.6.0-159.4.3.155.y.x86_64
**模块:** dyn_sandbox.ko（`landlock_enable` 默认 -1 auto，实测 Landlock 生效）
**目标命令:** `/usr/bin/true`
**计时:** bash 内置 `time`，`TIMEFORMAT=%R`（real，秒），换算 ms
**样本:** 每档 30 次（服务启动 5 次）

可复现脚本: `test/test_startup_bench.sh`

## 前置准备

```bash
# 自行创建的测试目录（避免依赖系统路径在沙箱 namespace 内不存在）
sudo mkdir -p /bench/m{1..10}
sudo chmod 755 /bench /bench/m*
sudo mkdir -p /usr/local/dynsb_bench/ll{1..10}
sudo chmod -R a+rx /usr/local/dynsb_bench

# 模块 + DNS 代理
sudo systemctl start dyn-sandbox.service
```

## 测试指令（各看护点）

`SB=./dist/dyn-sandbox`；均在 `/home/testuser/sandbox`（NFS 仓库根）下以 testuser 运行；
计时用 `{ time CMD >/dev/null 2>&1; } 2>&1` 取 real。

| # | 看护点 | 指令（×30 次） |
|---|--------|----------------|
| 1 | native 基线 | `$SB /usr/bin/true` 的对照：直接 `time /usr/bin/true` |
| 2 | 空配置（isolated，Landlock 默认 ~23 条） | `$SB /usr/bin/true` |
| 3 | Landlock 开关 | `$SB --no-landlock /usr/bin/true` |
| 4 | mount ×5（--no-landlock，隔离 mount 成本） | `$SB --no-landlock --mount /bench/m1:ro --mount /bench/m2:ro --mount /bench/m3:ro --mount /bench/m4:ro --mount /bench/m5:ro -- /usr/bin/true` |
| 5 | mount ×10（同上） | 同上 m1..m10 |
| 6 | landlock ×5（默认之上） | `$SB --landlock /usr/local/dynsb_bench/ll1:read+write+truncate --landlock /usr/local/dynsb_bench/ll2:read+write+truncate --landlock /usr/local/dynsb_bench/ll3:read+write+truncate --landlock /usr/local/dynsb_bench/ll4:read+write+truncate --landlock /usr/local/dynsb_bench/ll5:read+write+truncate -- /usr/bin/true` |
| 7 | landlock ×10 | 同上 ll1..ll10 |
| 8 | cidr ×5 | `$SB --cidr 10.1.0.0/16,10.2.0.0/16,10.3.0.0/16,10.4.0.0/16,10.5.0.0/16 -- /usr/bin/true` |
| 9 | cidr ×10 | `$SB --cidr 10.1.0.0/16,10.2.0.0/16,10.3.0.0/16,10.4.0.0/16,10.5.0.0/16,10.6.0.0/16,10.7.0.0/16,10.8.0.0/16,10.9.0.0/16,10.10.0.0/16 -- /usr/bin/true` |
| 10 | 服务启动（stop→start，含 modprobe + DNS 代理） | `sudo systemctl stop dyn-sandbox.service` 后 `time sudo systemctl start dyn-sandbox.service`（×5） |

## 测量结果（ms）

| 看护点 | mean | median | p95 | min | max |
|--------|-----:|-------:|----:|----:|----:|
| native /usr/bin/true | 0.03 | 0 | 0 | 0 | 1 |
| 空配置（Landlock 默认） | 14.40 | 14 | 18 | 13 | 19 |
| --no-landlock | 3.37 | 3 | 4 | 2 | 10 |
| mount ×5（--no-landlock） | 3.13 | 3 | 4 | 3 | 5 |
| mount ×10（--no-landlock） | 3.13 | 3 | 4 | 2 | 6 |
| landlock ×5 | 16.37 | 16 | 19 | 15 | 21 |
| landlock ×10 | 18.27 | 18 | 21 | 17 | 22 |
| cidr ×5 | 88.77 | 83.5 | 120 | 71 | 151 |
| cidr ×10 | 90.73 | 84 | 130 | 72 | 149 |
| 服务启动 | 81.60 | 80 | 89 | 78 | 89 |

## 绝对阈值（PASS 条件，median 判据）

| 看护点 | 基线 median | 绝对阈值 | 说明 |
|--------|-----------:|---------:|------|
| 空配置 | 14 | ≤ 30 | 2.1×，留足机器波动余量 |
| --no-landlock | 3 | ≤ 15 | 最大 10，取 15 |
| mount ×5（--no-landlock） | 3 | ≤ 15 | 与 --no-landlock 同档（×0 即该档） |
| mount ×10（--no-landlock） | 3 | ≤ 15 | 同上 |
| landlock ×5 | 16 | ≤ 35 | 每条 ~0.4ms，留扩展余量 |
| landlock ×10 | 18 | ≤ 35 | 同上 |
| cidr ×5 | 83.5 | ≤ 200 | p95=120、max=151，波动大 |
| cidr ×10 | 84 | ≤ 200 | 同上 |
| 服务启动 | 80 | ≤ 200 | 用户可感知，max=89 |

> 阈值按当前环境（VM36）实测设定，跨机器/架构（如 aarch64）需重跑基线后调整。
> 结论速览：Landlock 默认 23 条 ≈ 11ms 启动成本（14→3）；mount 条数完全免费
> （--no-landlock 下 ×0/×5/×10 均 ~3ms）；网络使能 ≈ 74ms 固定成本（veth+netns+nft）；
> cidr 条数无差别；Landlock 每条额外规则 ≈ 0.4ms。

## 已知约束（写测试时注意）

1. **`--landlock` 规则路径在子进程 namespace 内解析**：沙箱内仅存在
   /usr /etc /proc /sys /dev /tmp（/tmp 为全新 tmpfs），
   `--landlock /var/log:...` 会 `No such file`（rc=2）。规则路径须选 /usr、/etc 下真实存在的路径。
2. **`--cidr` 重叠会失败**：如 `10.0.0.0/8` + `10.1.0.0/16` → nft interval set 报
   `interval overlaps with an existing one` → SANDBOX_NET_CREATE 返回 EIO（沙箱 rc=7）。
   测试须用互不包含的网段。
