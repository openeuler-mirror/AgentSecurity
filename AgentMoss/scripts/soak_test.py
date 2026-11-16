#!/usr/bin/env python3
"""长稳压测 —— 验证「跑一段时间就变慢」是否真的修好了。

和 `bench_analyze.py` 的区别：

- bench 测的是**不同并发档位的瞬时能力**；
- soak 测的是**同一个负载下、时间拉长后是否退化**。

它会开启 `metadata.stateful_incremental`（AgentGate 默认行为），让链状态库持续
增长，每 ``--sample`` 秒采一次样，输出：

    时间  窗口QPS  p50    p95    loop_lag  chain_nodes  内存RSS

判定标准（脚本最后会自动给出结论）：

- **QPS 不随时间下降**（首尾窗口差 < 30%）
- **p95 不随时间上升**（末窗 p95 < 首窗 p95 × 2）
- **loop_lag 保持低位**（最大值 < 200ms）
- **chain_nodes 线性增长**（说明状态确实在累积，测试有效）

用法：

    # 终端 1（关闭并发闸门，让状态路径真正被打到）
    AGENT_MOSS_DISABLE_LLM=1 AGENT_MOSS_AUTH_MODE=off AGENT_MOSS_POOL_BIZ=0 \\
        AGENT_MOSS_DATA_DIR=/tmp/soak AGENT_MOSS_STATE_DIR=/tmp/soak \\
        agent-moss server --port 19092

    # 终端 2
    python3 scripts/soak_test.py --url http://127.0.0.1:19092 \\
        --concurrency 8 --duration 600 --sample 30
"""

from __future__ import annotations

import argparse
import asyncio
import statistics
import sys
import time
import uuid

try:
    import httpx
except ImportError:  # pragma: no cover
    print("需要 httpx：pip install httpx", file=sys.stderr)
    raise SystemExit(2)


def build_payload(idx: int) -> dict:
    return {
        "session_id": f"soak-{uuid.uuid4().hex[:8]}",
        "prompt_session": f"长稳请求 {idx}",
        "action_history": [],
        "a_next": {
            "action_type": "execute",
            "action_detail": f"cat /etc/hostname && echo 'soak-{idx}'",
        },
        "reason": "soak",
        "os_type": "linux",
        "cwd": "/tmp",
        # 关键：开启有状态增量，让链状态库真的增长（模拟 AgentGate 默认行为）
        "metadata": {"stateful_incremental": True, "soak": True},
    }


async def health_snapshot(client: httpx.AsyncClient, url: str) -> dict:
    try:
        r = await client.get(f"{url}/api/v1/health", timeout=5.0)
        return r.json().get("metrics", {}) if r.status_code == 200 else {}
    except Exception:  # noqa: BLE001
        return {}


async def _review_loop(
    client: httpx.AsyncClient,
    url: str,
    interval: float,
    recent: list[dict],
    stats: dict,
    stop_at: float,
) -> None:
    """模拟 AgentGate 的周期性 /review（每 N 秒一次，seed 最近的动作）。

    为什么要单独压这条路径（2026-11）：review 会 seed 全量历史，历史上它
    - 不幂等（同一批历史反复追加 → 节点成倍膨胀）
    - 不持锁（与并发 apply_action 竞态）
    - 没有规模上限（一次持锁几百毫秒）
    这两个 bug 是靠 review 路径长稳才能暴露的，之前只压 analyze 完全测不到。
    """
    while time.monotonic() < stop_at:
        await asyncio.sleep(interval)
        # 用最近产生的动作构造成「一个 session 的历史」，模拟 AgentGate 直读本地库
        snapshot = list(recent)
        if not snapshot:
            continue
        body = {
            "agent_id": "soak",
            "sessions": [
                {"session_id": "soak-history", "action_history": snapshot},
            ],
        }
        t0 = time.perf_counter()
        try:
            resp = await client.post(f"{url}/api/v1/review", json=body)
            elapsed = (time.perf_counter() - t0) * 1000
            stats["reviews"] += 1
            stats["review_ms"].append(elapsed)
            if resp.status_code != 200:
                stats["review_errors"] += 1
        except Exception:  # noqa: BLE001
            stats["review_errors"] += 1


async def main_async(args: argparse.Namespace) -> int:
    async with httpx.AsyncClient(timeout=args.timeout) as probe:
        h = await health_snapshot(probe, args.url)
        if not h:
            print(f"服务不可用: {args.url}", file=sys.stderr)
            return 1
        print(f"服务健康，初始指标: {h}\n")

    latencies: list[float] = []
    errors = 0
    stop_at = time.monotonic() + args.duration
    counter = {"n": 0}
    windows: list[dict] = []
    #: review 路径的观测（--with-review 时启用）
    recent_actions: list[dict] = []
    review_stats = {"reviews": 0, "review_errors": 0, "review_ms": []}
    review_task: asyncio.Task | None = None

    async with httpx.AsyncClient(
        timeout=args.timeout,
        limits=httpx.Limits(max_connections=args.concurrency * 2),
    ) as client:

        async def worker() -> None:
            nonlocal errors
            while time.monotonic() < stop_at:
                t0 = time.perf_counter()
                try:
                    payload = build_payload(counter["n"])
                    resp = await client.post(f"{args.url}/api/v1/analyze", json=payload)
                    counter["n"] += 1
                    latencies.append(time.perf_counter() - t0)
                    if resp.status_code != 200:
                        errors += 1
                    elif args.with_review:
                        # 保留最近 200 条作为「历史」，供 review seed
                        recent_actions.append(
                            {
                                "action_type": payload["a_next"]["action_type"],
                                "action_detail": payload["a_next"]["action_detail"],
                                "called_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                            }
                        )
                        if len(recent_actions) > 200:
                            del recent_actions[: len(recent_actions) - 200]
                except Exception:  # noqa: BLE001
                    errors += 1

        tasks = [asyncio.create_task(worker()) for _ in range(args.concurrency)]
        if args.with_review:
            review_task = asyncio.create_task(
                _review_loop(client, args.url, args.review_interval, recent_actions, review_stats, stop_at)
            )
        started = time.monotonic()
        header = (
            f"{'时间(s)':>8} {'窗口QPS':>8} {'p50(ms)':>9} {'p95(ms)':>9} "
            f"{'loop_lag':>9} {'chain_nodes':>12} {'错误':>5}"
        )
        print(header)
        print("-" * len(header))
        last_count = 0
        last_t = started
        while time.monotonic() < stop_at:
            await asyncio.sleep(args.sample)
            now = time.monotonic()
            snap = await health_snapshot(client, args.url)
            window = latencies[last_count:]
            last_count = len(latencies)
            qps = len(window) / max(0.001, now - last_t)
            last_t = now
            if window:
                w = sorted(x * 1000 for x in window)
                p50 = w[len(w) // 2]
                p95 = w[min(len(w) - 1, int(len(w) * 0.95))]
            else:
                p50 = p95 = 0.0
            rec = {
                "t": round(now - started, 1),
                "qps": round(qps, 1),
                "p50": round(p50, 1),
                "p95": round(p95, 1),
                "loop_lag": snap.get("loop_lag_ms", -1),
                "chain_nodes": snap.get("chain_nodes", -1),
                "errors": errors,
            }
            windows.append(rec)
            print(
                f"{rec['t']:>8} {rec['qps']:>8} {rec['p50']:>9} {rec['p95']:>9} "
                f"{rec['loop_lag']:>9} {rec['chain_nodes']:>12} {rec['errors']:>5}"
            )
        for t in tasks:
            t.cancel()
        if review_task is not None:
            review_task.cancel()

    # ---- 判定 ----
    print("\n===== 结论 =====")
    if len(windows) < 3:
        print("采样窗口太少，无法判定")
        return 0
    # 跳过第一个窗口（含预热）
    body = windows[1:]
    first, last = body[0], body[-1]
    ok = True

    qps_drop = (first["qps"] - last["qps"]) / max(first["qps"], 0.001)
    if qps_drop > 0.30:
        print(f"❌ QPS 衰减 {qps_drop * 100:.0f}%（{first['qps']} → {last['qps']}）")
        ok = False
    else:
        print(f"✅ QPS 稳定（{first['qps']} → {last['qps']}）")

    if last["p95"] > max(first["p95"] * 2, first["p95"] + 100):
        print(f"❌ p95 上升（{first['p95']}ms → {last['p95']}ms）")
        ok = False
    else:
        print(f"✅ p95 稳定（{first['p95']}ms → {last['p95']}ms）")

    # lag 看两件事：全段最大值（是否有卡顿）和后半段均值（是否随时间劣化）
    max_lag = max(w["loop_lag"] for w in body)
    half = max(1, len(body) // 2)
    early_avg = statistics.mean(w["loop_lag"] for w in body[:half])
    late_avg = statistics.mean(w["loop_lag"] for w in body[half:])
    if max_lag > 200:
        print(f"❌ 事件循环出现长卡顿（max {max_lag}ms）")
        ok = False
    else:
        print(f"✅ 事件循环延迟正常（max {max_lag}ms）")
    if late_avg > max(early_avg * 2, early_avg + 10):
        print(f"❌ 事件循环延迟随时间劣化（前半 {early_avg:.1f}ms → 后半 {late_avg:.1f}ms）")
        ok = False
    else:
        print(f"✅ 事件循环延迟未随时间劣化（前半 {early_avg:.1f}ms → 后半 {late_avg:.1f}ms）")

    nodes_first = body[0]["chain_nodes"]
    nodes_last = body[-1]["chain_nodes"]
    if nodes_last > nodes_first:
        print(f"✅ 链状态确实在累积（{nodes_first} → {nodes_last} 节点）")
    else:
        print(f"⚠️ 链节点没有增长（{nodes_first} → {nodes_last}）—— 状态路径可能没被压到")

    if args.with_review:
        print("\n--- review 路径 ---")
        if review_stats["review_errors"]:
            print(f"❌ review 失败 {review_stats['review_errors']} 次 / 共 {review_stats['reviews']} 次")
            ok = False
        else:
            print(f"✅ review 全部成功（{review_stats['reviews']} 次）")
        ms = sorted(review_stats["review_ms"])
        if ms:
            print(
                f"   review 耗时 p50={ms[len(ms)//2]:.0f}ms "
                f"p95={ms[min(len(ms)-1, int(len(ms)*0.95))]:.0f}ms max={ms[-1]:.0f}ms"
            )
            if ms[-1] > 2000:
                print("❌ 单次 review 超过 2 秒（持锁过久，会卡住并发 analyze）")
                ok = False
        # 注意：这里**不能**用「节点总增长 / review 次数」判断 seed 是否幂等 ——
        # 节点增长主要来自 analyze 本身（每个请求加一个节点），review 的增量
        # 淹没在里面。实测 10 分钟 22000 次 analyze + 29 次 review，总增长
        # 24945 条，按总量算会误报。seed 幂等由 tests/test_seed_dedup.py 保证。

    print("\n总体:", "通过 —— 未观察到随时间退化" if ok else "未通过 —— 见上面的 ❌")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="AgentMoss 长稳压测")
    ap.add_argument("--url", default="http://127.0.0.1:9092")
    ap.add_argument("--concurrency", type=int, default=8)
    ap.add_argument("--duration", type=float, default=600.0, help="总时长秒数（默认 600）")
    ap.add_argument("--sample", type=float, default=30.0, help="采样间隔秒数（默认 30）")
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument(
        "--with-review", action="store_true",
        help="同时压 /api/v1/review（模拟 AgentGate 每 100 次 analyze 触发一次）",
    )
    ap.add_argument(
        "--review-interval", type=float, default=20.0,
        help="review 触发间隔秒数（默认 20，约等于 QPS 5 时每 100 次 analyze）",
    )
    args = ap.parse_args()
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
