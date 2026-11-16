#!/usr/bin/env python3
"""AgentMoss 分层压测 —— 找出「本机 + 本模型」真正能吃下的并发。

为什么要分层（2026-11 招行现场）：

- **L1/L2（纯 CPU）**：Python 有 GIL，单进程多线程不线性扩展。并发从 1 加到 32
  时吞吐可能不升反降（实测 8 核：32.7 → 23.7 req/s），只是 p50 从 29ms 涨到
  1300ms。这一段要找出**吞吐拐点**。
- **L3（等 LLM）**：瓶颈在下游模型服务，不在本机。本机开再多并发也只是排队。
  这一段要找出**不触发超时的最大并发**。

用法：

    # 终端 1：起服务（L1/L2 模式，关闭并发闸门以便测真实能力）
    AGENT_MOSS_DISABLE_LLM=1 AGENT_MOSS_POOL_BIZ=0 agent-moss server --port 9090

    # 终端 2：
    python3 scripts/bench_analyze.py --url http://127.0.0.1:9090 \\
        --concurrency 1,2,4,8,16,32 --duration 10

    # L3 模式（需要真实 LLM key）：把终端 1 的 AGENT_MOSS_DISABLE_LLM 去掉，
    # 并发从 1 开始逐档加，观察 p95 与超时率。
    python3 scripts/bench_analyze.py --mode l3 --concurrency 1,2,4,8

输出：每个并发档位的 QPS / p50 / p95 / p99 / 错误率 / 503 数，以及一张
「并发 → QPS」拐点表，可直接抄进部署文档。

注意：`AGENT_MOSS_POOL_BIZ=0` 会关闭路径池限制 —— 只在压测时这么设，
生产必须保留（否则过载时没有保护）。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
import time
import uuid

try:
    import httpx
except ImportError:  # pragma: no cover
    print("需要 httpx：pip install httpx", file=sys.stderr)
    raise SystemExit(2)


def build_payload(idx: int, mode: str) -> dict:
    """构造一条典型的 analyze 请求。

    - L1/L2 模式：一条会走 L2 逻辑规则、但不触发 L1 命中的普通命令
      （`cat` 读配置文件 + `grep`），能真实压到 L2 的敏感路径/意图判定。
    - L3 模式：同上 —— L3 是否真正调用由服务端配置决定，压测脚本不区分。
    """
    action_detail = (
        "cat /etc/hostname && grep -c processor /proc/cpuinfo "
        f"&& echo 'bench-{idx}'"
    )
    return {
        "session_id": f"bench-{uuid.uuid4().hex[:8]}",
        "prompt_session": f"压测请求 {idx}：查看机器信息",
        "action_history": [],
        "a_next": {
            "action_type": "execute",
            "action_detail": action_detail,
        },
        "reason": "benchmark",
        "os_type": "linux",
        "cwd": "/tmp",
        "metadata": {"bench": True, "mode": mode},
    }


async def one_request(client: httpx.AsyncClient, url: str, idx: int, mode: str) -> tuple[bool, float, int]:
    """发一条请求，返回 (是否成功, 耗时秒, 状态码)。"""
    t0 = time.perf_counter()
    try:
        resp = await client.post(f"{url}/api/v1/analyze", json=build_payload(idx, mode))
        elapsed = time.perf_counter() - t0
        return resp.status_code == 200, elapsed, resp.status_code
    except Exception:  # noqa: BLE001
        return False, time.perf_counter() - t0, -1


async def run_level(url: str, concurrency: int, duration: float, mode: str, timeout: float) -> dict:
    """在一个并发档位上跑固定时长，统计延迟分位数。"""
    latencies: list[float] = []
    errors = 0
    codes: dict[int, int] = {}
    stop_at = time.monotonic() + duration
    counter = {"n": 0}

    async with httpx.AsyncClient(timeout=timeout, limits=httpx.Limits(max_connections=concurrency * 2)) as client:

        async def worker() -> None:
            while time.monotonic() < stop_at:
                ok, elapsed, code = await one_request(client, url, counter["n"], mode)
                counter["n"] += 1
                latencies.append(elapsed)
                codes[code] = codes.get(code, 0) + 1
                if not ok:
                    errors += 1

        started = time.monotonic()
        await asyncio.gather(*(worker() for _ in range(concurrency)))
        wall = time.monotonic() - started

    if not latencies:
        return {"concurrency": concurrency, "qps": 0, "p50": 0, "p95": 0, "p99": 0,
                "errors": 0, "codes": {}, "total": 0}
    lat_ms = sorted(x * 1000 for x in latencies)

    def pct(p: float) -> float:
        idx = min(len(lat_ms) - 1, max(0, int(len(lat_ms) * p) - 1))
        return lat_ms[idx]

    return {
        "concurrency": concurrency,
        "qps": round(len(latencies) / wall, 1) if wall > 0 else 0,
        "p50": round(pct(0.50), 1),
        "p95": round(pct(0.95), 1),
        "p99": round(pct(0.99), 1),
        "errors": errors,
        "error_rate": round(errors / len(latencies) * 100, 2),
        "codes": codes,
        "total": len(latencies),
    }


async def main_async(args: argparse.Namespace) -> int:
    # 先探活
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{args.url}/api/v1/health")
            if r.status_code != 200:
                print(f"健康检查失败: HTTP {r.status_code}", file=sys.stderr)
                return 1
            print(f"服务健康: {r.json()}")
    except Exception as e:  # noqa: BLE001
        print(f"连不上 {args.url}: {e}", file=sys.stderr)
        return 1

    results: list[dict] = []
    print(f"\n模式={args.mode}  每档 {args.duration}s\n")
    header = f"{'并发':>4} {'QPS':>8} {'p50(ms)':>9} {'p95(ms)':>9} {'p99(ms)':>9} {'错误率':>7} {'请求数':>7}  状态码"
    print(header)
    print("-" * len(header))
    for conc in args.concurrency:
        r = await run_level(args.url, conc, args.duration, args.mode, args.timeout)
        results.append(r)
        codes = ",".join(f"{k}:{v}" for k, v in sorted(r["codes"].items()))
        print(
            f"{r['concurrency']:>4} {r['qps']:>8} {r['p50']:>9} {r['p95']:>9} "
            f"{r['p99']:>9} {r.get('error_rate', 0):>6}% {r['total']:>7}  {codes}"
        )

    # 拐点分析：QPS 最高的那一档就是本机的吞吐上限
    if results:
        best = max(results, key=lambda x: x["qps"])
        print(f"\n吞吐最高档：并发 {best['concurrency']}（{best['qps']} req/s，p95 {best['p95']}ms）")
        over = [r for r in results if r["p95"] > args.p95_budget]
        if over:
            first = over[0]
            print(
                f"p95 超过 {args.p95_budget}ms 的第一档：并发 {first['concurrency']}"
                f"（p95 {first['p95']}ms，QPS {first['qps']}）"
            )
            print(f"→ 建议生产并发上限取 **{max(1, first['concurrency'] // 2)}** 左右（留一半余量）")
        else:
            print(f"所有档位 p95 均在 {args.p95_budget}ms 内")

    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="AgentMoss 分层压测")
    ap.add_argument("--url", default="http://127.0.0.1:9090")
    ap.add_argument("--concurrency", default="1,2,4,8,16",
                    help="并发档位，逗号分隔（默认 1,2,4,8,16）")
    ap.add_argument("--duration", type=float, default=10.0, help="每档持续秒数（默认 10）")
    ap.add_argument("--mode", choices=["l1l2", "l3"], default="l1l2")
    ap.add_argument("--timeout", type=float, default=60.0, help="单请求超时（默认 60s）")
    ap.add_argument("--p95-budget", type=float, default=500.0,
                    help="p95 预算毫秒（默认 500），用于给出建议并发")
    ap.add_argument("--json", action="store_true", help="额外输出 JSON（便于存档对比）")
    args = ap.parse_args()
    args.concurrency = [int(x) for x in str(args.concurrency).split(",") if x.strip()]
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
