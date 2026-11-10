#!/usr/bin/env python3
"""AgentMoss 大体量压测 — 模拟 agentgate 长期运行后 L2.2 formal 引擎的延迟/内存/FP 基线。

数据源：tests/bench/data/（gen_agent_gate_data.py 生成）或任意 AgentGate 存储
（SQLite tool_calls 表 / JSON 目录），经 agent_gate_reader 统一加载。

测量内容（每档规模 = 累计 N 个动作的历史）：
1. builder 耗时（行为图构建，含 O(N^2) 跨会话 data 边检测）
2. FormalEngine.verify 全量验证耗时（p50/p95）
3. analyzer.analyze 全链路（L1→L2→L2.2→L3）单次耗时 + FP 采样
   （良性动作被 Deny 且 violated_layers 含 L2.2 → formal 引擎误报）
4. 峰值内存 RSS

健壮性：
- 单次 verify / 单次 analyze 硬超时（signal alarm），超时记 timed_out 并停止加大规模
- 每档跑完立即增量落盘（被打断不丢已测档位）
- 膝盖点检测：某档单次超过 max_single_s 即判为"规模上限"，不再加档

用法：
    AGENT_MOSS_DISABLE_LLM=1 python3 tests/bench/run_bench.py
    AGENT_MOSS_DISABLE_LLM=1 python3 tests/bench/run_bench.py --db /path/agent_gate_ts.db --scales 1000,5000
    AGENT_MOSS_DISABLE_LLM=1 python3 tests/bench/run_bench.py --json-dir /path/tool_calls --repeats 5
"""

from __future__ import annotations

import argparse
import json
import os
import resource
import signal
import statistics
import sys
import time
from pathlib import Path

# 压测保持确定性：禁 LLM（与 CI 一致），不依赖本机 API key
os.environ.setdefault("AGENT_MOSS_DISABLE_LLM", "1")

import agent_moss  # noqa: F401  确保包路径可用


class _Timeout(Exception):
    """单次调用超时（signal alarm 触发）。"""


def _alarm_handler(signum, frame):  # noqa: ARG001
    raise _Timeout()


def _call_with_timeout(fn, timeout_s: float):
    """在硬超时内调用 fn()；超时抛 _Timeout。"""
    signal.signal(signal.SIGALRM, _alarm_handler)
    signal.alarm(max(1, int(timeout_s)))
    try:
        return fn()
    finally:
        signal.alarm(0)


def load_sessions(args) -> list[dict]:
    """经 agent_gate_reader 统一加载（SQLite 优先，JSON 兜底）。"""
    from agent_moss.server.agent_gate_reader import (
        load_agent_gate_sessions,
        read_agent_gate_json_sessions,
        read_agent_gate_sessions,
    )
    if args.json_dir:
        return read_agent_gate_json_sessions(dir_path=args.json_dir, limit=args.limit)
    if args.db:
        return read_agent_gate_sessions(db_path=args.db, limit=args.limit)
    return load_agent_gate_sessions()


def scale_sessions(sessions: list[dict], target_actions: int) -> list[dict]:
    """取累计 target_actions 个动作的 sessions 前缀（模拟运行到该规模的历史）。"""
    out: list[dict] = []
    total = 0
    for s in sessions:
        hist = s.get("action_history", []) or []
        if total + len(hist) > target_actions:
            if out:
                break
            hist = hist[:target_actions]
        out.append({"session_id": s.get("session_id", "s"), "action_history": hist})
        total += len(hist)
        if total >= target_actions:
            break
    return out


def time_verify(sessions: list[dict], repeats: int, max_single_s: float):
    """返回 (build_times, verify_times, cross_edges, timed_out)。

    build = 仅行为图构建；verify = FormalEngine.verify 全量（含内部重建图）。
    单次超过 max_single_s → timed_out=True（不再重复）。
    """
    from agent_moss.engine.formal_engine import FormalEngine
    from agent_moss.engine.formal_engine.builder import build_multi_session_graph

    engine = FormalEngine()
    build_times: list[float] = []
    verify_times: list[float] = []
    cross_edges = 0
    timed_out = False
    for i in range(repeats):
        # 1) 仅 builder
        t0 = time.perf_counter()
        try:
            g = _call_with_timeout(lambda: build_multi_session_graph(sessions), max_single_s)
        except _Timeout:
            timed_out = True
            break
        t1 = time.perf_counter()
        build_times.append(t1 - t0)
        if i == 0:
            cross_edges = len(g.cross_edges)
        # 2) 全量 verify（内部重建图，模拟真实调用路径）
        t2 = time.perf_counter()
        try:
            _call_with_timeout(lambda: engine.verify(sessions=sessions), max_single_s)
        except _Timeout:
            timed_out = True
            break
        t3 = time.perf_counter()
        verify_times.append(t3 - t2)
        # 单次已接近上限，不再重复（时间预算有限）
        if (t3 - t0) > max_single_s / 2:
            break
    return build_times, verify_times, cross_edges, timed_out


def sample_analyze(sessions: list[dict], n_samples: int, max_single_s: float, budget_s: float):
    """在历史末尾采样良性 a_next 跑全链路 analyze，统计 formal 引擎误报。

    良性动作 = 不命中任何 stage 的动作（生成器的良性池不会命中阶段）。
    误报 = decision == Deny 且 violated_layers 含 "L2.2"。

    预算控制：单样本硬超时 max_single_s，档内总预算 budget_s，超预算提前停止。
    """
    from agent_moss.engine.analyzer import analyze
    from agent_moss.engine.formal_engine.builder import _mark_stage

    results = []
    total = sum(len(s.get("action_history", [])) for s in sessions)
    if total == 0:
        return results
    last = sessions[-1]
    hist = last.get("action_history", []) or []
    prior = sessions[:-1]

    benign_candidates = [
        a for a in hist if isinstance(a, dict) and not _mark_stage(str(a.get("action_detail", "")))
    ]
    if not benign_candidates:
        return results

    step = max(1, len(benign_candidates) // n_samples)
    budget_deadline = time.monotonic() + budget_s
    seen = 0
    for i in range(0, len(benign_candidates), step):
        if seen >= n_samples or time.monotonic() > budget_deadline:
            break
        a_next = benign_candidates[i]

        def _one():
            return analyze(
                session_id=str(last.get("session_id", "s")),
                prompt_session="压测任务：正常开发操作",
                action_history=hist,
                a_next=a_next,
                reason="压测：普通操作",
                session_history=prior,
            )

        t0 = time.perf_counter()
        try:
            r = _call_with_timeout(_one, max_single_s)
        except _Timeout:
            results.append({"decision": "TIMEOUT", "dur_s": round(max_single_s, 1)})
            break
        except Exception as e:  # noqa: BLE001 压测不中断
            results.append({"decision": "ERROR", "error": str(e)[:120], "dur_s": round(time.perf_counter() - t0, 3)})
            seen += 1
            continue
        dur = time.perf_counter() - t0
        layers = r.get("violated_layers", []) or []
        results.append({
            "action_detail": str(a_next.get("action_detail", ""))[:100],
            "decision": r.get("decision", ""),
            "denied_by_formal": r.get("decision") == "Deny" and "L2.2" in layers,
            "violated_layers": layers,
            "risk_level": r.get("risk_level", ""),
            "dur_s": round(dur, 3),
        })
        seen += 1
    return results


def report_scale(name: str, n_actions: int, result: dict) -> None:
    bt = result.get("build_times") or []
    vt = result.get("verify_times") or []
    fp = result.get("analyze_samples") or []

    def pct(v, p):
        if len(v) >= 3:
            return round(statistics.quantiles(v, n=100)[p - 1] * 1000, 1)
        return round(statistics.mean(v) * 1000, 1) if v else 0.0

    fp_denied = sum(1 for s in fp if s.get("denied_by_formal"))
    fp_total = sum(1 for s in fp if s.get("decision") in ("Allow", "Deny"))
    fp_rate = f"{fp_denied}/{fp_total}" if fp_total else "-"
    timed = " TIMEOUT" if result.get("timed_out") else ""
    print(f"  {name:<8} 动作={n_actions:<8} "
          f"builder p50={pct(bt, 50):>9.1f}ms "
          f"verify p50={pct(vt, 50):>9.1f}ms "
          f"cross_edges={result.get('cross_edges', 0):<8} "
          f"analyze样本={len(fp)} FP={fp_rate}{timed}")


def run_bench(args) -> dict:
    print("加载 AgentGate 数据...")
    sessions = load_sessions(args)
    total = sum(len(s.get("action_history", [])) for s in sessions)
    print(f"  sessions={len(sessions)} 动作总数={total}")
    if not sessions:
        print("ERROR: 无数据可压测（检查 --db/--json-dir 或先生成 tests/bench/data）")
        sys.exit(2)

    scales = [int(x) for x in args.scales.split(",")]
    scales = sorted({min(s, total) for s in scales if s <= total} | {min(total, 1000000)})
    if not scales:
        sys.exit("ERROR: 无有效规模档")

    rss_start = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    results: dict = {"scales": {}, "summary": {}}
    out_path = args.json_out or str(Path("tests/bench/data") / "results" / "run_bench.json")

    print("开始分档测量（每档 = 累计 N 动作历史的全量 verify + analyze 采样）：")
    for scale in scales:
        subs = scale_sessions(sessions, scale)
        n = sum(len(s.get("action_history", [])) for s in subs)
        r: dict = {}
        r["build_times"], r["verify_times"], r["cross_edges"], r["timed_out"] = time_verify(
            subs, args.repeats, max_single_s=args.max_single
        )
        if not r["timed_out"]:
            r["analyze_samples"] = sample_analyze(subs, args.samples, args.max_single, budget_s=args.budget)
        else:
            r["analyze_samples"] = []
        results["scales"][str(n)] = r
        report_scale(f"scale", n, r)
        # 增量落盘：每档完成即保存
        results["summary"] = {"total_actions": total, "sessions": len(sessions),
                              "rss_peak_kb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        # 膝盖点：单次超时或耗时超限 → 停止加档
        if r["timed_out"]:
            print(f"  → 规模 {n} 单次验证超 {args.max_single}s，判定为当前实现规模上限，停止加档")
            break

    rss_end = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    results["summary"] = {
        "total_actions": total,
        "sessions": len(sessions),
        "rss_peak_kb": rss_end,
        "rss_delta_kb": rss_end - rss_start,
    }
    print(f"  峰值内存 RSS: {rss_end} KB（增量 {rss_end - rss_start} KB）")
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description="AgentMoss 大体量压测（formal 引擎延迟/内存/FP 基线）")
    ap.add_argument("--db", default="", help="AgentGate SQLite 路径（默认自动发现 tests/bench/data）")
    ap.add_argument("--json-dir", default="", help="AgentGate JSON 目录（tool_calls/*.json）")
    ap.add_argument("--scales", default="1000,5000,10000,20000,50000", help="规模档（累计动作数）")
    ap.add_argument("--repeats", type=int, default=3, help="每档 verify 重复次数")
    ap.add_argument("--samples", type=int, default=20, help="每档 analyze 采样数")
    ap.add_argument("--max-single", type=float, default=15.0, help="单次 verify/analyze 硬超时（秒）")
    ap.add_argument("--budget", type=float, default=30.0, help="每档 analyze 采样总预算（秒）")
    ap.add_argument("--limit", type=int, default=1000000, help="reader 读取上限")
    ap.add_argument("--json-out", default="", help="结果输出 JSON 路径（默认 tests/bench/data/results/）")
    args = ap.parse_args()

    t0 = time.time()
    results = run_bench(args)
    results["duration_s"] = round(time.time() - t0, 1)

    out_path = args.json_out or str(Path("tests/bench/data") / "results" / "run_bench.json")
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"结果已保存: {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
