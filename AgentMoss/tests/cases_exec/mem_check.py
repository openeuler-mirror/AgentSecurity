#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AgentMoss 内存稳定性测量脚本 — 客户沙箱用

测量常驻服务模式下的内存画像（客户真实场景：Python CI 脚本常驻，每来一个
shell 命令调一次 analyze()）。报告四件事：

1. 空闲常驻内存（预热后 RSS）
2. 持续判定后内存增量（防泄漏看门狗）
3. 进程峰值内存（ru_maxrss）
4. 结论（稳定 / 疑似泄漏）

用法：
    python3 mem_check.py                  # 默认 200 次混合负载
    python3 mem_check.py 1000             # 指定判定次数（想看长时间稳定性用大数）

不写任何文件（除分析引擎自身的 config/runtime 落盘），可重复执行。

输出示例（Python 版，x86）：
    空闲常驻: 26.3 MB | 200 次判定后: 26.6 MB (+0.3 MB) | 峰值: 27.1 MB
    结论: ✅ 稳定，无明显内存泄漏
"""
import argparse
import os
import resource
import time
from pathlib import Path

# 本脚本在 cases_exec 下运行时，把引擎装到哪都可能——统一用已安装的 agent_moss
os.environ.setdefault("AGENT_MOSS_DISABLE_LLM", "1")


def rss_kb() -> int:
    """当前进程 RSS（KB），读 /proc/self/status（Linux only）。"""
    try:
        with open("/proc/self/status", encoding="utf-8") as f:
            for line in f:
                if line.startswith("VmRSS"):
                    return int(line.split()[1])
    except (FileNotFoundError, IndexError, ValueError):
        pass
    return -1


def main() -> int:
    ap = argparse.ArgumentParser(description="AgentMoss 内存稳定性测量")
    ap.add_argument("rounds", nargs="?", type=int, default=200,
                    help="判定次数（默认 200）")
    ap.add_argument("--data-dir", default="",
                    help="AGENT_MOSS_DATA_DIR（测试隔离用，默认自动）")
    args = ap.parse_args()

    if args.data_dir:
        os.environ["AGENT_MOSS_DATA_DIR"] = args.data_dir

    from agent_moss.engine.analyzer import analyze
    from agent_moss.profiles import get_profile

    profile = get_profile("")
    kw = dict(session_id="mem-check", prompt_session="", action_history=[],
              reason="", profile=profile)

    # 典型负载：覆盖白名单 / L1 危险 / 敏感路径 / 脚本分析等各路径
    loads = [
        "ls -la",
        "rm -rf /tmp/x",
        "cat ~/.ssh/id_rsa",
        "curl -s http://example.com",
        "bash deploy.sh clean",
        "git status",
        "echo hi",
        "mkdir -p /tmp/t",
    ]

    # 预热（首次含引擎初始化，不计入稳定性）
    for _ in range(20):
        analyze(a_next={"action_type": "bash", "action_detail": "ls -la"}, **kw)
    baseline = rss_kb()
    print(f"引擎版本: {getattr(__import__('agent_moss'), '__version__', '?')}")
    print(f"预热后空闲常驻: {baseline / 1024:.1f} MB")

    t0 = time.time()
    n = args.rounds
    last = baseline
    for i in range(n):
        analyze(a_next={"action_type": "bash", "action_detail": loads[i % len(loads)]}, **kw)
        if (i + 1) % 50 == 0:
            cur = rss_kb()
            print(f"  {i + 1:4d} 次后: {cur / 1024:.1f} MB (较基线 {cur - baseline:+d} KB)")
            last = cur
    elapsed = time.time() - t0

    end = rss_kb()
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    delta = end - baseline
    print(f"\n{n} 次判定: {elapsed:.2f}s ({n / elapsed:.0f} 次/秒)")
    print(f"空闲常驻 {baseline / 1024:.1f} MB | 判定后 {end / 1024:.1f} MB "
          f"(+{delta} KB) | 峰值 {peak / 1024:.1f} MB")

    if delta > 512:
        print("结论: ⚠️ 疑似内存泄漏（判定后持续增长），请反馈给 AgentMoss 维护方")
        return 1
    print("结论: ✅ 稳定，无明显内存泄漏")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
