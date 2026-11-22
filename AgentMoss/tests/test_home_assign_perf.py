"""主目录赋值正则的性能回归（2026-11，N2）。

``HomeDeletionChecker._ASSIGN_RE`` 原用无界 ``[A-Za-z0-9_]*``：在 38KB 连续
字母串上每个起始位置都扫完整串再失败 → O(n²)（鸿蒙实测 27s）。变量名限长 64
后应回到线性。
"""
from __future__ import annotations

import re
import time

from agent_moss.engine.analyzer import analyze
from agent_moss.profiles import get_profile
from agent_moss.rules_loader import load_l2


def test_home_assign_regex_linear_on_long_alnum_run():
    cmd = "echo task-" + "A" * 38_000
    profile = get_profile("linux")
    start = time.time()
    result = analyze(
        session_id="perf-n2",
        prompt_session="",
        action_history=[],
        a_next={"action_type": "bash", "action_detail": cmd},
        reason="",
        profile=profile,
    )
    elapsed = time.time() - start
    assert result["decision"] in ("Allow", "Deny")
    # 5s：远大于修复后的线性耗时（~0.1-0.7s），但远小于 O(n²) 回退的几十秒；
    # 放宽是因为场景仓 CI 可能在并发负载下跑。
    assert elapsed < 5.0, f"38KB 命令耗时 {elapsed:.2f}s，疑似正则回溯未修复"


def test_exfil_combo_regex_linear_on_long_no_pipe_run():
    """EXFIL 组合链的 ``| nc`` 规则原带无界前缀 ``[^;&|\\n]*``，在无管道长串上 O(n²)。"""
    pats = (load_l2().get("combo_chains") or {}).get("stages", {}).get("EXFIL") or []
    text = "echo x-" + "aB1+/" * 10_000  # 50KB，无 | / ; / 换行
    start = time.time()
    for p in pats:
        re.compile(p, re.IGNORECASE).search(text)
    elapsed = time.time() - start
    assert elapsed < 5.0, f"EXFIL 正则耗时 {elapsed:.2f}s，疑似回溯未修复"
