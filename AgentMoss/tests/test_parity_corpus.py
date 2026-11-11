# -*- coding: utf-8 -*-
"""双端一致性语料（Python 侧）。

Python 和 TS 是同一套规则的两份实现，凡是"两边各写一遍"的逻辑迟早分叉。
2026-09 连续分叉过三次（白名单只看首段、危险命令扫描的文本带 action_type 前缀、
L2 字面量判定条件不一致、"按工具名免检"只有 Python 有），每次都是用户追问
"再检查一次"才被发现 —— **人工想攻击手法想不全**。

语料是**穷举生成**的（13 个命令头 × 5 种连接符 × 18 个危险尾巴 + 变体包裹 +
工具名伪装 + 只读白名单 + Windows 关机等，1401 条）。这个测试让分叉在改动的
当下就变成红灯，而不是等下次追问。

语料里存的是**两端一致时的判定**（冻结的共识，不是真理来源）：

- 改了规则、两端一起变了 → 跑 ``python3 scripts/gen_parity_corpus.py`` 重新生成，
  git diff 就是本次改动的行为影响面；
- 只改了一端 → 这个测试会红。

生成器会先跑两端并断言一致才写入，所以不会把某一端的错误行为固化成"标准答案"。
"""

import json
from pathlib import Path

from agent_moss.engine.analyzer import analyze
from agent_moss.profiles import get_profile

CORPUS_PATH = Path(__file__).parent / "parity" / "corpus.json"


def _load_cases() -> list[dict]:
    data = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    return data["cases"]


def _decide(case: dict, index: int) -> tuple[str, str, str]:
    """保持与 parity 语料一致的调用形状。"""
    result = analyze(
        # session_id 固定且唯一：避开 AgentMoss 的决策缓存把不同输入串味
        session_id=f"parity-{index}",
        prompt_session="",
        # 与 TS 侧同一份 snake_case 输入（含 output —— consent 类规则看的就是它）
        action_history=case.get("action_history", []),
        a_next={
            "action_type": case["action_type"],
            "action_detail": case["action_detail"],
        },
        reason="",
        config=None,
        cache=None,
        profile=get_profile(case["os_type"]),
        llm_config=None,
        cwd=case.get("cwd", "/tmp"),
        agent_id=case.get("agent_id", ""),
        scenario_id=case.get("scenario_id", ""),
        llm_log_path=None,
        prompt_history=[],
        session_history=[],
    )
    return (
        result["decision"],
        str(result.get("risk_level", "") or ""),
        str(result.get("risk_type", "") or ""),
    )


def test_corpus_exists_and_is_nontrivial():
    """语料得真的在、且够大 —— 防止有人为了绿灯把它清空。"""
    cases = _load_cases()
    assert len(cases) > 1000, f"语料只有 {len(cases)} 条，像是被清过"
    assert {"linux", "windows"} <= {c["os_type"] for c in cases}


def test_python_matches_the_frozen_corpus():
    cases = _load_cases()
    mismatches: list[str] = []
    for i, case in enumerate(cases):
        got, got_level, got_type = _decide(case, i)
        parts: list[str] = []
        if got != case["expected"]:
            parts.append(f"decision 语料={case['expected']} Python={got}")
        if case.get("expected_risk_level") is not None and got_level != case["expected_risk_level"]:
            parts.append(f"risk_level 语料={case['expected_risk_level']} Python={got_level}")
        if case.get("expected_risk_type") is not None and got_type != case["expected_risk_type"]:
            parts.append(f"risk_type 语料={case['expected_risk_type']} Python={got_type}")
        if parts:
            mismatches.append(
                f"[{case['os_type']}/{case['action_type']}] "
                f"{case['action_detail']!r} " + " | ".join(parts)
            )
    if mismatches:
        print(f"\nPython 与语料不一致 {len(mismatches)}/{len(cases)} 条：")
        for line in mismatches[:30]:
            print("  " + line)
        if len(mismatches) > 30:
            print(f"  … 另有 {len(mismatches) - 30} 条")
        print(
            "\n若这是**有意**改规则：两端一起改完后跑 "
            "python3 scripts/gen_parity_corpus.py 重新生成语料；"
            "若只改了一端，那是分叉，去查哪端对。\n"
        )
    assert mismatches == []
