"""L3 结局（``l3_outcome``）推导 —— 与 TS ``l3-outcome.test.ts`` 逐一对应。

背景（2026-11 招行）：客户看板上一条 Allow 分不清是「L3 认真判过放行」还是
「L3 挂了按 fail_open 瞎放」。``l3_outcome`` 是对外暴露的稳定枚举，
内部 ``source`` 有十几种取值且会演进，所以必须有一个**集中映射**并锁住。
"""

from __future__ import annotations

import pytest

from agent_moss.engine.types import (
    L3_OUTCOMES,
    SecurityJudgment,
    derive_l3_outcome,
)


def _j(source: str, allowed: bool = True) -> SecurityJudgment:
    return SecurityJudgment(allowed=allowed, reason="", source=source)


@pytest.mark.parametrize(
    ("source", "allowed", "expected"),
    [
        # L3 正常返回并采纳
        ("llm", True, "ok"),
        ("llm", False, "ok"),
        ("llm_extracted", True, "ok"),
        # content 空、判定取自 reasoning（判定仍有效，但要提示模型行为异常）
        ("llm_reasoning_fallback", True, "reasoning_fallback"),
        ("llm_reasoning_fallback", False, "reasoning_fallback"),
        # L3 未启用
        ("heuristic_and_logic_only", True, "skipped"),
        ("disabled", True, "skipped"),
        # L3 失败：按 fail_mode 分叉
        ("llm_failure_fallback", True, "fail_open"),
        ("llm_failure_fallback", False, "fail_closed"),
        # 熔断打开（连请求都没发）—— 必须与普通失败区分
        ("llm_circuit_open", True, "circuit_open"),
        ("llm_circuit_open", False, "circuit_open"),
        # L3 失败但前序层已拦截（结论不受影响）
        ("llm_failure_with_violation", False, "failed_but_blocked"),
        # 前两层已给出结论，没走到 L3
        ("whitelist_bypass", True, "not_reached"),
        ("heuristic", False, "not_reached"),
        ("logic_rule", False, "not_reached"),
        ("heuristic_script_scan", False, "not_reached"),
        ("formal_engine", False, "not_reached"),
        ("brain_rule", False, "not_reached"),
        # 未知 source（未来新增）落 not_reached，绝不误报成 ok/失败
        ("some_future_source", True, "not_reached"),
    ],
)
def test_derive_l3_outcome(source: str, allowed: bool, expected: str) -> None:
    assert derive_l3_outcome(_j(source, allowed)) == expected


def test_every_declared_outcome_is_reachable() -> None:
    """``L3_OUTCOMES`` 里声明的每个取值都必须真的能被某个 source 推导出来。

    防的是「文档/字段里写了一个取值，但实现永远推不出它」—— 调用方按文档
    写了告警分支却永远不触发，属于最隐蔽的一类漂移。
    """
    sources = (
        "llm", "llm_extracted", "llm_reasoning_fallback",
        "heuristic_and_logic_only", "disabled",
        "llm_failure_fallback", "llm_circuit_open",
        "llm_failure_with_violation",
        "whitelist_bypass", "heuristic", "logic_rule", "formal_engine",
    )
    derivable = {
        derive_l3_outcome(_j(src, allowed))
        for src in sources
        for allowed in (True, False)
    }
    assert derivable == set(L3_OUTCOMES)


def test_case_insensitive_source() -> None:
    """source 大小写不应影响判定（TS 侧同样 lower-case）。"""
    assert derive_l3_outcome(_j("LLM", True)) == "ok"
    assert derive_l3_outcome(_j("LLM_Failure_Fallback", True)) == "fail_open"
