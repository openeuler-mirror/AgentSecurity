"""L3 结局（``l3_outcome``）推导 —— 与 TS ``l3-outcome.test.ts`` 逐一对应。

背景（2026-11 招行）：客户看板上一条 Allow 分不清是「L3 认真判过放行」还是
「L3 挂了按 fail_open 瞎放」。``l3_outcome`` 是对外暴露的稳定枚举，
内部 ``source`` 有十几种取值且会演进，所以必须有一个**集中映射**并锁住。
"""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from agent_moss.engine import analyzer
from agent_moss.engine.types import (
    L3_OUTCOMES,
    SecurityJudgment,
    derive_l3_outcome,
)
from agent_moss.infra.config import CacheConfig, Config, RetryConfig, TimeoutConfig
from agent_moss.infra.policy_cache import PolicyCache


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
        ("llm_budget_skipped", True, "skipped"),
        ("llm_budget_skipped", False, "skipped"),
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
        "llm_budget_skipped",
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


@pytest.mark.parametrize("include_l3_diagnostics", [True, False])
def test_circuit_reason_is_preserved_when_policy_generation_fails(monkeypatch, include_l3_diagnostics):
    circuit_reason = "LLM 分析失败（warn-allow，fail_open）: fixture circuit open"
    monkeypatch.setattr(analyzer, "judge_security", Mock(return_value=SecurityJudgment(
        allowed=True, source="llm_circuit_open", reason=circuit_reason,
    )))
    monkeypatch.setattr(analyzer, "MossLogger", Mock())
    monkeypatch.setattr(analyzer, "is_policy_gen_enabled", lambda: True)
    monkeypatch.setattr(analyzer, "call_llm", Mock(side_effect=ValueError("fixture policy generation failure")))
    cache = Mock()
    cache.get.return_value = None
    config = Config(timeout=TimeoutConfig(step_interval=0), retry=RetryConfig(max_retries=1))

    result = analyzer.analyze(
        session_id="policy-circuit", prompt_session="", action_history=[],
        a_next={"action_type": "bash", "action_detail": "echo example"}, reason="",
        config=config, cache=cache, include_l3_diagnostics=include_l3_diagnostics,
    )

    assert result["decision"] == "Deny"
    assert "fixture policy generation failure" in result["reason"]
    assert result["l3_outcome"] == "circuit_open"
    if include_l3_diagnostics:
        assert result["_l3_circuit_reason"] == circuit_reason
    else:
        assert "_l3_circuit_reason" not in result


@pytest.fixture
def budget_model(monkeypatch, default_config):
    from agent_moss.engine import llm_analyzer

    monkeypatch.setenv("AGENT_MOSS_DISABLE_HEURISTIC", "1")
    monkeypatch.setenv("AGENT_MOSS_DISABLE_LOGIC_RULES", "1")
    monkeypatch.setenv("AGENT_MOSS_DISABLE_LLM", "0")
    monkeypatch.setenv("AGENT_MOSS_BRAIN_ENABLED", "0")
    monkeypatch.setenv("AGENT_MOSS_ENABLE_POLICY_GEN", "0")
    monkeypatch.setenv("AGENT_MOSS_SAVE_POLICY", "0")
    monkeypatch.setenv("AGENT_MOSS_LLM_MAX_PROMPT_TOKENS", "500")
    monkeypatch.setenv("AGENT_MOSS_LLM_PROMPT_SESSION_MIN_CHARS", "2000")
    monkeypatch.setenv("AGENT_MOSS_LLM_BUDGET_MODE", "hard")
    monkeypatch.setattr(analyzer, "get_default_config", lambda: default_config)
    monkeypatch.setattr(analyzer, "get_default_cache", lambda: PolicyCache(CacheConfig(enabled=False)))
    call = Mock(side_effect=ValueError("fixture model failure"))
    monkeypatch.setattr(llm_analyzer, "call_llm", call)
    return call


@pytest.mark.parametrize(("fail_mode", "decision"), [("fail_open", "Allow"), ("fail_closed", "Deny")])
def test_hard_budget_skip_reaches_python_and_http(monkeypatch, budget_model, fail_mode, decision):
    from fastapi.testclient import TestClient

    from agent_moss.server.app import create_app

    monkeypatch.setenv("AGENT_MOSS_LLM_FAIL_MODE", fail_mode)
    payload = {
        "session_id": "hard-budget",
        "prompt_session": "检查测试输出。" * 500,
        "a_next": {"action_type": "fixture_tool", "action_detail": "生成摘要"},
        "action_history": [],
        "reason": "测试",
    }

    result = analyzer.analyze(**payload)
    assert result["source"] == "llm_budget_skipped"
    with TestClient(create_app()) as client:
        response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 200
    for verdict in (result, response.json()):
        assert verdict["decision"] == decision
        assert verdict["l3_outcome"] == "skipped"
        assert verdict["violated_layers"] == []
        assert verdict["degraded"] == ["l3_budget_floor_exceeds"]
    budget_model.assert_not_called()


def test_soft_budget_degradation_survives_model_failure(monkeypatch, budget_model):
    monkeypatch.setenv("AGENT_MOSS_LLM_BUDGET_MODE", "soft")
    monkeypatch.setenv("AGENT_MOSS_LLM_FAIL_MODE", "fail_closed")
    result = analyzer.analyze(
        session_id="soft-budget", prompt_session="检查测试输出。" * 500, action_history=[],
        a_next={"action_type": "fixture_tool", "action_detail": "生成摘要"}, reason="测试",
    )

    budget_model.assert_called_once()
    assert result["decision"] == "Deny"
    assert result["l3_outcome"] == "fail_closed"
    assert result["degraded"] == ["l3_budget_unreachable"]
