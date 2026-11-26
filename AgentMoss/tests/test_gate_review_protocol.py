"""Moss accepts review correlation only from the configured Gate."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from agent_moss.engine import analyzer
from agent_moss.engine.formal_engine import chain_state, stateful
from agent_moss.engine.formal_engine.stateful import StatefulAnalysisUnavailable, UnconfirmedGateRetry
from agent_moss.infra import metrics, security_policy
from agent_moss.server import routes
from agent_moss.server.app import _PooledLimiter, _RateLimiter, create_app


CALL_ID = "a" * 32
CALL_TIME = 1795392000000000


def _headers(token="dedicated", call_id=CALL_ID):
    return {
        "Authorization": f"Bearer {token}",
        "X-AgentGate-Require-Identity": "1",
        "X-AgentGate-Call-Id": call_id,
    }


def _body(**changes):
    return {
        "session_id": "gate-session",
        "a_next": {"action_type": "bash", "action_detail": "echo example"},
        "gate_call_id": CALL_ID,
        "gate_call_time_us": CALL_TIME,
        "gate_delivery_uncertain": False,
        **changes,
    }


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_AUTH_MODE", "auto")
    monkeypatch.setenv("AGENT_MOSS_AUTH_TOKEN", "global")
    monkeypatch.setenv("AGENT_MOSS_AGENT_TOKENS", "example=agent")
    monkeypatch.setenv("AGENT_MOSS_GATE_AUTH_TOKEN", "dedicated")
    monkeypatch.setattr(analyzer, "analyze", lambda **kwargs: {
        "decision": "Allow", "reason": "fixture", "policy": "fixture allow policy",
    })
    return TestClient(create_app())


def test_gate_identity_is_required_for_correlation(client, monkeypatch):
    for token in ("global", "agent"):
        response = client.post("/api/v1/analyze", headers=_headers(token), json=_body())
        assert response.status_code == 403
        assert "gate_call_id" not in response.json()
    response = client.post("/api/v1/analyze", headers=_headers("wrong"), json=_body())
    assert response.status_code == 401
    assert client.get("/console/api/layers", headers=_headers()).status_code == 401
    assert client.post("/api/v1/review", headers=_headers("global"), json={}).status_code == 403

    malformed = _body(gate_call_id=[], gate_call_time_us={}, gate_delivery_uncertain="bad")
    for token in ("global", "agent"):
        response = client.post("/api/v1/analyze", headers={"Authorization": f"Bearer {token}"},
                               json=malformed)
        assert response.status_code == 200
        assert "gate_call_id" not in response.json()
    monkeypatch.setenv("AGENT_MOSS_AUTH_MODE", "off")
    assert "AGENT_MOSS_AUTH_MODE=off" in security_policy.auth_config_error()


@pytest.mark.parametrize("alias", ["global", "agent", "console"])
def test_gate_token_cannot_alias_existing_identity(client, monkeypatch, alias):
    monkeypatch.setenv("AGENT_MOSS_CONSOLE_TOKEN", "console")
    monkeypatch.setenv("AGENT_MOSS_GATE_AUTH_TOKEN", alias)
    assert security_policy.auth_config_error()
    response = client.post("/api/v1/analyze", headers=_headers(alias), json=_body())
    assert response.status_code == 401


@pytest.mark.parametrize("changes", [
    {"gate_call_id": "b" * 32},
    {"gate_call_time_us": True},
    {"gate_call_time_us": 0},
    {"gate_delivery_uncertain": "false"},
])
def test_invalid_gate_metadata_has_no_echo(client, changes):
    response = client.post("/api/v1/analyze", headers=_headers(), json=_body(**changes))
    assert response.status_code == 422
    assert "gate_call_id" not in response.json()


def test_gate_rate_limit_correlates_only_authenticated_admission(client, monkeypatch):
    async def rate_limited(self, _key):
        return False

    monkeypatch.setattr(_RateLimiter, "allow", rate_limited)
    response = client.post("/api/v1/analyze", headers=_headers(), content="unparsed")
    assert response.status_code == 429
    assert response.headers["X-AgentGate-Rate-Limited-Call-Id"] == CALL_ID
    response = client.post("/api/v1/analyze", headers=_headers("global"), json=_body())
    assert response.status_code == 403
    assert "X-AgentGate-Rate-Limited-Call-Id" not in response.headers
    response = client.post("/api/v1/analyze", headers={"Authorization": "Bearer global"}, json=_body())
    assert response.status_code == 429
    assert "X-AgentGate-Rate-Limited-Call-Id" not in response.headers


def test_gate_pool_full_correlates_only_authenticated_admission(client, monkeypatch):
    async def pool_full(self, _key, _limit):
        return False

    base_analysis = Mock(wraps=analyzer.analyze)
    monkeypatch.setattr(analyzer, "analyze", base_analysis)
    monkeypatch.setattr(_PooledLimiter, "try_acquire", pool_full)
    monkeypatch.setenv("AGENT_MOSS_QUEUE_ABUSE_THRESHOLD", "0")

    response = client.post("/api/v1/analyze", headers=_headers(), json=_body())
    assert response.status_code == 503
    assert response.headers["X-AgentGate-Busy-Call-Id"] == CALL_ID
    response = client.post("/api/v1/analyze", headers=_headers("global"), json=_body())
    assert response.status_code == 403
    assert "X-AgentGate-Busy-Call-Id" not in response.headers
    response = client.post("/api/v1/analyze", headers={"Authorization": "Bearer global"}, json=_body())
    assert response.status_code == 503
    assert "X-AgentGate-Busy-Call-Id" not in response.headers
    base_analysis.assert_not_called()


def test_gate_state_unavailable_degrades_without_blocking(client, monkeypatch):
    failure = Mock(side_effect=StatefulAnalysisUnavailable("fixture evidence unavailable"))
    monkeypatch.setattr(routes, "_chain_state_for_agent", lambda _: SimpleNamespace(apply_incremental=failure))
    response = client.post("/api/v1/analyze", headers=_headers(), json=_body(
        metadata={"stateful_incremental": True}, gate_delivery_uncertain=True,
    ))
    assert response.status_code == 200
    result = response.json()
    assert (result["decision"], result["risk_type"], result["policy"]) == (
        "Allow", "", "fixture allow policy",
    )
    assert result["gate_call_id"] == CALL_ID
    degraded = "\n".join(result["degraded"])
    assert "有状态分析不可用" in degraded and "本次动作未参与 L2.2" in degraded
    assert failure.call_args.args[0] == {
        "action_type": "bash",
        "action_detail": "echo example",
        "called_at": "",
        "_gate_call_id": CALL_ID,
        "_gate_call_time_us": CALL_TIME,
        "_gate_delivery_uncertain": True,
    }


def test_unconfirmed_gate_retry_is_denied_with_echo(client, monkeypatch):
    failure = Mock(side_effect=UnconfirmedGateRetry("fixture unconfirmed"))
    monkeypatch.setattr(routes, "_chain_state_for_agent", lambda _: SimpleNamespace(apply_incremental=failure))
    response = client.post("/api/v1/analyze", headers=_headers(), json=_body(
        metadata={"stateful_incremental": True}, gate_delivery_uncertain=True,
    ))
    assert response.status_code == 200
    result = response.json()
    assert (result["decision"], result["risk_type"], result["risk_level"]) == (
        "Deny", "service_unavailable", "high",
    )
    assert result["gate_call_id"] == CALL_ID
    assert "无法确认本次 Gate 调用是否已入链" in result["reason"]
    assert "避免重复入链" in "\n".join(result["degraded"])


@pytest.mark.parametrize("state_enabled", [True, False])
def test_l3_degradation_uses_final_stateful_decision_in_response_and_metrics(client, monkeypatch, state_enabled):
    l3_error = "fixture L3 unavailable"
    monkeypatch.setattr(analyzer, "analyze", lambda **kwargs: {
        "decision": "Allow", "reason": l3_error, "source": "llm_failure_fallback",
        "risk_level": "low", "l3_outcome": "fail_open", "policy": "fixture allow policy",
    })
    failure = Mock(side_effect=StatefulAnalysisUnavailable("fixture state unavailable"))
    monkeypatch.setattr(routes, "_chain_state_for_agent", lambda _: SimpleNamespace(apply_incremental=failure))
    analyze_total = Mock()
    monkeypatch.setattr(metrics, "ANALYZE_TOTAL", analyze_total)

    response = client.post("/api/v1/analyze", headers=_headers(), json=_body(
        metadata={"stateful_incremental": state_enabled}, gate_delivery_uncertain=True,
    ))
    assert response.status_code == 200
    result = response.json()
    degraded = "\n".join(result["degraded"])
    assert result["gate_call_id"] == CALL_ID
    assert l3_error in degraded
    if state_enabled:
        assert (result["decision"], result["l3_outcome"]) == ("Allow", "fail_open")
        assert "有状态分析不可用" in degraded
        assert "本次最终拒绝" not in degraded
        assert "fail_open 放行" in degraded
        analyze_total.inc.assert_called_once_with(decision="Allow", risk_level="low", l3_outcome="fail_open")
    else:
        assert (result["decision"], result["l3_outcome"]) == ("Allow", "fail_open")
        assert "fail_open 放行" in degraded
        analyze_total.inc.assert_called_once_with(decision="Allow", risk_level="low", l3_outcome="fail_open")
        failure.assert_not_called()


@pytest.mark.parametrize("state_enabled", [True, False])
def test_circuit_open_diagnostic_keeps_its_own_cause(client, monkeypatch, state_enabled):
    circuit_reason = "fixture circuit open after repeated model failures"
    monkeypatch.setattr(analyzer, "analyze", lambda **kwargs: {
        "decision": "Allow", "reason": f"LLM 分析失败（warn-allow，fail_open）: {circuit_reason}",
        "source": "llm_circuit_open", "l3_outcome": "circuit_open", "risk_level": "low",
    })
    analyze_total = Mock()
    monkeypatch.setattr(metrics, "ANALYZE_TOTAL", analyze_total)
    state_ok = Mock(return_value={
        "should_block": False, "matched": None, "exfil": [],
        "usage_pct": 0, "node_count": 0, "capacity": 1000,
        "skipped_for_capacity": False,
    })
    monkeypatch.setattr(routes, "_chain_state_for_agent", lambda _: SimpleNamespace(apply_incremental=state_ok))

    response = client.post("/api/v1/analyze", headers=_headers(), json=_body(
        metadata={"stateful_incremental": state_enabled},
    ))
    assert response.status_code == 200
    result = response.json()
    assert result["gate_call_id"] == CALL_ID
    assert result["l3_outcome"] == "circuit_open"
    [circuit_note] = [note for note in result["degraded"] if "LLM 熔断器打开" in note]
    assert circuit_reason in circuit_note and "未发起 L3 请求" in circuit_note
    assert "warn-allow" not in circuit_note and "有状态分析不可用" not in circuit_note
    assert "L1/L2 正常" not in circuit_note
    if state_enabled:
        assert result["decision"] == "Allow"
        assert result["reason"].startswith("LLM 分析失败")
        analyze_total.inc.assert_called_once_with(decision="Allow", risk_level="low", l3_outcome="circuit_open")
    else:
        assert result["decision"] == "Allow"
        assert result["degraded"] == [circuit_note]
        analyze_total.inc.assert_called_once_with(decision="Allow", risk_level="low", l3_outcome="circuit_open")


def test_circuit_diagnostic_is_independent_of_policy_failure(client, monkeypatch):
    policy_reason = "fixture policy generation failure"
    circuit_reason = "fixture circuit open"
    monkeypatch.setattr(analyzer, "analyze", lambda **kwargs: {
        "decision": "Deny", "reason": policy_reason, "source": "llm_circuit_open",
        "l3_outcome": "circuit_open", "_l3_circuit_reason": circuit_reason,
    })

    response = client.post("/api/v1/analyze", headers=_headers(), json=_body())
    assert response.status_code == 200
    result = response.json()
    assert (result["decision"], result["reason"]) == ("Deny", policy_reason)
    assert "_l3_circuit_reason" not in result
    [circuit_note] = result["degraded"]
    assert circuit_reason in circuit_note and policy_reason not in circuit_note


def test_uncertain_gate_retry_with_state_disabled_echoes_base_result(client, monkeypatch):
    state = Mock()
    monkeypatch.setattr(routes, "_chain_state_for_agent", state)
    response = client.post("/api/v1/analyze", headers=_headers(), json=_body(gate_delivery_uncertain=True))
    assert response.status_code == 200
    assert response.json()["decision"] == "Allow"
    assert response.json()["gate_call_id"] == CALL_ID
    state.assert_not_called()


def test_empty_gate_call_is_confirmed_across_restart(client):
    payload = _body(
        a_next={"action_type": "custom_tool", "action_detail": ""},
        metadata={"stateful_incremental": True},
    )
    direct = client.post("/api/v1/analyze", headers={"Authorization": "Bearer global"}, json=payload)
    assert direct.status_code == 200 and direct.json()["decision"] == "Allow"
    bucket = routes._chain_state_for_agent("")
    assert not bucket.store.load(bucket.agent_id).nodes

    first = client.post("/api/v1/analyze", headers=_headers(), json=payload)
    assert first.status_code == 200 and first.json()["decision"] == "Allow"
    # Insert an earlier action to force replay of the empty confirmation before restart.
    earlier = client.post("/api/v1/analyze", headers=_headers(call_id="b" * 32), json=_body(
        gate_call_id="b" * 32, gate_call_time_us=CALL_TIME - 1, metadata={"stateful_incremental": True},
    ))
    assert earlier.status_code == 200 and earlier.json()["decision"] == "Allow"
    chain_state.reset_chain_state_store()

    retry = client.post("/api/v1/analyze", headers=_headers(), json={**payload, "gate_delivery_uncertain": True})
    assert retry.status_code == 200
    assert (retry.json()["decision"], retry.json()["gate_call_id"]) == ("Allow", CALL_ID)
    bucket = routes._chain_state_for_agent("")
    [prior, node] = bucket.store.load(bucket.agent_id).nodes
    assert (prior.gate_call_id, node.gate_call_id) == ("b" * 32, CALL_ID)
    assert (node.action_detail, node.stage, node.lifecycle, node.resources, node.instances) == ("", "", "", (), ())
    assert node.confirmed == {"matched": None, "exfil": []}


def test_gate_token_with_auth_off_is_config_error(monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_AUTH_MODE", "off")
    monkeypatch.setenv("AGENT_MOSS_GATE_AUTH_TOKEN", "dedicated")
    security_policy.reset_auth_cache()
    assert "AGENT_MOSS_AUTH_MODE=off" in security_policy.auth_config_error()
    with pytest.raises(SystemExit):
        security_policy.fail_fast_on_auth_error()


def test_only_a_call_skipped_for_capacity_reports_lost_coverage(client, monkeypatch):
    monkeypatch.setattr(stateful, "_MAX_NODES", 2)
    first = _body(metadata={"stateful_incremental": True})
    second = {**first, "gate_call_id": "b" * 32, "gate_call_time_us": CALL_TIME + 1}
    for index, payload in enumerate((first, second)):
        response = client.post("/api/v1/analyze", headers=_headers(call_id=payload["gate_call_id"]), json=payload)
        assert response.status_code == 200 and response.json()["decision"] == "Allow"
        if index == 1:
            assert "本次判定完整" in "\n".join(response.json()["degraded"])

    retry = client.post(
        "/api/v1/analyze", headers=_headers(), json={**first, "gate_delivery_uncertain": True},
    )
    assert retry.status_code == 200 and retry.json()["decision"] == "Allow"
    retry_hint = "\n".join(retry.json()["degraded"])
    assert "本次判定完整" in retry_hint and "本次动作未参与" not in retry_hint

    monkeypatch.setattr(stateful.StatefulChainTracker, "rotate", Mock(side_effect=OSError("archive unavailable")))
    skipped = client.post("/api/v1/analyze", headers={"Authorization": "Bearer global"}, json=first)
    assert skipped.status_code == 200 and skipped.json()["decision"] == "Allow"
    assert "本次动作未参与" in "\n".join(skipped.json()["degraded"])
    bucket = routes._chain_state_for_agent("")
    assert len(bucket.store.load(bucket.agent_id).nodes) == 2
