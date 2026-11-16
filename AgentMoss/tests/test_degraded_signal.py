"""能力降级信号（2026-11）。

用户明确要求「预警必须能被**被动感知**」——不能只写日志等人去看。
- /api/v1/health 的 status 在能力降级时变为 "degraded"（探活/监控直接可见）
- /api/v1/analyze 的 degraded 字段标注「本次判定缺了哪层」
"""

from __future__ import annotations

from agent_moss.engine.formal_engine import stateful


def _feed(tracker, n: int) -> None:
    for i in range(n):
        tracker.advance(
            a_next={"action_type": "execute", "action_detail": f"echo d{i}"},
            session_id="s",
        )


def test_apply_incremental_reports_capacity(monkeypatch, tmp_path):
    """触顶后 apply_incremental 必须返回 at_capacity=True。"""
    from agent_moss.engine.formal_engine.chain_state import ChainStateStore
    from agent_moss.server.routes import _AgentState

    monkeypatch.setattr(stateful, "_MAX_NODES", 5)
    store = ChainStateStore(str(tmp_path / "t.db"))
    try:
        wrapper = _AgentState(store, "bucket")
        results = [
            wrapper.apply_incremental(
                {"action_type": "execute", "action_detail": f"echo {i}"}, "s"
            )
            for i in range(8)
        ]
        assert results[0]["at_capacity"] is False
        assert results[-1]["at_capacity"] is True
        assert results[-1]["node_count"] == 5
    finally:
        store.close()


def test_health_status_becomes_degraded_when_chain_full(monkeypatch, tmp_path):
    """链状态触顶 → health 的 status 必须是 degraded，不需要人读日志。"""
    from fastapi.testclient import TestClient

    from agent_moss.engine.formal_engine import chain_state as cs
    from agent_moss.server.app import create_app

    monkeypatch.setattr(stateful, "_MAX_NODES", 5)
    monkeypatch.setenv("AGENT_MOSS_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_MOSS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_MOSS_AUTH_MODE", "off")
    monkeypatch.setenv("AGENT_MOSS_DISABLE_LLM", "1")
    cs.reset_chain_state_store()

    store = cs.get_chain_state_store(str(tmp_path / "stateful_chains.db"))
    t = store.load_or_new("__system__")
    _feed(t, 6)
    store.save(t)

    app = create_app()
    with TestClient(app) as client:
        body = client.get("/api/v1/health").json()
    assert body["status"] == "degraded", body
    assert any("链状态" in x for x in body["degraded"]), body
    cs.reset_chain_state_store()


def test_health_status_is_healthy_under_normal_capacity(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from agent_moss.engine.formal_engine import chain_state as cs
    from agent_moss.server.app import create_app

    monkeypatch.setenv("AGENT_MOSS_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_MOSS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_MOSS_AUTH_MODE", "off")
    monkeypatch.setenv("AGENT_MOSS_DISABLE_LLM", "1")
    cs.reset_chain_state_store()

    app = create_app()
    with TestClient(app) as client:
        body = client.get("/api/v1/health").json()
    assert body["status"] == "healthy", body
    assert body["degraded"] == []
    cs.reset_chain_state_store()
