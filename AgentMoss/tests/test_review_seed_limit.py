"""review seed 规模上限与自适应兜底（2026-11）。"""

from __future__ import annotations

import os

from agent_moss.server.routes import _review_seed_limit, _trim_review_sessions


class _FakeTracker:
    def __init__(self, n: int):
        self.nodes = list(range(n))


class _FakeStore:
    def __init__(self, nodes: int):
        import threading

        self._lock = threading.RLock()
        self._trackers = {"a": _FakeTracker(nodes)}


def _sessions(counts: list[int]) -> list[dict]:
    return [
        {"session_id": f"s{i}", "action_history": [{"i": j} for j in range(n)]}
        for i, n in enumerate(counts)
    ]


def test_trim_keeps_most_recent():
    sessions = _sessions([10, 10])
    out, dropped = _trim_review_sessions(sessions, 15)
    assert dropped == 5
    assert sum(len(s["action_history"]) for s in out) == 15
    # 丢掉的是最老的（第一个 session 的前 5 条）
    assert out[0]["action_history"][0]["i"] == 5


def test_trim_noop_when_under_limit():
    sessions = _sessions([3, 4])
    out, dropped = _trim_review_sessions(sessions, 100)
    assert dropped == 0
    assert out is sessions


def test_trim_limit_smaller_than_last_session():
    sessions = _sessions([10, 10])
    out, dropped = _trim_review_sessions(sessions, 5)
    assert dropped == 15
    assert len(out) == 1
    assert len(out[0]["action_history"]) == 5


def test_limit_default(monkeypatch):
    monkeypatch.delenv("AGENT_MOSS_REVIEW_MAX_ACTIONS", raising=False)
    assert _review_seed_limit(_FakeStore(0)) == 5000


def test_limit_configurable(monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_REVIEW_MAX_ACTIONS", "800")
    assert _review_seed_limit(_FakeStore(0)) == 800


def test_limit_zero_means_unlimited(monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_REVIEW_MAX_ACTIONS", "0")
    assert _review_seed_limit(_FakeStore(99999)) == 0


def test_limit_shrinks_near_capacity(monkeypatch):
    """时间线逼近 10 万上限时自动收紧，避免持锁太久且新节点会被丢弃。"""
    monkeypatch.setenv("AGENT_MOSS_REVIEW_MAX_ACTIONS", "5000")
    assert _review_seed_limit(_FakeStore(0)) == 5000
    assert _review_seed_limit(_FakeStore(60000)) == 3000
    assert _review_seed_limit(_FakeStore(80000)) == 1000
    assert _review_seed_limit(_FakeStore(95000)) == 200
