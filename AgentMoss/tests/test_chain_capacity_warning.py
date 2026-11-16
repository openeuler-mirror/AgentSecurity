"""链状态容量分级预警（2026-11）。

背景：时间线上限 10 万节点，客户 QPS 5-10 时**几小时就触顶**，触顶后新动作
不再入链、组合链检测静默失效。原实现只在**已经触顶后**打一条 warning，
等于没有预警。现在 70%/85%/95% 各提前提醒一次。
"""

from __future__ import annotations

import logging

from agent_moss.engine.formal_engine import stateful

_A = {"action_type": "execute", "action_detail": "ls /tmp"}


def _feed(tracker, n: int) -> None:
    for i in range(n):
        tracker.advance(a_next={**_A, "action_detail": f"echo {i}"}, session_id="s")


def test_warns_at_thresholds(monkeypatch, caplog):
    monkeypatch.setattr(stateful, "_MAX_NODES", 100)
    t = stateful.StatefulChainTracker(agent_id="b")
    with caplog.at_level(logging.WARNING, logger=stateful.logger.name):
        _feed(t, 70)
        assert any("70%" in r.message for r in caplog.records)
        caplog.clear()
        _feed(t, 15)  # 到 85%
        assert any("85%" in r.message for r in caplog.records)
        caplog.clear()
        _feed(t, 10)  # 到 95%
        assert any("95%" in r.message for r in caplog.records)


def test_warns_only_once_per_level(monkeypatch, caplog):
    monkeypatch.setattr(stateful, "_MAX_NODES", 100)
    t = stateful.StatefulChainTracker(agent_id="b")
    with caplog.at_level(logging.WARNING, logger=stateful.logger.name):
        _feed(t, 75)
        n_first = sum(1 for r in caplog.records if "70%" in r.message)
        caplog.clear()
        _feed(t, 5)
        n_second = sum(1 for r in caplog.records if "70%" in r.message)
    assert n_first == 1
    assert n_second == 0


def test_hard_limit_still_reported(monkeypatch, caplog):
    monkeypatch.setattr(stateful, "_MAX_NODES", 20)
    t = stateful.StatefulChainTracker(agent_id="b")
    with caplog.at_level(logging.WARNING, logger=stateful.logger.name):
        _feed(t, 25)
    messages = [r.message for r in caplog.records]
    assert any("上限" in m for m in messages)
    assert len(t.nodes) == 20


def test_restore_resets_warned_levels(monkeypatch, caplog):
    monkeypatch.setattr(stateful, "_MAX_NODES", 100)
    t = stateful.StatefulChainTracker(agent_id="b")
    with caplog.at_level(logging.WARNING, logger=stateful.logger.name):
        _feed(t, 70)
    snap = t.to_snapshot()
    t2 = stateful.StatefulChainTracker(agent_id="b")
    t2.restore(snap)
    assert t2._capacity_warned == set()
    with caplog.at_level(logging.WARNING, logger=stateful.logger.name):
        caplog.clear()
        _feed(t2, 1)  # 已过 70%，恢复后应重新提醒一次
        assert any("70%" in r.message for r in caplog.records)
