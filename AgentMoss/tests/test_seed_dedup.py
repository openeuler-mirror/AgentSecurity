"""seed 幂等性看护（2026-11：review 周期性重复 seed 导致节点成倍膨胀）。

背景：AgentGate 每 100 次 analyze 触发一次 /review，review 会 seed 全量
历史。`seed` 原先无条件追加 —— 同一批历史 seed 5 次，节点从 2 条变 10 条，
跑一段时间就把 10 万节点上限打满，之后组合链检测静默失效。
"""

from __future__ import annotations

from agent_moss.engine.formal_engine.stateful import StatefulChainTracker

_SESSIONS = [
    {
        "session_id": "s1",
        "action_history": [
            {"action_type": "execute", "action_detail": "ls /tmp", "called_at": "2026-11-12T12:00:00"},
            {"action_type": "execute", "action_detail": "cat /etc/hostname", "called_at": "2026-11-12T12:00:01"},
        ],
    }
]


def test_repeated_seed_is_idempotent_with_called_at():
    t = StatefulChainTracker(agent_id="b")
    assert t.seed(_SESSIONS) == 2
    for _ in range(9):
        assert t.seed(_SESSIONS) == 0
    assert len(t.nodes) == 2


def test_seed_without_called_at_keeps_old_behavior():
    """无时间戳无法区分「重复 seed」与「合法地重复执行同一命令」，不去重。"""
    t = StatefulChainTracker(agent_id="b")
    s = [{"session_id": "s1", "action_history": [{"action_type": "execute", "action_detail": "ls /tmp"}]}]
    assert t.seed(s) == 1
    assert t.seed(s) == 1
    assert len(t.nodes) == 2


def test_new_actions_are_appended_incrementally():
    """历史追加新动作时，只补新增的那条。"""
    t = StatefulChainTracker(agent_id="b")
    t.seed(_SESSIONS)
    extended = [
        {
            "session_id": "s1",
            "action_history": _SESSIONS[0]["action_history"]
            + [{"action_type": "execute", "action_detail": "whoami", "called_at": "2026-11-12T12:00:02"}],
        }
    ]
    assert t.seed(extended) == 1
    assert len(t.nodes) == 3


def test_seeded_keys_survive_snapshot_roundtrip():
    """重启后仍要去重，否则每次重启后第一次 review 会再追加一遍全量历史。"""
    t = StatefulChainTracker(agent_id="b")
    t.seed(_SESSIONS)
    snap = t.to_snapshot()

    t2 = StatefulChainTracker(agent_id="b")
    t2.restore(snap)
    assert t2.seed(_SESSIONS) == 0
    assert len(t2.nodes) == 2
