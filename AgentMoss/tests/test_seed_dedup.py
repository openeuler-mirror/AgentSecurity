"""seed 幂等性看护（2026-11：review 周期性重复 seed 导致节点成倍膨胀）。

背景：AgentGate 每 100 次 analyze 触发一次 /review，review 会 seed 全量
历史。`seed` 原先无条件追加 —— 同一批历史 seed 5 次，节点从 2 条变 10 条，
跑一段时间就把 10 万节点上限打满，之后组合链检测静默失效。
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing

import pytest

from agent_moss.engine.formal_engine.chain_state import ChainStateStore
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
    assert "seeded_keys" not in snap
    assert all(node["legacy_fingerprint"] for node in snap["nodes"])

    t2 = StatefulChainTracker(agent_id="b")
    t2.restore(snap)
    assert t2.seed(_SESSIONS) == 0
    assert len(t2.nodes) == 2


def _old_snapshot_without_node_fingerprints():
    tracker = StatefulChainTracker(agent_id="b")
    tracker.seed(_SESSIONS)
    snapshot = tracker.to_snapshot()
    snapshot.pop("generation")
    snapshot["seeded_keys"] = [node.pop("legacy_fingerprint") for node in snapshot["nodes"]]
    for node in snapshot["nodes"]:
        node.pop("timestamp")
    return snapshot


def test_old_snapshot_with_seeded_keys_can_still_be_read():
    restored = StatefulChainTracker(agent_id="b")
    restored.restore(_old_snapshot_without_node_fingerprints())
    assert restored.seed(_SESSIONS) == 0
    assert len(restored.nodes) == 2


@pytest.mark.parametrize("replay", [False, True])
def test_old_snapshot_deduplication_survives_new_writes_and_second_start(tmp_path, replay):
    path = str(tmp_path / "legacy.sqlite3")
    snapshot = _old_snapshot_without_node_fingerprints()
    with closing(ChainStateStore(path)) as store:
        with closing(sqlite3.connect(path)) as conn, conn:
            conn.execute("INSERT INTO chain_state VALUES (?, ?, ?)", ("b", json.dumps(snapshot), 0))
        assert store.seed_and_save("b", _SESSIONS)[0] == 0

        orders = (2, 1) if replay else (1,)
        for order in orders:
            store.apply_action("b", {
                "action_type": "bash", "action_detail": f"echo new-{order}",
                "_gate_call_id": f"{order:032x}", "_gate_call_time_us": order,
            }, "s1")
        store.flush()

    with closing(ChainStateStore(path)) as reopened:
        assert reopened.seed_and_save("b", _SESSIONS)[0] == 0
        assert len(reopened.load("b").nodes) == 2 + len(orders)

    with closing(sqlite3.connect(path)) as conn:
        metadata = json.loads(conn.execute("SELECT meta_json FROM chain_meta WHERE agent_id='b'").fetchone()[0])
        assert "seeded_keys" not in metadata
        assert sorted(metadata["unmapped_legacy_keys"]) == sorted(snapshot["seeded_keys"])


def test_sqlite_writes_only_node_fingerprints_and_recovers_deduplication(tmp_path):
    path = str(tmp_path / "chains.sqlite3")
    with closing(ChainStateStore(path)) as store:
        assert store.seed_and_save("b", _SESSIONS)[0] == 2
        store.flush()

    with closing(sqlite3.connect(path)) as conn:
        metadata = json.loads(conn.execute("SELECT meta_json FROM chain_meta WHERE agent_id='b'").fetchone()[0])
        assert "seeded_keys" not in metadata
        assert "unmapped_legacy_keys" not in metadata

    with closing(ChainStateStore(path)) as reopened:
        assert reopened.seed_and_save("b", _SESSIONS)[0] == 0
        assert len(reopened.load("b").nodes) == 2


_EXPLICIT_RECEIPT_MATCH = {
    "action_type": "execute", "action_detail": "echo fixture-receipt",
    "called_at": "2026-11-12T12:00:02",
}


def _old_snapshot_with_receipt_time(monkeypatch):
    tracker = StatefulChainTracker(agent_id="b")
    tracker.seed(_SESSIONS)
    monkeypatch.setattr(StatefulChainTracker, "_now", staticmethod(lambda: _EXPLICIT_RECEIPT_MATCH["called_at"]))
    tracker.advance(
        {key: value for key, value in _EXPLICIT_RECEIPT_MATCH.items() if key != "called_at"}, session_id="s1",
    )
    snapshot = tracker.to_snapshot()
    snapshot.pop("generation")
    snapshot["seeded_keys"] = [
        key for node in snapshot["nodes"] if (key := node.pop("legacy_fingerprint"))
    ]
    return snapshot


def _install_old_rows(path, snapshot, *, split):
    with closing(sqlite3.connect(path)) as conn, conn:
        if split:
            metadata = {key: value for key, value in snapshot.items() if key not in ("nodes", "agent_id")}
            conn.execute("INSERT INTO chain_meta VALUES (?, ?, ?)", ("b", json.dumps(metadata), 0))
            conn.executemany(
                "INSERT INTO chain_nodes VALUES (?, ?, ?)",
                [("b", node["seq"], json.dumps(node)) for node in snapshot["nodes"]],
            )
        else:
            conn.execute("INSERT INTO chain_state VALUES (?, ?, ?)", ("b", json.dumps(snapshot), 0))


@pytest.mark.parametrize("split", [False, True])
def test_legacy_receipt_cannot_deduplicate_explicit_time_after_second_start(tmp_path, monkeypatch, split):
    path = str(tmp_path / "legacy.sqlite3")
    snapshot = _old_snapshot_with_receipt_time(monkeypatch)
    matching_history = [{"session_id": "s1", "action_history": [_EXPLICIT_RECEIPT_MATCH]}]
    with closing(ChainStateStore(path)) as store:
        _install_old_rows(path, snapshot, split=split)
        assert store.seed_and_save("b", _SESSIONS)[0] == 0
        store.apply_action("b", {"action_type": "execute", "action_detail": "echo next"}, "s1")
        assert store.flush() == 1

    with closing(sqlite3.connect(path)) as conn:
        row = conn.execute("SELECT node_json FROM chain_nodes WHERE agent_id='b' AND seq=2").fetchone()
        assert json.loads(row[0])["legacy_fingerprint"] == ""

    with closing(ChainStateStore(path)) as reopened:
        assert [node.legacy_fingerprint for node in reopened.load("b").nodes[:3]] == [
            *snapshot["seeded_keys"], "",
        ]
        assert reopened.seed_and_save("b", _SESSIONS)[0] == 0
        assert reopened.seed_and_save("b", matching_history)[0] == 1
        assert reopened.seed_and_save("b", matching_history)[0] == 0


def test_legacy_receipt_and_real_call_remain_distinct_across_same_generation_workers(tmp_path, monkeypatch):
    path = str(tmp_path / "legacy.sqlite3")
    snapshot = _old_snapshot_with_receipt_time(monkeypatch)
    matching_history = [{"session_id": "s1", "action_history": [_EXPLICIT_RECEIPT_MATCH]}]
    with closing(ChainStateStore(path)) as first, closing(ChainStateStore(path)) as second:
        _install_old_rows(path, snapshot, split=True)
        first.enable_multi_process()
        second.enable_multi_process()
        cached = second.load("b")
        generation = cached.generation
        assert cached.nodes[2].legacy_fingerprint == ""
        assert first.apply_action("b", _EXPLICIT_RECEIPT_MATCH, "s1").node is not None
        assert first.load("b").generation == generation
        added, tracker = second.seed_and_save("b", matching_history)
        assert added == 0
        assert tracker is cached
        assert tracker.generation == generation
        assert len(tracker.nodes) == 4


def test_legacy_empty_key_list_marks_receipt_time_synthetic(monkeypatch):
    snapshot = _old_snapshot_with_receipt_time(monkeypatch)
    receipt = snapshot["nodes"][2]
    snapshot["nodes"] = [dict(receipt, seq=0)]
    snapshot["seq_next"] = 1
    snapshot["seeded_keys"] = []
    tracker = StatefulChainTracker(agent_id="b")
    tracker.restore(snapshot)
    assert tracker.advance(_EXPLICIT_RECEIPT_MATCH, session_id="s1").node is not None
    assert tracker.nodes[0].legacy_fingerprint == ""
