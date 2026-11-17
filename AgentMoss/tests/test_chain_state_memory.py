"""链状态内存缓存 + 后台写盘的行为看护（2026-11 招行性能问题后新增）。

看护点：
- apply 之后 ``load`` 返回**同一个**内存对象（不再每次从 SQLite 反序列化）
- ``flush()`` 后重启能完整恢复
- 并发 apply 不丢节点（调用方已把它放进线程池）
- ``delete`` 同时清内存与磁盘
"""

from __future__ import annotations

import threading

from agent_moss.engine.formal_engine.chain_state import ChainStateStore

_ACTION = {"action_type": "execute", "action_detail": "cat /etc/hostname"}


def _store(tmp_path) -> ChainStateStore:
    return ChainStateStore(str(tmp_path / "chains.db"))


def test_apply_returns_cached_tracker(tmp_path):
    store = _store(tmp_path)
    try:
        store.apply_action("b", _ACTION, "s1")
        t1 = store.load("b")
        store.apply_action("b", _ACTION, "s2")
        t2 = store.load("b")
        # 同一个对象 → 不再有「每次 load 都重建全部节点」的开销
        assert t1 is t2
        assert len(t2.nodes) == 2
    finally:
        store.close()


def test_flush_persists_and_reloads(tmp_path):
    store = _store(tmp_path)
    try:
        for i in range(5):
            store.apply_action("b", _ACTION, f"s{i}")
        store.flush()
    finally:
        store.close()

    store2 = _store(tmp_path)
    try:
        tracker = store2.load("b")
        assert tracker is not None
        assert len(tracker.nodes) == 5
    finally:
        store2.close()


def test_concurrent_apply_does_not_lose_nodes(tmp_path):
    store = _store(tmp_path)
    threads = []
    try:
        def worker(k: int) -> None:
            for i in range(50):
                store.apply_action("b", _ACTION, f"c{k}-{i}")

        for k in range(8):
            threads.append(threading.Thread(target=worker, args=(k,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        tracker = store.load("b")
        assert tracker is not None
        # 8 线程 × 50 = 400 条，一条都不能丢（丢了就是组合链漏拦）
        assert len(tracker.nodes) == 400
    finally:
        store.close()


def test_delete_clears_memory_and_disk(tmp_path):
    store = _store(tmp_path)
    try:
        store.apply_action("b", _ACTION, "s1")
        store.delete("b")
        assert store.load("b") is None
        store.flush()
    finally:
        store.close()

    store2 = _store(tmp_path)
    try:
        assert store2.load("b") is None
    finally:
        store2.close()


def test_close_flushes_dirty(tmp_path):
    """close 必须先 flush，否则进程正常退出会丢最近一秒的增量。"""
    store = _store(tmp_path)
    store.apply_action("b", _ACTION, "s1")
    store.close()

    store2 = _store(tmp_path)
    try:
        tracker = store2.load("b")
        assert tracker is not None and len(tracker.nodes) == 1
    finally:
        store2.close()


def test_incremental_rows_only_new_nodes(tmp_path):
    """增量落盘：第二次 flush 只追加新节点，不重写已有行。"""
    store = _store(tmp_path)
    try:
        store.apply_action("b", _ACTION, "s1")
        store.flush()
        rows1 = store._conn.execute(
            "SELECT COUNT(*) AS c FROM chain_nodes WHERE agent_id='b'"
        ).fetchone()["c"]
        assert rows1 == 1

        store.apply_action("b", _ACTION, "s2")
        store.flush()
        rows2 = store._conn.execute(
            "SELECT COUNT(*) AS c FROM chain_nodes WHERE agent_id='b'"
        ).fetchone()["c"]
        assert rows2 == 2
        # 旧表不再写入
        legacy = store._conn.execute(
            "SELECT COUNT(*) AS c FROM chain_state WHERE agent_id='b'"
        ).fetchone()["c"]
        assert legacy == 0
    finally:
        store.close()


def test_migrates_legacy_single_row(tmp_path):
    """旧结构（chain_state 整份 JSON）首次 load 时自动迁移到新表。"""
    import json
    import sqlite3

    db = str(tmp_path / "chains.db")
    store = _store(tmp_path)
    store.close()  # 先建好表结构

    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    legacy_snap = {
        "agent_id": "b",
        "nodes": [
            {
                "seq": 0,
                "session_id": "s1",
                "action_type": "execute",
                "action_detail": "cat /etc/hostname",
                "stage": "",
                "resources": [],
                "instances": [],
                "is_error": False,
                "agent_id": "",
                "instance_id": "",
                "lifecycle": "",
                "timestamp": "2026-01-01T00:00:00",
            }
        ],
        "ptrs": {},
        "tainted": [],
        "taint_parent": {},
        "taint_origin": {},
        "alive": {},
        "seq_next": 1,
    }
    conn.execute(
        "INSERT INTO chain_state (agent_id, state_json, updated_at) VALUES (?, ?, ?)",
        ("b", json.dumps(legacy_snap), 0.0),
    )
    conn.commit()
    conn.close()

    store2 = _store(tmp_path)
    try:
        tracker = store2.load("b")
        assert tracker is not None
        assert len(tracker.nodes) == 1
        # 迁移后旧行被删除
        legacy = store2._conn.execute(
            "SELECT COUNT(*) AS c FROM chain_state WHERE agent_id='b'"
        ).fetchone()["c"]
        assert legacy == 0
    finally:
        store2.close()
