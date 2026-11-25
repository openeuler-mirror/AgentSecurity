"""Storage regressions for the Gate call identity timeline."""

from contextlib import closing
from json import dumps
from threading import Event, Lock, Thread, current_thread

import pytest

from agent_moss.engine.formal_engine import stateful
from agent_moss.engine.formal_engine.chain_state import ChainStateStore


_SAMPLE_RESOURCE = "/tmp/agentmoss-synthetic-resource"


def gate_action(index, detail=None, *, uncertain=False):
    return {
        "action_type": "bash",
        "action_detail": detail or f"echo store-{index}",
        "called_at": "2026-11-23T04:00:00+00:00",
        "_gate_call_id": f"{index:032x}",
        "_gate_call_time_us": 1795406400000000 + index,
        "_gate_delivery_uncertain": uncertain,
    }


def history(*actions):
    return [{"session_id": "smoke", "action_history": list(actions)}]


def test_second_worker_reloads_rotated_window_before_review(tmp_path, monkeypatch):
    monkeypatch.setattr(stateful, "_MAX_NODES", 4)
    monkeypatch.setenv("AGENT_MOSS_CHAIN_RETAIN_NODES", "2")
    monkeypatch.setenv("AGENT_MOSS_CHAIN_ARCHIVE_DIR", str(tmp_path / "archive"))
    db_path = str(tmp_path / "state.sqlite3")
    with closing(ChainStateStore(db_path)) as first, closing(ChainStateStore(db_path)) as second:
        first.enable_multi_process()
        second.enable_multi_process()
        for index in range(1, 5):
            first.apply_action("shared", gate_action(index), "smoke")
        assert len(second.load("shared").nodes) == 4
        assert second._synced_seq["shared"] == 3
        first.apply_action("shared", gate_action(5), "smoke")
        added, tracker = second.seed_and_save("shared", history(gate_action(5)))
        assert added == 0
        assert tracker.generation == first.load("shared").generation > 0
        assert second._synced_seq["shared"] == 2
        assert [node.action_detail for node in tracker.nodes] == [
            "echo store-3", "echo store-4", "echo store-5",
        ]
        second.apply_action("shared", gate_action(6), "smoke")
        added, tracker = first.seed_and_save("shared", history(gate_action(6)))
        assert added == 0
        assert tracker.nodes[-1].action_detail == "echo store-6"
        assert tracker.nodes[-1].seq == 3


def synthetic_match(tracker, node):
    if node.action_detail.startswith("echo complete"):
        return stateful.ChainMatch(
            "synthetic", ("TEST",), "high", "synthetic stateful match",
            [(node.session_id, node.seq, node.action_detail)],
        )
    return None


def test_same_generation_sync_restores_retry_evidence_and_legacy_keys(tmp_path, monkeypatch):
    monkeypatch.setattr(stateful.StatefulChainTracker, "_advance_chains", synthetic_match)
    first_detail = f"echo complete {_SAMPLE_RESOURCE}"
    next_detail = f"echo follow {_SAMPLE_RESOURCE}"

    def mark_taint(tracker, node):
        if node.action_detail == first_detail:
            tracker._tainted.add(node.seq)
            tracker._tainted_resources.update(node.resources)

    def check_taint(tracker, node):
        if node.action_detail == next_detail and _SAMPLE_RESOURCE in tracker._tainted_resources:
            return [{"reason": "synthetic follow-up match", "risk_level": "high"}]
        return []

    monkeypatch.setattr(stateful.StatefulChainTracker, "_advance_taint", mark_taint)
    monkeypatch.setattr(stateful.StatefulChainTracker, "_check_exfil_after_taint", check_taint)
    db_path = str(tmp_path / "state.sqlite3")
    with closing(ChainStateStore(db_path)) as first, closing(ChainStateStore(db_path)) as second:
        first.enable_multi_process()
        second.enable_multi_process()
        first.apply_action("shared", gate_action(1), "smoke")
        previous = second.load("shared")
        generation = previous.generation
        existing_legacy = {
            "action_type": "bash", "action_detail": "echo legacy",
            "called_at": "2026-11-23T04:00:01+00:00",
        }
        first.apply_action("shared", existing_legacy, "legacy")
        confirmed = first.apply_action("shared", gate_action(2, first_detail), "smoke")
        assert confirmed.should_block
        retry = second.apply_action(
            "shared", gate_action(2, first_detail, uncertain=True), "smoke",
        )
        assert retry.should_block
        assert retry.matched.to_judgment() == confirmed.matched.to_judgment()
        added, tracker = second.seed_and_save(
            "shared", [{"session_id": "legacy", "action_history": [existing_legacy]}],
        )
        assert added == 0
        assert tracker.generation == generation
        assert len(tracker.nodes) == 3
        follow_up = second.apply_action("shared", gate_action(3, next_detail), "smoke")

    with closing(ChainStateStore(str(tmp_path / "baseline.sqlite3"))) as baseline:
        baseline.apply_action("shared", gate_action(1), "smoke")
        baseline.apply_action("shared", existing_legacy, "legacy")
        baseline.apply_action("shared", gate_action(2, first_detail), "smoke")
        expected = baseline.apply_action("shared", gate_action(3, next_detail), "smoke")
        assert follow_up.exfil == expected.exfil
        assert follow_up.should_block


@pytest.mark.parametrize("committed_prefix", [False, True])
def test_old_background_flush_cannot_overwrite_corrected_generation(tmp_path, monkeypatch, committed_prefix):
    monkeypatch.setattr(ChainStateStore, "_FLUSH_INTERVAL", 60)
    monkeypatch.setattr(stateful.StatefulChainTracker, "_advance_chains", synthetic_match)
    db_path = str(tmp_path / "state.sqlite3")
    captured = Event()
    release = Event()
    outcomes = []
    index = 2 if committed_prefix else 1
    prefix = [gate_action(1)] if committed_prefix else []
    with closing(ChainStateStore(db_path)) as store:
        store.seed_and_save("shared", history(*prefix, gate_action(index, "echo truncated")))
        if committed_prefix:
            assert store.flush() == 1
            store.save(store.load("shared"))
        before = store.load("shared").generation
        serialize = store._serialize_snapshot

        def pause_old_flush(agent_id, parts, start):
            if current_thread() is delayed:
                captured.set()
                assert release.wait(5)
            return serialize(agent_id, parts, start)

        monkeypatch.setattr(store, "_serialize_snapshot", pause_old_flush)
        delayed = Thread(target=lambda: outcomes.append(store.flush()))
        delayed.start()
        try:
            assert captured.wait(5)
            writes = store._conn.total_changes
            confirmed = store.apply_action("shared", gate_action(index, "echo complete"), "smoke")
            assert confirmed.should_block
            corrected = store.load("shared").generation
            assert corrected > before
            if committed_prefix:
                assert store._conn.total_changes - writes == 2
        finally:
            release.set()
            delayed.join(5)
        assert outcomes == [0]

    with closing(ChainStateStore(db_path)) as reopened:
        tracker = reopened.load("shared")
        assert tracker.generation == corrected
        assert [node.action_detail for node in tracker.nodes] == [
            *[action["action_detail"] for action in prefix], "echo complete",
        ]
        retry = reopened.apply_action(
            "shared", gate_action(index, "echo complete", uncertain=True), "smoke",
        )
        assert retry.should_block
        assert retry.matched.to_judgment() == confirmed.matched.to_judgment()
        reopened.apply_action("shared", gate_action(index + 1), "smoke")

    with closing(ChainStateStore(db_path)) as reopened:
        assert [node.seq for node in reopened.load("shared").nodes] == list(range(index + 1))
        assert reopened._synced_seq["shared"] == index


@pytest.mark.parametrize("multi_process", [False, True])
def test_late_insert_only_writes_changed_sqlite_suffix(tmp_path, monkeypatch, multi_process):
    monkeypatch.setattr(ChainStateStore, "_FLUSH_INTERVAL", 60)
    monkeypatch.setattr(stateful, "_MAX_NODES", 20_000)
    db_path = str(tmp_path / "state.sqlite3")
    late = gate_action(19_999)
    with closing(ChainStateStore(db_path)) as writer, closing(ChainStateStore(db_path)) as observer:
        if multi_process:
            writer.enable_multi_process()
        observer.enable_multi_process()
        added, tracker = writer.seed_and_save(
            "shared", history(*(gate_action(index) for index in range(2, 20_001, 2))),
        )
        assert added == 10_000
        assert writer.flush() == int(not multi_process)
        observed = observer.load("shared")
        previous_generation = observed.generation
        before = writer._conn.total_changes

        result = writer.apply_action("shared", late, "smoke")
        assert result.node.seq == 9_999
        assert writer._conn.total_changes - before == 3
        assert tracker.generation > previous_generation

        retry = observer.apply_action("shared", {**late, "_gate_delivery_uncertain": True}, "smoke")
        assert retry.node.seq == 9_999
        assert observer.load("shared") is observed
        assert observed.generation == tracker.generation
        assert len(observed.nodes) == 10_001

    with closing(ChainStateStore(db_path)) as reopened:
        tracker = reopened.load("shared")
        assert len(tracker.nodes) == 10_001
        assert [(node.seq, node.action_detail) for node in tracker.nodes[-3:]] == [
            (9_998, "echo store-19998"), (9_999, "echo store-19999"), (10_000, "echo store-20000"),
        ]


def test_pending_replay_cannot_be_reused_as_durable_prefix(tmp_path, monkeypatch):
    monkeypatch.setattr(ChainStateStore, "_FLUSH_INTERVAL", 60)
    db_path = str(tmp_path / "state.sqlite3")
    with closing(ChainStateStore(db_path)) as store:
        _, tracker = store.seed_and_save(
            "shared", history(gate_action(2, "echo truncated"), gate_action(4), gate_action(6)),
        )
        assert store.flush() == 1
        generation = tracker.generation
        tracker.advance(gate_action(2, "echo complete"), session_id="smoke")
        assert tracker.generation > generation
        assert len(tracker.nodes) == 3
        store.save(tracker)
        store.apply_action("shared", gate_action(5), "smoke")

    with closing(ChainStateStore(db_path)) as reopened:
        tracker = reopened.load("shared")
        assert [node.action_detail for node in tracker.nodes] == [
            "echo complete", "echo store-4", "echo store-5", "echo store-6",
        ]
        assert tracker.nodes[0].confirmed is not None


def test_rewrite_retains_durable_prefix_with_pending_append(tmp_path, monkeypatch):
    monkeypatch.setattr(ChainStateStore, "_FLUSH_INTERVAL", 60)
    db_path = str(tmp_path / "state.sqlite3")
    with closing(ChainStateStore(db_path)) as store:
        store.seed_and_save("shared", history(*(gate_action(index) for index in (2, 4, 6))))
        assert store.flush() == 1
        store.apply_action("shared", gate_action(8), "smoke")
        before = store._conn.total_changes
        store.apply_action("shared", gate_action(7), "smoke")
        assert store._conn.total_changes - before == 3
        assert store.flush() == 0

    with closing(ChainStateStore(db_path)) as reopened:
        tracker = reopened.load("shared")
        assert [node.action_detail for node in tracker.nodes] == [
            f"echo store-{index}" for index in (2, 4, 6, 7, 8)
        ]
        assert tracker.nodes[-1].confirmed is not None


@pytest.mark.parametrize("multi_process", [False, True])
def test_rollback_keeps_pre_rotation_window_and_generation(tmp_path, monkeypatch, multi_process):
    monkeypatch.setattr(ChainStateStore, "_FLUSH_INTERVAL", 60)
    monkeypatch.setattr(stateful, "_MAX_NODES", 4)
    monkeypatch.setenv("AGENT_MOSS_CHAIN_RETAIN_NODES", "2")
    monkeypatch.setenv("AGENT_MOSS_CHAIN_ARCHIVE_DIR", str(tmp_path / "archive"))
    db_path = str(tmp_path / "state.sqlite3")
    with closing(ChainStateStore(db_path)) as store:
        if multi_process:
            store.enable_multi_process()
        _, tracker = store.seed_and_save("shared", history(*(gate_action(index) for index in range(1, 5))))
        store.flush()
        generation = tracker.generation
        write = store._write_snapshot

        def fail_after_write(*args, **kwargs):
            write(*args, **kwargs)
            assert store._read_meta("shared")["persisted_seq"] == 2
            raise RuntimeError("synthetic rotation write failure")

        with monkeypatch.context() as patch:
            patch.setattr(store, "_write_snapshot", fail_after_write)
            with pytest.raises(RuntimeError, match="synthetic rotation write failure"):
                store.apply_action("shared", gate_action(5), "smoke")
        restored = store.load("shared")
        assert restored.generation == generation
        assert [node.action_detail for node in restored.nodes] == [f"echo store-{index}" for index in range(1, 5)]

    with closing(ChainStateStore(db_path)) as reopened:
        restored = reopened.load("shared")
        assert restored.generation == generation
        assert [node.seq for node in restored.nodes] == [0, 1, 2, 3]


@pytest.mark.parametrize("close_while_flushing", [False, True])
def test_overlapping_flush_or_close_keeps_a_later_action(tmp_path, monkeypatch, close_while_flushing):
    monkeypatch.setattr(ChainStateStore, "_FLUSH_INTERVAL", 60)
    db_path = str(tmp_path / "state.sqlite3")
    first_captured = Event()
    second_started = Event()
    release_first = Event()
    first_committed = Event()
    outcomes = []

    with closing(ChainStateStore(db_path)) as store:
        serialize = store._serialize_snapshot

        class ObservedFlushLock:
            def __init__(self):
                self._lock = Lock()

            def __enter__(self):
                if current_thread() is second:
                    second_started.set()
                self._lock.acquire()

            def __exit__(self, *_):
                self._lock.release()

        def coordinate_snapshots(agent_id, parts, start):
            if current_thread() is first:
                first_captured.set()
                assert release_first.wait(5)
            elif current_thread() is second:
                # Observe either the new lock boundary or an overlapping capture in the old path.
                second_started.set()
                assert first_committed.wait(5)
            return serialize(agent_id, parts, start)

        def flush_first():
            try:
                outcomes.append(store.flush())
            finally:
                first_committed.set()

        def finish_second():
            outcomes.append(store.close() if close_while_flushing else store.flush())

        monkeypatch.setattr(store, "_flush_lock", ObservedFlushLock(), raising=False)
        monkeypatch.setattr(store, "_serialize_snapshot", coordinate_snapshots)
        first = Thread(target=flush_first)
        second = Thread(target=finish_second)
        store.apply_action("shared", gate_action(1), "smoke")
        first.start()
        try:
            assert first_captured.wait(5)
            store.apply_action("shared", gate_action(2), "smoke")
            second.start()
            assert second_started.wait(5)
        finally:
            release_first.set()
            first.join(5)
            if second.ident is not None:
                second.join(5)
        assert not first.is_alive() and not second.is_alive()
        assert outcomes == [1, None if close_while_flushing else 1]

    with closing(ChainStateStore(db_path)) as reopened:
        assert [node.action_detail for node in reopened.load("shared").nodes] == [
            "echo store-1", "echo store-2",
        ]


def test_save_replaces_persisted_generation_after_replay(tmp_path, monkeypatch):
    monkeypatch.setattr(ChainStateStore, "_FLUSH_INTERVAL", 60)
    db_path = str(tmp_path / "state.sqlite3")
    with closing(ChainStateStore(db_path)) as store:
        store.apply_action("shared", gate_action(2), "smoke")
        assert store.flush() == 1
        tracker = store.load_or_new("shared")
        previous_generation = tracker.generation
        assert tracker.seed(history(gate_action(1))) == 1
        assert tracker.generation > previous_generation
        store.save(tracker)
        assert store.flush() == 1
        assert tracker.seed(history(gate_action(3))) == 1
        store.save(tracker)
        assert store.flush() == 1
        assert store.flush() == 0

    with closing(ChainStateStore(db_path)) as reopened:
        restored = reopened.load("shared")
        assert restored.generation == tracker.generation
        assert [node.action_detail for node in restored.nodes] == [
            "echo store-1", "echo store-2", "echo store-3",
        ]


def test_save_cannot_replace_a_generation_committed_since_loading(tmp_path, monkeypatch):
    monkeypatch.setattr(ChainStateStore, "_FLUSH_INTERVAL", 60)
    db_path = str(tmp_path / "state.sqlite3")
    with closing(ChainStateStore(db_path)) as first, closing(ChainStateStore(db_path)) as second:
        _, stale = first.seed_and_save("shared", history(gate_action(2, "echo truncated")))
        assert first.flush() == 1
        second.enable_multi_process()
        second.apply_action("shared", gate_action(2, "echo complete"), "smoke")
        corrected = second.load("shared")
        assert stale.generation < corrected.generation
        assert stale.seed(history(gate_action(1))) == 1
        assert stale.generation == corrected.generation
        with pytest.raises(ValueError, match="predates the persisted generation"):
            first.save(stale)
        assert first.flush() == 0

    with closing(ChainStateStore(db_path)) as reopened:
        restored = reopened.load("shared")
        assert restored.generation == corrected.generation
        assert [node.action_detail for node in restored.nodes] == ["echo complete"]


def test_snapshot_failure_leaves_other_buckets_and_retries_failed_one(tmp_path, monkeypatch):
    monkeypatch.setattr(ChainStateStore, "_FLUSH_INTERVAL", 60)
    db_path = str(tmp_path / "state.sqlite3")
    with closing(ChainStateStore(db_path)) as store:
        store.apply_action("first", gate_action(1), "smoke")
        store.apply_action("second", gate_action(2), "smoke")
        snapshot = stateful.StatefulChainTracker.to_snapshot_parts
        captured = 0

        def fail_second_capture(tracker):
            nonlocal captured
            captured += 1
            if captured == 2:
                raise ValueError("synthetic snapshot error")
            return snapshot(tracker)

        monkeypatch.setattr(stateful.StatefulChainTracker, "to_snapshot_parts", fail_second_capture)
        assert store.flush() == 1
        assert captured == 2
        assert store.flush() == 1
        assert store.flush() == 0

    with closing(ChainStateStore(db_path)) as reopened:
        assert [node.action_detail for node in reopened.load("first").nodes] == ["echo store-1"]
        assert [node.action_detail for node in reopened.load("second").nodes] == ["echo store-2"]


def test_unconfirmed_retry_keeps_synchronized_tracker(tmp_path):
    db_path = str(tmp_path / "state.sqlite3")
    with closing(ChainStateStore(db_path)) as first, closing(ChainStateStore(db_path)) as second:
        first.enable_multi_process()
        second.enable_multi_process()
        first.apply_action("shared", gate_action(1), "smoke")
        tracker = second.load("shared")
        first.apply_action("shared", gate_action(2), "smoke")

        with pytest.raises(stateful.StatefulAnalysisUnavailable):
            second.apply_action("shared", gate_action(3, uncertain=True), "smoke")
        assert second.load("shared") is tracker
        assert second._synced_seq["shared"] == 1
        assert len(tracker.nodes) == 2
        assert second.apply_action("shared", gate_action(3), "smoke").node.seq == 2
        assert len(tracker.nodes) == 3


@pytest.mark.parametrize("recreated_count", [1, 2])
def test_worker_replaces_cached_prefix_after_delete_and_rebuild(tmp_path, monkeypatch, recreated_count):
    def match_old_prefix(tracker, node):
        if node.action_detail == "echo follow" and any(
            previous.action_detail == "echo old prefix" for previous in tracker.nodes
        ):
            return stateful.ChainMatch("synthetic", ("TEST",), "high", "old prefix", [])
        return None

    monkeypatch.setattr(stateful.StatefulChainTracker, "_advance_chains", match_old_prefix)
    db_path = str(tmp_path / "state.sqlite3")
    with closing(ChainStateStore(db_path)) as first, closing(ChainStateStore(db_path)) as second:
        first.enable_multi_process()
        second.enable_multi_process()
        first.apply_action("shared", gate_action(1, "echo old prefix"), "smoke")
        cached = second.load("shared")
        before = cached.generation
        first.delete("shared")
        assert first.load("shared") is None
        with closing(ChainStateStore(db_path)) as restarted:
            assert restarted.load("shared") is None
            restarted.enable_multi_process()
            for index in range(2, 2 + recreated_count):
                restarted.apply_action("shared", gate_action(index), "smoke")
        follow = second.apply_action("shared", gate_action(4, "echo follow"), "smoke")
        assert not follow.should_block
        assert second.load("shared") is cached
        assert cached.generation > before
        assert [node.action_detail for node in cached.nodes] == [
            *[f"echo store-{index}" for index in range(2, 2 + recreated_count)],
            "echo follow",
        ]


def test_flush_captured_before_delete_cannot_resurrect_state(tmp_path, monkeypatch):
    monkeypatch.setattr(ChainStateStore, "_FLUSH_INTERVAL", 60)
    db_path = str(tmp_path / "state.sqlite3")
    captured = Event()
    release = Event()
    written = []
    with closing(ChainStateStore(db_path)) as writer, closing(ChainStateStore(db_path)) as deleter:
        writer.apply_action("shared", gate_action(1), "smoke")
        writer.save(writer.load("shared"))
        serialize = writer._serialize_snapshot

        def pause_snapshot(agent_id, parts, start):
            if current_thread() is delayed:
                captured.set()
                assert release.wait(5)
            return serialize(agent_id, parts, start)

        monkeypatch.setattr(writer, "_serialize_snapshot", pause_snapshot)
        delayed = Thread(target=lambda: written.append(writer.flush()))
        delayed.start()
        try:
            assert captured.wait(5)
            deleter.delete("shared")
        finally:
            release.set()
            delayed.join(5)
        assert written == [0]
        assert writer.load("shared") is None

    with closing(ChainStateStore(db_path)) as restarted:
        assert restarted.load("shared") is None
        restarted.apply_action("shared", gate_action(2), "smoke")
        assert restarted.flush() == 1
    with closing(ChainStateStore(db_path)) as restarted:
        tracker = restarted.load("shared")
        assert tracker.generation > 0
        assert [node.action_detail for node in tracker.nodes] == ["echo store-2"]


def test_delete_fences_unmigrated_legacy_generation(tmp_path):
    db_path = str(tmp_path / "state.sqlite3")
    with closing(ChainStateStore(db_path)) as store:
        store._conn.execute(
            "INSERT INTO chain_state VALUES (?, ?, ?)",
            ("legacy", dumps({"generation": 5, "nodes": []}), 0),
        )
        store.delete("legacy")
        assert store.load("legacy") is None
    with closing(ChainStateStore(db_path)) as restarted:
        assert restarted.load("legacy") is None
        tracker = restarted.load_or_new("legacy")
        assert tracker.nodes == []
        assert tracker.generation == 6
        restarted.apply_action("legacy", gate_action(1), "smoke")
        assert restarted.flush() == 1


@pytest.mark.parametrize("observe_delete", [False, True])
def test_save_rejects_tracker_loaded_before_delete(tmp_path, monkeypatch, observe_delete):
    monkeypatch.setattr(ChainStateStore, "_FLUSH_INTERVAL", 60)
    db_path = str(tmp_path / "state.sqlite3")
    with closing(ChainStateStore(db_path)) as store:
        store.apply_action("shared", gate_action(1), "smoke")
        assert store.flush() == 1
        stale = store.load("shared")
        store.delete("shared")
        if observe_delete:
            assert store.load("shared") is None
        with pytest.raises(ValueError, match="predates the persisted generation"):
            store.save(stale)
        assert store.flush() == 0
        assert store.load("shared") is None

    with closing(ChainStateStore(db_path)) as restarted:
        assert restarted.load("shared") is None
        assert restarted.load_or_new("shared").generation > stale.generation


@pytest.mark.parametrize("same_store", [False, True])
def test_save_rejects_replay_from_before_delete_at_equal_generation(tmp_path, monkeypatch, same_store):
    monkeypatch.setattr(ChainStateStore, "_FLUSH_INTERVAL", 60)
    db_path = str(tmp_path / "state.sqlite3")
    with closing(ChainStateStore(db_path)) as writer, closing(ChainStateStore(db_path)) as other:
        writer.apply_action("shared", gate_action(2), "smoke")
        assert writer.flush() == 1
        stale = writer.load("shared")
        assert stale.seed(history(gate_action(1))) == 1

        deleter = writer if same_store else other
        deleter.delete("shared")
        current = deleter.load_or_new("shared")
        assert current.generation == stale.generation
        with pytest.raises(ValueError, match="predates the persisted generation"):
            writer.save(stale)
        assert writer.flush() == int(same_store)

    with closing(ChainStateStore(db_path)) as reopened:
        current = reopened.load_or_new("shared")
        assert current.generation == stale.generation
        assert current.nodes == []


def test_save_rejects_origin_cursor_older_than_database(tmp_path, monkeypatch):
    monkeypatch.setattr(ChainStateStore, "_FLUSH_INTERVAL", 60)
    db_path = str(tmp_path / "state.sqlite3")
    with closing(ChainStateStore(db_path)) as first, closing(ChainStateStore(db_path)) as second:
        first.apply_action("shared", gate_action(1), "smoke")
        assert first.flush() == 1
        stale = first.load("shared")
        second.enable_multi_process()
        second.apply_action("shared", gate_action(2), "smoke")
        assert stale.generation == second.load("shared").generation
        stale.advance(gate_action(3), session_id="smoke")
        with pytest.raises(ValueError, match="predates the persisted generation"):
            first.save(stale)
        assert [node.action_detail for node in first.load("shared").nodes] == [
            "echo store-1", "echo store-2",
        ]


@pytest.mark.parametrize("seeded_call", [1, 3])
def test_save_is_committed_before_next_worker_action(tmp_path, monkeypatch, seeded_call):
    monkeypatch.setattr(ChainStateStore, "_FLUSH_INTERVAL", 60)
    db_path = str(tmp_path / "state.sqlite3")
    with closing(ChainStateStore(db_path)) as first, closing(ChainStateStore(db_path)) as second:
        first.enable_multi_process()
        second.enable_multi_process()
        first.apply_action("shared", gate_action(2), "smoke")
        other_tracker = second.load("shared")
        tracker = first.load("shared")
        assert tracker.seed(history(gate_action(seeded_call))) == 1
        first.save(tracker)
        second.apply_action("shared", gate_action(4), "smoke")
        assert second.load("shared") is other_tracker
        assert [node.seq for node in other_tracker.nodes] == [0, 1, 2]
        assert first.flush() == 0

    with closing(ChainStateStore(db_path)) as reopened:
        tracker = reopened.load("shared")
        assert [node.seq for node in tracker.nodes] == [0, 1, 2]
        assert [node.action_detail for node in tracker.nodes] == [
            f"echo store-{index}" for index in sorted([2, seeded_call, 4])
        ]


@pytest.mark.parametrize("seeded_call", [1, 3])
def test_save_rejects_edit_based_on_previous_worker_commit(tmp_path, monkeypatch, seeded_call):
    monkeypatch.setattr(ChainStateStore, "_FLUSH_INTERVAL", 60)
    db_path = str(tmp_path / "state.sqlite3")
    with closing(ChainStateStore(db_path)) as first, closing(ChainStateStore(db_path)) as second:
        first.enable_multi_process()
        second.enable_multi_process()
        first.apply_action("shared", gate_action(2), "smoke")
        stale = second.load("shared")
        stale.advance(gate_action(4), session_id="smoke")
        current = first.load("shared")
        assert current.seed(history(gate_action(seeded_call))) == 1
        first.save(current)

        with pytest.raises(ValueError, match="predates the persisted generation or cursor"):
            second.save(stale)
        loaded = second.load("shared")
        assert loaded is not stale
        assert [node.action_detail for node in loaded.nodes] == [
            f"echo store-{index}" for index in sorted([2, seeded_call])
        ]
        second.apply_action("shared", gate_action(4), "smoke")
        assert [node.seq for node in loaded.nodes] == [0, 1, 2]


def test_save_rolls_back_and_evicts_uncommitted_tracker_on_write_error(tmp_path, monkeypatch):
    monkeypatch.setattr(ChainStateStore, "_FLUSH_INTERVAL", 60)
    db_path = str(tmp_path / "state.sqlite3")
    with closing(ChainStateStore(db_path)) as store:
        store.enable_multi_process()
        store.apply_action("shared", gate_action(1), "smoke")
        tracker = store.load("shared")
        tracker.advance(gate_action(2), session_id="smoke")
        write = store._write_snapshot

        def fail_after_write(*args, **kwargs):
            write(*args, **kwargs)
            raise RuntimeError("synthetic transaction failure")

        with monkeypatch.context() as patch:
            patch.setattr(store, "_write_snapshot", fail_after_write)
            with pytest.raises(RuntimeError, match="synthetic transaction failure"):
                store.save(tracker)
        loaded = store.load("shared")
        assert loaded is not tracker
        assert [node.action_detail for node in loaded.nodes] == ["echo store-1"]
        assert store.flush() == 0
        store.save(tracker)

    with closing(ChainStateStore(db_path)) as reopened:
        assert [node.action_detail for node in reopened.load("shared").nodes] == [
            "echo store-1", "echo store-2",
        ]


def insert_legacy_snapshot(store):
    tracker = stateful.StatefulChainTracker(agent_id="shared")
    tracker.advance(gate_action(1), session_id="smoke")
    store._conn.execute(
        "INSERT INTO chain_state VALUES (?, ?, ?)",
        ("shared", dumps(tracker.to_snapshot()), 0),
    )


@pytest.mark.parametrize("multi_process", [False, True])
def test_save_does_not_shadow_unmigrated_legacy_bucket(tmp_path, monkeypatch, multi_process):
    monkeypatch.setattr(ChainStateStore, "_FLUSH_INTERVAL", 60)
    db_path = str(tmp_path / "state.sqlite3")
    with closing(ChainStateStore(db_path)) as store:
        if multi_process:
            store.enable_multi_process()
        insert_legacy_snapshot(store)
        detached = stateful.StatefulChainTracker(agent_id="shared")
        detached.advance(gate_action(2), session_id="smoke")
        with pytest.raises(ValueError, match="unmigrated legacy snapshot"):
            store.save(detached)
        assert store.flush() == 0
        loaded = store.load("shared")
        assert [node.action_detail for node in loaded.nodes] == ["echo store-1"]
        loaded.advance(gate_action(2), session_id="smoke")
        store.save(loaded)

    with closing(ChainStateStore(db_path)) as reopened:
        assert [node.action_detail for node in reopened.load("shared").nodes] == [
            "echo store-1", "echo store-2",
        ]


def test_save_validated_before_legacy_arrived_does_not_shadow_legacy_at_flush(tmp_path, monkeypatch):
    monkeypatch.setattr(ChainStateStore, "_FLUSH_INTERVAL", 60)
    db_path = str(tmp_path / "state.sqlite3")
    with closing(ChainStateStore(db_path)) as store:
        detached = stateful.StatefulChainTracker(agent_id="shared")
        detached.advance(gate_action(2), session_id="smoke")
        store.save(detached)
        insert_legacy_snapshot(store)
        assert store.flush() == 0
        loaded = store.load("shared")
        assert [node.action_detail for node in loaded.nodes] == ["echo store-1"]


def test_uncertain_single_worker_retry_does_not_snapshot_or_restore(tmp_path, monkeypatch):
    monkeypatch.setattr(ChainStateStore, "_FLUSH_INTERVAL", 60)
    monkeypatch.setattr(stateful, "_MAX_NODES", 2)
    db_path = str(tmp_path / "state.sqlite3")
    with closing(ChainStateStore(db_path)) as store:
        store.apply_action("shared", gate_action(2), "smoke")
        confirmed = store.apply_action("shared", gate_action(3), "smoke")
        tracker = store.load("shared")
        original_nodes = list(tracker.nodes)
        calls = []

        with monkeypatch.context() as patch:
            def record_snapshot():
                calls.append("snapshot")
                return snapshot()

            def record_restore(parts):
                calls.append("restore")
                restore(parts)

            snapshot, restore = tracker.to_snapshot_parts, tracker.restore
            patch.setattr(tracker, "to_snapshot_parts", record_snapshot)
            patch.setattr(tracker, "restore", record_restore)
            with pytest.raises(stateful.UnconfirmedGateRetry):
                store.apply_action("shared", gate_action(1, uncertain=True), "smoke")
            retry = store.apply_action("shared", gate_action(3, uncertain=True), "smoke")
        assert calls == []
        assert retry.node is confirmed.node
        assert store.load("shared") is tracker
        assert all(current is original for current, original in zip(tracker.nodes, original_nodes, strict=True))
