"""Gate replay uses ordinary synthetic actions and a fixture rule set."""

import datetime as dt
import gzip
import json
import re
import time

import pytest

from agent_moss.engine.formal_engine import stateful


def _tracker(main_stages=("START", "FINISH")):
    tracker = stateful.StatefulChainTracker(agent_id="fixture")
    tracker.from_rules({
        "combo_chains": {
            "stages": {
                "START": [r"fixture-start$"],
                "MIDDLE": [r"fixture-middle$"],
                "FINISH": [r"fixture-finish$"],
                "FOLLOW": [r"fixture-follow$"],
                "CRED": [r"fixture-source"],
            },
            "chains": [
                {"id": "fixture-follow", "stages": ["FINISH", "FOLLOW"]},
                {"id": "fixture-main", "stages": main_stages},
            ],
        },
    })
    return tracker


def _action(number, text, timestamp="2026-11-23T08:00:00+00:00"):
    return {
        "action_type": "bash",
        "action_detail": f"echo {text}",
        "called_at": timestamp,
        "_gate_call_id": f"{number:032x}",
        "_gate_call_time_us": number,
    }


def _sessions(session_id, *actions):
    return [{"session_id": session_id, "action_history": list(actions)}]


def _legacy_action(number, text):
    return {
        "action_type": "bash",
        "action_detail": f"echo {text}",
        "called_at": f"2026-11-23T08:00:{number:02d}+00:00",
    }


@pytest.mark.skipif(not hasattr(time, "tzset"), reason="requires a configurable process timezone")
@pytest.mark.parametrize("snapshot_format", [None, "legacy-key", "legacy-key-list"])
@pytest.mark.parametrize("numbered", [False, True])
@pytest.mark.parametrize("audit_time", [
    "2026-11-23T10:01:00Z", "2026-11-23 10:01:00",
    "2026-11-23T10:01:00.1Z", "2026-11-23 10:01:00.123456789",
])
def test_review_orders_moss_receipt_and_audit_time_in_same_timezone(monkeypatch, snapshot_format, numbered, audit_time):
    class FixedDatetime(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            receipt = cls(2026, 11, 23, 10, tzinfo=dt.timezone.utc)
            return receipt.astimezone(tz) if tz is not None else receipt.astimezone().replace(tzinfo=None)

    try:
        with monkeypatch.context() as local:
            local.setenv("TZ", "Asia/Shanghai")
            time.tzset()
            local.setattr(dt, "datetime", FixedDatetime)
            local.setattr(stateful, "datetime", FixedDatetime)
            tracker = _tracker(("START", "MIDDLE", "FINISH"))
            start = {"action_type": "bash", "action_detail": "echo fixture-start"}
            if numbered:
                start = _action(1, "fixture-start", timestamp="")
            tracker.advance(start, session_id="live")
            if snapshot_format is not None:
                snapshot = tracker.to_snapshot()
                snapshot["nodes"][0]["timestamp"] = "2026-11-23T18:00:00"
                if snapshot_format == "legacy-key-list":
                    snapshot["nodes"][0].pop("legacy_fingerprint")
                    snapshot["seeded_keys"] = []
                tracker = _tracker(("START", "MIDDLE", "FINISH"))
                tracker.restore(snapshot)

            middle = {**_legacy_action(1, "fixture-middle"), "called_at": audit_time}
            assert tracker.seed(_sessions("audit", middle)) == 1
            assert [node.action_detail for node in tracker.nodes] == [start["action_detail"], middle["action_detail"]]
            assert tracker.nodes[1].timestamp == audit_time
            assert tracker.seed(_sessions("audit", middle)) == 0
            finish = {**_legacy_action(2, "fixture-finish"), "called_at": "2026-11-23T10:02:00Z"}
            assert tracker.advance(finish, session_id="live").matched.chain_id == "fixture-main"
            if snapshot_format is None:
                assert tracker.nodes[0].timestamp == "2026-11-23T10:00:00+00:00"
    finally:
        time.tzset()


def test_truncated_review_node_is_corrected_with_the_original_verdict():
    start, finish = _action(1, "fixture-start"), _action(2, "fixture-finish")
    filler, follow = _action(3, "fixture-gap"), _action(4, "fixture-follow")
    baseline = _tracker()
    baseline.advance(start, session_id="s")
    expected = baseline.advance(finish, session_id="s")
    baseline.advance(filler, session_id="s")
    expected_next = baseline.advance(follow, session_id="s")
    assert expected.should_block and expected_next.should_block

    reviewed = _tracker()
    reviewed.advance(start, session_id="s")
    assert reviewed.seed(_sessions("s", {**finish, "action_detail": "echo fixture-fin",
                                         "action_type": "tool-alias"})) == 1
    assert reviewed.nodes[-1].confirmed is None
    reviewed.advance(filler, session_id="s")
    result = reviewed.advance(finish, session_id="s")
    assert result.matched.to_judgment() == expected.matched.to_judgment()
    assert [node.action_detail for node in reviewed.nodes] == [
        start["action_detail"], finish["action_detail"], filler["action_detail"],
    ]
    assert reviewed.advance(follow, session_id="s").matched.to_judgment() == expected_next.matched.to_judgment()
    assert reviewed.seed(_sessions("s", start, finish, filler, follow)) == 0


@pytest.mark.parametrize("fraction", ["", ".1", ".0123", ".123456789"])
def test_review_orders_z_and_offset_timestamps_without_changing_the_stored_time(fraction):
    start = {**_legacy_action(1, "fixture-start"), "called_at": f"2026-11-23T09:00:00{fraction}Z"}
    middle = {**_legacy_action(2, "fixture-middle"), "called_at": "2026-11-23T09:01:00+00:00"}
    tracker = _tracker(("START", "MIDDLE", "FINISH"))
    tracker.advance(start, session_id="live")

    assert tracker.seed(_sessions("audit", middle)) == 1
    assert [node.timestamp for node in tracker.nodes] == [start["called_at"], middle["called_at"]]
    assert tracker.seed(_sessions("live", start) + _sessions("audit", middle)) == 0
    assert tracker.advance(_legacy_action(3, "fixture-finish"), session_id="live").should_block


@pytest.mark.parametrize("digits", range(1, 13))
@pytest.mark.parametrize(("clock", "separator", "suffix"), [
    ("2026-11-23T09:00:00", ".", "Z"),
    ("2026-11-23T09:00:00", ".", "+00:00"),
    ("2026-11-23T17:00:00", ".", "+08:00"),
    ("2026-11-23T05:30:00", ".", "-03:30"),
    ("2026-11-23 09:00:00", ".", ""),
    ("2026-11-23T09:00:00", ",", "Z"),
])
def test_history_time_normalizes_fractional_seconds(digits, clock, separator, suffix):
    fraction = "123456789012"[:digits]
    expected_fraction = fraction.ljust(6, "0") if digits <= 6 else fraction.rstrip("0")
    assert stateful._history_time(f"{clock}{separator}{fraction}{suffix}") == f"2026-11-23T09:00:00.{expected_fraction}"


@pytest.mark.parametrize(("value", "expected"), [
    ("2026-11-23T09:00:00.100000000Z", "2026-11-23T09:00:00.100000"),
    ("2026-11-23T09:00:00.000000000001Z", "2026-11-23T09:00:00.000000000001"),
    ("2026-11-24T00:15:00.123456789+08:00", "2026-11-23T16:15:00.123456789"),
    ("2026-11-23T23:59:59.999999999-01:00", "2026-11-24T00:59:59.999999999"),
    ("2026-11-23T09:00:00.100000001+00:00:01.123456", "2026-11-23T08:59:58.976544001"),
    ("2026-11-23T09:00:00..1Z", None),
    ("2026-11-23T09:00:00.1xZ", None),
    ("2026-11-23T09:00:00.1Zx", None),
    ("2026-11-23T09:00:00.1,2Z", None),
    ("2026-02-29T09:00:00.1Z", None),
    ("2026-11-23T09:00:60.123456789Z", None),
    ("2026-11-23T09:00:00.1+25:00", None),
])
def test_history_time_handles_fractional_boundaries_and_rejects_malformed_times(value, expected):
    assert stateful._history_time(value) == expected


def test_review_orders_fractional_timestamps_within_the_same_microsecond():
    start = {**_legacy_action(1, "fixture-start"), "called_at": "2026-11-23T09:00:00.123456701Z"}
    middle = {**_legacy_action(2, "fixture-middle"), "called_at": "2026-11-23T17:00:00.123456702+08:00"}
    tracker = _tracker(("START", "MIDDLE", "FINISH"))
    # Supply the two sessions in the opposite order from the actual calls.
    assert tracker.seed(_sessions("audit", middle) + _sessions("live", start)) == 2
    assert [node.timestamp for node in tracker.nodes] == [start["called_at"], middle["called_at"]]
    assert tracker.advance(_legacy_action(3, "fixture-finish"), session_id="live").should_block


def test_equivalent_fractional_timestamps_keep_distinct_legacy_fingerprints():
    short = {**_legacy_action(1, "fixture-same"), "called_at": "2026-11-23T09:00:00.1Z"}
    padded = {**short, "called_at": "2026-11-23T09:00:00.100000000+00:00"}
    assert stateful._history_time(short["called_at"]) == stateful._history_time(padded["called_at"])

    tracker = _tracker()
    assert tracker.seed(_sessions("s", short, padded)) == 2
    assert [node.timestamp for node in tracker.nodes] == [short["called_at"], padded["called_at"]]
    assert tracker.seed(_sessions("s", short, padded)) == 0


def test_missing_prefix_is_inserted_before_an_existing_later_action():
    start, finish, follow = (_action(1, "fixture-start"), _action(2, "fixture-finish"),
                             _action(3, "fixture-follow"))
    baseline = _tracker()
    baseline.advance(start, session_id="a")
    baseline.advance(finish, session_id="b")
    expected = baseline.advance(follow, session_id="a")
    reviewed = _tracker()
    reviewed.advance(finish, session_id="b")
    assert reviewed.seed(_sessions("a", start) + _sessions("b", finish)) == 1
    assert [node.session_id for node in reviewed.nodes] == ["a", "b"]
    assert reviewed.advance(follow, session_id="a").matched.to_judgment() == expected.matched.to_judgment()


@pytest.mark.parametrize("from_review", [False, True])
@pytest.mark.parametrize("at_capacity", [False, True])
def test_late_gate_action_preserves_legacy_chain_order(from_review, at_capacity, monkeypatch, tmp_path):
    monkeypatch.setattr(stateful, "_MAX_NODES", 6)
    monkeypatch.setenv("AGENT_MOSS_CHAIN_RETAIN_NODES", "4")
    tracker = _tracker(("START", "MIDDLE", "FINISH"))
    late = _action(4, "fixture-late")
    start = _action(5, "fixture-start")
    middle = {"action_type": "bash", "action_detail": "echo fixture-middle"}
    if at_capacity:
        for number in range(1, 4):
            tracker.advance(_action(number, f"fixture-old-{number}"), session_id="s")
    tracker.advance(start, session_id="s")
    tracker.advance(middle, session_id="s")
    if at_capacity:
        tracker.advance(_action(6, "fixture-tail"), session_id="s")

    if from_review:
        assert tracker.seed(_sessions("s", late), archive_dir=tmp_path) == 1
    else:
        tracker.advance(late, session_id="s", archive_dir=tmp_path)

    actions = [node.action_detail for node in tracker.nodes]
    begin = actions.index(late["action_detail"])
    assert actions[begin:begin + 3] == [
        late["action_detail"], start["action_detail"], middle["action_detail"],
    ]
    result = tracker.advance(_action(7, "fixture-finish"), session_id="s", archive_dir=tmp_path)
    assert result.should_block
    assert [entry[2] for entry in result.matched.path] == [
        start["action_detail"], middle["action_detail"], "echo fixture-finish",
    ]


def test_review_batch_archive_numbers_nodes_in_merge_order(monkeypatch, tmp_path):
    monkeypatch.setattr(stateful, "_MAX_NODES", 3)
    tracker = _tracker()
    batch = [_action(i, f"fixture-batch-{i}") for i in (6, 1, 4, 2, 5, 3)]

    assert tracker.seed(_sessions("s", *batch), archive_dir=tmp_path) == 3

    archive, = tmp_path.glob("*.jsonl.gz")
    with gzip.open(archive, "rt", encoding="utf-8") as archive_file:
        archived = [json.loads(line) for line in archive_file]
    assert [(node["seq"], node["gate_call_time_us"]) for node in archived] == [(0, 1), (1, 2), (2, 3)]
    assert [(node.seq, node.gate_call_time_us) for node in tracker.nodes] == [(0, 4), (1, 5), (2, 6)]
    assert tracker.seed(_sessions("s", *batch), archive_dir=tmp_path) == 0


@pytest.mark.parametrize("middle_already_live", [False, True])
def test_review_inserts_legacy_prefix_before_its_numbered_action(middle_already_live):
    start = _legacy_action(1, "fixture-start")
    middle = _action(2, "fixture-middle")
    filler = _action(3, "fixture-filler")
    finish = _action(4, "fixture-finish")
    history = _sessions("s", start, middle, filler)
    baseline = _tracker(("START", "MIDDLE", "FINISH"))
    assert baseline.seed(history) == 3
    expected = baseline.advance(finish, session_id="s")
    assert expected.should_block

    tracker = _tracker(("START", "MIDDLE", "FINISH"))
    if middle_already_live:
        tracker.advance(middle, session_id="s")
    tracker.advance(filler, session_id="s")
    assert tracker.seed(history) == (1 if middle_already_live else 2)
    assert [node.action_detail for node in tracker.nodes] == [
        start["action_detail"], middle["action_detail"], filler["action_detail"],
    ]
    assert tracker.seed(history) == 0
    result = tracker.advance(finish, session_id="s")
    assert result.should_block
    assert result.matched.to_judgment() == expected.matched.to_judgment()


def test_review_inserts_missing_legacy_action_before_retained_legacy_successor():
    start = _legacy_action(1, "fixture-start")
    middle = _legacy_action(2, "fixture-middle")
    gap = _action(3, "fixture-gap")
    tail = _action(4, "fixture-tail")
    history = _sessions("s", start, middle, gap, tail)

    tracker = _tracker(("START", "MIDDLE", "FINISH"))
    tracker.advance(middle, session_id="s")
    tracker.advance(tail, session_id="s")
    assert tracker.seed(history) == 2
    assert [node.action_detail for node in tracker.nodes] == [
        action["action_detail"] for action in (start, middle, gap, tail)
    ]
    assert tracker.seed(history) == 0
    assert tracker.advance(_action(5, "fixture-finish"), session_id="s").should_block


@pytest.mark.parametrize("other_session", [False, True])
def test_review_inserts_numbered_start_before_retained_legacy_middle(other_session):
    start = _action(4, "fixture-start")
    middle = _legacy_action(5, "fixture-middle")
    gap = _legacy_action(4, "fixture-legacy-gap")
    finish = _action(7, "fixture-finish")
    earlier = _action(1, "fixture-keep-earlier")
    later = _action(6, "fixture-keep-later")
    missing = _action(3, "fixture-other-missing")
    tracker = _tracker(("START", "MIDDLE", "FINISH"))
    if other_session:
        tracker.advance(earlier, session_id="other")
    tracker.advance(middle, session_id="s")
    if other_session:
        history = _sessions("s", start, gap, middle)
        tracker.advance(later, session_id="other")
        history += _sessions("other", earlier, missing, later)
        expected = [earlier, missing, start, gap, middle, later]
    else:
        history = _sessions("s", start, middle)
        expected = [start, middle]

    assert tracker.seed(history) == (3 if other_session else 1)
    assert [node.action_detail for node in tracker.nodes] == [a["action_detail"] for a in expected]
    assert tracker.seed(history) == 0
    result = tracker.advance(finish, session_id="s")
    assert result.should_block
    assert [entry[2] for entry in result.matched.path] == [
        a["action_detail"] for a in (start, middle, finish)
    ]


def test_review_preserves_shared_gate_order_when_legacy_anchor_conflicts():
    middle = _legacy_action(2, "fixture-middle")
    earlier = _action(1, "fixture-numbered-earlier")
    start = _action(3, "fixture-start")
    tracker = _tracker(("START", "MIDDLE", "FINISH"))
    tracker.advance(middle, session_id="s")
    tracker.advance(earlier, session_id="other")

    assert tracker.seed(_sessions("s", start, middle)) == 1
    assert [node.action_detail for node in tracker.nodes] == [
        a["action_detail"] for a in (middle, earlier, start)
    ]


def test_review_keeps_same_session_legacy_tail_after_numbered_start():
    start = {**_action(3, "fixture-start"), "_sqlite_review_rank": 3}
    middle = {**_legacy_action(3, "fixture-middle"), "_sqlite_review_rank": 1}
    other = {**_action(1, "fixture-other"), "_sqlite_review_rank": 2}
    finish = _action(4, "fixture-finish")
    tracker = _tracker(("START", "MIDDLE", "FINISH"))
    history = _sessions("a", start, middle) + _sessions("b", other)

    assert tracker.seed(history) == 3
    assert [node.action_detail for node in tracker.nodes] == [
        a["action_detail"] for a in (other, start, middle)
    ]
    assert tracker.seed(history) == 0
    assert tracker.advance(finish, session_id="a").should_block


def test_review_keeps_sqlite_order_across_sessions_for_equal_audit_times():
    calls = [{**_legacy_action(1, f"fixture-ranked-{i}"), "_sqlite_review_rank": 5 - i}
             for i in range(1, 5)]
    history = _sessions("a", calls[0], calls[2]) + _sessions("b", calls[1], calls[3])
    tracker = _tracker()

    assert tracker.seed(history) == 4
    assert [node.action_detail for node in tracker.nodes] == [call["action_detail"] for call in calls]
    assert tracker.seed(history) == 0


def test_review_does_not_evict_retained_calls_with_archived_legacy_history(monkeypatch, tmp_path):
    monkeypatch.setattr(stateful, "_MAX_NODES", 6)
    monkeypatch.setenv("AGENT_MOSS_CHAIN_RETAIN_NODES", "3")
    calls = [_legacy_action(i, f"fixture-call-{i}") for i in range(1, 9)]
    tracker = _tracker()
    for call in calls:
        tracker.advance(call, session_id="s", archive_dir=tmp_path / "live")
    initial = tracker.to_snapshot()
    expected = [call["action_detail"] for call in calls[3:]]
    assert [node.action_detail for node in tracker.nodes] == expected

    restored = _tracker()
    restored.restore(initial)
    history = _sessions("s", *calls[:3])
    assert restored.seed(history, archive_dir=tmp_path / "review") == 0
    assert [node.action_detail for node in restored.nodes] == expected
    assert restored.to_snapshot() == initial
    assert not (tmp_path / "review").exists()


def test_review_older_call_does_not_force_rotation_when_newer_call_fits(monkeypatch, tmp_path):
    monkeypatch.setattr(stateful, "_MAX_NODES", 6)
    monkeypatch.setenv("AGENT_MOSS_CHAIN_RETAIN_NODES", "3")
    tracker = _tracker()
    retained = [_legacy_action(i, f"fixture-retained-{i}") for i in range(4, 9)]
    older = _legacy_action(1, "fixture-older")
    newer = _legacy_action(9, "fixture-newer")
    assert tracker.seed(_sessions("s", *retained)) == 5

    assert tracker.seed(_sessions("s", older, newer), archive_dir=tmp_path) == 1
    assert [node.action_detail for node in tracker.nodes] == [
        call["action_detail"] for call in (*retained, newer)
    ]


def test_review_allows_distinct_legacy_action_at_archive_time_boundary(tmp_path):
    calls = [_legacy_action(3, f"fixture-tied-{i}") for i in range(4)]
    tracker = _tracker()
    assert tracker.seed(_sessions("s", *calls)) == 4
    assert tracker.rotate(tmp_path, retain=2)[0] == 2
    tracker.restore(json.loads(json.dumps(tracker.to_snapshot())))
    assert tracker.seed(_sessions("s", *calls)) == 0

    distinct = _legacy_action(3, "fixture-tied-missing")
    assert tracker.seed(_sessions("s", distinct)) == 1
    assert [node.action_detail for node in tracker.nodes] == [
        call["action_detail"] for call in [*calls[2:], distinct]
    ]
    assert tracker.seed(_sessions("s", distinct)) == 0


def test_review_keeps_old_archive_fingerprint_when_the_cutoff_gains_precision(tmp_path):
    def call(fraction, detail):
        return {**_legacy_action(1, detail), "called_at": f"2026-11-23T09:00:00.{fraction}Z"}

    archived = call("1234569", "fixture-archived")
    first = call("1234561", "fixture-first")
    last = call("1234568", "fixture-last")
    distinct = call("12345695", "fixture-distinct")
    tracker = _tracker()
    assert tracker.seed(_sessions("s", first, last)) == 2
    snapshot = tracker.to_snapshot()
    snapshot["legacy_archive_boundary"] = ["2026-11-23T09:00:00.123456", [tracker._legacy_key(archived, "s")]]
    tracker.restore(snapshot)

    assert tracker.seed(_sessions("s", archived)) == 0
    assert tracker.rotate(tmp_path, retain=1)[0] == 1
    assert tracker.to_snapshot()["legacy_archive_boundary"][0] == "2026-11-23T09:00:00.1234561"
    tracker.restore(json.loads(json.dumps(tracker.to_snapshot())))
    assert tracker.seed(_sessions("s", archived, distinct)) == 1
    assert [node.action_detail for node in tracker.nodes] == [last["action_detail"], distinct["action_detail"]]


@pytest.mark.parametrize("archived_second", [1, 5])
def test_review_fills_gap_in_mixed_window_after_rotation(tmp_path, archived_second):
    archived = _legacy_action(archived_second, "fixture-archived")
    start = _action(2, "fixture-start", timestamp="2026-11-23T08:00:02Z")
    middle = _legacy_action(3, "fixture-middle")
    later = _legacy_action(4, "fixture-later")
    finish = _action(6, "fixture-finish", timestamp="2026-11-23T08:00:06Z")
    tracker = _tracker(("START", "MIDDLE", "FINISH"))
    for call in (archived, start, later):
        tracker.advance(call, session_id="s")
    assert tracker.rotate(tmp_path, retain=2)[0] == 1
    tracker.restore(json.loads(json.dumps(tracker.to_snapshot())))

    assert tracker.seed(_sessions("s", start, middle, later), archive_dir=tmp_path) == 1
    assert [node.action_detail for node in tracker.nodes] == [
        call["action_detail"] for call in (start, middle, later)
    ]
    assert tracker.advance(finish, session_id="s").should_block


def test_legacy_archive_boundary_tracks_window_after_a_late_numbered_start(tmp_path):
    tracker = _tracker(("START", "MIDDLE", "FINISH"))
    tail = _legacy_action(5, "fixture-tail")
    tracker.seed(_sessions("other", _legacy_action(4, "fixture-archived"), tail))
    assert tracker.rotate(tmp_path, retain=1)[0] == 1
    start = _action(2, "fixture-start", timestamp="2026-11-23T08:00:02Z")
    middle = _legacy_action(3, "fixture-middle")
    tracker.advance(start, session_id="s")
    tracker.restore(json.loads(json.dumps(tracker.to_snapshot())))

    assert tracker.seed(_sessions("s", start, middle)) == 1
    assert tracker.advance(_action(6, "fixture-finish"), session_id="s").should_block


def test_review_older_candidates_cannot_evict_newer_live_window(monkeypatch, tmp_path):
    monkeypatch.setattr(stateful, "_MAX_NODES", 6)
    monkeypatch.setenv("AGENT_MOSS_CHAIN_RETAIN_NODES", "3")
    calls = [_legacy_action(i, f"fixture-window-{i}") for i in range(1, 9)]
    tracker = _tracker()
    for call in calls[3:]:
        tracker.advance(call, session_id="s")

    assert tracker.seed(_sessions("s", *calls[:3]), archive_dir=tmp_path) == 1
    assert [node.action_detail for node in tracker.nodes] == [call["action_detail"] for call in calls[2:]]
    assert tracker.seed(_sessions("s", *calls[:3]), archive_dir=tmp_path) == 0


def test_oversize_legacy_review_keeps_same_recent_window(monkeypatch, tmp_path):
    monkeypatch.setattr(stateful, "_MAX_NODES", 3)
    actions = [_legacy_action(i, f"fixture-window-{i}") for i in range(1, 7)]
    history = _sessions("s", *actions)
    tracker = _tracker()
    assert tracker.seed(history, archive_dir=tmp_path) == 3
    assert [node.action_detail for node in tracker.nodes] == [a["action_detail"] for a in actions[-3:]]
    initial = tracker.to_snapshot()
    archives = list(tmp_path.glob("*.jsonl.gz"))

    assert tracker.seed(history, archive_dir=tmp_path) == 0
    restored = _tracker()
    restored.restore(initial)
    assert restored.seed(history, archive_dir=tmp_path) == 0
    assert restored.to_snapshot() == tracker.to_snapshot() == initial
    assert list(tmp_path.glob("*.jsonl.gz")) == archives


@pytest.mark.parametrize("numbered_middle", [False, True])
@pytest.mark.parametrize("sqlite_ranked", [False, True])
def test_review_deduplicates_batch_before_capacity_to_preserve_chain_prefix(
    numbered_middle, sqlite_ranked, monkeypatch, tmp_path,
):
    monkeypatch.setattr(stateful, "_MAX_NODES", 3)
    start = _legacy_action(1, "fixture-start")
    middle = _legacy_action(2, "fixture-middle")
    if numbered_middle:
        middle.update(_gate_call_id=f"{2:032x}", _gate_call_time_us=2)
    finish = _action(3, "fixture-finish")
    batch = [start, middle, middle, middle]
    if sqlite_ranked:
        batch = [{**action, "_sqlite_review_rank": rank} for rank, action in zip((4, 3, 2, 1), batch)]

    tracker = _tracker(("START", "MIDDLE", "FINISH"))
    assert tracker.seed(_sessions("s", *batch), archive_dir=tmp_path) == 2
    assert not list(tmp_path.iterdir())
    assert [node.action_detail for node in tracker.nodes] == [start["action_detail"], middle["action_detail"]]
    result = tracker.advance(finish, session_id="s")
    assert result.should_block
    assert [entry[2] for entry in result.matched.path] == [
        action["action_detail"] for action in (start, middle, finish)
    ]


def test_review_capacity_preserves_untimed_repeats_and_suffix_from_the_right_session(monkeypatch):
    monkeypatch.setattr(stateful, "_MAX_NODES", 3)
    prefix = _legacy_action(1, "fixture-prefix")
    same = _legacy_action(2, "fixture-same-detail")
    untimed = {"action_type": "bash", "action_detail": "echo fixture-untimed"}
    tracker = _tracker()
    history = _sessions("a", prefix, same) + _sessions("b", same, untimed, untimed)

    assert tracker.seed(history) == 3
    assert [(node.session_id, node.action_detail) for node in tracker.nodes] == [
        ("b", action["action_detail"]) for action in (same, untimed, untimed)
    ]


def test_oversize_review_selects_recent_legacy_actions_across_sessions(monkeypatch, tmp_path):
    monkeypatch.setattr(stateful, "_MAX_NODES", 3)
    oldest = _legacy_action(1, "fixture-oldest")
    earlier_tie = _legacy_action(4, "fixture-earlier-tie")
    latest = _legacy_action(6, "fixture-latest")
    later_tie = _legacy_action(4, "fixture-later-tie")
    recent = _legacy_action(5, "fixture-recent")
    history = _sessions("a", oldest, earlier_tie, latest) + _sessions("b", later_tie, recent)

    tracker = _tracker()
    assert tracker.seed(history, archive_dir=tmp_path) == 3
    assert [node.action_detail for node in tracker.nodes] == [
        later_tie["action_detail"], recent["action_detail"], latest["action_detail"],
    ]
    assert tracker.seed(history, archive_dir=tmp_path) == 0


@pytest.mark.parametrize("last_time", ["2026-11-23T09:30:00+00:00", ""])
def test_oversize_review_uses_same_timestamp_priority_to_select_and_merge(last_time, monkeypatch, tmp_path):
    monkeypatch.setattr(stateful, "_MAX_NODES", 2)
    oldest = {**_legacy_action(1, "fixture-old-offset"), "called_at": "2026-11-23T10:00:00+02:00"}
    recent = {**_legacy_action(2, "fixture-recent-utc"), "called_at": "2026-11-23T09:00:00+00:00"}
    latest = {**_legacy_action(3, "fixture-latest"), "called_at": last_time}
    tracker = _tracker()

    assert tracker.seed(_sessions("a", oldest, latest) + _sessions("b", recent), archive_dir=tmp_path) == 2
    assert [node.action_detail for node in tracker.nodes] == [recent["action_detail"], latest["action_detail"]]


def test_review_uses_retained_receipt_time_to_avoid_unnecessary_replay(monkeypatch):
    monkeypatch.setattr(stateful.StatefulChainTracker, "_now", staticmethod(lambda: "2026-11-23T08:00:01+00:00"))
    retained = {"action_type": "bash", "action_detail": "echo fixture-retained"}
    reviewed = _legacy_action(2, "fixture-reviewed")
    tracker = _tracker()
    tracker.advance(retained, session_id="live")
    generation = tracker.generation

    assert tracker.seed(_sessions("review", reviewed)) == 1
    assert tracker.generation == generation
    assert [node.action_detail for node in tracker.nodes] == [retained["action_detail"], reviewed["action_detail"]]


@pytest.mark.parametrize(("same_second", "new_session"), [(False, False), (True, False), (True, True)])
def test_tail_review_uses_known_anchors_without_scanning_retained_window(same_second, new_session):
    class IndexOnlyWindow(list):
        def __iter__(self):
            raise AssertionError("tail review scanned the retained window")

    tracker = _tracker()
    timestamp = "2026-11-23T08:00:01+00:00"
    history = []
    for i in range(1, 50001):
        action = _action(i, f"fixture-retained-{i}", timestamp)
        if i % 2:
            action = {key: value for key, value in action.items() if not key.startswith("_gate_")}
        call_id = action.get("_gate_call_id", "")
        tracker._add_node(stateful.StateNode(
            seq=i - 1, session_id="s", action_type=action["action_type"],
            action_detail=action["action_detail"], timestamp=timestamp, gate_call_id=call_id,
            gate_call_time_us=i if call_id else 0,
            legacy_fingerprint="" if call_id else tracker._legacy_key(action, "s"),
        ), warn_capacity=False)
        if i > 50000 - 4999:
            if same_second:
                action["_sqlite_review_rank"] = 50002 - i
            history.append(action)
    tail = _action(50001, "fixture-new-tail", timestamp if same_second else "2026-11-23T08:00:02+00:00")
    if same_second:
        tail["_sqlite_review_rank"] = 1
    tracker.nodes = IndexOnlyWindow(tracker.nodes)
    generation = tracker.generation
    review = _sessions("s", *history) + _sessions("other", tail) if new_session else _sessions("s", *history, tail)

    assert tracker.seed(review) == 1
    assert len(tracker.nodes) == 50001
    assert tracker.nodes[-1].gate_call_id == tail["_gate_call_id"]
    assert tracker.generation == generation


@pytest.mark.parametrize("new_before_anchor", [False, True])
def test_tail_review_falls_back_when_retained_anchors_do_not_prove_append(new_before_anchor, monkeypatch):
    tracker = _tracker()
    first, second, new = [_legacy_action(i, f"fixture-anchor-{i}") for i in range(1, 4)]
    tracker.advance(first, session_id="s")
    tracker.advance(second, session_id="s")
    review = _sessions("s", first, new, second) if new_before_anchor else _sessions("s", second, first, new)
    merge_review = tracker._merge_review
    include_retained_calls = []

    def observe(additions, history, *, include_retained=True):
        include_retained_calls.append(include_retained)
        return merge_review(additions, history, include_retained=include_retained)

    monkeypatch.setattr(tracker, "_merge_review", observe)
    assert tracker.seed(review) == 1
    expected = (first, new, second) if new_before_anchor else (first, second, new)
    assert [node.action_detail for node in tracker.nodes] == [action["action_detail"] for action in expected]
    assert include_retained_calls == [True]


def test_review_does_not_reinsert_prefix_of_archived_numbered_action(tmp_path):
    start = _legacy_action(1, "fixture-start")
    middle = _action(2, "fixture-middle")
    tail = _action(3, "fixture-tail")
    tracker = _tracker()
    assert tracker.seed(_sessions("s", start, middle, tail)) == 3
    assert tracker.rotate(tmp_path, retain=1)[0] == 2

    restored = _tracker()
    restored.restore(tracker.to_snapshot())
    assert restored.seed(_sessions("s", start, middle, tail), archive_dir=tmp_path) == 0
    assert [node.action_detail for node in restored.nodes] == [tail["action_detail"]]


def test_full_window_retry_keeps_confirmed_deny_after_restore(monkeypatch, tmp_path):
    monkeypatch.setattr(stateful, "_MAX_NODES", 2)
    tracker = _tracker()
    tracker.advance(_action(1, "fixture-start"), session_id="s")
    finish = _action(2, "fixture-finish")
    expected = tracker.advance(finish, session_id="s").matched.to_judgment()
    restored = _tracker()
    restored.restore(json.loads(json.dumps(tracker.to_snapshot())))
    response = restored.advance({**finish, "_gate_delivery_uncertain": True}, session_id="s", archive_dir=tmp_path)
    assert response.matched.to_judgment() == expected
    assert len(restored.nodes) == 2 and not list(tmp_path.iterdir())
    assert restored.generation == tracker.generation


def test_uncertain_delivery_without_confirmation_never_uses_provisional_result():
    tracker = _tracker()
    retry = {**_action(2, "fixture-finish"), "_gate_delivery_uncertain": True}
    with pytest.raises(stateful.StatefulAnalysisUnavailable):
        tracker.advance(retry, session_id="s")
    assert not tracker.nodes
    tracker.seed(_sessions("s", retry))
    before = tracker.to_snapshot()
    with pytest.raises(stateful.StatefulAnalysisUnavailable):
        tracker.advance(retry, session_id="s")
    assert tracker.to_snapshot() == before


def test_same_gate_call_id_with_different_content_is_a_protocol_conflict():
    tracker = _tracker()
    first = _action(1, "fixture-start")
    tracker.advance(first, session_id="s")
    with pytest.raises(stateful.GateCallConflict):
        tracker.advance({**first, "action_detail": "echo fixture-other"}, session_id="s")
    assert len(tracker.nodes) == 1


def test_unconfirmed_gate_call_without_delivery_marker_is_a_protocol_conflict():
    tracker = _tracker()
    first = _action(1, "fixture-start")
    order = stateful._gate_order(first)
    fingerprint = stateful.StatefulChainTracker._input_fingerprint(
        first, False, "", "", order,
    )
    node = tracker._make_node(
        first, "s", False, "", "", order=order, input_fingerprint=fingerprint,
    )
    tracker._add_node(node)
    with pytest.raises(stateful.GateCallConflict):
        tracker.advance(first, session_id="s")
    with pytest.raises(stateful.UnconfirmedGateRetry):
        tracker.advance({**first, "_gate_delivery_uncertain": True}, session_id="s")
    assert len(tracker.nodes) == 1


def test_old_fingerprints_do_not_collapse_independent_numbered_calls():
    tracker = _tracker()
    first, second = _action(1, "same-content"), _action(2, "same-content")
    old = {k: v for k, v in first.items() if not k.startswith("_gate_")}
    assert tracker.seed(_sessions("s", old, first, second)) == 3
    assert tracker.seed(_sessions("s", old, first, second)) == 0
    assert [node.gate_call_id for node in tracker.nodes] == ["", first["_gate_call_id"], second["_gate_call_id"]]


def test_archived_numbered_calls_are_neither_reintroduced_nor_evaluated(tmp_path):
    tracker = _tracker()
    calls = [_action(i, f"number-{i}") for i in range(1, 5)]
    for call in calls:
        tracker.advance(call, session_id="s")
    tracker.rotate(tmp_path, retain=2)
    restored = _tracker()
    restored.restore(json.loads(json.dumps(tracker.to_snapshot())))
    assert restored.archived_through == (2, calls[1]["_gate_call_id"])
    assert restored.seed(_sessions("s", *calls)) == 0
    with pytest.raises(stateful.StatefulAnalysisUnavailable):
        restored.advance(calls[1], session_id="s", archive_dir=tmp_path)
    assert len(restored.nodes) == 2


def test_late_append_at_capacity_retains_verdict_from_before_rotation(monkeypatch, tmp_path):
    monkeypatch.setattr(stateful, "_MAX_NODES", 3)
    monkeypatch.setenv("AGENT_MOSS_CHAIN_RETAIN_NODES", "2")
    tracker = _tracker()
    tracker.advance(_action(1, "fixture-start"), session_id="s")
    tracker.advance(_action(3, "gap"), session_id="s")
    tracker.advance(_action(5, "tail"), session_id="s")
    with pytest.raises(stateful.StatefulAnalysisUnavailable):
        tracker.advance(_action(2, "too-old-to-retain"), session_id="s", archive_dir=tmp_path)
    assert [node.gate_call_time_us for node in tracker.nodes] == [1, 3, 5]
    assert not list(tmp_path.iterdir())

    late = _action(4, "fixture-finish")
    first = tracker.advance(late, session_id="s", archive_dir=tmp_path)
    assert first.should_block
    assert [node.gate_call_time_us for node in tracker.nodes] == [4, 5]
    assert tracker.advance(late, session_id="s", archive_dir=tmp_path).matched.to_judgment() == first.matched.to_judgment()


def test_same_generation_sync_restores_legacy_keys_and_taint_evidence(monkeypatch):
    monkeypatch.setattr(stateful, "_EXFIL_RE", re.compile("fixture-send"))
    writer, reader = _tracker(), _tracker()
    source = _action(1, "fixture-source /tmp/fixture-credentials.txt")
    writer.advance(source, session_id="s")
    reader.restore(writer.to_snapshot())

    legacy = {"action_type": "bash", "action_detail": "echo legacy", "called_at": "2026-11-23 08:00:01"}
    relay = _action(2, "fixture-copy /tmp/fixture-credentials.txt /tmp/fake-output.txt")
    writer.advance(legacy, session_id="s")
    writer.advance(relay, session_id="s")
    snapshot = writer.to_snapshot()
    reader.restore_incremental(snapshot, snapshot["nodes"][1:])
    assert reader.seed(_sessions("s", legacy, relay)) == 0
    assert not reader.advance(relay, session_id="s").should_block

    send = _action(3, "fixture-send /tmp/fake-output.txt")
    expected = writer.advance(send, session_id="s").exfil
    assert expected and reader.advance(send, session_id="s").exfil == expected
