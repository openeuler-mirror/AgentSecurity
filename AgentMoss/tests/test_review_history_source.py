"""Explicit review paths select one source, including when that source is empty."""

import asyncio
import json
import sqlite3
from pathlib import Path
from unittest.mock import Mock

from fastapi.testclient import TestClient
import pytest

from agent_moss.engine.formal_engine import FormalEngine, FormalVerificationResult, chain_state, stateful
from agent_moss.infra import security_policy
from agent_moss.server import agent_gate_reader
from agent_moss.server.app import create_app


ACTION = {"action_type": "bash", "action_detail": "echo sample"}
BACKUP = [{"session_id": "backup", "action_history": [ACTION]}]


def make_db(path, *, with_history=False):
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE tool_calls(id, session_id, action_type, tool_name, action_detail, command, called_at)")
        if with_history:
            db.execute("INSERT INTO tool_calls VALUES(1, 'sqlite', 'bash', 'bash', 'echo sqlite', '', '2026-11-01')")


@pytest.fixture
def review(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_REVIEW_PATHS", str(tmp_path))
    default_json = tmp_path / "default-json"
    default_json.mkdir()
    (default_json / "implicit.json").write_text(json.dumps([ACTION]))
    monkeypatch.setenv("AGENT_GATE_JSON_PATH", str(default_json))
    client = TestClient(create_app())
    return lambda **payload: client.post("/api/v1/review", json=payload)


@pytest.mark.parametrize("extra", [
    {}, {"sessions": []}, {"sessions": [{"action_history": []}]},
    {"sessions": [{"action_history": [{"action_detail": "  "}]}]}, {"a_next": ACTION},
])
def test_missing_path_is_404_before_accessing_state(review, tmp_path, monkeypatch, extra):
    assert review(sessions=BACKUP).json()["state_nodes"] == 1
    get_store = Mock(side_effect=AssertionError("accessed chain state"))
    monkeypatch.setattr(chain_state, "get_chain_state_store", get_store)
    path = tmp_path / "missing.db"
    response = review(db_path=str(path), **extra)
    assert response.status_code == 404
    assert response.json() == {"detail": "指定的回顾路径不存在"}
    get_store.assert_not_called()
    assert not path.exists()


@pytest.mark.parametrize("source", ["missing", "empty", "sqlite", "json"])
def test_review_selects_expected_source(review, tmp_path, source, caplog):
    path = tmp_path / "history #%?.db"
    if source in {"sqlite", "empty"}:
        make_db(path, with_history=source == "sqlite")
    elif source == "json":
        path.mkdir()
        (path / "json.json").write_text(json.dumps([ACTION]))
    response = review(db_path=str(path), sessions=BACKUP)
    assert response.status_code == 200
    assert response.json()["seeded_nodes"] == 1
    tracker = chain_state.get_chain_state_store().load(security_policy.chain_bucket("default"))
    [node] = tracker.nodes
    assert node.session_id == (source if source in {"sqlite", "json"} else "backup")
    if source == "missing":
        assert "sessions" in caplog.text
    if source == "sqlite":
        assert review(db_path=str(path)).json()["seeded_nodes"] == 0


def test_empty_db_separates_current_verification_from_existing_state(review, tmp_path, monkeypatch):
    assert review(sessions=BACKUP).json()["state_nodes"] == 1
    path = tmp_path / "empty.db"
    make_db(path)
    verify = Mock(return_value=FormalVerificationResult(verified=True))
    monkeypatch.setattr(FormalEngine, "verify", verify)
    response = review(db_path=str(path)).json()
    assert response["verified"] and response["violations"] == []
    assert response["seeded_nodes"] == 0 and response["state_nodes"] == 1
    verify.assert_not_called()
    assert review(db_path=str(path), a_next=ACTION).status_code == 200
    verify.assert_called_once_with(sessions=[], a_next=ACTION)
    assert review().status_code == 200
    [session] = verify.call_args.kwargs["sessions"]
    assert session["action_history"] == [ACTION]


def test_errors_do_not_use_backup(review, tmp_path, monkeypatch):
    invalid = tmp_path / "invalid.db"
    invalid.write_bytes(b"not sqlite")
    assert review(db_path=str(invalid), sessions=BACKUP).status_code == 500
    missing_schema = tmp_path / "missing-schema.db"
    with sqlite3.connect(missing_schema) as db:
        db.execute("CREATE TABLE other(id)")
    assert review(db_path=str(missing_schema), sessions=BACKUP).status_code == 500
    assert review(db_path=str(tmp_path.parent / "outside"), sessions=BACKUP).status_code == 403
    folder = tmp_path / "unreadable"
    folder.mkdir()
    # Simulate a directory-level I/O error even under a privileged test user.
    monkeypatch.setattr(Path, "iterdir", Mock(side_effect=PermissionError("cannot list directory")))
    assert review(db_path=str(folder), sessions=BACKUP).status_code == 500


def test_source_removed_during_open(review, tmp_path, monkeypatch):
    path = tmp_path / "rotated.db"
    make_db(path)
    connect = sqlite3.connect

    def open_after_rotation(database, **options):
        if database == f"{path.as_uri()}?mode=ro":
            path.rename(path.with_suffix(".bak"))
        return connect(database, **options)

    monkeypatch.setattr(sqlite3, "connect", open_after_rotation)
    assert review(db_path=str(path)).status_code == 404
    assert not path.exists()


def test_validated_and_read_path_match(review, tmp_path, monkeypatch):
    path = tmp_path / "history.db"
    make_db(path, with_history=True)
    (tmp_path / "link.db").symlink_to(path)
    monkeypatch.setenv("HOME", str(tmp_path))
    path_within = security_policy.path_within

    def check_in_worker(candidate, roots):
        with pytest.raises(RuntimeError, match="no running event loop"):
            asyncio.get_running_loop()
        return path_within(candidate, roots)

    monkeypatch.setattr(security_policy, "path_within", check_in_worker)
    load = Mock(wraps=agent_gate_reader.load_agent_gate_sessions)
    monkeypatch.setattr(agent_gate_reader, "load_agent_gate_sessions", load)
    assert review(db_path="~/link.db").status_code == 200
    load.assert_called_once()
    assert load.call_args.args == (str(path),)
    assert "limit" in load.call_args.kwargs


def test_automatic_discovery_uses_default_json(review, tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_GATE_DB", str(tmp_path / "undiscovered.db"))
    [session] = agent_gate_reader.load_agent_gate_sessions()
    assert session["session_id"] == "implicit"


@pytest.mark.parametrize(("total", "limit"), [(5002, 5000), (100001, 0)])
def test_sqlite_review_selects_latest_global_window_before_grouping(tmp_path, total, limit):
    path = tmp_path / "history.db"
    make_db(path)
    with sqlite3.connect(path) as db:
        db.executemany(
            "INSERT INTO tool_calls VALUES(?, ?, 'bash', 'bash', ?, '', '2026-11-23 10:00:00')",
            (
                (i, "A" if i in (1, total) else "B", f"echo {i}")
                for i in range(1, total + 1)
            ),
        )
    found = agent_gate_reader.read_agent_gate_sessions(str(path), limit=limit)
    effective_limit = limit or 100000
    assert sum(len(session["action_history"]) for session in found) == effective_limit
    assert found[-1]["session_id"] == "A"
    assert [a["action_detail"] for a in found[-1]["action_history"]] == [f"echo {total}"]
    assert found[0]["action_history"][0]["action_detail"] == f"echo {total-effective_limit+1}"
    assert "_sqlite_review_rank" not in found[-1]["action_history"][0]


@pytest.mark.parametrize("same_audit_id", [False, True])
def test_sqlite_state_capacity_keeps_global_window_of_tied_actions(review, tmp_path, monkeypatch, same_audit_id):
    monkeypatch.setattr(stateful, "_MAX_NODES", 2)
    monkeypatch.setenv("AGENT_MOSS_REVIEW_MAX_ACTIONS", "4")
    path = tmp_path / "same-second.db"
    make_db(path)
    with sqlite3.connect(path) as db:
        db.executemany(
            "INSERT INTO tool_calls VALUES(?, ?, 'bash', 'bash', ?, '', '2026-11-23 10:00:00')",
            [(1 if same_audit_id else i, sid, f"echo {i}") for i, sid in enumerate("ABBA", start=1)],
        )

    first = review(db_path=str(path))
    assert first.status_code == 200
    assert first.json()["seeded_nodes"] == 2
    tracker = chain_state.get_chain_state_store().load(security_policy.chain_bucket("default"))
    assert [(node.session_id, node.action_detail) for node in tracker.nodes] == [("B", "echo 3"), ("A", "echo 4")]

    repeat = review(db_path=str(path))
    assert repeat.status_code == 200
    assert repeat.json()["seeded_nodes"] == 0


def test_sqlite_review_loads_metadata_for_the_selected_physical_rows(tmp_path, monkeypatch):
    path = tmp_path / "history.db"
    make_db(path)
    monkeypatch.setenv("AGENT_GATE_DB", str(path))
    with sqlite3.connect(path) as db:
        db.execute("ALTER TABLE tool_calls ADD COLUMN moss_response TEXT")
        for index in range(1, 5):
            # Legacy schemas can have an ordinary id column and tied audit timestamps.
            db.execute(
                "INSERT INTO tool_calls VALUES(1, 'session', 'bash', 'bash', ?, '', ?, ?)",
                (
                    f"echo {index}" if index < 4 else "",
                    "2026-11-23 10:00:00",
                    json.dumps({
                        "_gate_call_id": f"{index:032x}",
                        "_gate_call_time_us": 1795392000000000 + index,
                        "policy": "p" * 16384,
                    }),
                ),
            )

    [session] = agent_gate_reader.read_agent_gate_sessions(str(path), limit=2)
    assert [action["action_detail"] for action in session["action_history"]] == ["echo 2", "echo 3"]
    assert [action["_gate_call_id"] for action in session["action_history"]] == [
        f"{2:032x}", f"{3:032x}",
    ]


def test_review_metadata_requires_exact_configured_file(tmp_path, monkeypatch):
    trusted = tmp_path / "live.db"
    other = tmp_path / "backup.db"
    alias = tmp_path / "alias.db"
    alias.symlink_to(other)
    gate_fields = {"_gate_call_id": "a" * 32, "_gate_call_time_us": 1795392000000000}
    for path in (trusted, other):
        make_db(path, with_history=True)
        with sqlite3.connect(path) as db:
            db.execute("ALTER TABLE tool_calls ADD COLUMN moss_response TEXT")
            db.execute("UPDATE tool_calls SET moss_response = ?", (json.dumps(gate_fields),))
    monkeypatch.setenv("AGENT_GATE_DB", str(trusted))
    live_action = agent_gate_reader.read_agent_gate_sessions(str(trusted))[0]["action_history"][0]
    assert all(live_action[key] == value for key, value in gate_fields.items())
    for path in (other, alias):
        legacy_action = agent_gate_reader.read_agent_gate_sessions(str(path))[0]["action_history"][0]
        assert gate_fields.keys().isdisjoint(legacy_action)
    monkeypatch.delenv("AGENT_GATE_DB")
    legacy_action = agent_gate_reader.read_agent_gate_sessions(str(trusted))[0]["action_history"][0]
    assert gate_fields.keys().isdisjoint(legacy_action)


def test_protocol_rejection_reaches_batch_verification_but_not_state(review, tmp_path, monkeypatch):
    path = tmp_path / "history.db"
    make_db(path, with_history=True)
    with sqlite3.connect(path) as db:
        db.execute("ALTER TABLE tool_calls ADD COLUMN moss_response TEXT")
        db.execute("UPDATE tool_calls SET moss_response = ?",
                   (json.dumps({"_gate_protocol_rejected": True}),))
    monkeypatch.setenv("AGENT_GATE_DB", str(path))
    verify = Mock(return_value=FormalVerificationResult(verified=True))
    monkeypatch.setattr(FormalEngine, "verify", verify)
    response = review(db_path=str(path))
    assert response.status_code == 200
    assert response.json()["seeded_nodes"] == 0
    assert response.json()["state_nodes"] == 0
    [session] = verify.call_args.kwargs["sessions"]
    assert session["action_history"][0]["action_detail"] == "echo sqlite"


def test_inline_history_cannot_claim_a_gate_call_or_suppress_seed(review, tmp_path):
    action = {
        **ACTION,
        "_gate_call_id": "a" * 32,
        "_gate_call_time_us": 1795392000000000,
        "_gate_protocol_rejected": True,
    }
    response = review(
        db_path=str(tmp_path / "missing.db"),
        sessions=[{"session_id": "inline", "action_history": [action]}],
    )
    assert response.status_code == 200
    assert response.json()["seeded_nodes"] == 1
    [node] = chain_state.get_chain_state_store().load(security_policy.chain_bucket("default")).nodes
    assert not node.gate_call_id


def test_inline_history_cannot_claim_sqlite_review_rank(review, monkeypatch):
    monkeypatch.setattr(stateful, "_MAX_NODES", 2)
    sessions = [{
        "session_id": "inline",
        "action_history": [
            {**ACTION, "action_detail": f"echo {i}", "called_at": "2026-11-23 10:00:00", "_sqlite_review_rank": i}
            for i in range(1, 5)
        ],
    }]
    response = review(sessions=sessions)
    assert response.status_code == 200
    assert response.json()["seeded_nodes"] == 2
    tracker = chain_state.get_chain_state_store().load(security_policy.chain_bucket("default"))
    assert [node.action_detail for node in tracker.nodes] == ["echo 3", "echo 4"]
