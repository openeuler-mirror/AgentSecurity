"""Explicit review paths select one source, including when that source is empty."""

import asyncio
import json
import sqlite3
from pathlib import Path
from unittest.mock import Mock

from fastapi.testclient import TestClient
import pytest

from agent_moss.engine.formal_engine import FormalEngine, FormalVerificationResult, chain_state
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
    load.assert_called_once_with(str(path))


def test_automatic_discovery_uses_default_json(review, tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_GATE_DB", str(tmp_path / "undiscovered.db"))
    [session] = agent_gate_reader.load_agent_gate_sessions()
    assert session["session_id"] == "implicit"
