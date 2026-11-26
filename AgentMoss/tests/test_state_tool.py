"""`agent-moss state`（链状态库备份/恢复）的行为看护。"""

from __future__ import annotations

import os

from agent_moss.engine.formal_engine.chain_state import ChainStateStore
from agent_moss.state_tool import (
    cmd_state_backup,
    cmd_state_reset,
    cmd_state_status,
)


class _Args:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def _seed(state_dir):
    store = ChainStateStore(str(state_dir / "stateful_chains.db"))
    for i in range(3):
        store.apply_action(
            "__system__",
            {"action_type": "execute", "action_detail": "cat /etc/hostname"},
            f"s{i}",
        )
    store.flush()
    store.close()


def test_status_reports_nodes(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AGENT_MOSS_STATE_DIR", str(tmp_path))
    _seed(tmp_path)
    rc = cmd_state_status(_Args())
    out = capsys.readouterr().out
    assert rc == 0
    assert "__system__: 3 节点" in out


def test_status_excludes_deleted_bucket(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AGENT_MOSS_STATE_DIR", str(tmp_path))
    _seed(tmp_path)
    store = ChainStateStore(str(tmp_path / "stateful_chains.db"))
    try:
        store.delete("__system__")
    finally:
        store.close()
    assert cmd_state_status(_Args()) == 0
    out = capsys.readouterr().out
    assert "agent 分桶: 0" in out
    assert "__system__" not in out


def test_status_missing_db_is_ok(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AGENT_MOSS_STATE_DIR", str(tmp_path / "empty"))
    (tmp_path / "empty").mkdir()
    rc = cmd_state_status(_Args())
    assert rc == 0
    assert "尚未创建" in capsys.readouterr().out


def test_backup_creates_file(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AGENT_MOSS_STATE_DIR", str(tmp_path))
    _seed(tmp_path)
    out = tmp_path / "bak.db"
    rc = cmd_state_backup(_Args(output=str(out), force=False))
    assert rc == 0
    assert out.exists() and out.stat().st_size > 0


def test_backup_refuses_overwrite_without_force(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AGENT_MOSS_STATE_DIR", str(tmp_path))
    _seed(tmp_path)
    out = tmp_path / "bak.db"
    out.write_text("x", encoding="utf-8")
    rc = cmd_state_backup(_Args(output=str(out), force=False))
    assert rc == 1


def test_reset_requires_yes(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AGENT_MOSS_STATE_DIR", str(tmp_path))
    _seed(tmp_path)
    db = tmp_path / "stateful_chains.db"
    rc = cmd_state_reset(_Args(yes=False, port=0))
    assert rc == 1
    assert db.exists()


def test_reset_removes_files(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AGENT_MOSS_STATE_DIR", str(tmp_path))
    _seed(tmp_path)
    db = tmp_path / "stateful_chains.db"
    # port=0 → 不会连上任何服务，_service_running 返回 False
    rc = cmd_state_reset(_Args(yes=True, port=0))
    assert rc == 0
    assert not db.exists()
