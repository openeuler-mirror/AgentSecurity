"""链归档清理（2026-11，D4）：chain-archive 只写不删会无限膨胀。

与 TS ``cleanupChainArchives`` 对称：默认按总大小 512MB 滚动删除最老文件，
按时间默认关闭（``AGENT_MOSS_CHAIN_ARCHIVE_MAX_AGE_DAYS=0``）。
"""
from __future__ import annotations

import os
import time

from agent_moss.engine.formal_engine.stateful import cleanup_chain_archives


def _seed(archive_dir, count: int, size: int = 600 * 1024):
    archive_dir.mkdir(parents=True, exist_ok=True)
    base = time.time() - (count + 1) * 3600
    files = []
    for i in range(count):
        p = archive_dir / f"chain-nodes-old-2026-01-0{i + 1}-000.jsonl.gz"
        p.write_bytes(b"x" * size)
        os.utime(p, (base + i * 3600, base + i * 3600))
        files.append(p)
    return files


def test_cleanup_by_size_keeps_newest(tmp_path):
    _seed(tmp_path, 3)  # 1.8MB
    removed, files, remaining = cleanup_chain_archives(
        tmp_path, max_bytes=1024 * 1024, max_age_days=0
    )
    assert removed == 2
    assert files == 1
    assert remaining <= 1024 * 1024


def test_cleanup_keeps_latest_single_file_over_limit(tmp_path):
    """单个归档本身超过上限时保留最新 1 个，不能刚写完就删（N1）。"""
    only = tmp_path / "chain-nodes-a-2026-01-01-000.jsonl.gz"
    only.write_bytes(b"x" * (2 * 1024 * 1024))
    removed, files, remaining = cleanup_chain_archives(
        tmp_path, max_bytes=1024 * 1024, max_age_days=0
    )
    assert removed == 0
    assert files == 1
    assert remaining == 2 * 1024 * 1024


def test_cleanup_by_age(tmp_path):
    files = _seed(tmp_path, 2)
    old = time.time() - 40 * 86400
    for p in files:
        os.utime(p, (old, old))
    removed, remain_files, _ = cleanup_chain_archives(
        tmp_path, max_bytes=0, max_age_days=30
    )
    assert removed == 2
    assert remain_files == 0


def test_cleanup_missing_dir_is_safe(tmp_path):
    assert cleanup_chain_archives(tmp_path / "nope", 1024, 0) == (0, 0, 0)


def test_rotate_triggers_cleanup(tmp_path, monkeypatch):
    from agent_moss.engine.formal_engine import stateful
    from agent_moss.engine.formal_engine.chain_state import ChainStateStore

    monkeypatch.setattr(stateful, "_MAX_NODES", 5)
    monkeypatch.setenv("AGENT_MOSS_CHAIN_RETAIN_NODES", "2")
    monkeypatch.setenv("AGENT_MOSS_CHAIN_ARCHIVE_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_MOSS_CHAIN_ARCHIVE_MAX_MB", "1")

    seeded = _seed(tmp_path, 2)  # 1.2MB 历史归档

    store = ChainStateStore(str(tmp_path / "state.db"))
    try:
        for i in range(6):
            store.apply_action(
                "agent-rotate-clean",
                {"action_type": "execute", "action_detail": f"echo clean-{i}"},
                f"s-{i}",
            )
        store.flush()
    finally:
        store.close()

    remain = sorted(tmp_path.glob("chain-nodes-*.jsonl.gz"), key=lambda p: p.stat().st_mtime)
    # 最老的历史归档被删，剩 1 个历史 + 1 个本次归档
    assert len(remain) == 2
    assert seeded[0] not in remain
    assert seeded[1] in remain
