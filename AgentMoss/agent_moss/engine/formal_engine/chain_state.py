"""链状态仓储（Chain State Store）— 有状态增量分析器的持久化层。

职责：按 agent 隔离地持久化 StatefulChainTracker 的快照（时间线节点 + 链指针 +
taint + 存活资源），并暴露增量的"种子/推进"入口。服务重启后从快照恢复，跨 session
组合链的"前序"状态不丢（这正是"从开始记录就持续分析"的落点）。

SQLite 将节点按 (agent_id, seq) 写入 chain_nodes，将指针等元数据写入 chain_meta。
首次读取旧版 chain_state 快照时，将其迁移到这两张表。

双端镜像：TS 端 ts/src/engine/formal-engine/chain_state.ts（JSON 文件形态，对应
无 sqlite 环境；AgentGate 侧逻辑一致）。
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import sqlite3
import threading
import time
from pathlib import Path
from weakref import WeakKeyDictionary

from .stateful import AdvanceResult, StateNode, StatefulChainTracker, UnconfirmedGateRetry

logger = logging.getLogger(__name__)


def default_state_db_path() -> str:
    """默认状态库路径（按 instance 隔离）。

    有 AGENT_MOSS_INSTANCE → <state_root>/<instance>/stateful_chains.db
    无 instance → <state_root>/stateful_chains.db（旧路径，兼容）
    旧共享库存在而 instance 库不存在时，用 SQLite backup 复制一份（保留历史链）。
    """
    from ...infra.paths import get_instance, get_state_db_path, get_state_root

    path = get_state_db_path()
    if get_instance():
        legacy = get_state_root() / "stateful_chains.db"
        if not path.exists() and legacy.exists():
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                with sqlite3.connect(str(legacy)) as src, sqlite3.connect(str(path)) as dst:
                    src.backup(dst)
                logger.warning(
                    "链状态库按 instance 隔离：已从旧共享库 %s 复制到 %s",
                    legacy, path,
                )
            except Exception:  # noqa: BLE001 — 迁移失败不阻断，使用新库
                logger.warning(
                    "迁移链状态库失败（将使用新空库）: %s", path, exc_info=True
                )
    return str(path)


class ChainStateStore:
    """SQLite 持久化的链状态仓储（线程安全）。

    单进程模式下，请求线程持锁推进缓存中的 tracker。普通追加由后台线程每
    ``_FLUSH_INTERVAL`` 秒批量落盘，重放或轮转产生的新代次在请求内提交。
    多 worker 模式在同一个 SQLite 写事务中同步已提交状态、判定并写回。
    """

    #: 后台落盘间隔（秒）。太短会让写盘重新变成热路径，太长会丢更多。
    _FLUSH_INTERVAL = 1.0

    def __init__(self, db_path: str = ""):
        self.db_path = db_path or default_state_db_path()
        # Serialize snapshot capture through commit, including the final flush.
        self._flush_lock = threading.Lock()
        self._lock = threading.RLock()
        #: 保护 SQLite 连接（后台 flush 线程与请求线程共用）。锁顺序固定为
        #: _flush_lock（仅 flush/close）→ _lock → _db_lock，不允许反向获取。
        self._db_lock = threading.Lock()
        #: agent_id -> 内存中的 tracker（唯一事实源；SQLite 是它的持久化副本）
        self._trackers: dict[str, StatefulChainTracker] = {}
        # A retained tracker can outlive its cache entry or advance its in-memory generation.
        self._tracker_origins: WeakKeyDictionary[StatefulChainTracker, tuple[str, int, int]] = WeakKeyDictionary()
        #: 自上次落盘以来变过的 agent_id
        self._dirty: set[str] = set()
        #: 每个桶上次同步的持久化版本。seq 从零连续编号，已提交节点数为最后的 seq + 1。
        self._persisted_generation: dict[str, int] = {}
        self._synced_seq: dict[str, int] = {}
        #: 多进程模式（2026-11，`AGENT_MOSS_MULTI_PROCESS=1` 或 --workers>1）：
        #: 每次 apply_action 前从 SQLite 拉增量节点 + 元数据，避免各进程缓存
        #: 互相看不见导致组合链漏判。代价是每请求多一次增量查询 + 立即落盘。
        self._multi_process = False
        self._closed = False
        self._stop = threading.Event()
        _parent = Path(self.db_path).parent
        _parent.mkdir(parents=True, exist_ok=True)
        # 安全（2026-10）：库里存的是**各 agent 的动作历史**，是最敏感的数据。
        # 目录 0700、文件 0600，避免同机其他用户直接读走。
        try:
            os.chmod(_parent, 0o700)
        except OSError:
            pass
        self._conn = sqlite3.connect(
            self.db_path, check_same_thread=False, isolation_level=None
        )
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            if self.db_path != ":memory:":
                try:
                    os.chmod(self.db_path, 0o600)
                except OSError:
                    pass
                # WAL:并发读写不互锁,且 NORMAL 同步下 commit 不再 fsync(性能大头)
                self._conn.execute("PRAGMA journal_mode=WAL")
                self._conn.execute("PRAGMA synchronous=NORMAL")
            # 旧表（整份 JSON 一行）：保留用于**一次性迁移**，新写入不再使用。
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS chain_state (
                    agent_id  TEXT PRIMARY KEY,
                    state_json TEXT NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )
            # 新结构（2026-11）：节点按行存，追加写；元数据单独一行（很小）。
            # 为什么：旧结构每秒把一行 2.4 万节点的 JSON（14 MB）整份重写，
            # 长稳实测 WAL 涨到 15 MB、IO 压力大，是残余性能退化的来源。
            # 增量后每次只 append 新产生的几个节点，IO 降三个数量级。
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS chain_nodes (
                    agent_id  TEXT NOT NULL,
                    seq       INTEGER NOT NULL,
                    node_json TEXT NOT NULL,
                    PRIMARY KEY (agent_id, seq)
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS chain_meta (
                    agent_id  TEXT PRIMARY KEY,
                    meta_json TEXT NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )
        #: 后台落盘线程（daemon：进程退出不阻塞；close() 会显式 flush）
        self._flusher = threading.Thread(
            target=self._flush_loop, name="chain-state-flusher", daemon=True
        )
        self._flusher.start()

    # ---------------- 后台落盘 ----------------

    def _flush_loop(self) -> None:
        while not self._stop.wait(self._FLUSH_INTERVAL):
            try:
                self.flush()
            except Exception:  # noqa: BLE001 —— 落盘失败不能让后台线程死掉
                continue

    def flush(self) -> int:
        """Serialize outside the timeline lock, then commit only the captured version."""
        with self._flush_lock:
            return self._flush_pending()

    def _flush_pending(self) -> int:
        with self._lock:
            if self._closed:
                return 0
            snapshots = []
            for agent_id in list(self._dirty):
                tracker = self._trackers.get(agent_id)
                if tracker is None:
                    self._dirty.discard(agent_id)
                    continue
                version = self._persisted_version(agent_id)
                origin = (agent_id, *version)
                if self._tracker_origins.get(tracker) != origin or tracker.generation < version[0]:
                    self._invalidate_cache(agent_id)
                    continue
                try:
                    parts = tracker.to_snapshot_parts()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("链状态快照读取失败（会重试）: agent=%s err=%s", agent_id, exc)
                    continue
                snapshots.append((agent_id, tracker, tracker.generation, version, parts))
                self._dirty.discard(agent_id)

        written = 0
        for agent_id, tracker, generation, version, parts in snapshots:
            persisted_generation, last_seq = version
            replace = generation > persisted_generation
            try:
                rows, metadata = self._serialize_snapshot(agent_id, parts, 0 if replace else last_seq + 1)
                with self._lock:
                    if self._closed:
                        break
                    if (
                        self._trackers.get(agent_id) is not tracker
                        or self._persisted_version(agent_id) != version
                    ):
                        continue
                    if tracker.generation != generation:
                        self._dirty.add(agent_id)
                        continue
                    with self._transaction():
                        if self._durable_version(agent_id) != version or (
                            version == (0, -1) and self._has_legacy_snapshot(agent_id)
                        ):
                            self._invalidate_cache(agent_id)
                            continue
                        self._write_snapshot(agent_id, rows, metadata, delete_from=0 if replace else None)
                    self._publish_cursor(agent_id, len(parts["nodes"]), generation, tracker=tracker)
                written += 1
            except Exception as exc:  # noqa: BLE001
                with self._lock:
                    if self._trackers.get(agent_id) is tracker and tracker.generation == generation:
                        self._dirty.add(agent_id)
                logger.warning("链状态写入失败（会重试）: agent=%s err=%s", agent_id, exc)
        return written

    def close(self) -> None:
        self._stop.set()
        with self._flush_lock, self._lock:
            if self._closed:
                return
            try:
                self._flush_pending()
            finally:
                self._closed = True
                with self._db_lock:
                    self._conn.close()

    # ---------------- 多进程模式 ----------------

    def enable_multi_process(self) -> None:
        """让各 worker 在 SQLite 写事务中同步并提交，避免基于过时的进度推进链状态。"""
        self._multi_process = True

    @contextlib.contextmanager
    def _transaction(self, *, write: bool = True):
        """Call while holding the timeline lock, before acquiring the database lock."""
        with self._db_lock:
            self._conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            try:
                yield
                self._conn.commit()
            except BaseException:
                self._conn.rollback()
                raise

    def _read_meta(self, agent_id: str) -> dict:
        row = self._conn.execute(
            "SELECT meta_json FROM chain_meta WHERE agent_id=?", (agent_id,)
        ).fetchone()
        return json.loads(row["meta_json"]) if row is not None else {}

    def _read_persisted_seq(self, agent_id: str, meta: dict) -> int:
        if "persisted_seq" in meta:
            return int(meta["persisted_seq"])
        # Snapshots from older builds have no persisted cursor in metadata.
        row = self._conn.execute(
            "SELECT COALESCE(MAX(seq), -1) FROM chain_nodes WHERE agent_id=?", (agent_id,)
        ).fetchone()
        return int(row[0])

    def _durable_version(self, agent_id: str) -> tuple[int, int]:
        meta = self._read_meta(agent_id)
        return int(meta.get("generation", 0)), self._read_persisted_seq(agent_id, meta)

    def _persisted_version(self, agent_id: str) -> tuple[int, int]:
        return self._persisted_generation.get(agent_id, 0), self._synced_seq.get(agent_id, -1)

    def _publish_cursor(
        self, agent_id: str, count: int, generation: int, *, tracker: StatefulChainTracker | None = None,
    ) -> None:
        cursor = count - 1
        self._persisted_generation[agent_id] = generation
        self._synced_seq[agent_id] = cursor
        if tracker is not None:
            self._tracker_origins[tracker] = (agent_id, generation, cursor)

    def _invalidate_cache(self, agent_id: str) -> None:
        self._trackers.pop(agent_id, None)
        self._synced_seq.pop(agent_id, None)
        self._persisted_generation.pop(agent_id, None)
        self._dirty.discard(agent_id)

    @staticmethod
    def _serialize_snapshot(agent_id: str, parts: dict, start: int) -> tuple[list, str]:
        nodes = parts["nodes"]
        rows = [
            (agent_id, node.seq, json.dumps(node.__dict__, ensure_ascii=False))
            for node in nodes[start:]
        ]
        meta = {key: value for key, value in parts.items() if key != "nodes"}
        meta["persisted_seq"] = nodes[-1].seq if nodes else -1
        return rows, json.dumps(meta, ensure_ascii=False)

    def _write_snapshot(
        self, agent_id: str, rows: list, metadata: str, *, delete_from: int | None = None,
    ) -> None:
        if delete_from is not None:
            self._conn.execute(
                "DELETE FROM chain_nodes WHERE agent_id=? AND seq >= ?", (agent_id, delete_from),
            )
        if rows:
            self._conn.executemany(
                "INSERT OR REPLACE INTO chain_nodes (agent_id, seq, node_json) VALUES (?, ?, ?)",
                rows,
            )
        self._conn.execute(
            "INSERT INTO chain_meta (agent_id, meta_json, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(agent_id) DO UPDATE SET "
            "meta_json=excluded.meta_json, updated_at=excluded.updated_at",
            (agent_id, metadata, time.time()),
        )

    def _sync_in_tx(self, agent_id: str, tracker: StatefulChainTracker) -> None:
        """Bring both the timeline and its derived state up to the committed version."""
        meta = self._read_meta(agent_id)
        durable_seq = self._read_persisted_seq(agent_id, meta)
        _, generation, last = self._tracker_origins[tracker]
        durable_generation = int(meta.get("generation", 0))
        working_count = len(tracker.nodes)
        if (generation, last) == (durable_generation, durable_seq) and (
            tracker.generation > generation or (tracker.generation == generation and working_count > last)
        ):
            # Include pending edits in the next commit while their durable base is current.
            return
        reload = (
            generation != durable_generation
            or tracker.generation != durable_generation
            or working_count != last + 1
            or durable_seq < last
        )
        if reload:
            last = -1

        rows = self._conn.execute(
            "SELECT seq, node_json FROM chain_nodes WHERE agent_id=? AND seq > ? ORDER BY seq",
            (agent_id, last),
        ).fetchall()
        nodes = []
        for expected, row in enumerate(rows, start=last + 1):
            node = json.loads(row["node_json"])
            if row["seq"] != expected or node["seq"] != expected:
                raise ValueError("chain state has a discontinuous sequence")
            nodes.append(node)
        if last + len(nodes) != durable_seq:
            raise ValueError("chain state cursor does not match its stored nodes")

        if reload:
            tracker.restore({**meta, "agent_id": agent_id, "nodes": nodes})
        else:
            tracker.restore_incremental(meta, nodes)
        self._publish_cursor(agent_id, len(tracker.nodes), tracker.generation, tracker=tracker)

    def _change_multi_process(self, agent_id, operation, *, preserve_readonly_denial: bool = False):
        with self._lock:
            for attempt in range(5):
                try:
                    tracker = self.load(agent_id) or self._new_tracker(agent_id)
                    with self._transaction():
                        self._sync_in_tx(agent_id, tracker)
                        _, generation, last = self._tracker_origins[tracker]
                        count = last + 1
                        before = None
                        if tracker.generation == generation and len(tracker.nodes) >= count:
                            # Replays allocate a new list. Appends leave the committed prefix intact.
                            before = tracker.nodes
                        result = operation(tracker)
                        if tracker.generation != generation:
                            self._replace_in_tx(agent_id, tracker, before)
                        elif len(tracker.nodes) != count:
                            rows, metadata = self._serialize_snapshot(
                                agent_id, tracker.to_snapshot_parts(), count,
                            )
                            self._write_snapshot(agent_id, rows, metadata)
                    self._trackers[agent_id] = tracker
                    self._publish_cursor(agent_id, len(tracker.nodes), tracker.generation, tracker=tracker)
                    self._dirty.discard(agent_id)
                    return result, tracker
                except UnconfirmedGateRetry:
                    # A plain advance rejected before mutation. Its sync only read committed state.
                    if preserve_readonly_denial:
                        self._trackers[agent_id] = tracker
                    else:
                        self._invalidate_cache(agent_id)
                    raise
                except Exception as exc:
                    self._invalidate_cache(agent_id)
                    if attempt == 4 or not isinstance(exc, sqlite3.OperationalError):
                        raise
                    message = str(exc).lower()
                    if "locked" not in message and "busy" not in message:
                        raise
                    time.sleep(0.05 * (attempt + 1))

    # ---------------- 读写 ----------------

    def _read_snapshot(self, agent_id: str, meta: dict) -> dict | None:
        if not meta:
            return None
        if meta.get("deleted"):
            return meta
        rows = self._conn.execute(
            "SELECT node_json FROM chain_nodes WHERE agent_id=? ORDER BY seq", (agent_id,),
        )
        return {**meta, "agent_id": agent_id, "nodes": [json.loads(row[0]) for row in rows]}

    def _read_legacy_snapshot(self, agent_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT state_json FROM chain_state WHERE agent_id=?", (agent_id,),
        ).fetchone()
        return json.loads(row[0]) if row is not None else None

    def _has_legacy_snapshot(self, agent_id: str) -> bool:
        return self._conn.execute(
            "SELECT 1 FROM chain_state WHERE agent_id=?", (agent_id,)
        ).fetchone() is not None

    def load(self, agent_id: str) -> StatefulChainTracker | None:
        """Read metadata and nodes from one durable snapshot before caching."""
        with self._lock:
            if self._closed:
                raise sqlite3.ProgrammingError("chain state store is closed")
            cached = self._trackers.get(agent_id)
            if cached is not None:
                return cached

            with self._transaction(write=False):
                meta = self._read_meta(agent_id)
                needs_normalization = "seeded_keys" in meta
                snapshot = None if needs_normalization else self._read_snapshot(agent_id, meta)
                legacy = self._read_legacy_snapshot(agent_id) if not meta else None

            tracker = None
            if legacy is not None or needs_normalization:
                with self._transaction():
                    # Recheck under the write lock before normalizing legacy fingerprints.
                    snapshot = self._read_snapshot(agent_id, self._read_meta(agent_id))
                    if snapshot is None:
                        legacy = self._read_legacy_snapshot(agent_id)
                        if legacy is not None:
                            tracker = self._migrate_from_old(agent_id, legacy)
                    elif "seeded_keys" in snapshot:
                        tracker = self._normalize_legacy_snapshot_in_tx(agent_id, snapshot)

            if tracker is None:
                if snapshot is None:
                    return None
                if snapshot.get("deleted"):
                    self._publish_cursor(agent_id, 0, int(snapshot["generation"]))
                    return None
                tracker = StatefulChainTracker(agent_id=agent_id)
                tracker.restore(snapshot)
            self._trackers[agent_id] = tracker
            self._publish_cursor(agent_id, len(tracker.nodes), tracker.generation, tracker=tracker)
            return tracker

    def _migrate_from_old(self, agent_id: str, snapshot: dict) -> StatefulChainTracker:
        """Migrate a legacy snapshot under the same transaction as its lookup."""
        tracker = self._normalize_legacy_snapshot_in_tx(agent_id, snapshot)
        self._conn.execute("DELETE FROM chain_state WHERE agent_id=?", (agent_id,))
        return tracker

    def _normalize_legacy_snapshot_in_tx(self, agent_id: str, snapshot: dict) -> StatefulChainTracker:
        tracker = StatefulChainTracker(agent_id=agent_id)
        tracker.restore({**snapshot, "agent_id": agent_id})
        rows, metadata = self._serialize_snapshot(agent_id, tracker.to_snapshot_parts(), 0)
        self._write_snapshot(agent_id, rows, metadata)
        return tracker

    def load_or_new(self, agent_id: str) -> StatefulChainTracker:
        """读取某 agent 的 tracker；不存在则新建（幂等）。"""
        with self._lock:
            t = self.load(agent_id)
            if t is None:
                t = self._new_tracker(agent_id)
                self._trackers[agent_id] = t
                self._dirty.add(agent_id)
            return t

    def _new_tracker(self, agent_id: str) -> StatefulChainTracker:
        tracker = StatefulChainTracker(agent_id=agent_id)
        generation, cursor = self._persisted_version(agent_id)
        tracker.generation = generation
        self._tracker_origins[tracker] = (agent_id, generation, cursor)
        return tracker

    def save(self, tracker: StatefulChainTracker) -> None:
        """多 worker 模式下立即提交，单进程模式下由后台线程批量写。

        tracker 必须基于当前已提交的代次和游标。外部创建的 tracker 只能初始化新状态桶，
        旧表中的快照须先通过 ``load()`` 迁移。单进程模式下可调用 ``flush()`` 立即落盘。
        """
        with self._lock:
            if self._closed:
                raise sqlite3.ProgrammingError("chain state store is closed")
            agent_id = tracker.agent_id
            origin = self._tracker_origins.get(tracker, (agent_id, 0, -1))
            write_now = self._multi_process
            try:
                with self._transaction(write=write_now):
                    generation, cursor = self._durable_version(agent_id)
                    count = cursor + 1
                    if origin != (agent_id, generation, cursor) or tracker.generation < generation:
                        raise ValueError("chain state tracker predates the persisted generation or cursor")
                    if (generation, cursor) == (0, -1) and self._has_legacy_snapshot(agent_id):
                        raise ValueError("chain state has an unmigrated legacy snapshot; load it before saving")
                    if write_now:
                        replace = tracker.generation > generation
                        parts = tracker.to_snapshot_parts()
                        rows, metadata = self._serialize_snapshot(agent_id, parts, 0 if replace else count)
                        self._write_snapshot(agent_id, rows, metadata, delete_from=0 if replace else None)
                        count, generation = len(parts["nodes"]), parts["generation"]
            except Exception as exc:
                if (write_now or isinstance(exc, ValueError)) and self._trackers.get(agent_id) is tracker:
                    self._invalidate_cache(agent_id)
                raise
            self._trackers[agent_id] = tracker
            self._publish_cursor(agent_id, count, generation, tracker=tracker)
            if write_now:
                self._dirty.discard(agent_id)
            else:
                self._dirty.add(agent_id)

    def delete(self, agent_id: str) -> None:
        with self._lock:
            with self._transaction():
                previous = self._read_meta(agent_id) or self._read_legacy_snapshot(agent_id) or {}
                generation = int(previous.get("generation", 0)) + 1
                # Retain the generation fence even when all action data is removed.
                metadata = json.dumps({
                    "deleted": True,
                    "generation": generation,
                    "persisted_seq": -1,
                })
                self._write_snapshot(agent_id, [], metadata, delete_from=0)
                self._conn.execute("DELETE FROM chain_state WHERE agent_id=?", (agent_id,))
            self._invalidate_cache(agent_id)
            self._publish_cursor(agent_id, 0, generation)

    # ---------------- 自动轮转与状态重放 ----------------

    def _archive_dir(self) -> Path:
        raw = os.getenv("AGENT_MOSS_CHAIN_ARCHIVE_DIR", "")
        if raw:
            return Path(raw)
        return Path(self.db_path).parent / "chain-archive"

    def _replace_in_tx(
        self, agent_id: str, tracker: StatefulChainTracker, before: list[StateNode] | None,
    ) -> None:
        """Commit the changed suffix when the previous durable nodes are known."""
        persisted_generation, last_seq = self._persisted_version(agent_id)
        if tracker.generation < persisted_generation:
            raise ValueError("chain state tracker predates the persisted generation")
        parts = tracker.to_snapshot_parts()
        nodes = parts["nodes"]
        persisted_count = last_seq + 1
        start = 0
        if before is not None:
            for index in range(min(persisted_count, len(before), len(nodes))):
                if before[index] is not nodes[index]:
                    break
                start += 1
        rows, metadata = self._serialize_snapshot(agent_id, parts, start)
        delete_from = None
        if start == 0:
            delete_from = 0
        elif len(nodes) < persisted_count:
            delete_from = len(nodes)
        self._write_snapshot(agent_id, rows, metadata, delete_from=delete_from)

    def _change_single_process(self, agent_id, operation, may_rewrite):
        with self._lock:
            tracker = self.load_or_new(agent_id)
            generation, count = tracker.generation, len(tracker.nodes)
            before = tracker.to_snapshot_parts() if may_rewrite(tracker) else None
            try:
                result = operation(tracker)
                if tracker.generation != generation:
                    version = self._persisted_version(agent_id)
                    durable_generation, durable_last = version
                    durable_nodes = None
                    if before is not None and generation == durable_generation and count > durable_last:
                        durable_nodes = before["nodes"]
                    with self._transaction():
                        if self._durable_version(agent_id) != version:
                            raise RuntimeError("chain state changed before replay could commit")
                        self._replace_in_tx(agent_id, tracker, durable_nodes)
                    self._publish_cursor(agent_id, len(tracker.nodes), tracker.generation, tracker=tracker)
                    self._dirty.discard(agent_id)
                elif len(tracker.nodes) != count:
                    self._dirty.add(agent_id)
                return result, tracker
            except Exception:
                if before is not None:
                    tracker.restore(tracker.finalize_snapshot(before))
                raise

    def apply_action(
        self,
        agent_id: str,
        a_next: dict,
        session_id: str,
        is_error: bool = False,
        source_agent: str = "",
        instance_id: str = "",
    ) -> AdvanceResult:
        def advance(tracker):
            return tracker.advance(
                a_next=a_next, session_id=session_id, is_error=is_error,
                agent_id=source_agent, instance_id=instance_id, archive_dir=self._archive_dir(),
            )

        if self._multi_process:
            result, _ = self._change_multi_process(agent_id, advance, preserve_readonly_denial=True)
        else:
            result, _ = self._change_single_process(
                agent_id, advance, lambda tracker: tracker.will_rewrite(a_next, session_id),
            )
        return result

    def seed_and_save(
        self, agent_id: str, sessions: list[dict],
    ) -> tuple[int, StatefulChainTracker]:
        def seed(tracker):
            return tracker.seed(sessions, archive_dir=self._archive_dir())

        if self._multi_process:
            return self._change_multi_process(agent_id, seed)
        return self._change_single_process(agent_id, seed, lambda _: True)

    def seed_and_apply(
        self,
        agent_id: str,
        sessions: list[dict],
        a_next: dict,
        session_id: str = "current",
        is_error: bool = False,
    ) -> AdvanceResult:
        """全量重打：seed 历史 + advance 当前动作（定期 review 时用）。

        语义等价 FormalEngine 全量验证（先建立历史时间线，再推进当前动作）。
        """
        def seed_then_advance(tracker):
            archive_dir = self._archive_dir()
            tracker.seed(sessions, archive_dir=archive_dir)
            return tracker.advance(
                a_next=a_next,
                session_id=session_id,
                is_error=is_error,
                archive_dir=archive_dir,
            )

        if self._multi_process:
            result, _ = self._change_multi_process(agent_id, seed_then_advance)
        else:
            result, _ = self._change_single_process(agent_id, seed_then_advance, lambda _: True)
        return result


# 全局单例（FastAPI 进程内共享；测试可注入独立实例）
_store: ChainStateStore | None = None
_atexit_registered = False


def _register_exit_flush() -> None:
    """进程退出前把 dirty 的 tracker 落盘。

    内存缓存把写盘推迟到后台线程（每 1 秒），正常退出（systemctl stop /
    Ctrl-C / SIGTERM）时若不 flush，最坏丢最近一个周期的增量。注册一次即可。
    """
    global _atexit_registered
    if _atexit_registered:
        return
    _atexit_registered = True
    import atexit

    def _flush_on_exit() -> None:
        try:
            if _store is not None:
                _store.close()
        except Exception:  # noqa: BLE001
            pass

    atexit.register(_flush_on_exit)


def get_chain_state_store(db_path: str = "") -> ChainStateStore:
    global _store
    if _store is None or (db_path and db_path != _store.db_path):
        if _store is not None:
            try:
                _store.close()
            except Exception:
                pass
        _store = ChainStateStore(db_path)
        _register_exit_flush()
    return _store


def reset_chain_state_store() -> None:
    """重置全局单例（测试隔离用：把库切到临时目录前先释放旧连接）。"""
    global _store
    if _store is not None:
        try:
            _store.close()
        except Exception:
            pass
        _store = None
