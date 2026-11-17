"""链状态仓储（Chain State Store）— 有状态增量分析器的持久化层。

职责：按 agent 隔离地持久化 StatefulChainTracker 的快照（时间线节点 + 链指针 +
taint + 存活资源），并暴露增量的"种子/推进"入口。服务重启后从快照恢复，跨 session
组合链的"前序"状态不丢（这正是"从开始记录就持续分析"的落点）。

存储形态：SQLite 单库（默认 ~/.agentmoss/stateful_chains.db；测试可注入 path）。
表：
- chain_state(agent_id PRIMARY KEY, state_json, updated_at)

JSON 文件形态，对应无 sqlite 环境；AgentGate 侧逻辑一致）。
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from .stateful import StatefulChainTracker, AdvanceResult


def default_state_db_path() -> str:
    """默认状态库路径（与 brain/runtime_config 同目录风格）。"""
    base = os.environ.get("AGENT_MOSS_STATE_DIR") or os.path.join(
        Path.home(), ".agentmoss"
    )
    return os.path.join(base, "stateful_chains.db")


class ChainStateStore:
    """SQLite 持久化的链状态仓储（线程安全）。

    性能演进（2026-11，招行现场）：

    旧实现每次 ``apply_action`` 都是「SQLite 全量读 → json.loads → 重建所有
    节点 → 追加 → 全量 json.dumps → 全量写回」，O(节点数)。长时间运行后
    时间线到几万节点，单次几十到几百毫秒 —— 招行表现为「跑一段时间就变慢、
    最后 503」。WAL/NORMAL 只砍掉了 fsync，全量读写的本质没变。

    新实现：
      - **进程内缓存** tracker（``_trackers``）：``apply_action`` 是纯内存
        O(1) 追加，不再每次读库/反序列化。
      - **防抖写盘**：变更标记 dirty，后台 daemon 线程每 ``_flush_interval``
        秒批量落盘一次。崩溃最坏丢最近一个间隔的增量（与 WAL+NORMAL 的
        「掉电丢最近一帧」同一量级）。
      - ``apply_action`` 全程持 ``RLock``：调用方已把它放进线程池，必须保证
        load→advance→标记 的原子性，否则并发请求会丢节点。

    已知限制：多 worker 部署时各进程缓存互相不可见（与并发池计数同样的
    限制，见文档）。单进程部署（默认）不受影响。
    """

    #: 后台落盘间隔（秒）。太短会让写盘重新变成热路径，太长会丢更多。
    _FLUSH_INTERVAL = 1.0

    def __init__(self, db_path: str = ""):
        self.db_path = db_path or default_state_db_path()
        self._lock = threading.RLock()
        #: 保护 SQLite 连接（后台 flush 线程与请求线程共用）。锁顺序固定为
        #: _lock → _db_lock，不允许反向获取。
        self._db_lock = threading.Lock()
        #: agent_id -> 内存中的 tracker（唯一事实源；SQLite 是它的持久化副本）
        self._trackers: dict[str, StatefulChainTracker] = {}
        #: 自上次落盘以来变过的 agent_id
        self._dirty: set[str] = set()
        #: agent_id -> 已经写进 chain_nodes 表的节点数（增量落盘的游标）。
        #: 节点本身创建后不可变（_append 之后没有任何字段修改），所以只需按
        #: 长度差追加新节点，不必每次重写整条时间线。
        self._persisted_nodes: dict[str, int] = {}
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
        """把 dirty 的 tracker 落盘，返回写入条数。

        锁粒度（关键，2026-11 长稳实测）：``to_snapshot_parts`` 必须在
        ``_lock`` 内（tracker 会被并发 advance），但它只做浅拷贝（4 万节点
        0.42ms）；**逐节点构建、``json.dumps``、SQLite 写全部在锁外** ——
        这部分 4 万节点要 100ms+，放锁内会让每秒一次的 flush 变成全局卡顿，
        实测长稳 QPS 47→32、p95 225→529ms。
        """
        with self._lock:
            if self._closed:
                return 0
            dirty = list(self._dirty)
            self._dirty.clear()
            parts: list[tuple[str, dict]] = []
            for agent_id in dirty:
                tracker = self._trackers.get(agent_id)
                if tracker is None:
                    continue
                try:
                    # 锁内只做浅拷贝（2 万节点约 0.2ms）；逐节点构建在锁外
                    parts.append((agent_id, tracker.to_snapshot_parts()))
                except Exception:  # noqa: BLE001
                    self._dirty.add(agent_id)
        written = 0
        for agent_id, part in parts:
            try:
                nodes = part["nodes"]  # list[StateNode]（浅拷贝）
                start = self._persisted_nodes.get(agent_id, 0)
                new_nodes = nodes[start:]
                # 锁外：只序列化**新增**的节点（通常 1~几个/秒），不再重写整条时间线
                rows = [
                    (
                        agent_id,
                        int(n.seq),
                        json.dumps(
                            {k: (v if k != "resources" else list(v)) for k, v in n.__dict__.items()},
                            ensure_ascii=False,
                        ),
                    )
                    for n in new_nodes
                ]
                # 元数据（链指针 / taint / alive 资源 / seed 指纹）体积很小，每次全量写。
                # 注意 seeded_keys 是 set，json 不能直接序列化（2026-11 踩到：
                # dumps 抛 TypeError 被外层吞掉 → chain_meta 永远写不进去 →
                # 重启后 load 返回 None，状态全丢）。
                meta = {k: v for k, v in part.items() if k != "nodes"}
                if isinstance(meta.get("seeded_keys"), set):
                    meta["seeded_keys"] = sorted(meta["seeded_keys"])
                meta_json = json.dumps(meta, ensure_ascii=False)
                with self._db_lock:
                    self._conn.execute("BEGIN")
                    try:
                        if rows:
                            self._conn.executemany(
                                "INSERT OR REPLACE INTO chain_nodes "
                                "(agent_id, seq, node_json) VALUES (?, ?, ?)",
                                rows,
                            )
                        self._conn.execute(
                            """
                            INSERT INTO chain_meta (agent_id, meta_json, updated_at)
                            VALUES (?, ?, ?)
                            ON CONFLICT(agent_id) DO UPDATE SET
                                meta_json=excluded.meta_json,
                                updated_at=excluded.updated_at
                            """,
                            (agent_id, meta_json, time.time()),
                        )
                        self._conn.execute("COMMIT")
                    except Exception:
                        try:
                            self._conn.execute("ROLLBACK")
                        except Exception:  # noqa: BLE001
                            pass
                        raise
                with self._lock:
                    self._persisted_nodes[agent_id] = len(nodes)
                written += 1
            except Exception:  # noqa: BLE001
                # 写失败 → 重新标记，下个周期再试（不能丢数据）
                with self._lock:
                    self._dirty.add(agent_id)
        return written

    def close(self) -> None:
        self._stop.set()
        try:
            self.flush()
        except Exception:  # noqa: BLE001
            pass
        with self._lock:
            self._closed = True
            with self._db_lock:
                try:
                    self._conn.close()
                except Exception:  # noqa: BLE001
                    pass

    # ---------------- 读写 ----------------

    def load(self, agent_id: str) -> StatefulChainTracker | None:
        """读取某 agent 的 tracker（优先内存缓存）；不存在返回 None。

        新结构（0.17.23 起）：节点按行存在 ``chain_nodes``，元数据在
        ``chain_meta``。首次遇到旧结构（``chain_state`` 整份 JSON）时做一次
        迁移，迁移完删掉旧行。
        """
        with self._lock:
            cached = self._trackers.get(agent_id)
            if cached is not None:
                return cached
            with self._db_lock:
                meta_row = self._conn.execute(
                    "SELECT meta_json FROM chain_meta WHERE agent_id=?", (agent_id,)
                ).fetchone()
                if meta_row is None:
                    old_row = self._conn.execute(
                        "SELECT state_json FROM chain_state WHERE agent_id=?", (agent_id,)
                    ).fetchone()
                    if old_row is None:
                        return None
                    try:
                        snap = json.loads(old_row["state_json"])
                    except (ValueError, TypeError):
                        return None
                    self._migrate_from_old(agent_id, snap)
                else:
                    node_rows = self._conn.execute(
                        "SELECT node_json FROM chain_nodes WHERE agent_id=? ORDER BY seq",
                        (agent_id,),
                    ).fetchall()
                    try:
                        meta = json.loads(meta_row["meta_json"])
                    except (ValueError, TypeError):
                        return None
                    snap = dict(meta)
                    snap["agent_id"] = agent_id
                    try:
                        snap["nodes"] = [json.loads(r["node_json"]) for r in node_rows]
                    except (ValueError, TypeError):
                        return None
            t = StatefulChainTracker(agent_id=agent_id)
            t.restore(snap)
            self._trackers[agent_id] = t
            self._persisted_nodes[agent_id] = len(t.nodes)
            return t

    def _migrate_from_old(self, agent_id: str, snap: dict) -> None:
        """把旧结构（``chain_state`` 整份 JSON 一行）迁移到新表，成功后删旧行。

        幂等：迁移失败（异常）会保留旧行，下次 load 再试；不会丢数据。
        """
        nodes = snap.get("nodes") or []
        meta = {k: v for k, v in snap.items() if k not in ("nodes", "agent_id")}
        self._conn.execute("BEGIN")
        try:
            if nodes:
                self._conn.executemany(
                    "INSERT OR REPLACE INTO chain_nodes (agent_id, seq, node_json) "
                    "VALUES (?, ?, ?)",
                    [
                        (agent_id, int(n.get("seq", i)), json.dumps(n, ensure_ascii=False))
                        for i, n in enumerate(nodes)
                    ],
                )
            self._conn.execute(
                "INSERT OR REPLACE INTO chain_meta (agent_id, meta_json, updated_at) "
                "VALUES (?, ?, ?)",
                (agent_id, json.dumps(meta, ensure_ascii=False), time.time()),
            )
            self._conn.execute("DELETE FROM chain_state WHERE agent_id=?", (agent_id,))
            self._conn.execute("COMMIT")
        except Exception:  # noqa: BLE001
            try:
                self._conn.execute("ROLLBACK")
            except Exception:  # noqa: BLE001
                pass
            raise

    def load_or_new(self, agent_id: str) -> StatefulChainTracker:
        """读取某 agent 的 tracker；不存在则新建（幂等）。"""
        with self._lock:
            t = self.load(agent_id)
            if t is None:
                t = StatefulChainTracker(agent_id=agent_id)
                self._trackers[agent_id] = t
                self._dirty.add(agent_id)
            return t

    def save(self, tracker: StatefulChainTracker) -> None:
        """标记 tracker 需要落盘（内存先更新，后台线程批量写）。

        立即写盘请调用 ``flush()`` —— review 这类「写完马上要被另外的进程
        读到」的场景用它。
        """
        with self._lock:
            self._trackers[tracker.agent_id] = tracker
            self._dirty.add(tracker.agent_id)

    def delete(self, agent_id: str) -> None:
        with self._lock:
            self._trackers.pop(agent_id, None)
            self._dirty.discard(agent_id)
            self._persisted_nodes.pop(agent_id, None)
            with self._db_lock:
                self._conn.execute("DELETE FROM chain_nodes WHERE agent_id=?", (agent_id,))
                self._conn.execute("DELETE FROM chain_meta WHERE agent_id=?", (agent_id,))
                self._conn.execute("DELETE FROM chain_state WHERE agent_id=?", (agent_id,))

    # ---------------- 应用层入口（供 server 用） ----------------

    def apply_action(
        self,
        agent_id: str,
        a_next: dict,
        session_id: str,
        is_error: bool = False,
        source_agent: str = "",
        instance_id: str = "",
    ) -> AdvanceResult:
        """有状态的实时增量：对某 agent 的 tracker 推送一条当前动作并判定。

        - 首次（无 tracker）→ 从空状态 advance（等价只分析当前动作）。
        - 之后 → 增量推进时间线 + 链指针。
        - 返回 AdvanceResult（matched/exfil = 应阻断；pending_prefixes = 前序）。

        并发：调用方已把本方法放进线程池，这里**全程持锁**保证
        load→advance→标记 的原子性 —— 否则两个并发请求会各自 based on
        同一份快照推进，后写的覆盖先写的（丢节点 = 组合链漏拦）。
        锁内只做内存操作，O(1)；写盘由后台线程完成。
        """
        with self._lock:
            t = self.load(agent_id) or StatefulChainTracker(agent_id=agent_id)
            r = t.advance(
                a_next=a_next,
                session_id=session_id,
                is_error=is_error,
                agent_id=source_agent,
                instance_id=instance_id,
            )
            self.save(t)
            return r

    def seed_and_save(
        self, agent_id: str, sessions: list[dict]
    ) -> tuple[int, "StatefulChainTracker"]:
        """review 专用：**持锁**完成 load → seed → 标记落盘，返回 (新增数, tracker)。

        为什么单独一个方法（2026-11）：``/review`` 原先在锁外调
        ``tracker.seed(...)`` —— 它修改的是内存缓存里的**同一个 tracker 对象**，
        而此时并发的 ``apply_action`` 正在持锁推进同一条时间线。两边同时改
        ``nodes`` / 链指针，结果就是丢节点或指针错位。锁必须覆盖整个 seed。
        """
        with self._lock:
            tracker = self.load_or_new(agent_id)
            added = tracker.seed(sessions)
            self.save(tracker)
            return added, tracker

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
        with self._lock:
            t = self.load(agent_id) or StatefulChainTracker(agent_id=agent_id)
            t.seed(sessions)
            r = t.advance(
                a_next=a_next,
                session_id=session_id,
                is_error=is_error,
            )
            self.save(t)
            return r


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