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

    P0 性能：实测每次 save() 全量重写 JSON + 逐次 commit（fsync）在
    长时间线下达 ~36ms/次，是增量热路径的瓶颈。规避：
      - WAL 模式 + synchronous=NORMAL：读多写少，WAL 下 NORMAL 已保证
        crash-safe（仅掉电边界丢最近一帧），砍掉每次 fsync（大头）。
      - save() 显式事务批内执行，避免逐条 AUTOCOMMIT 的 fsync 风暴。
    """

    def __init__(self, db_path: str = ""):
        self.db_path = db_path or default_state_db_path()
        self._lock = threading.RLock()
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
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS chain_state (
                    agent_id  TEXT PRIMARY KEY,
                    state_json TEXT NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def load(self, agent_id: str) -> StatefulChainTracker | None:
        """读取某 agent 的 tracker；不存在返回 None。"""
        with self._lock:
            row = self._conn.execute(
                "SELECT state_json FROM chain_state WHERE agent_id=?", (agent_id,)
            ).fetchone()
        if not row:
            return None
        try:
            snap = json.loads(row["state_json"])
        except (ValueError, TypeError):
            return None
        t = StatefulChainTracker(agent_id=agent_id)
        t.restore(snap)
        return t

    def load_or_new(self, agent_id: str) -> StatefulChainTracker:
        """读取某 agent 的 tracker；不存在则新建（幂等）。"""
        t = self.load(agent_id)
        if t is None:
            t = StatefulChainTracker(agent_id=agent_id)
            self.save(t)
        return t

    def save(self, tracker: StatefulChainTracker) -> None:
        """写回 tracker 快照（WAL + NORMAL 下 commit 不 fsync，近毫秒级）。"""
        snap = tracker.to_snapshot()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO chain_state (agent_id, state_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    state_json=excluded.state_json,
                    updated_at=excluded.updated_at
                """,
                (tracker.agent_id, json.dumps(snap, ensure_ascii=False), time.time()),
            )

    def delete(self, agent_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM chain_state WHERE agent_id=?", (agent_id,)
            )

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
        """
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


def get_chain_state_store(db_path: str = "") -> ChainStateStore:
    global _store
    if _store is None or (db_path and db_path != _store.db_path):
        if _store is not None:
            try:
                _store.close()
            except Exception:
                pass
        _store = ChainStateStore(db_path)
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