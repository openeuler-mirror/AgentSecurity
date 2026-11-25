"""AgentGate 本地存储读取器 — 让 AgentMoss 直接从 AgentGate 的存储文件读全量历史。

设计初衷（对齐最终方案）：
- 全量事件流单一归属 AgentGate（SQLite 或 JSON），AgentMoss 不复制原始数据；
- /api/v1/review 直接指向 AgentGate 存储路径（db_path），本模块把 tool_calls
  读成统一 sessions 结构（[{session_id, action_history:[{action_type, action_detail}]}]），
  供 ChainStateStore.seed / FormalEngine.verify 消费；
- 只读打开（mode=ro + busy_timeout），与 AgentGate 的写不冲突；
- agent 维度过滤：AgentGate DB 可能混多 agent，按 in_clause 无，简单返回全部，
  由调用方按 agent_id 过滤（AgentGate 单实例通常单 agent）。

支持两种后端：
- SQLite：`~/.local/share/agent_gate/agent_gate_ts.db`（default）或 env AGENT_GATE_DB。
- JSON 目录：`AGENT_GATE_STORAGE=json` → `tool_calls/<session_id>.json` 数组。
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from pathlib import Path

from ..infra import security_policy as sp

DEFAULT_SQLITE = os.path.expanduser("~/.local/share/agent_gate/agent_gate_ts.db")
SQLITE_HISTORY_LIMIT = 100000


def discover_agent_gate_db() -> str:
    """寻找 AgentGate SQLite 路径（env > 默认）。"""
    return os.environ.get("AGENT_GATE_DB", "").strip() or DEFAULT_SQLITE


def _normalize_action(row: dict) -> dict:
    act = {
        "action_type": str(row.get("action_type") or row.get("tool_name") or row.get("name") or ""),
        "action_detail": str(row.get("action_detail") or row.get("command") or row.get("input") or ""),
    }
    # 保留真实发生时间，供 stateful 时间线记录 timestamp（无则不带，退化为 seq）
    if row.get("called_at"):
        act["called_at"] = str(row["called_at"])
    return act


def _gate_review_metadata(raw: object) -> dict:
    if not isinstance(raw, str) or not (
        '"_gate_call_id"' in raw or '"_gate_protocol_rejected"' in raw
    ):
        return {}
    try:
        audit = json.loads(raw)
    except (ValueError, RecursionError):
        return {}
    if not isinstance(audit, dict):
        return {}
    if audit.get("_gate_protocol_rejected") is True:
        return {"_gate_protocol_rejected": True}
    call_id = audit.get("_gate_call_id")
    call_time = audit.get("_gate_call_time_us")
    if sp.valid_gate_call_id(call_id) and sp.valid_gate_call_time(call_time):
        return {"_gate_call_id": call_id, "_gate_call_time_us": call_time}
    return {}


def read_agent_gate_sessions(
    db_path: str = "",
    agent_id: str = "",
    limit: int = SQLITE_HISTORY_LIMIT,
    *,
    include_review_rank: bool = False,
) -> list[dict]:
    """Select the latest valid SQLite rows globally before grouping by session."""
    # Explicit review paths were resolved and authorized by the route. Use the
    # same path at open time instead of resolving it again after authorization.
    path = (
        Path(db_path).expanduser().absolute()
        if db_path
        else Path(os.path.realpath(os.path.expanduser(discover_agent_gate_db())))
    )
    configured = os.environ.get("AGENT_GATE_DB", "").strip()
    trusted = bool(configured) and path == Path(os.path.realpath(os.path.expanduser(configured)))
    limit = min(limit, SQLITE_HISTORY_LIMIT) if limit > 0 else SQLITE_HISTORY_LIMIT
    try:
        conn = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True, timeout=10)
    except sqlite3.OperationalError:
        # SQLite reports both a missing file and access failures as CANTOPEN.
        # Check after the open attempt in case the source disappeared.
        try:
            path.stat()
        except FileNotFoundError:
            if db_path:
                raise
            return []
        raise
    try:
        conn.row_factory = sqlite3.Row
        with_metadata = trusted and any(
            row["name"] == "moss_response"
            for row in conn.execute("PRAGMA table_info(tool_calls)")
        )
        audit_column = ", call.moss_response" if with_metadata else ""
        rows = conn.execute(
            f"""
            WITH recent AS (
                SELECT rowid AS call_rowid, called_at, id
                FROM tool_calls
                WHERE COALESCE(session_id, '') <> ''
                  AND (COALESCE(action_detail, '') <> '' OR COALESCE(command, '') <> '')
                ORDER BY called_at DESC, id DESC, rowid DESC
                LIMIT ?
            ), ranked AS (
                SELECT call_rowid,
                       ROW_NUMBER() OVER (ORDER BY called_at DESC, id DESC, call_rowid DESC) AS review_rank
                FROM recent
            )
            SELECT ranked.review_rank, call.session_id, call.action_type, call.tool_name,
                   call.action_detail, call.command, call.called_at{audit_column}
            FROM ranked
            CROSS JOIN tool_calls AS call ON call.rowid = ranked.call_rowid
            """,
            (limit,),
        )
        actions_by_rank: list[tuple[int, str, dict]] = []
        for r in rows:
            sid = str(r["session_id"] or "")
            if not sid:
                continue
            act = _normalize_action(dict(r))
            if not act["action_detail"]:
                continue
            if with_metadata:
                act.update(_gate_review_metadata(r["moss_response"]))
            rank = r["review_rank"]
            if include_review_rank:
                act["_sqlite_review_rank"] = rank
            # Rank narrow row identifiers in SQLite, then order only normalized
            # actions here so large response JSON never enters either sort.
            actions_by_rank.append((rank, sid, act))
    finally:
        conn.close()
    sessions: dict[str, list[dict]] = {}
    for _, sid, act in sorted(actions_by_rank, reverse=True):
        sessions.setdefault(sid, []).append(act)
    return [
        {"session_id": sid, "action_history": actions}
        for sid, actions in sessions.items()
    ]


def read_agent_gate_json_sessions(dir_path: str = "", limit: int = 100000) -> list[dict]:
    """从 AgentGate JSON 存储目录（tool_calls/<session_id>.json）读 sessions。"""
    d = dir_path or os.environ.get("AGENT_GATE_JSON_PATH", "")
    if not d:
        d = str(Path(os.path.expanduser("~/.local/share/agent_gate")) / "tool_calls")
    sessions: dict[str, list[dict]] = {}
    try:
        files = [
            p for p in Path(d).expanduser().iterdir()
            if not p.name.startswith(".") and p.match("*.json")
        ]
    except OSError:
        if dir_path:
            raise
        return []
    for fp in sorted(files)[-200:]:  # 防御海量文件
        sid = Path(fp).stem
        try:
            with open(fp, "r", encoding="utf-8") as f:
                arr = json.load(f)
        except (ValueError, OSError):
            continue
        if not isinstance(arr, list):
            continue
        for item in arr:
            act = _normalize_action(item) if isinstance(item, dict) else {}
            if act.get("action_detail"):
                sessions.setdefault(str(sid), []).append(act)
        if sum(len(v) for v in sessions.values()) > limit:
            break
    return [
        {"session_id": sid, "action_history": act}
        for sid, act in sessions.items()
    ]


def load_agent_gate_sessions(
    db_path: str = "", *, limit: int = SQLITE_HISTORY_LIMIT, include_review_rank: bool = False,
) -> list[dict]:
    """显式路径只读该来源；无参调用保留 SQLite、默认 JSON 的发现顺序。"""
    if db_path:
        path = Path(db_path).expanduser()
        if stat.S_ISDIR(path.stat().st_mode):
            return read_agent_gate_json_sessions(dir_path=str(path))
        return read_agent_gate_sessions(db_path=str(path), limit=limit, include_review_rank=include_review_rank)
    return read_agent_gate_sessions(limit=limit, include_review_rank=include_review_rank) or read_agent_gate_json_sessions()
