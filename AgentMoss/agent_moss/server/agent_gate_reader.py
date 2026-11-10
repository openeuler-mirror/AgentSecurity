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

import glob
import json
import os
import sqlite3
from pathlib import Path
from typing import Any

DEFAULT_SQLITE = os.path.expanduser("~/.local/share/agent_gate/agent_gate_ts.db")


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


def read_agent_gate_sessions(
    db_path: str = "",
    agent_id: str = "",
    limit: int = 100000,
) -> list[dict]:
    """从 AgentGate SQLite 读全量 tool_calls → sessions 结构。"""
    path = db_path or discover_agent_gate_db()
    sessions: dict[str, list[dict]] = {}
    if not os.path.exists(path):
        return []
    uri = f"file:{path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=10)
    try:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT session_id, action_type, tool_name, action_detail, command, called_at
            FROM tool_calls
            ORDER BY called_at, id
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        for r in rows:
            sid = str(r["session_id"] or "")
            if not sid:
                continue
            act = _normalize_action(dict(r))
            if not act["action_detail"]:
                continue
            sessions.setdefault(sid, []).append(act)
    finally:
        conn.close()
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
    files = glob.glob(os.path.join(d, "*.json"))
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


def load_agent_gate_sessions(db_path: str = "") -> list[dict]:
    """统一入口：优先 SQLite，找不到默认就试 JSON 目录。"""
    if db_path and os.path.isdir(db_path):
        return read_agent_gate_json_sessions(dir_path=db_path)
    sessions = read_agent_gate_sessions(db_path=db_path)
    if sessions:
        return sessions
    # 无显式路径/库里空 → 兜底 JSON 目录
    return read_agent_gate_json_sessions()