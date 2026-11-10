"""P4 常驻回归：用 AgentGate 真实 tool_calls 数据回放 FormalEngine 全量验证。

目的：规则/性质每次变更后，用真实历史数据验证：
  - P3/P4 抽象性质在"DB 全 Allow"的 session 上**零误报**（防误报回归）；
  - 预置链/敏感数据等性质仍有检出（防漏报回归）。

数据源：~/.local/share/agent_gate/agent_gate_ts.db 的 tool_calls 表。
若 DB 不存在或为空 → 跳过（CI/无数据不卡死）。

注意：这是"生产回放看门狗"，不是单元测试——它依赖真实数据的存在。
"""
import os
import sqlite3
from collections import defaultdict

import pytest

from agent_moss.engine.formal_engine.engine import FormalEngine

DB = os.path.expanduser("~/.local/share/agent_gate/agent_gate_ts.db")

# 抽象性质（误报必须 0）
ABSTRACT_PROPS = {"no-exfil-after-privesc", "no-exfil-after-credential"}


def _load_sessions():
    if not os.path.exists(DB):
        return None
    c = sqlite3.connect(DB)
    try:
        rows = c.execute(
            "SELECT session_id, tool_name, command, decision FROM tool_calls "
            "WHERE session_id IS NOT NULL AND session_id != '' "
            "ORDER BY session_id, seq"
        ).fetchall()
    except sqlite3.OperationalError:
        return None
    finally:
        c.close()
    if not rows:
        return None
    by_session = defaultdict(list)
    for sid, tool, cmd, dec in rows:
        by_session[sid].append({"tool": tool or "bash", "cmd": cmd or "", "decision": dec})
    return by_session


def _verify_session(acts):
    hist = [{"action_type": a["tool"], "action_detail": a["cmd"]} for a in acts]
    if not hist:
        return None
    return FormalEngine().verify([{"session_id": "s", "action_history": hist}]).violations


def test_p3_p4_zero_false_positive_on_real_data():
    """P3/P4 在真实"全 Allow"session 上零误报（回归看门狗）。"""
    by_session = _load_sessions()
    if by_session is None:
        pytest.skip("AgentGate tool_calls DB 不存在，跳过 P4 回放")

    false_pos = 0
    total_all_allow = 0
    examples = []
    for acts in by_session.values():
        if all(a["decision"] in ("Allow", "", None) for a in acts):
            total_all_allow += 1
            viols = _verify_session(acts) or []
            new_viol = [v for v in viols if v.property_id in ABSTRACT_PROPS]
            if new_viol:
                false_pos += 1
                if len(examples) < 3:
                    examples.append((new_viol[0].property_id, acts[:3]))

    # 零误报是硬性要求（P3/P4 是针对抽象性质的，不该打翻全 Allow 的正常流程）
    assert false_pos == 0, (
        f"P3/P4 在 {total_all_allow} 个全 Allow session 上误捕 {false_pos} 个: "
        f"{examples}"
    )


def test_formal_engine_still_detects_on_real_data():
    """预置链/taint 在真实数据上仍有检出（防漏报回归）。"""
    by_session = _load_sessions()
    if by_session is None:
        pytest.skip("AgentGate tool_calls DB 不存在，跳过 P4 回放")

    detected = 0
    deny_in_db = 0
    for acts in by_session.values():
        if any(a["decision"] == "Deny" for a in acts):
            deny_in_db += 1
        viols = _verify_session(acts) or []
        # 只有 count>0 的任意性质命中都算检出（含跨会话链/taint/抽象性质）
        if viols:
            detected += 1

    # 至少要有检出（若 DB 完全没有可检出的 session，说明数据太干净，跳过）
    if deny_in_db == 0 and detected == 0:
        pytest.skip("真实数据无任何 Deny 标注，跳过检出断言")
    assert detected > 0, "FormalEngine 在真实数据上零检出（疑似遗留或性质失效）"