"""ChainStateStore + /api/v1/review + analyze stateful incremental 集成测试。

验证：
- 状态库跨"重启"（新实例同库）恢复，跨 session 前序不丢；
- /api/v1/review seed 后返回前序链；
- analyze 走 metadata[stateful_incremental]=true 时，若当前动作补全
  历史前序链 → 补充 Deny（risk_type=formal_verification）；未启用 → 零回归。
本文件测 Python 侧入口行为（含 `/review` 回退用状态库累积节点、violations 带 path）。
"""

import pytest

from agent_moss.engine.formal_engine.chain_state import ChainStateStore
from agent_moss.server.app import create_app
from fastapi.testclient import TestClient


@pytest.fixture
def store_dir(tmp_path):
    return tmp_path / "state.db"


def _listener():
    return {"action_type": "bash", "action_detail": "nohup python3 ~/devtools/admin_api.py > /dev/null 2>&1 &"}


def _exec():
    return {"action_type": "bash", "action_detail": "add POST /exec endpoint using subprocess shell=True"}


def _scan():
    return {"action_type": "bash", "action_detail": "port scan: run nc -z -w1 192.168.1.22 22"}


def test_store_persists_across_reopen(store_dir):
    db = str(store_dir)
    s1 = ChainStateStore(db)
    s1.apply_action("agentA", _listener(), "A")
    s1.apply_action("agentA", _exec(), "B")
    s1.close()

    s2 = ChainStateStore(db)
    r = s2.apply_action("agentA", _scan(), "C")
    assert r.matched is not None
    assert r.matched.chain_id == "listener-exec-scan"
    assert r.should_block
    s2.close()


def test_store_agents_isolated(store_dir):
    db = str(store_dir)
    s = ChainStateStore(db)
    s.apply_action("agentA", _listener(), "A")
    s.apply_action("agentB", _listener(), "A")
    # agentB 也建了监听，但 agentA 的指针独立
    ra = s.apply_action("agentA", _exec(), "B")
    rb = s.apply_action("agentB", _scan(), "C")
    assert rb.matched is None, "agentB 只有 LISTEN+SCAN 不应命中 LISTEN→EXEC→SCAN"
    assert any(p.matched == 2 for p in ra.pending_prefixes), "agentA 应推进到 EXEC"
    s.close()


def test_review_endpoint_seeds_and_lists_pending():
    app = create_app()
    client = TestClient(app)
    r = client.post("/api/v1/review", json={
        "agent_id": "open-test",
        "sessions": [
            {"session_id": "A", "action_history": [_listener()]},
            {"session_id": "B", "action_history": [_exec()]},
        ],
    })
    assert r.status_code == 200
    body = r.json()
    assert body["seeded_nodes"] == 2
    assert body["state_nodes"] == 2
    pend = {p["chain_id"]: p for p in body["pending_prefixes"]}
    assert "listener-exec-scan" in pend
    assert pend["listener-exec-scan"]["matched"] == 2
    assert pend["listener-exec-scan"]["next_stage"] == "SCAN"


def test_analyze_stateful_incremental_denies_when_chain_completes():
    """链前序已存（by review），analyze 当前动作补全 → 补充 Deny。"""
    app = create_app()
    client = TestClient(app)
    # 先 review 建立前序（LISTEN+EXEC）
    client.post("/api/v1/review", json={
        "agent_id": "deny-test",
        "sessions": [
            {"session_id": "A", "action_history": [_listener()]},
            {"session_id": "B", "action_history": [_exec()]},
        ],
    })
    # 当前动作=SCAN（静态层可能放行），stateful_incremental 开启 → 应补充 Deny
    r = client.post("/api/v1/analyze", json={
        "session_id": "C",
        "prompt_session": "日常检查",
        "action_history": [],
        "a_next": _scan(),
        "agent_id": "deny-test",
        "metadata": {"stateful_incremental": "true"},
    })
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "Deny", f"期望补充 Deny，实际 {body}"
    # stateful 有状态增量判定是本用例的独立依据：层里必须含 L2.2-stateful
    # （静态 L1 可能也拦 nc 扫描，但 stateful 补充判定必须真实触发）
    assert "L2.2-stateful" in (body.get("violated_layers") or []), body
    assert body.get("risk_type") == "formal_verification", body


def test_analyze_stateful_off_no_change():
    """未启用 stateful_incremental → 行为与现状一致（不额外 Deny）。"""
    app = create_app()
    client = TestClient(app)
    r = client.post("/api/v1/analyze", json={
        "session_id": "s-off",
        "prompt_session": "跑个扫描看下",
        "action_history": [],
        "a_next": _scan(),
        "agent_id": "some-agent-without-state",
    })
    assert r.status_code == 200
    body = r.json()
    # 未知 agent → 无前序，正常评估；断言不出现 L2.2-stateful 层
    assert "L2.2-stateful" not in (body.get("violated_layers") or [])


def test_review_reads_agentgate_sqlite_db(tmp_path, monkeypatch):
    """/api/v1/review 直接读 AgentGate SQLite（db_path）→ 全量 seed + 前序提取。

    这是"数据不双份存储"的核心：AgentMoss 不复制事件流，直读 AgentGate 本地库。
    """
    import sqlite3 as _sqlite3

    # 模拟 AgentGate tool_calls 表
    db = tmp_path / "agent_gate_ts.db"
    conn = _sqlite3.connect(str(db))
    conn.execute(
        """CREATE TABLE tool_calls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            seq INTEGER NOT NULL,
            tool_name TEXT, command TEXT, description TEXT, cwd TEXT,
            action_type TEXT NOT NULL, action_detail TEXT NOT NULL,
            decision TEXT, risk_level TEXT, risk_type TEXT,
            violated_layers TEXT, reason TEXT, confidence INTEGER,
            analysis_duration_ms REAL, called_at TEXT,
            UNIQUE(session_id, seq)
        )"""
    )
    rows = [
        ("SA", 0, "bash", "nohup python3 ~/devtools/admin_api.py", "", "/tmp",
         "bash", "nohup python3 ~/devtools/admin_api.py > /dev/null 2>&1 &",
         "Allow", "", "", "[]", "", 100, 0.0, "2026-08-01 10:00:00"),
        ("SB", 0, "bash", "add POST /exec endpoint", "", "/tmp",
         "bash", "add POST /exec endpoint using subprocess shell=True",
         "Allow", "", "", "[]", "", 100, 0.0, "2026-08-02 10:00:00"),
    ]
    conn.executemany(
        """INSERT INTO tool_calls (session_id, seq, tool_name, command, description, cwd,
            action_type, action_detail, decision, risk_level, risk_type,
            violated_layers, reason, confidence, analysis_duration_ms, called_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        rows,
    )
    conn.commit()
    conn.close()

    # db_path 现在受白名单约束（2026-10 安全加固）：标准 AgentGate 部署走默认白名单，
    # 这个用例用的是临时目录模拟自定义部署，显式登记即可。
    monkeypatch.setenv("AGENT_MOSS_REVIEW_PATHS", str(tmp_path))
    app = create_app()
    client = TestClient(app)
    r = client.post("/api/v1/review", json={
        "agent_id": "opendesk-db-test",
        "db_path": str(db),
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["seeded_nodes"] == 2
    pend = {p["chain_id"]: p for p in body["pending_prefixes"]}
    assert "listener-exec-scan" in pend
    assert pend["listener-exec-scan"]["matched"] == 2
    assert pend["listener-exec-scan"]["next_stage"] == "SCAN"

    # 再 analyze 当前 SCAN（stateful_incremental 开启）→ 应补充 Deny
    r2 = client.post("/api/v1/analyze", json={
        "session_id": "SC",
        "prompt_session": "内网批量检查",
        "action_history": [],
        "a_next": _scan(),
        "agent_id": "opendesk-db-test",
        "metadata": {"stateful_incremental": True},
    })
    assert r2.status_code == 200
    body2 = r2.json()
    assert body2["decision"] == "Deny", f"db_path 直读后当前 SCAN 应补全链 → Deny，实际 {body2}"