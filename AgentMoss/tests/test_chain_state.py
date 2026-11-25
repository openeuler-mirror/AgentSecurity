"""ChainStateStore + /api/v1/review + analyze stateful incremental 集成测试。

验证：
- 状态库跨"重启"（新实例同库）恢复，跨 session 前序不丢；
- /api/v1/review seed 后返回前序链；
- analyze 走 metadata[stateful_incremental]=true 时，若当前动作补全
  历史前序链 → 补充 Deny（risk_type=formal_verification）；未启用 → 零回归。
双端镜像：TS 也有 HTTP 服务（`ts/src/routes.ts` 的 `reviewRoute` / analyze 的
`metadata.stateful_incremental`），本文件测 Python 侧；TS 侧入口行为由
`ts/src/__tests__/http-entrypoint-parity.test.ts` 覆盖（含 `/review` 回退用状态库
累积节点、violations 带 path），引擎语义一致性由 `formal-stateful.test.ts` 覆盖。
"""

import hashlib
import sys
from threading import Event
from types import SimpleNamespace
from unittest.mock import Mock

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
    assert body["violation_graph"]["property_id"] == "cross-listener-exec-scan"


@pytest.mark.parametrize(
    ("decision", "risk", "outcome", "exfil", "expected_reason", "expected_risk", "expected_outcome"),
    [
        ("Deny", "critical", "ok", False, "engine", "critical", "ok"),
        ("Deny", "high", "reasoning_fallback", False, "engine", "high", "reasoning_fallback"),
        ("Deny", "high", "ok", True, "flow", "critical", "ok"),
        ("Allow", "low", "fail_open", False, "chain", "high", "failed_but_blocked"),
        ("Allow", "low", "circuit_open", False, "chain", "high", "circuit_open"),
        ("Deny", "high", "failed_but_blocked", False, "chain", "high", "failed_but_blocked"),
        ("Allow", "low", "skipped", False, "chain", "high", "skipped"),
        ("Deny", "high", "skipped", False, "chain", "high", "skipped"),
    ],
)
def test_stateful_response_and_audit_follow_highest_denial(
    monkeypatch, decision, risk, outcome, exfil, expected_reason, expected_risk, expected_outcome,
):
    from agent_moss.engine import analyzer
    from agent_moss.infra import metrics
    from agent_moss.server import routes

    observed = outcome == "failed_but_blocked"
    budget_skipped = outcome == "skipped"
    prior_layers = ["L2.2"] if observed else (["L1.1"] if decision == "Deny" and not budget_skipped else [])
    sources = {"failed_but_blocked": "llm_failure_with_violation", "skipped": "llm_budget_skipped"}
    degraded = ["l3_budget_floor_exceeds"] if budget_skipped else []
    monkeypatch.setattr(analyzer, "analyze", Mock(return_value={
        "source": sources.get(outcome, "engine"),
        "decision": decision, "risk_level": risk, "risk_type": "" if observed else "engine",
        "reason": "model failed" if observed else "engine",
        "violated_policy": "engine", "violated_layers": prior_layers, "confidence": 76,
        "policy": "allow policy" if decision == "Allow" else "", "l3_outcome": outcome,
        "degraded": degraded,
    }))
    chain = {"risk_level": "high", "reason": "chain", "graph": {"property_id": "chain"}}
    flow = {"risk_level": "critical", "reason": "flow", "graph": {"property_id": "flow"}}
    state = Mock()
    state.apply_incremental.return_value = {
        "should_block": True, "matched": chain, "exfil": [flow] if exfil else [],
    }
    monkeypatch.setattr(routes, "_chain_state_for_agent", lambda agent_id: state)
    counter = Mock()
    monkeypatch.setattr(metrics, "ANALYZE_TOTAL", counter)
    reported = Event()
    audit = Mock(side_effect=lambda **fields: reported.set())
    monkeypatch.setitem(
        sys.modules, "agent_moss.infra.actrail", SimpleNamespace(report_enforcement_event=audit),
    )

    with TestClient(create_app()) as client:
        response = client.post("/api/v1/analyze", json={
            "session_id": "sample", "a_next": {"action_type": "fixture", "action_detail": "sample"},
            "metadata": {"stateful_incremental": True},
        })
        assert reported.wait(timeout=2)
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "Deny"
    assert body["risk_level"] == expected_risk
    assert body["reason"] == expected_reason
    assert body["l3_outcome"] == expected_outcome
    if budget_skipped:
        assert body["degraded"] == degraded
    assert body["violated_layers"] == prior_layers + ["L2.2-stateful"]
    assert body["risk_type"] == ("engine" if expected_reason == "engine" else "formal_verification")
    assert body["confidence"] == (76 if expected_reason == "engine" else 90)
    assert body["policy"] == ""
    assert body["violation_graph"]["property_id"] == ("flow" if exfil else "chain")
    counter.inc.assert_called_once_with(
        decision="Deny", risk_level=expected_risk, l3_outcome=expected_outcome,
    )
    assert audit.call_args.kwargs["decision"] == "deny"
    for field in ("risk_level", "risk_type", "reason", "confidence", "violated_layers"):
        assert audit.call_args.kwargs[field] == body[field]


@pytest.mark.parametrize("static_wins", [True, False], ids=["static-tie", "incremental-higher"])
@pytest.mark.parametrize("detail_mode", ["redacted", "full"])
def test_analyze_redacts_selected_flow_across_sessions(monkeypatch, static_wins, detail_mode):
    from agent_moss.engine import analyzer
    from agent_moss.server import routes

    monkeypatch.setenv("AGENT_MOSS_CHAIN_DETAIL", detail_mode)
    sid, command, resource = "private-session", "private-note", "/records/private"
    raw_reason = f"敏感数据传播外传：{sid}#0 访问 {resource} → mine#2 经共享载体外发"

    def finding(marker, static):
        nodes = [
            {"session_id": sid, "seq": 0, "instance_id": "other", "action_detail": command, "resources": [resource]},
            {"session_id": "sibling", "seq": 1, "instance_id": "here", "action_detail": marker, "resources": []},
            {"session_id": "mine", "seq": 2, "instance_id": "", "action_detail": "own note", "resources": []},
        ]
        path = [[n["session_id"], n["seq"], n["action_detail"]] for n in nodes]
        if not static:
            path = [step + ["", "agent", n["instance_id"]] for step, n in zip(path, nodes)]
        return {
            "property_id": "sensitive-data-flow", "risk_level": "critical", "reason": raw_reason,
            "path": path, "graph": {
                "property_id": "sensitive-data-flow", "nodes": nodes,
                "edges": [{"from": 0, "to": 1, "type": "data", "label": resource},
                          {"from": 1, "to": 2, "type": "data", "label": "visible label"}],
                "property_expression": [{"token": "CRED", "node_index": 0}],
            },
        }

    static = finding("static evidence", static=True)
    flow = finding("incremental evidence", static=False)
    if not static_wins:
        static["graph"]["property_id"] = "cross-sample"
        static["reason"] = "组合链"
    result = {
        "decision": "Deny", "source": "formal_engine", "risk_type": "formal_verification",
        "risk_level": "critical" if static_wins else "high", "reason": static["reason"],
        "violated_policy": f"[formal_verification] {static['reason']}", "violated_layers": ["L2.2"],
        "violation_chain": static["path"], "violation_graph": static["graph"],
    }
    monkeypatch.setattr(analyzer, "analyze", Mock(return_value=result))
    state = Mock()
    state.apply_incremental.return_value = {
        "should_block": True, "matched": {"reason": "组合链", "risk_level": "high"}, "exfil": [flow],
    }
    monkeypatch.setattr(routes, "_chain_state_for_agent", lambda agent_id: state)
    reported = Event()
    audit = Mock(side_effect=lambda **fields: reported.set())
    monkeypatch.setitem(sys.modules, "agent_moss.infra.actrail", SimpleNamespace(report_enforcement_event=audit))

    with TestClient(create_app()) as client:
        response = client.post("/api/v1/analyze", json={
            "session_id": "mine", "instance_id": "here",
            "a_next": {"action_type": "fixture", "action_detail": "own note"},
            "metadata": {"stateful_incremental": True},
        })
        assert response.status_code == 200, response.text
        assert reported.wait(timeout=2)
    body = response.json()
    graph = body["violation_graph"]
    marker = "static evidence" if static_wins else "incremental evidence"
    assert body["violation_chain"][1][2] == graph["nodes"][1]["action_detail"] == marker
    assert body["violation_chain"][2][2] == graph["nodes"][2]["action_detail"] == "own note"
    assert graph["edges"][1]["label"] == "visible label"
    assert graph["property_expression"] == [{"token": "CRED", "node_index": 0}]
    assert body["violated_policy"] == f"[formal_verification] {body['reason']}"
    assert audit.call_args.kwargs["reason"] == body["reason"]
    if detail_mode == "redacted":
        for private in (sid, command, resource):
            assert private not in response.text
        assert graph["edges"][0]["label"] == ""
        assert "<other-session>#0" in body["reason"]
    else:
        assert body["reason"] == raw_reason
        assert body["violation_chain"][0][2] == command
        assert graph["edges"][0]["label"] == resource


@pytest.mark.parametrize(("risk", "use_incremental_graph"), [("high", True), ("critical", False)])
def test_analyze_supplements_path_only_static_denial_on_equal_risk(monkeypatch, risk, use_incremental_graph):
    from agent_moss.engine import analyzer
    from agent_moss.server import routes

    monkeypatch.setenv("AGENT_MOSS_CHAIN_DETAIL", "redacted")
    static_chain = [["current", 1, "static note"]]
    monkeypatch.setattr(analyzer, "analyze", Mock(return_value={
        "decision": "Deny", "source": "formal_engine", "risk_level": risk, "risk_type": "formal_verification",
        "reason": "static rule", "violated_policy": "[formal_verification] static rule", "violated_layers": ["L2.2"],
        "violation_chain": static_chain, "violation_graph": None,
    }))
    path = [["current", 5, "foreign note"], ["mine", 7, "local note"]]
    graph = {
        "property_id": "sensitive-data-flow",
        "nodes": [{"session_id": sid, "seq": seq, "action_detail": detail} for sid, seq, detail in path],
        "edges": [{"from": 0, "to": 1, "type": "data", "label": "foreign resource"}],
    }
    state = Mock()
    state.apply_incremental.return_value = {
        "should_block": True, "matched": None,
        "exfil": [{"property_id": graph["property_id"], "risk_level": "high", "reason": "incremental rule",
                   "path": path, "graph": graph}],
    }
    monkeypatch.setattr(routes, "_chain_state_for_agent", lambda agent_id: state)

    with TestClient(create_app()) as client:
        response = client.post("/api/v1/analyze", json={
            "session_id": "mine", "a_next": {"action_type": "fixture", "action_detail": "local note"},
            "metadata": {"stateful_incremental": True},
        })
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "Deny"
    assert body["risk_level"] == risk
    assert body["reason"] == "static rule"
    assert body["violated_policy"] == "[formal_verification] static rule"
    assert body["violated_layers"] == ["L2.2", "L2.2-stateful"]
    if use_incremental_graph:
        visible_graph = body["violation_graph"]
        assert visible_graph["property_id"] == graph["property_id"]
        assert body["violation_chain"] == [["<other-session>", 5, "<已隐藏>", ""], path[1]]
        assert [node["action_detail"] for node in visible_graph["nodes"]] == ["<已隐藏>", "local note"]
        assert visible_graph["edges"][0]["label"] == ""
    else:
        assert body["violation_graph"] is None
        assert body["violation_chain"] == static_chain


@pytest.mark.parametrize(("incremental", "historical_current", "session_id", "visible"), [
    (False, False, "actual-session", True),
    (False, True, "actual-session", False),
    (False, True, "current", False),
    (True, False, "actual-session", False),
])
def test_legacy_current_alias_only_identifies_unambiguous_static_nodes(
    monkeypatch, incremental, historical_current, session_id, visible,
):
    from agent_moss.server.routes import _public_formal_result

    monkeypatch.setenv("AGENT_MOSS_CHAIN_DETAIL", "redacted")
    graph = {"nodes": [{"session_id": "current", "seq": 3, "action_detail": "sample"}]}
    chain = [["current", 3, "sample"]]
    base = {"decision": "Deny", "risk_level": "high", "violation_chain": chain, "violation_graph": graph}
    finding = {"risk_level": "critical", "path": chain, "graph": graph} if incremental else None
    history = [{"session_id": "current"}] if historical_current else []
    result = _public_formal_result(base, finding, "", session_id, history)
    detail = "sample" if visible else "<已隐藏>"
    assert result["violation_chain"][0][2] == detail
    assert result["violation_graph"]["nodes"][0]["action_detail"] == detail


def test_static_chain_does_not_inherit_visibility_from_different_command(monkeypatch):
    from agent_moss.infra import security_policy as sp

    monkeypatch.setenv("AGENT_MOSS_CHAIN_DETAIL", "redacted")
    graph = {"nodes": [{"session_id": "same", "seq": 0, "instance_id": "here", "action_detail": "own"}]}
    assert sp.redact_chain([["same", 0, "foreign"]], "here", "same", graph=graph) == [
        ["<other-session>", 0, "<已隐藏>", ""],
    ]


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

def test_chain_state_auto_rotate_keeps_recent_and_archives_old(tmp_path, monkeypatch):
    """到达节点上限时自动归档旧节点、保留最近窗口，不再丢新动作。"""
    import gzip
    import json
    from agent_moss.engine.formal_engine import stateful

    monkeypatch.setattr(stateful, "_MAX_NODES", 10)
    monkeypatch.setenv("AGENT_MOSS_CHAIN_RETAIN_NODES", "4")
    archive_dir = tmp_path / "archive"
    monkeypatch.setenv("AGENT_MOSS_CHAIN_ARCHIVE_DIR", str(archive_dir))
    db_path = str(tmp_path / "state.db")

    store = ChainStateStore(db_path)
    try:
        # 前 10 条填满；第 11 条触发轮转 → 保留最近 4 条，再追加 1 条 = 5 条
        for i in range(11):
            store.apply_action(
                "agent-rotate",
                {"action_type": "execute", "action_detail": f"echo rotate-{i}"},
                f"s-{i}",
            )
        store.flush()
        assert len(store.load("agent-rotate").nodes) == 5
    finally:
        store.close()

    files = list(archive_dir.glob("*.jsonl.gz"))
    assert len(files) == 1
    lines = gzip.decompress(files[0].read_bytes()).decode("utf-8").strip().split("\n")
    assert len(lines) == 6
    assert json.loads(lines[0])["action_detail"] == "echo rotate-0"

    # 重启后仍然只有保留窗口，不会把归档旧节点重新加载
    store2 = ChainStateStore(db_path)
    try:
        tracker = store2.load("agent-rotate")
        assert tracker is not None
        assert len(tracker.nodes) == 5
        assert tracker.nodes[-1].action_detail == "echo rotate-10"
    finally:
        store2.close()


def test_fingerprint_normalizes_time_alias_and_truncation():
    """旧审计兼容键归一实时小数秒、工具别名和落库截断。"""
    from agent_moss.engine.formal_engine.stateful import _legacy_audit_fingerprint

    full = "echo " + "x" * 100
    truncated = full[:20] + "…[truncated 84B sha256:" + hashlib.sha256(
        full.encode()
    ).hexdigest()[:16] + "]"

    realtime = _legacy_audit_fingerprint(
        "s", "executeBash", full, "2026-11-23T12:00:00.123456789Z",
    )
    review = _legacy_audit_fingerprint(
        "s", "terminal-executeBash", truncated, "2026-11-23 12:00:00",
    )
    assert realtime == review


@pytest.mark.parametrize("restore_format", [None, "exact", "normalized"])
def test_seed_skips_same_action_across_time_precision_and_alias(restore_format):
    """旧 Gate 的同一次调用在回顾时能找到原始节点。"""
    from agent_moss.engine.formal_engine.stateful import StatefulChainTracker, _legacy_audit_fingerprint

    tracker = StatefulChainTracker(agent_id="dedupe")
    first = {"session_id": "s", "action_history": [{
        "action_type": "executeBash", "action_detail": "echo hi",
        "called_at": "2026-11-23T12:00:00.999999+00:00",
    }]}
    second = {"session_id": "s", "action_history": [{
        "action_type": "terminal-executeBash", "action_detail": "echo hi",
        "called_at": "2026-11-23 12:00:00",
    }]}
    assert tracker.seed([first]) == 1
    if restore_format is not None:
        snapshot = tracker.to_snapshot()
        if restore_format == "normalized":
            node = snapshot["nodes"][0]
            node.pop("legacy_fingerprint")
            snapshot["seeded_keys"] = [_legacy_audit_fingerprint(
                "s", node["action_type"], node["action_detail"], node["timestamp"],
            )]
        tracker = StatefulChainTracker(agent_id="dedupe")
        tracker.restore(snapshot)
        assert "unmapped_legacy_keys" not in tracker.to_snapshot()
    assert tracker.seed([second]) == 0
    assert len(tracker.nodes) == 1


def test_legacy_audit_does_not_merge_multiple_calls_in_the_same_second():
    from agent_moss.engine.formal_engine.stateful import StatefulChainTracker

    tracker = StatefulChainTracker(agent_id="dedupe")
    action = {"action_type": "executeBash", "action_detail": "echo hi"}
    for fraction in ("1", "2"):
        tracker.advance({**action, "called_at": f"2026-11-23T12:00:00.{fraction}Z"}, session_id="s")
    review = {**action, "action_type": "terminal-executeBash", "called_at": "2026-11-23 12:00:00"}
    sessions = [{"session_id": "s", "action_history": [review]}]

    assert tracker.seed(sessions) == 1
    assert tracker.seed(sessions) == 0
    assert len(tracker.nodes) == 3
