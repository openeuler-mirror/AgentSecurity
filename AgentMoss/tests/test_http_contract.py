"""HTTP 契约看护 —— 安全加固不允许改坏对外字段。

安全改造（2026-10）动了路由层（来源校验、鉴权、脱敏、限额）。这份测试锁住
**响应契约本身**：字段名、类型、必需项都不能变，否则 opendesk / xiaoO / AgentGate
这些调用方会在升级后解析失败。

"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from agent_moss.server.app import create_app


@pytest.fixture
def client(monkeypatch, tmp_path):
    for name in ("AGENT_MOSS_ORIGIN_CHECK", "AGENT_MOSS_AUTH_TOKEN",
                 "AGENT_MOSS_AGENT_TOKENS", "AGENT_MOSS_CHAIN_DETAIL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AGENT_MOSS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_MOSS_DISABLE_LLM", "1")
    return TestClient(create_app())


ANALYZE_FIELDS = {
    "decision": str,
    "reason": str,
    "risk_level": str,
    "risk_type": str,
    "violated_layers": list,
    "policy": str,
    "violated_policy": str,
    "confidence": int,
    "analysis_duration_ms": (int, float),
    "violation_chain": list,
}


def test_analyze_response_schema(client):
    r = client.post("/api/v1/analyze", json={
        "session_id": "contract-1",
        "prompt_session": "",
        "prompt_history": [],
        "action_history": [],
        "session_history": [],
        "a_next": {"action_type": "bash", "action_detail": "ls -l /tmp"},
        "reason": "",
        "os_type": "linux",
        "cwd": "/tmp",
        "agent_id": "",
        "metadata": {},
    })
    assert r.status_code == 200
    body = r.json()
    for field, typ in ANALYZE_FIELDS.items():
        assert field in body, f"响应缺少字段: {field}"
        assert isinstance(body[field], typ), f"{field} 类型变了: {type(body[field])}"
    assert body["decision"] in ("Allow", "Deny")


def test_deny_response_schema(client):
    r = client.post("/api/v1/analyze", json={
        "session_id": "contract-2",
        "a_next": {"action_type": "bash", "action_detail": "rm -rf /"},
        "os_type": "linux",
    })
    body = r.json()
    assert body["decision"] == "Deny"
    assert body["risk_level"] == "critical"
    assert body["violated_policy"]


def test_health_schema(client):
    body = client.get("/api/v1/health").json()
    for field in ("status", "version", "instance"):
        assert field in body


def test_unknown_fields_do_not_break(client):
    """调用方多传字段不应报错（向后兼容）。"""
    r = client.post("/api/v1/analyze", json={
        "session_id": "contract-3",
        "a_next": {"action_type": "bash", "action_detail": "ls"},
        "future_field": {"x": 1},
    })
    assert r.status_code == 200


def test_console_config_schema(client):
    """/console/api/config 的顶层键不能少（前端按这些键渲染）。"""
    body = client.get("/console/api/config").json()
    for key in ("version", "layers", "L1_rules", "L2_rules", "L3_skills"):
        assert key in body, f"config 缺少 {key}"


def test_console_rules_schema(client):
    body = client.get("/console/api/rules").json()
    assert "L1_rules" in body


def test_documented_integration_payload(client):
    """完整示例必须原样可用。

    这是三个集成（openDesk / xiaoO / AgentGate）最可能照着写的形状：
    显式 os_type、prompt_history、metadata.llm_config / llm_log_path 都在。
    """
    payload = {
        "session_id": "agent-sandbox-001",
        "prompt_session": "继续",
        "prompt_history": [
            {"text": "请帮我读取分析 src/app.ts",
             "actions": [{"action_type": "read", "action_detail": "cat src/app.ts"}]},
            {"text": "请帮我为 src/ 补写单元测试", "actions": []},
            {"text": "继续", "actions": []},
        ],
        "action_history": [{"action_type": "read", "action_detail": "cat src/app.ts"}],
        "a_next": {"action_type": "bash", "action_detail": "rm /home/me/src/app.ts"},
        "reason": "清理文件",
        "os_type": "linux",
        "cwd": "/home/me",
        "agent_id": "xiaoo",
        "metadata": {
            # 故意给一个不可达的 baseUrl：校验只做协议/地址判断，不会发请求
            "llm_config": {"baseUrl": "https://api.example.com/v1", "apiKey": "", "model": "x"},
            "llm_log_path": "/tmp/agentmoss.log",
        },
    }
    r = client.post("/api/v1/analyze", json=payload)
    assert r.status_code == 200, r.text
    body = r.json()
    for field in ANALYZE_FIELDS:
        assert field in body
    assert body["decision"] in ("Allow", "Deny")
