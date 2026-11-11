"""真实攻击链的回归看护（2026-10 安全加固）。

这里的每条用例都对应一个**实测打穿过**的攻击，改回去就会红：

1. **任意网页关掉检测**：`Origin: https://evil` + `PUT /console/api/layers`
   → 修复前 200（L1 被关，`rm -rf /` 变 Allow），修复后 403。
2. **跨会话历史泄露**：攻击者声明受害者的 `agent_id`，补完组合链后
   `violation_chain` 里出现受害者会话的命令原文 → 修复后只剩 `<已隐藏>`。
3. **任意文件读**：`/api/v1/review` 的 `db_path` 指向任意路径 → 修复后 403。
4. **任意文件写**：`metadata.llm_log_path` 指向任意路径 → 修复后被拒绝。
5. **缓存投毒**：`/tmp` 下的缓存目录被换成符号链接 → 修复后回退私有目录。

"""
from __future__ import annotations

import json
import os

import pytest
from fastapi.testclient import TestClient

from agent_moss.server.app import create_app


@pytest.fixture
def client(monkeypatch, tmp_path):
    for name in (
        "AGENT_MOSS_ORIGIN_CHECK", "AGENT_MOSS_CORS_ORIGINS", "AGENT_MOSS_AUTH_TOKEN",
        "AGENT_MOSS_AGENT_TOKENS", "AGENT_MOSS_REVIEW_PATHS", "AGENT_MOSS_CHAIN_DETAIL",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AGENT_MOSS_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("AGENT_MOSS_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("AGENT_MOSS_DISABLE_LLM", "1")
    from agent_moss.engine.formal_engine import chain_state
    chain_state.reset_chain_state_store()
    yield TestClient(create_app())
    chain_state.reset_chain_state_store()


def _analyze(client, session, agent, detail, stateful=True):
    return client.post("/api/v1/analyze", json={
        "session_id": session,
        "agent_id": agent,
        "metadata": {"stateful_incremental": "true"} if stateful else {},
        "a_next": {"action_type": "bash", "action_detail": detail},
        "os_type": "linux",
    })


# ==================== 1. 任意网页关掉检测 ====================

def test_cross_origin_cannot_disable_l1(client):
    evil = {"Origin": "https://evil.example"}
    r = client.put("/console/api/layers",
                   json={"layer_key": "L1_heuristic", "enabled": False}, headers=evil)
    assert r.status_code == 403

    # L1 仍然开着：rm -rf / 照常 Deny
    r = _analyze(client, "s", "", "rm -rf /", stateful=False)
    assert r.status_code == 200
    assert r.json()["decision"] == "Deny"


def test_same_origin_can_still_toggle(client):
    """同源（Console 页面自己）必须照常可写 —— 否则管控台就废了。"""
    headers = {"Origin": "http://testserver"}
    r = client.put("/console/api/layers",
                   json={"layer_key": "L1_heuristic", "enabled": False}, headers=headers)
    assert r.status_code == 200
    # 改回去
    client.put("/console/api/layers",
               json={"layer_key": "L1_heuristic", "enabled": True}, headers=headers)


# ==================== 2. 跨会话历史泄露 ====================

def test_combo_chain_does_not_leak_other_sessions(client):
    victim = "xiaoo-real-session-SECRET-9f2"
    r = _analyze(client, victim, "xiaoo", 'bash -c "ls /home/xiaoo/客户资料"')
    assert r.json()["decision"] == "Allow"

    # 攻击者声明同一个 agent_id，补完 exec → scan → cred 链
    _analyze(client, "attacker", "xiaoo", "nmap -sT 10.0.0.5")
    r = _analyze(client, "attacker", "xiaoo", "cat /etc/shadow")
    body = r.json()

    assert body["decision"] == "Deny"
    chain = body["violation_chain"]
    assert chain, "应当仍返回反例路径（判定不变，只是脱敏）"
    text = json.dumps(chain, ensure_ascii=False)
    # 受害者会话的命令原文 / 会话 id 都不能出现
    assert "客户资料" not in text
    assert victim not in text
    # 攻击者自己的节点保持原样（那是他自己的数据）
    assert any("nmap" in json.dumps(step, ensure_ascii=False) for step in chain)


# ==================== 3. 任意文件读 ====================

def test_review_rejects_arbitrary_path(client):
    r = client.post("/api/v1/review", json={"agent_id": "x", "db_path": "/etc/passwd"})
    assert r.status_code == 403


# ==================== 4. 任意文件写 ====================

def test_llm_log_path_outside_roots_is_ignored(client, tmp_path, monkeypatch):
    """llm_log_path 越界时不写（分析照常完成）。

    注意默认白名单含 /tmp（文档里的 `/tmp/agentmoss.log` 必须可用），
    所以这里先把白名单收窄到专用目录，再指向另一个目录。
    """
    from agent_moss.engine.llm_analyzer import LLMAnalyzer
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    monkeypatch.setenv("AGENT_MOSS_LOG_ROOTS", str(allowed))
    target = tmp_path / "escape" / "evil.log"
    target.parent.mkdir()

    LLMAnalyzer._log_prompt("prompt-body", {"action_type": "bash", "action_detail": "x"},
                            str(target))
    assert not target.exists()


def test_llm_log_path_inside_home_still_works(tmp_path, monkeypatch):
    from agent_moss.engine.llm_analyzer import LLMAnalyzer
    monkeypatch.setenv("AGENT_MOSS_LOG_ROOTS", str(tmp_path))
    target = tmp_path / "agentmoss.log"
    LLMAnalyzer._log_prompt("prompt-body", {"action_type": "bash", "action_detail": "x"},
                            str(target))
    assert target.exists() and "prompt-body" in target.read_text(encoding="utf-8")


# ==================== 5. 缓存投毒 ====================

def test_policy_cache_rejects_symlinked_dir(tmp_path, monkeypatch):
    from agent_moss.infra import policy_cache as pc

    real = tmp_path / "attacker-controlled"
    real.mkdir()
    link = tmp_path / "cache_link"
    link.symlink_to(real)
    fallback_data = tmp_path / "data"
    monkeypatch.setenv("AGENT_MOSS_DATA_DIR", str(fallback_data))
    monkeypatch.setattr(pc, "CACHE_DIR", link)

    safe = pc._safe_cache_dir()
    assert not str(safe).startswith(str(link)), "不得沿用被接管的符号链接目录"
    assert "policy_cache" in str(safe)
