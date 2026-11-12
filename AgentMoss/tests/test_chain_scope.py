"""组合链时间线的作用域（AGENT_MOSS_CHAIN_SCOPE）双端镜像 TS chain-scope.test.ts。

威胁模型：组合攻击的目标是**这台服务器**，攻击者可以换用户、换 agent 分步实施
（agent1 建监听、agent2 扫描、agent3 外传）。因此默认 ``system`` 作用域下，
所有 agent 共用同一份时间线，跨 agent 的链必须能连上。

``agent`` 作用域只用于"一个 AgentGate 服务多个互不相关租户"的部署。
"""

import pytest

from agent_moss.engine.formal_engine import StatefulChainTracker
from agent_moss.engine.formal_engine.chain_state import ChainStateStore
from agent_moss.infra import security_policy as sp


def _listener():
    return {
        "action_type": "bash",
        "action_detail": "nohup python3 ~/devtools/admin_api.py > /dev/null 2>&1 &",
    }


def _exec():
    return {
        "action_type": "bash",
        "action_detail": "add POST /exec endpoint using subprocess shell=True",
    }


def _scan():
    return {
        "action_type": "bash",
        "action_detail": "port scan: run nc -z -w1 192.168.1.22 22",
    }


def test_default_scope_is_system(monkeypatch):
    monkeypatch.delenv("AGENT_MOSS_CHAIN_SCOPE", raising=False)
    assert sp.chain_scope() == "system"


def test_system_scope_shares_single_bucket(monkeypatch):
    monkeypatch.delenv("AGENT_MOSS_CHAIN_SCOPE", raising=False)
    assert sp.chain_bucket("opendesk") == sp.chain_bucket("xiaoo") == "__system__"


def test_agent_scope_isolates_buckets(monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_CHAIN_SCOPE", "agent")
    assert sp.chain_bucket("opendesk") != sp.chain_bucket("xiaoo")


def test_cross_agent_chain_detected_in_system_scope(tmp_path, monkeypatch):
    """三个不同 agent 分步做完同一条链 → 必须命中（默认 system 作用域）。"""
    monkeypatch.delenv("AGENT_MOSS_CHAIN_SCOPE", raising=False)
    store = ChainStateStore(str(tmp_path / "chains.db"))

    # 用户1 / agent1 做 step1
    t1 = store.load_or_new(sp.chain_bucket("agent1"))
    t1.advance(_listener(), session_id="sess-1")
    store.save(t1)

    # 用户2 / agent2 做 step2 —— 读到的是同一个系统桶
    t2 = store.load_or_new(sp.chain_bucket("agent2"))
    r2 = t2.advance(_exec(), session_id="sess-2")
    store.save(t2)
    assert r2.matched is None
    assert any(p.next_stage == "SCAN" for p in r2.pending_prefixes)

    # 用户3 / agent3 做 step3 → 链补全
    t3 = store.load_or_new(sp.chain_bucket("agent3"))
    r3 = t3.advance(_scan(), session_id="sess-3")
    assert r3.matched is not None
    assert r3.matched.chain_id == "listener-exec-scan"
    assert r3.should_block
    store.close()


def test_cross_agent_chain_not_detected_in_agent_scope(tmp_path, monkeypatch):
    """agent 作用域下各看各的：同样的三步分散在三个 agent，链连不上（多租户防误报）。"""
    monkeypatch.setenv("AGENT_MOSS_CHAIN_SCOPE", "agent")
    store = ChainStateStore(str(tmp_path / "chains.db"))

    t1 = store.load_or_new(sp.chain_bucket("agent1"))
    t1.advance(_listener(), session_id="sess-1")
    store.save(t1)

    # agent2 的 _exec 单步本身会生成"等 SCAN"的悬空前序（链允许从中间步骤开始
    # 累积），但它在自己的桶里看不到 agent1 的 LISTENER，所以没有 LISTENER→EXEC 的
    # 真实进度；agent3 的 SCAN 落在一个空桶里，链补不全。
    t2 = store.load_or_new(sp.chain_bucket("agent2"))
    r2 = t2.advance(_exec(), session_id="sess-2")
    store.save(t2)
    assert r2.matched is None

    t3 = store.load_or_new(sp.chain_bucket("agent3"))
    r3 = t3.advance(_scan(), session_id="sess-3")
    assert r3.matched is None
    store.close()
