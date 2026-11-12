"""`AGENT_MOSS_DISABLE_CACHE` 开关测试（2026-10 招行客户反馈）。

背景：招行客户反馈「运行后 /tmp 下会有 agent_moss 目录」。除了 ``/tmp/agent_moss/``
（策略文件，``AGENT_MOSS_SAVE_POLICY=0`` 关闭，见 test_policy_save.py），还有
``{临时目录}/agent_moss_policy_cache/``（**判定结果缓存**，默认开启，按 session_id
建子目录）——同样是给执行侧沙箱用的产物，只做判定、不做沙箱隔离的部署不需要，
且代码调用 + 唯一 session_id 时会按会话堆积目录。

``AGENT_MOSS_DISABLE_CACHE=1`` 关闭它：只影响**文件落盘与缓存读写**，
``analyze()`` 的判定结果（decision）不变。等价于 config.json 的
``"cache": {"enabled": false}``，env 优先（客户沙箱不方便手编配置文件）。

看护：默认开启（对照）→ env=1 关闭 → 缓存目录不再产生 → 判定结果不变。
"""
from __future__ import annotations

import pytest

from agent_moss.infra import policy_cache as pc_mod
from agent_moss.infra.config import CacheConfig, load_config
from agent_moss.infra.policy_cache import PolicyCache


@pytest.fixture(autouse=True)
def _disable_llm(monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_DISABLE_LLM", "1")
    monkeypatch.delenv("AGENT_MOSS_DISABLE_CACHE", raising=False)


def test_cache_enabled_by_default(monkeypatch):
    """对照：不设 env 时缓存默认开启（保持既有部署行为不变）。"""
    monkeypatch.delenv("AGENT_MOSS_DISABLE_CACHE", raising=False)
    assert load_config().cache.enabled is True


def test_disable_cache_env_turns_it_off(monkeypatch):
    """AGENT_MOSS_DISABLE_CACHE=1 → cache.enabled False。"""
    monkeypatch.setenv("AGENT_MOSS_DISABLE_CACHE", "1")
    assert load_config().cache.enabled is False


def test_disable_cache_env_other_values_ignored(monkeypatch):
    """只有 "1" 才是关闭（其余值按默认开启，与 DISABLE_* 家族语义一致）。"""
    for val in ("0", "true", ""):
        monkeypatch.setenv("AGENT_MOSS_DISABLE_CACHE", val)
        assert load_config().cache.enabled is True, f"值 {val!r} 不应关闭缓存"


def test_disabled_cache_does_not_write_dir(tmp_path, monkeypatch):
    """关闭后 save() 不落盘、不建目录（CACHE_DIR 重定向到临时目录验证）。"""
    cache_dir = tmp_path / "policy_cache"
    monkeypatch.setattr(pc_mod, "CACHE_DIR", cache_dir)
    cache = PolicyCache(CacheConfig(enabled=False))
    cache.put("sess-1", "", "policy-content")
    assert not cache_dir.exists(), "关闭缓存后不应创建缓存目录"
    # 读也不命中（不会读到别的会话的旧内容）
    assert cache.get("sess-1", "") is None


def test_enabled_cache_writes_dir(tmp_path, monkeypatch):
    """对照：开启时正常落盘（确认测试手法有效，不是恒空断言）。"""
    cache_dir = tmp_path / "policy_cache"
    monkeypatch.setattr(pc_mod, "CACHE_DIR", cache_dir)
    cache = PolicyCache(CacheConfig(enabled=True))
    cache.put("sess-1", "", "policy-content")
    assert (cache_dir / "sess-1").is_dir(), "开启时应有会话目录"
    assert cache.get("sess-1", "") == "policy-content"


def test_analyze_decision_unchanged_with_cache_disabled(tmp_path, monkeypatch):
    """端到端：关缓存后判定结果不变（Allow/Deny 与开启时一致）。"""
    from agent_moss.engine import analyzer as analyzer_mod
    from agent_moss.engine.analyzer import analyze
    from agent_moss.profiles import get_profile

    cache_dir = tmp_path / "policy_cache"
    monkeypatch.setattr(pc_mod, "CACHE_DIR", cache_dir)
    # Policy 落盘目录也重定向（另一条 /tmp 产物，与本测试无关但别污染）
    monkeypatch.setattr(analyzer_mod, "POLICY_OUTPUT_DIR", tmp_path / "policy_out")
    monkeypatch.setenv("AGENT_MOSS_DISABLE_CACHE", "1")
    disabled = PolicyCache(load_config().cache)
    monkeypatch.setattr(analyzer_mod, "get_default_cache", lambda: disabled)

    def _run(cmd: str) -> str:
        return analyze(
            session_id="cache-off",
            prompt_session="",
            action_history=[],
            a_next={"action_type": "bash", "action_detail": cmd},
            reason="",
            profile=get_profile("linux"),
        )["decision"]

    assert _run("ls -la") == "Allow"          # 一放
    assert _run("rm -rf /") == "Deny"         # 一拦
    assert not cache_dir.exists(), "关缓存后 analyze 不应产生缓存目录"
