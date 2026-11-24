"""场景包交付范围白名单（edition_scope.json）测试。"""

from __future__ import annotations

import json

import pytest

from agent_moss.infra import edition_scope
from agent_moss.infra.paths import ENV_RULES_ROOT


@pytest.fixture
def rules_root(tmp_path, monkeypatch):
    root = tmp_path / "rulesroot"
    (root / "agents" / "xiaoo").mkdir(parents=True)
    (root / "scenarios" / "bank").mkdir(parents=True)
    (root / "agents" / "xiaoo" / "rules.json").write_text(json.dumps({
        "agent_id": "xiaoo",
        "description": "test",
        "extra_command_patterns": [],
        "extra_injection_keywords": [],
        "extra_sensitive_paths": [],
    }), encoding="utf-8")
    (root / "scenarios" / "bank" / "rules.json").write_text(json.dumps({
        "scenario_id": "bank",
        "description": "test",
        "extra_command_patterns": [],
        "extra_injection_keywords": [],
        "extra_sensitive_paths": [],
    }), encoding="utf-8")
    monkeypatch.setenv(ENV_RULES_ROOT, str(root))
    _clear_caches()
    yield root
    _clear_caches()


def _clear_caches() -> None:
    from agent_moss.agents import _cache as agent_cache
    from agent_moss.scenarios import _cache as scenario_cache

    agent_cache.clear()
    scenario_cache.clear()
    edition_scope._cache_key = None
    edition_scope._cache_data = None


def test_without_scope_file_all_ids_allowed(rules_root):
    from agent_moss.agents import get_agent_extensions
    from agent_moss.scenarios import get_scenario_extensions

    assert get_agent_extensions("xiaoo") is not None
    assert get_scenario_extensions("bank") is not None
    assert get_agent_extensions("opendesk") is None


def test_scope_file_filters_agents_and_scenarios(rules_root):
    (rules_root / "edition_scope.json").write_text(
        json.dumps({"agents": ["xiaoo"], "scenarios": []}),
        encoding="utf-8",
    )
    _clear_caches()
    from agent_moss.agents import get_agent_extensions
    from agent_moss.scenarios import get_scenario_extensions

    assert get_agent_extensions("xiaoo") is not None
    assert get_agent_extensions("opendesk") is None
    # 即使 rules.json 还在，范围外场景也不能加载
    assert get_scenario_extensions("bank") is None
