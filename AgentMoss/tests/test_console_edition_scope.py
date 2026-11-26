"""Console 交付范围过滤：edition_scope 同时控制引擎加载与 Console 展示。"""

import pytest
from fastapi import HTTPException

from agent_moss.console import router
from agent_moss.infra import edition_scope


def test_get_agents_filters_by_scope(monkeypatch):
    monkeypatch.setattr(edition_scope, "_load_scope", lambda: {
        "agents": ["clawpartner"], "scenarios": ["cloud"],
    })
    monkeypatch.setattr(router, "_runtime_for_view", lambda: {})
    monkeypatch.setattr(router, "get_agent_rules", lambda _runtime: {
        "clawpartner": {"description": "allowed"},
        "xiaoo": {"description": "blocked"},
        "opendesk": {"description": "blocked"},
    })

    assert list(router.get_agents()["agents"]) == ["clawpartner"]


def test_get_scenarios_filters_scope_and_env(monkeypatch):
    monkeypatch.setattr(edition_scope, "_load_scope", lambda: {
        "agents": ["clawpartner"], "scenarios": ["cloud"],
    })
    monkeypatch.setattr(router, "_runtime_for_view", lambda: {})
    monkeypatch.setattr(router, "get_scenario_rules", lambda _runtime: {
        "cloud": {"description": "allowed"},
        "bank": {"description": "blocked"},
    })
    monkeypatch.setattr(router, "_enabled_scenario_ids", lambda: ["cloud", "bank"])

    result = router.get_scenarios()
    assert result["enabled"] == ["cloud"]
    assert list(result["scenarios"]) == ["cloud"]


def test_scope_is_not_enforced_when_file_absent(monkeypatch):
    monkeypatch.setattr(edition_scope, "_load_scope", lambda: None)
    monkeypatch.setattr(router, "_runtime_for_view", lambda: {})
    monkeypatch.setattr(router, "get_agent_rules", lambda _runtime: {
        "clawpartner": {}, "xiaoo": {},
    })

    assert set(router.get_agents()["agents"]) == {"clawpartner", "xiaoo"}


@pytest.mark.parametrize(("kind", "ident", "allowed"), [
    ("agents", "clawpartner", True),
    ("agents", "xiaoo", False),
    ("scenarios", "cloud", True),
    ("scenarios", "bank", False),
])
def test_console_mutation_guard(monkeypatch, kind, ident, allowed):
    monkeypatch.setattr(edition_scope, "_load_scope", lambda: {
        "agents": ["clawpartner"], "scenarios": ["cloud"],
    })
    ensure = router._ensure_agent_in_scope if kind == "agents" else router._ensure_scenario_in_scope
    if allowed:
        ensure(ident)
    else:
        with pytest.raises(HTTPException) as err:
            ensure(ident)
        assert err.value.status_code == 404
