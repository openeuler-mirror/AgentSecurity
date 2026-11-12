"""cold（冷启动）规则来源模式回归测试。

cold 与 builtin 的区别：
- builtin：连规则目录 / CUSTOM_RULES 都不读；
- cold：启动时读内置规则 + 规则目录 + CUSTOM_RULES + 场景，之后冻结；
  runtime JSON / Console 完全不参与。
"""
from __future__ import annotations

import json

import pytest

from agent_moss.infra import rules_mode
from agent_moss.infra import runtime_config as rc

_REAL_HAS_RUNTIME_CONFIG = rc.has_runtime_config


def _reset_caches() -> None:
    rules_mode.reset_cache()
    rc._RUNTIME_CONFIG_CACHE.clear()
    rc._HAS_RUNTIME_CONFIG_CACHE.clear()

    from agent_moss import rules_loader
    rules_loader.clear_rules_cache()

    from agent_moss.profiles import clear_profile_cache
    clear_profile_cache()

    from agent_moss.agents import clear_agent_extensions_cache
    from agent_moss.scenarios import clear_scenario_extensions_cache
    clear_agent_extensions_cache()
    clear_scenario_extensions_cache()

    from agent_moss.engine import heuristic, skill_engine
    heuristic._FROZEN_USER_RULES_CACHE.clear()
    skill_engine._FROZEN_SKILLS_CACHE.clear()

    from agent_moss.infra.config import invalidate_default_config_cache
    invalidate_default_config_cache()


@pytest.fixture
def cold_env(tmp_path, monkeypatch):
    runtime = tmp_path / "agent_moss_runtime.json"
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    monkeypatch.setenv("AGENT_MOSS_RULES_MODE", "cold")
    monkeypatch.delenv("AGENT_MOSS_RULES_BUILTIN_ONLY", raising=False)
    monkeypatch.delenv("AGENT_MOSS_DISABLE_RULE_HOT_RELOAD", raising=False)
    monkeypatch.setenv("AGENT_MOSS_RUNTIME_CONFIG_PATH", str(runtime))
    monkeypatch.setenv("AGENT_MOSS_EXTRA_RULES_DIR", str(rules_dir))
    monkeypatch.setenv("AGENT_MOSS_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("AGENT_MOSS_DISABLE_LLM", "1")
    monkeypatch.delenv("AGENT_MOSS_CUSTOM_RULES", raising=False)
    monkeypatch.delenv("AGENT_MOSS_OVERRIDE_RULES_DIR", raising=False)
    monkeypatch.setattr(rc, "has_runtime_config", _REAL_HAS_RUNTIME_CONFIG)
    _reset_caches()
    try:
        yield runtime, rules_dir
    finally:
        monkeypatch.delenv("AGENT_MOSS_RULES_MODE", raising=False)
        monkeypatch.delenv("AGENT_MOSS_EXTRA_RULES_DIR", raising=False)
        _reset_caches()


def _l1_patterns() -> list[str]:
    from agent_moss.infra.runtime_config import get_enabled_l1_command_patterns_or_default
    return [r["pattern"] for r in get_enabled_l1_command_patterns_or_default({}, "linux")]


def test_cold_loads_rules_dir_and_ignores_runtime(cold_env):
    runtime, rules_dir = cold_env
    runtime.write_text(json.dumps({
        "version": 1,
        "layers": {"L1_heuristic": False},
        "L1_rules": {"user_custom": {"category_enabled": True, "rules": [{
            "pattern": r"echo\s+runtime-probe", "risk_level": "critical",
            "risk_type": "custom_rule", "reason": "runtime",
        }]}},
    }), encoding="utf-8")
    (rules_dir / "extra.json").write_text(json.dumps({
        "dangerous_commands": [{
            "pattern": r"echo\s+cold-probe", "risk_level": "critical",
            "risk_type": "custom_rule", "reason": "cold",
        }],
    }), encoding="utf-8")
    original = runtime.read_text(encoding="utf-8")

    assert rules_mode.get_rules_mode() == "cold"
    assert rules_mode.is_runtime_config_disabled() is True
    assert rules_mode.is_builtin_only() is False

    from agent_moss.rules_loader import load_extra_rules, rules_dirs
    assert rules_dir in rules_dirs()
    assert any("cold-probe" in (r.get("pattern") or "")
               for r in load_extra_rules().get("dangerous_commands", []))

    patterns = _l1_patterns()
    assert any("cold-probe" in p for p in patterns)
    assert not any("runtime-probe" in p for p in patterns)

    # runtime JSON 不读、不写回
    assert _REAL_HAS_RUNTIME_CONFIG() is False
    assert runtime.read_text(encoding="utf-8") == original
    with pytest.raises(rc.RuntimeConfigReadOnlyError):
        rc.save_runtime_config(rc.load_runtime_config())

    # cold 下层级开关只认环境变量：runtime 里的 L1=false 不生效
    assert rc.is_layer_enabled("L1_heuristic") is True


def test_cold_freezes_rules_dir_until_restart(cold_env):
    _, rules_dir = cold_env
    (rules_dir / "extra.json").write_text(json.dumps({
        "dangerous_commands": [{
            "pattern": r"echo\s+cold-one", "risk_level": "critical",
            "risk_type": "custom_rule", "reason": "first",
        }],
    }), encoding="utf-8")

    from agent_moss.rules_loader import load_extra_rules
    first = load_extra_rules()
    assert any("cold-one" in (r.get("pattern") or "")
               for r in first.get("dangerous_commands", []))

    # 运行中改规则目录：cold 模式已冻结，不重扫
    (rules_dir / "extra.json").write_text(json.dumps({
        "dangerous_commands": [{
            "pattern": r"echo\s+cold-two", "risk_level": "critical",
            "risk_type": "custom_rule", "reason": "second",
        }],
    }), encoding="utf-8")
    second = load_extra_rules()
    assert any("cold-one" in (r.get("pattern") or "")
               for r in second.get("dangerous_commands", []))
    assert not any("cold-two" in (r.get("pattern") or "")
                   for r in second.get("dangerous_commands", []))


def test_cold_override_replaces_builtin_category(cold_env):
    _, rules_dir = cold_env
    (rules_dir / "override.json").write_text(json.dumps({
        "dangerous_commands": [{
            "pattern": r"echo\s+override-only", "risk_level": "high",
            "risk_type": "custom_rule", "reason": "override",
        }],
    }), encoding="utf-8")
    patterns = _l1_patterns()
    assert len(patterns) == 1, patterns
    assert "override-only" in patterns[0]


def test_cold_allows_custom_env_rules(cold_env, monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_CUSTOM_RULES", json.dumps([
        {"pattern": r"echo\s+env-cold", "action": "Deny", "severity": "high"},
    ]))
    from agent_moss.infra.config import load_custom_rules
    rules = load_custom_rules()
    assert len(rules) == 1
    assert "env-cold" in rules[0]["pattern"]


def test_cold_ignores_user_skill_and_brain(cold_env, tmp_path):
    data_root = tmp_path / "data"
    skill_dir = data_root / "agent_moss_skills"
    skill_dir.mkdir(parents=True)
    (skill_dir / "probe-skill.md").write_text("# probe", encoding="utf-8")

    from agent_moss.engine.skill_engine import SkillEngine
    assert SkillEngine()._load_user_skill("probe-skill") == ""

    from agent_moss.infra.config import is_brain_enabled
    assert is_brain_enabled() is False


def test_cold_scenario_rules_dir_override(cold_env):
    _, rules_dir = cold_env
    scen = rules_dir / "scenarios" / "bank"
    scen.mkdir(parents=True)
    (scen / "rules.json").write_text(json.dumps({
        "scenario_id": "bank",
        "extra_command_patterns": [{
            "pattern": r"echo\s+scenario-cold", "risk_level": "high",
            "risk_type": "custom_rule", "reason": "scenario cold",
        }],
    }), encoding="utf-8")

    from agent_moss.scenarios import get_scenario_extensions
    ext = get_scenario_extensions("bank")
    assert ext is not None
    assert any("scenario-cold" in p.pattern for p in ext.extra_command_patterns)


def test_cold_console_write_returns_403(cold_env):
    from fastapi.testclient import TestClient
    from agent_moss.server.app import create_app

    with TestClient(create_app()) as client:
        r = client.get("/console/api/layers")
        assert r.status_code == 200, r.text
        assert r.json().get("rules_mode") == "cold"
        assert r.json().get("builtin_only") is False

        w = client.put(
            "/console/api/layers",
            json={"layer_key": "L1_heuristic", "enabled": False},
        )
        assert w.status_code == 403, w.text
        assert "cold" in w.json()["detail"]


def test_rules_mode_precedence(monkeypatch):
    def mode_with(**env):
        for k in ("AGENT_MOSS_RULES_MODE", "AGENT_MOSS_RULES_BUILTIN_ONLY",
                  "AGENT_MOSS_DISABLE_RULE_HOT_RELOAD"):
            monkeypatch.delenv(k, raising=False)
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        rules_mode.reset_cache()
        return rules_mode.get_rules_mode()

    assert mode_with(AGENT_MOSS_RULES_MODE="hot") == "hot"
    assert mode_with(AGENT_MOSS_RULES_MODE="cold") == "cold"
    # 显式 mode 优先于别名
    assert mode_with(
        AGENT_MOSS_RULES_MODE="hot", AGENT_MOSS_RULES_BUILTIN_ONLY="1",
    ) == "hot"
    # 两个别名同时设置：builtin 优先
    assert mode_with(
        AGENT_MOSS_RULES_BUILTIN_ONLY="1", AGENT_MOSS_DISABLE_RULE_HOT_RELOAD="1",
    ) == "builtin"
    # 非法值 fail-safe 到 builtin
    assert mode_with(AGENT_MOSS_RULES_MODE="clod") == "builtin"
    rules_mode.reset_cache()
