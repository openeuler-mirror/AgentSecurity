"""runtime JSON 热生效的看护测试（手改文件，不重启、不调用 Console）。

覆盖两个历史缓存问题：
1. 手工编辑 runtime JSON 的 ``layers`` 后，层级开关必须在下一次判定生效
   （旧实现用 ``config.security.*_enabled`` 快照，只有 Console 改才会失效缓存）。
2. 手工编辑 runtime JSON 的 ``agent_rules`` / ``scenario_rules`` 后，
   agent/scenario 扩展必须在下次判定重新加载（旧实现按 id 永久缓存）。
"""
from __future__ import annotations

import json

import pytest

from agent_moss.infra import runtime_config as rc

#: conftest 的 autouse fixture 把 has_runtime_config 换成恒 False；这里抓住真实实现，
#: 并在热点用例里恢复，才能验证"真实读 runtime JSON"的路径。
_REAL_HAS_RUNTIME_CONFIG = rc.has_runtime_config


@pytest.fixture
def hot_env(tmp_path, monkeypatch):
    cfg = tmp_path / "agent_moss_runtime.json"
    monkeypatch.setenv("AGENT_MOSS_RUNTIME_CONFIG_PATH", str(cfg))
    monkeypatch.setenv("AGENT_MOSS_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("AGENT_MOSS_DISABLE_LLM", "1")
    monkeypatch.delenv("AGENT_MOSS_RULES_BUILTIN_ONLY", raising=False)
    monkeypatch.delenv("AGENT_MOSS_DISABLE_RULE_HOT_RELOAD", raising=False)
    monkeypatch.setattr(rc, "has_runtime_config", _REAL_HAS_RUNTIME_CONFIG)

    from agent_moss.infra import rules_mode
    rules_mode.reset_cache()
    rc._RUNTIME_CONFIG_CACHE.clear()
    rc._HAS_RUNTIME_CONFIG_CACHE.clear()

    from agent_moss.infra.config import invalidate_default_config_cache
    invalidate_default_config_cache()
    from agent_moss.agents import clear_agent_extensions_cache
    from agent_moss.scenarios import clear_scenario_extensions_cache
    clear_agent_extensions_cache()
    clear_scenario_extensions_cache()

    yield cfg

    from agent_moss.infra.config import invalidate_default_config_cache
    invalidate_default_config_cache()
    clear_agent_extensions_cache()
    clear_scenario_extensions_cache()
    rules_mode.reset_cache()


def _write(cfg, data) -> None:
    cfg.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _base_config() -> dict:
    return {"version": 1, "layers": dict(rc.DEFAULT_LAYERS)}


def test_manual_layer_edit_is_hot(hot_env):
    """手改 layers 后，下一次判定立即使用新层级开关（不需重启 / Console）。"""
    cfg = hot_env
    data = _base_config()
    data["L1_rules"] = {
        "user_custom": {
            "category_enabled": True,
            "rules": [{
                "pattern": r"echo\s+layer-hot-probe",
                "risk_level": "critical",
                "risk_type": "custom_rule",
                "reason": "layer hot probe",
            }],
        },
    }
    _write(cfg, data)

    from agent_moss.infra.config import get_default_config
    from agent_moss.engine.coordinator import judge_security

    config = get_default_config()
    action = {"action_type": "bash", "action_detail": "echo layer-hot-probe"}

    r1 = judge_security("", [], action, "", config=config)
    assert r1.allowed is False, r1
    # 记录旧快照：修复前的实现会一直用它，导致手改 layers 不生效
    assert config.security.heuristic_enabled is True

    # 手工编辑 runtime JSON：只关 L1，不调用 invalidate_default_config_cache()
    merged = json.loads(cfg.read_text(encoding="utf-8"))
    merged["layers"]["L1_heuristic"] = False
    _write(cfg, merged)

    r2 = judge_security("", [], action, "", config=config)
    assert r2.allowed is True, r2


def _agent_config(pattern: str) -> dict:
    data = _base_config()
    data["agent_rules"] = {
        "xiaoo": {
            "extra_command_patterns": {
                "category_enabled": True,
                "rules": [{
                    "pattern": pattern,
                    "risk_level": "high",
                    "risk_type": "custom_rule",
                    "reason": "agent hot probe",
                    "enabled": True,
                }],
            },
        },
    }
    return data


def _patterns(ext) -> list[str]:
    return [p.pattern for p in (ext.extra_command_patterns if ext else [])]


def test_agent_rules_edit_is_hot(hot_env):
    """手改 agent_rules 后，get_agent_extensions 下一次调用自动重载。"""
    cfg = hot_env
    _write(cfg, _agent_config(r"echo\s+agent-hot-one"))

    from agent_moss.agents import get_agent_extensions

    ext1 = get_agent_extensions("xiaoo")
    assert any("agent-hot-one" in p for p in _patterns(ext1)), _patterns(ext1)

    merged = json.loads(cfg.read_text(encoding="utf-8"))
    rules = merged["agent_rules"]["xiaoo"]["extra_command_patterns"]["rules"]
    for r in rules:
        if "agent-hot-one" in (r.get("pattern") or ""):
            r["pattern"] = r"echo\s+agent-hot-two"
    _write(cfg, merged)

    ext2 = get_agent_extensions("xiaoo")
    assert any("agent-hot-two" in p for p in _patterns(ext2)), _patterns(ext2)
    assert not any("agent-hot-one" in p for p in _patterns(ext2)), _patterns(ext2)


def _scenario_config(pattern: str) -> dict:
    data = _base_config()
    data["scenario_rules"] = {
        "bank": {
            "extra_command_patterns": {
                "category_enabled": True,
                "rules": [{
                    "pattern": pattern,
                    "risk_level": "high",
                    "risk_type": "custom_rule",
                    "reason": "scenario hot probe",
                    "enabled": True,
                }],
            },
        },
    }
    return data


def test_scenario_rules_edit_is_hot(hot_env):
    """手改 scenario_rules 后，get_scenario_extensions 下一次调用自动重载。"""
    cfg = hot_env
    _write(cfg, _scenario_config(r"echo\s+scenario-hot-one"))

    from agent_moss.scenarios import get_scenario_extensions

    ext1 = get_scenario_extensions("bank")
    assert any("scenario-hot-one" in p for p in _patterns(ext1)), _patterns(ext1)

    merged = json.loads(cfg.read_text(encoding="utf-8"))
    rules = merged["scenario_rules"]["bank"]["extra_command_patterns"]["rules"]
    for r in rules:
        if "scenario-hot-one" in (r.get("pattern") or ""):
            r["pattern"] = r"echo\s+scenario-hot-two"
    _write(cfg, merged)

    ext2 = get_scenario_extensions("bank")
    assert any("scenario-hot-two" in p for p in _patterns(ext2)), _patterns(ext2)
    assert not any("scenario-hot-one" in p for p in _patterns(ext2)), _patterns(ext2)
