"""仅内置规则模式（AGENT_MOSS_RULES_BUILTIN_ONLY=1）回归测试。

目标（对应需求）：
1. 开关打开后**完全不读用户 runtime 配置**：不 stat / 不 seed / 不 merge / 不写回；
2. Console / 规则目录 / AGENT_MOSS_CUSTOM_RULES / 用户 skill / Brain 全部忽略；
3. Console 写接口返回 403；
4. 开关未设置时行为与改动前完全一致（默认热加载）。
"""
from __future__ import annotations

import json

import pytest

from agent_moss.infra import rules_mode
from agent_moss.infra import runtime_config as rc

#: conftest 的 autouse fixture 会把 rc.has_runtime_config 换成恒 False 的 lambda；
#: 这里在 import 时抓住**真实实现**，用于断言"仅内置模式下连文件存在都当不存在"。
_REAL_HAS_RUNTIME_CONFIG = rc.has_runtime_config


def _reset_caches() -> None:
    """清空所有与规则来源相关的进程级缓存（切换模式时用）。"""
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
def builtin_only_env(tmp_path, monkeypatch):
    """打开仅内置模式，并把 runtime 路径/数据目录都指到临时位置。"""
    cfg = tmp_path / "agent_moss_runtime.json"
    monkeypatch.setenv("AGENT_MOSS_RULES_BUILTIN_ONLY", "1")
    monkeypatch.delenv("AGENT_MOSS_DISABLE_RULE_HOT_RELOAD", raising=False)
    monkeypatch.setenv("AGENT_MOSS_RUNTIME_CONFIG_PATH", str(cfg))
    monkeypatch.setenv("AGENT_MOSS_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("AGENT_MOSS_CUSTOM_RULES", raising=False)
    monkeypatch.delenv("AGENT_MOSS_EXTRA_RULES_DIR", raising=False)
    monkeypatch.delenv("AGENT_MOSS_OVERRIDE_RULES_DIR", raising=False)
    _reset_caches()
    try:
        yield cfg
    finally:
        # monkeypatch 的 env 还原发生在 fixture teardown 之后；先手动清掉并重置缓存，
        # 避免 is_builtin_only 的缓存泄漏到后续用例。
        monkeypatch.delenv("AGENT_MOSS_RULES_BUILTIN_ONLY", raising=False)
        monkeypatch.delenv("AGENT_MOSS_DISABLE_RULE_HOT_RELOAD", raising=False)
        _reset_caches()


def _write_runtime_with_probe(path, probe: str) -> str:
    data = {
        "version": 1,
        "layers": {"L1_heuristic": False, "L2_logic_rules": False, "L3_llm_analysis": False},
        "L1_rules": {
            "user_custom": {
                "category_enabled": True,
                "rules": [{
                    "pattern": probe,
                    "risk_level": "critical",
                    "risk_type": "custom_rule",
                    "reason": "仅内置模式下必须被忽略",
                }],
            },
        },
    }
    text = json.dumps(data, ensure_ascii=False, indent=2)
    path.write_text(text, encoding="utf-8")
    return text


def test_builtin_only_ignores_runtime_config_and_never_writes(builtin_only_env):
    """runtime 文件存在也当不存在：不读、不 merge、不写回。"""
    cfg = builtin_only_env
    original = _write_runtime_with_probe(cfg, r"echo\s+builtin-only-probe")

    assert _REAL_HAS_RUNTIME_CONFIG() is False
    assert rc.has_runtime_config() is False

    runtime = rc.load_runtime_config()
    # 只返回默认层级开关；没有任何用户规则
    assert runtime.keys() == {"version", "layers"}
    assert all(runtime["layers"].values()) is True

    from agent_moss.infra.runtime_config import get_enabled_l1_command_patterns_or_default
    patterns = [r["pattern"] for r in get_enabled_l1_command_patterns_or_default(runtime, "linux")]
    assert patterns, "内置规则不应为空"
    assert not any("builtin-only-probe" in p for p in patterns)

    # 文件内容一个字节都没变（没有 merge / 写回）
    assert cfg.read_text(encoding="utf-8") == original

    # 写操作被拒绝
    with pytest.raises(rc.RuntimeConfigReadOnlyError):
        rc.save_runtime_config(runtime)


def test_builtin_only_does_not_create_runtime_file(builtin_only_env):
    """runtime 文件不存在时也不能 seed 出一个来。"""
    cfg = builtin_only_env
    assert not cfg.exists()
    rc.load_runtime_config()
    from agent_moss.infra.runtime_config import get_enabled_l1_command_patterns_or_default
    get_enabled_l1_command_patterns_or_default({}, "linux")
    assert not cfg.exists(), "仅内置模式不得创建 runtime 配置文件"


def test_builtin_only_ignores_rules_dirs_and_custom_rules(builtin_only_env, tmp_path, monkeypatch):
    """规则目录 / AGENT_MOSS_CUSTOM_RULES 也属于用户规则来源，一并忽略。"""
    rules_dir = tmp_path / "rules-dir"
    rules_dir.mkdir()
    (rules_dir / "extra.json").write_text(json.dumps({
        "dangerous_commands": [{
            "pattern": r"echo\s+rules-dir-probe",
            "risk_level": "critical",
            "risk_type": "custom_rule",
            "reason": "规则目录规则",
        }],
    }), encoding="utf-8")
    monkeypatch.setenv("AGENT_MOSS_EXTRA_RULES_DIR", str(rules_dir))
    monkeypatch.setenv(
        "AGENT_MOSS_CUSTOM_RULES",
        json.dumps([{"pattern": r"echo\s+env-rule-probe", "action": "Deny", "severity": "critical"}]),
    )
    _reset_caches()

    from agent_moss.rules_loader import load_extra_rules, load_override_rules, rules_dirs
    from agent_moss.infra.config import load_custom_rules
    from agent_moss.infra.runtime_config import get_enabled_l1_command_patterns_or_default

    assert rules_dirs() == []
    assert load_extra_rules() == {}
    assert load_override_rules() == {}
    assert load_custom_rules() == []

    patterns = [r["pattern"] for r in get_enabled_l1_command_patterns_or_default({}, "linux")]
    assert not any("rules-dir-probe" in p or "env-rule-probe" in p for p in patterns)


def test_builtin_only_disables_brain(builtin_only_env):
    """Brain 自学习规则来自用户数据目录，仅内置模式下强制关闭。"""
    from agent_moss.infra.config import is_brain_enabled
    assert is_brain_enabled() is False


def test_builtin_only_ignores_custom_rules_path(builtin_only_env, tmp_path):
    """配置里的 security.rules_path（自定义 user_rules.json）不读，只用包内那份。"""
    custom = tmp_path / "custom_rules.json"
    custom.write_text(json.dumps({
        "sensitive_actions": [{
            "pattern": "echo custom-rules-path-probe",
            "description": "用户自定义规则文件",
        }],
        "sensitive_tools": [],
    }), encoding="utf-8")

    from agent_moss.engine.heuristic import UserRuleMatcher
    matcher = UserRuleMatcher(str(custom))
    assert not any(
        "custom-rules-path-probe" in (r.get("pattern") or "")
        for r in matcher._rules.get("sensitive_actions", [])
    )
    assert matcher.check("bash", "echo custom-rules-path-probe").hit is False


def test_builtin_only_ignores_user_skills(builtin_only_env, tmp_path):
    """用户自定义 skill（Console 新增）不参与匹配、也不读盘。"""
    skill_dir = tmp_path / "data" / "agent_moss_skills"
    skill_dir.mkdir(parents=True)
    (skill_dir / "probe-skill.md").write_text("# probe\n用户自定义 skill", encoding="utf-8")

    from agent_moss.engine.skill_engine import SkillEngine
    engine = SkillEngine()
    assert engine._load_user_skill("probe-skill") == ""
    assert "probe-skill" not in engine._skills_cache


def test_builtin_only_keeps_builtin_self_protection(builtin_only_env, tmp_path, monkeypatch):
    """override.json 想整类替换敏感路径也删不掉内置的 .config/agentmoss 保护。"""
    rules_dir = tmp_path / "override-dir"
    rules_dir.mkdir()
    (rules_dir / "override.json").write_text(json.dumps({
        "sensitive_path_access": [{
            "path": ".ssh/id_rsa", "risk_level": "critical",
            "desc": "只保留这一条（模拟用户自定义把内置保护整类换掉）",
        }],
    }), encoding="utf-8")
    monkeypatch.setenv("AGENT_MOSS_OVERRIDE_RULES_DIR", str(rules_dir))
    _reset_caches()

    from agent_moss.infra.runtime_config import get_enabled_l2_sensitive_paths_or_default
    paths = [r["path"] for r in get_enabled_l2_sensitive_paths_or_default({}, "linux")]
    assert ".config/agentmoss" in paths, "内置自保护规则不能被用户 override 删除"


def test_builtin_only_console_write_returns_403(builtin_only_env):
    """Console 只读：GET 可看内置规则，PUT/POST/DELETE 一律 403。"""
    from fastapi.testclient import TestClient
    from agent_moss.server.app import create_app

    with TestClient(create_app()) as client:
        r = client.get("/console/api/layers")
        assert r.status_code == 200, r.text
        assert r.json().get("builtin_only") is True
        assert all(r.json()["layers"].values())

        w = client.put(
            "/console/api/layers",
            json={"layer_key": "L1_heuristic", "enabled": False},
        )
        assert w.status_code == 403, w.text
        assert "builtin" in w.json()["detail"]


def test_alias_env_enables_cold_mode(monkeypatch):
    """别名 AGENT_MOSS_DISABLE_RULE_HOT_RELOAD=1 表示冷启动（cold），不是 builtin。"""
    monkeypatch.delenv("AGENT_MOSS_RULES_MODE", raising=False)
    monkeypatch.delenv("AGENT_MOSS_RULES_BUILTIN_ONLY", raising=False)
    monkeypatch.setenv("AGENT_MOSS_DISABLE_RULE_HOT_RELOAD", "1")
    rules_mode.reset_cache()
    try:
        assert rules_mode.get_rules_mode() == "cold"
        assert rules_mode.is_runtime_config_disabled() is True
        assert rules_mode.is_builtin_only() is False
    finally:
        monkeypatch.delenv("AGENT_MOSS_DISABLE_RULE_HOT_RELOAD", raising=False)
        rules_mode.reset_cache()


def test_default_mode_still_loads_runtime_config(tmp_path, monkeypatch):
    """开关未设置 = 保持原行为：runtime 配置照常读取（热加载不变）。"""
    cfg = tmp_path / "agent_moss_runtime.json"
    _write_runtime_with_probe(cfg, r"echo\s+default-mode-probe")
    monkeypatch.delenv("AGENT_MOSS_RULES_BUILTIN_ONLY", raising=False)
    monkeypatch.delenv("AGENT_MOSS_DISABLE_RULE_HOT_RELOAD", raising=False)
    monkeypatch.setenv("AGENT_MOSS_RUNTIME_CONFIG_PATH", str(cfg))
    monkeypatch.setenv("AGENT_MOSS_DATA_DIR", str(tmp_path / "data"))
    _reset_caches()
    try:
        assert _REAL_HAS_RUNTIME_CONFIG() is True
        runtime = rc.load_runtime_config()
        from agent_moss.infra.runtime_config import get_enabled_l1_command_patterns_or_default
        patterns = [r["pattern"] for r in get_enabled_l1_command_patterns_or_default(runtime, "linux")]
        assert any("default-mode-probe" in p for p in patterns), "默认模式必须仍读取 runtime 自定义规则"
    finally:
        _reset_caches()
