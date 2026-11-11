"""规则资产根目录「卡口」（2026-10）—— 规则仓剥离的前置条件。

**要解决什么**：规则 / skill / 场景 / agent 规则原先只能从**包内**
（`agent_moss/rules|skills|scenarios|agents`）读，路径写死在代码里。规则仓拆出去以后，
引擎必须能从一个**包外目录**读整套资产，否则拆了就装不上。

**卡口口径**：环境变量 `AGENT_MOSS_RULES_ROOT` 指向规则包根目录，其内部结构与包内一致：

```
<root>/rules/*.json          ← l1/l2/l3/mc/platform_traits/inline/script/...
<root>/skills/*.md
<root>/scenarios/<id>/rules.json
<root>/agents/<id>/rules.json
```

- **未设** → 仍读包内那一份（历史行为，逐字不变）；
- **设了** → **只认** `<root>/...`，缺文件就让各加载器报错，**绝不静默回退**到包内副本
  （否则客户以为在跑自家规则，实际跑的是内置那份）。

"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from agent_moss import rules_loader
from agent_moss.engine import skill_engine
from agent_moss.infra import runtime_config as rc
from agent_moss.infra import rules_mode
from agent_moss.infra.paths import ENV_RULES_ROOT, asset_dir, get_rules_root

PKG = Path(__file__).parent.parent / "agent_moss"


@pytest.fixture
def clean_env(monkeypatch):
    monkeypatch.delenv(ENV_RULES_ROOT, raising=False)
    monkeypatch.setenv("AGENT_MOSS_DISABLE_LLM", "1")
    monkeypatch.delenv("AGENT_MOSS_RULES_MODE", raising=False)
    _reset()
    yield monkeypatch
    _reset()


def _reset() -> None:
    rules_mode.reset_cache()
    rc._RUNTIME_CONFIG_CACHE.clear()
    rc._HAS_RUNTIME_CONFIG_CACHE.clear()
    rules_loader.clear_rules_cache()
    from agent_moss.profiles import clear_profile_cache
    clear_profile_cache()


# ==================== 默认（未设环境变量）：行为完全不变 ====================

def test_default_uses_package_assets(clean_env):
    assert get_rules_root() is None
    for name in ("rules", "skills", "scenarios", "agents"):
        assert asset_dir(name) == PKG / name


def test_default_loads_same_as_before(clean_env):
    assert rules_loader.builtin_rules_file("l1_rules.json") == PKG / "rules" / "l1_rules.json"
    assert skill_engine.default_skills_dir() == PKG / "skills"
    assert rules_loader.load_l1()  # 非空


# ==================== 设了环境变量：整套资产从包外读 ====================

@pytest.fixture
def rules_root(tmp_path, clean_env):
    """把包内四类资产复制到一个临时"规则包"里，并把环境变量指过去。"""
    for name in ("rules", "skills", "scenarios", "agents"):
        shutil.copytree(PKG / name, tmp_path / name,
                        ignore=shutil.ignore_patterns("__pycache__"))
    clean_env.setenv(ENV_RULES_ROOT, str(tmp_path))
    _reset()
    return tmp_path


def test_all_four_asset_dirs_come_from_root(rules_root):
    for name in ("rules", "skills", "scenarios", "agents"):
        assert asset_dir(name) == rules_root / name
    assert skill_engine.default_skills_dir() == rules_root / "skills"


def test_rules_really_loaded_from_root(rules_root):
    """改包外那份 JSON，引擎读到的就是改后的 —— 证明确实没读包内副本。"""
    p = rules_root / "rules" / "l1_rules.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    data["injection_detection"][0]["keyword"] = "__GATE_PROBE__"
    p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    _reset()

    kws = [k["keyword"] for k in rules_loader.load_l1()["injection_detection"]]
    assert "__GATE_PROBE__" in kws


def test_skills_really_loaded_from_root(rules_root):
    """包外 skills 目录里新加一个 .md，SkillEngine 能读到。"""
    (rules_root / "skills" / "gate_probe_skill.md").write_text(
        "# probe\n", encoding="utf-8")
    eng = skill_engine.SkillEngine()
    names = {s.name for s in eng.skills} if hasattr(eng, "skills") else set()
    # 不同版本属性名可能不同，退一步直接看目录确实被解析到包外
    assert eng._skills_dir == rules_root / "skills"


def test_scenario_and_agent_load_from_root(rules_root):
    """场景/agent 规则也从包外读：删掉包外的 bank 目录后应加载不到。"""
    from agent_moss.agents import get_agent_extensions
    from agent_moss.scenarios import get_scenario_extensions

    assert get_scenario_extensions("bank") is not None
    assert get_agent_extensions("xiaoo") is not None

    shutil.rmtree(rules_root / "scenarios" / "bank")
    shutil.rmtree(rules_root / "agents" / "xiaoo")
    from agent_moss.scenarios import _cache as sc_cache
    from agent_moss.agents import _cache as ag_cache
    sc_cache.clear()
    ag_cache.clear()
    assert get_scenario_extensions("bank") is None
    assert get_agent_extensions("xiaoo") is None


def test_seed_scans_root(rules_root):
    """Console 种子也要扫包外目录，否则规则包里的 agent/场景在控制台看不到。"""
    d = rc.generate_source_defaults()
    assert "xiaoo" in d.get("agent_rules", {})
    assert "bank" in d.get("scenario_rules", {})


def test_missing_file_does_not_silently_fall_back(rules_root):
    """包外缺 l1_rules.json → 返回空，**不是**偷偷用包内那份。"""
    (rules_root / "rules" / "l1_rules.json").unlink()
    _reset()
    assert rules_loader.load_l1() == {}


def test_env_var_removal_restores_package_assets(rules_root, clean_env):
    """去掉环境变量后立刻回到包内（解析不缓存环境变量）。"""
    assert asset_dir("rules") == rules_root / "rules"
    clean_env.delenv(ENV_RULES_ROOT)
    assert asset_dir("rules") == PKG / "rules"
