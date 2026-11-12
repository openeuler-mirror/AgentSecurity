"""注入关键词的平台作用域看护（2026-10 修双端分叉）。

**修的是什么**：`l1_rules.json` 的 `injection_detection` 原先 48 条**不带 os 字段**，
被按"不带 os = linux"的约定处理 → Windows 按 os 过滤后**一条不剩** → 静默回退到
`WindowsProfile` 里一份 14 条的硬编码副本；而 TS 端回退时**不带平台过滤**（拿全 48 条）。
结果两端在 Windows 上**双向分叉**：

| 关键词 | Python(修前) | TS(修前) |
|---|---|---|
| `DAN mode`（Linux 有、Windows 副本没有） | Allow ❌漏 | Deny |
| `绕过审计`（Windows 副本独有） | Deny | Allow ❌漏 |

**修法**：通用条目标 `os: "all"`（各平台都生效）、Windows 独有的 3 条标
`os: "windows"`；两端统一按 `all` / `accepted_os` 过滤；WindowsProfile 的硬编码副本删除；
种子改为遍历全部平台收集（否则那 3 条进不了 runtime）。

**本文件守**：
1. 通用条目三平台都生效、Windows 独有**不**泄漏到 Linux（防"修分叉"变成"给 Linux 加误报"）；
2. Linux 仍是 48 条（**主平台的检测面一条没动**）；
3. 种子包含全部 51 条（否则 Windows 又静默少检）；
4. 端到端：Windows 独有关键词在 Windows 上真能拦住、在 Linux 上不误拦。

"""
from __future__ import annotations

import pytest

from agent_moss.infra import rules_mode
from agent_moss.infra import runtime_config as rc
from agent_moss.profiles import get_profile
from agent_moss.rules_loader import load_l1

ALL_PLATFORMS = ("linux", "windows", "macos", "harmony")


def _reset_caches() -> None:
    rules_mode.reset_cache()
    rc._RUNTIME_CONFIG_CACHE.clear()
    rc._HAS_RUNTIME_CONFIG_CACHE.clear()
    from agent_moss import rules_loader
    rules_loader.clear_rules_cache()
    from agent_moss.profiles import clear_profile_cache
    clear_profile_cache()


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_MOSS_RUNTIME_CONFIG_PATH", str(tmp_path / "runtime.json"))
    monkeypatch.setenv("AGENT_MOSS_DISABLE_LLM", "1")
    for k in ("AGENT_MOSS_RULES_MODE", "AGENT_MOSS_EXTRA_RULES_DIR",
              "AGENT_MOSS_OVERRIDE_RULES_DIR", "AGENT_MOSS_CUSTOM_RULES"):
        monkeypatch.delenv(k, raising=False)
    _reset_caches()
    yield
    _reset_caches()


def _effective(os_type: str) -> set[str]:
    return {k["keyword"]
            for k in rc.get_enabled_l1_injection_keywords_or_default(
                rc.load_runtime_config(), os_type)}


def _catalog() -> tuple[set[str], set[str]]:
    entries = load_l1()["injection_detection"]
    universal = {e["keyword"] for e in entries if str(e.get("os") or "").lower() == "all"}
    win_only = {e["keyword"] for e in entries if str(e.get("os") or "").lower() == "windows"}
    return universal, win_only


def test_catalog_shape(isolated):
    """JSON 里通用条目单独成组、平台独有单独成组，两者不相交。"""
    universal, win_only = _catalog()
    assert universal and win_only, "两组都不该为空"
    assert not (universal & win_only), "同一条关键词不能既通用又平台独有"


def test_universal_keywords_apply_everywhere(isolated):
    """通用条目（`os: "all"`）四平台都生效。"""
    universal, _ = _catalog()
    for os_type in ALL_PLATFORMS:
        missing = universal - _effective(os_type)
        assert not missing, f"{os_type} 缺失通用注入关键词: {sorted(missing)[:5]}"


def test_windows_only_keywords_do_not_leak(isolated):
    """Windows 独有条目**不能**泄漏到其它平台（否则等于给 Linux 加误报）。"""
    _, win_only = _catalog()
    for os_type in ("linux", "macos", "harmony"):
        leaked = win_only & _effective(os_type)
        assert not leaked, f"{os_type} 泄漏了 Windows 独有注入关键词: {sorted(leaked)}"
    assert win_only <= _effective("windows"), "Windows 应拿到自己的独有关键词"


def test_linux_scope_unchanged(isolated):
    """主平台不受影响：Linux 仍是「通用条目」那一份，一条不多一条不少。"""
    universal, _ = _catalog()
    assert _effective("linux") == universal


def test_macos_harmony_match_linux(isolated):
    """类 Unix 继承：macOS / 鸿蒙与 Linux 完全一致。"""
    assert _effective("macos") == _effective("linux")
    assert _effective("harmony") == _effective("linux")


def test_seed_carries_all_platforms(isolated):
    """种子必须包含全部条目 —— 只取 linux profile 会让 Windows 独有条目永不生效。"""
    seeded = {r["keyword"] for r in rc.load_runtime_config()["L1_rules"]["injection_detection"]["rules"]}
    universal, win_only = _catalog()
    assert universal <= seeded
    assert win_only <= seeded, f"种子缺 Windows 独有条目: {sorted(win_only - seeded)}"


def test_profile_filters_by_os(isolated):
    """Profile 侧（种子来源）与 runtime 侧口径一致。"""
    universal, win_only = _catalog()
    assert {k["keyword"] for k in get_profile("linux").injection_keywords} == universal
    assert {k["keyword"] for k in get_profile("windows").injection_keywords} == universal | win_only


# ==================== 端到端：真能拦 / 真不误拦 ====================

@pytest.mark.parametrize("kw", ["DAN mode", "=== END OF", "jailbreak"])
def test_universal_keyword_blocks_on_every_platform(isolated, kw):
    """通用注入关键词在任一平台都应被拦（含 Windows —— 修前那里一条都不生效）。"""
    from agent_moss.engine.heuristic import InjectionKeywordChecker
    for os_type in ALL_PLATFORMS:
        checker = InjectionKeywordChecker(get_profile(os_type))
        # ⚠️ 文本必须先转小写：真实调用点传的就是 `.lower()` 后的拼接文本
        # （heuristic.py 的 combined_text），check() 内部是子串匹配、不自己转。
        assert checker.check(f"bash ls {kw}".lower()).hit, \
            f"{os_type} 未拦截通用注入词 {kw!r}"


def test_windows_only_keyword_blocks_on_windows_only(isolated):
    """Windows 独有关键词：Windows 拦、Linux 放（与 TS 端逐条一致）。"""
    from agent_moss.engine.heuristic import InjectionKeywordChecker
    _, win_only = _catalog()
    for kw in sorted(win_only):
        assert InjectionKeywordChecker(get_profile("windows")).check(f"bash ls {kw}".lower()).hit
        assert not InjectionKeywordChecker(get_profile("linux")).check(f"bash ls {kw}".lower()).hit


def test_reported_risk_levels_unchanged_for_linux(isolated):
    """回归：修分叉**不能顺带改风险等级** —— Linux 侧各条的 risk_level 与 JSON 逐字一致。"""
    entries = {e["keyword"]: e for e in load_l1()["injection_detection"]}
    for k in get_profile("linux").injection_keywords:
        assert k["risk_level"] == entries[k["keyword"]]["risk_level"], (
            f"{k['keyword']!r} 的 risk_level 被改动")
