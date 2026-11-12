"""场景定制化规则注册中心（客户沙箱场景级规则）

按 `scenario_id` 加载该场景的专属规则集（JSON 单一事实源）。
规则文件位置：`agent_moss/scenarios/<scenario_id>/rules.json`

与 agent 定制规则（agent_moss/agents/<id>/rules.json）**同构**——场景规则也是
`AgentExtensions` 结构（extra_command_patterns / extra_injection_keywords /
extra_sensitive_paths / builtin_safe_skills / builtin_safe_action_types），
唯一区别是顶层 id 字段叫 `scenario_id` 而非 `agent_id`，由
`AgentExtensions.from_json(..., id_key="scenario_id")` 解析。

设计动机：agent 规则靠调用方传 `agent_id`（真实 agent instance 身份）启用；
场景规则是**部署级**约束（客户沙箱的目录访问边界、禁 ssh 等），没有天然调用方
身份，启用判定为：
1. 调用方显式传 `scenario_id`（请求级，与 agent_id 并列）
2. 兜底环境变量 `AGENT_MOSS_SCENARIO`（部署级，客户沙箱设一次，所有请求生效）
3. 两者都空 → 通用模式（不加载场景规则）

使用：
    from agent_moss.scenarios import get_scenario_extensions
    ext = get_scenario_extensions("bank")
    if ext:
        # 把 ext.extra_command_patterns 追加到 agent_ext/通用规则之后
        ...

规则存放于 rules.json：
- py: agent_moss/scenarios/__init__.py:get_scenario_extensions

无 scenario_id 或 rules.json 不存在时返回 None（通用模式）。
"""

from pathlib import Path
import threading
import logging

from ..infra.paths import asset_dir, is_safe_id

# 场景规则与 agent 规则同构：复用 AgentExtensions 数据载体（agents/base.py）
from ..agents.base import AgentExtensions, InjectionKeyword, CommandPattern, SensitivePath  # noqa: F401

logger = logging.getLogger(__name__)

# 场景规则目录：默认包内 `agent_moss/scenarios/`；设了 AGENT_MOSS_RULES_ROOT →
# `<root>/scenarios/`。用函数而非常量，环境变量改了立即生效。
def _scenarios_dir() -> Path:
    return asset_dir("scenarios")


#: 兼容旧引用名（导入时快照）。新代码请用 _scenarios_dir()。
_SCENARIOS_DIR = _scenarios_dir()


#: scenario_id → (规则来源指纹, AgentExtensions | None)
#: 指纹含 runtime 配置文件的 path/mtime/size：手工编辑或 Console 写盘后自动重载。
_cache: dict[str, tuple[tuple, AgentExtensions | None]] = {}
_lock = threading.Lock()

#: 缓存条目上限（键来自调用方自报的 scenario_id，理由同 agents/__init__.py）。
_CACHE_MAX = 512


def _rule_source_fingerprint() -> tuple:
    """规则来源指纹；runtime_config 不可用时退化为常量（行为等同旧缓存）。"""
    try:
        from ..infra.runtime_config import get_rule_source_fingerprint
        return get_rule_source_fingerprint()
    except Exception:  # noqa: BLE001
        return ("unknown",)


def get_scenario_extensions(scenario_id: str) -> AgentExtensions | None:
    """按 scenario_id 加载该场景的专属规则集。

    Args:
        scenario_id: 场景标识，如 "bank"。空字符串返回 None（通用模式）。

    Returns:
        AgentExtensions 实例，或 None（无场景专属规则 / rules.json 不存在）。
    """
    if not scenario_id:
        return None
    # 目录穿越防护：scenario_id 会被拼进 `<scenarios>/<id>/rules.json`，而它是
    # 调用方自报的（请求字段或 AGENT_MOSS_SCENARIO 环境变量）。
    # `../../x` 会把任意 rules.json 当成场景规则加载 → 直接削弱该场景的检测。
    if not is_safe_id(scenario_id):
        logger.warning("非法 scenario_id 已忽略（含路径字符或超长）: %.120r", scenario_id)
        return None
    # 缓存键来自调用方自报，穷举不同 id 会撑大缓存（下面的 None 分支同样会写缓存）
    if len(_cache) >= _CACHE_MAX:
        _cache.clear()

    # 双重检查锁定，避免并发重复 IO；指纹变化（runtime JSON 被改）时重新加载。
    fp = _rule_source_fingerprint()
    cached = _cache.get(scenario_id)
    if cached is not None and cached[0] == fp:
        return cached[1]

    with _lock:
        fp = _rule_source_fingerprint()
        cached = _cache.get(scenario_id)
        if cached is not None and cached[0] == fp:
            return cached[1]
        if cached is not None:
            logger.debug("场景 %s 规则来源变化，重新加载", scenario_id)

        # 统一存储：优先读 runtime_config 的 scenario_rules 分区（用户可在 console
        # 查看/编辑/禁用/新增，与 agent_rules 同构，享受一致的合并升级）。回退
        # rules.json（无 runtime_config 时，如直接起服务未 seed、或旧部署）。
        # ⚠️ 例外：覆盖目录命中（AGENT_MOSS_OVERRIDE_RULES_DIR / data_root 的
        # scenarios/<id>/rules.json）时**覆盖文件优先于 runtime 分区** —— 覆盖是
        # 部署面显式应急替换（"内置场景规则出问题时不等升级"），runtime 分区只是
        # 种子的镜像；若 runtime 优先，已有 runtime 文件的部署上覆盖文件永远不生效
        # （2026-10 实测：TS 端到端测试抓出来的双端同病）。
        ext = None
        overridden_file = None
        try:
            from ..rules_loader import resolve_scenario_rules_file
            hit = resolve_scenario_rules_file(scenario_id)
            if hit is not None and hit != _scenarios_dir() / scenario_id / "rules.json":
                overridden_file = hit
        except Exception:
            pass

        if overridden_file is None:
            try:
                from ..infra.runtime_config import (has_runtime_config, load_runtime_config,
                                                   get_enabled_scenario_extensions)
                if has_runtime_config():
                    ext = get_enabled_scenario_extensions(load_runtime_config(), scenario_id)
            except Exception:
                pass  # runtime_config 不可用时回退 rules.json

        if ext is None:
            rules_file = overridden_file or (_scenarios_dir() / scenario_id / "rules.json")
            if not rules_file.exists():
                logger.debug("场景 %s 无 rules.json，走通用模式", scenario_id)
                _cache[scenario_id] = (fp, None)
                return None
            if overridden_file is not None:
                logger.warning(
                    "⚠️  场景 %s 规则被覆盖目录覆盖: %s（内置默认 %s 被忽略）。"
                    "该文件由部署侧自行维护，内置场景规则更新不会反映到它上面。",
                    scenario_id, rules_file, _scenarios_dir() / scenario_id / "rules.json",
                )
            try:
                ext = AgentExtensions.from_json(rules_file, id_key="scenario_id")
            except Exception as e:
                logger.error("加载场景 %s rules.json 失败: %s", scenario_id, e)
                _cache[scenario_id] = (fp, None)
                return None

        _cache[scenario_id] = (fp, ext)
        logger.info(
            "加载场景 %s 定制规则: %d cmd patterns, %d injection keywords, "
            "%d sensitive paths, %d builtin safe skills, %d builtin safe action types",
            scenario_id,
            len(ext.extra_command_patterns),
            len(ext.extra_injection_keywords),
            len(ext.extra_sensitive_paths),
            len(ext.builtin_safe_skills),
            len(ext.builtin_safe_action_types),
        )
        return ext


def clear_scenario_extensions_cache() -> None:
    """清空场景扩展缓存（用于测试或 rules.json 热加载）"""
    with _lock:
        _cache.clear()


def get_scenario_extensions_multi(scenario_spec: str | None) -> AgentExtensions | None:
    """按逗号分隔的场景列表加载并合并扩展（AGENT_MOSS_SCENARIO 支持多场景）。

    引擎层兜底 env 时使用：`AGENT_MOSS_SCENARIO=bank,meow` 会被拆成多个场景 id，
    逐个加载后合并成一个 AgentExtensions（append 语义，与 console 的
    _enabled_scenario_ids 逗号分隔口径一致）。

    Args:
        scenario_spec: 逗号分隔的场景 id 字符串（可为空）。

    Returns:
        合并后的 AgentExtensions，或 None（无任何场景可加载）。
    """
    if not scenario_spec:
        return None
    ids = [s.strip() for s in scenario_spec.split(",") if s.strip()]
    if not ids:
        return None
    exts = [get_scenario_extensions(sid) for sid in ids]
    non_null = [e for e in exts if e is not None]
    if not non_null:
        return None
    merged: AgentExtensions | None = non_null[0]
    for e in non_null[1:]:
        merged = AgentExtensions.merge(merged, e)
    return merged


__all__ = [
    "AgentExtensions",
    "InjectionKeyword",
    "CommandPattern",
    "SensitivePath",
    "get_scenario_extensions",
    "get_scenario_extensions_multi",
    "clear_scenario_extensions_cache",
]
