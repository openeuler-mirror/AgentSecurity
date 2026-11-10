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

Python 与 TypeScript 两端共享同一份 rules.json：
- py: agent_moss/scenarios/__init__.py:get_scenario_extensions
- ts: ts/src/scenarios/index.ts:getScenarioExtensions

无 scenario_id 或 rules.json 不存在时返回 None（通用模式）。
"""

from pathlib import Path
import threading
import logging

# 场景规则与 agent 规则同构：复用 AgentExtensions 数据载体（agents/base.py）
from ..agents.base import AgentExtensions, InjectionKeyword, CommandPattern, SensitivePath  # noqa: F401

logger = logging.getLogger(__name__)

_SCENARIOS_DIR = Path(__file__).parent
_cache: dict[str, AgentExtensions | None] = {}
_lock = threading.Lock()


def get_scenario_extensions(scenario_id: str) -> AgentExtensions | None:
    """按 scenario_id 加载该场景的专属规则集。

    Args:
        scenario_id: 场景标识，如 "bank"。空字符串返回 None（通用模式）。

    Returns:
        AgentExtensions 实例，或 None（无场景专属规则 / rules.json 不存在）。
    """
    if not scenario_id:
        return None

    # 双重检查锁定，避免并发重复 IO
    if scenario_id in _cache:
        return _cache[scenario_id]

    with _lock:
        if scenario_id in _cache:
            return _cache[scenario_id]

        # 统一存储：优先读 runtime_config 的 scenario_rules 分区（用户可在 console
        # 查看/编辑/禁用/新增，与 agent_rules 同构，享受一致的合并升级）。回退
        # rules.json（无 runtime_config 时，如直接起服务未 seed、或旧部署）。
        ext = None
        try:
            from ..infra.runtime_config import (has_runtime_config, load_runtime_config,
                                               get_enabled_scenario_extensions)
            if has_runtime_config():
                ext = get_enabled_scenario_extensions(load_runtime_config(), scenario_id)
        except Exception:
            pass  # runtime_config 不可用时回退 rules.json

        if ext is None:
            rules_file = _SCENARIOS_DIR / scenario_id / "rules.json"
            if not rules_file.exists():
                logger.debug("场景 %s 无 rules.json，走通用模式", scenario_id)
                _cache[scenario_id] = None
                return None
            try:
                ext = AgentExtensions.from_json(rules_file, id_key="scenario_id")
            except Exception as e:
                logger.error("加载场景 %s rules.json 失败: %s", scenario_id, e)
                _cache[scenario_id] = None
                return None

        _cache[scenario_id] = ext
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
