"""三方 agent 定制化注册中心

按 `agent_id` 加载该 agent 的专属规则集（JSON 单一事实源）。
规则文件位置：`agent_moss/agents/<agent_id>/rules.json`

Python 与 TypeScript 两端共享同一份 rules.json：
- py: agent_moss/agents/__init__.py:get_agent_extensions
- ts: ts/src/agents/index.ts:getAgentExtensions

使用：
    from agent_moss.agents import get_agent_extensions
    ext = get_agent_extensions("xiaoo")
    if ext:
        # 把 ext.extra_command_patterns 追加到通用规则之后
        ...

无 agent_id 或 rules.json 不存在时返回 None（通用模式）。
"""

from pathlib import Path
import threading
import logging

from .base import AgentExtensions, InjectionKeyword, CommandPattern, SensitivePath

logger = logging.getLogger(__name__)

_AGENTS_DIR = Path(__file__).parent
_cache: dict[str, AgentExtensions | None] = {}
_lock = threading.Lock()


def get_agent_extensions(agent_id: str) -> AgentExtensions | None:
    """按 agent_id 加载该 agent 的专属规则集。

    Args:
        agent_id: 调用方 agent 标识，如 "xiaoo" / "opencode" / "opendesk"。
                  空字符串返回 None（通用模式）。

    Returns:
        AgentExtensions 实例，或 None（无 agent 专属规则）。
    """
    if not agent_id:
        return None

    # 双重检查锁定，避免并发重复 IO
    if agent_id in _cache:
        return _cache[agent_id]

    with _lock:
        if agent_id in _cache:
            return _cache[agent_id]

        # 统一存储：优先读 runtime_config 的 agent_rules 分区（用户可在 console
        # 查看/编辑/禁用/新增，享受与通用规则一致的合并升级）。回退 rules.json
        # （无 runtime_config 时，如直接起服务未 seed、或旧部署）。
        ext = None
        try:
            from ..infra.runtime_config import has_runtime_config, load_runtime_config, get_enabled_agent_extensions
            if has_runtime_config():
                ext = get_enabled_agent_extensions(load_runtime_config(), agent_id)
        except Exception:
            pass  # runtime_config 不可用时回退 rules.json

        if ext is None:
            rules_file = _AGENTS_DIR / agent_id / "rules.json"
            if not rules_file.exists():
                logger.debug("agent %s 无 rules.json，走通用模式", agent_id)
                _cache[agent_id] = None
                return None
            try:
                ext = AgentExtensions.from_json(rules_file)
            except Exception as e:
                logger.error("加载 agent %s rules.json 失败: %s", agent_id, e)
                _cache[agent_id] = None
                return None

        _cache[agent_id] = ext
        logger.info(
            "加载 agent %s 定制规则: %d cmd patterns, %d injection keywords, "
            "%d sensitive paths, %d builtin safe skills, %d builtin safe action types",
            agent_id,
            len(ext.extra_command_patterns),
            len(ext.extra_injection_keywords),
            len(ext.extra_sensitive_paths),
            len(ext.builtin_safe_skills),
            len(ext.builtin_safe_action_types),
        )
        return ext


def clear_agent_extensions_cache() -> None:
    """清空 agent 扩展缓存（用于测试或 rules.json 热加载）"""
    with _lock:
        _cache.clear()


__all__ = [
    "AgentExtensions",
    "InjectionKeyword",
    "CommandPattern",
    "SensitivePath",
    "get_agent_extensions",
    "clear_agent_extensions_cache",
]
