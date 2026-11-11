"""三方 agent 定制化注册中心

按 `agent_id` 加载该 agent 的专属规则集（JSON 单一事实源）。
规则文件位置：`agent_moss/agents/<agent_id>/rules.json`

规则存放于 rules.json：
- py: agent_moss/agents/__init__.py:get_agent_extensions

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

from ..infra.paths import asset_dir, is_safe_id
from .base import AgentExtensions, InjectionKeyword, CommandPattern, SensitivePath

logger = logging.getLogger(__name__)

# agent 规则目录：默认包内 `agent_moss/agents/`；设了 AGENT_MOSS_RULES_ROOT →
# `<root>/agents/`（规则仓剥离后的落点）。用函数而非常量，环境变量改了立即生效。
def _agents_dir() -> Path:
    return asset_dir("agents")


#: 兼容旧引用名（导入时快照）。新代码请用 _agents_dir()。
_AGENTS_DIR = _agents_dir()
#: agent_id → (规则来源指纹, AgentExtensions | None)
#: 指纹含 runtime 配置文件的 path/mtime/size：手工编辑或 Console 写盘后自动重载，
#: 不再需要重启进程才能让 agent_rules 分区的修改生效。
_cache: dict[str, tuple[tuple, AgentExtensions | None]] = {}
_lock = threading.Lock()

#: 缓存条目上限。键来自调用方自报的 agent_id，即使格式合法也能被穷举成
#: 海量不同键 → 内存持续增长（DoS）。超过上限直接整体清空：规则加载本身是
#: 一次小的 JSON 读，重建成本可忽略。
_CACHE_MAX = 512


def _rule_source_fingerprint() -> tuple:
    """规则来源指纹；runtime_config 不可用时退化为常量（行为等同旧缓存）。"""
    try:
        from ..infra.runtime_config import get_rule_source_fingerprint
        return get_rule_source_fingerprint()
    except Exception:  # noqa: BLE001
        return ("unknown",)


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
    # 目录穿越防护：agent_id 会被拼进 `<agents>/<id>/rules.json`，而它是调用方
    # 自报的。`../../x` 会把任意 rules.json 当成该 agent 的规则集加载。
    if not is_safe_id(agent_id):
        logger.warning("非法 agent_id 已忽略（含路径字符或超长）: %.120r", agent_id)
        return None
    # 缓存键来自调用方自报，穷举不同 id 会撑大缓存（下面的 None 分支同样会写缓存）
    if len(_cache) >= _CACHE_MAX:
        _cache.clear()

    # 双重检查锁定，避免并发重复 IO；指纹变化（runtime JSON 被改）时重新加载。
    fp = _rule_source_fingerprint()
    cached = _cache.get(agent_id)
    if cached is not None and cached[0] == fp:
        return cached[1]

    with _lock:
        fp = _rule_source_fingerprint()
        cached = _cache.get(agent_id)
        if cached is not None and cached[0] == fp:
            return cached[1]
        if cached is not None:
            logger.debug("agent %s 规则来源变化，重新加载", agent_id)

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
            rules_file = _agents_dir() / agent_id / "rules.json"
            if not rules_file.exists():
                logger.debug("agent %s 无 rules.json，走通用模式", agent_id)
                _cache[agent_id] = (fp, None)
                return None
            try:
                ext = AgentExtensions.from_json(rules_file)
            except Exception as e:
                logger.error("加载 agent %s rules.json 失败: %s", agent_id, e)
                _cache[agent_id] = (fp, None)
                return None

        _cache[agent_id] = (fp, ext)
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
