"""规则来源模式（进程级，只读环境变量）。

三种模式：

- ``hot``（默认）：内置规则 + 规则目录 + runtime JSON / Console，全部生效；
  runtime 改完下一次判定即生效。
- ``cold``：**冷启动**。内置规则 + ``AGENT_MOSS_EXTRA_RULES_DIR`` /
  ``AGENT_MOSS_OVERRIDE_RULES_DIR`` / ``AGENT_MOSS_CUSTOM_RULES`` /
  ``AGENT_MOSS_SCENARIO`` 在启动时读一次并冻结；``agent_moss_runtime.json``
  与 Console 完全不参与（不读、不 seed、不 merge、不写回）；规则目录内容
  运行中修改不生效，重启才生效。适合"客户提供规则 + 防止 runtime 污染"。
- ``builtin``：**仅内置规则**。在 ``cold`` 的基础上再忽略规则目录 /
  ``AGENT_MOSS_CUSTOM_RULES`` / 配置里的 ``rules_path`` / ``skills_dir``。

环境变量：
- ``AGENT_MOSS_RULES_MODE=hot|cold|builtin``（优先级最高）；
- ``AGENT_MOSS_RULES_BUILTIN_ONLY=1`` → ``builtin``；
- ``AGENT_MOSS_DISABLE_RULE_HOT_RELOAD=1`` → ``cold``；
- 两个别名同时设置时 ``builtin`` 优先；非法 mode 值按 ``builtin`` 处理（fail-safe）。

⚠️ 只从环境变量读取，不写进 runtime JSON / settings JSON —— 否则攻击者可以
先改配置把开关本身关掉。首次调用时读取并缓存，进程生命周期内不再变化。
"""
from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

ENV_RULES_MODE = "AGENT_MOSS_RULES_MODE"
#: 仅内置规则（语义最严格）
ENV_RULES_BUILTIN_ONLY = "AGENT_MOSS_RULES_BUILTIN_ONLY"
#: 禁用热加载 = 冷启动（规则目录启动时读一次）
ENV_DISABLE_RULE_HOT_RELOAD = "AGENT_MOSS_DISABLE_RULE_HOT_RELOAD"

MODE_HOT = "hot"
MODE_COLD = "cold"
MODE_BUILTIN = "builtin"
_VALID_MODES = {MODE_HOT, MODE_COLD, MODE_BUILTIN}
_TRUTHY = {"1", "true", "yes", "on"}

_cached: str | None = None


def _truthy(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in _TRUTHY


def get_rules_mode() -> str:
    """当前进程的规则来源模式（首次调用时读取环境变量并缓存）。"""
    global _cached
    if _cached is not None:
        return _cached
    raw = os.getenv(ENV_RULES_MODE, "").strip().lower()
    if raw:
        if raw in _VALID_MODES:
            _cached = raw
        else:
            logger.error(
                "%s=%r 非法（只支持 hot / cold / builtin）；"
                "为安全起见按 builtin（仅内置规则）处理",
                ENV_RULES_MODE, raw,
            )
            _cached = MODE_BUILTIN
        return _cached
    if _truthy(ENV_RULES_BUILTIN_ONLY):
        _cached = MODE_BUILTIN
    elif _truthy(ENV_DISABLE_RULE_HOT_RELOAD):
        _cached = MODE_COLD
    else:
        _cached = MODE_HOT
    return _cached


def is_hot_reload_enabled() -> bool:
    """hot 模式：runtime / 规则目录均可运行中热生效。"""
    return get_rules_mode() == MODE_HOT


def is_runtime_config_disabled() -> bool:
    """cold / builtin：runtime JSON / Console 完全不参与判定。"""
    return get_rules_mode() != MODE_HOT


def is_builtin_only() -> bool:
    """builtin：连规则目录 / CUSTOM_RULES / 自定义 rules_path/skills_dir 也不读。"""
    return get_rules_mode() == MODE_BUILTIN


def reset_cache() -> None:
    """清空模式缓存（仅供测试；生产进程启动后不再改变）。"""
    global _cached
    _cached = None


__all__ = [
    "ENV_RULES_MODE",
    "ENV_RULES_BUILTIN_ONLY",
    "ENV_DISABLE_RULE_HOT_RELOAD",
    "MODE_HOT",
    "MODE_COLD",
    "MODE_BUILTIN",
    "get_rules_mode",
    "is_hot_reload_enabled",
    "is_runtime_config_disabled",
    "is_builtin_only",
    "reset_cache",
]
