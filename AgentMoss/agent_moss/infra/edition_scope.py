"""场景包的可选 agent/scenario 白名单（交付范围约束）。

基线包没有 `edition_scope.json` → 全部允许。boostkit / openEuler 等场景包
在 `agent_moss/edition_scope.json` 声明本场景允许的 id，例如：

    {"agents": ["xiaoo"], "scenarios": []}

加载入口（`get_agent_extensions` / `get_scenario_extensions`）在读取
rules.json **或 runtime_config** 之前统一校验，确保老机器升级后即使
`agent_moss_runtime.json` 里还残留已裁掉的规则分区，也不会重新加载。

文件不存在 = 不限制（基线/普通部署）；显式空数组 = 该类别全部禁止。
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path

from .paths import asset_root

logger = logging.getLogger(__name__)

_SCOPE_FILE = "edition_scope.json"
_cache_lock = threading.Lock()
_cache_key: tuple | None = None
_cache_data: dict | None = None


def _load_scope() -> dict | None:
    global _cache_key, _cache_data
    path = asset_root() / _SCOPE_FILE
    try:
        st = path.stat()
    except OSError:
        return None
    key = (str(path), st.st_mtime_ns, st.st_size)
    with _cache_lock:
        if _cache_key == key:
            return _cache_data
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("根节点不是对象")
    except Exception as exc:  # noqa: BLE001 — 坏文件不阻断服务，但必须留痕
        logger.warning("场景范围文件不可用，按不限制处理：%s (%s)", path, exc)
        data = None
    with _cache_lock:
        _cache_key = key
        _cache_data = data
    return data


def is_allowed(kind: str, ident: str) -> bool:
    """kind = "agents" / "scenarios"；无范围文件时恒 True。"""
    scope = _load_scope()
    if scope is None:
        return True
    allowed = scope.get(kind)
    if not isinstance(allowed, list):
        return True
    return ident in allowed
