"""Session 级别 Policy 缓存管理

同一 session 中同一 prompt 对应的 policy 只生成一次，后续从缓存读取。
缓存持久化到文件系统，支持跨进程共享。

缓存文件路径: /tmp/agent_moss_policy_cache/{session_id}/{hash(prompt_session)}.toml
"""

import hashlib
import os
import tempfile
import threading
from collections import OrderedDict
from pathlib import Path

from .config import CacheConfig, get_default_config

CACHE_DIR = Path(tempfile.gettempdir()) / "agent_moss_policy_cache"


class PolicyCache:
    """Session 级别的 policy 缓存，支持文件持久化"""

    def __init__(self, config: CacheConfig | None = None):
        self._config = config or get_default_config().cache
        self._memory_cache: OrderedDict[str, str] = OrderedDict()
        self._lock = threading.Lock()

    def _cache_key(self, session_id: str, prompt_session: str) -> str:
        """生成缓存键：基于 session_id 和 prompt 内容"""
        return f"{session_id}::{prompt_session}"

    def _cache_file_path(self, session_id: str, prompt_session: str) -> Path:
        """生成缓存文件路径"""
        prompt_hash = hashlib.md5(prompt_session.encode()).hexdigest()[:12]
        safe_session_id = session_id.replace("/", "_").replace("\\", "_")
        return CACHE_DIR / safe_session_id / f"{prompt_hash}.toml"

    def get(self, session_id: str, prompt_session: str) -> str | None:
        """
        从缓存中获取 policy。

        优先级：
        1. 内存缓存（当前进程）
        2. 文件缓存（跨进程共享）

        Args:
            session_id: 会话唯一标识
            prompt_session: 用户输入的原始 prompt

        Returns:
            str | None: 缓存的 policy（TOML 格式字符串），未命中返回 None
        """
        if not self._config.enabled:
            return None

        key = self._cache_key(session_id, prompt_session)

        with self._lock:
            if key in self._memory_cache:
                self._memory_cache.move_to_end(key)
                return self._memory_cache[key]

        cache_file = self._cache_file_path(session_id, prompt_session)
        if cache_file.exists():
            try:
                policy = cache_file.read_text(encoding="utf-8")
                with self._lock:
                    self._memory_cache[key] = policy
                    self._memory_cache.move_to_end(key)
                    while len(self._memory_cache) > self._config.max_size:
                        self._memory_cache.popitem(last=False)
                return policy
            except Exception:
                pass

        return None

    def put(self, session_id: str, prompt_session: str, policy: str) -> None:
        """
        将生成的 policy 存入缓存（内存 + 文件）。

        Args:
            session_id: 会话唯一标识
            prompt_session: 用户输入的原始 prompt
            policy: TOML 格式的 policy 字符串
        """
        if not self._config.enabled:
            return

        key = self._cache_key(session_id, prompt_session)

        with self._lock:
            if key in self._memory_cache:
                self._memory_cache.move_to_end(key)
            self._memory_cache[key] = policy
            while len(self._memory_cache) > self._config.max_size:
                self._memory_cache.popitem(last=False)

        cache_file = self._cache_file_path(session_id, prompt_session)
        try:
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(policy, encoding="utf-8")
        except Exception:
            pass

    def invalidate(self, session_id: str, prompt_session: str) -> None:
        """
        使指定 session + prompt 的 policy 缓存失效。

        Args:
            session_id: 会话唯一标识
            prompt_session: 用户输入的原始 prompt
        """
        key = self._cache_key(session_id, prompt_session)
        with self._lock:
            self._memory_cache.pop(key, None)

        cache_file = self._cache_file_path(session_id, prompt_session)
        try:
            cache_file.unlink(missing_ok=True)
        except Exception:
            pass

    def invalidate_session(self, session_id: str) -> None:
        """
        使指定 session 的所有 policy 缓存失效。

        Args:
            session_id: 会话唯一标识
        """
        with self._lock:
            keys_to_remove = [k for k in self._memory_cache if k.startswith(f"{session_id}::")]
            for key in keys_to_remove:
                del self._memory_cache[key]

        safe_session_id = session_id.replace("/", "_").replace("\\", "_")
        session_dir = CACHE_DIR / safe_session_id
        try:
            if session_dir.exists():
                for f in session_dir.iterdir():
                    f.unlink()
                session_dir.rmdir()
        except Exception:
            pass

    def clear(self) -> None:
        """清空所有缓存"""
        with self._lock:
            self._memory_cache.clear()

        try:
            if CACHE_DIR.exists():
                for session_dir in CACHE_DIR.iterdir():
                    for f in session_dir.iterdir():
                        f.unlink()
                    session_dir.rmdir()
        except Exception:
            pass

    def size(self) -> int:
        """返回当前内存缓存条目数"""
        with self._lock:
            return len(self._memory_cache)


_default_cache: PolicyCache | None = None


def get_default_cache() -> PolicyCache:
    """获取全局默认缓存实例（延迟初始化）"""
    global _default_cache
    if _default_cache is None:
        _default_cache = PolicyCache()
    return _default_cache