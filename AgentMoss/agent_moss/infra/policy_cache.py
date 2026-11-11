"""Session 级别 Policy 缓存管理

同一 session 中同一 prompt 对应的 policy 只生成一次，后续从缓存读取。
缓存持久化到文件系统，支持跨进程共享。

缓存文件路径: /tmp/agent_moss_policy_cache/{session_id}/{hash(prompt_session)}.toml
"""

import hashlib
import os
import tempfile
import logging
import threading
from collections import OrderedDict
from pathlib import Path

from .config import CacheConfig, get_default_config

logger = logging.getLogger(__name__)

CACHE_DIR = Path(tempfile.gettempdir()) / "agent_moss_policy_cache"


def _safe_cache_dir() -> Path:
    """返回可安全使用的缓存目录（2026-10 安全加固）。

    ``/tmp`` 下的固定目录是**可被任何本机用户预先创建/替换**的。原实现直接
    ``mkdir(exist_ok=True)`` + ``write_text``，于是别人可以：
      - 先把目录换成符号链接 → 我们的写入跟着落到他指定的位置；
      - 预置同名 policy 文件 → 我们读到伪造的策略；
      - 直接读 0644 的缓存文件 → 拿到别的会话的 policy。

    这里做三件事：目录必须由当前用户拥有、不是符号链接、权限收紧到 0700。
    不满足就**回退到数据目录下的私有目录**（仍然可用，只是换了个位置），
    并打一条警告 —— 正常环境下路径与以前完全一致。
    """
    from . import security_policy as sp
    if sp.ensure_private_dir(CACHE_DIR):
        return CACHE_DIR
    try:
        from .paths import get_data_root
        fallback = get_data_root() / "policy_cache"
        if sp.ensure_private_dir(fallback):
            logger.warning(
                "缓存目录 %s 不安全（被其他用户拥有或为符号链接），已回退到 %s",
                CACHE_DIR, fallback,
            )
            return fallback
    except Exception:  # noqa: BLE001
        pass
    return CACHE_DIR


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
        safe_session_id = session_id.replace("/", "_").replace("\\", "_").replace("..", "__")
        return _safe_cache_dir() / safe_session_id / f"{prompt_hash}.toml"

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
        # 拒绝读取符号链接（防"别人把缓存文件换成指向敏感文件的链接"）
        if cache_file.exists() and not cache_file.is_symlink():
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
            from . import security_policy as sp
            if not sp.ensure_private_dir(cache_file.parent):
                return
            sp.write_private_text(cache_file, policy)
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

        safe_session_id = session_id.replace("/", "_").replace("\\", "_").replace("..", "__")
        session_dir = _safe_cache_dir() / safe_session_id
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
            _cd = _safe_cache_dir()
            if _cd.exists():
                for session_dir in _cd.iterdir():
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