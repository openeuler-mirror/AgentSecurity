"""OS Profile 工厂 — 根据操作系统类型获取对应的 Profile 实例"""

import platform
from .base import OSProfile

_profile_cache: dict[str, OSProfile] = {}


def get_profile(os_type: str = "") -> OSProfile:
    """获取 OS Profile 实例（带缓存）

    如果未指定 os_type，自动检测当前操作系统。

    Args:
        os_type: 操作系统类型字符串，如 "linux"、"windows"。为空时自动检测。

    Returns:
        OSProfile: 对应操作系统的 Profile 实例

    Raises:
        ValueError: 不支持的 os_type
    """
    if not os_type:
        raw = platform.system().lower()
        if raw == "windows":
            os_type = "windows"
        else:
            os_type = "linux"

    if os_type not in _profile_cache:
        if os_type == "windows":
            from .windows import WindowsProfile
            _profile_cache[os_type] = WindowsProfile()
        elif os_type == "linux":
            from .linux import LinuxProfile
            _profile_cache[os_type] = LinuxProfile()
        else:
            raise ValueError(f"不支持的操作系统类型: {os_type}")

    return _profile_cache[os_type]


def clear_profile_cache() -> None:
    """清空 Profile 缓存（用于测试或配置热加载）"""
    _profile_cache.clear()


__all__ = [
    "OSProfile",
    "get_profile",
    "clear_profile_cache",
]
