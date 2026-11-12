"""OS Profile 工厂 — 根据操作系统类型获取对应的 Profile 实例"""

import logging
import platform
from .base import OSProfile

logger = logging.getLogger(__name__)

_profile_cache: dict[str, OSProfile] = {}


def get_profile(os_type: str = "") -> OSProfile:
    """获取 OS Profile 实例（带缓存）

    如果未指定 os_type，自动检测当前操作系统。

    四套规则集：Windows（cmd/注册表/del/icacls 等专属规则）、macOS
    （Linux 通用规则 + SIP/Gatekeeper/launchctl/钥匙串等专属补充）、
    **HarmonyOS**（Linux 通用规则 + bm/aa/param/hdc 等鸿蒙专属补充，
    2026-09 新增）、**linux 兜底**。openEuler / 麒麟 Kylin / 统信 UOS 等
    国产系统本身就是 Linux 发行版，命令体系一致；HarmonyOS 用 Toybox
    （类 Unix 命令集），rm -rf、敏感路径读写等通用操作仍受 Linux 规则覆盖。
    未知名系统兜底归 linux，好过整个请求失败。

    Args:
        os_type: 操作系统类型字符串，如 "linux"、"windows"、"macos"、
            "harmony"。为空时自动检测（platform.system()："Windows"→windows，
            "Darwin"→macos，其余→linux）。别名 darwin/mac/osx 归一化为 macos，
            hmos/openharmony 归一化为 harmony；未知名兜底为 linux。

    Returns:
        OSProfile: 对应操作系统的 Profile 实例
    """
    if not os_type:
        raw = platform.system().lower()
        if raw == "windows":
            os_type = "windows"
        elif raw == "darwin":
            os_type = "macos"  # macOS 的 platform.system() 返回 "Darwin"
        else:
            os_type = "linux"
    else:
        os_type = os_type.strip().lower()
        # 别名归一化：平台自报名与常见写法统一到规范值
        if os_type in ("darwin", "mac", "macosx", "osx"):
            os_type = "macos"
        if os_type in ("hmos", "openharmony", "hongmeng"):
            os_type = "harmony"

    if os_type not in ("linux", "windows", "macos", "harmony"):
        logger.warning(
            "未知的操作系统类型 %r，按 linux 处理（非 Windows/macOS/HarmonyOS 一律用类 Unix 规则集）",
            os_type,
        )
        os_type = "linux"

    if os_type not in _profile_cache:
        if os_type == "windows":
            from .windows import WindowsProfile
            _profile_cache[os_type] = WindowsProfile()
        elif os_type == "macos":
            from .macos import MacOSProfile
            _profile_cache[os_type] = MacOSProfile()
        elif os_type == "harmony":
            from .harmony import HarmonyProfile
            _profile_cache[os_type] = HarmonyProfile()
        else:
            from .linux import LinuxProfile
            _profile_cache[os_type] = LinuxProfile()

    return _profile_cache[os_type]


def clear_profile_cache() -> None:
    """清空 Profile 缓存（用于测试或配置热加载）"""
    _profile_cache.clear()


__all__ = [
    "OSProfile",
    "get_profile",
    "clear_profile_cache",
]
