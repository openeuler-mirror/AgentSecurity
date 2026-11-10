"""路径解析 — 统一数据根目录 + 多实例(instance)隔离。

解决两个问题：
1. **数据归属用户目录**：即使服务以 root/systemd 运行（sudo systemctl 起），
   也可通过 AGENT_MOSS_DATA_DIR 环境变量指向"当前用户"的数据目录，让
   config / runtime / token 都写到该用户目录而非 root 的 /root。
   未设时回退 Path.home()/.config/agentmoss（与旧行为一致）。

2. **token 按 instance 隔离**：不同 agent（AGENT_MOSS_INSTANCE）起的服务，
   token 消耗文件互不干扰。有 instance 时写到
   <data_root>/<instance>/agent_moss_token_stats.json，无 instance 时写到
   <data_root>/agent_moss_token_stats.json（保持默认位置）。

config / runtime 不按 instance 分（规则/配置是共享的），只跟随数据根目录。
"""

import os
import sys
from pathlib import Path

# 数据根目录环境变量（service/env 注入，解决 root→当前用户问题）
ENV_DATA_ROOT = "AGENT_MOSS_DATA_DIR"

# 归属实例标识（spawn/systemd 注入，多实例隔离用）
ENV_INSTANCE = "AGENT_MOSS_INSTANCE"

# 默认数据根目录（旧行为兼容）
DEFAULT_DATA_ROOT = Path.home() / ".config" / "agentmoss"


def _is_root() -> bool:
    """当前进程是否以 root 运行。"""
    try:
        return os.geteuid() == 0
    except (AttributeError, OSError):
        return False


def _resolve_owner_home() -> Path | None:
    """root 运行时探测"真实用户"的家目录。

    依赖顺序：SUDO_USER（sudo 发起者）> LOGNAME/USER（登录用户）>
    /etc/passwd 中第一个 UID>=1000 的非系统用户。探测不到返回 None。
    这样任何 `sudo systemctl start` 起的服务，即使 env 未设 AGENT_MOSS_DATA_DIR，
    数据也落到真实用户目录而非 /root。
    """
    for name in (os.getenv("SUDO_USER"), os.getenv("LOGNAME"), os.getenv("USER")):
        if _is_owner(name):
            return _home_of(name)
    # /etc/passwd 兜底：第一个 UID>=1000 的普通用户
    try:
        import pwd
        for u in pwd.getpwall():
            if u.pw_uid >= 1000 and not u.pw_name.startswith("_"):
                return Path(u.pw_dir)
    except Exception:
        pass
    return None


def _is_owner(name) -> bool:
    return bool(name) and name not in ("root", "")


def _home_of(name) -> Path | None:
    try:
        import pwd
        return Path(pwd.getpwnam(name).pw_dir)
    except Exception:
        return None


def get_data_root() -> Path:
    """获取数据根目录。

    优先级：env AGENT_MOSS_DATA_DIR > Path.home()/.config/agentmoss。
    但 root 运行时（任何 sudo systemctl 起的服务）自动改指向真实用户目录，
    让 config / runtime / token 落到当前用户而非 /root。
    """
    env_path = os.getenv(ENV_DATA_ROOT)
    if env_path:
        return Path(env_path)
    if _is_root():
        owner_home = _resolve_owner_home()
        if owner_home:
            return owner_home / ".config" / "agentmoss"
    return DEFAULT_DATA_ROOT


def get_instance() -> str:
    """获取归属实例标识（未设返回空串）。"""
    return os.getenv(ENV_INSTANCE, "").strip().strip("/\\")


def get_config_dir() -> Path:
    """配置文件目录（config.json 所在目录）。不按 instance 分，跟随数据根。"""
    return get_data_root()


def get_runtime_config_dir() -> Path:
    """runtime 配置目录（agent_moss_runtime.json + skills 目录）。不按 instance 分。"""
    return get_data_root()


def get_token_stats_path() -> Path:
    """token 统计文件路径。

    有 instance → <data_root>/<instance>/agent_moss_token_stats.json
    无 instance → <data_root>/agent_moss_token_stats.json
    """
    instance = get_instance()
    if instance:
        return get_data_root() / instance / "agent_moss_token_stats.json"
    return get_data_root() / "agent_moss_token_stats.json"