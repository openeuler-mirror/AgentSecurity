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
import re
import sys
from pathlib import Path

# 数据根目录环境变量（service/env 注入，解决 root→当前用户问题）
ENV_DATA_ROOT = "AGENT_MOSS_DATA_DIR"

# 归属实例标识（spawn/systemd 注入，多实例隔离用）
ENV_INSTANCE = "AGENT_MOSS_INSTANCE"

# 默认数据根目录（旧行为兼容）
DEFAULT_DATA_ROOT = Path.home() / ".config" / "agentmoss"

#: 规则/技能资产根目录（**规则仓剥离**后的落点）。
#: 目录结构必须与包内 `agent_moss/` 一致：`rules/` `skills/` `scenarios/` `agents/`。
#: 未设 → 用包内自带的那份（即历史行为，完全不变）。
ENV_RULES_ROOT = "AGENT_MOSS_RULES_ROOT"

#: 包内资产目录的父目录（`agent_moss/`）。
_PACKAGE_ASSET_ROOT = Path(__file__).parent.parent

#: agent_id / scenario_id 的合法形态。
#:
#: ⚠️ 为什么必须校验：这两个 id **由调用方自报**，并且会被直接拼进文件路径
#: （`agents/<id>/rules.json`、`scenarios/<id>/rules.json`）。
#: 不校验时 `agent_id="../../.."` 就能让 AgentMoss 去加载任意位置的 `rules.json`
#: （把攻击者控制的 JSON 当成规则集 = 直接削弱检测），同时把自报字符串塞进
#: 无界缓存（内存 DoS）。只允许字母数字下划线连字符，长度 ≤ 64。
#: 与 TS 侧 `isSafeId()` 必须完全一致。
_ID_MAX_LEN = 64
_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")


def is_safe_id(value: str) -> bool:
    """``agent_id`` / ``scenario_id`` 是否可以安全地用于拼接文件路径。"""
    if not value or len(value) > _ID_MAX_LEN:
        return False
    return bool(_ID_PATTERN.match(value))


def get_rules_root() -> Path | None:
    """规则包根目录；未设或为空 → None（表示用包内资产）。"""
    raw = os.environ.get(ENV_RULES_ROOT, "").strip()
    return Path(raw).expanduser() if raw else None


def asset_dir(name: str) -> Path:
    """解析资产目录：``rules`` / ``skills`` / ``scenarios`` / ``agents``。

    - 设了 ``AGENT_MOSS_RULES_ROOT`` → ``<root>/<name>``。**不检查是否存在**：
      指了个缺文件的坏目录就让各自的加载器报错，不要静默回退到包内副本
      （否则客户以为在用自家规则，实际跑的是内置那份）。
    - 未设 → 包内 ``agent_moss/<name>``，与历史行为逐字一致。

    ⚠️ 每次调用都读环境变量（不缓存）：测试用 monkeypatch 改完立即生效。
    """
    root = get_rules_root()
    return (root / name) if root is not None else (_PACKAGE_ASSET_ROOT / name)


def _is_root() -> bool:
    """当前进程是否以 root 运行。"""
    try:
        return os.geteuid() == 0
    except (AttributeError, OSError):
        return False


def _resolve_explicit_owner_home() -> Path | None:
    """只按显式环境变量解析「真实用户」家目录（SUDO_USER > LOGNAME/USER）。

    不查 /etc/passwd —— 多用户机器上「第一个 UID>=1000」不一定是调用方。
    systemd 直接起的服务通常这三个都为空。
    """
    for name in (os.getenv("SUDO_USER"), os.getenv("LOGNAME"), os.getenv("USER")):
        if _is_owner(name):
            return _home_of(name)
    return None


def _list_owner_homes() -> list[Path]:
    """所有普通用户（UID>=1000、非系统账户）的家目录。"""
    homes: list[Path] = []
    try:
        import pwd
        for u in pwd.getpwall():
            if u.pw_uid >= 1000 and not u.pw_name.startswith("_"):
                homes.append(Path(u.pw_dir))
    except Exception:
        pass
    return homes


def _resolve_owner_home() -> Path | None:
    """root 运行时探测"真实用户"的家目录（兼容保留，**不再用于数据目录**）。

    ⚠️ 2026-11 起 `get_data_root()` 不再调用本函数：root 下数据（含 token）
    固定落 `/root/.config/agentmoss`。原因是猜测会把 token（0600）暴露给
    与 AgentMoss 无关的普通用户，且多用户机器上「第一个 UID>=1000」与调用方
    毫无关系 —— AgentGate 按同一规则读 /root 时还会因路径不一致导致 401。

    依赖顺序（仅本函数内部使用）：SUDO_USER > LOGNAME/USER >
    /etc/passwd 中第一个 UID>=1000 的非系统用户。探测不到返回 None。

    安全边界（如 log_roots 白名单）必须用 `_resolve_explicit_owner_home` +
    `_list_owner_homes` 做分级判定，不能直接用它。
    """
    explicit = _resolve_explicit_owner_home()
    if explicit is not None:
        return explicit
    owners = _list_owner_homes()
    return owners[0] if owners else None


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

    root（含 sudo systemctl）启动时数据就落在 /root/.config/agentmoss ——
    **不再**按 SUDO_USER / LOGNAME / /etc/passwd 猜测"真实用户"：
    - 猜错会把 token（0600）暴露给一个与 AgentMoss 无关的普通用户；
    - 多用户机器上"第一个 UID>=1000"与调用方毫无关系；
    - 只有 SUDO_USER 是"sudo 代启"的可靠证据，systemd 启动时它也不存在。

    非 root 用户要访问 root 服务的数据（含 token）时显式传入：
    AGENT_MOSS_AUTH_TOKEN / AGENT_MOSS_AUTH_TOKEN_FILE / AGENT_MOSS_DATA_DIR。
    """
    env_path = os.getenv(ENV_DATA_ROOT)
    if env_path:
        return Path(env_path)
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