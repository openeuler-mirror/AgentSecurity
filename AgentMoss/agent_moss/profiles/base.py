"""OS Profile 抽象基类 — 定义操作系统安全检测 Profile 的接口

每个 OS Profile 提供了特定操作系统的：
- 危险命令正则模式
- 安全命令白名单
- 敏感路径列表
- 路径提取方法
- 读写关键词
- 意图偏离检测模式
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from functools import cached_property
from typing import Any
import re


@dataclass
class CommandPattern:
    """危险命令检测模式"""
    pattern: str         # 正则表达式
    risk_level: str      # low / medium / high / critical
    risk_type: str       # file_access / script_execution / data_exfiltration / ...
    reason: str          # 命中时的描述
    #: 条目的**原始平台归属**（"linux" / "windows" / "macos"；空视为 linux）。
    #: 注意与"加载它的 Profile"不同：MacOSProfile 继承 Linux 规则，加载到的
    #: Linux 条目 os 仍是 "linux" —— 生成 runtime 种子时据此去重/标记，
    #: 避免 macOS 把 Linux 条目重复写成自己的一份。
    os: str = ""


@dataclass
class SensitivePath:
    """敏感路径条目"""
    path: str
    risk_level: str = "high"      # low / medium / high / critical
    desc: str = ""
    credential: bool = False  # 凭据文件：无论读写都拦截（向后兼容，建议用 deny_mode）
    read_only: bool = False   # 只读危险：仅拦截读取，写入放行（向后兼容，建议用 deny_mode）
    deny_mode: str = ""       # 拦截模式：deny_write / deny_read / deny_both，优先于 credential/read_only
    dir_del_only: bool = False  # 目录级条目标记：仅拦截「删除」该目录本身/其下内容（rm -rf ~/.ssh）；
    #   目录创建（mkdir -p ~/.ssh）、目录内非删除写操作（chmod 700 ~/.ssh、echo >> known_hosts）
    #   放行——避免 SSH/AWS 目录初始化被 chmod 等写判定误拦（NEW-FP-1），目录内文件细粒度
    #   读写由具体路径条目（.ssh/id_rsa、.aws/credentials 等）独立兜底。需搭配 deny_write。
    #: 条目的**原始平台归属**（"linux" / "windows" / "macos"；空视为 linux）。
    #: 语义同 CommandPattern.os —— MacOSProfile 继承 Linux 规则时，加载到的
    #: Linux 条目 os 仍是 "linux"，生成 runtime 种子据此去重，不重复成 macos 条目。
    os: str = ""


@dataclass
class IntentDeviationPattern:
    """意图偏离关键词对"""
    intent_keywords: list[str]        # prompt_session 中的意图关键词
    dangerous_actions: list[str]      # a_next 中不应出现的危险关键词
    reason: str                       # 命中时的描述
    os: str = ""                      # 原始平台归属，语义同 CommandPattern.os


class OSProfile(ABC):
    """操作系统安全检测 Profile 抽象基类"""

    #: 本 Profile 接受的规则条目 os 值 —— JSON 条目的 ``os`` 字段命中其一才加载。
    #: - LinuxProfile：``("linux",)``
    #: - WindowsProfile：``("windows",)``
    #: - MacOSProfile：``("linux", "macos")``（macOS 与 Linux 同为 Unix 系，
    #:   通用规则直接继承，只额外叠加 macOS 专属安全面）
    #: 不带 ``os`` 字段的历史条目视为 linux，由各过滤点统一兜底。
    accepted_os: tuple[str, ...] = ("linux",)

    def accepts_os(self, os_value: str | None) -> bool:
        """某条规则的 ``os`` 字段是否适用于本平台。

        - ``"all"`` → **全平台通用**，恒通过；
        - 不带 ``os`` 字段的历史条目 → 视为 ``linux``（沿用既有约定）；
        - 其余按 ``accepted_os`` 判（macOS/鸿蒙继承 linux）。

        与 ``infra/runtime_config._rules_for_os`` 的过滤口径必须一致 ——
        种子（profile 侧）与运行时（runtime 侧）读同一份数据、用同一套语义。
        """
        v = str(os_value or "linux").lower()
        return v == "all" or v in self.accepted_os

    # ─── 平台命令集（Platform Traits）───
    #
    # 单一事实源：``rules/platform_traits.json``（Python 与 TS 读同一份）。
    # 这批"放行/豁免边界"原先硬编码在本文件与 ``profiles/{linux,windows}.py`` 里；
    # 2026-10 迁到 JSON —— 逐字搬移、判定零变化，
    # 目的是让规则仓剥离时这批数据能整体搬走。
    # 字段语义见 ``rules/platform_traits.json`` 的 ``_comment``；
    # macos / harmony 走 JSON 的 ``{"inherits": "linux"}``（同为类 Unix 命令集）。

    @cached_property
    def _traits(self) -> dict[str, Any]:
        """本平台的原始平台特征（已解析继承；键见 ``rules_loader.TRAITS_FIELDS``）。"""
        from ..rules_loader import load_platform_traits
        return load_platform_traits(self.os_type)

    @property
    def write_command_res(self) -> list["re.Pattern"]:
        """写/删命令词边界正则（is_write_operation 用）。"""
        return [re.compile(p) for p in self._traits.get("write_command_res", [])]

    @property
    def read_only_commands(self) -> set[str]:
        """只读命令集合（重定向写判定用）。"""
        return set(self._traits.get("read_only_commands", []))

    @property
    @abstractmethod
    def os_type(self) -> str:
        """返回 'linux' / 'windows' / 'macos'"""
        ...

    # ─── 层1：特征匹配检测 ───

    @property
    @abstractmethod
    def dangerous_commands(self) -> list[CommandPattern]:
        """危险命令正则模式列表"""
        ...

    # ── 以下 6 项来自 rules/platform_traits.json（原先各平台硬编码覆盖，现统一读 JSON）──

    @property
    def safe_commands(self) -> list[str]:
        """安全白名单命令正则列表（只读、低风险，向后兼容）。

        注意语义：**不是** json 里的字段，而是两项之和（与迁移前 linux.py 的实现一致）。
        """
        return self.fully_safe_commands + self.readonly_sensitive_commands

    @property
    def fully_safe_commands(self) -> list[str]:
        """完全安全的 bash 子命令正则列表（跳过 L2 + L3，不涉及文件内容读取）"""
        return list(self._traits.get("fully_safe_commands", []))

    @property
    def readonly_sensitive_commands(self) -> list[str]:
        """安全但可能访问敏感路径的 bash 子命令正则列表（跳过 L3，保留 L2）"""
        return list(self._traits.get("readonly_sensitive_commands", []))

    @property
    def safe_action_types(self) -> frozenset[str]:
        """完全安全操作类型白名单（跳过 L2 + L3）"""
        return frozenset(self._traits.get("safe_action_types", []))

    @property
    def readonly_sensitive_action_types(self) -> frozenset[str]:
        """安全但可能访问敏感路径的操作类型（跳过 L3，保留 L2）"""
        return frozenset(self._traits.get("readonly_sensitive_action_types", []))

    @cached_property
    def injection_keywords(self) -> list[dict]:
        """Prompt 注入检测关键词列表（归一化自 ``rules/l1_rules.json`` 的注入段）。

        各平台实现**完全相同**，故收拢在基类（分开写就是漂移源：Windows 此前
        自带一份 14 条的硬编码副本，与 JSON 的 48 条形成双向分叉，2026-10 修）。

        按 ``os`` 过滤：注入攻击与操作系统无关，通用条目在 JSON 里标
        ``os: "all"``（各平台都生效），平台独有的标具体平台。
        **不能不过滤**（Windows 会拿到不该给它的条目），**也不能把通用条目标成
        ``linux``**（Windows 会被过滤成一条不剩，静默回退到各自的兜底默认）。
        """
        from ..rules_loader import load_l1
        kws = load_l1().get("injection_detection", [])
        return [k for k in kws if self.accepts_os(k.get("os"))]

    # ─── 层2：逻辑规则检测 ───

    @property
    @abstractmethod
    def sensitive_paths(self) -> list[SensitivePath]:
        """敏感路径列表"""
        ...

    @property
    def write_keywords(self) -> list[str]:
        """写入操作关键词"""
        return list(self._traits.get("write_keywords", []))

    @property
    def read_keywords(self) -> list[str]:
        """读取操作关键词"""
        return list(self._traits.get("read_keywords", []))

    @property
    @abstractmethod
    def intent_deviation_patterns(self) -> list[IntentDeviationPattern]:
        """意图偏离关键词对"""
        ...

    @abstractmethod
    def extract_file_paths(self, text: str) -> list[str]:
        """从文本中提取文件路径（OS 特定实现）"""
        ...
