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
import re


@dataclass
class CommandPattern:
    """危险命令检测模式"""
    pattern: str         # 正则表达式
    risk_level: str      # low / medium / high / critical
    risk_type: str       # file_access / script_execution / data_exfiltration / ...
    reason: str          # 命中时的描述


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


@dataclass
class IntentDeviationPattern:
    """意图偏离关键词对"""
    intent_keywords: list[str]        # prompt_session 中的意图关键词
    dangerous_actions: list[str]      # a_next 中不应出现的危险关键词
    reason: str                       # 命中时的描述


class OSProfile(ABC):
    """操作系统安全检测 Profile 抽象基类"""

    @property
    @abstractmethod
    def os_type(self) -> str:
        """返回 'linux' 或 'windows'"""
        ...

    # ─── 层1：特征匹配检测 ───

    @property
    @abstractmethod
    def dangerous_commands(self) -> list[CommandPattern]:
        """危险命令正则模式列表"""
        ...

    @property
    @abstractmethod
    def safe_commands(self) -> list[str]:
        """安全白名单命令正则列表（只读、低风险，向后兼容）"""
        ...

    @property
    @abstractmethod
    def fully_safe_commands(self) -> list[str]:
        """完全安全的 bash 子命令正则列表（跳过 L2 + L3，不涉及文件内容读取）"""
        ...

    @property
    @abstractmethod
    def readonly_sensitive_commands(self) -> list[str]:
        """安全但可能访问敏感路径的 bash 子命令正则列表（跳过 L3，保留 L2）"""
        ...

    @property
    @abstractmethod
    def safe_action_types(self) -> frozenset[str]:
        """完全安全操作类型白名单（跳过 L2 + L3）"""
        ...

    @property
    @abstractmethod
    def readonly_sensitive_action_types(self) -> frozenset[str]:
        """安全但可能访问敏感路径的操作类型（跳过 L3，保留 L2）"""
        ...

    @property
    @abstractmethod
    def injection_keywords(self) -> list[dict]:
        """Prompt 注入检测关键词列表"""
        ...

    # ─── 层2：逻辑规则检测 ───

    @property
    @abstractmethod
    def sensitive_paths(self) -> list[SensitivePath]:
        """敏感路径列表"""
        ...

    @property
    @abstractmethod
    def write_keywords(self) -> list[str]:
        """写入操作关键词"""
        ...

    @property
    @abstractmethod
    def read_keywords(self) -> list[str]:
        """读取操作关键词"""
        ...

    @property
    @abstractmethod
    def intent_deviation_patterns(self) -> list[IntentDeviationPattern]:
        """意图偏离关键词对"""
        ...

    @abstractmethod
    def extract_file_paths(self, text: str) -> list[str]:
        """从文本中提取文件路径（OS 特定实现）"""
        ...
