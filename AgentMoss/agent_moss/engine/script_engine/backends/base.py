"""脚本分析引擎 — Language Backend 抽象基类。

Backend 职责：把源脚本内容解析成统一 IR（ScriptIR）。
- 只做静态文本分析，不执行脚本。
- 产出 reachable_content（能证明的可达部分）+ calls（子脚本调用，含参数）。
- 无法解析时返回 IR(control_flow_resolved=False)，调用方回退全文本（fail-closed）。

加新语言 = 新建子类实现 parse()，Scanner/Tracker 无需改动。
"""

from abc import ABC, abstractmethod

from ..ir import ScriptIR


class LanguageBackend(ABC):
    """脚本语言后端抽象。"""

    #: 后端对应的语言标识（shell/python/node/...）
    language: str = "unknown"

    #: 入口命令的脚本调用识别（正则集），由入口命令 -> backend 分派时用
    #: 如 "^(?:python3?)\s+(\S+\.py)" 等。
    ENTRY_PATTERNS: list[str] = []

    @abstractmethod
    def parse(self, content: str, entry_args: list[str] | None) -> ScriptIR:
        """把脚本内容解析成 IR。

        Args:
            content: 脚本原始内容
            entry_args: 入口命令携带的参数（如 bash x.sh backup → ["backup"]），
                用于分支选择（$1 等）。None 表示无参数。
        Returns:
            ScriptIR
        """
        raise NotImplementedError

    def extract_calls(self, content: str) -> list:  # 在 RecursiveTracker 中实现
        """由具体后端提供子脚本调用提取（路径+参数）。"""
        raise NotImplementedError