"""日志工具 — 记录每次 agent_moss 调用的输入、LLM 交互、决策结果和耗时

使用标准库 logging + RotatingFileHandler 实现，不再依赖 loguru，便于在
openEuler 等仅提供官方源的环境下纯 dnf 安装（loguru 不在官方源中）。

兼容性说明：
- 其余模块统一用 `logging.getLogger(__name__)` 获取各自 logger，
  本模块通过配置根 logger（"agent_moss"）+ propagate 即可统一控制级别与 sink。
- MossLogger 类内部也使用 logging.getLogger，接口（info/debug/warning/exception）
  与原 loguru 用法一致。
"""

import logging
import logging.handlers
import sys
import time
from typing import Any

from .config import get_default_config

# 模块级 logger：MossLogger 内部使用，与各模块 logger 共享根配置。
# 注意：这里不导出全局 logger 供其它文件用——其它文件按 stdlib 惯例
# `logger = logging.getLogger(__name__)` 自行获取。
_logger = logging.getLogger("agent_moss")

# 日志格式：时间 | 级别 | 模块:函数:行号 - 消息（对齐 loguru 原格式字段）
_FILE_FORMAT = (
    "%(asctime)s | %(levelname)-8s | %(name)s:%(funcName)s:%(lineno)d - %(message)s"
)
_FILE_DATEFMT = "%Y-%m-%d %H:%M:%S"

# 控制台格式：时间 | 级别 | 消息（对应 loguru 控制台精简格式，去掉彩色标记）
_CONSOLE_FORMAT = "%(asctime)s | %(levelname)-8s | %(message)s"

_CONFIGURED = False


def setup_logger(log_level: str | None = None) -> None:
    """
    初始化日志配置。

    配置根 logger "agent_moss" 的两个 sink：
    1. RotatingFileHandler → agent_moss.log（10MB 轮转，保留 7 天对应的 7 个备份）
    2. StreamHandler → stderr（替代原 loguru 的 print sink）

    幂等：重复调用不会叠加 handler。

    Args:
        log_level: 日志级别，为 None 时使用默认配置
    """
    global _CONFIGURED

    level = log_level or get_default_config().log_level
    root = logging.getLogger("agent_moss")
    root.setLevel(level)

    # 幂等：已配置过则只更新级别，避免重复 handler 导致日志重复输出
    if _CONFIGURED:
        root.setLevel(level)
        return

    # 清除既有 handler（对应 loguru 的 logger.remove()）
    for h in list(root.handlers):
        root.removeHandler(h)

    # 1. 文件 sink：10MB 轮转，保留 7 个备份（对应 loguru rotation="10 MB", retention="7 days"）
    file_handler = logging.handlers.RotatingFileHandler(
        filename="agent_moss.log",
        maxBytes=10 * 1024 * 1024,
        backupCount=7,
        encoding="utf-8",
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(
        logging.Formatter(_FILE_FORMAT, datefmt=_FILE_DATEFMT)
    )
    root.addHandler(file_handler)

    # 2. 控制台 sink：输出到 stderr（对应 loguru 的 print sink）
    # 服务端日志通常无需彩色，去掉 colorize；如需可加 colorama。
    console_handler = logging.StreamHandler(stream=sys.stderr)
    console_handler.setLevel(level)
    console_handler.setFormatter(
        logging.Formatter(_CONSOLE_FORMAT, datefmt=_FILE_DATEFMT)
    )
    root.addHandler(console_handler)

    _CONFIGURED = True


class MossLogger:
    """agent_moss 日志记录器，记录单次 agent_moss 调用的完整过程"""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.start_time = time.monotonic()
        self.step_times: dict[str, float] = {}
        self._step_start: float | None = None
        self._current_step: str | None = None

    def log_input(self, prompt_session: str, action_history: list[dict], a_next: dict, reason: str) -> None:
        """记录工具输入"""
        _logger.info(
            f"[{self.session_id}] agent_moss 输入 | "
            f"prompt={prompt_session[:100]}... | "
            f"历史动作数={len(action_history)} | "
            f"下一步动作={a_next.get('action_type', '?')}:{a_next.get('action_detail', '?')[:80]} | "
            f"理由={reason[:80]}"
        )

    def start_step(self, step_name: str) -> None:
        """开始计时某个步骤"""
        self._current_step = step_name
        self._step_start = time.monotonic()
        _logger.debug(f"[{self.session_id}] 开始步骤: {step_name}")

    def end_step(self, step_name: str, detail: str = "") -> None:
        """结束计时某个步骤"""
        if self._step_start is not None:
            elapsed = time.monotonic() - self._step_start
            self.step_times[step_name] = elapsed
            detail_str = f" | {detail}" if detail else ""
            _logger.info(f"[{self.session_id}] 步骤完成: {step_name} | 耗时={elapsed:.3f}s{detail_str}")
            self._step_start = None
            self._current_step = None

    def log_llm_interaction(self, step: str, prompt_summary: str, response_summary: str) -> None:
        """记录 LLM 交互内容"""
        _logger.debug(
            f"[{self.session_id}] LLM交互 | 步骤={step} | "
            f"PROMPT摘要={prompt_summary[:200]} | "
            f"响应摘要={response_summary[:200]}"
        )

    def log_result(self, decision: str, reason: str, policy: str = "") -> None:
        """记录最终决策结果"""
        total_time = time.monotonic() - self.start_time
        steps_info = ", ".join(f"{k}={v:.3f}s" for k, v in self.step_times.items())
        _logger.info(
            f"[{self.session_id}] agent_moss 结果 | 决策={decision} | "
            f"理由={reason[:150]} | "
            f"步骤耗时=[{steps_info}] | 总耗时={total_time:.3f}s"
        )
        if policy:
            _logger.debug(f"[{self.session_id}] 生成的Policy:\n{policy}")

    def log_error(self, step: str, error: Exception) -> None:
        """记录错误"""
        _logger.error(f"[{self.session_id}] 步骤异常: {step} | 错误={type(error).__name__}: {error}")
