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
import unicodedata
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

#: 需要转义的 Unicode 类别：
#:   Cc 控制字符（\n \r \t，以及 ANSI 转义 \x1b）
#:   Cf 格式字符（零宽空格 U+200B、双向控制符 U+202E 等，肉眼不可见）
#:   Cs 代理对 / Co 私用区 / Cn 未分配
_INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})


def _safe(text: Any, limit: int | None = None) -> str:
    """把**调用方可控**的文本转成日志安全形式（防日志注入 / 伪造）。

    为什么需要（2026-09-29 实测）：日志是审计留痕，不能让被审计的内容反过来伪造它。
    一条被分析的命令里放一个 ``\\n``，就能把日志劈成两行，**第二行看起来就是一条
    正常记录** —— 实测可伪造出「echo FAKE-日志行: 判定=Allow action=rm -rf /」这种
    假行；``\\r`` 会覆盖本行内容；ANSI 转义（``\\x1b[...]``）能让终端/查看器显示
    错乱；零宽字符则完全不可见。判定结果不受影响，但审计留痕可被污染。

    实现上**逐字符**转义而非整串 ``unicode_escape``：后者会把中文也变成
    ``\\u4f60\\u597d``，日志就没法读了；这里只动不可见字符，可打印字符保持原样，
    输出仍是可读文本且对任何 stdout 编码都安全（转义结果全是 ASCII）。

    Args:
        text: 任意值（None 视为空串）。
        limit: 先按此长度截断（与调用点原有的 ``[:N]`` 语义一致），再转义。

    Returns:
        转义后的字符串。
    """
    s = "" if text is None else str(text)
    if limit is not None:
        s = s[:limit]
    if not s:
        return s
    out = []
    for ch in s:
        if unicodedata.category(ch) in _INVISIBLE_CATEGORIES:
            out.append(ch.encode("unicode_escape").decode("ascii"))
        else:
            out.append(ch)
    return "".join(out)


def _escape_arg(value: Any) -> Any:
    """只转义字符串参数；**非字符串原样返回** —— 否则 ``%d``/``%f`` 会因为拿到
    str 而格式化失败（日志直接报错，比注入还糟）。"""
    return _safe(value) if isinstance(value, str) else value


def _install_log_injection_guard() -> None:
    """把不可见字符转义**装到 LogRecord 工厂**上 —— 一次覆盖全仓所有日志调用点。

    为什么不在调用点转义：全仓有上百个 ``logger.xxx()``，且会持续新增
    （2026-09-29 实测就漏了 ``coordinator.py:370`` 的
    ``完全安全 bash 命令快速放行: command=%s``）；漏一个注入就成立。

    为什么不用 ``Logger.addFilter``：**filter 只在记录被创建的那个 logger 上跑**，
    父 logger 上的 filter 对子 logger（``agent_moss.engine.coordinator`` 等）无效
    —— 实测挂在 ``agent_moss`` 上，子 logger 的记录照样原样落盘。而 handler 上的
    filter / 自定义 Formatter 又依赖 `setup_logger` 被调用（调用方自己配 logging
    时就不生效）。LogRecord 工厂是**每条记录创建时**都会走的唯一入口，与"谁记的、
    谁来输出"都无关。

    改写 ``record.msg`` / ``record.args``，因此两种写法都覆盖：
    - f-string（内容已在 msg 里）
    - 惰性 ``%s`` 格式化（内容在 args 里，Formatter 才拼进去）

    只处理 ``agent_moss`` 命名空间下的记录，不碰调用方自己的日志；链式调用原工厂，
    不覆盖别人已注册的工厂。与 :func:`_safe` 同一套规则，对已转义内容无副作用。
    """
    prev_factory = logging.getLogRecordFactory()

    def _factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = prev_factory(*args, **kwargs)
        if record.name.startswith("agent_moss"):
            if isinstance(record.msg, str):
                record.msg = _safe(record.msg)
            if record.args:
                if isinstance(record.args, tuple):
                    record.args = tuple(_escape_arg(a) for a in record.args)
                elif isinstance(record.args, dict):
                    record.args = {k: _escape_arg(v) for k, v in record.args.items()}
        return record

    logging.setLogRecordFactory(_factory)


#: 导入即装（幂等：模块只加载一次）。
_install_log_injection_guard()


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
            f"[{_safe(self.session_id, 64)}] agent_moss 输入 | "
            f"prompt={_safe(prompt_session, 100)}... | "
            f"历史动作数={len(action_history)} | "
            f"下一步动作={_safe(a_next.get('action_type', '?'), 32)}:"
            f"{_safe(a_next.get('action_detail', '?'), 80)} | "
            f"理由={_safe(reason, 80)}"
        )

    def start_step(self, step_name: str) -> None:
        """开始计时某个步骤"""
        self._current_step = step_name
        self._step_start = time.monotonic()
        _logger.debug(f"[{_safe(self.session_id, 64)}] 开始步骤: {_safe(step_name, 48)}")

    def end_step(self, step_name: str, detail: str = "") -> None:
        """结束计时某个步骤"""
        if self._step_start is not None:
            elapsed = time.monotonic() - self._step_start
            self.step_times[step_name] = elapsed
            detail_str = f" | {_safe(detail)}" if detail else ""
            _logger.info(f"[{_safe(self.session_id, 64)}] 步骤完成: {_safe(step_name, 48)} | 耗时={elapsed:.3f}s{detail_str}")
            self._step_start = None
            self._current_step = None

    def log_llm_interaction(self, step: str, prompt_summary: str, response_summary: str) -> None:
        """记录 LLM 交互内容"""
        _logger.debug(
            f"[{_safe(self.session_id, 64)}] LLM交互 | 步骤={_safe(step, 48)} | "
            f"PROMPT摘要={_safe(prompt_summary, 200)} | "
            f"响应摘要={_safe(response_summary, 200)}"
        )

    def log_result(self, decision: str, reason: str, policy: str = "") -> None:
        """记录最终决策结果"""
        total_time = time.monotonic() - self.start_time
        steps_info = ", ".join(f"{_safe(k, 48)}={v:.3f}s" for k, v in self.step_times.items())
        _logger.info(
            f"[{_safe(self.session_id, 64)}] agent_moss 结果 | 决策={_safe(decision, 16)} | "
            f"理由={_safe(reason, 150)} | "
            f"步骤耗时=[{steps_info}] | 总耗时={total_time:.3f}s"
        )
        if policy:
            _logger.debug(f"[{_safe(self.session_id, 64)}] 生成的Policy:\n{_safe(policy)}")

    def log_error(self, step: str, error: Exception) -> None:
        """记录错误"""
        _logger.error(f"[{_safe(self.session_id, 64)}] 步骤异常: {_safe(step, 48)} | "
                     f"错误={type(error).__name__}: {_safe(error)}")

