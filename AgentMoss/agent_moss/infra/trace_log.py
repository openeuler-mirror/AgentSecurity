"""分层追踪日志 —— L1/L2/L3 的完整输入输出（排障用）。

设计目标：出问题时**看一眼日志就能定位**，不用再猜"当时那条命令长什么样、
L2 哪条规则没命中、LLM 到底返回了什么"。

开关（环境变量 ``AGENT_MOSS_TRACE_LEVEL``）：

- ``off``（默认）：完全关闭。所有 trace 函数第一行判级别后立即返回，
  **不做字符串格式化**，开销是一次整数比较。
- ``summary``：每层判定 + 耗时 + 命中规则 ID/风险级别，不含正文。
  适合长期开着做运行监控，单请求约 5-10 行。
- ``full``：完整输入输出 —— 请求体、L1/L2 命中细节、L3 完整 prompt、
  LLM 原始响应（所有字段，不只是 content）。适合排障期短时开启。

与主日志的关系：

- 独立 logger（``agent_moss.trace``）、独立文件（``agent_moss_trace.log``）、
  独立轮转（20MB × 5）。**不**挂到 ``agent_moss`` 根 logger 上，避免被主日志
  级别过滤、也避免排障日志把主日志冲掉。
- 文件路径：``$AGENT_MOSS_TRACE_PATH`` > ``<data_root>/agent_moss_trace.log``。

安全与稳定性：

- 所有调用方可控文本经 ``_safe`` 转义（防日志注入 / 伪造审计行）。
- API key、token 等敏感字段由调用方**不要传进来**；本模块额外对
  ``api_key`` / ``authorization`` / ``token`` 键名做掩码兜底。
- 单字段上限 ``_MAX_FIELD_CHARS``（默认 64KB），超出截断并标注原长，
  防止一个超大 prompt 把磁盘写爆。
- 任何写日志异常都被吞掉：**排障日志绝不能影响主流程**。
"""

from __future__ import annotations

import contextvars
import json
import logging
import logging.handlers
import os
import time
from typing import Any

from .logging import _safe

# ==================== 级别 ====================

LEVEL_OFF = 0
LEVEL_SUMMARY = 1
LEVEL_FULL = 2

_LEVEL_NAMES = {"off": LEVEL_OFF, "summary": LEVEL_SUMMARY, "full": LEVEL_FULL}

#: 单字段最大字符数（full 模式下才有意义）。默认 64KB。
_MAX_FIELD_CHARS = 64 * 1024

#: 掩码键名（小写匹配）。调用方本不该传，这里是最后一道兜底。
_SECRET_KEYS = frozenset(
    {"api_key", "apikey", "authorization", "auth_token", "token", "password"}
)

_TRACE_LOGGER_NAME = "agent_moss.trace"

# 进程内缓存的级别。环境变量在进程启动后不会变，缓存的收益是让热路径
# 只做一次函数调用 + 整数比较。
_level_cache: int | None = None
_level_cache_raw: str | None = None
_configured = False


def trace_level() -> int:
    """当前追踪级别（0=off / 1=summary / 2=full）。

    首次读取后缓存：热路径只做一次整数比较（实测 off 模式 1.9μs/次 →
    优化后 <0.2μs/次）。环境变量在进程生命周期内不会变；测试改 env 后需调用
    ``reset_for_tests()`` 清缓存。

    环境变量非法值按 ``summary`` 处理并告警一次 —— 用户显式设了值，
    大概率是想看日志，静默降级成 off 会让排查白跑。
    """
    global _level_cache, _level_cache_raw
    if _level_cache is not None:
        return _level_cache
    raw = (os.getenv("AGENT_MOSS_TRACE_LEVEL") or "off").strip().lower()
    if raw in _LEVEL_NAMES:
        level = _LEVEL_NAMES[raw]
    else:
        level = LEVEL_SUMMARY
        logging.getLogger(__name__).warning(
            "AGENT_MOSS_TRACE_LEVEL=%r 非法，按 summary 处理（可选 off/summary/full）", raw
        )
    _level_cache = level
    _level_cache_raw = raw
    return level


def is_trace_enabled(min_level: int = LEVEL_SUMMARY) -> bool:
    """是否达到指定级别。调用方用它包住大字段构造，避免白算 f-string。"""
    return trace_level() >= min_level


#: 请求 ID（一次 analyze 的所有事件共享）。用 contextvars 而不是参数传递：
#: 引擎层（coordinator / llm_analyzer）不该为了日志而改函数签名。
_request_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    "agent_moss_req_id", default=""
)


def set_request_id(rid: str) -> None:
    """设置当前上下文的请求 ID（在请求入口调用）。

    注意：``run_in_executor`` 的线程不会自动继承 contextvars，调用方需要在
    工作函数里再设一次（见 ``routes.py`` 的 ``_with_request_id``）。
    """
    _request_id.set(rid or "")


def current_request_id() -> str:
    return _request_id.get()


def trace(event: str, level: int = LEVEL_SUMMARY, **fields: Any) -> None:
    """写一条追踪日志。``level`` 是**该条日志所需的最低级别**。

    调用方约定：事件名用点分（``request`` / ``l1.result`` / ``l2.result`` /
    ``l3.prompt`` / ``l3.response`` / ``result``），字段名用 snake_case。
    每条记录自动带上 ``req_id``（若当前上下文已设置）。
    """
    if trace_level() < level:
        return
    try:
        record: dict[str, Any] = {"ts": _now(), "event": event}
        rid = _request_id.get()
        if rid:
            record["req_id"] = rid
        for key, value in fields.items():
            record[key] = _sanitize(key, value)
        _emit(record)
    except Exception:  # noqa: BLE001 —— 排障日志绝不能影响主流程
        pass


def trace_summary(event: str, **fields: Any) -> None:
    """``summary`` 及以上才记录的便捷入口。"""
    trace(event, LEVEL_SUMMARY, **fields)


def trace_full(event: str, **fields: Any) -> None:
    """``full`` 才记录的便捷入口（大字段用它）。"""
    trace(event, LEVEL_FULL, **fields)


# ==================== 内部实现 ====================


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()) + (
        ".%03d" % (int(time.time() * 1000) % 1000)
    )


def _sanitize(key: str, value: Any) -> Any:
    """掩码敏感键 + 转义/截断字符串。"""
    if key.lower() in _SECRET_KEYS:
        return "***"
    if isinstance(value, str):
        if len(value) > _MAX_FIELD_CHARS:
            original = len(value)
            value = value[:_MAX_FIELD_CHARS] + f"...[truncated {original} chars]"
        # _safe 只转义不可见字符，可打印内容（含中文）保持可读
        return _safe(value)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, dict)):
        # 结构体：先估算序列化后的长度。**未超限就保留原结构** —— 否则日志里
        # 会出现 "action_history": "[]" 这种被转义成字符串的嵌套，人看着别扭、
        # jq 也不好过滤。超限时才降级成截断后的字符串。
        try:
            text = json.dumps(value, ensure_ascii=False, default=str)
        except Exception:  # noqa: BLE001
            return _safe(repr(value))
        if len(text) > _MAX_FIELD_CHARS:
            original = len(text)
            return _safe(text[:_MAX_FIELD_CHARS] + f"...[truncated {original} chars]")
        return value
    return _safe(repr(value))


def _trace_path() -> str:
    """追踪日志路径：显式 env > 数据目录。"""
    explicit = (os.getenv("AGENT_MOSS_TRACE_PATH") or "").strip()
    if explicit:
        return explicit
    try:
        from .paths import get_data_root

        return str(get_data_root() / "agent_moss_trace.log")
    except Exception:  # noqa: BLE001
        return "agent_moss_trace.log"


def _ensure_handler() -> logging.Logger:
    """惰性配置独立 logger（第一次真正要写日志时才建文件）。"""
    global _configured
    logger = logging.getLogger(_TRACE_LOGGER_NAME)
    # 注意：还要检查 handlers 非空。`_configured` 只是"本模块配过"，但如果
    # 别的代码（比如测试里的 logging 重置）把 handler 摘掉了，光看标志会
    # 直接返回一个没有任何 sink 的 logger → 日志静默丢失。
    if _configured and logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    logger.propagate = False  # 绝不进主日志的 handler
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    try:
        path = _trace_path()
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        handler = logging.handlers.RotatingFileHandler(
            filename=path,
            maxBytes=20 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        # 只写消息本身：格式已由 record 的 JSON 承载，加时间戳前缀反而
        # 让 grep / jq 解析变麻烦。
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    except Exception:  # noqa: BLE001
        # 文件建不出来（权限/路径）→ 退化成 no-op，不影响服务
        logger.addHandler(logging.NullHandler())
    _configured = True
    return logger


#: flush 计数器：每 N 条刷一次盘。每条都 flush 是 100μs 级开销（实测），
#: 每 8 条一次既能保证 `tail -f` 基本实时（一条请求内的几条事件通常一起到），
#: 又把 flush 的系统调用摊薄。
_FLUSH_EVERY = 8
_emit_count = 0


def _emit(record: dict[str, Any]) -> None:
    global _emit_count
    logger = _ensure_handler()
    line = json.dumps(record, ensure_ascii=False, default=str)
    logger.info(line)
    _emit_count += 1
    if _emit_count % _FLUSH_EVERY:
        return
    for handler in logger.handlers:
        try:
            handler.flush()
        except Exception:  # noqa: BLE001
            pass


def flush() -> None:
    """立即刷盘（测试断言前调用；正常运行由内部每 8 条自动刷）。"""
    logger = logging.getLogger(_TRACE_LOGGER_NAME)
    for handler in logger.handlers:
        try:
            handler.flush()
        except Exception:  # noqa: BLE001
            pass


def reset_for_tests() -> None:
    """测试隔离：先 flush 未落盘内容，再清缓存、断开 handler。"""
    global _level_cache, _level_cache_raw, _configured
    flush()
    _level_cache = None
    _level_cache_raw = None
    _configured = False
    logger = logging.getLogger(_TRACE_LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        try:
            handler.close()
        except Exception:  # noqa: BLE001
            pass
