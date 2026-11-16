"""LLM 调用熔断器（2026-11，商用标准 P0）。

要解决的问题：模型服务挂掉 / 网络不通 / 网关限流时，**每个** analyze 请求
都要等满 `AGENT_MOSS_LLM_TIMEOUT`（默认 300 秒）才 fail-open。并发一上来，
线程池和并发池全被「等超时」的请求占满 → 表面看就是「服务挂了」。

熔断后：连续失败 N 次 → 打开 30 秒，期间新请求**立即**拿到失败（走
fail_open / fail_closed 既定策略，不发起网络请求）；冷却后放一个请求试探，
成功则恢复，失败则继续熔断。

状态机：

    CLOSED --连续失败 N 次--> OPEN --冷却 T 秒--> HALF_OPEN
      ^                                            |
      +----------- 试探成功 ------------------------+
                                                   |
                   试探失败 --> OPEN（重新计时）<---+

开关：`AGENT_MOSS_LLM_CIRCUIT_THRESHOLD`（默认 5，0=禁用）
     `AGENT_MOSS_LLM_CIRCUIT_COOLDOWN`（默认 30 秒）
"""

from __future__ import annotations

import os
import threading
import time

CLOSED = "closed"
OPEN = "open"
HALF_OPEN = "half_open"


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


class CircuitBreaker:
    """线程安全的简单熔断器（进程级单实例）。"""

    def __init__(self, threshold: int = 5, cooldown: float = 30.0):
        self.threshold = threshold
        self.cooldown = cooldown
        self._lock = threading.Lock()
        self._state = CLOSED
        self._failures = 0
        self._opened_at = 0.0
        #: 统计（供 /metrics 与 doctor 展示）
        self.open_count = 0
        self.short_circuit_count = 0

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    def allow(self) -> bool:
        """当前是否允许发起真实调用。"""
        if self.threshold <= 0:
            return True
        with self._lock:
            if self._state == CLOSED:
                return True
            if self._state == OPEN:
                if time.monotonic() - self._opened_at >= self.cooldown:
                    # 冷却结束 → 放行试探
                    self._state = HALF_OPEN
                    return True
                self.short_circuit_count += 1
                return False
            # HALF_OPEN：放行（试探请求通常只有一两个，不需要额外限制）
            return True

    def record_success(self) -> None:
        if self.threshold <= 0:
            return
        with self._lock:
            self._state = CLOSED
            self._failures = 0

    def record_failure(self) -> None:
        if self.threshold <= 0:
            return
        with self._lock:
            if self._state == HALF_OPEN:
                # 试探失败 → 重新熔断并重新计时
                self._state = OPEN
                self._opened_at = time.monotonic()
                self.open_count += 1
                return
            self._failures += 1
            if self._failures >= self.threshold:
                self._state = OPEN
                self._opened_at = time.monotonic()
                self.open_count += 1

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "state": self._state,
                "failures": self._failures,
                "threshold": self.threshold,
                "cooldown_sec": self.cooldown,
                "open_count": self.open_count,
                "short_circuit_count": self.short_circuit_count,
            }

    def reset(self) -> None:
        with self._lock:
            self._state = CLOSED
            self._failures = 0
            self._opened_at = 0.0


_breaker: CircuitBreaker | None = None


def get_breaker() -> CircuitBreaker:
    """进程级单例（阈值/冷却时间来自环境变量）。"""
    global _breaker
    if _breaker is None:
        _breaker = CircuitBreaker(
            threshold=_env_int("AGENT_MOSS_LLM_CIRCUIT_THRESHOLD", 5),
            cooldown=_env_float("AGENT_MOSS_LLM_CIRCUIT_COOLDOWN", 30.0),
        )
    return _breaker


def reset_breaker_for_tests() -> None:
    global _breaker
    _breaker = None
