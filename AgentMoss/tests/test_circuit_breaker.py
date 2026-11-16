"""LLM 熔断器状态机看护（2026-11 商用标准 P0）。"""

from __future__ import annotations

import time

from agent_moss.infra.circuit_breaker import CLOSED, HALF_OPEN, OPEN, CircuitBreaker


def test_closed_allows_and_accumulates_failures():
    b = CircuitBreaker(threshold=3, cooldown=60)
    assert b.allow() is True
    b.record_failure()
    b.record_failure()
    assert b.state == CLOSED  # 还没到阈值
    b.record_failure()
    assert b.state == OPEN


def test_open_short_circuits_until_cooldown():
    b = CircuitBreaker(threshold=2, cooldown=0.1)
    b.record_failure()
    b.record_failure()
    assert b.state == OPEN
    assert b.allow() is False
    assert b.short_circuit_count == 1
    time.sleep(0.12)
    assert b.allow() is True  # 冷却结束 → 放行试探
    assert b.state == HALF_OPEN


def test_half_open_success_closes():
    b = CircuitBreaker(threshold=1, cooldown=0.05)
    b.record_failure()
    time.sleep(0.06)
    assert b.allow() is True
    b.record_success()
    assert b.state == CLOSED
    assert b.allow() is True


def test_half_open_failure_reopens():
    b = CircuitBreaker(threshold=1, cooldown=0.05)
    b.record_failure()
    time.sleep(0.06)
    assert b.allow() is True
    b.record_failure()
    assert b.state == OPEN
    assert b.allow() is False


def test_success_resets_failure_streak():
    b = CircuitBreaker(threshold=3, cooldown=60)
    b.record_failure()
    b.record_failure()
    b.record_success()
    b.record_failure()
    b.record_failure()
    assert b.state == CLOSED  # 成功清零后重新计数，未到 3


def test_threshold_zero_disables():
    b = CircuitBreaker(threshold=0, cooldown=60)
    for _ in range(100):
        b.record_failure()
    assert b.state == CLOSED
    assert b.allow() is True


def test_snapshot_reports_state():
    b = CircuitBreaker(threshold=1, cooldown=60)
    b.record_failure()
    snap = b.snapshot()
    assert snap["state"] == OPEN
    assert snap["open_count"] == 1
    assert snap["threshold"] == 1
