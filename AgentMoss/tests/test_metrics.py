"""Prometheus 指标（infra/metrics.py）的行为看护。

重点看护 2026-11 踩到的死锁：`refresh_runtime_gauges` 在持锁状态下调用
`Gauge.set()`（其内部再次获取同一把锁）→ 整个事件循环卡死，/metrics 与
health 全部超时。
"""

from __future__ import annotations

from agent_moss.infra import metrics


def setup_function():
    metrics.reset_for_tests()


def test_counter_and_labels():
    metrics.ANALYZE_TOTAL.inc(decision="Allow", risk_level="low")
    metrics.ANALYZE_TOTAL.inc(decision="Allow", risk_level="low")
    out = metrics.render_prometheus()
    assert 'agent_moss_analyze_total{decision="Allow",risk_level="low"} 2.0' in out


def test_histogram_buckets():
    metrics.ANALYZE_DURATION.observe(0.02, decision="Deny")
    out = metrics.render_prometheus()
    # 0.02 <= 0.025 的桶必须计入
    assert 'agent_moss_analyze_duration_seconds_bucket{decision="Deny",le="0.025"} 1.0' in out
    # 0.02 > 0.01 的桶不计入
    assert 'agent_moss_analyze_duration_seconds_bucket{decision="Deny",le="0.01"} 0.0' in out
    assert 'agent_moss_analyze_duration_seconds_count{decision="Deny"} 1.0' in out


def test_gauge_set_and_render():
    metrics.LOOP_LAG.set(0.012)
    out = metrics.render_prometheus()
    assert "agent_moss_event_loop_lag_seconds 0.012" in out


def test_refresh_runtime_gauges_does_not_deadlock():
    """回归：refresh 内部不能出现「持锁调用 set()」的嵌套获取。"""
    metrics.refresh_runtime_gauges(
        pools={"pool:biz": 3},
        chain_nodes=42,
        chain_db_bytes=1024,
        loop_lag_ms=12.0,
        loop_lag_max_ms=99.0,
    )
    out = metrics.render_prometheus()
    assert 'agent_moss_pool_inflight{pool="pool:biz"} 3' in out
    assert 'agent_moss_chain_nodes{agent="__total__"} 42' in out
    assert "agent_moss_chain_db_bytes 1024" in out
    assert "agent_moss_event_loop_lag_seconds 0.012" in out
    assert "agent_moss_event_loop_lag_max_seconds 0.099" in out


def test_refresh_clears_stale_pool_series():
    metrics.refresh_runtime_gauges(pools={"pool:biz": 3})
    metrics.refresh_runtime_gauges(pools={"pool:ops": 1})
    out = metrics.render_prometheus()
    assert 'agent_moss_pool_inflight{pool="pool:biz"}' not in out
    assert 'agent_moss_pool_inflight{pool="pool:ops"} 1' in out


def test_escape_label_values():
    metrics.REJECTED_TOTAL.inc(reason='a"b\\c')
    out = metrics.render_prometheus()
    assert 'reason="a\\"b\\\\c"' in out
