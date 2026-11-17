"""分层追踪日志（AGENT_MOSS_TRACE_LEVEL）的行为看护。

覆盖：
- off 时零输出
- summary / full 级别过滤
- 敏感键掩码
- 超长字段截断
- 非法级别按 summary 处理（显式设了值说明想看日志）
"""

from __future__ import annotations

import json
import os

import pytest

from agent_moss.infra import trace_log


@pytest.fixture()
def trace_file(tmp_path, monkeypatch):
    """把追踪日志指到临时文件，并清空进程内缓存。"""
    path = tmp_path / "trace.log"
    monkeypatch.setenv("AGENT_MOSS_TRACE_PATH", str(path))
    trace_log.reset_for_tests()
    yield path
    trace_log.reset_for_tests()


def _lines(path) -> list[dict]:
    # 内部每 8 条才刷一次盘（摊薄系统调用），断言前先强制 flush
    trace_log.flush()
    if not path.exists():
        return []
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def test_off_writes_nothing(trace_file, monkeypatch):
    monkeypatch.delenv("AGENT_MOSS_TRACE_LEVEL", raising=False)
    trace_log.reset_for_tests()
    assert trace_log.trace_level() == trace_log.LEVEL_OFF
    trace_log.trace_summary("l1.result", hit=True)
    trace_log.trace_full("l3.prompt", prompt="x")
    assert _lines(trace_file) == []


def test_summary_filters_full_events(trace_file, monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_TRACE_LEVEL", "summary")
    trace_log.reset_for_tests()
    trace_log.trace_summary("l1.result", hit=False)
    trace_log.trace_full("l3.prompt", prompt="SECRET-PROMPT")
    events = [x["event"] for x in _lines(trace_file)]
    assert events == ["l1.result"]


def test_full_writes_both(trace_file, monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_TRACE_LEVEL", "full")
    trace_log.reset_for_tests()
    trace_log.trace_summary("l1.result", hit=True)
    trace_log.trace_full("l3.prompt", prompt="hello")
    events = [x["event"] for x in _lines(trace_file)]
    assert events == ["l1.result", "l3.prompt"]


def test_secret_keys_masked(trace_file, monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_TRACE_LEVEL", "full")
    trace_log.reset_for_tests()
    trace_log.trace_full("request", api_key="sk-real-key", token="abc", model="m")
    record = _lines(trace_file)[0]
    assert record["api_key"] == "***"
    assert record["token"] == "***"
    assert record["model"] == "m"


def test_long_field_truncated(trace_file, monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_TRACE_LEVEL", "full")
    trace_log.reset_for_tests()
    trace_log.trace_full("l3.prompt", prompt="x" * (trace_log._MAX_FIELD_CHARS + 100))
    record = _lines(trace_file)[0]
    assert "truncated" in record["prompt"]
    assert len(record["prompt"]) < trace_log._MAX_FIELD_CHARS + 200


def test_invalid_level_falls_back_to_summary(trace_file, monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_TRACE_LEVEL", "verbose")
    trace_log.reset_for_tests()
    assert trace_log.trace_level() == trace_log.LEVEL_SUMMARY


def test_trace_never_raises_on_bad_path(monkeypatch, tmp_path):
    """写日志失败必须静默：排障日志绝不能影响主流程。"""
    monkeypatch.setenv("AGENT_MOSS_TRACE_LEVEL", "full")
    # 指向一个不可能建出来的路径（父路径是文件）
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    monkeypatch.setenv("AGENT_MOSS_TRACE_PATH", str(blocker / "sub" / "trace.log"))
    trace_log.reset_for_tests()
    trace_log.trace_full("l3.prompt", prompt="x")  # 不应抛异常


def test_request_id_propagates(trace_file, monkeypatch):
    """一次请求的所有事件必须带同一个 req_id，便于 grep 串起全过程。"""
    monkeypatch.setenv("AGENT_MOSS_TRACE_LEVEL", "summary")
    trace_log.reset_for_tests()
    trace_log.set_request_id("abc123")
    trace_log.trace_summary("l1.result", hit=False)
    trace_log.trace_summary("result", decision="Allow")
    trace_log.set_request_id("")
    trace_log.trace_summary("l2.result", hit=False)
    records = _lines(trace_file)
    assert records[0]["req_id"] == "abc123"
    assert records[1]["req_id"] == "abc123"
    assert "req_id" not in records[2]
