"""reasoning 字段兜底（2026-11 招行）。

背景：客户的 deepseek-v4-flash 是思考型模型，**部分请求**把完整判定 JSON
写进 reasoning 字段、content 留 null。实测样例：
    {"content": null, "reasoning": "{\"allowed\": true, \"reason\": ...}"}
兜底只在 reasoning 是**合法 JSON 且含判定字段**时启用，纯思考文本不采纳。
"""

from __future__ import annotations

from agent_moss.infra.llm_client import (
    _reasoning_fallback_content,
    _reasoning_text_fallback,
)


class _FakeMessage:
    def __init__(self, **fields):
        self._fields = fields

    def model_dump(self):
        return dict(self._fields)


def test_fallback_accepts_valid_judgment_json():
    msg = _FakeMessage(
        content=None,
        reasoning='{"allowed": true, "reason": "ok", "risk_level": "low"}',
    )
    got = _reasoning_fallback_content(msg)
    assert got.startswith("{") and '"allowed"' in got


def test_fallback_rejects_plain_thinking_text():
    """纯思考文本（不是 JSON）不能被当答案用。"""
    msg = _FakeMessage(content=None, reasoning="让我想想这个命令是否有风险……")
    assert _reasoning_fallback_content(msg) == ""


def test_fallback_rejects_json_without_judgment_fields():
    """合法 JSON 但没有判定字段 → 不是我们要的答案。"""
    msg = _FakeMessage(content=None, reasoning='{"foo": "bar"}')
    assert _reasoning_fallback_content(msg) == ""


def test_fallback_rejects_truncated_json():
    msg = _FakeMessage(content=None, reasoning='{"allowed": true, "reason": "半截')
    assert _reasoning_fallback_content(msg) == ""


def test_fallback_strips_markdown_fence():
    msg = _FakeMessage(
        content=None,
        reasoning='```json\n{"allowed": false, "risk_level": "high"}\n```',
    )
    got = _reasoning_fallback_content(msg)
    assert got.startswith("{") and '"allowed": false' in got


def test_fallback_tries_reasoning_content_and_thinking():
    assert _reasoning_text_fallback('{"decision": "Allow"}') != ""
    assert _reasoning_text_fallback("普通文本") == ""


def test_fallback_returns_empty_when_no_reasoning():
    assert _reasoning_fallback_content(_FakeMessage(content=None)) == ""


def test_fallback_ignores_non_string_reasoning():
    assert _reasoning_fallback_content(_FakeMessage(content=None, reasoning=123)) == ""
