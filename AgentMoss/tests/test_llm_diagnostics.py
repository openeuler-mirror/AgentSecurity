"""LLM 空返回诊断的看护（2026-11 招行「token 去哪了」问题后新增）。

核心要求：**空返回时日志必须能直接看出内容落在哪个字段**，
不能只打 content / reasoning_content 这两个固定字段。
"""

from __future__ import annotations

import json


class _FakeMessage:
    """模拟 OpenAI SDK 的 message：多出一个非标准的 ``reasoning`` 字段。"""

    def __init__(self, **fields):
        self._fields = fields

    def model_dump(self):
        return dict(self._fields)


class _FakeChoice:
    def __init__(self, message, finish_reason="stop"):
        self.message = message
        self.finish_reason = finish_reason


class _FakeResponse:
    def __init__(self, message, finish_reason="stop", model="m", prompt=100, completion=185):
        self.choices = [_FakeChoice(message, finish_reason)]
        self.model = model

        class _Usage:
            pass

        u = _Usage()
        u.prompt_tokens = prompt
        u.completion_tokens = completion
        self.usage = u


def test_field_lengths_sees_nonstandard_reasoning_field():
    from agent_moss.infra.llm_client import _response_field_lengths

    msg = _FakeMessage(
        content="",
        role="assistant",
        reasoning="思考内容" * 30,  # 网关塞进 model_extra 的非标准字段
        tool_calls=None,
    )
    lengths = _response_field_lengths(msg)
    assert lengths["reasoning"] == 120
    # 空字段不进结果
    assert "content" not in lengths
    assert "tool_calls" not in lengths


def test_describe_response_lists_all_nonempty_fields():
    from agent_moss.infra.llm_client import _describe_response

    resp = _FakeResponse(
        _FakeMessage(content="", role="assistant", reasoning="x" * 120),
        completion=185,
    )
    detail = _describe_response(resp)
    assert "reasoning_len=120" in detail
    assert "tokens=100/185" in detail


def test_dump_full_message_keeps_all_fields():
    from agent_moss.infra.llm_client import _dump_full_message

    msg = _FakeMessage(content="", reasoning="SECRET-THOUGHT", refusal=None)
    text = _dump_full_message(msg)
    data = json.loads(text)
    # 完整结构（含非标准字段的原文），不只是长度
    assert data["reasoning"] == "SECRET-THOUGHT"
    assert "content" in data


def test_dump_full_message_truncates_oversized():
    from agent_moss.infra.llm_client import _dump_full_message

    msg = _FakeMessage(content="", reasoning="x" * 20000)
    text = _dump_full_message(msg, limit=1000)
    assert len(text) < 1100
    assert "truncated" in text
