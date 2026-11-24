"""L3 prompt 历史动作、历史意图截断与 token 预算看护（2026-11）。

背景：客户的写文件类 tool call 会把整个文件内容放进 action_detail，历史累积
几十条后 prompt 能到几十万字符。本文件看护：

- 单条截断：保头 60% + 尾 40%，中间标注省略长度
- 历史条数限制：只保留最近 N 条，更早的只计数
- 0 = 不截断（向后兼容，既有用例的短历史行为不变）
- 历史意图：只展示最近 20 轮内的非空意图，保留原轮号
"""

import pytest

from agent_moss.engine.llm_analyzer import LLMAnalyzer


def test_truncate_detail_keeps_head_and_tail():
    detail = "HEAD" + "X" * 5000 + "TAIL"
    out = LLMAnalyzer._truncate_detail(detail, 500)
    assert len(out) < 600
    assert out.startswith("HEAD")
    assert out.endswith("TAIL")
    assert "省略" in out


def test_truncate_detail_noop_when_short():
    assert LLMAnalyzer._truncate_detail("ls -la", 500) == "ls -la"


def test_truncate_detail_zero_means_unlimited():
    detail = "A" * 10000
    assert LLMAnalyzer._truncate_detail(detail, 0) == detail


def test_format_action_history_limits_items():
    hist = [
        {"action_type": "bash", "action_detail": f"cmd{i}"} for i in range(30)
    ]
    out = LLMAnalyzer._format_action_history(hist, 20, 500)
    assert "更早的 10 条" in out
    assert "cmd29" in out
    # 第 1 条应是原来的第 11 条（下标 10）
    assert "  1. bash: cmd10" in out


def test_format_action_history_truncates_detail():
    hist = [{"action_type": "bash", "action_detail": "A" * 5000}]
    out = LLMAnalyzer._format_action_history(hist, 20, 500)
    assert "省略" in out
    assert len(out) < 1000


def test_format_action_history_zero_keeps_all():
    hist = [{"action_type": "bash", "action_detail": "A" * 5000}]
    out = LLMAnalyzer._format_action_history(hist, 0, 0)
    assert len(out) > 5000


@pytest.mark.parametrize(("turn_count", "first_turn"), [(1, 1), (20, 1), (21, 2), (25, 6)])
def test_format_prompt_history_keeps_latest_turns(turn_count, first_turn):
    history = [{"text": f"意图 {turn}"} for turn in range(1, turn_count + 1)]

    result = LLMAnalyzer._format_prompt_history(history)

    assert result.splitlines() == [
        f"  第{turn}轮用户意图: 意图 {turn}"
        for turn in range(first_turn, turn_count + 1)
    ]


def test_format_prompt_history_skips_empty_turns_within_window():
    history = [{"text": "较早的意图"}, {"text": " \t "}]
    history.extend({"text": "近期意图"} for _ in range(19))

    result = LLMAnalyzer._format_prompt_history(history)

    assert result.splitlines() == [f"  第{turn}轮用户意图: 近期意图" for turn in range(3, 22)]


@pytest.mark.parametrize(("input_chars", "kept_chars"), [(499, 499), (500, 500), (501, 500)])
def test_format_prompt_history_limits_text_and_only_shows_action_types(input_chars, kept_chars):
    history = [{
        "text": " " + "甲" * input_chars + " ",
        "actions": [{"action_type": "file_read", "action_detail": "notes.txt"}],
    }]

    result = LLMAnalyzer._format_prompt_history(history)

    assert result == f"  第1轮用户意图: {'甲' * kept_chars}  → 动作: file_read"


@pytest.mark.parametrize("history", [None, [], [{"text": " \t "}]])
def test_format_prompt_history_uses_placeholder_without_intent(history):
    assert LLMAnalyzer._format_prompt_history(history) == "（未提供历史意图）"


def test_format_prompt_history_respects_configured_turns(monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_LLM_PROMPT_HISTORY_MAX_TURNS", "2")
    history = [{"text": f"意图 {turn}"} for turn in range(1, 4)]

    result = LLMAnalyzer._format_prompt_history(history)

    assert result.splitlines() == [
        "  第2轮用户意图: 意图 2",
        "  第3轮用户意图: 意图 3",
    ]


def test_format_prompt_history_zero_keeps_all(monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_LLM_PROMPT_HISTORY_MAX_TURNS", "0")
    history = [{"text": f"意图 {turn}"} for turn in range(1, 26)]

    result = LLMAnalyzer._format_prompt_history(history)

    assert len(result.splitlines()) == 25


def test_estimate_tokens_roughly_matches_length():
    assert LLMAnalyzer._estimate_tokens("x" * 2500) == 1001
    assert LLMAnalyzer._estimate_tokens("") == 1
