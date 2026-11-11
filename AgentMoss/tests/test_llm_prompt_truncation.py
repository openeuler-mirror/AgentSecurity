"""L3 prompt 历史动作截断与 token 预算看护（2026-11）。

背景：客户的写文件类 tool call 会把整个文件内容放进 action_detail，历史累积
几十条后 prompt 能到几十万字符。本文件看护：

- 单条截断：保头 60% + 尾 40%，中间标注省略长度
- 历史条数限制：只保留最近 N 条，更早的只计数
- 0 = 不截断（向后兼容，既有用例的短历史行为不变）
"""

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


def test_estimate_tokens_roughly_matches_length():
    assert LLMAnalyzer._estimate_tokens("x" * 2500) == 1001
    assert LLMAnalyzer._estimate_tokens("") == 1
