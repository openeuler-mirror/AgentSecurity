"""Exercise L3 budgeting against the exact prompt passed to the model client."""

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from agent_moss.engine import llm_analyzer
from agent_moss.engine.types import HeuristicResult, LogicRuleResult
from agent_moss.infra import config as moss_config, metrics, token_stats
from agent_moss.infra.config import Config, RetryConfig, get_llm_max_prompt_tokens
from agent_moss.infra.llm_client import LLMResponseError, LLMResult
from agent_moss.infra.prompt_templates import get_security_judge_prompt


_DECISION = '{"allowed": true, "reason": "reviewed"}'
_BUDGET = "AGENT_MOSS_LLM_MAX_PROMPT_TOKENS"


@pytest.mark.parametrize(("configured", "effective"), [
    ("-1", 0), ("0", 0), ("1", 1200), ("500", 1200), ("1199", 1200),
    ("1200", 1200), ("1201", 1201), ("1299", 1299), ("5000", 5000), ("abc", 0),
])
def test_configured_prompt_budget(monkeypatch, configured, effective):
    monkeypatch.setenv(_BUDGET, configured)
    assert get_llm_max_prompt_tokens() == effective


@pytest.fixture
def llm(monkeypatch, tmp_path):
    for setting in (
        "MAX_PROMPT_TOKENS", "BUDGET_MODE", "HISTORY_MAX_ITEMS",
        "ACTION_DETAIL_MAX_CHARS", "PROMPT_HISTORY_MAX_TURNS",
        "PROMPT_TURN_MAX_CHARS", "PROMPT_TURN_MIN_CHARS",
        "PROMPT_RECENT_TURNS_FULL", "PROMPT_SESSION_MAX_CHARS",
        "PROMPT_SESSION_MIN_CHARS", "SCRIPT_ANALYSIS_MAX_CHARS",
    ):
        monkeypatch.delenv(f"AGENT_MOSS_LLM_{setting}", raising=False)
    monkeypatch.delenv("AGENT_MOSS_LOG_PATH", raising=False)
    monkeypatch.setenv("AGENT_MOSS_LLM_TIMEOUT", "5")
    monkeypatch.setenv("AGENT_MOSS_TOKEN_STATS_PATH", str(tmp_path / "token-usage.json"))
    prompts = []
    responses = []

    def call(*, prompt, **kwargs):
        prompts.append(prompt)
        response = responses.pop(0) if responses else LLMResult(content=_DECISION)
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(llm_analyzer, "call_llm", call)
    events = Mock()
    monkeypatch.setattr(metrics.L3_BUDGET_EVENTS_TOTAL, "inc", events)
    skill_engine = SimpleNamespace(
        match_skills=lambda *args: [],
        format_skills_for_prompt=lambda skills: "",
    )
    analyzer = llm_analyzer.LLMAnalyzer(skill_engine=skill_engine)

    def analyze(**kwargs):
        request = {
            "prompt_session": "整理报告",
            "action_history": [],
            "a_next": {"action_type": "write_report", "action_detail": "report.txt"},
            "reason": "保存报告",
            "heuristic_result": HeuristicResult(),
            "logic_result": LogicRuleResult(),
            "config": Config(retry=RetryConfig(max_retries=1, retry_interval=0)),
        }
        request.update(kwargs)
        return analyzer.analyze(**request)

    return SimpleNamespace(analyze=analyze, prompts=prompts, responses=responses, events=events)


def _estimate(prompt):
    return llm_analyzer.LLMAnalyzer._estimate_tokens(prompt)


def _set_test_budget(monkeypatch, budget):
    # Exercise exact rendering thresholds independently of environment defaults.
    monkeypatch.setattr(moss_config, "get_llm_max_prompt_tokens", lambda: budget)


def _set_hard_budget(monkeypatch, estimated_limit):
    budget = (estimated_limit * 115 + 99) // 100 + 1
    _set_test_budget(monkeypatch, budget)
    return int(budget / 1.15)


@pytest.mark.parametrize("budget", [None, "0", "invalid", "5000"])
def test_ordinary_prompt_matches_legacy_rendering(llm, monkeypatch, budget):
    if budget is not None:
        monkeypatch.setenv(_BUDGET, budget)
    previous = {"action_type": "file_read", "action_detail": "notes.txt"}
    result = llm.analyze(
        action_history=[previous],
        prompt_history=[{"text": "查看笔记", "actions": [previous]}],
    )

    expected = get_security_judge_prompt(
        prompt_session="整理报告",
        action_history="  1. file_read: notes.txt",
        prompt_history_text="  第1轮用户意图: 查看笔记  → 动作: file_read",
        a_next={"action_type": "write_report", "action_detail": "report.txt"},
        reason="保存报告",
        skills_text="",
        hints_text="特征匹配检测和逻辑规则检测均未发现风险。",
    )
    assert llm.prompts == [expected]
    assert llm.prompts[0].endswith("请严格按上述 JSON 格式输出，不要输出其他内容。")
    assert result.allowed is True
    assert not result.degraded
    llm.events.assert_not_called()


@pytest.mark.parametrize("budget", ["0", "5000"])
def test_history_char_cap_marks_missing_authorization_context(llm, monkeypatch, budget):
    monkeypatch.setenv(_BUDGET, budget)
    monkeypatch.setenv("AGENT_MOSS_LLM_PROMPT_TURN_MAX_CHARS", "4")
    history = [{"text": "修改报告，但先让我确认"}]

    llm.analyze(prompt_session="继续", prompt_history=history)

    [prompt] = llm.prompts
    assert "第1轮用户意图: 修改报告（本段因长度上限已截断）" in prompt
    assert "但先让我确认" not in prompt
    assert "被省略或被截断的历史不能作为授权依据" in prompt
    assert history == [{"text": "修改报告，但先让我确认"}]


def test_safety_caps_apply_with_disabled_budget(llm, monkeypatch):
    monkeypatch.setenv(_BUDGET, "0")
    session = "请求开头" + "甲" * 10000 + "请求结尾"
    script = "脚本报告开头" + "乙" * 100000 + "脚本报告结尾"
    monkeypatch.setattr(llm_analyzer, "format_script_chain_for_prompt", lambda result: script)

    llm.analyze(prompt_session=session, script_chain_result=object())

    [prompt] = llm.prompts
    assert "当前用户请求因长度上限已截断" in prompt
    assert "脚本分析因长度上限已截断" in prompt
    assert "请求开头" in prompt and "请求结尾" in prompt
    assert "脚本报告开头" in prompt and "脚本报告结尾" in prompt
    assert prompt.count("甲") <= 8000
    assert prompt.count("乙") <= 4000


def test_action_history_is_trimmed_before_intent_history(llm, monkeypatch):
    action_history = [
        {"action_type": "file_read", "action_detail": f"ACTION-{index:02d} " + "A" * 800}
        for index in range(20)
    ]
    prompt_history = [{"text": "INTENT " + "H" * 490}]
    request = {"action_history": action_history, "prompt_history": prompt_history}
    original_request = deepcopy(request)
    llm.analyze(**request)
    limit = _set_hard_budget(monkeypatch, _estimate(llm.prompts[-1]) - 700)

    llm.analyze(**request)

    prompt = llm.prompts[-1]
    assert _estimate(prompt) <= limit
    assert "ACTION-00" not in prompt and "ACTION-19" in prompt
    assert prompt_history[0]["text"] in prompt
    assert "本段已按 token 预算截断" not in prompt
    assert "不能作为授权依据" not in prompt
    assert request == original_request


def test_tight_action_history_caps_do_not_grow_during_budgeting(llm, monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_LLM_HISTORY_MAX_ITEMS", "1")
    monkeypatch.setenv("AGENT_MOSS_LLM_ACTION_DETAIL_MAX_CHARS", "30")
    action_history = [
        {"action_type": "file_read", "action_detail": f"ACTION-{index:02d} " + "Z" * 100}
        for index in range(3)
    ]
    request = {"action_history": action_history, "prompt_history": [{"text": "甲" * 480}] * 6}
    llm.analyze(**request)
    limit = _set_hard_budget(monkeypatch, _estimate(llm.prompts[-1]) - 90)

    llm.analyze(**request)

    prompt = llm.prompts[-1]
    assert _estimate(prompt) <= limit
    assert "ACTION-00" not in prompt and "ACTION-01" not in prompt
    assert "ACTION-02" in prompt
    assert prompt.count("Z") <= 30


def test_action_history_keeps_detail_when_its_own_marker_costs_more(llm, monkeypatch):
    long_detail = "甲" * 500
    short_detail = "乙" * 101
    history = [
        {"action_type": "A", "action_detail": long_detail},
        {"action_type": "B", "action_detail": short_detail},
    ]
    llm.analyze(action_history=history)
    expected = llm.prompts[-1].replace(long_detail, llm_analyzer.LLMAnalyzer._truncate_detail(long_detail, 100))
    target = _estimate(expected)
    budget = (target * 115 + 99) // 100
    _set_test_budget(monkeypatch, budget)

    result = llm.analyze(action_history=history)

    assert result.allowed is True
    assert llm.prompts[-1] == expected
    assert _estimate(llm.prompts[-1]) == budget * 100 // 115
    assert f"  2. B: {short_detail}\n" in llm.prompts[-1]


def test_short_action_history_is_kept_when_omission_marker_would_grow_prompt(llm, monkeypatch):
    action_history = [{"action_type": action} for action in ("A", "B", "C")]
    llm.analyze(action_history=action_history)
    original_prompt = llm.prompts[-1]
    _set_test_budget(monkeypatch, _estimate(original_prompt) - 1)
    monkeypatch.setenv("AGENT_MOSS_LLM_BUDGET_MODE", "soft")

    result = llm.analyze(action_history=action_history)

    assert llm.prompts[-1] == original_prompt
    assert "  1. A\n  2. B\n  3. C" in llm.prompts[-1]
    assert "l3_budget_unreachable" in result.degraded


@pytest.mark.parametrize("window_omitted", [0, 1])
def test_historical_intents_compress_older_rows_before_deleting_them(llm, monkeypatch, window_omitted):
    monkeypatch.setenv("AGENT_MOSS_LLM_PROMPT_HISTORY_MAX_TURNS", "6")
    history = [{"text": f"历史-{index}:" + "H" * 480} for index in range(6 + window_omitted)]
    llm.analyze(prompt_history=history)
    limit = _set_hard_budget(monkeypatch, _estimate(llm.prompts[-1]) - 90)

    llm.analyze(prompt_history=history)

    prompt = llm.prompts[-1]
    assert _estimate(prompt) <= limit
    assert f"第{window_omitted + 1}轮用户意图: 历史-{window_omitted}:" in prompt
    assert history[window_omitted]["text"] not in prompt
    assert "本段已按 token 预算截断" in prompt
    assert "不能作为授权依据" in prompt
    assert prompt.count("因历史窗口上限省略 1 轮更早历史意图") == window_omitted
    assert "因 token 预算已省略" not in prompt
    assert all(turn["text"] in prompt for turn in history[-3:])


def test_intent_above_minimum_is_kept_when_truncation_marker_would_grow_prompt(llm, monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_LLM_PROMPT_RECENT_TURNS_FULL", "0")
    history = [{"text": "甲" * 101}]
    llm.analyze(prompt_history=history)
    original_prompt = llm.prompts[-1]
    _set_test_budget(monkeypatch, _estimate(original_prompt) - 1)
    monkeypatch.setenv("AGENT_MOSS_LLM_BUDGET_MODE", "soft")

    result = llm.analyze(prompt_history=history)

    assert llm.prompts[-1] == original_prompt
    assert history[0]["text"] in llm.prompts[-1]
    assert "l3_budget_unreachable" in result.degraded


def test_old_history_stage_keeps_a_row_if_its_marker_costs_more_than_it_saves(llm, monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_LLM_PROMPT_RECENT_TURNS_FULL", "0")
    monkeypatch.setenv(_BUDGET, "1283")  # Effective budget of 1,115 tokens.
    history = [{"text": "甲" * 500}, {"text": "乙" * 301}]

    llm.analyze(prompt_history=history)

    [prompt] = llm.prompts
    assert _estimate(prompt) <= 1115
    assert f"第1轮用户意图: {'甲' * 300}（本段已按 token 预算截断）" in prompt
    assert f"第2轮用户意图: {history[1]['text']}\n" in prompt


def test_zero_history_window_keeps_all_turns_before_token_budgeting(llm, monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_LLM_PROMPT_HISTORY_MAX_TURNS", "0")

    llm.analyze(prompt_history=[{"text": f"任务 {index}"} for index in range(25)])

    [prompt] = llm.prompts
    assert "第1轮用户意图: 任务 0" in prompt
    assert "第25轮用户意图: 任务 24" in prompt
    assert "因 token 预算已省略" not in prompt


def test_action_only_turn_does_not_use_a_recent_intent_slot(llm, monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_LLM_PROMPT_RECENT_TURNS_FULL", "1")
    history = [
        {"text": "甲" * 500},
        {"text": "乙" * 500},
        {"text": "", "actions": [{"action_type": "file_read"}]},
    ]
    llm.analyze(prompt_history=history)
    limit = _set_hard_budget(monkeypatch, _estimate(llm.prompts[-1]) - 15)

    llm.analyze(prompt_history=history)

    prompt = llm.prompts[-1]
    assert _estimate(prompt) <= limit
    assert "甲" * 300 + "（本段已按 token 预算截断）" in prompt
    assert history[1]["text"] in prompt
    assert "第3轮动作: file_read" in prompt
    assert "因 token 预算已省略" not in prompt


def test_removing_action_only_history_is_marked_without_intent_guidance(llm, monkeypatch):
    llm.analyze()
    limit = _set_hard_budget(monkeypatch, _estimate(llm.prompts[-1]) + 30)
    actions = [{"action_type": f"read_report_{index:02d}"} for index in range(40)]

    llm.analyze(prompt_history=[{"text": "", "actions": actions}])

    prompt = llm.prompts[-1]
    assert _estimate(prompt) <= limit
    assert "因 token 预算已省略 1 轮动作摘要" in prompt
    assert "read_report_00" not in prompt
    assert "不能作为授权依据" not in prompt


@pytest.mark.parametrize("window_omitted", [0, 1])
def test_history_deletion_keeps_original_ordinals_and_ignores_empty_rows(llm, monkeypatch, window_omitted):
    monkeypatch.setenv("AGENT_MOSS_LLM_PROMPT_HISTORY_MAX_TURNS", "3")
    history = [{"text": "窗口外的意图"}] * window_omitted + [
        {"text": "最早意图：" + "A" * 475}, {"text": " \t "}, {"text": "较近意图"},
    ]
    llm.analyze(prompt_history=history)
    limit = _set_hard_budget(monkeypatch, _estimate(llm.prompts[-1]) - 110)

    llm.analyze(prompt_history=history)

    prompt = llm.prompts[-1]
    assert _estimate(prompt) <= limit
    assert "窗口外的意图" not in prompt and "最早意图" not in prompt
    assert prompt.count("轮用户意图:") == 1
    assert f"第{window_omitted + 3}轮用户意图: 较近意图" in prompt
    assert prompt.count("因历史窗口上限省略 1 轮更早历史意图") == window_omitted
    assert "因 token 预算已省略 1 轮历史意图" in prompt
    assert "不能作为授权依据" in prompt


def test_history_can_be_omitted_entirely(llm, monkeypatch):
    llm.analyze()
    limit = _set_hard_budget(monkeypatch, _estimate(llm.prompts[-1]) + 100)

    llm.analyze(prompt_history=[{"text": "H" * 500}] * 3)

    prompt = llm.prompts[-1]
    assert _estimate(prompt) <= limit
    assert "因 token 预算已省略 3 轮历史意图" in prompt
    assert "第1轮用户意图" not in prompt
    assert "整理报告" in prompt
    assert "不能作为授权依据" in prompt


def test_short_history_kept_if_its_omission_would_cost_more(llm, monkeypatch):
    history = [{"text": "继续"}]
    llm.analyze(prompt_history=history)
    original_prompt = llm.prompts[-1]
    _set_test_budget(monkeypatch, _estimate(original_prompt) - 1)
    monkeypatch.setenv("AGENT_MOSS_LLM_BUDGET_MODE", "soft")

    result = llm.analyze(prompt_history=history)

    assert llm.prompts[-1] == original_prompt
    assert "l3_budget_unreachable" in result.degraded


@pytest.mark.parametrize("turn_cap", [None, "1"])
def test_soft_keeps_history_if_omission_saves_no_estimated_token(llm, monkeypatch, turn_cap):
    if turn_cap is not None:
        monkeypatch.setenv("AGENT_MOSS_LLM_PROMPT_TURN_MAX_CHARS", turn_cap)
    history = [{"text": "甲" * 139}]
    request = {"prompt_session": "继续", "prompt_history": history}
    llm.analyze(**request)
    original_prompt = llm.prompts[-1]
    _set_test_budget(monkeypatch, 500)
    monkeypatch.setenv("AGENT_MOSS_LLM_BUDGET_MODE", "soft")

    result = llm.analyze(**request)

    assert "l3_budget_unreachable" in result.degraded
    assert llm.prompts[-1] == original_prompt
    assert "第1轮用户意图: 甲" in llm.prompts[-1]
    assert ("被省略或被截断的历史不能作为授权依据" in llm.prompts[-1]) == (turn_cap is not None)


def test_omission_search_continues_after_removing_a_short_history_turn(llm, monkeypatch):
    history = [{"text": "继续"}, {"text": "H" * 500}, {"text": "最近的意图"}]
    llm.analyze(prompt_history=history)
    limit = _set_hard_budget(monkeypatch, _estimate(llm.prompts[-1]) - 100)

    llm.analyze(prompt_history=history)

    prompt = llm.prompts[-1]
    assert _estimate(prompt) <= limit
    assert "第1轮用户意图" not in prompt and "第2轮用户意图" not in prompt
    assert "第3轮用户意图: 最近的意图" in prompt
    assert "因 token 预算已省略 2 轮历史意图" in prompt


def test_omission_saving_below_one_token_helps_the_next_action_trim(llm, monkeypatch):
    _set_test_budget(monkeypatch, 1093)  # Effective budget of 950 tokens.
    # Replacing the history with its omission notice and authorization guidance
    # saves one character. The action trim then reaches the last fitting character.
    detail = "Z" * 250
    result = llm.analyze(
        prompt_history=[{"text": "甲" * 139}],
        a_next={"action_type": "write_report", "action_detail": detail},
        reason="保存报告.",
    )

    [prompt] = llm.prompts
    assert result.allowed is True
    assert _estimate(prompt) == 950
    assert _estimate(prompt + "X") == 951
    assert "因 token 预算已省略 1 轮历史意图" in prompt
    assert llm_analyzer.LLMAnalyzer._truncate_detail(detail, 200) in prompt


def test_current_action_is_trimmed_before_current_request(llm, monkeypatch):
    request_text = "生成报告。" + "内容详情" * 120
    a_next = {"action_type": "write_report", "action_detail": "ACTION-HEAD " + "X" * 6000 + " ACTION-TAIL"}
    request = {"prompt_session": request_text, "a_next": a_next}
    original_request = deepcopy(request)
    llm.analyze(**request)
    limit = _set_hard_budget(monkeypatch, _estimate(llm.prompts[-1]) - 1000)

    llm.analyze(**request)

    prompt = llm.prompts[-1]
    assert _estimate(prompt) <= limit
    assert "ACTION-HEAD" in prompt and "ACTION-TAIL" in prompt
    assert a_next["action_detail"] not in prompt
    assert request_text in prompt
    assert "当前用户请求因 token 预算已截断" not in prompt
    assert request == original_request


def test_script_report_is_budgeted_without_trimming_short_current_request(llm, monkeypatch):
    request_text = "开头" + "甲" * 195 + "结尾"
    script = "脚本报告开头" + "乙" * 7000 + "脚本报告结尾"
    monkeypatch.setattr(llm_analyzer, "format_script_chain_for_prompt", lambda result: script)
    llm.analyze(prompt_session=request_text)
    limit = _set_hard_budget(monkeypatch, _estimate(llm.prompts[-1]) + 500)

    llm.analyze(prompt_session=request_text, script_chain_result=object())

    prompt = llm.prompts[-1]
    assert _estimate(prompt) <= limit
    assert request_text in prompt
    assert "当前用户请求因 token 预算已截断" not in prompt
    assert "脚本分析因 token 预算已截断" in prompt
    assert "脚本分析因长度上限已截断" not in prompt
    assert "脚本报告开头" in prompt and "脚本报告结尾" in prompt
    assert prompt.count("乙") <= 1000


def test_current_request_shrinks_only_as_needed_and_keeps_hints(llm, monkeypatch):
    request_text = "请求开头" + "甲" * 2400 + "请求结尾"
    heuristic_result = HeuristicResult(hit=True, reason="应保留的风险线索", matched_patterns=["HINT-MATCH"])
    logic_result = LogicRuleResult(hit=True, violated_rule="HINT-RULE", reason="应保留的逻辑线索")
    hints = {"heuristic_result": heuristic_result, "logic_result": logic_result}
    llm.analyze(prompt_session="", **hints)
    limit = _set_hard_budget(monkeypatch, _estimate(llm.prompts[-1]) + 160)

    llm.analyze(prompt_session=request_text, **hints)

    prompt = llm.prompts[-1]
    assert limit - 1 <= _estimate(prompt) <= limit
    assert "当前用户请求因 token 预算已截断" in prompt
    assert "请求开头" in prompt and "请求结尾" in prompt
    assert 200 <= prompt.count("甲") < 2400
    assert "report.txt" in prompt
    assert "应保留的风险线索" in prompt and "HINT-MATCH" in prompt
    assert "应保留的逻辑线索" in prompt and "HINT-RULE" in prompt


@pytest.mark.parametrize("history_turns", [0, 25])
def test_hard_budget_below_floor_never_invokes_model(llm, monkeypatch, history_turns):
    monkeypatch.setenv(_BUDGET, "500")
    history = [{"text": "历史意图" * 151} for _ in range(history_turns)]
    hints = LogicRuleResult(hit=True, reason="风险线索" * 200)

    with pytest.raises(llm_analyzer.LLMPromptBudgetExceeded) as raised:
        llm.analyze(prompt_session="当前意图" * 1000, prompt_history=history, logic_result=hints)

    assert raised.value.code == "l3_budget_floor_exceeds"
    assert llm.prompts == []
    assert token_stats.get_token_stats()["total_calls"] == 0
    llm.events.assert_called_once_with(event="l3_budget_floor_exceeds")


def test_cached_verdict_does_not_bypass_new_positive_budget(llm, monkeypatch):
    assert llm.analyze().allowed is True
    monkeypatch.setenv(_BUDGET, "500")
    hints = LogicRuleResult(hit=True, reason="风险线索" * 200)

    with pytest.raises(llm_analyzer.LLMPromptBudgetExceeded):
        llm.analyze(prompt_session="改用另一项请求", logic_result=hints)

    assert len(llm.prompts) == 1
    llm.events.assert_called_once_with(event="l3_budget_floor_exceeds")


def test_hard_budget_blocks_when_floor_fits_but_real_prompt_does_not(llm, monkeypatch):
    llm.analyze()
    _set_hard_budget(monkeypatch, _estimate(llm.prompts.pop()) + 15)

    with pytest.raises(llm_analyzer.LLMPromptBudgetExceeded) as raised:
        llm.analyze(a_next={"action_type": "write_report", "action_detail": "X" * 5000})

    assert raised.value.code == "l3_budget_unreachable"
    assert llm.prompts == []
    llm.events.assert_called_once_with(event="l3_budget_unreachable")


def test_floor_keeps_full_request_when_its_truncation_marker_would_cost_more(llm, monkeypatch):
    session = "甲" * 201
    floor = get_security_judge_prompt(
        prompt_session=session,
        action_history="",
        prompt_history_text="",
        a_next={"action_type": ""},
        reason="",
        skills_text="",
        hints_text="特征匹配检测和逻辑规则检测均未发现风险。",
    )
    _set_hard_budget(monkeypatch, _estimate(floor))

    with pytest.raises(llm_analyzer.LLMPromptBudgetExceeded) as raised:
        llm.analyze(prompt_session=session, a_next={"action_type": "write_report", "action_detail": "X" * 5000})

    assert raised.value.code == "l3_budget_unreachable"
    assert llm.prompts == []


def test_soft_budget_below_floor_invokes_model_with_degraded_result(llm, monkeypatch):
    monkeypatch.setenv(_BUDGET, "500")
    monkeypatch.setenv("AGENT_MOSS_LLM_BUDGET_MODE", "soft")
    hints = LogicRuleResult(hit=True, reason="HINT-CONTENT " * 300)
    request = "请求开头" + "甲" * 4000 + "请求结尾"
    action_detail = "当前动作开头" + "丙" * 50000 + "当前动作结尾"
    action_history = [
        {"action_type": "file_read", "action_detail": f"历史动作 {index:02d} " + "丁" * 500}
        for index in range(20)
    ]

    result = llm.analyze(
        prompt_session=request, reason="乙" * 3000, logic_result=hints,
        a_next={"action_type": "write_report", "action_detail": action_detail},
        action_history=action_history,
    )

    [prompt] = llm.prompts
    assert 1200 < _estimate(prompt) < 4000
    assert hints.reason in prompt
    assert "当前动作开头" in prompt and "当前动作结尾" in prompt
    assert "历史动作 00" not in prompt and "历史动作 19" in prompt
    assert "更早的 18 条历史动作已省略" in prompt
    assert prompt.count("乙") == 1000
    assert request not in prompt
    assert "请求开头" in prompt and "请求结尾" in prompt
    assert "当前用户请求因 token 预算已截断" in prompt
    assert result.allowed is True
    assert "l3_budget_unreachable" in result.degraded
    llm.events.assert_called_once_with(event="l3_budget_unreachable")


@pytest.mark.parametrize(
    ("budget", "used", "exceeded"),
    [(2000, 2001, True), (2000, 2000, False), (2000, 1900, False), (0, 2001, False),
     (500, 1200, False), (500, 1201, True)],
)
def test_reported_usage_compares_against_effective_budget(llm, monkeypatch, budget, used, exceeded):
    monkeypatch.setenv(_BUDGET, str(budget))
    llm.responses.append(LLMResult(content=_DECISION, prompt_tokens=used, total_tokens=used, model="test"))

    result = llm.analyze()

    assert result.allowed is True
    assert not result.degraded
    assert token_stats.get_token_stats()["total_prompt_tokens"] == used
    if exceeded:
        llm.events.assert_called_once_with(event="l3_budget_exceeded_actual")
    else:
        llm.events.assert_not_called()


@pytest.mark.parametrize(("prompt_tokens", "completion_tokens"), [(0, 0), (0, 7), (None, 7)])
def test_unknown_prompt_usage_is_not_replaced_with_estimate(llm, monkeypatch, prompt_tokens, completion_tokens):
    monkeypatch.setenv(_BUDGET, "2000")
    llm.responses.append(LLMResult(
        content=_DECISION, prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens, total_tokens=completion_tokens,
    ))

    result = llm.analyze()

    stats = token_stats.get_token_stats()
    assert result.allowed is True
    assert stats["total_calls"] == 1
    assert stats["by_step"]["L3_security_judge"]["calls"] == 1
    assert stats["total_prompt_tokens"] == 0
    assert stats["total_completion_tokens"] == completion_tokens
    assert stats["total_tokens"] == completion_tokens
    llm.events.assert_not_called()


def test_usage_from_failed_response_is_observed_once_before_retry(llm, monkeypatch):
    monkeypatch.setenv(_BUDGET, "2000")
    llm.responses.extend([
        LLMResponseError("empty", LLMResult(content="", prompt_tokens=2001, total_tokens=2001)),
        LLMResult(content=_DECISION, prompt_tokens=700, total_tokens=700),
    ])

    result = llm.analyze(config=Config(retry=RetryConfig(max_retries=2, retry_interval=0)))

    assert result.allowed is True
    assert len(llm.prompts) == 2
    stats = token_stats.get_token_stats()
    assert stats["total_calls"] == 2
    assert stats["total_prompt_tokens"] == 2701
    llm.events.assert_called_once_with(event="l3_budget_exceeded_actual")
