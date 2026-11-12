# -*- coding: utf-8 -*-
"""`action_type` 伪装：声明成"安全工具"不能当作免检依据。

L1 里有一条「安全工具白名单跳过」——action_type 精确等于 `ls`/`glob`/`list_dir`
等工具名时整层返回未命中。设计前提是这些工具的 `action_detail` 是路径/模式而非
命令，但 **action_type 是调用方声明的**，于是：

    {"action_type": "glob", "action_detail": "rm -rf /"}
    → L1 整层跳过 → no_high_risk=True → 工具名白名单直接 Allow

这跟"白名单被尾部命令挟持"是同一类问题的另一张面孔：拿**声明**当**事实**。
修法是对 detail 承载路径/模式的工具补一次危险命令扫描；自由文本类
（ask_user_question / count_text_length）仍跳过 —— 它们的 detail 不承载可执行
命令，扫自由文本反而会误报。
"""

import pytest

from agent_moss.engine.analyzer import analyze
from agent_moss.profiles import get_profile

#: 全部「安全工具名」都要扫 detail —— L1 不再按 action_type 整层免检。
#: 注意：这套"按工具名免检"原先**只有 Python 有、TS 没有**，本身就是一处双端分叉；
#: 穷举语料 tests/parity/corpus.json 一照就现形（count_text_length/ask_user_question
#: 两类工具 × 3 条危险 detail = 6 条两端不一致），故统一成"都扫"。
SAFE_TOOL_NAMES = [
    "glob", "list_dir", "ls", "filemgr-globfiles",
    "ask_user_question", "count_text_length",
]


def _decide(action_type: str, action_detail: str, os_type: str = "linux") -> str:
    profile = get_profile(os_type)
    result = analyze(
        session_id=f"spoof-{action_type}",
        prompt_session="",
        action_history=[],
        a_next={"action_type": action_type, "action_detail": action_detail},
        reason="",
        config=None,
        cache=None,
        profile=profile,
        llm_config=None,
        cwd="/tmp",
        agent_id="",
        scenario_id="",
        llm_log_path=None,
        prompt_history=[],
        session_history=[],
    )
    return result["decision"]


@pytest.mark.parametrize("action_type", SAFE_TOOL_NAMES)
def test_dangerous_detail_is_caught_under_a_safe_tool_name(action_type):
    """伪装成安全工具名 + 危险命令 → 仍要拦。"""
    assert _decide(action_type, "rm -rf /") == "Deny"


@pytest.mark.parametrize("action_type", SAFE_TOOL_NAMES)
def test_credential_read_is_caught_under_a_safe_tool_name(action_type):
    assert _decide(action_type, "cat ~/.ssh/id_rsa") == "Deny"


@pytest.mark.parametrize("action_type", SAFE_TOOL_NAMES)
def test_host_shutdown_is_caught_under_a_safe_tool_name(action_type):
    assert _decide(action_type, "shutdown -h now") == "Deny"


@pytest.mark.parametrize(
    "action_type,detail",
    [
        ("glob", "*.txt"), ("glob", "**/*.json"), ("glob", "src/**/*.ts"),
        ("list_dir", "/var/log"), ("list_dir", "/home/user/docs"), ("ls", "/tmp"),
        ("count_text_length", "这段文本共 120 字"), ("ask_user_question", "要重启吗？"),
        ("ask_user_question", "这个日志文件要留多久？"),
    ],
)
def test_normal_tool_usage_is_not_flagged(action_type, detail):
    """补扫描不能误伤正常用法 —— 路径/通配符本身不该命中危险命令模式。"""
    assert _decide(action_type, detail) == "Allow"
