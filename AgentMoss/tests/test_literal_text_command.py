# -*- coding: utf-8 -*-
"""`is_literal_text_command` 的逐段判定 —— 防止 echo 前缀绕过 file_access 拦截。

这个函数是 2026-09 为消除误报加的（`echo "cat /etc/shadow"` 只是打印文本，
不该拦），但旧实现用 `_ECHO_CMD_RE.search` 做门控 —— **命令里任意位置出现过
echo 就算**"纯文本输出命令"。于是 L1 命中 file_access 时（读 SSH 私钥、读
云凭据…），那道"交给 inline_analyzer 静态判定"的豁免会把**整个 Deny 丢掉**：

    cat ~/.ssh/id_rsa            → Deny
    echo hi && cat ~/.ssh/id_rsa  → Allow   ← 私钥被读走

也就是说，任意读凭据命令前面加个 `echo` 就能绕过。修法：要求**整条命令都由
echo/printf 段构成**，只要还挂着别的命令段就不算纯文本输出。
"""

import pytest

from agent_moss.engine.inline_analyzer import is_literal_text_command

#: 真正的纯文本输出命令 —— 这个函数存在的理由，必须保持 True
REAL_TEXT_COMMANDS = [
    'echo "cat /etc/shadow"',
    'echo "rm -rf /"',
    "printf 'userdel root'",
    'echo "访问 ~/.ssh/id_rsa 会报警"',
    'echo hello',
    'echo hello; echo world',          # 两段都是 echo
    'echo a && printf b',
]

#: 挂着别的命令段 —— 不是纯文本输出，file_access 豁免不得生效
COMPOUND_COMMANDS = [
    "echo hi && cat ~/.ssh/id_rsa",
    "cat ~/.ssh/id_rsa && echo hi",
    "echo hi; cat ~/.ssh/id_rsa",
    "echo hi | cat ~/.ssh/id_rsa",
    "ls && echo hi",
    "echo hi && rm -rf /",
    "cat ~/.aws/credentials",
]


@pytest.mark.parametrize("command", REAL_TEXT_COMMANDS)
def test_real_text_commands_are_recognised(command):
    assert is_literal_text_command(command) is True


@pytest.mark.parametrize("command", COMPOUND_COMMANDS)
def test_compound_commands_are_not_literal_text(command):
    assert is_literal_text_command(command) is False


@pytest.mark.parametrize(
    "command",
    [
        "cat ~/.ssh/id_rsa",
        "echo hi && cat ~/.ssh/id_rsa",
        "cat ~/.ssh/id_rsa && echo hi",
        "echo hi; cat ~/.ssh/id_rsa",
        "ls; cat ~/.aws/credentials",
        "echo hi && cat /etc/shadow",
    ],
)
def test_credential_read_is_denied_even_with_an_echo_prefix(command):
    """端到端：echo 前缀不能把读凭据洗成 Allow。"""
    from agent_moss.engine.analyzer import analyze
    from agent_moss.profiles import get_profile

    result = analyze(
        session_id="literal-text-guard",
        prompt_session="",
        action_history=[],
        a_next={"action_type": "bash", "action_detail": command},
        reason="",
        config=None,
        cache=None,
        profile=get_profile("linux"),
        llm_config=None,
        cwd="/tmp",
        agent_id="",
        scenario_id="",
        llm_log_path=None,
        prompt_history=[],
        session_history=[],
    )
    assert result["decision"] == "Deny", f"{command} 读凭据被放行了"
