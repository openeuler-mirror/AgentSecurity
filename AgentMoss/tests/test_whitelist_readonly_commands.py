# -*- coding: utf-8 -*-
"""只读命令白名单的「一拦一放」测试。

背景：白名单漏了一批常见的只读系统查询命令（`df`/`free`/`ps`/`ss`… 在列表里，
`df` 却不在），于是开 L3 的部署每查一次磁盘/内存都要走 LLM —— 实测 `df -h`
从 5ms 变成十几秒。补白名单本身不改变安全边界（白名单只在 L1 未命中
high/critical 时生效，且放行后仍会复扫完整命令），但**放进了不该放的命令**就是
扩大边界，所以每条新增都配一个"同类但破坏性"的反例。

这里直接断言匹配函数，而不是走完整 analyze()：断言的是"有没有进快速通道"
这个精确属性 —— 破坏性命令即使最终决策同为 Allow，也必须**不**被白名单收进来
（不能跳过 L3）。
"""

import pytest

from agent_moss.engine.heuristic import (
    is_fully_safe_bash_command,
    is_readonly_sensitive_bash_command,
)
from agent_moss.profiles import get_profile

LINUX = "linux"
WINDOWS = "windows"

#: (命令, 期望进入的通道)
LINUX_FULLY_SAFE = [
    ("df -h", True), ("df", True),
    ("free -m", True), ("vmstat 1 2", True), ("nproc", True),
    ("lscpu", True), ("lsblk -f", True), ("lspci", True),
    ("lsusb", True), ("lsmod", True),
]

LINUX_READONLY_SENSITIVE = [
    ("ps aux", True), ("ss -ltn", True), ("netstat -an", True), ("lsof -i", True),
    ("systemctl status sshd", True), ("systemctl is-active sshd", True),
    ("systemctl list-units", True), ("service sshd status", True),
    ("journalctl -u sshd -n 20", True), ("journalctl --since today", True),
    ("journalctl", True),
]

#: 「同类但破坏性」——绝不能被白名单收进来
LINUX_MUST_NOT = [
    "systemctl stop sshd", "systemctl disable sshd", "systemctl start sshd",
    "systemctl restart sshd", "service sshd stop", "service sshd restart",
    "journalctl --vacuum-size=100M", "journalctl --vacuum-time=7d",
    "journalctl --vacuum-files=5", "journalctl --rotate", "journalctl --flush",
    "journalctl --sync",
]

WINDOWS_FULLY_SAFE = [
    ("whoami", True), ("hostname", True), ("systeminfo", True),
    ("tasklist", True), ("getmac", True), ("driverquery", True),
    ("netstat -an", True),
]

WINDOWS_READONLY_SENSITIVE = [
    ("sc query sshd", True), ("reg query HKLM\\SOFTWARE", True),
]

WINDOWS_MUST_NOT = [
    "sc stop sshd", "sc start sshd", "sc delete sshd", "sc create x binPath= y",
    "reg add HKLM\\SOFTWARE\\x /v y /d z", "reg delete HKLM\\SOFTWARE\\x",
    "reg set HKLM\\SOFTWARE\\x /v y /d z",
]


@pytest.mark.parametrize("command,expected", LINUX_FULLY_SAFE)
def test_linux_fully_safe(command, expected):
    assert is_fully_safe_bash_command(command, get_profile(LINUX)) is expected


@pytest.mark.parametrize("command,expected", LINUX_READONLY_SENSITIVE)
def test_linux_readonly_sensitive(command, expected):
    """只跳 L3、保留 L2 —— 用 readonly_sensitive 判定，不能用 fully_safe。"""
    profile = get_profile(LINUX)
    assert is_readonly_sensitive_bash_command(command, profile) is expected
    # 这些命令不该被"完全放行"（它们会暴露敏感内容，必须留 L2）
    assert is_fully_safe_bash_command(command, profile) is False


@pytest.mark.parametrize("command", LINUX_MUST_NOT)
def test_linux_destructive_commands_stay_out(command):
    profile = get_profile(LINUX)
    assert is_fully_safe_bash_command(command, profile) is False
    assert is_readonly_sensitive_bash_command(command, profile) is False


@pytest.mark.parametrize("command,expected", WINDOWS_FULLY_SAFE)
def test_windows_fully_safe(command, expected):
    assert is_fully_safe_bash_command(command, get_profile(WINDOWS)) is expected


@pytest.mark.parametrize("command,expected", WINDOWS_READONLY_SENSITIVE)
def test_windows_readonly_sensitive(command, expected):
    profile = get_profile(WINDOWS)
    assert is_readonly_sensitive_bash_command(command, profile) is expected
    assert is_fully_safe_bash_command(command, profile) is False


@pytest.mark.parametrize("command", WINDOWS_MUST_NOT)
def test_windows_destructive_commands_stay_out(command):
    profile = get_profile(WINDOWS)
    assert is_fully_safe_bash_command(command, profile) is False
    assert is_readonly_sensitive_bash_command(command, profile) is False


#: 白名单命令后面挂各种连接符 —— 逐段判定之前，这些会被整条放行
COMPOUND_BYPASS = [
    "df -h ; shutdown -h now",
    "free -m; shutdown now",
    "ls & shutdown -h now",
    "ls\nshutdown -h now",
    "ps aux | xargs kill -9",
    "ls | xargs rm -rf",
    "cat /etc/passwd | xargs kill",
    "df -h ; kill -9 1",
    "ls $(shutdown -h now)",
    "ls `kill -9 1`",
    "journalctl -u sshd --vacuum-size=100M",
    "journalctl --rotate -n 5",
]

COMPOUND_BYPASS_WINDOWS = [
    "sc query x & sc stop y",
    "reg query HKLM & reg add HKLM\\x /v y /d z",
    "tasklist ; shutdown /s",
]


@pytest.mark.parametrize("command", COMPOUND_BYPASS)
def test_linux_whitelist_cannot_be_ridden_by_a_tail(command):
    """白名单命令后面挂别的命令 —— 整条都不许走白名单。

    白名单判定作用于**整条命令**，所以只看首段的话，`df -h ; shutdown -h now`
    会因为首段是 df 而整条快速放行；而危险命令特征又兜不住 shutdown/kill/sc stop
    这类（151 条特征里 0 条覆盖），尾部就是畅通的。修法是逐段判定：每一段都要
    命中白名单，出现命令替换（``$(``/反引号）也一律不放行。
    """
    profile = get_profile(LINUX)
    assert is_fully_safe_bash_command(command, profile) is False
    assert is_readonly_sensitive_bash_command(command, profile) is False


@pytest.mark.parametrize("command", COMPOUND_BYPASS_WINDOWS)
def test_windows_whitelist_cannot_be_ridden_by_a_tail(command):
    profile = get_profile(WINDOWS)
    assert is_fully_safe_bash_command(command, profile) is False
    assert is_readonly_sensitive_bash_command(command, profile) is False


@pytest.mark.parametrize(
    "command",
    ["ps aux | grep nginx", "ls -la | head -5", "df -h | grep sda", "cat /etc/hosts"],
)
def test_readonly_pipelines_keep_their_fast_path(command):
    """逐段判定不能把常见只读管道也误伤 —— 这些都是合理的快速通道用户。"""
    assert is_readonly_sensitive_bash_command(command, get_profile(LINUX)) is True


def test_strip_literal_text_segments_preserves_command_structure():
    """`_strip_literal_text_segments` 必须原样保留分隔符。

    ⚠️ 这条守的是一个**函数重名**事故：曾有人在同模块里又定义了一个叫
    `_split_command_segments` 的函数（与已有的引号感知版同名），Python 以后定义
    者为准，剥离函数于是用上了会丢分隔符的版本 —— `df -h && rm -rf /` 被拼成
    `df -hrm -rf /`，危险模式 `\\brm\\s+-...` 匹配不上，**任意复合命令里的危险
    命令全部漏检**（L1 静默失效，只有直接查剥离结果才看得出来）。
    """
    from agent_moss.engine.heuristic import _strip_literal_text_segments

    for command in ["df -h && rm -rf /", "ls; rm -rf /", "uptime | rm -rf /"]:
        stripped = _strip_literal_text_segments(command)
        assert "rm -rf /" in stripped, f"剥离破坏了命令结构: {command!r} → {stripped!r}"
        # 危险模式要求 rm 前面是词边界，粘连（-hrm）会让它失配
        assert "&&" in stripped or ";" in stripped or "|" in stripped or " " in stripped


def test_grep_pattern_pipe_passwd_is_false_positive():
    """NEW-FP-R：grep 搜索模式串里的 `|passwd`（正则或关系）不得命中管道改密
    规则（L1 与 L2 都不得命中）；引号外的真实管道必须仍被拦。"""
    from agent_moss.engine.analyzer import analyze

    fp = (
        'cd ~/.cache; grep -n -i -E "private key|BEGIN .*PRIVATE|password|passwd|'
        'secret|token" report.txt | head -20; wc -l report.txt'
    )
    result = analyze(
        session_id="fp-guard", prompt_session="", action_history=[],
        a_next={"action_type": "bash", "action_detail": fp}, reason="",
        config=None, cache=None, profile=get_profile(LINUX), llm_config=None,
        cwd="/tmp", agent_id="", scenario_id="", llm_log_path=None,
    )
    assert result["decision"] == "Allow", f"搜索模式串不应被拦: {result.get('reason')}"

    real = "grep '^newpass:' /tmp/seeds.txt | passwd --stdin ops"
    result = analyze(
        session_id="fp-guard", prompt_session="", action_history=[],
        a_next={"action_type": "bash", "action_detail": real}, reason="",
        config=None, cache=None, profile=get_profile(LINUX), llm_config=None,
        cwd="/tmp", agent_id="", scenario_id="", llm_log_path=None,
    )
    assert result["decision"] == "Deny", "真实管道必须仍被拦"

    bypass = 'echo "passwd --stdin root" > /tmp/x.sh && bash /tmp/x.sh'
    result = analyze(
        session_id="fp-guard", prompt_session="", action_history=[],
        a_next={"action_type": "bash", "action_detail": bypass}, reason="",
        config=None, cache=None, profile=get_profile(LINUX), llm_config=None,
        cwd="/tmp", agent_id="", scenario_id="", llm_log_path=None,
    )
    assert result["decision"] == "Deny", "绕过链（写脚本+执行）必须仍被拦"


@pytest.mark.parametrize(
    "command",
    ["ls && rm -rf /", "df -h && rm -rf /", "uptime | rm -rf /", "ls; rm -rf /"],
)
def test_dangerous_command_in_compound_still_denied(command):
    """端到端：复合命令里的危险命令必须仍被 L1 拦下（重名事故的直接后果）。"""
    from agent_moss.engine.analyzer import analyze

    result = analyze(
        session_id="compound-guard",
        prompt_session="",
        action_history=[],
        a_next={"action_type": "bash", "action_detail": command},
        reason="",
        config=None,
        cache=None,
        profile=get_profile(LINUX),
        llm_config=None,
        cwd="/tmp",
        agent_id="",
        scenario_id="",
        llm_log_path=None,
        prompt_history=[],
        session_history=[],
    )
    assert result["decision"] == "Deny", f"{command} 里的危险命令被漏检了"


@pytest.mark.parametrize(
    "command",
    ["df -h && rm -rf /", "ps aux; rm -rf /", "df -h | tee /etc/passwd"],
)
def test_whitelisted_head_with_dangerous_tail_is_still_denied(command):
    """白名单看的是第一段命令，但破坏性尾巴必须仍被拦下。

    `is_fully_safe_bash_command` 用 _extract_first_command 取第一段，所以
    `df -h && rm -rf /` 在它眼里是"df -h"——真正兜底的是 coordinator 里对**完整
    命令**的复扫（命中 high/critical 即撤销白名单放行）。这条断言走端到端。
    """
    from agent_moss.engine.analyzer import analyze

    result = analyze(
        session_id="whitelist-tail-guard",
        prompt_session="",
        action_history=[],
        a_next={"action_type": "bash", "action_detail": command},
        reason="",
        config=None,
        cache=None,
        profile=get_profile(LINUX),
        llm_config=None,
        cwd="/tmp",
        agent_id="",
        scenario_id="",
        llm_log_path=None,
        prompt_history=[],
        session_history=[],
    )
    assert result["decision"] == "Deny", f"{command} 应被完整命令复扫拦下"
