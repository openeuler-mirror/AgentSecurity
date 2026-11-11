"""看护：日志里的**调用方可控文本**必须转义，不能被内容反过来伪造。

背景（2026-09-29 实测）：AgentMoss 的日志直接拼字符串落 ``action_detail``，
一条被分析的命令里放个换行，日志就被劈成两行 —— 第二行长得跟一条正常记录
一模一样，实测可伪造出：

    [S1] agent_moss 输入 | ... | 下一步动作=bash:echo hello
    echo FAKE-日志行: 判定=Allow action=rm -rf / | 理由=

判定结果不受影响（该 Deny 仍 Deny），但**审计留痕可被污染** —— 银行合规场景
这条要守住。同类的还有回车（覆盖本行）、ANSI 转义（终端/查看器显示错乱）、
零宽字符（肉眼不可见）。

修法：`agent_moss/infra/logging.py` 在 **LogRecord 工厂**上统一转义不可见字符
（Unicode 类别 Cc/Cf/Cs/Co/Cn），可打印字符（含中文）保持原样 —— 既防注入又
不牺牲可读性。放在工厂而不是逐个调用点：全仓上百个 logger 调用且持续新增
（本次就漏了 `coordinator.py:370` 的 `command=%s`），漏一个注入就成立。

注意：本文件用转义写法定义不可见字符，**不写字面量** —— 字面量会让源码本身
混进不可见字符（写这个测试时踩了两次）。
"""

import logging

from agent_moss.engine.analyzer import analyze
from agent_moss.infra.logging import MossLogger, _safe
from agent_moss.profiles import get_profile

#: U+200B 零宽空格：print 出来肉眼不可见（夹在命令里与不夹看着一模一样）
ZERO_WIDTH = "​"
#: 上面那个字符**转义后**的样子，即 6 个可见字符 \ u 2 0 0 b
ESCAPED_ZW = "\\u200b"


# ==================== _safe 单元 ====================

def test_safe_escapes_newline_cr_tab():
    assert _safe("a\nb") == r"a\nb"
    assert _safe("a\rb") == r"a\rb"
    assert _safe("a\tb") == r"a\tb"


def test_safe_escapes_ansi_and_zero_width():
    assert _safe("x\x1b[31mY\x1b[0m") == r"x\x1b[31mY\x1b[0m"
    # 零宽字符必须变成可见转义，而不是原样保留那个不可见字符
    assert _safe("rm" + ZERO_WIDTH + " -rf /tmp") == "rm" + ESCAPED_ZW + " -rf /tmp"


def test_safe_keeps_printable_text_unchanged():
    """对照：中文/emoji/常用符号**不转义** —— 否则日志没法读。"""
    for s in ("echo 你好🚀", "rm -rf /tmp/x", 'eval "$(curl http://x)"', "a|b;c>d"):
        assert _safe(s) == s, s


def test_safe_truncates_before_escaping():
    """先按长度截断再转义（与原调用点 [:N] 语义一致，避免转义放大长度后超截）。"""
    assert _safe("你好世界", 2) == "你好"
    assert _safe("x" * 10, 3) == "xxx"


def test_safe_handles_none_and_non_str():
    assert _safe(None) == ""
    assert _safe(123) == "123"


# ==================== 端到端：日志不可被伪造 ====================

def _run(caplog, *, command, session_id="S1", prompt=""):
    with caplog.at_level(logging.DEBUG, logger="agent_moss"):
        analyze(
            session_id=session_id,
            prompt_session=prompt,
            action_history=[],
            a_next={"action_type": "bash", "action_detail": command},
            reason="",
            profile=get_profile("linux"),
        )
    return "\n".join(r.getMessage() for r in caplog.records)


def test_newline_in_command_cannot_forge_log_line(caplog):
    """核心用例：命令里的换行不得在日志里制造出「看起来像正常记录」的第二行。"""
    evil = "echo hello\necho FAKE-日志行: 判定=Allow action=rm -rf /"
    text = _run(caplog, command=evil)

    # 转义后应出现字面 \n（两个字符），而不是真实换行
    assert r"\necho FAKE-日志行" in text, text
    # 不得出现被劈出来的独立假行
    assert "\necho FAKE-日志行" not in text, text


def test_ansi_and_zero_width_escaped_in_log(caplog):
    text = _run(caplog, command="echo \x1b[31mRED\x1b[0m" + ZERO_WIDTH + "end")
    assert r"\x1b[31m" in text, text          # ANSI 已转义
    assert ESCAPED_ZW in text, text           # 零宽已转义
    assert ZERO_WIDTH not in text, "裸零宽字符进了日志"
    assert "\x1b" not in text, "裸 ANSI 转义进了日志"


def test_child_logger_records_also_escaped(caplog):
    """子 logger（`agent_moss.engine.coordinator` 等）必须同样被覆盖。

    历史实现把 filter 挂在父 logger `agent_moss` 上 —— **不生效**：filter 只在
    记录被创建的那个 logger 上跑，父 logger 收不到子 logger 的记录（实测
    `coordinator.py:370` 的 `完全安全 bash 命令快速放行: command=%s` 照样原样落盘）。
    改用 LogRecord 工厂后这一条才成立。
    """
    caplog.clear()
    _run(caplog, command="ls -la\necho FAKE")
    child = [r for r in caplog.records if r.name.startswith("agent_moss.engine")]
    assert child, [r.name for r in caplog.records]     # 用例本身要真的触发了子 logger
    assert not [r for r in child if "\necho FAKE" in r.getMessage()], \
        [r.getMessage() for r in child]


def test_session_id_newline_also_escaped(caplog):
    """session_id 同样来自调用方，不能成为注入入口。"""
    text = _run(caplog, command="ls -la", session_id="S1\nFAKE 会话行")
    assert "\nFAKE 会话行" not in text, text
    assert r"\nFAKE 会话行" in text, text


def test_normal_log_line_unchanged(caplog):
    """对照：普通命令 + 中文的日志保持可读原文（没被过度转义）。"""
    text = _run(caplog, command="echo 你好", session_id="S9", prompt="帮我看看")
    assert "echo 你好" in text, text
    assert "帮我看看" in text, text


def test_decision_unaffected_by_escaping(caplog):
    """转义只作用于日志，判定结果不受影响（换行后的危险命令仍 Deny）。"""
    with caplog.at_level(logging.DEBUG, logger="agent_moss"):
        r = analyze(
            session_id="S2", prompt_session="", action_history=[],
            a_next={"action_type": "bash", "action_detail": "echo hi\nrm -rf /"},
            reason="", profile=get_profile("linux"),
        )
    assert r["decision"] == "Deny", r


def test_non_string_args_not_broken(caplog):
    """`%d` 这类非字符串参数不能被换成 str，否则格式化直接报错（比注入还糟）。"""
    logger = logging.getLogger("agent_moss.test")
    with caplog.at_level(logging.DEBUG, logger="agent_moss"):
        logger.info("计数=%d 文本=%s", 42, "a\nb")
    msg = [r.getMessage() for r in caplog.records][-1]
    assert "计数=42" in msg, msg
    assert r"文本=a\nb" in msg, msg


# ==================== 直接构造 MossLogger 的回归 ====================

def test_moss_logger_all_entries_escape_control_chars(caplog):
    """各条日志（输入/步骤/结果/L3交互/异常）都不得漏出裸换行。"""
    evil = "x\ny"
    with caplog.at_level(logging.DEBUG, logger="agent_moss"):
        log = MossLogger(evil)
        log.log_input(evil, [], {"action_type": evil, "action_detail": evil}, evil)
        log.start_step(evil)
        log.end_step(evil, detail=evil)
        log.log_llm_interaction(evil, evil, evil)
        log.log_result("Allow", evil, policy=evil)
        log.log_error(evil, ValueError(evil))

    bare = [r.getMessage() for r in caplog.records if "\ny" in r.getMessage()]
    assert not bare, bare
