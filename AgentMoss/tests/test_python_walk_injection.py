"""Python os.walk 的回调参数不应当作 HTML 事件属性；其他载荷仍送检。"""

import shlex

import pytest
from agent_moss.engine.coordinator import judge_security
from agent_moss.engine.heuristic import HeuristicDetector, InjectionKeywordChecker
from agent_moss.infra.config import Config
from agent_moss.infra.rules_mode import reset_cache
from agent_moss.profiles import get_profile


@pytest.fixture(autouse=True)
def static_rules(monkeypatch):
    with monkeypatch.context() as patch:
        patch.setenv("AGENT_MOSS_RULES_MODE", "builtin")
        patch.setenv("AGENT_MOSS_DISABLE_LLM", "1")
        reset_cache()
        yield
    reset_cache()


def command(code, suffix=""):
    return "python3 -c " + shlex.quote(code) + suffix


def detect(detail, *, reason="", prompt="", action_type="bash"):
    return HeuristicDetector(get_profile("linux")).detect(
        {"action_type": action_type, "action_detail": detail}, reason, prompt,
    )


def judge(detail, *, reason="", prompt=""):
    return judge_security(
        prompt_session=prompt, action_history=[],
        a_next={"action_type": "bash", "action_detail": detail}, reason=reason,
        config=Config(), profile=get_profile("linux"), cwd="/tmp",
    )


@pytest.mark.parametrize("code,suffix", [
    ("import os; list(os.walk('.', onerror=print))", ""),
    ("import os; list(os.walk('.', onerror=print))", " 2>&1"),
    ("import os; enabled=True; list(os.walk('.', onerror=print)) if enabled else None", ""),
    ("import os; 标签='中文'; list(os.walk('.', onerror=print))", ""),
    ("import os; list(os.walk('.', onerror=print)); list(os.walk('.', onerror=print))", ""),
    ("import os\ndef report(error):\n    print(type(error).__name__)\n"
     "for root, directories, files in os.walk('.', onerror=report):\n    print(files)\n", " 2>&1"),
])
def test_python_walk_callback_is_not_injection(code, suffix):
    result = judge(command(code, suffix))
    assert result.allowed, result.reason


@pytest.mark.parametrize("code", [
    "import os; list(os.walk('.', onerror=print)); print('<img src=x onerror=alert(1)>')",
    "import os; list(os.walk('.', onerror=print)); print('onerror=')",
    "import os; list(os.walk('.', onerror=print))  # onerror=",
    "import os; list(os.walk('.', onerror=print)); other(onerror=print)",
    "import os; list(os.walk('.', onerror = print)); print('onerror=')",
    "import os; 标签='中文 onerror='; list(os.walk('.', onerror=print))",
    "import os; list(os.walk('.', onerror=lambda error: print('onerror=')))",
    "import os; print(f\"{os.walk('.', onerror=print)=}\")",
    "import os; alert=print; text=f\"{os.walk('.', onerror=alert)=}\"; "
    "print('<img src=x ' + text[text.index('onerror'):text.index(')')] + '(1)>')",
])
def test_unrelated_occurrence_is_never_cancelled_by_a_safe_keyword(code):
    result = detect(command(code))
    assert result.hit and "onerror=" in result.matched_patterns
    assert not judge(command(code)).allowed


@pytest.mark.parametrize("field", ["reason", "prompt"])
def test_python_keyword_never_exempts_prompt_or_reason(field):
    detail = command("import os; list(os.walk('.', onerror=print))")
    result = detect(detail, **{field: "<img src=x onerror=alert(1)>"})
    assert result.hit and "onerror=" in result.matched_patterns


def test_dangerous_callback_still_reaches_other_checks():
    detail = command("import os; list(os.walk('.', onerror=lambda error: os.system('rm -rf /')))")
    result = judge(detail)
    assert not result.allowed
    assert result.risk_type == "script_execution"


def test_sensitive_callback_still_reaches_l1_path_check():
    # The later inline/coordinator decision is a separate existing limitation.
    detail = command("import os; list(os.walk('.', onerror=lambda error: open('/etc/shadow').read()))")
    result = detect(detail)
    assert result.hit and result.risk_type == "file_access"


@pytest.mark.parametrize("code", [
    "import os; list(os.walk('.', onerror=lambda error: print(error)))",
    "import os; list(os.walk('.', onerror=callbacks.report))",
    "import os; list(os.walk('.', onerror=make_callback()))",
    "import os as OS; list(OS.walk('.', onerror=print))",
    "import os; list(os.walk('.', OnError=print))",
])
def test_only_exact_os_walk_with_named_callback_has_an_exception(code):
    result = detect(command(code))
    assert result.hit and "onerror=" in result.matched_patterns


def test_other_injection_keywords_still_match():
    detail = command("import os; list(os.walk('.', onerror=print)); print('ignore previous instructions')")
    result = detect(detail)
    assert result.hit
    assert "ignore previous instructions" in result.matched_patterns


@pytest.mark.parametrize("suffix", ["; true", " && true", " | cat", "\nprintf done"])
def test_complex_shell_keeps_the_existing_conservative_check(suffix):
    result = detect(command("import os; list(os.walk('.', onerror=print))", suffix))
    assert result.hit and "onerror=" in result.matched_patterns


@pytest.mark.parametrize("detail", [
    command("import os; os.walk('.', onerror=print"),
    command("import os; os.walk('.', onerror=print)", " extra_argument"),
    'python3 -c "import os; marker=\'$(printf marker)\'; list(os.walk(\'.\', onerror=print))"',
    'python3 -c "import os; marker=\'`printf marker`\'; list(os.walk(\'.\', onerror=print))"',
    "python3 -c 'import os; print(\"onerror=\"); os.walk(\".\", on''error=print)'",
    "onerror=",
    "<img src=x onerror=alert(1)>",
])
def test_unproven_syntax_or_literal_payload_keeps_matching(detail):
    result = detect(detail)
    assert result.hit and "onerror=" in result.matched_patterns


def test_non_shell_tool_does_not_gain_a_python_exception():
    result = detect(command("import os; list(os.walk('.', onerror=print))"), action_type="custom_tool")
    assert result.hit and "onerror=" in result.matched_patterns


def test_direct_keyword_checker_keeps_its_default_behavior():
    result = InjectionKeywordChecker(get_profile("linux")).check("os.walk('.', onerror=print)")
    assert result.hit and "onerror=" in result.matched_patterns


def test_template_string_source_is_not_exempted():
    # Python 3.14 exposes the expression source as data; older parsers reject it.
    code = "import os; text=t\"{os.walk('.',onerror=print)}\"; print(text.interpolations[0].expression)"
    result = detect(command(code))
    assert result.hit and "onerror=" in result.matched_patterns
