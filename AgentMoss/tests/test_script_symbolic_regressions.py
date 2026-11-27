"""LiteSE 符号执行回归：通配符/正则/嵌套结构/变量预算。

对应上游反馈的 LS-30 / LS-31 / LS-25 补充 / LS-28 补充。前三个是漏判
（危险命令被剪枝），最后一个是变量表上限未覆盖启动参数。
"""
import pytest

from agent_moss.engine.script_engine.backends import shell_backend, symbolic


@pytest.mark.parametrize(
    ("labels", "arg", "selected"),
    [
        (("bak*", "*"), "bak20260101", 0),
        (("bak*", "*"), "deploy", 1),
        (("bak*", "bak20260101"), "bak20260101", 0),
        (("*", "bak20260101"), "bak20260101", 0),
        (("archive|bak[0-9]?", "*"), "bak42", 0),
        (('"bak*"', "*"), "bak42", 1),
        (('"a|*|b"', "*"), "bak42", 1),
    ],
)
@pytest.mark.parametrize("nested", [False, True])
def test_shell_backend_case_glob_keeps_first_matching_branch(labels, arg, selected, nested):
    first_body = "echo first_branch ;;"
    if nested:
        first_body = "echo first_branch\n    case $2 in\n      x) echo nested_branch ;;\n    esac\n    ;;"
    script = f"case $1 in\n  {labels[0]}) {first_body}\n  {labels[1]}) echo second_branch ;;\nesac"

    ir = shell_backend.ShellBackend().parse(script, [arg])

    assert ir.control_flow_resolved
    markers = ("echo first_branch", "echo second_branch")
    assert markers[selected] in ir.reachable_content
    assert markers[1 - selected] not in ir.reachable_content


@pytest.mark.parametrize("terminator", [";&", ";;&"])
def test_shell_backend_case_fallthrough_keeps_later_branches(terminator):
    script = f"""case $1 in
  bak*) echo first_branch {terminator}
  *) echo second_branch ;;
esac"""

    ir = shell_backend.ShellBackend().parse(script, ["bak42"])

    assert not ir.control_flow_resolved
    assert "echo first_branch" in ir.reachable_content
    assert "echo second_branch" in ir.reachable_content


@pytest.mark.parametrize("selector", ["$1", '"$1"'])
@pytest.mark.parametrize("arg,selected", [("bak42", "first"), ("other", "second")])
def test_case_alternatives_match_in_both_parsers(selector, arg, selected):
    script = f"""case {selector} in
  archive|bak*) echo first_branch ;;
  *) echo second_branch ;;
esac"""

    diagnostics = {}
    ir = shell_backend.ShellBackend().parse(script, [arg], diagnostics=diagnostics)

    assert ir.control_flow_resolved
    assert f"echo {selected}_branch" in ir.reachable_content
    assert ("echo first_branch" in ir.reachable_content) is (selected == "first")
    assert ("echo second_branch" in ir.reachable_content) is (selected == "second")
    assert diagnostics["parser"] == ("shell_p1" if selector == "$1" else "shell_litese")


@pytest.mark.parametrize("selector", ["$1", '"$1"'])
@pytest.mark.parametrize("literal", ["# ;& ;;&", 'echo "case ;& ;;&"', r"echo \;\&", 'echo prefix";&"'])
def test_case_text_does_not_trigger_fallthrough(selector, literal):
    script = f"""case {selector} in
  bak*)
    {literal}
    echo first_branch ;; # ;&
  *) echo second_branch ;;
esac"""

    ir = shell_backend.ShellBackend().parse(script, ["bak42"])

    assert ir.control_flow_resolved
    assert "echo first_branch" in ir.reachable_content
    assert "echo second_branch" not in ir.reachable_content


@pytest.mark.parametrize("selector", ["$1", '"$1"'])
@pytest.mark.parametrize("terminator", [";&", ";;&"])
def test_case_fallthrough_tracks_bound_child(tmp_path, selector, terminator):
    from agent_moss.engine.script_engine.tracker import RecursiveTracker

    parent = tmp_path / "parent.sh"
    child = tmp_path / "child script.sh"
    child.write_text("echo child_body", encoding="utf-8")
    script = f"""case {selector} in
  bak*) echo first_branch {terminator} # keep scanning
  *) bash "$2" ;;
esac"""
    parent.write_text(script, encoding="utf-8")
    args = ["bak42", child.name]

    ir = shell_backend.ShellBackend().parse(script, args)
    result = RecursiveTracker().track(str(parent), args)

    assert not ir.control_flow_resolved
    assert "echo first_branch" in ir.reachable_content
    assert [call.path for call in ir.calls] == [child.name]
    assert [node.script_path for node in result.nodes] == [str(parent), str(child)]


@pytest.mark.parametrize("selector", ["$1", '"$1"'])
@pytest.mark.parametrize("arg", ["a", "b"])
def test_case_caret_negation_keeps_all_branches(selector, arg):
    script = f"""case {selector} in
  [^a]) echo first_branch ;;
  *) echo second_branch ;;
esac"""
    ir = shell_backend.ShellBackend().parse(script, [arg])

    assert not ir.control_flow_resolved
    assert "echo first_branch" in ir.reachable_content
    assert "echo second_branch" in ir.reachable_content


@pytest.mark.parametrize("selector", ["$1", '"$1"'])
@pytest.mark.parametrize("boundary", [";", "&&", "||"])
def test_inline_nested_case_keeps_outer_and_inner_bodies(selector, boundary):
    script = f"""case {selector} in
  bak*) echo before_nested {boundary} case "$2" in
      on) echo inner_on ;;
      off) echo inner_off ;;
    esac
    echo after_nested
    ;;
  *) echo outer_default ;;
esac"""

    ir = shell_backend.ShellBackend().parse(script, ["bak42", "off"])

    assert ir.control_flow_resolved
    for marker in ("inner_on", "inner_off", "after_nested"):
        assert f"echo {marker}" in ir.reachable_content
    assert "echo outer_default" not in ir.reachable_content


@pytest.mark.parametrize("selector", ["$1", '"$1"'])
@pytest.mark.parametrize("wrapper", ["time --", "time -p --"])
def test_timed_nested_case_keeps_inner_branches(selector, wrapper):
    script = f"""case {selector} in
  bak*) {wrapper} case "$2" in
      on) echo inner_on ;;
      off) echo inner_off ;;
    esac
    echo after_nested
    ;;
  *) echo outer_default ;;
esac"""

    ir = shell_backend.ShellBackend().parse(script, ["bak42", "off"])

    assert ir.control_flow_resolved
    for marker in ("inner_on", "inner_off", "after_nested"):
        assert f"echo {marker}" in ir.reachable_content
    assert "echo outer_default" not in ir.reachable_content


@pytest.mark.parametrize("selector", ["$1", '"$1"'])
@pytest.mark.parametrize("declaration", ["function worker", "worker()"])
def test_case_with_inline_function_keeps_full_text(selector, declaration):
    script = f"""case {selector} in
  bak*) echo before; {declaration} {{ case "$2" in
      on) echo inner_on ;;
      off) echo inner_off ;;
    esac
    }}
    worker
    echo after_function
    ;;
  *) echo outer_default ;;
esac"""

    ir = shell_backend.ShellBackend().parse(script, ["bak42", "off"])

    assert not ir.control_flow_resolved
    for marker in ("inner_on", "inner_off", "after_function", "outer_default"):
        assert f"echo {marker}" in ir.reachable_content


@pytest.mark.parametrize("selector", ["$1", '"$1"'])
def test_empty_array_assignment_does_not_disable_case_pruning(selector):
    script = f"""case {selector} in
  bak*) items=()
    echo selected_branch
    ;;
  *) echo other_branch ;;
esac"""

    ir = shell_backend.ShellBackend().parse(script, ["bak42"])

    assert ir.control_flow_resolved
    assert "items=()" in ir.reachable_content
    assert "echo selected_branch" in ir.reachable_content
    assert "echo other_branch" not in ir.reachable_content


def test_case_with_ambiguous_inline_closer_keeps_full_text():
    script = """case $1 in
  bak*) echo before; case $2 in
      off) echo inner_off ;; esac
    echo after
    ;;
  *) echo outer_default ;;
esac"""

    ir = shell_backend.ShellBackend().parse(script, ["bak42", "off"])

    assert not ir.control_flow_resolved
    assert "echo inner_off" in ir.reachable_content
    assert "echo after" in ir.reachable_content
    assert "echo outer_default" in ir.reachable_content


@pytest.mark.parametrize("selector", ["$1", '"$1"'])
@pytest.mark.parametrize("arg,selected", [("bak42", "first"), ("other", "second")])
def test_split_case_header_selects_branch(selector, arg, selected):
    script = f"""case {selector}
  # the keyword below completes the header
in
  bak*) echo first_branch ;;
  *) echo second_branch ;;
esac"""

    ir = shell_backend.ShellBackend().parse(script, [arg])

    assert ir.control_flow_resolved
    assert ("echo first_branch" in ir.reachable_content) is (selected == "first")
    assert ("echo second_branch" in ir.reachable_content) is (selected == "second")


def test_litese_child_arguments_preserve_shell_quoting(tmp_path):
    from agent_moss.engine.script_engine.tracker import RecursiveTracker

    parent = tmp_path / "parent.sh"
    child = tmp_path / "child.sh"
    script = r"""case "$1" in
  run) bash child.sh '$1' \$1 "\$1" "$1" "\${2}" "${2}" ;;
  *) echo other_branch ;;
esac"""
    parent.write_text(script, encoding="utf-8")
    child.write_text("""case "$1" in
  '$1') echo literal_branch ;;
  *) echo expanded_branch ;;
esac""", encoding="utf-8")
    args = ["run", 'two words; "$3"']

    diagnostics = {}
    ir = shell_backend.ShellBackend().parse(script, args, diagnostics=diagnostics)
    result = RecursiveTracker().track(str(parent), args)

    assert diagnostics["parser"] == "shell_litese"
    assert "'$1'" in ir.reachable_content
    assert r'"\$1"' in ir.reachable_content
    assert [(call.path, call.args) for call in ir.calls] == [
        ("child.sh", ["$1", "$1", "$1", "run", "${2}", args[1]])
    ]
    assert [node.script_path for node in result.nodes] == [str(parent), str(child)]
    assert "echo literal_branch" in result.nodes[1].preprocessed_content
    assert "echo expanded_branch" not in result.nodes[1].preprocessed_content


@pytest.mark.parametrize("selector", ["$1", '"$1"'])
def test_case_with_coproc_group_keeps_full_text(selector):
    script = f"""case {selector} in
  bak*) coproc worker {{ case "$2" in
      on) echo inner_on ;;
      off) echo inner_off ;;
    esac
    }}
    echo after_group
    ;;
  *) echo outer_default ;;
esac"""

    ir = shell_backend.ShellBackend().parse(script, ["bak42", "off"])

    assert not ir.control_flow_resolved
    for marker in ("inner_on", "inner_off", "after_group", "outer_default"):
        assert f"echo {marker}" in ir.reachable_content


@pytest.mark.parametrize(
    "args,default,expected",
    [
        (["child script.sh"], "$UNKNOWN", "child script.sh"),
        (["known.sh"], "$" + "{UNKNOWN}", "known.sh"),
        (["", "fallback.sh"], "$" + "{2}", "fallback.sh"),
        (["known.sh"], '"$UNKNOWN"', "known.sh"),
        (["known.sh"], "$" + "{UNKNOWN:-$OTHER}", "known.sh"),
        ([""], "$UNKNOWN", None),
    ],
)
def test_child_path_uses_positional_default_only_as_needed(tmp_path, args, default, expected):
    from agent_moss.engine.script_engine.tracker import RecursiveTracker

    script = 'bash "$' + '{1:-' + default + '}" run'
    parent = tmp_path / "parent.sh"
    parent.write_text(script, encoding="utf-8")
    if expected is not None:
        (tmp_path / expected).write_text("echo child_body", encoding="utf-8")

    ir = shell_backend.ShellBackend().parse(script, args)
    result = RecursiveTracker().track(str(parent), args)

    assert [(call.path, call.args) for call in ir.calls] == (
        [(expected, ["run"])] if expected is not None else []
    )
    assert [node.script_path for node in result.nodes[1:]] == (
        [str(tmp_path / expected)] if expected is not None else []
    )


def test_child_calls_require_shell_command_position():
    script = """echo Usage: bash ignored.sh
printf 'Example: bash quoted.sh; bash ignored.sh'
echo help bash ignored.sh; true && bash first.sh
echo input | bash second.sh
if bash check.sh; then bash third.sh; fi
case "$1" in
  run) bash case_child.sh ;;
esac"""

    calls = shell_backend.extract_calls_from_content(script)

    assert [call.path for call in calls] == [
        "first.sh", "second.sh", "check.sh", "third.sh", "case_child.sh",
    ]


@pytest.mark.parametrize("launcher", [
    "/usr/bin/bash",
    "/usr/local/bin/bash",
    "/usr/bin/python3",
    "/usr/local/bin/python3.12",
    "/bin/bash",
])
def test_absolute_interpreter_paths_extract_child_call(launcher):
    calls = shell_backend.extract_calls_from_content(f"{launcher} child.sh --flag")
    assert [(call.path, call.args) for call in calls] == [("child.sh", ["--flag"])]
    assert calls[0].interpreter == launcher


def test_wrapped_shell_calls_require_command_position():
    script = """echo Usage: time bash ignored_time.sh
printf '%s\\n' Example: env bash ignored_env.sh
time bash timed.sh first
time -p -- bash timed_options.sh second
env bash env_plain.sh third
/usr/bin/env -i MODE=test bash env_assigned.sh fourth
"""

    calls = shell_backend.extract_calls_from_content(script)

    assert [(call.path, call.args) for call in calls] == [
        ("timed.sh", ["first"]),
        ("timed_options.sh", ["second"]),
        ("env_plain.sh", ["third"]),
        ("env_assigned.sh", ["fourth"]),
    ]


def test_shell_wrapper_options_preserve_command_position():
    script = """echo Usage: command -- bash ignored.sh
printf '%s\n' Example: exec -- bash ignored.sh
command -v bash ignored.sh
command -- bash command_child.sh one
exec -- bash exec_child.sh two
env -u UNUSED bash env_child.sh three
env -u bash sh env_sh_child.sh four
"""

    calls = shell_backend.extract_calls_from_content(script)

    assert [(call.path, call.args, call.interpreter) for call in calls] == [
        ("command_child.sh", ["one"], "bash"),
        ("exec_child.sh", ["two"], "bash"),
        ("env_child.sh", ["three"], "bash"),
        ("env_sh_child.sh", ["four"], "sh"),
    ]


@pytest.mark.parametrize("quote", ["", '"'])
@pytest.mark.parametrize("path", ["known.sh", ""])
@pytest.mark.parametrize(
    "default", ["""$(printf '%s' "$(printf '%s' '})')")""", "`printf fallback.sh`"],
)
def test_child_path_ignores_unused_command_substitution(quote, path, default):
    expression = "$" + "{1:-" + default + "}"
    script = "bash " + quote + expression + quote + " run"

    ir = shell_backend.ShellBackend().parse(script, [path])

    assert [(call.path, call.args) for call in ir.calls] == (
        [("known.sh", ["run"])] if path else []
    )
    expected_text = "known.sh" if path else expression
    assert expected_text in ir.reachable_content


@pytest.mark.parametrize(
    "first_command",
    [
        'printf "%s" note # trailing "',
        "printf '%s' note # trailing '$1",
        'printf "%s" "$' + '{2:-$(printf "%s" fallback)}"',
    ],
)
def test_shell_binding_continues_after_comment_or_unsupported_command(first_command):
    script = first_command + '\nprintf %s $1\n'

    ir = shell_backend.ShellBackend().parse(script, ["visible"])

    assert ir.reachable_content == first_command + '\nprintf %s visible\n'


@pytest.mark.parametrize(
    "quote,default,expected",
    [
        ("", "one two", ["one", "two"]),
        ('"', "one two", ["one two"]),
        ("", r"one\ two tail", ["one two", "tail"]),
        ('"', "'one two'", ["'one two'"]),
        ("", "'one two'", ["one two"]),
        ('"', '"one two"', ["one two"]),
    ],
)
def test_positional_default_fields_follow_shell_quoting(quote, default, expected):
    script = "bash child.sh " + quote + "$" + "{1:-" + default + "}" + quote

    calls = shell_backend.ShellBackend().parse(script, [""]).calls

    assert [(call.path, call.args) for call in calls] == [("child.sh", expected)]


def test_double_quoted_default_preserves_literal_apostrophes_during_expansion():
    script = "bash child.sh \"$" + "{1:-'prefix $2'}\""

    calls = shell_backend.ShellBackend().parse(script, ["", "expanded"]).calls

    assert [(call.path, call.args) for call in calls] == [
        ("child.sh", ["'prefix expanded'"]),
    ]


@pytest.mark.parametrize("language", ["shell", "python"])
@pytest.mark.parametrize("substitution", [
    "$(printf '%s' runtime)",
    "$(printf '%s' \"$" + "{2:-runtime}\")",
])
@pytest.mark.parametrize("quote", ['"', ""])
def test_unknown_child_arguments_prevent_branch_pruning(tmp_path, language, substitution, quote):
    from agent_moss.engine.script_engine.tracker import RecursiveTracker

    parent = tmp_path / "parent.sh"
    if language == "shell":
        child = tmp_path / "child.sh"
        launcher = "bash"
        source = """case "$""" + """{1:-first}" in
  first) echo first_branch ;;
  *) echo other_branch ;;
esac"""
    else:
        child = tmp_path / "child.py"
        launcher = "python3"
        source = """import sys
mode = sys.argv[1] if len(sys.argv) > 1 else "first"
if mode == "first":
    print("first_branch")
else:
    print("other_branch")
"""
    script = f"""{launcher} {child.name} first {quote}{substitution}{quote} later
bash incomplete{quote}$(printf '%s' suffix){quote} later
"""
    parent.write_text(script, encoding="utf-8")
    child.write_text(source, encoding="utf-8")

    ir = shell_backend.ShellBackend().parse(script, [])
    result = RecursiveTracker().track(str(parent), [])

    assert [call.path for call in ir.calls] == [child.name]
    assert ir.calls[0].args == []
    assert not ir.calls[0].args_known
    assert [node.script_path for node in result.nodes] == [str(parent), str(child)]
    assert "first_branch" in result.nodes[1].preprocessed_content
    assert "other_branch" in result.nodes[1].preprocessed_content


def test_quoted_nested_default_retains_unresolved_expression():
    inner = "$" + "{2:-$(printf '%s' runtime)}"
    outer = "$" + "{1:-" + inner + "}"
    script = f'printf "%s" "{outer}"'

    ir = shell_backend.ShellBackend().parse(script, ["", ""])

    assert ir.reachable_content == script

    ir = shell_backend.ShellBackend().parse(script, ["", "known"])
    assert ir.reachable_content == 'printf "%s" "known"'


def test_tracker_visits_calls_with_distinct_arguments_and_stops_cycles(tmp_path):
    from agent_moss.engine.script_engine.tracker import RecursiveTracker

    parent = tmp_path / "parent.sh"
    child = tmp_path / "child.sh"
    parent.write_text(
        "bash child.sh first; bash child.sh first; bash child.sh second\n",
        encoding="utf-8",
    )
    child.write_text("""case $1 in
  first) echo first_branch ;;
  second) echo second_branch ;;
esac
bash parent.sh different
""", encoding="utf-8")

    result = RecursiveTracker().track(str(parent), ["original"])

    assert [node.script_path for node in result.nodes] == [str(parent), str(child), str(child)]
    assert "echo first_branch" in result.nodes[1].preprocessed_content
    assert "echo second_branch" in result.nodes[2].preprocessed_content


def test_import_after_direct_call_scans_no_arg_branch(tmp_path):
    """import 的执行参数与直接调用不同，不能被去重短路。

    先 `python3 child.py safe` 扫描过 safe 分支，再由 `from . import child`
    以无参上下文导入；child 在无参时会走 else 危险分支，必须重新扫描。
    """
    from agent_moss.engine.script_engine.tracker import RecursiveTracker

    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    child = pkg / "child.py"
    child.write_text(
        "import sys\n"
        "if len(sys.argv) > 1 and sys.argv[1] == 'safe':\n"
        "    print('SAFE_BRANCH')\n"
        "else:\n"
        "    print('IMPORT_DANGER')\n",
        encoding="utf-8",
    )
    (pkg / "parent.py").write_text("from . import child\n", encoding="utf-8")
    root = tmp_path / "root.sh"
    root.write_text("python3 pkg/child.py safe\npython3 pkg/parent.py\n", encoding="utf-8")

    result = RecursiveTracker().track(str(root), [])
    child_contents = [n.preprocessed_content for n in result.nodes if n.script_path == str(child)]
    assert any("SAFE_BRANCH" in text for text in child_contents), child_contents
    assert any("IMPORT_DANGER" in text for text in child_contents), child_contents


def test_single_bracket_glob_is_not_static_pattern_match():
    """`[ "$1" = bak* ]` 的 * 先做 pathname expansion，不能据此选分支。"""
    script = '''if [ "$1" = bak* ]; then
  echo SAFE
else
  rm -rf /tmp/DANGER
fi
'''
    ir = shell_backend.ShellBackend().parse(script, ["bak42"])
    assert not ir.control_flow_resolved
    assert "rm -rf /tmp/DANGER" in ir.reachable_content


def test_quoted_if_glob_is_literal_not_pattern():
    """引号内的 * 是字面量，不能被当成 glob 选中 then 分支。"""
    script = '''if [ "$1" = "a*b" ]; then
  echo SAFE
else
  rm -rf /tmp/DANGER
fi
'''
    ir = shell_backend.ShellBackend().parse(script, ["aXb"])
    assert "rm -rf /tmp/DANGER" in ir.reachable_content
    assert "echo SAFE" not in ir.reachable_content


def test_glob_if_keeps_dangerous_command():
    script = '''if [[ "$1" == bak* ]]; then
  rm -rf /opt/data
else
  echo safe
fi
'''
    args = ["bak20260101"]
    assert "rm -rf /opt/data" in (symbolic.symbolic_process(script, args) or "")
    assert "rm -rf /opt/data" in (shell_backend.parse_if(script, args) or "")


def test_regex_if_keeps_dangerous_command():
    script = '''if [[ "$1" =~ ^ba.* ]]; then
  rm -rf /opt/data
else
  echo safe
fi
'''
    args = ["baz"]
    assert "rm -rf /opt/data" in (symbolic.symbolic_process(script, args) or "")
    assert "rm -rf /opt/data" in (shell_backend.parse_if(script, args) or "")


def test_nested_case_keeps_outer_command():
    script = '''MODE=x
case "$MODE" in
  x)
    rm -rf /opt/data
    case "$2" in
      x) echo inner ;;
    esac
    ;;
esac
'''
    out = symbolic.symbolic_process(script, ["run", "x"]) or ""
    assert "rm -rf /opt/data" in out


def test_startup_args_respect_var_budget():
    # 199 个启动参数 + $@/$* = 201 > 200 → 放弃精确分析、回退全文
    args = [f"a{i}" for i in range(199)]
    assert symbolic.symbolic_process("MODE=x\n", args) is None


def test_modify_existing_var_at_budget_continues():
    # 200 个变量填满预算后，修改已有变量不增加表项，不应触发回退
    script = "\n".join([f"V{i}=x" for i in range(200)] + ["V0=y"])
    assert symbolic.symbolic_process(script, None) is not None


def test_branch_selection_reaches_l1_scanner(tmp_path):
    """接口级回归：危险分支必须真正进入 CommandPatternScanner，而不只是内部函数输出。"""
    from agent_moss.engine.heuristic import CommandPatternScanner
    from agent_moss.engine.script_content_analyzer import analyze_script_content
    from agent_moss.profiles.linux import LinuxProfile

    script = '''if [[ "$1" == bak* ]]; then
  rm -rf /opt/data
else
  echo safe
fi
'''
    (tmp_path / "x.sh").write_text(script, encoding="utf-8")
    scanner = CommandPatternScanner(LinuxProfile())
    result = analyze_script_content(
        "bash", "bash x.sh bak20260101", command_scanner=scanner, cwd=str(tmp_path)
    )
    assert result.has_high or result.has_critical


def test_nested_case_inner_dangerous_command():
    """内层 case 的危险分支不能被外层分支切分吞掉（openEuler 回归）。"""
    script = '''case $1 in
  clean)
    case $2 in
      hard) rm -rf ~/.ssh/id_rsa ;;
      soft) echo safe ;;
    esac
    ;;
  backup) echo safe ;;
esac
'''
    out = symbolic.symbolic_process(script, ["clean", "hard"]) or ""
    assert "rm -rf ~/.ssh/id_rsa" in out


def test_nested_if_keeps_outer_command():
    """报告示例的嵌套 if 形态：外层危险命令不能被内层 if 覆盖。"""
    script = '''if [ "$1" = x ]; then
  rm -rf /opt/data
  if [ "$2" = x ]; then
    echo inner
  fi
fi
'''
    out = symbolic.symbolic_process(script, ["x", "x"]) or ""
    assert "rm -rf /opt/data" in out
