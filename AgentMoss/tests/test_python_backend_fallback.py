"""Regression tests for static child calls in the Python fallback."""

from unittest.mock import Mock, call

import pytest

from agent_moss.engine.script_content_analyzer import analyze_script_content
from agent_moss.engine.script_engine import tracker
from agent_moss.engine.script_engine.backends.python_backend import PythonBackend
from agent_moss.engine.script_engine.ir import ScriptCall
from agent_moss.engine.types import HeuristicResult


def _with_lines(source, count):
    physical_lines = source.count("\n") + int(bool(source) and not source.endswith("\n"))
    return "pass\n" * (count - physical_lines) + source


@pytest.fixture(params=["syntax_error", "line_budget"])
def reason(request):
    return request.param


def _fallback_source(source, reason):
    if reason == "line_budget":
        return _with_lines(source, 501)
    return source + '\nif True print("broken")'


def _assert_fallback(source, reason, calls):
    diagnostics = {}
    ir = PythonBackend().parse(source, [], diagnostics=diagnostics)
    assert ir.reachable_content == source
    assert ir.control_flow_resolved is False
    assert diagnostics["fallback_reason"] == reason
    assert [(c.interpreter, c.path, c.args) for c in ir.calls] == [
        (c.interpreter, c.path, c.args) for c in calls
    ]
    for actual, expected in zip(ir.calls, calls):
        if expected.launch_cwd is not None:
            assert actual.launch_cwd == expected.launch_cwd
    return diagnostics


@pytest.mark.parametrize("invocation", [
    'os.system("bash child.sh clean")',
    'subprocess.run(\n    ["bash", "child.sh", "clean"],\n)',
    'subprocess.run("bash child.sh clean", shell=True)',
    'bash child.sh clean',
])
def test_static_child_call(reason, invocation):
    _assert_fallback(_fallback_source(invocation, reason), reason, [
        ScriptCall(path="child.sh", args=["clean"], interpreter="bash"),
    ])


@pytest.mark.parametrize("source", [
    "true && bash child.sh weekly",
    'os.system("""\n    true && bash child.sh weekly\n""")',
])
def test_existing_literal_child_after_connector(reason, source):
    _assert_fallback(_fallback_source(source, reason), reason, [
        ScriptCall(path="child.sh", args=["weekly"], interpreter="bash"),
    ])


def test_bare_literal_commands_on_one_line_keep_extensionless_paths(reason):
    source = 'bash ./tools/prepare clean; /bin/bash ./tools/report weekly'
    _assert_fallback(_fallback_source(source, reason), reason, [
        ScriptCall(path="./tools/prepare", args=["clean"], interpreter="bash"),
        ScriptCall(path="./tools/report", args=["weekly"], interpreter="/bin/bash"),
    ])


def test_multiline_shell_literal_retains_calls_around_output_redirection(reason):
    source = 'os.system("""\n    bash first.sh clean > report.txt\n    bash second.sh daily\n""")'
    _assert_fallback(_fallback_source(source, reason), reason, [
        ScriptCall(path="first.sh", args=["clean"], interpreter="bash"),
        ScriptCall(path="second.sh", args=["daily"], interpreter="bash"),
    ])


@pytest.mark.parametrize("mode", ["python_ast", "syntax_error", "line_budget"])
@pytest.mark.parametrize("command", [
    "echo ready\nexec bash child.sh 'two words' clean",
    "bash child.sh 'two words' clean\necho bash notes.sh weekly > output.txt",
    "echo bash notes.sh >>output.txt; exec bash child.sh 'two words' 2>output.txt clean",
    "false && exec bash notes.sh; echo 'exec bash notes.sh' >output.txt && exec bash child.sh 'two words' clean",
    "LC_ALL=C bash child.sh 'two words' clean",
    "bash child.sh 'two words' clean\nexit\nbash notes.sh 'two words' clean",
    "LANG='two words' 2>output.txt LC_ALL=C exec bash child.sh 'two words' clean && bash notes.sh",
    "'LANG=C' bash notes.sh\nLANG\\=C bash notes.sh\necho LC_ALL=C bash notes.sh\n"
    "LC_ALL=C bash child.sh 'two words' clean\n'exit' 0\nbash notes.sh",
    "false && LC_ALL=C exit 1; false || LABEL=ready && bash child.sh 'two words' clean",
    "echo ready && exit 0; bash child.sh 'two words' clean",
])
def test_literal_shell_command_heads_and_redirects(tmp_path, mode, command):
    for name in ("notes.sh", "output.txt"):
        (tmp_path / name).write_text("echo REFERENCE_DATA\n", encoding="utf-8")
    source = 'import os\nos.system("""\n' + command.replace("\\", "\\\\") + '\n""")'
    if mode != "python_ast":
        source = _fallback_source(source, mode)
    _, details = _scan_marked_child(tmp_path, source)
    assert details.get("fallback_reason", details["parser"]) == mode


def test_shell_assignment_after_script_name_is_an_argument():
    source = """os.system("LC_ALL=C bash child.sh LANG=C clean")"""
    assert PythonBackend().parse(source, []).calls == [
        ScriptCall(path="child.sh", interpreter="bash", args=["LANG=C", "clean"]),
    ]


def test_subprocess_string_and_argv_observe_shell_mode(reason):
    source = """subprocess.run("bash unused.sh 'two words'")
subprocess.run("bash unused.sh 'two words'", shell=False)
subprocess.run(["bash", "unused.sh", "two words"], shell=True)
subprocess.run(["bash", "direct.sh", "two words"])
subprocess.run("bash shell.sh 'two words'", shell=True)"""
    _assert_fallback(_fallback_source(source, reason), reason, [
        ScriptCall(path="direct.sh", args=["two words"], interpreter="bash"),
        ScriptCall(path="shell.sh", args=["two words"], interpreter="bash"),
    ])


@pytest.mark.parametrize("parse_mode", ["python_ast", "syntax_error", "line_budget"])
def test_env_delegates_only_to_the_named_program(tmp_path, parse_mode):
    source = (
        'import os, subprocess\n'
        'os.system("echo env bash notes.sh")\n'
        'os.system("env cat notes.sh")\n'
        'subprocess.run(["env", "printf", "bash", "notes.sh"])\n'
        'subprocess.run(["/usr/bin/env", "--", "LC_ALL=C", "bash", "child.sh", "two words", "clean"])'
    )
    if parse_mode != "python_ast":
        source = _fallback_source(source, parse_mode)
    (tmp_path / "notes.sh").write_text("echo DATA_ONLY\n", encoding="utf-8")
    _scan_marked_child(tmp_path, source)


def test_env_without_a_script_keeps_the_next_command():
    command = "env printf ready\n/usr/bin/env LC_ALL=C bash child.sh 'two words' clean"
    result = PythonBackend().parse(f"os.system({command!r})\nif :", [])
    assert [(c.interpreter, c.path, c.args) for c in result.calls] == [("bash", "child.sh", ["two words", "clean"])]


@pytest.mark.parametrize("parse_mode", ["python_ast", "syntax_error", "line_budget"])
def test_subprocess_uses_actual_interpreter_for_literal_scripts(parse_mode):
    source = """subprocess.run(["/usr/bin/python3.12", "versioned.py", "two words"])
subprocess.run([".venv/bin/python", "venv.py", "two words"])
subprocess.run(["/bin/dash", "shell.sh", "two words"])
subprocess.run(["python3", "explicit.py", "two words"], executable="/usr/bin/python3")
subprocess.Popen(["launcher", "override.sh", "two words"], -1, "/bin/dash")
subprocess.run("bash text.sh 'two words'", shell=True, executable="/bin/dash")
subprocess.run(["sh", "notes.sh"], executable="/bin/cat")
subprocess.run("bash notes.sh", shell=True, executable="/bin/echo")
subprocess.run(["cat", "notes.sh"])"""
    if parse_mode != "python_ast":
        source = _fallback_source(source, parse_mode)
    diagnostics = {}
    result = PythonBackend().parse(source, [], diagnostics=diagnostics)
    assert diagnostics.get("fallback_reason", diagnostics["parser"]) == parse_mode
    assert [(c.interpreter, c.path, c.args) for c in result.calls] == [
        ("/usr/bin/python3.12", "versioned.py", ["two words"]),
        (".venv/bin/python", "venv.py", ["two words"]),
        ("/bin/dash", "shell.sh", ["two words"]),
        ("/usr/bin/python3", "explicit.py", ["two words"]),
        ("/bin/dash", "override.sh", ["two words"]),
        ("bash", "text.sh", ["two words"]),
    ]


@pytest.mark.parametrize("parse_mode", ["python_ast", "syntax_error", "line_budget"])
def test_subprocess_unpacks_literal_options_at_the_call_site(tmp_path, parse_mode):
    argv = '["bash", "child.sh", "two words", "clean"]'
    source = (
        'import subprocess\n'
        'subprocess.run(["bash", "notes.sh"], **{"executable": "/bin/cat"})\n'
        'subprocess.run(["bash", "notes.sh"], cwd=".", **{"cwd": "."})\n'
        'subprocess.run(["bash", "notes.sh"], **options)\n'
        f'subprocess.run({argv}, **{{"check": True}})'
    )
    if parse_mode != "python_ast":
        source = _fallback_source(source, parse_mode)
    (tmp_path / "notes.sh").write_text("echo DATA_ONLY\n", encoding="utf-8")
    _scan_marked_child(tmp_path, source)


def test_mapping_supplies_command_and_child_working_directory(tmp_path):
    (tmp_path / "jobs").mkdir()
    child = tmp_path / "jobs/child.sh"
    child.write_text("echo JOB_MARKER\n", encoding="utf-8")
    (tmp_path / "child.sh").write_text("echo ROOT_MARKER\n", encoding="utf-8")
    parent = tmp_path / "parent.py"
    parent.write_text(
        'import subprocess\n'
        'subprocess.run(**{"args": ["sh", "child.sh"], **{"cwd": "."}, "cwd": "jobs"})',
        encoding="utf-8",
    )
    result = analyze_script_content("bash", "python3 parent.py", cwd=str(tmp_path))
    assert [node.script_path for node in result.nodes] == [str(parent), str(child)]
    assert result.nodes[1].preprocessed_content == "echo JOB_MARKER\n"


@pytest.mark.parametrize("mode", ["syntax_error", "500", "501"])
def test_imported_calls_on_both_sides_of_main_directory_change(tmp_path, monkeypatch, mode):
    source = (
        'import os as process\nfrom os import system as launch\nfrom subprocess import run as run_child\n'
        'def helper():\n    pass\n'
        + ('label = "draft\n' if mode == "syntax_error" else '')
        + 'if __name__ == "__main__":\n'
        '    launch("bash child.sh \'two words\' clean")\n'
        '    process.chdir("jobs")\n'
        '    run_child(["bash", "child.sh", "two words", "clean"], **{"check": True})\n'
    )
    if mode != "syntax_error":
        source = _with_lines(source, int(mode))
    parent = tmp_path / "parent.py"
    parent.write_text(source, encoding="utf-8")
    (tmp_path / "jobs").mkdir()
    children = [tmp_path / "child.sh", tmp_path / "jobs/child.sh"]
    for child, marker in zip(children, ["FIRST", "SECOND"]):
        child.write_text(
            f'if [ "${{1}}:${{2}}" = "two words:clean" ]; then\n echo {marker}\nelse\n echo WRONG\nfi\n',
            encoding="utf-8",
        )
    shell_parse = Mock(wraps=tracker._DEFAULT_BACKEND.parse)
    monkeypatch.setattr(tracker._DEFAULT_BACKEND, "parse", shell_parse)
    result = analyze_script_content("bash", "python3 parent.py", cwd=str(tmp_path))
    assert [node.script_path for node in result.nodes] == [str(path) for path in [parent, *children]]
    assert [entry.args[1] for entry in shell_parse.call_args_list] == [["two words", "clean"]] * 2
    for node, marker in zip(result.nodes[1:], ["FIRST", "SECOND"]):
        assert marker in node.preprocessed_content
        assert "WRONG" not in node.preprocessed_content


def test_subprocess_overrides_and_shell_state_do_not_invent_a_local_call(reason):
    source = """subprocess.Popen(["sh", "notes.sh"], -1, "/bin/echo")
subprocess.Popen(["sh", "notes.sh"], executable="/bin/echo")
subprocess.Popen(["sh", "notes.sh"], -1, None, None, None, None, None, True, False, "elsewhere")
subprocess.run(["sh", "notes.sh"], cwd="elsewhere")
os.system("cd elsewhere; sh notes.sh")
os.system("exit; sh notes.sh")
os.system("sh real.sh")"""
    _assert_fallback(_fallback_source(source, reason), reason, [
        ScriptCall(path="notes.sh", interpreter="sh", launch_cwd="elsewhere"),
        ScriptCall(path="real.sh", interpreter="sh"),
    ])


def test_unquoted_tilde_keeps_prior_bare_path_and_is_not_a_literal_argument(reason):
    source = """bash ~/child.sh clean
os.system("bash child.sh ~")
subprocess.run(["sh", "real.sh", "~"])"""
    _assert_fallback(_fallback_source(source, reason), reason, [
        ScriptCall(path="~/child.sh", args=["clean"], interpreter="bash"),
        ScriptCall(path="real.sh", args=["~"], interpreter="sh"),
    ])


def test_multiline_elif_uses_the_branch_selected_by_python_analysis(tmp_path):
    source = (
        'import os\nif (\n    False\n):\n    os.system("bash notes.sh")\n'
        'elif (\n    __name__ == "__main__"\n):\n    os.system("bash child.sh \'two words\' clean")\n'
        'else:\n    os.system("bash notes.sh")'
    )
    (tmp_path / "notes.sh").write_text("echo UNSELECTED\n", encoding="utf-8")
    _scan_marked_child(tmp_path, source)


def test_500_lines_use_the_normal_ast_and_prune_unreachable_calls():
    source = _with_lines(
        'if False:\n    os.system("bash skipped.sh")\nos.system("bash child.sh clean")', 500,
    )
    diagnostics = {}
    ir = PythonBackend().parse(source, [], diagnostics=diagnostics)
    assert diagnostics["parser"] == "python_ast"
    assert diagnostics["physical_lines"] == 500
    assert ir.control_flow_resolved is True
    assert "skipped.sh" not in ir.reachable_content
    assert ir.calls == [ScriptCall(path="child.sh", args=["clean"], interpreter="bash")]


@pytest.mark.parametrize("line_count", [499, 500, 501])
@pytest.mark.parametrize("newline", ["", "\n"], ids=["no-final-newline", "final-newline"])
def test_child_files_and_arguments_across_line_budget(tmp_path, monkeypatch, line_count, newline):
    source = _with_lines(
        'import os, subprocess\n'
        'subprocess.run(["cat", "notes.sh"])\n'
        'os.system("""\nbash first.sh\nbash child.sh \'two words\' clean\necho bash notes.sh weekly\n""")',
        line_count,
    ) + newline
    (tmp_path / "parent.py").write_text(source, encoding="utf-8")
    (tmp_path / "notes.sh").write_text("echo DATA_ONLY\n", encoding="utf-8")
    (tmp_path / "first.sh").write_text("echo FIRST\n", encoding="utf-8")
    (tmp_path / "child.sh").write_text(
        'if [ "${1}:${2}" = "two words:clean" ]; then\n echo SELECTED\nelse\n echo OTHER\nfi\n',
        encoding="utf-8",
    )
    shell_parse = Mock(wraps=tracker._DEFAULT_BACKEND.parse)
    monkeypatch.setattr(tracker._DEFAULT_BACKEND, "parse", shell_parse)
    scanner = Mock()
    scanner.scan.return_value = HeuristicResult()

    result = analyze_script_content("bash", "python3 parent.py", cwd=str(tmp_path), command_scanner=scanner)

    assert [node.script_path for node in result.nodes] == [
        str(tmp_path / name) for name in ("parent.py", "first.sh", "child.sh")
    ]
    assert [entry.args[1] for entry in shell_parse.call_args_list] == [[], ["two words", "clean"]]
    scanned = [entry.args[0] for entry in scanner.scan.call_args_list]
    assert len(scanned) == 3
    assert "FIRST" in scanned[1]
    assert "SELECTED" in scanned[2] and "OTHER" not in scanned[2]


def test_pruned_multiline_commands_and_data_are_not_children(tmp_path):
    source = _with_lines(
        'import os\nexample = """\nbash data.sh\n"""\n'
        'if False:\n    os.system("""\nbash hidden.sh\n""")\n',
        500,
    )
    for name in ("hidden.sh", "data.sh"):
        (tmp_path / name).write_text("echo UNUSED\n", encoding="utf-8")
    parent = tmp_path / "parent.py"
    parent.write_text(source, encoding="utf-8")
    result = analyze_script_content("bash", "python3 parent.py", cwd=str(tmp_path))
    assert [node.script_path for node in result.nodes] == [str(parent)]


@pytest.mark.parametrize("line_count", [500, 501])
def test_main_guard_with_imported_system_at_line_budget(tmp_path, line_count):
    source = _with_lines(
        'from os import system\nif __name__ == "__main__":\n'
        '    system("bash child.sh \'two words\' clean")\n',
        line_count,
    )
    _scan_marked_child(tmp_path, source)


def test_comments_strings_and_unresolved_paths_are_not_calls(reason):
    source = '''# bash comment.sh
"""Illustration:
bash doc.sh
"""
print('os.system("bash sample.sh")')
os.system(command)
subprocess.run(["bash", filename])
os.system("bash real.sh")
'''
    _assert_fallback(_fallback_source(source, reason), reason, [
        ScriptCall(path="real.sh", interpreter="bash"),
    ])


def test_fstring_calls_are_extracted_only_from_replacement_fields(reason):
    source = (
        'message = f"""os.system(\'bash example.sh\') {{os.system(\'bash escaped.sh\')}} '
        '{subprocess.check_output([\'bash\', \'actual.sh\', \'two words\'])}"""'
    )
    _assert_fallback(_fallback_source(source, reason), reason, [
        ScriptCall(path="actual.sh", args=["two words"], interpreter="bash"),
    ])


def test_calls_keep_source_order_and_distinct_arguments(reason):
    first = 'os.system("bash child.sh first")'
    second = 'subprocess.run(["bash", "child.sh", "second"])'
    source = _fallback_source("\n".join([first, second, first]), reason)
    _assert_fallback(source, reason, [
        ScriptCall(path="child.sh", args=["first"], interpreter="bash"),
        ScriptCall(path="child.sh", args=["second"], interpreter="bash"),
    ])


@pytest.mark.parametrize("reason", ["python_ast", "line_budget", "syntax_error"])
@pytest.mark.parametrize("source", [
    'mode = "early"\n'
    'subprocess.run(["sh", "child.sh", mode, (mode := "late"), mode])\n'
    'subprocess.run(["sh", "next.sh", mode])',
    'cmd = "sh child.sh early"\n'
    'subprocess.run(cmd, shell=True, input=(cmd := "sh next.sh late"))\n'
    'os.system(cmd)',
    'cmd = "sh child.sh early"\n'
    'subprocess.run(shell=True, args=cmd, input=(cmd := "sh next.sh late"))\n'
    'os.system(cmd)',
])
def test_launch_arguments_capture_values_before_later_assignments(tmp_path, monkeypatch, reason, source):
    parent = tmp_path / "parent.py"
    text = "import subprocess, os\n" + source
    parent.write_text(text if reason == "python_ast" else _fallback_source(text, reason), encoding="utf-8")
    for name in ("child.sh", "next.sh"):
        (tmp_path / name).write_text("echo CHILD\n", encoding="utf-8")
    shell_parse = Mock(wraps=tracker._DEFAULT_BACKEND.parse)
    monkeypatch.setattr(tracker._DEFAULT_BACKEND, "parse", shell_parse)
    result = analyze_script_content("bash", "python3 parent.py", cwd=str(tmp_path))
    first_args = ["early", "late", "late"] if source.startswith("mode =") else ["early"]
    assert [node.script_path for node in result.nodes] == [str(parent), str(tmp_path / "child.sh"), str(tmp_path / "next.sh")]
    assert [entry.args[1] for entry in shell_parse.call_args_list] == [first_args, ["late"]]


@pytest.mark.parametrize("reason", ["python_ast", "line_budget", "syntax_error"])
def test_keyword_directory_is_captured_before_a_later_kwarg(tmp_path, reason):
    source = ('import subprocess\ndirectory = "first"\n'
              'subprocess.run(["sh", "child.sh"], **{"cwd": directory, "input": (directory := "second")})\n'
              'subprocess.run(["sh", "child.sh"], cwd=directory)')
    parent = tmp_path / "parent.py"
    parent.write_text(source if reason == "python_ast" else _fallback_source(source, reason), encoding="utf-8")
    paths = [tmp_path / name / "child.sh" for name in ("first", "second")]
    for path in paths:
        path.parent.mkdir()
        path.write_text("echo MARKER\n", encoding="utf-8")
    result = analyze_script_content("bash", "python3 parent.py", cwd=str(tmp_path))
    assert [node.script_path for node in result.nodes] == [str(parent), *(str(path) for path in paths)]


@pytest.mark.parametrize("reason", ["python_ast", "line_budget", "syntax_error"])
def test_opaque_later_argument_keeps_only_the_already_captured_command(reason):
    source = ('import os, subprocess\ncmd = "sh child.sh early"\nnext_cmd = "sh stale.sh"\n'
              'subprocess.run(cmd, shell=True, input=update())\nos.system(next_cmd)')
    if reason != "python_ast":
        source = _fallback_source(source, reason)
    result = PythonBackend().parse(source, [])
    assert [(call.path, call.args) for call in result.calls] == [("child.sh", ["early"])]


@pytest.mark.parametrize("reason", ["python_ast", "line_budget", "syntax_error"])
@pytest.mark.parametrize("iterable,expected", [
    ('["sh inner.sh inside"]', {"inner.sh": ["inside"]}),
    ('(cmd,)', {"outer.sh": ["outside"]}),
    ("values", {}),
    ("[]", {}),
    ('["sh inner.sh inside"] if False', {}),
])
def test_comprehension_scope_for_child_commands(tmp_path, monkeypatch, reason, iterable, expected):
    source = (
        'import os, subprocess\ncmd = "sh outer.sh outside"\n'
        f'[os.system(cmd) for cmd in {iterable}]\n'
        'subprocess.run(["sh", "after.sh", cmd])'
    )
    parent = tmp_path / "parent.py"
    parent.write_text(source if reason == "python_ast" else _fallback_source(source, reason), encoding="utf-8")
    for child in ("outer.sh", "inner.sh", "after.sh"):
        (tmp_path / child).write_text("echo MARKER\n", encoding="utf-8")
    shell_parse = Mock(wraps=tracker._DEFAULT_BACKEND.parse)
    monkeypatch.setattr(tracker._DEFAULT_BACKEND, "parse", shell_parse)
    result = analyze_script_content("bash", "python3 parent.py", cwd=str(tmp_path))
    children = result.nodes[1:]
    assert result.nodes[0].script_path == str(parent)
    assert len(children) == len(shell_parse.call_args_list) == len(expected) + 1
    assert {node.script_path: entry.args[1] for node, entry in zip(children, shell_parse.call_args_list)} == {
        str(tmp_path / name): args for name, args in {**expected, "after.sh": ["sh outer.sh outside"]}.items()
    }


@pytest.mark.parametrize("reason", ["python_ast", "line_budget", "syntax_error"])
def test_creating_generator_does_not_launch_a_child(reason):
    source = ('import os\ncmd = "sh outer.sh"\n'
              'generated = (os.system(cmd) for cmd in ["sh inner.sh"])\nos.system(cmd)')
    ir = PythonBackend().parse(source if reason == "python_ast" else _fallback_source(source, reason), [])
    assert [call.path for call in ir.calls] == ["outer.sh"]


@pytest.mark.parametrize("reason", ["python_ast", "line_budget", "syntax_error"])
@pytest.mark.parametrize("form", ["list({body})", "list(({body}))"])
def test_consuming_generator_retains_its_literal_child(reason, form):
    source = 'import os\n' + form.format(body='os.system("sh inner.sh") for item in [1]')
    ir = PythonBackend().parse(source if reason == "python_ast" else _fallback_source(source, reason), [])
    assert [call.path for call in ir.calls] == ["inner.sh"]


def test_incomplete_last_statement_preserves_completed_call():
    source = 'os.system("bash child.sh clean")\nsubprocess.run('
    diagnostics = _assert_fallback(source, "syntax_error", [
        ScriptCall(path="child.sh", args=["clean"], interpreter="bash"),
    ])
    assert diagnostics["child_tokenization_incomplete"] is True


@pytest.mark.parametrize("broken", [
    pytest.param('label = "draft', id="double-quote"),
    pytest.param("label = 'draft", id="single-quote"),
    pytest.param('label = "draft\\\nos.system(\'bash reference.sh\')', id="escaped-newline"),
])
def test_unterminated_short_string_resumes_after_its_last_line(tmp_path, reason, broken):
    (tmp_path / "reference.sh").write_text("echo REFERENCE_DATA\n", encoding="utf-8")
    source = _fallback_source(f"import os\n{broken}\nos.system(\n{_MULTILINE_COMMAND}\n)", reason)
    retained, details = _scan_marked_child(tmp_path, source)
    assert retained == source
    assert details["fallback_reason"] == reason
    assert details["child_tokenization_incomplete"] is True


@pytest.mark.parametrize("text", [
    'text = """draft\nos.system("bash reference.sh")\n',
    'text = f"""{\n\'draft\n}\nos.system("bash reference.sh")\n"""\n',
])
def test_token_error_keeps_multiline_string_data_out_of_the_call_graph(tmp_path, text):
    parent = tmp_path / "parent.py"
    parent.write_text("import os\n" + text, encoding="utf-8")
    (tmp_path / "reference.sh").write_text("echo REFERENCE_DATA\n", encoding="utf-8")
    result = analyze_script_content("bash", "python3 parent.py", cwd=str(tmp_path))
    assert [node.script_path for node in result.nodes] == [str(parent)]


def test_local_parse_budgets_skip_only_the_oversized_candidates(reason):
    def by_length(path, size):
        template = f'subprocess.run(["bash", "{path}", "{{}}"])'
        return template.format("a" * (size - len(template.format(""))))

    def by_depth(path, depth):
        # The call and its list already account for two levels.
        arg = "(" * (depth - 2) + '"ok"' + ")" * (depth - 2)
        return f'subprocess.run(["bash", "{path}", {arg}])'

    sources = [
        by_length("fits.sh", 8192), by_length("too-long.sh", 8193),
        by_depth("fits-depth.sh", 32), by_depth("too-deep.sh", 33),
        'os.system("bash later.sh")',
    ]
    source = _fallback_source("\n".join(sources), reason)
    ir = PythonBackend().parse(source, [])
    assert [child.path for child in ir.calls] == ["fits.sh", "fits-depth.sh", "later.sh"]


def test_string_assignments_reach_child_with_exact_arguments(reason):
    source = (
        'from subprocess import run as launch\n'
        'first = "draft"\n'
        'first = "two words"; second = \'\'\n'
        'launch(["bash", "child.sh", first, second])\n'
        'launch = "replaced"\n'
        'launch(["bash", "hidden.sh"])'
    )
    _assert_fallback(_fallback_source(source, reason), reason, [
        ScriptCall(path="child.sh", args=["two words", ""], interpreter="bash"),
    ])


@pytest.mark.parametrize("assignment, operand, expected", [
    ('mode = "two" " words"', "mode", "two words"),
    ('mode = "draft" + unknown', "mode", None),
    ('mode = "clean"  # note', "mode", "clean"),
    (r'mode = "one\ttwo"', "mode", "one\ttwo"),
    ('ｍode = "normalized"', "mode", "normalized"),  # Python normalizes the fullwidth m.
    ('None = "invalid"', "Ｎｏｎｅ", None),  # Only the fullwidth spelling parses as a name.
])
def test_fallback_binds_only_the_complete_assignment(reason, assignment, operand, expected):
    source = _fallback_source(f'{assignment}\nsubprocess.run(["bash", "child.sh", {operand}])', reason)
    calls = [] if expected is None else [ScriptCall(path="child.sh", args=[expected], interpreter="bash")]
    _assert_fallback(source, reason, calls)


@pytest.mark.parametrize("size", [8192, 8193])
def test_literal_assignment_respects_statement_budget(reason, size):
    value = "a" * (size - len('mode = ""'))
    source = _fallback_source(
        f'mode = "previous"\nmode = "{value}"\nsubprocess.run(["bash", "child.sh", mode])', reason,
    )
    calls = [ScriptCall(path="child.sh", args=[value], interpreter="bash")] if size == 8192 else []
    _assert_fallback(source, reason, calls)


def _scan_marked_child(tmp_path, source):
    parent = tmp_path / "parent.py"
    child = tmp_path / "child.sh"
    parent.write_text(source, encoding="utf-8")
    child.write_text(
        'if [ "${1}:${2}" = "two words:clean" ]; then\n'
        '    echo SELECTED_MARKER\n'
        'else\n'
        '    echo OTHER_MARKER\n'
        'fi\n',
        encoding="utf-8",
    )
    scanner = Mock()
    scanner.scan.return_value = HeuristicResult()
    diagnostics = Mock()
    diagnostics.begin.return_value = {}

    result = analyze_script_content("bash", "python3 parent.py", command_scanner=scanner,
                                    cwd=str(tmp_path), diagnostics=diagnostics)

    assert [node.script_path for node in result.nodes] == [str(parent), str(child)]
    parent_node, child_node = result.nodes
    assert parent_node.child_paths == [str(child)]
    assert child_node.error == ""
    parent_details = diagnostics.begin.return_value["nodes"][0]
    assert parent_details["child_arg_counts"] == [2]
    assert scanner.scan.call_args_list == [call(parent_node.preprocessed_content), call(child_node.preprocessed_content)]
    assert "SELECTED_MARKER" in child_node.preprocessed_content
    assert "OTHER_MARKER" not in child_node.preprocessed_content
    return parent_node.preprocessed_content, parent_details


@pytest.mark.parametrize("invocation", [
    '''os.system("bash child.sh 'two words' clean")''',
    'subprocess.run(["bash", "child.sh", "two words", "clean"])',
])
def test_recursive_scan_preserves_parent_text_and_argument_boundaries(tmp_path, reason, invocation):
    source = _fallback_source("import os, subprocess\n" + invocation, reason)
    retained, parent_details = _scan_marked_child(tmp_path, source)
    assert retained == source
    assert parent_details["parser"] == "python_full"
    assert parent_details["fallback_reason"] == reason
    assert parent_details["line_limit"] == 500
    assert parent_details["physical_lines"] == (501 if reason == "line_budget" else 3)
    assert parent_details["child_extractor"] == "tokenize"
    assert parent_details["child_tokenization_incomplete"] is False


_MULTILINE_COMMAND = '"""\nbash child.sh \'two words\' clean\n"""'


@pytest.mark.parametrize("invocation", [
    pytest.param("if True:\n    pass\n  pass\nos.system({command})", id="after-indentation-error"),
    pytest.param("(os.system)({command})", id="parenthesized-callee"),
    pytest.param("from os import system\nsystem({command})", id="imported-function"),
    pytest.param("os.system(f{command})", id="constant-fstring"),
    pytest.param("cmd = {command}\nos.system(cmd)", id="assigned-string"),
    pytest.param("cmd = f{command}\nos.system(cmd)", id="assigned-constant-fstring"),
    pytest.param('subprocess.run({command}, shell=True, cwd=".")', id="explicit-cwd"),
    pytest.param('subprocess.run({command}, shell=True, executable="/bin/sh")', id="shell-executable"),
    pytest.param('subprocess.run(["bash", "-c", {command}])', id="shell-c"),
    pytest.param("os.system(\n#" + "x" * 8192 + "\n{command})", id="long-comment"),
])
def test_multiline_literal_still_reaches_child_after_python_fallback(tmp_path, invocation):
    source = "import os, subprocess\n" + invocation.format(command=_MULTILINE_COMMAND) + "\nif :"
    retained, details = _scan_marked_child(tmp_path, source)
    assert retained == source
    assert details["fallback_reason"] == "syntax_error"


def test_multiline_text_and_reassigned_names_do_not_create_child_calls(tmp_path):
    data = _MULTILINE_COMMAND.replace("child.sh", "data.sh")
    (tmp_path / "data.sh").write_text("echo REFERENCE_DATA\n", encoding="utf-8")
    source = (
        'import os\nfrom os import system\n'
        f'print({data})\nsystem = print\nsystem({data})\n'
        f'cmd = {data}\ncmd = "echo ready"\nos.system(cmd)\n'
        f'os.system({_MULTILINE_COMMAND})\nif :'
    )
    retained, _ = _scan_marked_child(tmp_path, source)
    assert retained == source


@pytest.mark.parametrize("body", [
    pytest.param(
        'import subprocess\nmode = "draft"\nlabel = f"{(mode := \'clean\')}"\n'
        'subprocess.run(["bash", "child.sh", "two words", mode])', id="argument",
    ),
    pytest.param(
        'import os\ncmd = "bash child.sh other clean"\n'
        'f"""{(cmd := \'\'\'\nbash child.sh \'two words\' clean\n\'\'\')}"""\n'
        'os.system(cmd)', id="command",
    ),
])
def test_literal_assignment_in_fstring_reaches_correct_child_branch(tmp_path, reason, body):
    source = _fallback_source(body, reason)
    retained, _ = _scan_marked_child(tmp_path, source)
    assert retained == source


def test_conditional_fstring_field_does_not_bind_a_definite_command(tmp_path, reason):
    (tmp_path / "reference.sh").write_text("echo REFERENCE_DATA\n", encoding="utf-8")
    source = _fallback_source(
        'import os\ncmd = "echo ready"\nf"{False and (cmd := \'bash reference.sh\')}"\n'
        f'os.system(cmd)\nos.system({_MULTILINE_COMMAND})', reason,
    )
    retained, _ = _scan_marked_child(tmp_path, source)
    assert retained == source


def test_main_guard_keeps_imported_function_until_its_reassignment(tmp_path, reason):
    (tmp_path / "reference.sh").write_text("echo REFERENCE_DATA\n", encoding="utf-8")
    source = _fallback_source(
        'from os import system\nif __name__ == "__main__":\n'
        f'    system({_MULTILINE_COMMAND})\n'
        '    system = print\n    system("bash reference.sh")\n'
        'system("bash reference.sh")', reason,
    )
    retained, _ = _scan_marked_child(tmp_path, source)
    assert retained == source


@pytest.mark.parametrize("body", [
    pytest.param('import os as proc\nproc.system({command})', id="os-module-alias"),
    pytest.param('import subprocess as sp\nsp.run(["bash", "child.sh", "two words", "clean"])', id="subprocess-module-alias"),
    pytest.param(
        'from os import system as launch\ndef helper():\n    launch = print\n'
        '    launch("bash reference.sh")\nlaunch({command})', id="local-shadow",
    ),
    pytest.param(
        'import os as proc\ndef helper(proc):\n    proc.system("bash reference.sh")\n'
        'proc.system({command})', id="parameter-shadow",
    ),
    pytest.param(
        'from os import system as launch\ndef launch(text):\n    pass\n'
        'launch("bash reference.sh")\nimport os\nos.system({command})', id="definition-shadows-function",
    ),
])
def test_import_bindings_respect_function_scope(tmp_path, reason, body):
    (tmp_path / "reference.sh").write_text("echo REFERENCE_DATA\n", encoding="utf-8")
    source = _fallback_source(body.format(command=_MULTILINE_COMMAND), reason)
    retained, _ = _scan_marked_child(tmp_path, source)
    assert retained == source


@pytest.mark.parametrize("parse_mode", ["python_ast", "syntax_error", "line_budget"])
def test_annotated_binding_uses_the_value_and_preserves_it_on_annotation_only(tmp_path, parse_mode):
    source = (
        'from os import system as launch\ncommand = "bash reference.sh"\n'
        f'command: str = {_MULTILINE_COMMAND}\ncommand: str\nlaunch: object\n'
        'if command != "bash reference.sh":\n    launch(command)'
    )
    (tmp_path / "reference.sh").write_text("echo DATA\n", encoding="utf-8")
    _scan_marked_child(tmp_path, source if parse_mode == "python_ast" else _fallback_source(source, parse_mode))


@pytest.mark.parametrize("parse_mode", ["python_ast", "syntax_error", "line_budget"])
@pytest.mark.parametrize("action", [
    'main()',
    'launch = print\nmain()',
    'main = print\nmain()',
    'pass',
])
def test_zero_argument_wrapper_reads_its_global_alias_when_invoked(tmp_path, parse_mode, action):
    source = ('from os import system as launch\ndef main():\n'
              '    """A wrapper mentioning bash reference.sh."""\n'
              f'    launch({_MULTILINE_COMMAND})\n{action}')
    if parse_mode != "python_ast":
        source = _fallback_source(source, parse_mode)
    (tmp_path / "reference.sh").write_text("echo DATA\n", encoding="utf-8")
    if action == "main()":
        _scan_marked_child(tmp_path, source)
    else:
        parent = tmp_path / "parent.py"
        parent.write_text(source, encoding="utf-8")
        (tmp_path / "child.sh").write_text("echo UNINVOKED\n", encoding="utf-8")
        result = analyze_script_content("bash", "python3 parent.py", cwd=str(tmp_path))
        assert [node.script_path for node in result.nodes] == [str(parent)]


@pytest.mark.parametrize("parse_mode", ["python_ast", "syntax_error", "line_budget"])
def test_wrapper_cannot_use_an_outer_alias_shadowed_by_a_function_local(tmp_path, parse_mode):
    source = ('from os import system as launch\n'
              'def main():\n    if False:\n        launch = print\n'
              '    launch("bash reference.sh")\nmain()')
    if parse_mode != "python_ast":
        source = _fallback_source(source, parse_mode)
    parent = tmp_path / "parent.py"
    parent.write_text(source, encoding="utf-8")
    (tmp_path / "reference.sh").write_text("echo UNUSED\n", encoding="utf-8")
    result = analyze_script_content("bash", "python3 parent.py", cwd=str(tmp_path))
    assert [node.script_path for node in result.nodes] == [str(parent)]


@pytest.mark.parametrize("statements", [
    "if True: pass",
    "if choice:\n    label = 'other'",
    "if False:\n    cmd = 'echo unused'",
    "if not False:\n    cmd = {command}\nelse:\n    cmd = 'echo unused'",
    "if choice: cmd = {command}\nelif other: cmd = {command}\nelse: cmd = {command}",
    'if (\n    __name__ == "__main__"\n):\n    pass',
])
def test_if_paths_preserve_agreed_bindings(tmp_path, reason, statements):
    source = _fallback_source(
        'from os import system as launch\ncmd = ' + _MULTILINE_COMMAND + '\n'
        + statements.format(command=_MULTILINE_COMMAND) + '\nlaunch(cmd)', reason,
    )
    retained, _ = _scan_marked_child(tmp_path, source)
    assert retained == source


def test_if_paths_do_not_publish_a_disputed_binding(tmp_path, reason):
    (tmp_path / "reference.sh").write_text("echo REFERENCE_DATA\n", encoding="utf-8")
    source = _fallback_source(
        'import os\ncmd = "bash reference.sh"\nif choice:\n    cmd = "echo ready"\n'
        f'os.system(cmd)\nos.system({_MULTILINE_COMMAND})', reason,
    )
    retained, _ = _scan_marked_child(tmp_path, source)
    assert retained == source


@pytest.mark.parametrize("body", [
    'from os import system as launch\ncmd = {command}\n'
    'if False:\n    launch("bash reference.sh")\nlaunch(cmd)',
    'if False: os.system("bash reference.sh")\nos.system({command})',
    'if False:\n    if True:\n        os.system("bash reference.sh")\n'
    'else:\n    os.system({command})',
    'if False:\n    bash reference.sh\n'
    '    f"{{os.system(\'bash reference.sh\')}}"\nos.system({command})',
    'if os.system({command}): pass\n'
    'if True: pass\nelif os.system("bash reference.sh"): pass',
    'if 1 == "1": os.system("bash reference.sh")\n'
    'if "ready" in [unknown]: os.system({command})',
])
def test_only_potentially_executed_fallback_calls_visit_children(tmp_path, reason, body):
    (tmp_path / "reference.sh").write_text("echo REFERENCE_DATA\n", encoding="utf-8")
    source = _fallback_source(body.format(command=_MULTILINE_COMMAND), reason)
    retained, _ = _scan_marked_child(tmp_path, source)
    assert retained == source


_NESTED_UNREACHABLE = (
    'import os\nif False:\n    if False:\n        os.system("bash inner.sh")\n'
    '    os.system("bash outer.sh")\nos.system("bash top.sh")'
)


@pytest.mark.parametrize("source, reason, incomplete", [
    (_with_lines(_NESTED_UNREACHABLE, 501), "line_budget", False),
    (_NESTED_UNREACHABLE + "\nif :", "syntax_error", False),
    ('import os\nif False:\n    os.system("bash hidden.sh")\n  pass\nos.system("bash top.sh")', "syntax_error", True),
], ids=["nested-line-budget", "nested-syntax-error", "recover-inside-unreachable-suite"])
def test_fallback_reads_top_level_child_after_unreachable_suites(tmp_path, monkeypatch, source, reason, incomplete):
    parent = tmp_path / "parent.py"
    parent.write_text(source, encoding="utf-8")
    for name in ("inner.sh", "outer.sh", "hidden.sh", "top.sh"):
        (tmp_path / name).write_text(f"echo {name}\n", encoding="utf-8")
    read_script = Mock(wraps=tracker._read_script)
    monkeypatch.setattr(tracker, "_read_script", read_script)
    diagnostics = Mock()
    diagnostics.begin.return_value = {}

    result = analyze_script_content("bash", "python3 parent.py", cwd=str(tmp_path), diagnostics=diagnostics)

    assert [entry.args[0] for entry in read_script.call_args_list] == [str(parent), str(tmp_path / "top.sh")]
    assert [node.preprocessed_content for node in result.nodes] == [source, "echo top.sh\n"]
    details = diagnostics.begin.return_value["nodes"][0]
    assert details["fallback_reason"] == reason
    assert details["child_tokenization_incomplete"] is incomplete


def test_agreeing_if_and_else_replace_the_previous_binding(tmp_path, reason):
    source = _fallback_source(
        'import os\ncmd = "echo before"\nif choice:\n    cmd = ' + _MULTILINE_COMMAND
        + '\nelse:\n    cmd = ' + _MULTILINE_COMMAND + '\nos.system(cmd)', reason,
    )
    retained, _ = _scan_marked_child(tmp_path, source)
    assert retained == source


def test_dotted_import_binds_top_level_module_only_without_as(tmp_path, reason):
    (tmp_path / "reference.sh").write_text("echo REFERENCE_DATA\n", encoding="utf-8")
    source = _fallback_source(
        'import os.path as paths\npaths.system("bash reference.sh")\n'
        'import os.path as os\nos.system("bash reference.sh")\n'
        f'import os.path\nos.system({_MULTILINE_COMMAND})', reason,
    )
    retained, _ = _scan_marked_child(tmp_path, source)
    assert retained == source


def test_unrelated_incomplete_assignment_preserves_only_completed_imports(tmp_path):
    (tmp_path / "reference.sh").write_text("echo REFERENCE_DATA\n", encoding="utf-8")
    source = (
        'from os import system as launch, popen as replaced\nreplaced = "broken\n'
        f'launch({_MULTILINE_COMMAND})\nreplaced("bash reference.sh")'
    )
    retained, details = _scan_marked_child(tmp_path, source)
    assert retained == source
    assert details["child_tokenization_incomplete"] is True


@pytest.mark.parametrize("fields", [
    '{(mode := "other")} {1} {(mode := "clean")}',
    '{opaque()} {(mode := "clean")}',
])
def test_multiple_fstring_fields_apply_literal_writes_in_order(tmp_path, reason, fields):
    source = _fallback_source(
        f'import subprocess\nmode = "draft"\nf\'\'\'{fields}\'\'\'\n'
        'subprocess.run(["bash", "child.sh", "two words", mode])', reason,
    )
    retained, _ = _scan_marked_child(tmp_path, source)
    assert retained == source


def test_later_fstring_call_invalidates_an_earlier_field(tmp_path, reason):
    (tmp_path / "reference.sh").write_text("echo REFERENCE_DATA\n", encoding="utf-8")
    source = _fallback_source(
        'import os\ncmd = "echo ready"\nf\'\'\'{(cmd := "bash reference.sh")} {opaque()}\'\'\'\n'
        f'os.system(cmd)\nos.system({_MULTILINE_COMMAND})', reason,
    )
    retained, _ = _scan_marked_child(tmp_path, source)
    assert retained == source


@pytest.mark.parametrize("body", [
    'from os import system as launch\nprint("ready")\nlaunch({command})',
    'from os import system as launch\n' + '''f"""{{print("ready")}}"""''' + '\nlaunch({command})',
    'def update(value):\n    global launch\n    launch = str\n'
    'print = update\nfrom os import system as launch\nprint("ready")\n'
    'launch("bash reference.sh")\nimport os\nos.system({command})',
])
def test_constant_print_preserves_bindings_only_for_the_builtin(tmp_path, reason, body):
    (tmp_path / "reference.sh").write_text("echo REFERENCE_DATA\n", encoding="utf-8")
    source = _fallback_source(body.format(command=_MULTILINE_COMMAND), reason)
    retained, _ = _scan_marked_child(tmp_path, source)
    assert retained == source


def test_later_fstring_field_uses_earlier_literal_assignment(tmp_path, reason):
    source = _fallback_source(
        'import subprocess\nmode = "draft"\nf\'\'\'{(mode := "clean")} '
        '{subprocess.run(["bash", "child.sh", "two words", mode])}\'\'\'', reason,
    )
    retained, _ = _scan_marked_child(tmp_path, source)
    assert retained == source


@pytest.mark.parametrize("body", [
    pytest.param(
        'def update(result):\n    global cmd\n    cmd = "echo updated"\n'
        'cmd = "bash reference.sh"\n'
        'result = update(os.system({command}))\nos.system(cmd)',
        id="string",
    ),
    pytest.param(
        'def update(result):\n    global launch\n    launch = str\n'
        'from os import system as launch\n'
        'update(launch({command}))\nlaunch("bash reference.sh")',
        id="imported-function",
    ),
    pytest.param(
        'def update():\n    global cmd\n    cmd = "echo updated"\n'
        'cmd = "bash reference.sh"\nmessage = f"{{update()}}"\n'
        'os.system(cmd)\nos.system({command})',
        id="opaque-fstring-field",
    ),
])
def test_unknown_call_keeps_inner_child_and_invalidates_earlier_bindings(tmp_path, reason, body):
    (tmp_path / "reference.sh").write_text("echo REFERENCE_DATA\n", encoding="utf-8")
    source = _fallback_source("import os\n" + body.format(command=_MULTILINE_COMMAND), reason)
    retained, _ = _scan_marked_child(tmp_path, source)
    assert retained == source


@pytest.mark.parametrize("lines", [500, 501])
@pytest.mark.parametrize("final_newline", [False, True], ids=["unterminated", "terminated"])
def test_line_budget_counts_physical_lines(tmp_path, lines, final_newline):
    statements = 'if False:\n    print("UNREACHED_PARENT_DATA")\nos.system("bash child.sh \'two words\' clean")'
    source = _with_lines(statements, lines) + ("\n" if final_newline else "")
    retained, details = _scan_marked_child(tmp_path, source)
    assert details["physical_lines"] == lines
    assert details["reachable_content"] == retained
    assert details["reachable_content_matches_source"] is (lines == 501)
    if lines == 500:
        assert details["parser"] == "python_ast"
        assert "UNREACHED_PARENT_DATA" not in retained
    else:
        assert details["fallback_reason"] == "line_budget"
        assert retained == source


@pytest.mark.parametrize("invocation", [
    '''os.system("bash +x child.sh 'two words' clean")''',
    'subprocess.run(["bash", "+x", "child.sh", "two words", "clean"])',
])
def test_bash_plus_option_is_not_the_script_operand(tmp_path, reason, invocation):
    (tmp_path / "+x").write_text("echo REFERENCE_DATA\n", encoding="utf-8")
    source = _fallback_source("import os, subprocess\n" + invocation, reason)
    retained, details = _scan_marked_child(tmp_path, source)
    assert retained == source
    assert details["fallback_reason"] == reason


def test_500_terminated_lines_do_not_visit_the_only_unreachable_child(tmp_path):
    source = ("pass\n" * 497 + "import subprocess\nif False:\n"
              '    subprocess.run(["bash", "child.sh", "two words", "clean"])\n')
    parent = tmp_path / "parent.py"
    parent.write_text(source, encoding="utf-8")
    (tmp_path / "child.sh").write_text("echo UNREACHABLE_CHILD\n", encoding="utf-8")
    diagnostics = Mock()
    diagnostics.begin.return_value = {}
    result = analyze_script_content("bash", "python3 parent.py", cwd=str(tmp_path), diagnostics=diagnostics)
    assert [node.script_path for node in result.nodes] == [str(parent)]
    assert diagnostics.begin.return_value["nodes"][0]["parser"] == "python_ast"


def test_recursive_scan_reads_only_scripts_invoked_as_code(tmp_path, monkeypatch, reason):
    parent = tmp_path / "parent.py"
    child = tmp_path / "child.sh"
    data = tmp_path / "reference notes.sh"
    source = 'subprocess.run(["cat", "reference notes.sh"])\nsubprocess.run(["bash", "child.sh"])'
    parent.write_text(_fallback_source(source, reason), encoding="utf-8")
    data.write_text("echo REFERENCE_DATA\n", encoding="utf-8")
    child.write_text("echo CHILD_MARKER\n", encoding="utf-8")
    read_script = Mock(wraps=tracker._read_script)
    monkeypatch.setattr(tracker, "_read_script", read_script)

    result = analyze_script_content("bash", "python3 parent.py", cwd=str(tmp_path))

    assert [read.args[0] for read in read_script.call_args_list] == [str(parent), str(child)]
    assert [node.script_path for node in result.nodes] == [str(parent), str(child)]
