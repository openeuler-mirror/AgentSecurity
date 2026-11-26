"""Verify which files the recursive tracker reads for Python fallback calls."""

import pytest

from agent_moss.engine.script_content_analyzer import analyze_script_content


def _write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


@pytest.mark.parametrize("reason", ["line_budget", "syntax_error"])
@pytest.mark.parametrize("invocation", [
    'os.system("sh child.sh")',
    'subprocess.run(["sh", "child.sh"])',
    'subprocess.run(["sh", "child.sh"], cwd=".")',
])
def test_python_fallback_child_uses_launch_directory(tmp_path, reason, invocation):
    source = 'import os, subprocess\n' + invocation
    source = "# padding\n" * 500 + source if reason == "line_budget" else source + "\nif broken"
    parent = _write(tmp_path / "scripts/parent.py", source)
    child = _write(tmp_path / "child.sh", "echo CWD_MARKER\n")
    _write(parent.parent / "child.sh", "echo SIBLING_MARKER\n")

    result = analyze_script_content("bash", "python3 scripts/parent.py", cwd=str(tmp_path))

    assert [node.script_path for node in result.nodes] == [str(parent), str(child)]
    assert result.nodes[0].child_paths == [str(child)]
    assert result.nodes[1].preprocessed_content == "echo CWD_MARKER\n"


def test_nested_python_fallback_calls_inherit_the_entry_workdir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    parent = _write(tmp_path / "scripts/parent.py", 'os.system("python3 jobs/relay.py")\nif broken')
    relay = _write(tmp_path / "jobs/relay.py", 'subprocess.run(["sh", "leaf.sh"], cwd=".")\nif broken')
    leaf = _write(tmp_path / "leaf.sh", "echo LEAF_MARKER\n")
    _write(relay.parent / "leaf.sh", "echo SIBLING_MARKER\n")

    result = analyze_script_content("bash", "python3 scripts/parent.py")

    assert [node.script_path for node in result.nodes] == [str(parent), str(relay), str(leaf)]
    assert result.nodes[1].child_paths == [str(leaf)]


def test_python_chdir_changes_only_subsequent_launches(tmp_path):
    source = ('import os\nos.system("sh child.sh before")\nos.chdir("scripts")\n'
              'os.system("""\nbash child.sh \'two words\' clean\n""")')
    parent = _write(tmp_path / "scripts/parent.py", "pass\n" * (501 - len(source.splitlines())) + source)
    before = _write(tmp_path / "child.sh", "echo BEFORE_MARKER\n")
    after = _write(parent.parent / "child.sh",
                   'if [ "${1}:${2}" = "two words:clean" ]; then\n echo AFTER_MARKER\nelse\n echo WRONG_ARGS\nfi\n')

    result = analyze_script_content("bash", "python3 scripts/parent.py", cwd=str(tmp_path))

    assert [node.script_path for node in result.nodes] == [str(parent), str(before), str(after)]
    assert "AFTER_MARKER" in result.nodes[2].preprocessed_content
    assert "WRONG_ARGS" not in result.nodes[2].preprocessed_content


@pytest.mark.parametrize("over_budget", [False, True], ids=["ast", "fallback"])
@pytest.mark.parametrize("final_clause", [
    'finally:\n    os.chdir("jobs")',
    'finally: os.chdir("jobs")',
])
def test_finally_changes_cwd_before_the_following_call(tmp_path, over_budget, final_clause):
    source = (f'import os, subprocess\ntry:\n    subprocess.run(["sh", "child.sh", "before"], cwd=".")\n{final_clause}\n'
              'os.system("sh child.sh after")')
    if over_budget:
        source = "pass\n" * (501 - len(source.splitlines())) + source
    parent = _write(tmp_path / "scripts/parent.py", source)
    before = _write(tmp_path / "child.sh", 'if [ "$1" = "before" ]; then\n echo BEFORE\nelse\n echo WRONG\nfi\n')
    after = _write(tmp_path / "jobs/child.sh", 'if [ "$1" = "after" ]; then\n echo AFTER\nelse\n echo WRONG\nfi\n')
    _write(parent.parent / "child.sh", "echo SOURCE_DIRECTORY\n")

    result = analyze_script_content("bash", "python3 scripts/parent.py", cwd=str(tmp_path))

    scanned = {node.script_path: node.preprocessed_content for node in result.nodes}
    assert set(scanned) == {str(parent), str(before), str(after)}
    assert "echo BEFORE" in scanned[str(before)] and "echo WRONG" not in scanned[str(before)]
    assert "echo AFTER" in scanned[str(after)] and "echo WRONG" not in scanned[str(after)]


@pytest.mark.parametrize("over_budget", [False, True], ids=["ast", "fallback"])
@pytest.mark.parametrize("body", [
    'try:\n    pass\nfinally:\n    if flag:\n        os.chdir("scripts")',
    'try:\n    pass\nfinally:\n    os.chdir(directory)',
    'try:\n    try:\n        pass\n    finally:\n        os.chdir("scripts")\nexcept OSError:\n    pass',
])
def test_uncertain_finally_directory_does_not_select_either_copy(tmp_path, over_budget, body):
    source = f'import os\n{body}\nos.system("sh child.sh")'
    if over_budget:
        source = "pass\n" * (501 - len(source.splitlines())) + source
    parent = _write(tmp_path / "scripts/parent.py", source)
    for directory in (tmp_path, parent.parent):
        _write(directory / "child.sh", "echo AMBIGUOUS\n")

    result = analyze_script_content("bash", "python3 scripts/parent.py", cwd=str(tmp_path))

    assert [node.script_path for node in result.nodes] == [str(parent)]


@pytest.mark.parametrize("lines", [499, 500, 501])
@pytest.mark.parametrize("option", ['', ', cwd="."'])
def test_sequential_chdir_selects_the_same_files_across_the_ast_budget(tmp_path, lines, option):
    source = ('import os, subprocess\n'
              'os.chdir("scripts")\n'
              f'subprocess.run(["sh", "child.sh"]{option})\n'
              'os.chdir("jobs")\n'
              f'subprocess.run(["sh", "child.sh"]{option})\n')
    parent = _write(tmp_path / "scripts/parent.py", "pass\n" * (lines - len(source.splitlines())) + source)
    _write(tmp_path / "child.sh", "echo WRONG_MARKER\n")
    first = _write(parent.parent / "child.sh", "echo FIRST_MARKER\n")
    second = _write(parent.parent / "jobs/child.sh", "echo SECOND_MARKER\n")

    result = analyze_script_content("bash", "python3 scripts/parent.py", cwd=str(tmp_path))

    assert [node.script_path for node in result.nodes] == [str(parent), str(first), str(second)]
    assert [node.preprocessed_content for node in result.nodes[1:]] == ["echo FIRST_MARKER\n", "echo SECOND_MARKER\n"]


def test_ast_chdir_ignores_pruned_changes_and_keeps_relative_imports(tmp_path):
    source = ('from . import sibling\nimport os, subprocess\nos.chdir("jobs")\n'
              'if False:\n    os.chdir("ignored")\n'
              'subprocess.run(["sh", "child.sh"], cwd=".")')
    parent = _write(tmp_path / "scripts/parent.py", source)
    child = _write(tmp_path / "jobs/child.sh", "echo JOB_MARKER\n")
    imported = _write(parent.parent / "sibling.py", 'print("IMPORT_MARKER")\n')
    _write(tmp_path / "jobs/ignored/child.sh", "echo WRONG_MARKER\n")

    result = analyze_script_content("bash", "python3 scripts/parent.py", cwd=str(tmp_path))

    assert [node.script_path for node in result.nodes] == [str(parent), str(child), str(imported)]
    assert "ignored" not in result.nodes[0].preprocessed_content


@pytest.mark.parametrize("lines", [499, 500, 501])
def test_entry_guard_observes_launches_on_both_sides_of_chdir(tmp_path, lines):
    source = ('import os, subprocess\nfrom os import system as launch\n'
              'if __name__ == "__main__":\n'
              '    launch("sh child.sh")\n'
              '    os.chdir("jobs")\n'
              '    subprocess.run(["sh", "child.sh"], cwd=".")\n'
              '    cmd = "sh last.sh"\n'
              '    launch(cmd)\n')
    parent = _write(tmp_path / "scripts/parent.py", "pass\n" * (lines - len(source.splitlines())) + source)
    first = _write(tmp_path / "child.sh", "echo BEFORE\n")
    second = _write(tmp_path / "jobs/child.sh", "echo AFTER\n")
    last = _write(tmp_path / "jobs/last.sh", "echo ALIAS\n")
    _write(parent.parent / "child.sh", "echo DECOY\n")

    result = analyze_script_content("bash", "python3 scripts/parent.py", cwd=str(tmp_path))

    assert [node.script_path for node in result.nodes] == [str(p) for p in (parent, first, second, last)]


def test_ast_mixes_legacy_direct_and_bound_calls_with_their_original_path_bases(tmp_path):
    source = ('import os\nfrom os import system as launch\n'
              'os.system("sh direct.sh")\n'
              'cmd = "sh ignored.sh"\nprint("ready")\n'
              """f"{(cmd := 'sh bound.sh')}"\n"""
              'launch(cmd)\n')
    parent = _write(tmp_path / "scripts/parent.py", source)
    direct = _write(parent.parent / "direct.sh", "echo DIRECT\n")
    bound = _write(tmp_path / "bound.sh", "echo BOUND\n")
    _write(tmp_path / "direct.sh", "echo WRONG\n")
    _write(parent.parent / "bound.sh", "echo WRONG\n")
    _write(tmp_path / "ignored.sh", "echo WRONG\n")

    result = analyze_script_content("bash", "python3 scripts/parent.py", cwd=str(tmp_path))

    assert [node.script_path for node in result.nodes] == [str(p) for p in (parent, direct, bound)]


@pytest.mark.parametrize("block", [
    'launch, other = print, None\nlaunch("sh ignored.sh")',
    'first = cmd = value\nos.system(cmd)',
    'for launch in functions:\n    launch("sh ignored.sh")',
    'with context as launch:\n    launch("sh ignored.sh")',
])
def test_ast_writes_clear_previous_callee_or_command_bindings(tmp_path, block):
    source = ('import os\nfrom os import system as launch\ncmd = "sh ignored.sh"\n' + block
              + '\nos.system("sh child.sh")')
    parent = _write(tmp_path / "parent.py", source)
    child = _write(tmp_path / "child.sh", "echo CHILD\n")
    _write(tmp_path / "ignored.sh", "echo DATA\n")

    result = analyze_script_content("bash", "python3 parent.py", cwd=str(tmp_path))

    assert [node.script_path for node in result.nodes] == [str(parent), str(child)]


def test_ast_chdir_inside_uncalled_function_does_not_change_module_cwd(tmp_path):
    source = ('import os, subprocess\nos.chdir("jobs")\n'
              'def prepare():\n    os.chdir("ignored")\n'
              'subprocess.run(["sh", "child.sh"], cwd=".")')
    parent = _write(tmp_path / "scripts/parent.py", source)
    child = _write(tmp_path / "jobs/child.sh", "echo JOB_MARKER\n")
    _write(tmp_path / "jobs/ignored/child.sh", "echo WRONG_MARKER\n")

    result = analyze_script_content("bash", "python3 scripts/parent.py", cwd=str(tmp_path))

    assert [node.script_path for node in result.nodes] == [str(parent), str(child)]


@pytest.mark.parametrize("change", [
    "os.chdir(where)",
    'if flag:\n    os.chdir("scripts")',
    'os.chdir("scripts") if flag else None',
])
def test_ambiguous_chdir_does_not_guess_a_directory(tmp_path, change):
    source = (f'import os\n{change}\nos.system("sh child.sh")\n'
              f'os.chdir({str(tmp_path / "scripts")!r})\nos.system("sh final.sh")\nif broken')
    parent = _write(tmp_path / "scripts/parent.py", source)
    _write(tmp_path / "child.sh", "echo ENTRY_MARKER\n")
    _write(parent.parent / "child.sh", "echo SIBLING_MARKER\n")
    final = _write(parent.parent / "final.sh", "echo FINAL_MARKER\n")

    result = analyze_script_content("bash", "python3 scripts/parent.py", cwd=str(tmp_path))

    assert [node.script_path for node in result.nodes] == [str(parent), str(final)]


def test_absolute_child_inherits_unknown_workdir(tmp_path):
    leaf = _write(tmp_path / "leaf.sh", "echo ABSOLUTE_MARKER\n")
    relay = _write(tmp_path / "scripts/relay.py",
                   f'os.system("sh relative.sh")\nsubprocess.run(["sh", {str(leaf)!r}])\nif broken')
    parent = _write(tmp_path / "parent.py",
                    f'os.chdir(where)\nsubprocess.run(["python3", {str(relay)!r}])\nif broken')
    _write(tmp_path / "relative.sh", "echo ENTRY_MARKER\n")
    _write(relay.parent / "relative.sh", "echo SIBLING_MARKER\n")

    result = analyze_script_content("bash", "python3 parent.py", cwd=str(tmp_path))

    assert [node.script_path for node in result.nodes] == [str(parent), str(relay), str(leaf)]


@pytest.mark.parametrize("fallback", [False, True])
def test_subprocess_uses_its_explicit_workdir_for_relative_and_absolute_children(tmp_path, fallback):
    absolute = _write(tmp_path / "programs/relay.py", 'os.system("sh leaf.sh")\nif broken')
    leaf = _write(tmp_path / "jobs/a/leaf.sh", "echo LEAF\n")
    first = _write(tmp_path / "jobs/a/child.sh", "echo FIRST\n")
    second = _write(tmp_path / "jobs/b/child.sh", "echo SECOND\n")
    source = (f'subprocess.run(["python3", {str(absolute)!r}], cwd="jobs/a")\n'
              'subprocess.run(["sh", "child.sh"], cwd="jobs/a")\n'
              'subprocess.Popen(["sh", "child.sh"], -1, None, None, None, None, None, True, False, "jobs/b")')
    parent = _write(tmp_path / "scripts/parent.py", source + ("\nif broken" if fallback else ""))
    _write(parent.parent / "child.sh", "echo SIBLING\n")
    _write(tmp_path / "child.sh", "echo LAUNCH_DIRECTORY\n")

    result = analyze_script_content("bash", "python3 scripts/parent.py", cwd=str(tmp_path))

    assert [node.script_path for node in result.nodes] == [str(p) for p in (parent, absolute, leaf, first, second)]


def test_subprocess_relative_cwd_follows_prior_chdir_without_changing_the_parent(tmp_path):
    source = ('import os, subprocess\nos.chdir("scripts")\n'
              'subprocess.run(["sh", "child.sh"], cwd="jobs")\nos.system("sh child.sh")\nif broken')
    parent = _write(tmp_path / "scripts/parent.py", source)
    job = _write(tmp_path / "scripts/jobs/child.sh", "echo JOB\n")
    sibling = _write(parent.parent / "child.sh", "echo PARENT\n")

    result = analyze_script_content("bash", "python3 scripts/parent.py", cwd=str(tmp_path))

    assert [node.script_path for node in result.nodes] == [str(parent), str(job), str(sibling)]


@pytest.mark.parametrize(("entry", "command", "source", "child_name"), [
    ("wrapper.sh", "sh", "sh sibling.sh", "sibling.sh"),
    ("module.py", "python3", "from . import sibling", "sibling.py"),
])
def test_shell_calls_and_python_imports_keep_their_source_directory(tmp_path, entry, command, source, child_name):
    parent = _write(tmp_path / "package" / entry, source)
    child = _write(parent.parent / child_name, "# SIBLING_MARKER\n")
    _write(tmp_path / child_name, "# CWD_MARKER\n")

    result = analyze_script_content("bash", f"{command} package/{entry}", cwd=str(tmp_path))

    assert [node.script_path for node in result.nodes] == [str(parent), str(child)]
    assert result.nodes[0].child_paths == [str(child)]
