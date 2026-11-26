"""Check the child files, argv and scanned branches on both sides of the Python line budget."""

from pathlib import Path
from unittest.mock import Mock

import pytest

from agent_moss.engine.script_content_analyzer import analyze_script_content
from agent_moss.engine.script_engine import tracker
from agent_moss.engine.types import HeuristicResult


COMMAND = '''"""
bash child.sh 'two words' clean
"""'''
DIRECT = f"os.system({COMMAND})"
FSTRING_COMMAND = COMMAND.replace('"""', "'''")
IMPORT = "from os import system as launch"
MAIN = 'if __name__ == "__main__":\n    '
FIRST = 'os.system("""\nbash first.sh\n""")'
ARGS = ["two words", "clean"]
CHILD = ("child.sh", ARGS, "CHILD_SELECTED")
SIBLING = ("scripts/child.sh", ARGS, "SIBLING_SELECTED")
FIRST_CHILD = ("first.sh", [], "FIRST")


# Each case supplies the entry path, the Python source and the child scans in order.
CASES = {
    "unclosed-quote": ("parent.py", f'import os\nlabel = "draft\n{DIRECT}', [CHILD]),
    "cat": ("parent.py", 'import subprocess\nsubprocess.run(["cat", "notes.sh"])', []),
    "two-commands": ("parent.py", 'import os\nos.system("""\nbash first.sh\n'
                     'bash child.sh \'two words\' clean\n""")', [FIRST_CHILD, CHILD]),
    "fstring": ("parent.py", 'import subprocess\nmode = "draft"\nlabel = f"{(mode := \'clean\')}"\n'
                'subprocess.run(["bash", "child.sh", "two words", mode])', [CHILD]),
    "chdir": ("scripts/parent.py", f'import os\nos.chdir("scripts")\n{DIRECT}', [SIBLING]),
    "main-alias": ("parent.py", f"{IMPORT}\n{MAIN}launch({COMMAND})", [CHILD]),
    "module-alias": ("parent.py", f"import os as proc\n{MAIN}proc.system({COMMAND})", [CHILD]),
    "mixed-calls": ("parent.py", f"import os\n{IMPORT}\n{FIRST}\n{MAIN}launch({COMMAND})", [FIRST_CHILD, CHILD]),
    "chdir-in-main": ("scripts/parent.py", f'import os\n{MAIN}os.chdir("scripts")\n    {DIRECT}', [SIBLING]),
    "alias-after-error": ("parent.py", f'{IMPORT}\nlabel = "draft\nlaunch({COMMAND})', [CHILD]),
    "two-fstring-fields": ("parent.py", 'import os\ncmd = "bash child.sh other clean"\n'
                           f'f"""{{(cmd := {FSTRING_COMMAND})}} {{1}}"""\nos.system(cmd)', [CHILD]),
    "unrelated-function": ("parent.py", f"{IMPORT}\ndef hello():\n    pass\n{MAIN}launch({COMMAND})", [CHILD]),
    "call-before-chdir": ("parent.py", f'import os\n{MAIN}os.system("bash child.sh \'two words\' clean")\n'
                          '    os.chdir("scripts")', [CHILD]),
    "redirected-echo": ("parent.py", 'import os\nos.system("""\nbash child.sh \'two words\' clean\n'
                        'echo bash notes.sh weekly > output.txt\n""")', [CHILD]),
    "shell-exec": ("parent.py", 'import os\nos.system("""\necho ready\nexec bash child.sh \'two words\' clean\n""")',
                   [CHILD]),
    "static-kwargs": ("parent.py", 'import subprocess\nsubprocess.run(["bash", "child.sh", "two words", "clean"], '
                      '**{"check": True})', [CHILD]),
    "multiline-main-guard": ("parent.py", f'import os\nif (\n    __name__ == "__main__"\n):\n    {DIRECT}', [CHILD]),
    "import-submodule": ("parent.py", f"import os.path\n{DIRECT}", [CHILD]),
    "unchanged-command": ("parent.py", f"import os\ncmd = {COMMAND}\nif True:\n    pass\nos.system(cmd)", [CHILD]),
    "shell-environment-prefix": ("parent.py", 'import os\nos.system("""\nLC_ALL=C bash child.sh \'two words\' clean\n""")',
                                [CHILD]),
    "shell-exit": ("parent.py", 'import os\nos.system("""\nbash child.sh \'two words\' clean\nexit\n'
                   'bash notes.sh \'two words\' clean\n""")', [CHILD]),
    "subsequent-argument": ("parent.py", f"import subprocess\ncmd = {COMMAND}\n"
                            'subprocess.run(cmd, shell=True, text=True, input=(cmd := "bash child.sh \'two words\' draft"))',
                            [CHILD]),
    "comprehension-target": ("parent.py", 'import os\ncmd = "bash child.sh other clean"\n'
                             f'[os.system(cmd) for cmd in [{COMMAND}]]', [CHILD]),
    "annotated-command": ("parent.py", f"import os\ncommand: str = {COMMAND}\nos.system(command)", [CHILD]),
    "global-launch": ("parent.py", f"{IMPORT}\ndef main():\n    launch({COMMAND})\nmain()", [CHILD]),
    "env-runner": ("parent.py", 'import os\nos.system("""\nenv bash child.sh \'two words\' clean\n""")', [CHILD]),
    "finally-cwd": ("scripts/parent.py", f'import os\ntry:\n    pass\nfinally:\n    os.chdir("scripts")\n{DIRECT}',
                    [SIBLING]),
}


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("line_count", [None, 499, 500, 501], ids=["short", "499", "500", "501"])
@pytest.mark.parametrize("ending", ["", "\n"], ids=["no-final-lf", "final-lf"])
def test_python_child_scans(tmp_path, monkeypatch, case, line_count, ending):
    entry, body, expected = CASES[case]
    padding = line_count - len(body.splitlines()) if line_count is not None else 0
    parent = "pass\n" * padding + body + ending
    (tmp_path / "scripts").mkdir()
    (tmp_path / entry).write_text(parent, encoding="utf-8")
    (tmp_path / "first.sh").write_text("echo FIRST\n", encoding="utf-8")
    (tmp_path / "notes.sh").write_text("echo DATA_ONLY\n", encoding="utf-8")
    for path, _, marker in (CHILD, SIBLING):
        (tmp_path / path).write_text(
            f'if [ "${{1}}:${{2}}" = "two words:clean" ]; then\n echo {marker}\nelse\n echo OTHER\nfi\n',
            encoding="utf-8",
        )

    read = Mock(wraps=tracker._read_script)
    parse = Mock(wraps=tracker._DEFAULT_BACKEND.parse)
    monkeypatch.setattr(tracker, "_read_script", read)
    monkeypatch.setattr(tracker._DEFAULT_BACKEND, "parse", parse)
    scanner = Mock()
    scanner.scan.return_value = HeuristicResult()
    result = analyze_script_content("bash", f"python3 {entry}", command_scanner=scanner, cwd=str(tmp_path))

    paths = [str(Path(call.args[0]).relative_to(tmp_path)) for call in read.call_args_list]
    assert paths == [entry, *(path for path, _, _ in expected)]
    assert all(not node.error for node in result.nodes)
    assert [call.args[1] for call in parse.call_args_list] == [args for _, args, _ in expected]
    scanned = [call.args[0] for call in scanner.scan.call_args_list]
    assert len(scanned) == len(paths)
    if line_count == 501 or case in ("alias-after-error", "unclosed-quote"):
        assert scanned[0] == parent
    for text, (_, _, marker) in zip(scanned[1:], expected):
        assert [line.strip() for line in text.splitlines() if line.strip().startswith("echo ")] == [f"echo {marker}"]
