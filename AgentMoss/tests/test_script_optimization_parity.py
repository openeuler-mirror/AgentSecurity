"""Preserve exact output while reducing traversal and segmentation work."""
import ast
import itertools
import random
from dataclasses import asdict

import pytest
from agent_moss.engine import heuristic
from agent_moss.engine.script_engine.backends import python_backend as backend
from _script_optimization_reference import legacy_split, legacy_mark, legacy_mark_tree


@pytest.mark.parametrize('text,expected', [
    ('', []), (';', ['', ';']), ('a;;', ['a', ';', '', ';']),
    ('a&&&b|||c', ['a', '&&', '&b', '||', '|c']),
    ('echo "a;b";x', ['echo "a;b"', ';', 'x']),
    ('a;"open;\nx', ['a', ';', '"open;\nx']),
    ('a\\;b', ['a\\', ';', 'b']),
    ('"a\\";b', ['"a\\"', ';', 'b']),
    ('中文\x00;\ud800\n', ['中文\x00', ';', '\ud800', '\n']),
])
def test_split_exact_output(text, expected):
    assert heuristic._split_command_segments(text) == expected


def test_split_exhaustive_and_seeded_strings():
    alphabet = "a'\";&|\n\\"
    for size in range(6):
        for chars in itertools.product(alphabet, repeat=size):
            text = ''.join(chars)
            assert heuristic._split_command_segments(text) == legacy_split(text), repr(text)
    rng = random.Random(20261109)
    alphabet += '中\x00\ud800\r\t'
    for _ in range(3000):
        text = ''.join(rng.choices(alphabet, k=rng.randrange(512)))
        assert heuristic._split_command_segments(text) == legacy_split(text), repr(text)


SOURCES = [
    '@first\n# gap\n\n@second(\n    "arg",\n)\n\nasync def f(x: int = 1):\n    return x\n',
    '@outer\nclass A(Base):\n    @inner(\n        1,\n    )\n    def f(self):\n        if False:\n            os.system("bash hidden.sh")\n        return 1\n',
    'def f():\n    """multi\n    line"""\n    @deco\n    async def nested():\n        return 2\n    return nested\n',
    'if flag:\n    @yes\n    def f():\n        return 1\nelse:\n    @no\n    class X:\n        pass\n',
    '@(lambda x: x)\ndef f(): return "中文"\n',
    'for x in range(2):\n    @deco\n    def f():\n        pass\n',
    '# no definition\nx = 2\nif x == 2:\n    os.system("bash child.sh")\n',
    'def invalid(:\n',
]


@pytest.mark.parametrize('source', SOURCES)
def test_complete_ir_matches_legacy_line_marking(source, monkeypatch):
    actual = asdict(backend.PythonBackend().parse(source, ['clean']))
    monkeypatch.setattr(backend, '_mark_node_lines', legacy_mark)
    monkeypatch.setattr(backend, '_mark_def_tree', legacy_mark_tree)
    expected = asdict(backend.PythonBackend().parse(source, ['clean']))
    assert actual == expected


def test_decorator_gaps_are_not_added():
    source = '@first\n# gap\n\n@second(\n    1,\n)\n\ndef f():\n    return 1\n'
    result = backend.PythonBackend().parse(source, [])
    assert result.reachable_content == '@first\n@second(\n    1,\n)\ndef f():\n    return 1'


@pytest.mark.parametrize('start,end', [(None,None),(0,2),(-4,8),(2,None),(4,1),(9,20)])
def test_line_marking_clamps_to_source(start, end):
    node = ast.Constant(value=1)
    if start is not None:
        node.lineno = start
    if end is not None:
        node.end_lineno = end
    actual, expected = {2}, {2}
    backend._mark_node_lines(node, actual, ['a','b','c'])
    legacy_mark(node, expected, ['a','b','c'])
    assert actual == expected


@pytest.mark.parametrize('reachable,expected', [
    (None, [('shared.py', (), 'python3'), ('last.sh', (), 'bash'), ('extra.py', (), 'python3'), ('name.py', (), 'python3')]),
    ({4}, [('last.sh', (), 'bash'), ('shared.py', (), 'python3'), ('extra.py', (), 'python3'), ('name.py', (), 'python3')]),
])
def test_calls_precede_imports_and_keep_deduplication(reachable, expected):
    source = 'from . import shared\nsubprocess.run(["python3", "shared.py"])\nfrom .extra import name\nos.system("bash last.sh")\n'
    calls = backend._extract_calls_ast(ast.parse(source), source, reachable)
    assert [(call.path, tuple(call.args), call.interpreter) for call in calls] == expected


CALL_FORMS = [
    'subprocess.run(["python3", "shared.py", "{mode}", "two words"])',
    'subprocess.run("python3 shared.py {mode} \'two words\'", shell=True)',
    'os.system("python3 shared.py {mode} \'two words\'")',
]


@pytest.mark.parametrize('call_form', CALL_FORMS)
@pytest.mark.parametrize('reachable', [None, {2, 4, 5}])
def test_call_arguments_order_and_deduplication(call_form, reachable):
    source = '\n'.join([
        'from . import shared',
        call_form.format(mode='backup'),
        call_form.format(mode='clean'),
        call_form.format(mode='backup'),  # Exact duplicate must disappear.
        'subprocess.run(["bash", "shared.py", "backup", "two words"])',
        'from . import shared',
    ])
    calls = backend._extract_calls_ast(ast.parse(source), source, reachable)
    expected = [('shared.py', ('backup', 'two words'), 'python3')]
    if reachable is None:
        expected.append(('shared.py', ('clean', 'two words'), 'python3'))
    expected.extend([
        ('shared.py', ('backup', 'two words'), 'bash'),
        ('shared.py', (), 'python3'),
    ])
    assert [(call.path, tuple(call.args), call.interpreter) for call in calls] == expected


def test_nested_calls_keep_breadth_first_order_before_imports():
    source = '''from . import root

def task():
    from .nested import helper
    subprocess.run(["python3", "second.py", "clean"])

subprocess.run(["python3", "first.py", "backup"])
'''
    calls = backend._extract_calls_ast(ast.parse(source), source)
    assert [(call.path, tuple(call.args), call.interpreter) for call in calls] == [
        ('first.py', ('backup',), 'python3'),
        ('second.py', ('clean',), 'python3'),
        ('root.py', (), 'python3'),
        ('nested.py', (), 'python3'),
        ('helper.py', (), 'python3'),
    ]


@pytest.mark.parametrize('call_form', CALL_FORMS)
@pytest.mark.parametrize('mode,dangerous', [('backup', False), ('clean', True)])
def test_python_parent_passes_arguments_before_relative_import(tmp_path, call_form, mode, dangerous):
    from agent_moss.engine.script_engine.tracker import RecursiveTracker
    from agent_moss.profiles.linux import LinuxProfile

    # Import comes first in source, but explicit calls must be analyzed first:
    # the tracker visits each path only once, so an empty argument list would
    # select the safe default branch and hide the clean invocation.
    parent = tmp_path / 'parent.py'
    parent.write_text('from . import shared\nimport subprocess, os\n' + call_form.format(mode=mode))
    child = tmp_path / 'shared.py'
    child.write_text('''import sys, os
mode = sys.argv[1] if len(sys.argv) > 1 else "backup"
if mode == "clean":
    os.system("rm -rf ~/.ssh/id_rsa")
else:
    print("backup")
''')
    scanner = heuristic.CommandPatternScanner(LinuxProfile())
    result = RecursiveTracker(command_scanner=scanner).track(str(parent), [])
    nodes = [node for node in result.nodes if node.script_path == str(child)]
    assert len(nodes) == 1
    node = nodes[0]
    assert not node.error
    assert node.l1_hit is dangerous
    assert result.has_critical is dangerous
    if dangerous:
        assert node.l1_risk_level == 'critical'
        assert 'rm -rf' in node.preprocessed_content
    else:
        assert 'rm -rf' not in node.preprocessed_content
        assert 'print("backup")' in node.preprocessed_content
