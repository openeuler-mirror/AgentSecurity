"""The exact same native package is loaded by each available Python minor."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest

from agent_moss.engine.prefilter_build import build_package
from agent_moss.engine.prefilter_contract import RuleSpec


_WORKTREE = Path(__file__).resolve().parents[1]
_CHECK = r'''
import json, re, sys
from agent_moss.engine.prefilter import load_package
from agent_moss.engine.prefilter_simplify import simplify_rule
from agent_moss.engine.prefilter_contract import RuleSpec
from agent_moss.engine.prefilter_compat import python_compatibility
entry, library = sys.argv[1:]
assert python_compatibility().supported, python_compatibility().reason
rules = (RuleSpec(r"curl\s+https://", re.I), RuleSpec(r"chmod\s+777", re.I))
package = load_package(entry, library, backend="hyperscan")
assert package.metadata["schema_version"] == 4
assert package.metadata["converter_version"] == 3
binding = package.bind(rules)
assert binding.covered == frozenset({0, 1})
for text in ("curl https://example.com", "chmod 中文 777", "pwd"):
    actual = binding.candidates(text)
    expected = {i for i, rule in enumerate(rules) if re.search(rule.pattern, text, rule.flags)}
    assert expected <= actual, (text, expected, actual)
counterexamples = (r"ab(?i)?cd", r"ab(?i)*cd", r"ab(?u){0}cd")
legal = 0
for source in counterexamples:
    try:
        compiled = re.compile(source)
    except re.error:
        continue
    legal += 1
    assert compiled.search("acd") is not None
    result = simplify_rule(RuleSpec(source, compiled.flags))
    assert result.expression is None
print(json.dumps({"python": sys.version.split()[0], "package": package.identity,
                  "covered": len(binding.covered), "legal_counterexamples": legal}))
'''


def _interpreter(minor):
    configured = os.environ.get(f"AGENT_MOSS_TEST_PYTHON_{minor}")
    if configured:
        return configured
    candidate = Path.home() / ".local" / "share" / "uv" / "python" / f"cpython-3.{minor}-linux-x86_64-gnu" / "bin" / "python"
    if candidate.exists():
        return str(candidate)
    return shutil.which(f"python3.{minor}")


def test_one_package_loads_under_python_310_to_314(tmp_path):
    library = os.environ.get("AGENT_MOSS_TEST_HS_LIB")
    if not library:
        pytest.skip("set AGENT_MOSS_TEST_HS_LIB to a real Hyperscan compile library")
    entry = tmp_path / "prefilter.hsdb"
    rules = (RuleSpec(r"curl\s+https://", re.I), RuleSpec(r"chmod\s+777", re.I))
    build_package(rules, entry, library_path=library, backend="hyperscan")
    results = []
    for minor in range(10, 15):
        executable = _interpreter(minor)
        if executable is None:
            pytest.skip(f"Python 3.{minor} interpreter unavailable; matrix unverified")
        env = dict(os.environ, PYTHONPATH=str(_WORKTREE))
        result = subprocess.run([executable, "-c", _CHECK, str(entry), library],
                                env=env, cwd=tmp_path, capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, f"Python 3.{minor}: {result.stderr}"
        results.append(json.loads(result.stdout))
    assert len({item["package"] for item in results}) == 1
    assert len(results) == 5
    assert results[0]["legal_counterexamples"] == 3
    print("T08", json.dumps(results, ensure_ascii=True))
