"""A localized compiler rejection removes one shared expression, not a rule."""

import json
import os

import pytest

from agent_moss.engine.prefilter_build import build_package
from agent_moss.engine.prefilter_contract import RuleSpec
from agent_moss.engine.prefilter_manifest import PackageError
from agent_moss.engine.prefilter_native import NativeCompileError, NativeLibrary


def _library():
    path = os.environ.get("AGENT_MOSS_TEST_HS_LIB")
    if not path:
        pytest.skip("set AGENT_MOSS_TEST_HS_LIB to a real Hyperscan compile library")
    return path


def test_local_compile_error_drops_all_rules_sharing_expression(tmp_path, monkeypatch):
    library = _library()
    entry = tmp_path / "prefilter.hsdb"
    original = NativeLibrary.compile
    attempts = 0

    def reject_first(self, expressions):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise NativeCompileError("unsupported generated expression", expression_index=0,
                                     stage="compile", status=-4)
        return original(self, expressions)

    monkeypatch.setattr(NativeLibrary, "compile", reject_first)
    rules = [RuleSpec("abc", 0), RuleSpec("^abc$", 0), RuleSpec("def", 0)]
    report = build_package(rules, entry, library_path=library, backend="hyperscan")
    metadata = json.loads((entry.resolve() / "metadata.json").read_text())
    assert attempts == 2
    assert report["rules_prefilter"] == 1
    assert report["rules_python"] == 2
    assert [record["expression_id"] for record in metadata["rules"]] == [None, None, 0]


def test_memory_error_with_expression_index_aborts_entire_build(tmp_path, monkeypatch):
    library = _library()
    entry = tmp_path / "prefilter.hsdb"
    build_package([], entry)
    old_target = entry.resolve()

    def out_of_memory(self, expressions):
        raise NativeCompileError("Out of memory", expression_index=0,
                                 stage="compile", status=-4)

    monkeypatch.setattr(NativeLibrary, "compile", out_of_memory)
    with pytest.raises(PackageError, match="memory"):
        build_package([RuleSpec("abc", 0)], entry, library_path=library, backend="hyperscan")
    assert entry.resolve() == old_target
