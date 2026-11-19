"""New packages map each covered rule directly to one generated expression."""

import hashlib
import json
import os
import re

import pytest

from agent_moss.engine.prefilter_build import build_package
from agent_moss.engine.prefilter_build import read_rules_snapshot
from agent_moss.engine.prefilter_contract import RuleSpec
from agent_moss.engine.prefilter import load_package
from agent_moss.engine.prefilter_manifest import PackageError, encode_rule_pattern


def _library():
    path = os.environ.get("AGENT_MOSS_TEST_HS_LIB")
    if not path:
        pytest.skip("set AGENT_MOSS_TEST_HS_LIB to a real Hyperscan compile library")
    return path


def test_ascii_class_is_covered_without_literal_condition(tmp_path):
    library = _library()
    rules = (RuleSpec(r"[0-9]+", 0), RuleSpec(r"\d+", 0),
             RuleSpec(r"curl\s+https://", re.I))
    entry = tmp_path / "prefilter.hsdb"
    report = build_package(rules, entry, library_path=library, backend="hyperscan")
    metadata = json.loads((entry.resolve() / "metadata.json").read_text())
    assert (metadata["schema_version"], metadata["converter_version"]) == (4, 3)
    assert report["rules_prefilter"] == 2
    assert report["rules_python"] == 1
    assert len(metadata["expressions"]) == 2
    assert [record["expression_id"] is not None for record in metadata["rules"]] == [True, False, True]
    assert all("literal" not in record and "structural" not in record for record in metadata["rules"])
    assert all("uses" not in expression for expression in metadata["expressions"])
    bound = load_package(entry, library, backend="hyperscan").bind(rules)
    assert bound.covered == frozenset({0, 2})
    assert bound.candidates("123") == {0}
    assert bound.candidates("abc") == set()


def test_shared_expression_keeps_duplicate_business_indices(tmp_path):
    library = _library()
    rules = (RuleSpec("abc", 0), RuleSpec("^abc$", 0), RuleSpec("abc", 0))
    entry = tmp_path / "prefilter.hsdb"
    build_package(rules, entry, library_path=library, backend="hyperscan")
    metadata = json.loads((entry.resolve() / "metadata.json").read_text())
    assert len(metadata["expressions"]) == 1
    assert [record["expression_id"] for record in metadata["rules"]] == [0, 0, 0]
    bound = load_package(entry, library, backend="hyperscan").bind(rules)
    assert bound.candidates("abc") == {0, 1, 2}


def test_old_double_condition_schema_is_rejected(tmp_path):
    entry = tmp_path / "prefilter.hsdb"
    build_package([], entry)
    metadata_file = entry.resolve() / "metadata.json"
    metadata = json.loads(metadata_file.read_text())
    metadata["schema_version"] = 1
    metadata["converter_version"] = 2
    metadata_file.write_text(json.dumps(metadata))
    (entry / 'metadata.sha256').write_text(hashlib.sha256(metadata_file.read_bytes()).hexdigest() + '\n')
    with pytest.raises(PackageError, match='schema_version'):
        load_package(entry)


def test_overlong_legal_rule_stays_python_without_disabling_other_rules(tmp_path):
    library = _library()
    rules = (RuleSpec("a" * 65_537, 0), RuleSpec("abc", 0))
    entry = tmp_path / "prefilter.hsdb"
    report = build_package(rules, entry, library_path=library, backend="hyperscan")
    metadata = json.loads((entry.resolve() / "metadata.json").read_text())
    assert report["rules_total"] == 2
    assert report["rules_python"] == 1
    assert report["rules_prefilter"] == 1
    assert report["rules"][0] == {"index": 0, "category": "python",
                                  "reason": "rule source length budget exceeded"}
    assert len(metadata["rules"]) == 1
    assert load_package(entry, library, backend="hyperscan").bind(rules).covered == frozenset({1})


def test_exported_snapshot_can_preserve_overlong_surrogate_rule(tmp_path):
    original = "a" * 65_537 + "\ud800"
    snapshot = tmp_path / "rules.json"
    snapshot.write_text(json.dumps({"schema_version": 1, "rules": [
        {"pattern": encode_rule_pattern(original), "flags": ["UNICODE"]},
    ]}))
    assert read_rules_snapshot(snapshot)[0].pattern == original
