"""Package publication and load checks using a real native compiler."""

import hashlib
import json
import os
import re

import pytest

from agent_moss.engine.prefilter_build import build_package
from agent_moss.engine.prefilter_contract import RuleSpec, CONVERTER_VERSION
from agent_moss.engine.prefilter import load_package
from agent_moss.engine.prefilter_manifest import PackageError


def _library():
    path = os.environ.get("AGENT_MOSS_TEST_HS_LIB")
    if not path:
        pytest.skip("set AGENT_MOSS_TEST_HS_LIB to a real Hyperscan compile library")
    return path


def test_build_publishes_complete_version_and_matches_by_identity(tmp_path):
    entry = tmp_path / "prefilter.hsdb"
    rules = [RuleSpec(r"curl\s+https://", re.I), RuleSpec(r"abc(?i:xyz)", 0)]
    report = build_package(rules, entry, library_path=_library(), backend="hyperscan")
    assert entry.is_dir() and not entry.is_symlink()
    assert report["rules_total"] == 2
    assert report["rules_python"] == 1
    package = load_package(entry, _library(), backend="hyperscan")
    assert package.metadata["schema_version"] == 4
    assert package.metadata["converter_version"] == CONVERTER_VERSION == 3
    bound = package.bind(tuple(rules))
    assert bound.covered == frozenset({0})
    assert bound.candidates("curl https://") == {0}
    assert bound.candidates("https:// curl") == set()
    assert package.bind((RuleSpec(r"curl\s+https://", 0),)).covered == frozenset()


def test_empty_coverage_package_needs_no_native_library(tmp_path):
    entry = tmp_path / "prefilter.hsdb"
    build_package([], entry)
    package = load_package(entry)
    assert package.database is None
    assert package.bind(()).covered == frozenset()
    assert not (entry.resolve() / "database.bin").exists()


def test_old_converter_is_rejected_and_failed_build_preserves_entry(tmp_path):
    entry = tmp_path / "prefilter.hsdb"
    build_package([], entry)
    original = entry.resolve()
    metadata_file = original / "metadata.json"
    metadata = json.loads(metadata_file.read_text())
    metadata["converter_version"] = 1
    metadata_file.write_text(json.dumps(metadata))
    (original / 'metadata.sha256').write_text(hashlib.sha256(metadata_file.read_bytes()).hexdigest() + '\n')
    with pytest.raises(PackageError, match='converter_version'):
        load_package(entry)
    with pytest.raises(PackageError):
        build_package([RuleSpec("invalid(", 0)], entry)
    assert entry.resolve() == original


def test_surrogate_rule_is_reported_without_packaged_identity(tmp_path):
    entry = tmp_path / "prefilter.hsdb"
    report = build_package([RuleSpec("ab\ud800cd", 0)], entry)
    metadata = json.loads((entry.resolve() / "metadata.json").read_text())
    assert report["rules_total"] == 1
    assert report["rules_python"] == 1
    assert metadata["rules"] == []
    assert report["rules"][0] == {"index": 0, "category": "python", "reason": "surrogate source"}
