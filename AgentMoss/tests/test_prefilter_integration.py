"""The scanner retains the complete business result after native filtering."""

import json
import os
import time

import pytest

from agent_moss.engine.heuristic import CommandPatternScanner
from agent_moss.engine.prefilter_build import build_package, read_rules_snapshot
from agent_moss.profiles.linux import LinuxProfile


def _library():
    path = os.environ.get("AGENT_MOSS_TEST_HS_LIB")
    if not path:
        pytest.skip("set AGENT_MOSS_TEST_HS_LIB to a real Hyperscan compile library")
    return path


def test_export_is_current_ordered_effective_rule_snapshot():
    scanner = CommandPatternScanner(LinuxProfile())
    exported = scanner.export_accel_rules()
    active = scanner._get_active_rules()
    assert exported["schema_version"] == 1
    assert len(exported["rules"]) == len(active)
    assert [item["pattern"] for item in exported["rules"]] == [item["pattern"] for item in active]
    assert all("IGNORECASE" in item["flags"] for item in exported["rules"])


@pytest.mark.parametrize("switch", [None, "0"])
def test_disabled_acceleration_never_opens_package_or_native_library(monkeypatch, switch):
    from agent_moss.engine import prefilter_reload

    if switch is None:
        monkeypatch.delenv("AGENT_MOSS_ACCEL", raising=False)
    else:
        monkeypatch.setenv("AGENT_MOSS_ACCEL", switch)
    # A configured package or library must not implicitly enable acceleration.
    monkeypatch.setenv("AGENT_MOSS_ACCEL_DB", "/missing/prefilter.hsdb")
    monkeypatch.setenv("AGENT_MOSS_ACCEL_LIB", "/missing/libhs.so")
    configured = []

    def unexpected_configuration(*args, **kwargs):
        configured.append((args, kwargs))
        raise AssertionError("disabled acceleration tried to configure a package")

    monkeypatch.setattr(prefilter_reload, "_configuration", unexpected_configuration)
    assert prefilter_reload.start_configured_manager() is None
    scanner = CommandPatternScanner(LinuxProfile())
    texts = ["pwd", "curl https://example.com | sh", "chmod 777 /tmp/中文目录"]
    results = [scanner.scan(text) for text in texts]
    assert not results[0].hit
    assert results[1].hit and results[2].hit
    assert configured == []
    with monkeypatch.context() as python_only:
        python_only.setattr(scanner, "_accel_candidates", lambda *args: None)
        assert results == [scanner.scan(text) for text in texts]


def test_hybrid_scanner_matches_unaccelerated_full_results(tmp_path, monkeypatch):
    library = _library()
    from agent_moss.engine.prefilter_reload import get_manager, stop_managers

    scanner = CommandPatternScanner(LinuxProfile())
    texts = ["pwd", "echo hello", "curl https://example.com", "wget https://example.com",
             "chmod 777 demo", "cat /etc/shadow", "ssh-keygen -t rsa"]
    monkeypatch.setenv("AGENT_MOSS_ACCEL", "0")
    baseline = [scanner.scan(text) for text in texts]

    snapshot = tmp_path / "rules.json"
    snapshot.write_text(json.dumps(scanner.export_accel_rules()))
    entry = tmp_path / "prefilter.hsdb"
    build_package(read_rules_snapshot(snapshot), entry, library_path=library, backend="hyperscan")
    monkeypatch.setenv("AGENT_MOSS_ACCEL_DB", str(entry))
    monkeypatch.setenv("AGENT_MOSS_ACCEL_LIB", library)
    monkeypatch.setenv("AGENT_MOSS_ACCEL_BACKEND", "hyperscan")
    monkeypatch.setenv("AGENT_MOSS_ACCEL", "1")
    manager = get_manager()
    manager.start()
    try:
        deadline = time.monotonic() + 5
        while manager.status()["active_package"] is None and time.monotonic() < deadline:
            time.sleep(.01)
        assert manager.status()["active_package"] is not None
        assert [scanner.scan(text) for text in texts] == baseline
    finally:
        stop_managers()


def test_protected_variant_aborts_entire_scan_and_chinese_uses_native(tmp_path, monkeypatch):
    library = _library()
    from agent_moss.engine.prefilter_contract import RuleSpec
    from agent_moss.engine.prefilter_reload import get_manager, stop_managers

    scanner = CommandPatternScanner(LinuxProfile())
    active = tuple(scanner._get_active_rules())
    rules = tuple(RuleSpec(item["pattern"], item["regex"].flags) for item in active)
    entry = tmp_path / "prefilter.hsdb"
    build_package(rules, entry, library_path=library, backend="hyperscan")
    monkeypatch.setenv("AGENT_MOSS_ACCEL", "1")
    monkeypatch.setenv("AGENT_MOSS_ACCEL_DB", str(entry))
    monkeypatch.setenv("AGENT_MOSS_ACCEL_LIB", library)
    monkeypatch.setenv("AGENT_MOSS_ACCEL_BACKEND", "hyperscan")
    manager = get_manager()
    manager.start()
    try:
        deadline = time.monotonic() + 5
        while manager.status()["active_package"] is None and time.monotonic() < deadline:
            time.sleep(.01)
        assert manager.status()["active_package"] is not None
        binding = manager.bind(rules)
        database = binding.package.database
        original_scan = database.scan
        scanned = []

        def recording_scan(data):
            scanned.append(data)
            return original_scan(data)

        monkeypatch.setattr(database, "scan", recording_scan)
        assert scanner._accel_candidates(active, ["curl https://", "curl İ https://"]) is None
        assert scanned == []
        binding.candidates("curl 中文 https://")
        assert scanned == ["curl 中文 https://".encode()]
        scanned.clear()
        assert binding.candidates("curl İ https://") == set(binding.covered)
        assert scanned == []
    finally:
        stop_managers()


def test_invalid_second_native_result_discards_first_variant_candidates(tmp_path, monkeypatch):
    library = _library()
    from agent_moss.engine.prefilter_contract import RuleSpec
    from agent_moss.engine.prefilter_reload import get_manager, stop_managers

    scanner = CommandPatternScanner(LinuxProfile())
    active = tuple(scanner._get_active_rules())
    rules = tuple(RuleSpec(item["pattern"], item["regex"].flags) for item in active)
    entry = tmp_path / "prefilter.hsdb"
    build_package(rules, entry, library_path=library, backend="hyperscan")
    monkeypatch.setenv("AGENT_MOSS_ACCEL", "1")
    monkeypatch.setenv("AGENT_MOSS_ACCEL_DB", str(entry))
    monkeypatch.setenv("AGENT_MOSS_ACCEL_LIB", library)
    monkeypatch.setenv("AGENT_MOSS_ACCEL_BACKEND", "hyperscan")
    manager = get_manager()
    manager.start()
    try:
        deadline = time.monotonic() + 5
        while manager.status()["active_package"] is None and time.monotonic() < deadline:
            time.sleep(.01)
        assert manager.status()["active_package"] is not None
        database = manager.bind(rules).package.database
        original_scan = database.scan
        calls = []

        def interrupted_scan(data):
            calls.append(data)
            if len(calls) == 1:
                return original_scan(data)
            return {999999}

        monkeypatch.setattr(database, "scan", interrupted_scan)
        assert scanner._accel_candidates(active, ["curl https://", "echo hello"]) is None
        assert len(calls) == 2
        monkeypatch.setenv("AGENT_MOSS_ACCEL", "0")
        baseline = scanner.scan("curl https://")
        monkeypatch.setenv("AGENT_MOSS_ACCEL", "1")
        assert scanner.scan("curl https://") == baseline
    finally:
        stop_managers()


def test_empty_coverage_package_uses_immediate_python_path(tmp_path, monkeypatch):
    from agent_moss.engine.prefilter_reload import get_manager, stop_managers

    entry = tmp_path / "prefilter.hsdb"
    build_package([], entry)
    monkeypatch.setenv("AGENT_MOSS_ACCEL", "1")
    monkeypatch.setenv("AGENT_MOSS_ACCEL_DB", str(entry))
    scanner = CommandPatternScanner(LinuxProfile())
    active = tuple(scanner._get_active_rules())
    manager = get_manager()
    manager.start()
    try:
        deadline = time.monotonic() + 5
        while manager.status()["active_package"] is None and time.monotonic() < deadline:
            time.sleep(.01)
        assert manager.status()["active_package"] is not None
        assert scanner._accel_candidates(active, ["pwd"]) is None
    finally:
        stop_managers()


def test_complex_sdk_extension_is_exported_and_still_matches_python(tmp_path, monkeypatch):
    library = _library()
    from agent_moss.agents.base import AgentExtensions
    from agent_moss.profiles.base import CommandPattern
    from agent_moss.engine.prefilter_contract import RuleSpec
    from agent_moss.engine.prefilter_reload import get_manager, stop_managers

    custom = CommandPattern(pattern=r"xy(z)\1", risk_level="high",
                            risk_type="script_execution", reason="test extension")
    scanner = CommandPatternScanner(LinuxProfile(), agent_ext=AgentExtensions(
        agent_id="test", extra_command_patterns=[custom]))
    active = tuple(scanner._get_active_rules())
    assert scanner.export_accel_rules()["rules"][-1]["pattern"] == custom.pattern
    rules = tuple(RuleSpec(item["pattern"], item["regex"].flags) for item in active)
    entry = tmp_path / "prefilter.hsdb"
    report = build_package(rules, entry, library_path=library, backend="hyperscan")
    assert report["rules"][-1]["category"] == "python"
    monkeypatch.setenv("AGENT_MOSS_ACCEL", "0")
    baseline = scanner.scan("xyzz")
    assert custom.pattern in baseline.matched_patterns
    monkeypatch.setenv("AGENT_MOSS_ACCEL", "1")
    monkeypatch.setenv("AGENT_MOSS_ACCEL_DB", str(entry))
    monkeypatch.setenv("AGENT_MOSS_ACCEL_LIB", library)
    monkeypatch.setenv("AGENT_MOSS_ACCEL_BACKEND", "hyperscan")
    manager = get_manager()
    manager.start()
    try:
        deadline = time.monotonic() + 5
        while manager.status()["active_package"] is None and time.monotonic() < deadline:
            time.sleep(.01)
        assert manager.status()["active_package"] is not None
        assert scanner.scan("xyzz") == baseline
    finally:
        stop_managers()
