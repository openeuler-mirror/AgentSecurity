"""Script tracking checks each readable body once and retains its evidence."""

from dataclasses import asdict
import os
from pathlib import Path
import time

import pytest

from agent_moss.engine.heuristic import CommandPatternScanner
from agent_moss.engine.script_content_analyzer import (
    analyze_script_content,
    scan_script_chain_with_l1,
)
from agent_moss.engine.types import ScriptChainAnalysisResult, ScriptNode
from agent_moss.profiles.linux import LinuxProfile


@pytest.fixture
def recording_scanner(monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_RULES_MODE", "builtin")
    monkeypatch.setenv("AGENT_MOSS_ACCEL", "0")
    monkeypatch.setenv("AGENT_MOSS_ACCEL_AUTO_BUILD", "0")
    scanner = CommandPatternScanner(LinuxProfile())
    calls = []
    original = scanner.scan

    def record(text):
        calls.append(text)
        return original(text)

    monkeypatch.setattr(scanner, "scan", record)
    return scanner, calls


def _write(directory, name, content):
    (directory / name).write_text(content, encoding="utf-8")


def _analyze(directory, scanner, *, stop_on_critical=True):
    return analyze_script_content(
        "bash", "bash parent.sh", command_scanner=scanner,
        cwd=str(directory), stop_on_critical=stop_on_critical,
    )


def test_safe_shell_and_python_bodies_are_scanned_once(tmp_path, recording_scanner):
    scanner, calls = recording_scanner
    _write(tmp_path, "parent.sh", "#!/bin/sh\npython3 child.py\n")
    _write(tmp_path, "child.py", "print('safe child')\n")

    result = _analyze(tmp_path, scanner)

    assert [Path(node.script_path).name for node in result.nodes] == ["parent.sh", "child.py"]
    assert [text.strip() for text in calls] == ["python3 child.py", "print('safe child')"]
    assert all(not node.l1_hit and not node.error for node in result.nodes)
    assert not result.has_critical and not result.has_high
    assert result.first_hit_node is None


@pytest.mark.parametrize("danger_at,stop,expected_names,expected_calls", [
    ("parent", True, ["parent.sh"], 1),
    ("parent", False, ["parent.sh", "child.sh", "sibling.sh"], 3),
    ("child", True, ["parent.sh", "child.sh"], 2),
    ("child", False, ["parent.sh", "child.sh", "sibling.sh"], 3),
])
def test_critical_scan_preserves_early_stop_and_evidence(
        tmp_path, recording_scanner, danger_at, stop, expected_names, expected_calls):
    scanner, calls = recording_scanner
    bodies = {
        "parent.sh": ("rm -rf /\n" if danger_at == "parent" else "")
        + "bash child.sh\nbash sibling.sh\n",
        "child.sh": "rm -rf /\n" if danger_at == "child" else "echo child\n",
        "sibling.sh": "echo sibling\n",
    }
    for name, content in bodies.items():
        _write(tmp_path, name, content)

    result = _analyze(tmp_path, scanner, stop_on_critical=stop)

    assert [Path(node.script_path).name for node in result.nodes] == expected_names
    assert len(calls) == expected_calls
    assert calls == [bodies[name] for name in expected_names]
    hit = next(node for node in result.nodes if node.l1_hit)
    assert Path(hit.script_path).name == danger_at + ".sh"
    assert hit.l1_risk_level == "critical"
    assert hit.l1_reason and hit.l1_matched_patterns and hit.l1_risk_type
    assert result.has_critical and result.has_high
    assert result.first_hit_node is hit


def test_empty_and_missing_bodies_are_not_scanned(tmp_path, recording_scanner):
    scanner, calls = recording_scanner
    _write(tmp_path, "parent.sh", "bash empty.sh\nbash missing.sh\n")
    _write(tmp_path, "empty.sh", "")

    result = _analyze(tmp_path, scanner)

    assert [Path(node.script_path).name for node in result.nodes] == ["parent.sh", "empty.sh", "missing.sh"]
    assert calls == ["bash empty.sh\nbash missing.sh\n"]
    assert result.nodes[1].preprocessed_content == ""
    assert not result.nodes[1].l1_hit
    assert result.nodes[2].error and not result.nodes[2].l1_hit


def test_cycle_does_not_rescan_visited_bodies(tmp_path, recording_scanner):
    scanner, calls = recording_scanner
    _write(tmp_path, "parent.sh", "bash child.sh\n")
    _write(tmp_path, "child.sh", "bash parent.sh\n")

    result = _analyze(tmp_path, scanner)

    assert [Path(node.script_path).name for node in result.nodes] == ["parent.sh", "child.sh"]
    assert calls == ["bash child.sh\n", "bash parent.sh\n"]
    assert not result.has_critical


@pytest.mark.parametrize("with_scanner", [True, False])
def test_keyword_evidence_survives_without_a_command_rule_hit(
        tmp_path, recording_scanner, with_scanner):
    scanner, calls = recording_scanner
    _write(tmp_path, "parent.sh", "curl -X POST http://127.0.0.1/api\n")

    result = _analyze(tmp_path, scanner if with_scanner else None)

    assert calls == (["curl -X POST http://127.0.0.1/api\n"] if with_scanner else [])
    assert not result.nodes[0].l1_hit
    assert result.nodes[0].is_suspicious
    assert "curl POST" in result.nodes[0].matched_keywords


def test_scan_failure_propagates_instead_of_using_a_partial_result(
        tmp_path, recording_scanner, monkeypatch):
    scanner, _ = recording_scanner
    _write(tmp_path, "parent.sh", "echo safe\n")

    def fail(text):
        raise RuntimeError("scanner failed")

    monkeypatch.setattr(scanner, "scan", fail)
    with pytest.raises(RuntimeError, match="scanner failed"):
        _analyze(tmp_path, scanner)


def test_standalone_l1_helper_remains_available(recording_scanner):
    scanner, calls = recording_scanner
    chain = ScriptChainAnalysisResult(nodes=[
        ScriptNode(script_path="standalone.sh", preprocessed_content="rm -rf /"),
    ])

    result = scan_script_chain_with_l1(chain, scanner)

    assert calls == ["rm -rf /"]
    assert result.nodes[0].l1_hit and result.has_critical
    assert result.first_hit_node is result.nodes[0]


@pytest.mark.parametrize("dangerous", [False, True])
def test_native_scanning_preserves_full_result_without_rescanning(
        tmp_path, recording_scanner, monkeypatch, dangerous):
    library = os.environ.get("AGENT_MOSS_TEST_ACCEL_LIB") or os.environ.get("AGENT_MOSS_TEST_HS_LIB")
    if not library:
        pytest.skip("requires a real Hyperscan/Ultrascan compile library")
    backend = os.environ.get("AGENT_MOSS_TEST_ACCEL_BACKEND")
    from agent_moss.engine.prefilter_build import build_package
    from agent_moss.engine.prefilter_contract import RuleSpec
    from agent_moss.engine.prefilter_native import NativeDatabase
    from agent_moss.engine.prefilter_reload import get_manager, stop_managers

    scanner, calls = recording_scanner
    _write(tmp_path, "parent.sh", "bash child.sh\n")
    _write(tmp_path, "child.sh", "rm -rf /\n" if dangerous else "echo safe\n")
    expected_inputs = ["bash child.sh\n", "rm -rf /\n" if dangerous else "echo safe\n"]
    baseline = _analyze(tmp_path, scanner)
    assert calls == expected_inputs
    assert baseline.nodes[1].l1_hit is dangerous
    calls.clear()
    rules = tuple(RuleSpec(rule["pattern"], rule["regex"].flags)
                  for rule in scanner._get_active_rules())
    package = tmp_path / "package"
    build_package(rules, package, library_path=library, backend=backend)
    monkeypatch.setenv("AGENT_MOSS_ACCEL_DB", str(package))
    monkeypatch.setenv("AGENT_MOSS_ACCEL_LIB", library)
    if backend:
        monkeypatch.setenv("AGENT_MOSS_ACCEL_BACKEND", backend)
    else:
        monkeypatch.delenv("AGENT_MOSS_ACCEL_BACKEND", raising=False)
    monkeypatch.setenv("AGENT_MOSS_ACCEL", "1")
    manager = get_manager()
    native_calls = []
    original_scan = NativeDatabase.scan

    def record_native(database, data):
        result = original_scan(database, data)
        native_calls.append(data)
        return result

    try:
        manager.start()
        deadline = time.monotonic() + 10
        while manager.status()["active_package"] is None and time.monotonic() < deadline:
            time.sleep(.01)
        assert manager.status()["active_package"] is not None, manager.status()
        monkeypatch.setattr(NativeDatabase, "scan", record_native)

        accelerated = _analyze(tmp_path, scanner)

        assert asdict(accelerated) == asdict(baseline)
        assert calls == expected_inputs
        assert len(native_calls) == 2
    finally:
        stop_managers()
