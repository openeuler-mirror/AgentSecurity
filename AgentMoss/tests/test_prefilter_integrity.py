"""Corrupt metadata must never turn a real Python match into an exclusion."""

import hashlib
import json
import os
import re
import time
from types import SimpleNamespace

import pytest

from agent_moss.accel_cli import _disk_status
from agent_moss.agents.base import AgentExtensions
from agent_moss.engine.heuristic import CommandPatternScanner
from agent_moss.engine.prefilter import load_package
from agent_moss.engine.prefilter_build import build_package
from agent_moss.engine.prefilter_contract import RuleSpec
from agent_moss.engine.prefilter_manifest import PackageError
from agent_moss.engine.prefilter_reload import get_manager, stop_managers
from agent_moss.profiles.base import CommandPattern
from agent_moss.profiles.linux import LinuxProfile


@pytest.fixture
def library():
    path = os.environ.get('AGENT_MOSS_TEST_HS_LIB')
    if not path:
        pytest.skip('requires real Hyperscan')
    return path


def _read(entry, consumer, library=None):
    if consumer == 'loader':
        return load_package(entry, library, backend='hyperscan')
    return _disk_status(SimpleNamespace(db=str(entry)))


def _rules():
    # The first two distinct rules share expression 0; expression 1 also exists.
    return (RuleSpec('uniqueAA', re.I), RuleSpec(r'\buniqueAA\b', re.I),
            RuleSpec('uniqueBB', re.I))


def _corrupt_mapping(entry):
    path = entry.resolve() / 'metadata.json'
    raw = path.read_bytes()
    changed = raw.replace(b'"expression_id":0', b'"expression_id":1', 1)
    assert len(raw) == len(changed)
    assert sum(a != b for a, b in zip(raw, changed)) == 1
    path.write_bytes(changed)


@pytest.mark.parametrize('consumer', ['loader', 'status'])
def test_valid_expression_id_corruption_is_rejected(tmp_path, library, consumer):
    entry = tmp_path / 'current'
    build_package(_rules(), entry, library_path=library, backend='hyperscan')
    assert load_package(entry, library, backend='hyperscan').bind(_rules()[:1]).candidates('uniqueAA') == {0}
    _corrupt_mapping(entry)
    with pytest.raises(PackageError, match='metadata.*digest mismatch'):
        _read(entry, consumer, library)


@pytest.mark.parametrize('consumer', ['loader', 'status'])
@pytest.mark.parametrize('damage', ['missing', 'malformed', 'wrong', 'oversized', 'symlink'])
def test_invalid_metadata_checksum_is_rejected(tmp_path, consumer, damage):
    entry = tmp_path / 'current'
    build_package([], entry)
    checksum = entry.resolve() / 'metadata.sha256'
    checksum.unlink(missing_ok=True)
    if damage == 'malformed':
        checksum.write_bytes(b'not-a-checksum\n')
    elif damage == 'wrong':
        checksum.write_bytes(b'0' * 64 + b'\n')
    elif damage == 'oversized':
        checksum.write_bytes(b'0' * 66)
    elif damage == 'symlink':
        target = tmp_path / 'checksum-target'
        raw = (entry.resolve() / 'metadata.json').read_bytes()
        target.write_bytes(hashlib.sha256(raw).hexdigest().encode('ascii') + b'\n')
        checksum.symlink_to(target)
    with pytest.raises(PackageError):
        _read(entry, consumer)


@pytest.mark.parametrize('consumer', ['loader', 'status'])
def test_old_schema_is_rejected_even_with_valid_checksum(tmp_path, consumer):
    entry = tmp_path / 'current'
    build_package([], entry)
    directory = entry.resolve()
    metadata = json.loads((directory / 'metadata.json').read_bytes())
    metadata['schema_version'] = 2
    raw = json.dumps(metadata).encode('utf-8')
    (directory / 'metadata.json').write_bytes(raw)
    (directory / 'metadata.sha256').write_bytes(hashlib.sha256(raw).hexdigest().encode('ascii') + b'\n')
    with pytest.raises(PackageError, match='schema_version'):
        _read(entry, consumer)


def test_package_byte_count_includes_every_published_file(tmp_path):
    entry = tmp_path / 'current'
    report = build_package([], entry)
    size = sum(path.stat().st_size for path in entry.resolve().iterdir())
    assert report['package_bytes'] == size
    assert json.loads((entry / 'report.json').read_bytes())['package_bytes'] == size


def _wait_for_state(manager, predicate):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        state = manager.status()
        if predicate(state):
            return state
        time.sleep(.01)
    pytest.fail(f'background load did not finish: {manager.status()}')


@pytest.mark.parametrize('has_previous_package', [False, True])
def test_corrupt_package_preserves_python_match(tmp_path, monkeypatch, library, has_previous_package):
    rule = CommandPattern(pattern='uniqueAA', risk_level='high',
                          risk_type='script_execution', reason='integrity regression')
    scanner = CommandPatternScanner(LinuxProfile(), agent_ext=AgentExtensions(
        agent_id='integrity-test', extra_command_patterns=[rule]))
    monkeypatch.setenv('AGENT_MOSS_ACCEL', '0')
    expected = scanner.scan('uniqueAA')
    assert expected.hit and expected.risk_level == 'high'
    entry = tmp_path / 'current'
    staging = tmp_path / 'staging'
    build_package(_rules(), staging, library_path=library, backend='hyperscan')
    _corrupt_mapping(staging)
    if has_previous_package:
        build_package(_rules(), entry, library_path=library, backend='hyperscan')
    else:
        staging.replace(entry)
    monkeypatch.setenv('AGENT_MOSS_ACCEL', '1')
    monkeypatch.setenv('AGENT_MOSS_ACCEL_AUTO_BUILD', '0')
    monkeypatch.setenv('AGENT_MOSS_ACCEL_DB', str(entry))
    monkeypatch.setenv('AGENT_MOSS_ACCEL_LIB', library)
    monkeypatch.setenv('AGENT_MOSS_ACCEL_BACKEND', 'hyperscan')
    manager = get_manager()
    manager.start()
    previous = None
    try:
        if has_previous_package:
            previous = _wait_for_state(manager, lambda state: state['active_package'])['active_package']
            _corrupt_mapping(entry)
        bad_target = str(entry.resolve())
        state = _wait_for_state(manager, lambda state: state['error'])
        assert scanner.scan('uniqueAA') == expected
        assert state['error'] and 'digest mismatch' in state['error']
        assert state['active_package'] == previous
    finally:
        stop_managers()
