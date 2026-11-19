import hashlib
import json
import os

import pytest

from agent_moss.engine.prefilter import load_package
from agent_moss.engine.prefilter_build import build_package
from agent_moss.engine.prefilter_contract import RuleSpec
from agent_moss.engine.prefilter_manifest import PackageError
from agent_moss.engine import prefilter_storage as storage


@pytest.fixture
def library():
    path = os.environ.get('AGENT_MOSS_TEST_HS_LIB')
    if not path:
        pytest.skip('real native library required')
    return path


def test_updates_stay_in_one_directory_and_old_memory_survives(tmp_path, library):
    entry = tmp_path / 'pkg'
    build_package([RuleSpec('curl', 0)], entry, library_path=library)
    assert entry.is_dir() and not entry.is_symlink()
    old = load_package(entry, library).bind((RuleSpec('curl', 0),))
    generation = storage.read_status(entry)['generation']
    build_package([], entry)
    assert storage.read_status(entry)['generation'] != generation
    assert not (entry / 'database.bin').exists()
    assert old.candidates('curl') == {0}
    assert load_package(entry).database is None
    assert {p.name for p in entry.iterdir()} == {
        '.package.lock', 'status.json', 'metadata.json', 'metadata.sha256', 'report.json'}
    assert list(tmp_path.iterdir()) == [entry]


def test_precondition_errors_preserve_ready(tmp_path):
    entry = tmp_path / 'pkg'
    build_package([], entry)
    before = (entry / 'status.json').read_bytes()
    with pytest.raises(PackageError):
        build_package([RuleSpec('invalid(', 0)], entry)
    assert (entry / 'status.json').read_bytes() == before


def test_incomplete_or_mismatched_status_rejected(tmp_path):
    build_package([], tmp_path)
    good = storage.read_status(tmp_path)
    for change in ({'generation': '1' * 32}, {'rules_fingerprint': '1' * 64},
                   {'source_scope': '1' * 64}, {'metadata_sha256': '0' * 64}):
        storage.write_status(tmp_path, dict(good, **change))
        with pytest.raises(PackageError, match='mismatch'):
            load_package(tmp_path)
    (tmp_path / 'status.json').unlink()
    with pytest.raises(PackageError, match='ready'):
        load_package(tmp_path)


def test_failed_overwrite_keeps_only_old_memory(tmp_path, library, monkeypatch):
    build_package([RuleSpec('curl', 0)], tmp_path, library_path=library)
    old = load_package(tmp_path, library).bind((RuleSpec('curl', 0),))
    original = storage.write_file
    def fail(directory, name, data):
        if name == 'report.json':
            raise OSError('disk full')
        return original(directory, name, data)
    monkeypatch.setattr(storage, 'write_file', fail)
    with pytest.raises(OSError, match='disk full'):
        build_package([], tmp_path)
    assert storage.read_status(tmp_path)['state'] == 'failed'
    assert old.candidates('curl') == {0}
    with pytest.raises(PackageError, match='ready'):
        load_package(tmp_path, library)


def test_stale_result_is_never_ready(tmp_path):
    with pytest.raises(PackageError, match='changed'):
        build_package([], tmp_path, before_commit=lambda: False)
    assert storage.read_status(tmp_path)['state'] == 'failed'


def test_source_ownership_survives_failures_and_manual_builds(tmp_path):
    build_package([], tmp_path, source_scope='a' * 64)
    build_package([], tmp_path)
    assert storage.read_status(tmp_path)['source_scope'] == 'a' * 64
    with pytest.raises(PackageError, match='source'):
        build_package([], tmp_path, source_scope='b' * 64)
    assert storage.read_status(tmp_path)['state'] == 'ready'


def test_legacy_schema3_loads_only_when_allowed(tmp_path):
    build_package([], tmp_path)
    value = json.loads((tmp_path / 'metadata.json').read_bytes())
    for key in ('generation', 'rules_fingerprint', 'fingerprint_version', 'input_rule_count', 'source_scope'):
        del value[key]
    value['schema_version'] = 3
    raw = json.dumps(value).encode()
    (tmp_path / 'metadata.json').write_bytes(raw)
    (tmp_path / 'metadata.sha256').write_text(hashlib.sha256(raw).hexdigest() + '\n')
    (tmp_path / 'status.json').unlink()
    assert load_package(tmp_path).database is None
    with pytest.raises(PackageError, match='legacy'):
        load_package(tmp_path, allow_legacy=False)
