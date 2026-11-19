"""Fixed-directory protocol: incomplete files never become readable packages."""
import hashlib
import json
import os
import re
import uuid

import pytest

from agent_moss.engine.prefilter_contract import RuleSpec
from agent_moss.engine.prefilter_manifest import PackageError


def state(kind='building', **extra):
    return dict(status_version=1, state=kind, generation=uuid.uuid4().hex,
                rules_fingerprint='a' * 64, fingerprint_version=1,
                source_scope=None, **extra)


def test_fingerprint_is_lossless_set_of_effective_patterns():
    from agent_moss.engine.prefilter_fingerprint import rules_fingerprint
    rules = [RuleSpec('curl', re.I), RuleSpec('wget', 0)]
    wire = b'{"fingerprint_version":1,"rules":[["curl",34],["wget",32]]}'
    assert rules_fingerprint(rules) == hashlib.sha256(wire).hexdigest()
    assert rules_fingerprint(rules[::-1] + rules) == rules_fingerprint(rules)
    assert rules_fingerprint([RuleSpec('curl', 0)]) != rules_fingerprint(rules[:1])
    assert rules_fingerprint([RuleSpec('\ud800\udc00', 0)]) != rules_fingerprint([RuleSpec('\U00010000', 0)])


def test_readers_share_but_writer_does_not_overlap(tmp_path):
    from agent_moss.engine.prefilter_storage import PackageLock, PackageBusy
    directory = tmp_path / 'package'
    with PackageLock(directory, exclusive=True, create=True):
        with pytest.raises(PackageBusy):
            with PackageLock(directory):
                pytest.fail('reader entered during write')
    with PackageLock(directory), PackageLock(directory):
        with pytest.raises(PackageBusy):
            with PackageLock(directory, exclusive=True):
                pytest.fail('writer entered during read')
    assert (directory / '.package.lock').is_file()


def test_status_roundtrip_and_strict_validation(tmp_path):
    from agent_moss.engine.prefilter_storage import read_status, write_status
    assert read_status(tmp_path) is None
    value = state('ready', metadata_sha256='b' * 64)
    write_status(tmp_path, value)
    assert read_status(tmp_path) == value
    assert not (tmp_path / '.status.tmp').exists()
    for change in ({'state': 'other'}, {'generation': 'bad'}, {'source_scope': True},
                   {'metadata_sha256': ''}, {'unexpected': 1}, {'status_version': True}):
        (tmp_path / 'status.json').write_text(json.dumps(dict(value, **change)))
        with pytest.raises(PackageError):
            read_status(tmp_path)


def test_write_failure_before_replace_preserves_status(tmp_path, monkeypatch):
    from agent_moss.engine import prefilter_storage as storage
    original = state()
    storage.write_status(tmp_path, original)
    def fail(fd):
        raise OSError('disk full')
    monkeypatch.setattr(storage.os, 'fsync', fail)
    with pytest.raises(OSError):
        storage.write_status(tmp_path, state('ready', metadata_sha256='b' * 64))
    assert storage.read_status(tmp_path) == original


@pytest.mark.parametrize('name', ['database.bin', '.status.tmp', '.package.lock'])
def test_managed_files_do_not_follow_links(tmp_path, name):
    from agent_moss.engine.prefilter_storage import PackageLock, write_file, write_status
    outside = tmp_path / 'outside'
    outside.write_bytes(b'keep')
    directory = tmp_path / 'package'
    directory.mkdir()
    (directory / name).symlink_to(outside)
    with pytest.raises((OSError, PackageError)):
        if name == '.package.lock':
            with PackageLock(directory, exclusive=True):
                pass
        elif name == '.status.tmp':
            write_status(directory, state())
        else:
            write_file(directory, name, b'overwrite')
    assert outside.read_bytes() == b'keep'


def test_lock_child_close_does_not_unlock_parent(tmp_path):
    from agent_moss.engine.prefilter_storage import PackageLock, PackageBusy
    with PackageLock(tmp_path, exclusive=True, create=True):
        pid = os.fork()
        if pid == 0:
            try:
                with PackageLock(tmp_path, exclusive=True):
                    os._exit(1)
            except PackageBusy:
                os._exit(0)
            except BaseException:
                os._exit(2)
        _, code = os.waitpid(pid, 0)
        assert os.waitstatus_to_exitcode(code) == 0
        with pytest.raises(PackageBusy):
            with PackageLock(tmp_path, exclusive=True):
                pass
