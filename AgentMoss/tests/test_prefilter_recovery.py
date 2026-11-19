"""Crash and multi-process checks use real native databases; no sample is executed."""
import os
import signal
import threading
import time
from types import SimpleNamespace

import pytest

from agent_moss.engine.prefilter import load_package
from agent_moss.engine.prefilter_build import build_package
from agent_moss.engine.prefilter_contract import RuleSpec
from agent_moss.engine.prefilter_manifest import PackageError
from agent_moss.engine import prefilter_storage as storage


@pytest.fixture
def library():
    value = os.environ.get('AGENT_MOSS_TEST_HS_LIB')
    if not value:
        pytest.skip('real compiler required')
    return value


@pytest.mark.parametrize('phase', ['building', 'database.bin', 'metadata.json',
    'metadata.sha256', 'report.json', 'trial', 'before-ready', 'after-ready'])
def test_killed_writer_recovers_without_releasing_old_memory(tmp_path, library, phase):
    from agent_moss.engine import prefilter_build as build
    build_package([RuleSpec('old', 0)], tmp_path, library_path=library)
    old = load_package(tmp_path, library).bind((RuleSpec('old', 0),))
    pid = os.fork()
    if pid == 0:
        def kill():
            os.kill(os.getpid(), signal.SIGKILL)
        write_status, write_file, trial = storage.write_status, storage.write_file, build._load_package_locked
        def status(directory, value):
            if value['state'] == 'ready' and phase == 'before-ready':
                kill()
            write_status(directory, value)
            if (value['state'], phase) in (('building', 'building'), ('ready', 'after-ready')):
                kill()
        def file(directory, name, data):
            if name == phase:
                write_file(directory, name, data[:max(1, len(data) // 2)])
                kill()
            write_file(directory, name, data)
        def load(*args, **kwargs):
            result = trial(*args, **kwargs)
            if phase == 'trial':
                kill()
            return result
        storage.write_status, storage.write_file, build._load_package_locked = status, file, load
        try:
            build_package([RuleSpec('new', 0)], tmp_path, library_path=library)
        except BaseException:
            os._exit(3)
        os._exit(2)
    _, status = os.waitpid(pid, 0)
    assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
    assert old.candidates('old') == {0}
    if phase == 'after-ready':
        assert load_package(tmp_path, library).bind((RuleSpec('new', 0),)).candidates('new') == {0}
    else:
        with pytest.raises(PackageError):
            load_package(tmp_path, library)
    build_package([RuleSpec('recovered', 0)], tmp_path, library_path=library)
    assert load_package(tmp_path, library).bind((RuleSpec('recovered', 0),)).candidates('recovered') == {0}
    assert not (tmp_path / storage.STATUS_TEMP).exists()


def test_two_processes_build_same_input_once(tmp_path, library):
    from agent_moss.engine.prefilter_autobuild import AutoBuilder
    from agent_moss.engine.prefilter_fingerprint import rules_fingerprint
    from agent_moss.engine.prefilter_rule_source import RuleSnapshot
    class Source:
        def snapshot(self):
            rules = (RuleSpec('curl', 0),)
            return RuleSnapshot(rules, rules_fingerprint(rules), 'a' * 64, 'b' * 64, True)
    reads, writes = os.pipe()
    children = []
    for _ in range(2):
        pid = os.fork()
        if pid == 0:
            os.close(reads)
            clock = [0.0]
            task = AutoBuilder(tmp_path, library, 'hyperscan', source=Source(), clock=lambda: clock[0])
            count = 0
            try:
                task.check(threading.Event(), threading.Lock())
                clock[0] = 1
                for attempt in range(20):
                    count += task.check(threading.Event(), threading.Lock()) is not None
                    time.sleep(.01)
                os.write(writes, bytes([count]))
                os._exit(0)
            except BaseException:
                os._exit(3)
        children.append(pid)
    os.close(writes)
    for pid in children:
        _, code = os.waitpid(pid, 0)
        assert os.waitstatus_to_exitcode(code) == 0
    counts = os.read(reads, 2)
    os.close(reads)
    assert len(counts) == 2 and sum(counts) == 1
    assert storage.read_status(tmp_path)['state'] == 'ready'


def test_cli_reports_failed_stage_without_native_load(tmp_path):
    from agent_moss.accel_cli import _disk_status
    with pytest.raises(PackageError):
        build_package([], tmp_path, before_commit=lambda: False)
    result = _disk_status(SimpleNamespace(db=str(tmp_path)))
    assert result['state'] == 'failed'
    assert result['error_stage'] == 'commit'
    assert 'changed' in result['error_reason']
    assert result['worker_state'] == 'not_checked'


def test_status_fsync_order_and_initial_failure_preserve_payload(tmp_path, monkeypatch):
    build_package([], tmp_path)
    original = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    replace = storage.os.replace
    def fail(source, target):
        if str(target).endswith('status.json'):
            raise OSError('replace failed')
        return replace(source, target)
    monkeypatch.setattr(storage.os, 'replace', fail)
    with pytest.raises(OSError, match='replace failed'):
        build_package([], tmp_path)
    assert {name: (tmp_path / name).read_bytes() for name in original} == original
    assert load_package(tmp_path).database is None
