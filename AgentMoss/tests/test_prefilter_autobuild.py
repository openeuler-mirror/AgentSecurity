import os
import threading
import time
from contextlib import ExitStack, contextmanager

import pytest

from agent_moss.engine.prefilter_contract import RuleSpec
from agent_moss.engine.prefilter_fingerprint import rules_fingerprint
from agent_moss.engine.prefilter_rule_source import RuleSnapshot
from agent_moss.engine.prefilter_manifest import PackageError
from agent_moss.engine.prefilter_native import NativeCompileError, NativeLibrary
from agent_moss.engine.prefilter_storage import PackageBusy, PackageLock, read_status


class Source:
    def __init__(self, *patterns):
        self.rules = tuple(RuleSpec(p, 0) for p in patterns)
        self.eligible = True

    def snapshot(self):
        return RuleSnapshot(self.rules, rules_fingerprint(self.rules), 'a' * 64, 'b' * 64, self.eligible)


@pytest.fixture
def library():
    value = os.environ.get('AGENT_MOSS_TEST_HS_LIB')
    if not value:
        pytest.skip('requires real compiler')
    return value


def builder(entry, library, source, clock):
    from agent_moss.engine.prefilter_autobuild import AutoBuilder
    return AutoBuilder(entry, library, 'hyperscan', source=source, clock=lambda: clock[0])


def check(task):
    return task.check(threading.Event(), threading.Lock())


def wait_for(predicate, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.01)
    pytest.fail('background operation did not finish')


@contextmanager
def exclusive_when_idle(entry):
    """Wait for the actual lock, not the earlier in-memory publication."""
    deadline = time.monotonic() + 8
    with ExitStack() as stack:
        while True:
            try:
                stack.enter_context(PackageLock(entry, exclusive=True))
                break
            except PackageBusy:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.005)
        yield


def test_debounce_no_rebuild_and_all_python_input(tmp_path, library):
    clock = [0.0]
    source = Source(r'(abc)\1')
    task = builder(tmp_path / 'pkg', library, source, clock)
    assert check(task) is None and not task.entry.exists()
    clock[0] = .99
    assert check(task) is None and not task.entry.exists()
    clock[0] = 1.01
    result = check(task)
    assert result['rules_python'] == 1
    generation = read_status(task.entry)['generation']
    clock[0] = 10
    assert check(task) is None
    assert read_status(task.entry)['generation'] == generation


def test_changes_restart_debounce_and_repair_same_generation_damage(tmp_path, library):
    clock = [0.0]
    source = Source('curl')
    task = builder(tmp_path, library, source, clock)
    check(task)
    clock[0] = 1
    source.rules = (RuleSpec('wget', 0),)
    assert check(task) is None
    clock[0] = 2
    check(task)
    previous = read_status(tmp_path)['generation']
    (tmp_path / 'database.bin').write_bytes(b'broken')
    clock[0] = 3
    check(task)
    assert read_status(tmp_path)['generation'] != previous


def test_other_worker_observes_shared_failure_cooldown(tmp_path, library, monkeypatch):
    clock = [0.0]
    source = Source('curl')
    first, second = [builder(tmp_path, library, source, clock) for _ in range(2)]
    check(first)
    check(second)
    clock[0] = 1
    def fail(self, expressions):
        raise NativeCompileError('out of memory', stage='compile', status=-2)
    monkeypatch.setattr(NativeLibrary, 'compile', fail)
    with pytest.raises(PackageError, match='memory'):
        check(first)
    status = read_status(tmp_path)
    assert status['state'] == 'failed'
    assert check(second) is None
    assert read_status(tmp_path) == status


def test_rule_change_during_compile_never_becomes_ready(tmp_path, library, monkeypatch):
    clock = [0.0]
    source = Source('curl')
    task = builder(tmp_path, library, source, clock)
    original = NativeLibrary.compile
    def change(self, expressions):
        result = original(self, expressions)
        source.rules = (RuleSpec('wget', 0),)
        return result
    monkeypatch.setattr(NativeLibrary, 'compile', change)
    check(task)
    clock[0] = 1
    with pytest.raises(PackageError, match='changed'):
        check(task)
    assert read_status(tmp_path)['state'] == 'failed'


def test_cold_process_cannot_overwrite_new_package(tmp_path, library):
    from agent_moss.engine.prefilter_build import build_package
    build_package([RuleSpec('new', 0)], tmp_path, library_path=library, source_scope='a' * 64)
    original = read_status(tmp_path)
    source = Source('old')
    source.eligible = False
    clock = [0.0]
    task = builder(tmp_path, library, source, clock)
    check(task)
    clock[0] = 3
    check(task)
    assert read_status(tmp_path) == original


def test_background_build_and_reload_keep_requests_on_memory(tmp_path, library):
    from agent_moss.engine.prefilter_reload import PackageManager
    source = Source('curl', 'chmod')
    manager = PackageManager(tmp_path, library, auto_build=True, rule_source=source, poll_interval=.01)
    manager.start()
    try:
        wait_for(lambda: manager.status()['active_package'])
        old = manager.bind(source.rules)
        first = manager.status()['active_package']
        # Both locks may be held: request bindings still use existing memory.
        with exclusive_when_idle(tmp_path):
            source.rules = (RuleSpec('wget', 0), RuleSpec('chmod', 0))
            assert manager.bind(source.rules).covered == frozenset({1})
            assert old.candidates('curl') == {0}
        wait_for(lambda: manager.status()['active_package'] != first)
        assert manager.bind(source.rules).candidates('wget') == {0}
        assert old.candidates('curl') == {0}
    finally:
        manager.stop()


def test_stop_during_compile_never_publishes(tmp_path, library, monkeypatch):
    clock = [0.0]
    task = builder(tmp_path, library, Source('curl'), clock)
    stop = threading.Event()
    original = NativeLibrary.compile
    def stopping(self, expressions):
        value = original(self, expressions)
        stop.set()
        return value
    monkeypatch.setattr(NativeLibrary, 'compile', stopping)
    task.check(stop, threading.Lock())
    clock[0] = 1
    with pytest.raises(PackageError, match='stopped'):
        task.check(stop, threading.Lock())
    assert read_status(tmp_path)['state'] == 'failed'


def test_stop_returns_while_committing_but_writer_keeps_its_lock(tmp_path, library, monkeypatch):
    from agent_moss.engine.prefilter_reload import PackageManager
    from agent_moss.engine import prefilter_storage as storage
    entered, release = threading.Event(), threading.Event()
    original = storage.write_status
    def blocked(directory, value):
        if value['state'] == 'ready':
            entered.set()
            assert release.wait(10)
        return original(directory, value)
    monkeypatch.setattr(storage, 'write_status', blocked)
    manager = PackageManager(tmp_path, library, auto_build=True, rule_source=Source('curl'), poll_interval=.01)
    manager.start()
    try:
        assert entered.wait(5)
        began = time.monotonic()
        manager.stop(timeout=.01)
        assert time.monotonic() - began < .3
        with pytest.raises(storage.PackageBusy):
            with PackageLock(tmp_path, exclusive=True):
                pass
    finally:
        release.set()
        manager.stop()


def test_local_native_allocation_failure_does_not_destroy_ready_package(tmp_path, library, monkeypatch):
    from agent_moss.engine.prefilter_build import build_package
    from agent_moss.engine.prefilter_native import NativeLoadError
    source = Source('curl')
    build_package(source.rules, tmp_path, library_path=library, source_scope='a' * 64)
    before = read_status(tmp_path)
    def fail(self, blob, count):
        raise NativeLoadError('out of memory', stage='scratch', status=-2)
    monkeypatch.setattr(NativeLibrary, 'load', fail)
    clock = [0.0]
    task = builder(tmp_path, library, source, clock)
    check(task)
    clock[0] = 1
    check(task)
    assert read_status(tmp_path) == before
