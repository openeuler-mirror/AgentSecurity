"""Hot-update acceptance with real files, native databases and service workers.

All command strings are data passed to the scanner; none are executed.
"""
import errno
import json
import multiprocessing
import os
import re
import signal
import threading
import time
from types import SimpleNamespace

import pytest

from agent_moss.engine.heuristic import CommandPatternScanner
from agent_moss.engine.prefilter import load_package
from agent_moss.engine.prefilter_build import build_package
from agent_moss.engine.prefilter_contract import RuleSpec
from agent_moss.engine.prefilter_manifest import PackageError
from agent_moss.engine.prefilter_native import NativeCompileError, NativeLibrary, NativeLoadError
from agent_moss.engine.prefilter_reload import PackageManager
from agent_moss.engine import prefilter_storage as storage
from test_prefilter_autobuild import Source, builder, check, exclusive_when_idle, library, wait_for
from test_prefilter_rule_source import _isolate_runtime_config, rule, sources


def active_rules(scanner):
    return tuple(RuleSpec(r['pattern'], r['regex'].flags) for r in scanner._get_active_rules())


def assert_results(scanner, monkeypatch, texts, hits):
    monkeypatch.setenv('AGENT_MOSS_ACCEL', '0')
    expected = [scanner.scan(text) for text in texts]
    assert [result.hit for result in expected] == hits
    monkeypatch.setenv('AGENT_MOSS_ACCEL', '1')
    assert [scanner.scan(text) for text in texts] == expected


@pytest.mark.parametrize('entrypoint', ['file', 'console', 'extra-file'])
def test_rule_edits_apply_before_build_and_after_native_activation(sources, library, monkeypatch, entrypoint):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from agent_moss.console.router import router
    from agent_moss.profiles import get_profile
    from agent_moss.engine import prefilter_reload as reload
    from agent_moss.infra import runtime_config

    path, source_module = sources
    runtime_config.save_runtime_config({'layers': {}, 'L1_rules': {'user_custom': {'rules': []}}})
    scanner = CommandPatternScanner(get_profile('linux'))
    source = source_module.RuleSource()
    manager = PackageManager(path / 'pkg', library, auto_build=True, rule_source=source, poll_interval=.01)
    monkeypatch.setattr(reload, 'get_manager', lambda: manager if os.getenv('AGENT_MOSS_ACCEL') == '1' else None)
    app = FastAPI()
    app.include_router(router)
    texts = ['builtin', 'uniqueAlpha', 'uniqueBeta', 'harmless']
    changes = [('add', [True, True, False, False]), ('edit', [True, False, True, False]),
               ('disable', [True, False, False, False]), ('enable', [True, False, True, False]),
               ('delete', [True, False, False, False])]
    if entrypoint == 'extra-file':
        changes = [change for change in changes if change[0] not in ('enable', 'disable')]
    manager.start()
    try:
        wait_for(lambda: manager.status()['active_package'])
        old = manager.bind((RuleSpec('builtin', re.I),))
        with TestClient(app) as client:
            for step, hits in changes:
                previous = manager.status()['active_generation']
                # Deliberately prevent rebuilding; new business rules must work now.
                with exclusive_when_idle(path / 'pkg'):
                    if entrypoint == 'console' and step != 'edit':
                        if step == 'add':
                            response = client.post('/console/api/rules', json=dict(
                                layer='L1_rules', category='user_custom', **rule('uniqueAlpha')))
                        elif step == 'delete':
                            response = client.request('DELETE', '/console/api/rules', json=dict(
                                layer='L1_rules', category='user_custom', rule_id=rule_id))
                        else:
                            response = client.put('/console/api/rules/enabled', json=dict(
                                layer='L1_rules', category='user_custom', rule_id=rule_id, enabled=step == 'enable'))
                        assert response.status_code == 200, response.text
                        if step == 'add':
                            rule_id = response.json()['L1_rules']['user_custom']['rules'][0]['id']
                    else:
                        if entrypoint == 'extra-file':
                            target = path / 'extra' / 'extra.json'
                            value = json.loads(target.read_text()) if target.exists() else {'dangerous_commands': []}
                            records = value['dangerous_commands']
                        else:
                            target = path / 'runtime.json'
                            value = json.loads(target.read_text())
                            records = value['L1_rules']['user_custom']['rules']
                        if step == 'add':
                            records.append(rule('uniqueAlpha', id='custom-live', builtin=False, enabled=True))
                        elif step == 'edit':
                            records[0]['pattern'] = 'uniqueBeta'
                        elif step == 'delete':
                            records.clear()
                        else:
                            records[0]['enabled'] = step == 'enable'
                        pending = target.with_suffix('.next')
                        pending.write_text(json.dumps(value))
                        pending.replace(target)
                    assert manager.status()['active_generation'] == previous
                    assert_results(scanner, monkeypatch, texts, hits)
                    binding = manager.bind(active_rules(scanner))
                    if step in ('add', 'edit'):
                        current = 'uniqueAlpha' if step == 'add' else 'uniqueBeta'
                        index = next(i for i, r in enumerate(active_rules(scanner)) if r.pattern == current)
                        assert index not in binding.covered
                    assert old.candidates('builtin') == {0}
                wait_for(lambda: manager.status()['active_generation'] != previous)
                binding = manager.bind(active_rules(scanner))
                assert binding.covered == frozenset(range(len(active_rules(scanner))))
                database = binding.package.database
                native_calls = []
                original = database.scan
                def record(data):
                    result = original(data)
                    native_calls.append(data)
                    return result
                with monkeypatch.context() as patch:
                    patch.setattr(database, 'scan', record)
                    assert_results(scanner, monkeypatch, texts, hits)
                assert all(text.encode() in native_calls for text in texts)
                for index, spec in enumerate(active_rules(scanner)):
                    assert index in binding.candidates(spec.pattern)
                assert binding.candidates('harmless') == set()
                assert old.candidates('builtin') == {0}
    finally:
        manager.stop()


@pytest.mark.parametrize('retry_worker', ['same', 'other'])
def test_failed_build_retries_at_30_seconds_and_activates(tmp_path, library, monkeypatch, retry_worker):
    from agent_moss.engine import prefilter_autobuild as automatic, prefilter_build as build
    clock, wall = [0.0], [1000.0]
    fake_time = SimpleNamespace(time=lambda: wall[0], monotonic=lambda: clock[0])
    monkeypatch.setattr(automatic, 'time', fake_time)
    monkeypatch.setattr(build, 'time', fake_time)
    source = Source('curl')
    first, second = [builder(tmp_path, library, source, clock) for _ in range(2)]
    for task in (first, second):
        check(task)
    clock[0], wall[0] = 1., 1001.
    with monkeypatch.context() as patch:
        def fail(self, expressions):
            raise NativeCompileError('temporary failure', stage='compile', status=-2)
        patch.setattr(NativeLibrary, 'compile', fail)
        with pytest.raises(PackageError):
            check(first)
    failed = storage.read_status(tmp_path)
    manager = PackageManager(tmp_path, library, retry_interval=.01, poll_interval=.01)
    try:
        task = first if retry_worker == 'same' else second
        clock[0], wall[0] = 30.999, 1030.999
        assert check(task) is None
        assert storage.read_status(tmp_path) == failed
        assert manager.bind(source.rules) is None
        clock[0], wall[0] = 31., 1031.
        assert check(task) is not None
        manager.start()
        wait_for(lambda: manager.status()['active_package'])
        assert manager.bind(source.rules).candidates('curl') == {0}
        assert manager.bind(source.rules).candidates('unrelated') == set()
    finally:
        manager.stop()


def test_new_input_bypasses_previous_failure_cooldown(tmp_path, library, monkeypatch):
    clock = [0.]
    source = Source('old')
    task = builder(tmp_path, library, source, clock)
    check(task)
    clock[0] = 1.
    with monkeypatch.context() as patch:
        def fail(self, expressions):
            raise NativeCompileError('temporary failure', stage='compile', status=-2)
        patch.setattr(NativeLibrary, 'compile', fail)
        with pytest.raises(PackageError):
            check(task)
    source.rules = (RuleSpec('new', 0),)
    clock[0] = 2.
    assert check(task) is None
    clock[0] = 3.
    assert check(task) is not None
    assert load_package(tmp_path, library).bind(source.rules).candidates('new') == {0}


def test_discarded_stale_build_automatically_builds_latest(tmp_path, library, monkeypatch):
    source = Source('original')
    original = NativeLibrary.compile
    changed = threading.Event()
    def change_once(self, expressions):
        result = original(self, expressions)
        if not changed.is_set():
            source.rules = (RuleSpec('latest', 0),)
            changed.set()
        return result
    monkeypatch.setattr(NativeLibrary, 'compile', change_once)
    manager = PackageManager(tmp_path, library, auto_build=True, rule_source=source, poll_interval=.01)
    manager.start()
    try:
        assert changed.wait(5)
        wait_for(lambda: manager.status()['active_package'])
        assert manager.bind(source.rules).covered == {0}
        assert manager.bind(source.rules).candidates('latest') == {0}
        assert manager.bind((RuleSpec('original', 0),)).covered == set()
        assert storage.read_status(tmp_path)['state'] == 'ready'
    finally:
        manager.stop()


@pytest.mark.parametrize('phase', ['database.bin', 'before-ready'])
def test_killed_build_is_recovered_by_background_worker(tmp_path, library, phase):
    old_rules = (RuleSpec('old', 0),)
    build_package(old_rules, tmp_path, library_path=library)
    old = load_package(tmp_path, library).bind(old_rules)
    pid = os.fork()
    if pid == 0:
        write_file, write_status = storage.write_file, storage.write_status
        def file(directory, name, data):
            if phase == name:
                write_file(directory, name, data[:len(data)//2])
                os.kill(os.getpid(), signal.SIGKILL)
            return write_file(directory, name, data)
        def status(directory, value):
            if phase == 'before-ready' and value['state'] == 'ready':
                os.kill(os.getpid(), signal.SIGKILL)
            return write_status(directory, value)
        storage.write_file, storage.write_status = file, status
        try:
            build_package([RuleSpec('new', 0)], tmp_path, library_path=library)
        finally:
            os._exit(3)
    _, code = os.waitpid(pid, 0)
    assert os.WIFSIGNALED(code) and os.WTERMSIG(code) == signal.SIGKILL
    source = Source('new')
    manager = PackageManager(tmp_path, library, auto_build=True, rule_source=source, poll_interval=.01)
    assert manager.bind(source.rules) is None
    manager.start()
    try:
        wait_for(lambda: manager.status()['active_package'])
        assert manager.bind(source.rules).candidates('new') == {0}
        assert old.candidates('old') == {0}
        assert storage.read_status(tmp_path)['state'] == 'ready'
    finally:
        manager.stop()


def _service_worker(entry, library_path, rules_file, connection, fail_load, compiles):
    """Separate address space: its own background thread, native owner and cache."""
    from pathlib import Path
    from agent_moss.engine.prefilter_fingerprint import rules_fingerprint
    from agent_moss.engine.prefilter_rule_source import RuleSnapshot
    from agent_moss.engine import prefilter_reload as reload
    import traceback
    class FileSource:
        @property
        def rules(self):
            return tuple(RuleSpec(p, re.I) for p in json.loads(Path(rules_file).read_text()))
        def snapshot(self):
            rules = self.rules
            return RuleSnapshot(rules, rules_fingerprint(rules), 'a' * 64, 'b' * 64, True)
    source = FileSource()
    compile_native = NativeLibrary.compile
    def compile(self, expressions):
        with compiles.get_lock():
            compiles.value += 1
        return compile_native(self, expressions)
    def load(directory, library_path, *, backend):
        if fail_load.is_set():
            raise NativeLoadError('worker-local scratch failure', stage='scratch', status=-2)
        return load_package(directory, library_path, backend=backend)
    NativeLibrary.compile = compile
    manager = PackageManager(entry, library_path, auto_build=True, rule_source=source,
                             loader=load, poll_interval=.01, retry_interval=.05)
    reload.get_manager = lambda: manager if os.getenv('AGENT_MOSS_ACCEL') == '1' else None
    manager.start()
    old = None
    try:
        while connection.poll(25):
            action = connection.recv()
            if action == 'stop':
                return
            current_rules = source.rules
            binding = manager.bind(current_rules)
            if old is None and binding is not None:
                old = binding
            scanner = CommandPatternScanner(SimpleNamespace(os_type='linux',
                dangerous_commands=[rule(r.pattern) for r in current_rules]))
            scanner._get_active_rules = lambda: scanner._compiled
            os.environ['AGENT_MOSS_ACCEL'] = '0'
            expected = [scanner.scan(text) for text in ('old', 'new', 'unrelated')]
            os.environ['AGENT_MOSS_ACCEL'] = '1'
            assert [scanner.scan(text) for text in ('old', 'new', 'unrelated')] == expected
            connection.send(dict(status=manager.status(),
                business_hits=[result.hit for result in expected],
                covered=sorted(binding.covered) if binding else [],
                hits=sorted(binding.candidates('new')) if binding else [],
                old_hits=sorted(old.candidates('old')) if old else []))
    except BaseException:
        connection.send({'exception': traceback.format_exc()})
        raise
    finally:
        manager.stop()
        connection.close()


def test_two_services_activate_independently_and_failed_worker_recovers(tmp_path, library):
    ctx = multiprocessing.get_context('spawn')
    entry, rules_file = tmp_path / 'pkg', tmp_path / 'rules.json'
    rules_file.write_text(json.dumps(['old']))
    build_package([RuleSpec('old', re.I)], entry, library_path=library, source_scope='a' * 64)
    compiles = ctx.Value('i', 0)
    workers = []
    def start():
        parent, child = ctx.Pipe()
        fault = ctx.Event()
        process = ctx.Process(target=_service_worker,
            args=(entry, library, rules_file, child, fault, compiles))
        process.start()
        child.close()
        workers.append((process, parent, fault))
        return parent, fault
    def status(pipe):
        pipe.send('status')
        assert pipe.poll(5), 'service failed to answer'
        value = pipe.recv()
        assert 'exception' not in value, value
        return value
    def stop_worker(worker):
        process, pipe, _ = worker
        if process.is_alive():
            pipe.send('stop')
        process.join(5)
        if process.is_alive():
            process.kill()
            process.join(5)
        pipe.close()
        assert process.exitcode == 0
    try:
        first, _ = start()
        second, fault = start()
        for pipe in (first, second):
            wait_for(lambda: status(pipe)['covered'] == [0])
        initial = status(first)['status']['active_generation']
        assert status(second)['status']['active_generation'] == initial
        fault.set()
        pending = rules_file.with_suffix('.next')
        pending.write_text(json.dumps(['new']))
        pending.replace(rules_file)
        wait_for(lambda: status(first)['status']['active_generation'] != initial)
        wait_for(lambda: status(second)['status']['error'])
        latest = status(first)
        lagging = status(second)
        assert latest['hits'] == [0] and latest['covered'] == [0]
        assert lagging['status']['active_generation'] == initial and lagging['covered'] == []
        assert latest['business_hits'] == lagging['business_hits'] == [False, True, False]
        assert latest['old_hits'] == lagging['old_hits'] == [0]
        assert compiles.value == 1
        generation = storage.read_status(entry)['generation']
        assert generation == latest['status']['active_generation']
        fault.clear()
        wait_for(lambda: status(second)['status']['active_generation'] == generation)
        assert status(second)['hits'] == [0]
        assert compiles.value == 1
        stop_worker(workers.pop())
        restarted, _ = start()
        wait_for(lambda: status(restarted)['status']['active_generation'] == generation)
        assert status(restarted)['hits'] == [0] and compiles.value == 1
    finally:
        for worker in workers:
            stop_worker(worker)


@pytest.mark.parametrize('phase', ['database.bin', 'metadata.json', 'report.json',
    'payload-directory', 'ready-temp', 'ready-replace', 'ready-directory', 'failure-record'])
def test_persistence_failure_never_replaces_memory_and_automatically_recovers(
        tmp_path, library, monkeypatch, phase):
    source = Source('old')
    source.rules = (RuleSpec('old', re.I),)
    build_package(source.rules, tmp_path, library_path=library, source_scope='a' * 64)
    manager = PackageManager(tmp_path, library, poll_interval=.01, retry_interval=.01)
    manager.start()
    try:
        wait_for(lambda: manager.status()['active_package'])
        old = manager.bind(source.rules)
        active = manager.status()['active_generation']
        clock, wall = [0.], [1000.]
        from agent_moss.engine import prefilter_autobuild as automatic, prefilter_build as build
        fake_time = SimpleNamespace(time=lambda: wall[0], monotonic=lambda: clock[0])
        monkeypatch.setattr(automatic, 'time', fake_time)
        monkeypatch.setattr(build, 'time', fake_time)
        source.rules = (RuleSpec('new', re.I),)
        from agent_moss.engine import prefilter_reload as reload
        # This storage test fixes the business input; real file/Console resolution
        # is exercised separately above. Keep the complete scan and fallback real.
        monkeypatch.setattr(reload, 'get_manager', lambda: manager if os.getenv('AGENT_MOSS_ACCEL') == '1' else None)
        scanner = CommandPatternScanner(SimpleNamespace(os_type='linux', dangerous_commands=[rule('new')]))
        monkeypatch.setattr(scanner, '_get_active_rules', lambda: scanner._compiled)
        task = builder(tmp_path, library, source, clock)
        check(task)
        clock[0] = 1.
        calls = []
        original_sync, original_replace = os.fsync, os.replace
        def sync(fd):
            target = os.readlink(f'/proc/self/fd/{fd}')
            name = os.path.basename(target)
            state = storage.read_status(tmp_path)
            state = state['state'] if state else None
            failed = name == phase
            if name == storage.STATUS_TEMP and phase == 'ready-temp':
                failed = json.loads((tmp_path / name).read_text())['state'] == 'ready'
            if target == str(tmp_path):
                calls.append(state)
                failed = (phase == 'payload-directory' and calls == ['building', 'building']
                          or phase == 'ready-directory' and state == 'ready')
            if phase == 'failure-record':
                failed = name == 'report.json' or (name == storage.STATUS_TEMP and
                    json.loads((tmp_path / name).read_text())['state'] == 'failed')
            if failed:
                raise OSError(errno.ENOSPC, 'injected disk full')
            return original_sync(fd)
        def replace(src, dst):
            if phase == 'ready-replace' and str(dst).endswith('status.json'):
                if json.loads(src.read_text())['state'] == 'ready':
                    raise OSError(errno.EIO, 'injected replace error')
            return original_replace(src, dst)
        # The builder takes the write lock; the live loader must reject partial files.
        with monkeypatch.context() as patch:
            patch.setattr(os, 'fsync', sync)
            patch.setattr(os, 'replace', replace)
            def attempt():
                try:
                    check(task)
                except OSError:
                    return True
                return False
            wait_for(attempt)
        assert storage.read_status(tmp_path)['state'] in ('building', 'failed')
        assert manager.status()['active_generation'] == active
        assert old.candidates('old') == {0}
        assert manager.bind(source.rules).covered == set()
        assert_results(scanner, monkeypatch, ['old', 'new', 'harmless'], [False, True, False])
        with pytest.raises(PackageError, match='ready'):
            load_package(tmp_path, library)
        # No manual build: the original automatic builder retries after its cooldown.
        clock[0], wall[0] = 31., 1031.
        wait_for(lambda: check(task) is not None)
        wait_for(lambda: manager.status()['active_generation'] != active)
        assert manager.bind(source.rules).candidates('new') == {0}
        assert_results(scanner, monkeypatch, ['old', 'new', 'harmless'], [False, True, False])
        assert old.candidates('old') == {0}
        assert not (tmp_path / storage.STATUS_TEMP).exists()
    finally:
        manager.stop()


def test_readonly_prebuilt_package_loads_without_writes_and_auto_recovers_permissions(tmp_path, library):
    entry = tmp_path / 'pkg'
    source = Source('old')
    build_package(source.rules, entry, library_path=library, source_scope='a' * 64)
    before = {p.name: p.read_bytes() for p in entry.iterdir()}
    for path in entry.iterdir():
        path.chmod(0o444)
    entry.chmod(0o555)
    manager = PackageManager(entry, library, auto_build=False, poll_interval=.01)
    try:
        # An actual denied write is required; chmod alone proves nothing as root.
        with pytest.raises(PermissionError):
            with (entry / 'write-probe').open('wb'):
                pass
        manager.start()
        wait_for(lambda: manager.status()['active_package'])
        assert manager.bind(source.rules).candidates('old') == {0}
        assert {p.name: p.read_bytes() for p in entry.iterdir()} == before
        clock = [0.]
        source.rules = (RuleSpec('new', 0),)
        task = builder(entry, library, source, clock)
        check(task)
        clock[0] = 1.
        with pytest.raises(PermissionError):
            check(task)
        assert manager.bind((RuleSpec('old', 0),)).candidates('old') == {0}
        assert {p.name: p.read_bytes() for p in entry.iterdir()} == before
        entry.chmod(0o755)
        for path in entry.iterdir():
            path.chmod(0o600)
        clock[0] = 31.
        wait_for(lambda: check(task) is not None)
        wait_for(lambda: manager.bind(source.rules).covered == {0})
        assert manager.bind(source.rules).candidates('new') == {0}
    finally:
        manager.stop()
        entry.chmod(0o755)
        for path in entry.iterdir():
            path.chmod(0o600)


def test_live_background_worker_retries_after_real_30_second_cooldown(tmp_path, library, monkeypatch):
    source = Source('old')
    build_package(source.rules, tmp_path, library_path=library, source_scope='a' * 64)
    manager = PackageManager(tmp_path, library, auto_build=True, rule_source=source, poll_interval=.02)
    original = NativeLibrary.compile
    failed, repair = threading.Event(), threading.Event()
    attempts = []
    def compile(self, expressions):
        attempts.append(time.monotonic())
        if not repair.is_set():
            failed.set()
            raise NativeCompileError('temporary compiler outage', stage='compile', status=-2)
        return original(self, expressions)
    monkeypatch.setattr(NativeLibrary, 'compile', compile)
    manager.start()
    try:
        wait_for(lambda: manager.status()['active_package'])
        generation = manager.status()['active_generation']
        old = manager.bind(source.rules)
        source.rules = (RuleSpec('new', 0),)
        assert failed.wait(5)
        wait_for(lambda: manager.status()['build_error'])
        repair.set()
        assert manager.status()['active_generation'] == generation
        assert manager.bind(source.rules).covered == set()
        assert old.candidates('old') == {0}
        # Do not call AutoBuilder.check or alter the clock/retry policy here.
        wait_for(lambda: manager.status()['active_generation'] != generation, timeout=38)
        assert len(attempts) == 2
        assert attempts[1] - attempts[0] >= 30
        assert manager.bind(source.rules).candidates('new') == {0}
        assert manager.bind(source.rules).candidates('unrelated') == set()
        assert manager.status()['build_error'] is None
        assert old.candidates('old') == {0}
    finally:
        manager.stop()
