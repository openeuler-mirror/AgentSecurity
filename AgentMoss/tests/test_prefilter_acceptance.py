"""Remaining business, package failure and resource-lifetime acceptance checks.

Native calls are real; injected errors/delays are confined to the boundary they
exercise. Command strings are only scanned, never executed.
"""
import concurrent.futures
import gc
import hashlib
import json
import os
import re
import select
import threading
import time
import weakref

import pytest

from agent_moss.engine.heuristic import CommandPatternScanner
from agent_moss.engine.prefilter import load_package
from agent_moss.engine.prefilter_build import build_package
from agent_moss.engine.prefilter_contract import RuleSpec
from agent_moss.engine.prefilter_manifest import PackageError
from agent_moss.engine.prefilter_native import NativeCompileError, NativeLibrary, NativeScanError
from agent_moss.engine.prefilter_reload import PackageManager, get_manager, stop_managers
from agent_moss.profiles.linux import LinuxProfile
from agent_moss.profiles.windows import WindowsProfile


@pytest.fixture
def library():
    value = os.environ.get('AGENT_MOSS_TEST_HS_LIB')
    if not value:
        pytest.skip('requires real Hyperscan')
    return value


def wait_for(predicate):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.005)
    pytest.fail('background operation did not finish')


def build_when_idle(*args, **kwargs):
    from agent_moss.engine.prefilter_storage import PackageBusy
    deadline = time.monotonic() + 10
    while True:
        try:
            return build_package(*args, **kwargs)
        except PackageBusy:
            if time.monotonic() >= deadline:
                raise
            time.sleep(.005)


def activate(entry, library, monkeypatch):
    monkeypatch.setenv('AGENT_MOSS_ACCEL', '1')
    monkeypatch.setenv('AGENT_MOSS_ACCEL_AUTO_BUILD', '0')
    monkeypatch.setenv('AGENT_MOSS_ACCEL_DB', str(entry))
    monkeypatch.setenv('AGENT_MOSS_ACCEL_LIB', library)
    monkeypatch.setenv('AGENT_MOSS_ACCEL_BACKEND', 'hyperscan')
    manager = get_manager()
    manager.start()
    wait_for(lambda: manager.status()['active_package'])
    return manager


def specs(scanner):
    return tuple(RuleSpec(rule['pattern'], rule['regex'].flags)
                 for rule in scanner._get_active_rules())


@pytest.mark.parametrize('profile,texts', [
    (LinuxProfile, [
        'cat /etc//shadow', 'r""m -rf /', 'rm$IFS-rf$IFS/',
        'grep "echo pass | passwd" file', 'echo pass | passwd',
        'bash -c "echo pass | passwd"',
        'ssh-keygen -t rsa -f ~/.ssh/id_rsa', 'ssh-keygen -y -f ~/.ssh/id_rsa',
        'cat /etc/shadow; chmod 777 demo; curl https://example.com',
        'echo "rm -rf /"', 'echo 中文; chmod\u3000777 demo',
    ]),
    (WindowsProfile, [
        'type C:/Windows/System32/config/SAM',
        r'type C:\Windows\System32\config\SAM',
        'net user example pass /add', 'shutdown /s /t 0',
        'powershell -EncodedCommand YQ==',
    ]),
])
def test_business_filters_and_variants_keep_complete_ordered_result(
        tmp_path, monkeypatch, library, profile, texts):
    scanner = CommandPatternScanner(profile())
    monkeypatch.setenv('AGENT_MOSS_ACCEL', '0')
    expected = [scanner.scan(text) for text in texts]
    assert any(result.hit for result in expected)
    entry = tmp_path / 'pkg'
    build_package(specs(scanner), entry, library_path=library, backend='hyperscan')
    manager = activate(entry, library, monkeypatch)
    database = manager.bind(specs(scanner)).package.database
    original = database.scan
    calls = []

    def record(data):
        calls.append(data)
        return original(data)

    monkeypatch.setattr(database, 'scan', record)
    try:
        assert [scanner.scan(text) for text in texts] == expected
        assert len(calls) >= len(texts)
    finally:
        stop_managers()


def test_changed_sdk_rules_are_checked_without_package_refresh(tmp_path, monkeypatch, library):
    from agent_moss.agents.base import AgentExtensions
    from agent_moss.profiles.base import CommandPattern

    def rule(pattern, reason):
        return CommandPattern(pattern=pattern, risk_level='high',
                              risk_type='script_execution', reason=reason)

    a, b, c = rule('uniqueAA', 'first'), rule('uniqueBB', 'second'), rule(r'xy(z)\1', 'complex')
    old = CommandPatternScanner(LinuxProfile(), agent_ext=AgentExtensions(
        agent_id='test', extra_command_patterns=[a, b]))
    entry = tmp_path / 'pkg'
    build_package(specs(old), entry, library_path=library, backend='hyperscan')
    manager = activate(entry, library, monkeypatch)
    identity = manager.status()['active_package']
    try:
        # SDK extensions are compiled on scanner construction. Recreate using
        # the public constructor, as SDK callers do after configuration changes.
        for rules, reasons in [([b, a], 'second; first'), ([a, c], 'first; complex'),
                               ([c], 'complex'), ([a, a, c], 'first; first; complex')]:
            scanner = CommandPatternScanner(LinuxProfile(), agent_ext=AgentExtensions(
                agent_id='test', extra_command_patterns=rules))
            text = 'uniqueAA uniqueBB xyzz'
            monkeypatch.setenv('AGENT_MOSS_ACCEL', '0')
            expected = scanner.scan(text)
            assert expected.reason == reasons
            monkeypatch.setenv('AGENT_MOSS_ACCEL', '1')
            assert scanner.scan(text) == expected
            assert manager.status()['active_package'] == identity
    finally:
        stop_managers()


@pytest.mark.parametrize('rejections,success', [(15, True), (16, False)])
def test_compile_attempt_boundary_preserves_old_entry(tmp_path, monkeypatch, library, rejections, success):
    entry = tmp_path / 'pkg'
    build_package([], entry)
    previous = entry.resolve()
    original = NativeLibrary.compile
    calls = []

    def reject(self, expressions):
        calls.append(tuple(expressions))
        if len(calls) <= rejections:
            raise NativeCompileError('unsupported pattern', stage='compile', status=-4, expression_index=0)
        return original(self, expressions)

    monkeypatch.setattr(NativeLibrary, 'compile', reject)
    rules = tuple(RuleSpec(f'pattern{i:02}', 0) for i in range(17))
    if success:
        report = build_package(rules, entry, library_path=library, backend='hyperscan')
        assert report['rules_prefilter'] == 2
        assert load_package(entry, library, backend='hyperscan').bind(rules).candidates('pattern16') == {16}
    else:
        with pytest.raises(PackageError, match='attempt budget'):
            build_package(rules, entry, library_path=library, backend='hyperscan')
        assert entry.resolve() == previous
    assert len(calls) == 16
    assert all(len(after) == len(before) - 1 for before, after in zip(calls, calls[1:]))


@pytest.mark.parametrize('field,value', [
    ('expression_id', -1), ('expression_id', True), ('expression_id', 999),
    ('id', 1), ('id', False), ('source', '.*'), ('native_flags', 1),
    ('backend', 'ultrascan'), ('architecture', 'aarch64'), ('version_numeric', '0.0.0'),
    ('expression_count', 2), ('mode', 2), ('database_sha256', '0' * 64),
    ('report_sha256', '0' * 64), ('schema_version', True),
])
def test_corrupt_metadata_cannot_be_loaded(tmp_path, library, field, value):
    entry = tmp_path / 'pkg'
    build_package([RuleSpec('abc', 0)], entry, library_path=library, backend='hyperscan')
    path = entry.resolve() / 'metadata.json'
    data = json.loads(path.read_text())
    if field == 'expression_id':
        data['rules'][0][field] = value
    elif field in ('id', 'source'):
        data['expressions'][0][field] = value
    elif field == 'native_flags':
        data['expressions'][0]['flags'] = value
    elif field.endswith('_sha256'):
        data[field.split('_')[0]]['sha256'] = value
    elif field == 'schema_version':
        data[field] = value
    else:
        data['database'][field] = value
    path.write_text(json.dumps(data))
    # Keep the checksum valid so these cases still exercise schema validation.
    (entry / 'metadata.sha256').write_text(hashlib.sha256(path.read_bytes()).hexdigest() + '\n')
    with pytest.raises(PackageError):
        load_package(entry, library, backend='hyperscan')


def test_reader_prevents_overwrite_until_native_load_finishes(tmp_path, library):
    entry = tmp_path / 'pkg'
    rules = (RuleSpec('abc', 0),)
    build_package(rules, entry, library_path=library, backend='hyperscan')
    delayed = entry.resolve()
    entered, release = threading.Event(), threading.Event()

    def loader(path, lib, *, backend):
        package = load_package(path, lib, backend=backend)
        if path == delayed:
            entered.set()
            assert release.wait(10)
        return package

    manager = PackageManager(entry, library, backend='hyperscan', loader=loader, poll_interval=.005)
    manager.start()
    try:
        assert entered.wait(10)
        assert manager.bind(rules) is None  # No blocking read on first request.
        from agent_moss.engine.prefilter_storage import PackageBusy
        with pytest.raises(PackageBusy):
            build_package([RuleSpec('def', 0)], entry, library_path=library, backend='hyperscan')
        release.set()
        wait_for(lambda: manager.status()['active_package'])
        assert manager.bind(rules).candidates('abc') == {0}
        build_when_idle([RuleSpec('def', 0)], entry, library_path=library, backend='hyperscan')
        wait_for(lambda: manager.status()['epoch'] == 2)
        assert manager.bind(rules).covered == frozenset()
    finally:
        release.set()
        manager.stop()


def test_concurrent_scans_continuous_replacement_and_resource_release(tmp_path, library):
    entry = tmp_path / 'pkg'
    rules = (RuleSpec('abc', 0), RuleSpec('def', 0))
    build_package(rules, entry, library_path=library, backend='hyperscan')
    manager = PackageManager(entry, library, backend='hyperscan', poll_interval=.005)
    manager.start()
    try:
        wait_for(lambda: manager.status()['active_package'])
        held = manager.bind(rules)
        old_db = weakref.ref(held.package.database)

        def scan():
            for _ in range(100):
                bound = manager.bind(rules)
                assert bound.candidates('abc def') == set(bound.covered)
                assert bound.candidates('absent') == set()

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            futures = [pool.submit(scan) for _ in range(6)]
            for index in range(8):
                before = manager.status()['epoch']
                from agent_moss.engine.prefilter_storage import PackageBusy
                def publish():
                    try:
                        build_package(rules[:1] if index % 2 else rules, entry,
                                      library_path=library, backend='hyperscan')
                        return True
                    except PackageBusy:
                        return False
                wait_for(publish)
                wait_for(lambda: manager.status()['epoch'] > before)
                assert held.candidates('abc def') == {0, 1}
            for future in futures:
                future.result(timeout=10)
        assert old_db() is not None
        del held
        gc.collect()
        assert old_db() is None
        bound = manager.bind(rules)
        latest_db = weakref.ref(bound.package.database)
        manager.stop()
        assert bound.candidates('abc') == {0}
        del bound
        gc.collect()
        assert latest_db() is None
        assert manager.status()['cached_bindings'] == 0
    finally:
        manager.stop()


@pytest.mark.skipif(not hasattr(os, 'fork'), reason='requires fork')
def test_fork_discards_inherited_locked_resources_and_reloads(tmp_path, library):
    entry = tmp_path / 'pkg'
    rules = (RuleSpec('abc', 0),)
    build_package(rules, entry, library_path=library, backend='hyperscan')
    manager = PackageManager(entry, library, backend='hyperscan', poll_interval=.005)
    manager.start()
    wait_for(lambda: manager.status()['active_package'])
    inherited = manager.bind(rules)
    read_fd, write_fd = os.pipe()
    # Inherited locks really are held at fork; the child must not acquire them.
    with manager._state.lock, inherited.package.database._lock:
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            try:
                assert manager.bind(rules) is None
                with pytest.raises(NativeScanError, match='fork'):
                    inherited.candidates('abc')
                manager.start()
                wait_for(lambda: manager.status()['active_package'])
                assert manager.bind(rules).candidates('abc') == {0}
                assert manager.status()['pid'] == os.getpid()
                manager.stop()
                os.write(write_fd, b'OK')
            except BaseException as error:
                os.write(write_fd, repr(error).encode())
            finally:
                os._exit(0)
    os.close(write_fd)
    try:
        ready, _, _ = select.select([read_fd], [], [], 15)
        assert ready, 'fork child deadlocked'
        assert os.read(read_fd, 4096) == b'OK'
        assert inherited.candidates('abc') == {0}
    finally:
        os.close(read_fd)
        # Terminate only this test-owned child if it failed to exit.
        waited, _ = os.waitpid(pid, os.WNOHANG)
        if not waited:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
        manager.stop()


def test_sdk_shutdown_stops_shared_monitor_and_allows_later_restart(tmp_path, monkeypatch):
    import agent_moss
    entry = tmp_path / 'pkg'
    build_package([], entry)
    manager = activate(entry, 'missing-unused-library', monkeypatch)
    try:
        agent_moss.shutdown_acceleration()
        assert not manager.status()['running']
        assert manager.status()['active_package'] is None
        agent_moss.shutdown_acceleration()  # idempotent
        manager.start()
        wait_for(lambda: manager.status()['active_package'])
    finally:
        stop_managers()


@pytest.mark.parametrize('status,index,stage', [(-2, 0, 'compile'), (-4, -1, 'compile'),
                                               (-4, None, 'compile'), (-4, 0, 'serialize')])
def test_unlocalizable_native_failures_leave_published_package(tmp_path, monkeypatch, library, status, index, stage):
    entry = tmp_path / 'pkg'
    build_package([], entry)
    previous = entry.resolve()

    def fail(self, expressions):
        raise NativeCompileError('native failure', stage=stage, status=status, expression_index=index)

    monkeypatch.setattr(NativeLibrary, 'compile', fail)
    with pytest.raises(PackageError, match='nonlocal'):
        build_package([RuleSpec('abc', 0)], entry, library_path=library, backend='hyperscan')
    assert entry.resolve() == previous


def test_missing_files_empty_package_and_rebuild(tmp_path, library):
    entry = tmp_path / 'pkg'
    rules = (RuleSpec('abc', 0),)
    build_package(rules, entry, library_path=library, backend='hyperscan')
    first = entry.resolve()
    manager = PackageManager(entry, library, backend='hyperscan', poll_interval=.005, retry_interval=.01)
    manager.start()
    try:
        wait_for(lambda: manager.status()['active_package'])
        (entry / 'database.bin').unlink()
        wait_for(lambda: manager.status()['error'])
        assert manager.bind(rules).candidates('abc') == {0}
        previous = manager.status()['active_package']
        build_when_idle([], entry)
        wait_for(lambda: manager.status()['active_package'] != previous)
        assert manager.bind(rules).covered == frozenset()
        previous = manager.status()['active_package']
        build_when_idle(rules, entry, library_path=library, backend='hyperscan')
        wait_for(lambda: manager.status()['active_package'] != previous)
        assert manager.bind(rules).candidates('abc') == {0}
    finally:
        manager.stop()
