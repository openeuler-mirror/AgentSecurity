"""Process-local background loading; request bindings never touch the filesystem.

Call start() from SDK first use or worker startup. Hold bind()'s result only for
one scan: that strong reference keeps its package alive across a replacement.
"""
from collections import OrderedDict
from dataclasses import dataclass
import itertools
import logging
import os
from pathlib import Path
import platform
import threading
import time
from typing import TYPE_CHECKING

from .prefilter_contract import MAX_RULES, RuleSpec, rule_key

if TYPE_CHECKING:
    from .prefilter import Package, Prefilter

_LOG = logging.getLogger(__name__)
_INSTANCES = itertools.count(1)
_CACHE_LIMIT = 64


def _load_package(version_dir, library_path, *, backend):
    # No loader/native import is required to inspect configuration or status.
    from .prefilter import load_package
    return load_package(version_dir, library_path, backend=backend)


@dataclass(frozen=True)
class _Config:
    entry: str
    library_path: str
    backend: str | None
    auto_build: bool


def _configuration(entry, library_path, backend, auto_build=None):
    # Normalize lexically only: resolving the entry here would freeze its symlink
    # target and introduce request-path disk I/O. Preserve bare loader names.
    entry = os.path.abspath(os.fspath(entry))
    library_path = library_path or os.environ.get('AGENT_MOSS_ACCEL_LIB') or 'libhs.so.5'
    library_path = os.fspath(library_path)
    if os.path.dirname(library_path):
        library_path = os.path.abspath(library_path)
    backend = backend if backend is not None else os.environ.get('AGENT_MOSS_ACCEL_BACKEND')
    if backend is None:
        backend = {'x86_64': 'hyperscan', 'amd64': 'hyperscan',
                   'aarch64': 'ultrascan', 'arm64': 'ultrascan'}.get(platform.machine().lower())
    if auto_build is None:
        auto_build = os.environ.get('AGENT_MOSS_ACCEL_AUTO_BUILD', '1') != '0'
    return _Config(entry, library_path, backend, auto_build)


@dataclass(frozen=True)
class _Snapshot:
    pid: int
    instance: str
    config: _Config
    epoch: int
    target: str
    package: 'Package'


class _ManagerState:
    def __init__(self):
        self.pid = os.getpid()
        self.instance = f'{self.pid}:{next(_INSTANCES)}'
        self.lock = threading.Lock()
        self.commit_lock = threading.Lock()
        self.builder = None
        self.build_error = None
        self.build_logged_at = float("-inf")
        self.wake = threading.Event()
        self.thread = None
        self.running = False
        self.lifecycle = 0
        self.snapshot = None
        self.retired = None
        self.epoch = 0
        self.bindings = OrderedDict()
        self.observed_target = None
        self.checked_at = None
        self.loading = False
        self.error = None
        self.failed_target = None
        self.retry_at = 0.0
        self.log_key = None
        self.logged_at = float('-inf')


class PackageManager:
    """One serial loader for a fixed entry/library/backend configuration.

    loader/poll_interval/retry_interval allow deterministic integration with
    other storage or scheduling environments. Defaults implement 1s/30s policy.
    A start while stopped native loading or cleanup is still running is a no-op;
    a later start can restart the manager once that worker exits, never a second
    loader.
    """
    def __init__(self, entry: str, library_path: str | None = None, *,
                 backend: str | None = None, loader=None, poll_interval=1.0,
                 retry_interval=30.0, auto_build=False, rule_source=None):
        self._config = _configuration(entry, library_path, backend, auto_build)
        self._rule_source = rule_source
        self._loader = loader if loader is not None else _load_package
        self._poll_interval = max(.001, float(poll_interval))
        self._retry_interval = max(0.0, float(retry_interval))
        self._state = _ManagerState()

    def _process_state(self):
        # Mandatory before every inherited lock/cache access, including status,
        # stop and start. Native owners independently reject inherited resources.
        if self._state.pid != os.getpid():
            self._state = _ManagerState()
        return self._state

    def start(self):
        state = self._process_state()
        with state.lock:
            if state.thread is not None:
                return
            state.lifecycle += 1
            state.running = True
            state.wake = threading.Event()
            state.thread = threading.Thread(
                target=self._run, args=(state, state.lifecycle),
                name=f'agent-moss-prefilter-{state.instance}', daemon=True)
            try:
                state.thread.start()
            except Exception:
                state.running = False
                state.thread = None
                raise

    def bind(self, rules: tuple[RuleSpec, ...]) -> 'Prefilter | None':
        """Compatibility entry point for callers with validated RuleSpec records."""
        # rule_key accepts str subclasses; retain their underlying text without
        # invoking a user-defined __str__ or letting custom equality into the cache.
        identities = tuple((str.__str__(pattern), flags) for pattern, flags in
                           (rule_key(rule.pattern, rule.flags) for rule in rules))
        return self.bind_patterns(identities)

    def bind_patterns(self, identities: tuple[tuple[str, int], ...]) -> 'Prefilter | None':
        """Bind compiled-pattern identities; fully validate only on a cache miss.

        Exact immutable types are required before looking up the cache: e.g.
        bool/float flags compare equal to ints but must not reuse their entries.
        """
        if type(identities) is not tuple or len(identities) > MAX_RULES:
            raise ValueError('binding requires a bounded immutable rule snapshot')
        for identity in identities:
            if (type(identity) is not tuple or len(identity) != 2
                    or type(identity[0]) is not str or type(identity[1]) is not int):
                raise TypeError('binding identities require exact (str, int) pairs')
        state = self._process_state()
        with state.lock:
            snapshot = state.snapshot
            if snapshot is None:
                return None
            key = (snapshot.epoch, identities)
            bound = state.bindings.get(key)
            if bound is not None:
                state.bindings.move_to_end(key)
                return bound
        rules = tuple(RuleSpec(pattern, flags) for pattern, flags in identities)
        bound = snapshot.package.bind(rules)
        with state.lock:
            # Publication and cache insertion share this lock; an old in-flight
            # bind remains valid for its caller but cannot repopulate the cache.
            if state.snapshot is snapshot:
                existing = state.bindings.get(key)
                if existing is not None:
                    state.bindings.move_to_end(key)
                    return existing
                state.bindings[key] = bound
                if len(state.bindings) > _CACHE_LIMIT:
                    state.bindings.popitem(last=False)
        return bound

    def status(self) -> dict:
        state = self._process_state()
        with state.lock:
            snapshot = state.snapshot
            return {
                'pid': state.pid, 'instance': state.instance,
                'entry': self._config.entry,
                'library_path': self._config.library_path, 'backend': self._config.backend,
                'observed_target': state.observed_target,
                'active_target': snapshot.target if snapshot else None,
                'active_package': snapshot.package.identity if snapshot else None,
                'epoch': state.epoch, 'checked_at': state.checked_at,
                'running': state.running, 'loading': state.loading,
                'error': state.error, 'cached_bindings': len(state.bindings),
                'auto_build': self._config.auto_build, 'build_error': state.build_error,
                'active_generation': snapshot.package.metadata.get('generation') if snapshot else None,
            }

    def stop(self, timeout=5.0):
        deadline = time.monotonic() + min(5.0, max(0.0, float(timeout)))
        _join_until(self._request_stop(), deadline)

    def _request_stop(self):
        state = self._process_state()
        # A busy commit gate means final publication already started. Signal
        # shutdown without waiting for its disk flush; the worker keeps its flock.
        acquired = state.commit_lock.acquire(blocking=False)
        try:
            with state.lock:
                state.running = False
                state.lifecycle += 1
                state.wake.set()
                if state.snapshot is not None:
                    state.retired = state.snapshot, state.bindings
                    state.snapshot = None
                    state.bindings = OrderedDict()
                return state.thread
        finally:
            if acquired:
                state.commit_lock.release()

    def _run(self, state, lifecycle):
        try:
            while not state.wake.is_set():
                if self._config.auto_build:
                    self._build_once(state)
                self._check_once(state, lifecycle)
                if state.wake.wait(self._poll_interval):
                    break
        finally:
            with state.lock:
                state.loading = False
                state.running = False
                retired = state.snapshot, state.bindings, state.retired
                state.snapshot = state.retired = None
                state.bindings = OrderedDict()
            try:
                # Only the existing daemon worker drops manager-owned packages.
                # Native free may block, so keep both it and logging outside the
                # state lock. In-flight scans retain their own strong references.
                del retired
            finally:
                with state.lock:
                    # A new worker cannot start until native cleanup finishes.
                    state.thread = None

    def _build_once(self, state):
        try:
            if state.builder is None:
                from .prefilter_autobuild import AutoBuilder
                state.builder = AutoBuilder(self._config.entry, self._config.library_path,
                                            self._config.backend, source=self._rule_source)
            state.builder.check(state.wake, state.commit_lock)
            error = state.builder.error
        except Exception as exc:
            error = f'{type(exc).__name__}: {exc}'
        with state.lock:
            changed = error != state.build_error
            state.build_error = error
        now = time.monotonic()
        if error and (changed or now - state.build_logged_at >= self._retry_interval):
            state.build_logged_at = now
            try:
                _LOG.warning('prefilter build deferred pid=%s entry=%s: %s',
                             state.pid, self._config.entry, error)
            except Exception:
                pass

    def _check_once(self, state, lifecycle):
        from .prefilter_storage import PackageBusy
        target = attempt_key = self._config.entry
        logs = []
        try:
            from .prefilter_disk import read_package
            from .prefilter import _load_disk
            # Verify the bytes even if the same generation is already active.
            # The shared file lock stays held through native deserialization.
            with read_package(self._config.entry, allow_legacy=not self._config.auto_build) as disk:
                target = str(disk.directory)
                attempt_key = disk.identity
                now = time.monotonic()
                with state.lock:
                    if not state.running or lifecycle != state.lifecycle:
                        return
                    state.checked_at = time.time()
                    state.observed_target = target
                    if state.snapshot is not None and state.snapshot.package.identity == disk.identity:
                        self._recovered(state, logs)
                        return
                    if state.failed_target == attempt_key and now < state.retry_at:
                        return
                    state.loading = True
                package = (_load_disk(disk, self._config.library_path, backend=self._config.backend)
                           if self._loader is _load_package else
                           self._loader(disk.directory, self._config.library_path, backend=self._config.backend))
                with state.lock:
                    state.loading = False
                    if not state.running or lifecycle != state.lifecycle:
                        return
                    retired = state.snapshot, state.bindings
                    state.epoch += 1
                    state.snapshot = _Snapshot(state.pid, state.instance, self._config,
                                               state.epoch, target, package)
                    state.bindings = OrderedDict()
                    self._recovered(state, logs)
                    logs.append(('info',
                        'prefilter activated pid=%s instance=%s entry=%s target=%s package=%s epoch=%s',
                        (state.pid, state.instance, self._config.entry, target,
                         package.identity, state.epoch)))
            del retired
        except PackageBusy:
            return
        except Exception as exc:
            message = f'{type(exc).__name__}: {exc}'
            with state.lock:
                state.loading = False
                if not state.running or lifecycle != state.lifecycle:
                    return
                now = time.monotonic()
                state.checked_at = time.time()
                state.observed_target = target
                state.error = message
                state.failed_target = attempt_key
                state.retry_at = now + self._retry_interval
                key = (target, message)
                if key != state.log_key or now - state.logged_at >= self._retry_interval:
                    logs.append(('warning',
                        'prefilter load failed pid=%s instance=%s entry=%s target=%s active_package=%s epoch=%s: %s',
                        (state.pid, state.instance, self._config.entry, target,
                         state.snapshot.package.identity if state.snapshot else None,
                         state.epoch, message)))
                    state.log_key, state.logged_at = key, now
        finally:
            # File/network handlers may block or raise. Never run them with the
            # request state lock held or turn an observability fault into a load
            # failure after a successful publication.
            for level, message, args in logs:
                try:
                    getattr(_LOG, level)(message, *args)
                except Exception:
                    pass

    def _recovered(self, state, logs):
        if state.error is not None:
            logs.append(('info',
                'prefilter recovered pid=%s instance=%s entry=%s target=%s epoch=%s',
                (state.pid, state.instance, self._config.entry,
                 state.observed_target, state.epoch)))
        state.error = state.failed_target = state.log_key = None
        state.retry_at = 0.0


class _Registry:
    def __init__(self):
        self.pid = os.getpid()
        self.lock = threading.Lock()
        self.managers = {}


_registry = _Registry()


def _reset_registry():
    global _registry
    inherited = _registry
    fresh = _Registry()
    # Existing SDK objects may still hold a manager. Preserve that identity in
    # the child registry, while rebuilding every process-owned field before use.
    for config, manager in inherited.managers.items():
        manager._process_state()
        fresh.managers[config] = manager
    _registry = fresh


def _process_registry():
    if _registry.pid != os.getpid():
        _reset_registry()
    return _registry


if hasattr(os, 'register_at_fork'):
    os.register_at_fork(after_in_child=_reset_registry)


def get_manager(entry: str | None = None, library_path: str | None = None, *,
                backend: str | None = None) -> PackageManager | None:
    if os.environ.get('AGENT_MOSS_ACCEL', '0') != '1':
        return None
    entry = entry if entry is not None else os.environ.get('AGENT_MOSS_ACCEL_DB')
    if not entry:
        return None
    config = _configuration(entry, library_path, backend)
    registry = _process_registry()
    with registry.lock:
        manager = registry.managers.get(config)
        if manager is None:
            manager = PackageManager(config.entry, config.library_path, backend=config.backend,
                                     auto_build=config.auto_build)
            registry.managers[config] = manager
        return manager


def start_configured_manager() -> PackageManager | None:
    manager = get_manager()
    if manager is not None:
        manager.start()
    return manager


def _join_until(thread, deadline):
    if thread is not None and thread is not threading.current_thread():
        thread.join(max(0.0, deadline - time.monotonic()))


def stop_managers():
    deadline = time.monotonic() + 5.0
    registry = _process_registry()
    with registry.lock:
        managers = tuple(registry.managers.values())
    # Signal every manager before waiting on any native load or release.
    threads = [manager._request_stop() for manager in managers]
    for thread in threads:
        _join_until(thread, deadline)
