"""Serial background rebuilds; never called by a detection request."""
from contextlib import contextmanager
import logging
from pathlib import Path
import time

from .prefilter_build import build_package, package_scope
from .prefilter_disk import inspect_locked
from .prefilter_manifest import PackageError
from .prefilter_storage import PackageBusy, PackageLock, read_status

_LOG = logging.getLogger(__name__)


class AutoBuilder:
    def __init__(self, entry, library_path, backend, *, source=None, clock=None):
        self.entry = Path(entry)
        self.library_path = library_path
        self.backend = backend
        if source is None:
            from .prefilter_rule_source import RuleSource
            source = RuleSource()
        self.source = source
        self.clock = clock or time.monotonic
        self.observed = None
        self.stable_since = 0.0
        self.failed = None
        self.retry_at = 0.0
        self.validated = None
        self.error = None

    def _stable(self, snapshot):
        identity = (snapshot.source_scope, snapshot.fingerprint)
        now = self.clock()
        if identity != self.observed:
            self.observed, self.stable_since = identity, now
            return False
        return now - self.stable_since >= 1.0

    def _usable_locked(self, snapshot):
        try:
            disk = inspect_locked(self.entry, allow_legacy=False)
        except (OSError, PackageError):
            return False
        if disk.metadata['rules_fingerprint'] != snapshot.fingerprint:
            return False
        descriptor = disk.metadata['database']
        if descriptor is not None and self.validated != disk.identity:
            from .prefilter_native import NativeLibrary
            info = NativeLibrary(self.library_path, backend=self.backend).info()
            if any(descriptor[key] != info[key] for key in
                   ('backend', 'architecture', 'version_numeric')):
                return False
        # Deserialization belongs to the loader. A local scratch allocation or
        # environment failure must not overwrite a complete shared ready package.
        self.validated = disk.identity
        return True

    def check(self, stop_event, commit_lock):
        if stop_event.is_set():
            return None
        snapshot = self.source.snapshot()
        stable = self._stable(snapshot)
        if not snapshot.eligible:
            self.error = 'rule source generation changed or startup snapshot is untrusted; restart required to build'
            return None
        if not stable or (self.failed == self.observed and self.clock() < self.retry_at):
            return None
        try:
            # The first check is readonly, including in runtime-only deployments.
            try:
                with PackageLock(self.entry):
                    package_scope(self.entry, snapshot.source_scope)
                    if self._usable_locked(snapshot):
                        self.error = None
                        return None
            except FileNotFoundError:
                pass
            with PackageLock(self.entry, exclusive=True, create=True):
                if stop_event.is_set():
                    return None
                current = self.source.snapshot()
                if not current.eligible or not self._stable(current):
                    return None
                # Scope and retry checks are repeated after winning the lock.
                package_scope(self.entry, current.source_scope)
                try:
                    status = read_status(self.entry)
                except PackageError:
                    status = None
                if (status is not None and status['state'] == 'failed'
                        and status['rules_fingerprint'] == current.fingerprint
                        and 0 <= time.time() - status['failed_at'] < 30):
                    return None
                if self._usable_locked(current):
                    self.error = None
                    return None

                def before_commit():
                    if stop_event.is_set():
                        return False
                    latest = self.source.snapshot()
                    return (latest.eligible and latest.fingerprint == current.fingerprint
                            and latest.source_scope == current.source_scope)

                @contextmanager
                def commit_guard():
                    with commit_lock:
                        if stop_event.is_set():
                            raise PackageError('builder stopped before commit')
                        yield

                result = build_package(current.rules, self.entry,
                    library_path=self.library_path, backend=self.backend,
                    source='effective command rules', source_scope=current.source_scope,
                    locked=True, before_commit=before_commit, commit_guard=commit_guard)
                self.validated = result['identity']
                self.failed = self.error = None
                try:
                    _LOG.info('prefilter generated generation=%s rules=%s directory=%s',
                              result['generation'], current.fingerprint, self.entry)
                except Exception:
                    pass
                return result
        except PackageBusy:
            return None
        except Exception as error:
            self.failed, self.retry_at = self.observed, self.clock() + 30.0
            self.error = str(error)
            raise
