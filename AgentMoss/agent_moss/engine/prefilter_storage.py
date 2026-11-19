"""Single-directory package state, nonblocking file locks and durable writes.

Callers hold one PackageLock across a complete read or write transaction.
Detection requests never enter this module. The directory is deployment-owned.
"""
from contextlib import contextmanager
import errno
import math
import os
from pathlib import Path
import stat
import threading
import uuid

from . import prefilter_manifest as manifest
from .prefilter_fingerprint import fixed_json

PackageError = manifest.PackageError
STATUS_FILE = 'status.json'
LOCK_FILE = '.package.lock'
STATUS_TEMP = '.status.tmp'
MAX_STATUS_BYTES = 64 * 1024
PAYLOAD_FILES = frozenset((manifest.DATABASE_FILE, manifest.METADATA_FILE,
                          manifest.METADATA_CHECKSUM_FILE, manifest.REPORT_FILE))
_fds = set()
_fd_lock = threading.Lock()


class PackageBusy(PackageError):
    """Another background reader or builder currently owns the directory."""


def _after_fork():
    global _fd_lock
    # Close only: LOCK_UN would also release the parent's inherited flock.
    for fd in _fds:
        os.close(fd)
    _fds.clear()
    _fd_lock = threading.Lock()


if hasattr(os, 'register_at_fork'):
    os.register_at_fork(before=_fd_lock.acquire, after_in_parent=_fd_lock.release,
                        after_in_child=_after_fork)


def require_directory(directory):
    directory = Path(directory)
    if not stat.S_ISDIR(directory.lstat().st_mode):
        raise PackageError('package path must be a real directory, not a symlink')
    return directory


def _regular(fd, name):
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise PackageError(f'{name} must be a regular, unshared file')


@contextmanager
def PackageLock(directory, *, exclusive=False, create=False):
    import fcntl
    directory = Path(directory)
    if create:
        directory.mkdir(parents=True, exist_ok=True)
    require_directory(directory)
    flags = os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    flags |= (os.O_RDWR | os.O_CREAT) if create else os.O_RDONLY
    pid = os.getpid()
    with _fd_lock:
        fd = os.open(directory / LOCK_FILE, flags, 0o600)
        _fds.add(fd)
    try:
        _regular(fd, LOCK_FILE)
        try:
            fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                raise PackageBusy('正在生成或加载，请稍后重试') from exc
            raise
        yield directory
    finally:
        if pid == os.getpid():
            with _fd_lock:
                _fds.discard(fd)
                os.close(fd)


def sync_directory(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_file(directory, name, data):
    if name not in PAYLOAD_FILES | {STATUS_TEMP}:
        raise PackageError('unmanaged package file')
    require_directory(directory)
    fd = os.open(Path(directory) / name, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW
                 | os.O_NONBLOCK | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        _regular(stream.fileno(), name)
        os.ftruncate(stream.fileno(), 0)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def remove_file(directory, name):
    if name not in PAYLOAD_FILES | {STATUS_TEMP}:
        raise PackageError('unmanaged package file')
    path = Path(directory) / name
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise PackageError(f'{name} must be a regular, unshared file')
    path.unlink()


def valid_digest(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def validate_identity(value):
    generation = value['generation']
    try:
        valid = type(generation) is str and uuid.UUID(hex=generation).hex == generation
    except (ValueError, AttributeError):
        valid = False
    if not valid:
        raise PackageError('invalid generation')
    if not valid_digest(value['rules_fingerprint']):
        raise PackageError('invalid rules fingerprint')
    if type(value['fingerprint_version']) is not int or value['fingerprint_version'] != 1:
        raise PackageError('invalid fingerprint version')
    if value['source_scope'] is not None and not valid_digest(value['source_scope']):
        raise PackageError('invalid source scope')


def validate_status(value):
    common = {'status_version', 'state', 'generation', 'rules_fingerprint',
              'fingerprint_version', 'source_scope'}
    if type(value) is not dict or type(value.get('state')) is not str:
        raise PackageError('invalid package state')
    kind = value['state']
    extra = {'building': set(), 'ready': {'metadata_sha256'},
             'failed': {'failed_at', 'error_stage', 'error_reason'}}.get(kind)
    if extra is None or set(value) != common | extra:
        raise PackageError('invalid package status fields')
    if type(value['status_version']) is not int or value['status_version'] != 1:
        raise PackageError('invalid status version')
    validate_identity(value)
    if kind == 'ready' and not valid_digest(value['metadata_sha256']):
        raise PackageError('invalid metadata digest in status')
    if kind == 'failed':
        stamp = value['failed_at']
        if type(stamp) not in (int, float) or not math.isfinite(stamp) or stamp < 0:
            raise PackageError('invalid failure timestamp')
        for key, maximum in (('error_stage', 128), ('error_reason', 2048)):
            if type(value[key]) is not str or len(value[key]) > maximum:
                raise PackageError('invalid failure diagnostic')
    return value


def read_status(directory):
    path = Path(directory) / STATUS_FILE
    try:
        raw = manifest.read_bounded(path, MAX_STATUS_BYTES)
    except PackageError as exc:
        if isinstance(exc.__cause__, FileNotFoundError):
            return None
        raise
    return validate_status(manifest.parse_json(raw, STATUS_FILE))


def write_status(directory, value):
    raw = fixed_json(validate_status(value))
    if len(raw) > MAX_STATUS_BYTES:
        raise PackageError('status exceeds byte budget')
    path = Path(directory) / STATUS_FILE
    if os.path.lexists(path) and not stat.S_ISREG(path.lstat().st_mode):
        raise PackageError('status must be a regular file')
    write_file(directory, STATUS_TEMP, raw)
    os.replace(Path(directory) / STATUS_TEMP, path)
    sync_directory(directory)


def check_ready(status, metadata, identity):
    if status is None or status['state'] != 'ready':
        raise PackageError('package is not ready')
    if status['metadata_sha256'] != identity:
        raise PackageError('status metadata digest mismatch')
    for name in ('generation', 'rules_fingerprint', 'fingerprint_version', 'source_scope'):
        if status[name] != metadata[name]:
            raise PackageError(f'status {name} mismatch')
