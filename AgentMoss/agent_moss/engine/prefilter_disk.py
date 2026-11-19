"""Verify a package's on-disk contents while its shared/exclusive lock is held."""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path

from . import prefilter_manifest as manifest
from . import prefilter_storage as storage


@dataclass(frozen=True)
class DiskPackage:
    directory: Path
    identity: str
    metadata: dict
    report: dict
    rules: tuple
    blob: bytes | None


def inspect_locked(directory, *, require_ready=True, allow_legacy=True):
    directory = Path(directory)
    status = storage.read_status(directory)
    if require_ready and status is not None and status['state'] != 'ready':
        raise manifest.PackageError('package is not ready: ' + status['state'])
    raw = manifest.read_metadata(directory)
    metadata = manifest.parse_json(raw, manifest.METADATA_FILE)
    rules = manifest.validate_metadata(metadata)
    identity = hashlib.sha256(raw).hexdigest()
    if metadata['schema_version'] == 4:
        if require_ready:
            storage.check_ready(status, metadata, identity)
    elif not allow_legacy or status is not None:
        raise manifest.PackageError('legacy package requires manual readonly mode')
    report = manifest.parse_json(manifest.read_verified(
        directory, metadata['report'], manifest.MAX_REPORT_BYTES), manifest.REPORT_FILE)
    descriptor = metadata['database']
    blob = None
    if descriptor is not None:
        blob = manifest.read_verified(directory, descriptor, manifest.MAX_DATABASE_BYTES)
    elif os.path.lexists(directory / manifest.DATABASE_FILE):
        raise manifest.PackageError('empty package must not contain a database file')
    return DiskPackage(directory, identity, metadata, report, rules, blob)


@contextmanager
def read_package(entry, *, allow_legacy=True):
    """The lock spans validation AND the consumer's native deserialization."""
    entry = Path(entry)
    if entry.is_symlink() and not allow_legacy:
        raise manifest.PackageError('automatic updates require a real package directory')
    directory = entry.resolve(strict=True)
    if os.path.lexists(directory / storage.LOCK_FILE):
        with storage.PackageLock(directory):
            disk = inspect_locked(directory, allow_legacy=allow_legacy)
            if entry.is_symlink() and disk.metadata['schema_version'] != 3:
                raise manifest.PackageError('new package path must not be a symlink')
            yield disk
    else:
        disk = inspect_locked(directory, allow_legacy=allow_legacy)
        if disk.metadata['schema_version'] != 3:
            raise manifest.PackageError('new package requires a lock file')
        yield disk
