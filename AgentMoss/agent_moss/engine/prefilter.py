"""Read immutable prefilter packages and bind them to current business rules."""
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from . import prefilter_contract as contract
from . import prefilter_manifest as manifest
from .prefilter_manifest import PackageError, PackageRule
from .prefilter_native import NativeDatabase, NativeLibrary, NativeError, NativeScanError


@dataclass(frozen=True)
class Package:
    identity: str
    version_dir: Path
    metadata: Mapping
    report: Mapping
    database: NativeDatabase | None
    _rules: tuple[PackageRule, ...] = field(repr=False)
    _by_key: Mapping = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        object.__setattr__(self, '_by_key', MappingProxyType({
            rule.key: rule for rule in self._rules if rule.expression_id is not None}))

    def bind(self, rules: tuple[contract.RuleSpec, ...]) -> 'Prefilter':
        if type(rules) is not tuple or len(rules) > contract.MAX_RULES:
            raise PackageError('binding requires a bounded immutable rule snapshot')
        bound = []
        for index, rule in enumerate(rules):
            if not isinstance(rule, contract.RuleSpec):
                raise PackageError('binding requires RuleSpec records')
            packaged = self._by_key.get(contract.rule_key(rule.pattern, rule.flags))
            if packaged is not None:
                bound.append((index, packaged))
        return Prefilter(self, tuple(bound), frozenset(index for index, _ in bound))


@dataclass(frozen=True)
class Prefilter:
    package: Package
    _rules: tuple[tuple[int, PackageRule], ...] = field(repr=False)
    covered: frozenset[int]

    def candidates(self, text: str) -> set[int]:
        if not isinstance(text, str):
            raise TypeError('prefilter input must be text')
        if not self.covered:
            return set()
        if contract.guard_text(text):
            return set(self.covered)
        if self.package.database is None:
            raise PackageError('covered rules require a native database')
        hits = self.package.database.scan(text.encode('utf-8'))
        count = len(self.package.metadata['expressions'])
        if not isinstance(hits, set) or any(type(index) is not int or not 0 <= index < count for index in hits):
            raise NativeScanError('invalid expression IDs returned by native scan')
        return {index for index, rule in self._rules if rule.expression_id in hits}


def load_package(version_dir: Path, library_path: str | None = None, *,
                 backend: str | None = None, allow_legacy=True) -> Package:
    from .prefilter_disk import read_package
    try:
        with read_package(version_dir, allow_legacy=allow_legacy) as disk:
            return _load_disk(disk, library_path, backend=backend)
    except OSError as exc:
        raise PackageError(f'cannot load prefilter package: {exc}') from exc


def _load_package_locked(directory, library_path=None, *, backend=None, require_ready=True):
    from .prefilter_disk import inspect_locked
    return _load_disk(inspect_locked(directory, require_ready=require_ready, allow_legacy=False),
                      library_path, backend=backend)


def _load_disk(disk, library_path, *, backend):
    database = None
    try:
        metadata = disk.metadata
        descriptor = metadata['database']
        if descriptor is not None:
            from .prefilter_compat import python_compatibility
            compatibility = python_compatibility()
            if not compatibility.supported:
                raise PackageError('Python runtime failed the prefilter capability check: ' + compatibility.reason)
            library = NativeLibrary(library_path, backend=backend)
            info = library.info()
            for key in ('backend', 'architecture', 'version_numeric'):
                if descriptor[key] != info[key]:
                    raise PackageError(f'native {key} mismatch: package={descriptor[key]!r}, runtime={info[key]!r}')
            database = library.load(disk.blob, descriptor['expression_count'])
        return Package(disk.identity, disk.directory, manifest.freeze(metadata),
                       manifest.freeze(disk.report), database, disk.rules)
    except (OSError, NativeError, TypeError, ValueError, RecursionError) as exc:
        if database is not None:
            database.close()
        if isinstance(exc, PackageError):
            raise
        raise PackageError(f'cannot load prefilter package: {exc}') from exc
