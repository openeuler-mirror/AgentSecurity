"""Build and validate a fixed-directory package outside detection requests."""
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import time
import unicodedata
import uuid
import warnings

from . import prefilter_contract as limits
from . import prefilter_manifest as manifest
from contextlib import nullcontext

from . import prefilter_storage as storage
from .prefilter_fingerprint import rules_fingerprint
from .prefilter import _load_package_locked
from .prefilter_simplify import simplify_rule
from .prefilter_contract import RuleSpec
from .prefilter_manifest import PackageError
from .prefilter_native import NativeCompileError, NativeLibrary

MAX_PROVENANCE_BYTES = 1024 * 1024
# Use the shared wire vocabulary, including historical TEMPLATE on Python
# versions that removed its public alias but still accept the numeric flag.
FLAG_NAMES = tuple(limits.FLAG_VALUES)
_FLAG_VALUES = limits.FLAG_VALUES
FINGERPRINT_FORMAT = 'sha256(compact-json([encode_rule_pattern(pattern),effective_flags]))'


def _source_bytes(value):
    # Measure standard JSON only. Never decode this representation: JSON merges
    # adjacent surrogate escapes and would change an SDK rule's Python str.
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'),
                      allow_nan=False).encode('utf-8', 'backslashreplace')


def _check_input(records):
    """Validate the entire collection and its input budget before any compile."""
    # Files have a separate whole-file cap. Here charge source strings only:
    # compiling may add effective inline/default flags, whose bounded record
    # overhead is already included in the metadata output bound.
    size = 0
    for index, (pattern, flags) in enumerate(records):
        if index >= limits.MAX_RULES:
            raise PackageError('rule count exceeds budget')
        limits.rule_key(pattern, flags)
        size += len(_source_bytes(pattern))
        if size > limits.MAX_SNAPSHOT_BYTES:
            raise PackageError('source snapshot exceeds byte budget')


def _compile_rules(records):
    """Use only public compilation; DEBUG has no matching semantics."""
    result = []
    for index, (pattern, flags) in enumerate(records):
        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always', FutureWarning)
                compiled = re.compile(pattern, flags & ~re.DEBUG)
        except (re.error, ValueError, OverflowError, RecursionError) as exc:
            raise PackageError(f'invalid original regex at rule {index}: {exc}') from exc
        canonical = RuleSpec(pattern, int(compiled.flags) | (flags & re.DEBUG))
        future = any(issubclass(item.category, FutureWarning) for item in caught)
        result.append((canonical, future))
    return result


def read_rules_snapshot(path: Path) -> tuple[RuleSpec, ...]:
    """Read schema_version=1 and full flag names; never append default rules.

    Pattern strings use standard JSON semantics. SDK exporters may use the
    manifest's typed encoding to preserve actual surrogate codepoints exactly.
    """
    data = manifest.read_bounded(Path(path), limits.MAX_SNAPSHOT_BYTES)
    value = manifest.parse_json(data, 'rules snapshot')
    if (set(value) != {'schema_version', 'rules'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or type(value['rules']) is not list):
        raise PackageError('invalid rules snapshot schema')
    if len(value['rules']) > limits.MAX_RULES:
        raise PackageError('rule count exceeds budget')
    records = []
    for record in value['rules']:
        if type(record) is not dict or set(record) != {'pattern', 'flags'}:
            raise PackageError('invalid snapshot rule fields')
        pattern = manifest.decode_rule_pattern(record['pattern'],
                                               max_length=limits.MAX_SNAPSHOT_BYTES)
        names = record['flags']
        if (type(names) is not list or any(type(name) is not str for name in names)
                or len(set(names)) != len(names)
                or any(name not in _FLAG_VALUES and name != 'NOFLAG' for name in names)):
            raise PackageError('invalid snapshot flag names')
        flags = 0
        for name in names:
            flags |= _FLAG_VALUES.get(name, 0)
        records.append((pattern, flags))
    _check_input(records)
    return tuple(rule for rule, _ in _compile_rules(records))


def _fingerprint(rule):
    return hashlib.sha256(manifest.compact_json_bytes([
        manifest.encode_rule_pattern(rule.pattern), rule.flags])).hexdigest()


def rule_fingerprint(rule: RuleSpec) -> str:
    """Stable S-disable identity, independent of ordering and duplicate rules.

    SHA256 of compact UTF-8 JSON [typed-pattern, public effective flags]. For
    ordinary patterns typed-pattern is simply the original string. The helper
    compiles publicly so inline flags agree with those used by build_package.
    """
    if not isinstance(rule, RuleSpec):
        raise TypeError('fingerprint requires RuleSpec')
    records = [(rule.pattern, rule.flags)]
    _check_input(records)
    return _fingerprint(_compile_rules(records)[0][0])


def _short_reason(reason):
    reason = str(reason).encode('utf-8', 'backslashreplace').decode('utf-8')
    while len(manifest.compact_json_bytes(reason)) > manifest.MAX_REASON_BYTES:
        reason = reason[:max(0, len(reason) // 2)]
    return reason


@dataclass
class _Rule:
    spec: RuleSpec
    fingerprint: str
    expression: str | None
    reason: str


def _allocate(compiled, disabled):
    """Assign one generated expression or Python fallback per unique identity."""
    unique = {}
    ordered = []
    sources = set()
    for spec, future in compiled:
        key = (spec.pattern, spec.flags)
        item = unique.get(key)
        if item is None:
            overlong = len(spec.pattern) > limits.MAX_PATTERN_LENGTH
            surrogate = any(0xD800 <= ord(char) <= 0xDFFF for char in spec.pattern)
            fingerprint = '' if surrogate or overlong else _fingerprint(spec)
            if overlong:
                expression, reason = None, 'rule source length budget exceeded'
            elif surrogate:
                expression, reason = None, 'surrogate source'
            elif future:
                expression, reason = None, 'FutureWarning: ambiguous future regex semantics'
            elif fingerprint in disabled:
                expression, reason = None, 'rule explicitly disabled for acceleration'
            else:
                simplified = simplify_rule(spec)
                expression, reason = simplified.expression, simplified.reason
            if expression is not None:
                if expression not in sources and len(sources) >= limits.MAX_EXPRESSIONS:
                    expression, reason = None, 'expression count budget exceeded'
                else:
                    sources.add(expression)
            item = _Rule(spec, fingerprint, expression, _short_reason(reason))
            unique[key] = item
        ordered.append(item)
    return ordered, tuple(unique.values())


def _expressions(unique):
    result = {}
    for item in unique:
        if item.expression is not None and item.expression not in result:
            result[item.expression] = {'id': len(result), 'source': item.expression,
                                       'flags': limits.NATIVE_FLAGS}
    return list(result.values())


def _compile_native(unique, library_path, backend):
    library = None
    attempts = 0
    diagnostics = []
    while True:
        expressions = _expressions(unique)
        if not expressions:
            return expressions, None, None, attempts, diagnostics
        if attempts >= limits.MAX_COMPILE_ATTEMPTS:
            raise PackageError('native compilation attempt budget exhausted')
        if library is None:
            library = NativeLibrary(library_path, backend=backend)
        attempts += 1
        try:
            blob = library.compile([expression['source'] for expression in expressions])
        except NativeCompileError as error:
            index = error.expression_index
            # HS_COMPILER_ERROR (-4) with a valid expression index is local.
            # HS_NOMEM (-2), serialize/bind failures and unknown statuses are not.
            resource_failure = any(word in str(error).lower()
                                   for word in ('memory', 'allocation', 'resource', 'internal error'))
            if (error.stage != 'compile' or error.status != -4 or resource_failure
                    or type(index) is not int or not 0 <= index < len(expressions)):
                raise PackageError(f'nonlocal native compilation failure: {error}') from error
            failed = expressions[index]['source']
            diagnostics.append({'attempt': attempts, 'expression_index': index,
                                'source': failed, 'error': _short_reason(error)})
            for item in unique:
                if item.expression == failed:
                    item.expression = None
                    item.reason = 'native expression compilation failed'
            continue
        if not blob or len(blob) > manifest.MAX_DATABASE_BYTES:
            raise PackageError('native database exceeds byte budget or is empty')
        return expressions, blob, library.info(), attempts, diagnostics


def _descriptor(filename, data):
    return {'file': filename, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def _serialize_bundle(metadata, report, status_bytes=0):
    report.update(package_bytes=0, metadata_bytes=0, report_bytes=0)
    for _ in range(8):
        report_bytes = manifest.compact_json_bytes(report)
        if len(report_bytes) > manifest.MAX_REPORT_BYTES:
            raise PackageError('report exceeds byte budget')
        metadata['report'] = _descriptor(manifest.REPORT_FILE, report_bytes)
        metadata_bytes = manifest.compact_json_bytes(metadata)
        if len(metadata_bytes) > manifest.MAX_METADATA_BYTES:
            raise PackageError('metadata exceeds byte budget')
        sizes = {'metadata_bytes': len(metadata_bytes), 'report_bytes': len(report_bytes),
                 'package_bytes': (len(metadata_bytes) + manifest.METADATA_CHECKSUM_BYTES
                                   + len(report_bytes) + report['database_bytes'] + status_bytes)}
        if all(report[key] == value for key, value in sizes.items()):
            return metadata_bytes, report_bytes
        report.update(sizes)
    raise PackageError('package size accounting did not converge')


def _prepare_bundle(rules, *, library_path, backend, disabled_rules, source, begin):
    started = time.monotonic()
    if source is not None and type(source) is not str:
        raise PackageError('invalid build source')
    if len(manifest.compact_json_bytes({'source': source})) + 512 > MAX_PROVENANCE_BYTES:
        raise PackageError('source provenance exceeds byte budget')
    disabled = set()
    for fingerprint in disabled_rules:
        if (type(fingerprint) is not str or len(fingerprint) != 64
                or any(char not in '0123456789abcdef' for char in fingerprint)):
            raise PackageError('disabled rules require fingerprint strings')
        disabled.add(fingerprint)
        if len(disabled) > limits.MAX_RULES:
            raise PackageError('disabled rule count exceeds budget')
    records = []
    for rule in rules:
        if len(records) >= limits.MAX_RULES:
            raise PackageError('rule count exceeds budget')
        if not isinstance(rule, RuleSpec):
            raise TypeError('build requires RuleSpec records')
        records.append((rule.pattern, rule.flags))
    _check_input(records)
    compiled = _compile_rules(records)
    ordered, unique = _allocate(compiled, disabled)
    if _expressions(unique):
        if not NativeLibrary(library_path, backend=backend).info()['compiler_available']:
            raise PackageError('full native compiler library required')
    identity = begin(tuple(spec for spec, _ in compiled))
    expressions, blob, info, attempts, diagnostics = _compile_native(unique, library_path, backend)
    ids = {expression['source']: expression['id'] for expression in expressions}
    metadata_rules = []
    report_rules = []
    counts = Counter()
    reasons = Counter()
    for index, item in enumerate(ordered):
        category = 'prefilter' if item.expression is not None else 'python'
        counts[category] += 1
        if category == 'python':
            reasons[item.reason] += 1
        if item.reason in ('surrogate source', 'rule source length budget exceeded'):
            report_rules.append({'index': index, 'category': category, 'reason': item.reason})
            continue
        pattern = manifest.encode_rule_pattern(item.spec.pattern)
        metadata_rules.append({'pattern': pattern, 'flags': item.spec.flags,
                               'key': [pattern, item.spec.flags],
                               'expression_id': ids.get(item.expression), 'reason': item.reason})
        report_rules.append({'index': index, 'fingerprint': item.fingerprint,
                             'category': category, 'reason': item.reason})
    report = {'rules_total': len(ordered), 'rules_prefilter': counts['prefilter'],
              'rules_python': counts['python'], 'fallback_reasons': dict(reasons),
              'expressions_total': len(expressions), 'rules': report_rules,
              'fingerprint_format': FINGERPRINT_FORMAT, 'disabled_rules': sorted(disabled),
              'compile_attempts': attempts, 'compile_diagnostics': diagnostics,
              'database_bytes': len(blob) if blob else 0,
              'prepare_seconds': time.monotonic() - started}
    descriptor = _descriptor(manifest.DATABASE_FILE, blob) if blob else None
    if descriptor is not None:
        descriptor.update(mode=limits.NATIVE_MODE, flags=limits.NATIVE_FLAGS,
                          expression_count=len(expressions), cpu='native',
                          **{key: info[key] for key in ('backend', 'architecture', 'version_numeric')})
    metadata = {**manifest.VERSIONS, **identity,
                'guard_ranges': [list(pair) for pair in manifest.GUARD_RANGES],
                'expressions': expressions, 'rules': metadata_rules,
                'database': descriptor,
                'build': {'python': platform.python_version(),
                          'implementation': platform.python_implementation(),
                          'unicode_version': unicodedata.unidata_version,
                          'source': source,
                          'backend_source': info['backend_source'] if info else None,
                          'build_date': info['build_date'] if info else None},
                'report': None}
    ready = dict(status_version=1, state='ready', metadata_sha256='0' * 64,
                 **{key: value for key, value in identity.items() if key != 'input_rule_count'})
    metadata_bytes, report_bytes = _serialize_bundle(metadata, report, len(storage.fixed_json(ready)))
    return report, metadata_bytes, report_bytes, blob


def package_scope(directory, requested=None):
    """Keep independently verified ownership, including after a failed write."""
    scopes = set()
    if requested is not None:
        if not storage.valid_digest(requested):
            raise PackageError('invalid source scope')
        scopes.add(requested)
    try:
        status = storage.read_status(directory)
        if status and status['source_scope'] is not None:
            scopes.add(status['source_scope'])
    except PackageError:
        pass
    try:
        value = manifest.parse_json(manifest.read_metadata(directory), manifest.METADATA_FILE)
        manifest.validate_metadata(value)
        if value.get('source_scope') is not None:
            scopes.add(value['source_scope'])
    except PackageError:
        pass
    if len(scopes) > 1:
        raise PackageError('package source scope conflicts with configured rule sources')
    return next(iter(scopes), None)


def build_package(rules, output: Path, *, library_path=None, backend=None,
                  disabled_rules=(), source=None, source_scope=None,
                  before_commit=None, commit_guard=None, locked=False) -> dict:
    """Persist building, overwrite managed files, trial-load, then persist ready.

    locked is for the automatic builder already holding this directory's
    exclusive lock. before_commit and commit_guard protect rule/lifecycle checks.
    """
    started = time.monotonic()
    entry = Path(os.path.abspath(output))
    guard = nullcontext() if locked else storage.PackageLock(entry, exclusive=True, create=True)
    with guard:
        storage.require_directory(entry)
        scope = package_scope(entry, source_scope)
        status = None
        stage = 'prepare'

        def begin(compiled):
            nonlocal status, stage
            status = dict(status_version=1, state='building', generation=uuid.uuid4().hex,
                          rules_fingerprint=rules_fingerprint(compiled), fingerprint_version=1,
                          source_scope=scope)
            # A stale .status.tmp is never a publishable package.
            storage.remove_file(entry, storage.STATUS_TEMP)
            storage.write_status(entry, status)
            stage = 'compile'
            return dict(generation=status['generation'], rules_fingerprint=status['rules_fingerprint'],
                        fingerprint_version=1, input_rule_count=len(compiled), source_scope=scope)

        try:
            report, metadata_bytes, report_bytes, blob = _prepare_bundle(
                rules, library_path=library_path, backend=backend,
                disabled_rules=disabled_rules, source=source, begin=begin)
            stage = 'write'
            if blob is None:
                storage.remove_file(entry, manifest.DATABASE_FILE)
            else:
                storage.write_file(entry, manifest.DATABASE_FILE, blob)
            storage.write_file(entry, manifest.METADATA_FILE, metadata_bytes)
            identity = hashlib.sha256(metadata_bytes).hexdigest()
            storage.write_file(entry, manifest.METADATA_CHECKSUM_FILE, identity.encode('ascii') + b'\n')
            storage.write_file(entry, manifest.REPORT_FILE, report_bytes)
            storage.sync_directory(entry)
            stage = 'validate'
            package = _load_package_locked(entry, library_path, backend=backend, require_ready=False)
            del package
            stage = 'commit'
            if before_commit is not None and not before_commit():
                raise PackageError('rules changed or builder stopped before commit')
            with (commit_guard() if commit_guard is not None else nullcontext()):
                storage.write_status(entry, dict(status, state='ready', metadata_sha256=identity))
        except Exception as error:
            # If initial building persistence failed, no payload has been touched.
            if status is not None and stage != 'prepare':
                try:
                    storage.write_status(entry, dict(status, state='failed', failed_at=time.time(),
                        error_stage=stage, error_reason=str(error)[:2048]))
                except (OSError, ValueError):
                    pass
            raise
    return dict(report, identity=identity, output=str(entry), version_dir=str(entry),
                generation=status['generation'], rules_fingerprint=status['rules_fingerprint'],
                duration_seconds=time.monotonic() - started)
