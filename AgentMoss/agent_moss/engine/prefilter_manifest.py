"""Versioned package format and bounded runtime validation.

This module validates generated data only; it never parses or compiles source
rules. Builders write metadata.json, metadata.sha256, report.json and optional
database.bin. Checksums detect corruption, not an untrusted publisher.
"""
from dataclasses import dataclass
import base64
import binascii
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType

from . import prefilter_contract as contract

METADATA_FILE = 'metadata.json'
METADATA_CHECKSUM_FILE = 'metadata.sha256'
METADATA_CHECKSUM_BYTES = 65  # Lowercase SHA-256 hex plus one LF.
REPORT_FILE = 'report.json'
DATABASE_FILE = 'database.bin'
# Output repeats rule identities and adds bounded condition trees. It must not
# inherit the 16 MiB source-snapshot cap. Compact generated output fits below
# 240 MiB, including tagged surrogate sources and bounded build provenance.
MAX_METADATA_BYTES = 256 * 1024 * 1024
MAX_REASON_BYTES = 256  # Serialized JSON string bytes, including quotes.
MAX_REPORT_BYTES = contract.MAX_SNAPSHOT_BYTES
MAX_DATABASE_BYTES = 256 * 1024 * 1024
GUARD_RANGES = contract.GUARD_RANGES
VERSIONS = {'schema_version': contract.SCHEMA_VERSION,
            'converter_version': contract.CONVERTER_VERSION,
            'byte_format_version': contract.BYTE_FORMAT_VERSION,
            'guard_version': contract.GUARD_VERSION,
            'strategy_version': contract.STRATEGY_VERSION}
_PATTERN_ENCODING = 'utf8-surrogatepass-base64'
_SURROGATE = re.compile('[\ud800-\udfff]')
_SURROGATE_PAIR = re.compile('[\ud800-\udbff][\udc00-\udfff]')


class PackageError(ValueError):
    """An invalid, incompatible, missing or corrupt prefilter package."""


def _require(ok, message):
    if not ok:
        raise PackageError(message)


def _keys(value, expected, label):
    _require(type(value) is dict and set(value) == set(expected), f'invalid {label} fields')


def _integer(value, lower, upper, label):
    _require(type(value) is int and lower <= value <= upper, f'invalid {label}')


def _string(value, label, *, nullable=False):
    _require((nullable and value is None) or type(value) is str, f'invalid {label}')


def freeze(value):
    if isinstance(value, dict):
        return MappingProxyType({key: freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(freeze(item) for item in value)
    return value


def read_bounded(path: Path, limit: int) -> bytes:
    """Read one regular file through a stable descriptor, with a hard byte cap."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            _require(stat.S_ISREG(info.st_mode), f'{path.name} must be a regular file')
            _require(info.st_size <= limit, f'{path.name} exceeds byte budget')
            data = stream.read(limit + 1)
            _require(len(data) <= limit, f'{path.name} exceeds byte budget')
            return data
    except OSError as exc:
        raise PackageError(f'cannot read {path.name}: {exc}') from exc


def compact_json_bytes(value) -> bytes:
    """Encode package JSON without ASCII expansion or whitespace overhead.

    Rule sources must first pass through encode_rule_pattern. Other values
    with adjacent raw surrogate pairs are rejected: standard JSON would
    silently combine their distinct Python codepoints when decoding.
    """
    text = json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
    _require(_SURROGATE_PAIR.search(text) is None,
             'adjacent surrogate codepoints require typed rule-pattern encoding')
    return text.encode('utf-8', 'backslashreplace')


def read_metadata(directory: Path) -> bytes:
    """Check all metadata bytes before trusting any rule or file descriptor."""
    checksum = read_bounded(directory / METADATA_CHECKSUM_FILE, METADATA_CHECKSUM_BYTES)
    _require(re.fullmatch(rb'[0-9a-f]{64}\n', checksum) is not None,
             'invalid metadata checksum')
    raw = read_bounded(directory / METADATA_FILE, MAX_METADATA_BYTES)
    expected = hashlib.sha256(raw).hexdigest().encode('ascii') + b'\n'
    _require(checksum == expected, 'metadata digest mismatch')
    return raw


def encode_rule_pattern(pattern: str) -> str | dict:
    """Preserve exact Python source identity using a tag only for surrogates."""
    _require(type(pattern) is str, 'invalid rule pattern')
    if _SURROGATE.search(pattern) is None:
        return pattern
    data = base64.b64encode(pattern.encode('utf-8', 'surrogatepass')).decode('ascii')
    return {'encoding': _PATTERN_ENCODING, 'data': data}


def decode_rule_pattern(value, *, max_length=contract.MAX_PATTERN_LENGTH) -> str:
    """Decode only canonical typed pattern fields, never arbitrary JSON data."""
    if type(value) is str:
        _require(len(value) <= max_length and _SURROGATE.search(value) is None,
                 'rule pattern with surrogate codepoints requires typed encoding')
        return value
    _keys(value, {'encoding', 'data'}, 'encoded rule pattern')
    _require(value['encoding'] == _PATTERN_ENCODING, 'unknown rule pattern encoding')
    data = value['data']
    # One Python codepoint needs at most four UTF-8 bytes; cap before decoding.
    maximum = 4 * ((4 * max_length + 2) // 3)
    _require(type(data) is str and len(data) <= maximum, 'encoded rule pattern exceeds byte budget')
    try:
        decoded = base64.b64decode(data, validate=True).decode('utf-8', 'surrogatepass')
    except (ValueError, UnicodeError, binascii.Error) as exc:
        raise PackageError(f'invalid encoded rule pattern: {exc}') from exc
    _require(encode_rule_pattern(decoded) == value, 'noncanonical rule pattern encoding')
    return decoded


def parse_json(data: bytes, label: str):
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            _require(key not in result, f'duplicate key in {label}: {key}')
            result[key] = value
        return result

    def invalid_constant(value):
        raise PackageError(f'invalid JSON constant in {label}: {value}')

    def finite_float(text):
        value = float(text)
        _require(math.isfinite(value), f'nonfinite number in {label}')
        return value

    try:
        value = json.loads(data.decode('utf-8'), object_pairs_hook=object_pairs,
                           parse_constant=invalid_constant, parse_float=finite_float)
        _require(type(value) is dict, f'{label} must be an object')
        return value
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise PackageError(f'invalid {label}: {exc}') from exc


@dataclass(frozen=True)
class PackageRule:
    key: tuple[str, int]
    expression_id: int | None


def _descriptor(value, filename, limit, *, database=False):
    fields = {'file', 'size', 'sha256'}
    if database:
        fields |= {'mode', 'flags', 'expression_count', 'backend', 'architecture', 'version_numeric', 'cpu'}
    _keys(value, fields, filename)
    _require(value['file'] == filename, f'invalid {filename} path')
    _integer(value['size'], 1, limit, f'{filename} size')
    digest = value['sha256']
    _require(type(digest) is str and len(digest) == 64 and all(c in '0123456789abcdef' for c in digest), f'invalid {filename} digest')


def read_verified(directory, descriptor, limit):
    data = read_bounded(directory / descriptor['file'], limit)
    _require(len(data) == descriptor['size'], f"{descriptor['file']} size mismatch")
    _require(hashlib.sha256(data).hexdigest() == descriptor['sha256'], f"{descriptor['file']} digest mismatch")
    return data


def validate_metadata(value):
    """Validate current or readonly legacy metadata and return rule records."""
    fields = set(VERSIONS) | {'guard_ranges', 'expressions', 'rules', 'database', 'build', 'report'}
    schema = value.get('schema_version') if type(value) is dict else None
    _require(type(schema) is int and schema in (3, 4), 'invalid schema_version')
    if schema == 4:
        fields |= {'generation', 'rules_fingerprint', 'fingerprint_version', 'input_rule_count', 'source_scope'}
    _keys(value, fields, 'metadata')
    for name, expected in VERSIONS.items():
        if name != 'schema_version':
            _integer(value[name], expected, expected, name)
    if schema == 4:
        from .prefilter_storage import validate_identity
        validate_identity(value)
        _integer(value['input_rule_count'], 0, contract.MAX_RULES, 'input rule count')
    ranges = value['guard_ranges']
    _require(type(ranges) is list and all(type(pair) is list and len(pair) == 2
             and all(type(number) is int for number in pair) for pair in ranges)
             and tuple(map(tuple, ranges)) == GUARD_RANGES, 'unknown guard ranges')

    expressions = value['expressions']
    records = value['rules']
    _require(type(expressions) is list and len(expressions) <= contract.MAX_EXPRESSIONS,
             'expression count exceeds budget')
    _require(type(records) is list and len(records) <= contract.MAX_RULES,
             'rule count exceeds budget')
    unique_sources = set()
    for index, expression in enumerate(expressions):
        _keys(expression, {'id', 'source', 'flags'}, 'expression')
        _integer(expression['id'], index, index, 'expression id')
        _integer(expression['flags'], contract.NATIVE_FLAGS, contract.NATIVE_FLAGS, 'native flags')
        source = expression['source']
        _require(contract.validate_generated_expression(source), 'invalid generated byte expression')
        _require(source not in unique_sources, 'duplicate generated expression')
        unique_sources.add(source)

    used = set()
    identities = {}
    result = []
    for record in records:
        _keys(record, {'pattern', 'flags', 'key', 'expression_id', 'reason'}, 'rule')
        try:
            pattern = decode_rule_pattern(record['pattern'])
            key = contract.rule_key(pattern, record['flags'])
        except (TypeError, ValueError) as error:
            raise PackageError(f'invalid rule identity: {error}') from error
        _require(not any(0xD800 <= ord(char) <= 0xDFFF for char in pattern),
                 'surrogate rule must not be packaged')
        _require(record['flags'] == key[1], 'rule flags must be canonical effective flags')
        _require(type(record['key']) is list and len(record['key']) == 2
                 and type(record['key'][1]) is int
                 and record['key'] == [record['pattern'], key[1]], 'rule key mismatch')
        _string(record['reason'], 'rule reason', nullable=True)
        _require(len(compact_json_bytes(record['reason'])) <= MAX_REASON_BYTES,
                 'rule reason exceeds byte budget')
        expression_id = record['expression_id']
        if expression_id is not None:
            _integer(expression_id, 0, len(expressions) - 1, 'rule expression id')
            used.add(expression_id)
        item = PackageRule(key, expression_id)
        _require(key not in identities or identities[key] == item,
                 'duplicate rule identity has conflicting expressions')
        identities[key] = item
        result.append(item)
    _require(used == set(range(len(expressions))), 'unused generated expression')

    covered = bool(used)
    descriptor = value['database']
    if covered:
        _descriptor(descriptor, DATABASE_FILE, MAX_DATABASE_BYTES, database=True)
        _integer(descriptor['mode'], contract.NATIVE_MODE, contract.NATIVE_MODE, 'native mode')
        _integer(descriptor['flags'], contract.NATIVE_FLAGS, contract.NATIVE_FLAGS, 'database flags')
        _integer(descriptor['expression_count'], len(expressions), len(expressions),
                 'database expression count')
        _require(descriptor['backend'] in ('hyperscan', 'ultrascan'), 'unknown backend')
        _require(descriptor['architecture'] in ('x86_64', 'aarch64'), 'unknown architecture')
        version = descriptor['version_numeric']
        _require(type(version) is str and len(version.split('.')) == 3
                 and all(part.isascii() and part.isdigit() for part in version.split('.')),
                 'invalid native numeric version')
        _string(descriptor['cpu'], 'cpu')
    else:
        _require(descriptor is None, 'empty package must have no database descriptor')
    build = value['build']
    _keys(build, {'python', 'implementation', 'unicode_version', 'source',
                  'backend_source', 'build_date'}, 'build')
    for field in ('python', 'implementation', 'unicode_version'):
        _string(build[field], field)
    for field in ('source', 'build_date'):
        _string(build[field], field, nullable=True)
    _require(build['backend_source'] in ('config', 'platform_default', None),
             'invalid backend provenance')
    _require(not covered or build['backend_source'] is not None,
             'missing backend provenance')
    _descriptor(value['report'], REPORT_FILE, MAX_REPORT_BYTES)
    return tuple(result)
