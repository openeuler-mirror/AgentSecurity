"""Readonly snapshots of the same command rules used by business scanners."""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading

from .prefilter_contract import MAX_SNAPSHOT_BYTES, RuleSpec
from .prefilter_fingerprint import canonical_rules, fixed_json, rules_fingerprint
from .prefilter_manifest import PackageError

_startup = None
_startup_files = {}
_startup_lock = threading.RLock()


def _after_fork():
    global _startup_lock
    _startup_lock = threading.RLock()


if hasattr(os, 'register_at_fork'):
    os.register_at_fork(after_in_child=_after_fork)


def _layout():
    from ..infra.paths import asset_dir
    from ..infra.rules_mode import get_rules_mode
    from ..infra.runtime_config import get_runtime_config_path
    from ..rules_loader import rules_dirs
    mode = get_rules_mode()
    roots = {name: Path(os.path.abspath(asset_dir(name))) for name in ('rules', 'agents', 'scenarios')}
    directories = tuple(Path(os.path.abspath(p)) for p in rules_dirs())
    runtime = Path(os.path.abspath(get_runtime_config_path())) if mode == 'hot' else None
    scope = hashlib.sha256(fixed_json({
        'mode': mode, 'assets': {k: str(v) for k, v in roots.items()},
        'directories': list(map(str, directories)), 'runtime': str(runtime) if runtime else None,
        'scenario': os.environ.get('AGENT_MOSS_SCENARIO', '')})).hexdigest()
    return mode, roots, directories, runtime, scope


def _children(directory):
    from ..infra.paths import is_safe_id
    try:
        return sorted(p.name for p in directory.iterdir() if p.is_dir() and is_safe_id(p.name))
    except FileNotFoundError:
        return []


def _inventory(*, cold_only=False, validate=True):
    mode, roots, directories, runtime, scope = _layout()
    files = {roots['rules'] / name: 'object' for name in
             ('l1_rules.json', 'l2_rules.json', 'l3_rules.json', 'mc_rules.json')}
    agent_ids = set(_children(roots['agents']))
    scenario_ids = set(_children(roots['scenarios']))
    for directory in directories:
        scenario_ids.update(_children(directory / 'scenarios'))
        if not cold_only or mode != 'hot':
            for name in ('override.json', 'extra.json'):
                files[directory / name] = 'rules'
    for name in agent_ids:
        files[roots['agents'] / name / 'rules.json'] = 'agent'
    for name in scenario_ids:
        files[roots['scenarios'] / name / 'rules.json'] = 'scenario'
        for directory in directories:
            files[directory / 'scenarios' / name / 'rules.json'] = 'scenario'
    if runtime is not None and not cold_only:
        files[runtime] = 'object'
    records = []
    for path, kind in sorted(files.items()):
        try:
            # ConfigMap-style source symlinks are allowed. Package files are not.
            with path.open('rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SNAPSHOT_BYTES:
                    raise PackageError(f'invalid or oversized rule source: {path}')
                raw = stream.read(MAX_SNAPSHOT_BYTES + 1)
                if len(raw) > MAX_SNAPSHOT_BYTES:
                    raise PackageError(f'oversized rule source: {path}')
        except FileNotFoundError:
            if path == roots['rules'] / 'l1_rules.json':
                raise PackageError('missing builtin command rules')
            records.append((str(path), None))
            continue
        if validate:
            _validate_source(raw, kind, path)
        records.append((str(path), hashlib.sha256(raw).hexdigest()))
    generation = hashlib.sha256(fixed_json(records)).hexdigest()
    return scope, generation, agent_ids, scenario_ids, tuple(records)


def _validate_source(raw, kind, path):
    try:
        value = json.loads(raw)
        if type(value) is not dict and not (kind == 'rules' and type(value) is list):
            raise ValueError('expected a rule object or a flat rule list')
        if type(value) is dict:
            name = 'extra_command_patterns' if kind in ('agent', 'scenario') else 'dangerous_commands'
            if name in value:
                entries = value[name]
                if type(entries) is not list or any(type(r) is not dict or
                        type(r.get('pattern')) is not str for r in entries):
                    raise ValueError('invalid command pattern list')
        if kind in ('agent', 'scenario'):
            from ..agents.base import AgentExtensions
            # Reuse business validation, including required IDs and fields.
            AgentExtensions.from_json(path, id_key=kind + '_id')
    except (KeyError, ValueError, TypeError, UnicodeError, RecursionError) as error:
        raise PackageError(f'invalid rule source {path}: {error}') from error


def capture_startup_sources():
    """Called before business source loading, never first recorded by a poll.

    Already-loaded caches without a startup generation cannot publish. Hot
    runtime/override/extra files remain mutable; cached asset profiles do not.
    This function is a constant-time no-op after capture or when disabled.
    """
    global _startup, _startup_files
    if _startup is not None or os.environ.get('AGENT_MOSS_ACCEL') != '1' or os.environ.get('AGENT_MOSS_ACCEL_AUTO_BUILD', '1') == '0':
        return
    with _startup_lock:
        if _startup is not None:
            return
        from .. import rules_loader, agents, scenarios
        try:
            scope, generation, _, _, records = _inventory(cold_only=True, validate=False)
            trusted = not (rules_loader._JSON_CACHE or rules_loader._RULES_CACHE
                           or agents._cache or scenarios._cache)
            _startup_files = dict(records)
            _startup = (scope, generation if trusted else None)
        except Exception:
            # Never alter business rule loading on an acceleration-only failure.
            _startup = (None, None)


def record_startup_read(path, raw):
    """Bind startup eligibility to bytes actually read into a business cache.

    Comparing only disk-before and disk-after misses an A -> B -> A rollback.
    Once any frozen read differs, this process cannot auto-publish until restart.
    """
    global _startup
    if _startup is None or _startup[1] is None:
        return
    name = os.path.abspath(path)
    if name not in _startup_files:
        return
    digest = None if raw is None else hashlib.sha256(raw).hexdigest()
    with _startup_lock:
        if digest != _startup_files[name]:
            _startup = (_startup[0], None)


def record_startup_directory(directory, files):
    """Record absent deployment files too, before a cold directory cache is set."""
    if _startup is None or _startup[1] is None:
        return
    present = {os.path.abspath(path) for path in files}
    for name in ('override.json', 'extra.json'):
        path = Path(directory) / name
        if os.path.abspath(path) not in present:
            record_startup_read(path, None)


@dataclass(frozen=True)
class RuleSnapshot:
    rules: tuple[RuleSpec, ...]
    fingerprint: str
    source_scope: str
    source_generation: str
    eligible: bool


class RuleSource:
    def snapshot(self):
        from .. import profiles, agents, scenarios
        from ..infra import runtime_config as runtime
        before = _inventory()
        records = []
        with runtime.readonly_runtime_snapshot() as config:
            # Preserve the scanner's existing empty-selection fallback.
            for os_name in ('linux', 'windows', 'macos', 'harmony'):
                profile = profiles.get_profile(os_name)
                selected = runtime.get_enabled_l1_command_patterns_or_default(config, os_name)
                patterns = [r['pattern'] for r in selected] if selected else [r.pattern for r in profile.dangerous_commands]
                records.extend(patterns)
            if config.get('layers', {}).get('agent_rules_enabled', True):
                for name in sorted(before[2] | set(config.get('agent_rules', {}))):
                    extension = agents.get_agent_extensions(name)
                    if extension is not None:
                        records.extend(r.pattern for r in extension.extra_command_patterns)
            if config.get('layers', {}).get('scenario_rules_enabled', True):
                for name in sorted(before[3] | set(config.get('scenario_rules', {}))):
                    extension = scenarios.get_scenario_extensions(name)
                    if extension is not None:
                        records.extend(r.pattern for r in extension.extra_command_patterns)
        # Public re.compile captures effective flags, including inline flags.
        try:
            rules = canonical_rules(RuleSpec(p, int(re.compile(p, re.I).flags)) for p in records)
        except (TypeError, ValueError, RecursionError, OverflowError) as error:
            raise PackageError(f'invalid effective command rules: {error}') from error
        after = _inventory()
        if before != after:
            raise PackageError('rule sources changed while collecting snapshot')
        cold = _inventory(cold_only=True, validate=False)
        eligible = _startup == cold[:2]
        return RuleSnapshot(rules, rules_fingerprint(rules), before[0], before[1], eligible)
