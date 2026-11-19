import json
import re

import pytest

from agent_moss.engine.prefilter_contract import RuleSpec
from agent_moss.engine.prefilter_manifest import PackageError


@pytest.fixture(autouse=True)
def _isolate_runtime_config():
    """Override the suite's has_runtime_config=False stub for these real-file tests."""
    yield


def rule(pattern, **kw):
    return dict(pattern=pattern, risk_level='high', risk_type='script_execution', reason='test', **kw)


@pytest.fixture
def sources(tmp_path, monkeypatch):
    from agent_moss import rules_loader, profiles, agents, scenarios
    from agent_moss.infra import runtime_config, rules_mode
    from agent_moss.engine import prefilter_rule_source as source
    monkeypatch.setenv('AGENT_MOSS_ACCEL', '1')
    monkeypatch.setenv('AGENT_MOSS_DATA_DIR', str(tmp_path / 'data'))
    monkeypatch.setenv('AGENT_MOSS_RULES_ROOT', str(tmp_path / 'assets'))
    monkeypatch.setenv('AGENT_MOSS_RUNTIME_CONFIG_PATH', str(tmp_path / 'runtime.json'))
    monkeypatch.setenv('AGENT_MOSS_EXTRA_RULES_DIR', str(tmp_path / 'extra'))
    monkeypatch.delenv('AGENT_MOSS_OVERRIDE_RULES_DIR', raising=False)
    monkeypatch.setenv('AGENT_MOSS_RULES_MODE', 'hot')
    monkeypatch.setattr(source, '_startup', None)
    root = tmp_path / 'assets' / 'rules'
    root.mkdir(parents=True)
    for name in ('l1_rules.json', 'l2_rules.json', 'l3_rules.json', 'mc_rules.json'):
        (root / name).write_text(json.dumps({'dangerous_commands': [rule('builtin', os='linux'),
            rule('winonly', os='windows')]} if name == 'l1_rules.json' else {}))
    (tmp_path / 'extra').mkdir()
    def clear():
        rules_mode.reset_cache()
        rules_loader.clear_rules_cache()
        profiles.clear_profile_cache()
        agents.clear_agent_extensions_cache()
        scenarios.clear_scenario_extensions_cache()
        runtime_config._RUNTIME_CONFIG_CACHE.clear()
        runtime_config._HAS_RUNTIME_CONFIG_CACHE.clear()
    clear()
    yield tmp_path, source
    clear()


def patterns(snapshot):
    return {r.pattern for r in snapshot.rules}


def test_readonly_snapshot_covers_platforms_without_creating_config(sources):
    path, source = sources
    result = source.RuleSource().snapshot()
    assert {'builtin', 'winonly'} <= patterns(result)
    assert result.eligible
    assert not (path / 'runtime.json').exists()
    assert not (path / 'data').exists()


def test_override_extra_and_runtime_custom_preserve_business_selection(sources):
    path, source = sources
    (path / 'extra' / 'override.json').write_text(json.dumps({'dangerous_commands': [rule('override')]}))
    (path / 'extra' / 'extra.json').write_text(json.dumps({'dangerous_commands': [rule('extra')]}))
    runtime = {'layers': {}, 'L1_rules': {'user_custom': {'rules': [rule('custom'), rule('disabled', enabled=False)]}}}
    (path / 'runtime.json').write_text(json.dumps(runtime))
    before = (path / 'runtime.json').read_bytes()
    result = source.RuleSource().snapshot()
    assert patterns(result) == {'override', 'extra', 'custom', 'winonly'}
    assert (path / 'runtime.json').read_bytes() == before
    assert all(r.flags == int(re.I | re.U) for r in result.rules)


def test_extensions_and_scenario_override_use_same_precedence(sources):
    path, source = sources
    for kind, ident, pattern in [('agents', 'alpha', 'agentcmd'), ('scenarios', 'bank', 'original')]:
        root = path / 'assets' / kind / ident
        root.mkdir(parents=True)
        (root / 'rules.json').write_text(json.dumps({'agent_id' if kind == 'agents' else 'scenario_id': ident, 'extra_command_patterns': [rule(pattern)]}))
    override = path / 'extra' / 'scenarios' / 'bank'
    override.mkdir(parents=True)
    (override / 'rules.json').write_text(json.dumps({'scenario_id': 'bank', 'extra_command_patterns': [rule('overridecmd')]}))
    result = source.RuleSource().snapshot()
    assert {'agentcmd', 'overridecmd'} <= patterns(result)
    assert 'original' not in patterns(result)
    assert not (path / 'runtime.json').exists()


def test_description_and_duplicates_do_not_change_fingerprint(sources):
    path, source = sources
    extra = path / 'extra' / 'extra.json'
    extra.write_text(json.dumps({'dangerous_commands': [rule('custom')]}))
    reader = source.RuleSource()
    first = reader.snapshot()
    altered = rule('custom')
    altered['reason'] = 'changed documentation'
    extra.write_text(json.dumps({'dangerous_commands': [altered, altered]}, indent=4))
    second = reader.snapshot()
    assert first.fingerprint == second.fingerprint
    assert first.source_generation != second.source_generation


@pytest.mark.parametrize('text', ['{', '42', '{"dangerous_commands": {}}'])
def test_incomplete_or_malformed_source_is_not_an_empty_snapshot(sources, text):
    path, source = sources
    (path / 'extra' / 'extra.json').write_text(text)
    with pytest.raises(PackageError):
        source.RuleSource().snapshot()


def test_cold_generation_is_recorded_when_business_loads_not_at_first_poll(sources, monkeypatch):
    path, source = sources
    from agent_moss import rules_loader
    from agent_moss.infra import rules_mode
    monkeypatch.setenv('AGENT_MOSS_RULES_MODE', 'cold')
    rules_mode.reset_cache()
    extra = path / 'extra' / 'extra.json'
    extra.write_text(json.dumps({'dangerous_commands': [rule('old')]}))
    assert rules_loader.load_extra_rules()['dangerous_commands'][0]['pattern'] == 'old'
    extra.write_text(json.dumps({'dangerous_commands': [rule('new')]}))
    result = source.RuleSource().snapshot()
    assert not result.eligible
    assert 'old' in patterns(result) and 'new' not in patterns(result)


def test_source_changed_during_read_cannot_be_published(sources, monkeypatch):
    path, source = sources
    from agent_moss.infra import runtime_config
    original = runtime_config.load_runtime_config_readonly
    def changing():
        value = original()
        (path / 'extra' / 'extra.json').write_text(json.dumps({'dangerous_commands': [rule('late')]}))
        return value
    monkeypatch.setattr(runtime_config, 'load_runtime_config_readonly', changing)
    with pytest.raises(PackageError, match='changed'):
        source.RuleSource().snapshot()


def test_bad_extension_cannot_silently_disappear_from_snapshot(sources):
    path, source = sources
    root = path / 'assets' / 'agents' / 'broken'
    root.mkdir(parents=True)
    (root / 'rules.json').write_text(json.dumps({'extra_command_patterns': [rule('lost')]}))
    with pytest.raises(PackageError):
        source.RuleSource().snapshot()


def test_disabled_extension_layer_does_not_build_unused_patterns(sources):
    path, source = sources
    config = {'layers': {'agent_rules_enabled': False}, 'agent_rules': {'alpha': {
        'extra_command_patterns': {'rules': [rule('disabled-agent')]}}}}
    (path / 'runtime.json').write_text(json.dumps(config))
    assert 'disabled-agent' not in patterns(source.RuleSource().snapshot())


@pytest.mark.parametrize('kind', ['agent', 'scenario'])
def test_changed_runtime_snapshot_does_not_poison_business_cache(sources, monkeypatch, kind):
    path, source = sources
    from agent_moss import agents, scenarios
    from agent_moss.infra import runtime_config
    owner = agents if kind == 'agent' else scenarios
    key = kind + '_rules'
    def config(pattern):
        return {'layers': {}, key: {'alpha': {
            'extra_command_patterns': {'rules': [rule(pattern)]}}}}
    runtime_file = path / 'runtime.json'
    runtime_file.write_text(json.dumps(config('old_rule')))
    original = runtime_config.load_runtime_config_readonly
    def changing():
        value = original()
        runtime_file.write_text(json.dumps(config('new_long_rule')))
        return value
    monkeypatch.setattr(runtime_config, 'load_runtime_config_readonly', changing)
    with pytest.raises(PackageError, match='changed'):
        source.RuleSource().snapshot()
    actual = getattr(owner, 'get_' + kind + '_extensions')('alpha')
    assert [r.pattern for r in actual.extra_command_patterns] == ['new_long_rule']


def test_malformed_runtime_extension_is_not_silently_skipped(sources):
    path, source = sources
    (path / 'runtime.json').write_text(json.dumps({'agent_rules': {'alpha': {
        'extra_command_patterns': {'rules': [{'pattern': 'lost', 'risk_level': 'high'}]}}}}))
    with pytest.raises((KeyError, PackageError)):
        source.RuleSource().snapshot()


def test_startup_a_b_a_change_cannot_publish_b_rules_as_a(sources, monkeypatch):
    path, source = sources
    from agent_moss import profiles
    from agent_moss.infra import rules_mode
    monkeypatch.setenv('AGENT_MOSS_RULES_MODE', 'cold')
    rules_mode.reset_cache()
    file = path / 'assets' / 'rules' / 'l1_rules.json'
    original_bytes = file.read_bytes()
    original_inventory = source._inventory
    changed = False
    def changing(**kwargs):
        nonlocal changed
        result = original_inventory(**kwargs)
        if kwargs.get('cold_only') and not changed:
            changed = True
            file.write_text(json.dumps({'dangerous_commands': [rule('version_B')]}))
        return result
    monkeypatch.setattr(source, '_inventory', changing)
    assert profiles.get_profile('linux').dangerous_commands[0].pattern == 'version_B'
    file.write_bytes(original_bytes)
    result = source.RuleSource().snapshot()
    assert 'version_B' in patterns(result)
    assert not result.eligible
