"""Live manager tests use real packages, not a fake loader."""

import os
import re
import time

import pytest

from agent_moss.engine.prefilter_build import build_package
from agent_moss.engine.prefilter_contract import RuleSpec
from agent_moss.engine.prefilter_reload import PackageManager, get_manager


def test_acceleration_is_disabled_unless_explicitly_enabled(monkeypatch, tmp_path):
    monkeypatch.delenv("AGENT_MOSS_ACCEL", raising=False)
    assert get_manager(str(tmp_path / "prefilter.hsdb")) is None


def _library():
    path = os.environ.get("AGENT_MOSS_TEST_HS_LIB")
    if not path:
        pytest.skip("set AGENT_MOSS_TEST_HS_LIB to a real Hyperscan compile library")
    return path


def _await_package(manager, previous=None):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        current = manager.status()["active_package"]
        if current is not None and current != previous:
            return current
        time.sleep(.01)
    pytest.fail(f"package did not activate: {manager.status()}")


def test_hot_swap_keeps_inflight_old_binding_alive(tmp_path):
    library = _library()
    entry = tmp_path / "prefilter.hsdb"
    old_rules = (RuleSpec(r"curl\s+https://", re.I),)
    new_rules = (RuleSpec(r"wget\s+https://", re.I),)
    build_package(old_rules, entry, library_path=library, backend="hyperscan")
    manager = PackageManager(str(entry), library, backend="hyperscan", poll_interval=.01)
    manager.start()
    try:
        first = _await_package(manager)
        old_binding = manager.bind(old_rules)
        assert old_binding.covered == frozenset({0})
        assert old_binding.candidates("curl https://") == {0}
        from agent_moss.engine.prefilter_storage import PackageBusy
        deadline = time.monotonic() + 5
        while True:
            try:
                build_package(new_rules, entry, library_path=library, backend="hyperscan")
                break
            except PackageBusy:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.005)
        second = _await_package(manager, previous=first)
        assert second != first
        assert manager.bind(new_rules).candidates("wget https://") == {0}
        assert old_binding.candidates("curl https://") == {0}
    finally:
        manager.stop()


def test_failed_target_keeps_current_package(tmp_path):
    library = _library()
    entry = tmp_path / "prefilter.hsdb"
    rules = (RuleSpec(r"curl\s+https://", re.I),)
    build_package(rules, entry, library_path=library, backend="hyperscan")
    manager = PackageManager(str(entry), library, backend="hyperscan", poll_interval=.01, retry_interval=.01)
    manager.start()
    try:
        active = _await_package(manager)
        (entry / 'database.bin').write_bytes(b'corrupt')
        deadline = time.monotonic() + 5
        while manager.status()["error"] is None and time.monotonic() < deadline:
            time.sleep(.01)
        assert manager.status()["error"]
        assert manager.status()["active_package"] == active
        assert manager.bind(rules).candidates("curl https://") == {0}
    finally:
        manager.stop()


def test_binding_cache_uses_ordered_full_rule_identity(tmp_path):
    library = _library()
    entry = tmp_path / "prefilter.hsdb"
    first = RuleSpec(r"curl\s+https://", re.I)
    second = RuleSpec(r"wget\s+https://", re.I)
    third = RuleSpec(r"chmod\s+777", re.I)
    build_package((first, second), entry, library_path=library, backend="hyperscan")
    manager = PackageManager(str(entry), library, backend="hyperscan", poll_interval=.01)
    manager.start()
    try:
        _await_package(manager)
        assert manager.bind((first, second)).candidates("curl https://") == {0}
        assert manager.bind((second, first)).candidates("curl https://") == {1}
        assert manager.bind((first, third)).covered == frozenset({0})
        assert manager.bind((first, first)).candidates("curl https://") == {0, 1}
        assert manager.bind((RuleSpec(first.pattern, 0),)).covered == frozenset()
        for index in range(70):
            manager.bind((first, RuleSpec(f"unpacked-{index}", re.I)))
        assert manager.status()["cached_bindings"] <= 64
    finally:
        manager.stop()
