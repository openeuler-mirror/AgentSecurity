"""Public regex capability checks run during build/background load only."""

import os

from agent_moss.engine.prefilter_compat import python_compatibility


def test_current_python_satisfies_finite_regex_contract():
    result = python_compatibility()
    assert result.supported, result.reason


def test_capability_result_is_cached_per_process():
    first = python_compatibility()
    second = python_compatibility()
    assert first is second
    assert os.getpid() > 0
