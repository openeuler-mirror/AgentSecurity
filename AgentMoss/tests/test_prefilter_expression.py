"""Loaded metadata accepts only expressions emitted by our byte generator."""

import pytest

from agent_moss.engine.prefilter_expression import validate_generated_expression


@pytest.mark.parametrize("expression", [
    r"\x61\x62", r"[\x41\x61]{1,3}\x62", r"(?:\x61|\x62)\x63",
    r"\x61(?s:.*)\x62", r"(?:\x61|)\x62",
])
def test_valid_nonnullable_generated_byte_expressions(expression):
    assert validate_generated_expression(expression)


@pytest.mark.parametrize("expression", [
    "", "abc", "中文", r"\w", r"\xGG", r"\x80", r"\x61|\x62",
    r"(?i)\x61", r"(?=x)\x61", r"\x61**", r"\x61{65}",
    r"\x61{2,1}", r"(?:\x61|)", r"(?s:.*)", r"\x61[abc]",
])
def test_foreign_or_nullable_expression_is_rejected(expression):
    assert not validate_generated_expression(expression)
