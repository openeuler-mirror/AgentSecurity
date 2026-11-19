"""A complete source rule yields one necessary byte regex or Python fallback."""

import re

import pytest

from agent_moss.engine.prefilter_contract import RuleSpec, guard_text
from agent_moss.engine.prefilter_simplify import simplify_rule


def _accepts(result, text):
    return result.expression is not None and re.search(
        result.expression.encode("ascii"), text.encode("utf-8")) is not None


def test_ascii_class_without_fixed_word_can_be_prefiltered():
    result = simplify_rule(RuleSpec(r"[0-9]+", 0))
    assert result.expression is not None
    assert _accepts(result, "123")
    assert not _accepts(result, "abc")


def test_unicode_digit_category_relaxes_to_nullable_and_uses_python():
    result = simplify_rule(RuleSpec(r"\d+", 0))
    assert result.expression is None
    assert "nullable" in result.reason


def test_single_ascii_literal_has_no_minimum_word_length():
    result = simplify_rule(RuleSpec("a", re.I))
    assert result.expression is not None
    assert _accepts(result, "A")
    assert not _accepts(result, "b")


def test_order_and_full_consumed_gap_are_preserved():
    result = simplify_rule(RuleSpec(r"curl\s+https://", re.I))
    assert _accepts(result, "CURL 中文\nhttps://")
    assert not _accepts(result, "https:// 中文 curl")


def test_nullable_alternative_uses_python_without_second_expression():
    result = simplify_rule(RuleSpec(r"(?:a|)", 0))
    assert result.expression is None
    assert "nullable" in result.reason


@pytest.mark.parametrize("count,covered", [(63, True), (64, True), (65, False)])
def test_structural_branch_budget_is_64(count, covered):
    source = "(?:" + "|".join("ab" if index % 2 else "cd" for index in range(count)) + ")"
    result = simplify_rule(RuleSpec(source, 0))
    assert (result.expression is not None) is covered
    if covered:
        assert _accepts(result, "ab")
        assert _accepts(result, "cd")


def test_unsupported_nested_extension_discards_entire_expression():
    result = simplify_rule(RuleSpec(r"ab(?=x(?i:yz))cd", 0))
    assert result.expression is None
    assert result.reason


@pytest.mark.parametrize("text", ["İ", "ı", "ſ", "K", "\x00", "\x08", "\x0b", "\x1f", "\x7f", "\x85", "\x9f", "\ud800"])
def test_special_text_requires_python(text):
    assert guard_text("cmd" + text)


@pytest.mark.parametrize("text", ["", "普通中文路径", "\u3000", "\t\n\r", "é٣"])
def test_normal_unicode_is_not_guarded(text):
    assert not guard_text(text)
