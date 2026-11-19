"""The finite reader must consume the whole source before conditions exist."""

import re
import warnings

import pytest

from agent_moss.engine.regex_subset_parser import UnsupportedPattern, parse_pattern


def test_quantifier_binds_to_last_atom_and_preserves_source_spans():
    tree = parse_pattern("abc?", 0)
    assert tree.kind == "seq"
    assert tree.span == (0, 4)
    assert [(n.kind, n.span) for n in tree.children] == [
        ("literal", (0, 1)), ("literal", (1, 2)), ("repeat", (2, 4))
    ]
    assert tree.children[-1].children[0].value == "c"
    assert (tree.children[-1].minimum, tree.children[-1].maximum) == (0, 1)


def test_escaped_syntax_and_class_context_are_read_completely():
    tree = parse_pattern(r"\(\|\[\b[\b]", 0)
    assert tree.span == (0, 12)
    assert [n.kind for n in tree.children] == ["literal"] * 3 + ["anchor", "class"]
    assert [n.value for n in tree.children[:3]] == ["(", "|", "["]
    assert tree.children[-1].value == "\b"


@pytest.mark.parametrize("source", [r"[]a]", r"[a-]", r"[-a]", r"[a\-z]", r"[\]]"])
def test_unambiguous_character_class_is_read(source):
    assert parse_pattern(source, 0).span == (0, len(source))


@pytest.mark.parametrize("source", [
    r"(?i)ab", r"ab(?i)cd", r"ab(?i)?cd", r"ab(?i)*cd",
    r"ab(?u){0}cd", r"ab(?i:cd)", r"ab(?-i:cd)",
    r"ab(?=x(?i))cd", r"ab(?P<n>x)cd", r"ab(?>(?:x))cd",
    r"ab(?#comment)cd", r"ab(a)?(?(1)c|d)", r"ab\1cd",
    r"ab\N{SPACE}cd", r"ab{,2}cd", r"ab[a&&b]cd",
])
def test_unsupported_syntax_discards_entire_rule(source):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FutureWarning)
            re.compile(source)
    except re.error:
        pytest.skip("Python version rejects original pattern")
    with pytest.raises(UnsupportedPattern):
        parse_pattern(source, 0)


def test_invalid_original_regex_keeps_python_error():
    with pytest.raises(re.error):
        parse_pattern("ab(", 0)
