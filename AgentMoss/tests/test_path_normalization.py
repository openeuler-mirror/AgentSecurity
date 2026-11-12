"""Path normalization compatibility and repeated-work regression tests.

Inputs are strings for static analysis. No sample commands are executed.
"""
import cProfile
import pstats

import pytest

from agent_moss.engine.heuristic import _normalize_path_segments


# Explicit expected outputs include intentionally preserved legacy behavior.
CONTRACTS = [('empty', '', '', ''),
 ('plain', 'cat /etc/shadow', 'cat /etc/shadow', 'cat /etc/shadow'),
 ('slashes', 'cat /etc///shadow', 'cat /etc/shadow', 'cat /etc/shadow'),
 ('dot', 'cat /etc/./shadow', 'cat /etc/shadow', 'cat /etc/shadow'),
 ('dot_overlap', 'cat /././etc//shadow', 'cat /./etc/shadow', 'cat /./etc/shadow'),
 ('parent_retained', 'cat /a/../etc//shadow', 'cat /a/../etc/shadow', 'cat /a/../etc/shadow'),
 ('quote_default', 'grep "a//b" /etc//shadow', 'grep "a//b" /etc/shadow', 'grep "a/b" /etc/shadow'),
 ('single_quote', "cat '/etc//shadow'", "cat '/etc//shadow'", "cat '/etc/shadow'"),
 ('url', 'curl https://host//a/./b', 'curl https://host/a/b', 'curl https://host/a/b'),
 ('quoted_url', "'http://a//b'", "'http://a//b'", "'http://a/b'"),
 ('extra_url_slash', 'http:///a//b', 'http:///a/b', 'http:///a/b'),
 ('uppercase_protocol', 'HTTPS://h//a', 'HTTPS://h/a', 'HTTPS://h/a'),
 ('file_url', 'file:///etc//shadow', 'file:///etc/shadow', 'file:///etc/shadow'),
 ('unclosed_quote', "a'//b", "a'/b", "a'/b"),
 ('multiline_quote', "'a\n//b' /x//y", "'a\n//b' /x/y", "'a\n/b' /x/y"),
 ('chinese', 'cat /目录//文件', 'cat /目录/文件', 'cat /目录/文件'),
 ('nul', 'a\x00//b', 'a\x00/b', 'a\x00/b'),
 ('fullwidth_slashes', 'cat ／／etc／shadow', 'cat ／／etc／shadow', 'cat ／／etc／shadow'),
 ('quote_collision', '__Q0__ "x"', '"x" "x"', '__Q0__ "x"'),
 ('nested_collision', "'__Q1__' 'x'", "''x'' 'x'", "'__Q1__' 'x'"),
 ('protocol_collision', '__PROT0__ http://x', ':// http://x', ':// http://x'),
 ('unknown_token', '__Q999__ //x', '__Q999__ /x', '__Q999__ /x'),
 ('literal_zero_padding', '__Q00__ "x"', '__Q00__ "x"', '__Q00__ "x"')]


# Generated markers can supply the missing underscores on either side.
CONTRACTS += [
    ('boundary_quote_tail', "'a' 'b'Q0__", "'a' __Q1'a'", "'a' 'b'Q0__"),
    ('boundary_quote_tail_path', "'a' 'b'Q0__ //", "'a' __Q1'a' /", "'a' 'b'Q0__ /"),
    ('boundary_quote_both_sides', "'a' 'b'Q0'c'", "'a' __Q1'a'Q2__", "'a' 'b'Q0'c'"),
    ('boundary_quote_both_sides_path', "'a' 'b'Q0'c' /./x", "'a' __Q1'a'Q2__ /x", "'a' 'b'Q0'c' /x"),
    ('boundary_protocol_tail', 'http://x http://PROT0__', 'http://x http__PROT1://', 'http://x http__PROT1://'),
    ('boundary_adjacent_protocols', 'ftp://ftp://PROT0__x', 'ftp://ftp__PROT1://x', 'ftp://ftp__PROT1://x'),
    ('boundary_unknown_quote', "http://Q1__ 'a'", "http://Q1__ 'a'", "http://Q1__ 'a'"),
    ('boundary_unknown_quote_path', "http://Q9__ 'a' //", "http://Q9__ 'a' /", "http://Q9__ 'a' /"),
]


@pytest.mark.parametrize("name,text,default,folded", CONTRACTS, ids=[c[0] for c in CONTRACTS])
@pytest.mark.parametrize("fold_quotes", [False, True])
def test_normalization_contract(name, text, default, folded, fold_quotes):
    expected = folded if fold_quotes else default
    assert _normalize_path_segments(text, fold_quotes) == expected


@pytest.mark.parametrize("count", [0, 1, 9, 10, 11, 99, 100, 101, 999, 1000, 1001])
@pytest.mark.parametrize("fold_quotes", [False, True])
def test_quote_and_protocol_indices_across_digit_boundaries(count, fold_quotes):
    text = " ".join(f'"value-{i} http://h//x"' for i in range(count)) + ' /etc//shadow'
    url_path = 'http://h/x' if fold_quotes else 'http://h//x'
    expected = " ".join(f'"value-{i} {url_path}"' for i in range(count)) + ' /etc/shadow'
    assert _normalize_path_segments(text, fold_quotes) == expected


@pytest.mark.parametrize("unit,expected_unit", [
    ('"component" ', '"component" '),
    ('"component" /a//b ', '"component" /a/b '),
    ('"http://host//path" ', '"http://host//path" '),
])
def test_long_text_does_not_replace_whole_string_per_placeholder(unit, expected_unit):
    # Count real built-in calls instead of asserting a machine-dependent time limit.
    profiler = cProfile.Profile()
    result = profiler.runcall(_normalize_path_segments, unit * 1000)
    assert result == expected_unit * 1000
    replace_calls = sum(stats[1] for key, stats in pstats.Stats(profiler).stats.items()
                        if key[2] == "<method 'replace' of 'str' objects>")
    assert replace_calls <= 2, f"Repeated full-string replacements: {replace_calls}"


@pytest.mark.parametrize("count", [0, 1, 2, 3, 7, 8, 9, 12])
def test_restore_strategy_switch_preserves_output(count):
    """少量令牌走 str.replace、大量令牌走批量正则（阈值 8），两条路径输出必须一致。"""
    text = " ".join(f'cat "v{i}" http://h{i}//x' for i in range(count)) + ' /a//b'
    expected = " ".join(f'cat "v{i}" http://h{i}/x' for i in range(count)) + ' /a/b'
    assert _normalize_path_segments(text) == expected
