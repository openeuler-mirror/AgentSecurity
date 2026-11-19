"""Seeded native sufficiency checks over generated finite-grammar rules.

No input text is executed. The same package is scanned by the actual C ABI.
"""

import itertools
import json
import os
import random
import re

import pytest

from agent_moss.engine.prefilter import load_package
from agent_moss.engine.prefilter_build import build_package
from agent_moss.engine.prefilter_contract import RuleSpec


SEED = 20261110


def _library():
    path = os.environ.get("AGENT_MOSS_TEST_HS_LIB")
    if not path:
        pytest.skip("set AGENT_MOSS_TEST_HS_LIB to a real Hyperscan compile library")
    return path


def _digits(index):
    return "".join("abcd"[(index >> shift) & 3] for shift in (8, 6, 4, 2, 0))


def _rule_case(index):
    digits = _digits(index)
    left, right, tail = "ab" + digits, "cd" + digits, "tail"
    lead = "(?:" + left + "|" + right + ")"
    family = index % 5
    gap = (r"\s+", r"[ \t]+", r"(?:中文)?\s+", r"(?=x)x\s+", r"\d+")[family]
    middles = ((" ", "\t"), (" ", "\t"), (" ", "中文 "),
               ("x ", "x\t"), ("3", "٣"))[family]
    pattern = lead + gap + tail
    positives = [prefix + middle + tail for prefix in (left, right, left.upper(), right.upper())
                 for middle in middles]
    samples = positives + [
        "echo hello", tail + " " + left, left + " other", right + " tailish",
        left + "\nother", left + "中文" + tail,
        left + middles[0] + "TAIL", left + middles[0] + "tail!",
        "!" + right + middles[-1] + tail, left + middles[-1] + tail + "!",
        left + "x" + middles[0] + tail, right + middles[-1] + "tailx",
    ]
    assert len(samples) == 20
    return RuleSpec(pattern, re.I), samples


def test_1000_generated_rules_have_no_native_false_negative(tmp_path):
    library = _library()
    randomizer = random.Random(SEED)
    cases = [_rule_case(index) for index in range(1000)]
    rules = tuple(rule for rule, _ in cases)
    entry = tmp_path / "prefilter.hsdb"
    report = build_package(rules, entry, library_path=library, backend="hyperscan")
    package = load_package(entry, library, backend="hyperscan")
    bound = package.bind(rules)
    assert report["rules_total"] == 1000
    assert len(bound.covered) >= 950
    assert report["rules_prefilter"] >= 950
    compiled = [re.compile(rule.pattern, rule.flags) for rule in rules]
    uncovered = set(range(len(rules))) - bound.covered
    samples = [text for _, texts in cases for text in texts]
    randomizer.shuffle(samples)
    true_matches = 0
    for ordinal, text in enumerate(samples):
        expected = {index for index, regex in enumerate(compiled) if regex.search(text)}
        true_matches += len(expected)
        actual = bound.candidates(text) | uncovered
        missing = expected - actual
        if missing:
            rule_index = min(missing)
            minimum = text
            changed = True
            while changed:
                changed = False
                for offset in range(len(minimum)):
                    shorter = minimum[:offset] + minimum[offset + 1:]
                    if (compiled[rule_index].search(shorter)
                            and rule_index not in (bound.candidates(shorter) | uncovered)):
                        minimum = shorter
                        changed = True
                        break
            failure = {"seed": SEED, "sample": ordinal, "rule_index": rule_index,
                       "rule": rules[rule_index].pattern, "text": text, "minimum": minimum}
            artifact = tmp_path / "t06-minimum-failure.json"
            artifact.write_text(json.dumps(failure, ensure_ascii=False, indent=2))
            pytest.fail(f"native false negative; evidence={artifact}; {failure!r}")
    assert true_matches >= 8000
    print(f"T06 seed={SEED} rules={len(rules)} covered={len(bound.covered)} "
          f"prefilter={report['rules_prefilter']} "
          f"samples={len(samples)} python_true={true_matches} missed=0")


def test_small_alphabet_exhaustion_has_no_native_false_negative(tmp_path):
    library = _library()
    rules = tuple(RuleSpec(pattern, 0) for pattern in (
        r"ab[ab]c", r"ab(?:a|b)c", r"ab(?:|a)c", r"ab\s*c", r"ab(?=c)c",
        r"(?:ab|ba)c", r"ab[a-b]{1,2}c", r"ab[^x]c", r"ab.c", r"ab\w+c",
    ))
    entry = tmp_path / "prefilter.hsdb"
    build_package(rules, entry, library_path=library, backend="hyperscan")
    bound = load_package(entry, library, backend="hyperscan").bind(rules)
    compiled = [re.compile(rule.pattern) for rule in rules]
    uncovered = set(range(len(rules))) - bound.covered
    truth = 0
    for length in range(6):
        for chars in itertools.product("abc \n", repeat=length):
            text = "".join(chars)
            expected = {index for index, regex in enumerate(compiled) if regex.search(text)}
            truth += len(expected)
            assert expected <= bound.candidates(text) | uncovered, (text, expected)
    assert truth > 0


def _random_tree(randomizer, depth):
    leaves = ((r"\d", "٣"), (r"\s", " "), (r"[a-c]", "b"),
              (r"[^x]", "中"), (".", "q"), ("中文", "中文"),
              (r"\x28", "("), ("x", "x"))
    if depth == 0 or randomizer.random() < .35:
        return ("leaf", *randomizer.choice(leaves))
    kind = randomizer.choice(("seq", "alt", "repeat"))
    if kind == "repeat":
        return (kind, _random_tree(randomizer, depth - 1), randomizer.choice((0, 1, 2)))
    return (kind, _random_tree(randomizer, depth - 1), _random_tree(randomizer, depth - 1))


def _render_tree(tree):
    kind = tree[0]
    if kind == "leaf":
        return tree[1], tree[2]
    if kind == "seq":
        first, first_text = _render_tree(tree[1])
        second, second_text = _render_tree(tree[2])
        return first + second, first_text + second_text
    if kind == "alt":
        first, first_text = _render_tree(tree[1])
        second, _ = _render_tree(tree[2])
        return "(?:" + first + "|" + second + ")", first_text
    child, child_text = _render_tree(tree[1])
    minimum = tree[2]
    return "(?:" + child + "){" + str(minimum) + ",3}", child_text * minimum


def test_seeded_grammar_tree_rules_keep_native_superset(tmp_path):
    library = _library()
    randomizer = random.Random(SEED + 1)
    rules = []
    samples = []
    for index in range(200):
        tree = _random_tree(randomizer, 3)
        middle, witness = _render_tree(tree)
        prefix = "ab" + _digits(index)
        rule = RuleSpec(prefix + middle + "zz", re.I)
        positive = prefix + witness + "zz"
        assert re.search(rule.pattern, positive, rule.flags), (tree, rule.pattern, positive)
        rules.append(rule)
        samples.extend((positive, positive.upper(), positive + "!", "!" + positive,
                        positive[:-1], positive.replace(prefix, "qq", 1),
                        prefix + "中" + witness + "zz", prefix + witness + "yy"))
    entry = tmp_path / "prefilter.hsdb"
    report = build_package(rules, entry, library_path=library, backend="hyperscan")
    bound = load_package(entry, library, backend="hyperscan").bind(tuple(rules))
    assert len(bound.covered) >= 190
    assert report["rules_prefilter"] >= 190
    compiled = [re.compile(rule.pattern, rule.flags) for rule in rules]
    uncovered = set(range(len(rules))) - bound.covered
    true_count = 0
    for text in samples:
        expected = {index for index, regex in enumerate(compiled) if regex.search(text)}
        true_count += len(expected)
        missing = expected - (bound.candidates(text) | uncovered)
        assert not missing, (SEED + 1, text, [(index, rules[index].pattern) for index in missing])
    assert true_count >= 200
    print(f"T06-tree seed={SEED + 1} rules={len(rules)} covered={len(bound.covered)} "
          f"prefilter={report['rules_prefilter']} samples={len(samples)} "
          f"python_true={true_count} missed=0")
