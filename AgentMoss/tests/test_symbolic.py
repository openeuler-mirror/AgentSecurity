"""LiteSE 符号执行器测试 — Python 端。

镜像 TS ts/src/__tests__/symbolic.test.ts。覆盖四类场景 + fail-closed。
双端算法/数据结构/用例对齐（AgentMoss 铁律）。
"""

import pytest

from agent_moss.engine.script_engine.backends.symbolic import (
    symbolic_process,
    eval_condition,
    match_glob,
    eval_expr,
    eval_numeric_compare,
)


class TestP2Concat:
    def test_case_selector_prefix_concat(self):
        src = '#!/bin/bash\ncase "prefix${1}suffix" in\n  prefixcleansuffix) rm -rf ~/.ssh/id_rsa ;;\n  prefixbacksuffix) echo safe ;;\nesac\n'
        out = symbolic_process(src, ["clean"])
        assert out is not None
        assert "id_rsa" in out
        assert "safe" not in out


class TestP3NamedVars:
    def test_mode_clean(self):
        src = '#!/bin/bash\nMODE=clean\ncase $MODE in\n  clean) rm -rf ~/.ssh/id_rsa ;;\n  dev) echo safe ;;\nesac\n'
        out = symbolic_process(src, [])
        assert out is not None
        assert "id_rsa" in out

    def test_global_var_if_equal(self):
        src = '#!/bin/bash\nENV=prod\nif [ "$ENV" = "prod" ]; then\n  echo inprod\nelse\n  echo other\nfi\n'
        out = symbolic_process(src, [])
        assert out is not None
        assert "inprod" in out


class TestP4Glob:
    def test_bak_star_matches_bakery(self):
        src = '#!/bin/bash\ncase $1 in\n  bak*) echo dangerous ;;\n  *) echo safe ;;\nesac\n'
        out = symbolic_process(src, ["bakery"])
        assert out is not None
        assert "dangerous" in out

    def test_dev_falls_to_star(self):
        src = '#!/bin/bash\ncase $1 in\n  bak*) echo dangerous ;;\n  *) echo safe ;;\nesac\n'
        out = symbolic_process(src, ["dev"])
        assert out is not None
        assert "dangerous" not in out
        assert "safe" in out

    def test_match_glob_primitive(self):
        assert match_glob("bak*", "bakery") is True
        assert match_glob("bak*", "dev") is False
        assert match_glob("a?c", "abc") is True


class TestP4Numeric:
    def test_eval_numeric_compare(self):
        assert eval_numeric_compare("-gt", "10", "5") is True
        assert eval_numeric_compare("-lt", "3", "5") is True
        assert eval_numeric_compare("-gt", "a", "5") is None

    def test_if_numeric(self):
        src = '#!/bin/bash\nif [ "$1" -gt 5 ]; then\n  echo big\nelse\n  echo small\nfi\n'
        out = symbolic_process(src, ["10"])
        assert out is not None and "big" in out
        out2 = symbolic_process(src, ["3"])
        assert out2 is not None and "small" in out2


class TestFailClosed:
    def test_unknown_named_selector(self):
        src = '#!/bin/bash\nMODE=$1\ncase $MODE in\n  prod) rm -rf ~/.ssh/id_rsa ;;\nesac\n'
        assert symbolic_process(src, []) is None

    def test_non_modelable(self):
        src = '#!/bin/bash\ncase $1 in\n  clean) rm -rf ~/.ssh/id_rsa ;;\nesac\n$(echo evil)\n'
        assert symbolic_process(src, ["clean"]) is None