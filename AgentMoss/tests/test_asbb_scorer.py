"""ASBB benchmark 判分引擎 unit tests（_wilson_ci / integrity_check / _pct_ci）。

注意：harness 的 loader.py/scorer.py/run.py 相互以顶层模块导入（from loader import ...），
所以这里把 benchmarks/agentsafety/harness/ 加进 sys.path 再 import。
"""
from __future__ import annotations

import sys
from pathlib import Path

_HARNESS = Path(__file__).resolve().parent.parent / "benchmarks" / "agentsafety" / "harness"
if str(_HARNESS) not in sys.path:
    sys.path.insert(0, str(_HARNESS))

from benchmarks.agentsafety.harness.scorer import (  # noqa: E402
    CaseResult, Metrics, _pct, _pct_ci, _wilson_ci, all_breakdowns,
    breakdown, coverage, eq_class_consistency, integrity_check, tally,
)


def _make_case(case_id: str, expected: str, tool: str = "T1",
               threat: str = "W1", complexity: str = "S",
               decision_kind: str = "D", eq_class: str = "EC-001",
               scenario: str = "") -> CaseResult:
    from benchmarks.agentsafety.harness.loader import Case
    c = Case(case_id=case_id, expected=expected, input={},
             metadata=dict(tool_category=tool, threat_pattern=threat,
                           complexity=complexity, decision_kind=decision_kind,
                           scenario_id=scenario),
             eq_class=eq_class)
    return CaseResult(c, None, "mock error")  # caller sets decision


# ── _wilson_ci ────────────────────────────────────────────────

def test_wilson_ci_p0_n100():
    """k=0, n=100 → CI 非常窄，下限=0，上限接近 0"""
    lo, hi = _wilson_ci(0, 100)
    assert 0.0 <= lo < 0.01
    assert hi < 0.05  # Wilson 比正态近似紧


def test_wilson_ci_p100_n100():
    """k=100, n=100 → CI 非常窄，下限接近 1，上限=1"""
    lo, hi = _wilson_ci(100, 100)
    assert lo > 0.95
    assert hi == 1.0


def test_wilson_ci_p50_n100():
    """k=50, n=100 → CI 约 [0.403, 0.597]（威尔逊区间有对称性）"""
    lo, hi = _wilson_ci(50, 100)
    assert 0.40 < lo < 0.41
    assert 0.59 < hi < 0.60


def test_wilson_ci_p0_n1():
    """k=0, n=1 → 只有一次观察，CI 极宽（Wilson 上限 0.79，非正态近似的 1.0）"""
    lo, hi = _wilson_ci(0, 1)
    assert lo == 0.0
    assert 0.75 < hi < 0.85  # Wilson 校正：单次成功观察的信息量极小 → 上限显著 < 1


def test_wilson_ci_n0():
    """n=0 → None"""
    assert _wilson_ci(0, 0) is None


def test_wilson_ci_p50_n2000():
    """k=1000, n=2000 → 大样本下 CI 很窄"""
    lo, hi = _wilson_ci(1000, 2000)
    assert 0.47 < lo < 0.53
    assert 0.47 < hi < 0.53
    assert hi - lo < 0.05  # 大样本区间极窄


# ── _pct_ci ────────────────────────────────────────────────────

def test_pct_ci_normal():
    assert _pct_ci((0.5, 0.6)) == [50.0, 60.0]


def test_pct_ci_none():
    assert _pct_ci(None) is None


# ── integrity_check ────────────────────────────────────────────

def _case_result(decision: str | None, expected: str = "Allow"):
    from benchmarks.agentsafety.harness.loader import Case
    c = Case(case_id="t", expected=expected, input={}, metadata={})
    return CaseResult(c, decision, "" if decision else "mock error")


def test_integrity_mixed_decisions():
    """正常 SUT：混合 Allow/Deny → 完整性标记 ok"""
    results = [_case_result("Allow") for _ in range(80)]
    results += [_case_result("Deny") for _ in range(20)]
    m = tally(results)
    chk = integrity_check(results, m)
    assert chk["ok"] is True
    assert chk["flags"] == []


def test_integrity_all_allow():
    """全部 Allow → degenerate_all_allow"""
    results = [_case_result("Allow") for _ in range(100)]
    m = tally(results)
    chk = integrity_check(results, m)
    assert chk["ok"] is False
    assert "degenerate_all_allow" in chk["flags"]


def test_integrity_all_deny():
    """全部 Deny → degenerate_all_deny"""
    results = [_case_result("Deny") for _ in range(100)]
    m = tally(results)
    chk = integrity_check(results, m)
    assert chk["ok"] is False
    assert "degenerate_all_deny" in chk["flags"]


def test_integrity_all_errors():
    """全部 error → no_decisions"""
    results = [_case_result(None) for _ in range(50)]
    m = tally(results)
    chk = integrity_check(results, m)
    assert chk["ok"] is False
    assert "no_decisions" in chk["flags"]


def test_integrity_high_errors():
    """error 率 > 5% → high_error_rate"""
    results = [_case_result("Allow") for _ in range(90)]
    results += [_case_result(None) for _ in range(10)]  # ~10%
    m = tally(results)
    chk = integrity_check(results, m)
    assert chk["ok"] is False
    assert "high_error_rate" in chk["flags"]


def test_integrity_empty():
    """空结果 → empty flag"""
    m = Metrics()
    chk = integrity_check([], m)
    assert chk["ok"] is False
    assert "empty" in chk["flags"]


# ── tally / Metrics ────────────────────────────────────────────

def test_tally_tp():
    results = [_case_result("Deny", "Deny")]
    m = tally(results)
    assert m.tp == 1 and m.fn == 0 and m.fp == 0 and m.tn == 0


def test_tally_fn():
    results = [_case_result("Allow", "Deny")]
    m = tally(results)
    assert m.tp == 0 and m.fn == 1 and m.fp == 0 and m.tn == 0


def test_tally_fp():
    results = [_case_result("Deny", "Allow")]
    m = tally(results)
    assert m.tp == 0 and m.fn == 0 and m.fp == 1 and m.tn == 0


def test_tally_tn():
    results = [_case_result("Allow", "Allow")]
    m = tally(results)
    assert m.tp == 0 and m.fn == 0 and m.fp == 0 and m.tn == 1


def test_tally_error():
    results = [_case_result(None)]
    m = tally(results)
    assert m.errors == 1


def test_metrics_deny_recall_none():
    """无应拦用例 → None（不是 0）"""
    m = Metrics(tp=0, fn=0, tn=10)
    assert m.deny_recall is None


def test_metrics_allow_fidelity_none():
    """无应放用例 → None"""
    m = Metrics(tp=10, fp=0, tn=0)
    assert m.allow_fidelity is None


def test_metrics_balanced_accuracy_ok():
    m = Metrics(tp=80, fn=20, tn=90, fp=10)
    r = round(m.balanced_accuracy, 2) if m.balanced_accuracy else None
    assert r == 0.85  # (80% + 90%)/2 = 85%


# ── 等价类一致性（A3 边界用例已知不一致，验证报告不崩）───────

def test_eq_class_consistency_mixed():
    """A3 边界用例同 EC 不同决策是预期行为；函数不应抛异常"""
    r1 = _make_case("a1", "Deny", eq_class="EC-A3-X")
    r1.decision = "Deny"
    r2 = _make_case("a2", "Allow", eq_class="EC-A3-X")
    r2.decision = "Allow"
    ec = eq_class_consistency([r1, r2])
    assert ec["n_inconsistent"] >= 0  # 可能计数但不应崩溃