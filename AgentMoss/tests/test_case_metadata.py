"""用例元数据漂移看护 —— `expected_risk_type` 必须与实际判定一致。

**为什么需要这个看护**：常规用例（`test_all_cases.py` / `json-cases.test.ts`）
只断言 `expected_decision` 和 `expected_risk_level`，**从不校验
`expected_layers` 与 `expected_risk_type`**。于是出现了一类"假绿"：

  `tests/cases/l2/logic-08-userdel-no-consent.json` 声明
  `expected_layers: ["1.2"]` + `risk_type: "consent_missing"`（自称在测 L2 授权），
  实际被 L1 的 `userdel` 规则先拦下，返回 `1.1` + `script_execution`。
  两者都 Deny、都是 high —— 测试全绿，但**用例根本没测到它声称要测的东西**。

这个看护锁定 `expected_risk_type`（拦截原因分类，语义明确）。
`expected_layers` 暂不校验：层标签的书写口径不统一（`"1.1"` / `"L1.1"` / `"1.2"`），
且 `violated_layers` 在多余命中时内容不稳定，贸然断言会制造大量无关失败。

**已知偏差清单**：`tests/parity/known_risk_type_drift.json`。
偏差集合必须与清单**完全一致**——
  - 新增漂移（用例声明与实际不符且不在清单）→ 失败
  - 清单过期（偏差已修复）→ 失败，提示删除该条
  - 清单条目的内容变了（expected/actual 任一变化）→ 失败
清理历史债时，从清单删掉对应条目即可。

"""

import json
from pathlib import Path

import pytest

import test_all_cases as T

CASES = Path(__file__).parent / "cases"
DRIFT_FILE = Path(__file__).parent / "parity" / "known_risk_type_drift.json"
SUBS = ("l1", "l2", "agent")


def _load_known_drift() -> dict[str, tuple[str, str]]:
    """清单条目 → (用例声明, Python 实际判定)。"""
    data = json.loads(DRIFT_FILE.read_text(encoding="utf-8"))
    return {
        str(r["case"]): (str(r.get("expected") or ""), str(r.get("python") or ""))
        for r in data.get("drift", [])
    }


KNOWN_DRIFT = _load_known_drift()


def _case_files() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for sub in SUBS:
        d = CASES / sub
        if d.is_dir():
            out.extend((sub, p.name) for p in sorted(d.glob("*.json")))
    return out


@pytest.mark.parametrize("sub,case_file", _case_files())
def test_expected_risk_type_matches_actual(sub, case_file, default_config, linux_profile):
    """用例声明的 risk_type 必须等于实际判定（已知偏差清单除外）。"""
    case = json.loads((CASES / sub / case_file).read_text(encoding="utf-8"))
    case = T._expand_placeholder(case)
    if "expected_risk_type" not in case:
        pytest.skip("用例未声明 expected_risk_type")

    result, _ = T._run_case(case, default_config, linux_profile)
    key = f"{sub}/{case_file}"
    expected = str(case.get("expected_risk_type") or "").strip()
    actual = str(result.get("risk_type") or "").strip()

    known = KNOWN_DRIFT.get(key)
    if expected == actual:
        # 本端已一致。清单条目若记录了「本端曾不符」，说明历史债已修复 → 提示删除。
        assert known is None or known[1] == expected, (
            f"[{key}] 该偏差已修复（期望与实际都是 {expected!r}），"
            f"请从 {DRIFT_FILE.name} 的 drift 列表删除这一条。"
        )
        return

    assert known is not None, (
        f"[{key}] 新增 risk_type 漂移：用例声明 {expected!r}，实际判定 {actual!r}。\n"
        f"两种处理：\n"
        f"  1. 用例声明写错了 → 改用例；\n"
        f"  2. 引擎分类该改 → 改引擎；\n"
        f"  3. 确认是口径差异（非行为错误）→ 登记进 {DRIFT_FILE.name}。"
    )
    assert known == (expected, actual), (
        f"[{key}] 漂移内容变化：清单记录 {known}，当前为 {(expected, actual)}。"
        f"如属预期，更新清单条目。"
    )
