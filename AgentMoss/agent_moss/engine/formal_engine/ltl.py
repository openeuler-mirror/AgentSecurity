"""L2.2 模型检测 — LTL 有限迹求值器 + mc_rules 规则检查（镜像 TS ltl.ts）。

数据源：agent_moss/rules/mc_rules.json（单一事实源，双端共用）：
- ap_patterns: 原子命题 → 正则列表（labelEvent 用）
- rules: [{id, type, formula(前缀 AST), risk_level, action, reason}]

LTL 公式 AST（嵌套列表，在事件迹位置 0 处评估，公式满足 = 攻击存在）：
  ["ap", name]        原子命题：name ∈ L(trace[i])
  ["!", inner]        否定
  ["&", l, r]         合取
  ["|", l, r]         析取
  ["->", l, r]        蕴含（!l | r）
  ["X", inner]        next：i+1 存在且 inner 在 i+1 成立
  ["G", inner]        globally：所有 j ∈ [i, n] 成立
  ["F", inner]        finally：存在 j ∈ [i, n] 成立
  ["U", l, r]         until：存在 j 使 r 在 j 成立，且 [i, j) 内 l 一直成立

witness 语义（修复"历史全局匹配 → 永久拒绝锁定"FP，与 properties.py 的
witness_idx 对齐）：
  实时判定只当**当前动作（a_next = 图末节点）是使公式从不满足变为满足的必要
  witness**时才判违规：公式在"含当前动作的迹"上成立，且在"不含当前动作的迹"
  上不成立 → 当前动作触发了攻击模式。历史中已随机出现的完整模式不再误伤后续
  良性动作。低频回顾（witness_idx=None）时保留"公式在整个迹上成立即违规"。
"""

from __future__ import annotations

import re
from typing import Any

from .ir import MultiSessionGraph, PropertyViolation

_AP_RE: dict[str, list[re.Pattern]] = {}


def _load_mc() -> dict[str, Any]:
    """加载 mc_rules.json（幂等；缺失/损坏回退空）。"""
    from ...rules_loader import load_mc
    return load_mc()


def _compile_aps(ap_patterns: dict) -> None:
    """编译原子命题正则（幂等）。"""
    global _AP_RE
    if _AP_RE:
        return
    for name, pats in (ap_patterns or {}).items():
        _AP_RE[name] = [re.compile(p, re.IGNORECASE) for p in pats]


def label_event(action_detail: str) -> set[str]:
    """labelEvent：从动作文本提取命中的原子命题集合（复用 mc_rules ap_patterns）。

    抗编码绕过（对齐 P1 decode 旁路，见 decode.py）：除原文外，对 action_detail
    的**解码候选**（base64 字面量 / URL 编码 / 数值八进制 / 反序等）逐个也跑 AP
    正则，命中即算该 AP。只对"有明显编码痕迹"的文本解码（decode 设计约束，
    防误报），平凡命令零变化；`echo c3VicHJvY2Vzcw== | base64 -d | bash` 这类
    编码绕过现在能命中 execute_file，而不是漏检。
    """
    global _AP_RE
    if not _AP_RE:
        _compile_aps(_load_mc().get("ap_patterns", {}))
    try:
        from .decode import _all_candidates
        candidates = _all_candidates(action_detail)
    except Exception:
        candidates = [action_detail]  # decode 不可用时仅原文匹配（兼容/降级）

    hits: set[str] = set()
    for name, pats in _AP_RE.items():
        for c in candidates:
            for p in pats:
                if p.search(c):
                    hits.add(name)
                    break
            if name in hits:
                break
    return hits


def evaluate_ltl(formula: list, trace: list[set[str]], pos: int) -> bool:
    """在迹 trace（list[set[ap]]）的位置 pos 处递归评估 LTL 公式（有限迹语义）。"""
    op = formula[0]
    if op == "ap":
        return formula[1] in trace[pos]
    if op == "!":
        return not evaluate_ltl(formula[1], trace, pos)
    if op == "&":
        return evaluate_ltl(formula[1], trace, pos) and evaluate_ltl(formula[2], trace, pos)
    if op == "|":
        return evaluate_ltl(formula[1], trace, pos) or evaluate_ltl(formula[2], trace, pos)
    if op == "->":
        return (not evaluate_ltl(formula[1], trace, pos)) or evaluate_ltl(formula[2], trace, pos)
    if op == "X":
        return pos + 1 < len(trace) and evaluate_ltl(formula[1], trace, pos + 1)
    if op == "G":
        return all(evaluate_ltl(formula[1], trace, j) for j in range(pos, len(trace)))
    if op == "F":
        return any(evaluate_ltl(formula[1], trace, j) for j in range(pos, len(trace)))
    if op == "U":
        for j in range(pos, len(trace)):
            if evaluate_ltl(formula[2], trace, j):
                return all(evaluate_ltl(formula[1], trace, k) for k in range(pos, j))
        return False
    return False


def _rule_violates(rule: dict, trace_with: list[set[str]], witness_mode: bool) -> bool:
    """单条规则是否违规。

    witness_mode（实时判定）：当前动作（末节点）必须是必要 witness——公式在
    含当前动作的迹上成立，且在不含当前动作的迹上不成立。
    回顾模式（witness_idx=None）：公式在整个迹上成立即违规。
    """
    formula = rule.get("formula")
    if not isinstance(formula, list) or not formula:
        return False
    sat_with = evaluate_ltl(formula, trace_with, 0)
    if not sat_with:
        return False
    if witness_mode and len(trace_with) > 1:
        trace_without = trace_with[:-1]
        if evaluate_ltl(formula, trace_without, 0):
            return False  # 历史已成立 → 当前动作不是必要 witness → 不误伤
    return True


def check_mc_rules(graph: MultiSessionGraph) -> list[PropertyViolation]:
    """L2.2 LTL 规则检查：对图节点序列构建事件迹，逐条评估 mc_rules。

    witness 语义由 graph.witness_idx 决定（engine.verify 在带 a_next 时设置）：
    非 None → 实时判定（末节点 = 当前动作，必要 witness）；None → 低频回顾。
    """
    violations: list[PropertyViolation] = []
    nodes = graph.all_nodes
    if not nodes:
        return violations
    mc = _load_mc()
    rules = mc.get("rules", [])
    if not rules:
        return violations
    trace = [label_event(n.action_detail) for n in nodes]
    witness_mode = graph.witness_idx is not None
    for rule in rules:
        if rule.get("type") != "ltl" or not rule.get("enabled", True):
            continue  # 仅评估 LTL 型且未被 console 关闭的规则
            continue
        if _rule_violates(rule, trace, witness_mode):
            violations.append(PropertyViolation(
                property_id=rule.get("id", "mc-ltl"),
                reason=rule.get("reason", "L2.2 模型检测规则命中"),
                risk_level=rule.get("risk_level", "high"),
                path=[(n.session_id, n.seq, n.action_detail[:60])
                      for n in nodes if label_event(n.action_detail)][-3:],
            ))
            if witness_mode:
                return violations  # 实时判定命中即停（与 L2 短路语义一致）
    return violations
