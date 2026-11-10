/**
 * L2.2 model checking — LTL finite-trace evaluator + mc_rules check.
 * Mirrors Python agent_moss/engine/formal_engine/ltl.py EXACTLY.
 *
 * Data source: agent_moss/rules/mc_rules.json (single source of truth, dual-end):
 * - ap_patterns: atomic proposition → regex list (used by labelEvent)
 * - rules: [{id, type, formula (prefix AST), risk_level, action, reason}]
 *
 * LTL formula AST (nested array; evaluated at trace position 0; formula satisfied = attack):
 *   ["ap", name]        atomic proposition: name ∈ L(trace[i])
 *   ["!", inner]        negation
 *   ["&", l, r]         conjunction
 *   ["|", l, r]         disjunction
 *   ["->", l, r]        implication (!l | r)
 *   ["X", inner]        next: i+1 exists and inner holds at i+1
 *   ["G", inner]        globally: holds for all j ∈ [i, n]
 *   ["F", inner]        finally: holds for some j ∈ [i, n]
 *   ["U", l, r]         until: some j where r holds, and l holds throughout [i, j)
 *
 * witness semantics (fixes "history-global match → permanent-deny lock", aligned
 * with witnessIdx in properties.ts; see docs/DETECTION_METHODS.md 6.3):
 *   Real-time judgment only flags when the current action (aNext = last node) is
 *   the necessary witness — the formula holds on the trace WITH the current
 *   action but NOT on the trace WITHOUT it. Random full patterns in history no
 *   longer block benign subsequent actions. Low-frequency review
 *   (witnessIdx undefined) keeps "formula holds on whole trace = violation".
 */

import { loadMC } from '../../infra/rules-loader';
import type { MultiSessionGraph, PropertyViolation } from './ir';
import { allNodes } from './ir';
import { allCandidates } from './decode';

let AP_RE: Record<string, RegExp[]> | null = null;

function compileAps(apPatterns: Record<string, string[]>): void {
  if (AP_RE) return;
  AP_RE = {};
  for (const [name, pats] of Object.entries(apPatterns || {})) {
    AP_RE[name] = (pats as string[]).map(p => new RegExp(p, 'i'));
  }
}

/** labelEvent: extract atomic propositions satisfied by an action text.
 * 抗编码绕过（对齐 Python decode 旁路）：除原文外对解码候选（base64/URL 编码/
 * 数值八进制/反序）也跑 AP 正则，命中即算该 AP。平凡命令零变化，防误报。 */
export function labelEvent(actionDetail: string): Set<string> {
  if (!AP_RE) compileAps((loadMC().ap_patterns || {}) as Record<string, string[]>);
  const candidates = allCandidates(actionDetail);
  const hits = new Set<string>();
  for (const [name, pats] of Object.entries(AP_RE || {})) {
    for (const c of candidates) {
      const m = pats.some((p) => p.test(c));
      if (m) {
        hits.add(name);
        break;
      }
    }
  }
  return hits;
}

/** Evaluate an LTL formula at position pos on trace (list of AP sets; finite-trace semantics). */
export function evaluateLTL(formula: any[], trace: Set<string>[], pos: number): boolean {
  const op = formula[0];
  switch (op) {
    case 'ap': return trace[pos].has(formula[1]);
    case '!': return !evaluateLTL(formula[1], trace, pos);
    case '&': return evaluateLTL(formula[1], trace, pos) && evaluateLTL(formula[2], trace, pos);
    case '|': return evaluateLTL(formula[1], trace, pos) || evaluateLTL(formula[2], trace, pos);
    case '->': return !evaluateLTL(formula[1], trace, pos) || evaluateLTL(formula[2], trace, pos);
    case 'X': return pos + 1 < trace.length && evaluateLTL(formula[1], trace, pos + 1);
    case 'G': {
      for (let j = pos; j < trace.length; j++) {
        if (!evaluateLTL(formula[1], trace, j)) return false;
      }
      return true;
    }
    case 'F': {
      for (let j = pos; j < trace.length; j++) {
        if (evaluateLTL(formula[1], trace, j)) return true;
      }
      return false;
    }
    case 'U': {
      for (let j = pos; j < trace.length; j++) {
        if (evaluateLTL(formula[2], trace, j)) {
          for (let k = pos; k < j; k++) {
            if (!evaluateLTL(formula[1], trace, k)) return false;
          }
          return true;
        }
      }
      return false;
    }
    default: return false;
  }
}

function ruleViolates(rule: any, traceWith: Set<string>[], witnessMode: boolean): boolean {
  const formula = rule?.formula;
  if (!Array.isArray(formula) || formula.length === 0) return false;
  const satWith = evaluateLTL(formula, traceWith, 0);
  if (!satWith) return false;
  if (witnessMode && traceWith.length > 1) {
    const traceWithout = traceWith.slice(0, -1);
    if (evaluateLTL(formula, traceWithout, 0)) return false; // history already satisfied → not necessary witness
  }
  return true;
}

/** L2.2 LTL rule check: build an event trace from graph nodes, evaluate mc_rules. */
export function checkMCRules(graph: MultiSessionGraph): PropertyViolation[] {
  const violations: PropertyViolation[] = [];
  const nodes = allNodes(graph);
  if (nodes.length === 0) return violations;
  const mc = loadMC();
  const rules: any[] = mc.rules || [];
  if (rules.length === 0) return violations;

  const trace: Set<string>[] = nodes.map(n => labelEvent(n.actionDetail));
  const witnessMode = graph.witnessIdx !== undefined;
  for (const rule of rules) {
    // 仅评估 LTL 型且未被 console 关闭的规则
    if (rule?.type !== 'ltl' || !(rule.enabled !== false)) continue;
    if (ruleViolates(rule, trace, witnessMode)) {
      violations.push({
        propertyId: String(rule.id || 'mc-ltl'),
        reason: String(rule.reason || 'L2.2 模型检测规则命中'),
        riskLevel: String(rule.risk_level || 'high'),
        path: nodes
          .filter(n => labelEvent(n.actionDetail).size > 0)
          .slice(-3)
          .map(n => ({ sessionId: n.sessionId, seq: n.seq, detail: n.actionDetail.slice(0, 60) })),
      });
      if (witnessMode) return violations; // 实时判定命中即停（与 L2 短路语义一致）
    }
  }
  return violations;
}
