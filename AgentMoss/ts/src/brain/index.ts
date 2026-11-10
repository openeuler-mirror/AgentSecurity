/**
 * Brain module — TypeScript implementation.
 *
 * Mirrors Python agent_moss/brain/ (rule_store + pattern_extractor + curator).
 * Default OFF: only active when AGENT_MOSS_BRAIN_ENABLED=1 (see isBrainEnabled
 * in ../config). When off, no store is created and checks are no-ops.
 */

import { BrainRuleStore } from './rule-store';
import { PatternExtractor } from './pattern-extractor';

export { BrainRuleStore } from './rule-store';
export { PatternExtractor } from './pattern-extractor';
export { createBrainReviewer, parseReview } from './reviewer';

export interface BrainCheckResult {
  ruleId: string;
  pattern: string;
  explanation: string;
  confidence: number;
}

/**
 * Check active brain rules against an action. Layer 1 = current action only;
 * Layer 2 = may consult action history. Returns the first matching rule.
 */
export function checkBrainRules(
  store: BrainRuleStore | null,
  opts: {
    layer: number;
    actionType: string;
    actionDetail: string;
    actionHistory?: { actionType: string; actionDetail: string }[];
  },
): BrainCheckResult | null {
  if (!store) return null;
  const rules = store.getActiveRules(opts.layer);
  if (rules.length === 0) return null;

  const combined = `${opts.actionType} ${opts.actionDetail}`;
  for (const rule of rules) {
    try {
      if (new RegExp(rule.pattern, 'i').test(combined)) {
        // Layer 2 rules may need history context
        if (opts.layer === 2 && opts.actionHistory) {
          if (!checkLayer2Context(rule.pattern, opts.actionHistory, opts.actionDetail)) {
            continue;
          }
        }
        store.recordTrigger(rule.id);
        return {
          ruleId: rule.id,
          pattern: rule.pattern,
          explanation: rule.explanation,
          confidence: rule.confidence,
        };
      }
    } catch {
      continue;
    }
  }
  return null;
}

function checkLayer2Context(
  pattern: string,
  actionHistory: { actionType: string; actionDetail: string }[],
  actionDetail: string,
): boolean {
  if (pattern.startsWith('BEHAVIOR_CHAIN:')) {
    const chainType = pattern.replace('BEHAVIOR_CHAIN:', '');
    if (chainType === 'external_read→sensitive_write') {
      const hasExternalRead = actionHistory.slice(-5).some(h =>
        /curl|wget|http/i.test(h.actionDetail ?? ''));
      const isSensitiveWrite = /\.ssh|\.gnupg|authorized_keys|bashrc|profile/i.test(actionDetail);
      return hasExternalRead && isSensitiveWrite;
    }
    if (chainType === 'multi_config_read→privilege_action') {
      const configReads = actionHistory.slice(-5).filter(h =>
        /\/etc\/|config|\.conf|\.yaml|\.json/i.test(h.actionDetail ?? '')).length;
      const isPrivilege = /sudo|su |chmod|chown/i.test(actionDetail);
      return configReads >= 2 && isPrivilege;
    }
    return false;
  }
  return true;
}