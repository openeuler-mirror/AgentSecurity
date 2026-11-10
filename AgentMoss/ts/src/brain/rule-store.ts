/**
 * Brain rule store — TypeScript implementation.
 *
 * Mirrors Python agent_moss/brain/rule_store.py but stores rules in a JSON file
 * (Python uses SQLite; TS has no sqlite dependency). Semantics are equivalent:
 * rules have a status lifecycle (draft → approved → active → disputed/stale →
 * archived), and pattern_candidates accumulate occurrences before a draft rule
 * is created.
 *
 * Storage: ~/.agentmoss/brain/rules.json (matches Python DB location ~/.agentmoss)
 *   env override: AGENT_MOSS_BRAIN_RULES_PATH (tests use this to isolate)
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

export const BRAIN_DIR = '.';
export const DEFAULT_RULES_PATH = join(homedir(), '.agentmoss', 'brain', 'rules.json');
const ENV_RULES_PATH = 'AGENT_MOSS_BRAIN_RULES_PATH';

export const STATUS_DRAFT = 'draft';
export const STATUS_APPROVED = 'approved';
export const STATUS_ACTIVE = 'active';
export const STATUS_DISPUTED = 'disputed';
export const STATUS_STALE = 'stale';
export const STATUS_ARCHIVED = 'archived';
export const STATUS_REJECTED = 'rejected';

export interface BrainRule {
  id: string;
  layer: number;              // 1 = feature match, 2 = logic rule
  ruleType: string;           // deny_path | deny_command | deny_pattern | allow_pattern
  pattern: string;
  scope: string;              // openat | execve | connect | all
  source: string;             // llm_extracted | user | central
  sourceEventIds: string[];
  confidence: number;
  status: string;
  createdAt: number;
  lastTriggeredAt: number;
  triggerCount: number;
  disputedCount: number;
  explanation: string;
  originNode: string;
}

interface PatternCandidate {
  pattern: string;
  layer: number;
  scope: string;
  sourceEventIds: string[];
  confidence: number;
  occurrenceCount: number;
  firstSeenAt: number;
  lastSeenAt: number;
  reviewStatus: string;    // pending | approved | rejected
  reviewReason: string;
  reviewedAt: number;
}

interface BrainRulesFile {
  version: number;
  rules: BrainRule[];
  pattern_candidates: PatternCandidate[];
}

function getRulesPath(): string {
  const envPath = process.env[ENV_RULES_PATH];
  if (envPath) return envPath;
  return DEFAULT_RULES_PATH;
}

function uuid(): string {
  // crypto.randomUUID is available in Node 14.17+
  try {
    return (crypto as any).randomUUID();
  } catch {
    return `rule_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
  }
}

export class BrainRuleStore {
  private path: string;
  private data: BrainRulesFile;

  constructor(path?: string) {
    this.path = path || getRulesPath();
    this.data = this.load();
  }

  private load(): BrainRulesFile {
    if (!existsSync(this.path)) {
      return { version: 1, rules: [], pattern_candidates: [] };
    }
    try {
      const raw = JSON.parse(readFileSync(this.path, 'utf-8'));
      return {
        version: raw.version || 1,
        rules: raw.rules || [],
        pattern_candidates: raw.pattern_candidates || [],
      };
    } catch {
      return { version: 1, rules: [], pattern_candidates: [] };
    }
  }

  private save(): void {
    const dir = this.path.substring(0, this.path.lastIndexOf('/'));
    if (dir) mkdirSync(dir, { recursive: true });
    writeFileSync(this.path, JSON.stringify(this.data, null, 2), 'utf-8');
  }

  addRule(rule: Partial<BrainRule> & { pattern: string; layer: number }): string {
    const now = Date.now();
    const full: BrainRule = {
      id: rule.id || uuid(),
      layer: rule.layer,
      ruleType: rule.ruleType || 'deny_pattern',
      pattern: rule.pattern,
      scope: rule.scope || 'all',
      source: rule.source || 'llm_extracted',
      sourceEventIds: rule.sourceEventIds || [],
      confidence: rule.confidence || 0,
      status: rule.status || STATUS_DRAFT,
      createdAt: rule.createdAt || now,
      lastTriggeredAt: rule.lastTriggeredAt || 0,
      triggerCount: rule.triggerCount || 0,
      disputedCount: rule.disputedCount || 0,
      explanation: rule.explanation || '',
      originNode: rule.originNode || 'local',
    };
    this.data.rules.push(full);
    this.save();
    return full.id;
  }

  approveRule(ruleId: string): void {
    const rule = this.getRule(ruleId);
    if (!rule) throw new Error(`规则不存在: ${ruleId}`);
    if (rule.status !== STATUS_DRAFT) throw new Error(`只有 draft 状态可审核，当前: ${rule.status}`);
    rule.status = STATUS_ACTIVE;
    this.save();
  }

  rejectRule(ruleId: string): void {
    const rule = this.getRule(ruleId);
    if (!rule) throw new Error(`规则不存在: ${ruleId}`);
    if (rule.status !== STATUS_DRAFT) throw new Error(`只有 draft 状态可拒绝，当前: ${rule.status}`);
    rule.status = STATUS_REJECTED;
    this.save();
  }

  getRule(ruleId: string): BrainRule | undefined {
    return this.data.rules.find(r => r.id === ruleId);
  }

  getActiveRules(layer?: number): BrainRule[] {
    return this.data.rules.filter(r => r.status === STATUS_ACTIVE && (layer === undefined || r.layer === layer));
  }

  getDraftRules(): BrainRule[] {
    return this.data.rules
      .filter(r => r.status === STATUS_DRAFT)
      .sort((a, b) => b.createdAt - a.createdAt);
  }

  recordTrigger(ruleId: string): void {
    const rule = this.getRule(ruleId);
    if (!rule) return;
    rule.triggerCount += 1;
    rule.lastTriggeredAt = Date.now();
    this.save();
  }

  // --- pattern_candidates ---

  addPatternCandidate(pattern: string, layer: number, scope: string,
                      sourceEventId: string, confidence: number): number {
    const now = Date.now();
    const existing = this.data.pattern_candidates.find(
      c => c.pattern === pattern && c.layer === layer && c.scope === scope,
    );
    if (existing) {
      // 已审核拒绝：不累计（永久排除）
      if (existing.reviewStatus === 'rejected') return 0;
      existing.occurrenceCount += 1;
      existing.lastSeenAt = now;
      existing.sourceEventIds.unshift(sourceEventId);
      this.save();
      return existing.occurrenceCount;
    }
    this.data.pattern_candidates.push({
      pattern, layer, scope,
      sourceEventIds: [sourceEventId],
      confidence, occurrenceCount: 1,
      firstSeenAt: now, lastSeenAt: now,
      reviewStatus: 'pending', reviewReason: '', reviewedAt: 0,
    });
    this.save();
    return 1;
  }

  getPatternCandidates(minOccurrences = 3): PatternCandidate[] {
    return this.data.pattern_candidates
      .filter(c => c.occurrenceCount >= minOccurrences && c.reviewStatus !== 'rejected')
      .sort((a, b) => b.occurrenceCount - a.occurrenceCount);
  }

  getPendingReviewCandidates(minOccurrences = 3): PatternCandidate[] {
    return this.data.pattern_candidates
      .filter(c => c.occurrenceCount >= minOccurrences && c.reviewStatus === 'pending')
      .sort((a, b) => b.occurrenceCount - a.occurrenceCount);
  }

  isExcludedPattern(pattern: string, layer: number, scope: string): boolean {
    const c = this.data.pattern_candidates.find(
      c => c.pattern === pattern && c.layer === layer && c.scope === scope,
    );
    return !!c && c.reviewStatus === 'rejected';
  }

  setPatternReviewStatus(pattern: string, layer: number, scope: string,
                         status: string, reason = ''): void {
    const c = this.data.pattern_candidates.find(
      c => c.pattern === pattern && c.layer === layer && c.scope === scope,
    );
    if (c) {
      c.reviewStatus = status;
      c.reviewReason = reason;
      c.reviewedAt = Date.now();
      this.save();
    }
  }

  removePatternCandidate(pattern: string, layer: number, scope: string): void {
    this.data.pattern_candidates = this.data.pattern_candidates.filter(
      c => !(c.pattern === pattern && c.layer === layer && c.scope === scope),
    );
    this.save();
  }

  getStats(): Record<string, unknown> {
    const count = (status: string) => this.data.rules.filter(r => r.status === status).length;
    return {
      draft: count(STATUS_DRAFT),
      approved: count(STATUS_APPROVED),
      active: count(STATUS_ACTIVE),
      disputed: count(STATUS_DISPUTED),
      stale: count(STATUS_STALE),
      archived: count(STATUS_ARCHIVED),
      rejected: count(STATUS_REJECTED),
      total: this.data.rules.length,
      by_layer: {
        1: this.data.rules.filter(r => r.layer === 1 && r.status === STATUS_ACTIVE).length,
        2: this.data.rules.filter(r => r.layer === 2 && r.status === STATUS_ACTIVE).length,
      },
      pattern_candidates: this.data.pattern_candidates.length,
    };
  }
}