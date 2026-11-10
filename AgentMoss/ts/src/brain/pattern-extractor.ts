/**
 * Brain pattern extractor — TypeScript implementation.
 *
 * Mirrors Python agent_moss/brain/pattern_extractor.py. Extracts reusable
 * patterns from Layer 3 LLM Deny results:
 *  - static rules (deny_path / deny_command) → accumulated via pattern_candidates
 *    until min_occurrences, then a draft rule is created
 *  - dedup: if the action_detail is already covered by builtin rules, skip
 *
 * Anchor fix: generalized patterns use (?:^|[^a-z0-9_-]) boundaries instead of
 * ^/$ anchors, because the coordinator matches against
 * `combined = actionType + ' ' + actionDetail` with re.search.
 */

import { BrainRuleStore, STATUS_DRAFT } from './rule-store';

export interface ExtractionResult {
  rulesCreated: number;
  patternsRecorded: number;
  skippedReason: string;
  deduped: string[];
}

export interface PatternInfo {
  pattern: string;
  layer: number;
  scope: string;
  ruleType: string;
}

/** LLM 审核回调：返回 true=保留, false=拒绝, null=无法审核（降级保持候选） */
export type BrainReviewFn = (opts: {
  pattern: string;
  layer: number;
  ruleType: string;
  actionDetail: string;
  reason: string;
}) => Promise<{ shouldKeep: boolean; reason?: string } | null> | { shouldKeep: boolean; reason?: string } | null;

export class PatternExtractor {
  private ruleStore: BrainRuleStore;
  private minConfidence: number;
  private minOccurrences: number;
  private builtinPatterns: string[];
  private reviewFn: BrainReviewFn | null;

  constructor(ruleStore: BrainRuleStore, opts?: {
    minConfidence?: number;
    minOccurrences?: number;
    builtinPatterns?: string[];
    review?: BrainReviewFn | null;
  }) {
    this.ruleStore = ruleStore;
    this.minConfidence = opts?.minConfidence ?? 0.9;
    this.minOccurrences = opts?.minOccurrences ?? 3;
    this.builtinPatterns = opts?.builtinPatterns ?? [];
    this.reviewFn = opts?.review ?? null;
  }

  async extract(event: { actionDetail?: string; eventId?: string },
                llmResult: { confidence: number; reason: string; riskType: string; actionDetail?: string }): Promise<ExtractionResult> {
    const result: ExtractionResult = { rulesCreated: 0, patternsRecorded: 0, skippedReason: '', deduped: [] };
    const confidence = llmResult.confidence ?? 0;
    const reason = llmResult.reason ?? '';
    const riskType = llmResult.riskType ?? '';
    const actionDetail = llmResult.actionDetail ?? event.actionDetail ?? '';
    const eventId = event.eventId ?? '';

    if (confidence < this.minConfidence) {
      result.skippedReason = `confidence ${confidence} < ${this.minConfidence}`;
      return result;
    }

    const patterns = this.extractPatterns(actionDetail, reason, riskType);
    if (patterns.length === 0) {
      result.skippedReason = 'no extractable pattern';
      return result;
    }

    for (const p of patterns) {
      // Dedup: action_detail already covered by builtin rules → skip
      if (this.isCoveredByBuiltin(actionDetail)) {
        result.deduped.push(p.pattern);
        continue;
      }

      const count = this.ruleStore.addPatternCandidate(
        p.pattern, p.layer, p.scope, eventId, confidence,
      );
      if (count === 0) {
        // 已审核拒绝：永久排除
        result.deduped.push(p.pattern);
        continue;
      }
      result.patternsRecorded += 1;

      if (count >= this.minOccurrences) {
        const candidates = this.ruleStore.getPatternCandidates(this.minOccurrences);
        const matched = candidates.find(c => c.pattern === p.pattern && c.layer === p.layer);
        if (!matched) continue;

        // LLM 审核（可选）：判定该 pattern 是否值得沉淀
        if (this.reviewFn) {
          let review: Awaited<ReturnType<BrainReviewFn>>;
          try {
            review = await this.reviewFn({
              pattern: p.pattern, layer: p.layer, ruleType: p.ruleType,
              actionDetail, reason,
            });
          } catch {
            review = null;
          }
          if (review === null) {
            // LLM 不可用/失败：降级保持候选，下次再试
            continue;
          }
          if (!review.shouldKeep) {
            this.ruleStore.setPatternReviewStatus(
              p.pattern, p.layer, p.scope, 'rejected', review.reason || 'LLM 审核拒绝',
            );
            result.deduped.push(p.pattern);
            continue;
          }
          this.ruleStore.setPatternReviewStatus(
            p.pattern, p.layer, p.scope, 'approved', review.reason || 'LLM 审核通过',
          );
        }

        this.ruleStore.addRule({
          layer: p.layer,
          ruleType: p.ruleType,
          pattern: p.pattern,
          scope: p.scope,
          source: 'llm_extracted',
          sourceEventIds: eventId ? [eventId] : [],
          confidence: matched.confidence,
          status: STATUS_DRAFT,
          explanation: `从 ${count} 次 LLM Deny 中提取(经审核): ${reason.slice(0, 200)}`,
        });
        this.ruleStore.removePatternCandidate(p.pattern, p.layer, p.scope);
        result.rulesCreated += 1;
      }
    }
    return result;
  }

  extractPatterns(actionDetail: string, reason: string, riskType?: string): PatternInfo[] {
    const patterns: PatternInfo[] = [];
    const detailLower = actionDetail.toLowerCase();
    const seen = new Set<string>();

    // --- Layer 1: sensitive paths in action_detail ---
    const sensitivePathRe = /(\/(?:etc|root)(?:\/[^\s;|&"'<>`$]*)?|(?:[^\s;|&"'<>`$]*)?\/\.ssh\/[^\s;|&"'<>`$]*|(?:[^\s;|&"'<>`$]*)?\/\.aws\/[^\s;|&"'<>`$]*|\S+\.(?:pem|key|p12|pfx|id_rsa|authorized_keys)\b)/;
    const m = detailLower.match(sensitivePathRe);
    if (m) {
      const gen = this.generalizePath(m[1]);
      if (!seen.has(gen)) {
        seen.add(gen);
        patterns.push({ pattern: gen, layer: 1, scope: 'openat', ruleType: 'deny_path' });
      }
    }

    // --- Layer 1: dangerous commands ---
    const dangerousCmdRe = /\b(rm\s+-[a-zA-Z]*r[a-zA-Z]*f|rm\s+--recursive|chmod\s+777|curl\s+[^|]*\|\s*(?:ba)?sh|wget\s+[^|]*\|\s*(?:ba)?sh|mkfs\.|dd\s+if=|>\s*\/dev\/sd)\b/;
    const cmdM = detailLower.match(dangerousCmdRe);
    if (cmdM) {
      const gen = this.generalizeCommand(cmdM[1]);
      const seenKey = `cmd:${gen}`;
      if (!seen.has(seenKey)) {
        seen.add(seenKey);
        patterns.push({ pattern: gen, layer: 1, scope: 'execve', ruleType: 'deny_command' });
      }
    }

    // --- Layer 2: behavior chain patterns ---
    const reasonLower = (reason || '').toLowerCase();
    if (reasonLower.includes('inject') || reasonLower.includes('数据注入')) {
      patterns.push({
        pattern: 'BEHAVIOR_CHAIN:external_read→sensitive_write',
        layer: 2, scope: 'all', ruleType: 'deny_pattern',
      });
    }
    if (reasonLower.includes('reconnaissance') || reasonLower.includes('侦察') || reasonLower.includes('提权')) {
      patterns.push({
        pattern: 'BEHAVIOR_CHAIN:multi_config_read→privilege_action',
        layer: 2, scope: 'all', ruleType: 'deny_pattern',
      });
    }

    // --- Layer 1: extract new sensitive paths from action_detail + reason ---
    // 前缀：空白、引号、左括号、= （URL query 参数如 src=/path）
    // 后缀：空白、引号、右括号、中英文标点、行尾
    const pathPrefix = '(?:^|[\\s"\'(=])';
    const pathBody = '(\\/(?:[a-zA-Z0-9_.-]+\\/)+[a-zA-Z0-9_.-]+)';
    const pathSuffix = '(?=[\\s"\')，。）；;]|$)';
    for (const src of [detailLower, reasonLower]) {
      // 每次循环新建正则，避免全局 lastIndex 状态污染（JS 全局正则跨字符串复用 bug）
      const pathRe = new RegExp(pathPrefix + pathBody + pathSuffix, 'g');
      let mm: RegExpExecArray | null;
      while ((mm = pathRe.exec(src)) !== null) {
        const path = mm[1];
        if (path.split('/').length < 3) continue;  // need >= 2 dir levels
        if (['/dev/null', '/dev/zero', '/dev/random', '/dev/urandom'].includes(path)) continue;
        const gen = this.generalizePath(path);
        if (seen.has(gen)) continue;
        seen.add(gen);
        patterns.push({ pattern: gen, layer: 1, scope: 'openat', ruleType: 'deny_path' });
      }
    }
    return patterns;
  }

  isCoveredByBuiltin(actionDetail: string): boolean {
    if (this.builtinPatterns.length === 0 || !actionDetail) return false;
    for (const pat of this.builtinPatterns) {
      try {
        if (new RegExp(pat, 'i').test(actionDetail)) return true;
      } catch {
        continue;
      }
    }
    return false;
  }

  generalizePath(path: string): string {
    const p = path.toLowerCase();
    if (/\/etc\/(shadow|passwd|sudoers|security|ssh)/.test(p)) {
      return '(?:^|[^a-z0-9_-])etc/(?:shadow|passwd|sudoers|security/|ssh/)';
    }
    if (p.includes('/etc/')) {
      return '(?:^|[^a-z0-9_-])etc/';
    }
    if (p.includes('/root/')) {
      return '(?:^|[^a-z0-9_-])root/\\.(?:ssh|gnupg|aws|config)/';
    }
    if (p.includes('.ssh/')) {
      return '(?:^|[^a-z0-9_-])[\\w./-]*/\\.ssh/';
    }
    if (p.includes('.aws/')) {
      return '(?:^|[^a-z0-9_-])[\\w./-]*/\\.aws/';
    }
    if (/\.(pem|key|p12|pfx|id_rsa|authorized_keys)\b/.test(p)) {
      return '[\\w./-]*\\.(?:pem|key|p12|pfx|id_rsa|authorized_keys)(?:$|[^a-z0-9])';
    }
    const escaped = p.replace(/^\//, '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return `(?:^|[^a-z0-9_-])${escaped}(?:/|\\b)`;
  }

  generalizeCommand(cmd: string): string {
    if (cmd.includes('rm') && cmd.includes('r') && cmd.includes('f')) {
      return 'rm\\s+(?:-[a-zA-Z]*r[a-zA-Z]*f|--recursive)\\s+/';
    }
    if (cmd.includes('chmod')) return 'chmod\\s+777';
    if (cmd.includes('curl') || cmd.includes('wget')) {
      return '(?:curl|wget)\\s+[^|]*\\|\\s*(?:ba)?sh';
    }
    if (cmd.includes('mkfs')) return 'mkfs\\.';
    if (cmd.includes('dd')) return 'dd\\s+if=';
    return cmd.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
}