/**
 * Dangerous frequent-pattern mining (PatternMiner) — TS mirror of Python pattern_miner.py.
 *
 * 从已发生行为中自动发现组合攻击前序（突破预置链盲区）。
 * 1. 投影 + 压缩：stage 序列 + 连续重复压缩
 * 2. 轻量 PrefixSpan 挖掘跨 session 频繁有序子序列
 * 3. 危险标注：含 PRIVESC/EXFIL/LISTEN 或 CRED↔LISTEN 才标记候选
 */
import { markStage } from './builder';

const DANGER_STAGES = new Set(['PRIVESC', 'EXFIL', 'LISTEN']);
const SENSITIVE_PAIRS = new Set(['CRED|LISTEN', 'LISTEN|CRED']);

export interface DiscoveredPattern {
  pattern: string[];
  support: number;
  risk: string;
  reason: string;
}

/** 把单 session 动作序列投影成压缩后的 stage 序列。 */
export function projectStages(actionHistory: { actionType?: string; actionDetail?: string }[]): string[] {
  const stages: string[] = [];
  let prev: string | null = null;
  for (const act of actionHistory) {
    const s = markStage(String(act.actionDetail || ''));
    if (s && s !== prev) {
      stages.push(s);
      prev = s;
    }
  }
  return stages;
}

function isDangerous(pat: string[]): boolean {
  if (pat.some(s => DANGER_STAGES.has(s))) return true;
  for (let i = 0; i < pat.length - 1; i++) {
    if (SENSITIVE_PAIRS.has(pat[i] + '|' + pat[i + 1])) return true;
  }
  return false;
}

export function mineDangerousPatterns(
  sessions: { sessionId?: string; actionHistory?: { actionType?: string; actionDetail?: string }[] }[],
  minSup = 2,
  maxLen = 4,
): DiscoveredPattern[] {
  // 1. 投影 + 压缩
  const seqs: [string, string[]][] = [];
  for (const s of sessions) {
    const sid = String(s.sessionId || '');
    const stages = projectStages(s.actionHistory || []);
    if (stages.length > 0) seqs.push([sid, stages]);
  }
  if (seqs.length === 0) return [];

  // 2. 轻量 PrefixSpan（递归前缀投影）
  const results = new Map<string, number>();

  const mine = (prefix: string[], projected: [string, string[]][]) => {
    if (prefix.length > 0) {
      results.set(prefix.join('→'), projected.length);
    }
    if (prefix.length >= maxLen) return;
    const itemSids = new Map<string, Set<string>>();
    for (const [sid, suffix] of projected) {
      const seen = new Set<string>();
      for (const it of suffix) {
        if (!seen.has(it)) {
          seen.add(it);
          if (!itemSids.has(it)) itemSids.set(it, new Set());
          itemSids.get(it)!.add(sid);
        }
      }
    }
    for (const [it, sids] of [...itemSids.entries()].sort()) {
      if (sids.size >= minSup) {
        const next: [string, string[]][] = [];
        for (const [sid, suffix] of projected) {
          const idx = suffix.indexOf(it);
          if (idx >= 0) next.push([sid, suffix.slice(idx + 1)]);
        }
        mine([...prefix, it], next);
      }
    }
  };

  mine([], seqs);

  // 3. 危险标注 + 排序
  const out: DiscoveredPattern[] = [];
  for (const [key, support] of results) {
    const pat = key.split('→');
    if (pat.length < 2 || !isDangerous(pat)) continue;
    const risk = pat.some(s => s === 'PRIVESC' || s === 'EXFIL') ? 'high' : 'medium';
    out.push({
      pattern: pat,
      support,
      risk,
      reason: `跨 session 频繁出现组合 ${pat.join('→')}（${support} 个 session），预置链未直接覆盖，疑似攻击前序`,
    });
  }
  out.sort((a, b) => b.support - a.support || b.pattern.length - a.pattern.length);
  return out;
}