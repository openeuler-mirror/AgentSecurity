/**
 * Script-engine ShellBackend — static shell (bash/sh/zsh) parser → IR.
 * Mirrors Python agent_moss/engine/script_engine/backends/shell_backend.py.
 *
 * Upgrades over old branch_aware_preprocess in script-content-analyzer.ts:
 *  1. case supports ANY selector ($1 / $MODE / ${1}), bindable from entryArgs.
 *  2. if supports string-equality conditions  [ "$1" = "clean" ]  etc.
 *  3. loops (while/for) body kept reachable (conservative).
 *  4. child script calls extracted WITH args (bash child.sh backup → args=['backup']),
 *     enabling cross-script arg passing (fixes old sub-call arg loss bug).
 */

import { emptyIR, ScriptCall, ScriptIR } from '../ir';
import { LanguageBackend } from './index';
import { symbolicProcess } from '../symbolic';

// ==================== arg binding ====================

function bindPositionalArgs(content: string, args: string[]): string {
  if (!args.length) return content;
  const allArgs = args.join(' ');

  content = content.replace(/\$\{(\d+|@|\*)(?::?[-]?([^}]*))?\}/g, (full, kind: string, defv: string) => {
    if (kind === '@' || kind === '*') return allArgs;
    if (!/^\d+$/.test(kind)) return full;
    const idx = parseInt(kind, 10);
    if (1 <= idx && idx <= args.length) return args[idx - 1];
    return defv !== undefined ? defv : '';
  });
  content = content.replace(/\$\{(\d+)\}/g, (full, kind: string) => {
    const idx = parseInt(kind, 10);
    if (1 <= idx && idx <= args.length) return args[idx - 1];
    return '';
  });
  content = content.replace(/\$(\d+)/g, (full, kind: string) => {
    const idx = parseInt(kind, 10);
    if (1 <= idx && idx <= args.length) return args[idx - 1];
    return '';
  });
  content = content.replace(/\$[@*]/g, allArgs);
  return content;
}

// ==================== case parsing ====================

function findSelectorValue(selector: string, args: string[] | null): string | null {
  if (!args || !args.length) return null;
  const m = selector.match(/^\$\{?(\d+)\}?$/);
  if (m) {
    const idx = parseInt(m[1], 10);
    if (1 <= idx && idx <= args.length) return args[idx - 1];
    return null;
  }
  return null; // $MODE named var — not statically bindable
}

function splitCaseBody(body: string): { label: string; body: string }[] {
  const lines = body.split('\n');
  const branches: { label: string; body: string }[] = [];
  let cur: { label: string; body: string } | null = null;
  for (const ln of lines) {
    const stripped = ln.trim();
    if (/^[\w:-]+\s*\(\)\s*\{/.test(stripped)) continue; // fn def
    const m = stripped.match(/^([^()]+?)\s*\)\s*(.*)$/);
    if (m) {
      const pat = m[1].trim().replace(/^["']|["']$/g, '');
      const inline = m[2].trim();
      if (pat) {
        if (cur) branches.push(cur);
        cur = { label: pat, body: inline };
      }
      continue;
    }
    if (cur) {
      cur.body += (cur.body ? '\n' + ln : ln);
      if (stripped.endsWith(';;')) {
        branches.push(cur);
        cur = null;
      }
    }
  }
  if (cur && cur.body.trim()) {
    if (!branches.includes(cur)) branches.push(cur);
  }
  return branches;
}

function parseCase(content: string, args: string[] | null): string | null {
  const m = content.match(/\bcase\s+(\$\{?\d+\}?|[A-Za-z_]\w*|\$[A-Za-z_]\w*)\s+in/i);
  if (!m) return null;
  const selector = m[1].trim();
  const val = findSelectorValue(selector, args);
  if (val === null) return null;

  const lines = content.split('\n');
  // 深度配对找本层 esac（嵌套 case 时不能 indexOf 第一个）
  const endMatch = findCaseEndInLines(lines, 0);
  if (endMatch === -1) return null;
  const bodyLines = lines.slice(1, endMatch);
  const body = bodyLines.join('\n');

  const hasNested = /\bcase\s+/.test(body) || /\bif\s+/.test(body);
  let final: string | null;
  if (hasNested) {
    // 外层仍剪枝：选中分支整体保留（内层候选不细化），未选中剔除
    final = splitNestedCaseBranches(bodyLines, val);
    if (final === null) return null;
  } else {
    const branches = splitCaseBody(body);
    let selected: string | null = null;
    let fallback = '';
    for (const b of branches) {
      const values = b.label.split('|').map(v => v.trim()).filter(Boolean);
      if (values.includes('*')) fallback = b.body;
      else if (values.includes(val)) selected = b.body;
    }
    final = selected !== null ? selected : (fallback || null);
    if (final === null) return null;
  }

  const prefix = content.slice(0, m.index ?? 0);
  const suffix = lines.slice(endMatch + 1).join('\n');
  return `${prefix}\n${final}\n${suffix}`;
}

/** Depth-match: find the line index of the esac paired with the case at headerLine. */
function findCaseEndInLines(lines: string[], headerLine: number): number {
  let depth = 0;
  for (let idx = headerLine; idx < lines.length; idx++) {
    const ln = lines[idx];
    const opens = (ln.match(/\bcase\b/g) || []).length;
    const closes = (ln.match(/\besac\b/g) || []).length;
    depth += opens - closes;
    if (depth <= 0 && idx > headerLine) return idx;
  }
  return -1;
}

/** Nested case: outer branch selection, preserving selected branch body (incl. nested). */
function splitNestedCaseBranches(bodyLines: string[], selectorVal: string): string | null {
  let depth = 0;
  let curPat: string | null = null;
  let curBody: string[] = [];
  let selected: string | null = null;
  let fallback: string | null = null;

  const flush = () => {
    if (curPat === null) return;
    const values = curPat.split('|').map(v => v.trim()).filter(Boolean);
    const body = curBody.join('\n');
    if (values.includes('*')) { if (fallback === null) fallback = body; }
    else if (values.includes(selectorVal)) { selected = body; }
    curPat = null;
    curBody = [];
  };

  for (const ln of bodyLines) {
    const stripped = ln.trim();
    if (depth === 0) {
      const bm = stripped.match(/^([^()]+?)\s*\)\s*(.*)$/);
      if (bm) {
        if (curPat !== null) flush();
        curPat = bm[1].trim().replace(/^["']|["']$/g, '');
        curBody = bm[2].trim() ? [bm[2].trim()] : [];
        continue;
      }
    }
    if (/\bcase\b/.test(stripped)) depth += 1;
    else if (/\besac\b/.test(stripped)) depth = Math.max(0, depth - 1);
    else if (curPat !== null) {
      curBody.push(ln);
      if (depth === 0 && stripped.endsWith(';;')) flush();
    }
  }
  if (curPat !== null && curBody.length) flush();

  return selected !== null ? selected : fallback;
}

// ==================== if parsing ====================

function evalIfCondition(cond: string, args: string[] | null): boolean | null {
  if (!args || !args.length) return null;
  let inner = cond.replace(/^\[\[?|\]\]?$/g, '').replace(/"/g, '').replace(/'/g, '').trim();
  const m = inner.match(/(.*?)\s*(==|=)\s*(.*)/);
  if (!m) return null;
  let left = m[1].trim();
  let right = m[3].trim();
  const lm = left.match(/^\$(\d+)$/);
  if (lm) {
    const idx = parseInt(lm[1], 10);
    if (1 <= idx && idx <= args.length) left = args[idx - 1];
    else return null;
  } else if (left.startsWith('$')) return null;
  const rm = right.match(/^\$(\d+)$/);
  if (rm) {
    const idx = parseInt(rm[1], 10);
    if (1 <= idx && idx <= args.length) right = args[idx - 1];
    else return null;
  } else if (right.startsWith('$')) return null;
  return left === right;
}

function parseIf(content: string, args: string[] | null): string | null {
  const m = content.match(/\bif\s+([^\n;]+?)\s*;\s*then/i);
  if (!m) return null;
  const truth = evalIfCondition(m[1].trim(), args);
  if (truth === null) return null;

  const start = m.index ?? 0;
  const thenBodyStart = start + m[0].length;
  const fiPos = content.indexOf('fi', thenBodyStart);
  if (fiPos === -1) return null;
  const segment = content.slice(thenBodyStart, fiPos);
  const elseM = segment.match(/\belse\b/);
  let chosen: string;
  if (truth) chosen = elseM ? segment.slice(0, elseM.index) : segment;
  else {
    if (!elseM) return null;
    chosen = segment.slice((elseM.index ?? 0) + 4); // len('else') == 4
  }
  return `${content.slice(0, start)}\n${chosen}\n${content.slice(fiPos + 2)}`;
}

// ==================== loops (conservative) ====================

function markLoopsReachable(content: string): string {
  // Conservative: loop body always kept (can't prove unreachable). No-op.
  return content;
}

// ==================== child call extraction (with args) ====================

const CHILD_CALL_RE = /(?:^|\s|&&|\|\|)\s*((?:\/bin\/)?bash|sh|zsh|(?:python|python3|node|ruby|perl|php|lua))\s+(\S+(?:\.(?:sh|shrc|py|js|rb|pl|php|lua))?)([^\n;|&]*?)$/gmi;

function extractCallsFromContent(content: string): ScriptCall[] {
  const calls: ScriptCall[] = [];
  let m: RegExpExecArray | null;
  CHILD_CALL_RE.lastIndex = 0;
  while ((m = CHILD_CALL_RE.exec(content)) !== null) {
    const interp = m[1];
    const path = m[2].trim();
    let rest = m[3].trim();
    if (path.startsWith('-') || path.startsWith('$') || path.includes('/dev/')) continue;
    rest = rest.split(/[;|&<>]/)[0].trim();
    const args: string[] = [];
    for (const tm of rest.matchAll(/(["'])(.*?)\1|(\S+)/g)) {
      args.push(tm[1] ? tm[2] : tm[3]);
    }
    calls.push({ path, args, interpreter: interp });
  }
  return calls;
}

// ==================== ShellBackend ====================

export class ShellBackend implements LanguageBackend {
  language = 'shell';

  parse(content: string | null | undefined, entryArgs: string[] | null): ScriptIR {
    const c = content || '';
    const orig = c;
    let candidate = c;
    let resolved = false;

    // 位置参数/变量绑定安全性检测：命中则跳过 P1 的 $1 绑定剪枝。
    // 漏报防护（NEW-FN）：shift / set -- / read / 函数定义 会改写 $1 语义或
    // 函数内 $1 是函数参数而非入口参数 → $1 绑定不可靠，交 symbolic fail-closed。
    // `set --` 后是空格，`--` 末尾不能用 \b（- 非词字符，后无词边界）
    const p1Safe = !/(?:\bshift\b|\bset\s+--(?:\s|$)|[\s;|&]read\b|^\s*read\b|\(\)\s*\{|function\s+\w+)/.test(c);

    if (p1Safe) {
      // P1: existing case/if literal slicing
      const caseOut = parseCase(candidate, entryArgs);
      if (caseOut !== null && caseOut !== candidate) { resolved = true; candidate = caseOut; }
      const ifOut = parseIf(candidate, entryArgs);
      if (ifOut !== null && ifOut !== candidate) { resolved = true; candidate = ifOut; }
    }
    let bound = p1Safe ? bindPositionalArgs(candidate, entryArgs || []) : candidate;

    // P2/P3/P4: LiteSE symbolic executor (upgrade when P1 can't resolve)
    if (!resolved) {
      const symOut = symbolicProcess(c, entryArgs);
      if (symOut !== null && symOut !== c) {
        resolved = true;
        bound = symOut;
      }
    }

    // loops: conservative
    const loopMarked = markLoopsReachable(bound);
    // child calls
    const calls = extractCallsFromContent(loopMarked);

    return {
      reachableContent: loopMarked,
      controlFlowResolved: resolved,
      calls,
      branches: [],
      unresolvedSnippets: [],
      language: this.language,
    };
  }
}