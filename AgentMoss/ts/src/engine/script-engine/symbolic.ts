/**
 * LiteSE symbolic environment executor — TS side.
 * Mirrors Python agent_moss/engine/script_engine/backends/symbolic.py EXACTLY
 * (fields, algorithms, return semantics). Do not diverge.
 *
 * Upgrades ShellBackend when P1 (literal replace + case/if string equality)
 * cannot resolve:
 *  1. variable concatenation: `case "prefix${1}suffix"` / `${1}${2}`
 *  2. internal named-variable tracking: `MODE=clean; case $MODE`
 *  3. glob pattern branches: `case $1 in bak*)`
 *  4. numeric condition branches: `if [ "$1" -gt 5 ]`
 *
 * Design (performance fence):
 *  - SVal concrete/symbol/expr; expr folds to concrete when all children concrete.
 *  - Sequential execution with env map (var -> SVal).
 *  - case/if: selector/cond folded via env to concrete → precise match;
 *    can't fold → return null (caller fail-closed).
 *  - glob: glob -> regex (JS RegExp), concrete-only match; symbol -> null.
 *  - numeric: concrete-int only; symbol -> null.
 *  - budgets (lines/branches) + MAX_VARS; over budget -> null (caller full-text).
 */

// ==================== local helpers (no external deps) ====================

function reescape(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
const RE_DOTALL = 's';

// ==================== budgets (P5) ====================

const MAX_LINES = 500;
const MAX_BRANCHES = 50;
const MAX_VARS = 200;

// ==================== SVal ====================

export type SValKind = 'concrete' | 'symbol' | 'expr';

export interface SVal {
  kind: SValKind;
  value: string | null;
  children: SVal[];
  op: string;
}

export function svalConc(v: string): SVal {
  return { kind: 'concrete', value: v, children: [], op: '' };
}
function svalSym(name: string): SVal {
  return { kind: 'symbol', value: name, children: [], op: '' };
}
function svalExpr(children: SVal[]): SVal {
  return { kind: 'expr', value: null, children, op: '+' };
}

export function fold(val: SVal): SVal {
  if (val.kind !== 'expr') return val;
  const parts: string[] = [];
  for (const c of val.children) {
    const cc = fold(c);
    if (cc.kind === 'concrete') {
      parts.push(cc.value || '');
    } else {
      return cc; // symbol → propagate (can't fold)
    }
  }
  return svalConc(parts.join(''));
}

// ==================== statement model ====================

interface BaseStmt {
  line: string;
  modelable: boolean;
}
interface AssignStmt extends BaseStmt {
  kind: 'assign';
  name: string;
  rhs: string;
}
interface CaseStmt extends BaseStmt {
  kind: 'case';
  selector: string;
  branches: { pat: string; body: string }[];
}
interface IfStmt extends BaseStmt {
  kind: 'if';
  cond: string;
  thenBody: string;
  elseBody: string | null;
}
interface PlainStmt extends BaseStmt {
  kind: 'plain';
}
type Stmt = AssignStmt | CaseStmt | IfStmt | PlainStmt;

// ==================== tokenize ====================

const ASGN_RE = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$/;
const CASE_START_RE = /^\s*case\s+/;
const IF_START_RE = /^\s*if\s+/;
const NOT_MODELED_RE = /\$\(|`[^`]*`/;

// ==================== nested depth matching ====================
// Fix: original parseCaseStmt/parseIfStmt used indexOf('esac') / lastIndexOf('fi')
// / line-includes——nested case/if took the inner keyword and truncated the outer
// block (cutting branches wrong). Depth counting pairs open/close keywords:
// each open (+1), close (-1), depth reaches 0 → the matching close. Linear O(lines).

const CASE_OPEN_RE = /\bcase\b/;
const CASE_CLOSE_RE = /\besac\b/;
const IF_OPEN_RE = /\bif\b/;
const IF_CLOSE_RE = /\bfi\b/;

function countMatches(re: RegExp, s: string): number {
  const m = s.match(re);
  return m ? m.length : 0;
}

/** Find the closing line index for open keyword at startLine. -1 if unclosed. */
function findBlockEnd(lines: string[], startLine: number, openRe: RegExp, closeRe: RegExp): number {
  let depth = 0;
  for (let idx = startLine; idx < lines.length; idx++) {
    depth += countMatches(openRe, lines[idx]) - countMatches(closeRe, lines[idx]);
    if (depth <= 0 && idx > startLine) return idx;
  }
  return -1;
}

function findCaseEnd(lines: string[], start: number): number {
  return findBlockEnd(lines, start, CASE_OPEN_RE, CASE_CLOSE_RE);
}
function findIfEnd(lines: string[], start: number): number {
  return findBlockEnd(lines, start, IF_OPEN_RE, IF_CLOSE_RE);
}

const LOOP_DO_RE = /\bdo\b/g;
const LOOP_DONE_RE = /\bdone\b/g;

/** Loop block (while/for/until ... do ... done) closing line. -1 if unclosed. */
function findLoopEnd(lines: string[], start: number): number {
  let depth = 0;
  for (let idx = start; idx < lines.length; idx++) {
    depth += countMatches(LOOP_DO_RE, lines[idx]) - countMatches(LOOP_DONE_RE, lines[idx]);
    if (depth <= 0 && idx > start) return idx;
  }
  return -1;
}

const FN_DEF_RE = /^\s*(?:function\s+)?[A-Za-z_][A-Za-z0-9_]*\s*\(\s*\)\s*\{/;
const FN_DEF_KW_RE = /^\s*function\s+[A-Za-z_][A-Za-z0-9_]*\s*\{?/;

/** Function definition block (name() { ... }) closing line. -1 if unclosed. */
function findFnEnd(lines: string[], start: number): number {
  let depth = 0;
  for (let idx = start; idx < lines.length; idx++) {
    depth += (lines[idx].match(/\{/g) || []).length - (lines[idx].match(/\}/g) || []).length;
    if (depth <= 0 && idx > start) return idx;
  }
  return -1;
}

function stripComments(content: string): string {
  return content.split('\n').filter(l => !l.trimStart().startsWith('#')).join('\n');
}

function parseCaseStmt(block: string): CaseStmt | null {
  const header = block.match(/\s*case\s+(\S[^;]*?)\s*\bin\b[\s\S]*/);
  if (!header) return null;
  const sel = header[1].trim();

  const lines = block.split('\n');
  // 定位 header 行（含 "in"）之后 body 起始行
  let headerLine = 0;
  for (let i = 0; i < lines.length; i++) {
    if (/\bin\b/.test(lines[i]) && /\bcase\b/.test(lines[i])) { headerLine = i; break; }
  }
  const bodyStartLine = headerLine + 1;
  // 深度配对找本层 esac（嵌套 case 时不能 indexOf 第一个）
  const endLine = findCaseEnd(lines, 0);
  if (endLine === -1) return null;

  // 深度感知分支切分：内层 case 的 `pattern)` 行（depth>0）不作为外层分支。
  // 用与 splitNestedCaseBranches 相同的深度计数逻辑，保证 case-in-case 时
  // 外层分支边界正确、内层内容保留在选中分支 body 中。
  const branches = splitCaseBranchesDepthAware(lines.slice(bodyStartLine, endLine));

  // 无分支（无 `pattern)`）或切分失败 → null（fail-closed 回退全文）
  if (!branches.length) return null;

  return { kind: 'case', line: block, modelable: true, selector: sel, branches };
}

/** 深度感知的 case 分支切分：depth 0 的 `pattern)` 才是外层分支。 */
function splitCaseBranchesDepthAware(bodyLines: string[]): { pat: string; body: string }[] {
  let depth = 0;
  let curPat: string | null = null;
  let curBody: string[] = [];
  const branches: { pat: string; body: string }[] = [];
  const flush = () => {
    if (curPat !== null) {
      branches.push({ pat: curPat, body: curBody.join('\n') });
    }
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
  return branches;
}

function parseIfStmt(block: string): IfStmt | null {
  const m = block.match(/\s*if\s+([^\n;]+?)\s*;\s*then/);
  if (!m) return null;
  const cond = m[1].trim();

  const lines = block.split('\n');
  const fiLine = findIfEnd(lines, 0);
  if (fiLine === -1) return null;
  // then 到本层 fi 之间的 body
  const body = lines.slice(1, fiLine).join('\n');

  const elseM = /\belse\b/.exec(body);
  let thenBody: string;
  let elseBody: string | null;
  if (elseM) {
    thenBody = body.slice(0, elseM.index);
    elseBody = body.slice(elseM.index! + 4);
  } else {
    thenBody = body;
    elseBody = null;
  }
  return { kind: 'if', line: block, modelable: true, cond, thenBody, elseBody };
}

function tokenize(content: string): Stmt[] {
  const lines = stripComments(content).split('\n');
  const stmts: Stmt[] = [];
  let i = 0;
  while (i < lines.length) {
    const ln = lines[i];
    const stripped = ln.trim();
    if (!stripped) { i++; continue; }

    // loop block while/for/until ... do ... done: body assignments unreliable
    // outside the loop (may run 0/many times) → whole block NotModeled
    // → symbolicProcess returns null → caller fail-closed full text
    if (/\b(?:while|for|until)\b/.test(stripped) && !CASE_START_RE.test(stripped) && !IF_START_RE.test(stripped)) {
      const endLine = findLoopEnd(lines, i);
      if (endLine !== -1) {
        for (let k = i; k <= endLine; k++) stmts.push({ kind: 'plain', line: lines[k], modelable: false });
        i = endLine + 1;
        continue;
      }
      stmts.push({ kind: 'plain', line: ln, modelable: false });
      i++;
      continue;
    }

    // function definition name() { ... } / function name { ... }: $1 inside the
    // function is the function arg, not the entry arg; body runs only on call and
    // may modify globals → whole block NotModeled
    if (FN_DEF_RE.test(stripped) || FN_DEF_KW_RE.test(stripped)) {
      const endLine = findFnEnd(lines, i);
      if (endLine !== -1) {
        for (let k = i; k <= endLine; k++) stmts.push({ kind: 'plain', line: lines[k], modelable: false });
        i = endLine + 1;
        continue;
      }
      stmts.push({ kind: 'plain', line: ln, modelable: false });
      i++;
      continue;
    }

    // case block
    if (CASE_START_RE.test(stripped)) {
      const endLine = findCaseEnd(lines, i);
      if (endLine === -1) { stmts.push({ kind: 'plain', line: ln, modelable: false }); i++; continue; }
      const parsed = parseCaseStmt(lines.slice(i, endLine + 1).join('\n'));
      stmts.push(parsed || { kind: 'plain', line: ln, modelable: false });
      i = endLine + 1;
      continue;
    }

    // if block
    if (IF_START_RE.test(stripped)) {
      const endLine = findIfEnd(lines, i);
      if (endLine === -1) { stmts.push({ kind: 'plain', line: ln, modelable: false }); i++; continue; }
      const parsed = parseIfStmt(lines.slice(i, endLine + 1).join('\n'));
      stmts.push(parsed || { kind: 'plain', line: ln, modelable: false });
      i = endLine + 1;
      continue;
    }

    // shift / set -- / read change positional args or var bindings → $1 semantics
    // change, P1 binding unreliable. Note: `set -e` does NOT change positional args;
    // only `set --` (followed by args). `set --` is followed by a space, so `--`
    // cannot end with \b (non-word char, no word boundary after it).
    if (/\bshift\b|\bset\s+--(?:\s|$)|[\s;|&]read\b|^\s*read\b/.test(stripped)) {
      stmts.push({ kind: 'plain', line: ln, modelable: false });
      i++;
      continue;
    }

    const am = stripped.match(ASGN_RE);
    if (am && !NOT_MODELED_RE.test(stripped)) {
      stmts.push({ kind: 'assign', line: stripped, modelable: true, name: am[1], rhs: am[2].trim() });
      i++;
      continue;
    }

    stmts.push(NOT_MODELED_RE.test(stripped)
      ? { kind: 'plain', line: ln, modelable: false }
      : { kind: 'plain', line: ln, modelable: true });
    i++;
  }
  return stmts;
}

// ==================== expression eval (P2) ====================

const EXPR_SPLIT_RE = /(\$\{?\d+\}?|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?)/;

export function evalExpr(text: string, env: Map<string, SVal>): SVal {
  // quote semantics: "..." expands; '...' literal
  const isSingleQuoted = text.length >= 2 && text[0] === "'" && text[text.length - 1] === "'";
  if (text.length >= 2 && (text[0] === '"' || text[0] === "'") && text[text.length - 1] === text[0]) {
    text = text.slice(1, -1);
  }
  if (isSingleQuoted) return svalConc(text);

  const parts = text.split(EXPR_SPLIT_RE);
  const result: SVal[] = [];
  for (const p of parts) {
    if (!p) continue;
    const brace = p.match(/^\$\{([^}]+)\}$/);
    if (brace) {
      const inner = brace[1];
      if (/^\d+$/.test(inner)) {
        const v = env.get(`$${inner}`);
        result.push(v || svalSym(`$${inner}`));
      } else {
        const v = env.get(inner);
        result.push(v || svalSym(inner));
      }
      continue;
    }
    const bare = p.match(/^\$([A-Za-z_][A-Za-z0-9_]*|\d+)$/);
    if (bare) {
      const varName = bare[1];
      const key = /^\d+$/.test(varName) ? `$${varName}` : varName;
      const v = env.get(key);
      result.push(v || svalSym(p));
      continue;
    }
    result.push(svalConc(p));
  }
  if (result.length === 1) return fold(result[0]);
  return fold(svalExpr(result));
}

// ==================== init env ====================

function initEnv(entryArgs: string[] | null): Map<string, SVal> {
  const env = new Map<string, SVal>();
  if (entryArgs && entryArgs.length) {
    entryArgs.forEach((a, idx) => env.set(`$${idx + 1}`, svalConc(a)));
    env.set('$@', svalConc(entryArgs.join(' ')));
    env.set('$*', svalConc(entryArgs.join(' ')));
  }
  return env;
}

// ==================== glob (P4) ====================

const HAS_GLOB = /[*?[]/;

export function globToRegex(pattern: string): RegExp {
  let out = '^';
  let i = 0;
  while (i < pattern.length) {
    const c = pattern[i];
    if (c === '*') out += '.*';
    else if (c === '?') out += '.';
    else if (c === '[') {
      let j = i + 1;
      let neg = false;
      if (j < pattern.length && (pattern[j] === '!' || pattern[j] === '^')) { neg = true; j++; }
      let cls = '';
      while (j < pattern.length && pattern[j] !== ']') { cls += pattern[j]; j++; }
      if (j >= pattern.length) {
        out += reescape(pattern.slice(i));
        break;
      }
      out += '[' + (neg ? '^' : '') + reescape(cls) + ']';
      i = j;
    } else {
      out += reescape(c);
    }
    i++;
  }
  out += '$';
  return new RegExp(out, RE_DOTALL);
}

export function matchGlob(pattern: string, value: string): boolean {
  if (!HAS_GLOB.test(pattern)) return pattern === value;
  return globToRegex(pattern).test(value);
}

// ==================== numeric compare (P4) ====================

export function evalNumericCompare(op: string, left: string, right: string): boolean | null {
  const li = parseInt(left, 10);
  const ri = parseInt(right, 10);
  if (isNaN(li) || isNaN(ri)) return null;
  switch (op) {
    case '-gt': return li > ri;
    case '-lt': return li < ri;
    case '-eq': return li === ri;
    case '-ge': return li >= ri;
    case '-le': return li <= ri;
    default: return null;
  }
}

// ==================== if condition (P2/P4) ====================

function resolveVarSide(tok: string, env: Map<string, SVal>): string | null {
  if (!tok.startsWith('$')) return tok;
  const ev = evalExpr(tok, env);
  return ev.kind === 'concrete' ? ev.value : null;
}

export function evalCondition(cond: string, env: Map<string, SVal>): boolean | null {
  let inner = cond.trim().replace(/^\[\[?|\]\]?$/g, '').trim();
  if (/^-[A-Za-z]\s/.test(inner) || inner.startsWith('-d') || inner.startsWith('-f')) return null;
  const innerQ = inner.replace(/"/g, '').replace(/'/g, '');

  // numeric
  for (const op of ['-gt', '-lt', '-eq', '-ge', '-le']) {
    const re = new RegExp(`\\s${op}\\s`);
    const opm = re.exec(innerQ);
    if (!opm) continue;
    const left = innerQ.slice(0, opm.index).trim();
    // opm[0] 是 \s-gt\s（含两侧空格），其末尾才是操作数起点
    const right = innerQ.slice(opm.index + opm[0].length).trim();
    const lv = resolveVarSide(left, env);
    const rv = resolveVarSide(right, env);
    if (lv === null || rv === null) return null;
    return evalNumericCompare(op, lv, rv);
  }

  // string equal / not / regex
  const sm = innerQ.match(/(.*?)\s*(==|=|!=|=~)\s*(.*)/);
  if (!sm) return null;
  const op = sm[2];
  let left = sm[1].trim();
  let right = sm[3].trim();
  if (op === '=~') {
    if (right.startsWith('/') && right.endsWith('/')) right = right.slice(1, -1);
    const lv = resolveVarSide(left, env);
    if (lv === null) return null;
    try { return new RegExp(right).test(lv); } catch { return null; }
  }
  const lv = resolveVarSide(left, env);
  const rv = resolveVarSide(right, env);
  if (lv === null || rv === null) return null;
  if (op === '!=') return lv !== rv;
  return lv === rv;
}

// ==================== executor ====================

export function symbolicProcess(content: string, entryArgs: string[] | null): string | null {
  if (!content) return null;
  const stmts = tokenize(content);
  if (!stmts.some(s => s.kind === 'case' || s.kind === 'if' || s.kind === 'assign')) return null;
  if (stmts.some(s => !s.modelable)) return null;

  const env = initEnv(entryArgs);
  let linesBudget = 0;
  let branchesBudget = 0;
  let modelable = false;
  const out: string[] = [];

  for (const s of stmts) {
    linesBudget++;
    if (linesBudget > MAX_LINES) return null;

    if (s.kind === 'assign') {
      modelable = true;
      if (env.size >= MAX_VARS) return null;
      const v = evalExpr(s.rhs, env);
      env.set(s.name, fold(v));
      out.push(s.line);
      continue;
    }

    if (s.kind === 'case') {
      modelable = true;
      branchesBudget += s.branches.length;
      if (branchesBudget > MAX_BRANCHES) return null;
      const selVal = fold(evalExpr(s.selector, env));
      if (selVal.kind !== 'concrete') return null; // symbol selector -> fail-closed
      const concrete = selVal.value || '';
      let selected: string | null = null;
      let fallback = '';
      for (const b of s.branches) {
        const patStripped = b.pat.trim();
        if (patStripped === '*') { fallback = b.body; continue; }
        if (matchGlob(patStripped, concrete)) { selected = b.body; break; }
      }
      const final = selected !== null ? selected : (fallback || null);
      if (final === null) return null;
      out.push(`case ${s.selector} in\n${final}\nesac`);
      continue;
    }

    if (s.kind === 'if') {
      modelable = true;
      branchesBudget++;
      if (branchesBudget > MAX_BRANCHES) return null;
      const truth = evalCondition(s.cond, env);
      if (truth === null) return null; // unknown -> fail-closed
      const chosen = truth ? s.thenBody : s.elseBody;
      if (chosen === null) return null;
      out.push(`if ${s.cond}; then\n${chosen}\nfi`);
      continue;
    }

    out.push(s.line);
  }

  if (!modelable) return null;
  return out.join('\n');
}