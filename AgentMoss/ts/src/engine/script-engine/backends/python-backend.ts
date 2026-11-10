/**
 * Script-engine PythonBackend — static python3 parser → IR.
 * Mirrors Python agent_moss/engine/script_engine/backends/python_backend.py.
 *
 * Uses @lezer/python (pure JS, zero native deps, ~134KB) to build a CST,
 * then performs the same control-flow pruning + child-call extraction as the
 * Python end (stdlib `ast`), producing identical IR behavior:
 * - sys.argv[N] bound to entry args (like shell $N)
 * - simple assignment tracking: mode = sys.argv[1] → if mode == "clean" judged
 * - if/elif condition statically evaluable → branch selected; else keep all (fail-closed)
 * - if __name__ == "__main__" → always true (entry script)
 * - for/while/try/with bodies kept (can't prove unreachable); nested if still pruned
 * - def/class bodies fully kept (call-time env unknown), no inner pruning
 *
 * Child calls: subprocess.run(["bash","x.sh",arg]) list form,
 * subprocess.run("bash x.sh arg", shell=True) / os.system("...") string form,
 * relative imports (from . import x / from .x import y).
 */

import { parser } from '@lezer/python';
import type { SyntaxNode } from '@lezer/common';
import type { BranchInfo, ScriptCall, ScriptIR } from '../ir';
import type { LanguageBackend } from './index';

// ==================== budget (P5 fuse, mirrors symbolic.py red line) ====================

const MAX_LINES = 500;

// Pure builtins whose calls never mutate script globals (safe to keep env).
const PURE_BUILTINS = new Set([
  'len', 'print', 'str', 'int', 'float', 'bool', 'list', 'dict', 'set',
  'tuple', 'range', 'sorted', 'enumerate', 'zip', 'map', 'filter',
  'sum', 'min', 'max', 'abs', 'round', 'isinstance', 'type', 'open',
  'input', 'repr', 'ord', 'chr', 'hex', 'oct', 'bin', 'format', 'id',
  'hash', 'any', 'all', 'next', 'iter', 'reversed', 'pow', 'divmod',
]);

// ==================== child-call regex (mirrors shell_backend._CHILD_CALL_RE) ====================

const CHILD_CALL_RE = /(?:^|\s|&&|\|\|)\s*((?:\/bin\/)?bash|sh|zsh|(?:python|python3|node|ruby|perl|php|lua))\s+(\S+(?:\.(?:sh|shrc|py|js|rb|pl|php|lua))?)([^\n;|&]*?)$/gim;

const SUBPROCESS_FUNCS = new Set(['run', 'call', 'Popen', 'check_call', 'check_output']);
const OS_FUNCS = new Set(['system', 'popen', 'popen2', 'popen3', 'popen4']);

// ==================== line mapping ====================

function buildLineStarts(content: string): number[] {
  const starts = [0];
  for (let i = 0; i < content.length; i++) {
    if (content[i] === '\n') starts.push(i + 1);
  }
  return starts;
}

function lineAt(lineStarts: number[], pos: number): number {
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (lineStarts[mid] <= pos) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1; // 1-based
}

function markNodeLines(node: SyntaxNode, lines: Set<number>, lineStarts: number[]): void {
  const start = lineAt(lineStarts, node.from);
  const end = node.to > node.from ? lineAt(lineStarts, node.to - 1) : start;
  for (let i = start; i <= end; i++) lines.add(i);
}

function reconstruct(sourceLines: string[], lines: Set<number>): string {
  const out: string[] = [];
  for (const i of [...lines].sort((a, b) => a - b)) {
    if (i >= 1 && i <= sourceLines.length) out.push(sourceLines[i - 1]);
  }
  return out.join('\n');
}

// ==================== value evaluation (simplified SVal: string | null) ====================

interface Env {
  argv: string[];
  vars: Record<string, string | null>;
}

function makeEnv(argv: string[]): Env {
  return { argv, vars: {} };
}

function textOf(node: SyntaxNode): string {
  return node.to > node.from ? node.parent!.tree!.length === 0 ? '' : srcSlice(node) : '';
}

/** Slice original source for a node (needs access to full source). */
let SOURCE = '';
function srcSlice(node: SyntaxNode): string {
  return SOURCE.slice(node.from, node.to);
}

/** Unquote a lezer String token (e.g. "clean" / 'clean'). */
function stringValue(tokenText: string): string {
  let s = tokenText;
  if (s.length >= 2) {
    const q = s[0];
    if ((q === '"' || q === "'") && s.endsWith(q)) s = s.slice(1, -1);
  }
  // basic escapes so values match Python ast.Constant
  s = s.replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\r/g, '\r')
       .replace(/\\\\/g, '\\').replace(/\\"/g, '"').replace(/\\'/g, "'");
  return s;
}

function isSysArgv(node: SyntaxNode | null): boolean {
  if (!node || node.name !== 'MemberExpression') return false;
  const first = node.firstChild;
  if (!first || first.name !== 'VariableName' || srcSlice(first) !== 'sys') return false;
  const prop = node.getChild('PropertyName');
  return prop !== null && srcSlice(prop) === 'argv';
}

function evalExpr(node: SyntaxNode | null, env: Env): string | null {
  if (!node) return null;
  const name = node.name;
  if (name === 'String') return stringValue(srcSlice(node));
  if (name === 'Number') return srcSlice(node);
  if (name === 'VariableName') {
    const id = srcSlice(node);
    return id in env.vars ? env.vars[id] : null;
  }
  if (name === 'MemberExpression') {
    // sys.argv[N]
    const bracket = node.getChild('[');
    if (bracket) {
      const inner = node.firstChild;
      if (inner && isSysArgv(inner)) {
        const idxNode = bracket.nextSibling;
        if (idxNode && idxNode.name === 'Number') {
          const idx = parseInt(srcSlice(idxNode), 10);
          if (idx >= 1 && idx <= env.argv.length) return env.argv[idx - 1];
          return null;
        }
      }
      return null;
    }
    // sys.argv whole
    if (isSysArgv(node)) return env.argv[0] ?? null;
    return null;
  }
  if (name === 'CallExpression') {
    // len(sys.argv)
    const func = node.firstChild;
    if (func && func.name === 'VariableName' && srcSlice(func) === 'len') {
      const argList = node.getChild('ArgList');
      const inner = argList ? firstNamedChild(argList) : null;
      if (inner && isSysArgv(inner)) return String(env.argv.length + 1);
    }
    return null;
  }
  if (name === 'ConditionalExpression') {
    // then if cond else orelse
    const ifKw = node.getChild('if');
    const elseKw = node.getChild('else');
    if (!ifKw || !elseKw) return null;
    const thenNode = node.firstChild;
    const condNode = ifKw.nextSibling;
    const orelseNode = elseKw.nextSibling;
    if (!thenNode || !condNode || !orelseNode) return null;
    const cond = evalCondition(condNode, env);
    if (cond === true) return evalExpr(thenNode, env);
    if (cond === false) return evalExpr(orelseNode, env);
    return null;
  }
  if (name === 'BinaryExpression') {
    // string concat with +
    const op = findOp(node);
    if (op === '+') {
      const left = evalExpr(node.firstChild, env);
      const right = evalExpr(lastNamedChild(node), env);
      if (left !== null && right !== null) return left + right;
    }
    return null;
  }
  return null;
}

function firstNamedChild(node: SyntaxNode): SyntaxNode | null {
  let c = node.firstChild;
  while (c) {
    if (c.name !== '(' && c.name !== ')' && c.name !== ',' && c.name !== ':') return c;
    c = c.nextSibling;
  }
  return null;
}

function lastNamedChild(node: SyntaxNode): SyntaxNode | null {
  let c = node.lastChild;
  while (c) {
    if (c.name !== '(' && c.name !== ')' && c.name !== ',' && c.name !== ':') return c;
    c = c.prevSibling;
  }
  return null;
}

/** Find comparison/boolean operator token inside a BinaryExpression. */
function findOp(node: SyntaxNode): string | null {
  let c = node.firstChild;
  while (c) {
    if (c.name === 'CompareOp' || c.name === 'and' || c.name === 'or' || c.name === 'UpdateOp') {
      return srcSlice(c).trim();
    }
    c = c.nextSibling;
  }
  return null;
}

// ==================== condition evaluation ====================

function evalCondition(node: SyntaxNode | null, env: Env): boolean | null {
  if (!node) return null;
  const name = node.name;
  if (name === 'Boolean') {
    const t = srcSlice(node).trim();
    return t === 'True' ? true : t === 'False' ? false : null;
  }
  if (name === 'BinaryExpression') {
    const op = findOp(node);
    if (op === 'and' || op === 'or') {
      const parts = namedChildren(node);
      const vals = parts.map((p) => evalCondition(p, env));
      if (op === 'and') {
        if (vals.some((v) => v === false)) return false;
        if (vals.every((v) => v === true)) return true;
        return null;
      }
      if (vals.some((v) => v === true)) return true;
      if (vals.every((v) => v === false)) return false;
      return null;
    }
    // comparison
    const parts = namedChildren(node);
    if (parts.length !== 3) return null;
    const [left, opNode, right] = parts;
    const opText = srcSlice(opNode).trim();
    return evalCompare(left, opText, right, env);
  }
  if (name === 'UnaryExpression') {
    // not x
    const kw = node.getChild('not');
    if (kw) {
      const operand = kw.nextSibling;
      const v = evalCondition(operand, env);
      return v === null ? null : !v;
    }
    return null;
  }
  if (name === 'CallExpression') {
    // truthiness of call — cannot statically judge → null (fail-closed)
    return null;
  }
  return null;
}

function namedChildren(node: SyntaxNode): SyntaxNode[] {
  const out: SyntaxNode[] = [];
  let c = node.firstChild;
  while (c) {
    if (c.name !== '(' && c.name !== ')' && c.name !== ',' && c.name !== ':' && c.name !== '[' && c.name !== ']') {
      out.push(c);
    }
    c = c.nextSibling;
  }
  return out;
}

function evalCompare(left: SyntaxNode, opText: string, right: SyntaxNode, env: Env): boolean | null {
  // __name__ == "__main__"
  if (opText === '==' && left.name === 'VariableName' && srcSlice(left) === '__name__') {
    const rv = evalExpr(right, env);
    if (rv !== null) return rv === '__main__';
    return null;
  }
  if (opText === '==' || opText === '!=') {
    const lv = evalExpr(left, env);
    const rv = evalExpr(right, env);
    if (lv !== null && rv !== null) {
      return opText === '==' ? lv === rv : lv !== rv;
    }
    return null;
  }
  if (opText === 'in') {
    const lv = evalExpr(left, env);
    if (lv === null) return null;
    // right may be a Tuple/List/Array literal or a string
    const rightName = right.name;
    if (rightName === 'TupleExpression' || rightName === 'ArrayExpression' || rightName === 'SetExpression' || rightName === 'ParenthesizedExpression') {
      const container = rightName === 'ParenthesizedExpression' && right.firstChild && right.firstChild.name === 'TupleExpression'
        ? right.firstChild : right;
      for (const elt of namedChildren(container)) {
        const ev = evalExpr(elt, env);
        if (ev !== null && ev === lv) return true;
      }
      return false;
    }
    const rv = evalExpr(right, env);
    if (rv !== null) return rv.includes(lv);
    return null;
  }
  if (opText === '>' || opText === '>=' || opText === '<' || opText === '<=') {
    // len(sys.argv) > 1 form
    const lv = evalExpr(left, env);
    const rv = evalExpr(right, env);
    if (lv === null || rv === null) return null;
    const ln = parseInt(lv, 10);
    const rn = parseInt(rv, 10);
    if (Number.isNaN(ln) || Number.isNaN(rn)) return null;
    if (opText === '>') return ln > rn;
    if (opText === '>=') return ln >= rn;
    if (opText === '<') return ln < rn;
    return ln <= rn;
  }
  return null;
}

// ==================== control-flow pruning ====================

function processStmts(stmts: SyntaxNode[], env: Env, lineStarts: number[], lines: Set<number>, branches: BranchInfo[]): void {
  for (const s of stmts) processStmt(s, env, lineStarts, lines, branches);
}

/**
 * If node contains a call to a non-pure function (user-defined etc., which may
 * mutate globals), invalidate the whole env. Leak guard: `def set_clean():
 * global mode; mode="clean"` then `set_clean()` — env.mode is stale, a later
 * `if mode == "clean"` would wrongly prune the dangerous branch. Can't prove
 * the call has no global side effect → conservatively set all vars unknown
 * (fail-closed: keep everything).
 */
function invalidateEnvOnCalls(node: SyntaxNode, env: Env): void {
  const cursor = node.cursor();
  cursor.iterate((n) => {
    const nd = n.node;
    if (nd.name !== 'CallExpression') return true;
    const func = nd.firstChild;
    if (func && func.name === 'VariableName' && !PURE_BUILTINS.has(srcSlice(func))) {
      for (const k of Object.keys(env.vars)) env.vars[k] = null;
      return false; // stop iterating
    }
    return true;
  });
}

function processStmt(stmt: SyntaxNode, env: Env, lineStarts: number[], lines: Set<number>, branches: BranchInfo[]): void {
  const name = stmt.name;
  // assignment: update env vars; RHS with non-pure call → invalidate env
  if (name === 'AssignStatement') {
    const target = stmt.firstChild;
    if (target && target.name === 'VariableName') {
      const valNode = target.nextSibling ? target.nextSibling.nextSibling : null; // skip AssignOp
      invalidateEnvOnCalls(stmt, env);
      const val = evalExpr(valNode, env);
      env.vars[srcSlice(target)] = val;
    }
    markNodeLines(stmt, lines, lineStarts);
    return;
  }
  // augmented assignment x += 1: var becomes unknown
  if (name === 'UpdateStatement') {
    const target = stmt.firstChild;
    if (target && target.name === 'VariableName') env.vars[srcSlice(target)] = null;
    invalidateEnvOnCalls(stmt, env);
    markNodeLines(stmt, lines, lineStarts);
    return;
  }
  // if / elif / else chain
  if (name === 'IfStatement') {
    processIf(stmt, env, lineStarts, lines, branches);
    return;
  }
  // loops / try / with / match: bodies kept (conservative); nested if still pruned.
  // LEAK GUARD: loop body may run 0/many times, try body may abort with exception,
  // with body may not run — body assignments are unreliable outside the block,
  // so process each body with an env COPY and never write back to the outer env
  // (fail-closed: keep more rather than miss).
  if (name === 'ForStatement' || name === 'WhileStatement') {
    markNodeLines(stmt, lines, lineStarts);
    for (const body of stmt.getChildren('Body')) {
      processStmts(bodyStmts(body), { argv: env.argv, vars: { ...env.vars } }, lineStarts, lines, branches);
    }
    return;
  }
  if (name === 'TryStatement') {
    markNodeLines(stmt, lines, lineStarts);
    for (const body of stmt.getChildren('Body')) {
      processStmts(bodyStmts(body), { argv: env.argv, vars: { ...env.vars } }, lineStarts, lines, branches);
    }
    return;
  }
  if (name === 'WithStatement') {
    markNodeLines(stmt, lines, lineStarts);
    const body = stmt.getChild('Body');
    if (body) processStmts(bodyStmts(body), { argv: env.argv, vars: { ...env.vars } }, lineStarts, lines, branches);
    return;
  }
  if (name === 'MatchStatement') {
    markNodeLines(stmt, lines, lineStarts);
    for (const clause of stmt.getChildren('MatchClause')) {
      const body = clause.getChild('Body');
      if (body) processStmts(bodyStmts(body), { argv: env.argv, vars: { ...env.vars } }, lineStarts, lines, branches);
    }
    return;
  }
  // def / class: whole tree kept (call-time env unknown), no inner pruning
  if (name === 'FunctionDefinition' || name === 'ClassDefinition') {
    markDefTree(stmt, lines, lineStarts);
    return;
  }
  // import / expression / everything else: keep.
  // top-level expression statement: non-pure function call (VariableName form)
  // may mutate globals → invalidate env (leak guard)
  if (name === 'ExpressionStatement') {
    invalidateEnvOnCalls(stmt, env);
  }
  markNodeLines(stmt, lines, lineStarts);
}

function markDefTree(stmt: SyntaxNode, lines: Set<number>, lineStarts: number[]): void {
  const cursor = stmt.cursor();
  cursor.iterate((n) => {
    markNodeLines(n.node, lines, lineStarts);
    return true;
  });
}

function bodyStmts(body: SyntaxNode): SyntaxNode[] {
  const out: SyntaxNode[] = [];
  let c = body.firstChild;
  while (c) {
    if (c.name !== ':' && c.name !== ';') out.push(c);
    c = c.nextSibling;
  }
  return out;
}

/** Process if/elif/else chain. Mirrors Python _process_if. */
function processIf(stmt: SyntaxNode, env: Env, lineStarts: number[], lines: Set<number>, branches: BranchInfo[]): void {
  // collect sections: {cond|null, body, isElse}
  const sections: { cond: SyntaxNode | null; body: SyntaxNode | null; isElse: boolean }[] = [];
  let c = stmt.firstChild;
  while (c) {
    if (c.name === 'if' || c.name === 'elif') {
      sections.push({ cond: c.nextSibling ?? null, body: null, isElse: false });
    } else if (c.name === 'else') {
      sections.push({ cond: null, body: null, isElse: true });
    } else if (c.name === 'Body') {
      if (sections.length > 0 && sections[sections.length - 1].body === null) {
        sections[sections.length - 1].body = c;
      }
    }
    c = c.nextSibling;
  }
  processIfSections(stmt, sections, 0, env, lineStarts, lines, branches);
}

function processIfSections(
  _stmt: SyntaxNode,
  sections: { cond: SyntaxNode | null; body: SyntaxNode | null; isElse: boolean }[],
  idx: number,
  env: Env,
  lineStarts: number[],
  lines: Set<number>,
  branches: BranchInfo[],
): void {
  if (idx >= sections.length) return;
  const s = sections[idx];
  // if header (condition is evaluated) always reachable: mark condition line(s)
  if (s.cond) markNodeLines(s.cond, lines, lineStarts);

  if (s.isElse) {
    // else reached only when all prior conditions provably False (guaranteed by recursion)
    if (s.body) processStmts(bodyStmts(s.body), env, lineStarts, lines, branches);
    return;
  }

  const cond = s.cond ? evalCondition(s.cond, env) : null;
  branches.push({
    kind: 'if',
    label: s.cond ? srcSlice(s.cond) : '',
    body: '',
    reachable: cond !== false,
  });

  if (cond === true) {
    // this branch taken; elif/else chain dropped
    if (s.body) processStmts(bodyStmts(s.body), env, lineStarts, lines, branches);
    return;
  }
  if (cond === false) {
    // this branch unreachable; try next (elif or else)
    processIfSections(_stmt, sections, idx + 1, env, lineStarts, lines, branches);
    return;
  }
  // condition not statically judgeable → keep this branch AND all remaining (fail-closed)
  if (s.body) processStmts(bodyStmts(s.body), env, lineStarts, lines, branches);
  for (let j = idx + 1; j < sections.length; j++) {
    const sj = sections[j];
    if (sj.cond) markNodeLines(sj.cond, lines, lineStarts);
    if (sj.body) processStmts(bodyStmts(sj.body), env, lineStarts, lines, branches);
  }
}

// ==================== child-call extraction ====================

function parseShellString(s: string): ScriptCall | null {
  CHILD_CALL_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = CHILD_CALL_RE.exec(s)) !== null) {
    const interp = m[1];
    const path = m[2].trim();
    let rest = m[3].trim();
    if (path.startsWith('-') || path.startsWith('$') || path.includes('/dev/')) continue;
    rest = rest.split(/[;|&<>]/)[0].trim();
    const args: string[] = [];
    for (const tm of rest.matchAll(/(["'])(.*?)\1|(\S+)/g)) {
      args.push(tm[1] ? tm[2] : tm[3]);
    }
    return { path, args, interpreter: interp };
  }
  return null;
}

function extractCallsFromTree(tree: SyntaxNode, reachableLines: Set<number> | null): ScriptCall[] {
  const calls: ScriptCall[] = [];
  const seen = new Set<string>();

  const add = (c: ScriptCall) => {
    const key = `${c.path}\u0000${c.args.join('\u0000')}\u0000${c.interpreter}`;
    if (!seen.has(key)) {
      seen.add(key);
      calls.push(c);
    }
  };

  const lineReachable = (node: SyntaxNode): boolean => {
    if (reachableLines === null) return true;
    return reachableLines.has(lineAt(buildLineStarts(SOURCE), node.from));
  };

  const cursor = tree.cursor();
  cursor.iterate((n) => {
    const node = n.node;
    if (node.name !== 'CallExpression') return true;
    if (!lineReachable(node)) return true;
    const func = node.firstChild;
    if (!func || func.name !== 'MemberExpression') return true;
    const modName = func.firstChild;
    if (!modName || modName.name !== 'VariableName') return true;
    const funcNameNode = func.getChild('PropertyName');
    if (!funcNameNode) return true;
    const mod = srcSlice(modName);
    const funcName = srcSlice(funcNameNode);

    const argList = node.getChild('ArgList');
    const firstArg = argList ? firstNamedChild(argList) : null;

    if (mod === 'subprocess' && SUBPROCESS_FUNCS.has(funcName)) {
      // list form: subprocess.run(["bash", "x.sh", "arg"])
      if (firstArg && (firstArg.name === 'ArrayExpression' || firstArg.name === 'TupleExpression')) {
        const elts: string[] = [];
        let allStr = true;
        for (const elt of namedChildren(firstArg)) {
          if (elt.name === 'String') elts.push(stringValue(srcSlice(elt)));
          else { allStr = false; break; }
        }
        if (allStr && elts.length >= 2) {
          const interp = elts[0];
          const path = elts[1];
          if (!path.startsWith('-') && !path.startsWith('$') && !path.includes('/dev/')) {
            add({ path, args: elts.slice(2), interpreter: interp });
            return true;
          }
        }
      }
      // string form: subprocess.run("bash x.sh backup", shell=True)
      if (firstArg && firstArg.name === 'String') {
        const sc = parseShellString(stringValue(srcSlice(firstArg)));
        if (sc) add(sc);
      }
    } else if (mod === 'os' && OS_FUNCS.has(funcName)) {
      // os.system("bash x.sh backup")
      if (firstArg && firstArg.name === 'String') {
        const sc = parseShellString(stringValue(srcSlice(firstArg)));
        if (sc) add(sc);
      }
    }
    return true;
  });

  // relative imports: from . import x / from .x import y
  const cursor2 = tree.cursor();
  cursor2.iterate((n) => {
    const node = n.node;
    if (node.name !== 'ImportStatement') return true;
    const txt = srcSlice(node);
    if (!/^from\s+\./m.test(txt)) return true;
    // extract module names after import keyword
    const m = txt.match(/\bimport\s+(.+)$/m);
    if (m) {
      for (const part of m[1].split(',')) {
        const name = part.trim().replace(/\s+as\s+\w+$/, '');
        if (name && name !== '*') add({ path: name.replace(/\./g, '/') + '.py', args: [], interpreter: 'python3' });
      }
    }
    return true;
  });

  return calls;
}

function extractCallsRegex(content: string): ScriptCall[] {
  const calls: ScriptCall[] = [];
  CHILD_CALL_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
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

// ==================== PythonBackend ====================

export class PythonBackend implements LanguageBackend {
  language = 'python';

  parse(content: string | null | undefined, entryArgs: string[] | null): ScriptIR {
    const c = content || '';
    SOURCE = c;
    const sourceLines = c.split('\n');
    const lineStarts = buildLineStarts(c);
    const env = makeEnv(entryArgs || []);
    const lines = new Set<number>();
    const branches: BranchInfo[] = [];

    // budget fuse: over line limit → full text fail-closed
    if (sourceLines.length > MAX_LINES) {
      return {
        reachableContent: c,
        controlFlowResolved: false,
        calls: extractCallsRegex(c),
        branches: [],
        unresolvedSnippets: [],
        language: this.language,
      };
    }

    let tree: SyntaxNode;
    try {
      tree = parser.parse(c).topNode;
    } catch {
      // malformed script: full text fail-closed, still try to extract calls
      return {
        reachableContent: c,
        controlFlowResolved: false,
        calls: extractCallsRegex(c),
        branches: [],
        unresolvedSnippets: [],
        language: this.language,
      };
    }

    const stmts = bodyStmts(tree);
    processStmts(stmts, env, lineStarts, lines, branches);
    const reachable = reconstruct(sourceLines, lines);

    // child-call extraction (AST-first; only calls inside reachable branches)
    let calls = extractCallsFromTree(tree, lines);
    if (calls.length === 0) calls = extractCallsRegex(c);

    // resolved = content actually pruned (compare non-blank line sets, ignore trailing newline)
    const srcNonblank = sourceLines.filter((l) => l.trim().length > 0);
    const rcNonblank = reachable.split('\n').filter((l) => l.trim().length > 0);
    const resolved = rcNonblank.length !== srcNonblank.length || rcNonblank.some((l, i) => l !== srcNonblank[i]);

    return {
      reachableContent: reachable,
      controlFlowResolved: resolved,
      calls,
      branches,
      unresolvedSnippets: [],
      language: this.language,
    };
  }
}
