/**
 * Script analysis engine — unified intermediate representation (IR).
 *
 * Mirrors Python agent_moss/engine/script_engine/ir.py.
 *
 * Language backends (Shell/Python/Node...) parse source scripts into
 * uniform IR:
 * - ScriptIR.reachableContent: statically-determinable reachable content
 *   (fed to L1/L2/L3 scanners, replacing full-text scan).
 * - ScriptIR.calls: child script calls (path + args), consumed by
 *   RecursiveTracker.
 *
 * IR is language-agnostic. Adding a language = new backend producing the
 * same IR; Scanner/Tracker unchanged.
 */

/** Child script call — path + args. Consumed by RecursiveTracker. */
export interface ScriptCall {
  path: string;
  args: string[];
  interpreter: string;
}

/** Single control-flow branch (case / if / loop body). */
export interface BranchInfo {
  kind: 'case' | 'if' | 'loop';
  label: string;
  body: string;
  reachable: boolean;
}

/** Static analysis IR for a single script. */
export interface ScriptIR {
  /** Statically-proven reachable content (scanner input). */
  reachableContent: string;
  /** True if control flow was recognized (some unreachable content dropped). */
  controlFlowResolved: boolean;
  /** Child script calls. */
  calls: ScriptCall[];
  /** Control-flow summary (audit). */
  branches: BranchInfo[];
  /** Fragments that couldn't be statically judged (fail-closed). */
  unresolvedSnippets: string[];
  /** Script language (shell / python / node / java...). */
  language: string;
}

export function emptyIR(): ScriptIR {
  return {
    reachableContent: '',
    controlFlowResolved: false,
    calls: [],
    branches: [],
    unresolvedSnippets: [],
    language: 'shell',
  };
}