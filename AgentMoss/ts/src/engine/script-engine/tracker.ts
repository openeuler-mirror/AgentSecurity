/**
 * Script-engine RecursiveTracker — cross-script call chain traversal.
 * Mirrors Python agent_moss/engine/script_engine/tracker.py.
 *
 * Language-agnostic (consumes ScriptIR.calls):
 * - Depth budget (default 14), replacing old fixed max_depth=3.
 * - Cycle detection (DFS visiting set), preventing A→B→A infinite recursion.
 * - Cross-script arg passing: each child uses ITS OWN call args for branch
 *   awareness (fixes old sub-call param loss bug).
 * - Node/byte budgets prevent memory blowup (keeps peak RSS flat vs current).
 *
 * Contract with coordinator: command_scanner runs inline L1 on each node's
 * reachableContent (high/critical short-circuit). Returns ScriptChainAnalysisResult
 * (compatible with existing ScriptNode structure).
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import type { AnalysisInput } from '../coordinator';
import { ScriptNode, ScriptChainAnalysisResult } from '../script-content-analyzer';
import { ScriptIR } from './ir';
import { PythonBackend } from './backends/python-backend';
import { ShellBackend } from './backends';
import type { LanguageBackend } from './backends';

const DEFAULT_MAX_DEPTH = 14;
const DEFAULT_MAX_NODES = 64;
const DEFAULT_MAX_FILE_SIZE = 2 * 1024 * 1024;
const DEFAULT_MAX_TOTAL_SIZE = 8 * 1024 * 1024;

// Language backend registry — dispatch by script file extension.
// Adding a language = register here + new backend.
const BACKENDS: Record<string, LanguageBackend> = {
  '.py': new PythonBackend(),
};
const DEFAULT_BACKEND = new ShellBackend();

function pickBackend(pathStr: string): LanguageBackend {
  const lower = pathStr.toLowerCase();
  for (const ext of Object.keys(BACKENDS)) {
    if (lower.endsWith(ext)) return BACKENDS[ext];
  }
  return DEFAULT_BACKEND;
}

export function resolvePath(p: string, baseDir?: string): string {
  let expanded = p;
  if (expanded.startsWith('~/') || expanded === '~') {
    expanded = path.join(os.homedir(), expanded.slice(1));
  } else if (!path.isAbsolute(expanded) && baseDir) {
    expanded = path.join(baseDir, expanded);
  }
  return path.resolve(expanded);
}

function readScript(
  pathStr: string,
  maxFileSize: number,
): { content: string; lineCount: number; fileSize: number; error: string } {
  try {
    const p = resolvePath(pathStr);
    if (!fs.existsSync(p)) return { content: '', lineCount: 0, fileSize: 0, error: `脚本不存在: ${pathStr}` };
    const stat = fs.statSync(p);
    if (!stat.isFile()) return { content: '', lineCount: 0, fileSize: 0, error: `不是文件: ${pathStr}` };
    if (stat.size > maxFileSize) {
      return { content: '', lineCount: 0, fileSize: stat.size, error: `脚本文件过大 (${stat.size} bytes)，跳过读取` };
    }
    const content = fs.readFileSync(p, 'utf-8');
    return { content, lineCount: content ? content.split('\n').length : 0, fileSize: stat.size, error: '' };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { content: '', lineCount: 0, fileSize: 0, error: `读取脚本失败: ${msg}` };
  }
}

function emptyNode(pathStr: string, depth: number): ScriptNode {
  return {
    scriptPath: pathStr, rawContent: '', preprocessedContent: '', lineCount: 0,
    fileSize: 0, depth, childPaths: [], error: '',
    l1Hit: false, l1RiskLevel: '', l1RiskType: '', l1Reason: '', l1MatchedPatterns: [],
    l2Hit: false, l2ViolatedRule: '', l2RiskLevel: '', l2RiskType: '', l2Reason: '',
    matchedKeywords: [], isSuspicious: false, keywordRiskLevel: '', keywordRiskReason: '',
  };
}

/** Lightweight L1 check compatible with the current scan contract. */
type L1Scanner = (content: string) => { hit: boolean; riskLevel: string; riskType: string; reason: string; matchedPatterns: string[] };

export class RecursiveTracker {
  private result: ScriptChainAnalysisResult;
  private visiting = new Set<string>();
  private visitedPaths = new Set<string>();
  private _scanner: L1Scanner | null;

  constructor(
    commandScanner: L1Scanner | null,
    private maxDepth = DEFAULT_MAX_DEPTH,
    private maxNodes = DEFAULT_MAX_NODES,
    private maxFileSize = DEFAULT_MAX_FILE_SIZE,
    private maxTotalSize = DEFAULT_MAX_TOTAL_SIZE,
  ) {
    this._scanner = commandScanner;
    this.result = {
      nodes: [], entryPath: '', maxDepthReached: false, maxSizeReached: false,
      maxNodesReached: false, totalSize: 0, totalLines: 0, totalNodes: 0,
      hasCritical: false, hasHigh: false, firstHitNode: null, error: '',
    };
  }

  track(entryPath: string, entryArgs: string[] | null, cwd: string = ''): ScriptChainAnalysisResult {
    const baseDir = cwd || process.cwd();
    const resolved = resolvePath(entryPath);
    this.result.entryPath = resolved;

    this.visitScript(resolved, 0, path.dirname(resolved), entryArgs);

    const nodes = this.result.nodes;
    this.result.hasCritical = nodes.some(n =>
      n.l1RiskLevel === 'critical' || n.l2RiskLevel === 'critical' || n.keywordRiskLevel === 'critical') || this.result.hasCritical;
    this.result.hasHigh = nodes.some(n =>
      ['high', 'critical'].includes(n.l1RiskLevel) ||
      ['high', 'critical'].includes(n.l2RiskLevel) ||
      ['high', 'critical'].includes(n.keywordRiskLevel));
    this.result.firstHitNode = nodes.find(n => n.l1Hit || n.l2Hit || n.isSuspicious) || null;
    return this.result;
  }

  private visitScript(pathStr: string, depth: number, baseDir: string, args: string[] | null): void {
    pathStr = resolvePath(pathStr);

    if (this.visiting.has(pathStr)) return;
    if (this.visitedPaths.has(pathStr)) return;
    if (depth > this.maxDepth) {
      this.result.maxDepthReached = true;
      return;
    }
    if (this.result.nodes.length >= this.maxNodes) {
      this.result.maxNodesReached = true;
      return;
    }
    if (this.result.totalSize >= this.maxTotalSize) {
      this.result.maxSizeReached = true;
      return;
    }

    this.visiting.add(pathStr);
    this.visitedPaths.add(pathStr);

    const { content, lineCount, fileSize, error } = readScript(pathStr, this.maxFileSize);
    if (error) {
      const node = emptyNode(pathStr, depth);
      node.error = error;
      node.fileSize = fileSize;
      node.lineCount = lineCount;
      this.result.nodes.push(node);
      this.visiting.delete(pathStr);
      return;
    }

    this.result.totalSize += fileSize;
    this.result.totalLines += lineCount;

    const ir: ScriptIR = pickBackend(pathStr).parse(content, args);
    const node = emptyNode(pathStr, depth);
    node.rawContent = content;
    node.preprocessedContent = ir.reachableContent;
    node.lineCount = lineCount;
    node.fileSize = fileSize;
    this.result.nodes.push(node);
    this.result.totalNodes = this.result.nodes.length;

    // inline L1
    if (this._scanner && ir.reachableContent) {
      const l1 = this._scanner(ir.reachableContent);
      if (l1.hit) {
        node.l1Hit = true;
        node.l1RiskLevel = l1.riskLevel;
        node.l1RiskType = l1.riskType;
        node.l1Reason = l1.reason;
        node.l1MatchedPatterns = l1.matchedPatterns || [];
        if (l1.riskLevel === 'critical') {
          this.result.hasCritical = true;
          this.result.firstHitNode = node;
          this.visiting.delete(pathStr);
          return;
        }
      }
    }

    // child calls (with args) → recurse
    // 相对子路径按当前脚本目录解析（对齐 Python _resolve_path(call.path, parent dir)），
    // 不能基于 process.cwd()（那会导致 `./child.sh` 解析错目录，DRY 掉 9+ 层深链）。
    const parentDir = path.dirname(pathStr);
    const childPaths: string[] = [];
    for (const call of ir.calls) {
      const child = resolvePath(call.path, parentDir);
      childPaths.push(child);
      this.visitScript(child, depth + 1, path.dirname(child), call.args);
      if (this.result.hasCritical) break;
    }
    node.childPaths = childPaths;

    this.visiting.delete(pathStr);
  }
}