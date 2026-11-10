/**
 * Formal engine — behavior-graph builder.
 * Mirrors Python agent_moss/engine/formal_engine/builder.py.
 *
 * Builds behavior graphs from action histories:
 * - buildSessionGraph(actionHistory, aNext?) → SessionGraph
 * - buildMultiSessionGraph(sessions, aNext?) → MultiSessionGraph (cross-session data edges)
 *
 * Stage marking reuses L2 l2_rules.json combo_chains.stages patterns
 * (single source of truth), so L2 combo-chain rules and the formal engine
 * agree on stage classification.
 */

import { loadL2 } from '../../infra/rules-loader';
import { matchStageAny } from './decode';
import { labelEvent } from './ltl';
import type { ActionNode, BehaviorEdge, MultiSessionGraph, SessionGraph } from './ir';

// stage patterns compiled from l2_rules.json combo_chains.stages
let COMBO_STAGES: Record<string, RegExp[]> | null = null;

function loadStages(): Record<string, RegExp[]> {
  if (COMBO_STAGES) return COMBO_STAGES;
  const combo = (loadL2().combo_chains || {}) as any;
  const stages: Record<string, RegExp[]> = {};
  for (const [name, pats] of Object.entries((combo.stages || {}) as Record<string, string[]>)) {
    stages[name] = (pats as string[]).map(p => new RegExp(p, 'i'));
  }
  COMBO_STAGES = stages;
  return stages;
}

// file-path extraction (/path, ~/path; strip quotes; allow @/= prefixes for
// tool-argument forms like curl -d @/tmp/x, --output=/tmp/x)
const PATH_RE = /(?:^|\s|[@=])((?:\/|~\/)[\w./~-]+)/g;

export function extractResources(actionDetail: string): Set<string> {
  const resources = new Set<string>();
  const text = actionDetail.replace(/'[^']*'|"[^"]*"/g, '');
  PATH_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = PATH_RE.exec(text)) !== null) {
    const p = m[1];
    if (p.startsWith('/dev/') || p.includes('://')) continue;
    resources.add(p);
  }
  return resources;
}

export function markStage(actionDetail: string): string {
  return matchStageAny(actionDetail, loadStages());
}

/**
 * 标记完整性标签 + 是否低完整性源（镜像 Python _mark_integrity）。
 * 低完整性源 = 外取/下载（download_file AP）或注入内容（prompt_injection AP）——
 * 其资源视为不可信，下游动作经共享载体继承 low（Rule 5 数据源）。
 */
function markIntegrity(actionDetail: string): { integrity: string; isLowSource: boolean } {
  const aps = labelEvent(actionDetail);
  if (aps.has('download_file') || aps.has('prompt_injection')) {
    return { integrity: 'low', isLowSource: true };
  }
  return { integrity: 'medium', isLowSource: false };
}

/** 统一构造 ActionNode（含 stage + resources + integrity 标记，镜像 Python _init_node）。 */
function initNode(sessionId: string, seq: number, actionType: string, actionDetail: string): ActionNode {
  const { integrity, isLowSource } = markIntegrity(actionDetail);
  return {
    sessionId, seq, actionType, actionDetail,
    stage: markStage(actionDetail),
    resources: extractResources(actionDetail),
    integrity, isLowSource,
  };
}

export function buildSessionGraph(
  actionHistory: { actionType?: string; actionDetail?: string }[],
  aNext?: { actionType?: string; actionDetail?: string },
  sessionId = 'current',
): SessionGraph {
  const nodes: ActionNode[] = [];
  const edges: BehaviorEdge[] = [];
  const stageFlags = new Set<string>();
  const details: { actionType: string; actionDetail: string }[] = [];
  for (const a of actionHistory) {
    const ad = String(a.actionDetail || '');
    if (ad) details.push({ actionType: String(a.actionType || ''), actionDetail: ad });
  }
  if (aNext) {
    details.push({ actionType: String(aNext.actionType || ''), actionDetail: String(aNext.actionDetail || '') });
  }
  details.forEach((d, seq) => {
    const node = initNode(sessionId, seq, d.actionType, d.actionDetail);
    nodes.push(node);
    if (node.stage) stageFlags.add(node.stage);
  });
  for (let i = 0; i < nodes.length - 1; i++) {
    edges.push({ src: i, dst: i + 1, kind: 'next' });
  }
  return { sessionId, nodes, edges, stageFlags };
}

export function buildMultiSessionGraph(
  sessions: { sessionId?: string; actionHistory?: { actionType?: string; actionDetail?: string }[] }[],
  aNext?: { actionType?: string; actionDetail?: string },
): MultiSessionGraph {
  const mg: MultiSessionGraph = { sessions: [], crossEdges: [] };
  if (!sessions || sessions.length === 0) {
    mg.sessions.push(buildSessionGraph([], aNext, 'current'));
    return mg;
  }
  for (const s of sessions) {
    const sid = String(s.sessionId || 's');
    mg.sessions.push(buildSessionGraph(s.actionHistory || [], undefined, sid));
  }
  if (aNext) {
    const last = mg.sessions[mg.sessions.length - 1];
    if (last.sessionId === 'current') {
      last.nodes.push(initNode(
        last.sessionId, last.nodes.length,
        String(aNext.actionType || ''), String(aNext.actionDetail || ''),
      ));
      if (last.nodes.length > 1) {
        last.edges.push({ src: last.nodes.length - 2, dst: last.nodes.length - 1, kind: 'next' });
      }
    } else {
      mg.sessions.push(buildSessionGraph([], aNext, 'current'));
    }
  }
  addCrossDataEdges(mg);
  return mg;
}

function addCrossDataEdges(mg: MultiSessionGraph): void {
  const nodes = allNodesFlat(mg);
  if (nodes.length < 2) return;
  // Performance: group node indices by resource (resource → [node_idx...]),
  // only compare node pairs sharing the same resource (and cross-session),
  // down from O(N²) all-pairs to O(N·R) (R = resource kinds). Deduplicate
  // node pairs that share multiple resources (one data edge per pair).
  const resIndex = new Map<string, number[]>();
  nodes.forEach((n, i) => {
    for (const r of n.resources) {
      const list = resIndex.get(r);
      if (list) list.push(i);
      else resIndex.set(r, [i]);
    }
  });
  const seen = new Set<string>();
  for (const idxs of resIndex.values()) {
    if (idxs.length < 2) continue;
    for (let a = 0; a < idxs.length; a++) {
      const i = idxs[a];
      for (let b = a + 1; b < idxs.length; b++) {
        const j = idxs[b];
        if (nodes[i].sessionId === nodes[j].sessionId) continue;
        const key = `${i}:${j}`;
        if (seen.has(key)) continue;
        seen.add(key);
        mg.crossEdges.push({ src: i, dst: j, kind: 'data' });
      }
    }
  }
}

function allNodesFlat(mg: MultiSessionGraph): ActionNode[] {
  const out: ActionNode[] = [];
  for (const s of mg.sessions) out.push(...s.nodes);
  return out;
}

function intersect(a: Set<string>, b: Set<string>): Set<string> {
  const out = new Set<string>();
  for (const v of a) if (b.has(v)) out.add(v);
  return out;
}
