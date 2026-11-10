/**
 * Formal engine — unified behavior-graph IR (data model + interface).
 * Mirrors Python agent_moss/engine/formal_engine/ir.py EXACTLY.
 *
 * Turns an agent's historical actions into a behavior graph
 * (nodes = actions/tool calls, edges = time order / data flow),
 * which FormalEngine verifies against safety properties.
 *
 * Data sources (backward compatible):
 * - Single session: built from existing actionHistory/promptHistory — no caller change.
 * - Multi session: caller (incl. future agentgate non-intrusive collection) passes
 *   multiple sessions' histories → MultiSessionGraph with cross-session data edges
 *   (shared files/memory/tools). coordinator gains optional `sessionHistory`;
 *   when absent only the current session graph is built (identical behavior, zero regression).
 */

export interface ActionNode {
  sessionId: string;
  seq: number;
  actionType: string;
  actionDetail: string;
  /** Matched kill-chain stage ('' if none): LISTEN/EXEC/SCAN/CRED/EXFIL/PERSIST/PRIVESC. */
  stage: string;
  /** Involved resources (file paths / carriers / tool targets). */
  resources: Set<string>;
  /** Integrity label (high/medium/low; min-propagation along data edges, low-flows principle). */
  integrity: string;
  /** Low-integrity source (external fetch/download/injected content) → its resources are inherited low by later actions. */
  isLowSource: boolean;
}

export interface BehaviorEdge {
  /** Source node index (global graph index). */
  src: number;
  dst: number;
  /** 'next' (time order) | 'data' (shared resource flow) | 'call' (invocation). */
  kind: 'next' | 'data' | 'call';
}

export interface SessionGraph {
  sessionId: string;
  nodes: ActionNode[];
  edges: BehaviorEdge[];
  stageFlags: Set<string>;
}

export interface MultiSessionGraph {
  sessions: SessionGraph[];
  crossEdges: BehaviorEdge[];
  /**
   * witness 语义（实时判定）：当 verify 带 aNext 时，图末节点（索引 = witnessIdx）
   * 即"当前拟执行动作"；性质检查只当该节点补全链/触发后置外传时才判违规
   * （修复"历史全局匹配 → 永久拒绝锁定"FP，镜像 Python ir.py witness_idx）。
   * undefined = 低频回顾（/api/v1/review 全量历史），报告历史中已形成的违规。
   */
  witnessIdx?: number;
}

export function allNodes(mg: MultiSessionGraph): ActionNode[] {
  const out: ActionNode[] = [];
  for (const s of mg.sessions) out.push(...s.nodes);
  return out;
}

export function allEdges(mg: MultiSessionGraph): BehaviorEdge[] {
  const out: BehaviorEdge[] = [];
  for (const s of mg.sessions) out.push(...s.edges);
  out.push(...mg.crossEdges);
  return out;
}

export interface PropertyViolation {
  propertyId: string;
  reason: string;
  riskLevel: string;
  /** Counter-example path: [(sessionId, seq, actionDetail)] */
  path: { sessionId: string; seq: number; detail: string }[];
}

export interface FormalVerificationResult {
  verified: boolean;
  violations: PropertyViolation[];
}

export function emptyVerificationResult(): FormalVerificationResult {
  return { verified: true, violations: [] };
}
