/**
 * Stateful incremental behavior analysis — 有状态的增量行为链分析器。
 * Mirrors Python agent_moss/engine/formal_engine/stateful.py EXACTLY.
 *
 * 把"每次请求传什么就分析什么"改成"时间线持续累积 + 每次新动作增量推进链指针 +
 * 生命周期（能力鲜活度）判定"：
 * - StatefulChainTracker: 按 agent 维护一条安全相关事件时间线（追加模式）。
 * - 增量判定: 每来一个新动作，只做一次阶段命中比较 + 链指针推进（O(链数)），
 *   产出 matched（链补全 → 阻断）与 pendingPrefixes（待攻击前序）。
 * - 生命周期: create/destroy 信号（kill/systemctl stop/rm）与创建失败（is_error）
 *   → alive/dead/never_activated；dead 资源不再参与后续链段（堵"服务已关仍判链"误报）。
 * - 敏感数据传播（P2）: 增量 taint，最终 EXFIL 形态即违反。
 *
 * 与 FormalEngine 关系：全量无状态快照验证（低频/后台用）；本模块为增量有状态版本
 * （每次 tool call 实时用），结果应一致。
 */

import { loadL2 } from '../../infra/rules-loader';
import { matchStageAny } from './decode';

// ---------------- 生命周期/敏感数据 辅助正则 ----------------
const DESTROY_RE = /\b(?:pkill|kill)\b|systemctl\s+stop|service\s+stop|crontab\s+-r|rm\s+-[rf]?\s+/i;
const NEVER_ACTIVATED_RE =
  /\b(?:not\s+found|no\s+such\s+file|command\s+not\s+found|refused|failed\s+to\s+(?:start|bind|listen)|address\s+already\s+in\s+use)\b/i;
const CRED_FILE_RE = /(known_hosts|\.ssh|id_rsa|\/etc\/shadow|\/etc\/passwd|credentials)/i;
// 排回环（localhost/127.x/0.0.0.0/::1）：curl/自检本地服务不算数据外传。
// 与 l2_rules.json EXFIL 同步（唯一事实源在外层规则，此处为 P2 taint 判定镜像）。
const EXFIL_RE = /https?:\/\/(?!127\.\d+\.\d+\.\d+|0\.0\.0\.0|localhost|\[?::1\]?)|scp\s+.*@|rsync\s+.*@/i;

// ---- 实例资源提取（端口 / socket / systemd unit / 可执行载体）----
// 目标：把"不同端口的 LISTEN"区分成不同实例，链指针按实例推进，避免
// 不同监听串扰（A 端口的进度被 B 端口动作推进 → 误报）。无实例信息时
// 回退全局共享桶（保守，不漏判）。
const PORT_RE = /(?:-p\s+(\d{1,5})|-p(\d{1,5})|:(\d{1,5})\b)/i;
// SCAN 阶段常以裸端口形态出现（nc -z host 9999 / nmap -p 22）——放行"独立数字参数"为端口。
const BARE_PORT_RE = /(?<=^|\s)(\d{1,5})(?=\s|$)/g;
const SOCK_RE = /([\w./-]*(?:\/tmp\/|\/var\/run\/|\.sock\b)[\w./-]*)/;
const UNIT_RE = /systemctl\s+(?:start|enable|restart)\s+([\w.-]+)/i;
const LISTEN_VERB_RE = /(?:flask|uvicorn|gunicorn)\s+run|http\.server|httpserver|listen\(|bind\(/i;
// 有"端口实例"语义的阶段：LISTEN/PERSIST（开放端口）+ SCAN（探查具体端口）；
// EXEC/CRED/EXFIL 等不绑定单一监听资源，避免 URL/命令参数误归属。
const PORT_STAGE_RE = /LISTEN|PERSIST|SCAN/;
const LISTEN_ONLY_RE = /LISTEN|PERSIST/; // http 默认端口仅对监听/持久化阶段生效

/** 从动作文本提取实例 key（null = 无实例信息，走全局桶）。 */
export function extractInstances(actionDetail: string, stage: string): string[] {
  const out: string[] = [];
  // 仅 LISTEN/PERSIST 阶段承载"可独立命名的资源实例"；
  // 其他阶段（EXEC/SCAN/CRED/EXFIL/PRIVESC）一般不绑定单一监听资源，
  // 交由全局桶处理（无信息时保守推进全部桶）。
  if (PORT_STAGE_RE.test(stage)) {
    const d = actionDetail;
    let m: RegExpExecArray | null;
    const re = new RegExp(PORT_RE.source, 'gi');
    while ((m = re.exec(d)) !== null) {
      const p = m[1] || m[2] || m[3];
      if (p && Number(p) > 0 && Number(p) <= 65535) out.push(`port:${p}`);
    }
    // SCAN 阶段：裸端口数字参数（nc -z host 9999 / nmap ... 22）
    if (/SCAN/.test(stage)) {
      const bareRe = new RegExp(BARE_PORT_RE.source, 'g');
      while ((m = bareRe.exec(d)) !== null) {
        if (m[1] && Number(m[1]) > 0 && Number(m[1]) <= 65535) out.push(`port:${m[1]}`);
      }
    }
    m = SOCK_RE.exec(d);
    if (m && m[1]) out.push(`sock:${m[1]}`);
    m = UNIT_RE.exec(d);
    if (m && m[1]) out.push(`unit:${m[1]}`);
    // LISTEN_VERB 无端口形态（python -m http.server、flask run）→ 不臆测端口，
    // 走全局桶（与无端口链一致，保守补全）。
  }
  return out;
}

/** 全局共享桶 key（无实例信息的动作推进它）。 */
export const GLOBAL_BUCKET = '__global__';

/** 桶 key：chainId 与实例组合。兼容旧快照（无 @@ 分隔 = 全局桶）。 */
export function buckKey(chainId: string, inst: string | null): string {
  return inst ? `${chainId}@@${inst}` : chainId;
}

/** 从桶 key 解析 chainId。 */
export function chainIdOfBucket(key: string): string {
  const i = key.indexOf('@@');
  return i >= 0 ? key.slice(0, i) : key;
}

/** 判断桶 key 是否属于某实例（非全局）。 */
export function isInstanceBucket(key: string): boolean {
  return key.includes('@@');
}

export interface StateNode {
  seq: number;
  sessionId: string;
  actionType: string;
  actionDetail: string;
  stage: string;
  resources: string[];
  /** 实例 key（端口 / socket / unit）。空 = 无实例信息（走全局桶）。 */
  instances: string[];
  isError: boolean;
  /** "" | "alive" | "dead" | "never_activated" */
  lifecycle: string;
  /** 真实发生时间（ISO，来自 action.called_at；缺失 → null，退化为 seq） */
  timestamp: string | null;
}

export interface PendingPrefix {
  chainId: string;
  stages: string[];
  matched: number;
  riskLevel: string;
  /** 当前前序链的下一阶段（matched<len 时为 stages[matched]，否则空）。 */
  readonly nextStage: string;
}

export function nextStageOf(p: PendingPrefix): string {
  return p.matched < p.stages.length ? p.stages[p.matched] : '';
}

export interface PathItem {
  sessionId: string;
  seq: number;
  detail: string;
}

export interface ChainMatch {
  chainId: string;
  stages: string[];
  riskLevel: string;
  reason: string;
  path: { sessionId: string; seq: number; stage: string; timestamp: string | null }[];
}

export function chainMatchToJudgment(m: ChainMatch) {
  return {
    property_id: 'cross-' + m.chainId,
    reason: m.reason,
    risk_level: m.riskLevel,
    // path 每步含时间戳：[session_id, seq, stage, timestamp]
    path: m.path.map(p => [p.sessionId, p.seq, p.stage, p.timestamp] as (string | number | null)[]),
  };
}

export interface JudgmentLike {
  property_id: string;
  reason: string;
  risk_level: string;
  path: (string | number)[][];
}

export interface AdvanceResult {
  seq: number;
  node: StateNode | null;
  matched: ChainMatch | null;
  pendingPrefixes: PendingPrefix[];
  exfil: JudgmentLike[];
  readonly shouldBlock: boolean;
}

// ---------------- 阶段/资源（复用 L2 combo_stages，单一事实源） ----------------

let STAGES_PATTERNS: Record<string, RegExp[]> | null = null;
let CHAINS: any[] | null = null;

function loadRules(): { stages: Record<string, RegExp[]>; chains: any[] } {
  if (STAGES_PATTERNS !== null && CHAINS !== null) {
    return { stages: STAGES_PATTERNS, chains: CHAINS };
  }
  const combo = ((loadL2().combo_chains || {}) as any);
  const stages: Record<string, RegExp[]> = {};
  for (const [name, pats] of Object.entries((combo.stages || {}) as Record<string, string[]>)) {
    stages[name] = (pats as string[]).map(p => new RegExp(p, 'i'));
  }
  const chains = (combo.chains || []) as any[];
  STAGES_PATTERNS = stages;
  CHAINS = chains;
  return { stages, chains };
}

function markStage(actionDetail: string): string {
  const { stages } = loadRules();
  return matchStageAny(actionDetail, stages);
}

function extractResources(actionDetail: string): string[] {
  const text = actionDetail.replace(/'[^']*'|"[^"]*"/g, '');
  const out: string[] = [];
  const re = /(?:^|\s|[@=])((?:\/|~\/)[\w./~-]+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const p = m[1];
    if (p.startsWith('/dev/') || p.includes('://')) continue;
    if (!out.includes(p)) out.push(p);
  }
  return out;
}

function lifecycleFor(detail: string, stage: string, isError: boolean): string {
  if (isError) {
    if (stage === 'LISTEN' || stage === 'PERSIST' || NEVER_ACTIVATED_RE.test(detail)) return 'never_activated';
  }
  if (DESTROY_RE.test(detail)) return 'dead';
  if (stage === 'LISTEN' || stage === 'PERSIST') return 'alive';
  if (detail.includes('>>') || detail.includes('>')) return 'alive';
  return '';
}

// 时间线上限（安全相关节点）；超限忽略新节点，建议定期 review 重建。
const MAX_NODES = 100_000;

export class StatefulChainTracker {
  /** 本地接收时刻（实时路径无 called_at 时的兜底时间戳，ISO）。 */
  static now(): string {
    return new Date().toISOString();
  }

  agentId: string;
  private nodes_: StateNode[] = [];
  private ptr: Record<string, number> = {};
  private tainted: Set<number> = new Set();
  /** taint 反索引：资源路径 → 已染毒（O(1) 命中）。 */
  private taintedResources: Set<string> = new Set();
  private aliveResources: Record<string, number> = {};
  seqNext: number = 0;

  constructor(agentId = '') {
    this.agentId = agentId;
    loadRules();
  }

  get nodes(): StateNode[] {
    return this.nodes_;
  }

  get pendingPrefixes(): PendingPrefix[] {
    const { chains } = loadRules();
    const out: PendingPrefix[] = [];
    for (const chain of chains) {
      const stages = (chain.stages || []) as string[];
      if (stages.length === 0) continue;
      const cid = String(chain.id || '');
      // 聚合该 chain 的所有桶（全局 + 各实例），取最大进度作为该链的前序进度。
      // 任一实例推进到"缺最后一步"都算 pending，满足预判需求。
      let matched = this.ptr[cid] || 0;
      for (const [k, v] of Object.entries(this.ptr)) {
        if (k.startsWith(`${cid}@@`) && v > matched && v < stages.length) matched = v;
      }
      if (matched > 0 && matched < stages.length) {
        const pf: PendingPrefix = {
          chainId: cid,
          stages,
          matched,
          riskLevel: String(chain.riskLevel || chain.risk_level || 'high'),
          get nextStage() {
            return this.matched < this.stages.length ? this.stages[this.matched] : '';
          },
        };
        out.push(pf);
      }
    }
    return out;
  }

  get aliveResourcesSnapshot(): Record<string, number> {
    return { ...this.aliveResources };
  }

  /**
   * 全量/定期灌入历史 session（多 session 各动作追加到时间线）。
   * 历史节点同样推进链指针 / 生命周期 / taint，否则后续 advance 无法在历史基础上
   * 补全链。历史阶段推进若补全链，属于历史事实，不阻断当前动作。
   */
  seed(sessions?: { sessionId?: string; actionHistory?: { actionType?: string; actionDetail?: string }[] }[]): number {
    let added = 0;
    for (const s of sessions || []) {
      const sid = String(s.sessionId || 's');
      for (const a of s.actionHistory || []) {
        const node = this.appendNode(a, sid);
        if (!node) {
          continue;
        }
        added += 1;
        this.recordLifecycle(node);
        this.advanceTaint(node);
        this.advanceChains(node); // 历史阶段推进指针（补全匹配属于历史，忽略）
      }
    }
    return added;
  }

  /** 增量推进：把当前动作追加到时间线 → 链指针推进 → 判定。 */
  advance(args: {
    aNext: { actionType?: string; actionDetail?: string };
    actionHistory?: { actionType?: string; actionDetail?: string }[];
    sessionId?: string;
    isError?: boolean;
  }): AdvanceResult {
    const { aNext, sessionId = 'current', isError = false } = args;
    const node = this.appendNode(aNext, sessionId, isError);
    if (!node) {
      return { seq: this.seqNext, node: null, matched: null, pendingPrefixes: this.pendingPrefixes, exfil: [], shouldBlock: false };
    }
    const seq = this.seqNext;
    this.recordLifecycle(node);

    const matched = this.advanceChains(node);
    this.advanceTaint(node);
    const exfil = this.checkExfilAfterTaint(node);
    return {
      seq,
      node,
      matched,
      pendingPrefixes: this.pendingPrefixes,
      exfil,
      get shouldBlock() {
        return this.matched !== null || this.exfil.length > 0;
      },
    };
  }

  appendNode(action: { actionType?: string; actionDetail?: string }, sessionId: string, isError = false): StateNode | null {
    const ad = String(action.actionDetail || '');
    const at = String(action.actionType || '');
    if (!ad) return null;
    if (this.nodes_.length >= MAX_NODES) {
      // 时间线上限保护：超限忽略新节点（seq==index 不变式不破坏），建议 review 重建
      return null;
    }
    const stage = markStage(ad);
    const node: StateNode = {
      seq: this.seqNext,
      sessionId,
      actionType: at,
      actionDetail: ad,
      stage,
      resources: extractResources(ad),
      instances: extractInstances(ad, stage),
      isError,
      lifecycle: lifecycleFor(ad, stage, isError),
      timestamp: typeof (action as any).calledAt === 'string' ? (action as any).calledAt : StatefulChainTracker.now(),
    };
    this.nodes_.push(node);
    this.seqNext += 1;
    return node;
  }

  private recordLifecycle(node: StateNode): void {
    if (node.lifecycle === 'dead') {
      // a) 精确实例定位：销毁动作显式提到端口/socket/unit
      const clearedInsts: string[] = [];
      for (const inst of node.instances) {
        const key = `inst:${inst}`;
        if (key in this.aliveResources) {
          delete this.aliveResources[key];
          clearedInsts.push(inst);
        }
      }
      // b) 路径/basename 定位（文件载体销毁，无法精确到桶）
      let pathHit = false;
      for (const r of node.resources) {
        if (r in this.aliveResources) {
          delete this.aliveResources[r];
          pathHit = true;
        }
      }
      const detail = node.actionDetail;
      for (const r of Object.keys(this.aliveResources)) {
        const base = r.split('/').pop() || '';
        if (base && detail.includes(base)) {
          delete this.aliveResources[r];
          pathHit = true;
        }
      }
      // c) 判定：纯实例销毁 → 只清对应实例桶（不误杀其他端口）；
      //    命中文件载体或无法定位 → 保守全清（原行为，置底防线）
      if (clearedInsts.length > 0 && !pathHit) {
        for (const inst of clearedInsts) this.resetChainsForInstance(inst);
      } else {
        this.resetChainsOnDestroy();
      }
      return;
    }
    if (node.lifecycle === 'alive') {
      // 资源路径照旧登记
      for (const r of node.resources) {
        this.aliveResources[r] = node.seq;
      }
      // 实例也登记（inst: 前缀），供后续实例级销毁/活性判定
      for (const inst of node.instances) {
        this.aliveResources[`inst:${inst}`] = node.seq;
      }
    }
  }

  /** 只重置指定实例在全部链上的进度（不影响其他端口/资源）。 */
  private resetChainsForInstance(inst: string): void {
    const key = buckKey('', inst).slice(2); // chainId 前导忽略，直接算前缀
    for (const k of Object.keys(this.ptr)) {
      if (k.endsWith(`@@${inst}`)) this.ptr[k] = 0;
    }
  }

  private resetChainsOnDestroy(): void {
    for (const cid of Object.keys(this.ptr)) {
      this.ptr[cid] = 0;
    }
  }

  /**
   * 当前节点应推进的链桶集合。
   * - 有实例节点（LISTEN/PERSIST 带端口/socket/unit）→ 只推自己的实例桶；
   *   同时为所有链的该实例建立桶（若首次出现）。
   * - 无实例节点（EXEC/SCAN 等中间段）→ 推全局桶 + 所有当前活跃实例桶
   *   （信息不足时保守推进一切可能，避免漏判）。
   */
  private targetsForNode(node: StateNode, chainId: string): string[] {
    const insts = node.instances;
    if (insts.length > 0) {
      // 精确分支：只推"活跃匹配"的实例桶（同端口才归同一链，不同端口不串扰）。
      const active = insts.filter((i) => this.aliveResources[`inst:${i}`] !== undefined);
      if (active.length > 0) return active.map((i) => buckKey(chainId, i));
      // 端口无对应活跃监听（信息孤岛/独立于既有链）→ 回退全局桶（保守补全无端口链）。
      return [chainId];
    }
    const targets = [chainId]; // 全局桶
    for (const k of Object.keys(this.aliveResources)) {
      if (k.startsWith('inst:')) {
        const inst = k.slice('inst:'.length);
        targets.push(`${chainId}@@${inst}`);
      }
    }
    return targets;
  }

  private advanceChains(node: StateNode): ChainMatch | null {
    if (node.lifecycle === 'dead') return null;
    if (node.lifecycle === 'never_activated') {
      this.invalidateChainOnFailure(node);
      return null;
    }
    const stage = node.stage;
    if (!stage) return null;
    const { chains } = loadRules();
    for (const chain of chains) {
      const stages = (chain.stages || []) as string[];
      if (stages.length === 0) continue;
      const cid = String(chain.id || '');
      // 当前动作若命中链的首阶段 LISTEN → 应在所有目标桶上"从 0 开始"
      // （桶首次出现时从 0 推进；已推进的桶保持 cur）
      const targets = this.targetsForNode(node, cid);
      for (const key of targets) {
        const cur = this.ptr[key] || 0;
        if (cur < stages.length && stages[cur] === stage) {
          this.ptr[key] = cur + 1;
          if (cur + 1 >= stages.length) {
            return {
              chainId: cid,
              stages,
              riskLevel: String(chain.riskLevel || chain.risk_level || 'high'),
              reason: String(chain.reason || '检测到组合攻击链'),
              path: this.chainPath(stages),
            };
          }
        }
      }
    }
    return null;
  }

  private invalidateChainOnFailure(node: StateNode): void {
    // 实例级失败：只失效该实例的链桶；无实例信息则保守全清（原行为）。
    if (node.instances.length > 0) {
      for (const inst of node.instances) {
        this.resetChainsForInstance(inst);
      }
      return;
    }
    const failed = new Set(node.resources);
    if (failed.size === 0) return;
    const { chains } = loadRules();
    for (const chain of chains) {
      const cid = String(chain.id || '');
      if ((this.ptr[cid] || 0) > 0) {
        this.ptr[cid] = 0;
      }
    }
  }

  private chainPath(stages: string[]): { sessionId: string; seq: number; stage: string; timestamp: string | null }[] {
    const path: { sessionId: string; seq: number; stage: string; timestamp: string | null }[] = [];
    let want = stages[0];
    for (const n of this.nodes_) {
      if (n.stage === want) {
        path.push({ sessionId: n.sessionId, seq: n.seq, stage: n.stage, timestamp: n.timestamp });
        const idx = stages.indexOf(n.stage);
        if (idx + 1 < stages.length) {
          want = stages[idx + 1];
        } else {
          break;
        }
      }
    }
    return path;
  }

  // ---------------- 敏感数据 taint（P2） ----------------
  private advanceTaint(node: StateNode): void {
    if (node.lifecycle === 'dead') return;
    const idx = node.seq;
    const taintedRes = new Set<string>();
    for (const r of node.resources) {
      if (this.resourceTainted(r)) taintedRes.add(r);
    }
    if (node.stage === 'CRED' && node.resources.some(r => CRED_FILE_RE.test(r))) {
      this.tainted.add(idx);
      for (const r of node.resources) taintedRes.add(r);
    }
    if (taintedRes.size > 0) {
      this.tainted.add(idx);
      for (const r of taintedRes) this.taintedResources.add(r);
    }
  }

  private resourceTainted(resource: string): boolean {
    // O(1) 反索引命中（避免每次扫描全部染毒节点）
    return this.taintedResources.has(resource);
    return false;
  }

  private checkExfilAfterTaint(node: StateNode): JudgmentLike[] {
    if (!this.tainted.has(node.seq)) return [];
    if (EXFIL_RE.test(node.actionDetail)) {
      return [{
        property_id: 'sensitive-data-flow',
        reason: `敏感数据传播外传：${this.taintSource(node)} → ${node.sessionId}#${node.seq} 经共享载体外发`,
        risk_level: 'critical',
        path: [[node.sessionId, node.seq, node.actionDetail.slice(0, 60)]],
      }];
    }
    return [];
  }

  private taintSource(node: StateNode): string {
    const sorted = [...this.tainted].sort((a, b) => a - b);
    for (const i of sorted) {
      if (i === node.seq) continue;
      const n = this.nodes_[i];
      if (!n) continue;
      for (const r of node.resources) {
        if (n.resources.includes(r)) return `${n.sessionId}#${n.seq} 访问 ${r}`;
      }
    }
    return '未知凭据源';
  }

  // ---------------- 序列化/状态 ----------------
  toSnapshot(): Record<string, unknown> {
    return {
      agent_id: this.agentId,
      nodes: this.nodes_.map(n => ({ ...n, resources: [...n.resources] })),
      ptrs: { ...this.ptr },
      tainted: [...this.tainted].sort((a, b) => a - b),
      alive: { ...this.aliveResources },
      seq_next: this.seqNext,
    };
  }

  restore(snapshot: Record<string, unknown> | null | undefined): void {
    if (!snapshot) return;
    this.agentId = String(snapshot.agent_id || this.agentId);
    for (const raw of (snapshot.nodes as any[]) || []) {
      this.nodes_.push({
        seq: Number(raw.seq || 0),
        sessionId: String(raw.sessionId || ''),
        actionType: String(raw.actionType || ''),
        actionDetail: String(raw.actionDetail || ''),
        stage: String(raw.stage || ''),
        resources: [...((raw.resources as string[]) || [])],
        instances: [...((raw.instances as string[]) || [])], // 旧快照无此字段 → 空
        isError: Boolean(raw.isError),
        lifecycle: String(raw.lifecycle || ''),
        timestamp: typeof raw.timestamp === 'string' ? raw.timestamp : null, // 旧快照无此字段 → null
      });
    }
    this.seqNext = Number(snapshot.seq_next || this.nodes_.length);
    this.ptr = Object.fromEntries(Object.entries((snapshot.ptrs as Record<string, unknown>) || {}).map(([k, v]) => [k, Number(v)]));
    this.tainted = new Set((snapshot.tainted as number[] || []).map(Number));
    // 重建 taint 资源反索引：由染毒节点的 resources 推导
    this.taintedResources = new Set();
    for (const i of this.tainted) {
      const n = this.nodes_[i];
      if (n) for (const r of n.resources) this.taintedResources.add(r);
    }
    this.aliveResources = Object.fromEntries(
      Object.entries((snapshot.alive as Record<string, unknown>) || {}).map(([k, v]) => [k, Number(v)])
    );
  }
}

/** 便捷入口：先 seed 历史，再 advance 当前动作。 */
export function advanceIfCompletesChain(args: {
  tracker: StatefulChainTracker;
  sessions?: { sessionId?: string; actionHistory?: { actionType?: string; actionDetail?: string }[] }[];
  actionHistory?: { actionType?: string; actionDetail?: string }[];
  aNext: { actionType?: string; actionDetail?: string };
  sessionId?: string;
  isError?: boolean;
}): AdvanceResult {
  args.tracker.seed(args.sessions);
  return args.tracker.advance(args);
}