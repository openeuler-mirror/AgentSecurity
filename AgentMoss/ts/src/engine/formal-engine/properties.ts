/**
 * Formal engine — safety property definitions (security invariants).
 * Mirrors Python agent_moss/engine/formal_engine/properties.py.
 *
 * Each property implements check(graph) → PropertyViolation[].
 *
 * Built-in properties (B/C classes that depend on behavior graph / data flow):
 * - P1 cross-session chain: stage subsequence matching over the multi-session
 *   concatenated graph (LISTEN→EXEC→SCAN may span sessions).
 * - P2 sensitive data flow: taint propagation along data edges — credential
 *   files touched in CRED stage flowing via shared carriers to EXFIL actions.
 *
 * fail-closed: unverifiable stages/resources treated as occurred; any
 * possibly-violating path is reported (keep more rather than miss).
 */

import { loadL2, loadToolRegistry } from '../../infra/rules-loader';
import type { MultiSessionGraph, PropertyViolation } from './ir';
import { allEdges, allNodes } from './ir';
import { checkMCRules } from './ltl';
import { stripStringLiterals } from './decode';

// ==================== P1 cross-session chain ====================

// Reuse l2_rules.json combo_chains.chains (single source of truth, same
// definitions as L2 in-session chains) but match over the multi-session graph.
interface ChainDef {
  id: string;
  stages: string[];
  riskLevel: string;
  reason: string;
}

let CROSS_SESSION_CHAINS: ChainDef[] | null = null;

function loadCrossSessionChains(): ChainDef[] {
  if (CROSS_SESSION_CHAINS) return CROSS_SESSION_CHAINS;
  const combo = (loadL2().combo_chains || {}) as any;
  CROSS_SESSION_CHAINS = ((combo.chains || []) as any[]).map((c: any) => ({
    id: String(c.id || 'combo_chain'),
    stages: (c.stages || []) as string[],
    riskLevel: String(c.riskLevel || c.risk_level || 'high'),
    reason: '跨会话' + String(c.reason || '组合攻击链'),
  }));
  return CROSS_SESSION_CHAINS;
}

// credential file feature (P2: files touched in CRED stage are taint sources)
const CRED_FILE_RE = /(known_hosts|\.ssh|id_rsa|\/etc\/shadow|\/etc\/passwd|credentials)/i;
// exfil action feature (P2/P4/P5: EXFIL stage or network-exfil shape).
// http(s) excludes loopback addresses (aligned with l2_rules.json EXFIL stage) to
// avoid curl 127.0.0.1/localhost health checks being misjudged as exfiltration.
const EXFIL_RE = /https?:\/\/(?!127\.\d+\.\d+\.\d+|0\.0\.0\.0|localhost|\[?::1\]?)[^\s]+|\bscp\s+.*@|\brsync\s+.*@/i;

export function checkCrossSessionChain(graph: MultiSessionGraph): PropertyViolation[] {
  const violations: PropertyViolation[] = [];
  const nodes = allNodes(graph);
  if (nodes.length === 0) return violations;
  const witness = graph.witnessIdx;

  for (const chain of loadCrossSessionChains()) {
    const stages = chain.stages;
    if (!stages.length) continue;

    if (witness !== undefined) {
      // —— 实时判定（witness）：链的最后阶段必须由当前动作（aNext = 图末节点）命中 ——
      // 历史中已随机出现的完整链不再影响后续良性动作（修复"历史全局匹配 → 永久拒绝锁定"FP，
      // 镜像 Python check_cross_session_chain；对齐站点 L2.2 "仅当当前事件属于 witness 才 block"）。
      if (nodes[witness].stage !== stages[stages.length - 1]) continue;
      let matched = 0;
      const path: { sessionId: string; seq: number; detail: string }[] = [];
      for (let k = 0; k < witness; k++) {
        const n = nodes[k];
        if (matched < stages.length - 1 && n.stage === stages[matched]) {
          matched += 1;
          path.push({ sessionId: n.sessionId, seq: n.seq, detail: n.actionDetail.slice(0, 60) });
        }
      }
      if (matched < stages.length - 1) continue;
      path.push({ sessionId: nodes[witness].sessionId, seq: nodes[witness].seq, detail: nodes[witness].actionDetail.slice(0, 60) });
      violations.push({
        propertyId: 'cross-' + chain.id,
        reason: chain.reason,
        riskLevel: chain.riskLevel,
        path,
      });
      return violations; // 命中即停（与 L2 短路语义一致）
    } else {
      // —— 低频回顾（witnessIdx 未定义）：全历史贪心子序列匹配 ——
      let matched = 0;
      let stageIdx = 0;
      const path: { sessionId: string; seq: number; detail: string }[] = [];
      for (const n of nodes) {
        if (stageIdx < stages.length && n.stage === stages[stageIdx]) {
          matched += 1;
          path.push({ sessionId: n.sessionId, seq: n.seq, detail: n.actionDetail.slice(0, 60) });
          stageIdx += 1;
          if (matched >= stages.length) break;
        }
      }
      if (matched >= stages.length) {
        violations.push({
          propertyId: 'cross-' + chain.id,
          reason: chain.reason,
          riskLevel: chain.riskLevel,
          path,
        });
      }
    }
  }
  return violations;
}

export function checkSensitiveDataFlow(graph: MultiSessionGraph): PropertyViolation[] {
  const violations: PropertyViolation[] = [];
  const nodes = allNodes(graph);
  if (nodes.length === 0) return violations;

  // taint: nodeIdx -> source description
  const tainted = new Map<number, string>();
  for (let i = 0; i < nodes.length; i++) {
    const n = nodes[i];
    if (n.stage === 'CRED' && [...n.resources].some(r => CRED_FILE_RE.test(r))) {
      tainted.set(i, `${n.sessionId}#${n.seq} 访问 ${[...n.resources][0]}`);
    }
  }
  if (tainted.size === 0) return violations;

  // forward propagation until fixpoint (small graph, linear OK)
  const edges = allEdges(graph);
  let changed = true;
  while (changed) {
    changed = false;
    for (const e of edges) {
      if (tainted.has(e.src) && !tainted.has(e.dst)) {
        const srcRes = nodes[e.src].resources;
        const dstRes = nodes[e.dst].resources;
        for (const r of srcRes) {
          if (dstRes.has(r)) {
            tainted.set(e.dst, tainted.get(e.src)!);
            changed = true;
            break;
          }
        }
      }
    }
  }

  // witness 语义（实时判定）：只查当前动作（aNext = 图末节点）是否 tainted 且 EXFIL；
  // 历史中已发生的凭据外传不再误伤后续良性动作；undefined（低频回顾）时查全部。
  const witness = graph.witnessIdx;
  const candidates: number[] = witness !== undefined ? [witness] : nodes.map((_, i) => i);
  for (const i of candidates) {
    const n = nodes[i];
    if (tainted.has(i) && EXFIL_RE.test(n.actionDetail)) {
      violations.push({
        propertyId: 'sensitive-data-flow',
        reason: `敏感数据传播外传：${tainted.get(i)} → ${n.sessionId}#${n.seq} 经共享载体外发`,
        riskLevel: 'critical',
        path: [{ sessionId: n.sessionId, seq: n.seq, detail: n.actionDetail.slice(0, 60) }],
      });
      if (witness !== undefined) return violations; // 实时判定命中即停
    }
  }
  return violations;
}

// ==================== P3/P4 abstract properties (LTL-style, chain-order independent) ====================

// eBPF evidence: real network exfil (connect/sendto to remote) also counts as EXFIL.
const EBPF_NET_RE = /connect|sendto|network_connect/i;
const REMOTE_RE = /to\s+\d+\.\d+\.\d+\.\d+|remote_addr/i;
// active exfil verbs: command itself performs exfil (not a doc/heredoc mentioning URL)
const EXFIL_ACTION_RE = /\bcurl\b|\bwget\b|\bscp\b|\brsync\b|\brclone\b|\bftp\b|connect\s+.*\d+\.\d+\.\d+\.\d+|open\s+.*tcp|base64\s+.*\-o/i;
// strict credential detection (P3/P4): real credential files/paths only
const CRED_STRICT_RE = /(known_hosts|\.ssh|id_rsa|\.pem|\b\.key\b|\/etc\/shadow|\/etc\/passwd|\.aws\/credentials|credentials\.json|netrc|password|secrets?\.ya?ml|credentials?\s*(file|path)?\s*(=|\:)|\bconfig.*(password|token))/i;

// ── privilege-escalation semantics (command-position matching, no literal FPs) ──
// Old `/\bsudo\b|\bsu\b|.../` substring-matched the whole actionDetail, so
// echo "sudo ..."/grep -rn "sudo"/awk '/su -/'/email body "sudo 收窄" were
// misjudged as real escalation. Replaced with command-position detection: only a
// leading token that is truly a privilege command (sudo/su/chmod u+s/setcap/
// pkexec/doas) escalates; query/output commands (grep/awk/echo/...) don't.

// inline shell extraction: real command inside os.system(...)/subprocess(...)/sh -c "..."
const INLINE_SHELL_RE =
  /(?:os\.system|os\.popen)\s*\(\s*['"]([^'"]+)['"]|subprocess\.[a-z_]+\(\s*\[([^\]]+)\]|subprocess\.[a-z_]+\(\s*['"]([^'"]+)['"]|(?:bash|sh|zsh)\s+-c\s*['"]([^'"]+)['"]/gi;

function extractInlineShell(s: string): string[] {
  const out: string[] = [];
  let m: RegExpExecArray | null;
  INLINE_SHELL_RE.lastIndex = 0;
  while ((m = INLINE_SHELL_RE.exec(s)) !== null) {
    let g = m[1] ?? m[2] ?? m[3] ?? m[4] ?? '';
    // subprocess list form ["sudo","su"] → strip quotes/commas/brackets → "sudo su"
    if (/^["']/.test(g) && (/"\s*,/.test(g) || /'\s*,/.test(g))) {
      g = g.replace(/['"\[\],]+/g, ' ');
    }
    g = g.trim();
    if (g) out.push(g);
  }
  return out;
}

// package managers: sudo <pkg-mgr> is install/ops, not privilege escalation
const PKG_MGR = new Set(['apt', 'apt-get', 'aptitude', 'yum', 'dnf', 'pacman', 'zypper', 'apk', 'brew']);
// bare shells immediately after sudo
const SHELLS = new Set(['bash', 'sh', 'zsh', 'dash', 'fish', 'ksh', 'csh', 'tcsh', 'nologin']);

function containsPrivesc(shell: string): boolean {
  if (!shell) return false;
  for (const seg of shell.split(/\&\&|\|\||;|\n/)) {
    const s = seg.trim();
    if (!s) continue;
    const toks = s.split(/\s+/);
    const head = (toks[0] || '').toLowerCase();
    const rest = toks.slice(1).join(' ');
    if (head === 'chmod' && /(?:u\+s|g\+s|[2-7][0-7]{3})/.test(rest)) return true;
    if (head === 'setcap' && /cap_/.test(rest)) return true;
    if (head === 'pkexec' || head === 'doas') return true;
    if (head === 'sudo') {
      // sudo -u <user>: only root escalates; non-root skips this segment
      if (/^-u\s+/.test(rest)) {
        if (/^-u\s+root\b/.test(rest)) return true;
        continue;
      }
      const m = /^(\S+)(.*)$/.exec(rest);
      if (m) {
        const nxt = m[1].toLowerCase();
        const tail = m[2];
        if (PKG_MGR.has(nxt)) continue; // install/ops, not escalation
        if (SHELLS.has(nxt)) return true;
        if (nxt === '-i' || nxt === '-s') return true;
        if (nxt.startsWith('su')) return true;
        if (nxt.startsWith('/') && /bin\/(?:bash|sh|zsh|dash|fish)$/.test(nxt)) return true;
      }
      // danger words anywhere after sudo (cross-flag, e.g. sudo -E /bin/bash)
      if (/\/(?:usr\/(?:local\/)?bin|bin)\/(?:bash|sh|zsh|dash|fish)\b/.test(rest)) return true;
      if (/\bchmod\s+(?:u\+s|g\+s|[2-7][0-7]{3})\b/.test(rest)) return true;
      if (/\bsetcap\s+cap_\w+/.test(rest)) return true;
      if (/\bvisudo\b/.test(rest)) return true;
      if (/\bpasswd\s+root\b/.test(rest)) return true;
      if (/\buseradd\b/.test(rest)) return true;
    }
    if (head === 'su') {
      // escalation only: bare su / su - / su -l (root) / su root / su - root
      if (!rest) return true;
      if (/^-l?\s*$/.test(rest)) return true;
      if (/^root\b/.test(rest) || /^-l?\s+root\b/.test(rest)) return true;
      // su <other-user> (e.g. su postgres) is not escalation
    }
  }
  // setuid syscall (real code call, not string literal)
  if (/\bset(?:uid|euid|gid|egid|reuid|regid|resuid|resgid)\s*\(/i.test(shell)) return true;
  return false;
}

function isExfilNode(n: { stage: string; actionDetail: string }): boolean {
  if (n.stage === 'EXFIL') return true;
  // text URL/scp/rsync requires an active exfil verb — avoid heredoc/doc false positives
  if (EXFIL_RE.test(n.actionDetail) && EXFIL_ACTION_RE.test(n.actionDetail)) return true;
  if (EBPF_NET_RE.test(n.actionDetail) && REMOTE_RE.test(n.actionDetail)) return true;
  return false;
}

function isCredNode(n: { stage: string; actionDetail: string; resources: Set<string> }): boolean {
  // strict credential (P3/P4): stage CRED is only coarse; require real credential path/text
  if (n.stage !== 'CRED') return false;
  for (const r of n.resources) {
    if (CRED_STRICT_RE.test(r)) return true;
  }
  return CRED_STRICT_RE.test(n.actionDetail);
}

function isPrivescNode(n: { stage: string; actionDetail: string }): boolean {
  // Do NOT trust n.stage === 'PRIVESC': builder marks stage via l2_rules.json stage
  // regexes, whose PRIVESC rule #4 bare `setuid` mislabels `grep "setuid"` as PRIVESC.
  // containsPrivesc (command-position) fully covers stage PRIVESC's 5 rules and
  // additionally backs up bare-shell escalation (sudo su / sudo bash) preempted by EXEC.
  const shell = stripStringLiterals(n.actionDetail);
  if (containsPrivesc(shell)) return true;
  for (const cmd of extractInlineShell(shell)) {
    if (containsPrivesc(cmd)) return true;
  }
  return false;
}

export function checkNeverExfilAfterPrivesc(graph: MultiSessionGraph): PropertyViolation[] {
  // □(PRIVESC → ¬◇ EXFIL): any PRIVESC earlier + any EXFIL later (cross-session/any gap)
  // is a violation. Independent of the fixed 9 preset chains.
  // witness 语义（实时判定）：只当当前动作（aNext = 图末节点）是 EXFIL 且历史中有
  // PRIVESC 在前才判违规——历史中已随机出现的 PRIVESC+EXFIL 组合不再误伤后续良性动作。
  const violations: PropertyViolation[] = [];
  const nodes = allNodes(graph);
  if (nodes.length < 2) return violations;
  const witness = graph.witnessIdx;

  if (witness !== undefined) {
    // 实时判定：当前动作的 EXFIL 证据 = aNext 节点 + eBPF 行为证据节点
    // （aNext 是"声明"，ebpf 是"行为"——镜像 Python 的 ebpf-evidence 纳入）。
    const evIdx: number[] = [];
    nodes.forEach((n, i) => {
      if ((i === witness || n.sessionId === 'ebpf-evidence') && isExfilNode(n)) evIdx.push(i);
    });
    if (evIdx.length === 0) return violations;
    const firstEv = Math.min(...evIdx);
    let pre: { sessionId: string; seq: number; actionDetail: string } | null = null;
    for (let i = 0; i < firstEv; i++) {
      if (isPrivescNode(nodes[i])) pre = nodes[i];
    }
    if (pre) {
      const post = nodes[firstEv];
      return [{
        propertyId: 'no-exfil-after-privesc',
        reason: '提权后出现外传：提权(前) → 外传(后)，违反 □(PRIVESC→¬◇EXFIL)',
        riskLevel: 'critical',
        path: [
          { sessionId: pre.sessionId, seq: pre.seq, detail: pre.actionDetail.slice(0, 60) },
          { sessionId: post.sessionId, seq: post.seq, detail: post.actionDetail.slice(0, 60) },
        ],
      }];
    }
    return violations;
  }

  for (let i = 0; i < nodes.length; i++) {
    if (!isPrivescNode(nodes[i])) continue;
    for (let j = i + 1; j < nodes.length; j++) {
      if (isExfilNode(nodes[j])) {
        violations.push({
          propertyId: 'no-exfil-after-privesc',
          reason: '提权后出现外传：提权(前) → 外传(后)，违反 □(PRIVESC→¬◇EXFIL)',
          riskLevel: 'critical',
          path: [
            { sessionId: nodes[i].sessionId, seq: nodes[i].seq, detail: nodes[i].actionDetail.slice(0, 60) },
            { sessionId: nodes[j].sessionId, seq: nodes[j].seq, detail: nodes[j].actionDetail.slice(0, 60) },
          ],
        });
        return violations;
      }
    }
  }
  return violations;
}

export function checkNeverExfilAfterCred(graph: MultiSessionGraph): PropertyViolation[] {
  // □(CRED → ¬◇ EXFIL): any CRED earlier + any EXFIL later is a violation.
  // More conservative (and lighter) than P2 taint propagation: catches
  // indirect/zipped/implicit exfiltration P2's shared-carrier can't see.
  // witness 语义（实时判定）：只当当前动作（aNext = 图末节点）是 EXFIL 且历史中有
  // CRED 在前才判违规——历史中已随机出现的 CRED+EXFIL 组合不再误伤后续良性动作。
  const violations: PropertyViolation[] = [];
  const nodes = allNodes(graph);
  if (nodes.length < 2) return violations;
  const witness = graph.witnessIdx;

  if (witness !== undefined) {
    // 实时判定：当前动作的 EXFIL 证据 = aNext 节点 + eBPF 行为证据节点
    const evIdx: number[] = [];
    nodes.forEach((n, i) => {
      if ((i === witness || n.sessionId === 'ebpf-evidence') && isExfilNode(n)) evIdx.push(i);
    });
    if (evIdx.length === 0) return violations;
    const firstEv = Math.min(...evIdx);
    let pre: { sessionId: string; seq: number; actionDetail: string } | null = null;
    for (let i = 0; i < firstEv; i++) {
      if (isCredNode(nodes[i])) pre = nodes[i];
    }
    if (pre) {
      const post = nodes[firstEv];
      return [{
        propertyId: 'no-exfil-after-credential',
        reason: '读取凭据后出现外传，违反 □(CRED→¬◇EXFIL)',
        riskLevel: 'critical',
        path: [
          { sessionId: pre.sessionId, seq: pre.seq, detail: pre.actionDetail.slice(0, 60) },
          { sessionId: post.sessionId, seq: post.seq, detail: post.actionDetail.slice(0, 60) },
        ],
      }];
    }
    return violations;
  }

  for (let i = 0; i < nodes.length; i++) {
    if (!isCredNode(nodes[i])) continue;
    for (let j = i + 1; j < nodes.length; j++) {
      if (isExfilNode(nodes[j])) {
        violations.push({
          propertyId: 'no-exfil-after-credential',
          reason: '读取凭据后出现外传，违反 □(CRED→¬◇EXFIL)',
          riskLevel: 'critical',
          path: [
            { sessionId: nodes[i].sessionId, seq: nodes[i].seq, detail: nodes[i].actionDetail.slice(0, 60) },
            { sessionId: nodes[j].sessionId, seq: nodes[j].seq, detail: nodes[j].actionDetail.slice(0, 60) },
          ],
        });
        return violations;
      }
    }
  }
  return violations;
}

// ==================== Rule 5 低完整性控制命令执行 ====================
// （镜像 Python check_low_integrity_command_exec）

// Tool Registry 缓存（工具名 → actionClass/requireHighIntegrity，单一事实源）
let TOOL_REGISTRY: Record<string, any> | null = null;

function getToolRegistry(): Record<string, any> {
  if (TOOL_REGISTRY) return TOOL_REGISTRY;
  TOOL_REGISTRY = (loadToolRegistry().tools || {}) as Record<string, any>;
  return TOOL_REGISTRY;
}

/** Tool Registry：按工具名/命令查 actionClass（未注册返回 undefined，回退正则判定）。 */
export function lookupToolClass(actionType: string): string | undefined {
  const entry = getToolRegistry()[actionType] || {};
  return entry.actionClass as string | undefined;
}

// compute 动作形态（命令执行）：bash/sh -c 执行脚本、python/node 解释执行、
// subprocess/eval/exec 动态执行等。cat/ls/grep 等只读命令即使经 bash 工具运行
// 也不算"命令执行"——必须 detail 命中执行形态。
const COMPUTE_RE = /subprocess|os\.system|shell\s*=\s*True|\beval\(|\bexec\(|bash\s+[^\s]|sh\s+-c|python3?\s+|node\s+|\btimeout\s+|nohup\s+|\b\.\/[\w./-]+/i;
// 解释器/终端类 actionType：直接算 compute（无论 detail）
const STRONG_COMPUTE_TYPES = new Set(['python', 'node', 'exec', 'terminal', 'cmd']);

function isComputeNode(n: { actionType: string; actionDetail: string }): boolean {
  // 强类型解释器/终端 → compute（无论 detail）
  if (STRONG_COMPUTE_TYPES.has(n.actionType.toLowerCase())) return true;
  // Registry 明确标为非 compute（read/write/egress）→ 排除（如 cat/file.read 经 bash 运行不算执行）
  const cls = lookupToolClass(n.actionType);
  if (cls === 'read' || cls === 'write' || cls === 'network_egress' || cls === 'message_egress') return false;
  // 其余（bash/shell 等）：detail 命中执行形态才算（bash x.sh、sh -c、subprocess、./script）
  return COMPUTE_RE.test(n.actionDetail);
}

/**
 * Rule 5：低完整性控制命令执行 — 不可信数据（外取/下载/注入内容）经共享载体
 * 控制 shell/terminal 执行（站点 L2.1 critical block，最有区分度的检测之一）。
 * 机制：低完整性源（isLowSource：download_file / prompt_injection AP 命中）的资源
 * 视为不可信；沿共享资源传播 min（低处流原则，迭代收敛）；compute 形态且 low → 违规。
 * witness 语义：实时判定（witnessIdx 非 undefined）只当当前动作是 low compute 才判。
 */
export function checkLowIntegrityCommandExec(graph: MultiSessionGraph): PropertyViolation[] {
  const violations: PropertyViolation[] = [];
  const nodes = allNodes(graph);
  if (nodes.length === 0) return violations;
  const witness = graph.witnessIdx;

  // 1. 收集 low 源资源 + 初始 low 节点
  const lowResources = new Set<string>();
  const lowAt = new Map<number, string>();
  nodes.forEach((n, i) => {
    if (n.isLowSource) {
      lowAt.set(i, n.actionDetail.slice(0, 60));
      for (const r of n.resources) lowResources.add(r);
    }
  });

  // 2. 沿共享资源传播（迭代收敛）
  let changed = true;
  while (changed) {
    changed = false;
    for (let i = 0; i < nodes.length; i++) {
      if (lowAt.has(i)) continue;
      let shared = '';
      for (const r of nodes[i].resources) {
        if (lowResources.has(r)) { shared = r; break; }
      }
      if (shared) {
        lowAt.set(i, `继承自 ${shared}`);
        for (const r of nodes[i].resources) lowResources.add(r);
        changed = true;
      }
    }
  }

  if (lowAt.size === 0) return violations;

  // 3. compute + low → 违规（witness 语义：只查当前动作；回顾：查全部）
  const candidates: number[] = witness !== undefined ? [witness] : nodes.map((_, i) => i);
  for (const i of candidates) {
    const n = nodes[i];
    if (lowAt.has(i) && isComputeNode(n)) {
      violations.push({
        propertyId: 'low-integrity-command-exec',
        reason: `低完整性数据控制命令执行：${lowAt.get(i)} → ${n.sessionId}#${n.seq} 执行不可信内容`,
        riskLevel: 'critical',
        path: [{ sessionId: n.sessionId, seq: n.seq, detail: n.actionDetail.slice(0, 60) }],
      });
      if (witness !== undefined) return violations; // 实时判定命中即停
    }
  }
  return violations;
}

// ==================== 跨 session 数据流可达性（多跳，镜像 Python） ====================
// 站点 L2.1"不可信数据沿依赖图流动"，P2 只做单跳传播且只盯凭据。这里推广到
// **多跳跨 session**：低完整性源（isLowSource/download 形态）沿 data 边（共享
// 文件路径）多跳流至当前动作，覆盖"下载 → 改名 → 执行"免杀场景（改名后 Rule 5
// 的 integrity 按节点传播可能失效，但 data 边仍以新旧路径相连）。witness 语义：
// 实时只查末节点；回顾查全图。
const DL_OR_LOW_RE = /curl\s+.*-o\b|wget\s+.*\s+-O\b|curl\s+.*\|\s*(bash|sh|python)|wget\s+.*\|\s*(bash|sh|python)|git\s+clone|docker\s+pull|pip\s+install|npm\s+install|base64\s+-d/i;

export function checkCrossSessionReachability(graph: MultiSessionGraph): PropertyViolation[] {
  const violations: PropertyViolation[] = [];
  const nodes = allNodes(graph);
  if (nodes.length === 0) return violations;
  const witness = graph.witnessIdx;

  // 源：恶意下载/外取产物（与 Rule 5 的 isLowSource 同源）
  const sources = new Set<number>();
  nodes.forEach((n, i) => {
    if (n.isLowSource || DL_OR_LOW_RE.test(n.actionDetail)) sources.add(i);
  });
  if (sources.size === 0) return violations;

  // data 边 + next 边迭代传播（共享资源 i.e. 同一文件/载体）
  const reached = new Set<number>(sources);
  let changed = true;
  while (changed) {
    changed = false;
    for (const e of allEdges(graph)) {
      if (reached.has(e.src) && !reached.has(e.dst)) {
        const srcRes = nodes[e.src].resources;
        const dstRes = nodes[e.dst].resources;
        for (const r of srcRes) {
          if (dstRes.has(r)) {
            reached.add(e.dst);
            changed = true;
            break;
          }
        }
      }
    }
  }

  const candidates: number[] = witness !== undefined ? [witness] : nodes.map((_, i) => i);
  for (const i of candidates) {
    const n = nodes[i];
    if (sources.has(i)) continue; // 源自身（下载/安装/注入动作）不算"再次流入"目标，避免自触发
    if (reached.has(i)) {
      const srcIdx = Math.min(...sources);
      const srcDesc = nodes[srcIdx].actionDetail.slice(0, 40);
      violations.push({
        propertyId: 'low-integrity-reachability',
        reason: `低完整性源经跨 session 数据链多跳到达当前执行（源: ${srcDesc} → ${n.sessionId}#${n.seq}）`,
        riskLevel: 'high',
        path: nodes.slice(-3).map((m) => ({ sessionId: m.sessionId, seq: m.seq, detail: m.actionDetail.slice(0, 60) })),
      });
      if (witness !== undefined) return violations; // 实时判定命中即停
    }
  }
  return violations;
}

// ==================== Rule 12 敏感数据聚合外传 ====================
// （镜像 Python check_sensitive_data_aggregation）

/**
 * Rule 12: sensitive-data-aggregation — egress 聚合 ≥2 个不同事件源。
 * 站点定义：isEgress → incoming data_dependency → uniqueEventIds.size >= 2。
 * 当前模型无 OBS 通道，用"共享资源/载体"近似 data_dependency：EXFIL 节点的
 * 资源被 ≥2 个不同事件（sessionId, seq 唯一）接触过 → 视为聚合多个来源。
 * 性能：资源 → [node_idx] 索引，O(N·R)；witness 语义只查当前动作。
 */
export function checkSensitiveDataAggregation(graph: MultiSessionGraph): PropertyViolation[] {
  const violations: PropertyViolation[] = [];
  const nodes = allNodes(graph);
  if (nodes.length < 2) return violations;
  const witness = graph.witnessIdx;

  // resource → [node_idx]
  const resIndex = new Map<string, number[]>();
  nodes.forEach((n, i) => {
    for (const r of n.resources) {
      const list = resIndex.get(r);
      if (list) list.push(i);
      else resIndex.set(r, [i]);
    }
  });

  const sourcesFor = (exfilIdx: number): Set<string> => {
    const srcs = new Set<string>();
    const n = nodes[exfilIdx];
    for (const r of n.resources) {
      for (const j of resIndex.get(r) || []) {
        if (j === exfilIdx) continue;
        srcs.add(`${nodes[j].sessionId}#${nodes[j].seq}`);
      }
    }
    return srcs;
  };

  const candidates: number[] = witness !== undefined ? [witness] : nodes.map((_, i) => i);
  for (const i of candidates) {
    const n = nodes[i];
    if (!isExfilNode(n)) continue;
    const srcs = sourcesFor(i);
    if (srcs.size >= 2) {
      violations.push({
        propertyId: 'sensitive-data-aggregation',
        reason: `敏感数据聚合外传：egress 聚合 ${srcs.size} 个事件源数据（Rule 12）`,
        riskLevel: 'critical',
        path: [{ sessionId: n.sessionId, seq: n.seq, detail: n.actionDetail.slice(0, 60) }],
      });
      if (witness !== undefined) return violations; // 实时判定命中即停
    }
  }
  return violations;
}

// ==================== property registry ====================

export interface Property {
  id: string;
  check: (graph: MultiSessionGraph) => PropertyViolation[];
  shortName?: string;
}

//! 顺序即 fail-closed 短路优先级：verify 逐个执行，首个返回违规的性质成为
//! first_violation，后续不再评估。调整顺序影响判定归属，须与 Python
//! properties.py ALL_PROPERTIES 保持一致并双端测试确认。
//!
//! shortName（P1~P8 连续短名）与 id（语义化英文）对照（与 Python 一致）：
//!   P1 cross-session-chain          跨会话组合链
//!   P2 sensitive-data-flow          敏感数据传播
//!   P3 low-integrity-reachability   低完整性数据流可达
//!   P4 no-exfil-after-privesc       提权后禁外传
//!   P5 no-exfil-after-credential    凭据后禁外传
//!   P6 mc-ltl-rules                 LTL 模型检测
//!   P7 low-integrity-command-exec   低完整性命令执行
//!   P8 sensitive-data-aggregation   敏感数据聚合外传
export const ALL_PROPERTIES: Property[] = [
  { id: 'cross-session-chain', check: checkCrossSessionChain, shortName: 'P1' },
  { id: 'sensitive-data-flow', check: checkSensitiveDataFlow, shortName: 'P2' },
  { id: 'low-integrity-reachability', check: checkCrossSessionReachability, shortName: 'P3' },
  { id: 'no-exfil-after-privesc', check: checkNeverExfilAfterPrivesc, shortName: 'P4' },
  { id: 'no-exfil-after-credential', check: checkNeverExfilAfterCred, shortName: 'P5' },
  // L2.2 模型检测（通用 LTL 求值器，mc_rules.json 单一事实源；witness 语义见 ltl.ts）
  { id: 'mc-ltl-rules', check: checkMCRules, shortName: 'P6' },
  // P7 低完整性控制命令执行（integrity 维度，站点 L2.1 最有区分度的检测之一）
  { id: 'low-integrity-command-exec', check: checkLowIntegrityCommandExec, shortName: 'P7' },
  // P8 敏感数据聚合外传（egress 聚合 ≥2 事件源）
  { id: 'sensitive-data-aggregation', check: checkSensitiveDataAggregation, shortName: 'P8' },
];
