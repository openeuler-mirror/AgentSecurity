/**
 * Formal engine — FormalEngine verification entry.
 * Mirrors Python agent_moss/engine/formal_engine/engine.py.
 *
 * Public API (same architecture as script_engine: engine + unified IR + scanner):
 * - FormalEngine.verify(sessions?, aNext?) → FormalVerificationResult
 *
 * Runtime cost: O(nodes × properties × edges), no state explosion / path
 * enumeration — milliseconds for a single session, linear for multi-session.
 */

import { buildMultiSessionGraph } from './builder';
import type { FormalVerificationResult, PropertyViolation } from './ir';
import { allNodes, emptyVerificationResult } from './ir';
import { ALL_PROPERTIES, Property } from './properties';

/** 把 eBPF syscall 事件转成 stage 正则可识别的一句话（镜像 Python _ebpf_event_to_detail）。 */
export function ebpfEventToDetail(e: Record<string, unknown>): string {
  const parts: string[] = [];
  const syscall = String(e.syscall || e.op || '');
  const argv = String(e.argv || e.pathname || '');
  const remote = String(e.remote_addr || '');
  const port = e.remote_port;
  if (syscall) parts.push(syscall);
  if (argv && argv !== '' && argv !== 'None') parts.push(argv);
  if (remote) parts.push('to ' + remote + (port ? ':' + String(port) : ''));
  return parts.join(' ');
}

export class FormalEngine {
  private properties: Property[];

  constructor(properties?: Property[]) {
    this.properties = properties && properties.length > 0 ? properties : ALL_PROPERTIES;
  }

  verify(
    sessions?: { sessionId?: string; actionHistory?: { actionType?: string; actionDetail?: string }[] }[],
    aNext?: { actionType?: string; actionDetail?: string },
    ebpfEvents?: Record<string, unknown>[],
  ): FormalVerificationResult {
    const all = sessions ? [...sessions] : [];
    if (ebpfEvents && ebpfEvents.length > 0) {
      // 真实 syscall 证据（AgentGate eBPF）作为独立 session 追加，
      // 供 P3/P4 做"声明(a_next) vs 行为(ebpf)"交叉校验。
      all.push({
        sessionId: 'ebpf-evidence',
        actionHistory: ebpfEvents.map(e => ({
          actionType: 'syscall',
          actionDetail: ebpfEventToDetail(e),
        })),
      });
    }
    const graph = buildMultiSessionGraph(all, aNext);
    if (aNext) {
      // witness 语义：aNext 即"当前拟执行动作"，是图末节点。性质检查只当
      // 该节点补全链/触发后置外传才判违规（修复历史全局匹配 → 永久拒绝 FP）。
      graph.witnessIdx = allNodes(graph).length - 1;
    }
    const result: FormalVerificationResult = emptyVerificationResult();

    for (const prop of this.properties) {
      let violations: PropertyViolation[];
      try {
        violations = prop.check(graph);
      } catch (e) {
        // property verification error → fail-closed (keep)
        result.verified = false;
        result.violations.push({
          propertyId: prop.id,
          reason: `形式化性质验证异常，保守拦截: ${e}`,
          riskLevel: 'medium',
          path: [],
        });
        return result;
      }
      if (violations.length > 0) {
        result.verified = false;
        result.violations.push(...violations);
        break; // hit-and-stop (consistent with L2 short-circuit)
      }
    }
    return result;
  }
}
