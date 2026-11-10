import type { Context } from 'hono';
import { AnalyzeRequestSchema, AnalyzeResponseSchema, HealthResponseSchema, ReviewRequestSchema, ReviewResponseSchema } from './models';
import { runAnalysis } from './engine/coordinator';
import { reportEnforcementEvent } from './actrail';
import { ChainStateStore, FormalEngine, StatefulChainTracker } from './engine/formal-engine';
import { mineDangerousPatterns } from './engine/formal-engine/pattern_miner';
import { loadAgentGateSessions } from './agent-gate-reader';

export async function healthRoute(c: Context) {
  return c.json(HealthResponseSchema.parse({
    instance: process.env.AGENT_MOSS_INSTANCE || '',
  }));
}

export async function analyzeRoute(c: Context) {
  const t0 = performance.now();

  try {
    const body = await c.req.json();
    const req = AnalyzeRequestSchema.parse(body);

    // OS auto-detect
    let osType = req.os_type;
    if (!osType) {
      osType = process.platform === 'win32' ? 'windows' : 'linux';
    }

    // agent_id 透传（先解析出来供 stateful 增量使用；优先顶层，兜底 metadata.agent_type）
    const agentId = req.agent_id || (req.metadata as any)?.agent_type || '';

    const result = await runAnalysis({
      sessionId: req.session_id,
      promptSession: req.prompt_session,
      actionHistory: req.action_history.map(h => ({
        actionType: h.action_type,
        actionDetail: h.action_detail,
      })),
      sessionHistory: (req.session_history || []).map(s => ({
        sessionId: s.session_id,
        actionHistory: (s.action_history || []).map(h => ({
          actionType: h.action_type,
          actionDetail: h.action_detail,
        })),
      })),
      aNext: {
        actionType: req.a_next.action_type,
        actionDetail: req.a_next.action_detail,
      },
      reason: req.reason,
      osType,
      cwd: req.cwd,
      // agent_id：AgentGate V1 normalizer 历史上把 agent_type 塞 metadata，
      // 顶层为空时兜底（OpenDesk 的 agent-moss 需 agent_id 加载专属规则）。
      agentId,
      llmConfig: (req.metadata as any)?.llm_config,
      llmLogPath: (req.metadata as any)?.llm_log_path,
    });

    const durationMs = performance.now() - t0;

    // Report enforcement event to AcTrail (fire-and-forget)
    try {
      reportEnforcementEvent({
        traceId: req.session_id,
        decision: result.allowed ? 'allow' : 'deny',
        toolName: req.a_next.action_type,
        toolCommand: req.a_next.action_detail,
        sessionId: req.session_id,
        prompt: req.prompt_session,
        riskLevel: result.riskLevel,
        riskType: result.riskType,
        reason: result.reason,
        violatedLayers: result.violatedLayers,
        confidence: result.confidence,
        durationMs: Math.round(durationMs * 10) / 10,
      });
    } catch { /* non-fatal, never block response */ }

    // ========== L2.2 stateful incremental（有状态实时判定，可选启用） ==========
    // 镜像 Python routes.py：metadata.stateful_incremental=true 时把当前动作 push 进
    // 该 agent 的持久化时间线；补全历史前序链 → 覆盖为 Deny（violated_layers 含 L2.2-stateful）。
    const meta = (req.metadata || {}) as Record<string, unknown>;
    const incEnabled = String(meta.stateful_incremental || '').toLowerCase();
    if (incEnabled === '1' || incEnabled === 'true' || incEnabled === 'yes' || incEnabled === 'on') {
      try {
        const store = getChainStateStoreFor(agentId);
        const inc = store.applyAction(agentId, {
          actionType: req.a_next.action_type,
          actionDetail: req.a_next.action_detail,
        }, req.session_id, Boolean(meta.is_error));
        const judgment = incMatchedToDeny(inc);
        if (judgment) {
          const layers = [...result.violatedLayers];
          if (!layers.includes('L2.2-stateful')) layers.push('L2.2-stateful');
          console.error(
            `[AgentMoss] stateful 增量拦截: agent=${agentId || '-'} property=${judgment.property_id} risk=${judgment.risk_level}`,
          );
          return c.json(
            AnalyzeResponseSchema.parse({
              decision: 'Deny',
              reason: judgment.reason,
              risk_level: judgment.risk_level,
              risk_type: 'formal_verification',
              violated_layers: layers,
              policy: '',
              violated_policy: '',
              confidence: 90,
              analysis_duration_ms: Math.round((performance.now() - t0) * 10) / 10,
              violation_chain: judgment.violation_chain,
            })
          );
        }
      } catch (err) {
        console.error('[AgentMoss] stateful incremental error (non-fatal):', err);
      }
    }

    return c.json(
      AnalyzeResponseSchema.parse({
        decision: result.allowed ? 'Allow' : 'Deny',
        reason: result.reason,
        risk_level: result.riskLevel,
        risk_type: result.riskType,
        violated_layers: result.violatedLayers,
        policy: '',
        violated_policy: '',
        confidence: result.confidence,
        analysis_duration_ms: Math.round(durationMs * 10) / 10,
      })
    );
  } catch (err) {
    console.error('[AgentMoss] Analysis error:', err);
    if (err instanceof SyntaxError) {
      return c.json({ error: 'Invalid JSON', detail: err.message }, 400);
    }
    if ((err as any)?.issues) {
      return c.json({ error: 'Validation error', detail: (err as any).issues }, 400);
    }
    return c.json({ error: 'Internal error', detail: String(err) }, 500);
  }
}

// ===========================================================================
// POST /api/v1/review 低频全量回顾（镜像 Python routes.py review 语义）
// ===========================================================================

let reviewStore: ChainStateStore | null = null;

function getChainStateStoreFor(_agentId: string): ChainStateStore {
  if (!reviewStore) reviewStore = new ChainStateStore();
  return reviewStore;
}

/** 把 stateful advance 的结果转成补充 Deny 判定（无命中返回 null）。 */
function incMatchedToDeny(
  inc: { matched?: { chainId: string; riskLevel: string; reason: string; path?: { sessionId: string; seq: number; stage: string; timestamp: string | null }[] } | null; exfil?: { reason: string; risk_level: string }[] },
): { property_id: string; reason: string; risk_level: string; violation_chain: (string | number | null)[][] } | null {
  if (inc.matched) {
    // path 每步含时间戳：[session_id, seq, stage, timestamp]
    const chain = (inc.matched.path || []).map(p => [p.sessionId, p.seq, p.stage, p.timestamp]);
    return {
      property_id: 'cross-' + inc.matched.chainId,
      reason: inc.matched.reason,
      risk_level: inc.matched.riskLevel,
      violation_chain: chain,
    };
  }
  if (inc.exfil && inc.exfil.length > 0) {
    return {
      property_id: 'sensitive-data-flow',
      reason: inc.exfil[0].reason,
      risk_level: inc.exfil[0].risk_level,
      violation_chain: [],
    };
  }
  return null;
}

export async function reviewRoute(c: Context) {
  const t0 = performance.now();
  try {
    const body = await c.req.json();
    const req = ReviewRequestSchema.parse(body);
    const agentId = req.agent_id || 'default';
    const store = getChainStateStoreFor(agentId);
    let tracker = store.load(agentId);
    if (!tracker) {
      tracker = new StatefulChainTracker(agentId);
    }

    // 1. 读取历史（db_path 直读 > 显式 sessions）
    let sessions: { sessionId?: string; actionHistory?: { actionType: string; actionDetail: string }[] }[] = [];
    if (req.db_path) {
      sessions = loadAgentGateSessions(req.db_path);
      if (sessions.length === 0) sessions = (req.sessions || []).map(s => ({
        sessionId: s.session_id,
        actionHistory: s.action_history.map(a => ({ actionType: a.action_type, actionDetail: a.action_detail })),
      }));
    } else {
      sessions = (req.sessions || []).map(s => ({
        sessionId: s.session_id,
        actionHistory: s.action_history.map(a => ({ actionType: a.action_type, actionDetail: a.action_detail })),
      }));
    }
    const added = sessions.length > 0 ? tracker.seed(sessions) : 0;
    store.save(tracker);

    // 2. 全量 FormalEngine 验证
    let verified = true;
    const violations: { property_id: string; reason: string; risk_level: string }[] = [];
    if (sessions.length > 0 || tracker.nodes.length > 0) {
      const eng = new FormalEngine();
      const full = eng.verify(
        sessions.map(s => ({ sessionId: s.sessionId, actionHistory: s.actionHistory })),
        req.a_next ? { actionType: req.a_next.action_type, actionDetail: req.a_next.action_detail } : undefined,
      );
      verified = full.verified;
      for (const v of full.violations) {
        violations.push({ property_id: v.propertyId, reason: v.reason, risk_level: v.riskLevel });
      }
    }

    // 3. 提取待攻击前序
    const pending = tracker.pendingPrefixes.map(p => ({
      chain_id: p.chainId,
      matched: p.matched,
      next_stage: p.nextStage,
      risk_level: p.riskLevel,
    }));

    // 4. 数据驱动发现：跨 session 频繁危险组合（预置链外新形态）
    let discovered: { pattern: string[]; support: number; risk: string; reason: string }[] = [];
    if (sessions.length > 0) {
      try {
        discovered = mineDangerousPatterns(sessions, 2);
      } catch {
        // 挖掘失败不阻塞 review
      }
    }

    return c.json(ReviewResponseSchema.parse({
      agent_id: agentId,
      seeded_nodes: added,
      verified,
      violations,
      pending_prefixes: pending,
      state_nodes: tracker.nodes.length,
      discovered_patterns: discovered,
    }));
  } catch (err) {
    console.error('[AgentMoss] Review error:', err);
    return c.json({ error: 'Internal error', detail: String(err) }, 500);
  }
}

