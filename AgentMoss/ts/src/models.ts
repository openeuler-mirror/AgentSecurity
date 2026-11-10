import { z } from 'zod';
import { version as PACKAGE_VERSION } from './package-json.js';

/** Single action in history or next action */
export const ActionItemSchema = z.object({
  action_type: z.string().describe('Action type, e.g. bash, file_read, file_write'),
  action_detail: z.string().describe('Action detail / command content'),
});

/** A single user prompt turn with the actions it triggered (interleaved time order). */
export const PromptTurnSchema = z.object({
  text: z.string().default('').describe('User prompt text at this turn'),
  actions: z.array(ActionItemSchema).default([]).describe('Actions triggered by this prompt, in order, until the next prompt'),
});

export const AnalyzeRequestSchema = z.object({
  session_id: z.string().describe('Session / agent unique identifier'),
  prompt_session: z.string().default('').describe('User original prompt (most recent user message; backward compat)'),
  prompt_history: z.array(PromptTurnSchema).default([]).describe('Full interleaved prompt history (ordered turns, each with its triggered actions). Optional; empty = fall back to prompt_session only.'),
  action_history: z.array(ActionItemSchema).default([]).describe('Historical action sequence'),
  session_history: z.array(z.object({
    session_id: z.string(),
    action_history: z.array(ActionItemSchema).default([]),
  })).default([]).describe('Multi-session historical actions (optional): for L2.2 formal engine cross-session combo-chain / sensitive-data-flow verification. Provided by caller (incl. future agentgate).'),
  a_next: ActionItemSchema.describe('Next action to be executed'),
  reason: z.string().default('').describe('Reason for executing this action'),
  os_type: z.string().default('').describe("OS type: 'linux', 'windows', or empty for auto-detect"),
  cwd: z.string().default('').describe('Current working directory'),
  agent_id: z.string().default('').describe("Caller agent identifier, e.g. 'xiaoo' / 'opencode' / 'opendesk'. Empty = generic mode (no agent-specific rules)."),
  metadata: z.record(z.unknown()).optional().describe('Extended metadata'),
});

export const AnalyzeResponseSchema = z.object({
  decision: z.enum(['Allow', 'Deny']).describe('Allow or Deny'),
  reason: z.string().describe('Decision reason'),
  risk_level: z.enum(['low', 'medium', 'high', 'critical']).default('low'),
  risk_type: z.string().default(''),
  violated_layers: z.array(z.string()).default([]),
  policy: z.string().default(''),
  violated_policy: z.string().default(''),
  confidence: z.number().int().min(0).max(100).default(100),
  analysis_duration_ms: z.number().default(0),
  // 组合攻击链反例路径：每步 [session_id, seq, stage, timestamp]，含真实发生时间
  violation_chain: z.array(z.array(z.union([z.string(), z.number()]).nullable())).default([]),
});

export const HealthResponseSchema = z.object({
  status: z.string().default('healthy'),
  version: z.string().default(PACKAGE_VERSION),
  // 归属实例标识：值来自 env AGENT_MOSS_INSTANCE（spawn/systemd 注入），默认空串。
  // 多个 agentmoss 同机并存时，调用方按 instance 过滤避免连到别人的进程。
  // 空=未配置（独立部署或旧版），调用方可选择兼容或严格过滤。
  instance: z.string().default(''),
});

/** POST /api/v1/review 请求（低频全量回顾 + 状态重建）。镜像 Python ReviewRequest。 */
export const ReviewRequestSchema = z.object({
  agent_id: z.string().default('').describe('目标 agent 标识（决定状态库分桶）'),
  db_path: z.string().default('').describe('AgentGate 本地存储路径（SQLite 文件 或 tool_calls JSON 目录）；为空则用 sessions'),
  sessions: z.array(z.object({
    session_id: z.string(),
    action_history: z.array(ActionItemSchema).default([]),
  })).default([]).describe('多 session 历史动作（替代/兜底 db_path）'),
  a_next: ActionItemSchema.optional().describe('可选：seed 后连同当前动作一起判定'),
  is_error: z.boolean().default(false).describe('当前动作执行是否失败'),
  output_pending: z.boolean().default(false).describe('返回前序链清单 pending_prefixes'),
});

/** POST /api/v1/review 响应。镜像 Python ReviewResponse。 */
export const ReviewResponseSchema = z.object({
  agent_id: z.string().default(''),
  seeded_nodes: z.number().default(0),
  verified: z.boolean().default(true),
  violations: z.array(z.record(z.unknown())).default([]),
  pending_prefixes: z.array(z.record(z.unknown())).default([]),
  state_nodes: z.number().default(0),
  discovered_patterns: z.array(z.record(z.unknown())).default([]).describe('数据驱动发现：跨 session 频繁危险组合（预置链盲区，PatternMiner）'),
});

export type ActionItem = z.infer<typeof ActionItemSchema>;
export type AnalyzeRequest = z.infer<typeof AnalyzeRequestSchema>;
export type AnalyzeResponse = z.infer<typeof AnalyzeResponseSchema>;
export type HealthResponse = z.infer<typeof HealthResponseSchema>;
export type ReviewRequest = z.infer<typeof ReviewRequestSchema>;
export type ReviewResponse = z.infer<typeof ReviewResponseSchema>;
