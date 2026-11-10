/** Security judgment result from a single analysis layer */
export interface SecurityJudgment {
  allowed: boolean;
  reason: string;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  riskType: string;
  confidence: number;
  source: string; // "heuristic" | "logic_rule" | "llm"
  violatedLayers: string[];
  isCredential?: boolean; // 是否命中凭据文件（凭据文件无论读写都拦截，不进 inline 跳过）
}

/** Heuristic detection result */
export interface HeuristicResult {
  hit: boolean;
  matchedPatterns: string[];
  riskLevel: string;
  reason: string;
  riskType: string;
  confidence: number;
}

/** Logic rule detection result */
export interface LogicRuleResult {
  hit: boolean;
  violatedRule: string;
  riskLevel: string;
  reason: string;
  riskType: string;
  isCredential?: boolean; // 是否命中凭据文件（凭据文件无论读写都拦截，不进 inline 跳过）
}

/** Matched skill info */
export interface SkillMatch {
  skillName: string;
  relevance: number; // 0-1
  skillContent: string;
}

/** LLM configuration injected by host (OpenDesk or CLI) */
export interface LLMConfig {
  provider: string;       // e.g. "openai", "openrouter"
  baseUrl: string;        // e.g. "https://api.openai.com/v1"
  apiKey: string;
  model: string;          // e.g. "gpt-4o", "google/gemini-2.5-flash"
  temperature?: number;
  maxTokens?: number;
  timeout?: number;       // LLM request timeout in seconds (deprecated: 用 TimeoutConfig.prompt1Timeout 代替，保留向后兼容)
}

/** LLM call result — content + token usage (mirrors Python LLMResult) */
export interface LLMResult {
  content: string;
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  model: string;
}

/** 超时配置（对齐 Python TimeoutConfig） */
export interface TimeoutConfig {
  totalTimeout: number;       // 总超时（含重试），默认 90s
  prompt1Timeout: number;     // 单次 LLM 调用超时，默认 40s
  prompt2Timeout: number;     // policy 生成 LLM 调用超时（TS 暂未实现 policy 生成，保留字段对齐 py），默认 20s
  stepInterval: number;       // 步骤间隔，默认 0
}

/** 重试配置（对齐 Python RetryConfig） */
export interface RetryConfig {
  maxRetries: number;         // 最大重试次数，默认 2
  retryInterval: number;      // 重试间隔，默认 2s
}
