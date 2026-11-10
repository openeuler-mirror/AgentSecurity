import { SecurityJudgment } from './types';
import type { AnalysisInput } from './coordinator';
import { getLLMConfig, isLLMAvailable, detectProvider, getProviderHeaders, getTimeoutConfig, getRetryConfig } from '../config';
import { matchSkills, formatSkillsForPrompt } from './skill-loader';
import { loadTemplates } from './template-loader';
import { analyzeScriptContent, formatScriptAnalysisForPrompt } from './script-analyzer';
import { formatScriptChainForPrompt } from './script-content-analyzer';
import { appendFileSync } from 'fs';
import OpenAI from 'openai';

// LRU cache to avoid duplicate LLM calls for identical commands
const llmCache = new Map<string, SecurityJudgment>();
const LLM_CACHE_MAX = 200;

interface PreviousResults {
  heuristic: SecurityJudgment | null;
  logic: SecurityJudgment | null;
  skipL3Hints?: string;
  scriptChain?: import('./script-content-analyzer').ScriptChainAnalysisResult;
  /** per-request LLM prompt 日志路径（来自调用方 metadata.llm_log_path） */
  llmLogPath?: string;
}

/**
 * Layer 3: LLM + Skill semantic analysis.
 * Only called when layers 1 and 2 both pass.
 * Loads skills from the shared skills directory and uses LLM for deep analysis.
 */
export async function runLLMAnalysis(
  input: AnalysisInput,
  previous: PreviousResults
): Promise<SecurityJudgment> {
  if (!isLLMAvailable()) {
    console.log('[AgentMoss] LLM not configured, skipping deep analysis');
    return {
      allowed: true,
      reason: 'LLM 未配置，跳过深层分析',
      riskLevel: 'low',
      riskType: '',
      confidence: 50,
      source: 'llm',
      violatedLayers: [],
    };
  }

  // 优先使用 per-request 的 LLM 配置（OpenDesk 按当前会话模型传入）
  const globalConfig = getLLMConfig();
  const config = input.llmConfig?.apiKey
    ? { ...globalConfig, ...input.llmConfig }
    : globalConfig;

  // Check LRU cache (use raw command as key, strip OpenDesk metadata)
  const rawDetail = input.aNext.actionDetail.replace(/^terminal-\w+:\s*command=([^,]+).*/, '$1').trim();
  const cacheKey = `${input.aNext.actionType}:${rawDetail || input.aNext.actionDetail}`;
  const cached = llmCache.get(cacheKey);
  if (cached) {
    console.log('[AgentMoss] LLM cache hit');
    return cached;
  }

  // Load skills and templates (cached)
  const matchedSkills = matchSkills(input.aNext.actionType, input.aNext.actionDetail, input.reason);
  const templates = loadTemplates();

  // Build the analysis prompt. Prefer the script chain from coordinator
  // (L1.2/L2.3 already did recursive tracking); fall back to single-file scan.
  let scriptAnalysis: import('./script-analyzer').ScriptAnalysisResult | undefined;
  let scriptChainText = '';
  if (previous.scriptChain) {
    scriptChainText = formatScriptChainForPrompt(previous.scriptChain);
  } else {
    scriptAnalysis = analyzeScriptContent(input.aNext.actionType, input.aNext.actionDetail);
  }
  const prompt = buildPrompt(input, previous, matchedSkills, templates, scriptAnalysis, previous.skipL3Hints ?? '', scriptChainText);

  // 写 LLM prompt 到日志（per-request logPath 优先，对齐 py _log_prompt）。
  // 与 bridge.ts 写 HOOK_INPUT/HOOK_OUTPUT 同一个文件，对齐 audit_agent AUDIT_LOG_PATH。
  logPrompt(prompt, input.aNext, previous.llmLogPath);

  // Call LLM
  const result = await analyzeWithLLM(prompt, config);

  // Cache result
  if (llmCache.size >= LLM_CACHE_MAX) {
    const firstKey = llmCache.keys().next().value;
    if (firstKey) llmCache.delete(firstKey);
  }
  llmCache.set(cacheKey, result);

  return result;
}

/**
 * 写 LLM prompt 到日志文件（对齐 Python _log_prompt）。
 * logPath 来自 per-request metadata.llm_log_path（调用方 env 注入）。
 * 与 bridge.ts 的 HOOK_INPUT/HOOK_OUTPUT 写同一个文件，对齐 audit_agent AUDIT_LOG_PATH。
 */
function logPrompt(prompt: string, aNext: { actionType: string; actionDetail: string }, logPath?: string): void {
  if (!logPath) return;
  try {
    const actionType = aNext.actionType || 'unknown';
    const actionDetail = (aNext.actionDetail || '').slice(0, 100);
    const line =
      `[${new Date().toISOString()}] ` +
      `[LLM_PROMPT] action_type=${actionType}, action_detail=${actionDetail}... ` +
      `prompt_length=${prompt.length}\n` +
      `${prompt}\n` +
      `--- END PROMPT ---\n`;
    appendFileSync(logPath, line, 'utf-8');
  } catch (e) {
    console.warn('[AgentMoss] Failed to write LLM prompt to log:', e);
  }
}

export function buildPrompt(
  input: AnalysisInput,
  previous: PreviousResults,
  matchedSkills: import('./skill-loader').SkillMatch[],
  templates: Record<string, string>,
  scriptAnalysis?: import('./script-analyzer').ScriptAnalysisResult,
  skipL3Hints: string = '',
  scriptChainText: string = '',
): string {
  const skillsText = formatSkillsForPrompt(matchedSkills);
  const historyStr = input.actionHistory
    .map((h, i) => `${i + 1}. ${h.actionType}: ${h.actionDetail}`)
    .join('\n') || '(无历史操作)';

  // 交错历史 prompt（供 LLM 判断意图一致性，避免"继续"覆盖初始意图）。
  const promptHistoryText = formatPromptHistory(input.promptHistory);

  // Prefer coordinator-provided script chain text (recursive tracking result);
  // fall back to single-file keyword prescan; else empty.
  const scriptAnalysisText = scriptChainText
    ? scriptChainText
    : (scriptAnalysis ? formatScriptAnalysisForPrompt(scriptAnalysis) : '');

  // Format L1/L2 hints (mirrors Python LLMAnalyzer._format_hints)
  const hintsText = formatHints(previous);

  // Layer 3 安全判断用 security_judge_template（对齐 Python get_security_judge_prompt）。
  // prompt1/prompt2 是 Cerberus 沙箱策略模板，不适用于此处的 Allow/Deny 裁决。
  const securityJudgeTemplate = templates['security_judge'];
  if (securityJudgeTemplate) {
    // 占位符逐个替换（不能用全局 {x} 正则：模板 JSON 示例里的 {{ }} 会误伤）。
    // security_judge_template.txt 用 {{ }} 转义 JSON 大括号，替换完后还原为单括号。
    return securityJudgeTemplate
      .replaceAll('{prompt_session}', input.promptSession || '（未提供）')
      .replaceAll('{prompt_history_text}', promptHistoryText)
      .replaceAll('{action_history}', historyStr)
      .replaceAll('{action_type}', input.aNext.actionType)
      .replaceAll('{action_detail}', input.aNext.actionDetail)
      .replaceAll('{reason}', input.reason || '未说明')
      .replaceAll('{skills_text}', skillsText)
      .replaceAll('{hints_text}', hintsText)
      .replaceAll('{script_analysis_text}', scriptAnalysisText)
      .replaceAll('{skip_l3_hints}', skipL3Hints)
      .replaceAll('{{', '{')
      .replaceAll('}}', '}');
  }

  // Fallback：security_judge 模板缺失时（旧包/加载异常），退回稀疏 prompt，避免崩溃。
  // 这种情况下 LLM 裸跑，判断质量下降，但不阻断流程。
  console.warn('[AgentMoss] security_judge template missing, using sparse fallback prompt');
  return `## 当前操作上下文
- 会话 ID: ${input.sessionId}
- 用户任务: ${input.promptSession || '未指定'}
- 操作系统: ${input.osType}
- 工作目录: ${input.cwd || '/'}
- 操作原因: ${input.reason || '未说明'}
- 历史操作序列:
${historyStr}

- 即将执行的操作:
  类型: ${input.aNext.actionType}
  详情: ${input.aNext.actionDetail}

## 可用安全 Skill
${skillsText}

## 前置检测结果
${hintsText}
${scriptAnalysisText ? `\n## 脚本内容分析\n${scriptAnalysisText}` : ''}

请根据以上信息，对即将执行的操作进行安全判断。前置检测为 low/medium 且有合理执行理由时应当允许。你必须输出严格的 JSON 格式，不要包含任何其他文字、注释或 markdown 标记。

输出格式:
{"allowed": true/false, "reason": "判断理由", "riskLevel": "low|medium|high|critical", "riskType": "风险类型", "confidence": 0-100}`;
}

/** 格式化交错历史 prompt 为 LLM 可读文本（对齐 Python LLMAnalyzer._format_prompt_history）。 */
function formatPromptHistory(
  promptHistory?: AnalysisInput['promptHistory'],
  maxTextChars = 500,
): string {
  if (!promptHistory || promptHistory.length === 0) {
    return '（未提供历史意图）';
  }
  const lines: string[] = [];
  for (let i = 0; i < promptHistory.length; i++) {
    const turn = promptHistory[i];
    // 兼容两种元素格式：纯文本 string（AgentGate v3 旧格式）与 {text, actions} dict
    const text = (typeof turn === 'string' ? turn : (turn?.text || '')).trim();
    if (!text) continue;
    let line = `  第${i + 1}轮用户意图: ${text.slice(0, maxTextChars)}`;
    const actions = typeof turn === 'string' ? undefined : turn?.actions;
    if (actions && actions.length > 0) {
      const types = actions
        .map(a => a?.actionType)
        .filter((t): t is string => typeof t === 'string' && t.length > 0);
      if (types.length > 0) {
        line += `  → 动作: ${types.join(', ')}`;
      }
    }
    lines.push(line);
  }
  return lines.length > 0 ? lines.join('\n') : '（未提供历史意图）';
}

function formatHints(previous: PreviousResults): string {
  const hints: string[] = [];

  if (previous.heuristic) {
    hints.push(
      `特征匹配检测发现风险 [风险等级: ${previous.heuristic.riskLevel}]:\n` +
      `   类型: ${previous.heuristic.riskType}\n` +
      `   原因: ${previous.heuristic.reason}`
    );
  }

  if (previous.logic) {
    hints.push(
      `逻辑规则检测发现风险 [风险等级: ${previous.logic.riskLevel}]:\n` +
      `   类型: ${previous.logic.riskType}\n` +
      `   原因: ${previous.logic.reason}`
    );
  }

  return hints.length > 0 ? hints.join('\n\n') : '特征匹配检测和逻辑规则检测均未发现风险。';
}

async function analyzeWithLLM(prompt: string, config: ReturnType<typeof getLLMConfig>): Promise<SecurityJudgment> {
  console.log(`[AgentMoss] LLM analyzing with model: ${config.model}, url: ${config.baseUrl}`);

  const provider = detectProvider(config.baseUrl, config.provider);
  const extraHeaders = getProviderHeaders(provider);
  if (Object.keys(extraHeaders).length > 0) {
    console.log(`[AgentMoss] Provider detected: ${provider}, injecting headers: ${Object.keys(extraHeaders).join(', ')}`);
  }

  const timeoutCfg = getTimeoutConfig();
  const retryCfg = getRetryConfig();
  const client = new OpenAI({
    baseURL: config.baseUrl,
    apiKey: config.apiKey,
    // 单次 LLM 调用超时用 prompt1Timeout（对齐 py）；env 覆盖的 config.timeout 仍向后兼容
    timeout: (config.timeout || timeoutCfg.prompt1Timeout) * 1000,
    defaultHeaders: Object.keys(extraHeaders).length > 0 ? extraHeaders : undefined,
  });

  // maxRetries 优先 env，否则用 retry 配置（默认 2，对齐 py）
  const maxRetries = parseInt(process.env.AGENT_MOSS_LLM_RETRIES || String(retryCfg.maxRetries), 10);

  // totalTimeout 强制执行：用 AbortController 确保整个 LLM 分析（含所有重试）
  // 在 totalTimeout（默认 90s）后强制中断，防止最坏情况 ~372s 超时。
  const totalTimeoutMs = timeoutCfg.totalTimeout * 1000;
  const abortController = new AbortController();
  const totalTimeoutTimer = setTimeout(() => {
    console.error(`[AgentMoss] totalTimeout (${timeoutCfg.totalTimeout}s) exceeded, aborting all LLM calls`);
    abortController.abort();
  }, totalTimeoutMs);

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    if (abortController.signal.aborted) {
      break;
    }
    try {
      const response = await client.chat.completions.create({
        model: config.model,
        temperature: config.temperature || 0.1,
        max_tokens: config.maxTokens || 1024,
        messages: [
          { role: 'system', content: '只输出纯 JSON，不要包含 markdown 标记、代码块或任何其他文字。' },
          { role: 'user', content: prompt },
        ],
        signal: abortController.signal,
      } as any);

      const content = response.choices[0]?.message?.content || '{}';
      console.log(`[AgentMoss] LLM raw response (attempt ${attempt + 1}/${maxRetries + 1}): ${content.substring(0, 300)}`);

      let jsonStr = content.trim();
      if (jsonStr.startsWith('```')) {
        jsonStr = jsonStr.replace(/^```[\w]*\n?/, '').replace(/\n?```$/, '');
      }
      const parsed = JSON.parse(jsonStr);

      // 记录 token 用量（step="L3_security_judge"）
      try {
        const usage = response.usage;
        const { recordTokenUsage } = await import('./token-stats');
        recordTokenUsage({
          sessionId: 'audit',
          step: 'L3_security_judge',
          model: response.model || config.model,
          promptTokens: usage?.prompt_tokens || 0,
          completionTokens: usage?.completion_tokens || 0,
          totalTokens: usage?.total_tokens || 0,
        });
      } catch { /* token stats optional */ }

      clearTimeout(totalTimeoutTimer);
      // LLM 回 JSON 字段名可能是 camelCase（riskLevel）或 snake_case（risk_level），
      // 两种都兼容避免拿不到 risk_level 走兜底 'low'（双端对齐 Python 字段名）
      const riskLevel = parsed.riskLevel ?? parsed.risk_level;
      const riskType = parsed.riskType ?? parsed.risk_type;
      return {
        allowed: parsed.allowed !== false,
        reason: parsed.reason || 'LLM 分析完成',
        riskLevel: ['low', 'medium', 'high', 'critical'].includes(riskLevel) ? riskLevel : 'low',
        riskType: riskType || '',
        confidence: typeof parsed.confidence === 'number' ? Math.min(100, Math.max(0, parsed.confidence)) : 70,
        source: 'llm',
        violatedLayers: ['L3.1'],
      };
    } catch (err) {
      // totalTimeout 触发的 AbortError：直接跳出循环，不再重试
      if (abortController.signal.aborted) {
        console.error(`[AgentMoss] LLM analysis aborted by totalTimeout (${timeoutCfg.totalTimeout}s)`);
        break;
      }
      if (attempt < maxRetries) {
        console.error(`[AgentMoss] LLM call failed (attempt ${attempt + 1}/${maxRetries + 1}), retrying in ${retryCfg.retryInterval}s:`, (err as Error).message);
        await new Promise(resolve => setTimeout(resolve, retryCfg.retryInterval * 1000));
      } else {
        clearTimeout(totalTimeoutTimer);
        console.error('[AgentMoss] LLM call failed after all retries:', (err as Error).message);
        throw new Error(`LLM 分析失败 (${maxRetries + 1} 次尝试): ${(err as Error).message}`);
      }
    }
  }

  // totalTimeout 超时或 AbortError 导致循环中断
  clearTimeout(totalTimeoutTimer);
  throw new Error(`LLM 分析超时（totalTimeout ${timeoutCfg.totalTimeout}s）`);
}
