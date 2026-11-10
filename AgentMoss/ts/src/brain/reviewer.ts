/**
 * Brain 候选 pattern LLM 审核器 — TypeScript implementation.
 *
 * Mirrors Python agent_moss/brain/reviewer.py. When a pattern candidate
 * reaches the occurrence threshold, ask the LLM whether it's worth promoting
 * to a local rule. Rejects are permanently excluded; LLM-unavailable degrades
 * to "keep candidate" (don't promote, don't reject).
 */

import OpenAI from 'openai';
import { getLLMConfig, isLLMAvailable, detectProvider, getProviderHeaders } from '../config';

interface ReviewResult {
  shouldKeep: boolean;
  reason?: string;
}

const REVIEW_PROMPT = `你是 AgentMoss 安全规则审核器。判断下列"从 LLM 拒绝结果中提取的安全模式"是否值得沉淀为本地规则。

## 提取的模式（候选）
- 模式: {pattern}
- 所属层: Layer {layer}（1=特征匹配，2=行为链）
- 类型: {ruleType}

## 原始被拒绝的操作
{actionDetail}

## LLM 当时的拒绝理由
{reason}

## 判断准则
1. **是否过高泛化**：这条模式是否会误拦正常的合法操作？
2. **是否符合敏感特征**：指向的路径/命令是否确实敏感（凭据/系统文件/恶意命令/外传）？
3. **与三层规则重复**：是否已被现有 L1/L2 规则覆盖？
4. **是不是真实攻击模式**：是否代表一种连续的攻击行为模式？

## 输出 JSON（只输出 JSON，无其他文字）
{"should_keep": true/false, "confidence": 0-100, "reason": "简短理由（中文）", "suggested_rule": "若保留则输出建议正则，否则空串", "duplicate_of": "若重复则说明是哪个，否则空串"}`;

interface ParsedReview {
  shouldKeep: boolean;
  confidence: number;
  reason: string;
}

export function createBrainReviewer(timeoutMs = 10000):
  (opts: { pattern: string; layer: number; ruleType: string; actionDetail: string; reason: string })
    => Promise<ReviewResult | null> {
  return async (opts) => {
    // 审核开关：AGENT_MOSS_BRAIN_REVIEW=0 关闭（对齐 Python）
    if (process.env.AGENT_MOSS_BRAIN_REVIEW === '0') return null;
    if (!isLLMAvailable()) return null;

    const config = getLLMConfig();
    const provider = detectProvider(config.baseUrl, config.provider);
    const extraHeaders = getProviderHeaders(provider);
    const client = new OpenAI({
      baseURL: config.baseUrl,
      apiKey: config.apiKey,
      timeout: timeoutMs,
      maxRetries: 1,
      defaultHeaders: Object.keys(extraHeaders).length > 0 ? extraHeaders : undefined,
    });

    const prompt = REVIEW_PROMPT
      .replace('{pattern}', opts.pattern)
      .replace('{layer}', String(opts.layer))
      .replace('{ruleType}', opts.ruleType)
      .replace('{actionDetail}', (opts.actionDetail || '').slice(0, 400))
      .replace('{reason}', (opts.reason || '').slice(0, 400));

    try {
      const response = await client.chat.completions.create({
        model: config.model,
        temperature: config.temperature || 0.1,
        max_tokens: 256,
        messages: [
          { role: 'system', content: '只输出纯 JSON，不要包含 markdown 标记、代码块或任何其他文字。' },
          { role: 'user', content: prompt },
        ],
      } as any);
      const content = response.choices[0]?.message?.content || '';
      const parsed = parseReview(content);
      return { shouldKeep: parsed.shouldKeep, reason: parsed.reason };
    } catch (e) {
      console.warn(`[AgentMoss] Brain 审核 LLM 调用失败（降级保持候选）: ${(e as Error).message}`);
      return null;
    }
  };
}

export function parseReview(content: string): ParsedReview {
  let text = content.trim();
  if (text.startsWith('```')) {
    text = text.replace(/^```[a-zA-Z]*\n?/, '').replace(/\n?```$/, '');
  }
  // 提取第一个 JSON 对象
  const match = text.match(/\{[\s\S]*\}/);
  if (!match) throw new Error(`审核响应无 JSON 对象: ${text.slice(0, 200)}`);
  const data = JSON.parse(match[0]);
  if (!('should_keep' in data) && !('shouldKeep' in data)) {
    throw new Error(`审核响应缺 should_keep: ${text.slice(0, 200)}`);
  }
  let shouldKeep = data.shouldKeep ?? data.should_keep;
  if (typeof shouldKeep === 'string') {
    shouldKeep = ['true', '1', '是', 'yes'].includes(shouldKeep.trim().toLowerCase());
  }
  return {
    shouldKeep: !!shouldKeep,
    confidence: Number(data.confidence ?? 0) || 0,
    reason: String(data.reason ?? data.suggested_rule ?? '') || '',
  };
}