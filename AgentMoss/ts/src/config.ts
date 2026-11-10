import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import type { LLMConfig, TimeoutConfig, RetryConfig } from './engine/types';
import { getConfigDir } from './infra/paths';

/** Custom rule from user config */
export interface CustomRule {
  pattern: string;
  action: 'Allow' | 'Deny';
  severity: string;
  description?: string;
}

/** Read config from file (JSON), returns parsed object or null */
function loadConfigFile(filePath: string): Record<string, any> | null {
  try {
    const raw = fs.readFileSync(filePath, 'utf-8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/** Determine config file path with priority:
 *  1. AGENT_MOSS_CONFIG_PATH env var
 *  2. ~/.config/agentmoss/config.json (auto-create if missing)
 *  3. Package default (relative to __dirname)
 */
function resolveConfigPath(): string {
  const envPath = process.env.AGENT_MOSS_CONFIG_PATH;
  if (envPath) return envPath;

  const userConfig = path.join(getConfigDir(), 'config.json');
  if (fs.existsSync(userConfig)) return userConfig;

  // Auto-create from package default
  const defaultConfig = path.join(__dirname, '..', '..', 'agent_moss', 'infra', 'config.json.example');
  if (fs.existsSync(defaultConfig)) {
    const configDir = path.dirname(userConfig);
    fs.mkdirSync(configDir, { recursive: true });
    // Read the default config and filter out the api_key for safety
    const pkgConfig = loadConfigFile(defaultConfig);
    const safeConfig = pkgConfig ? { ...pkgConfig, llm: { ...pkgConfig.llm, api_key: '' } } : {};
    fs.writeFileSync(userConfig, JSON.stringify(safeConfig, null, 4), 'utf-8');
    console.log(`[AgentMoss] 已创建用户配置文件: ${userConfig}`);
    console.log(`[AgentMoss] 请编辑该文件配置你的 LLM API Key`);
  }
  return userConfig;
}

/** Load LLM config from file, merged with environment variables (env wins) */
function loadLLMConfigFromFile(configPath: string): Partial<LLMConfig> {
  const data = loadConfigFile(configPath);
  if (!data?.llm) return {};

  const llm = data.llm;
  return {
    provider: llm.provider || '',
    baseUrl: llm.base_url || '',
    apiKey: llm.api_key || '',
    model: llm.model || '',
    temperature: llm.temperature ?? 0.1,
    maxTokens: llm.max_tokens ?? 4096,
    timeout: llm.timeout ?? 40,
  };
}

/** Load timeout/retry config from file (对齐 Python TimeoutConfig / RetryConfig) */
function loadTimeoutRetryFromFile(configPath: string): { timeout: TimeoutConfig; retry: RetryConfig } {
  const data = loadConfigFile(configPath);
  const t = data?.timeout ?? {};
  const r = data?.retry ?? {};
  return {
    timeout: {
      totalTimeout: Number(t.total_timeout ?? 90),
      prompt1Timeout: Number(t.prompt1_timeout ?? 40),
      prompt2Timeout: Number(t.prompt2_timeout ?? 20),
      stepInterval: Number(t.step_interval ?? 0),
    },
    retry: {
      maxRetries: Number(r.max_retries ?? 2),
      retryInterval: Number(r.retry_interval ?? 2),
    },
  };
}

/** Global timeout/retry configuration (对齐 Python TimeoutConfig / RetryConfig) */
let timeoutConfig: TimeoutConfig;
let retryConfig: RetryConfig;

/** Global LLM configuration, initialized from file + env vars (env wins) */
let llmConfig: LLMConfig = (() => {
  const configPath = resolveConfigPath();
  const fileConfig = fs.existsSync(configPath) ? loadLLMConfigFromFile(configPath) : {};
  const tr = loadTimeoutRetryFromFile(configPath);
  timeoutConfig = tr.timeout;
  retryConfig = tr.retry;

  return {
    provider: process.env.AGENT_MOSS_LLM_PROVIDER || fileConfig.provider || 'openai',
    baseUrl: process.env.AGENT_MOSS_LLM_BASE_URL || fileConfig.baseUrl || 'https://api.openai.com/v1',
    apiKey: process.env.AGENT_MOSS_LLM_API_KEY || process.env.OPENAI_API_KEY || fileConfig.apiKey || '',
    model: process.env.AGENT_MOSS_LLM_MODEL || fileConfig.model || 'gpt-4o',
    temperature: parseFloat(process.env.AGENT_MOSS_LLM_TEMPERATURE || String(fileConfig.temperature ?? '0.1')),
    maxTokens: parseInt(process.env.AGENT_MOSS_LLM_MAX_TOKENS || String(fileConfig.maxTokens ?? '4096'), 10),
    // 优先用 env，否则用 timeout 块的 prompt1Timeout（对齐 py）
    timeout: parseInt(process.env.AGENT_MOSS_LLM_TIMEOUT || String(fileConfig.timeout ?? String(tr.timeout.prompt1Timeout)), 10),
  };
})();

export function getTimeoutConfig(): Readonly<TimeoutConfig> {
  return timeoutConfig;
}

export function getRetryConfig(): Readonly<RetryConfig> {
  return retryConfig;
}

// 打包内 user_rules.json 路径（npm 安装自包含）+ dev 回退到仓库根 agent_moss/rules。
// 对齐 skill-loader.ts 的 fileURLToPath(import.meta.url) 双路径解析：
// - tsup 打包后 config.ts 被内联进 dist/{cli,server,engine/coordinator}.js，
//   import.meta.url 指向该 chunk（dist/engine/coordinator.js → __dirname=dist/engine/），
//   故 dist 内 rules 在 ../rules（即 dist/rules/user_rules.json，copy-assets.cjs 复制）。
// - dev(vitest) 模式 config.ts 源文件 __dirname=ts/src/，仓库根 agent_moss/rules
//   在 ../../agent_moss/rules。三条候选路径覆盖 dist 与 dev 两种形态，命中即用。
const __configModuleDir = (() => {
  try { return path.dirname(fileURLToPath(import.meta.url)); }
  catch { return typeof __dirname !== 'undefined' ? __dirname : process.cwd(); }
})();
const USER_RULES_PATHS = [
  path.join(__configModuleDir, 'rules', 'user_rules.json'),          // 源在 ts/src/rules（一般不存在）
  path.join(__configModuleDir, '..', 'rules', 'user_rules.json'),    // dist: dist/engine/../rules = dist/rules ✅
  path.join(__configModuleDir, '..', '..', 'agent_moss', 'rules', 'user_rules.json'), // dev src: ts/src/../../agent_moss
];

function wildcardToRegExp(pattern: string): string {
  // 对齐 Python UserRuleMatcher: re.escape(pattern).replace(r"\*", ".*")
  // JS 无 re.escape，手动转义所有正则元字符，再把转义后的 \* 还原为 .*
  return pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\\\*/g, '.*');
}

function loadCustomRules(): CustomRule[] {
  const rules: CustomRule[] = [];
  // 1. AGENT_MOSS_CUSTOM_RULES env var（运行时注入，最高优先）
  try {
    const raw = process.env.AGENT_MOSS_CUSTOM_RULES;
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        for (const r of parsed) {
          if (r && r.pattern && r.action) rules.push({ pattern: r.pattern, action: r.action, severity: r.severity || 'high' });
        }
      }
    }
  } catch { /* ignore env parse error */ }

  // 2. 打包内 agent_moss/rules/user_rules.json 的 sensitive_actions（通配符规则）。
  // 对齐 Python UserRuleMatcher（DEFAULT_RULES_PATH = agent_moss/rules/user_rules.json），
  // 含 crontab -e / crontab -r / * | crontab / iptables - 等用户敏感规则。
  // TS 此前只读 env 不读该文件，导致 crontab -e 等 L1 漏检（FN-2）。wildcard → RegExp。
  for (const rulesPath of USER_RULES_PATHS) {
    try {
      if (!fs.existsSync(rulesPath)) continue;
      const data = JSON.parse(fs.readFileSync(rulesPath, 'utf-8'));
      const actions = Array.isArray(data?.sensitive_actions) ? data.sensitive_actions : [];
      for (const r of actions) {
        const p = r?.pattern;
        if (!p) continue;
        rules.push({ pattern: wildcardToRegExp(p), action: 'Deny', severity: 'high' });
      }
      break; // 命中第一个存在的文件即可
    } catch { /* ignore user_rules.json read/parse error */ }
  }
  return rules;
}

/** Custom rules loaded from AGENT_MOSS_CUSTOM_RULES env var + packaged user_rules.json */
let customRules: CustomRule[] = loadCustomRules();

export function getLLMConfig(): Readonly<LLMConfig> {
  return llmConfig;
}

export function updateLLMConfig(partial: Partial<LLMConfig>): void {
  llmConfig = { ...llmConfig, ...partial };
}

export function getCustomRules(): Readonly<CustomRule[]> {
  return customRules;
}

/** Check if LLM analysis is available (API key configured + not disabled) */
export function isLLMAvailable(): boolean {
  if (process.env.AGENT_MOSS_DISABLE_LLM === '1') return false;
  if (!layerEnabledOrDefault('L3_llm_analysis')) return false;
  return llmConfig.apiKey.length > 0;
}

/**
 * Probe LLM connectivity with a minimal max_tokens=1 request.
 * Mirrors Python _probe_llm (tests/conftest.py): same source of truth
 * (getLLMConfig / get_default_config), so a passing probe means the actual
 * L3 call in tests uses the same key/endpoint and will succeed.
 *
 * Returns true on any successful response (finish_reason length/stop both ok);
 * false on timeout / 401 / network error. Used by L3 tests to skip rather than
 * let a dead key fail-open and false-pass.
 */
export async function probeLLMConnection(timeoutMs: number = 8000): Promise<boolean> {
  if (!isLLMAvailable()) return false;
  const OpenAI = (await import('openai')).default;
  const config = getLLMConfig();
  const provider = detectProvider(config.baseUrl, config.provider);
  const extraHeaders = getProviderHeaders(provider);
  const client = new OpenAI({
    baseURL: config.baseUrl,
    apiKey: config.apiKey,
    timeout: timeoutMs,
    maxRetries: 0,
    defaultHeaders: Object.keys(extraHeaders).length > 0 ? extraHeaders : undefined,
  });
  try {
    const resp = await client.chat.completions.create({
      model: config.model,
      messages: [{ role: 'user', content: 'ping' } as any],
      max_tokens: 1,
    } as any);
    return !!(resp && resp.choices && resp.choices[0]);
  } catch {
    return false;
  }
}

/**
 * LLM analysis failure mode (mirrors Python get_llm_fail_mode).
 *
 * - "fail_open" (default): when L3 LLM fails and prior layers did NOT block,
 *   Allow + warning log (availability-first)
 * - "fail_closed": LLM failure -> Deny (safety-first)
 *
 * Priority: env AGENT_MOSS_LLM_FAIL_MODE > default fail_open.
 */
export function getLLMFailMode(): 'fail_open' | 'fail_closed' {
  const val = (process.env.AGENT_MOSS_LLM_FAIL_MODE || 'fail_open').toLowerCase();
  return val === 'fail_closed' ? 'fail_closed' : 'fail_open';
}

// ========== Provider detection & headers ==========

const PROVIDER_HEADERS: Record<string, Record<string, string>> = {
  'openrouter': {
    'HTTP-Referer': 'shturl.cc/LlVD5pyWViHjM',
    'X-OpenRouter-Title': 'AgentMoss',
  },
  'xai': {
    'HTTP-Referer': 'shturl.cc/LlVD5pyWViHjM',
  },
};

/** Detect provider from base URL or explicit hint (mirrors Python detect_provider) */
export function detectProvider(baseUrl: string, providerHint: string = ''): string {
  if (providerHint) {
    const hint = providerHint.toLowerCase();
    if (['claude', 'anthropic'].includes(hint)) return 'anthropic';
    if (['google', 'gemini'].includes(hint)) return 'gemini';
    if (['zai-coding-plan', 'zhipu-coding-plan', 'zhipuai-coding-plan'].includes(hint)) return 'zai-coding-plan';
    if (['zai', 'z-ai', 'z.ai', 'zai-cn', 'zai-china', 'zhipu', 'glm-cn', 'bigmodel'].includes(hint)) return 'zhipu';
    if (['xai', 'xai-grok'].includes(hint)) return 'xai';
    if (['minimax', 'minimax-openai'].includes(hint)) return 'minimax';
    if (['minimax-anthropic'].includes(hint)) return 'minimax-anthropic';
    if (['other', 'custom', 'local'].includes(hint)) return 'openai-compatible';
    return hint;
  }

  const url = baseUrl.toLowerCase();
  if (url.includes('openrouter.ai')) return 'openrouter';
  if (url.includes('api.openai.com')) return 'openai';
  if (url.includes('anthropic.com') || url.includes('api.anthropic.com')) return 'anthropic';
  if (url.includes('generativelanguage.googleapis.com') || url.includes('gemini')) return 'gemini';
  if (url.includes('api.deepseek.com')) return 'deepseek';
  if (url.includes('api.groq.com')) return 'groq';
  if (url.includes('api.mistral.ai')) return 'mistral';
  if (url.includes('api.together.xyz')) return 'together';
  if (url.includes('api.x.ai')) return 'xai';
  if (url.includes('api.minimaxi.com')) return 'minimax';
  if (url.includes('api-ai.gitcode.com')) return 'gitcode';
  if (url.includes('api.z.ai')) return 'zai-coding-plan';
  if (url.includes('open.bigmodel.cn') || url.includes('bigmodel')) return 'zhipu';
  if (url.includes(':11434')) return 'ollama';
  return 'openai-compatible';
}

/** Get provider-specific headers (mirrors Python get_provider_headers) */
export function getProviderHeaders(provider: string): Record<string, string> {
  return PROVIDER_HEADERS[provider] || {};
}

/** Per-layer enable/disable (matches Python SecurityConfig + runtime layers).
 * env 优先（显式禁用），其次 runtime_config.layers（console 层级全局开关），
 * 默认 true。延迟 require isLayerEnabled 避免 config↔runtime-config 循环依赖。 */
export function isHeuristicEnabled(): boolean {
  if (process.env.AGENT_MOSS_DISABLE_HEURISTIC === '1') return false;
  return layerEnabledOrDefault('L1_heuristic');
}
function layerEnabledOrDefault(key: string): boolean {
  try {
    const { isLayerEnabled } = require('../infra/runtime-config') as any;
    return isLayerEnabled(key);
  } catch {
    return true;
  }
}

/**
 * Brain 自学习机制是否启用。默认关闭（开发中，避免污染 L1/L2 判定与 L3 prompt），
 * 仅当显式设置 AGENT_MOSS_BRAIN_ENABLED=1 时启用（镜像 Python is_brain_enabled）。
 */
export function isBrainEnabled(): boolean {
  return process.env.AGENT_MOSS_BRAIN_ENABLED === '1';
}

export function isLogicRulesEnabled(): boolean {
  if (process.env.AGENT_MOSS_DISABLE_LOGIC_RULES === '1') return false;
  return layerEnabledOrDefault('L2_logic_rules');
}

/**
 * L2.2 formal 引擎 observe 模式是否启用（镜像 Python SecurityConfig.formal_observe_mode
 * + AGENT_MOSS_FORMAL_OBSERVE=1）：命中违规时只记录不拦截（灰度观察 FP 率用）。
 */
export function isFormalObserveMode(): boolean {
  return process.env.AGENT_MOSS_FORMAL_OBSERVE === '1';
}
