/**
 * Runtime config — full implementation (mirrors Python runtime_config.py).
 *
 * Runtime JSON: ~/.config/agentmoss/agent_moss_runtime.json
 * (env AGENT_MOSS_RUNTIME_CONFIG_PATH override). Seed from OSProfile +
 * module consts + SKILL_KEYWORD_MAP. mergeConfig on load (preserve user
 * toggles, append builtins, mark removed).
 *
 * Priority: env > runtime JSON > agent_moss_settings > default.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, unlinkSync, readdirSync } from 'fs';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { getRuntimeConfigDir } from './paths';
const __dirname = dirname(fileURLToPath(import.meta.url));
// 静态 import（非 require）：package.json type=module，require 在 ESM 不可用。
// 这三个模块不反向 import runtime-config，无循环依赖。
import { DANGEROUS_PATTERNS, INJECTION_KEYWORDS } from '../engine/heuristic';
import {
  ROOT_SENSITIVE_PATHS, HOME_SENSITIVE_PATHS, CREDENTIAL_PATHS,
  PASSWORD_MODIFY_PATTERNS, USER_DELETION_PATTERNS, INTENT_DEVIATION_PATTERNS,
} from '../engine/logic-rules';
import { SKILL_KEYWORD_MAP } from '../engine/skill-loader';
// type-only import：避免 agents ↔ runtime-config 循环依赖（运行时用 require 取 resolveAgentsDir）
import type { AgentExtensions } from '../agents/types';

const ENV_RUNTIME_CONFIG_PATH = 'AGENT_MOSS_RUNTIME_CONFIG_PATH';

function runtimeDir(): string {
  return getRuntimeConfigDir();
}

const RUNTIME_CONFIG_DIR = runtimeDir();
const RUNTIME_CONFIG_PATH = join(RUNTIME_CONFIG_DIR, 'agent_moss_runtime.json');

const LAYER_DISABLE_ENV: Record<string, string> = {
  L1_heuristic: 'AGENT_MOSS_DISABLE_HEURISTIC',
  L2_logic_rules: 'AGENT_MOSS_DISABLE_LOGIC_RULES',
  L3_llm_analysis: 'AGENT_MOSS_DISABLE_LLM',
};

/** 出厂默认层开关（含 L2.2 形式化独立开关，默认开）。 */
export const DEFAULT_LAYERS = {
  L1_heuristic: true,
  L2_logic_rules: true,
  L3_llm_analysis: true,
  agent_rules_enabled: true,
  scenario_rules_enabled: true,
};

export const DENY_MODE_LABELS: Record<string, string> = {
  deny_write: '仅拦截写入',
  deny_read: '仅拦截读取',
  deny_both: '读写均拦截',
};

// ==================== Types ====================

export interface Rule {
  id: string;
  enabled: boolean;
  builtin: boolean;
  source_removed?: boolean;
  pattern?: string;
  risk_level?: string;
  risk_type?: string;
  reason?: string;
  keyword?: string;
  lang?: string;
  path?: string;
  desc?: string;
  deny_mode?: string;
  source_deny_mode?: string;
  credential?: boolean;
  read_only?: boolean;
  dir_del_only?: boolean; // NEW-FP-1: 目录级条目标记（仅删除拦截，.ssh/.aws 目录初始化放行）
  skip_l3_on_disabled?: boolean;
  intent_keywords?: string[];
  dangerous_actions?: string[];
  /** builtin_safe_action_types / builtin_safe_skills 项的值（前缀或精确工具名） */
  value?: string;
}

export interface Skill {
  id: string;
  keywords: string[];
  enabled: boolean;
  builtin: boolean;
}

interface Category {
  category_enabled?: boolean;
  category_desc?: string;
  rules?: Rule[];
  skills?: Skill[];
}

export interface RuntimeConfig {
  version: number;
  layers: { L1_heuristic: boolean; L2_logic_rules: boolean; L3_llm_analysis: boolean };
  L1_rules: Record<string, Category>;
  L2_rules: Record<string, Category>;
  L3_skills: Record<string, Category>;
  /** L2.2 模型检测规则开关（ltl_rules 分区，console 可逐条启停） */
  L2_2?: Record<string, Category>;
  /** agent 定制规则（按 agent_id 分区，每 agent 内按类别组织） */
  agent_rules?: Record<string, Record<string, Category>>;
  /** 场景定制规则（按 scenario_id 分区，如 bank；与 agent_rules 同构） */
  scenario_rules?: Record<string, Record<string, Category>>;
}

// ==================== Path / load / save ====================

export function getRuntimeConfigPath(): string {
  const envPath = process.env[ENV_RUNTIME_CONFIG_PATH];
  if (envPath) return envPath;
  // agent_moss_settings.json fallback omitted in TS (env-only); default path.
  return RUNTIME_CONFIG_PATH;
}

export function saveRuntimeConfig(config: RuntimeConfig): void {
  const p = getRuntimeConfigPath();
  const dir = p.substring(0, p.lastIndexOf('/'));
  if (dir && !existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(p, JSON.stringify(config, null, 2), 'utf-8');
}

/** Minimal default (all layers on, empty rule categories). The full
 * profile-driven seed generator (generate_source_defaults equivalent)
 * is deferred to Stage 4 (console backend); for now a missing runtime
 * file yields this minimal config — coordinator's getDisabledL2RulesWithSkipL3
 * returns {} (safe default, no skip_l3 hard constraint). */
function emptyRuntimeConfig(): RuntimeConfig {
  return {
    version: 1,
    layers: { L1_heuristic: true, L2_logic_rules: true, L3_llm_analysis: true },
    L1_rules: {},
    L2_rules: {},
    L3_skills: {},
    L2_2: {},
    agent_rules: {},
    scenario_rules: {},
  };
}

export function loadRuntimeConfig(): RuntimeConfig {
  const p = getRuntimeConfigPath();
  if (!existsSync(p)) {
    // 首次：seed + save，与 py load_runtime_config 的 fallback seed 对齐。
    // 不 seed 时 getDisabledL2RulesWithSkipL3 返回 {}（无 skip_l3 约束），
    // 但 Console 需要全量规则展示，所以必须 seed。
    const seeded = mergeConfig({}, generateSourceDefaults());
    try { saveRuntimeConfig(seeded); } catch { /* 只读 fs 时忽略 */ }
    return seeded;
  }
  try {
    const data = JSON.parse(readFileSync(p, 'utf-8'));
    const merged = mergeConfig(data, generateSourceDefaults());
    return {
      version: data.version || 1,
      layers: {
        L1_heuristic: data.layers?.L1_heuristic ?? true,
        L2_logic_rules: data.layers?.L2_logic_rules ?? true,
        L3_llm_analysis: data.layers?.L3_llm_analysis ?? true,
      },
      L1_rules: merged.L1_rules || {},
      L2_rules: merged.L2_rules || {},
      L3_skills: merged.L3_skills || {},
      L2_2: merged.L2_2 || {},
      agent_rules: merged.agent_rules || {},
      scenario_rules: merged.scenario_rules || {},
    };
  } catch {
    return emptyRuntimeConfig();
  }
}

// ==================== Layer toggles ====================

/**
 * Is a layer enabled? Priority: env > runtime JSON > default true.
 *
 * Note: the agent_moss_settings.json fallback (used in Python) is not
 * consulted here — env vars are the primary TS-side override. The runtime
 * JSON is authoritative when env is unset.
 */
export function isLayerEnabled(layerKey: string): boolean {
  const disableKey = LAYER_DISABLE_ENV[layerKey];
  if (disableKey && process.env[disableKey] === '1') return false;
  const runtime = loadRuntimeConfig();
  const layers = runtime.layers || {} as RuntimeConfig['layers'];
  if (layerKey in layers) return !!layers[layerKey as keyof typeof layers];
  return true;
}

export function getEnvOverrides(): Record<string, {
  env_var: string; env_value: string; overridden: boolean; effect: string;
}> {
  const overrides: Record<string, any> = {};
  for (const [layerKey, envKey] of Object.entries(LAYER_DISABLE_ENV)) {
    const val = process.env[envKey];
    if (val !== undefined) {
      overrides[layerKey] = {
        env_var: envKey,
        env_value: val,
        overridden: val === '1',
        effect: val === '1' ? 'disabled' : 'no_override',
      };
    }
  }
  return overrides;
}

// ==================== Rule filtering / queries ====================

export function filterEnabledRules(rules: Rule[], categoryEnabled: boolean = true): Rule[] {
  if (!categoryEnabled) return [];
  return rules.filter(r => r.enabled !== false);
}

export function getEnabledL1CommandPatterns(runtime: RuntimeConfig): { pattern: string; risk_level: string; risk_type: string; reason: string }[] {
  const cat = runtime.L1_rules?.dangerous_commands || { category_enabled: true, rules: [] };
  return filterEnabledRules(cat.rules || [], cat.category_enabled).map(r => ({
    pattern: r.pattern || '', risk_level: r.risk_level || '', risk_type: r.risk_type || '', reason: r.reason || '',
  }));
}

export function getEnabledL2SensitivePaths(runtime: RuntimeConfig): { path: string; risk_level: string; desc: string; deny_mode: string; credential?: boolean; read_only?: boolean; dir_del_only?: boolean }[] {
  // 优先读 L1_rules.sensitive_path_access（重分类后归属 L1）；
  // 回退 L2_rules.sensitive_path_access（兼容迁移前老配置）。函数名保留 l2 前缀仅为兼容。
  let cat = runtime.L1_rules?.sensitive_path_access;
  if (!cat || !cat.rules || cat.rules.length === 0) {
    cat = runtime.L2_rules?.sensitive_path_access || { category_enabled: true, rules: [] };
  }
  return filterEnabledRules(cat.rules || [], cat.category_enabled).map(r => {
    const out: any = { path: r.path || '', risk_level: r.risk_level || '', desc: r.desc || '', deny_mode: r.deny_mode || 'deny_write' };
    if (r.credential) out.credential = true;
    if (r.read_only) out.read_only = true;
    if (r.dir_del_only) out.dir_del_only = true; // NEW-FP-1: 目录级条目标记透传（仅删除拦截）
    return out;
  });
}

export function hasRuntimeConfig(): boolean {
  const p = getRuntimeConfigPath();
  if (!existsSync(p)) return false;
  try {
    JSON.parse(readFileSync(p, 'utf-8'));
    return true;
  } catch { return false; }
}

// ==================== skip_l3 hard constraint ====================

/**
 * L2 rules with enabled=false AND skip_l3_on_disabled=true, grouped by
 * category, returning their key content (path / intent_keywords / pattern).
 * Consumed by coordinator to build skip_l3_hints for the L3 prompt.
 */
export function getDisabledL2RulesWithSkipL3(): Record<string, string[]> {
  let runtime: RuntimeConfig;
  try { runtime = loadRuntimeConfig(); }
  catch { return {}; }
  const result: Record<string, string[]> = {};
  // 敏感路径已重分类到 L1，遍历 L1_rules + L2_rules 两层。函数名保留 l2 前缀仅为兼容。
  for (const layerKey of ['L1_rules', 'L2_rules'] as const) {
    const layer = runtime[layerKey] || {};
    for (const [catName, cat] of Object.entries(layer)) {
      if (!cat.category_enabled) continue;
      const items: string[] = [];
      for (const r of cat.rules || []) {
        if (r.enabled === false && r.skip_l3_on_disabled) {
          if (catName === 'sensitive_path_access') {
            if (r.path) items.push(r.path);
          } else if (catName === 'intent_consistency') {
            items.push(...(r.intent_keywords || []));
          } else if (r.pattern) {
            items.push(r.pattern);
          }
        }
      }
      if (items.length > 0) result[catName] = items;
    }
  }
  return result;
}

// ==================== Helpers ====================

function _slugify(text: string): string {
  return text.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '') || 'x';
}

/** FNV-1a 32bit hash → 8 位 hex。与 Python `_fnv1a_32` 同算法（对 ASCII 输入结果一致）。 */
function _fnv1a32(text: string): string {
  let h = 0x811c9dc5;
  for (const b of Buffer.from(text, 'utf-8')) {
    h ^= b;
    h = (h * 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, '0');
}

function _generatePatternId(pattern: string): string {
  // slug 保留可读性，hash8 保证唯一性（旧版只 slug 会因特殊字符抹平成 `_` 而撞 id）。
  return `pat_${_slugify(pattern)}_${_fnv1a32(pattern)}`;
}

/** 从 credential / read_only 推导 deny_mode（向后兼容）。优先用已有 deny_mode。 */
function _deriveDenyMode(rule: Partial<Rule>): string {
  if (rule.deny_mode) return rule.deny_mode;
  if (rule.credential) return 'deny_both';
  if (rule.read_only) return 'deny_read';
  return 'deny_write';
}

/** 根据 deny_mode 同步 credential / read_only（保持底层检测逻辑兼容） */
function _syncDenyModeFields(rule: Rule): void {
  const dm = rule.deny_mode || 'deny_write';
  if (dm === 'deny_both') {
    rule.credential = true;
    delete rule.read_only;
  } else if (dm === 'deny_read') {
    delete rule.credential;
    rule.read_only = true;
  } else {
    delete rule.credential;
    delete rule.read_only;
  }
}

// ==================== Seed (generateSourceDefaults) ====================
//
// py 的 generate_source_defaults 从 OSProfile 拿 dangerous_commands / sensitive_paths
// / intent_deviation_patterns / injection_keywords（运行时按 OS 类型分叉）。
// TS 不分 OS profile（只 win/linux 用于 os_type 字段，不影响规则集），规则集硬编码
// 在 heuristic.ts / logic-rules.ts 常量里。所以 TS seed 直接从常量生成，不走 profile。

function _l1CommandPatternsToRules(): Rule[] {
  // DANGEROUS_PATTERNS 是 RegExp，seed 时存 source 字符串。
  return DANGEROUS_PATTERNS.map((p) => ({
    id: _generatePatternId(p.pattern instanceof RegExp ? p.pattern.source : p.pattern),
    pattern: p.pattern instanceof RegExp ? p.pattern.source : p.pattern,
    risk_level: p.severity,
    risk_type: p.riskType,
    reason: p.description,
    enabled: true,
    builtin: true,
  }));
}

function _l1InjectionKeywordsToRules(): Rule[] {
  return INJECTION_KEYWORDS.map((kw) => ({
    id: `inj_${_slugify(kw.keyword)}`,
    keyword: kw.keyword,
    risk_level: kw.riskLevel,
    lang: kw.lang || 'en',
    enabled: true,
    builtin: true,
  }));
}

function _l2SensitivePathsToRules(): Rule[] {
  const all = [...ROOT_SENSITIVE_PATHS, ...HOME_SENSITIVE_PATHS, ...CREDENTIAL_PATHS] as any[];
  return all.map((sp) => {
    const denyMode = _deriveDenyMode({
      deny_mode: sp.deny_mode,
      credential: sp.credential,
      read_only: sp.read_only,
    });
    const rule: Rule = {
      id: `path_${_slugify(sp.path)}`,
      path: sp.path,
      risk_level: sp.riskLevel,
      desc: sp.desc,
      deny_mode: denyMode,
      source_deny_mode: denyMode,
      skip_l3_on_disabled: true,
      enabled: true,
      builtin: true,
    };
    _syncDenyModeFields(rule);
    // NEW-FP-1: dir_del_only 目录级条目标记透传（用户重存 runtime 时不丢字段）
    if ((sp as any).dirDelOnly) rule.dir_del_only = true;
    return rule;
  });
}

function _l2IntentPatternsToRules(): Rule[] {
  return INTENT_DEVIATION_PATTERNS.map((pat, i) => ({
    id: `intent_${i + 1}_${_slugify(pat.reason.slice(0, 30))}`,
    intent_keywords: pat.intentKeywords,
    dangerous_actions: pat.dangerousActions,
    reason: pat.reason,
    skip_l3_on_disabled: true,
    enabled: true,
    builtin: true,
  }));
}

function _l2PasswordPatternsToRules(): Rule[] {
  return PASSWORD_MODIFY_PATTERNS.map((p) => ({
    id: `pw_${_slugify(p.source)}`,
    pattern: p.source,
    skip_l3_on_disabled: true,
    enabled: true,
    builtin: true,
  }));
}

function _l2UserDeletionPatternsToRules(): Rule[] {
  return USER_DELETION_PATTERNS.map((p) => ({
    id: `ud_${_slugify(p.source)}`,
    pattern: p.source,
    skip_l3_on_disabled: true,
    enabled: true,
    builtin: true,
  }));
}

function _l3SkillsToRules(): Record<string, Category> {
  const skillCategories: Record<string, string[]> = {
    file_operations: ['file_access_guard', 'script_execution_guard', 'indirect_access_guard'],
    network_security: ['data_exfiltration_guard', 'browser_web_access_guard',
      'lateral_movement_guard', 'email_operation_guard'],
    persistence_supply_chain: ['persistence_backdoor_guard', 'supply_chain_guard',
      'skill_installation_guard'],
    intent_and_general: ['intent_deviation_guard', 'general_tool_risk_guard'],
    resource: ['resource_exhaustion_guard'],
  };
  const out: Record<string, Category> = {};
  for (const [cat, ids] of Object.entries(skillCategories)) {
    out[cat] = {
      category_enabled: true,
      category_desc: '',
      skills: ids.map((s: string) => ({
        id: s,
        keywords: SKILL_KEYWORD_MAP[s] || [],
        enabled: true,
        builtin: true,
      })),
    };
  }
  const categorized = new Set<string>(Object.values(skillCategories).flat());
  for (const s of Object.keys(SKILL_KEYWORD_MAP)) {
    if (!categorized.has(s)) {
      (out.intent_and_general ??= { category_enabled: true, category_desc: '', skills: [] })
        .skills!.push({
          id: s, keywords: SKILL_KEYWORD_MAP[s], enabled: true, builtin: true,
        });
    }
  }
  out.user_custom = { category_enabled: true, category_desc: '', skills: [] };
  return out;
}

/** 扫描 agent_moss/agents/<id>/rules.json，转为 agent_rules 分区结构（出厂种子）。
 * 每个 agent 的 rules.json 字段 → agent_rules[<id>] 的 Category 结构（与 L1/L2 同形）。
 * builtin_safe_action_types / builtin_safe_skills 原为 string[]，转成 [{value, enabled, builtin}]。
 * 路径内联解析（不 import agents/index.ts 避免 ESM 循环依赖），与 agents/index.ts resolveAgentsDir 同策略。 */
const _AGENTS_DIR_PROD = join(__dirname, 'agents');
const _AGENTS_DIR_DEV = join(__dirname, '..', '..', '..', 'agent_moss', 'agents');

/** 扫描 agent_moss/scenarios/<id>/rules.json，转为 scenario_rules 分区结构（出厂种子）。
 * 与 _agentRulesToDefaults 同构（场景规则也是 AgentExtensions 结构），唯一区别：
 * 目录是 scenarios/ 而非 agents/。场景不含 builtin_safe_action_types/builtin_safe_skills
 * （场景是部署级约束，不定义 agent 白名单），仍保留这两个类别占位（空 rules），
 * 与 agent 分区结构对齐，console 渲染共用一套模板。 */
const _SCENARIOS_DIR_PROD = join(__dirname, 'scenarios');
const _SCENARIOS_DIR_DEV = join(__dirname, '..', '..', '..', 'agent_moss', 'scenarios');
function _scenarioRulesToDefaults(): Record<string, Record<string, Category>> {
  const out: Record<string, Record<string, Category>> = {};
  const scenDir = existsSync(_SCENARIOS_DIR_PROD) ? _SCENARIOS_DIR_PROD
    : existsSync(_SCENARIOS_DIR_DEV) ? _SCENARIOS_DIR_DEV : _SCENARIOS_DIR_PROD;
  if (!existsSync(scenDir)) return out;
  let entries: string[];
  try {
    entries = readdirSync(scenDir, { withFileTypes: true })
      .filter(d => d.isDirectory()).map(d => d.name);
  } catch {
    return out;
  }
  for (const scenarioId of entries) {
    const rulesFile = join(scenDir, scenarioId, 'rules.json');
    if (!existsSync(rulesFile)) continue;
    let data: any;
    try { data = JSON.parse(readFileSync(rulesFile, 'utf-8')); } catch { continue; }
    out[scenarioId] = {
      builtin_safe_action_types: {
        category_enabled: true,
        category_desc: '场景完全安全操作白名单（场景通常不使用）',
        rules: [],
      },
      builtin_safe_skills: {
        category_enabled: true,
        category_desc: '场景信任的内置 Skill（场景通常不使用）',
        rules: [],
      },
      extra_command_patterns: {
        category_enabled: true,
        category_desc: '场景专属危险命令正则（L1 末尾追加）',
        rules: (data.extra_command_patterns || []).map((p: any) =>
          ({ ...p, enabled: true, builtin: true })),
      },
      extra_injection_keywords: {
        category_enabled: true,
        category_desc: '场景专属注入关键词（L1 末尾追加）',
        rules: (data.extra_injection_keywords || []).map((k: any) =>
          ({ ...k, enabled: true, builtin: true })),
      },
      extra_sensitive_paths: {
        category_enabled: true,
        category_desc: '场景专属敏感路径（L1 末尾追加）',
        rules: (data.extra_sensitive_paths || []).map((sp: any) =>
          ({ ...sp, enabled: true, builtin: true })),
      },
    };
  }
  return out;
}

function _agentRulesToDefaults(): Record<string, Record<string, Category>> {
  const out: Record<string, Record<string, Category>> = {};
  const agentsDir = existsSync(_AGENTS_DIR_PROD) ? _AGENTS_DIR_PROD
    : existsSync(_AGENTS_DIR_DEV) ? _AGENTS_DIR_DEV : _AGENTS_DIR_PROD;
  if (!existsSync(agentsDir)) return out;
  let entries: string[];
  try {
    entries = readdirSync(agentsDir, { withFileTypes: true })
      .filter(d => d.isDirectory()).map(d => d.name);
  } catch {
    return out;
  }
  for (const agentId of entries) {
    const rulesFile = join(agentsDir, agentId, 'rules.json');
    if (!existsSync(rulesFile)) continue;
    let data: any;
    try { data = JSON.parse(readFileSync(rulesFile, 'utf-8')); } catch { continue; }
    out[agentId] = {
      builtin_safe_action_types: {
        category_enabled: true,
        category_desc: 'agent 完全安全操作白名单（前缀尾随 - 或精确名，命中跳 L2+L3）',
        rules: (data.builtin_safe_action_types || []).map((v: string) =>
          ({ value: v, enabled: true, builtin: true })),
      },
      builtin_safe_skills: {
        category_enabled: true,
        category_desc: 'agent 信任的内置 Skill（命中跳 L2+L3）',
        rules: (data.builtin_safe_skills || []).map((v: string) =>
          ({ value: v, enabled: true, builtin: true })),
      },
      extra_command_patterns: {
        category_enabled: true,
        category_desc: 'agent 专属危险命令正则（L1 末尾追加）',
        rules: (data.extra_command_patterns || []).map((p: any) =>
          ({ ...p, enabled: true, builtin: true })),
      },
      extra_injection_keywords: {
        category_enabled: true,
        category_desc: 'agent 专属注入关键词（L1 末尾追加）',
        rules: (data.extra_injection_keywords || []).map((k: any) =>
          ({ ...k, enabled: true, builtin: true })),
      },
      extra_sensitive_paths: {
        category_enabled: true,
        category_desc: 'agent 专属敏感路径（L1 末尾追加）',
        rules: (data.extra_sensitive_paths || []).map((sp: any) =>
          ({ ...sp, enabled: true, builtin: true })),
      },
    };
  }
  return out;
}

/** 从 TS 常量生成 runtime 默认结构（出厂种子）。TS 不走 profile，直接从常量。 */
export function generateSourceDefaults(): RuntimeConfig {
  return {
    version: 1,
    layers: { ...DEFAULT_LAYERS },
    L1_rules: {
      dangerous_commands: {
        category_enabled: true,
        category_desc: '危险命令检测（递归删除、全权限设置、提权执行等）',
        rules: _l1CommandPatternsToRules(),
      },
      injection_detection: {
        category_enabled: true,
        category_desc: 'Prompt 注入攻击检测',
        rules: _l1InjectionKeywordsToRules(),
      },
      sensitive_path_access: {
        category_enabled: true,
        category_desc: '敏感路径访问检测（deny_both/deny_read/deny_write）',
        rules: _l2SensitivePathsToRules(),
      },
      user_custom: { category_enabled: true, category_desc: '用户自定义命令规则', rules: [] },
    },
    L2_rules: {
      intent_consistency: {
        category_enabled: true,
        category_desc: '意图一致性检测',
        rules: _l2IntentPatternsToRules(),
      },
      password_modify_consent: {
        category_enabled: true,
        category_desc: '非交互式密码修改授权检测',
        rules: _l2PasswordPatternsToRules(),
      },
      user_deletion_consent: {
        category_enabled: true,
        category_desc: '用户/组删除操作授权检测',
        rules: _l2UserDeletionPatternsToRules(),
      },
      read_before_write: { category_enabled: true, category_desc: 'read_before_write 安全原则检测', rules: [] },
      user_custom: { category_enabled: true, category_desc: '用户自定义 L2 逻辑规则', rules: [] },
    },
    L3_skills: _l3SkillsToRules(),
    L2_2: _ltlRulesToRuntime(),
    agent_rules: _agentRulesToDefaults(),
    scenario_rules: _scenarioRulesToDefaults(),
  };
}

/** mc_rules.json 的 LTL 规则 → L2_2 分区（每条 enabled 默认开）。
 * 必须直接读文件（不经 loadMC）——loadMC 内部反向依赖 loadRuntimeConfig，
 * 调用会产生循环。与 Python _ltl_rules_to_runtime 对齐。 */
function _ltlRulesToRuntime(): Record<string, Category> {
  // 候选路径与 rules-loader 的 RULES_DIR_CANDS 对齐：dist bundle 里 __dirname=dist/
  // 或 dist/engine/，只有覆盖这些形态才能读对 mc_rules.json（否则 src 规则空 →
  // merge 把 user 侧 LTL 全标 source_removed，导致 console「只能启用 1 条」）。
  const cands = [
    getRuntimeConfigDir() && join(getRuntimeConfigDir(), 'rules'),
    join(__dirname, '../rules'),
    join(__dirname, 'rules'),
    join(__dirname, '../../../agent_moss/rules'),
    join(__dirname, '../../../../agent_moss/rules'),
    join(process.cwd(), 'agent_moss/rules'),
  ].filter(Boolean) as string[];
  let mc: any = {};
  for (const dir of cands) {
    const p = join(dir, 'mc_rules.json');
    if (existsSync(p)) {
      try { mc = JSON.parse(readFileSync(p, 'utf-8')) || {}; } catch { mc = {}; }
      break;
    }
  }
  const rules: any[] = mc.rules || [];
  return {
    ltl_rules: {
      category_enabled: true,
      category_desc: 'LTL 攻击模式规则（时序攻击检测，先 A 后 B）',
      rules: rules.map((r: any) => ({
        id: r.id, reason: r.reason || '', risk_level: r.risk_level || 'high',
        action: r.action || 'block', enabled: true, builtin: true,
      })),
    },
  };
}

// ==================== Merge (preserve user toggles) ====================

/** 规则内容指纹（跨 id 变更识别同一规则）。 */
/**
 * 正则 pattern 规范化，用于计算规则指纹。
 *
 * Python 与 TS 生成规则时对 `/` 的转义不一致：TS 用 RegExp.source（`/` 转义为 `\/`），
 * Python 直接存 `/`。这导致同一规则在两端生成 pattern 字符串不同 → 指纹不同 →
 * 双端 merge 时互相把对方标记 source_removed 而禁用（L1 启用数不一致）。
 *
 * 这里把 `\/` 规范化为 `/`，使两端 pattern 指纹一致。只处理 `/` 转义，不动其他正则转义。
 */
function normalizePatternForFingerprint(pattern: string): string {
  return pattern.replace(/\\\//g, '/');
}

function _ruleFingerprint(rule: Partial<Rule>): string {
  if ((rule.intent_keywords && rule.intent_keywords.length) || (rule.dangerous_actions && rule.dangerous_actions.length)) {
    return JSON.stringify([
      [...(rule.intent_keywords || [])].sort(),
      [...(rule.dangerous_actions || [])].sort(),
    ]);
  }
  if (rule.path) return JSON.stringify([normalizePatternForFingerprint(rule.path)]);
  if (rule.pattern) return JSON.stringify([normalizePatternForFingerprint(rule.pattern)]);
  if (rule.keyword) return JSON.stringify([rule.keyword, rule.lang || '']);
  // builtin_safe_action_types / builtin_safe_skills 项用 value 字段
  if (rule.value) return JSON.stringify([rule.value]);
  return JSON.stringify([rule.id || '']);
}

/** 合并 L1/L2 分类与规则（保留用户 enabled/skip_l3/deny_mode，补入新 builtin，标记删除）。 */
function _mergeRuleCategories(userCfg: RuntimeConfig, srcDefaults: RuntimeConfig, layerKey: 'L1_rules' | 'L2_rules' | 'L2_2'): void {
  const userLayer = (userCfg[layerKey] || (userCfg[layerKey] = {})) as Record<string, Category>;
  const srcLayer = srcDefaults[layerKey] || {};
  for (const [catName, srcCat] of Object.entries(srcLayer)) {
    if (!(catName in userLayer)) {
      userLayer[catName] = srcCat;
      continue;
    }
    const userCat: Category = userLayer[catName];
    if (userCat.category_desc === undefined) userCat.category_desc = srcCat.category_desc || '';
    if (userCat.category_enabled === undefined) userCat.category_enabled = srcCat.category_enabled ?? true;
    const srcRules = srcCat.rules || [];
    const userRules = (userCat.rules || (userCat.rules = []));
    const userByFp = new Map<string, Rule>();
    for (const r of userRules) userByFp.set(_ruleFingerprint(r), r);
    const srcFps = new Set<string>();
    for (const srcR of srcRules) {
      const fp = _ruleFingerprint(srcR);
      srcFps.add(fp);
      if (userByFp.has(fp)) {
        const existing = userByFp.get(fp)!;
        const userEnabled = existing.enabled;
        const userSkipL3 = existing.skip_l3_on_disabled;
        const userDenyMode = existing.deny_mode;
        const userSourceDeny = existing.source_deny_mode;
        Object.keys(existing).forEach(k => delete (existing as any)[k]);
        Object.assign(existing, srcR);
        existing.enabled = userEnabled;
        if (userSkipL3 !== undefined) existing.skip_l3_on_disabled = userSkipL3;
        if (userDenyMode && userSourceDeny && userDenyMode !== userSourceDeny) {
          existing.deny_mode = userDenyMode;
        }
        if (existing.deny_mode) _syncDenyModeFields(existing);
      } else {
        const newR: Rule = { ...srcR, enabled: true };
        userRules.push(newR);
      }
    }
    for (const r of userRules) {
      // builtin 且指纹不在 src 集合 → 源码已删除该规则
      if (r.builtin && !srcFps.has(_ruleFingerprint(r))) {
        r.source_removed = true;
        r.enabled = false;
      }
    }
    if (catName === 'sensitive_path_access') {
      for (const r of userRules) {
        if (!r.deny_mode) r.deny_mode = _deriveDenyMode(r);
        _syncDenyModeFields(r);
      }
    }
  }
  // 清理源码已移除的类目：保留 user_custom（用户自定义壳），删除其余不在 src 的类目
  // （如本次重构删除的 dangerous_patterns / lateral_movement，老配置落盘仍残留）。
  for (const catName of Object.keys(userLayer)) {
    if (catName === 'user_custom') continue;
    if (!(catName in srcLayer)) delete userLayer[catName];
  }
}

/** 合并 L3_skills 分类。新分类整体加入；已有分类补全元字段 + 追加新 builtin skill。 */
function _mergeSkillCategories(userCfg: RuntimeConfig, srcDefaults: RuntimeConfig, layerKey: 'L3_skills'): void {
  const userLayer = (userCfg[layerKey] || (userCfg[layerKey] = {})) as Record<string, Category>;
  const srcLayer = srcDefaults[layerKey] || {};
  for (const [catName, srcCat] of Object.entries(srcLayer)) {
    if (!(catName in userLayer)) {
      userLayer[catName] = srcCat;
      continue;
    }
    const userCat: Category = userLayer[catName];
    if (userCat.category_desc === undefined) userCat.category_desc = srcCat.category_desc || '';
    if (userCat.category_enabled === undefined) userCat.category_enabled = srcCat.category_enabled ?? true;
    const userSkills = (userCat.skills || (userCat.skills = []));
    const existingIds = new Set(userSkills.map(s => s.id));
    for (const srcS of (srcCat.skills || [])) {
      if (!existingIds.has(srcS.id)) userSkills.push({ ...srcS });
    }
  }
}

/** 合并 agent_rules 分区（按 agent_id 分区，每个 agent 内复用类别合并逻辑）。
 * 新出厂 agent → 整体加入；已有 agent → 每类别走 _mergeRuleCategories 同套
 * （指纹去重 + 保留 enabled + 新 builtin 追加 + 删除标记 source_removed）。 */
function _mergeAgentRules(userCfg: RuntimeConfig, srcDefaults: RuntimeConfig, partition: 'agent_rules' | 'scenario_rules' = 'agent_rules'): void {
  const userAgent = (userCfg[partition] || (userCfg[partition] = {})) as Record<string, Record<string, Category>>;
  const srcAgent = srcDefaults[partition] || {};
  for (const [agentId, srcCats] of Object.entries(srcAgent)) {
    if (!(agentId in userAgent)) {
      userAgent[agentId] = JSON.parse(JSON.stringify(srcCats));
      continue;
    }
    const userCats = userAgent[agentId];
    for (const [catName, srcCat] of Object.entries(srcCats)) {
      if (!(catName in userCats)) {
        userCats[catName] = JSON.parse(JSON.stringify(srcCat));
        continue;
      }
      const userCat: Category = userCats[catName];
      if (userCat.category_desc === undefined) userCat.category_desc = srcCat.category_desc || '';
      if (userCat.category_enabled === undefined) userCat.category_enabled = srcCat.category_enabled ?? true;
      const srcRules = srcCat.rules || [];
      const userRules = (userCat.rules || (userCat.rules = []));
      const userByFp = new Map<string, Rule>();
      for (const r of userRules) userByFp.set(_ruleFingerprint(r), r);
      const srcFps = new Set<string>();
      for (const srcR of srcRules) {
        const fp = _ruleFingerprint(srcR);
        srcFps.add(fp);
        if (userByFp.has(fp)) {
          const existing = userByFp.get(fp)!;
          const userEnabled = existing.enabled;
          Object.keys(existing).forEach(k => delete (existing as any)[k]);
          Object.assign(existing, srcR);
          existing.enabled = userEnabled;
        } else {
          userRules.push({ ...srcR, enabled: true });
        }
      }
      for (const r of userRules) {
        if (r.builtin && !srcFps.has(_ruleFingerprint(r))) {
          r.source_removed = true;
          r.enabled = false;
        }
      }
    }
  }
}

/** 合并用户配置与源码默认值。保留用户开关；新增 builtin 补入；源码删除的标记。 */
export function mergeConfig(userCfg: Partial<RuntimeConfig>, srcDefaults: RuntimeConfig): RuntimeConfig {
  const cfg = userCfg as RuntimeConfig;
  if (cfg.version === undefined) cfg.version = srcDefaults.version || 1;
  if (!cfg.layers) cfg.layers = {} as RuntimeConfig['layers'];
  for (const [layerKey, defaultVal] of Object.entries(srcDefaults.layers)) {
    if (!(layerKey in cfg.layers)) (cfg.layers as any)[layerKey] = defaultVal;
  }
  // 跨层迁移：敏感路径已从 L2 重分类到 L1。老配置 sensitive_path_access 还在
  // L2_rules 下，搬到 L1_rules（保留用户 enabled/deny_mode/自定义项），L2 删除该分类。
  // 注：dangerous_patterns / lateral_movement 检测是硬编码子检测器，不读 runtime
  // config rules，故老配置 L2 里这两类的 rules 不迁移（默认种子已删除该类目）。
  _migrateCategoriesAcrossLayers(cfg, 'L2_rules', 'L1_rules',
    ['sensitive_path_access']);
  _mergeRuleCategories(cfg, srcDefaults, 'L1_rules');
  _mergeRuleCategories(cfg, srcDefaults, 'L2_rules');
  // 跨版本迁移：形式化引擎层号 L2.4 已统一重命名 L2.2。旧配置键 L2_4 迁移到
  // L2_2（保留用户 enabled/自定义规则），与 Python merge_config 一致。
  if (!cfg.L2_2 && (cfg as any).L2_4) {
    (cfg as any).L2_2 = (cfg as any).L2_4;
    delete (cfg as any).L2_4;
  }
  _mergeRuleCategories(cfg, srcDefaults, 'L2_2');
  _mergeSkillCategories(cfg, srcDefaults, 'L3_skills');
  _mergeAgentRules(cfg, srcDefaults);
  _mergeAgentRules(cfg, srcDefaults, 'scenario_rules');
  return cfg;
}

/** 把指定分类从 srcLayer 搬到 dstLayer（保留分类内全部内容，按指纹去重合并）。 */
function _migrateCategoriesAcrossLayers(cfg: RuntimeConfig, srcLayer: 'L1_rules' | 'L2_rules', dstLayer: 'L1_rules' | 'L2_rules', catNames: string[]): void {
  const src = (cfg as any)[srcLayer] || {};
  const dst: any = cfg[dstLayer] || (cfg[dstLayer] = {} as RuntimeConfig['L1_rules']);
  for (const catName of catNames) {
    if (!(catName in src)) continue;
    const srcCat = src[catName];
    if (!dst[catName]) {
      dst[catName] = { category_enabled: true, category_desc: '', rules: [] };
    }
    const dstCat = dst[catName];
    if (!dstCat.category_desc && srcCat.category_desc) dstCat.category_desc = srcCat.category_desc;
    if (dstCat.category_enabled === undefined) dstCat.category_enabled = srcCat.category_enabled;
    // 合并 rules：dst 已有的按指纹保留，src 独有的追加
    if (srcCat.rules && srcCat.rules.length > 0) {
      const dstFps = new Set((dstCat.rules || []).map((r: any) => _ruleFingerprint(r)));
      for (const r of srcCat.rules) {
        const fp = _ruleFingerprint(r);
        if (!dstFps.has(fp)) {
          (dstCat.rules = dstCat.rules || []).push(r);
          dstFps.add(fp);
        }
      }
    }
    delete src[catName];
  }
}

// ==================== Query 补齐 ====================

export function getEnabledL1InjectionKeywords(runtime: RuntimeConfig): { keyword: string; risk_level: string; lang: string }[] {
  const cat = runtime.L1_rules?.injection_detection || { category_enabled: true, rules: [] };
  return filterEnabledRules(cat.rules || [], cat.category_enabled).map(r => ({
    keyword: r.keyword || '', risk_level: r.risk_level || '', lang: r.lang || 'en',
  }));
}

export function getEnabledL2IntentPatterns(runtime: RuntimeConfig): { intent_keywords: string[]; dangerous_actions: string[]; reason: string }[] {
  const cat = runtime.L2_rules?.intent_consistency || { category_enabled: true, rules: [] };
  return filterEnabledRules(cat.rules || [], cat.category_enabled).map(r => ({
    intent_keywords: r.intent_keywords || [], dangerous_actions: r.dangerous_actions || [], reason: r.reason || '',
  }));
}

export function getEnabledL2PasswordPatterns(runtime: RuntimeConfig): string[] {
  const cat = runtime.L2_rules?.password_modify_consent || { category_enabled: true, rules: [] };
  return filterEnabledRules(cat.rules || [], cat.category_enabled).map(r => r.pattern || '');
}

export function getEnabledL2UserDeletionPatterns(runtime: RuntimeConfig): string[] {
  const cat = runtime.L2_rules?.user_deletion_consent || { category_enabled: true, rules: [] };
  return filterEnabledRules(cat.rules || [], cat.category_enabled).map(r => r.pattern || '');
}

export function isL2CategoryEnabled(runtime: RuntimeConfig, categoryKey: string): boolean {
  const cat = runtime.L2_rules?.[categoryKey as keyof typeof runtime.L2_rules] as Category | undefined;
  return cat?.category_enabled ?? true;
}

/** 所有被禁用的 skill id（整分类禁用→该分类所有 skill，或单条 enabled=false） */
export function getDisabledSkillIds(runtime: RuntimeConfig): Set<string> {
  const disabled = new Set<string>();
  for (const catData of Object.values(runtime.L3_skills || {})) {
    if (!catData.category_enabled) {
      for (const s of (catData.skills || [])) disabled.add(s.id);
    } else {
      for (const s of (catData.skills || [])) {
        if (s.enabled === false) disabled.add(s.id);
      }
    }
  }
  return disabled;
}

// ==================== _or_default 回退系列 ====================
// runtime 规则非空→用 runtime；为空且文件不存在→回退 source defaults；
// 为空但文件存在（用户主动禁用）→返回空。与 py 语义对齐。

export function getEnabledL1CommandPatternsOrDefault(runtime: RuntimeConfig): Rule[] {
  const enabled = getEnabledL1CommandPatterns(runtime) as unknown as Rule[];
  if (enabled.length) return enabled;
  if (!hasRuntimeConfig()) return _l1CommandPatternsToRules();
  return [];
}
export function getEnabledL1InjectionKeywordsOrDefault(runtime: RuntimeConfig): Rule[] {
  const enabled = getEnabledL1InjectionKeywords(runtime) as unknown as Rule[];
  if (enabled.length) return enabled;
  if (!hasRuntimeConfig()) return _l1InjectionKeywordsToRules();
  return [];
}
export function getEnabledL2SensitivePathsOrDefault(runtime: RuntimeConfig): Rule[] {
  const enabled = getEnabledL2SensitivePaths(runtime) as unknown as Rule[];
  if (enabled.length) return enabled;
  if (!hasRuntimeConfig()) return _l2SensitivePathsToRules();
  return [];
}
export function getEnabledL2IntentPatternsOrDefault(runtime: RuntimeConfig): Rule[] {
  const enabled = getEnabledL2IntentPatterns(runtime) as unknown as Rule[];
  if (enabled.length) return enabled;
  if (!hasRuntimeConfig()) return _l2IntentPatternsToRules();
  return [];
}
export function getEnabledL2PasswordPatternsOrDefault(runtime: RuntimeConfig): string[] {
  const enabled = getEnabledL2PasswordPatterns(runtime);
  if (enabled.length) return enabled;
  if (!hasRuntimeConfig()) {
    return PASSWORD_MODIFY_PATTERNS.map((p) => p.source);
  }
  return [];
}
export function getEnabledL2UserDeletionPatternsOrDefault(runtime: RuntimeConfig): string[] {
  const enabled = getEnabledL2UserDeletionPatterns(runtime);
  if (enabled.length) return enabled;
  if (!hasRuntimeConfig()) {
    return USER_DELETION_PATTERNS.map((p) => p.source);
  }
  return [];
}

// ==================== CRUD / update ====================

const SKILL_ID_RE = /^[A-Za-z0-9_-]+$/;
function _validateSkillId(skillId: string): void {
  if (!skillId || !SKILL_ID_RE.test(skillId)) {
    throw new Error(`skill_id '${skillId}' 不合法：只允许字母、数字、下划线和连字符`);
  }
}

export function updateLayerEnabled(layerKey: string, enabled: boolean): RuntimeConfig {
  const runtime = loadRuntimeConfig();
  (runtime.layers as any)[layerKey] = enabled;
  saveRuntimeConfig(runtime);
  return runtime;
}

export function updateRuleEnabled(layer: 'L1_rules' | 'L2_rules', category: string, ruleId: string, enabled: boolean): RuntimeConfig {
  const runtime = loadRuntimeConfig();
  for (const r of (runtime[layer]?.[category]?.rules || [])) {
    if (r.id === ruleId) { r.enabled = enabled; break; }
  }
  saveRuntimeConfig(runtime);
  return runtime;
}

export function updateRuleDenyMode(layer: 'L1_rules' | 'L2_rules', category: string, ruleId: string, denyMode: string): RuntimeConfig {
  const runtime = loadRuntimeConfig();
  for (const r of (runtime[layer]?.[category]?.rules || [])) {
    if (r.id === ruleId) { r.deny_mode = denyMode; _syncDenyModeFields(r); break; }
  }
  saveRuntimeConfig(runtime);
  return runtime;
}

export function updateRuleSkipL3(layer: 'L1_rules' | 'L2_rules', category: string, ruleId: string, skipL3: boolean): RuntimeConfig {
  const runtime = loadRuntimeConfig();
  for (const r of (runtime[layer]?.[category]?.rules || [])) {
    if (r.id === ruleId) { r.skip_l3_on_disabled = skipL3; break; }
  }
  saveRuntimeConfig(runtime);
  return runtime;
}

export function updateCategoryEnabled(layer: 'L1_rules' | 'L2_rules' | 'L2_2', category: string, enabled: boolean): RuntimeConfig {
  const runtime = loadRuntimeConfig();
  const cat = runtime[layer]?.[category];
  if (cat) cat.category_enabled = enabled;
  saveRuntimeConfig(runtime);
  return runtime;
}

export function addCustomRule(layer: 'L1_rules' | 'L2_rules', category: string, rule: Partial<Rule>): RuntimeConfig {
  const runtime = loadRuntimeConfig();
  const layerObj = runtime[layer] || (runtime[layer] = {} as Record<string, Category>);
  const cat = layerObj[category] || (layerObj[category] = { category_enabled: true, category_desc: '', rules: [] });
  const rules = cat.rules || (cat.rules = []);
  const newRule: Rule = { ...rule, builtin: false, enabled: true } as Rule;
  if (!newRule.id) {
    newRule.id = `custom_${Date.now()}_${_slugify(JSON.stringify(rule).slice(0, 30))}`;
  }
  if (newRule.deny_mode) _syncDenyModeFields(newRule);
  rules.push(newRule);
  saveRuntimeConfig(runtime);
  return runtime;
}

/** 从 rules 里选一条「可删」规则并就地移除；返回 null 表示拒绝（命中但无可删项）。 */
export function pickDeletableRule(rules: Rule[], ruleId: string): Rule[] | null {
  // 可删 = builtin=false（用户自定义）或 source_removed=true（源码已删除的历史保留）。
  // 同 id 多命中（历史撞车）时优先删可删项；仅当命中的全是活跃 builtin 才拒绝。
  const idx = rules.findIndex(r => r.id === ruleId && (!r.builtin || r.source_removed));
  if (idx >= 0) {
    rules.splice(idx, 1);
    return rules;
  }
  if (rules.some(r => r.id === ruleId)) return null; // 命中了活跃 builtin → 拒绝
  return rules; // 未命中，无操作
}

export function deleteCustomRule(layer: 'L1_rules' | 'L2_rules', category: string, ruleId: string): RuntimeConfig | null {
  // 允许删：用户自定义（builtin=false）+ 已移除的（builtin=true 但 source_removed=true）。
  // 活跃 builtin 规则不允许删（用 enabled 开关）。
  const runtime = loadRuntimeConfig();
  const rules = runtime[layer]?.[category]?.rules || [];
  if (pickDeletableRule(rules, ruleId) === null) return null;
  saveRuntimeConfig(runtime);
  return runtime;
}

export function addCustomSkill(skillId: string, category: string, keywords: string[], content: string): RuntimeConfig {
  _validateSkillId(skillId);
  const runtime = loadRuntimeConfig();
  const skillsDir = join(RUNTIME_CONFIG_DIR, 'agent_moss_skills');
  try { mkdirSync(skillsDir, { recursive: true }); } catch { /* 已存在 */ }
  writeFileSync(join(skillsDir, `${skillId}.md`), content, 'utf-8');
  const l3 = runtime.L3_skills || (runtime.L3_skills = {});
  const cat = l3[category] || (l3[category] = { category_enabled: true, category_desc: '', skills: [] });
  (cat.skills || (cat.skills = [])).push({ id: skillId, keywords, enabled: true, builtin: false });
  saveRuntimeConfig(runtime);
  return runtime;
}

export function deleteCustomSkill(skillId: string, category: string): RuntimeConfig | null {
  _validateSkillId(skillId);
  const runtime = loadRuntimeConfig();
  const skills = runtime.L3_skills?.[category]?.skills || [];
  const idx = skills.findIndex(s => s.id === skillId);
  if (idx >= 0) {
    if (skills[idx].builtin) return null;
    skills.splice(idx, 1);
    const skillPath = join(RUNTIME_CONFIG_DIR, 'agent_moss_skills', `${skillId}.md`);
    try { if (existsSync(skillPath)) unlinkSync(skillPath); } catch { /* ignore */ }
    saveRuntimeConfig(runtime);
  }
  return runtime;
}

export function updateSkillEnabled(skillId: string, enabled: boolean): RuntimeConfig {
  const runtime = loadRuntimeConfig();
  for (const catData of Object.values(runtime.L3_skills || {})) {
    for (const s of (catData.skills || [])) {
      if (s.id === skillId) { s.enabled = enabled; break; }
    }
  }
  saveRuntimeConfig(runtime);
  return runtime;
}

export function updateSkillCategoryEnabled(category: string, enabled: boolean): RuntimeConfig {
  const runtime = loadRuntimeConfig();
  const cat = runtime.L3_skills?.[category];
  if (cat) cat.category_enabled = enabled;
  saveRuntimeConfig(runtime);
  return runtime;
}

export function getProfileOrDetect(): null {
  // TS 不走 OSProfile（规则集硬编码常量），此函数仅为 py API 对齐保留，返回 null。
  return null;
}

// ==================== agent 定制规则（runtime_config 统一治理）====================

export function getAgentRules(runtime: RuntimeConfig): Record<string, Record<string, Category>> {
  return runtime.agent_rules || {};
}

function _agentCategoryEnabledRules(cat: Category | undefined): Rule[] {
  if (!cat || cat.category_enabled === false) return [];
  return (cat.rules || []).filter(r => r.enabled !== false);
}

/** 从 runtime_config 的 agent_rules[agent_id] 构造 AgentExtensions（应用 enabled 过滤）。
 * 供 getAgentExtensions 在 hasRuntimeConfig() 时调用。无该 agent 分区返回 null。 */
export function getEnabledAgentExtensions(runtime: RuntimeConfig, agentId: string): AgentExtensions | null {
  const agentData = runtime.agent_rules?.[agentId];
  if (!agentData) return null;
  const safeAction = _agentCategoryEnabledRules(agentData.builtin_safe_action_types);
  const safeSkills = _agentCategoryEnabledRules(agentData.builtin_safe_skills);
  const cmdPatterns = _agentCategoryEnabledRules(agentData.extra_command_patterns)
    .filter(r => r.pattern).map(r => ({
      pattern: r.pattern!, risk_level: r.risk_level || '',
      risk_type: r.risk_type || '', reason: r.reason || '',
    }));
  const injKeywords = _agentCategoryEnabledRules(agentData.extra_injection_keywords)
    .filter(r => r.keyword).map(r => ({
      keyword: r.keyword!, risk_level: r.risk_level || '', lang: r.lang || 'en',
    }));
  const sensitivePaths = _agentCategoryEnabledRules(agentData.extra_sensitive_paths)
    .filter(r => r.path).map(r => ({
      path: r.path!, risk_level: r.risk_level || '', desc: r.desc || '',
      credential: r.credential, read_only: r.read_only, deny_mode: r.deny_mode,
    }));
  return {
    agent_id: agentId,
    description: '',
    extra_command_patterns: cmdPatterns,
    extra_injection_keywords: injKeywords,
    extra_sensitive_paths: sensitivePaths,
    builtin_safe_skills: safeSkills.filter(r => r.value).map(r => r.value!),
    builtin_safe_action_types: safeAction.filter(r => r.value).map(r => r.value!),
    extra_skills: [],
  };
}

export function updateAgentRuleEnabled(agentId: string, category: string, ruleFp: Partial<Rule>, enabled: boolean): RuntimeConfig {
  const runtime = loadRuntimeConfig();
  const cat = runtime.agent_rules?.[agentId]?.[category];
  if (cat) {
    const targetFp = _ruleFingerprint(ruleFp);
    for (const r of (cat.rules || [])) {
      if (_ruleFingerprint(r) === targetFp) { r.enabled = enabled; break; }
    }
  }
  saveRuntimeConfig(runtime);
  return runtime;
}

export function addAgentRule(agentId: string, category: string, rule: Record<string, unknown>): RuntimeConfig {
  const runtime = loadRuntimeConfig();
  if (!runtime.agent_rules) runtime.agent_rules = {};
  if (!runtime.agent_rules[agentId]) runtime.agent_rules[agentId] = {};
  const cats = runtime.agent_rules[agentId];
  if (!cats[category]) cats[category] = { category_enabled: true, category_desc: '', rules: [] };
  (cats[category].rules || (cats[category].rules = [])).push({ ...rule, enabled: true, builtin: false } as Rule);
  saveRuntimeConfig(runtime);
  return runtime;
}

export function deleteAgentRule(agentId: string, category: string, ruleFp: Partial<Rule>): RuntimeConfig {
  const runtime = loadRuntimeConfig();
  const cat = runtime.agent_rules?.[agentId]?.[category];
  if (cat) {
    const targetFp = _ruleFingerprint(ruleFp);
    cat.rules = (cat.rules || []).filter(r => _ruleFingerprint(r) !== targetFp);
  }
  saveRuntimeConfig(runtime);
  return runtime;
}

/** 切换某 agent 某类别的 category_enabled（整类开关，与通用规则分类开关同范式）。 */
export function updateAgentCategoryEnabled(agentId: string, category: string, enabled: boolean): RuntimeConfig {
  const runtime = loadRuntimeConfig();
  const cat = runtime.agent_rules?.[agentId]?.[category];
  if (cat) cat.category_enabled = enabled;
  saveRuntimeConfig(runtime);
  return runtime;
}

// ==================== 场景定制规则（scenario_rules 分区，与 agent_rules 同构）====================

export function getScenarioRules(runtime: RuntimeConfig): Record<string, Record<string, Category>> {
  return runtime.scenario_rules || {};
}

/** 从 runtime_config 的 scenario_rules[scenario_id] 构造 AgentExtensions（应用 enabled 过滤）。
 * 供 getScenarioExtensions 在 hasRuntimeConfig() 时调用。无该场景分区返回 null。 */
export function getEnabledScenarioExtensions(runtime: RuntimeConfig, scenarioId: string): AgentExtensions | null {
  const scenData = runtime.scenario_rules?.[scenarioId];
  if (!scenData) return null;
  const cmdPatterns = _agentCategoryEnabledRules(scenData.extra_command_patterns)
    .filter(r => r.pattern).map(r => ({
      pattern: r.pattern!, risk_level: r.risk_level || '',
      risk_type: r.risk_type || '', reason: r.reason || '',
    }));
  const injKeywords = _agentCategoryEnabledRules(scenData.extra_injection_keywords)
    .filter(r => r.keyword).map(r => ({
      keyword: r.keyword!, risk_level: r.risk_level || '', lang: r.lang || 'en',
    }));
  const sensitivePaths = _agentCategoryEnabledRules(scenData.extra_sensitive_paths)
    .filter(r => r.path).map(r => ({
      path: r.path!, risk_level: r.risk_level || '', desc: r.desc || '',
      credential: r.credential, read_only: r.read_only, deny_mode: r.deny_mode,
    }));
  return {
    agent_id: scenarioId,
    description: '',
    extra_command_patterns: cmdPatterns,
    extra_injection_keywords: injKeywords,
    extra_sensitive_paths: sensitivePaths,
    builtin_safe_skills: [],
    builtin_safe_action_types: [],
    extra_skills: [],
  };
}

export function updateScenarioRuleEnabled(scenarioId: string, category: string, ruleFp: Partial<Rule>, enabled: boolean): RuntimeConfig {
  const runtime = loadRuntimeConfig();
  const cat = runtime.scenario_rules?.[scenarioId]?.[category];
  if (cat) {
    const targetFp = _ruleFingerprint(ruleFp);
    for (const r of (cat.rules || [])) {
      if (_ruleFingerprint(r) === targetFp) { r.enabled = enabled; break; }
    }
  }
  saveRuntimeConfig(runtime);
  return runtime;
}

export function addScenarioRule(scenarioId: string, category: string, rule: Record<string, unknown>): RuntimeConfig {
  const runtime = loadRuntimeConfig();
  if (!runtime.scenario_rules) runtime.scenario_rules = {};
  if (!runtime.scenario_rules[scenarioId]) runtime.scenario_rules[scenarioId] = {};
  const cats = runtime.scenario_rules[scenarioId];
  if (!cats[category]) cats[category] = { category_enabled: true, category_desc: '', rules: [] };
  (cats[category].rules || (cats[category].rules = [])).push({ ...rule, enabled: true, builtin: false } as Rule);
  saveRuntimeConfig(runtime);
  return runtime;
}

export function deleteScenarioRule(scenarioId: string, category: string, ruleFp: Partial<Rule>): RuntimeConfig {
  const runtime = loadRuntimeConfig();
  const cat = runtime.scenario_rules?.[scenarioId]?.[category];
  if (cat) {
    const targetFp = _ruleFingerprint(ruleFp);
    cat.rules = (cat.rules || []).filter(r => _ruleFingerprint(r) !== targetFp);
  }
  saveRuntimeConfig(runtime);
  return runtime;
}

/** 切换某场景某类别的 category_enabled（整类开关，与通用规则分类开关同范式）。 */
export function updateScenarioCategoryEnabled(scenarioId: string, category: string, enabled: boolean): RuntimeConfig {
  const runtime = loadRuntimeConfig();
  const cat = runtime.scenario_rules?.[scenarioId]?.[category];
  if (cat) cat.category_enabled = enabled;
  saveRuntimeConfig(runtime);
  return runtime;
}
