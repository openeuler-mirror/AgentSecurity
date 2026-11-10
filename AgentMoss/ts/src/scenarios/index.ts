/**
 * 场景定制化规则注册中心 — TypeScript 加载器
 *
 * 按 `scenarioId` 加载该场景的专属规则集（JSON 单一事实源）。
 * 规则文件位置：`agent_moss/scenarios/<scenarioId>/rules.json`
 *
 * 与 Python `agent_moss/scenarios/__init__.py:get_scenario_extensions` 一一对应。
 * 两端共享同一份 rules.json。场景规则与 agent 规则同构（都是 AgentExtensions
 * 结构：extra_command_patterns / extra_injection_keywords / extra_sensitive_paths /
 * builtin_safe_skills / builtin_safe_action_types），唯一区别是顶层 id 字段叫
 * `scenario_id` 而非 `agent_id`（解析时兼容）。
 *
 * 设计动机：agent 规则靠调用方传 `agentId`（真实 agent instance 身份）启用；
 * 场景规则是**部署级**约束（客户沙箱的目录访问边界、禁 ssh 等），没有天然调用方
 * 身份，启用判定为：
 * 1. 调用方显式传 `scenarioId`（请求级，与 agentId 并列）
 * 2. 兜底环境变量 `AGENT_MOSS_SCENARIO`（部署级，客户沙箱设一次，所有请求生效）
 * 3. 两者都空 → 通用模式（不加载场景规则）
 *
 * 路径解析：
 * - prod（dist/cli.js）：copy-assets.cjs 复制 rules.json 到 dist/scenarios/<id>/rules.json
 * - dev（tsx src/cli.ts）：从 ts/src/scenarios/ 出发，回退到 ../../../agent_moss/scenarios
 *
 * 缓存：首次加载后缓存在 Map 中，clearScenarioExtensionsCache 清空（测试用）。
 */

import { readFileSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import type { AgentExtensions } from '../agents/types';
import { mergeAgentExtensions } from '../agents/index';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// 优先用 dist 内联目录（prod，copy-assets.cjs 复制后）；
// 缺失时回退到仓库根 agent_moss/scenarios（dev）。
const SCENARIOS_DIR_PROD = resolve(__dirname, 'scenarios');
const SCENARIOS_DIR_DEV_FALLBACK = resolve(__dirname, '../../../agent_moss/scenarios');

const cache = new Map<string, AgentExtensions | null>();

export function resolveScenariosDir(): string {
  if (existsSync(SCENARIOS_DIR_PROD)) return SCENARIOS_DIR_PROD;
  if (existsSync(SCENARIOS_DIR_DEV_FALLBACK)) return SCENARIOS_DIR_DEV_FALLBACK;
  return SCENARIOS_DIR_PROD; // 不存在时也返回 prod 路径，让后续 existsSync 检查返回 false
}

/**
 * 按 scenarioId 加载该场景的专属规则集。
 *
 * @param scenarioId 调用方场景标识，如 "bank"。空字符串返回 null（通用模式）。
 * @returns AgentExtensions 实例，或 null（无场景专属规则 / rules.json 不存在 / 解析失败）
 */
export function getScenarioExtensions(scenarioId: string): AgentExtensions | null {
  if (!scenarioId) return null;
  if (cache.has(scenarioId)) return cache.get(scenarioId) ?? null;

  let ext: AgentExtensions | null = null;
  // 统一存储：优先读 runtime_config 的 scenario_rules 分区（用户可在 console
  // 查看/编辑/禁用/新增，与 agent_rules 同构，享受与通用规则一致的合并升级）。
  // 回退 rules.json（无 runtime_config 时，如直接起服务未 seed、或旧部署）。
  try {
    const { hasRuntimeConfig, loadRuntimeConfig, getEnabledScenarioExtensions } = require('../infra/runtime-config');
    if (hasRuntimeConfig()) {
      ext = getEnabledScenarioExtensions(loadRuntimeConfig(), scenarioId);
    }
  } catch { /* runtime-config 不可用时回退 rules.json */ }

  if (ext === null) {
    const scenariosDir = resolveScenariosDir();
    const rulesFile = resolve(scenariosDir, scenarioId, 'rules.json');
    if (!existsSync(rulesFile)) {
      cache.set(scenarioId, null);
      return null;
    }
    try {
      const raw = readFileSync(rulesFile, 'utf-8');
      const data = JSON.parse(raw) as any;
      // 场景规则顶层 id 字段是 scenario_id（兼容缺失时回退 agent_id）
      const id = data.scenario_id || data.agent_id || '';
      if (!id) {
        console.warn(`[AgentMoss scenarios] rules.json 缺少 scenario_id 字段: ${rulesFile}`);
        cache.set(scenarioId, null);
        return null;
      }
      ext = {
        agent_id: id,
        description: data.description || '',
        extra_command_patterns: data.extra_command_patterns || [],
        extra_injection_keywords: data.extra_injection_keywords || [],
        extra_sensitive_paths: data.extra_sensitive_paths || [],
        builtin_safe_skills: data.builtin_safe_skills || [],
        builtin_safe_action_types: data.builtin_safe_action_types || [],
        extra_skills: data.extra_skills || [],
      };
    } catch (e) {
      console.error(`[AgentMoss scenarios] 加载场景 ${scenarioId} rules.json 失败:`, (e as Error).message);
      cache.set(scenarioId, null);
      return null;
    }
  }

  cache.set(scenarioId, ext);
  console.log(
    `[AgentMoss scenarios] 加载场景 ${scenarioId} 定制规则: ` +
    `${ext.extra_command_patterns?.length ?? 0} cmd patterns, ` +
    `${ext.extra_injection_keywords?.length ?? 0} injection keywords, ` +
    `${ext.extra_sensitive_paths?.length ?? 0} sensitive paths`
  );
  return ext;
}

/**
 * 清空场景扩展缓存（用于测试或 rules.json 热加载）。
 */
export function clearScenarioExtensionsCache(): void {
  cache.clear();
}

/**
 * 按逗号分隔的场景列表加载并合并扩展（AGENT_MOSS_SCENARIO 支持多场景）。
 * 引擎层兜底 env 时使用：`AGENT_MOSS_SCENARIO=bank,meow` 拆成多个场景 id，
 * 逐个加载后合并（append 语义，与 Python get_scenario_extensions_multi 对齐）。
 */
export function getScenarioExtensionsMulti(scenarioSpec: string | null | undefined): AgentExtensions | null {
  if (!scenarioSpec) return null;
  const ids = scenarioSpec.split(',').map((s) => s.trim()).filter(Boolean);
  if (ids.length === 0) return null;
  const exts = ids.map((id) => getScenarioExtensions(id));
  const nonNull = exts.filter((e): e is AgentExtensions => e !== null);
  if (nonNull.length === 0) return null;
  return mergeAgentExtensions(...nonNull);
}
