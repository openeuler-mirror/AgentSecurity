/**
 * 三方 agent 定制化注册中心 — TypeScript 加载器
 *
 * 按 `agentId` 加载该 agent 的专属规则集（JSON 单一事实源）。
 * 规则文件位置：`agent_moss/agents/<agentId>/rules.json`
 *
 * 与 Python `agent_moss/agents/__init__.py:get_agent_extensions` 一一对应。
 * 两端共享同一份 rules.json。
 *
 * 路径解析：
 * - prod（dist/cli.js）：copy-assets.cjs 复制 rules.json 到 dist/agents/<id>/rules.json
 * - dev（tsx src/cli.ts）：从 ts/src/agents/ 出发，回退到 ../../../agent_moss/agents
 *
 * 缓存：首次加载后缓存在 Map 中，clearAgentExtensionsCache 清空（测试用）。
 */

import { readFileSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import type { AgentExtensions } from './types';

export type { AgentExtensions } from './types';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// 优先用 dist 内联目录（prod，copy-assets.cjs 复制后）；
// 缺失时回退到仓库根 agent_moss/agents（dev）。
// 注意：从 ts/src/agents/ 出发，仓库根 agent_moss/agents 在 ../../../agent_moss/agents。
const AGENTS_DIR_PROD = resolve(__dirname, 'agents');
const AGENTS_DIR_DEV_FALLBACK = resolve(__dirname, '../../../agent_moss/agents');

const cache = new Map<string, AgentExtensions | null>();

export function resolveAgentsDir(): string {
  if (existsSync(AGENTS_DIR_PROD)) return AGENTS_DIR_PROD;
  if (existsSync(AGENTS_DIR_DEV_FALLBACK)) return AGENTS_DIR_DEV_FALLBACK;
  return AGENTS_DIR_PROD; // 不存在时也返回 prod 路径，让后续 existsSync 检查返回 false
}

/**
 * 按 agentId 加载该 agent 的专属规则集。
 *
 * @param agentId 调用方 agent 标识，如 "xiaoo" / "opencode" / "opendesk"。
 *                空字符串返回 null（通用模式）。
 * @returns AgentExtensions 实例，或 null（无 agent 专属规则 / rules.json 不存在 / 解析失败）
 */
export function getAgentExtensions(agentId: string): AgentExtensions | null {
  if (!agentId) return null;
  if (cache.has(agentId)) return cache.get(agentId) ?? null;

  let ext: AgentExtensions | null = null;
  // 统一存储：优先读 runtime_config 的 agent_rules 分区（用户可在 console
  // 查看/编辑/禁用/新增，享受与通用规则一致的合并升级）。回退 rules.json
  // （无 runtime_config 时，如直接起服务未 seed、或旧部署）。
  try {
    const { hasRuntimeConfig, loadRuntimeConfig, getEnabledAgentExtensions } = require('../infra/runtime-config');
    if (hasRuntimeConfig()) {
      ext = getEnabledAgentExtensions(loadRuntimeConfig(), agentId);
    }
  } catch { /* runtime-config 不可用时回退 rules.json */ }

  if (ext === null) {
    const agentsDir = resolveAgentsDir();
    const rulesFile = resolve(agentsDir, agentId, 'rules.json');
    if (!existsSync(rulesFile)) {
      cache.set(agentId, null);
      return null;
    }
    try {
      const raw = readFileSync(rulesFile, 'utf-8');
      ext = JSON.parse(raw) as AgentExtensions;
      if (!ext.agent_id) {
        console.warn(`[AgentMoss agents] rules.json 缺少 agent_id 字段: ${rulesFile}`);
        cache.set(agentId, null);
        return null;
      }
    } catch (e) {
      console.error(`[AgentMoss agents] 加载 agent ${agentId} rules.json 失败:`, (e as Error).message);
      cache.set(agentId, null);
      return null;
    }
  }

  cache.set(agentId, ext);
  console.log(
    `[AgentMoss agents] 加载 agent ${agentId} 定制规则: ` +
    `${ext.extra_command_patterns?.length ?? 0} cmd patterns, ` +
    `${ext.extra_injection_keywords?.length ?? 0} injection keywords, ` +
    `${ext.extra_sensitive_paths?.length ?? 0} sensitive paths, ` +
    `${ext.builtin_safe_skills?.length ?? 0} builtin safe skills, ` +
    `${ext.builtin_safe_action_types?.length ?? 0} builtin safe action types`
  );
  return ext;
}

/**
 * 清空 agent 扩展缓存（用于测试或 rules.json 热加载）。
 */
export function clearAgentExtensionsCache(): void {
  cache.clear();
}

/**
 * 合并多个 AgentExtensions（如 agent 规则 + 场景规则），追加式拼接各 extra_* 列表。
 *
 * 全部为 null 时返回 null（通用模式）。非 null 时以第一个非空实例为骨架，
 * 其余实例的 extra_* / builtin_safe_* 列表依次追加在后（不覆盖）。
 * 与 Python `AgentExtensions.merge`（agent_moss/agents/base.py）一一对应。
 */
export function mergeAgentExtensions(...exts: (AgentExtensions | null | undefined)[]): AgentExtensions | null {
  const nonNull = exts.filter((e): e is AgentExtensions => !!e);
  if (nonNull.length === 0) return null;
  const base = nonNull[0];
  return {
    agent_id: base.agent_id,
    description: base.description,
    extra_command_patterns: nonNull.flatMap(e => e.extra_command_patterns || []),
    extra_injection_keywords: nonNull.flatMap(e => e.extra_injection_keywords || []),
    extra_sensitive_paths: nonNull.flatMap(e => e.extra_sensitive_paths || []),
    builtin_safe_skills: nonNull.flatMap(e => e.builtin_safe_skills || []),
    builtin_safe_action_types: nonNull.flatMap(e => e.builtin_safe_action_types || []),
    extra_skills: nonNull.flatMap(e => e.extra_skills || []),
  };
}
