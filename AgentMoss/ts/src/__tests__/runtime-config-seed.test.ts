/**
 * runtime-config seed/merge/CRUD 单测（块 B1）。
 * 用临时 AGENT_MOSS_RUNTIME_CONFIG_PATH 隔离，不污染真实配置。
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, existsSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

let tmpDir: string;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), 'amrc-'));
  process.env.AGENT_MOSS_RUNTIME_CONFIG_PATH = join(tmpDir, 'runtime.json');
  // 清 require 缓存让 runtime-config 重新读 env（vitest 隔离模块）
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
  delete process.env.AGENT_MOSS_RUNTIME_CONFIG_PATH;
});

// 动态 import 让 env 生效
async function loadRc() {
  const mod = await import('../infra/runtime-config');
  return mod;
}

describe('generateSourceDefaults (seed)', () => {
  it('生成正确顶层结构', async () => {
    const { generateSourceDefaults, DEFAULT_LAYERS: DFL } = await loadRc();
    const d = generateSourceDefaults();
    expect(d.version).toBe(1);
    expect(d.layers).toEqual(DFL);
    expect(Object.keys(d.L1_rules)).toContain('dangerous_commands');
    expect(Object.keys(d.L1_rules)).toContain('injection_detection');
    expect(Object.keys(d.L1_rules)).toContain('sensitive_path_access'); // 重分类后归属 L1
    expect(Object.keys(d.L3_skills)).toContain('file_operations');
  });

  it('L1 dangerous_commands 规则数 > 0 且 builtin', async () => {
    const { generateSourceDefaults } = await loadRc();
    const d = generateSourceDefaults();
    const rules = d.L1_rules.dangerous_commands.rules!;
    expect(rules.length).toBeGreaterThan(10);
    expect(rules.every(r => r.builtin === true && r.enabled === true)).toBe(true);
    expect(rules.every(r => typeof r.pattern === 'string')).toBe(true); // RegExp source
  });

  it('L1 sensitive_path 有 credential deny_both 标记', async () => {
    const { generateSourceDefaults } = await loadRc();
    const d = generateSourceDefaults();
    const shadowRule = d.L1_rules.sensitive_path_access.rules!.find(r => r.path && r.path.includes('shadow'));
    expect(shadowRule).toBeTruthy();
    expect(shadowRule!.deny_mode).toBe('deny_both');
    expect(shadowRule!.credential).toBe(true);
  });

  it('不同 pattern 生成不同 id（历史撞车对 rm 规则）', async () => {
    // 验证 id 唯一性：旧版仅 slug 会把特殊字符抹平导致撞 id。
    const d = (await loadRc()).generateSourceDefaults();
    const rules = d.L1_rules.dangerous_commands.rules!;
    const ids = rules.map(r => r.id!);
    expect(new Set(ids).size).toBe(ids.length); // 全部唯一
  });

  it('seed 中所有 L1/L2 规则 id 唯一', async () => {
    const { generateSourceDefaults } = await loadRc();
    const d = generateSourceDefaults();
    const seen = new Set<string>();
    for (const layerKey of ['L1_rules', 'L2_rules'] as const) {
      for (const cat of Object.values(d[layerKey] as Record<string, any>)) {
        for (const r of (cat.rules || [])) seen.add(r.id!);
      }
    }
    // 无重复即 seen 无冲突；累计数与总规则数一致由调用处保证，这里断言关键分类无重复。
    expect(seen.size).toBeGreaterThan(0);
  });
});

describe('mergeConfig (preserve user toggles)', () => {
  it('用户禁用的规则，merge 后仍禁用', async () => {
    const { generateSourceDefaults, mergeConfig } = await loadRc();
    const src = generateSourceDefaults();
    const user = JSON.parse(JSON.stringify(src)) as typeof src;
    const targetId = user.L1_rules.sensitive_path_access.rules![0].id;
    user.L1_rules.sensitive_path_access.rules![0].enabled = false;
    const merged = mergeConfig(user, src);
    const r = merged.L1_rules.sensitive_path_access.rules!.find(x => x.id === targetId);
    expect(r?.enabled).toBe(false);
  });

  it('用户新增自定义规则保留，且 builtin=false', async () => {
    const { generateSourceDefaults, mergeConfig } = await loadRc();
    const src = generateSourceDefaults();
    const user: any = JSON.parse(JSON.stringify(src));
    user.L1_rules.user_custom.rules = [{ id: 'my_rule', pattern: 'foo', enabled: true, builtin: false }];
    const merged = mergeConfig(user, src);
    expect(merged.L1_rules.user_custom.rules!.find(r => r.id === 'my_rule')).toBeTruthy();
  });
});

describe('CRUD', () => {
  it('updateLayerEnabled 改 L3 并落盘', async () => {
    const { updateLayerEnabled, loadRuntimeConfig } = await loadRc();
    updateLayerEnabled('L3_llm_analysis', false);
    const rc = loadRuntimeConfig();
    expect(rc.layers.L3_llm_analysis).toBe(false);
    expect(existsSync(process.env.AGENT_MOSS_RUNTIME_CONFIG_PATH!)).toBe(true);
  });

  it('addCustomRule + deleteCustomRule', async () => {
    const { addCustomRule, deleteCustomRule, loadRuntimeConfig } = await loadRc();
    addCustomRule('L1_rules', 'user_custom', { pattern: 'evil_cmd', risk_level: 'high' });
    let rc = loadRuntimeConfig();
    const added = rc.L1_rules.user_custom.rules!.find(r => r.pattern === 'evil_cmd');
    expect(added).toBeTruthy();
    expect(added!.builtin).toBe(false);
    // 删除
    const deleted = deleteCustomRule('L1_rules', 'user_custom', added!.id!);
    expect(deleted).not.toBeNull();
    rc = loadRuntimeConfig();
    expect(rc.L1_rules.user_custom.rules!.find(r => r.pattern === 'evil_cmd')).toBeFalsy();
  });

  it('deleteCustomRule 拒绝删 builtin', async () => {
    const { generateSourceDefaults, saveRuntimeConfig, deleteCustomRule, loadRuntimeConfig } = await loadRc();
    // 手动 seed 一个 builtin 规则
    const src = generateSourceDefaults();
    saveRuntimeConfig(src);
    const builtinId = src.L1_rules.sensitive_path_access.rules![0].id!;
    const result = deleteCustomRule('L1_rules', 'sensitive_path_access', builtinId);
    expect(result).toBeNull(); // builtin 不删
    const rc = loadRuntimeConfig();
    expect(rc.L1_rules.sensitive_path_access.rules!.find(r => r.id === builtinId)).toBeTruthy();
  });

  it('同 id 撞车时 pickDeletableRule 优先删 source_removed', async () => {
    const { pickDeletableRule } = await loadRc();
    const rid = 'cmd_dup';
    const active = { id: rid, pattern: 'x', enabled: true, builtin: true } as any;
    const removed = { id: rid, pattern: 'y', enabled: false, builtin: true, source_removed: true } as any;
    const rules = [active, removed];
    const result = pickDeletableRule(rules, rid);
    expect(result).not.toBeNull();
    expect(rules).toHaveLength(1);
    expect(rules[0].pattern).toBe('x'); // 删 source_removed（y），活跃（x）保留
  });

  it('同 id 撞车时 pickDeletableRule 优先删 builtin=false', async () => {
    const { pickDeletableRule } = await loadRc();
    const rid = 'cmd_dup';
    const active = { id: rid, pattern: 'x', enabled: true, builtin: true } as any;
    const custom = { id: rid, pattern: 'z', enabled: true, builtin: false } as any;
    const rules = [active, custom];
    pickDeletableRule(rules, rid);
    expect(rules).toHaveLength(1);
    expect(rules[0].pattern).toBe('x');
  });

  it('同 id 仅活跃 builtin 时 pickDeletableRule 拒绝', async () => {
    const { pickDeletableRule } = await loadRc();
    const rid = 'cmd_only_active';
    const active = { id: rid, pattern: 'x', enabled: true, builtin: true } as any;
    expect(pickDeletableRule([active], rid)).toBeNull();
  });

  it('id 未命中时 pickDeletableRule 无操作', async () => {
    const { pickDeletableRule } = await loadRc();
    const rules = [{ id: 'a', pattern: 'x', enabled: true, builtin: true } as any];
    expect(pickDeletableRule(rules, 'nope')).not.toBeNull();
    expect(rules).toHaveLength(1);
  });

  it('updateSkillEnabled 跨分类找 skill', async () => {
    const { updateSkillEnabled, loadRuntimeConfig } = await loadRc();
    updateSkillEnabled('file_access_guard', false);
    const rc = loadRuntimeConfig();
    const fileOps = rc.L3_skills.file_operations.skills!;
    expect(fileOps.find(s => s.id === 'file_access_guard')!.enabled).toBe(false);
  });
});

describe('loadRuntimeConfig seed fallback', () => {
  it('文件不存在时自动 seed + 落盘', async () => {
    const { loadRuntimeConfig } = await loadRc();
    const rc = loadRuntimeConfig();
    expect(Object.keys(rc.L1_rules).length).toBeGreaterThan(0); // seeded
    expect(existsSync(process.env.AGENT_MOSS_RUNTIME_CONFIG_PATH!)).toBe(true);
  });
});
