/**
 * Console 路由单测（块 B2）—— 23 路由契约对齐 py console/router.py。
 * 用临时 runtime config 隔离，不污染真实配置。
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { createApp } from '../server';

let tmpDir: string;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), 'amc-'));
  process.env.AGENT_MOSS_RUNTIME_CONFIG_PATH = join(tmpDir, 'runtime.json');
  process.env.AGENT_MOSS_TOKEN_STATS_PATH = join(tmpDir, 'token.json');
  delete process.env.AGENT_MOSS_CONSOLE_TOKEN; // 免鉴权
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
  delete process.env.AGENT_MOSS_RUNTIME_CONFIG_PATH;
  delete process.env.AGENT_MOSS_TOKEN_STATS_PATH;
});

async function req(method: string, path: string, body?: any): Promise<{ status: number; data: any }> {
  const init: any = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) init.body = JSON.stringify(body);
  const r = await createApp().request(`http://localhost${path}`, init);
  const text = await r.text();
  let data: any = text;
  try { data = JSON.parse(text); } catch { /* keep text */ }
  return { status: r.status, data };
}

describe('Console SPA', () => {
  it('GET /console 返回 SPA HTML', async () => {
    const { status, data } = await req('GET', '/console');
    expect(status).toBe(200);
    // 真实 index.html 的 <title> 为 "AgentMoss 安全策略管控台"，
    // fallback HTML 为 "<h1>AgentMoss Policy Console</h1>"。
    // 两者都含 "AgentMoss"，用它做稳定锚点确认返回的是 console SPA。
    expect(String(data)).toContain('AgentMoss');
  });
});

describe('Console 层级管理', () => {
  it('GET /console/api/layers 返回全部层级（含 Agent/场景开关）', async () => {
    const { status, data } = await req('GET', '/console/api/layers');
    expect(status).toBe(200);
    // 5 个层开关（L2.2 形式化跟随 L2_logic_rules，无独立开关）
    for (const k of ['L1_heuristic', 'L2_logic_rules', 'L3_llm_analysis',
      'agent_rules_enabled', 'scenario_rules_enabled']) {
      expect(data.layers[k]).toBe(true);
    }
  });

  it('PUT /console/api/layers 禁用 L3 并落盘', async () => {
    const r1 = await req('PUT', '/console/api/layers', { layer_key: 'L3_llm_analysis', enabled: false });
    expect(r1.status).toBe(200);
    expect(r1.data.layers.L3_llm_analysis).toBe(false);
    const r2 = await req('GET', '/console/api/layers');
    expect(r2.data.layers.L3_llm_analysis).toBe(false);
  });
});

describe('Console 规则管理', () => {
  it('GET /console/api/rules 返回 seeded 规则', async () => {
    const { status, data } = await req('GET', '/console/api/rules');
    expect(status).toBe(200);
    expect(Object.keys(data.L1_rules)).toContain('dangerous_commands');
    expect(Object.keys(data.L1_rules)).toContain('sensitive_path_access'); // 重分类后归属 L1
    expect(data.L1_rules.dangerous_commands.rules.length).toBeGreaterThan(10);
  });

  it('POST/DELETE /console/api/rules 增删自定义规则', async () => {
    const add = await req('POST', '/console/api/rules', {
      layer: 'L1_rules', category: 'user_custom', pattern: 'evil', risk_level: 'high',
    });
    expect(add.status).toBe(200);
    const added = add.data.L1_rules.user_custom.rules.find((r: any) => r.pattern === 'evil');
    expect(added).toBeTruthy();
    expect(added.builtin).toBe(false);
    const del = await req('DELETE', '/console/api/rules', {
      layer: 'L1_rules', category: 'user_custom', rule_id: added.id,
    });
    expect(del.status).toBe(200);
    expect(del.data.L1_rules.user_custom.rules.find((r: any) => r.pattern === 'evil')).toBeFalsy();
  });

  it('PUT /console/api/rules/enabled 翻转规则', async () => {
    const before = await req('GET', '/console/api/rules');
    const firstRule = before.data.L1_rules.dangerous_commands.rules[0];
    const r = await req('PUT', '/console/api/rules/enabled', {
      layer: 'L1_rules', category: 'dangerous_commands', rule_id: firstRule.id, enabled: false,
    });
    expect(r.status).toBe(200);
    const after = r.data.L1_rules.dangerous_commands.rules.find((x: any) => x.id === firstRule.id);
    expect(after.enabled).toBe(false);
  });

  it('PUT /console/api/rules/enabled 翻转 L2_2 LTL 规则后 L2_2.ltl_rules 仍为数组（契约）', async () => {
    const r = await req('PUT', '/console/api/rules/enabled', {
      layer: 'L2_2', category: 'ltl_rules', rule_id: 'mc-ltl-001', enabled: false,
    });
    expect(r.status).toBe(200);
    // toggle 后返回的 L2_2 必须与 /api/config 同构（ltl_rules 是数组），
    // 否则前端 renderLtlCard 的 map 崩溃——镜像 Python _with_l2_2_view 契约。
    const l = r.data.L2_2;
    expect(Array.isArray(l.ltl_rules)).toBe(true);
    expect(l.ltl_rules.length).toBe(11);
    const target = l.ltl_rules.find((x: any) => x.id === 'mc-ltl-001');
    expect(target.enabled).toBe(false);
    expect(typeof target.human).toBe('string');
  });

  it('PUT /console/api/categories/enabled 返回的 L2_2.ltl_rules 仍为数组（bug 回归）', async () => {
    // 历史 bug：/api/categories/enabled 未包 withL22View，禁任意分类后 L2_2 变
    // Category dict，前端 renderLtlCard 报 ltl.filter is not a function。
    const r = await req('PUT', '/console/api/categories/enabled', {
      layer: 'L2_rules', category: 'intent_consistency', enabled: false,
    });
    expect(r.status).toBe(200);
    const l = r.data.L2_2;
    expect(Array.isArray(l.ltl_rules)).toBe(true);
    expect(l.ltl_rules.length).toBe(11);
    expect(typeof l.category_enabled).toBe('boolean'); // 大类开关字段存在
  });

  it('PUT /console/api/categories/enabled 切换 LTL 大类 category_enabled 生效', async () => {
    // 关闭 LTL 大类 → view 的 category_enabled=false，且 /api/config 也返回 false
    const off = await req('PUT', '/console/api/categories/enabled', {
      layer: 'L2_2', category: 'ltl_rules', enabled: false,
    });
    expect(off.status).toBe(200);
    expect(off.data.L2_2.category_enabled).toBe(false);

    const cfg = await req('GET', '/console/api/config');
    expect(cfg.data.L2_2.category_enabled).toBe(false);

    // 重新打开
    const on = await req('PUT', '/console/api/categories/enabled', {
      layer: 'L2_2', category: 'ltl_rules', enabled: true,
    });
    expect(on.status).toBe(200);
    expect(on.data.L2_2.category_enabled).toBe(true);
  });
});

describe('Console Skill 管理', () => {
  it('GET /console/api/skills 返回 L3 分类（顶层 L3_skills，与 py 一致）', async () => {
    const { status, data } = await req('GET', '/console/api/skills');
    expect(status).toBe(200);
    expect(Object.keys(data)).toContain('file_operations');
  });

  it('PUT /console/api/skills/enabled 禁用 skill', async () => {
    const r = await req('PUT', '/console/api/skills/enabled', {
      skill_id: 'file_access_guard', enabled: false,
    });
    expect(r.status).toBe(200);
    const s = r.data.L3_skills.file_operations.skills.find((x: any) => x.id === 'file_access_guard');
    expect(s.enabled).toBe(false);
  });
});

describe('Console agent 定制规则', () => {
  it('GET /console/api/agents 返回 seeded agent 规则（含 opendesk）', async () => {
    const { status, data } = await req('GET', '/console/api/agents');
    expect(status).toBe(200);
    expect(data.agents).toBeTruthy();
    expect(Object.keys(data.agents)).toContain('opendesk');
    // builtin_safe_action_types 应含 memory- 前缀项
    const cats = data.agents.opendesk;
    expect(cats.builtin_safe_action_types).toBeTruthy();
    const values = cats.builtin_safe_action_types.rules.map((r: any) => r.value);
    expect(values).toContain('memory-');
  });

  it('PUT /console/api/agents/rules/enabled 禁用 memory- 并落盘', async () => {
    const r = await req('PUT', '/console/api/agents/rules/enabled', {
      agent_id: 'opendesk', category: 'builtin_safe_action_types',
      value: 'memory-', enabled: false,
    });
    expect(r.status).toBe(200);
    const rules = r.data.agents.opendesk.builtin_safe_action_types.rules;
    const mem = rules.find((x: any) => x.value === 'memory-');
    expect(mem.enabled).toBe(false);
    // 再 GET 确认落盘
    const r2 = await req('GET', '/console/api/agents');
    const mem2 = r2.data.agents.opendesk.builtin_safe_action_types.rules
      .find((x: any) => x.value === 'memory-');
    expect(mem2.enabled).toBe(false);
  });

  it('POST/DELETE /console/api/agents/rules 增删 agent 规则', async () => {
    const add = await req('POST', '/console/api/agents/rules', {
      agent_id: 'opendesk', category: 'builtin_safe_action_types', value: 'custom-test-',
    });
    expect(add.status).toBe(200);
    const added = add.data.agents.opendesk.builtin_safe_action_types.rules
      .find((r: any) => r.value === 'custom-test-');
    expect(added).toBeTruthy();
    expect(added.builtin).toBe(false);
    const del = await req('DELETE', '/console/api/agents/rules', {
      agent_id: 'opendesk', category: 'builtin_safe_action_types', value: 'custom-test-',
    });
    expect(del.status).toBe(200);
    expect(del.data.agents.opendesk.builtin_safe_action_types.rules
      .find((r: any) => r.value === 'custom-test-')).toBeFalsy();
  });

  it('PUT /console/api/agents/categories/enabled 禁用整类', async () => {
    const r = await req('PUT', '/console/api/agents/categories/enabled', {
      agent_id: 'opendesk', category: 'builtin_safe_action_types', enabled: false,
    });
    expect(r.status).toBe(200);
    expect(r.data.agents.opendesk.builtin_safe_action_types.category_enabled).toBe(false);
  });
});

describe('Console 配置/env/reset', () => {
  it('GET /console/api/config 返回完整配置（顶层契约，与 py 一致）', async () => {
    const { status, data } = await req('GET', '/console/api/config');
    expect(status).toBe(200);
    // 顶层直接含 L1_rules/L2_rules/L3_skills/layers（前端 state.config 读取顶层字段）
    expect(data.L1_rules).toBeTruthy();
    expect(data.L2_rules).toBeTruthy();
    expect(data.L3_skills).toBeTruthy();
    expect(data.layers).toBeTruthy();
  });

  it('GET /console/api/env-overrides', async () => {
    const { status, data } = await req('GET', '/console/api/env-overrides');
    expect(status).toBe(200);
    expect(data.overrides).toBeDefined();
  });

  it('POST /console/api/reset 重置为出厂默认', async () => {
    // 先禁用一层
    await req('PUT', '/console/api/layers', { layer_key: 'L1_heuristic', enabled: false });
    const r = await req('POST', '/console/api/reset');
    expect(r.status).toBe(200);
    expect(r.data.layers.L1_heuristic).toBe(true); // 返回完整默认配置（顶层），重置回默认
  });
});

describe('Console Token stats', () => {
  it('GET /console/api/token-stats', async () => {
    const { status, data } = await req('GET', '/console/api/token-stats?days=7');
    expect(status).toBe(200);
    expect(data).toHaveProperty('total_tokens');
  });

  it('GET /console/api/token-stats/recent', async () => {
    const { status, data } = await req('GET', '/console/api/token-stats/recent?limit=5');
    expect(status).toBe(200);
    // 与 Python 契约一致（router.py:445）：返回 { records, total } 分页对象（68213cb 分页改动），
    // records 为裸数组、total 为总数（前端据此分页）
    expect(Array.isArray(data.records)).toBe(true);
    expect(typeof data.total).toBe('number');
  });

  it('GET /console/api/token-stats/trend', async () => {
    const { status, data } = await req('GET', '/console/api/token-stats/trend?days=7');
    expect(status).toBe(200);
    expect(data).toBeDefined();
  });

  it('POST /console/api/token-stats/reset', async () => {
    const { status, data } = await req('POST', '/console/api/token-stats/reset');
    expect(status).toBe(200);
    expect(data.reset).toBe(true);
  });
});

describe('Console auth', () => {
  beforeEach(() => {
    process.env.AGENT_MOSS_CONSOLE_TOKEN = 'secret-token';
  });
  afterEach(() => {
    delete process.env.AGENT_MOSS_CONSOLE_TOKEN;
  });

  it('无 Bearer token → 401', async () => {
    const r = await req('GET', '/console/api/layers');
    expect(r.status).toBe(401);
  });

  it('正确 Bearer token → 200', async () => {
    const app = createApp();
    const r = await app.request('http://localhost/console/api/layers', {
      headers: { Authorization: 'Bearer secret-token' },
    });
    expect(r.status).toBe(200);
  });
});

// Health 端点归属实例字段（多实例区分用）：值来自 env AGENT_MOSS_INSTANCE。
// xiaoo/OpenDesk 同机并存时，bridge 探测靠此过滤避免漂移到对方的 agentmoss。
describe('Health endpoint: instance field', () => {
  it('未设 AGENT_MOSS_INSTANCE → instance 为空串', async () => {
    delete process.env.AGENT_MOSS_INSTANCE;
    const { status, data } = await req('GET', '/api/v1/health');
    expect(status).toBe(200);
    expect(data.status).toBe('healthy');
    expect(data.instance).toBe('');
  });

  it('设 AGENT_MOSS_INSTANCE=xiaoo → instance=xiaoo', async () => {
    process.env.AGENT_MOSS_INSTANCE = 'xiaoo';
    try {
      const { status, data } = await req('GET', '/api/v1/health');
      expect(status).toBe(200);
      expect(data.instance).toBe('xiaoo');
    } finally {
      delete process.env.AGENT_MOSS_INSTANCE;
    }
  });
});
