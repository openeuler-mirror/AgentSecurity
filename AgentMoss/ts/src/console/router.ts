/**
 * Policy Console Hono 路由 — 挂载到主 app 的 /console 前缀下。
 * 1:1 对齐 Python console/router.py 的 23 路由契约（前端 SPA 共用）。
 *
 * 复用 infra.runtime-config + engine.token-stats。Bearer 认证
 * （AGENT_MOSS_CONSOLE_TOKEN 未设则本机免认证，iframe 嵌入场景）。
 */
import { Hono } from 'hono';
import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import {
  loadRuntimeConfig, saveRuntimeConfig, updateLayerEnabled,
  updateRuleEnabled, updateRuleDenyMode, updateRuleSkipL3,
  updateCategoryEnabled, addCustomRule, deleteCustomRule,
  addCustomSkill, deleteCustomSkill, updateSkillEnabled,
  updateSkillCategoryEnabled, getEnvOverrides, generateSourceDefaults,
  getRuntimeConfigPath,
  getAgentRules, updateAgentRuleEnabled, addAgentRule, deleteAgentRule,
  updateAgentCategoryEnabled,
  getScenarioRules, updateScenarioRuleEnabled, addScenarioRule,
  deleteScenarioRule, updateScenarioCategoryEnabled,
} from '../infra/runtime-config';
import {
  getTokenStats, getRecentRecords, getRecentRecordsCount, getTokenTrend, resetTokenStats,
} from '../engine/token-stats';
import { loadMC } from '../infra/rules-loader';

const __dirname = dirname(fileURLToPath(import.meta.url));
const STATIC_DIR = join(__dirname, 'static');

const CONSOLE_TOKEN_ENV = 'AGENT_MOSS_CONSOLE_TOKEN';

function getConsoleToken(): string {
  return process.env[CONSOLE_TOKEN_ENV] || '';
}

/** 验证 Bearer token。未配置 token 时本机访问免认证（iframe 嵌入场景）。 */
function verifyAuth(req: Request): boolean {
  const token = getConsoleToken();
  if (!token) return true;
  const auth = req.headers.get('Authorization') || '';
  if (auth.startsWith('Bearer ')) return auth.slice(7) === token;
  return false;
}

/** 鉴权中间件：失败返 401。 */
function authMiddleware() {
  return async (c: any, next: any) => {
    if (!verifyAuth(c.req.raw)) {
      return c.json({ error: 'Unauthorized: invalid or missing Bearer token' }, 401);
    }
    await next();
  };
}

export function createConsoleRouter(): Hono {
  const console = new Hono();
  console.use('/api/*', authMiddleware());

  // ==================== SPA ====================
  // /console 和 /console/ 都返回 SPA（hono route 挂载后两者匹配行为不同，都兜住）
  const serveIndex = (c: any) => {
    const indexFile = join(STATIC_DIR, 'index.html');
    if (existsSync(indexFile)) {
      return c.html(readFileSync(indexFile, 'utf-8'));
    }
    return c.html('<h1>AgentMoss Policy Console</h1><p>Frontend not built. Use /console/api/* endpoints.</p>');
  };
  console.get('/', serveIndex);
  console.get('', serveIndex);

  // ==================== 层级管理 ====================
  console.get('/api/layers', (c) => {
    const rc = loadRuntimeConfig();
    return c.json({ layers: rc.layers, env_overrides: getEnvOverrides() });
  });

  console.put('/api/layers', async (c) => {
    const body = await c.req.json();
    const rc = updateLayerEnabled(body.layer_key, body.enabled);
    return c.json({ layers: rc.layers, env_overrides: getEnvOverrides() });
  });

  // ==================== 规则管理 ====================
  function getL22View(): unknown {
    // L2.2 LTL 规则只读展示（mc_rules.json），与 Python _get_l2_4_view() 对齐。
    // 只返回 ltl_rules（带 enabled + 人话描述），不消费 formal 引擎/其他字段。
    // 只读：formal 引擎整体受 L2_logic_rules 层开关控制，用户自定义 LTL 规则
    // 加在用户数据目录 <data_root>/rules/mc_rules.json。
    const ltlHuman: Record<string, string> = {
      'mc-ltl-001': '先读取了凭据/密钥，之后出现网络外传',
      'mc-ltl-002': '先下载/获取了文件，之后执行了文件',
      'mc-ltl-003': '先禁用了安全防护，之后出现破坏性操作（执行/删除/提权）',
      'mc-ltl-004': '先出现提示词注入，之后出现敏感操作（外传/写文件/执行）',
      'mc-ltl-005': '先读取凭据，之后出现横向移动（ssh/scp 到远程）',
      'mc-ltl-006': '先接触敏感数据，之后清除日志',
      'mc-ltl-007': '先提权，之后安装持久化后门',
      'mc-ltl-008': '先下载文件，之后安装持久化后门',
      'mc-ltl-009': '先接触敏感数据 → 打包压缩 → 网络外传',
      'mc-ltl-010': '安装了持久化机制（crontab/systemd/.bashrc 等），需审批',
      'mc-ctl-001': '任何情况下不允许清除日志（安全底线）',
    };
    const mc = loadMC();
    const rules = (mc.rules || []) as any[];
    // category_enabled 从 runtime 读（loadMC 只合并单条 enabled，不读大类开关）
    let catEnabled = true;
    try {
      const rt = loadRuntimeConfig();
      catEnabled = (rt.L2_2 as any)?.ltl_rules?.category_enabled !== false;
    } catch { /* 缺 runtime 时默认开 */ }
    return {
      enabled_via: 'L2_logic_rules',
      description: '时序与数据流攻击检测（L2.2 模型检测）',
      category_enabled: catEnabled,
      ltl_rules: rules.map((r: any) => ({
        id: r.id, type: r.type,
        formula: Array.isArray(r.formula) ? '<公式>' : r.formula,
        reason: r.reason, risk_level: r.risk_level, action: r.action,
        enabled: r.enabled !== false,
        human: ltlHuman[r.id] || r.reason || '',
      })),
    };
  }

  // 把返回给前端的 runtimeConfig 的 L2_2 统一转成 view 结构（ltl_rules=list）。
  // 前端 toggle LTL 开关后 state.config 需与 /api/config 同构（renderLtlCard 依赖
  // ltl_rules 为数组）；runtime 里 L2_2 是 Category dict，直接返回会崩。镜像 Python _with_l2_2_view。
  function withL22View(rc: any): any {
    // 幂等：仅当 L2_2 是 Category dict（ltl_rules 为 dict）才转 view；已是 list 则跳过。
    const l22 = rc && rc.L2_2;
    if (l22 && typeof l22 === 'object' && !Array.isArray(l22) &&
        l22.ltl_rules && typeof l22.ltl_rules === 'object' && !Array.isArray(l22.ltl_rules)) {
      const rls = l22.ltl_rules.rules || [];
      const ltlHumanLocal: Record<string, string> = {
        'mc-ltl-001': '先读取了凭据/密钥，之后出现网络外传',
        'mc-ltl-002': '先下载/获取了文件，之后执行了文件',
        'mc-ltl-003': '先禁用了安全防护，之后出现破坏性操作（执行/删除/提权）',
        'mc-ltl-004': '先出现提示词注入，之后出现敏感操作（外传/写文件/执行）',
        'mc-ltl-005': '先读取凭据，之后出现横向移动（ssh/scp 到远程）',
        'mc-ltl-006': '先接触敏感数据，之后清除日志',
        'mc-ltl-007': '先提权，之后安装持久化后门',
        'mc-ltl-008': '先下载文件，之后安装持久化后门',
        'mc-ltl-009': '先接触敏感数据 → 打包压缩 → 网络外传',
        'mc-ltl-010': '安装了持久化机制（crontab/systemd/.bashrc 等），需审批',
        'mc-ctl-001': '任何情况下不允许清除日志（安全底线）',
      };
      rc.L2_2 = {
        enabled_via: 'L2_logic_rules',
        description: '时序与数据流攻击检测（L2.2 模型检测）',
        category_enabled: l22.ltl_rules.category_enabled !== false,
        ltl_rules: rls.map((r: any) => ({
          id: r.id, type: 'ltl', formula: '<公式>',
          reason: r.reason || '', risk_level: r.risk_level || 'high',
          action: r.action || 'block', enabled: r.enabled !== false,
          human: ltlHumanLocal[r.id] || r.reason || '',
        })),
      };
    }
    return rc;
  }

  console.get('/api/rules', (c) => {
    const rc = loadRuntimeConfig();
    return c.json({ L1_rules: rc.L1_rules, L2_rules: rc.L2_rules, L2_2: getL22View() });
  });

  console.put('/api/rules/enabled', async (c) => {
    const b = await c.req.json();
    const rc = updateRuleEnabled(b.layer, b.category, b.rule_id, b.enabled);
    return c.json(withL22View(rc));
  });

  console.put('/api/rules/deny_mode', async (c) => {
    const b = await c.req.json();
    const rc = updateRuleDenyMode(b.layer, b.category, b.rule_id, b.deny_mode);
    return c.json(withL22View(rc));
  });

  console.put('/api/rules/skip_l3', async (c) => {
    const b = await c.req.json();
    const rc = updateRuleSkipL3(b.layer, b.category, b.rule_id, b.skip_l3_on_disabled);
    return c.json(withL22View(rc));
  });

  console.put('/api/categories/enabled', async (c) => {
    const b = await c.req.json();
    const rc = updateCategoryEnabled(b.layer, b.category, b.enabled);
    return c.json(withL22View(rc));
  });

  console.post('/api/rules', async (c) => {
    const b = await c.req.json();
    const rc = addCustomRule(b.layer, b.category, {
      pattern: b.pattern, risk_level: b.risk_level, risk_type: b.risk_type,
      reason: b.reason, keyword: b.keyword, lang: b.lang,
      path: b.path, desc: b.desc, credential: b.credential, deny_mode: b.deny_mode,
    });
    return c.json(withL22View(rc));
  });

  console.delete('/api/rules', async (c) => {
    const b = await c.req.json();
    deleteCustomRule(b.layer, b.category, b.rule_id);
    const rc = loadRuntimeConfig();
    return c.json(withL22View(rc));
  });

  // ==================== Skill 管理 ====================
  console.get('/api/skills', (c) => {
    const rc = loadRuntimeConfig();
    return c.json(rc.L3_skills);
  });

  console.put('/api/skills/enabled', async (c) => {
    const b = await c.req.json();
    const rc = updateSkillEnabled(b.skill_id, b.enabled);
    return c.json(withL22View(rc));
  });

  console.put('/api/skill-categories/enabled', async (c) => {
    const b = await c.req.json();
    const rc = updateSkillCategoryEnabled(b.category, b.enabled);
    return c.json(withL22View(rc));
  });

  console.post('/api/skills', async (c) => {
    const b = await c.req.json();
    const rc = addCustomSkill(b.skill_id, b.category || 'user_custom', b.keywords || [], b.content);
    return c.json(withL22View(rc));
  });

  console.delete('/api/skills', async (c) => {
    const b = await c.req.json();
    deleteCustomSkill(b.skill_id, b.category);
    const rc = loadRuntimeConfig();
    return c.json(withL22View(rc));
  });

  console.get('/api/skills/:skill_id/content', async (c) => {
    const skillId = c.req.param('skill_id');
    if (!/^[A-Za-z0-9_-]+$/.test(skillId)) {
      return c.json({ error: 'invalid skill_id' }, 400);
    }
    const skillPath = join(dirname(getRuntimeConfigPath()), 'agent_moss_skills', `${skillId}.md`);
    if (!existsSync(skillPath)) {
      // fallback 到 builtin skill 目录
      const builtinPath = join(__dirname, '..', '..', 'agent_moss', 'skills', `${skillId}.md`);
      if (existsSync(builtinPath)) return c.text(readFileSync(builtinPath, 'utf-8'));
      return c.json({ error: 'skill not found' }, 404);
    }
    return c.text(readFileSync(skillPath, 'utf-8'));
  });

  // ==================== agent 定制规则 ====================
  console.get('/api/agents', (c) => {
    const rc = loadRuntimeConfig();
    return c.json({ agents: getAgentRules(rc) });
  });

  console.put('/api/agents/rules/enabled', async (c) => {
    const b = await c.req.json();
    const fp: Record<string, string> = {};
    if (b.value) fp.value = b.value;
    if (b.pattern) fp.pattern = b.pattern;
    if (b.keyword) fp.keyword = b.keyword;
    if (b.path) fp.path = b.path;
    const rc = updateAgentRuleEnabled(b.agent_id, b.category, fp, b.enabled);
    return c.json({ agents: getAgentRules(rc) });
  });

  console.post('/api/agents/rules', async (c) => {
    const b = await c.req.json();
    const rule: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(b)) {
      if (!['agent_id', 'category'].includes(k) && v !== undefined && v !== null) rule[k] = v;
    }
    const rc = addAgentRule(b.agent_id, b.category, rule);
    return c.json({ agents: getAgentRules(rc) });
  });

  console.delete('/api/agents/rules', async (c) => {
    const b = await c.req.json();
    const fp: Record<string, string> = {};
    if (b.value) fp.value = b.value;
    if (b.pattern) fp.pattern = b.pattern;
    if (b.keyword) fp.keyword = b.keyword;
    if (b.path) fp.path = b.path;
    const rc = deleteAgentRule(b.agent_id, b.category, fp);
    return c.json({ agents: getAgentRules(rc) });
  });

  console.put('/api/agents/categories/enabled', async (c) => {
    const b = await c.req.json();
    const rc = updateAgentCategoryEnabled(b.agent_id, b.category, b.enabled);
    return c.json({ agents: getAgentRules(rc) });
  });

  // ==================== 场景定制规则 ====================

  /** 当前启用的场景 id（与 Python 端一致）：AGENT_MOSS_SCENARIO env（逗号分隔多场景）。 */
  const enabledScenarioIds = (): string[] =>
    (process.env.AGENT_MOSS_SCENARIO || '').split(',').map(s => s.trim()).filter(Boolean);

  // 只返回已启用场景（无 env → 空，console 不显示、引擎不加载）
  console.get('/api/scenarios', (c) => {
    const all = getScenarioRules(loadRuntimeConfig());
    const enabled = enabledScenarioIds();
    if (!enabled.length) return c.json({ scenarios: {}, enabled: [] });
    const shown: Record<string, unknown> = {};
    for (const sid of enabled) if (all[sid]) shown[sid] = all[sid];
    return c.json({ scenarios: shown, enabled });
  });

  console.put('/api/scenarios/rules/enabled', async (c) => {
    const b = await c.req.json();
    const fp: Record<string, string> = {};
    if (b.value) fp.value = b.value;
    if (b.pattern) fp.pattern = b.pattern;
    if (b.keyword) fp.keyword = b.keyword;
    if (b.path) fp.path = b.path;
    const rc = updateScenarioRuleEnabled(b.scenario_id, b.category, fp, b.enabled);
    return c.json({ scenarios: getScenarioRules(rc), enabled: enabledScenarioIds() });
  });

  console.post('/api/scenarios/rules', async (c) => {
    const b = await c.req.json();
    const rule: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(b)) {
      if (!['scenario_id', 'category'].includes(k) && v !== undefined && v !== null) rule[k] = v;
    }
    const rc = addScenarioRule(b.scenario_id, b.category, rule);
    return c.json({ scenarios: getScenarioRules(rc), enabled: enabledScenarioIds() });
  });

  console.delete('/api/scenarios/rules', async (c) => {
    const b = await c.req.json();
    const fp: Record<string, string> = {};
    if (b.value) fp.value = b.value;
    if (b.pattern) fp.pattern = b.pattern;
    if (b.keyword) fp.keyword = b.keyword;
    if (b.path) fp.path = b.path;
    const rc = deleteScenarioRule(b.scenario_id, b.category, fp);
    return c.json({ scenarios: getScenarioRules(rc), enabled: enabledScenarioIds() });
  });

  console.put('/api/scenarios/categories/enabled', async (c) => {
    const b = await c.req.json();
    const rc = updateScenarioCategoryEnabled(b.scenario_id, b.category, b.enabled);
    return c.json({ scenarios: getScenarioRules(rc), enabled: enabledScenarioIds() });
  });

  // ==================== 配置 / env / reset ====================
  // 契约对齐：Python console/router.py 的 /api/config 直接返回完整 runtime config
  // （顶层含 L1_rules/L2_rules/L3_skills/layers），前端 state.config 读取顶层字段。
  // 之前 TS 返回 {config, config_path} 包装导致前端 L1/L2/L3 标签页全空（数据丢）。
  console.get('/api/config', (c) => {
    const rc = loadRuntimeConfig();
    // 与 Python /api/config 一致：附加上 L2_2 形式化只读视图（前端"形式化"页）
    return c.json({ ...rc, L2_2: getL22View() });
  });

  console.get('/api/env-overrides', (c) => {
    return c.json({ overrides: getEnvOverrides() });
  });

  console.post('/api/reset', (c) => {
    const defaults = generateSourceDefaults();
    saveRuntimeConfig(defaults);
    return c.json(withL22View(defaults));
  });

  // ==================== Token stats ====================
  console.get('/api/token-stats', (c) => {
    const days = parseInt(c.req.query('days') || '7', 10);
    return c.json(getTokenStats(days));
  });

  console.get('/api/token-stats/recent', (c) => {
    const limit = parseInt(c.req.query('limit') || '20', 10);
    const offset = parseInt(c.req.query('offset') || '0', 10);
    // 返回 { records, total }，前端据此分页（total 供分页器计算总页数）
    return c.json({ records: getRecentRecords(limit, offset), total: getRecentRecordsCount() });
  });

  console.get('/api/token-stats/trend', (c) => {
    const days = parseInt(c.req.query('days') || '7', 10);
    return c.json(getTokenTrend(days));
  });

  console.post('/api/token-stats/reset', (c) => {
    resetTokenStats();
    return c.json({ reset: true });
  });

  return console;
}
