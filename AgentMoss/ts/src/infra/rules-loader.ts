/**
 * 归一化规则加载器（单一事实源，与 Python rules_loader.py 对齐）。
 *
 * L1/L2/L3 的正则规则数据统一存放在 agent_moss/rules/ 下：
 *   - l1_rules.json: 危险命令 / 注入关键词 / 敏感路径
 *   - l2_rules.json: 意图偏离 / 密码修改授权 / 用户删除授权
 *   - l3_rules.json: skill 关键词映射
 *
 * Python 与 TS 两端都从这些 JSON 读取，消除双端规则漂移。
 *
 * 路径解析（健壮多候选）：
 * 本模块可能被 tsup 内联进不同入口 bundle，`__dirname` 随打包产物而异：
 *   - dist/cli.js / dist/server.js         → __dirname = dist/
 *   - dist/engine/coordinator.js           → __dirname = dist/engine/
 *   - dev (vitest 源文件) ts/src/infra/    → __dirname = ts/src/infra/
 * 因此枚举所有可能的 rules 目录候选，命中即用（首个存在者）。
 */
import { readFileSync, existsSync } from 'fs';
import { resolve, dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { homedir } from 'os';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/** 数据根目录（与 Python agent_moss/infra/paths.py get_data_root() 对齐）：
 *  AGENT_MOSS_DATA_DIR 优先，否则 ~/.config/agentmoss（Windows 用 %USERPROFILE%）。 */
function dataRootDir(): string {
  return process.env.AGENT_MOSS_DATA_DIR || join(homedir(), '.config', 'agentmoss');
}

// 候选 rules 目录（覆盖 dist / dist/engine / dev 源 三种 __dirname 形态）。
// 从 __dirname 出发尝试若干相对深度，命中 agent_moss/rules 或 dist/rules 即用。
const RULES_DIR_CANDS = (() => {
  const cands: string[] = [
    // 用户数据目录覆盖优先（与 Python rules_loader._load_json 的
    // <data_root>/rules/<name> 优先逻辑对齐）。用户安装 pip/npm 包后把自定义
    // mc_rules.json 放到 <data_root>/rules/ 即可覆盖内置默认，无需改源码。
    resolve(dataRootDir(), 'rules'),
    // dist: __dirname=dist/ → dist/rules；__dirname=dist/engine/ → dist/engine/../rules=dist/rules
    resolve(__dirname, '../rules'),
    resolve(__dirname, 'rules'),
    // dev src: __dirname=ts/src/infra/ → ts/src/infra/../../../agent_moss/rules = 仓库根 agent_moss/rules
    resolve(__dirname, '../../../agent_moss/rules'),
    // dist 但 __dirname 指向 dist/engine 再往上两级的仓库根 agent_moss/rules
    resolve(__dirname, '../../../../agent_moss/rules'),
    // 相对当前工作目录的仓库根（兜底，兼容以仓库根为 cwd 运行）
    resolve(process.cwd(), 'agent_moss/rules'),
  ];
  return cands.filter((c) => existsSync(c));
})();

function findRulesFile(name: string): string | null {
  for (const dir of RULES_DIR_CANDS) {
    const p = resolve(dir, name);
    if (existsSync(p)) return p;
  }
  return null;
}

function loadJson(name: string): Record<string, any> {
  const p = findRulesFile(name);
  if (!p) return {};
  try {
    return JSON.parse(readFileSync(p, 'utf-8')) || {};
  } catch {
    return {};
  }
}

/** L1 规则数据：{dangerous_commands, injection_detection, sensitive_path_access} */
export function loadL1(): Record<string, any> {
  return loadJson('l1_rules.json');
}

/** L2 规则数据：{intent_consistency, password_modify_consent, user_deletion_consent} */
export function loadL2(): Record<string, any> {
  return loadJson('l2_rules.json');
}

/** L3 规则数据：{category: {skill_id: [keywords]}} */
export function loadL3(): Record<string, any> {
  return loadJson('l3_rules.json');
}

/** L2.2 模型检测规则数据：{ap_patterns, rules}（LTL 公式 AST，双端共用）。 */
export function loadMC(): Record<string, any> {
  const mc = loadJson('mc_rules.json');
  const rules: any[] = mc.rules || [];
  // 运行时开关：合并 runtime_config 的 L2_2.ltl_rules 分区 enabled（按 id 覆盖），
  // 引擎据此跳过被禁用的 LTL 规则；出厂默认全开。与 Python rules_loader.load_mc 对齐。
  try {
    // 延迟加载 runtime-config（裸 require）：与 agents/index.ts、scenarios/index.ts、
    // config.ts 同模式——规避 cycles（runtime-config ← heuristic/logic-rules ←
    // rules-loader），dist 打包由 tsup shims:true 注入 __require 使 require 可用。
    // 注：vitest ESM 下 require 失效（回退内置默认），与其它模块同；门控逻辑由
    // Python 端对拍 + dist 真跑验证。
    const rt: any = require('./runtime-config');
    if (rules.length > 0 && typeof rt.hasRuntimeConfig === 'function' && rt.hasRuntimeConfig()) {
      const ltl: any = (rt.loadRuntimeConfig()?.L2_2?.ltl_rules) || {};
      const rtRules: any[] = ltl.rules || [];
      const enabledById: Record<string, boolean> = {};
      for (const r of rtRules) if (r?.id) enabledById[r.id] = r.enabled !== false;
      // 大类开关：category_enabled=false 时整类禁用（对齐 L1/L2 filter_enabled_rules 语义）
      const catEnabled = ltl.category_enabled !== false;
      for (const r of rules) {
        if (r?.id && r.id in enabledById) r.enabled = enabledById[r.id];
        if (!catEnabled) r.enabled = false;
      }
    }
  } catch { /* runtime-config 不可用则维持内置默认（全开） */ }
  return mc;
}

/** Tool Registry 数据：{tools: {name: {actionClass, requireHighIntegrity}}}（双端共用）。 */
export function loadToolRegistry(): Record<string, any> {
  return loadJson('tool_registry.json');
}