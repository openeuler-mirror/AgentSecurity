/**
 * 归一化规则加载器测试 — 验证 L1/L2/L3 规则从 JSON 单一事实源加载。
 *
 * 规则数据统一存放在 agent_moss/rules/ 下（l1/l2/l3_rules.json），Python 与 TS
 * 共用。此测试断言计数稳定，守护出厂默认，防误删/误改导致双端漂移。
 */
import { describe, it, expect, vi } from 'vitest';
import { loadL1, loadL2, loadL3 } from '../infra/rules-loader';
import { generateSourceDefaults } from '../infra/runtime-config';
import {
  DANGEROUS_PATTERNS,
  INJECTION_KEYWORDS,
} from '../engine/heuristic';
import {
  ROOT_SENSITIVE_PATHS,
  HOME_SENSITIVE_PATHS,
  CREDENTIAL_PATHS,
  PASSWORD_MODIFY_PATTERNS,
  USER_DELETION_PATTERNS,
  INTENT_DEVIATION_PATTERNS,
} from '../engine/logic-rules';

describe('归一化规则加载器 (rules-loader)', () => {
  it('L1 计数稳定', () => {
    const l1 = loadL1();
    expect(l1.dangerous_commands.length).toBe(56);
    expect(l1.injection_detection.length).toBe(46);
    expect(l1.sensitive_path_access.length).toBe(42);  // +3: .config/agentmoss 目录/config.json + .agentmoss/brain；+2: .ssh/.aws 目录级（收紧 home 根删除后凭据目录删除兜底）
  });

  it('L2 计数稳定', () => {
    const l2 = loadL2();
    expect(l2.intent_consistency.length).toBe(2);
    expect(l2.password_modify_consent.length).toBe(7);
    expect(l2.user_deletion_consent.length).toBe(5);
  });

  it('L3 skills 计数', () => {
    const l3 = loadL3();
    let total = 0;
    for (const cat of Object.values(l3)) {
      const v = cat as Record<string, unknown>;
      if (v && typeof v === 'object') total += Object.keys(v).length;
    }
    expect(total).toBe(13);
  });

  it('检测常量从 JSON 加载（与 seed 计数一致）', () => {
    const l1 = loadL1();
    expect(DANGEROUS_PATTERNS.length).toBe(l1.dangerous_commands.length);
    expect(INJECTION_KEYWORDS.length).toBe(l1.injection_detection.length);
    // 敏感路径三数组合计 = JSON 敏感路径数
    const total = ROOT_SENSITIVE_PATHS.length + HOME_SENSITIVE_PATHS.length + CREDENTIAL_PATHS.length;
    expect(total).toBe(l1.sensitive_path_access.length);
    // L2
    expect(PASSWORD_MODIFY_PATTERNS.length).toBe(loadL2().password_modify_consent.length);
    expect(USER_DELETION_PATTERNS.length).toBe(loadL2().user_deletion_consent.length);
    expect(INTENT_DEVIATION_PATTERNS.length).toBe(loadL2().intent_consistency.length);
  });

  it('seed 生成与 JSON 计数一致', () => {
    const d = generateSourceDefaults();
    const l1 = loadL1();
    expect(d.L1_rules.dangerous_commands.rules!.length).toBe(l1.dangerous_commands.length);
    expect(d.L1_rules.injection_detection.rules!.length).toBe(l1.injection_detection.length);
    expect(d.L1_rules.sensitive_path_access.rules!.length).toBe(l1.sensitive_path_access.length);
  });

  it('用户数据目录覆盖优先（AGENT_MOSS_DATA_DIR/rules/mc_rules.json 优先于内置）', async () => {
    const os = await import('os');
    const path = await import('path');
    const fs = await import('fs');
    // RULES_DIR_CANDS 在模块级求值，须在设 env 后重载模块才能测到覆盖生效
    const dir = await import('fs').then(m => m.mkdtempSync(path.join(os.tmpdir(), 'am-rules-')));
    const rulesDir = path.join(dir, 'rules');
    fs.mkdirSync(rulesDir, { recursive: true });
    // 用户自定义 mc_rules.json：只含 1 条规则，无内置 ap
    fs.writeFileSync(path.join(rulesDir, 'mc_rules.json'), JSON.stringify({
      ap_patterns: { only_user_ap: ['xyz'] },
      rules: [{ id: 'user-custom-001', type: 'ltl', formula: ['F', ['ap', 'only_user_ap']], risk_level: 'high', action: 'block', reason: '用户自定义规则' }],
    }));
    const old = process.env.AGENT_MOSS_DATA_DIR;
    process.env.AGENT_MOSS_DATA_DIR = dir;
    vi.resetModules();
    try {
      const { loadMC, loadL1 } = await import('../infra/rules-loader');
      const mc = loadMC();
      expect(mc.rules).toHaveLength(1);
      expect(mc.rules[0].id).toBe('user-custom-001');
      // 未覆盖的 L1 仍读内置种子
      expect(loadL1().dangerous_commands.length).toBe(56);
    } finally {
      if (old === undefined) delete process.env.AGENT_MOSS_DATA_DIR; else process.env.AGENT_MOSS_DATA_DIR = old;
      vi.resetModules();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
