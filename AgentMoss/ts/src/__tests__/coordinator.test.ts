import { describe, it, expect } from 'vitest';
import { runAnalysis, type AnalysisInput } from '../engine/coordinator';

// 本文件测 L1/L2 白名单与静态检测逻辑（skill 白名单、OpenDesk safe-action-types 豁免、
// agent 隔离），不依赖 L3 LLM。显式禁用 LLM，避免配置了 LLM key 后这些用例
// 走 L3 语义判定导致判定波动（同 json-cases.test.ts 对 L1/L2 case 设 DISABLE_LLM 的做法）。
process.env.AGENT_MOSS_DISABLE_LLM = '1';

function makeInput(partial: Partial<AnalysisInput> = {}): AnalysisInput {
  return {
    sessionId: 'test',
    promptSession: '',
    actionHistory: [],
    aNext: { actionType: 'bash', actionDetail: 'ls' },
    reason: '',
    osType: 'linux',
    cwd: '/tmp',
    agentId: '',
    ...partial,
  };
}

describe('Coordinator: Three-layer defense', () => {
  describe('Trusted skill bypass', () => {
    it('should allow xiaoo-guardian skill directly', async () => {
      const result = await runAnalysis(makeInput({
        aNext: { actionType: 'skill', actionDetail: 'xiaoo-guardian' },
        agentId: 'xiaoo',
      }));
      expect(result.allowed).toBe(true);
      expect(result.source).toBe('whitelist_bypass');
    });

    it('should not bypass untrusted skills', async () => {
      const result = await runAnalysis(makeInput({
        aNext: { actionType: 'skill', actionDetail: 'malicious-skill' },
        agentId: 'xiaoo',
      }));
      // Untrusted skill is not in whitelist, continues to L2/L3
      // With LLM disabled, it should Allow if no violations
      expect(result.allowed).toBe(true);
    });
  });

  describe('OpenDesk agent safe-action-types bypass', () => {
    // OpenDesk 的 memory-*/todomgr-*/planning-* 是纯数据/只读操作，
    // 走 L3 LLM 耗时 1~137s 无意义。agent_moss/agents/opendesk/rules.json
    // 的 builtin_safe_action_types 把它们豁免 L2+L3。
    it('should bypass memory-addMemory (prefix match)', async () => {
      const result = await runAnalysis(makeInput({
        aNext: { actionType: 'memory-addMemory', actionDetail: 'memory-addMemory: scope=workspace' },
        agentId: 'opendesk',
      }));
      expect(result.allowed).toBe(true);
      expect(result.source).toBe('whitelist_bypass');
    });

    it('should bypass todomgr-TodoWrite (prefix match)', async () => {
      const result = await runAnalysis(makeInput({
        aNext: { actionType: 'todomgr-TodoWrite', actionDetail: 'todos update' },
        agentId: 'opendesk',
      }));
      expect(result.allowed).toBe(true);
      expect(result.source).toBe('whitelist_bypass');
    });

    it('should bypass mailbox-getEmailList (exact name match)', async () => {
      const result = await runAnalysis(makeInput({
        aNext: { actionType: 'mailbox-getEmailList', actionDetail: 'mailbox-getEmailList' },
        agentId: 'opendesk',
      }));
      expect(result.allowed).toBe(true);
      expect(result.source).toBe('whitelist_bypass');
    });

    it('should NOT bypass mailbox-sendEmail (exfiltration risk, keeps L3)', async () => {
      // sendEmail 不在白名单 → 不命中 whitelist_bypass（其余放行与否取决于后续层，
      // 这里只守护"不被前缀误豁免"，不断言最终 Allow/Deny）
      const result = await runAnalysis(makeInput({
        aNext: { actionType: 'mailbox-sendEmail', actionDetail: 'mailbox-sendEmail: to=x@x.com' },
        agentId: 'opendesk',
      }));
      expect(result.source).not.toBe('whitelist_bypass');
    });

    it('should NOT bypass mailbox-replyEmail (exfiltration risk, keeps L3)', async () => {
      const result = await runAnalysis(makeInput({
        aNext: { actionType: 'mailbox-replyEmail', actionDetail: 'mailbox-replyEmail: uid=abc' },
        agentId: 'opendesk',
      }));
      expect(result.source).not.toBe('whitelist_bypass');
    });

    it('should NOT bypass skill- (arbitrary capability, keeps L3)', async () => {
      const result = await runAnalysis(makeInput({
        aNext: { actionType: 'skill-someTool', actionDetail: 'skill-someTool' },
        agentId: 'opendesk',
      }));
      expect(result.source).not.toBe('whitelist_bypass');
    });

    it('should not apply opendesk whitelist to xiaoo (agent isolation)', async () => {
      // xiaoo 无 opendesk rules.json → memory-addMemory 不命中白名单
      const result = await runAnalysis(makeInput({
        aNext: { actionType: 'memory-addMemory', actionDetail: 'memory-addMemory' },
        agentId: 'xiaoo',
      }));
      expect(result.source).not.toBe('whitelist_bypass');
    });

    it('should not apply opendesk whitelist without agent_id (generic mode)', async () => {
      const result = await runAnalysis(makeInput({
        aNext: { actionType: 'memory-addMemory', actionDetail: 'memory-addMemory' },
        agentId: '',
      }));
      expect(result.source).not.toBe('whitelist_bypass');
    });
  });

  describe('System info command bypass', () => {
    const systemCommands = ['whoami', 'hostname', 'uname', 'date', 'id', 'tty', 'env', 'arch', 'uptime', 'groups', 'logname', 'printenv'];

    for (const cmd of systemCommands) {
      it(`should allow ${cmd}`, async () => {
        const result = await runAnalysis(makeInput({
          aNext: { actionType: 'bash', actionDetail: cmd },
        }));
        expect(result.allowed).toBe(true);
        expect(result.source).toBe('whitelist_bypass');
      });
    }
  });

  describe('Password modification interception', () => {
    it('should deny pipe to passwd', async () => {
      const result = await runAnalysis(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'echo pass | passwd' },
      }));
      expect(result.allowed).toBe(false);
      expect(result.riskLevel).toBe('high');
    });

    it('should deny passwd --stdin', async () => {
      const result = await runAnalysis(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'passwd --stdin user' },
      }));
      expect(result.allowed).toBe(false);
    });

    it('should deny chpasswd', async () => {
      const result = await runAnalysis(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'chpasswd' },
      }));
      expect(result.allowed).toBe(false);
    });
  });

  describe('Safety fallback (pipe tail scan)', () => {
    it('should not whitelist echo when piped to passwd', async () => {
      const result = await runAnalysis(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'echo pass | passwd' },
      }));
      // echo is safe, but full command contains | passwd
      // Safety fallback should block whitelist bypass
      expect(result.allowed).toBe(false);
    });

    // Bug3: echo 带重定向写不应被 fully_safe 白名单放行。
    // 旧逻辑 is_fully_safe_bash_command 只看首命令名（echo），忽略 >/>>，
    // 导致 `echo x > /tmp/file` 被白名单跳过 L2。修复后查重定向，不走 whitelist_bypass。
    it('Bug3: echo with redirect should not be whitelisted as fully_safe', async () => {
      const result = await runAnalysis(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'echo x > /tmp/agentmoss_bug3_test.txt' },
      }));
      // 不应走 whitelist_bypass（source 不应是 whitelist_bypass）
      expect(result.source).not.toBe('whitelist_bypass');
      // echo 无重定向仍应白名单放行（对照）
      const control = await runAnalysis(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'echo hello' },
      }));
      expect(control.source).toBe('whitelist_bypass');
    });
  });

  describe('Layer 1 direct intercept', () => {
    it('should deny rm -rf /', async () => {
      const result = await runAnalysis(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'rm -rf /' },
      }));
      expect(result.allowed).toBe(false);
      expect(result.riskLevel).toBe('critical');
    });

    it('should deny chmod 777', async () => {
      const result = await runAnalysis(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'chmod 777 /tmp/file' },
      }));
      expect(result.allowed).toBe(false);
    });
  });

  describe('Layer 2 sensitive path', () => {
    it('should deny /etc/shadow access', async () => {
      const result = await runAnalysis(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'cat /etc/shadow' },
      }));
      expect(result.allowed).toBe(false);
    });
  });

  describe('Safe commands', () => {
    it('should allow ls', async () => {
      const result = await runAnalysis(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'ls -la /tmp' },
      }));
      expect(result.allowed).toBe(true);
    });

    it('should allow cat (readonly, skip L3)', async () => {
      const result = await runAnalysis(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'cat /tmp/test.txt' },
      }));
      expect(result.allowed).toBe(true);
    });

    it('should allow fully safe tools', async () => {
      const result = await runAnalysis(makeInput({
        aNext: { actionType: 'glob', actionDetail: '**/*.ts' },
      }));
      expect(result.allowed).toBe(true);
    });
  });

  describe('Formal engine observe mode + witness semantics (L2.2)', () => {
    // witness 语义：实时判定只当当前动作（aNext）补全链/触发后置外传才判违规——
    // 历史中已随机出现的完整链不再误伤后续良性动作（修复"历史全局匹配 → 永久拒绝锁定"FP）。
    // a_next 用不进安全只读白名单的 cat（echo hello 会被 whitelist_bypass 提前放行）。
    const prefixHist = [
      { sessionId: 'A', actionHistory: [{ actionType: 'bash', actionDetail: 'flask --app app.py run' }] },
      { sessionId: 'B', actionHistory: [
        { actionType: 'bash', actionDetail: "python -c 'import subprocess; subprocess.run()'" },
      ] },
    ];
    const fullHist = [
      { sessionId: 'A', actionHistory: [{ actionType: 'bash', actionDetail: 'flask --app app.py run' }] },
      { sessionId: 'B', actionHistory: [
        { actionType: 'bash', actionDetail: "python -c 'import subprocess; subprocess.run()'" },
        { actionType: 'bash', actionDetail: 'nc -z 10.0.0.5 22' },
      ] },
    ];
    const nextScan = { actionType: 'bash', actionDetail: 'nc -z 10.0.0.5 22' };   // 补全 SCAN
    const nextCat = { actionType: 'bash', actionDetail: 'cat /tmp/x.txt' };       // 良性

    it('witness: aNext completing the chain should block', async () => {
      const result = await runAnalysis(makeInput({
        sessionHistory: prefixHist,
        aNext: nextScan,
      }));
      expect(result.allowed).toBe(false);
      expect(result.violatedLayers).toContain('L2.2');
    });

    it('witness: full chain in history should NOT block benign aNext (FP fix)', async () => {
      const result = await runAnalysis(makeInput({
        sessionHistory: fullHist,
        aNext: nextCat,
      }));
      expect(result.allowed).toBe(true);
      expect(result.violatedLayers).not.toContain('L2.2');
    });

    it('observe mode: records but does not block (L2.2 still surfaced)', async () => {
      process.env.AGENT_MOSS_FORMAL_OBSERVE = '1';
      try {
        const result = await runAnalysis(makeInput({
          sessionHistory: prefixHist,
          aNext: nextScan,
        }));
        expect(result.allowed).toBe(true);
        expect(result.violatedLayers).toContain('L2.2');
      } finally {
        delete process.env.AGENT_MOSS_FORMAL_OBSERVE;
      }
    });

    it('observe mode: clean history control (no false L2.2)', async () => {
      process.env.AGENT_MOSS_FORMAL_OBSERVE = '1';
      try {
        const result = await runAnalysis(makeInput({
          sessionHistory: [{ sessionId: 'A', actionHistory: [{ actionType: 'bash', actionDetail: 'ls -la' }] }],
          aNext: nextCat,
        }));
        expect(result.allowed).toBe(true);
        expect(result.violatedLayers).not.toContain('L2.2');
      } finally {
        delete process.env.AGENT_MOSS_FORMAL_OBSERVE;
      }
    });
  });
});
