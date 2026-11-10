import { describe, it, expect } from 'vitest';
import { buildPrompt } from '../engine/llm-analyzer';
import { matchSkills } from '../engine/skill-loader';
import { loadTemplates } from '../engine/template-loader';
import type { AnalysisInput } from '../engine/coordinator';

function makeInput(partial: Partial<AnalysisInput> = {}): AnalysisInput {
    return {
        sessionId: 'test',
        promptSession: '帮我把日志显示bug记录到memory',
        actionHistory: [],
        aNext: { actionType: 'memory-addMemory', actionDetail: 'memory-addMemory: scope=workspace' },
        reason: '记录工作区关键事实',
        osType: 'linux',
        cwd: '/tmp',
        ...partial,
    } as AnalysisInput;
}

describe('LLM analyzer: security_judge template', () => {
    it('should load security_judge template', () => {
        const templates = loadTemplates();
        expect(templates['security_judge']).toBeTruthy();
        // security_judge 模板特征：判断动作是否允许
        expect(templates['security_judge']).toContain('判断一个待执行的动作是否应该被允许');
    });

    it('buildPrompt should use security_judge template, not Cerberus prompt1/prompt2', () => {
        const templates = loadTemplates();
        const input = makeInput();
        const prompt = buildPrompt(
            input,
            { heuristic: null, logic: null },
            [],
            templates,
            undefined
        );

        // security_judge 模板特征文本应出现
        expect(prompt).toContain('判断一个待执行的动作是否应该被允许');
        // Cerberus 策略模板特征不应出现（prompt1 输出 TOML，prompt2 输出 compliant）
        expect(prompt).not.toContain('Landlock');
        expect(prompt).not.toContain('TOML');
        expect(prompt).not.toContain('compliant');
    });

    it('buildPrompt should fill placeholders and unescape JSON braces', () => {
        const templates = loadTemplates();
        const input = makeInput({ reason: '测试理由XYZ' });
        const prompt = buildPrompt(
            input,
            { heuristic: null, logic: null },
            [],
            templates,
            undefined
        );

        // 占位符被填充
        expect(prompt).toContain('测试理由XYZ');
        expect(prompt).toContain('memory-addMemory');
        // {{ }} 已还原为 { }（JSON 输出格式示例里应有 "allowed": true）
        expect(prompt).toContain('"allowed"');
        // 不应残留未替换的占位符
        expect(prompt).not.toContain('{prompt_session}');
        expect(prompt).not.toContain('{action_type}');
    });
});

describe('LLM analyzer: skill keyword de-misassociation', () => {
    it('memory-addMemory should NOT match resource_exhaustion_guard', () => {
        const matches = matchSkills(
            'memory-addMemory',
            'memory-addMemory: scope=workspace',
            '记录工作区关键事实'
        );
        const matchedNames = matches.map(m => m.skillName);
        // 关键：不再误关联到资源耗尽守卫
        expect(matchedNames).not.toContain('resource_exhaustion_guard');
    });

    it('real memory-exhaustion attack should still match resource_exhaustion_guard', () => {
        const matches = matchSkills('bash', ':(){ :|:& };: memory bomb', 'fork bomb');
        const matchedNames = matches.map(m => m.skillName);
        // 真实资源耗尽攻击仍应命中（靠 fork/bomb/memory bomb 等组合词）
        expect(matchedNames).toContain('resource_exhaustion_guard');
    });
});
