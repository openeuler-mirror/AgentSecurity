/**
 * PatternMiner 测试（TS 镜像 Python test_pattern_miner.py）：
 * 数据驱动发现危险频繁子序列（预置链外的新形态）。
 */
import { describe, expect, it } from 'vitest';
import { mineDangerousPatterns, projectStages } from '../engine/formal-engine/pattern_miner';

function sessions(...seqs: string[][]): { sessionId: string; actionHistory: { actionType: string; actionDetail: string }[] }[] {
  return seqs.map((seq, i) => ({
    sessionId: `s${i}`,
    actionHistory: seq.map(detail => ({ actionType: 'bash', actionDetail: detail })),
  }));
}

describe('PatternMiner (TS)', () => {
  it('cred then listen detected (preset-chain blind spot)', () => {
    const out = mineDangerousPatterns(sessions(
      ['cat ~/.ssh/id_rsa', 'flask --app app.py run'],
      ['cat ~/.ssh/id_rsa', 'node server.js'],
      ['cat ~/.ssh/config', 'python -m http.server 8080'],
    ), 2);
    const pats = out.map(d => d.pattern.join('→'));
    expect(pats).toContain('CRED→LISTEN');
  });

  it('privesc then cred detected', () => {
    const out = mineDangerousPatterns(sessions(
      ['sudo -u root whoami', 'cat ~/.ssh/id_rsa'],
      ['sudo -u root id', 'cat /root/.aws/credentials'],
    ), 2);
    const pats = out.map(d => d.pattern.join('→'));
    expect(pats).toContain('PRIVESC→CRED');
  });

  it('normal flow not detected', () => {
    const out = mineDangerousPatterns(sessions(
      ['ls -la', 'npm install', 'npm run build'],
      ['cd repos && git pull', 'git push'],
    ), 2);
    expect(out).toEqual([]);
  });

  it('single frequent stage not candidate', () => {
    const out = mineDangerousPatterns(sessions(
      ['cat ~/.ssh/id_rsa'],
      ['cat ~/.ssh/id_rsa'],
      ['cat ~/.ssh/id_rsa'],
    ), 2);
    expect(out).toEqual([]);
  });

  it('min_sup respected', () => {
    const out = mineDangerousPatterns(sessions(
      ['cat ~/.ssh/id_rsa', 'flask --app a.py run'],
      ['ls'],
    ), 2);
    expect(out).toEqual([]);
  });

  it('projection compresses repeats', () => {
    expect(projectStages([
      { actionType: 'read', actionDetail: 'cat ~/.ssh/id_rsa' },
      { actionType: 'read', actionDetail: 'cat ~/.ssh/config' },
      { actionType: 'bash', actionDetail: 'nmap -sV 10.0.0.0/24' },
    ])).toEqual(['CRED', 'SCAN']);
  });
});