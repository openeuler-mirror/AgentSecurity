/**
 * ChainStateStore(TS JSON 形态) 测试 — 镜像 Python test_chain_state.py 的存储语义。
 * 验证：
 * - 同一实例跨"重启"（新实例同文件）恢复，跨 session 前序不丢；
 * - 不同 agent 隔离；
 * - seed 后 pending 前序链可列。
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { ChainStateStore } from '../engine/formal-engine';

const listener = () => ({ actionType: 'bash', actionDetail: 'nohup python3 ~/devtools/admin_api.py > /dev/null 2>&1 &' });
const execAction = () => ({ actionType: 'bash', actionDetail: 'add POST /exec endpoint using subprocess shell=True' });
const scan = () => ({ actionType: 'bash', actionDetail: 'port scan: run nc -z -w1 192.168.1.22 22' });

let dir: string;

function newStore(): ChainStateStore {
  return new ChainStateStore(path.join(dir, 'store.json'));
}

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-state-'));
});

afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

describe('ChainStateStore (TS)', () => {
  it('persists across reopen (new instance, same file)', () => {
    let s = newStore();
    s.applyAction('agentA', listener(), 'A');
    s.applyAction('agentA', execAction(), 'B');
    s.flush(); // debounce 落盘（模拟重启前的同步 flush）

    s = newStore(); // "重启"
    const r = s.applyAction('agentA', scan(), 'C');
    expect(r.matched).not.toBeNull();
    expect(r.matched!.chainId).toBe('listener-exec-scan');
    expect(r.shouldBlock).toBe(true);
  });

  it('agents are isolated', () => {
    const s = newStore();
    s.applyAction('agentA', listener(), 'A');
    s.applyAction('agentB', listener(), 'A');
    const ra = s.applyAction('agentA', execAction(), 'B');
    const rb = s.applyAction('agentB', scan(), 'C');
    expect(rb.matched).toBeNull();
    expect(ra.pendingPrefixes.some(p => p.matched === 2)).toBe(true);
  });

  it('seed then pending prefixes listed', () => {
    const s = newStore();
    s.seedAndApply(
      'seedA',
      [
        { sessionId: 'A', actionHistory: [listener()] },
        { sessionId: 'B', actionHistory: [execAction()] },
      ],
      { actionType: 'bash', actionDetail: 'echo nothing' }, // irrelevant advance
      'Z',
    );
    const track = s.load('seedA');
    expect(track).not.toBeNull();
    const pend = track!.pendingPrefixes;
    const hit = pend.find(p => p.chainId === 'listener-exec-scan');
    expect(hit).toBeDefined();
    expect(hit!.matched).toBe(2);
    expect(hit!.nextStage).toBe('SCAN');
  });
});