/**
 * Chain State Store — 有状态增量分析器的持久化层（TS 镜像 Python chain_state.py）。
 *
 * 按 agent 隔离地持久化 StatefulChainTracker 快照（时间线节点 + 链指针 + taint +
 * 存活资源）。TS 侧用 JSON 文件形态（无 sqlite 的鸿蒙/纯 Node 环境可运行），
 * 与 Python SQLite 形态语义一致。
 *
 * 路径：默认 ~/.agentmoss/stateful_chains_<hash>.json；env AGENT_MOSS_STATE_DIR 覆盖；
 * 测试注入显式 path。
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { createHash } from 'node:crypto';

import { StatefulChainTracker, AdvanceResult } from './stateful';

export function defaultStateDbPath(): string {
  const dir = process.env.AGENT_MOSS_STATE_DIR || path.join(os.homedir(), '.agentmoss');
  // agent 维度用哈希目录隔离（避免与其他实例冲突），简单按 user 哈希
  const tag = createHash('sha1').update('agentmoss-stateful').digest('hex').slice(0, 8);
  return path.join(dir, `stateful_chains_${tag}.json`);
}

export interface ChainStateFile {
  [agentId: string]: {
    state: Record<string, unknown>;
    updated_at: string;
  };
}

export class ChainStateStore {
  private filePath: string;
  private data: ChainStateFile;
  private _timer: ReturnType<typeof setTimeout> | null = null;
  private _flushDelayMs = 50;

  constructor(filePath = '') {
    this.filePath = filePath || defaultStateDbPath();
    this.data = this._read();
  }

  private _read(): ChainStateFile {
    try {
      if (fs.existsSync(this.filePath)) {
        const raw = fs.readFileSync(this.filePath, 'utf-8');
        return JSON.parse(raw) as ChainStateFile;
      }
    } catch {
      /* 损坏/首启 → 空 */
    }
    return {};
  }

  /** 防抖写入：save() 只改内存，后台批量落盘（避免每次 tool call 全量 writeFileSync）。 */
  private _scheduleWrite(): void {
    if (this._timer !== null) return;
    this._timer = setTimeout(() => {
      this._timer = null;
      try {
        fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
        fs.writeFileSync(this.filePath, JSON.stringify(this.data, null, 2), 'utf-8');
      } catch {
        // 落盘失败不阻断分析（下次再试）
      }
    }, this._flushDelayMs);
  }

  /** 立即落盘（测试/关停前调用，保证状态不丢）。 */
  flush(): void {
    if (this._timer !== null) {
      clearTimeout(this._timer);
      this._timer = null;
    }
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      fs.writeFileSync(this.filePath, JSON.stringify(this.data, null, 2), 'utf-8');
    } catch {
      /* 忽略 */
    }
  }

  load(agentId: string): StatefulChainTracker | null {
    const entry = this.data[agentId];
    if (!entry) return null;
    const t = new StatefulChainTracker(agentId);
    t.restore(entry.state);
    return t;
  }

  save(tracker: StatefulChainTracker): void {
    this.data[tracker.agentId] = {
      state: tracker.toSnapshot(),
      updated_at: new Date().toISOString(),
    };
    this._scheduleWrite();
  }

  delete(agentId: string): void {
    delete this.data[agentId];
    this._scheduleWrite();
  }

  applyAction(
    agentId: string,
    aNext: { actionType?: string; actionDetail?: string },
    sessionId: string,
    isError = false,
  ): AdvanceResult {
    const t = this.load(agentId) || new StatefulChainTracker(agentId);
    const r = t.advance({ aNext, sessionId, isError });
    this.save(t);
    return r;
  }

  seedAndApply(
    agentId: string,
    sessions: { sessionId?: string; actionHistory?: { actionType?: string; actionDetail?: string }[] }[],
    aNext: { actionType?: string; actionDetail?: string },
    sessionId = 'current',
    isError = false,
  ): AdvanceResult {
    const t = this.load(agentId) || new StatefulChainTracker(agentId);
    t.seed(sessions);
    const r = t.advance({ aNext, sessionId, isError });
    this.save(t);
    return r;
  }
}

let _store: ChainStateStore | null = null;

export function getChainStateStore(filePath = ''): ChainStateStore {
  if (_store === null || (filePath && filePath !== _store['filePath'])) {
    _store = new ChainStateStore(filePath);
  }
  return _store;
}