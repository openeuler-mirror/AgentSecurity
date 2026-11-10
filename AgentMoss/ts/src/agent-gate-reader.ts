/**
 * AgentGate 本地存储读取器（TS 侧）— 镜像 Python server/agent_gate_reader.py。
 *
 * 让 TS server 的 /api/v1/review 直接读 AgentGate 本地存储，避免复制原始数据。
 * - SQLite：动态 require('better-sqlite3')（AgentMoss 有该依赖；不可用降级 JSON）
 * - JSON 目录：tool_calls/<session_id>.json 数组
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

export const DEFAULT_AGENTGATE_SQLITE = path.join(
  os.homedir(), '.local', 'share', 'agent_gate', 'agent_gate_ts.db'
);

export interface SessionLike {
  sessionId?: string;
  actionHistory?: { actionType: string; actionDetail: string }[];
}

function normalizeAction(row: Record<string, unknown>): { actionType: string; actionDetail: string } {
  return {
    actionType: String(row.action_type || row.tool_name || row.name || ''),
    actionDetail: String(row.action_detail || row.command || row.input || ''),
  };
}

function readJsonDir(dirPath: string, limit = 100000): SessionLike[] {
  const sessions = new Map<string, { actionType: string; actionDetail: string }[]>();
  try {
    const files = fs.readdirSync(dirPath).filter(f => f.endsWith('.json')).sort();
    for (const f of files.slice(-200)) {
      const sid = f.replace(/\.json$/, '');
      const raw = fs.readFileSync(path.join(dirPath, f), 'utf-8');
      const arr = JSON.parse(raw);
      if (!Array.isArray(arr)) continue;
      for (const item of arr) {
        if (!item || typeof item !== 'object') continue;
        const act = normalizeAction(item as Record<string, unknown>);
        if (act.actionDetail) {
          const list = sessions.get(sid) || [];
          list.push(act);
          sessions.set(sid, list);
        }
      }
      let total = 0;
      for (const v of sessions.values()) total += v.length;
      if (total > limit) break;
    }
  } catch {
    /* 目录不存在/非法 → 空 */
  }
  return [...sessions.entries()].map(([sessionId, actionHistory]) => ({ sessionId, actionHistory }));
}

function readSqlite(dbPath: string, limit = 100000): SessionLike[] {
  let Database: any;
  try {
    // dynamic require：better-sqlite3 不可用时降级 JSON
    Database = require('better-sqlite3');
  } catch {
    return [];
  }
  let db: any;
  try {
    db = new Database(dbPath, { readonly: true });
    const rows = db
      .prepare(
        `SELECT session_id, action_type, tool_name, action_detail, command, called_at
         FROM tool_calls ORDER BY called_at, id LIMIT ?`
      )
      .all(limit) as Record<string, unknown>[];
    const sessions = new Map<string, { actionType: string; actionDetail: string }[]>();
    for (const r of rows) {
      const sid = String(r.session_id || '');
      if (!sid) continue;
      const act = normalizeAction(r);
      if (!act.actionDetail) continue;
      const list = sessions.get(sid) || [];
      list.push(act);
      sessions.set(sid, list);
    }
    return [...sessions.entries()].map(([sessionId, actionHistory]) => ({ sessionId, actionHistory }));
  } catch {
    return [];
  } finally {
    try { db?.close(); } catch { /* ignore */ }
  }
}

/** 统一入口：dbPath 为目录(JSON) → JSON；否则 SQLite → 兜底 JSON 默认目录。 */
export function loadAgentGateSessions(dbPath = ''): SessionLike[] {
  if (dbPath) {
    try {
      if (fs.statSync(dbPath).isDirectory()) {
        return readJsonDir(dbPath);
      }
    } catch { /* not a dir */ }
    const sql = readSqlite(dbPath);
    if (sql.length > 0) return sql;
    return readJsonDir(dbPath);
  }
  // 无显式路径：先 SQLite 默认，JSON 兜底
  const sql = readSqlite(DEFAULT_AGENTGATE_SQLITE);
  if (sql.length > 0) return sql;
  const jsonDefault = path.join(os.homedir(), '.local', 'share', 'agent_gate', 'tool_calls');
  return readJsonDir(jsonDefault);
}