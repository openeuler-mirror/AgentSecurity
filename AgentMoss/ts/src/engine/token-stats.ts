/**
 * Token usage statistics — record and query LLM token consumption.
 *
 * Mirrors Python agent_moss/infra/token_stats.py.
 *
 * Storage: JSON file at <data_root>/agent_moss_token_stats.json
 * (default ~/.config/agentmoss). With AGENT_MOSS_INSTANCE the file is isolated
 * to <data_root>/<instance>/ (see infra/paths.ts). env override
 * AGENT_MOSS_TOKEN_STATS_PATH wins. Whole-file rewrite per record (not append).
 * Max 10000 records, oldest trimmed.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, unlinkSync } from 'fs';
import { join } from 'path';
import { getTokenStatsPath } from '../infra/paths';

const ENV_STATS_PATH = 'AGENT_MOSS_TOKEN_STATS_PATH';
const MAX_RECORDS = 10000;

export interface TokenUsageRecord {
  timestamp?: string;      // ISO with milliseconds; auto-filled if omitted
  sessionId: string;
  step: string;           // "L3_security_judge" | "step2_policy_gen"
  model: string;
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
}

interface RawRecord {
  timestamp: string;
  session_id: string;
  step: string;
  model: string;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
}

interface Aggregated {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  calls: number;
}

export interface TokenStatsSummary {
  total_prompt_tokens: number;
  total_completion_tokens: number;
  total_tokens: number;
  total_calls: number;
  by_step: Record<string, Aggregated>;
  by_model: Record<string, Aggregated>;
  by_date: Record<string, Aggregated>;
}

export interface TokenTrend {
  dates: string[];
  models: string[];
  series: Record<string, Record<string, number>>;
}

function getStatsPath(): string {
  const envPath = process.env[ENV_STATS_PATH];
  if (envPath) return envPath;
  return getTokenStatsPath();
}

function loadAllRecords(statsPath: string): RawRecord[] {
  if (!existsSync(statsPath)) return [];
  try {
    const data = JSON.parse(readFileSync(statsPath, 'utf-8'));
    if (Array.isArray(data)) return data;
    if (data && Array.isArray(data.records)) return data.records;
    return [];
  } catch (e) {
    return [];
  }
}

function saveRecords(statsPath: string, records: RawRecord[]): void {
  try {
    const dir = statsPath.substring(0, statsPath.lastIndexOf('/'));
    if (dir && !existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(statsPath, JSON.stringify(records, null, 2), 'utf-8');
  } catch (e) {
    // best-effort
  }
}

/** Record a single LLM call's token usage. */
export function recordTokenUsage(record: TokenUsageRecord): void {
  const statsPath = getStatsPath();
  const records = loadAllRecords(statsPath);
  records.push({
    timestamp: record.timestamp || new Date().toISOString(),
    session_id: record.sessionId,
    step: record.step,
    model: record.model,
    prompt_tokens: record.promptTokens,
    completion_tokens: record.completionTokens,
    total_tokens: record.totalTokens,
  });
  if (records.length > MAX_RECORDS) {
    records.splice(0, records.length - MAX_RECORDS);
  }
  saveRecords(statsPath, records);
}

function filterByDate(
  records: RawRecord[],
  days: number = 0,
  startDate?: string | null,
  endDate?: string | null,
): RawRecord[] {
  if (startDate || endDate) {
    let startDt = startDate ? new Date(startDate) : new Date(-8640000000000000);
    let endDt = endDate ? new Date(endDate) : undefined;
    if (endDate) {
      const e = new Date(endDate);
      e.setHours(23, 59, 59, 999);
      endDt = e;
    }
    const endMs = endDt ? endDt.getTime() : Number.MAX_SAFE_INTEGER;
    return records.filter(r => {
      try {
        const ts = new Date(r.timestamp).getTime();
        return ts >= startDt.getTime() && ts <= endMs;
      } catch { return true; }
    });
  } else if (days > 0) {
    const cutoff = Date.now() - days * 86400000;
    return records.filter(r => {
      try { return new Date(r.timestamp).getTime() >= cutoff; }
      catch { return true; }
    });
  }
  return records;
}

function aggregate(records: RawRecord[]): {
  totalPrompt: number; totalCompletion: number; totalTotal: number;
  byStep: Record<string, Aggregated>; byModel: Record<string, Aggregated>; byDate: Record<string, Aggregated>;
} {
  let totalPrompt = 0, totalCompletion = 0, totalTotal = 0;
  const byStep: Record<string, Aggregated> = {};
  const byModel: Record<string, Aggregated> = {};
  const byDate: Record<string, Aggregated> = {};

  const bucket = (b: Record<string, Aggregated>, key: string, r: RawRecord) => {
    const e = b[key] || (b[key] = { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0, calls: 0 });
    e.prompt_tokens += r.prompt_tokens || 0;
    e.completion_tokens += r.completion_tokens || 0;
    e.total_tokens += r.total_tokens || 0;
    e.calls += 1;
  };

  for (const r of records) {
    totalPrompt += r.prompt_tokens || 0;
    totalCompletion += r.completion_tokens || 0;
    totalTotal += r.total_tokens || 0;
    bucket(byStep, r.step || 'unknown', r);
    bucket(byModel, r.model || 'unknown', r);
    let dateKey = 'unknown';
    try {
      dateKey = new Date(r.timestamp).toISOString().slice(0, 10);
    } catch { /* keep unknown */ }
    bucket(byDate, dateKey, r);
  }

  // by_date sorted desc by date
  const sortedDate = Object.keys(byDate).sort((a, b) => (a < b ? 1 : a > b ? -1 : 0));
  const sortedByDate: Record<string, Aggregated> = {};
  for (const k of sortedDate) sortedByDate[k] = byDate[k];

  return { totalPrompt, totalCompletion, totalTotal, byStep, byModel, byDate: sortedByDate };
}

export function getTokenStats(
  days: number = 0,
  startDate?: string | null,
  endDate?: string | null,
): TokenStatsSummary {
  const records = filterByDate(loadAllRecords(getStatsPath()), days, startDate, endDate);
  const a = aggregate(records);
  return {
    total_prompt_tokens: a.totalPrompt,
    total_completion_tokens: a.totalCompletion,
    total_tokens: a.totalTotal,
    total_calls: records.length,
    by_step: a.byStep,
    by_model: a.byModel,
    by_date: a.byDate,
  };
}

export function getRecentRecords(limit: number = 20, offset: number = 0): RawRecord[] {
  const records = loadAllRecords(getStatsPath());
  // 按时间升序存储，取"最近"需从末尾往前 offset 条再取 limit 条
  const start = Math.max(0, records.length - offset - limit);
  const end = records.length - offset;
  return records.slice(start, end);
}

/** 获取最近记录分页总数（供前端分页器使用） */
export function getRecentRecordsCount(): number {
  return loadAllRecords(getStatsPath()).length;
}

export function getTokenTrend(
  days: number = 0,
  startDate?: string | null,
  endDate?: string | null,
): TokenTrend {
  const records = filterByDate(loadAllRecords(getStatsPath()), days, startDate, endDate);
  const series: Record<string, Record<string, number>> = {};
  const datesSet = new Set<string>();
  for (const r of records) {
    let dateKey: string;
    try { dateKey = new Date(r.timestamp).toISOString().slice(0, 10); }
    catch { continue; }
    const model = r.model || 'unknown';
    const tokens = r.total_tokens || 0;
    datesSet.add(dateKey);
    series[model] = series[model] || {};
    series[model][dateKey] = (series[model][dateKey] || 0) + tokens;
  }
  const dates = Array.from(datesSet).sort();
  const models = Object.keys(series).sort();
  return { dates, models, series };
}

export function resetTokenStats(): void {
  const statsPath = getStatsPath();
  if (existsSync(statsPath)) {
    try { unlinkSync(statsPath); } catch { /* ignore */ }
  }
}
