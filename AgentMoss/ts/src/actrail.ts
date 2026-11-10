/**
 * AcTrail enforcement event reporter for TypeScript.
 *
 * Writes AgentMoss allow/deny decisions as Enforcement events to AcTrail's
 * SQLite storage, enabling unified agent behavior audit trails.
 *
 * Configuration (environment variables):
 *   ACTRAIL_ENABLED: Set to "1" to enable reporting (default: disabled)
 *   ACTRAIL_STORAGE_PATH: Path to AcTrail SQLite DB (default: /tmp/actrail.sqlite)
 *   ACTRAIL_TIMEOUT_MS: Write timeout in milliseconds (default: 100)
 */

import * as fs from 'fs';
import * as path from 'path';

/** AcTrail key=value escape (mirrors Rust encode_map) */
function escape(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/\n/g, '\\n').replace(/=/g, '\\e');
}

/** Convert session_id string to u64 trace_id (SHA-256 based, masked to signed 64-bit) */
function sessionToTraceId(sessionId: string): number {
  // Simple hash - not cryptographic, but sufficient for ID generation
  let hash = 0;
  for (let i = 0; i < sessionId.length; i++) {
    const char = sessionId.charCodeAt(i);
    hash = ((hash << 5) - hash + char) | 0;
  }
  // Combine with length for better distribution, mask to signed 64-bit
  return Math.abs((hash * 31 + sessionId.length) % Number.MAX_SAFE_INTEGER);
}

export interface ActrailReportOptions {
  traceId: string;
  decision: 'allow' | 'deny';
  toolName: string;
  toolCommand: string;
  sessionId: string;
  prompt?: string;
  riskLevel?: string;
  riskType?: string;
  reason?: string;
  violatedLayers?: string[];
  confidence?: number;
  durationMs?: number;
}

let dbConnected = false;
let dbPath = '';

function isEnabled(): boolean {
  return process.env.ACTRAIL_ENABLED === '1' || process.env.ACTRAIL_ENABLED === 'true';
}

function getStoragePath(): string {
  return process.env.ACTRAIL_STORAGE_PATH || '/tmp/actrail.sqlite';
}

/**
 * Report an enforcement event to AcTrail (fire-and-forget).
 * Returns true if written, false if disabled or write failed.
 */
export function reportEnforcementEvent(opts: ActrailReportOptions): boolean {
  if (!isEnabled()) return false;

  const storagePath = getStoragePath();
  if (!fs.existsSync(storagePath)) return false;

  try {
    // Dynamic import - better-sqlite3 is an optional dependency
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    let Database: any;
    try {
      Database = require('better-sqlite3');
    } catch {
      console.debug('[AgentMoss] better-sqlite3 not installed, AcTrail reporting disabled');
      return false;
    }

    const db = new Database(storagePath, { timeout: 100, readonly: false });

    // Verify events table exists
    const tableCheck = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='events'"
    ).get();
    if (!tableCheck) {
      db.close();
      return false;
    }

    const nowNs = BigInt(Date.now()) * 1000000n;
    const eventId = Number(nowNs % BigInt(2 ** 62));
    const traceIdInt = sessionToTraceId(opts.traceId);

    // Build payload fields in AcTrail's key=value format
    const rawFields: Record<string, string> = {
      'backend': 'agent-moss',
      'operation': 'tool_call',
      'decision': opts.decision,
      'result': opts.decision === 'allow' ? 'allowed' : 'denied',
      'tool.name': opts.toolName,
      'tool.command': (opts.toolCommand || '').slice(0, 500),
      'agent.session_id': opts.sessionId,
      'agent.prompt': (opts.prompt || '').slice(0, 500),
      'risk.level': opts.riskLevel || '',
      'risk.type': opts.riskType || '',
      'reason': (opts.reason || '').slice(0, 500),
      'violated_layers': (opts.violatedLayers || []).join(','),
      'confidence': String(opts.confidence ?? 100),
      'duration_ms': (opts.durationMs ?? 0).toFixed(1),
    };
    const payloadFields = Object.entries(rawFields)
      .map(([k, v]) => `${escape(k)}=${escape(v)}`)
      .join('\n');

    db.prepare(`
      INSERT OR REPLACE INTO events (
        event_id, trace_id, observed_at,
        process_pid, process_task_id, process_start_ticks,
        process_pid_namespace, process_generation,
        collector, kind,
        bootstrap_observed, metadata_partial, policy_modified,
        payload_variant, payload_fields, payload_bytes,
        policy_verdict, policy_note,
        policy_redactions, policy_truncations
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      eventId,
      traceIdInt,
      Number(nowNs),
      process.pid,
      0,
      0,
      null,
      0,
      'agent-moss',
      'enforcement',
      0,
      0,
      0,
      'enforcement',
      payloadFields,
      '',
      opts.decision === 'allow' ? 'allow' : 'drop',
      opts.reason || '',
      '[]',
      '[]'
    );

    db.close();
    return true;
  } catch (err) {
    // Non-fatal - never block the response
    console.debug(`[AgentMoss] AcTrail write failed (non-fatal): ${(err as Error).message}`);
    return false;
  }
}
