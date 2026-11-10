/**
 * Path resolution — unified data root + multi-instance (instance) isolation.
 *
 * Mirrors Python agent_moss/infra/paths.py.
 *
 * Solves two problems:
 *  1. Data-owner user directory: even when the service runs as root/systemd
 *     (started via `sudo systemctl`), AGENT_MOSS_DATA_DIR can point it at the
 *     "current user"'s data dir, so config / runtime / token all land in that
 *     user's directory instead of root's /root. Falls back to
 *     ~/.config/agentmoss (legacy behavior) when unset.
 *
 *  2. Token isolation by instance: services started by different agents
 *     (AGENT_MOSS_INSTANCE) don't share token-usage files. With an instance,
 *     tokens go to <data_root>/<instance>/agent_moss_token_stats.json; without
 *     one, to <data_root>/agent_moss_token_stats.json (default location).
 *
 * config / runtime are NOT split by instance (rules/config are shared); they
 * only follow the data root.
 */

import { join } from 'path';
import { homedir } from 'os';
import { readFileSync } from 'fs';

const ENV_DATA_ROOT = 'AGENT_MOSS_DATA_DIR';
const ENV_INSTANCE = 'AGENT_MOSS_INSTANCE';

const DEFAULT_DATA_ROOT = join(homedir(), '.config', 'agentmoss');

/** True when the process runs as root (systemd `sudo systemctl`). */
export function isRoot(): boolean {
  const getuid = (process as any).getuid;
  return typeof getuid === 'function' && getuid() === 0;
}

/** Resolve the "real user"'s home when running as root.
 *  Priority: SUDO_USER (sudo invoker) > LOGNAME/USER (login user) >
 *  first UID>=1000 ordinary user in /etc/passwd. Returns null if none found. */
export function resolveOwnerHome(): string | null {
  for (const name of [process.env.SUDO_USER, process.env.LOGNAME, process.env.USER]) {
    if (name && name !== 'root' && name !== '') {
      const home = homeOf(name);
      if (home) return home;
    }
  }
  // /etc/passwd fallback: first UID>=1000 ordinary user
  try {
    const passwd = readFileSync('/etc/passwd', 'utf-8');
    for (const line of passwd.split('\n')) {
      if (!line || line.startsWith('#')) continue;
      const parts = line.split(':');
      if (parts.length < 6) continue;
      const uid = parseInt(parts[2], 10);
      const name = parts[0];
      if (uid >= 1000 && name && !name.startsWith('_')) {
        return parts[5];
      }
    }
  } catch { /* ignore */ }
  return null;
}

function homeOf(name: string): string | null {
  try {
    const passwd = readFileSync('/etc/passwd', 'utf-8');
    for (const line of passwd.split('\n')) {
      if (!line || line.startsWith('#')) continue;
      const parts = line.split(':');
      if (parts.length >= 6 && parts[0] === name) {
        return parts[5];
      }
    }
  } catch { /* ignore */ }
  return null;
}

/** Data root directory.
 *  Priority: env AGENT_MOSS_DATA_DIR > ~/.config/agentmoss.
 *  BUT when running as root (any `sudo systemctl` service), automatically
 *  redirects to the real user's dir so config/runtime/token land there
 *  instead of /root. */
export function getDataRoot(): string {
  const envPath = process.env[ENV_DATA_ROOT];
  if (envPath) return envPath;
  if (isRoot()) {
    const ownerHome = resolveOwnerHome();
    if (ownerHome) {
      return join(ownerHome, '.config', 'agentmoss');
    }
  }
  return DEFAULT_DATA_ROOT;
}

/** Instance identifier (empty string when unset). */
export function getInstance(): string {
  const v = process.env[ENV_INSTANCE] || '';
  return v.trim().replace(/^[/\\]+|[/\\]+$/g, '');
}

/** Config file directory (config.json). Not split by instance; follows data root. */
export function getConfigDir(): string {
  return getDataRoot();
}

/** Runtime config directory (agent_moss_runtime.json + skills dir). Not split by instance. */
export function getRuntimeConfigDir(): string {
  return getDataRoot();
}

/**
 * Token stats file path.
 * With instance → <data_root>/<instance>/agent_moss_token_stats.json
 * Without → <data_root>/agent_moss_token_stats.json
 */
export function getTokenStatsPath(): string {
  const instance = getInstance();
  if (instance) {
    return join(getDataRoot(), instance, 'agent_moss_token_stats.json');
  }
  return join(getDataRoot(), 'agent_moss_token_stats.json');
}