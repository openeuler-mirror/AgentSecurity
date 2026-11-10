/**
 * instance 数据目录隔离 + 数据归属用户 的单元测试。
 * 对齐 Python tests/test_instance_paths.py。
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { join } from 'path';
import { homedir } from 'os';

const saved = {
  instance: process.env.AGENT_MOSS_INSTANCE,
  dataRoot: process.env.AGENT_MOSS_DATA_DIR,
};

beforeEach(() => {
  delete process.env.AGENT_MOSS_INSTANCE;
  delete process.env.AGENT_MOSS_DATA_DIR;
});

afterEach(() => {
  if (saved.instance === undefined) delete process.env.AGENT_MOSS_INSTANCE;
  else process.env.AGENT_MOSS_INSTANCE = saved.instance;
  if (saved.dataRoot === undefined) delete process.env.AGENT_MOSS_DATA_DIR;
  else process.env.AGENT_MOSS_DATA_DIR = saved.dataRoot;
  vi.restoreAllMocks();
});

// 动态 import 以绕过模块级缓存（paths.ts 内部在 import 时求值 DEFAULT_DATA_ROOT）
async function freshTokenPath(): Promise<string> {
  const { getTokenStatsPath } = await import('../infra/paths');
  return getTokenStatsPath();
}

// root 探测分支：mock isRoot=true + resolveOwnerHome 返回用户家目录
async function freshTokenPathRoot(): Promise<string> {
  const paths = await import('../infra/paths');
  vi.spyOn(paths, 'isRoot').mockReturnValue(true);
  vi.spyOn(paths, 'resolveOwnerHome').mockReturnValue('/home/hkl');
  return paths.getTokenStatsPath();
}

describe('paths instance isolation', () => {
  it('无 instance → 默认路径', async () => {
    const p = await freshTokenPath();
    expect(p).toBe(join(homedir(), '.config', 'agentmoss', 'agent_moss_token_stats.json'));
  });

  it('有 instance → <data_root>/<instance>/ 子目录', async () => {
    process.env.AGENT_MOSS_INSTANCE = 'xiaoo';
    const p = await freshTokenPath();
    expect(p).toBe(join(homedir(), '.config', 'agentmoss', 'xiaoo', 'agent_moss_token_stats.json'));
  });

  it('root 运行时（env 未设）数据落到真实用户目录而非 /root', async () => {
    delete process.env.AGENT_MOSS_DATA_DIR;
    delete process.env.AGENT_MOSS_INSTANCE;
    const p = await freshTokenPathRoot();
    expect(p).toBe('/home/hkl/.config/agentmoss/agent_moss_token_stats.json');
  });

  it('root + instance 时 token 落到 <owner_home>/<instance>/', async () => {
    delete process.env.AGENT_MOSS_DATA_DIR;
    process.env.AGENT_MOSS_INSTANCE = 'xiaoo';
    const p = await freshTokenPathRoot();
    expect(p).toBe('/home/hkl/.config/agentmoss/xiaoo/agent_moss_token_stats.json');
  });

  it('AGENT_MOSS_DATA_DIR 覆盖数据根 + instance', async () => {
    process.env.AGENT_MOSS_DATA_DIR = '/home/hkl/.config/agentmoss';
    process.env.AGENT_MOSS_INSTANCE = 'opendesk';
    const p = await freshTokenPath();
    expect(p).toBe('/home/hkl/.config/agentmoss/opendesk/agent_moss_token_stats.json');
  });

  it('AGENT_MOSS_DATA_DIR 覆盖数据根，无 instance', async () => {
    process.env.AGENT_MOSS_DATA_DIR = '/tmp/am-data';
    const p = await freshTokenPath();
    expect(p).toBe('/tmp/am-data/agent_moss_token_stats.json');
  });
});