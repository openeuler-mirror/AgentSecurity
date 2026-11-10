/**
 * findFreePort 单测（块 A：端口动态分配）。
 * 照搬 OpenDesk findFreePort 策略：startPort 被占则递增找空闲。
 */
import net from 'node:net';
import { describe, it, expect } from 'vitest';
import { findFreePort } from '../server';

async function occupy(port: number): Promise<net.Server> {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.on('error', reject);
    s.listen(port, '127.0.0.1', () => resolve(s));
  });
}

describe('findFreePort', () => {
  it('returns startPort when free', async () => {
    const port = await findFreePort(9300, '127.0.0.1', 10);
    expect(port).toBe(9300);
  });

  it('skips occupied port to next free', async () => {
    const occ = await occupy(9301);
    try {
      const port = await findFreePort(9301, '127.0.0.1', 10);
      expect(port).toBe(9302);
    } finally {
      await new Promise<void>((r) => occ.close(() => r()));
    }
  });

  it('skips multiple occupied ports', async () => {
    const occ1 = await occupy(9310);
    const occ2 = await occupy(9311);
    try {
      const port = await findFreePort(9310, '127.0.0.1', 10);
      expect(port).toBe(9312);
    } finally {
      await new Promise<void>((r) => occ1.close(() => r()));
      await new Promise<void>((r) => occ2.close(() => r()));
    }
  });

  it('falls back to startPort when all occupied in scan range', async () => {
    const servers: net.Server[] = [];
    for (let i = 0; i < 5; i++) servers.push(await occupy(9320 + i));
    try {
      const port = await findFreePort(9320, '127.0.0.1', 5);
      expect(port).toBe(9320); // fallback
    } finally {
      for (const s of servers) await new Promise<void>((r) => s.close(() => r()));
    }
  });
});
