import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import net from 'node:net';
import { analyzeRoute, healthRoute, reviewRoute } from './routes';
import { createConsoleRouter } from './console';

export function createApp(): Hono {
  const app = new Hono();

  // Middleware
  app.use('*', cors({ origin: '*', allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], allowHeaders: ['*'] }));
  app.use('*', logger());

  // Routes
  app.get('/api/v1/health', healthRoute);
  app.post('/api/v1/analyze', analyzeRoute);
  app.post('/api/v1/review', reviewRoute);

  // Policy Console（浏览器策略管控台，挂载在 /console 前缀）
  app.route('/console', createConsoleRouter());
  // /console/ → /console（hono route 挂载后带尾斜杠匹配行为不一致，加重定向兼容）
  app.get('/console/', (c) => c.redirect('/console'));

  return app;
}

/**
 * 从 startPort 开始找第一个可用端口（照搬 OpenDesk findFreePort 策略）。
 * 用 net.createServer().listen 试端口，成功立刻 close 返回该端口；全占 fallback
 * 到 startPort（让 hono 自己报错，不静默换到离谱端口）。
 *
 * 为什么需要：默认 9090 被占时服务起不来、xiaoO 全 fail-closed。预探测找空闲端口，
 * 配合消费方探测兜底（bridge.ts probeAgentMossUrl），保证服务总能起、消费方能连上。
 */
export async function findFreePort(
  startPort: number,
  host: string = '127.0.0.1',
  scan: number = 100,
): Promise<number> {
  for (let port = startPort; port < startPort + scan; port++) {
    const free = await new Promise<boolean>((resolve) => {
      const server = net.createServer();
      server.listen(port, host, () => {
        server.close(() => resolve(true));
      });
      server.on('error', () => resolve(false));
    });
    if (free) {
      if (port !== startPort) {
        console.warn(`[AgentMoss] Port ${startPort} in use, using ${port} instead`);
      }
      return port;
    }
  }
  return startPort; // fallback
}

export async function startServer(
  host = '127.0.0.1',
  port = 9090,
): Promise<{ serve: () => Promise<void>; port: number }> {
  const actualPort = await findFreePort(port, host);
  const app = createApp();
  return {
    port: actualPort,
    serve: async () => {
      console.log(`AgentMoss HTTP server on ${host}:${actualPort}`);
      // @hono/node-server 动态 import（ESM 下 require 不可用）
      // 必须 await：honoServe 会起阻塞循环让进程常驻，未 await 时 main() 返回后 Node
      // 见无 pending 任务直接 exit 0，server 起不来。
      const { serve: honoServe } = await import('@hono/node-server');
      honoServe({ fetch: app.fetch, hostname: host, port: actualPort });
    },
  };
}
