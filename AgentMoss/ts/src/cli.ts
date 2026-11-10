#!/usr/bin/env node
/**
 * AgentMoss CLI — TypeScript version.
 * Supports: init | analyze | server
 */

import { parseArgs } from 'util';
import { createApp, startServer } from './server';
import { version } from './package-json.js';

function printHelp(): void {
  console.log(`AgentMoss security analysis engine (TypeScript v${version})

Commands:
  init                  Generate input.json template
  analyze <input>       Run security analysis on input JSON
  server                Start HTTP API server
  install               Install systemd service for AgentMoss

Server options:
  --host <host>         Listen host (default: 127.0.0.1)
  --port <port>         Listen port (default: 9090, 0=auto assign)

Install options:
  --enable              Enable service on boot (systemctl enable)
`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === '--help' || command === '-h') {
    printHelp();
    process.exit(command ? 0 : 1);
  }

  switch (command) {
    case 'init': {
      const output = args[2] || 'input.json';
      const fs = await import('fs');
      const template = {
        session_id: 'my-session-001',
        prompt_session: 'Read /var/log/app.log and analyze errors',
        action_history: [],
        a_next: { action_type: 'bash', action_detail: 'cat /var/log/app.log' },
        reason: 'Need to read log file for error analysis',
        os_type: '',
        cwd: '/home/user/project',
      };
      fs.writeFileSync(output, JSON.stringify(template, null, 2), 'utf-8');
      console.log(`Template written to ${output}`);
      break;
    }

    case 'analyze': {
      if (!args[1]) {
        console.error('Usage: agent-moss analyze <input.json>');
        process.exit(1);
      }
      const fs = await import('fs');
      const path = await import('path');
      const { runAnalysis } = await import('./engine/coordinator');
      const filePath = path.resolve(args[1]);
      const data = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
      const result = await runAnalysis({
        sessionId: data.session_id || 'unknown',
        promptSession: data.prompt_session || '',
        actionHistory: (data.action_history || []).map((h: any) => ({
          actionType: h.action_type || h.name || '',
          actionDetail: h.action_detail || '',
        })),
        aNext: {
          actionType: data.a_next?.action_type || '',
          actionDetail: data.a_next?.action_detail || '',
        },
        reason: data.reason || '',
        osType: data.os_type || (process.platform === 'win32' ? 'windows' : 'linux'),
        cwd: data.cwd || process.cwd(),
        agentId: data.agent_id || '',
      });
      console.log(JSON.stringify(result, null, 2));
      process.exit(result.allowed ? 0 : 1);
      break;
    }

    case 'server': {
      let host = '127.0.0.1';
      let port = 9090;

      for (let i = 1; i < args.length; i++) {
        if (args[i] === '--host' && args[i + 1]) host = args[++i];
        else if (args[i] === '--port' && args[i + 1]) port = parseInt(args[++i], 10);
      }
      // --port 0 表示"自动从 9090 开始找空闲端口"
      if (port === 0) port = 9090;

      // startServer 内部 findFreePort：port 被占自动找空闲端口。
      const server = await startServer(host, port);
      console.log(`Listening on http://${host}:${server.port}`);
      // 必须 await serve()：其内部 honoServe 起阻塞循环让进程常驻，
      // 未 await 时 main() 返回后 Node 见无 pending 任务直接 exit 0。
      await server.serve();
      break;
    }

    case 'install': {
      const enable = args.includes('--enable');
      const { execSync } = await import('child_process');
      const fs = await import('fs');
      const path = await import('path');
      const { fileURLToPath } = await import('url');

      // 检查 root 权限
      if (process.getuid?.() !== 0) {
        try {
          execSync('sudo -n true', { stdio: 'ignore', timeout: 5000 });
        } catch {
          console.log('⚠️  无 sudo 权限，跳过 systemd service 安装');
          console.log('   手动启动：agent-moss server --port 0');
          process.exit(0);
        }
        const sudoArgs = ['sudo', process.execPath, ...process.argv.slice(1)];
        if (enable) sudoArgs.push('--enable');
        console.log('需要 root 权限安装 systemd service，正在通过 sudo 重新执行...');
        execSync(sudoArgs.join(' '), { stdio: 'inherit' });
        process.exit(0);
      }

      // 找到 service 文件（dist/data/ 或 src/data/）
      const __filename = fileURLToPath(import.meta.url);
      const __dirname = path.dirname(__filename);
      let srcPath = path.join(__dirname, 'data', 'agent_moss.service');
      if (!fs.existsSync(srcPath)) {
        // 开发模式回退
        srcPath = path.join(__dirname, '..', 'src', 'data', 'agent_moss.service');
      }
      if (!fs.existsSync(srcPath)) {
        console.error('错误：找不到 agent_moss.service 模板文件');
        process.exit(1);
      }

      // 找到 agent-moss 命令路径
      const which = execSync('which agent-moss 2>/dev/null || true', { encoding: 'utf-8' }).trim();
      const binPath = which || `${process.execPath} ${path.join(__dirname, 'cli.js')}`;

      // 读取模板，替换 ExecStart
      let content = fs.readFileSync(srcPath, 'utf-8');
      content = content.replace('__AGENT_MOSS_BIN__', binPath);

      // 写入 /etc/systemd/system/
      const dst = '/etc/systemd/system/agent-moss.service';
      fs.writeFileSync(dst, content, 'utf-8');
      fs.chmodSync(dst, 0o644);
      console.log(`✅ 已安装 systemd service: ${dst}`);

      // daemon-reload
      execSync('systemctl daemon-reload', { stdio: 'inherit' });
      console.log('✅ systemctl daemon-reload 完成');

      // 可选 enable
      if (enable) {
        execSync('systemctl enable agent-moss', { stdio: 'inherit' });
        console.log('✅ systemctl enable agent-moss 完成');
      }

      console.log('\n启动服务：  sudo systemctl start agent-moss');
      console.log('查看状态：  sudo systemctl status agent-moss');
      console.log('查看日志：  journalctl -u agent_moss -f');
      break;
    }

    case 'status': {
      const http = await import('http');
      const { execSync } = await import('child_process');

      // systemd 状态
      let systemdInfo = '';
      try {
        const out = execSync('systemctl is-active agent-moss 2>/dev/null || true', { encoding: 'utf-8' }).trim();
        if (out === 'active') {
          const show = execSync('systemctl show agent-moss --property=MainPID,ActiveEnterTimestamp,ExecStart 2>/dev/null || true', { encoding: 'utf-8' });
          for (const line of show.trim().split('\n')) {
            const [key, ...vals] = line.split('=');
            const val = vals.join('=');
            if (key === 'MainPID' && val && val !== '0') systemdInfo += `   PID:      ${val}\n`;
            else if (key === 'ActiveEnterTimestamp' && val) systemdInfo += `   启动时间: ${val}\n`;
            else if (key === 'ExecStart' && val) systemdInfo += `   启动命令: ${val}\n`;
          }
          if (!systemdInfo) systemdInfo = '   Systemd:  active\n';
        }
      } catch {}

      // 探测端口
      let foundPort = 0;
      let version = '';
      for (let port = 9090; port <= 9095; port++) {
        try {
          const data = await new Promise<any>((resolve, reject) => {
            const req = http.get(`http://127.0.0.1:${port}/api/v1/health`, { timeout: 2000 }, (res) => {
              let body = '';
              res.on('data', (chunk: string) => body += chunk);
              res.on('end', () => { try { resolve(JSON.parse(body)); } catch { reject(); } });
            });
            req.on('error', reject);
          });
          if (data.status === 'healthy') {
            foundPort = port;
            version = data.version || '';
            break;
          }
        } catch {}
      }

      if (foundPort) {
        console.log(`✅ AgentMoss 服务运行中`);
        console.log(`   版本:     ${version || '?'}`);
        console.log(`   端口:     ${foundPort}`);
        console.log(`   Console:  http://127.0.0.1:${foundPort}/console`);
        console.log(`   Health:   http://127.0.0.1:${foundPort}/api/v1/health`);
        if (systemdInfo) {
          process.stdout.write(systemdInfo);
        } else {
          console.log(`   Systemd:  未注册（运行 agent-moss install --enable 安装）`);
        }
        // 获取 L3 状态
        try {
          const data = await new Promise<any>((resolve, reject) => {
            const req = http.get(`http://127.0.0.1:${foundPort}/console/api/config`, { timeout: 3000 }, (res) => {
              let body = '';
              res.on('data', (chunk: string) => body += chunk);
              res.on('end', () => { try { resolve(JSON.parse(body)); } catch { reject(); } });
            });
            req.on('error', reject);
          });
          const layers = data.layers || {};
          const l1 = layers.L1_heuristic !== false ? '✅ 启用' : '❌ 禁用';
          const l2 = layers.L2_logic_rules !== false ? '✅ 启用' : '❌ 禁用';
          const l3 = layers.L3_llm_analysis !== false ? '✅ 启用' : '❌ 禁用';
          console.log(`   L1 静态检测: ${l1}`);
          console.log(`   L2 逻辑规则: ${l2}`);
          console.log(`   L3 LLM 分析: ${l3}`);
        } catch {}
        console.log();
        console.log('   启停命令：');
        console.log('     systemctl start agent-moss   启动');
        console.log('     systemctl stop agent-moss    停止');
        console.log('     systemctl restart agent-moss 重启');
        console.log('     systemctl status agent-moss  状态');
        console.log('     journalctl -u agent_moss -f  日志');
      } else {
        console.log(`❌ AgentMoss 服务未运行`);
        if (systemdInfo) {
          console.log(`   Systemd:  active 但端口探测不到`);
          console.log(`   检查日志：journalctl -u agent_moss -n 20 --no-pager`);
        } else {
          console.log(`   启动方式：`);
          console.log(`     systemctl start agent-moss  （systemd）`);
          console.log(`     agent-moss server           （前台）`);
        }
        process.exit(1);
      }
      break;
    }

    default:
      console.error(`Unknown command: ${command}`);
      printHelp();
      process.exit(1);
  }
}

// Only run the CLI when this file is the entry point, so the package can also
// be imported as a library (see `exports` in package.json) without triggering
// main() and process.exit().
import { fileURLToPath } from 'node:url';
import { realpathSync } from 'node:fs';
const isMain = (() => {
  try {
    if (!process.argv[1]) return false;
    // 兼容两种 spawn 方式：
    //   ① node /path/to/cli.js        — argv[1] 是普通路径
    //   ② node file:///path/to/cli.js — argv[1] 是 file:// URL（少见）
    // realpath 规范化两端，规避 symlink / 大小写 / file:// 协议差异导致的误判。
    const thisFile = realpathSync(fileURLToPath(import.meta.url));
    const argv1 = realpathSync(
      process.argv[1].startsWith('file://') ? fileURLToPath(process.argv[1]) : process.argv[1]
    );
    return thisFile === argv1;
  } catch {
    return false;
  }
})();

if (isMain) {
  main().catch((err) => {
    console.error('Fatal error:', err);
    process.exit(1);
  });
}
