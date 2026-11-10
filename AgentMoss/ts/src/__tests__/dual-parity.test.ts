import { describe, it, expect } from 'vitest';
import { isWriteOperation } from '../engine/logic-rules';

// 双端一致性测试：isWriteOperation 对同一批 case 的返回必须和 Python _is_write_operation 完全一致。
// 期望值来自 Python verify_iswrite.py 的实跑结果，确保本轮修复（引号路径/wget-O/rsync/
// echo文本命令/find|xargs）双端行为同步。
describe('双端一致性: isWriteOperation (Python parity)', () => {
  const CASES: Array<[string, boolean]> = [
    ["echo x > '/tmp/out'", true],
    ["echo payload > '~/.bashrc'", true],
    ["cat /tmp/in > '/etc/hosts'", true],
    ["wget -O /tmp/out http://x", true],
    ["wget -O ~/.bashrc http://x", true],
    ["curl -o /etc/hosts http://x", true],
    ["wget http://x", false],
    ["rsync -a /src /dest", true],
    ["rsync --list-only /src /dest", false],
    ["rsync -n /src /dest", false],
    ["find /tmp -name x | xargs sed -i 's/a/b/'", true],
    ["find /tmp -name x | xargs grep pat", false],
    ["cat /tmp/in > /tmp/out", true],
    ["sort /tmp/in > /tmp/out", true],
    ["cat /tmp/in > /dev/null", false],
    ["grep 'a>b' /tmp/in", false],
    ["ls 2>&1", false],
    ["echo hello world", false],
    ["echo wget -O file", false],
  ];
  for (const [cmd, expected] of CASES) {
    it(`isWriteOperation: ${cmd}`, () => {
      expect(isWriteOperation('bash', cmd)).toBe(expected);
    });
  }
});

import { DANGEROUS_PATTERNS } from '../engine/heuristic';

// 双端规则同步校验：TS DANGEROUS_PATTERNS 必须与 Python profiles/linux.py 语义对齐。
// 双端拆分粒度允许不同（如 Python 合并 curl|bash 为 1 条，TS 拆 bash/shell 为多条），
// 关键是同一批危险行为两端都能拦截。改规则须双端同步更新关键规则断言。
describe('双端规则同步: DANGEROUS_PATTERNS (Python parity)', () => {
  it('包含双端共有的关键规则（与 Python linux.py 对齐）', () => {
    // 匹配对象是正则 source 字符串（含字面 \s \b 等），用子串包含断言稳定可靠。
    const joined = DANGEROUS_PATTERNS.map(r => r.pattern.source).join('\n');
    const expected = [
      'rm\\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\\s+\\/', // rm -rf /
      '[0-7]{0,3}7\\b', // chmod 危险权限（含 -R 递归形态，对齐 Python NEW-FN）
      '[2-7][0-7]{3}', // setuid/setgid（含 3/5/7xxx 组合位，对齐 Python NEW-FN）
      'sudo\\s+(rm|chmod|chown', // sudo 提权
      ':\\(\\)\\s*\\{.*:\\|:&.*\\};:', // Fork Bomb (Python 补齐)
      '\\/dev\\/tcp\\/', // 反弹 Shell (Python 补齐)
      'nc\\s+-[el]\\s+.*\\d{1,5}', // Netcat 反弹
      'eval\\s+\\$\\(curl', // eval 远程执行
      'base64\\s+-d\\s+.*\\|\\s*bash', // base64 解码执行
      'curl\\s+.*\\|\\s*bash', // curl pipe bash
      'wget\\s+.*\\|\\s*(bash|sh)', // wget pipe shell
      'git\\s+clone\\s+.*\\|.*bash', // git clone pipe
      'pip\\s+install\\s+.*\\|\\s*bash', // pip install pipe
      'npm\\s+install\\s+-g\\s+.*\\|\\s*bash', // npm install pipe
      'export\\s+.*(?:TOKEN|KEY|SECRET|PASSWORD)', // 导出凭证
      '>\\s*\\/boot\\/', // 覆盖 /boot/ (Python 补齐)
      '>\\s*\\/etc\\/', // 覆盖 /etc/
      'curl\\s+.*-X\\s+POST.*\\b(env|environment|secret|key|token|password)\\b', // curl POST 外传 (Python 补齐)
      '(?:curl|wget)\\s+\\S+.*\\b(?:chmod|chown)\\s+\\+x\\b', // 下载后 chmod+x
      '\\$\\(|`', // 命令替换隐藏执行 $(touch pwned) / 反引号变体
    ];
    for (const frag of expected) {
      expect(joined).toContain(frag);
    }
  });
});

// 双端敏感路径同步校验：TS ROOT/HOME/CREDENTIAL_SENSITIVE_PATHS 必须与 Python
// profiles/linux.py sensitive_paths 语义对齐。关键敏感路径双端都必须存在，
// 且凭据路径（.aws/credentials、SSH 私钥、shadow 等）双端均为 deny_both（读写都拦）。
// 改敏感路径须双端同步更新此处断言，防止单向漂移（如 .aws/credentials 曾 TS 有 Python 无）。
import {
  ROOT_SENSITIVE_PATHS,
  HOME_SENSITIVE_PATHS,
  CREDENTIAL_PATHS,
} from '../engine/logic-rules';
describe('双端敏感路径同步: sensitive_paths (Python parity)', () => {
  const allRoot = ROOT_SENSITIVE_PATHS.map(p => p.path);
  const allHome = HOME_SENSITIVE_PATHS.map(p => p.path);
  const allCred = CREDENTIAL_PATHS.map(p => p.path);
  const all = [...allRoot, ...allHome, ...allCred];

  it('包含双端共有的关键敏感路径（与 Python linux.py 对齐）', () => {
    const expected = [
      '/etc/shadow', '/etc/gshadow', '/etc/passwd', '/etc/sudoers', // 系统认证凭据
      '/etc/hosts', '/etc/crontab', '/etc/cron.d/', '/var/spool/cron/', // 系统配置
      '/etc/systemd/', '/etc/ssh/sshd_config', '/etc/pam.d/', // 服务配置
      '/etc/nginx/nginx.conf', '/etc/nginx/conf.d/', '/etc/nginx/sites-enabled/', // Nginx (TS 补齐, 对齐 Python)
      '/boot/', '/proc/sys/', '/sys/', // 危险目录
      '/dev/random', '/dev/mem', '/dev/kmsg', // 设备文件
      '/etc/ssh/ssh_host_rsa_key', '/etc/ssh/ssh_host_ed25519_key', '/etc/ssh/ssh_host_ecdsa_key', // SSH 主机私钥
      '.ssh/id_rsa', '.ssh/id_ed25519', '.ssh/authorized_keys', // 用户 SSH 密钥
      '.aws/credentials', '.gitconfig', '.gnupg', // 云凭据 / Git 配置 / GPG 目录 (对齐 Python)
      'credentials.yml', 'credentials.yaml', 'secrets.yml', 'secrets.yaml', '.env', // 凭据文件
      '.config/agentmoss', '.agentmoss', // AgentMoss 自身配置 + Brain 数据（deny_both, agent tool call 不可碰）
    ];
    for (const p of expected) {
      // TS 路径可能带正则后缀（如 /etc/ssh/ssh_host_rsa_key(?!\\.pub) 排除公钥变体），
      // 用 startsWith 匹配裸路径，避免断言因后缀差异误报。
      const found = all.some(x => x.startsWith(p));
      expect(found, `缺双端共有敏感路径: ${p}`).toBe(true);
    }
  });

  it('凭据路径双端 deny_both（读写都拦）', () => {
    // 凭据路径必须标记 credential=true（TS 读写都拦，对齐 Python deny_both）
    const credPaths = ['.aws/credentials', '.ssh/id_rsa', '/etc/shadow', '/etc/sudoers',
      '.config/agentmoss/config.json'];
    for (const p of credPaths) {
      const found = [...ROOT_SENSITIVE_PATHS, ...HOME_SENSITIVE_PATHS].find(sp => sp.path.startsWith(p));
      expect(found?.credential, `${p} 应为凭据路径 (credential=true)`).toBe(true);
    }
  });

  it('目录级凭据目录（.ssh/.aws）dirDelOnly（仅删除拦截，对齐 Python NEW-FP-1）', () => {
    // NEW-FP-1: 目录级条目必须 dirDelOnly——仅「删除该目录/其下内容」拦截，
    // mkdir/chmod 等 SSH/AWS 目录初始化放行（否则 ssh 工具 demo 被卡）。
    // 这是双端同步防线：TS 端 seed/加载/消费需整体透传 dir_del_only，若 TS 退化
    // 回「写/删都拦序」此断言拦下。对应 Python test_linux_profile_sensitive_paths_sync_with_ts。
    const all = [...ROOT_SENSITIVE_PATHS, ...HOME_SENSITIVE_PATHS];
    for (const dp of ['.ssh', '.aws']) {
      const sp = all.find(x => x.path === dp);
      expect(sp, `缺目录级敏感路径: ${dp}`).toBeDefined();
      expect(sp!.dirDelOnly, `目录级 ${dp} 必须 dirDelOnly=true`).toBe(true);
    }
  });
});

// 通配符+删除 误报修复：heredoc 文档内容不误报，真实删除仍拦截（与 Python 同步）
import { checkDangerousPatterns, stripHeredocContent } from '../engine/heuristic';
describe('双端误报修复: 通配符+删除 (heredoc 豁免)', () => {
  it('heredoc 文档（含 * ? rm 字样）不误报', () => {
    const weekly = `cd /x && cat > "周报.md" <<'EOF'
# 周报
- 根因是 **sqlite** 与 **json** 的 ? 判断
- 曾有 rm -rf 误报分析
EOF
echo done`;
    expect(checkDangerousPatterns('terminal-executeBash', weekly)).toBeNull();
  });
  it('真实通配符删除仍拦截', () => {
    expect(checkDangerousPatterns('terminal-executeBash', 'rm -rf /data/*')).not.toBeNull();
    expect(checkDangerousPatterns('terminal-executeBash', 'cd /data && rm *')).not.toBeNull();
  });
  it('stripHeredocContent 剥离 heredoc 块', () => {
    const weekly = `cat > "x.md" <<'EOF'
abc ** ** rm
EOF
echo done`;
    expect(stripHeredocContent(weekly)).toContain('<<heredoc>>');
    expect(stripHeredocContent(weekly)).not.toContain('**');
  });
});
