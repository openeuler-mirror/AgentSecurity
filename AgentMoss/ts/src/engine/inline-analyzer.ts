/**
 * 内联脚本静态语义判定 — 区分敏感路径是"被当作文本"还是"被当作读写目标"。
 *
 * 对内联脚本（python -c / perl -e / ruby -e / php -r / node -e / lua / echo / printf）
 * 里出现非凭据敏感路径的场景，做静态判定（不依赖 LLM）：
 *
 * 1. 写入+执行绕过链 → Deny（echo "cat /etc/shadow" > x.sh && bash x.sh / printf | bash）
 * 2. 重定向写入敏感路径 → Deny（echo '...' >> /etc/hosts）
 * 3. 含读写调用词 + 敏感路径共存 → Deny（open('/etc/shadow')、os.system('cat /etc/shadow')）
 *    注意：仅对 python -c 等真正的内联脚本代码做读写调用词检测；
 *    echo/printf 的字符串参数是自然语言文本，跳过此检测（不可能触发真实读写）。
 * 4. 否则（敏感路径在代码里但无读写调用词，如 print('/etc/shadow')） → Allow
 * 5. 目录遍历 + 文件读写组合 → Deny（os.listdir + open() 动态发现并读写文件，绕过静态路径检测）
 *    注意：仅对 python -c 等真正的内联脚本代码做此检测。
 * 6. 否则（无目录遍历读写组合） → Allow
 *
 * 凭据文件不进此判定（coordinator 层 isCredential 直接 Deny）。
 */

export interface InlineAnalysisResult {
  /** 是否命中本判定器可处理的内联脚本场景；false 时回退原逻辑 */
  actionable: boolean;
  allowed: boolean;
  reason: string;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  riskType: string;
}

// 内联脚本解释器 + 代码标志：python -c / perl -e / ruby -e / php -r / node -e / lua -e
// 捕获 -c/-e/-r 后的代码内容（双引号组 1 / 单引号组 2，支持转义）
const INLINE_CODE_RE = /(?:python|python3|perl|perl5|ruby|jruby|mruby|node|php|lua)\s+(?:-[a-zA-Z]*[cera][a-zA-Z]*\s+)"([^"\\]*(?:\\.[^"\\]*)*)"|'([^'\\]*(?:\\.[^'\\]*)*)'/gi;

// echo / printf 的字符串参数（双引号组 1 / 单引号组 2）
const ECHO_STRING_RE = /\b(?:echo|printf)\s+"([^"\\]*(?:\\.[^"\\]*)*)"|\b(?:echo|printf)\s+'([^'\\]*(?:\\.[^'\\]*)*)'/gi;

// echo / printf 命令本身（用于 isLiteralTextCommand 门控）
const ECHO_CMD_RE = /(?:^|\s|;|&&|\|\|)(?:echo|printf)\s/gi;

/** 判断命令是否为 echo/printf 等纯文本输出命令（敏感路径可能作为字符串字面量出现）。

  echo/printf 含真实文件重定向（> /path，非 /dev/null 丢弃、非 >& fd）时返回 false——
  重定向目标是真实写文件，路径不是字面量，不当文本命令（否则 echo x > '~/.bashrc'
  被当文本命令 → inline_analyzer 把引号内路径当字面量 → 漏报敏感路径写）。 */
export function isLiteralTextCommand(command: string): boolean {
  ECHO_CMD_RE.lastIndex = 0;
  if (!ECHO_CMD_RE.test(command)) return false;
  // 含真实文件重定向 → 不是纯文本输出
  if (command.includes('>')) {
    let d = command.replace(/<=>|>=|<=|<>|=>/g, ' ');
    d = d.replace(/(?:2|&|1)?\s*>\s*\/dev\/null\b/g, '');
    // 摘引号重定向目标（去引号保留路径，支持 / 或 ~ 开头）
    d = d.replace(new RegExp(">{1,2}\\s*(['\"])([~./][^'\"]+)\\1", "g"), (_m, _q, p) => '>' + p);
    d = d.replace(/'[^']*'|"[^"]*"/g, '');
    if (/>{1,2}\s*(?!&)\S/.test(d)) {
      return false;
    }
  }
  return true;
}

// 读写调用词：仅用于 python -c 等真正的内联脚本代码（不对 echo/printf 的字符串生效）。
// 出现这些词 + 敏感路径共存 → 判为真实读写。
//
// 全部采用组合/函数调用形态，避免自然语言误触发：
// - 函数调用形态：open(, read(, write(, system(, exec(, eval( 等（后跟 '('）
// - 组合关键词：os.system, import os, shell=True 等（自带足够区分度）
// - 不再包含裸短词（open, read, system, exec 等），因 \b 无法区分编程调用与自然语言
const READ_WRITE_KEYWORDS = [
  // 函数调用形态（关键词后跟 '('）
  'open(', 'read(', 'write(', 'fopen(', 'system(', 'exec(', 'eval(',
  'popen(', 'load(', 'dump(',
  // 文件读写（组合形态）
  'readline', 'readlines', 'writelines', 'getpass',
  'pickle.load', 'yaml.load', 'json.load', 'json.read', 'configparser',
  'fread', 'fwrite', 'fgets',
  // 子进程执行（组合形态）
  'os.system', 'os.popen', 'subprocess', 'os.exec', 'os.spawn',
  'import os', 'import subprocess',
  'shell=true', 'check_output', 'check_call', 'run(',
  // 绕过变体检测
  'getattr(', '__builtins__', 'globals(', 'locals(',
  // PHP
  'file_get_contents', 'file_put_contents', 'passthru', 'shell_exec', 'proc_open',
  // Perl-Ruby
  '<stdin>', 'open my',
];

// 写入+执行绕过链
const WRITE_EXEC_CHAIN_PATTERNS: RegExp[] = [
  // echo/cat/printf "..." > file && bash/sh/python file
  /(?:echo|cat|printf)\b.*?>\s*\S+.*(?:&&|;|\|)\s*(?:bash|sh|zsh|python\d?|perl|ruby|node|php)\s/gis,
  // ... | bash / | sh / | python（管道喂解释器执行）
  /\|\s*(?:bash|sh|zsh|python\d?|perl|ruby|node|php)\b/gi,
  // eval "$(cat ...)" / eval "$(echo ...)"
  /eval\s+"\$\(/gi,
  // xargs bash / xargs sh
  /\|\s*xargs\s+(?:bash|sh|zsh)/gi,
];

// 重定向写入敏感路径：> / >> 后跟敏感路径 = 真实写入（不是字符串字面量）
// 敏感路径片段（非凭据，凭据已在 coordinator 层直接 Deny 不进此判定）
// 对齐 Python inline_analyzer._build_redirect_to_sensitive_re(profile)：Python 按
// profile.sensitive_paths 动态编译（其中含 ~/.bashrc）。TS 无 profile 运行时注入，
// 故在 ROOT/HOME/CREDENTIAL 静态列表基础上，额外补 shell rc 文件名片段，
// 让 `echo 'x' >> ~/.bashrc`、`echo 'x' >> /storage/Users/currentUser/.bashrc`
//（鸿蒙 home 形态）都能被识别为真实重定向写入 → Deny，而非落到"文本字面量"放行。
// 注意：shell rc 片段用文件名匹配（不带 ~ 前缀），可命中任意 home 绝对路径下的 rc 文件。
const SHELL_RC_FRAGMENTS = [
  '.bashrc', '.zshrc', '.profile', '.bash_profile', '.zprofile',
];
const SENSITIVE_PATH_FRAGMENTS = [
  '/etc/shadow', '/etc/gshadow', '/etc/passwd', '/etc/sudoers', '/etc/hosts',
  '/etc/crontab', '/etc/systemd/', '/etc/ssh/sshd_config', '/boot/', '/proc/sys/',
  '/sys/', '/dev/mem', '/dev/kmsg', '.ssh/id_rsa', '.ssh/id_ed25519',
  '.ssh/authorized_keys',
  ...SHELL_RC_FRAGMENTS,
];
const REDIRECT_TO_SENSITIVE_RE = new RegExp(`>{1,2}\\s*(?:\\S*/)?(${SENSITIVE_PATH_FRAGMENTS.map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})(?:\\s|$)`, 'i');

export function extractInlineCode(command: string): string {
  const parts: string[] = [];
  let m: RegExpExecArray | null;
  INLINE_CODE_RE.lastIndex = 0;
  while ((m = INLINE_CODE_RE.exec(command)) !== null) {
    const code = m[1] ?? m[2];
    if (code) parts.push(code);
  }
  ECHO_STRING_RE.lastIndex = 0;
  while ((m = ECHO_STRING_RE.exec(command)) !== null) {
    const code = m[1] ?? m[2];
    if (code) parts.push(code);
  }
  return parts.join('\n');
}

function hasWriteExecChain(command: string): boolean {
  return WRITE_EXEC_CHAIN_PATTERNS.some((p) => {
    p.lastIndex = 0;
    return p.test(command);
  });
}

// 目录遍历关键词：用于检测通过动态发现文件路径绕过静态路径匹配的行为
// 仅对 python -c 等真正的内联脚本代码生效
const DIR_TRAVERSAL_KEYWORDS = [
  // Python 目录遍历
  'os.listdir', 'os.walk', 'os.scandir',
  'glob.glob', 'glob.iglob', 'pathlib.', 'iterdir', 'rglob',
  'scandir(', 'listdir(',
];

function hasDirTraversal(code: string): boolean {
  /** 检测代码中是否含目录遍历函数（用于识别动态文件发现绕过行为）。 */
  const lower = code.toLowerCase();
  return DIR_TRAVERSAL_KEYWORDS.some((kw) => lower.includes(kw));
}

export function hasReadWriteKeyword(code: string): boolean {
  /** 检测代码中是否含读写调用词（仅用于 python -c 等真正的内联脚本代码）。
   * 全部关键词为组合/函数调用形态（open(, os.system, import os 等），
   * 不会在自然语言文本里误触发。 */
  const lower = code.toLowerCase();
  return READ_WRITE_KEYWORDS.some((kw) => lower.includes(kw));
}

/**
 * 对内联脚本做静态语义判定。
 * 调用前提：coordinator 已确认是 inline 脚本 + 命中非凭据敏感路径。
 */
export function analyzeInlineScript(command: string): InlineAnalysisResult {
  const code = extractInlineCode(command);
  if (!code) {
    // 提取不到代码（命令结构不匹配已知 inline 模式）→ 不处理，回退保守
    return { actionable: false, allowed: true, reason: '', riskLevel: 'low', riskType: '' };
  }

  // 1. 写入+执行绕过链 → Deny
  if (hasWriteExecChain(command)) {
    return {
      actionable: true,
      allowed: false,
      reason: '内联脚本含写入文件后执行的模式，疑似绕过敏感路径检测',
      riskLevel: 'critical',
      riskType: 'script_execution',
    };
  }

  // 1.5 重定向写入敏感路径（echo '...' >> /etc/hosts 等）→ 真实写入 → Deny
  const redirMatch = command.match(REDIRECT_TO_SENSITIVE_RE);
  if (redirMatch) {
    return {
      actionable: true,
      allowed: false,
      reason: `重定向写入敏感路径: ${redirMatch[1]}`,
      riskLevel: 'critical',
      riskType: 'file_access',
    };
  }

  // 1.6 目录遍历 + 文件读写组合 → 不自行判定，回退 coordinator 走层3 LLM 分析
  // 检测 os.listdir/glob/pathlib 等目录遍历函数 + open()/write()/read() 等读写调用，
  // 用于识别"通过动态发现文件路径绕过静态路径匹配"的行为。
  // 仅对 python -c 等真正的内联脚本代码做此检测（echo/printf 无此能力）。
  // 注意：此处返回 actionable: false，让 coordinator 回退到正常逻辑，
  // 由层2 的 _checkIndirectFileAccess 规则触发层3 LLM 语义判断。
  const isEchoOrPrintf1 = isLiteralTextCommand(command);
  if (!isEchoOrPrintf1 && hasDirTraversal(code) && hasReadWriteKeyword(code)) {
    return { actionable: false, allowed: true, reason: '', riskLevel: 'low', riskType: '' };
  }

  // 2. 含读写调用词 → 判为真实读写 → Deny
  // 注意：仅对 python -c 等真正的内联脚本代码做此检测。
  // echo/printf 的字符串参数是自然语言文本，不可能触发真实文件读写；
  // 重定向（>> /etc/hosts）和管道执行（| bash）已在步骤 1/1.5 覆盖。
  const isEchoOrPrintf = isLiteralTextCommand(command);
  if (!isEchoOrPrintf && hasReadWriteKeyword(code)) {
    return {
      actionable: true,
      allowed: false,
      reason: '内联脚本含敏感路径且含文件读写/命令执行调用，判为真实访问',
      riskLevel: 'critical',
      riskType: 'file_access',
    };
  }

  // 3. 敏感路径在代码里但无读写调用词 → 文本字面量 → Allow
  return {
    actionable: true,
    allowed: true,
    reason: '敏感路径仅作为文本字面量出现，未伴随读写操作',
    riskLevel: 'low',
    riskType: 'file_access',
  };
}
