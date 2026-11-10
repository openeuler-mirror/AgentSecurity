import { readFileSync } from 'fs';
import { resolve, join } from 'path';

/**
 * Script content pre-scanning — detects suspicious patterns in bash scripts.
 * When a script execution is detected, reads up to 500 lines and scans for
 * high-risk patterns (network exfil, reverse shells, base64 obfuscation,
 * sensitive file access, persistence backdoors).
 */

// High-risk detection patterns
const SUSPICIOUS_PATTERNS: { name: string; pattern: RegExp }[] = [
  // Network exfiltration (curl/wget POST in scripts is almost never legitimate)
  { name: 'curl POST', pattern: /curl\s+(.*\s)?-X\s+POST/i },
  { name: 'curl --data', pattern: /curl\s+(.*\s)?--data/i },
  { name: 'curl -d', pattern: /curl\s+(.*\s)?-d\s/i },
  { name: 'wget --post-data', pattern: /wget\s+(.*\s)?--post-data/i },
  { name: 'wget --post-file', pattern: /wget\s+(.*\s)?--post-file/i },
  // Reverse shell
  { name: 'nc -e', pattern: /\bnc\s+.*-e\b/ },
  { name: 'ncat -e', pattern: /\bncat\s+.*-e\b/ },
  { name: '/dev/tcp', pattern: /\/dev\/tcp\// },
  { name: '/dev/udp', pattern: /\/dev\/udp\// },
  // Base64 obfuscation
  { name: '$(base64', pattern: /\$\(\s*base64/ },
  { name: '`base64', pattern: /`\s*base64/ },
  { name: 'base64 decode pipe', pattern: /base64\s+(-d|--decode)\s*\|/ },
  // Sensitive file access
  { name: '/etc/shadow', pattern: /\/etc\/shadow/ },
  { name: 'id_rsa', pattern: /\bid_rsa\b/ },
  { name: 'id_ed25519', pattern: /\bid_ed25519\b/ },
  // Persistence backdoor
  { name: 'crontab install', pattern: /crontab\s+-/ },
  { name: 'authorized_keys', pattern: /authorized_keys/ },
  { name: 'ssh no host key check', pattern: /ssh\s+.*StrictHostKeyChecking\s*=\s*no/ },
];

// Script execution patterns
const SCRIPT_EXEC_PATTERNS = [
  /bash\s+(\S+\.sh)/,
  /sh\s+(\S+\.sh)/,
  /\.\/(\S+\.sh)/,
  /source\s+(\S+\.sh)/,
  /\.\s+(\S+\.sh)/,
  /zsh\s+(\S+\.sh)/,
];

// Keyword combination risk rules
const KEYWORD_COMBINATION_RISKS: { group1: Set<string>; group2: Set<string>; level: string; reason: string }[] = [
  {
    group1: new Set(['curl POST', 'curl --data', 'curl -d', 'wget --post-data', 'wget --post-file']),
    group2: new Set(['$(base64', '`base64', 'base64 decode pipe']),
    level: 'critical',
    reason: '检测到网络数据发送 + Base64编码组合，构成 Critical 级别数据外传风险。攻击者可能将敏感数据编码后外传。',
  },
  {
    group1: new Set(['curl POST', 'curl --data', 'curl -d', 'wget --post-data', 'wget --post-file']),
    group2: new Set(['/etc/shadow', 'id_rsa', 'id_ed25519']),
    level: 'critical',
    reason: '检测到网络数据发送 + 敏感文件访问组合，构成 Critical 级别凭证外传风险。',
  },
  {
    group1: new Set(['nc -e', 'ncat -e', '/dev/tcp', '/dev/udp']),
    group2: new Set(),
    level: 'high',
    reason: '检测到反弹 Shell 特征，攻击者可能建立远程控制通道。',
  },
  {
    group1: new Set(['crontab install', 'authorized_keys', 'ssh no host key check']),
    group2: new Set(),
    level: 'high',
    reason: '检测到持久化后门特征，攻击者可能在系统中植入后门。',
  },
];

const SINGLE_KEYWORD_RISKS: Record<string, { level: string; reason: string }> = {
  'curl POST': { level: 'high', reason: '检测到 curl POST 请求，可能向外部服务器发送数据。' },
  'curl --data': { level: 'high', reason: '检测到 curl --data 参数，可能向外部服务器发送数据。' },
  'curl -d': { level: 'high', reason: '检测到 curl -d 参数，可能向外部服务器发送数据。' },
  'wget --post-data': { level: 'high', reason: '检测到 wget POST 请求，可能向外部服务器发送数据。' },
  'wget --post-file': { level: 'high', reason: '检测到 wget 文件上传，可能向外部服务器发送文件。' },
  'nc -e': { level: 'critical', reason: '检测到 nc -e 反弹 Shell 特征。' },
  'ncat -e': { level: 'critical', reason: '检测到 ncat -e 反弹 Shell 特征。' },
  '/dev/tcp': { level: 'critical', reason: '检测到 /dev/tcp 反弹 Shell 特征。' },
  '/dev/udp': { level: 'critical', reason: '检测到 /dev/udp 反弹 Shell 特征。' },
  '$(base64': { level: 'high', reason: '检测到 Base64 编码执行，可能是混淆逃逸。' },
  '`base64': { level: 'high', reason: '检测到 Base64 编码执行，可能是混淆逃逸。' },
  'base64 decode pipe': { level: 'high', reason: '检测到 Base64 解码后管道执行，可能是混淆逃逸。' },
  '/etc/shadow': { level: 'critical', reason: '检测到访问系统密码文件。' },
  'id_rsa': { level: 'critical', reason: '检测到访问 SSH 私钥。' },
  'id_ed25519': { level: 'critical', reason: '检测到访问 SSH 私钥。' },
  'crontab install': { level: 'high', reason: '检测到修改定时任务，可能是持久化后门。' },
  'authorized_keys': { level: 'high', reason: '检测到修改 SSH 授权密钥，可能是持久化后门。' },
  'ssh no host key check': { level: 'high', reason: '检测到 SSH 跳过主机密钥验证，可能是横向移动。' },
};

const LEVEL_ORDER: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };

export interface ScriptAnalysisResult {
  scriptPath: string;
  scriptContent: string;
  matchedKeywords: string[];
  lineCount: number;
  isSuspicious: boolean;
  error: string;
  riskLevel: string;
  riskReason: string;
}

function emptyResult(): ScriptAnalysisResult {
  return { scriptPath: '', scriptContent: '', matchedKeywords: [], lineCount: 0, isSuspicious: false, error: '', riskLevel: '', riskReason: '' };
}

function extractScriptPath(command: string): string | null {
  for (const pattern of SCRIPT_EXEC_PATTERNS) {
    const m = command.match(pattern);
    if (m) return m[1];
  }
  return null;
}

function scanScriptForKeywords(content: string): string[] {
  const matched: string[] = [];
  for (const { name, pattern } of SUSPICIOUS_PATTERNS) {
    if (pattern.test(content)) matched.push(name);
  }
  return matched;
}

function assessKeywordCombinationRisk(matchedKeywords: string[], scriptContent: string): { level: string; reason: string } {
  if (matchedKeywords.length === 0) return { level: '', reason: '' };

  const keywordSet = new Set(matchedKeywords);

  // Check combination rules
  for (const rule of KEYWORD_COMBINATION_RISKS) {
    const hitGroup1 = [...rule.group1].some(k => keywordSet.has(k));
    const hitGroup2 = rule.group2.size === 0 ? true : [...rule.group2].some(k => keywordSet.has(k));
    if (hitGroup1 && hitGroup2) return { level: rule.level, reason: rule.reason };
  }

  // Extra: network post + env variable collection
  const networkPostKeywords = new Set(['curl POST', 'curl --data', 'curl -d', 'wget --post-data', 'wget --post-file']);
  const hasNetworkPost = [...networkPostKeywords].some(k => keywordSet.has(k));
  if (hasNetworkPost) {
    const envPatterns = ['$env', '$(env)', '$USER', '$(hostname)', '$(pwd)', '$HOME'];
    const contentLower = scriptContent.toLowerCase();
    for (const p of envPatterns) {
      if (contentLower.includes(p.toLowerCase())) {
        return {
          level: 'critical',
          reason: '检测到网络数据发送 + 系统环境变量收集组合，构成 Critical 级别数据外传风险。脚本可能将用户环境变量（可能包含 API Key、密钥等敏感信息）发送到远程服务器。',
        };
      }
    }
  }

  // Single keyword fallback
  let bestLevel = '';
  let bestReason = '';
  for (const kw of matchedKeywords) {
    const risk = SINGLE_KEYWORD_RISKS[kw];
    if (risk && (LEVEL_ORDER[risk.level] || 0) > (LEVEL_ORDER[bestLevel] || 0)) {
      bestLevel = risk.level;
      bestReason = risk.reason;
    }
  }

  return { level: bestLevel, reason: bestReason };
}

function readScriptContent(scriptPath: string, maxLines: number = 500): { content: string; lineCount: number; error: string } {
  try {
    const expandedPath = scriptPath.startsWith('~')
      ? join(process.env.HOME || '/home/user', scriptPath.slice(2))
      : resolve(scriptPath);

    const raw = readFileSync(expandedPath, 'utf-8');
    const lines = raw.split('\n').slice(0, maxLines);
    return { content: lines.join('\n'), lineCount: lines.length, error: '' };
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    return { content: '', lineCount: 0, error: `读取脚本失败: ${msg}` };
  }
}

export function analyzeScriptContent(actionType: string, actionDetail: string, maxLines: number = 500): ScriptAnalysisResult {
  if (actionType.toLowerCase() !== 'bash') return emptyResult();

  const scriptPath = extractScriptPath(actionDetail);
  if (!scriptPath) return emptyResult();

  const { content, lineCount, error } = readScriptContent(scriptPath, maxLines);
  if (error) return { ...emptyResult(), scriptPath, error };

  const matchedKeywords = scanScriptForKeywords(content);
  const isSuspicious = matchedKeywords.length > 0;

  let riskLevel = '';
  let riskReason = '';
  if (isSuspicious) {
    const risk = assessKeywordCombinationRisk(matchedKeywords, content);
    riskLevel = risk.level;
    riskReason = risk.reason;
  }

  return { scriptPath, scriptContent: content, matchedKeywords, lineCount, isSuspicious, error: '', riskLevel, riskReason };
}

export function formatScriptAnalysisForPrompt(result: ScriptAnalysisResult): string {
  if (!result.scriptPath) return '';
  if (result.error) return `脚本内容分析失败: ${result.error}`;
  if (!result.isSuspicious) return '';

  const keywordsStr = result.matchedKeywords.join(', ');
  let riskHint = '';
  if (result.riskLevel && result.riskReason) {
    riskHint = `\n\n风险评估: ${result.riskLevel.toUpperCase()} 级别\n风险原因: ${result.riskReason}\n建议: 此脚本应被拒绝（Deny），除非有明确的业务需求且已确认目标服务器可信。`;
  }

  return `检测到脚本执行，且脚本内容包含可疑关键词:\n   脚本路径: ${result.scriptPath}\n   可疑关键词: ${keywordsStr}\n   脚本行数: ${result.lineCount}${riskHint}\n\n### 脚本内容 ###\n\`\`\`\n${result.scriptContent}\n\`\`\`\n`;
}
