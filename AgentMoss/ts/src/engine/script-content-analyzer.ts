/**
 * Script content analyzer — recursive chain tracking + preprocessing + L1/L2 reuse.
 *
 * Mirrors Python agent_moss/engine/script_content_analyzer.py.
 *
 * Core improvements over the old single-file script-analyzer.ts:
 *  1. Preprocessing pipeline: strip comments -> strip echo text -> expand simple vars
 *  2. Broader script path extraction (no .sh restriction; python/node/ruby/...)
 *  3. File-size limit instead of line limit (full read; ms-scale cost)
 *  4. Recursive tracking: A.sh -> B.sh -> C.sh nested calls are caught
 *  5. L1/L2 reuse: preprocessed content scanned via existing runHeuristicCheck /
 *     runLogicCheck; high/critical deny directly, skipping L3
 *
 * Difference from Python: AgentMoss-TS heuristic/logic are single entry functions
 * (runHeuristicCheck / runLogicCheck taking AnalysisInput), not reusable scanner
 * objects. So L1/L2 per-node reuse wraps each node's preprocessed content as a
 * virtual AnalysisInput and calls those functions.
 */

import { readFileSync, statSync, existsSync } from 'fs';
import { resolve, join, isAbsolute, dirname } from 'path';
import { homedir } from 'os';
import type { AnalysisInput } from './coordinator';
import type { SecurityJudgment } from './types';
import { runHeuristicCheck } from './heuristic';
import { runLogicCheck } from './logic-rules';
import { extractInlineCode } from './inline-analyzer';
import { RecursiveTracker } from './script-engine/tracker';

// ==================== Types ====================

export interface ScriptNode {
  scriptPath: string;
  rawContent: string;
  preprocessedContent: string;
  lineCount: number;
  fileSize: number;
  depth: number;
  childPaths: string[];
  error: string;

  l1Hit: boolean;
  l1RiskLevel: string;
  l1RiskType: string;
  l1Reason: string;
  l1MatchedPatterns: string[];

  l2Hit: boolean;
  l2ViolatedRule: string;
  l2RiskLevel: string;
  l2RiskType: string;
  l2Reason: string;

  matchedKeywords: string[];
  isSuspicious: boolean;
  keywordRiskLevel: string;
  keywordRiskReason: string;
}

export interface ScriptChainAnalysisResult {
  nodes: ScriptNode[];
  entryPath: string;
  maxDepthReached: boolean;
  maxSizeReached: boolean;
  maxNodesReached: boolean;
  totalSize: number;
  totalLines: number;
  totalNodes: number;
  hasCritical: boolean;
  hasHigh: boolean;
  firstHitNode: ScriptNode | null;
  error: string;
}

function emptyChain(): ScriptChainAnalysisResult {
  return {
    nodes: [], entryPath: '', maxDepthReached: false, maxSizeReached: false,
    maxNodesReached: false, totalSize: 0, totalLines: 0, totalNodes: 0,
    hasCritical: false, hasHigh: false, firstHitNode: null, error: '',
  };
}

function newNode(path: string, depth: number): ScriptNode {
  return {
    scriptPath: path, rawContent: '', preprocessedContent: '', lineCount: 0,
    fileSize: 0, depth, childPaths: [], error: '',
    l1Hit: false, l1RiskLevel: '', l1RiskType: '', l1Reason: '', l1MatchedPatterns: [],
    l2Hit: false, l2ViolatedRule: '', l2RiskLevel: '', l2RiskType: '', l2Reason: '',
    matchedKeywords: [], isSuspicious: false, keywordRiskLevel: '', keywordRiskReason: '',
  };
}


// ==================== High-risk keyword patterns (L3 compatible) ====================

const SUSPICIOUS_PATTERNS: { name: string; pattern: RegExp }[] = [
  { name: 'curl POST', pattern: /curl\s+(.*\s)?-X\s+POST/i },
  { name: 'curl --data', pattern: /curl\s+(.*\s)?--data/i },
  { name: 'curl -d', pattern: /curl\s+(.*\s)?-d\s/i },
  { name: 'wget --post-data', pattern: /wget\s+(.*\s)?--post-data/i },
  { name: 'wget --post-file', pattern: /wget\s+(.*\s)?--post-file/i },
  { name: 'nc -e', pattern: /\bnc\s+.*-e\b/ },
  { name: 'ncat -e', pattern: /\bncat\s+.*-e\b/ },
  { name: '/dev/tcp', pattern: /\/dev\/tcp\// },
  { name: '/dev/udp', pattern: /\/dev\/udp\// },
  { name: '$(base64', pattern: /\$\(\s*base64/ },
  { name: '`base64', pattern: /`\s*base64/ },
  { name: 'base64 decode pipe', pattern: /base64\s+(-d|--decode)\s*\|/ },
  { name: '/etc/shadow', pattern: /\/etc\/shadow/ },
  { name: 'id_rsa', pattern: /\bid_rsa\b/ },
  { name: 'id_ed25519', pattern: /\bid_ed25519\b/ },
  { name: 'crontab install', pattern: /crontab\s+-/ },
  { name: 'authorized_keys', pattern: /authorized_keys/ },
  { name: 'ssh no host key check', pattern: /ssh\s+.*StrictHostKeyChecking\s*=\s*no/ },
];


// ==================== Script execution patterns ====================

const SCRIPT_EXEC_PATTERNS: RegExp[] = [
  /(?:^|\s|&&|\|\|)\s*bash\s+(\S+)/i,
  /(?:^|\s|&&|\|\|)\s*\/bin\/bash\s+(\S+)/i,
  /(?:^|\s|&&|\|\|)\s*sh\s+(\S+)/i,
  /(?:^|\s|&&|\|\|)\s*zsh\s+(\S+)/i,
  /\.\/(\S+)/,
  /(?:^|\s|&&|\|\|)\s*source\s+(\S+)/i,
  /(?:^|\s|&&|\|\|)\s*\.\s+(\S+)/,
  /(?:^|\s|&&|\|\|)\s*python3?\s+(\S+\.py)/i,
  /(?:^|\s|&&|\|\|)\s*node\s+(\S+\.js)/i,
  /(?:^|\s|&&|\|\|)\s*ruby\s+(\S+\.rb)/i,
  /(?:^|\s|&&|\|\|)\s*perl\s+(\S+\.pl)/i,
  /(?:^|\s|&&|\|\|)\s*php\s+(\S+\.php)/i,
  /(?:^|\s|&&|\|\|)\s*lua\s+(\S+\.lua)/i,
];


// ==================== Keyword combination risk rules ====================

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

  for (const rule of KEYWORD_COMBINATION_RISKS) {
    const hitGroup1 = [...rule.group1].some(k => keywordSet.has(k));
    const hitGroup2 = rule.group2.size === 0 ? true : [...rule.group2].some(k => keywordSet.has(k));
    if (hitGroup1 && hitGroup2) return { level: rule.level, reason: rule.reason };
  }

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


// ==================== Script path extraction ====================

function extractScriptPath(command: string): string | null {
  for (const pattern of SCRIPT_EXEC_PATTERNS) {
    const m = command.match(pattern);
    if (m) return m[1];
  }
  return null;
}

/** Extract script path AND the positional args following it. Mirrors Python. */
function extractScriptPathWithArgs(command: string): { path: string | null; args: string[] } {
  // Inline form `bash -c '...'` / `sh -c '...'` / `zsh -c '...'`:
  // -c is an option, not a script path (old code mis-took it as the path → tracking
  // "-c" file fails → L1.2 silently skipped). Parse the command string after -c and
  // recursively extract the real script path from it.
  const inline = command.match(/(?:^|\s|&&|\|\|)\s*(?:bash|\/bin\/bash|sh|zsh)\s+-c\s*(['"])([\s\S]*?)\1/i);
  if (inline) {
    const inner = inline[2];
    const realPath = extractScriptPath(inner);
    if (realPath) return { path: realPath, args: [] };
    return { path: null, args: [] };
  }

  const scriptPath = extractScriptPath(command);
  if (!scriptPath) return { path: null, args: [] };

  const idx = command.indexOf(scriptPath);
  if (idx < 0) return { path: scriptPath, args: [] };

  let rest = command.slice(idx + scriptPath.length);
  // strip pipe/redirect/semicolon connectors (not script args)
  rest = rest.split(/[;|&<>]/)[0].trim();
  const tokens = [...rest.matchAll(/(["'])(.*?)\1|(\S+)/g)];
  const args: string[] = [];
  for (const m of tokens) {
    args.push(m[1] ? m[2] : m[3]);
  }
  return { path: scriptPath, args };
}

function looksLikeScriptPath(tok: string): boolean {
  const t = tok.trim().replace(/^['"]|['"]$/g, '');
  if (!t) return false;
  const low = t.toLowerCase();
  if (['bash', 'sh', 'zsh', 'dash', 'python', 'python3', 'perl', 'ruby', 'node', 'php', 'lua'].includes(low)) return false;
  if (/\.(sh|bash|py|pl|rb|js|php|lua)$/.test(low)) return true;
  if (t.includes('/') && !t.startsWith('-')) return true;
  return false;
}

function extractInlineScriptPath(actionDetail: string): string | null {
  // 盲区修复：内联代码里「执行某个脚本文件」的形态也提取脚本路径，交给脚本引擎递归扫描
  // （否则 os.system('bash x.sh') / subprocess.run(['bash','x.sh']) 里 x.sh 内容完全失明）。
  // 镜像 Python _extract_inline_script_path。
  const code = extractInlineCode(actionDetail);
  if (code) {
    const candidates: string[] = [];
    const osRe = /os\.(?:system|popen)\s*\(\s*(['"])(.*?)\1\s*\)/gi;
    let m: RegExpExecArray | null;
    while ((m = osRe.exec(code)) !== null) candidates.push(m[2]);
    const subListRe = /subprocess\.(?:run|call|Popen|check_output|check_call)\s*\(\s*\[(.*?)\]/gi;
    while ((m = subListRe.exec(code)) !== null) candidates.push(m[1]);
    const subShellRe = /subprocess\.(?:run|call|Popen|check_output|check_call)\s*\(\s*(['"])(.*?)\1[^)]*?shell\s*=\s*true/gi;
    while ((m = subShellRe.exec(code)) !== null) candidates.push(m[2]);

    for (const cand of candidates) {
      const tokens = cand.includes(',')
        ? cand.split(/\s*,\s*/).map(t => t.trim().replace(/^['"]|['"]$/g, ''))
        : cand.split(/\s+/);
      for (const tok of tokens) {
        if (looksLikeScriptPath(tok)) {
          try {
            const resolved = resolvePath(tok.replace(/^['"]|['"]$/g, ''));
            if (existsSync(resolved)) {
              const stat = statSync(resolved);
              if (stat.isFile()) return resolved;
            }
          } catch { /* ignore */ }
        }
      }
    }

    // 兜底：open('x.py').read() 形态
    const openRe = /open\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
    while ((m = openRe.exec(code)) !== null) {
      const p = m[1];
      try {
        const resolved = resolvePath(p);
        if (existsSync(resolved)) {
          const stat = statSync(resolved);
          if (stat.isFile()) return resolved;
        }
      } catch { /* ignore */ }
    }
    return null;
  }

  const re = /open\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
  let m2: RegExpExecArray | null;
  while ((m2 = re.exec(actionDetail)) !== null) {
    const p = m2[1];
    let resolved: string;
    try {
      resolved = resolvePath(p);
      if (existsSync(resolved)) {
        const stat = statSync(resolved);
        if (stat.isFile()) return resolved;
      }
    } catch { /* ignore */ }
  }
  return null;
}

/** Resolve a path: expand ~, resolve relative against cwd. */
function resolvePath(p: string): string {
  let expanded = p;
  if (expanded.startsWith('~/') || expanded === '~') {
    expanded = join(homedir(), expanded.slice(1));
  }
  return resolve(expanded);
}



// ==================== L1/L2 fallback chain scan ====================

/** L1 fallback: scan nodes that weren't inline-scanned during recursion. */
function scanScriptChainWithL1(chain: ScriptChainAnalysisResult, input: AnalysisInput): ScriptChainAnalysisResult {
  for (const node of chain.nodes) {
    if (node.error || !node.preprocessedContent || node.l1Hit) continue;
    const virtualInput: AnalysisInput = {
      ...input,
      aNext: { actionType: 'bash', actionDetail: node.preprocessedContent },
    };
    const l1 = runHeuristicCheck(virtualInput);
    if (l1 && !l1.allowed) {
      node.l1Hit = true;
      node.l1RiskLevel = l1.riskLevel;
      node.l1RiskType = l1.riskType;
      node.l1Reason = l1.reason;
      if (l1.riskLevel === 'critical') {
        chain.hasCritical = true;
        chain.firstHitNode = node;
        break;
      }
    }
  }
  return chain;
}

/**
 * L2 fallback: scan each node's preprocessed content via runLogicCheck.
 * Only reuses action-history-independent rules (sensitive path / dangerous
 * patterns / intent). runLogicCheck runs all L2 rules; we accept its verdict
 * per node (matching Python's per-rule reuse behaviorally).
 */
function scanScriptChainWithL2(chain: ScriptChainAnalysisResult, input: AnalysisInput): ScriptChainAnalysisResult {
  for (const node of chain.nodes) {
    if (node.error || !node.preprocessedContent) continue;
    if (node.l1RiskLevel === 'critical') break;

    const virtualInput: AnalysisInput = {
      ...input,
      aNext: { actionType: 'bash', actionDetail: node.preprocessedContent },
    };
    const l2 = runLogicCheck(virtualInput);
    if (l2 && !l2.allowed) {
      node.l2Hit = true;
      node.l2ViolatedRule = `script_logic:${node.scriptPath}`;
      node.l2RiskLevel = l2.riskLevel;
      node.l2RiskType = l2.riskType;
      node.l2Reason = `脚本 ${node.scriptPath} (深度 ${node.depth}) 中: ${l2.reason}`;
      if (l2.riskLevel === 'critical') {
        chain.hasCritical = true;
        chain.firstHitNode = node;
        break;
      }
    }
  }
  if (!chain.hasHigh) {
    chain.hasHigh = chain.nodes.some(n => ['high', 'critical'].includes(n.l2RiskLevel));
  }
  return chain;
}

/** Keyword scan per node (L3-compatible). Only nodes not hit by L1/L2. */
function scanScriptChainKeywords(chain: ScriptChainAnalysisResult): ScriptChainAnalysisResult {
  for (const node of chain.nodes) {
    if (node.error || !node.preprocessedContent) continue;
    if (node.l1Hit || node.l2Hit) continue;

    const matched = scanScriptForKeywords(node.preprocessedContent);
    node.matchedKeywords = matched;
    node.isSuspicious = matched.length > 0;

    if (matched.length > 0) {
      const risk = assessKeywordCombinationRisk(matched, node.preprocessedContent);
      node.keywordRiskLevel = risk.level;
      node.keywordRiskReason = risk.reason;
    }
  }
  return chain;
}


// ==================== Entry function ====================

/**
 * Analyze script content: recursive tracking + preprocessing + L1/L2/keyword scan.
 * Only runs when actionType is 'bash' and the command invokes a script.
 *
 * Mirrors Python analyze_script_content. L1/L2 reuse wraps each node's
 * preprocessed content as a virtual AnalysisInput.
 */
export function analyzeScriptContent(input: AnalysisInput): ScriptChainAnalysisResult {
  const actionType = input.aNext.actionType.toLowerCase();
  if (actionType !== 'bash') return emptyChain();

  const { path: scriptPath, args: scriptArgs } = extractScriptPathWithArgs(input.aNext.actionDetail);
  let resolvedPath = scriptPath;
  let isInline = false;
  if (!resolvedPath) {
    const inline = extractInlineScriptPath(input.aNext.actionDetail);
    if (!inline) return emptyChain();
    resolvedPath = inline;
    isInline = true;
  }

  // 相对脚本路径按 cwd 解析（对齐 Python base_dir=cwd），避免落到 process.cwd()
  if (resolvedPath && !isAbsolute(resolvedPath) && !resolvedPath.startsWith('~/')) {
    resolvedPath = join(input.cwd || process.cwd(), resolvedPath);
  }

  // ===== 脚本分析引擎（独立引擎层） =====
  // RecursiveTracker 消费 ShellBackend 的 IR：case/if 控制流切片 + 子脚本调用
  // 参数传递（修复子调用参数丢失 + 深层链漏追踪）。对齐 Python RecursiveTracker。
  const l1Adapter: (content: string) => { hit: boolean; riskLevel: string; riskType: string; reason: string; matchedPatterns: string[] } = (content) => {
    const virtualInput: AnalysisInput = {
      ...input,
      aNext: { actionType: 'bash', actionDetail: content },
    };
    const j = runHeuristicCheck(virtualInput);
    if (j && !j.allowed) {
      return { hit: true, riskLevel: j.riskLevel, riskType: j.riskType, reason: j.reason, matchedPatterns: [] };
    }
    return { hit: false, riskLevel: '', riskType: '', reason: '', matchedPatterns: [] };
  };
  const tracker = new RecursiveTracker(l1Adapter);
  const chain = tracker.track(resolvedPath, isInline ? null : scriptArgs, input.cwd || process.cwd());

  if (chain.nodes.length === 0) return chain;

  // L1 fallback + L2 + keyword scans
  scanScriptChainWithL1(chain, input);
  scanScriptChainWithL2(chain, input);
  scanScriptChainKeywords(chain);

  return chain;
}


// ==================== L3 prompt formatting ====================

export function formatScriptChainForPrompt(chain: ScriptChainAnalysisResult): string {
  if (chain.nodes.length === 0) return '';

  const errorNodes = chain.nodes.filter(n => n.error);
  if (errorNodes.length > 0 && chain.nodes.length === 1) {
    return `⚠️ 脚本内容分析失败: ${errorNodes[0].error}`;
  }

  const suspiciousNodes = chain.nodes.filter(n => n.isSuspicious && !n.l1Hit && !n.l2Hit);
  if (suspiciousNodes.length === 0) {
    const safeNodes = chain.nodes.filter(n => !n.error);
    if (safeNodes.length === 0) return '';
    const parts: string[] = ['✓ 脚本内容已分析，未发现危险/可疑操作（L1/L2/关键词扫描均未命中）：'];
    for (const node of safeNodes) {
      const pre = node.preprocessedContent || '';
      let preview = pre.slice(0, 600);
      if (pre.length > 600) preview += `\n... (截断，完整内容 ${pre.length} 字符)`;
      parts.push(
        `   脚本路径: ${node.scriptPath}（递归深度 ${node.depth}，${node.lineCount} 行）\n` +
        `   内容（预处理后）:\n\`\`\`\n${preview}\n\`\`\``
      );
    }
    return parts.join('\n');
  }

  const parts: string[] = [];
  for (const node of suspiciousNodes) {
    const keywordsStr = node.matchedKeywords.join(', ');
    let riskHint = '';
    if (node.keywordRiskLevel && node.keywordRiskReason) {
      riskHint =
        `\n\n🔴 **风险评估**: ${node.keywordRiskLevel.toUpperCase()} 级别\n` +
        `**风险原因**: ${node.keywordRiskReason}\n` +
        `**建议**: 此脚本应被拒绝（Deny），除非有明确的业务需求且已确认目标服务器可信。`;
    }
    const pre = node.preprocessedContent;
    let contentPreview = pre.slice(0, 2000);
    if (pre.length > 2000) contentPreview += `\n... (截断，完整内容 ${pre.length} 字符)`;
    parts.push(
      `⚠️ 脚本内容包含可疑关键词:\n` +
      `   脚本路径: ${node.scriptPath}\n` +
      `   递归深度: ${node.depth}\n` +
      `   可疑关键词: ${keywordsStr}\n` +
      `   脚本行数: ${node.lineCount}${riskHint}\n\n` +
      `### 脚本内容（预处理后）###\n\`\`\`\n${contentPreview}\n\`\`\`\n`
    );
  }

  let header = `⚠️ 检测到脚本执行链（共 ${chain.nodes.length} 个脚本），其中 ${suspiciousNodes.length} 个包含可疑关键词:\n`;
  if (chain.maxDepthReached) header += '⚠️ 注意：递归追踪触达深度上限，可能存在更深层的脚本调用未被扫描。\n';
  if (chain.maxSizeReached) header += '⚠️ 注意：累计文件大小触达上限，部分脚本可能未被完整读取。\n';

  return header + parts.join('\n---\n\n');
}

/** [deprecated] Use formatScriptChainForPrompt. */
export function formatScriptAnalysisForPrompt(chain: ScriptChainAnalysisResult): string {
  return formatScriptChainForPrompt(chain);
}


