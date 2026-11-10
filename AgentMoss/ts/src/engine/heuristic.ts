import { SecurityJudgment, HeuristicResult } from './types';
import type { AnalysisInput } from './coordinator';
import { getCustomRules } from '../config';
import { getAgentExtensions, mergeAgentExtensions } from '../agents';
import { getScenarioExtensionsMulti } from '../scenarios';
import { isLayerEnabled } from '../infra/runtime-config';
import type { CommandPattern, InjectionKeyword } from '../agents/types';
import { loadL1 } from '../infra/rules-loader';
import {
  ROOT_SENSITIVE_PATHS,
  HOME_SENSITIVE_PATHS,
  CREDENTIAL_PATHS,
  isWriteOperation,
} from './logic-rules';

/**
 * Layer 1: Feature-matching static detection.
 * Uses regex patterns to detect dangerous commands, user-defined rules,
 * and prompt injection keywords.
 * Runs in < 1ms, no LLM cost.
 */

// Prompt injection keywords (synced with Python linux.py _DEFAULT_INJECTION_KEYWORDS)
export const INJECTION_KEYWORDS: { keyword: string; riskLevel: string; lang: string }[] = (() => {
  // 归一化自 agent_moss/rules/l1_rules.json 的注入段（单一事实源，与 Python 共用）。
  const kws = (loadL1().injection_detection || []) as any[];
  return kws.map((k) => ({
    keyword: k.keyword,
    riskLevel: k.risk_level,
    lang: k.lang || 'en',
  }));
})();

// High-risk command patterns (unified Python + TS, all case-insensitive)
export const DANGEROUS_PATTERNS: { pattern: RegExp; severity: string; description: string; riskType: string }[] = (() => {
  // 归一化自 agent_moss/rules/l1_rules.json 的危险命令段（单一事实源，与 Python 共用）。
  const cmds = (loadL1().dangerous_commands || []) as any[];
  return cmds.map((c) => ({
    pattern: new RegExp(c.pattern, 'i'),
    severity: c.risk_level,
    riskType: c.risk_type,
    description: c.reason,
  }));
})();

export function runHeuristicCheck(input: AnalysisInput): SecurityJudgment | null {
  const command = `${input.aNext.actionType}: ${input.aNext.actionDetail}`;
  const matched: string[] = [];
  let highestSeverity = 'low';
  let highestRiskType = '';

  // Check user-defined custom rules first（对齐 Python UserRuleMatcher 命中即短路返回，
  // 不让后续 CommandPatternScanner/SensitivePathChecker 叠加取最高遮蔽 user rules 的判定）。
  const userRules = getCustomRules();
  for (const rule of userRules) {
    try {
      const re = new RegExp(rule.pattern);
      if (re.test(command)) {
        if (rule.action === 'Deny') {
          return {
            allowed: false,
            reason: `命中用户敏感动作规则: ${rule.description || rule.pattern}`,
            riskLevel: rule.severity as SecurityJudgment['riskLevel'],
            riskType: 'sensitive_action',
            confidence: 90,
            source: 'heuristic',
            violatedLayers: ['L1.1'],
          };
        }
        // Allow rules just pass through
      }
    } catch { /* invalid regex, skip */ }
  }

  // Check built-in dangerous patterns
  // NEW-FP-I: echo/printf 引号内参数是字面量非真实命令，剥掉引号内容后再匹配，
  // 避免 echo "rm -rf /tmp" 的输出文本被当真实命令误报。引号外的重定向 > 和管道 |
  // 后的真实操作保留（echo "x" > /etc/passwd 仍被 >/etc/ 检测，echo pass | passwd
  // 的 passwd 仍被匹配）。非 echo/printf 段（rm -rf; echo done 的 rm 段）不剥。
  const scanDetail = normalizePathSegments(stripLiteralTextSegments(input.aNext.actionDetail));
  const scanCommand = `${input.aNext.actionType}: ${scanDetail}`;
  let topRiskType = '';
  // ssh-keygen 生成模式：-f 是写目标（生成新私钥），不命中「访问私钥」命令正则。
  const exemptKeygen = isSshKeygenGenerate(input.aNext.actionDetail);
  for (const rule of DANGEROUS_PATTERNS) {
    if (rule.pattern.test(scanCommand)) {
      if (exemptKeygen && rule.riskType === 'file_access') continue;
      matched.push(rule.description);
      if (severityRank(rule.severity) > severityRank(highestSeverity)) {
        highestSeverity = rule.severity;
        topRiskType = rule.riskType;
      }
    }
  }
  highestRiskType = topRiskType || highestRiskType;

  // Check agent-specific extra command patterns (追加在通用规则之后)
  // agent 专属规则（agent_id）+ 场景定制规则（scenario_id，如 bank 沙箱的目录白名单/禁 ssh），
  // 合并后统一注入 L1 检测。场景规则：显式 scenarioId > 环境变量 AGENT_MOSS_SCENARIO。
  // Agent/场景专属规则总开关（console 层级全局开关 agent_rules_enabled / scenario_rules_enabled）
  const agentExt = mergeAgentExtensions(
    isLayerEnabled('agent_rules_enabled') ? getAgentExtensions(input.agentId) : null,
    isLayerEnabled('scenario_rules_enabled')
      ? getScenarioExtensionsMulti(input.scenarioId || process.env.AGENT_MOSS_SCENARIO || '')
      : null,
  );
  if (agentExt?.extra_command_patterns) {
    for (const rule of agentExt.extra_command_patterns) {
      try {
        const re = new RegExp(rule.pattern, 'i');
        if (re.test(scanCommand)) {
          matched.push(`agent 专属规则: ${rule.reason}`);
          if (severityRank(rule.risk_level) > severityRank(highestSeverity)) {
            highestSeverity = rule.risk_level;
            highestRiskType = rule.risk_type;
          }
        }
      } catch { /* invalid regex, skip */ }
    }
  }

  // Check prompt injection keywords (通用 + agent_ext.extra_injection_keywords)
  // 搜索/查询类工具（search-WebSearch 等）的 actionDetail 是查询参数（数据载荷），
  // 不是指令。注入检测只针对指令性文本（用户 prompt / reason / 命令），
  // 排除搜索工具的 actionDetail，避免 "搜索 jailbreak" 等被误判为注入攻击。
  const injectionText = isSearchActionType(input.aNext.actionType)
    ? `${input.aNext.actionType} ${input.reason || ''} ${input.promptSession || ''}`.toLowerCase()
    : `${input.aNext.actionType} ${input.aNext.actionDetail} ${input.reason || ''} ${input.promptSession || ''}`.toLowerCase();
  const injectionHits = checkInjectionKeywords(injectionText, agentExt?.extra_injection_keywords);
  if (injectionHits.length > 0) {
    const topHit = injectionHits.reduce((a, b) => severityRank(a.riskLevel) >= severityRank(b.riskLevel) ? a : b);
    matched.push(...injectionHits.map(h => `注入关键词 [${h.lang}]: ${h.keyword}`));
    if (severityRank(topHit.riskLevel) > severityRank(highestSeverity)) {
      highestSeverity = topHit.riskLevel;
      highestRiskType = 'prompt_injection';
    }
  }

  // ===== 从 L2 搬入的静态子检测器（只看 a_next）=====
  const actionTypeL = input.aNext.actionType.toLowerCase();
  const detailL = input.aNext.actionDetail.toLowerCase();
  const isExcludedType = SENSITIVE_EXCLUDED_PREFIXES.some(p => actionTypeL.startsWith(p));

  // 危险操作模式检测 + 敏感路径检测 + 主目录删除检测取最高合并（对齐 Python
  // HeuristicDetector.detect 的 max 合并语义）。不"先命中即 return"：A16 重定向写设备
  // high 不会遮蔽 checkSensitivePath 的 /dev/mem deny_both critical，双端漂移（Python
  // 取最高 → critical）。主目录检查在 max 合并里参与，不受只读/危险命令早退遮蔽。
  const dangerousResult = checkDangerousPatterns(actionTypeL, detailL);
  const pathResult = isExcludedType ? null : checkSensitivePath(detailL, input.cwd || '/', agentExt);
  const homeResult = checkHomeDeletion(actionTypeL, detailL);
  const mergeResults = [dangerousResult, pathResult, homeResult].filter(Boolean) as SecurityJudgment[];
  if (mergeResults.length > 0) {
    let best = mergeResults[0];
    for (const r of mergeResults) {
      if (severityRank(r.riskLevel) > severityRank(best.riskLevel)) best = r;
    }
    // agent 专属规则 / 用户规则命中（matched）若风险更高（如 xiaoo-guardian critical）,
    // 不能被 home 删除检测的 high 抢走——返回 matched（Python UserRuleMatcher 命中即
    // 短路返回，不参与 max 合并；此处对齐：只在 merge 结果低于 matched 时用 matched）。
    if (severityRank(highestSeverity) > severityRank(best.riskLevel)) {
      return {
        allowed: false,
        reason: `检测到高危操作: ${matched.join(', ')}`,
        riskLevel: highestSeverity as SecurityJudgment['riskLevel'],
        riskType: highestRiskType,
        confidence: 95,
        source: 'heuristic',
        violatedLayers: ['L1.1'],
      };
    }
    return best;
  }
  // merge 无命中，但 agent/用户规则/注入命中（matched）——返回 matched。
  if (matched.length > 0) {
    return {
      allowed: false,
      reason: `检测到高危操作: ${matched.join(', ')}`,
      riskLevel: highestSeverity as SecurityJudgment['riskLevel'],
      riskType: highestRiskType,
      confidence: 95,
      source: 'heuristic',
      violatedLayers: ['L1.1'],
    };
  }

  // 横向移动检测：ssh/scp/rsync 到非本机主机
  const lateralResult = checkLateralMovement(detailL);
  if (lateralResult) return lateralResult;

  return null; // No match, pass to next layer
}

function checkInjectionKeywords(
  text: string,
  extraKeywords?: InjectionKeyword[],
): { keyword: string; riskLevel: string; lang: string }[] {
  const hits: { keyword: string; riskLevel: string; lang: string }[] = [];
  for (const entry of INJECTION_KEYWORDS) {
    if (text.includes(entry.keyword.toLowerCase())) {
      hits.push(entry);
    }
  }
  // agent 专属注入关键词（追加在后）
  if (extraKeywords) {
    for (const entry of extraKeywords) {
      if (text.includes(entry.keyword.toLowerCase())) {
        hits.push({ keyword: entry.keyword, riskLevel: entry.risk_level, lang: entry.lang });
      }
    }
  }
  return hits;
}

export function isInlineScriptCommand(actionDetail: string): boolean {
  // 判断命令是否为内联脚本解释器命令（python -c, perl -e, php -r 等）
  const re = /(?:^|\s)(?:python|python3|python3\.\d+|perl|perl5|ruby|jruby|mruby|node|php|lua)\s+(?:-[a-zA-Z]*[cer][a-zA-Z]*\s+)/i;
  return re.test(actionDetail);
}

/**
 * NEW-FP-I: 对首词 echo/printf 的命令段剥掉引号内容（字面量参数）。
 *
 * echo/printf 是文本输出命令，其引号内参数是被打印的字面量而非真实命令——
 * `echo "rm -rf /tmp"` 是打印这串文本不是执行删除。但 DANGEROUS_PATTERNS 旧实现
 * 对整个 actionDetail 做正则匹配，引号内的 rm/chmod/mkfs 等危险命令模式被误当
 * 真实命令匹配 → 误报（NEW-FP-I）。
 *
 * 修复：按 &&/||/;/换行 分段，首词是 echo/printf 的段，剥掉引号内容（字面量），
 * 保留引号外的重定向 >/>> 和管道 | 后的真实操作：
 * - `echo "rm -rf /tmp"` → `echo `（rm 模式不匹配，误报消除）
 * - `echo "x" > /etc/passwd` → `echo  > /etc/passwd`（重定向 >/etc/ 仍匹配，真实写不漏报）
 * - `rm -rf /tmp; echo done` → rm 段不剥，echo 段剥，rm 仍匹配（真实危险不漏报）
 * - `echo pass | passwd` → passwd 无引号在管道后，剥后仍保留（管道注入不漏报）
 */
export function stripLiteralTextSegments(actionDetail: string): string {
  // 旁路（NEW-FN-H 待修）：含"写脚本 + 后续执行"或"管道喂解释器"绕过链时整条不剥离。
  // 保留引号内路径让 L1 凭据检测兜底，避免剥离后绕过链漏检（inline-09/10 依赖）。
  // - inline-09: echo "cat /etc/shadow" > /tmp/x.sh && bash /tmp/x.sh（写脚本+执行）
  // - inline-10: printf 'cat /etc/shadow' | bash（管道喂解释器）
  const writeScriptExec = />\s*[/~]\S*\.(sh|py|pl|rb)\b/.test(actionDetail) &&
    /(?:&&|\|\||;|\n|\|)\s*(?:bash|sh|zsh|dash|python|perl|ruby|node)/.test(actionDetail);
  const pipeToInterpreter = /\|\s*(?:bash|sh|zsh|dash|python|perl|ruby|node)\b/.test(actionDetail);
  if (writeScriptExec || pipeToInterpreter) {
    return actionDetail;
  }
  // 按命令分隔符分段，但跳过引号内的分隔符（echo "a; b" 的 ; 在引号内不分段）
  const resultParts: string[] = [];
  for (const seg of splitCommandSegments(actionDetail)) {
    const fw = (seg.trim().split(/\s+/)[0] || '').toLowerCase();
    if (fw === 'echo' || fw === 'printf') {
      // 先摘重定向目标的引号路径为裸路径（保留真实写目标），再剥剩余引号内容
      const segUnquotedRedirect = seg.replace(
        />{1,2}\s*(['"])([~./][^'"]+)\1/g,
        (_m, _q, p: string) => '>' + p,
      );
      resultParts.push(segUnquotedRedirect.replace(/'[^']*'|"[^"]*"/g, ''));
    } else {
      resultParts.push(seg);
    }
  }
  return resultParts.join('');
}

/**
 * 剥离 heredoc 文档字面量内容（<<EOF ... EOF / <<'EOF' ... EOF）。
 * heredoc 是文档正文不是命令，其中的 `*`/`?`/`rm`/`删除` 是文本而非删除操作。
 * 不剥离会导致 checkDangerousPatterns 的「通配符+删除」误判写文档为批量删除
 * （NEW-FP：写含 markdown 加粗 / 三元表达式 / 描述含 rm 的周报即误报）。
 * 支持 <<EOF / <<-EOF / <<'EOF' / <<"EOF"，匹配到行首结束标记，替换为 <<heredoc>>。
 */
export function stripHeredocContent(actionDetail: string): string {
  return actionDetail.replace(
    /<<-?\s*(?:['"]?)([A-Za-z_][A-Za-z0-9_]*)(?:['"]?)[^\n]*\n[\s\S]*?\n\s*\1\s*(?:\n|$)/g,
    '<<heredoc>>\n',
  );
}

/**
 * NORM-PATH: 折叠路径混淆段，堵路径穿越变体（对齐 Python _normalize_path_segments，
 * 对应 CVE-2023-37274 攻击面）。
 *
 * 敏感路径/危险命令匹配前，把「路径混淆」归一回真实路径，避免子串/正则漏检：
 * - 连续斜杠 `//` → `/`（`cat /etc//shadow` 与 `cat /etc/shadow` 等价，应同判）
 * - 单点段 `/./` → `/`（`cat /etc/./shadow` 同理）
 *
 * 不做 `..` 解析（`..` 可能改变路径语义，且现有 dangerous pattern 已对 `..`
 * 穿越有兜底），只折叠无歧义的 `//` 与 `/./`，避免过度归一化误伤。
 *
 * 约束（must not break）：
 * 1. 跳过协议 URL 的 `//`（`curl http://x` 的 `http://` 是协议分隔，折叠成
 *    `http:/x` 会破坏 curl 下载/管道检测）。
 * 2. 跳过引号内字面量（`grep "a//b"` 引号内是搜索模式非路径）。
 */
export function normalizePathSegments(text: string): string {
  // 1. 保护协议 URL 的 //（用不含 / 的令牌占位，避免被 /{2,} 折叠）
  const protTokens: string[] = [];
  let t = text.replace(/\b(https?|ftp|file):\/\//gi, (m) => {
    const scheme = m.slice(0, m.indexOf(':'));
    protTokens.push('://');
    return `${scheme}__PROT${protTokens.length - 1}__`;
  });
  // 2. 保护引号内内容（非路径字面量不折叠）
  const quoteTokens: string[] = [];
  t = t.replace(/'[^']*'|"[^"]*"/g, (m) => {
    quoteTokens.push(m);
    return `__Q${quoteTokens.length - 1}__`;
  });
  // 3. 折叠引号外 + 非 URL 的连续斜杠与单点段
  t = t.replace(/\/{2,}/g, '/');
  t = t.replace(/\/\.\//g, '/');
  // 4. 还原引号与协议
  for (let i = 0; i < quoteTokens.length; i++) {
    t = t.replace(`__Q${i}__`, quoteTokens[i]);
  }
  for (let i = 0; i < protTokens.length; i++) {
    t = t.replace(`__PROT${i}__`, protTokens[i]);
  }
  return t;
}

/**
 * 按命令分隔符分段，跳过引号内的分隔符（对齐 Python _split_command_segments）。
 * echo "a; b && c" 的引号内分隔符是字面量非命令分隔，不能分段——否则
 * 引号内 chmod/mkfs 等词会脱离 echo 段被当独立命令首词误匹配（NEW-FP-I）。
 */
function splitCommandSegments(actionDetail: string): string[] {
  const segments: string[] = [];
  let cur = '';
  let quote: string | null = null;
  for (let i = 0; i < actionDetail.length; i++) {
    const ch = actionDetail[i];
    if (quote) {
      cur += ch;
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      cur += ch;
      continue;
    }
    if (ch === ';' || ch === '\n') {
      segments.push(cur); segments.push(ch); cur = '';
      continue;
    }
    if (ch === '&' && actionDetail[i + 1] === '&') {
      segments.push(cur); segments.push('&&'); cur = '';
      i++; continue;
    }
    if (ch === '|' && actionDetail[i + 1] === '|') {
      segments.push(cur); segments.push('||'); cur = '';
      i++; continue;
    }
    cur += ch;
  }
  if (cur) segments.push(cur);
  return segments;
}

function severityRank(s: string): number {
  const ranks: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };
  return ranks[s] || 0;
}

// ==================== 从 L2 搬入 L1 的静态子检测器 ====================
// 以下三个检测器只看 a_next（不看 action_history），按"L1 只看这一步"原则
// 从 logic-rules.ts 搬入。逻辑原样保留，source 改为 'heuristic'、
// violatedLayers 改为 ['L1.1']，对齐 L1 特征匹配检测的层号。

// 敏感路径检测排除的非文件工具前缀（避免 memory-searchMemory 等误报）
const SENSITIVE_EXCLUDED_PREFIXES = ['memory-', 'skill-', 'skill-manager-', 'mailbox-', 'app-'];

// 搜索/查询类工具前缀：其 actionDetail 是「查询数据」（如 query=...），不是指令。
// 注入关键词检测应只针对指令性文本（用户 prompt / reason / 命令），
// 否则搜索 "jailbreak"、"bypass" 等资料会被 L1 注入检测误判为注入攻击（prompt injection 误报）。
// 与 Python 端 agent_moss/engine/heuristic.py 的 _SEARCH_ACTION_PREFIXES 保持一致。
const SEARCH_ACTION_PREFIXES = ['search-', 'web-', 'browser-', 'query-', 'websearch', 'web_search'];

function isSearchActionType(actionType: string): boolean {
  const at = actionType.toLowerCase();
  return (
    SEARCH_ACTION_PREFIXES.some((p) => at.startsWith(p)) ||
    ['websearch', 'web_search', 'search', 'query'].includes(at)
  );
}

/**
 * 敏感路径访问检测（从 L2 搬入）。
 * deny_both（凭据）：无论读写都拦截，isCredential=true
 * deny_read：只拦截读取（如 /dev/random）
 * deny_write：只拦截写入/删除
 */
export function checkSensitivePath(
  command: string,
  cwd: string,
  agentExt?: import('../agents').AgentExtensions | null,
): SecurityJudgment | null {
  const expandedCwd = cwd.replace(/^~/, process.env.HOME || '/home/user');

  // 写判定统一用 isWriteOperation（对齐 Python _is_write_operation 单一事实源），
  // 替代原手写 isWriteOpFlag（含 ''.includes(kw) 笔误、重定向逻辑矛盾）。
  // command 在此 = actionDetail 小写（调用方 :231 传 detailL），actionType 留空——
  // isWriteOperation 的 actionType.includes 走空串无影响，actionDetail 部分覆盖 command。
  const isWriteOpFlag = isWriteOperation('', command);
  // ssh-keygen 生成模式：-f 是写目标（生成新私钥），不命中私钥 deny_both 拦截。
  const keygenGenerate = isSshKeygenGenerate(command);

  // NEW-FP-I: echo/printf 引号内参数是字面量，其中的敏感路径不应被当真实访问。
  // 对首词 echo/printf 的段剥引号内容后再做路径匹配。非 echo/printf 段（cat "/etc/shadow"）
  // 不剥，引号内真实路径参数仍匹配。引号外的重定向（echo "x" > /etc/passwd）保留。
  // NORM-PATH: 再折叠路径混淆段（//、/./），堵路径穿越变体（cat /etc//shadow 漏检）。
  const pathScanText = normalizePathSegments(stripLiteralTextSegments(command));

  // 边界路径匹配（对齐 Python heuristic.py:121-132，避免子串误报）。
  // 裸 command.includes(sp.path) 会把 /etc/passwd 命中到 /tmp/etc_passwd_backup、
  // /boot/ 命中到 /boot-log。改用边界正则：/ 开头路径前导用 ^|空白|/|反斜杠|引号，
  // 其余用 \b；尾随 \b。凭据（deny_both）尤其需要边界（如 .env 不能命中 .environment）。
  const pathMatches = (text: string, path: string): boolean => {
    // 含正则前瞻语法（如 (?!\\.pub) 排除公钥变体）时保留前瞻不转义，仅转义其余元字符。
    // 把路径切成「前瞻块 / 其余」分段处理，前瞻块原样保留，其余分段转义元字符。
    const parts = path.split(/(\(\?!.*?\))/);
    const escaped = parts.map(part => {
      if (part.startsWith('(?!')) return part; // 前瞻块原样
      return part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }).join('');
    const re = path.startsWith('.') || path.startsWith('/')
      ? new RegExp(`(?:^|[\\s/\\\\'"])${escaped}\\b`, 'i')
      : new RegExp(`\\b${escaped}\\b`, 'i');
    return re.test(text);
  };

  for (const sp of ROOT_SENSITIVE_PATHS) {
    if (pathMatches(pathScanText, sp.path.toLowerCase())) {
      // ssh-keygen 生成模式：-f 是写目标，放行（host key 生成 -A、私钥生成 -t 不读已有私钥）。
      if (keygenGenerate) continue;
      // /dev/random：只拦截读取操作，写入/删除放行（读取可耗尽熵池导致 TLS 阻塞）
      if (sp.path === '/dev/random') {
        if (isWriteOpFlag) {
          continue; // 允许写入操作（投喂熵池）
        }
        return {
          allowed: false,
          reason: `读取敏感路径: ${sp.desc} (${sp.path})`,
          riskLevel: sp.riskLevel as SecurityJudgment['riskLevel'],
          riskType: 'file_access',
          confidence: 90,
          source: 'heuristic',
          violatedLayers: ['L1.1'],
        };
      }
      // 非凭据路径：只拦截写入/删除操作，只读访问放行。
      // 凭据路径（sp.credential=true，如 /etc/shadow、SSH 私钥、AWS 凭证）：
      // 读写均拦（读取凭据同样危险）。与 py deny_both 一致。
      if (!isWriteOpFlag && !sp.credential) {
        continue;
      }
      return {
        allowed: false,
        reason: `尝试访问系统敏感路径: ${sp.desc} (${sp.path})`,
        riskLevel: sp.riskLevel as SecurityJudgment['riskLevel'],
        riskType: 'file_access',
        confidence: 90,
        source: 'heuristic',
        violatedLayers: ['L1.1'],
        isCredential: !!sp.credential,
      };
    }
  }

  for (const sp of HOME_SENSITIVE_PATHS) {
    const expanded = `${expandedCwd}/${sp.path}`;
    // NEW-FP-3: 统一用边界匹配（pathMatches：/ 或 . 开头路径前导用 ^|空白|/|反斜杠|引号，
    // 尾随 \b），替代原裸正则子串——目录级条目（.ssh/.aws）裸子串会把 .sshkey、.ssh 内嵌
    // 片段都命中，误报面过宽。与 ROOT 循环、Python _SensitivePathMatcher 语义对齐。
    // 私钥路径（不以 .pub 结尾）排除公钥变体：.ssh/id_rsa 不应命中 .ssh/id_rsa.pub（公钥公开）。
    let pPath = sp.path;
    if (!sp.path.endsWith('.pub')) pPath = `${sp.path}(?!\\.pub)`;
    // NEW-FP-1 审核（dirDelOnly）：目录级条目（.ssh/.aws）的尾随 .pub 前瞻后再判
    // 「目录前缀」——.ssh 后只接受 /、空白、引号、反斜杠、行尾，不接受继续拼字符
    // （~/.ssh.bak、~/.ssh_backup 是独立备份目录，删备份不删 .ssh 本体）。
    // pathMatches 的通用 \b 在 ".ssh" 与 ".bak" 之间的 h|. 处仍构成边界，挡不住，
    // 故 dirDelOnly 路径额外走目录前缀精确匹配（/home/<u>/.ssh 全展开形态也在列）。
    let dirPrefixMatch: boolean | null = null;
    if (sp.dirDelOnly) {
      // 目录前缀精确匹配：路径字面量 <t>（.ssh / 全展开绝对路径）后只接受
      // /、空白、引号、反斜杠、行尾。模板参数是「路径」，被测文本是 pathScanText。
      const dirRe = (t: string) =>
        new RegExp(`(?:^|[\\s/\\\\'"])${t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:/|[\\s'"\\\\]|$)`, 'i');
      dirPrefixMatch = dirRe(sp.path).test(pathScanText) || dirRe(expanded.toLowerCase()).test(pathScanText);
    }
    const pathReMatch = sp.dirDelOnly ? !!dirPrefixMatch : pathMatches(pathScanText, pPath);
    const expandedReMatch = sp.dirDelOnly
      ? false
      : pathMatches(pathScanText, expanded + (sp.path.endsWith('.pub') ? '' : '(?!\\.pub)'));
    if (pathReMatch || expandedReMatch) {
      // ssh-keygen 生成模式：-f 是写目标（生成新私钥），放行（读模式 -y/-l/-p 不受豁免）。
      if (keygenGenerate) continue;
      // dirDelOnly 目录级条目（.ssh/.aws）独立于 isWriteOpFlag 判定：
      // 只拦「删除该目录」或「归档/复制读源整包读取」，不拦 mkdir/chmod/echo/ls/cat
      // 等正常初始化/只读/解压恢复。与 Python dir_del_only 语义对齐（缺口修复）。
      if (sp.dirDelOnly) {
        if (isDeleteActionForDir(command, sp.path)) {
          return {
            allowed: false,
            reason: `删除敏感目录: ${sp.desc} (${sp.path})`,
            riskLevel: sp.riskLevel as SecurityJudgment['riskLevel'],
            riskType: 'file_access',
            confidence: 90,
            source: 'heuristic',
            violatedLayers: ['L1.1'],
            isCredential: !!sp.credential,
          };
        }
        if (isArchiveReadOfDir(command, sp.path)) {
          return {
            allowed: false,
            reason: `归档/复制读取敏感目录: ${sp.desc} (${sp.path})`,
            riskLevel: sp.riskLevel as SecurityJudgment['riskLevel'],
            riskType: 'file_access',
            confidence: 90,
            source: 'heuristic',
            violatedLayers: ['L1.1'],
            isCredential: !!sp.credential,
          };
        }
        continue;
      }
      // 非凭据路径：只拦截写入/删除操作，只读访问放行。
      // 凭据路径（sp.credential=true，如 SSH 私钥、AWS 凭证）：
      // 读写均拦（读取凭据同样危险）。与 py deny_both 一致。
      if (!isWriteOpFlag && !sp.credential) {
        continue;
      }
      return {
        allowed: false,
        reason: `尝试访问敏感路径: ${sp.desc} (${sp.path})`,
        riskLevel: sp.riskLevel as SecurityJudgment['riskLevel'],
        riskType: 'file_access',
        confidence: 90,
        source: 'heuristic',
        violatedLayers: ['L1.1'],
        isCredential: !!sp.credential,
      };
    }
  }

  // agent 专属敏感路径（追加在通用规则之后）
  if (agentExt?.extra_sensitive_paths && agentExt.extra_sensitive_paths.length > 0) {
    for (const sp of agentExt.extra_sensitive_paths) {
      const spPath = sp.path.toLowerCase();
      const expanded = `${expandedCwd}/${spPath}`;
      if (pathMatches(command, spPath) || pathMatches(command, expanded.toLowerCase())) {
        const denyMode = sp.deny_mode || (sp.credential ? 'deny_both' : sp.read_only ? 'deny_read' : 'deny_write');
        if (denyMode === 'deny_read') {
          if (isWriteOpFlag) continue;
        } else if (denyMode === 'deny_write') {
          if (!isWriteOpFlag) continue;
        }
        // deny_both：读写均拦
        return {
          allowed: false,
          reason: `尝试访问 agent 专属敏感路径: ${sp.desc} (${sp.path})`,
          riskLevel: sp.risk_level as SecurityJudgment['riskLevel'],
          riskType: 'file_access',
          confidence: 90,
          source: 'heuristic',
          violatedLayers: ['L1.1'],
          isCredential: !!sp.credential,
        };
      }
    }
  }

  // Credential files: always intercept regardless of read/write
  // Files starting with . need special handling since \b doesn't match before .
  // 边界字符含引号：凭据常出现在 open('.env')、cat ".env" 等引号上下文里
  for (const cp of CREDENTIAL_PATHS) {
    const escaped = cp.path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = cp.path.startsWith('.')
      ? new RegExp(`(?:^|[\\s/\\\\'"])${escaped}\\b`)
      : new RegExp(`\\b${escaped}\\b`);
    if (re.test(command)) {
      return {
        allowed: false,
        reason: `访问敏感路径: ${cp.desc} (${cp.path})`,
        riskLevel: cp.riskLevel as SecurityJudgment['riskLevel'],
        riskType: 'file_access',
        confidence: 90,
        source: 'heuristic',
        violatedLayers: ['L1.1'],
        isCredential: true,
      };
    }
  }

  // Check deletion of sensitive directories
  if ((command.includes('rm ') || command.includes('unlink')) &&
      (command.includes('/etc/') || command.includes('/root/') || command.includes('/var/log/'))) {
    return {
      allowed: false,
      reason: '检测到删除关键系统目录内容',
      riskLevel: 'critical',
      riskType: 'file_access',
      confidence: 90,
      source: 'heuristic',
      violatedLayers: ['L1.1'],
    };
  }

  return null;
}

/** 主目录删除/写改检测（NEW-FN，对齐 Python HomeDeletionChecker）：rm -rf ~ / $HOME / 变量间接删主目录。 */
// 主目录根目标：~ / $HOME / ${HOME}（可带尾斜杠、通配全内容 / 自身点）。
// 语义：只拦「删主目录根/全部内容」，不拦「删主目录下具体子路径」——NEW-FP 修复：
//   rm -rf ~ / rm -rf ~/ / rm -rf ~/* / rm -rf ~/.* / rm -rf $HOME / rm -rf $HOME/ 拦；
//   rm -rf ~/project/build / rm -rf ~/.cache（定向清理具体子路径）放行——
//   凭据子目录（~/.ssh、~/.aws/credentials、.gnupg）由敏感路径独立兜底，不依赖本子检测器。
// 前界 ^|空白|=|引号|$（命令替换内）；后界 行尾|空白|引号|;|}（不含 / 子路径段）；
// 允许 0..1 个 / 后跟 *、.*、.（通配全内容/自身）。
const HOME_TARGET_RE = /(?:^|[\s="'($])(?:~|(?:\$home|\$\{home\}))(?:\/(?:\.\*|\*|\.)?)?(?=[\s"';}|&)]|$)/i;
// 捕获整个赋值值（~/x、$HOME/x、${HOME}/x、/home/xxx、命令替换 $()），由 isHomeValue 判定。
const HOME_ASSIGN_RE = /([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(~[A-Za-z0-9_./-]*|\$HOME[A-Za-z0-9_./-]*|\$\{HOME\}[A-Za-z0-9_./-]*|\/home\/[^\s;|&]+|\$\((?:[^()]|\([^()]*\))*\))(?=\s|;|$|\||&)/gi;

function isHomeValue(path: string): boolean {
  // detailL 已 toLowerCase，$HOME→$home；统一小写比对（对齐 Python）。
  let p = path.trim().toLowerCase();
  // 命令替换：$(echo ~) / $(echo $HOME) / $(echo ~/x)——剥离 $() 内层，复用根目标判定。
  if (p.startsWith('$(') && p.endsWith(')')) {
    const inner = p.slice(2, -1).trim();
    return HOME_TARGET_RE.test(' ' + inner);
  }
  // 绝对路径根：仅 /home/<user> 或 /home/<user>/（后代路径不算）。
  if (/^\/home\/[^/\s]+\/?$/.test(p)) return true;
  return HOME_TARGET_RE.test(' ' + p);
}

function isDeleteCommand(seg: string): boolean {
  const s = seg.trimStart();
  if (/^(?:rm|rmdir|unlink)\b/i.test(s)) return true;
  return /删除|移除/.test(s);
}

/**
 * NEW-FN-1: `..` 穿越段是否解析到「主目录根或以上」（删主目录根的放大形态，对齐 Python
 * HomeDeletionChecker._home_escape_target）。
 * rm -rf ~/.. == 删 /home；rm -rf $HOME/../.. == 删 /。深度行走（token 化 + .. 弹栈）判定：
 *  - 起点为主目录根（~/、$HOME/、/home/<user>/），行走后深度 <= 根深度 → 拦（删根及以上）；
 *  - 深度 > 根深度（落在具体子路径，如 ~/a/../b）→ 定向清理，放行。
 */
function homeEscapeTarget(seg: string): boolean {
  const low = seg.toLowerCase();
  const re = /(?:~|(?:\$home|\$\{home\})|\/home\/[a-z0-9_.-]+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(low)) !== null) {
    const endIdx = m.index + m[0].length;
    const tail = low.slice(endIdx);
    if (!tail) continue;
    let token = tail.trimStart().split(/\s+/)[0] || '';
    token = token.split('&&')[0].split('||')[0].split(';')[0].replace(/\/+$/, '');
    token = token.replace(/^['"]|['"]$/g, '');
    const segments = token.split('/').filter(s => s && s !== '.');
    if (!segments.some(s => s === '..')) continue; // 无 .. 由 HOME_TARGET_RE 覆盖
    let depth = 0; // 主目录根 = 深度 0
    let minDepth = 0; // 行走过程中的最低深度（记录中途逃逸）
    for (const s of segments) {
      depth += (s === '..' ? -1 : 1);
      minDepth = Math.min(minDepth, depth);
    }
    // 中途曾逃出主目录根（~/a/../.. → minDepth<0，目标 /home/… 或 / 级）→ 拦，
    // 无论最终是否回升；~/a/../b（1→0→1，minDepth=0 未出界）不受影响仍放行。
    if (minDepth < 0) return true;
    if (depth <= 0) return true;
  }
  return false;
}

export function checkHomeDeletion(actionType: string, actionDetail: string): SecurityJudgment | null {
  // 只对 bash 类命令判定
  if (actionType !== 'bash' && actionType !== 'executebash' && actionType !== 'terminal-executebash') return null;
  const segs = actionDetail.split(/&&|\|\||;|\n/).map(s => s.trim()).filter(Boolean);

  // ① 删除类命令段 + 主目录根目标：rm -rf ~ / rm -rf $HOME / rm -rf ~/ 等（不拦 ~/子路径）。
  // NEW-FN-1: 段内主目录根目标 + `..` 穿越解析——rm -rf ~/..（删 /home）、
  // rm -rf $HOME/../..（删 /）等形态由 homeEscapeTarget 深度解析（对齐 Python）。。
  for (const seg of segs) {
    if (!isDeleteCommand(seg)) continue;
    if (HOME_TARGET_RE.test(seg) || homeEscapeTarget(seg)) {
      return {
        allowed: false,
        reason: '检测到删除主目录 (~/$HOME) 操作',
        riskLevel: 'high' as SecurityJudgment['riskLevel'],
        riskType: 'script_execution',
        confidence: 90,
        source: 'heuristic',
        violatedLayers: ['L1.1'],
      };
    }
  }

  // ② 同段赋值后删除命令引用：TARGET=$HOME; rm -rf $TARGET（文章同款变量间接形态）
  const assigned: Record<string, string> = {};
  for (const m of actionDetail.matchAll(HOME_ASSIGN_RE)) assigned[m[1]] = m[2];
  for (const [varName, path] of Object.entries(assigned)) {
    if (!isHomeValue(path)) continue;
    const varRefRe = new RegExp(`(?:${escapeRegExp(varName)}|\\$\\{${escapeRegExp(varName)}\\})`);
    for (const seg of segs) {
      if (!isDeleteCommand(seg)) continue;
      if (varRefRe.test(seg)) {
        return {
          allowed: false,
          reason: `检测到通过变量 ${varName}（=${path}，主目录）执行删除`,
          riskLevel: 'high' as SecurityJudgment['riskLevel'],
          riskType: 'script_execution',
          confidence: 90,
          source: 'heuristic',
          violatedLayers: ['L1.1'],
        };
      }
    }
  }
  return null;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * NEW-FP-1: 判断命令是否含「删除该目录/其下内容」意图（dir_del_only 目录级条目专用）。
 * 目录级 deny_write 条目若按普通「写/删都拦」语义，会把 mkdir -p ~/.ssh、chmod 700 ~/.ssh、
 * echo x >> ~/.ssh/known_hosts 等 SSH/AWS 目录初始化/权限收紧操作误拦（chmod/echo 均判写）。
 * 收紧为段级删除意图：仅当『含该目录路径的命令段』首词是删除类命令（rm/unlink/rmdir/删除/移除）
 * 才视为删目录。mkdir/chmod/echo/ssh-keygen 等一律放行。目录内文件细粒度读写由具体路径条目
 * （.ssh/id_rsa、.aws/credentials deny_both）兜底。对齐 Python _is_directory_delete_action。
 */
function isDeleteActionForDir(command: string, dirPath: string): boolean {
  const low = command.toLowerCase();
  const dpath = dirPath.toLowerCase();
  // rm -rf /路径/.ssh / rm -rf "~/.ssh" / rm -rf ~/.ssh/* —— 删除命令 + 目录路径
  if (new RegExp(`\\b(?:rm|unlink|rmdir)\\b[^&|;]*?${escapeRegExp(dpath)}`, 'i').test(low)) {
    return true;
  }
  // 中文删除：删除 ~/.ssh / 清空 ~/.aws 目录等（删除/移除 + 目录路径）
  if (new RegExp(`(?:删除|移除)[^\\n;|&]*?${escapeRegExp(dpath)}`).test(low)) {
    return true;
  }
  // 段首删除命令（rm -rf ~/.ssh 里 rm 在段首）兜底：整条含删除命令且含目录路径
  for (const seg of low.split(/&&|\|\||;|\n/)) {
    const fw = (seg.trim().split(/\s+/)[0] || '').toLowerCase();
    if ((fw === 'rm' || fw === 'unlink' || fw === 'rmdir') && low.includes(dpath)) {
      return true;
    }
  }
  return false;
}

/** 归档/复制读源整包读取目录（dir_del_only 条目）——绕过文件级凭据条目一次性读走私钥。镜像 Python _is_archive_read_of_dir。 */
function isArchiveReadOfDir(command: string, dirPath: string): boolean {
  const low = command.toLowerCase();
  const dpath = dirPath.toLowerCase();
  for (const seg of low.split(/&&|\|\||;|\n/)) {
    const s = seg.trim();
    if (!s || !s.includes(dpath)) continue;
    const parts = s.split(/\s+/);
    const fw = parts[0] || '';
    if (fw === 'zip') return true;
    if (fw === 'tar') {
      if (/(?:^|\s)-[a-zA-Z]*x|--extract/.test(s)) continue;
      return true;
    }
    if (fw === 'cp' || fw === 'rsync') {
      const segPaths = s.match(/[/~][^\s;|&><'"]*/g) || [];
      if (segPaths.length && segPaths[0].includes(dpath)) return true;
    }
  }
  return false;
}

/** ssh-keygen 生成模式：-t <type> 时 -f 是写目标（生成新私钥），非读源。镜像 Python _is_ssh_keygen_generate。 */
function isSshKeygenGenerate(command: string): boolean {
  const low = command.toLowerCase();
  if (!low.includes('ssh-keygen')) return false;
  if (!/(?:^|\s)-t\s+\S+/.test(low)) return false;
  // 读私钥内容 / 改密 / 显示指纹 的 flag 都是读源
  if (/(?:^|\s)-\S*[ylpB]\S*/.test(low)) return false;
  return true;
}

/** 危险操作模式检测（从 L2 搬入）：通配符+删除、重定向覆盖 /etc /boot /proc */
export function checkDangerousPatterns(actionType: string, actionDetail: string): SecurityJudgment | null {
  if (actionType === 'file_write' || actionType === 'file_edit') return null;

  // Wildcard + delete — 排除 /tmp 等临时目录的清理操作
  // 用边界正则匹配目录名本身（/tmp 和 /tmp/ 都算），避免 `find /tmp -delete`
  // 因 "/tmp/" 子串不匹配（/tmp 后是空格）而 isTempPath=false 误报（Bug6）。
  // NEW-FP（鸿蒙写周报误报）：先剥离 heredoc 文档字面量内容——文档正文里的
  // `*`/`?`/`rm`/`删除` 是文本不是真实删除命令，不剥离会误判为批量删除。
  const scan = stripHeredocContent(actionDetail);
  const TEMP_DIRS = ['/tmp', '/var/tmp', '/run', '/dev/shm'];
  // NEW-FP-2 审核：相对 var/tmp（无前导 /）& 深层绝对路径（/opt/app/var/tmp）——
  // 裸露的 (?:^|[\s/])var/tmp(?:[\s/]|$) 会把「以 var/tmp 结尾的深层子路径」误当临时目录
  // 豁免（rm -rf /opt/app/var/tmp/* 是删业务数据却被放行 = 漏拦）。相对 var/tmp 只认
  // 「命令中独立路径 token 首段为 var/tmp」的精确形态（rm -rf var/tmp/*、cd var/tmp && rm *）；
  // 深层绝对路径必须是 /var/tmp（tmp 目录在根下才是标准临时位置）。
  const isTempPath = TEMP_DIRS.some(td =>
    new RegExp(`(?:^|[\\s/])${td.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:[\\s/]|$)`).test(actionDetail)
  ) || /(?:^|[\s;]|&&\s*|\|\|\s*)var\/tmp(?:[/\s;]|$)/.test(actionDetail);
  // 通配符必须紧邻删除命令（真实命令 token），而非任意位置子串。
  // 收紧：`*`/`?` 出现在删除命令（rm/del/delete/remove/删除/移除）附近——
  // 匹配「删除命令 + 通配符路径」组合，如 `rm -rf /tmp/*`、`rm *`、`find . -delete`。
  // 不再用 actionDetail.includes('*') && includes('rm') 的宽泛子串匹配，
  // 避免文档正文/heredoc/grep 模式里的字面量误报。
  const wildcardDeleteRe =
    /(?:\brm\b|\b(r?mdir|del|delete|remove|rmdir|unlink)\b|\b删除\b|\b移除\b)[\s\S]{0,40}?[*?]|[*?][\s\S]{0,40}?\b(?:rm|del|delete|remove|rmdir|unlink)\b|rm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+\S*[*?]/i;
  if (!isTempPath && wildcardDeleteRe.test(scan)) {
    return {
      allowed: false,
      reason: '检测到通配符结合删除操作，可能造成批量误删',
      riskLevel: 'high',
      riskType: 'script_execution',
      confidence: 90,
      source: 'heuristic',
      violatedLayers: ['L1.1'],
    };
  }
  // find -exec <写命令> / find | xargs <写命令> — find 在 READ_ONLY_COMMANDS 导致整段
  // 被当只读，-exec 或 | xargs 后的 chmod/cp/mv/rm/sed -i 等写命令漏检（NEW-FN-C: -exec；
  // NEW-FN-E: | xargs 等价变体未覆盖）。find 遍历出的文件被批量执行写操作，静态无法确定
  // 具体目标文件，但「find + 写命令」组合本身就是批量写意图，此处识别 -exec/-execdir/-ok
  // 后紧跟写命令、或 | xargs 后紧跟写命令即拦截。只匹配写命令首词，避免 -exec grep /
  // | xargs ls 等只读误报。xargs 后的 sed -i 单独匹配（sed -i 是 sed + -i 参数）。
  const findWriteMatch = actionDetail.match(
    /\bfind\b.*?(?:(?:^|\s)-exec(?:dir)?\s+(chmod|chown|cp|mv|rm|dd|tee|truncate|mkfs|shred|rmdir|unlink)\b|(?:^|\s)\|\s*xargs\s+(?:sed\s+-[a-zA-Z]*i|chmod|chown|cp|mv|rm|dd|tee|truncate|mkfs|shred|rmdir|unlink)\b)/i
  );
  if (findWriteMatch) {
    const cmdHit = findWriteMatch[1] || 'xargs';
    return {
      allowed: false,
      reason: `检测到 find 批量执行写操作 (${cmdHit})，可能批量修改/删除文件`,
      riskLevel: 'high',
      riskType: 'script_execution',
      confidence: 90,
      source: 'heuristic',
      violatedLayers: ['L1.1'],
    };
  }
  // Redirect overwrite to system directories（对齐 Python _check_dangerous_patterns
  // `>\s*['\"]?/etc/ > /boot/ > /proc/` critical，不排除敏感路径）。支持可选引号路径：
  // echo > '/etc/x'、cat > /etc/ssh/sshd_config 均命中 critical 短路（Python ground truth）。
  if (
    />\s*['"]?\/etc\//.test(actionDetail) ||
    />\s*['"]?\/boot\//.test(actionDetail) ||
    />\s*['"]?\/proc\//.test(actionDetail)
  ) {
    return {
      allowed: false,
      reason: '检测到重定向覆盖写入关键系统目录',
      riskLevel: 'critical',
      riskType: 'file_access',
      confidence: 95,
      source: 'heuristic',
      violatedLayers: ['L1.1'],
    };
  }
  // A16: 重定向覆盖设备文件（对齐 Python linux.py:180 `>\s*/dev/(sd|hd|nvme|vd|loop|mem|kmsg|port|zero|random|urandom|full|core)`）。
  // high/file_access。须先于 checkSensitivePath 的 /dev/mem critical 命中，避免写 /dev/mem 被标 critical（Python 是 high）。
  if (/>\s*\/dev\/(sd|hd|nvme|vd|loop|mem|kmsg|port|zero|random|urandom|full|core)/i.test(actionDetail)) {
    return {
      allowed: false,
      reason: '检测到重定向写入设备文件',
      riskLevel: 'high',
      riskType: 'file_access',
      confidence: 90,
      source: 'heuristic',
      violatedLayers: ['L1.1'],
    };
  }
  return null;
}


function extractRemoteHost(command: string): string | null {
  // NEW-FN-G: 旧正则 (?:ssh|scp|rsync)\s+(?:-[\w]+\s+)*(\S+@\S+|\b(?!-)[\w.-]+\b)
  // 的 (?:-[\w]+\s+)* 只匹配单选项不匹配带参数值选项（-p 2222、-L 8080:...、
  // -D 1080、-e ssh），导致 host 提取取到端口号或选项参数。token 化三策略更可靠。
  // NEW-FP-E: bash -c/sh -c "ssh user@host" 的 user@host 被引号包裹成 "user@host"
  // 正则不匹配（" 非 \w）→ 漏报。bash -c 内联命令是真实调用，应检测。
  // 剥 token 首尾引号后再匹配（python -c 已在 checkLateralMovement 开头 INLINE_SCRIPT_RE 跳过）。
  const tokens = command.split(/\s+/).map(t => t.replace(/^["']|["']$/g, ''));
  // 策略1：优先找 user@host 或 user@host: 模式（最可靠，带值选项参数值如
  // -L 8080:localhost:80 的 localhost 会被 isLocalHost 排除，不会误匹配）。
  for (const tok of tokens) {
    const am = tok.match(/^([\w.-]+)@([\w.-]+)(:.*)?$/);
    if (am && am[2] && !isLocalHost(am[2])) {
      return `${am[1]}@${am[2]}`;
    }
  }
  // 策略2：host: 模式（rsync/scp 远程路径 host:/path，无 user@）
  for (const tok of tokens) {
    const hm = tok.match(/^([\w.-]+):\/(.*)?$/);
    if (hm && hm[1] && !isLocalHost(hm[1])) {
      return hm[1];
    }
  }
  // 策略3：回退"第一个非选项 token"（ssh host 无 @ 无 :，如 ssh 10.0.0.5）。
  // 跳过 - 开头选项及其参数值（-p 2222 / -e ssh / -L 8080:...）。
  const skipValueOpts = new Set([
    '-p', '-l', '-i', '-o', '-b', '-c', '-m', '-F',
    '-e', '-S', '-W', '-J', '-I', '-T', '-B',
    '-L', '-R', '-D', '-E', '-M', '-O', '-P', '-q',
  ]);
  let foundCmd = false;
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t === 'ssh' || t === 'scp' || t === 'rsync') {
      foundCmd = true;
      continue;
    }
    if (!foundCmd) continue;
    if (t.startsWith('-')) {
      // 带值选项：跳过下一个 token（-p 2222 / -e ssh / -L 8080:...）
      if (skipValueOpts.has(t) && i + 1 < tokens.length) {
        i++;
      }
      continue;
    }
    // 非选项 token：候选主机。排除纯路径（/ 开头本地路径非主机名）。
    if (t.startsWith('/')) continue;
    return t;
  }
  return null;
}

function isLocalHost(host: string): boolean {
  const localNames = ['localhost', '127.0.0.1', '::1', process.env.HOSTNAME || '', '0.0.0.0'];
  return localNames.includes(host.replace(/.*@/, ''));
}

/** 横向移动检测（从 L2 括入）：ssh/scp/rsync 到非本机主机 */
export function checkLateralMovement(actionDetail: string): SecurityJudgment | null {
  // NEW-FP-D: 内联脚本（python -c / perl -e 等）里的 ssh/scp/rsync 是字面量非真调用，
  // 跳过交 inline-analyzer 专门管，与 intent/privilege 一致
  if (/\b(?:python|python3|perl|ruby|node|php|lua)\b\s+.*-[cer][a-zA-Z]*\s/.test(actionDetail)) return null;

  // NEW-FP-D: echo/printf �首词的参数是字面量非真调用（echo ssh user@host 是打印字面量）
  // 按命令段判定：首词 echo/printf 跳过，与 isWriteOperation 的 wget/curl 字面量判定一致
  const segments = actionDetail.split(/&&|\|\||;|\n/).map(s => s.trim()).filter(Boolean);
  let hasRealCall = false;
  for (const seg of segments) {
    const parts = seg.split(/\s+/);
    const fw = (parts[0] || '').toLowerCase();
    if (fw === 'echo' || fw === 'printf') continue;
    if (/(?:ssh|scp|rsync)\s+/.test(seg)) { hasRealCall = true; break; }
  }
  if (!hasRealCall) return null;

  if (/(?:ssh|scp|rsync)\s+/.test(actionDetail)) {
    const targetHost = extractRemoteHost(actionDetail);
    if (targetHost && !isLocalHost(targetHost)) {
      return {
        allowed: false,
        reason: `尝试横向移动到远程主机: ${targetHost}`,
        riskLevel: 'medium',
        riskType: 'lateral_movement',
        confidence: 80,
        source: 'heuristic',
        violatedLayers: ['L1.1'],
      };
    }
  }
  return null;
}
