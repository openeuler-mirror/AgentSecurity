import { SecurityJudgment } from './types';
import { runHeuristicCheck, isInlineScriptCommand, DANGEROUS_PATTERNS } from './heuristic';
import { runLogicCheck, isWriteOperation } from './logic-rules';
import { analyzeInlineScript, isLiteralTextCommand } from './inline-analyzer';
import { runLLMAnalysis } from './llm-analyzer';
import { analyzeScriptContent as analyzeScriptChain, formatScriptChainForPrompt } from './script-content-analyzer';
import { isHeuristicEnabled, isLogicRulesEnabled, isLLMAvailable, isBrainEnabled, isFormalObserveMode } from '../config';
import { isLayerEnabled } from '../infra/runtime-config';
import { getAgentExtensions, mergeAgentExtensions } from '../agents';
import { getScenarioExtensionsMulti } from '../scenarios';
import { BrainRuleStore, PatternExtractor, checkBrainRules } from '../brain';
import { createBrainReviewer } from '../brain/reviewer';
import { FormalEngine } from './formal-engine';

export interface AnalysisInput {
  sessionId: string;
  promptSession: string;
  actionHistory: { actionType: string; actionDetail: string }[];
  /** 完整的交错历史 prompt（可选），每轮 {text, actions} 或纯文本 string（AgentGate v3 旧格式），按时间序。
   *  供 L2 意图一致性与 L3 语义分析使用；空则回退单条 promptSession。 */
  promptHistory?: ({ text: string; actions: { actionType: string; actionDetail: string }[] } | string)[];
  /** 多 session 历史动作（可选），每项 {sessionId, actionHistory}。供 L2.2 形式化引擎
   *  做跨会话组合链/敏感数据传播验证；缺省时仅用当前 session 构建行为图（向后兼容）。
   *  由调用方（含未来 agentgate 非侵入式采集）提供。 */
  sessionHistory?: { sessionId?: string; actionHistory: { actionType: string; actionDetail: string }[] }[];
  aNext: { actionType: string; actionDetail: string };
  reason: string;
  osType: string;
  cwd: string;
  /** 调用方 agent 标识（如 'xiaoo' / 'opencode' / 'opendesk'）。空 = 通用模式。 */
  agentId: string;
  /** 调用方场景标识（如 'bank'），用于加载场景定制规则（客户沙箱的目录访问边界/禁 ssh 等）。
   *  空时兜底环境变量 AGENT_MOSS_SCENARIO（部署级，客户沙箱设一次，所有请求生效）。 */
  scenarioId?: string;
  /** 可选的 per-request LLM 配置覆盖（由 OpenDesk 按当前会话模型传入） */
  llmConfig?: { baseUrl: string; apiKey: string; model: string; provider?: string };
  /** 可选的 per-request LLM prompt 日志路径（来自调用方 env，per-request 注入。
   * 跟 llmConfig 同理：调用方子进程有 AGENT_MOSS_LOG_PATH env 但服务进程不一定有，
   * 通过 metadata 注入让服务端写 [LLM_PROMPT] 日志，对齐 py _log_prompt） */
  llmLogPath?: string;
}

// ========== 快速放行白名单 ==========

/** 完全安全工具：跳过 Layer 2 + Layer 3 */
const FULLY_SAFE_TOOLS = new Set([
  'ask_user_question', 'glob', 'list_dir', 'ls', 'count_text_length',
  'filemgr-globfiles',
]);

/** 内置安全 Skill 白名单（通用 baseline，agent_ext.builtin_safe_skills 会追加）。
 * 测试可 import 此常量直接断言"无 agentId 时白名单不含某 skill"，避免走 L3
 * LLM 调用导致测试脆弱（依赖 LLM 401 fail_open 兜底）。 */
export const TRUSTED_SKILLS_BASE = new Set<string>([]);

/** 安全但可能访问敏感路径：跳过 Layer 3，保留 Layer 2 */
const READONLY_SENSITIVE_TOOLS = new Set([
  'read', 'file_read', 'read_file', 'head', 'tail', 'grep',
  'filemgr-readfile', 'filemgr-grepfiles',
]);

/** 完全安全 bash 子命令正则 */
const FULLY_SAFE_BASH_PATTERNS: RegExp[] = [
  /^ls(?:\s|$)/i, /^dir(?:\s|$)/i,
  /^pwd(?:\s|$)/i, /^which\s+/i, /^whereis\s+/i, /^realpath\s+/i,
  /^basename\s+/i, /^dirname\s+/i,
  /^file\s+/i, /^stat\s+/i, /^du(?:\s|$)/i,
  /^echo\s+/i, /^printf\s+/i,
  /^type\s+/i, /^command\s+/i,
  // 系统信息查询（只读，不涉及文件/网络/权限）
  /^whoami(?:\s|$)/i, /^id(?:\s|$)/i,
  /^hostname(?:\s|$)/i, /^uname(?:\s|$)/i,
  /^date(?:\s|$)/i, /^env(?:\s|$)/i,
  /^printenv(?:\s|$)/i, /^tty(?:\s|$)/i,
  /^arch(?:\s|$)/i, /^uptime(?:\s|$)/i,
  /^groups(?:\s|$)/i, /^logname(?:\s|$)/i,
];

/** 安全但可能访问敏感路径的 bash 子命令正则 */
const READONLY_SENSITIVE_BASH_PATTERNS: RegExp[] = [
  /^cat\s+/i, /^head(?:\s|$)/i, /^tail(?:\s|$)/i,
  /^less(?:\s|$)/i, /^more(?:\s|$)/i, /^wc(?:\s|$)/i,
  /^grep(?:\s|$)/i, /^find\s+/i, /^ag(?:\s|$)/i, /^rg(?:\s|$)/i,
  /^awk\s+/i, /^sed\s+/i, /^cut\s+/i, /^sort(?:\s|$)/i, /^uniq(?:\s|$)/i,
];

/** 提取管道和链式命令的第一段 */
function extractFirstCommand(command: string): string {
  let main = command.split('|')[0].trim();
  for (const sep of ['&&', '||']) {
    const idx = main.indexOf(sep);
    if (idx !== -1) {
      main = main.substring(0, idx).trim();
      break;
    }
  }
  return main;
}

/** 从 OpenDesk 格式中提取实际命令 */
function extractRawCommand(detail: string): string {
  const m = detail.match(/command=([^,]+)/);
  return m ? m[1].trim() : detail;
}

function matchesAny(cmd: string, patterns: RegExp[]): boolean {
  return patterns.some(p => p.test(cmd));
}

// ========== Brain（默认关闭，AGENT_MOSS_BRAIN_ENABLED=1 才启用） ==========
let _brainStore: BrainRuleStore | null = null;
let _brainExtractor: PatternExtractor | null = null;
let _brainInitialized = false;

function getBrainStore(): BrainRuleStore | null {
  if (!isBrainEnabled()) return null;
  if (!_brainInitialized) {
    _brainStore = new BrainRuleStore();
    _brainExtractor = new PatternExtractor(_brainStore, { review: createBrainReviewer() });
    _brainInitialized = true;
  }
  return _brainStore;
}

/** 供测试隔离：重置 brain 单例 */
export function _resetBrainForTest(): void {
  _brainStore = null;
  _brainExtractor = null;
  _brainInitialized = false;
}

// ========== 三层防御协调器 ==========

/**
 * Three-layer defense coordinator.
 * Layer 1 → fast-pass check → Layer 2 → Layer 3.
 * Fast-pass: whitelisted safe tools/commands skip L2+L3 or L3 only.
 */

// 形式化引擎实例（L2.2）：行为图 + 性质验证（跨会话组合链/敏感数据传播）。
// 单 session 向后兼容（仅用 actionHistory），多 session 由 input.sessionHistory 提供。
const formalEngine = new FormalEngine();

export async function runAnalysis(input: AnalysisInput): Promise<SecurityJudgment> {
  // observe 模式累积层标记：formal 引擎（L2.2）命中但未拦截时记录，供最终 Allow 结果透出。
  const observedFormalLayers: string[] = [];

  // Layer 1: Feature-matching static detection (fast)
  const heuristicResult = isHeuristicEnabled() ? runHeuristicCheck(input) : null;

  // 内联脚本/文本输出命令 file_access 假阳性防护：不立即拦截，交 inline_analyzer 静态判定
  // 因为字符串字面量中的敏感路径（如 '/etc/shadow'）不应被正则误拦截
  const isInlineScriptCmd = isInlineScriptCommand(input.aNext.actionDetail.toLowerCase());
  const isLiteralTextCmd = isLiteralTextCommand(input.aNext.actionDetail.toLowerCase());
  if (heuristicResult && !heuristicResult.allowed) {
    const skipInlineFileAccess = (isInlineScriptCmd || isLiteralTextCmd) && heuristicResult.riskType === 'file_access';
    if (!skipInlineFileAccess) {
      // 对齐 py coordinator.py:172-176 should_deny_l1：
      //   high/critical 直接 Deny；
      //   medium + file_access（敏感路径写）确定性拦截；
      //   其他 medium（如 git push --force / rm -f 单文件 / prompt 注入 repeat-instructions）
      //   不直接 Deny，fall-through 到 L2/L3。
      const shouldDenyL1 =
        heuristicResult.riskLevel === 'high' ||
        heuristicResult.riskLevel === 'critical' ||
        (heuristicResult.riskLevel === 'medium' && heuristicResult.riskType === 'file_access');
      if (shouldDenyL1) {
        return heuristicResult;
      }
    }
  }

  // ===== L1.2: Script content pre-scan (recursive chain + L1 reuse) =====
  // For bash actions invoking a script, recursively track the call chain,
  // preprocess, and scan each node with runHeuristicCheck (L1). high/critical
  // deny directly (layer L1.2, script content L1 scan). Catches "rm -rf /" inside
  // a script whose entry command is just "bash deploy.sh". Reduces L3 token use.
  let scriptChain: ReturnType<typeof analyzeScriptChain> | null = null;
  if (input.aNext.actionType.toLowerCase() === 'bash') {
    scriptChain = analyzeScriptChain(input);
    if (scriptChain.nodes.length > 0) {
      for (const node of scriptChain.nodes) {
        if (node.l1Hit && (node.l1RiskLevel === 'high' || node.l1RiskLevel === 'critical')) {
          return {
            allowed: false,
            reason: `脚本内容包含危险操作: ${node.l1Reason} (文件: ${node.scriptPath}, 深度: ${node.depth})`,
            riskLevel: node.l1RiskLevel as SecurityJudgment['riskLevel'],
            riskType: node.l1RiskType,
            confidence: 90,
            source: 'heuristic_script_scan',
            violatedLayers: ['L1.2'],
          };
        }
      }
    }
  }

  // ===== Brain L1 rule check (only when brain enabled) =====
  const brainStore = getBrainStore();
  if (brainStore) {
    const brainL1 = checkBrainRules(brainStore, {
      layer: 1,
      actionType: input.aNext.actionType,
      actionDetail: input.aNext.actionDetail,
    });
    if (brainL1) {
      return {
        allowed: false,
        reason: `[Brain L1] ${brainL1.explanation}`,
        riskLevel: 'high',
        riskType: 'brain_rule',
        confidence: Math.round(brainL1.confidence * 100),
        source: 'brain_rule',
        violatedLayers: ['brain_L1'],
      };
    }
  }

  // ===== Fast-pass check =====
  const actionType = input.aNext.actionType.toLowerCase();
  const rawDetail = extractRawCommand(input.aNext.actionDetail);
  const lowerDetail = rawDetail.toLowerCase();
  // agent 专属扩展（agent_moss/agents/<id>/rules.json）+ 场景定制规则
  // （agent_moss/scenarios/<id>/rules.json），合并后供 fast-pass 各白名单复用。
  // 场景规则：调用方显式 scenarioId > 环境变量 AGENT_MOSS_SCENARIO（部署级兜底）。
  // Agent/场景专属规则总开关（console 层级全局开关 agent_rules_enabled / scenario_rules_enabled）
  const agentExt = mergeAgentExtensions(
    isLayerEnabled('agent_rules_enabled') ? getAgentExtensions(input.agentId) : null,
    isLayerEnabled('scenario_rules_enabled')
      ? getScenarioExtensionsMulti(input.scenarioId || process.env.AGENT_MOSS_SCENARIO || '')
      : null,
  );

  // Fully safe tools: skip L2 + L3
  if (FULLY_SAFE_TOOLS.has(actionType)) {
    return {
      allowed: true,
      reason: `完全安全工具，跳过深度分析: ${actionType}`,
      riskLevel: (heuristicResult?.riskLevel || 'low') as SecurityJudgment['riskLevel'],
      riskType: '',
      confidence: 95,
      source: 'whitelist_bypass',
      violatedLayers: [],
    };
  }

  // agent 专属完全安全操作白名单（精确名或前缀，来自 rules.json builtin_safe_action_types）。
  // 前缀以 '-' 结尾 → startswith 匹配（如 "memory-"）；否则精确名匹配（如 "mailbox-getEmailList"）。
  // 命中即跳过 L2+L3，与 builtin_safe_skills 同范式。仅对该 agent_id 生效，不污染其他 agent。
  // OpenDesk 的 memory-*/todomgr-*/planning-* 是纯数据/只读操作，走 L3 LLM 耗时 1~137s 无意义。
  if (agentExt?.builtin_safe_action_types && agentExt.builtin_safe_action_types.length > 0) {
    // actionType 已小写化（:143）；rules.json 精确名可能是驼峰（如 mailbox-getEmailList），
    // 故比较时对白名单项也 lower。前缀项（尾随 '-'）同样 lower 后 startswith。
    const hit = agentExt.builtin_safe_action_types.some(t => {
      const tl = t.toLowerCase();
      return tl.endsWith('-') ? actionType.startsWith(tl) : actionType === tl;
    });
    if (hit) {
      return {
        allowed: true,
        reason: `agent 内部安全操作，跳过深度分析: ${actionType}`,
        riskLevel: (heuristicResult?.riskLevel || 'low') as SecurityJudgment['riskLevel'],
        riskType: '',
        confidence: 95,
        source: 'whitelist_bypass',
        violatedLayers: [],
      };
    }
  }

  // 内置安全 Skill 直接放行（通用 baseline + agent_ext.builtin_safe_skills）
  const trustedSkills = new Set<string>(TRUSTED_SKILLS_BASE);
  if (agentExt?.builtin_safe_skills) {
    for (const s of agentExt.builtin_safe_skills) trustedSkills.add(s);
  }
  if (actionType === 'skill' && trustedSkills.has(lowerDetail)) {
    return {
      allowed: true,
      reason: `内置安全 Skill，跳过深度分析: ${lowerDetail}`,
      riskLevel: (heuristicResult?.riskLevel || 'low') as SecurityJudgment['riskLevel'],
      riskType: '',
      confidence: 95,
      source: 'whitelist_bypass',
      violatedLayers: [],
    };
  }

  // Readonly sensitive tools: skip L3, continue to L2
  let skipLLM = READONLY_SENSITIVE_TOOLS.has(actionType);

  // Bash sub-command checks
  if (actionType === 'bash' || actionType === 'executebash' || actionType === 'terminal-executebash') {
    const firstCmd = extractFirstCommand(lowerDetail);
    if (matchesAny(firstCmd, FULLY_SAFE_BASH_PATTERNS)) {
      // 安全兜底 1：检查完整命令是否命中高危模式（如 echo ... | passwd）
      const fullCmdHit = DANGEROUS_PATTERNS.some(p =>
        p.severity === 'critical' || p.severity === 'high'
      ) && DANGEROUS_PATTERNS.some(p =>
        (p.severity === 'critical' || p.severity === 'high') && p.pattern.test(lowerDetail)
      );
      // 安全兜底 2：检查是否含真实重定向写（echo x > file / printf >> file）。
      // is_fully_safe_bash_command 只看首命令名（echo），会忽略 >/>> 重定向，
      // 导致 `echo x > /tmp/existing.txt` 覆写已存在文件被白名单放行跳过 L2（Bug3）。
      // 复用 isWriteOperation 的重定向判定（已剥 devnull + 比较运算符 + 只读首词保护）。
      const hasRedirectWrite = isWriteOperation(firstCmd, lowerDetail);
      if (!fullCmdHit && !hasRedirectWrite) {
        return {
          allowed: true,
          reason: `安全的只读 bash 命令: ${firstCmd}`,
          riskLevel: 'low',
          riskType: '',
          confidence: 95,
          source: 'whitelist_bypass',
          violatedLayers: [],
        };
      }
    }
    if (matchesAny(firstCmd, READONLY_SENSITIVE_BASH_PATTERNS)) {
      skipLLM = true;
    }
  }

  // Layer 2: Logic rule detection (fast)
  const logicResult = isLogicRulesEnabled() ? runLogicCheck(input) : null;
  // file_access 命中合并：敏感路径/危险模式现已在 L1（heuristicResult），
  // 间接文件访问仍在 L2（logicResult）。两者任一命中 file_access 都需进入
  // inline/credential 包装判定。优先采用 logicResult，退而取 heuristicResult。
  const l1FileAccessHit = !!(heuristicResult && !heuristicResult.allowed && heuristicResult.riskType === 'file_access');
  const effectiveResult = (logicResult && !logicResult.allowed) ? logicResult
    : (l1FileAccessHit ? heuristicResult : null);
  if (effectiveResult) {
    // 凭据文件：无论读写、无论是否 inline，都直接拒绝。
    // 来源：L1 sensitive path（isCredential）或 L2 indirect_file_access
    const isCredentialPath = !!effectiveResult.isCredential;
    // 内联脚本/文本输出命令：走静态语义判定，区分"文本字面量"vs"真实读写"。
    // 即使是凭据路径（如 deny_both 的 /etc/shadow），只要它是字符串字面量
    // （python -c "print('/etc/shadow')"），inline_analyzer 判 Allow 时应放行——
    // 因为并未真实读取该文件。actionable=false（提取不到代码）时才回退到
    // 凭据/敏感路径的硬拒绝。
    const skipInlineFileAccess = (isInlineScriptCmd || isLiteralTextCmd) && effectiveResult.riskType === 'file_access';
    if (skipInlineFileAccess) {
      const inlineJudgment = analyzeInlineScript(input.aNext.actionDetail);
      if (inlineJudgment.actionable) {
        if (!inlineJudgment.allowed) {
          return {
            allowed: false,
            reason: inlineJudgment.reason,
            riskLevel: inlineJudgment.riskLevel as SecurityJudgment['riskLevel'],
            riskType: inlineJudgment.riskType,
            confidence: 90,
            source: 'logic_rule',
            violatedLayers: ['L2.1'],
          };
        }
        // 字面量 → Allow，不再走 Layer 3
        return {
          allowed: true,
          reason: inlineJudgment.reason,
          riskLevel: inlineJudgment.riskLevel as SecurityJudgment['riskLevel'],
          riskType: inlineJudgment.riskType,
          confidence: 90,
          source: 'logic_rule',
          violatedLayers: [],
        };
      }
      // actionable=false（提取不到代码）→ 回退原逻辑：high/critical 直接 Deny
    }
    if ((effectiveResult.riskLevel === 'high' || effectiveResult.riskLevel === 'critical') && (!skipInlineFileAccess || isCredentialPath)) {
      return effectiveResult;
    }
    // medium/low 风险：不直接拦截，走层3 LLM 语义判断
  }

  // ===== L2.2: Formal verification (behavior graph + property verification,
  // incl. cross-session combo chains). Mirrors Python coordinator L2.2.
  // Single session builds from actionHistory (backward compatible); multi-session
  // comes from input.sessionHistory (future agentgate non-intrusive collection).
  if (isLogicRulesEnabled()) {
    const formalSessions: { sessionId?: string; actionHistory: { actionType: string; actionDetail: string }[] }[] = [];
    if (input.sessionHistory) {
      for (const s of input.sessionHistory) {
        formalSessions.push({ sessionId: s.sessionId || 's', actionHistory: s.actionHistory || [] });
      }
    }
    formalSessions.push({ sessionId: 'current', actionHistory: input.actionHistory });
    const formalResult = formalEngine.verify(formalSessions, input.aNext);
    if (!formalResult.verified) {
      const v = formalResult.violations[0];
      if (isFormalObserveMode()) {
        // observe 模式：只记录不拦截（灰度观察 FP 率用，镜像 Python coordinator）。
        // 违规仍标记进 observedLayers 供调用方观测，但不短路 Deny，继续走后续层。
        console.warn(
          `[AgentMoss] 形式化验证 observe（只记录不拦截）: property=${v?.propertyId ?? '?'} ` +
            `risk=${v?.riskLevel ?? '?'} path_len=${v?.path?.length ?? 0} reason=${(v?.reason ?? '?').slice(0, 200)}`,
        );
        observedFormalLayers.push('L2.2');
      } else {
        return {
          allowed: false,
          reason: v ? v.reason : '形式化验证未通过（行为性质违反）',
          riskLevel: (v ? v.riskLevel : 'high') as SecurityJudgment['riskLevel'],
          riskType: 'formal_verification',
          confidence: 90,
          source: 'formal_engine',
          violatedLayers: ['L2.2'],
        };
      }
    }
  }

  // ===== L2.3: Script content L2 scan (per-node sensitive path / dangerous
  // pattern / intent reuse on preprocessed content). high/critical deny
  // directly (layer L2.3, script content L2 scan). =====
  if (scriptChain && scriptChain.nodes.length > 0 && isLogicRulesEnabled()) {
    for (const node of scriptChain.nodes) {
      if (node.error || !node.preprocessedContent) continue;
      if (node.l1RiskLevel === 'critical') break;
      if (node.l2Hit && (node.l2RiskLevel === 'high' || node.l2RiskLevel === 'critical')) {
        return {
          allowed: false,
          reason: node.l2Reason,
          riskLevel: node.l2RiskLevel as SecurityJudgment['riskLevel'],
          riskType: node.l2RiskType,
          confidence: 85,
          source: 'logic_rule_script_scan',
          violatedLayers: ['L2.3'],
        };
      }
    }
  }

  // ===== Brain L2 rule check (only when brain enabled) =====
  if (brainStore) {
    const brainL2 = checkBrainRules(brainStore, {
      layer: 2,
      actionType: input.aNext.actionType,
      actionDetail: input.aNext.actionDetail,
      actionHistory: input.actionHistory,
    });
    if (brainL2) {
      return {
        allowed: false,
        reason: `[Brain L2] ${brainL2.explanation}`,
        riskLevel: 'high',
        riskType: 'brain_rule',
        confidence: Math.round(brainL2.confidence * 100),
        source: 'brain_rule',
        violatedLayers: ['brain_L2'],
      };
    }
  }

  // Layer 3: LLM analysis (skipped for readonly sensitive tools/commands)
  if (skipLLM || !isLLMAvailable()) {
    return {
      allowed: true,
      reason: '只读操作且无逻辑规则违规，跳过 LLM 分析',
      riskLevel: (logicResult?.riskLevel || 'low') as SecurityJudgment['riskLevel'],
      riskType: '',
      confidence: 85,
      source: 'heuristic_and_logic_only',
      violatedLayers: observedFormalLayers.length > 0 ? [...observedFormalLayers] : [],
    };
  }

  // Build skip_l3_hints: hard-constraint for user-disabled L2 rules with
  // skip_l3_on_disabled. runtime_config lands in Stage 2; until then
  // getDisabledL2RulesWithSkipL3 resolves to a no-op returning empty.
  let skipL3Hints = '无（当前无禁用规则命中）';
  try {
    const { getDisabledL2RulesWithSkipL3 } = await import('../infra/runtime-config');
    const disabledL2 = getDisabledL2RulesWithSkipL3();
    if (disabledL2 && Object.keys(disabledL2).length > 0) {
      const actionLower = input.aNext.actionDetail.toLowerCase();
      const matched: string[] = [];
      for (const items of Object.values(disabledL2)) {
        for (const item of items) {
          if (item.toLowerCase().includes(actionLower) || actionLower.includes(item.toLowerCase())) {
            matched.push(item);
          }
        }
      }
      if (matched.length > 0) {
        skipL3Hints =
          `⚠️ 重要约束：用户已主动禁用针对以下内容的安全拦截规则，这是用户的明确决策：\n` +
          `  ${matched.join(', ')}\n` +
          `对这些路径/关键词的相关操作，必须视为允许的，不允许仅因涉及这些内容就拒绝。` +
          `但你仍需检查命令的其他部分是否有独立于这些内容的安全风险（如网络外传、提权等）。`;
      }
    }
  } catch { /* runtime_config not yet present — skip_l3_hints stays default */ }

  let llmResult: SecurityJudgment;
  try {
    llmResult = await runLLMAnalysis(input, {
      heuristic: heuristicResult,
      logic: logicResult,
      skipL3Hints,
      scriptChain: scriptChain ?? undefined,
      llmLogPath: input.llmLogPath,
    });
  } catch (e) {
    // LLM 分析失败。前两层未拦截时按 fail_mode 决策：
    // - fail_open（默认）：Allow + 警告（可用性优先）
    // - fail_closed：Deny（安全优先）
    const { getLLMFailMode } = await import('../config');
    if (getLLMFailMode() === 'fail_open') {
      console.warn(`[AgentMoss] LLM 分析失败，fail_open 模式：允许执行（前两层未拦截）: ${(e as Error).message}`);
      return {
        allowed: true,
        reason: `LLM 分析失败（warn-allow，fail_open）: ${(e as Error).message}`,
        riskLevel: 'low',
        riskType: '',
        confidence: 50,
        source: 'llm_failure_fallback',
        violatedLayers: observedFormalLayers.length > 0 ? [...observedFormalLayers] : [],
      };
    }
    return {
      allowed: false,
      reason: `LLM 分析失败，因无法完成深度语义分析，按 fail-closed 原则拒绝: ${(e as Error).message}`,
      riskLevel: 'medium',
      riskType: '',
      confidence: 60,
      source: 'llm_failure_fallback',
      violatedLayers: ['L3.1'],
    };
  }

  // Layer 3 Deny + high confidence → feed Brain (only when enabled)
  if (!llmResult.allowed && llmResult.confidence && llmResult.confidence >= 90 && _brainExtractor) {
    try {
      await _brainExtractor.extract(
        { actionDetail: input.aNext.actionDetail, eventId: '' },
        {
          confidence: llmResult.confidence / 100,
          reason: llmResult.reason || '',
          riskType: llmResult.riskType || '',
          actionDetail: input.aNext.actionDetail,
        },
      );
    } catch {
      // Brain extraction failure must not affect main flow
    }
  }

  // observe 模式：formal 引擎命中但未拦截 → 把标记合并进最终结果（LLM Allow 路径），
  // 使调用方/actrail 可见"本会拦但未拦"（与 skipLLM / LLM 禁用路径一致）。
  if (observedFormalLayers.length > 0 && llmResult.allowed) {
    llmResult.violatedLayers = Array.from(new Set([...observedFormalLayers, ...(llmResult.violatedLayers || [])]));
  }

  return llmResult;
}
