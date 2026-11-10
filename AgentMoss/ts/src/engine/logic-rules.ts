import * as fs from 'fs';
import { SecurityJudgment } from './types';
import type { AnalysisInput } from './coordinator';
import { extractInlineCode } from './inline-analyzer.js';
import { getAgentExtensions } from '../agents';
import type { AgentExtensions } from '../agents';
import { loadL1, loadL2 } from '../infra/rules-loader';

/**
 * Layer 2: Logic rule detection.
 * Checks behavioral patterns: read-before-write, intent consistency,
 * sensitive path access, privilege escalation, and lateral movement.
 * Runs in < 1ms, no LLM cost.
 */

// Sensitive paths with per-path risk levels (unified Python + TS)

interface SensitivePathEntry { path: string; riskLevel: string; desc: string; credential?: boolean; dirDelOnly?: boolean; }

function _loadSensitivePathScope(scope: 'root' | 'home' | 'credential'): SensitivePathEntry[] {
  // 归一化自 agent_moss/rules/l1_rules.json（单一事实源，与 Python 共用）。
  // 每条含 scope(root/home/credential) + deny_mode；deny_mode=deny_both 视为 credential。
  // NEW-FP-1: dir_del_only 目录级条目（.ssh/.aws）——仅拦截「删除该目录/其下内容」，
  // mkdir/chmod 等初始化放行（与 Python SensitivePath.dir_del_only 对齐）。
  const sps = (loadL1().sensitive_path_access || []) as any[];
  return sps
    .filter((sp) => sp.scope === scope)
    .map((sp) => ({
      path: sp.path,
      riskLevel: sp.risk_level,
      desc: sp.desc,
      credential: sp.deny_mode === 'deny_both' ? true : undefined,
      dirDelOnly: sp.dir_del_only === true ? true : undefined,
    }));
}

export const ROOT_SENSITIVE_PATHS: SensitivePathEntry[] = _loadSensitivePathScope('root');

export const HOME_SENSITIVE_PATHS: SensitivePathEntry[] = _loadSensitivePathScope('home');

// Credential files: intercept on both read and write (reading credentials is equally dangerous)
// credential=true 使 seed 推导出 deny_mode=deny_both，与 Python 一致（对齐单一事实源）。
export const CREDENTIAL_PATHS: SensitivePathEntry[] = _loadSensitivePathScope('credential').map(({ path, riskLevel, desc, dirDelOnly }) => ({ path, riskLevel, desc, credential: true, dirDelOnly }));

// 只读工具精确名（豁免 read_before_write；与 coordinator READONLY_SENSITIVE_TOOLS/FULLY_SAFE_TOOLS 对齐）。
// 注意：不含 filemgr-writefile/filemgr-editfile/filemgr-searchreplace（这些是真写）。
const NON_WRITE_TOOLS = new Set([
  'ask_user_question', 'glob', 'grep', 'list_dir', 'count_text_length', 'search',
  // filemgr 只读三件套（globfiles 在 coordinator FULLY_SAFE_TOOLS 提前放行，此处兜底防御非 coordinator 入口）
  'filemgr-globfiles', 'filemgr-readfile', 'filemgr-grepfiles',
  // 通用只读工具名
  'read', 'read_file', 'file_read', 'head', 'tail', 'cat',
]);

// 非 bash/terminal 类工具前缀豁免 read_before_write。
// 仅保留通用基线前缀（与 EXCLUDED_PREFIXES / SENSITIVE_EXCLUDED_PREFIXES 一致）：
// memory-/skill-manager-/mailbox-/app- 是数据/编排/通信工具，read_before_write（写文件前先读）对其
// 无意义，且工具名含 remove/update（memory-removeMemory/memory-updateUserPortrait）会命中
// WRITE_KEYWORDS 子串 → 误判为写。L2 层独立豁免，不再仅依赖 coordinator opendesk 白名单。
// 不含 skill-（任意能力，coordinator 故意保留 L3）、todomgr-/planning-（opendesk 专属命名空间，
// 经 opendesk/rules.json builtin_safe_action_types 在 coordinator 层豁免 L2+L3，不到 L2）。
// mailbox-sendEmail/replyEmail 的外传风险由 L3 LLM 管，不归 L2 read_before_write。
const NON_WRITE_TOOL_PREFIXES = ['memory-', 'skill-manager-', 'mailbox-', 'app-'];

// Read-only commands that use > for output redirection (not write intent)
const READ_ONLY_REDIR_CMDS = new Set(['cat', 'head', 'tail', 'less', 'more', 'grep', 'find', 'awk', 'sed', 'sort', 'uniq', 'wc', 'cut', 'strings', 'od', 'xxd', 'hexdump']);

// Write keywords for read-before-write detection (also used by L1 SensitivePathChecker)
export const WRITE_KEYWORDS = ['write', '写入', 'save', '保存', 'modify', '修改', 'update', '更新', 'delete', '删除', 'remove', '移除', 'create', '创建', 'append', '追加', 'truncate', '截断', 'overwrite', '覆盖', 'replace', '替换', 'edit'];

// 写/删命令词边界正则（对齐 Python _WRITE_COMMAND_RES）。
// 子串匹配无法可靠识别 rm/cp/dd（"rm" 误命中 arm/form），故用词边界。
export const WRITE_COMMAND_RES: RegExp[] = [
  /\brm\b/, /\bunlink\b/, /\brmdir\b/, /\bshred\b/, /\bcp\b/, /\bmv\b/,
  /\binstall\b/, /\btee\b/, /\bdd\b/, /\bmkfs\b/,
  /\b(fdisk|parted|cfdisk|sfdisk)\b/, /\bchmod\b/, /\bchown\b/, /\btruncate\b/,
];

// 只读命令集合（重定向写判定用，对齐 Python READ_ONLY_COMMANDS）。
// 这些命令带 > 也是输出重定向非写文件意图（如 cat file > /dev/null）。
export const READ_ONLY_COMMANDS = new Set([
  'cat', 'head', 'tail', 'less', 'more', 'grep', 'find', 'awk', 'sed',
  'sort', 'uniq', 'wc', 'cut', 'strings', 'od', 'xxd', 'hexdump', 'tr',
  'file', 'stat', 'du', 'df', 'ls', 'dir', 'tree', 'nl', 'tac', 'rev',
  // NEW-FP-I: echo/printf 是文本输出命令，参数是字面量非写目标。加入此集让
  // read_before_write 的 echo 段走只读命令分支（只提取重定向目标，不提取参数路径），
  // 避免 echo "cat /etc/shadow" > /tmp/x.sh 的引号内 /etc/shadow 被当写目标误报。
  // echo "x" > /tmp/x.sh 的重定向目标 /tmp/x.sh 仍被提取（真实写不漏报）。
  'echo', 'printf',
  'lsblk', 'blockdev', 'smartctl', 'udevadm', 'dmidecode', 'lscpu', 'lspci',
  'lsusb', 'lsmem', 'lsns', 'lsof', 'hwinfo', 'inxi', 'fdisk', 'parted',
  'dmesg', 'journalctl', 'systemctl', 'hostnamectl', 'localectl', 'timedatectl',
  'ps', 'top', 'free', 'vmstat', 'iostat', 'mpstat', 'pidof', 'pgrep',
  'ip', 'ifconfig', 'route', 'ss', 'netstat', 'arp', 'ethtool', 'nmcli',
  'uname', 'arch', 'nproc', 'getconf', 'getent', 'id', 'whoami', 'who',
  'w', 'last', 'uptime', 'lsmod', 'modinfo', 'sysctl',
]);

// 重定向到 /dev/null 的丢弃写法（对齐 Python _DEVNULL_REDIRECT_RE）。
// 注意带 g 标志：一条诊断命令常含多个 2>/dev/null（cd ... && ls ... 2>/dev/null; find ... 2>/dev/null），
// JS String.replace 无 g 只替换首个，残留的 2>/dev/null 仍带 `>` 会触发重定向写误判（FP）。
// Python 端用 re.sub 全局替换，此处对齐之。
const DEVNULL_REDIRECT_RE = /(?:2|&|1)?\s*>\s*\/dev\/null\b/g;

/**
 * 综合判定是否为写/删操作（对齐 Python _is_write_operation，单一事实源）。
 * 供 L2 read_before_write 与 L1 sensitive_path 共用，避免手写复刻漂移。
 *
 * 1. WRITE_KEYWORDS 子串匹配 actionType+actionDetail（与 Python 一致，不加词边界以保持双端同步）
 * 2. WRITE_COMMAND_RES 词边界正则（rm/cp/dd/tee/truncate/...）
 * 3. sed -i 原地编辑
 * 4. 重定向写入：剥 devnull 后有 `>` 且首词非只读命令
 */
export function isWriteOperation(actionType: string, actionDetail: string, writeKeywords: string[] = WRITE_KEYWORDS): boolean {
  // 1. 关键词子串匹配（actionType 或 actionDetail）
  if (writeKeywords.some(kw => actionType.includes(kw) || actionDetail.includes(kw))) return true;
  // 2. 写/删命令词边界
  if (WRITE_COMMAND_RES.some(rx => rx.test(actionDetail))) return true;
  // 3. sed -i 原地编辑
  if (/\bsed\s+-[a-zA-Z]*i/i.test(actionDetail)) return true;
  // 3b. wget/curl + -O/-o/--output 下载写入（无 > 重定向，漏判 → 漏报，且可写 shell 后门绕过敏感路径）
  // 3c. rsync 同步写 dest（非 --list-only/--dry-run/-n 只读模式）
  // 两类都按命令段判定首词（排除 echo/printf 字面量）
  for (const seg of actionDetail.split(/&&|\|\||;|\n/)) {
    const trimmed = seg.trim();
    if (!trimmed) continue;
    const parts = trimmed.split(/\s+/);
    const fw = parts[0]?.toLowerCase() || '';
    if (fw === 'wget' || fw === 'curl') {
      // NEW-FP-C: -O- / -o- / --output-document=- / --output=- 是 stdout（值为 -），不算文件写
      const isStdout = /\s(?:-O|-o)-(?:\s|$)/.test(trimmed) ||
                       /\s--output-document=-(?:\s|$)/i.test(trimmed) ||
                       /\s--output=-(?:\s|$)/i.test(trimmed);
      if (isStdout) continue;
      // NEW-FP-N: -o /dev/null / --output=/dev/null 是丢弃响应体只测状态码，非真实写文件
      const isDevnull = /\s(?:-O|--output-document|--output)\s*\/dev\/null(?:\s|$)/i.test(trimmed) ||
                        /\s(?:-O|--output-document|--output)=[/]?dev\/null(?:\s|$)/i.test(trimmed);
      if (isDevnull) continue;
      if (/\s(?:-O|--output-document|--output)(?:=|\s|$)/i.test(trimmed) || /\s-O\S/.test(trimmed)) {
        return true;
      }
    }
    if (fw === 'rsync' && !/--list-only|--dry-run/i.test(trimmed) && !/(^|[^a-zA-Z])-n([^a-zA-Z]|$)/.test(trimmed)) {
      return true;
    }
  }
  // 4. 重定向写入：先排除 /dev/null 丢弃和比较运算符，再看是否还有真实文件重定向。
  // NEW-FN-D 修复：不再用「整条命令首词是否只读」判断——`cat in > out` 里 cat 是
  // 只读命令但其重定向目标 out 是真实写文件（覆写/追加），应判写。只读命令的「安全
  // 重定向」只指 `> /dev/null`（丢弃输出，已剥）。改为只读命令带真实文件重定向也算写。
  // fd 重定向（>&N / N>&M / 2>&1）不是写文件，用「> 后紧跟 &」排除。
  // grep/awk 搜索模式里的 > 字面量（如 grep "a>b" file）不是重定向——剥引号内容后再判。
  if (actionDetail.includes('>')) {
    // 先剥掉比较运算符（>=, <=, <>, <=>, =>），避免 Python 代码里的 `r.get('seq',0) >= 28`
    // 被当成重定向写（`>=` 含 `>`）。这些是表达式而非重定向，不应计入写判定。
    const detailWithoutCompare = actionDetail.replace(/<=>|>=|<=|<>|=>/g, ' ');
    const detailWithoutDevnull = detailWithoutCompare.replace(DEVNULL_REDIRECT_RE, '');
    // 先摘「> '引号路径'」为裸路径（支持引号包裹的重定向目标，如 echo x > '/tmp/file'），
    // 否则下一步剥引号内容会把重定向目标路径也删掉 → 漏判写（漏报）。
    const detailUnquotedRedirect = detailWithoutDevnull.replace(
      />{1,2}\s*(['"])([~./][^'"]+)\1/g,
      (_m, _q, p) => '>' + p,
    );
    // 剥掉剩余引号内内容（grep/awk 搜索模式、python -c 代码里的 > 字面量），只看引号外
    // 是否还有真实文件重定向。
    const detailWithoutQuotes = detailUnquotedRedirect.replace(/'[^']*'|"[^"]*"/g, '');
    // 真实文件重定向：> 或 >> 后紧跟非空白、非 & 的文件目标字符。
    // `>{1,2}\s*(?!&)\S` 匹配 echo x > /file、cat in >file、sort in >> /file；
    // 排除 ls 2>&1、echo >&2（>& 紧邻或 > 后 & 是 fd 合并，非写文件）。
    if (/>{1,2}\s*(?!&)\S/.test(detailWithoutQuotes)) {
      return true;
    }
  }
  return false;
}

// Read keywords for read-before-write detection
const READ_KEYWORDS = ['read', '读取', 'cat', 'head', 'tail', 'less', 'more', 'view', '查看', 'open', '打开', 'load', '加载', 'grep', 'search', '搜索', 'find', '查找'];

// Create-action exception keywords
const CREATE_KEYWORDS = ['创建', '新建', 'create', 'new file', 'touch'];

// Non-interactive password modification patterns
export const PASSWORD_MODIFY_PATTERNS: RegExp[] = (() => {
  // 归一化自 agent_moss/rules/l2_rules.json（单一事实源，与 Python 共用）。
  const pats = (loadL2().password_modify_consent || []) as any[];
  return pats.map((p) => new RegExp(p.pattern, 'i'));
})();

// Non-interactive user/group deletion patterns
export const USER_DELETION_PATTERNS: RegExp[] = (() => {
  // 归一化自 agent_moss/rules/l2_rules.json（单一事实源，与 Python 共用）。
  const pats = (loadL2().user_deletion_consent || []) as any[];
  return pats.map((p) => new RegExp(p.pattern, 'i'));
})();

// Intent deviation patterns (synced with Python linux.py IntentDeviationPattern)
export const INTENT_DEVIATION_PATTERNS: { intentKeywords: string[]; dangerousActions: string[]; reason: string }[] = (() => {
  // 归一化自 agent_moss/rules/l2_rules.json（单一事实源，与 Python 共用）。
  const pats = (loadL2().intent_consistency || []) as any[];
  return pats.map((p) => ({
    intentKeywords: p.intent_keywords,
    dangerousActions: p.dangerous_actions,
    reason: p.reason,
  }));
})();

/**
 * 匹配危险动作词。中文用子串（无词边界歧义），英文用词边界正则。
 *
 * 裸 includes() 会在 actionDetail 参数/搜索模式里误报：
 *   - `git log --format=` 含 "format" → 误判"格式化磁盘"
 *   - grep 搜索模式 `NON_WRITE|non_write` 含 "write" → 误判"修改"
 *   - `pip install --update` 含 "update" → 误判"修改"
 * 英文词用 `(?<!-)\bWORD\b`：
 *   - 前面不是 `-`（排除 --format / --update / -delete 等参数形态）
 *   - 词边界（排除 NON_WRITE 里的 write、arm 里的 rm 等）
 */
function matchDangerousAction(actionDetail: string, action: string): boolean {
  // 中文词（含非 ASCII）走子串匹配
  if (/[^\x00-\x7f]/.test(action)) {
    return actionDetail.includes(action);
  }
  // 英文词走词边界 + 排除参数前缀
  const escaped = action.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`(?<![-\\w])${escaped}\\b`, 'i');
  return re.test(actionDetail);
}

/** 按时间序收集本次会话的全部意图文本（含历史 prompt，去空、去重、lower 化）。
 *  兼容 dict {text, actions} 与纯文本 string 两种元素（后者为 AgentGate v3 旧格式）。 */
function collectIntentTexts(
  promptSession: string,
  promptHistory?: AnalysisInput['promptHistory'],
): string[] {
  const texts: string[] = [];
  if (promptHistory) {
    for (const turn of promptHistory) {
      if (typeof turn === 'string') {
        const t = turn.trim();
        if (t) texts.push(t.toLowerCase());
        continue;
      }
      const t = (turn?.text || '').trim();
      if (t) texts.push(t.toLowerCase());
    }
  }
  if (promptSession && promptSession.trim()) {
    texts.push(promptSession.toLowerCase());
  }
  // 去重保序
  const seen = new Set<string>();
  const deduped: string[] = [];
  for (const t of texts) {
    if (!seen.has(t)) {
      seen.add(t);
      deduped.push(t);
    }
  }
  return deduped;
}

export function runLogicCheck(input: AnalysisInput): SecurityJudgment | null {
  const { actionHistory, aNext, cwd } = input;
  const actionDetail = aNext.actionDetail.toLowerCase();
  const actionType = aNext.actionType.toLowerCase();
  const resolvedCwd = cwd || '/';

  // 非 shell/文件类操作跳过意图一致性和敏感路径检查
  const EXCLUDED_PREFIXES = ['memory-', 'skill-', 'skill-manager-', 'mailbox-', 'app-'];
  const isExcludedType = EXCLUDED_PREFIXES.some(p => actionType.startsWith(p));

  // Rule 1: Read-before-write principle
  const rbwResult = checkReadBeforeWrite(actionType, actionDetail, actionHistory, input.reason, resolvedCwd);
  if (rbwResult) return rbwResult;

  // Rule 2: Intent deviation detection
  // 只对 shell/文件类操作执行意图一致性检查
  if (!isExcludedType) {
    // 内联脚本命令（python -c / perl -e 等）跳过 intent 的 dangerousAction 词匹配。
    // 内联脚本代码内容里的英文词（print(delete this) 的 delete）是字符串字面量，
    // 不是真实动作；词边界 (?<![-\w])delete\b 能挡 print 里的 rm（短词），但挡不住
    // delete（长词独立词）→ intent 误报（Bug4）。内联脚本的「危险」由 L1.2
    // inline-analyzer 专门管（区分字面量 vs 真实调用），intent 不重复管。
    if (!INLINE_SCRIPT_RE.test(actionDetail)) {
      // 收集本次会话的全部意图文本（含历史 prompt，按时间序去重）。
      // 避免多轮会话里 "continue/继续" 等最近输入覆盖掉最初的读取/搜索意图而漏报。
      const intentTexts = collectIntentTexts(input.promptSession, input.promptHistory);
      for (const pattern of INTENT_DEVIATION_PATTERNS) {
        // 任一历史 prompt 命中意图词即视为"存在该意图"（防"继续"覆盖漏报）
        const intentMatched = intentTexts.some(text =>
          pattern.intentKeywords.some(kw => text.includes(kw))
        );
        const dangerousMatched = pattern.dangerousActions.some(kw => matchDangerousAction(actionDetail, kw));
        if (intentMatched && dangerousMatched) {
          return {
            allowed: false,
            reason: pattern.reason,
            riskLevel: 'high',
            riskType: 'intent_deviation',
            confidence: 85,
            source: 'logic_rule',
            violatedLayers: ['L2.1'],
          };
        }
      }
    }
  }

  // 注：敏感路径访问检测 (checkSensitivePath) / 危险操作模式检测 / 横向移动检测
  // 已按"L1 只看这一步"原则搬至 heuristic.ts 的 runHeuristicCheck。
  // 本函数仅保留需要 action_history / prompt_session / cwd 的 L2 规则。

  // Rule 4.5: Indirect file access — inline script with dir traversal + file read/write
  // Uses cwd to list actual files and check against sensitive paths directly
  const indirectResult = checkIndirectFileAccess(actionType, actionDetail, resolvedCwd);
  if (indirectResult) return indirectResult;

  // Rule 5: Privilege escalation detection
  // 判据：sudo 后跟的命令本身是包管理/服务管理（apt/systemctl/yum/...）→ 合法运维
  // 直接放行，不要求历史先有一次 admin（新会话首次 sudo apt install 是合法高频运维）。
  // sudo + 非运维命令才查历史有无 admin 上下文；历史也无则视为异常提权。
  // 注意：剥掉 sudo 前缀再匹配 admin 关键词，否则 actionDetail 必含 sudo 导致永远放行。
  // 注：admin 关键词曾尝试词边界 \b，但 grep apt / pip apt 里 apt 是独立词，\bapt\b 仍命中，
  // 词边界无法区分"命令位置"vs"参数位置"，故暂保留子串匹配。提权漏检（grep apt 误当 admin
  // 上下文放行 sudo cat）是已知问题，待用命令位置匹配专项处理。
  // 内联脚本命令（python -c / perl -e 等）跳过提权词匹配：代码内容里的词
  // （print("chmod u+s") 的 chmod u+s）是字符串字面量，不是真实动作，提权子串匹配
  // 会误报（FP-2 变体）。内联脚本的「危险」由 inline-analyzer 管，提权检测不重复管。
  if (INLINE_SCRIPT_RE.test(actionDetail)) {
    // fall through to next rule, skip privilege escalation
    // NEW-FP-J: 提权关键词改为「命令位置」判定。旧逻辑对整个 actionDetail 做子串匹配，
    // grep -rn "sudo" file、awk '/sudo/'、echo "sudo make install" 里参数/搜索模式/字面量
    // 位置的 sudo 被误判为真实提权。仅当段首词是提权命令（sudo/su/setuid，或 chmod+u+s）
    // 才认为存在提权意图。
  } else if (containsPrivilegeEscalation(actionDetail)) {
    const detailAfterSudo = actionDetail.replace(/(^|\|\||&&|\s)sudo\s+/g, ' ');
    const isAdminCmd = ['apt', 'systemctl', 'yum', 'dnf', 'pacman', 'zypper', 'apk'].some(kw => detailAfterSudo.includes(kw));
    if (!isAdminCmd) {
      const adminContext = actionHistory.some(h =>
        h.actionDetail.includes('sudo') || h.actionDetail.includes('apt') || h.actionDetail.includes('systemctl') ||
        h.actionDetail.includes('yum') || h.actionDetail.includes('dnf') || h.actionDetail.includes('pacman') ||
        h.actionDetail.includes('zypper') || h.actionDetail.includes('apk')
      );
      if (!adminContext) {
        return {
          allowed: false,
          reason: '检测到提权操作，未发现合法管理上下文',
          riskLevel: 'high',
          riskType: 'privilege_escalation',
          confidence: 85,
          source: 'logic_rule',
          violatedLayers: ['L2.1'],
        };
      }
    }
  }

  // 注：横向移动检测已搬至 heuristic.ts (runHeuristicCheck)。
  // Rule 6: Non-interactive password modification consent check
  const pwdResult = checkPasswordConsent(actionType, actionDetail, actionHistory);
  if (pwdResult) return pwdResult;

  // Rule 7: User/group deletion consent check
  const userDelResult = checkUserDeletionConsent(actionType, actionDetail, actionHistory);
  if (userDelResult) return userDelResult;

  // Rule 8: 组合攻击链检测（combo_chain）
  // 单步操作（创建 Flask 服务 / 端口扫描 / 读 known_hosts）各自无害，但按 kill chain
  // 顺序组合（LISTEN→EXEC→SCAN→CRED）即为后渗透攻击链。镜像 Python
  // logic_rules.py::_check_combo_chain；阶段 pattern 与链定义归一化自
  // l2_rules.json 的 combo_chains 段（单一事实源）。
  const comboResult = checkComboChain(actionHistory, aNext.actionDetail);
  if (comboResult) return comboResult;

  return null; // Pass to next layer
}

// ==================== 组合攻击链检测（combo_chain，镜像 Python _check_combo_chain）====================

// 阶段 pattern（编译自 l2_rules.json combo_chains.stages）
const COMBO_STAGES: Record<string, RegExp[]> = (() => {
  const combo = (loadL2().combo_chains || {}) as any;
  const stages: Record<string, RegExp[]> = {};
  for (const [name, pats] of Object.entries((combo.stages || {}) as Record<string, string[]>)) {
    stages[name] = (pats as string[]).map(p => new RegExp(p, 'i'));
  }
  return stages;
})();

// 链定义（l2_rules.json combo_chains.chains）
const COMBO_CHAINS: { id: string; stages: string[]; min_stages: number; risk_level: string; reason: string }[] = (() => {
  const combo = (loadL2().combo_chains || {}) as any;
  return ((combo.chains || []) as any[]).map(c => ({
    id: String(c.id || 'combo_chain'),
    stages: (c.stages || []) as string[],
    min_stages: Number(c.min_stages) || (c.stages || []).length,
    risk_level: String(c.risk_level || 'high'),
    reason: String(c.reason || '检测到组合攻击链'),
  }));
})();

function checkComboChain(
  actionHistory: { actionType: string; actionDetail: string }[],
  actionDetailRaw: string,
): SecurityJudgment | null {
  // 内联脚本命令（python -c 等）：代码内容是字符串字面量，阶段词可能只是文本
  // （print("subprocess")），交 inline-analyzer 专门管，不在此组合判定。
  INLINE_SCRIPT_RE.lastIndex = 0;
  if (INLINE_SCRIPT_RE.test(actionDetailRaw)) return null;

  // 动作序列：历史动作（按时间序）+ 当前动作
  const details: string[] = [];
  for (const h of actionHistory) {
    if (h.actionDetail) details.push(h.actionDetail.toLowerCase());
  }
  details.push(actionDetailRaw.toLowerCase());

  // 阶段标签序列：每个动作命中哪些阶段（一个动作可命中多阶段）
  const seq: Set<string>[] = details.map(d => {
    const hits = new Set<string>();
    for (const [stage, pats] of Object.entries(COMBO_STAGES)) {
      if (pats.some(p => { p.lastIndex = 0; return p.test(d); })) hits.add(stage);
    }
    return hits;
  });

  // 子序列匹配每条链：阶段按顺序在动作序列中出现（贪心，不必连续）
  for (const chain of COMBO_CHAINS) {
    const chainStages = chain.stages;
    if (!chainStages.length || chain.min_stages <= 0) continue;
    let matched = 0;
    let stageIdx = 0;
    for (const hits of seq) {
      if (stageIdx < chainStages.length && hits.has(chainStages[stageIdx])) {
        matched += 1;
        stageIdx += 1;
        if (matched >= chain.min_stages) break;
      }
    }
    if (matched >= chain.min_stages) {
      const riskLevel = (chain.risk_level === 'critical' || chain.risk_level === 'high' ||
        chain.risk_level === 'medium' || chain.risk_level === 'low') ? chain.risk_level : 'high';
      return {
        allowed: false,
        reason: chain.reason,
        riskLevel,
        riskType: 'combo_chain',
        confidence: 85,
        source: 'logic_rule',
        violatedLayers: ['L2.1'],
      };
    }
  }

  return null;
}

// Extract file paths from text (mirrors Python extract_file_paths)
export function extractFilePaths(text: string): string[] {
  const paths: string[] = [];
  // Unix paths starting with /（路径前是行首或空白）
  const unixPaths = text.match(/(?:^|\s)(\/[^\s;|&><'"]+)/g);
  if (unixPaths) paths.push(...unixPaths.map(p => p.trim()));
  // key=value 语法的路径：of=/path、if=/path、--output=/path 等。
  // 现有 unixPaths 正则要求路径前是行首或空白，`of=/tmp/x` 里 / 前是 = 不匹配 →
  // dd of=/path 等漏报（NEW-FN-A）。此正则匹配 `=` 后紧跟的 / 路径。
  // NEW-FP-H: 先剥掉引号内容，避免 echo "of=/dev/null done" 这类输出文本里的
  // of=/dev/null 被误当真实写目标。引号内纯路径（dd of="/tmp/file"）由下方
  // quotedPaths 独立提取（要求引号内以 / 开头），故剥引号不会漏报真实写。
  const textNoQuotes = text.replace(/'[^']*'|"[^"]*"/g, '');
  const kvPaths = textNoQuotes.match(/(?:=)(\/[^\s;|&><'"]+)/g);
  if (kvPaths) paths.push(...kvPaths.map(p => p.replace(/^=/, '')));
  // Quoted paths
  const quotedPaths = text.match(/["']\/([^"']+)["']/g);
  if (quotedPaths) paths.push(...quotedPaths.map(p => p.replace(/["']/g, '')));
  return [...new Set(paths)];
}

function checkReadBeforeWrite(
  actionType: string, actionDetail: string,
  actionHistory: { actionType: string; actionDetail: string }[],
  reason: string, cwd: string
): SecurityJudgment | null {
  // 豁免非文件类工具前缀（memory-/skill-/mailbox-/todomgr-...）与只读工具，
  // 避免 memory-removeMemory（工具名含 remove）/ filemgr-grepfiles（搜索模式含 write）等误判为写。
  // L2 层独立保护，不再仅依赖 coordinator opendesk 白名单（非 opendesk agent / 单测直调也安全）。
  if (NON_WRITE_TOOL_PREFIXES.some(p => actionType.startsWith(p))) return null;
  if (NON_WRITE_TOOLS.has(actionType)) return null;

  // 写判定按工具类型分流：
  // - bash/executebash/terminal-executebash：用 isWriteOperation（对齐 Python
  //   _is_write_operation 单一事实源：WRITE_KEYWORDS 子串 + WRITE_COMMAND_RES 词边界
  //   rm/cp/dd + sed -i + 重定向(剥 devnull+只读首词保护)）。比手写 WRITE_KEYWORDS.includes
  //   多了词边界命令识别，能抓 `rm`/`cp`/`dd` 等；重定向/2>/dev/null 由它统一处理。
  // - 其他工具：只匹配 actionType，不看 actionDetail 内容。
  //   理由：非 shell 工具的写意图只能从工具名体现（filemgr-writefile/write/edit），
  //   参数内容里的中文"更新""移除"是业务语义不是文件写语义；
  //   grep 搜索模式里的 write/update/remove 子串绝不能算写意图（误报根因）。
  const isBashLike = actionType === 'bash' || actionType === 'executebash' || actionType === 'terminal-executebash';
  const isWrite = isBashLike
    ? isWriteOperation(actionType, actionDetail)
    : WRITE_KEYWORDS.some(kw => actionType.includes(kw));

  if (!isWrite) return null;

  // 删除/安全命令复合（无真正写命令）不触发 read_before_write。
  // read_before_write 的语义是「写文件前先读内容」，对删除不适用——删除不需要读文件字节，
  // 且删除的元数据预检（rm -rf /etc 等敏感路径、递归）由 L1 命令模式负责（/tmp 清理 L1
  // 判定安全放行，rm -rf /etc L1 拦截）。这是「rm 豁免狭义读内容」而非「跳过 RBW」——
  // 广义元数据预检仍由 L1 完成。判定：命令链无「写命令段」即跳过。写命令段 = 段首词是
  // 写命令（cp/mv/install/tee/dd/truncate/mkfs/sed -i）或含真实重定向写。
  // 注意：chmod/chown 不在此列——改元数据不改文件内容，「写前先读」对其无意义，
  // `chmod 644 /tmp/已有未读` 不应误报。危险 chmod 形态（777/u+s/4755 提权、chmod /敏感路径）
  // 由 L1 专门模式和 sensitive_path 检测负责（WRITE_COMMAND_RES 仍保留 chmod/chown 供敏感路径写判定）。
  // `rm ... && echo done` 豁免，`rm /a && echo x > /b` 仍走 rbw，
  // `chmod 644 /tmp/x`（普通）豁免，`chmod u+s /tmp/x`（提权）由 L1 拦。
  const WRITE_CMDS = new Set(['cp', 'mv', 'install', 'tee', 'dd', 'truncate', 'mkfs', 'fdisk', 'parted']);
  if (isBashLike) {
    const detailNoCompare = actionDetail.replace(/<=>|>=|<=|<>|=>/g, ' ');
    const detailNoDevnull = detailNoCompare.replace(DEVNULL_REDIRECT_RE, '');
    // 先摘「> '引号路径'」为裸路径（支持引号包裹重定向目标），再剥剩余引号内容，
    // 与 isWriteOperation 的重定向判定保持一致（避免两处漂移）。
    const detailUnquotedRedirect = detailNoDevnull.replace(
      />{1,2}\s*(['"])([~./][^'"]+)\1/g,
      (_m, _q, p) => '>' + p,
    );
    const detailNoQuotes = detailUnquotedRedirect.replace(/'[^']*'|"[^"]*"/g, '');
    const hasRedirectWrite = />{1,2}\s*(?!&)\S/.test(detailNoQuotes);
    let hasWriteSeg = hasRedirectWrite;
    if (!hasWriteSeg) {
      for (const seg of actionDetail.split(/&&|\|\||;|\n/)) {
        const trimmed = seg.trim();
        if (!trimmed) continue;
        const fw = trimmed.split(/\s+/)[0]?.toLowerCase() || '';
        if (WRITE_CMDS.has(fw) || /\bsed\s+-[a-zA-Z]*i/i.test(trimmed)) {
          hasWriteSeg = true;
          break;
        }
        // wget/curl + -O/-o/--output 下载写入
        if ((fw === 'wget' || fw === 'curl') &&
            (/\s(?:-O|--output-document|--output)(?:=|\s|$)/i.test(trimmed) || /\s-O\S/.test(trimmed))) {
          hasWriteSeg = true;
          break;
        }
        // rsync 同步写 dest（非 --list-only/--dry-run/-n 只读模式）
        if (fw === 'rsync' && !/--list-only|--dry-run/i.test(trimmed) && !/(^|[^a-zA-Z])-n([^a-zA-Z]|$)/.test(trimmed)) {
          hasWriteSeg = true;
          break;
        }
      }
    }
    if (!hasWriteSeg) return null;
  }

  // Extract target file paths，过滤掉非写目标的参数路径。
  // - cd 是目录切换不是写操作，cd /path 的 /path 不应作为写目标（否则 `cd /敏感 && ls` 误报）。
  // - 读命令（cat/head/tail/grep/find/less/more/wc/cut 等 READ_ONLY_COMMANDS）的文件参数是
  //   读取目标不是写目标，`echo x > /tmp/t1; cat /tmp/t2` 里 t2 是 cat 的读目标却会被
  //   extractFilePaths 当写目标提取 → read_before_write 误报（Bug5）。过滤之。
  // - 写命令的源文件参数（cp/mv/install 的首个路径参数）是读取目标不是写目标，
  //   `cp /src /dst` 里 /src 是读目标不是写目标 → 误报（NEW-FP-1）。过滤首个路径参数。
  // - dd 的 if=/path 是输入源（读目标），of=/path 才是输出目标（写目标）。
  //   `dd if=/dev/zero of=/tmp/x` 里 if= 的 /dev/zero 是读源，必须排除否则误报；
  //   of= 的 /tmp/x 是写目标保留（NEW-FN-A：此前 of= 路径根本提取不到 → 漏报）。
  // 逐段法（per-segment）：按 &&/||/;/换行 拆命令段，每段独立计算写目标——
  //   cd → 无写目标（切目录）；
  //   只读命令（cat/grep/sort/head 等）→ 命令参数是读目标，但重定向目标（> /path）
  //     是写目标，需提取（NEW-FN-D：此前整段排除把重定向目标也丢了 → `cat in > out` 漏检 out）；
  //   cp/mv/install → 排除首个路径（源文件），其余为写目标；
  //   dd → 排除 if= 路径（输入源），of= 为写目标；
  //   其他段 → 所有路径为写目标。
  // 关键：排除是 per-segment 局部的，不是全局——否则 `cp /a /b && cp /b /c` 里
  // /b 既是第一段 dest（写目标）又是第二段 source（读目标），全局排除会让第一段
  // 对 /b 的覆写漏检（NEW-FN-B）。逐段计算确保 /b 在第一段仍被作为写目标检查。
  const SOURCE_ARG_CMDS = new Set(['cp', 'mv', 'install', 'rsync']);
  // 重定向写目标正则：> 或 >> 后紧跟文件路径（裸路径或引号包裹，排除 >& fd）。
  // 用 RegExp 构造避免正则字面量里 / 与路径分隔符冲突。
  const REDIRECT_TARGET_RE = new RegExp(">{1,2}\\s*(?!&)(?:'(/[^']+)'|\"(/[^\\\"]+)\"|(/[^\\s;|&><'\\\"]+))");
  const targetPaths: string[] = [];
  for (const seg of actionDetail.split(/&&|\|\||;|\n/)) {
    const trimmed = seg.trim();
    if (!trimmed) continue;
    const firstWord = trimmed.split(/\s+/)[0]?.toLowerCase() || '';
    if (firstWord === 'cd') {
      continue;
    }
    if (READ_ONLY_COMMANDS.has(firstWord)) {
      // 只读命令：文件参数是读目标，但重定向目标是写目标（NEW-FN-D）。
      // 先摘引号重定向目标（去引号保留路径），再剥剩余引号内容（grep 模式），再提取目标。
      // NEW-FP-M: 先剥 /dev/null 重定向（cat f 2>/dev/null 的 /dev/null 是 stderr 丢弃
      // 非写目标），否则 REDIRECT_TARGET_RE 把 2>/dev/null 提取为写目标误报。
      const segUnquoted = trimmed.replace(new RegExp(">{1,2}\\s*(['\"])([~./][^'\"]+)\\1", "g"), (_m, _q: string, p: string) => '>' + p);
      const segNoDevnull = segUnquoted.replace(DEVNULL_REDIRECT_RE, '');
      const segNoQuotes = segNoDevnull.replace(/'[^']*'|"[^"]*"/g, '');
      const m = segNoQuotes.match(REDIRECT_TARGET_RE);
      if (m) targetPaths.push(m[1] || m[2] || m[3]);
      continue;
    }
    const segPaths = extractFilePaths(trimmed);
    // NEW-FP-N: curl/wget 的 -o /dev/null 是丢弃响应体非真实写文件，排除 /dev/null
    // 路径（extractFilePaths 会把 -o /dev/null 的 /dev/null 提取为写目标 → 误报）。
    const segPathsFiltered = (firstWord === 'wget' || firstWord === 'curl')
      ? segPaths.filter(p => p !== '/dev/null')
      : segPaths;
    if (SOURCE_ARG_CMDS.has(firstWord)) {
      // 排除首个路径（源文件），其余为写目标
      if (segPathsFiltered.length > 1) targetPaths.push(...segPathsFiltered.slice(1));
    } else if (firstWord === 'dd') {
      // dd 的 if= 是输入源（读目标），of= 是输出目标（写目标）。
      // 排除 if= 的路径，保留 of= 的路径作为写目标。
      // NEW-FP-G: of=/dev/null 是丢弃输出非真实写文件（dd if=/dev/zero
      // of=/dev/null 是丢弃测试），与重定向 >/dev/null 同语义，排除避免
      // read_before_write 误报 /dev/null。/dev/zero/urandom 同理（设备文件）。
      const ifSourceMatches = trimmed.match(/\bif=(\/[^\s;|&><'"]+)/g);
      const ifSourcePaths = new Set(ifSourceMatches ? ifSourceMatches.map((m: string) => m.replace(/^if=/, '')) : []);
      const devNullMatches = trimmed.match(/\bof=(\/dev\/\S+)/g);
      const devNullTargets = new Set(devNullMatches ? devNullMatches.map((m: string) => m.replace(/^of=/, '')) : []);
      for (const sp of segPaths) {
        if (!ifSourcePaths.has(sp) && !devNullTargets.has(sp)) targetPaths.push(sp);
      }
    } else {
      // 其他段（含重定向写 echo > file、tee、truncate 等）：该段所有路径为写目标
      targetPaths.push(...segPathsFiltered);
    }
  }
  // 去重
  const uniqueTargetPaths = [...new Set(targetPaths)];
  if (uniqueTargetPaths.length === 0) return null;

  // Collect read paths from history
  const historyReadPaths = new Set<string>();
  for (const action of actionHistory) {
    const histDetail = action.actionDetail.toLowerCase();
    const histType = action.actionType.toLowerCase();
    const isRead = READ_KEYWORDS.some(kw => histType.includes(kw) || histDetail.includes(kw));
    if (isRead) {
      for (const p of extractFilePaths(histDetail)) {
        historyReadPaths.add(p);
      }
    }
  }

  // Check if target paths have been read
  const unreadPaths: string[] = [];
  for (const path of uniqueTargetPaths) {
    const hasRead = [...historyReadPaths].some(rp =>
      path === rp || path.startsWith(rp) || rp.startsWith(path)
    );
    if (!hasRead) {
      // 排除新文件创建：文件不存在于磁盘时视为新建，直接放行
      // 同时检查 reason/action_detail 中是否有创建/新建关键词
      let isCreate = !fs.existsSync(path);
      if (!isCreate) {
        isCreate = CREATE_KEYWORDS.some(kw => reason.toLowerCase().includes(kw) || actionDetail.includes(kw));
      }
      if (!isCreate) {
        unreadPaths.push(path);
      }
    }
  }

  if (unreadPaths.length > 0) {
    return {
      allowed: false,
      reason: `违反 read_before_write 安全原则：对文件 ${unreadPaths[0]} 执行写入操作，但历史执行序列中未发现对该文件的读取操作`,
      riskLevel: 'high',
      riskType: 'read_before_write',
      confidence: 85,
      source: 'logic_rule',
      violatedLayers: ['L2.1'],
    };
  }

  return null;
}

function checkPasswordConsent(
  actionType: string, actionDetail: string,
  actionHistory: { actionType: string; actionDetail: string }[]
): SecurityJudgment | null {
  if (actionType !== 'bash') return null;

  const isPasswordModify = PASSWORD_MODIFY_PATTERNS.some(p => p.test(actionDetail));
  if (!isPasswordModify) return null;

  // 检查 action_history 中是否有 ask_user_question 且用户返回了答案
  const hasConsent = actionHistory.some(h =>
    h.actionType.toLowerCase() === 'ask_user_question' && h.actionDetail.trim().length > 0
  );
  if (hasConsent) return null;

  return {
    allowed: false,
    reason: '执行非交互式密码修改命令，但历史执行序列中未发现向用户确认密码的 ask_user_question 操作，可能存在未授权的密码修改风险',
    riskLevel: 'high',
    riskType: 'consent_missing',
    confidence: 85,
    source: 'logic_rule',
    violatedLayers: ['L2.1'],
  };
}

function checkUserDeletionConsent(
  actionType: string, actionDetail: string,
  actionHistory: { actionType: string; actionDetail: string }[]
): SecurityJudgment | null {
  if (actionType !== 'bash') return null;

  const isUserDeletion = USER_DELETION_PATTERNS.some(p => p.test(actionDetail));
  if (!isUserDeletion) return null;

  // 检查 action_history 中是否有 ask_user_question 且用户确认了
  const hasConsent = actionHistory.some(h =>
    h.actionType.toLowerCase() === 'ask_user_question' && h.actionDetail.trim().length > 0
  );
  if (hasConsent) return null;

  return {
    allowed: false,
    reason: '执行删除系统用户命令，但历史执行序列中未发现向用户确认的 ask_user_question 操作，可能存在未授权的用户删除风险',
    riskLevel: 'high',
    riskType: 'consent_missing',
    confidence: 85,
    source: 'logic_rule',
    violatedLayers: ['L2.1'],
  };
}

// 内联脚本解释器正则
const INLINE_SCRIPT_RE = /(?:^|\s)(?:python|python3|python3\.\d+|perl|perl5|ruby|jruby|mruby|node|php|lua)\s+(?:-[a-zA-Z]*[cer][a-zA-Z]*\s+)/i;

// NEW-FP-J: 提权关键词「命令位置」判定。仅当段首词是提权命令（sudo/su/setuid，
// 或 chmod+u+s setuid 位）才认为存在提权意图。引号感知分段：echo "a; sudo rm" 的
// ; 在引号内不分段，整段首词 echo 不触发。grep/awk/echo 首词段的参数是搜索模式/字面量。
function containsPrivilegeEscalation(actionDetail: string): boolean {
  const ad = actionDetail.toLowerCase();
  for (const seg of ad.split(/&&|\|\||;|\n/)) {
    const trimmed = seg.trim();
    if (!trimmed) continue;
    const parts = trimmed.split(/\s+/);
    const fw = parts[0]?.toLowerCase() || '';
    if (fw === 'sudo' || fw === 'su' || fw === 'setuid') return true;
    if (fw === 'chmod' && /\bu\s*\+\s*s\b/.test(trimmed)) return true;
  }
  return false;
}

// 目录遍历关键词（用唯一名称避免与 inline-analyzer.ts 的 DIR_TRAVERSAL_KEYWORDS 冲突）
const DIR_TRAVERSAL_KW = [
  'os.listdir', 'os.walk', 'os.scandir',
  'glob.glob', 'glob.iglob', 'pathlib.', 'iterdir', 'rglob',
  'scandir(', 'listdir(',
];

/**
 * Rule 4.5: Indirect file access detection.
 * Detects inline scripts that use directory traversal (os.listdir/glob/pathlib)
 * combined with file read/write operations to dynamically discover and access
 * sensitive files, bypassing static path matching.
 *
 * Returns medium risk so the coordinator forwards to Layer 3 LLM analysis
 * instead of denying immediately.
 */
function checkIndirectFileAccess(actionType: string, actionDetail: string, cwd: string): SecurityJudgment | null {
  // Only check bash tool inline scripts
  if (actionType !== 'bash' && actionType !== 'executebash' && actionType !== 'terminal-executebash') {
    return null;
  }

  // Check if it's an inline script command
  INLINE_SCRIPT_RE.lastIndex = 0;
  if (!INLINE_SCRIPT_RE.test(actionDetail)) {
    return null;
  }

  // Check for directory traversal keywords
  const lowerDetail = actionDetail.toLowerCase();
  const hasTraversal = DIR_TRAVERSAL_KW.some(kw => lowerDetail.includes(kw));
  if (!hasTraversal) {
    return null;
  }

  // Extract code and check for read/write keywords, distinguishing read/write/exec
  const READ_KEYWORDS = ['read(', 'readline', 'readlines', 'fread', 'fgets', 'load(', 'getpass', 'file_get_contents'];
  const WRITE_KEYWORDS = ['write(', 'writelines', 'fwrite', 'file_put_contents'];
  const EXEC_KEYWORDS = ['system(', 'exec(', 'eval(', 'popen(', 'os.system', 'os.popen', 'subprocess', 'os.exec', 'os.spawn', 'shell=true', 'check_output', 'check_call', 'run(', 'passthru', 'shell_exec', 'proc_open'];
  const OPEN_KEYWORDS = ['open(', 'fopen('];
  const code = extractInlineCode(actionDetail);
  if (!code) return null;
  const codeLower = code.toLowerCase();
  const hasAnyOp = READ_KEYWORDS.some(kw => codeLower.includes(kw)) ||
    WRITE_KEYWORDS.some(kw => codeLower.includes(kw)) ||
    EXEC_KEYWORDS.some(kw => codeLower.includes(kw)) ||
    OPEN_KEYWORDS.some(kw => codeLower.includes(kw));
  if (!hasAnyOp) {
    return null;
  }

  // Determine operation type
  const hasWrite = WRITE_KEYWORDS.some(kw => codeLower.includes(kw));
  const hasExec = EXEC_KEYWORDS.some(kw => codeLower.includes(kw));
  // Write/exec: block all sensitive files. Read only: block only credential files.
  const blockAllSensitive = hasWrite || hasExec;

  // Pattern matched — try to list actual files in cwd and check against sensitive paths
  let actualFiles: string[] = [];
  if (cwd && cwd !== '/') {
    try {
      actualFiles = fs.readdirSync(cwd);
    } catch {
      // cwd invalid or inaccessible, fall through
    }
  }

  if (actualFiles.length > 0) {
    // Check credential files
    for (const cp of CREDENTIAL_PATHS) {
      const fname = cp.path.split('/').pop() || cp.path;
      if (actualFiles.some(f => f === fname || f.toLowerCase() === fname.toLowerCase())) {
        return {
          allowed: false,
          reason: `内联脚本使用目录遍历动态发现文件并执行读写操作，cwd (${cwd}) 中包含凭据文件: ${fname}`,
          riskLevel: 'high',
          riskType: 'file_access',
          confidence: 95,
          source: 'logic_rule',
          violatedLayers: ['L2.1'],
          isCredential: true,
        };
      }
    }

    // Check other sensitive files (only block on write/exec, read-only is safe for non-credential)
    if (blockAllSensitive) {
      for (const sp of [...ROOT_SENSITIVE_PATHS, ...HOME_SENSITIVE_PATHS]) {
        const fname = sp.path.split('/').pop() || sp.path;
        if (actualFiles.some(f => f === fname || f.toLowerCase() === fname.toLowerCase())) {
          return {
            allowed: false,
            reason: `内联脚本使用目录遍历动态发现文件并执行写操作，cwd (${cwd}) 中包含敏感文件: ${fname}`,
            riskLevel: 'high',
            riskType: 'file_access',
            confidence: 95,
            source: 'logic_rule',
            violatedLayers: ['L2.1'],
          };
        }
      }
    }

    // No sensitive files found in cwd — safe to allow
    return null;
  }

  // cwd invalid, can't check actual files — fall back to medium risk (L3)
  return {
    allowed: false,
    reason: '内联脚本使用目录遍历函数动态发现文件并执行读写操作，无法获取 cwd 实际文件列表，转层3 LLM 分析',
    riskLevel: 'medium',
    riskType: 'file_access',
    confidence: 70,
    source: 'logic_rule',
    violatedLayers: ['L2.1'],
  };
}
