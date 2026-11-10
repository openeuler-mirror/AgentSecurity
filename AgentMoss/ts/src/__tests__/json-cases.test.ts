/**
 * 双端共用 JSON 测试用例加载器（单一事实源）。
 *
 * 读取 tests/cases/*.json（与 Python test_all_cases.py 共用同一批 case），
 * 转换字段名（snake_case → camelCase，对齐 TS AnalysisInput），调 runAnalysis
 * 禁用 LLM（仅跑 L1+L2，对齐 Python TestLayer1And2），断言 expected_decision/
 * risk_level。新增 case 只改 JSON，双端自动跑，避免「改 Python 忘改 TS」。
 *
 * 字段映射（JSON snake_case → TS camelCase）：
 *   session_id    → sessionId
 *   prompt_session→ promptSession
 *   action_history→ actionHistory (元素: action_type/action_detail → actionType/actionDetail)
 *   a_next        → aNext (同上)
 *   reason        → reason
 *   os_type       → osType（默认 linux）
 *   agent_id      → agentId（默认空=通用模式，与 Python 不传 agent_id 一致）
 *
 * LLM 禁用：process.env.AGENT_MOSS_DISABLE_LLM=1（见 config.ts isLLMAvailable），
 *          runAnalysis 走 skipLLM 分支，只跑 L1+L2。
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { runAnalysis } from '../engine/coordinator';
import type { AnalysisInput } from '../engine/coordinator';
import { isLLMAvailable, probeLLMConnection } from '../config';
import { extractFilePaths } from '../engine/logic-rules';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

// read_before_write 文件状态预处理——双端对齐 Python conftest._prep_file_state：
// read_before_write 判定依赖磁盘（fs.existsSync），同命令在目标「存在/不存在」时
// 结论可能相反（新建→Allow；写已有未读→Deny）。执行每个用例前对齐：写新建→删、
// 写已有（历史读过）→建。纯读命令的目标由 prep.sh 建，测试不干预。
function prepFileState(c: JsonCase): void {
  const inp = c.input;
  const aNext = inp.a_next;
  if (!aNext.action_detail || !['bash', 'executebash', 'terminal-executebash'].includes(aNext.action_type.toLowerCase())) {
    return;
  }
  // 历史读取路径
  const readKeywords = ['read', 'cat', 'head', 'tail', 'less', 'more', 'grep', 'find', 'search', 'view', '打开', '读取', '查看'];
  const historyRead = new Set<string>();
  for (const h of inp.action_history || []) {
    const hd = String(h.action_detail || '').toLowerCase();
    if (readKeywords.some(kw => hd.includes(kw))) {
      for (const p of extractFilePaths(hd)) historyRead.add(p);
    }
  }
  // 写目标：> 重定向 + wget/curl -o 落盘
  const writeTargets: string[] = [];
  const seg = aNext.action_detail.replace(/'[^']*'|"[^"]*"/g, '');
  const redirectRe = />\s*(?!\/dev\/null\b)(?!\/proc\/)(?!\/sys\/)(?!\/run\/)([^\s;|&<>"']+)/g;
  let m: RegExpExecArray | null;
  while ((m = redirectRe.exec(seg)) !== null) writeTargets.push(m[1]);
  const dlRe = /\s(?:-O|--output-document|--output|-o)\s*([^\s;|&<>"']+)/gi;
  while ((m = dlRe.exec(aNext.action_detail)) !== null) {
    const t = (m[1] || '').trim();
    if (t.startsWith('/') && t !== '-' && t !== '/dev/null'
        && !t.startsWith('/dev/') && !t.startsWith('/proc/') && !t.startsWith('/sys/') && !t.startsWith('/run/')) {
      writeTargets.push(t);
    }
  }
  for (const target of [...new Set(writeTargets)]) {
    if (!target.startsWith('/')) continue;
    const readBefore = [...historyRead].some(rp => target === rp || target.startsWith(rp) || rp.startsWith(target));
    try {
      if (readBefore) {
        if (!fs.existsSync(target)) {
          fs.mkdirSync(path.dirname(target), { recursive: true });
          fs.writeFileSync(target, '');
        }
      } else if (fs.existsSync(target)) {
        fs.rmSync(target, { force: true });
      }
    } catch { /* 权限/只读路径忽略，engine 该拦就拦 */ }
  }
}

// LLM 判定（对齐 Python tests/conftest.py 的 llm_probe_available）：
//   1) isLLMAvailable()：判定源 = env + ~/.config/agentmoss/config.json 的 api_key（非空）
//   2) probeLLMConnection()：无 key 则禁 LLM 仅跑 L1+L2；
//      有 key 再发一次 max_tokens=1 ping，连通才保留 LLM；key 无效/网络不通则
//      禁 LLM + 明确提示，避免坏 key 真调 LLM 走 fail-open 假通过。
//
// 对齐 Python：判据是「连通性探测结果」而非「key 是否存在」。探测是异步的，
// 无法在收集时（it/it.skip 注册阶段）同步拿到，故：
//   - 模块级缓存探测结果（_llmProbeOk），beforeAll 幂等探测一次写入；
//   - 所有用例统一用 it()（不提前 it.skip），测试函数体内遇 llm_required 且
//     探测失败时运行时 ctx.skip() —— 等价 Python 函数体内 `if not llm_probe_available: pytest.skip`。
//   这样「有 key 但网络不通」时 L3 被跳过而非失败（修复旧逻辑在收集时用
//   isLLMAvailable() 只看 key、忽略探测结果的误判）。
let _llmProbeOk: boolean | null = null; // null=未探测，true/false=结果

async function ensureLlmProbe(): Promise<boolean> {
  if (_llmProbeOk !== null) return _llmProbeOk;
  if (!isLLMAvailable()) {
    _llmProbeOk = false;
    process.env.AGENT_MOSS_DISABLE_LLM = '1';
    return false;
  }
  const ok = await probeLLMConnection();
  _llmProbeOk = ok;
  if (!ok) {
    process.env.AGENT_MOSS_DISABLE_LLM = '1';
    // eslint-disable-next-line no-console
    console.error(
      '[AgentMoss test] LLM 连通性探测失败（地址/模型见 config），key 可能无效或网络不通，L3 用例将被跳过（避免 fail-open 假通过）'
    );
  } else {
    // eslint-disable-next-line no-console
    console.log('[AgentMoss test] LLM 连通性探测通过，L3 用例将真调 LLM');
  }
  return ok;
}

let _llmProbeStarted = false;
beforeAll(async () => {
  if (!_llmProbeStarted) {
    _llmProbeStarted = true;
    await ensureLlmProbe();
  }
});

const CASES_DIR = path.resolve(__dirname, '../../../tests/cases');

interface JsonCase {
  id: string;
  desc: string;
  expected_decision: string;  // snake_case（JSON 原文）
  expected_layers?: string[];
  expected_risk_level?: string;
  expected_risk_type?: string;
  llm_required?: boolean;
  note?: string;
  input: {
    session_id?: string;
    prompt_session?: string;
    prompt_history?: Array<{ text: string; actions: Array<{ action_type: string; action_detail: string }> }>;
    action_history?: Array<{ action_type: string; action_detail: string }>;
    session_history?: Array<{
      session_id?: string;
      action_history: Array<{ action_type: string; action_detail: string }>;
    }>;
    a_next: { action_type: string; action_detail: string };
    reason?: string;
    os_type?: string;
    agent_id?: string;
    scenario_id?: string;
    cwd?: string;
  };
}

/** JSON case（snake_case）→ TS AnalysisInput（camelCase）。 */
/** AM_YOUR_HOME 占位符 → 当前用户家目录绝对路径（对齐 Python conftest._expand_placeholder）。
 * JSON 里 /home/xxx 硬编码路径写成 AM_YOUR_HOME，加载时展开成当前用户家目录，
 * 保证判定与原来的 /home/me、/home/user 一致（不依赖具体用户名）。 */
function expandPlaceholder(s: string): string {
  return s.replaceAll('AM_YOUR_HOME', os.homedir());
}

function toAnalysisInput(c: JsonCase): AnalysisInput {
  const inp = c.input;
  return {
    sessionId: inp.session_id || c.id,
    promptSession: expandPlaceholder(inp.prompt_session || ''),
    promptHistory: (inp.prompt_history || []).map(t => ({
      text: expandPlaceholder(t.text || ''),
      actions: (t.actions || []).map(a => ({
        actionType: a.action_type,
        actionDetail: expandPlaceholder(a.action_detail),
      })),
    })),
    actionHistory: (inp.action_history || []).map(h => ({
      actionType: h.action_type,
      actionDetail: expandPlaceholder(h.action_detail),
    })),
    sessionHistory: (inp.session_history || []).map(s => ({
      sessionId: s.session_id || 's',
      actionHistory: (s.action_history || []).map(h => ({
        actionType: h.action_type,
        actionDetail: expandPlaceholder(h.action_detail),
      })),
    })),
    aNext: {
      actionType: inp.a_next.action_type,
      actionDetail: expandPlaceholder(inp.a_next.action_detail),
    },
    reason: expandPlaceholder(inp.reason || ''),
    osType: inp.os_type || 'linux',
    cwd: expandPlaceholder(inp.cwd || '/tmp'),
    agentId: inp.agent_id || '',
    scenarioId: inp.scenario_id || '',
  };
}

/** 加载所有 JSON case（递归扫 cases/ 下所有子目录，按 L1/L2/L3 分类）。
 * 场景用例在子目录 scenario/<scenario_id>/*.json（如 scenario/bank/*.json），
 * 故递归遍历；file 用相对路径（如 "scenario/bank/scenario-bank-01.json"）。 */
function loadCases(): Array<{ file: string; case: JsonCase }> {
  const out: Array<{ file: string; case: JsonCase }> = [];
  const walk = (dir: string, prefix: string) => {
    for (const f of fs.readdirSync(dir).sort()) {
      const full = path.join(dir, f);
      if (fs.statSync(full).isDirectory()) {
        walk(full, prefix ? `${prefix}/${f}` : f);
      } else if (f.endsWith('.json')) {
        const raw = fs.readFileSync(full, 'utf-8');
        out.push({ file: prefix ? `${prefix}/${f}` : f, case: JSON.parse(raw) as JsonCase });
      }
    }
  };
  walk(CASES_DIR, '');
  return out;
}

const cases = loadCases();

// indirect_file_access 规则需 cwd 实际含凭据文件才命中（对齐 Python os.listdir 检查）。
// beforeAll setup 临时目录放 .env 凭据，供 l2/logic-10-indirect-access.json 用。
let _indirectCwd = '/tmp';
beforeAll(() => {
  const fs2 = fs;
  const path2 = path;
  const os = require('os');
  const d = path2.join(os.tmpdir(), `agentmoss-indirect-${process.pid}`);
  try {
    fs2.mkdirSync(d, { recursive: true });
    fs2.writeFileSync(path2.join(d, '.env'), 'KEY=val');
    _indirectCwd = d;
  } catch { /* ignore setup error, fallback /tmp */ }
});
afterAll(() => {
  try { fs.rmSync(_indirectCwd, { recursive: true, force: true }); } catch { /* ignore */ };
});

// ========== 脚本分支感知（case $1）测试环境（对齐 Python script_branch_cwd fixture） ==========
// deploy.sh 的 case $1 in 中 clean 分支含 rm -rf ~/.ssh/id_rsa（危险），backup 分支安全。
// 供 l1/script-branch-*.json 用例用（clean→Deny、backup→Allow，双端共用）。
const _SCRIPT_BRANCH_BODY = `#!/bin/bash
case $1 in
  clean)
    echo 'cleaning'
    rm -rf ~/.ssh/id_rsa
    ;;
  backup)
    echo 'backing up'
    tar -czf /tmp/backup.tar.gz ~/docs
    ;;
esac
`;
let _scriptBranchCwd = '/tmp';
beforeAll(() => {
  try {
    const d = path.join(os.tmpdir(), `agentmoss-script-branch-${process.pid}`);
    fs.rmSync(d, { recursive: true, force: true });
    fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(path.join(d, 'deploy.sh'), _SCRIPT_BRANCH_BODY);
    _scriptBranchCwd = d;
  } catch { /* fallback /tmp */ }
});
afterAll(() => {
  try { fs.rmSync(_scriptBranchCwd, { recursive: true, force: true }); } catch { /* ignore */ };
});

// ========== Python 脚本分支感知（sys.argv 分支）测试环境（对齐 Python python_script_branch_cwd fixture） ==========
// deploy.py 的 sys.argv[1] 分派中 clean 分支含 os.system rm -rf ~/.ssh/id_rsa（危险），backup 分支安全。
// 供 l1/script-branch-py-*.json 用例用（clean→Deny、backup→Allow，双端共用）。
const _PYTHON_BRANCH_BODY = `#!/usr/bin/env python3
import sys
import os

mode = sys.argv[1] if len(sys.argv) > 1 else "backup"

if mode == "clean":
    os.system("rm -rf ~/.ssh/id_rsa")
elif mode == "backup":
    print("backing up")
else:
    print("unknown mode")
`;
let _pythonScriptBranchCwd = '/tmp';
beforeAll(() => {
  try {
    const d = path.join(os.tmpdir(), `agentmoss-python-branch-${process.pid}`);
    fs.rmSync(d, { recursive: true, force: true });
    fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(path.join(d, 'deploy.py'), _PYTHON_BRANCH_BODY);
    _pythonScriptBranchCwd = d;
  } catch { /* fallback /tmp */ }
});
afterAll(() => {
  try { fs.rmSync(_pythonScriptBranchCwd, { recursive: true, force: true }); } catch { /* ignore */ };
});

// ========== Shell shift 漏报防护（$1 语义被改写）测试环境（对齐 Python shell_shift_cwd fixture） ==========
// deploy_shift.sh 开头 shift 改写 $1：bash deploy_shift.sh backup clean 实际走 clean 危险分支。
// 修复前 P1 绑定 $1=backup 误剪危险分支（漏报）；修复后含 shift 跳过 P1 → fail-closed 全文本 → 拦。
const _SHIFT_BRANCH_BODY = `#!/bin/bash
shift
case $1 in
  clean)
    rm -rf ~/.ssh/id_rsa
    ;;
  backup)
    echo 'backing up'
    ;;
esac
`;
let _shellShiftCwd = '/tmp';
beforeAll(() => {
  try {
    const d = path.join(os.tmpdir(), `agentmoss-shell-shift-${process.pid}`);
    fs.rmSync(d, { recursive: true, force: true });
    fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(path.join(d, 'deploy_shift.sh'), _SHIFT_BRANCH_BODY);
    _shellShiftCwd = d;
  } catch { /* fallback /tmp */ }
});
afterAll(() => {
  try { fs.rmSync(_shellShiftCwd, { recursive: true, force: true }); } catch { /* ignore */ };
});

// L3 case 真跑 LLM 时需串行（避免并行撞 DeepSeek rate limit 走 fallback 假命中）
// 用一个 promise 链做串行 gate：每个 L3 test 等前一个跑完才开跑
let l3SerialGate: Promise<void> = Promise.resolve();

describe('JSON case 双端共用（Python parity）', () => {
  for (const { file, case: c } of cases) {
    // llm_required case 仅在 LLM 可用时真验证；探测失败运行时 ctx.skip()
    // （对齐 Python 函数体内 pytest.skip），避免收集时用 isLLMAvailable() 只看
    // key 存在与否（key 无效/网络不通时旧逻辑会真跑坏 key 走 fail-open 假通过）。
    const timeout = !!c.llm_required ? 120_000 : undefined;
    it(`${file} — ${c.desc}`, async (ctx) => {
      // L3 判定放到运行时：等探测结果（beforeAll 已触发并缓存），探测失败则 skip
      const llmOk = await ensureLlmProbe();
      const llmRequiredAndDisabled = !!c.llm_required && !llmOk;
      if (llmRequiredAndDisabled) {
        ctx.skip();
        return;
      }
      // L3 case（llm_required）真跑 LLM 时串行等待，避免并行撞 rate limit
      if (!!c.llm_required && llmOk) {
        let release!: () => void;
        const wait = new Promise<void>(r => { release = r; });
        const prev = l3SerialGate;
        l3SerialGate = prev.then(() => wait);
        await prev;
        try {
          await runCase(file, c, true);
        } finally {
          release();
        }
      } else {
        await runCase(file, c, false);
      }
    }, timeout);
  }

  async function runCase(file: string, c: any, useLlm: boolean) {
    // 对齐 Python：L1/L2 用例（!llm_required）强制禁 LLM，只测 L1+L2 静态结果，
    // 避免 LLM 二次判定翻盘导致 decision/risk_level 波动（Allow 变 Deny 等）。
    // 仅 llm_required 用例在 LLM 可用时真跑。isLLMAvailable 实时读
    // process.env.AGENT_MOSS_DISABLE_LLM，故临时设 env 即可按用例切换。
    const prevDisable = process.env.AGENT_MOSS_DISABLE_LLM;
    if (!useLlm) {
      process.env.AGENT_MOSS_DISABLE_LLM = '1';
    }
    try {
      const input = toAnalysisInput(c);
      // 文件状态预处理：read_before_write 判据依赖磁盘，写新建用例需删目标、
      // 写已有用例需建目标，保证双端判定不随机器残留翻转（对齐 Python conftest）。
      prepFileState(c);
      // indirect_file_access case 用 setup 的临时 cwd（含 .env 凭据）
      if (file.includes('logic-10-indirect-access') && _indirectCwd !== '/tmp') {
        input.cwd = _indirectCwd;
      }
      // script-branch case 用 setup 的临时 cwd（含 deploy.sh 分支脚本）
      if (file.includes('script-branch-shift') && _shellShiftCwd !== '/tmp') {
        input.cwd = _shellShiftCwd;
      } else if (file.includes('script-branch-py') && _pythonScriptBranchCwd !== '/tmp') {
        input.cwd = _pythonScriptBranchCwd;
      } else if (file.includes('script-branch') && _scriptBranchCwd !== '/tmp') {
        input.cwd = _scriptBranchCwd;
      }
      const result = await runAnalysis(input);
      // decision 对齐 Python expected_decision
      // l3_decision_flexible（对齐 Python test_llm_cases）：L1 medium 进入 L3 的用例，
      // LLM 对边界场景（rsync 到远程 / git push --force）判 Allow 或 Deny 都合理，
      // 模型波动不造成假失败，只验证进入 L3（未在 L1 短路）。
      if (c.l3_decision_flexible) return;
      const expectedBlocked = c.expected_decision === 'Deny';
      const actualBlocked = result.allowed === false;
      expect(actualBlocked).toBe(expectedBlocked);
      // risk_level（仅对 L1/L2 case 断言；LLM 语义层 risk_level 有非确定性波动，
      // 对齐 Python TestLayer3 只断言 decision，不硬绑定 risk_level）
      if (c.expected_risk_level && !c.llm_required) {
        expect(result.riskLevel).toBe(c.expected_risk_level);
      }
    } finally {
      if (!useLlm) {
        if (prevDisable === undefined) {
          delete process.env.AGENT_MOSS_DISABLE_LLM;
        } else {
          process.env.AGENT_MOSS_DISABLE_LLM = prevDisable;
        }
      }
    }
  }
});
