/**
 * P1 抗编码绕过：把动作文本做解码规范化，生成候选串（镜像 Python decode.py）。
 *
 * stage 正则匹配前先对 action_detail 尝试 base64 / URL 编码 / 八进制构造等
 * 常见变形，再拿解码候选去匹配 CRED/EXEC/EXFIL stage，把"编码绕过预置范式"
 * 转为命中。防误报第一：只对明显编码痕迹下手，解码失败原样返回。
 */

// ---------- base64 字面量 ----------
const B64_TOKEN_RE = /[A-Za-z0-9+/]+={0,2}/g;

function isValidBase64Token(tok: string): boolean {
  if (tok.length < 8) return false;
  // 长度须为 4 的倍数，或 == / = 结尾
  if (!(tok.length % 4 === 0 || tok.endsWith('==') || tok.endsWith('='))) return false;
  return true;
}

function isPrintable(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 32 || c > 126) return false;
  }
  return true;
}

export function decodeBase64Literals(text: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const m of text.matchAll(B64_TOKEN_RE)) {
    const tok = m[0];
    if (!isValidBase64Token(tok)) continue;
    // 纯 token 须有 base64 特征：同时含大小写和数字更可信；过短跳过
    if (!/[A-Z]/.test(tok) || !/[a-z]/.test(tok)) continue;
    try {
      // 补齐 padding 再解码
      const padded = tok + '='.repeat((4 - (tok.length % 4)) % 4);
      const bin = Buffer.from(padded, 'base64');
      const s = bin.toString('utf8');
      if (s && isPrintable(s) && !seen.has(s)) {
        seen.add(s);
        out.push(s);
      }
    } catch {
      // ignore
    }
  }
  return out;
}

// ---------- 剥离字符串字面量（防 print/echo 文本误报阶段） ----------
const QUOTED_STR_RE = /('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|`(?:[^`\\]|\\.)*`)/g;

/** 输出类命令词：顶层命令是它们时，引号内是「数据」可剥；否则是「代码」不剥。 */
const OUTPUT_CMDS = new Set(['echo', 'printf', 'print']); // 只剥纯输出；grep/cat 等查询类引号内是搜索词（有安全语义），不剥

/** 仅当命令起始 token 是输出类命令时，剥离引号字符串 → 命令外壳。 */
export function stripStringLiterals(text: string): string {
  const m = text.match(/\s*([A-Za-z_][\w-]*|\/?[\w./-]+)\b/);
  if (!m) return text;
  const cmd = m[1].split('/').pop()!.toLowerCase();
  if (!OUTPUT_CMDS.has(cmd)) return text;
  return text.replace(QUOTED_STR_RE, '');
}

// ---------- URL / 数值构造 ----------
export function decodeUrlAndNumeric(text: string): string[] {
  const out: string[] = [];

  // URL 解码多次直至稳定
  let s = text;
  for (let i = 0; i < 3; i++) {
    let nxt = s;
    try {
      nxt = decodeURIComponent(s);
    } catch {
      break;
    }
    if (nxt === s) break;
    s = nxt;
  }
  if (s !== text) out.push(s);

  // 八进制 \nnn 展开（printf 常见）
  if (/\\[0-7]{3}/.test(text)) {
    let expanded = '';
    try {
      expanded = text.replace(/\\[0-7]{3}/g, m => String.fromCharCode(parseInt(m.slice(1), 8)));
    } catch { /* ignore */ }
    if (expanded && expanded !== text) out.push(expanded);
  }
  // hex \xNN 展开
  if (/\\x[0-9a-fA-F]{2}/.test(text)) {
    let expanded = '';
    try {
      expanded = text.replace(/\\x[0-9a-fA-F]{2}/g, m => String.fromCharCode(parseInt(m.slice(2), 16)));
    } catch { /* ignore */ }
    if (expanded && expanded !== text) out.push(expanded);
  }

  return out;
}

// ---------- 统一入口 ----------
export function allCandidates(detail: string, max = 8): string[] {
  const shell = stripStringLiterals(detail);
  const cands: string[] = [shell];
  cands.push(...decodeBase64Literals(shell));
  cands.push(...decodeUrlAndNumeric(shell));
  cands.push(...decodeBase64Literals(detail));
  cands.push(...decodeUrlAndNumeric(detail));
  const seen = new Set<string>();
  const out: string[] = [];
  for (const c of cands) {
    if (seen.has(c) || c.length > 4096) continue;
    seen.add(c);
    out.push(c);
    if (out.length >= max) break;
  }
  return out;
}

// 多 stage 命中时的特异性优先序（2026-09 stage 抢占修复，镜像 Python decode.py）：
// EXEC 不进此序（单独仲裁，见下）；其余按目的性排前——EXFIL/PRIVESC/PERSIST/
// SCAN/LISTEN 优先于 EXEC **载体类**（bash -c/python3 -c 只是执行载体，目的在
// 引号内：python3 -c 'socket listen' → LISTEN、pkexec sh -c → PRIVESC）。
// 注意 CRED 不在让位序中：bash -c 'cat /etc/shadow' 保持 EXEC（执行 shell 本身
// 就是获取执行能力，守护矩阵权威期望）。修复真实案例：
// 「编辑 Flask 文件加 subprocess shell=True /exec 后门」同时命中 LISTEN（flask 词）
// 与 EXEC（subprocess/shell=True），旧版按字典序 LISTEN 抢占 → 时间线标 LISTEN，
// listener-exec-scan 链的 EXEC 环节永久缺失 → 组合链漏报。
const STAGE_PRIORITY = ['EXFIL', 'PRIVESC', 'PERSIST', 'SCAN', 'LISTEN'];
// EXEC 目的类（调用形态）：动作本身就是获取执行能力 → 特异性最高，覆盖
// flask/fastapi 等内容噪声（目标修复案例）。裸词 "uses subprocess"（注释）不算。
const PURPOSE_EXEC_RE =
  /subprocess\.\w+\s*\(|os\.system\s*\(|shell\s*=\s*True|\beval\s*\(|\bexec\s*\(|os\.popen\s*\(|\/exec\b/i;
// 起服务顶层形态：nohup/http.server/flask run/nc -l/socat 主导时 LISTEN 特异性更高
const LISTEN_LEAD_RE = /http\.server|flask\s+run|nohup\b|nc\s+-l|socat\s+TCP-LISTEN/i;
const LISTEN_NOISE_RE =
  /shell\s*=\s*True|os\.system|subprocess\.(?:run|call|Popen)|\beval\s*\(|\bexec\s*\(/i;

/** 对原始 + 解码候选一起做 stage 匹配（P1 核心）。返回命中的 stage（空 = 未命中）。
 *
 * 多命中仲裁（2026-09，镜像 Python match_stage_any）：
 * 1. EXEC 目的类命中（subprocess.run(/shell=True/os.system(/eval/exec）→ EXEC 胜出；
 * 2. 起服务顶层形态主导且无目的类执行词 → LISTEN 胜出；
 * 3. 其余按 STAGE_PRIORITY 取第一个（EXEC 载体类让位；CRED 不让位 EXEC 载体）。
 */
export function matchStageAny(
  detail: string,
  stages: Record<string, RegExp[]>,
): string {
  const cands = allCandidates(detail);
  if (cands.length === 0) return '';

  // 外壳上的多命中收集
  const shell = cands[0];
  const hits: string[] = [];
  for (const [name, pats] of Object.entries(stages)) {
    for (const p of pats) {
      p.lastIndex = 0;
      if (p.test(shell)) {
        hits.push(name);
        break;
      }
    }
  }

  if (hits.length > 0) {
    if (hits.length === 1) return hits[0];
    // 1. EXEC 目的类命中 → EXEC 胜出
    if (hits.includes('EXEC') && PURPOSE_EXEC_RE.test(shell)) return 'EXEC';
    // 2. 起服务顶层形态豁免：LISTEN 主导且无目的类执行词 → 保持 LISTEN
    if (hits.includes('LISTEN') && LISTEN_LEAD_RE.test(shell) && !LISTEN_NOISE_RE.test(shell)) {
      return 'LISTEN';
    }
    // 3. 其余按优先序（EXEC 载体类让位；CRED 不让位 EXEC 载体）
    for (const s of STAGE_PRIORITY) {
      if (hits.includes(s)) return s;
    }
    if (hits.includes('EXEC')) return 'EXEC';
  }

  // 解码候选逐个匹配（编码绕过兜底，语义与旧版一致）
  for (const cand of cands.slice(1)) {
    for (const [name, pats] of Object.entries(stages)) {
      for (const p of pats) {
        p.lastIndex = 0;
        if (p.test(cand)) return name;
      }
    }
  }
  return '';
}