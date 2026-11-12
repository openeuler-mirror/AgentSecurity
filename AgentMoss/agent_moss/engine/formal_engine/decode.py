"""P1 抗编码绕过：把动作文本做"解码规范化"，生成候选串集合。

用途：stage 正则匹配前，先对 action_detail 尝试常见编码形态解码（base64 字面量、
URL 编码、数值/八进制构造、反序等），再拿解码结果去匹配 CRED/EXEC/EXFIL 等 stage，
把"编码变形绕过预置范式"转为命中。

设计约束（防误报第一）：
- 只对「有明显编码痕迹」的文本下手，绝不凭空猜测。
- 解码后仅作为**候选**：仍要求候选串正中某个 stage 正则，且解码目标有安全
  语义关键词才触发，平凡文本的解码不会无端提升风险。
- 有界：最多返回有限个候选（防 DoS）；解码失败的输入原样返回 [detail]。
"""

from __future__ import annotations

import base64
import binascii
import re

from ...rules_loader import load_formal_rules
import urllib.parse

# ---------------- 解码算法 ----------------

_ENC_TRACE_RE = re.compile(
    r"(?:base64|b64|frombase64|Atob)?\s*[-_d]?\s*|"
    r"urlencode|percent|\\x[0-9a-f]{2}|\\[0-7]{3}|"
    r"chr\s*\(|String\.fromCharCode|from_char_code|"
    r"unhex|xxd\s*-p|od\s+-A\s*x|rev\s*\||`{2,}",
    re.IGNORECASE,
)


def decode_base64_literals(text: str) -> list[str]:
    """识别 base64 形态的 token 并解码。

    - 'echo c3VicHJvY2Vzcw== | base64 -d | bash' → 提取 c3VicHJvY2Vzcw== 解码出 subprocess
    - 兼容 `-d`/`-D`/Python/JS 常见用法，只对合法 base64（长度%4==0 或补齐后
      解码成功且可打印）下手。
    """
    out: list[str] = []
    # 宽匹配：base64 可见字符 + == 结尾
    for tok in re.findall(r"[A-Za-z0-9+/]+={0,2}", text):
        if len(tok) < 8:  # 过短不算
            continue
        if not (len(tok) % 4 == 0 or tok.endswith("==") or tok.endswith("=")):
            continue
        try:
            raw = base64.b64decode(tok, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            s = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            continue
        # 解码结果应可打印（非二进制乱码）
        if s and all(32 <= ord(c) < 127 for c in s):
            out.append(s)
    return out


_QUOTED_STR_RE = re.compile(r"""
    ('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|`(?:[^`\\]|\\.)*`)
""", re.VERBOSE)


# 输出类命令词：其后的引号内容是「数据」（纯文本输出），应剥离后再判阶段。
# 非输出类命令（python3 -c / bash -c / eval / exec 等）的引号内容是「要执行的代码」，
# 不可剥——否则连 os.system 等真实攻击形态一起被剥掉（漏报）。
# 注意：那是「顶层命令词」判定（命令起始 token），不是全文包含判定。
# 数据见 rules/formal_rules.json 的 output_commands（与 TS 同源）。
_OUTPUT_CMDS = frozenset(load_formal_rules().get("output_commands") or ())


def strip_string_literals(text: str) -> str:
    """仅当命令的**顶层命令词**为「输出类」（echo/printf/print/cat 等）时，剥掉引号
    包裹的字符串字面量 → 命令外壳。

    用途：防「echo / print 一段文本里提到 port scan」这类**纯字面量文本**被阶段
    正则当成真实行为。判定依据是**命令起始 token**（剥引号前先看外层命令词），
    而不是全文搜 echo/print——这避免把 `python3 -c 'print("x")'` 引号内的 print
    （那是代码）误判成输出类。

      - `echo 'checking port scan'` → 顶层 echo → 剥 → 剩 `echo `（不命中）
      - `print('known_hosts')` → 顶层 print → 剥（不命中）
      - `python3 -c 'print("port scan now")'` → 顶层 python3 → 不剥 → 原文（但这是
        执行类，引号内是代码，仍会按原文判，需配合阶段正则本身不误触、见下文）
      - `python3 -c 'import os; os.system("id")'` → 顶层 python3 → 不剥 → 命中 EXEC（不漏报）
      - `cat /etc/passwd` → 顶层 cat（真读文件）→ 剥引号无影响 → 命中 CRED
    """
    # 取第一个命令 token（容忍前导空白/重定向/环境变量前缀）
    first = re.match(r"\s*(?:[A-Za-z_][\w-]*|[\w./-]+(?:/[A-Za-z_][\w-]*)+)\b", text)
    if first and first.group(0).split("/")[-1].lower() in _OUTPUT_CMDS:
        return _QUOTED_STR_RE.sub("", text)
    return text


def decode_url_and_numeric(text: str) -> list[str]:
    """URL 解码 + 常见数值/八进制构造展开。"""
    out: list[str] = []
    # URL 编码：%XX 多次解码直至稳定
    s = text
    for _ in range(3):
        nxt = urllib.parse.unquote(s)
        if nxt == s:
            break
        s = nxt
    if s != text:
        out.append(s)
    # 八进制/hex 转义展开：\143\141\164 → cat  （printf/echo 常见）
    if "\\1" in text or "\\x6" in text or "0x63" in text.lower():
        try:
            # 八进制 \nnn
            oct_expand = re.sub(r"\\[0-7]{3}",
                                lambda m: chr(int(m.group(0)[1:], 8)), text)
            if oct_expand != text:
                out.append(oct_expand)
            # hex \xNN
            hex_expand = re.sub(r"\\x([0-9a-fA-F]{2})",
                                lambda m: chr(int(m.group(1), 16)), text)
            if hex_expand != text:
                out.append(hex_expand)
        except ValueError:
            pass
    return out


def _all_candidates(detail: str) -> list[str]:
    """产出去混淆候选串（含原始串）。

    首项为「剥引号字符串后的命令外壳」（用于 stage 匹配，防字面量误报）；
    后续为解码候选（base64/URL/数值，由外壳+原文共同解码）。
    """
    shell = strip_string_literals(detail)
    cands: list[str] = [shell]
    cands.extend(decode_base64_literals(shell))
    cands.extend(decode_url_and_numeric(shell))
    cands.extend(decode_base64_literals(detail))
    cands.extend(decode_url_and_numeric(detail))
    # 去重保序，限长防 DoS
    seen = set()
    out: list[str] = []
    for c in cands:
        ck = repr(c)
        if ck in seen or len(c) > 4096:
            continue
        seen.add(ck)
        out.append(c)
        if len(out) >= 12:
            break
    return out


# 多 stage 命中时的特异性优先序（2026-09 stage 抢占修复）：
# EXEC 不进此序（单独仲裁，见下）；其余按目的性排前——EXFIL/PRIVESC/PERSIST/
# SCAN/LISTEN 优先于 EXEC **载体类**（bash -c/python3 -c 只是执行载体，目的在
# 引号内：python3 -c 'socket listen' → LISTEN、pkexec sh -c → PRIVESC）。
# 注意 CRED 不在让位序中：bash -c 'cat /etc/shadow' 保持 EXEC（执行 shell 本身
# 就是获取执行能力，守护矩阵权威期望）。修复真实案例：
# 「编辑 Flask 文件加 subprocess shell=True /exec 后门」同时命中 LISTEN（flask 词）
# 与 EXEC（subprocess/shell=True），旧版按字典序 LISTEN 抢占 → 时间线标 LISTEN，
# listener-exec-scan 链的 EXEC 环节永久缺失 → 组合链漏报。
_STAGE_PRIORITY = ("EXFIL", "PRIVESC", "PERSIST", "SCAN", "LISTEN")
# EXEC 不进固定优先序，单独仲裁——EXEC 正则分两类：
#   目的类（subprocess/os.system/shell=True/eval/exec）：动作本身就是获取执行能力
#     → 特异性最高，覆盖 flask/fastapi 等内容噪声（目标修复案例）
#   载体类（python3 -c / bash -c / sh -c / perl -e / node -e）：只是执行载体，
#     目的语义在引号内/参数里（如 python3 -c 'socket bind listen'、pkexec sh -c）
#     → 载体让位给同时命中的其他 stage（守护矩阵用例：socket listen 应标 LISTEN、
#       pkexec sh -c 应标 PRIVESC）
_PURPOSE_EXEC_RE = re.compile(
    r"subprocess\.\w+\s*\(|os\.system\s*\(|shell\s*=\s*True|\beval\s*\(|\bexec\s*\(|os\.popen\s*\(|/exec\b",
    re.IGNORECASE,
)
# 起服务顶层形态：nohup/http.server/flask run/nc -l/socat 主导时 LISTEN 特异性更高
# （起服务命令的注释/参数里提到 subprocess 等执行词不应把「起服务」标成 EXEC）
_LISTEN_LEAD_RE = re.compile(r"http\.server|flask\s+run|nohup\b|nc\s+-l|socat\s+TCP-LISTEN", re.IGNORECASE)
_LISTEN_NOISE_RE = re.compile(
    r"shell\s*=\s*True|os\.system|subprocess\.(?:run|call|Popen)|\beval\s*\(|\bexec\s*\(",
    re.IGNORECASE,
)


def match_stage_any(detail: str, combo_stages: dict[str, list[any]]) -> str:
    """对「命令外壳 + 解码候选」做 stage 匹配（P1 核心）。

    返回命中的 stage 名（空 = 未命中）。

    防字面量误报：优先匹配「剥掉引号字符串后的命令外壳」。引号通常只包
    **参数值**（print('port scan now') 的文本、URL、路径），命令名/工具调用
    （nmap、nc -z、curl、http.server、subprocess、os.system）在外壳上保留，
    因此真攻击形态不变、仍能命中；纯字面量文本（print("recruit scan")）
    被剥掉，不再误判阶段。解码候选仅由外壳派生，继续兜底编码绕过。

    多命中仲裁（2026-09）：外壳同时命中多个 stage 时——
    1. EXEC 目的类命中（subprocess/shell=True/os.system/eval/exec）→ EXEC 胜出
       （覆盖 flask 等内容噪声，修「编辑 Flask 文件加 shell=True 后门被标 LISTEN」漏报）；
    2. 起服务顶层形态（nohup/http.server/flask run/nc -l）主导且无目的类执行词
       → LISTEN 胜出（起服务命令注释里提到 subprocess 不改标）；
    3. 其余按 _STAGE_PRIORITY 取第一个（EXEC 载体类让位给目的性 stage：
       python3 -c 'socket listen' → LISTEN、pkexec sh -c → PRIVESC）。
    解码候选仍按旧序逐个匹配（编码绕过兜底语义不变）。
    """
    cands = _all_candidates(detail)
    if not cands:
        return ""

    # 外壳上的多命中收集
    shell = cands[0]
    hits: list[str] = []
    for name, pats in combo_stages.items():
        for p in pats:
            if p.search(shell):
                hits.append(name)
                break

    if hits:
        if len(hits) == 1:
            return hits[0]
        # 1. EXEC 目的类命中 → EXEC 胜出（获取执行能力是主语义）
        if "EXEC" in hits and _PURPOSE_EXEC_RE.search(shell):
            return "EXEC"
        # 2. 起服务顶层形态豁免：LISTEN 主导且无目的类执行词 → 保持 LISTEN
        if "LISTEN" in hits and _LISTEN_LEAD_RE.search(shell) and not _LISTEN_NOISE_RE.search(shell):
            return "LISTEN"
        # 3. 其余按优先序（EXEC 载体类让位）
        for s in _STAGE_PRIORITY:
            if s in hits:
                return s
        # 只剩 EXEC（载体类）→ 标 EXEC
        return "EXEC"

    # 解码候选逐个匹配（编码绕过兜底，语义与旧版一致）
    for cand in cands[1:]:
        for name, pats in combo_stages.items():
            for p in pats:
                if p.search(cand):
                    return name
    return ""