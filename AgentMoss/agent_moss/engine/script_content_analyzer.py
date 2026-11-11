"""脚本内容分析器 — 递归追踪 + 预处理 + L1/L2 静态扫描

核心改造（相比旧版 script_analyzer.py）：
1. 预处理流水线：去注释 → 去 echo 文本 → 简单变量展开，消除常见误报
2. 扩展脚本路径提取：去掉 .sh 后缀限制，增加 Python/Node/Ruby 等解释器
3. 去掉行数限制改用文件大小限制：完整读取文件内容再扫描（实测开销毫秒级）
4. 递归追踪：A.sh → B.sh → C.sh 的嵌套调用也能拦截
5. L1/L2 复用扫描：脚本内容经过预处理后，复用现有 CommandPatternScanner
   和 LogicRulesChecker 做静态扫描，high/critical 直接拦截，不走 L3

性能预算（实测数据）：
  - 10000 行 (~600KB) 读取+扫描: 43ms
  - 50000 行 (~2MB)  读取+扫描: 123ms
  - 3 层递归 (3 个普通脚本): 预计 ~5-10ms
  - vs L3 LLM 调用: 2-10s + 数千 token

与 audit_agent 的差异：CommandPatternScanner 在 AgentMoss 中是 OS Profile 驱动的
（构造需要 profile），因此本模块不内部构造扫描器，而是由调用方（coordinator）
把 HeuristicDetector 的 CommandPatternScanner 实例注入进来。
"""

import logging
import re
import shlex
from pathlib import Path
from typing import TYPE_CHECKING

from ..rules_loader import compile_rule_regex, load_script_rules, resolve_keyword_set
from .types import ScriptNode, ScriptChainAnalysisResult

if TYPE_CHECKING:
    from ..profiles.base import OSProfile

logger = logging.getLogger(__name__)

# 脚本分析词表：单一事实源 rules/script_rules.json（Python/TS 四份副本收拢成一份）。
# 模块导入时读一次 —— 与迁移前的硬编码常量行为一致（进程内不变，改 JSON 需重启）。
# ⚠️ 缺失/损坏 → 词表为空，脚本关键词扫描一条都不命中（更松），故必须报错。
_SCRIPT_RULES = load_script_rules()
if not _SCRIPT_RULES:
    logger.error(
        "规则文件 script_rules.json 缺失或损坏 —— 脚本内容关键词扫描将不命中任何模式"
        "（比正常更松）。请检查包完整性。"
    )


# ==================== 高风险检测规则（关键词扫描，兼容 L3） ====================
# 仅保留误报率极低、几乎必然指示恶意行为的模式。数据见 rules/script_rules.json。

SUSPICIOUS_PATTERNS: list[tuple[str, re.Pattern]] = [
    (str(r["name"]), compile_rule_regex(r))
    for r in (_SCRIPT_RULES.get("suspicious_patterns") or [])
]


# ==================== 脚本执行模式匹配 ====================
# 入口命令的脚本路径提取（从 action_detail 提取）

# 数据见 rules/script_rules.json 的 script_exec_patterns.chain（13 条，识别解释器 +
# 任意后缀，供递归追踪）。注意 legacy 那份只认 .sh，两份不可互换。
SCRIPT_EXEC_PATTERNS: list[str] = [
    str(p["pattern"])
    for p in ((_SCRIPT_RULES.get("script_exec_patterns") or {}).get("chain") or [])
]

_SCRIPT_EXEC_COMPILED = [
    compile_rule_regex(p)
    for p in ((_SCRIPT_RULES.get("script_exec_patterns") or {}).get("chain") or [])
]


# ==================== 关键词组合风险评估规则 ====================

# 组合放大规则：group1/group2 里以 `$` 开头的是对 keyword_sets 的引用
# （如 `$network_post`），免得同一组词写两遍。数据见 rules/script_rules.json。
_KEYWORD_SETS: dict[str, list[str]] = dict(_SCRIPT_RULES.get("keyword_sets") or {})

KEYWORD_COMBINATION_RISKS: list[tuple[set[str], set[str], str, str]] = [
    (
        resolve_keyword_set(r.get("group1"), _KEYWORD_SETS),
        resolve_keyword_set(r.get("group2"), _KEYWORD_SETS),
        str(r["level"]),
        str(r["reason"]),
    )
    for r in (_SCRIPT_RULES.get("keyword_combination_risks") or [])
]

SINGLE_KEYWORD_RISKS: dict[str, tuple[str, str]] = {
    str(k): (str(v["level"]), str(v["reason"]))
    for k, v in (_SCRIPT_RULES.get("single_keyword_risks") or {}).items()
}

_RISK_PRIORITY = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def scan_script_for_keywords(script_content: str) -> list[str]:
    """扫描脚本内容中的高风险模式。"""
    matched = []
    for name, pattern in SUSPICIOUS_PATTERNS:
        if pattern.search(script_content):
            matched.append(name)
    return matched


def assess_keyword_combination_risk(
    matched_keywords: list[str], script_content: str
) -> tuple[str, str]:
    """根据命中的关键词组合评估风险等级。"""
    if not matched_keywords:
        return "", ""

    keyword_set = set(matched_keywords)

    for group1, group2, level, reason in KEYWORD_COMBINATION_RISKS:
        hit_group1 = bool(keyword_set & group1)
        hit_group2 = bool(keyword_set & group2) if group2 else True
        if hit_group1 and hit_group2:
            return level, reason

    has_network_post = bool(keyword_set & set(_KEYWORD_SETS.get("network_post") or []))
    if has_network_post:
        env_patterns = [str(p) for p in (_SCRIPT_RULES.get("env_exfil_patterns") or [])]
        content_lower = script_content.lower()
        for pattern in env_patterns:
            if pattern.lower() in content_lower:
                return "critical", (
                    "检测到网络数据发送 + 系统环境变量收集组合，构成 Critical 级别数据外传风险。"
                    "脚本可能将用户环境变量（可能包含 API Key、密钥等敏感信息）发送到远程服务器。"
                )

    best_level = ""
    best_reason = ""
    for kw in matched_keywords:
        if kw in SINGLE_KEYWORD_RISKS:
            level, reason = SINGLE_KEYWORD_RISKS[kw]
            if _RISK_PRIORITY.get(level, 0) > _RISK_PRIORITY.get(best_level, 0):
                best_level = level
                best_reason = reason
    return best_level, best_reason


# ==================== 脚本路径提取 ====================


def extract_script_path(command: str) -> str | None:
    """从 bash 命令中提取脚本路径。

    ⚠️ 必须剥掉包裹引号：`bash "/root/s.sh"` 的捕获组带引号，直接当路径用会变成
    **相对路径**（`"/root/s.sh"` 不以 / 开头），后续按 cwd 拼成 `/root/"/root/s.sh"`
    这种怪物路径 → 文件系统探测抛异常 → fail-closed。TS 侧一直有剥引号
    （`tok.replace(/^['"]|['"]$/g, '')`），Python 漏了。
    """
    for compiled in _SCRIPT_EXEC_COMPILED:
        match = compiled.search(command)
        if match:
            return match.group(1).strip().strip("'\"")
    return None


def _is_existing_file(path) -> bool:
    """该路径是否存在且是文件。**任何文件系统异常一律当"不是"**。

    ⚠️ Python 3.12 的 ``Path.exists()`` / ``is_file()`` 在**父目录不可读**时会抛
    ``PermissionError``（不是返回 False，``os.path.exists`` 才是返回 False）。
    不设防的话异常会一路上抛 → 外层 fail-closed → 同一条命令的判定**随 cwd/
    文件权限变化**且不可复现（实测 ``cat "/etc/./shadow"`` 在 cwd=/root 时 Deny、
    换 cwd 就 Allow，差异纯粹来自这里探测 `/root/...` 时抛不抛异常）。
    路径探测只是"这个词像不像脚本文件"的辅助判断，探测失败按"不是"处理最合理。
    """
    try:
        p = Path(path).expanduser().resolve()
        return p.exists() and p.is_file()
    except OSError:
        return False

def extract_script_path_with_args(command: str) -> tuple[str | None, list[str]]:
    """从 bash 命令中同时提取脚本路径和其后的位置参数/选项。

    例如:
      "bash deploy.sh clean"            → (deploy.sh, ["clean"])
      "bash deploy.sh --env prod"       → (deploy.sh, ["--env", "prod"])
      "bash deploy.sh"                  → (deploy.sh, [])
      "./run.sh backup"                 → (run.sh, ["backup"])

    参数提取基于语法切分：脚本路径后的 token 视为脚本参数（含引号剥除）。
    只识别无引号与单/双引号包裹的简单 token；命令替换/子 shell/重定向不做
    深度解析（那些场景走 fail-closed 全文本扫描）。

    内联命令形态 `bash -c '...'` / `sh -c '...'` / `zsh -c '...'`：
    -c 是选项不是脚本路径（旧实现会把它误当脚本路径 → 追踪 -c 文件失败 →
    L1.2 静默跳过，漏掉内联命令串里引用的真实脚本）。这里改为解析 -c 后的
    命令串，从其中递归提取真实脚本路径。
    """
    # 内联命令形态：-c 后跟引号命令串，从命令串里找真实脚本
    m_inline = re.search(
        r"(?:^|\s|&&|\|\|)\s*(?:bash|/bin/bash|sh|zsh)\s+-c\s*"
        r"([\"'])(.*?)\1",
        command, re.IGNORECASE | re.DOTALL,
    )
    if m_inline:
        inner = m_inline.group(2)
        real_path = extract_script_path(inner)
        if real_path:
            return real_path, []
        return None, []  # -c 命令串里无脚本文件 → 不追踪（交给 L1 文本扫描）

    script_path = extract_script_path(command)
    if not script_path:
        return None, []

    # 定位脚本路径在命令中的位置，取其后的剩余部分作为参数串
    idx = command.find(script_path)
    if idx < 0:
        return script_path, []
    rest = command[idx + len(script_path):]
    # 剥掉管道/重定向/分号（这些不是脚本参数，是命令连接符）
    rest = re.split(r'[;|&<>]', rest)[0].strip()
    tokens = re.findall(
        r'(["\'])(.*?)\1|(\S+)',
        rest,
    )
    args: list[str] = []
    for quoted, q_content, bare in tokens:
        args.append(q_content if quoted else bare)
    return script_path, args


def _extract_inline_script_path(action_detail: str) -> str | None:
    """从内联脚本命令中尝试提取引用的文件路径。

    例如: python3 -c "exec(open('evil.py').read())" → 尝试提取 evil.py

    盲区修复：内联代码里「执行某个 .sh 脚本」的形态也提取脚本路径，交给脚本
    引擎递归扫描——否则 `python3 -c "os.system('bash /tmp/evil.sh')"` 里 evil.sh
    的内容（如 rm -rf /etc）完全失明（此前 inline_analyzer 只对那一行代码做正则，
    不打开引用的脚本文件）。
    """
    # 1. 提取内联代码内容（python -c "..." 的引号内代码）
    from .inline_analyzer import _extract_inline_code
    code = _extract_inline_code(action_detail)
    if not code:
        return None

    # 2. 解析「执行脚本」形态，提取脚本文件路径：
    #    - os.system('bash /tmp/x.sh') / os.popen("sh ./x.sh")
    #    - subprocess.run(['bash', '/tmp/x.sh']) / subprocess.call(["bash","x.sh"])
    #    - os.system("xxx.sh 参数")（直接执行脚本）
    #    保守：只在「出现了 shell/bash/sh/zsh/python 解释器 + 脚本文件」或
    #    「明显 .sh/.py/.pl 脚本路径」时提取，避免把 print('bash x.sh') 字面量误当执行。
    candidates: list[str] = []
    # os.system / os.popen / commands.getoutput 等：括起来自后再用 shlex 拆
    for m in re.finditer(
        r"""os\.(?:system|popen)\s*\(\s*(['"])(.*?)\1\s*\)""",
        code,
        re.DOTALL | re.IGNORECASE,
    ):
        candidates.append(m.group(2))
    # subprocess.run/call/Popen 的列表形态：['bash', '/tmp/x.sh'] 或 ["sh", "x.sh"]
    for m in re.finditer(
        r"""subprocess\.(?:run|call|Popen|check_output|check_call)\s*\(\s*\[(.*?)\]""",
        code,
        re.DOTALL | re.IGNORECASE,
    ):
        candidates.append(m.group(1))
    # subprocess 的字符串形态 + shell=True：subprocess.run("bash x.sh", shell=True)
    for m in re.finditer(
        r"""subprocess\.(?:run|call|Popen|check_output|check_call)\s*\(\s*(['"])(.*?)\1[^)]*?shell\s*=\s*true""",
        code,
        re.DOTALL | re.IGNORECASE,
    ):
        candidates.append(m.group(2))

    for cand in candidates:
        # 列表形态 ['bash','/tmp/x.sh'] 先按逗号/空白切成独立 token，
        # 字符串形态 "bash /tmp/x.sh" 用 shlex 拆。两者都要找「脚本文件」token。
        if "," in cand:
            raw_tokens = re.split(r"\s*,\s*", cand)
            tokens = [t.strip().strip("'\"") for t in raw_tokens]
        else:
            tokens = shlex.split(cand) if cand else []
        for tok in tokens:
            if _looks_like_script_path(tok):
                if _is_existing_file(tok):
                    return str(Path(tok).expanduser().resolve())
        # 字符串形态：整个 cand 若是单个脚本路径（无解释器前缀）
        if not tokens and _looks_like_script_path(cand.strip()):
            if _is_existing_file(cand.strip()):
                return str(Path(cand.strip()).expanduser().resolve())

    # 3. 兜底：open('x.py').read() 形态（原有逻辑）
    for m in re.finditer(r"""open\s*\(\s*['"]([^'"]+)['"]\s*\)""", code):
        path = m.group(1)
        if _is_existing_file(path):
            return str(Path(path).expanduser().resolve())
    return None


def _looks_like_script_path(tok: str) -> bool:
    """判断一个 token 是否像脚本文件路径（.sh/.py/.pl/.bash 等脚本后缀，或含 / 的路径）。

    排除 python/bash/sh 等解释器名本身，避免把['bash','/tmp/x.sh']里的 'bash' 当脚本。
    """
    tok = tok.strip().strip("'\",")
    if not tok:
        return False
    low = tok.lower()
    if low in ("bash", "sh", "zsh", "dash", "python", "python3", "perl", "ruby", "node", "php", "lua"):
        return False
    if low.endswith((".sh", ".bash", ".py", ".pl", ".rb", ".js", ".php", ".lua")):
        return True
    # 含路径分隔符且不以 - 开头（排除 -c 等选项）
    if "/" in tok and not tok.startswith("-"):
        return True
    return False


# ==================== 脚本内容读取 ====================


def read_script_content(
    script_path: str,
    max_file_size: int = 2 * 1024 * 1024,
) -> tuple[str, int, int, str]:
    """读取脚本内容，限制文件大小而非行数。

    Returns:
        tuple[str, int, int, str]: (内容, 行数, 文件大小bytes, 错误信息)
    """
    try:
        path = Path(script_path).expanduser().resolve()
        if not path.exists():
            return "", 0, 0, f"脚本不存在: {script_path}"
        if not path.is_file():
            return "", 0, 0, f"不是文件: {script_path}"

        file_size = path.stat().st_size
        if file_size > max_file_size:
            logger.warning(
                "脚本文件过大 (%d bytes > %d bytes)，跳过读取: %s",
                file_size, max_file_size, script_path,
            )
            return "", 0, file_size, f"脚本文件过大 ({file_size} bytes)，跳过读取"

        content = path.read_text(encoding="utf-8", errors="ignore")
        line_count = content.count('\n') + 1 if content else 0
        return content, line_count, file_size, ""

    except Exception as e:
        return "", 0, 0, f"读取脚本失败: {e}"


# ==================== 递归追踪 ====================



# ==================== L1/L2 复用扫描 ====================


def scan_script_chain_with_l1(
    chain_result: ScriptChainAnalysisResult,
    command_scanner,
) -> ScriptChainAnalysisResult:
    """对脚本调用链中每个节点的预处理内容做 L1 CommandPatternScanner 扫描。

    跳过：错误节点、无内容节点、递归过程中已内联扫描的命中节点（避免重复扫描）。
    """
    for node in chain_result.nodes:
        if node.error or not node.preprocessed_content or node.l1_hit:
            continue

        l1_result = command_scanner.scan(node.preprocessed_content)
        if l1_result.hit:
            node.l1_hit = True
            node.l1_risk_level = l1_result.risk_level
            node.l1_risk_type = l1_result.risk_type
            node.l1_reason = l1_result.reason
            node.l1_matched_patterns = l1_result.matched_patterns

            logger.info(
                "脚本内容 L1 扫描命中: path=%s, depth=%d, risk_level=%s, reason=%s",
                node.script_path, node.depth, node.l1_risk_level, node.l1_reason,
            )

            if l1_result.risk_level == "critical":
                chain_result.has_critical = True
                chain_result.first_hit_node = node
                break

    return chain_result


def scan_script_chain_with_l2(
    chain_result: ScriptChainAnalysisResult,
    logic_checker,
    prompt_session: str,
) -> ScriptChainAnalysisResult:
    """对脚本调用链中每个节点的预处理内容做 L2 规则扫描。

    只复用以下 L2 规则（不依赖 action_history）：
    - sensitive_path_access — 敏感路径访问检测
    - dangerous_patterns — 危险操作模式检测
    - intent_consistency — 意图偏离检测（用 prompt_session）

    不复用（依赖 action_history）：read_before_write / password_modify_consent /
    user_deletion_consent
    """
    for node in chain_result.nodes:
        if node.error or not node.preprocessed_content:
            continue
        if node.l1_risk_level == "critical":
            break

        virtual_a_next = {
            "action_type": "bash",
            "action_detail": node.preprocessed_content,
        }

        path_result = logic_checker._check_sensitive_path_access(virtual_a_next)
        if path_result.hit:
            node.l2_hit = True
            node.l2_violated_rule = f"script_sensitive_path:{node.script_path}"
            node.l2_risk_level = path_result.risk_level
            node.l2_risk_type = path_result.risk_type
            node.l2_reason = f"脚本 {node.script_path} (深度 {node.depth}) 中: {path_result.reason}"

            logger.info(
                "脚本内容 L2 敏感路径命中: path=%s, depth=%d, risk_level=%s",
                node.script_path, node.depth, node.l2_risk_level,
            )

            if path_result.risk_level == "critical":
                chain_result.has_critical = True
                chain_result.first_hit_node = node
                break
            continue

        dangerous_result = logic_checker._check_dangerous_patterns(virtual_a_next)
        if dangerous_result.hit:
            node.l2_hit = True
            node.l2_violated_rule = f"script_dangerous_pattern:{node.script_path}"
            node.l2_risk_level = dangerous_result.risk_level
            node.l2_risk_type = dangerous_result.risk_type
            node.l2_reason = f"脚本 {node.script_path} (深度 {node.depth}) 中: {dangerous_result.reason}"

            logger.info(
                "脚本内容 L2 危险模式命中: path=%s, depth=%d, risk_level=%s",
                node.script_path, node.depth, node.l2_risk_level,
            )

            if dangerous_result.risk_level == "critical":
                chain_result.has_critical = True
                chain_result.first_hit_node = node
                break
            continue

        if prompt_session and prompt_session.strip():
            intent_result = logic_checker._check_intent_consistency(
                prompt_session, virtual_a_next
            )
            if intent_result.hit:
                node.l2_hit = True
                node.l2_violated_rule = f"script_intent_deviation:{node.script_path}"
                node.l2_risk_level = intent_result.risk_level
                node.l2_risk_type = intent_result.risk_type
                node.l2_reason = f"脚本 {node.script_path} (深度 {node.depth}) 中意图偏离: {intent_result.reason}"

                logger.info(
                    "脚本内容 L2 意图偏离命中: path=%s, depth=%d, reason=%s",
                    node.script_path, node.depth, node.l2_reason,
                )

    if not chain_result.has_high:
        chain_result.has_high = any(
            n.l2_risk_level in ("high", "critical") for n in chain_result.nodes
        )

    return chain_result


def scan_script_chain_keywords(
    chain_result: ScriptChainAnalysisResult,
) -> ScriptChainAnalysisResult:
    """对调用链中每个节点做 SUSPICIOUS_PATTERNS 关键词扫描（兼容 L3 流程）。

    只对预处理后的内容做关键词扫描，且只扫描 L1/L2 未命中的节点。
    """
    for node in chain_result.nodes:
        if node.error or not node.preprocessed_content:
            continue
        if node.l1_hit or node.l2_hit:
            continue

        matched = scan_script_for_keywords(node.preprocessed_content)
        node.matched_keywords = matched
        node.is_suspicious = bool(matched)

        if matched:
            risk_level, risk_reason = assess_keyword_combination_risk(
                matched, node.preprocessed_content
            )
            node.keyword_risk_level = risk_level
            node.keyword_risk_reason = risk_reason

            logger.info(
                "脚本关键词命中: path=%s, depth=%d, keywords=%s, risk_level=%s",
                node.script_path, node.depth, matched, risk_level,
            )

    return chain_result


# ==================== 入口函数 ====================


def analyze_script_content(
    action_type: str,
    action_detail: str,
    command_scanner=None,
    cwd: str = "",
) -> ScriptChainAnalysisResult:
    """分析脚本内容（递归追踪 + 预处理 + L1/L2 扫描）。

    只在 action_type 为 bash 且命令中包含脚本执行时才进行分析。

    流程：
    1. 提取脚本路径
    2. 递归追踪读取调用链（传入 command_scanner，递归过程中即时做 L1 扫描）
    3. L1 CommandPatternScanner 兜底扫描预处理内容
    4. 关键词扫描（兼容 L3）
    5. 返回 ScriptChainAnalysisResult

    Args:
        action_type: 动作类型
        action_detail: 动作详情（命令）
        command_scanner: CommandPatternScanner 实例（AgentMoss 中 OS Profile 驱动，
            由 coordinator 注入）。为 None 时跳过 L1 扫描（仅做关键词扫描）。

    Returns:
        ScriptChainAnalysisResult: 调用链完整分析结果
    """
    if action_type.lower() != "bash":
        return ScriptChainAnalysisResult()

    script_path, script_args = extract_script_path_with_args(action_detail)
    # 内联脚本路径（open('evil.py') 形态）无位置参数
    is_inline = False
    if not script_path:
        inline_path = _extract_inline_script_path(action_detail)
        if not inline_path:
            return ScriptChainAnalysisResult()
        script_path = inline_path
        is_inline = True

    logger.info("检测到脚本执行，启动递归追踪(engine): %s (args=%s)", script_path, script_args)

    # ===== 脚本分析引擎（独立引擎层） =====
    # RecursiveTracker 消费 ShellBackend 的 IR：case/if 控制流切片 + 子脚本
    # 调用参数传递（修复子调用参数丢失 + 深层链漏追踪）。
    from .script_engine.tracker import RecursiveTracker
    tracker = RecursiveTracker(command_scanner=command_scanner)
    chain_result = tracker.track(
        entry_path=script_path,
        entry_args=None if is_inline else script_args,
        cwd=cwd,
    )

    if not chain_result.nodes:
        return chain_result

    # L1 兜底扫描：递归过程中已内联扫描的命中节点（l1_hit）跳过，其余补扫
    if command_scanner is not None:
        scan_script_chain_with_l1(chain_result, command_scanner)

    # 关键词扫描（兼容 L3）
    scan_script_chain_keywords(chain_result)

    return chain_result


# ==================== L3 prompt 格式化 ====================


def format_script_chain_for_prompt(chain_result: ScriptChainAnalysisResult) -> str:
    """将脚本调用链分析结果格式化为 LLM prompt 可用的文本。

    - L1/L2 已命中的节点不会走到 L3（在 coordinator 中直接 Deny），不在此展示。
    - 有可疑信号（关键词命中但 L1/L2 未拦截）的节点：输出可疑内容供 L3 深度判断。
    - 全部节点均无危险/可疑信号（即"安全脚本"）：输出"已分析、未发现危险"明确结论
      + 内容预览，给 LLM 一个判 Allow 的依据。
    """
    if not chain_result.nodes:
        return ""

    error_nodes = [n for n in chain_result.nodes if n.error]
    if error_nodes and len(chain_result.nodes) == 1:
        return f"⚠️ 脚本内容分析失败: {error_nodes[0].error}"

    suspicious_nodes = [
        n for n in chain_result.nodes
        if n.is_suspicious and not n.l1_hit and not n.l2_hit
    ]
    if not suspicious_nodes:
        safe_nodes = [n for n in chain_result.nodes if not n.error]
        if not safe_nodes:
            return ""
        parts = ["✓ 脚本内容已分析，未发现危险/可疑操作（L1/L2/关键词扫描均未命中）："]
        for node in safe_nodes:
            preview = (node.preprocessed_content or "")[:600]
            if len(node.preprocessed_content or "") > 600:
                preview += "\n... (截断，完整内容 {} 字符)".format(
                    len(node.preprocessed_content or ""))
            parts.append(
                f"   脚本路径: {node.script_path}（递归深度 {node.depth}，{node.line_count} 行）"
                f"\n   内容（预处理后）:\n```\n{preview}\n```"
            )
        return "\n".join(parts)

    parts = []
    for node in suspicious_nodes:
        keywords_str = ", ".join(node.matched_keywords)

        risk_hint = ""
        if node.keyword_risk_level and node.keyword_risk_reason:
            risk_level_upper = node.keyword_risk_level.upper()
            risk_hint = (
                f"\n\n🔴 **风险评估**: {risk_level_upper} 级别\n"
                f"**风险原因**: {node.keyword_risk_reason}\n"
                f"**建议**: 此脚本应被拒绝（Deny），除非有明确的业务需求且已确认目标服务器可信。"
            )

        content_preview = node.preprocessed_content[:2000]
        if len(node.preprocessed_content) > 2000:
            content_preview += "\n... (截断，完整内容 {} 字符)".format(len(node.preprocessed_content))

        parts.append(
            f"⚠️ 脚本内容包含可疑关键词:\n"
            f"   脚本路径: {node.script_path}\n"
            f"   递归深度: {node.depth}\n"
            f"   可疑关键词: {keywords_str}\n"
            f"   脚本行数: {node.line_count}"
            f"{risk_hint}\n\n"
            f"### 脚本内容（预处理后）###\n```\n{content_preview}\n```\n"
        )

    header = (
        f"⚠️ 检测到脚本执行链（共 {len(chain_result.nodes)} 个脚本），"
        f"其中 {len(suspicious_nodes)} 个包含可疑关键词:\n"
    )

    if chain_result.max_depth_reached:
        header += "⚠️ 注意：递归追踪触达深度上限，可能存在更深层的脚本调用未被扫描。\n"
    if chain_result.max_size_reached:
        header += "⚠️ 注意：累计文件大小触达上限，部分脚本可能未被完整读取。\n"

    return header + "\n---\n\n".join(parts)


# ==================== 向后兼容（deprecated） ====================


def format_script_analysis_for_prompt(result) -> str:
    """[deprecated] 使用 format_script_chain_for_prompt 替代。

    兼容旧调用方：若传入 ScriptChainAnalysisResult 直接用新函数；
    旧式 ScriptAnalysisResult 不存在于新代码中，返回空串。
    """
    if isinstance(result, ScriptChainAnalysisResult):
        return format_script_chain_for_prompt(result)
    return ""
