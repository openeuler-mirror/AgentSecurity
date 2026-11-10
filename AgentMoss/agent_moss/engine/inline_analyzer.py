"""内联脚本静态语义判定 — 区分敏感路径是"被当作文本"还是"被当作读写目标"。

对内联脚本（python -c / perl -e / ruby -e / php -r / node -e / lua / echo / printf）
里出现非凭据敏感路径的场景，做静态判定（不依赖 LLM）：

1. 写入+执行绕过链 → Deny（echo "cat /etc/shadow" > x.sh && bash x.sh / printf | bash）
2. 重定向写入敏感路径 → Deny（echo '...' >> /etc/hosts）
3. 含读写调用词 + 敏感路径共存 → Deny（open('/etc/shadow')、os.system('cat /etc/shadow')）
   注意：仅对 python -c 等真正的内联脚本代码做读写调用词检测；
   echo/printf 的字符串参数是自然语言文本，跳过此检测（不可能触发真实读写）。
4. 否则（敏感路径在代码里但无读写调用词，如 print('/etc/shadow')） → Allow

5. 目录遍历 + 文件读写组合 → Deny（os.listdir + open() 动态发现并读写文件，绕过静态路径检测）
   注意：仅对 python -c 等真正的内联脚本代码做此检测。
6. 否则（无目录遍历读写组合） → Allow

凭据文件不进此判定（coordinator 层 is_credential 直接 Deny）。
"""

import re
import shlex
from dataclasses import dataclass


@dataclass
class InlineAnalysisResult:
    """内联脚本静态语义判定结果"""

    actionable: bool = False  # 是否命中本判定器可处理的内联脚本场景
    allowed: bool = True
    reason: str = ""
    risk_level: str = "low"
    risk_type: str = ""


# 内联脚本解释器 + 代码标志：python -c / perl -e / ruby -e / php -r / node -e / lua -e
# 捕获 -c/-e/-r 后的代码内容（引号内或到行尾）
_INLINE_CODE_RE = re.compile(
    r"(?:python|python3|perl|perl5|ruby|jruby|mruby|node|php|lua)\s+"
    r"(?:-[a-zA-Z]*[cera][a-zA-Z]*\s+)"
    r"\"([^\"\\]*(?:\\.[^\"\\]*)*)\"|"  # 双引号代码（支持转义）
    r"'([^'\\]*(?:\\.[^'\\]*)*)'",      # 单引号代码
    re.IGNORECASE,
)

# echo / printf 的字符串参数（单/双引号）
_ECHO_STRING_RE = re.compile(
    r"\b(?:echo|printf)\s+"
    r"\"([^\"\\]*(?:\\.[^\"\\]*)*)\"|"
    r"\b(?:echo|printf)\s+"
    r"'([^'\\]*(?:\\.[^'\\]*)*)'",
    re.IGNORECASE,
)

# echo / printf 命令本身（用于 is_literal_text_command 门控）
_ECHO_CMD_RE = re.compile(r"(?:^|\s|;|&&|\|\|)(?:echo|printf)\s", re.IGNORECASE)


def is_literal_text_command(command: str) -> bool:
    """判断命令是否为 echo/printf 等纯文本输出命令（敏感路径可能作为字符串字面量出现）。

    echo/printf 含真实文件重定向（> /path，非 /dev/null 丢弃、非 >& fd）时返回 False——
    重定向目标是真实写文件，路径不是字面量，不当文本命令（否则 echo x > '~/.bashrc'
    被当文本命令 → inline_analyzer 把引号内路径当字面量 → 漏报敏感路径写）。
    """
    if not _ECHO_CMD_RE.search(command):
        return False
    # 含真实文件重定向 → 不是纯文本输出
    from .logic_rules import _is_write_operation, _DEVNULL_REDIRECT_RE
    import re
    if ">" in command:
        d = re.sub(r"<=>|>=|<=|<>|=>", " ", command)
        d = _DEVNULL_REDIRECT_RE.sub("", d)
        # 摘引号重定向目标（去引号保留路径，支持 / 或 ~ 开头）
        d = re.sub(r">{1,2}\s*(['\"])([~./][^'\"]+)\1", lambda m: ">" + m.group(2), d)
        d = re.sub(r"'[^']*'|\"[^\"]*\"", "", d)
        if re.search(r">{1,2}\s*(?!&)\S", d):
            return False
    return True

# 读写调用词：仅用于 python -c 等真正的内联脚本代码（不对 echo/printf 的字符串生效）。
# 出现这些词 + 敏感路径共存 → 判为真实读写。
#
# 全部采用组合/函数调用形态，避免自然语言误触发：
# - 函数调用形态：open(, read(, write(, system(, exec(, eval( 等（后跟 '('）
# - 组合关键词：os.system, import os, shell=True 等（自带足够区分度）
# - 不再包含裸短词（open, read, system, exec 等），因 \b 无法区分编程调用与自然语言
_READ_WRITE_KEYWORDS = [
    # 函数调用形态（关键词后跟 '('）
    "open(", "read(", "write(", "fopen(", "system(", "exec(", "eval(",
    "popen(", "load(", "dump(",
    # 文件读写（组合形态）
    "readline", "readlines", "writelines", "getpass",
    "pickle.load", "yaml.load", "json.load", "json.read", "configparser",
    "fread", "fwrite", "fgets",
    # 子进程执行（组合形态）
    "os.system", "os.popen", "subprocess", "os.exec", "os.spawn",
    "import os", "import subprocess",
    "shell=true", "check_output", "check_call", "run(",
    # 绕过变体检测
    "getattr(", "__builtins__", "globals(", "locals(",
    # PHP
    "file_get_contents", "file_put_contents", "passthru", "shell_exec", "proc_open",
    # Perl/Ruby
    "<stdin>", "open my",
]

# 写入+执行绕过链：把含敏感操作的文本写入文件再执行，或管道喂给解释器
_WRITE_EXEC_CHAIN_PATTERNS = [
    # echo/cat/printf "..." > file && bash/sh/python file
    re.compile(
        r"(?:echo|cat|printf)\b.*?>\s*\S+.*"
        r"(?:&&|;|\|)\s*(?:bash|sh|zsh|python\d?|perl|ruby|node|php)\s",
        re.IGNORECASE | re.DOTALL,
    ),
    # ... | bash / | sh / | python（管道喂解释器执行）
    re.compile(r"\|\s*(?:bash|sh|zsh|python\d?|perl|ruby|node|php)\b", re.IGNORECASE),
    # eval "$(cat ...)" / eval "$(echo ...)"
    re.compile(r"eval\s+\"\$\(", re.IGNORECASE),
    # xargs bash / xargs sh
    re.compile(r"\|\s*xargs\s+(?:bash|sh|zsh)", re.IGNORECASE),
]

# 重定向写入敏感路径：> / >> 后跟敏感路径 = 真实写入（不是字符串字面量）
# 兜底默认列表（无 profile 时用）。真实数据源是 profile.sensitive_paths，
# analyze_inline_script 传入 profile 时按 profile 动态编译正则，避免双份维护漂移。
_SENSITIVE_PATH_FRAGMENTS_DEFAULT = [
    "/etc/shadow", "/etc/gshadow", "/etc/passwd", "/etc/sudoers", "/etc/hosts",
    "/etc/crontab", "/etc/systemd/", "/etc/ssh/sshd_config", "/etc/pam.d/",
    "/etc/nginx/nginx.conf", "/etc/nginx/conf.d/", "/etc/nginx/sites-enabled/",
    "/boot/", "/proc/sys/", "/sys/", "/dev/mem", "/dev/kmsg",
    ".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/authorized_keys",
]
_REDIRECT_TO_SENSITIVE_RE = re.compile(
    r">{1,2}\s*(" + "|".join(re.escape(p) for p in _SENSITIVE_PATH_FRAGMENTS_DEFAULT) + r")",
    re.IGNORECASE,
)


def _build_redirect_to_sensitive_re(profile):
    """按 profile.sensitive_paths 动态编译重定向写敏感路径正则。

    单一数据源：路径来自 profile（存储一处），inline_analyzer 和 SensitivePathChecker
    都从同一 profile 读取（调用两处），不再各硬编码一份避免漂移。
    凭据路径（deny_both）也纳入：echo > /etc/shadow 重定向写凭据更该 Deny。
    """
    from .types import LogicRuleResult  # 仅用于类型，实际不调
    try:
        paths = [sp.path for sp in profile.sensitive_paths]
    except Exception:
        return _REDIRECT_TO_SENSITIVE_RE  # profile 不可用 → 回退兜底默认
    if not paths:
        return _REDIRECT_TO_SENSITIVE_RE
    return re.compile(
        r">{1,2}\s*(" + "|".join(re.escape(p) for p in paths) + r")",
        re.IGNORECASE,
    )


def _extract_inline_code(command: str) -> str:
    """从内联脚本命令中提取 -c/-e/-r 后的代码内容；提取 echo/printf 的字符串参数。

    Returns:
        提取出的代码/字符串文本（可能多段拼接）；若无匹配返回空串。
    """
    parts: list[str] = []
    for m in _INLINE_CODE_RE.finditer(command):
        # 两个捕获组（双引号组 / 单引号组），取非空的那个
        code = m.group(1) if m.group(1) is not None else m.group(2)
        if code:
            parts.append(code)
    for m in _ECHO_STRING_RE.finditer(command):
        code = m.group(1) if m.group(1) is not None else m.group(2)
        if code:
            parts.append(code)
    return "\n".join(parts)


def _has_write_exec_chain(command: str) -> bool:
    """检测写入+执行绕过链。"""
    return any(p.search(command) for p in _WRITE_EXEC_CHAIN_PATTERNS)


# 目录遍历关键词：用于检测通过动态发现文件路径绕过静态路径匹配的行为
# 仅对 python -c 等真正的内联脚本代码生效
_DIR_TRAVERSAL_KEYWORDS = [
    # Python 目录遍历
    "os.listdir", "os.walk", "os.scandir", "os.walk",
    "glob.glob", "glob.iglob", "pathlib.", "iterdir", "rglob",
    "scandir(", "listdir(",
]


def _has_dir_traversal(code: str) -> bool:
    """检测代码中是否含目录遍历函数（用于识别动态文件发现绕过行为）。"""
    code_lower = code.lower()
    return any(kw in code_lower for kw in _DIR_TRAVERSAL_KEYWORDS)


def _has_read_write_keyword(code: str) -> bool:
    """检测代码中是否含读写调用词（仅用于 python -c 等真正的内联脚本代码）。

    全部关键词为组合/函数调用形态（open(, os.system, import os 等），
    不会在自然语言文本里误触发。
    """
    code_lower = code.lower()
    return any(kw in code_lower for kw in _READ_WRITE_KEYWORDS)


def analyze_inline_script(command: str, profile=None) -> InlineAnalysisResult:
    """对内联脚本做静态语义判定。

    调用前提：coordinator 已确认是 inline 脚本 + 命中非凭据敏感路径。
    本函数判定该敏感路径是"文本字面量"还是"被真实读写"。

    Args:
        command: 完整命令字符串（action_detail）
        profile: OSProfile（可选）。传入时按 profile.sensitive_paths 动态编译
            重定向写敏感路径正则（单一数据源，避免与硬编码列表漂移）；
            不传时回退模块级 _REDIRECT_TO_SENSITIVE_RE 兜底默认。

    Returns:
        InlineAnalysisResult: actionable=True 时 coordinator 采用其 allowed/reason；
        actionable=False 表示本判定器无法处理（回退原逻辑）。
    """
    # 1. 重定向写入敏感路径（echo x > /etc/hosts / echo 'x' >> /etc/hosts 等）
    # 必须在 _extract_inline_code 之前：> /敏感路径 是命令本身的特征，不依赖提取的
    # 字符串内容。否则 echo x > /敏感路径（x 无引号）提取不到 code → actionable=False
    # → 回退后因 skip_inline_file_access 被放行，形成绕过。
    redirect_re = _build_redirect_to_sensitive_re(profile) if profile else _REDIRECT_TO_SENSITIVE_RE
    redir_match = redirect_re.search(command)
    if redir_match:
        return InlineAnalysisResult(
            actionable=True,
            allowed=False,
            reason=f"重定向写入敏感路径: {redir_match.group(1)}",
            risk_level="critical",
            risk_type="file_access",
        )

    code = _extract_inline_code(command)
    if not code:
        # 提取不到代码（命令结构不匹配已知 inline 模式）→ 不处理，回退保守
        return InlineAnalysisResult(actionable=False)

    # 1.5 写入+执行绕过链 → Deny
    if _has_write_exec_chain(command):
        return InlineAnalysisResult(
            actionable=True,
            allowed=False,
            reason="内联脚本含写入文件后执行的模式，疑似绕过敏感路径检测",
            risk_level="critical",
            risk_type="script_execution",
        )

    # 1.6 目录遍历 + 文件读写组合 → 不自行判定，回退 coordinator 走层3 LLM 分析
    # 检测 os.listdir/glob/pathlib 等目录遍历函数 + open()/write()/read() 等读写调用，
    # 用于识别"通过动态发现文件路径绕过静态路径匹配"的行为。
    # 仅对 python -c 等真正的内联脚本代码做此检测（echo/printf 无此能力）。
    # 注意：此处返回 actionable=False，让 coordinator 回退到正常逻辑，
    # 由层2 的 _check_indirect_file_access 规则触发层3 LLM 语义判断。
    is_echo_or_printf = is_literal_text_command(command)
    if not is_echo_or_printf and _has_dir_traversal(code) and _has_read_write_keyword(code):
        return InlineAnalysisResult(actionable=False)

    # 2. 含读写调用词 → 判为真实读写 → Deny
    # 注意：仅对 python -c 等真正的内联脚本代码做此检测。
    # echo/printf 的字符串参数是自然语言文本，不可能触发真实文件读写；
    # 重定向（>> /etc/hosts）和管道执行（| bash）已在步骤 1/1.5 覆盖。
    is_echo_or_printf = is_literal_text_command(command)
    if not is_echo_or_printf and _has_read_write_keyword(code):
        return InlineAnalysisResult(
            actionable=True,
            allowed=False,
            reason="内联脚本含敏感路径且含文件读写/命令执行调用，判为真实访问",
            risk_level="critical",
            risk_type="file_access",
        )

    # 3. 敏感路径在代码里但无读写调用词 → 文本字面量 → Allow
    return InlineAnalysisResult(
        actionable=True,
        allowed=True,
        reason="敏感路径仅作为文本字面量出现，未伴随读写操作",
        risk_level="low",
        risk_type="file_access",
    )
