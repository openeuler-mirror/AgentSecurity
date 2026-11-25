"""写入内容的按语言静态分析（writeFile / editFile）。

**为什么不能直接用命令执行规则扫 content**：命令替换/危险命令只有在"被执行"时
才有语义。写 Markdown 文档里的 `` `python -m pytest` ``、quoted heredoc 里的
``rm``、Python 字符串里的 ``os.system(...)`` 都不是本次动作的执行内容。用 shell
规则扫一切内容 = 严重误报（2026-11 OpenDesk 维测：写指南被 critical 拦截）。

按目标语言分流（确定性 L1/L2，不依赖 L3）：
- 文档/数据（.md/.json/.yaml/...）：不做命令执行检测；
- shell（.sh/.bash/... 或无扩展名 + shebang）：ShellBackend 解析后只扫危险片段；
- python（.py）：AST 遍历真实调用节点，只扫危险调用（字符串字面量不算）；
- 其他脚本：保守预筛 + 片段扫描。

性能：预筛 + 片段上限（max_scan_bytes）+ 时间预算（max_scan_ms）+ 内容上限
（max_content_bytes）。普通文档预筛不命中，成本接近 0。
"""

import ast
import json
import os
import re
import time

from .types import HeuristicResult
from ..rules_loader import load_heuristic_rules

_CFG = load_heuristic_rules().get("write_content_analysis") or {}
_DATA_EXTS = {e.lower() for e in (_CFG.get("data_exts") or [])}
_SHELL_EXTS = {e.lower() for e in (_CFG.get("shell_exts") or [])}
_PY_EXTS = {e.lower() for e in (_CFG.get("python_exts") or [])}
_SHELL_PRECHECK = re.compile(_CFG.get("shell_precheck") or r"$^")
_PY_PRECHECK = re.compile(_CFG.get("python_precheck") or r"$^")
_MAX_CONTENT = int(_CFG.get("max_content_bytes") or 262144)
_MAX_SCAN = int(_CFG.get("max_scan_bytes") or 65536)
_MAX_MS = int(_CFG.get("max_scan_ms") or 100)

#: 单文件写工具（action_type 已小写）。applyPatch 是多文件 diff，不做内容命令分析。
_WRITE_TOOL_EXACT = {
    "write", "file_write", "writefile", "edit", "file_edit", "editfile",
    "searchreplace", "search_replace",
    # 通用 workspace 工具名（ClawPartner/QwenPaw 等宿主常用），语义明确：
    # workspace_write_file 写单个文件，workspace_edit_file 编辑单个文件。
    "workspace_write_file", "workspace_edit_file",
    "workspace_writefile", "workspace_editfile",
}
_WRITE_TOOL_SUFFIXES = ("-writefile", "-editfile", "-searchreplace")
_APPLY_PATCH_SUFFIX = ("applypatch", "apply_patch", "-applypatch")

#: OpenDesk/通用调用方的 command 文本前缀：`写入文件: <path> [ (追加) ] —`
_WRITE_PREFIX_HEAD_RE = re.compile(
    # 路径允许空格（`my notes/x.sh`）；非贪婪到可选的「(追加)」后缀/行尾。
    r"^(?:写入文件|编辑文件|应用补丁|写入|编辑)\s*[:：]\s*(.+?)\s*"
    r"(?:\(\s*追加\s*\))?\s*$"
)
#: editFile 只分析 newString（oldString 是原文，不是写入内容）
_EDIT_NEW_RE = re.compile(r"\|\s*new:\s*([\s\S]*)$", re.IGNORECASE)

#: Python 危险调用（只匹配 AST 里的真实调用，不匹配字符串字面量）
_PY_DANGEROUS_CALL_RE = re.compile(
    r"^(?:"
    r"os\.(?:system|popen|remove|unlink|rmdir|chmod|chown|kill|spawn\w*)|"
    r"subprocess\.\w+|pty\.\w+|ctypes\.\w+|"
    r"eval|exec|compile|__import__|"
    r"shutil\.(?:rmtree|move|copy\w*)"
    r")$"
)


def is_file_write_action(action_type: str) -> bool:
    """action_type 是否为文件写入/编辑工具。"""
    at = (action_type or "").lower()
    if at in _WRITE_TOOL_EXACT:
        return True
    if any(at.endswith(s) for s in _WRITE_TOOL_SUFFIXES):
        return True
    return False


def _is_apply_patch(action_type: str) -> bool:
    at = (action_type or "").lower()
    return any(at.endswith(s) for s in _APPLY_PATCH_SUFFIX)


def extract_write_payload(action_type: str, action_detail_raw: str) -> tuple[str, str] | None:
    """从写工具的 action_detail 提取 (目标路径, 写入内容)。

    解析不出来（裸路径/未知格式/`?` 占位）返回 None —— 没有可信内容可分析，
    交给敏感路径/执行时脚本分析，不用猜。
    """
    if _is_apply_patch(action_type):
        return None
    detail = action_detail_raw or ""
    # 先用分隔符切前缀再匹配，避免对 1MB 内容跑 `([\s\S]*)` 捕获组正则（10ms → <1ms）。
    sep = detail.find("—")
    if sep > 0:
        m = _WRITE_PREFIX_HEAD_RE.match(detail[:sep])
        if m:
            path = m.group(1)
            content = detail[sep + 1:]
            if not path or path in ("?", "-") or not content.strip():
                return None
            if "editfile" in (action_type or "").lower():
                nm = _EDIT_NEW_RE.search(content)
                if nm:
                    content = nm.group(1)
            return path, content
    # 通用调用方可能直接透传 args JSON
    stripped = detail.strip()
    if stripped.startswith("{"):
        try:
            obj = json.loads(stripped)
            if isinstance(obj, dict):
                path = obj.get("path") or obj.get("file_path") or obj.get("filePath")
                content = obj.get("content") or obj.get("newString") or obj.get("new_string")
                if (
                    isinstance(path, str) and path not in ("", "?", "-")
                    and isinstance(content, str) and content.strip()
                ):
                    return path, content
        except Exception:  # noqa: BLE001 — 非法 JSON 按原文处理
            pass
    return None


#: 指令/提示词/记忆/技能类写入目标。写入这些位置的正文会被下游 agent 当指令读，
#: 注入关键词检测必须保留；普通报告/数据文档则只按数据内容处理。
_INSTRUCTION_TARGET_RE = re.compile(
    r"(?:^|[/\\])(?:prompts?|instructions?|skills?|memories|memory|"
    r"config|policies|policy|\.claude|\.cursor)(?:[/\\]|$)"
    r"|(?:^|[/\\])(?:AGENTS?|CLAUDE|SYSTEM|PROMPT|INSTRUCTIONS?)"
    r"(?:\.[^/\\]+)?$"
    r"|(?:^|[/\\])\.cursorrules$",
    re.IGNORECASE,
)


def is_instruction_target(path: str) -> bool:
    """写目标是否属于“会被下游当指令读取”的文件/目录。"""
    p = (path or "").replace("\\", "/").lower()
    if not p:
        return False
    base = p.rsplit("/", 1)[-1]
    if base in ("agents.md", "claude.md", "system.md", "prompt.md",
                "instructions.md", ".cursorrules"):
        return True
    # `agentmoss-prompt.txt` / `system_prompt.md` 这类名字也按指令源处理。
    if re.search(r"(?:^|[-_.])(?:prompt|instruction|system)(?:[-_.]|$)", base):
        return True
    return bool(_INSTRUCTION_TARGET_RE.search(p))


def is_data_document(action_type: str, action_detail_raw: str) -> bool:
    """是否为“普通数据文档”写入（可跳过正文注入关键词检测）。

    只认能解析出明确 path/content、语言判定为 data、且目标不是指令源的文件。
    """
    payload = extract_write_payload(action_type, action_detail_raw)
    if payload is None:
        return False
    path, content = payload
    return detect_language(path, content) == "data" and not is_instruction_target(path)


def handles_written_content(action_type: str, action_detail_raw: str) -> bool:
    """该写工具调用是否走「按内容语言分析」分支。

    - 能解析出 (path, content) → 是；
    - OpenDesk 文本格式（含 `写入文件: ?` 占位 / applyPatch）→ 是（内容不可判定
      或为补丁时跳过命令执行检测，避免把 content 当命令）；
    - 其他格式（如 `write` 直接带 shell 命令 `echo ... >> /etc/hosts`）→ 否，
      保持原有 L1 命令扫描，不放松真实命令。
    """
    if not is_file_write_action(action_type):
        return False
    if extract_write_payload(action_type, action_detail_raw) is not None:
        return True
    return bool(re.match(r"^(?:写入文件|编辑文件|应用补丁)\s*[:：]", action_detail_raw or ""))


def detect_language(path: str, content: str) -> str:
    """按扩展名/shebang 判定写入内容的语言。"""
    ext = os.path.splitext(path)[1].lower()
    if ext in _SHELL_EXTS:
        return "shell"
    if ext in _PY_EXTS:
        return "python"
    if ext in _DATA_EXTS:
        return "data"
    if not ext:
        first = content.lstrip().splitlines()[0] if content.strip() else ""
        if first.startswith("#!"):
            if re.search(r"\b(?:ba|z|k|da)?sh\b", first):
                return "shell"
            if "python" in first:
                return "python"
        # 无扩展名无 shebang：按数据文件处理（不猜）
        return "data"
    return "other"


#: 解释器 heredoc：`bash <<EOF` / `bash <<'EOF'` 的正文会作为脚本执行，
#: 必须保留分析（quoted heredoc 不展开命令替换，但命令本身仍执行）。
_INTERP_HEREDOC_RE = re.compile(
    r"(?:^|[\s;|&])(?:bash|sh|zsh|dash|python[0-9.]*|perl|ruby|node|php|lua)"
    r"\s*<<-?\s*['\"]?[A-Za-z_]",
    re.IGNORECASE,
)
#: quoted heredoc 内容不会被展开/执行（只对非解释器消费者如 cat 生效）。
_QUOTED_HEREDOC_RE = re.compile(
    r"<<-?\s*(['\"])([A-Za-z_][A-Za-z0-9_]*)\1[^\n]*\n.*?\n\s*\2\s*(?:\n|$)",
    re.DOTALL | re.MULTILINE,
)


#: heredoc 起始标记（含结束标记名），用于「正文不剥注释」。
_HEREDOC_START_RE = re.compile(r"<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?")


def _strip_shell_comments(text: str) -> str:
    """剥离 shell 注释（引号外的 # 到行尾）。

    **heredoc 正文内的 # 不剥**：正文是数据不是注释（`cat <<EOF` 里
    `# 见 /etc/passwd` 是内容），剥了会让场景白名单/敏感路径漏检
    （2026-11 回归：heredoc 体内路径恒 Allow）。
    """
    out_lines: list[str] = []
    heredoc_end: str | None = None
    for line in text.splitlines():
        if heredoc_end is not None:
            # heredoc 正文：整行是数据，原样保留
            out_lines.append(line)
            if line.strip() == heredoc_end:
                heredoc_end = None
            continue
        hm = _HEREDOC_START_RE.search(line)
        if hm:
            heredoc_end = hm.group(1)
        res: list[str] = []
        quote: str | None = None
        i = 0
        while i < len(line):
            ch = line[i]
            if quote:
                res.append(ch)
                if ch == quote:
                    quote = None
                i += 1
                continue
            if ch in ("'", '"'):
                quote = ch
                res.append(ch)
                i += 1
                continue
            if ch == "#" and (i == 0 or line[i - 1].isspace()):
                break
            res.append(ch)
            i += 1
        out_lines.append("".join(res))
    return "\n".join(out_lines)


def strip_shell_docs_only(content: str) -> str:
    """剥掉 shell 中明确不执行的区域：非解释器 quoted heredoc + 注释。

    **不改变命令结构**（引号、管道、分隔符原样保留）：单引号/双引号的字面量
    交给原有的 _strip_literal_text_segments（echo/printf）处理，避免把
    grep 凭据关键词、fork bomb、cron 持久化消费者等真实规则一起剥掉。

    - `bash <<EOF` / `bash <<'EOF'`（解释器 heredoc）：正文作为脚本执行，不剥；
    - `cat <<'EOF'`（quoted heredoc）：不展开命令替换，正文是数据，剥；
    - 注释：不执行，剥。
    """
    if not content:
        return content
    if _INTERP_HEREDOC_RE.search(content):
        return content
    text = _QUOTED_HEREDOC_RE.sub("<<quoted-heredoc>>\n", content)
    return _strip_shell_comments(text)


def _line_snippets(content: str, precheck: re.Pattern) -> list[str]:
    """按行提取命中预筛词的片段（命中行 ±1 行），总大小受限。

    只对危险行附近跑规则，避免大内容全文扫描（1MB 全文正则 2~4 秒）。
    """
    lines = content.splitlines()
    picked: set[int] = set()
    for i, line in enumerate(lines):
        if precheck.search(line):
            picked.update({i - 1, i, i + 1})
    snippets: list[str] = []
    total = 0
    for i in sorted(picked):
        if i < 0 or i >= len(lines):
            continue
        s = lines[i]
        if total + len(s) > _MAX_SCAN:
            break
        snippets.append(s)
        total += len(s) + 1
    return snippets


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _string_values(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, (ast.List, ast.Tuple)):
        out: list[str] = []
        for elt in node.elts:
            out.extend(_string_values(elt))
        return out
    if isinstance(node, ast.JoinedStr):
        # f-string：静态文本部分是 Constant（`f"rm -rf /opt/{x}"` 的
        # "rm -rf /opt/"），动态部分是 FormattedValue。提取静态文本，
        # 与 TS 端"取原文参数"的行为对齐（否则 Python 漏报 f-string 危险命令）。
        out = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                out.append(v.value)
        return out
    return []


def _python_snippets(content: str) -> tuple[list[str], bool]:
    """AST 遍历真实调用，返回 (危险调用片段, 是否解析成功)。"""
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return [], False
    snippets: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node.func)
        if not name or not _PY_DANGEROUS_CALL_RE.match(name):
            continue
        args: list[str] = []
        for arg in node.args:
            args.extend(_string_values(arg))
        snippets.append(f"{name}({' '.join(args)})")
    return snippets, True


def _scan_snippets(snippets: list[str], scanner, deadline: float) -> HeuristicResult | None:
    best: HeuristicResult | None = None
    for snippet in snippets:
        if time.monotonic() > deadline:
            break
        result = scanner.scan(snippet)
        if not result.hit:
            continue
        if best is None or _priority(result.risk_level) > _priority(best.risk_level):
            best = result
    return best


_PRIORITY = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _priority(level: str) -> int:
    return _PRIORITY.get((level or "").lower(), 0)


def analyze_written_content(
    action_type: str,
    action_detail_raw: str,
    scanner,
    literal_stripper=None,
) -> HeuristicResult | None:
    """分析写工具将要写入的内容；返回命中的 HeuristicResult 或 None。

    解析失败/无法静态确定时**降级为 medium**（不直接 Deny），交 L2/L3，
    避免"复杂脚本解析不了就硬拦"的误报。
    """
    payload = extract_write_payload(action_type, action_detail_raw)
    if payload is None:
        return None
    path, content = payload
    language = detect_language(path, content)
    if language == "data":
        return None
    # 调用方常把换行转义成字面 `\n`（OpenDesk command / JSON 透传），
    # 不还原会让 shebang 后的整行被当注释、Python 变成语法错误 → 漏报。
    content = content.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\t", "\t")
    # 分隔符后的前导空白（`— import os`）会让 ast.parse 报 unexpected indent；
    # 去掉行首空白不改变语义（shell/python 顶层语句允许前导空格）。
    content = content.lstrip()
    content = content[:_MAX_CONTENT]

    resolved = True
    if language == "python":
        if not _PY_PRECHECK.search(content):
            return None
        snippets, resolved = _python_snippets(content)
    else:  # shell / other
        content = strip_shell_docs_only(content)
        if literal_stripper is not None:
            # 复用 heuristic 的 echo/printf 字面量剥离（含 exec bypass 旁路），
            # 不在这里另抄一份，避免双份实现漂移。
            content = literal_stripper(content)
        if not _SHELL_PRECHECK.search(content):
            return None
        snippets = _line_snippets(content, _SHELL_PRECHECK)

    deadline = time.monotonic() + _MAX_MS / 1000.0
    best = _scan_snippets(snippets, scanner, deadline)
    if best is None:
        return None
    if not resolved:
        # 解析失败：不直接 Deny，降级 medium 交 L2/L3
        return HeuristicResult(
            hit=True,
            matched_patterns=best.matched_patterns,
            risk_level="medium",
            reason=f"{best.reason}（内容无法完整静态解析，降级为可疑）",
            risk_type=best.risk_type,
            violated_rule=best.violated_rule,
        )
    return best
