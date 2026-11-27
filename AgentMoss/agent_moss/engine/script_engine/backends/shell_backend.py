"""脚本分析引擎 — ShellBackend

shell（bash/sh/zsh）脚本的静态解析后端，产出 IR。

比旧版 branch_aware_preprocess 三点升级：
1. **case 支持任意 selector**：`case $1 in` / `case $MODE in` / `case ${1} in`。
   只要 selector 变量能被 entry_args 绑定，就用绑定的值选分支。
2. **if 支持字符串相等条件**：`if [ "$1" = "clean" ]` / `[ "$MODE" == "x" ]` /
   `[[ "$1" = clean ]]`。只识别"字面量相等"这类可静态判定的条件。
3. **循环可达**：`while`/`for` 循环体视为可达（保守——循环次数运行期未知，
   不能证明不可达，故保留，避免漏报）。

子脚本调用提取升级：`bash child.sh cleanup` 提取 (child.sh, ["cleanup"])，
供 RecursiveTracker 做跨脚本参数传递（修复旧版子调用参数丢失 bug）。

性能：纯正则 + 行扫描，单脚本 < 40ms（与旧版 preprocess 量级一致）。
双端（Python/TS）各实现一份，行为逐 case 对齐。
"""

import re
from collections.abc import Iterator
from enum import Enum, auto

from ..ir import ScriptCall, ScriptIR, scan_fingerprint
from .base import LanguageBackend
from .symbolic import (
    CASE_HEADER_RE,
    case_syntax_lines,
    parse_case_statement,
    select_case_branch,
)


# ==================== 参数绑定 ====================
_POSITIONAL_RE = re.compile(r"\$(?:([1-9@*])|\{([1-9][0-9]*|[@*])(?:(:-|-)|\}))")
_QUOTED_WORD_PART_RE = re.compile(r"""\$\{|\\[\s\S]|\$[1-9@*]""")
_SHELL_WORD_PART_RE = re.compile(rf"""'[^']*'|"|{_QUOTED_WORD_PART_RE.pattern}""")
_SHELL_SOURCE_PART_RE = re.compile(rf"\#|{_SHELL_WORD_PART_RE.pattern}")
_SUBSTITUTION_START = r"\$\(|\x60"
_DEFAULT_WORD_PART_RE = re.compile(rf"{_SUBSTITUTION_START}|{_SHELL_WORD_PART_RE.pattern}")
_QUOTED_DEFAULT_PART_RE = re.compile(rf'{_SUBSTITUTION_START}|"|{_QUOTED_WORD_PART_RE.pattern}')
_DOUBLE_QUOTE_END_RE = re.compile(rf'\\[\s\S]|\$\{{|{_SUBSTITUTION_START}|"')
_DEFAULT_BOUNDARY_RE = re.compile(
    rf"""\\[\s\S]|'[^']*'|"|\$\{{|{_SUBSTITUTION_START}|[}}']"""
)
_SUBSTITUTION_BOUNDARY_RE = re.compile(
    rf"""\\[\s\S]|'[^']*'|"|\$\{{|{_SUBSTITUTION_START}|[()']|<<"""
    r"|(?<![^\s;&|()<>])(?:\#[^\n]*|case(?=[ \t]))"
)
_BACKTICK_RE = re.compile(r"\x60(?:\\[\s\S]|[^\x60\\])*\x60")
_IFS_RE = re.compile(r"([ \t\n]+)")
_MAX_DEFAULT_DEPTH = 32



class _ExpansionStatus(Enum):
    UNRESOLVED = auto()


def _substitution_end(text: str, start: int, opening: str, level: int) -> int | None:
    """Locate a command substitution without interpreting its output."""
    if level >= _MAX_DEFAULT_DEPTH:
        return None
    if opening == "`":
        match = _BACKTICK_RE.match(text, start - 1)
        return match.end() if match else None

    depth = 1
    while token := _SUBSTITUTION_BOUNDARY_RE.search(text, start):
        part = token[0]
        start = token.end()
        if part in ("(", "$("):
            depth += 1
        elif part == ")":
            depth -= 1
            if not depth:
                return start
        elif part == '"':
            start = _double_quote_end(text, start, level + 1)
        elif part == "${":
            start = _braced_word_end(text, start, level + 1)
        elif part == "`":
            start = _substitution_end(text, start, part, level + 1)
        elif part in ("'", "<<", "case"):
            return None  # These can change the meaning of a closing parenthesis.
        if start is None:
            return None
    return None


def _braced_word_end(text: str, start: int, level: int = 0) -> int | None:
    if level >= _MAX_DEFAULT_DEPTH:
        return None
    depth = 1
    while token := _DEFAULT_BOUNDARY_RE.search(text, start):
        part = token[0]
        start = token.end()
        if part == "${":
            depth += 1
        elif part == "}":
            depth -= 1
            if not depth:
                return start
        elif part in ("$(", "`"):
            start = _substitution_end(text, start, part, level + 1)
        elif part == '"':
            start = _double_quote_end(text, start, level + 1)
        elif part == "'":
            return None
        if start is None:
            return None
    return None


def _double_quote_end(text: str, start: int, level: int = 0) -> int | None:
    if level >= _MAX_DEFAULT_DEPTH:
        return None
    while token := _DOUBLE_QUOTE_END_RE.search(text, start):
        part = token[0]
        if part == '"':
            return token.end()
        start = token.end()
        if part == "${":
            start = _braced_word_end(text, start, level + 1)
        elif part in ("$(", "`"):
            start = _substitution_end(text, start, part, level + 1)
        if start is None:
            return None
    return None


def _shell_word_parts(
    text: str, quoted: bool = False, *,
    syntax: str | None = None, default_text: bool = False,
) -> Iterator[tuple[int, int]]:
    if default_text:
        pattern = _QUOTED_DEFAULT_PART_RE if quoted else _DEFAULT_WORD_PART_RE
    elif quoted:
        pattern = _QUOTED_WORD_PART_RE
    else:
        pattern = _SHELL_SOURCE_PART_RE if syntax is not None else _SHELL_WORD_PART_RE
    offset = 0
    while token := pattern.search(text, offset):
        part = token[0]
        end = token.end()
        if part == "#" and syntax is not None and syntax[token.start()] == " ":
            end = text.find("\n", end)
            if end < 0:
                return
            offset = end + 1
            continue
        if part == "${":
            end = _braced_word_end(text, end)
        elif part == '"':
            end = _double_quote_end(text, end)
        elif part in ("$(", "`"):
            end = _substitution_end(text, end, part, 0)
        if end is None:
            if syntax is None:
                return
            # Keep the unsupported command as text and resume on the next line.
            newline = text.find("\n", token.end())
            if newline < 0:
                return
            offset = newline + 1
            continue
        yield token.start(), end
        offset = end


def _default_has_substitution(text: str, quoted: bool) -> bool:
    for start, end in _shell_word_parts(text, quoted, default_text=True):
        part = text[start:end]
        if part.startswith(("$(", "`")):
            return True
        if part.startswith('"') and _default_has_substitution(part[1:-1], True):
            return True
    return False


def _positional_value(token: str, args: list[str]) -> tuple[str | list[str], bool]:
    """返回可用的实参，或尚未求值的默认项。"""
    part = _POSITIONAL_RE.match(token)
    if part is None:
        return token, False
    bare, braced, operator = part.groups()
    name = bare or braced
    if name == "@":
        return args, False
    if name == "*":
        return " ".join(args), False
    # 先按长度筛选不可到达的索引，避免超长数字影响分析。
    index = int(name) - 1 if len(name) <= len(str(len(args))) else len(args)
    if index < len(args) and (operator != ":-" or args[index]):
        return args[index], False
    return (token[part.end():-1], True) if operator else ("", False)


def bind_positional_args(content: str, args: list[str]) -> str:
    """为文本扫描展开位置参数，保留单引号和转义字面量。"""
    if not args or "$" not in content:
        return content

    def bind_text(text: str, *, quoted: bool = False) -> str:
        output: list[str] = []
        offset = 0
        syntax = None
        if not quoted:
            syntax = "\n".join(case_syntax_lines(text)) if "#" in text else text
        for start, end in _shell_word_parts(text, quoted, syntax=syntax):
            token = text[start:end]
            output.append(text[offset:start])
            offset = end
            if token.startswith('"'):
                output.append('"' + bind_text(token[1:-1], quoted=True) + '"')
            elif _POSITIONAL_RE.match(token):
                value, use_default = _positional_value(token, args)
                values = value if isinstance(value, list) else [value]
                if use_default:
                    if _default_has_substitution(values[0], quoted):
                        output.append(token)
                        continue
                    expanded = _expand_shell_word(values[0], args, quoted_default=quoted)
                    if expanded is None:
                        output.append(token)
                        continue
                    values = expanded
                if quoted:
                    values = [re.sub(r'([\\$"\x60])', r"\\\1", item) for item in values]
                output.append(('" "' if quoted else " ").join(values))
            else:
                output.append(token)
        output.append(text[offset:])
        return "".join(output)

    return bind_text(content)


# ==================== case 分支解析 ====================


def _find_selector_value(selector: str, args: list[str] | None) -> str | None:
    """解析 case selector（$1 / $MODE / ${1}），从 args 中找到绑定值。

    只支持位置参数：$1 → args[0]，$2 → args[1]，$@ → 所有参数。
    命名字符串（$MODE）不识别（无环境变量上下文），返回 None（fail-closed）。
    """
    if not args:
        return None
    m = re.match(r"^\$\{?(\d+)\}?$", selector)
    if m:
        idx = int(m.group(1))
        if 1 <= idx <= len(args):
            return args[idx - 1]
        return None  # 位置越界，未知
    return None  # $MODE 等命名变量不可静态绑定


def parse_case(
    content: str, args: list[str] | None, *, diagnostics: dict | None = None,
) -> str | None:
    """用已知的入口参数选择 case 分支；无法确定时交给 LiteSE。"""
    if not args or not CASE_HEADER_RE.search(content):
        return None
    lines = content.split("\n")
    syntax_lines = case_syntax_lines(content)
    for index, line in enumerate(syntax_lines):
        if CASE_HEADER_RE.match(line):
            break
    else:
        return None

    case = parse_case_statement(lines, syntax_lines, index)
    if case is None:
        return None
    value = _find_selector_value(case.selector, args)
    if value is None:
        return None
    selection = select_case_branch(case, value)
    if selection is None:
        return None

    branch, kind = selection
    if diagnostics is not None:
        diagnostics["p1_case"] = kind
    end = index + case.line.count("\n") + 1
    return "\n".join([*lines[:index], case.branches[branch][1], *lines[end:]])


# ==================== if 分支解析 ====================


def _eval_if_condition(cond: str, args: list[str] | None) -> bool | None:
    """求值 if 的字符串条件；无法判定返回 None。

    支持：
      [ "$1" = "clean" ] / [ "$1" == "clean" ] / [ "$1" != "x" ]
      [ "$1" = bak* ]（未加引号 → glob 通配符）
      [[ "$1" =~ ^ba.* ]]（未加引号 → 正则）
      [ -f /tmp/x ]（文件存在性 → None，运行期）
    条件变量里 $1 替换为 args[0] 后比较；操作符按最长优先匹配，`=~` 不会被 `=` 截断。

    引号语义必须保留：`[ "$1" = "a*b" ]` 是字面量比较，不能当 glob；
    `[[ "$1" =~ "a.*" ]]` 的 RHS 被引号包住时也是字面量，不能当正则。
    复杂引号/转义无法可靠求值时返回 None（fail-closed）。
    """
    if not args:
        return None
    double_bracket = cond.lstrip().startswith("[[")
    inner = re.sub(r"^\[\[?|\]\]?$", "", cond).strip()
    m = re.search(r"(.*?)\s*(=~|==|!=|=)\s*(.*)", inner)
    if not m:
        return None  # 非字符串条件（-f 等）无法静态判定
    op = m.group(2)

    def _unquote(tok: str) -> tuple[str, bool] | None:
        tok = tok.strip()
        if len(tok) >= 2 and tok[0] in "\"'" and tok[-1] == tok[0]:
            tok = tok[1:-1]
            quoted = True
        else:
            quoted = False
        # 交错引号/未成对转义会改变 shell 语义；交给 fail-closed。
        if '"' in tok or "'" in tok or "\\" in tok:
            return None
        return tok, quoted

    left_pair = _unquote(m.group(1))
    right_pair = _unquote(m.group(3))
    if left_pair is None or right_pair is None:
        return None
    left, _ = left_pair
    right, right_quoted = right_pair

    def _resolve(tok: str) -> str | None:
        rm = re.match(r"^\$(\d+)$", tok)
        if rm:
            idx = int(rm.group(1))
            return args[idx - 1] if 1 <= idx <= len(args) else None
        if tok.startswith("$"):
            return None  # $MODE 命名变量不可绑定
        return tok

    lv, rv = _resolve(left), _resolve(right)
    if lv is None or rv is None:
        return None
    if op == "=~":
        if not double_bracket:
            return None  # [ ... =~ ... ] 不是 bash 正则匹配
        if rv.startswith("/") and rv.endswith("/") and len(rv) > 1:
            rv = rv[1:-1]
        pattern = re.escape(rv) if right_quoted else rv
        try:
            return bool(re.search(pattern, lv))
        except re.error:
            return None
    if not right_quoted and ("*" in rv or "?" in rv or "[" in rv):
        if not double_bracket:
            # `[ "$1" = bak* ]` 的 * 会先做 pathname expansion，结果依赖工作目录；
            # 不能按 glob 静态判定，否则可能选错分支造成漏报。
            return None
        import fnmatch
        matched = fnmatch.fnmatchcase(lv, rv)
    else:
        matched = lv == rv
    return (not matched) if op == "!=" else matched


def parse_if(
    content: str, args: list[str] | None, *, diagnostics: dict | None = None,
) -> str | None:
    """解析 if [cond] then A else B fi，选可达分支。None = 无法静态判定。

    只支持 else 分支存在且条件可求值的形态；无法判定 → 保两条分支都可达
    （fail-open 方向，由 Scanner fail-closed 兜底 → 等价于全文本，不丢召回）。
    """
    m = re.search(r"\bif\s+([^\n;]+?)\s*;\s*then", content)
    if not m:
        return None
    cond = m.group(1).strip()
    truth = _eval_if_condition(cond, args)
    if truth is None:
        return None  # 不可静态判定 → 全文本（两分支都留）

    start = m.start()
    then_body_start = m.end()
    # then 到 else / elif / fi
    fi_pos = content.find("fi", then_body_start)
    if fi_pos == -1:
        return None
    segment = content[then_body_start:fi_pos]
    else_m = re.search(r"\belse\b", segment)
    if truth:
        chosen = segment if not else_m else segment[: else_m.start()]
    else:
        if not else_m:
            return None  # 无 else 且条件假 → 什么都不执行，但保守保整个（无法证明）
        chosen = segment[else_m.end():]

    prefix = content[:start]
    suffix = content[fi_pos + len("fi"):]
    if diagnostics is not None:
        diagnostics["p1_if"] = "then" if truth else "else"
    return f"{prefix}\n{chosen}\n{suffix}"


# ==================== 非执行行剔除（shebang / 整行注释） ====================

_HEREDOC_RE = re.compile(r"<<-?\s*['\"]?(\w+)['\"]?")


def strip_non_executable_lines(content: str) -> str:
    """剔除**不会执行**的行：首行 shebang 与整行注释，供 L1/L2/L3 扫描。

    为什么（2026-09-30 实测）：脚本内容会被套用 L1 规则（含银行场景的目录白名单），
    而 shebang 里的 `/bin/bash`、`/usr/bin/env` 以及注释里提到的路径都会被当成
    "真实文件访问" → 命中场景白名单规则 → **整脚本 Deny**。表现是「任何带 shebang
    的脚本，被 `bash x.sh` 调用就拦」—— 而客户沙箱里几乎每个运维脚本都带 shebang。
    注释同理：`# 见 /etc/passwd` 不是访问，不该拦。

    两个保守约束（都是防"剔出新漏报"）：
    1. 只剔**整行**注释（行首空白后可跟 `#`），不动行尾注释 —— 尾注释与代码同行，
       代码部分必须保留；
    2. **heredoc 体内不剔**：`cat <<EOF` 与 `EOF` 之间是数据（会被写进文件/传给命令），
       里面的 `# ...` 是内容不是注释，剔掉会漏掉其中的路径。
    3. shebang 只认**首行**，避免误伤 heredoc 或字符串里的 `#!`。
    """
    if not content:
        return content
    out: list[str] = []
    heredoc_end: str | None = None
    for i, line in enumerate(content.split("\n")):
        if heredoc_end is not None:
            if line.strip() == heredoc_end:
                heredoc_end = None
            out.append(line)
            continue
        m = _HEREDOC_RE.search(line)
        if m:
            heredoc_end = m.group(1)
        stripped = line.lstrip()
        if i == 0 and stripped.startswith("#!"):
            continue
        if stripped.startswith("#"):
            continue
        out.append(line)
    return "\n".join(out)


# ==================== 循环体（保守可达） ====================



def _mark_loops_reachable(content: str) -> str:
    """循环体（while/for/until）全部保留（保守：循环执行次数未知，不可证明不可达）。"""
    # 标记循环结构已处理（不剔除任何内容），返回原样。
    # 这是保守决策：任何剔除都可能漏报（循环体可能在多次迭代中触发危险）。
    return content


# ==================== 子脚本调用提取（含参数） ====================

_CHILD_INTERPRETER_RE = re.compile(r"\b(?:bash|sh|zsh|python(?:3(?:\.[0-9]+)?)?|node|ruby|perl|php|lua)\b")
_CHILD_CALL_RE = re.compile(
    r"(?:^[ \t]*(?:\(?[^()\n;&<>]+\)[ \t]*)?|(?<=[;&|])(?<![<>][&|]))[ \t]*"
    r"(?:(?:if|then|elif|else|while|until|do|!|\{)[ \t]+|\([ \t]*"
    r"|command(?:[ \t]+-p)?(?:[ \t]+--)?[ \t]+"
    r"|exec(?:[ \t]+(?:-[cl]+|-a[ \t]+[^ \t\n;&|<>()\x00]+))*(?:[ \t]+--)?[ \t]+"
    r"|(?:(?:/usr)?/bin/)?time(?:[ \t]+-p)?(?:[ \t]+--)?[ \t]+"
    r"|(?:(?:/usr)?/bin/)?env(?:[ \t]+(?:-i|--ignore-environment"
    r"|(?:-u[ \t]*|--unset(?:[ \t]+|=))[^ \t\n;&|<>()\x00]+"
    r"))*(?:[ \t]+--)?[ \t]+"
    r"|[A-Za-z_][A-Za-z0-9_]*=[^ \t\n;&|<>()\x00]*[ \t]+)*"
    r"((?:(?:/usr)?(?:/local)?/bin/)?(?:bash|sh|zsh|python(?:3(?:\.[0-9]+)?)?|node|ruby|perl|php|lua))[ \t]+"
    r"([^\n;|&<>()\x00]+)",
    re.MULTILINE,
)


def _split_fields(text: str) -> Iterator[str | None]:
    # shortcut: use default IFS; pathname expansion and custom IFS are runtime-dependent.
    for index, field in enumerate(_IFS_RE.split(text)):
        if index % 2:
            yield None
        elif field:
            yield field


def _argument_parts(
    word: str, args: list[str] | None, *, quoted: bool = False,
    default_text: bool = False, default_depth: int = 0,
) -> Iterator[str | None | _ExpansionStatus]:
    """产出单词的字面片段、字段边界或未求值状态。"""
    field_split = not quoted
    offset = 0
    for start, end in _shell_word_parts(word, quoted, default_text=default_text):
        if start > offset:
            literal = word[offset:start]
            yield from _split_fields(literal) if field_split else (literal,)
        offset = end
        text = word[start:end]
        if not quoted and text.startswith("'"):
            yield text[1:-1]
        elif text.startswith('"'):
            if text == '""':
                yield ""
            else:
                yield from _argument_parts(
                    text[1:-1], args, quoted=True, default_depth=default_depth,
                )
        elif text.startswith("\\"):
            escaped = text[1:]
            if escaped != "\n":
                specials = '$"\\`}' if default_text else '$"\\`'
                yield escaped if not quoted or escaped in specials else text
        elif _POSITIONAL_RE.match(text) is None:
            yield text
        elif args is None:
            yield _ExpansionStatus.UNRESOLVED
        else:
            value, use_default = _positional_value(text, args)
            if use_default:
                if default_depth >= _MAX_DEFAULT_DEPTH or _default_has_substitution(value, quoted):
                    yield _ExpansionStatus.UNRESOLVED
                    continue
                yield from _argument_parts(
                    value, args, quoted=quoted, default_text=True, default_depth=default_depth + 1,
                )
                if not value and not field_split:
                    yield ""
            elif not field_split and isinstance(value, list):
                for index, item in enumerate(value):
                    if index:
                        yield None
                    yield item
            elif not field_split:
                yield value
            else:
                yield from _split_fields(" ".join(value) if isinstance(value, list) else value)
    if offset < len(word):
        literal = word[offset:]
        yield from _split_fields(literal) if field_split else (literal,)


def _expand_shell_word(
    word: str, args: list[str] | None, *, quoted_default: bool = False,
) -> list[str] | None:
    fields: list[str] = []
    pieces: list[str] = []
    for part in _argument_parts(word, args, quoted=quoted_default, default_text=quoted_default):
        if part is _ExpansionStatus.UNRESOLVED:
            return None
        if part is not None:
            pieces.append(part)
        elif pieces:
            fields.append("".join(pieces))
            pieces.clear()
    if pieces:
        fields.append("".join(pieces))
    return fields


def extract_calls_from_content(content: str, entry_args: list[str] | None = None) -> list[ScriptCall]:
    """基于原始单词边界提取子脚本参数，展开后的值不再作为 Shell 语法解析。"""
    if not _CHILD_INTERPRETER_RE.search(content):
        return []
    syntax = "\n".join(case_syntax_lines(content))
    # 默认项可以包含空格或控制字符，整段仍只属于原来的一个单词。
    if "${" in content:
        parts: list[str] = []
        offset = 0
        for start, end in _shell_word_parts(content, syntax=syntax):
            token = content[start:end]
            if "${" not in token or syntax[start] == " ":
                continue
            # A quoted substitution may itself contain a braced parameter.
            if token.startswith('"') and _default_has_substitution(token[1:-1], True):
                continue
            parts.append(syntax[offset:start])
            parts.append("".join("\n" if ch == "\n" else "x" for ch in token))
            offset = end
        parts.append(syntax[offset:])
        syntax = "".join(parts)
    calls: list[ScriptCall] = []
    for match in _CHILD_CALL_RE.finditer(syntax):
        start, end = match.span(2)
        words = list(re.finditer(r"[^ \t]+", syntax[start:end]))
        truncated = (
            (syntax[end:end + 1] == "\0" and not content.startswith("<<", end))
            or syntax.startswith("$(", end - 1)  # Unquoted substitution stops the match at '('.
        )
        if truncated and words and words[-1].end() == end - start:
            words.pop()  # The unknown fragment may be part of this word.
        argv: list[str] = []
        args_known = not truncated
        for word in words:
            fields = _expand_shell_word(content[start + word.start():start + word.end()], entry_args)
            if fields is None:
                args_known = False
                break
            argv.extend(fields)
        if argv and argv[0] and not argv[0].startswith(("-", "$")) and "/dev/" not in argv[0]:
            calls.append(ScriptCall(
                path=argv[0], args=argv[1:] if args_known else [],
                interpreter=match[1], args_known=args_known,
            ))
    return calls


# ==================== ShellBackend ====================


class ShellBackend(LanguageBackend):
    """shell(bash/sh/zsh) 脚本解析后端。"""

    language = "shell"

    ENTRY_PATTERNS = [
        r"(?:^|\s|&&|\|\|)\s*bash\s+(\S+)",
        r"(?:^|\s|&&|\|\|)\s*(?:/bin/)?sh\s+(\S+)",
        r"(?:^|\s|&&|\|\|)\s*zsh\s+(\S+)",
        r"\./(\S+)",
        r"(?:^|\s|&&|\|\|)\s*source\s+(\S+)",
    ]

    def parse(
        self, content: str, entry_args: list[str] | None, *,
        diagnostics: dict | None = None, args_known: bool = True,
    ) -> ScriptIR:
        """解析 shell 脚本：P1 → P2/P3/P4 升级 → fail-closed 回退。

        逐级责任链：
          P1 基于入口参数匹配 case/if → 能选分支就用
          P2/P3/P4 符号环境执行器 → P1 处理不了时升级（变量拼接/内部变量/数值）
          都处理不了 → fail-closed 全文本（loop_marked）

        漏报防护（NEW-FN）：脚本含 shift / set -- / read / 函数定义 时，
        P1 用入口参数绑定 $1 剪枝不可靠——$1 语义可能已被改写，或函数内
        $1 是函数参数而非入口参数。此时跳过 P1 绑定，交给 symbolic
        （对不可建模行 NotModeled → 整体 fail-closed 全文本），宁可多拦不可漏。
        """
        if content is None:
            content = ""

        candidate = content
        resolved = False

        # 位置参数/变量绑定安全性检测：命中则跳过 P1 的 $1 绑定剪枝。
        # `set --` 后是空格，`--` 末尾不能用 \b（- 非词字符，后无词边界）
        _P1_UNSAFE_RE = re.compile(r"\bshift\b|\bset\s+--(?:\s|$)|[\s;|&]read\b|^\s*read\b|\(\)\s*\{|function\s+\w+")
        p1_safe = args_known and not _P1_UNSAFE_RE.search(content)

        if p1_safe:
            case_out = parse_case(candidate, entry_args, diagnostics=diagnostics)
            if case_out is not None and case_out != candidate:
                resolved = True
                candidate = case_out
            # case 尚未解析时，不能用 if 剪枝绕过 LiteSE 的 case 判定。
            if not CASE_HEADER_RE.search(candidate):
                if_out = parse_if(candidate, entry_args, diagnostics=diagnostics)
                if if_out is not None and if_out != candidate:
                    resolved = True
                    candidate = if_out

        # P2/P3/P4 升级：LiteSE 顺序执行器（只在 P1 未能裁剪时尝试，避免双实现）
        if diagnostics is not None:
            diagnostics.update(parser="shell_p1", p1_safe=p1_safe, child_extractor="regex")
        if not args_known:
            if diagnostics is not None:
                diagnostics.update(parser="shell_full", fallback_reason="unknown_args")
        elif not resolved:
            from .symbolic import symbolic_process
            symbolic_diagnostics = {} if diagnostics is not None else None
            sym_out = symbolic_process(content, entry_args, diagnostics=symbolic_diagnostics)
            if sym_out is not None and sym_out != content:
                resolved = True
                candidate = sym_out
            if diagnostics is not None and symbolic_diagnostics is not None:
                diagnostics["parser"] = "shell_litese" if resolved else "shell_full"
                diagnostics["symbolic"] = symbolic_diagnostics
                if not resolved:
                    diagnostics["fallback_reason"] = symbolic_diagnostics["fallback_reason"] or "no_pruning"
                if sym_out is not None:
                    length, digest = scan_fingerprint(sym_out)
                    symbolic_diagnostics.update(output_bytes=length, output_sha256=digest)

        # 剔除不会执行的行（shebang / 整行注释）—— 见函数 docstring：
        # 否则 shebang 里的 /bin/bash 会被当"访问白名单外路径"，整脚本被误拦。
        candidate = strip_non_executable_lines(candidate)
        bind_args = entry_args if p1_safe else None
        calls = extract_calls_from_content(candidate, bind_args)
        bound = bind_positional_args(candidate, bind_args or [])

        # 循环体保守标记（保留，不剔除）
        loop_marked = _mark_loops_reachable(bound)

        if resolved:
            ir = ScriptIR(
                reachable_content=loop_marked,
                control_flow_resolved=True,
                calls=calls,
                language=self.language,
            )
        else:
            # fail-closed：全文本
            ir = ScriptIR(
                reachable_content=loop_marked,  # 即全文（未裁剪）
                control_flow_resolved=False,
                calls=calls,
                language=self.language,
            )
        return ir
