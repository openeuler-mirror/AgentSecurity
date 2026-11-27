"""符号环境轻量执行器（LiteSE 核心，Python 端）。

在现有 P1（字面量替换 + case/if 字符串相等）处理不了时升级接管，解决：
  1. 变量拼接展开：`case "prefix${1}suffix"` / `case ${1}${2}`
  2. 内部命名变量追踪：`MODE=clean; case $MODE in ...`
  3. glob 通配符分支：`case $1 in bak*)`
  4. 数值条件分支：`if [ "$1" -gt 5 ]`

设计原则（对齐总方案 + 性能红线）：
  - SVal 统一表示具体值 / 未解析的符号 / 表达式（可折叠为 concrete）。
  - 顺序执行脚本，维护 `env` 符号环境（变量名 → SVal）。
  - case/if 分支：selector/条件先查环境折叠成 concrete → 精确匹配；无法折叠 → 保留全部分支（fail-closed）。
  - case 模式匹配：P1 与 LiteSE 共用，无法建模时保留全文。
  - 数值比较：只对 concrete 整数值比较；符号 → fail-closed。
  - 三重预算（行/分支/约束）+ 全局行数上限，超限回退（None → 调用方做 fail-closed 全文本）。
  - 全是线性/确定性算法，无路径枚举，无回溯。

与 TS 端共享符号执行约定。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Optional

# ==================== 预算（P5 熔断） ====================
MAX_LINES = 500            # 单脚本最大解析有效行
MAX_BRANCHES = 50          # 最多处理的分支数
MAX_VARS = 200             # 环境变量数上限（防变量注入表膨胀）


# ==================== SVal ====================


@dataclass
class SVal:
    """统一符号值。concrete: 可匹配进位；symbol: 未解析；expr: 表达式节点。"""

    kind: str            # "concrete" | "symbol" | "expr"
    value: Optional[str] = None      # concrete: 字符串；symbol: 变量名（如 "$1"/"MODE"）
    children: list["SVal"] = field(default_factory=list)  # expr: 子节点
    op: str = ""         # expr: 文本拼接

    @staticmethod
    def conc(base: str) -> "SVal":
        return SVal(kind="concrete", value=base)

    @staticmethod
    def sym(name: str) -> "SVal":
        return SVal(kind="symbol", value=name)

    @staticmethod
    def expr(children: list["SVal"]) -> "SVal":
        return SVal(kind="expr", children=children, op="+")


def fold(val: SVal) -> SVal:
    """折叠 expr：子节点全 concrete 合并为 concrete；含 symbol 则降为 symbol。

    fail-closed 方向：含 symbol 一律保守处理（保留分支），不做激进折叠。
    """
    if val.kind != "expr":
        return val
    parts = []
    for c in val.children:
        cc = fold(c)
        if cc.kind == "concrete":
            parts.append(cc.value or "")
        else:
            return cc  # symbol → 返回第一个 symbol（无法折叠）
    return SVal.conc("".join(p for p in parts if p))


# ==================== 分词：从脚本文本提取最小语句集 ====================


_ASGN_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$")


def tokenize(content: str) -> list["Stmt"]:
    """逐行分词成最小语句集（仅安全扫描所需子集）。

    'Stmt' 定义见下。不可建模语句（循环/管道/子 shell/函数/重定向/命令替换）
    标记为 NotModeled，作用域内后续一切保守。
    """
    return _split_statements(content)


# ==================== 语句模型 ====================

class Stmt:
    """语句基类：line 保留原文，modelable 标记是否可建模。"""

    line: str
    modelable: bool

    def __init__(self, line: str, modelable: bool = True):
        self.line = line
        self.modelable = modelable


class AssignStmt(Stmt):
    def __init__(self, line: str, name: str, rhs: str):
        super().__init__(line)
        self.name = name
        self.rhs = rhs


class CaseStmt(Stmt):
    def __init__(self, line: str, selector: str, branches: list[tuple[str, str]]):
        """branches 中保存每个分支的原始模式和分支体。"""
        super().__init__(line)
        self.selector = selector
        self.branches = branches


class IfStmt(Stmt):
    def __init__(self, line: str, cond: str, then_body: str, else_body: Optional[str]):
        super().__init__(line)
        self.cond = cond
        self.then_body = then_body
        self.else_body = else_body


class NotModeledStmt(Stmt):
    def __init__(self, line: str, reason: str = "unsupported"):
        super().__init__(line, modelable=False)
        self.reason = reason


# ==================== 嵌套深度配对 ====================
# 修复：_split_statements/parse_case_statement/_parse_if_stmt 原先用
# `find("esac")` / `rfind("fi")` / `"esac" in line` 简单匹配，嵌套 case/if 时
# 取到内层关键字导致外层提前结束（切错分支）。这里用深度计数做真正的配对：
# 逐行扫描，open_keyword 出现深度+1、close_keyword 出现深度-1，深度归零才结束。
# 线性复杂度 O(行数)，无嵌套遍历开销。

CASE_HEADER_RE = re.compile(r"^[ \t]*case[ \t]+", re.MULTILINE)
_CASE_COMMAND_START = (
    r"(?:^|(?<=[;|&()]))[ \t]*"
    r"(?:(?:if|then|elif|else|while|until|do|\{|!|time(?:[ \t]+-p)?(?:[ \t]+--)?)[ \t]+)*"
)
_COPROC_PREFIX = r"coproc[ \t]+(?:[^\s;&|()<>]+[ \t]+)?"
_CASE_OPEN_RE = re.compile(
    _CASE_COMMAND_START + rf"(?:{_COPROC_PREFIX})?case[ \t]+(?=[^\s;&|()<>])"
)
_COPROC_GROUP_RE = re.compile(
    _CASE_COMMAND_START + _COPROC_PREFIX
    + r"(?:(?:\{|if|for|while|until|select)(?=$|[\s;&|()<>])|\()"
)
_CASE_FUNCTION_RE = re.compile(
    _CASE_COMMAND_START
    + r"(?:function[ \t]+[^\s;&|()<>]+|(?P<name>[^\s;&|()<>]+)[ \t]*\([ \t]*\))"
)
_CASE_ARRAY_ASSIGNMENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\[.+\])?\+?=")
_CASE_CLOSE_RE = re.compile(r"(?:^|(?<=[;&]))[ \t]*esac(?=$|[ \t;&|])")
_CASE_HEADER_LINE_RE = re.compile(r"[ \t]*case[ \t]+([^\s;&|()<>]+)(?:[ \t]+(in))?[ \t]*")
_IF_OPEN_RE = re.compile(r"\bif\b")
_IF_CLOSE_RE = re.compile(r"\bfi\b")


def _find_block_end(
    lines: list[str],
    start_line: int,
    open_re: re.Pattern,
    close_re: re.Pattern,
) -> int:
    """从 start_line 起找与第一个 open 配对的 close 所在行号（含）。

    Returns:
        匹配的行号（-1 表示未找到闭合）。
    """
    depth = 0
    for idx in range(start_line, len(lines)):
        ln = lines[idx]
        # 用词边界避免 `fi` 匹配到 `file`、`esac` 匹配到 `esac` 等误判
        opens = len(open_re.findall(ln))
        closes = len(close_re.findall(ln))
        depth += opens - closes
        if depth <= 0 and idx > start_line:
            return idx
    return -1


def _case_depth_delta(line: str, raw_line: str) -> int | None:
    """在已遮蔽的语法行中识别命令边界；无法可靠配对时返回 None。"""
    if _COPROC_GROUP_RE.search(line):
        return None  # coproc 命令组可能在同一行开启内层 case。
    for function in _CASE_FUNCTION_RE.finditer(line):
        start, end = function.span("name")
        # 遮蔽后的函数名可能看起来像赋值，按原始文本识别空数组。
        if (
            start < 0
            or raw_line[end] != "("
            or not _CASE_ARRAY_ASSIGNMENT_RE.fullmatch(raw_line[start:end])
        ):
            return None  # 函数体可能在同一行开启内层 case。
    opens = len(_CASE_OPEN_RE.findall(line))
    closes = list(_CASE_CLOSE_RE.finditer(line))
    if opens + len(closes) > 1 or (closes and closes[0].start() != 0):
        return None  # 行内 esac 或同一行的多层边界需要更完整的语法分析。
    return opens - len(closes)


def _find_case_end(lines: list[str], syntax_lines: list[str], start_line: int) -> int:
    depth = 0
    for index in range(start_line, len(lines)):
        delta = _case_depth_delta(syntax_lines[index], lines[index])
        if delta is None or (index == start_line and delta != 1):
            return -1
        depth += delta
        if depth == 0:
            return index
    return -1


def _find_if_end(lines: list[str], start_line: int) -> int:
    return _find_block_end(lines, start_line, _IF_OPEN_RE, _IF_CLOSE_RE)


_LOOP_OPEN_RE = re.compile(r"\b(?:while|for|until)\b")
_LOOP_DO_RE = re.compile(r"\bdo\b")
_LOOP_DONE_RE = re.compile(r"\bdone\b")


def _find_loop_end(lines: list[str], start_line: int) -> int:
    """从 start_line 起找与第一个 while/for/until 配对的 done 所在行号（含）。

    循环块（while/for/until ... do ... done）体内赋值对循环外不可靠
    （可能执行 0 次/多次），整体标记 NotModeled → 调用方 fail-closed 全文本。
    """
    depth = 0
    for idx in range(start_line, len(lines)):
        opens = len(_LOOP_DO_RE.findall(lines[idx]))
        closes = len(_LOOP_DONE_RE.findall(lines[idx]))
        depth += opens - closes
        if depth <= 0 and idx > start_line:
            return idx
    return -1


_FN_DEF_RE = re.compile(r"^\s*(?:function\s+)?[A-Za-z_][A-Za-z0-9_]*\s*\(\s*\)\s*\{")
_FN_DEF_KW_RE = re.compile(r"^\s*function\s+[A-Za-z_][A-Za-z0-9_]*\s*\{?")


def _find_fn_end(lines: list[str], start_line: int) -> int:
    """函数定义块（name() { ... }）结束行：{ +1, } -1 深度配对。"""
    depth = 0
    for idx in range(start_line, len(lines)):
        depth += lines[idx].count("{") - lines[idx].count("}")
        if depth <= 0 and idx > start_line:
            return idx
    return -1


# ==================== 语句切分 ====================


def _split_statements(content: str) -> list[Stmt]:
    """把脚本切成顺序执行的语句列表。

    只识别：赋值 / case ... esac / if ... fi / 普通行（其他）。
    普通行里含管道/子shell/命令替换/**重定向** 视为 NotModeled。
    不处理嵌套 case/if（识别到嵌套 marker 直接整体 NotModeled 保守）。
    """
    lines = content.split("\n")
    syntax_lines = case_syntax_lines(content) if CASE_HEADER_RE.search(content) else lines
    stmts: list[Stmt] = []
    i = 0
    n = len(lines)

    def _not_modeled_if_contains(line: str) -> bool:
        # 再考虑 sub-shell / 命令替换 / 管道 —— 保守标记
        if re.search(r"\$\(" , line) or re.search(r"`[^`]*`", line):
            return True
        return False

    while i < n:
        ln = lines[i]
        stripped = ln.strip()
        if not syntax_lines[i].strip() or stripped.startswith("#"):
            i += 1
            continue

        # 循环块 while/for/until ... do ... done：体内赋值对循环外不可靠
        # （可能 0 次/多次执行）→ 整体 NotModeled → symbolic_process 返回 None → fail-closed 全文本
        if _LOOP_OPEN_RE.search(stripped) and not re.match(r"^\s*case\s+", stripped) and not re.match(r"^\s*if\s+", stripped):
            end_line = _find_loop_end(lines, i)
            if end_line != -1:
                for k in range(i, end_line + 1):
                    stmts.append(NotModeledStmt(lines[k], "loop"))
                i = end_line + 1
                continue
            # 找不到配对 done → 该行保守 NotModeled
            stmts.append(NotModeledStmt(ln, "loop"))
            i += 1
            continue

        # 函数定义 name() { ... } / function name { ... }：函数内 $1 是函数参数
        # 不是入口参数；函数体调用时才执行、可修改全局变量 → 整体 NotModeled
        if _FN_DEF_RE.match(stripped) or _FN_DEF_KW_RE.match(stripped):
            end_line = _find_fn_end(lines, i)
            if end_line != -1:
                for k in range(i, end_line + 1):
                    stmts.append(NotModeledStmt(lines[k], "function"))
                i = end_line + 1
                continue
            stmts.append(NotModeledStmt(ln, "function"))
            i += 1
            continue

        if CASE_HEADER_RE.match(syntax_lines[i]):
            case = parse_case_statement(lines, syntax_lines, i)
            stmts.append(case if case is not None else NotModeledStmt(ln, "case_syntax"))
            i += 1 if case is None else case.line.count("\n") + 1
            continue

        # if ... fi 块（嵌套深度配对）
        if re.match(r"^\s*if\s+", stripped):
            end_line = _find_if_end(lines, i)
            if end_line == -1:
                stmts.append(NotModeledStmt(ln, "if_syntax"))
                i += 1
                continue
            block_text = "\n".join(lines[i:end_line + 1])
            stmts.append(_parse_if_stmt(block_text) or NotModeledStmt(ln, "if_syntax"))
            i = end_line + 1
            continue

        # shift / set -- / read 改变位置参数或变量绑定 → $1 语义变化，P1 绑定不可靠
        # 注意：`set -e` 不改变位置参数，只匹配 `set --`（其后跟具体参数）；
        # `set --` 后是空格，`--` 末尾不能用 \b（- 非词字符，后无词边界）
        if re.search(r"\bshift\b|\bset\s+--(?:\s|$)|[\s;|&]read\b|^\s*read\b", stripped):
            stmts.append(NotModeledStmt(ln, "positional_mutation"))
            i += 1
            continue

        # 赋值
        m = _ASGN_RE.match(stripped)
        if m and not _not_modeled_if_contains(stripped):
            stmts.append(AssignStmt(stripped, m.group(1), m.group(2).strip()))
            i += 1
            continue

        stmts.append(
            NotModeledStmt(ln, "command_substitution") if _not_modeled_if_contains(stripped) else Stmt(ln)
        )
        i += 1

    return stmts


_CASE_QUOTED_PART = r"""'[^']*'|"(?:\\[\s\S]|[^"\\])*"|\\[\s\S]"""
_CASE_QUOTED_RE = re.compile(_CASE_QUOTED_PART)
_CASE_SYNTAX_TOKEN_RE = re.compile(
    r"\#[^\n]*"
    rf"""|(?:{_CASE_QUOTED_PART}|[^\s;&|()<>'"\\\x60])+"""
    r"""|<<|['"\\\x60]"""
)
_CASE_LABEL_END_RE = re.compile(r"\s*\(?([^()]+)\)\s*")
_CASE_TERMINATOR_RE = re.compile(r";;&|;&|;;")


def case_syntax_lines(content: str) -> list[str]:
    """遮蔽注释和 shell 字面文本，保留控制符、换行及原始偏移。"""
    def mask_word(token: re.Match[str]) -> str:
        text = token[0]
        if text.startswith("#"):
            return " " * len(text)
        if text in ("<<", "'", '"', "\\", '`'):
            return "\0" * len(text)

        def mask_literal(part: re.Match[str]) -> str:
            literal = part[0]
            unsupported = literal == "\\\n" or (
                literal.startswith('"') and ("$(" in literal or '`' in literal)
            )
            mask = "\0" if unsupported else "x"
            return "".join("\n" if ch == "\n" else mask for ch in literal)

        return _CASE_QUOTED_RE.sub(mask_literal, text)

    return _CASE_SYNTAX_TOKEN_RE.sub(mask_word, content).split("\n")


def parse_case_statement(lines: list[str], syntax_lines: list[str], start: int) -> CaseStmt | None:
    """切分逐行 case 块，保留原始模式和嵌套分支。"""
    header = _CASE_HEADER_LINE_RE.fullmatch(syntax_lines[start])
    if header is None:
        return None
    body_start = start + 1
    if header[2] is None:
        while body_start < len(syntax_lines) and not syntax_lines[body_start].strip():
            body_start += 1
        if body_start == len(syntax_lines) or syntax_lines[body_start].strip() != "in":
            return None
        body_start += 1

    end = _find_case_end(lines, syntax_lines, start)
    if end < body_start or not re.fullmatch(r"\s*esac\s*;?\s*", syntax_lines[end]):
        return None
    if any("\0" in line or "$(" in line for line in syntax_lines[start:end + 1]):
        return None

    selector = lines[start][header.start(1):header.end(1)]
    branches: list[tuple[str, str]] = []
    label: str | None = None
    body: list[str] = []
    depth = 0
    for index in range(body_start, end):
        line, syntax = lines[index], syntax_lines[index]
        if label is None:
            if not syntax.strip():
                continue
            branch = _CASE_LABEL_END_RE.match(syntax)
            if branch is None:
                return None
            label = line[branch.start(1):branch.end(1)].strip()
            line, syntax = line[branch.end():], syntax[branch.end():]

        delta = _case_depth_delta(syntax, line)
        if delta is None or depth + delta < 0:
            return None
        depth += delta

        body.append(line)
        if depth == 0 and (terminator := _CASE_TERMINATOR_RE.search(syntax)):
            # ;& 和 ;;& 会继续执行或重新匹配后续分支，必须保留全文。
            if terminator[0] != ";;" or syntax[terminator.end():].strip():
                return None
            branches.append((label, "\n".join(body)))
            label, body = None, []

    if depth:
        return None
    if label is not None:
        branches.append((label, "\n".join(body)))
    return CaseStmt("\n".join(lines[start:end + 1]), selector, branches)


def _parse_if_stmt(block: str) -> Optional[IfStmt]:
    m = re.match(r"\s*if\s+([^\n;]+?)\s*;\s*then", block)
    if not m:
        return None
    cond = m.group(1).strip()
    block_lines = block.split("\n")
    fi_line = _find_if_end(block_lines, 0)
    if fi_line == -1:
        return None
    body = "\n".join(block_lines[1:fi_line])
    else_m = re.search(r"\belse\b", body)
    if else_m:
        then_body = body[: else_m.start()]
        else_body = body[else_m.end():]
    else:
        then_body = body
        else_body = None
    return IfStmt(block, cond, then_body, else_body)


# ==================== 表达式求值（P2） ====================


def eval_expr(text: str, env: dict[str, SVal]) -> SVal:
    """求值简单字符串表达式：字面量 + $var/${var} 拼接。返回 SVal。"""
    # 引号语义：
    #   "..." 内变量会展开（shell 双引号语义）→ 剥引号参与展开
    #   '...' 内变量不展开（shell 单引号语义）→ 整体按字面量（不识别变量）
    is_single_quoted = len(text) >= 2 and text[0] == "'" and text[-1] == "'"
    if len(text) >= 2 and text[0] in "\"'" and text[-1] == text[0]:
        text = text[1:-1]
    if is_single_quoted:
        return SVal.conc(text)  # 单引号：整体字面量，不展开变量

    # 先按变量引用切分
    result: list[SVal] = []
    # 切分 token：完整的 ${...} 算一个 token（旧写法 `\$\{?\d+\}?` 会把 `${1:-x}` 切成 `${1`
    # 加 `:-x}`，导致参数展开语法整体解析错乱）
    parts = re.split(r"(\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|\$\d+)", text)
    for p in parts:
        if not p:
            continue
        m = re.match(r"^\$\{([^}]*)\}$", p)
        if m:
            # 参数展开 ${var:-默认值} / ${var-默认值}（2026-09 补）
            # 历史实现把 `1:-deploy` 整个当变量名 → 查不到 → 符号值 → 无法剪枝 →
            # fail-closed 回全文本扫描 → **安全分支被过度拦截**。而
            # `MODE="${1:-deploy}"` 是真实脚本里极常见的写法（实测：用它时
            # `bash x.sh deploy` 会被判 Deny，只因为脚本另一分支里有危险命令）。
            _dm = re.match(r"^([A-Za-z_][A-Za-z0-9_]*|\d+):?-(.*)$", m.group(1), re.DOTALL)
            if _dm:
                _name, _default = _dm.group(1), _dm.group(2)
                _key = f"${_name}" if _name.isdigit() else _name
                _bound = env.get(_key)
                if _bound is not None and not (_bound.kind == "concrete" and not _bound.value):
                    result.append(_bound)
                else:
                    result.append(eval_expr(_default, env))
                continue
            # 数字位置参数
            if m.group(1).isdigit():
                numeric = m.group(1)
                v = env.get(f"${numeric}")
                result.append(v if v is not None else SVal.sym(f"${numeric}"))
            else:
                v = env.get(m.group(1))
                result.append(v if v is not None else SVal.sym(m.group(1)))
            continue
        m2 = re.match(r"^\$([A-Za-z_][A-Za-z0-9_]*|\d+)$", p)
        if m2:
            var = m2.group(1)
            # 命名变量键为 var（MODE）；位置参数键为 $N
            key = f"${var}" if var.isdigit() else var
            v = env.get(key)
            result.append(v if v is not None else SVal.sym(p))
            continue
        result.append(SVal.conc(p))
    if len(result) == 1:
        return fold(result[0])
    return fold(SVal.expr(result))


# ==================== case 模式匹配 ====================

# 只用 fnmatchcase 处理与 shell 语义一致的子集。
# shortcut: ^ 取反、复杂字符类、混合引号和展开交回全文，扩充语法时再建模。
_CASE_BARE_PATTERN = r"(?:[A-Za-z0-9_./:+,@%=-]|\*|\?|\[!?(?:[0-9]-[0-9]|[A-Za-z0-9_.])+\])+"
_CASE_PATTERN = rf"""(?:{_CASE_BARE_PATTERN}|'[^']*'|"[^"\\$\x60]*")"""
_CASE_PATTERN_RE = re.compile(_CASE_PATTERN)
_CASE_LABEL_RE = re.compile(rf"{_CASE_PATTERN}(?:[ \t]*\|[ \t]*{_CASE_PATTERN})*")


def match_glob(pattern: str, value: str) -> bool | None:
    """匹配已建模的单个 glob；返回 None 时不能安全剪枝。"""
    if _CASE_PATTERN_RE.fullmatch(pattern) is None:
        return None
    if pattern.startswith(("'", '"')):
        return pattern[1:-1] == value
    if not value.isascii() and ("?" in pattern or "[" in pattern):
        return None  # 字符宽度和字符类受 shell locale 影响。
    return fnmatchcase(value, pattern)


def select_case_branch(case: CaseStmt, value: str) -> tuple[int, str] | None:
    """按源代码顺序返回首个匹配；较早的分支无法判定时保留全文。"""
    for index, (label, _) in enumerate(case.branches):
        if _CASE_LABEL_RE.fullmatch(label) is None:
            return None
        for match in _CASE_PATTERN_RE.finditer(label):
            pattern = match[0]
            matched = match_glob(pattern, value)
            if matched is None:
                return None
            if matched:
                return index, "default" if pattern == "*" else "match"
    return None


# ==================== 数值比较（P4） ====================


def eval_numeric_compare(op: str, left: str, right: str) -> Optional[bool]:
    """数值比较：-gt/-lt/-eq/-ge/-le。只有两侧都能解析为 int 才比较；否则 None。"""
    try:
        li, ri = int(left), int(right)
    except ValueError:
        return None
    if op == "-gt":
        return li > ri
    if op == "-lt":
        return li < ri
    if op == "-eq":
        return li == ri
    if op == "-ge":
        return li >= ri
    if op == "-le":
        return li <= ri
    return None


# ==================== if 条件求值 ====================


def eval_condition(
    cond: str, env: dict[str, SVal], *, diagnostics: dict | None = None,
) -> Optional[bool]:
    """求值 if 条件。能确定返回 True/False；无法确定（符号/模式/文件谓词）返回 None。

    支持：字符串相等/不等（= == !=）、字符串匹配（=~ / glob）、数值比较（-gt 等）。
    fail-closed：任何不确定 → None → 调用方保留双分支。
    """
    if diagnostics is not None:
        diagnostics.pop("condition_operator", None)
        diagnostics.pop("condition_failure", None)
    inner = cond.strip()
    # 剥外层 [ ] 或 [[ ]]（test 结构）
    double_bracket = inner.startswith("[[")
    inner = re.sub(r"^\[\[?|\]\]?$", "", inner).strip()
    # 文件谓词 / 非比较：返回 None
    if re.match(r"^-[A-Za-z]\s", inner) or inner.startswith("-d") or inner.startswith("-f"):
        if diagnostics is not None:
            diagnostics["condition_failure"] = "unsupported_predicate"
        return None
    inner_q = inner.replace('"', "").replace("'", "")

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

    def _resolve_var_side(tok: str) -> Optional[str]:
        """把 token 解析为具体字符串；无法解析返回 None。"""
        # 纯字面量（非变量）
        if not tok.startswith("$"):
            return tok
        # 变量 → 查环境
        ev = eval_expr(tok, env)
        if ev.kind == "concrete":
            return ev.value
        return None

    # 数值比较：left OP right
    for op in ("-gt", "-lt", "-eq", "-ge", "-le"):
        opm = re.search(r"\s" + re.escape(op) + r"\s", inner_q)
        if not opm:
            continue
        left = inner_q[: opm.start()].strip()
        right = inner_q[opm.end():].strip()
        lv = _resolve_var_side(left)
        rv = _resolve_var_side(right)
        if diagnostics is not None:
            diagnostics["condition_operator"] = op
        if lv is None or rv is None:
            if diagnostics is not None:
                diagnostics["condition_failure"] = "unbound_operand"
            return None
        result = eval_numeric_compare(op, lv, rv)
        if result is None and diagnostics is not None:
            diagnostics["condition_failure"] = "not_integer"
        return result

    # 字符串相等/不等/匹配
    m = re.search(r"(.*?)\s*(=~|==|!=|=)\s*(.*)", inner)
    if not m:
        if diagnostics is not None:
            diagnostics["condition_failure"] = "unsupported_comparison"
        return None
    op = m.group(2)
    if diagnostics is not None:
        diagnostics["condition_operator"] = op
    left_pair = _unquote(m.group(1))
    right_pair = _unquote(m.group(3))
    if left_pair is None or right_pair is None:
        if diagnostics is not None:
            diagnostics["condition_failure"] = "unsupported_quoting"
        return None
    left, _ = left_pair
    right, right_quoted = right_pair
    lv = _resolve_var_side(left)
    if lv is None:
        if diagnostics is not None:
            diagnostics["condition_failure"] = "unbound_operand"
        return None
    if op == "=~":
        if not double_bracket:
            if diagnostics is not None:
                diagnostics["condition_failure"] = "unsupported_operator"
            return None
        rv = _resolve_var_side(right)
        if rv is None:
            if diagnostics is not None:
                diagnostics["condition_failure"] = "unbound_operand"
            return None
        if rv.startswith("/") and rv.endswith("/") and len(rv) > 1:
            rv = rv[1:-1]
        pattern = re.escape(rv) if right_quoted or right.startswith("$") else rv
        try:
            return bool(re.search(pattern, lv))
        except re.error:
            if diagnostics is not None:
                diagnostics["condition_failure"] = "invalid_regex"
            return None
    rv = _resolve_var_side(right)
    if rv is None:
        if diagnostics is not None:
            diagnostics["condition_failure"] = "unbound_operand"
        return None
    # 未加引号的变量/通配符在单括号 [ ] 里还可能发生 pathname expansion。
    glob = ("*" in rv or "?" in rv or "[" in rv)
    if not right_quoted and (glob or right.startswith("$")):
        if not double_bracket:
            if diagnostics is not None:
                diagnostics["condition_failure"] = "pathname_expansion"
            return None
        import fnmatch
        matched = fnmatch.fnmatchcase(lv, rv) if glob else lv == rv
    else:
        matched = lv == rv
    return (not matched) if op == "!=" else matched


# ==================== 执行器 ====================


def _init_env(entry_args: list[str] | None) -> dict[str, SVal]:
    env: dict[str, SVal] = {}
    if entry_args:
        for idx, a in enumerate(entry_args, start=1):
            env[f"${idx}"] = SVal.conc(a)
        env["$@"] = SVal.conc(" ".join(entry_args))
        env["$*"] = SVal.conc(" ".join(entry_args))
    return env


class Budget:
    """P5 熔断计数器。"""

    def __init__(self, max_lines=MAX_LINES, max_branches=MAX_BRANCHES):
        self.lines = 0
        self.branches = 0
        self.max_lines = max_lines
        self.max_branches = max_branches

    @property
    def over(self) -> bool:
        return self.lines > self.max_lines or self.branches > self.max_branches


def symbolic_process(
    content: str, entry_args: list[str] | None, *, diagnostics: dict | None = None,
) -> Optional[str]:
    """LiteSE 顺序执行：返回"剪枝后的可达分支展开文本"；None = 无法处理（回退全文）。

    职责和 fail-closed：
      - 识别赋值/case/if；这些都不出现 → 返回 None（调用方保持原文）。
      - case selector 可折叠 → 精确选分支（支持 glob 分支值）。
      - if 条件可确定 → 选 then/else。
      - 任何不确定 / 超预算 / 语法不识别 → 返回 None → 调用方 fail-closed 全文本。
    """
    def record_result(reason: str, budget: Budget | None = None, variables: int = 0) -> None:
        if diagnostics is not None:
            diagnostics.update(
                result="none" if reason else "text",
                fallback_reason=reason,
                lines=budget.lines if budget else 0,
                branches=budget.branches if budget else 0,
                variables=variables,
            )

    if diagnostics is not None:
        diagnostics.update(line_limit=MAX_LINES, branch_limit=MAX_BRANCHES, variable_limit=MAX_VARS)
    if content is None:
        record_result("empty")
        return None
    stmts = tokenize(content)
    if diagnostics is not None:
        diagnostics["statement_count"] = len(stmts)
        # Even a script with no modeled statements may contain an unsupported block.
        unsupported = next((s for s in stmts if isinstance(s, NotModeledStmt)), None)
        if unsupported is not None:
            diagnostics["unsupported"] = unsupported.reason
    if not any(isinstance(s, (CaseStmt, IfStmt, AssignStmt)) for s in stmts):
        record_result("no_modeled_statements" if stmts else "empty")
        return None  # 没有可提升的结构，交给 P1 处理

    if any(not s.modelable for s in stmts):
        record_result("unsupported_statement")
        return None  # 含不可建模语句 → 保守不剪

    budget = Budget()
    env = _init_env(entry_args)
    # 预算覆盖初始化入口（启动参数 + $@/$*）。超过上限 → 放弃精确分析、回退全文。
    if len(env) > MAX_VARS:
        record_result("variable_budget", budget, len(env))
        return None

    # 组装可达文本：保留被选中的分支体，其余普通行原样保留
    out: list[str] = []
    modelable_encountered = False
    choices = [] if diagnostics is not None else None
    if diagnostics is not None:
        diagnostics["choices"] = choices

    for s in stmts:
        budget.lines += 1
        if budget.over:
            record_result("line_budget", budget, len(env))
            return None  # 超预算 → 降级

        if isinstance(s, AssignStmt):
            # 变量表上限：脚本可以是自动生成/拼接的，几万个变量赋值会把
            # 环境表一路撑大（TS 侧同款保护，超限返回 None 回退全文匹配）。
            # 只限制“新增变量”；修改已有变量的值不增加表项，不应触发回退。
            if s.name not in env and len(env) >= MAX_VARS:
                record_result("variable_budget", budget, len(env))
                return None
            # 赋值：右值求值写入 env
            modelable_encountered = True
            val = eval_expr(s.rhs, env)
            env[s.name] = fold(val)
            out.append(s.line)  # 保留赋值行（无危险，但保留原文可被 L1 扫）
            continue

        if isinstance(s, CaseStmt):
            modelable_encountered = True
            budget.branches += len(s.branches)
            if budget.over:
                record_result("branch_budget", budget, len(env))
                return None
            sel_val = eval_expr(s.selector, env)
            check_val = fold(sel_val)
            if check_val.kind != "concrete":
                # 符号 selector → 无法选择 → fail-closed
                record_result("unbound_selector", budget, len(env))
                return None
            selection = select_case_branch(s, check_val.value or "")
            if selection is None:
                record_result("case_unresolved", budget, len(env))
                return None
            index, kind = selection
            if choices is not None and len(choices) < 4:
                label = "case_default" if kind == "default" else "case"
                choices.append(f"{label}:{index + 1}")
            out.append(f"case {s.selector} in\n{s.branches[index][1]}\nesac")
            continue

        if isinstance(s, IfStmt):
            modelable_encountered = True
            budget.branches += 1
            if budget.over:
                record_result("branch_budget", budget, len(env))
                return None
            truth = eval_condition(s.cond, env, diagnostics=diagnostics)
            if truth is None:
                record_result("condition_unresolved", budget, len(env))
                return None  # 无法确定 → 保留双分支（fail-closed）
            chosen = s.then_body if truth else s.else_body
            if chosen is None:
                record_result("missing_else", budget, len(env))
                return None
            if choices is not None and len(choices) < 4:
                choices.append("then" if truth else "else")
            out.append(f"if {s.cond}; then\n{chosen}\nfi")
            continue

        # 普通行：保留原文（安全扫描用）
        out.append(s.line)

    if not modelable_encountered:
        record_result("no_modeled_statements", budget, len(env))
        return None
    record_result("", budget, len(env))
    return "\n".join(out)
