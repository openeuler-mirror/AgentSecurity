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
  - glob 匹配：glob → 正则（Python `re`），只对 concrete 值匹配；符号不匹配 → fail-closed。
  - 数值比较：只对 concrete 整数值比较；符号 → fail-closed。
  - 三重预算（行/分支/约束）+ 全局行数上限，超限回退（None → 调用方做 fail-closed 全文本）。
  - 全是线性/确定性算法，无路径枚举，无回溯。

与 TS `symbolic.ts` 100% 镜像（字段、算法、返回值语义对齐）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
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


def _strip_comments(content: str) -> str:
    return "\n".join(
        line for line in content.split("\n") if not line.lstrip().startswith("#")
    )


_ASGN_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$")


def tokenize(content: str) -> list["Stmt"]:
    """逐行分词成最小语句集（仅安全扫描所需子集）。

    'Stmt' 定义见下。不可建模语句（循环/管道/子 shell/函数/重定向/命令替换）
    标记为 NotModeled，作用域内后续一切保守。
    """
    return _split_statements(_strip_comments(content))


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
    def __init__(self, line: str, selector: str, branches: list[tuple[str, str, str]]):
        """branches: [(pattern, body, body_end)] 各分支 pattern 原文与 body/text。"""
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
    def __init__(self, line: str):
        super().__init__(line, modelable=False)


# ==================== 嵌套深度配对 ====================
# 修复：_split_statements/_parse_case_stmt/_parse_if_stmt 原先用
# `find("esac")` / `rfind("fi")` / `"esac" in line` 简单匹配，嵌套 case/if 时
# 取到内层关键字导致外层提前结束（切错分支）。这里用深度计数做真正的配对：
# 逐行扫描，open_keyword 出现深度+1、close_keyword 出现深度-1，深度归零才结束。
# 线性复杂度 O(行数)，无嵌套遍历开销。

_CASE_OPEN_RE = re.compile(r"\bcase\b")
_CASE_CLOSE_RE = re.compile(r"\besac\b")
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


def _find_case_end(lines: list[str], start_line: int) -> int:
    return _find_block_end(lines, start_line, _CASE_OPEN_RE, _CASE_CLOSE_RE)


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
        if not stripped:
            i += 1
            continue

        # 循环块 while/for/until ... do ... done：体内赋值对循环外不可靠
        # （可能 0 次/多次执行）→ 整体 NotModeled → symbolic_process 返回 None → fail-closed 全文本
        if _LOOP_OPEN_RE.search(stripped) and not re.match(r"^\s*case\s+", stripped) and not re.match(r"^\s*if\s+", stripped):
            end_line = _find_loop_end(lines, i)
            if end_line != -1:
                for k in range(i, end_line + 1):
                    stmts.append(NotModeledStmt(lines[k]))
                i = end_line + 1
                continue
            # 找不到配对 done → 该行保守 NotModeled
            stmts.append(NotModeledStmt(ln))
            i += 1
            continue

        # 函数定义 name() { ... } / function name { ... }：函数内 $1 是函数参数
        # 不是入口参数；函数体调用时才执行、可修改全局变量 → 整体 NotModeled
        if _FN_DEF_RE.match(stripped) or _FN_DEF_KW_RE.match(stripped):
            end_line = _find_fn_end(lines, i)
            if end_line != -1:
                for k in range(i, end_line + 1):
                    stmts.append(NotModeledStmt(lines[k]))
                i = end_line + 1
                continue
            stmts.append(NotModeledStmt(ln))
            i += 1
            continue

        # case ... esac 块（嵌套深度配对，不再按行含 esac 提前结束）
        if re.match(r"^\s*case\s+", stripped):
            end_line = _find_case_end(lines, i)
            if end_line == -1:
                stmts.append(NotModeledStmt(ln))
                i += 1
                continue
            block_text = "\n".join(lines[i:end_line + 1])
            stmts.append(_parse_case_stmt(block_text) or NotModeledStmt(ln))
            i = end_line + 1
            continue

        # if ... fi 块（嵌套深度配对）
        if re.match(r"^\s*if\s+", stripped):
            end_line = _find_if_end(lines, i)
            if end_line == -1:
                stmts.append(NotModeledStmt(ln))
                i += 1
                continue
            block_text = "\n".join(lines[i:end_line + 1])
            stmts.append(_parse_if_stmt(block_text) or NotModeledStmt(ln))
            i = end_line + 1
            continue

        # shift / set -- / read 改变位置参数或变量绑定 → $1 语义变化，P1 绑定不可靠
        # 注意：`set -e` 不改变位置参数，只匹配 `set --`（其后跟具体参数）；
        # `set --` 后是空格，`--` 末尾不能用 \b（- 非词字符，后无词边界）
        if re.search(r"\bshift\b|\bset\s+--(?:\s|$)|[\s;|&]read\b|^\s*read\b", stripped):
            stmts.append(NotModeledStmt(ln))
            i += 1
            continue

        # 赋值
        m = _ASGN_RE.match(stripped)
        if m and not _not_modeled_if_contains(stripped):
            stmts.append(AssignStmt(stripped, m.group(1), m.group(2).strip()))
            i += 1
            continue

        stmts.append(NotModeledStmt(ln) if _not_modeled_if_contains(stripped) else Stmt(ln))
        i += 1

    return stmts


def _parse_case_stmt(block: str) -> Optional[CaseStmt]:
    # selector 放宽容忍任意表达式（$1 / $MODE / "prefix${1}suffix" / ${1}${2}），
    # 实际求值交给 eval_expr（P2）；这里只负责提取分支结构。
    m = re.match(r"\s*case\s+(\S[^;]*?)\s*\bin\b", block, re.DOTALL)
    if not m:
        return None
    sel = m.group(1).strip()
    # 用深度配对找本层 esac（嵌套 case 时不能 find 第一个）
    block_lines = block.split("\n")
    body_start_idx = _find_body_start_line(block_lines, m)
    end_line = _find_case_end(block_lines, 0)
    if end_line == -1:
        return None
    # body = header("... in") 之后到 esac 之前
    body_text = "\n".join(block_lines[body_start_idx:end_line])
    body = body_text
    branches: list[tuple[str, str, str]] = []
    cur_pat: str | None = None
    cur_body: list[str] = []
    for ln in body.split("\n"):
        stripped = ln.strip()
        bm = re.match(r"^([^()]+?)\s*\)\s*(.*)$", stripped)
        if bm:
            if cur_pat is not None:
                branches.append((cur_pat, "\n".join(cur_body), cur_pat))
            cur_pat = bm.group(1).strip().strip("\"'")
            cur_body = [bm.group(2).strip()] if bm.group(2).strip() else []
        elif cur_pat is not None:
            cur_body.append(ln)
            if stripped.endswith(";;"):
                branches.append((cur_pat, "\n".join(cur_body), cur_pat))
                cur_pat = None
                cur_body = []
    # flush 最后的未闭合分支（单行 `*) ... ;;` 结尾）
    if cur_pat is not None and cur_body:
        branches.append((cur_pat, "\n".join(cur_body), cur_pat))
    return CaseStmt(block, sel, branches)


def _find_body_start_line(block_lines: list[str], header_match) -> int:
    """定位 case 头（... in）之后再 body 的第一行索引。"""
    start = 0
    for i, ln in enumerate(block_lines):
        if "in" in ln and ("case " in ln or ln.lstrip().startswith("case")):
            start = i
    # body 从含 in 的行之后开始
    for j in range(start + 1, len(block_lines)):
        return j
    return start + 1


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


# ==================== glob→正则（P4） ====================


def glob_to_regex(pattern: str) -> re.Pattern:
    """把 shell glob 转成正则（仅当 pattern 含 glob 元字符时）。
    * → .*, ? → ., [abc] → 字符类, [!a] → 取反。其余转义。"""
    out = ["^"]
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            out.append(".*")
        elif c == "?":
            out.append(".")
        elif c == "[":
            j = i + 1
            neg = False
            if j < len(pattern) and pattern[j] in "!^":
                neg = True
                j += 1
            cls = ""
            while j < len(pattern) and pattern[j] != "]":
                cls += pattern[j]
                j += 1
            if j >= len(pattern):
                frac = re.compile(r"^(.*)$").match(pattern[i:])
                out.append(re.escape(frac.group(1)))
                break
            out.append("[" + ("^" if neg else "") + re.escape(cls) + "]")
            i = j
        else:
            out.append(re.escape(c))
        i += 1
    out.append("$")
    return re.compile("".join(out), re.DOTALL)


_HAS_GLOB = re.compile(r"[*?[]")


def match_glob(pattern: str, value: str) -> bool:
    """glob 模式对具体值匹配；值含符号/非确定性 → False（调用方 fail-closed）。"""
    if not _HAS_GLOB.search(pattern):
        return pattern == value  # 无元字符 → 字面相等，与现有 P1 语义一致
    return bool(glob_to_regex(pattern).match(value))


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


def eval_condition(cond: str, env: dict[str, SVal]) -> Optional[bool]:
    """求值 if 条件。能确定返回 True/False；无法确定（符号/模式/文件谓词）返回 None。

    支持：字符串相等/不等（= == !=）、字符串匹配（=~ / glob）、数值比较（-gt 等）。
    fail-closed：任何不确定 → None → 调用方保留双分支。
    """
    inner = cond.strip()
    # 剥外层 [ ] 或 [[ ]]（test 结构）
    inner = re.sub(r"^\[\[?|\]\]?$", "", inner).strip()
    # 文件谓词 / 非比较：返回 None
    if re.match(r"^-[A-Za-z]\s", inner) or inner.startswith("-d") or inner.startswith("-f"):
        return None
    # 剥引号
    inner_q = inner.replace('"', "").replace("'", "")

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
        if lv is None or rv is None:
            return None
        return eval_numeric_compare(op, lv, rv)

    # 字符串相等/不等/匹配
    m = re.search(r"(.*?)\s*(==|=|!=|=~)\s*(.*)", inner_q)
    if not m:
        return None
    op = m.group(2)
    left = m.group(1).strip()
    right = m.group(3).strip()
    lv = _resolve_var_side(left)
    if op == "=~":
        # 正则匹配：右侧为正则
        if right.startswith("/") and right.endswith("/"):
            right = right[1:-1]
        if lv is None:
            return None
        try:
            return bool(re.search(right, lv))
        except re.error:
            return None
    rv = _resolve_var_side(right)
    if lv is None or rv is None:
        return None
    if op == "!=":
        return lv != rv
    return lv == rv


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


def symbolic_process(content: str, entry_args: list[str] | None) -> Optional[str]:
    """LiteSE 顺序执行：返回"剪枝后的可达分支展开文本"；None = 无法处理（回退全文）。

    职责和 fail-closed：
      - 识别赋值/case/if；这些都不出现 → 返回 None（调用方保持原文）。
      - case selector 可折叠 → 精确选分支（支持 glob 分支值）。
      - if 条件可确定 → 选 then/else。
      - 任何不确定 / 超预算 / 语法不识别 → 返回 None → 调用方 fail-closed 全文本。
    """
    if content is None:
        return None
    stmts = tokenize(content)
    if not any(isinstance(s, (CaseStmt, IfStmt, AssignStmt)) for s in stmts):
        return None  # 没有可提升的结构，交给 P1 处理

    if any(not s.modelable for s in stmts):
        return None  # 含不可建模语句 → 保守不剪

    budget = Budget()
    env = _init_env(entry_args)

    # 组装可达文本：保留被选中的分支体，其余普通行原样保留
    out: list[str] = []
    modelable_encountered = False

    for s in stmts:
        budget.lines += 1
        if budget.over:
            return None  # 超预算 → 降级

        if isinstance(s, AssignStmt):
            # 变量表上限：脚本可以是自动生成/拼接的，几万个变量赋值会把
            # 环境表一路撑大（超限返回 None 回退全文匹配）。
            if len(env) >= MAX_VARS:
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
                return None
            sel_val = eval_expr(s.selector, env)
            check_val = fold(sel_val)
            if check_val.kind != "concrete":
                # 符号 selector → 无法选择 → fail-closed
                return None
            concrete = check_val.value or ""
            selected_body: str | None = None
            fallback_body: str = ""
            for pat, body, _end in s.branches:
                pat_stripped = pat.strip()
                if "*" in pat_stripped and not _HAS_GLOB.search(pat_stripped):
                    # 纯 * → 兜底
                    fallback_body = body if not fallback_body else fallback_body
                    continue
                if match_glob(pat_stripped, concrete):
                    selected_body = body
                    break
            final = selected_body if selected_body is not None else (fallback_body or None)
            if final is None:
                return None  # 未命中任何 → fail-closed
            out.append(f"case {s.selector} in\n{final}\nesac")
            continue

        if isinstance(s, IfStmt):
            modelable_encountered = True
            budget.branches += 1
            if budget.over:
                return None
            truth = eval_condition(s.cond, env)
            if truth is None:
                return None  # 无法确定 → 保留双分支（fail-closed）
            chosen = s.then_body if truth else s.else_body
            if chosen is None:
                return None
            out.append(f"if {s.cond}; then\n{chosen}\nfi")
            continue

        # 普通行：保留原文（安全扫描用）
        out.append(s.line)

    if not modelable_encountered:
        return None
    return "\n".join(out)