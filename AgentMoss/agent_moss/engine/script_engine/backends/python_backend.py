"""脚本分析引擎 — PythonBackend

python（python3）脚本的静态解析后端，产出 IR。
用标准库 ast 解析（零第三方依赖、工业级），做控制流剪枝 + 子脚本调用提取。

控制流哲学（与 ShellBackend 一致：**能证明不可达才剔除，否则保留**）：
- sys.argv[N] 绑定入口参数（等价 shell 的 $N）
- 简单赋值追踪：mode = sys.argv[1] → if mode == "clean" 可静态判定
- if/elif 条件可静态求值 → 选分支；不可求值 → 全部保留（fail-closed，不漏报）
- if __name__ == "__main__" → 恒真（入口脚本，体必达）
- for/while/try/with 体 → 保留（执行次数/异常路径未知，不可证明不可达）；
  但体内的 if 仍按静态条件剪枝（同一执行环境）
- def/class 体 → 全部保留（调用时环境未知，不可证明不可达），不做内部剪枝

子脚本调用提取（RecursiveTracker 消费 calls 递归）：
- subprocess.run/call/Popen/check_call/check_output(["bash", "x.sh", arg]) → AST 列表形式
- subprocess.run("bash x.sh arg", shell=True) / os.system("bash x.sh arg") → 字符串形式（复用 shell 正则）
- from . import x / from .x import y → 本地相对导入（模块链追踪；绝对导入跳过，防 stdlib 噪音）

整文件 AST 超出行数预算或解析失败时，保留父脚本全文，只对已定位的短调用做局部解析。
"""

import ast
import io
import keyword
import os
import re
import tokenize
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import PurePath
from typing import Optional

from ..ir import BranchInfo, ScriptCall, ScriptIR, WorkingDirectory
from .base import LanguageBackend

# ==================== 预算（P5 熔断，与 symbolic.py 红线一致） ====================
MAX_LINES = 500
_MAX_FALLBACK_CALL_CHARS = 8192
_MAX_FALLBACK_CALL_DEPTH = 32

# ==================== 子脚本调用正则（字符串形式，与 shell_backend._CHILD_CALL_RE 同构） ====================
_CHILD_CALL_RE = re.compile(
    r"(?:^|\s|&&|\|\|)\s*"
    r"((?:/bin/)?bash|sh|zsh|(?:python|python3|node|ruby|perl|php|lua))\s+"
    r"(\S+(?:\.(?:sh|shrc|py|js|rb|pl|php|lua))?)"
    r"([^\n;|&]*?)$",
    re.MULTILINE | re.IGNORECASE,
)

# subprocess 调用函数名集合（列表/字符串两种形态都覆盖）
_SUBPROCESS_FUNCS = {"run", "call", "Popen", "check_call", "check_output"}
# os 调用函数名集合（字符串形态）
_OS_FUNCS = {"system", "popen", "popen2", "popen3", "popen4"}
_CWD_METHODS = {"chdir", "fchdir"}
_END_OF_STATEMENT = re.compile(r"[ \t]*(?:[;#]|$)")
_CALL_FUNCTIONS = {"os": _OS_FUNCS | _CWD_METHODS, "subprocess": _SUBPROCESS_FUNCS}
_SHELL_INTERPRETERS = frozenset({"bash", "dash", "sh", "zsh"})
_SCRIPT_INTERPRETERS = _SHELL_INTERPRETERS | {"python", "python3", "node", "ruby", "perl", "php", "lua"}
_VERSIONED_PYTHON = re.compile(r"python3\.[0-9]+t?")
_BARE_INTERPRETER_STARTS = _SCRIPT_INTERPRETERS | {"/"}
_OPEN_DELIMITERS = {"(": ")", "[": "]", "{": "}"}
_CLOSE_DELIMITERS = frozenset(_OPEN_DELIMITERS.values())
_FALLBACK_PYTHON_CALL_HINTS = tuple(
    (module, re.compile(rf"\b{module}\b"), re.compile(rf"\b(?:{'|'.join(sorted(methods))})\b"))
    for module, methods in _CALL_FUNCTIONS.items()
)
_BARE_CALL_HINT_RE = re.compile(r"(?:/bin/)?(?:bash|sh|zsh|python3?|node|ruby|perl|php|lua)[ \t]+", re.IGNORECASE)
_ASSIGNMENT_PREFIXES = ("=", ":=", "+=", "-=", "*=", "/=", "%=", "@=", "&=", "|=", "^=", "//=", "**=", "<", ">")
_FSTRING_START_RE = re.compile(r"(?i:fr?|rf)['\"]")
_PLAIN_STRING_ASSIGNMENT = re.compile(
    r"""[A-Za-z_]\w*[ \t]*=[ \t]*(?:"[^"\\]*"|'[^'\\]*')[ \t]*""", re.ASCII,
)


# ==================== 符号环境 ====================


@dataclass
class _Env:
    """Python 脚本静态符号环境：argv 绑定 + 简单变量追踪。"""

    argv: list[str] = field(default_factory=list)   # sys.argv[1:] = 入口参数
    vars: dict = field(default_factory=dict)        # name -> str | None（None = 未解析）

    conditions: dict[ast.If, bool | None] = field(default_factory=dict)

    @property
    def argv_len(self) -> int:
        """sys.argv 长度 = 入口参数数 + 1（argv[0] 是脚本名）。"""
        return len(self.argv) + 1


# ==================== 值求值（SVal 简化版：concrete str / None） ====================


def _eval_expr(node: ast.AST, env: _Env) -> Optional[str]:
    """把表达式静态求值为字符串；求不出返回 None（未解析）。"""
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (str, int, float, bool)):
            return str(node.value)
        return None
    if isinstance(node, ast.Name):
        return env.vars.get(node.id)  # None 表示未解析
    if isinstance(node, ast.Subscript):
        # sys.argv[1]
        if (
            isinstance(node.value, ast.Attribute)
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == "sys"
            and node.value.attr == "argv"
            and isinstance(node.slice, ast.Constant)
            and isinstance(node.slice.value, int)
        ):
            idx = node.slice.value
            if idx >= 1 and idx <= len(env.argv):
                return env.argv[idx - 1]
            return None
        return None
    if isinstance(node, ast.Attribute):
        # sys.argv 整体
        if (
            isinstance(node.value, ast.Name)
            and node.value.id == "sys"
            and node.attr == "argv"
        ):
            return env.argv[0] if env.argv else None
        return None
    if isinstance(node, ast.Call):
        # len(sys.argv)
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "len"
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Attribute)
            and isinstance(node.args[0].value, ast.Name)
            and node.args[0].value.id == "sys"
            and node.args[0].attr == "argv"
        ):
            return str(env.argv_len)
        # sys.argv[1] if ... else ... 的普通调用求不出
        return None
    if isinstance(node, ast.IfExp):
        # a if cond else b
        cond = _eval_condition(node.test, env)
        if cond is True:
            return _eval_expr(node.body, env)
        if cond is False:
            return _eval_expr(node.orelse, env)
        return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _eval_expr(node.left, env)
        right = _eval_expr(node.right, env)
        if left is not None and right is not None:
            return left + right
        return None
    return None


def _eval_condition(node: ast.AST, env: _Env) -> Optional[bool]:
    """把 if/elif 条件静态求值为 bool；求不出返回 None（fail-closed）。"""
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool):
            return node.value
        return None
    if isinstance(node, ast.Compare):
        # 仅支持单比较（a == b / a != b / a in (...)/ len(argv) > 1）
        if len(node.ops) != 1 or len(node.comparators) != 1:
            return None
        op = node.ops[0]
        left = node.left
        right = node.comparators[0]
        # __name__ == "__main__"
        if (
            isinstance(op, ast.Eq)
            and isinstance(left, ast.Name)
            and left.id == "__name__"
        ):
            rv = _eval_expr(right, env)
            if rv is not None:
                return rv == "__main__"
            return None
        if isinstance(op, (ast.Eq, ast.NotEq)):
            lv = _eval_expr(left, env)
            rv = _eval_expr(right, env)
            if lv is not None and rv is not None:
                return (lv == rv) if isinstance(op, ast.Eq) else (lv != rv)
            return None
        if isinstance(op, ast.In):
            lv = _eval_expr(left, env)
            if lv is None:
                return None
            # 右值必须是字面量元组/列表/集合/字符串
            if isinstance(right, (ast.Tuple, ast.List, ast.Set)):
                for elt in right.elts:
                    ev = _eval_expr(elt, env)
                    if ev is not None and ev == lv:
                        return True
                return False
            rv = _eval_expr(right, env)
            if rv is not None:
                return lv in rv
            return None
        if isinstance(op, (ast.Gt, ast.GtE, ast.Lt, ast.LtE)):
            # len(sys.argv) > 1 形态
            lv = _eval_expr(left, env)
            rv = _eval_expr(right, env)
            if lv is None or rv is None:
                return None
            try:
                ln, rn = int(lv), int(rv)
            except (TypeError, ValueError):
                return None
            if isinstance(op, ast.Gt):
                return ln > rn
            if isinstance(op, ast.GtE):
                return ln >= rn
            if isinstance(op, ast.Lt):
                return ln < rn
            return ln <= rn
        return None
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        v = _eval_condition(node.operand, env)
        return None if v is None else (not v)
    if isinstance(node, ast.BoolOp):
        # and / or：能确定则确定，否则 None
        values = []
        for v in node.values:
            values.append(_eval_condition(v, env))
        if isinstance(node.op, ast.And):
            if any(v is False for v in values):
                return False
            if all(v is True for v in values):
                return True
            return None
        # Or
        if any(v is True for v in values):
            return True
        if all(v is False for v in values):
            return False
        return None
    return None


# ==================== 行标记（重建 reachable_content） ====================


def _mark_node_lines(node: ast.AST, lines: set, source_lines: list) -> None:
    """把节点的源行加入可达行集合（含多行节点）。"""
    start = getattr(node, "lineno", None)
    end = getattr(node, "end_lineno", None)
    if start is None:
        return
    if end is None:
        end = start
    lines.update(range(max(1, start), min(end, len(source_lines)) + 1))


def _reconstruct(source_lines: list, lines: set) -> str:
    """按行号重建可达文本。"""
    return "\n".join(source_lines[i - 1] for i in sorted(lines) if 1 <= i <= len(source_lines))


# ==================== 控制流剪枝 ====================

# 纯函数白名单（调用不会修改脚本全局变量，安全不失效 env）
_PURE_BUILTINS = {
    "len", "print", "str", "int", "float", "bool", "list", "dict", "set",
    "tuple", "range", "sorted", "enumerate", "zip", "map", "filter",
    "sum", "min", "max", "abs", "round", "isinstance", "type", "open",
    "input", "repr", "ord", "chr", "hex", "oct", "bin", "format", "id",
    "hash", "any", "all", "next", "iter", "reversed", "pow", "divmod",
}


def _invalidate_env_on_calls(node: ast.AST, env: _Env) -> None:
    """node 内含非纯函数调用（用户函数等，可能修改全局变量）→ 全部 env 失效。

    关键安全点（漏报防护）：`def set_clean(): global mode; mode="clean"` 后调用
    `set_clean()`，env 里 mode 还是旧值 → 后续 `if mode == "clean"` 会误剪危险分支。
    无法静态证明调用不改全局 → 保守置未知（None），后续条件 fail-closed 全保留。
    """
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
            if sub.func.id not in _PURE_BUILTINS:
                for k in env.vars:
                    env.vars[k] = None
                return


def _process_stmts(stmts: list, env: _Env, source_lines: list, lines: set, branches: list) -> None:
    """顺序处理语句列表：赋值更新环境；if 剪枝；其余语句保守保留并递归。"""
    for stmt in stmts:
        _process_stmt(stmt, env, source_lines, lines, branches)


def _assigned_name(statement: ast.AST) -> str | None:
    if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
        target = statement.targets[0]
    elif isinstance(statement, ast.AnnAssign):
        target = statement.target
    else:
        return None
    return target.id if isinstance(target, ast.Name) else None


def _process_stmt(stmt: ast.AST, env: _Env, source_lines: list, lines: set, branches: list) -> None:
    # 赋值：更新变量环境（只追踪可静态求值的）；RHS 含非纯调用 → env 失效
    name = _assigned_name(stmt)
    if name is not None:
        if stmt.value is not None:
            _invalidate_env_on_calls(stmt.value, env)
            env.vars[name] = _eval_expr(stmt.value, env)
        if isinstance(stmt, ast.AnnAssign):
            _invalidate_env_on_calls(stmt.annotation, env)
        _mark_node_lines(stmt, lines, source_lines)
        return
    # 增强赋值 x += ...：变量变未知
    if isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
        _invalidate_env_on_calls(stmt.value, env)
        env.vars[stmt.target.id] = None
        _mark_node_lines(stmt, lines, source_lines)
        return
    # if / elif 链
    if isinstance(stmt, ast.If):
        _process_if(stmt, env, source_lines, lines, branches)
        return
    # 循环 / try / with / 其他：体全部保留（保守），体内 if 仍按静态条件剪枝。
    # 关键安全点（漏报防护）：循环体可能执行 0 次 / 多次、try 体可能抛异常中断、
    # with 体可能因 __enter__ 异常未执行——体内赋值对循环外不可靠，
    # 故用 env 副本处理体内，**不写回外部 env**（fail-closed：宁可多保留，不可漏）。
    if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
        _mark_node_lines(stmt, lines, source_lines)
        body_env = _Env(argv=env.argv, vars=dict(env.vars), conditions=env.conditions)
        _process_stmts(stmt.body, body_env, source_lines, lines, branches)
        if isinstance(stmt, ast.While):
            orelse_env = _Env(argv=env.argv, vars=dict(env.vars), conditions=env.conditions)
            _process_stmts(stmt.orelse, orelse_env, source_lines, lines, branches)
        return
    if isinstance(stmt, ast.Try):
        _mark_node_lines(stmt, lines, source_lines)
        for part in ([stmt.body] + [h.body for h in stmt.handlers if h.body] + [stmt.orelse] + [stmt.finalbody]):
            part_env = _Env(argv=env.argv, vars=dict(env.vars), conditions=env.conditions)
            _process_stmts(part, part_env, source_lines, lines, branches)
        return
    if isinstance(stmt, ast.With) or isinstance(stmt, ast.AsyncWith):
        _mark_node_lines(stmt, lines, source_lines)
        body_env = _Env(argv=env.argv, vars=dict(env.vars), conditions=env.conditions)
        _process_stmts(stmt.body, body_env, source_lines, lines, branches)
        return
    if isinstance(stmt, ast.Match):
        # match/case（3.10+）：无法静态判定 → 全保留；各 case 用副本 env（可能都不匹配）
        _mark_node_lines(stmt, lines, source_lines)
        for case in stmt.cases:
            case_env = _Env(argv=env.argv, vars=dict(env.vars), conditions=env.conditions)
            _process_stmts(case.body, case_env, source_lines, lines, branches)
        return
    # def/class 体内不做剪枝（保守）；但若体内有嵌套 if，不处理（保持 fail-closed）
    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        _mark_def_tree(stmt, lines, source_lines)
        return
    # import / 普通表达式等：全部保留。
    _mark_node_lines(stmt, lines, source_lines)
    # 顶层表达式语句（含 subprocess.run(...) / os.system(...) / 用户函数调用）：
    # 非纯函数调用（Name 形态）可能修改全局变量 → 失效 env（漏报防护）。
    if isinstance(stmt, ast.Expr):
        _invalidate_env_on_calls(stmt.value, env)


def _mark_def_tree(stmt: ast.AST, lines: set, source_lines: list) -> None:
    """保留定义及装饰器；解析器的定义范围已包含整个定义体。"""
    _mark_node_lines(stmt, lines, source_lines)
    # ast.parse 的顶层装饰器位于定义范围之前；内部定义的装饰器已在
    # 外层范围内。分别标记表达式，避免额外加入装饰器之间的空白/注释。
    for decorator in stmt.decorator_list:
        _mark_node_lines(decorator, lines, source_lines)


def _process_if(stmt: ast.If, env: _Env, source_lines: list, lines: set, branches: list) -> None:
    """处理 if/elif 链：条件可静态求值 → 选分支；否则整链保留（fail-closed）。"""
    cond = _eval_condition(stmt.test, env)
    env.conditions[stmt] = cond
    branches.append(BranchInfo(kind="if", label=ast.unparse(stmt.test) if stmt.test else "", reachable=cond is not False))
    # if 头（条件被求值）必达：只标条件行，不标整个 if/elif/else 块
    _mark_node_lines(stmt.test, lines, source_lines)

    if cond is True:
        # 本分支必达，else/elif 链剔除
        _process_stmts(stmt.body, env, source_lines, lines, branches)
        return
    if cond is False:
        # 本分支不可达；看 orelse（可能是 elif 或 else）
        if stmt.orelse:
            # orelse 是单一 If（elif）→ 继续判；否则 else 体可达
            if len(stmt.orelse) == 1 and isinstance(stmt.orelse[0], ast.If):
                _process_if(stmt.orelse[0], env, source_lines, lines, branches)
            else:
                _process_stmts(stmt.orelse, env, source_lines, lines, branches)
        return
    # 条件不可求值 → 本分支 + else 全保留（fail-closed）
    _process_stmts(stmt.body, env, source_lines, lines, branches)
    _process_stmts(stmt.orelse, env, source_lines, lines, branches)


# ==================== 子脚本调用提取 ====================


_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
_COLLECTION_CONSTRUCTORS = {"list", "tuple", "set", "frozenset", "dict"}


class _AstProcessCalls:
    """Evaluate bindings in statement order; the caller emits results in AST breadth-first order."""

    def __init__(self, reachable_lines: set | None, conditions: dict, source: str | None = None):
        self.source = source
        self.reachable_lines = reachable_lines
        self.conditions = conditions
        self.found: dict[ast.Call, list[ScriptCall]] = {}

    def block(self, statements, bindings):
        for statement in statements:
            # A visited if/elif is recorded by node. Its condition can start on
            # a later line than the keyword, so the keyword's line can be absent.
            if self.reachable_lines is None or statement.lineno in self.reachable_lines or statement in self.conditions:
                self.statement(statement, bindings)

    def statement(self, node, bindings):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            bindings._record_import(node)
            return
        if isinstance(node, ast.If):
            self.expression(node.test, bindings)
            decision = self.conditions.get(node)
            if decision is None:
                left, right = bindings.fork(), bindings.fork()
                self.block(node.body, left)
                self.block(node.orelse, right)
                bindings.merge([left, right])
            else:
                self.block(node.body if decision else node.orelse, bindings)
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = set(node.body)
            for child in ast.iter_child_nodes(node):
                if child not in body:
                    self.expression(child, bindings)
            if bindings.record_wrapper(node):
                return
            local = bindings.fork()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for argument in ast.walk(node.args):
                    if isinstance(argument, ast.arg):
                        local._forget(argument.arg)
                # A name assigned in this scope is local even before the assignment.
                pending = list(node.body)
                assigned = set()
                external = set()
                while pending:
                    part = pending.pop()
                    if isinstance(part, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        assigned.add(part.name)
                    elif isinstance(part, (ast.Global, ast.Nonlocal)):
                        external.update(part.names)
                    elif isinstance(part, ast.Name) and isinstance(part.ctx, (ast.Store, ast.Del)):
                        assigned.add(part.id)
                    elif isinstance(part, ast.alias):
                        assigned.add(part.asname or part.name.split(".")[0])
                    elif not isinstance(part, (ast.Lambda, ast.comprehension)):
                        pending.extend(ast.iter_child_nodes(part))
                for name in assigned - external:
                    local._forget(name)
            self.block(node.body, local)
            if isinstance(node, ast.ClassDef):
                bindings.cwd = local.cwd
            bindings._forget(node.name)
            return
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete)):
            targets = node.targets if isinstance(node, (ast.Assign, ast.Delete)) else [node.target]
            if isinstance(node, ast.AugAssign):
                self.expression(node.target, bindings)
            value = getattr(node, "value", None)
            if value is not None:
                self.expression(value, bindings)
            if not isinstance(node, ast.AugAssign):
                for target in targets:
                    self.expression(target, bindings)
            if _assigned_name(node) is not None:
                bindings.record_assignment(node, fields_already_evaluated=True)
            else:
                for target in targets:
                    self.forget_target(target, bindings)
            if isinstance(node, ast.AnnAssign):
                self.expression(node.annotation, bindings)
            return
        if isinstance(node, (ast.For, ast.AsyncFor)):
            self.expression(node.iter, bindings, consume_generator=True)
            body = bindings.fork()
            self.forget_target(node.target, body)
            self.block(node.body, body)
            bindings.merge([bindings, body])
            if node.orelse:
                on_exhaustion = bindings.fork()
                self.block(node.orelse, on_exhaustion)
                bindings.merge([bindings, on_exhaustion])
            return
        if isinstance(node, (ast.With, ast.AsyncWith)):
            body = bindings.fork()
            for item in node.items:
                self.expression(item.context_expr, body)
                if item.optional_vars is not None:
                    self.forget_target(item.optional_vars, body)
            self.block(node.body, body)
            bindings.merge([bindings, body])
            return
        if isinstance(node, ast.Expr):
            self.expression(node.value, bindings, standalone=True)
            return
        # Keep bindings common to the possible paths into the next suite.
        alternatives = []
        finalbody = ()
        for field_name, value in ast.iter_fields(node):
            if field_name == "finalbody":
                finalbody = value
                continue
            children = value if isinstance(value, list) else [value]
            if children and isinstance(children[0], (ast.stmt, ast.ExceptHandler, ast.match_case)):
                branch = bindings.fork()
                for child in children:
                    if isinstance(child, ast.stmt):
                        self.block([child], branch)
                    else:
                        arm = bindings.fork()
                        body = set(child.body)
                        for header in ast.iter_child_nodes(child):
                            if header not in body:
                                self.expression(header, arm)
                        if isinstance(child, ast.ExceptHandler) and child.name:
                            arm._forget(child.name)
                        self.block(child.body, arm)
                        alternatives.append(arm)
                if isinstance(children[0], ast.stmt):
                    alternatives.append(branch)
            else:
                for child in children:
                    if isinstance(child, ast.AST):
                        self.expression(child, bindings)
        if alternatives:
            bindings.merge([bindings, *alternatives])
        # A path that reaches the statement after try has completed finally.
        if finalbody:
            self.block(finalbody, bindings)

    @staticmethod
    def forget_target(target, bindings):
        for name in ast.walk(target):
            if isinstance(name, ast.Name) and isinstance(name.ctx, (ast.Store, ast.Del)):
                bindings._forget(name.id)

    def comprehension(self, node, bindings, *, consumed):
        # Python evaluates the first iterable outside the comprehension scope.
        first = node.generators[0]
        lazy = isinstance(node, ast.GeneratorExp)
        self.expression(first.iter, bindings, consume_generator=not lazy or consumed)
        if lazy and not consumed:
            # Creating a generator does not iterate it or run its result expression.
            return
        local = bindings.fork()
        targets = {name.id for gen in node.generators for name in ast.walk(gen.target)
                   if isinstance(name, ast.Name) and isinstance(name.ctx, ast.Store)}
        for name in targets:
            local._forget(name)
        self.comprehension_body(node, bindings, local)

        # Only iteration variables are local. Other writes and call effects
        # in a possibly empty iterable may still invalidate outer bindings.
        for field in ("modules", "functions", "strings", "wrappers"):
            outer, inner = getattr(bindings, field), getattr(local, field)
            for name in targets:
                if name in outer:
                    inner[name] = outer[name]
                else:
                    inner.pop(name, None)
        if "print" in targets:
            local.builtin_print = bindings.builtin_print
        bindings.merge([bindings, local])

    def comprehension_body(self, node, outer, local):
        for index, generator in enumerate(node.generators):
            iterable = generator.iter
            if index:
                self.expression(iterable, local, consume_generator=True)
            value = None
            if not generator.is_async and isinstance(iterable, (ast.List, ast.Tuple)):
                if not iterable.elts:
                    return
                # Only eagerly evaluated singleton literals establish one loop value.
                if len(iterable.elts) == 1 and not isinstance(node, ast.GeneratorExp):
                    value = _literal_text(iterable.elts[0], local if index else outer)
            self.forget_target(generator.target, local)
            if value is not None and isinstance(generator.target, ast.Name):
                local.strings[generator.target.id] = value
            for condition in generator.ifs:
                self.expression(condition, local)
                if local._condition_value(condition) is False:
                    return
        elements = (node.key, node.value) if isinstance(node, ast.DictComp) else (node.elt,)
        for element in elements:
            self.expression(element, local)

    def expression(self, root, bindings, *, standalone=False, consume_generator=False):
        # Use an explicit stack for long expressions on a single physical line.
        captured = {}
        consumed_generators = {root} if consume_generator else set()
        pending = [(root, False, False, None)]
        while pending:
            node, complete, optional, identity = pending.pop()
            if not complete:
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                    captured[node] = bindings.strings.get(node.id)
                    continue
                if isinstance(node, _COMPREHENSIONS):
                    self.comprehension(node, bindings, consumed=node in consumed_generators)
                    continue
                if isinstance(node, ast.Lambda):
                    self.expression(node.args, bindings)
                    local = bindings.fork()
                    for argument in ast.walk(node.args):
                        if isinstance(argument, ast.arg):
                            local._forget(argument.arg)
                    self.expression(node.body, local)
                    continue
                if isinstance(node, (ast.Call, ast.NamedExpr)):
                    # Python resolves the callable before evaluating its arguments.
                    identity = _call_identity(node, bindings) if isinstance(node, ast.Call) else None
                    pending.append((node, True, optional, identity))
                    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                            and node.func.id in _COLLECTION_CONSTRUCTORS and len(node.args) == 1
                            and not node.keywords and isinstance(node.args[0], ast.GeneratorExp)):
                        consumed_generators.add(node.args[0])
                if isinstance(node, ast.Dict):
                    # Dict displays evaluate each key immediately before its value.
                    children = [part for pair in zip(node.keys, node.values) for part in pair if part is not None]
                else:
                    children = list(ast.iter_child_nodes(node))
                for index in range(len(children) - 1, -1, -1):
                    may_skip = (isinstance(node, ast.IfExp) and index > 0
                                or isinstance(node, ast.BoolOp) and children[index] is not node.values[0])
                    pending.append((children[index], False, optional or may_skip, None))
                continue
            if self.reachable_lines is not None and node.lineno not in self.reachable_lines:
                continue
            if isinstance(node, ast.NamedExpr):
                value = _literal_text(node.value, bindings, captured)
                captured[node] = value
                bindings._forget(node.target.id)
                if value is not None and not optional:
                    bindings.strings[node.target.id] = value
                continue
            if identity is None:
                forwarded = bindings.wrapper_calls(node, self.source)
                if forwarded is not None:
                    self.found[node] = forwarded
                    continue
                if not bindings.is_literal_print(node):
                    bindings.invalidate()
                continue
            module, method = identity
            if module == "os" and method in _CWD_METHODS:
                bindings.observe_chdir(node, method, standalone=standalone and node is root and not optional, captured=captured)
                continue
            calls = _decode_process_call(node, module, method, self.source, bindings, captured)
            if calls:
                directory = bindings.cwd
                if directory is None and (not isinstance(node.func, ast.Attribute) or node.func.value.id != module
                                          or any(isinstance(arg, ast.Name) and captured.get(arg) is not None
                                                 for arg in ast.walk(node))):
                    # Calls recovered from an imported name or bound argument
                    # previously used the process launch directory.
                    directory = "."
                for call in calls:
                    if call.launch_cwd is None:
                        call.launch_cwd = directory
                self.found[node] = calls


def _extract_calls_ast(
    tree: ast.Module, source: str, reachable_lines: set | None = None, *, conditions: dict | None = None,
) -> list[ScriptCall]:
    calls: list[ScriptCall] = []
    import_calls: list[ScriptCall] = []
    analysis = _AstProcessCalls(reachable_lines, conditions or {})
    if _has_python_call_hint(source):
        bindings = _FallbackBindings()
        bindings.cwd = None  # Legacy full-AST calls use the source directory until an explicit change.
        analysis.block(tree.body, bindings)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            calls.extend(analysis.found.get(node, ()))
        elif isinstance(node, ast.ImportFrom) and node.level:
            if node.module:
                import_calls.append(ScriptCall(
                    path=node.module.replace(".", "/") + ".py", interpreter="python3", is_import=True,
                ))
            for alias in node.names:
                if alias.name != "*":
                    import_calls.append(ScriptCall(
                        path=alias.name.replace(".", "/") + ".py", interpreter="python3", is_import=True,
                    ))

    calls.extend(import_calls)

    # 去重（保持顺序）
    seen: set = set()
    unique: list[ScriptCall] = []
    for c in calls:
        key = _call_key(c)
        if key not in seen:
            seen.add(key)
            unique.append(c)
    return unique


def _extract_calls_regex(source: str) -> list[ScriptCall]:
    """正则兜底提取（AST 解析失败时仍能提取字符串形式的子调用）。"""
    calls: list[ScriptCall] = []
    for m in _CHILD_CALL_RE.finditer(source):
        interp, path, rest = m.group(1), m.group(2).strip(), m.group(3).strip()
        if path.startswith("-") or path.startswith("$") or "/dev/" in path:
            continue
        rest = re.split(r"[;|&<>]", rest)[0].strip()
        args = []
        for tm in re.finditer(r"""(["'])(.*?)\1|(\S+)""", rest):
            args.append(tm.group(2) if tm.group(1) else tm.group(3))
        calls.append(ScriptCall(path=path, args=args, interpreter=interp))
    return calls


# Only literal Shell words are needed to recover static Python calls. Keep the
# original spelling until quotes and escapes have been decoded.
_LITERAL_PART = re.compile(
    r"""[^\s'"\\$`*?\[\]{}();|&<>]+|'[^']*'|"(?:[^"\\$`]|\\.)*"|\\[^\n]""",
)
_SHELL_DOUBLE_ESCAPE = re.compile(r'\\(["\\$`])')
_FILE_REDIRECT = re.compile(r">>|>\||>&|<>|<&|[<>]")
_IO_NUMBER = re.compile(r"[0-9]+")
_SHELL_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_ENV_PROGRAMS = frozenset({"env", "/bin/env", "/usr/bin/env"})


def _call_key(call: ScriptCall) -> tuple:
    return call.path, tuple(call.args), call.interpreter, call.launch_cwd


def _legacy_literal_calls(command: str, source: str | None) -> list[ScriptCall]:
    # Preserve only calls the previous raw-source scan already found. Checking
    # the decoded text too keeps Python quotes out of paths and arguments.
    calls = _extract_calls_regex(command)
    if calls and source is not None and command != source:
        old = {_call_key(call) for call in _extract_calls_regex(source)}
        calls = [call for call in calls if _call_key(call) in old]
    return [call for call in calls if "\0" not in call.path]


def _literal_shell_commands(command: str) -> Iterator[tuple[list[str] | None, str, int, bool]]:
    """Yield argv, its following separator, source offset and file-redirection flag."""
    words = []
    assigned = redirected = redirect_target = False
    index = statement_start = 0
    while index <= len(command):
        char = command[index] if index < len(command) else "\n"
        if char in " \t":
            index += 1
            continue
        if char == "#":
            newline = command.find("\n", index)
            index = len(command) if newline < 0 else newline
            continue
        if char in "\n;" or command.startswith(("&&", "||"), index):
            if redirect_target:
                return
            separator = command[index:index + 2] if char in "&|" else char
            if words or redirected or assigned:
                yield words, separator, statement_start, redirected
            words = []
            assigned = redirected = False
            index += len(separator)
            statement_start = index
            continue
        if char in "<>" and not command.startswith("<<", index):
            if redirect_target:
                return
            # The redirect and its operand contribute no argv element.
            index = _FILE_REDIRECT.match(command, index).end()
            redirected = redirect_target = True
            continue

        start = index
        parts = []
        if char != "~":  # A leading unquoted tilde needs Shell expansion.
            while (match := _LITERAL_PART.match(command, index)) is not None:
                raw = match[0]
                if raw.startswith('"'):
                    parts.append(_SHELL_DOUBLE_ESCAPE.sub(r'\1', raw[1:-1]))
                elif raw.startswith("'"):
                    parts.append(raw[1:-1])
                elif raw.startswith("\\"):
                    parts.append(raw[1:])
                else:
                    parts.append(raw)
                index = match.end()
        if not parts or (index < len(command) and command[index] not in " \t\n;<>|&"):
            yield None, "", statement_start, redirected
            return
        if redirect_target:
            redirect_target = False
        elif not words and _SHELL_ASSIGNMENT.match(command, start, index):
            # Only an unquoted name and equals sign before the command name
            # introduce an assignment. Its literal value may contain quotes.
            assigned = True
        elif not (index < len(command) and command[index] in "<>" and _IO_NUMBER.fullmatch(command, start, index)):
            # Only unquoted digits adjacent to a redirect specify an fd.
            words.append("".join(parts))


def _literal_shell_calls(command: str, source: str | None) -> list[ScriptCall]:
    calls = []
    eligible = None
    # On a conditional list, some paths may skip this command and retain
    # their previous exit status. Only a known exit status can rule a path out.
    statuses = {True, False}
    required = None
    for words, separator, start, redirected in _literal_shell_commands(command):
        if words is None:
            calls.extend(_legacy_literal_calls(command[start:], source))
            break
        if required is None or required in statuses:
            if required is None:
                statuses.clear()
            else:
                statuses.discard(required)
            head = words[0] if words else ""
            replaces_shell = head == "exec" and len(words) > 1
            program = words[1:] if replaces_shell else words
            call = _literal_script_call(_env_command(program))
            if call is not None:
                if eligible is None or _call_key(call) in eligible:
                    calls.append(call)
            elif (head and head not in ("echo", "printf", ":", "true", "false", "exit")
                  and head not in _ENV_PROGRAMS and eligible is None):
                # An unmodeled command can exit or change directory.
                eligible = {_call_key(old) for old in _legacy_literal_calls(command, source)}
            exits = head == "exit" and (
                len(words) == 1 or (len(words) == 2 and re.fullmatch(r"[+-]?[0-9]+", words[1]) is not None)
            )
            if exits or (call is not None and replaces_shell):
                if redirected:
                    statuses.add(False)  # A failed redirect can prevent exit or exec.
            elif not redirected and head in (":", "true", "false"):
                statuses.add(head != "false")
            else:
                statuses.update((True, False))
            if not statuses:
                break
        required = {"&&": True, "||": False}.get(separator)
    return calls


def _env_command(words: list[str]) -> list[str]:
    """Return the utility argv for a literal 'env [--] [NAME=value ...] utility'."""
    if not words or words[0] not in _ENV_PROGRAMS:
        return words
    index = 2 if len(words) > 1 and words[1] == "--" else 1
    while index < len(words) and _SHELL_ASSIGNMENT.match(words[index]):
        if "\0" in words[index]:
            return []
        index += 1
    return words[index:]


def _shell_program_operand(words: list[str]) -> tuple[str, int] | None:
    """Locate a Shell's script filename or -c text after simple invocation flags."""
    if not words:
        return None
    name = words[0].rsplit("/", 1)[-1]
    if name not in _SHELL_INTERPRETERS:
        return None
    kind = "script"
    for index in range(1, len(words)):
        word = words[index]
        if word == "--":
            return (kind, index + 1) if index + 1 < len(words) else None
        if not word.startswith(("-", "+")):
            return kind, index
        # Other flags can read stdin, suppress execution, or consume an operand.
        if len(word) < 2 or any(flag not in "acefuvx" for flag in word[1:]):
            return None
        if "c" in word[1:]:
            kind = "command"
    return None


def _literal_script_call(words: list[str]) -> ScriptCall | None:
    if len(words) < 2:
        return None
    interpreter = words[0]
    name = interpreter.rsplit("/", 1)[-1]
    if name not in _SCRIPT_INTERPRETERS and not _VERSIONED_PYTHON.fullmatch(name):
        return None
    if any("\0" in word for word in words):
        return None
    index = 1
    if name in _SHELL_INTERPRETERS:
        operand = _shell_program_operand(words)
        if operand is None or operand[0] != "script":
            return None
        index = operand[1]
    elif words[index].startswith("-"):
        return None
    path = words[index]
    if not path or path.startswith(("$", "~")) or "/dev/" in path:
        return None
    return ScriptCall(path=path, args=words[index + 1:], interpreter=interpreter)


def _literal_text(node: ast.expr, bindings: "_FallbackBindings", captured: dict | None = None) -> str | None:
    if captured is not None and isinstance(node, (ast.Name, ast.NamedExpr)):
        return captured.get(node)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return bindings.strings.get(node.id)
    if isinstance(node, ast.JoinedStr) and all(isinstance(part, ast.Constant) for part in node.values):
        # No replacement fields. The Python parser already decoded doubled braces.
        return "".join(part.value for part in node.values)
    return None


def _literal_keyword_dict(node: ast.expr) -> dict[str, ast.expr] | None:
    if not isinstance(node, ast.Dict):
        return None
    values = {}
    for key, value in zip(node.keys, node.values):
        if key is None:
            nested = _literal_keyword_dict(value)
            if nested is None:
                return None
            values.update(nested)
        elif isinstance(key, ast.Constant) and isinstance(key.value, str):
            values[key.value] = value  # Within a dict, later values replace earlier ones.
        else:
            return None
    return values


def _call_keywords(node: ast.Call) -> dict[str, ast.expr] | None:
    values = {}
    for keyword in node.keywords:
        if keyword.arg is None:
            expansion = _literal_keyword_dict(keyword.value)
            if expansion is None or not values.keys().isdisjoint(expansion):
                return None  # Duplicate arguments at the call site raise TypeError.
            values.update(expansion)
        elif keyword.arg in values:
            return None
        else:
            values[keyword.arg] = keyword.value
    return values


def _subprocess_calls(
    command: ast.expr, options: dict[str, ast.expr], source: str | None, bindings: "_FallbackBindings",
    captured: dict | None = None,
) -> list[ScriptCall]:
    executable_node = options.get("executable")
    shell_node = options.get("shell")
    if executable_node is not None and not isinstance(executable_node, ast.Constant):
        return []
    if shell_node is not None and not isinstance(shell_node, ast.Constant):
        return []
    executable = executable_node.value if executable_node is not None else None
    shell = shell_node.value if shell_node is not None else False
    if executable is not None and (not isinstance(executable, str) or not executable or "\0" in executable):
        return []
    if shell is True:
        if executable is not None and executable.rsplit("/", 1)[-1] not in _SHELL_INTERPRETERS:
            return []
        if isinstance(command, (ast.List, ast.Tuple)) and command.elts:
            command = command.elts[0]
        text = _literal_text(command, bindings, captured)
        return _literal_shell_calls(text, source) if text is not None else []
    if shell is not False:
        return []
    if not isinstance(command, (ast.List, ast.Tuple)):
        return []
    words = []
    for operand in command.elts:
        word = _literal_text(operand, bindings, captured)
        if word is None or "\0" in word:
            return []
        words.append(word)
    # On POSIX executable chooses the running program while argv[1:] stays intact.
    if executable is not None and words:
        words[0] = executable
    words = _env_command(words)
    program = _shell_program_operand(words)
    if program is not None and program[0] == "command":
        return _literal_shell_calls(words[program[1]], source)
    call = _literal_script_call(words)
    return [call] if call is not None else []


def _call_identity(node: ast.Call, bindings: "_FallbackBindings") -> tuple[str, str] | None:
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        module, method = bindings.modules.get(func.value.id), func.attr
        if method in _CALL_FUNCTIONS.get(module, ()):
            return module, method
    if isinstance(func, ast.Name):
        return bindings.functions.get(func.id)
    return None


def _decode_process_call(
    node: ast.Call, module: str, method: str, source: str | None, bindings: "_FallbackBindings",
    captured: dict | None = None,
) -> list[ScriptCall]:
    """Decode the same command and argv for both full and partial Python syntax trees."""
    if module == "os" and method not in _OS_FUNCS:
        return []
    argument_name = "args" if module == "subprocess" else {"system": "command", "popen": "cmd"}.get(method)
    options = _call_keywords(node)
    if options is None or any(isinstance(arg, ast.Starred) for arg in node.args):
        return []
    named = options.get(argument_name)
    if named is not None and node.args:
        return []
    operand = node.args[0] if node.args else named
    if operand is None:
        return []
    if module == "subprocess":
        # subprocess wrappers also forward positional Popen arguments.
        for name, index in (("executable", 2), ("shell", 8), ("cwd", 9)):
            if len(node.args) > index:
                if name in options:
                    return []
                options[name] = node.args[index]
        calls = _subprocess_calls(operand, options, source, bindings, captured)
        option = options.get("cwd")
        if not calls or option is None:
            return calls
        if isinstance(option, ast.Constant):
            if option.value is None:
                return calls
            if not isinstance(option.value, (str, bytes)):
                return []
            directory = os.fsdecode(option.value)
        else:
            directory = _literal_text(option, bindings, captured)
        if directory == "" or (directory is not None and "\0" in directory):
            return []
        launch_cwd = bindings.directory_for(directory)
        for call in calls:
            call.launch_cwd = launch_cwd
        return calls
    text = _literal_text(operand, bindings, captured)
    return _literal_shell_calls(text, source) if text is not None else []


def _fallback_calls_from_ast(
    node: ast.Call, source: str, bindings: "_FallbackBindings", *, standalone: bool = False,
) -> list[ScriptCall]:
    identity = _call_identity(node, bindings)
    if identity is None:
        return bindings.wrapper_calls(node, source) or []
    module, method = identity
    if module == "os" and method in _CWD_METHODS:
        bindings.observe_chdir(node, method, standalone=standalone)
        return []
    calls = _decode_process_call(node, module, method, source, bindings)
    for call in calls:
        if call.launch_cwd is None:
            call.launch_cwd = bindings.cwd
    return calls


def _bare_script_calls(line: str, column: int) -> list[ScriptCall] | None:
    # A bare Shell line in otherwise unparseable Python was already supported.
    match = _BARE_CALL_HINT_RE.match(line, column)
    if match is None:
        return None
    if match.end() == len(line) or line.startswith(("#", *_ASSIGNMENT_PREFIXES), match.end()):
        return None
    text = line[column:]
    if line[:column].strip():
        return _legacy_literal_calls(text, line)
    return _literal_shell_calls(text, line)


@dataclass
class _IfBranch:
    # Alternative paths with identical bindings can be joined as each suite ends.
    completed: Optional["_FallbackBindings"]
    remaining: Optional["_FallbackBindings"]
    reachable: bool


class _FallbackBindings:
    """Track simple imports and literal strings within a straight-line block."""

    _BOUNDARIES = frozenset(
        "if elif else for while try except finally with def class async match case "
        "global nonlocal del return raise break continue".split()
    )
    _WRITES = frozenset("= += -= *= /= //= %= **= @= &= |= ^= <<= >>=".split())

    def __init__(self):
        self.cwd: str | WorkingDirectory | None = "."
        self.modules = {name: name for name in _CALL_FUNCTIONS}
        self.builtin_print = True
        self.functions: dict[str, tuple[str, str]] = {}
        self.wrappers: dict[str, ast.Call] = {}
        self._after_decorator = False
        self.strings: dict[str, str] = {"__name__": "__main__"}
        self._head: list[tokenize.TokenInfo] = []
        self._suites = []
        self._unreachable_suites = 0
        self._last_if = None
        self._reset_statement()

    def invalidate(self) -> None:
        self.builtin_print = False
        self.functions.clear()
        self.wrappers.clear()
        self.strings.clear()
        self.modules = {name: module for name, module in self.modules.items() if name == module}

    def fork(self):
        other = _FallbackBindings()
        other.modules = self.modules.copy()
        other.functions = self.functions.copy()
        other.wrappers = self.wrappers.copy()
        other.strings = self.strings.copy()
        other.builtin_print = self.builtin_print
        other.cwd = self.cwd
        return other

    def merge(self, paths) -> None:
        for field_name in ("modules", "functions", "strings", "wrappers"):
            first, *rest = [getattr(path, field_name) for path in paths]
            setattr(self, field_name, {k: v for k, v in first.items() if all(d.get(k) == v for d in rest)})
        first = paths[0].cwd
        self.cwd = first if all(path.cwd == first for path in paths) else WorkingDirectory.UNKNOWN
        self.builtin_print = all(path.builtin_print for path in paths)

    def change_directory(self, directory: str | None) -> None:
        self.cwd = self.directory_for(directory)

    def observe_chdir(self, node: ast.Call, method: str, *, standalone: bool, captured: dict | None = None) -> None:
        directory = None
        if standalone and method == "chdir":
            if len(node.args) == 1 and not node.keywords:
                directory = _literal_text(node.args[0], self, captured)
            elif not node.args and len(node.keywords) == 1 and node.keywords[0].arg == "path":
                directory = _literal_text(node.keywords[0].value, self, captured)
        self.change_directory(directory)

    def directory_for(self, directory: str | None) -> str | WorkingDirectory:
        if directory and "\0" not in directory:
            path = PurePath(directory)
            if path.is_absolute():
                return str(path)
            if self.cwd is not WorkingDirectory.UNKNOWN:
                return str(PurePath(self.cwd or ".") / path)
        return WorkingDirectory.UNKNOWN

    def starts_statement(self, position: tuple[int, int]) -> bool:
        if not self._head or self._blocked or self._depth:
            return False
        if self._head[0].start == position:
            return True
        return (len(self._head) == 3 and self._head[0].type == tokenize.NAME
                and self._head[1].string == "=" and self._head[2].start == position)

    def _reset_statement(self) -> None:
        self._head.clear()
        self._depth = 0
        self._peak_depth = 0
        self._blocked = False
        self._pending_suite = None
        self._definition = None
        self._inline_function = False
        self._branch_header = None
        self._inline_branch = None

    @property
    def at_entry_scope(self) -> bool:
        return (all(suite == "finally" or isinstance(state, _IfBranch) and state.reachable
                    for suite, state in self._suites)
                and (self._inline_branch is None or self._inline_branch.reachable))

    @property
    def may_execute(self) -> bool:
        if self._branch_header is not None and not self._branch_header[2]:
            return False  # A previous branch already matched this elif/else.
        if self._inline_branch is not None and not self._inline_branch.reachable:
            return False
        return self._unreachable_suites == 0

    def recover(self) -> None:
        # Completed top-level statements survive a lexical restart. A pending
        # assignment has already forgotten its target when '=' was observed.
        if self._suites or self._depth or self._blocked or (
            self._head and self._head[0].string in ("from", "import")
        ):
            self.invalidate()
        self._suites.clear()
        self._unreachable_suites = 0
        self._last_if = None
        self._reset_statement()

    def _forget(self, name: str) -> None:
        if name == "print":
            self.builtin_print = False
        self.functions.pop(name, None)
        self.strings.pop(name, None)
        self.modules.pop(name, None)
        self.wrappers.pop(name, None)

    def record_wrapper(self, definition) -> bool:
        """Defer a direct alias call in a parameterless wrapper until it is invoked."""
        if (not isinstance(definition, ast.FunctionDef) or definition.decorator_list
                or any(ast.iter_child_nodes(definition.args))):
            return False
        body = definition.body[1:] if ast.get_docstring(definition) is not None else definition.body
        if len(body) != 1 or not isinstance(body[0], ast.Expr) or not isinstance(body[0].value, ast.Call):
            return False
        call = body[0].value
        if not isinstance(call.func, ast.Name) or call.func.id not in self.functions:
            return False
        if any(isinstance(child, (ast.Call, ast.NamedExpr)) for arg in [*call.args, *call.keywords]
               for child in ast.walk(arg)):
            return False
        self._forget(definition.name)
        self.wrappers[definition.name] = call
        return True

    def wrapper_calls(self, invocation, source):
        if not isinstance(invocation.func, ast.Name) or invocation.args or invocation.keywords:
            return None
        call = self.wrappers.get(invocation.func.id)
        if call is None:
            return None
        identity = _call_identity(call, self)
        if identity is None:
            return []
        calls = _decode_process_call(call, *identity, source, self)
        for child in calls:
            if child.launch_cwd is None:
                child.launch_cwd = self.cwd or "."
        return calls

    def is_literal_print(self, node: ast.Call) -> bool:
        return (self.builtin_print and isinstance(node.func, ast.Name) and node.func.id == "print"
                and all(isinstance(arg, ast.Constant) for arg in node.args)
                and all(kw.arg in {"sep", "end", "flush"} and isinstance(kw.value, ast.Constant)
                        for kw in node.keywords))

    def _condition_value(self, node: ast.expr) -> bool | None:
        if isinstance(node, ast.Constant):
            return bool(node.value)
        if isinstance(node, ast.Name) and node.id in self.strings:
            return bool(self.strings[node.id])
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            value = self._condition_value(node.operand)
            return None if value is None else not value
        if isinstance(node, ast.BoolOp):
            decisive = isinstance(node.op, ast.Or)
            values = [self._condition_value(child) for child in node.values]
            if decisive in values:
                return decisive
            return None if None in values else not decisive
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
            operands = []
            for operand in (node.left, node.comparators[0]):
                if isinstance(operand, ast.Constant):
                    operands.append(operand.value)
                elif isinstance(operand, ast.Name) and operand.id in self.strings:
                    operands.append(self.strings[operand.id])
                else:
                    return None
            equal = operands[0] == operands[1]
            return equal if isinstance(node.ops[0], ast.Eq) else not equal
        return None

    def _open_branch(self, source, offsets, colon):
        first, completed, possible = self._branch_header
        if first.string == "finally":
            self._pending_suite = ("finally", None)
            self._branch_header = None
            self._blocked = False
            return
        begin = offsets[first.end[0] - 1] + first.end[1]
        end = offsets[colon[0] - 1] + colon[1]
        truth = True if first.string == "else" else None
        if truth is None and end - begin <= _MAX_FALLBACK_CALL_CHARS:
            condition = _parse_fallback_expression(source[begin:end])
            if condition is not None:
                try:
                    truth = self._condition_value(condition)
                except RecursionError:
                    truth = None
        remaining = self.fork() if possible and truth is not True else None
        branch = _IfBranch(completed, remaining, possible and truth is not False)
        self._pending_suite = ("branch", branch)
        self._branch_header = None
        self._blocked = False

    def _close_branch(self, branch):
        if branch.reachable:
            if branch.completed is not None:
                self.merge([branch.completed, self])
            branch.completed = self.fork()
        paths = [state for state in (branch.completed, branch.remaining) if state is not None]
        if paths:
            self.merge(paths)
        self._last_if = (len(self._suites), branch)

    def observe(
        self, token: tokenize.TokenInfo, source: str, line_offsets: list[int],
        previous: tokenize.TokenInfo | None = None,
    ) -> None:
        kind, word, start, _, _ = token
        if kind in (tokenize.COMMENT, tokenize.NL):
            return
        if kind == tokenize.INDENT:
            suite, outer = self._pending_suite or ("conditional", None)
            self._suites.append((suite, outer))
            if isinstance(outer, _IfBranch) and not outer.reachable:
                self._unreachable_suites += 1
            if suite == "conditional":
                self.invalidate()
            self._reset_statement()
            return
        if kind == tokenize.DEDENT:
            suite, outer = self._suites.pop() if self._suites else ("conditional", None)
            if suite == "function":
                self._leave_definition(outer, source, line_offsets[start[0] - 1] + start[1])
            elif isinstance(outer, _IfBranch):
                if not outer.reachable:
                    self._unreachable_suites -= 1
                self._close_branch(outer)
            elif suite != "finally":
                self.invalidate()
            self._reset_statement()
            return
        end_of_line = kind in (tokenize.NEWLINE, tokenize.ENDMARKER)
        if end_of_line or (kind == tokenize.OP and word == ";" and not self._depth):
            if self._head and not self._blocked:
                self._finish(source, line_offsets, start)
            if kind == tokenize.NEWLINE:
                self._after_decorator = bool(self._head and self._head[0].string == "@")
            self._head.clear()
            self._peak_depth = 0
            if end_of_line:
                if self._inline_branch is not None:
                    self._close_branch(self._inline_branch)
                    self._inline_branch = None
                if self._inline_function:
                    self._leave_definition(self._pending_suite[1], source, line_offsets[start[0] - 1] + start[1])
                    self._pending_suite = None
                    self._inline_function = False
                self._depth = 0
                self._blocked = False
                self._branch_header = None
            return
        if self._branch_header is not None:
            if kind == tokenize.OP:
                if word == ":" and not self._depth:
                    self._open_branch(source, line_offsets, start)
                else:
                    self._depth += int(word in _OPEN_DELIMITERS) - int(word in _CLOSE_DELIMITERS)
                    if word == ":=" and previous and previous.type == tokenize.NAME:
                        self._forget(previous.string)
            return
        if self._definition is not None:
            if kind == tokenize.OP and word == ":" and not self._depth:
                begin = line_offsets[self._definition.start[0] - 1] + self._definition.start[1]
                end = line_offsets[start[0] - 1] + start[1] + 1
                self._enter_definition(source[begin:end] if end - begin <= _MAX_FALLBACK_CALL_CHARS else "", begin)
                self._definition = None
            elif kind == tokenize.OP:
                self._depth += int(word in _OPEN_DELIMITERS) - int(word in _CLOSE_DELIMITERS)
            return
        if self._blocked:
            if self._pending_suite is not None and self._pending_suite[0] == "function":
                self._inline_function = True
            return
        if self._pending_suite is not None:
            suite, outer = self._pending_suite
            if suite == "function":
                self._leave_definition(outer, source, line_offsets[start[0] - 1] + start[1])
            elif isinstance(outer, _IfBranch):
                self._inline_branch = outer
            self._pending_suite = None
        if not self._head and kind == tokenize.NAME and word in ("if", "elif", "else", "finally"):
            last = self._last_if
            self._last_if = None
            completed, possible = None, True
            if word in ("elif", "else"):
                if last is not None and last[0] == len(self._suites):
                    completed = last[1].completed
                    possible = last[1].remaining is not None
                    if possible:
                        self.merge([last[1].remaining])
                else:
                    self.invalidate()
            self._branch_header = (token, completed, possible)
            self._blocked = True
            return
        if not self._head:
            self._last_if = None
        if not self._head and kind == tokenize.NAME and (
            word == "def" or (word == "async" and re.match(r"async\s+def\b", token.line[start[1]:]))
        ):
            self._definition = token
            self._blocked = True
            return
        if kind == tokenize.NAME and (
            (not self._head and word in self._BOUNDARIES) or word == "lambda" or (word == "for" and not self._depth)
        ):
            self.invalidate()
            self._reset_statement()
            self._blocked = True  # Includes inline suites and lambda-local bindings.
            return
        if kind == tokenize.OP:
            if word == ":=":
                if previous and previous.type == tokenize.NAME:
                    self._forget(previous.string)
                else:
                    self.invalidate()
            elif not self._depth and word in self._WRITES:
                if self._head and self._head[0].type == tokenize.NAME and (
                    len(self._head) == 1 or self._head[1].string == ":"
                ):
                    self._forget(self._head[0].string)
                else:
                    self.invalidate()
            if word in _OPEN_DELIMITERS:
                self._depth += 1
                self._peak_depth = max(self._peak_depth, self._depth)
            elif word in _CLOSE_DELIMITERS:
                self._depth = max(0, self._depth - 1)
        if len(self._head) < 3:
            self._head.append(token)

    def _enter_definition(self, header: str, start: int) -> None:
        try:
            definition = ast.parse(header + " pass").body[0]
        except (SyntaxError, ValueError, RecursionError, IndexError):
            self.invalidate()
            return
        self._forget(definition.name)
        wrapper_start = start if self.functions and self.at_entry_scope and not self._after_decorator else None
        outer = (self.modules, self.functions, self.strings, self.builtin_print, self.wrappers, wrapper_start)
        # Only the function's own imports can establish additional aliases.
        self.modules = {name: module for name, module in self.modules.items() if name == module}
        for argument in ast.walk(definition.args):
            if isinstance(argument, ast.arg):
                self.modules.pop(argument.arg, None)
                if argument.arg == "print":
                    self.builtin_print = False
        self.functions, self.strings, self.wrappers = {}, {}, {}
        self._pending_suite = ("function", outer)

    def _leave_definition(self, outer, source: str, end: int) -> None:
        self.modules, self.functions, self.strings, self.builtin_print, self.wrappers, begin = outer
        if begin is not None and end - begin <= _MAX_FALLBACK_CALL_CHARS:
            try:
                statements = ast.parse(source[begin:end]).body
            except (SyntaxError, ValueError, RecursionError):
                return
            if len(statements) == 1:
                self.record_wrapper(statements[0])

    def _finish(self, source: str, offsets: list[int], end: tuple[int, int]) -> None:
        first = self._head[0]
        is_import = first.string in ("import", "from")
        literal = None
        if not is_import:
            if first.type == tokenize.NAME:
                if len(self._head) != 3:
                    return
                _, operator, operand = self._head
                if operator.string == "=" and operand.type == tokenize.STRING:
                    literal = operand
                elif operator.string != ":" and not (
                    operator.string == "=" and (operand.string == "(" or _FSTRING_START_RE.match(operand.string))
                ):
                    return
            elif not _FSTRING_START_RE.match(first.string):
                return
        begin = offsets[first.start[0] - 1] + first.start[1]
        stop = offsets[end[0] - 1] + end[1]
        if self._peak_depth <= _MAX_FALLBACK_CALL_DEPTH and stop - begin <= _MAX_FALLBACK_CALL_CHARS:
            fragment = source[begin:stop]
            if first.type != tokenize.NAME and not is_import and ":=" not in fragment:
                return
            # The three head tokens may be followed by another literal or an
            # expression. Only the complete bounded statement can establish a value.
            if (literal is not None and (literal.end == end or fragment.endswith((" ", "\t")))
                    and literal.string.isascii() and literal.string.isprintable()
                    and _PLAIN_STRING_ASSIGNMENT.fullmatch(fragment) and not keyword.iskeyword(first.string)):
                self._bind_string(first.string, literal.string[1:-1])
                return
            try:
                statements = ast.parse(fragment).body
            except (SyntaxError, ValueError, RecursionError):
                statements = []
            if len(statements) == 1:
                statement = statements[0]
                if isinstance(statement, (ast.Import, ast.ImportFrom)):
                    self._record_import(statement)
                    return
                self.record_assignment(statement)
                return
        if is_import:
            # An incomplete or over-budget import may replace any tracked name.
            self.invalidate()

    def record_assignment(self, statement: ast.stmt, *, fields_already_evaluated: bool = False) -> None:
        target = _assigned_name(statement)
        if target is None and not isinstance(statement, ast.Expr):
            return
        if statement.value is None:
            return  # An annotation alone does not replace the existing value.
        if isinstance(statement, ast.AnnAssign) and not fields_already_evaluated and any(
            isinstance(part, (ast.Call, ast.NamedExpr)) for part in ast.walk(statement.annotation)
        ):
            # Evaluating the annotation after the assignment may rebind the name.
            self._forget(target)
            return
        if not fields_already_evaluated and isinstance(statement.value, ast.JoinedStr):
            for field in statement.value.values:
                if not isinstance(field, ast.FormattedValue):
                    continue
                for node in ast.walk(field):
                    if isinstance(node, ast.Call) and _call_identity(node, self) is None and not self.is_literal_print(node):
                        self.invalidate()
                    elif isinstance(node, ast.NamedExpr):
                        self._forget(node.target.id)
                assignment = field.value
                if (field.format_spec is None and isinstance(assignment, ast.NamedExpr)
                        and isinstance(assignment.value, ast.Constant) and isinstance(assignment.value.value, str)):
                    self.strings[assignment.target.id] = assignment.value.value
        if target is not None:
            self._bind_string(target, _literal_text(statement.value, self))

    def _bind_string(self, name: str, value: str | None) -> None:
        self._forget(name)
        if value is not None:
            self.strings[name] = value

    def _record_import(self, statement: ast.Import | ast.ImportFrom) -> None:
        for alias in statement.names:
            if alias.name == "*":
                self.invalidate()
                return
            name = alias.asname or alias.name.split(".")[0]
            self._forget(name)
            if isinstance(statement, ast.Import):
                module = alias.name if alias.asname else name
                if module in _CALL_FUNCTIONS:
                    self.modules[name] = module
            elif isinstance(statement, ast.ImportFrom) and not statement.level:
                module = statement.module
                if module and alias.name in _CALL_FUNCTIONS.get(module, ()):
                    self.functions[name] = (module, alias.name)


def _call_start(tokens: deque[tokenize.TokenInfo], bindings: "_FallbackBindings") -> tuple[int, int] | None:
    if tokens and tokens[-1].type == tokenize.NAME and (
        tokens[-1].string in bindings.functions or tokens[-1].string in bindings.wrappers
    ):
        if len(tokens) == 1 or tokens[-2].string != ".":
            return tokens[-1].start
    if len(tokens) < 3:
        return None
    module, dot, method = tokens[-3], tokens[-2], tokens[-1]
    if module.type != tokenize.NAME or dot.string != "." or method.type != tokenize.NAME:
        return None
    if method.string not in _CALL_FUNCTIONS.get(bindings.modules.get(module.string), ()):
        return None
    if len(tokens) == 4 and tokens[0].string == ".":
        return None
    return module.start


def _has_python_call_hint(source: str) -> bool:
    # Keep the hints independent of whitespace, comments and line continuations.
    return ("." in source or "import" in source) and any(
        module in source and module_word.search(source) and method_word.search(source)
        for module, module_word, method_word in _FALLBACK_PYTHON_CALL_HINTS
    )


def _parse_fallback_expression(fragment: str) -> ast.expr | None:
    try:
        # The original call can rely on implicit continuation around its callee.
        return ast.parse(f"({fragment})", mode="eval").body
    except (SyntaxError, ValueError, RecursionError):
        return None


def _within_local_depth(expression: ast.expr) -> bool:
    pending = [(expression, 0)]
    while pending:
        node, depth = pending.pop()
        if depth > _MAX_FALLBACK_CALL_DEPTH:
            return False
        pending.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
    return True


def _calls_from_fstring(fragment: str, bindings: "_FallbackBindings") -> list[ScriptCall]:
    expression = _parse_fallback_expression(fragment)
    if not isinstance(expression, ast.JoinedStr) or not _within_local_depth(expression):
        bindings.invalidate()
        return []

    analysis = _AstProcessCalls(None, {}, fragment)
    analysis.expression(expression, bindings)
    # The enclosing statement commits unconditional replacement-field writes.
    for part in expression.values:
        if isinstance(part, ast.FormattedValue) and isinstance(part.value, ast.NamedExpr):
            bindings._forget(part.value.target.id)
    return _calls_in_source_order(analysis.found)


def _calls_in_source_order(found: dict[ast.Call, list[ScriptCall]]) -> list[ScriptCall]:
    return [call for node in sorted(found, key=lambda n: (n.lineno, n.col_offset)) for call in found[node]]


def _evaluate_fallback_expression(
    expression, fragment, bindings, frame, reads, *, standalone, commit_writes,
):
    # Replay only the names referenced in this bounded expression. Scanning
    # backwards leaves the first observed binding for each name, including
    # values no longer present after a later assignment or opaque call.
    names = {node.id for node in ast.walk(expression) if isinstance(node, ast.Name)}
    initial = {name: (bindings.modules.get(name), bindings.functions.get(name), bindings.strings.get(name))
               for name in names}
    for position, name, values in reversed(reads):
        if position < (frame.call_start or frame.opening):
            break
        if name in names:
            initial[name] = values

    local = _FallbackBindings()
    local.cwd, local.builtin_print = frame.initial_cwd, frame.initial_print
    local.modules = {name: values[0] for name, values in initial.items() if values[0] is not None}
    local.functions = {name: values[1] for name, values in initial.items() if values[1] is not None}
    local.strings = {name: values[2] for name, values in initial.items() if values[2] is not None}
    analysis = _AstProcessCalls(None, {}, fragment)
    analysis.expression(expression, local, standalone=standalone)
    bindings.cwd = local.cwd
    if commit_writes:
        for node in ast.walk(expression):
            if isinstance(node, ast.NamedExpr):
                name = node.target.id
                bindings._forget(name)
                if name in local.strings:
                    bindings.strings[name] = local.strings[name]
    return _calls_in_source_order(analysis.found)


@dataclass(slots=True)
class _FallbackDelimiter:
    closing: str
    call_start: tuple[int, int] | None
    group_start: tuple[int, int] | None
    opening: tuple[int, int]
    depth: int = 1
    opaque_call: bool = False
    changes_cwd: bool = False
    print_start: int | None = None
    initial_cwd: str | WorkingDirectory | None = None
    initial_print: bool = False
    found_start: int = 0
    comprehension: bool = False
    collection_start: tuple[int, int] | None = None
    contains_comprehension: bool = False


def _can_open_group(recent: deque[tokenize.TokenInfo]) -> bool:
    """Exclude call-argument parentheses, e.g. factory(os.system)(...)."""
    if not recent:
        return True
    previous = recent[-1]
    if previous.type == tokenize.NAME:
        return keyword.iskeyword(previous.string) and previous.string not in {"False", "None", "True"}
    if previous.type == tokenize.OP:
        return previous.string not in {")", "]", "}", "..."}
    return previous.type in {tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT}


_INTERPOLATED_STRING_DEPTH = {
    getattr(tokenize, name): delta
    for name, delta in (("FSTRING_START", 1), ("FSTRING_END", -1), ("TSTRING_START", 1), ("TSTRING_END", -1))
    if hasattr(tokenize, name)
}


def _fallback_tokens(
    source: str, line_offsets: list[int], diagnostics: dict | None,
) -> Iterator[tokenize.TokenInfo | None]:
    reader = io.StringIO(source)
    row_offset = 0
    while True:
        string_depth = 0
        try:
            for token in tokenize.generate_tokens(reader.readline):
                if token.type in _INTERPOLATED_STRING_DEPTH:
                    string_depth += _INTERPOLATED_STRING_DEPTH[token.type]
                if token.type == tokenize.ERRORTOKEN and re.match(r"""(?i:[rubf]*)(?:'|")""", token.string):
                    # Python 3.10/3.11 return the quote or the broken string,
                    # including physical lines it consumed via continuation.
                    resume = token.end[0]
                    break
                if row_offset:
                    token = token._replace(start=(token.start[0] + row_offset, token.start[1]),
                                           end=(token.end[0] + row_offset, token.end[1]))
                yield token
            else:
                return
        except (tokenize.TokenError, SyntaxError) as error:
            resume = 0
            if isinstance(error, IndentationError) and error.lineno:
                # This line was read but not lexed. Include it on restart.
                resume = error.lineno - 1
            elif isinstance(error, tokenize.TokenError):
                # On 3.12+ the exception location points to the opening quote.
                # The diagnostic names the last line consumed by the string.
                match = re.fullmatch(r"unterminated string literal \(detected at line ([0-9]+)\)", error.args[0])
                if match:
                    resume = int(match[1])
        if diagnostics is not None:
            diagnostics["child_tokenization_incomplete"] = True
        if not resume or string_depth:
            return
        row_offset += resume
        if row_offset >= len(line_offsets) - 1:
            return
        reader.seek(line_offsets[row_offset])
        yield None


def _bounded_call_fragment(
    source: str, start: int, end: int, comments: deque[tuple[int, int]],
) -> str | None:
    if end - start <= _MAX_FALLBACK_CALL_CHARS:
        return source[start:end]
    # Discard comment text while retaining its newline. Materialize at most
    # the parse budget, even if an individual comment occupies most of a file.
    remaining = _MAX_FALLBACK_CALL_CHARS
    pieces = []
    for comment_start, comment_end in reversed(comments):
        if comment_start < start:
            break
        remaining -= end - comment_end
        if remaining < 0:
            return None
        pieces.append(source[comment_end:end])
        end = comment_start
    if end - start > remaining:
        return None
    pieces.append(source[start:end])
    return "".join(reversed(pieces))


def _walrus_fstring_tokens(tokens, source: str, offsets: list[int]):
    """Use the same field evaluation order across both tokenizer formats."""
    pending = []
    depth = start = 0
    for token in tokens:
        if token is None:
            pending.clear()
            depth = 0
        elif depth or token.type == tokenize.FSTRING_START:
            if not depth:
                start = offsets[token.start[0] - 1] + token.start[1]
                pending.append(token)
            elif pending:
                pending.append(token)
            depth += _INTERPOLATED_STRING_DEPTH.get(token.type, 0)
            if pending:
                end = offsets[token.end[0] - 1] + token.end[1]
                if end - start > _MAX_FALLBACK_CALL_CHARS:
                    yield from pending
                    pending.clear()
                elif not depth:
                    yield pending[0]._replace(type=tokenize.STRING, string=source[start:end], end=token.end)
                    pending.clear()
                continue
        yield token


def _extract_calls_fallback(
    source: str, source_lines: list[str], diagnostics: dict | None,
) -> list[ScriptCall]:
    if diagnostics is not None:
        diagnostics.update(child_extractor="tokenize", child_tokenization_incomplete=False)
    if not _has_python_call_hint(source) and not _BARE_CALL_HINT_RE.search(source):
        return []

    line_offsets = [0]
    for line in source_lines:
        line_offsets.append(line_offsets[-1] + len(line) + 1)

    recent: deque[tokenize.TokenInfo] = deque(maxlen=4)
    delimiters: list[_FallbackDelimiter] = []
    found: list[tuple[tuple[int, int], ScriptCall]] = []
    bare_line = 0
    # At least one source character per name. Entries older than this cannot
    # belong to a fragment that fits the local parse budget (comments have no names).
    reads = deque(maxlen=_MAX_FALLBACK_CALL_CHARS)
    bindings = _FallbackBindings()
    track_cwd = "chdir" in source
    has_if = re.search(r"\bif\b", source) is not None
    track_bindings = has_if or "=" in source or track_cwd or re.search(r"\b(?:as|from|def)\b", source) is not None
    # Each comment leaves at least its newline in the fragment. Older spans
    # cannot make a candidate fit once this many intervening comments exist.
    comments: deque[tuple[int, int]] = deque(maxlen=_MAX_FALLBACK_CALL_CHARS)
    grouped = None

    tokens = _fallback_tokens(source, line_offsets, diagnostics)
    if ":=" in source and hasattr(tokenize, "FSTRING_START"):
        tokens = _walrus_fstring_tokens(tokens, source, line_offsets)
    for token in tokens:
        if token is None:
            recent.clear()
            delimiters.clear()
            comments.clear()
            bindings.recover()
            grouped = None
            continue
        token_type, value, position, end, _ = token
        row, column = position
        if track_bindings and token_type == tokenize.NAME and (
            delimiters or value in bindings.functions or value in bindings.modules
        ):
            reads.append((position, value, (bindings.modules.get(value), bindings.functions.get(value),
                                            bindings.strings.get(value))))
        if track_bindings:
            bindings.observe(token, source, line_offsets, recent[-1] if recent else None)
            if has_if and not bindings.may_execute:
                # Still observe suite boundaries so a following alternative
                # starts from its own bindings. No call in this suite can run.
                recent.clear()
                grouped = None
                continue
        if token_type == tokenize.COMMENT:
            offset = line_offsets[row - 1] + column
            comments.append((offset, offset + len(value)))
            continue
        if token_type == tokenize.NL:
            continue
        if token_type == tokenize.NEWLINE:
            comments.clear()

        if (row != bare_line and token_type in (tokenize.NAME, tokenize.OP)
                and value.lower() in _BARE_INTERPRETER_STARTS):
            calls = _bare_script_calls(source_lines[row - 1], column)
            if calls is not None:
                found.extend((position, call) for call in calls)
                bare_line = row

        previous_group = grouped
        grouped = None
        if token_type == tokenize.NAME and value == "for" and delimiters:
            # The result expression precedes its iteration variables in source.
            # Its provisional calls must be resolved in the completed local scope.
            delimiters[-1].comprehension = True
            del found[delimiters[-1].found_start:]
        if token_type == tokenize.OP and value in _OPEN_DELIMITERS:
            start = group_start = None
            depth = 1
            parameters = len(recent) >= 2 and recent[-2].string == "def"
            if value == "(" and not parameters:
                if previous_group is not None:
                    start, depth = previous_group.group_start, previous_group.depth
                else:
                    start = _call_start(recent, bindings)
                    if start is None and _can_open_group(recent):
                        group_start = position
            opaque_call = track_bindings and value == "(" and start is None and group_start is None and not parameters
            changes_cwd = False
            if track_cwd and start is not None:
                if previous_group is not None:
                    changes_cwd = previous_group.changes_cwd
                elif recent:
                    name = recent[-1].string
                    changes_cwd = name in _CWD_METHODS or bindings.functions.get(name) in {
                        ("os", "chdir"), ("os", "fchdir"),
                    }
            print_start = None
            if (opaque_call and bindings.builtin_print and recent and recent[-1].string == "print"
                    and (len(recent) < 2 or recent[-2].string != ".")):
                r, c = recent[-1].start
                print_start = line_offsets[r - 1] + c
            collection_start = None
            if (value == "(" and recent and recent[-1].string in _COLLECTION_CONSTRUCTORS
                    and (len(recent) < 2 or recent[-2].string != ".")):
                collection_start = recent[-1].start
            delimiters.append(_FallbackDelimiter(
                _OPEN_DELIMITERS[value], start, group_start, position, depth, opaque_call, changes_cwd, print_start,
                bindings.cwd, bindings.builtin_print, len(found),
                collection_start=collection_start,
            ))
        elif token_type == tokenize.OP and value in _CLOSE_DELIMITERS:
            if not delimiters or delimiters[-1].closing != value:
                delimiters.clear()
            else:
                frame = delimiters.pop()
                if delimiters:
                    parent = delimiters[-1]
                    parent.depth = max(parent.depth, frame.depth + 1)
                    if frame.comprehension or frame.contains_comprehension:
                        parent.contains_comprehension = True
                if frame.group_start is not None and (previous_group is not None or _call_start(recent, bindings)):
                    grouped = frame
                if frame.opaque_call:
                    # Arguments have already been visited. The call can now rebind names.
                    expression = None
                    if frame.print_start is not None and frame.depth <= _MAX_FALLBACK_CALL_DEPTH:
                        end_offset = line_offsets[end[0] - 1] + end[1]
                        if end_offset - frame.print_start <= _MAX_FALLBACK_CALL_CHARS:
                            expression = _parse_fallback_expression(source[frame.print_start:end_offset])
                    if not isinstance(expression, ast.Call) or not bindings.is_literal_print(expression):
                        bindings.invalidate()
                collection = frame.collection_start if frame.contains_comprehension or frame.comprehension else None
                if frame.call_start is not None or frame.comprehension or collection is not None:
                    expression_start = frame.call_start or collection or frame.opening
                    first_row, first_column = expression_start
                    start_offset = line_offsets[first_row - 1] + first_column
                    end_offset = line_offsets[end[0] - 1] + end[1]
                    fragment = (_bounded_call_fragment(source, start_offset, end_offset, comments)
                                if frame.depth <= _MAX_FALLBACK_CALL_DEPTH else None)
                    expression = _parse_fallback_expression(fragment) if fragment is not None else None
                    if frame.comprehension:
                        del found[frame.found_start:]
                    if isinstance(expression, ast.Call) or (frame.comprehension and isinstance(expression, _COMPREHENSIONS)):
                        whole_statement = (
                            bindings.starts_statement(expression_start)
                            and _END_OF_STATEMENT.match(source_lines[end[0] - 1], end[1]) is not None
                        )
                        standalone = frame.changes_cwd and bindings.at_entry_scope and whole_statement
                        # The tokenizer has already seen the writes in a nested
                        # expression. Re-evaluate the bounded AST from its earlier
                        # reads to capture each operand at its actual evaluation point.
                        has_effects = (":=" in fragment or fragment.count("(") > 1) and any(
                            isinstance(node, ast.NamedExpr) or (isinstance(node, ast.Call) and node is not expression)
                            for node in ast.walk(expression)
                        )
                        if has_effects or frame.comprehension:
                            if not _within_local_depth(expression):
                                recent.append(token)
                                continue  # Inner calls already passed their own bounds.
                            calls = _evaluate_fallback_expression(
                                expression, fragment, bindings, frame, reads,
                                standalone=standalone, commit_writes=whole_statement,
                            )
                            del found[frame.found_start:]
                        else:
                            calls = _fallback_calls_from_ast(expression, fragment, bindings, standalone=standalone)
                        found.extend((expression_start, call) for call in calls)
                    elif frame.changes_cwd:
                        bindings.change_directory(None)
        elif token_type == tokenize.STRING and _FSTRING_START_RE.match(value):
            active = "{" in value and (
                ":=" in value or ("(" in value and (bindings.functions or bindings.strings or bindings.modules))
            )
            if len(value) > _MAX_FALLBACK_CALL_CHARS:
                if active:
                    bindings.invalidate()
            elif active or _has_python_call_hint(value):
                found.extend((position, call) for call in _calls_from_fstring(value, bindings))
        recent.append(token)
    # An inner call closes first. The offsets retain the order of their starts.
    found.sort(key=lambda entry: entry[0])
    unique = []
    seen = set()
    for _, call in found:
        key = _call_key(call)
        if key not in seen:
            unique.append(call)
            seen.add(key)
    return unique


# ==================== PythonBackend ====================


class PythonBackend(LanguageBackend):
    """python（python3）脚本解析后端。"""

    language = "python"

    ENTRY_PATTERNS = [
        r"(?:^|\s|&&|\|\|)\s*python3?\s+(\S+\.py)",
    ]

    def parse(
        self, content: str, entry_args: list[str] | None, *,
        diagnostics: dict | None = None, args_known: bool = True,
    ) -> ScriptIR:
        """解析 python 脚本：ast 控制流剪枝 + 子脚本调用提取；失败回退全文本。

        fail-closed 原则（与 ShellBackend 一致）：
        - 语法解析失败 / 超预算 → reachable_content = 全文本，control_flow_resolved=False
        - 条件不可静态求值 → 该分支链整体保留
        """
        if content is None:
            content = ""
        source_lines = content.split("\n")
        if not source_lines[-1]:
            # The last newline terminates the preceding physical line.
            source_lines.pop()
        env = _Env(argv=list(entry_args or []))
        lines: set = set()
        branches: list[BranchInfo] = []
        if diagnostics is not None:
            diagnostics.update(physical_lines=len(source_lines), line_limit=MAX_LINES)

        # 预算熔断：超行数直接全文本（保持性能红线）
        if len(source_lines) > MAX_LINES:
            if diagnostics is not None:
                diagnostics.update(parser="python_full", fallback_reason="line_budget")
            calls = _extract_calls_fallback(content, source_lines, diagnostics)
            return ScriptIR(
                reachable_content=content,
                control_flow_resolved=False,
                calls=calls,
                language=self.language,
            )

        try:
            tree = ast.parse(content)
        except (SyntaxError, ValueError):
            # 残缺/混淆脚本：全文本 fail-closed，仍尽力提取子调用
            if diagnostics is not None:
                diagnostics.update(parser="python_full", fallback_reason="syntax_error")
            calls = _extract_calls_fallback(content, source_lines, diagnostics)
            return ScriptIR(
                reachable_content=content,
                control_flow_resolved=False,
                calls=calls,
                language=self.language,
            )

        if not args_known:
            if diagnostics is not None:
                diagnostics.update(parser="python_full", fallback_reason="unknown_args", child_extractor="ast")
            return ScriptIR(
                reachable_content=content,
                calls=_extract_calls_ast(tree, content),
                language=self.language,
            )

        _process_stmts(tree.body, env, source_lines, lines, branches)
        reachable = _reconstruct(source_lines, lines)

        calls = _extract_calls_ast(tree, content, reachable_lines=lines, conditions=env.conditions)
        if diagnostics is not None:
            diagnostics.update(
                parser="python_ast",
                child_extractor="ast",
                retained_lines=len(lines),
                branch_count=len(branches),
                branch_reachable=[branch.reachable for branch in branches[:4]],
            )

        # 是否真的裁剪了内容：按非空行集合比较（忽略末尾空行/换行差异，
        # 避免"全保留但文本尾换行不同"误判为已裁剪）
        src_nonblank = [l for l in source_lines if l.strip()]
        rc_nonblank = [l for l in reachable.split("\n") if l.strip()]
        resolved = rc_nonblank != src_nonblank
        return ScriptIR(
            reachable_content=reachable,
            control_flow_resolved=resolved,
            calls=calls,
            branches=branches,
            language=self.language,
        )
