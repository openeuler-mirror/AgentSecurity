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

预算：单脚本有效行超 MAX_LINES → fail-closed 全文本（与 symbolic.py 红线一致）。
ast.parse 对 <2MB 文件毫秒级，无额外状态空间，天然满足性能红线。
"""

import ast
import re
from dataclasses import dataclass, field
from typing import Optional

from ..ir import BranchInfo, ScriptCall, ScriptIR
from .base import LanguageBackend

# ==================== 预算（P5 熔断，与 symbolic.py 红线一致） ====================
MAX_LINES = 500

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


# ==================== 符号环境 ====================


@dataclass
class _Env:
    """Python 脚本静态符号环境：argv 绑定 + 简单变量追踪。"""

    argv: list[str] = field(default_factory=list)   # sys.argv[1:] = 入口参数
    vars: dict = field(default_factory=dict)        # name -> str | None（None = 未解析）

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


def _process_stmt(stmt: ast.AST, env: _Env, source_lines: list, lines: set, branches: list) -> None:
    # 赋值：更新变量环境（只追踪可静态求值的）；RHS 含非纯调用 → env 失效
    if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
        _invalidate_env_on_calls(stmt.value, env)
        val = _eval_expr(stmt.value, env)
        env.vars[stmt.targets[0].id] = val
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
        body_env = _Env(argv=env.argv, vars=dict(env.vars))
        _process_stmts(stmt.body, body_env, source_lines, lines, branches)
        if isinstance(stmt, ast.While):
            orelse_env = _Env(argv=env.argv, vars=dict(env.vars))
            _process_stmts(stmt.orelse, orelse_env, source_lines, lines, branches)
        return
    if isinstance(stmt, ast.Try):
        _mark_node_lines(stmt, lines, source_lines)
        for part in ([stmt.body] + [h.body for h in stmt.handlers if h.body] + [stmt.orelse] + [stmt.finalbody]):
            part_env = _Env(argv=env.argv, vars=dict(env.vars))
            _process_stmts(part, part_env, source_lines, lines, branches)
        return
    if isinstance(stmt, ast.With) or isinstance(stmt, ast.AsyncWith):
        _mark_node_lines(stmt, lines, source_lines)
        body_env = _Env(argv=env.argv, vars=dict(env.vars))
        _process_stmts(stmt.body, body_env, source_lines, lines, branches)
        return
    if isinstance(stmt, ast.Match):
        # match/case（3.10+）：无法静态判定 → 全保留；各 case 用副本 env（可能都不匹配）
        _mark_node_lines(stmt, lines, source_lines)
        for case in stmt.cases:
            case_env = _Env(argv=env.argv, vars=dict(env.vars))
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


def _extract_calls_ast(tree: ast.Module, source: str, reachable_lines: set | None = None) -> list[ScriptCall]:
    """从 AST 提取子脚本调用（subprocess 列表形式 + os.system 字符串形式）。

    reachable_lines 非 None 时只提取可达分支内的调用（与剪枝结果一致，
    避免不可达分支的子调用被递归追踪）。
    """
    calls: list[ScriptCall] = []
    import_calls: list[ScriptCall] = []

    def _line_reachable(node: ast.AST) -> bool:
        if reachable_lines is None:
            return True
        return getattr(node, "lineno", -1) in reachable_lines

    def _parse_shell_string(s: str) -> Optional[ScriptCall]:
        """把 shell 命令字符串解析为 ScriptCall（复用 shell 正则语义）。"""
        for m in _CHILD_CALL_RE.finditer(s):
            interp, path, rest = m.group(1), m.group(2).strip(), m.group(3).strip()
            if path.startswith("-") or path.startswith("$") or "/dev/" in path:
                continue
            rest = re.split(r"[;|&<>]", rest)[0].strip()
            args = []
            for tm in re.finditer(r"""(["'])(.*?)\1|(\S+)""", rest):
                args.append(tm.group(2) if tm.group(1) else tm.group(3))
            return ScriptCall(path=path, args=args, interpreter=interp)
        return None

    for node in ast.walk(tree):
        # Collect imports in the same traversal, but append them after command
        # calls to preserve the original ordering and reachability behavior.
        if isinstance(node, ast.ImportFrom) and node.level and node.level >= 1:
            if node.module:
                import_calls.append(ScriptCall(path=node.module.replace(".", "/") + ".py", args=[], interpreter="python3"))
            for alias in node.names:
                if alias.name != "*":
                    import_calls.append(ScriptCall(path=alias.name.replace(".", "/") + ".py", args=[], interpreter="python3"))
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if not _line_reachable(node):
            continue
        mod = node.func.value
        if not isinstance(mod, ast.Name):
            continue
        mod_name, func_name = mod.id, node.func.attr

        # subprocess.run(["bash", "x.sh", "arg"]) 列表形式
        if mod_name == "subprocess" and func_name in _SUBPROCESS_FUNCS:
            if node.args and isinstance(node.args[0], (ast.List, ast.Tuple)):
                elts = []
                all_str = True
                for elt in node.args[0].elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        elts.append(elt.value)
                    else:
                        all_str = False
                        break
                if all_str and len(elts) >= 2:
                    interp = elts[0]
                    path = elts[1]
                    if path.startswith("-") or path.startswith("$") or "/dev/" in path:
                        continue
                    calls.append(ScriptCall(path=path, args=elts[2:], interpreter=interp))
                    continue
            # 字符串形式 subprocess.run("bash x.sh backup", shell=True)
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                sc = _parse_shell_string(node.args[0].value)
                if sc is not None:
                    calls.append(sc)
        # os.system("bash x.sh backup") 字符串形式
        elif mod_name == "os" and func_name in _OS_FUNCS:
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                sc = _parse_shell_string(node.args[0].value)
                if sc is not None:
                    calls.append(sc)

    calls.extend(import_calls)

    # 去重（保持顺序）
    seen: set = set()
    unique: list[ScriptCall] = []
    for c in calls:
        key = (c.path, tuple(c.args), c.interpreter)
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


# ==================== PythonBackend ====================


class PythonBackend(LanguageBackend):
    """python（python3）脚本解析后端。"""

    language = "python"

    ENTRY_PATTERNS = [
        r"(?:^|\s|&&|\|\|)\s*python3?\s+(\S+\.py)",
    ]

    def parse(self, content: str, entry_args: list[str] | None) -> ScriptIR:
        """解析 python 脚本：ast 控制流剪枝 + 子脚本调用提取；失败回退全文本。

        fail-closed 原则（与 ShellBackend 一致）：
        - 语法解析失败 / 超预算 → reachable_content = 全文本，control_flow_resolved=False
        - 条件不可静态求值 → 该分支链整体保留
        """
        if content is None:
            content = ""
        source_lines = content.split("\n")
        env = _Env(argv=list(entry_args or []))
        lines: set = set()
        branches: list[BranchInfo] = []

        # 预算熔断：超行数直接全文本（保持性能红线）
        if len(source_lines) > MAX_LINES:
            calls = _extract_calls_regex(content)
            return ScriptIR(
                reachable_content=content,
                control_flow_resolved=False,
                calls=calls,
                language=self.language,
            )

        try:
            tree = ast.parse(content)
        except SyntaxError:
            # 残缺/混淆脚本：全文本 fail-closed，仍尽力提取子调用
            calls = _extract_calls_regex(content)
            return ScriptIR(
                reachable_content=content,
                control_flow_resolved=False,
                calls=calls,
                language=self.language,
            )

        _process_stmts(tree.body, env, source_lines, lines, branches)
        reachable = _reconstruct(source_lines, lines)

        # 子脚本调用提取（AST 形式优先，正则兜底字符串形式；只取可达分支内的调用）
        calls = _extract_calls_ast(tree, content, reachable_lines=lines)
        if not calls:
            calls = _extract_calls_regex(content)

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
