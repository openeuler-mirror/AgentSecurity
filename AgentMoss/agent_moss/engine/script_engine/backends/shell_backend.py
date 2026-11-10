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
from dataclasses import dataclass, field

from ..ir import BranchInfo, ScriptCall, ScriptIR
from .base import LanguageBackend


# ==================== 参数绑定 ====================
# 把 entry_args 绑到 $1/$2/${1}/${@}/$*，支持 ${1:-default}


def bind_positional_args(content: str, args: list[str]) -> str:
    """把脚本位置参数 $1/$2/${1}/${@}/${*} 替换为实际参数值。"""
    if not args:
        return content
    all_args = " ".join(args)

    def _repl_num(kind: str, default_val: str | None = None) -> str:
        idx = int(kind)
        if 1 <= idx <= len(args):
            return args[idx - 1]
        if default_val is not None:
            return default_val
        return ""

    # ${n} / ${n:-default} / ${@} / ${*}
    content = re.sub(
        r"\$\{(\d+|@|\*)(?::?[-]?([^}]*))?\}",
        lambda m: (
            all_args
            if m.group(1) in ("@", "*")
            else _repl_num(m.group(1), m.group(2) if m.group(2) is not None else None)
        ),
        content,
    )
    # 裸 $1 $2（不含 ${...}）
    content = re.sub(r"\$(\d+)", lambda m: _repl_num(m.group(1)), content)
    content = re.sub(r"\$[@*]", lambda m: all_args, content)
    return content


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


def _split_case_body(body: str) -> list[BranchInfo]:
    """把 case 分支体切分成 BranchInfo 列表（含单行/多行分支）。"""
    lines = body.split("\n")
    branches: list[BranchInfo] = []
    cur: BranchInfo | None = None
    for ln in lines:
        stripped = ln.strip()
        # 跳过函数定义 name() {
        if re.match(r"^[\w:-]+\s*\(\)\s*\{", stripped):
            continue
        m = re.match(r"^([^()]+?)\)\s*(.*)$", stripped)
        if m:
            pat = m.group(1).strip().strip("\"'")
            inline = m.group(2).strip()
            if pat:
                # 收割上一个分支
                if cur is not None:
                    branches.append(cur)
                cur = BranchInfo(kind="case", label=pat, body=inline, reachable=False)
            continue
        if cur is not None:
            # 多行分支体累积；;; 结束当前分支
            if stripped.strip(";") == "" and stripped.strip() == "":
                pass
            cur.body += (("\n" + ln) if cur.body else ln)
            if stripped.endswith(";;"):
                if cur is not None:
                    branches.append(cur)
                    cur = None
                cur = None
    if cur is not None and cur.body.strip() and not any(b is cur for b in branches):
        branches.append(cur)
    return branches


def _split_nested_case_branches(
    body_lines: list[str],
    selector_val: str,
) -> str | None:
    """嵌套 case 的外层分支切分：选中的分支整体保留，未选中剔除。

    在 body_lines（外层 in 之后、外层 esac 之前的行）上做深度感知扫描：
    - `pattern)` 行（depth 0）开启一个新外层分支；
    - depth 0 的 `;;` 结束当前外层分支（内层 case 的 `;;` 因 depth>0 被跳过）；
    - 匹配 selector_val 的分支被选中，返回其 body（含嵌套原样）。
    意外返 None = 未命中任何外层分支（fail-closed 回退全文）。

    Args:
        body_lines: 外层 case 分支体各行
        selector_val: 外层 selector 已绑定的具体值
    Returns:
        选中分支的 body 文本；无法确定时 None。
    """
    depth = 0
    cur_pat: str | None = None
    cur_body: list[str] = []
    selected: str | None = None
    fallback: str | None = None

    def _flush_as_selected(body_text: str, pat: str | None) -> None:
        nonlocal selected, fallback
        if pat is None:
            return
        pat_values = [v.strip() for v in pat.split("|") if v.strip()]
        if "*" in pat_values:
            if fallback is None:
                fallback = body_text
        elif selector_val in pat_values:
            ordered_vals = pat_values
            if selector_val in ordered_vals:
                selected = body_text

    for ln in body_lines:
        stripped = ln.strip()
        # depth 0 且是 `pattern)` 行 → 新分支
        if depth == 0:
            bm = re.match(r"^([^()]+?)\s*\)\s*(.*)$", stripped)
            if bm:
                if cur_pat is not None:
                    _flush_as_selected("\n".join(cur_body), cur_pat)
                cur_pat = bm.group(1).strip().strip("\"'")
                cur_body = [bm.group(2).strip()] if bm.group(2).strip() else []
                continue
        if re.search(r"\bcase\b", stripped):
            depth += 1
        elif re.search(r"\besac\b", stripped):
            depth = max(0, depth - 1)
        elif cur_pat is not None:
            cur_body.append(ln)
            if depth == 0 and stripped.endswith(";;"):
                _flush_as_selected("\n".join(cur_body), cur_pat)
                cur_pat = None
                cur_body = []
    if cur_pat is not None and cur_body:
        _flush_as_selected("\n".join(cur_body), cur_pat)

    return selected if selected is not None else fallback


def parse_case(content: str, args: list[str] | None) -> str | None:
    """解析 case 结构，返回可达分支内容（None = 未识别/fail-closed）。

    识别 `case <selector> in ... esac`。selector 由 args 绑定，
    命中分支 (显式 / *) 保留，未命中剔除。完全未命中 → None（继续走全文本）。
    """
    m = re.search(r"\bcase\s+(\$\{?\d+\}?|[A-Za-z_]\w*|\$[A-Za-z_]\w*)\s+in", content)
    if not m:
        return None
    selector = m.group(1).strip()
    val = _find_selector_value(selector, args)
    if val is None:
        return None  # selector 无法绑定 → fail-closed

    # 深度配对找本层 esac（嵌套 case 时不能 find 第一个）
    from .symbolic import _find_case_end
    content_lines = content.split("\n")
    end_match = _find_case_end(content_lines, 0)
    if end_match == -1:
        return None
    # body = "in" 之后到本层 esac 之前的行
    body_lines = content_lines[1:end_match]
    body = "\n".join(body_lines)

    has_nested = bool(re.search(r"\bcase\s+", body)) or bool(re.search(r"\bif\s+", body))

    if has_nested:
        # 嵌套：外层仍剪枝（选中的分支整体保留，未选中的剔除），内层候选不细化。
        # 用深度感知的分支切分：`pattern)` 行 + `;;` 结束，但 `;;` 属于外层分支时才算
        # 分支结束（内层 case 的 `;;` 不结束外层）。
        selected = _split_nested_case_branches(body_lines, val)
        if selected is None:
            return None
    else:
        branches = _split_case_body(body)
        selected = None
        fallback = ""
        for b in branches:
            values = [v.strip() for v in b.label.split("|") if v.strip()]
            if "*" in values:
                fallback = b.body
            elif val in values:
                selected = b.body
        selected = selected if selected is not None else (fallback or None)
        if selected is None:
            return None

    prefix = content[: m.start()]
    suffix = "\n".join(content_lines[end_match + 1:])
    return f"{prefix}\n{selected}\n{suffix}"


# ==================== if 分支解析 ====================


def _eval_if_condition(cond: str, args: list[str] | None) -> bool | None:
    """求值 if 的字符串相等条件；无法判定返回 None。

    支持：
      [ "$1" = "clean" ]   /  [ "$1" == "clean" ]
      [ "$MODE" = "x" ]    （$MODE 不可绑定 → None）
      [[ "$1" = test ]]
      [ -f /tmp/x ]        （文件存在性 → None，运行期）
    条件变量里 $1 替换为 args[0] 后比较。
    """
    if not args:
        return None
    inner = re.sub(r"^\[\[?|\]\]?$", "", cond).strip()
    # 单引号/双引号剥除
    inner = inner.replace('"', "").replace("'", "")
    # 找相等操作符
    m = re.search(r"(.*?)\s*(==|=)\s*(.*)", inner)
    if not m:
        return None  # 非相等条件（-f 等）无法静态判定
    left, right = m.group(1).strip(), m.group(3).strip()
    # 左侧变量绑定：$1 → args[0]
    lm = re.match(r"^\$(\d+)$", left)
    if lm:
        idx = int(lm.group(1))
        if 1 <= idx <= len(args):
            left = args[idx - 1]
        else:
            return None
    elif left.startswith("$"):
        return None  # $MODE 命名变量不可绑定
    # 右侧同理
    rm = re.match(r"^\$(\d+)$", right)
    if rm:
        idx = int(rm.group(1))
        if 1 <= idx <= len(args):
            right = args[idx - 1]
        else:
            return None
    # 字面量相等判断
    return (left == right)


def parse_if(content: str, args: list[str] | None) -> str | None:
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
    return f"{prefix}\n{chosen}\n{suffix}"


# ==================== 循环体（保守可达） ====================


def _mark_loops_reachable(content: str) -> str:
    """循环体（while/for/until）全部保留（保守：循环执行次数未知，不可证明不可达）。"""
    # 标记循环结构已处理（不剔除任何内容），返回原样。
    # 这是保守决策：任何剔除都可能漏报（循环体可能在多次迭代中触发危险）。
    return content


# ==================== 子脚本调用提取（含参数） ====================

# bash x.sh param → (x.sh, [param])；整体覆盖含 |/引号的后缀参数
_CHILD_CALL_RE = re.compile(
    r"(?:^|\s|&&|\|\|)\s*"
    r"((?:/bin/)?bash|sh|zsh|(?:python|python3|node|ruby|perl|php|lua))\s+"
    r"(\S+(?:\.(?:sh|shrc|py|js|rb|pl|php|lua))?)"
    r"([^\n;|&]*?)$",
    re.MULTILINE | re.IGNORECASE,
)


def extract_calls_from_content(content: str) -> list[ScriptCall]:
    """提取脚本内容里的子脚本调用（含参数）。Python/Node 等解释器子调用也可识别。"""
    calls: list[ScriptCall] = []
    for m in _CHILD_CALL_RE.finditer(content):
        interp, path, rest = m.group(1), m.group(2).strip(), m.group(3).strip()
        if path.startswith("-") or path.startswith("$") or "/dev/" in path:
            continue
        # 参数切分（剥引号，按空白/管道断）
        rest = re.split(r"[;|&<>]", rest)[0].strip()
        args = []
        for tm in re.finditer(r"""(["'])(.*?)\1|(\S+)""", rest):
            args.append(tm.group(2) if tm.group(1) else tm.group(3))
        calls.append(ScriptCall(path=path, args=args, interpreter=interp))
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

    def parse(self, content: str, entry_args: list[str] | None) -> ScriptIR:
        """解析 shell 脚本：P1 → P2/P3/P4 升级 → fail-closed 回退。

        逐级责任链：
          P1 现有 case/if 字面量匹配 → 能选分支就用
          P2/P3/P4 符号环境执行器 → P1 处理不了时升级（变量拼接/内部变量/glob/数值）
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
        p1_safe = not _P1_UNSAFE_RE.search(content)

        if p1_safe:
            # P1: 现有 case/if 字面量裁剪（bind_positional_args + parse_case/parse_if）
            case_out = parse_case(candidate, entry_args)
            if case_out is not None and case_out != candidate:
                resolved = True
                candidate = case_out
            if_out = parse_if(candidate, entry_args)
            if if_out is not None and if_out != candidate:
                resolved = True
                candidate = if_out
            bound = bind_positional_args(candidate, entry_args or [])
        else:
            # $1 语义不可靠 → 不做绑定/裁剪，保持原文（fail-closed，交 symbolic）
            bound = candidate

        # P2/P3/P4 升级：LiteSE 顺序执行器（只在 P1 未能裁剪时尝试，避免双实现）
        if not resolved:
            from .symbolic import symbolic_process
            sym_out = symbolic_process(content, entry_args)
            if sym_out is not None and sym_out != content:
                resolved = True
                candidate = sym_out
                bound = candidate  # bind 已在 symbolic 内完成

        # 循环体保守标记（保留，不剔除）
        loop_marked = _mark_loops_reachable(bound)

        # 子脚本调用提取
        calls = extract_calls_from_content(loop_marked)

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