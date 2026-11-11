"""Frozen old behavior used only by optimization parity tests."""
import ast


def legacy_split(action_detail: str) -> list[str]:
    """按 &&/||/;/换行 分段，跳过引号内的分隔符。

    echo "a; b && c" 的引号内分隔符是字面量非命令分隔，不能分段——否则
    引号内 chmod/mkfs 等词会脱离 echo 段被当独立命令首词误匹配（NEW-FP-I）。
    """
    segments: list[str] = []
    cur = []
    i = 0
    quote: str | None = None
    while i < len(action_detail):
        ch = action_detail[i]
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            cur.append(ch)
            i += 1
            continue
        # 检查分隔符 &&/||/;/换行（引号外）
        if ch == ';' or ch == '\n':
            segments.append("".join(cur))
            segments.append(ch)
            cur = []
            i += 1
            continue
        if ch == '&' and i + 1 < len(action_detail) and action_detail[i + 1] == '&':
            segments.append("".join(cur))
            segments.append("&&")
            cur = []
            i += 2
            continue
        if ch == '|' and i + 1 < len(action_detail) and action_detail[i + 1] == '|':
            segments.append("".join(cur))
            segments.append("||")
            cur = []
            i += 2
            continue
        cur.append(ch)
        i += 1
    if cur:
        segments.append("".join(cur))
    return segments

def legacy_mark(node: ast.AST, lines: set, source_lines: list) -> None:
    """把节点的源行加入可达行集合（含多行节点）。"""
    start = getattr(node, "lineno", None)
    end = getattr(node, "end_lineno", None)
    if start is None:
        return
    if end is None:
        end = start
    for i in range(start, end + 1):
        if 1 <= i <= len(source_lines):
            lines.add(i)

def legacy_mark_tree(stmt: ast.AST, lines: set, source_lines: list) -> None:
    """def/class 体整树保守标记（不剪枝）。"""
    for n in ast.walk(stmt):
        legacy_mark(n, lines, source_lines)
