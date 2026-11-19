"""Validate loaded byte patterns without executing or trusting package text."""

import re

from .prefilter_contract import MAX_STRUCTURE_BYTES, MAX_STRUCTURE_NODES, MAX_STRUCTURE_BRANCHES


_BYTE = re.compile(r"\\x([0-9a-f]{2})")
_COUNT = re.compile(r"\{([0-9]+)(?:,([0-9]*))?\}")


def validate_generated_expression(expression: str) -> bool:
    if not isinstance(expression, str) or not expression.isascii() or not 0 < len(expression) <= MAX_STRUCTURE_BYTES:
        return False
    position = nodes = branches = 0

    def byte():
        nonlocal position
        match = _BYTE.match(expression, position)
        if match is None or int(match[1], 16) > 127:
            raise ValueError("not an ASCII byte atom")
        position = match.end()

    def alternation(depth):
        nonlocal position, branches
        nullable = sequence(depth)
        count = 1
        while position < len(expression) and expression[position] == "|":
            position += 1
            count += 1
            nullable |= sequence(depth)
        if count > 1:
            branches += count
            if branches > MAX_STRUCTURE_BRANCHES:
                raise ValueError("too many branches")
        return nullable

    def sequence(depth):
        nonlocal position, nodes
        if depth > 64:
            raise ValueError("too deeply nested")
        nullable = True
        while position < len(expression) and expression[position] not in "|)":
            nodes += 1
            if nodes > MAX_STRUCTURE_NODES:
                raise ValueError("too many atoms")
            repeatable = False
            if expression.startswith("(?s:.*)", position):
                position += 7
                atom_nullable = True
            elif expression.startswith("(?:", position):
                position += 3
                atom_nullable = alternation(depth + 1)
                if position >= len(expression) or expression[position] != ")":
                    raise ValueError("unterminated group")
                position += 1
            elif expression[position] == "[":
                position += 1
                members = 0
                while position < len(expression) and expression[position] != "]":
                    byte()
                    members += 1
                if members == 0 or position >= len(expression):
                    raise ValueError("invalid byte class")
                position += 1
                atom_nullable = False
                repeatable = True
            else:
                byte()
                atom_nullable = False
                repeatable = True
            if position < len(expression) and expression[position] in "?*+{":
                if not repeatable:
                    raise ValueError("invalid repetition target")
                ch = expression[position]
                if ch in "?*+":
                    position += 1
                    atom_nullable = ch in "?*"
                else:
                    match = _COUNT.match(expression, position)
                    if match is None:
                        raise ValueError("invalid repetition")
                    minimum = int(match[1])
                    maximum = minimum if match[2] is None else (int(match[2]) if match[2] else None)
                    if minimum > 64 or maximum is not None and (maximum < minimum or maximum > 64):
                        raise ValueError("repetition budget exceeded")
                    position = match.end()
                    atom_nullable = minimum == 0
            nullable &= atom_nullable
        return nullable

    try:
        nullable = sequence(0)
        return position == len(expression) and not nullable
    except (ValueError, RecursionError):
        return False
