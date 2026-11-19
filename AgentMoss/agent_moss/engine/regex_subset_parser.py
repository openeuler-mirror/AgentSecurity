"""Complete reader for the finite, build-time acceleration regex subset.

Python's public compiler validates the original expression. This reader then
consumes every source character or rejects the *whole* conversion.
"""

from dataclasses import dataclass
import re
import warnings


MAX_PATTERN = 65_536
MAX_NODES = 4_096
MAX_DEPTH = 64


class UnsupportedPattern(ValueError):
    """The original rule is legal, but cannot be converted safely."""


@dataclass(frozen=True)
class Node:
    kind: str
    span: tuple[int, int]
    value: str = ""
    children: tuple["Node", ...] = ()
    minimum: int = 1
    maximum: int | None = 1


_REPEAT = re.compile(r"\{([0-9]+)(?:,([0-9]*))?\}")
_CONTROLS = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v"}
_HEX = set("0123456789abcdefABCDEF")


def parse_pattern(pattern: str, flags: int) -> Node:
    if not isinstance(pattern, str):
        raise TypeError("pattern must be a Unicode string")
    if not isinstance(flags, int) or flags < 0:
        raise ValueError("invalid regex flags")
    if len(pattern) > MAX_PATTERN:
        raise UnsupportedPattern("pattern length budget exceeded")
    # DEBUG prints to stdout, so never pass it to the public compiler.
    with warnings.catch_warnings(record=True) as seen:
        warnings.simplefilter("always", FutureWarning)
        compiled = re.compile(pattern, flags & ~re.DEBUG)
    if any(issubclass(item.category, FutureWarning) for item in seen):
        raise UnsupportedPattern("ambiguous future character-set syntax")
    if (int(compiled.flags) | flags) & ~int(re.I | re.U):
        raise UnsupportedPattern("unsupported flags")
    return _Reader(pattern).parse()


class _Reader:
    def __init__(self, source: str):
        self.source = source
        self.pos = 0
        self.nodes = 0

    def make(self, kind: str, start: int, **kwargs) -> Node:
        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise UnsupportedPattern("parse node budget exceeded")
        return Node(kind, (start, self.pos), **kwargs)

    def parse(self) -> Node:
        root = self.alternation(0)
        if self.pos != len(self.source):
            raise UnsupportedPattern(f"unconsumed source at {self.pos}")
        return root

    def alternation(self, depth: int) -> Node:
        start = self.pos
        branches = [self.sequence(depth)]
        while self.pos < len(self.source) and self.source[self.pos] == "|":
            self.pos += 1
            branches.append(self.sequence(depth))
        return branches[0] if len(branches) == 1 else self.make("alt", start, children=tuple(branches))

    def sequence(self, depth: int) -> Node:
        start = self.pos
        parts = []
        while self.pos < len(self.source) and self.source[self.pos] not in "|)":
            atom = self.atom(depth)
            if self.pos < len(self.source):
                at = self.pos
                ch = self.source[at]
                bounds = {"?": (0, 1), "*": (0, None), "+": (1, None)}.get(ch)
                if bounds is not None:
                    self.pos += 1
                elif ch == "{":
                    match = _REPEAT.match(self.source, at)
                    if match:
                        lower = int(match[1])
                        upper = lower if match[2] is None else (int(match[2]) if match[2] else None)
                        bounds = (lower, upper)
                        self.pos = match.end()
                if bounds is not None:
                    if self.pos < len(self.source) and self.source[self.pos] == "?":
                        self.pos += 1
                    elif self.pos < len(self.source) and self.source[self.pos] == "+":
                        raise UnsupportedPattern(f"possessive repeat at {self.pos}")
                    atom = self.make("repeat", atom.span[0], children=(atom,), minimum=bounds[0], maximum=bounds[1])
            parts.append(atom)
        if not parts:
            return self.make("empty", start)
        return parts[0] if len(parts) == 1 else self.make("seq", start, children=tuple(parts))

    def atom(self, depth: int) -> Node:
        start = self.pos
        ch = self.source[self.pos]
        self.pos += 1
        if ch == "(":
            if depth >= MAX_DEPTH:
                raise UnsupportedPattern("parse depth budget exceeded")
            kind = "group"
            if self.source.startswith("?", self.pos):
                self.pos += 1
                if self.source.startswith(":", self.pos):
                    self.pos += 1
                elif self.source.startswith(("=", "!"), self.pos):
                    kind = "assertion"
                    self.pos += 1
                elif self.source.startswith(("<=", "<!"), self.pos):
                    kind = "assertion"
                    self.pos += 2
                else:
                    raise UnsupportedPattern(f"unsupported group extension at {start}")
            child = self.alternation(depth + 1)
            if self.pos >= len(self.source) or self.source[self.pos] != ")":
                raise UnsupportedPattern(f"unterminated group at {start}")
            self.pos += 1
            return self.make(kind, start, children=(child,))
        if ch == "[":
            return self.character_class(start)
        if ch == "\\":
            kind, value = self.escape(False)
            return self.make(kind, start, value=value)
        if ch == ".":
            return self.make("any", start)
        if ch in "^$":
            return self.make("anchor", start)
        if ch in "{}]":
            raise UnsupportedPattern(f"unsupported literal punctuation at {start}")
        return self.make("literal", start, value=ch)

    def escape(self, in_class: bool) -> tuple[str, str]:
        if self.pos >= len(self.source):
            raise UnsupportedPattern("trailing escape")
        ch = self.source[self.pos]
        self.pos += 1
        if ch.isdecimal() or ch == "N":
            raise UnsupportedPattern(f"unsupported numeric or named escape at {self.pos - 2}")
        if ch in "dDsSwW":
            return "any", ""
        if not in_class and ch in "bBAZ":
            return "anchor", ""
        if ch in _CONTROLS:
            return "literal", _CONTROLS[ch]
        if ch in "xuU":
            size = {"x": 2, "u": 4, "U": 8}[ch]
            digits = self.source[self.pos:self.pos + size]
            if len(digits) != size or any(d not in _HEX for d in digits):
                raise UnsupportedPattern(f"malformed hex escape at {self.pos - 2}")
            self.pos += size
            return "literal", chr(int(digits, 16))
        if ch.isascii() and ch.isalpha():
            raise UnsupportedPattern(f"unsupported letter escape at {self.pos - 2}")
        return "literal", ch

    def class_item(self) -> tuple[str, str]:
        ch = self.source[self.pos]
        self.pos += 1
        return self.escape(True) if ch == "\\" else ("literal", ch)

    def character_class(self, start: int) -> Node:
        negated = self.pos < len(self.source) and self.source[self.pos] == "^"
        if negated:
            self.pos += 1
        chars = set()
        relaxed = negated
        first = True
        while self.pos < len(self.source):
            if (first and self.source[self.pos] == "[") or self.source.startswith(("&&", "||", "~~", "--"), self.pos):
                raise UnsupportedPattern(f"ambiguous character class at {self.pos}")
            if self.source[self.pos] == "]" and not first:
                self.pos += 1
                return self.make("any" if relaxed else "class", start, value="" if relaxed else "".join(sorted(chars)))
            first = False
            left_kind, left = self.class_item()
            if self.pos + 1 < len(self.source) and self.source[self.pos] == "-" and self.source[self.pos + 1] != "]":
                if self.source.startswith("--", self.pos):
                    raise UnsupportedPattern(f"ambiguous character class at {self.pos}")
                self.pos += 1
                right_kind, right = self.class_item()
                if left_kind != "literal" or right_kind != "literal":
                    raise UnsupportedPattern(f"unsupported class range at {self.pos}")
                if ord(left) > 127 or ord(right) > 127:
                    relaxed = True
                else:
                    chars.update(chr(code) for code in range(ord(left), ord(right) + 1))
            elif left_kind != "literal" or ord(left) > 127:
                relaxed = True
            else:
                chars.add(left)
        raise UnsupportedPattern(f"unterminated character class at {start}")
