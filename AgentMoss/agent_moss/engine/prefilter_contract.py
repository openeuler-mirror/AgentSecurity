"""Shared rule identities, resource limits, and text protection policy."""

from dataclasses import dataclass
import re
from types import MappingProxyType


SCHEMA_VERSION = 4  # Fixed-directory status and full-input fingerprint.
CONVERTER_VERSION = 3  # Single simplified regex; rejects both old converters.
BYTE_FORMAT_VERSION = 1
GUARD_VERSION = 1
STRATEGY_VERSION = 1
MAX_PATTERN_LENGTH = 65_536
MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
MAX_RULES = 50_000
MAX_PARSE_NODES = 4_096
MAX_PARSE_DEPTH = 64
MAX_STRUCTURE_BYTES = 4096
MAX_STRUCTURE_NODES = 256
MAX_STRUCTURE_BRANCHES = 64
MAX_EXPRESSIONS = 5120
MAX_COMPILE_ATTEMPTS = 16
NATIVE_MODE = 1  # HS_MODE_BLOCK
NATIVE_FLAGS = 8  # HS_FLAG_SINGLEMATCH

FLAG_VALUES = MappingProxyType({
    "TEMPLATE": 1, "IGNORECASE": int(re.I), "LOCALE": int(re.L),
    "MULTILINE": int(re.M), "DOTALL": int(re.S), "UNICODE": int(re.U),
    "VERBOSE": int(re.X), "DEBUG": int(re.DEBUG), "ASCII": int(re.A),
})
_KNOWN_FLAGS = sum(FLAG_VALUES.values())
GUARD_RANGES = ((0, 8), (11, 12), (14, 31), (127, 159),
                (304, 305), (383, 383), (8490, 8490), (55296, 57343))
_GUARD = re.compile(
    "[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f-\x9f\u0130\u0131\u017f\u212a\ud800-\udfff]"
)


def flag_names(flags: int) -> list[str]:
    if not isinstance(flags, int) or isinstance(flags, bool):
        raise TypeError("rule flags must be an integer")
    if flags < 0 or flags & ~_KNOWN_FLAGS:
        raise ValueError("unknown rule flag bits")
    return [name for name, value in FLAG_VALUES.items() if flags & value]


def rule_key(pattern: str, flags: int) -> tuple[str, int]:
    if not isinstance(pattern, str):
        raise TypeError("rule pattern must be str")
    if not isinstance(flags, int) or isinstance(flags, bool):
        raise TypeError("rule flags must be an integer")
    if flags < 0 or flags & ~_KNOWN_FLAGS:
        raise ValueError("unknown rule flag bits")
    if flags & re.L or flags & re.A and flags & re.U:
        raise ValueError("invalid flags for Unicode string rule")
    return pattern, int(flags if flags & re.A else flags | re.U)


@dataclass(frozen=True)
class RuleSpec:
    pattern: str
    flags: int

    def __post_init__(self):
        _, flags = rule_key(self.pattern, self.flags)
        object.__setattr__(self, "flags", flags)


def guard_text(text: str) -> bool:
    """Any protected character makes the entire scan use Python."""
    return _GUARD.search(text) is not None


def validate_generated_expression(expression: str) -> bool:
    from .prefilter_expression import validate_generated_expression as validate
    return validate(expression)
