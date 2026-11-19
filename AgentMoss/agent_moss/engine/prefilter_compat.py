"""Cached public-API checks for the finite regex conversion contract."""

from dataclasses import dataclass, field
import os
import re
import threading
import warnings

from .prefilter_contract import guard_text


@dataclass(frozen=True)
class PythonCompatibility:
    supported: bool
    reason: str


@dataclass
class _Cache:
    pid: int = field(default_factory=os.getpid)
    lock: object = field(default_factory=threading.Lock)
    result: PythonCompatibility | None = None


_cache = _Cache()


def python_compatibility() -> PythonCompatibility:
    """Call only during offline build or background load, never in a scan."""
    global _cache
    cache = _cache
    if cache.pid != os.getpid():
        cache = _cache = _Cache()  # Do not acquire a lock inherited from fork.
    with cache.lock:
        if cache.result is None:
            try:
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter("always", FutureWarning)
                    _check_flags()
                    _check_syntax()
                    _check_ascii_closure()
                if any(issubclass(item.category, FutureWarning) for item in caught):
                    raise ValueError("FutureWarning in regex capability check")
                cache.result = PythonCompatibility(True, "public regex capabilities verified")
            except Exception as error:
                cache.result = PythonCompatibility(False, f"{type(error).__name__}: {error}")
        return cache.result


def _check_flags():
    for name, value in (("IGNORECASE", 2), ("UNICODE", 32), ("DOTALL", 16)):
        if int(getattr(re, name)) != value:
            raise ValueError(f"public flag changed: {name}")
    for source, flags, expected in (("", 0, 32), ("", re.I, 34), ("", re.U, 32)):
        if int(re.compile(source, flags).flags) != expected:
            raise ValueError("effective public flags changed")


def _check_syntax():
    # These are the retained grammar primitives; assertions and Unicode
    # consuming categories are relaxed by conversion, so only syntax matters.
    examples = (
        (r"a\+\(\)\[\]\\b", 0, ("a+()[]\\b",), ("ab",)),
        (r"\x61\u0062\U00000063", 0, ("abc",), ("ABC",)),
        (r"\t\n\r", 0, ("\t\n\r",), ("tnr",)),
        (r"(?:ab|cd)e", 0, ("abe", "cde"), ("ab", "ace")),
        (r"(?:ab|)cd", 0, ("abcd", "cd"), ("ab",)),
        (r"ab?c", 0, ("ac", "abc"), ("abbc",)),
        (r"ab*c", 0, ("ac", "abbbc"), ("bc",)),
        (r"ab+c", 0, ("abc", "abbbc"), ("ac",)),
        (r"(?:ab){2,}c", 0, ("ababc", "abababc"), ("abc",)),
        (r"[]a\-\\]", 0, ("]", "a", "-", "\\"), ("b",)),
        (r"[a-c]", re.I, ("a", "A", "C"), ("d",)),
        (r"\Aab\b(?=!)!(?<!x)\Z", 0, ("ab!",), ("xab!",)),
        (r"a\s\d\wb", 0, ("a\u3000٣中b",), ("ab",)),
        (r"a[^x]b", 0, ("a中b", "a\nb"), ("axb",)),
    )
    for source, flags, accepted, rejected in examples:
        compiled = re.compile(source, flags)
        if any(compiled.fullmatch(text) is None for text in accepted):
            raise ValueError(f"retained syntax changed: {source!r}")
        if any(compiled.fullmatch(text) is not None for text in rejected):
            raise ValueError(f"retained syntax changed: {source!r}")


def _check_ascii_closure():
    checks = []
    for codepoint in range(128):
        char = chr(codepoint)
        expected = {char}
        if "a" <= char <= "z" or "A" <= char <= "Z":
            expected.update((char.lower(), char.upper()))
        expected = {value for value in expected if not guard_text(value)}
        for source in (f"\\x{codepoint:02x}", f"[\\x{codepoint:02x}]"):
            checks.append((re.compile(source, re.I), expected, set()))
    alphabet = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
    for source in ("[a-z]", "[A-Z]", "[a-zA-Z]"):
        checks.append((re.compile(source, re.I), alphabet, set()))
    for start in range(0, 0x110000, 4096):
        text = "".join(chr(codepoint) for codepoint in range(start, min(start + 4096, 0x110000)))
        for compiled, expected, seen in checks:
            for match in compiled.finditer(text):
                value = match.group()
                if len(value) != 1:
                    raise ValueError("ASCII atom no longer consumes one character")
                if not guard_text(value):
                    if value not in expected:
                        raise ValueError(f"ASCII closure changed: {compiled.pattern!r}, U+{ord(value):04X}")
                    seen.add(value)
    if any(seen != expected for _, expected, seen in checks):
        raise ValueError("ASCII closure missing expected match")
