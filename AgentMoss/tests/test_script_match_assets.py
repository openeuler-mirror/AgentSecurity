# -*- coding: utf-8 -*-
"""`script_match/` 基准素材与引擎的一致性看护。

`tests/cases_exec/script_match/` 是给做**正则匹配加速**的同事用的基准目录：
`scripts/` 下每个脚本都用 `rules.txt` 里的全部正则跑一遍。README 明写
「改引擎规则后重跑 extract_rules.py 即可」—— 但**没有任何测试看护**，
2026-09 实测它已经漂了：`rules.txt` 停在 135 条，而引擎实际有 185 条
（缺 50 条，含后来新增的 kill/云/DB 破坏性命令）。

后果是**同事拿着过时的规则集测加速**：少 50 条意味着匹配负载被低估，
且在旧规则上做的优化可能在新规则上不成立。

这个测试把漂移变成红灯：改了引擎规则却忘了重跑提取器 → 这里直接失败。
"""

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT_MATCH_DIR = Path(__file__).parent / "cases_exec" / "script_match"


def test_script_match_dir_exists():
    """素材目录得真的在（防止有人为了绿灯把它挪走）。"""
    assert SCRIPT_MATCH_DIR.is_dir()
    assert (SCRIPT_MATCH_DIR / "scripts").is_dir()
    assert (SCRIPT_MATCH_DIR / "extract_rules.py").is_file()
    assert (SCRIPT_MATCH_DIR / "rules.txt").is_file()


def test_rules_txt_matches_engine(tmp_path):
    """`rules.txt` 必须与**当前引擎**提取出来的一致。

    在临时副本里跑提取器（它写死输出路径），避免改动工作区文件。
    """
    src = SCRIPT_MATCH_DIR
    dst = tmp_path / "script_match"
    shutil.copytree(src, dst)

    proc = subprocess.run(
        [sys.executable, str(dst / "extract_rules.py")],
        capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, f"提取器失败：{proc.stderr[-800:]}"

    want = (src / "rules.txt").read_text(encoding="utf-8")
    got = (dst / "rules.txt").read_text(encoding="utf-8")
    if got == want:
        return

    want_set = {ln for ln in want.splitlines() if ln.strip()}
    got_set = {ln for ln in got.splitlines() if ln.strip()}
    missing = sorted(got_set - want_set)   # 引擎有、rules.txt 缺
    extra = sorted(want_set - got_set)     # rules.txt 有、引擎已删
    msg = [
        f"rules.txt 与引擎不一致（提交 {len(want_set)} 条 / 引擎 {len(got_set)} 条）",
        f"  引擎有但 rules.txt 缺 {len(missing)} 条（前 5 条）：",
        *[f"    {p[:100]}" for p in missing[:5]],
        f"  rules.txt 有但引擎已删 {len(extra)} 条（前 5 条）：",
        *[f"    {p[:100]}" for p in extra[:5]],
        "修复：cd tests/cases_exec/script_match && python3 extract_rules.py",
    ]
    pytest.fail("\n".join(msg))


def test_rules_txt_entries_are_compilable():
    """rules.txt 里每条都必须是合法正则 —— 否则同事那边的基准直接跑不起来。"""
    lines = [ln.strip() for ln in (SCRIPT_MATCH_DIR / "rules.txt").read_text(
        encoding="utf-8").splitlines() if ln.strip()]
    assert lines, "rules.txt 是空的"
    bad = []
    for ln in lines:
        try:
            re.compile(ln)
        except re.error as exc:
            bad.append(f"{ln[:80]} → {exc}")
    assert bad == [], "以下正则无法编译：\n" + "\n".join(bad)


def test_scripts_dir_has_large_scripts():
    """`scripts/` 里必须有大脚本 —— 2~39 行的样本压不出真实匹配负载。

    2026-09 客户/同事反馈：样本都太小（最大 39 行），测出来的加速比不代表
    真实生产脚本。补了 500+ 行的 .sh 与 1000+ 行的 .py，这里钉住不让它们退化。
    """
    scripts = SCRIPT_MATCH_DIR / "scripts"
    sh_lines = 0
    py_lines = 0
    for f in scripts.rglob("*"):
        if not f.is_file():
            continue
        try:
            n = len(f.read_text(encoding="utf-8", errors="ignore").splitlines())
        except OSError:
            continue
        if f.suffix == ".sh":
            sh_lines = max(sh_lines, n)
        elif f.suffix == ".py":
            py_lines = max(py_lines, n)
    assert sh_lines >= 500, f"缺 500+ 行的 .sh 样本（当前最大 {sh_lines}）"
    assert py_lines >= 1000, f"缺 1000+ 行的 .py 样本（当前最大 {py_lines}）"
