#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 AgentMoss 引擎**动态提取**「脚本内容扫描」实际用到的全部正则，导出为 rules.txt。

背景：旧版本这里是手写的硬编码规则列表，与引擎漂移后无人发现（假规则 18 条、
漏规则 4 条）。改为全部从引擎实时读取，改引擎规则后重跑本脚本即可。

格式：每行一条正则表达式。读取方式与引擎一致：

    patterns = [line.strip() for line in open("rules.txt") if line.strip()]
    compiled = [re.compile(p) for p in patterns]
    hits = [p for p in compiled if p.search(script_text)]   # re.search 语义，
                                                            # 命中与否即可，勿用 match/findall

来源（= 引擎对脚本文件内容实际执行的**正则**匹配，逐条对应）：
  1. LinuxProfile.dangerous_commands         引擎 re.compile(pattern, re.IGNORECASE)
  2. LinuxProfile.sensitive_paths            引擎 _check_sensitive_path_access
       - deny_both        → _SensitivePathMatcher.match 的边界式
       - dir_del_only     → 目录边界式（仅「删除/整包归档读该目录」时判定）
       - 其余             → 子串 `path in action_detail` → re.escape 等价正则
  3. logic_rules._check_dangerous_patterns   重定向覆盖 3 条（引擎对已 lower 的入参做 search）
  4. script_content_analyzer.SUSPICIOUS_PATTERNS  脚本关键词扫描（仅对 L1/L2 均未命中的节点执行）

未收录（引擎里不是正则，已知且有意排除）：
  - _check_dangerous_patterns 的「通配符 + 删除」检查：`*`/`?` + 删除关键词的子串组合，
    且带「文本含 /tmp/ 等临时目录则跳过」的守卫，不是单条正则可等价表达。
    实测该检查在当前 9 个脚本上均未命中（含 `*` 的脚本都同时含 /tmp/）。

用法：
    python3 extract_rules.py                 # 引擎默认在 ~/gitcode/AgentMoss
    AGENT_MOSS_ROOT=/path/to/AgentMoss python3 extract_rules.py
"""
from __future__ import annotations

import ast
import inspect
import os
import re
import sys
import textwrap
from pathlib import Path

OUT = Path(__file__).resolve().parent / "rules.txt"


def _find_agent_moss_root() -> Path:
    """定位 AgentMoss 引擎仓：环境变量 > 本仓（在本仓内直接运行）> 默认位置（本脚本被复制到别的仓时）。"""
    candidates = []
    if os.environ.get("AGENT_MOSS_ROOT"):
        candidates.append(Path(os.environ["AGENT_MOSS_ROOT"]))
    candidates.append(Path(__file__).resolve().parents[3])
    candidates.append(Path.home() / "gitcode" / "AgentMoss")
    for c in candidates:
        if (c / "agent_moss" / "engine").is_dir():
            return c
    raise SystemExit(
        "找不到 AgentMoss 引擎仓（需含 agent_moss/engine/）。"
        "请设置 AGENT_MOSS_ROOT 指向引擎仓根目录。"
    )


ROOT = _find_agent_moss_root()
sys.path.insert(0, str(ROOT))

from agent_moss.engine.logic_rules import LogicRulesChecker  # noqa: E402
from agent_moss.engine.script_content_analyzer import SUSPICIOUS_PATTERNS  # noqa: E402
from agent_moss.profiles.linux import LinuxProfile  # noqa: E402

# 与 _SensitivePathMatcher._escape_with_lookahead 一致：lookahead 块原样保留，其余段转义
_LOOKAHEAD_RE = re.compile(r"(\(\?!.*?\))")

lines: list[str] = []

# 1) L1 危险命令 —— 引擎 CommandPatternScanner._compile_from_rules 用 re.IGNORECASE
profile = LinuxProfile()
for c in profile.dangerous_commands:
    lines.append(f"(?i){c.pattern}")

# 2) 敏感路径 —— 引擎 _check_sensitive_path_access（入参与 path 均已 lower）
for sp in profile.sensitive_paths:
    path = sp.path
    low = path.lower()
    deny_mode = sp.deny_mode or (
        "deny_both" if sp.credential else "deny_read" if sp.read_only else "deny_write"
    )
    if deny_mode == "deny_both":
        # 引擎用 _SensitivePathMatcher.match：. 或 / 开头 → 前导 (?:^|[\s/\\'"])；
        # 否则（如 credentials.yml）→ 前导 \b。两者尾随一律 \b。
        escaped = "".join(
            p if p.startswith("(?!") else re.escape(p) for p in _LOOKAHEAD_RE.split(low)
        )
        lead = r"(?:^|[\s/\\'\"])" if (path.startswith(".") or path.startswith("/")) else r"\b"
        lines.append(f"(?i){lead}{escaped}\\b")
    elif getattr(sp, "dir_del_only", False):
        # 目录级条目：前导边界 + 目录名后只接路径分隔符/空白/引号/行尾
        lines.append(rf"(?i)(?:^|[\s/\\'\"]){re.escape(low)}(?:/|[\s'\"\\]|$)")
    else:
        # 引擎此处是子串 `path in action_detail`（deny_write / deny_read）
        lines.append(f"(?i){re.escape(low)}")

# 3) _check_dangerous_patterns 的重定向覆盖 —— 从函数源码 AST 读，引擎改了这里会立刻反映
_src = textwrap.dedent(inspect.getsource(LogicRulesChecker._check_dangerous_patterns))
_override = None
for _node in ast.walk(ast.parse(_src)):
    if isinstance(_node, ast.Assign) and any(
        isinstance(t, ast.Name) and t.id == "override_patterns" for t in _node.targets
    ):
        _override = ast.literal_eval(_node.value)
if not _override:
    raise SystemExit(
        "未能从 LogicRulesChecker._check_dangerous_patterns 提取 override_patterns，"
        "引擎实现可能已改动，请更新本脚本。"
    )
for pat in _override:
    lines.append(f"(?i){pat}")

# 4) SUSPICIOUS_PATTERNS —— 引擎 script_content_analyzer 的脚本关键词扫描（14 条 IGNORECASE + 4 条敏感）
for _name, _pat in SUSPICIOUS_PATTERNS:
    lines.append(f"(?i){_pat.pattern}" if _pat.flags & re.IGNORECASE else _pat.pattern)

# 去重（保序）：重定向覆盖里的 >\s*/etc/ 等与 L1 危险命令重复
seen: set[str] = set()
unique: list[str] = []
for ln in lines:
    if ln not in seen:
        seen.add(ln)
        unique.append(ln)

# 自检：全部可编译，且不得有空行/换行混入
for ln in unique:
    re.compile(ln)

OUT.write_text("\n".join(unique) + "\n", encoding="utf-8")

print(f"引擎仓: {ROOT}")
print(f"已写出 {OUT}")
print(f"  共 {len(unique)} 条唯一正则（去重前 {len(lines)} 条）")
print(f"  L1 危险命令      : {len(profile.dangerous_commands)}")
print(f"  敏感路径         : {len(profile.sensitive_paths)}"
      f"（deny_both {sum(1 for s in profile.sensitive_paths if (s.deny_mode or ('deny_both' if s.credential else 'deny_read' if s.read_only else 'deny_write')) == 'deny_both')}）")
print(f"  重定向覆盖       : {len(_override)}")
print(f"  脚本关键词       : {len(SUSPICIOUS_PATTERNS)}"
      f"（大小写敏感 {sum(1 for _, p in SUSPICIOUS_PATTERNS if not p.flags & re.IGNORECASE)}）")
print(f"  大小写敏感规则   : {sum(1 for ln in unique if not ln.startswith('(?i)'))}")
