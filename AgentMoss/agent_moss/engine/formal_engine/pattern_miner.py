"""危险频繁子序列挖掘（Pattern Miner）— 从已发生行为中自动发现组合攻击前序。

背景：FormalEngine 用预置链（l2_rules.json combo_chains）+ P3/P4 抽象性质在图上
验证。但**预置链外的组合形态**（如 CRED→LISTEN、LISTEN→PERSIST）不会命中预置链，
需要数据驱动地"自动发现"。

方法（轻量自研，不引 PAMI 依赖）：
1. **投影 + 压缩**：把每 session 的动作序列用 L2 stage 投影成阶段串（LISTEN/EXEC/
   SCAN/CRED/EXFIL/PERSIST/PRIVESC），并**压缩连续重复**（同 session 连读多个敏感
   文件 → 一个 CRED，避免噪音）。
2. **PrefixSpan 挖掘**：跨 session 挖频繁出现的有序子序列（min_sup 阈值控制）。
3. **危险标注**：频繁 ≠ 危险。只有含危险 stage（PRIVESC/EXFIL/LISTEN）或
   CRED↔LISTEN 等敏感双段组合的才标记为候选攻击模式。

用途：接入 `/api/v1/review` 的 `discovered_patterns` 输出（低频全量回顾），
让"数据驱动发现预置链盲区"成为可审计产物。不参与实时路径。
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable

from .builder import _mark_stage

# 危险 stage：含这些的频繁组合才标记为候选攻击模式
DANGER_STAGES = {"PRIVESC", "EXFIL", "LISTEN"}
# 敏感双段：即便无危险 stage，CRED 紧邻 LISTEN 也算
_SENSITIVE_PAIRS = {("CRED", "LISTEN"), ("LISTEN", "CRED")}


def project_stages(action_history: list[dict[str, Any]]) -> list[str]:
    """把单 session 动作序列投影成压缩后的 stage 序列。"""
    stages: list[str] = []
    prev: str | None = None
    for act in action_history:
        detail = str(act.get("action_detail", ""))
        s = _mark_stage(detail)
        if s and s != prev:
            stages.append(s)
            prev = s
    return stages


def is_dangerous(pat: tuple[str, ...]) -> bool:
    """一个频繁子序列是否算候选攻击模式（危险标注）。"""
    if any(s in DANGER_STAGES for s in pat):
        return True
    for a, b in zip(pat, pat[1:]):
        if (a, b) in _SENSITIVE_PAIRS:
            return True
    return False


def mine_dangerous_patterns(
    sessions: Iterable[dict[str, Any]],
    min_sup: int = 2,
    max_len: int = 4,
) -> list[dict[str, Any]]:
    """从多 session 历史中挖掘危险频繁子序列。

    Args:
        sessions: [{"session_id", "action_history": [{action_type, action_detail}]}]
        min_sup: 最少出现 session 数（跨 session 组合阈值）。
        max_len: 子序列最大长度（防组合爆炸）。

    Returns:
        [{"pattern": [...], "support": int, "risk": str, "reason": str}] 按 support 降序。
    """
    # 1. 投影 + 压缩
    seqs: list[tuple[str, list[str]]] = []
    for s in sessions:
        sid = str(s.get("session_id", ""))
        hist = s.get("action_history") or []
        stages = project_stages(hist)
        if stages:
            seqs.append((sid, stages))
    if not seqs:
        return []

    # 2. 轻量 PrefixSpan
    # 递归前缀投影：projected = [(sid, suffix)] 的列表
    results: dict[tuple[str, ...], int] = {}

    def _mine(prefix: list[str], projected: list[tuple[str, list[str]]]) -> None:
        if prefix:
            results[tuple(prefix)] = len(projected)
        if len(prefix) >= max_len:
            return
        item_sids: dict[str, set[str]] = defaultdict(set)
        for sid, suffix in projected:
            seen: set[str] = set()
            for it in suffix:
                if it not in seen:
                    seen.add(it)
                    item_sids[it].add(sid)
        for it in sorted(item_sids):
            if len(item_sids[it]) >= min_sup:
                _mine(
                    prefix + [it],
                    [
                        (sid, suffix[suffix.index(it) + 1:])
                        for sid, suffix in projected if it in suffix
                    ],
                )

    _mine([], list(seqs))

    # 3. 危险标注 + 排序
    out: list[dict[str, Any]] = []
    for pat, support in results.items():
        if len(pat) < 2 or not is_dangerous(pat):
            continue
        risk = "high" if ("PRIVESC" in pat or "EXFIL" in pat) else "medium"
        out.append({
            "pattern": list(pat),
            "support": support,
            "risk": risk,
            "reason": f"跨 session 频繁出现组合 {'→'.join(pat)}（{support} 个 session），"
                      "预置链未直接覆盖，疑似攻击前序",
        })
    out.sort(key=lambda x: (-x["support"], len(x["pattern"])))
    return out