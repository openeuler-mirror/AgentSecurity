"""`agent-moss verify` —— 批量验证一组命令的判定结果。

用途（2026-11 商用标准 P1）：客户或我们自己改了规则（extra.json /
override.json / Console 开关）之后，需要回答「拦截率有没有退化」。

测试用例集不进发布包，所以客户手上没有 `tests/cases`。这个命令让他们用
**自己的一批真实命令**做基线对比：

    agent-moss verify commands.txt --no-llm > before.txt
    # 改规则
    agent-moss verify commands.txt --no-llm > after.txt
    diff before.txt after.txt

输入格式：每行一条命令；空行和 `#` 开头忽略。

输出：
    Allow  ls -la /tmp
    Deny   rm -rf /
    ...
    汇总：10 条，Deny 3（high 2 / critical 1）

`--json` 输出机器可读格式，便于进 CI 做基线比对。
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass


@dataclass
class VerifyResult:
    command: str
    decision: str
    risk_level: str
    risk_type: str
    violated_layers: list[str]
    reason: str


def load_commands(path: str) -> list[str]:
    p = path.strip()
    if not os.path.isfile(p):
        raise FileNotFoundError(path)
    out: list[str] = []
    with open(p, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            out.append(line)
    return out


def verify_commands(commands: list[str], use_llm: bool = True) -> list[VerifyResult]:
    """逐条调用分析引擎（与 `agent-moss analyze "<命令>"` 同一路径）。"""
    if not use_llm:
        os.environ["AGENT_MOSS_DISABLE_LLM"] = "1"
    from agent_moss.engine.analyzer import analyze
    from agent_moss.profiles import get_profile

    profile = get_profile("linux")
    results: list[VerifyResult] = []
    for cmd in commands:
        out = analyze(
            session_id="verify",
            prompt_session="",
            action_history=[],
            a_next={"action_type": "execute", "action_detail": cmd},
            reason="",
            profile=profile,
        )
        results.append(
            VerifyResult(
                command=cmd,
                decision=str(out.get("decision", "")),
                risk_level=str(out.get("risk_level", "")),
                risk_type=str(out.get("risk_type", "")),
                violated_layers=list(out.get("violated_layers") or []),
                reason=str(out.get("reason", "")),
            )
        )
    return results


def cmd_verify(args) -> int:
    try:
        commands = load_commands(args.file)
    except FileNotFoundError:
        print(f"❌ 文件不存在: {args.file}", file=sys.stderr)
        return 2
    if not commands:
        print("❌ 文件里没有有效命令（空行和 # 注释会被忽略）", file=sys.stderr)
        return 2

    results = verify_commands(commands, use_llm=not args.no_llm)

    if args.json:
        print(
            json.dumps(
                [
                    {
                        "command": r.command,
                        "decision": r.decision,
                        "risk_level": r.risk_level,
                        "risk_type": r.risk_type,
                        "violated_layers": r.violated_layers,
                        "reason": r.reason,
                    }
                    for r in results
                ],
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    deny_by_level: dict[str, int] = {}
    for r in results:
        mark = "Deny " if r.decision.lower() == "deny" else "Allow"
        print(f"{mark}  {r.command}")
        if r.decision.lower() == "deny":
            deny_by_level[r.risk_level] = deny_by_level.get(r.risk_level, 0) + 1
    total = len(results)
    denied = sum(deny_by_level.values())
    detail = " / ".join(f"{k} {v}" for k, v in sorted(deny_by_level.items()))
    print(
        f"\n汇总：{total} 条，Deny {denied}" + (f"（{detail}）" if detail else "")
        + f"，Allow {total - denied}"
    )
    return 0
