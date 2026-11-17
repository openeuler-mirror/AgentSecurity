"""`agent-moss verify` 批量判定验证的行为看护。"""

from __future__ import annotations

from agent_moss.verify_tool import load_commands, verify_commands


def test_load_skips_blank_and_comments(tmp_path):
    f = tmp_path / "cmds.txt"
    f.write_text("# 注释\n\nls -la /tmp\n   \nrm -rf /\n", encoding="utf-8")
    assert load_commands(str(f)) == ["ls -la /tmp", "rm -rf /"]


def test_load_missing_file(tmp_path):
    try:
        load_commands(str(tmp_path / "nope.txt"))
    except FileNotFoundError:
        return
    raise AssertionError("应抛 FileNotFoundError")


def test_verify_decisions():
    results = verify_commands(["ls -la /tmp", "rm -rf /"], use_llm=False)
    assert results[0].decision.lower() == "allow"
    assert results[1].decision.lower() == "deny"
    assert results[1].risk_level in ("high", "critical")
    assert results[1].violated_layers


def test_verify_is_stable_across_runs():
    """同一批命令两次结果必须一致（规则变更对比的前提）。"""
    cmds = ["cat /etc/hostname", "rm -rf /tmp/x", "echo hi"]
    a = verify_commands(cmds, use_llm=False)
    b = verify_commands(cmds, use_llm=False)
    assert [(r.decision, r.risk_level) for r in a] == [(r.decision, r.risk_level) for r in b]
