"""MAX_VARS 上限：超限回退降级，判定不受影响（双端同款保护）。

TS 侧 symbolic.ts 早就有 `if (env.size >= MAX_VARS) return null`；Python 此前
只有常量声明没有检查 —— 自动生成/拼接的脚本若包含几万个变量赋值，环境表会
一路撑大。这里锁住"超限即降级（返回 None → 调用方走全文匹配）"。
"""
from agent_moss.engine.script_engine.backends.symbolic import MAX_VARS, symbolic_process


def test_over_budget_returns_none():
    lines = [f"V{i}=/tmp/f{i}" for i in range(MAX_VARS + 50)]
    lines.append("echo done")
    assert symbolic_process("\n".join(lines), None) is None


def test_under_budget_still_processes():
    lines = [f"V{i}=/tmp/f{i}" for i in range(10)]
    lines.append("rm -rf /tmp/x")
    out = symbolic_process("\n".join(lines), None)
    assert out is not None and "rm -rf /tmp/x" in out
