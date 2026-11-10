"""脚本分析引擎 — 统一中间表示（IR）

Language Backend（Shell/Python/Node...）把源脚本解析成统一的 IR：
- ScriptIR：单个脚本的静态分析结果
  - reachable_content: 静态判定的可达内容（供 L1/L2/L3 扫描，替代整段全文本）
  - candidate_commands: 所有不可达候选命令（供 fail-closed 时回退全文本）
  - calls: 子脚本调用（路径 + 参数），RecursiveTracker 消费它递归
  - control_flow: 识别的控制流摘要（case 分支数、if 数、循环数），仅供审计/调试

设计原则：
- IR 与语言无关。加新语言 = 新 backend 产出同一份 IR，Scanner/Tracker 不动。
- reachable_content 是保守的：无法静态证明不可达的，宁可放进去（fail-open 方向），
  最终由 Scanner 层做 fail-closed 决策。这里只负责"能证明的精确切片"。
- 所有字段可选，backend 无法解析时返回空 reachable（调用方回退全文本）。
"""

from dataclasses import dataclass, field


@dataclass
class ScriptCall:
    """子脚本调用（路径 + 参数）。由 RecursiveTracker 消费。"""

    path: str                       # 子脚本路径（可相对/绝对/~）
    args: list[str] = field(default_factory=list)  # 调用参数（如 bash child.py backup → ["backup"]）
    interpreter: str = "bash"       # 调用解释器（bash/python3/node...）


@dataclass
class BranchInfo:
    """单个控制流分支（case 分支 / if 分支 / 循环体）"""

    kind: str                       # "case" / "if" / "loop"
    label: str = ""                 # 分支名（case 的 value，如 clean）或 if 条件原文
    body: str = ""                  # 分支体内容（可达才保留）
    reachable: bool = False         # 是否判定为可达（case 命中值 / if 条件真 / 循环体总是可达）


@dataclass
class ScriptIR:
    """单个脚本的静态分析 IR。"""

    # 可达内容：静态证明会执行的部分（供 L1/L2/L3 扫描）
    reachable_content: str = ""
    # 是否成功识别了控制流（True 时丢弃了部分不可达内容；False 时 reachable_content 应为全文本）
    control_flow_resolved: bool = False
    # 子脚本调用
    calls: list[ScriptCall] = field(default_factory=list)
    # 控制流摘要（审计用）
    branches: list[BranchInfo] = field(default_factory=list)
    # 无法静态判定的片段（保留原文，fail-closed 时使用）
    unresolved_snippets: list[str] = field(default_factory=list)
    # 语言（shell / python / node / java...）
    language: str = "shell"

    @property
    def has_calls(self) -> bool:
        return bool(self.calls)


def merge_reachable(ir_list: list[ScriptIR]) -> str:
    """把多个脚本的 reachable_content 拼接（递归链各节点的扫描输入）。"""
    return "\n".join(ir.reachable_content for ir in ir_list if ir.reachable_content)