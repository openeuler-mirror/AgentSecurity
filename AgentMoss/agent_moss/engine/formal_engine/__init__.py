"""形式化引擎（Formal Engine）— Agent 行为形式化验证模块。

定位：类似 script_engine 的独立引擎——把 agent 的多 session 历史动作构建为
行为图（节点=动作，边=时间序/数据流），再对图做安全性质验证（跨会话组合链、
敏感数据传播等），输出合规证明或反例路径。

三层架构：
- IR（ir.py）：ActionNode / BehaviorEdge / SessionGraph / MultiSessionGraph
- 构建（builder.py）：从 action_history / session_history 构建行为图
- 验证（engine.py + properties.py）：FormalEngine 对图执行性质验证

有状态增量模块：
- stateful.py：StatefulChainTracker —— 时间线持续累积 + 链指针增量推进 +
  生命周期（alive/dead/never_activated）+ 敏感数据 taint 增量传播。
  每次新动作实时判定（O(链数)），结果与 FormalEngine 全量 verify 一致。

双端镜像：TS 端 ts/src/engine/formal-engine/ 与本包逐文件对齐。
"""

from .engine import FormalEngine
from .ir import (
    ActionNode,
    BehaviorEdge,
    FormalVerificationResult,
    MultiSessionGraph,
    PropertyViolation,
    SessionGraph,
)
from .stateful import StatefulChainTracker

__all__ = [
    "FormalEngine",
    "StatefulChainTracker",
    "ActionNode",
    "BehaviorEdge",
    "FormalVerificationResult",
    "MultiSessionGraph",
    "PropertyViolation",
    "SessionGraph",
]