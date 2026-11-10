"""形式化引擎 — FormalEngine 验证引擎入口

对外 API（对齐 script_engine 的"引擎 + 统一 IR + 扫描层"架构）：
- `FormalEngine.verify(sessions, a_next)` → FormalVerificationResult
  输入多 session 历史动作（向后兼容：可只传当前 session），内部：
  1. builder 构建 MultiSessionGraph（单 session 也可，跨会话边自动生成）
  2. 依次执行 ALL_PROPERTIES 的性质验证（命中即停，fail-closed）
  3. 输出 verified / violations（反例路径）

运行成本：O(节点 × 性质 × 边)，无状态爆炸、无路径枚举——单 session
几毫秒内完成，多 session 线性增长，符合 AgentMoss 性能红线。
"""

import logging
from typing import Any

from .builder import build_multi_session_graph
from .ir import FormalVerificationResult
from .properties import ALL_PROPERTIES

logger = logging.getLogger(__name__)


def _ebpf_event_to_detail(e: dict) -> str:
    """把 eBPF syscall 事件转成 stage 正则可识别的一句话。

    e 来自 AgentGate metadata.ebpf_events，关键字段：syscall/op/argv/remote_addr/
    remote_port。目标是让 EXFIL（remote 外发）、CRED（读 .ssh 等）、PRIVESC
    （sudo/root 提权）阶段能命中真实行为特征。
    """
    parts: list[str] = []
    syscall = str(e.get("syscall") or e.get("op") or "")
    argv = str(e.get("argv") or e.get("pathname") or "")
    remote = str(e.get("remote_addr") or "")
    port = e.get("remote_port") or 0
    if syscall:
        parts.append(syscall)
    if argv and argv not in ("", "None"):
        parts.append(argv)
    if remote:
        parts.append("to " + remote + (f":{port}" if port else ""))
    return " ".join(parts)


class FormalEngine:
    """行为形式化验证引擎（独立模块，类似 script_engine 架构）。"""

    def __init__(self, properties: list | None = None):
        """properties: 自定义性质列表（缺省用内置 ALL_PROPERTIES）。"""
        self._properties = list(properties) if properties is not None else ALL_PROPERTIES

    def verify(
        self,
        sessions: list[dict[str, Any]] | None = None,
        a_next: dict[str, Any] | None = None,
        ebpf_events: list[dict[str, Any]] | None = None,
    ) -> FormalVerificationResult:
        """对行为图做性质验证。

        Args:
            sessions: 多 session 历史动作列表，每项 {"session_id", "action_history"}。
                缺省/空 → 仅用 a_next 构建单 session 图（向后兼容）。
            a_next: 当前 session 拟执行的下一步动作（可选）。
            ebpf_events: 真实 syscall 事件（AgentGate eBPF 采集）作为"行为证据"
                注入独立 session（P3 接入：让 P3/P4 用真实系统调用校验声明-行为一致）。

        Returns:
            FormalVerificationResult: verified=True 放行；否则 violations 含反例路径。
        """
        sessions = list(sessions) if sessions else []
        if ebpf_events:
            # 真实 syscall 证据作为独立 session 追加（source_collector=ebpf）。
            # 公开的 a_next 是"声明"，这里的 syscall 是"行为"，性质可交叉校验。
            sessions.append({
                "session_id": "ebpf-evidence",
                "action_history": [
                    {
                        "action_type": "syscall",
                        "action_detail": _ebpf_event_to_detail(e),
                    }
                    for e in ebpf_events
                ],
            })
        graph = build_multi_session_graph(sessions or [], a_next=a_next)
        if a_next is not None:
            # witness 语义：a_next 即"当前拟执行动作"，是图末节点。性质检查只当
            # 该节点补全链/触发后置外传才判违规（修复历史全局匹配 → 永久拒绝 FP）。
            graph.witness_idx = len(graph.all_nodes) - 1
        result = FormalVerificationResult(verified=True)

        for prop in self._properties:
            try:
                violations = prop.check(graph)
            except Exception as e:  # 性质验证异常 → fail-closed（保守拦截）
                logger.warning("形式化性质 %s 验证异常，fail-closed: %s", prop.id, e)
                from .ir import PropertyViolation
                result.verified = False
                result.violations.append(PropertyViolation(
                    property_id=prop.id,
                    reason=f"形式化性质验证异常，保守拦截: {e}",
                    risk_level="medium",
                ))
                return result
            if violations:
                result.verified = False
                result.violations.extend(violations)
                break  # 命中即停（与 L2 短路语义一致）

        if not result.verified:
            v = result.first_violation
            logger.info(
                "形式化验证未通过: property=%s risk=%s path_len=%d",
                v.property_id if v else "?", v.risk_level if v else "?",
                len(v.path) if v else 0,
            )
        return result
