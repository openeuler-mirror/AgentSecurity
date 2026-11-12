"""Adapter for AgentOS observability service syscall data.

将 AgentOS 可观测服务采集的 syscall 数据转换为标准 AnalyzeRequest 格式。
"""

import logging

logger = logging.getLogger(__name__)


class ObservableAdapter:
    """将 AgentOS 可观测服务 syscall 数据转换为标准 AnalyzeRequest

    输入格式（来自可观测服务）：
    {
        "agent_id": "agent-001",
        "session_id": "session-abc",
        "sandbox_id": "sb-001",
        "os_type": "linux",
        "cwd": "/home/user/project",
        "prompt": "分析日志文件",
        "current_action": {
            "tool": "bash",
            "command": "cat /var/log/app.log",
            "description": "读取应用日志"
        },
        "action_history": [{"tool": "read", "command": "ls -la", "output": "..."}],
        "trace_id": "trace-xyz"
    }

    输出格式：标准 AnalyzeRequest dict
    """

    def adapt(self, raw_data: dict) -> dict:
        """
        将可观测服务数据转换为标准 AnalyzeRequest dict。

        Args:
            raw_data: 可观测服务原始数据

        Returns:
            dict: 标准 AnalyzeRequest 格式
        """
        session_id = raw_data.get("session_id") or raw_data.get("agent_id", "unknown")

        # 可观测服务可能使用 current_action 而非 a_next
        action_raw = raw_data.get("a_next") or raw_data.get("current_action", {})
        if isinstance(action_raw, dict):
            a_next = {
                "action_type": action_raw.get("action_type") or action_raw.get("tool", "unknown"),
                "action_detail": action_raw.get("action_detail") or action_raw.get("command", ""),
            }
        else:
            a_next = {"action_type": "unknown", "action_detail": ""}

        # 可观测服务可能使用 action_history 中的 tool/command 格式
        history_raw = raw_data.get("action_history", [])
        action_history = []
        for h in history_raw:
            if isinstance(h, dict):
                history_item = {
                    "name": h.get("name") or h.get("action_type") or h.get("tool", ""),
                    "action_detail": h.get("action_detail") or h.get("command", ""),
                }
                # 透传 output（工具返回/用户回答）—— L2 授权（consent）判定依赖它：
                # 判「用户是否已授权」看的是 ask_user_question 的回答，不是提问正文。
                # 与 server/routes.py 的标准分支保持同一口径。
                if "output" in h:
                    history_item["output"] = h.get("output", "")
                action_history.append(history_item)

        result = {
            "session_id": session_id,
            "prompt_session": raw_data.get("prompt_session") or raw_data.get("prompt", ""),
            "action_history": action_history,
            "a_next": a_next,
            "reason": raw_data.get("reason") or raw_data.get("current_action", {}).get("description", ""),
            "os_type": raw_data.get("os_type", ""),
            "cwd": raw_data.get("cwd", ""),
        }

        # 从 current_action.description 补充 reason
        if not result["reason"] and isinstance(action_raw, dict):
            result["reason"] = action_raw.get("description", "")

        # 传递 metadata
        metadata = raw_data.get("metadata", {})
        if not metadata:
            metadata = {
                k: raw_data[k] for k in ("agent_id", "sandbox_id", "trace_id", "sandbox_id")
                if k in raw_data and k not in result
            }
        if metadata:
            result["metadata"] = metadata

        logger.debug("Adapted request for session %s (os_type=%s)", session_id, result.get("os_type", "auto"))
        return result


def is_raw_format(data: dict) -> bool:
    """判断数据是否为原始可观测服务格式（需要适配器转换）"""
    # 如果包含 current_action 或缺少 a_next，认为是原始格式
    if "current_action" in data:
        return True
    if "a_next" not in data:
        return True
    # 如果 session_id 缺失但 agent_id 存在，也认为是原始格式
    if "session_id" not in data and "agent_id" in data:
        return True
    return False
