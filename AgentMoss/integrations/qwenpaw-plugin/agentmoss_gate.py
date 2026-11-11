# -*- coding: utf-8 -*-
"""AgentMoss Security Gate plugin for QwenPaw.

Zero-intrusion integration: this plugin is a *separate file* placed in
QwenPaw's plugin directory.  It does not modify any QwenPaw source code.

Flow (per tool call):

    QwenPaw resolves the tool and runs its permission check
      -> on_check_permission is invoked (our hook)
      -> we call the AgentGate `/api/v1/analyze` endpoint with:
             tool name + arguments
             the current turn prompt  (user message that drove this call)
             the full session context  (agent.state.context, interleaved
                                        prompts and prior tool calls)
      -> AgentGate returns an AgentMoss verdict (Allow / Deny)
      -> if Deny: we return a Deny decision to QwenPaw, which then refuses
         to execute the tool (the action never runs).

Because we hook `on_check_permission` (NOT `on_acting`), we see the tool
call *before* it is allowed to execute, we have full prompt + history
context, and a Deny truly prevents the tool from running.

This complements QwenPaw's own governance: QwenPaw's decision is passed
to AgentGate as context, and AgentMoss's verdict is authoritative when it
is stricter (double gate).

Fail-open: if AgentGate is unreachable or errors, we fall back to the
underlying QwenPaw permission decision so the agent keeps working
(exactly like AgentMoss's own fail-open L3 design).  Set
``fail_closed: true`` in the plugin config to fail closed instead.
"""

import json
import logging
import os
import platform
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

import httpx

from agentscope.middleware import MiddlewareBase
from agentscope.permission import PermissionBehavior, PermissionDecision

from qwenpaw.plugins.api import PluginApi

logger = logging.getLogger(__name__)

DEFAULT_GATE_URL = os.environ.get(
    "AGENTMOSS_GATE_URL",
    # Matches AgentGate's own default port (agent-gate server --port 9100).
    "http://127.0.0.1:9100",
)
DEFAULT_TIMEOUT = float(os.environ.get("AGENTMOSS_GATE_TIMEOUT", "5.0"))
DEFAULT_AGENT_TYPE = "qwenpaw"
DEFAULT_FAIL_CLOSED = os.environ.get("AGENTMOSS_FAIL_CLOSED", "").lower() in (
    "1",
    "true",
    "yes",
)

# Deny/ask behaviors from QwenPaw's own engine that we surface to AgentGate
# as the "governance decision" context (so AgentMoss sees QwenPaw already
# flagged it).
QP_DENY_BEHAVIORS = {
    PermissionBehavior.DENY,
    PermissionBehavior.ASK,
}


def _load_config(plugin_dir: Path) -> dict[str, Any]:
    """Load plugin config from ``config.json`` next to this file."""
    default = {
        "gate_url": DEFAULT_GATE_URL,
        "timeout": DEFAULT_TIMEOUT,
        "agent_type": DEFAULT_AGENT_TYPE,
        "fail_closed": DEFAULT_FAIL_CLOSED,
        "api_token": "",
        "extra_metadata": {},
    }
    path = plugin_dir / "config.json"
    if not path.exists():
        return default
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            default.update({k: v for k, v in data.items() if v not in (None, "")})
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Failed to read %s: %s", path, exc)
    return default


def _block_type(block: Any) -> str:
    """Content block 的 type 字段（兼容 str / dict / pydantic 模型）。

    AgentScope 的 ``Msg.content`` 是 **ContentBlock 对象列表**（TextBlock /
    ToolCallBlock 等 pydantic 模型），不是字符串也不是 dict —— 早期实现只认
    str/dict，导致所有块都落到 ``str(content)`` 兜底，提取出的是对象 repr
    （含随机 id、时间戳），而非真实内容。
    """
    if isinstance(block, str):
        return "text"
    if isinstance(block, dict):
        return str(block.get("type") or "")
    return str(getattr(block, "type", "") or "")


def _block_text(block: Any) -> str:
    """文本块的内容（兼容 str / dict / pydantic 模型）。"""
    if isinstance(block, str):
        return block
    if isinstance(block, dict):
        text = block.get("text")
    else:
        text = getattr(block, "text", None)
    return str(text) if text is not None else ""


def _msg_text(msg: Any) -> str:
    """Extract human-readable text from an AgentScope Msg (best effort)."""
    if msg is None:
        return ""
    content = getattr(msg, "content", None)
    if content is None:
        return str(msg)
    if isinstance(content, str):
        return content
    if isinstance(content, (list, tuple)):
        parts = [
            _block_text(b) for b in content
            if _block_type(b) == "text" and _block_text(b).strip()
        ]
        if parts:
            return "\n".join(parts)
        return ""
    return str(content)


def _msg_tool_calls(msg: Any) -> list[dict[str, str]]:
    """真实工具调用块（ToolCallBlock）→ [{action_type, action_detail}]。

    历史动作必须取自 ToolCallBlock（``name`` + ``input``），**不能**用
    assistant 的文本充当——文本是模型的说明文字，不是执行过的动作。
    ``input`` 是原始 JSON 字符串（流式累积），保持原样透传。
    """
    content = getattr(msg, "content", None)
    if not isinstance(content, (list, tuple)):
        return []
    calls: list[dict[str, str]] = []
    for block in content:
        if _block_type(block) != "tool_call":
            continue
        if isinstance(block, dict):
            name = str(block.get("name") or "")
            raw = block.get("input") or ""
        else:
            name = str(getattr(block, "name", "") or "")
            raw = getattr(block, "input", "") or ""
        if not name:
            continue
        # Unescape the raw JSON input — a JSON-escaped Windows path would
        # otherwise reach AgentMoss with doubled separators and match nothing.
        calls.append({
            "action_type": name,
            "action_detail": _raw_input_text(raw)[:2000],
        })
    return calls


def _role_of(msg: Any) -> str:
    role = getattr(msg, "role", None) or getattr(msg, "name", "")
    if role == "user":
        return "user"
    if role in ("assistant", "system"):
        return role
    return str(role)


def _extract_cwd(agent: Any) -> str:
    """Agent 的工作目录（AgentMoss 用于相对路径解析 / 间接访问检测）。

    QwenPaw agent 上的实际属性是 ``_workspace_dir``；``work_dir`` 并不存在
    （早期实现用它 + getattr 默认值，导致 cwd **恒为空字符串**）。
    逐级兜底，全部缺失时返回空串。
    """
    for attr in ("_workspace_dir", "workspace_dir", "work_dir"):
        value = getattr(agent, attr, None)
        if value:
            return str(value)
    return ""


def _extract_session_context(agent: Any) -> dict[str, Any]:
    """从 agent 提取上报给 AgentGate 的会话上下文。

    Reads ``agent.state.context`` (the interleaved live message window)
    plus ``agent._request_context['session_id']`` when present.

    Returns a dict with:
        - prompt_turns:   [{"text": <user prompt>, "actions": [...]}], in
          order; each user prompt is grouped with the tool calls that
          followed it until the next prompt.
        - user_prompt:    the most recent user prompt.
        - session_id:     QwenPaw session id if known, else "".
        - action_history: flattened tool calls across the window, in order —
          the same information AgentMoss uses for read_before_write.
        - reason:         assistant text emitted alongside the most recent
          tool call (the model's stated rationale); "" when absent.
        - cwd:            agent working directory.
    """
    state = getattr(agent, "state", None)
    context = getattr(state, "context", None) or []
    session_id = ""
    request_context = getattr(agent, "_request_context", None) or {}
    if isinstance(request_context, dict):
        session_id = str(request_context.get("session_id", "") or "")

    turns: list[dict[str, Any]] = []
    last_user_index = -1
    reason = ""

    for msg in context:
        role = _role_of(msg)
        text = _msg_text(msg).strip()
        calls = _msg_tool_calls(msg)

        if role == "user" and text:
            turns.append({"text": text, "actions": []})
            last_user_index = len(turns) - 1
            continue

        if not calls:
            continue
        # Tool calls belong to the latest user turn (drop orphans that appear
        # before any user prompt — they are not part of this conversation).
        if last_user_index >= 0:
            turns[last_user_index]["actions"].extend(calls)
        # The assistant's text next to a tool call is its stated rationale.
        # Keep the newest one, so `reason` describes the CURRENT call.
        if role == "assistant" and text:
            reason = text

    user_prompt = turns[-1]["text"] if turns else ""
    action_history = [
        action for turn in turns for action in turn["actions"]
    ]

    # Guard against unbounded growth: keep the last 50 turns.
    if len(turns) > 50:
        turns = turns[-50:]
    if len(action_history) > 200:
        action_history = action_history[-200:]

    return {
        "prompt_turns": turns,
        "user_prompt": user_prompt,
        "session_id": session_id,
        "action_history": action_history,
        "reason": reason[:2000],
        "cwd": _extract_cwd(agent),
    }

    return turns, user_prompt, session_id


#: Tool-input keys most likely to carry the action itself, in priority order.
#: QwenPaw declares the shell one explicitly (``target_param="command"``); the
#: rest cover the file/search/network tools so their target is still surfaced.
_PRIMARY_INPUT_KEYS = (
    "command", "cmd", "shell_command", "script", "code",
    "path", "file_path", "filepath", "target", "dir", "directory",
    "url", "query", "pattern", "content", "text",
)


def _tool_input_text(tool_input: dict[str, Any]) -> str:
    """Render tool input for AgentMoss, **without JSON escaping**.

    JSON-dumping the input dict escapes backslashes — ``C:\\Windows`` becomes
    ``C:\\\\Windows`` in the emitted text — so every Windows path rule (which
    matches a single separator) fails to fire. Emitting the parameter values
    verbatim keeps paths intact; the primary key comes first, remaining string
    values follow so nothing is lost.
    """
    if not tool_input:
        return ""
    parts: list[str] = []
    for key in _PRIMARY_INPUT_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            parts.append(value)
    for key, value in tool_input.items():
        if key in _PRIMARY_INPUT_KEYS:
            continue
        if isinstance(value, str) and value.strip():
            parts.append(value)
    if parts:
        return "\n".join(parts)[:8000]
    # No string parameter at all (pure numeric/bool input) — keep the dict form
    # so the call is still visible to the analysis.
    try:
        return json.dumps(tool_input, ensure_ascii=False, default=str)[:8000]
    except (TypeError, ValueError):
        return str(tool_input)[:8000]


def _raw_input_text(raw: Any) -> str:
    """``ToolCallBlock.input`` (a raw JSON string) → the same unescaped form."""
    if isinstance(raw, dict):
        return _tool_input_text(raw)
    text = str(raw or "")
    if not text.strip():
        return ""
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return text[:8000]
    if isinstance(parsed, dict):
        return _tool_input_text(parsed)
    return str(parsed)[:8000]


class AgentMossGateMiddleware(MiddlewareBase):
    """Intercepts the permission check for each tool call."""

    def __init__(
        self,
        *,
        gate_url: str,
        timeout: float,
        agent_type: str,
        fail_closed: bool,
        api_token: str,
        extra_metadata: dict[str, Any],
    ) -> None:
        self._gate_url = gate_url.rstrip("/")
        self._timeout = timeout
        self._agent_type = agent_type
        self._fail_closed = fail_closed
        self._api_token = api_token
        self._extra_metadata = extra_metadata
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self._timeout),
        )

    # ------------------------------------------------------------------
    # Hook implementation
    # ------------------------------------------------------------------

    async def on_check_permission(
        self,
        agent: Any,
        input_kwargs: dict[str, Any],
        next_handler: Callable[..., Awaitable[PermissionDecision]],
    ) -> PermissionDecision:
        """Call AgentGate before the tool is allowed to execute."""
        tool_call = input_kwargs.get("tool_call")
        tool = input_kwargs.get("tool")
        tool_input = input_kwargs.get("tool_input") or {}

        tool_name = getattr(tool_call, "name", "") or getattr(tool, "name", "")

        # Let QwenPaw resolve its own decision first — we need it both as
        # fallback (fail-open) and as context for AgentGate.
        qp_decision = await next_handler(**input_kwargs)
        qp_behavior = getattr(qp_decision, "behavior", None)
        qp_message = getattr(qp_decision, "message", "") or ""
        qp_allowed = qp_behavior == PermissionBehavior.ALLOW

        # Build AgentGate payload
        ctx = _extract_session_context(agent)
        command = _tool_input_text(tool_input)

        # cwd 优先取**本次调用显式指定**的值：QwenPaw 的 shell 工具签名是
        # `execute_shell_command(command, timeout, cwd=None, ...)` —— cwd 为 None
        # 时才回退 agent workspace，模型完全可以为此条命令指定别处的工作目录
        # （实测：agent 执行 `dir` 时传了 cwd="C:\Windows"）。
        # AgentMoss 用 cwd 做间接文件访问检测（列 cwd 下文件）与相对路径解析，
        # 报错目录会让这两项对着错误的位置判断。
        call_cwd = ""
        if isinstance(tool_input, dict):
            raw_cwd = tool_input.get("cwd")
            if raw_cwd:
                call_cwd = str(raw_cwd)

        payload = {
            "agent_type": self._agent_type,
            "agent_version": "qwenpaw-plugin-0.1.0",
            "session_id": ctx["session_id"] or "qwenpaw-unknown",
            "cwd": call_cwd or ctx["cwd"],
            "tool_name": tool_name,
            "command": command,
            # The model's stated rationale next to this tool call. AgentMoss
            # feeds it to L3 skill matching and uses it to tell "create a new
            # file" from "overwrite an existing one" in read_before_write.
            "description": ctx["reason"],
            "user_prompt": ctx["user_prompt"],
            "prompt_history": ctx["prompt_turns"],
            # Send the tool calls we saw in this session's context window.
            # Previously omitted in favour of AgentGate's SQLite auto-fill,
            # which only knows calls made *after* the plugin was enabled —
            # history-dependent L2 rules (read_before_write) then missed
            # everything from earlier in the session.
            "action_history": ctx["action_history"],
            "metadata": {
                "source": "qwenpaw-plugin",
                # The OS the agent itself runs on. AgentGate normally infers
                # this from its own host, which is wrong when the gateway is
                # deployed on a different platform than the agent (e.g. agent
                # on Windows, gateway on Linux) — AgentMoss would then apply
                # the Linux rule set to Windows commands.
                "os_type": platform.system().lower(),
                # The machine the AGENT runs on. AgentGate builds its agent id
                # as f"{agent_type}:{hostname}"; without this it falls back to
                # the gateway's own hostname, so every same-type agent behind
                # one gateway is merged into a single record and the dashboard
                # can no longer say which machine a call came from (measured:
                # an agent on another host was filed under the gateway's name).
                "hostname": platform.node(),
                "qp_behavior": getattr(qp_behavior, "value", ""),
                "qp_message": qp_message[:1000],
                **self._extra_metadata,
            },
        }

        verdict = await self._query_agentgate(payload, tool_name, command)

        if verdict is None:
            # AgentGate unreachable / error.
            if self._fail_closed:
                logger.warning(
                    "AgentGate unreachable and fail_closed is set; "
                    "denying %s (message: %s)",
                    tool_name,
                    qp_message[:200],
                )
                return PermissionDecision(
                    behavior=PermissionBehavior.DENY,
                    message="AgentGate unavailable (fail closed): "
                    + qp_message,
                )
            logger.warning(
                "AgentGate unreachable; falling back to QwenPaw "
                "decision for %s (allowed=%s)",
                tool_name,
                qp_allowed,
            )
            return qp_decision

        # AgentGate responded with an AgentMoss verdict.
        if verdict.get("decision") in ("Deny", "deny"):
            return PermissionDecision(
                behavior=PermissionBehavior.DENY,
                message=(
                    "AgentMoss: "
                    + str(verdict.get("reason", ""))[:500]
                ),
                decision_reason=(
                    "risk_level="
                    + str(verdict.get("risk_level", ""))
                    + " risk_type="
                    + str(verdict.get("risk_type", ""))
                ),
            )

        # Allow: return QwenPaw's own decision (so its messages/behavior
        # are preserved), but propagate any AgentMoss denial info as
        # context for auditing.
        if not qp_allowed:
            # QwenPaw denied even though AgentMoss allowed -> keep QwenPaw's
            # denial (it is the stricter gate in this direction).
            return qp_decision
        return qp_decision

    # ------------------------------------------------------------------
    # AgentGate client
    # ------------------------------------------------------------------

    async def _query_agentgate(
        self,
        payload: dict[str, Any],
        tool_name: str,
        command: str,
    ) -> Optional[dict[str, Any]]:
        url = self._gate_url + "/api/v1/analyze"
        headers = {"Content-Type": "application/json"}
        if self._api_token:
            headers["Authorization"] = f"Bearer {self._api_token}"
        try:
            resp = await self._client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:  # noqa: BLE001
            # Include the exception type: httpx timeout errors stringify to
            # an empty message, which makes "failed: " logs undiagnosable.
            logger.warning(
                "AgentGate analyze failed for %s (cmd=%s...): %s: %s",
                tool_name,
                command[:80],
                type(exc).__name__,
                exc or "(no message)",
            )
            return None


# ----------------------------------------------------------------------
# Plugin factory
# ----------------------------------------------------------------------


def _middleware_factory(ctx: Any, agent_config: Any):
    """Create the middleware, or None (skip) when the plugin is disabled."""
    del agent_config

    plugin_dir = Path(__file__).resolve().parent
    config = _load_config(plugin_dir)

    # Allow disabling via env var without touching config.json
    if os.environ.get("AGENTMOSS_DISABLE") in ("1", "true", "yes"):
        logger.info("AgentMoss gate plugin disabled via env var")
        return None

    return AgentMossGateMiddleware(
        gate_url=str(config["gate_url"]),
        timeout=float(config["timeout"]),
        agent_type=str(config["agent_type"]),
        fail_closed=bool(config["fail_closed"]),
        api_token=str(config.get("api_token", "")),
        extra_metadata=dict(config.get("extra_metadata", {}) or {}),
    )


class AgentMossGatePlugin:
    """Plugin entry point."""

    def register(self, api: PluginApi) -> None:
        api.register_middleware(
            _middleware_factory,
            # Low priority number = outermost in the onion model.  We want
            # to run *around* the whole permission chain so our verdict is
            # authoritative (last one to deny wins).
            priority=1,
        )


plugin = AgentMossGatePlugin()
