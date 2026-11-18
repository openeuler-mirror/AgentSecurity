# -*- coding: utf-8 -*-
"""Standalone smoke tests for the AgentMoss Gate plugin.

These tests do NOT import QwenPaw or AgentMoss. They exercise the plugin
logic with a fake agent / fake middleware chain / mocked HTTP, so they
run anywhere Python 3.10+ is available.

Usage:
    cd plugins/agentmoss-gate
    python test_agentmoss_gate_plugin.py
"""

import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

# Allow importing the plugin module from this directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from agentscope.middleware import MiddlewareBase  # noqa: E402
from agentscope.permission import (  # noqa: E402
    PermissionBehavior,
    PermissionDecision,
)

from agentmoss_gate import (  # noqa: E402
    AgentMossGateMiddleware,
    _extract_session_context,
)


# ----------------------------------------------------------------------
# Fakes
# ----------------------------------------------------------------------


class FakeToolCall:
    def __init__(self, name):
        self.name = name


class FakeTool:
    def __init__(self, name):
        self.name = name


class FakeMsg:
    def __init__(self, role, content):
        self.role = role
        self.content = content


class FakeTextBlock:
    """Mirrors agentscope TextBlock (a pydantic model, NOT a dict/str).

    The plugin previously only recognised ``str``/``dict`` content parts, so
    real TextBlock objects fell through to a ``str(content)`` fallback and the
    extracted prompt was the object repr instead of the text.
    """

    def __init__(self, text):
        self.type = "text"
        self.text = text


class FakeToolCallBlock:
    """Mirrors agentscope ToolCallBlock (``input`` is a raw JSON string)."""

    def __init__(self, name, raw_input, block_id="c1"):
        self.type = "tool_call"
        self.id = block_id
        self.name = name
        self.input = raw_input


class FakeState:
    def __init__(self, context):
        self.context = context


class FakeAgent:
    def __init__(self, context=None, session_id="sess-1", workspace_dir="/tmp/ws"):
        self.state = FakeState(context or [])
        self._request_context = {"session_id": session_id}
        # QwenPaw stores the working directory as _workspace_dir; there is no
        # `work_dir` attribute (the plugin used to read that and always got "").
        self._workspace_dir = workspace_dir


async def _allow_handler(**kwargs):
    return PermissionDecision(
        behavior=PermissionBehavior.ALLOW,
        message="qp allow",
    )


async def _deny_handler(**kwargs):
    return PermissionDecision(
        behavior=PermissionBehavior.DENY,
        message="qp deny",
    )


def _make_input_kwargs(tool_name="bash", tool_input=None):
    return {
        "tool_call": FakeToolCall(tool_name),
        "tool": FakeTool(tool_name),
        "tool_input": tool_input or {"command": "ls"},
    }


# ----------------------------------------------------------------------
# Unit tests
# ----------------------------------------------------------------------


class TestExtractSessionContext(unittest.TestCase):
    def test_groups_tool_calls_under_user_prompt(self):
        """Tool calls (ToolCallBlock) group under the prompt that triggered them."""
        context = [
            FakeMsg("user", [FakeTextBlock("帮我清理临时文件")]),
            FakeMsg("assistant", [
                FakeTextBlock("好的，我来清理"),
                FakeToolCallBlock("execute_shell_command",
                                  '{"command": "rm -rf /tmp/x"}', "c1"),
            ]),
            FakeMsg("user", [FakeTextBlock("继续")]),
            FakeMsg("assistant", [
                FakeToolCallBlock("execute_shell_command",
                                  '{"command": "df -h"}', "c2"),
            ]),
        ]
        r = _extract_session_context(FakeAgent(context=context))

        self.assertEqual(r["session_id"], "sess-1")
        self.assertEqual(len(r["prompt_turns"]), 2)
        self.assertEqual(r["prompt_turns"][0]["text"], "帮我清理临时文件")
        self.assertEqual(len(r["prompt_turns"][0]["actions"]), 1)
        self.assertEqual(r["prompt_turns"][1]["text"], "继续")
        self.assertEqual(len(r["prompt_turns"][1]["actions"]), 1)
        self.assertEqual(r["user_prompt"], "继续")

    def test_text_is_plain_not_object_repr(self):
        """TextBlock objects must yield their text, not a repr.

        Regression: content parts were only recognised as str/dict, so real
        TextBlock instances fell through to str(content) and the prompt became
        "[TextBlock(type='text', text='...', id='...', created_at='...')]".
        """
        context = [FakeMsg("user", [FakeTextBlock("帮我分析下这个日志文件")])]
        r = _extract_session_context(FakeAgent(context=context))
        self.assertEqual(r["user_prompt"], "帮我分析下这个日志文件")
        self.assertNotIn("TextBlock", r["user_prompt"])
        self.assertNotIn("created_at", r["user_prompt"])

    def test_action_history_holds_real_tool_calls(self):
        """action_history carries the actual tool calls, in order."""
        context = [
            FakeMsg("user", [FakeTextBlock("分析日志")]),
            FakeMsg("assistant", [
                FakeToolCallBlock("execute_shell_command",
                                  '{"command": "cat /var/log/app.log"}', "c1"),
            ]),
            FakeMsg("assistant", [
                FakeToolCallBlock("write_file",
                                  '{"path": "/tmp/summary.txt"}', "c2"),
            ]),
        ]
        r = _extract_session_context(FakeAgent(context=context))
        self.assertEqual(len(r["action_history"]), 2)
        self.assertEqual(r["action_history"][0]["action_type"],
                         "execute_shell_command")
        self.assertIn("/var/log/app.log", r["action_history"][0]["action_detail"])
        self.assertEqual(r["action_history"][1]["action_type"], "write_file")

    def test_assistant_text_becomes_reason(self):
        """The assistant's text next to a tool call is the stated rationale."""
        context = [
            FakeMsg("user", [FakeTextBlock("分析日志")]),
            FakeMsg("assistant", [
                FakeTextBlock("我先读取日志文件看看"),
                FakeToolCallBlock("execute_shell_command",
                                  '{"command": "cat /log"}', "c1"),
            ]),
        ]
        r = _extract_session_context(FakeAgent(context=context))
        self.assertEqual(r["reason"], "我先读取日志文件看看")

    def test_reason_empty_when_no_assistant_text(self):
        context = [
            FakeMsg("user", [FakeTextBlock("分析日志")]),
            FakeMsg("assistant", [
                FakeToolCallBlock("execute_shell_command", '{"command": "ls"}', "c1"),
            ]),
        ]
        r = _extract_session_context(FakeAgent(context=context))
        self.assertEqual(r["reason"], "")

    def test_cwd_read_from_workspace_dir(self):
        """cwd must come from the attribute QwenPaw actually sets."""
        r = _extract_session_context(FakeAgent(workspace_dir="C:\\ws\\default"))
        self.assertEqual(r["cwd"], "C:\\ws\\default")

    def test_cwd_empty_when_absent(self):
        agent = FakeAgent()
        del agent._workspace_dir
        r = _extract_session_context(agent)
        self.assertEqual(r["cwd"], "")


class TestGateDenyBlocks(unittest.TestCase):
    def test_agentmoss_deny_returns_deny(self):
        mw = AgentMossGateMiddleware(
            gate_url="http://gate",
            timeout=1.0,
            agent_type="qwenpaw",
            fail_closed=False,
            api_token="",
            extra_metadata={},
        )

        async def fake_analyze(payload, tool_name, command):
            return {"decision": "Deny", "reason": "rm -rf / is critical"}

        mw._query_agentgate = fake_analyze  # noqa: SLF001
        decision = asyncio.run(
            mw.on_check_permission(
                FakeAgent(),
                _make_input_kwargs("bash", {"command": "rm -rf /"}),
                _allow_handler,
            )
        )
        self.assertEqual(decision.behavior, PermissionBehavior.DENY)
        self.assertIn("rm -rf /", decision.message)


class TestGateAllow(unittest.TestCase):
    def test_agentmoss_allow_returns_qp_decision(self):
        mw = AgentMossGateMiddleware(
            gate_url="http://gate",
            timeout=1.0,
            agent_type="qwenpaw",
            fail_closed=False,
            api_token="",
            extra_metadata={},
        )

        async def fake_analyze(payload, tool_name, command):
            return {"decision": "Allow", "reason": "safe"}

        mw._query_agentgate = fake_analyze  # noqa: SLF001
        decision = asyncio.run(
            mw.on_check_permission(
                FakeAgent(),
                _make_input_kwargs("bash", {"command": "ls"}),
                _allow_handler,
            )
        )
        self.assertEqual(decision.behavior, PermissionBehavior.ALLOW)


class TestGateUnreachable(unittest.TestCase):
    def test_fail_open_returns_qp_decision(self):
        mw = AgentMossGateMiddleware(
            gate_url="http://gate",
            timeout=1.0,
            agent_type="qwenpaw",
            fail_closed=False,
            api_token="",
            extra_metadata={},
        )

        async def fake_analyze(payload, tool_name, command):
            return None  # unreachable

        mw._query_agentgate = fake_analyze  # noqa: SLF001
        decision = asyncio.run(
            mw.on_check_permission(
                FakeAgent(),
                _make_input_kwargs("bash", {"command": "ls"}),
                _allow_handler,
            )
        )
        self.assertEqual(decision.behavior, PermissionBehavior.ALLOW)

    def test_fail_closed_returns_deny(self):
        mw = AgentMossGateMiddleware(
            gate_url="http://gate",
            timeout=1.0,
            agent_type="qwenpaw",
            fail_closed=True,
            api_token="",
            extra_metadata={},
        )

        async def fake_analyze(payload, tool_name, command):
            return None

        mw._query_agentgate = fake_analyze  # noqa: SLF001
        decision = asyncio.run(
            mw.on_check_permission(
                FakeAgent(),
                _make_input_kwargs("bash", {"command": "ls"}),
                _allow_handler,
            )
        )
        self.assertEqual(decision.behavior, PermissionBehavior.DENY)


class TestPayloadBuild(unittest.TestCase):
    def test_payload_contains_prompt_history_and_context(self):
        mw = AgentMossGateMiddleware(
            gate_url="http://gate",
            timeout=1.0,
            agent_type="qwenpaw",
            fail_closed=False,
            api_token="",
            extra_metadata={"tenant": "cmb"},
        )

        seen = {}

        async def fake_analyze(payload, tool_name, command):
            seen.update(payload)
            return {"decision": "Allow"}

        mw._query_agentgate = fake_analyze  # noqa: SLF001
        asyncio.run(
            mw.on_check_permission(
                FakeAgent(
                    context=[
                        FakeMsg("user", "查一下磁盘"),
                        FakeMsg("assistant", "用 bash"),
                    ],
                    session_id="cmb-sess",
                ),
                _make_input_kwargs("bash", {"command": "df -h"}),
                _allow_handler,
            )
        )
        self.assertEqual(seen["session_id"], "cmb-sess")
        self.assertEqual(seen["tool_name"], "bash")
        self.assertEqual(seen["agent_type"], "qwenpaw")
        self.assertEqual(seen["user_prompt"], "查一下磁盘")
        self.assertEqual(seen["metadata"]["tenant"], "cmb")
        self.assertEqual(seen["metadata"]["source"], "qwenpaw-plugin")
        self.assertIn("qp_behavior", seen["metadata"])

    def test_tool_input_is_not_json_escaped(self):
        """Backslashes must survive verbatim, or Windows rules never match.

        Regression: the input dict was JSON-dumped for the `command` field, so
        `C:\\Windows` reached AgentMoss as `C:\\\\Windows` and every Windows
        path rule (which matches a single separator) missed.
        """
        from agentmoss_gate import _tool_input_text

        raw_path = "C:\\Windows\\System32\\config\\SAM"
        text = _tool_input_text({"command": f"type {raw_path}", "timeout": 60})
        self.assertIn(raw_path, text)
        self.assertNotIn("\\\\", text.split("type ")[1].split("\n")[0])
        # No stray JSON scaffolding either.
        self.assertNotIn('"command"', text)
        self.assertNotIn("{", text)

    def test_raw_json_input_is_unescaped(self):
        """ToolCallBlock.input is a raw JSON string — parse, don't pass through."""
        from agentmoss_gate import _raw_input_text

        raw = '{"command": "type C:\\\\Windows\\\\System32\\\\config\\\\SAM"}'
        text = _raw_input_text(raw)
        self.assertEqual(text, "type C:\\Windows\\System32\\config\\SAM")

    def test_raw_input_keeps_unparsable_text(self):
        from agentmoss_gate import _raw_input_text

        self.assertEqual(_raw_input_text("not json at all"), "not json at all")
        self.assertEqual(_raw_input_text(""), "")

    def test_tool_input_keeps_secondary_values(self):
        """Non-primary string parameters are still surfaced to the analysis."""
        from agentmoss_gate import _tool_input_text

        text = _tool_input_text({"path": "/tmp/out.txt", "content": "payload"})
        self.assertIn("/tmp/out.txt", text)
        self.assertIn("payload", text)

    def _payload_for(self, tool_input, agent=None):
        mw = AgentMossGateMiddleware(
            gate_url="http://gate", timeout=1.0, agent_type="qwenpaw",
            fail_closed=False, api_token="", extra_metadata={},
        )
        seen = {}

        async def fake_analyze(payload, tool_name, command):
            seen.update(payload)
            return {"decision": "Allow"}

        mw._query_agentgate = fake_analyze  # noqa: SLF001
        asyncio.run(
            mw.on_check_permission(
                agent or FakeAgent(workspace_dir="C:\\ws\\default"),
                _make_input_kwargs("bash", tool_input),
                _allow_handler,
            )
        )
        return seen

    def test_cwd_prefers_call_specific_directory(self):
        """A per-call cwd must win over the agent workspace.

        QwenPaw's shell tool is `execute_shell_command(command, timeout, cwd=None)`
        — cwd defaults to the workspace only when the caller omits it. The model
        regularly passes its own (measured: `dir` ran with cwd="C:\\Windows").
        Reporting the workspace instead makes AgentMoss resolve relative paths
        and enumerate files against the wrong directory.
        """
        seen = self._payload_for({"command": "dir", "cwd": "C:\\Windows"})
        self.assertEqual(seen["cwd"], "C:\\Windows")

    def test_cwd_falls_back_to_workspace(self):
        """No per-call cwd → the workspace directory is used."""
        seen = self._payload_for({"command": "dir"})
        self.assertEqual(seen["cwd"], "C:\\ws\\default")

    def test_payload_reports_agent_os_type(self):
        """The payload carries the OS the AGENT runs on, not the gateway's.

        AgentGate may run on a different platform than QwenPaw (e.g. agent on
        Windows, gateway on Linux). AgentMoss picks its rule set from os_type,
        so reporting the gateway's OS would apply Linux rules to Windows
        commands. The plugin must therefore report its own platform.
        """
        import platform as _platform

        mw = AgentMossGateMiddleware(
            gate_url="http://gate",
            timeout=1.0,
            agent_type="qwenpaw",
            fail_closed=False,
            api_token="",
            extra_metadata={},
        )

        seen = {}

        async def fake_analyze(payload, tool_name, command):
            seen.update(payload)
            return {"decision": "Allow"}

        mw._query_agentgate = fake_analyze  # noqa: SLF001
        asyncio.run(
            mw.on_check_permission(
                FakeAgent(context=[FakeMsg("user", "查系统配置")]),
                _make_input_kwargs("bash", {"command": "type SAM"}),
                _allow_handler,
            )
        )
        self.assertEqual(
            seen["metadata"]["os_type"],
            _platform.system().lower(),
            "os_type must be the agent's own platform",
        )
        # Must be a value AgentMoss recognises (never empty / never the
        # gateway's host name leaking through).
        self.assertTrue(seen["metadata"]["os_type"])

    def test_payload_reports_agent_hostname(self):
        """The payload carries the AGENT's hostname, not the gateway's.

        AgentGate builds its agent id as ``f"{agent_type}:{hostname}"``. If
        the plugin omits this, AgentGate falls back to *its own* hostname, so
        every same-type agent behind one gateway merges into a single record
        (measured: a Windows QwenPaw filed as ``qwenpaw:kenhkl`` — the WSL
        gateway's host — which also hid which machine the call came from).
        """
        import platform as _platform

        seen = self._payload_for({"command": "dir"})

        self.assertEqual(seen["metadata"]["hostname"], _platform.node())
        self.assertTrue(seen["metadata"]["hostname"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
