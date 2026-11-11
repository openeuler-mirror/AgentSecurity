"""`AGENT_MOSS_SAVE_POLICY` 开关测试。

背景：``analyze()`` 每次 Allow 都会把最小权限 Policy 落盘到
``{临时目录}/agent_moss/{session_id}.toml``（给**执行侧沙箱**按会话读取，
用于配置 Landlock/namespace 隔离）。只取 ``decision``、不做沙箱隔离的调用方
（如客户沙箱的 FastAPI 校验服务）这份文件纯属无谓 I/O——实测 ~0.6ms/次，
且 session_id 唯一时会按请求堆积。

``AGENT_MOSS_SAVE_POLICY=0`` 可关闭落盘：**只影响文件**，
``analyze()`` 的返回值（decision / policy 字段）与判定结果不变。
"""
from __future__ import annotations

from pathlib import Path

import pytest

from agent_moss.engine import analyzer as analyzer_mod
from agent_moss.engine.analyzer import analyze
from agent_moss.profiles import get_profile


@pytest.fixture(autouse=True)
def _disable_llm(monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_DISABLE_LLM", "1")


@pytest.fixture
def policy_dir(tmp_path, monkeypatch):
    """把 Policy 落盘目录重定向到临时目录，避免污染真实 /tmp/agent_moss。"""
    d = tmp_path / "policy_out"
    monkeypatch.setattr(analyzer_mod, "POLICY_OUTPUT_DIR", d)
    return d


def _run(cmd: str, session_id: str = "t") -> dict:
    return analyze(
        session_id=session_id,
        prompt_session="",
        action_history=[],
        a_next={"action_type": "bash", "action_detail": cmd},
        reason="",
        profile=get_profile(""),
    )


def test_policy_written_by_default(policy_dir):
    """默认（不设开关）保持既有行为：Allow 落盘。"""
    r = _run("ls -la")
    assert r["decision"] == "Allow"
    assert r["policy"], "policy 字段应照常返回"
    assert (policy_dir / "t.toml").is_file(), "默认应落盘"


def test_save_policy_disabled_by_env(policy_dir, monkeypatch):
    """AGENT_MOSS_SAVE_POLICY=0 → 不落盘，但返回值与判定不变。"""
    monkeypatch.setenv("AGENT_MOSS_SAVE_POLICY", "0")

    r = _run("ls -la")
    assert r["decision"] == "Allow", "判定不应受开关影响"
    assert r["policy"], "policy 字段仍应照常返回（开关只影响文件）"
    assert not list(policy_dir.glob("*.toml")) if policy_dir.exists() else True, \
        "开关关闭时不应产生任何 policy 文件"


def test_deny_never_writes_policy(policy_dir, monkeypatch):
    """Deny 路径本就不落盘（无论开关）。"""
    monkeypatch.delenv("AGENT_MOSS_SAVE_POLICY", raising=False)
    r = _run("rm -rf /")
    assert r["decision"] == "Deny"
    assert r["violated_layers"], "应给出命中层"
    assert not list(policy_dir.glob("*.toml")) if policy_dir.exists() else True


def test_session_id_unique_accumulates_files(policy_dir):
    """回归说明：session_id 唯一时按请求堆积（这正是开关要解决的问题）。"""
    for i in range(3):
        _run("ls", session_id=f"shell-{i}")
    files = sorted(f.name for f in policy_dir.glob("*.toml"))
    assert files == ["shell-0.toml", "shell-1.toml", "shell-2.toml"]


def test_session_id_with_slash_is_sanitized(policy_dir):
    """session_id 含路径分隔符时转义，不越出输出目录。"""
    _run("ls", session_id="a/b\\c")
    files = [f.name for f in policy_dir.glob("*.toml")]
    assert files == ["a_b_c.toml"], files
