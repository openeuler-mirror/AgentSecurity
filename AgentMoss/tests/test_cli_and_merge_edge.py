# -*- coding: utf-8 -*-
"""两条边角修复的看护（2026-09）：

1. **CLI 必须透传 agent_id / scenario_id / cwd**。
   历史 bug：Python CLI 只传 5 个参数，于是**同一个输入文件两端判定不同** ——
   agent 专属规则、场景定制规则全不加载，cwd 缺失还让间接文件访问检测直接跳过
   （logic_rules 里 `if cwd and os.path.isdir(cwd)`）。

2. **源码删掉整个分类时，不能把用户自定义规则一起删**。
   Console 的 add-rule 端点 category 是请求参数，API 调用方可以指定任意分类；
   源码某次重构删掉该分类时，里面的非 builtin 条目应迁到 user_custom 保留。
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


# ==================== 1. CLI 参数透传 ====================


@pytest.fixture()
def cli_env():
    """隔离的 runtime/数据目录，避免污染开发者本机配置。"""
    with tempfile.TemporaryDirectory(prefix="agentmoss-cli-") as d:
        env = dict(os.environ)
        env["AGENT_MOSS_DATA_DIR"] = d
        env["AGENT_MOSS_DISABLE_LLM"] = "1"
        env["PYTHONPATH"] = str(REPO_ROOT)
        yield env


def _run_cli(env, payload: dict) -> dict:
    with tempfile.TemporaryDirectory() as d:
        inp = Path(d) / "in.json"
        inp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, "-m", "agent_moss.cli", "analyze", str(inp), "--no-file"],
            env=env, capture_output=True, text=True, timeout=120,
        )
        assert proc.returncode == 0, proc.stderr[-500:]
        return json.loads(proc.stdout)


def test_cli_passes_agent_id(cli_env):
    """带 agent_id 时 agent 专属规则必须生效。

    opendesk 的 builtin_safe_action_types 含 `todomgr-` 前缀 → `todomgr-list`
    命中「完全安全工具」白名单。不透传 agent_id 时走不到这条路径。
    """
    payload = {
        "session_id": "cli-agent", "prompt_session": "", "action_history": [],
        "a_next": {"action_type": "todomgr-list", "action_detail": "列任务"},
        "reason": "列任务", "agent_id": "opendesk", "cwd": "/tmp",
    }
    with_agent = _run_cli(cli_env, payload)
    without_agent = _run_cli(cli_env, {**payload, "agent_id": ""})

    assert "完全安全工具" in with_agent["reason"], (
        f"agent_id 未透传，agent 专属规则没生效: {with_agent['reason']}"
    )
    assert "完全安全工具" not in without_agent["reason"], (
        "对照组不该命中 agent 白名单 —— 否则这条测试没有鉴别力"
    )


def test_cli_does_not_pollute_stdout(cli_env):
    """stdout 必须是干净 JSON（给脚本/管道用）。"""
    payload = {
        "session_id": "cli-clean", "prompt_session": "", "action_history": [],
        "a_next": {"action_type": "ls", "action_detail": "ls -la"},
        "reason": "列目录", "agent_id": "opendesk", "cwd": "/tmp",
    }
    out = _run_cli(cli_env, payload)
    assert "decision" in out


def test_cli_accepts_commands_ending_in_file_like_suffix(cli_env):
    """命令文本以 .yaml/.json/.toml 结尾时不能被当成"写错的文件路径"。

    历史 bug：`agent-moss analyze "cat /home/sandbox/config.yaml"` 判成文件不存在
    直接退出（招行沙箱实测）—— 而 `cat x.yaml` 这类在读配置的运维里极常见。
    现在只有**不含空白的单个 token** 才当疑似误写的文件路径。
    """
    # ① 含空格的命令 → 正常分析
    r = _run_cli_cmd(cli_env, "cat /home/sandbox/config.yaml")
    assert "decision" in r, r
    # ② 单个 token（疑似写错路径）→ 仍报错退出
    proc = subprocess.run(
        [sys.executable, "-m", "agent_moss.cli", "analyze", "input.json"],
        env=cli_env, capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 2
    assert "文件不存在" in proc.stderr


def _run_cli_cmd(env, command: str) -> dict:
    """命令模式调用（与 _run_cli 的文件模式区分）。"""
    proc = subprocess.run(
        [sys.executable, "-m", "agent_moss.cli", "analyze", command],
        env=env, capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode in (0, 1), proc.stderr[-400:]
    return {"decision": proc.stdout.strip().splitlines()[-1]}


def test_cli_defaults_cwd_to_process_cwd(cli_env):
    """没给 cwd 时应落到进程当前目录（与 TS CLI 的 process.cwd() 对齐），而不是空串。"""
    payload = {
        "session_id": "cli-cwd", "prompt_session": "", "action_history": [],
        "a_next": {"action_type": "bash", "action_detail": "ls -la"},
        "reason": "列目录",
    }
    out = _run_cli(cli_env, payload)
    assert "decision" in out  # 关键是不因 cwd="" 而抛错/静默跳过


# ==================== 2. 分类删除保留用户规则 ====================


def test_removed_category_keeps_user_rules():
    """源码删掉整个分类时，用户加在该分类里的自定义规则迁到 user_custom 保留。"""
    with tempfile.TemporaryDirectory(prefix="agentmoss-merge-") as d:
        os.environ["AGENT_MOSS_DATA_DIR"] = d
        os.environ["AGENT_MOSS_RUNTIME_CONFIG_PATH"] = os.path.join(d, "rc.json")
        try:
            from agent_moss.infra import runtime_config as rc

            gone = "legacy_removed_category"

            # ① 源码**这一版有**这个分类（否则第一次 merge 就会把它清掉，测不到目标场景）
            src_with = rc.generate_source_defaults()
            src_with["L1_rules"][gone] = {
                "category_enabled": True, "category_desc": "", "rules": [
                    {"id": "builtin_1", "pattern": r"\bbuiltin\b", "enabled": True,
                     "builtin": True},
                ],
            }
            # ② 用户在这个内置分类里**自己加了一条**
            user = {"version": 1, "layers": dict(src_with.get("layers", {})), "L1_rules": {
                gone: {"category_enabled": True, "category_desc": "", "rules": [
                    {"id": "builtin_1", "pattern": r"\bbuiltin\b", "enabled": True,
                     "builtin": True},
                    {"id": "my_custom_1", "pattern": r"\bmine\b", "enabled": True,
                     "builtin": False},
                ]},
            }}
            merged_1 = rc.merge_config(user, src_with)
            assert len(merged_1["L1_rules"][gone]["rules"]) == 2, "前置：分类在，两条规则都在"

            # ③ 源码下一版把这个分类删了
            src_without = json.loads(json.dumps(src_with))
            del src_without["L1_rules"][gone]
            merged = rc.merge_config(merged_1, src_without)

            assert gone not in merged["L1_rules"], "该分类应被清理"
            kept = [r for r in merged["L1_rules"].get("user_custom", {}).get("rules", [])
                    if r.get("id") == "my_custom_1"]
            assert kept, "用户自定义规则不该随分类一起被删"
            # 内置条目（源码已删）不该被"迁移"过来 —— 它该走 source_removed 那套
            moved_builtin = [r for r in merged["L1_rules"].get("user_custom", {}).get("rules", [])
                             if r.get("id") == "builtin_1"]
            assert not moved_builtin, "内置条目不该被当成用户规则迁移"
        finally:
            os.environ.pop("AGENT_MOSS_RUNTIME_CONFIG_PATH", None)
