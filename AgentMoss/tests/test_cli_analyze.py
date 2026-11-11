"""CLI `analyze` 命令模式（shell 命令直传）测试。

需求背景：客户沙箱要求零文件 IO 的快速判定——`agent-moss analyze "cmd"` 直接输出
Deny/Allow，退出码供 shell 判断，避免「先写 input.json、再读结果文件」的开销。

覆盖：
- 命令模式 Deny/Allow 判定 + 退出码（0=Allow / 1=Deny / 2=用法错误）
- `--json` 输出完整 JSON
- 文件模式行为不变（回归保护）
- 路径写错（.json 结尾但不存在）/ 目录 / 空输入 → 明确报错，而非被当成命令分析

"""

from __future__ import annotations

import argparse
import json
import os

import pytest

from agent_moss.cli import cmd_analyze


@pytest.fixture(autouse=True)
def _disable_llm(monkeypatch):
    """命令模式判定与静态层一致，禁 L3 保证结果确定性。"""
    monkeypatch.setenv("AGENT_MOSS_DISABLE_LLM", "1")


def _ns(input_: str, **kw) -> argparse.Namespace:
    """构造 cmd_analyze 需要的参数命名空间。"""
    base = {"input": input_, "output_dir": None, "no_file": True, "json": False}
    base.update(kw)
    return argparse.Namespace(**base)


class TestCommandMode:
    def test_deny_command_prints_deny_exit_1(self, capsys):
        rc = cmd_analyze(_ns("cat ~/.ssh/id_rsa"))
        assert rc == 1
        # 末行是判定结果（首次运行可能先打印「已创建用户配置文件」提示）
        assert capsys.readouterr().out.strip().splitlines()[-1] == "Deny"

    def test_allow_command_prints_allow_exit_0(self, capsys):
        rc = cmd_analyze(_ns("ls -la"))
        assert rc == 0
        assert capsys.readouterr().out.strip().splitlines()[-1] == "Allow"

    def test_json_flag_prints_full_result(self, capsys):
        rc = cmd_analyze(_ns("rm -rf /", json=True))
        assert rc == 1
        data = json.loads(capsys.readouterr().out)
        assert data["decision"] == "Deny"
        assert "L1.1" in data["violated_layers"]

    def test_missing_json_path_reports_error_not_command(self, capsys, tmp_path):
        """拼错的 .json 路径要报错，不能被当成名为 `nope.json` 的命令分析。"""
        rc = cmd_analyze(_ns(str(tmp_path / "not-there.json")))
        assert rc == 2
        assert "文件不存在" in capsys.readouterr().err

    def test_empty_input_reports_error(self, capsys):
        rc = cmd_analyze(_ns("   "))
        assert rc == 2

    def test_directory_arg_reports_error(self, capsys, tmp_path):
        rc = cmd_analyze(_ns(str(tmp_path)))
        assert rc == 2


class TestFileModeUnchanged:
    def test_file_mode_prints_json_and_uses_input(self, capsys, tmp_path):
        f = tmp_path / "in.json"
        f.write_text(
            json.dumps(
                {
                    "session_id": "t",
                    "prompt_session": "",
                    "action_history": [],
                    "a_next": {"action_type": "bash", "action_detail": "cat ~/.ssh/id_rsa"},
                    "reason": "",
                    "os_type": "linux",
                    "cwd": "/tmp",
                }
            ),
            encoding="utf-8",
        )
        rc = cmd_analyze(_ns(str(f)))
        assert rc == 1
        data = json.loads(capsys.readouterr().out)
        assert data["decision"] == "Deny"


# ==================== 命令模式的 cwd（双端镜像，2026-10 修） ====================
# 间接文件访问检测（os.listdir('.') + 写）要靠 cwd 列出目录里的凭据文件才判得出。
# Python 命令模式此前**不传 cwd** → 该检测被跳过：同一个命令
# CLI 命令模式 Allow、文件模式/HTTP/TS CLI/客户验收脚本 Deny（漏报）。
# 看护：一拦（cwd 含 .env 的 listdir+写 → Deny）一放（普通命令 → Allow）。

_LISTDIR_WRITE = (
    'python3 -c "import os; '
    '[open(f,chr(119)).write(chr(120)) for f in os.listdir(chr(46)) if os.path.isfile(f)]"'
)


def _run_command_mode(command: str) -> int:
    """直接在进程内跑 `_analyze_command`（等价于 `agent-moss analyze "<cmd>"`）。"""
    import argparse

    from agent_moss.cli import _analyze_command

    return _analyze_command(argparse.Namespace(json=False), command)


def test_command_mode_uses_cwd_for_indirect_access(tmp_path, monkeypatch, capsys):
    """一拦：cwd 下有 .env 凭据时，listdir+写 判 Deny（此前因 cwd 缺失而漏）。"""
    (tmp_path / ".env").write_text("KEY=val")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AGENT_MOSS_DISABLE_LLM", "1")
    monkeypatch.setenv("AGENT_MOSS_SAVE_POLICY", "0")
    monkeypatch.setenv("AGENT_MOSS_DISABLE_CACHE", "1")

    rc = _run_command_mode(_LISTDIR_WRITE)
    capsys.readouterr()
    assert rc == 1, "cwd 含凭据的间接访问应判 Deny（cwd 没传就会漏成 Allow）"


def test_command_mode_plain_command_still_allowed(tmp_path, monkeypatch, capsys):
    """一放（对照）：普通命令不受影响（确认不是把命令模式改成了恒 Deny）。"""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AGENT_MOSS_DISABLE_LLM", "1")
    monkeypatch.setenv("AGENT_MOSS_SAVE_POLICY", "0")
    monkeypatch.setenv("AGENT_MOSS_DISABLE_CACHE", "1")

    rc = _run_command_mode("ls -la")
    capsys.readouterr()
    assert rc == 0


# ==================== CLI 参数面：init 两种写法（双端互认，2026-10） ====================
# Python 只认 `init -o x.json`，TS 只认 `init x.json` —— 照着一端文档写的命令在
# 另一端直接报错。现双端都接受两种写法（看护：两种都能真的写出文件）。


def test_init_accepts_both_flag_and_positional(tmp_path, monkeypatch, capsys):
    import subprocess
    import sys

    env = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", "")}
    for argv in (["init", "-o", str(tmp_path / "a.json")],
                 ["init", str(tmp_path / "b.json")]):
        res = subprocess.run([sys.executable, "-m", "agent_moss.cli", *argv],
                             capture_output=True, text=True, env=env, cwd=str(tmp_path))
        assert res.returncode == 0, f"{argv} 失败: {res.stderr[:200]}"
    assert (tmp_path / "a.json").exists()
    assert (tmp_path / "b.json").exists()
