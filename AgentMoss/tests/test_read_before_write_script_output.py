"""RBW-11：本会话自己写并执行过的脚本生成的文件，写它不要求先读。

2026-11 鸿蒙实测误报：agent 用 writeFile 写 ``gen_depreciation.py`` → 执行它
生成 ``折旧表.csv`` → 再 writeFile 覆盖该 CSV，被 read_before_write 拦。
RBW 只追踪工具层读/写，脚本生成的写事件引擎看不到。

豁免条件（缺一不可）：同目录 + 脚本内容提到目标 basename + 脚本确实被执行过；
受保护路径不豁免。本文件同时看护「不满足条件仍拦」的反向用例。
"""

import json
import os

import pytest

from agent_moss.engine.analyzer import analyze


@pytest.fixture(autouse=True)
def _static_analysis(monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_DISABLE_LLM", "1")
    monkeypatch.setenv("AGENT_MOSS_SAVE_POLICY", "0")


def _analyze(config, profile, history, cwd, target):
    return analyze(
        session_id="read-before-write-script-output",
        prompt_session="生成折旧表",
        action_history=history,
        a_next={
            "action_type": "filemgr-writeFile",
            "action_detail": json.dumps(
                {"path": target, "mode": "overwrite", "content": "new content"},
                ensure_ascii=False,
            ),
        },
        reason="更新脚本生成的折旧表",
        config=config,
        profile=profile,
        cwd=cwd,
    )


def _write_script_action(script_path, content):
    return {
        "action_type": "filemgr-writeFile",
        "action_detail": json.dumps(
            {"path": str(script_path), "mode": "overwrite", "content": content},
            ensure_ascii=False,
        ),
    }


def _run_script_action(command):
    return {
        "action_type": "terminal-executeBash",
        "action_detail": json.dumps({"command": command}, ensure_ascii=False),
    }


def test_overwrite_script_generated_file_allowed(tmp_path, default_config, linux_profile):
    """同目录脚本生成的文件：writeFile 覆盖不要求先读。"""
    script = tmp_path / "gen_depreciation.py"
    target = tmp_path / "折旧表.csv"
    target.write_text("old\n", encoding="utf-8")
    history = [
        _write_script_action(script, "open('折旧表.csv', 'w').write('x')\n"),
        _run_script_action(f"cd {tmp_path} && python3 gen_depreciation.py"),
    ]

    result = _analyze(
        default_config, linux_profile, history, str(tmp_path), str(target)
    )

    assert result["decision"] == "Allow"
    assert result["risk_type"] != "read_before_write"


def test_script_not_executed_still_denied(tmp_path, default_config, linux_profile):
    """脚本写了但没执行过：目标不可能是它生成的，维持拦截。"""
    script = tmp_path / "gen_depreciation.py"
    target = tmp_path / "折旧表.csv"
    target.write_text("old\n", encoding="utf-8")
    history = [_write_script_action(script, "open('折旧表.csv', 'w').write('x')\n")]

    result = _analyze(
        default_config, linux_profile, history, str(tmp_path), str(target)
    )

    assert result["decision"] == "Deny"
    assert result["risk_type"] == "read_before_write"


def test_script_in_other_directory_still_denied(
    tmp_path, default_config, linux_profile
):
    """脚本在别的目录：不认为是它生成的，维持拦截（防豁免过宽）。"""
    script_dir = tmp_path / "scripts"
    data_dir = tmp_path / "data"
    script_dir.mkdir()
    data_dir.mkdir()
    target = data_dir / "折旧表.csv"
    target.write_text("old\n", encoding="utf-8")
    history = [
        _write_script_action(
            script_dir / "gen_depreciation.py",
            "open('../data/折旧表.csv', 'w').write('x')\n",
        ),
        _run_script_action(f"cd {script_dir} && python3 gen_depreciation.py"),
    ]

    result = _analyze(
        default_config, linux_profile, history, str(data_dir), str(target)
    )

    assert result["decision"] == "Deny"
    assert result["risk_type"] == "read_before_write"


@pytest.mark.skipif(
    not os.path.exists("/etc/hostname"), reason="需要已存在的受保护路径文件"
)
def test_protected_path_not_exempted(default_config, linux_profile):
    """受保护路径（/etc）即使「像脚本产物」也不豁免。"""
    history = [
        _write_script_action(
            "/etc/hostname.gen.py", "open('/etc/hostname', 'w').write('x')\n"
        ),
        _run_script_action("cd /etc && python3 hostname.gen.py"),
    ]

    result = _analyze(
        default_config, linux_profile, history, "/etc", "/etc/hostname"
    )

    assert result["decision"] == "Deny"
    assert result["risk_type"] == "read_before_write"
