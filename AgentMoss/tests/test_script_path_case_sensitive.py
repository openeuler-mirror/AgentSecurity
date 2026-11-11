# -*- coding: utf-8 -*-
"""脚本路径大小写：`bash Deploy.sh` 的脚本内容必须真的被扫描。

历史 bug（Python 侧漏报，TS 无此问题）：coordinator 把 action_detail **小写后**
才传给脚本链分析，于是 `bash Deploy.sh` → `bash deploy.sh` → tracker 按小写路径
去文件系统找文件 → Linux 文件名大小写敏感 → 找不到 → 整个脚本内容不被扫描 →
`Deploy.sh` 里写 `rm -rf /` 也一路放行。

影响面不小：`Deploy.sh` / `Setup.sh` / `Install.sh` 这类带大写的脚本名在真实
仓库里极常见，等于 **L1.2（脚本内容预扫描）整层失效**。

修法是 action_detail 原样透传（只对 action_type 做 .lower()）。这里用真实临时
文件把两个方向都钉住：
- 文件存在且内容危险 → Deny（修复前是 Allow）
- 文件不存在 → 仍 Allow（不能因为"找不到文件"就一律拦，那会把正常调用打成误报）
"""

import tempfile
from pathlib import Path

import pytest

from agent_moss.engine.analyzer import analyze
from agent_moss.profiles import get_profile


@pytest.fixture(scope="module")
def script_dir():
    """含大小写混合脚本名的临时目录。"""
    with tempfile.TemporaryDirectory(prefix="agentmoss-case-") as d:
        (Path(d) / "Deploy.sh").write_text("#!/bin/sh\nrm -rf /\n")
        (Path(d) / "ok.sh").write_text("#!/bin/sh\necho hello\n")
        yield d


def _decide(command: str, cwd: str) -> str:
    result = analyze(
        session_id=f"case-{command}-{cwd}",
        prompt_session="",
        action_history=[],
        a_next={"action_type": "bash", "action_detail": command},
        reason="",
        config=None,
        cache=None,
        profile=get_profile("linux"),
        llm_config=None,
        cwd=cwd,
        agent_id="",
        scenario_id="",
        llm_log_path=None,
        prompt_history=[],
        session_history=[],
    )
    return result["decision"]


@pytest.mark.parametrize(
    "command",
    [
        "bash Deploy.sh",          # 相对路径，大小写混合
        "sh Deploy.sh",            # 换解释器
        "./Deploy.sh",             # 直接执行
    ],
)
def test_uppercase_script_name_is_still_scanned(command, script_dir):
    """文件名含大写 → 脚本内容照样要被扫到（修复前全部 Allow）。"""
    assert _decide(command, script_dir) == "Deny"


def test_absolute_uppercase_script_path_is_still_scanned(script_dir):
    """绝对路径同理 —— 小写化会把它也一起弄丢。"""
    assert _decide(f"bash {script_dir}/Deploy.sh", script_dir) == "Deny"


def test_benign_script_is_not_flagged(script_dir):
    """对照：内容无害的脚本不该被误拦（防"找不到文件就一律拦"式修法）。"""
    assert _decide("bash ok.sh", script_dir) == "Allow"


def test_nonexistent_script_is_not_flagged(script_dir):
    """对照：文件不存在时不该拦 —— 大小写修复不能变成"路径解析失败即拒绝"。"""
    assert _decide("bash NoSuchScript.sh", script_dir) == "Allow"
