# -*- coding: utf-8 -*-
"""脚本**无法分析**时不能当安全放行（fail-closed）+ 大脚本仍要被扫。

2026-09 实测发现的漏报：脚本超过单文件大小上限（默认 2MB）时，读取直接返回错误，
三遍扫描（L1 / L2 / 关键词）全部 `if node.error: continue` → **整个脚本内容不扫** →
判定 Allow。把恶意脚本用注释撑到 2MB 就绕过了内容扫描：

    bash huge2mb.sh   # 内容：4 万行注释 + 末尾 rm -rf /
    修复前 → Allow        修复后 → Deny（"脚本存在但内容无法静态分析…按不可信处理"）

关键区分：**「脚本存在但读不了」≠「脚本不存在」**。后者跑也跑不起来，不算风险；
前者是"我们没法确认它安全"，必须按规定拒绝。

"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

#: 略超默认上限（2MB）即可，别把测试做太慢
_DEFAULT_LIMIT = 2 * 1024 * 1024


def _decide(command: str, cwd: str, env_extra: dict | None = None) -> str:
    """在子进程里跑判定 —— 大小上限在模块导入期读环境变量，必须隔离进程。"""
    env = dict(os.environ)
    env["AGENT_MOSS_DISABLE_LLM"] = "1"
    env["AGENT_MOSS_DATA_DIR"] = tempfile.mkdtemp(prefix="sz-")
    env["PYTHONPATH"] = str(REPO_ROOT)
    env.pop("AGENT_MOSS_SCRIPT_MAX_FILE_SIZE", None)
    if env_extra:
        env.update(env_extra)
    code = f"""
import json, os, tempfile
os.environ['AGENT_MOSS_DATA_DIR'] = tempfile.mkdtemp()
from agent_moss.engine.analyzer import analyze
from agent_moss.profiles import get_profile
r = analyze(session_id='sz', prompt_session='', action_history=[],
            a_next={{'action_type': 'bash', 'action_detail': {command!r}}},
            reason='', config=None, cache=None, profile=get_profile('linux'),
            llm_config=None, cwd={cwd!r}, agent_id='', scenario_id='',
            llm_log_path=None, prompt_history=[], session_history=[])
print(json.dumps({{'decision': r['decision'], 'reason': r.get('reason', '')}}))
"""
    out = subprocess.run([sys.executable, "-c", code], env=env,
                         capture_output=True, text=True, timeout=300)
    assert out.returncode == 0, out.stderr[-800:]
    import json

    return json.loads(out.stdout.strip().splitlines()[-1])["decision"]


@pytest.fixture(scope="module")
def big_scripts():
    """造：超大脚本（含危险命令）/ 大但正常脚本 / 不存在的脚本。"""
    with tempfile.TemporaryDirectory(prefix="agentmoss-size-") as d:
        root = Path(d)
        filler = "\n".join(f"# filler line {i} padding padding padding padding" for i in range(42000))
        (root / "huge.sh").write_text("#!/bin/bash\n" + filler + "\nrm -rf /\n", encoding="utf-8")
        (root / "huge_benign.sh").write_text("#!/bin/bash\n" + filler + "\nls /tmp\n", encoding="utf-8")
        assert (root / "huge.sh").stat().st_size > _DEFAULT_LIMIT, "样本没超过上限，测试无效"
        yield d


def test_oversize_script_is_not_silently_allowed(big_scripts):
    """超过大小上限的脚本 → 不能静默放行（这个是实测出来的漏报）。"""
    assert _decide(f"bash {big_scripts}/huge.sh", big_scripts) == "Deny"


def test_oversize_deny_reason_is_actionable(big_scripts):
    """拒绝理由要讲清「为什么」和「怎么放宽」，否则客户只会看到莫名 Deny。"""
    env = dict(os.environ)
    env["AGENT_MOSS_DISABLE_LLM"] = "1"
    env["PYTHONPATH"] = str(REPO_ROOT)
    code = f"""
import json, os, tempfile
os.environ['AGENT_MOSS_DATA_DIR'] = tempfile.mkdtemp()
from agent_moss.engine.analyzer import analyze
from agent_moss.profiles import get_profile
r = analyze(session_id='sz2', prompt_session='', action_history=[],
            a_next={{'action_type': 'bash', 'action_detail': 'bash {big_scripts}/huge.sh'}},
            reason='', config=None, cache=None, profile=get_profile('linux'),
            llm_config=None, cwd={big_scripts!r}, agent_id='', scenario_id='',
            llm_log_path=None, prompt_history=[], session_history=[])
print(json.dumps(r.get('reason', '')))
"""
    out = subprocess.run([sys.executable, "-c", code], env=env,
                         capture_output=True, text=True, timeout=300)
    import json as _json
    reason = _json.loads(out.stdout.strip().splitlines()[-1])   # 子进程打的是 JSON 字符串
    assert "无法静态分析" in reason
    assert "AGENT_MOSS_SCRIPT_MAX_FILE_SIZE" in reason   # 给出放宽手段


def test_env_var_can_raise_the_limit(big_scripts):
    """放宽上限后，超大脚本要被**真正读取并扫描** —— 藏在末尾的 rm -rf / 必须抓到。"""
    got = _decide(f"bash {big_scripts}/huge.sh", big_scripts,
                  {"AGENT_MOSS_SCRIPT_MAX_FILE_SIZE": str(8 * 1024 * 1024)})
    assert got == "Deny"


def test_benign_oversize_script_is_allowed_when_limit_raised(big_scripts):
    """对照：内容无害的超大脚本，放宽上限后应放行（防"放宽了还一律拦"）。"""
    got = _decide(f"bash {big_scripts}/huge_benign.sh", big_scripts,
                  {"AGENT_MOSS_SCRIPT_MAX_FILE_SIZE": str(8 * 1024 * 1024)})
    assert got == "Allow"


def test_nonexistent_script_is_not_flagged(big_scripts):
    """**关键区分**：「脚本不存在」不算风险（跑也跑不起来），不能被 fail-closed 误伤。"""
    assert _decide(f"bash {big_scripts}/nope.sh", big_scripts) == "Allow"
