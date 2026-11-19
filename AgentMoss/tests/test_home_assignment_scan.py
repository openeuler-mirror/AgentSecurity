"""主目录变量扫描的语义与长输入回归；只分析文本，不执行命令。"""

import os
from pathlib import Path
import subprocess
import sys

import pytest

from agent_moss.engine.heuristic import HomeDeletionChecker
from agent_moss.profiles import get_profile


@pytest.mark.parametrize(
    ("command", "hit"),
    [
        ("TARGET=$HOME; rm -rf $TARGET", True),
        ("TARGET=${HOME}; unlink ${TARGET}", True),
        ("TARGET=~/; rmdir $TARGET", True),
        ("TARGET=/home/alice; rm -rf $TARGET", True),
        ("TARGET=/home/alice/; rm -rf $TARGET", True),
        ("TARGET=$(echo $HOME); rm -rf $TARGET", True),
        ("TARGET=$(echo (x) $HOME); rm -rf $TARGET", True),
        ("TARGET\t=\n$HOME; rm -rf $TARGET", True),
        ("TARGET\u2003=\u00a0$HOME; rm -rf $TARGET", True),
        ("9TARGET=$HOME; rm -rf $TARGET", True),
        ("prefix-TARGET=$HOME; rm -rf $TARGET", True),
        ("ſ=$HOME; rm -rf $ſ", True),
        ("ı=$HOME; rm -rf $ı", True),
        ("K=$HOME; rm -rf $K", True),
        ("T=$HOME; T=~/cache; rm -rf $T", False),
        ("T=~/cache; T=$HOME; rm -rf $T", True),
        # 原扫描忽略不支持的赋值值，不覆盖此前已识别的赋值。
        ("T=$HOME; T=/tmp/cache; rm -rf $T", True),
        ("T=/home/alice/cache; rm -rf $T", False),
        ("T=$HOME/cache; rm -rf $T", False),
        ("T=${HOME}/cache; rm -rf $T", False),
        ("T=$(echo ~/cache); rm -rf $T", False),
        ("T='$HOME'; rm -rf $T", False),
        ("T=$HOME!; rm -rf $T", False),
        ("T=$HOME; echo $T", False),
        ("T=$HOME; rm -rf $XYZ", False),
        ("echo ordinary text", False),
        # 成功的外层赋值会消费整个值，不另外捕获其内部赋值。
        ("OUT=$(INNER=$HOME); rm -rf $INNER", False),
        ("OUT=/home/INNER=$HOME; rm -rf $INNER", False),
        # 外层失败后仍需继续发现其后的有效赋值。
        ("OUT=$(INNER=$HOME ; rm -rf $INNER", True),
        ("OUT=unsupported INNER=$HOME; rm -rf $INNER", True),
        ("OUT=$(x (INNER=$HOME ); rm -rf $INNER", True),
        ("A=$HOME; B=~/cache; rm -rf $A", True),
    ],
)
def test_assignment_detection_preserves_results(command, hit):
    result = HomeDeletionChecker(get_profile("linux")).check(
        {"action_type": "bash", "action_detail": command}
    )
    assert result.hit is hit
    if hit:
        assert result.risk_level == "high"
        assert result.violated_rule == "home_directory_delete"
        assert result.matched_patterns == ["home-assigned-var-delete"]


@pytest.mark.parametrize("action_type", ["bash", "executeBash", "terminal-executeBash"])
def test_assignment_shell_tool_aliases(action_type):
    assert HomeDeletionChecker(get_profile("linux")).check(
        {"action_type": action_type, "action_detail": "T=$HOME; rm -rf $T"}
    ).hit


def test_assignment_non_shell_tool_is_ignored():
    assert not HomeDeletionChecker(get_profile("linux")).check(
        {"action_type": "read", "action_detail": "T=$HOME; rm -rf $T"}
    ).hit


@pytest.mark.parametrize("length", [25_000, 100_000])
def test_long_assignment_candidates_finish_promptly(length):
    # 子进程超时让旧的反复匹配能够明确失败，而不会卡住整个测试任务。
    # 两秒检测预算远大于修复后的通常耗时，另留十秒导入/进程启动余量。
    code = r'''
import sys, time
from agent_moss.engine.heuristic import HomeDeletionChecker
from agent_moss.profiles import get_profile
n = int(sys.argv[1])
checker = HomeDeletionChecker(get_profile("linux"))
cases = [
    ("echo " + "a" * n, False),
    ("echo " + "a" * n + "=unsupported; rm -rf $OTHER", False),
    ("echo " + "a" * n + " " * n + "!; rm -rf $OTHER", False),
    ("echo " + "a" * n + "=$(unterminated; rm -rf $OTHER", False),
    ("echo " + "a" * n + "; TARGET=$HOME; rm -rf $TARGET", True),
    ("a" * n + "=$HOME; rm -rf $" + "a" * n, True),
]
for index, (command, expected) in enumerate(cases):
    start = time.perf_counter()
    result = checker.check({"action_type": "bash", "action_detail": command})
    elapsed = time.perf_counter() - start
    assert result.hit is expected, (index, result)
    assert elapsed < 2.0, (index, n, elapsed)
'''
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]))
    try:
        result = subprocess.run(
            [sys.executable, "-c", code, str(length)],
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"{length}-character assignment scan exceeded 10 seconds")
    assert result.returncode == 0, result.stdout + result.stderr
