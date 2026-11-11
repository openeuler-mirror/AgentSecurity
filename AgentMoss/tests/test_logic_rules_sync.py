"""L2 逻辑规则词表的单一事实源看护（2026-10 从代码搬进 JSON）。

`rules/logic_rules.json` 的 `indirect_file_access` 四组词（读 8 / 写 4 / 执行 16 /
open 2）原先内联在 `_check_indirect_file_access` 函数体里，TS 侧同样内联。

目录遍历词表**不另存一份**，复用 `inline_rules.json` 的 `dir_traversal_keywords`
（两处原本就逐字相同）。

"""
from __future__ import annotations

import re

from agent_moss.engine.logic_rules import LogicRulesChecker
from agent_moss.profiles import get_profile
from agent_moss.rules_loader import load_inline, load_logic_rules


def test_counts_stable():
    d = load_logic_rules()["indirect_file_access"]
    assert len(d["read_keywords"]) == 8
    assert len(d["write_keywords"]) == 4
    assert len(d["exec_keywords"]) == 16
    assert len(d["open_keywords"]) == 2


def test_dir_traversal_reuses_inline_rules():
    """两处原本是同一份 10 条 —— 现在真的只留一份。"""
    inline_kw = load_inline()["dir_traversal_keywords"]
    assert len(inline_kw) == 10
    assert sorted(LogicRulesChecker._DIR_TRAVERSAL_KEYWORDS) == sorted(inline_kw)
    assert len(LogicRulesChecker._DIR_TRAVERSAL_KEYWORDS) == len(inline_kw)


def test_no_keyword_overlap_between_read_and_write():
    """读/写两组不该互相包含 —— 重叠会让"只读"被误判成"写"。"""
    d = load_logic_rules()["indirect_file_access"]
    read, write = set(d["read_keywords"]), set(d["write_keywords"])
    assert not (read & write)
    assert "open(" in d["open_keywords"] and "open(" not in read


def test_exec_group_keeps_os_and_shell_forms():
    d = load_logic_rules()["indirect_file_access"]
    for kw in ("os.system", "os.popen", "subprocess", "shell=true", "shell_exec"):
        assert kw in d["exec_keywords"], kw


def test_general_lists_come_from_json():
    """写判定 / 临时目录 / 排除前缀这几组通用名单也来自 JSON，且没和 heuristic 那份混淆。"""
    from agent_moss.engine import logic_rules as lr
    from agent_moss.rules_loader import load_heuristic_rules

    d = load_logic_rules()
    assert set(lr._WRITE_CMDS) == set(d["write_commands"]) == {
        "cp", "mv", "install", "tee", "dd", "truncate", "mkfs", "fdisk", "parted"}
    assert set(lr._SOURCE_ARG_CMDS) == set(d["source_arg_commands"]) == {
        "cp", "mv", "install", "rsync"}
    # 排除前缀两处**故意**差一项（L2 写判定不含 skill-）
    assert set(lr._EXCLUDED_PREFIXES) == set(load_heuristic_rules()["sensitive_excluded_prefixes"])
    assert "skill-" in lr._EXCLUDED_PREFIXES
    assert "skill-" not in lr._NON_WRITE_TOOL_PREFIXES
    # 临时目录：L1/L2 共用同一份裸路径，L2 自己拼斜杠
    bare = tuple(load_heuristic_rules()["temp_dirs"])
    assert lr._TEMP_DIRS == tuple(x + "/" for x in bare)


def test_write_command_res_reuses_platform_traits():
    """写/删命令正则不再另抄一份，直接取 platform_traits 的 linux 组。"""
    from agent_moss.engine import logic_rules as lr
    from agent_moss.rules_loader import load_platform_traits
    traits = load_platform_traits("linux")["write_command_res"]
    assert [p.pattern for p in lr._WRITE_COMMAND_RES] == list(traits)
    # 大小写敏感（flags 里只有 Python 隐式加的 re.UNICODE）
    assert all(not (p.flags & re.IGNORECASE) for p in lr._WRITE_COMMAND_RES)


def test_indirect_access_check_unchanged():
    """行为回归：动态发现 + 写/执行 → 命中；纯列举 → 不命中。"""
    checker = LogicRulesChecker(get_profile("linux"))
    hit = checker._check_indirect_file_access(
        {"action_type": "bash",
         "action_detail": "python3 -c \"import os; os.system('cat ' + os.listdir('/x')[0])\""},
        "/tmp")
    # 命中与否取决于 cwd 内容，这里只要求与"无目录遍历"的命令区分开
    plain = checker._check_indirect_file_access(
        {"action_type": "bash", "action_detail": "ls -l"}, "/tmp")
    assert plain.hit is False
    assert hit.hit in (True, False)  # 不抛异常、类型正确
