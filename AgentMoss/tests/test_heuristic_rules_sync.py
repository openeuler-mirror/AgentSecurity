"""L1 小型名单的单一事实源看护（2026-10 从代码搬进 JSON）。

`rules/heuristic_rules.json` 里的三组名单原先硬编码在 `engine/heuristic.py`：

- `sensitive_excluded_prefixes`（5）：敏感路径检测跳过的非文件工具前缀
- `search_action_prefixes`（6）+ `search_action_exact`（4）：搜索类工具（其
  action_detail 是查询数据，不做注入检测）
- `loopback_hosts`（4）：回环地址豁免名单

搬家原则是**判定零变化**，故这里守计数、内容，以及三处判定的实际结果。

"""
from __future__ import annotations

from agent_moss.engine import heuristic as h
from agent_moss.profiles import get_profile
from agent_moss.rules_loader import load_heuristic_rules


def test_counts_stable():
    d = load_heuristic_rules()
    assert len(d["sensitive_excluded_prefixes"]) == 5
    assert len(d["search_action_prefixes"]) == 6
    assert len(d["search_action_exact"]) == 4
    assert len(d["loopback_hosts"]) == 4


def test_constants_come_from_json():
    d = load_heuristic_rules()
    assert list(h._SENSITIVE_EXCLUDED_PREFIXES) == d["sensitive_excluded_prefixes"]
    assert list(h._SEARCH_ACTION_PREFIXES) == d["search_action_prefixes"]
    assert list(h._SEARCH_ACTION_EXACT) == d["search_action_exact"]
    assert list(h._LOOPBACK_HOSTS) == d["loopback_hosts"]


def test_search_action_detection():
    """前缀命中、精确名命中、大小写不敏感 —— 三者都要保持。"""
    for at in ("search-web", "web-fetch", "browser-click", "query-db"):
        assert h._is_search_action_type(at), at
    for at in ("websearch", "WEB_SEARCH", "search", "query"):
        assert h._is_search_action_type(at), at
    for at in ("bash", "read", "memory-search", "filemgr-readfile"):
        assert not h._is_search_action_type(at), at


def test_loopback_exemption():
    assert h._all_urls_loopback("curl -d x http://127.0.0.1:9090/a")
    assert h._all_urls_loopback("curl -d x http://localhost:1/a")
    assert h._all_urls_loopback("curl -d x http://0.0.0.0:5/a")
    assert not h._all_urls_loopback("curl -d x http://evil.example/a")
    assert not h._all_urls_loopback("curl -d x http://127.0.0.1/a http://evil.example/b")
    # 注意：`[::1]` 在本函数里**实际不生效** —— URL 正则抓不到方括号形式的主机名。
    # 名单里有这一项，但被这条正则挡住了；这是迁移前就有的行为，别顺手"修"。
    assert not h._all_urls_loopback("curl -d x http://[::1]:2/b")


def test_search_action_not_flagged_as_injection():
    """搜索类工具的 action_detail 是查询数据 —— 搜「jailbreak」不该判注入。"""
    profile = get_profile("linux")
    checker = h.InjectionKeywordChecker(profile)
    # 直接调 check() 会命中；上层 `_is_search_action_type` 才是门控。
    assert checker.check('search "jailbreak bypass"'.lower()).hit
    assert h._is_search_action_type("web-search")


def test_sensitive_excluded_prefixes_cover_non_file_tools():
    """名单口径：非文件工具（memory/skill/mailbox/app）排除，文件工具不在名单里。"""
    prefixes = h._SENSITIVE_EXCLUDED_PREFIXES
    for tool in ("memory-searchMemory", "skill-run", "mailbox-getEmailList", "app-launch"):
        assert any(tool.startswith(p) for p in prefixes), tool
    for tool in ("filemgr-readfile", "bash", "read"):
        assert not any(tool.startswith(p) for p in prefixes), tool
