"""内联脚本判定词表的单一事实源看护（2026-10 从代码搬进 JSON）。

`rules/inline_rules.json` 里的四组数据原先**硬编码**在
`agent_moss/engine/inline_analyzer.py`：

- `read_write_keywords`（66 条）：内联脚本里出现即视为真实读写
- `dir_traversal_keywords`（10 条）：目录遍历函数（配合读写词判"动态发现文件"）
- `write_exec_chain_patterns`（4 条）：写入后执行的绕过链
- `redirect_sensitive_paths`：重定向写敏感路径的清单

搬家的原则是**判定零变化**，故本文件同时守三件事：
1. 计数与内容稳定（防误删/误改）；
2. 正则 flags 被两端**按同一语义**解释（i/s 才是判定的一部分，漏掉 DOTALL 会让
   `echo x > f && bash f\n` 这类跨行绕过漏网）；
3. 兜底路径清单与迁移前逐字一致。

"""
from __future__ import annotations

import re

from agent_moss.engine import inline_analyzer as ia
from agent_moss.rules_loader import load_inline


def test_counts_stable():
    data = load_inline()
    assert len(data["read_write_keywords"]) == 66
    assert len(data["dir_traversal_keywords"]) == 10
    assert len(data["write_exec_chain_patterns"]) == 4
    assert len(data["redirect_sensitive_paths"]["python_fallback"]) == 20
    assert len(data["redirect_sensitive_paths"]["ts_static"]) == 16
    assert len(data["redirect_sensitive_paths"]["shell_rc_fragments"]) == 5


def test_module_constants_come_from_json():
    data = load_inline()
    assert ia._READ_WRITE_KEYWORDS == data["read_write_keywords"]
    assert ia._DIR_TRAVERSAL_KEYWORDS == data["dir_traversal_keywords"]
    assert ia._SENSITIVE_PATH_FRAGMENTS_DEFAULT == data["redirect_sensitive_paths"]["python_fallback"]


def test_chain_regex_flags_are_semantic():
    """flags 只存 i/s/m 三个语义字符，且被正确编译。

    第一条（写入后执行）必须带 DOTALL —— 命令里常出现换行（多行 heredoc / 换行拼接），
    少了它就会漏掉跨行的 `echo ... > f && bash f`。
    """
    pats = ia._WRITE_EXEC_CHAIN_PATTERNS
    assert len(pats) == 4
    first = pats[0]
    assert first.flags & re.DOTALL, "写入+执行链第一条丢了 DOTALL"
    assert first.flags & re.IGNORECASE
    for p in pats:
        assert p.flags & re.IGNORECASE
        # 不允许多渲染出 VERBOSE/LOCALE 这类会改变语义的隐式标志
        assert not (p.flags & re.VERBOSE)


def test_chain_regex_matches_representative_commands():
    """四条绕过链各自的代表性输入都要命中（数据搬家不许改行为）。"""
    cases = [
        'echo "cat /etc/shadow" > x.sh && bash x.sh',
        "cat payload | sh",
        'eval "$(cat /tmp/x)"',
        "echo rm | xargs bash",
    ]
    for cmd in cases:
        assert ia._has_write_exec_chain(cmd), f"绕过链未命中: {cmd}"


def test_chain_regex_cross_line():
    """跨行也要命中（DOTALL 生效）。

    这条命令的 `&&` 落在 `> x.sh` 的下一行 —— 没有 DOTALL 就跨不过去。
    """
    assert ia._has_write_exec_chain('echo "cat /etc/shadow" > x.sh\nls && bash x.sh')
    # 注意：单纯换行**不算**命令分隔符，`echo x > f` 下一行 `bash f` 修前修后都不命中，
    # 不是搬家引入的退化 —— 这里钉住它，防止有人"顺手"放宽。
    assert not ia._has_write_exec_chain('echo x > /tmp/a.sh\nbash /tmp/a.sh')


def test_read_write_keywords_keep_node_coverage():
    """Node API 一族不能丢 —— 历史缺口（node -e 读文件曾整体放行）。"""
    for kw in ("readfilesync(", "writefilesync(", "require('fs')", "require('child_process')"):
        assert kw in ia._READ_WRITE_KEYWORDS


def test_no_bare_short_words():
    """裸短词会让自然语言文本误触发（echo "open the door" 不该被当读写）。"""
    for bare in ("open", "read", "write", "system", "exec", "eval"):
        assert bare not in ia._READ_WRITE_KEYWORDS, f"裸短词 {bare!r} 不该进词表"


def test_dir_traversal_deduped():
    """迁移前 `os.walk` 在列表里写了两遍；去重不改变 any(子串) 的语义。"""
    assert ia._DIR_TRAVERSAL_KEYWORDS.count("os.walk") == 1
    assert ia._has_dir_traversal("for f in os.walk('/etc'): pass")


def test_redirect_fallback_matches_pre_migration():
    """兜底清单逐字等于迁移前那份（生产路径用 profile.sensitive_paths，此表只在
    profile 缺失时兜底；搬家不改内容）。"""
    assert ia._SENSITIVE_PATH_FRAGMENTS_DEFAULT == [
        "/etc/shadow", "/etc/gshadow", "/etc/passwd", "/etc/sudoers", "/etc/hosts",
        "/etc/crontab", "/etc/systemd/", "/etc/ssh/sshd_config", "/etc/pam.d/",
        "/etc/nginx/nginx.conf", "/etc/nginx/conf.d/", "/etc/nginx/sites-enabled/",
        "/boot/", "/proc/sys/", "/sys/", "/dev/mem", "/dev/kmsg",
        ".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/authorized_keys",
    ]


def test_end_to_end_still_blocks():
    """端到端回归：内联脚本读敏感文件仍判 Deny（搬家后判定不变）。"""
    from agent_moss.profiles import get_profile
    r = ia.analyze_inline_script(
        """python3 -c "open('/etc/shadow').read()" """.strip(),
        profile=get_profile("linux"),
    )
    assert r.actionable and not r.allowed
    assert r.risk_type == "file_access"

    # 纯字面量仍放行（不制造误报）
    lit = ia.analyze_inline_script(
        """python3 -c "print('/etc/shadow')" """.strip(),
        profile=get_profile("linux"),
    )
    assert lit.actionable and lit.allowed
