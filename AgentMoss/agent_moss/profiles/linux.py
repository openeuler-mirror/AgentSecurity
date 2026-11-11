"""LinuxProfile — Linux 操作系统的安全检测 Profile

从现有的 heuristic.py 和 logic_rules.py 迁移所有 Linux 特定模式，
确保与现有检测行为完全一致。
"""

import os
import re
from functools import cached_property
from pathlib import Path

from .base import OSProfile, CommandPattern, SensitivePath, IntentDeviationPattern


class LinuxProfile(OSProfile):
    """Linux 操作系统安全检测 Profile"""

    os_type_value = "linux"

    @cached_property
    def os_type(self) -> str:
        return self.os_type_value

    # ─── 层1：危险命令模式 ───

    @cached_property
    def dangerous_commands(self) -> list[CommandPattern]:
        """危险命令正则模式列表（归一化自 rules/l1_rules.json 的危险命令段）。

        按 os 字段过滤：Windows 专属条目（del/icacls/certutil/注册表等）不进
        Linux Profile，避免跨平台误判；不带 os 字段的历史条目视为 linux。
        """
        from ..rules_loader import load_l1
        cmds = load_l1().get("dangerous_commands", [])
        return [
            CommandPattern(
                pattern=c["pattern"],
                risk_level=c["risk_level"],
                risk_type=c["risk_type"],
                reason=c["reason"],
                # 原始平台归属（不是加载它的 Profile）——MacOSProfile 继承
                # Linux 规则时，Linux 条目仍标 linux，供 runtime 种子去重
                os=str(c.get("os") or "linux").lower(),
            )
            for c in cmds
            if str(c.get("os") or "linux").lower() in self.accepted_os
        ]


    # 安全命令白名单（fully_safe_commands / readonly_sensitive_commands /
    # safe_action_types / readonly_sensitive_action_types）已迁到
    # rules/platform_traits.json，由 OSProfile 基类统一读取 —— 本类不再覆盖。

    # injection_keywords 各平台实现相同，已收拢到 OSProfile 基类（读
    # rules/l1_rules.json 的注入段 + 按 os 过滤），本类不再覆盖。

    # ─── 层2：敏感路径 ───

    @cached_property
    def sensitive_paths(self) -> list[SensitivePath]:
        """敏感路径列表（归一化自 rules/l1_rules.json 的敏感路径段）。

        字段：path / risk_level / desc / deny_mode。deny_mode 为源数据，
        与 credential/read_only 向后兼容推导无关（deny_mode 优先）。

        按 os 字段过滤：Windows 专属条目（os=windows）不进 Linux Profile，
        避免 Windows 路径（C:\\Windows\\...、HKLM\\...）在 Linux 判定中误报。
        不带 os 字段的历史条目视为 linux（向后兼容）。
        """
        from ..rules_loader import load_l1
        sps = load_l1().get("sensitive_path_access", [])
        return [
            SensitivePath(
                path=sp["path"],
                risk_level=sp["risk_level"],
                desc=sp["desc"],
                deny_mode=sp.get("deny_mode", ""),
                # ⚠️ credential / read_only 必须从 deny_mode 派生（TS 侧
                # _loadSensitivePathScope 一直这么干）。历史 bug：这里不派生，
                # 于是 sp.credential **恒为 False** —— _check_indirect_file_access
                # 的 found_credential 分支成死代码，cwd 里只有凭据文件时 Python
                # 判不出来（TS 能），两端分叉。
                credential=sp.get("deny_mode", "") == "deny_both",
                read_only=sp.get("deny_mode", "") == "deny_read",
                dir_del_only=sp.get("dir_del_only", False),
                os=str(sp.get("os") or "linux").lower(),
            )
            for sp in sps
            if str(sp.get("os") or "linux").lower() in self.accepted_os
        ]

    # write_keywords / read_keywords 已迁到 rules/platform_traits.json
    # （由 OSProfile 基类统一读取），本类不再覆盖。

    @cached_property
    def intent_deviation_patterns(self) -> list[IntentDeviationPattern]:
        """意图偏离关键词对（归一化自 rules/l2_rules.json 的 intent_consistency）。

        按 os 字段过滤（同危险命令/敏感路径）：Windows 专属意图模式
        （del/rmdir/reg delete 等动作词）不进 Linux 判定。
        """
        from ..rules_loader import load_l2
        pats = load_l2().get("intent_consistency", [])
        return [
            IntentDeviationPattern(
                intent_keywords=p["intent_keywords"],
                dangerous_actions=p["dangerous_actions"],
                reason=p["reason"],
                os=str(p.get("os") or "linux").lower(),
            )
            for p in pats
            if str(p.get("os") or "linux").lower() in self.accepted_os
        ]

    # ─── 路径提取 ───

    def extract_file_paths(self, text: str) -> list[str]:
        """
        从文本中提取文件路径。
        支持 Linux/Unix 格式的路径（/ 开头）和 Windows 格式的路径（C:\\ 开头）。
        支持 key=value 语法的路径（of=/path、if=/path、--output=/path 等）。
        """
        paths = []

        # 提取 / 开头的路径（路径前是行首或空白）
        unix_paths = re.findall(r'(?:^|\s)(/[^\s;|&><\'"]+)', text)
        paths.extend(unix_paths)

        # 提取 key=value 语法的路径：of=/path、if=/path、--output=/path 等。
        # 现有 unix_paths 正则要求路径前是行首或空白，`of=/tmp/x` 里 / 前是 = 不匹配 →
        # dd of=/path 等漏报（NEW-FN-A）。此正则匹配 `=` 或长选项 `--output=` 后紧跟的 / 路径。
        # NEW-FP-H: 先剥掉引号内容，避免 echo "of=/dev/null done" 这类输出文本里的
        # of=/dev/null 被误当真实写目标。引号内纯路径（dd of="/tmp/file"）由下方
        # quoted_paths 独立提取（要求引号内以 / 开头），故剥引号不会漏报真实写。
        text_no_quotes = re.sub(r"'[^']*'|\"[^\"]*\"", "", text)
        kv_paths = re.findall(r'(?:=)(/[^\s;|&><\'"]+)', text_no_quotes)
        paths.extend(kv_paths)

        # 提取引号内的路径
        quoted_paths = re.findall(r'["\'](/[^\"\']+)["\']', text)
        paths.extend(quoted_paths)

        # 提取 Windows 路径（用于跨平台场景）
        win_paths = re.findall(r'(?:^|\s)([A-Za-z]:[\\/][^\s;|&><\'"]+)', text)
        paths.extend(win_paths)

        # 去重
        return list(dict.fromkeys(paths))
