"""WindowsProfile — Windows 操作系统的安全检测 Profile

首批 Windows 特定规则集，覆盖常见危险操作模式。
后续根据实际攻击案例持续扩展。
"""

import re
from functools import cached_property

from .base import OSProfile, CommandPattern, SensitivePath, IntentDeviationPattern


class WindowsProfile(OSProfile):
    """Windows 操作系统安全检测 Profile"""

    os_type_value = "windows"

    # 只加载 os=windows 的规则条目（Linux/macOS 条目一律不参与 Windows 判定）
    accepted_os = ("windows",)

    # 平台命令集（write_command_res / read_only_commands / fully_safe_commands /
    # readonly_sensitive_commands / safe_action_types /
    # readonly_sensitive_action_types / write_keywords / read_keywords）已迁到
    # rules/platform_traits.json，由 OSProfile 基类统一读取 —— 本类不再覆盖。
    # 注意：Windows 之所以必须独立一份，是因为命令体系与 Unix 不同
    # （del/copy/icacls/reg 而非 rm/cp；type/findstr 而非 cat/head）。

    @property
    def os_type(self) -> str:
        return self.os_type_value

    # ─── 层1：危险命令模式 ───

    @cached_property
    def dangerous_commands(self) -> list[CommandPattern]:
        """危险命令正则模式列表（归一化自 rules/l1_rules.json 的 Windows 段）。

        与 LinuxProfile 共用同一份 JSON 单一事实源，靠 os 字段区分平台：
        带 "os": "windows" 的条目仅 Windows Profile 加载；不带 os 字段的历史
        条目视为 linux，Windows 不加载（避免 Linux 的 rm 规则误伤 Windows 命令）。
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

    # injection_keywords 各平台实现相同，已收拢到 OSProfile 基类（读
    # rules/l1_rules.json 的注入段 + 按 os 过滤）。本类此前自带一份 14 条的
    # 硬编码副本，与 JSON 的 48 条形成双向分叉，2026-10 删除。

    # ─── 层2：敏感路径 ───

    @cached_property
    def sensitive_paths(self) -> list[SensitivePath]:
        """敏感路径列表（归一化自 rules/l1_rules.json 的敏感路径段，os=windows）。

        与 LinuxProfile 共用同一份 JSON 单一事实源，靠 os 字段区分平台：
        - 带 "os": "windows" 的条目 → 仅 Windows Profile 加载
        - 不带 os 字段的历史条目 → 视为 linux，Windows 不加载

        每条的 deny_mode 在 JSON 中显式声明（deny_both 表示读也拦）——
        系统凭据库（SAM/SECURITY/NTDS）与用户私钥必须读也拦，否则
        `type ...\\SAM` 这类只读窃取动作会直接放行。
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

    @cached_property
    def intent_deviation_patterns(self) -> list[IntentDeviationPattern]:
        """意图偏离关键词对（归一化自 rules/l2_rules.json，os=windows）。

        与 Linux 共用同一份 JSON 单一事实源；Windows 的动作词（del/rmdir/
        reg delete）与 Linux（rm/rmdir）不同，故按 os 字段区分平台。
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
        从文本中提取文件路径，优先识别 Windows 路径格式。
        """
        paths = []

        # 提取 Windows 路径（C:\... 或 C:/... 或 \\server\share）
        win_paths = re.findall(r'(?:^|\s)([A-Za-z]:[\\/][^\s;|&><\'"]+)', text)
        paths.extend(win_paths)

        # 提取 UNC 路径
        unc_paths = re.findall(r'(?:^|\s)(\\\\[^\\\s;|&><\'"][^\\\s;|&><\'"]*(?:\\[^\s;|&><\'"]+)+)', text)
        paths.extend(unc_paths)

        # 提取引号内的 Windows 路径
        quoted_paths = re.findall(r'["\'](' + r'[A-Za-z]:[\\/][^\"\']+' + r')["\']', text)
        paths.extend(quoted_paths)

        # 提取 / 开头的路径（用于 WSL/Cygwin 兼容场景）
        unix_paths = re.findall(r'(?:^|\s)(/[^\s;|&><\'"]+)', text)
        paths.extend(unix_paths)

        # 去重
        return list(dict.fromkeys(paths))
