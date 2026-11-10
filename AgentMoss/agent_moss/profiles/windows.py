"""WindowsProfile — Windows 操作系统的安全检测 Profile

首批 Windows 特定规则集，覆盖常见危险操作模式。
后续根据实际攻击案例持续扩展。
"""

import re

from .base import OSProfile, CommandPattern, SensitivePath, IntentDeviationPattern

_DEFAULT_INJECTION_KEYWORDS: list[dict] = [
    # 复用与 Linux 相同的注入检测关键词（与语言无关的注入攻击）
    {"keyword": "ignore previous instructions", "risk_level": "critical", "lang": "en"},
    {"keyword": "forget everything", "risk_level": "high", "lang": "en"},
    {"keyword": "忽略之前的指令", "risk_level": "critical", "lang": "zh"},
    {"keyword": "you are now", "risk_level": "high", "lang": "en"},
    {"keyword": "system prompt", "risk_level": "high", "lang": "en"},
    {"keyword": "reveal your instructions", "risk_level": "high", "lang": "en"},
    {"keyword": "admin override", "risk_level": "critical", "lang": "en"},
    {"keyword": "<script>", "risk_level": "high", "lang": "en"},
    {"keyword": "developer mode", "risk_level": "critical", "lang": "en"},
    {"keyword": "jailbreak", "risk_level": "critical", "lang": "en"},
    {"keyword": "bypass audit", "risk_level": "critical", "lang": "en"},
    {"keyword": "disable guard", "risk_level": "critical", "lang": "en"},
    {"keyword": "绕过审计", "risk_level": "critical", "lang": "zh"},
    {"keyword": "禁用安全检查", "risk_level": "critical", "lang": "zh"},
]


class WindowsProfile(OSProfile):
    """Windows 操作系统安全检测 Profile"""

    os_type_value = "windows"

    @property
    def os_type(self) -> str:
        return self.os_type_value

    # ─── 层1：危险命令模式 ───

    @property
    def dangerous_commands(self) -> list[CommandPattern]:
        return [
            # 递归删除
            CommandPattern(
                pattern=r"(?:del|rmdir|rd)\s+[\\/][a-zA-Z]:",
                risk_level="critical",
                risk_type="script_execution",
                reason="检测到递归删除关键路径 (del/rmdir C:\\)",
            ),
            CommandPattern(
                pattern=r"del\s+[\\/][a-zA-Z]:",
                risk_level="critical",
                risk_type="script_execution",
                reason="检测到删除卷根目录文件 (del C:\\)",
            ),
            # 全权限设置
            CommandPattern(
                pattern=r"icacls\s+\*?\s*[\\/]?[a-zA-Z]:.*Everyone:F",
                risk_level="critical",
                risk_type="script_execution",
                reason="检测到授予 Everyone 完全控制权限",
            ),
            # 用户管理
            CommandPattern(
                pattern=r"net\s+user\s+[/]?add",
                risk_level="high",
                risk_type="privilege_escalation",
                reason="检测到添加系统用户 (net user /add)",
            ),
            CommandPattern(
                pattern=r"net\s+localgroup\s+[/]?add",
                risk_level="high",
                risk_type="privilege_escalation",
                reason="检测到添加用户到本地组 (net localgroup /add)",
            ),
            # 注册表操作
            CommandPattern(
                pattern=r"reg\s+delete\s+HK",
                risk_level="high",
                risk_type="file_access",
                reason="检测到删除注册表项 (reg delete)",
            ),
            # 磁盘格式化
            CommandPattern(
                pattern=r"format\s+[a-zA-Z]:",
                risk_level="critical",
                risk_type="script_execution",
                reason="检测到格式化磁盘操作",
            ),
            # PowerShell 编码执行
            CommandPattern(
                pattern=r"powershell\s+.*-EncodedCommand\b",
                risk_level="critical",
                risk_type="script_execution",
                reason="检测到 PowerShell 编码命令执行，可能隐藏恶意操作",
            ),
            CommandPattern(
                pattern=r"powershell\s+.*-Command\s+\S",
                risk_level="high",
                risk_type="script_execution",
                reason="检测到 PowerShell 命令执行",
            ),
            # 远程下载执行
            CommandPattern(
                pattern=r"(?:Invoke-WebRequest|Invoke-RestMethod|curl|wget)\s+.*?\.(?:ps1|exe|bat)\b",
                risk_level="critical",
                risk_type="script_execution",
                reason="检测到远程下载可执行脚本 (powershell curl)",
            ),
            # WMI 进程创建
            CommandPattern(
                pattern=r"wmic\s+process\s+call\s+create",
                risk_level="high",
                risk_type="script_execution",
                reason="检测到 WMI 远程进程创建",
            ),
            # SAM 文件访问
            CommandPattern(
                pattern=r"config\\SAM",
                risk_level="critical",
                risk_type="file_access",
                reason="检测到访问 Windows SAM 安全账户管理器",
            ),
            CommandPattern(
                pattern=r"ntds\.dit",
                risk_level="critical",
                risk_type="file_access",
                reason="检测到访问 Active Directory 数据库 (ntds.dit)",
            ),
            # 关闭防御
            CommandPattern(
                pattern=r"Set-MpPreference\s+.*DisableRealtimeMonitoring\s+\$true",
                risk_level="critical",
                risk_type="script_execution",
                reason="检测到尝试关闭 Windows Defender 实时监控",
            ),
            CommandPattern(
                pattern=r"netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off",
                risk_level="high",
                risk_type="script_execution",
                reason="检测到尝试关闭 Windows 防火墙",
            ),
            # 计划任务
            CommandPattern(
                pattern=r"schtasks\s+[/]?create",
                risk_level="high",
                risk_type="persistence",
                reason="检测到创建计划任务（持久化）",
            ),
        ]

    # ─── 安全命令白名单（两级） ───

    @property
    def fully_safe_commands(self) -> list[str]:
        """完全安全的命令：跳过 L2 + L3"""
        return [
            r"^dir(?:\s|$)",
            r"^where\s+",
            r"^echo\s+",
            r"^cd(?:\s|$)",
            r"^tree(?:\s|$)",
            r"^help(?:\s|$)",
            r"^cls(?:\s|$)",
            r"^ver(?:\s|$)",
        ]

    @property
    def readonly_sensitive_commands(self) -> list[str]:
        """安全但可能访问敏感路径的命令：跳过 L3，保留 L2"""
        return [
            r"^type\s+",
            r"^findstr\s+",
        ]

    @property
    def safe_commands(self) -> list[str]:
        """向后兼容：合并为完整安全列表"""
        return self.fully_safe_commands + self.readonly_sensitive_commands

    @property
    def safe_action_types(self) -> frozenset[str]:
        """完全安全操作类型：跳过 L2 + L3"""
        return frozenset({
            "ask_user_question", "glob", "list_dir", "ls", "count_text_length",
            "filemgr-globfiles",
        })

    @property
    def readonly_sensitive_action_types(self) -> frozenset[str]:
        """安全但可能访问敏感路径的操作类型：跳过 L3，保留 L2"""
        return frozenset({
            "read", "file_read", "read_file", "head", "tail", "grep",
            "filemgr-readfile", "filemgr-grepfiles",
        })

    @property
    def injection_keywords(self) -> list[dict]:
        return _DEFAULT_INJECTION_KEYWORDS

    # ─── 层2：敏感路径 ───

    @property
    def sensitive_paths(self) -> list[SensitivePath]:
        return [
            SensitivePath(path="C:\\Windows\\System32\\config\\SAM", risk_level="critical", desc="Windows SAM 安全账户管理器"),
            SensitivePath(path="C:\\Windows\\System32\\config\\SECURITY", risk_level="critical", desc="Windows 安全配置"),
            SensitivePath(path="C:\\Windows\\System32\\config\\SYSTEM", risk_level="high", desc="Windows 系统配置"),
            SensitivePath(path="C:\\Windows\\System32\\LSA", risk_level="high", desc="LSA 认证配置"),
            SensitivePath(path="C:\\Windows\\NTDS", risk_level="critical", desc="Active Directory 数据库"),
            SensitivePath(path="C:\\Windows\\repair", risk_level="high", desc="系统修复备份（含 SAM 备份）"),
            SensitivePath(path="C:\\Windows\\System32\\GroupPolicy", risk_level="high", desc="组策略"),
            SensitivePath(path="AppData\\Roaming\\.ssh\\", risk_level="critical", desc="SSH 密钥 (Windows)"),
            SensitivePath(path="\\.ssh\\id_rsa", risk_level="critical", desc="SSH 私钥 (Windows)"),
            SensitivePath(path="\\.ssh\\authorized_keys", risk_level="high", desc="SSH 授权密钥 (Windows)"),
            SensitivePath(path="C:\\ProgramData\\", risk_level="medium", desc="程序数据目录（共享配置）"),
            SensitivePath(path="HKLM\\SOFTWARE\\Microsoft\\", risk_level="high", desc="注册表 HKLM 软件配置"),
            SensitivePath(path="HKLM\\SYSTEM\\CurrentControlSet\\", risk_level="critical", desc="注册表系统关键配置"),
            SensitivePath(path="HKCU\\SOFTWARE\\Microsoft\\", risk_level="medium", desc="注册表 HKCU 软件配置"),
        ]

    @property
    def write_keywords(self) -> list[str]:
        return [
            "write", "写入", "save", "保存", "modify", "修改",
            "update", "更新", "delete", "删除", "remove", "移除",
            "create", "创建", "append", "追加", "overwrite", "覆盖",
            "replace", "替换", "set", "设置", "reg", "注册表",
        ]

    @property
    def read_keywords(self) -> list[str]:
        return [
            "read", "读取", "type", "findstr", "dir",
            "view", "查看", "open", "打开", "load", "加载",
            "search", "搜索", "find", "查找", "get", "获取",
        ]

    @property
    def intent_deviation_patterns(self) -> list[IntentDeviationPattern]:
        return [
            IntentDeviationPattern(
                intent_keywords=["读取", "查看", "分析", "read", "analyze", "view", "list", "列出"],
                # 英文词由 _match_dangerous_action 用词边界+排参数前缀匹配
                dangerous_actions=["删除", "remove", "delete", "del", "rmdir", "格式化", "format"],
                reason="原始意图为读取/分析，但执行了删除操作",
            ),
            IntentDeviationPattern(
                intent_keywords=["查询", "搜索", "search", "query", "find"],
                dangerous_actions=["修改", "write", "写入", "set", "alter", "reg delete"],
                reason="原始意图为查询/搜索，但执行了修改操作",
            ),
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
