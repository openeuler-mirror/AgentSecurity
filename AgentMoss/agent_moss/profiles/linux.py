"""LinuxProfile — Linux 操作系统的安全检测 Profile

从现有的 heuristic.py 和 logic_rules.py 迁移所有 Linux 特定模式，
确保与现有检测行为完全一致。
"""

import os
import re
from pathlib import Path

from .base import OSProfile, CommandPattern, SensitivePath, IntentDeviationPattern

_DEFAULT_INJECTION_KEYWORDS: list[dict] = [
    # ---- 指令覆盖 / Instruction Override ----
    {"keyword": "ignore previous instructions", "risk_level": "critical", "lang": "en"},
    {"keyword": "ignore all previous", "risk_level": "critical", "lang": "en"},
    {"keyword": "disregard all prior", "risk_level": "critical", "lang": "en"},
    {"keyword": "forget everything", "risk_level": "high", "lang": "en"},
    {"keyword": "忽略之前的指令", "risk_level": "critical", "lang": "zh"},
    {"keyword": "忽略所有先前的", "risk_level": "critical", "lang": "zh"},
    {"keyword": "忽略上面所有", "risk_level": "high", "lang": "zh"},
    {"keyword": "请忘记之前", "risk_level": "high", "lang": "zh"},
    # ---- 角色劫持 / Role Hijacking ----
    {"keyword": "you are now", "risk_level": "high", "lang": "en"},
    {"keyword": "you are no longer", "risk_level": "high", "lang": "en"},
    {"keyword": "new instructions", "risk_level": "high", "lang": "en"},
    {"keyword": "from now on, you", "risk_level": "high", "lang": "en"},
    {"keyword": "你现在是一个", "risk_level": "high", "lang": "zh"},
    {"keyword": "你不再是一个", "risk_level": "high", "lang": "zh"},
    {"keyword": "从现在开始你", "risk_level": "high", "lang": "zh"},
    {"keyword": "你的新角色是", "risk_level": "high", "lang": "zh"},
    # ---- 命令注入 / Command Injection ----
    {"keyword": "system prompt", "risk_level": "high", "lang": "en"},
    {"keyword": "reveal your instructions", "risk_level": "high", "lang": "en"},
    {"keyword": "output your instructions", "risk_level": "high", "lang": "en"},
    {"keyword": "repeat your instructions", "risk_level": "medium", "lang": "en"},
    {"keyword": "系统提示", "risk_level": "high", "lang": "zh"},
    {"keyword": "输出你的指令", "risk_level": "high", "lang": "zh"},
    {"keyword": "重复你的指令", "risk_level": "medium", "lang": "zh"},
    # ---- 社会工程 / Social Engineering ----
    {"keyword": "this is an authorized test", "risk_level": "high", "lang": "en"},
    {"keyword": "security audit approved", "risk_level": "high", "lang": "en"},
    {"keyword": "admin override", "risk_level": "critical", "lang": "en"},
    {"keyword": "debug mode", "risk_level": "high", "lang": "en"},
    {"keyword": "maintenance mode", "risk_level": "high", "lang": "en"},
    {"keyword": "这是授权的测试", "risk_level": "high", "lang": "zh"},
    {"keyword": "安全审计已批准", "risk_level": "high", "lang": "zh"},
    {"keyword": "管理员覆盖", "risk_level": "critical", "lang": "zh"},
    {"keyword": "调试模式", "risk_level": "high", "lang": "zh"},
    # ---- XSS / 注入 ----
    {"keyword": "<script>", "risk_level": "high", "lang": "en"},
    {"keyword": "javascript:", "risk_level": "high", "lang": "en"},
    {"keyword": "onerror=", "risk_level": "high", "lang": "en"},
    {"keyword": "onload=", "risk_level": "high", "lang": "en"},
    # ---- 伪造边界 / Fake Boundaries ----
    {"keyword": "=== END OF", "risk_level": "high", "lang": "en"},
    {"keyword": "--- END SYSTEM", "risk_level": "high", "lang": "en"},
    {"keyword": "[END OF", "risk_level": "high", "lang": "en"},
    {"keyword": "=== 结束", "risk_level": "high", "lang": "zh"},
    {"keyword": "--- 结束系统", "risk_level": "high", "lang": "zh"},
    # ---- 开发者模式 ----
    {"keyword": "developer mode", "risk_level": "critical", "lang": "en"},
    {"keyword": "DAN mode", "risk_level": "critical", "lang": "en"},
    {"keyword": "jailbreak", "risk_level": "critical", "lang": "en"},
    {"keyword": "开发者模式", "risk_level": "critical", "lang": "zh"},
    {"keyword": "越狱", "risk_level": "critical", "lang": "zh"},
]


class LinuxProfile(OSProfile):
    """Linux 操作系统安全检测 Profile"""

    os_type_value = "linux"

    @property
    def os_type(self) -> str:
        return self.os_type_value

    # ─── 层1：危险命令模式 ───

    @property
    def dangerous_commands(self) -> list[CommandPattern]:
        """危险命令正则模式列表（归一化自 rules/l1_rules.json 的危险命令段）。"""
        from ..rules_loader import load_l1
        cmds = load_l1().get("dangerous_commands", [])
        return [
            CommandPattern(
                pattern=c["pattern"],
                risk_level=c["risk_level"],
                risk_type=c["risk_type"],
                reason=c["reason"],
            )
            for c in cmds
        ]


    # ─── 安全命令白名单（两级） ───

    @property
    def fully_safe_commands(self) -> list[str]:
        """完全安全的 bash 子命令：跳过 L2 + L3（不涉及文件内容读取）"""
        return [
            r"^ls(?:\s|$)", r"^dir(?:\s|$)",
            r"^pwd(?:\s|$)", r"^which\s+", r"^whereis\s+", r"^realpath\s+",
            r"^basename\s+", r"^dirname\s+",
            r"^file\s+", r"^stat\s+", r"^du(?:\s|$)",
            r"^echo\s+", r"^printf\s+",
            r"^type\s+", r"^command\s+",
            # 系统信息查询（只读，不涉及文件/网络/权限）
            r"^whoami(?:\s|$)", r"^id(?:\s|$)",
            r"^hostname(?:\s|$)", r"^uname(?:\s|$)",
            r"^date(?:\s|$)", r"^env(?:\s|$)",
            r"^printenv(?:\s|$)", r"^tty(?:\s|$)",
            r"^arch(?:\s|$)", r"^uptime(?:\s|$)",
            r"^groups(?:\s|$)", r"^logname(?:\s|$)",
        ]

    @property
    def readonly_sensitive_commands(self) -> list[str]:
        """安全但可能访问敏感路径的 bash 子命令：跳过 L3，保留 L2"""
        return [
            r"^cat\s+\S", r"^head(?:\s|$)", r"^tail(?:\s|$)",
            r"^less(?:\s|$)", r"^more(?:\s|$)", r"^wc(?:\s|$)",
            r"^grep(?:\s|$)", r"^find\s+",
            r"^ag(?:\s|$)", r"^rg(?:\s|$)",
            r"^awk\s+", r"^sed\s+", r"^cut\s+",
            r"^sort(?:\s|$)", r"^uniq(?:\s|$)",
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
        """Prompt 注入检测关键词列表（归一化自 rules/l1_rules.json 的注入段）。"""
        from ..rules_loader import load_l1
        return load_l1().get("injection_detection", [])

    # ─── 层2：敏感路径 ───

    @property
    def sensitive_paths(self) -> list[SensitivePath]:
        """敏感路径列表（归一化自 rules/l1_rules.json 的敏感路径段）。

        字段：path / risk_level / desc / deny_mode。deny_mode 为源数据，
        与 credential/read_only 向后兼容推导无关（deny_mode 优先）。
        """
        from ..rules_loader import load_l1
        sps = load_l1().get("sensitive_path_access", [])
        return [
            SensitivePath(
                path=sp["path"],
                risk_level=sp["risk_level"],
                desc=sp["desc"],
                deny_mode=sp.get("deny_mode", ""),
                dir_del_only=sp.get("dir_del_only", False),
            )
            for sp in sps
        ]

    @property
    def write_keywords(self) -> list[str]:
        return [
            "write", "写入", "save", "保存", "modify", "修改",
            "update", "更新", "delete", "删除", "remove", "移除",
            "create", "创建", "append", "追加", "truncate", "截断",
            "overwrite", "覆盖", "replace", "替换",
            "edit",  # filemgr-editfile 是写操作，action_type 含 "edit" 需被检测为写
        ]

    @property
    def read_keywords(self) -> list[str]:
        return [
            "read", "读取", "cat", "head", "tail", "less", "more",
            "view", "查看", "open", "打开", "load", "加载",
            "grep", "search", "搜索", "find", "查找",
        ]

    @property
    def intent_deviation_patterns(self) -> list[IntentDeviationPattern]:
        """意图偏离关键词对（归一化自 rules/l2_rules.json 的 intent_consistency）。"""
        from ..rules_loader import load_l2
        pats = load_l2().get("intent_consistency", [])
        return [
            IntentDeviationPattern(
                intent_keywords=p["intent_keywords"],
                dangerous_actions=p["dangerous_actions"],
                reason=p["reason"],
            )
            for p in pats
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
