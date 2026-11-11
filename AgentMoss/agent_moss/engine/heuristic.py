"""特征匹配静态检测 — 快速拦截已知危险模式

采用组合式检测器架构，包含三个独立子检测器：
1. UserRuleMatcher — 用户敏感动作规则匹配（精确 + 通配符）
2. CommandPatternScanner — 关键命令正则检测（从 OSProfile 获取模式）
3. InjectionKeywordChecker — Prompt 注入检测（从 OSProfile 获取关键词）

三者由 HeuristicDetector 统一协调，按优先级依次执行，支持短路返回。
"""

import json
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..profiles.base import OSProfile
    from ..agents.base import AgentExtensions

from ..infra.rules_mode import is_builtin_only, is_hot_reload_enabled
from ..infra.paths import asset_dir
from ..rules_loader import load_heuristic_rules
from .types import HeuristicResult

# _is_write_operation 留在 logic_rules.py 作为单一事实源（read_before_write 也用），
# 此处复用避免读写判定逻辑漂移。
from .logic_rules import _is_write_operation, _SensitivePathMatcher, _is_directory_delete_action, _is_archive_read_of_dir, _is_ssh_keygen_generate
from .logic_rules import has_exec_bypass_chain, ALL_QUOTES_RE
# 引号感知命令段切分同样下沉 logic_rules（NEW-FN-M 起含单管道切分），单一事实源：
from .logic_rules import _SEPARATOR_SEGMENTS, _split_shell_segments

# 默认用户规则文件路径（随包内置；builtin 模式下唯一允许读取的 user_rules.json）
# 用户自定义规则文件（随规则目录走）。函数而非常量：AGENT_MOSS_RULES_ROOT 改了立即生效。
def default_rules_path() -> Path:
    return asset_dir("rules") / "user_rules.json"


#: 兼容旧引用名（模块导入时求值；内部调用请用 default_rules_path()）
DEFAULT_RULES_PATH = default_rules_path()

#: cold / builtin 模式下的进程级 user_rules.json 冻结副本（按路径区分）。
#: UserRuleMatcher 每次 analyze 新建，若每次重读文件，同用户改包内文件仍会热生效。
_FROZEN_USER_RULES_CACHE: dict[str, dict] = {}

# ==================== 风险等级优先级映射 ====================
_RISK_PRIORITY = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _max_risk(*levels: str) -> str:
    """返回多个风险等级中最高的那个"""
    return max(levels, key=lambda l: _RISK_PRIORITY.get(l, 0))


def _merge_heuristic_hit(cur: HeuristicResult, new: HeuristicResult) -> HeuristicResult:
    """合并两次启发式命中,取风险等级更高者（对齐 TS runHeuristicCheck 的 max 合并）。

    detect() 原是"先命中即 return"的早退结构,导致低等级命中（如命令正则 medium）
    遮蔽高等级子检测器（如通配符+删除 high）→ 双端漂移（TS 取 max 不漏 wildcard,
    Python 早退漏）。改为扫完全部子检测器后取最高,与 TS 语义一致。
    """
    if not cur.hit:
        return new
    if not new.hit:
        return cur
    if _RISK_PRIORITY.get(new.risk_level, 0) <= _RISK_PRIORITY.get(cur.risk_level, 0):
        return cur
    return new


# ==================== 从 L2 搬入 L1 的静态子检测器 ====================
# 以下三个检测器只看 a_next（不看 action_history），按"L1 只看这一步"原则
# 从 logic_rules.py 搬入。逻辑原样保留，返回类型从 LogicRuleResult 改为
# HeuristicResult（携带 is_credential / violated_rule），保证三层分析效果一致。

# 小型名单：单一事实源 rules/heuristic_rules.json（与 TS heuristic.ts 共用）。
_HEURISTIC_RULES = load_heuristic_rules()

# sensitive_path 排除的非文件工具前缀（避免 memory-searchMemory 等误报）
_SENSITIVE_EXCLUDED_PREFIXES: tuple[str, ...] = tuple(
    _HEURISTIC_RULES.get("sensitive_excluded_prefixes") or ()
)

# 搜索/查询类工具前缀：其 action_detail 是「查询数据」（如 query=...），不是指令。
# 注入关键词检测应只针对指令性文本（用户 prompt / reason / 命令），
# 否则搜索 "jailbreak"、"bypass" 等资料会被 L1 注入检测误判为注入攻击（prompt injection 误报）。
_SEARCH_ACTION_PREFIXES: tuple[str, ...] = tuple(
    _HEURISTIC_RULES.get("search_action_prefixes") or ()
)
_SEARCH_ACTION_EXACT: tuple[str, ...] = tuple(
    _HEURISTIC_RULES.get("search_action_exact") or ()
)


def _is_search_action_type(action_type: str) -> bool:
    """判断是否为搜索/查询类工具（action_detail 是数据载荷，非指令）。"""
    at = action_type.lower()
    return any(at.startswith(p) for p in _SEARCH_ACTION_PREFIXES) or at in _SEARCH_ACTION_EXACT


class SensitivePathChecker:
    """子检测器：敏感路径访问检测（从 L2 搬入）

    deny_both（凭据）：无论读写都拦截，is_credential=True
    deny_read：只拦截读取
    deny_write：只拦截写入/删除

    热生效：runtime_config 启用敏感路径 > profile 默认（复用 L2 getter，
    不改 runtime_config JSON schema，保持用户已配置的敏感路径热更新生效）。
    agent_ext.extra_sensitive_paths 追加在后。
    """

    def __init__(self, profile: "OSProfile", agent_ext: "AgentExtensions | None" = None):
        self._profile = profile
        self._agent_ext = agent_ext

    def _get_sensitive_paths(self):
        """runtime_config 启用敏感路径（热更新） > profile 默认；
        末尾追加 agent_ext.extra_sensitive_paths（如有）。

        runtime_config 返回 dict 形态；转为 SensitivePath dataclass 以复用循环体。
        """
        base_paths: list = self._profile.sensitive_paths
        try:
            from ..infra.runtime_config import get_enabled_l2_sensitive_paths_or_default, load_runtime_config
            # 传入当前 profile 的 os_type：runtime config 覆盖按平台隔离，
            # 该平台无条目时回退到该平台 profile 默认（Windows 部署的关键路径）。
            enabled = get_enabled_l2_sensitive_paths_or_default(
                load_runtime_config(),
                getattr(self._profile, "os_type", ""),
            )
            if enabled:
                    from ..profiles.base import SensitivePath
                    # NEW-FP-1: runtime overlay 是用户 stdout 保存的旧数据，.ssh/.aws 目录级
                    # 条目没有 dir_del_only 标记（dir_del_only 是本次新增语义字段）。若仅按
                    # runtime 构造，老 runtime 会丢失该语义 → 目录级条目退化回「写/删都拦」，
                    # mkdir/chmod 初始化被误拦。缺省取 profile 同名条目的 dir_del_only 补齐。
                    _profile_dir_del: dict[str, bool] = {
                        getattr(sp, "path", ""): getattr(sp, "dir_del_only", False)
                        for sp in self._profile.sensitive_paths
                    }
                    base_paths = [
                        SensitivePath(
                            path=r["path"], risk_level=r["risk_level"], desc=r["desc"],
                            credential=r.get("credential", False),
                            read_only=r.get("read_only", False),
                            deny_mode=r.get("deny_mode", ""),
                            dir_del_only=r.get("dir_del_only", _profile_dir_del.get(r["path"], False)),
                        )
                        for r in enabled
                    ]
        except Exception:
            pass

        # agent 专属敏感路径追加在后（通用规则先匹配命中即短路）
        if self._agent_ext and self._agent_ext.extra_sensitive_paths:
            base_paths = base_paths + self._agent_ext.extra_sensitive_paths
        return base_paths

    def check(self, a_next: dict[str, str]) -> HeuristicResult:
        action_type = a_next.get("action_type", "").lower()
        action_detail = a_next.get("action_detail", "").lower()

        # 只对文件/命令类操作执行敏感路径检查，避免 memory-searchMemory 等
        # 非文件工具的关键词参数触发路径子串匹配误报
        if any(action_type.startswith(p) for p in _SENSITIVE_EXCLUDED_PREFIXES):
            return HeuristicResult(hit=False)

        # 检测操作类型：读/写/其他（统一用 _is_write_operation，与 read_before_write 对齐）
        is_write_op = _is_write_operation(action_type, action_detail, self._profile.write_keywords, self._profile)

        # ssh-keygen 生成模式豁免：-t <type> 生成新私钥时 -f 是写目标（输出），
        # 不读取任何已有私钥内容，不应命中 deny_both 的「读私钥」拦截（误报卡死初始化）。
        is_keygen_generate = _is_ssh_keygen_generate(action_detail)

        # NEW-FP-I: echo/printf 引号内参数是字面量（打印文本），其中的敏感路径
        # （echo "/etc/passwd"）不应被当真实路径访问。对首词 echo/printf 的段剥掉
        # 引号内容后再做路径匹配。非 echo/printf 段（cat "/etc/passwd"）不剥，
        # 引号内真实路径参数仍匹配。引号外的重定向（echo "x" > /etc/passwd）在
        # 剥离后保留，仍被路径匹配。
        # NORM-PATH: 再折叠路径混淆段（//、/./），堵 CVE-2023-37274 路径穿越变体。
        # 变体清单见 _path_scan_variants（含「连引号一起折叠」那份，堵
        # `cat "/etc//shadow"` 这类加个引号就绕过的形态）。
        path_scan_texts = _path_scan_variants(action_detail)

        # WIN-SEP: Windows 下追加「分隔符归一化」变体（/ → \）。
        # Windows 的敏感路径规则按反斜杠书写（.aws\credentials、C:\Windows\...），
        # 而 agent 常写正斜杠（cat ~/.aws/credentials、type C:/Windows/...）——
        # 只匹配原文会整条漏掉。**不能直接替换原文**：Win 命令行标志（net user /add、
        # bitsadmin /transfer）与 URL（https://）里的 / 是有语义的，替换会破坏命令规则。
        # 故保留原文、追加变体，任一命中即算命中。
        if getattr(self._profile, "os_type", "") == "windows":
            path_scan_texts += [t.replace("/", "\\") for t in path_scan_texts]

        def _path_search(pattern: str) -> bool:
            """任一扫描变体命中即算命中。"""
            return any(re.search(pattern, t) for t in path_scan_texts)

        for sp in self._get_sensitive_paths():
            raw_path = sp.path
            path = raw_path.lower()
            # 确定拦截模式：优先 deny_mode，向后兼容 credential / read_only
            deny_mode = sp.deny_mode
            if not deny_mode:
                if sp.credential:
                    deny_mode = "deny_both"
                elif sp.read_only:
                    deny_mode = "deny_read"
                else:
                    deny_mode = "deny_write"

            # 检查路径是否在操作中出现
            # deny_both 路径使用边界匹配，避免非文件名拼接（如 something_credentials_yml）误报
            if deny_mode == "deny_both":
                # 以 . 或 / 开头的路径，其首字符不是单词字符，\b 在它前面不构成边界
                # （空格→/ 之间没有 \b），故用 (?:^|[\s/\\]) 替代前导 \b。
                # 也兼容引号上下文：open('.env')、cat ".env" 等
                # 私钥路径（不以 .pub 结尾）加负向先行 (?!\.pub) 排除公钥变体：
                # .ssh/id_rsa 不应命中 .ssh/id_rsa.pub（公钥本就公开）。
                # 内联带 (?!...) 块的路径（如 /etc/ssh/ssh_host_rsa_key(?!\.pub)，
                # 对齐 TS ROOT_SENSITIVE_PATHS）用 _SensitivePathMatcher 复刻 TS
                # pathMatches 分段逻辑；裸路径（无内联块）仍走原 pub_excl 追加。
                if "(" in path and "?" in path:
                    path_match = any(
                        _SensitivePathMatcher.match(path, t) for t in path_scan_texts
                    )
                else:
                    escaped = re.escape(path)
                    pub_excl = r"(?!\.pub)" if not path.endswith(".pub") else r""
                    if path.startswith(".") or path.startswith("/"):
                        path_match = _path_search(rf"(?:^|[\s/\\'\"]){escaped}{pub_excl}\b")
                    else:
                        path_match = _path_search(rf"\b{escaped}{pub_excl}\b")
            else:
                if getattr(sp, "dir_del_only", False):
                    # NEW-FP-1 审核：目录级条目（.ssh/.aws）在下面非 deny_both 分支原本用
                    # 裸子串 path in text——删 ~/.ssh.bak（主目录下独立备份目录，如
                    # ~/.ssh.bak）会被 ".ssh" 子串误命中。改用「目录边界」匹配：
                    # 前导 (?:^|[\s/\\'\"]) + 尾随 (?:/|[\s'\"\\]|$)——目录名后只接受
                    # 路径分隔符或空白/引号/行尾，不接受继续拼字符（.ssh.bak 的 . 不是边界）
                    # dbak'、~/.ssh_backup、~/.ssh-hist 等拼写变体也放行。
                    path_match = _path_search(
                        rf"(?:^|[\s/\\'\"]){re.escape(path)}(?:/|[\s'\"\\]|$)"
                    )
                else:
                    path_match = any(path in t for t in path_scan_texts)

            if not path_match and raw_path.startswith("~"):
                expanded = os.path.expanduser(raw_path)
                if any(expanded.lower() in t for t in path_scan_texts):
                    path_match = True
                else:
                    home_dir = str(Path.home())
                    if expanded.startswith(home_dir):
                        rel_path = expanded[len(home_dir):]
                        if any(
                            rel_path.lower() in t or expanded.lower() in t
                            for t in path_scan_texts
                        ):
                            path_match = True

            if path_match:
                # ssh-keygen 生成模式：-f 是写目标（生成新私钥），放行（不读已有私钥）。
                # 读模式（-y 推导公钥 / -l 指纹 / -p 改密）不受此豁免，仍走 deny_both 拦。
                if is_keygen_generate:
                    continue
                # 凭据文件：无论读写都拦截（读凭据文件同样危险）
                if deny_mode == "deny_both":
                    # chmod 收权豁免（NEW-FP 2026-09）：chmod 600/700/644 等是对敏感文件的
                    # 权限加固（收权），不是读写内容，不应命中 deny_both 的「访问私钥」。
                    # 判据 = other 位无写权限（bit 2 未置位）→ 收权/加固；
                    # other 位有写权限（777/666/707/1777）→ 权限敞开，仍拦截。
                    # 注意：仅对 deny_both（凭据文件）生效，不适用于 deny_write（系统文件）
                    # 的 chmod 改权限——后者仍按原有 deny_write 逻辑拦截。
                    if _is_chmod_tightening(action_detail):
                        continue
                    return HeuristicResult(
                        hit=True,
                        matched_patterns=[sp.path],
                        risk_level=sp.risk_level,
                        reason=f"访问敏感路径: {sp.desc} ({sp.path})",
                        risk_type="file_access",
                        is_credential=True,
                        violated_rule="sensitive_path_access",
                    )
                # read_only 路径：只拦截读取操作，写入/删除放行（如 /dev/random：
                #   读取可耗尽熵池导致 TLS 阻塞（攻击向量），写入是投喂熵（增强安全））
                if deny_mode == "deny_read":
                    if is_write_op:
                        continue  # 允许写入操作（如投喂熵池）
                    return HeuristicResult(
                        hit=True,
                        matched_patterns=[sp.path],
                        risk_level=sp.risk_level,
                        reason=f"读取敏感路径: {sp.desc} ({sp.path})",
                        risk_type="file_access",
                        violated_rule="sensitive_path_access",
                    )
                # dir_del_only 目录级条目（.ssh/.aws）独立于 is_write 判定：
                # 只拦「删除该目录」或「归档/复制读源整包读取」两种高危语义，
                # 不拦 mkdir/chmod/echo 等正常初始化/权限收紧（NEW-FP-1），
                # 也不拦 ls/cat 只读及解压恢复（tar -x、cp 目标位）。
                if getattr(sp, "dir_del_only", False):
                    if self._is_delete_action(action_detail, raw_path):
                        return HeuristicResult(
                            hit=True,
                            matched_patterns=[sp.path],
                            risk_level=sp.risk_level,
                            reason=f"删除敏感目录: {sp.desc} ({sp.path})",
                            risk_type="file_access",
                            violated_rule="sensitive_path_access",
                        )
                    if self._is_archive_read(action_detail, raw_path):
                        return HeuristicResult(
                            hit=True,
                            matched_patterns=[sp.path],
                            risk_level=sp.risk_level,
                            reason=f"归档/复制读取敏感目录: {sp.desc} ({sp.path})",
                            risk_type="file_access",
                            violated_rule="sensitive_path_access",
                        )
                    continue  # 其余对目录级的读/写（mkdir/chmod/echo/ls/cat/解压/写目标位）放行
                # 默认（无特殊标记）：只拦截写入/删除操作，只读访问放行
                if not is_write_op:
                    continue  # 允许读取操作
                return HeuristicResult(
                    hit=True,
                    matched_patterns=[sp.path],
                    risk_level=sp.risk_level,
                    reason=f"访问敏感路径: {sp.desc} ({sp.path})",
                    risk_type="file_access",
                    violated_rule="sensitive_path_access",
                )

        return HeuristicResult(hit=False)

    @staticmethod
    def _is_delete_action(action_detail: str, dir_path: str) -> bool:
        """判断命令是否含「删除该目录/其下内容」意图（dir_del_only 目录级条目专用）。

        复用 L2 单一事实源（_is_directory_delete_action），避免 L1/L2 双份删除判定漂移
        导致同一 .ssh 删除命令两端判定不一致。实现见 logic_rules.py。
        """
        return _is_directory_delete_action(action_detail, dir_path)

    @staticmethod
    def _is_archive_read(action_detail: str, dir_path: str) -> bool:
        """判断命令是否把目录作为归档/复制读源整包读取（dir_del_only 条目专用）。

        复用 L2 单一事实源（_is_archive_read_of_dir），见 logic_rules.py。
        """
        return _is_archive_read_of_dir(action_detail, dir_path)


class DangerousPatternChecker:
    """子检测器：危险操作模式检测（从 L2 搬入）

    通配符+删除（排除 /tmp 等临时目录清理）、重定向覆盖 /etc /boot /proc。
    """

    def check(self, a_next: dict[str, str]) -> HeuristicResult:
        action_detail = a_next.get("action_detail", "").lower()
        action_type = a_next.get("action_type", "").lower()

        if action_type in ("file_write", "file_edit"):
            return HeuristicResult(hit=False)

        # 通配符 + 删除/修改 — 排除 /tmp 等临时目录的清理操作
        # 用边界正则匹配目录名本身（/tmp 和 /tmp/ 都算），避免 `find /tmp -delete`
        # 因 "/tmp/" 子串不匹配（/tmp 后是空格）而 is_temp_path=False 误报（Bug6）。
        # NEW-FP（鸿蒙写周报误报）：先剥离 heredoc 文档字面量内容——文档正文里的
        # `*`/`?`/`rm`/`删除` 是文本不是真实删除命令，不剥离会误判为批量删除。
        # NEW-FP-2: 临时目录豁免扩充相对 var/tmp 前缀——rm -rf var/tmp/* 清理本地 venv
        # 的临时目录（相对路径），旧豁免只认绝对 /tmp 等 4 个，相对 var/tmp/* 漏过 →
        # 通配符+删除误报。相对 var/tmp（无前导 /）也是标准临时目录名，一并豁免。
        _scan = _strip_heredoc_content(action_detail)
        _TEMP_DIRS = _HEURISTIC_TEMP_DIRS
        # NEW-FP-2 审核：相对 var/tmp（无前导 /）& 深层绝对路径（/opt/app/var/tmp）——
        # 裸露的 (?:^|[\s/])td(?:[\s/]|$) 会把「以 var/tmp 结尾的深层子路径」误当临时目录
        # 豁免（rm -rf /opt/app/var/tmp/* 是删业务数据却被放行 = 漏拦）。相对 var/tmp
        # 只认「命令中独立路径 token 首段为 var/tmp（rm -rf var/tmp/*、cd var/tmp && rm *）」
        # 的精确形态；深层绝对路径必须是 /var/tmp（tmp 目录在根下才是标准临时位置）。
        # 相对 token 判定：变量赋值对（VAR=… && rm）、(rm|cd|pushd) 后紧跟的相对首段
        # 是 var/tmp，或整条命令仅 rm 一个目标 token 恰为 var/tmp（var/tmp/foo）。
        is_temp_path = any(
            re.search(rf"(?:^|[\s/]){re.escape(td)}(?:[\s/]|$)", action_detail)
            for td in _TEMP_DIRS
        ) or re.search(
            r"(?:^|[\s;]|&&\s*|\|\|\s*)var/tmp(?:/|[\s;]|$)",
            action_detail,
        ) is not None

        # 通配符必须紧邻删除命令（真实命令 token），而非任意位置子串。
        # 收紧：`*`/`?` 出现在删除命令（rm/del/delete/remove/删除/移除）附近——
        # 匹配「删除命令 + 通配符路径」组合，如 `rm -rf /tmp/*`、`rm *`、`find . -delete`。
        # 不再用 action_detail.includes('*') && includes('rm') 的宽泛子串匹配，
        # 避免文档正文/heredoc/grep 模式里的字面量误报。
        _wildcard_delete_re = re.compile(
            r"(?:\brm\b|\b(r?mdir|del|delete|remove|rmdir|unlink)\b|\b删除\b|\b移除\b)[\s\S]{0,40}?[*?]"
            r"|[*?][\s\S]{0,40}?\b(?:rm|del|delete|remove|rmdir|unlink)\b"
            r"|rm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+\S*[*?]",
            re.IGNORECASE,
        )
        if not is_temp_path and _wildcard_delete_re.search(_scan):
            return HeuristicResult(
                hit=True,
                matched_patterns=["wildcard+delete"],
                risk_level="high",
                reason="检测到通配符结合删除操作，可能造成批量误删",
                risk_type="script_execution",
                violated_rule="dangerous_wildcard_operation",
            )

        # find -exec <写命令> / find | xargs <写命令> — find 在 READ_ONLY_COMMANDS
        # 导致整段被当只读，-exec 或 | xargs 后的 chmod/cp/mv/rm/sed -i 等写命令漏检
        # （NEW-FN-C: -exec；NEW-FN-E: | xargs 等价变体未覆盖）。find 遍历出的文件被
        # 批量执行写操作，静态无法确定具体目标文件，但「find + 写命令」组合本身就是
        # 批量写意图，此处识别 -exec/-execdir/-ok 后紧跟写命令、或 | xargs 后紧跟写命令
        # 即拦截。只匹配写命令首词，避免 -exec grep / | xargs ls 等只读误报。
        # xargs 后的 sed -i 单独匹配（sed -i 是 sed + -i 参数，不是简单首词）。
        _FIND_WRITE_RE = re.compile(
            r"\bfind\b.*?(?:"
            r"(?:^|\s)-exec(?:dir)?\s+(chmod|chown|cp|mv|rm|dd|tee|truncate|mkfs|shred|rmdir|unlink)\b"
            r"|(?:^|\s)\|\s*xargs\s+(?:sed\s+-[a-zA-Z]*i|chmod|chown|cp|mv|rm|dd|tee|truncate|mkfs|shred|rmdir|unlink)\b"
            r")",
            re.IGNORECASE,
        )
        m = _FIND_WRITE_RE.search(action_detail)
        if m:
            cmd_hit = m.group(1) if m.group(1) else "xargs"
            return HeuristicResult(
                hit=True,
                matched_patterns=[f"find ... {cmd_hit}"],
                risk_level="high",
                reason=f"检测到 find 批量执行写操作 ({cmd_hit})，可能批量修改/删除文件",
                risk_type="script_execution",
                violated_rule="find_exec_write",
            )

        # 重定向覆盖关键文件
        # 重定向覆盖关键系统目录——支持引号包裹路径（echo > '/etc/x' 绕过裸 > /etc/ 正则）
        override_patterns = [r">\s*['\"]?/etc/", r">\s*['\"]?/boot/", r">\s*['\"]?/proc/"]
        for pat in override_patterns:
            if re.search(pat, action_detail):
                return HeuristicResult(
                    hit=True,
                    matched_patterns=["redirect+critical-dir"],
                    risk_level="critical",
                    reason="检测到重定向覆盖写入关键系统目录",
                    risk_type="file_access",
                    violated_rule="dangerous_redirect",
                )

        return HeuristicResult(hit=False)


class HomeDeletionChecker:
    """子检测器：主目录删除检测（NEW-FN: rm -rf ~ / $HOME 漏报）

    危险命令正则以 / 开头匹配，`~` 和 `$HOME` 形态全部绕过（rm -rf ~、rm -rf $HOME、
    TARGET=$HOME; rm -rf $TARGET 均漏放——文章"Claude 删 700GB 主目录"同款攻击形态）。
    本检测器按命令段判定：
      - 段首命令是删除类（rm/unlink/rmdir/删除）且目标指向主目录（`~`、`$HOME`、
        `~/…`、`$HOME/…`）→ high / home-deletion。
      - 同段赋值后续删除命令引用主目录变量：`TARGET=$HOME; rm -rf $TARGET` → high。
    只拦删除（home 目录被删是破坏性最大的）；chmod/dd/写文件的定级交给其它规则
    （chmod 规则 critical、敏感路径 deny_write 如 .gitconfig medium），避免误报
     `echo >> ~/.gitconfig`（写 home 下具体文件，非删主目录）被升 high。
    """

    def __init__(self, profile: "OSProfile"):
        self._profile = profile

    # 主目录根目标：~ / $HOME / ${HOME}（可带尾斜杠、通配全内容 / 自身点）。
    # 语义：只拦「删主目录根/全部内容」，不拦「删主目录下具体子路径」——NEW-FP 修复：
    #   rm -rf ~ / rm -rf ~/ / rm -rf ~/* / rm -rf ~/.* / rm -rf $HOME / rm -rf $HOME/ 拦；
    #   rm -rf ~/project/build / rm -rf ~/.cache / rm ~/notes.txt（定向清理具体子路径）放行——
    #   凭据子目录（~/.ssh、~/.aws/credentials、.gnupg）由 SensitivePathChecker 独立兜底，
    #   不依赖本子检测器（收紧后凭据保护不缺口子）。
    # ~ 是非词字符，前导 \b 不生效：前界 ^|空白|=|引号|$（命令替换内）。
    # 后界 行尾|空白|引号|;|}（不接 / 子路径段）；允许 0..1 个 / 后跟 *、.*、.（通配全内容/自身）。
    # NEW-FN-1: `..` 穿越段（~/..、~/../..、$HOME/..、~/a/.. 等）由 _walk_depth 深度解析
    # 单独判定（本正则不含 ..，避免 `~/a` 因后接段而误匹配）。rm -rf ~/.. 等于删 /home、
    # rm -rf /home/user/.. 同理，是删主目录根的放大形态，须拦截（详见 ① 分支）。
    _HOME_TARGET_RE = re.compile(
        r"(?:^|[\s=\"'($])(?:~|(?:\$home|\$\{home\}))(?:/(?:\.\*|\*|\.)?)?(?=[\s\"';}|&|\)]|$)",
        re.IGNORECASE,
    )
    # 同段赋值：VAR=(~ | ~/ | $HOME | $HOME/ | /home/xxx | 命令替换 $() 含根 ~/$HOME)。
    # 捕获整个赋值值（到下一个 shell 分隔符），由 _is_home_value 判定是否主目录根。
    _ASSIGN_RE = re.compile(
        r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
        r"(~[A-Za-z0-9_./-]*|\$HOME[A-Za-z0-9_./-]*|\$\{HOME\}[A-Za-z0-9_./-]*|/home/[^\s;|&]+"
        r"|\$\((?:[^()]|\([^()]*\))*\))(?=\s|;|$|\||&)",
        re.IGNORECASE,
    )
    # 删除类命令（主目录删除专指删除：rm/unlink/rmdir；chmod/dd/echo-写 交给其它规则定级）
    _DELETE_CMDS_RE = re.compile(r"\b(?:rm|unlink|rmdir)\b|删除|移除", re.IGNORECASE)

    @staticmethod
    def _is_home_value(path: str) -> bool:
        """赋值源是否为主目录根：~ | ~/ | $HOME | $HOME/ | /home/xxx（根本身）| 命令替换含根。

        NEW-FP 修复：只认「用户主目录根」，不认后代路径——T=/home/myuser/backup 是定向
        清理（放行），T=/home/myuser 或 T=~/ 才是删主目录根（拦）。
        命令替换形态：VAR=$(echo $HOME)、VAR=$(echo ~)——剥离 $() 内层，复用根目标判定。
        /home/xxx 分支仅认「用户目录根」本身（允许尾斜杠），后代路径不算。
        """
        p = path.strip().lower()
        # 命令替换：$(echo ~) / $(echo $HOME) / $(echo ~/x) —— 内层按根目标判定（不含子路径段）。
        if p.startswith("$(") and p.endswith(")"):
            inner = p[2:-1].strip()
            return HomeDeletionChecker._HOME_TARGET_RE.search(" " + inner) is not None
        # 绝对路径根：仅 /home/<user> 或 /home/<user>/（后代路径不算）
        if re.match(r"^/home/[^/\s]+/?$", p):
            return True
        return HomeDeletionChecker._HOME_TARGET_RE.search(" " + p) is not None

    @staticmethod
    def _home_escape_target(seg: str) -> bool:
        """NEW-FN-1: `..` 穿越段是否解析到「主目录根或以上」（删主目录根的放大形态）。

        rm -rf ~/.. == rm -rf /home/<user>/.. == 删 /home（同时删掉本机所有主目录！）；
        rm -rf $HOME/../.. == 删 /。这些用 .. 逃逸主目录删更上一级的形态，主目录根正则
        不含 .. 全部漏放。深度行走（token 化 + .. 弹栈）判定：
          - 记录行走过程中的**最低深度**（min_depth）：任何一步弹到 < 0（逃出主目录根、
            进入 /home/.. 以上，即 /home/b/c、/ 等）→ 整个目标已不在主目录内 → 拦；
          - 起点为主目录根（~/、$HOME/、/home/<user>/），最终深度 < 主目录根深度 → 拦；
          - 深度 == 主目录根深度且至少弹过一次 .. → 拦（~/.ssh/.. 弹回主目录根）；
          - 深度 > 主目录根深度且从未逃出（最低深度 ≥ 0，如 ~/a/../b）→ 定向清理，放行。
        修复（NEW-FN 审核）：`~/a/../../b/c` 深度行走 1→0→-1→0→1，中途逃出主目录根
        （到 /home 层）后又回升 —— 旧判定只看最终深度(>0) 全放，实际目标是 /home/b/c
        （删主目录外的根级内容）。记录 min_depth < 0 一并拦截；`~/a/../b`（1→0→1，未出界）
        不受影响仍放行。

        只解析主目录前缀后的首个路径 token（rm 的目标参数之一），不误伤同段其它路径。
        """
        low = seg.lower()
        # 找所有 ~ / $HOME / ${HOME} / /home/<user> 起始的主目录前缀
        for m in re.finditer(r"(?:~|(?:\$home|\$\{home\})|/home/[a-z0-9_.-]+)", low):
            prefix = m.group(0)
            end_idx = m.end()
            # 取主目录前缀后的首个 whitespace-界 token（./../etc 到下一个空白/分隔符）
            tail = low[end_idx:]
            if not tail:
                continue
            # 目标 token：主目录后紧跟的第一段路径（到空白/;|& 等分隔符）
            token = re.split(r"\s+", tail)[0].rstrip("/")
            token = token.split("&&")[0].split("||")[0].split(";")[0]
            # 清洗：剥引号、纯路径段（去空/.）；保留 ..（弹栈）
            token = token.strip("'\"")
            segments = [s for s in token.split("/") if s and s != "."]
            # 只处理含 .. 的目标（无 .. 由 _HOME_TARGET_RE 根正则覆盖那个目标）
            if not any(s == ".." for s in segments):
                continue
            depth = 0  # 主目录根 = 深度 0
            min_depth = 0  # 行走过程中的最低深度（记录中途逃逸）
            for s in segments:
                depth += -1 if s == ".." else 1
                min_depth = min(min_depth, depth)
            # 新增（NEW-FN-1 审核）：行走途中曾弹到根深度以下（逃出主目录，如 ~/a/../..）
            # → 目标已指向主目录外（/home/.. 甚至 / 级），无论最终是否回升都必须拦；
            # ~/a/../b（1→0→1，min_depth=0 未逃出）不受影响仍放行。
            if min_depth < 0:
                return True
            # 弹过栈（有 ..）且最终深度 <= 根深度 → 删主目录根或以上
            if depth <= 0:
                return True
        return False

    @staticmethod
    def _is_delete_command(seg: str) -> bool:
        """判断命令段是否为删除类命令段（段首词 rm/rmdir/unlink 或含 删除/移除）。"""
        seg = seg.lstrip()
        m = re.match(r"^(?:rm|rmdir|unlink)\b", seg, re.IGNORECASE)
        if m:
            return True
        return bool(re.search(r"删除|移除", seg))

    def check(self, a_next: dict[str, str]) -> HeuristicResult:
        action_type = a_next.get("action_type", "").lower()
        action_detail = a_next.get("action_detail", "").lower()

        # 只对 bash 类命令判定（非 shell 工具名/参数不追）
        if action_type not in ("bash", "executebash", "terminal-executebash"):
            return HeuristicResult(hit=False)

        # ① 删除类命令段 + 主目录根目标：rm -rf ~ / rm -rf $HOME / rm -rf ~/ 等（不拦 ~/子路径）。
        # NEW-FN-1: 段内主目录根目标 + `..` 穿越解析——rm -rf ~/..（删 /home）、
        # rm -rf $HOME/../..（删 /）等用 .. 逃逸主目录删更上一级的形态，主目录根正则不含
        # .. 全部漏放。深度行走：~/a/.. 解析回 ~ 根（拦）、~/a/../b 落具体子路径（放行）。
        for seg in re.split(r"&&|\|\||;|\n", action_detail):
            seg = seg.strip()
            if not seg or not self._is_delete_command(seg):
                continue
            if self._HOME_TARGET_RE.search(seg) or self._home_escape_target(seg):
                return HeuristicResult(
                    hit=True,
                    matched_patterns=["home-literal-delete"],
                    risk_level="high",
                    reason="检测到删除主目录 (~/$HOME) 操作",
                    risk_type="script_execution",
                    violated_rule="home_directory_delete",
                )

        # ② 同段赋值后删除命令引用：TARGET=$HOME; rm -rf $TARGET（文章同款变量间接形态）
        assigned: dict[str, str] = {}
        for m in self._ASSIGN_RE.finditer(action_detail):
            assigned[m.group(1)] = m.group(2)
        if assigned:
            for var, path in assigned.items():
                if not self._is_home_value(path):
                    continue
                var_ref_re = re.compile(rf"(?:{re.escape(var)}|\${{{re.escape(var)}}})")
                for seg in re.split(r"&&|\|\||;|\n", action_detail):
                    seg = seg.strip()
                    if not seg or not self._is_delete_command(seg):
                        continue
                    if var_ref_re.search(seg):
                        return HeuristicResult(
                            hit=True,
                            matched_patterns=["home-assigned-var-delete"],
                            risk_level="high",
                            reason=f"检测到通过变量 {var}（={path}，主目录）执行删除",
                            risk_type="script_execution",
                            violated_rule="home_directory_delete",
                        )
        return HeuristicResult(hit=False)


class LateralMovementChecker:
    """子检测器：横向移动检测（从 L2 搬入，原为死代码，启用后归 L1）

    ssh/scp/rsync 到非本机主机即拦截。

    复用 L2 `LogicRulesChecker._check_lateral_movement`：内联脚本（python -c 等）
    里的 ssh/scp/rsync 是字面量非真调用、echo/printf 首词段是字面量，都跳过
    （NEW-FP-D），用 token 化三策略提取主机（NEW-FN-G/F/E）。避免 L1/L2 双份
    横向移动逻辑漂移导致判定不一致（曾因 L1 缺内联脚本跳过而误报 python -c 测试）。
    """

    def __init__(self, profile: "OSProfile | None" = None):
        self._profile = profile

    def check(self, a_next: dict[str, str]) -> HeuristicResult:
        # 懒加载复用 L2 检测逻辑（需 OSProfile 构造 LogicRulesChecker）
        if self._profile is None:
            from ..profiles.linux import LinuxProfile
            self._profile = LinuxProfile()
        from .logic_rules import LogicRulesChecker
        lr = LogicRulesChecker(self._profile)._check_lateral_movement(a_next)
        if not lr.hit:
            return HeuristicResult(hit=False)
        return HeuristicResult(
            hit=True,
            matched_patterns=[lr.reason],
            risk_level="medium",
            reason=lr.reason,
            risk_type="lateral_movement",
            violated_rule="lateral_movement",
        )


#: 回环 URL host 提取（M20）：http(s):// 后到首个分隔符
_LOOPBACK_URL_RE = re.compile(r"https?://([^/\s;'\"|&)]+)", re.IGNORECASE)
_LOOPBACK_HOSTS: tuple[str, ...] = tuple(_HEURISTIC_RULES.get("loopback_hosts") or ())
_HEURISTIC_TEMP_DIRS: tuple[str, ...] = tuple(_HEURISTIC_RULES.get("temp_dirs") or ())


def _all_urls_loopback(action_detail: str) -> bool:
    """命令中的所有 http(s) URL 是否均为回环地址（M20，对齐 A17 内置规则的豁免口径）。

    A17（curl -X POST 到外部地址）早已豁免 127.*/localhost/[::1]，但用户敏感动作
    规则层未同步——agent 与本机服务（审计 API/本地 LLM/本地 DB）的合法回环通信
    被用户规则误拦（M20：curl -X POST http://127.0.0.1:9090/... 命中 curl * -d *）。
    含非回环 URL 或无 URL → False（不豁免）。
    """
    hosts = _LOOPBACK_URL_RE.findall(action_detail)
    if not hosts:
        return False
    for h in hosts:
        host = h.rsplit("@", 1)[-1].split(":", 1)[0].strip("[]").lower()
        if host in _LOOPBACK_HOSTS or host.startswith("127."):
            continue
        return False
    return True


def _strip_echo_params_for_user_rules(action_detail: str) -> str:
    """M19：echo/printf 段的参数（含无引号的叙述文本）是输出文本非命令。

    `echo下面用curl localhost POST 提交数据` 是一句描述性中文——curl 在 echo 的
    参数位置（字面量），用户规则 `curl * POST *` 全文搜索把它当真命令命中 → 误拦。
    只供用户规则匹配使用（L1 危险命令扫描的 echo 剥离走 _strip_literal_text_segments，
    两层口径独立——此处剥参数本体，保留首词与重定向/管道结构）。
    """
    out = []
    for seg in _split_shell_segments(action_detail):
        # \b 词边界识别 echo/printf 首词——`echo下面用curl...`（中文无空格粘连）
        # 的首词 token 是整串粘连文本，split()[0] 识别不了，必须用 \b
        # 不用 \b：Unicode 模式下中文算 \w，「echo下面」的 o|下 之间不是边界。
        # (?![a-zA-Z0-9_]) 只排除 ASCII 词字符——echox 不剥、echo下面 剥。
        m = re.match(r"^(echo|printf)(?![a-zA-Z0-9_])\s*", seg, re.IGNORECASE)
        if m:
            head = m.group(1).lower()
            rest = seg[m.end():]
            # 分离重定向/管道：参数区 = 到第一个 > 或 | 之前（重定向目标保留）
            cut = re.search(r">+|\|", rest)
            out.append(f"{head} " + (rest[cut.start():] if cut else ""))
        else:
            out.append(seg)
    return " ".join(out)


def _user_rule_regex_variants(pattern: str) -> list[str]:
    """M05：`curl * -d *` 生成参数前置变体 `curl -d *`。

    通配规则按 re.escape 语义是**顺序敏感**的——`curl * -d *` 要求 curl 与 -d
    之间有内容，`curl -d 'x=1' http://...`（-d 在首位）失配 → 用户规则被参数
    顺序绕过（M05）。变体生成：首 token + `*` + 字面 token（curl * -d ...）
    → 把字面 token 提前、`*` 挪到尾部。只做一阶交换，控制误报面。
    """
    tokens = pattern.split()
    if len(tokens) >= 3 and tokens[1] == "*" and tokens[2] != "*":
        lead = tokens[0]
        rest = tokens[2:]
        variant = " ".join([lead] + rest)
        if not variant.endswith("*"):
            variant += " *"
        escaped = re.escape(variant).replace(r"\*", ".*")
        return [escaped]
    return []


class UserRuleMatcher:
    """子检测器：用户自定义敏感动作/工具规则匹配"""

    def __init__(self, rules_path: str | Path | None = None):
        # builtin：忽略配置里的自定义 rules_path，只用包内 user_rules.json；
        # cold：允许 rules_path 作为启动时输入，首次加载后冻结。
        if is_builtin_only():
            rules_path = None
        self._rules = self._load(rules_path)

    @staticmethod
    def _load(rules_path: str | Path | None) -> dict:
        if not is_hot_reload_enabled():
            # cold / builtin：只读一次并进程级冻结（不随文件 mtime 热加载）。
            path = Path(rules_path) if rules_path else default_rules_path()
            key = str(path)
            cached = _FROZEN_USER_RULES_CACHE.get(key)
            if cached is not None:
                return cached
            if not path.exists():
                data: dict = {"sensitive_actions": [], "sensitive_tools": []}
            else:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            _FROZEN_USER_RULES_CACHE[key] = data
            return data
        path = Path(rules_path) if rules_path else DEFAULT_RULES_PATH
        if not path.exists():
            return {"sensitive_actions": [], "sensitive_tools": []}
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def check(self, action_type: str, action_detail: str) -> HeuristicResult:
        # M19/M20 前置：bash 类命令剥 echo/printf 参数（叙述文本非命令）。
        # 注入词检测用原文（载荷语义），此处只服务用户敏感动作规则的命令位锚定。
        is_bash_like = action_type.lower() in ("bash", "executebash", "terminal-executebash")
        # M20：所有 URL 均为回环 → 跳过敏感动作规则（对齐 A17 的回环豁免口径）
        urls_all_loopback = _all_urls_loopback(action_detail)
        scan_detail = _strip_echo_params_for_user_rules(action_detail) if is_bash_like else action_detail
        # 通配符匹配敏感动作
        for rule in self._rules.get("sensitive_actions", []):
            pattern = rule.get("pattern", "").lower()
            description = rule.get("description", "")
            if not pattern:
                continue
            regex = re.escape(pattern).replace(r"\*", ".*")
            hit = re.search(regex, scan_detail) or re.search(regex, action_type)
            # M05：参数前置变体（curl -d 首位形态）
            if not hit:
                for vr in _user_rule_regex_variants(pattern):
                    if re.search(vr, scan_detail) or re.search(vr, action_type):
                        hit = True
                        break
            if hit:
                if urls_all_loopback:
                    continue  # M20：回环通信豁免（对齐 A17）
                return HeuristicResult(
                    hit=True,
                    matched_patterns=[pattern],
                    risk_level="high",
                    reason=f"命中用户敏感动作规则: {description or pattern}",
                    risk_type="sensitive_action",
                )

        # 精确匹配敏感工具名
        for tool_name in self._rules.get("sensitive_tools", []):
            if tool_name.lower() == action_type:
                return HeuristicResult(
                    hit=True,
                    matched_patterns=[tool_name],
                    risk_level="high",
                    reason=f"命中敏感工具规则: {tool_name}",
                    risk_type="sensitive_tool",
                )

        return HeuristicResult(hit=False)


def _is_chmod_tightening(action_detail: str) -> bool:
    """判断 chmod 命令是否是「权限加固」（收权）而非「权限敞开」。

    判据：chmod 的数字权限串（3-4 位八进制），other 位（末位）**无写权限**
    （bit 2 未置位，即末位为 0/1/4/5）→ 收权/加固，安全；
    other 位**有写权限**（末位为 2/3/6/7，如 777/666/707/1777）→ 权限敞开，危险。

    setuid/setgid/sticky 组合位（chmod u+s、chmod 4755 等）不在此豁免——
    它们由 chmod 危险权限规则单独管理（收权 vs 提权是两回事）。
    非 chmod 命令、或非数字权限形态（chmod +x 等）→ 返回 False（不豁免）。

    动机（NEW-FP 2026-09）：chmod 600 ~/.ssh/id_rsa 是对私钥的权限加固，
    此前被敏感路径表 deny_both 误当「访问私钥」拦截，卡死正常安全配置。
    """
    m = re.search(r"\bchmod\s+(?:-\S+\s+)*([0-7]{3,4})\b", action_detail, re.IGNORECASE)
    if not m:
        return False
    val = int(m.group(1)[-1])
    # other 位无写权限（bit 2 未置位）→ 收权
    return (val & 2) == 0


def _strip_heredoc_content(action_detail: str) -> str:
    """剥离 heredoc 文档字面量内容（<<EOF ... EOF）。

    heredoc 是传递给命令的文档正文，不是命令本身。其中的 `*`/`?`/`rm`/`删除` 等
    字样是文档内容而非真实删除操作——若不加剥离，写含 markdown 加粗（\\*\\*）、
    三元表达式（? :）、或描述性文字（含 rm）的文档时，会被 DangerousPatternChecker
    的「通配符+删除」误判为批量删除（NEW-FP：写周报文件即触发）。

    支持 <<EOF / <<-EOF / <<'EOF' / <<"EOF" 四种引号形态，匹配到行首的结束标记
    为止，替换为占位符 <<heredoc>>。
    """
    return re.sub(
        r"<<-?\s*(?:['\"]?)([A-Za-z_][A-Za-z0-9_]*)(?:['\"]?)[^\n]*\n.*?\n\s*\1\s*(?:\n|$)",
        "<<heredoc>>\n",
        action_detail,
        flags=re.DOTALL | re.MULTILINE,
    )


#: python 内联代码中的执行/IO/列举/敏感调用 —— 出现任意一个即认定 -c 代码不是纯输出，
#: 保留原文（真实威胁不漏，M07a 特征依赖此项不剥离）
_PY_EXEC_IO_RE = re.compile(
    r"os\.system|os\.popen|subprocess|eval\s*\(|exec\s*\(|__import__|open\s*\(|"
    r"socket|urllib|requests\.|shutil|os\.(?:remove|unlink|rename|makedirs?|listdir|"
    r"scandir|walk|chmod|chown|kill|environ)|iterdir|glob\s*\(|path\(",
    re.IGNORECASE,
)
#: 纯输出调用（print / stdout.write）
_PY_PRINT_RE = re.compile(r"\b(?:print|sys\.stdout\.write)\s*\(")
#: 大数字字面量（资源消耗形态，M07b 特征面 —— 含大数字的代码一律不剥）
_PY_BIGNUM_RE = re.compile(r"\d{6,}")
#: 内联解释器 -c 参数（含外层引号，非贪婪取到同引号；含转义引号/反斜杠的复杂代码不剥）
# 外层引号分支：双引号内可含单引号（print('x')），单引号内可含双引号
_PY_INLINE_C_RE = re.compile(
    r"(python(?:3(?:\.\d+)?)?|perl5?|ruby|node|php|lua)\s+(?:-[a-zA-Z]+\s+)*-c\s+(?:\"([^\"]*)\"|'([^']*)')",
    re.IGNORECASE,
)
#: 命令替换包裹的 python -c（$(python3 -c '...')）——M21：纯输出时整个 $() 降级为
#: $(<<pylit>>)，否则 A51 命令替换执行器列表（含 python3）恒命中良性 print 形态
_PY_CMD_SUBST_C_RE = re.compile(
    r"\$\(\s*(python(?:3(?:\.\d+)?)?|perl5?|ruby|node|php|lua)\s+(?:-[a-zA-Z]+\s+)*-c\s+(?:\"([^\"]*)\"|'([^']*)')\s*\)",
    re.IGNORECASE,
)


def _is_pure_print_code(code: str) -> bool:
    """-c 代码是否为「纯输出」：只做 print/stdout.write 输出与字面量/算术运算。

    含执行/IO/列举调用（os.system/open/socket/iterdir/...）→ False（真实威胁，
    保留拦截面）；含大数字字面量 → False（资源消耗形态，M07b）；含反斜杠
    （引号嵌套复杂形态）→ False（保守不剥，宁误报不漏报）。
    """
    if "\\" in code:
        return False
    if _PY_EXEC_IO_RE.search(code) or _PY_BIGNUM_RE.search(code):
        return False
    # print/stdout.write 输出 → 纯；完全无调用的赋值/算术（x=1+2）→ 也是纯字面量
    return bool(_PY_PRINT_RE.search(code)) or not re.search(r"\w+\s*\(", code)


def _strip_inline_python_literals(text: str) -> str:
    """NEW-FP-Q（M18/M21）：python -c 纯输出代码的字面量剥离。

    `python3 -c "print('chmod 777 /tmp/x')"` 的 'chmod 777 ...' 是 print 的
    字符串参数 = 被打印的字面量，不是真实命令；危险命令扫描对 -c 代码全文
    re.search 把它当真 → critical 短路误拦安全测试/示例代码类任务（M18）。
    `echo $(python3 -c 'print(1)')` 同理被 A51 命令替换执行器列表命中（M21）。

    处理（只对纯输出代码）：
    - 命令替换内（$(python3 -c '...')）→ 整个 $() 替换为 $(<<pylit>>)
      ——否则 A51 的 $( 后跟 python3 仍命中；
    - 裸 python -c '...' → -c 参数替换为 '<<pylit>>'（保留骨架）。
    非「纯输出」代码（os.system/open/iterdir/大数字等）原样保留。
    """
    def _code_of(m):
        return m.group(2) if m.group(2) is not None else m.group(3)

    def _subst_repl(m):
        if not _is_pure_print_code(_code_of(m)):
            return m.group(0)
        return "$(<<pylit>>)"

    def _c_repl(m):
        if not _is_pure_print_code(_code_of(m)):
            return m.group(0)
        q = '"' if m.group(0).rstrip().endswith('"') else "'"
        return f"{m.group(1)} -c {q}<<pylit>>{q}"

    out = _PY_CMD_SUBST_C_RE.sub(_subst_repl, text)
    out = _PY_INLINE_C_RE.sub(_c_repl, out)
    return out


#: NEW-FP-R（2026-11，xiaoO 实测误报）：非交互式密码修改家族的真实语义要求
#: 「管道/命令词出现在引号外」——`grep -E "password|passwd|secret" f` 的模式串
#: 里 `|passwd` 是正则或关系，却被 `\\|\\s*passwd\\b` 误当"管道喂密码给 passwd"。
#: 守卫：原始命中后，若剥离全部引号内容就不再命中 → 丢弃该模式命中。
#: 绕过链（has_exec_bypass_chain）不适用此守卫（引号内载荷会被执行）。
QUOTED_SAFE_PASSWORD_PATTERNS = frozenset(
    {
        r"\|\s*passwd\b",
        r"\bpasswd\s+--stdin\b",
        r"\bchpasswd\b",
    }
)


def _strip_literal_text_segments(action_detail: str) -> str:
    """NEW-FP-I: 对首词 echo/printf 的命令段剥掉引号内容（字面量参数）。

    echo/printf 是文本输出命令，其引号内参数是被打印的字面量而非真实命令——
    `echo "rm -rf /tmp"` 是打印这串文本不是执行删除。但 CommandPatternScanner
    旧实现对整个 action_detail 做正则搜索，引号内的 rm/chmod/mkfs 等危险命令
    模式被误当真实命令匹配 → 误报（NEW-FP-I）。

    修复：按 &&/||/;/换行 分段，首词是 echo/printf 的段，剥掉引号内容（字面量），
    保留引号外的重定向 `>`/`>>` 和管道 `|` 后的真实操作。这样：
    - `echo "rm -rf /tmp"` → `echo `（rm 模式不匹配，误报消除）
    - `echo "x" > /etc/passwd` → `echo  > /etc/passwd`（重定向 >/etc/ 仍匹配，真实写不漏报）
    - `rm -rf /tmp; echo done` → rm 段不剥，echo 段剥，rm 仍匹配（真实危险不漏报）
    - `echo pass | passwd` → passwd 无引号在管道后，剥后仍保留（管道注入不漏报）

    注意：重定向目标的引号路径（`echo 'x' > '~/.bashrc'` 的 `'~/.bashrc'`）
    是真实写目标不是字面量。先摘 `> 'path'` / `> "path"` 为裸路径 `> path`，
    再剥剩余引号内容，避免重定向目标被当字面量剥掉导致漏报（与 read_before_write
    的 _REDIRECT_TARGET_RE 一致）。

    旁路（NEW-FN-H 待修）：若整条命令含"写入脚本文件后执行"或"管道喂给解释器执行"
    的绕过链，不剥离 echo/printf 段——该场景真实威胁是绕过链而非字面量，保留引号
    内路径让 L1 凭据检测兜底，避免剥离后绕过链在 L1/L2 漏检（inline-09/10 依赖）。
    - inline-09: echo "cat /etc/shadow" > /tmp/x.sh && bash /tmp/x.sh（写脚本+执行）
    - inline-10: printf 'cat /etc/shadow' | bash（管道喂给解释器）
    """
    # 旁路：含"写脚本 + 后续执行"或"管道喂解释器/持久化消费者"绕过链时整条不剥离。
    # crontab/at 是"持久化消费者"：`echo '<schedule> <命令>' | crontab -` 里的内容会被
    # 写入定时任务**稍后执行**，等价于喂给解释器——剥离会把载荷当文本丢弃，导致
    # `@reboot /tmp/x.sh`、`wget ... && bash ...` 这类 cron 后门整体漏拦（2026-09 修复）。
    if has_exec_bypass_chain(action_detail):
        return action_detail
    # 按命令分隔符分段，但跳过引号内的分隔符（echo "a; b" 的 ; 在引号内不分段）
    result_parts: list[str] = []
    for seg in _split_command_segments(action_detail):
        words = seg.strip().split()
        fw = words[0].lower() if words else ""
        if fw in ("echo", "printf"):
            # NEW-FP-Q（M21）：先剥 $() 内 python -c 纯输出（echo $(python3 -c 'print(1)')），
            # 否则下面的引号剥离只剥掉代码引号、$(python3 -c ) 骨架残留仍被 A51 命中；
            # 非纯输出（os.system 等）原样保留，A51 照常拦真威胁。
            seg = _strip_inline_python_literals(seg)
            # 先摘重定向目标的引号路径为裸路径（保留真实写目标），再剥剩余引号内容
            seg_unquoted_redirect = re.sub(
                r">{1,2}\s*(['\"])([~./][^'\"]+)\1",
                lambda m: ">" + m.group(2),
                seg,
            )
            result_parts.append(re.sub(r"'[^']*'|\"[^\"]*\"", "", seg_unquoted_redirect))
        else:
            # NEW-FP-Q（M18/M21）：python -c 纯输出代码的字面量剥离（print 参数
            # 不是真实命令；$(python3 -c 'print(1)') 不算命令替换执行）。
            result_parts.append(_strip_inline_python_literals(seg))
    return "".join(result_parts)


def _normalize_shell_obfuscation(text: str) -> str:
    """折叠**语义确定**的 shell 混淆形态（对齐 TS 同名实现）。

    只做"读命令的人一定能算出结果"的等价变换，**不做需要执行才能确定的求值**：

    - **空引号拼接** `r""m -rf /` / `r''m -rf /` → `rm -rf /`
      bash 把空引号当不存在，等价。只折叠**夹在词字符之间**的空引号
      （`(?<=\\w)(?:''|"") (?=\\w)` 形态），避免动到 `a="" b` 这类赋值语句，
      把误报面压到最小。
    - **$IFS 展开** `rm$IFS-rf$IFS/` → `rm -rf /`
      默认 IFS 就是空白（空格/制表/换行），是最常见的混淆写法。

    ⚠️ 不处理 `$(echo rm)` / 反引号 / base64 —— 那些需要**执行**才能知道结果，
    静态无法确定，强行猜会带来误报。`_normalize_path_segments` 负责路径混淆
    （`//`、`/./`），两者互补。
    """
    t = re.sub(r"(?<=\w)(?:''|\"\")(?=\w)", "", text)
    # ⚠️ 大小写不敏感：analyze() 会把命令小写化，$IFS 到这时已经是 $ifs。
    t = re.sub(r"\$\{IFS\}|\$IFS", " ", t, flags=re.IGNORECASE)
    return t

def _path_scan_variants(action_detail_lower: str) -> list[str]:
    """敏感路径检查用的扫描文本变体（原文 + 深度归一化）。

    为什么需要一个**额外**变体，而不是直接改归一化本身：默认归一化刻意跳过引号内
    内容（`grep "a//b"` 的引号内是搜索模式，不是路径），这个取舍对危险命令扫描是
    对的，但对敏感路径检查会开一个口子 —— 引号内恰恰是真实路径参数：

        cat  /etc//shadow   → Deny
        cat "/etc//shadow"  → Allow   ← 只因为加了引号
        cat "~/.ssh//id_rsa" → Allow  ← 私钥

    所以敏感路径额外扫一份 `fold_quotes=True` 的变体（原文照扫，命中即命中），
    纯增量、不改动其它规则看到的文本。

    `echo "/etc//shadow"` 这类字面量不受影响：L1 会先用
    `_strip_literal_text_segments` 把 echo/printf 段的引号内容整段剥掉，
    剥完连路径都不剩，再加变体也匹配不到。
    """
    base = _strip_literal_text_segments(action_detail_lower)
    deep = _normalize_path_segments(base, fold_quotes=True)
    variants = [base]
    if deep != base:
        variants.append(deep)
    return variants


_PATH_QUOTE_TOKEN_RE = re.compile(r"__Q([0-9]+)__")
_PATH_PROTOCOL_TOKEN_RE = re.compile(r"__PROT([0-9]+)__")

#: 占位令牌批量还原阈值：少于该值逐个 str.replace 更快（C 实现，无正则引擎
#: 与回调开销），达到该值一次 re.sub 更快（避免每个编号都重新扫描全文）。
#: 实测交叉点约 8 个令牌（随文本长度浮动，取偏保守值）。
_PATH_RESTORE_BATCH_MIN_TOKENS = 8


def _restore_path_tokens(
    text: str, tokens: list[str], prefix: str, token_re: re.Pattern[str]
) -> str:
    """还原路径归一化占位令牌，按令牌数选择更快的还原策略。

    少量令牌时批量正则反而比逐个 replace 慢（少量令牌 + 含 `//` 的输入
    实测回退 1.4~1.75 倍），因此只在令牌较多时走批量正则。
    """
    if not tokens:
        return text
    if len(tokens) < _PATH_RESTORE_BATCH_MIN_TOKENS:
        for i, token in enumerate(tokens):
            text = text.replace(f"__{prefix}{i}__", token)
        return text
    return token_re.sub(lambda m: tokens[int(m.group(1))], text)


def _normalize_path_segments(text: str, fold_quotes: bool = False) -> str:
    """NORM-PATH: 折叠路径混淆段，堵路径穿越变体（对齐 CVE-2023-37274 攻击面）。

    敏感路径/危险命令匹配前，把「路径混淆」归一回真实路径，避免子串/正则漏检：
    - 连续斜杠 `//` → `/`（`cat /etc//shadow` 与 `cat /etc/shadow` 等价，应同判）
    - 单点段 `/./` → `/`（`cat /etc/./shadow` 同理）

    不做 `..` 解析（`cat ../../etc/shadow` 的 `..` 可能改变路径语义，且现有
    dangerous pattern / read_before_write 已对 `..` 穿越有兜底），只折叠无歧义的
    `//` 与 `/./`，避免过度归一化误伤。

    约束（must not break）：
    1. 跳过协议 URL 的 `//`（`curl http://x` 的 `http://` 是协议分隔，折叠成
       `http:/x` 会破坏 curl 下载/管道检测）。
    2. 默认跳过引号内内容（`grep "a//b"` 引号内是搜索模式非路径）。

    Args:
        fold_quotes: 连引号内内容一起折叠。敏感路径检查用（引号内是真实路径参数，
            `cat "/etc//shadow"` 应同判 Deny），见 `_path_scan_variants`。
    """
    # 原文中的 Q/PROT 可能与生成标记的边界拼出额外标记（如 'a' 'b'Q0'c'）。
    # 保守地保留旧还原顺序；仅检查完整的 __Q/__PROT 前缀并不足够。
    needs_legacy_restore = "Q" in text or "PROT" in text
    if not needs_legacy_restore and "//" not in text and "/./" not in text:
        return text

    # 1. 保护协议 URL 的 //（用不含 / 的令牌占位，避免被 /{2,} 折叠）
    prot_tokens: list[str] = []
    def _stash_prot(m: re.Match[str]) -> str:
        prot_tokens.append("://")
        return f"{m.group(1)}__PROT{len(prot_tokens) - 1}__"
    text = re.sub(r"\b(https?|ftp|file)://", _stash_prot, text, flags=re.IGNORECASE)
    # 2. 保护引号内内容（非路径字面量不折叠）—— fold_quotes 时跳过本步
    quote_tokens: list[str] = []
    if not fold_quotes:
        def _stash_quote(m: re.Match[str]) -> str:
            quote_tokens.append(m.group(0))
            return f"__Q{len(quote_tokens) - 1}__"
        text = re.sub(r"'[^']*'|\"[^\"]*\"", _stash_quote, text)
    # 3. 折叠非 URL 的连续斜杠与单点段
    text = re.sub(r"/{2,}", "/", text)
    text = re.sub(r"/\./", "/", text)
    # 4. 原文存在编号冲突时，保留逐次替换的兼容行为。
    if needs_legacy_restore:
        for i, quote in enumerate(quote_tokens):
            text = text.replace(f"__Q{i}__", quote)
        for i, protocol in enumerate(prot_tokens):
            text = text.replace(f"__PROT{i}__", protocol)
        return text

    # 普通输入按令牌数择优还原：少量逐个 replace、大量批量正则（避免每个编号
    # 都重新搜索全文）。引号内容可能含协议编号，因此必须先还原引号，再还原协议。
    text = _restore_path_tokens(text, quote_tokens, "Q", _PATH_QUOTE_TOKEN_RE)
    text = _restore_path_tokens(text, prot_tokens, "PROT", _PATH_PROTOCOL_TOKEN_RE)
    return text


_COMMAND_SEGMENT_TOKEN_RE = re.compile(r"['\";\n]|&&|\|\|")


def _split_command_segments(action_detail: str) -> list[str]:
    """按 &&/||/;/换行 分段，跳过引号内的分隔符。

    echo "a; b && c" 的引号内分隔符是字面量非命令分隔，不能分段——否则
    引号内 chmod/mkfs 等词会脱离 echo 段被当独立命令首词误匹配（NEW-FP-I）。
    """
    segments: list[str] = []
    start = cursor = 0
    while match := _COMMAND_SEGMENT_TOKEN_RE.search(action_detail, cursor):
        token = match.group()
        if token in ("'", '"'):
            # 保持旧状态机语义：同种引号关闭，不额外解释反斜杠转义。
            end = action_detail.find(token, match.end())
            if end < 0:
                break
            cursor = end + 1
            continue
        segments.append(action_detail[start:match.start()])
        segments.append(token)
        start = cursor = match.end()
    if start < len(action_detail):
        segments.append(action_detail[start:])
    return segments


class CommandPatternScanner:
    """子检测器：关键命令正则扫描（从 OSProfile 获取模式）

    热生效：scan 时若存在 runtime_config，按其 enabled 规则集覆盖编译列表，
    使用户在 console 关闭某条 L1 命令规则后立即生效（下次调用即不再触发）。
    runtime_config 缺失时回退到 profile 默认（__init__ 编译的 _compiled）。

    agent_ext：三方 agent 定制化规则（agent_moss.agents.AgentExtensions）。
    在通用规则（runtime_config 或 profile 默认）之后追加该 agent 的
    extra_command_patterns；通用规则先匹配命中即短路，避免重复检测。
    """

    def __init__(
        self,
        profile: "OSProfile",
        agent_ext: "AgentExtensions | None" = None,
    ):
        self._profile = profile
        self._compiled = self._compile_from_rules(profile.dangerous_commands)
        self._agent_ext = agent_ext
        # 预编译 agent_ext 的 extra_command_patterns（一次性，避免 scan 时重复编译）
        self._agent_extra_compiled: list[dict] = []
        if agent_ext and agent_ext.extra_command_patterns:
            self._agent_extra_compiled = self._compile_from_rules(
                agent_ext.extra_command_patterns
            )

    @staticmethod
    def _compile_from_rules(rules) -> list[dict]:
        """将规则列表（CommandPattern 或 runtime dict）编译为正则条目"""
        compiled = []
        for p in rules:
            pattern = p.get("pattern") if isinstance(p, dict) else p.pattern
            compiled.append({
                "pattern": pattern,
                "risk_level": p.get("risk_level") if isinstance(p, dict) else p.risk_level,
                "risk_type": p.get("risk_type") if isinstance(p, dict) else p.risk_type,
                "reason": p.get("reason") if isinstance(p, dict) else p.reason,
                "regex": re.compile(pattern, re.IGNORECASE),
            })
        return compiled

    def _get_active_rules(self) -> list[dict]:
        """获取当前生效的规则集：
        runtime_config 启用规则（热更新） > profile 默认；
        末尾追加 agent_ext.extra_command_patterns（如有）。
        """
        try:
            from ..infra.runtime_config import get_enabled_l1_command_patterns_or_default, load_runtime_config
            # 传入当前 profile 的 os_type：runtime 覆盖按平台隔离（Windows 无
            # 条目时回退 WindowsProfile，不再沿用 Linux 危险命令规则）。
            enabled = get_enabled_l1_command_patterns_or_default(
                load_runtime_config(),
                getattr(self._profile, "os_type", ""),
            )
            if enabled:
                return self._compile_from_rules(enabled) + self._agent_extra_compiled
        except Exception:
            pass
        return self._compiled + self._agent_extra_compiled

    def scan(self, action_detail: str) -> HeuristicResult:
        active = self._get_active_rules()
        # NEW-FP-I: echo/printf 是文本输出命令，其引号内参数是字面量非真实命令。
        # 旧实现对整个 action_detail 做正则搜索，echo "rm -rf /tmp" 的输出文本里
        # rm -rf 被当真实命令匹配 → 误报。修复：对首词 echo/printf 的命令段剥掉
        # 引号内容（字面量），保留引号外的重定向 > 和管道 | 后的真实操作（echo "x" > /etc/passwd
        # 的重定向仍被检测，echo pass | passwd 的管道后 passwd 仍被匹配）。非 echo/printf
        # 段（rm -rf /tmp; echo done 的 rm 段）不剥，真实危险命令不漏报。
        # NORM-PATH: 再折叠路径混淆段（//、/./），堵路径穿越变体（cat /etc//shadow 漏检）。
        scan_text = _normalize_path_segments(_strip_literal_text_segments(action_detail))
        # WIN-SEP: 同 SensitivePathChecker —— Windows 下追加分隔符归一化变体，
        # 让 `type C:/Windows/.../SAM` 这类正斜杠写法也能命中按反斜杠书写的规则。
        # 原文保留，故 `net user /add`、`https://` 等含 / 的命令模式不受影响。
        scan_texts = [scan_text]
        # SHELL-OBF：追加「确定性 shell 混淆已折叠」的变体（原文照扫，纯增量）。
        # 折叠 r""m -rf / （空引号拼接）与 rm$IFS-rf$IFS/ （$IFS 展开为空白）。
        # 不做 $(echo rm) / base64 这类需要**执行**才能确定的形态 —— 猜会带来误报。
        _deob = _normalize_shell_obfuscation(scan_text)
        if _deob != scan_text:
            scan_texts.append(_deob)
        if getattr(self._profile, "os_type", "") == "windows":
            scan_texts.append(scan_text.replace("/", "\\"))
        # ssh-keygen 生成模式豁免：生成新私钥时 -f 后的私钥路径是写目标，不应命中
        # 「访问私钥」命令正则（如 .ssh/id_rsa）。读模式（-y/-l/-p）不受豁免。
        exempt_keygen = _is_ssh_keygen_generate(action_detail)
        # NEW-FP-R：密码修改家族的命中必须经得起全量剥引号——真实语义的管道/命令词
        # 都在引号外；只在引号内出现（grep 搜索模式串）是字面量误报。绕过链例外。
        _pw_guard_off = has_exec_bypass_chain(action_detail)
        _no_quotes = None if _pw_guard_off else ALL_QUOTES_RE.sub(" ", action_detail)
        hits = [
            p for p in active
            if any(p["regex"].search(t) for t in scan_texts)
            and not (exempt_keygen and p["risk_type"] == "file_access")
            and (
                p["pattern"] not in QUOTED_SAFE_PASSWORD_PATTERNS
                or _no_quotes is None
                or p["regex"].search(_no_quotes) is not None
            )
        ]
        if not hits:
            return HeuristicResult(hit=False)

        top = max(hits, key=lambda p: _RISK_PRIORITY.get(p["risk_level"], 0))
        return HeuristicResult(
            hit=True,
            matched_patterns=[p["pattern"] for p in hits],
            risk_level=top["risk_level"],
            reason="; ".join(p["reason"] for p in hits),
            risk_type=top["risk_type"],
        )


class InjectionKeywordChecker:
    """子检测器：Prompt 注入关键词检测（从 OSProfile 获取关键词）

    热生效：check 时若存在 runtime_config，按其 enabled 关键词集覆盖，
    使用户在 console 关闭某条注入关键词后立即生效。

    agent_ext：三方 agent 定制化关键词（agent_moss.agents.AgentExtensions）。
    在通用关键词（runtime_config 或 profile 默认）之后追加该 agent 的
    extra_injection_keywords；通用关键词先匹配命中即短路。
    """

    def __init__(
        self,
        profile: "OSProfile",
        agent_ext: "AgentExtensions | None" = None,
    ):
        self._profile = profile
        self._keywords = profile.injection_keywords
        self._agent_extra_keywords: list[dict] = []
        if agent_ext and agent_ext.extra_injection_keywords:
            self._agent_extra_keywords = [
                {
                    "keyword": k.keyword,
                    "risk_level": k.risk_level,
                    "lang": k.lang,
                }
                for k in agent_ext.extra_injection_keywords
            ]

    def _get_active_keywords(self) -> list[dict]:
        """runtime_config 启用关键词（热更新） > profile 默认；
        末尾追加 agent_ext.extra_injection_keywords（如有）。
        """
        try:
            from ..infra.runtime_config import get_enabled_l1_injection_keywords_or_default, load_runtime_config
            # 同 _get_active_rules：runtime 覆盖按平台隔离
            enabled = get_enabled_l1_injection_keywords_or_default(
                load_runtime_config(),
                getattr(self._profile, "os_type", ""),
            )
            if enabled:
                return enabled + self._agent_extra_keywords
        except Exception:
            pass
        return self._keywords + self._agent_extra_keywords

    def check(self, text: str) -> HeuristicResult:
        keywords = self._get_active_keywords()
        hits = [p for p in keywords if p["keyword"].lower() in text]
        if not hits:
            return HeuristicResult(hit=False)

        top = max(hits, key=lambda p: _RISK_PRIORITY.get(p["risk_level"], 0))
        return HeuristicResult(
            hit=True,
            matched_patterns=[p["keyword"] for p in hits],
            risk_level=top["risk_level"],
            reason="; ".join(
                f"检测到注入关键词 [{p.get('lang', 'unknown')}]: {p['keyword']}"
                for p in hits
            ),
            risk_type="prompt_injection",
        )


class CustomEnvRuleChecker:
    """子检测器：AGENT_MOSS_CUSTOM_RULES 环境变量自定义规则（与 TS 版一致）"""

    def __init__(self):
        from ..infra.config import load_custom_rules
        self._rules = load_custom_rules()

    def check(self, action_type: str, action_detail: str) -> HeuristicResult:
        if not self._rules:
            return HeuristicResult(hit=False)

        command = f"{action_type}: {action_detail}"
        matched = []
        highest_severity = "low"
        _rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}

        for rule in self._rules:
            try:
                if re.search(rule["pattern"], command):
                    if rule["action"] == "Deny":
                        matched.append(f"自定义规则: {rule['pattern']}")
                        sev = rule.get("severity", "high")
                        if _rank.get(sev, 0) > _rank.get(highest_severity, 0):
                            highest_severity = sev
            except re.error:
                continue

        if matched:
            return HeuristicResult(
                hit=True,
                matched_patterns=matched,
                risk_level=highest_severity,
                reason=f"命中自定义规则: {', '.join(matched)}",
                risk_type="custom_rule",
            )
        return HeuristicResult(hit=False)


#: 命令替换/进程替换：能让"看起来只读"的命令执行任意东西
#: （`ls $(shutdown -h now)`、`` ls `kill -9 1` ``）。出现即不白名单。
_CMD_SUBSTITUTION = re.compile(r"\$\(|`|<\(")


def _split_shell_commands(command: str) -> list[str]:
    """把命令切成「命令段」列表（不含分隔符），供白名单逐段判定。

    NEW-FN-M 起委托 `logic_rules._split_shell_segments`（引号感知 + &&/||/;/换行/
    单 `|` / 单 `&` 全切 + 滤分隔符段），保持单一事实源 —— 此前的两步实现
    （先 `_split_command_segments` 引号感知切 && || ; \\n，再对每段无引号感知地
    `re.split(r"[|&]")` 补切）对引号内的 `|`/`&` 会误切（`echo "a|b"` 被拆成两段）。
    委托后引号内的 `|`/`&` 是字面量不切，行为更正确。

    ⚠️ 不要再写一个叫 `_split_command_segments` 的函数：与已有同名函数冲突时
    Python 以**后定义者**为准，会静默改掉剥离函数的分段行为 —— 曾因此把
    `df -h && rm -rf /` 拼成 `df -hrm -rf /`，危险模式 `\\brm\\s+-...` 匹配不上，
    任意复合命令里的危险命令全部漏检。命名冲突已有「剥离函数保持结构」用例守住。
    """
    return _split_shell_segments(command)


def _extract_first_command(command: str) -> str:
    """提取第一段命令（供重定向写判定等使用）"""
    segments = _split_shell_commands(command)
    return segments[0] if segments else ""


def _whitelist_tier(command: str, profile: "OSProfile") -> str:
    """判定命令能走哪一档白名单，返回 ``"full"`` / ``"readonly"`` / ``""``（不可放行）。

    **要求每一段都命中白名单**，而不是只看第一段。白名单判定作用于整条命令：
    只看首段的话，`df -h ; shutdown -h now` 会因为首段是 df 而整条放行 —— 危险
    命令特征又兜不住 shutdown/kill/sc stop 这类，等于开了个口子。同理 `|` 管道
    也要逐段看：`ps aux | xargs kill -9` 的尾段不是白名单命令，整条就不放行；
    而 `ps aux | grep nginx` 两段都是只读，照常放行。

    出现命令替换（``$(`` / 反引号 / ``<(``）一律不放行。
    """
    segments = _split_shell_commands(command)
    if not segments:
        return ""
    if any(_CMD_SUBSTITUTION.search(seg) for seg in segments):
        return ""

    full = [re.compile(p, re.IGNORECASE) for p in profile.fully_safe_commands]
    readonly = [re.compile(p, re.IGNORECASE) for p in profile.readonly_sensitive_commands]

    def hits(seg: str, patterns: list) -> bool:
        return any(p.match(seg) for p in patterns)

    if all(hits(seg, full) for seg in segments):
        return "full"
    if all(hits(seg, full) or hits(seg, readonly) for seg in segments):
        return "readonly"
    return ""


def is_fully_safe_bash_command(command: str, profile: "OSProfile") -> bool:
    """检查是否为完全安全的 bash 命令（跳过 L2 + L3）

    含真实重定向写（echo x > file / printf >> file）的不算 fully_safe——
    白名单只看首段命令（echo），会忽略 >/>> 重定向，导致
    `echo x > /tmp/existing.txt` 覆写已存在文件被白名单放行跳过 L2（Bug3）。
    复用 _is_write_operation 的重定向判定（已剥 devnull + 比较运算符 + 只读首词保护）。
    注意：heredoc/内联脚本内容中的 > 字符不应触发重定向写检测（待优化）。
    """
    if _whitelist_tier(command, profile) != "full":
        return False
    # 命中 fully_safe 首命令后，再查完整命令是否含真实重定向写
    main_cmd = _extract_first_command(command)
    if _is_write_operation(main_cmd, command, profile.write_keywords, profile):
        return False
    return True


def is_readonly_sensitive_bash_command(command: str, profile: "OSProfile") -> bool:
    """检查是否为安全但可能访问敏感路径的 bash 命令（跳过 L3，保留 L2）

    比 is_fully_safe_bash_command 宽一档：每一段命中完全安全**或**只读敏感即可
    （于是 `ls | grep x` 这种"完全安全 + 只读敏感"的管道仍能跳 L3）。
    """
    return _whitelist_tier(command, profile) in ("full", "readonly")


def is_safe_bash_command(command: str, profile: "OSProfile") -> bool:
    """检查 bash 命令是否是安全的只读操作（向后兼容）"""
    return is_fully_safe_bash_command(command, profile) or is_readonly_sensitive_bash_command(command, profile)


# 内联脚本命令检测 — 供 coordinator 判断是否需要跳过 Layer 1/2 立即拦截
_INLINE_SCRIPT_RE = re.compile(
    r"(?:^|\s)(?:python|python3|python3\.\d+|perl|perl5|ruby|jruby|mruby|node|php|lua)\s+"
    r"(?:-[a-zA-Z]*[cer][a-zA-Z]*\s+)",
    re.IGNORECASE,
)


def is_inline_script_command(action_detail: str) -> bool:
    """判断命令是否为内联脚本解释器命令（python -c, perl -e 等）"""
    return bool(_INLINE_SCRIPT_RE.search(action_detail))


# ==================== 路径事实上下文（供 L3 注入）====================
# 动机（2026-09）：allow-116（rm -rf ~/a/../b）在 L3 被以错误理由判 Deny——
# LLM 猜测「解析依赖 ~/a 是否存在」，实际词法解析是确定的（~/a/../b ≡ ~/b）。
# L3 缺少的是「词法解析结果」这一事实 + 「运行时符号链接未验证」这一不确定性标注。
# 本函数只做纯词法解析（不读文件系统、无 TOCTOU），产出结构化事实文本注入 L3 prompt。

# 触发词法解析的操作动词（删除/软链/移动/权限/覆盖——目标路径语义敏感的写类操作）
_PATH_CONTEXT_TRIGGER_RE = re.compile(
    r"(?:^|[;&|]\s*)(?:rm|rmdir|unlink|ln|mv|cp|dd|truncate|shred|chmod|chown)\b",
    re.IGNORECASE,
)

# 主目录前缀（~、$HOME、${HOME}、/home/<user>）
_HOME_PREFIX_RE = re.compile(
    r"(?:~|~(?=/)|\$HOME\b|\$\{HOME\}|/home/[a-z0-9_.-]+)",
    re.IGNORECASE,
)


def _resolve_path_tokens(segment: str) -> list[tuple[str, str]]:
    """解析单个命令段中的主目录相关路径 token，返回 [(原文, 词法解析结果)]。

    词法解析规则（纯文本，不读文件系统）：
    - ~/a/../b → ~/b（.. 弹栈，. 折叠）
    - ~ 弹栈到主目录根以下 → 标注「逃出主目录」
    - 其余 token 原样返回（无 .. 不需要解析）
    """
    out: list[tuple[str, str]] = []
    low = segment.lower()
    for m in _HOME_PREFIX_RE.finditer(low):
        end_idx = m.end()
        tail = low[end_idx:]
        if not tail or not tail[0] in ("/", " "):
            # ~ 后无 /：裸主目录，无路径段要解析
            out.append((m.group(0), m.group(0)))
            continue
        token = re.split(r"\s+", tail.strip())[0] if tail.strip() else ""
        if not token.startswith("/"):
            continue
        token = token.rstrip("/").strip("'\"")
        segments = [s for s in token.split("/") if s and s != "."]
        if not any(s == ".." for s in segments):
            continue  # 无 .. 不需要解析
        depth = 0
        kept: list[str] = []
        escaped = False
        for s in segments:
            if s == "..":
                depth -= 1
                if kept:
                    kept.pop()
                if depth < 0:
                    escaped = True
                    depth = 0  # 继续统计但标注逃逸
            else:
                depth += 1
                kept.append(s)
        resolved = "~/" + "/".join(kept) if kept else "~"
        if escaped:
            resolved += "（⚠️ .. 弹栈超出主目录根，实际目标在主目录之外）"
        out.append((m.group(0) + token, resolved))
    return out


def build_path_context(action_detail: str) -> str:
    """为含路径敏感操作的命令构建「路径事实上下文」文本（纯词法，不读文件系统）。

    产出格式（无主目录相关路径时返回空串，不注入）：
        路径解析事实（词法分析，确定）：
          - 命令段 `rm -rf ~/a/../b`：~/a/../b 词法解析为 ~/b（目标在主目录内）
        运行时未验证（供参考，不是事实）：
          - 符号链接：分析器不读文件系统，无法确认路径中的中间目录是否为符号链接；
            若中间段在执行时被替换为指向主目录外的软链，实际删除目标可能随之改变。

    设计约束：
    - 只对「写类敏感操作」触发（rm/ln/mv/cp/dd/chmod...），只读命令不注入（省 token）
    - 只解析主目录相关 token（其余路径无 ~/ 语义歧义，L1 已有 NORM-PATH 兜底）
    - 词法结论表述为「事实」，符号链接风险表述为「未验证」——不替 L3 下结论
    """
    if not _PATH_CONTEXT_TRIGGER_RE.search(action_detail):
        return ""
    # 剥字面量（echo/printf 的文本参数不是真实路径）
    stripped = _strip_literal_text_segments(action_detail)
    lines: list[str] = []
    for seg in _split_command_segments(stripped):
        resolved = _resolve_path_tokens(seg)
        for raw, lex in resolved:
            lines.append(f"- 命令段 `{seg.strip()[:60]}`：`{raw}` 词法解析为 `{lex}`")
    if not lines:
        return ""
    return (
        "## 路径解析事实（词法分析，确定性结论）\n"
        + "\n".join(lines)
        + "\n\n## 运行时未验证（供参考，非事实）\n"
        "- 分析器不读文件系统：无法确认路径中的中间目录是否为符号链接；"
        "若中间段在执行时是（或被替换为）指向主目录外的软链，实际操作目标可能随之改变。"
        "词法解析结果基于标准路径语义，不应因猜测「解析依赖某段是否存在」而否定它。"
    )


class HeuristicDetector:
    """特征匹配静态检测器 — 组合式协调器

    按优先级依次调用子检测器，支持短路返回：
    1. CustomEnvRuleChecker — AGENT_MOSS_CUSTOM_RULES 环境变量规则
    2. UserRuleMatcher — 用户敏感规则
    3. CommandPatternScanner — 关键命令正则（OS Profile 驱动）
    4. InjectionKeywordChecker — Prompt 注入关键词（OS Profile 驱动）
    5. SensitivePathChecker — 敏感路径访问检测（从 L2 搬入，含凭据边界匹配）
    6. DangerousPatternChecker — 危险操作模式检测（从 L2 搬入）
    7. LateralMovementChecker — 横向移动检测（从 L2 搬入，原死代码启用）
    """

    def __init__(
        self,
        profile: "OSProfile",
        rules_path: str | Path | None = None,
        agent_ext: "AgentExtensions | None" = None,
    ):
        self._profile = profile
        self._agent_ext = agent_ext
        self._custom_env_checker = CustomEnvRuleChecker()
        self._rule_matcher = UserRuleMatcher(rules_path)
        self._command_scanner = CommandPatternScanner(profile, agent_ext=agent_ext)
        self._injection_checker = InjectionKeywordChecker(profile, agent_ext=agent_ext)
        # 从 L2 搬入的三个静态子检测器（只看 a_next）
        self._sensitive_path_checker = SensitivePathChecker(profile, agent_ext=agent_ext)
        self._dangerous_pattern_checker = DangerousPatternChecker()
        self._home_deletion_checker = HomeDeletionChecker(profile)
        self._lateral_movement_checker = LateralMovementChecker(profile)

    def detect(
        self,
        a_next: dict[str, str],
        reason: str,
        prompt_session: str = "",
    ) -> HeuristicResult:
        """
        执行特征匹配检测。

        Args:
            a_next: 下一步动作，含 action_type 和 action_detail
            reason: 执行该动作的理由
            prompt_session: 用户原始 prompt（用于注入关键词检测）

        Returns:
            HeuristicResult: 检测结果
        """
        action_type = a_next.get("action_type", "").lower()
        action_detail = a_next.get("action_detail", "").lower()
        # 注入关键词检测**用原文 action_detail**（不过字面量剥离）：echo 引号内的
        # "ignore previous instructions" 是**载荷本体**——echo 输出会进入下游 LLM
        # 上下文，构成间接 prompt injection 通道（deny-08/177/232、agent-xiaoo-03
        # 的既有防线）。与危险命令词的「词面巧合」本质不同，不做字面量豁免
        # （2026-10 M22 复评结论：保留拦截，测试反馈的「误拦良性讨论」需产品再确认）。
        combined_text = f"{action_type} {action_detail} {reason} {prompt_session}".lower()

        # ⚠️ 这里**不再**按 action_type 整层免检。
        #
        # 旧实现在 `action_type in profile.safe_action_types`（ls/glob/list_dir/
        # count_text_length…）时直接 return 未命中，于是 L1 整层被跳过 →
        # no_high_risk=True → 工具名白名单放行：
        #     {"action_type": "glob", "action_detail": "rm -rf /"}  → Allow
        # **action_type 是调用方声明的，不能当免检依据。** 而且这套"按工具名免检"
        # 只有 Python 有，本身就是一处实现分叉（穷举语料一照就现形）。
        #
        # 去掉后不影响正当用法：`glob "*.txt"`、`list_dir /var/log`、
        # `ask_user_question "要重启吗？"` 的 detail 不含危险模式，照样 Allow；
        # 只有 detail 里真塞了危险命令才会命中。
        # 注：agent 专属白名单（rules.json builtin_safe_action_types，如
        # OpenDesk 的 memory-*）走 coordinator 且受 no_high_risk 门控，不受影响。

        # 0. 环境变量自定义规则（AGENT_MOSS_CUSTOM_RULES）
        result = self._custom_env_checker.check(action_type, action_detail)
        if result.hit:
            return result

        # 1. 用户敏感规则
        result = self._rule_matcher.check(action_type, action_detail)
        if result.hit:
            return result

        # 2. 关键命令正则
        best: HeuristicResult = self._command_scanner.scan(action_detail)

        # 3. Prompt 注入
        # 搜索/查询类工具（search-WebSearch 等）的 action_detail 是查询参数（数据载荷），
        # 不是指令。注入检测只针对指令性文本（用户 prompt / reason / 命令），
        # 排除搜索工具的 action_detail，避免 "搜索 jailbreak" 等被误判为注入攻击。
        injection_text = combined_text
        if _is_search_action_type(action_type):
            injection_text = f"{action_type} {reason} {prompt_session}".lower()
        result = self._injection_checker.check(injection_text)
        if result.hit:
            best = _merge_heuristic_hit(best, result)

        # 4. 敏感路径访问检测（从 L2 搬入）
        # 排在 safe_action_types 短路之后：glob/list_dir/ask_user_question 等纯元数据
        # 工具已在前放行；read/grep 不在 safe_action_types 中，会进此检查，
        # 凭据文件（deny_both）无论读写都拦截——与原 L2 行为一致。
        result = self._sensitive_path_checker.check(a_next)
        if result.hit:
            best = _merge_heuristic_hit(best, result)

        # 5. 危险操作模式检测（从 L2 搬入）：通配符+删除、重定向覆盖关键目录
        result = self._dangerous_pattern_checker.check(a_next)
        if result.hit:
            best = _merge_heuristic_hit(best, result)

        # 5b. 主目录删除/写改检测（NEW-FN）：rm -rf ~ / $HOME / 变量间接删主目录
        result = self._home_deletion_checker.check(a_next)
        if result.hit:
            best = _merge_heuristic_hit(best, result)

        # 6. 横向移动检测（从 L2 搬入，原死代码启用）：ssh/scp/rsync 到非本机
        result = self._lateral_movement_checker.check(a_next)
        if result.hit:
            best = _merge_heuristic_hit(best, result)

        return best
