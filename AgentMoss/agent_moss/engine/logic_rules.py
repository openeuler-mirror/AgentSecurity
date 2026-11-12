"""逻辑规则检测 (L2) — 需要 action_history / prompt_session / cwd 的规则

L2 定位：光看 a_next 不够、需要历史动作或原始 prompt 或文件系统状态的规则。
本模块的 check() 串联以下规则（短路返回）：
1. read_before_write 原则 — 写入文件前必须有读取操作（看 action_history）
2. 意图一致性检测 — 动作是否与原始 prompt 意图一致（看 prompt_session）
3. 间接文件访问检测 — 内联脚本通过目录遍历动态发现并读写文件（看 cwd）
4. 密码修改授权检测 — 非交互式密码修改必须有用户授权（看 action_history）
5. 用户/组删除授权检测 — 删除系统用户/组必须有用户授权（看 action_history）
6. 提权检测 — sudo/su/chmod u+s/setuid 无管理上下文时拦截（看 action_history）

注：敏感路径访问检测 / 危险操作模式检测 / 横向移动检测 已按"L1 只看这一步"
原则搬至 agent_moss/engine/heuristic.py 的 HeuristicDetector 子检测器
（SensitivePathChecker / DangerousPatternChecker / LateralMovementChecker）。
本模块仍保留这三个方法的原始实现（_check_sensitive_path_access /
_check_dangerous_patterns / _check_lateral_movement），供 script_content_analyzer
的脚本内容扫描和单元测试直接调用，逻辑与 L1 子检测器保持同步。
"""

import json
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..profiles.base import OSProfile
    from ..agents.base import AgentExtensions

from ..rules_loader import (
    load_heuristic_rules, load_inline, load_logic_rules, load_platform_traits,
)
from .types import LogicRuleResult

# ── 间接文件访问检测的词表：单一事实源 rules/logic_rules.json ────────────────
# 四组词原先内联在 _check_indirect_file_access 函数体里（TS 侧同样内联）。搬到
# 模块级后再进 JSON，是因为它们直接决定「拦不拦」——属于规则，不是算法。
_LOGIC_RULES = load_logic_rules()
_IFA = (_LOGIC_RULES.get("indirect_file_access") or {}) if _LOGIC_RULES else {}
_IFA_READ_KEYWORDS: tuple[str, ...] = tuple(_IFA.get("read_keywords") or ())
_IFA_WRITE_KEYWORDS: tuple[str, ...] = tuple(_IFA.get("write_keywords") or ())
_IFA_EXEC_KEYWORDS: tuple[str, ...] = tuple(_IFA.get("exec_keywords") or ())
_IFA_OPEN_KEYWORDS: tuple[str, ...] = tuple(_IFA.get("open_keywords") or ())

#: 工具名排除前缀：与 heuristic 的敏感路径排除名单是同一份，不另存。
_EXCLUDED_PREFIXES: tuple[str, ...] = tuple(
    load_heuristic_rules().get("sensitive_excluded_prefixes") or ()
)
#: 写判定豁免的非写工具前缀（**故意**比上面少一个 `skill-`，别合并）。
_NON_WRITE_TOOL_PREFIXES: tuple[str, ...] = tuple(
    _LOGIC_RULES.get("non_write_tool_prefixes") or ()
)
#: 写/删命令集合（逐段首词判定）。
_WRITE_CMDS: frozenset[str] = frozenset(_LOGIC_RULES.get("write_commands") or ())
#: 首个位置参数是源文件的命令（源在敏感目录 → 视为读取）。
_SOURCE_ARG_CMDS: frozenset[str] = frozenset(_LOGIC_RULES.get("source_arg_commands") or ())
#: 临时目录（批量删除豁免）。与 heuristic 的 L1 判定共用 heuristic_rules.json 那一份；
#: 本模块按 startswith 用，故拼上尾随斜杠。
_TEMP_DIRS: tuple[str, ...] = tuple(
    d + "/" for d in (load_heuristic_rules().get("temp_dirs") or ())
)
#: 伪文件系统前缀：写这些路径是内核控制面动作，不存在「先读内容再覆写」的语义。
_PSEUDO_FS_PREFIXES: tuple[str, ...] = ("/sys/", "/proc/", "/dev/", "/run/")

# ==================== 引号感知命令段切分（NEW-FN-M，单一事实源）====================
#: 切分器会把分隔符本身作为独立段返回，这些是分隔符段
_SEPARATOR_SEGMENTS = frozenset({"&&", "||", ";", "\n", "|", "&"})


def _split_shell_segments(command: str) -> list[str]:
    """引号感知的命令段切分：按 &&/||/;/换行/单|/单& 切段，滤掉分隔符段。

    供 L2 各「逐段判定」复用（提权/写判定/路径提取/横向移动/删除判定）。
    旧实现用裸 re.split(r"&&|\\|\\||;|\\n")——不引号感知、缺单管道：
    - `cat f |tee g` 的 tee 写段在 read_before_write 里永远看不到（NEW-FN-M，M01/M02）；
    - `echo x | sudo tee /etc/passwd` 的 sudo 段在提权判定里不可见（同族）；
    - `echo "a; rm b"` 引号内的 ; 被切段（NEW-FP-I 已在别层感知，这里对齐）。

    heuristic.py 的 `_split_shell_commands` 委托本函数（heuristic 已 import
    logic_rules，反向导入会循环），保持单一事实源。

    ⚠️ 不要写名为 `_split_command_segments` / `_split_shell_commands` 的函数：
    heuristic.py 有同名实现（后者现委托本函数），同名冲突会静默改掉对方的分段行为
    （历史事故：`df -h && rm -rf /` 被拼成 `df -hrm -rf /`，危险模式漏检）。
    """
    segments: list[str] = []
    cur: list[str] = []
    quote: str | None = None
    i = 0
    n = len(command)
    while i < n:
        ch = command[i]
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            cur.append(ch)
            i += 1
            continue
        if ch == ';' or ch == '\n':
            segments.append("".join(cur))
            segments.append(ch)
            cur = []
            i += 1
            continue
        if ch == '&':
            if i + 1 < n and command[i + 1] == '&':
                segments.append("".join(cur))
                segments.append("&&")
                cur = []
                i += 2
            else:
                segments.append("".join(cur))
                segments.append("&")
                cur = []
                i += 1
            continue
        if ch == '|':
            if i + 1 < n and command[i + 1] == '|':
                segments.append("".join(cur))
                segments.append("||")
                cur = []
                i += 2
            else:
                segments.append("".join(cur))
                segments.append("|")
                cur = []
                i += 1
            continue
        cur.append(ch)
        i += 1
    if cur:
        segments.append("".join(cur))
    return [
        s for s in (seg.strip() for seg in segments)
        if s and s not in _SEPARATOR_SEGMENTS
    ]


# ==================== 提权命令段判定（NEW-FP-J）====================
# 提权关键词改为「命令位置」判定：只有段首词是提权命令才认为存在提权意图。
# 旧逻辑对整个 action_detail 做子串匹配，grep -rn "sudo" file、awk '/sudo/'、
# echo "sudo make install" 里参数/搜索模式/字面量位置的 sudo 被误判为真实提权。
# 引号感知分段：echo "a; sudo rm" 的 ; 在引号内不分段，整段首词 echo 不触发。
def _contains_privilege_escalation(action_detail: str) -> bool:
    ad = action_detail.lower()
    for seg in _split_shell_segments(ad):
        seg = seg.strip()
        if not seg:
            continue
        parts = seg.split()
        fw = parts[0].lower() if parts else ""
        # 段首词是多数工位命令（grep/awk/find/sed/echo/printf...）时，参数是搜索模式
        # /字面量，不是提权命令。只有 sudo/su/setuid 自身，或 chmod 设 setuid 位才算。
        if fw in ("sudo", "su"):
            return True
        if fw == "setuid":
            return True
        if fw == "chmod" and re.search(r"\bu\s*\+\s*s\b", seg):
            return True
    return False

# ==================== 非交互式密码修改命令模式 ====================
def _load_l2_patterns(cat: str) -> list[str]:
    """从归一化 L2 JSON 读取某分类的 pattern 列表（单一事实源）。"""
    from ..rules_loader import load_l2
    return [p["pattern"] for p in load_l2().get(cat, [])]


# 密码修改授权模式（归一化自 rules/l2_rules.json）
PASSWORD_MODIFY_PATTERNS: list[str] = _load_l2_patterns("password_modify_consent")

# 用户/组删除命令模式（归一化自 rules/l2_rules.json）
USER_DELETION_PATTERNS: list[str] = _load_l2_patterns("user_deletion_consent")

#: 授权提问的**相关性**判定：``ask_user_question`` 的提问正文是否与本类操作相关。
#:
#: 只在提问正文命中了密码/账户类关键词时，这条提问才有资格作为授权来源。
CONSENT_TOPIC_PATTERN = re.compile(
    r"密码|口令|passwd|password|凭据|凭证|用户|账户|账号|userdel|deluser|groupdel",
    re.IGNORECASE,
)

#: 用户回答的**否定词**。命中即视为拒绝 —— 优先于肯定词判定（「不，别删」含否定）。
CONSENT_NEGATIVE_PATTERN = re.compile(
    r"(?:"
    r"否|不|别|取消|拒绝|停止|终止|算了|算了|"
    r"\bno\b|\bnope\b|\bcancel\b|\babort\b|\bstop\b|\bdeny\b|\breject\b|"
    r"\bdecline\b|\bdon'?t\b|\bdo\s+not\b"
    r")",
    re.IGNORECASE,
)

#: 用户回答的**肯定词**。否定词优先；两者都不命中 → 意图无法判定 → 不算授权。
CONSENT_AFFIRMATIVE_PATTERN = re.compile(
    r"(?:"
    r"是|好|可以|行|嗯|对|确认|同意|继续|执行|删除|删掉|移除|修改|重置|改密|"
    r"\byes\b|\by\b|\byep\b|\byeah\b|\bok\b|\bokay\b|\bconfirm(?:ed)?\b|"
    r"\bproceed\b|\bcontinue\b|\bsure\b|\bapprove\b|\baccept\b|\bagree\b|"
    r"\bdo\s+it\b|\bgo\s+ahead\b"
    r")",
    re.IGNORECASE,
)

#: **索取型**提问：agent 向用户**索取凭据/内容**（而不是征求同意）。
#:
#: 「请输入新的登录密码」这类提问，用户的回答就是密码本身（`mypassword`），
#: 不可能出现「是/好/确认」——用户提供了内容即视为配合改密。区别于确认型提问
#: （「确认删除用户 ops 吗？」），后者必须拿到肯定回答。
CONSENT_INPUT_REQUEST_PATTERN = re.compile(
    r"(?:请|输入|提供|填写|给出|告诉我).{0,8}(?:新的?)?(?:密码|口令|passwd|password)",
    re.IGNORECASE,
)

#: 授权提问必须落在**最近 N 条动作**内。
#:
#: 防「预支授权」：一小时前问过「要重启服务吗」用户答「是」，不能拿来删今天的用户。
#: 正常流程是「问 → 答 → 立刻执行」，中间隔着大量无关动作说明这条提问与本次操作无关。
#: 取最近一条 ``ask_user_question`` 判定，更早的一律不认（不做「往前翻找任意一条」）。
CONSENT_MAX_DISTANCE = 5

#: 授权时效（秒）。仅当提问与本次动作**都**带 ``called_at`` 时生效；缺任一侧则跳过
#: 时间窗，由 ``CONSENT_MAX_DISTANCE`` 兜底。可用环境变量覆盖。
CONSENT_TTL_SECONDS = 300

#: 「shell 工具」的动作类型集合。
#:
#: 与 L2 其他规则（read_before_write / 写意图判定）保持同一口径：OpenDesk 注册的
#: ``executeBash``（以及旧版 ``terminal-executeBash``）同样是 shell 工具。授权类规则
#: 只认裸 ``bash`` 时，经 AgentGate 透传的工具名会让整条规则**命中不了** ——
#: 不是「判未授权」，而是「规则根本没跑」（OpenDesk 链路实测缺陷）。
BASH_LIKE_ACTION_TYPES = ("bash", "executebash", "terminal-executebash")

#: 「向用户提问」的动作类型：标准名 + OpenDesk 注册名。
#:
#: OpenDesk 的 AskUserTool 注册名是 ``askUser``（消息里也可能带 ``interaction-`` 前缀）。
#: AgentGate 未做工具名归一化时，历史里的提问会以 ``askuser`` 出现 —— 只认
#: ``ask_user_question`` 会把真实授权判成「没问过」，用户答「是」也照样拦。
ASK_USER_ACTION_TYPES = ("ask_user_question", "askuser")


def _is_ask_user_action(action_type: str) -> bool:
    """动作类型是否为「向用户提问」。兼容裸名与 ``<ns>-askUser`` 命名空间前缀。"""
    if action_type in ASK_USER_ACTION_TYPES:
        return True
    return action_type.endswith("-askuser")

# ==================== 组合攻击链检测（combo_chain）====================
# 单步操作（创建 Flask 服务 / 端口扫描 / 读 known_hosts）各自无害，但按 kill chain
# 顺序组合（LISTEN→EXEC→SCAN→CRED）即为后渗透攻击链（参考 ChainWatch 六阶段
# kill chain arXiv 2607.19432 / 玄武实验室 Hermes 案例）。阶段 pattern 与链定义
# 归一化自 rules/l2_rules.json 的 combo_chains 段（Python/TS 共用单一事实源）。


def _load_combo_chains() -> dict:
    """加载组合链定义（单一事实源 l2_rules.json）。"""
    from ..rules_loader import load_l2
    return load_l2().get("combo_chains", {"stages": {}, "chains": []})


# 模块级缓存（编译一次，避免每次 check 重编译）
_COMBO_STAGES: dict[str, list[re.Pattern]] = {}
_COMBO_CHAINS: list[dict] = []


def _init_combo_chains() -> None:
    """初始化组合链阶段 pattern 与链定义（幂等）。"""
    global _COMBO_STAGES, _COMBO_CHAINS
    if _COMBO_STAGES:
        return
    combo = _load_combo_chains()
    _COMBO_STAGES = {
        name: [re.compile(p, re.IGNORECASE) for p in pats]
        for name, pats in combo.get("stages", {}).items()
    }
    _COMBO_CHAINS = combo.get("chains", [])


_init_combo_chains()

# ==================== 只读命令集合 ====================
# 2026-10 删除：这里曾有一份 `READ_ONLY_COMMANDS` 模块级常量，是 `profiles/*.py`
# `read_only_commands` 的**历史重复副本**（profile 化改造后已无人引用，只剩注释里
# 提到名字）。只读命中的实际来源是 `OSProfile.read_only_commands`，现读
# `rules/platform_traits.json` 的 `read_only_commands`（单一事实源）。
# 留下这些注释是因为下方多处注释仍以 "READ_ONLY_COMMANDS" 指代这个概念。

# 重定向到 /dev/null 的丢弃写法（2>/dev/null、&>/dev/null、>/dev/null）——这是丢弃输出的标准
# shell 实践，不是写文件意图，不应计入"写操作"判定。
_DEVNULL_REDIRECT_RE = re.compile(r"(?:2|&|1)?\s*>\s*/dev/null\b")

# sed 原地写统一判定（NEW-FN-P，单一事实源）：-i 及其组合位（-in/-ri）、--in-place，
# 允许中间隔其他 flag（sed -n -i）。rbw 写段判定/写操作判定/路径提取三处共用。
SED_INPLACE_RE = re.compile(r"\bsed\s+(?:-\S+\s+)*(?:-[a-zA-Z]*i[a-zA-Z]*|--in-place)\b")

# ==================== 写/删命令模式（用于写操作判定）====================
# WRITE_KEYWORDS 走子串匹配，无法可靠识别 rm/cp/dd 等命令（"rm" 会误命中 arm/form），
# 故单独用词边界正则识别这些命令出现即视为写/删意图。覆盖：删除、复制写入、重定向写入、
# 块设备写入、文件系统格式化等。
#
# 数据源 = `rules/platform_traits.json` 的 `linux.write_command_res`（逐字相同）。
# 原先这里另抄了一份完全一样的 14 条正则；TS 侧 2026-10 已删掉自己那份，这次把
# Python 的剩余副本也去掉。`profile` 缺省时才用这份 linux 兜底（生产调用点都传 profile）。
_WRITE_COMMAND_RES = [
    re.compile(str(p)) for p in (load_platform_traits("linux").get("write_command_res") or [])
]


def _match_dangerous_action(action_detail: str, action: str) -> bool:
    """匹配意图偏离检测的危险动作词。中文走子串，英文走词边界正则。

    裸 ``action in action_detail`` 会在参数/搜索模式里误报：
      - ``git log --format=`` 含 "format" → 误判"格式化磁盘"
      - grep 搜索模式 ``NON_WRITE|non_write`` 含 "write" → 误判"修改"
      - ``pip install --update`` 含 "update" → 误判"修改"
    英文词用 ``(?<![-\\w])WORD\\b``：前面不是 ``-``（排除 --format/--update 等参数形态），
    且词边界（排除 NON_WRITE 里的 write、arm 里的 rm 等）。
    """
    # 中文词（含非 ASCII）走子串匹配
    if re.search(r"[^\x00-\x7f]", action):
        return action in action_detail
    # 英文词走词边界 + 排除参数前缀
    escaped = re.escape(action)
    return bool(re.search(rf"(?<![-\w]){escaped}\b", action_detail, re.IGNORECASE))


def has_exec_bypass_chain(action_detail: str) -> bool:
    """是否含「写脚本 + 后续执行」或「管道喂解释器/持久化消费者」绕过链。

    这两种链里的引号内容是**稍后会被执行的载荷**而非字面量，任何"引号内不算"
    类守卫（heuristic 的 _strip_literal_text_segments 剥离、NEW-FP-R 引号守卫）
    都必须对它失效，否则绕过链在 L1/L2 漏检（inline-09/10 依赖）。
    """
    _exec_after = r"&&|\|\||;|\n|\|"
    return (
        re.search(r">\s*[/~]\S*\.(sh|py|pl|rb)\b", action_detail)
        and re.search(rf"(?:{_exec_after})\s*(?:bash|sh|zsh|dash|python|perl|ruby|node)", action_detail)
    ) or re.search(r"\|\s*(?:bash|sh|zsh|dash|python|perl|ruby|node|crontab|at)\b", action_detail) is not None


#: 全量剥引号内容（NEW-FP-R 引号守卫用）：剥**整条命令**的引号内容（不按首词
#: 区分），只用于判断「命中是否纯在引号内」。与 heuristic 的
#: _strip_literal_text_segments（首词 echo/printf 才剥）语义不同。
ALL_QUOTES_RE = re.compile(r"'[^']*'|\"[^\"]*\"")


def _is_write_operation(
    action_type: str,
    action_detail: str,
    write_keywords: list[str] | None = None,
    profile: "OSProfile | None" = None,
) -> bool:
    """综合判定是否为写/删操作：关键词命中 或 写/删命令命中 或（真实重定向且非只读命令）。
    统一供 _check_read_before_write 与 _check_sensitive_path_access 使用，避免两处逻辑漂移。

    Args:
        write_keywords: 写关键词（profile.write_keywords 或审计日志来源）。
        profile: 平台特征来源 —— 传入时用其 write_command_res（Windows 的
            del/copy/icacls 与 Unix 的 rm/cp 不同），缺省回退模块级 Linux 常量。
    """
    # 关键词匹配（使用传入的 write_keywords，兼容 profile 和审计日志两种来源）
    if write_keywords and any(kw in action_type or kw in action_detail for kw in write_keywords):
        return True
    # 写/删命令词边界正则匹配（按平台：profile 提供命令集，Windows 用 del/copy 等）
    write_cmds = profile.write_command_res if profile is not None else _WRITE_COMMAND_RES
    if any(rx.search(action_detail) for rx in write_cmds):
        return True
    # sed -i 原地编辑
    if SED_INPLACE_RE.search(action_detail):
        return True
    # wget/curl + -O/-o/--output 下载写入文件（无 > 重定向，旧实现漏判 → 漏报，
    # 且 wget -O ~/.bashrc URL 可写 shell 后门绕过敏感路径）。
    # 按命令段判定：首词 wget/curl 且该段含 -O/-o/--output-document/--output。
    # 排除 echo/printf 首词（echo wget -O 是字面量非命令）。
    # NEW-FP-C: -O- / --output-document=- / -o- 是 stdout（值为 -），不算文件写。
    for seg in _split_shell_segments(action_detail):
        seg = seg.strip()
        if not seg:
            continue
        parts = seg.split()
        fw = parts[0].lower() if parts else ""
        if fw in ("wget", "curl"):
            # stdout 值排除：-O- / -o- / --output-document=- / --output=- 是 stdout 非文件写
            # （- 后跟空格/行尾表示 stdout 值，非文件路径）
            is_stdout = (
                re.search(r"\s(?:-O|-o)-(?:\s|$)", seg) or
                re.search(r"\s--output-document=-(?:\s|$)", seg, re.IGNORECASE) or
                re.search(r"\s--output=-(?:\s|$)", seg, re.IGNORECASE)
            )
            if is_stdout:
                continue
            # NEW-FP-N: -o /dev/null / --output=/dev/null 是丢弃响应体只测状态码，
            # 非真实写文件（类似 - 值 stdout 排除），应排除。
            is_devnull = (
                re.search(r"\s(?:-O|--output-document|--output)\s*/dev/null(?:\s|$)", seg, re.IGNORECASE) or
                re.search(r"\s(?:-O|--output-document|--output)=/dev/null(?:\s|$)", seg, re.IGNORECASE)
            )
            if is_devnull:
                continue
            if re.search(r"\s(?:-O|--output-document|--output)(?:=|\s|$)", seg, re.IGNORECASE) or \
               re.search(r"\s-O\S", seg):
                return True
    # rsync 同步写 dest（非只读模式）——rsync src dest 默认写 dest，漏判会绕过
    # 敏感路径（rsync -a payload/ ~/.bashrc 写 shell 后门）。排除只读模式 --list-only/
    # --dry-run/-n。echo/printf 首词的字面量不算（命令位置判定）。
    for seg in _split_shell_segments(action_detail):
        seg = seg.strip()
        if not seg:
            continue
        parts = seg.split()
        fw = parts[0].lower() if parts else ""
        if fw == "rsync" and not (
            re.search(r"--list-only|--dry-run", seg)
            or re.search(r"(?<![a-zA-Z])-n(?![a-zA-Z])", seg)
        ):
            return True
    # 重定向写入：先排除 /dev/null 丢弃和比较运算符，再看是否还有真实文件重定向。
    # NEW-FN-D 修复：不再用「整条命令首词是否只读」判断——`cat in > out` 里 cat 是
    # 只读命令但其重定向目标 out 是真实写文件（覆写/追加），应判写。只读命令的「安全
    # 重定向」只指 `> /dev/null`（丢弃输出，已剥）。改为只读命令带真实文件重定向也算写。
    # fd 重定向（>&N / N>&M / 2>&1）不是写文件，用「> 后紧跟 &」排除。
    # grep/awk 搜索模式里的 > 字面量（如 grep "a>b" file）不是重定向——剥引号内容后再判。
    if ">" in action_detail:
        # 先剥掉比较运算符（>=, <=, <>, <=>, =>），避免 Python 代码里的
        # `r.get('seq',0) >= 28` 被当成重定向写（`>=` 含 `>`）。表达式非重定向。
        detail_without_compare = re.sub(r"<=>|>=|<=|<>|=>", " ", action_detail)
        detail_without_devnull = _DEVNULL_REDIRECT_RE.sub("", detail_without_compare)
        # 重定向目标可能用引号包裹：`echo x > '/tmp/file'` 或 `> "/tmp/file"`。
        # 先把「> '引号路径'」摘出来（去引号保留路径），否则下一步剥引号内容会把
        # 重定向目标路径也删掉 → 漏判写操作（漏报）。grep "a>b" 的引号内容仍会被剥。
        detail_unquoted_redirect = re.sub(
            r">{1,2}\s*(['\"])([~./][^'\"]+)\1",
            lambda m: ">" + m.group(2),
            detail_without_devnull,
        )
        # 剥掉剩余引号内内容（grep/awk 搜索模式、python -c 代码里的 > 字面量），
        # 只看引号外是否还有真实文件重定向。
        detail_without_quotes = re.sub(r"'[^']*'|\"[^\"]*\"", "", detail_unquoted_redirect)
        # 真实文件重定向：> 或 >> 后紧跟非空白、非 & 的文件目标字符。
        # `>{1,2}\s*(?!&)\S` 匹配 echo x > /file、cat in >file、sort in >> /file；
        # 排除 ls 2>&1、echo >&2（>& 紧邻或 > 后 & 是 fd 合并，非写文件）。
        # 另排除代码符号里的 >：`/>`（XML 闭合）、`->`（类型注解）、`=>`（箭头）。
        # 2026-11 实测：python heredoc 里 `<a:alpha val="100"/>` 剥引号后剩 `val=/>`，
        # 被当重定向写 → read_before_write 误判（xiaoO 生成 PPT 时被 Deny）。
        if re.search(r"(?<![/\-=>])>{1,2}\s*(?!&)\S", detail_without_quotes):
            return True
    return False


def _is_ssh_keygen_generate(action_detail: str) -> bool:
    """判断是否为 ssh-keygen「生成模式」——私钥路径是写目标（输出），非读源。

    ssh-keygen 的 -f 参数在「生成模式」（含 -t <type> 且无 -y/-l 读模式）下是**输出文件**：
    `ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519` 生成新私钥，不读取任何已有私钥内容。
    此时 -f 后的 .ssh/id_ed25519 路径不该命中 deny_both 的「读私钥」拦截（误报卡死初始化/换 key）。

    有 -y（从私钥推导公钥）/ -l（显示指纹）是**读模式**，-f 是读源，仍应拦截。
    保守：仅当命令含 -t <type> 且不含 -y/-l/-p（改密）/ -B 等读私钥内容的 flag 时判生成。
    """
    low = action_detail.lower()
    if "ssh-keygen" not in low:
        return False
    has_type = bool(re.search(r"(?:^|\s)-t\s+\S+", low))
    if not has_type:
        return False
    # 读私钥内容 / 改密 / 显示指纹 的 flag 都意味着 -f 是读源
    if re.search(r"(?:^|\s)-\S*[ylpB]\S*", low):
        return False
    return True


class _SensitivePathMatcher:
    """敏感路径匹配器：与 TS heuristic.ts pathMatches 语义对齐。

    TS 在 ROOT_SENSITIVE_PATHS 里存的内联路径可能带负向先行块（如
    `/etc/ssh/ssh_host_rsa_key(?!\\.pub)`），其 pathMatches 会把 `(?!...)` 块
    原样保留当正则，其余部分转义字面量。Python 此前 re.escape 整条路径，把
    `(?!\\.pub)` 当字面文本，导致 host key 规则永不匹配（漏报）。

    这里复刻 TS 的分段逻辑：把 `(?!块)` 拆出原样保留，其余段 re.escape，
    保证双端对同一 path 字符串的匹配语义一致。
    """

    @staticmethod
    def _escape_with_lookahead(path: str) -> str:
        """把 path 拆成 lookahead 块 + 其余段，lookahead 块原样、其余段转义后拼接。"""
        parts = re.split(r"(\(\?!.*?\))", path)
        escaped = "".join(
            part if part.startswith("(?!") else re.escape(part)
            for part in parts
        )
        return escaped

    @staticmethod
    def match(path: str, text: str) -> bool:
        """边界匹配：/ 或 . 开头路径前导用 ^|空白|/|反斜杠|引号，其余用 \\b；尾随 \\b。"""
        escaped = _SensitivePathMatcher._escape_with_lookahead(path.lower())
        if path.startswith(".") or path.startswith("/"):
            return bool(re.search(rf"(?:^|[\s/\\'\"]){escaped}\b", text))
        return bool(re.search(rf"\b{escaped}\b", text))


def _is_directory_delete_action(action_detail: str, dir_path: str) -> bool:
    """判断命令是否含「删除该目录/其下内容」意图（dir_del_only 目录级条目专用）。

    NEW-FP-1: 目录级 deny_write 条目（.ssh/.aws）若按普通「写/删都拦」语义，会把
    mkdir -p ~/.ssh、chmod 700 ~/.ssh、echo x >> ~/.ssh/known_hosts 等 SSH/AWS 目录
    初始化/权限收紧操作误拦（chmod/echo 均被 _is_write_operation 判写）。收紧为段级
    删除意图：仅当『含该目录路径的命令段』首词是删除类命令（rm/unlink/rmdir/删除/移除），
    才视为删目录。mkdir/chmod/echo/ssh-keygen 等一律放行。目录内文件细粒度读写由具体
    路径条目（.ssh/id_rsa、.aws/credentials deny_both）兜底，此处放行不产生凭据保护缺口。
    L1 SensitivePathChecker 使用本函数（从 L2 import），保证双端 L1/L2 语义一致。
    """
    low = action_detail.lower()
    dpath = dir_path.lower()
    # rm -rf /路径/.ssh / rm -rf "~/.ssh" / rm -rf ~/.ssh/* —— 删除命令 + 目录路径
    del_seg_re = re.compile(
        r"\b(?:rm|unlink|rmdir)\b[^&|;]*?" + re.escape(dpath), re.IGNORECASE
    )
    if del_seg_re.search(low):
        return True
    # 中文删除：删除 ~/.ssh / 清空 ~/.aws 目录等（删除/移除 + 目录路径）
    if re.search(r"(?:删除|移除)[^\n;|&]*?" + re.escape(dpath), low):
        return True
    # 段首删除命令（rm -rf ~/.ssh 里 rm 在段首）兜底：整条含删除命令且含目录路径
    for seg in _split_shell_segments(low):
        fw = seg.strip().split()[0] if seg.strip().split() else ""
        if fw in ("rm", "unlink", "rmdir") and dpath in seg:
            return True
    return False


def _is_archive_read_of_dir(action_detail: str, dir_path: str) -> bool:
    """判断命令是否把该目录作为「归档/复制读源」整包读取（绕过文件级凭据条目）。

    攻击面：`tar -czf out.gz ~/.ssh`、`cp -r ~/.ssh /tmp/`、`zip -r out.zip ~/.ssh`、
    `rsync -a ~/.ssh /tmp/` 等，把 deny_write 目录级条目（.ssh/.aws）作为读源
    一次性打包/复制走全部内容（含私钥/凭据）。命令文本只出现目录路径、无具体
    凭据文件名，文件级 deny_both 条目兜不住 → 必须在目录级拦截。

    只认「目录是读源」的三种归档/复制命令段（首词 tar/zip/cp/rsync），并排除
    「目录是写目标」的形态（tar -x 解压到目录、cp 目标位、rsync 目标位），
    避免误拦 ssh-keygen/ssh-copy-id/解压恢复等正常初始化操作。
    """
    low = action_detail.lower()
    dpath = dir_path.lower()
    for seg in _split_shell_segments(low):
        seg = seg.strip()
        if not seg or dpath not in seg:
            continue
        parts = seg.split()
        fw = parts[0] if parts else ""
        if fw == "zip":
            # zip 只打包（unzip 才是解压），目录参数恒为读源
            return True
        if fw == "tar":
            # -x/--extract 是解压到目录（写目标），其余（-c 打包 / -t 列出 / 默认）读源
            if re.search(r"(?:^|\s)-[a-zA-Z]*x|--extract", seg):
                continue
            return True
        if fw in ("cp", "rsync"):
            # 目录是第一个路径参数 = 源（读源）；第二个及之后 = 目标（写目标）。
            # 提取按序路径，看 dpath 是否出现在源位（非首词之后的首个路径 token）。
            seg_paths = re.findall(r"[/~][^\s;|&><'\"]*", seg)
            if seg_paths and dpath in seg_paths[0]:
                return True
    return False


class LogicRulesChecker:
    """逻辑规则检测器（从 OSProfile 获取敏感路径和关键词）

    热生效：sensitive_path / intent / password / user_deletion 检查时，若存在
    runtime_config，按其 enabled 规则集覆盖（用户在 console 关闭某条 L2 规则
    后立即生效）。runtime_config 缺失时回退 profile/模块常量默认。
    """

    def __init__(
        self,
        profile: "OSProfile",
        agent_ext: "AgentExtensions | None" = None,
    ):
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
            # 传入当前 profile 的 os_type：runtime 覆盖按平台隔离（Windows 无
            # 条目时回退 WindowsProfile 默认，不再沿用 Linux 敏感路径规则）。
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

    def _get_intent_patterns(self):
        """runtime_config 启用意图偏离模式（热更新） > profile 默认。"""
        try:
            from ..infra.runtime_config import get_enabled_l2_intent_patterns_or_default, load_runtime_config
            # 意图模式含平台特有动作词（Windows 的 del/rmdir/reg delete），
            # 必须按平台取，否则 Windows 上会拿 Linux 动作词误判。
            enabled = get_enabled_l2_intent_patterns_or_default(
                load_runtime_config(),
                getattr(self._profile, "os_type", ""),
            )
            if enabled:
                    from ..profiles.base import IntentDeviationPattern
                    return [
                        IntentDeviationPattern(
                            intent_keywords=r["intent_keywords"],
                            dangerous_actions=r["dangerous_actions"],
                            reason=r["reason"],
                        )
                        for r in enabled
                    ]
        except Exception:
            pass
        return self._profile.intent_deviation_patterns

    def _get_password_patterns(self):
        """runtime_config 启用密码修改模式（热更新） > 模块常量默认。"""
        try:
            from ..infra.runtime_config import has_runtime_config, get_enabled_l2_password_patterns_or_default, load_runtime_config
            if has_runtime_config():
                enabled = get_enabled_l2_password_patterns_or_default(load_runtime_config())
                if enabled:
                    return enabled
        except Exception:
            pass
        return PASSWORD_MODIFY_PATTERNS

    def _get_user_deletion_patterns(self):
        """runtime_config 启用用户删除模式（热更新） > 模块常量默认。"""
        try:
            from ..infra.runtime_config import has_runtime_config, get_enabled_l2_user_deletion_patterns_or_default, load_runtime_config
            if has_runtime_config():
                enabled = get_enabled_l2_user_deletion_patterns_or_default(load_runtime_config())
                if enabled:
                    return enabled
        except Exception:
            pass
        return USER_DELETION_PATTERNS

    def check(
        self,
        prompt_session: str,
        action_history: list[dict[str, object]],
        a_next: dict[str, str],
        reason: str,
        cwd: str = "",
        prompt_history: list[dict[str, object]] | None = None,
    ) -> LogicRuleResult:
        """
        执行逻辑规则检测。

        Args:
            prompt_session: 用户输入的原始 prompt
            action_history: 历史动作序列
            a_next: 下一步动作
            reason: 执行该动作的理由
            cwd: 当前工作目录（用于间接文件访问检测）
            prompt_history: 完整的交错历史 prompt（可选）。每个元素形如
                {"text": ...} 或 {"text": ..., "actions": [...]}，按时间序。
                用于意图一致性检测，避免会话中"continue"等最近词覆盖初始意图。

        Returns:
            LogicRuleResult: 检测结果
        """
        # 1. read_before_write 原则
        rbw_result = self._check_read_before_write(action_history, a_next, reason)
        if rbw_result.hit:
            return rbw_result

        # 2. 意图一致性检测
        intent_result = self._check_intent_consistency(prompt_session, a_next, prompt_history)
        if intent_result.hit:
            return intent_result

        # 注：敏感路径访问检测 / 危险操作模式检测 / 横向移动检测 已搬至 L1
        # (HeuristicDetector 的 SensitivePathChecker / DangerousPatternChecker /
        #  LateralMovementChecker)，此处不再调用。本方法仅保留需要 action_history
        # 或 prompt_session / cwd 的 L2 规则。

        # 3. 间接文件访问检测 — 内联脚本通过目录遍历动态发现并读写文件
        # 用 cwd 列出实际文件，检查是否包含敏感路径
        indirect_result = self._check_indirect_file_access(a_next, cwd=cwd)
        if indirect_result.hit:
            return indirect_result

        # 4. 密码修改授权检测
        consent_result = self._check_password_consent(action_history, a_next)
        if consent_result.hit:
            return consent_result

        # 5. 用户/组删除授权检测
        user_del_result = self._check_user_deletion_consent(action_history, a_next)
        if user_del_result.hit:
            return user_del_result

        # 6. 提权检测（原死代码，启用；放最后，不抢已有规则优先级）
        priv_result = self._check_privilege_escalation(action_history, a_next)
        if priv_result.hit:
            return priv_result

        # 7. 组合攻击链检测（combo_chain）：历史动作 + 当前动作按 kill chain 顺序
        #    组合（LISTEN→EXEC→SCAN→CRED 等）→ 拦截。单步无害，组合成链才是攻击。
        combo_result = self._check_combo_chain(action_history, a_next)
        if combo_result.hit:
            return combo_result

        return LogicRuleResult(hit=False)

    def _check_combo_chain(
        self, action_history: list[dict[str, object]], a_next: dict[str, str]
    ) -> LogicRuleResult:
        """组合攻击链检测：跨动作按 kill chain 阶段顺序组合即拦截。

        参考 ChainWatch 六阶段 MCP kill chain（arXiv 2607.19432）+ 玄武实验室
        Hermes 案例（Flask 监听 → /exec 执行 → 端口扫描 → known_hosts 凭据访问）。

        方法：
        1. 对 action_history 每个动作 + a_next 匹配阶段 pattern（LISTEN/EXEC/
           SCAN/CRED/EXFIL），得阶段标签序列。
        2. 对 l2_rules.json 每条链定义做**子序列匹配**（阶段按顺序出现即可，
           不必连续）：若 a_next 的动作补全了一条链（命中 ≥ min_stages 个阶段），
           则拦截——单步无害（只建服务/只扫描）不会触发，组合成链才触发。

        fail-closed：阶段 pattern 是特征匹配，命中链即拦，宁可多拦不可漏。
        """
        action_detail = a_next.get("action_detail", "")
        # 内联脚本命令（python -c 等）：代码内容是字符串字面量，阶段词可能只是
        # 文本（print("subprocess")），交 inline-analyzer 专门管，不在此组合判定。
        if self._INLINE_SCRIPT_RE.search(action_detail):
            return LogicRuleResult(hit=False)

        # 动作序列：历史动作（按时间序）+ 当前动作
        details: list[str] = []
        for action in action_history:
            d = str(action.get("action_detail", ""))
            if d:
                details.append(d)
        details.append(action_detail)

        # 阶段标签序列：每个动作命中哪些阶段（一个动作可命中多阶段）
        seq: list[set[str]] = []
        for d in details:
            hits: set[str] = set()
            for stage, pats in _COMBO_STAGES.items():
                if any(p.search(d) for p in pats):
                    hits.add(stage)
            seq.append(hits)

        # 子序列匹配每条链：阶段按顺序在动作序列中出现
        for chain in _COMBO_CHAINS:
            chain_stages = chain.get("stages", [])
            min_stages = chain.get("min_stages", len(chain_stages))
            if not chain_stages or min_stages <= 0:
                continue
            # 贪心子序列匹配：期望 stage_idx 在动作序列中出现
            matched = 0
            stage_idx = 0
            for hits in seq:
                if stage_idx < len(chain_stages) and chain_stages[stage_idx] in hits:
                    matched += 1
                    stage_idx += 1
                    if matched >= min_stages:
                        break
            if matched >= min_stages:
                return LogicRuleResult(
                    hit=True,
                    violated_rule=str(chain.get("id", "combo_chain")),
                    risk_level=str(chain.get("risk_level", "high")),
                    reason=str(chain.get("reason", "检测到组合攻击链")),
                    risk_type="combo_chain",
                )

        return LogicRuleResult(hit=False)

    def _check_read_before_write(
        self, action_history: list[dict[str, object]], a_next: dict[str, str], reason: str = ""
    ) -> LogicRuleResult:
        write_keywords = self._profile.write_keywords
        read_keywords = self._profile.read_keywords

        action_detail = a_next.get("action_detail", "").lower()
        action_type = a_next.get("action_type", "").lower()

        # 豁免非文件类工具前缀（仅通用基线，与 EXCLUDED_PREFIXES 一致）。
        # memory-/skill-manager-/mailbox-/app- 是数据/编排/通信工具，read_before_write 对其无意义，
        # 且工具名含 remove/update（memory-removeMemory/memory-updateUserPortrait）会命中 WRITE_KEYWORDS
        # 子串 → 误判为写。L2 层独立豁免，不再仅依赖 coordinator opendesk 白名单。
        # 不含 skill-（任意能力，coordinator 故意保留 L3）、todomgr-/planning-（opendesk 专属命名空间，
        # 经 opendesk/rules.json builtin_safe_action_types 在 coordinator 层豁免 L2+L3，不到 L2）。
        # mailbox-sendEmail/replyEmail 的外传风险由 L3 LLM 管，不归 L2 read_before_write。
        if any(action_type.startswith(p) for p in _NON_WRITE_TOOL_PREFIXES):
            return LogicRuleResult(hit=False)

        # 排除非写入类工具（filemgr 只读三件套 + 通用只读名）。
        # 只查 action_type（工具名），不查 action_detail 子串——否则复合命令里出现
        # "cat"/"head"/"tail" 等读命令词，整条命令被误当非写豁免（如 `echo x > /tmp/f; cat /tmp/g`
        # 含 "cat" 子串 → 命中豁免 → read_before_write 被跳过）。读命令的路径过滤由下方
        # exclude_paths（按命令段首词识别）处理，不靠这里的子串豁免。
        non_write_tools = {
            "ask_user_question", "glob", "grep", "list_dir", "count_text_length", "search",
            # filemgr 只读三件套（globfiles 在 platform_traits.safe_action_types 提前放行，此处兜底）
            "filemgr-globfiles", "filemgr-readfile", "filemgr-grepfiles",
            # 通用只读工具名
            "read", "read_file", "file_read", "head", "tail", "cat",
        }
        if any(t in action_type for t in non_write_tools):
            return LogicRuleResult(hit=False)

        # 豁免：系统伪文件系统写入。「读前写后」针对普通文件内容，sysfs/procfs/devfs/tracefs
        # 的写入是控制面动作（trace_marker 打点、/proc/self/... 调参），不存在「先读内容再覆写」
        # 的语义。真机实测（鸿蒙 PC，2026-10）：定向 syscall 实时研判把 trace_marker 判 high
        # 并真拦，被跟的 agent 卡死。
        # 注：本豁免只针对路径本身；`file_write` 覆写普通文件仍按 RBW 守护。

        # 写判定按工具类型分流：
        # - bash/executebash/terminal-executebash：同时匹配 action_type + action_detail
        #   （要抓 `echo > file` 重定向、shell 命令里的 rm/cp 等写意图），并补充
        #   _is_write_operation 统一判定（重定向/sed -i/rm 命令词边界）。
        # - 其他工具：只匹配 action_type，不看 action_detail 内容，**也不 fallback 调
        #   _is_write_operation**。理由：_is_write_operation 第一行对所有工具检查
        #   `kw in action_detail`，会让 filemgr-editfile 的 oldString/newString 内容含
        #   "update"/"delete"/"replace" 时误判为写（Bug2）。非 bash 工具的写意图只能从
        #   工具名体现（filemgr-writefile/editfile/searchreplace，含 write/edit/replace）；
        #   参数内容里的"更新""移除"是业务语义不是文件写语义。
        is_bash_like = action_type in ("bash", "executebash", "terminal-executebash")
        if is_bash_like:
            is_write = any(kw in action_type or kw in action_detail for kw in write_keywords)
            # 补充检测 shell 重定向写入（>、>>）、rm/cp 命令词边界、sed -i
            # 使用 _is_write_operation 统一判定，与 _check_sensitive_path_access 对齐
            if not is_write:
                is_write = _is_write_operation(action_type, action_detail, self._profile.write_keywords, self._profile)
        else:
            is_write = any(kw in action_type for kw in write_keywords)

        if not is_write:
            return LogicRuleResult(hit=False)

        # 删除/安全命令复合（无真正写命令）不触发 read_before_write。
        # read_before_write 的语义是「写文件前先读内容」，对删除不适用——删除不需要读
        # 文件字节，且删除的元数据预检（rm -rf /etc 等敏感路径、递归）由 L1 命令模式负责
        # （/tmp 清理 L1 判定安全放行，rm -rf /etc L1 拦截）。这是「rm 豁免狭义读内容」而非
        # 「跳过 RBW」——广义元数据预检仍由 L1 完成。
        # 判定：命令链中没有任何「写命令段」即跳过。写命令段 = 段首词是写命令
        # （cp/mv/install/tee/dd/truncate/mkfs/sed -i）或该段含真实重定向写。
        # 注意：chmod/chown 不在此列——它们改元数据（权限/属主）不改文件内容，
        # 「写前先读」对它们无意义，`chmod 644 /tmp/已有未读` 不应误报。
        # chmod/chown 的危险形态（chmod 777/u+s/4755 等提权、chmod /敏感路径）由 L1 专门模式
        # 和 sensitive_path 检测负责（_WRITE_COMMAND_RES 仍保留 chmod/chown 供敏感路径写判定）。
        # 这样 `rm ... && echo done`（删除 + 安全 echo）豁免，`rm /a && echo x > /b`（含重定向写）仍走 rbw，
        # `chmod 644 /tmp/x`（普通权限）豁免，`chmod u+s /tmp/x`（提权）由 L1 拦。
        if action_type in ("bash", "executebash", "terminal-executebash"):
            detail_no_compare = re.sub(r"<=>|>=|<=|<>|=>", " ", action_detail)
            detail_no_devnull = _DEVNULL_REDIRECT_RE.sub("", detail_no_compare)
            # 先摘「> '引号路径'」为裸路径（支持引号包裹的重定向目标），再剥剩余引号内容，
            # 与 _is_write_operation 的重定向判定保持一致（避免两处漂移）。
            detail_unquoted_redirect = re.sub(
                r">{1,2}\s*(['\"])([~./][^'\"]+)\1",
                lambda m: ">" + m.group(2),
                detail_no_devnull,
            )
            detail_no_quotes = re.sub(r"'[^']*'|\"[^\"]*\"", "", detail_unquoted_redirect)
            # 排除代码符号里的 >：`/>`（XML 闭合）、`->`（类型注解）、`=>`（箭头）。
            # 2026-11 实测：python heredoc 里 `<a:alpha val="100"/>` 剥引号后剩
            # `val=/>`，被当重定向写 → read_before_write 误判。
            has_redirect_write = bool(
                re.search(r"(?<![/\-=>])>{1,2}\s*(?!&)\S", detail_no_quotes)
            )
            has_write_seg = has_redirect_write
            if not has_write_seg:
                for seg in _split_shell_segments(action_detail):
                    seg = seg.strip()
                    if not seg:
                        continue
                    fw = seg.split()[0].lower() if seg.split() else ""
                    if fw in _WRITE_CMDS or SED_INPLACE_RE.search(seg):
                        has_write_seg = True
                        break
                    # wget/curl + -O/-o/--output 下载写入（无 > 重定向，需单独识别）
                    # NEW-FP-N: -o /dev/null / --output=/dev/null 是丢弃响应体只测状态码，
                    # 非真实写文件（类似 NEW-FP-C 的 - 值 stdout 排除），应排除。
                    if fw in ("wget", "curl") and (
                        re.search(r"\s(?:-O|--output-document|--output)(?:=|\s|$)", seg, re.IGNORECASE)
                        or re.search(r"\s-O\S", seg)
                    ):
                        is_devnull_out = re.search(
                            r"\s(?:-O|--output-document|--output)\s*/dev/null(?:\s|$)", seg, re.IGNORECASE
                        ) or re.search(
                            r"\s(?:-O|--output-document|--output)=/dev/null(?:\s|$)", seg, re.IGNORECASE
                        )
                        if not is_devnull_out:
                            has_write_seg = True
                            break
                    # rsync 同步写 dest（非 --list-only/--dry-run/-n 只读模式）
                    if fw == "rsync" and not (
                        re.search(r"--list-only|--dry-run", seg)
                        or re.search(r"(?<![a-zA-Z])-n(?![a-zA-Z])", seg)
                    ):
                        has_write_seg = True
                        break
            if not has_write_seg:
                return LogicRuleResult(hit=False)

        # 提取 a_next 中涉及的文件路径，过滤掉非写目标的参数路径。
        # - cd 是目录切换不是写操作，cd /path 的 /path 不应作为写目标（否则
        #   `cd /敏感路径 && ls` 被误判为对该路径写入）。
        # - 读命令（cat/head/tail/grep/find/less/more/wc/cut 等 READ_ONLY_COMMANDS）的文件
        #   参数是读取目标不是写目标，`echo x > /tmp/t1; cat /tmp/t2` 里 t2 是 cat 的读目标
        #   却会被 extract_file_paths 当写目标提取 → read_before_write 误报（Bug5）。过滤之。
        # - 写命令的源文件参数（cp/mv/install 的首个路径参数）是读取目标不是写目标，
        #   `cp /src /dst` 里 /src 是读目标不是写目标 → 误报。过滤首个路径参数。
        # - dd 的 if=/path 是输入源（读目标），of=/path 才是输出目标（写目标）。
        #   `dd if=/dev/zero of=/tmp/x` 里 if= 的 /dev/zero 是读源，必须排除，否则误报；
        #   of= 的 /tmp/x 是写目标保留（NEW-FN-A：此前 of= 路径根本提取不到 → 漏报）。
        # 逐段法（per-segment）：按 &&/||/;/换行 拆命令段，每段独立计算写目标——
        # 该段首词是 cd → 无写目标（切目录）；
        # 该段首词是只读命令（cat/grep/sort/head 等）→ 命令参数是读目标，但重定向目标
        #   （> /path / >> /path）是写目标，需提取（NEW-FN-D：此前整段 continue 把重定向
        #   目标也丢了 → `cat in > out` 漏检 out）；
        # 该段首词是 cp/mv/install → 排除该段首个路径（源文件），其余为写目标；
        # 该段首词是 dd → 排除该段 if= 路径（输入源），of= 为写目标；
        # 其他段 → 该段所有路径均为写目标。
        # 关键：排除是 per-segment 局部的，不是全局——否则 `cp /a /b && cp /b /c` 里
        # /b 既是第一段 dest（写目标）又是第二段 source（读目标），全局排除会让第一段
        # 对 /b 的覆写漏检（NEW-FN-B）。逐段计算确保 /b 在第一段仍被作为写目标检查。
        # 重定向写目标正则：> 或 >> 后紧跟文件路径（裸路径或引号包裹，排除 >& fd）。
        # 引号路径组（'...'/"..."）与裸路径组分别捕获，findall 返回非空组。
        # 先摘引号重定向目标（去引号保留路径）再剥剩余引号内容，避免 grep "a>b" 误匹配。
        _REDIRECT_TARGET_RE = re.compile(
            r">{1,2}\s*(?!&)(?:'(/[^']+)'|\"(/[^\"]+)\"|(/[^\s;|&><'\"]+))"
        )
        target_paths: list[str] = []
        for seg in _split_shell_segments(action_detail):
            seg = seg.strip()
            if not seg:
                continue
            first_word = seg.split()[0].lower() if seg.split() else ""
            if first_word == "cd":
                # 切目录，无写目标
                continue
            # NEW-FN-P（M03）：sed -i/--in-place 是原地写，不算只读段——
            # sed 在 READ_ONLY_COMMANDS 里，此前 sed -i file 的 file 被当读目标丢弃，
            # rbw 提取不到写目标（白名单挡出后仍漏拦的第二层根因）。
            if first_word == "sed" and SED_INPLACE_RE.search(seg):
                pass  # 落到下方写段提取
            elif first_word in self._profile.read_only_commands:
                # 只读命令：文件参数是读目标，但重定向目标是写目标（NEW-FN-D）。
                # 先摘引号重定向目标（去引号），再剥剩余引号内容（grep 模式），再提取目标。
                # NEW-FP-M: 先剥 /dev/null 重定向（cat f 2>/dev/null 的 /dev/null 是 stderr 丢弃
                # 非写目标），否则 _REDIRECT_TARGET_RE 把 2>/dev/null 提取为写目标误报。
                seg_unquoted = re.sub(
                    r">{1,2}\s*(['\"])([~./][^'\"]+)\1",
                    lambda m: ">" + m.group(2),
                    seg,
                )
                seg_no_devnull = _DEVNULL_REDIRECT_RE.sub("", seg_unquoted)
                seg_no_quotes = re.sub(r"'[^']*'|\"[^\"]*\"", "", seg_no_devnull)
                # findall 返回各捕获组的元组，取非空者
                redirect_targets = [
                    t[0] or t[1] or t[2]
                    for t in _REDIRECT_TARGET_RE.findall(seg_no_quotes)
                    if t[0] or t[1] or t[2]
                ]
                target_paths.extend(redirect_targets)
                continue
            seg_paths = self._profile.extract_file_paths(seg)
            # NEW-FP-N: curl/wget 的 -o /dev/null 是丢弃响应体非真实写文件，排除 /dev/null
            # 路径（extract_file_paths 会把 -o /dev/null 的 /dev/null 提取为写目标 → 误报）。
            if first_word in ("wget", "curl"):
                seg_paths = [p for p in seg_paths if p != "/dev/null"]
            if first_word in _SOURCE_ARG_CMDS:
                # 排除首个路径（源文件），其余为写目标
                if len(seg_paths) > 1:
                    target_paths.extend(seg_paths[1:])
            elif first_word == "dd":
                # dd 的 if= 是输入源（读目标），of= 是输出目标（写目标）。
                # 排除 if= 的路径，保留 of= 的路径作为写目标。
                # NEW-FP-G: of=/dev/null 是丢弃输出非真实写文件（dd if=/dev/zero
                # of=/dev/null 是丢弃测试），与重定向 >/dev/null 同语义，排除避免
                # read_before_write 误报 /dev/null。/dev/zero/urandom 同理（设备文件
                # 非真实写目标）。
                if_source_paths = set(re.findall(r"\bif=(/[^\s;|&><'\"]+)", seg))
                dev_null_targets = set(re.findall(r"\bof=(/dev/\S+)", seg))
                target_paths.extend(
                    p for p in seg_paths
                    if p not in if_source_paths and p not in dev_null_targets
                )
            else:
                # 其他段（含重定向写 echo > file、tee、truncate 等）：该段所有路径为写目标
                target_paths.extend(seg_paths)
        # 去重，并剔除伪文件系统路径（写 sysfs/procfs/devfs 是控制面动作，见豁免 2）。
        # 全部目标都在伪文件系统里时本规则无事可判。
        target_paths = [
            p for p in dict.fromkeys(target_paths)
            if not p.startswith(_PSEUDO_FS_PREFIXES)
        ]
        if not target_paths:
            return LogicRuleResult(hit=False)

        # 检查历史动作中是否有对这些路径的读取操作
        history_read_paths = set()
        for action in action_history:
            hist_detail_raw = action.get("action_detail", "") if isinstance(action, dict) else ""
            if isinstance(hist_detail_raw, dict):
                hist_detail = json.dumps(hist_detail_raw, ensure_ascii=False).lower()
            else:
                hist_detail = str(hist_detail_raw).lower()
            hist_name = action.get("name", action.get("action_type", "")).lower() if isinstance(action, dict) else ""
            is_read = any(kw in hist_name or kw in hist_detail for kw in read_keywords)
            if is_read:
                hist_paths = self._profile.extract_file_paths(hist_detail)
                history_read_paths.update(hist_paths)

        # 豁免「纯临时文件生成」写目标：`dd if=/dev/zero of=/tmp/file`（用 /dev/zero
        # 填充临时文件）是明确的 scratch 空间生成，无敏感语义（A2 定义里 /tmp 清理
        # 即实质安全），read_before_write 对其无意义，不应误报。仅豁免 dd 的
        # if=/dev/zero + of=<临时目录> 形态——`echo x > /tmp/已存在文件` 这类覆盖已有
        # 文件的写仍触发 RBW（tests 里依赖 tmp_path 验证此语义，不得放宽）。
        # 与 _check_dangerous_patterns 的 _TEMP_DIRS 保持一致。
        if re.search(r"\bdd\b", action_detail) and re.search(r"\bif=/dev/zero\b", action_detail):
            target_paths = [
                p for p in target_paths
                if not any(p.startswith(td) for td in _TEMP_DIRS)
            ]
        if not target_paths:
            return LogicRuleResult(hit=False)

        # 检查写入目标是否在已读取的路径中
        unread_paths = []
        for path in target_paths:
            if not any(
                path == rp or path.startswith(rp) or rp.startswith(path)
                for rp in history_read_paths
            ):
                # 排除新文件创建：文件不存在于磁盘时视为新建，直接放行
                # 同时检查 reason/action_detail 中是否有创建/新建关键词
                is_create = not os.path.exists(path)
                if not is_create:
                    create_keywords = ["创建", "新建", "create", "new file", "touch"]
                    is_create = any(kw in reason.lower() or kw in action_detail for kw in create_keywords)
                if not is_create:
                    unread_paths.append(path)

        if unread_paths:
            return LogicRuleResult(
                hit=True,
                violated_rule="read_before_write",
                risk_level="high",
                reason=(
                    f"违反 read_before_write 安全原则：对文件 {unread_paths[0]} 执行写入操作，"
                    f"但历史执行序列中未发现对该文件的读取操作"
                ),
                risk_type="read_before_write",
            )

        return LogicRuleResult(hit=False)

    def _check_intent_consistency(
        self,
        prompt_session: str,
        a_next: dict[str, str],
        prompt_history: list[dict[str, object]] | None = None,
    ) -> LogicRuleResult:
        # 只对 shell/文件类操作执行意图一致性检查，避免 memory-removeMemory 等
        # 非命令工具因工具名含 delete/remove 导致误报
        action_type = a_next.get("action_type", "").lower()
        action_detail = a_next.get("action_detail", "").lower()

        # 内联脚本命令（python -c / perl -e 等）跳过 intent 的 dangerousAction 词匹配。
        # 内联脚本的代码内容里的英文词（print(delete this) 的 delete）是字符串字面量，
        # 不是真实动作；词边界 (?<![-\w])delete\b 能挡 print 里的 rm（短词），但挡不住
        # delete（长词独立词）→ intent 误报（Bug4）。内联脚本的「危险」由 L1.2
        # inline-analyzer 专门管（区分字面量 vs 真实调用），intent 不重复管。
        if self._INLINE_SCRIPT_RE.search(action_detail):
            return LogicRuleResult(hit=False)
        if any(action_type.startswith(p) for p in _EXCLUDED_PREFIXES):
            return LogicRuleResult(hit=False)

        # 收集本次会话的全部意图文本（含历史 prompt，按时间序去重）。
        # 避免多轮会话里 "continue/继续" 等最近输入覆盖掉最初的读取/搜索意图而漏报。
        # 有交错 prompt_history 时优先用它；否则退化为单条 prompt_session（向后兼容）。
        intent_texts = self._collect_intent_texts(prompt_session, prompt_history)
        if not intent_texts:
            return LogicRuleResult(hit=False)

        for pattern in self._get_intent_patterns():
            # 任一历史 prompt 命中意图词即视为"存在该意图"（防"继续"覆盖漏报）
            intent_matched = any(
                kw in text
                for text in intent_texts
                for kw in pattern.intent_keywords
            )
            dangerous_matched = any(
                _match_dangerous_action(action_detail, kw)
                for kw in pattern.dangerous_actions
            )
            if intent_matched and dangerous_matched:
                return LogicRuleResult(
                    hit=True,
                    violated_rule="intent_consistency",
                    risk_level="high",
                    reason=pattern.reason,
                    risk_type="intent_deviation",
                )

        return LogicRuleResult(hit=False)

    @staticmethod
    def _collect_intent_texts(
        prompt_session: str,
        prompt_history: list[dict[str, object]] | None,
    ) -> list[str]:
        """按时间序收集本次会话的全部意图文本。

        优先交错 prompt_history，并在末尾追加单条 prompt_session
        （最近一条，可能未被 prompt_history 覆盖）。各文本 lower 化、去重、去空。
        兼容两种 prompt_history 元素格式：
          - dict: {"text": ...}（AgentGate v1 / xiaoO 的 {text, actions} 结构）
          - str: 纯文本（AgentGate v3 旧格式，无 actions）
        """
        texts: list[str] = []
        if prompt_history:
            for turn in prompt_history:
                if isinstance(turn, str):  # 纯文本格式（v3 旧格式）
                    if turn.strip():
                        texts.append(turn.lower())
                    continue
                if not isinstance(turn, dict):
                    continue
                t = turn.get("text", "")
                if isinstance(t, str) and t.strip():
                    texts.append(t.lower())
        if prompt_session and prompt_session.strip():
            texts.append(prompt_session.lower())
        # 去重保序
        seen: set[str] = set()
        deduped = []
        for t in texts:
            if t not in seen:
                seen.add(t)
                deduped.append(t)
        return deduped

    def _check_sensitive_path_access(self, a_next: dict[str, str]) -> LogicRuleResult:
        action_type = a_next.get("action_type", "").lower()
        action_detail = a_next.get("action_detail", "").lower()

        # 只对文件/命令类操作执行敏感路径检查，避免 memory-searchMemory 等
        # 非文件工具的关键词参数触发路径子串匹配误报
        if any(action_type.startswith(p) for p in _EXCLUDED_PREFIXES):
            return LogicRuleResult(hit=False)

        # 检测操作类型：读/写/其他（统一用 _is_write_operation，与 _check_read_before_write 对齐）
        is_write_op = _is_write_operation(action_type, action_detail, self._profile.write_keywords, self._profile)

        # ssh-keygen 生成模式豁免（与 L1 SensitivePathChecker 对齐）：-t <type> 生成新私钥
        # 时 -f 是写目标，不读已有私钥，不应命中 deny_both「读私钥」拦截。
        is_keygen_generate = _is_ssh_keygen_generate(action_detail)

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
            # 以 . 或 / 开头的路径，其首字符不是单词字符，\b 在它前面不构成边界
            # （空格→/ 之间没有 \b），故用 (?:^|[\s/\\]) 替代前导 \b。
            # 也兼容引号上下文：open('.env')、cat ".env" 等
            # 支持内联负向先行块（如 /etc/ssh/ssh_host_rsa_key(?!\.pub)），
            # 与 TS pathMatches 语义对齐：lookahead 块原样当正则，其余段转义。
            if deny_mode == "deny_both":
                path_match = _SensitivePathMatcher.match(path, action_detail)
            else:
                if getattr(sp, "dir_del_only", False):
                    # NEW-FP-1 审核：目录级条目（.ssh/.aws）用目录边界匹配，避免删
                    # ~/.ssh.bak / ~/.ssh_backup（主目录下独立的备份目录）因 .ssh 子串
                    # 命中误拦。与 L1 SensitivePathChecker 同源修复。前导
                    # (?:^|[\s/\\'\"]) + 尾随 (?:/|[\s'\"\\]|$)：目录名后只接受路径分隔符
                    # 或空白/引号/行尾，不接受继续拼字符（.ssh.bak 的 . 不是边界）。
                    path_match = bool(
                        re.search(
                            rf"(?:^|[\s/\\'\"]){re.escape(path)}(?:/|[\s'\"\\]|$)",
                            action_detail,
                        )
                    )
                else:
                    path_match = path in action_detail

            if not path_match and raw_path.startswith("~"):
                expanded = os.path.expanduser(raw_path)
                if expanded.lower() in action_detail:
                    path_match = True
                else:
                    home_dir = str(Path.home())
                    if expanded.startswith(home_dir):
                        rel_path = expanded[len(home_dir):]
                        if rel_path.lower() in action_detail or expanded.lower() in action_detail:
                            path_match = True

            if path_match:
                # ssh-keygen 生成模式：-f 是写目标（生成新私钥），放行。读模式不受豁免。
                if is_keygen_generate:
                    continue
                # 凭据文件：无论读写都拦截（读凭据文件同样危险）
                if deny_mode == "deny_both":
                    return LogicRuleResult(
                        hit=True,
                        violated_rule="sensitive_path_access",
                        risk_level=sp.risk_level,
                        reason=f"访问敏感路径: {sp.desc} ({sp.path})",
                        risk_type="file_access",
                        is_credential=True,
                    )
                # read_only 路径：只拦截读取操作，写入/删除放行（如 /dev/random：
                #   读取可耗尽熵池导致 TLS 阻塞（攻击向量），写入是投喂熵（增强安全））
                if deny_mode == "deny_read":
                    if is_write_op:
                        continue  # 允许写入操作（如投喂熵池）
                    return LogicRuleResult(
                        hit=True,
                        violated_rule="sensitive_path_access",
                        risk_level=sp.risk_level,
                        reason=f"读取敏感路径: {sp.desc} ({sp.path})",
                        risk_type="file_access",
                    )
                # dir_del_only 目录级条目独立于 is_write 判定（与 L1 SensitivePathChecker 对齐）：
                # 只拦「删除该目录」或「归档/复制读源整包读取」，不拦 mkdir/chmod/echo/ls/cat
                # 等正常初始化/只读/解压恢复（NEW-FP-1）。
                if getattr(sp, "dir_del_only", False):
                    if _is_directory_delete_action(action_detail, raw_path):
                        return LogicRuleResult(
                            hit=True,
                            violated_rule="sensitive_path_access",
                            risk_level=sp.risk_level,
                            reason=f"删除敏感目录: {sp.desc} ({sp.path})",
                            risk_type="file_access",
                        )
                    if _is_archive_read_of_dir(action_detail, raw_path):
                        return LogicRuleResult(
                            hit=True,
                            violated_rule="sensitive_path_access",
                            risk_level=sp.risk_level,
                            reason=f"归档/复制读取敏感目录: {sp.desc} ({sp.path})",
                            risk_type="file_access",
                        )
                    continue
                # 默认（无特殊标记）：只拦截写入/删除操作，只读访问放行
                if not is_write_op:
                    continue  # 允许读取操作
                # 写入/删除敏感路径 → 拦截
                return LogicRuleResult(
                    hit=True,
                    violated_rule="sensitive_path_access",
                    risk_level=sp.risk_level,
                    reason=f"访问敏感路径: {sp.desc} ({sp.path})",
                    risk_type="file_access",
                )

        return LogicRuleResult(hit=False)

    def _check_privilege_escalation(
        self, action_history: list[dict[str, object]], a_next: dict[str, str]
    ) -> LogicRuleResult:
        """提权检测：sudo/su/chmod u+s/setuid 无管理上下文时拦截

        判据：sudo 后跟的命令本身是合法运维命令（包管理器/服务管理）→ 直接放行，
        不要求历史先有一次 admin 操作（新会话首次 sudo apt install 是合法高频运维）。
        sudo + 非运维命令（rm/chmod/dd 等）才查历史有无 admin 上下文；
        历史也无管理上下文则视为异常提权。L1 CommandPatternScanner 已拦
        sudo+危险命令的典型组合，本规则补 sudo+非典型命令的上下文判定。
        """
        action_detail = a_next.get("action_detail", "").lower()

        # 内联脚本命令（python -c / perl -e 等）跳过提权词匹配。
        # 内联脚本的代码内容里的英文词（print("chmod u+s") 的 chmod u+s）是字符串字面量，
        # 不是真实动作；提权关键词子串匹配会误报（FP-2 变体）。内联脚本的「危险」由
        # inline-analyzer 专门管（区分字面量 vs 真实调用），提权检测不重复管。
        if self._INLINE_SCRIPT_RE.search(action_detail):
            return LogicRuleResult(hit=False)

        # NEW-FP-J: 提权关键词改为「命令位置」判定，不再对整个 action_detail 做子串匹配。
        # 旧实现 any(kw in action_detail) 会把 grep -rn "sudo" file、awk '/sudo/'、
        # echo "sudo make install" 里参数/搜索模式/字面量位置的 sudo 误判为真实提权。
        # 修复：引号感知分段，仅当段首词是提权命令（sudo/su/setuid，或 chmod+u+s setuid 位）
        # 才认为存在提权意图。grep/awk/echo 首词段的参数是搜索模式/字面量，不触发。
        if not _contains_privilege_escalation(action_detail):
            return LogicRuleResult(hit=False)

        # 注：admin 关键词曾尝试词边界 \b，但 grep apt / pip apt 里 apt 是独立词，\bapt\b
        # 仍命中，词边界无法区分"命令位置"vs"参数位置"，故暂保留子串匹配。提权漏检
        # （grep apt 误当 admin 上下文放行 sudo cat）是已知问题，待命令位置匹配专项处理。
        # ⚠️ 当前命令侧的管理关键词**不含 "sudo" 自身**（与 TS 对齐）。
        # 历史性 bug：该列表曾含 "sudo"，靠「先剥 sudo 前缀再匹配」来兜底，但剥除正则
        # 是 `\bsudo\s+`（要求 sudo 后有空白），于是 `sudo; cmd`、`sudo&&cmd`、行尾裸
        # `sudo` 都剥不掉 → 残留的 sudo 自己命中关键词 → 判为「已是管理上下文」→
        # **整条规则失效放行**。实测：`sudo; whoami` Python 放行、TS 拦截。
        # 现在直接不把 sudo 当管理命令，从根上消除自指；剥除保留只为可读性。
        admin_keywords = ["apt", "systemctl", "yum", "dnf", "pacman", "zypper", "apk"]
        # sudo 后跟的命令本身就是包管理/服务管理 → 合法运维，直接放行
        # （新会话首次 sudo apt install / sudo systemctl restart 不应被误杀）。
        detail_after_sudo = re.sub(r"^sudo\s+|&&\s*sudo\s+|\|\|\s*sudo\s+|\bsudo\s+", " ", action_detail)
        if any(kw in detail_after_sudo for kw in admin_keywords):
            return LogicRuleResult(hit=False)

        # 历史上下文侧**仍然认 sudo**（"本次会话此前用过 sudo"确实说明有管理上下文），
        # 与 TS logic-rules.ts 的历史判定一致。
        admin_context = False
        for action in action_history:
            hist_detail = str(action.get("action_detail", "")).lower()
            if any(kw in hist_detail for kw in ("sudo", *admin_keywords)):
                admin_context = True
                break

        if not admin_context:
            return LogicRuleResult(
                hit=True,
                violated_rule="privilege_escalation",
                risk_level="high",
                reason="检测到提权操作，未发现合法管理上下文",
                risk_type="privilege_escalation",
            )

        return LogicRuleResult(hit=False)

    def _check_lateral_movement(self, a_next: dict[str, str]) -> LogicRuleResult:
        """横向移动检测：ssh/scp/rsync 到非本机主机"""
        action_detail = a_next.get("action_detail", "").lower()
        action_type = a_next.get("action_type", "").lower()

        # NEW-FP-D: 内联脚本（python -c / perl -e 等）里的 ssh/scp/rsync 是字面量非真调用，
        # 跳过交 inline-analyzer 专门管（区分字面量 vs 真实调用），与 intent/privilege 一致
        if self._INLINE_SCRIPT_RE.search(action_detail):
            return LogicRuleResult(hit=False)

        # NEW-FP-D: echo/printf 首词的参数是字面量非真调用（echo ssh user@host 是打印字面量）
        # 按命令段判定：首词 echo/printf 跳过，与 _is_write_operation 的 wget/curl 字面量判定一致
        for seg in _split_shell_segments(action_detail):
            seg = seg.strip()
            if not seg:
                continue
            parts = seg.split()
            fw = parts[0].lower() if parts else ""
            if fw in ("echo", "printf"):
                continue
            if re.search(r"(?:ssh|scp|rsync)\s+", seg):
                break  # 真调用段，跳出继续后续主机提取
        else:
            # 全段都是 echo/printf 字面量，无真调用
            return LogicRuleResult(hit=False)

        if not re.search(r"(?:ssh|scp|rsync)\s+", action_detail):
            return LogicRuleResult(hit=False)

        # 提取远程主机
        # NEW-FN-G: 旧正则 (?:ssh|scp|rsync)\s+(?:-[\w]+\s+)*(\S+@\S+|\b(?!-)[\w.-]+\b)
        # 的 (?:-[\w]+\s+)* 只匹配单选项（-p）不匹配带参数值选项（-p 2222、-L 8080:...、
        # -D 1080、-e ssh），导致 ssh -p 2222 user@host 把"2222"当主机，ssh -L/R/D 把端口号
        # 当主机，rsync -e ssh 把"ssh"当主机。token 化 + 跳过 - 开头选项更可靠。
        # NEW-FP-E: bash -c/sh -c "ssh user@host" 的 user@host 被引号包裹成 "user@host"
        # 正则不匹配（" 非 \w）→ 漏报。bash -c 内联的命令是真实调用（非字面量），
        # 应检测。剥引号后再 token 化（python -c 已在上方 _INLINE_SCRIPT_RE 跳过）。
        import socket
        local_hosts = {"localhost", "127.0.0.1", "::1", "0.0.0.0", socket.gethostname().lower()}

        # 剥 token 首尾的引号（bash -c "user@host" → user@host），保留 python -c 跳过
        tokens_raw = action_detail.split()
        tokens = [t.strip("\"'") for t in tokens_raw]
        target_host = None
        host_only = None
        # 策略1：优先找 user@host 或 user@host: 模式（最可靠的主机标识，带值选项的参数
        # 值如 -L 8080:localhost:80 里的 localhost 会被 local_hosts 排除，不会误匹配）。
        for tok in tokens:
            # user@host 或 user@host:（scp/rsync 远程源/目标）
            am = re.match(r"([\w.-]+)@([\w.-]+)(:.*)?$", tok)
            if am and am.group(2).lower() not in local_hosts:
                host_only = am.group(2)
                target_host = f"{am.group(1)}@{am.group(2)}"
                break
        # 策略2：host: 模式（rsync/scp 远程路径 host:/path，无 user@）
        if host_only is None:
            for tok in tokens:
                hm = re.match(r"([\w.-]+):(/.*)?$", tok)
                if hm and hm.group(1).lower() not in local_hosts:
                    host_only = hm.group(1)
                    target_host = hm.group(1)
                    break
        # 策略3：回退到"第一个非选项 token"（ssh user@host 的 user@host 已被策略1抓；
        # 纯 ssh host 无 @ 无 : 的场景，如 ssh 10.0.0.5）。跳过 - 开头选项及其参数值。
        if host_only is None:
            # 跳过命令本身（ssh/scp/rsync）和 sudo/env 等前缀
            skip_value_opts = {"-p", "-l", "-i", "-o", "-b", "-c", "-m", "-F",
                               "-e", "-S", "-W", "-J", "-I", "-T", "-B",
                               "-L", "-R", "-D", "-E", "-M", "-O",
                               "-P", "-q"}  # rsync -e / ssh -L/-R/-D 等带值选项
            i = 0
            found_cmd = False
            while i < len(tokens):
                t = tokens[i]
                if t in ("ssh", "scp", "rsync"):
                    found_cmd = True
                    i += 1
                    continue
                if not found_cmd:
                    i += 1
                    continue
                # 跳过选项
                if t.startswith("-"):
                    # 带值选项：跳过下一个 token（-p 2222 / -e ssh / -L 8080:...）
                    # 合并形式 -p2222 不占下一个 token；-p 2222 占
                    if t in skip_value_opts and i + 1 < len(tokens):
                        i += 2
                    else:
                        i += 1
                    continue
                # 非选项 token：候选主机
                # 排除纯路径（/ 开头是本地路径非主机名，scp src 阶段）
                if t.startswith("/"):
                    i += 1
                    continue
                host_only = t.split("@")[-1]
                target_host = t
                break

        if host_only is None or host_only.lower() in local_hosts:
            return LogicRuleResult(hit=False)

        return LogicRuleResult(
            hit=True,
            violated_rule="lateral_movement",
            risk_level="medium",
            reason=f"尝试横向移动到远程主机: {target_host}",
            risk_type="lateral_movement",
        )

    def _check_dangerous_patterns(self, a_next: dict[str, str]) -> LogicRuleResult:
        action_detail = a_next.get("action_detail", "").lower()
        action_type = a_next.get("action_type", "").lower()

        if action_type in ("file_write", "file_edit"):
            return LogicRuleResult(hit=False)

        # 通配符 + 删除/修改 — 排除 /tmp 等临时目录的清理操作
        is_temp_path = any(td in action_detail for td in _TEMP_DIRS)

        if not is_temp_path and ("*" in action_detail or "?" in action_detail) and any(
            kw in action_detail for kw in ["rm ", "rm\t", "del ", "del\t", "delete", "remove ", "remove\t", "删除", "移除"]
        ):
            return LogicRuleResult(
                hit=True,
                violated_rule="dangerous_wildcard_operation",
                risk_level="high",
                reason="检测到通配符结合删除操作，可能造成批量误删",
                risk_type="script_execution",
            )

        # 重定向覆盖关键文件
        override_patterns = [r">\s*/etc/", r">\s*/boot/", r">\s*/proc/"]
        for pat in override_patterns:
            if re.search(pat, action_detail):
                return LogicRuleResult(
                    hit=True,
                    violated_rule="dangerous_redirect",
                    risk_level="critical",
                    reason="检测到重定向覆盖写入关键系统目录",
                    risk_type="file_access",
                )

        return LogicRuleResult(hit=False)

    # ==================== 内联脚本目录遍历检测 ====================
    # 内联脚本解释器 + 代码标志：python -c / perl -e / ruby -e / php -r / node -e / lua -e
    _INLINE_SCRIPT_RE = re.compile(
        r"(?:^|\s)(?:python|python3|python3\.\d+|perl|perl5|ruby|jruby|mruby|node|php|lua)\s+"
        r"(?:-[a-zA-Z]*[cer][a-zA-Z]*\s+)",
        re.IGNORECASE,
    )

    # 目录遍历关键词：复用 inline_rules.json 那一份（两处原本逐字相同）
    _DIR_TRAVERSAL_KEYWORDS = list(load_inline().get("dir_traversal_keywords") or [])

    def _check_indirect_file_access(self, a_next: dict[str, str], cwd: str = "") -> LogicRuleResult:
        """检测内联脚本通过目录遍历动态发现文件并读写的行为。

        此类命令不包含敏感路径字面量，无法被静态路径匹配检测到，
        但实际执行时可能通过 os.listdir/glob 等动态发现并访问敏感文件。

        检测到模式后，用 cwd 列出实际文件，对照敏感路径列表检查：
        - 发现敏感文件 → 直接 Deny（确定性，不走层3）
        - 无敏感文件 → 直接 Allow（确定性，不走层3）
        - cwd 无效 → 回退 medium 风险，走层3 LLM 分析

        Args:
            a_next: 下一步动作
            cwd: 当前工作目录（用于列出实际文件检查）

        Returns:
            LogicRuleResult: hit=True, risk_level="high" 时直接 Deny；
                           hit=True, risk_level="medium" 时走层3；
                           hit=False 时放行
        """
        action_detail = a_next.get("action_detail", "").lower()
        action_type = a_next.get("action_type", "").lower()

        # 只对 bash 工具中的内联脚本命令做检测
        if action_type not in ("bash", "executebash", "terminal-executebash"):
            return LogicRuleResult(hit=False)

        # 检查是否为内联脚本命令
        if not self._INLINE_SCRIPT_RE.search(action_detail):
            return LogicRuleResult(hit=False)

        # 检查是否包含目录遍历关键词
        has_traversal = any(kw in action_detail for kw in self._DIR_TRAVERSAL_KEYWORDS)
        if not has_traversal:
            return LogicRuleResult(hit=False)

        # 检查是否包含文件读写调用词（提取代码部分检测），区分读/写/执行
        # 读操作：仅凭据文件拦截（读凭据已足够危险）
        # 写操作：所有敏感文件拦截（写入破坏性更大）
        # 执行操作：所有敏感文件拦截（执行命令可做任何事）
        # 四组词见 rules/logic_rules.json 的 indirect_file_access
        # （open( 和 fopen( 默认是读模式（'r'），也可用于写；同时出现 open( +
        #  write( 时，write( 会被 _IFA_WRITE_KEYWORDS 捕获）
        _READ_KEYWORDS = _IFA_READ_KEYWORDS
        _WRITE_KEYWORDS = _IFA_WRITE_KEYWORDS
        _EXEC_KEYWORDS = _IFA_EXEC_KEYWORDS
        _OPEN_KEYWORDS = _IFA_OPEN_KEYWORDS
        from .inline_analyzer import _extract_inline_code
        code = _extract_inline_code(action_detail)
        if not code:
            return LogicRuleResult(hit=False)
        code_lower = code.lower()
        # 先检查是否有任何文件操作，没有则跳过
        has_any_op = (
            any(kw in code_lower for kw in _READ_KEYWORDS)
            or any(kw in code_lower for kw in _WRITE_KEYWORDS)
            or any(kw in code_lower for kw in _EXEC_KEYWORDS)
            or any(kw in code_lower for kw in _OPEN_KEYWORDS)
        )
        if not has_any_op:
            return LogicRuleResult(hit=False)

        # 判断操作类型
        has_write = any(kw in code_lower for kw in _WRITE_KEYWORDS)
        has_exec = any(kw in code_lower for kw in _EXEC_KEYWORDS)
        # 写/执行操作：任何敏感文件都危险
        # 只读操作：仅凭据文件危险
        block_all_sensitive = has_write or has_exec

        # 模式已命中 — 用 cwd 列出实际文件，检查敏感路径
        cwd = cwd.strip() if cwd else ""
        if cwd and os.path.isdir(cwd):
            try:
                actual_files = os.listdir(cwd)
            except Exception:
                actual_files = []
        else:
            actual_files = []

        if actual_files:
            # 从 profile 获取敏感路径列表，匹配实际文件名
            found_credential: list[str] = []
            found_sensitive: list[str] = []
            for sp in self._profile.sensitive_paths:
                raw_path = sp.path
                # 只检查文件名（去掉路径前缀）。
                # ⚠️ 必须**同时按 / 和 \ 切**：Windows 敏感路径在 rules 里是反斜杠
                # （C:\Windows\System32\config\SAM、.ssh\id_rsa），只按 "/" 切会得到
                # 整条路径字符串，永远不等于文件名 → **Windows 上恒不命中**。
                # TS 侧一直用 split(/[/\\]/).pop()，两端分叉（2026-09 实测确认）。
                base_name = raw_path.lstrip("/\\").replace("home/", "").replace("~", "")
                fname = re.split(r"[/\\]", base_name)[-1] if re.search(r"[/\\]", base_name) else base_name
                if not fname:
                    continue
                for af in actual_files:
                    if af == fname or af.lower() == fname.lower():
                        if sp.credential:
                            found_credential.append(af)
                        else:
                            found_sensitive.append(af)
                        break

            if found_credential:
                return LogicRuleResult(
                    hit=True,
                    violated_rule="indirect_file_access",
                    risk_level="high",
                    reason=(
                        f"内联脚本使用目录遍历动态发现文件并执行读写操作，"
                        f"cwd ({cwd}) 中包含凭据文件: {', '.join(found_credential)}"
                    ),
                    risk_type="file_access",
                    is_credential=True,
                )

            # 非凭据敏感文件：仅写/执行操作时拦截，只读操作不拦截
            # 因为只读非凭据文件（如 README.md）不构成危险
            if found_sensitive and block_all_sensitive:
                return LogicRuleResult(
                    hit=True,
                    violated_rule="indirect_file_access",
                    risk_level="high",
                    reason=(
                        f"内联脚本使用目录遍历动态发现文件并执行写操作，"
                        f"cwd ({cwd}) 中包含敏感文件: {', '.join(found_sensitive)}"
                    ),
                    risk_type="file_access",
                )

            # 目录中无敏感文件，安全放行
            return LogicRuleResult(hit=False)

        # cwd 无效，无法检查实际文件，回退 medium 走层3
        return LogicRuleResult(
            hit=True,
            violated_rule="indirect_file_access",
            risk_level="medium",
            reason="内联脚本使用目录遍历函数动态发现文件并执行读写操作，无法获取 cwd 实际文件列表，转层3 LLM 分析",
            risk_type="file_access",
        )

    @staticmethod
    def _consent_within_ttl(asked: dict, a_next: dict) -> bool:
        """提问与本次动作的间隔是否在 ``CONSENT_TTL_SECONDS`` 内。

        仅当两侧都带 ``called_at`` 时校验；缺任一侧（调用方未上报时间）返回 True，
        由 ``CONSENT_MAX_DISTANCE`` 的距离窗口兜底。时间格式不合法同样返回 True ——
        时间窗是增强项，不是主防线，不因解析失败额外拦截。
        """
        raw = os.getenv("AGENT_MOSS_CONSENT_TTL_SECONDS", "").strip()
        try:
            ttl = int(raw) if raw else CONSENT_TTL_SECONDS
        except ValueError:
            ttl = CONSENT_TTL_SECONDS
        if ttl <= 0:
            return True
        asked_at = str(asked.get("called_at", "") or "").strip()
        next_at = str(a_next.get("called_at", "") or "").strip()
        if not asked_at or not next_at:
            return True
        try:
            from datetime import datetime
            a = datetime.fromisoformat(asked_at.replace("Z", "+00:00"))
            b = datetime.fromisoformat(next_at.replace("Z", "+00:00"))
            return abs((b - a).total_seconds()) <= ttl
        except (ValueError, TypeError):
            return True

    def _has_valid_consent(
        self, action_history: list[dict[str, object]], a_next: dict[str, str]
    ) -> bool:
        """历史中是否存在**可采信**的用户授权。

        有效授权必须同时满足 5 条（任一条不满足即视为未授权，fail-closed）：

        1. 动作类型是 ``ask_user_question``；
        2. ``output``（用户回答）非空 —— 只提问不回答不算授权；
        3. 提问正文命中本类操作关键词（``CONSENT_TOPIC_PATTERN``）——
           「要重启服务吗」不能给删用户背书；
        4. 回答是**肯定**：否定词优先（回答「否」也曾被判为授权，实测缺陷），
           既无否定也无肯定 → 意图无法判定 → 不算授权；
        5. 提问落在最近 ``CONSENT_MAX_DISTANCE`` 条动作内，且（若带 ``called_at``）
           与本次动作间隔不超过 ``CONSENT_TTL_SECONDS``。

        ⚠️ 只看**最近一条** ``ask_user_question``，不往前翻找：正常流程是
        「问 → 答 → 立刻执行」，更早的提问与本次操作无关。旧实现遍历整个
        action_history、任意一条带 output 的提问就放行 —— 实测「用户回答『否』」
        「问『要重启服务吗』答『是』」都能过，授权形同虚设。
        """
        if not action_history:
            return False
        for action in reversed(action_history[-CONSENT_MAX_DISTANCE:]):
            if not isinstance(action, dict):
                continue
            hist_type = str(action.get("action_type", action.get("name", ""))).lower()
            if not _is_ask_user_action(hist_type):
                continue
            # 最近这条提问是唯一候选；它不合格就直接判未授权，不再往前找。
            output = str(action.get("output", "") or "").strip()
            if not output:
                return False
            question = str(action.get("action_detail", "") or "")
            if not CONSENT_TOPIC_PATTERN.search(question):
                return False
            if CONSENT_NEGATIVE_PATTERN.search(output):
                return False
            # 索取型提问（「请输入新的登录密码」）：用户提供了内容即为授权；
            # 确认型提问（「确认删除用户 ops 吗？」）：必须拿到肯定回答。
            if not CONSENT_INPUT_REQUEST_PATTERN.search(question) and not CONSENT_AFFIRMATIVE_PATTERN.search(output):
                return False
            return self._consent_within_ttl(action, a_next)
        return False

    def _check_password_consent(
        self, action_history: list[dict[str, object]], a_next: dict[str, str]
    ) -> LogicRuleResult:
        """
        密码修改授权检测：
        非交互式密码修改命令必须在 action_history 中有 ask_user_question 且用户明确确认。
        交互式 passwd（无参数）不在此列，因为 LLM 无法完成交互式输入。
        """
        action_detail = a_next.get("action_detail", "").lower()
        action_type = a_next.get("action_type", "").lower()

        # 只检测 shell 工具中的密码修改命令（executeBash 等同 bash）
        if action_type not in BASH_LIKE_ACTION_TYPES:
            return LogicRuleResult(hit=False)

        is_password_modify = any(
            re.search(p, action_detail, re.IGNORECASE) for p in self._get_password_patterns()
        )
        # NEW-FP-R：密码修改家族的命中必须经得起全量剥引号——真实语义的管道/命令词
        # 都在引号外；只在引号内出现（grep 搜索模式串里的 |passwd）是字面量误报。
        # 绕过链（写脚本+执行 / 管道喂解释器）例外：引号内载荷稍后会被执行。
        if is_password_modify and not has_exec_bypass_chain(action_detail):
            _no_quotes = ALL_QUOTES_RE.sub(" ", action_detail)
            is_password_modify = any(
                re.search(p, _no_quotes, re.IGNORECASE) for p in self._get_password_patterns()
            )
        if not is_password_modify:
            return LogicRuleResult(hit=False)

        if self._has_valid_consent(action_history, a_next):
            return LogicRuleResult(hit=False)  # 用户已明确授权，放行

        return LogicRuleResult(
            hit=True,
            violated_rule="password_modify_requires_consent",
            risk_level="high",
            reason=(
                "执行非交互式密码修改命令，但历史执行序列中未发现用户明确授权的 "
                "ask_user_question（须用户正面回答且与本次操作相关），"
                "可能存在未授权的密码修改风险"
            ),
            risk_type="consent_missing",
        )

    def _check_user_deletion_consent(
        self, action_history: list[dict[str, object]], a_next: dict[str, str]
    ) -> LogicRuleResult:
        """
        用户/组删除授权检测：
        删除系统用户/组的命令必须在 action_history 中有 ask_user_question 且用户确认了操作。
        """
        action_detail = a_next.get("action_detail", "").lower()
        action_type = a_next.get("action_type", "").lower()

        # 只检测 shell 工具中的用户删除命令（executeBash 等同 bash）
        if action_type not in BASH_LIKE_ACTION_TYPES:
            return LogicRuleResult(hit=False)

        is_user_deletion = any(
            re.search(p, action_detail, re.IGNORECASE) for p in self._get_user_deletion_patterns()
        )
        if not is_user_deletion:
            return LogicRuleResult(hit=False)

        if self._has_valid_consent(action_history, a_next):
            return LogicRuleResult(hit=False)  # 用户已明确授权，放行

        return LogicRuleResult(
            hit=True,
            violated_rule="user_deletion_requires_consent",
            risk_level="high",
            reason=(
                "执行删除系统用户命令，但历史执行序列中未发现用户明确授权的 "
                "ask_user_question（须用户正面回答且与本次操作相关），"
                "可能存在未授权的用户删除风险"
            ),
            risk_type="consent_missing",
        )
