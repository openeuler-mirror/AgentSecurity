# -*- coding: utf-8 -*-
"""场景规则判定（自包含，可随 tests 目录独立分发，零第三方依赖）。

为什么存在
----------
生成器在 `--scenario bank` 模式下，需要判定「一条命令是否会被场景规则拦截」——
用于把被 bank 目录白名单/禁 ssh 规则拦的 allow 命令移出主 allow.sh。

此判定逻辑**原样搬运自 agent_moss 包**（仓库根目录的 agent_moss/，不随 tests 分发）：
- 场景规则正则：`agent_moss/scenarios/bank/rules.json` 的 extra_command_patterns；
- 字面量豁免：`agent_moss/engine/inline_analyzer.py::is_literal_text_command`（echo/
  printf 纯文本输出里作字面量的路径不算访问）+ 其依赖的 `_DEVNULL_REDIRECT_RE`
  （`agent_moss/engine/logic_rules.py`）。

搬运原因：客户拿到的交付物只有 tests/ 目录，不含 agent_moss 包，但生成器必须用
「与引擎完全一致」的判定逻辑——故此处内嵌自包含副本。**若上游 agent_moss 改动这些
逻辑，需同步更新本文件**（grep is_literal_text_command 与 bank/rules.json 比对）。

本模块只依赖标准库 re，输出与引擎 analyze(scenario_id=…) 对 allow 命令的场景判定
一致（已用引擎逐条验证：bank 模式下 81 条主 allow 全放行、22 条白名单外路径全拦截）。
"""

import re
import shlex

# ---------------------------------------------------------------------------
# 1) 场景规则（对齐 agent_moss/scenarios/bank/rules.json 的 extra_command_patterns）
# ---------------------------------------------------------------------------
# bank：访问 /home/sandbox、/opt/sandbox、/tmp 之外的路径 → 拦；用 .. 逃逸 → 拦。
#
# ⚠️ 2026-09 客户实测暴露的一批绕过（招行沙箱），改法如下：
#   1) 前缀判定不能"枚举路径前面能是什么字符"（那是开集）—— 旧写法
#      `(?:^|[;\s>&|@'"])` 只覆盖 8 个字符，实测 33 个标点里有 **25 个**能绕过
#      （`X=/etc`、`cat</etc/passwd`、`(cd /etc)` …）。改成用负向回顾判定
#      "这里是路径 token 的起点"：`(?<![\w.:~/-])`。
#   2) 白名单前缀 + 回溯逃逸：`/tmp/../etc` 因为开头是 /tmp 被 lookahead 跳过 →
#      放行。补一条「路径里夹 `..` 一律拦」的分支。
#   3) 相对路径 `..` 逃逸（`cd ..`、`cat ../etc/passwd`）此前完全没覆盖。
#   4) 注意排除 `://`（URL）—— 否则 `curl http://x` 会被当成路径访问（误报）。
# 注意：模式里**不能留空格/换行**（Python re 非 VERBOSE 下是字面量，会破坏匹配）。
_BANK_PATH_PATTERN = re.compile(
    '(?<![\\w.:~/-])/(?:(?!home/sandbox(?:\\s|/|$)|opt/sandbox(?:\\s|/|$)|tmp(?:\\s|/|$)|dev/null(?=[\\s;&|<>)"\'`]|$)|dev/stdout(?=[\\s;&|<>)"\'`]|$)|dev/stderr(?=[\\s;&|<>)"\'`]|$)|(?:usr/)?(?:local/)?s?bin/(?!.*\\.\\.)[^\\s;&|>"\'`]*(?=[\\s;&|<>)"\'`]|$))[^\\s;&|>"\'`]*|[^\\s;&|>"\'`]*/\\.\\.[^\\s;&|>"\'`]*)|(?:^|[\\s;&|<>=(`\'"!/])(?:\\.\\./|\\.\\.(?=\\s|$|[;&|]))|(?:^|[\\s;&|<>=(`\'"!])~(?!sandbox\\b)[\\w-]+',
    re.IGNORECASE,
)
# bank：命令的**绝对路径写法**（`/bin/ls`、`/usr/bin/python3`）是正常执行，不算路径访问
# —— 已在 _BANK_PATH_PATTERN 的白名单里豁免。但把它们当**写目标**仍然拦（否则
# `cp /tmp/x /bin/evil` 就漏了）。这条只覆盖写入形态，`cat /bin/ls` 这类读取不拦。
_BANK_WRITE_BIN_PATTERN = re.compile(
    '(?:^|[\\s;&|(])(?:>|>>|\\btee\\b|\\bcp\\b|\\bmv\\b|\\binstall\\b|\\bln\\b)[^;&|\\n]*?/(?:usr/)?(?:local/)?s?bin/',
    re.IGNORECASE,
)
# bank：写系统定时任务（crontab 安装/编辑/删除）→ 拦。写落在 /var/spool/cron（白名单外），
# 且是持久化后门；`crontab -l` 只读放行。这条同时兜住「路径全在系统目录里、
# 路径规则豁免后没人拦」的形态（如 `echo '... /usr/local/bin/backup.sh' | crontab -`）。
_BANK_CRONTAB_PATTERN = re.compile(
    '(?:^|[;&|(\\n])\\s*(?:sudo\\s+)?crontab\\s+(?!-l\\b)\\S',
    re.IGNORECASE,
)
# bank：禁止执行 ssh（横向移动/远程访问）→ 拦
_BANK_SSH_PATTERN = re.compile(r"(?:^|[;&|\n]|\$\(|`)\s*(?:sudo\s+(?:-\S+\s+)*|doas\s+|nohup\s+|time\s+|timeout\s+(?:\S+\s+)?|env\s+(?:\w+=\S*\s+)*|command\s+|builtin\s+|exec\s+|xargs\s+(?:-\S+\s+)*)*ssh(?![\w-])(?!-keygen|-add|-agent)|(?:^|[;&|\n]|\$\(|`)\s*(?:sudo\s+(?:-\S+\s+)*|doas\s+|nohup\s+|time\s+|timeout\s+(?:\S+\s+)?|env\s+(?:\w+=\S*\s+)*|command\s+|builtin\s+|exec\s+|xargs\s+(?:-\S+\s+)*)*(?:scp|sftp|sshpass|ssh-copy-id)(?![\w-])|(?:^|[;&|\n]|\$\(|`)\s*(?:sudo\s+(?:-\S+\s+)*|doas\s+|nohup\s+|time\s+|timeout\s+(?:\S+\s+)?|env\s+(?:\w+=\S*\s+)*|command\s+|builtin\s+|exec\s+|xargs\s+(?:-\S+\s+)*)*rsync\b[^\n]*?\s(?:-e|--rsh)[=\s]", re.IGNORECASE)

# 各场景白名单目录（对齐 agent_moss/scenarios/<id>/rules.json 的目录白名单）。
# 当前仅 bank 有场景规则；新增场景时在此追加，并从对应 rules.json 复制宏观正则。
_SCENARIO_ALLOWED_DIRS = {
    "bank": ("/home/sandbox", "/opt/sandbox", "/tmp"),
}
_SCENARIO_EXTRA_PATTERNS = {
    "bank": (_BANK_PATH_PATTERN, _BANK_SSH_PATTERN, _BANK_WRITE_BIN_PATTERN, _BANK_CRONTAB_PATTERN),
}


def scenario_allowed_dirs(scenario_id: str) -> tuple:
    """场景白名单目录（如 bank 的 /home/sandbox、/opt/sandbox、/tmp）。

    供生成器在「剔除被场景拦截的 allow 命令」时把白名单打进提示——家目录不在白名单内的
    机器会少几条命令，不说清楚客户只会看到「同一份包、两个环境、数字对不上」。
    """
    return _SCENARIO_ALLOWED_DIRS.get(scenario_id, ())

# ---------------------------------------------------------------------------
# 2) 字面量豁免（对齐 agent_moss/engine/inline_analyzer.py::is_literal_text_command）
# ---------------------------------------------------------------------------
# 单段是否为 echo/printf 命令（**段级**门控，见 is_literal_text_command）
_ECHO_SEG_RE = re.compile(r"^\s*(?:echo|printf)(?:\s|$)", re.IGNORECASE)

# 重定向到 /dev/null 的丢弃写法（2>/dev/null、&>/dev/null、>/dev/null）——
# 丢弃输出不算写文件意图（对齐 agent_moss/engine/logic_rules.py::_DEVNULL_REDIRECT_RE）
_DEVNULL_REDIRECT_RE = re.compile(r"(?:2|&|1)?\s*>\s*/dev/null\b")

#: 命令分隔符段（_split_command_segments 会把分隔符本身也作为独立段返回）
_SEPARATOR_SEGMENTS = frozenset({"&&", "||", ";", "\n", "|", "&"})


def _split_command_segments(action_detail: str) -> list:
    """按 &&/||/;/换行 分段，跳过引号内的分隔符（原样搬运自
    agent_moss/engine/heuristic.py::_split_command_segments）。"""
    segments: list = []
    cur: list = []
    i = 0
    quote = None
    while i < len(action_detail):
        ch = action_detail[i]
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
        if ch == ";" or ch == "\n":
            segments.append("".join(cur)); segments.append(ch); cur = []; i += 1
            continue
        if ch == "&" and i + 1 < len(action_detail) and action_detail[i + 1] == "&":
            segments.append("".join(cur)); segments.append("&&"); cur = []; i += 2
            continue
        if ch == "|" and i + 1 < len(action_detail) and action_detail[i + 1] == "|":
            segments.append("".join(cur)); segments.append("||"); cur = []; i += 2
            continue
        cur.append(ch)
        i += 1
    if cur:
        segments.append("".join(cur))
    return segments


def _split_shell_commands(command: str) -> list:
    """切成「命令段」列表（不含分隔符），供逐段判定。原样搬运自
    agent_moss/engine/heuristic.py::_split_shell_commands。"""
    segments: list = []
    for seg in _split_command_segments(command):
        if seg in _SEPARATOR_SEGMENTS:
            continue
        segments.extend(p.strip() for p in re.split(r"[|&]", seg) if p.strip())
    return segments


def is_literal_text_command(command: str) -> bool:
    """判断命令是否为 echo/printf 等纯文本输出命令（敏感路径可能作为字符串字面量出现）。

    echo/printf 含真实文件重定向（> /path，非 /dev/null 丢弃、非 >& fd）时返回 False——
    重定向目标是真实写文件，路径不是字面量，不当文本命令（否则 echo x > '~/.bashrc'
    被当文本命令 → 漏报敏感路径写）。

    ⚠️ 门控必须是**整条命令全由 echo/printf 段构成**，不能只看"任意位置出现过 echo"。
    旧副本用 `_ECHO_CMD_RE.search(command)` 做门控，于是
    `cd /storage/x && ps aux; echo done` 这类**含 echo 的复合命令**被整条当成"纯文本
    输出"豁免 → scenario_blocks_allow 判"不拦" → 该命令留在 allow.sh 里，而引擎照常
    按场景规则 Deny → 客户跑 run_all.sh 看到「应放被拦」（实测 6 条，2026-09-30）。
    引擎侧同类洞更严重（`echo hi && cat ~/.ssh/id_rsa` 可绕过凭据读取拦截），
    已于 2026-09-15 修成段级判定；本副本当时没跟改，属**副本与引擎漂移**。
    看护：tests/test_scenario_rules_parity.py 逐条比对副本与引擎的判定。
    """
    segments = _split_shell_commands(command)
    if not segments or any(not _ECHO_SEG_RE.match(seg) for seg in segments):
        return False
    if ">" in command:
        d = re.sub(r"<=>|>=|<=|<>|=>", " ", command)
        d = _DEVNULL_REDIRECT_RE.sub("", d)
        # 摘引号重定向目标（去引号保留路径，支持 / 或 ~ 开头）
        d = re.sub(r">{1,2}\s*(['\"])([~./][^'\"]+)\1", lambda m: ">" + m.group(2), d)
        d = re.sub(r"'[^']*'|\"[^\"]*\"", "", d)
        if re.search(r">{1,2}\s*(?!&)\S", d):
            return False
    # 管道喂写入消费者（tee/tac/install）→ 不是纯文本输出（tee 从 stdin 读并写文件）
    if re.search(r"\|\s*\b(?:tee|tac|install)\b", command):
        return False
    return True


# ---------------------------------------------------------------------------
# 3) 场景拦截判定：命令是否会被场景规则拦
# ---------------------------------------------------------------------------
def is_literal_inline_script_code(seg_first: str, seg: list[str]) -> bool:
    """内联脚本段（python3 -c / perl -e / ruby -e / php -r）的「纯字符串字面量」代码：
    代码里出现的 /path 是文本不是真实访问（对齐引擎 inline_analyzer 对 python -c
    内联代码的语义：print('/etc/shadow') → 豁免；open('/etc/passwd') → 真实读）。
    """
    # 形态：[python3?, -c, code] / [perl, -e, code] / [php, -r, code] / [ruby, -e, code]
    code = None
    if seg_first in ("python3", "python") and len(seg) >= 3 and seg[1] == "-c":
        code = " ".join(seg[2:])
    elif seg_first in ("perl", "ruby") and len(seg) >= 3 and seg[1] == "-e":
        code = " ".join(seg[2:])
    elif seg_first == "php" and len(seg) >= 3 and seg[1] == "-r":
        code = " ".join(seg[2:])
    if code is None:
        return False
    # 出现真实读写/执行动作 → 不是纯字面量（需拦）
    if re.search(r"\b(?:open|system|exec|eval|popen|os\.system)\s*\(|os\.system|"
                 r"rm\s+-rf\b|>\s*['\"]?/|\bwrite\s*\(|\bfile_write", code):
        return False
    return True


def scenario_blocks_allow(cmd: str, scenario_id: str) -> bool:
    """命令是否会被场景规则拦截（用于把被拦的 allow 命令移出主 allow.sh）。

    与引擎 analyze(scenario_id=…) 对 allow 命令的场景判定一致，逻辑优先级：
    1. 场景禁命令（bank 禁 ssh 段首）→ 拦；
    2. 访问白名单目录之外的绝对路径（bank：/home/sandbox|/opt/sandbox|/tmp 之外）
       → 拦；但两处豁免与引擎一致：
       a. echo/printf 纯文本输出里的路径字面量（无真实重定向）→ 不拦；
       b. python3 -c / perl -e / ruby -e / php -r 内联脚本的纯字符串字面量 → 不拦；
       c. ~ 家目录相对路径（bank 沙箱内客户家目录）→ 不拦；
       d. $()/反引号命令替换拼接的相对路径（如 cd $(pwd)/app）→ 运行时才解析，不拦。
    保守原则：无法判定的不拦（allow 保留），避免把客户可执行命令误移出。

    ⚠️ 已知能力边界（与引擎不同，非回归）：本函数只看**命令文本**，不做**脚本内容**
    分析。引擎对 `bash x.sh` 会递归读取脚本内容并套用场景规则
    （实测 `bash evil.sh`（内容 `cd /etc`）→ 引擎 bank 场景 Deny、无场景 Allow），
    本副本不读文件 → 判不拦。本副本只服务「把被场景拦的 allow 命令移出 allow.sh」
    这一个用途，那个集合里不含需要读脚本才能判定的命令，故不影响生成结果。
    """
    if scenario_id not in _SCENARIO_ALLOWED_DIRS:
        return False
    allowed_dirs = _SCENARIO_ALLOWED_DIRS[scenario_id]
    extra = _SCENARIO_EXTRA_PATTERNS.get(scenario_id, ())

    # 0) 场景追加禁命令正则（bank 禁 ssh）——段首/独立 token 命中即拦
    for pat in extra:
        if pat is _BANK_SSH_PATTERN:
            if _BANK_SSH_PATTERN.search(cmd):
                return True
        elif pat is _BANK_PATH_PATTERN:
            continue  # 路径检测走下面 token 级，语义等价且更精确
        else:
            if pat.search(cmd):
                return True

    # 1) 命令拆段（shlex 分词，echo 字符串内容不会被拆成独立命令段）
    try:
        toks = shlex.split(cmd)
    except ValueError:
        toks = [t for t in cmd.replace("&&", " && ").replace("||", " || ")
                .replace("|", " | ").replace(";", " ; ").split() if t]
    segs, cur = [], []
    for t in toks:
        if t in (";", "|", "||", "&&"):
            if cur:
                segs.append(cur); cur = []
        else:
            cur.append(t)
    if cur:
        segs.append(cur)
    if not segs:
        return False

    # 2) echo/printf 纯文本输出（无真实重定向）：整条命令是字面量，路径不构成访问
    if is_literal_text_command(cmd):
        return False

    for seg in segs:
        if not seg:
            continue
        # 内联脚本纯字符串代码 → 段内路径是字面量
        if is_literal_inline_script_code(seg[0], seg):
            continue
        # ⚠️ 路径判定**直接复用引擎的同一套正则**（_BANK_PATH_PATTERN），
        # 不要在这里另写一套 token 级判定 —— 2026-09 实测两套逻辑已经漂移：
        # 旧 token 逻辑 `(?<![:\w/])(/(?:[^\s;&|>'\"])+)` 与引擎的
        # `(?<![\w.:~/-])` 边界不同，且 `if t.startswith("~"): continue` 会把
        # `~root`（白名单外的家目录）一并跳过。副本的意义就是与引擎一致，故共用正则。
        if _BANK_PATH_PATTERN.search(" ".join(seg)):
            return True
    return False
