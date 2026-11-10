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
# bank：访问 /home/sandbox、/opt/sandbox、/tmp 之外的绝对路径 → 拦
_BANK_PATH_PATTERN = re.compile(
    r"(?:^|[;\s>&|@'\"])(/(?!home/sandbox(?:\s|/|$)|opt/sandbox(?:\s|/|$)|tmp(?:\s|/|$))[^\s;&|>\"]+)",
    re.IGNORECASE,
)
# bank：禁止执行 ssh（横向移动/远程访问）→ 拦
_BANK_SSH_PATTERN = re.compile(r"(?:^|[;&|:]\s*)ssh(?:\s|$)", re.IGNORECASE)

# 各场景白名单目录（对齐 agent_moss/scenarios/<id>/rules.json 的目录白名单）。
# 当前仅 bank 有场景规则；新增场景时在此追加，并从对应 rules.json 复制宏观正则。
_SCENARIO_ALLOWED_DIRS = {
    "bank": ("/home/sandbox", "/opt/sandbox", "/tmp"),
}
_SCENARIO_EXTRA_PATTERNS = {
    "bank": (_BANK_PATH_PATTERN, _BANK_SSH_PATTERN),
}

# ---------------------------------------------------------------------------
# 2) 字面量豁免（对齐 agent_moss/engine/inline_analyzer.py::is_literal_text_command）
# ---------------------------------------------------------------------------
# echo / printf 命令本身（用于 is_literal_text_command 门控）
_ECHO_CMD_RE = re.compile(r"(?:^|\s|;|&&|\|\|)(?:echo|printf)\s", re.IGNORECASE)

# 重定向到 /dev/null 的丢弃写法（2>/dev/null、&>/dev/null、>/dev/null）——
# 丢弃输出不算写文件意图（对齐 agent_moss/engine/logic_rules.py::_DEVNULL_REDIRECT_RE）
_DEVNULL_REDIRECT_RE = re.compile(r"(?:2|&|1)?\s*>\s*/dev/null\b")


def is_literal_text_command(command: str) -> bool:
    """判断命令是否为 echo/printf 等纯文本输出命令（敏感路径可能作为字符串字面量出现）。

    echo/printf 含真实文件重定向（> /path，非 /dev/null 丢弃、非 >& fd）时返回 False——
    重定向目标是真实写文件，路径不是字面量，不当文本命令（否则 echo x > '~/.bashrc'
    被当文本命令 → 漏报敏感路径写）。
    原样搬运自 agent_moss/engine/inline_analyzer.py，勿改语义。
    """
    if not _ECHO_CMD_RE.search(command):
        return False
    if ">" in command:
        d = re.sub(r"<=>|>=|<=|<>|=>", " ", command)
        d = _DEVNULL_REDIRECT_RE.sub("", d)
        # 摘引号重定向目标（去引号保留路径，支持 / 或 ~ 开头）
        d = re.sub(r">{1,2}\s*(['\"])([~./][^'\"]+)\1", lambda m: ">" + m.group(2), d)
        d = re.sub(r"'[^']*'|\"[^\"]*\"", "", d)
        if re.search(r">{1,2}\s*(?!&)\S", d):
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
        for t in seg:
            if t.startswith("~"):
                continue  # 家目录相对路径 = 沙箱内允许目录
            # $() / 反引号命令替换拼接的相对路径：运行时才解析，静态判不拦
            if re.match(r"\$\(", t):
                if not t[: re.match(r"\$\(", t).start()].startswith("/"):
                    continue
            elif "`" in t:
                if not t[: t.index("`")].startswith("/"):
                    continue
            # 提取绝对路径 token（与引擎 bank 正则一致的边界）
            for m in re.finditer(r"(?<![:\w/])(/(?:[^\s;&|>'\"])+)", t):
                p = m.group(1).rstrip(",);]'")
                if not p.startswith("/"):
                    continue
                if any(p == d or p.startswith(d + "/") for d in allowed_dirs):
                    continue  # 白名单内
                return True  # 白名单外绝对路径 → 场景规则拦截
    return False