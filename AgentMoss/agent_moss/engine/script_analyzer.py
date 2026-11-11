"""脚本内容分析器 — 预扫描脚本内容检测可疑关键词

当检测到脚本执行动作时，预扫描脚本内容中的可疑关键词。
如果命中可疑关键词，将脚本内容注入 LLM prompt 进行深度分析。

方案3: 关键词预筛选
- 限制读取 500 行，避免 prompt 爆炸
- 只在检测到可疑关键词时才注入脚本内容
- 不影响前两层（特征匹配、逻辑规则）的处理逻辑
"""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..rules_loader import compile_rule_regex, load_script_rules, resolve_keyword_set

logger = logging.getLogger(__name__)

# 脚本分析词表：单一事实源 rules/script_rules.json（与 script_content_analyzer 共用）。
# ⚠️ 缺失/损坏 → 词表为空（更松），故必须报错。
_SCRIPT_RULES = load_script_rules()
if not _SCRIPT_RULES:
    logger.error(
        "规则文件 script_rules.json 缺失或损坏 —— 脚本关键词扫描将不命中任何模式"
        "（比正常更松）。请检查包完整性。"
    )

# 高风险检测规则 — (名称, 正则模式)
# 仅保留误报率极低、几乎必然指示恶意行为的模式。数据见 rules/script_rules.json。
SUSPICIOUS_PATTERNS: list[tuple[str, re.Pattern]] = [
    (str(r["name"]), compile_rule_regex(r))
    for r in (_SCRIPT_RULES.get("suspicious_patterns") or [])
]

# 脚本执行模式匹配：本模块（供 L3 提示词用）只认 .sh，故用 script_exec_patterns.legacy。
# 递归追踪用的是 chain 那份（认解释器 + 任意后缀），两份不可互换。
SCRIPT_EXEC_PATTERNS = [
    str(p["pattern"])
    for p in ((_SCRIPT_RULES.get("script_exec_patterns") or {}).get("legacy") or [])
]


@dataclass
class ScriptAnalysisResult:
    """脚本内容分析结果"""

    script_path: str = ""  # 脚本路径
    script_content: str = ""  # 脚本内容（最多 500 行）
    matched_keywords: list[str] = field(default_factory=list)  # 命中的可疑关键词
    line_count: int = 0  # 脚本行数
    is_suspicious: bool = False  # 是否可疑
    error: str = ""  # 读取错误信息
    risk_level: str = ""  # 预判风险等级: critical, high, medium, low
    risk_reason: str = ""  # 预判风险原因


def extract_script_path(command: str) -> str | None:
    """
    从 bash 命令中提取脚本路径。

    Args:
        command: bash 命令字符串

    Returns:
        str | None: 脚本路径，如果未匹配到则返回 None
    """
    for pattern in SCRIPT_EXEC_PATTERNS:
        match = re.search(pattern, command)
        if match:
            return match.group(1)
    return None


def scan_script_for_keywords(script_content: str) -> list[str]:
    """
    扫描脚本内容中的高风险模式。

    Args:
        script_content: 脚本内容

    Returns:
        list[str]: 命中的高风险模式名称列表
    """
    matched = []
    for name, pattern in SUSPICIOUS_PATTERNS:
        if pattern.search(script_content):
            matched.append(name)
    return matched


# 关键词组合风险评估规则：数据见 rules/script_rules.json。
# group1/group2 里以 `$` 开头的是对 keyword_sets 的引用（如 `$network_post`）。
_KEYWORD_SETS: dict[str, list[str]] = dict(_SCRIPT_RULES.get("keyword_sets") or {})

KEYWORD_COMBINATION_RISKS: list[tuple[set[str], set[str], str, str]] = [
    (
        resolve_keyword_set(r.get("group1"), _KEYWORD_SETS),
        resolve_keyword_set(r.get("group2"), _KEYWORD_SETS),
        str(r["level"]),
        str(r["reason"]),
    )
    for r in (_SCRIPT_RULES.get("keyword_combination_risks") or [])
]


SINGLE_KEYWORD_RISKS: dict[str, tuple[str, str]] = {
    str(k): (str(v["level"]), str(v["reason"]))
    for k, v in (_SCRIPT_RULES.get("single_keyword_risks") or {}).items()
}


def assess_keyword_combination_risk(
    matched_keywords: list[str], script_content: str
) -> tuple[str, str]:
    """
    根据命中的关键词组合评估风险等级。

    Args:
        matched_keywords: 命中的关键词列表
        script_content: 脚本内容（用于额外检测）

    Returns:
        tuple[str, str]: (风险等级, 风险原因)
    """
    if not matched_keywords:
        return "", ""

    keyword_set = set(matched_keywords)

    # 检查关键词组合规则
    for group1, group2, level, reason in KEYWORD_COMBINATION_RISKS:
        hit_group1 = bool(keyword_set & group1)
        hit_group2 = bool(keyword_set & group2) if group2 else True

        if hit_group1 and hit_group2:
            return level, reason

    # 额外检测：curl POST + env 变量外传
    # 这是一个常见的数据外传模式，即使没有匹配到 base64 关键词
    has_network_post = bool(keyword_set & set(_KEYWORD_SETS.get("network_post") or []))
    if has_network_post:
        # 检查脚本中是否包含 env、$USER、$(hostname) 等系统信息收集
        env_patterns = [str(p) for p in (_SCRIPT_RULES.get("env_exfil_patterns") or [])]
        content_lower = script_content.lower()
        for pattern in env_patterns:
            if pattern.lower() in content_lower:
                return "critical", (
                    "检测到网络数据发送 + 系统环境变量收集组合，构成 Critical 级别数据外传风险。"
                    "脚本可能将用户环境变量（可能包含 API Key、密钥等敏感信息）发送到远程服务器。"
                )

    # 单独关键词的默认风险等级
    single_keyword_risks = SINGLE_KEYWORD_RISKS

    # 取最高风险等级
    best_level = ""
    best_reason = ""
    level_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    for kw in matched_keywords:
        if kw in single_keyword_risks:
            level, reason = single_keyword_risks[kw]
            if level_order.get(level, 0) > level_order.get(best_level, 0):
                best_level = level
                best_reason = reason

    return best_level, best_reason


def read_script_content(script_path: str, max_lines: int = 500) -> tuple[str, int, str]:
    """
    读取脚本内容，限制行数。

    Args:
        script_path: 脚本路径
        max_lines: 最大读取行数

    Returns:
        tuple[str, int, str]: (脚本内容, 实际行数, 错误信息)
    """
    try:
        path = Path(script_path).expanduser()
        if not path.exists():
            return "", 0, f"脚本不存在: {script_path}"
        if not path.is_file():
            return "", 0, f"不是文件: {script_path}"

        lines = []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                lines.append(line.rstrip("\n"))

        content = "\n".join(lines)
        return content, len(lines), ""

    except Exception as e:
        return "", 0, f"读取脚本失败: {e}"


def analyze_script_content(
    action_type: str,
    action_detail: str,
    max_lines: int = 500,
) -> ScriptAnalysisResult:
    """
    分析脚本内容，检测可疑关键词。

    只在 action_type 为 bash 且命令中包含脚本执行时才进行分析。

    Args:
        action_type: 动作类型
        action_detail: 动作详情（命令）
        max_lines: 最大读取行数

    Returns:
        ScriptAnalysisResult: 分析结果
    """
    # 只处理 bash 类型的动作
    if action_type.lower() != "bash":
        return ScriptAnalysisResult()

    # 提取脚本路径
    script_path = extract_script_path(action_detail)
    if not script_path:
        return ScriptAnalysisResult()

    logger.debug("检测到脚本执行: %s", script_path)

    # 读取脚本内容
    content, line_count, error = read_script_content(script_path, max_lines)
    if error:
        logger.warning("读取脚本内容失败: %s", error)
        return ScriptAnalysisResult(script_path=script_path, error=error)

    # 扫描可疑关键词
    matched_keywords = scan_script_for_keywords(content)
    is_suspicious = len(matched_keywords) > 0

    # 评估关键词组合风险
    risk_level, risk_reason = "", ""
    if is_suspicious:
        risk_level, risk_reason = assess_keyword_combination_risk(matched_keywords, content)
        logger.info(
            "脚本内容检测到可疑关键词: path=%s, keywords=%s, risk_level=%s",
            script_path,
            matched_keywords,
            risk_level,
        )

    return ScriptAnalysisResult(
        script_path=script_path,
        script_content=content,
        matched_keywords=matched_keywords,
        line_count=line_count,
        is_suspicious=is_suspicious,
        risk_level=risk_level,
        risk_reason=risk_reason,
    )


def format_script_analysis_for_prompt(result: ScriptAnalysisResult) -> str:
    """
    将脚本分析结果格式化为 LLM prompt 可用的文本。

    Args:
        result: 脚本分析结果

    Returns:
        str: 格式化后的文本
    """
    if not result.script_path:
        return ""

    if result.error:
        return f"⚠️ 脚本内容分析失败: {result.error}"

    if not result.is_suspicious:
        return ""

    keywords_str = ", ".join(result.matched_keywords)

    # 构建风险提示
    risk_hint = ""
    if result.risk_level and result.risk_reason:
        risk_level_upper = result.risk_level.upper()
        risk_hint = (
            f"\n\n🔴 **风险评估**: {risk_level_upper} 级别\n"
            f"**风险原因**: {result.risk_reason}\n"
            f"**建议**: 此脚本应被拒绝（Deny），除非有明确的业务需求且已确认目标服务器可信。"
        )

    return (
        f"⚠️ 检测到脚本执行，且脚本内容包含可疑关键词:\n"
        f"   脚本路径: {result.script_path}\n"
        f"   可疑关键词: {keywords_str}\n"
        f"   脚本行数: {result.line_count}"
        f"{risk_hint}\n\n"
        f"### 脚本内容 ###\n```\n{result.script_content}\n```\n"
    )