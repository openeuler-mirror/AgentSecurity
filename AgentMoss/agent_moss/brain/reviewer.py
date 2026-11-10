"""Brain 候选 pattern LLM 审核器 — 判断"是否值得沉淀为规则/Skill"

机械的正则提取（PatternExtractor）+ 关键词去重无法判断语义价值：
- 误报：LLM reason 提到 /app/config 但这是合法审查路径 → 机械提取会沉淀，误拦合法访问
- 漏报：LLM 判危险的理由千变万化（竞态/隐写/语义九曲），正则追不上
- 语义重复：scp secret.tar 和 curl -F file=@secret.tar 语义同构但关键词完全不同

本审核器在候选"达到阈值（复现 3 次）后"接入一道 LLM 判定：
  通过 → 沉淀 draft 规则 / Skill
  拒绝 → 标记 rejected，永久排除（同一 pattern 不再消费审核 token）

无 LLM 配置时优雅降级：返回 None → 调用方按既有自动机制处理（不去拒绝一个
可能有价值的候选，也不强制 approve 一个质量不明的候选）。
"""

import json
import logging
import re
from dataclasses import dataclass

from ..infra.config import is_llm_enabled
from ..infra.llm_client import call_llm

logger = logging.getLogger(__name__)

REVIEW_PROMPT = """你是 AgentMoss 安全规则审核器。判断下列"从 LLM 拒绝结果中提取的安全模式"是否值得沉淀为本地规则。

## 提取的模式（候选）
- 模式: {pattern}
- 所属层: Layer {layer}（1=特征匹配，2=行为链）
- 类型: {rule_type}

## 原始被拒绝的操作
{action_detail}

## LLM 当时的拒绝理由
{reason}

## 判断准则
1. **是否过高泛化**：这条模式是否会误拦正常的合法操作？（如从 reason 抠出的普通路径，但用户正常使用）
2. **是否符合敏感特征**：该模式指向的路径/命令是否确实敏感（凭据/系统文件/恶意命令/外传）？
3. **与三层规则重复**：这条模式是否已被现有 L1/L2 规则覆盖（重复则无价值）？
4. **是不是真实攻击模式**：该模式是否代表一种连续的攻击行为模式？

## 输出 JSON（只输出 JSON，无其他文字）
{{"should_keep": true/false, "confidence": 0-100, "reason": "简短理由（中文）", "suggested_rule": "若应保留则输出建议正则，否则空串", "duplicate_of": "若与现有规则重复则说明是哪个，否则空串"}}
"""


@dataclass
class BrainReview:
    """LLM 审核判定结果"""

    should_keep: bool = False
    confidence: float = 0.0
    reason: str = ""
    suggested_rule: str = ""
    duplicate_of: str = ""


class BrainReviewer:
    """对达到阈值（复现）的候选 pattern 做 LLM 审核"""

    def __init__(self, timeout: float = 10.0):
        self._timeout = timeout

    def review(
        self,
        pattern: str,
        layer: int,
        rule_type: str,
        action_detail: str,
        reason: str,
    ) -> BrainReview | None:
        """审核候选 pattern。

        Returns:
            BrainReview: 审核判定
            None: LLM 不可用/调用失败（降级，调用方按不影响主流程处理）
        """
        if not is_llm_enabled():
            logger.debug("Brain 审核跳过：LLM 未启用")
            return None

        prompt = REVIEW_PROMPT.format(
            pattern=pattern,
            layer=layer,
            rule_type=rule_type,
            action_detail=(action_detail or "")[:400],
            reason=(reason or "")[:400],
        )
        try:
            resp = call_llm(prompt, timeout=self._timeout)
            return self._parse_review(resp.content or "")
        except Exception as e:
            logger.debug("Brain 审核 LLM 调用失败（降级）: %s", e)
            return None

    def _parse_review(self, content: str) -> BrainReview:
        """解析 LLM JSON 响应为 BrainReview"""
        # 容忍 markdown 代码块：剥掉 ```json ... ```
        text = content.strip()
        if text.startswith("```"):
            text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
            text = re.sub(r"\n?```$", "", text)
        # 提取第一个 JSON 对象（容忍前后赘余文字）
        json_match = re.search(r"\{.*\}", text, re.DOTALL)
        if not json_match:
            raise ValueError(f"审核响应无 JSON 对象: {text[:200]}")
        try:
            data = json.loads(json_match.group(0))
        except json.JSONDecodeError as e:
            raise ValueError(f"审核响应 JSON 解析失败: {e}") from e
        if "should_keep" not in data:
            raise ValueError(f"审核响应缺 should_keep: {text[:200]}")

        sk = data.get("should_keep")
        if isinstance(sk, str):
            sk = sk.strip().lower() in ("true", "1", "是", "yes")
        return BrainReview(
            should_keep=bool(sk),
            confidence=float(data.get("confidence", 0) or 0),
            reason=str(data.get("reason", "") or ""),
            suggested_rule=str(data.get("suggested_rule", "") or ""),
            duplicate_of=str(data.get("duplicate_of", "") or ""),
        )