"""LLM 深度分析器 — 结合 Skill 规则进行安全判断

将匹配到的 Skill 检测规则注入 LLM prompt，指导 LLM 进行安全判断。
轻量化实现：直接注入 skill 规则到 prompt，进行深度语义分析。
"""

import json
import logging
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from datetime import datetime

from ..infra.config import Config, get_log_path, get_llm_timeout
from ..infra.llm_client import call_llm
from .script_analyzer import (
    ScriptAnalysisResult,
    analyze_script_content,
    format_script_analysis_for_prompt,
)
from .script_content_analyzer import (
    ScriptChainAnalysisResult,
    format_script_chain_for_prompt,
)
from .skill_engine import SkillEngine
from .types import HeuristicResult, LogicRuleResult, SecurityJudgment

logger = logging.getLogger(__name__)


class LLMAnalysisFailure(Exception):
    """LLM 分析失败的异常"""
    pass


class LLMAnalyzer:
    """LLM 深度分析器 — 结合 Skill 规则进行安全判断"""

    def __init__(self, skill_engine: SkillEngine | None = None):
        self._skill_engine = skill_engine or SkillEngine()
        self._cache: OrderedDict[str, SecurityJudgment] = OrderedDict()
        self._cache_max = 200

    def analyze(
        self,
        prompt_session: str,
        action_history: list[dict[str, object]],
        a_next: dict[str, str],
        reason: str,
        heuristic_result: HeuristicResult,
        logic_result: LogicRuleResult,
        config: Config,
        llm_config: dict | None = None,
        skip_l3_hints: str = "",
        script_chain_result: ScriptChainAnalysisResult | None = None,
        llm_log_path: str | None = None,
        prompt_history: list[dict[str, object]] | None = None,
    ) -> SecurityJudgment:
        """
        使用 LLM + Skill 进行深度安全分析。

        Args:
            prompt_session: 用户输入的原始 prompt
            action_history: 历史动作序列
            a_next: 下一步动作
            reason: 执行理由
            heuristic_result: 特征匹配检测结果（作为提示信息注入）
            logic_result: 逻辑规则检测结果（作为提示信息注入）
            config: 全局配置
            skip_l3_hints: 用户禁用规则的 skip_l3 提示（硬约束注入 L3 prompt）
            script_chain_result: coordinator 在 L1.2/L2.3 产出的脚本调用链
                分析结果；提供时用其格式化文本作为脚本分析提示，跳过重复扫描。
            prompt_history: 完整的交错历史 prompt（可选），每轮 {"text", "actions"}
                按时间序。供 LLM 判断意图一致性与行为链。

        Returns:
            SecurityJudgment: 安全判断结果
        """
        from ..infra.prompt_templates import get_security_judge_prompt

        # 0. LLM 结果缓存查找
        action_type = a_next.get("action_type", "")
        action_detail = a_next.get("action_detail", "")
        cache_key = f"{action_type}:{action_detail}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            logger.debug("LLM cache hit: %s", cache_key)
            return cached

        # 1. 匹配相关 Skill
        matched_skills = self._skill_engine.match_skills(a_next, reason)
        skills_text = self._skill_engine.format_skills_for_prompt(matched_skills)

        # 2. 格式化历史动作
        history_text = self._format_action_history(action_history)

        # 2.5 格式化交错历史 prompt（供 LLM 判断意图一致性，避免"继续"覆盖初始意图）
        # 只喂 prompt 文本 + 各轮动作类型/详情（截断），与 action_history 互补但不重复。
        prompt_history_text = self._format_prompt_history(prompt_history)

        # 3. 格式化特征匹配/逻辑规则提示
        hints_text = self._format_hints(heuristic_result, logic_result)

        # 3.5 脚本内容分析
        # 优先复用 coordinator 在 L1.2/L2.3 产出的 script_chain_result
        # （已递归追踪 + 预处理 + L1/L2 扫描）；缺失时回退单文件关键词预扫。
        if script_chain_result is not None:
            script_analysis_text = format_script_chain_for_prompt(script_chain_result)
        else:
            script_analysis = analyze_script_content(action_type, action_detail)
            script_analysis_text = format_script_analysis_for_prompt(script_analysis)

        # 4. 生成安全判断 prompt
        judge_prompt = get_security_judge_prompt(
            prompt_session=prompt_session,
            action_history=history_text,
            prompt_history_text=prompt_history_text,
            a_next=a_next,
            reason=reason,
            skills_text=skills_text,
            hints_text=hints_text,
            script_analysis_text=script_analysis_text,
            skip_l3_hints=skip_l3_hints,
        )

        # 4.5 打印 prompt 到日志文件（如果配置了 AGENT_MOSS_LOG_PATH）
        # 优先级：per-request 注入的 llm_log_path（来自调用方 env，bridge 子进程有
        # AGENT_MOSS_LOG_PATH 但服务进程不一定有，per-request 注入解决跨进程）>
        # 服务进程自己的 AGENT_MOSS_LOG_PATH env > agent_moss_settings > 空（不记）。
        # 与 bridge.py 记 HOOK_INPUT/HOOK_OUTPUT 写同一个文件，
        # 对齐 audit_agent 的 AUDIT_LOG_PATH（hook 日志 + LLM prompt 都写同文件）。
        log_path = llm_log_path or get_log_path()
        if log_path:
            self._log_prompt(judge_prompt, a_next, log_path)

        # 5. 调用 LLM（带超时和重试）
        max_retries = config.retry.max_retries
        retry_interval = config.retry.retry_interval
        _call_start = time.monotonic()  # 记录调用开始时间，用于精确计算耗时
        llm_timeout = get_llm_timeout()

        # 如果请求携带了 per-request LLM 配置，用它覆盖全局配置
        llm_config_to_use = config.llm
        if llm_config and llm_config.get("apiKey"):
            from ..infra.config import LLMConfig
            # 只覆盖调用相关的字段（apiKey/baseUrl/model/provider），保留超时/重试
            # 等基础设施配置（超时由 get_llm_timeout() 单独管，不在 LLMConfig 里）。
            overrides = {k: v for k, v in llm_config.items() if k in ("baseUrl", "apiKey", "model", "provider")}
            llm_config_to_use = LLMConfig(
                api_key=overrides.get("apiKey", config.llm.api_key),
                base_url=overrides.get("baseUrl", config.llm.base_url),
                model=overrides.get("model", config.llm.model),
                provider=overrides.get("provider", config.llm.provider),
                temperature=config.llm.temperature,
                max_tokens=config.llm.max_tokens,
            )

        # 根据 LLM 超时时间自动计算单次 call_llm 超时时间
        # 公式：总超时 = N 次调用 + (N-1) 次重试间隔
        # 所以：单次超时 = (总超时 - 重试间隔 * (max_retries - 1)) / max_retries
        single_call_timeout = (
            llm_timeout - retry_interval * (max_retries - 1)
        ) / max_retries
        # 确保单次超时至少 10 秒
        single_call_timeout = max(single_call_timeout, 10.0)

        for attempt in range(1, max_retries + 1):
            try:
                # 使用 ThreadPoolExecutor 包装 LLM 调用，支持超时控制
                with ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(
                        call_llm,
                        prompt=judge_prompt,
                        timeout=single_call_timeout,
                        config=llm_config_to_use,
                    )
                    llm_result = future.result(timeout=llm_timeout)

                # 记录 token 用量（step="L3_security_judge"）
                try:
                    from ..infra.token_stats import record_token_usage
                    record_token_usage(
                        session_id="audit",
                        step="L3_security_judge",
                        model=llm_result.model,
                        prompt_tokens=llm_result.prompt_tokens,
                        completion_tokens=llm_result.completion_tokens,
                        total_tokens=llm_result.total_tokens,
                    )
                except Exception:
                    pass  # token 统计失败不影响主流程

                judgment = self._parse_llm_response(llm_result.content)
                judgment.source = "llm"
                # 写入缓存（超出上限时淘汰最旧条目）
                if len(self._cache) >= self._cache_max:
                    self._cache.popitem(last=False)
                self._cache[cache_key] = judgment
                return judgment

            except FuturesTimeoutError:
                # ThreadPoolExecutor 超时：LLM 调用在 llm_timeout 内未返回
                elapsed = time.monotonic() - _call_start
                logger.warning(
                    "LLM 安全分析超时（耗时 %.1fs，上限 %ds），第 %d/%d 次尝试",
                    elapsed,
                    llm_timeout,
                    attempt,
                    max_retries,
                )
                if attempt < max_retries:
                    time.sleep(retry_interval)
                else:
                    raise LLMAnalysisFailure(
                        f"LLM 安全分析超时（耗时 {elapsed:.1f}s，上限 {llm_timeout}s，已重试 {max_retries} 次）"
                    )

            except TimeoutError as e:
                # call_llm 抛出的真正超时（网络/读取超时）
                logger.warning(
                    "LLM 调用网络超时: %s，第 %d/%d 次尝试",
                    e,
                    attempt,
                    max_retries,
                )
                if attempt < max_retries:
                    time.sleep(retry_interval)
                else:
                    raise LLMAnalysisFailure(
                        f"LLM 调用网络超时（已重试 {max_retries} 次）: {e}"
                    )

            except Exception as e:
                # API 错误（如并发限制 500006、400/500 错误等），非超时
                error_type = type(e).__name__
                logger.warning(
                    "LLM 安全分析第 %d/%d 次调用失败 [%s]: %s",
                    attempt,
                    max_retries,
                    error_type,
                    e,
                )
                if attempt < max_retries:
                    time.sleep(retry_interval)
                else:
                    raise LLMAnalysisFailure(
                        f"LLM 安全分析失败（{max_retries} 次）[{error_type}]: {e}"
                    )

    def _parse_llm_response(self, response: str) -> SecurityJudgment:
        """解析 LLM 返回的安全判断结果"""
        from ..infra.parsers import parse_security_judgment

        return parse_security_judgment(response)

    @staticmethod
    def _format_action_history(action_history: list[dict[str, object]]) -> str:
        """格式化历史动作序列"""
        if not action_history:
            return "（无历史动作）"

        lines = []
        for i, action in enumerate(action_history, 1):
            if isinstance(action, dict):
                name = action.get("name", action.get("action_type", "未知"))
                detail = action.get("action_detail", "")
                if detail:
                    lines.append(f"  {i}. {name}: {detail}")
                else:
                    lines.append(f"  {i}. {name}")
            else:
                lines.append(f"  {i}. {action}")
        return "\n".join(lines)

    @staticmethod
    def _format_prompt_history(
        prompt_history: list[dict[str, object]] | None,
        max_text_chars: int = 500,
    ) -> str:
        """格式化交错历史 prompt 为 LLM 可读文本。

        每轮输出 "第 N 轮用户意图: <text>"，若该轮带 actions 则附上动作类型
        （动作详情截断，避免撑爆 context）。空/None 返回占位。
        """
        if not prompt_history:
            return "（未提供历史意图）"

        lines = []
        for i, turn in enumerate(prompt_history, 1):
            if not isinstance(turn, dict):
                continue
            text = turn.get("text", "")
            if not isinstance(text, str):
                text = ""
            text = text.strip()
            if not text:
                continue
            text = text[:max_text_chars]
            line = f"  第{i}轮用户意图: {text}"
            actions = turn.get("actions")
            if actions and isinstance(actions, list):
                action_types = []
                for a in actions:
                    if isinstance(a, dict):
                        at = a.get("action_type", "")
                        detail = a.get("action_detail", "")
                        if isinstance(at, str) and at:
                            action_types.append(at if not detail or not isinstance(detail, str) else f"{at}")
                if action_types:
                    line += f"  → 动作: {', '.join(action_types)}"
            lines.append(line)

        if not lines:
            return "（未提供历史意图）"
        return "\n".join(lines)

    @staticmethod
    def _format_hints(
        heuristic_result: HeuristicResult,
        logic_result: LogicRuleResult,
    ) -> str:
        """格式化特征匹配/逻辑规则检测提示"""
        hints = []

        if heuristic_result.hit:
            hints.append(
                f"⚠️ 特征匹配检测发现风险 [风险等级: {heuristic_result.risk_level}]:\n"
                f"   类型: {heuristic_result.risk_type}\n"
                f"   原因: {heuristic_result.reason}\n"
                f"   匹配模式: {', '.join(heuristic_result.matched_patterns)}"
            )

        if logic_result.hit:
            hints.append(
                f"⚠️ 逻辑规则检测发现风险 [风险等级: {logic_result.risk_level}]:\n"
                f"   违反规则: {logic_result.violated_rule}\n"
                f"   类型: {logic_result.risk_type}\n"
                f"   原因: {logic_result.reason}"
            )

        if not hints:
            return "特征匹配检测和逻辑规则检测均未发现风险。"

        return "\n\n".join(hints)

    @staticmethod
    def _log_prompt(prompt: str, a_next: dict[str, str], log_path: str) -> None:
        """将 LLM prompt 写入日志文件。"""
        if not log_path:
            return
        try:
            action_type = a_next.get("action_type", "unknown")
            action_detail = a_next.get("action_detail", "")[:100]
            log_line = (
                f"[{datetime.now().isoformat(timespec='milliseconds')}] "
                f"[LLM_PROMPT] action_type={action_type}, action_detail={action_detail}... "
                f"prompt_length={len(prompt)}\n"
                f"{prompt}\n"
                f"--- END PROMPT ---\n"
            )
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(log_line)
        except Exception as e:
            logger.warning("Failed to write LLM prompt to log: %s", e)