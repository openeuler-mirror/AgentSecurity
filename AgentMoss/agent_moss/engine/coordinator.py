"""AgentMoss Security Agent 主协调器 — 三层防御安全判断

整体流程（层号 = violated_layers = 文档层名，严格按执行顺序）：
- L1.1 特征匹配静态检测（关键命令 + 注入检测 + 用户敏感规则）→ high/critical 直接 Deny
- L1.2 脚本内容预扫描（递归追踪脚本调用链，复用 L1 扫描）→ high/critical 直接 Deny
- L2.1 逻辑规则检测（read_before_write + 意图一致性 + 敏感路径 + 危险模式）→ high/critical 直接 Deny
- L2.2 形式化验证（行为图 + 性质验证，含跨会话组合链）
- L2.3 脚本内容 L2 扫描（对预处理后脚本内容复用 L2 规则）
- L3.1 LLM + Skill 深度分析（特征匹配和逻辑规则结果作为提示注入）
   → Deny 结果异步喂给 Brain 提取规则和 Skill

Brain 规则融入：
- Layer 1 类型 brain 规则在 L1.1/L1.2 检测后执行（violated_layers=brain_L1）
- Layer 2 类型 brain 规则在 L2.x 检测后执行（violated_layers=brain_L2）
- Brain Skill 写入 skills/ 目录，由 SkillEngine 自动匹配

配置控制（优先级：环境变量 > agent_moss_settings.json > 默认值）：
- AGENT_MOSS_DISABLE_LLM=1: 禁用第三层 LLM 分析，只执行前两层静态分析
"""

import asyncio
import logging
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..profiles.base import OSProfile
    from ..agents.base import AgentExtensions

from ..infra.config import Config, is_brain_enabled, is_llm_enabled
from ..profiles import get_profile
from .heuristic import (
    HeuristicDetector, is_safe_bash_command,
    is_fully_safe_bash_command, is_readonly_sensitive_bash_command,
    is_inline_script_command,
)
from .inline_analyzer import analyze_inline_script, is_literal_text_command
from .llm_analyzer import LLMAnalyzer
from .logic_rules import LogicRulesChecker
from .script_content_analyzer import (
    analyze_script_content,
    scan_script_chain_with_l2,
    ScriptChainAnalysisResult,
)
from .skill_engine import SkillEngine
from .types import HeuristicResult, SecurityJudgment

logger = logging.getLogger(__name__)

# 完全安全工具：跳过 Layer 2 + Layer 3（不具备读取文件内容的能力）
FULLY_SAFE_TOOLS = frozenset({
    "ask_user_question", "glob", "list_dir", "ls", "count_text_length",
    "filemgr-globfiles",
})

# 内置安全 Skill 白名单（通用 baseline）：空集。
# 各宿主 agent 的专属内置安全 Skill 通过 agent_ext.builtin_safe_skills 注入，
# 例如 xiaoO 的 xiaoo-guardian 由 agent_moss/agents/xiaoo/rules.json 提供。
TRUSTED_SKILLS = frozenset()

# 安全但可能访问敏感路径：跳过 Layer 3，保留 Layer 2 敏感路径检测
READONLY_SENSITIVE_TOOLS = frozenset({
    "read", "file_read", "read_file", "head", "tail", "grep",
    "filemgr-readfile", "filemgr-grepfiles",
})

# 向后兼容
READONLY_SAFE_TOOLS = FULLY_SAFE_TOOLS | READONLY_SENSITIVE_TOOLS


class AgentMossBot:
    """AgentMoss Security Agent 安全检测 Agent — 三层防御体系（OS Profile 驱动）"""

    def __init__(
        self,
        profile: "OSProfile | None" = None,
        rules_path: str | Path | None = None,
        skills_dir: str | Path | None = None,
        agent_ext: "AgentExtensions | None" = None,
    ):
        self._profile = profile or get_profile()
        self._agent_ext = agent_ext
        self._heuristic_detector = HeuristicDetector(
            self._profile, rules_path=rules_path, agent_ext=agent_ext
        )
        self._logic_rules_checker = LogicRulesChecker(self._profile, agent_ext=agent_ext)
        # 形式化引擎（L2.2）：多 session 行为图 + 性质验证（跨会话组合链/敏感数据传播）
        from .formal_engine import FormalEngine
        self._formal_engine = FormalEngine()
        # 保存 skills_dir 供 brain 注入用（brain skill 也写该目录，对齐 SkillEngine 加载源）
        self._skills_dir = skills_dir
        self._skill_engine = SkillEngine(skills_dir=skills_dir, agent_ext=agent_ext)
        self._llm_analyzer = LLMAnalyzer(skill_engine=self._skill_engine)

        # Brain 模块（默认关闭，AGENT_MOSS_BRAIN_ENABLED=1 才启用）
        # 为避免默认开启时产生建库/写文件/读库等副作用，实例化延迟到首次访问：
        # 未启用时 _brain_rule_store 保持 None，_check_brain_rules_layer 与提取触发点
        # 均直接短路。启用后通过 _ensure_brain() 惰性实例化。
        self._brain_enabled = is_brain_enabled()
        self._brain_rule_store = None
        self._brain_skill_manager = None
        self._brain_extractor = None
        self._brain_curator = None
        self._brain_last_maintenance = 0

    def judge(
        self,
        prompt_session: str,
        action_history: list[dict[str, object]],
        a_next: dict[str, str],
        reason: str,
        config: Config,
        llm_config: dict | None = None,
        cwd: str = "",
        llm_log_path: str | None = None,
        prompt_history: list[dict[str, object]] | None = None,
        session_history: list[dict[str, object]] | None = None,
    ) -> SecurityJudgment:
        """
        执行三层防御安全判断。

        Args:
            prompt_session: 用户输入的原始 prompt
            action_history: 历史动作序列（当前 session）
            a_next: 下一步动作
            reason: 执行理由
            config: 全局配置
            prompt_history: 完整的交错历史 prompt（可选），每轮 {"text", "actions"}，
                按时间序。供 L2 意图一致性与 L3 语义分析使用。
            session_history: 多 session 历史动作（可选），每项 {"session_id",
                "action_history": [...]}。供 L2.2 形式化引擎做跨会话组合链/敏感数据
                传播验证；缺省时仅用当前 session 构建行为图（向后兼容）。由调用方
                （含未来 agentgate 非侵入式采集）提供。

        Returns:
            SecurityJudgment: 安全判断结果
        """
        security_cfg = config.security

        # 如果安全检测被禁用，默认 Allow
        if not security_cfg.enabled:
            logger.info("安全检测已禁用，默认允许")
            return SecurityJudgment(
                allowed=True,
                reason="安全检测已禁用",
                risk_level="low",
                source="disabled",
            )

        violated_layers: list[str] = []

        # ========== Brain 维护（节流，仅启用时） ==========
        # 定期执行 curator：draft 规则自动激活 + 规则/skill 生命周期（stale/archived）。
        # 节流：每 MIN_BRAIN_MAINT_INTERVAL 秒最多一次，避免每次 judge 都跑 SQL。
        if self._brain_enabled:
            self._maybe_run_brain_maintenance()

        # ========== 内联脚本命令检查（假阳性防护） ==========
        # 对内联脚本命令（python -c, perl -e 等）和 echo/printf 文本输出命令，
        # Layer 1/2 的 file_access 模式（如 /etc/shadow）不立即 Deny。因为敏感路径
        # 可能出现在字符串字面量中，而纯正则无法可靠区分字符串和执行路径。
        # 由 inline_analyzer 做静态语义判定（区分文本字面量 vs 真实读写），不依赖 LLM。
        action_detail = a_next.get("action_detail", "").lower()
        is_inline_script_cmd = is_inline_script_command(action_detail)
        is_literal_text_cmd = is_literal_text_command(action_detail)
        skip_inline_file_access = False

        # ========== 层1: 特征匹配静态检测 ==========
        if security_cfg.heuristic_enabled:
            heuristic_result = self._heuristic_detector.detect(a_next, reason, prompt_session)
            logger.debug(
                "特征匹配检测结果: hit=%s, risk_level=%s, reason=%s",
                heuristic_result.hit,
                heuristic_result.risk_level,
                heuristic_result.reason,
            )
            if heuristic_result.hit:
                # 对内联脚本/文本输出命令，file_access 风险不立即 Deny（交 inline_analyzer 静态判定）
                skip_inline_file_access = (
                    (is_inline_script_cmd or is_literal_text_cmd)
                    and heuristic_result.risk_type == "file_access"
                )
                # 短路 Deny 条件：
                # - high/critical：任何类型（含 file_access，非 inline 时）直接拦
                # - medium + file_access：敏感路径写操作也确定性拦截，不依赖 L3 兜底。
                #   仅 /etc/hosts 这类 medium 级 deny_write 路径的写操作受此影响（读操作
                #   在 SensitivePathChecker 内部已 continue 放行，不会 hit），不会误拦
                #   cat /etc/hosts 等只读；其他 medium 命中（git push --force / rm -f 单文件 /
                #   prompt 注入 repeat-instructions）不走 file_access，不受影响，仍交 L3。
                should_deny_l1 = (
                    heuristic_result.risk_level in ("high", "critical")
                    or (heuristic_result.risk_level == "medium"
                        and heuristic_result.risk_type == "file_access")
                ) and not skip_inline_file_access
                if should_deny_l1:
                    violated_layers.append("L1.1")
                    logger.info(
                        "特征匹配检测拦截: risk_level=%s, reason=%s",
                        heuristic_result.risk_level,
                        heuristic_result.reason,
                    )
                    return SecurityJudgment(
                        allowed=False,
                        reason=heuristic_result.reason,
                        risk_level=heuristic_result.risk_level,
                        risk_type=heuristic_result.risk_type,
                        confidence=95,
                        source="heuristic",
                        action_desc=a_next.get("action_detail", ""),
                        violated_layers=violated_layers,
                    )
        else:
            heuristic_result = HeuristicResult(hit=False)

        # ========== L1.2: 脚本内容预扫描（递归追踪 + L1 规则复用） ==========
        # 对 bash 类型的脚本执行动作，递归追踪脚本调用链，预处理后用 L1
        # CommandPatternScanner 扫描，命中 high/critical 直接 Deny。
        # 避免"脚本内有 rm -rf / 但 L1 只看命令字段 bash deploy.sh 不命中"的漏报，
        # 也减少 L3 的 token 消耗（L1 可拦截的场景不再走 LLM）。
        script_chain_result: ScriptChainAnalysisResult | None = None
        _l15_action_type = a_next.get("action_type", "").lower()
        _l15_action_detail = a_next.get("action_detail", "").lower()
        if _l15_action_type == "bash":
            # 复用 HeuristicDetector 的 CommandPatternScanner（OS Profile 驱动）
            _scanner = self._heuristic_detector._command_scanner
            script_chain_result = analyze_script_content(
                _l15_action_type, _l15_action_detail, command_scanner=_scanner,
                cwd=cwd,
            )
            if script_chain_result and script_chain_result.nodes:
                for node in script_chain_result.nodes:
                    if node.l1_hit and node.l1_risk_level in ("high", "critical"):
                        violated_layers.append("L1.2")
                        logger.info(
                            "脚本内容 L1 拦截: path=%s, depth=%d, risk_level=%s, reason=%s",
                            node.script_path, node.depth, node.l1_risk_level, node.l1_reason,
                        )
                        return SecurityJudgment(
                            allowed=False,
                            reason=f"脚本内容包含危险操作: {node.l1_reason} (文件: {node.script_path}, 深度: {node.depth})",
                            risk_level=node.l1_risk_level,
                            risk_type=node.l1_risk_type,
                            confidence=90,
                            source="heuristic_script_scan",
                            action_desc=a_next.get("action_detail", ""),
                            violated_layers=violated_layers,
                        )

        # ========== Brain Layer 1 规则检查 ==========
        brain_l1_deny = self._check_brain_rules_layer(a_next, layer=1)
        if brain_l1_deny:
            violated_layers.append("brain_L1")
            logger.info("Brain Layer 1 规则拦截: %s", brain_l1_deny.explanation[:100])
            return SecurityJudgment(
                allowed=False,
                reason=f"[Brain L1] {brain_l1_deny.explanation}",
                risk_level="high",
                risk_type="brain_rule",
                confidence=int(brain_l1_deny.confidence * 100),
                source="brain_rule",
                action_desc=a_next.get("action_detail", ""),
                violated_layers=violated_layers,
            )

        # ========== 白名单快速放行（两级） ==========
        action_type = a_next.get("action_type", "").lower()
        action_detail = a_next.get("action_detail", "").lower()
        heuristic_risk = heuristic_result.risk_level or "low"
        no_high_risk = heuristic_risk not in ("high", "critical")

        # --- 完全放行：跳过 L2 + L3 ---
        # agent 专属完全安全操作白名单（精确名或前缀，来自 rules.json builtin_safe_action_types）。
        # 前缀以 '-' 结尾 → startswith 匹配（如 "memory-"）；否则精确名匹配（如 "mailbox-getEmailList"）。
        # 命中即跳过 L2+L3，与 builtin_safe_skills 同范式。仅对该 agent_id 生效，不污染其他 agent。
        # OpenDesk 的 memory-*/todomgr-*/planning-* 是纯数据/只读操作，走 L3 LLM 耗时 1~137s 无意义。
        safe_action_types = (
            self._agent_ext.builtin_safe_action_types if self._agent_ext else []
        )
        # action_type 已小写化（:235）；rules.json 精确名可能是驼峰（如 mailbox-getEmailList），
        # 故比较时对白名单项也 lower。前缀项（尾随 '-'）lower 后 startswith。
        def _hit(t: str) -> bool:
            tl = t.lower()
            return (
                (tl.endswith("-") and action_type.startswith(tl))
                or (not tl.endswith("-") and action_type == tl)
            )

        is_agent_safe_action = any(_hit(t) for t in safe_action_types)
        is_fully_safe_tool = (
            action_type in FULLY_SAFE_TOOLS
            or action_type in self._profile.safe_action_types
            or is_agent_safe_action
        )
        # 内置安全 Skill 直接放行
        # 通用 baseline (TRUSTED_SKILLS) + agent_ext.builtin_safe_skills
        builtin_safe_skills = TRUSTED_SKILLS | self._skill_engine.agent_builtin_safe_skills
        is_trusted_skill = (
            action_type == "skill"
            and action_detail in builtin_safe_skills
        )
        is_fully_safe_bash = (
            action_type in ("bash", "executebash", "terminal-executebash")
            and is_fully_safe_bash_command(action_detail, self._profile)
            and no_high_risk
        )

        # 安全兜底：is_fully_safe_bash_command 只检查管道前的第一段命令，
        # 对于 "echo ... | passwd" 等管道命令，第一段 (echo) 是安全的，
        # 但完整命令包含危险模式。此处用 CommandPatternScanner 扫描完整命令，
        # 如果命中 high/critical 模式则不允许白名单放行。
        if is_fully_safe_bash:
            from .heuristic import CommandPatternScanner
            _full_cmd_scanner = CommandPatternScanner(self._profile)
            _full_scan = _full_cmd_scanner.scan(action_detail)
            if _full_scan.hit and _full_scan.risk_level in ("high", "critical"):
                is_fully_safe_bash = False
                logger.info(
                    "白名单放行覆盖: 完整命令命中高危模式 [%s]: %s",
                    _full_scan.risk_level, _full_scan.reason,
                )

        if (is_fully_safe_tool or is_trusted_skill) and no_high_risk:
            logger.info(
                "完全安全工具快速放行: action_type=%s, heuristic_risk=%s",
                action_type, heuristic_risk,
            )
            return SecurityJudgment(
                allowed=True,
                reason=f"完全安全工具，跳过深度分析: {action_type}",
                risk_level=heuristic_risk,
                source="whitelist_bypass",
                action_desc=action_detail,
            )

        if is_fully_safe_bash:
            logger.info("完全安全 bash 命令快速放行: command=%s", action_detail[:50])
            return SecurityJudgment(
                allowed=True,
                reason=f"安全的只读 bash 命令: {action_detail[:100]}",
                risk_level="low",
                source="whitelist_bypass",
                action_desc=action_detail,
            )

        # --- 轻量放行：跳过 L3，保留 L2 ---
        skip_llm = False
        if (action_type in READONLY_SENSITIVE_TOOLS or action_type in self._profile.readonly_sensitive_action_types) and no_high_risk:
            skip_llm = True
        elif (
            action_type in ("bash", "executebash", "terminal-executebash")
            and is_readonly_sensitive_bash_command(action_detail, self._profile)
            and no_high_risk
        ):
            skip_llm = True

        if skip_llm:
            logger.info(
                "只读敏感工具，跳过 LLM 分析: action_type=%s", action_type,
            )

        # ========== 层2: 逻辑规则检测 ==========
        if security_cfg.logic_rules_enabled:
            logic_result = self._logic_rules_checker.check(
                prompt_session, action_history, a_next, reason, cwd=cwd,
                prompt_history=prompt_history,
            )
            logger.debug(
                "逻辑规则检测结果: hit=%s, risk_level=%s, reason=%s",
                logic_result.hit,
                logic_result.risk_level,
                logic_result.reason,
            )
            # file_access 命中合并：敏感路径/危险模式现已在 L1（heuristic_result），
            # 间接文件访问仍在 L2（logic_result）。两者任一命中 file_access 都需进入
            # inline/credential 包装判定。优先采用 logic_result（L2 indirect 仍是 L2 职责），
            # 退而取 heuristic_result（L1 sensitive_path/dangerous）。
            l1_file_access_hit = (
                heuristic_result.hit and heuristic_result.risk_type == "file_access"
            )
            effective_result = logic_result if logic_result.hit else (
                heuristic_result if l1_file_access_hit else None
            )
            if effective_result is not None:
                # 凭据文件：无论读写、无论是否 inline，都直接拒绝。
                # 来源：L1 sensitive_path（is_credential）或 L2 indirect_file_access
                is_credential_path = (
                    getattr(effective_result, "is_credential", False)
                )
                # 内联脚本/文本输出命令：走静态语义判定，区分"文本字面量"vs"真实读写"。
                # 即使是凭据路径（如 deny_both 的 /etc/shadow），只要它是字符串字面量
                # （python -c "print('/etc/shadow')"），inline_analyzer 判 Allow 时应放行——
                # 因为并未真实读取该文件。inline_analyzer 无法提取代码（actionable=False）
                # 时才回退到凭据/敏感路径的硬拒绝。
                # 注意：此处独立判定，不依赖 Layer 1 的 skip_inline_file_access（Layer 1 可能未命中）
                is_inline_or_text = is_inline_script_cmd or is_literal_text_cmd
                if is_inline_or_text:
                    inline_judgment = analyze_inline_script(a_next.get("action_detail", ""), profile=self._profile)
                    if inline_judgment.actionable:
                        violated_layers.append("L2.1")
                        if not inline_judgment.allowed:
                            logger.info(
                                "内联脚本语义判定拦截: reason=%s", inline_judgment.reason,
                            )
                            return SecurityJudgment(
                                allowed=False,
                                reason=inline_judgment.reason,
                                risk_level=inline_judgment.risk_level,
                                risk_type=inline_judgment.risk_type,
                                confidence=90,
                                source="logic_rule",
                                action_desc=a_next.get("action_detail", ""),
                                violated_layers=violated_layers,
                            )
                        # 字面量 → Allow，不再走 Layer 3
                        return SecurityJudgment(
                            allowed=True,
                            reason=inline_judgment.reason,
                            risk_level=inline_judgment.risk_level,
                            risk_type=inline_judgment.risk_type,
                            confidence=90,
                            source="logic_rule",
                            action_desc=a_next.get("action_detail", ""),
                            violated_layers=[],
                        )
                    # actionable=False（提取不到代码）→ 回退原逻辑：high/critical 直接 Deny
                if effective_result.risk_level in ("high", "critical") and (not skip_inline_file_access or is_credential_path):
                    violated_layers.append("L2.1")
                    logger.info(
                        "逻辑规则检测拦截: violated_rule=%s, reason=%s",
                        getattr(effective_result, "violated_rule", ""),
                        effective_result.reason,
                    )
                    return SecurityJudgment(
                        allowed=False,
                        reason=effective_result.reason,
                        risk_level=effective_result.risk_level,
                        risk_type=effective_result.risk_type,
                        confidence=90,
                        source="logic_rule",
                        action_desc=a_next.get("action_detail", ""),
                        violated_layers=violated_layers,
                    )
        else:
            from .types import LogicRuleResult
            logic_result = LogicRuleResult(hit=False)

        # ========== L2.2: 形式化验证（行为图 + 性质验证，含跨会话组合链） ==========
        # 独立引擎（formal_engine）：把（多）session 历史动作构建为行为图，验证
        # 安全性质（跨会话组合链 / 敏感数据传播）。单 session 从现有 action_history
        # 构建（向后兼容）；多 session 由调用方 session_history（含未来 agentgate
        # 非侵入式采集）提供，缺省时仅用当前 session → 行为与现状一致、零回归。
        # 门控：仅 L2 总开关（形式化属 L2，不设独立开关）
        if security_cfg.logic_rules_enabled:
            formal_sessions = []
            if session_history:
                for s in session_history:
                    formal_sessions.append({
                        "session_id": str(s.get("session_id", "s")),
                        "action_history": s.get("action_history", []) or [],
                    })
            formal_sessions.append({
                "session_id": "current",
                "action_history": action_history,
            })
            formal_result = self._formal_engine.verify(
                sessions=formal_sessions,
                a_next=a_next,
            )
            if not formal_result.verified:
                v = formal_result.first_violation
                violated_layers.append("L2.2")
                if security_cfg.formal_observe_mode:
                    # observe 模式：只记录不拦截（灰度观察 FP 率用，如商用前的
                    # 大体量数据回放阶段）。违规仍标记进 violated_layers 供
                    # actrail/调用方观测，但不短路 Deny，继续走后续层。
                    logger.warning(
                        "形式化验证 observe（只记录不拦截）: property=%s risk=%s path_len=%d reason=%s",
                        v.property_id if v else "?",
                        v.risk_level if v else "?",
                        len(v.path) if v else 0,
                        (v.reason if v else "?")[:200],
                    )
                else:
                    logger.info(
                        "形式化验证拦截: property=%s risk=%s path_len=%d",
                        v.property_id if v else "?",
                        v.risk_level if v else "?",
                        len(v.path) if v else 0,
                    )
                    return SecurityJudgment(
                        allowed=False,
                        reason=v.reason if v else "形式化验证未通过（行为性质违反）",
                        risk_level=v.risk_level if v else "high",
                        risk_type="formal_verification",
                        confidence=90,
                        source="formal_engine",
                        action_desc=a_next.get("action_detail", ""),
                        violated_layers=violated_layers,
                    )

        # ========== L2.3: 脚本内容 L2 扫描（对预处理后脚本内容做 L2 规则检测） ==========
        # 对脚本调用链中每个节点的预处理内容，复用 L2 的敏感路径/危险模式/意图偏离检测。
        if script_chain_result and script_chain_result.nodes and security_cfg.logic_rules_enabled:
            scan_script_chain_with_l2(
                script_chain_result, self._logic_rules_checker, prompt_session
            )
            for node in script_chain_result.nodes:
                if node.l2_hit and node.l2_risk_level in ("high", "critical"):
                    violated_layers.append("L2.3")
                    logger.info(
                        "脚本内容 L2 拦截: path=%s, depth=%d, violated_rule=%s, reason=%s",
                        node.script_path, node.depth, node.l2_violated_rule, node.l2_reason,
                    )
                    return SecurityJudgment(
                        allowed=False,
                        reason=node.l2_reason,
                        risk_level=node.l2_risk_level,
                        risk_type=node.l2_risk_type,
                        confidence=85,
                        source="logic_rule_script_scan",
                        action_desc=a_next.get("action_detail", ""),
                        violated_layers=violated_layers,
                    )

        # ========== Brain Layer 2 规则检查 ==========
        brain_l2_deny = self._check_brain_rules_layer(a_next, layer=2, action_history=action_history)
        if brain_l2_deny:
            violated_layers.append("brain_L2")
            logger.info("Brain Layer 2 规则拦截: %s", brain_l2_deny.explanation[:100])
            return SecurityJudgment(
                allowed=False,
                reason=f"[Brain L2] {brain_l2_deny.explanation}",
                risk_level="high",
                risk_type="brain_rule",
                confidence=int(brain_l2_deny.confidence * 100),
                source="brain_rule",
                action_desc=a_next.get("action_detail", ""),
                violated_layers=violated_layers,
            )

        # ========== L3.1: LLM + Skill 深度分析 ==========
        if skip_llm:
            return SecurityJudgment(
                allowed=True,
                reason="只读操作且无逻辑规则违规，跳过 LLM 分析",
                risk_level=logic_result.risk_level or "low",
                source="heuristic_and_logic_only",
                action_desc=action_detail,
                violated_layers=violated_layers,
            )

        llm_analysis_enabled = security_cfg.llm_analysis_enabled and is_llm_enabled()

        # 收集 L2 禁用且 skip_l3_on_disabled 的规则关键内容，命中时作为硬约束
        # 传给 L3：对这些路径/关键词必须放行，但 L3 仍分析命令其他部分的安全风险。
        # runtime_config 模块在 Stage 2 才落地；缺失时 get_disabled_l2_rules_with_skip_l3
        # 返回空，skip_l3_hints 为默认"无"，不影响主流程。
        skip_l3_hints = "无（当前无禁用规则命中）"
        try:
            from ..infra.runtime_config import get_disabled_l2_rules_with_skip_l3
            disabled_l2 = get_disabled_l2_rules_with_skip_l3()
            if disabled_l2:
                action_lower = a_next.get("action_detail", "").lower()
                matched_items: list[str] = []
                for _cat, items in disabled_l2.items():
                    for item in items:
                        if item.lower() in action_lower:
                            matched_items.append(item)
                if matched_items:
                    skip_l3_hints = (
                        f"⚠️ 重要约束：用户已主动禁用针对以下内容的安全拦截规则，这是用户的明确决策：\n"
                        f"  {', '.join(matched_items)}\n"
                        f"对这些路径/关键词的相关操作，必须视为允许的，不允许仅因涉及这些内容就拒绝。"
                        f"但你仍需检查命令的其他部分是否有独立于这些内容的安全风险（如网络外传、提权等）。"
                    )
                    logger.info(
                        "L3 skip_l3_hints: action_detail 命中了禁用规则的 skip_l3 内容（硬约束）: %s",
                        matched_items,
                    )
        except Exception:
            pass  # runtime_config 缺失或异常时不影响 L3

        if llm_analysis_enabled:
            try:
                llm_judgment = self._llm_analyzer.analyze(
                    prompt_session=prompt_session,
                    action_history=action_history,
                    a_next=a_next,
                    reason=reason,
                    heuristic_result=heuristic_result,
                    logic_result=logic_result,
                    config=config,
                    llm_config=llm_config,
                    skip_l3_hints=skip_l3_hints,
                    script_chain_result=script_chain_result,
                    llm_log_path=llm_log_path,
                    prompt_history=prompt_history,
                )
            except Exception as e:
                logger.warning("LLM 分析异常: %s", e)
                # 前两层已拦截 → 无论 fail_mode 都 Deny
                if violated_layers:
                    return SecurityJudgment(
                        allowed=False,
                        reason=f"LLM 分析失败且前序检测已拦截: {e}",
                        risk_level="high",
                        source="llm_failure_with_violation",
                        action_desc=a_next.get("action_detail", ""),
                        violated_layers=violated_layers,
                    )
                # 纯靠 L3 时 LLM 挂了：按 fail_mode 决策
                # - fail_open（默认）：Allow + 警告，可用性优先
                # - fail_closed：Deny，安全优先
                from ..infra.config import get_llm_fail_mode
                if get_llm_fail_mode() == "fail_open":
                    logger.warning(
                        "LLM 分析失败，fail_open 模式：允许执行（前两层未拦截）: %s", e
                    )
                    return SecurityJudgment(
                        allowed=True,
                        reason=f"LLM 分析失败（warn-allow，fail_open）: {e}",
                        risk_level="low",
                        source="llm_failure_fallback",
                        action_desc=a_next.get("action_detail", ""),
                        violated_layers=violated_layers,
                    )
                return SecurityJudgment(
                    allowed=False,
                    reason=f"LLM 分析失败，因无法完成深度语义分析，按 fail-closed 原则拒绝: {e}",
                    risk_level="medium",
                    source="llm_failure_fallback",
                    action_desc=a_next.get("action_detail", ""),
                )
            if not llm_judgment.allowed:
                violated_layers.append("L3.1")
                llm_judgment.violated_layers = violated_layers
                # Layer 3 Deny → 异步喂给 Brain 提取规则和 Skill（仅启用时）
                if (
                    self._brain_enabled
                    and llm_judgment.confidence and llm_judgment.confidence >= 90
                ):
                    try:
                        self._ensure_brain()
                        self._brain_extractor.extract(
                            event={"action_detail": action_detail, "event_id": ""},
                            llm_result={
                                "confidence": llm_judgment.confidence / 100.0,
                                "reason": llm_judgment.reason or "",
                                "risk_type": llm_judgment.risk_type or "",
                                "action_detail": action_detail,
                            },
                        )
                    except Exception as e:
                        logger.debug("Brain 提取异常（不影响主流程）: %s", e)
            elif "L2.2" in violated_layers:
                # observe 模式：formal 引擎命中但未拦截 → 把标记合并进 LLM Allow 结果，
                # 使调用方/actrail 可见"本会拦但未拦"（与 skip_llm / LLM 禁用路径一致）。
                llm_judgment.violated_layers = list(dict.fromkeys(
                    ["L2.2", *llm_judgment.violated_layers]
                ))
            return llm_judgment
        else:
            return SecurityJudgment(
                allowed=True,
                reason="前两层检测均未发现高风险问题，LLM 分析已禁用",
                risk_level="low",
                source="heuristic_and_logic_only",
                action_desc=a_next.get("action_detail", ""),
                violated_layers=violated_layers,
            )

    def _maybe_run_brain_maintenance(self) -> None:
        """节流执行 Brain curator 维护（draft 自动激活 + 生命周期）。

        频率：每 BRAIN_MAINT_INTERVAL 秒最多一次（默认 300s）。失败不影响主流程。
        """
        try:
            import time as _time
            now = _time.time()
            if self._brain_last_maintenance and \
                    now - self._brain_last_maintenance < 300:
                return
            self._ensure_brain()
            if self._brain_curator:
                self._brain_curator.run_maintenance(auto_approve=True)
            self._brain_last_maintenance = now
        except Exception as e:
            logger.debug("Brain 维护异常（不影响主流程）: %s", e)

    def _ensure_brain(self):
        """惰性实例化 Brain 模块（仅当 AGENT_MOSS_BRAIN_ENABLED=1 时被调用）"""
        if self._brain_rule_store is not None:
            return
        from ..brain.curator import BrainCurator
        from ..brain.pattern_extractor import PatternExtractor
        from ..brain.rule_store import BrainRuleStore
        from ..brain.skill_manager import BrainSkillManager

        _skills_dir = self._skills_dir or (Path(__file__).parent.parent / "skills")
        self._brain_rule_store = BrainRuleStore()
        self._brain_skill_manager = BrainSkillManager(
            skills_dir=_skills_dir, skill_engine=self._skill_engine
        )
        # 去重：收集内置规则正则以传给 extractor。源 = profile dangerous_commands
        # pattern + sensitive_paths deny 路径 + runtime_config L1 命令规则。
        # 新增 pattern 若被内置规则覆盖则跳过，避免与 L1/L2 重复。
        builtin_patterns: list[str] = []
        try:
            for cp in self._profile.dangerous_commands:
                builtin_patterns.append(cp.pattern)
            for sp in self._profile.sensitive_paths:
                if sp.deny_mode in ("deny_both", "deny_write", "deny_read"):
                    builtin_patterns.append(re.escape(sp.path))
                elif sp.credential:
                    builtin_patterns.append(re.escape(sp.path))
        except Exception:
            pass
        try:
            from ..infra.runtime_config import (
                get_enabled_l1_command_patterns_or_default,
                has_runtime_config,
                load_runtime_config,
            )
            if has_runtime_config():
                runtime = load_runtime_config()
                enabled = get_enabled_l1_command_patterns_or_default(runtime)
                if enabled:
                    for p in enabled:
                        if isinstance(p, dict):
                            builtin_patterns.append(p.get("pattern", ""))
                        else:
                            builtin_patterns.append(getattr(p, "pattern", ""))
        except Exception:
            pass
        builtin_patterns = [p for p in builtin_patterns if p]

        self._brain_extractor = PatternExtractor(
            rule_store=self._brain_rule_store,
            skill_manager=self._brain_skill_manager,
            builtin_patterns=builtin_patterns,
            reviewer=self._make_brain_reviewer(),
        )
        self._brain_curator = BrainCurator(
            self._brain_rule_store, self._brain_skill_manager
        )

    def _make_brain_reviewer(self):
        """创建 Brain LLM 审核器。无 LLM 配置时 reviewer 内部会降级（返回 None）。

        审核是 L3 Deny 后的一次额外 LLM 调用（只对达到阈值的候选，且每 pattern 一生
        最多一次）。默认开启；可通过 AGENT_MOSS_BRAIN_REVIEW=0 关闭。
        """
        try:
            if os.getenv("AGENT_MOSS_BRAIN_REVIEW") == "0":
                return None
            from ..brain.reviewer import BrainReviewer
            return BrainReviewer(timeout=10.0)
        except Exception as e:
            logger.debug("Brain 审核器初始化跳过: %s", e)
            return None

    def _check_brain_rules_layer(
        self,
        a_next: dict[str, str],
        layer: int,
        action_history: list[dict] | None = None,
    ) -> "BrainRule | None":
        """检查 Brain 指定 layer 的活跃规则，返回匹配的规则或 None"""
        if not self._brain_enabled or self._brain_rule_store is None:
            return None
        try:
            rules = self._brain_rule_store.get_active_rules(layer=layer)
            if not rules:
                return None

            action_detail = a_next.get("action_detail", "").lower()
            action_type = a_next.get("action_type", "").lower()
            combined = f"{action_type} {action_detail}"

            for rule in rules:
                try:
                    if re.search(rule.pattern, combined, re.IGNORECASE):
                        # Layer 2 规则可能需要检查 action_history
                        if layer == 2 and action_history:
                            if not self._check_layer2_context(rule, action_history, a_next):
                                continue
                        self._brain_rule_store.record_trigger(rule.id)
                        return rule
                except re.error:
                    logger.debug("Brain 规则正则错误: %s", rule.pattern)
                    continue
        except Exception as e:
            logger.debug("Brain 规则检查异常: %s", e)
        return None

    def _check_layer2_context(
        self,
        rule: "BrainRule",
        action_history: list[dict],
        a_next: dict[str, str],
    ) -> bool:
        """Layer 2 类型的 Brain 规则需要检查上下文"""
        # 行为链模式匹配
        if rule.pattern.startswith("BEHAVIOR_CHAIN:"):
            chain_type = rule.pattern.replace("BEHAVIOR_CHAIN:", "")
            if chain_type == "external_read→sensitive_write":
                # 检查历史中是否有外部读取 + 当前是敏感写入
                has_external_read = any(
                    "curl" in str(h.get("action_detail", "")).lower()
                    or "wget" in str(h.get("action_detail", "")).lower()
                    or "http" in str(h.get("action_detail", "")).lower()
                    for h in action_history[-5:]
                )
                is_sensitive_write = any(
                    k in a_next.get("action_detail", "").lower()
                    for k in [".ssh", ".gnupg", "authorized_keys", "bashrc", "profile"]
                )
                return has_external_read and is_sensitive_write
            if chain_type == "multi_config_read→privilege_action":
                # 检查历史中是否连续读取多个配置文件
                config_reads = sum(
                    1 for h in action_history[-5:]
                    if any(k in str(h.get("action_detail", "")).lower()
                           for k in ["/etc/", "config", ".conf", ".yaml", ".json"])
                )
                is_privilege = any(
                    k in a_next.get("action_detail", "").lower()
                    for k in ["sudo", "su ", "chmod", "chown"]
                )
                return config_reads >= 2 and is_privilege
            return False
        # 非行为链规则，正则已匹配，直接通过
        return True


def judge_security(
    prompt_session: str,
    action_history: list[dict[str, object]],
    a_next: dict[str, str],
    reason: str,
    config: Config,
    profile: "OSProfile | None" = None,
    llm_config: dict | None = None,
    cwd: str = "",
    agent_id: str = "",
    scenario_id: str = "",
    llm_log_path: str | None = None,
    prompt_history: list[dict[str, object]] | None = None,
    session_history: list[dict[str, object]] | None = None,
) -> SecurityJudgment:
    """
    便捷函数：执行 AgentMoss 安全判断。

    Args:
        prompt_session: 用户输入的原始 prompt
        action_history: 历史动作序列
        a_next: 下一步动作
        reason: 执行理由
        config: 全局配置
        profile: OS Profile（可选，默认自动检测）
        llm_config: 每请求 LLM 配置（可选）
        cwd: 当前工作目录（用于间接文件访问检测）
        agent_id: 调用方 agent 标识（如 "xiaoo"），用于加载该 agent 专属规则
        scenario_id: 调用方场景标识（如 "bank"），用于加载场景定制规则
            （客户沙箱的目录访问边界/禁 ssh 等）。空时兜底环境变量
            AGENT_MOSS_SCENARIO（部署级，客户沙箱设一次，所有请求生效）。
        llm_log_path: 每请求 LLM prompt 日志路径（可选，per-request 注入）
        prompt_history: 完整的交错历史 prompt（可选），供 L2/L3 使用。
        session_history: 多 session 历史动作（可选），每项 {"session_id",
            "action_history": [...]}。供 L2.2 形式化引擎跨会话验证。

    Returns:
        SecurityJudgment: 安全判断结果
    """
    from ..agents import get_agent_extensions
    from ..scenarios import get_scenario_extensions_multi
    from ..agents.base import AgentExtensions
    from ..infra.runtime_config import is_layer_enabled

    def _layer_on(key: str) -> bool:
        try:
            return is_layer_enabled(key)
        except Exception:
            return True

    # Agent 专属规则总开关（console 层级全局开关可关，agent_rules_enabled）
    agent_ext = get_agent_extensions(agent_id) if _layer_on("agent_rules_enabled") else None
    # 场景规则：调用方显式 scenario_id > 环境变量 AGENT_MOSS_SCENARIO（部署级兜底）。
    # env 支持逗号分隔多场景（如 AGENT_MOSS_SCENARIO=bank,meow），multi 逐场景合并。
    # 场景总开关（console 层级全局开关可关，scenario_rules_enabled）。
    eff_scenario_spec = scenario_id or os.getenv("AGENT_MOSS_SCENARIO", "")
    scenario_ext = get_scenario_extensions_multi(eff_scenario_spec) if _layer_on("scenario_rules_enabled") else None
    ext = AgentExtensions.merge(agent_ext, scenario_ext)
    agent = AgentMossBot(
        profile=profile,
        rules_path=config.security.rules_path,
        skills_dir=config.security.skills_dir,
        agent_ext=ext,
    )
    return agent.judge(prompt_session, action_history, a_next, reason, config, llm_config=llm_config, cwd=cwd, llm_log_path=llm_log_path, prompt_history=prompt_history, session_history=session_history)
