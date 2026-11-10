"""API route definitions for AgentMoss (v2: with OS auto-detection and adapter)."""

import asyncio
import os
import platform
import time
import logging

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from ..__version__ import __version__
from .models import (
    AnalyzeRequest,
    AnalyzeResponse,
    HealthResponse,
    ErrorResponse,
    ReviewRequest,
    ReviewResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1")


# ==================== Stateful incremental (L2.2 有状态) ====================

def _chain_state_for_agent(agent_id: str):
    """拿到某 agent 的链状态仓储（按 agent_id 分桶）。"""
    from ..engine.formal_engine.chain_state import get_chain_state_store
    store = get_chain_state_store()
    return _AgentState(store, agent_id or "default")


class _AgentState:
    """轻封装：某 agent 的 chain_state 读写。"""

    def __init__(self, store, agent_id: str):
        self.store = store
        self.agent_id = agent_id

    def apply_incremental(
        self,
        a_next: dict,
        session_id: str,
        is_error: bool = False,
    ) -> dict:
        r = self.store.apply_action(
            self.agent_id, a_next=a_next, session_id=session_id, is_error=is_error
        )
        return {
            "matched": r.matched.to_judgment() if r.matched else None,
            "exfil": r.exfil,
            "pending_prefixes": [
                {
                    "chain_id": p.chain_id,
                    "matched": p.matched,
                    "next_stage": p.next_stage,
                    "risk_level": p.risk_level,
                }
                for p in r.pending_prefixes
            ],
            "should_block": r.should_block,
        }

    def seed_full(self, sessions: list[dict]) -> int:
        t = self.store.load_or_new(self.agent_id)
        added = t.seed(sessions)
        self.store.save(t)
        return added


# ==================== Brain API ====================

def _get_brain_store():
    from ..brain.rule_store import BrainRuleStore
    return BrainRuleStore()

def _get_brain_skill_manager():
    from ..brain.skill_manager import BrainSkillManager
    from pathlib import Path
    skills_dir = Path(__file__).parent.parent / "skills"
    return BrainSkillManager(skills_dir=skills_dir)


class BrainRuleResponse(BaseModel):
    id: str
    layer: int
    rule_type: str
    pattern: str
    scope: str
    confidence: float
    status: str
    explanation: str
    trigger_count: int
    disputed_count: int


class BrainStatsResponse(BaseModel):
    draft: int = 0
    approved: int = 0
    active: int = 0
    disputed: int = 0
    stale: int = 0
    archived: int = 0
    total: int = 0
    by_layer: dict = {}
    pattern_candidates: int = 0


@router.get("/brain/rules")
async def get_brain_rules(
    layer: int | None = Query(None, description="按 layer 过滤 (1 或 2)"),
    status: str = Query("active", description="按状态过滤"),
):
    """获取 Brain 规则（AgentGate 拉取用）"""
    store = _get_brain_store()
    try:
        rules = store.get_active_rules(layer=layer)
        return {
            "rules": [
                {
                    "id": r.id,
                    "layer": r.layer,
                    "rule_type": r.rule_type,
                    "pattern": r.pattern,
                    "scope": r.scope,
                    "confidence": r.confidence,
                    "explanation": r.explanation,
                }
                for r in rules
            ]
        }
    finally:
        store.close()


@router.get("/brain/rules/drafts")
async def get_brain_drafts():
    """获取待审核的 Brain 规则"""
    store = _get_brain_store()
    try:
        drafts = store.get_draft_rules()
        return {
            "drafts": [
                {
                    "id": r.id,
                    "layer": r.layer,
                    "rule_type": r.rule_type,
                    "pattern": r.pattern,
                    "scope": r.scope,
                    "confidence": r.confidence,
                    "explanation": r.explanation,
                    "source_event_ids": r.source_event_ids,
                }
                for r in drafts
            ]
        }
    finally:
        store.close()


@router.post("/brain/rules/{rule_id}/approve")
async def approve_brain_rule(rule_id: str):
    """审核通过 Brain 规则"""
    store = _get_brain_store()
    try:
        store.approve_rule(rule_id)
        return {"status": "approved"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        store.close()


@router.post("/brain/rules/{rule_id}/reject")
async def reject_brain_rule(rule_id: str, reason: str = ""):
    """拒绝 Brain 规则"""
    store = _get_brain_store()
    try:
        store.reject_rule(rule_id, reason)
        return {"status": "rejected"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        store.close()


@router.get("/brain/stats")
async def get_brain_stats():
    """获取 Brain 统计信息"""
    store = _get_brain_store()
    try:
        return store.get_stats()
    finally:
        store.close()


@router.get("/brain/skills")
async def get_brain_skills():
    """获取 Brain Skills"""
    mgr = _get_brain_skill_manager()
    try:
        skills = mgr.get_active_skills()
        return {"skills": skills}
    finally:
        mgr.close()


@router.get("/brain/rules/export")
async def export_brain_rules():
    """导出本地 Brain 规则（预留中心化）"""
    store = _get_brain_store()
    try:
        rules = store.get_rules_for_export()
        return {
            "rules": [
                {
                    "id": r.id,
                    "layer": r.layer,
                    "rule_type": r.rule_type,
                    "pattern": r.pattern,
                    "scope": r.scope,
                    "confidence": r.confidence,
                    "explanation": r.explanation,
                    "origin_node": r.origin_node,
                }
                for r in rules
            ]
        }
    finally:
        store.close()


@router.post("/brain/rules/import")
async def import_brain_rules(rules: list[dict]):
    """导入中心下发规则（预留中心化）"""
    from ..brain.rule_store import BrainRule
    store = _get_brain_store()
    try:
        imported = []
        for r in rules:
            imported.append(BrainRule(
                layer=r.get("layer", 1),
                rule_type=r.get("rule_type", ""),
                pattern=r.get("pattern", ""),
                scope=r.get("scope", "all"),
                confidence=r.get("confidence", 0.9),
                explanation=r.get("explanation", ""),
            ))
        store.import_rules(imported)
        return {"imported": len(imported)}
    finally:
        store.close()


# ==================== 原有 API ====================


@router.get("/health", response_model=HealthResponse)
async def health():
    return HealthResponse(
        status="healthy",
        version=__version__,
        instance=os.getenv("AGENT_MOSS_INSTANCE", ""),
    )


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest):
    try:
        from ..adapters.observable import is_raw_format
        from ..engine.analyzer import analyze as run_analysis
        from ..profiles import get_profile

        # Step 1: 适配器转换（如果传入的是原始 syscall 格式）
        data = req.model_dump()
        if is_raw_format(data):
            from ..adapters import ObservableAdapter
            adapter = ObservableAdapter()
            adapted = adapter.adapt(data)
            # 合并适配后的字段回 req
            session_id = adapted.get("session_id", req.session_id)
            prompt_session = adapted.get("prompt_session", req.prompt_session)
            a_next = {"action_type": adapted["a_next"]["action_type"], "action_detail": adapted["a_next"]["action_detail"]}
            action_history = [{"name": h.get("name", ""), "action_detail": h.get("action_detail", "")} for h in adapted.get("action_history", [])]
            reason = adapted.get("reason", req.reason)
            os_type = adapted.get("os_type", req.os_type)
            cwd = adapted.get("cwd", req.cwd)
        else:
            session_id = req.session_id
            prompt_session = req.prompt_session
            a_next = {"action_type": req.a_next.action_type, "action_detail": req.a_next.action_detail}
            action_history = [{"name": h.action_type, "action_detail": h.action_detail} for h in req.action_history]
            reason = req.reason
            os_type = req.os_type
            cwd = req.cwd

        # prompt_history: 完整的交错历史 prompt（可选）。每轮 {"text", "actions"}，
        # 供 L2 意图一致性 / L3 语义分析使用；空则回退单条 prompt_session。
        prompt_history = [
            {"text": t.text, "actions": [{"action_type": a.action_type, "action_detail": a.action_detail} for a in t.actions]}
            for t in req.prompt_history
        ]

        # session_history: 多 session 历史动作（可选），每项 {"session_id",
        # "action_history": [{action_type, action_detail}]}。供 L2.2 形式化引擎
        # 跨会话组合链/敏感数据传播验证；由调用方（含 agentgate）提供。
        session_history = [
            {
                "session_id": s.get("session_id", ""),
                "action_history": [
                    {"action_type": a.get("action_type", ""), "action_detail": a.get("action_detail", "")}
                    for a in s.get("action_history", [])
                ],
            }
            for s in req.session_history
        ]

        # agent_id 透传：用于加载三方 agent 定制化规则（agent_moss/agents/<id>/rules.json）
        # 优先顶层 agent_id；为空时兜底从 metadata.agent_type 取（AgentGate V1
        # normalizer 历史上只把 agent_type 塞进 metadata，顶层 agent_id 为空 →
        # 定制规则不生效。AgentGate 已修，此处兜底防御其他只传 metadata 的调用方）。
        agent_id = req.agent_id
        if not agent_id and req.metadata:
            agent_id = str(req.metadata.get("agent_type") or "")

        # Step 2: OS 自动检测
        if not os_type:
            os_type = platform.system().lower()
            # 非 Windows 统一用 linux
            if os_type != "windows":
                os_type = "linux"

        # Step 3: 获取 OS Profile 并调用分析引擎
        profile = get_profile(os_type)

        start = time.monotonic()
        # Run analysis in a thread pool to avoid blocking the event loop.
        # Without this, the health endpoint and new connections hang while
        # analysis is in progress (synchronous blocking call in async handler).
        loop = asyncio.get_event_loop()
        llm_config = req.metadata.get("llm_config") if req.metadata else None
        llm_log_path = req.metadata.get("llm_log_path") if req.metadata else None
        # ⚠️ 必须用关键字参数调用 analyze：analyze 签名含 scenario_id（6abe6c6 在
        # llm_log_path 之前插入），此前按位置传参（14 实参对 15 形参）从第 12 位起
        # 全部右错一位——llm_log_path 被绑成 scenario_id（LLM_PROMPT 日志静默丢失，
        # xiaoO hkl.log 无 [LLM_PROMPT] 行的根因）、prompt_history 被绑成 llm_log_path
        # （open(list) TypeError 被 _log_prompt 吞掉）、session_history 被绑成
        # prompt_history（L2.2 跨会话注入从 HTTP 入口一直失效）。改关键字参数根治。
        result = await loop.run_in_executor(
            None,
            lambda: run_analysis(
                session_id=session_id,
                prompt_session=prompt_session,
                action_history=action_history,
                a_next=a_next,
                reason=reason,
                config=None,       # 用默认配置
                cache=None,        # 用默认缓存
                profile=profile,   # OS Profile
                llm_config=llm_config,      # 来自 req.metadata.llm_config
                cwd=cwd,
                agent_id=agent_id,
                scenario_id="",    # 部署级兜底走 env AGENT_MOSS_SCENARIO
                llm_log_path=llm_log_path,  # 来自 req.metadata.llm_log_path（per-request 日志路径）
                prompt_history=prompt_history,   # 交错历史 prompt（可选）
                session_history=session_history,  # 多 session 历史（L2.2 跨会话验证）
            ),
        )
        duration_ms = (time.monotonic() - start) * 1000

        # Report enforcement event to AcTrail (fire-and-forget)
        try:
            from ..infra.actrail import report_enforcement_event
            report_enforcement_event(
                trace_id=session_id,
                decision=result["decision"].lower(),
                tool_name=a_next.get("action_type", ""),
                tool_command=a_next.get("action_detail", ""),
                session_id=session_id,
                prompt=prompt_session,
                risk_level=result.get("risk_level", ""),
                risk_type=result.get("risk_type", ""),
                reason=result.get("reason", ""),
                violated_layers=result.get("violated_layers", []),
                confidence=result.get("confidence", 100),
                duration_ms=duration_ms,
            )
        except Exception:
            pass  # Non-fatal, never block the response

        # ========== L2.2 stateful incremental（有状态实时判定，可选启用） ==========
        # 调用方在 metadata.stateful_incremental=true 时启用：把当前动作推入该 agent
        # 的持久化时间线，若当前动作补全某组合链（跨 session/长时距前序已就位）→ Deny。
        # 不启用则行为与现状一致（零回归）。提交的违例作为补充判定覆盖 L1-L3 结果。
        metadata = req.metadata or {}
        if str(metadata.get("stateful_incremental", "") or "").lower() in ("1", "true", "yes", "on"):
            try:
                inc = _chain_state_for_agent(agent_id).apply_incremental(
                    a_next,
                    session_id=session_id,
                    is_error=bool(metadata.get("is_error", False)),
                )
                if inc["should_block"]:
                    j = inc["matched"] or (inc["exfil"][0] if inc["exfil"] else None)
                    if j is not None:
                        violated = list(result.get("violated_layers", []))
                        if "L2.2-stateful" not in violated:
                            violated.append("L2.2-stateful")
                        result = dict(result)
                        result.update(
                            decision="Deny",
                            reason=j.get("reason", "有状态增量链判定：组合攻击链命中"),
                            risk_level=j.get("risk_level", "high"),
                            risk_type="formal_verification",
                            violated_layers=violated,
                            # 反例路径：每步 [session_id, seq, stage, timestamp]
                            violation_chain=j.get("path", []) or [],
                        )
                        logger.info(
                            "stateful 增量拦截: agent=%s property=%s risk=%s",
                            agent_id or "-", j.get("property_id", "?"), j.get("risk_level", "?"),
                        )
            except Exception as e:
                logger.warning("stateful incremental 异常（不阻断响应）: %s", e)

        return AnalyzeResponse(
            decision=result["decision"],
            reason=result["reason"],
            risk_level=result.get("risk_level", "low"),
            risk_type=result.get("risk_type", ""),
            violated_layers=result.get("violated_layers", []),
            policy=result.get("policy", ""),
            violated_policy=result.get("violated_policy", ""),
            confidence=result.get("confidence", 100),
            analysis_duration_ms=duration_ms,
            violation_chain=result.get("violation_chain", []) or [],
        )
    except Exception as e:
        logger.exception("Analysis failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/review", response_model=ReviewResponse)
async def review(req: ReviewRequest):
    """低频全量回顾：seed 全量历史（AgentGate 本地存储直读或显式 sessions）→
    FormalEngine 全量验证 + 提取待攻击前序 → 写回链状态库。

    这是"从开始记录就持续累积前序链"的落点：
    - db_path：AgentGate SQLite/JSON 路径，服务端直读全量 tool_calls（不复制存储）；
    - sessions：显式传入多 session 历史（兜底）；
    - a_next（可选）：seed 后连同当前动作一起判定（模拟一次 advance）。
    """
    try:
        from ..engine.formal_engine import FormalEngine
        from ..engine.formal_engine.chain_state import get_chain_state_store
        from .agent_gate_reader import load_agent_gate_sessions

        agent_id = req.agent_id or "default"
        store = get_chain_state_store()
        tracker = store.load_or_new(agent_id)

        # 1. 读取历史（db_path 直读 > 显式 sessions）
        sessions: list[dict] = []
        if req.db_path:
            sessions = load_agent_gate_sessions(req.db_path)
            if not sessions:
                sessions = req.sessions if req.sessions else []
        else:
            sessions = req.sessions if req.sessions else []
        added = tracker.seed(sessions) if sessions else 0
        store.save(tracker)

        # 2. 全量 FormalEngine 验证（跨会话组合链 / 敏感数据传播）
        #    用"本次 seed 的 sessions（多 session 原始结构）+ 当前已累积节点"构建
        #    多 session 行为图，正确跨越 session 边界匹配链。
        verified = True
        violations: list[dict] = []
        if sessions or tracker.nodes:
            eng = FormalEngine()
            # 历史用本次 seed 的 sessions（多 session）；若 db 直读则用读出来的 sessions。
            verify_sessions = sessions or [
                {"session_id": tracker.agent_id, "action_history": [
                    {"action_type": n.action_type, "action_detail": n.action_detail}
                    for n in tracker.nodes
                ]}
            ]
            full = eng.verify(
                sessions=verify_sessions,
                a_next=(
                    {"action_type": req.a_next.action_type, "action_detail": req.a_next.action_detail}
                    if req.a_next else None
                ),
            )
            verified = full.verified
            violations = [
                {"property_id": v.property_id, "reason": v.reason, "risk_level": v.risk_level, "path": v.path}
                for v in full.violations
            ]

        # 3. 提取待攻击前序（写回状态库的"前序链"概念）
        pending = [
            {"chain_id": p.chain_id, "matched": p.matched, "next_stage": p.next_stage, "risk_level": p.risk_level}
            for p in tracker.pending_prefixes
        ]

        # 4. 数据驱动发现：跨 session 频繁危险组合（预置链外的新形态）
        #    复用 verify_sessions（本次 seed 的历史），低频挖掘，不进实时路径。
        discovered = []
        if sessions:
            from ..engine.formal_engine.pattern_miner import mine_dangerous_patterns
            discovered = mine_dangerous_patterns(
                verify_sessions if sessions else [],
                min_sup=2,
            )

        return ReviewResponse(
            agent_id=agent_id,
            seeded_nodes=added,
            verified=verified,
            violations=violations,
            pending_prefixes=pending,
            state_nodes=len(tracker.nodes),
            discovered_patterns=discovered,
        )
    except Exception as e:
        logger.exception("Review failed")
        raise HTTPException(status_code=500, detail=str(e))
