"""API route definitions for AgentMoss (v2: with OS auto-detection and adapter)."""

import asyncio
import os
import platform
import time
import logging
import uuid

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel
from ..__version__ import __version__
from ..engine.skill_engine import default_skills_dir
from ..infra import security_policy as sp
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


def _internal_error(exc: Exception) -> HTTPException:
    """500 错误归一化：默认只回一个 ref，完整堆栈留在服务端日志。

    ``str(e)`` 会把内部路径、配置值、解析片段带进响应体。调用方**本身就是被
    检测对象**，拿到这些可以据此规避（设计说明书 14.4.1 / SEC-10）。
    需要旧行为排查问题时设 ``AGENT_MOSS_ERROR_DETAIL=full``。
    """
    if sp.error_detail_mode() == "full":
        return HTTPException(status_code=500, detail=str(exc))
    ref = uuid.uuid4().hex[:8]
    logger.exception("内部错误（ref=%s）", ref)
    return HTTPException(status_code=500, detail=f"Internal server error (ref: {ref})")


# ==================== Stateful incremental (L2.2 有状态) ====================

def _chain_state_for_agent(agent_id: str):
    """拿到链状态仓储。

    分桶由 ``AGENT_MOSS_CHAIN_SCOPE`` 决定：默认 ``system`` —— 所有 agent 共用
    一个桶（组合攻击针对的是这台服务器，换 agent 分步实施也不能漏）；只有多租户
    部署才切到 ``agent`` 模式。
    """
    from ..engine.formal_engine.chain_state import get_chain_state_store
    from ..infra import security_policy as sp

    store = get_chain_state_store()
    return _AgentState(store, sp.chain_bucket(agent_id))


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
        source_agent: str = "",
        instance_id: str = "",
    ) -> dict:
        r = self.store.apply_action(
            self.agent_id,
            a_next=a_next,
            session_id=session_id,
            is_error=is_error,
            source_agent=source_agent,
            instance_id=instance_id,
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
    skills_dir = default_skills_dir()
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
async def analyze(req: AnalyzeRequest, request: Request):
    try:
        from ..engine.analyzer import analyze as run_analysis
        from ..profiles import get_profile

        # Step 1: 取字段（原始可观测格式已在 **模型校验前** 适配成标准格式 —— 见
        # models.py::AnalyzeRequest._adapt_observable_format。这里不再分支：
        # 原先的 `is_raw_format(req.model_dump())` 分支是**不可达死代码**，
        # 因为真正的原始 payload 缺少必填的 a_next，会在校验处 422。）
        session_id = req.session_id
        prompt_session = req.prompt_session
        # called_at 一并透传：L2 授权（consent）的时效窗（CONSENT_TTL_SECONDS）
        # 需要「提问时刻」与「本次动作时刻」两侧都有时间戳才生效；缺了它就只剩
        # 「最近 N 条」的距离窗口兜底。
        a_next = {
            "action_type": req.a_next.action_type,
            "action_detail": req.a_next.action_detail,
            "called_at": req.a_next.called_at,
        }
        # ⚠️ 必须透传 output（工具返回 = 用户对 ask_user_question 的回答）。
        # L2 的授权（consent）判定看的是**用户答了什么**（logic_rules.py 的
        # `action.get("output", "")`），不是提问正文。历史 bug：这里只映射
        # name/action_detail，output 被丢掉 → 即使调用方传了用户已确认的回答，
        # 引擎看到的仍是空 → 已授权的改密/删用户被判「未授权」。
        # （TS 路由 routes.ts 早已透传 output，双端在此分叉；2026-10 修正。）
        action_history = [
            {**h.model_dump(), "name": h.action_type} for h in req.action_history
        ]
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

        # 安全（2026-10）：启用「每 agent 一个 token」后，请求声明的 agent_id 必须与
        # token 对应 —— 否则任何人都能声称自己是 xiaoo 并往它的时间线里写东西。
        # 未配置该模式时 principal 为空、bind_agent 恒放行（与历史行为一致）。
        _principal = sp.principal_of(request.headers, request.url.path)
        _bound_ok, agent_id = sp.bind_agent(_principal, agent_id)
        if not _bound_ok:
            raise HTTPException(
                status_code=403,
                detail=f"agent_id 与所持凭证不匹配: {agent_id}",
            )

        # 跨会话批量访问信号（2026-10）：正常 agent 只用自己的会话；拿到 token 的
        # 冒充者为了凑组合链反例路径，常在短时间内声明大量不同 session_id。
        # 默认只告警（不改变任何判定），AGENT_MOSS_SESSION_SWEEP_ACTION=deny 才拦截。
        _sweep_key = _principal or ("ip:" + (getattr(request.client, "host", "") or "-"))
        _sweep_n, _sweep_hit = sp.note_session_access(_sweep_key, session_id)
        if _sweep_hit:
            if sp.session_sweep_action() == "deny":
                raise HTTPException(
                    status_code=429,
                    detail=(
                        f"短时间内访问了 {_sweep_n} 个不同会话，超出阈值 "
                        f"{sp.session_sweep_threshold()}（疑似冒充/扫描）"
                    ),
                )
            logger.warning(
                "⚠️ 跨会话批量访问: key=%s 窗口内 %d 个不同 session（阈值 %d）",
                _sweep_key, _sweep_n, sp.session_sweep_threshold(),
            )

        # Step 2: OS 自动检测
        if not os_type:
            os_type = platform.system().lower()
            # 非 Windows 统一用 linux
            if os_type != "windows":
                os_type = "linux"

        # 来源实例：仅用于展示层脱敏（同实例不隐藏），不参与判定。
        instance_id = str(
            (getattr(req, "instance_id", "") or "")
            or ((req.metadata or {}).get("instance_id") or "")
        )

        # Step 3: 获取 OS Profile 并调用分析引擎
        profile = get_profile(os_type)

        start = time.monotonic()
        # Run analysis in a thread pool to avoid blocking the event loop.
        # Without this, the health endpoint and new connections hang while
        # analysis is in progress (synchronous blocking call in async handler).
        loop = asyncio.get_event_loop()
        llm_config = req.metadata.get("llm_config") if req.metadata else None
        # 严格模式：完全不接受 per-request LLM 配置（默认接受，保持原行为）
        if llm_config and not sp.per_request_llm_enabled():
            logger.info("已忽略请求携带的 metadata.llm_config（AGENT_MOSS_ALLOW_PER_REQUEST_LLM=0）")
            llm_config = None
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
                instance_id=instance_id,  # 来源实例（仅展示层脱敏）
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
                    # 来源：真实 agent（不是桶 key），仅用于链路径取证/展示
                    source_agent=agent_id,
                    instance_id=instance_id,
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
                            # 反例路径：每步 [session_id, seq, action_detail, timestamp]
                            # 安全（2026-10）：跨会话节点脱敏 —— 这条时间线按 agent_id
                            # 共享，别人能往里写；原样返回等于把别人的命令原文递出去。
                            # 当前会话的节点保持原样（本来就是调用方自己的数据）。
                            violation_chain=sp.redact_chain(
                                j.get("path", []) or [], instance_id, session_id),
                            violation_graph=sp.redact_graph(
                                j.get("graph"), instance_id, session_id),
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
            violation_graph=sp.redact_graph(result.get("violation_graph"), instance_id, session_id),
        )
    except HTTPException:
        raise  # 鉴权/越界等显式状态码不能被兜底 500 覆盖
    except Exception as e:
        raise _internal_error(e)


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

        # 安全（2026-10）：db_path 原先可以是任意本地路径 —— 等于让调用方指定
        # 「读哪个文件」。现在限制在 AgentGate 标准目录 + AGENT_MOSS_REVIEW_PATHS。
        if req.db_path and not sp.path_within(req.db_path, sp.review_roots()):
            raise HTTPException(
                status_code=403,
                detail=(
                    "db_path 不在允许读取的目录内；标准 AgentGate 部署无需配置，"
                    "自定义路径请加入 AGENT_MOSS_REVIEW_PATHS"
                ),
            )

        agent_id = req.agent_id or "default"
        store = get_chain_state_store()
        # 与实时链路同一个桶：review 全量读到的历史要写进增量引擎之后会读的位置，
        # 否则"谁触发 review 谁才有跨 agent 历史"的不一致会一直存在。
        tracker = store.load_or_new(sp.chain_bucket(agent_id))

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

        # 5. 结果出口（2026-10）：review 是 fire-and-forget，调用方（AgentGate）
        #    只检查 HTTP 状态码、不解析响应体 —— 违规结果此前**没有任何出口**，
        #    全量范围内的 P3–P8 等于静默漏报。这里至少落一条 warning，让
        #    "历史上存在完整攻击链"这件事可见。
        if violations:
            logger.warning(
                "全量回顾发现性质违规: agent=%s count=%d properties=%s",
                agent_id or "-", len(violations),
                ", ".join(str(v.get("property_id", "?")) for v in violations[:8]),
            )
        elif not verified:
            logger.warning("全量回顾 verified=False 但未返回 violation 明细: agent=%s", agent_id or "-")

        return ReviewResponse(
            agent_id=agent_id,
            seeded_nodes=added,
            verified=verified,
            violations=violations,
            pending_prefixes=pending,
            state_nodes=len(tracker.nodes),
            discovered_patterns=discovered,
        )
    except HTTPException:
        raise  # 鉴权/越界等显式状态码不能被兜底 500 覆盖
    except Exception as e:
        raise _internal_error(e)
