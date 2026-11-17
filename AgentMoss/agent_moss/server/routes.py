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
        # 容量状态（2026-11）：调用方据此在响应里标注"这次判定缺了什么/快缺什么"。
        # 分两档语义：
        #   - usage_pct >= 90：**预警**（还没降级，只是提醒尽快处理）
        #   - at_capacity：**已降级**（新动作不入链，L2.2 没覆盖本次动作）
        _at_capacity = False
        _node_count = 0
        _usage_pct = 0.0
        _max_nodes = 0
        try:
            from ..engine.formal_engine.stateful import _MAX_NODES

            _max_nodes = _MAX_NODES
            _tracker = self.store.load(self.agent_id)
            if _tracker is not None:
                _node_count = len(_tracker.nodes)
                _at_capacity = _node_count >= _MAX_NODES
                _usage_pct = round(_node_count / _MAX_NODES * 100, 1) if _MAX_NODES > 0 else 0.0
        except Exception:  # noqa: BLE001
            pass
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
            "at_capacity": _at_capacity,
            "node_count": _node_count,
            "usage_pct": _usage_pct,
            "capacity": _max_nodes,
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
async def health(request: Request):
    """健康检查 + 运行态指标（2026-11 增强）。

    原有字段保持不变（调用方按 status/version/instance 判断）；新增 ``metrics``
    **只在有数据时**出现，且属于附加信息 —— 老客户端解析不受影响（Pydantic 模型
    里给了默认空 dict）。

    指标的意义：
    - ``loop_lag_ms`` / ``loop_lag_max_ms``：事件循环延迟。正常 <10ms；
      持续几百毫秒说明有同步代码在阻塞（2026-11 招行 console 打不开就是这个）。
    - ``pools``：各并发池当前占用。``pool:biz`` 打满 = 新 analyze 会被 503。
    - ``chain_nodes`` / ``chain_db_bytes``：链状态规模，用于提前发现膨胀。
    """
    metrics: dict = {}
    try:
        from ..infra.loop_monitor import get_loop_monitor

        metrics.update(get_loop_monitor().snapshot())
    except Exception:  # noqa: BLE001
        pass
    try:
        pools = getattr(request.app.state, "pools", None)
        if pools is not None:
            metrics["pools"] = await pools.snapshot()
    except Exception:  # noqa: BLE001
        pass
    try:
        from ..infra.circuit_breaker import get_breaker

        metrics["llm_circuit"] = get_breaker().snapshot()
    except Exception:  # noqa: BLE001
        pass
    try:
        from ..engine.formal_engine.chain_state import get_chain_state_store

        store = get_chain_state_store()
        db_path = getattr(store, "db_path", "")
        metrics["chain_db_bytes"] = os.path.getsize(db_path) if db_path and os.path.exists(db_path) else 0
        with store._lock:  # noqa: SLF001 —— 同包内只读快照
            metrics["chain_agents"] = len(store._trackers)  # noqa: SLF001
            metrics["chain_nodes"] = sum(
                len(t.nodes) for t in store._trackers.values()  # noqa: SLF001
            )
        # 容量使用率：触顶后新动作不再入链、组合链检测失效，运维要提前看到
        try:
            from ..engine.formal_engine.stateful import _MAX_NODES

            metrics["chain_capacity"] = _MAX_NODES
            metrics["chain_usage_pct"] = round(
                metrics["chain_nodes"] / _MAX_NODES * 100, 1
            ) if _MAX_NODES > 0 else 0.0
        except Exception:  # noqa: BLE001
            pass
    except Exception:  # noqa: BLE001
        pass
    # status 反映**能力**是否完整，而不只是进程活着（2026-11，用户明确要求
    # 「预警必须能被被动感知」）：
    #   - 链状态接近/达到上限 → 组合链检测这类安全能力会失效，但进程仍然可用
    #   - LLM 熔断打开 → L3 语义分析停止工作
    # 任何探活脚本 / 负载均衡 / 监控平台只看 status 就能发现异常，不需要人去读日志。
    degraded: list[str] = []
    _pct = metrics.get("chain_usage_pct")
    if isinstance(_pct, (int, float)):
        if _pct >= 100:
            degraded.append(
                f"【已降级】链状态时间线已满（{metrics.get('chain_nodes')}/"
                f"{metrics.get('chain_capacity')} 节点）：新动作不再入链，"
                "**L2.2 组合链检测已失效**（跨会话组合攻击可能漏判），L1/L2.1/L3 正常。"
                "处理：agent-moss state backup <备份目录> → systemctl stop agent_moss "
                "→ agent-moss state reset --yes → systemctl start agent_moss；"
                "或调大 AGENT_MOSS_CHAIN_MAX_NODES 后重启。"
            )
        elif _pct >= 90:
            degraded.append(
                f"【预警】链状态时间线已用 {_pct}%（{metrics.get('chain_nodes')}/"
                f"{metrics.get('chain_capacity')} 节点）：即将触顶，触顶后 L2.2 "
                "组合链检测（跨会话组合攻击）将失效，L1/L2.1/L3 不受影响。"
                "处理（任选其一）：① 备份后重置：agent-moss state backup <备份目录> "
                "→ 停服 → agent-moss state reset --yes → 起服；"
                "② 临时扩容：调大 AGENT_MOSS_CHAIN_MAX_NODES 后重启。"
            )
    _circuit = metrics.get("llm_circuit") or {}
    if isinstance(_circuit, dict) and _circuit.get("state") == "open":
        degraded.append(
            f"【已降级】LLM 熔断器已打开（连续失败 {_circuit.get('failures')} 次，"
            f"阈值 {_circuit.get('threshold')}）：**L3 语义分析停止工作**，"
            "当前按 AGENT_MOSS_LLM_FAIL_MODE 的既定策略处理"
            "（fail_open 放行 / fail_closed 拒绝），L1/L2 正常。"
            f"处理：检查模型服务是否存活、网络是否通、api_key 是否有效；"
            f"修复后冷却 {_circuit.get('cooldown_sec')} 秒会自动放试探请求恢复，"
            "无需重启。"
        )
    return HealthResponse(
        status="degraded" if degraded else "healthy",
        degraded=degraded,
        version=__version__,
        instance=os.getenv("AGENT_MOSS_INSTANCE", ""),
        metrics=metrics,
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

        # 本次判定的能力降级说明（空 = 全层都完整跑过）
        _degraded: list[str] = []

        # 请求 ID：一次 analyze 的所有追踪事件共享，便于 grep 串起全过程
        _req_id = uuid.uuid4().hex[:12]
        try:
            from ..infra.trace_log import set_request_id

            set_request_id(_req_id)
        except Exception:  # noqa: BLE001
            pass

        # 追踪日志：完整请求入参（summary=关键字段 / full=含全部历史）
        try:
            from ..infra.trace_log import (
                is_trace_enabled as _te,
                LEVEL_FULL as _LF,
                trace_summary as _ts,
                trace_full as _tf,
            )

            if _te(_LF):
                _tf(
                    "request",
                    session_id=session_id,
                    agent_id=agent_id,
                    os_type=os_type,
                    cwd=cwd,
                    action_type=a_next.get("action_type", ""),
                    action_detail=a_next.get("action_detail", ""),
                    reason=reason,
                    prompt_session=prompt_session,
                    action_history=action_history,
                    prompt_history=prompt_history,
                    session_history=session_history,
                    metadata=req.metadata or {},
                )
            else:
                _ts(
                    "request.summary",
                    session_id=session_id,
                    agent_id=agent_id,
                    action_type=a_next.get("action_type", ""),
                    action_detail=a_next.get("action_detail", "")[:200],
                    history_len=len(action_history),
                    prompt_history_len=len(prompt_history),
                    session_history_len=len(session_history),
                )
        except Exception:  # noqa: BLE001
            pass

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
        def _run_analysis_with_req_id(**_kwargs):
            """在 executor 线程里恢复请求 ID 再调引擎。

            ``run_in_executor`` 的线程**不继承** contextvars，不恢复的话
            引擎层的 L1/L2/L3 trace 事件都没有 req_id，串不起一次请求。
            """
            try:
                from ..infra.trace_log import set_request_id

                set_request_id(_kwargs.pop("_req_id", ""))
            except Exception:  # noqa: BLE001
                pass
            return run_analysis(**_kwargs)

        result = await loop.run_in_executor(
            None,
            lambda: _run_analysis_with_req_id(
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
                _req_id=_req_id,   # 仅在 executor 线程里恢复 contextvars 用
            ),
        )
        duration_ms = (time.monotonic() - start) * 1000

        # 追踪日志：最终判定 + 总耗时
        try:
            from ..infra.trace_log import trace_summary as _ts

            _ts(
                "result",
                session_id=session_id,
                decision=result.get("decision", ""),
                risk_level=result.get("risk_level", ""),
                risk_type=result.get("risk_type", ""),
                reason=result.get("reason", ""),
                violated_layers=result.get("violated_layers", []),
                duration_ms=round(duration_ms, 1),
            )
        except Exception:  # noqa: BLE001
            pass

        # Prometheus 指标（2026-11）：判定分布、端到端耗时、各层命中
        try:
            from ..infra import metrics as _m

            _decision = str(result.get("decision", "") or "")
            _risk = str(result.get("risk_level", "") or "")
            _m.ANALYZE_TOTAL.inc(decision=_decision, risk_level=_risk)
            _m.ANALYZE_DURATION.observe(max(0.0, duration_ms / 1000.0), decision=_decision)
            for _layer in result.get("violated_layers", []) or []:
                # "L2.2-stateful" -> "L2.2"；便于按层聚合
                _m.LAYER_HIT_TOTAL.inc(layer=str(_layer).split("-")[0])
        except Exception:  # noqa: BLE001
            pass

        # 慢请求告警（2026-11）：客户现场「越来越慢」只能靠人肉感觉。超过阈值
        # 直接打一条 warning，配合追踪日志能直接看出慢在哪一层。
        try:
            _slow_ms = float(os.getenv("AGENT_MOSS_SLOW_REQUEST_MS", "1000") or "1000")
        except ValueError:
            _slow_ms = 1000.0
        if _slow_ms > 0 and duration_ms >= _slow_ms:
            logger.warning(
                "慢请求: %.0fms（阈值 %.0fms） action_type=%s agent=%s decision=%s",
                duration_ms,
                _slow_ms,
                a_next.get("action_type", ""),
                agent_id or "-",
                result.get("decision", ""),
            )

        # Report enforcement event to AcTrail（fire-and-forget）。
        # 2026-11：原先在事件循环里同步写 SQLite —— 注释写的是 fire-and-forget、
        # 代码却是同步调用。改为丢线程池、不 await：失败只丢一条记录，绝不能
        # 因为审计库慢而拖住判定响应。
        def _report_actrail() -> None:
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

        try:
            loop.run_in_executor(None, _report_actrail)
        except Exception:
            pass

        # ========== L2.2 stateful incremental（有状态实时判定，可选启用） ==========
        # 调用方在 metadata.stateful_incremental=true 时启用：把当前动作推入该 agent
        # 的持久化时间线，若当前动作补全某组合链（跨 session/长时距前序已就位）→ Deny。
        # 不启用则行为与现状一致（零回归）。提交的违例作为补充判定覆盖 L1-L3 结果。
        metadata = req.metadata or {}
        if str(metadata.get("stateful_incremental", "") or "").lower() in ("1", "true", "yes", "on"):
            try:
                # ⚠️ 必须在 executor 里跑（2026-11 修）：apply_incremental 是
                # 「SQLite 全量读 → json.loads → 重建所有节点 → 追加 → 全量
                # json.dumps → 全量写回」，O(节点数)。跑在事件循环上时，时间线
                # 一长就每次占住几十到几百毫秒，console / 其它 analyze 全排不上。
                # 放线程池后事件循环不受影响（线程内串行由 ChainStateStore 的
                # RLock + 单连接保证）。
                _inc_state = _chain_state_for_agent(agent_id)
                inc = await loop.run_in_executor(
                    None,
                    lambda: _inc_state.apply_incremental(
                        a_next,
                        session_id=session_id,
                        is_error=bool(metadata.get("is_error", False)),
                        # 来源：真实 agent（不是桶 key），仅用于链路径取证/展示
                        source_agent=agent_id,
                        instance_id=instance_id,
                    ),
                )
                # 能力状态两档（2026-11，用户要求「先预警、后降级」）：
                #   >=90%  → 预警：还能完整判定，但很快会触顶，请尽快处理
                #   >=100% → 降级：本次动作确实没参与 L2.2，如实告知
                _pct = inc.get("usage_pct") or 0
                if inc.get("at_capacity"):
                    _degraded.append(
                        f"【已降级】链状态时间线已满（{inc.get('node_count')}/"
                        f"{inc.get('capacity')} 节点）：**本次动作未参与 L2.2 组合链检测**"
                        "（L1/L2.1/L3 不受影响，仍在正常工作）。"
                        "影响：跨会话组合攻击（如先下载后执行、先读凭据后外传）可能漏判。"
                        "处理：agent-moss state backup <备份目录> → systemctl stop agent_moss "
                        "→ agent-moss state reset --yes → systemctl start agent_moss；"
                        "或调大 AGENT_MOSS_CHAIN_MAX_NODES 并重启。"
                    )
                elif _pct >= 90:
                    _degraded.append(
                        f"【预警】链状态时间线已用 {_pct}%（{inc.get('node_count')}/"
                        f"{inc.get('capacity')} 节点）：**本次判定完整**，但即将触顶。"
                        f"触顶后 L2.2 组合链检测（跨会话组合攻击）将失效，"
                        "L1/L2.1/L3 不受影响。"
                        "处理（任选其一）：① 备份后重置：agent-moss state backup <备份目录> "
                        "→ 停服 → agent-moss state reset --yes → 起服；"
                        "② 临时扩容：调大 AGENT_MOSS_CHAIN_MAX_NODES 后重启。"
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
            degraded=_degraded,
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

    ⚠️ **必须在 executor 里跑**（2026-11 修）：本接口要读最多 10 万条
    AgentGate 记录、seed 全量时间线、跑 FormalEngine 全量验证，单次实测
    数百毫秒到数秒。而 AgentGate 是**每 100 次 analyze 自动触发一次**
    ——跑在事件循环上时，招行现场表现为「analyze 一多，console 就打不开、
    随后 503」。与 analyze 同样的处理：整体丢进线程池。

    安全校验（路径越界 403）留在事件循环里：纯字符串判断，微秒级，
    且能在真正开始读盘之前就把请求挡掉。
    """
    if req.db_path and not sp.path_within(req.db_path, sp.review_roots()):
        raise HTTPException(
            status_code=403,
            detail=(
                "db_path 不在允许读取的目录内；标准 AgentGate 部署无需配置，"
                "自定义路径请加入 AGENT_MOSS_REVIEW_PATHS"
            ),
        )
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: _run_review(req))


def _review_seed_limit(store) -> int:
    """单次 review 允许 seed 的动作上限（0 = 不限）。

    基础值来自 ``AGENT_MOSS_REVIEW_MAX_ACTIONS``（默认 5000）。在此之上做
    **自适应兜底**：时间线越接近 10 万上限，seed 上限越收紧 —— 否则一次
    review 持锁几百毫秒会把并发 analyze 全卡住，而且逼近上限时新节点会被
    静默丢弃，seed 再多也没用。

    为什么需要（2026-11）：实测 4 万节点 + seed 1000 条 = 43ms 持锁；
    历史 1 万条就是 400ms。review 是 AgentGate 每 100 次 analyze 自动触发的，
    不设上限等于把客户的历史规模当成了我们的性能假设。
    """
    try:
        base = int(os.getenv("AGENT_MOSS_REVIEW_MAX_ACTIONS", "5000") or "5000")
    except ValueError:
        base = 5000
    if base <= 0:
        return 0
    total_nodes = 0
    try:
        with store._lock:  # noqa: SLF001 —— 同包内只读快照
            total_nodes = sum(len(t.nodes) for t in store._trackers.values())  # noqa: SLF001
    except Exception:  # noqa: BLE001
        return base
    if total_nodes >= 95000:
        return min(base, 200)
    if total_nodes >= 80000:
        return min(base, 1000)
    if total_nodes >= 60000:
        return min(base, 3000)
    return base


def _trim_review_sessions(sessions: list[dict], limit: int) -> tuple[list[dict], int]:
    """限制 seed 的动作总数，**保留最近的**，返回 (裁剪后, 丢弃条数)。

    历史按时间升序，从最老的丢：跨会话组合链真正关心的是"最近这段时间
    发生了什么"，十年前的一条无关命令对判定没有帮助，还会把时间线撑满。
    """
    total = sum(len(s.get("action_history") or []) for s in sessions)
    if limit <= 0 or total <= limit:
        return sessions, 0
    drop = total - limit
    out: list[dict] = []
    for s in sessions:
        actions = list(s.get("action_history") or [])
        if drop <= 0:
            out.append({**s, "action_history": actions})
            continue
        if len(actions) <= drop:
            drop -= len(actions)
            continue
        actions = actions[drop:]
        drop = 0
        out.append({**s, "action_history": actions})
    return out, total - limit


def _run_review(req: ReviewRequest) -> ReviewResponse:
    """``/review`` 的同步主体（在 executor 线程里执行，绝不阻塞事件循环）。

    db_path 的越界校验已上移到 async 入口（读盘前先挡掉），这里不再重复。
    """
    try:
        from ..engine.formal_engine import FormalEngine
        from ..engine.formal_engine.chain_state import get_chain_state_store
        from .agent_gate_reader import load_agent_gate_sessions

        agent_id = req.agent_id or "default"
        _review_t0 = time.monotonic()
        try:
            from ..infra.trace_log import trace_summary as _ts

            _ts(
                "review.request",
                agent_id=agent_id,
                db_path=req.db_path or "",
                inline_sessions=len(req.sessions or []),
                has_a_next=bool(req.a_next),
            )
        except Exception:  # noqa: BLE001
            pass
        store = get_chain_state_store()

        # 1. 读取历史（db_path 直读 > 显式 sessions）
        sessions: list[dict] = []
        if req.db_path:
            sessions = load_agent_gate_sessions(req.db_path)
            if not sessions:
                sessions = req.sessions if req.sessions else []
        else:
            sessions = req.sessions if req.sessions else []
        # 限制单次 seed 的规模（可配置 + 按时间线水位自适应收紧）
        _seed_limit = _review_seed_limit(store)
        sessions, _dropped = _trim_review_sessions(sessions, _seed_limit)
        if _dropped:
            logger.warning(
                "review seed 超过上限（%d 条），丢弃最老的 %d 条；"
                "当前 agent=%s（可用 AGENT_MOSS_REVIEW_MAX_ACTIONS 调整）",
                _seed_limit, _dropped, agent_id or "-",
            )
        # 与实时链路同一个桶：review 全量读到的历史要写进增量引擎之后会读的位置，
        # 否则"谁触发 review 谁才有跨 agent 历史"的不一致会一直存在。
        # ⚠️ seed 必须持锁（seed_and_save）：它修改的是内存缓存里的同一个 tracker，
        # 并发的 apply_action 正在持锁推进同一条时间线，锁外 seed 会丢节点。
        added, tracker = store.seed_and_save(sp.chain_bucket(agent_id), sessions)
        try:
            from ..infra.trace_log import trace_summary as _ts

            _ts(
                "review.seed",
                agent_id=agent_id,
                sessions=len(sessions),
                seeded_nodes=added,
                total_nodes=len(tracker.nodes),
                elapsed_ms=round((time.monotonic() - _review_t0) * 1000, 1),
            )
        except Exception:  # noqa: BLE001
            pass

        # 2. 全量 FormalEngine 验证（跨会话组合链 / 敏感数据传播）
        #    用"本次 seed 的 sessions（多 session 原始结构）+ 当前已累积节点"构建
        #    多 session 行为图，正确跨越 session 边界匹配链。
        verified = True
        violations: list[dict] = []
        if sessions or tracker.nodes:
            eng = FormalEngine()
            # 历史用本次 seed 的 sessions（多 session）；若 db 直读则用读出来的 sessions。
            #
            # ⚠️ **必须限制规模**（2026-11 实测）：FormalEngine.verify 的耗时是
            # 超线性的 —— 1000 条 203ms、5000 条 1.5s、20000 条 **14s**。
            # 原先 sessions 为空时拿 tracker.nodes 全量去验证，6 万节点就是
            # 一分钟以上；而 AgentGate 每 100 次 analyze 就触发一次 review，
            # 线程池会被这一个接口吃干。这里与 seed 用同一个上限。
            if sessions:
                verify_sessions = sessions
            else:
                _nodes = tracker.nodes[-_seed_limit:] if _seed_limit > 0 else tracker.nodes
                verify_sessions = [
                    {"session_id": tracker.agent_id, "action_history": [
                        {"action_type": n.action_type, "action_detail": n.action_detail}
                        for n in _nodes
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

        try:
            from ..infra.trace_log import trace_summary as _ts

            _ts(
                "review.result",
                agent_id=agent_id,
                verified=verified,
                violations=len(violations),
                violation_properties=[v.get("property_id", "") for v in violations[:10]],
                pending_prefixes=len(pending),
                discovered_patterns=len(discovered),
                state_nodes=len(tracker.nodes),
                total_elapsed_ms=round((time.monotonic() - _review_t0) * 1000, 1),
            )
        except Exception:  # noqa: BLE001
            pass

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
