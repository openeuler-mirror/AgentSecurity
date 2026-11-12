"""Pydantic models for AgentMoss API requests and responses."""

from typing import Optional
from pydantic import BaseModel, Field, model_validator

from ..__version__ import __version__


class ActionItem(BaseModel):
    """Single action description."""
    action_type: str = Field(..., description="Action type, e.g. bash, file_read, file_write")
    action_detail: str = Field(..., description="Action detail / command content")
    #: 动作真实发生时间（调用方上报）。可选 —— 供 P4「提权→外传」时间窗口
    #: 判定；缺省时该性质退回不设窗口的旧行为。
    called_at: str = Field(default="", description="Action timestamp (optional)")

    class Config:
        extra = "allow"


class PromptTurn(BaseModel):
    """A single user prompt turn with the actions it triggered (interleaved time order).

    Expresses the interleaving prompt1→tool1→tool2→prompt2→tool3 as:
      [{text: prompt1, actions:[tool1,tool2]}, {text: prompt2, actions:[tool3]}]
    so intent-consistency (L2) and LLM semantic analysis (L3) can see the full session
    intent + the actions each prompt triggered, not just the latest user message (which
    may be "continue" after compaction replaced earlier history).
    """
    text: str = Field(default="", description="User prompt text at this turn")
    actions: list[ActionItem] = Field(default_factory=list, description="Actions triggered by this prompt (in order, until the next prompt)")

    class Config:
        extra = "allow"


class AnalyzeRequest(BaseModel):
    """Security analysis request (v2: added os_type, cwd; v3: added agent_id; v4: added prompt_history; v5: added session_history; v6: added stateful incremental)."""
    session_id: str = Field(..., description="Session / agent unique identifier")
    prompt_session: str = Field(default="", description="User / upstream original prompt or task description (most recent user message; kept for backward compat)")
    prompt_history: list[PromptTurn] = Field(default_factory=list, description="Full interleaved prompt history (ordered turns, each with its triggered actions). Optional; empty = fall back to prompt_session only.")
    action_history: list[ActionItem] = Field(default_factory=list, description="Historical action sequence")
    session_history: list[dict] = Field(default_factory=list, description="Multi-session historical actions (optional): [{session_id, action_history: [{action_type, action_detail}]}] for L2.2 formal engine cross-session verification. Provided by caller (incl. agentgate).")
    a_next: ActionItem = Field(..., description="Next action to be executed")
    reason: str = Field(default="", description="Reason for executing this action")
    os_type: str = Field(default="", description="OS type: 'linux', 'windows', or empty for auto-detect")
    cwd: str = Field(default="", description="Current working directory for context-aware path detection")
    agent_id: str = Field(default="", description="Caller agent identifier, e.g. 'xiaoo' / 'opencode' / 'opendesk'. Empty = generic mode (no agent-specific rules).")
    instance_id: str = Field(default="", description="Agent installation/instance identifier. Used only for display-layer redaction: nodes from the same instance are returned unredacted. Does not affect detection.")
    metadata: Optional[dict] = Field(default=None, description="Extended metadata (sandbox_id, trace_id, etc.)")

    @model_validator(mode="before")
    @classmethod
    def _adapt_observable_format(cls, data):
        """**校验前**把「AgentOS 可观测服务」的原始 syscall 格式转成标准格式。

        为什么必须在校验前做（2026-10 修的坑）：原始格式用 `current_action` / `tool`
        / `command` / `prompt` 这些键，而本模型把 `a_next`（含 action_type/action_detail）
        声明为必填 —— 真正的原始 payload 会在校验处直接 **422**，永远到不了路由里的
        `is_raw_format` 分支。也就是说 `adapters/observable.py` 与文档描述的
        「可观测服务直接接入」一直是**不可达的死代码**。

        放在模型层而不是路由里：① 任何构造 AnalyzeRequest 的地方（含未来新增入口）
        都自动获得同样的适配；② 适配后仍走**严格的字段校验**（原始格式的 action_history
        项只有 tool/command，不先适配就会 422）。
        双端对称：TS 在 `routes.ts` 解析 zon schema 之前调用同一个语义的适配器。

        防"变成静默放行"：适配后若拿不到任何动作（a_next 为空且没有 current_action），
        直接抛错 → 422。否则畸形请求会被当成"未知动作"分析并大概率 Allow（fail-open）。
        """
        if not isinstance(data, dict):
            return data
        try:
            from ..adapters.observable import ObservableAdapter, is_raw_format
        except Exception:  # noqa: BLE001 — 适配层不可用时保持原样，交给常规校验
            return data
        if not is_raw_format(data):
            return data
        adapted = ObservableAdapter().adapt(data)
        a_next = adapted.get("a_next") or {}
        action_type = str(a_next.get("action_type") or "").strip().lower()
        action_detail = str(a_next.get("action_detail") or "").strip()
        if not action_detail and action_type in ("", "unknown"):
            raise ValueError(
                "无法识别本次动作：既没有 a_next（标准格式），也没有 current_action"
                "（可观测服务原始格式）"
            )
        # 历史项统一成 ActionItem 形态：适配器用的是 name 键（兼容旧入口），
        # 而 ActionItem 要求 action_type —— 不补齐仍会在 action_history 项上 422。
        history = []
        for h in adapted.get("action_history", []) or []:
            hist_type = str(h.get("action_type") or h.get("name") or "")
            item = {"action_type": hist_type, "action_detail": h.get("action_detail", "")}
            if "output" in h:
                item["output"] = h.get("output", "")
            history.append(item)

        # 原始 payload 里的 agent_id / session_id 由适配器兜底（见 ObservableAdapter.adapt）
        return {**data, **adapted, "action_history": history}


class ReviewRequest(BaseModel):
    """POST /api/v1/review 请求：低频全量回顾 + 状态重建。

    由 AgentGate（或 AgentMoss 后台调度）调用：
    - 直接传 sessions（与 analyze 的 session_history 同构）→ seed 全部、跑 FormalEngine
      全量验证 + 提取待攻击前序；
    - 或传 db_path（AgentGate SQLite/JSON 路径）→ 服务端自读全量。
    - output_pending=true 时返回前序链清单。
    """
    agent_id: str = Field(default="", description="目标 agent 标识（决定状态库分桶）")
    db_path: str = Field(default="", description="AgentGate 本地存储路径（SQLite 文件 或 tool_calls JSON 目录）；为空则用 sessions")
    sessions: list[dict] = Field(default_factory=list, description="多 session 历史动作（替代/兜底 db_path）")
    a_next: Optional[ActionItem] = Field(default=None, description="可选：连同当前动作一起判定（seed 之后 advance）")
    is_error: bool = Field(default=False, description="当前动作执行是否失败（用于生命周期 never_activated）")
    output_pending: bool = Field(default=False, description="返回前序链清单 pending_prefixes")


class ReviewResponse(BaseModel):
    """POST /api/v1/review 响应。"""
    agent_id: str = Field(default="")
    seeded_nodes: int = Field(default=0, description="seed 进状态库的节点数")
    verified: bool = Field(default=True, description="全量 FormalEngine 验证是否通过（False = 已存在完整链违反）")
    violations: list[dict] = Field(default_factory=list, description="全量验证的违反（跨会话组合链/敏感数据传播）")
    pending_prefixes: list[dict] = Field(default_factory=list, description="待攻击前序链（matched<len，下一阶段将补全）")
    state_nodes: int = Field(default=0, description="当前状态库累计节点数")
    discovered_patterns: list[dict] = Field(default_factory=list,
                                            description="数据驱动发现：跨 session 频繁危险组合（预置链谜区，PatternMiner）")


class AnalyzeResponse(BaseModel):
    """Security analysis response."""
    decision: str = Field(..., description="Allow or Deny")
    reason: str = Field(..., description="Decision reason")
    risk_level: str = Field(default="low", description="low, medium, high, critical")
    risk_type: str = Field(default="", description="Risk type")
    violated_layers: list[str] = Field(default_factory=list, description="Triggered detection layers")
    policy: str = Field(default="", description="Cerberus Policy TOML (when allowed)")
    violated_policy: str = Field(default="", description="Violated policy clause (when denied)")
    confidence: int = Field(default=100, description="Confidence 0-100")
    analysis_duration_ms: float = Field(default=0.0, description="Analysis duration in milliseconds")

    # 组合攻击链反例路径：每步 [session_id, seq, stage, timestamp]，含真实发生时间
    violation_chain: list[list] = Field(default_factory=list,
                                        description="Combo-chain counterexample path with timestamps")
    # 结构化攻击链图（前端可视化）：{"nodes": [...], "edges": [...]}
    violation_graph: dict | None = Field(default=None,
                                         description="Structured attack-chain graph for visualization")


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = Field(default="healthy", description="Service status")
    version: str = Field(default=__version__, description="Service version")
    # 归属实例标识：值来自 env AGENT_MOSS_INSTANCE（spawn/systemd 注入），默认空串。
    # 多个 agentmoss 同机并存时，调用方按 instance 过滤避免连到别人的进程。
    # 空=未配置（独立部署或旧版），调用方可选择兼容或严格过滤。
    instance: str = Field(default="", description="Owner instance id (env AGENT_MOSS_INSTANCE), for multi-instance disambiguation")


class ErrorResponse(BaseModel):
    """Error response."""
    error: str = Field(..., description="Error message")
    detail: Optional[str] = Field(default=None, description="Error detail")
