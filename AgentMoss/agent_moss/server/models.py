"""Pydantic models for AgentMoss API requests and responses."""

from typing import Optional
from pydantic import BaseModel, Field

from ..__version__ import __version__


class ActionItem(BaseModel):
    """Single action description."""
    action_type: str = Field(..., description="Action type, e.g. bash, file_read, file_write")
    action_detail: str = Field(..., description="Action detail / command content")

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
    metadata: Optional[dict] = Field(default=None, description="Extended metadata (sandbox_id, trace_id, etc.)")


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
