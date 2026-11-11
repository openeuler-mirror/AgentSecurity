"""形式化引擎 — 统一行为图 IR（数据模型 + 接口）

Agent 行为的形式化建模中间表示，供 FormalEngine（性质验证）消费。
定位：类似 script_engine 的 ScriptIR——把"agent 的历史动作序列"抽象为
**行为图**（节点=动作/工具调用，边=时间序/数据流），再对图做性质验证。

数据来源（向后兼容）：
- **单 session**：从现有 `action_history` + `prompt_history`（coordinator 已有
  参数）构建 `SessionGraph`，无需调用方改动。
- **多 session**：调用方（含未来 agentgate 非侵入式采集）传入多个 session 的
  历史动作 → 拼接为 `MultiSessionGraph`（跨会话数据流边：共享文件/记忆/工具）。
  coordinator 新增可选参数 `session_history`，缺省时只用当前 session 构建
  单 session 图（行为与现状一致，零回归）。

设计原则：
- IR 与验证器解耦：加性质 = 新增 Property 定义，Graph/Engine 不动。
- fail-closed：无法确认的阶段/资源按"已发生"保守标记；性质不可判定时
  按违反处理（宁可多拦，不可漏）。
"""

from dataclasses import dataclass, field


@dataclass
class ActionNode:
    """行为图节点：一次动作 / 工具调用。

    session_id + seq 唯一定位节点；stage 是组合链阶段标记（L2 combo_chains
    的 5 阶段 LISTEN/EXEC/SCAN/CRED/EXFIL），由构建器从 action_detail 匹配。
    """

    session_id: str
    seq: int                        # 会话内序号（0 起）
    action_type: str = ""
    action_detail: str = ""
    stage: str = ""                 # 命中的阶段（空 = 未命中任何阶段）
    resources: set = field(default_factory=set)  # 涉及资源（文件路径/网络目标/工具名）
    integrity: str = "medium"       # 完整性标签（high/medium/low，低处流原则沿 data 边取 min）
    is_low_source: bool = False     # 低完整性源（外取/下载/注入内容）→ 其资源被后续动作继承 low
    #: 动作真实发生时间（调用方上报的 called_at，ISO 或 "YYYY-MM-DD HH:MM:SS"）。
    #: 可空 —— 旧调用方 / 旧数据没有这个字段时，依赖时间的性质（P4 提权窗口）
    #: 退回"不设窗口"的旧行为，不改变判定。
    timestamp: str | None = None
    #: 动作来源（哪个 agent 上报的）。**仅用于取证与告警展示，不参与链匹配** ——
    #: 组合攻击针对的是这台服务器，跨 agent 分步实施同样成立（见 AGENT_MOSS_CHAIN_SCOPE）。
    agent_id: str = ""
    #: 来源实例（哪个 agent 安装/实例上报的）。**仅用于展示层脱敏**：
    #: 同实例的历史节点不隐藏命令原文，跨实例才隐藏。不参与链匹配。
    instance_id: str = ""


@dataclass
class BehaviorEdge:
    """行为图边：时间序 / 数据流 / 调用。

    kind:
      - "next": 时间序（同 session 内相邻动作）
      - "data": 数据流（跨动作共享资源：同一文件被先后读写、同一记忆被先后访问）
      - "call": 调用关系（动作 A 触发了动作 B，如脚本→子脚本、tool→subtool）
    """

    src: int                        # 源节点索引（图内全局索引）
    dst: int
    kind: str = "next"


@dataclass
class SessionGraph:
    """单 session 行为图（从 action_history + a_next 构建）。"""

    session_id: str
    nodes: list[ActionNode] = field(default_factory=list)
    edges: list[BehaviorEdge] = field(default_factory=list)
    stage_flags: set = field(default_factory=set)  # 已进入的阶段集合（供快速判定）


@dataclass
class MultiSessionGraph:
    """多 session 行为图：多个 SessionGraph 拼接 + 跨会话数据流边。

    跨会话边由构建器从共享资源（文件/记忆/工具）检测生成——
    例如 session A 写入 /tmp/x.sh、session B 执行 bash /tmp/x.sh → data 边。

    witness_idx: 实时判定语义（witness）——当 verify 带 a_next 时，图末节点
    （索引 = witness_idx）即"当前拟执行动作"；性质检查只当**该节点补全链/触发
    后置外传**时才判违规（修复"历史全局匹配 → 永久拒绝锁定"FP，对齐站点 L2.2
    "仅当当前事件属于 violation witness 时才返回 block"）。None = 低频回顾
    （/api/v1/review 全量历史），保留"报告历史中已形成的违规"语义。
    """

    sessions: list[SessionGraph] = field(default_factory=list)
    cross_edges: list[BehaviorEdge] = field(default_factory=list)
    witness_idx: int | None = None

    @property
    def all_nodes(self) -> list[ActionNode]:
        out: list[ActionNode] = []
        for s in self.sessions:
            out.extend(s.nodes)
        return out

    @property
    def all_edges(self) -> list[BehaviorEdge]:
        out: list[BehaviorEdge] = []
        base = 0
        for s in self.sessions:
            out.extend(e for e in s.edges)
            base += len(s.nodes)
        out.extend(self.cross_edges)
        return out


@dataclass
class PropertyViolation:
    """性质违反结果（反例路径）。"""

    property_id: str
    reason: str
    risk_level: str = "high"
    path: list = field(default_factory=list)  # [(session_id, seq, action_detail)] 反例路径
    # 结构化攻击链图（前端可视化用）：
    # {"nodes": [{session_id, seq, stage, action_detail, resources}],
    #  "edges": [{from, to, type: "next"|"data", label?}]}
    graph: dict | None = None


@dataclass
class FormalVerificationResult:
    """一次性质验证的结果（FormalEngine.verify 的输出）。

    - verified: 全部性质满足 → 放行（含合规证明摘要）
    - violation: 存在性质违反 → 拦截 + 反例路径
    """

    verified: bool = True
    violations: list[PropertyViolation] = field(default_factory=list)

    @property
    def first_violation(self) -> PropertyViolation | None:
        return self.violations[0] if self.violations else None
