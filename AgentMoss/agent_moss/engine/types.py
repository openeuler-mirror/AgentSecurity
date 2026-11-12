"""安全检测相关类型定义"""

from dataclasses import dataclass, field


@dataclass
class SecurityJudgment:
    """AgentMoss 安全判断结果"""

    allowed: bool
    reason: str
    risk_level: str = "low"  # "low" | "medium" | "high" | "critical"
    risk_type: str = ""  # 风险类别（如 "file_access", "script_execution" 等）
    confidence: int = 100  # 0-100
    source: str = ""  # 判断来源："heuristic" | "logic_rule" | "llm"
    action_desc: str = ""  # 动作描述
    violated_layers: list[str] = field(default_factory=list)  # 违反的具体层号，如 ["L1.1"], ["L2.1", "L3.1"]
    # 组合式拦截的结构化攻击链（前端可视化用）：
    # {"nodes": [{session_id, seq, stage, action_detail, resources}],
    #  "edges": [{from, to, type, label?}]}
    violation_graph: dict | None = None
    # 兼容旧调用方：反例路径数组 [[session_id, seq, detail, timestamp?, agent?], ...]
    violation_chain: list = field(default_factory=list)


@dataclass
class HeuristicResult:
    """特征匹配检测结果"""

    hit: bool = False
    matched_patterns: list[str] = field(default_factory=list)
    risk_level: str = "low"
    reason: str = ""
    risk_type: str = ""
    confidence: int = 100  # 0-100，置信度；<80 时不立即 Deny，转交 Layer 2/3 分析
    # 敏感路径检测搬到 L1 后携带：是否命中凭据文件（deny_both，无论读写都拦截，
    # 不进 inline 跳过）；以及命中规则名（供 coordinator 日志/Brain/LLM prompt 用）
    is_credential: bool = False
    violated_rule: str = ""


@dataclass
class LogicRuleResult:
    """逻辑规则检测结果"""

    hit: bool = False
    violated_rule: str = ""
    risk_level: str = "low"
    reason: str = ""
    risk_type: str = ""
    is_credential: bool = False  # 是否命中凭据文件（凭据文件无论读写都拦截，不进 inline 跳过）


@dataclass
class SkillMatch:
    """匹配到的 Skill"""

    skill_name: str = ""
    relevance: float = 0.0  # 0-1 相关度
    skill_content: str = ""  # Skill 文件内容


@dataclass
class ScriptNode:
    """递归追踪链中的单个脚本节点"""

    script_path: str = ""                          # 脚本绝对路径（resolve 后）
    raw_content: str = ""                          # 原始脚本内容（完整读取）
    preprocessed_content: str = ""                 # 预处理后内容（去注释+去echo+变量展开）
    line_count: int = 0                            # 原始行数
    file_size: int = 0                             # 文件大小（bytes）
    depth: int = 0                                 # 递归深度（0=入口脚本）
    child_paths: list[str] = field(default_factory=list)  # 提取到的子脚本路径
    error: str = ""                                # 读取错误信息
    # 「文件存在但内容读不了」（过大 / 权限）—— 与「脚本不存在」本质不同：
    # 前者是**无法分析**（不能当安全放行），后者是"跑也跑不起来"（无所谓）。
    unanalyzable: bool = False

    # L1 扫描结果（CommandPatternScanner 对 preprocessed_content 的扫描结果）
    l1_hit: bool = False
    l1_risk_level: str = ""
    l1_risk_type: str = ""
    l1_reason: str = ""
    l1_matched_patterns: list[str] = field(default_factory=list)

    # L2 扫描结果（LogicRulesChecker 对 preprocessed_content 的扫描结果）
    l2_hit: bool = False
    l2_violated_rule: str = ""
    l2_risk_level: str = ""
    l2_risk_type: str = ""
    l2_reason: str = ""

    # 关键词扫描结果（兼容现有 L3 SUSPICIOUS_PATTERNS 流程）
    matched_keywords: list[str] = field(default_factory=list)
    is_suspicious: bool = False
    keyword_risk_level: str = ""
    keyword_risk_reason: str = ""


@dataclass
class ScriptChainAnalysisResult:
    """脚本调用链完整分析结果"""

    nodes: list[ScriptNode] = field(default_factory=list)
    entry_path: str = ""                           # 入口脚本路径
    max_depth_reached: bool = False                # 是否触达递归深度上限
    max_size_reached: bool = False                # 是否触达总大小上限
    max_nodes_reached: bool = False               # 是否触达节点数上限（防链巨大化）
    total_nodes: int = 0                           # 已追踪节点数
    total_size: int = 0                            # 所有文件累计大小（bytes）
    total_lines: int = 0                           # 所有文件累计行数
    has_critical: bool = False                    # 调用链中是否有 critical 级别风险
    has_high: bool = False                        # 调用链中是否有 high 级别风险
    first_hit_node: ScriptNode | None = None      # 第一个命中的节点（用于快速 Deny）
    error: str = ""                               # 全局错误信息