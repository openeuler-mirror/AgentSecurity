"""形式化引擎 — 行为图构建器（从 action_history / session_history 构建行为图）

把 agent 的历史动作序列抽象为行为图：
- **单 session**：`build_session_graph(action_history, a_next, session_id)` →
  SessionGraph（节点=动作，next 边=时间序，阶段标记，资源提取）。
- **多 session**：`build_multi_session_graph(sessions, a_next)` →
  MultiSessionGraph（跨会话 data 边：共享文件/记忆/工具路径）。

阶段标记复用 L2 l2_rules.json combo_chains.stages 的 pattern（单一事实源），
保证 L2 组合链规则与形式化引擎的阶段判定一致。

资源提取：从 action_detail 提取文件路径（/path/to/file 形态）+ 工具名，
用于跨会话数据流边（同一文件被先后读写 = 数据传播通道）。
"""

import re
from dataclasses import dataclass, field

from .ir import ActionNode, BehaviorEdge, MultiSessionGraph, SessionGraph

# 阶段 pattern 缓存（复用 L2 combo_chains 定义，单一事实源）
_COMBO_STAGES: dict[str, list[re.Pattern]] = {}


def _load_stages() -> dict[str, list[re.Pattern]]:
    """加载并编译 L2 combo_chains.stages 阶段 pattern（幂等）。"""
    global _COMBO_STAGES
    if _COMBO_STAGES:
        return _COMBO_STAGES
    from ...rules_loader import load_l2
    combo = load_l2().get("combo_chains", {})
    _COMBO_STAGES = {
        name: [re.compile(p, re.IGNORECASE) for p in pats]
        for name, pats in combo.get("stages", {}).items()
    }
    return _COMBO_STAGES


# 文件路径提取（/path、~/path 形态；剥引号避免字面量误提取）。
# 前缀允许 @/= （curl -d @/tmp/x、--output=/tmp/x 等工具参数形态），
# 使敏感数据传播链能识别"载体文件经工具参数传递"的通道。
_PATH_RE = re.compile(r"(?:^|\s|[@=])((?:/|~/)[\w./~-]+)")
# 常见临时文件/脚本载体（跨会话传播的关键通道）
_CARRIER_RE = re.compile(r"(?:/tmp/|/var/tmp/|~/|\./)[\w./-]+\.(?:sh|py|js|rb|pl|php|txt|log|json|db)")


def extract_resources(action_detail: str) -> set:
    """从动作详情提取涉及资源（文件路径 + 载体文件）。"""
    resources: set = set()
    text = re.sub(r"'[^']*'|\"[^\"]*\"", "", action_detail)  # 剥引号内容
    for m in _PATH_RE.finditer(text):
        p = m.group(1)
        # 过滤明显非文件路径（/dev/ 设备、URL 内路径）
        if p.startswith("/dev/") or "://" in p:
            continue
        resources.add(p)
    return resources


def _mark_stage(action_detail: str) -> str:
    """匹配动作命中的组合链阶段（空 = 未命中）。P1：先解码再匹配（抗编码绕过）。"""
    from .decode import match_stage_any
    return match_stage_any(action_detail, _load_stages())


def _mark_integrity(action_detail: str) -> tuple[str, bool]:
    """标记完整性标签 + 是否低完整性源。

    低完整性源 = 外取/下载（download_file AP）或注入内容（prompt_injection AP）——
    其资源（如 curl -o 写入的 /tmp/x.sh、wget 产物）视为不可信，下游动作经共享
    载体继承 low（Rule 5 低完整性控制命令执行的数据源）。复用 mc_rules.json 的
    原子命题正则（单一事实源），避免独立正则漂移。
    """
    from .ltl import label_event
    aps = label_event(action_detail)
    if "download_file" in aps or "prompt_injection" in aps:
        return "low", True
    return "medium", False


def _init_node(session_id: str, seq: int, at: str, ad: str) -> ActionNode:
    """统一构造 ActionNode（含 stage + resources + integrity 标记）。"""
    integrity, is_low = _mark_integrity(ad)
    return ActionNode(
        session_id=session_id,
        seq=seq,
        action_type=at,
        action_detail=ad,
        stage=_mark_stage(ad),
        resources=extract_resources(ad),
        integrity=integrity,
        is_low_source=is_low,
    )


def build_session_graph(
    action_history: list,
    a_next: dict | None = None,
    session_id: str = "current",
) -> SessionGraph:
    """从单 session 动作历史构建 SessionGraph。

    action_history: [{"action_type", "action_detail", ...}] 按时间序。
    a_next: 可选，拟执行的下一步动作（追加为末节点）。
    """
    graph = SessionGraph(session_id=session_id)
    details: list[tuple[str, str]] = []
    for action in action_history:
        at = str(action.get("action_type", ""))
        ad = str(action.get("action_detail", ""))
        if ad:
            details.append((at, ad))
    if a_next:
        details.append((str(a_next.get("action_type", "")), str(a_next.get("action_detail", ""))))

    for seq, (at, ad) in enumerate(details):
        node = _init_node(session_id, seq, at, ad)
        graph.nodes.append(node)
        if node.stage:
            graph.stage_flags.add(node.stage)

    # next 边（时间序）
    for i in range(len(graph.nodes) - 1):
        graph.edges.append(BehaviorEdge(src=i, dst=i + 1, kind="next"))
    return graph


def build_multi_session_graph(
    sessions: list,
    a_next: dict | None = None,
) -> MultiSessionGraph:
    """从多个 session 构建 MultiSessionGraph。

    sessions: [{"session_id", "action_history": [...]}, ...] 按时间序。
    a_next: 可选，当前 session 拟执行的下一步（追加到最后一个 session）。
    """
    mg = MultiSessionGraph()
    if not sessions:
        # 无历史 session → 只用 a_next 构建单 session 图
        sg = build_session_graph([], a_next=a_next, session_id="current")
        mg.sessions.append(sg)
        return mg

    for s in sessions:
        sid = str(s.get("session_id", "s"))
        hist = s.get("action_history", []) or []
        sg = build_session_graph(hist, session_id=sid)
        mg.sessions.append(sg)

    # 当前 session 的 a_next（若 sessions 最后一个是当前 session，附加其历史）
    if a_next:
        # 追加到最后一个 session 图（若其 session_id 为 current）或新开
        last = mg.sessions[-1]
        if last.session_id == "current":
            last.nodes.append(_init_node(
                last.session_id, len(last.nodes),
                str(a_next.get("action_type", "")),
                str(a_next.get("action_detail", "")),
            ))
            if len(last.nodes) > 1:
                last.edges.append(BehaviorEdge(src=len(last.nodes) - 2, dst=len(last.nodes) - 1, kind="next"))
        else:
            sg = build_session_graph([], a_next=a_next, session_id="current")
            mg.sessions.append(sg)

    # 跨会话 data 边：共享资源（文件/载体）被先后访问
    _add_cross_data_edges(mg)
    return mg


def _add_cross_data_edges(mg: MultiSessionGraph) -> None:
    """检测跨会话共享资源 → 生成 data 边。

    规则：节点 A 的资源集合与后续节点 B 的资源集合有交集（同一文件/载体），
    且 A、B 属于不同 session → data 边（A → B，数据传播通道）。
    载体文件（/tmp/*.sh 等）权重更高——脚本被写入后执行是典型传播链。

    性能：按资源哈希分组（resource → [node_idx...]），只比较共享同一资源的
    节点对（且跨 session），从 O(N²) 全节点对降为 O(N·R)（R=资源种类）。
    同一节点对共享多个资源时去重（仅建一条 data 边）。
    """
    nodes = mg.all_nodes
    if len(nodes) < 2:
        return
    res_index: dict[str, list[int]] = {}
    for i, n in enumerate(nodes):
        for r in n.resources:
            res_index.setdefault(r, []).append(i)
    seen: set[tuple[int, int]] = set()
    for idxs in res_index.values():
        if len(idxs) < 2:
            continue
        for a in range(len(idxs)):
            i = idxs[a]
            for b in range(a + 1, len(idxs)):
                j = idxs[b]
                if nodes[i].session_id == nodes[j].session_id:
                    continue
                key = (i, j)
                if key in seen:
                    continue
                seen.add(key)
                mg.cross_edges.append(BehaviorEdge(src=i, dst=j, kind="data"))
