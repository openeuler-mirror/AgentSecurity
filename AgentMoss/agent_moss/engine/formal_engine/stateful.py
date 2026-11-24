"""Stateful incremental behavior analysis — 有状态的增量行为链分析器。

把"每次请求传什么就分析什么"改成"时间线持续累积 + 每次新动作增量推进链指针 +
生命周期（能力鲜活度）判定"：

- **StatefulChainTracker**：按 agent 维护一条"安全相关事件时间线"（追加模式）。
- **增量判定**：每来一个新动作，只做一次阶段命中比较 + 链指针推进（O(链数)），
  并产出两类结果：
  - `matched`   — 当前动作恰好补全了一条链（跨会话/跨长期，前序已就位）→ 高可信阻断；
  - `pending_prefixes` — 当前动作让某条链推进到前 k 个阶段（尚未完整，是"待攻击前序"）
    ，写回状态库，供下一次动作预判。
- **生命周期**：识别 create/destroy 信号（kill/pkill/systemctl stop/删除文件等）
  与"创建失败"（`is_error` / 退出码非 0 / "not found"/"refused"）→ 资源节点标记
  alive / dead / never_activated；dead 资源不再参与后续链段（堵"服务已关仍判链"误报）。
- **敏感数据传播（P2）**：增量 taint —— CRED 节点染毒；后续动作若与已染毒资源共享载体
  则传播；传播后最终 EXFIL 形态即违反。

与 FormalEngine 的关系：FormalEngine 是**全量无状态**快照验证（定期/低频用，保持一致语义）；
本模块是**增量有状态**版本（每次 tool call 实时用，结果应与全量一致）。
"""

from __future__ import annotations

import gzip
import datetime
import hashlib
import json
import logging
import os
import re
import time
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


_TRUNCATED_DETAIL_RE = re.compile(r"…\[truncated \d+B sha256:([0-9a-f]{16})\]$")
_SHELL_ACTION_ALIASES = {
    "executebash": "bash",
    "terminal-executebash": "bash",
    "execute_bash": "bash",
    "terminal_execute_bash": "bash",
}


def _canonical_action_type(action_type: str) -> str:
    """工具别名归一：AgentGate 实时链路归一化，review 读 DB 原始名，必须同键。"""
    low = str(action_type or "").strip().lower()
    return _SHELL_ACTION_ALIASES.get(low, low)


def _canonical_detail(action_detail: str) -> str:
    """命令内容归一：落库截断保留全文 sha256，实时与 review 用同一摘要。"""
    detail = str(action_detail or "")
    m = _TRUNCATED_DETAIL_RE.search(detail)
    digest = m.group(1) if m else hashlib.sha256(
        detail.encode("utf-8", "surrogatepass")
    ).hexdigest()[:16]
    return f"sha256:{digest}"


def _canonical_called_at(called_at: str) -> str:
    """时间归一：实时是微秒 ISO，SQLite 是秒级；统一到 UTC epoch 秒。"""
    value = str(called_at or "").strip()
    if not value:
        return ""
    try:
        dt = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return str(int(dt.timestamp()))
    except (ValueError, OverflowError):
        return value


def _fingerprint(session_id: str, action_type: str, action_detail: str, called_at: str) -> str:
    """动作指纹（seed 去重用）。

    只对**带 called_at 的动作**生成 —— 同一 session 里重复执行同一命令是
    合法行为，没有时间戳就无法区分，宁可不作为也不误去重。

    实时与 review 的同一动作必须同键：时间统一到秒、工具名过别名归一化、
    命令用全文 sha256（截断记录里保留了原摘要）。
    """
    raw = "\x00".join((
        str(session_id),
        _canonical_action_type(action_type),
        _canonical_detail(action_detail),
        _canonical_called_at(called_at),
    ))
    return hashlib.blake2b(raw.encode("utf-8", "replace"), digest_size=8).hexdigest()

# 时间线上限（安全相关节点；平凡动作即便不单独建安全语义节点也会被 append，
# 高频大项目下需上限保护防无限增长。超限忽略新节点，建议定期 /api/v1/review 重建。）
#
# 可用 AGENT_MOSS_CHAIN_MAX_NODES 覆盖（默认 10 万）。按客户 QPS 5-10 估算，
# **几小时就会触顶**；触顶后新动作不入链、组合链检测失效，所以必须提前预警
# （见 _CAPACITY_WARN_RATIOS）而不能等撞墙。
def _max_nodes() -> int:
    try:
        return int(os.getenv("AGENT_MOSS_CHAIN_MAX_NODES", "100000") or "100000")
    except ValueError:
        return 100000


_MAX_NODES = _max_nodes()


def _retain_nodes() -> int:
    """轮转后保留的最近节点数（默认上限的一半）。

    AgentMoss 的链状态是派生缓存；到上限时自动归档旧节点并保留最近窗口，
    不再丢新动作、也不要求客户手工 reset。
    """
    raw = os.getenv("AGENT_MOSS_CHAIN_RETAIN_NODES", "")
    try:
        n = int(raw) if raw else max(1, _MAX_NODES // 2)
    except ValueError:
        n = max(1, _MAX_NODES // 2)
    return max(1, min(n, _MAX_NODES - 1))


def cleanup_chain_archives(
    archive_dir: Path,
    max_bytes: int | None = None,
    max_age_days: int | None = None,
) -> tuple[int, int, int]:
    """清理链归档目录：先按年龄、再按总大小删最老的 ``chain-nodes-*.jsonl.gz``。

    默认按总大小 512MB 滚动删除（``AGENT_MOSS_CHAIN_ARCHIVE_MAX_MB``），
    按时间默认关闭（``AGENT_MOSS_CHAIN_ARCHIVE_MAX_AGE_DAYS=0``）。
    与 TS ``cleanupChainArchives`` 对称。返回 ``(删除数, 剩余文件数, 剩余字节)``。
    """
    if max_bytes is None or max_age_days is None:
        try:
            mb = max(0, int(os.getenv("AGENT_MOSS_CHAIN_ARCHIVE_MAX_MB", "512")))
        except ValueError:
            mb = 512
        try:
            days = max(0, int(os.getenv("AGENT_MOSS_CHAIN_ARCHIVE_MAX_AGE_DAYS", "0")))
        except ValueError:
            days = 0
        if max_bytes is None:
            max_bytes = mb * 1024 * 1024
        if max_age_days is None:
            max_age_days = days
    try:
        files = sorted(
            (p for p in archive_dir.iterdir()
             if p.name.startswith("chain-nodes-") and p.name.endswith(".jsonl.gz")),
            key=lambda p: p.stat().st_mtime,
        )
    except OSError:
        return 0, 0, 0
    removed = 0
    if max_age_days > 0:
        cutoff = time.time() - max_age_days * 86400
        kept = []
        for p in files:
            try:
                if p.stat().st_mtime < cutoff:
                    p.unlink()
                    removed += 1
                else:
                    kept.append(p)
            except OSError:
                kept.append(p)
        files = kept
    total = 0
    for p in files:
        try:
            total += p.stat().st_size
        except OSError:
            pass
    if max_bytes > 0:
        # 至少保留最新 1 个归档（单个文件本身超限时不删，2026-11 修 N1）
        for idx, p in enumerate(files):
            if total <= max_bytes:
                break
            if idx == len(files) - 1:
                break
            try:
                size = p.stat().st_size
                p.unlink()
                total -= size
                removed += 1
            except OSError:
                continue
    remain_files = remain_bytes = 0
    try:
        for p in archive_dir.iterdir():
            if p.name.startswith("chain-nodes-") and p.name.endswith(".jsonl.gz"):
                remain_files += 1
                try:
                    remain_bytes += p.stat().st_size
                except OSError:
                    pass
    except OSError:
        pass
    return removed, remain_files, remain_bytes
#: 容量分级预警阈值（达到即打一条 warning，每档只打一次）
_CAPACITY_WARN_RATIOS = (0.7, 0.85, 0.95)

# ---------------- 生命周期/敏感数据 辅助正则 ----------------

# 销毁信号（能力资源被关闭/删除/停止）
_DESTROY_RE = re.compile(
    r"\b(?:pkill|kill)\b|systemctl\s+stop|service\s+stop|crontab\s+-r|rm\s+-[rf]?\s+",
    re.IGNORECASE,
)
# 创建失败信号（进程未能建立/文件不存在/连接拒绝）
_NEVER_ACTIVATED_RE = re.compile(
    r"\b(?:not\s+found|no\s+such\s+file|command\s+not\s+found|refused|failed\s+to\s+(?:start|bind|listen)|address\s+already\s+in\s+use)\b",
    re.IGNORECASE,
)
# 敏感数据源（P2 染毒源：CRED 阶段访问的凭据类文件）
_CRED_FILE_RE = re.compile(
    r"(known_hosts|\.ssh|id_rsa|/etc/shadow|/etc/passwd|credentials)", re.IGNORECASE
)
# 外传形态（P2 最终导出：网络外发/远程拷贝）
_EXFIL_RE = re.compile(
    r"https?://(?!127\.\d+\.\d+\.\d+|0\.0\.0\.0|localhost|\[?::1\]?)|scp\s+.*@|rsync\s+.*@",
    re.IGNORECASE,
)


@dataclass
class StateNode:
    """时间线节点（一次动作的安全相关视图）。"""

    seq: int
    session_id: str
    action_type: str = ""
    action_detail: str = ""
    stage: str = ""
    resources: tuple = ()
    # 实例 key（端口 / socket / unit）。空 = 无实例信息（走全局桶）。
    instances: tuple = ()
    is_error: bool = False
    # 生命周期："" (默认) | "alive" | "dead" | "never_activated"
    lifecycle: str = ""
    #: 动作来源（哪个 agent 上报的）。仅用于取证/告警展示，不参与链匹配。
    agent_id: str = ""
    #: 来源实例（哪个 agent 安装/实例上报的）。仅用于展示层脱敏，不参与链匹配。
    instance_id: str = ""
    # 真实发生时间（ISO 字符串，来自 action.called_at；无则 None → 退化为 seq 序号）
    timestamp: str | None = None


@dataclass
class PendingPrefix:
    """待攻击前序：某条链只推进到前 k 个阶段。"""

    chain_id: str
    stages: tuple
    matched: int
    risk_level: str

    @property
    def next_stage(self) -> str:
        if self.matched < len(self.stages):
            return self.stages[self.matched]
        return ""


@dataclass
class ChainMatch:
    """当前动作补全的一条链。"""

    chain_id: str
    stages: tuple
    risk_level: str
    reason: str
    path: list = field(default_factory=list)  # [(session_id, seq, stage)]

    def to_judgment(self) -> dict:
        return {
            "property_id": "cross-" + self.chain_id,
            "reason": self.reason,
            "risk_level": self.risk_level,
            "path": self.path,
            "graph": self.build_graph(),
        }

    def build_graph(self) -> dict:
        """把链路径转成前端可画的结构化图（相邻节点用 next 边）。"""
        nodes: list[dict] = []
        edges: list[dict] = []
        for k, item in enumerate(self.path):
            nodes.append({
                "session_id": item[0],
                "seq": item[1],
                "stage": self.stages[k] if k < len(self.stages) else "",
                "action_detail": str(item[2]) if len(item) > 2 else "",
                "resources": [],
                "role": self.stages[k] if k < len(self.stages) else "",
                "instance_id": str(item[5]) if len(item) > 5 else "",
            })
            if k > 0:
                edges.append({"from": k - 1, "to": k, "type": "next"})
        if nodes:
            nodes[-1]["witness"] = True
        return {
            "property_id": "cross-" + self.chain_id,
            "property_short": "P1",
            "property_name": "跨会话组合链",
            "property_expression": [
                {"token": s, "node_index": i} for i, s in enumerate(self.stages)
            ],
            "nodes": nodes,
            "edges": edges,
        }


def _mark_stage(action_detail: str, combo_stages: dict[str, list[re.Pattern]]) -> str:
    """匹配动作命中的组合链阶段（空 = 未命中）。P1：先解码再匹配（抗编码绕过）。"""
    from .decode import match_stage_any
    return match_stage_any(action_detail, combo_stages)


def _extract_resources(action_detail: str) -> tuple:
    """提取涉及资源（文件路径/网络目标），剥引号避免字面量误提取（对齐 builder）。"""
    text = re.sub(r"'[^']*'|\"[^\"]*\"", "", action_detail)
    resources: list[str] = []
    for m in re.finditer(r"(?:^|\s|[@=])((?:/|~/)[\w./~-]+)", text):
        p = m.group(1)
        if p.startswith("/dev/") or "://" in p:
            continue
        if p not in resources:
            resources.append(p)
    return tuple(resources)


# ---- 实例资源提取（端口 / socket / systemd unit）----
# 目标：把"不同端口的 LISTEN"区分成不同实例，链指针按实例推进，避免不同监听
# 串扰（A 端口进度被 B 端口动作推进 → 误报）。无实例信息时回退全局共享桶（保守）。
_PORT_RE = re.compile(r"(?:-p\s+(\d{1,5})|-p(\d{1,5})|:(\d{1,5})\b)", re.IGNORECASE)
_SOCK_RE = re.compile(r"([\w./-]*(?:\/tmp\/|\/var\/run\/|\.sock\b)[\w./-]*)")
_UNIT_RE = re.compile(r"systemctl\s+(?:start|enable|restart)\s+([\w.-]+)", re.IGNORECASE)
_LISTEN_VERB_RE = re.compile(
    r"(?:flask|uvicorn|gunicorn)\s+run|http\.server|httpserver|listen\(|bind\(",
    re.IGNORECASE,
)
_PORT_STAGE_RE = re.compile(r"LISTEN|PERSIST|SCAN")  # 有实例语义的阶段
_LISTEN_ONLY_RE = re.compile(r"LISTEN|PERSIST")  # http 默认端口仅监听/持久化阶段生效
_PORT_SCAN_RE = re.compile(r"SCAN")  # SCAN 阶段才放开裸端口提取
_BARE_PORT_RE = re.compile(r"(?:(?<=^)|(?<=\s))(\d{1,5})(?=\s|$)")


def _extract_instances(action_detail: str, stage: str) -> tuple:
    """从动作文本提取实例 key。仅 LISTEN/PERSIST 阶段承载可命名的资源实例；
    其他阶段无实例绑定 → 空（走全局桶，信息不足时保守推进所有桶）。"""
    if not _PORT_STAGE_RE.search(stage or ""):
        return ()
    out: list[str] = []
    d = action_detail or ""
    for m in _PORT_RE.finditer(d):
        p = m.group(1) or m.group(2) or m.group(3)
        if p and p.isdigit() and 0 < int(p) <= 65535:
            val = f"port:{p}"
            if val not in out:
                out.append(val)
    # SCAN 阶段：裸端口数字参数（nc -z host 9999 / nmap ... 22）
    if _PORT_SCAN_RE.search(stage or ""):
        for m in _BARE_PORT_RE.finditer(d):
            p = m.group(1)
            if p and p.isdigit() and 0 < int(p) <= 65535:
                val = f"port:{p}"
                if val not in out:
                    out.append(val)
    m = _SOCK_RE.search(d)
    if m and m.group(1):
        val = f"sock:{m.group(1)}"
        if val not in out:
            out.append(val)
    m = _UNIT_RE.search(d)
    if m and m.group(1):
        val = f"unit:{m.group(1)}"
        if val not in out:
            out.append(val)
    # LISTEN_VERB 无端口形态（python -m http.server、flask run）→ 不臆测端口，
    # 走全局桶（与无端口链一致，保守补全）。
    return tuple(out)


GLOBAL_BUCKET = "__global__"


def _buck_key(chain_id: str, inst: str | None) -> str:
    """桶 key：chainId 与实例组合。兼容旧快照（无 @@ 分隔 = 全局桶）。"""
    return f"{chain_id}@@{inst}" if inst else chain_id


def _chain_id_of_bucket(key: str) -> str:
    return key.split("@@", 1)[0]


class StatefulChainTracker:
    """有状态的增量行为链分析器。

    Usage:
        tracker = StatefulChainTracker(agent_id="opendesk")
        tracker.seed(sessions=[...])        # 初始灌入历史（全量/定期）
        result = tracker.advance(a_next=..., action_history=..., is_error=...)
        result.matched        # 链补全 → 应阻断
        result.pending_prefixes  # 前序链（写回状态库，供预判）
    """

    @staticmethod
    def _now() -> str:
        """本地接收时刻（实时路径无 called_at 时的兜底时间戳，ISO）。"""
        import datetime
        return datetime.datetime.now().isoformat(timespec="seconds")

    def __init__(self, agent_id: str = "", properties=None):
        self.agent_id = agent_id
        # 复用 l2_rules.json combo_chains（单一事实源）
        self._combo: dict[str, Any] = {}
        self._chains: list[dict] = []
        self._stages_patterns: dict[str, list[re.Pattern]] = {}
        self.from_rules()

        # 时间线（全局序）
        self.nodes: list[StateNode] = []
        self._session_ends: set = set()  # session 已结束（预留）
        #: 已入时间线的动作指纹（**只有带 called_at 的动作才登记**）。
        #:
        #: 为什么需要（2026-11 实测）：`seed()` 原先无条件追加历史 —— 同一批
        #: session seed 5 次，节点从 2 条变成 10 条。AgentGate 每 100 次
        #: analyze 就触发一次 review 并 seed 全量历史，跑一小时能把 10 万节点
        #: 上限打满，之后 `_append` 静默丢弃新节点 → **组合链检测彻底失效**。
        #:
        #: 只用 `(_agent, _type, _detail, called_at)` 做键；`called_at` 为空时
        #: 不登记也不去重（同一 session 重复执行同一命令是合法行为，无时间戳
        #: 无法区分，宁可重复也不能漏）。
        self._seeded_keys: set[str] = set()
        #: 已打过的容量预警档位（0.7 / 0.85 / 0.95），防每请求刷屏
        self._capacity_warned: set[float] = set()

        # 每条链的推进指针: chain_id -> (matched, session_id 组合)
        self._ptr: dict[str, int] = {}
        # 敏感数据 taint: node_idx 集合（染毒节点索引）
        self._tainted: set = set()
        # 敏感数据 taint 反索引：资源路径 → 已染毒（O(1) 命中，避免扫描全部染毒节点）
        self._tainted_resources: set = set()
        # taint 传播路径（前端攻击链图用）：
        # node_idx -> 使该节点染毒的前驱 node_idx（CRED 源为 None）
        self._taint_parent: dict[int, int | None] = {}
        # (parent_idx, child_idx) -> 触发传播的共享资源（图上的 data 边标签）
        self._taint_edge_label: dict[tuple[int, int], str] = {}
        # 资源 -> 首次染毒该资源的节点 seq（给传播节点找父）
        self._taint_origin: dict[str, int] = {}
        # 生命周期：资源路径 -> 最近活跃 seq（"alive" 判定）
        self._alive_resources: dict[str, int] = {}

        # 自上次 seed 后的节点数（供外部保存游标）
        self.seq_next: int = 0

    # ---------------- 规则加载 ----------------

    def from_rules(self, l2: dict | None = None) -> None:
        """加载 L2 combo_chains 定义（默认走 rules_loader）。"""
        if l2 is None:
            from ...rules_loader import load_l2
            l2 = load_l2()
        combo = (l2 or {}).get("combo_chains", {}) or {}
        self._combo = combo
        self._chains = list(combo.get("chains", []))
        self._stages_patterns = {
            name: [re.compile(p, re.IGNORECASE) for p in pats]
            for name, pats in (combo.get("stages", {}) or {}).items()
        }

    @property
    def pending_prefixes(self) -> list[PendingPrefix]:
        """当前所有前序链（matched > 0 且未完整）。"""
        out: list[PendingPrefix] = []
        for chain in self._chains:
            stages = tuple(chain.get("stages", []))
            if not stages:
                continue
            cid = str(chain.get("id", ""))
            # 聚合该 chain 的所有桶（全局 + 各实例），取最大进度作为该链前序进度。
            matched = self._ptr.get(cid, 0)
            for k, v in self._ptr.items():
                if k.startswith(f"{cid}@@") and v > matched and v < len(stages):
                    matched = v
            if 0 < matched < len(stages):
                out.append(PendingPrefix(
                    chain_id=cid,
                    stages=stages,
                    matched=matched,
                    risk_level=str(chain.get("risk_level", "high")),
                ))
        return out

    # ---------------- 生命周期 ----------------

    def _lifecycle_for(self, detail: str, stage: str, is_error: bool) -> str:
        """判定动作涉及能力的生命周期变化。

        - 创建失败（工具结果 is_error + 能力创建语义，或文本含失败语义）→ never_activated
        - 创建/启动语义（LISTEN/PERSIST/写代码）→ alive
        - 销毁/删除/停止语义 → dead（后续引用不判链）
        """
        if is_error:
            # 工具结果错误 = 该次动作未能成功建立（LISTEN/PERSIST/写文件是能力建立）
            if stage in ("LISTEN", "PERSIST") or _NEVER_ACTIVATED_RE.search(detail):
                return "never_activated"
        if _DESTROY_RE.search(detail):
            return "dead"
        if stage in ("LISTEN", "PERSIST"):
            return "alive"
        if ">>" in detail or ">" in detail:  # 写入文件/覆盖（能力文件被创建）
            return "alive"
        return ""

    def _record_lifecycle(self, node: StateNode) -> None:
        """把新节点涉及的能力资源登记（或销毁）到 _alive_resources。

        destroy 动作除了登记 dead，还要把与它关联的（直接路径/basename/实例端口）
        存活资源一并从 alive 中移除，并**打断依赖该能力的前序链**（服务已关，
        后续阶段不再成立）——堵"能力已销毁仍判链"的误报。
        实例级销毁（显式端口/socket/unit）只清对应实例的链桶，不影响其他端口。
        """
        if node.lifecycle == "dead":
            cleared_insts: list[str] = []
            # a) 精确实例定位：销毁动作显式提到端口/socket/unit
            for inst in node.instances:
                key = f"inst:{inst}"
                if key in self._alive_resources:
                    del self._alive_resources[key]
                    cleared_insts.append(inst)
            # b) 路径/basename 定位（文件载体销毁，无法精确到桶）
            path_hit = False
            for r in node.resources:
                if r in self._alive_resources:
                    del self._alive_resources[r]
                    path_hit = True
            # basename 关联（kill -f admin_api.py 命中 ~/devtools/admin_api.py）
            detail = node.action_detail
            for r in list(self._alive_resources):
                base = r.rsplit("/", 1)[-1]
                if base and base in detail:
                    del self._alive_resources[r]
                    path_hit = True
            # c) 判定：纯实例销毁 → 只清对应实例桶（不误杀其他端口）；
            #    命中文件载体或无法定位 → 保守全清（原行为，置底防线）
            if cleared_insts and not path_hit:
                for inst in cleared_insts:
                    self._reset_chains_for_instance(inst)
            else:
                self._reset_chains_on_destroy()
            return
        if node.lifecycle == "alive":
            for r in node.resources:
                self._alive_resources[r] = node.seq
            # 实例也登记（inst: 前缀），供实例级销毁/活性判定
            for inst in node.instances:
                self._alive_resources[f"inst:{inst}"] = node.seq

    def _reset_chains_for_instance(self, inst: str) -> None:
        """只重置指定实例在全部链上的进度（不影响其他端口/资源）。"""
        for k in list(self._ptr):
            if k.endswith(f"@@{inst}"):
                self._ptr[k] = 0

    def _reset_chains_on_destroy(self) -> None:
        """能力被销毁：保守断开所有前序链（清空指针）。后续不再续链。"""
        for cid in self._ptr:
            self._ptr[cid] = 0

    @property
    def alive_resources(self) -> dict[str, int]:
        """仍然鲜活（没被销毁）的资源路径 → 最近活跃 seq。"""
        return dict(self._alive_resources)

    # ---------------- 种子 / 增量 ----------------

    def seed(self, sessions: list[dict] | None = None) -> int:
        """全量/定期灌入历史 session（多 session 各动作追加到时间线）。返回节点数。

        历史节点也要推进链指针 / 生命周期 / taint，否则后续 advance() 无法在
        历史基础上补全链。历史阶段推进时若某条链被补全，属于历史事实，不阻断
        当前动作（实时只在"当前动作补全链"时拦截）。
        """
        added = 0
        for s in sessions or []:
            sid = str(s.get("session_id", "s"))
            for a in s.get("action_history", []) or []:
                node = self._append(a, sid, instance_id=str(s.get("instance_id") or ""))
                if node is None:
                    continue
                added += 1
                self._record_lifecycle(node)
                self._advance_taint(node)
                self._advance_chains(node)  # 历史阶段推进指针（补全匹配属于历史，忽略）
        return added

    def advance(
        self,
        a_next: dict,
        action_history: list[dict] | None = None,
        session_id: str = "current",
        is_error: bool = False,
        external_resources: dict | None = None,
        agent_id: str = "",
        instance_id: str = "",
    ) -> "AdvanceResult":
        """增量推进：把当前动作追加到时间线 → 链指针推进 → 判定。

        a_next: {"action_type", "action_detail"} 当前待执行动作。
        action_history: 可选，当前 session 到这一步的历史（未含 a_next），
            用于"跨会话渲染前序链路径"。缺省则只针对时间线已累积的节点。
        is_error: 工具结果失败标志（AgentGate 的 is_error / 退出码非 0）。
        """
        # 1. 新节点
        seq = self.seq_next
        node = self._append(
            a_next, session_id, is_error=is_error,
            agent_id=agent_id, instance_id=instance_id,
        )
        if node is None:
            return AdvanceResult(seq=self.seq_next)
        seq = self.seq_next  # 追加后的下一个序号（节点 seq 索引为 seq_next-1）

        # 2. 生命周期登记（在链判定前，让"创建失败/销毁"正确失效前序）
        self._record_lifecycle(node)

        # 3. 链推进（当前动作参与；dead 资源不续链）
        matched = self._advance_chains(node)

        # 4. 敏感数据 taint 增量（P2）
        self._advance_taint(node)

        # 5. 判定
        #    若当前动作正好补全一条链 → matched（阻断级）
        #    否则记录 pending 前序（供外部持久化/预判）
        exfil_violations = self._check_exfil_after_taint(node)
        return AdvanceResult(
            seq=seq,
            node=node,
            matched=matched,
            pending_prefixes=self.pending_prefixes,
            exfil=exfil_violations,
        )

    def _archive_nodes(self, nodes: list[StateNode], archive_dir: Path | None = None) -> Path:
        """把旧节点写 gzip JSONL；写成功后才允许调用方删除/重置。"""
        if archive_dir is None:
            raw = os.getenv("AGENT_MOSS_CHAIN_ARCHIVE_DIR", "")
            if raw:
                archive_dir = Path(raw)
            else:
                from ...infra.paths import get_state_root
                archive_dir = get_state_root() / "chain-archive"
        archive_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(archive_dir, 0o700)
        except OSError:
            pass
        stamp = time.strftime("%Y%m%dT%H%M%S", time.localtime())
        path = archive_dir / f"chain-nodes-{self.agent_id or 'default'}-{stamp}-{int(time.time()*1000)%1000:03d}.jsonl.gz"
        payload = "\n".join(
            json.dumps(
                {k: (list(v) if k == "resources" or k == "instances" else v)
                 for k, v in n.__dict__.items()},
                ensure_ascii=False,
            )
            for n in nodes
        ) + "\n"
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(gzip.compress(payload.encode("utf-8")))
        # 归档成功后再滚动清理旧归档（只写不删会无限膨胀）；清理失败不影响轮转。
        try:
            removed, remain_files, remain_bytes = cleanup_chain_archives(archive_dir)
            if removed:
                logger.info(
                    "chain-archive 清理: 删除 %d 个旧归档（剩余 %d 个 / %d 字节）",
                    removed, remain_files, remain_bytes,
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning("chain-archive 清理失败（继续）: %s", exc)
        return path

    def rotate(self, archive_dir: Path | None = None, retain: int | None = None) -> tuple[int, str]:
        """归档旧节点并只保留最近窗口，重建链指针/taint 状态。

        返回 ``(归档条数, 归档文件)``。归档失败抛异常，调用方不得丢状态。
        """
        keep = _retain_nodes() if retain is None else max(1, min(retain, _MAX_NODES - 1))
        if len(self.nodes) <= keep:
            return 0, ""
        old = self.nodes[:-keep]
        kept = self.nodes[-keep:]
        path = self._archive_nodes(old, archive_dir)

        # 重建为一棵新的时间线：保留节点重新编号，链指针/taint 从头 replay。
        self.nodes = []
        self._ptr = {}
        self._tainted = set()
        self._tainted_resources = set()
        self._taint_parent = {}
        self._taint_edge_label = {}
        self._taint_origin = {}
        self._alive_resources = {}
        self._seeded_keys = set()
        self._capacity_warned = set()
        self.seq_next = 0
        for n in kept:
            action = {
                "action_type": n.action_type,
                "action_detail": n.action_detail,
                "called_at": n.timestamp or "",
                "agent_id": n.agent_id,
                "instance_id": n.instance_id,
            }
            node = self._append(
                action, n.session_id, is_error=n.is_error,
                agent_id=n.agent_id, instance_id=n.instance_id,
            )
            if node is not None:
                self._record_lifecycle(node)
                self._advance_taint(node)
                self._advance_chains(node)
        return len(old), str(path)

    def _append(
        self,
        action: dict,
        session_id: str,
        is_error: bool = False,
        agent_id: str = "",
        instance_id: str = "",
    ) -> StateNode | None:
        """构造并追加一个节点，返回节点；空 detail 跳过。

        时间线上限保护：防无限增长（高频大项目下平凡动作会持续产生节点）。
        超限后**忽略新节点**（warn 一次）并返回 None，由外部低频 /api/v1/review
        重建来恢复（seq==index 不变式不被破坏，链指针/taint 索引安全）。

        幂等（2026-11）：带 ``called_at`` 的动作按「session + 类型 + 详情 +
        时间」去重。review 会周期性重复 seed 全量历史，不去重就会成倍膨胀。
        """
        ad = str(action.get("action_detail", "") or "")
        at = str(action.get("action_type", "") or "")
        if not ad:
            return None
        _called_at = str(action.get("called_at", "") or "")
        _dedupe_key = ""
        if _called_at:
            _dedupe_key = _fingerprint(session_id, at, ad, _called_at)
            if _dedupe_key in self._seeded_keys:
                return None  # 这条动作已经在时间线里了
        # 触顶保护（硬上限）
        if len(self.nodes) >= _MAX_NODES:
            logger.warning(
                "stateful 时间线达到兜底上限 %d（agent=%s），自动轮转未生效，忽略本次新节点；"
                "请检查链状态归档目录权限/磁盘空间，不要用 state reset 清空历史",
                _MAX_NODES, self.agent_id,
            )
            return None
        stage = _mark_stage(ad, self._stages_patterns)
        node = StateNode(
            seq=self.seq_next,
            session_id=session_id,
            action_type=at,
            action_detail=ad,
            stage=stage,
            resources=_extract_resources(ad),
            instances=_extract_instances(ad, stage),
            is_error=is_error,
            agent_id=str(action.get("agent_id") or agent_id or ""),
            instance_id=str(action.get("instance_id") or instance_id or ""),
            lifecycle=self._lifecycle_for(ad, stage, is_error),
            # 调用方带 called_at → 用真实发生时间；否则用本地接收时刻（实时路径）
            timestamp=(str(action.get("called_at", "")) or self._now()),
        )
        self.nodes.append(node)
        self.seq_next += 1
        if _dedupe_key:
            self._seeded_keys.add(_dedupe_key)
        # 容量分级预警（2026-11）：在**触顶之前**提醒，给运维留处理时间。
        # 放在 append 之后，这样「第 70 条落库时正好打 70% 的提醒」。
        _n = len(self.nodes)
        for _ratio in _CAPACITY_WARN_RATIOS:
            if _n >= int(_MAX_NODES * _ratio) and _ratio not in self._capacity_warned:
                self._capacity_warned.add(_ratio)
                logger.warning(
                    "stateful 时间线已用 %d%%（%d/%d 节点，agent=%s）。"
                    "达到上限后会自动归档旧节点并保留最近窗口，不会丢新动作；"
                    "无需手工 state reset。",
                    int(_ratio * 100), _n, _MAX_NODES, self.agent_id,
                )
        return node

    def _advance_chains(self, node: StateNode) -> ChainMatch | None:
        """链指针推进：若新节点命中某条链的下一阶段，推进 matched。

        dead 资源上的节点不推进（服务已关/文件已删，前序不成立）。
        """
        if node.lifecycle == "dead":
            # 销毁动作不推进链；但本身可能是"清理行为"，标记无影响
            return None
        if node.lifecycle == "never_activated":
            # 创建失败：后续不能依赖它；把涉及这条链的前序"失效"
            self._invalidate_chain_on_failure(node)
            return None
        # 新动作不在 alive 资源上但在某已 alive 资源上使用 → 正常推进视图
        stage = node.stage
        if not stage:
            return None
        for chain in self._chains:
            stages = list(chain.get("stages", []))
            if not stages:
                continue
            cid = str(chain.get("id", ""))
            # 桶化推进：有实例节点只推自己的实例桶；无实例节点推全局桶 + 所有
            # 活跃实例桶（信息不足时保守推进一切可能，避免漏判）。
            targets = self._targets_for_node(node, cid)
            for key in targets:
                cur = self._ptr.get(key, 0)
                if cur < len(stages) and stages[cur] == stage:
                    self._ptr[key] = cur + 1
                    if cur + 1 >= len(stages):
                        # 链补全
                        path = self._chain_path(stages)
                        return ChainMatch(
                            chain_id=cid,
                            stages=tuple(stages),
                            risk_level=str(chain.get("risk_level", "high")),
                            reason=str(chain.get("reason", "检测到组合攻击链")),
                            path=path,
                        )
        return None

    def _targets_for_node(self, node: StateNode, chain_id: str) -> list[str]:
        """当前节点应推进的链桶集合。

        带实例节点 → 只推"活跃匹配"的实例桶（同端口归同一链，不同端口不串扰）；
        端口无对应活跃监听（信息孤岛）→ 回退全局桶（保守补全无端口链）。
        无实例节点 → 全局桶 + 所有活跃实例桶（保守推进一切可能）。
        """
        if node.instances:
            active = [i for i in node.instances if f"inst:{i}" in self._alive_resources]
            if active:
                return [_buck_key(chain_id, inst) for inst in active]
            return [chain_id]
        targets = [chain_id]  # 全局桶
        for k in list(self._alive_resources):
            if k.startswith("inst:"):
                inst = k[len("inst:"):]
                targets.append(_buck_key(chain_id, inst))
        return targets

    def _invalidate_chain_on_failure(self, node: StateNode) -> None:
        """创建失败：让依赖该资源的链前序失效（回退指针）。

        带实例信息 → 只失效该实例的链桶；无实例信息 → 保守全清（原行为）。
        """
        if node.instances:
            for inst in node.instances:
                self._reset_chains_for_instance(inst)
            return
        failed_res = set(node.resources)
        if not failed_res:
            return
        # 命中该链的下一阶段本来要依赖 failed 资源 → 把前序回退/失效
        for chain in self._chains:
            cid = str(chain.get("id", ""))
            if self._ptr.get(cid, 0) > 0:
                # 简化：创建失败会让所有前序链的"起头"失效（后续不再续）
                self._ptr[cid] = 0

    def _chain_path(self, stages: list[str]) -> list:
        """构造链的反例路径（最近匹配节点的快照，按全局序）。

        每步元组：[(session_id, seq, detail, timestamp)]——timestamp 为该步真实发生
        时间（无则 None），便于展示"哪几个具体时间点的 tool call 拼成了这条链"。
        """
        path: list = []
        want = stages[0]
        for n in self.nodes:
            if n.stage == want:
                path.append(
                    (n.session_id, n.seq, n.action_detail[:60], n.timestamp,
                     n.agent_id, n.instance_id)
                )
                idx = stages.index(n.stage)
                if idx + 1 < len(stages):
                    want = stages[idx + 1]
                else:
                    break
        return path

    # ---------------- 敏感数据 taint（P2） ----------------

    def _advance_taint(self, node: StateNode) -> None:
        """增量 taint：新节点若染毒则记录；若有共享载体则传播。

        同时记录传播来源（parent + 共享资源），供前端画攻击链图。
        """
        if node.lifecycle == "dead":
            return
        idx = node.seq
        tainted_res: set = set()
        parent: int | None = None
        label = ""
        for r in node.resources:
            if self._resource_tainted(r):
                tainted_res.add(r)
                if parent is None:
                    parent = self._taint_origin.get(r)
                    label = r
        if node.stage == "CRED" and any(_CRED_FILE_RE.search(r) for r in node.resources):
            self._tainted.add(idx)
            parent = None  # 凭据源 = 链头
            label = ""
            for r in node.resources:
                tainted_res.add(r)
        if tainted_res:
            self._tainted.add(idx)
            self._taint_parent[idx] = parent
            if parent is not None:
                self._taint_edge_label[(parent, idx)] = label
            # 节点一旦染毒，它的**全部资源**都视为携带同一份敏感数据：
            # mv/cp 的目标路径也是这份数据的载体，必须一起染毒。旧实现只
            # update(tainted_res)（命中的旧资源），目标路径没染毒 → 改名链
            # 在第二次 mv 处断开（2026-10 修，双端同步）。
            for r in node.resources:
                self._tainted_resources.add(r)
                self._taint_origin.setdefault(r, idx)

    def _resource_tainted(self, resource: str) -> bool:
        """某个资源是否已被染毒（O(1) 反索引，避免每次扫描全部染毒节点）。"""
        return resource in self._tainted_resources

    def _trace_taint_chain(self, idx: int) -> list[int]:
        """沿 taint parent 回溯出 CRED 源 → 当前节点的完整路径。"""
        chain = [idx]
        seen = {idx}
        while True:
            parent = self._taint_parent.get(chain[-1])
            if parent is None or parent in seen:
                break
            chain.append(parent)
            seen.add(parent)
        return list(reversed(chain))

    def _taint_graph(self, chain: list[int]) -> dict:
        """把 taint 路径转成前端可画的结构化图（data 边带共享资源标签）。"""
        g_nodes: list[dict] = []
        g_edges: list[dict] = []
        for k, ni in enumerate(chain):
            n = self.nodes[ni]
            role = "source" if k == 0 else ("sink" if k == len(chain) - 1 else "carrier")
            g_nodes.append({
                "session_id": n.session_id,
                "seq": n.seq,
                "stage": n.stage,
                "action_detail": n.action_detail,
                "resources": sorted(n.resources),
                "role": role,
                "instance_id": n.instance_id,
            })
            if k > 0:
                prev = chain[k - 1]
                g_edges.append({
                    "from": k - 1,
                    "to": k,
                    "type": "data",
                    "label": self._taint_edge_label.get((prev, ni), ""),
                })
        if g_nodes:
            g_nodes[-1]["witness"] = True
        expr: list[dict] = [{"token": "CRED", "node_index": 0}]
        if len(chain) > 2:
            expr.append({"token": "共享载体", "node_index": list(range(1, len(chain) - 1))})
        expr.append({"token": "EXFIL", "node_index": len(chain) - 1})
        return {
            "property_id": "sensitive-data-flow",
            "property_short": "P2",
            "property_name": "敏感数据传播外传",
            "property_expression": expr,
            "nodes": g_nodes,
            "edges": g_edges,
        }

    def _check_exfil_after_taint(self, node: StateNode) -> list:
        """若当前节点已染毒且是外传形态 → 敏感数据传播外传。"""
        if node.seq not in self._tainted:
            return []
        if _EXFIL_RE.search(node.action_detail):
            chain = self._trace_taint_chain(node.seq)
            src = self._taint_source(node, chain)
            return [{
                "property_id": "sensitive-data-flow",
                "reason": f"敏感数据传播外传：{src} → {node.session_id}#{node.seq} 经共享载体外发",
                "risk_level": "critical",
                "path": [
                    (self.nodes[j].session_id, self.nodes[j].seq,
                     self.nodes[j].action_detail[:60], self.nodes[j].timestamp,
                     self.nodes[j].agent_id, self.nodes[j].instance_id)
                    for j in chain
                ],
                "graph": self._taint_graph(chain),
                "node_idx": node.seq,
            }]
        return []

    def _taint_source(self, node: StateNode, chain: list[int] | None = None) -> str:
        if chain:
            n = self.nodes[chain[0]]
            for r in node.resources:
                if r in n.resources:
                    return f"{n.session_id}#{n.seq} 访问 {r}"
        # 兜底（旧状态无 parent 信息）
        for i in sorted(self._tainted):
            if i != node.seq:
                n = self.nodes[i]
                for r in node.resources:
                    if r in n.resources:
                        return f"{n.session_id}#{n.seq} 访问 {r}"
        return "未知凭据源"

    # ---------------- 序列化/状态 ----------------

    def to_snapshot(self) -> dict:
        """持久化快照：节点 + 指针 + taint + alive 资源（供 SQLite 存）。"""
        return self.finalize_snapshot(self.to_snapshot_parts())

    def to_snapshot_parts(self) -> dict:
        """**锁内调用**：只做浅拷贝（O(n) 复制指针，2 万节点约 0.2ms）。

        为什么要拆成两阶段（2026-11 招行长稳实测）：``to_snapshot`` 完整构建
        2 万节点要 40ms、4 万节点 117ms。如果它在状态锁内执行，每秒一次的落盘
        就是一次全局卡顿 —— 所有 ``apply_action`` 都要等，实测长稳 10 分钟
        QPS 从 47 掉到 32、p95 从 225ms 涨到 529ms。

        现在：锁内只取引用（浅拷贝），真正的逐节点构建和 json.dumps 在锁外做
        （``finalize_snapshot``）。节点对象创建后不再被修改，浅拷贝安全。
        """
        return {
            "agent_id": self.agent_id,
            "nodes": list(self.nodes),
            "ptrs": dict(self._ptr),
            "tainted": sorted(self._tainted),
            # taint 传播路径（前端攻击链图）；taint_edge_label 是 tuple key，
            # 不入快照（重启后可从 parent + 资源交集重建，结构不受影响）。
            "taint_parent": {str(k): v for k, v in self._taint_parent.items()},
            "taint_origin": dict(self._taint_origin),
            "alive": {k: v for k, v in self._alive_resources.items()},
            "seq_next": self.seq_next,
            # seed 去重指纹：不持久化的话，重启后 review 会再把全量历史追加一遍。
            # 锁内只做 set 浅拷贝（10 万条约 2ms），排序在 finalize 里做。
            "seeded_keys": set(self._seeded_keys),
        }

    @staticmethod
    def finalize_snapshot(parts: dict) -> dict:
        """**锁外调用**：把浅拷贝展开成可 JSON 化的完整快照。"""
        return {
            "agent_id": parts["agent_id"],
            "nodes": [
                {k: (v if k != "resources" else list(v)) for k, v in n.__dict__.items()}
                for n in parts["nodes"]
            ],
            "ptrs": parts["ptrs"],
            "tainted": parts["tainted"],
            "taint_parent": parts["taint_parent"],
            "taint_origin": parts["taint_origin"],
            "alive": parts["alive"],
            "seq_next": parts["seq_next"],
            "seeded_keys": sorted(parts.get("seeded_keys") or ()),
        }

    def restore(self, snapshot: dict | None) -> None:
        """从快照恢复（幂等，供服务重启后重建）。

        ⚠️ 幂等要求先清空（2026-11）：原先直接 ``nodes.append`` —— 同一个
        tracker 被 restore 两次，节点就翻倍。这与 ``seed`` 重复追加是同一类坑，
        只是当前调用路径恰好每次 new 新对象才没暴露。防御性清空。
        """
        if not snapshot:
            return
        self.nodes = []
        self._ptr = {}
        self._tainted = set()
        self._taint_parent = {}
        self._taint_origin = {}
        self._taint_edge_label = {}
        self._tainted_resources = set()
        self._alive_resources = {}
        self._seeded_keys = set()
        self._capacity_warned = set()
        self.seq_next = 0
        self.agent_id = str(snapshot.get("agent_id", self.agent_id))
        for raw in snapshot.get("nodes", []) or []:
            n = StateNode(
                seq=int(raw.get("seq", 0)),
                session_id=str(raw.get("session_id", "")),
                action_type=str(raw.get("action_type", "")),
                action_detail=str(raw.get("action_detail", "")),
                stage=str(raw.get("stage", "")),
                resources=tuple(raw.get("resources") or ()),
                instances=tuple(raw.get("instances") or ()),  # 旧快照无此字段 → 空
                is_error=bool(raw.get("is_error", False)),
                agent_id=str(raw.get("agent_id", "")),  # 旧快照无此字段 → 空
                instance_id=str(raw.get("instance_id", "")),  # 旧快照无此字段 → 空
                lifecycle=str(raw.get("lifecycle", "")),
                timestamp=(raw.get("timestamp") or None),  # 旧快照无此字段 → None
            )
            self.nodes.append(n)
        self.seq_next = int(snapshot.get("seq_next", len(self.nodes)))
        self._ptr = {str(k): int(v) for k, v in (snapshot.get("ptrs") or {}).items()}
        self._tainted = set(int(i) for i in (snapshot.get("tainted") or []))
        self._taint_parent = {
            int(k): (int(v) if v is not None else None)
            for k, v in (snapshot.get("taint_parent") or {}).items()
        }
        self._taint_origin = {
            str(k): int(v) for k, v in (snapshot.get("taint_origin") or {}).items()
        }
        self._taint_edge_label = {}  # 旧快照无此字段：边标签缺失，图结构不受影响
        # seed 去重指纹（旧快照没有这个字段：从已有节点重建，保证升级后
        # 第一次 review 不会把历史再追加一遍）。
        # 无论是否有旧 keys，都用新指纹补一遍当前节点：指纹算法从 2026-11 起
        # 对时间/别名/截断做归一，旧 keys 可能对不上当前节点的规范键。
        _keys = snapshot.get("seeded_keys")
        self._seeded_keys = {str(k) for k in _keys} if _keys else set()
        for n in self.nodes:
            if getattr(n, "timestamp", ""):
                self._seeded_keys.add(
                    _fingerprint(n.session_id, n.action_type, n.action_detail, n.timestamp)
                )
        # 重建 taint 资源反索引：由染毒节点的 resources 推导（并集 all）
        self._tainted_resources = set()
        for i in self._tainted:
            if 0 <= i < len(self.nodes):
                self._tainted_resources.update(self.nodes[i].resources)
        if self._tainted and not self._taint_parent:
            self._rebuild_taint_parent()
        if not self._taint_origin:
            for i in sorted(self._tainted):
                for r in self.nodes[i].resources:
                    self._taint_origin.setdefault(r, i)
        self._alive_resources = {
            str(k): int(v) for k, v in (snapshot.get("alive") or {}).items()
        }

    def _rebuild_taint_parent(self) -> None:
        """旧快照无 parent 信息时，按 seq 顺序找最近的资源相交染毒前驱。"""
        for i in sorted(self._tainted):
            n = self.nodes[i]
            parent = None
            for j in range(i - 1, -1, -1):
                if j in self._tainted and (self.nodes[j].resources & n.resources):
                    parent = j
                    break
            self._taint_parent[i] = parent


@dataclass
class AdvanceResult:
    """advance() 的一次输出。"""

    seq: int = 0
    node: StateNode | None = None
    matched: ChainMatch | None = None
    pending_prefixes: list = field(default_factory=list)
    exfil: list = field(default_factory=list)

    @property
    def should_block(self) -> bool:
        return self.matched is not None or bool(self.exfil)

    def to_judgment(self) -> dict | None:
        """转成 coordinator 可用的 SecurityJudgment 参数（命中时）。"""
        if self.matched:
            return self.matched.to_judgment()
        if self.exfil:
            v = self.exfil[0]
            return {
                "property_id": v["property_id"],
                "reason": v["reason"],
                "risk_level": v["risk_level"],
                "path": v["path"],
            }
        return None


def advance_if_completes_chain(
    tracker: StatefulChainTracker,
    sessions: list[dict] | None,
    action_history: list[dict] | None,
    a_next: dict,
    session_id: str = "current",
    is_error: bool = False,
) -> AdvanceResult:
    """便捷入口：先 seed 历史，再 advance 当前动作（一次调用完成全量+增量）。

    等价于：
        tracker.seed(sessions)
        return tracker.advance(a_next, action_history, session_id, is_error)
    """
    tracker.seed(sessions)
    return tracker.advance(
        a_next,
        action_history=action_history,
        session_id=session_id,
        is_error=is_error,
    )