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
import hashlib
import json
import logging
import os
import re
import time
from copy import copy, deepcopy
from dataclasses import asdict, dataclass, field, replace
from bisect import bisect_left
from datetime import datetime, timezone
from heapq import heappop, heappush
from pathlib import Path
from typing import Any, NamedTuple

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
        dt, _ = _parse_history_datetime(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return str(int(dt.timestamp()))
    except (OSError, ValueError, OverflowError):
        return value


def _legacy_audit_fingerprint(session_id: str, action_type: str, action_detail: str, called_at: str) -> str:
    """兼容旧 Gate 审计库的秒级时间、工具别名和截断正文。"""
    return _fingerprint(session_id, _canonical_action_type(action_type),
                        _canonical_detail(action_detail), _canonical_called_at(called_at))


class StatefulAnalysisUnavailable(RuntimeError):
    """A trusted Gate call could not be evaluated against the required state."""


class UnconfirmedGateRetry(StatefulAnalysisUnavailable):
    """A retry with uncertain delivery has no confirmed result to reuse."""


class GateCallConflict(UnconfirmedGateRetry):
    """The same Gate call id was reused with different content or timing."""


def _gate_order(action: dict) -> tuple[int, str] | None:
    call_id = action.get("_gate_call_id")
    call_time = action.get("_gate_call_time_us")
    if isinstance(call_id, str) and call_id and type(call_time) is int and call_time > 0:
        return call_time, call_id
    return None


_FRACTIONAL_SECONDS = re.compile(r"(?<=\d\d:\d\d:\d\d)[.,]([0-9]+)")
_DATETIME_FRACTION = re.compile(r"([0-9]{4}-[0-9]{2}-[0-9]{2}.[0-9]{2}:[0-9]{2}:[0-9]{2})[.,]([0-9]+)")
_MICROSECOND_TIMESTAMP_LENGTH = len("0000-00-00T00:00:00.000000")


def _parse_history_datetime(value: str) -> tuple[datetime, str]:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    remainder = ""
    if match := _DATETIME_FRACTION.match(value):
        clock, fraction = match.groups()
        offset = value[match.end():]
        if offset and offset[0] not in "+-":
            raise ValueError("unexpected text after fractional seconds")
        remainder = fraction[6:].rstrip("0")
        value = f"{clock}.{fraction[:6].ljust(6, '0')}{offset}"
    try:
        return datetime.fromisoformat(value), remainder
    except ValueError:
        # Python 3.10 also limits fractional seconds in an explicit UTC offset.
        normalized = _FRACTIONAL_SECONDS.sub(lambda m: "." + m[1][:6].ljust(6, "0"), value)
        if normalized == value:
            raise
        return datetime.fromisoformat(normalized), remainder


def _history_time(value: object, *, local_naive: bool = False) -> str | None:
    """Normalize audit timestamps for chronological comparisons."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed, remainder = _parse_history_datetime(value)
        if parsed.tzinfo is not None or local_naive:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        # Retain the existing microsecond prefix and compare any finer precision after it.
        return parsed.isoformat(timespec="microseconds") + remainder
    except (OSError, OverflowError, ValueError):
        return None


def _history_priority(value: object) -> tuple[bool, str]:
    stamp = _history_time(value)
    return stamp is None, stamp or ""


def _fingerprint(session_id: str, action_type: str, action_detail: str, called_at: str) -> str:
    """动作指纹（seed 去重用）。

    只对**带 called_at 的动作**生成 —— 同一 session 里重复执行同一命令是
    合法行为，没有时间戳就无法区分，宁可不作为也不误去重。
    """
    raw = "\x00".join((str(session_id), str(action_type), str(action_detail), str(called_at)))
    return hashlib.blake2b(raw.encode("utf-8", "replace"), digest_size=8).hexdigest()


def _is_sqlite_second(value: object) -> bool:
    return isinstance(value, str) and len(value) == 19 and value[10] == " "


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
    # 保留 action.called_at 原文，缺省时记录 Moss 接收时间。
    timestamp: str | None = None
    gate_call_id: str = ""
    gate_call_time_us: int = 0
    input_fingerprint: str = ""
    # None 表示只有回顾审计，空命中同样保存为已确认结果。
    confirmed: dict | None = None
    # None 是未增加此字段的旧快照，空串表示新的无时间戳记录。
    legacy_fingerprint: str | None = None

    @property
    def order_key(self) -> tuple[int, str] | None:
        if self.gate_call_id:
            return self.gate_call_time_us, self.gate_call_id
        return None


class _ReviewRecord(NamedTuple):
    session_id: str
    instance_id: str
    action: dict
    gate_order: tuple[int, str] | None
    legacy_fingerprint: str


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
        """实时请求无 called_at 时，记录带时区的 UTC 接收时间。"""
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def __init__(self, agent_id: str = "", properties=None):
        self.agent_id = agent_id
        # 复用 l2_rules.json combo_chains（单一事实源）
        self._combo: dict[str, Any] = {}
        self._chains: list[dict] = []
        self._stages_patterns: dict[str, list[re.Pattern]] = {}
        self.from_rules()

        self._session_ends: set = set()  # session 已结束（预留）
        # 旧快照里仍有效、但无法从旧节点重建的去重键。
        self._unmapped_legacy_keys: tuple[str, ...] = ()
        self.archived_through: tuple[int, str] | None = None
        self._legacy_archive_boundary: tuple[str, tuple[str, ...]] | None = None
        self.generation = 0
        self._reset_timeline()

    def _reset_timeline(self) -> None:
        """初始化保留窗口，以及从窗口节点派生的索引和规则状态。"""
        self.nodes: list[StateNode] = []
        self.seq_next = 0
        # 无编号动作只按显式 called_at 去重，同一会话可以合法地重复执行命令。
        self._seeded_keys: set[str] = set()
        self._legacy_positions: dict[str, int] = {}
        self._legacy_audit_candidates: dict[str, StateNode | None] | None = None
        self._gate_nodes: dict[tuple[str, str], StateNode] = {}
        self._last_gate_order: tuple[int, str] | None = None
        self._gate_window_sorted = True
        self._latest_history_priority: tuple[bool, str] = (False, "")
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

    def _review_records(self, sessions: list[dict] | None) -> list[_ReviewRecord]:
        """先做批内去重，再决定哪些无号记录进入本轮回顾窗口。"""
        records: list[_ReviewRecord] = []
        batch_keys: set[tuple[str, str] | str] = set()
        for session in sessions or []:
            sid = str(session.get("session_id", "s"))
            instance = str(session.get("instance_id") or "")
            for action in session.get("action_history") or []:
                if not action.get("action_detail"):
                    continue
                order = _gate_order(action)
                fingerprint = self._legacy_key(action, sid) if order is None else ""
                key = (sid, order[1]) if order is not None else fingerprint
                if key in batch_keys:
                    continue
                if key:
                    batch_keys.add(key)
                records.append(_ReviewRecord(sid, instance, action, order, fingerprint))

        if len(records) <= _MAX_NODES or all(record.gate_order is not None for record in records):
            return records
        if all("_sqlite_review_rank" in record.action for record in records):
            # SQLite 排名从新到旧，反向排序恢复审计顺序。
            records.sort(key=lambda record: record.action["_sqlite_review_rank"], reverse=True)
            cutoff = len(records) - _MAX_NODES
            return [record for i, record in enumerate(records) if i >= cutoff or record.gate_order is not None]

        # 其他来源按时间选取最近记录，并保持它们在输入中的相对位置。
        by_time = sorted(range(len(records)), key=lambda i: _history_priority(records[i].action.get("called_at")))
        recent = set(by_time[-_MAX_NODES:])
        return [record for i, record in enumerate(records) if i in recent or record.gate_order is not None]

    def seed(self, sessions: list[dict] | None = None, *, archive_dir: Path | None = None) -> int:
        """按调用编号补录暂定节点，并按实际添加的数量准备容量。"""
        if _MAX_NODES <= 0:
            return 0
        additions: list[StateNode] = []
        history: dict[str, list[tuple[StateNode | str, int]]] = {}
        unnumbered_prefixes: dict[str, list[StateNode]] = {}
        outside_window: set[int] = set()
        records = self._review_records(sessions)
        legacy_matches = self._match_legacy_audit(records)
        for sid, instance, action, order, fingerprint in records:
            rank = action.get("_sqlite_review_rank", 0)
            rank = rank if type(rank) is int and rank > 0 else 0
            if order is not None:
                key = sid, order[1]
                prefix = unnumbered_prefixes.pop(sid, ())
                if retained := self._gate_nodes.get(key):
                    history.setdefault(sid, []).append((retained, rank))
                    continue
                if self._is_archived(order):
                    outside_window.update(id(node) for node in prefix)
                    continue
            else:
                if fingerprint in self._seeded_keys:
                    history.setdefault(sid, []).append((fingerprint, rank))
                    continue
                if retained := legacy_matches.get(fingerprint):
                    history.setdefault(sid, []).append((retained, rank))
                    continue
                if self._is_legacy_archived(action.get("called_at"), fingerprint):
                    continue
            node = self._make_node(action, sid, bool(action.get("is_error")) if order else False, "",
                                   instance, order=order, legacy_fingerprint=fingerprint)
            additions.append(node)
            history.setdefault(sid, []).append((node, rank))
            if order is None:
                unnumbered_prefixes.setdefault(sid, []).append(node)

        # 锚点已归档时，它的旧记录前驱也处于边界之外，不能改为从尾部补回。
        if outside_window:
            additions = [node for node in additions if id(node) not in outside_window]
        if not additions:
            return 0

        existing = len(self.nodes)
        if archive_dir is None and existing >= _MAX_NODES:
            return 0
        if existing + len(additions) <= _MAX_NODES and self._review_follows_window(additions, history):
            for node in self._merge_review(additions, history, include_retained=False):
                self._step(self._add_node(node), evaluate=False)
            return len(additions)
        merged = self._merge_review(additions, history)
        added_ids = {id(node) for node in additions}
        if archive_dir is not None and len(merged) > _MAX_NODES:
            keep = min(_MAX_NODES, _retain_nodes() + len(additions))
            # 先看容量边界是否真的移出了既有节点。只有旧补录被裁掉时，保留整个现有窗口。
            if self.nodes and any(node is self.nodes[0] for node in merged[-_MAX_NODES:]):
                keep = _MAX_NODES
            added = sum(id(node) in added_ids for node in merged[-keep:])
            if added:
                self._rotate_nodes(merged, archive_dir, keep)
            return added

        if len(merged) > _MAX_NODES:
            free = _MAX_NODES - existing
            candidates = [node for node in merged if id(node) in added_ids]
            allowed = {id(node) for node in candidates[-free:]}
            merged = [node for node in merged if id(node) not in added_ids or id(node) in allowed]
        if existing and merged[existing - 1] is not self.nodes[-1]:
            updated, _ = self._replay(merged)
            self.__dict__.update(updated.__dict__)
        else:
            for node in merged[existing:]:
                self._step(self._add_node(node), evaluate=False)
        return len(merged) - existing

    def _match_legacy_audit(self, records: list[_ReviewRecord]) -> dict[str, StateNode]:
        """Allow a unique old SQLite row to match a unique full-time legacy node."""
        if not self._legacy_positions or not any(
            record.gate_order is None and record.legacy_fingerprint not in self._seeded_keys
            and _is_sqlite_second(record.action.get("called_at")) for record in records
        ):
            return {}
        if self._legacy_audit_candidates is None:
            self._legacy_audit_candidates = {}
            for node in self.nodes:
                self._index_legacy_audit(node)

        matches = {}
        seen = {}
        for record in records:
            action = record.action
            called_at = action.get("called_at")
            if record.gate_order is not None or not _is_sqlite_second(called_at):
                continue
            key = _legacy_audit_fingerprint(record.session_id, action.get("action_type") or "",
                                            action.get("action_detail") or "", called_at)
            retained = self._legacy_audit_candidates.get(key)
            if retained is not None:
                fingerprint = record.legacy_fingerprint
                if key in seen:
                    matches.pop(seen[key], None)
                else:
                    seen[key] = fingerprint
                    matches[fingerprint] = retained
        return matches

    def will_rewrite(self, a_next: dict, session_id: str) -> bool:
        """Determine whether this request may need a structural state write."""
        order = _gate_order(a_next)
        if order is not None and a_next.get("_gate_delivery_uncertain") is True:
            # These retries either reuse a confirmation or stop before mutation.
            return False
        if len(self.nodes) >= _MAX_NODES:
            return True
        if order is None:
            return False
        existing = self._gate_nodes.get((session_id, order[1]))
        if existing is not None:
            return existing.confirmed is None
        return self._last_gate_order is not None and order < self._last_gate_order

    def advance(
        self,
        a_next: dict,
        action_history: list[dict] | None = None,
        session_id: str = "current",
        is_error: bool = False,
        external_resources: dict | None = None,
        agent_id: str = "",
        instance_id: str = "",
        *,
        archive_dir: Path | None = None,
    ) -> "AdvanceResult":
        """增量推进：把当前动作追加到时间线 → 链指针推进 → 判定。

        a_next: {"action_type", "action_detail"} 当前待执行动作。
        action_history: 可选，当前 session 到这一步的历史（未含 a_next），
            用于"跨会话渲染前序链路径"。缺省则只针对时间线已累积的节点。
        is_error: 工具结果失败标志（AgentGate 的 is_error / 退出码非 0）。
        """
        order = _gate_order(a_next)
        existing = None
        input_fingerprint = ""
        if order is not None:
            existing = self._gate_nodes.get((session_id, order[1]))
            input_fingerprint = self._input_fingerprint(a_next, is_error, agent_id, instance_id, order)
            if existing is not None:
                if existing.confirmed is not None:
                    if (existing.input_fingerprint == input_fingerprint
                            and existing.order_key == order):
                        return self._confirmed_result(existing)
                    raise GateCallConflict("同一 Gate call_id 的内容或时间不一致")
                if a_next.get("_gate_delivery_uncertain") is True:
                    raise UnconfirmedGateRetry("不确定送达的调用缺少已确认的状态化判定")
                if existing.order_key != order:
                    raise GateCallConflict("同一 Gate call_id 的时间不一致")
                if existing.input_fingerprint:
                    raise GateCallConflict("同一 Gate call_id 的重复调用缺少送达不确定标记")
                # Review seed 建的是未确认节点（无 input_fingerprint）：允许本次真实调用纠正它。
            if a_next.get("_gate_delivery_uncertain") is True:
                raise UnconfirmedGateRetry("不确定送达的调用缺少已确认的状态化判定")
            if self._is_archived(order):
                raise StatefulAnalysisUnavailable("调用早于当前链状态保留窗口")

        # 带编号的空动作也保存确认结果，供响应丢失后的重试关联。
        if order is None and not a_next.get("action_detail"):
            return AdvanceResult(seq=self.seq_next)
        legacy_fingerprint = self._legacy_key(a_next, session_id) if order is None else ""
        if legacy_fingerprint in self._seeded_keys:
            return AdvanceResult(seq=self.seq_next)

        node = self._make_node(a_next, session_id, is_error, agent_id, instance_id,
                               order=order, input_fingerprint=input_fingerprint,
                               legacy_fingerprint=legacy_fingerprint)
        at_capacity = len(self.nodes) >= _MAX_NODES
        out_of_order = order is not None and self._last_gate_order is not None and order < self._last_gate_order
        if existing is not None:
            merged = [node if old is existing else old for old in self.nodes]
        elif out_of_order:
            index = next(i for i, old in enumerate(self.nodes)
                         if old.order_key is not None and old.order_key > order)
            merged = [*self.nodes[:index], node, *self.nodes[index:]]
        else:
            merged = None

        if merged is not None:
            needs_rotation = at_capacity and existing is None
            if needs_rotation and (archive_dir is None
                                   or not any(kept is node for kept in merged[-_retain_nodes():])):
                raise StatefulAnalysisUnavailable("迟到调用无法在轮转后的窗口保留")
            updated, result = self._replay(merged, confirm=node)
            if needs_rotation:
                updated._rotate_for_gate(archive_dir)
            assert result is not None
            self.__dict__.update(updated.__dict__)
            return result

        if at_capacity:
            if order is not None:
                if archive_dir is None:
                    raise StatefulAnalysisUnavailable("链状态窗口已满")
                self._rotate_for_gate(archive_dir)
            elif archive_dir is not None:
                try:
                    self.rotate(archive_dir)
                except OSError as exc:
                    logger.error("链状态轮转失败: %s", exc)
            if len(self.nodes) >= _MAX_NODES:
                logger.warning("stateful 时间线达到兜底上限 %d（agent=%s），忽略本次新节点",
                               _MAX_NODES, self.agent_id)
                return AdvanceResult(seq=self.seq_next, skipped_for_capacity=True)
        node = self._add_node(node)
        matched, exfil = self._step(node, evaluate=True)
        return self._result(node, matched, exfil)

    def _rotate_for_gate(self, archive_dir: Path) -> None:
        try:
            self.rotate(archive_dir)
        except OSError as exc:
            raise StatefulAnalysisUnavailable("链状态归档失败") from exc
        if len(self.nodes) >= _MAX_NODES:
            raise StatefulAnalysisUnavailable("链状态无法释放节点容量")

    def _is_archived(self, order: tuple[int, str]) -> bool:
        return self.archived_through is not None and order <= self.archived_through

    def _is_legacy_archived(self, called_at: object, fingerprint: str) -> bool:
        if self._legacy_archive_boundary is None or not fingerprint:
            return False
        boundary, keys = self._legacy_archive_boundary
        stamp = _history_time(called_at)
        if stamp is None:
            return False
        if stamp < boundary:
            return True
        # An old cutoff truncated to microseconds can still identify an exact archived call.
        i = bisect_left(keys, fingerprint)
        return i < len(keys) and keys[i] == fingerprint

    def _merge_review(
        self, additions: list[StateNode], history: dict[str, list[tuple[StateNode | str, int]]],
        *, include_retained: bool = True,
    ) -> list[StateNode]:
        """保留既有顺序及共享键，尽量遵守回顾中的同会话相邻关系。"""
        retained = self.nodes if include_retained else ()
        nodes = [*retained, *additions]
        existing = len(retained)
        positions = {id(node): i for i, node in enumerate(nodes)}
        legacy_positions = self._legacy_positions if include_retained else {}

        # 拓扑排序的每种关系最多为每个节点增加一条出边。旧窗口顺序不能改变，正常窗口
        # 已按共享键排列。若旧快照的带号子序列曾经逆序，保留该窗口并按键排序新增调用。
        edges: list[list[tuple[int, bool]]] = [[] for _ in nodes]
        hard_in = [0] * len(nodes)
        session_in = [0] * len(nodes)

        def link(left: int, right: int, *, shared: bool) -> None:
            edges[left].append((right, shared))
            incoming = hard_in if shared else session_in
            incoming[right] += 1

        for i in range(1, existing):
            link(i - 1, i, shared=True)
        numbered = [(order, i) for i, node in enumerate(nodes) if (order := node.order_key) is not None]
        if not self._gate_window_sorted and include_retained:
            numbered = [(order, i) for order, i in numbered if i >= existing]
        numbered.sort()
        for (_, left), (_, right) in zip(numbered, numbered[1:]):
            link(left, right, shared=True)

        ranks = {}
        for rows in history.values():
            previous = None
            seen = set()
            for ref, rank in rows:
                index = legacy_positions.get(ref) if isinstance(ref, str) else positions.get(id(ref))
                if index is None or index in seen:
                    continue
                seen.add(index)
                if rank:
                    ranks[index] = rank
                if previous is not None:
                    link(previous, index, shared=False)
                previous = index

        # 审计时间排在最前，SQLite 同时刻的排名由新到旧，需反向比较；无时间沿用输入顺序。
        priority = []
        ready = []
        hard_ready = []
        for i, node in enumerate(nodes):
            time_priority = self._node_history_priority(node) if i < existing else self._new_review_priority(node)
            key = (*time_priority, -ranks.get(i, 0), i)
            priority.append(key)
            if not hard_in[i]:
                heappush(hard_ready, key)
                if not session_in[i]:
                    heappush(ready, key)

        # 会话次序与硬约束有环时，选择审计顺序最早的可用节点，放弃它尚未满足的会话前驱。
        # 没有冲突时全部约束同时满足。最坏 O((保留节点 + 新节点) log(保留节点 + 新节点))。
        emitted = set()
        merged = []
        while len(merged) < len(nodes):
            while ready and ready[0][-1] in emitted:
                heappop(ready)
            while hard_ready and hard_ready[0][-1] in emitted:
                heappop(hard_ready)
            index = heappop(ready or hard_ready)[-1]
            emitted.add(index)
            merged.append(nodes[index])
            for child, shared in edges[index]:
                if shared:
                    hard_in[child] -= 1
                    if not hard_in[child]:
                        heappush(hard_ready, priority[child])
                else:
                    session_in[child] -= 1
                if child not in emitted and not hard_in[child] and not session_in[child]:
                    heappush(ready, priority[child])
        return merged

    def _new_review_priority(self, node: StateNode) -> tuple[bool, str]:
        if not node.gate_call_id and node.legacy_fingerprint == "":
            return True, ""
        return self._node_history_priority(node)

    def _review_follows_window(
        self, additions: list[StateNode], history: dict[str, list[tuple[StateNode | str, int]]],
    ) -> bool:
        if not self.nodes:
            return True
        latest = self._last_gate_order
        if latest is not None and any((order := node.order_key) is not None and order < latest for node in additions):
            return False

        # 已保留锚点必须原序出现，且位于本会话新增节点之前。每段新增必须经由尾部
        # 锚点或共享键排在窗口之后，或按时间/排名优先级不可能先于尚未输出的旧节点。
        # 按回顾记录查索引，开销与本批大小相关，不扫描保留窗口。
        tail = len(self.nodes) - 1
        gate_tail = self._gate_window_sorted and self.nodes[tail].gate_call_id
        addition_ids = {id(node) for node in additions}
        for rows in history.values():
            last_anchor = -1
            seen = set()
            saw_addition = False
            follows_tail = False
            for ref, rank in rows:
                if not isinstance(ref, str) and id(ref) in addition_ids:
                    if not follows_tail and not (gate_tail and ref.gate_call_id):
                        priority = self._new_review_priority(ref)
                        if priority < self._latest_history_priority or (rank and priority == self._latest_history_priority):
                            return False
                    saw_addition = follows_tail = True
                    continue
                if isinstance(ref, str):
                    index = self._legacy_positions.get(ref)
                    if index is None:
                        continue
                else:
                    index = ref.seq
                    if index > tail or self.nodes[index] is not ref:
                        continue
                if index in seen:
                    continue
                if saw_addition or index < last_anchor:
                    return False
                seen.add(index)
                last_anchor = index
                follows_tail = index == tail
        return True

    def _step(self, node: StateNode, *, evaluate: bool) -> tuple[ChainMatch | None, list]:
        if node.gate_call_id and not node.action_detail:
            return None, []
        self._record_lifecycle(node)
        matched = self._advance_chains(node)
        self._advance_taint(node)
        return matched, self._check_exfil_after_taint(node) if evaluate else []

    def _result(self, node: StateNode, matched: ChainMatch | None, exfil: list) -> AdvanceResult:
        if node.input_fingerprint:
            # 保存原始证据，轮转重编号后也不再根据 seq 反查历史节点。
            node = replace(node, confirmed={"matched": asdict(matched) if matched else None,
                                            "exfil": deepcopy(exfil)})
            self.nodes[node.seq] = node
            self._gate_nodes[node.session_id, node.gate_call_id] = node
        return AdvanceResult(seq=node.seq + 1, node=node, matched=matched,
                             pending_prefixes=self.pending_prefixes, exfil=exfil)

    def _confirmed_result(self, node: StateNode) -> AdvanceResult:
        result = deepcopy(node.confirmed)
        match = result["matched"]
        if match:
            match["stages"] = tuple(match["stages"])
            match["path"] = [tuple(item) for item in match["path"]]
        return AdvanceResult(seq=node.seq + 1, node=node, matched=ChainMatch(**match) if match else None,
                             pending_prefixes=self.pending_prefixes, exfil=result["exfil"])

    def _replay(
        self, nodes: list[StateNode], *, confirm: StateNode | None = None,
    ) -> tuple[StatefulChainTracker, AdvanceResult | None]:
        # 重放在独立状态上进行，完成前不修改可见的时间线。
        updated = copy(self)
        updated._reset_timeline()
        updated._seeded_keys.update(updated._unmapped_legacy_keys)
        updated.generation = self.generation + 1
        result = None
        for old in nodes:
            node = updated._add_node(old, warn_capacity=False)
            matched, exfil = updated._step(node, evaluate=old is confirm)
            if old is confirm:
                result = updated._result(node, matched, exfil)
        return updated, result

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
                node.__dict__ | {"seq": seq, "resources": list(node.resources), "instances": list(node.instances)},
                ensure_ascii=False,
            )
            for seq, node in enumerate(nodes)
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
        return self._rotate_nodes(self.nodes, archive_dir, keep)

    def _rotate_nodes(
        self, nodes: list[StateNode], archive_dir: Path | None, keep: int,
    ) -> tuple[int, str]:
        if len(nodes) <= keep:
            return 0, ""
        old = nodes[:-keep]
        updated, _ = self._replay(nodes[-keep:])
        archived = max((node.order_key for node in old if node.order_key), default=None)
        if archived is not None and (self.archived_through is None or archived > self.archived_through):
            updated.archived_through = archived
        updated._update_legacy_archive_boundary(old)
        path = self._archive_nodes(old, archive_dir)
        self.__dict__.update(updated.__dict__)
        return len(old), str(path)

    def _update_legacy_archive_boundary(self, archived: list[StateNode]) -> None:
        previous_time, previous_keys = self._legacy_archive_boundary or ("", ())
        dated = [(stamp, self._legacy_node_key(node)) for node in archived
                 if (stamp := self._legacy_history_time(node)) is not None]
        latest = max(previous_time, max((stamp for stamp, _ in dated), default=""))
        if not latest:
            return
        earliest_retained = min(
            (stamp for node in self.nodes if (stamp := self._node_history_time(node)) is not None),
            default=latest,
        )
        # Never split the retained window by its timestamps, even if an archived action arrived late.
        boundary = min(latest, earliest_retained)
        keys = {key for stamp, key in dated if stamp == boundary}
        if boundary.startswith(previous_time[:_MICROSECOND_TIMESTAMP_LENGTH]):
            keys.update(previous_keys)
        self._legacy_archive_boundary = boundary, tuple(sorted(keys))

    @staticmethod
    def _legacy_key(action: dict, session_id: str) -> str:
        called_at = action.get("called_at")
        if called_at:
            return _fingerprint(session_id, action.get("action_type") or "",
                                action.get("action_detail") or "", called_at)
        return ""

    @staticmethod
    def _input_fingerprint(action: dict, is_error: bool, agent_id: str, instance_id: str,
                           order: tuple[int, str]) -> str:
        values = (action.get("action_type") or "", action.get("action_detail") or "",
                  action.get("called_at") or "", action.get("agent_id") or agent_id,
                  action.get("instance_id") or instance_id, is_error, order[0])
        return hashlib.sha256(json.dumps(values, separators=(",", ":")).encode()).hexdigest()

    def _make_node(
        self,
        action: dict,
        session_id: str,
        is_error: bool,
        agent_id: str,
        instance_id: str,
        *,
        order: tuple[int, str] | None,
        input_fingerprint: str = "",
        legacy_fingerprint: str = "",
    ) -> StateNode:
        ad = str(action.get("action_detail", "") or "")
        at = str(action.get("action_type", "") or "")
        stage = _mark_stage(ad, self._stages_patterns) if ad else ""
        return StateNode(
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
            timestamp=str(action.get("called_at") or "") or self._now(),
            gate_call_id=order[1] if order else "",
            gate_call_time_us=order[0] if order else 0,
            input_fingerprint=input_fingerprint,
            legacy_fingerprint=legacy_fingerprint,
        )

    @classmethod
    def _node_history_time(cls, node: StateNode) -> str | None:
        order = node.order_key
        if order is None:
            return _history_time(node.timestamp, local_naive=node.legacy_fingerprint == "")
        # 旧 Moss 生成的接收时刻固定精度且无偏移；有编号时用原请求指纹区分空 called_at。
        stamp = node.timestamp
        local_naive = False
        if isinstance(stamp, str) and len(stamp) == 19 and stamp[10] == "T" and node.input_fingerprint:
            without_called_at = cls._input_fingerprint(
                {"action_type": node.action_type, "action_detail": node.action_detail},
                node.is_error, node.agent_id, node.instance_id, order,
            )
            local_naive = without_called_at == node.input_fingerprint
        return _history_time(stamp, local_naive=local_naive)

    @classmethod
    def _node_history_priority(cls, node: StateNode) -> tuple[bool, str]:
        stamp = cls._node_history_time(node)
        return stamp is None, stamp or ""

    def _index_node(self, node: StateNode) -> None:
        priority = self._node_history_priority(node)
        self._latest_history_priority = max(self._latest_history_priority, priority)
        unknown, stamp = priority
        if self._legacy_archive_boundary is not None and not unknown and stamp < self._legacy_archive_boundary[0]:
            # A late numbered node can move the start of the retained interval backwards.
            self._legacy_archive_boundary = stamp, ()
        order = node.order_key
        if order is not None:
            self._gate_nodes[node.session_id, node.gate_call_id] = node
            if self._last_gate_order is None or order > self._last_gate_order:
                self._last_gate_order = order
            elif order < self._last_gate_order:
                self._gate_window_sorted = False
            return
        legacy = self._legacy_node_key(node)
        if legacy:
            self._seeded_keys.add(legacy)
            self._legacy_positions.setdefault(legacy, node.seq)
            if self._legacy_audit_candidates is not None:
                self._index_legacy_audit(node)

    def _index_legacy_audit(self, node: StateNode) -> None:
        candidates = self._legacy_audit_candidates
        if candidates is None or node.gate_call_id or not self._legacy_node_key(node):
            return
        if stamp := node.timestamp:
            key = _legacy_audit_fingerprint(node.session_id, node.action_type, node.action_detail, stamp)
            # Ambiguity includes already-retained SQLite rows as well as other live calls.
            candidates[key] = None if key in candidates or _is_sqlite_second(stamp) else node

    @staticmethod
    def _legacy_node_key(node: StateNode) -> str:
        if node.legacy_fingerprint is None and node.timestamp:
            return _fingerprint(node.session_id, node.action_type, node.action_detail, node.timestamp)
        return node.legacy_fingerprint or ""

    @staticmethod
    def _legacy_history_time(node: StateNode) -> str | None:
        if not node.gate_call_id and node.legacy_fingerprint:
            return _history_time(node.timestamp)
        return None

    def _add_node(self, node: StateNode, *, warn_capacity: bool = True) -> StateNode:
        if node.seq != self.seq_next:
            node = replace(node, seq=self.seq_next)
        self.nodes.append(node)
        self.seq_next += 1
        self._index_node(node)
        if not warn_capacity:
            return node
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
        parts = {
            "agent_id": self.agent_id,
            "nodes": list(self.nodes),
            "generation": self.generation,
            "archived_through": self.archived_through,
            "ptrs": dict(self._ptr),
            "tainted": sorted(self._tainted),
            "taint_parent": {str(k): v for k, v in self._taint_parent.items()},
            "taint_origin": dict(self._taint_origin),
            "taint_edge_labels": [[src, dst, label] for (src, dst), label in self._taint_edge_label.items()],
            "alive": {k: v for k, v in self._alive_resources.items()},
            "seq_next": self.seq_next,
        }
        if self._unmapped_legacy_keys:
            parts["unmapped_legacy_keys"] = self._unmapped_legacy_keys
        if self._legacy_archive_boundary is not None:
            parts["legacy_archive_boundary"] = self._legacy_archive_boundary
        return parts

    @staticmethod
    def finalize_snapshot(parts: dict) -> dict:
        """**锁外调用**：把浅拷贝展开成可 JSON 化的完整快照。"""
        return {
            **parts,
            "nodes": [
                {k: (v if k != "resources" else list(v)) for k, v in n.__dict__.items()}
                for n in parts["nodes"]
            ],
        }

    def restore(self, snapshot: dict | None) -> None:
        """从快照幂等恢复当前保留窗口。"""
        if not snapshot:
            return
        updated = copy(self)
        updated._unmapped_legacy_keys = ()
        updated._reset_timeline()
        updated.agent_id = str(snapshot.get("agent_id", self.agent_id))
        updated.restore_incremental(snapshot, snapshot.get("nodes") or [])
        self.__dict__.update(updated.__dict__)

    @staticmethod
    def _node_from_snapshot(raw: dict, legacy_keys: set[str] | None, migrated_keys: set[str]) -> StateNode:
        session_id = str(raw.get("session_id", ""))
        action_type = str(raw.get("action_type", ""))
        action_detail = str(raw.get("action_detail", ""))
        timestamp = raw.get("timestamp") or None
        gate_call_id = str(raw.get("gate_call_id") or "")
        legacy_fingerprint = raw.get("legacy_fingerprint")
        if legacy_fingerprint is None and legacy_keys is not None:
            # Old nodes stored receipt time too. Only the old key list can identify a real call time.
            legacy_fingerprint = ""
            if timestamp and not gate_call_id:
                candidate = _fingerprint(session_id, action_type, action_detail, timestamp)
                if candidate in legacy_keys:
                    legacy_fingerprint = candidate
                elif len(timestamp) != 19 or timestamp[10] != "T":
                    # The old local receipt clock used a naive T-separated timestamp.
                    audit_key = _legacy_audit_fingerprint(session_id, action_type, action_detail, timestamp)
                    if audit_key in legacy_keys:
                        legacy_fingerprint = candidate
                        migrated_keys.add(audit_key)
        return StateNode(
            seq=int(raw.get("seq", 0)),
            session_id=session_id,
            action_type=action_type,
            action_detail=action_detail,
            stage=str(raw.get("stage", "")),
            resources=tuple(raw.get("resources") or ()),
            instances=tuple(raw.get("instances") or ()),
            is_error=bool(raw.get("is_error", False)),
            agent_id=str(raw.get("agent_id", "")),
            instance_id=str(raw.get("instance_id", "")),
            lifecycle=str(raw.get("lifecycle", "")),
            timestamp=timestamp,
            gate_call_id=gate_call_id,
            gate_call_time_us=int(raw.get("gate_call_time_us") or 0),
            input_fingerprint=str(raw.get("input_fingerprint") or ""),
            confirmed=raw.get("confirmed"),
            legacy_fingerprint=legacy_fingerprint,
        )

    def restore_incremental(self, snapshot: dict, rows: list[dict]) -> None:
        """Apply a validated same-generation SQLite increment and its metadata."""
        legacy_keys = None
        if "seeded_keys" in snapshot:
            legacy_keys = {str(key) for key in (snapshot["seeded_keys"] or ())}
        migrated_keys: set[str] = set()
        appended = [self._node_from_snapshot(raw, legacy_keys, migrated_keys) for raw in rows]
        previous_size = len(self.nodes)
        next_seq = previous_size + len(appended)
        if any(node.seq != index for index, node in enumerate(appended, previous_size)):
            raise ValueError("状态节点序号不连续")
        if int(snapshot.get("seq_next", next_seq)) != next_seq:
            raise ValueError("状态元数据与节点游标不一致")
        keys = set()
        for node in appended:
            if node.gate_call_id:
                key = node.session_id, node.gate_call_id
                if key in keys or key in self._gate_nodes:
                    raise ValueError("状态窗口存在重复的 Gate 调用编号")
                keys.add(key)

        def get_node(seq: int) -> StateNode:
            if not 0 <= seq < next_seq:
                raise ValueError("状态节点引用超出保留窗口")
            if seq < previous_size:
                return self.nodes[seq]
            return appended[seq - previous_size]

        generation = int(snapshot.get("generation", 0))
        archived = snapshot.get("archived_through")
        archived_through = (int(archived[0]), str(archived[1])) if archived else None
        ptr = {str(k): int(v) for k, v in (snapshot.get("ptrs") or {}).items()}
        tainted = set(int(i) for i in (snapshot.get("tainted") or []))
        taint_parent = {
            int(k): (int(v) if v is not None else None)
            for k, v in (snapshot.get("taint_parent") or {}).items()
        }
        taint_origin = {
            str(k): int(v) for k, v in (snapshot.get("taint_origin") or {}).items()
        }
        edge_labels = {(int(src), int(dst)): str(label)
                       for src, dst, label in (snapshot.get("taint_edge_labels") or ())}
        alive_resources = {
            str(k): int(v) for k, v in (snapshot.get("alive") or {}).items()
        }
        tainted_resources = {resource for seq in tainted for resource in get_node(seq).resources}
        if tainted and (not taint_parent or not taint_origin):
            latest: dict[str, int] = {}
            for seq in sorted(tainted):
                resources = get_node(seq).resources
                taint_parent.setdefault(seq, max((latest[r] for r in resources if r in latest), default=None))
                for resource in resources:
                    taint_origin.setdefault(resource, seq)
                    latest[resource] = seq

        self.nodes.extend(appended)
        for node in appended:
            self._index_node(node)
        unmapped_keys = set(snapshot.get("unmapped_legacy_keys") or ())
        if legacy_keys is not None:
            unmapped_keys.update(legacy_keys.difference(self._seeded_keys, migrated_keys))
            unmapped_keys.update(self._unmapped_legacy_keys)
        if unmapped_keys:
            self._unmapped_legacy_keys = tuple(sorted(unmapped_keys))
            self._seeded_keys.update(self._unmapped_legacy_keys)
        self.seq_next = next_seq
        self.generation = generation
        self.archived_through = archived_through
        # The older archived_legacy_through value used retained timestamps and could hide valid history.
        legacy_boundary = snapshot.get("legacy_archive_boundary")
        self._legacy_archive_boundary = (legacy_boundary[0], tuple(legacy_boundary[1])) if legacy_boundary else None
        self._ptr = ptr
        self._tainted = tainted
        self._taint_parent = taint_parent
        self._taint_origin = taint_origin
        self._taint_edge_label = edge_labels
        self._alive_resources = alive_resources
        self._tainted_resources = tainted_resources


@dataclass
class AdvanceResult:
    """advance() 的一次输出。"""

    seq: int = 0
    node: StateNode | None = None
    matched: ChainMatch | None = None
    pending_prefixes: list = field(default_factory=list)
    exfil: list = field(default_factory=list)
    skipped_for_capacity: bool = False

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
