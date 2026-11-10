"""Brain 规则仓库 — 独立存储 LLM 沉淀的静态安全规则

存储位置：~/.agentmoss/brain/rules.json（JSON 文件，对齐 runtime_config 范式）
和内置规则（heuristic.py、logic_rules.py）完全分离。

存储格式：单一 JSON 文件 {version: 1, rules: [...], pattern_candidates: [...]}。
曾用 SQLite（rules.db），因鸿蒙 PC 等受限环境可能无 sqlite3，故改为纯标准库 JSON。
存量 sqlite 库在首次加载时自动迁移（旧 .db → .db.bak）。
"""

import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path.home() / ".agentmoss" / "brain" / "rules.json"
# 旧 sqlite 库路径（迁移源）
LEGACY_SQLITE_PATH = Path.home() / ".agentmoss" / "brain" / "rules.db"

# 规则状态机
# draft → approved → active → disputed → stale → archived
# draft → rejected → archived
STATUS_DRAFT = "draft"
STATUS_APPROVED = "approved"
STATUS_ACTIVE = "active"
STATUS_DISPUTED = "disputed"
STATUS_STALE = "stale"
STATUS_ARCHIVED = "archived"
STATUS_REJECTED = "rejected"

VALID_TRANSITIONS = {
    STATUS_DRAFT: {STATUS_APPROVED, STATUS_REJECTED, STATUS_ARCHIVED},
    STATUS_APPROVED: {STATUS_ACTIVE},
    STATUS_ACTIVE: {STATUS_DISPUTED, STATUS_STALE, STATUS_ARCHIVED},
    STATUS_DISPUTED: {STATUS_ACTIVE, STATUS_STALE, STATUS_ARCHIVED},
    STATUS_STALE: {STATUS_ARCHIVED, STATUS_ACTIVE},
}


@dataclass
class BrainRule:
    """一条 Brain 沉淀的静态安全规则"""
    id: str = ""
    layer: int = 1              # 1 = 特征匹配（只看当前 action）
                                # 2 = 逻辑规则（需要 action history）
    rule_type: str = ""         # "deny_path" | "deny_command" | "deny_pattern" | "allow_pattern"
    pattern: str = ""           # 匹配模式（正则）
    scope: str = "all"          # "openat" | "execve" | "connect" | "all"
    source: str = "llm_extracted"  # "llm_extracted" | "user" | "central"
    source_event_ids: list[str] = field(default_factory=list)
    confidence: float = 0.0     # 0.0-1.0
    status: str = STATUS_DRAFT
    created_at: float = 0.0
    last_triggered_at: float = 0.0
    trigger_count: int = 0
    disputed_count: int = 0
    explanation: str = ""
    origin_node: str = "local"  # 预留：中心化下发时为节点标识

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())
        if not self.created_at:
            self.created_at = time.time()


class BrainRuleStore:
    """Brain 规则独立存储（JSON 文件）

    全部方法签名与 SQLite 时代一致（测试/调用方无感）；内部改为内存 list + 落盘 JSON。
    """

    def __init__(self, db_path: str | Path | None = None):
        self._db_path = Path(db_path) if db_path is not None else Path(DEFAULT_DB_PATH)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        # 若指定路径以 .db 结尾且不存在，可能是调用方沿用旧后缀，尝试找同名 .json
        if not self._db_path.exists() and str(self._db_path).endswith(".db"):
            alt = self._db_path.with_suffix(".json")
            if alt.exists():
                self._db_path = alt
        self._migrate_from_sqlite()
        self._rules: list[BrainRule] = []
        self._pattern_candidates: list[dict] = []
        self._load()

    # --- 迁移 ---

    def _migrate_from_sqlite(self):
        """旧 sqlite rules.db → JSON（幂等）。

        SQLite 库存在且目标 JSON 不存在时：读取旧数据 → 写 JSON → 旧库改名 .db.bak。
        若源 .db 已不存在但 .db.bak 存在（此前迁移中断/已迁过），回读 .bak 补产出 JSON。
        环境无 sqlite3（鸿蒙等）时静默跳过。
        """
        # 若本 store 用的是非默认路径（测试），不触发全局迁移
        if self._db_path != Path(DEFAULT_DB_PATH):
            return
        if self._db_path.exists():
            return
        src = Path(LEGACY_SQLITE_PATH)
        if not src.exists():
            bak = Path(str(src) + ".bak")
            if not bak.exists():
                return
            src = bak  # 源 .db 已改名 → 回读 .bak（幂等补偿）
        try:
            import sqlite3
        except ImportError:
            logger.info("环境无 sqlite3，跳过旧库迁移（继续使用空 JSON 库）")
            return
        try:
            conn = sqlite3.connect(str(src))
            conn.row_factory = sqlite3.Row
            migrated = {"version": 1, "rules": [], "pattern_candidates": []}
            for row in conn.execute("SELECT * FROM brain_rules"):
                migrated["rules"].append({
                    "id": row["id"], "layer": row["layer"],
                    "rule_type": row["rule_type"], "pattern": row["pattern"],
                    "scope": row["scope"], "source": row["source"],
                    "source_event_ids": json.loads(row["source_event_ids"]),
                    "confidence": row["confidence"], "status": row["status"],
                    "created_at": row["created_at"],
                    "last_triggered_at": row["last_triggered_at"],
                    "trigger_count": row["trigger_count"],
                    "disputed_count": row["disputed_count"],
                    "explanation": row["explanation"], "origin_node": row["origin_node"],
                })
            try:
                for r in conn.execute("SELECT * FROM pattern_candidates"):
                    migrated["pattern_candidates"].append({
                        "pattern": r["pattern"], "layer": r["layer"], "scope": r["scope"],
                        "source_event_ids": json.loads(r["source_event_ids"]),
                        "confidence": r["confidence"], "occurrence_count": r["occurrence_count"],
                        "first_seen_at": r["first_seen_at"], "last_seen_at": r["last_seen_at"],
                        "review_status": r["review_status"] if "review_status" in r.keys() else "pending",
                        "review_reason": r["review_reason"] if "review_reason" in r.keys() else "",
                        "reviewed_at": r["reviewed_at"] if "reviewed_at" in r.keys() else 0,
                    })
            except Exception:
                pass  # pattern_candidates 表可能不存在（旧版）
            conn.close()
            self._db_path.write_text(
                json.dumps(migrated, indent=2, ensure_ascii=False), encoding="utf-8",
            )
            # 备份旧库：仅当 src 还是原始 .db（非 .bak 回读）时才 rename
            if src.suffix == ".db" and not Path(str(src) + ".bak").exists():
                src.rename(Path(str(src) + ".bak"))
            logger.info("Brain 旧 sqlite 库已迁移到 JSON: %d 规则, %d 候选",
                        len(migrated["rules"]), len(migrated["pattern_candidates"]))
        except Exception as e:
            logger.debug("Brain sqlite 迁移异常（跳过）: %s", e)

    # --- 加载/落盘 ---

    def _load(self):
        """从 JSON 加载数据到内存。文件不存在/损坏 → 空库。"""
        if not self._db_path.exists():
            return
        try:
            data = json.loads(self._db_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.debug("Brain 规则 JSON 读取失败（空库）: %s", e)
            return
        for r in data.get("rules", []):
            try:
                self._rules.append(self._dict_to_rule(r))
            except Exception:
                continue
        self._pattern_candidates = data.get("pattern_candidates", [])

    def _save(self):
        """内存数据全量写回 JSON（原子：先写 tmp 再 rename）。"""
        out = {
            "version": 1,
            "rules": [asdict(r) for r in self._rules],
            "pattern_candidates": self._pattern_candidates,
        }
        tmp = self._db_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self._db_path)

    # --- 规则 CRUD ---

    def add_rule(self, rule: BrainRule) -> str:
        """添加新规则，默认 draft 状态"""
        self._rules.append(rule)
        self._save()
        logger.info("Brain 规则已添加: id=%s, layer=%d, pattern=%s", rule.id, rule.layer, rule.pattern[:50])
        return rule.id

    def approve_rule(self, rule_id: str):
        """审核通过：draft → approved → active"""
        rule = self.get_rule(rule_id)
        if not rule:
            raise ValueError(f"规则不存在: {rule_id}")
        if rule.status != STATUS_DRAFT:
            raise ValueError(f"只有 draft 状态可审核，当前: {rule.status}")
        self._update_status(rule_id, STATUS_APPROVED)
        self._update_status(rule_id, STATUS_ACTIVE)
        logger.info("Brain 规则已审核通过: id=%s", rule_id)

    def reject_rule(self, rule_id: str, reason: str = ""):
        """拒绝：draft → rejected → archived"""
        rule = self.get_rule(rule_id)
        if not rule:
            raise ValueError(f"规则不存在: {rule_id}")
        if rule.status != STATUS_DRAFT:
            raise ValueError(f"只有 draft 状态可拒绝，当前: {rule.status}")
        self._update_status(rule_id, STATUS_REJECTED)
        self._update_status(rule_id, STATUS_ARCHIVED)
        logger.info("Brain 规则已拒绝: id=%s, reason=%s", rule_id, reason)

    def dispute_rule(self, rule_id: str, reason: str = ""):
        """质疑：active → disputed"""
        rule = self.get_rule(rule_id)
        if not rule:
            raise ValueError(f"规则不存在: {rule_id}")
        if rule.status != STATUS_ACTIVE:
            raise ValueError(f"只有 active 状态可质疑，当前: {rule.status}")
        rule.status = STATUS_DISPUTED
        rule.disputed_count += 1
        self._save()
        logger.info("Brain 规则已质疑: id=%s, reason=%s", rule_id, reason)

    def get_rule(self, rule_id: str) -> BrainRule | None:
        return next((r for r in self._rules if r.id == rule_id), None)

    def get_active_rules(self, layer: int | None = None, scope: str | None = None) -> list[BrainRule]:
        """获取活跃规则，可按 layer 和 scope 过滤"""
        rules = [r for r in self._rules if r.status == STATUS_ACTIVE]
        if layer is not None:
            rules = [r for r in rules if r.layer == layer]
        if scope is not None:
            rules = [r for r in rules if r.scope == scope or r.scope == "all"]
        return rules

    def get_draft_rules(self) -> list[BrainRule]:
        return sorted(
            [r for r in self._rules if r.status == STATUS_DRAFT],
            key=lambda r: r.created_at, reverse=True,
        )

    def record_trigger(self, rule_id: str):
        """记录规则被触发"""
        rule = self.get_rule(rule_id)
        if not rule:
            return
        rule.trigger_count += 1
        rule.last_triggered_at = time.time()
        self._save()

    # --- pattern_candidates 管理 ---

    def add_pattern_candidate(self, pattern: str, layer: int, scope: str,
                               source_event_id: str, confidence: float) -> int:
        """记录一个 pattern 候选，返回累计出现次数

        已审核拒绝（rejected）的 pattern 不再重新记录：永久排除。
        """
        now = time.time()
        if self.is_excluded_pattern(pattern, layer, scope):
            return 0
        existing = self._find_candidate(pattern, layer, scope)
        if existing:
            if existing.get("review_status") == "rejected":
                return 0
            existing["occurrence_count"] += 1
            existing["last_seen_at"] = now
            src_ids = existing.get("source_event_ids", [])
            src_ids.insert(0, source_event_id)
            existing["source_event_ids"] = src_ids[:50]
        else:
            self._pattern_candidates.append({
                "pattern": pattern, "layer": layer, "scope": scope,
                "source_event_ids": [source_event_id],
                "confidence": confidence, "occurrence_count": 1,
                "first_seen_at": now, "last_seen_at": now,
                "review_status": "pending", "review_reason": "", "reviewed_at": 0,
            })
        self._save()
        return existing["occurrence_count"] if existing else 1

    def _find_candidate(self, pattern: str, layer: int, scope: str) -> dict | None:
        return next(
            (c for c in self._pattern_candidates
             if c["pattern"] == pattern and c["layer"] == layer and c["scope"] == scope),
            None,
        )

    def get_pattern_candidates(self, min_occurrences: int = 3) -> list[dict]:
        """获取达到阈值且待审核（pending）或已通过（approved）的 pattern 候选"""
        return sorted(
            [c for c in self._pattern_candidates
             if c.get("occurrence_count", 0) >= min_occurrences
             and c.get("review_status") != "rejected"],
            key=lambda c: c.get("occurrence_count", 0), reverse=True,
        )

    def set_pattern_review_status(self, pattern: str, layer: int, scope: str,
                                  status: str, reason: str = ""):
        """设置 pattern 候选的审核状态（pending/approved/rejected）"""
        c = self._find_candidate(pattern, layer, scope)
        if c:
            c["review_status"] = status
            c["review_reason"] = reason
            c["reviewed_at"] = time.time()
            self._save()

    def is_excluded_pattern(self, pattern: str, layer: int, scope: str) -> bool:
        """pattern 候选是否已被审核拒绝（永久排除）"""
        c = self._find_candidate(pattern, layer, scope)
        return bool(c and c.get("review_status") == "rejected")

    def get_pending_review_candidates(self, min_occurrences: int = 3) -> list[dict]:
        """获取达到阈值且等待 LLM 审核的候选"""
        return sorted(
            [c for c in self._pattern_candidates
             if c.get("occurrence_count", 0) >= min_occurrences
             and c.get("review_status") == "pending"],
            key=lambda c: c.get("occurrence_count", 0), reverse=True,
        )

    def remove_pattern_candidate(self, pattern: str, layer: int, scope: str):
        """已转化为规则的候选移除"""
        self._pattern_candidates = [
            c for c in self._pattern_candidates
            if not (c["pattern"] == pattern and c["layer"] == layer and c["scope"] == scope)
        ]
        self._save()

    # --- 生命周期管理 ---

    def mark_stale(self, stale_days: int = 30):
        """长期未触发的 active/disputed 规则 → stale"""
        cutoff = time.time() - stale_days * 86400
        for r in self._rules:
            if r.status in (STATUS_ACTIVE, STATUS_DISPUTED) \
                    and 0 < r.last_triggered_at < cutoff:
                r.status = STATUS_STALE
        self._save()

    def mark_archived(self, archive_days: int = 90):
        """长期 stale 的规则 → archived"""
        cutoff = time.time() - archive_days * 86400
        for r in self._rules:
            if r.status == STATUS_STALE and 0 < r.last_triggered_at < cutoff:
                r.status = STATUS_ARCHIVED
        self._save()

    def auto_demote_disputed(self, dispute_threshold: int = 3):
        """disputed 次数达标的规则自动降级为 stale"""
        for r in self._rules:
            if r.status == STATUS_DISPUTED and r.disputed_count >= dispute_threshold:
                r.status = STATUS_STALE
        self._save()

    # --- 中心化预留 ---

    def get_rules_for_export(self) -> list[BrainRule]:
        """导出本地新增规则，供上报中心"""
        return [r for r in self._rules if r.source != "central" and r.status == STATUS_ACTIVE]

    def import_rules(self, rules: list[BrainRule]):
        """导入中心下发规则"""
        for rule in rules:
            rule.source = "central"
            rule.origin_node = "central"
            self.add_rule(rule)
        logger.info("导入 %d 条中心化规则", len(rules))

    # --- 统计 ---

    def get_stats(self) -> dict:
        stats = {}
        for status in [STATUS_DRAFT, STATUS_APPROVED, STATUS_ACTIVE,
                        STATUS_DISPUTED, STATUS_STALE, STATUS_ARCHIVED]:
            stats[status] = sum(1 for r in self._rules if r.status == status)
        stats["total"] = sum(stats.values())
        stats["by_layer"] = {
            1: sum(1 for r in self._rules if r.layer == 1 and r.status == STATUS_ACTIVE),
            2: sum(1 for r in self._rules if r.layer == 2 and r.status == STATUS_ACTIVE),
        }
        stats["pattern_candidates"] = len(self._pattern_candidates)
        return stats

    def close(self):
        """保留 close 签名（调用方已有），JSON 无连接可关，落盘已逐次持久化。"""
        self._save()

    def _update_status(self, rule_id: str, new_status: str):
        rule = self.get_rule(rule_id)
        if rule:
            rule.status = new_status
            self._save()

    def _dict_to_rule(self, d: dict) -> BrainRule:
        """从 JSON dict 构造 BrainRule（带默认值，容忍缺字段）"""
        return BrainRule(
            id=d.get("id", ""),
            layer=d.get("layer", 1),
            rule_type=d.get("rule_type", ""),
            pattern=d.get("pattern", ""),
            scope=d.get("scope", "all"),
            source=d.get("source", "llm_extracted"),
            source_event_ids=list(d.get("source_event_ids", [])),
            confidence=d.get("confidence", 0.0),
            status=d.get("status", STATUS_DRAFT),
            created_at=d.get("created_at", 0.0),
            last_triggered_at=d.get("last_triggered_at", 0.0),
            trigger_count=d.get("trigger_count", 0),
            disputed_count=d.get("disputed_count", 0),
            explanation=d.get("explanation", ""),
            origin_node=d.get("origin_node", "local"),
        )