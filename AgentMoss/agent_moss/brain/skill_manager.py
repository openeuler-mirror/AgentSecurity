"""Brain Skill 管理器 — 从 LLM 分析中沉淀过程性知识

Brain Skill 直接写入 skills/ 目录，复用现有 SkillEngine 加载和匹配机制。
元数据（status、usage_count 等）存储在 ~/.agentmoss/brain/skill_meta.json（JSON，
对齐 runtime_config 范式）。曾用 SQLite（skill_meta.db），因鸿蒙 PC 等受限环境
可能无 sqlite3，改为纯标准库 JSON；存量 sqlite 库首次加载自动迁移。
"""

import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_META_DB = Path.home() / ".agentmoss" / "brain" / "skill_meta.json"
# 旧 sqlite 库路径（迁移源）
LEGACY_SQLITE_META = Path.home() / ".agentmoss" / "brain" / "skill_meta.db"


@dataclass
class BrainSkill:
    """一条 Brain 沉淀的 Skill"""
    id: str = ""
    name: str = ""              # 文件名（不含 .md），如 "prompt_injection_via_env"
    category: str = ""          # "attack_pattern" | "defense_strategy" | "edge_case"
    content: str = ""           # Markdown 内容
    keywords: list[str] = field(default_factory=list)  # 用于 SKILL_KEYWORD_MAP
    source_event_ids: list[str] = field(default_factory=list)
    status: str = "draft"       # "draft" | "active" | "stale"
    created_at: float = 0.0
    usage_count: int = 0        # 被 Layer 3 引用次数
    origin_node: str = "local"

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())
        if not self.created_at:
            self.created_at = time.time()


class BrainSkillManager:
    """管理 Brain 生成的 Skill，写入 skills/ 目录并维护 SKILL_KEYWORD_MAP

    全部方法签名与 SQLite 时代一致（测试/调用方无感）；内部改为内存 list + 落盘 JSON。
    """

    def __init__(self, skills_dir: str | Path, skill_engine=None,
             meta_db: str | Path | None = None):
        self._skills_dir = Path(skills_dir)
        self._skill_engine = skill_engine  # SkillEngine 实例，用于动态扩展关键词
        self._meta_db_path = Path(meta_db) if meta_db is not None else Path(DEFAULT_META_DB)
        # 若指定路径以 .db 结尾且不存在，尝试找同名 .json
        if not self._meta_db_path.exists() and str(self._meta_db_path).endswith(".db"):
            alt = self._meta_db_path.with_suffix(".json")
            if alt.exists():
                self._meta_db_path = alt
        self._meta_db_path.parent.mkdir(parents=True, exist_ok=True)
        self._migrate_from_sqlite()
        self._skills: list[dict] = []
        self._load()
        self._cleanup_ghost_skills()

    # --- 迁移 ---

    def _migrate_from_sqlite(self):
        """旧 sqlite skill_meta.db → JSON（幂等）。

        仅当 store 用默认路径时触发（测试传 meta_db 隔离不触发）。环境无 sqlite3 时静默跳过。
        """
        src = Path(LEGACY_SQLITE_META)
        # 若本 store 用非默认路径（测试），不触发全局迁移
        if self._meta_db_path != Path(DEFAULT_META_DB):
            return
        if self._meta_db_path.exists():
            return
        if not src.exists():
            bak = Path(str(src) + ".bak")
            if not bak.exists():
                return
            src = bak  # 源 .db 已改名 → 回读 .bak（幂等补偿）
        try:
            import sqlite3
        except ImportError:
            logger.info("环境无 sqlite3，跳过旧 skill meta 迁移（使用空 JSON 库）")
            return
        try:
            conn = sqlite3.connect(str(src))
            conn.row_factory = sqlite3.Row
            out = {"version": 1, "skills": []}
            for row in conn.execute("SELECT * FROM skill_meta"):
                out["skills"].append({
                    "id": row["id"], "name": row["name"],
                    "category": row["category"],
                    "keywords": json.loads(row["keywords"]),
                    "source_event_ids": json.loads(row["source_event_ids"]),
                    "status": row["status"], "created_at": row["created_at"],
                    "usage_count": row["usage_count"], "origin_node": row["origin_node"],
                })
            conn.close()
            self._meta_db_path.write_text(
                json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8",
            )
            # 备份旧库：仅当 src 还是原始 .db（非 .bak 回读）时才 rename
            if src.suffix == ".db" and not Path(str(src) + ".bak").exists():
                src.rename(Path(str(src) + ".bak"))
            logger.info("Brain 旧 skill sqlite 库已迁移到 JSON: %d skills", len(out["skills"]))
        except Exception as e:
            logger.debug("Brain skill sqlite 迁移异常（跳过）: %s", e)

    # --- 加载/落盘 ---

    def _load(self):
        if not self._meta_db_path.exists():
            return
        try:
            data = json.loads(self._meta_db_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.debug("Brain skill JSON 读取失败（空库）: %s", e)
            return
        self._skills = data.get("skills", [])

    def _save(self):
        out = {"version": 1, "skills": self._skills}
        tmp = self._meta_db_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self._meta_db_path)

    # --- 基础操作 ---

    def _cleanup_ghost_skills(self) -> None:
        """清理"幽灵 skill"元数据：meta 记录 active 但磁盘 .md 已不存在的孤儿。

        历史遗留：早期 brain 生成的 skill 文件被删除后，skill_meta 仍记 active，
        会污染 SKILL_KEYWORD_MAP 并阻塞同名新 skill 生成。启动时校验一次：
        磁盘不存在的 active 记录 → status 置 stale。
        """
        try:
            changed = False
            for sk in self._skills:
                if sk.get("status") != "active":
                    continue
                md_path = self._skills_dir / f"{sk.get('name')}.md"
                if not md_path.exists():
                    sk["status"] = "stale"
                    changed = True
                    logger.info("Brain 幽灵 skill 清理: %s (磁盘文件不存在)", sk.get("name"))
            if changed:
                self._save()
        except Exception as e:
            logger.debug("Brain 幽灵 skill 清理异常: %s", e)

    def add_skill(self, skill: BrainSkill) -> str:
        """
        添加 Brain Skill：
        1. 写 .md 文件到 skills/ 目录
        2. 更新 SkillEngine 的 SKILL_KEYWORD_MAP
        3. 记录元数据到 meta_db

        写入前做价值评估：若 skills/ 目录不存在或文件已存在同名则跳过。
        """
        if not skill.name:
            skill.name = f"brain_{skill.id[:8]}"

        # 价值评估 1：skills/ 目录必须存在（缺失说明未正确初始化，跳过写入）
        if not self._skills_dir.exists():
            logger.warning("Brain Skill 跳过写入（skills 目录不存在）: %s", self._skills_dir)
            return ""

        # 价值评估 2：同名 skill 文件已存在 → 跳过（去重）
        md_path = self._skills_dir / f"{skill.name}.md"
        if md_path.exists():
            logger.info("Brain Skill 跳过写入（同名已存在）: %s", skill.name)
            return ""

        # 1. 写 .md 文件
        md_path.write_text(skill.content, encoding="utf-8")
        logger.info("Brain Skill 文件已写入: %s", md_path)

        # 2. 更新 SKILL_KEYWORD_MAP
        if self._skill_engine and skill.keywords:
            from ..engine.skill_engine import SKILL_KEYWORD_MAP
            SKILL_KEYWORD_MAP[skill.name] = skill.keywords
            # 重新加载 skills 缓存
            self._skill_engine.reload_skills()
            logger.info("SKILL_KEYWORD_MAP 已更新: %s -> %s", skill.name, skill.keywords)

        # 3. 记录元数据（key 用 snake_case，与旧 sqlite Row 的 dict() 字段一致）
        self._skills.append({
            "id": skill.id, "name": skill.name,
            "category": skill.category,
            "keywords": skill.keywords,
            "source_event_ids": skill.source_event_ids,
            "status": skill.status, "created_at": skill.created_at,
            "usage_count": skill.usage_count, "origin_node": skill.origin_node,
        })
        self._save()
        return skill.id

    def get_skill_meta(self, name: str) -> dict | None:
        return next((sk for sk in self._skills if sk.get("name") == name), None)

    def get_active_skills(self) -> list[dict]:
        return sorted(
            [sk for sk in self._skills if sk.get("status") == "active"],
            key=lambda sk: sk.get("created_at", 0), reverse=True,
        )

    def record_usage(self, name: str):
        """记录 Skill 被 Layer 3 引用"""
        sk = self.get_skill_meta(name)
        if sk:
            sk["usage_count"] = sk.get("usage_count", 0) + 1
            self._save()

    def mark_stale(self, stale_days: int = 60):
        """长期未使用的 Skill → stale"""
        cutoff = time.time() - stale_days * 86400
        changed = False
        for sk in self._skills:
            if sk.get("status") == "active" and sk.get("usage_count", 0) == 0 \
                    and sk.get("created_at", 0) < cutoff:
                sk["status"] = "stale"
                changed = True
        if changed:
            self._save()

    # --- 中心化预留 ---

    def export_skills(self) -> list[dict]:
        """导出本地新增 Skill，供上报中心"""
        results = []
        for sk in self._skills:
            if sk.get("origin_node") != "local" or sk.get("status") != "active":
                continue
            md_path = self._skills_dir / f"{sk.get('name')}.md"
            if md_path.exists():
                results.append({
                    "name": sk.get("name"),
                    "category": sk.get("category", ""),
                    "content": md_path.read_text(encoding="utf-8"),
                    "keywords": sk.get("keywords", []),
                })
        return results

    def import_skills(self, skills: list[dict]):
        """导入中心下发 Skill"""
        for s in skills:
            skill = BrainSkill(
                name=s["name"],
                category=s.get("category", ""),
                content=s["content"],
                keywords=s.get("keywords", []),
                status="active",
                origin_node="central",
            )
            self.add_skill(skill)
        logger.info("导入 %d 条中心化 Skill", len(skills))

    def close(self):
        """保留 close 签名（调用方已有），JSON 落盘已逐次持久化。"""
        self._save()