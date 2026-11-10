"""Skill 引擎 — 加载、匹配和注入安全检测 Skill

管理安全检测 Skill 规则的生命周期：
- 加载 skills/ 目录下的所有 .md 规则文件
- 根据动作类型和内容匹配最相关的 Skill
- 格式化后注入 LLM prompt 指导安全判断
"""

import re
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..agents.base import AgentExtensions

from .types import SkillMatch

# Skills 目录路径
DEFAULT_SKILLS_DIR = Path(__file__).parent.parent / "skills"

# ==================== Skill 分类映射 ====================
# action_type / action_detail 中的关键词 → 匹配的 skill 文件名
def _load_l3_skills() -> dict[str, list[str]]:
    """从归一化 L3 JSON 读取 skill 关键词映射（单一事实源）。

    l3_rules.json 结构为 {category: {skill_id: [keywords]}}，此函数展平为
    {skill_id: [keywords]}（与旧 SKILL_KEYWORD_MAP 一致）。
    """
    from ..rules_loader import load_l3
    out: dict[str, list[str]] = {}
    for _cat, skills in load_l3().items():
        if not isinstance(skills, dict):
            continue
        for skill_id, keywords in skills.items():
            out[skill_id] = keywords
    return out


SKILL_KEYWORD_MAP: dict[str, list[str]] = _load_l3_skills()


class SkillEngine:
    """Skill 引擎 — 加载、匹配和注入安全检测 Skill"""

    def __init__(
        self,
        skills_dir: str | Path | None = None,
        agent_ext: "AgentExtensions | None" = None,
    ):
        self._skills_dir = Path(skills_dir) if skills_dir else DEFAULT_SKILLS_DIR
        self._skills_cache: dict[str, str] = {}
        # agent 专属 builtin safe skills 白名单（追加到通用 TRUSTED_SKILLS）
        self._agent_builtin_safe_skills: set[str] = set()
        if agent_ext and agent_ext.builtin_safe_skills:
            self._agent_builtin_safe_skills = set(agent_ext.builtin_safe_skills)
        self._load_all_skills()

    def _load_all_skills(self) -> None:
        """加载所有 Skill 文件到缓存"""
        if not self._skills_dir.exists():
            return
        for md_file in sorted(self._skills_dir.glob("*.md")):
            skill_name = md_file.stem
            self._skills_cache[skill_name] = md_file.read_text(encoding="utf-8")

    def match_skills(
        self,
        a_next: dict[str, str],
        reason: str,
        max_skills: int = 3,
    ) -> list[SkillMatch]:
        """
        根据 a_next 和 reason 匹配最相关的 Skill。

        Args:
            a_next: 下一步动作
            reason: 执行理由
            max_skills: 最多返回的 Skill 数量

        Returns:
            list[SkillMatch]: 匹配到的 Skill 列表，按相关度降序
        """
        action_type = a_next.get("action_type", "").lower()
        action_detail = a_next.get("action_detail", "").lower()
        combined = f"{action_type} {action_detail} {reason}".lower()

        # 热生效：console 禁用的 skill（或其分类禁用）不参与匹配
        disabled_skill_ids: set[str] = set()
        try:
            from ..infra.runtime_config import has_runtime_config, get_disabled_skill_ids, load_runtime_config
            if has_runtime_config():
                disabled_skill_ids = get_disabled_skill_ids(load_runtime_config())
        except Exception:
            pass

        # 计算每个 skill 的相关度
        scores: dict[str, float] = {}
        for skill_name, keywords in SKILL_KEYWORD_MAP.items():
            if skill_name in disabled_skill_ids:
                continue
            score = 0.0
            for kw in keywords:
                if kw in combined:
                    # action_type 精确匹配权重更高
                    if kw == action_type:
                        score += 2.0
                    elif kw in action_detail:
                        score += 1.5
                    elif kw in reason.lower():
                        score += 1.0
                    else:
                        score += 0.5
            if score > 0:
                scores[skill_name] = score

        # 排序并取 top-N
        sorted_skills = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        top_skills = sorted_skills[:max_skills]

        # 归一化相关度到 0-1
        max_score = top_skills[0][1] if top_skills else 1.0

        results = []
        for skill_name, score in top_skills:
            content = self._skills_cache.get(skill_name, "")
            if content:
                results.append(
                    SkillMatch(
                        skill_name=skill_name,
                        relevance=min(score / max_score, 1.0),
                        skill_content=content,
                    )
                )

        # 如果没有匹配到任何 skill，加载 general_tool_risk_guard 作为兜底
        if not results:
            fallback = self._skills_cache.get("general_tool_risk_guard", "")
            if fallback:
                results.append(
                    SkillMatch(
                        skill_name="general_tool_risk_guard",
                        relevance=0.3,
                        skill_content=fallback,
                    )
                )

        return results

    def format_skills_for_prompt(self, skills: list[SkillMatch]) -> str:
        """
        将匹配到的 Skill 格式化为 LLM prompt 可用的文本。

        Args:
            skills: 匹配到的 Skill 列表

        Returns:
            str: 格式化后的 Skill 规则文本
        """
        if not skills:
            return "（未匹配到特定安全检测规则）"

        sections = []
        for skill in skills:
            sections.append(
                f"### 安全检测规则: {skill.skill_name} (相关度: {skill.relevance:.0%})\n\n"
                f"{skill.skill_content}"
            )

        return "\n\n---\n\n".join(sections)

    @property
    def available_skills(self) -> list[str]:
        """获取所有已加载的 Skill 名称"""
        return list(self._skills_cache.keys())

    @property
    def agent_builtin_safe_skills(self) -> set[str]:
        """agent 专属 builtin safe skills 白名单（来自 agent_ext.builtin_safe_skills）"""
        return self._agent_builtin_safe_skills

    def reload_skills(self) -> None:
        """重新加载所有 Skill 文件"""
        self._skills_cache.clear()
        self._load_all_skills()