"""Skill 引擎 — 加载、匹配和注入安全检测 Skill

管理安全检测 Skill 规则的生命周期：
- 加载 skills/ 目录下的所有 .md 规则文件
- 根据动作类型和内容匹配最相关的 Skill
- 格式化后注入 LLM prompt 指导安全判断
"""

import re
from pathlib import Path
from typing import TYPE_CHECKING

from ..infra.paths import asset_dir
from ..infra.rules_mode import is_builtin_only, is_hot_reload_enabled, is_runtime_config_disabled

if TYPE_CHECKING:
    from ..agents.base import AgentExtensions

from .types import SkillMatch

# Skills 目录：默认包内 `agent_moss/skills/`；设了 AGENT_MOSS_RULES_ROOT →
# `<root>/skills/`（规则仓剥离后的落点）。用函数不用常量 —— 测试会 monkeypatch 环境变量。
def default_skills_dir() -> Path:
    return asset_dir("skills")


#: 兼容旧引用名（模块导入时求值一次）。**新代码请用 default_skills_dir()** ——
#: 它会跟随 AGENT_MOSS_RULES_ROOT 的当前值，而这个常量只在导入那一刻取。
DEFAULT_SKILLS_DIR = default_skills_dir()


#: cold / builtin 模式下的进程级 skill 冻结副本（按 skills_dir 区分）。
#: 为什么需要：SkillEngine 是每次 analyze 新建的，若每次都重新 glob/read 包内 .md，
#: 同用户改 venv 里的 skill 文件仍会热生效；冻结后本次运行只认首次读到的内容。
_FROZEN_SKILLS_CACHE: dict[str, dict[str, str]] = {}

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


def runtime_custom_skill_keywords() -> dict[str, list[str]]:
    """runtime 里**用户新增**的 L3 skill（builtin=False 且启用）→ ``{skill_id: keywords}``。

    为什么需要：Console「新增 Skill」把 .md 写到 ``<data_root>/agent_moss_skills/``、
    关键词记进 runtime 的 ``L3_skills.<分类>.skills``，但 ``SKILL_KEYWORD_MAP`` 是
    **模块级常量**（只读包内 l3_rules.json）——于是自定义 skill 既进不了关键词表、
    .md 也不在加载目录，**写完永远不参与判定且无任何提示**（2026-09 招行客户
    "当前的规则我没办法追加"的另一半）。此处按调用实时合并，控制台新增即生效。
    """
    try:
        from ..infra.runtime_config import has_runtime_config, load_runtime_config
        if not has_runtime_config():
            return {}
        rt = load_runtime_config() or {}
    except Exception:
        return {}
    out: dict[str, list[str]] = {}
    for _cat, cat in (rt.get("L3_skills") or {}).items():
        if not isinstance(cat, dict) or not cat.get("category_enabled", True):
            continue
        for sk in cat.get("skills", []) or []:
            if sk.get("builtin", True) or not sk.get("enabled", True):
                continue
            sid = sk.get("id")
            if sid:
                out[sid] = list(sk.get("keywords") or [])
    return out


class SkillEngine:
    """Skill 引擎 — 加载、匹配和注入安全检测 Skill"""

    def __init__(
        self,
        skills_dir: str | Path | None = None,
        agent_ext: "AgentExtensions | None" = None,
    ):
        # 仅内置规则模式：忽略配置里的自定义 skills_dir，只用包内 skills/。
        if is_builtin_only():
            self._skills_dir = default_skills_dir()
        else:
            self._skills_dir = Path(skills_dir) if skills_dir else default_skills_dir()
        self._skills_cache: dict[str, str] = {}
        # agent 专属 builtin safe skills 白名单（追加到通用 TRUSTED_SKILLS）
        self._agent_builtin_safe_skills: set[str] = set()
        if agent_ext and agent_ext.builtin_safe_skills:
            self._agent_builtin_safe_skills = set(agent_ext.builtin_safe_skills)
        self._load_all_skills()

    def _load_all_skills(self) -> None:
        """加载所有 Skill 文件到缓存。

        cold / builtin 模式：skill 目录只读一次并进程级冻结（不随文件变化热加载）。
        cold 允许配置里的自定义 skills_dir（作为启动时输入）；builtin 强制包内目录。
        """
        if not is_hot_reload_enabled():
            key = str(self._skills_dir)
            cache = _FROZEN_SKILLS_CACHE.get(key)
            if cache is None:
                cache = {}
                if self._skills_dir.exists():
                    for md_file in sorted(self._skills_dir.glob("*.md")):
                        cache[md_file.stem] = md_file.read_text(encoding="utf-8")
                _FROZEN_SKILLS_CACHE[key] = cache
            self._skills_cache = dict(cache)
            return
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

        # 计算每个 skill 的相关度（内置关键词表 + 用户自定义 skill，后者实时合并）
        skill_map = dict(SKILL_KEYWORD_MAP)
        skill_map.update(runtime_custom_skill_keywords())
        scores: dict[str, float] = {}
        for skill_name, keywords in skill_map.items():
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
            content = self._skills_cache.get(skill_name) or self._load_user_skill(skill_name)
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

    def _load_user_skill(self, name: str) -> str:
        """惰性读用户自定义 skill：``<data_root>/agent_moss_skills/<id>.md``。

        刻意**不**放进启动时的 ``_load_all_skills`` 扫描：控制台新增 skill 是运行中
        发生的事，只在启动扫一次会导致"刚加的 skill 要重启才生效"，与 console 其余
        开关的"改完立刻生效"语义不一致。

        cold / builtin 模式：用户自定义 skill 属于运行期用户数据，直接返回空（不读盘）。
        """
        if is_runtime_config_disabled():
            return ""
        try:
            from ..infra.paths import get_data_root
            p = get_data_root() / "agent_moss_skills" / f"{name}.md"
            if p.is_file():
                content = p.read_text(encoding="utf-8")
                self._skills_cache[name] = content   # 缓存，避免每次判定都读盘
                return content
        except Exception:
            pass
        return ""

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
        """重新加载所有 Skill 文件。

        cold / builtin 模式下不热加载：保留进程级冻结副本（清空实例缓存后从冻结副本恢复）。
        """
        self._skills_cache.clear()
        self._load_all_skills()
