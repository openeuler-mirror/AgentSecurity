"""AgentMoss Brain — 本地自学习大脑

从 Layer 3 LLM 分析结果中沉淀两类知识：
- 静态规则（BrainRule）→ 融入 Layer 1/2 执行
- Skill（BrainSkill）→ 写入 skills/ 目录，供 Layer 3 匹配使用

存储：
- 规则：~/.agentmoss/brain/rules.db（SQLite）
- Skill：agent_moss/skills/*.md（和内置 Skill 并列）
- 元数据：~/.agentmoss/brain/skill_meta.db（Skill 状态追踪）
"""

from .rule_store import BrainRule, BrainRuleStore
from .skill_manager import BrainSkill, BrainSkillManager

__all__ = [
    "BrainRule",
    "BrainRuleStore",
    "BrainSkill",
    "BrainSkillManager",
]
