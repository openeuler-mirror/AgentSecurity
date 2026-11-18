"""三方 agent 定制化扩展 — 数据载体

`AgentExtensions` 描述某个宿主 agent（xiaoO / opencode / opendesk）在通用安全规则
之上需要追加的专属规则。规则以 JSON 单一事实源存储（agent_moss/agents/<id>/rules.json），
Python 与 TypeScript 两端共享同一份文件。

设计原则：
- 所有字段以 `extra_` 为前缀，表示"追加到通用规则之后"，不覆盖通用规则。
- 通用规则先匹配；命中即短路，避免重复检测。
- agent 专属规则只做"通用规则没覆盖的宿主 agent 特有风险"。

JSON schema（agent_moss/agents/<id>/rules.json）：
{
  "agent_id": "xiaoo",
  "description": "xiaoO 宿主 agent 专属安全规则",
  "extra_command_patterns": [CommandPattern...],
  "extra_injection_keywords": [InjectionKeyword...],
  "extra_sensitive_paths": [SensitivePath...],
  "builtin_safe_skills": ["xiaoo-guardian"],
  "builtin_safe_action_types": ["memory-", "todomgr-", "mailbox-getEmailList"],
  "extra_skills": []
}
"""

from dataclasses import dataclass, field
from pathlib import Path
import json
import logging

from agent_moss.profiles.base import CommandPattern, SensitivePath

logger = logging.getLogger(__name__)


@dataclass
class InjectionKeyword:
    """Prompt 注入关键词条目"""
    keyword: str
    risk_level: str      # low / medium / high / critical
    lang: str            # en / zh


@dataclass
class AgentExtensions:
    """三方 agent 定制化扩展

    由 `agent_moss.agents.get_agent_extensions(agent_id)` 按需加载。
    缺失 rules.json 时返回 None（通用模式）。
    """
    agent_id: str
    description: str = ""
    extra_command_patterns: list[CommandPattern] = field(default_factory=list)
    extra_injection_keywords: list[InjectionKeyword] = field(default_factory=list)
    extra_sensitive_paths: list[SensitivePath] = field(default_factory=list)
    builtin_safe_skills: list[str] = field(default_factory=list)
    # agent 专属"完全安全操作"白名单（精确名或前缀，前缀以 '-' 结尾）→ 跳过 L2+L3。
    # 对齐 TS ts/src/agents/types.ts。前缀匹配（如 "memory-"）走 startswith，精确名走 ==。
    builtin_safe_action_types: list[str] = field(default_factory=list)
    # agent 专属「单文件写工具」名（小写，精确匹配 action_type）。这些工具的语义是
    # 「把声明的内容写到声明的一个路径」，read_before_write 只取声明路径、不扫 content。
    # 通用名单在 rules/logic_rules.json 的 single_file_write_tools；这里只放宿主独占的工具名
    # （如 OpenDesk 的 filemgr-writeFile），避免把宿主专属命名写进通用规则。
    extra_single_file_write_tools: list[str] = field(default_factory=list)
    extra_skills: list[dict] = field(default_factory=list)

    @classmethod
    def merge(cls, *exts: "AgentExtensions | None") -> "AgentExtensions | None":
        """合并多个 AgentExtensions（如 agent 规则 + 场景规则），追加式拼接各 extra_* 列表。

        全部为 None 时返回 None（通用模式）。非 None 时以第一个非空实例为骨架，
        其余实例的 extra_* / builtin_safe_* 列表依次追加在后（不覆盖）。
        """
        non_null = [e for e in exts if e is not None]
        if not non_null:
            return None
        base = non_null[0]
        return cls(
            agent_id=base.agent_id,
            description=base.description,
            extra_command_patterns=[
                p for e in non_null for p in e.extra_command_patterns
            ],
            extra_injection_keywords=[
                k for e in non_null for k in e.extra_injection_keywords
            ],
            extra_sensitive_paths=[
                sp for e in non_null for sp in e.extra_sensitive_paths
            ],
            builtin_safe_skills=[
                s for e in non_null for s in e.builtin_safe_skills
            ],
            builtin_safe_action_types=[
                t for e in non_null for t in e.builtin_safe_action_types
            ],
            extra_single_file_write_tools=[
                t for e in non_null for t in e.extra_single_file_write_tools
            ],
            extra_skills=[
                sk for e in non_null for sk in e.extra_skills
            ],
        )

    @classmethod
    def from_json(cls, rules_file: Path, id_key: str = "agent_id") -> "AgentExtensions":
        """从 rules.json 加载 AgentExtensions。

        Args:
            rules_file: agent_moss/agents/<id>/rules.json 的绝对路径（场景规则传
                        agent_moss/scenarios/<id>/rules.json，id_key="scenario_id"）
            id_key: JSON 中的 id 字段名。agent 规则默认 "agent_id"；
                    场景规则（agent_moss/scenarios/<id>/rules.json）用 "scenario_id"。

        Returns:
            AgentExtensions 实例

        Raises:
            ValueError: JSON 结构不合法
        """
        with open(rules_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        agent_id = data.get(id_key, "")
        if not agent_id:
            raise ValueError(f"rules.json 缺少 {id_key} 字段: {rules_file}")

        # extra_command_patterns: dict → CommandPattern
        extra_cmd_patterns: list[CommandPattern] = []
        for p in data.get("extra_command_patterns", []):
            extra_cmd_patterns.append(CommandPattern(
                pattern=p["pattern"],
                risk_level=p["risk_level"],
                risk_type=p["risk_type"],
                reason=p["reason"],
            ))

        # extra_injection_keywords: dict → InjectionKeyword
        extra_inj_keywords: list[InjectionKeyword] = []
        for k in data.get("extra_injection_keywords", []):
            extra_inj_keywords.append(InjectionKeyword(
                keyword=k["keyword"],
                risk_level=k["risk_level"],
                lang=k.get("lang", "en"),
            ))

        # extra_sensitive_paths: dict → SensitivePath
        extra_sensitive_paths: list[SensitivePath] = []
        for sp in data.get("extra_sensitive_paths", []):
            extra_sensitive_paths.append(SensitivePath(
                path=sp["path"],
                risk_level=sp["risk_level"],
                desc=sp["desc"],
                credential=sp.get("credential", False),
                read_only=sp.get("read_only", False),
                deny_mode=sp.get("deny_mode", ""),
            ))

        return cls(
            agent_id=agent_id,
            description=data.get("description", ""),
            extra_command_patterns=extra_cmd_patterns,
            extra_injection_keywords=extra_inj_keywords,
            extra_sensitive_paths=extra_sensitive_paths,
            builtin_safe_skills=data.get("builtin_safe_skills", []),
            builtin_safe_action_types=data.get("builtin_safe_action_types", []),
            extra_single_file_write_tools=[
                str(t).lower() for t in data.get("extra_single_file_write_tools", [])
            ],
            extra_skills=data.get("extra_skills", []),
        )
