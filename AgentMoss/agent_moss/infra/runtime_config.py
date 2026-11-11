"""运行时配置管理 — 种子默认值 → 用户本地副本的初始化、加载、合并

核心模型：
  Profile 驱动的规则源 = "出厂默认"（种子，不可变，随 OSProfile 变化）
  ~/.config/agentmoss/agent_moss_runtime.json = "用户副本"（可增删改，持久化在本地）

优先级：环境变量 > 用户本地 runtime JSON > agent_moss_settings.json > 默认值

热生效原理：agent-moss 作为常驻 HTTP 服务，每次 analyze 调用读取用户本地 JSON。
修改 JSON 文件 → 下次调用自动生效，无需重启。
"""

import json
import logging
import os
import re
from pathlib import Path

from .rules_mode import get_rules_mode, is_runtime_config_disabled

from . import security_policy as sp

logger = logging.getLogger(__name__)

ENV_RUNTIME_CONFIG_PATH = "AGENT_MOSS_RUNTIME_CONFIG_PATH"


class RuntimeConfigReadOnlyError(RuntimeError):
    """cold / builtin 模式下禁止写入 runtime 配置。"""


def _runtime_dir() -> Path:
    """runtime 配置所在目录（跟随数据根，见 infra/paths）。"""
    from .paths import get_runtime_config_dir
    return get_runtime_config_dir()


RUNTIME_CONFIG_DIR = _runtime_dir()
RUNTIME_CONFIG_PATH = RUNTIME_CONFIG_DIR / "agent_moss_runtime.json"

# 层级"禁用"环境变量（值="1" 表示禁用）
LAYER_DISABLE_ENV = {
    "L1_heuristic": "AGENT_MOSS_DISABLE_HEURISTIC",
    "L2_logic_rules": "AGENT_MOSS_DISABLE_LOGIC_RULES",
    "L3_llm_analysis": "AGENT_MOSS_DISABLE_LLM",
}

# 出厂默认层开关（含 L2.2 形式化独立开关、Agent/场景定制规则总开关，默认全开）
DEFAULT_LAYERS = {
    "L1_heuristic": True,
    "L2_logic_rules": True,
    "L3_llm_analysis": True,
    "agent_rules_enabled": True,
    "scenario_rules_enabled": True,
}

DENY_MODE_LABELS = {
    "deny_write": "仅拦截写入",
    "deny_read": "仅拦截读取",
    "deny_both": "读写均拦截",
}

_SKILL_ID_RE = re.compile(r'^[a-zA-Z0-9_-]+$')


# ==================== 种子默认值生成 ====================


def _slugify(text: str) -> str:
    """将文本转为 slug（小写、非字母数字/CJK 转 _、压缩、去首尾、限长 50）"""
    s = re.sub(r"[^a-zA-Z0-9一-鿿]", "_", text.lower())
    s = re.sub(r"_+", "_", s)
    return s.strip("_")[:50]


def _fnv1a_32(text: str) -> str:
    """FNV-1a 32bit hash → 8 位 hex。

    用于规则 id 尾缀，保证不同 pattern 生成不同 id。与 TS 端 `_fnv1a32` 同算法，
    对 ASCII 输入两端结果一致（id 只作定位键，双端去重靠 fingerprint，不强依赖 id 相同）。
    """
    h = 0x811C9DC5
    for b in text.encode("utf-8"):
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return f"{h:08x}"


def _generate_pattern_id(pattern: str) -> str:
    """从正则 pattern 生成唯一规则 id（cmd_<slug>_<hash8>）。

    slug 保留可读性，hash8 保证唯一性——旧版仅截 40 字符 slug，斜杠/竖线/叹号/括号/
    反斜杠等特殊字符被 _slugify 抹平成下划线，导致两条「差异在 40 字符之后 /
    特殊字符布局」的 pattern 撞出同一 id（如两条 rm 规则），console 删除时按 id 取
    第一条会误判「内置规则不可删除」。现在 hash 覆盖完整 pattern，撞车不再可能。
    """
    s = pattern.strip().replace(r"\b", "").replace(r"\s+", "_").replace(r"\s", "_")
    return f"cmd_{_slugify(s[:40])}_{_fnv1a_32(pattern)}"


def _l1_command_patterns_to_rules(profile) -> list[dict]:
    """profile.dangerous_commands (list[CommandPattern]) → rules"""
    rules = []
    for p in profile.dangerous_commands:
        rules.append({
            "id": _generate_pattern_id(p.pattern),
            "pattern": p.pattern,
            "risk_level": p.risk_level,
            "risk_type": p.risk_type,
            "reason": p.reason,
            "enabled": True,
            "builtin": True,
            # 平台归属取**条目自身**的 os（不是加载它的 Profile）——MacOSProfile
            # 继承 Linux 规则时，加载到的 Linux 条目必须仍标 linux，否则 runtime
            # 种子会把它们重复写成 macos 条目（去重失效）。
            "os": getattr(p, "os", "") or "linux",
        })
    return rules


def _l1_injection_keywords_to_rules(profile) -> list[dict]:
    """profile.injection_keywords (list[dict{keyword,risk_level,lang}]) → rules"""
    rules = []
    for kw in profile.injection_keywords:
        keyword = kw["keyword"]
        lang = kw.get("lang", "en")
        rules.append({
            # slug 会抹平前导符号：'=== END OF' 与 '[END OF' 同 slug 成 end_of，
            # 撞 id → Console 操作歧义。hash 覆盖完整 keyword 保证唯一。
            "id": f"inj_{_slugify(keyword)}_{_fnv1a_32(keyword)}",
            "keyword": keyword,
            "risk_level": kw["risk_level"],
            "lang": lang,
            "enabled": True,
            "builtin": True,
            # ⚠️ 带上**条目自己的** os，不要标成 profile 的 os。
            # 旧实现标 profile 自身（调用方只传 linux profile）→ 全被标成 linux，
            # Windows 按 os 过滤后一条不剩 → 静默回退到 profile 里那份 14 条的
            # 历史副本，与 TS 分叉。现在 JSON 里通用条目标 `all`、平台独有标平台。
            "os": str(kw.get("os") or "all").lower(),
        })
    return rules


def _derive_deny_mode(rule: dict) -> str:
    """从 credential / read_only 推导 deny_mode（向后兼容）。优先用已有 deny_mode。"""
    if rule.get("deny_mode"):
        return rule["deny_mode"]
    if rule.get("credential"):
        return "deny_both"
    if rule.get("read_only"):
        return "deny_read"
    return "deny_write"


def _derive_legacy_deny_mode(rule: dict) -> str | None:
    """从 credential / read_only 派生旧版基线 deny_mode（不看 deny_mode 本身）。

    source_deny_mode 字段在 deny_mode 重构后才引入，老配置没有此字段。
    合并时若用户规则缺 source_deny_mode，用 credential/read_only 派生
    "该规则在旧版本的 deny_mode 基线"，补上后走现有合并逻辑，避免用户
    改过的 deny_mode 被 source_deny_mode 缺失静默抹掉（问题 3）。

    与 _derive_deny_mode 的区别：本函数不看 deny_mode（deny_mode 可能是
    用户改过的值，不能当基线），只看 credential/read_only 两个旧字段。

    Returns:
        "deny_both" | "deny_read" | "deny_write" | None（无 credential/read_only 字段）
    """
    if rule.get("credential"):
        return "deny_both"
    if rule.get("read_only"):
        return "deny_read"
    if "credential" in rule or "read_only" in rule:
        # 字段存在但都为 falsy → deny_write
        return "deny_write"
    return None


def _sync_deny_mode_fields(rule: dict) -> None:
    """根据 deny_mode 同步 credential / read_only（保持底层检测逻辑兼容）"""
    dm = rule.get("deny_mode", "deny_write")
    if dm == "deny_both":
        rule["credential"] = True
        rule.pop("read_only", None)
    elif dm == "deny_read":
        rule.pop("credential", None)
        rule["read_only"] = True
    else:  # deny_write
        rule.pop("credential", None)
        rule.pop("read_only", None)


def _l2_sensitive_paths_to_rules(profile) -> list[dict]:
    """profile.sensitive_paths (list[SensitivePath]) → rules"""
    rules = []
    for sp in profile.sensitive_paths:
        sp_dict = {
            "path": sp.path, "risk_level": sp.risk_level, "desc": sp.desc,
            "credential": sp.credential, "read_only": sp.read_only, "deny_mode": sp.deny_mode,
            "dir_del_only": getattr(sp, "dir_del_only", False),
        }
        deny_mode = _derive_deny_mode(sp_dict)
        os_tag = getattr(sp, "os", "") or "linux"
        # id = path_<平台>_<slug>_<hash8>：
        # - 平台段：Linux/Windows 存在同名 path（.ssh/.aws 各一条），不加会跨平台撞 id
        # - hash 段：同平台内 slug 也可能撞（macOS 的 /Library/LaunchAgents 系统级与
        #   Library/LaunchAgents 用户级，slug 后同名但语义不同）——hash 覆盖完整 path 保证唯一
        # Console 按 id 操作（改 deny_mode/启停），撞 id 会取到第一条 = 误改别的规则。
        rule = {
            "id": f"path_{os_tag}_{_slugify(sp.path)}_{_fnv1a_32(sp.path)}",
            "path": sp.path,
            "risk_level": sp.risk_level,
            "desc": sp.desc,
            "deny_mode": deny_mode,
            "source_deny_mode": deny_mode,
            "skip_l3_on_disabled": True,
            "enabled": True,
            "builtin": True,
            # 标记平台归属：runtime 覆盖按 os 过滤，条目必须自报平台。
            # 取条目自身的 os（非 Profile 的）——MacOSProfile 继承的 Linux 条目
            # 仍标 linux，保证种子去重与 Console 分组正确。
            "os": getattr(sp, "os", "") or "linux",
        }
        _sync_deny_mode_fields(rule)
        if getattr(sp, "dir_del_only", False):
            rule["dir_del_only"] = True
        rules.append(rule)
    return rules


def _l2_intent_patterns_to_rules(profile) -> list[dict]:
    """profile.intent_deviation_patterns (list[IntentDeviationPattern]) → rules"""
    rules = []
    for i, pat in enumerate(profile.intent_deviation_patterns):
        os_tag = getattr(pat, "os", "") or "linux"
        rules.append({
            # id 含平台段：三平台的意图模式 reason 可能相同（如 macOS 继承 Linux），
            # 不加平台段会撞 id → Console 操作歧义。
            "id": f"intent_{os_tag}_{i+1}_{_slugify(pat.reason[:30])}",
            "intent_keywords": pat.intent_keywords,
            "dangerous_actions": pat.dangerous_actions,
            "reason": pat.reason,
            "skip_l3_on_disabled": True,
            "enabled": True,
            "builtin": True,
            "os": getattr(pat, "os", "") or "linux",
        })
    return rules


def _l2_password_patterns_to_rules() -> list[dict]:
    """PASSWORD_MODIFY_PATTERNS (module const) → rules"""
    from ..engine.logic_rules import PASSWORD_MODIFY_PATTERNS
    return [
        {"id": f"pw_{_slugify(p)}", "pattern": p, "skip_l3_on_disabled": True,
         "enabled": True, "builtin": True}
        for p in PASSWORD_MODIFY_PATTERNS
    ]


def _l2_user_deletion_patterns_to_rules() -> list[dict]:
    """USER_DELETION_PATTERNS (module const) → rules"""
    from ..engine.logic_rules import USER_DELETION_PATTERNS
    return [
        {"id": f"ud_{_slugify(p)}", "pattern": p, "skip_l3_on_disabled": True,
         "enabled": True, "builtin": True}
        for p in USER_DELETION_PATTERNS
    ]


def _l3_skills_to_rules() -> dict:
    """SKILL_KEYWORD_MAP (dict[str,list[str]]) → 分类 skill 结构。"""
    from ..engine.skill_engine import SKILL_KEYWORD_MAP
    skill_categories = {
        "file_operations": ["file_access_guard", "script_execution_guard", "indirect_access_guard"],
        "network_security": ["data_exfiltration_guard", "browser_web_access_guard",
                             "lateral_movement_guard", "email_operation_guard"],
        "persistence_supply_chain": ["persistence_backdoor_guard", "supply_chain_guard",
                                     "skill_installation_guard"],
        "intent_and_general": ["intent_deviation_guard", "general_tool_risk_guard"],
        "resource": ["resource_exhaustion_guard"],
    }
    out = {}
    for cat, ids in skill_categories.items():
        out[cat] = {
            "category_enabled": True, "category_desc": "",
            "skills": [{"id": s, "keywords": SKILL_KEYWORD_MAP.get(s, []),
                        "enabled": True, "builtin": True} for s in ids],
        }
    categorized = {s for ids in skill_categories.values() for s in ids}
    for s in SKILL_KEYWORD_MAP:
        if s not in categorized:
            out.setdefault("intent_and_general",
                           {"category_enabled": True, "category_desc": "", "skills": []}
                           )["skills"].append(
                {"id": s, "keywords": SKILL_KEYWORD_MAP[s], "enabled": True, "builtin": True})
    out["user_custom"] = {"category_enabled": True, "category_desc": "", "skills": []}
    return out


def _agent_rules_to_defaults() -> dict:
    """扫描 agent_moss/agents/<id>/rules.json，转为 agent_rules 分区结构（出厂种子）。

    每个 agent 的 rules.json 字段（AgentExtensions）→ runtime_config 的
    agent_rules[<id>] 的 Category 结构，与 L1_rules/L2_rules 同形：
      { category_enabled, category_desc, rules: [{value/pattern/... , enabled:true, builtin:true}] }

    builtin_safe_action_types / builtin_safe_skills 原为 string[]，转成
    [{value, enabled:true, builtin:true}]。extra_* 原为对象数组，加 enabled/builtin。

    缺失 agents 目录或无 rules.json 时返回 {}（无 agent 规则，不影响通用规则）。
    """
    try:
        from ..agents import _agents_dir
    except Exception:
        return {}
    _agents = _agents_dir()
    if not _agents.exists():
        return {}
    out = {}
    for agent_dir in sorted(_agents.iterdir()):
        rules_file = agent_dir / "rules.json"
        if not rules_file.is_file():
            continue
        agent_id = agent_dir.name
        try:
            with open(rules_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue
        cats = {}
        # builtin_safe_action_types: string[] → [{value, enabled, builtin}]
        cats["builtin_safe_action_types"] = {
            "category_enabled": True,
            "category_desc": "agent 完全安全操作白名单（前缀尾随 - 或精确名，命中跳 L2+L3）",
            "rules": [{"value": v, "enabled": True, "builtin": True}
                      for v in data.get("builtin_safe_action_types", [])],
        }
        cats["builtin_safe_skills"] = {
            "category_enabled": True,
            "category_desc": "agent 信任的内置 Skill（命中跳 L2+L3）",
            "rules": [{"value": v, "enabled": True, "builtin": True}
                      for v in data.get("builtin_safe_skills", [])],
        }
        # extra_command_patterns: [{pattern, risk_level, risk_type, reason}] → 加 enabled/builtin
        cats["extra_command_patterns"] = {
            "category_enabled": True,
            "category_desc": "agent 专属危险命令正则（L1 末尾追加）",
            "rules": [{**p, "enabled": True, "builtin": True}
                      for p in data.get("extra_command_patterns", [])],
        }
        cats["extra_injection_keywords"] = {
            "category_enabled": True,
            "category_desc": "agent 专属注入关键词（L1 末尾追加）",
            "rules": [{**k, "enabled": True, "builtin": True}
                      for k in data.get("extra_injection_keywords", [])],
        }
        cats["extra_sensitive_paths"] = {
            "category_enabled": True,
            "category_desc": "agent 专属敏感路径（L1 末尾追加）",
            "rules": [{**sp, "enabled": True, "builtin": True}
                      for sp in data.get("extra_sensitive_paths", [])],
        }
        out[agent_id] = cats
    return out


def _scenario_rules_to_defaults() -> dict:
    """扫描 agent_moss/scenarios/<id>/rules.json，转为 scenario_rules 分区结构（出厂种子）。

    与 _agent_rules_to_defaults 同构（场景规则也是 AgentExtensions 结构），唯一区别：
    - 目录是 scenarios/ 而非 agents/；
    - 顶层 id 字段是 scenario_id 而非 agent_id（AgentExtensions.from_json id_key 兼容）。
    每个场景的 rules.json 字段 → runtime_config 的 scenario_rules[<id>] 的 Category 结构
    （与 L1_rules/L2_rules 同形）。场景不含 builtin_safe_action_types/builtin_safe_skills
    （场景是部署级约束，不定义 agent 白名单），但仍保留这两个类别占位（空 rules），
    与 agent 分区结构对齐，console 渲染共用一套模板。

    缺失 scenarios 目录或无 rules.json 时返回 {}。

    ⚠️ 每个场景的 rules.json 走**覆盖目录链**解析（AGENT_MOSS_OVERRIDE_RULES_DIR /
    data_root 的 scenarios/<id>/rules.json 优先）—— 覆盖文件替换了场景规则时，
    种子必须反映覆盖后的内容，否则 runtime 分区会把覆盖文件盖回去（覆盖失效）。
    """
    try:
        from ..rules_loader import resolve_scenario_rules_file
        from ..scenarios import _scenarios_dir
    except Exception:
        return {}
    _scenarios = _scenarios_dir()
    if not _scenarios.exists():
        return {}
    out = {}
    for scen_dir in sorted(_scenarios.iterdir()):
        scenario_id = scen_dir.name
        # __pycache__ 等以 __ 开头的运行时目录不是场景。不跳过的话，每次生成
        # 种子都会走一遍 resolve_scenario_rules_file 并刷一条「非法 scenario_id」
        # 告警 —— 那是给"目录穿越尝试"用的信号，不该被缓存目录淹掉。
        if not scen_dir.is_dir() or scenario_id.startswith("__"):
            continue
        rules_file = resolve_scenario_rules_file(scenario_id)
        if not rules_file.is_file():
            continue
        try:
            with open(rules_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue
        cats = {}
        cats["builtin_safe_action_types"] = {
            "category_enabled": True,
            "category_desc": "场景完全安全操作白名单（场景通常不使用）",
            "rules": [],
        }
        cats["builtin_safe_skills"] = {
            "category_enabled": True,
            "category_desc": "场景信任的内置 Skill（场景通常不使用）",
            "rules": [],
        }
        cats["extra_command_patterns"] = {
            "category_enabled": True,
            "category_desc": "场景专属危险命令正则（L1 末尾追加）",
            "rules": [{**p, "enabled": True, "builtin": True}
                      for p in data.get("extra_command_patterns", [])],
        }
        cats["extra_injection_keywords"] = {
            "category_enabled": True,
            "category_desc": "场景专属注入关键词（L1 末尾追加）",
            "rules": [{**k, "enabled": True, "builtin": True}
                      for k in data.get("extra_injection_keywords", [])],
        }
        cats["extra_sensitive_paths"] = {
            "category_enabled": True,
            "category_desc": "场景专属敏感路径（L1 末尾追加）",
            "rules": [{**sp, "enabled": True, "builtin": True}
                      for sp in data.get("extra_sensitive_paths", [])],
        }
        out[scenario_id] = cats
    return out


def generate_source_defaults(profile=None) -> dict:
    """从 Profile + 模块常量，提取为 JSON 结构（出厂默认种子）。

    Args:
        profile: OSProfile 实例。为 None 时**遍历所有平台**（linux/windows/macos）
            产出带 `os` 标记的全量规则集 —— 这样：
            1. Policy Console 能显示并配置各平台规则（只生成当前平台会让
               Windows/macOS 规则在 Console 里不可见、不可配）；
            2. merge 时各平台条目独立合并（`_rule_fingerprint` 含 os，互不覆盖）；
            3. 运行时按 `os_type` 过滤取对应平台（见 `_rules_for_os`）。
            显式传入 profile 时只生成该平台（兼容旧调用）。
    """
    if profile is not None:
        profiles = [profile]
    else:
        from ..profiles import get_profile
        profiles = [
            get_profile(os_name) for os_name in ("linux", "windows", "macos", "harmony")
        ]

    def _collect(fn) -> list:
        """按平台遍历收集规则（各条自带 os 标记），按指纹去重。

        去重必要性：`MacOSProfile` 继承 `LinuxProfile`，其 `accepted_os` 含
        'linux' —— 遍历到 macOS 时会**再生成一遍全部 Linux 条目**（os 标记仍是
        linux）。指纹（含 os 维度）去重后，macOS 只贡献自己的专属条目，
        Linux 条目不被重复写入。最终各平台条目数 == JSON 中该平台条目数。
        """
        out: list = []
        seen: set = set()
        for prof in profiles:
            for rule in fn(prof):
                fp = _rule_fingerprint(rule)
                if fp in seen:
                    continue
                seen.add(fp)
                out.append(rule)
        return out

    return {
        "version": 1,
        "layers": dict(DEFAULT_LAYERS),
        "L1_rules": {
            "dangerous_commands": {
                "category_enabled": True,
                "category_desc": "危险命令检测（递归删除、全权限设置、提权执行等；含平台专属）",
                "rules": _collect(_l1_command_patterns_to_rules),
            },
            "injection_detection": {
                "category_enabled": True,
                "category_desc": "Prompt 注入攻击检测",
                # ⚠️ 必须 `_collect` 遍历**全部平台**，不能只取 `profiles[0]`。
                # 旧实现的理由是"注入与操作系统无关、三平台 keyword 集相同"，但
                # `WindowsProfile` 实际自带 3 条独有关键词 —— 只取 linux 一份，
                # 这 3 条永远进不了种子，Windows 判定时静默少检（2026-10 修）。
                # 现在 JSON 里通用条目标 `os: "all"`、平台独有标平台，靠指纹去重
                # （`all` 条目四平台各贡献一次、指纹相同 → 只留一份）。
                "rules": _collect(_l1_injection_keywords_to_rules),
            },
            "sensitive_path_access": {
                "category_enabled": True,
                "category_desc": "敏感路径访问检测（deny_both/deny_read/deny_write；含平台专属）",
                "rules": _collect(_l2_sensitive_paths_to_rules),
            },
            "user_custom": {
                "category_enabled": True,
                "category_desc": "用户自定义命令规则",
                "rules": [],
            },
        },
        "L2_rules": {
            "intent_consistency": {
                "category_enabled": True,
                "category_desc": "意图一致性检测（含平台专属动作词）",
                "rules": _collect(_l2_intent_patterns_to_rules),
            },
            "password_modify_consent": {
                "category_enabled": True,
                "category_desc": "非交互式密码修改授权检测",
                "rules": _l2_password_patterns_to_rules(),
            },
            "user_deletion_consent": {
                "category_enabled": True,
                "category_desc": "用户/组删除操作授权检测",
                "rules": _l2_user_deletion_patterns_to_rules(),
            },
            "read_before_write": {
                "category_enabled": True,
                "category_desc": "read_before_write 安全原则检测",
                "rules": [],
            },
            "user_custom": {
                "category_enabled": True,
                "category_desc": "用户自定义 L2 逻辑规则",
                "rules": [],
            },
        },
        "L3_skills": _l3_skills_to_rules(),
        "L2_2": _ltl_rules_to_runtime(),
        "agent_rules": _agent_rules_to_defaults(),
        "scenario_rules": _scenario_rules_to_defaults(),
    }


# ==================== 配置加载与合并 ====================


def get_runtime_config_path() -> Path:
    """获取 runtime 配置文件路径。

    优先级：env AGENT_MOSS_RUNTIME_CONFIG_PATH > agent_moss_settings.json 同名键 > 默认路径

    cold / builtin 模式下不再回落 settings JSON（连路径解析都尽量不碰用户配置；
    该路径只用于日志展示，引擎不会读写它）。
    """
    env_path = os.getenv(ENV_RUNTIME_CONFIG_PATH)
    if env_path:
        return Path(env_path)
    if is_runtime_config_disabled():
        return RUNTIME_CONFIG_PATH
    from .config import get_agent_moss_setting
    settings_path = get_agent_moss_setting(ENV_RUNTIME_CONFIG_PATH, "")
    if settings_path:
        return Path(settings_path)
    return RUNTIME_CONFIG_PATH


def get_rule_source_fingerprint() -> tuple:
    """规则来源指纹（runtime 配置文件的 path / mtime_ns / size）。

    供 agent/scenario 扩展缓存判断是否需要重新加载：手工编辑 runtime JSON 或
    Console 写盘后，下一次判定会自动重建扩展，而不是一直使用首次加载的副本。

    cold / builtin 模式返回常量（runtime 配置本就不参与判定）；文件不存在时返回
    ``("absent",)``，文件出现/被删/被改都会改变指纹。
    """
    if is_runtime_config_disabled():
        return (f"mode:{get_rules_mode()}",)
    try:
        path = get_runtime_config_path()
        st = path.stat()
        return (str(path), st.st_mtime_ns, st.st_size)
    except OSError:
        return ("absent",)


def save_runtime_config(config: dict) -> None:
    """保存运行时配置到用户本地文件。

    cold / builtin 模式下**拒绝写入**：Console / CLI 的修改一律不落盘，服务重启也
    不会读到用户配置。抛异常而不是静默 no-op —— 静默会让调用方以为保存成功。
    """
    if is_runtime_config_disabled():
        raise RuntimeConfigReadOnlyError(
            f"规则来源模式为 {get_rules_mode()}（runtime 配置已禁用）："
            "修改规则不会生效，请改用 hot 模式（AGENT_MOSS_RULES_MODE=hot）"
            "或调整规则目录后重启服务。"
        )
    config_path = get_runtime_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    sp.write_private_text(config_path, json.dumps(config, indent=2, ensure_ascii=False))
    # 落盘即失效进程内缓存，保证写后读一致（mtime 指纹之外的第二道保险）
    _RUNTIME_CONFIG_CACHE.clear()
    _HAS_RUNTIME_CONFIG_CACHE.clear()
    logger.info("配置已保存: %s", config_path)


#: load_runtime_config 的进程内缓存：(path, mtime_ns, size) → 合并后的配置。
#: 缓存键含文件指纹——用户手工编辑 / console 保存 / save_runtime_config 落盘后
#: mtime 变化 → 自动失效，热生效语义不变（见模块 docstring「热生效原理」）。
#: 收益：单次 analyze 会调用本函数 6 次（各检测器各自取配置），缓存把重复的
#: 「读 69KB JSON + 深拷贝 + merge + 生成源码默认」收敛为一次（实测 49ms → 个位 ms）。
#: 约定：调用方**不得原地修改**返回的 dict（需改请 copy 后改，或改完落盘使缓存失效）。
_RUNTIME_CONFIG_CACHE: dict[tuple[str, int, int], dict] = {}


def load_runtime_config() -> dict:
    """加载运行时配置：缺失则从种子生成并写入，已有则合并新出厂规则。

    结果按文件指纹缓存（见 `_RUNTIME_CONFIG_CACHE`），改文件后自动失效。

    cold / builtin 模式下**完全不碰用户配置文件**：不读、不 seed、不 merge、不写回，
    直接返回只含默认层级开关的空配置；各 `*_or_default` 取数函数因此自动回退到
    包内 profile / 模块常量（cold 模式再叠加规则目录）。
    """
    if is_runtime_config_disabled():
        return {"version": 1, "layers": dict(DEFAULT_LAYERS)}
    config_path = get_runtime_config_path()
    if not config_path.exists():
        defaults = generate_source_defaults()
        config_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            sp.write_private_text(config_path, json.dumps(defaults, indent=2, ensure_ascii=False))
            logger.info("首次运行，已生成默认配置: %s", config_path)
        except OSError as e:
            logger.warning("无法写入配置文件 %s: %s，使用内存默认值", config_path, e)
        return defaults

    # 命中缓存直接返回（文件未变：mtime + size 相同）
    try:
        st = config_path.stat()
        cache_key: tuple[str, int, int] | None = (str(config_path), st.st_mtime_ns, st.st_size)
    except OSError:
        cache_key = None
    if cache_key is not None:
        cached = _RUNTIME_CONFIG_CACHE.get(cache_key)
        if cached is not None:
            return cached

    try:
        user_config = json.loads(config_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("配置文件 %s 读取失败: %s，使用默认值", config_path, e)
        return generate_source_defaults()
    source_defaults = generate_source_defaults()
    # 深拷贝原始配置，用于对比 merge 是否产生变化（merge_config 是 in-place 修改，
    # 直接用 merged != user_config 会因同对象永远 False，导致迁移结果不写回文件）。
    import copy
    original = copy.deepcopy(user_config)
    merged = merge_config(user_config, source_defaults)
    if merged != original:
        try:
            sp.write_private_text(config_path, json.dumps(merged, indent=2, ensure_ascii=False))
            logger.info("配置已合并更新: %s", config_path)
        except OSError as e:
            logger.warning("无法写入合并后的配置: %s", e)

    # 写回后文件指纹已变，重新取一次再入缓存（只保留最新一份，避免条目累积）
    try:
        st_new = config_path.stat()
        _RUNTIME_CONFIG_CACHE.clear()
        _RUNTIME_CONFIG_CACHE[(str(config_path), st_new.st_mtime_ns, st_new.st_size)] = merged
    except OSError:
        pass
    return merged


def merge_config(user_cfg: dict, source_defaults: dict) -> dict:
    """合并用户配置与源码默认值。

    策略：保留用户 enabled 开关；新增 builtin 规则补入 enabled=True；
    源码已删除的 builtin 标记 source_removed+enabled=False；用户自定义规则保留。
    """
    if "version" not in user_cfg:
        user_cfg["version"] = source_defaults.get("version", 1)
    if "layers" not in user_cfg:
        user_cfg["layers"] = {}
    for layer_key, default_val in source_defaults["layers"].items():
        if layer_key not in user_cfg["layers"]:
            user_cfg["layers"][layer_key] = default_val
    # 跨层迁移：敏感路径已从 L2 重分类到 L1。
    # 老配置 sensitive_path_access 还在 L2_rules 下，搬到 L1_rules（保留用户的
    # enabled/deny_mode/自定义项），L2 节点下删除该分类。新配置无此问题。
    # 注：dangerous_patterns / lateral_movement 检测是硬编码子检测器，不读 runtime
    # config rules，故老配置 L2 里这两类的 rules 不迁移（默认种子已删除该类目）。
    _migrate_categories_across_layers(user_cfg, "L2_rules", "L1_rules",
                                      ["sensitive_path_access"])
    # 跨版本迁移：形式化引擎层号 L2.4 已统一重命名为 L2.2（violated_layers 与层名
    # 三套并一套）。旧配置键 L2_4 迁移到新键 L2_2，保留用户 enabled/自定义规则。
    if "L2_2" not in user_cfg and "L2_4" in user_cfg:
        user_cfg["L2_2"] = user_cfg.pop("L2_4")
    _merge_rule_categories(user_cfg, source_defaults, "L1_rules")
    _merge_rule_categories(user_cfg, source_defaults, "L2_rules")
    _merge_rule_categories(user_cfg, source_defaults, "L2_2")
    _merge_skill_categories(user_cfg, source_defaults, "L3_skills")
    _merge_agent_rules(user_cfg, source_defaults)
    _merge_agent_rules(user_cfg, source_defaults, partition="scenario_rules")
    return user_cfg


def _migrate_categories_across_layers(user_cfg: dict, src_layer: str, dst_layer: str, cat_names: list[str]) -> None:
    """把指定分类从 src_layer 搬到 dst_layer（保留分类内全部内容）。

    迁移后 src_layer 下该分类置空 rules（保留分类壳，避免下游 KeyError）。
    若 dst_layer 已有同名分类，合并 rules（按指纹去重，dst 优先）。
    """
    src = user_cfg.get(src_layer, {})
    dst = user_cfg.setdefault(dst_layer, {})
    for cat_name in cat_names:
        if cat_name not in src:
            continue  # src 无此分类，跳过
        src_cat = src[cat_name]
        # dst 确保有此分类（即使 src rules 为空，也把分类壳搬到 dst）
        dst_cat = dst.setdefault(cat_name, {
            "category_enabled": True,
            "category_desc": "",
            "rules": [],
        })
        if "category_desc" not in dst_cat or not dst_cat.get("category_desc"):
            dst_cat["category_desc"] = src_cat.get("category_desc", "")
        dst_cat.setdefault("category_enabled", src_cat.get("category_enabled", True))
        # 合并 rules：dst 已有的按指纹保留，src 独有的追加
        if src_cat.get("rules"):
            dst_fps = {_rule_fingerprint(r) for r in dst_cat.get("rules", [])}
            for r in src_cat["rules"]:
                if _rule_fingerprint(r) not in dst_fps:
                    dst_cat.setdefault("rules", []).append(r)
                    dst_fps.add(_rule_fingerprint(r))
        # src 删除该分类（搬走了，不留壳，避免 console 还在 L2 显示）
        del src[cat_name]


def _normalize_pattern_for_fingerprint(pattern: str) -> str:
    """正则 pattern 规范化，用于计算规则指纹。

    Python 与 TS 生成规则时对 `/` 的转义不一致：TS 用 RegExp.source（`/` 转义为 `\\/`），
    Python 直接存 `/`。这导致同一规则在两端生成 pattern 字符串不同 → 指纹不同 →
    双端 merge 时互相把对方标记 source_removed 而禁用（L1 启用数不一致）。

    这里把 `\\/` 规范化为 `/`，使两端 pattern 指纹一致。只处理 `/` 转义，不动其他正则转义。
    """
    return pattern.replace(r"\/", "/")


def _rule_fingerprint(rule: dict) -> tuple:
    """规则内容指纹（跨 id 变更识别同一规则）。

    **含平台维度**：同一 path/pattern 在不同平台是不同规则 —— 如 `.ssh`/`.aws`
    目录级条目在 Linux 与 Windows 各有一条（各自的 deny_mode/desc 不同）。
    若指纹不含 os，merge 的 `user_by_fp = {指纹: 规则}` 会让两个平台的同名条目
    互相覆盖，其中一个平台的规则**静默丢失**（2026-09 实测 .ssh/.aws 两组冲突）。

    无 os 字段的历史条目视为 linux —— 与加载过滤、runtime 覆盖的口径一致，
    保证老配置的 enabled/deny_mode 用户设置仍能匹配到源码条目。
    """
    os_tag = str(rule.get("os") or "linux").lower()
    if rule.get("intent_keywords") or rule.get("dangerous_actions"):
        return (os_tag, tuple(sorted(rule.get("intent_keywords", []))),
                tuple(sorted(rule.get("dangerous_actions", []))))
    if rule.get("path"):
        return (os_tag, _normalize_pattern_for_fingerprint(rule["path"]))
    if rule.get("pattern"):
        return (os_tag, _normalize_pattern_for_fingerprint(rule["pattern"]))
    if rule.get("keyword"):
        return (os_tag, rule["keyword"], rule.get("lang", ""))
    # builtin_safe_action_types / builtin_safe_skills 项用 value 字段
    if rule.get("value"):
        return (os_tag, rule["value"])
    return (os_tag, rule.get("id", ""))


def _merge_rule_categories(user_cfg: dict, source_defaults: dict, layer_key: str) -> None:
    """合并单个 layer（L1_rules / L2_rules / L2_2）的分类与规则。"""
    user_layer = user_cfg.setdefault(layer_key, {})
    src_layer = source_defaults.get(layer_key, {})
    for cat_name, src_cat in src_layer.items():
        if cat_name not in user_layer:
            user_layer[cat_name] = src_cat
            continue
        user_cat = user_layer[cat_name]
        # 容错：老配置该分类不是 dict（真/假等残留）→ 直接用新默认覆盖
        if not isinstance(user_cat, dict):
            user_layer[cat_name] = src_cat
            continue
        if "category_desc" not in user_cat:
            user_cat["category_desc"] = src_cat.get("category_desc", "")
        user_cat.setdefault("category_enabled", src_cat.get("category_enabled", True))
        src_rules = src_cat.get("rules", [])
        user_rules = user_cat.setdefault("rules", [])
        user_by_fp = {_rule_fingerprint(r): r for r in user_rules}
        src_fps = set()
        for src_r in src_rules:
            fp = _rule_fingerprint(src_r)
            src_fps.add(fp)
            if fp in user_by_fp:
                existing = user_by_fp[fp]
                # 用户是否**主动**禁用过这条（见 _apply_rule_enabled）。
                # ⚠️ 不能像以前那样无条件沿用 existing["enabled"]：源码里仍有这条规则时，
                # 无法区分「用户主动禁用」与「历史污染/系统自动禁用」，沿用就等于一次污染
                # 永久锁死（源码里规则一直都在，merge 一百次也救不回来，只能手动删 runtime）。
                # 现在：有 user_disabled 标记才保持禁用，无标记的 False 自动痊愈为启用。
                user_disabled = existing.get("user_disabled", False)
                user_skip_l3 = existing.get("skip_l3_on_disabled")
                user_deny_mode = existing.get("deny_mode")
                user_source_deny = existing.get("source_deny_mode")
                # 老配置缺 source_deny_mode 基线：从 credential/read_only 派生旧基线
                # （不看 deny_mode 本身，deny_mode 可能是用户改过的值）。补基线后
                # 走下方 user_deny_mode != user_source_deny 判定，避免用户改过的
                # deny_mode 被 source_deny_mode 缺失静默抹掉（问题 3）。
                if user_source_deny is None:
                    legacy_baseline = _derive_legacy_deny_mode(existing)
                    if legacy_baseline is not None:
                        user_source_deny = legacy_baseline
                existing.clear()
                existing.update(src_r)
                # existing.update(src_r) 会抹掉 user_disabled（源码规则不带该字段），故在其后重写
                existing["enabled"] = not user_disabled
                if user_disabled:
                    existing["user_disabled"] = True
                if user_skip_l3 is not None:
                    existing["skip_l3_on_disabled"] = user_skip_l3
                if user_deny_mode and user_source_deny and user_deny_mode != user_source_deny:
                    existing["deny_mode"] = user_deny_mode
                # 派生基线写回（源码总带 source_deny_mode，此处仅兜底）
                if user_source_deny is not None and existing.get("source_deny_mode") is None:
                    existing["source_deny_mode"] = user_source_deny
                if "deny_mode" in existing:
                    _sync_deny_mode_fields(existing)
            else:
                new_r = dict(src_r)
                new_r["enabled"] = True
                user_rules.append(new_r)
        for r in user_rules:
            if r.get("builtin") and _rule_fingerprint(r) not in src_fps:
                r["source_removed"] = True
                r["enabled"] = False
        if cat_name == "sensitive_path_access":
            for r in user_rules:
                if "deny_mode" not in r:
                    r["deny_mode"] = _derive_deny_mode(r)
                _sync_deny_mode_fields(r)
    # 清理源码已移除的类目：保留 user_custom（用户自定义壳），删除其余不在 src 的类目
    # （如本次重构删除的 dangerous_patterns / lateral_movement，老配置落盘仍残留）。
    for cat_name in list(user_layer.keys()):
        if cat_name == "user_custom":
            continue
        if cat_name not in src_layer:
            # 分类被源码移除（如历史上的 dangerous_patterns / lateral_movement）。
            # ⚠️ 别把用户自己加的规则一起删了：Console 的 add-rule 端点 category 是
            # 请求参数，API 调用方可以指定任意分类（如直接把自定义规则塞进
            # dangerous_commands）。源码删整类时这些非 builtin 条目应迁到 user_custom
            # 保留，否则静默丢用户的规则。
            _kept = [
                r for r in user_layer[cat_name].get("rules", [])
                if not r.get("builtin", True)
            ]
            if _kept:
                _uc = user_layer.setdefault("user_custom", {
                    "category_enabled": True, "category_desc": "", "rules": [],
                })
                _existing = {r.get("id") for r in _uc.setdefault("rules", [])}
                _uc["rules"].extend(r for r in _kept if r.get("id") not in _existing)
            del user_layer[cat_name]


def _merge_skill_categories(user_cfg: dict, source_defaults: dict, layer_key: str) -> None:
    """合并 L3_skills 分类。新分类整体加入；已有分类补全元字段 + 追加新 builtin skill。"""
    user_layer = user_cfg.setdefault(layer_key, {})
    src_layer = source_defaults.get(layer_key, {})
    for cat_name, src_cat in src_layer.items():
        if cat_name not in user_layer:
            user_layer[cat_name] = src_cat
            continue
        user_cat = user_layer[cat_name]
        if "category_desc" not in user_cat:
            user_cat["category_desc"] = src_cat.get("category_desc", "")
        user_cat.setdefault("category_enabled", src_cat.get("category_enabled", True))
        user_skills = user_cat.setdefault("skills", [])
        existing_ids = {s.get("id") for s in user_skills}
        for src_s in src_cat.get("skills", []):
            if src_s.get("id") not in existing_ids:
                user_skills.append(dict(src_s))


def _merge_agent_rules(user_cfg: dict, source_defaults: dict,
                       partition: str = "agent_rules") -> None:
    """合并 agent_rules / scenario_rules 分区（按 id 分区，每个 id 内复用类别合并逻辑）。

    - 新出厂 agent/场景（源有、用户无）→ 整体加入。
    - 已有 → 每个类别走 _merge_rule_categories 的同一套：指纹去重 +
      保留用户 enabled + 新出厂条目追加(enabled=true) + 删除标记(source_removed)。
    - agent 规则指纹：builtin_safe_action_types/builtin_safe_skills 用 value；
      extra_* 用其既有指纹字段（pattern/path/keyword）。
    """
    user_agent = user_cfg.setdefault(partition, {})
    src_agent = source_defaults.get(partition, {})
    for agent_id, src_cats in src_agent.items():
        if agent_id not in user_agent:
            user_agent[agent_id] = dict(src_cats)
            continue
        user_cats = user_agent[agent_id]
        for cat_name, src_cat in src_cats.items():
            if cat_name not in user_cats:
                user_cats[cat_name] = dict(src_cat)
                continue
            user_cat = user_cats[cat_name]
            if "category_desc" not in user_cat:
                user_cat["category_desc"] = src_cat.get("category_desc", "")
            user_cat.setdefault("category_enabled", src_cat.get("category_enabled", True))
            src_rules = src_cat.get("rules", [])
            user_rules = user_cat.setdefault("rules", [])
            user_by_fp = {_rule_fingerprint(r): r for r in user_rules}
            src_fps = set()
            for src_r in src_rules:
                fp = _rule_fingerprint(src_r)
                src_fps.add(fp)
                if fp in user_by_fp:
                    existing = user_by_fp[fp]
                    # 同主 merge：只认 user_disabled 标记，无标记的 False 自动痊愈
                    user_disabled = existing.get("user_disabled", False)
                    existing.clear()
                    existing.update(src_r)
                    existing["enabled"] = not user_disabled
                    if user_disabled:
                        existing["user_disabled"] = True
                else:
                    new_r = dict(src_r)
                    new_r.setdefault("enabled", True)
                    user_rules.append(new_r)
            for r in user_rules:
                if r.get("builtin") and _rule_fingerprint(r) not in src_fps:
                    r["source_removed"] = True
                    r["enabled"] = False


# ==================== 层级开关 ====================


def is_layer_enabled(layer_key: str) -> bool:
    """判断指定层级是否启用。

    优先级：env > runtime JSON > agent_moss_settings.json > 默认 True。

    cold / builtin 模式下**规则开关只认环境变量**：runtime JSON / settings JSON 里的
    层级开关一律忽略（用户改配置文件无法关层）。
    """
    disable_key = LAYER_DISABLE_ENV.get(layer_key)
    if disable_key and os.getenv(disable_key) == "1":
        return False
    if is_runtime_config_disabled():
        return True
    runtime = load_runtime_config()
    layers = runtime.get("layers", {})
    if layer_key in layers:
        return bool(layers[layer_key])
    if disable_key:
        from .config import get_agent_moss_setting
        if get_agent_moss_setting(disable_key, "") == "1":
            return False
    return True


def get_env_overrides() -> dict:
    """获取当前环境变量的覆盖状态（供 console 展示被 env 接管的开关）。"""
    overrides = {}
    for layer_key, env_key in LAYER_DISABLE_ENV.items():
        val = os.getenv(env_key)
        if val is not None:
            overrides[layer_key] = {
                "env_var": env_key,
                "env_value": val,
                "overridden": val == "1",
                "effect": "disabled" if val == "1" else "no_override",
            }
    return overrides


# ==================== 规则过滤 ====================


def filter_enabled_rules(rules: list[dict], category_enabled: bool = True) -> list[dict]:
    """过滤出启用的规则"""
    if not category_enabled:
        return []
    return [r for r in rules if r.get("enabled", True)]


def _user_custom_rules(runtime: dict, layer: str, required_key: str) -> list[dict]:
    """取 ``<layer>.user_custom`` 里**形态匹配**的启用规则。

    为什么必须合并进生效规则集：Console「新增规则」的"所属分类"**默认就是
    「用户自定义」**（console/static/index.html 的 input-category 首个 option，
    且代码里 fallback 也是 user_custom），另外源码删整类时用户规则也会迁到这里
    保留（见 ``_merge_rule_categories`` 的清理段）。而引擎此前**完全不读这个分类**
    —— 于是在控制台新增的规则写进去之后判定毫无变化，且没有任何提示，属静默失效
    （2026-09 招行客户反馈"当前的规则我没办法追加"即此）。

    ``required_key`` 用于丢开形态不符的条目：user_custom 会混入从各类目迁移来的
    规则（可能是 path / intent_keywords 形态），直接当命令正则用会 KeyError。
    """
    cat = runtime.get(layer, {}).get("user_custom", {}) or {}
    rules = filter_enabled_rules(cat.get("rules", []), cat.get("category_enabled", True))
    out = []
    for r in rules:
        if not r.get(required_key):
            continue
        # risk_level 缺失时补 high：L1 只有 high/critical（及 medium+file_access）
        # 才短路 Deny，留空 = 规则写进去了却永远不拦（又一次静默失效）。
        # 语义与 AGENT_MOSS_CUSTOM_RULES 通道一致（那边是 rule.get("severity","high")）。
        if not r.get("risk_level"):
            r = {**r, "risk_level": "high"}
        out.append(r)
    return out


def _merge_user_custom(
    primary: list[dict], runtime: dict, layers, key: str,
) -> list[dict]:
    """把 user_custom 的启用规则**追加**到主规则集之后（内置在前，命中即短路，
    与 agent_ext 的追加约定一致）。

    ``layers`` 可为单层名字符串或元组：敏感路径在历史上归属过 L2（重分类后归 L1），
    老配置的 user_custom 可能留在任一层，两层都取才不会漏。
    """
    if isinstance(layers, str):
        layers = (layers,)
    extra: list[dict] = []
    for layer in layers:
        extra.extend(_user_custom_rules(runtime, layer, key))
    return list(primary) + extra if extra else list(primary)


#: 各类别条目的去重键（同键保留**先出现**的那条 → 优先级 override > extra > 内置）。
_DEDUP_KEYS: dict[str, tuple[str, ...]] = {
    "dangerous_commands": ("pattern",),
    "password_modify_consent": ("pattern",),
    "user_deletion_consent": ("pattern",),
    "sensitive_path_access": ("path",),
    "injection_detection": ("keyword", "lang"),
    "intent_consistency": ("intent_keywords", "reason"),
}


def _dedup(rules: list[dict], category: str) -> list[dict]:
    """按类别去重键去重，**保留先出现的**（调用方已按优先级排好序）。"""
    keys = _DEDUP_KEYS.get(category)
    if not keys:
        return rules
    seen: set[tuple] = set()
    out: list[dict] = []
    for r in rules:
        k = tuple(str(r.get(x, "")) for x in keys)
        if k in seen:
            continue
        seen.add(k)
        out.append(r)
    return out


def _merge_rules_from_dirs(primary: list[dict], category: str) -> list[dict]:
    """应用**规则目录**（ConfigMap）里该类别的 override.json / extra.json。

    语义（2026-10 与客户确认）：
      - ``override.json`` 出现了该类别 → **整份替换**内置（写空数组 = 明确清空该类）；
        未出现的类别保持内置；
      - ``extra.json`` 出现了该类别 → **追加**在（替换后的）规则之后；
      - 同一类别内按去重键去重，**先出现者优先**（override > extra > 内置）。

    与 user_custom 的区别：user_custom 是 Console 管理面（运行时逐条合并、热
    生效），规则目录是部署面（进程启动时从挂载目录整份加载）。
    rules_loader 不可用时静默跳过（不影响判定主流程）。
    """
    base = list(primary)
    try:
        from ..rules_loader import load_extra_rules, load_override_rules
        override = load_override_rules().get(category)
        if override is not None:
            base = list(override)
        extra = load_extra_rules().get(category) or []
    except Exception:  # noqa: BLE001 — 规则加载失败绝不能把判定打挂
        return base
    return _dedup(base + list(extra), category)


def get_enabled_l1_command_patterns(runtime: dict, os_type: str = "") -> list[dict]:
    cat = runtime.get("L1_rules", {}).get("dangerous_commands", {})
    rules = filter_enabled_rules(cat.get("rules", []), cat.get("category_enabled", True))
    rules = _merge_rules_from_dirs(rules, "dangerous_commands")
    rules = _merge_user_custom(rules, runtime, "L1_rules", "pattern")
    if os_type:
        rules = _rules_for_os(rules, os_type)   # 同敏感路径：防跨平台条目串台
    # ⚠️ 一律 .get：user_custom 条目由用户填，可能缺 risk_type/reason（Console 的
    # NewRule 这些字段可空），硬下标会 KeyError 把整次判定打成 500。
    return [{"pattern": r["pattern"], "risk_level": r.get("risk_level", ""),
             "risk_type": r.get("risk_type", ""), "reason": r.get("reason", "")} for r in rules]


def get_enabled_l1_injection_keywords(runtime: dict, os_type: str = "") -> list[dict]:
    cat = runtime.get("L1_rules", {}).get("injection_detection", {})
    rules = filter_enabled_rules(cat.get("rules", []), cat.get("category_enabled", True))
    rules = _merge_rules_from_dirs(rules, "injection_detection")
    rules = _merge_user_custom(rules, runtime, "L1_rules", "keyword")
    if os_type:
        rules = _rules_for_os(rules, os_type)
    return [{"keyword": r["keyword"], "risk_level": r.get("risk_level", ""),
             "lang": r.get("lang", "en")} for r in rules]


def _sensitive_path_category(runtime: dict) -> dict:
    """取敏感路径类别配置。

    优先读 L1_rules.sensitive_path_access（重分类后敏感路径归属 L1）；
    回退 L2_rules.sensitive_path_access（兼容迁移前的老配置）。
    """
    cat = runtime.get("L1_rules", {}).get("sensitive_path_access", {})
    if not cat.get("rules"):
        # 老配置未迁移：回退 L2_rules
        cat = runtime.get("L2_rules", {}).get("sensitive_path_access", {})
    return cat


def get_enabled_l2_sensitive_paths(runtime: dict, os_type: str = "") -> list[dict]:
    """读取启用的敏感路径规则（os_type 非空时按平台过滤）。

    函数名保留 l2 前缀仅为向后兼容，实际数据源已迁至 L1。

    **必须传 os_type**：runtime 配置含全平台条目（Console 需要展示各平台），
    不过滤会把 Windows 的 .ssh 或 C:/Windows/... 混进 Linux 判定 —— 表现为
    "在 Console 禁用某平台规则后该平台判定仍生效"（实际生效的是别平台的同名条目）。
    """
    cat = _sensitive_path_category(runtime)
    rules = filter_enabled_rules(cat.get("rules", []), cat.get("category_enabled", True))
    # 敏感路径历史归属过 L2（重分类后归 L1），老配置的 user_custom 可能留在任一层
    rules = _merge_rules_from_dirs(rules, "sensitive_path_access")
    rules = _merge_user_custom(rules, runtime, ("L1_rules", "L2_rules"), "path")
    if os_type:
        rules = _rules_for_os(rules, os_type)
    out = []
    for r in rules:
        item = {"path": r["path"], "risk_level": r.get("risk_level", ""),
                "desc": r.get("desc", ""),
                "deny_mode": r.get("deny_mode", _derive_deny_mode(r))}
        if r.get("credential"):
            item["credential"] = True
        if r.get("read_only"):
            item["read_only"] = True
        if r.get("dir_del_only"):
            item["dir_del_only"] = True
        out.append(item)
    return out


def get_enabled_l2_intent_patterns(runtime: dict, os_type: str = "") -> list[dict]:
    cat = runtime.get("L2_rules", {}).get("intent_consistency", {})
    rules = filter_enabled_rules(cat.get("rules", []), cat.get("category_enabled", True))
    rules = _merge_rules_from_dirs(rules, "intent_consistency")
    rules = _merge_user_custom(rules, runtime, "L2_rules", "intent_keywords")
    if os_type:
        rules = _rules_for_os(rules, os_type)
    return [{"intent_keywords": r["intent_keywords"],
             "dangerous_actions": r.get("dangerous_actions", []),
             "reason": r.get("reason", "")} for r in rules]


def get_enabled_l2_password_patterns(runtime: dict) -> list[str]:
    cat = runtime.get("L2_rules", {}).get("password_modify_consent", {})
    rules = filter_enabled_rules(cat.get("rules", []), cat.get("category_enabled", True))
    rules = _merge_rules_from_dirs(rules, "password_modify_consent")
    rules = _merge_user_custom(rules, runtime, "L2_rules", "pattern")
    return [r["pattern"] for r in rules]


def get_enabled_l2_user_deletion_patterns(runtime: dict) -> list[str]:
    cat = runtime.get("L2_rules", {}).get("user_deletion_consent", {})
    rules = filter_enabled_rules(cat.get("rules", []), cat.get("category_enabled", True))
    rules = _merge_rules_from_dirs(rules, "user_deletion_consent")
    rules = _merge_user_custom(rules, runtime, "L2_rules", "pattern")
    return [r["pattern"] for r in rules]


def is_l2_category_enabled(runtime: dict, category_key: str) -> bool:
    cat = runtime.get("L2_rules", {}).get(category_key, {})
    return cat.get("category_enabled", True)


#: has_runtime_config 的结果缓存：与 _RUNTIME_CONFIG_CACHE 同款文件指纹键。
#: 历史实现**每次调用都整份读 + json.loads**（runtime JSON 近百 KB，实测 ~4ms），
#: 而单次 analyze 会调它 5~6 次（rules_loader.load_mc / skill_engine.match_skills /
#: config 构建 / 各 *_or_default）—— 纯浪费 20ms+。文件改动后 mtime/size 变化即失效，
#: 「热生效」语义不变。
_HAS_RUNTIME_CONFIG_CACHE: dict[tuple[str, int, int], bool] = {}


def has_runtime_config() -> bool:
    """判断用户本地 runtime 配置文件是否存在且可正常读取。

    区分：文件不存在→从未配置，应用源码默认；文件存在但规则空→用户主动禁用，不回退。
    结果按文件指纹缓存（见 `_HAS_RUNTIME_CONFIG_CACHE`）。

    cold / builtin 模式下恒为 False —— **不 stat、不读**用户配置文件，文件存在等于不存在。
    """
    if is_runtime_config_disabled():
        return False
    config_path = get_runtime_config_path()
    try:
        st = config_path.stat()
    except OSError:
        return False
    key = (str(config_path), st.st_mtime_ns, st.st_size)
    cached = _HAS_RUNTIME_CONFIG_CACHE.get(key)
    if cached is not None:
        return cached
    try:
        json.loads(config_path.read_text(encoding="utf-8"))
        ok = True
    except (json.JSONDecodeError, OSError):
        ok = False
    _HAS_RUNTIME_CONFIG_CACHE[key] = ok
    return ok


def get_disabled_skill_ids(runtime: dict) -> set[str]:
    """所有被禁用的 skill id（整分类禁用→该分类所有 skill，或单条 enabled=False）"""
    disabled = set()
    for cat_data in runtime.get("L3_skills", {}).values():
        if not cat_data.get("category_enabled", True):
            for s in cat_data.get("skills", []):
                disabled.add(s["id"])
        else:
            for s in cat_data.get("skills", []):
                if not s.get("enabled", True):
                    disabled.add(s["id"])
    return disabled


# ==================== _or_default 回退系列 ====================
# 仅在无 runtime config 文件时才回退到 profile/模块默认值；文件存在但规则为空
# 表示用户主动禁用，不回退。


def get_enabled_l1_command_patterns_or_default(
    runtime: dict, os_type: str = "",
) -> list[dict]:
    """读取生效的危险命令规则：runtime 覆盖 > profile 默认（按平台隔离）。

    平台隔离语义与 get_enabled_l2_sensitive_paths_or_default 一致：该平台在
    runtime 里无条目时回退该平台 profile 默认，避免 Windows 部署沿用 Linux 规则。
    """
    os_type = normalize_os_type(os_type)
    if _rules_for_os(_category_rules(runtime, "L1_rules", "dangerous_commands"), os_type):
        return get_enabled_l1_command_patterns(runtime, os_type)
    # 回退 profile 默认时**同样要带上**追加目录与 user_custom —— 否则"runtime 里
    # 该平台无内置条目"的部署上，部署面/管理面的自定义规则会被这条回退分支悄悄丢掉。
    return _merge_user_custom(
        _merge_rules_from_dirs(
            _l1_command_patterns_to_rules(get_profile_by_os(os_type)),
            "dangerous_commands",
        ),
        runtime, "L1_rules", "pattern",
    )


def get_enabled_l1_injection_keywords_or_default(
    runtime: dict, os_type: str = "",
) -> list[dict]:
    """读取生效的注入检测关键词：runtime 覆盖 > profile 默认（按平台隔离）。"""
    os_type = normalize_os_type(os_type)
    if _rules_for_os(_category_rules(runtime, "L1_rules", "injection_detection"), os_type):
        return get_enabled_l1_injection_keywords(runtime, os_type)
    return _merge_user_custom(
        _merge_rules_from_dirs(
            _l1_injection_keywords_to_rules(get_profile_by_os(os_type)),
            "injection_detection",
        ),
        runtime, "L1_rules", "keyword",
    )


def get_enabled_l2_sensitive_paths_or_default(
    runtime: dict, os_type: str = "",
) -> list[dict]:
    """读取生效的敏感路径规则：runtime 覆盖 > profile 默认。

    runtime 覆盖按 os_type 隔离：
    - 该平台在 runtime 里有条目（含 enabled=false 的）→ 用 runtime 结果，
      尊重 enabled 开关；全被禁用则返回空（用户主动禁用，不回退）
    - 该平台在 runtime 里没有任何条目 → 回退该平台 profile 的默认规则。
      典型场景：在 Linux 环境生成的配置里没有 Windows 条目，Windows 部署
      必须回退到 WindowsProfile，否则一条规则都不生效。
    """
    os_type = normalize_os_type(os_type)
    cat = _sensitive_path_category(runtime)
    if _rules_for_os(cat.get("rules", []), os_type):
        return get_enabled_l2_sensitive_paths(runtime, os_type)
    return _merge_user_custom(
        _merge_rules_from_dirs(
            _l2_sensitive_paths_to_rules(get_profile_by_os(os_type)),
            "sensitive_path_access",
        ),
        runtime, ("L1_rules", "L2_rules"), "path",
    )


def get_enabled_l2_intent_patterns_or_default(
    runtime: dict, os_type: str = "",
) -> list[dict]:
    """读取生效的意图一致性规则：runtime 覆盖 > profile 默认（按平台隔离）。

    意图模式含平台特有动作词（Windows 的 del/rmdir/reg delete），必须与所属
    profile 一致，否则 Windows 上会拿 Linux 的动作词做误判。
    """
    os_type = normalize_os_type(os_type)
    if _rules_for_os(_category_rules(runtime, "L2_rules", "intent_consistency"), os_type):
        return get_enabled_l2_intent_patterns(runtime, os_type)
    return _merge_user_custom(
        _merge_rules_from_dirs(
            _l2_intent_patterns_to_rules(get_profile_by_os(os_type)),
            "intent_consistency",
        ),
        runtime, "L2_rules", "intent_keywords",
    )


def get_enabled_l2_password_patterns_or_default(runtime: dict) -> list[str]:
    enabled = get_enabled_l2_password_patterns(runtime)
    if enabled:
        return enabled
    if not has_runtime_config():
        from ..engine.logic_rules import PASSWORD_MODIFY_PATTERNS
        return list(PASSWORD_MODIFY_PATTERNS)
    return []


def get_enabled_l2_user_deletion_patterns_or_default(runtime: dict) -> list[str]:
    enabled = get_enabled_l2_user_deletion_patterns(runtime)
    if enabled:
        return enabled
    if not has_runtime_config():
        from ..engine.logic_rules import USER_DELETION_PATTERNS
        return list(USER_DELETION_PATTERNS)
    return []


def get_profile_or_detect():
    """获取当前 OS Profile（延迟导入，避免循环依赖）"""
    from ..profiles import get_profile
    return get_profile()


def get_profile_by_os(os_type: str):
    """按 os_type 获取对应 OS Profile（延迟导入，避免循环依赖）"""
    from ..profiles import get_profile
    return get_profile(os_type)


def normalize_os_type(os_type: str = "") -> str:
    """归一化 os_type：空值时按当前运行环境检测。

    与 ``profiles.get_profile`` 的判定口径一致（非 windows 一律视为 linux），
    避免同一进程内 "profile 选了 Windows、runtime 过滤按 linux" 的分裂。
    """
    if os_type:
        return os_type.strip().lower()
    import platform
    return "windows" if platform.system().lower() == "windows" else "linux"


def _accepted_os_values(os_type: str = "") -> tuple[str, ...]:
    """该平台接受的条目 os 值（与 ``OSProfile.accepted_os`` 同一口径）。

    - windows：只接受 {windows}
    - macos：接受 {linux, macos} —— 继承 Linux 通用规则 + macOS 专属补充
    - harmony：接受 {linux, harmony} —— Toybox 类 Unix，继承 Linux + 鸿蒙专属
    - linux / 未知名：只接受 {linux}
    """
    t = normalize_os_type(os_type)
    if t == "windows":
        return ("windows",)
    if t == "macos":
        return ("linux", "macos")
    if t == "harmony":
        return ("linux", "harmony")
    return ("linux",)


def _rules_for_os(rules: list[dict], os_type: str) -> list[dict]:
    """筛选属于指定操作系统的规则条目（按该平台的 accepted_os 语义）。

    与 ``OSProfile.accepted_os`` 对齐：macOS 会拿到 Linux 通用条目 + macOS 专属
    条目（继承语义），Windows 只拿 windows 条目，linux 只拿 linux 条目。

    不带 ``os`` 字段的历史条目一律视为 linux —— 既保证老配置兼容，也保证
    Windows 部署不会误用 Linux 条目（被过滤后调用方回退 WindowsProfile 默认）。

    ``"all"`` = **全平台通用**，各平台都生效。目前用于 ``injection_detection``：
    注入攻击与操作系统无关，同一套关键词三平台共用。此前那批关键词被标成
    ``linux``，于是 Windows 按 os 过滤后**一条不剩**、静默回退到 ``WindowsProfile``
    里一份只有 14 条的历史副本，而 TS 端回退时不带平台过滤（拿全 48 条）——
    两端在 Windows 上双向分叉（`DAN mode` 与 `绕过审计` 各有一端漏报，2026-10 修）。
    """
    accepted = _accepted_os_values(os_type)
    out: list[dict] = []
    for r in rules:
        v = str(r.get("os") or "linux").lower()
        if v == "all" or v in accepted:
            out.append(r)
    return out


def _category_rules(runtime: dict, layer: str, category: str) -> list[dict]:
    """取 runtime 中某层某类别的规则原始列表（不看 enabled）。"""
    return runtime.get(layer, {}).get(category, {}).get("rules", [])


def get_disabled_l2_rules_with_skip_l3() -> dict[str, list[str]]:
    """获取所有 enabled=False 且 skip_l3_on_disabled=True 的规则关键内容。

    敏感路径已重分类到 L1，故遍历 L1_rules + L2_rules 两层。
    函数名保留 l2 前缀仅为向后兼容。

    Returns:
        dict: 按类别分组
            - sensitive_path_access: path 列表
            - intent_consistency: intent_keywords 列表
            - 其他: pattern 列表
    """
    runtime = load_runtime_config()
    result: dict[str, list[str]] = {}
    for layer_key in ("L1_rules", "L2_rules"):
        for cat_name, cat in runtime.get(layer_key, {}).items():
            if not cat.get("category_enabled", True):
                continue
            items = []
            for r in cat.get("rules", []):
                if not r.get("enabled", True) and r.get("skip_l3_on_disabled", False):
                    if cat_name == "sensitive_path_access":
                        items.append(r.get("path", ""))
                    elif cat_name == "intent_consistency":
                        items.extend(r.get("intent_keywords", []))
                    elif r.get("pattern"):
                        items.append(r["pattern"])
            if items:
                result[cat_name] = items
    return result


# ==================== 配置写入（供 console API 使用） ====================


def update_layer_enabled(layer_key: str, enabled: bool) -> dict:
    """更新层级开关并保存。同时失效引擎默认配置缓存，使 console toggle 立即生效。"""
    runtime = load_runtime_config()
    runtime["layers"][layer_key] = enabled
    save_runtime_config(runtime)
    try:
        from .config import invalidate_default_config_cache
        invalidate_default_config_cache()
    except Exception:
        pass
    return runtime


def _apply_rule_enabled(rule: dict, enabled: bool) -> None:
    """设置规则的启用状态，并记录「这是用户主动改的」（user_disabled 标记）。

    为什么要标记：merge 时若源码里仍有这条内置规则，**无法区分** existing 的
    `enabled=False` 是「用户在 Console 主动禁用」还是「历史污染 / 系统自动禁用」。
    不标记就只能无条件沿用旧值 → 一次污染永久锁死：源码里规则一直都在，merge 一百次
    也救不回来，用户只能手动删 runtime 文件才能恢复（2026-09 用户实测反复踩到）。

    打标记后：**无标记的 False 会在下次 merge 自动痊愈为启用**，有标记的才尊重用户选择。
    """
    rule["enabled"] = enabled
    if enabled:
        # 重新启用 = "用户禁用过它"这句话不再成立 → 清掉标记（只清标记，不删规则）
        rule.pop("user_disabled", None)
    else:
        rule["user_disabled"] = True


def update_rule_enabled(layer: str, category: str, rule_id: str, enabled: bool) -> dict:
    runtime = load_runtime_config()
    for r in runtime.get(layer, {}).get(category, {}).get("rules", []):
        if r.get("id") == rule_id:
            _apply_rule_enabled(r, enabled)
            break
    save_runtime_config(runtime)
    return runtime


def update_rule_deny_mode(layer: str, category: str, rule_id: str, deny_mode: str) -> dict:
    runtime = load_runtime_config()
    for r in runtime.get(layer, {}).get(category, {}).get("rules", []):
        if r.get("id") == rule_id:
            r["deny_mode"] = deny_mode
            _sync_deny_mode_fields(r)
            break
    save_runtime_config(runtime)
    return runtime


def update_rule_skip_l3(layer: str, category: str, rule_id: str, skip_l3_on_disabled: bool) -> dict:
    runtime = load_runtime_config()
    for r in runtime.get(layer, {}).get(category, {}).get("rules", []):
        if r.get("id") == rule_id:
            r["skip_l3_on_disabled"] = skip_l3_on_disabled
            break
    save_runtime_config(runtime)
    return runtime


def update_category_enabled(layer: str, category: str, enabled: bool) -> dict:
    runtime = load_runtime_config()
    runtime.get(layer, {}).get(category, {})["category_enabled"] = enabled
    save_runtime_config(runtime)
    return runtime


def add_custom_rule(layer: str, category: str, rule: dict) -> dict:
    """新增自定义规则并保存。builtin=False, enabled=True，自动生成 id。"""
    import time
    runtime = load_runtime_config()
    rules = runtime.setdefault(layer, {}).setdefault(category, {}).setdefault("rules", [])
    rule = dict(rule)
    rule["builtin"] = False
    rule["enabled"] = True
    if not rule.get("id"):
        rule["id"] = f"custom_{int(time.time())}_{_slugify(str(rule)[:30])}"
    if "deny_mode" in rule:
        _sync_deny_mode_fields(rule)
    rules.append(rule)
    save_runtime_config(runtime)
    return runtime


def _delete_rule_from_rules(rules: list, rule_id: str) -> list | None:
    """从 rules 里选一条「可删」的规则并就地移除。返回 None 表示拒绝（命中但无可删项）。

    可删 = builtin=False（用户自定义）或 source_removed=True（源码已删除的历史保留）。
    同 id 多命中（历史撞车）时优先删可删项；仅当命中的全是活跃 builtin 才返回 None。
    """
    for i, r in enumerate(rules):
        if r.get("id") == rule_id and (
            not r.get("builtin", True) or r.get("source_removed", False)
        ):
            rules.pop(i)
            return rules
    if any(r.get("id") == rule_id for r in rules):
        return None  # 命中了同 id 的活跃 builtin → 拒绝
    return rules  # 未命中，无操作


def delete_custom_rule(layer: str, category: str, rule_id: str) -> dict | None:
    """删除规则。

    允许删除：用户自定义规则（builtin=False）+ 已从默认规则集移除的规则
    （builtin=True 但 source_removed=True，这些是源码新版本删掉、仅作历史保留的，
    用户可在 console 清理）。活跃的 builtin 规则不允许删除（应改 enabled 开关）。
    """
    runtime = load_runtime_config()
    rules = runtime.get(layer, {}).get(category, {}).get("rules", [])
    if _delete_rule_from_rules(rules, rule_id) is None:
        return None
    save_runtime_config(runtime)
    return runtime


def _validate_skill_id(skill_id: str) -> None:
    """校验 skill_id：只允许字母数字下划线连字符，禁止路径穿越"""
    if not skill_id or not _SKILL_ID_RE.match(skill_id):
        raise ValueError(
            f"skill_id '{skill_id}' 不合法：只允许字母、数字、下划线和连字符，禁止路径穿越字符"
        )


def add_custom_skill(skill_id: str, category: str, keywords: list[str], content: str) -> dict:
    """新增自定义 skill：写入 markdown 文件 + 更新 runtime JSON。

    自定义 skill 文件写入用户目录 ~/.config/agentmoss/agent_moss_skills/。
    """
    _validate_skill_id(skill_id)
    if is_runtime_config_disabled():
        raise RuntimeConfigReadOnlyError(
            f"规则来源模式为 {get_rules_mode()}（runtime 配置已禁用），不允许新增自定义 skill。"
        )
    runtime = load_runtime_config()
    skills_dir = _runtime_dir() / "agent_moss_skills"
    skills_dir.mkdir(parents=True, exist_ok=True)
    (skills_dir / f"{skill_id}.md").write_text(content, encoding="utf-8")
    cat_skills = runtime.setdefault("L3_skills", {}).setdefault(category, {}).setdefault("skills", [])
    cat_skills.append({"id": skill_id, "keywords": keywords, "enabled": True, "builtin": False})
    save_runtime_config(runtime)
    return runtime


def delete_custom_skill(skill_id: str, category: str) -> dict | None:
    """删除自定义 skill（builtin=True 不允许删除）"""
    _validate_skill_id(skill_id)
    runtime = load_runtime_config()
    cat_skills = runtime.get("L3_skills", {}).get(category, {}).get("skills", [])
    target = None
    for s in cat_skills:
        if s.get("id") == skill_id:
            if s.get("builtin", True):
                return None
            target = s
            break
    if target:
        cat_skills.remove(target)
        skill_path = _runtime_dir() / "agent_moss_skills" / f"{skill_id}.md"
        if skill_path.exists():
            skill_path.unlink()
        save_runtime_config(runtime)
    return runtime


def update_skill_enabled(skill_id: str, enabled: bool) -> dict:
    runtime = load_runtime_config()
    for cat_data in runtime.get("L3_skills", {}).values():
        for s in cat_data.get("skills", []):
            if s.get("id") == skill_id:
                s["enabled"] = enabled
                break
    save_runtime_config(runtime)
    return runtime


def update_skill_category_enabled(category: str, enabled: bool) -> dict:
    runtime = load_runtime_config()
    runtime.get("L3_skills", {}).get(category, {})["category_enabled"] = enabled
    save_runtime_config(runtime)
    return runtime


# ==================== agent 定制规则（runtime_config 统一治理）====================


def get_agent_rules(runtime: dict) -> dict:
    """返回 runtime_config 的 agent_rules 分区（含 enabled 状态，供 console 展示）。"""
    return runtime.get("agent_rules", {})


def _agent_category_enabled_rules(cat: dict) -> list:
    """单个 agent 类别中 enabled=True 的规则（category_enabled 也为 True 时）。"""
    if not cat.get("category_enabled", True):
        return []
    return [r for r in cat.get("rules", []) if r.get("enabled", True)]


def get_enabled_agent_extensions(runtime: dict, agent_id: str):
    """从 runtime_config 的 agent_rules[agent_id] 构造 AgentExtensions（应用 enabled 过滤）。

    供 get_agent_extensions 在 has_runtime_config() 时调用：返回的 AgentExtensions
    与从 rules.json 加载的形态一致，coordinator 消费侧无需改动。
    builtin_safe_action_types/skills 过滤 enabled 后展平回 string[]。

    无该 agent_id 分区时返回 None（回退到 rules.json）。
    """
    agent_data = runtime.get("agent_rules", {}).get(agent_id)
    if not agent_data:
        return None
    from ..agents.base import AgentExtensions, InjectionKeyword
    from ..profiles.base import CommandPattern, SensitivePath

    cats = agent_data
    safe_action = _agent_category_enabled_rules(
        cats.get("builtin_safe_action_types", {}))
    safe_skills = _agent_category_enabled_rules(
        cats.get("builtin_safe_skills", {}))
    cmd_patterns = [
        CommandPattern(pattern=r["pattern"], risk_level=r["risk_level"],
                       risk_type=r["risk_type"], reason=r.get("reason", ""))
        for r in _agent_category_enabled_rules(cats.get("extra_command_patterns", {}))
        if "pattern" in r
    ]
    inj_keywords = [
        InjectionKeyword(keyword=k["keyword"], risk_level=k["risk_level"],
                         lang=k.get("lang", "en"))
        for k in _agent_category_enabled_rules(cats.get("extra_injection_keywords", {}))
        if "keyword" in k
    ]
    sensitive_paths = [
        SensitivePath(path=sp["path"], risk_level=sp["risk_level"],
                      desc=sp.get("desc", ""), credential=sp.get("credential", False),
                      read_only=sp.get("read_only", False),
                      deny_mode=sp.get("deny_mode", ""))
        for sp in _agent_category_enabled_rules(cats.get("extra_sensitive_paths", {}))
        if "path" in sp
    ]
    return AgentExtensions(
        agent_id=agent_id,
        description="",
        extra_command_patterns=cmd_patterns,
        extra_injection_keywords=inj_keywords,
        extra_sensitive_paths=sensitive_paths,
        builtin_safe_skills=[s["value"] for s in safe_skills if "value" in s],
        builtin_safe_action_types=[a["value"] for a in safe_action if "value" in a],
        extra_skills=[],
    )


def update_agent_rule_enabled(agent_id: str, category: str, rule_fp: dict,
                              enabled: bool) -> dict:
    """切换某 agent 某条规则的 enabled。rule_fp 用于定位条目（value/pattern/path/keyword）。"""
    runtime = load_runtime_config()
    agent = runtime.get("agent_rules", {}).get(agent_id, {})
    cat = agent.get(category, {})
    target_fp = _rule_fingerprint(rule_fp)
    for r in cat.get("rules", []):
        if _rule_fingerprint(r) == target_fp:
            _apply_rule_enabled(r, enabled)
            break
    save_runtime_config(runtime)
    return runtime


def add_agent_rule(agent_id: str, category: str, rule: dict) -> dict:
    """向某 agent 的某类别新增规则条目。"""
    runtime = load_runtime_config()
    agent_rules = runtime.setdefault("agent_rules", {})
    if agent_id not in agent_rules:
        agent_rules[agent_id] = {}
    cat = agent_rules[agent_id].setdefault(
        category, {"category_enabled": True, "category_desc": "", "rules": []})
    cat.setdefault("rules", []).append({**rule, "enabled": True, "builtin": False})
    save_runtime_config(runtime)
    return runtime


def delete_agent_rule(agent_id: str, category: str, rule_fp: dict) -> dict:
    """删除某 agent 某条规则。"""
    runtime = load_runtime_config()
    agent = runtime.get("agent_rules", {}).get(agent_id, {})
    cat = agent.get(category, {})
    target_fp = _rule_fingerprint(rule_fp)
    cat["rules"] = [r for r in cat.get("rules", []) if _rule_fingerprint(r) != target_fp]
    save_runtime_config(runtime)
    return runtime


def update_agent_category_enabled(agent_id: str, category: str, enabled: bool) -> dict:
    """切换某 agent 某类别的 category_enabled（整类开关，与通用规则的分类开关同范式）。"""
    runtime = load_runtime_config()
    cat = runtime.get("agent_rules", {}).get(agent_id, {}).get(category, {})
    cat["category_enabled"] = enabled
    save_runtime_config(runtime)
    return runtime


# ==================== 场景定制规则（scenario_rules 分区，与 agent_rules 同构）====================


def get_scenario_rules(runtime: dict) -> dict:
    """返回 runtime_config 的 scenario_rules 分区（含 enabled 状态，供 console 展示）。"""
    return runtime.get("scenario_rules", {})


def get_enabled_scenario_extensions(runtime: dict, scenario_id: str):
    """从 runtime_config 的 scenario_rules[scenario_id] 构造 AgentExtensions（应用 enabled 过滤）。

    供 get_scenario_extensions 在 has_runtime_config() 时调用，与 agent 版
    get_enabled_agent_extensions 同构（场景规则也是 AgentExtensions 结构）。
    无该 scenario_id 分区时返回 None（回退到 rules.json）。
    """
    scen_data = runtime.get("scenario_rules", {}).get(scenario_id)
    if not scen_data:
        return None
    from ..agents.base import AgentExtensions, InjectionKeyword
    from ..profiles.base import CommandPattern, SensitivePath

    cats = scen_data
    cmd_patterns = [
        CommandPattern(pattern=r["pattern"], risk_level=r["risk_level"],
                       risk_type=r["risk_type"], reason=r.get("reason", ""))
        for r in _agent_category_enabled_rules(cats.get("extra_command_patterns", {}))
        if "pattern" in r
    ]
    inj_keywords = [
        InjectionKeyword(keyword=k["keyword"], risk_level=k["risk_level"],
                         lang=k.get("lang", "en"))
        for k in _agent_category_enabled_rules(cats.get("extra_injection_keywords", {}))
        if "keyword" in k
    ]
    sensitive_paths = [
        SensitivePath(path=sp["path"], risk_level=sp["risk_level"],
                      desc=sp.get("desc", ""), credential=sp.get("credential", False),
                      read_only=sp.get("read_only", False),
                      deny_mode=sp.get("deny_mode", ""))
        for sp in _agent_category_enabled_rules(cats.get("extra_sensitive_paths", {}))
        if "path" in sp
    ]
    return AgentExtensions(
        agent_id=scenario_id,
        description="",
        extra_command_patterns=cmd_patterns,
        extra_injection_keywords=inj_keywords,
        extra_sensitive_paths=sensitive_paths,
        builtin_safe_skills=[],
        builtin_safe_action_types=[],
        extra_skills=[],
    )


def update_scenario_rule_enabled(scenario_id: str, category: str, rule_fp: dict,
                                 enabled: bool) -> dict:
    """切换某场景某条规则的 enabled（定位规则用 rule_fp 的 pattern/keyword/path/value）。"""
    runtime = load_runtime_config()
    scen = runtime.get("scenario_rules", {}).get(scenario_id, {})
    cat = scen.get(category, {})
    target_fp = _rule_fingerprint(rule_fp)
    for r in cat.get("rules", []):
        if _rule_fingerprint(r) == target_fp:
            _apply_rule_enabled(r, enabled)
            break
    save_runtime_config(runtime)
    return runtime


def add_scenario_rule(scenario_id: str, category: str, rule: dict) -> dict:
    """向某场景的某类别新增规则条目。"""
    runtime = load_runtime_config()
    scen_rules = runtime.setdefault("scenario_rules", {})
    if scenario_id not in scen_rules:
        scen_rules[scenario_id] = {}
    cat = scen_rules[scenario_id].setdefault(
        category, {"category_enabled": True, "category_desc": "", "rules": []})
    cat.setdefault("rules", []).append({**rule, "enabled": True, "builtin": False})
    save_runtime_config(runtime)
    return runtime


def delete_scenario_rule(scenario_id: str, category: str, rule_fp: dict) -> dict:
    """删除某场景某条规则。"""
    runtime = load_runtime_config()
    scen = runtime.get("scenario_rules", {}).get(scenario_id, {})
    cat = scen.get(category, {})
    target_fp = _rule_fingerprint(rule_fp)
    cat["rules"] = [r for r in cat.get("rules", []) if _rule_fingerprint(r) != target_fp]
    save_runtime_config(runtime)
    return runtime


def update_scenario_category_enabled(scenario_id: str, category: str, enabled: bool) -> dict:
    """切换某场景某类别的 category_enabled（整类开关）。"""
    runtime = load_runtime_config()
    cat = runtime.get("scenario_rules", {}).get(scenario_id, {}).get(category, {})
    cat["category_enabled"] = enabled
    save_runtime_config(runtime)
    return runtime


def _ltl_rules_to_runtime() -> dict:
    """mc_rules.json 的 LTL 规则 → L2_2 分区（每条含 enabled，出厂默认全开）。

    L2.2 模型检测规则的运行时开关落点：console 可逐条启停，引擎经
    rules_loader.load_mc() 合并（按 id 覆盖 enabled）后读取。

    ⚠️ 必须**直接读 mc_rules.json 文件**，不能走 rules_loader.load_mc()——
    load_mc() 内部又调 load_runtime_config()，会与 generate_source_defaults()
    形成互相递归（每次 1.7s+）。此处只取"出厂规则清单"，不带开关。

    路径解析：2026-10 起规则目录只认 override.json / extra.json（不再支持
    "按内置文件名覆盖"），故此处直接读包内 mc_rules.json —— 与
    ``rules_loader.load_mc()`` 同一份数据，只是绕开它的 runtime 递归。
    """
    try:
        # 用 ``load_mc_raw()``：它应用规则目录的 override/extra（ltl_rules）但**不碰 runtime**，
        # 因此不会与 generate_source_defaults 互相递归；且与引擎 load_mc() 读**同一份**数据
        # （历史 bug：这里读内置文件，用户覆盖了 LTL 规则时引擎与种子清单脱节）。
        from ..rules_loader import load_mc_raw
        mc = load_mc_raw()
    except Exception:
        return {"category_enabled": True, "category_desc": "LTL 攻击模式规则", "rules": []}
    return {
        "ltl_rules": {
        "category_enabled": True,
        "category_desc": "LTL 攻击模式规则（时序攻击检测，先 A 后 B）",
        "rules": [
            {
                "id": r.get("id"),
                "reason": r.get("reason", ""),
                "risk_level": r.get("risk_level", "high"),
                "action": r.get("action", "block"),
                "enabled": True,
                "builtin": True,
            }
            for r in (mc.get("rules", []) or [])
        ],
        },
    }
