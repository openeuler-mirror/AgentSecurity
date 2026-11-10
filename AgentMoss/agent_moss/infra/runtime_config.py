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

logger = logging.getLogger(__name__)

ENV_RUNTIME_CONFIG_PATH = "AGENT_MOSS_RUNTIME_CONFIG_PATH"


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
        })
    return rules


def _l1_injection_keywords_to_rules(profile) -> list[dict]:
    """profile.injection_keywords (list[dict{keyword,risk_level,lang}]) → rules"""
    rules = []
    for kw in profile.injection_keywords:
        keyword = kw["keyword"]
        lang = kw.get("lang", "en")
        rules.append({
            "id": f"inj_{_slugify(keyword)}",
            "keyword": keyword,
            "risk_level": kw["risk_level"],
            "lang": lang,
            "enabled": True,
            "builtin": True,
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
        rule = {
            "id": f"path_{_slugify(sp.path)}",
            "path": sp.path,
            "risk_level": sp.risk_level,
            "desc": sp.desc,
            "deny_mode": deny_mode,
            "source_deny_mode": deny_mode,
            "skip_l3_on_disabled": True,
            "enabled": True,
            "builtin": True,
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
        rules.append({
            "id": f"intent_{i+1}_{_slugify(pat.reason[:30])}",
            "intent_keywords": pat.intent_keywords,
            "dangerous_actions": pat.dangerous_actions,
            "reason": pat.reason,
            "skip_l3_on_disabled": True,
            "enabled": True,
            "builtin": True,
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
        from ..agents import _AGENTS_DIR
    except Exception:
        return {}
    if not _AGENTS_DIR.exists():
        return {}
    out = {}
    for agent_dir in sorted(_AGENTS_DIR.iterdir()):
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
    """
    try:
        from ..scenarios import _SCENARIOS_DIR
    except Exception:
        return {}
    if not _SCENARIOS_DIR.exists():
        return {}
    out = {}
    for scen_dir in sorted(_SCENARIOS_DIR.iterdir()):
        rules_file = scen_dir / "rules.json"
        if not rules_file.is_file():
            continue
        scenario_id = scen_dir.name
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
        profile: OSProfile 实例。为 None 时调用 ..profiles.get_profile() 自动检测。
    """
    if profile is None:
        from ..profiles import get_profile
        profile = get_profile()
    return {
        "version": 1,
        "layers": dict(DEFAULT_LAYERS),
        "L1_rules": {
            "dangerous_commands": {
                "category_enabled": True,
                "category_desc": "危险命令检测（递归删除、全权限设置、提权执行等）",
                "rules": _l1_command_patterns_to_rules(profile),
            },
            "injection_detection": {
                "category_enabled": True,
                "category_desc": "Prompt 注入攻击检测",
                "rules": _l1_injection_keywords_to_rules(profile),
            },
            "sensitive_path_access": {
                "category_enabled": True,
                "category_desc": "敏感路径访问检测（deny_both/deny_read/deny_write）",
                "rules": _l2_sensitive_paths_to_rules(profile),
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
                "category_desc": "意图一致性检测",
                "rules": _l2_intent_patterns_to_rules(profile),
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
    """
    env_path = os.getenv(ENV_RUNTIME_CONFIG_PATH)
    if env_path:
        return Path(env_path)
    from .config import get_agent_moss_setting
    settings_path = get_agent_moss_setting(ENV_RUNTIME_CONFIG_PATH, "")
    if settings_path:
        return Path(settings_path)
    return RUNTIME_CONFIG_PATH


def save_runtime_config(config: dict) -> None:
    """保存运行时配置到用户本地文件"""
    config_path = get_runtime_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("配置已保存: %s", config_path)


def load_runtime_config() -> dict:
    """加载运行时配置：缺失则从种子生成并写入，已有则合并新出厂规则。"""
    config_path = get_runtime_config_path()
    if not config_path.exists():
        defaults = generate_source_defaults()
        config_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            config_path.write_text(json.dumps(defaults, indent=2, ensure_ascii=False), encoding="utf-8")
            logger.info("首次运行，已生成默认配置: %s", config_path)
        except OSError as e:
            logger.warning("无法写入配置文件 %s: %s，使用内存默认值", config_path, e)
        return defaults
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
            config_path.write_text(json.dumps(merged, indent=2, ensure_ascii=False), encoding="utf-8")
            logger.info("配置已合并更新: %s", config_path)
        except OSError as e:
            logger.warning("无法写入合并后的配置: %s", e)
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
    """规则内容指纹（跨 id 变更识别同一规则）。"""
    if rule.get("intent_keywords") or rule.get("dangerous_actions"):
        return (tuple(sorted(rule.get("intent_keywords", []))),
                tuple(sorted(rule.get("dangerous_actions", []))))
    if rule.get("path"):
        return (_normalize_pattern_for_fingerprint(rule["path"]),)
    if rule.get("pattern"):
        return (_normalize_pattern_for_fingerprint(rule["pattern"]),)
    if rule.get("keyword"):
        return (rule["keyword"], rule.get("lang", ""))
    # builtin_safe_action_types / builtin_safe_skills 项用 value 字段
    if rule.get("value"):
        return (rule["value"],)
    return (rule.get("id", ""),)


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
                user_enabled = existing.get("enabled", True)
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
                existing["enabled"] = user_enabled
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
                    user_enabled = existing.get("enabled", True)
                    existing.clear()
                    existing.update(src_r)
                    existing["enabled"] = user_enabled
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
    """
    disable_key = LAYER_DISABLE_ENV.get(layer_key)
    if disable_key and os.getenv(disable_key) == "1":
        return False
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


def get_enabled_l1_command_patterns(runtime: dict) -> list[dict]:
    cat = runtime.get("L1_rules", {}).get("dangerous_commands", {})
    rules = filter_enabled_rules(cat.get("rules", []), cat.get("category_enabled", True))
    return [{"pattern": r["pattern"], "risk_level": r["risk_level"],
             "risk_type": r["risk_type"], "reason": r["reason"]} for r in rules]


def get_enabled_l1_injection_keywords(runtime: dict) -> list[dict]:
    cat = runtime.get("L1_rules", {}).get("injection_detection", {})
    rules = filter_enabled_rules(cat.get("rules", []), cat.get("category_enabled", True))
    return [{"keyword": r["keyword"], "risk_level": r["risk_level"],
             "lang": r.get("lang", "en")} for r in rules]


def get_enabled_l2_sensitive_paths(runtime: dict) -> list[dict]:
    """读取启用的敏感路径规则。

    优先读 L1_rules.sensitive_path_access（重分类后敏感路径归属 L1）；
    回退 L2_rules.sensitive_path_access（兼容迁移前的老配置）。
    函数名保留 l2 前缀仅为向后兼容，实际数据源已迁至 L1。
    """
    cat = runtime.get("L1_rules", {}).get("sensitive_path_access", {})
    if not cat.get("rules"):
        # 老配置未迁移：回退 L2_rules
        cat = runtime.get("L2_rules", {}).get("sensitive_path_access", {})
    rules = filter_enabled_rules(cat.get("rules", []), cat.get("category_enabled", True))
    out = []
    for r in rules:
        item = {"path": r["path"], "risk_level": r["risk_level"], "desc": r["desc"],
                "deny_mode": r.get("deny_mode", _derive_deny_mode(r))}
        if r.get("credential"):
            item["credential"] = True
        if r.get("read_only"):
            item["read_only"] = True
        if r.get("dir_del_only"):
            item["dir_del_only"] = True
        out.append(item)
    return out


def get_enabled_l2_intent_patterns(runtime: dict) -> list[dict]:
    cat = runtime.get("L2_rules", {}).get("intent_consistency", {})
    rules = filter_enabled_rules(cat.get("rules", []), cat.get("category_enabled", True))
    return [{"intent_keywords": r["intent_keywords"], "dangerous_actions": r["dangerous_actions"],
             "reason": r["reason"]} for r in rules]


def get_enabled_l2_password_patterns(runtime: dict) -> list[str]:
    cat = runtime.get("L2_rules", {}).get("password_modify_consent", {})
    rules = filter_enabled_rules(cat.get("rules", []), cat.get("category_enabled", True))
    return [r["pattern"] for r in rules]


def get_enabled_l2_user_deletion_patterns(runtime: dict) -> list[str]:
    cat = runtime.get("L2_rules", {}).get("user_deletion_consent", {})
    rules = filter_enabled_rules(cat.get("rules", []), cat.get("category_enabled", True))
    return [r["pattern"] for r in rules]


def is_l2_category_enabled(runtime: dict, category_key: str) -> bool:
    cat = runtime.get("L2_rules", {}).get(category_key, {})
    return cat.get("category_enabled", True)


def has_runtime_config() -> bool:
    """判断用户本地 runtime 配置文件是否存在且可正常读取。

    区分：文件不存在→从未配置，应用源码默认；文件存在但规则空→用户主动禁用，不回退。
    """
    config_path = get_runtime_config_path()
    if not config_path.exists():
        return False
    try:
        json.loads(config_path.read_text(encoding="utf-8"))
        return True
    except (json.JSONDecodeError, OSError):
        return False


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


def get_enabled_l1_command_patterns_or_default(runtime: dict) -> list[dict]:
    enabled = get_enabled_l1_command_patterns(runtime)
    if enabled:
        return enabled
    if not has_runtime_config():
        return _l1_command_patterns_to_rules(get_profile_or_detect())
    return []


def get_enabled_l1_injection_keywords_or_default(runtime: dict) -> list[dict]:
    enabled = get_enabled_l1_injection_keywords(runtime)
    if enabled:
        return enabled
    if not has_runtime_config():
        return _l1_injection_keywords_to_rules(get_profile_or_detect())
    return []


def get_enabled_l2_sensitive_paths_or_default(runtime: dict) -> list[dict]:
    enabled = get_enabled_l2_sensitive_paths(runtime)
    if enabled:
        return enabled
    if not has_runtime_config():
        return _l2_sensitive_paths_to_rules(get_profile_or_detect())
    return []


def get_enabled_l2_intent_patterns_or_default(runtime: dict) -> list[dict]:
    enabled = get_enabled_l2_intent_patterns(runtime)
    if enabled:
        return enabled
    if not has_runtime_config():
        return _l2_intent_patterns_to_rules(get_profile_or_detect())
    return []


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


def update_rule_enabled(layer: str, category: str, rule_id: str, enabled: bool) -> dict:
    runtime = load_runtime_config()
    for r in runtime.get(layer, {}).get(category, {}).get("rules", []):
        if r.get("id") == rule_id:
            r["enabled"] = enabled
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
    runtime = load_runtime_config()
    skills_dir = RUNTIME_CONFIG_DIR / "agent_moss_skills"
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
        skill_path = RUNTIME_CONFIG_DIR / "agent_moss_skills" / f"{skill_id}.md"
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
            r["enabled"] = enabled
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
            r["enabled"] = enabled
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
    """
    import json as _json
    from pathlib import Path as _Path
    try:
        mc_file = _Path(__file__).parent.parent / "rules" / "mc_rules.json"
        if not mc_file.is_file():
            return {"category_enabled": True, "category_desc": "LTL 攻击模式规则", "rules": []}
        mc = _json.loads(mc_file.read_text(encoding="utf-8")) or {}
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
