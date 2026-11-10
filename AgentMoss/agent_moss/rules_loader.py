"""归一化规则加载器（单一事实源）。

L1/L2/L3 的正则规则数据统一存放在 agent_moss/rules/ 下的三份 JSON：
  - l1_rules.json: 危险命令 / 注入关键词 / 敏感路径
  - l2_rules.json: 意图偏离 / 密码修改授权 / 用户删除授权
  - l3_rules.json: skill 关键词映射

Python 与 TS 两端都从这些 JSON 读取规则数据，消除双端规则漂移。
本模块提供纯数据读取；profile / engine 层负责把数据组装成各自的
CommandPattern / SensitivePath / IntentDeviationPattern 等结构。

规则数据是"出厂默认种子"的单一事实源；运行时用户可在共享 runtime JSON
里增删改规则（runtime 机制不受影响）。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .infra.paths import get_data_root

# 归一化规则文件均位于 agent_moss/rules/（源码目录，TS copy-assets 会同步到 dist）
_RULES_DIR = Path(__file__).parent / "rules"


def _load_json(name: str) -> dict[str, Any]:
    """读取某份归一化规则 JSON。文件缺失或损坏时回退空 dict（不影响启动）。"""
    path = _RULES_DIR / name
    if not path.is_file():
        # 兼容：运行时数据根目录下若也有同名文件优先用（允许部署侧覆盖）
        alt = get_data_root() / "rules" / name
        path = alt if alt.is_file() else path
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except (json.JSONDecodeError, OSError):
        return {}


def load_l1() -> dict[str, Any]:
    """返回 L1 规则数据：{dangerous_commands, injection_detection, sensitive_path_access}。"""
    return _load_json("l1_rules.json")


def load_l2() -> dict[str, Any]:
    """返回 L2 规则数据：{intent_consistency, password_modify_consent, user_deletion_consent}。"""
    return _load_json("l2_rules.json")


def load_l3() -> dict[str, Any]:
    """返回 L3 规则数据：{category: {skill_id: [keywords...]}}。"""
    return _load_json("l3_rules.json")


def load_mc() -> dict[str, Any]:
    """返回 L2.2 模型检测规则数据：{ap_patterns, rules}（LTL 公式 AST，双端共用）。

    运行时开关：合并 runtime_config 的 L2_2.ltl_rules 分区 enabled（按 id 覆盖），
    引擎 check_mc_rules 据此跳过被禁用的规则；出厂默认全开。
    """
    mc = _load_json("mc_rules.json")
    rules = mc.get("rules", [])
    try:
        from .infra.runtime_config import has_runtime_config, load_runtime_config
        if rules and has_runtime_config():
            rt = load_runtime_config().get("L2_2", {}).get("ltl_rules", {})
            rt_rules = rt.get("rules", [])
            enabled_by_id = {r.get("id"): r.get("enabled", True) for r in rt_rules}
            # 大类开关：category_enabled=False 时整类禁用（对齐 L1/L2 的 filter_enabled_rules 语义）
            cat_enabled = rt.get("category_enabled", True)
            for r in rules:
                if r.get("id") in enabled_by_id:
                    r["enabled"] = enabled_by_id[r["id"]]
                if not cat_enabled:
                    r["enabled"] = False
    except Exception:
        pass  # runtime_config 不可用则维持内置默认（全开）
    return mc


def load_tool_registry() -> dict[str, Any]:
    """返回 Tool Registry 数据：{tools: {name: {actionClass, requireHighIntegrity}}}。"""
    return _load_json("tool_registry.json")