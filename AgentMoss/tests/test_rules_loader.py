"""归一化规则加载器测试 — 验证 L1/L2/L3 规则数据从 JSON 单一事实源加载。

规则数据统一存放在 agent_moss/rules/ 下（l1/l2/l3_rules.json），Python 与 TS
共用。此测试断言：
1. 三份 JSON 可加载且计数稳定（守护出厂默认，防误删/误改导致漂移）。
2. 加载器产出与 profile 规则对象一致（LinuxProfile 组装正确）。
3. 种子生成（generate_source_defaults）与 JSON 数据一致（无手工双份）。
"""

import json
from pathlib import Path

from agent_moss import rules_loader
from agent_moss.infra import runtime_config
from agent_moss.profiles.linux import LinuxProfile


RULES_DIR = Path(__file__).parent.parent / "agent_moss" / "rules"


def test_three_json_files_exist():
    for name in ("l1_rules.json", "l2_rules.json", "l3_rules.json"):
        p = RULES_DIR / name
        assert p.is_file(), f"缺失归一化规则文件: {name}"


def test_l1_counts_stable():
    l1 = rules_loader.load_l1()
    assert len(l1["dangerous_commands"]) == 56
    assert len(l1["injection_detection"]) == 46
    assert len(l1["sensitive_path_access"]) == 42  # +3: .config/agentmoss 目录/config.json + .agentmoss/brain；+2: .ssh/.aws 目录级（收紧 home 根删除后凭据目录删除兜底）


def test_l2_counts_stable():
    l2 = rules_loader.load_l2()
    assert len(l2["intent_consistency"]) == 2
    assert len(l2["password_modify_consent"]) == 7
    assert len(l2["user_deletion_consent"]) == 5


def test_l3_skills_count():
    l3 = rules_loader.load_l3()
    total = sum(len(v) for v in l3.values() if isinstance(v, dict))
    assert total == 13  # 13 个 skill


def test_profile_loads_from_json():
    """LinuxProfile 各规则属性应从 JSON 加载，计数与 JSON 一致。"""
    prof = LinuxProfile()
    l1 = rules_loader.load_l1()
    assert len(prof.dangerous_commands) == len(l1["dangerous_commands"])
    assert len(prof.injection_keywords) == len(l1["injection_detection"])
    assert len(prof.sensitive_paths) == len(l1["sensitive_path_access"])
    # 敏感路径 path 与 JSON 逐条一致（顺序敏感）
    json_paths = [sp["path"] for sp in l1["sensitive_path_access"]]
    prof_paths = [sp.path for sp in prof.sensitive_paths]
    assert json_paths == prof_paths, "profile 敏感路径与 JSON 顺序/内容不一致"


def test_seed_matches_json_rule_data():
    """generate_source_defaults 的规则数据应完全来自 JSON（非手工双份）。"""
    seed = runtime_config.generate_source_defaults()
    l1 = rules_loader.load_l1()
    # 危险命令 pattern 集合一致
    seed_pats = {r["pattern"] for r in seed["L1_rules"]["dangerous_commands"]["rules"]}
    json_pats = {c["pattern"] for c in l1["dangerous_commands"]}
    assert seed_pats == json_pats, "种子危险命令与 JSON 不一致"
    # 注入关键词一致
    seed_kws = {r["keyword"] for r in seed["L1_rules"]["injection_detection"]["rules"]}
    json_kws = {k["keyword"] for k in l1["injection_detection"]}
    assert seed_kws == json_kws, "种子注入关键词与 JSON 不一致"
    # 敏感路径 path + deny_mode 一致
    seed_sp = {(r["path"], r["deny_mode"]) for r in seed["L1_rules"]["sensitive_path_access"]["rules"]}
    json_sp = {(s["path"], s["deny_mode"]) for s in l1["sensitive_path_access"]}
    assert seed_sp == json_sp, "种子敏感路径与 JSON 不一致"

def test_mc_rules_loaded():
    """mc_rules.json 可加载：11 条 LTL/降级规则 + 14 原子命题。"""
    mc = rules_loader.load_mc()
    rules = mc.get("rules", [])
    aps = mc.get("ap_patterns", {})
    assert len(rules) == 11, len(rules)
    ids = [r["id"] for r in rules]
    assert "mc-ltl-001" in ids and "mc-ctl-001" in ids
    # 全部是 ltl 型（CTL 活性不实现，mc-ctl-001 以 F(clear_logs) 降级）
    assert all(r["type"] == "ltl" for r in rules)
    assert len(aps) == 14, len(aps)


def test_l22_view_contract():
    """console /api/rules 的 L2_2 只读视图契约（双端对齐）。

    当前只下发 ltl_rules（带 enabled + 人话），不再下发 formal_properties/
    atomic_propositions（引擎检测器/原子命题不以视图形式暴露给 console）。
    """
    from agent_moss.console.router import _get_l2_2_view
    v = _get_l2_2_view()
    assert v["enabled_via"] == "L2_logic_rules"
    assert len(v["ltl_rules"]) == 11
    assert "category_enabled" in v  # 大类开关字段（供前端 LTL 大类开关）
    # 每条规则带结果来源字段
    assert all(k in v["ltl_rules"][0] for k in ("id", "risk_level", "action", "reason", "human", "enabled"))
    # 公式以占位符返回（避免把 AST 泄漏到接口层）
    assert v["ltl_rules"][0]["formula"] == "<公式>"
    # 不再承载引擎检测器/原子命题（前端"形式化"页只展示 LTL 规则）
    assert "atomic_propositions" not in v and "formal_properties" not in v


def test_load_mc_category_disabled_gates_all_rules(monkeypatch):
    """LTL 大类开关：L2_2.ltl_rules.category_enabled=False → load_mc 所有规则 enabled 归 False。

    对齐 L1/L2 的 filter_enabled_rules(category_enabled=False) 语义——大类关 = 整类禁用。
    """
    from agent_moss.infra.runtime_config import update_category_enabled
    from agent_moss.rules_loader import load_mc

    # conftest 的 autouse _isolate_runtime_config 会把 has_runtime_config 恒置 False，
    # 这里局部恢复 True 以覆盖 load_mc 的 runtime 合并分支（否则测不到门控逻辑）。
    monkeypatch.setattr(runtime_config, "has_runtime_config", lambda: True)

    try:
        update_category_enabled("L2_2", "ltl_rules", False)
        mc = load_mc()
        rules = mc.get("rules", [])
        assert len(rules) == 11
        assert all(r.get("enabled", True) is False for r in rules), \
            "category_enabled=False 时所有 LTL 规则应全禁用"
    finally:
        # 还原大类开关，避免污染后续测试
        update_category_enabled("L2_2", "ltl_rules", True)


def test_l22_view_after_toggle_is_list():
    """toggle LTL 规则后，返回给前端的 L2_2.ltl_rules 必须仍是 list（契约）。

    否则前端 renderLtlCard 的 ltl.map() 崩溃（runtime L2_2 是 Category dict）。
    镜像 TS console-routes 同款断言。
    """
    from agent_moss.console.router import _with_l2_2_view
    from agent_moss.infra.runtime_config import update_rule_enabled
    rt = update_rule_enabled("L2_2", "ltl_rules", "mc-ltl-001", False)
    v = _with_l2_2_view(dict(rt))
    l = v["L2_2"]
    assert isinstance(l["ltl_rules"], list), l["ltl_rules"]
    assert len(l["ltl_rules"]) == 11
    target = next(x for x in l["ltl_rules"] if x["id"] == "mc-ltl-001")
    assert target["enabled"] is False
    assert isinstance(target["human"], str) and target["human"]
    # 还原，避免污染后续
    update_rule_enabled("L2_2", "ltl_rules", "mc-ltl-001", True)
