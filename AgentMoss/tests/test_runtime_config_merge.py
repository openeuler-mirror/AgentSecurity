"""runtime_config 合并逻辑测试 — 覆盖 deny_mode 基线迁移（问题 3）

source_deny_mode 字段在 deny_mode 重构后才引入，老配置没有此字段。
合并时若用户规则缺 source_deny_mode，需从 credential/read_only 派生旧基线，
避免用户改过的 deny_mode 被 source_deny_mode 缺失静默抹掉。
"""

from agent_moss.infra.runtime_config import (
    merge_config,
    _derive_legacy_deny_mode,
    _generate_pattern_id,
    _delete_rule_from_rules,
    delete_custom_rule,
)
from agent_moss.console.router import _with_l2_2_view, _l2_2_runtime_to_view


def _mk_src(path: str, deny_mode: str) -> dict:
    """源码新版默认：sensitive_path_access 在 L1_rules（重分类后），带 source_deny_mode 基线。"""
    return {
        "version": 2, "layers": {},
        "L1_rules": {
            "sensitive_path_access": {
                "category_desc": "x", "category_enabled": True,
                "rules": [{
                    "id": "p", "path": path, "risk_level": "high", "desc": "x",
                    "deny_mode": deny_mode, "source_deny_mode": deny_mode,
                    "skip_l3_on_disabled": True, "enabled": True, "builtin": True,
                }],
            }
        },
        "L2_rules": {},
        "L3_skills": {},
    }


def _mk_user(path: str, user_deny: str, credential=None, read_only=None) -> dict:
    """老用户配置：缺 source_deny_mode（重构前格式）。"""
    r = {
        "id": "p", "path": path, "risk_level": "high", "desc": "x",
        "deny_mode": user_deny, "skip_l3_on_disabled": True, "enabled": True, "builtin": True,
    }
    if credential is not None:
        r["credential"] = credential
    if read_only is not None:
        r["read_only"] = read_only
    return {
        "version": 1, "layers": {},
        "L1_rules": {},
        "L2_rules": {
            "sensitive_path_access": {
                "category_desc": "x", "category_enabled": True,
                "rules": [r],
            }
        },
        "L3_skills": {},
    }


def _merged_rule(src: dict, user: dict) -> dict:
    """合并后从 L1_rules 读 sensitive_path_access（迁移后归属 L1）。"""
    m = merge_config(user, src)
    return m["L1_rules"]["sensitive_path_access"]["rules"][0]


class TestDeriveLegacyDenyMode:
    """_derive_legacy_deny_mode：只看 credential/read_only，不看 deny_mode 本身。"""

    def test_credential_true_returns_deny_both(self):
        assert _derive_legacy_deny_mode({"deny_mode": "deny_write", "credential": True}) == "deny_both"

    def test_read_only_true_returns_deny_read(self):
        assert _derive_legacy_deny_mode({"deny_mode": "deny_both", "read_only": True}) == "deny_read"

    def test_both_falsy_returns_deny_write(self):
        assert _derive_legacy_deny_mode({"deny_mode": "deny_both", "credential": False, "read_only": False}) == "deny_write"

    def test_no_legacy_fields_returns_none(self):
        assert _derive_legacy_deny_mode({"deny_mode": "deny_both"}) is None


class TestDenyModeMergeBaseline:
    """老配置缺 source_deny_mode 时的合并行为（问题 3 回归保护）。"""

    def test_user_modified_deny_mode_preserved_with_credential_baseline(self):
        # 用户把 deny_both 改成 deny_write，老配置无 source_deny_mode，credential=True
        r = _merged_rule(_mk_src("/etc/shadow", "deny_both"), _mk_user("/etc/shadow", "deny_write", credential=True))
        assert r["deny_mode"] == "deny_write"  # 用户改动保留

    def test_user_unmodified_follows_source(self):
        # 用户没改（deny_both = 旧默认），credential=True 派生基线 deny_both，相等 → 跟源码
        r = _merged_rule(_mk_src("/etc/shadow", "deny_both"), _mk_user("/etc/shadow", "deny_both", credential=True))
        assert r["deny_mode"] == "deny_both"

    def test_source_changed_deny_mode_takes_effect_when_user_unmodified(self):
        # 源码 deny_both→deny_read，老用户 deny_both（旧默认）+ credential=True
        # 派生基线 deny_both = 用户 deny_both → 判"未改" → 源码 deny_read 生效
        r = _merged_rule(_mk_src("/etc/x", "deny_read"), _mk_user("/etc/x", "deny_both", credential=True))
        assert r["deny_mode"] == "deny_read"

    def test_both_source_and_user_changed_user_wins(self):
        # 源码 deny_read，用户改 deny_write + credential=True → 用户优先
        r = _merged_rule(_mk_src("/etc/x", "deny_read"), _mk_user("/etc/x", "deny_write", credential=True))
        assert r["deny_mode"] == "deny_write"

    def test_new_config_with_source_deny_mode_unchanged(self):
        # 新配置（有 source_deny_mode）行为不变：源码 deny_both + 用户改 deny_write
        # 既有基线场景，验证修法不破坏新配置路径
        src = _mk_src("/etc/shadow", "deny_both")
        user = _mk_user("/etc/shadow", "deny_write", credential=True)
        # 给用户配置补上 source_deny_mode（新配置特征）
        user["L2_rules"]["sensitive_path_access"]["rules"][0]["source_deny_mode"] = "deny_both"
        r = _merged_rule(src, user)
        assert r["deny_mode"] == "deny_write"  # 用户改动保留


class TestRuleIdUniqueness:
    """规则 id 唯一性（bug：旧版仅截 40 字符 slug，特殊字符抹平成 _ 导致撞 id）。"""

    def test_two_rm_patterns_generate_distinct_ids(self):
        # 历史撞车的一对真实 pattern：差异在 40 字符之后 vs 特殊字符布局。
        active = r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*\s+/(?!tmp|var/tmp|run|dev/shm|mnt|media)(?:/|\b)"
        removed = r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*\s+/(?!tmp/|var/tmp/|run/|dev/shm/)"
        id_active = _generate_pattern_id(active)
        id_removed = _generate_pattern_id(removed)
        assert id_active != id_removed  # 撞车解除

    def test_same_pattern_generates_same_id(self):
        # 同一 pattern 的 id 应确定稳定（merge 依赖幂等）。
        p = r"\bnmap\s+"
        assert _generate_pattern_id(p) == _generate_pattern_id(p)


class TestDeleteRuleFromRules:
    """同 id 多命中时 _delete_rule_from_rules 语义（bug：撞 id 时按首条命中误拒删）。"""

    def test_prioritizes_deleting_source_removed(self):
        # 同一 id 下：活跃 builtin 在前，source_removed 历史遗留在后。
        # 删除应删 source_removed 那条（可删），活跃的保留。
        rid = "cmd_dup"
        active = {"id": rid, "pattern": "x", "enabled": True, "builtin": True}
        removed = {"id": rid, "pattern": "y", "enabled": False, "builtin": True, "source_removed": True}
        rules = [active, removed]
        result = _delete_rule_from_rules(rules, rid)
        assert result is not None  # 不再拒绝
        assert len(rules) == 1
        assert rules[0]["pattern"] == "x"  # 删的是 source_removed（y），活跃（x）保留

    def test_prioritizes_deleting_custom(self):
        # 同 id 下：活跃 builtin 在前，用户自定义（builtin=False）在后 → 删自定义。
        rid = "cmd_dup"
        active = {"id": rid, "pattern": "x", "enabled": True, "builtin": True}
        custom = {"id": rid, "pattern": "z", "enabled": True, "builtin": False}
        rules = [active, custom]
        _delete_rule_from_rules(rules, rid)
        assert len(rules) == 1
        assert rules[0]["pattern"] == "x"

    def test_rejects_when_only_active_builtin(self):
        # 同 id 只有活跃 builtin → 拒绝（保护活跃内置规则）。
        rid = "cmd_only_active"
        active = {"id": rid, "pattern": "x", "enabled": True, "builtin": True}
        result = _delete_rule_from_rules([active], rid)
        assert result is None  # 拒绝

    def test_nomatch_returns_unchanged(self):
        # id 未命中 → 无操作，返回原列表（不拒绝）。
        rules = [{"id": "a", "pattern": "x", "enabled": True, "builtin": True}]
        result = _delete_rule_from_rules(rules, "nope")
        assert result is not None
        assert len(rules) == 1


class TestWithL22View:
    """console 写端点返回 runtimeConfig 前须把 L2_2 转成 view（ltl_rules=list）。"""

    def _cat_runtime(self):
        return {
            "L1_rules": {}, "L2_rules": {},
            "L2_2": {"ltl_rules": {"category_enabled": True, "category_desc": "", "rules": [
                {"id": "mc-ltl-001", "enabled": True, "reason": "x", "risk_level": "critical", "action": "block"},
            ]}},
        }

    def test_converts_category_dict_to_view_list(self):
        # Category dict → view：ltl_rules 从 dict 变 list。
        out = _with_l2_2_view(self._cat_runtime())
        ltl = out["L2_2"]["ltl_rules"]
        assert isinstance(ltl, list)
        assert ltl[0]["id"] == "mc-ltl-001"

    def test_idempotent_on_already_view(self):
        # 已转成 view 的 dict 再次调用不应破坏（幂等）。
        once = _with_l2_2_view(self._cat_runtime())
        twice = _with_l2_2_view(once)
        assert isinstance(twice["L2_2"]["ltl_rules"], list)
        assert len(twice["L2_2"]["ltl_rules"]) == 1

    def test_no_l2_2_passthrough(self):
        # 无 L2_2 字段时原样返回，不报错。
        runtime = {"L1_rules": {}, "L2_rules": {}}
        assert _with_l2_2_view(runtime) is runtime
