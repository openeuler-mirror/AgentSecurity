"""三方 agent 定制化扩展测试 — OpenDesk 用例

验证：
1. agent_moss/agents/opendesk/rules.json 能被 py 加载（rules.json 是 py+ts 共享单一事实源）
2. builtin_safe_action_types 白名单字段被正确解析（含前缀项 memory- 和精确名 mailbox-getEmailList）
3. coordinator 端到端：memory-*/todomgr-*/planning-* 命中白名单 → whitelist_bypass 放行（跳 L2+L3）
4. coordinator 端到端：mailbox-sendEmail/replyEmail 不在白名单 → 不命中 whitelist_bypass（保留 L3）
5. coordinator 端到端：skill- 不在白名单 → 不命中 whitelist_bypass
6. agent 隔离：xiaoo 不加载 opendesk rules.json；无 agent_id 走通用模式，memory- 不被豁免
"""

import pytest

from agent_moss.agents import (
    get_agent_extensions,
    clear_agent_extensions_cache,
)


@pytest.fixture(autouse=True)
def _clear_cache():
    """每个测试前清空 agent 扩展缓存，避免污染。"""
    clear_agent_extensions_cache()
    yield
    clear_agent_extensions_cache()


# ==================== 加载机制 + 字段解析 ====================

class TestOpendeskExtensionsLoading:
    """验证 opendesk rules.json 加载与 builtin_safe_action_types 字段解析。"""

    def test_load_opendesk_extensions(self):
        """agent_id='opendesk' 加载成功。"""
        ext = get_agent_extensions("opendesk")
        assert ext is not None
        assert ext.agent_id == "opendesk"

    def test_builtin_safe_action_types_present(self):
        """builtin_safe_action_types 非空，含前缀项和精确名项。"""
        ext = get_agent_extensions("opendesk")
        assert ext is not None
        assert len(ext.builtin_safe_action_types) > 0

    def test_prefix_entries_present(self):
        """前缀白名单项存在（memory- / todomgr- / planning-）。"""
        ext = get_agent_extensions("opendesk")
        assert ext is not None
        for prefix in ("memory-", "todomgr-", "planning-"):
            assert prefix in ext.builtin_safe_action_types

    def test_exact_name_entries_present(self):
        """精确名白名单项存在（mailbox-getEmailList）；发信类不在内。"""
        ext = get_agent_extensions("opendesk")
        assert ext is not None
        assert "mailbox-getEmailList" in ext.builtin_safe_action_types
        # 发信类必须不在白名单（外传风险保留 L3）
        assert "mailbox-sendEmail" not in ext.builtin_safe_action_types
        assert "mailbox-replyEmail" not in ext.builtin_safe_action_types


# ==================== 端到端：白名单放行 ====================

class TestOpendeskSafeActionBypass:
    """验证 opendesk builtin_safe_action_types 在 coordinator 中真正生效。"""

    @pytest.fixture
    def opendesk_bot(self, linux_profile, default_config):
        """构造带 opendesk agent_ext 的 AgentMossBot。"""
        from agent_moss.engine.coordinator import AgentMossBot
        ext = get_agent_extensions("opendesk")
        return AgentMossBot(profile=linux_profile, agent_ext=ext), default_config

    def test_memory_addmemory_bypassed(self, opendesk_bot):
        """memory-addMemory 命中前缀白名单 → whitelist_bypass 放行。"""
        bot, config = opendesk_bot
        judgment = bot.judge(
            prompt_session="",
            action_history=[],
            a_next={"action_type": "memory-addMemory", "action_detail": "memory-addMemory: scope=workspace"},
            reason="",
            config=config,
        )
        assert judgment.allowed
        assert judgment.source == "whitelist_bypass"

    def test_todomgr_todowrite_bypassed(self, opendesk_bot):
        """todomgr-TodoWrite 命中前缀白名单 → whitelist_bypass 放行。"""
        bot, config = opendesk_bot
        judgment = bot.judge(
            prompt_session="",
            action_history=[],
            a_next={"action_type": "todomgr-TodoWrite", "action_detail": "todos update"},
            reason="",
            config=config,
        )
        assert judgment.allowed
        assert judgment.source == "whitelist_bypass"

    def test_planning_createsubtask_bypassed(self, opendesk_bot):
        """planning-createSubTask 命中前缀白名单 → whitelist_bypass 放行。"""
        bot, config = opendesk_bot
        judgment = bot.judge(
            prompt_session="",
            action_history=[],
            a_next={"action_type": "planning-createSubTask", "action_detail": "planning-createSubTask"},
            reason="",
            config=config,
        )
        assert judgment.allowed
        assert judgment.source == "whitelist_bypass"

    def test_mailbox_getEmailList_bypassed(self, opendesk_bot):
        """mailbox-getEmailList 命中精确名白名单 → whitelist_bypass 放行。

        注意：rules.json 用驼峰 mailbox-getEmailList，action_type 经 .lower() 后是
        mailbox-getemaillist；匹配逻辑对白名单项也 lower，故仍命中。
        """
        bot, config = opendesk_bot
        judgment = bot.judge(
            prompt_session="",
            action_history=[],
            a_next={"action_type": "mailbox-getEmailList", "action_detail": "mailbox-getEmailList"},
            reason="",
            config=config,
        )
        assert judgment.allowed
        assert judgment.source == "whitelist_bypass"


# ==================== 端到端：不豁免（保留 L3） ====================

class TestOpendeskNoBypass:
    """验证发信类 / skill- 不命中白名单（保留 L3）。"""

    @pytest.fixture
    def opendesk_bot(self, linux_profile, default_config):
        from agent_moss.engine.coordinator import AgentMossBot
        ext = get_agent_extensions("opendesk")
        return AgentMossBot(profile=linux_profile, agent_ext=ext), default_config

    def test_mailbox_sendEmail_not_bypassed(self, opendesk_bot):
        """mailbox-sendEmail 不在白名单 → 不命中 whitelist_bypass。"""
        bot, config = opendesk_bot
        judgment = bot.judge(
            prompt_session="",
            action_history=[],
            a_next={"action_type": "mailbox-sendEmail", "action_detail": "mailbox-sendEmail: to=x@x.com"},
            reason="",
            config=config,
        )
        # default_config 禁用 LLM → 前两层未命中时走 heuristic_and_logic_only 放行，
        # 但 source 不应是 whitelist_bypass（守护"不被前缀误豁免"）
        assert judgment.source != "whitelist_bypass"

    def test_mailbox_replyEmail_not_bypassed(self, opendesk_bot):
        """mailbox-replyEmail 不在白名单 → 不命中 whitelist_bypass。"""
        bot, config = opendesk_bot
        judgment = bot.judge(
            prompt_session="",
            action_history=[],
            a_next={"action_type": "mailbox-replyEmail", "action_detail": "mailbox-replyEmail: uid=abc"},
            reason="",
            config=config,
        )
        assert judgment.source != "whitelist_bypass"

    def test_skill_not_bypassed(self, opendesk_bot):
        """skill- 前缀不在白名单 → 不命中 whitelist_bypass。"""
        bot, config = opendesk_bot
        judgment = bot.judge(
            prompt_session="",
            action_history=[],
            a_next={"action_type": "skill-someTool", "action_detail": "skill-someTool"},
            reason="",
            config=config,
        )
        assert judgment.source != "whitelist_bypass"


# ==================== agent 隔离 ====================

class TestOpendeskAgentIsolation:
    """验证 opendesk 白名单只对 agent_id=opendesk 生效，不污染其他 agent / 通用模式。"""

    def test_xiaoo_does_not_get_opendesk_whitelist(self, linux_profile, default_config):
        """xiaoo 不加载 opendesk rules.json → memory-addMemory 不命中 whitelist_bypass。"""
        from agent_moss.engine.coordinator import AgentMossBot
        ext = get_agent_extensions("xiaoo")
        bot = AgentMossBot(profile=linux_profile, agent_ext=ext)
        judgment = bot.judge(
            prompt_session="",
            action_history=[],
            a_next={"action_type": "memory-addMemory", "action_detail": "memory-addMemory"},
            reason="",
            config=default_config,
        )
        assert judgment.source != "whitelist_bypass"

    def test_generic_mode_does_not_get_opendesk_whitelist(self, linux_profile, default_config):
        """无 agent_ext（通用模式）→ memory-addMemory 不命中 whitelist_bypass。"""
        from agent_moss.engine.coordinator import AgentMossBot
        bot = AgentMossBot(profile=linux_profile)  # 无 agent_ext
        judgment = bot.judge(
            prompt_session="",
            action_history=[],
            a_next={"action_type": "memory-addMemory", "action_detail": "memory-addMemory"},
            reason="",
            config=default_config,
        )
        assert judgment.source != "whitelist_bypass"


# ==================== runtime_config 统一存储覆盖 ====================

class TestAgentRulesRuntimeConfigOverride:
    """验证 agent 规则纳入 runtime_config 后：console 禁用某条 → coordinator 生效。

    不依赖 has_runtime_config()（conftest 全局 mock False）；直接调
    get_enabled_agent_extensions 验证 enabled 过滤逻辑。
    """

    def test_get_enabled_agent_extensions_filters_disabled(self):
        """runtime_config 中禁用 memory- → get_enabled_agent_extensions 不返回它。"""
        from agent_moss.infra.runtime_config import (
            generate_source_defaults, get_enabled_agent_extensions,
        )
        defaults = generate_source_defaults()
        # opendesk 应在 agent_rules 种子里
        assert "opendesk" in defaults.get("agent_rules", {})
        ext = get_enabled_agent_extensions(defaults, "opendesk")
        assert ext is not None
        assert "memory-" in ext.builtin_safe_action_types

        # 禁用 memory- 后不应再返回
        defaults["agent_rules"]["opendesk"]["builtin_safe_action_types"]["rules"][0]["enabled"] = False
        ext2 = get_enabled_agent_extensions(defaults, "opendesk")
        assert ext2 is not None
        assert "memory-" not in ext2.builtin_safe_action_types
        # todomgr- 仍在
        assert "todomgr-" in ext2.builtin_safe_action_types

    def test_merge_preserves_user_disabled(self):
        """merge_config 后用户禁用的 agent 规则保留 enabled=False。"""
        from agent_moss.infra.runtime_config import (
            generate_source_defaults, merge_config, _rule_fingerprint,
        )
        src = generate_source_defaults()
        # 用户配置：opendesk 的第一条 builtin_safe_action_types 禁用
        user = {"agent_rules": {"opendesk": {
            "builtin_safe_action_types": {
                "category_enabled": True, "category_desc": "",
                "rules": [{"value": "memory-", "enabled": False, "builtin": True}],
            }}}}
        merged = merge_config(user, src)
        rules = merged["agent_rules"]["opendesk"]["builtin_safe_action_types"]["rules"]
        memory_rule = next(r for r in rules if r["value"] == "memory-")
        assert memory_rule["enabled"] is False
        # 其余出厂条目被补进来且 enabled=True
        todomgr_rule = next(r for r in rules if r["value"] == "todomgr-")
        assert todomgr_rule["enabled"] is True

    def test_merge_adds_new_agent(self):
        """新增 agent（源有、用户无）→ 整体加入。"""
        from agent_moss.infra.runtime_config import generate_source_defaults, merge_config
        src = generate_source_defaults()
        user = {"agent_rules": {}}  # 用户无任何 agent 规则
        merged = merge_config(user, src)
        assert "opendesk" in merged["agent_rules"]
        assert "memory-" in [
            r["value"] for r in
            merged["agent_rules"]["opendesk"]["builtin_safe_action_types"]["rules"]
        ]
