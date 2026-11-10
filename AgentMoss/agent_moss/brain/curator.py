"""Brain 规则/Skill 维护器 — 定期生命周期管理

参考 hermes-agent 的 Curator 设计，定期执行：
- 规则生命周期转换（active → stale → archived）
- Skill 生命周期管理
- 规则冲突检测
- 统计报告
"""

import logging
from .rule_store import BrainRuleStore
from .skill_manager import BrainSkillManager

logger = logging.getLogger(__name__)


class BrainCurator:
    """Brain 规则/Skill 定期维护器"""

    def __init__(self, rule_store: BrainRuleStore, skill_manager: BrainSkillManager):
        self._rule_store = rule_store
        self._skill_manager = skill_manager

    def run_maintenance(
        self,
        stale_rule_days: int = 30,
        archive_rule_days: int = 90,
        stale_skill_days: int = 60,
        dispute_threshold: int = 3,
        auto_approve: bool = True,
    ) -> dict:
        """
        执行维护任务，返回报告。

        Args:
            stale_rule_days: 规则多少天未触发 → stale
            archive_rule_days: 规则 stale 多少天 → archived
            stale_skill_days: Skill 多少天未使用 → stale
            dispute_threshold: disputed 次数达到多少 → 自动降级
            auto_approve: draft 规则是否自动激活（draft → approved → active）。
                默认 True：brain 提取的规则达到阈值后自动生效，形成学习闭环；
                若需人工审核可设为 False（由 console API 手动 approve）。

        Returns:
            dict: 维护报告
        """
        report = {}

        # 0. draft 规则自动激活（学习闭环：提取 → 生效）
        auto_approved = []
        if auto_approve:
            auto_approved = self._auto_approve_drafts()

        # 1. 规则生命周期
        self._rule_store.mark_stale(stale_rule_days)
        self._rule_store.mark_archived(archive_rule_days)
        self._rule_store.auto_demote_disputed(dispute_threshold)

        # 2. Skill 生命周期
        self._skill_manager.mark_stale(stale_skill_days)

        # 3. 统计
        report["rule_stats"] = self._rule_store.get_stats()
        report["auto_approved"] = auto_approved

        logger.info("Brain 维护完成: %s", report)
        return report

    def _auto_approve_drafts(self) -> list[str]:
        """自动激活 draft 规则：draft → approved → active。

        条件：规则已存在（达到提取阈值才会生成 draft），且未处于 disputed。
        自动激活后首次触发即生效——若后续被质疑（dispute），由生命周期机制
        自动降级（dispute_threshold 次质疑 → stale），形成"自动学习 + 自动纠错"
        的闭环。
        """
        approved_ids = []
        try:
            drafts = self._rule_store.get_draft_rules()
        except Exception as e:
            logger.debug("获取 draft 规则异常: %s", e)
            return approved_ids
        for rule in drafts:
            try:
                self._rule_store.approve_rule(rule.id)
                approved_ids.append(rule.pattern[:60])
            except Exception:
                continue
        if approved_ids:
            logger.info("Brain 自动激活 %d 条 draft 规则", len(approved_ids))
        return approved_ids
