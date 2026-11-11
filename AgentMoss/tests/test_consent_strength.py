"""L2 授权（consent）判定强度看护 —— 直接测规则本身，绕过 L1。

**为什么要单独看护**：`userdel` / `passwd` 这几条命令的 L1 规则与 L2 的
`user_deletion_consent` / `password_modify_consent` 用的是**同一组 pattern**，
而 L1 先于 L2 执行并直接 Deny —— L2 的授权分支在常规用例里**永远走不到**。
常规用例（`tests/cases/l2/logic-06/08`）实际测的是 L1，把 L2 的缺陷全遮住了。

2026-10 实测到的问题（旧实现）：
  - 用户回答「否」→ **放行**（只看 output 非空，不区分肯定/否定）
  - 只提问、用户没回答 → **放行**（弱授权）
  - 问「要重启服务吗」用户答「是」→ **放行 userdel**（提问与操作无关也认）
  - 一小时前的任意提问回答 → **放行**（没有时效、没有距离约束）

本文件直接调 `LogicRulesChecker`，不经过 L1，专门锁死上面每一条。

"""

import pytest

from agent_moss.engine.logic_rules import LogicRulesChecker


def _q(question: str, output: str = "", called_at: str = "") -> dict:
    """构造一条 ask_user_question 历史。"""
    item = {"action_type": "ask_user_question", "action_detail": question, "output": output}
    if called_at:
        item["called_at"] = called_at
    return item


@pytest.fixture()
def checker(linux_profile):
    return LogicRulesChecker(linux_profile)


def _userdel(checker, history, called_at=""):
    a_next = {"action_type": "bash", "action_detail": "userdel -r ops"}
    if called_at:
        a_next["called_at"] = called_at
    return checker._check_user_deletion_consent(history, a_next)


def _passwd(checker, history, called_at=""):
    a_next = {"action_type": "bash", "action_detail": "echo 'x' | passwd"}
    if called_at:
        a_next["called_at"] = called_at
    return checker._check_password_consent(history, a_next)


class TestUserDeletionConsent:
    """userdel 的授权判定。"""

    def test_no_history_denied(self, checker):
        assert _userdel(checker, []).hit

    def test_explicit_yes_allowed(self, checker):
        assert not _userdel(checker, [_q("确认删除用户 ops 吗？", "是")]).hit

    def test_explicit_yes_with_context_allowed(self, checker):
        assert not _userdel(checker, [_q("确认删除用户 ops 吗？", "好的，确认")]).hit

    def test_answer_no_denied(self, checker):
        """用户明确拒绝 ≠ 授权（旧实现会放行 —— 最严重的一条）。"""
        r = _userdel(checker, [_q("确认删除用户 ops 吗？", "否")])
        assert r.hit and r.risk_type == "consent_missing"

    def test_answer_no_english_denied(self, checker):
        assert _userdel(checker, [_q("确认删除用户 ops 吗？", "no, don't")]).hit

    def test_answer_cancel_denied(self, checker):
        assert _userdel(checker, [_q("确认删除用户 ops 吗？", "取消")]).hit

    def test_unanswered_denied(self, checker):
        """只提问不回答不是授权（弱授权已取消）。"""
        assert _userdel(checker, [_q("确认删除用户 ops 吗？", "")]).hit

    def test_ambiguous_answer_denied(self, checker):
        """回答无法判定为肯定 → fail-closed。"""
        assert _userdel(checker, [_q("确认删除用户 ops 吗？", "再看看")]).hit

    def test_unrelated_question_denied(self, checker):
        """问「要重启服务吗」用户答「是」不能给删用户背书。"""
        assert _userdel(checker, [_q("要重启服务吗？", "是")]).hit

    def test_recent_question_allowed(self, checker):
        """提问后隔 2 条动作仍算授权（距离窗口内）。"""
        hist = [_q("确认删除用户 ops 吗？", "是")] + [
            {"action_type": "bash", "action_detail": f"ls /tmp/{i}"} for i in range(2)
        ]
        assert not _userdel(checker, hist).hit

    def test_stale_question_denied(self, checker):
        """提问隔了 6 条以上动作 → 不认（防预支授权）。"""
        hist = [_q("确认删除用户 ops 吗？", "是")] + [
            {"action_type": "bash", "action_detail": f"ls /tmp/{i}"} for i in range(6)
        ]
        assert _userdel(checker, hist).hit

    def test_only_latest_question_counts(self, checker):
        """只看最近一条提问：最近那条不合格 → Deny，不往前翻找更早的授权。"""
        hist = [
            _q("确认删除用户 ops 吗？", "是"),          # 更早，合格
            {"action_type": "bash", "action_detail": "ls /tmp"},
            _q("确认删除用户 ops 吗？", "否"),          # 最近，拒绝
        ]
        assert _userdel(checker, hist).hit

    def test_non_bash_action_not_checked(self, checker):
        r = checker._check_user_deletion_consent(
            [], {"action_type": "file_write", "action_detail": "userdel -r ops"}
        )
        assert not r.hit


class TestPasswordConsent:
    """非交互式改密的授权判定。"""

    def test_no_history_denied(self, checker):
        assert _passwd(checker, []).hit

    def test_explicit_yes_allowed(self, checker):
        assert not _passwd(checker, [_q("要修改 ops 的密码吗？", "是")]).hit

    def test_input_request_with_secret_allowed(self, checker):
        """索取型提问：用户直接给出密码即为授权（回答里不会有「是」）。"""
        assert not _passwd(checker, [_q("请输入新的登录密码", "n3wP@ss")]).hit

    def test_input_request_no_answer_denied(self, checker):
        assert _passwd(checker, [_q("请输入新的登录密码", "")]).hit

    def test_answer_no_denied(self, checker):
        assert _passwd(checker, [_q("要修改 ops 的密码吗？", "不")]).hit

    def test_unrelated_question_denied(self, checker):
        assert _passwd(checker, [_q("要重启服务吗？", "是")]).hit


class TestConsentTtl:
    """时效窗：提问与执行间隔超过 TTL 不算授权。"""

    def test_ttl_expired_denied(self, checker):
        hist = [_q("确认删除用户 ops 吗？", "是", called_at="2026-10-31T10:00:00")]
        assert _userdel(checker, hist, called_at="2026-10-31T10:10:00").hit

    def test_ttl_within_allowed(self, checker):
        hist = [_q("确认删除用户 ops 吗？", "是", called_at="2026-10-31T10:00:00")]
        assert not _userdel(checker, hist, called_at="2026-10-31T10:02:00").hit

    def test_ttl_override_via_env(self, checker, monkeypatch):
        monkeypatch.setenv("AGENT_MOSS_CONSENT_TTL_SECONDS", "0")
        hist = [_q("确认删除用户 ops 吗？", "是", called_at="2020-01-01T00:00:00")]
        assert not _userdel(checker, hist, called_at="2026-10-31T10:00:00").hit

    def test_missing_timestamp_skips_ttl(self, checker):
        """调用方没上报时间 → 跳过时间窗，由距离窗口兜底。"""
        hist = [_q("确认删除用户 ops 吗？", "是", called_at="2020-01-01T00:00:00")]
        assert not _userdel(checker, hist).hit


class TestToolNameAliases:
    """工具名别名：OpenDesk 链路（executeBash / askUser）也要能触发授权判定。

    经 AgentGate 透传的工具名不是裸 ``bash`` / ``ask_user_question``：
      - OpenDesk 的 shell 工具注册名是 ``executeBash``（消息里可能带命名空间前缀）
      - AskUserTool 的注册名是 ``askUser``
    只认标准名时，这两条授权规则在 OpenDesk 链路上**根本不执行** ——
    不是「判未授权」，而是「规则没跑」，改密/删用户完全不受管控。
    """

    def test_execute_bash_triggers_password_rule(self, checker):
        a_next = {"action_type": "executeBash", "action_detail": "echo 'x' | passwd"}
        assert checker._check_password_consent([], a_next).hit

    def test_execute_bash_triggers_userdel_rule(self, checker):
        a_next = {"action_type": "executeBash", "action_detail": "userdel -r ops"}
        assert checker._check_user_deletion_consent([], a_next).hit

    def test_ns_prefixed_execute_bash_triggers(self, checker):
        a_next = {"action_type": "terminal-executeBash", "action_detail": "userdel -r ops"}
        assert checker._check_user_deletion_consent([], a_next).hit

    def test_ask_user_camel_case_allowed(self, checker):
        hist = [{"action_type": "askUser", "action_detail": "确认删除用户 ops 吗？", "output": "是"}]
        assert not _userdel(checker, hist).hit

    def test_ns_prefixed_ask_user_allowed(self, checker):
        hist = [{"action_type": "interaction-askUser", "action_detail": "要修改 ops 的密码吗？", "output": "是"}]
        assert not _passwd(checker, hist).hit

    def test_non_shell_tool_not_triggered(self, checker):
        """别名放宽不能波及其他工具：读文件里出现 userdel 字样不算删用户。"""
        a_next = {"action_type": "readFile", "action_detail": "userdel -r ops"}
        assert not checker._check_user_deletion_consent([], a_next).hit
