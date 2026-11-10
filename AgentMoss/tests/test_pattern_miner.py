"""PatternMiner 单测：数据驱动发现危险频繁子序列（预置链外的新形态）。"""
from agent_moss.engine.formal_engine.pattern_miner import mine_dangerous_patterns, project_stages


def _sessions(*seqs):
    return [
        {"session_id": f"s{i}", "action_history": [
            {"action_type": "bash", "action_detail": detail}
            for detail in seq
        ]}
        for i, seq in enumerate(seqs)
    ]


# 预置链外的危险组合（预置链没有 CRED 开头的链）
def test_cred_then_listen_detected():
    """拦：CRED→LISTEN（读凭据后建服务）是预置链盲区，应被挖掘发现。"""
    sessions = _sessions(
        ["cat ~/.ssh/id_rsa", "flask --app app.py run"],
        ["cat ~/.ssh/id_rsa", "node server.js"],
        ["cat ~/.ssh/config", "python -m http.server 8080"],
    )
    out = mine_dangerous_patterns(sessions, min_sup=2)
    pats = {tuple(d["pattern"]) for d in out}
    assert ("CRED", "LISTEN") in pats


def test_privesc_cred_detected():
    """拦：PRIVESC→CRED（提权后读凭据）应被挖掘。"""
    sessions = _sessions(
        ["sudo -u root whoami", "cat ~/.ssh/id_rsa"],
        ["sudo -u root id", "cat /root/.aws/credentials"],
    )
    out = mine_dangerous_patterns(sessions, min_sup=2)
    pats = {tuple(d["pattern"]) for d in out}
    assert ("PRIVESC", "CRED") in pats


def test_normal_flow_not_detected():
    """放：平凡开发流程（无危险 stage 组合）不应有候选。"""
    sessions = _sessions(
        ["ls -la", "npm install", "npm run build"],
        ["cd repos && git pull", "git push"],
    )
    out = mine_dangerous_patterns(sessions, min_sup=2)
    assert out == []


def test_single_frequent_stage_not_counted():
    """放：单阶段（CRED 单独频繁）不构成候选（要求长度>=2 组合）。"""
    sessions = _sessions(
        ["cat ~/.ssh/id_rsa"],
        ["cat ~/.ssh/id_rsa"],
        ["cat ~/.ssh/id_rsa"],
    )
    out = mine_dangerous_patterns(sessions, min_sup=2)
    assert out == []


def test_min_sup_respected():
    """放：support 低于 min_sup 的组合不出现。"""
    sessions = _sessions(
        ["cat ~/.ssh/id_rsa", "flask --app a.py run"],
        ["ls"],  # 只有 1 个 session 出现 CRED→LISTEN
    )
    out = mine_dangerous_patterns(sessions, min_sup=2)
    assert out == []


def test_projection_compresses_repeats():
    """压：连续同 stage 压缩（连读多个凭据文件 → 一个 CRED）。"""
    assert project_stages([
        {"action_type": "read", "action_detail": "cat ~/.ssh/id_rsa"},
        {"action_type": "read", "action_detail": "cat ~/.ssh/config"},
        {"action_type": "bash", "action_detail": "nmap -sV 10.0.0.0/24"},
    ]) == ["CRED", "SCAN"]