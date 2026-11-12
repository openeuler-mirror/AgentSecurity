"""L2.2 形式化引擎名单的单一事实源看护（2026-10 从代码搬进 JSON）。

`rules/formal_rules.json`：
- `privesc.package_managers`（9）/ `privesc.bare_shells`（9）：提权判定的命令位置旁证
- `compute_action_types`（5）：一律视为命令执行形态的 action_type
- `pattern_miner.danger_stages`（3）/ `sensitive_pairs`（2）：组合链挖掘的危险面

**没搬的**：`decode._STAGE_PRIORITY` —— 它表达「多阶段同时命中时报哪个」的仲裁顺序，
是逻辑而非可增删的规则。

"""
from __future__ import annotations

from agent_moss.engine.formal_engine import pattern_miner as pm
from agent_moss.engine.formal_engine import properties as props
from agent_moss.rules_loader import load_formal_rules


def test_counts_stable():
    d = load_formal_rules()
    assert len(d["privesc"]["package_managers"]) == 9
    assert len(d["privesc"]["bare_shells"]) == 9
    assert len(d["compute_action_types"]) == 5
    assert len(d["pattern_miner"]["danger_stages"]) == 3
    assert len(d["pattern_miner"]["sensitive_pairs"]) == 2


def test_constants_come_from_json():
    d = load_formal_rules()
    assert set(props._PKG_MGR) == set(d["privesc"]["package_managers"])
    assert set(props._SHELLS) == set(d["privesc"]["bare_shells"])
    assert set(props._STRONG_COMPUTE_TYPES) == set(d["compute_action_types"])
    assert set(pm.DANGER_STAGES) == set(d["pattern_miner"]["danger_stages"])
    assert {tuple(p) for p in d["pattern_miner"]["sensitive_pairs"]} == set(pm._SENSITIVE_PAIRS)


def test_package_managers_not_treated_as_privesc():
    """`sudo apt install` 是运维不是提权 —— 名单空了就会误报。"""
    assert props._contains_privesc("sudo apt install nginx") is False
    assert props._contains_privesc("sudo apt-get update") is False
    assert props._contains_privesc("sudo dnf install -y vim") is False


def test_bare_shell_after_sudo_is_privesc():
    for cmd in ("sudo bash", "sudo -E /bin/bash", "sudo zsh", "sudo su -"):
        assert props._contains_privesc(cmd) is True, cmd


def test_compute_action_types():
    class _N:
        def __init__(self, t, d=""):
            self.action_type, self.action_detail = t, d

    for t in ("python", "node", "exec", "terminal", "cmd"):
        assert props._is_compute_node(_N(t)) is True, t
    # 只读工具即使走 bash 也不算 compute
    assert props._is_compute_node(_N("read", "cat /tmp/x")) is False


def test_danger_stages_cover_reverse_shell():
    """组合链挖掘：危险阶段空了 → 整条链不再报（漏报）。"""
    assert {"PRIVESC", "EXFIL", "LISTEN"} <= set(pm.DANGER_STAGES)
    assert ("CRED", "LISTEN") in pm._SENSITIVE_PAIRS
    assert ("LISTEN", "CRED") in pm._SENSITIVE_PAIRS
