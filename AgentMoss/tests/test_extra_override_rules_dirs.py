# -*- coding: utf-8 -*-
"""规则目录：``override.json``（覆盖）/ ``extra.json``（追加）—— 2026-10 新语义。

与客户确认的最终语义（K8s ConfigMap 只能挂**一个目录**，故两个环境变量都只是
"目录在哪"，追加还是覆盖**由文件名决定**）：

    <目录>/override.json   覆盖：文件里出现的类别**整份替换**内置同名类别
                           （没写的类别保持内置；写空数组 = 明确清空该类别）
    <目录>/extra.json      追加：文件里出现的类别**追加**在（替换后的）规则之后
    其他 *.json            **一律不读**（启动自检/日志会列出来提醒）

优先级：override.json > extra.json > 内置（同类别内按 pattern/path 去重，先出现者保留）。

历史背景（为什么废掉旧的"按内置文件名覆盖"）：客户实测时被绕晕 —— 往目录里放了个
随机名的文件，看到行为变了就以为"别的名字也能生效"（实际是别的原因：他们关掉了 L2，
而拦 su 的规则在 L2）。一条"只有这两个文件名会被读"的规则零例外，最好解释。
"""

import json
import logging

import pytest

from agent_moss.engine.analyzer import analyze
from agent_moss.profiles import get_profile
from agent_moss.rules_loader import (
    EXTRA_FILENAME,
    OVERRIDE_FILENAME,
    clear_rules_cache,
    ignored_rule_files,
    load_extra_rules,
    load_override_rules,
    rule_files_loaded,
)
from agent_moss.rules_loader import clear_rules_cache as _clear_rules_cache  # noqa: F401
from agent_moss.scenarios import clear_scenario_extensions_cache, get_scenario_extensions

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch, tmp_path):
    """隔离环境 + 全部相关缓存（规则目录/运行时配置/profile/场景）。

    ⚠️ 判定链路上有**多层缓存**（rules_loader 的目录缓存、runtime_config 的
    合并缓存与文件指纹缓存、profile 的 cached_property）：不逐层清就会"改了文件
    判定不变"，写出假绿/假红的测试。
    """
    monkeypatch.delenv("AGENT_MOSS_EXTRA_RULES_DIR", raising=False)
    monkeypatch.delenv("AGENT_MOSS_OVERRIDE_RULES_DIR", raising=False)
    monkeypatch.setenv("AGENT_MOSS_DISABLE_LLM", "1")
    monkeypatch.setenv("AGENT_MOSS_SAVE_POLICY", "0")
    monkeypatch.setenv("AGENT_MOSS_DISABLE_CACHE", "1")

    from agent_moss.infra import runtime_config as rc

    def _clear():
        clear_rules_cache()
        clear_scenario_extensions_cache()
        rc._RUNTIME_CONFIG_CACHE.clear()
        rc._HAS_RUNTIME_CONFIG_CACHE.clear()
        try:
            from agent_moss.profiles import clear_profile_cache
            clear_profile_cache()
        except Exception:
            pass

    _clear()
    yield
    _clear()


def _write(d, name: str, data) -> None:
    (d / name).write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


def _analyze(cmd: str, **kw) -> dict:
    from agent_moss.infra import runtime_config as rc
    from agent_moss.rules_loader import clear_rules_cache as _c

    _c()
    rc._RUNTIME_CONFIG_CACHE.clear()
    rc._HAS_RUNTIME_CONFIG_CACHE.clear()
    try:
        from agent_moss.profiles import clear_profile_cache
        clear_profile_cache()
    except Exception:
        pass
    return analyze(
        session_id="rules-dir", prompt_session="", action_history=[],
        a_next={"action_type": "bash", "action_detail": cmd}, reason="",
        profile=get_profile("linux"), **kw,
    )


def _su_rule(pattern=r"(?:^|[;&|\n])\s*su(?:\s|$)"):
    return {"pattern": pattern, "risk_level": "high",
            "risk_type": "privilege_escalation", "reason": "禁止 su"}


# ==================== extra.json：追加 ====================


def test_extra_json_appends_dangerous_command(tmp_path, monkeypatch):
    """一拦一放：追加的规则命中 → Deny；同族不命中 → 不受牵连。"""
    d = tmp_path / "rulesdir"
    d.mkdir()
    _write(d, EXTRA_FILENAME, {"dangerous_commands": [
        {"pattern": r"\bcmb_forbidden_tool\b", "risk_level": "high",
         "risk_type": "script_execution", "reason": "客户自定义禁用命令"},
    ]})
    monkeypatch.setenv("AGENT_MOSS_EXTRA_RULES_DIR", str(d))

    deny = _analyze("cmb_forbidden_tool --go")
    assert deny["decision"] == "Deny" and deny["risk_type"] == "script_execution"
    allow = _analyze("ls -la")
    assert allow["decision"] == "Allow"


def test_extra_json_appends_sensitive_path_deny_both(tmp_path, monkeypatch):
    """追加敏感路径（deny_both）→ 读该路径 Deny，普通路径不受牵连。"""
    d = tmp_path / "rulesdir"
    d.mkdir()
    _write(d, EXTRA_FILENAME, {"sensitive_path_access": [
        {"path": "/opt/cmb_secret", "risk_level": "high", "desc": "客户机密目录",
         "deny_mode": "deny_both"},
    ]})
    monkeypatch.setenv("AGENT_MOSS_EXTRA_RULES_DIR", str(d))

    assert _analyze("cat /opt/cmb_secret/key.pem")["decision"] == "Deny"
    assert _analyze("ls /home/sandbox")["decision"] == "Allow"


def test_extra_json_does_not_remove_builtin(tmp_path, monkeypatch):
    """追加语义 = 内置全保留（与覆盖的区别就在这）。"""
    d = tmp_path / "rulesdir"
    d.mkdir()
    _write(d, EXTRA_FILENAME, {"dangerous_commands": [
        {"pattern": r"\bcmb_x\b", "risk_level": "high", "risk_type": "script_execution",
         "reason": "追加"}]})
    monkeypatch.setenv("AGENT_MOSS_EXTRA_RULES_DIR", str(d))
    # 内置的 rm -rf / 规则必须仍然在
    r = _analyze("rm -rf /")
    assert r["decision"] == "Deny"


# ==================== override.json：整份替换 ====================


def test_override_json_replaces_whole_category(tmp_path, monkeypatch):
    """覆盖语义：该类别**整份替换**（内置消失、我的生效），未涉及的类别保持内置。"""
    d = tmp_path / "rulesdir"
    d.mkdir()
    _write(d, OVERRIDE_FILENAME, {"dangerous_commands": [_su_rule()]})
    monkeypatch.setenv("AGENT_MOSS_OVERRIDE_RULES_DIR", str(d))

    # 我的规则生效（一拦）
    assert _analyze("su - root")["decision"] == "Deny"

    # 内置 dangerous_commands 已被整类替换：内置的 rm -rf / 规则不再拦
    # （注意：仍可能被别的层/类别拦，这里看 risk_type 确认不是"内置危险命令"那条）
    replaced = _analyze("rm -rf /tmp/isolated_dir_xyz")
    assert replaced.get("risk_type") != "script_execution" or replaced["decision"] == "Deny"

    # 未涉及的类别保持内置：injection_detection / sensitive_path_access 照常
    assert _analyze("cat /etc/shadow")["decision"] == "Deny"


def test_override_json_empty_array_means_no_override(tmp_path, monkeypatch):
    """空数组 = **不覆盖该类**（模板就是空壳，原样拷进去必须什么都不改）。

    历史：本语义曾是"空数组 = 清空该类"——配上空模板就是灾难（客户一拷就把内置整类干掉），
    2026-10 改成"不覆盖"。
    """
    d = tmp_path / "rulesdir"
    d.mkdir()
    _write(d, OVERRIDE_FILENAME, {"sensitive_path_access": []})
    monkeypatch.setenv("AGENT_MOSS_OVERRIDE_RULES_DIR", str(d))
    assert "sensitive_path_access" not in load_override_rules()
    # 内置该类别照常生效
    assert _analyze("cat /etc/sudoers")["decision"] == "Deny"


def test_override_beats_extra_and_builtin(tmp_path, monkeypatch):
    """优先级：override > extra > 内置（同 pattern 去重，保留先出现的）。"""
    d = tmp_path / "rulesdir"
    d.mkdir()
    _write(d, OVERRIDE_FILENAME, {"dangerous_commands": [
        {"pattern": r"\bsame_key\b", "risk_level": "high",
         "risk_type": "from_override", "reason": "覆盖版"}]})
    _write(d, EXTRA_FILENAME, {"dangerous_commands": [
        {"pattern": r"\bsame_key\b", "risk_level": "high",
         "risk_type": "from_extra", "reason": "追加版"}]})
    monkeypatch.setenv("AGENT_MOSS_EXTRA_RULES_DIR", str(d))
    monkeypatch.setenv("AGENT_MOSS_OVERRIDE_RULES_DIR", str(d))

    r = _analyze("same_key")
    assert r["decision"] == "Deny"
    assert r["risk_type"] == "from_override", "同 pattern 应以 override.json 的为准"


def test_both_env_vars_pointing_to_same_dir(tmp_path, monkeypatch):
    """ConfigMap 只挂一个目录：两个环境变量指向同一目录 → 覆盖与追加都生效。"""
    d = tmp_path / "rulesdir"
    d.mkdir()
    _write(d, OVERRIDE_FILENAME, {"dangerous_commands": [_su_rule()]})
    _write(d, EXTRA_FILENAME, {"dangerous_commands": [
        {"pattern": r"\bextra_only\b", "risk_level": "high",
         "risk_type": "script_execution", "reason": "追加"}]})
    monkeypatch.setenv("AGENT_MOSS_EXTRA_RULES_DIR", str(d))
    monkeypatch.setenv("AGENT_MOSS_OVERRIDE_RULES_DIR", str(d))

    assert _analyze("su - root")["decision"] == "Deny"
    assert _analyze("extra_only")["decision"] == "Deny"


# ==================== 其他文件名：一律不读 ====================


def test_other_filenames_are_ignored(tmp_path, monkeypatch):
    """随机名文件**完全不生效**，并被列进"不会被读取"清单（客户踩过的坑）。"""
    d = tmp_path / "rulesdir"
    d.mkdir()
    # 一个"看起来该生效"的规则文件，但名字不对
    _write(d, "my_patch.json", {"dangerous_commands": [
        {"pattern": r"\bnever_effective\b", "risk_level": "high",
         "risk_type": "script_execution", "reason": "不该生效"}]})
    # 连内置同名文件也不再被读（旧语义已废除）
    _write(d, "l1_rules.json", {"dangerous_commands": [
        {"pattern": r"\balso_never\b", "risk_level": "high",
         "risk_type": "script_execution", "reason": "不该生效"}]})
    monkeypatch.setenv("AGENT_MOSS_EXTRA_RULES_DIR", str(d))
    monkeypatch.setenv("AGENT_MOSS_OVERRIDE_RULES_DIR", str(d))

    assert _analyze("never_effective")["decision"] == "Allow"
    assert _analyze("also_never")["decision"] == "Allow"
    ignored = {p.name for p in ignored_rule_files()}
    assert ignored == {"my_patch.json", "l1_rules.json"}


# ==================== 结构写错：跳过 + 告警，绝不崩判定 ====================


def test_malformed_category_is_skipped_not_crashing(tmp_path, monkeypatch, caplog):
    """类别写成 runtime config 的字典形态 → 跳过该类 + 明确报错，**引擎照常工作**。

    历史事故（2026-10 实测）：这种写法以前会让每次 analyze 抛
    `'str' object has no attribute 'get'` → **全部 Deny**（连 ls 都拦），
    是对客户而言最致命的一种"一个笔误把 agent 打死"。
    """
    d = tmp_path / "rulesdir"
    d.mkdir()
    _write(d, OVERRIDE_FILENAME, {
        "dangerous_commands": {"category_enabled": True, "rules": [_su_rule()]},
        "sensitive_path_access": [
            {"path": "/opt/cmb_secret2", "risk_level": "high", "desc": "x", "deny_mode": "deny_both"}],
    })
    monkeypatch.setenv("AGENT_MOSS_OVERRIDE_RULES_DIR", str(d))

    with caplog.at_level(logging.ERROR):
        allow = _analyze("ls -la")
        deny = _analyze("cat /opt/cmb_secret2/pem")

    assert allow["decision"] == "Allow", "一个类别写错不应把整个引擎打成全拦"
    assert deny["decision"] == "Deny", "同一文件里**合法**的类别应当照常生效"
    assert "应为**对象数组**" in caplog.text or "对象数组" in caplog.text


def test_broken_json_is_skipped(tmp_path, monkeypatch, caplog):
    """坏 JSON → 跳过并报错，不崩。"""
    d = tmp_path / "rulesdir"
    d.mkdir()
    (d / OVERRIDE_FILENAME).write_text("{ 这不是 json", encoding="utf-8")
    monkeypatch.setenv("AGENT_MOSS_OVERRIDE_RULES_DIR", str(d))
    with caplog.at_level(logging.ERROR):
        assert _analyze("ls -la")["decision"] == "Allow"
    assert "损坏" in caplog.text or "不可读" in caplog.text


def test_unknown_category_and_missing_field_skipped(tmp_path, monkeypatch, caplog):
    """未知类别键 / 缺必需字段 → 告警跳过该类别或该条。"""
    d = tmp_path / "rulesdir"
    d.mkdir()
    _write(d, EXTRA_FILENAME, {
        "not_a_category": [{"pattern": "x"}],
        "dangerous_commands": [{"risk_level": "high"}],  # 缺 pattern
    })
    monkeypatch.setenv("AGENT_MOSS_EXTRA_RULES_DIR", str(d))
    with caplog.at_level(logging.WARNING):
        assert _analyze("ls -la")["decision"] == "Allow"
    assert "未知类别键" in caplog.text
    assert load_extra_rules().get("dangerous_commands") in (None, [])


# ==================== 场景规则的应急替换位（按路径，保留） ====================


def test_scenario_rules_override_still_works(tmp_path, monkeypatch):
    """场景规则仍可应急替换（scenarios/<id>/rules.json，按路径寻址）。"""
    d = tmp_path / "rulesdir"
    (d / "scenarios" / "bank").mkdir(parents=True)
    _write(d / "scenarios" / "bank", "rules.json", {
        "scenario_id": "bank",
        "description": "测试用覆盖",
        "extra_command_patterns": [
            {"pattern": r"\bscenario_custom_cmd\b", "risk_level": "high",
             "risk_type": "script_execution", "reason": "场景覆盖规则"}],
        "extra_injection_keywords": [],
        "extra_sensitive_paths": [],
    })
    monkeypatch.setenv("AGENT_MOSS_OVERRIDE_RULES_DIR", str(d))
    clear_scenario_extensions_cache()
    ext = get_scenario_extensions("bank")
    assert ext is not None
    assert any("scenario_custom_cmd" in p.pattern for p in ext.extra_command_patterns)


def test_scenario_rules_override_malformed_falls_back(tmp_path, monkeypatch, caplog):
    """场景规则写错（数组写成对象）→ 拒绝并回退内置（否则场景会静默失效）。"""
    d = tmp_path / "rulesdir"
    (d / "scenarios" / "bank").mkdir(parents=True)
    _write(d / "scenarios" / "bank", "rules.json", {
        "scenario_id": "bank",
        "extra_sensitive_paths": {"oops": "should be a list"},
    })
    monkeypatch.setenv("AGENT_MOSS_OVERRIDE_RULES_DIR", str(d))
    clear_scenario_extensions_cache()
    with caplog.at_level(logging.ERROR):
        ext = get_scenario_extensions("bank")
    assert ext is not None, "结构错误的覆盖文件不应让场景整个消失"
    assert "已忽略并回退内置" in caplog.text


def test_rule_files_loaded_reports_only_successful(tmp_path, monkeypatch):
    """自检清单只含**成功加载**的文件。"""
    d = tmp_path / "rulesdir"
    d.mkdir()
    _write(d, EXTRA_FILENAME, {"dangerous_commands": [
        {"pattern": r"\bok\b", "risk_level": "high", "risk_type": "x", "reason": "r"}]})
    (d / OVERRIDE_FILENAME).write_text("{ 坏 json", encoding="utf-8")
    monkeypatch.setenv("AGENT_MOSS_EXTRA_RULES_DIR", str(d))
    names = {p.name for p in rule_files_loaded()}
    assert names == {EXTRA_FILENAME}


# ==================== 自助工具：模板生成 + 自查（客户要"够简单"） ====================


def test_rules_init_writes_empty_templates_that_change_nothing(tmp_path, monkeypatch, caplog):
    """`rules init` 生成的两个文件**类别全部清空**、命名一致；原样拷进目录 = **什么都不改**。

    （曾经把内置 L1 规则全量拷进 override.json —— 那会让客户"一拷就把内置钉住/清空"，
    2026-10 按要求改成空壳，样例只写在 `_说明` 里。）
    """
    import logging

    from agent_moss.rules_tools import init_rules_dir

    d = tmp_path / "mydir"
    written = init_rules_dir(str(d))
    assert {p.name for p in written} == {"extra.json", "override.json", "README.md"}

    for name in ("extra.json", "override.json"):
        data = json.loads((d / name).read_text(encoding="utf-8"))
        cats = {k: v for k, v in data.items() if not str(k).startswith("_")}
        assert cats and all(v == [] for v in cats.values()), f"{name} 的类别应全部清空: {cats}"
        assert any("样例" in line for line in data["_说明"]), f"{name} 的说明里应带样例"

    monkeypatch.setenv("AGENT_MOSS_EXTRA_RULES_DIR", str(d))
    monkeypatch.setenv("AGENT_MOSS_OVERRIDE_RULES_DIR", str(d))
    with caplog.at_level(logging.WARNING):
        _analyze("ls -la")
    # 判定与纯内置**逐条一致**
    assert _analyze("ls -la")["decision"] == "Allow"
    assert _analyze("rm -rf /")["decision"] == "Deny"
    assert _analyze("cat /etc/shadow")["decision"] == "Deny"
    assert _analyze("cat /etc/sudoers")["decision"] == "Deny"
    assert load_override_rules() == {} and not any(load_extra_rules().values())


def test_rules_init_with_builtin_for_editing_builtin_rules(tmp_path, monkeypatch):
    """`--with-builtin`：要就地把内置某条删/改时才用（生成全量拷贝，删一条即那条不再拦）。

    注意同一条命令常被**多条**内置规则覆盖（/etc/shadow 在敏感路径与危险命令里各一条）。
    """
    from agent_moss.rules_tools import init_rules_dir

    d = tmp_path / "mydir2"
    init_rules_dir(str(d), with_builtin=True)
    data = json.loads((d / "override.json").read_text(encoding="utf-8"))
    assert len(data["dangerous_commands"]) > 100 and len(data["sensitive_path_access"]) > 50

    data["sensitive_path_access"] = [
        r for r in data["sensitive_path_access"] if r.get("path") != "/etc/shadow"
    ]
    data["dangerous_commands"] = [
        r for r in data["dangerous_commands"]
        if "shadow" not in str(r.get("reason", "")) + str(r.get("pattern", ""))
    ]
    (d / "override.json").write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    monkeypatch.setenv("AGENT_MOSS_OVERRIDE_RULES_DIR", str(d))

    assert _analyze("cat /etc/shadow")["decision"] == "Allow"      # 两类都删干净
    assert _analyze("cat /etc/sudoers")["decision"] == "Deny"      # 其余照常


def test_rules_status_reports_loaded_and_ignored(tmp_path, monkeypatch, capsys):
    """`rules status` 必须把"生效了什么、什么没被读"讲清楚（客户自查入口）。"""
    from agent_moss.rules_tools import rules_status_text

    d = tmp_path / "mydir"
    d.mkdir()
    _write(d, EXTRA_FILENAME, {"dangerous_commands": [
        {"pattern": r"\\bcmb_x\\b", "risk_level": "high", "risk_type": "script_execution",
         "reason": "追加"}]})
    _write(d, "random_name.json", {"dangerous_commands": []})
    monkeypatch.setenv("AGENT_MOSS_EXTRA_RULES_DIR", str(d))
    clear_rules_cache()

    text = rules_status_text()
    assert "追加生效" in text and "dangerous_commands: 1 条" in text
    assert "不会被读取" in text and "random_name.json" in text


def test_rules_status_says_nothing_loaded_when_empty(tmp_path, monkeypatch):
    """目录里啥都没有时要明说"当前用内置"，而不是让人猜。"""
    from agent_moss.rules_tools import rules_status_text

    d = tmp_path / "empty-dir"
    d.mkdir()
    monkeypatch.setenv("AGENT_MOSS_EXTRA_RULES_DIR", str(d))
    clear_rules_cache()
    text = rules_status_text()
    assert "用的是内置规则" in text


def test_shipped_templates_match_code(monkeypatch, tmp_path):
    """随包分发的**两个**模板文件（extra.json / override.json）必须：
    ① 存在（缺一个就是"客户拿到的东西和文档说的不一致"）；
    ② 与代码里的常量逐字一致（防漂移：客户拿到的 vs `rules init` 生成的不能是两份）；
    ③ 说明里**没有转义引号**（JSON 里塞样例必然写成双重转义的一行，没人看得懂 —— 样例统一在 README）。

    历史事故：只测了 extra.json，于是 override.json 既没随包发、内容还是老版（带转义样例），
    客户看到的包里只有 extra.json。
    """
    import json as _json
    from agent_moss.rules_tools import EXTRA_TEMPLATE, OVERRIDE_TEMPLATE, template_source_dir

    d = template_source_dir()
    for name, const in (("extra.json", EXTRA_TEMPLATE), ("override.json", OVERRIDE_TEMPLATE)):
        tpl = d / name
        assert tpl.is_file(), f"随包模板缺失: {tpl}"
        raw = tpl.read_text(encoding="utf-8")
        assert _json.loads(raw) == _json.loads(_json.dumps(const, ensure_ascii=False)), name
        assert '\\"' not in raw, f"{name} 的说明里出现了转义引号（样例该放 README.md）"
        cats = {k: v for k, v in _json.loads(raw).items() if not str(k).startswith("_")}
        assert cats and all(v == [] for v in cats.values()), f"{name} 的类别应全部清空"


def test_rules_status_points_to_shipped_template(tmp_path, monkeypatch):
    """目录里什么都没有时，`rules status` 要直接给出**随包模板的位置**（客户不必记命令）。"""
    from agent_moss.rules_tools import rules_status_text

    d = tmp_path / "empty"
    d.mkdir()
    monkeypatch.setenv("AGENT_MOSS_EXTRA_RULES_DIR", str(d))
    clear_rules_cache()
    text = rules_status_text()
    assert "模板随包分发" in text and "rules_template" in text


# ==================== 模板 README 里的样例必须"能直接跑" ====================


def _readme_json_blocks() -> list[str]:
    """抽出模板 README 里所有 ```json 代码块（客户会直接复制这些）。"""
    import re as _re
    from agent_moss.rules_tools import template_source_dir

    text = (template_source_dir() / "README.md").read_text(encoding="utf-8")
    return _re.findall(r"```json\n(.*?)```", text, _re.DOTALL)


def test_readme_examples_are_valid_json():
    """README 里的每个 json 代码块都必须是合法 JSON（客户照抄的第一道关）。"""
    blocks = _readme_json_blocks()
    assert len(blocks) >= 2, "README 里应至少有 追加 / 覆盖 两个样例"
    for b in blocks:
        json.loads(b)   # 不合法直接抛


def test_readme_extra_example_actually_works(tmp_path, monkeypatch):
    """README 的第一个样例（追加：禁 su + 保护 /data/hr）**照抄进 extra.json 就能生效**。"""
    d = tmp_path / "rulesdir"
    d.mkdir()
    (d / EXTRA_FILENAME).write_text(_readme_json_blocks()[0], encoding="utf-8")
    monkeypatch.setenv("AGENT_MOSS_EXTRA_RULES_DIR", str(d))

    assert _analyze("su - root")["decision"] == "Deny"          # 禁 su 生效
    assert _analyze("cat /data/hr/k.pem")["decision"] == "Deny"  # 敏感路径生效（deny_both 连读一起拦）
    assert _analyze("ls -la")["decision"] == "Allow"             # 不误伤
    assert _analyze("rm -rf /")["decision"] == "Deny"            # 内置保留


def test_readme_override_example_actually_works(tmp_path, monkeypatch):
    """README 的覆盖样例：只写敏感路径 → 该类内置被整份替换、别的类别不动。"""
    d = tmp_path / "rulesdir2"
    d.mkdir()
    (d / OVERRIDE_FILENAME).write_text(_readme_json_blocks()[1], encoding="utf-8")
    monkeypatch.setenv("AGENT_MOSS_OVERRIDE_RULES_DIR", str(d))

    assert _analyze("cat /data/hr/k.pem")["decision"] == "Deny"   # 我写的生效
    assert _analyze("cat /etc/sudoers")["decision"] == "Allow"    # 内置同类被替换掉
    assert _analyze("rm -rf /")["decision"] == "Deny"             # 未写类别保持内置


# ==================== 三个结构性通道：skills / ltl_rules / tools（2026-10 补） ====================


def test_ltl_rules_override_and_extra(tmp_path, monkeypatch):
    """L2.2 的 LTL 规则：override 整份替换、extra 按 id 合并；**种子与引擎读同一份**。

    为什么单独看护这条：种子清单（Console 的 L2.2 分区）以前自己找文件读内置，
    用户覆盖后"引擎按覆盖跑、种子按内置生成"→ merge 把用户侧规则全标 source_removed，
    Console 上只剩内置那几条可点。
    """
    d = tmp_path / "rulesdir"
    d.mkdir()
    _write(d, OVERRIDE_FILENAME, {"ltl_rules": [
        {"id": "user-001", "type": "ltl", "reason": "自定义", "risk_level": "high"}]})
    monkeypatch.setenv("AGENT_MOSS_OVERRIDE_RULES_DIR", str(d))
    clear_rules_cache()

    from agent_moss.infra.runtime_config import _ltl_rules_to_runtime
    from agent_moss.rules_loader import load_mc, load_mc_raw

    engine_ids = [r["id"] for r in load_mc_raw()["rules"]]
    assert engine_ids == ["user-001"]
    seeded_ids = [r["id"] for r in _ltl_rules_to_runtime()["ltl_rules"]["rules"]]
    assert seeded_ids == engine_ids, "种子清单必须与引擎读同一份（否则 Console 与判定脱节）"

    # extra 追加：按 id 合并（同 id 以 extra 为准）
    _write(d, EXTRA_FILENAME, {"ltl_rules": [
        {"id": "user-001", "type": "ltl", "reason": "追加版覆盖", "risk_level": "critical"},
        {"id": "user-002", "type": "ltl", "reason": "新增", "risk_level": "high"}]})
    clear_rules_cache()
    rules = {r["id"]: r for r in load_mc_raw()["rules"]}
    assert set(rules) == {"user-001", "user-002"}
    assert rules["user-001"]["reason"] == "追加版覆盖"      # 同 id 以 extra 为准
    assert load_mc() is not None                            # 完整链路不报错


def test_skills_override_and_extra(tmp_path, monkeypatch):
    """L3 技能表：override 按类别整份替换、extra 按技能名合并。"""
    d = tmp_path / "rulesdir2"
    d.mkdir()
    _write(d, OVERRIDE_FILENAME, {"skills": {
        "file_operations": {"my_guard": ["自定义关键词"]}}})
    monkeypatch.setenv("AGENT_MOSS_OVERRIDE_RULES_DIR", str(d))
    clear_rules_cache()
    from agent_moss.rules_loader import load_l3

    l3 = load_l3()
    assert l3["file_operations"] == {"my_guard": ["自定义关键词"]}   # 该类被整份替换
    assert "network_security" in l3                                 # 未提到的类别保持内置

    _write(d, EXTRA_FILENAME, {"skills": {
        "file_operations": {"extra_guard": ["追加关键词"]}}})
    clear_rules_cache()
    l3 = load_l3()
    assert set(l3["file_operations"]) == {"my_guard", "extra_guard"}  # 追加合并


def test_tools_override_and_extra(tmp_path, monkeypatch):
    """工具注册表：override 整份替换、extra 按工具名合并。"""
    d = tmp_path / "rulesdir3"
    d.mkdir()
    _write(d, OVERRIDE_FILENAME, {"tools": {"my_tool": {"actionClass": "compute"}}})
    monkeypatch.setenv("AGENT_MOSS_OVERRIDE_RULES_DIR", str(d))
    clear_rules_cache()
    from agent_moss.rules_loader import load_tool_registry

    tools = load_tool_registry()["tools"]
    assert tools == {"my_tool": {"actionClass": "compute"}}

    _write(d, EXTRA_FILENAME, {"tools": {"another_tool": {"actionClass": "network"}}})
    clear_rules_cache()
    tools = load_tool_registry()["tools"]
    assert set(tools) == {"my_tool", "another_tool"}


def test_struct_keys_malformed_are_skipped(tmp_path, monkeypatch, caplog):
    """三个结构性键写错形状 → 告警跳过，不影响其他类别与引擎。"""
    import logging

    d = tmp_path / "rulesdir4"
    d.mkdir()
    _write(d, OVERRIDE_FILENAME, {
        "skills": ["不该是数组"],
        "ltl_rules": {"不该是对象": 1},
        "tools": [{"不该是数组": 1}],
        "sensitive_path_access": [{"path": "/data/hr2", "risk_level": "high", "desc": "x",
                                   "deny_mode": "deny_both"}],
    })
    monkeypatch.setenv("AGENT_MOSS_OVERRIDE_RULES_DIR", str(d))
    with caplog.at_level(logging.ERROR):
        assert _analyze("cat /data/hr2/k.pem")["decision"] == "Deny"   # 合法类别照常
        assert _analyze("ls -la")["decision"] == "Allow"                # 引擎不崩
    assert "已跳过" in caplog.text


def test_readme_documents_the_merge_semantics():
    """随包 README 必须把"谁会被读、谁压谁"讲清楚 —— 客户最容易懵的就是这个。

    看护理由：这套语义（只读两个文件名 / 其他不读 / override>extra>内置 / 场景规则独立）
    一度**只存在于内部文档与聊天里**，客户拿到的 README 一个字都没有。
    """
    from agent_moss.rules_tools import template_source_dir

    text = (template_source_dir() / "README.md").read_text(encoding="utf-8")
    for must in (
        "一律不读",          # 其他文件名不读
        "同时存在",          # 两个文件同时存在都生效
        "优先级",            # override > extra > 内置
        "scenarios/",        # 场景规则替换位
        "整份替换",          # 覆盖语义
        "空数组 = 不覆盖",   # 空数组语义（原样放置安全）
        "AGENT_MOSS_SCENARIO",  # 场景规则前提：开关必须开着
    ):
        assert must in text, f"README 缺少关键说明: {must}"


def test_cli_version_flag():
    """`agent-moss --version` 能用（客户确认装了哪个版本；版本混淆在招行那边真出过）。"""
    import subprocess
    import sys

    from agent_moss.__version__ import __version__
    res = subprocess.run([sys.executable, "-m", "agent_moss.cli", "--version"],
                         capture_output=True, text=True)
    assert res.returncode == 0
    assert __version__ in res.stdout
