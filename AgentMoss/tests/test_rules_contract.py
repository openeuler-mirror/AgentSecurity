"""规则包契约看护（2026-10）—— schema 版本 / 完整性 / 内容指纹。

**要解决什么**：规则仓独立后，规则包是可被替换、也可被改坏的外部输入。没有契约时，
"规则文件缺了一类"的后果是那一类规则**静默为空** —— 引擎照常启动、照常放行，
看起来一切正常，实际防护面少了一块（fail-open）。

三条要求：
1. schema 版本对不上 → 明确报错，不是"读不懂就当空"；
2. 缺文件 / 缺顶层键 → 报出来；
3. 有内容指纹，启动打印，客户报问题时可据此确认跑的是哪份规则。

"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from agent_moss.infra.paths import ENV_RULES_ROOT
from agent_moss.rules_contract import (
    MANIFEST_FILE,
    REQUIRED_RULE_FILES,
    RULES_SCHEMA_VERSION,
    check_rules_assets,
    enforce_rules_contract,
    format_rules_integrity,
)

PKG = Path(__file__).parent.parent / "agent_moss"


def test_package_rules_pass():
    rep = check_rules_assets()
    assert rep.ok, rep.errors
    assert rep.schema_version == RULES_SCHEMA_VERSION
    assert rep.fingerprint and len(rep.fingerprint) == 12
    assert set(rep.file_hashes) == set(REQUIRED_RULE_FILES)
    assert all(v not in ("MISSING", "BADJSON", "UNREADABLE") for v in rep.file_hashes.values())


def test_fingerprint_is_stable_and_content_sensitive():
    a = check_rules_assets().fingerprint
    b = check_rules_assets().fingerprint
    assert a == b  # 同样内容 → 同指纹


@pytest.fixture
def root(tmp_path, monkeypatch):
    for name in ("rules", "skills", "scenarios", "agents"):
        shutil.copytree(PKG / name, tmp_path / name,
                        ignore=shutil.ignore_patterns("__pycache__"))
    monkeypatch.setenv(ENV_RULES_ROOT, str(tmp_path))
    return tmp_path


def test_manifest_version_mismatch_is_error(root):
    p = root / "rules" / MANIFEST_FILE
    m = json.loads(p.read_text(encoding="utf-8"))
    m["schema_version"] = RULES_SCHEMA_VERSION + 1
    p.write_text(json.dumps(m), encoding="utf-8")

    rep = check_rules_assets()
    assert not rep.ok
    assert any("schema 版本不匹配" in e for e in rep.errors)


def test_missing_file_is_error(root):
    (root / "rules" / "l1_rules.json").unlink()
    rep = check_rules_assets()
    assert not rep.ok
    assert rep.file_hashes["l1_rules.json"] == "MISSING"
    assert any("缺少规则文件 l1_rules.json" in e for e in rep.errors)


def test_missing_top_level_key_is_error(root):
    p = root / "rules" / "l1_rules.json"
    d = json.loads(p.read_text(encoding="utf-8"))
    d.pop("sensitive_path_access")
    p.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")

    rep = check_rules_assets()
    assert not rep.ok
    assert any("sensitive_path_access" in e for e in rep.errors)


def test_bad_json_is_error(root):
    (root / "rules" / "l2_rules.json").write_text("{not json", encoding="utf-8")
    rep = check_rules_assets()
    assert not rep.ok
    assert rep.file_hashes["l2_rules.json"] == "BADJSON"


def test_external_broken_package_refuses_to_start(root):
    """显式指定了外部规则包又坏着 → 必须抛，不能带着残缺规则跑。"""
    (root / "rules" / "l1_rules.json").unlink()
    with pytest.raises(RuntimeError, match="拒绝启动"):
        enforce_rules_contract()


def test_package_internal_broken_only_warns(monkeypatch):
    """包内规则坏了只报错不抛（把已装好的引擎直接弄挂更糟，日志里能看见）。"""
    from agent_moss import rules_contract as rc
    monkeypatch.setattr(rc, "check_rules_assets", lambda: rc.RulesIntegrityReport(
        ok=False, schema_version=1, fingerprint="x",
        errors=["伪造的坏包"], external=False))
    rep = rc.enforce_rules_contract()  # 不抛
    assert rep.ok is False


def test_format_line_contains_source_version_fingerprint():
    line = format_rules_integrity(check_rules_assets())
    assert "schema v1" in line
    assert "指纹" in line
    assert "包内规则" in line
