"""`agent-moss doctor` 部署自检的行为看护。

要求：
- 不修改任何文件（只读）
- 隔离数据目录，不碰真实 HOME
- 关键项（规则加载、磁盘、环境变量）能被检出
"""

from __future__ import annotations

import json


def _run(tmp_path, monkeypatch, **env):
    monkeypatch.setenv("AGENT_MOSS_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("AGENT_MOSS_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("AGENT_MOSS_DISABLE_LLM", "1")
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    from agent_moss.doctor import run_doctor

    return run_doctor(include_llm=False)


def _by_name(report, name):
    return next(r for r in report.results if r.name == name)


def test_checks_cover_core_items(tmp_path, monkeypatch):
    report = _run(tmp_path, monkeypatch)
    names = [r.name for r in report.results]
    for expected in ("数据目录", "规则包", "L1 规则", "链状态库", "磁盘空间", "环境变量"):
        assert expected in names, f"缺少检查项 {expected}"


def test_rule_counts_loaded(tmp_path, monkeypatch):
    report = _run(tmp_path, monkeypatch)
    r = _by_name(report, "L1 规则")
    # 规则文件没加载 = 危险命令 0 条，必须报失败而不是"通过"
    assert r.status == "ok", r.detail
    assert "危险命令" in r.detail


def test_flags_zero_pool_as_warning(tmp_path, monkeypatch):
    report = _run(tmp_path, monkeypatch, AGENT_MOSS_POOL_BIZ="0")
    r = _by_name(report, "环境变量")
    assert r.status == "warn"
    assert "POOL_BIZ" in r.detail


def test_flags_invalid_trace_level(tmp_path, monkeypatch):
    report = _run(tmp_path, monkeypatch, AGENT_MOSS_TRACE_LEVEL="verbose")
    r = _by_name(report, "环境变量")
    assert r.status == "warn"
    assert "TRACE_LEVEL" in r.detail


def test_reports_missing_api_key(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir(parents=True, exist_ok=True)
    (data / "config.json").write_text(
        json.dumps({"llm": {"model": "m", "base_url": "http://x/v1"}}), encoding="utf-8"
    )
    report = _run(tmp_path, monkeypatch)
    r = _by_name(report, "LLM 模型")
    assert r.status == "warn"
    assert "api_key" in r.hint


def test_reports_invalid_extra_body_type(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir(parents=True, exist_ok=True)
    (data / "config.json").write_text(
        json.dumps({"llm": {"model": "m", "api_key": "k", "extra_body": "oops"}}),
        encoding="utf-8",
    )
    report = _run(tmp_path, monkeypatch)
    r = _by_name(report, "LLM extra_body")
    assert r.status == "fail"


def test_doctor_is_read_only(tmp_path, monkeypatch):
    """跑一遍 doctor 不能留下任何文件。"""
    data = tmp_path / "data"
    data.mkdir(parents=True, exist_ok=True)
    before = {p.name for p in data.iterdir()}
    _run(tmp_path, monkeypatch)
    after = {p.name for p in data.iterdir()}
    assert before == after
