# -*- coding: utf-8 -*-
"""部署自检日志的看护。

为什么需要（2026-09 招行客户实例）：客户反馈「简单的路径绕过都不拦」，排查下来是
**场景规则压根没启用**（`AGENT_MOSS_SCENARIO` 未设置）—— 此时 bank 沙箱的目录白名单
一条都不跑，**所有路径都放行**，而服务启动没有任何提示。这类「静默失效」是安全产品
最不该有的，故启动时必须把「场景规则是否启用」喊出来。

"""

import logging
import os

import pytest


@pytest.fixture()
def clean_env(monkeypatch, tmp_path):
    """隔离数据目录，并清掉可能影响自检的环境变量。"""
    monkeypatch.setenv("AGENT_MOSS_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("AGENT_MOSS_SCENARIO", raising=False)
    return monkeypatch


def _capture(caplog, fn):
    with caplog.at_level(logging.INFO, logger="agent_moss.server.app"):
        fn()
    return "\n".join(r.getMessage() for r in caplog.records)


def test_warns_when_scenario_not_enabled(clean_env, caplog):
    """未设 AGENT_MOSS_SCENARIO → 必须**明确警告**场景规则不会生效。"""
    from agent_moss.server.app import _log_deployment_selfcheck

    out = _capture(caplog, _log_deployment_selfcheck)
    assert "场景规则【未启用】" in out, out
    assert "AGENT_MOSS_SCENARIO" in out
    # 必须讲清后果与启用方式，否则客户看不懂
    assert "不会生效" in out
    assert "重启" in out


def test_reports_enabled_scenario(clean_env, caplog):
    """设了 → 报告具体场景 id，且不再出现未启用警告。"""
    clean_env.setenv("AGENT_MOSS_SCENARIO", "bank")
    from agent_moss.server.app import _log_deployment_selfcheck

    out = _capture(caplog, _log_deployment_selfcheck)
    assert "场景规则已启用: bank" in out
    assert "未启用" not in out


def test_reports_multi_scenario_and_layers(clean_env, caplog):
    """多场景逗号分隔照常展示；层级开关一并打出来（关掉的层要看得见）。"""
    clean_env.setenv("AGENT_MOSS_SCENARIO", "bank,meow")
    from agent_moss.server.app import _log_deployment_selfcheck

    out = _capture(caplog, _log_deployment_selfcheck)
    assert "bank,meow" in out
    assert "L1_heuristic=on" in out
    assert "scenario_rules_enabled=on" in out


def test_never_raises(clean_env, caplog):
    """自检失败不能影响服务启动。"""
    from agent_moss.server import app as app_mod

    orig = app_mod.os.getenv

    def boom(*a, **k):
        raise RuntimeError("模拟自检异常")

    app_mod.os.getenv = boom  # type: ignore[attr-defined]
    try:
        _capture(caplog, app_mod._log_deployment_selfcheck)  # 不应抛
    finally:
        app_mod.os.getenv = orig  # type: ignore[attr-defined]
