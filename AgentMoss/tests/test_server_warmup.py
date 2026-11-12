# -*- coding: utf-8 -*-
"""引擎预热（消除服务重启后第一个请求的冷启动延迟）的回归测试。

背景：引擎模块树是在请求处理函数里惰性 import 的，规则的加载与正则编译也发生在
首次 analyze() 时 —— 于是重启后**第一个请求**要替所有人付这笔钱。实测（全新实例，
只用 health 预热客户端、不碰引擎）：

    修复前：第 1 个 analyze 131.6ms / 65.6ms，第 2 个 14.5ms / 7.6ms
    修复后：第 1 个 analyze  11.8ms / 12.7ms，第 2 个  7.6ms /  6.6ms

这里守的是三件事：启动钩子确实调了预热、预热不落盘、预热失败不拖垮启动。
"""

import pytest


def test_startup_runs_warm_up(monkeypatch):
    """启动钩子必须真的调用预热 —— 否则冷启动会悄悄回来。"""
    from fastapi.testclient import TestClient

    import agent_moss.server.app as app_module

    calls: list[int] = []
    monkeypatch.setattr(app_module, "_warm_up_engine", lambda: calls.append(1))

    with TestClient(app_module.create_app()):
        pass  # 进入 context manager 即触发 startup 事件

    assert calls == [1], "startup 没有调用 _warm_up_engine"


def test_warm_up_leaves_no_policy_file(tmp_path, monkeypatch):
    """预热不能落盘。

    预热命令走白名单快速放行，而白名单放行**也会**写 Policy 文件 —— 不在预热
    期间临时关掉落盘的话，每次重启都会在 policy 目录留下一个
    ``__startup_warmup__.toml``。
    """
    from agent_moss.engine import analyzer
    from agent_moss.server.app import _warm_up_engine

    policy_dir = tmp_path / "policy"
    monkeypatch.setattr(analyzer, "POLICY_OUTPUT_DIR", policy_dir)
    monkeypatch.setenv("AGENT_MOSS_SAVE_POLICY", "1")  # 默认值就是开启落盘

    _warm_up_engine()

    leftovers = list(policy_dir.rglob("__startup_warmup__*")) if policy_dir.exists() else []
    assert leftovers == [], f"预热留下了 Policy 文件: {leftovers}"


def test_warm_up_restores_save_policy_setting(tmp_path, monkeypatch):
    """预热期间临时改的 AGENT_MOSS_SAVE_POLICY 必须原样还原。

    没还原的话，之后所有真实请求都不会再写 Policy 文件 —— 而执行侧沙箱要靠
    这个文件做隔离，属于静默失效。
    """
    import os

    from agent_moss.server.app import _warm_up_engine

    monkeypatch.setenv("AGENT_MOSS_SAVE_POLICY", "1")
    _warm_up_engine()
    assert os.environ["AGENT_MOSS_SAVE_POLICY"] == "1"

    # 原本没设过这个变量时，预热结束后也不该凭空多出来
    monkeypatch.delenv("AGENT_MOSS_SAVE_POLICY", raising=False)
    _warm_up_engine()
    assert "AGENT_MOSS_SAVE_POLICY" not in os.environ


def test_warm_up_failure_does_not_break_startup(monkeypatch):
    """预热失败只告警，不能抛异常 —— 否则服务直接起不来。"""
    from agent_moss.engine import analyzer
    from agent_moss.server.app import _warm_up_engine

    def _boom(**kwargs):
        raise RuntimeError("引擎炸了")

    monkeypatch.setattr(analyzer, "analyze", _boom)

    _warm_up_engine()  # 不应抛出
