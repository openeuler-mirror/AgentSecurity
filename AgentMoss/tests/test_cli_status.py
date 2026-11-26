# -*- coding: utf-8 -*-
"""``agent-moss status`` 的多实例可见性（2026-11）。

事故背景：同机同时装了两套 AgentMoss（WSL 的 instance=xiaoo + Windows 的
instance 为空）。在 shell 里跑 ``status`` 时没有 ``AGENT_MOSS_INSTANCE``，
于是：

- 匹配到了 **另一个系统** 的实例（9092），却没有任何提示；
- 输出里没有 Instance 行（只在设了变量时才打印），用户完全看不出这是谁；
- 只列"第一个命中的"，同机另外两个实例根本不显示。

同时 ``status != "healthy"`` 直接跳过，服务进入 ``degraded``（链状态触顶 /
LLM 熔断）时会被报成"未运行"，运维会去重启一个活着的服务。

看护这三点：Instance 行总在、多实例全列、degraded 算运行中。
"""

from __future__ import annotations

import io
import json

import pytest

from agent_moss import cli


class _FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):  # noqa: D105
        return False


def _patch_probe(monkeypatch, instances: dict[int, dict]) -> None:
    """把端口探测换成固定响应。``instances`` = {端口: health 响应体}。"""

    def fake_urlopen(req, timeout=None):  # noqa: ARG001
        url = getattr(req, "full_url", str(req))
        if "console/api/config" in url:
            raise OSError("skip config probe")
        port = int(url.split("://", 1)[1].split(":")[1].split("/")[0])
        if port not in instances:
            raise OSError("no service")
        return _FakeResp(json.dumps(instances[port]).encode())

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    # systemd 查询与测试无关，固定为"未注册"
    class _R:
        returncode = 1
        stdout = ""
        stderr = ""

    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: _R())


def _run_status(monkeypatch, capsys) -> str:
    cli.cmd_status(None)
    return capsys.readouterr().out


def test_instance_line_always_present_and_others_listed(
    monkeypatch,
    capsys,
) -> None:
    """设了 instance：选中同名实例，其余实例全部列出并标注同名。"""
    _patch_probe(
        monkeypatch,
        {
            9090: {"status": "healthy", "instance": "xiaoo", "version": "0.17.22"},
            9091: {"status": "healthy", "instance": "xiaoo", "version": "0.17.33"},
            9092: {"status": "healthy", "instance": "", "version": "0.17.41"},
        },
    )
    monkeypatch.setenv("AGENT_MOSS_INSTANCE", "xiaoo")

    out = _run_status(monkeypatch, capsys)

    assert "Instance: xiaoo" in out
    assert "端口:     9090" in out, "第一个同名实例应被选中"
    # 另一个同名实例必须列出来并标注，否则升级残留的旧/新进程看不出来
    assert "端口 9091  instance=xiaoo  v0.17.33" in out
    assert "与本实例同名" in out
    # 不同名的实例也要可见
    assert "端口 9092  instance=(空)  v0.17.41" in out


def test_no_instance_env_warns_and_lists_all(monkeypatch, capsys) -> None:
    """没设 instance：明确告知选中了空 instance，并列出所有实例。"""
    _patch_probe(
        monkeypatch,
        {
            9091: {"status": "healthy", "instance": "xiaoo", "version": "0.17.33"},
            9092: {"status": "healthy", "instance": "", "version": "0.17.41"},
        },
    )
    monkeypatch.delenv("AGENT_MOSS_INSTANCE", raising=False)

    out = _run_status(monkeypatch, capsys)

    assert "Instance: (未指定)" in out
    assert "未设置 AGENT_MOSS_INSTANCE" in out
    assert "端口:     9092" in out
    assert "端口 9091  instance=xiaoo  v0.17.33" in out


def test_degraded_instance_counts_as_running(monkeypatch, capsys) -> None:
    """degraded（能力降级但进程活着）不能被报成"未运行"。"""
    _patch_probe(
        monkeypatch,
        {
            9090: {
                "status": "degraded",
                "instance": "xiaoo",
                "version": "0.17.41",
                "degraded": ["链状态时间线已满"],
            },
        },
    )
    monkeypatch.setenv("AGENT_MOSS_INSTANCE", "xiaoo")

    out = _run_status(monkeypatch, capsys)

    assert "服务运行中" in out
    assert "未运行" not in out
    assert "端口:     9090" in out


def test_only_other_instances_reports_mismatch(monkeypatch, capsys) -> None:
    """只有不匹配的实例时，报错要带版本号，方便判断是不是旧/新版本。"""
    _patch_probe(
        monkeypatch,
        {9092: {"status": "healthy", "instance": "", "version": "0.17.41"}},
    )
    monkeypatch.setenv("AGENT_MOSS_INSTANCE", "xiaoo")

    out = _run_status(monkeypatch, capsys)

    assert "服务未运行" in out
    assert "端口 9092 (instance=(空), v0.17.41)" in out
