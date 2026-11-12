"""instance 数据目录隔离 + 数据归属用户 的单元测试。

验证：
- 无 instance → <data_root>/agent_moss_token_stats.json
- 有 instance → <data_root>/<instance>/agent_moss_token_stats.json
- AGENT_MOSS_DATA_DIR 覆盖数据根（root 服务写当前用户目录）
"""

import os
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _clean_env():
    """每个用例前清掉 AGENT_MOSS_INSTANCE / AGENT_MOSS_DATA_DIR，用后还原。"""
    saved_i = os.environ.get("AGENT_MOSS_INSTANCE")
    saved_d = os.environ.get("AGENT_MOSS_DATA_DIR")
    os.environ.pop("AGENT_MOSS_INSTANCE", None)
    os.environ.pop("AGENT_MOSS_DATA_DIR", None)
    yield
    if saved_i is None:
        os.environ.pop("AGENT_MOSS_INSTANCE", None)
    else:
        os.environ["AGENT_MOSS_INSTANCE"] = saved_i
    if saved_d is None:
        os.environ.pop("AGENT_MOSS_DATA_DIR", None)
    else:
        os.environ["AGENT_MOSS_DATA_DIR"] = saved_d


def _fresh_token_path():
    """重新 import 以绕过模块级缓存的默认数据根。"""
    import importlib
    from agent_moss.infra import paths
    importlib.reload(paths)
    return paths.get_token_stats_path()


def test_no_instance_default_path():
    from agent_moss.infra.paths import get_token_stats_path
    assert get_token_stats_path() == Path.home() / ".config" / "agentmoss" / "agent_moss_token_stats.json"


def test_instance_subdir():
    os.environ["AGENT_MOSS_INSTANCE"] = "xiaoo"
    assert Path(_fresh_token_path()) == Path.home() / ".config" / "agentmoss" / "xiaoo" / "agent_moss_token_stats.json"


def test_data_root_override():
    os.environ["AGENT_MOSS_DATA_DIR"] = "/home/hkl/.config/agentmoss"
    os.environ["AGENT_MOSS_INSTANCE"] = "opendesk"
    assert Path(_fresh_token_path()) == Path("/home/hkl/.config/agentmoss/opendesk/agent_moss_token_stats.json")


def test_root_uses_root_home(monkeypatch):
    """root 运行时（sudo systemctl / 直接 root 启动）数据就落在 /root，不猜真实用户。"""
    from agent_moss.infra import paths
    monkeypatch.setattr(paths, "_is_root", lambda: True)
    # 清掉 env，模拟任何 sudo systemctl start（无 AGENT_MOSS_DATA_DIR）
    os.environ.pop("AGENT_MOSS_DATA_DIR", None)
    os.environ.pop("AGENT_MOSS_INSTANCE", None)
    assert Path(paths.get_data_root()) == paths.DEFAULT_DATA_ROOT
    assert Path(paths.get_token_stats_path()) == paths.DEFAULT_DATA_ROOT / "agent_moss_token_stats.json"


def test_root_uses_root_home_respects_instance(monkeypatch):
    """root + instance 时，token 落到 <root 数据目录>/<instance>/。"""
    from agent_moss.infra import paths
    monkeypatch.setattr(paths, "_is_root", lambda: True)
    os.environ.pop("AGENT_MOSS_DATA_DIR", None)
    os.environ["AGENT_MOSS_INSTANCE"] = "xiaoo"
    assert Path(paths.get_token_stats_path()) == (
        paths.DEFAULT_DATA_ROOT / "xiaoo" / "agent_moss_token_stats.json"
    )


def test_data_root_override_no_instance():
    os.environ["AGENT_MOSS_DATA_DIR"] = "/tmp/am-data"
    os.environ.pop("AGENT_MOSS_INSTANCE", None)
    assert Path(_fresh_token_path()) == Path("/tmp/am-data/agent_moss_token_stats.json")