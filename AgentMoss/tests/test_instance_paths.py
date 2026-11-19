"""instance 数据目录隔离 + 数据归属用户 的单元测试。

对齐 TS ts/src/infra/paths.test.ts。验证：
- 无 instance → <data_root>/agent_moss_token_stats.json
- 有 instance → <data_root>/<instance>/agent_moss_token_stats.json
- AGENT_MOSS_DATA_DIR 覆盖数据根（root 服务写当前用户目录）
"""

import os
import sqlite3
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _clean_env():
    """每个用例前清掉 AGENT_MOSS_INSTANCE / AGENT_MOSS_DATA_DIR，用后还原。"""
    saved_i = os.environ.get("AGENT_MOSS_INSTANCE")
    saved_d = os.environ.get("AGENT_MOSS_DATA_DIR")
    saved_s = os.environ.get("AGENT_MOSS_STATE_DIR")
    os.environ.pop("AGENT_MOSS_INSTANCE", None)
    os.environ.pop("AGENT_MOSS_DATA_DIR", None)
    os.environ.pop("AGENT_MOSS_STATE_DIR", None)
    yield
    if saved_i is None:
        os.environ.pop("AGENT_MOSS_INSTANCE", None)
    else:
        os.environ["AGENT_MOSS_INSTANCE"] = saved_i
    if saved_d is None:
        os.environ.pop("AGENT_MOSS_DATA_DIR", None)
    else:
        os.environ["AGENT_MOSS_DATA_DIR"] = saved_d
    if saved_s is None:
        os.environ.pop("AGENT_MOSS_STATE_DIR", None)
    else:
        os.environ["AGENT_MOSS_STATE_DIR"] = saved_s


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

def test_port_file_instance_scoped():
    """端口文件按 instance 分：避免同机多实例互相覆盖。"""
    from agent_moss.infra.paths import get_port_file_path

    os.environ["AGENT_MOSS_DATA_DIR"] = "/tmp/am-data"
    os.environ["AGENT_MOSS_INSTANCE"] = "xiaoo"
    assert get_port_file_path() == Path("/tmp/am-data/xiaoo/agent_moss_server.port.json")
    os.environ.pop("AGENT_MOSS_INSTANCE", None)
    assert get_port_file_path() == Path("/tmp/am-data/agent_moss_server.port.json")


def test_state_db_instance_scoped():
    """链状态库按 instance 分：避免 xiaoO / OpenDesk 共用一份状态。"""
    from agent_moss.infra.paths import get_state_db_path

    os.environ["AGENT_MOSS_STATE_DIR"] = "/tmp/am-state"
    os.environ["AGENT_MOSS_INSTANCE"] = "opendesk"
    assert get_state_db_path() == Path("/tmp/am-state/opendesk/stateful_chains.db")
    os.environ.pop("AGENT_MOSS_INSTANCE", None)
    assert get_state_db_path() == Path("/tmp/am-state/stateful_chains.db")


def test_state_db_migrates_legacy_shared_db(tmp_path):
    """首次启用 instance 隔离时，把旧共享库复制到实例目录（保留历史链）。"""
    from agent_moss.engine.formal_engine.chain_state import default_state_db_path

    os.environ["AGENT_MOSS_STATE_DIR"] = str(tmp_path)
    os.environ["AGENT_MOSS_INSTANCE"] = "xiaoo"
    legacy = tmp_path / "stateful_chains.db"
    conn = sqlite3.connect(legacy)
    conn.execute("CREATE TABLE marker(x INTEGER)")
    conn.execute("INSERT INTO marker VALUES (1)")
    conn.commit()
    conn.close()

    path = Path(default_state_db_path())
    assert path == tmp_path / "xiaoo" / "stateful_chains.db"
    assert path.exists()
    conn = sqlite3.connect(path)
    assert conn.execute("SELECT x FROM marker").fetchone()[0] == 1
    conn.close()
