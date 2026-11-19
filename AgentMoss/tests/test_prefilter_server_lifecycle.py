"""The HTTP worker starts and stops its configured package monitor."""

import asyncio
import time
import warnings

from agent_moss.engine.prefilter_build import build_package
from agent_moss.engine.prefilter_reload import get_manager, stop_managers
from agent_moss.server import app as server_app


def test_prefilter_shutdown_registration_adds_no_legacy_warning():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", DeprecationWarning)
        server_app.create_app()
    legacy = [item for item in caught if "on_event is deprecated" in str(item.message)]
    assert len(legacy) <= 4  # 基线现有 4 处 on_event；prefilter 用 add_event_handler 不新增


def test_worker_lifecycle_owns_prefilter_manager(tmp_path, monkeypatch):
    entry = tmp_path / "prefilter.hsdb"
    build_package([], entry)
    monkeypatch.setenv("AGENT_MOSS_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("AGENT_MOSS_ACCEL", "1")
    monkeypatch.setenv("AGENT_MOSS_ACCEL_DB", str(entry))
    monkeypatch.setattr(server_app, "_warm_up_engine", lambda: None)
    app = server_app.create_app()
    manager = get_manager()
    try:
        async def exercise():
            async with app.router.lifespan_context(app):
                deadline = time.monotonic() + 5
                while manager.status()["active_package"] is None and time.monotonic() < deadline:
                    await asyncio.sleep(.01)
                assert manager.status()["active_package"] is not None

        asyncio.run(exercise())
        assert not manager.status()["running"]
    finally:
        stop_managers()
