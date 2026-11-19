"""The manual package CLI neither starts a worker nor needs a native library for an empty package."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


def _run(tmp_path, *args):
    env = dict(os.environ, AGENT_MOSS_DATA_DIR=str(tmp_path / "data"), AGENT_MOSS_ACCEL="0")
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
    return subprocess.run([sys.executable, "-m", "agent_moss.cli", "accel", *args],
                          cwd=tmp_path, env=env, capture_output=True, text=True, timeout=20)


def test_empty_rules_file_build_and_disk_status(tmp_path):
    source = tmp_path / "rules.json"
    source.write_text(json.dumps({"schema_version": 1, "rules": []}))
    entry = tmp_path / "prefilter.hsdb"
    built = _run(tmp_path, "build-db", "--rules-file", str(source), "--out", str(entry))
    assert built.returncode == 0, built.stderr
    assert entry.is_dir() and not entry.is_symlink()
    assert json.loads(built.stdout)["rules_total"] == 0

    status = _run(tmp_path, "status", "--db", str(entry))
    assert status.returncode == 0, status.stderr
    data = json.loads(status.stdout)
    assert data["scope"] == "disk_only"
    assert data["package"]["rules_accelerated"] == 0
    assert data["worker_state"] == "not_checked"


def test_linux_profile_build_uses_real_native_and_status_is_disk_only(tmp_path, monkeypatch):
    library = os.environ.get("AGENT_MOSS_TEST_HS_LIB")
    if not library:
        pytest.skip("set AGENT_MOSS_TEST_HS_LIB to a real Hyperscan compile library")
    monkeypatch.setenv("AGENT_MOSS_ACCEL_LIB", library)
    monkeypatch.setenv("AGENT_MOSS_ACCEL_BACKEND", "hyperscan")
    entry = tmp_path / "prefilter.hsdb"
    built = _run(tmp_path, "build-db", "--profile", "linux", "--out", str(entry))
    assert built.returncode == 0, built.stderr
    report = json.loads(built.stdout)
    assert report["rules_total"] == 163
    assert report["rules_prefilter"] >= 160
    status = _run(tmp_path, "status", "--db", str(entry))
    assert status.returncode == 0, status.stderr
    data = json.loads(status.stdout)
    assert data["package"]["rules_accelerated"] == report["rules_prefilter"]
    assert data["worker_state"] == "not_checked"
