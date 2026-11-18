"""Successful LLM usage must be stored and visible through the Console API."""
import json
import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from agent_moss.infra.token_stats import record_token_usage
from agent_moss.server.app import create_app


def test_usage_is_persisted_and_aggregated_by_console(monkeypatch, tmp_path):
    path = tmp_path / "stats.json"
    monkeypatch.setenv("AGENT_MOSS_TOKEN_STATS_PATH", str(path))
    record_token_usage("session", "L3_security_judge", "local-test", 11, 7, 18)
    record_token_usage("session", "L3_security_judge", "local-test", 3, 2, 5)
    assert len(json.loads(path.read_text())) == 2
    with TestClient(create_app()) as client:
        response = client.get("/console/api/token-stats")
        assert response.status_code == 200
        stats = response.json()
        assert stats["total_calls"] == 2
        assert stats["total_prompt_tokens"] == 14
        assert stats["total_completion_tokens"] == 9
        assert stats["total_tokens"] == 23


def test_concurrent_threads_preserve_every_usage_record(monkeypatch, tmp_path):
    path = tmp_path / "thread-stats.json"
    monkeypatch.setenv("AGENT_MOSS_TOKEN_STATS_PATH", str(path))

    def record(i):
        record_token_usage(str(i), "L3_security_judge", "local-test", 1, 1, 2)

    with ThreadPoolExecutor(max_workers=4) as workers:
        list(workers.map(record, range(40)))
    records = json.loads(path.read_text())
    assert len(records) == 40
    assert sum(r["total_tokens"] for r in records) == 80


def test_concurrent_processes_preserve_every_usage_record(tmp_path):
    path = tmp_path / "process-stats.json"
    env = {**os.environ, "AGENT_MOSS_TOKEN_STATS_PATH": str(path)}
    script = (
        "from agent_moss.infra.token_stats import record_token_usage\n"
        "for i in range(15):\n"
        "    record_token_usage(str(i), 'L3_security_judge', 'local-test', 1, 1, 2)\n"
    )
    workers = [subprocess.Popen([sys.executable, "-c", script], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
               for _ in range(4)]
    try:
        for worker in workers:
            _, stderr = worker.communicate(timeout=20)
            assert worker.returncode == 0, stderr.decode()
    finally:
        for worker in workers:
            if worker.poll() is None:
                worker.kill()
                worker.wait()
    records = json.loads(path.read_text())
    assert len(records) == 60
    assert sum(r["total_tokens"] for r in records) == 120


def test_readers_only_observe_complete_json_during_updates(monkeypatch, tmp_path):
    path = tmp_path / "read-stats.json"
    monkeypatch.setenv("AGENT_MOSS_TOKEN_STATS_PATH", str(path))
    record_token_usage("initial", "L3_security_judge", "local-test", 1, 1, 2)
    done = threading.Event()

    def writer():
        try:
            for i in range(40):
                record_token_usage(str(i), "L3_security_judge", "x" * 3000, 1, 1, 2)
        finally:
            done.set()

    with ThreadPoolExecutor(max_workers=1) as worker:
        future = worker.submit(writer)
        while not done.is_set():
            assert len(json.loads(path.read_text())) >= 1
        future.result()
    assert len(json.loads(path.read_text())) == 41
