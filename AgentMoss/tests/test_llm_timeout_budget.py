"""The configured L3 timeout covers calls, retries and retry delays together."""
import asyncio
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from agent_moss.engine import llm_analyzer
from agent_moss.engine.types import HeuristicResult, LogicRuleResult
from agent_moss.infra.config import Config, LLMConfig, RetryConfig
from agent_moss.infra.llm_client import LLMResult, call_llm


def run_analysis(config):
    return llm_analyzer.LLMAnalyzer().analyze(
        prompt_session="计算结果", action_history=[],
        a_next={"action_type": "bash", "action_detail": "python3 -c 'print(1+1)'"},
        reason="", heuristic_result=HeuristicResult(), logic_result=LogicRuleResult(),
        config=config,
    )


@pytest.mark.parametrize("total_timeout", [1.0, 2.0, 2.01])
def test_short_budget_allows_fast_response_with_default_retries(monkeypatch, total_timeout):
    def successful_call(**kwargs):
        time.sleep(0.02)
        return LLMResult(content='{"allowed":true,"reason":"ok"}')

    monkeypatch.setattr(llm_analyzer, "call_llm", successful_call)
    monkeypatch.setattr(llm_analyzer, "get_llm_timeout", lambda: total_timeout)

    started = time.monotonic()
    judgment = run_analysis(Config())

    assert judgment.allowed is True
    assert judgment.source == "llm"
    assert time.monotonic() - started < 0.5


def test_short_budget_failure_does_not_wait_for_unusable_retry(monkeypatch):
    attempts = []

    def failed_call(**kwargs):
        attempts.append(time.monotonic())
        raise ConnectionError("local endpoint unavailable")

    monkeypatch.setattr(llm_analyzer, "call_llm", failed_call)
    monkeypatch.setattr(llm_analyzer, "get_llm_timeout", lambda: 1.0)

    started = time.monotonic()
    with pytest.raises(llm_analyzer.LLMAnalysisFailure, match="ConnectionError"):
        run_analysis(Config())

    assert len(attempts) == 1
    assert time.monotonic() - started < 0.5


@pytest.mark.parametrize("retry_interval", [0.0, 0.05])
def test_sufficient_budget_preserves_retry_and_delay(monkeypatch, retry_interval):
    attempts = []

    def transient_call(**kwargs):
        attempts.append(time.monotonic())
        if len(attempts) == 1:
            raise ConnectionError("temporary local failure")
        time.sleep(0.02)
        return LLMResult(content='{"allowed":true,"reason":"recovered"}')

    monkeypatch.setattr(llm_analyzer, "call_llm", transient_call)
    monkeypatch.setattr(llm_analyzer, "get_llm_timeout", lambda: 1.0)

    started = time.monotonic()
    judgment = run_analysis(Config(retry=RetryConfig(max_retries=2, retry_interval=retry_interval)))

    assert judgment.allowed is True
    assert len(attempts) == 2
    assert attempts[1] - attempts[0] >= retry_interval
    assert time.monotonic() - started < 1.0


def test_budget_reduces_attempts_without_disabling_feasible_retry(monkeypatch):
    attempts = []

    def transient_call(**kwargs):
        attempts.append(time.monotonic())
        if len(attempts) == 1:
            raise ConnectionError("temporary local failure")
        time.sleep(0.08)
        return LLMResult(content='{"allowed":true,"reason":"recovered"}')

    monkeypatch.setattr(llm_analyzer, "call_llm", transient_call)
    monkeypatch.setattr(llm_analyzer, "get_llm_timeout", lambda: 0.4)

    started = time.monotonic()
    judgment = run_analysis(Config(retry=RetryConfig(max_retries=4, retry_interval=0.1)))

    assert judgment.allowed is True
    assert len(attempts) == 2
    assert attempts[1] - attempts[0] >= 0.1
    assert time.monotonic() - started < 0.4


def test_zero_budget_does_not_start_model_call(monkeypatch):
    def unexpected_call(**kwargs):
        pytest.fail("an exhausted budget must not start a model call")

    monkeypatch.setattr(llm_analyzer, "call_llm", unexpected_call)
    monkeypatch.setattr(llm_analyzer, "get_llm_timeout", lambda: 0.0)

    with pytest.raises(llm_analyzer.LLMAnalysisFailure, match="总上限"):
        run_analysis(Config())


def test_timeout_does_not_wait_for_worker_shutdown(monkeypatch):
    release = threading.Event()

    def stalled_call(**kwargs):
        release.wait(1)
        raise TimeoutError("transport stalled")

    monkeypatch.setattr(llm_analyzer, "call_llm", stalled_call)
    monkeypatch.setattr(llm_analyzer, "get_llm_timeout", lambda: 0.15)
    started = time.monotonic()
    try:
        with pytest.raises(llm_analyzer.LLMAnalysisFailure):
            run_analysis(Config(retry=RetryConfig(max_retries=1, retry_interval=0)))
        assert time.monotonic() - started < 0.5
    finally:
        release.set()


def test_retry_delay_cannot_exceed_total_timeout(monkeypatch):
    def failed_call(**kwargs):
        raise ConnectionError("local endpoint unavailable")

    monkeypatch.setattr(llm_analyzer, "call_llm", failed_call)
    monkeypatch.setattr(llm_analyzer, "get_llm_timeout", lambda: 0.15)
    started = time.monotonic()
    with pytest.raises(llm_analyzer.LLMAnalysisFailure):
        run_analysis(Config(retry=RetryConfig(max_retries=3, retry_interval=0.4)))
    assert time.monotonic() - started < 0.5


def test_stalled_retries_and_delay_share_total_deadline(monkeypatch):
    release = threading.Event()
    workers = []
    attempts = []

    def stalled_call(*, timeout, **kwargs):
        workers.append(threading.current_thread())
        attempts.append((time.monotonic(), timeout))
        release.wait(3)
        raise TimeoutError("local transport stalled")

    monkeypatch.setattr(llm_analyzer, "call_llm", stalled_call)
    monkeypatch.setattr(llm_analyzer, "get_llm_timeout", lambda: 0.6)

    started = time.monotonic()
    try:
        with pytest.raises(llm_analyzer.LLMAnalysisFailure):
            run_analysis(Config(retry=RetryConfig(max_retries=2, retry_interval=0.1)))

        elapsed = time.monotonic() - started
        assert len(attempts) == 2
        first_started, first_timeout = attempts[0]
        second_started, _ = attempts[1]
        # The first call must time out and then wait the retry interval before
        # starting the second. Allow scheduling jitter around the measurement.
        assert second_started - first_started >= first_timeout + 0.1 - 0.03
        # Both calls and the delay fit within one budget; allow generous
        # scheduler overhead without allowing a fresh full budget per call.
        assert elapsed < 1.1
    finally:
        release.set()
        for worker in workers:
            worker.join(timeout=1)
            assert not worker.is_alive(), "stalled model worker did not finish"


def test_transport_does_not_retry_outside_analyzer_budget(monkeypatch):
    requests = []

    class Unavailable(BaseHTTPRequestHandler):
        def do_POST(self):
            requests.append(self.path)
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.send_response(503)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Unavailable)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    try:
        with pytest.raises(Exception):
            call_llm("local failure test", timeout=2.0, config=LLMConfig(
                api_key="local-test", model="local-test",
                base_url=f"http://127.0.0.1:{server.server_port}/v1",
            ))
        assert len(requests) == 1
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


@pytest.mark.parametrize("phase", ["headers", "body"])
def test_total_transport_timeout_closes_slow_drip_connection(monkeypatch, phase):
    stop = threading.Event()
    disconnected = threading.Event()

    class SlowDrip(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            if phase == "body":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", "1000000")
                self.end_headers()
            else:
                self.wfile.write(b"HTTP/1.1 200 OK\r\nX-Slow: ")
                self.wfile.flush()
            try:
                # Bytes arrive faster than the read-idle timeout. Only an
                # overall deadline can stop this response before it finishes.
                for _ in range(40):
                    self.wfile.write(b" ")
                    self.wfile.flush()
                    if stop.wait(0.025):
                        break
            except (BrokenPipeError, ConnectionResetError):
                disconnected.set()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), SlowDrip)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    try:
        started = time.monotonic()
        with pytest.raises(TimeoutError):
            call_llm("local slow response", timeout=0.2, config=LLMConfig(
                api_key="local-test", model="local-test",
                base_url=f"http://127.0.0.1:{server.server_port}/v1",
            ))
        assert time.monotonic() - started < 0.6
        assert disconnected.wait(0.3), "deadline left the HTTP connection open"
    finally:
        stop.set()
        server.shutdown()
        server.server_close()
        worker.join()


def test_stream_fallback_preserves_response_and_usage_inside_event_loop(monkeypatch):
    class StreamOnly(BaseHTTPRequestHandler):
        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if not request.get("stream"):
                body = b'{"error":{"message":"only support stream mode"}}'
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
            else:
                chunks = [
                    {"id": "local", "object": "chat.completion.chunk", "created": 1,
                     "model": "local-test", "choices": [{"index": 0, "delta": {"content": "ok"}, "finish_reason": None}]},
                    {"id": "local", "object": "chat.completion.chunk", "created": 1,
                     "model": "local-test", "choices": [],
                     "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}},
                ]
                body = ("".join("data: " + json.dumps(c) + "\n\n" for c in chunks)
                        + "data: [DONE]\n\n").encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), StreamOnly)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")

    async def caller():
        return call_llm("local streaming test", timeout=2, config=LLMConfig(
            api_key="local-test", model="local-test",
            base_url=f"http://127.0.0.1:{server.server_port}/v1",
        ))

    try:
        result = asyncio.run(caller())
        assert result.content == "ok"
        assert (result.prompt_tokens, result.completion_tokens, result.total_tokens) == (11, 7, 18)
    finally:
        server.shutdown()
        server.server_close()
        worker.join()
