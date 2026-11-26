"""A model response can consume tokens even when it cannot be used."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from agent_moss.engine.llm_analyzer import LLMAnalyzer, LLMAnalysisFailure
from agent_moss.engine.types import HeuristicResult, LogicRuleResult
from agent_moss.infra.config import CacheConfig, Config, LLMConfig, RetryConfig
from agent_moss.infra.token_stats import get_token_stats


@pytest.fixture
def local_model(monkeypatch, tmp_path):
    responses = []
    settings = {"stream_only": False}

    class Model(BaseHTTPRequestHandler):
        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if settings["stream_only"] and not request.get("stream"):
                status, content_type, body = 400, "application/json", b'{"error":{"message":"only support stream mode"}}'
            else:
                response = responses.pop(0)
                status = response.pop("status", 200)
                if request.get("stream"):
                    content_type = "text/event-stream"
                    chunks = [
                        {"id": "local", "object": "chat.completion.chunk", "created": 1,
                         "model": "local-test", "choices": [{"index": 0,
                         "delta": {"content": response.get("content")},
                         "finish_reason": response.get("finish_reason", "stop")}]},
                    ]
                    if "usage" in response:
                        chunks.append({"id": "local", "object": "chat.completion.chunk", "created": 1,
                                       "model": "local-test", "choices": [], "usage": response["usage"]})
                    body = ("".join("data: " + json.dumps(chunk) + "\n\n" for chunk in chunks)
                            + "data: [DONE]\n\n").encode()
                else:
                    content_type = "application/json"
                    payload = {"id": "local", "object": "chat.completion", "created": 1,
                               "model": "local-test", "choices": [{"index": 0,
                               "message": {"role": "assistant", "content": response.get("content")},
                               "finish_reason": response.get("finish_reason", "stop")}]}
                    if "usage" in response:
                        payload["usage"] = response["usage"]
                    body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Model)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    # 原仓有熔断器：本文件多个用例故意制造失败，不重置会让后续用例直接被熔断拦下
    # （裁剪仓无此机制，移植时补上）。
    from agent_moss.infra.circuit_breaker import reset_breaker_for_tests
    reset_breaker_for_tests()
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    monkeypatch.setenv("AGENT_MOSS_TOKEN_STATS_PATH", str(tmp_path / "usage.json"))
    monkeypatch.setenv("AGENT_MOSS_LLM_TIMEOUT", "5")
    config = Config(
        llm=LLMConfig(api_key="local-test", model="local-test", base_url=f"http://127.0.0.1:{server.server_port}/v1"),
        retry=RetryConfig(max_retries=1, retry_interval=0),
        cache=CacheConfig(enabled=False),
    )
    try:
        yield responses, settings, config
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


USED = {"prompt_tokens": 3064, "completion_tokens": 4096, "total_tokens": 7160}
SUCCESS = {"content": '{"allowed":true,"reason":"ok"}',
           "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}}


def analyze(config):
    return LLMAnalyzer().analyze(
        "计算", [], {"action_type": "bash", "action_detail": "python3 -c 'print(1+1)'"}, "",
        HeuristicResult(), LogicRuleResult(), config,
    )


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("finish_reason", ["length", "stop"])
def test_empty_response_records_reported_usage(local_model, streaming, finish_reason):
    responses, settings, config = local_model
    settings["stream_only"] = streaming
    responses.append({"content": None, "finish_reason": finish_reason, "usage": USED})
    with pytest.raises(LLMAnalysisFailure):
        analyze(config)
    stats = get_token_stats()
    assert stats["total_calls"] == 1
    assert stats["total_prompt_tokens"] == 3064
    assert stats["total_completion_tokens"] == 4096
    assert stats["total_tokens"] == 7160


def test_failed_then_successful_attempt_counts_each_usage_once(local_model):
    responses, _, config = local_model
    config.retry.max_retries = 2
    responses.extend([{"content": None, "finish_reason": "length", "usage": USED}, dict(SUCCESS)])
    assert analyze(config).allowed is True
    stats = get_token_stats()
    assert stats["total_calls"] == 2
    assert stats["total_tokens"] == 7178


@pytest.mark.parametrize("response", [{"content": None}, {"status": 503}])
def test_failure_without_usage_does_not_invent_consumption(local_model, response):
    responses, _, config = local_model
    responses.append(dict(response))
    with pytest.raises(LLMAnalysisFailure):
        analyze(config)
    assert get_token_stats()["total_calls"] == 0


def test_invalid_json_response_does_not_double_count_usage(local_model):
    responses, _, config = local_model
    config.retry.max_retries = 2
    responses.extend([{**SUCCESS, "content": "not valid JSON"}, dict(SUCCESS)])
    assert analyze(config).allowed is True
    stats = get_token_stats()
    assert stats["total_calls"] == 2
    assert stats["total_tokens"] == 36


@pytest.mark.parametrize("streaming", [False, True])
def test_invalid_json_retry_counts_both_responses_when_usage_is_missing(local_model, streaming):
    responses, settings, config = local_model
    settings["stream_only"] = streaming
    config.retry.max_retries = 2
    responses.extend([{"content": "not valid JSON"}, {"content": SUCCESS["content"]}])

    assert analyze(config).allowed is True

    stats = get_token_stats()
    assert stats["total_calls"] == 2
    assert stats["total_tokens"] == 0
    assert stats["total_prompt_tokens"] == 0
    assert stats["by_step"]["L3_security_judge"]["calls"] == 2


def test_failed_policy_response_records_usage(local_model, monkeypatch):
    from agent_moss.engine.analyzer import analyze as run_analysis
    from agent_moss.infra.policy_cache import PolicyCache
    responses, _, config = local_model
    config.timeout.step_interval = 0
    # Reserve the mock response for policy generation by disabling the L3 judge.
    monkeypatch.setenv("AGENT_MOSS_DISABLE_LLM", "1")
    monkeypatch.setenv("AGENT_MOSS_ENABLE_POLICY_GEN", "1")
    monkeypatch.setenv("AGENT_MOSS_SAVE_POLICY", "0")
    responses.append({"content": None, "finish_reason": "length", "usage": USED})
    result = run_analysis("policy-usage", "change permissions", [],
                          {"action_type": "bash", "action_detail": "chmod 644 /tmp/test_file"}, "",
                          config=config, cache=PolicyCache(config.cache))
    assert result["decision"] == "Deny"
    stats = get_token_stats()
    assert stats["total_calls"] == 1
    assert stats["total_tokens"] == 7160
    assert stats["by_step"]["step2_policy_gen"]["total_tokens"] == 7160


def test_stats_write_failure_preserves_model_failure(local_model, monkeypatch):
    from agent_moss.infra import token_stats
    responses, _, config = local_model
    responses.append({"content": None, "finish_reason": "length", "usage": USED})

    def failed_write(*args, **kwargs):
        raise OSError("usage disk unavailable")

    monkeypatch.setattr(token_stats, "record_token_usage", failed_write)
    with pytest.raises(LLMAnalysisFailure, match="finish_reason=length"):
        analyze(config)
