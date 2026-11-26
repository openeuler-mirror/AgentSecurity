"""回归：异步 LLM 客户端不能跨 ``asyncio.run`` 的事件循环复用。

背景（2026-11 招行）：``call_llm`` 每次都在独立线程里新建短生命周期事件循环，
但 ``AsyncOpenAI`` 曾被全局缓存；第一次调用结束后循环关闭，第二次复用同一个
客户端就会报 ``APIConnectionError: Connection error.``，异常链里是
``RuntimeError: Event loop is closed``。表现为 L3 时好时坏、两次重试都在 0 秒
失败并按 fail_open 放行。
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from agent_moss.infra.config import LLMConfig
from agent_moss.infra.llm_client import call_llm, reset_client_cache_for_tests


class _ChatHandler(BaseHTTPRequestHandler):
    """最小 OpenAI Chat Completions 端点；HTTP/1.1 + Content-Length 保持连接。"""

    protocol_version = "HTTP/1.1"
    requests = 0

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler API
        type(self).requests += 1
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        payload = {
            "id": "chatcmpl-local",
            "object": "chat.completion",
            "created": 1,
            "model": "local-test",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "ok"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def test_sequential_calls_do_not_reuse_async_client_across_event_loops(monkeypatch):
    _ChatHandler.requests = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ChatHandler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()

    # 排除本机代理对 127.0.0.1 的干扰（与 test_llm_timeout_budget 同口径）。
    for name in (
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
        "http_proxy", "https_proxy", "all_proxy",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")

    config = LLMConfig(
        api_key="local-test",
        model="local-test",
        base_url=f"http://127.0.0.1:{server.server_port}/v1",
    )
    reset_client_cache_for_tests()
    try:
        # 连续三次，确保不是“第一次成功、第二次失败、第三次又成功”的假象。
        for i in range(3):
            result = call_llm(f"local test {i}", timeout=2.0, config=config)
            assert result.content == "ok"
        assert _ChatHandler.requests == 3
    finally:
        reset_client_cache_for_tests()
        server.shutdown()
        server.server_close()
        worker.join()
