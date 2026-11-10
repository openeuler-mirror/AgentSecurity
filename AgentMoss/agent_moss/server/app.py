"""FastAPI application entry point for AgentMoss HTTP API server."""

import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ..__version__ import __version__
from .routes import router
from .middleware import request_logging_middleware
from ..console import console_router

logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    app = FastAPI(
        title="AgentMoss Security Service",
        description="Multi-layer security analysis engine for AI agents",
        version=__version__,
    )

    @app.on_event("startup")
    async def init_config():
        """Initialize config on startup (triggers config file auto-creation)."""
        from ..infra.config import get_default_config
        get_default_config()

    app.add_middleware(
        CORSMiddleware,
        # 允许本机 console（含 iframe 嵌入）+ 分析 API
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.middleware("http")(request_logging_middleware)
    app.include_router(router)
    # Policy Console（浏览器策略管控台，挂载在 /console 前缀）
    app.include_router(console_router)

    return app


def _find_free_port(start_port: int, host: str = "127.0.0.1", scan: int = 100) -> int:
    """从 start_port 开始找第一个可用端口（照搬 OpenDesk findFreePort 策略）。

    用 socket 试 bind，成功即空闲。扫最多 scan 个端口，全被占则 fallback 到
    start_port（让 uvicorn 自己报错，不静默换到离谱端口）。

    为什么需要：默认 9090 被占时，服务起不来、xiaoO 全 fail-closed。预探测找空闲
    端口，配合 bridge.py 探测兜底，保证服务总能起来且消费方能连上。
    """
    import socket
    for candidate in range(start_port, start_port + scan):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((host, candidate))
                if candidate != start_port:
                    logger.info(
                        "Port %d in use, using %d instead", start_port, candidate
                    )
                return candidate
        except OSError:
            # 端口被占，试下一个
            continue
    return start_port


def run_server(
    host: str = "127.0.0.1",
    port: int = 9090,
    mode: str = "http",
    socket_path: str = "/var/run/agent_moss/agent_moss.sock",
) -> None:
    """
    Start AgentMoss server in the specified mode.

    Args:
        host: HTTP listen host
        port: HTTP listen port（被占时自动找空闲端口，见 _find_free_port）
        mode: "http" (TCP) or "socket" (Unix Domain Socket)
        socket_path: Unix socket path (when mode="socket")
    """
    if mode == "socket":
        from .socket_server import run_socket_server
        run_socket_server(socket_path=socket_path)
    else:
        import uvicorn
        actual_port = _find_free_port(port, host)
        app = create_app()
        logger.info("Starting AgentMoss HTTP server on %s:%d", host, actual_port)
        uvicorn.run(app, host=host, port=actual_port, log_level="info")
