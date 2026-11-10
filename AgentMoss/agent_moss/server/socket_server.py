"""Unix Domain Socket server for AgentMoss.

Reuses the same FastAPI application and routing as the HTTP server,
but listens on a Unix Domain Socket instead of TCP.
"""

import os
import logging

logger = logging.getLogger(__name__)


def run_socket_server(
    socket_path: str = "/var/run/agent_moss/agent_moss.sock",
    workers: int = 4,
) -> None:
    """
    Start AgentMoss HTTP server over Unix Domain Socket.

    Args:
        socket_path: Path to the Unix socket file
        workers: Number of uvicorn workers
    """
    import uvicorn
    from .app import create_app

    # Ensure parent directory exists
    socket_dir = os.path.dirname(socket_path)
    if socket_dir and not os.path.exists(socket_dir):
        os.makedirs(socket_dir, exist_ok=True)
        logger.info("Created socket directory: %s", socket_dir)

    app = create_app()
    logger.info("Starting AgentMoss server on Unix socket: %s", socket_path)
    uvicorn.run(
        app,
        uds=socket_path,
        workers=workers,
        log_level="info",
    )
