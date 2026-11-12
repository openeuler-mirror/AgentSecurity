"""Unix Domain Socket server for AgentMoss.

Reuses the same FastAPI application and routing as the HTTP server,
but listens on a Unix Domain Socket instead of TCP.
"""

import os
import logging

from ..infra import security_policy as sp

logger = logging.getLogger(__name__)


def unlink_stale_socket(socket_path: str) -> bool:
    """清理**残留**的 socket 文件；返回是否真的删了。

    为什么需要：进程被 ``kill -9`` 时 socket 文件不会被清理，下次启动 uvicorn
    ``bind`` 直接 ``EADDRINUSE``，而报错信息看不出是"死文件"造成的，表现为
    "服务重启起不来"。

    为什么**先探测再删**：文件存在 ≠ 没人用。直接 ``unlink`` 会把正在运行的实例的
    socket 路径摘掉（新连接全部失败，旧实例毫无察觉）。只有连不上才判定为残留；
    连得上就让 bind 正常失败（端口占用语义清晰）。

    与 TS 端 ``startUnixSocketServer`` 的同名逻辑保持一致（双端同行为）。
    """
    if not os.path.exists(socket_path):
        return False
    import socket as _socket

    probe = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
    probe.settimeout(0.5)
    try:
        probe.connect(socket_path)
    except OSError:
        try:
            os.unlink(socket_path)
            logger.info("清理残留 socket 文件: %s", socket_path)
            return True
        except OSError as e:
            logger.warning("残留 socket 清理失败（随后 bind 会报错）: %s: %s", socket_path, e)
            return False
    else:
        logger.warning(
            "socket %s 已有服务在监听，不清理（bind 会因端口占用而失败）", socket_path,
        )
        return False
    finally:
        probe.close()


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

    # Ensure parent directory exists
    socket_dir = os.path.dirname(socket_path)
    if socket_dir and not os.path.exists(socket_dir):
        os.makedirs(socket_dir, exist_ok=True)
        logger.info("Created socket directory: %s", socket_dir)

    unlink_stale_socket(socket_path)

    # socket 文件权限就是 UDS 模式唯一的内核级访问控制：以前跟随 umask（常见 0777），
    # 同机任何用户都能连。这里用 umask 保证以 AGENT_MOSS_SOCKET_MODE（默认 0600）
    # 创建；多 worker 时子进程继承同一 umask。
    _socket_mode = sp.socket_mode()
    _old_umask = os.umask(0o777 & ~_socket_mode)
    logger.info("Socket 权限: %04o（AGENT_MOSS_SOCKET_MODE）", _socket_mode)

    logger.info("Starting AgentMoss server on Unix socket: %s（workers=%d）", socket_path, workers)
    try:
        if workers > 1:
            # ⚠️ uvicorn 的 workers 模式**要求 app 以 import 字符串传入**：
            # 传 app 对象时 uvicorn 只打一行 WARNING 然后退出 —— 也就是说
            # `workers>1` 以前从来没生效过（默认 workers=4 时 socket 模式甚至起不来）。
            # 改为 factory 形式，多 worker 才真的能并行（分析是 CPU 密集，靠线程没用）。
            uvicorn.run(
                "agent_moss.server.app:create_app",
                factory=True,
                uds=socket_path,
                workers=workers,
                log_level="info",
                limit_concurrency=sp.max_connections(),
                timeout_keep_alive=sp.keep_alive_sec(),
            )
        else:
            from .app import create_app
            uvicorn.run(
                create_app(), uds=socket_path, log_level="info",
                limit_concurrency=sp.max_connections(),
                timeout_keep_alive=sp.keep_alive_sec(),
            )
    finally:
        # 恢复进程 umask，避免影响调用方后续创建的文件
        os.umask(_old_umask)
