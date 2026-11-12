# -*- coding: utf-8 -*-
"""Unix Domain Socket 模式的残留文件清理（镜像 TS 端 unix-socket-server.test.ts）。

背景：进程被 `kill -9` 时 socket 文件不会被清理，下次启动 uvicorn `bind` 直接
`EADDRINUSE`，报错信息看不出是"死文件"造成的，表现为"服务重启起不来"。

关键在**先探测再删**：文件存在 ≠ 没人用。直接 unlink 会把正在运行实例的 socket
路径摘掉（新连接全失败，旧实例毫无察觉）。只有连不上才判残留。
"""

import os
import socket
import threading

import pytest

from agent_moss.server.socket_server import unlink_stale_socket


def test_removes_stale_file(tmp_path):
    """一拦：连不上的残留文件 → 清掉（否则重启 bind 报 EADDRINUSE）。"""
    sock = tmp_path / "dead.sock"
    sock.write_text("")  # 普通文件：connect 必然失败，等价于死 socket
    assert unlink_stale_socket(str(sock)) is True
    assert not sock.exists()


def test_keeps_live_socket(tmp_path):
    """一放：已有服务在监听 → 不动它（不抢活实例的路径）。

    用一个真实 bind+listen 的 AF_UNIX socket 模拟运行中的实例 —— 这正是
    "文件存在但有人在用"的情形，直接 unlink 会把对方摘掉。
    """
    sock_path = str(tmp_path / "live.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    srv.listen(1)
    accepted: list = []

    def _accept_once():
        try:
            conn, _ = srv.accept()
            accepted.append(conn)
        except OSError:
            pass

    t = threading.Thread(target=_accept_once, daemon=True)
    t.start()
    try:
        assert unlink_stale_socket(sock_path) is False
        assert os.path.exists(sock_path), "活实例的 socket 文件不能被删"
        # 探测连接确实建立过（证明上面判"有人在用"不是假阳性）
        t.join(timeout=2)
        assert accepted, "探测应当真的连上过活实例"
    finally:
        for c in accepted:
            c.close()
        srv.close()


def test_missing_path_is_noop(tmp_path):
    """路径不存在 → 什么都不做（返回 False，不抛异常）。"""
    assert unlink_stale_socket(str(tmp_path / "nope.sock")) is False
