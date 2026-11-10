"""_find_free_port 单测（块 A：端口动态分配）。

照搬 OpenDesk findFreePort 策略：start_port 被占则递增找空闲。
验证 9090 被占时自动到 9091，空闲时直接用 start_port。
"""

import socket

import pytest

from agent_moss.server.app import _find_free_port


def _occupy(port: int):
    """占住 port，返回 socket 句柄（用完 close 释放）。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(1)
    return s


def test_find_free_port_returns_start_when_free():
    """start_port 空闲时，直接返回 start_port。"""
    # 用一个不太可能被占的高端口
    port = _find_free_port(9300, "127.0.0.1", scan=10)
    assert port == 9300


def test_find_free_port_skips_occupied():
    """start_port 被占时，返回下一个空闲端口（start_port+1）。"""
    occ = _occupy(9301)
    try:
        port = _find_free_port(9301, "127.0.0.1", scan=10)
        assert port == 9302, f"期望 9302，实际 {port}"
    finally:
        occ.close()


def test_find_free_port_skips_multiple_occupied():
    """连续两个端口被占时，返回第三个。"""
    occ1 = _occupy(9310)
    occ2 = _occupy(9311)
    try:
        port = _find_free_port(9310, "127.0.0.1", scan=10)
        assert port == 9312, f"期望 9312，实际 {port}"
    finally:
        occ1.close()
        occ2.close()


def test_find_free_port_fallback_when_all_occupied():
    """scan 范围内全被占时，fallback 返回 start_port（让 uvicorn 自己报错）。"""
    sockets = [_occupy(9320 + i) for i in range(5)]
    try:
        port = _find_free_port(9320, "127.0.0.1", scan=5)
        assert port == 9320, f"全占应 fallback 9320，实际 {port}"
    finally:
        for s in sockets:
            s.close()
