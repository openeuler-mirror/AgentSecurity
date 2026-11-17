"""事件循环延迟监控 —— 发现「同步阻塞把事件循环卡住」的直接指标。

为什么需要（2026-11 招行现场）：客户反馈「analyze 一多，console 就打不开、
随后 503」。根因是若干同步操作（``/review``、``apply_incremental``、console
写配置）跑在事件循环上，把整个进程的单线程卡住。这类问题在日志里**看不出来**
—— 请求没有报错，只是变得极慢；只有测量「循环本该 100ms 醒一次、实际醒了
多久」才能直接暴露。

实现：后台协程每 ``interval`` 秒 ``await asyncio.sleep`` 一次，比较实际间隔
与期望间隔的差值。差值为 0 说明循环空闲；几百毫秒说明有同步代码占着。
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass


@dataclass
class LoopStats:
    """最近一次采样 + 历史峰值。"""

    #: 最近一次采样的事件循环延迟（毫秒）
    lag_ms: float = 0.0
    #: 进程启动以来观测到的最大延迟（毫秒）
    max_lag_ms: float = 0.0
    #: 超过 ``slow_threshold_ms`` 的采样次数（累计）
    slow_count: int = 0
    #: 已采样次数
    samples: int = 0


class LoopLagMonitor:
    """轻量事件循环延迟探针（单例，随 app 生命周期启停）。"""

    def __init__(self, interval: float = 0.1, slow_threshold_ms: float = 200.0):
        self.interval = interval
        self.slow_threshold_ms = slow_threshold_ms
        self.stats = LoopStats()
        self._task: asyncio.Task | None = None

    def start(self) -> None:
        """在当前事件循环里启动探针（重复调用幂等）。"""
        if self._task is not None and not self._task.done():
            return
        self._task = asyncio.get_event_loop().create_task(self._run())

    async def stop(self) -> None:
        task = self._task
        self._task = None
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

    async def _run(self) -> None:
        while True:
            t0 = time.perf_counter()
            await asyncio.sleep(self.interval)
            # 理想情况下应该恰好睡了 interval 秒；多出来的部分就是被同步代码
            # 占用的时间。扣掉调度抖动后取非负值。
            lag = (time.perf_counter() - t0 - self.interval) * 1000.0
            lag = max(0.0, lag)
            s = self.stats
            s.lag_ms = lag
            s.samples += 1
            if lag > s.max_lag_ms:
                s.max_lag_ms = lag
            if lag > self.slow_threshold_ms:
                s.slow_count += 1

    def snapshot(self) -> dict:
        s = self.stats
        return {
            "loop_lag_ms": round(s.lag_ms, 1),
            "loop_lag_max_ms": round(s.max_lag_ms, 1),
            "loop_slow_count": s.slow_count,
            "loop_samples": s.samples,
        }


#: 进程级单例（FastAPI 单事件循环；测试注入独立实例）
_monitor: LoopLagMonitor | None = None


def get_loop_monitor() -> LoopLagMonitor:
    global _monitor
    if _monitor is None:
        _monitor = LoopLagMonitor()
    return _monitor


def reset_loop_monitor() -> None:
    """测试隔离。"""
    global _monitor
    _monitor = None
