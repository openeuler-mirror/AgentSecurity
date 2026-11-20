"""进程内指标收集 + Prometheus 文本格式输出（零第三方依赖）。

为什么手写而不引入 `prometheus_client`（2026-11）：

- 本项目面向**离线/内网**部署，多一个依赖就多一份交付风险（客户环境没有 pip 源）。
- 需要的指标形态很固定（计数器 + 直方图 + Gauge），Prometheus 文本格式本身
  只有几行规则，自己渲染比引依赖更可控。

暴露方式：`GET /metrics`（与 `/api/v1/health` 同级的运维端点）。

指标清单见 `docs/deploy/PERFORMANCE_TUNING.md` / `docs/METRICS.md`。

线程安全：所有写入走同一把 `threading.Lock`。单次写入是几个 dict 操作，
在 analyze 的耗时里占比可忽略（实测 < 1μs）。
"""

from __future__ import annotations

import threading
import time

#: 默认耗时桶（秒）。覆盖 L1/L2 的毫秒级到 L3 的几十秒。
DEFAULT_BUCKETS = (
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0,
)

#: 用 RLock：内部辅助函数之间偶尔会复用公开方法（如 refresh_runtime_gauges
#: 调 Gauge.set），普通 Lock 重入即死锁。RLock 让这类调用安全，同时仍保证
#: 跨线程互斥。
_lock = threading.RLock()
_started_at = time.time()


def _format_labels(labels: dict[str, str] | None) -> str:
    if not labels:
        return ""
    inner = ",".join(f'{k}="{_escape(v)}"' for k, v in sorted(labels.items()))
    return "{" + inner + "}"


def _escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class _Metric:
    """所有指标的公共部分：名称 / 帮助文本 / 标签名。"""

    def __init__(self, name: str, help_text: str, labelnames: tuple[str, ...] = ()):
        self.name = name
        self.help_text = help_text
        self.labelnames = labelnames


class Counter(_Metric):
    """单调递增计数器（进程重启归零）。"""

    def __init__(self, name: str, help_text: str, labelnames: tuple[str, ...] = ()):
        super().__init__(name, help_text, labelnames)
        self._values: dict[tuple[str, ...], float] = {}

    def inc(self, amount: float = 1.0, **labels: str) -> None:
        key = tuple(str(labels.get(k, "")) for k in self.labelnames)
        with _lock:
            self._values[key] = self._values.get(key, 0.0) + amount

    def render(self) -> list[str]:
        out = [f"# HELP {self.name} {self.help_text}", f"# TYPE {self.name} counter"]
        with _lock:
            items = list(self._values.items())
        if not items:
            # 至少输出一条 0，否则 Prometheus 里看不到这个序列
            out.append(f"{self.name}{_format_labels({k: '' for k in self.labelnames})} 0")
            return out
        for key, value in items:
            labels = dict(zip(self.labelnames, key)) if self.labelnames else None
            out.append(f"{self.name}{_format_labels(labels)} {value}")
        return out


class Gauge(_Metric):
    """可增可减的瞬时值。"""

    def __init__(self, name: str, help_text: str, labelnames: tuple[str, ...] = ()):
        super().__init__(name, help_text, labelnames)
        self._values: dict[tuple[str, ...], float] = {}

    def set(self, value: float, **labels: str) -> None:
        key = tuple(str(labels.get(k, "")) for k in self.labelnames)
        with _lock:
            self._values[key] = float(value)

    def render(self) -> list[str]:
        out = [f"# HELP {self.name} {self.help_text}", f"# TYPE {self.name} gauge"]
        with _lock:
            items = list(self._values.items())
        for key, value in items:
            labels = dict(zip(self.labelnames, key)) if self.labelnames else None
            out.append(f"{self.name}{_format_labels(labels)} {value}")
        return out


class Histogram(_Metric):
    """累积直方图（只输出 `_bucket` / `_sum` / `_count`）。"""

    def __init__(
        self,
        name: str,
        help_text: str,
        buckets: tuple[float, ...] = DEFAULT_BUCKETS,
        labelnames: tuple[str, ...] = (),
    ):
        super().__init__(name, help_text, labelnames)
        self.buckets = tuple(sorted(buckets))
        # key -> [bucket_counts..., sum, count]
        self._values: dict[tuple[str, ...], list[float]] = {}

    def observe(self, value: float, **labels: str) -> None:
        key = tuple(str(labels.get(k, "")) for k in self.labelnames)
        v = float(value)
        with _lock:
            slot = self._values.get(key)
            if slot is None:
                slot = [0.0] * len(self.buckets) + [0.0, 0.0]
                self._values[key] = slot
            for i, bound in enumerate(self.buckets):
                if v <= bound:
                    slot[i] += 1.0
            slot[-2] += v
            slot[-1] += 1.0

    def render(self) -> list[str]:
        out = [
            f"# HELP {self.name} {self.help_text}",
            f"# TYPE {self.name} histogram",
        ]
        with _lock:
            items = list(self._values.items())
        for key, slot in items:
            base = dict(zip(self.labelnames, key)) if self.labelnames else {}
            for i, bound in enumerate(self.buckets):
                labels = dict(base)
                labels["le"] = str(bound)
                out.append(f"{self.name}_bucket{_format_labels(labels)} {slot[i]}")
            labels = dict(base)
            labels["le"] = "+Inf"
            out.append(f"{self.name}_bucket{_format_labels(labels)} {slot[-1]}")
            out.append(f"{self.name}_sum{_format_labels(base or None)} {slot[-2]}")
            out.append(f"{self.name}_count{_format_labels(base or None)} {slot[-1]}")
        return out


# ==================== 指标定义 ====================

ANALYZE_TOTAL = Counter(
    "agent_moss_analyze_total",
    "Total analyze requests handled, by decision, risk level and L3 outcome.",
    ("decision", "risk_level", "l3_outcome"),
)
ANALYZE_DURATION = Histogram(
    "agent_moss_analyze_duration_seconds",
    "End-to-end analyze duration in seconds.",
    labelnames=("decision",),
)
#: 排队等待时长（进入路由 → 真正开始在 executor 里执行）。
#: 与 ``ANALYZE_DURATION`` 对比就能区分「算得慢」还是「排不上队」——
#: 客户 TPS < 1 时这两个值是最直接的判据（2026-11）。
ANALYZE_QUEUE_WAIT = Histogram(
    "agent_moss_analyze_queue_wait_seconds",
    "Time an analyze request waited before an executor thread picked it up.",
    buckets=(0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0),
)
#: 纯计算时长（不含排队）。= ANALYZE_DURATION - 排队 - 响应序列化等开销。
ANALYZE_WORK_DURATION = Histogram(
    "agent_moss_analyze_work_seconds",
    "Pure analysis work duration (excludes queueing and response serialization).",
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
)
LAYER_HIT_TOTAL = Counter(
    "agent_moss_layer_hit_total",
    "Number of requests where a given defense layer produced the final verdict.",
    ("layer",),
)
LAYER_DURATION = Histogram(
    "agent_moss_layer_duration_seconds",
    "Per-layer detection duration in seconds (L1 heuristic / L2 logic rules).",
    buckets=(
        0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0,
    ),
    labelnames=("layer",),
)
REJECTED_TOTAL = Counter(
    "agent_moss_rejected_total",
    "Requests rejected before analysis (concurrency / rate limit / auth).",
    ("reason",),
)
LLM_CALLS_TOTAL = Counter(
    "agent_moss_llm_calls_total",
    "LLM API calls, by outcome.",
    ("result",),
)
LLM_DURATION = Histogram(
    "agent_moss_llm_duration_seconds",
    "LLM API call duration in seconds.",
    labelnames=("result",),
)
POOL_INFLIGHT = Gauge(
    "agent_moss_pool_inflight",
    "Current in-flight requests per concurrency pool.",
    ("pool",),
)
CHAIN_NODES = Gauge(
    "agent_moss_chain_nodes",
    "Number of nodes in the stateful chain timeline.",
    ("agent",),
)
CHAIN_DB_BYTES = Gauge(
    "agent_moss_chain_db_bytes",
    "Size of the chain state database in bytes.",
)
LOOP_LAG = Gauge(
    "agent_moss_event_loop_lag_seconds",
    "Most recent event loop lag sample in seconds.",
)
LOOP_LAG_MAX = Gauge(
    "agent_moss_event_loop_lag_max_seconds",
    "Maximum event loop lag observed since process start, in seconds.",
)
UPTIME = Gauge(
    "agent_moss_uptime_seconds",
    "Seconds since process start.",
)
LLM_CIRCUIT_STATE = Gauge(
    "agent_moss_llm_circuit_state",
    "LLM circuit breaker state (0=closed, 1=open, 2=half_open).",
)
LLM_SHORT_CIRCUIT_TOTAL = Counter(
    "agent_moss_llm_short_circuit_total",
    "LLM calls short-circuited by the breaker (no network request made).",
)


def render_prometheus() -> str:
    """渲染全部指标（Prometheus text exposition format 0.0.4）。"""
    lines: list[str] = []
    for metric in (
        ANALYZE_TOTAL,
        ANALYZE_DURATION,
        ANALYZE_QUEUE_WAIT,
        ANALYZE_WORK_DURATION,
        LAYER_HIT_TOTAL,
        LAYER_DURATION,
        REJECTED_TOTAL,
        LLM_CALLS_TOTAL,
        LLM_DURATION,
        POOL_INFLIGHT,
        CHAIN_NODES,
        CHAIN_DB_BYTES,
        LOOP_LAG,
        LOOP_LAG_MAX,
        UPTIME,
        LLM_CIRCUIT_STATE,
        LLM_SHORT_CIRCUIT_TOTAL,
    ):
        lines.extend(metric.render())
    return "\n".join(lines) + "\n"


def refresh_runtime_gauges(
    pools: dict[str, int] | None = None,
    chain_nodes: int | None = None,
    chain_db_bytes: int | None = None,
    loop_lag_ms: float | None = None,
    loop_lag_max_ms: float | None = None,
) -> None:
    """把瞬时值刷进 Gauge（在 /metrics 被拉取时调用）。"""
    UPTIME.set(time.time() - _started_at)
    try:
        from .circuit_breaker import get_breaker

        snap = get_breaker().snapshot()
        LLM_CIRCUIT_STATE.set({"closed": 0, "open": 1, "half_open": 2}.get(snap["state"], 0))
        # 计数器是单调的，用 state 直接赋值会丢失历史；这里只反映当前进程累计
        with _lock:
            LLM_SHORT_CIRCUIT_TOTAL._values.clear()  # noqa: SLF001
        LLM_SHORT_CIRCUIT_TOTAL.inc(snap["short_circuit_count"])
    except Exception:  # noqa: BLE001
        pass
    if pools is not None:
        # 先清掉旧的 label 组合：池占用是动态的，不清会残留历史序列
        with _lock:
            POOL_INFLIGHT._values.clear()  # noqa: SLF001 —— 同模块内的受控清理
        for key, value in pools.items():
            POOL_INFLIGHT.set(value, pool=key)
    if chain_nodes is not None:
        # 注意：`set()` 自己也要拿 _lock。**必须在锁外调用**，否则
        # threading.Lock 不可重入 → 整个事件循环死锁（2026-11 端到端实测踩到：
        # /metrics 与 health 全部超时）。
        with _lock:
            CHAIN_NODES._values.clear()  # noqa: SLF001
        CHAIN_NODES.set(chain_nodes, agent="__total__")
    if chain_db_bytes is not None:
        CHAIN_DB_BYTES.set(chain_db_bytes)
    if loop_lag_ms is not None:
        LOOP_LAG.set(loop_lag_ms / 1000.0)
    if loop_lag_max_ms is not None:
        LOOP_LAG_MAX.set(loop_lag_max_ms / 1000.0)


def reset_for_tests() -> None:
    """测试隔离：清空所有指标。"""
    global _started_at
    with _lock:
        for metric in (
            ANALYZE_TOTAL,
            ANALYZE_DURATION,
            ANALYZE_QUEUE_WAIT,
            ANALYZE_WORK_DURATION,
            LAYER_HIT_TOTAL,
            LAYER_DURATION,
            REJECTED_TOTAL,
            LLM_CALLS_TOTAL,
            LLM_DURATION,
            POOL_INFLIGHT,
            CHAIN_NODES,
            CHAIN_DB_BYTES,
            LOOP_LAG,
            LOOP_LAG_MAX,
            UPTIME,
        ):
            metric._values.clear()  # noqa: SLF001
    _started_at = time.time()
