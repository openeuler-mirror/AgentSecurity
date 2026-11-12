"""FastAPI application entry point for AgentMoss HTTP API server."""

import asyncio
import logging
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from ..__version__ import __version__
from .routes import router
from .middleware import request_logging_middleware
from ..console import console_router
from ..infra.rules_mode import (
    get_rules_mode, is_builtin_only, is_runtime_config_disabled,
)
from ..infra import security_policy as sp

logger = logging.getLogger(__name__)


# ==================== 安全闸门（2026-10） ====================
# 默认值全部等于改造前的行为；唯一默认开启的是「浏览器跨源拦截」——
# 它只影响网页，对原生客户端（AgentGate / xiaoO / OpenDesk）完全不可见。

#: 需要保护、但允许浏览器直接打开的页面前缀（Console 页面本身要能加载，
#: 用户才能在页面里输入 token；页面内的 API 调用走 /console/api，照常鉴权）。
_PUBLIC_PAGE_PREFIXES = ("/console",)
_API_PREFIX = "/console/api"


def _is_public_page(path: str) -> bool:
    if not path.startswith(_API_PREFIX):
        for p in _PUBLIC_PAGE_PREFIXES:
            if path == p or path == p + "/" or path.startswith(p + "/"):
                return True
    return False


class _PooledLimiter:
    """分层并发闸门：未认证全局 → 未认证单 IP → agent → 路径池。

    全部**快速拒绝**，不排队 —— 排队会让请求继续占着连接和内存，反而放大
    DoS。计数按进程（多 worker 时各算各的，文档已说明）。
    """

    def __init__(self) -> None:
        self._counts: dict[str, int] = {}
        self._lock = asyncio.Lock()

    async def try_acquire(self, key: str, limit: int) -> bool:
        if limit <= 0:
            return True
        async with self._lock:
            cur = self._counts.get(key, 0)
            if cur >= limit:
                return False
            self._counts[key] = cur + 1
            return True

    async def release(self, key: str) -> None:
        async with self._lock:
            cur = self._counts.get(key, 0)
            if cur <= 1:
                self._counts.pop(key, None)
            else:
                self._counts[key] = cur - 1


def _busy(detail: str, status: int = 503) -> JSONResponse:
    """并发超限响应，带 ``Connection: close`` 缩短连接占用。"""
    return JSONResponse(
        status_code=status,
        content={"detail": detail},
        headers={"Retry-After": "1", "Connection": "close"},
    )


def _unauth_ip_key(request) -> str:
    return "unauth:ip:" + (getattr(request.client, "host", "") or "-")


class _RateLimiter:
    """令牌桶（按主体/来源 IP）。``qps<=0`` 时不生效（默认）。"""

    def __init__(self, qps: int, burst: int | None = None):
        self._qps = qps
        self._burst = burst or max(qps, 1) * 2
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = asyncio.Lock()

    @property
    def enabled(self) -> bool:
        return self._qps > 0

    async def allow(self, key: str) -> bool:
        if not self.enabled:
            return True
        import time as _time
        now = _time.monotonic()
        async with self._lock:
            tokens, last = self._buckets.get(key, (float(self._burst), now))
            tokens = min(self._burst, tokens + (now - last) * self._qps)
            if tokens < 1.0:
                self._buckets[key] = (tokens, now)
                return False
            self._buckets[key] = (tokens - 1.0, now)
            if len(self._buckets) > 10000:  # 防内存膨胀
                self._buckets.clear()
            return True


def _rate_key(request, principal: str) -> str:
    if principal:
        return "p:" + sp.principal_hash(principal)
    client = getattr(request, "client", None)
    return "c:" + (getattr(client, "host", "") or "-")


def _log_deployment_selfcheck() -> None:
    """启动时打印**部署自检** —— 把「会静默让安全功能失效」的配置一次性说清楚。

    为什么需要（2026-09 招行客户实例）：客户反馈「简单的路径绕过都不拦」，排查下来是
    **场景规则压根没启用**（`AGENT_MOSS_SCENARIO` 未设置）—— 此时 bank 沙箱的目录白名单
    一条都不跑，**所有路径都放行**，而服务启动没有任何提示（控制台也只是不显示场景卡片，
    客户不一定会去看）。这类「静默失效」是安全产品最不该有的，必须在启动日志里喊出来。

    ⚠️ 顺带说明为什么只能靠环境变量：HTTP 路由**不接受**请求里的 `scenario_id`
    （见 routes.py 的显式调用注释），场景是**部署级**配置。
    """
    try:
        from ..infra.runtime_config import get_runtime_config_path, is_layer_enabled

        mode = get_rules_mode()
        builtin_only = is_builtin_only()
        runtime_disabled = is_runtime_config_disabled()
        logger.info("================ AgentMoss 部署自检 ================")
        if runtime_disabled:
            logger.info("runtime 配置: %s（**已忽略**：规则来源模式=%s）",
                        get_runtime_config_path(), mode)
            if builtin_only:
                logger.warning(
                    "规则来源: **仅内置** —— 不读 runtime 配置 / Console 自定义 / 规则目录 / "
                    "AGENT_MOSS_CUSTOM_RULES；不 seed、不 merge、不写回。"
                )
            else:
                logger.warning(
                    "规则来源: **冷启动（cold）** —— 启动时读取内置规则 + 规则目录 / "
                    "AGENT_MOSS_CUSTOM_RULES / 场景，之后冻结；不读 runtime 配置 / Console，"
                    "不 seed、不 merge、不写回。"
                )
                logger.warning("规则目录内容改动需重启服务才生效。")
            logger.warning(
                "Console: 只读（规则写接口返回 403）；修改规则需重启服务并切换规则来源模式。"
            )
        else:
            logger.info("runtime 配置: %s", get_runtime_config_path())
        logger.info(
            "层级开关: %s",
            " ".join(
                f"{k}={'on' if is_layer_enabled(k) else 'OFF'}"
                for k in (
                    "L1_heuristic", "L2_logic_rules", "L3_llm_analysis",
                    "agent_rules_enabled", "scenario_rules_enabled",
                )
            ),
        )

        # 规则目录自检（2026-10 起：一个目录 + 两个固定文件名）
        #   override.json → 出现的类别**整份替换**内置
        #   extra.json    → 出现的类别**追加**在（替换后的）规则之后
        #   其他 *.json   → **不读**（必须报出来，否则就是"我放了文件怎么不生效"）
        # 仅内置规则模式下规则目录被整体忽略，不再打印（避免让部署方误以为读到了）。
        if not builtin_only:
            try:
                from ..rules_loader import (OVERRIDE_FILENAME, EXTRA_FILENAME, rules_dirs,
                                            rule_files_loaded, ignored_rule_files)
                _dirs = [str(d) for d in rules_dirs() if d.is_dir()]
                if _dirs:
                    logger.info("规则目录: %s（只读其中 %s / %s）",
                                ", ".join(_dirs), OVERRIDE_FILENAME, EXTRA_FILENAME)
                _loaded = rule_files_loaded()
                if _loaded:
                    logger.warning(
                        "已从规则目录加载 %d 个文件（**整份替换**或追加，内置更新不会反映到它们上面）:",
                        len(_loaded),
                    )
                    for _p in _loaded:
                        logger.warning("      %s", _p)
                _ignored = ignored_rule_files()
                if _ignored:
                    logger.warning(
                        "⚠️  规则目录里有 %d 个 json **不会被读取**（只认 %s / %s）:",
                        len(_ignored), OVERRIDE_FILENAME, EXTRA_FILENAME,
                    )
                    for _p in _ignored:
                        logger.warning("      %s", _p)
            except Exception as exc:  # noqa: BLE001 — 自检失败不影响启动
                logger.debug("规则目录自检失败: %s", exc)

        scenario_raw = os.getenv("AGENT_MOSS_SCENARIO", "").strip()
        if scenario_raw:
            logger.info(
                "场景规则已启用: %s（来源：环境变量 AGENT_MOSS_SCENARIO）", scenario_raw,
            )
        else:
            logger.warning(
                "⚠️  场景规则【未启用】—— 环境变量 AGENT_MOSS_SCENARIO 未设置。\n"
                "    场景定制规则（如银行沙箱的目录白名单 / 禁 ssh）**不会生效**，"
                "白名单外的路径会被放行。\n"
                "    启用方式：设 AGENT_MOSS_SCENARIO=<场景id>（如 bank；多场景逗号分隔）"
                "后**重启本服务**。\n"
                "    （HTTP 请求无法指定场景 id，场景是部署级配置。）"
            )
        logger.info("==================================================")
    except Exception as exc:  # 自检失败不能影响服务启动
        logger.warning("部署自检失败（不影响服务）: %s", exc)

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
        # 规则包契约：schema 版本 / 完整性 / 内容指纹。
        # 显式指定了 AGENT_MOSS_RULES_ROOT 且校验失败 → 这里会抛异常，服务拒绝启动
        # （带着残缺规则跑 = 静默放开一批防护）。
        from ..rules_contract import enforce_rules_contract
        enforce_rules_contract()
        # 存量文件的权限收紧（升级前就是 0644 的那些）
        sp.harden_existing_paths()
        # 安全配置摘要（不含任何 secret）—— 客户报问题时一眼看清当前生效的安全姿态
        logger.info("安全策略: %s", sp.describe())
        # 鉴权配置坏了（例如显式指定了 AUTH_TOKEN_FD 却读不到）就**不要带病运行**：
        # 要么全部 401（看着像客户端问题），要么悄悄退回无鉴权（安全问题）。
        sp.fail_fast_on_auth_error()
        # 部署自检：明确告知场景规则是否启用（未启用 = 银行沙箱目录白名单不生效）
        _log_deployment_selfcheck()
        # 在默认线程池里预热：真实请求也是经 run_in_executor 跑的（routes.py:350），
        # 这样线程池本身、以及 worker 线程里才会触发的惰性导入也一并热掉。
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, _warm_up_engine)

    # CORS：**不再默认全放行**（2026-10 安全加固）。
    # 为什么收紧是安全的：Console 前端用的是相对路径 fetch（同源），iframe 嵌入时
    # iframe 内的 JS 也运行在 AgentMoss 自己的 origin，两者都不需要 CORS；
    # 而 analyze 等接口的调用方是**原生进程**（AgentGate / xiaoO / OpenDesk），
    # CORS 对它们根本不适用。需要额外来源（如 app:// webview 直连）时配
    # `AGENT_MOSS_CORS_ORIGINS`，或用 `AGENT_MOSS_ORIGIN_CHECK=0` 一键回退。
    app.add_middleware(
        CORSMiddleware,
        allow_origins=sp.allowed_origins(),
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    app.middleware("http")(request_logging_middleware)

    @app.middleware("http")
    async def _block_console_writes(request, call_next):
        """cold / builtin 模式下 Console 只读：所有规则写请求直接 403。

        不依赖各个端点自己检查 —— 新加的写端点也自动被兜住。GET/HEAD/OPTIONS
        仍放行，保留查看内置规则的能力。中间件**无条件注册**、每个请求现判模式，
        避免 create_app 之后环境变量/缓存变化导致中间件缺失。
        """
        if (
            is_runtime_config_disabled()
            and request.url.path.startswith("/console/api")
            and request.method not in ("GET", "HEAD", "OPTIONS")
        ):
            return JSONResponse(
                status_code=403,
                content={
                    "detail": (
                        f"规则来源模式为 {get_rules_mode()}（runtime 配置已禁用）："
                        "Console 只读，修改不会保存。请切换规则来源模式并重启服务后再改规则。"
                    )
                },
                # 本中间件在 CORSMiddleware 外层；手动带上 CORS 头，跨域 iframe
                # 嵌入时前端才能读到 403 的 detail（而不是一个笼统的网络错误）。
                headers={"Access-Control-Allow-Origin": "*"},
            )
        return await call_next(request)

    # ==================== 安全闸门（最外层，先于业务路由） ====================
    _pools = _PooledLimiter()
    _limiter = _RateLimiter(sp.rate_limit_qps())

    @app.middleware("http")
    async def _security_guard(request, call_next):
        """来源校验 / 鉴权 / 体积上限 / 限流。全部有开关，默认值见 security_policy。

        顺序刻意如此：先做最便宜的判断（体积、来源、鉴权），被拒的请求不再进入
        分析路径 —— 这本身就是 DoS 的第一道闸。
        """
        path = request.url.path
        method = request.method.upper()

        # 0) 预检交给 CORS 中间件处理（它决定是否回 allow-* 头）
        if method == "OPTIONS":
            return await call_next(request)

        # 1) 请求体大小上限（仅对带 Content-Length 的常规客户端；
        #    chunked 由各框架的读取上限兜底）
        max_body = sp.max_body_bytes()
        cl = request.headers.get("content-length")
        if cl and max_body > 0:
            try:
                if int(cl) > max_body:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": f"请求体超过上限 {max_body} 字节"},
                    )
            except ValueError:
                pass

        # 2) 浏览器跨源拦截（原生客户端不带 Origin → 不受影响）
        if sp.origin_check_enabled():
            origin = request.headers.get("origin", "")
            if origin and not sp.origin_allowed(origin, request.headers.get("host", "")):
                logger.warning(
                    "已拦截跨源请求: origin=%s path=%s（如需放行，把来源加入 "
                    "AGENT_MOSS_CORS_ORIGINS）", origin, path,
                )
                return JSONResponse(
                    status_code=403,
                    content={"detail": f"跨源来源未被允许: {origin}"},
                )

        # 3) 鉴权（未配置 token 时 auth_enabled()=False → 完全保持历史行为）
        ok_auth, principal = sp.check_request_auth(request.headers, path)
        if not ok_auth and not _is_public_page(path):
            return JSONResponse(
                status_code=401,
                content={"detail": "Unauthorized: invalid or missing Bearer token"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        # 4) 限流（0 = 不限，默认）
        if _limiter.enabled and path.startswith("/api/"):
            if not await _limiter.allow(_rate_key(request, principal)):
                return JSONResponse(
                    status_code=429,
                    content={"detail": "请求过于频繁，请稍后重试"},
                    headers={"Retry-After": "1"},
                )

        # 5) 分层并发闸门（快速拒绝，不排队）
        #    未认证全局 → 未认证单 IP → agent → 路径池，四层都拿到才放行。
        _keys: list[str] = []

        async def _take(key: str, limit: int) -> bool:
            if await _pools.try_acquire(key, limit):
                _keys.append(key)
                return True
            return False

        try:
            # 5.1 未认证配额。AUTH_MODE=off 时跳过：没有身份是配置选择，
            #     不是攻击，不能把正常业务全当成未认证。
            if not principal and sp.auth_enabled():
                if not await _take("unauth:total", sp.unauth_inflight()):
                    return _busy("未认证请求并发超限，请持凭证访问")
                if not await _take(_unauth_ip_key(request), sp.unauth_per_ip()):
                    return _busy("该来源的未认证请求并发超限")
            else:
                _bound = sp.bound_agent_of(principal)
                if _bound and not await _take(f"agent:{_bound}", sp.agent_inflight()):
                    return _busy(f"agent '{_bound}' 的并发超限，请稍后重试", 429)

            # 5.2 路径池：Console 打满只占 ops 池，不挤占 analyze 的 biz 池；
            #     review 单独 1 条，全量回顾不能和实时分析抢并发
            _pool = sp.pool_of(path)
            if not await _take(f"pool:{_pool}", sp.pool_limit(_pool)):
                # 并发被拒的频次统计：同一主体反复撞池上限，说明是在刷
                _qkey = _rate_key(request, principal)
                _q_n, _q_abusive = sp.note_queue_reject(_qkey)
                if _q_abusive and sp.queue_abuse_action() == "deny":
                    return _busy("并发拒绝过于频繁，疑似恶意请求", 429)
                if _q_abusive:
                    logger.warning(
                        "⚠️ 疑似恶意并发占用: key=%s 窗口内被拒 %d 次（阈值 %d）",
                        _qkey, _q_n, sp.queue_abuse_threshold(),
                    )
                return _busy("服务繁忙（并发已满），请稍后重试")

            return await call_next(request)
        finally:
            while _keys:
                await _pools.release(_keys.pop())

    app.include_router(router)
    # Policy Console（浏览器策略管控台，挂载在 /console 前缀）
    app.include_router(console_router)

    return app


#: 预热用的命令：whoami 在 Linux 白名单里（`^whoami(?:\s|$)`），命中即快速放行，
#: 只走 L1 特征匹配，不会调 LLM。换成需要 L2/L3 的命令会带出副作用（写 Policy、
#: 连 LLM），所以刻意选它。
_WARMUP_COMMAND = "whoami"

#: 预热时构造一遍的平台 profile —— 各平台的规则 JSON 就在构造时读取。
_WARMUP_PLATFORMS = ("linux", "windows", "macos", "harmony")


def _warm_up_engine() -> None:
    """预热分析引擎，消除服务重启后**第一个请求**的冷启动延迟。

    引擎模块树（analyzer → coordinator → heuristic → logic_rules → …）原先是在
    请求处理函数里惰性 import 的（routes.py:272），规则 JSON 的加载与正则编译则
    发生在首次 analyze() 时。于是重启后的第一个请求要替所有人付这笔钱 ——
    实测（全新进程）：首个请求 104.9ms，之后稳定 5–7ms；单是导入引擎模块树
    就要 ~276ms。放到启动钩子里做，这笔钱就花在没人等的时刻。

    副作用：无。预热命令走白名单快速放行（不碰 LLM），且期间临时关掉落盘
    （否则会在 policy 目录留下一个 __startup_warmup__.toml）。任何异常都只记
    日志 —— 预热失败不能拖垮服务启动。
    """
    import os

    prev_save_policy = os.environ.get("AGENT_MOSS_SAVE_POLICY")
    try:
        from ..engine.analyzer import analyze  # noqa: F401 — 触发引擎模块树导入
        from ..profiles import get_profile
        # 路由在 analyze() 之前还会惰性导入这个（routes.py:271），首访 ~12ms，一并热掉
        from ..adapters.observable import is_raw_format  # noqa: F401

        profiles = {}
        for name in _WARMUP_PLATFORMS:
            try:
                profiles[name] = get_profile(name)
            except Exception as exc:  # noqa: BLE001 — 单个平台失败不影响其余
                logger.warning("预热 %s profile 失败（忽略）: %s", name, exc)

        # 白名单放行也会写 Policy 文件；预热不该在磁盘上留东西
        os.environ["AGENT_MOSS_SAVE_POLICY"] = "0"
        analyze(
            session_id="__startup_warmup__",
            prompt_session="",
            action_history=[],
            a_next={"action_type": "bash", "action_detail": _WARMUP_COMMAND},
            reason="",
            config=None,
            cache=None,
            profile=profiles.get("linux"),
            llm_config=None,
            cwd="",
            agent_id="",
            scenario_id="",
            llm_log_path=None,
            prompt_history=[],
            session_history=[],
        )
        logger.info("引擎预热完成（首个请求不再付冷启动开销）")
    except Exception as exc:  # noqa: BLE001
        logger.warning("引擎预热失败（不影响服务）: %s", exc)
    finally:
        if prev_save_policy is None:
            os.environ.pop("AGENT_MOSS_SAVE_POLICY", None)
        else:
            os.environ["AGENT_MOSS_SAVE_POLICY"] = prev_save_policy


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
        uvicorn.run(
            app, host=host, port=actual_port, log_level="info",
            # 连接层防护（2026-10）：限并发连接 + 空闲连接超时，
            # 挡住"只占连接不发完整请求"的慢速攻击。
            limit_concurrency=sp.max_connections(),
            timeout_keep_alive=sp.keep_alive_sec(),
        )
