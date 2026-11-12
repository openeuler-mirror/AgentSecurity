"""AgentMoss 自身的安全策略 —— 来源校验 / 鉴权 / 路径白名单 / 脱敏 / 限额。

**设计原则（2026-10）**：所有开关的**默认值都必须等于改造前的行为**，除非该默认值
本身就是漏洞（例如"任意 Origin 都放行"）。这样存量用户升级后功能与体验完全不变，
需要更严的部署（客户沙箱 / 送检）再显式打开。

| 环境变量 | 默认 | 作用 |
|---|---|---|
| ``AGENT_MOSS_ORIGIN_CHECK`` | ``1`` | 浏览器跨源请求拦截（**默认开**：只影响网页，不影响原生客户端） |
| ``AGENT_MOSS_CORS_ORIGINS`` | 空 | 额外允许的跨源来源，逗号分隔；``null`` 表示允许 file:// |
| ``AGENT_MOSS_AUTH_TOKEN`` | 空 | 全局 Bearer token；**空 = 不鉴权（保持现状）** |
| ``AGENT_MOSS_AUTH_TOKEN_FILE`` | 空 | 同上，从文件读（便于 0600 保存） |
| ``AGENT_MOSS_AGENT_TOKENS`` | 空 | 每个 agent 一个 token，``agent=tok,agent2=tok2``；启用后 ``agent_id`` 必须与 token 匹配 |
| ``AGENT_MOSS_LOG_ROOTS`` | ``$HOME,/tmp,$TMPDIR`` | ``metadata.llm_log_path`` 允许落盘的根目录（root 下取真实用户家目录；多用户机器不猜，需显式配置） |
| ``AGENT_MOSS_REVIEW_PATHS`` | AgentGate 标准目录 | ``/api/v1/review`` 的 ``db_path`` 允许读取的根目录 |
| ``AGENT_MOSS_CHAIN_DETAIL`` | ``redacted`` | 组合链返回：``redacted`` 隐藏跨会话命令原文，``full`` 全量 |
| ``AGENT_MOSS_MAX_BODY_BYTES`` | 16MB | 请求体上限 |
| ``AGENT_MOSS_MAX_INFLIGHT`` | 16 | 同时分析的最大请求数（**默认开启**）；0 = 不限（仅调试用） |
| ``AGENT_MOSS_MAX_QUEUE`` | 256 | 超出并发后允许排队的数量（仅 ``MAX_INFLIGHT>0`` 时生效） |
| ``AGENT_MOSS_RATE_LIMIT_QPS`` | 100 | 单主体每秒请求数上限（**默认开启**）；0 = 不限（仅调试用） |
| ``AGENT_MOSS_LLM_HOST_ALLOWLIST`` | 空 | ``metadata.llm_config.baseUrl`` 允许的主机；空 = 不限主机（协议仍校验） |
| ``AGENT_MOSS_TRUST_PRIVATE_LLM`` | ``1`` | 是否允许 baseUrl 指向内网/回环（本地模型常见，默认允许） |

"""
from __future__ import annotations

import hashlib
import hmac
import logging
import ipaddress
import os
import stat
import tempfile
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger("agent_moss.security")


# ==================== 基础读取 ====================

TRUTHY = ("1", "true", "yes", "on")


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _env_int(name: str, default: int) -> int:
    raw = _env(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _split(raw: str) -> list[str]:
    return [x.strip() for x in raw.replace(";", ",").split(",") if x.strip()]


# ==================== 来源校验（浏览器跨源） ====================

def origin_check_enabled() -> bool:
    return _env("AGENT_MOSS_ORIGIN_CHECK", "1").lower() in TRUTHY


def allowed_origins() -> list[str]:
    """额外允许的来源（同源永远允许，不需要列在这里）。"""
    return _split(_env("AGENT_MOSS_CORS_ORIGINS"))


def normalize_origin(origin: str) -> str:
    return (origin or "").strip().rstrip("/")


def origin_allowed(origin: str, host_header: str, extra: list[str] | None = None) -> bool:
    """跨源请求是否放行。

    - 没有 Origin 头 → 放行（原生客户端不发 Origin）
    - Origin 与 Host 同源 → 放行（Console 页面自己）
    - 在 ``AGENT_MOSS_CORS_ORIGINS`` 里 → 放行
    - 其他 → 拒绝
    """
    o = normalize_origin(origin)
    if not o:
        return True
    entries = [normalize_origin(x) for x in (extra if extra is not None else allowed_origins())]
    if o in entries:
        return True
    host = (host_header or "").strip()
    if not host:
        return False
    parsed = urlparse(o)
    return bool(parsed.netloc) and parsed.netloc == host


# ==================== 鉴权 ====================

HEALTH_PATHS = ("/api/v1/health",)

#: 鉴权模式：
#: - ``auto``（默认）：首次启动自动生成 token 写到 ``<data_root>/auth_token``（0600），
#:   之后所有非 health 请求都要带它 —— 出厂即安全，不需要运维额外配置。
#: - ``off``：完全关闭鉴权（等价于 0.16.14 之前的行为），给"本机单用户、只想要旧体验"的场景。
AUTH_MODE_AUTO = "auto"
AUTH_MODE_OFF = "off"

#: 解析结果缓存：(cache_key, token, agent_tokens)。键里带上所有相关环境变量与数据根，
#: 测试 monkeypatch 改完立即生效，同时避免每次请求都重新解析/读文件。
_TOKEN_CACHE: tuple[tuple, str, dict[str, str], str] | None = None


def auth_mode() -> str:
    return (_env("AGENT_MOSS_AUTH_MODE", AUTH_MODE_AUTO) or AUTH_MODE_AUTO).lower()


def auto_token_path() -> Path:
    from .paths import get_data_root
    return get_data_root() / "auth_token"


#: 从继承的 fd 读到的 token（fd → token）。fd 只能读一次，缓存起来；
#: 键是 fd 号，测试换 fd 时自动重读。
_FD_TOKEN_CACHE: dict[int, str] = {}


def _read_fd_token() -> str:
    """从**继承的文件描述符**读 token（``AGENT_MOSS_AUTH_TOKEN_FD=3``）。

    为什么需要：写进文件/env 的 token，同 OS 用户的任何进程都能读
    （文件 → cat；env → /proc/<pid>/environ）。走 fd 时，只有**分配这个 fd 的父进程**
    和本进程持有它，其他进程既不在文件系统里、也不在 environ 里看到它。
    配合 ``kernel.yama.ptrace_scope=1``（Ubuntu 默认），同用户进程也读不到内存 ——
    这才真正堵住"偷 token 冒充 agent"这条路。
    """
    raw = _env("AGENT_MOSS_AUTH_TOKEN_FD")
    if not raw:
        return ""
    try:
        fd = int(raw)
    except ValueError:
        return ""
    if fd in _FD_TOKEN_CACHE:
        return _FD_TOKEN_CACHE[fd]
    try:
        data = os.read(fd, 8192)
    except OSError as e:
        logger.error("从 fd %d 读取访问 token 失败: %s", fd, e)
        _FD_TOKEN_CACHE[fd] = ""
        return ""
    try:
        os.close(fd)  # 读完即关，避免 fd 泄漏
    except OSError:
        pass
    tok = data.decode("utf-8", errors="ignore").strip()
    _FD_TOKEN_CACHE[fd] = tok
    if not tok:
        logger.error("fd %d 里没有读到访问 token", fd)
    return tok


def _read_explicit_token() -> str:
    tok = _env("AGENT_MOSS_AUTH_TOKEN")
    if tok:
        return tok
    tok = _read_fd_token()
    if tok:
        return tok
    path = _env("AGENT_MOSS_AUTH_TOKEN_FILE")
    if path:
        try:
            return Path(path).read_text(encoding="utf-8").strip()
        except OSError:
            return ""
    return ""


def _ensure_auto_token() -> str:
    """首次启动生成 token（0600）；已存在则读取。失败返回空串（不阻断启动）。"""
    path = auto_token_path()
    try:
        if path.is_file() and not path.is_symlink():
            tok = path.read_text(encoding="utf-8").strip()
            if tok:
                harden_permissions(path, stat.S_IRUSR | stat.S_IWUSR)
                return tok
        import secrets
        tok = secrets.token_urlsafe(32)
        ensure_private_dir(path.parent)
        # 原子创建（O_EXCL）：多 worker 同时启动时只有一个能创建成功，
        # 其余读到同一份 token —— 否则每个 worker 各生成一个，客户端只能猜中一个。
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(str(path), flags, 0o600)
            try:
                os.write(fd, (tok + "\n").encode("utf-8"))
            finally:
                os.close(fd)
        except FileExistsError:
            tok = path.read_text(encoding="utf-8").strip()
            return tok
        logger.warning(
            "已生成访问 token 并写入 %s（0600）。客户端需带 "
            "`Authorization: Bearer <token>`；查看：cat %s；"
            "如需关闭鉴权：AGENT_MOSS_AUTH_MODE=off",
            path, path,
        )
        return tok
    except Exception as e:  # noqa: BLE001
        logger.error("生成访问 token 失败（本次运行将不鉴权）: %s", e)
        return ""


def _parse_agent_tokens(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for pair in _split(raw):
        if "=" in pair:
            agent, tok = pair.split("=", 1)
            if agent.strip() and tok.strip():
                out[agent.strip()] = tok.strip()
    return out


def _resolve_auth() -> tuple[str, dict[str, str], str]:
    """返回 ``(全局 token, 每 agent token, 配置错误信息)``，解析一次并缓存。

    ⚠️ 缓存键**只由环境变量字符串组成** —— 不要把 ``auto_token_path()`` 放进键里：
    它要走 get_data_root()（约 7µs）+ Path 运算，而这是**每个请求**都会调用的热路径。
    环境变量改了键自然变化，缓存立即失效。
    """
    global _TOKEN_CACHE
    raw_agents = _env("AGENT_MOSS_AGENT_TOKENS")
    key = (
        auth_mode(),
        _env("AGENT_MOSS_AUTH_TOKEN"),
        _env("AGENT_MOSS_AUTH_TOKEN_FILE"),
        _env("AGENT_MOSS_AUTH_TOKEN_FD"),
        raw_agents,
        _env("AGENT_MOSS_DATA_DIR"),
    )
    if _TOKEN_CACHE is not None and _TOKEN_CACHE[0] == key:
        return _TOKEN_CACHE[1], _TOKEN_CACHE[2], _TOKEN_CACHE[3]

    error = ""
    token = _read_explicit_token()

    # 显式指定了 fd 却读不到 —— **绝不静默降级**去磁盘生成 token。
    # 降级的后果是双输：调用方拿着自己的 token 全部 401（服务等于挂了），
    # 同时磁盘上多出一份同用户任何进程都能读的凭证（安全目标也丢了）。
    # 正确做法是明确报错、拒绝启动（见 fail_fast_on_auth_error）。
    if not token and _env("AGENT_MOSS_AUTH_TOKEN_FD") and auth_mode() != AUTH_MODE_OFF:
        error = (
            "AGENT_MOSS_AUTH_TOKEN_FD 已设置，但没能从该文件描述符读到 token。"
            "拒绝降级到磁盘 token（那会在本机留下一份同用户可读的凭证）。"
        )
        logger.error(error)

    if not token and not error and auth_mode() != AUTH_MODE_OFF:
        token = _ensure_auto_token()

    agents = _parse_agent_tokens(raw_agents)
    _TOKEN_CACHE = (key, token, agents, error)
    return token, agents, error


def _auth_token() -> str:
    return _resolve_auth()[0]


def agent_tokens() -> dict[str, str]:
    """``AGENT_MOSS_AGENT_TOKENS`` → ``{agent_id: token}``。"""
    return _resolve_auth()[1]


def auth_config_error() -> str:
    """鉴权配置是否坏了（目前只有 fd 读取失败这一种）。空串 = 正常。"""
    return _resolve_auth()[2]


def fail_fast_on_auth_error() -> None:
    """启动时调用：鉴权配置错误就**直接退出**，不要带病运行。

    带病运行的两种表现都比退出更难排查：要么全部 401（看着像客户端问题），
    要么悄悄退回无鉴权（安全问题）。
    """
    err = auth_config_error()
    if err:
        logger.error("鉴权配置错误，拒绝启动: %s", err)
        raise SystemExit(1)


def auth_enabled() -> bool:
    if auth_mode() == AUTH_MODE_OFF:
        return False
    tok, agents, _err = _resolve_auth()
    return bool(tok or agents)


def _bearer(headers) -> str:
    value = headers.get("authorization", "") if hasattr(headers, "get") else ""
    if value.lower().startswith("bearer "):
        return value[7:].strip()
    return ""


def _const_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def check_request_auth(headers, path: str) -> tuple[bool, str]:
    """返回 ``(是否放行, 绑定到的主体)``。

    - 未配置任何 token → 放行，主体为空（保持历史行为）
    - 鉴权配置坏了（fd 读不到）→ **除 health 外全部拒绝**（fail-closed）
    - ``/api/v1/health`` 永远放行（探活）
    - 全局 token：任一请求带上即可
    - 每 agent token：请求的 ``agent_id`` 必须与 token 对应（由调用方在拿到
      agent_id 后二次校验，见 ``bind_agent``）
    """
    if auth_mode() == AUTH_MODE_OFF:
        return True, ""
    is_health = path.rstrip("/") in HEALTH_PATHS
    global_tok, agents, err = _resolve_auth()
    if err:
        return (True, "") if is_health else (False, "")
    if not global_tok and not agents:
        return True, ""
    if is_health:
        return True, ""
    tok = _bearer(headers)
    if not tok:
        return False, ""
    # Console 自己的 token 继续有效（存量部署已经配了 AGENT_MOSS_CONSOLE_TOKEN 的不用改）
    if path.startswith("/console/api"):
        console_tok = _env("AGENT_MOSS_CONSOLE_TOKEN")
        if console_tok and _const_eq(tok, console_tok):
            return True, "console"
    if global_tok and _const_eq(tok, global_tok):
        return True, "global"
    for agent, expected in agents.items():
        if _const_eq(tok, expected):
            return True, f"agent:{agent}"
    return False, ""


def bind_agent(principal: str, agent_id: str) -> tuple[bool, str]:
    """每 agent token 模式下，请求声明的 agent_id 必须与 token 对应。

    未启用每 agent token 时永远放行（主体 ``agent:<id>`` 由调用方自己声明，
    与历史行为一致）。
    """
    tokens = agent_tokens()
    if not tokens:
        return True, agent_id
    if not principal.startswith("agent:"):
        # 用的是全局 token：允许声明任意 agent（兼容老部署），但主体记全局
        return True, agent_id
    bound = principal[6:]
    if not agent_id:
        return True, bound
    return (bound == agent_id), bound


def principal_of(headers, path: str = "") -> str:
    ok, principal = check_request_auth(headers, path)
    return principal if ok else ""


def principal_hash(principal: str) -> str:
    """主体短哈希（用于状态分桶，不落明文 token）。"""
    if not principal:
        return ""
    return hashlib.sha256(principal.encode("utf-8")).hexdigest()[:12]


# ==================== 路径白名单 ====================

def _default_home() -> Path:
    try:
        home = Path.home()
    except Exception:  # noqa: BLE001
        return Path(tempfile.gettempdir())
    # root（systemd 模式）下 Path.home() = /root，但真实用户的数据/日志在
    # /home/<user>。0.17.0 引入 log_roots 白名单时漏了 systemd/root 部署：
    #   - llm_log_path 落在 /home/<user> 被判越界（xiaoO hkl.log 无 [LLM_PROMPT]）；
    #   - hardenExistingPaths 去 /root 下找根本不存在的文件、权限收紧从未生效。
    #
    # 分级判定（不能无条件用 _resolve_owner_home —— 它会猜）：
    #   1. SUDO_USER / LOGNAME / USER 明确 → 该用户（sudo 启动）；
    #   2. 只有一个普通用户 → 自动识别（单用户机器开箱即用）；
    #   3. 多个普通用户 → **不猜**，保持 /root（安全）。
    #      多用户共享同一 root 服务时，由安装脚本显式写 AGENT_MOSS_LOG_ROOTS
    #      （每条目的用户装一次，累积进白名单）。
    from .paths import (
        _is_root,
        _list_owner_homes,
        _resolve_explicit_owner_home,
    )
    if _is_root():
        explicit = _resolve_explicit_owner_home()
        if explicit is not None:
            return explicit
        owners = _list_owner_homes()
        if len(owners) == 1:
            return owners[0]
    return home


def log_roots() -> list[Path]:
    raw = _env("AGENT_MOSS_LOG_ROOTS")
    if raw:
        return [Path(x).expanduser() for x in _split(raw)]
    roots = [_default_home(), Path("/tmp"), Path(tempfile.gettempdir())]
    return list(dict.fromkeys(roots))


def review_roots() -> list[Path]:
    """``/api/v1/review`` 的 ``db_path`` 允许读取的根目录。

    默认放行 AgentGate 的标准位置 —— 标准部署不用改任何配置。
    """
    roots: list[Path] = [Path("~/.local/share/agent_gate").expanduser()]
    for env in ("AGENT_GATE_DB", "AGENT_GATE_JSON_PATH"):
        val = _env(env)
        if val:
            p = Path(val).expanduser()
            roots.append(p if p.is_dir() else p.parent)
    roots += [Path(x).expanduser() for x in _split(_env("AGENT_MOSS_REVIEW_PATHS"))]
    return list(dict.fromkeys(roots))


def path_within(path: str, roots: list[Path]) -> bool:
    """``path`` 是否落在任一白名单根目录内（解析符号链接后比较）。"""
    if not path:
        return True
    try:
        target = Path(path).expanduser().resolve()
    except OSError:
        return False
    for root in roots:
        try:
            root_r = root.resolve()
        except OSError:
            continue
        if target == root_r or root_r in target.parents:
            return True
    return False


# ==================== 私有文件 / 目录 ====================

def ensure_private_dir(path: Path) -> bool:
    """确保目录存在且为 0700；失败返回 False（调用方决定是否回退）。"""
    try:
        path.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            return False
        st = path.stat()
        if st.st_uid != os.getuid():
            return False
        os.chmod(path, stat.S_IRWXU)
        return True
    except OSError:
        return False


def open_private_append(path: Path):
    """以 0600 + ``O_NOFOLLOW`` 追加打开（拒绝符号链接）。"""
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(path), flags, 0o600)
    import io
    return io.TextIOWrapper(io.FileIO(fd, "a", closefd=True), encoding="utf-8")


def write_private_text(path: Path, text: str) -> None:
    """以 0600 + ``O_NOFOLLOW`` 覆盖写。"""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(path), flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


def harden_permissions(path: Path, mode: int) -> None:
    """尽力而为地把已存在路径改成更严的权限（失败忽略）。"""
    try:
        if path.exists() and not path.is_symlink():
            os.chmod(path, mode)
    except OSError:
        pass


def harden_existing_paths() -> None:
    """把**升级前就已存在**的数据文件权限收紧到 0600 / 目录 0700。

    新建文件在写入时就是私有权限（``write_private_text`` / ``ensure_private_dir``），
    但存量用户机器上那些 0644 的旧文件不会自己变 —— 而状态库里存的是各 agent 的
    动作历史，是整条产品线上最敏感的数据。启动时补一遍，失败只忽略（权限不是功能）。
    """
    try:
        from .paths import get_data_root
        roots = [get_data_root(), _default_home() / ".agentmoss"]
        file_names = (
            "agent_moss_runtime.json", "config.json", "agent_moss_settings.json",
            "agent_moss_token_stats.json", "stateful_chains.db",
            "stateful_chains.db-wal", "stateful_chains.db-shm",
        )
        for root in roots:
            harden_permissions(root, stat.S_IRWXU)
            for name in file_names:
                harden_permissions(root / name, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:  # noqa: BLE001 — 权限加固绝不能影响启动
        pass


# ==================== LLM 配置校验 ====================

#: 云厂商元数据地址 —— 任何情况下都不允许（正常 LLM 不会在这里）。
_BLOCKED_HOSTS = ("169.254.169.254", "metadata.google.internal", "metadata.tencentyun.com")


def per_request_llm_enabled() -> bool:
    """是否接受请求里的 ``metadata.llm_config``（**默认接受**）。

    多数部署的 LLM 地址是固定的，根本不需要调用方指定。设
    ``AGENT_MOSS_ALLOW_PER_REQUEST_LLM=0`` 后，请求里的 ``llm_config`` 会被**完全忽略**，
    统一用服务端配置 —— 这样 SSRF 这一类问题就从根上没有了（不是"过滤"，是"不接受"）。
    """
    return _env("AGENT_MOSS_ALLOW_PER_REQUEST_LLM", "1").lower() in TRUTHY


def validate_llm_base_url(url: str, allow_private: bool | None = None) -> tuple[bool, str]:
    """校验 ``metadata.llm_config.baseUrl``。

    默认**只校验协议 + 封禁云元数据地址**，不限制内网/回环（本地 Ollama 等需要）。
    配置 ``AGENT_MOSS_LLM_HOST_ALLOWLIST`` 后只允许列表内主机。
    """
    if not url:
        return True, ""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, f"baseUrl 协议不受支持: {parsed.scheme or '(空)'}"
    host = (parsed.hostname or "").lower()
    if not host:
        return False, "baseUrl 缺少主机名"
    if host in _BLOCKED_HOSTS:
        return False, f"baseUrl 指向云元数据地址，已拒绝: {host}"
    # 链路本地 169.254.0.0/16 一律拒绝（云元数据都在这个段，正常 LLM 不会用它），
    # 即使 AGENT_MOSS_TRUST_PRIVATE_LLM=1 也不放行。
    try:
        if ipaddress.ip_address(host).is_link_local:
            return False, f"baseUrl 指向链路本地地址，已拒绝: {host}"
    except ValueError:
        pass

    allowlist = _split(_env("AGENT_MOSS_LLM_HOST_ALLOWLIST"))
    if allowlist and host not in [h.lower() for h in allowlist]:
        return False, f"baseUrl 主机不在允许列表: {host}"

    if allow_private is None:
        allow_private = _env("AGENT_MOSS_TRUST_PRIVATE_LLM", "1").lower() in TRUTHY
    if not allow_private:
        try:
            addr = ipaddress.ip_address(host)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return False, f"baseUrl 指向内网地址，已拒绝: {host}"
        except ValueError:
            if host == "localhost":
                return False, "baseUrl 指向本机，已拒绝"
    return True, ""


# ==================== 组合链脱敏 ====================

def chain_detail_mode() -> str:
    return (_env("AGENT_MOSS_CHAIN_DETAIL", "redacted") or "redacted").lower()


def redact_graph(
    graph,
    current_instance_id: str = "",
    current_session_id: str = "",
) -> dict | None:
    """结构化攻击链图的脱敏：同实例不隐藏，跨实例/跨会话隐藏命令原文。

    判定优先级：
    1. 节点有 instance_id 且与当前请求的 instance_id 相同 → 原样返回
       （同一个人/同一个 agent 实例的多个会话，没必要对自己打码）。
    2. 节点没有 instance_id（旧数据）→ 回退到 session 比较，只有当前会话可见。
    3. 其他 → 隐藏 session_id / action_detail / resources。
    """
    if not graph:
        return None
    if chain_detail_mode() == "full":
        return graph
    nodes = []
    for n in graph.get("nodes", []) or []:
        m = dict(n)
        inst = str(m.get("instance_id", "") or "")
        sid = str(m.get("session_id", "") or "")
        same_instance = bool(inst and current_instance_id and inst == str(current_instance_id))
        same_session_fallback = bool(
            not inst and current_session_id and sid == str(current_session_id)
        )
        if not (same_instance or same_session_fallback):
            m["session_id"] = "<other-session>"
            m["action_detail"] = "<已隐藏>"
            m["resources"] = []
        nodes.append(m)
    out: dict = {"nodes": nodes, "edges": graph.get("edges", []) or []}
    # 性质元信息/表达式只含性质名与节点索引，不含命令原文，脱敏时必须保留
    # （否则前端无法展示"违反了哪条性质"与表达式对应关系）。
    for key in ("property_id", "property_short", "property_name", "property_expression"):
        if graph.get(key) is not None:
            out[key] = graph[key]
    return out


def redact_chain(
    chain,
    current_instance_id: str = "",
    current_session_id: str = "",
) -> list:
    """跨会话节点只保留结构，去掉命令原文与会话标识。

    节点形状为 ``[session_id, seq, action_detail, timestamp, agent_id, instance_id]``。
    同实例的节点原样返回（同一个人自己的多个会话）；旧数据没有 instance_id 时
    回退到 session 比较。其他节点隐藏命令原文与资源。
    """
    if not chain:
        return []
    if chain_detail_mode() == "full":
        return list(chain)
    out = []
    for step in chain:
        if isinstance(step, (list, tuple)) and len(step) >= 3:
            sid, seq, detail = step[0], step[1], step[2]
            ts = step[3] if len(step) > 3 else ""
            inst = str(step[5]) if len(step) > 5 else ""
            same_instance = bool(inst and current_instance_id and inst == str(current_instance_id))
            same_session_fallback = bool(
                not inst and current_session_id and str(sid) == str(current_session_id)
            )
            if same_instance or same_session_fallback:
                out.append(list(step))
            else:
                out.append(["<other-session>", seq, "<已隐藏>", ts])
        else:
            out.append(step)
    return out


# ==================== 跨会话批量访问信号 ====================

#: principal/IP → [(monotonic_ts, session_id)]。攻击者拿到 token 后，为了凑出
#: 被冒充 agent 的组合链反例路径，往往会在短时间内声明大量不同的 session_id ——
#: 正常 agent 始终用自己的那一个会话。阈值内去重计数即可识别。
_SESSION_WINDOW: dict[str, list[tuple[float, str]]] = {}
_SESSION_LOCK = __import__("threading").Lock()


def session_sweep_threshold() -> int:
    """窗口内允许的不同 session 数；<=0 关闭（默认 50）。"""
    return _env_int("AGENT_MOSS_SESSION_SWEEP_THRESHOLD", 50)


def session_sweep_window() -> int:
    return _env_int("AGENT_MOSS_SESSION_SWEEP_WINDOW_SEC", 300)


def session_sweep_action() -> str:
    """``log``（默认，只告警）或 ``deny``（直接 429）。"""
    return (_env("AGENT_MOSS_SESSION_SWEEP_ACTION", "log") or "log").lower()


def note_session_access(key: str, session_id: str) -> tuple[int, bool]:
    """记录一次会话访问，返回 ``(窗口内不同 session 数, 是否超过阈值)``。

    阈值 <=0 时不做任何统计，返回 ``(0, False)``（默认行为，零开销）。
    """
    limit = session_sweep_threshold()
    if limit <= 0 or not session_id:
        return 0, False
    import time as _time
    now = _time.monotonic()
    window = session_sweep_window()
    with _SESSION_LOCK:
        entries = _SESSION_WINDOW.get(key, [])
        cutoff = now - window
        entries = [(t, s) for (t, s) in entries if t >= cutoff]
        entries.append((now, session_id))
        # 防内存膨胀：单 key 最多留 4 倍阈值条
        if len(entries) > limit * 4:
            entries = entries[-limit * 4:]
        _SESSION_WINDOW[key] = entries
        if len(_SESSION_WINDOW) > 10000:
            _SESSION_WINDOW.clear()
            _SESSION_WINDOW[key] = entries
        distinct = len({s for (_t, s) in entries})
    return distinct, distinct > limit


def reset_auth_cache() -> None:
    """清空 token 解析缓存（测试隔离用：fd 号会被复用）。"""
    global _TOKEN_CACHE
    _TOKEN_CACHE = None
    _FD_TOKEN_CACHE.clear()


# ==================== 恶意排队识别 ====================

#: 主体 → 最近被"排队拒绝"的时间戳。被 503/超时拒绝得异常频繁的主体，
#: 大概率不是正常业务（正常业务偶尔碰到一次 503 不会每秒好几次）。
_QUEUE_REJECTS: dict[str, list[float]] = {}
_QUEUE_LOCK = __import__("threading").Lock()


def queue_abuse_threshold() -> int:
    """窗口内允许的排队拒绝次数；<=0 关闭（默认 10）。"""
    return _env_int("AGENT_MOSS_QUEUE_ABUSE_THRESHOLD", 10)


def queue_abuse_window() -> int:
    return _env_int("AGENT_MOSS_QUEUE_ABUSE_WINDOW_SEC", 60)


def queue_abuse_action() -> str:
    """``log``（默认，只告警）或 ``deny``（对疑似恶意排队主体直接 429）。"""
    return (_env("AGENT_MOSS_QUEUE_ABUSE_ACTION", "log") or "log").lower()


def note_queue_reject(key: str) -> tuple[int, bool]:
    """记录一次"因排队满/超时被拒"，返回 ``(窗口内拒绝次数, 是否疑似恶意排队)``。"""
    limit = queue_abuse_threshold()
    if limit <= 0 or not key:
        return 0, False
    import time as _time
    now = _time.monotonic()
    cutoff = now - queue_abuse_window()
    with _QUEUE_LOCK:
        entries = [t for t in _QUEUE_REJECTS.get(key, []) if t >= cutoff]
        entries.append(now)
        if len(entries) > limit * 4:
            entries = entries[-limit * 4:]
        _QUEUE_REJECTS[key] = entries
        if len(_QUEUE_REJECTS) > 10000:
            _QUEUE_REJECTS.clear()
            _QUEUE_REJECTS[key] = entries
        n = len(entries)
    return n, n > limit


def reset_queue_tracker() -> None:
    """测试隔离用。"""
    with _QUEUE_LOCK:
        _QUEUE_REJECTS.clear()


def reset_session_sweep() -> None:
    """测试隔离用。"""
    with _SESSION_LOCK:
        _SESSION_WINDOW.clear()


# ==================== 限额 ====================

def socket_mode() -> int:
    """Unix socket 文件权限（八进制字符串，默认 ``600``）。

    UDS 模式没有网络面，socket 文件的权限就是唯一的内核级访问控制：
    以前跟随进程 umask（常见 0777），同机任何用户都能连。收紧到 0600 后只有
    属主能连 —— 与 token 的 ``0600`` 同一档。
    需要同组多用户共用一个 socket 时设 ``AGENT_MOSS_SOCKET_MODE=660``。
    """
    raw = _env("AGENT_MOSS_SOCKET_MODE", "600")
    try:
        mode = int(raw, 8)
    except ValueError:
        logger.warning("AGENT_MOSS_SOCKET_MODE=%r 不是八进制，回退 600", raw)
        return 0o600
    if not 0 <= mode <= 0o777:
        logger.warning("AGENT_MOSS_SOCKET_MODE=%r 超出范围，回退 600", raw)
        return 0o600
    return mode


def error_detail_mode() -> str:
    """500 响应里的错误详情：``generic``（默认）/ ``full``（旧行为，返回 ``str(e)``）。

    ``str(e)`` 会把内部路径、配置值、解析片段带进响应体 —— 调用方（可能就是被
    检测的 Agent）拿到后可以据此规避。默认只回一个 ref，完整堆栈只进服务端日志。
    排查问题需要旧行为时设 ``AGENT_MOSS_ERROR_DETAIL=full``。
    """
    return (_env("AGENT_MOSS_ERROR_DETAIL", "generic") or "generic").lower()


def max_body_bytes() -> int:
    return _env_int("AGENT_MOSS_MAX_BODY_BYTES", 16 * 1024 * 1024)


def max_inflight() -> int:
    """同时进行分析的最大请求数。

    默认 16 的由来（2026-10 实测，8 核）：
    - 分析是 CPU 密集（GIL 限制），并发从 1 加到 32 吞吐**不涨**（32.7 → 23.7/s），
      只让 p50 从 29ms 涨到 1300ms；
    - 但生产默认开 L3，请求会花几秒等 LLM（I/O，释放 GIL）——那种负载下并发才提吞吐；
    - Python 默认线程池是 min(32, cpu+4)，16 与之匹配，不额外制造排队。
    设 0 = 不限（改造前的行为）。
    """
    return _env_int("AGENT_MOSS_MAX_INFLIGHT", 16)


#: 路径 → 并发池。池之间互不影响：Console 打满只占自己的 ops 池。
_POOL_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("biz", ("/api/v1/analyze",)),
    ("review", ("/api/v1/review",)),
    ("ops", ("/console", "/api/v1/brain")),
    ("health", ("/api/v1/health",)),
)

#: 池默认值。review 只给 1：全量回顾耗时长，必须串行，不能和 analyze 抢。
_POOL_DEFAULTS = {"biz": 16, "review": 1, "ops": 4, "health": 4, "other": 4}


def pool_of(path: str) -> str:
    """请求走哪个并发池。"""
    for name, prefixes in _POOL_RULES:
        for p in prefixes:
            if path == p or path.startswith(p + "/"):
                return name
    return "other"


def pool_limit(name: str) -> int:
    """某个池的并发上限。0 = 不限（仅调试用）。``biz`` 兼容旧 MAX_INFLIGHT。"""
    default = _POOL_DEFAULTS.get(name, 4)
    if name == "biz":
        default = _env_int("AGENT_MOSS_MAX_INFLIGHT", default)
    return _env_int(f"AGENT_MOSS_POOL_{name.upper()}", default)


def unauth_inflight() -> int:
    """**未认证请求**的全局并发上限。默认 4。

    未认证请求没有身份，只能靠一个很小的全局配额兜住：攻击者最多占 4 条，
    剩下的并发留给带 token 的正常业务。``AUTH_MODE=off`` 时不生效。
    """
    return _env_int("AGENT_MOSS_MAX_UNAUTH_INFLIGHT", 4)


def unauth_per_ip() -> int:
    """单个来源 IP 的未认证并发上限。默认 2（同机回环共享这一份额度）。"""
    return _env_int("AGENT_MOSS_MAX_UNAUTH_PER_IP", 2)


def agent_inflight() -> int:
    """**单个 agent** 的并发上限（已认证请求按 principal 分桶）。默认 8。"""
    return _env_int("AGENT_MOSS_MAX_AGENT_INFLIGHT", 8)


def chain_scope() -> str:
    """组合链时间线的作用域。

    - ``system``（默认）：**全系统共享一个桶**。组合攻击的目标是这台服务器，
      攻击者可能换用户、换 agent 分步实施（agent1 建监听、agent2 扫描、agent3 外传），
      按 agent 隔离会直接漏掉这类跨 agent 链。
    - ``agent``：每个 agent 独立分桶。仅用于"一个 AgentGate 服务多个互不相关租户"
      的部署，避免把不同租户的正常操作拼成攻击链。
    """
    return (_env("AGENT_MOSS_CHAIN_SCOPE", "system") or "system").lower()


def chain_bucket(agent_id: str = "") -> str:
    """时间线分桶 key。system 模式所有 agent 共用一个；agent 模式按 agent_id。"""
    if chain_scope() == "agent":
        return agent_id or "default"
    return "__system__"


def bound_agent_of(principal: str) -> str:
    """principal → 绑定的 agent 名；全局 token / 未知返回空串。"""
    return principal[len("agent:"):] if principal.startswith("agent:") else ""


def max_queue() -> int:
    """排队上限（仅 MAX_INFLIGHT>0 生效）。超了直接 503，不无限占内存。"""
    return _env_int("AGENT_MOSS_MAX_QUEUE", 256)


def queue_wait_sec() -> int:
    """单个请求最多排队多久；超过返回 503。

    安全网关卡在每次工具调用上，排太久比直接拒绝更糟 —— 默认 5 秒。
    """
    return _env_int("AGENT_MOSS_QUEUE_WAIT_SEC", 5)


def rate_limit_qps() -> int:
    """单主体每秒请求数上限。**默认 100（开启）**；0 = 不限（仅调试用）。

    与 AgentGate 同口径：限流防的是调用方把服务打满，默认值应在发布时定成安全的。
    """
    return _env_int("AGENT_MOSS_RATE_LIMIT_QPS", 100)


def max_connections() -> int:
    """服务器同时接受的连接数上限（默认 128）。

    补的是**连接层** DoS：只建立连接、慢慢发（slowloris），应用层的并发/排队管不到，
    因为它压根没形成一个完整请求。配合 ``keep_alive`` 一起用。
    """
    return _env_int("AGENT_MOSS_MAX_CONNECTIONS", 128)


def keep_alive_sec() -> int:
    """空闲连接保持时间（默认 5 秒，uvicorn 默认值）。"""
    return _env_int("AGENT_MOSS_KEEP_ALIVE_SEC", 5)


def describe() -> str:
    """启动时打印的一行安全配置摘要（不含任何 secret）。"""
    err = auth_config_error()
    if err:
        auth_desc = f"ERROR({err})"
    elif auth_mode() == AUTH_MODE_OFF:
        auth_desc = "off"
    elif auth_enabled():
        auth_desc = "on(" + (str(auto_token_path()) if not _read_explicit_token() else "explicit") + ")"
    else:
        auth_desc = "on(no-token!)"
    parts = [
        f"origin_check={'on' if origin_check_enabled() else 'off'}",
        f"auth={auth_desc}",
        f"agent_tokens={len(agent_tokens())}",
        f"chain_detail={chain_detail_mode()}",
        f"max_body={max_body_bytes() // (1024 * 1024)}MB",
        f"max_inflight={max_inflight() or 'unlimited'}",
        f"queue_wait={queue_wait_sec()}s",
        f"rate_limit={rate_limit_qps() or 'off'}qps",
    ]
    return " | ".join(parts)
