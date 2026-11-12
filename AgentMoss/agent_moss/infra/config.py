"""配置项管理 — 从配置文件加载配置"""

import json
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from .rules_mode import is_builtin_only, is_runtime_config_disabled

DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.json.example"


@dataclass
class LLMConfig:
    """LLM 调用配置（支持多种 Provider）"""

    api_key: str = ""
    model: str = "anthropic/claude-3.5-sonnet"
    temperature: float = 0.1
    max_tokens: int = 4096
    base_url: str = "https://openrouter.ai/api/v1"
    provider: str = ""


@dataclass
class TimeoutConfig:
    """超时配置"""

    total_timeout: float = 90.0
    prompt1_timeout: float = 40.0
    prompt2_timeout: float = 20.0
    step_interval: float = 0.0


@dataclass
class CacheConfig:
    """缓存配置"""

    enabled: bool = True
    max_size: int = 1000


@dataclass
class RetryConfig:
    """重试配置"""

    max_retries: int = 2
    retry_interval: float = 2.0


@dataclass
class SecurityConfig:
    """安全检测配置"""

    enabled: bool = True
    heuristic_enabled: bool = True
    logic_rules_enabled: bool = True
    llm_analysis_enabled: bool = True
    formal_observe_mode: bool = False  # L2.2 formal 引擎 observe 模式：只记录不拦截（灰度观察 FP 用）
    rules_path: str = ""
    skills_dir: str = ""


@dataclass
class OSProfileConfig:
    """OS Profile 配置（v2 新增）"""

    type: str = ""          # 留空自动检测，可手动指定 linux / windows
    dir: str = ""           # Profile 文件目录（预留，暂未使用）


@dataclass
class ServerConfig:
    """服务配置（v2 新增）"""

    mode: str = "http"             # "http" 或 "socket"
    http_host: str = "127.0.0.1"
    http_port: int = 9090
    socket_path: str = "/var/run/agent_moss/agent_moss.sock"
    workers: int = 4


@dataclass
class Config:
    """全局配置"""

    llm: LLMConfig = field(default_factory=LLMConfig)
    timeout: TimeoutConfig = field(default_factory=TimeoutConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    retry: RetryConfig = field(default_factory=RetryConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    os_profile: OSProfileConfig = field(default_factory=OSProfileConfig)  # v2 新增
    server: ServerConfig = field(default_factory=ServerConfig)              # v2 新增
    log_level: str = "INFO"


def load_config(config_path: str | Path | None = None) -> Config:
    """
    从配置文件加载配置。支持 JSON（.json）、YAML（.yaml / .yml）、TOML（.toml）格式。

    加载优先级：
    1. 指定的 config_path（给程序内部调用使用）
    2. 环境变量 AGENT_MOSS_CONFIG_PATH 指定的路径
    3. ~/.config/agentmoss/config.{json,yaml,toml}（AgentMoss 用户目录配置）
    4. 默认路径：agent_moss/infra/config.json（包内默认配置）

    注：服务端不再无条件继承 ~/.config/xiaoo/config.toml。xiaoo 调用场景下，
    LLM 配置由 bridge.py 读 xiaoo config + 解析 env，per-request 注入到请求
    metadata.llm_config（llm_analyzer 优先用它覆盖全局）。这样服务端保持通用——
    谁调用谁的 key，互不污染。

    Args:
        config_path: 配置文件路径，为 None 时按优先级自动查找

    Returns:
        Config: 加载后的配置对象
    """
    if config_path is not None:
        path = Path(config_path)
    elif os.getenv("AGENT_MOSS_CONFIG_PATH"):
        path = Path(os.getenv("AGENT_MOSS_CONFIG_PATH"))
    else:
        # 优先级 3: 数据根目录下的 config.{json,yaml,toml}（AgentMoss 用户目录配置）。
        # 数据根默认 ~/.config/agentmoss，可经 AGENT_MOSS_DATA_DIR 覆盖（如 root 服务
        # 写当前用户目录，见 infra/paths）。
        from .paths import get_config_dir
        agent_moss_user_dir = get_config_dir()
        path = None
        for suffix in (".json", ".yaml", ".yml", ".toml"):
            candidate = agent_moss_user_dir / f"config{suffix}"
            if candidate.exists():
                path = candidate
                break

        if path is None:
            # 不再无条件读 ~/.config/xiaoo/config.toml —— 那是 xiaoo 专属逻辑。
            # xiaoo 调用场景由 bridge.py 读 xiaoo config + 解析 env，per-request 注入
            # metadata.llm_config（llm_analyzer 优先用它）。服务端保持通用：谁调用谁的 key。
            # 服务自己的全局 LLM 配置来源：env > AGENT_MOSS_CONFIG_PATH/YAML > agent_moss_settings。
            # 优先级: 默认路径首次安装自动复制
            if DEFAULT_CONFIG_PATH.exists():
                path = agent_moss_user_dir / "config.json"
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(DEFAULT_CONFIG_PATH, path)
                # ⚠️ 走 stderr，不要 print 到 stdout —— CLI 的 stdout 是给脚本/管道
                # 解析的 JSON，首次运行混入这两行会让 `agent-moss analyze x.json | jq`
                # 直接失败（且只在"首次运行/换数据目录"时出现，很难复现）。
                import sys as _sys
                print(f"[AgentMoss] 已创建用户配置文件: {path}", file=_sys.stderr)
                print(
                    "[AgentMoss] 请编辑该文件配置 LLM API Key"
                    "（或设 AGENT_MOSS_LLM_API_KEY 环境变量）",
                    file=_sys.stderr,
                )

    # path 仍为 None = 无用户配置且包内模板缺失（config.json.example 未随包分发，
    # 如 wheel 安装场景）。此时回退默认配置，不可对 None 调 .exists()（历史 bug：
    # AttributeError: 'NoneType' object has no attribute 'exists'）。
    if path is None or not path.exists():
        return _build_config({})

    suffix = path.suffix.lower()
    if suffix in (".yaml", ".yml"):
        data = _load_yaml(path)
    else:
        data = _load_json(path)
    return _build_config(data)


def _load_json(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_yaml(path: Path) -> dict:
    try:
        import yaml
    except ImportError:
        raise ImportError(
            f"读取 YAML 配置文件需要安装 PyYAML: pip install pyyaml\n"
            f"或使用 JSON 格式配置文件。"
        )
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _load_toml(path: Path) -> dict:
    """读取 TOML 配置文件（继承宿主 agent xiaoo 的 config.toml 时用）。

    Python 3.11+ 走 stdlib tomllib；3.10- 走 tomli（tenacity 已拉）。
    """
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            raise ImportError(
                f"读取 TOML 配置文件需要 Python 3.11+ 或 pip install tomli\n"
                f"或使用 JSON/YAML 格式配置文件。"
            )
    with open(path, "rb") as f:
        return tomllib.load(f)


def _build_config(data: dict) -> Config:
    llm_data = data.get("llm", {})
    llm_config = LLMConfig(
        api_key=llm_data.get("api_key", ""),
        model=llm_data.get("model", "anthropic/claude-3.5-sonnet"),
        temperature=llm_data.get("temperature", 0.1),
        max_tokens=llm_data.get("max_tokens", 4096),
        base_url=llm_data.get("base_url", "https://openrouter.ai/api/v1"),
        provider=llm_data.get("provider", ""),
    )

    api_key_env = llm_data.get("api_key_env", "")
    if api_key_env:
        env_api_key = os.getenv(api_key_env)
        if env_api_key:
            llm_config.api_key = env_api_key

    for fallback_env in ("AGENT_MOSS_LLM_API_KEY", "OPENROUTER_API_KEY", "OPENAI_API_KEY"):
        env_api_key = os.getenv(fallback_env)
        if env_api_key:
            llm_config.api_key = env_api_key
            break

    # 环境变量覆盖 model 和 base_url（方便容器化/CI 环境）
    if env_model := os.getenv("AGENT_MOSS_LLM_MODEL"):
        llm_config.model = env_model
    if env_base_url := os.getenv("AGENT_MOSS_LLM_BASE_URL"):
        llm_config.base_url = env_base_url

    timeout_data = data.get("timeout", {})
    timeout_config = TimeoutConfig(
        total_timeout=timeout_data.get("total_timeout", 90.0),
        prompt1_timeout=timeout_data.get("prompt1_timeout", 40.0),
        prompt2_timeout=timeout_data.get("prompt2_timeout", 20.0),
        step_interval=timeout_data.get("step_interval", 0.0),
    )

    cache_data = data.get("cache", {})
    cache_config = CacheConfig(
        enabled=cache_data.get("enabled", True),
        max_size=cache_data.get("max_size", 1000),
    )
    # 环境变量覆盖：AGENT_MOSS_DISABLE_CACHE=1 关闭判定结果缓存 —— 不再写
    # {临时目录}/agent_moss_policy_cache/。只做命令判定、不做沙箱隔离的部署不需要
    # 这份缓存产物（与 AGENT_MOSS_SAVE_POLICY=0 同一动机：别在 /tmp 堆无用文件）。
    # 语义对齐 AGENT_MOSS_DISABLE_HEURISTIC / DISABLE_LOGIC_RULES 的 "=1 关闭"；
    # 等价于 config.json 的 "cache": {"enabled": false}（env 优先，无需手编配置）。
    if os.getenv("AGENT_MOSS_DISABLE_CACHE") == "1":
        cache_config.enabled = False

    retry_data = data.get("retry", {})
    retry_config = RetryConfig(
        max_retries=retry_data.get("max_retries", 2),
        retry_interval=retry_data.get("retry_interval", 2.0),
    )

    sec_data = data.get("security", {})
    # console 层级全局开关（runtime_config.layers）覆盖 security 三开关：
    # L1_heuristic → heuristic_enabled / L2_logic_rules → logic_rules_enabled /
    # L3_llm_analysis → llm_analysis_enabled。这样 console toggle 真正控到引擎
    # （否则各层开关只是 UI 状态，引擎照常全跑）。默认与 config.json 一致。
    _builtin_only = is_builtin_only()
    _runtime_disabled = is_runtime_config_disabled()
    _layers = {}
    if not _runtime_disabled:
        try:
            from .runtime_config import has_runtime_config, load_runtime_config
            if has_runtime_config():
                _layers = (load_runtime_config() or {}).get("layers", {}) or {}
        except Exception:
            _layers = {}  # runtime_config 不可用（如 seed 阶段）则保持 config.json 值
    # cold / builtin 模式下规则开关只认环境变量：忽略 runtime JSON / 配置文件里的
    # 层级开关，默认全开；下面的 AGENT_MOSS_DISABLE_* 环境变量覆盖仍然生效。
    security_config = SecurityConfig(
        # cold / builtin：忽略配置文件里的全局安全开关（规则开关只认环境变量）。
        enabled=True if _runtime_disabled else sec_data.get("enabled", True),
        heuristic_enabled=(
            True if _runtime_disabled
            else _layers.get("L1_heuristic", sec_data.get("heuristic_enabled", True))
        ),
        logic_rules_enabled=(
            True if _runtime_disabled
            else _layers.get("L2_logic_rules", sec_data.get("logic_rules_enabled", True))
        ),
        llm_analysis_enabled=(
            True if _runtime_disabled
            else _layers.get("L3_llm_analysis", sec_data.get("llm_analysis_enabled", True))
        ),
        formal_observe_mode=sec_data.get("formal_observe_mode", False),
        # builtin：忽略配置里的自定义规则文件/skill 目录（只用包内资源）；
        # cold：允许这两项作为“启动时输入”，由引擎在首次加载后冻结。
        rules_path="" if _builtin_only else sec_data.get("rules_path", ""),
        skills_dir="" if _builtin_only else sec_data.get("skills_dir", ""),
    )

    # 环境变量覆盖 security 和 LLM 配置
    if os.getenv("AGENT_MOSS_DISABLE_HEURISTIC") == "1":
        security_config.heuristic_enabled = False
    if os.getenv("AGENT_MOSS_DISABLE_LOGIC_RULES") == "1":
        security_config.logic_rules_enabled = False
    if os.getenv("AGENT_MOSS_FORMAL_OBSERVE") == "1":
        security_config.formal_observe_mode = True
    if env_temp := os.getenv("AGENT_MOSS_LLM_TEMPERATURE"):
        try:
            llm_config.temperature = float(env_temp)
        except ValueError:
            pass
    if env_max_tokens := os.getenv("AGENT_MOSS_LLM_MAX_TOKENS"):
        try:
            llm_config.max_tokens = int(env_max_tokens)
        except ValueError:
            pass
    if env_retries := os.getenv("AGENT_MOSS_LLM_RETRIES"):
        try:
            retry_config.max_retries = max(0, int(env_retries))
        except ValueError:
            pass

    # v2: OS Profile 配置
    os_profile_data = data.get("os_profile", {})
    os_profile_config = OSProfileConfig(
        type=os_profile_data.get("type", ""),
        dir=os_profile_data.get("dir", ""),
    )

    # v2: Server 配置
    server_data = data.get("server", {})
    server_config = ServerConfig(
        mode=server_data.get("mode", "http"),
        http_host=server_data.get("http_host", "127.0.0.1"),
        http_port=server_data.get("http_port", 9090),
        socket_path=server_data.get("socket_path", "/var/run/agent_moss/agent_moss.sock"),
        workers=server_data.get("workers", 4),
    )

    return Config(
        llm=llm_config,
        timeout=timeout_config,
        cache=cache_config,
        retry=retry_config,
        security=security_config,
        os_profile=os_profile_config,
        server=server_config,
        log_level=data.get("log_level", "INFO"),
    )


_default_config: Config | None = None


def invalidate_default_config_cache() -> None:
    """失效全局默认配置缓存。console toggle 层开关后调用，引擎下次请求重新加载。"""
    global _default_config
    _default_config = None


def get_default_config() -> Config:
    """获取全局默认配置（延迟加载）"""
    global _default_config
    if _default_config is None:
        _default_config = load_config()
    return _default_config


PROVIDER_BASE_URLS: dict[str, str] = {
    "openai": "https://api.openai.com/v1",
    "openrouter": "https://openrouter.ai/api/v1",
    "groq": "https://api.groq.com/openai/v1",
    "mistral": "https://api.mistral.ai/v1",
    "together": "https://api.together.xyz/v1",
    "xai": "https://api.x.ai/v1",
    "xai-grok": "https://api.x.ai/v1",
    "deepseek": "https://api.deepseek.com",
    "gitcode": "https://api-ai.gitcode.com/v1",
    "ollama": "http://localhost:11434",
    "zai-coding-plan": "https://api.z.ai/api/coding/paas/v4",
    "zhipu-coding-plan": "https://api.z.ai/api/coding/paas/v4",
    "zhipuai-coding-plan": "https://api.z.ai/api/coding/paas/v4",
}

PROVIDER_API_KEY_ENVS: dict[str, str] = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "claude": "ANTHROPIC_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "google": "GEMINI_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "groq": "GROQ_API_KEY",
    "mistral": "MISTRAL_API_KEY",
    "xai": "XAI_API_KEY",
    "xai-grok": "XAI_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "zai": "ZHIPU_API_KEY",
    "zai-global": "ZHIPU_API_KEY",
    "z.ai": "ZHIPU_API_KEY",
    "zai-cn": "ZHIPU_API_KEY",
    "zai-china": "ZHIPU_API_KEY",
    "bigmodel": "ZHIPU_API_KEY",
    "zhipu": "ZHIPU_API_KEY",
    "glm-cn": "ZHIPU_API_KEY",
    "zai-coding-plan": "ZHIPU_API_KEY",
    "zhipu-coding-plan": "ZHIPU_API_KEY",
    "zhipuai-coding-plan": "ZHIPU_API_KEY",
    "glm": "GLM_API_KEY",
    "glm-global": "GLM_API_KEY",
    "gitcode": "GITCODE_API_KEY",
}


DEFAULT_AGENT_MOSS_SETTINGS_PATH = Path(__file__).parent / "agent_moss_settings.json"


def load_agent_moss_settings(settings_path: str | Path | None = None) -> dict:
    """
    从 agent_moss_settings.json 加载 agent_moss 配置。

    Args:
        settings_path: 配置文件路径，为 None 时使用默认路径

    Returns:
        dict: agent_moss 配置字典

    Raises:
        FileNotFoundError: 配置文件不存在
        json.JSONDecodeError: 配置文件 JSON 格式错误
    """
    if settings_path is not None:
        path = Path(settings_path)
    else:
        path = DEFAULT_AGENT_MOSS_SETTINGS_PATH

    if not path.exists():
        return {}

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
        return {k: v for k, v in data.items() if not k.startswith("_")}


_agent_moss_settings: dict | None = None


def get_agent_moss_settings() -> dict:
    """获取全局 agent_moss 设置（延迟加载）"""
    global _agent_moss_settings
    if _agent_moss_settings is None:
        _agent_moss_settings = load_agent_moss_settings()
    return _agent_moss_settings


def get_agent_moss_setting(key: str, default: str | int | bool = "") -> str:
    """
    获取 agent_moss 配置值，优先级：环境变量 > agent_moss_settings.json > 默认值

    Args:
        key: 配置键名
        default: 默认值

    Returns:
        str: 配置值
    """
    env_value = os.environ.get(key)
    if env_value is not None:
        return env_value

    settings = get_agent_moss_settings()
    if key in settings:
        return str(settings[key])

    return str(default)


def is_llm_enabled() -> bool:
    """判断是否启用 LLM 深度分析。

    cold / builtin 模式下规则开关只认环境变量（忽略 settings JSON）。
    """
    if is_runtime_config_disabled():
        return os.getenv("AGENT_MOSS_DISABLE_LLM") != "1"
    disable_value = get_agent_moss_setting("AGENT_MOSS_DISABLE_LLM", "")
    return disable_value != "1"


def get_llm_fail_mode() -> str:
    """获取 LLM 分析失败时的处理策略。

    取值：
    - "fail_open"（默认）：纯靠 L3 时 LLM 挂了 → Allow + 警告日志
      （可用性优先；前两层已拦截时仍 Deny）
    - "fail_closed"：LLM 挂了 → Deny（安全优先）

    优先级：环境变量 AGENT_MOSS_LLM_FAIL_MODE > agent_moss_settings.json >
    默认 fail_open。
    """
    val = get_agent_moss_setting("AGENT_MOSS_LLM_FAIL_MODE", "fail_open")
    return "fail_closed" if val.lower() == "fail_closed" else "fail_open"


def get_llm_timeout() -> int:
    """获取 LLM 超时时间（秒）"""
    timeout = get_agent_moss_setting("AGENT_MOSS_LLM_TIMEOUT", 300)
    try:
        return int(timeout)
    except ValueError:
        return 300


def _get_int_setting(key: str, default: int) -> int:
    """读整型配置；非法值/未设置 → 默认值。"""
    raw = get_agent_moss_setting(key, default)
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def get_llm_history_max_items() -> int:
    """L3 prompt 最多注入多少条历史动作（0 = 不限，默认 20）。

    客户的写文件类 tool call，`action_detail` 可能包含整个文件内容，历史
    累积几十条后 prompt 会膨胀到几十万字符。只保留最近 N 条既够判断意图
    偏离，又能把 prompt 控制在可用范围。
    """
    return _get_int_setting("AGENT_MOSS_LLM_HISTORY_MAX_ITEMS", 20)


def get_llm_action_detail_max_chars() -> int:
    """L3 prompt 中单条历史动作详情最多保留多少字符（0 = 不截断，默认 500）。

    截断保留头部（命令本身）+ 尾部（结构），中间标注省略长度。
    """
    return _get_int_setting("AGENT_MOSS_LLM_ACTION_DETAIL_MAX_CHARS", 500)


def get_llm_max_prompt_tokens() -> int:
    """L3 输入 prompt 的 token 总预算（0 = 不限，默认 0）。

    超限时按「历史条数减半 → 单条截断长度减半 → 截断当前动作详情」逐级压缩，
    保证 prompt 不会因为超长 tool call 无限膨胀。
    """
    return _get_int_setting("AGENT_MOSS_LLM_MAX_PROMPT_TOKENS", 0)


def get_log_path() -> str:
    """获取 LLM prompt 日志路径"""
    return get_agent_moss_setting("AGENT_MOSS_LOG_PATH", "")


def is_policy_gen_enabled() -> bool:
    """判断是否启用策略生成"""
    enable_value = get_agent_moss_setting("AGENT_MOSS_ENABLE_POLICY_GEN", "")
    return enable_value == "1"


def is_brain_enabled() -> bool:
    """判断是否启用 Brain 自学习机制。

    默认关闭（开发中，避免污染 L1/L2 判定和 L3 prompt），仅当显式设置
    AGENT_MOSS_BRAIN_ENABLED=1（env 或 agent_moss_settings.json）时启用。

    cold / builtin 模式下**强制关闭**：Brain 自学习规则来自用户数据目录，属于
    用户级运行期规则来源，不属于冷启动/内置输入。
    """
    if is_runtime_config_disabled():
        return False
    enable_value = get_agent_moss_setting("AGENT_MOSS_BRAIN_ENABLED", "")
    return enable_value == "1"


def is_heuristic_enabled() -> bool:
    """判断是否启用层1特征匹配静态检测（cold / builtin 下只认环境变量）"""
    if is_runtime_config_disabled():
        return os.getenv("AGENT_MOSS_DISABLE_HEURISTIC") != "1"
    return get_agent_moss_setting("AGENT_MOSS_DISABLE_HEURISTIC", "") != "1"


def is_logic_rules_enabled() -> bool:
    """判断是否启用层2逻辑规则检测（cold / builtin 下只认环境变量）"""
    if is_runtime_config_disabled():
        return os.getenv("AGENT_MOSS_DISABLE_LOGIC_RULES") != "1"
    return get_agent_moss_setting("AGENT_MOSS_DISABLE_LOGIC_RULES", "") != "1"


def get_llm_retries() -> int:
    """获取 LLM 调用重试次数（默认 2 次重试 = 3 次尝试）"""
    val = get_agent_moss_setting("AGENT_MOSS_LLM_RETRIES", 2)
    try:
        return max(0, int(val))
    except ValueError:
        return 2


def get_llm_temperature() -> float:
    """获取 LLM 采样温度"""
    val = get_agent_moss_setting("AGENT_MOSS_LLM_TEMPERATURE", 0.1)
    try:
        return float(val)
    except ValueError:
        return 0.1


def get_llm_max_tokens() -> int:
    """获取 LLM 最大输出 token 数"""
    val = get_agent_moss_setting("AGENT_MOSS_LLM_MAX_TOKENS", 4096)
    try:
        return max(1, int(val))
    except ValueError:
        return 4096


def load_custom_rules() -> list[dict]:
    """
    从 AGENT_MOSS_CUSTOM_RULES 环境变量加载自定义规则。

    格式（与 TS 版一致）:
    [{"pattern": "kubectl delete namespace", "action": "Deny", "severity": "critical"}]
    """
    import json as _json

    # 仅内置规则模式：AGENT_MOSS_CUSTOM_RULES 属于用户注入规则，一并忽略。
    if is_builtin_only():
        return []
    raw = get_agent_moss_setting("AGENT_MOSS_CUSTOM_RULES", "")
    if not raw:
        return []
    try:
        parsed = _json.loads(raw)
        if not isinstance(parsed, list):
            return []
        return [r for r in parsed if isinstance(r, dict) and r.get("pattern") and r.get("action")]
    except (ValueError, TypeError):
        return []
