"""LLM 调用客户端 — 基于 OpenAI SDK 调用多种大模型（支持不同 Provider 的 Headers）

注意：openai SDK 在函数内部延迟导入，而非模块顶层 import。
这样未安装 openai 的环境也能正常 import 本包并运行 L1/L2 静态分析
（对应 AGENT_MOSS_DISABLE_LLM=1 或未配置 LLM 的纯静态分析场景），
仅在实际发起 LLM 调用时才需要 openai。
"""


from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass

from .config import LLMConfig, get_default_config

logger = logging.getLogger(__name__)


@dataclass
class LLMResult:
    """LLM 调用结果 — 包含返回文本和 token 用量。

    token 用量用于 token_stats 统计（policy_console 展示趋势）。
    """
    content: str                # LLM 返回的文本内容
    prompt_tokens: int = 0      # 输入 prompt 的 token 数
    completion_tokens: int = 0  # LLM 生成的 token 数
    total_tokens: int = 0       # 总 token 数（prompt + completion）
    model: str = ""             # 实际使用的模型名称（可能被 Provider 路径修改）

    def to_usage_dict(self) -> dict:
        """转换为 token 用量字典（用于统计记录）"""
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "model": self.model,
        }


def _get_openai_client_class():
    """延迟导入 openai.OpenAI，未安装时给出明确错误。

    将 openai 作为运行时依赖而非导入时硬依赖，使 LLM 成为可选项。
    """
    try:
        from openai import OpenAI
    except ImportError as e:
        raise ImportError(
            "LLM 调用需要 openai SDK，但当前环境未安装。"
            "若不需要 LLM 分析，可设置 AGENT_MOSS_DISABLE_LLM=1 只运行静态分析。"
        ) from e
    return OpenAI


def _resolve_api_key(config: LLMConfig) -> str:
    """解析 API Key：优先用配置值，空值时从环境变量兜底"""
    if config.api_key:
        return config.api_key
    for env_var in ("AGENT_MOSS_LLM_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY"):
        val = os.getenv(env_var)
        if val:
            return val
    return ""

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

PROVIDER_HEADERS: dict[str, dict[str, str]] = {
    "openrouter": {
        "HTTP-Referer": "shturl.cc/LlVD5pyWViHjM",
        "X-OpenRouter-Title": "AgentMoss",
    },
    "xai": {
        "HTTP-Referer": "shturl.cc/LlVD5pyWViHjM",
    },
}


def detect_provider(base_url: str, provider_hint: str = "") -> str:
    """
    从 base_url 或 provider 提示推测 provider 类型。

    Args:
        base_url: API base URL
        provider_hint: 可选的 provider 名称提示（优先于 URL 推测）

    Returns:
        str: provider 标识符（如 openrouter, openai, deepseek 等）
    """
    if provider_hint:
        hint = provider_hint.lower()
        if hint in ("claude", "anthropic"):
            return "anthropic"
        if hint in ("google", "gemini"):
            return "gemini"
        if hint in ("zai-coding-plan", "zhipu-coding-plan", "zhipuai-coding-plan"):
            return "zai-coding-plan"
        if hint in ("zai", "z-ai", "z.ai", "zai-cn", "zai-china", "zhipu", "glm-cn", "bigmodel"):
            return "zhipu"
        if hint in ("xai", "xai-grok"):
            return "xai"
        if hint in ("minimax", "minimax-openai"):
            return "minimax"
        if hint in ("minimax-anthropic"):
            return "minimax-anthropic"
        if hint in ("other", "custom", "local"):
            return "openai-compatible"
        return hint

    url = base_url.lower()

    if "openrouter.ai" in url:
        return "openrouter"

    if "api.openai.com" in url:
        return "openai"

    if "anthropic.com" in url or "api.anthropic.com" in url:
        return "anthropic"

    if "generativelanguage.googleapis.com" in url or "gemini" in url:
        return "gemini"

    if "api.deepseek.com" in url:
        return "deepseek"

    if "api.groq.com" in url:
        return "groq"

    if "api.mistral.ai" in url:
        return "mistral"

    if "api.together.xyz" in url:
        return "together"

    if "api.x.ai" in url:
        return "xai"

    if "api.minimaxi.com" in url:
        return "minimax"

    if "api-ai.gitcode.com" in url:
        return "gitcode"

    if "api.z.ai" in url:
        return "zai-coding-plan"
    if "open.bigmodel.cn" in url or "bigmodel" in url:
        return "zhipu"

    if ":11434" in url:
        return "ollama"

    return "openai-compatible"

def get_provider_headers(provider: str) -> dict[str, str]:
    """
    获取 provider 特定的 headers。

    Args:
        provider: provider 标识符

    Returns:
        dict[str, str]: 需要注入的额外 headers（不含基础认证 Header）
    """
    return PROVIDER_HEADERS.get(provider, {})


def create_client(config: LLMConfig | None = None) -> OpenAI:
    """
    创建 LLM 客户端（根据 Provider 自动添加特殊 Headers）。

    Args:
        config: LLM 配置，为 None 时使用默认配置

    Returns:
        OpenAI: 客户端实例
    """
    if config is None:
        config = get_default_config().llm

    base_url = config.base_url or OPENROUTER_BASE_URL
    provider = detect_provider(base_url, config.provider)
    extra_headers = get_provider_headers(provider)
    api_key = _resolve_api_key(config)

    OpenAI = _get_openai_client_class()
    return OpenAI(
        api_key=api_key,
        base_url=base_url,
        timeout=30.0,
        default_headers=extra_headers if extra_headers else None,
    )


def _response_field_lengths(msg) -> dict[str, int]:
    """枚举 message 里所有**非空**字段的长度（诊断空返回的必备信息）。

    历史教训（2026-11 招行）：模型返回 ``completion_tokens=185`` 但
    ``content`` 为空，旧诊断只打了 ``content`` / ``reasoning_content`` 两个
    字段，看不到内容到底落在哪 —— 只能猜。这里把 message 的**所有字段**
    实际长度都列出来，包括网关通过 ``model_extra`` 塞进来的非标准字段
    （如 ``reasoning``）。

    返回 ``{}`` 表示解析失败或全部为空。
    """
    try:
        d = msg.model_dump() if hasattr(msg, "model_dump") else {}
        if not d:
            return {}
        out: dict[str, int] = {}
        for key, value in d.items():
            if value is None or value == "" or value == [] or value == {}:
                continue
            try:
                if isinstance(value, str):
                    out[key] = len(value)
                elif isinstance(value, (list, dict)):
                    out[key] = len(str(value))
                elif isinstance(value, bool):
                    continue  # role 之外的布尔字段没有诊断价值
                else:
                    out[key] = len(str(value))
            except Exception:  # noqa: BLE001
                out[key] = -1
        return out
    except Exception:  # noqa: BLE001
        return {}


def _describe_response(response) -> str:
    """空返回时的诊断摘要（不含 prompt 全文，避免日志爆炸）。

    输出模型名、finish_reason、**所有非空字段的长度**、token 用量 ——
    足以判断「模型没输出」还是「输出落在了哪个字段里」。
    """
    try:
        choice = response.choices[0]
        msg = choice.message
        lengths = _response_field_lengths(msg)
        if lengths:
            fields = ",".join(f"{k}_len={v}" for k, v in lengths.items())
        else:
            # 一个字段都没有：至少把字段名列出来，说明结构是通的
            d = msg.model_dump() if hasattr(msg, "model_dump") else {}
            fields = f"all_empty message_keys={','.join(d.keys())}"
        usage = getattr(response, "usage", None)
        return (
            f"model={getattr(response, 'model', '?')} "
            f"finish_reason={choice.finish_reason} "
            f"{fields} "
            f"tokens={getattr(usage, 'prompt_tokens', '?')}/"
            f"{getattr(usage, 'completion_tokens', '?')}"
        )
    except Exception as e:  # noqa: BLE001 —— 诊断信息本身绝不能影响主流程
        return f"<无法解析响应结构: {e}>"


#: LLM 客户端缓存：key = (base_url, api_key, headers, timeout) → OpenAI。
#:
#: 为什么缓存（2026-11，客户 TPS < 1）：原先每次 call_llm 都 `OpenAI(...)` 新建
#: 客户端 —— 每次都新建 httpx 连接池，**TCP + TLS 握手开销**在高并发下非常可观
#: （几十毫秒 × 每秒数百次）。复用后连接池保持存活，二次请求直接走已有连接。
_CLIENT_CACHE: dict[tuple, object] = {}
_CLIENT_LOCK = threading.Lock()


def _get_shared_client(base_url: str, api_key: str, extra_headers: dict, timeout: float):
    """按 (base_url, api_key, headers, timeout) 复用 OpenAI 客户端。

    注意：超时时间不同的调用（prompt1 40s / prompt2 20s）会各自缓存一份，
    避免用错超时。缓存无上限但 key 组合极少（通常 1-2 个）。
    """
    key = (
        base_url,
        api_key,
        tuple(sorted((extra_headers or {}).items())),
        float(timeout),
    )
    with _CLIENT_LOCK:
        client = _CLIENT_CACHE.get(key)
        if client is None:
            OpenAI = _get_openai_client_class()
            client = OpenAI(
                api_key=api_key,
                base_url=base_url,
                timeout=timeout,
                default_headers=extra_headers if extra_headers else None,
            )
            _CLIENT_CACHE[key] = client
        return client


def reset_client_cache_for_tests() -> None:
    """测试隔离：清空客户端缓存（避免测试间串配置）。"""
    with _CLIENT_LOCK:
        _CLIENT_CACHE.clear()


def _record_llm_metrics(result: str, elapsed: float) -> None:
    """记录一次 LLM 调用的结果与耗时（Prometheus 指标，失败静默）。"""
    try:
        from . import metrics as _m

        _m.LLM_CALLS_TOTAL.inc(result=result)
        _m.LLM_DURATION.observe(max(0.0, elapsed), result=result)
    except Exception:  # noqa: BLE001
        pass


def _dump_full_message(msg, limit: int = 8000) -> str:
    """把 message 的**完整原始结构**序列化成可读文本（空返回诊断用）。

    为什么默认就要打全（2026-11 招行）：之前只打 ``content`` / ``reasoning_content``
    两个字段的长度，客户日志里明明有 ``completion_tokens=185`` 却看不出内容去了哪
    —— 排查只能靠猜。空返回是**异常路径**、频率低，打全不会把日志撑爆，却能一次
    定位到具体字段。超过 ``limit`` 字符才截断（防止恶意/异常的超大响应）。
    """
    try:
        d = msg.model_dump() if hasattr(msg, "model_dump") else {}
        if not d:
            return "<empty>"
        text = json.dumps(d, ensure_ascii=False, default=str)
    except Exception as e:  # noqa: BLE001
        return f"<无法序列化: {e}>"
    if len(text) > limit:
        return text[:limit] + f"...[truncated {len(text)} chars]"
    return text


def _trace_empty_response(response) -> None:
    """空返回时把**完整原始响应**写进追踪日志（仅 ``full`` 级别）。

    主日志里已经有完整 message（``_dump_full_message``）；这里额外落一份结构化
    的、带 token 用量的记录，便于按事件名过滤。
    """
    try:
        from .trace_log import is_trace_enabled, LEVEL_FULL, trace_full

        if not is_trace_enabled(LEVEL_FULL):
            return
        choice = response.choices[0]
        msg = choice.message
        raw = msg.model_dump() if hasattr(msg, "model_dump") else {}
        usage = getattr(response, "usage", None)
        trace_full(
            "l3.empty_response",
            model=getattr(response, "model", "?"),
            finish_reason=choice.finish_reason,
            message=raw,
            prompt_tokens=getattr(usage, "prompt_tokens", 0),
            completion_tokens=getattr(usage, "completion_tokens", 0),
        )
    except Exception:  # noqa: BLE001
        pass


def call_llm(
    prompt: str,
    timeout: float = 5.0,
    config: LLMConfig | None = None,
) -> LLMResult:
    """
    调用大模型（根据 Provider 自动添加特殊 Headers）。

    Args:
        prompt: 完整的 prompt 文本
        timeout: 超时时间（秒）
        config: LLM 配置，为 None 时使用默认配置

    Returns:
        LLMResult: 包含返回文本和 token 用量的结果对象

    Raises:
        TimeoutError: 调用超时
        Exception: API 调用失败
    """
    if config is None:
        config = get_default_config().llm

    base_url = config.base_url or OPENROUTER_BASE_URL
    provider = detect_provider(base_url, config.provider)
    extra_headers = get_provider_headers(provider)
    api_key = _resolve_api_key(config)

    client = _get_shared_client(base_url, api_key, extra_headers, timeout)

    # 熔断（2026-11）：模型服务挂掉时，不让每个请求都等满超时把池占死。
    from .circuit_breaker import get_breaker

    _breaker = get_breaker()
    if not _breaker.allow():
        _record_llm_metrics("circuit_open", 0.0)
        raise ValueError(
            "LLM 调用已熔断（连续失败过多），冷却期内不再发起请求；"
            "检查模型服务可用性，或调 AGENT_MOSS_LLM_CIRCUIT_COOLDOWN"
        )

    _llm_t0 = time.monotonic()
    try:
        # 先试非流式（多数端点默认支持）。某些端点（如阿里 compatible-mode 的 glm-4.5）
        # 仅支持流式，会报 400 "only support stream mode"——此时回退流式聚合 chunks。
        try:
            response = client.chat.completions.create(
                model=config.model,
                messages=[
                    {"role": "user", "content": prompt},
                ],
                temperature=config.temperature,
                max_tokens=getattr(config, "max_tokens", 4096),
                # 私有化网关的额外参数（关思考等）原样透传；空则不传。
                extra_body=getattr(config, "extra_body", None) or None,
            )

            message = response.choices[0].message
            content = message.content
            finish_reason = response.choices[0].finish_reason

            if not content:
                detail = _describe_response(response)
                _trace_empty_response(response)
                # 默认就把**完整响应**打出来（不需要开任何开关）：空返回是异常
                # 路径，频率低、日志量可控，但这是定位「token 去哪了」的唯一直接
                # 证据。2026-11 招行就是只打两个字段，导致排查只能靠猜。
                full = _dump_full_message(message)
                if finish_reason == "length":
                    logger.error(
                        "LLM 推理耗尽 token（finish_reason=length）: %s | 完整响应: %s",
                        detail, full,
                    )
                    raise ValueError(
                        "LLM 推理耗尽 token（finish_reason=length），无实际输出"
                    )
                logger.error("LLM 返回内容为空: %s | 完整响应: %s", detail, full)
                raise ValueError("LLM 返回内容为空")

            cleaned = content.strip()
            if cleaned.startswith("\ufeff"):
                cleaned = cleaned[1:]

            # 提取 token 用量统计
            usage = response.usage
            prompt_tokens = usage.prompt_tokens if usage else 0
            completion_tokens = usage.completion_tokens if usage else 0
            total_tokens = usage.total_tokens if usage else 0
            model_used = response.model if response.model else config.model

            _record_llm_metrics("success", time.monotonic() - _llm_t0)
            _breaker.record_success()
            return LLMResult(
                content=cleaned,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                model=model_used,
            )
        except Exception as mid_exc:
            # 流式回退条件：端点报"only support stream mode"或"stream parameter"
            mid_msg = str(mid_exc).lower()
            if "stream mode" not in mid_msg and "stream parameter" not in mid_msg:
                raise  # 不是流式问题，向上抛

            # 流式聚合 chunks
            stream = client.chat.completions.create(
                model=config.model,
                messages=[
                    {"role": "user", "content": prompt},
                ],
                temperature=config.temperature,
                max_tokens=getattr(config, "max_tokens", 4096),
                stream=True,
                extra_body=getattr(config, "extra_body", None) or None,
            )
            chunks_content: list[str] = []
            finish_reason = None
            prompt_tokens = 0
            completion_tokens = 0
            total_tokens = 0
            model_used = config.model
            chunk_count = 0
            last_chunk_raw: str = "<无 chunk>"
            for chunk in stream:
                chunk_count += 1
                if chunk.choices and chunk.choices[0].delta:
                    delta_content = chunk.choices[0].delta.content
                    if delta_content:
                        chunks_content.append(delta_content)
                    if chunk.choices[0].finish_reason:
                        finish_reason = chunk.choices[0].finish_reason
                if chunk.model:
                    model_used = chunk.model
                if chunk.usage:
                    prompt_tokens = chunk.usage.prompt_tokens or 0
                    completion_tokens = chunk.usage.completion_tokens or 0
                    total_tokens = chunk.usage.total_tokens or 0
                # 保留最后一个 chunk 的完整结构：空返回时它就是唯一的证据
                # （能看出 delta 里到底有什么字段，以及 usage 的 token 数）
                try:
                    dump = chunk.model_dump() if hasattr(chunk, "model_dump") else None
                    if dump is not None:
                        last_chunk_raw = json.dumps(dump, ensure_ascii=False, default=str)
                        if len(last_chunk_raw) > 4000:
                            last_chunk_raw = last_chunk_raw[:4000] + "...[truncated]"
                except Exception:  # noqa: BLE001
                    pass

            content = "".join(chunks_content)
            if not content:
                detail = (
                    f"chunks={chunk_count} finish_reason={finish_reason} "
                    f"tokens={prompt_tokens}/{completion_tokens} "
                    f"| 最后 chunk: {last_chunk_raw}"
                )
                _record_llm_metrics("empty", time.monotonic() - _llm_t0)
                if finish_reason == "length":
                    logger.error(
                        "LLM 流式推理耗尽 token（finish_reason=length）: %s", detail
                    )
                    raise ValueError(
                        "LLM 推理耗尽 token（finish_reason=length），无实际输出"
                    )
                logger.error("LLM 流式返回内容为空: %s", detail)
                raise ValueError("LLM 返回内容为空（流式聚合后仍空）")

            cleaned = content.strip()
            if cleaned.startswith("\ufeff"):
                cleaned = cleaned[1:]

            _record_llm_metrics("success", time.monotonic() - _llm_t0)
            return LLMResult(
                content=cleaned,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                model=model_used,
            )

    except Exception as e:
        error_msg = str(e).lower()
        _breaker.record_failure()
        if "timeout" in error_msg or "timed out" in error_msg:
            _record_llm_metrics("timeout", time.monotonic() - _llm_t0)
            raise TimeoutError(f"LLM 调用超时（{timeout}s）: {e}") from e
        _record_llm_metrics("error", time.monotonic() - _llm_t0)
        raise