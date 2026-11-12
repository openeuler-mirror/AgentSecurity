"""主入口函数 — 串联 Step 1-2 的完整 AgentMoss 安全分析流程

Step 1: AgentMoss Security Agent 安全判断（三层防御）
  ├── 1.1 特征匹配静态检测（关键命令 + 注入检测 + 用户敏感规则）
  ├── 1.2 逻辑规则检测（read_before_write + 意图一致性 + 敏感路径 + 危险模式）
  └── 1.3 LLM + Skill 深度分析
  → 如果 Deny → 直接返回 Deny + 原因（结束）

Step 2: Allow → 查缓存 / 生成 policy
  ├── 缓存命中 → 使用缓存 policy
  └── 缓存未命中 → LLM 生成 policy + 写入缓存
  → 返回 Allow + policy
"""

import logging
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..profiles.base import OSProfile

from ..infra.config import Config, get_agent_moss_setting, get_default_config, is_policy_gen_enabled
from ..infra.llm_client import call_llm
from ..infra.parsers import parse_policy_from_llm
from ..infra.policy_cache import PolicyCache, get_default_cache
from ..infra.prompt_templates import get_prompt1
from ..infra.logging import MossLogger
from ..profiles import get_profile
from .coordinator import judge_security

# Policy 临时文件输出目录
POLICY_OUTPUT_DIR = Path(tempfile.gettempdir()) / "agent_moss"

# 白名单只读工具的默认最小权限 Policy
DEFAULT_READONLY_POLICY = """landlock_optional = false
mount_isolation_fallback = false

[path_groups]
system_binaries = true
system_libraries = true
temp_directories = true
device_files = false
proc_filesystem = false
network_config = false
wsl_paths = false

[namespaces]
mount = true
pid = false
network = true
user = false

[resources]
timeout_secs = 30
max_memory_bytes = 268435456

[environment]
whitelist = ["PATH", "LANG", "HOME", "USER", "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"]
"""


def analyze(
    session_id: str,
    prompt_session: str,
    action_history: list[dict[str, object]],
    a_next: dict[str, str],
    reason: str,
    config: Config | None = None,
    cache: PolicyCache | None = None,
    profile: "OSProfile | None" = None,
    llm_config: dict | None = None,
    cwd: str = "",
    agent_id: str = "",
    scenario_id: str = "",
    llm_log_path: str | None = None,
    prompt_history: list[dict[str, object]] | None = None,
    session_history: list[dict[str, object]] | None = None,
    instance_id: str = "",
) -> dict[str, str]:
    """
    分析 agent 的下一步动作是否在安全范围内，并在允许时生成最小 policy。

    Args:
        session_id: 会话唯一标识
        prompt_session: 用户输入的原始 prompt
        action_history: 历史动作序列
        a_next: 下一步动作，含 action_type 和 action_detail
        reason: 执行该动作的理由
        config: 配置项，为 None 时使用默认配置
        cache: Policy 缓存实例，为 None 时使用默认缓存
        profile: OS Profile（可选，默认自动检测）
        llm_config: 每请求 LLM 配置（可选）
        cwd: 当前工作目录（用于间接文件访问检测）
        agent_id: 调用方 agent 标识（如 "xiaoo"），用于加载该 agent 专属规则
        scenario_id: 调用方场景标识（如 "bank"），用于加载场景定制规则
            （客户沙箱的目录访问边界/禁 ssh 等）。空时兜底环境变量
            AGENT_MOSS_SCENARIO（部署级，客户沙箱设一次，所有请求生效）。
        llm_log_path: 每请求 LLM prompt 日志路径（可选，来自调用方 env，per-request 注入）
        prompt_history: 完整的交错历史 prompt（可选），供 L2/L3 使用。
        session_history: 多 session 历史动作（可选），每项 {"session_id",
            "action_history": [...]}。供 L2.2 形式化引擎跨会话验证。

    Returns:
        dict: {"decision": "Allow"|"Deny", "policy": "...", "reason": "...", ...}
    """
    cfg = config or get_default_config()
    os_profile = profile or get_profile()
    moss_log = MossLogger(session_id)
    max_retries = cfg.retry.max_retries
    retry_interval = cfg.retry.retry_interval

    moss_log.log_input(prompt_session, action_history, a_next, reason)

    try:
        # ==================== Step 1: AgentMoss Security Agent 安全判断 ====================
        moss_log.start_step("step1_security_judge")
        judgment = judge_security(
            prompt_session=prompt_session,
            action_history=action_history,
            a_next=a_next,
            reason=reason,
            config=cfg,
            profile=os_profile,
            llm_config=llm_config,
            cwd=cwd,
            agent_id=agent_id,
            scenario_id=scenario_id,
            llm_log_path=llm_log_path,
            prompt_history=prompt_history,
            session_history=session_history,
            instance_id=instance_id,
        )

        if not judgment.allowed:
            layers_str = ", ".join(judgment.violated_layers) if judgment.violated_layers else judgment.source
            moss_log.end_step(
                "step1_security_judge",
                detail=f"allowed=False, risk_level={judgment.risk_level}, violated_layers=[{layers_str}]",
            )
            result = {
                "decision": "Deny",
                "policy": "",
                "reason": judgment.reason,
                "violated_policy": f"[{judgment.risk_type}] {judgment.reason}",
                "violated_layers": judgment.violated_layers,
                "risk_level": judgment.risk_level,
                "risk_type": judgment.risk_type,
                "confidence": judgment.confidence,
                # 组合式拦截的结构化攻击链（前端可视化）；普通单步拦截为空
                "violation_graph": judgment.violation_graph,
                "violation_chain": judgment.violation_chain,
            }
            moss_log.log_result("Deny", result["reason"])
            return result

        moss_log.end_step(
            "step1_security_judge",
            detail=f"allowed=True, risk_level={judgment.risk_level}, source={judgment.source}",
        )

        # ==================== Step 2: Allow → 查缓存 / 生成 policy ====================
        policy_cache = cache or get_default_cache()
        enable_policy_gen = is_policy_gen_enabled()

        moss_log.start_step("step2_cache_lookup")
        cached_policy = policy_cache.get(session_id, prompt_session)

        if cached_policy is not None:
            moss_log.end_step("step2_cache_lookup", detail="缓存命中")
            policy_a_next = cached_policy
            _ = _save_policy_to_file(session_id, policy_a_next)
        elif not enable_policy_gen:
            moss_log.end_step("step2_cache_lookup", detail="缓存未命中，Policy 生成已禁用")
            moss_log.start_step("step2_default_policy")
            policy_a_next = DEFAULT_READONLY_POLICY
            policy_cache.put(session_id, prompt_session, policy_a_next)
            _ = _save_policy_to_file(session_id, policy_a_next)
            moss_log.end_step("step2_default_policy", detail="使用默认最小权限 Policy")
            result = {
                "decision": "Allow",
                "policy": policy_a_next,
                "reason": judgment.reason,
                "violated_policy": "",
                "violated_layers": judgment.violated_layers,
                "risk_level": judgment.risk_level,
                "risk_type": judgment.risk_type,
                "confidence": judgment.confidence,
            }
            moss_log.log_result("Allow", result["reason"], policy_a_next)
            return result
        else:
            moss_log.end_step("step2_cache_lookup", detail="缓存未命中，启用 LLM 生成")

            if judgment.source == "whitelist_bypass":
                moss_log.start_step("step2_whitelist_policy")
                policy_a_next = DEFAULT_READONLY_POLICY
                policy_cache.put(session_id, prompt_session, policy_a_next)
                _ = _save_policy_to_file(session_id, policy_a_next)
                moss_log.end_step("step2_whitelist_policy", detail="白名单工具使用预定义最小权限 Policy")
                result = {
                    "decision": "Allow",
                    "policy": policy_a_next,
                    "reason": judgment.reason,
                    "violated_policy": "",
                    "violated_layers": judgment.violated_layers,
                    "risk_level": judgment.risk_level,
                    "risk_type": judgment.risk_type,
                    "confidence": judgment.confidence,
                }
                moss_log.log_result("Allow", result["reason"], policy_a_next)
                return result

            if cfg.timeout.step_interval > 0:
                time.sleep(cfg.timeout.step_interval)

            moss_log.start_step("step2_generate_policy")
            prompt1_text = get_prompt1(prompt_session)
            step2_error: Exception | None = None
            policy_a_next = None

            for attempt in range(1, max_retries + 1):
                try:
                    llm_result = call_llm(
                        prompt=prompt1_text,
                        timeout=cfg.timeout.prompt1_timeout,
                        config=cfg.llm,
                    )
                    # 记录 token 用量（step="step2_policy_gen"）
                    try:
                        from ..infra.token_stats import record_token_usage
                        record_token_usage(
                            session_id=session_id,
                            step="step2_policy_gen",
                            model=llm_result.model,
                            prompt_tokens=llm_result.prompt_tokens,
                            completion_tokens=llm_result.completion_tokens,
                            total_tokens=llm_result.total_tokens,
                        )
                    except Exception:
                        pass  # token 统计失败不影响主流程
                    policy_a_next = parse_policy_from_llm(llm_result.content)
                    moss_log.log_llm_interaction(
                        "step2_generate_policy",
                        prompt1_text[:200],
                        llm_result.content[:200],
                    )
                    policy_cache.put(session_id, prompt_session, policy_a_next)
                    _ = _save_policy_to_file(session_id, policy_a_next)
                    moss_log.end_step("step2_generate_policy", detail="Policy 生成并缓存成功")
                    step2_error = None
                    break
                except (TimeoutError, ValueError, Exception) as e:
                    step2_error = e
                    if attempt < max_retries:
                        moss_log.log_error("step2_generate_policy", e)
                        moss_log.start_step(f"step2_retry_{attempt}")
                        time.sleep(retry_interval)
                        moss_log.end_step(
                            f"step2_retry_{attempt}",
                            detail=f"第 {attempt} 次重试，等待 {retry_interval}s",
                        )
                    else:
                        moss_log.log_error("step2_generate_policy", e)

            if step2_error is not None or policy_a_next is None:
                if isinstance(step2_error, TimeoutError):
                    moss_log.end_step(
                        "step2_generate_policy",
                        detail=f"超时（已重试 {max_retries} 次）",
                    )
                    result = {
                        "decision": "Deny",
                        "policy": "",
                        "reason": f"安全检测通过，但策略生成超时（已重试 {max_retries} 次），出于安全考虑拒绝执行",
                        "violated_policy": "无法生成策略：LLM 调用超时",
                    }
                elif isinstance(step2_error, ValueError):
                    moss_log.end_step(
                        "step2_generate_policy",
                        detail=f"解析失败（已重试 {max_retries} 次）: {step2_error}",
                    )
                    result = {
                        "decision": "Deny",
                        "policy": "",
                        "reason": f"安全检测通过，但策略生成失败（已重试 {max_retries} 次）：{step2_error}",
                        "violated_policy": "生成的策略格式无效",
                    }
                else:
                    moss_log.end_step(
                        "step2_generate_policy",
                        detail=f"异常（已重试 {max_retries} 次）: {step2_error}",
                    )
                    result = {
                        "decision": "Deny",
                        "policy": "",
                        "reason": f"安全检测通过，但策略生成服务异常（已重试 {max_retries} 次）：{step2_error}",
                        "violated_policy": "无法生成策略：LLM 服务异常",
                    }
                moss_log.log_result("Deny", result["reason"])
                return result

        result = {
            "decision": "Allow",
            "policy": policy_a_next,
            "reason": judgment.reason,
            "violated_policy": "",
            "violated_layers": judgment.violated_layers,
            "risk_level": judgment.risk_level,
            "risk_type": judgment.risk_type,
            "confidence": judgment.confidence,
        }
        moss_log.log_result("Allow", result["reason"], policy_a_next)
        return result

    except Exception as e:
        moss_log.log_error("unknown", e)
        result = {
            "decision": "Deny",
            "policy": "",
            "reason": f"分析过程发生未预期异常：{e}",
            "violated_policy": "未知异常",
        }
        moss_log.log_result("Deny", result["reason"])
        return result


def _save_policy_to_file(session_id: str, policy_toml: str) -> Path | None:
    """把最小权限 Policy 落盘到 {临时目录}/agent_moss/{session_id}.toml。

    落盘是给**执行侧沙箱**（按会话读取该文件配置 Landlock/namespace 隔离）用的；
    若调用方只取 analyze() 返回的 decision/policy 字段、不做沙箱隔离，则这份文件
    纯属无谓 I/O（每次 Allow 都写，实测 ~0.6ms/次；session_id 唯一时还会按请求
    堆积）。此类调用方可设 ``AGENT_MOSS_SAVE_POLICY=0`` 关闭落盘——只影响文件，
    analyze() 返回值与判定结果不变。
    """
    if get_agent_moss_setting("AGENT_MOSS_SAVE_POLICY", "1") == "0":
        return None
    # ⚠️ 落盘失败**绝不能影响分析结果**：这份文件只是给执行侧沙箱用的旁路产物
    # （见上方说明），analyze() 的返回值与判定与它无关。
    # 历史 bug：这里不设防，于是 /tmp/agent_moss/ 下若恰好有**同名但不可写**的旧文件
    # （实测本机有 25 个 root 拥有的残留，历史上 root 跑过一次就会留下），
    # write_text 抛 PermissionError → 整步异常 → 外层 fail-closed → **一律 Deny
    # 「未知异常」**。表现是"同一个 session_id 在一台机器上永远 Deny、换台机器就好"，
    # 判定随 /tmp 内容变化，且失败方向是误报。
    try:
        # 安全（2026-10）：/tmp 下的固定目录可被他人预创建/换成符号链接。
        # 目录必须是我们的、非符号链接、0700；写入用 O_NOFOLLOW + 0600。
        from ..infra import security_policy as sp
        if not sp.ensure_private_dir(POLICY_OUTPUT_DIR):
            logging.getLogger("agent_moss").warning(
                "Policy 输出目录 %s 不安全（被其他用户拥有或为符号链接），跳过落盘"
                "（不影响判定与返回值）", POLICY_OUTPUT_DIR)
            return None
        safe_name = session_id.replace("/", "_").replace("\\", "_").replace("..", "__")
        filepath = POLICY_OUTPUT_DIR / f"{safe_name}.toml"
        sp.write_private_text(filepath, policy_toml)
        return filepath
    except OSError as e:
        logging.getLogger("agent_moss").warning(
            "策略文件落盘失败（不影响判定）: %s: %s", POLICY_OUTPUT_DIR, e,
        )
        return None
