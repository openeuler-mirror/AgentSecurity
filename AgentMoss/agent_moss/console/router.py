"""Policy Console FastAPI 路由 — 挂载到主 app 的 /console 前缀下。

复用 infra.runtime_config + infra.token_stats。Bearer 认证
（AGENT_MOSS_CONSOLE_TOKEN 未设则本机免认证）。
"""

import os
from pathlib import Path

from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel

from ..infra.runtime_config import (
    load_runtime_config,
    save_runtime_config,
    update_layer_enabled,
    update_rule_enabled,
    update_rule_deny_mode,
    update_rule_skip_l3,
    update_category_enabled,
    add_custom_rule,
    delete_custom_rule,
    add_custom_skill,
    delete_custom_skill,
    update_skill_enabled,
    update_skill_category_enabled,
    get_agent_rules,
    update_agent_rule_enabled,
    add_agent_rule,
    delete_agent_rule,
    update_agent_category_enabled,
    get_scenario_rules,
    update_scenario_rule_enabled,
    add_scenario_rule,
    delete_scenario_rule,
    update_scenario_category_enabled,
    get_env_overrides,
    generate_source_defaults,
    get_runtime_config_path,
    RUNTIME_CONFIG_DIR,
)
from ..infra.rules_mode import (
    get_rules_mode, is_builtin_only, is_runtime_config_disabled,
)
from ..engine.skill_engine import default_skills_dir
from ..infra.token_stats import (
    get_token_stats,
    get_recent_records,
    get_recent_records_count,
    get_token_trend,
    reset_token_stats,
)

router = APIRouter(prefix="/console")


def _runtime_for_view() -> dict:
    """Console **读接口**的 runtime 数据源。

    - 正常模式：用户 runtime 配置（含 Console 自定义规则）。
    - cold / builtin 模式：随包内置规则的只读视图（``generate_source_defaults``），
      **绝不读用户 runtime 文件**。写接口已由 server 中间件统一 403。

    ⚠️ **正常模式下返回的是 ``load_runtime_config()`` 的进程内缓存对象本身**，
    调用方**一律只读**（``.get(...)`` / 取值）。要往里塞键（如附加视图、标记）必须先
    ``dict(...)`` 浅拷贝，否则会污染缓存并被后续写操作落盘 —— 2026-10 的
    ``/api/config`` 500 就是这么来的（详见 ``get_full_config`` 注释）。
    """
    if is_runtime_config_disabled():
        return generate_source_defaults()
    return load_runtime_config()


# ==================== Auth ====================

CONSOLE_TOKEN_ENV = "AGENT_MOSS_CONSOLE_TOKEN"


def _get_console_token() -> str:
    return os.getenv(CONSOLE_TOKEN_ENV, "")


def _verify_auth(request: Request) -> bool:
    """验证 Bearer token。未配置 token 时本机访问免认证（iframe 嵌入场景）。"""
    token = _get_console_token()
    if not token:
        return True
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        # 恒定时间比较：避免按字节比较带来的时序侧信道（2026-10 安全加固）
        import hmac as _hmac
        return _hmac.compare_digest(auth_header[7:].encode("utf-8"), token.encode("utf-8"))
    return False


async def auth_dependency(request: Request):
    if not _verify_auth(request):
        raise HTTPException(
            status_code=401, detail="Unauthorized: invalid or missing Bearer token"
        )


# ==================== Pydantic Models ====================


class LayerToggle(BaseModel):
    layer_key: str  # "L1_heuristic" | "L2_logic_rules" | "L3_llm_analysis"
    enabled: bool


class RuleToggle(BaseModel):
    layer: str  # "L1_rules" | "L2_rules"
    category: str
    rule_id: str
    enabled: bool


class CategoryToggle(BaseModel):
    layer: str
    category: str
    enabled: bool


class NewRule(BaseModel):
    layer: str
    category: str
    pattern: str | None = None
    risk_level: str | None = None
    risk_type: str | None = None
    reason: str | None = None
    keyword: str | None = None
    lang: str | None = None
    path: str | None = None
    desc: str | None = None
    credential: bool | None = None
    deny_mode: str | None = None


class DenyModeUpdate(BaseModel):
    layer: str
    category: str
    rule_id: str
    deny_mode: str


class SkipL3Update(BaseModel):
    layer: str
    category: str
    rule_id: str
    skip_l3_on_disabled: bool


class DeleteRule(BaseModel):
    layer: str
    category: str
    rule_id: str


class SkillToggle(BaseModel):
    skill_id: str
    enabled: bool


class SkillCategoryToggle(BaseModel):
    category: str
    enabled: bool


class NewSkill(BaseModel):
    skill_id: str
    category: str = "user_custom"
    keywords: list[str] = []
    content: str


class DeleteSkill(BaseModel):
    skill_id: str
    category: str


# ==================== agent 定制规则 ====================


class AgentRuleToggle(BaseModel):
    agent_id: str
    category: str
    value: str | None = None
    pattern: str | None = None
    keyword: str | None = None
    path: str | None = None
    enabled: bool


class NewAgentRule(BaseModel):
    agent_id: str
    category: str
    value: str | None = None
    pattern: str | None = None
    risk_level: str | None = None
    risk_type: str | None = None
    reason: str | None = None
    keyword: str | None = None
    lang: str | None = None
    path: str | None = None
    desc: str | None = None
    credential: bool | None = None
    deny_mode: str | None = None


class DeleteAgentRule(BaseModel):
    agent_id: str
    category: str
    value: str | None = None
    pattern: str | None = None
    keyword: str | None = None
    path: str | None = None


class AgentCategoryToggle(BaseModel):
    agent_id: str
    category: str
    enabled: bool


# ==================== 场景定制规则 ====================


class ScenarioRuleToggle(BaseModel):
    scenario_id: str
    category: str
    value: str | None = None
    pattern: str | None = None
    keyword: str | None = None
    path: str | None = None
    enabled: bool


class NewScenarioRule(BaseModel):
    scenario_id: str
    category: str
    value: str | None = None
    pattern: str | None = None
    risk_level: str | None = None
    risk_type: str | None = None
    reason: str | None = None
    keyword: str | None = None
    lang: str | None = None
    path: str | None = None
    desc: str | None = None
    credential: bool | None = None
    deny_mode: str | None = None


class DeleteScenarioRule(BaseModel):
    scenario_id: str
    category: str
    value: str | None = None
    pattern: str | None = None
    keyword: str | None = None
    path: str | None = None


class ScenarioCategoryToggle(BaseModel):
    scenario_id: str
    category: str
    enabled: bool


# ==================== SPA ====================

STATIC_DIR = Path(__file__).parent / "static"


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index():
    """返回 SPA index.html"""
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return HTMLResponse(
        "<h1>AgentMoss Policy Console</h1><p>Frontend not built yet. Use /console/api/* endpoints.</p>"
    )


# ==================== 层级管理 ====================


@router.get("/api/layers", dependencies=[Depends(auth_dependency)])
async def get_layers():
    """获取 L1/L2/L3 开关状态 + env 覆盖"""
    runtime = _runtime_for_view()
    return {
        "layers": runtime.get("layers", {}),
        "env_overrides": get_env_overrides(),
        "builtin_only": is_builtin_only(),
        "rules_mode": get_rules_mode(),
    }


@router.put("/api/layers", dependencies=[Depends(auth_dependency)])
async def set_layers(body: LayerToggle):
    valid_keys = {"L1_heuristic", "L2_logic_rules", "L3_llm_analysis"}
    if body.layer_key not in valid_keys:
        raise HTTPException(status_code=400, detail=f"Invalid layer_key: {body.layer_key}")
    env_overrides = get_env_overrides()
    if body.layer_key in env_overrides and env_overrides[body.layer_key]["overridden"]:
        raise HTTPException(
            status_code=409,
            detail=f"层级 {body.layer_key} 被环境变量 {env_overrides[body.layer_key]['env_var']}=1 强制覆盖，Web 设置无效",
        )
    runtime = update_layer_enabled(body.layer_key, body.enabled)
    return {"layers": runtime["layers"], "env_overrides": env_overrides}


# ==================== 规则管理 ====================


# 内置性质 → 客户可懂的一句话"检测能力"说明（人话，无学术黑话）
_PROP_HUMAN: dict[str, str] = {
    "cross-session-chain": "跨会话组合攻击链：多个会话的动作拼接起来能组成攻击链条时拦截",
    "sensitive-data-flow": "敏感数据外传：凭据/密钥等被共享文件带到外传动作时拦截",
    "low-integrity-reachability": "下载产物跨会话执行：网上下载/注入的文件经改名等中转后被当前动作执行时拦截",
    "no-exfil-after-privesc": "提权后外传：一旦历史出现过提权动作，任何数据外传都被拦截",
    "no-exfil-after-credential": "读凭据后外传：一旦读取过凭据文件，任何数据外传都被拦截",
    "mc-ltl-rules": "时序攻击模式检查：按下方 11 条 LTL 规则逐条核对历史动作序列",
    "low-integrity-command-exec": "低完整性命令执行：网上下载/外部注入的不可信内容被当成命令执行时拦截",
    "sensitive-data-aggregation": "敏感数据聚合外传：外传动作要发送的数据被 2 个以上不同来源接触过时拦截",
}

# LTL 规则 id → 人话描述（"检测什么攻击模式"）
LTL_HUMAN: dict[str, str] = {
    "mc-ltl-001": "先读取了凭据/密钥，之后出现网络外传",
    "mc-ltl-002": "先下载/获取了文件，之后执行了文件",
    "mc-ltl-003": "先禁用了安全防护，之后出现破坏性操作（执行/删除/提权）",
    "mc-ltl-004": "先出现提示词注入，之后出现敏感操作（外传/写文件/执行）",
    "mc-ltl-005": "先读取凭据，之后出现横向移动（ssh/scp 到远程）",
    "mc-ltl-006": "先接触敏感数据，之后清除日志",
    "mc-ltl-007": "先提权，之后安装持久化后门",
    "mc-ltl-008": "先下载文件，之后安装持久化后门",
    "mc-ltl-009": "先接触敏感数据 → 打包压缩 → 网络外传",
    "mc-ltl-010": "安装了持久化机制（crontab/systemd/.bashrc 等），需审批",
    "mc-ctl-001": "任何情况下不允许清除日志（安全底线）",
}

# 原子命题 → 人话解释（"这条命令的两个动作之间到底在检测什么特征"）
_AP_HUMAN: dict[str, str] = {
    "reads_credential": "读凭据（id_rsa / .aws/credentials / /etc/shadow 等）",
    "network_egress": "网络外传（curl 发送 / scp / rsync 到远程）",
    "execute_file": "执行文件/命令（bash / python / subprocess / eval 等）",
    "write_file": "写入文件（> 重定向 / tee / mv / cp 等）",
    "delete_file": "删除文件（rm / unlink / rmdir）",
    "disable_security": "禁用安全防护（iptables -F / setenforce 0 / 停防火墙）",
    "install_persistence": "安装持久化后门（crontab / systemd / 写 .bashrc）",
    "privilege_escalation": "提权（sudo / su / setuid / setcap）",
    "download_file": "下载文件（curl -o / wget / git clone / pip install）",
    "archive_data": "打包压缩（tar / gzip / zip / base64）",
    "prompt_injection": "提示词注入（忽略之前指令 / 伪造指令等）",
    "sensitive_data": "接触敏感数据（各种 token / 私钥 / .env / 密码）",
    "lateral_movement": "横向移动（ssh / scp 到远程主机）",
    "clear_logs": "清除日志（history -c / 清 /var/log）",
}


def _get_l2_2_view() -> dict:
    """L2.2 LTL 规则只读展示（mc_rules.json，双端共用）。

    只返回 ltl_rules（带 enabled + 人话描述）。刻意**不** import formal 引擎
    （ALL_PROPERTIES import 每次 ~1.5s，曾拖慢 /api/config 到 3s）——本层仅做
    规则展示，引擎逻辑不在此路径。只读：formal 引擎整体由 L2_logic_rules 层
    开关控制；用户自定义 LTL 规则走用户数据目录覆盖 <data_root>/rules/mc_rules.json。
    """
    from ..rules_loader import load_mc
    try:
        mc = load_mc() or {}
    except Exception:
        mc = {}
    rules = mc.get("rules", []) or []
    # category_enabled 必须**从 runtime 读**，不能恒 True：Console 关掉 LTL 大类后
    # 前端会重新拉 /api/config 并按此字段渲染卡片开关，恒 True 会把用户的关闭操作
    # 显示回「开启」（且与写端点返回的 _l2_2_runtime_to_view 自相矛盾）。
    # load_mc() 只合并单条 enabled，不读大类开关（对齐 TS getL22View 的读法）。
    try:
        _l2_2 = (_runtime_for_view() or {}).get("L2_2") or {}
        _cat_enabled = (((_l2_2.get("ltl_rules") or {}) or {}).get("category_enabled", True)) is not False
    except Exception:
        _cat_enabled = True
    return {
        "enabled_via": "L2_logic_rules",
        "description": "时序与数据流攻击检测（L2.2 模型检测）",
        "category_enabled": _cat_enabled,
        "ltl_rules": [
            {"id": r.get("id"), "type": r.get("type"),
             "formula": "<公式>" if isinstance(r.get("formula"), list) else r.get("formula"),
             "reason": r.get("reason", ""), "risk_level": r.get("risk_level"),
             "action": r.get("action"),
             "enabled": r.get("enabled", True),
             "human": LTL_HUMAN.get(r.get("id"), r.get("reason", ""))}
            for r in rules
        ],
    }


def _l2_2_runtime_to_view(runtime_l2_2: dict) -> dict:
    """把 runtime 的 L2_2（Category 结构 {ltl_rules:{category_*, rules}}）转成
    与 /api/config 一致的 view 结构（ltl_rules = list[dict]）。

    供 /api/rules/enabled 等"返回完整 runtimeConfig"的端点使用——否则前端
    toggle 后 state.config.L2_2 变成 Category dict，renderLtlCard 的 map 会崩。
    """
    cat = (runtime_l2_2 or {}).get("ltl_rules", {}) or {}
    rls = cat.get("rules", []) or []
    return {
        "enabled_via": "L2_logic_rules",
        "description": "时序与数据流攻击检测（L2.2 模型检测）",
        "category_enabled": cat.get("category_enabled", True),
        "ltl_rules": [
            {"id": r.get("id"), "type": "ltl",
             "formula": "<公式>",
             "reason": r.get("reason", ""), "risk_level": r.get("risk_level", "high"),
             "action": r.get("action", "block"),
             "enabled": r.get("enabled", True),
             "human": LTL_HUMAN.get(r.get("id"), r.get("reason", ""))}
            for r in rls
        ],
    }


@router.get("/api/rules", dependencies=[Depends(auth_dependency)])
async def get_rules(layer: str | None = None, category: str | None = None):
    runtime = _runtime_for_view()
    result: dict = {}
    for layer_key in ["L1_rules", "L2_rules"]:
        if layer and layer != layer_key:
            continue
        layer_data = runtime.get(layer_key, {})
        for cat_name, cat_data in layer_data.items():
            if category and category != cat_name:
                continue
            result.setdefault(layer_key, {})[cat_name] = cat_data
    # L2.2/形式化只读展示（不参与 L1/L2 的增删改编辑模型）
    if not category:
        result["L2_2"] = _get_l2_2_view()
    return result


def _with_l2_2_view(runtime: dict) -> dict:
    """把返回给前端的 runtimeConfig 的 L2_2 统一转成 view 结构（ltl_rules=list）。

    前端 toggle LTL 开关后 state.config 需与 /api/config 同构（renderLtlCard
    依赖 ltl_rules 为数组）；runtime 里 L2_2 是 Category dict（ltl_rules 为 dict），
    直接返回会崩（前端 ltl.filter 报 not a function）。
    幂等：仅当 ltl_rules 是 dict（Category 结构）才转换；已是 list（view）则跳过。
    """
    l22 = runtime.get("L2_2")
    if isinstance(l22, dict) and isinstance(l22.get("ltl_rules"), dict):
        # 不原地修改：runtime 可能来自 load_runtime_config 的进程内缓存，原地改会把
        # view 结构（ltl_rules=list）写进缓存，污染后续规则加载（rules_loader 按
        # dict 取 ltl_rules.rules → list.get 会崩）。改为浅拷贝后替换。
        runtime = {**runtime, "L2_2": _l2_2_runtime_to_view(l22)}
    return runtime


@router.put("/api/rules/enabled", dependencies=[Depends(auth_dependency)])
async def toggle_rule(body: RuleToggle):
    """开关单条规则。返回完整 runtimeConfig（避免前端全局状态被部分数据覆盖）。"""
    return _with_l2_2_view(update_rule_enabled(body.layer, body.category, body.rule_id, body.enabled))


@router.put("/api/rules/deny_mode", dependencies=[Depends(auth_dependency)])
async def change_rule_deny_mode(body: DenyModeUpdate):
    if body.deny_mode not in ("deny_write", "deny_read", "deny_both"):
        raise HTTPException(status_code=400, detail=f"无效的 deny_mode: {body.deny_mode}")
    return _with_l2_2_view(update_rule_deny_mode(body.layer, body.category, body.rule_id, body.deny_mode))


@router.put("/api/rules/skip_l3", dependencies=[Depends(auth_dependency)])
async def change_rule_skip_l3(body: SkipL3Update):
    return _with_l2_2_view(update_rule_skip_l3(
        body.layer, body.category, body.rule_id, body.skip_l3_on_disabled
    ))


@router.put("/api/categories/enabled", dependencies=[Depends(auth_dependency)])
async def toggle_category(body: CategoryToggle):
    return _with_l2_2_view(update_category_enabled(body.layer, body.category, body.enabled))


@router.post("/api/rules", dependencies=[Depends(auth_dependency)])
async def create_rule(body: NewRule):
    """新增自定义规则"""
    rule_dict: dict = {}
    for field in ("pattern", "keyword", "risk_level", "risk_type", "reason", "lang",
                  "path", "desc", "deny_mode"):
        val = getattr(body, field)
        if val:
            rule_dict[field] = val
    if body.credential:
        rule_dict["credential"] = body.credential

    # credential=True 要求 deny_mode=deny_both（读写均拦），否则 _sync_deny_mode_fields
    # 会静默 pop credential，导致凭据标记丢失。
    if body.credential and body.deny_mode and body.deny_mode != "deny_both":
        raise HTTPException(
            status_code=400,
            detail="credential=True 要求 deny_mode=deny_both（凭据读写均拦），"
            f"当前 deny_mode={body.deny_mode} 与之冲突",
        )
    return _with_l2_2_view(add_custom_rule(body.layer, body.category, rule_dict))


@router.delete("/api/rules", dependencies=[Depends(auth_dependency)])
async def remove_rule(body: DeleteRule):
    """删除自定义规则（内置规则不可删除）"""
    runtime = delete_custom_rule(body.layer, body.category, body.rule_id)
    if runtime is None:
        raise HTTPException(status_code=403, detail="内置规则不可删除，只能禁用")
    return _with_l2_2_view(runtime)


# ==================== Skill 管理 ====================


@router.get("/api/skills", dependencies=[Depends(auth_dependency)])
async def get_skills():
    runtime = _runtime_for_view()
    return runtime.get("L3_skills", {})


@router.put("/api/skills/enabled", dependencies=[Depends(auth_dependency)])
async def toggle_skill(body: SkillToggle):
    return _with_l2_2_view(update_skill_enabled(body.skill_id, body.enabled))


@router.put("/api/skill-categories/enabled", dependencies=[Depends(auth_dependency)])
async def toggle_skill_category(body: SkillCategoryToggle):
    return _with_l2_2_view(update_skill_category_enabled(body.category, body.enabled))


@router.post("/api/skills", dependencies=[Depends(auth_dependency)])
async def create_skill(body: NewSkill):
    return _with_l2_2_view(add_custom_skill(body.skill_id, body.category, body.keywords, body.content))


@router.delete("/api/skills", dependencies=[Depends(auth_dependency)])
async def remove_skill(body: DeleteSkill):
    runtime = delete_custom_skill(body.skill_id, body.category)
    if runtime is None:
        raise HTTPException(status_code=403, detail="内置 skill 不可删除，只能禁用")
    return _with_l2_2_view(runtime)


@router.get("/api/skills/{skill_id}/content", dependencies=[Depends(auth_dependency)])
async def get_skill_content(skill_id: str):
    """获取 skill 的完整 Markdown 内容。优先用户自定义目录，再内置 skills 目录。"""
    # 防路径穿越：skill_id 只允许字母数字下划线横线
    if not skill_id.replace("-", "").replace("_", "").isalnum():
        raise HTTPException(status_code=400, detail="非法 skill id")
    # 用户自定义 skill 目录（cold / builtin 模式下不读，只展示包内 skill）
    user_skills_dir = RUNTIME_CONFIG_DIR / "agent_moss_skills"
    # 内置 skill 目录（agent_moss/skills/）
    builtin_skills_dir = default_skills_dir()
    bases = ((builtin_skills_dir,) if is_runtime_config_disabled()
             else (user_skills_dir, builtin_skills_dir))
    for base in bases:
        p = base / f"{skill_id}.md"
        if p.exists():
            return {"skill_id": skill_id, "path": str(p), "content": p.read_text(encoding="utf-8")}
    raise HTTPException(status_code=404, detail=f"skill {skill_id} 不存在")


# ==================== agent 定制规则 ====================


@router.get("/api/agents", dependencies=[Depends(auth_dependency)])
async def get_agents():
    """获取所有 agent 定制规则（含 enabled 状态，供 console 展示）。"""
    return {"agents": get_agent_rules(_runtime_for_view())}


@router.put("/api/agents/rules/enabled", dependencies=[Depends(auth_dependency)])
async def toggle_agent_rule(body: AgentRuleToggle):
    """切换某 agent 某条规则的 enabled。"""
    fp = {k: v for k, v in {
        "value": body.value, "pattern": body.pattern,
        "keyword": body.keyword, "path": body.path,
    }.items() if v is not None}
    runtime = update_agent_rule_enabled(body.agent_id, body.category, fp, body.enabled)
    return {"agents": get_agent_rules(runtime)}


@router.post("/api/agents/rules", dependencies=[Depends(auth_dependency)])
async def create_agent_rule(body: NewAgentRule):
    """向某 agent 的某类别新增规则条目。"""
    rule = {k: v for k, v in body.model_dump().items()
            if k not in ("agent_id", "category") and v is not None}
    runtime = add_agent_rule(body.agent_id, body.category, rule)
    return {"agents": get_agent_rules(runtime)}


@router.delete("/api/agents/rules", dependencies=[Depends(auth_dependency)])
async def remove_agent_rule(body: DeleteAgentRule):
    """删除某 agent 某条规则。"""
    fp = {k: v for k, v in {
        "value": body.value, "pattern": body.pattern,
        "keyword": body.keyword, "path": body.path,
    }.items() if v is not None}
    runtime = delete_agent_rule(body.agent_id, body.category, fp)
    return {"agents": get_agent_rules(runtime)}


@router.put("/api/agents/categories/enabled", dependencies=[Depends(auth_dependency)])
async def toggle_agent_category(body: AgentCategoryToggle):
    """切换某 agent 某类别的整类开关（category_enabled）。"""
    runtime = update_agent_category_enabled(body.agent_id, body.category, body.enabled)
    return {"agents": get_agent_rules(runtime)}


# ==================== 场景定制规则 ====================


def _enabled_scenario_ids() -> list[str]:
    """返回当前启用的场景 id 列表。

    启用判定（与引擎 get_scenario_extensions 兜底一致）：环境变量
    AGENT_MOSS_SCENARIO（逗号分隔可多场景）。未设置 → 空列表
    （console 不显示场景卡片，引擎也不加载场景规则——部署级场景未启用）。
    """
    raw = os.getenv("AGENT_MOSS_SCENARIO", "")
    return [s.strip() for s in raw.split(",") if s.strip()]


@router.get("/api/scenarios", dependencies=[Depends(auth_dependency)])
async def get_scenarios():
    """获取所有场景定制规则（含 enabled 状态，供 console 展示）。

    只返回**已启用**的场景（由 AGENT_MOSS_SCENARIO env 决定）——没有 env 时不显示
    也不启用（部署级场景未配置）；有 env（如 AGENT_MOSS_SCENARIO=bank）时显示该场景。
    """
    all_scenarios = get_scenario_rules(_runtime_for_view())
    enabled = _enabled_scenario_ids()
    if not enabled:
        return {"scenarios": {}, "enabled": []}
    shown = {sid: all_scenarios[sid] for sid in enabled if sid in all_scenarios}
    return {"scenarios": shown, "enabled": enabled}


@router.put("/api/scenarios/rules/enabled", dependencies=[Depends(auth_dependency)])
async def toggle_scenario_rule(body: ScenarioRuleToggle):
    """切换某场景某条规则的 enabled。"""
    fp = {k: v for k, v in {
        "value": body.value, "pattern": body.pattern,
        "keyword": body.keyword, "path": body.path,
    }.items() if v is not None}
    runtime = update_scenario_rule_enabled(body.scenario_id, body.category, fp, body.enabled)
    return {"scenarios": get_scenario_rules(runtime), "enabled": _enabled_scenario_ids()}


@router.post("/api/scenarios/rules", dependencies=[Depends(auth_dependency)])
async def create_scenario_rule(body: NewScenarioRule):
    """向某场景的某类别新增规则条目。"""
    rule = {k: v for k, v in body.model_dump().items()
            if k not in ("scenario_id", "category") and v is not None}
    runtime = add_scenario_rule(body.scenario_id, body.category, rule)
    return {"scenarios": get_scenario_rules(runtime), "enabled": _enabled_scenario_ids()}


@router.delete("/api/scenarios/rules", dependencies=[Depends(auth_dependency)])
async def remove_scenario_rule(body: DeleteScenarioRule):
    """删除某场景某条规则。"""
    fp = {k: v for k, v in {
        "value": body.value, "pattern": body.pattern,
        "keyword": body.keyword, "path": body.path,
    }.items() if v is not None}
    runtime = delete_scenario_rule(body.scenario_id, body.category, fp)
    return {"scenarios": get_scenario_rules(runtime), "enabled": _enabled_scenario_ids()}


@router.put("/api/scenarios/categories/enabled", dependencies=[Depends(auth_dependency)])
async def toggle_scenario_category(body: ScenarioCategoryToggle):
    """切换某场景某类别的整类开关（category_enabled）。"""
    runtime = update_scenario_category_enabled(body.scenario_id, body.category, body.enabled)
    return {"scenarios": get_scenario_rules(runtime), "enabled": _enabled_scenario_ids()}


# ==================== 配置 / env / reset ====================


@router.get("/api/config", dependencies=[Depends(auth_dependency)])
async def get_full_config():
    """获取完整 runtime config（含 L2_2 形式化只读视图，供前端"形式化"页展示）"""
    # ⚠️ `dict(...)` 这层浅拷贝**不能省**：`_runtime_for_view()` 在正常模式下返回的是
    # `load_runtime_config()` 的**进程内缓存对象本身**，直接往上面写 L2_2 / builtin_only
    # / rules_mode 会**污染缓存**。污染后：
    #   ① 紧接着任何一次写操作都会 `save_runtime_config(load_runtime_config())`，
    #      把视图结构（L2_2.ltl_rules 由 dict 变 list，另多出 enabled_via / description
    #      两个**字符串**键）与两个伪层级键**落盘**；
    #   ② 再下一次 merge 时，`_merge_rule_categories` 的"清理源码已移除的类目"分支对
    #      `enabled_via`(str) 调 `.get("rules")` → AttributeError → 该接口 500。
    # 复现路径（2026-10 实测，前端页面加载即触发第 ①步）：
    #   打开 Console（GET /api/config）→ 点**第一次**开关 200（但已写坏文件）
    #   → 点**第二次**开关 500。
    # 写路径的 `_with_l2_2_view` 早已做了同样的浅拷贝（见其注释），读路径此前漏了。
    cfg = dict(_runtime_for_view())
    cfg["L2_2"] = _get_l2_2_view()
    cfg["builtin_only"] = is_builtin_only()
    cfg["rules_mode"] = get_rules_mode()
    return cfg


@router.get("/api/env-overrides", dependencies=[Depends(auth_dependency)])
async def get_env_status():
    # ⚠️ 必须包一层 ``{"overrides": ...}``：前端（console/static/index.html）
    # `loadEnvOverrides()` 读的是 ``resp?.overrides``，直接返回扁平 map 会让
    # 「环境变量接管」信息**恒为空**（禁用了哪些层看不出来）。TS 端
    # console/router.ts 一直是 ``{overrides: ...}``，双端在此分叉（2026-10 修正）。
    return {"overrides": get_env_overrides()}


@router.post("/api/reset", dependencies=[Depends(auth_dependency)])
async def reset_config():
    """重置配置到出厂默认（删除用户本地副本，下次调用自动重新生成）"""
    config_path = get_runtime_config_path()
    if config_path.exists():
        config_path.unlink()
    return _with_l2_2_view(generate_source_defaults())


# ==================== Token Stats ====================


@router.get("/api/token-stats", dependencies=[Depends(auth_dependency)])
async def get_token_stats_api(
    days: int = 0,
    start_date: str | None = None,
    end_date: str | None = None,
):
    """Token 用量汇总。days: 0=全部, 1=今天, 7=近7天。start/end_date 优先于 days。"""
    return get_token_stats(days, start_date=start_date, end_date=end_date)


@router.get("/api/token-stats/recent", dependencies=[Depends(auth_dependency)])
async def get_recent_token_records(limit: int = 20, offset: int = 0):
    return {"records": get_recent_records(limit, offset), "total": get_recent_records_count()}


@router.get("/api/token-stats/trend", dependencies=[Depends(auth_dependency)])
async def get_token_trend_api(
    days: int = 0,
    start_date: str | None = None,
    end_date: str | None = None,
):
    """Token 趋势（日期×模型），供折线图渲染。"""
    return get_token_trend(days=days, start_date=start_date, end_date=end_date)


@router.post("/api/token-stats/reset", dependencies=[Depends(auth_dependency)])
async def reset_token_stats_api():
    reset_token_stats()
    return {"detail": "Token stats reset successfully"}


# ==================== 构造函数 ====================


def create_console_router() -> APIRouter:
    """返回 console 路由（供主 app include_router 挂载到 /console）。"""
    return router


console_router = router
