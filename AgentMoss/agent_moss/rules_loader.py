"""归一化规则加载器（单一事实源）。

L1/L2/L3 的正则规则数据统一存放在 agent_moss/rules/ 下的三份 JSON：
  - l1_rules.json: 危险命令 / 注入关键词 / 敏感路径
  - l2_rules.json: 意图偏离 / 密码修改授权 / 用户删除授权
  - l3_rules.json: skill 关键词映射

Python 与 TS 两端都从这些 JSON 读取规则数据，消除双端规则漂移。
本模块提供纯数据读取；profile / engine 层负责把数据组装成各自的
CommandPattern / SensitivePath / IntentDeviationPattern 等结构。

规则数据是"出厂默认种子"的单一事实源；运行时用户可在共享 runtime JSON
里增删改规则（runtime 机制不受影响）。

**四条规则通道，语义不同，别用混**：

1. ``AGENT_MOSS_OVERRIDE_RULES_DIR`` / ``<data_root>/rules/<同名文件>``（本模块）
   —— **整份替换**内置 JSON。适合"内置规则出问题时自救，不等升级"或
   "我们有自己的整套规则"。部署面典型用法：K8s ConfigMap 挂目录 + 环境变量
   指过去（ConfigMap 只读，别拿它顶替整个 data_root —— 那里还有要写的文件）。
   放进同名文件即生效（需重启进程），内置规则后续更新**不会**反映到它上面。
2. runtime config（``agent_moss/infra/runtime_config.py``，即 Console）——
   **逐条合并**，内置新增的规则会自动出现且默认启用。适合日常调规则。
3. ``AGENT_MOSS_EXTRA_RULES_DIR``（本模块 ``load_extra_rules``）—— **追加目录**：
   扫描目录下全部 ``*.json``，把其中的规则**追加**到内置之后（内置保留，命中即
   短路）。适合部署侧批量补充自己的规则；文件名随意，内容按类别键组织。
4. ``AGENT_MOSS_CUSTOM_RULES`` 环境变量（``infra/config.py``）—— 内联 JSON
   注入 L1 正则，最轻量但只能进 L1 且规则要塞在环境变量值里。

⚠️ 历史坑：通道 1 的注释一直写着"数据根目录优先（允许部署侧覆盖）"，但代码
写的是**包内优先**（只有包内文件缺失才看数据目录）—— 注释与实现相反。
即「把自有规则丢进 <data_root>/rules/」曾静默不生效，而客户用的是 Python 版。
2026-09 修正为**数据根目录优先**。
"""
from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

from .infra.paths import asset_dir, get_data_root
from .infra.rules_mode import is_builtin_only, is_hot_reload_enabled

logger = logging.getLogger("agent_moss.rules_loader")

# 归一化规则文件的位置：
#   - 默认包内 `agent_moss/rules/`（TS copy-assets 会同步到 dist/rules）；
#   - 设了 `AGENT_MOSS_RULES_ROOT` → `<root>/rules/`（规则仓剥离后的落点）。
# 用函数而不是模块级常量：环境变量在进程内可被测试 monkeypatch 改，缓存住会失效。
def _rules_dir() -> Path:
    return asset_dir("rules")

#: 场景规则文件里**必须是数组**的键（客户最可能手改的就是它）。
#: 结构写错的后果：AgentExtensions 构造抛异常 → 调用方把整个场景置 None →
#: **场景保护静默全失效**（fail-open）。故加载时校验，不合格就回退内置。
_SCENARIO_LIST_KEYS = (
    "extra_command_patterns", "extra_injection_keywords", "extra_sensitive_paths",
)


def invalid_scenario_rules_reason(data: Any) -> str:
    """场景规则覆盖文件结构不可用时返回原因（``""`` = 可用）。"""
    if not isinstance(data, dict):
        return f"顶层必须是 JSON 对象，实际是 {type(data).__name__}"
    return "；".join(
        f"`{k}` 应为数组（对象数组），实际是 {type(data[k]).__name__}"
        for k in _SCENARIO_LIST_KEYS
        if k in data and not isinstance(data[k], list)
    )


def _parse_dir_env(env_name: str) -> list[Path]:
    """解析目录列表型环境变量：逗号或分号分隔，支持多个；未设/为空返回 []。

    ⚠️ 不收冒号（PATH 的 ``:`` 惯例）—— Windows 盘符 ``C:\\x`` 会被冒号拆坏。
    """
    raw = os.environ.get(env_name, "").strip()
    if not raw:
        return []
    return [Path(p.strip()) for p in re.split(r"[,;]", raw) if p.strip()]


#: 规则目录里**唯一会被读取的两个文件名**（2026-10 与客户确认的语义）。
#: 目录根下的其他 ``*.json`` **一律不读**（客户踩过：随机名文件"看起来生效了"，
#: 实际是别的原因，白折腾一轮）。语义只看文件名，与用哪个环境变量指定目录无关。
OVERRIDE_FILENAME = "override.json"   # 覆盖：出现的类别**整份替换**内置同类
EXTRA_FILENAME = "extra.json"         # 追加：出现的类别追加到（替换后的）规则之后

RULES_DIR_ENVS = ("AGENT_MOSS_EXTRA_RULES_DIR", "AGENT_MOSS_OVERRIDE_RULES_DIR")


def rules_dirs() -> list[Path]:
    """规则目录清单（去重保序）：
    1. ``AGENT_MOSS_EXTRA_RULES_DIR`` / ``AGENT_MOSS_OVERRIDE_RULES_DIR``
       —— 两个变量**语义相同**，都只是"目录在哪"；追加还是覆盖**由文件名决定**。
       （K8s ConfigMap 通常只能挂一个目录，故两个变量指向同一个目录是预期用法。）
    2. ``<data_root>/rules/``（本地开发/单机用法）。

    目录不存在时只告警、不报错（部署侧可能还没挂上 ConfigMap）。

    仅内置规则模式下**返回空列表**：``AGENT_MOSS_EXTRA_RULES_DIR`` /
    ``AGENT_MOSS_OVERRIDE_RULES_DIR`` / ``<data_root>/rules`` 全部忽略。
    """
    if is_builtin_only():
        return []
    dirs: list[Path] = []
    for env in RULES_DIR_ENVS:
        dirs.extend(_parse_dir_env(env))
    dirs.append(get_data_root() / "rules")
    out: list[Path] = []
    seen: set[str] = set()
    for d in dirs:
        key = str(d)
        if key not in seen:
            seen.add(key)
            out.append(d)
    return out


def rule_dir_files() -> dict[str, list[Path]]:
    """规则目录里的文件清单（供启动自检说清"读了什么、忽略了什么"）：

    ``{"override": [...], "extra": [...], "ignored": [...]}`` —— ``ignored`` 是
    目录根下既不叫 override.json 也不叫 extra.json 的 ``*.json``（**不会被读取**，
    必须显式报出来，否则就是"我明明放了文件怎么不生效"）。
    """
    out: dict[str, list[Path]] = {"override": [], "extra": [], "ignored": []}
    for d in rules_dirs():
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.json")):
            if f.name == OVERRIDE_FILENAME:
                out["override"].append(f)
            elif f.name == EXTRA_FILENAME:
                out["extra"].append(f)
            else:
                out["ignored"].append(f)
    return out


def rule_files_report() -> str:
    """一行式的规则目录自检摘要（启动时打印）。"""
    files = rule_dir_files()
    parts = []
    if files["override"]:
        parts.append("覆盖(override.json): " + ", ".join(str(p) for p in files["override"]))
    if files["extra"]:
        parts.append("追加(extra.json): " + ", ".join(str(p) for p in files["extra"]))
    if files["ignored"]:
        parts.append(
            "**未读取**（目录里只有 override.json / extra.json 会被读）: "
            + ", ".join(str(p) for p in files["ignored"])
        )
    return "；".join(parts) if parts else ""


def resolve_scenario_rules_file(scenario_id: str) -> Path:
    """场景规则文件解析：规则目录里的 ``scenarios/<id>/rules.json`` 优先，
    否则包内 ``agent_moss/scenarios/<id>/rules.json``。

    为什么场景规则单独留一个**按路径寻址**的替换位（而不是并进 override.json）：
    场景规则的字段（extra_command_patterns / extra_sensitive_paths / 目录白名单…）
    与 L1/L2 的六个类别不同构，塞进同一个文件表达不了。它不在目录根、也不与
    "目录根只认 override.json / extra.json" 冲突（2026-10 与客户确认该规则时，
    客户关心的是根目录下那些自由命名的文件）。
    内置场景规则出问题时的应急修法：拷一份改好放这个路径，不必等升级。

    **结构校验**：写错（如把数组写成对象）会被拒绝并回退内置 —— 否则
    AgentExtensions 构造抛异常 → 调用方把整个场景置 None → 场景保护静默失效。
    """
    # 目录穿越防护：scenario_id 来自请求/环境变量，直接拼路径会被 `../` 利用。
    # ⚠️ 本函数**永远返回 Path**（调用方直接 .is_file()），所以非法 id 返回一个
    # 必定不存在的路径，而不是 None —— 等价于"这个场景没有规则"。
    from .infra.paths import is_safe_id
    if not is_safe_id(scenario_id):
        logger.warning("非法 scenario_id 已忽略（含路径字符或超长）: %.120r", scenario_id)
        return asset_dir("scenarios") / "__invalid__" / "rules.json"
    rel = Path("scenarios") / scenario_id / "rules.json"
    builtin = asset_dir("scenarios") / scenario_id / "rules.json"
    for d in rules_dirs():
        p = d / rel
        if p.is_file():
            reason = ""
            try:
                with open(p, "r", encoding="utf-8") as f:
                    reason = invalid_scenario_rules_reason(json.load(f) or {})
            except (json.JSONDecodeError, OSError) as e:
                reason = f"读取/解析失败: {e}"
            if reason:
                logger.error(
                    "❌ 场景规则覆盖文件结构不可用，**已忽略并回退内置**: %s\n"
                    "    原因: %s\n    期望格式见: %s",
                    p, reason, builtin,
                )
                return builtin
            logger.warning(
                "⚠️  场景 %s 规则被覆盖: %s（内置 %s 被忽略；内置更新不会反映到它上面）",
                scenario_id, p, builtin,
            )
            return p
    return builtin


#: 规则文件进程内缓存：path → (mtime_ns, size, 解析后的 dict)。
#: 规则 JSON 是包内只读资源，但一次 analyze 会重复读取多次（profile 各属性各自
#: 调 load_l1/load_l2），缓存把重复的「读文件 + JSON 解析」收敛为一次。
#: 文件被改动（mtime/size 变化）时自动失效；每个路径各留一份，互不挤兑。
#: 约定：调用方**不得原地修改**返回的 dict（只读取用）。
_JSON_CACHE: dict[str, tuple[int, int, dict[str, Any]]] = {}


def _load_json(name: str) -> dict[str, Any]:
    """读取**包内内置**规则 JSON。文件缺失或损坏时回退空 dict（不影响启动）。

    ⚠️ 部署侧的覆盖/追加**不在这里**：规则目录里的 ``override.json``（整类替换）与
    ``extra.json``（整类追加）由 ``load_override_rules()`` / ``load_extra_rules()``
    解析，并在 ``infra/runtime_config.py`` 的合并层生效（判定时读的正是那一层）。
    """
    path = _rules_dir() / name
    cache_key = str(path)
    cached = _JSON_CACHE.get(cache_key)
    # cold / builtin 模式下**不再按 mtime 失效、也不再 stat**：包内规则文件在进程
    # 启动后即使被改/被删，本次运行也继续使用首次读到的内容（否则同用户改 venv 里的
    # 包内 JSON 仍是热生效）。
    if not is_hot_reload_enabled() and cached is not None:
        return cached[2]
    try:
        st = path.stat()
    except OSError:
        return {}
    if cached is not None and cached[0] == st.st_mtime_ns and cached[1] == st.st_size:
        return cached[2]
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f) or {}
    except (json.JSONDecodeError, OSError):
        return {}
    _JSON_CACHE[cache_key] = (st.st_mtime_ns, st.st_size, data)
    return data


def builtin_rules_file(name: str) -> Path:
    """包内**内置**规则文件路径（规则目录不再按内置文件名覆盖，故路径恒定）。"""
    return _rules_dir() / name


def load_l1() -> dict[str, Any]:
    """返回 L1 规则数据：{dangerous_commands, injection_detection, sensitive_path_access}。"""
    return _load_json("l1_rules.json")


def load_l2() -> dict[str, Any]:
    """返回 L2 规则数据：{intent_consistency, password_modify_consent, user_deletion_consent}。"""
    return _load_json("l2_rules.json")


def load_l3() -> dict[str, Any]:
    """返回 L3 规则数据：{category: {skill_id: [keywords...]}}。

    规则目录的 ``skills`` 键生效：
      - ``override.json`` → 出现的**类别**整份替换（未出现的类别保持内置）；
      - ``extra.json`` → 按技能名合并（同名以 extra 为准，新技能追加进去）。
    """
    data = dict(_load_json("l3_rules.json"))
    try:
        ov = load_override_rules().get("skills")
        ex = load_extra_rules().get("skills") or {}
    except Exception:  # noqa: BLE001 — 规则目录不可用不影响内置加载
        return data
    if isinstance(ov, dict):
        for cat, skills in ov.items():
            if isinstance(skills, dict):
                data[cat] = dict(skills)
    if isinstance(ex, dict):
        for cat, skills in ex.items():
            if isinstance(skills, dict):
                data[cat] = {**(data.get(cat) or {}), **skills}
    return data


#: 规则 JSON 里正则的**语义**标志字符 → Python re 标志。
#: TS 侧读同一份字符（另加 g 用于循环匹配，不参与语义）。改动会直接改变判定。
RE_FLAG_MAP = {"i": re.IGNORECASE, "s": re.DOTALL, "m": re.MULTILINE}


def regex_flags(flags: str) -> int:
    """把规则 JSON 里的标志字符串（如 ``"is"``）转成 Python ``re`` 标志。"""
    out = 0
    for ch in str(flags or ""):
        out |= RE_FLAG_MAP.get(ch, 0)
    return out


def compile_rule_regex(rule: dict[str, Any]) -> re.Pattern[str]:
    """按规则 JSON 里的 ``{pattern, flags}`` 编译正则。"""
    return re.compile(str(rule["pattern"]), regex_flags(str(rule.get("flags", ""))))


def resolve_keyword_set(group: Any, keyword_sets: dict[str, Any]) -> set[str]:
    """解析组合规则里的 ``group1`` / ``group2``。

    以 ``$`` 开头的字符串是对 ``keyword_sets`` 的引用（如 ``"$network_post"``），
    这样「网络外发」那组词只写一遍；否则就是显式数组。
    """
    if isinstance(group, str):
        return {str(k) for k in (keyword_sets.get(group[1:]) or [])}
    return {str(k) for k in (group or [])}


def load_inline() -> dict[str, Any]:
    """返回内联脚本判定的识别词表（``rules/inline_rules.json``）。

    键：``read_write_keywords``（读写调用词，子串匹配）、``dir_traversal_keywords``
    （目录遍历词，子串匹配）、``write_exec_chain_patterns``（写入+执行绕过链，正则）、
    ``redirect_sensitive_paths``（重定向写敏感路径的清单）。

    这批词表原先**硬编码**在 ``engine/inline_analyzer.py`` 中 —— 迁进 JSON 后单一事实源，
    是规则仓剥离的前置工作。

    与 ``platform_traits`` 一样**不参与 runtime 合并、也不读规则目录**（override/extra）：
    它们在进程内就是常量，改 JSON 需重启进程。

    ⚠️ 文件缺失/损坏 → 返回 ``{}``。调用方拿到空词表后，内联脚本会一律被当"文本字面量"
    放行（**更松**），故 ``inline_analyzer`` 加载为空时会打 error 日志。
    """
    return _load_json("inline_rules.json")


def load_formal_rules() -> dict[str, Any]:
    """返回 L2.2 形式化引擎的识别名单（``rules/formal_rules.json``）。

    键：``privesc.package_managers`` / ``privesc.bare_shells``（提权判定的命令位置旁证）、
    ``compute_action_types``（一律视为命令执行形态的 action_type）、
    ``pattern_miner.danger_stages`` / ``pattern_miner.sensitive_pairs``

    文件缺失/损坏 → ``{}``。后果分两块：包管理器名单空 → sudo apt 被误判为提权（更严）；
    危险阶段名单空 → 组合链挖掘**不报**（更松）。两者都不会静默放宽"拦截"，故加载方
    只记 error 日志。
    """
    return _load_json("formal_rules.json")


def load_logic_rules() -> dict[str, Any]:
    """返回 L2 逻辑规则的识别词表（``rules/logic_rules.json``）。

    目前只有 ``indirect_file_access`` 一组（间接文件访问检测的读/写/执行/open 词）。
    目录遍历词表不在本文件，复用 ``inline_rules.json`` 的 ``dir_traversal_keywords``
    —— 两处原本就是同一份 10 条。

    文件缺失/损坏 → ``{}``，后果是间接访问检测**不命中**（更松），故加载方需报错。
    """
    return _load_json("logic_rules.json")


def load_heuristic_rules() -> dict[str, Any]:
    """返回 L1 特征检测的小型名单（``rules/heuristic_rules.json``）。

    原先硬编码在 ``engine/heuristic.py``：
    敏感路径检测排除前缀、搜索类工具前缀/精确名、回环地址名单。

    与其它 ``*_rules.json`` 一样不参与 runtime 合并；文件缺失/损坏 → ``{}``，
    后果是排除名单为空（**更严**）—— 不会静默放宽判定。
    """
    return _load_json("heuristic_rules.json")


def load_script_rules() -> dict[str, Any]:
    """返回脚本内容分析的高风险词表（``rules/script_rules.json``）。

    原先**两份**副本硬编码在 ``engine/script_content_analyzer.py``、
    ``engine/script_analyzer.py``。迁进 JSON 后只有一份。

    键：``keyword_sets``（可被组合规则以 ``$name`` 引用的词集）、
    ``suspicious_patterns``（18 条高风险关键词正则）、
    ``keyword_combination_risks``（组合放大规则）、``single_keyword_risks``
    （单词默认风险等级与文案）、``env_exfil_patterns``（环境变量外发旁证）、
    ``script_exec_patterns``（脚本路径提取，分 ``chain`` / ``legacy`` 两份，不可互换）。

    与 ``platform_traits`` / ``inline_rules`` 一样不参与 runtime 合并。
    ⚠️ 文件缺失/损坏 → ``{}``，脚本关键词扫描将一条都不命中（更松），
    故加载方需打 error 日志。
    """
    return _load_json("script_rules.json")


#: 平台特征的字段清单 —— 与 ``rules/platform_traits.json`` 的平台对象键一一对应。
#: 字段语义见 ``rules/platform_traits.json`` 的 ``_comment``。
TRAITS_FIELDS: tuple[str, ...] = (
    "write_keywords",
    "read_keywords",
    "write_command_res",
    "read_only_commands",
    "fully_safe_commands",
    "readonly_sensitive_commands",
    "safe_action_types",
    "readonly_sensitive_action_types",
)

#: 平台特征里"集合类"字段：语义只做成员判断，顺序无意义，JSON 侧按字典序存。
TRAITS_SET_FIELDS: frozenset[str] = frozenset(
    {"read_only_commands", "safe_action_types", "readonly_sensitive_action_types"}
)

_TRAITS_OS_FALLBACK = "linux"


def load_platform_traits(os_name: str = "") -> dict[str, Any]:
    """返回某平台**已解析继承**的平台特征：``{字段: 值}``（键见 ``TRAITS_FIELDS``）。

    背景：这些"放行/豁免边界"（只读白名单、写命令正则、意图关键词……）原先**硬编码**在各
    ``profiles/*.py`` 里，还有重复副本。
    迁到 ``rules/platform_traits.json`` 后，双端读同一份，后续规则仓才能整体剥离。

    - ``macos`` / ``harmony`` 在 JSON 里写 ``{"inherits": "linux"}``，此处解析成 linux
      那一份 —— 与 ``OSProfile.accepted_os`` 的"类 Unix 继承 linux"语义一致；
    - 未知平台、或 ``inherits`` 成环 → 回落 ``linux``（绝不返回半截数据）；
    - **文件缺失/损坏 → 返回 ``{}``**：调用方得到"空特征"，其后果是白名单为空
      （更多命令走完整 L2/L3、重定向按写处理）= **更严不是更松**，不会静默放宽判定；
      同时记 error 日志，避免"包坏了但看起来一切正常"。

    ⚠️ 与其它规则不同，平台特征**不参与 runtime 合并、也不读规则目录**（override/extra）：
    它们在内置规则模式下就是常量，进程内不变。改 JSON 需重新导入进程（与今天的硬编码
    常量行为一致）。
    """
    data = _load_json("platform_traits.json")
    if not data:
        logger.error(
            "规则文件 platform_traits.json 缺失或损坏 —— 平台特征回落为空（白名单为空，"
            "判定会变严）。请检查包完整性。"
        )
        return {}

    name = (os_name or "").strip().lower() or _TRAITS_OS_FALLBACK
    seen: set[str] = set()
    while True:
        if name in seen:  # inherits 成环：回落 linux，绝不死循环
            logger.error("platform_traits.json 的 inherits 成环（%s）—— 回落 linux。", name)
            name = _TRAITS_OS_FALLBACK
            break
        seen.add(name)
        entry = data.get(name)
        if isinstance(entry, dict):
            nxt = entry.get("inherits")
            if isinstance(nxt, str) and nxt.strip().lower() != name:
                name = nxt.strip().lower()
                continue
            return {f: entry[f] for f in TRAITS_FIELDS if f in entry}
        # 该平台没有独立条目（或平台名未收录）→ 回落 linux
        if name == _TRAITS_OS_FALLBACK:
            logger.error("platform_traits.json 里没有 linux 条目 —— 平台特征为空。")
            return {}
        name = _TRAITS_OS_FALLBACK


def load_mc_raw() -> dict[str, Any]:
    """只应用**规则目录**（override/extra 的 ``ltl_rules``）后的 mc 数据，**不碰 runtime**。

    为什么单独一个函数：runtime_config 生成种子清单时也要读这份数据，而
    ``load_mc()`` 内部又调 ``load_runtime_config()`` —— 直接调会互相递归（老坑）。
    种子与引擎必须读**同一份**，否则"引擎按覆盖跑、种子按内置生成"，merge 会把
    用户侧规则误标 source_removed（Console 上只剩内置那几条可点）。
    """
    mc = dict(_load_json("mc_rules.json"))
    rules = list(mc.get("rules") or [])
    try:
        ov = load_override_rules().get("ltl_rules")
        ex = load_extra_rules().get("ltl_rules") or []
    except Exception:  # noqa: BLE001
        return mc
    if isinstance(ov, list):
        rules = list(ov)          # 覆盖：整份替换规则清单
    if isinstance(ex, list) and ex:
        by_id = {r.get("id"): r for r in rules if isinstance(r, dict)}
        for r in ex:
            if isinstance(r, dict) and r.get("id"):
                by_id[r["id"]] = r   # 同名 id 以 extra 为准
        rules = list(by_id.values())
    mc["rules"] = rules
    return mc


def load_mc() -> dict[str, Any]:
    """返回 L2.2 模型检测规则数据：{ap_patterns, rules}（LTL 公式 AST，双端共用）。

    规则目录的 ``ltl_rules`` 键先应用（override 整份替换 / extra 按 id 合并），
    再合并 runtime_config 的 L2_2.ltl_rules 分区 enabled（按 id 覆盖），
    引擎 check_mc_rules 据此跳过被禁用的规则；出厂默认全开。
    """
    mc = load_mc_raw()
    rules = mc.get("rules", [])
    try:
        from .infra.runtime_config import has_runtime_config, load_runtime_config
        if rules and has_runtime_config():
            rt = load_runtime_config().get("L2_2", {}).get("ltl_rules", {})
            rt_rules = rt.get("rules", [])
            enabled_by_id = {r.get("id"): r.get("enabled", True) for r in rt_rules}
            # 大类开关：category_enabled=False 时整类禁用（对齐 L1/L2 的 filter_enabled_rules 语义）
            cat_enabled = rt.get("category_enabled", True)
            for r in rules:
                if r.get("id") in enabled_by_id:
                    r["enabled"] = enabled_by_id[r["id"]]
                if not cat_enabled:
                    r["enabled"] = False
    except Exception:
        pass  # runtime_config 不可用则维持内置默认（全开）
    return mc


def load_tool_registry() -> dict[str, Any]:
    """返回 Tool Registry 数据：{tools: {name: {actionClass, requireHighIntegrity}}}。

    规则目录的 ``tools`` 键生效：override 整份替换、extra 按工具名合并（同名以 extra 为准）。
    """
    data = dict(_load_json("tool_registry.json"))
    tools = dict(data.get("tools") or {})
    try:
        ov = load_override_rules().get("tools")
        ex = load_extra_rules().get("tools") or {}
    except Exception:  # noqa: BLE001
        return data
    if isinstance(ov, dict):
        tools = dict(ov)
    if isinstance(ex, dict):
        tools.update(ex)
    data["tools"] = tools
    return data


# ---------------------------------------------------------------------------
# 规则目录（一个目录 + 两个固定文件名）—— 覆盖 override.json / 追加 extra.json
# ---------------------------------------------------------------------------
# 语义（2026-10 与客户确认；K8s ConfigMap 只能挂一个目录，故两个环境变量都只是
# "目录在哪"，追加还是覆盖**由文件名决定**）：
#
#   <目录>/override.json   覆盖：文件里出现的类别**整份替换**内置同名类别
#                          （没写的类别保持内置；写空数组 = 明确清空该类别）
#   <目录>/extra.json      追加：文件里出现的类别**追加**在（替换后的）规则之后
#   其他 *.json            **一律不读**（启动自检会列出来提醒）
#
# 优先级：override.json > extra.json > 内置；同一类别内按 pattern/path 去重，
# 先出现的（高优先）保留。
#
# 为什么废掉原来"按内置文件名覆盖"（l1_rules.json 等）：客户实测时被它绕晕了——
# "我放了个别的名字的文件，怎么好像也生效了？"（实际生效的是别的原因）。一条
# "只有这两个文件名会被读"的规则零例外，最好解释、最不容易踩。

#: 规则目录里允许的类别键 → 该类别条目的**必需字段**。与内置 l1/l2_rules.json
#: 的类别键同构（客户拷内置文件的某个类别改改就能用），未知键告警跳过。
_CATEGORIES: dict[str, tuple[str, ...]] = {
    # L1
    "dangerous_commands": ("pattern",),
    "injection_detection": ("keyword", "lang"),
    "sensitive_path_access": ("path",),
    # L2
    "intent_consistency": ("intent_keywords",),
    "password_modify_consent": ("pattern",),
    "user_deletion_consent": ("pattern",),
}

#: 除六个规则类别外，另外三个**结构性数据**的键（形状不同，单独校验/合并）：
#:   skills    —— L3 技能表 ``{类别: {技能名: [关键词...]}}``（覆盖：按类别整份替换；追加：按技能名合并）
#:   ltl_rules —— L2.2 模型检测规则 ``[{id, type, formula, ...}]``（覆盖：整份替换；追加：按 id 合并）
#:   tools     —— 工具注册表 ``{工具名: {actionClass, requireHighIntegrity}}``（覆盖：整份替换；追加：按工具名合并）
#: 2026-10 补：此前这三类只有"按内置文件名覆盖"（已废除）能改，override/extra 管不到。
_STRUCT_KEYS = ("skills", "ltl_rules", "tools")

#: 平铺数组条目的归类依据（字段 → 类别）。``pattern`` 裸出现（无 risk_level/risk_type）
#: 无法区分 L1 危险命令与 L2 授权类，拒绝 —— 让部署侧放进显式类别键下。
_FLAT_FIELD: tuple[tuple[tuple[str, ...], str], ...] = (
    (("path",), "sensitive_path_access"),
    (("keyword", "lang"), "injection_detection"),
    (("intent_keywords",), "intent_consistency"),
    (("pattern", "risk_level"), "dangerous_commands"),
    (("pattern", "risk_type"), "dangerous_commands"),
)

#: 规则目录解析缓存：单槽 (env 签名, 文件指纹, override 结果, extra 结果,
#: 成功加载的文件, 被忽略的文件)。文件 mtime/size 或 env 变化即重扫。
_RULES_CACHE: tuple[str, tuple, dict[str, list[dict]], dict[str, list[dict]],
                    list[Path], list[Path]] | None = None

#: 已告警过的"目录里有不会被读取的 json"（同一批文件只吼一次）
_warned_ignored: set[str] = set()


def _scan_rules_file(path: Path, kind: str) -> dict[str, list[dict]]:
    """解析一个规则文件（kind ∈ {"override", "extra"}，仅用于日志措辞）。

    返回 ``{类别键: [条目...]}``。坏文件 / 非法结构 / 缺必需字段 / id 重复 →
    **告警跳过**，绝不崩判定（加载失败的表现必须是"少一条规则 + 有日志"，
    不能是每次 analyze 抛异常 → 全量 Deny）。

    特别地：类别值写成 runtime config 的字典形态
    （``{"dangerous_commands": {"category_enabled": true, "rules": [...]}}``）是
    高频误用，这里显式识破并给出可操作的提示。
    """
    out: dict[str, list[dict]] = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error("规则文件 %s 损坏/不可读，已跳过（%s 规则不生效）: %s", path, kind, e)
        return out
    except UnicodeDecodeError as e:
        logger.error("规则文件 %s 编码非 UTF-8，已跳过: %s", path, e)
        return out

    pairs: list[tuple[str, Any]] = []
    if isinstance(data, dict):
        pairs = list(data.items())
    elif isinstance(data, list):
        flat_bad = 0
        for r in data:
            cat = None
            for keys, c in _FLAT_FIELD:
                if isinstance(r, dict) and all(r.get(k) for k in keys):
                    cat = c
                    break
            if cat is None:
                flat_bad += 1
                continue
            pairs.append((cat, [r]))
        if flat_bad:
            logger.warning(
                "规则文件 %s 有 %d 条平铺条目无法归类（裸 pattern 不带 "
                "risk_level/risk_type 时区分不了 L1 危险命令与 L2 授权类）——"
                "请改用对象形式：{\"类别键\": [条目...]}。", path, flat_bad,
            )
    else:
        logger.error(
            "规则文件 %s 顶层应是对象（类别键→条目数组）或数组，已跳过。", path,
        )
        return out

    for cat, rules in pairs:
        if str(cat).startswith("_"):
            continue  # _comment 等说明键
        if cat in _STRUCT_KEYS:
            got = _scan_struct_entry(cat, rules, path)
            if got is not None:
                out[cat] = got
            continue
        required = _CATEGORIES.get(cat)
        if required is None:
            logger.warning(
                "规则文件 %s 含未知类别键 %r（可用：%s）—— 已跳过该类别。",
                path, cat, ", ".join(_CATEGORIES),
            )
            continue
        if isinstance(rules, dict):
            # 高频误用：把 runtime config 的类别结构当规则文件用
            logger.error(
                "❌ 规则文件 %s 的类别 %r 是**对象**，应为**对象数组** —— 已跳过该类别。\n"
                "    正确写法: {\"%s\": [{\"pattern\": \"...\", \"risk_level\": \"high\", ...}]}\n"
                "    你写的像是 runtime config 的格式（{\"category_enabled\": ..., \"rules\": [...]}）——"
                "那是 ~/.config/agentmoss/agent_moss_runtime.json 的格式，不能直接当规则文件用。",
                path, cat, cat,
            )
            continue
        if not isinstance(rules, list):
            logger.warning(
                "规则文件 %s 的类别 %r 应为数组，实际是 %s —— 已跳过该类别。",
                path, cat, type(rules).__name__,
            )
            continue
        # ⚠️ **空数组 = 不覆盖该类别**（不是清空）：只在真有有效条目时才建键。
        # 为什么：模板是空壳，客户可能原样拷进去 —— 若"空数组 = 清空"，那一拷就把
        # 内置规则整类干掉（灾难）。"清空某类"这个能力因此不提供（要逐条禁用请用
        # runtime config）。
        items: list[dict] = []
        for r in rules:
            if not isinstance(r, dict) or not all(r.get(k) for k in required):
                logger.warning(
                    "规则文件 %s 类别 %s 有条目缺必需字段 %s —— 已跳过该条。",
                    path, cat, required,
                )
                continue
            items.append(r)
        if items:
            out[cat] = out.get(cat, []) + items
    if out:
        logger.info(
            "已加载%s规则文件 %s：%s",
            "覆盖" if kind == "override" else "追加", path,
            ", ".join(f"{k}×{len(v)}" for k, v in sorted(out.items())),
        )
    return out


def _scan_struct_entry(cat: str, value: Any, path: Path) -> Any:
    """校验 ``skills`` / ``ltl_rules`` / ``tools`` 三个结构性键；不合法返回 None（告警跳过）。"""
    if cat == "skills":
        if not isinstance(value, dict):
            logger.error("规则文件 %s 的 skills 应为对象（{类别: {技能名: [关键词]}}）—— 已跳过。", path)
            return None
        out: dict[str, dict] = {}
        for sk_cat, skills in value.items():
            if not isinstance(skills, dict):
                logger.error("规则文件 %s 的 skills.%s 应为对象（技能名 → 关键词数组）—— 已跳过该类别。",
                             path, sk_cat)
                continue
            keep = {k: v for k, v in skills.items() if isinstance(v, list)}
            if len(keep) != len(skills):
                logger.warning("规则文件 %s 的 skills.%s 有条目的关键词不是数组 —— 已跳过该条。", path, sk_cat)
            if keep:
                out[str(sk_cat)] = keep
        return out or None

    if cat == "ltl_rules":
        if not isinstance(value, list):
            logger.error("规则文件 %s 的 ltl_rules 应为对象数组 —— 已跳过。", path)
            return None
        keep = [r for r in value if isinstance(r, dict) and r.get("id")]
        if len(keep) != len(value):
            logger.warning("规则文件 %s 的 ltl_rules 有条目缺 id 或不是对象 —— 已跳过该条。", path)
        return keep or None

    if cat == "tools":
        if not isinstance(value, dict):
            logger.error("规则文件 %s 的 tools 应为对象（{工具名: {actionClass, ...}}）—— 已跳过。", path)
            return None
        keep = {str(k): v for k, v in value.items() if isinstance(v, dict)}
        if len(keep) != len(value):
            logger.warning("规则文件 %s 的 tools 有条目的值不是对象 —— 已跳过该条。", path)
        return keep or None

    return None


def _scan_rule_dirs() -> tuple[dict[str, list[dict]], dict[str, list[dict]], dict[str, list[Path]]]:
    """扫描规则目录，返回 (override 类别表, extra 类别表, 各类文件清单)。"""
    override: dict[str, list[dict]] = {}
    extra: dict[str, list[dict]] = {}
    loaded: dict[str, list[Path]] = {"override": [], "extra": [], "ignored": []}
    for d in rules_dirs():
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.json")):
            if f.name == OVERRIDE_FILENAME:
                got = _scan_rules_file(f, "override")
                # override 只要**声明了类别**就算生效（空数组 = 显式清空该类，是有效指令）；
                # extra 必须真的贡献了条目才算（空数组对追加而言等于没写）。
                if got:
                    loaded["override"].append(f)
                for cat, items in got.items():
                    # ⚠️ 结构性键（skills / tools）是**对象**，不能当数组 extend ——
                    # 否则被展开成键名列表（实测：skills 变成 ["file_operations"]，
                    # 覆盖静默失效）。按形状分别合并。
                    if isinstance(items, dict):
                        override.setdefault(cat, {}).update(items)
                    else:
                        override.setdefault(cat, []).extend(items)
            elif f.name == EXTRA_FILENAME:
                got = _scan_rules_file(f, "extra")
                if any(len(v) > 0 for v in got.values()):
                    loaded["extra"].append(f)
                for cat, items in got.items():
                    if isinstance(items, dict):
                        extra.setdefault(cat, {}).update(items)     # skills / tools 这类对象
                    else:
                        extra.setdefault(cat, []).extend(items)
            else:
                loaded["ignored"].append(f)
    # 防呆：override.json 与内置**逐条一致**（多半是"模板原样拷进来没改"）→ 必须点破。
    # 这类文件的真实代价是"把内置 L1 规则钉在这一版"（以后升级不跟随），
    # 而用户往往只是想追加规则、误拷了这个文件。
    if override:
        builtin_same = _identical_to_builtin(override)
        if builtin_same:
            key_id = "override-identical::" + "|".join(f"{c}={len(v)}" for c, v in sorted(override.items()))
            if key_id not in _warned_ignored:
                _warned_ignored.add(key_id)
                logger.warning(
                    "ℹ️  %s 与**内置规则完全一致**（%s）—— 看起来是模板原样拷进来没改。\n"
                    "    它现在的效果 = 内置规则；但**以后升级内置规则不会反映到这份上**（被钉住了）。\n"
                    "    只想追加规则：删掉 %s，改用 %s。",
                    OVERRIDE_FILENAME,
                    ", ".join(f"{c}×{len(v)}" for c, v in sorted(override.items())),
                    OVERRIDE_FILENAME, EXTRA_FILENAME,
                )

    # 整类替换必须**量化告警**：override.json 里写一个类别 = 该类别的内置规则
    # 全部不再生效（"我就加了一条规则，怎么 rm -rf / 都不拦了" 是真实风险）。
    if override:
        builtin_counts = {
            "dangerous_commands": len(load_l1().get("dangerous_commands") or []),
            "injection_detection": len(load_l1().get("injection_detection") or []),
            "sensitive_path_access": len(load_l1().get("sensitive_path_access") or []),
            "intent_consistency": len(load_l2().get("intent_consistency") or []),
            "password_modify_consent": len(load_l2().get("password_modify_consent") or []),
            "user_deletion_consent": len(load_l2().get("user_deletion_consent") or []),
        }
        key_ov = "override-summary::" + "|".join(f"{c}={len(v)}" for c, v in sorted(override.items()))
        if key_ov not in _warned_ignored:
            _warned_ignored.add(key_ov)
            logger.warning(
                "⚠️  %s 生效（**整份替换**，未列出的内置规则不再生效）：", OVERRIDE_FILENAME,
            )
            for cat, items in sorted(override.items()):
                logger.warning(
                    "      类别 %s：内置 %d 条 → 你的 %d 条",
                    cat, builtin_counts.get(cat, 0), len(items),
                )
            logger.warning(
                "    只想**追加**规则请改用 %s；要改某一条内置规则，请先拷贝内置文件再改。",
                EXTRA_FILENAME,
            )

    ignored = loaded["ignored"]
    if ignored:
        key = "|".join(str(p) for p in ignored)
        if key not in _warned_ignored:
            _warned_ignored.add(key)
            logger.warning(
                "⚠️  规则目录里有 %d 个 json **不会被读取**（只有 %s 与 %s 会被读）: %s\n"
                "    要覆盖内置规则 → 改名/内容放进 %s；要追加 → 放进 %s。",
                len(ignored), OVERRIDE_FILENAME, EXTRA_FILENAME,
                ", ".join(str(p) for p in ignored), OVERRIDE_FILENAME, EXTRA_FILENAME,
            )
    return override, extra, loaded


def _rules_cached() -> tuple[dict[str, list[dict]], dict[str, list[dict]]]:
    """带指纹缓存地扫描规则目录（文件 mtime/size 或 env 变化即重扫）。

    cold / builtin 模式：首次扫描后**冻结**，运行中改规则目录不重扫（重启才生效）。
    """
    global _RULES_CACHE
    if not is_hot_reload_enabled() and _RULES_CACHE is not None:
        return _RULES_CACHE[2], _RULES_CACHE[3]
    dirs = rules_dirs()
    sig = "|".join(f"{env}={os.environ.get(env, '')}" for env in RULES_DIR_ENVS) + "|" + "|".join(str(d) for d in dirs)
    files: list[Path] = []
    for d in dirs:
        if d.is_dir():
            files.extend(sorted(d.glob("*.json")))
    fp = tuple(
        (str(p), st.st_mtime_ns, st.st_size) if st is not None else (str(p), -1, -1)
        for p in files
        for st in [_safe_stat(p)]
    )
    if _RULES_CACHE is not None and _RULES_CACHE[0] == sig and _RULES_CACHE[1] == fp:
        return _RULES_CACHE[2], _RULES_CACHE[3]
    override, extra, loaded = _scan_rule_dirs()
    _RULES_CACHE = (sig, fp, override, extra, loaded["override"] + loaded["extra"], loaded["ignored"])
    return override, extra


def _identical_to_builtin(override: dict[str, list[dict]]) -> bool:
    """override.json 的每个类别是否都与内置**逐条相同**（判"模板没改"）。"""
    l1 = load_l1()
    l2 = load_l2()
    for cat, items in override.items():
        builtin = l1.get(cat) if cat in l1 else l2.get(cat)
        if not isinstance(builtin, list) or len(builtin) != len(items):
            return False
        try:
            if json.dumps(builtin, sort_keys=True, ensure_ascii=False) != \
                    json.dumps(items, sort_keys=True, ensure_ascii=False):
                return False
        except (TypeError, ValueError):
            return False
    return bool(override)


def load_override_rules() -> dict[str, list[dict]]:
    """规则目录里的 ``override.json``：``{类别键: [条目...]}``（**整份替换**语义）。

    未提供该文件时返回空 dict（= 不覆盖任何类别）。类别值为空数组表示
    "该类别清空"（不是"未覆盖"）—— 部署侧显式写下空数组才生效。
    """
    if is_builtin_only():
        return {}
    return _rules_cached()[0]


def load_extra_rules() -> dict[str, list[dict]]:
    """规则目录里的 ``extra.json``：``{类别键: [条目...]}``（**追加**语义）。"""
    if is_builtin_only():
        return {}
    return _rules_cached()[1]


def rule_files_loaded() -> list[Path]:
    """**成功加载**的规则文件清单（override.json / extra.json），供启动自检。"""
    _rules_cached()
    return list(_RULES_CACHE[4]) if _RULES_CACHE else []


def ignored_rule_files() -> list[Path]:
    """规则目录里**不会被读取**的 json（除那两个固定名之外的全部），供启动自检。"""
    _rules_cached()
    return list(_RULES_CACHE[5]) if _RULES_CACHE else []


def clear_rules_cache() -> None:
    """清空规则目录缓存（测试用；运行时靠指纹自动失效）。"""
    global _RULES_CACHE
    _RULES_CACHE = None
    # 仅内置模式的包内 JSON 冻结缓存也要能清（测试切换模式时用；生产不调用）。
    _JSON_CACHE.clear()


def _safe_stat(p: Path):
    try:
        return p.stat()
    except OSError:
        return None
