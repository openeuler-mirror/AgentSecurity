"""规则包契约 —— schema 版本 / 完整性校验 / 内容指纹。

**为什么要有这层**：规则仓独立出去之后，规则包是可以被客户替换、也可以被改坏的
外部输入。没有契约时，"规则文件缺了一类"的后果是那一类规则**静默为空** ——
引擎照常启动、照常放行，看起来一切正常，实际上是防护面少了一块（fail-open）。

所以这里做三件事：
1. **schema 版本**：引擎声明自己认识的版本，规则包在 `manifest.json` 里声明自己是哪个
   版本。对不上就明确报错，而不是"能读就读、读不懂就当空"。
2. **完整性**：引擎在代码里声明"我需要哪几个文件、每个文件必须有哪几个顶层键"
   （引擎知道自己要什么，所以期望写在引擎侧；规则包只负责声明版本）。
3. **内容指纹**：把所有规则文件的 sha256 汇总成一个短指纹，启动时打印 —— 客户报问题时
   一句"指纹是多少"就能确定跑的是哪一份规则。

**致命 vs 告警**：
- 设了 `AGENT_MOSS_RULES_ROOT`（客户显式指定了自家规则包）→ 校验失败**拒绝启动**；
- 未设（用包内自带规则）→ 只记 error 日志、照常启动（包坏了是打包事故，但把已经
  装好的引擎直接弄挂更糟；日志里能看见）。

与规则文件格式有关的只有"规则文件长什么样"，此模块本身是 Python 侧的实现。
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .infra.paths import asset_dir, get_rules_root

logger = logging.getLogger(__name__)

#: 当前引擎认识的规则包 schema 版本。规则包结构有**破坏性**变更时才 +1。
#: 纯新增文件 / 新增可选键不需要动它。
RULES_SCHEMA_VERSION = 1

#: 规则包必须包含的文件 → 该文件必须存在的顶层键。
#: 键列表为 `[]` 表示"文件必须在，但顶层结构不固定"（如 l3 是 category 字典）。
REQUIRED_RULE_FILES: dict[str, list[str]] = {
    "l1_rules.json": ["dangerous_commands", "injection_detection", "sensitive_path_access"],
    "l2_rules.json": ["intent_consistency", "password_modify_consent", "user_deletion_consent"],
    "l3_rules.json": [],
    "mc_rules.json": ["rules", "ap_patterns"],
    "tool_registry.json": ["tools"],
    "platform_traits.json": ["linux", "windows"],
    "inline_rules.json": ["read_write_keywords", "dir_traversal_keywords", "write_exec_chain_patterns"],
    "script_rules.json": [
        "suspicious_patterns", "keyword_combination_risks", "single_keyword_risks",
        "script_exec_patterns",
    ],
    "heuristic_rules.json": [
        "sensitive_excluded_prefixes", "search_action_prefixes",
        "loopback_hosts", "temp_dirs",
    ],
    "logic_rules.json": ["indirect_file_access", "write_commands", "source_arg_commands"],
    "formal_rules.json": ["privesc", "compute_action_types", "pattern_miner", "output_commands"],
}

#: 规则包里必须存在的顶层键（manifest）。
MANIFEST_FILE = "manifest.json"


@dataclass
class RulesIntegrityReport:
    """规则包校验结果。"""

    ok: bool = True
    schema_version: int = 0
    fingerprint: str = ""
    #: 文件名 → 短 sha256（缺失为 "MISSING"，解析失败为 "BADJSON"）
    file_hashes: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    #: 是否来自包外（AGENT_MOSS_RULES_ROOT）
    external: bool = False


def _sha256_short(data: bytes, n: int = 12) -> str:
    return hashlib.sha256(data).hexdigest()[:n]


def check_rules_assets() -> RulesIntegrityReport:
    """校验整套规则资产，返回报告（不抛异常、不改任何状态）。

    调用方（启动入口）根据 `report.ok` 与 `report.external` 决定是打印告警还是拒绝启动。
    """
    rep = RulesIntegrityReport(external=get_rules_root() is not None)
    rules_dir = asset_dir("rules")

    # ── manifest：schema 版本 ──
    manifest_path = rules_dir / MANIFEST_FILE
    manifest: dict[str, Any] = {}
    if not manifest_path.is_file():
        rep.errors.append(f"缺少 {MANIFEST_FILE}（规则包必须声明 schema 版本）")
    else:
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8")) or {}
        except (json.JSONDecodeError, OSError) as e:
            rep.errors.append(f"{MANIFEST_FILE} 读取/解析失败: {e}")
        else:
            ver = manifest.get("schema_version")
            if not isinstance(ver, int):
                rep.errors.append(f"{MANIFEST_FILE} 缺少整数 schema_version")
            else:
                rep.schema_version = ver
                if ver != RULES_SCHEMA_VERSION:
                    rep.errors.append(
                        f"schema 版本不匹配：规则包是 {ver}，本引擎认识 {RULES_SCHEMA_VERSION}。"
                        "请升级引擎或改用对应版本的规则包。"
                    )

    # ── 逐文件：存在性 + 可解析 + 必有键 ──
    fp_parts: list[str] = []
    for name, required_keys in REQUIRED_RULE_FILES.items():
        p = rules_dir / name
        if not p.is_file():
            rep.errors.append(f"缺少规则文件 {name}")
            rep.file_hashes[name] = "MISSING"
            fp_parts.append(f"{name}:MISSING")
            continue
        try:
            raw = p.read_bytes()
        except OSError as e:
            rep.errors.append(f"{name} 读取失败: {e}")
            rep.file_hashes[name] = "UNREADABLE"
            fp_parts.append(f"{name}:UNREADABLE")
            continue
        rep.file_hashes[name] = _sha256_short(raw)
        fp_parts.append(f"{name}:{rep.file_hashes[name]}")
        try:
            data = json.loads(raw.decode("utf-8")) or {}
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            rep.errors.append(f"{name} 解析失败: {e}")
            rep.file_hashes[name] = "BADJSON"
            continue
        if not isinstance(data, dict):
            rep.errors.append(f"{name} 顶层必须是 JSON 对象")
            continue
        missing = [k for k in required_keys if k not in data]
        if missing:
            rep.errors.append(f"{name} 缺少顶层键: {', '.join(missing)}")

    rep.fingerprint = _sha256_short("\n".join(sorted(fp_parts)).encode("utf-8"))
    rep.ok = not rep.errors
    return rep


def format_rules_integrity(rep: RulesIntegrityReport) -> str:
    """一行式摘要（启动时打印）：来源 + schema + 指纹 + 错误数。"""
    src = f"外部规则包 {get_rules_root()}" if rep.external else "包内规则"
    head = (
        f"规则包: {src} | schema v{rep.schema_version} | 指纹 {rep.fingerprint or '-'}"
    )
    if rep.ok:
        return head
    return head + f" | ❌ {len(rep.errors)} 个问题: " + "；".join(rep.errors[:5])


def enforce_rules_contract() -> RulesIntegrityReport:
    """启动入口调用：校验 + 打日志；显式指定了外部规则包且校验失败时**抛异常**。

    `AGENT_MOSS_RULES_ROOT` 是客户显式声明的"我要用这套规则"，坏了必须立刻停 ——
    带着残缺规则跑起来 = 静默放开一批防护。
    """
    rep = check_rules_assets()
    if rep.ok:
        logger.info(format_rules_integrity(rep))
        return rep
    msg = format_rules_integrity(rep)
    if rep.external:
        logger.error("❌ " + msg)
        raise RuntimeError(
            "规则包校验失败，拒绝启动（AGENT_MOSS_RULES_ROOT 已显式指定，"
            "不允许带着残缺规则运行）：" + "；".join(rep.errors)
        )
    logger.error("⚠️  " + msg + "（使用包内规则，照常启动；若是 pip 安装请重装）")
    return rep
