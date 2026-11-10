"""Brain 规则/Skill 提取器 — 从 Layer 3 LLM 分析结果中沉淀知识

当 Layer 3 LLM 返回 Deny 且置信度足够高时，提取可复用的模式：
- 静态规则（BrainRule）→ 融入 Layer 1/2
- Skill（BrainSkill）→ 写入 skills/ 供 Layer 3 使用

提取前做去重检查：若 pattern 已被内置规则（profile dangerous_commands /
sensitive_paths / runtime_config L1 规则）覆盖，则跳过，避免冗余沉底。
"""

import logging
import re
from dataclasses import dataclass, field

from .rule_store import BrainRule, BrainRuleStore
from .skill_manager import BrainSkill, BrainSkillManager

logger = logging.getLogger(__name__)


@dataclass
class ExtractionResult:
    """提取结果"""
    rules_created: int = 0
    skills_created: int = 0
    patterns_recorded: int = 0
    skipped_reason: str = ""
    deduped: list[str] = field(default_factory=list)  # 与内置规则重复被跳过的 pattern


class PatternExtractor:
    """从 Layer 3 LLM Deny 结果中提取可沉淀的规则和 Skill"""

    def __init__(
        self,
        rule_store: BrainRuleStore,
        skill_manager: BrainSkillManager,
        min_confidence: float = 0.9,
        min_occurrences: int = 3,
        builtin_patterns: list[str] | None = None,
        reviewer=None,
    ):
        self._rule_store = rule_store
        self._skill_manager = skill_manager
        self._min_confidence = min_confidence
        self._min_occurrences = min_occurrences
        # 内置规则正则列表（dangerous_commands 的 pattern + sensitive_paths 的 deny 路径）。
        # 提取前若新 pattern 与内置规则重叠 → 跳过（避免与 L1/L2 重复的冗余规则）。
        self._builtin_patterns = builtin_patterns or []
        # LLC LLM 审核器：候选达到阈值后判定是否值得沉淀。None = 不启用审核（兼容旧行为）。
        self._reviewer = reviewer

    def extract(
        self,
        event: dict,
        llm_result: dict,
    ) -> ExtractionResult:
        """
        从 LLM 分析结果中提取规则和 Skill。

        Args:
            event: 原始事件数据
            llm_result: LLM 分析结果，需包含:
                - confidence: float
                - reason: str
                - risk_type: str
                - action_detail: str
                - event_id: str (可选)

        Returns:
            ExtractionResult
        """
        result = ExtractionResult()

        confidence = llm_result.get("confidence", 0)
        reason = llm_result.get("reason", "")
        risk_type = llm_result.get("risk_type", "")
        action_detail = llm_result.get("action_detail", event.get("action_detail", ""))
        event_id = llm_result.get("event_id", event.get("event_id", ""))

        # 置信度门槛
        if confidence < self._min_confidence:
            result.skipped_reason = f"confidence {confidence} < {self._min_confidence}"
            logger.debug("Brain 提取跳过: %s", result.skipped_reason)
            return result

        # 提取 pattern
        patterns = self._extract_patterns(action_detail, reason, risk_type)
        if not patterns:
            result.skipped_reason = "no extractable pattern"
            return result

        for pattern_info in patterns:
            pattern = pattern_info["pattern"]
            layer = pattern_info["layer"]
            scope = pattern_info["scope"]
            rule_type = pattern_info["rule_type"]

            # 去重：原始 action_detail 已被内置规则命中 → 这条 pattern 是 L1/L2
            # 已在生效的重复项，跳过（避免与内置规则重复的冗余规则）。
            if self._is_covered_by_builtin(action_detail):
                result.deduped.append(pattern)
                logger.debug("Brain 提取跳过（内置规则已覆盖）: %s", pattern)
                continue

            # 记录到 pattern_candidates
            count = self._rule_store.add_pattern_candidate(
                pattern=pattern,
                layer=layer,
                scope=scope,
                source_event_id=event_id,
                confidence=confidence,
            )
            if count == 0:
                # 已审核拒绝的 pattern：永久排除，不再记录
                result.deduped.append(pattern)
                continue
            result.patterns_recorded += 1

            # 达到阈值 → LLM 审核 → 通过则生成 draft 规则
            if count >= self._min_occurrences:
                candidates = self._rule_store.get_pattern_candidates(self._min_occurrences)
                matched = [c for c in candidates if c["pattern"] == pattern and c["layer"] == layer]
                if matched:
                    candidate = matched[0]
                    # LLM 审核（可选）：判定该 pattern 是否值得沉淀
                    if self._reviewer is not None:
                        review = self._reviewer.review(
                            pattern=pattern,
                            layer=layer,
                            rule_type=rule_type,
                            action_detail=action_detail,
                            reason=reason,
                        )
                        if review is None:
                            # LLM 不可用/失败：降级为"不沉淀也不排除"（保留候选，下次再试）
                            logger.debug(
                                "Brain 审核降级（LLM 不可用），保留候选: %s", pattern
                            )
                            continue
                        if not review.should_keep:
                            # 审核拒绝 → 永久排除
                            self._rule_store.set_pattern_review_status(
                                pattern, layer, scope,
                                "rejected", review.reason or "LLM 审核拒绝",
                            )
                            result.deduped.append(pattern)
                            logger.info(
                                "Brain 候选被 LLM 审核拒绝（永久排除）: %s - %s",
                                pattern, review.reason,
                            )
                            continue
                        # 审核通过 → 沉淀
                        self._rule_store.set_pattern_review_status(
                            pattern, layer, scope,
                            "approved", review.reason or "LLM 审核通过",
                        )
                    rule = BrainRule(
                        layer=layer,
                        rule_type=rule_type,
                        pattern=pattern,
                        scope=scope,
                        source="llm_extracted",
                        source_event_ids=event_id.split(",") if event_id else [],
                        confidence=candidate["confidence"],
                        status="draft",
                        explanation=f"从 {count} 次 LLM Deny 中提取(经审核): {reason[:200]}",
                    )
                    self._rule_store.add_rule(rule)
                    self._rule_store.remove_pattern_candidate(pattern, layer, scope)
                    result.rules_created += 1
                    logger.info("Brain 规则已创建: pattern=%s, layer=%d, count=%d", pattern, layer, count)

        # 提取 Skill（如果分析过程包含有价值的判断逻辑）
        skill = self._extract_skill(action_detail, reason, risk_type, event_id, confidence)
        if skill:
            self._skill_manager.add_skill(skill)
            result.skills_created += 1
            logger.info("Brain Skill 已创建: name=%s", skill.name)

        return result

    def _extract_patterns(self, action_detail: str, reason: str, risk_type: str) -> list[dict]:
        """从事件中提取可泛化的模式"""
        patterns = []
        detail_lower = action_detail.lower()

        # --- Layer 1 类型：路径模式（只看当前 action） ---
        # 敏感文件路径：覆盖 /etc/ 凭据+系统配置、/root/ 特权、.ssh/ 密钥、
        # .aws/ 云凭据、关键私钥文件（.pem/.key/.p12/.pfx）。
        # 旧正则只匹配 /etc/ 下 6 个名字，/root/.ssh/id_rsa 这类高频敏感路径
        # 完全漏掉 → 提取不到 pattern → brain 空转。统一用宽路径捕获 + generalize。
        sensitive_paths = re.findall(
            r'(/(?:etc|root)(?:/[^\s;|&"\'<>`$]*)?|'
            r'(?:[^\s;|&"\'<>`$]*)?/\.ssh/[^\s;|&"\'<>`$]*|'
            r'(?:[^\s;|&"\'<>`$]*)?/\.aws/[^\s;|&"\'<>`$]*|'
            r'\S+\.(?:pem|key|p12|pfx|id_rsa|authorized_keys)\b)',
            detail_lower,
        )
        for path in sensitive_paths:
            patterns.append({
                "pattern": self._generalize_path(path),
                "layer": 1,
                "scope": "openat",
                "rule_type": "deny_path",
            })

        # --- Layer 1 类型：命令模式 ---
        dangerous_cmds = re.findall(
            r'\b(rm\s+-[a-zA-Z]*r[a-zA-Z]*f|rm\s+--recursive|chmod\s+777|'
            r'curl\s+[^\|]*\|\s*(?:ba)?sh|wget\s+[^\|]*\|\s*(?:ba)?sh|'
            r'mkfs\.|dd\s+if=|>\s*/dev/sd)\b',
            detail_lower,
        )
        for cmd in dangerous_cmds:
            patterns.append({
                "pattern": self._generalize_command(cmd),
                "layer": 1,
                "scope": "execve",
                "rule_type": "deny_command",
            })

        # --- Layer 2 类型：行为链模式（需要 history 上下文） ---
        # 数据注入模式：读外部 → 写敏感位置
        if "inject" in reason.lower() or "数据注入" in reason:
            patterns.append({
                "pattern": self._generalize_behavior("inject_external_to_sensitive", detail_lower),
                "layer": 2,
                "scope": "all",
                "rule_type": "deny_pattern",
            })

        # 提权侦察模式
        if "reconnaissance" in reason.lower() or "侦察" in reason or "提权" in reason:
            patterns.append({
                "pattern": self._generalize_behavior("privilege_recon", detail_lower),
                "layer": 2,
                "scope": "all",
                "rule_type": "deny_pattern",
            })

        # --- Layer 1 类型：从 reason 提取未被内置规则覆盖的新敏感路径 ---
        # LLM 的 reason 会描述"为什么危险"（如 "accessing API secrets in /opt/app/keys"），
        # 其中出现的绝对路径是"LLM 判定为敏感"的信号。将这些路径提取出来，
        # 由去重过滤掉内置规则已覆盖的，剩下的就是 L1/L2 的盲区 → 值得沉淀。
        # 不做字符匹配（可信特征），而做候选制：新路径进 pattern_candidates，
        # 达到 min_occurrences 才沉淀为 draft 规则，避免单次幻觉路径污染。
        seen = {p["pattern"] for p in patterns}  # 去重：避免 detail/reason 重复提取
        # 前缀：空白、引号、左括号、= （URL query 参数如 src=/path）
        # 后缀：空白、引号、右括号、中英文标点、行尾
        _path_prefix = '(?:^|[\\s"\'(=])'
        _path_body = '(/(?:[a-zA-Z0-9_.-]+/)+[a-zA-Z0-9_.-]+)'
        _path_suffix = '(?=[\\s"\')，。）；;]|$)'
        for src in (detail_lower, reason.lower()):
            for path in re.findall(
                _path_prefix + _path_body + _path_suffix,
                src,
            ):
                # 只接受绝对路径（含至少两级目录），排除 /dev/null 等标准路径
                if path.count("/") < 2:
                    continue
                if path in ("/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"):
                    continue
                generalized = self._generalize_path(path)
                if generalized in seen:
                    continue
                seen.add(generalized)
                patterns.append({
                    "pattern": generalized,
                    "layer": 1,
                    "scope": "openat",
                    "rule_type": "deny_path",
                })

        return patterns

    def _is_covered_by_builtin(self, action_detail: str) -> bool:
        """判断原始 action_detail 是否已被内置规则命中（去重）。

        内置规则来源：profile.dangerous_commands 的 pattern + sensitive_paths deny
        路径 + runtime_config L1 命令规则。用内置规则的正则匹配原始 action_detail，
        命中即视为已覆盖——该次 LLM Deny 的案例 L1/L2 本来就能拦，无需重复沉淀。
        """
        if not self._builtin_patterns or not action_detail:
            return False
        for builtin_pat in self._builtin_patterns:
            try:
                if re.search(builtin_pat, action_detail, re.IGNORECASE):
                    return True
            except re.error:
                continue
        return False

    def _generalize_path(self, path: str) -> str:
        """将具体路径泛化为正则（无 ^ 锚定）

        注意：coordinator 匹配时是 combined = f"{action_type} {action_detail}" +
        re.search。带 ^ 锚定的 pattern（如 ^/etc/shadow）在 combined 开头是
        action_type（如 "bash cat /etc/shadow"）时永远匹配不到——这是既有 bug
        （DB 里唯一 active 规则 trigger_count=0 的铁证）。故统一用
        (?:^|[^a-z0-9]) 边界形式，保证在拼接文本任意位置都能命中。
        """
        p = path.lower()
        # /etc/shadow、/etc/passwd → (?:^|[^a-z0-9_-])etc/(shadow|...)
        if re.search(r"/etc/(shadow|passwd|sudoers|security|ssh)", p):
            return r"(?:^|[^a-z0-9_-])etc/(?:shadow|passwd|sudoers|security/|ssh/)"
        # /etc/ 其他系统配置（如 /etc/crontab、/etc/fstab）→ 泛化为 etc 目录
        if "/etc/" in p:
            return r"(?:^|[^a-z0-9_-])etc/"
        # /root/.ssh/、/root/.aws/ → 泛化为 root 下隐私目录
        if "/root/" in p:
            return r"(?:^|[^a-z0-9_-])root/\.(?:ssh|gnupg|aws|config)/"
        # 任意路径下的 .ssh / .aws → 泛化
        if ".ssh/" in p:
            return r"(?:^|[^a-z0-9_-])[\w./-]*/\.ssh/"
        if ".aws/" in p:
            return r"(?:^|[^a-z0-9_-])[\w./-]*/\.aws/"
        # 私钥/凭据文件扩展名
        if re.search(r"\.(pem|key|p12|pfx|id_rsa|authorized_keys)\b", p):
            return r"[\w./-]*\.(?:pem|key|p12|pfx|id_rsa|authorized_keys)(?:$|[^a-z0-9])"
        escaped = re.escape(p.lstrip("/"))
        # 目录路径：尾部加 (?:/|\\b)，避免 keys2 误匹配 keys
        return rf"(?:^|[^a-z0-9_-]){escaped}(?:/|\b)"

    def _generalize_command(self, cmd: str) -> str:
        """将具体命令泛化为正则（无 ^ 锚定）"""
        if "rm" in cmd and ("r" in cmd and "f" in cmd):
            return r"rm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f|--recursive)\s+/"
        if "chmod" in cmd:
            return r"chmod\s+777"
        if "curl" in cmd or "wget" in cmd:
            return r"(?:curl|wget)\s+[^\|]*\|\s*(?:ba)?sh"
        if "mkfs" in cmd:
            return r"mkfs\."
        if "dd" in cmd:
            return r"dd\s+if="
        return re.escape(cmd)

    def _generalize_behavior(self, behavior_type: str, detail: str) -> str:
        """泛化行为链模式"""
        if behavior_type == "inject_external_to_sensitive":
            return r"BEHAVIOR_CHAIN:external_read→sensitive_write"
        if behavior_type == "privilege_recon":
            return r"BEHAVIOR_CHAIN:multi_config_read→privilege_action"
        return f"BEHAVIOR_CHAIN:{behavior_type}"

    def _extract_skill(
        self, action_detail: str, reason: str, risk_type: str,
        event_id: str, confidence: float,
    ) -> BrainSkill | None:
        """从 LLM 分析中提取 Skill（如果判断逻辑有复用价值）"""
        # 价值评估 1：只有包含明确判断逻辑的结果才值得沉淀为 Skill
        if not reason or len(reason) < 50:
            return None

        # 生成 Skill 名称
        skill_name = self._generate_skill_name(risk_type, action_detail)
        if not skill_name:
            return None

        # 价值评估 2：已存在同名 Skill（meta_db 或磁盘已有）→ 跳过
        existing = self._skill_manager.get_skill_meta(skill_name)
        if existing:
            return None

        # 生成 Skill 内容
        content = self._generate_skill_content(skill_name, action_detail, reason, risk_type)
        keywords = self._extract_keywords(action_detail, reason, risk_type)

        # 价值评估 3：与内置 skill 高度相似（同 risk_type + 关键词重叠）→ 跳过。
        # 防止"同类案例每次生成一个近乎重复的 skill"（如 cat /etc/shadow 与
        # cat /etc/sudoers 生成两个 90% 重复的 brain_file_access_* skill）。
        if self._is_covered_by_existing_skill(risk_type, keywords):
            logger.debug("Brain Skill 跳过写入（与已有 skill 高度相似）: %s", skill_name)
            return None

        return BrainSkill(
            name=skill_name,
            category=self._categorize_risk(risk_type),
            content=content,
            keywords=keywords,
            source_event_ids=[event_id] if event_id else [],
            status="active",  # Skill 默认直接激活（不像规则需要审核）
        )

    def _is_covered_by_existing_skill(self, risk_type: str, keywords: list[str]) -> bool:
        """检查候选 skill 是否与已有 skill（内置 + brain）高度相似。

        相似判定：已有 skill 的 keywords 与候选 keywords 重叠 >= 2 个，
        且（risk_type 相同 或 关键词含 guard 系列通用词）。
        """
        if not risk_type or not keywords:
            return False
        try:
            existing_skills = self._skill_manager.get_active_skills()
        except Exception:
            existing_skills = []
        for meta in existing_skills:
            meta_keywords = meta.get("keywords") or []
            if isinstance(meta_keywords, str):
                try:
                    import json
                    meta_keywords = json.loads(meta_keywords)
                except Exception:
                    meta_keywords = []
            if not meta_keywords:
                continue
            overlap = len(set(k.lower() for k in keywords) & set(k.lower() for k in meta_keywords))
            if overlap >= 2:
                return True
        return False

    def _generate_skill_name(self, risk_type: str, action_detail: str) -> str:
        """生成 Skill 文件名"""
        if not risk_type:
            return ""
        # 简化：用 risk_type + 关键特征
        detail_words = re.findall(r'[a-z]+', action_detail.lower())[:3]
        if detail_words:
            return f"brain_{risk_type}_{'_'.join(detail_words)}"
        return f"brain_{risk_type}"

    def _generate_skill_content(self, name: str, action_detail: str, reason: str, risk_type: str) -> str:
        """生成 Skill Markdown 内容"""
        return f"""# {name}

## 来源
Brain 自动提取（LLM 分析沉淀）

## 场景
当 Agent 执行以下类型操作时触发：
- 风险类型: {risk_type}
- 操作特征: {action_detail[:200]}

## 判断依据
{reason[:500]}

## 处理建议
- 优先检查操作的上下文和意图
- 结合 action_history 判断是否存在恶意链
- 必要时 Deny 并记录原因
"""

    def _extract_keywords(self, action_detail: str, reason: str, risk_type: str) -> list[str]:
        """从内容中提取关键词，用于 SKILL_KEYWORD_MAP"""
        keywords = set()
        # 风险类型
        if risk_type:
            keywords.add(risk_type)
        # 从 action_detail 提取关键词
        words = re.findall(r'[a-z_]{3,}', action_detail.lower())
        keywords.update(words[:10])
        # 从 reason 提取关键词
        words = re.findall(r'[a-z_]{3,}', reason.lower())
        keywords.update(words[:5])
        return list(keywords)

    def _categorize_risk(self, risk_type: str) -> str:
        """风险类型 → Skill 分类"""
        if not risk_type:
            return "edge_case"
        if any(k in risk_type for k in ["inject", "backdoor", "persist"]):
            return "attack_pattern"
        if any(k in risk_type for k in ["exfil", "leak", "export"]):
            return "attack_pattern"
        return "defense_strategy"
