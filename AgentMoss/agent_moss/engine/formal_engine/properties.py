"""形式化引擎 — 安全性质定义（安全不变量）

性质 = 对行为图的验证断言（LTL/CTL 风格的工程化表达）。每类性质实现
一个 `check(graph) -> list[PropertyViolation]`。

当前内置性质（对应 L2 方案中依赖行为图/数据流的 B/C 类）：
- **P1 跨会话组合链**（B 类）：阶段子序列匹配作用于多 session 拼接图——
  LISTEN→EXEC→SCAN 等链可以跨 session 出现（session A 建监听、session B
  加执行、session C 扫描），单 session 各自无害。
- **P2 敏感数据传播**（C 类）：沿 data 边做 taint 传播——CRED 阶段访问的
  凭据文件（如 ~/.ssh、/etc/shadow、known_hosts）被后续动作经共享文件
  载体传递到 EXFIL 动作 = 数据外传链。

fail-closed：阶段标记/资源提取无法确认时按"已发生"保守处理；
性质验证对任何"可能违反"路径即报反例（宁可多拦，不可漏）。
"""

import re
from dataclasses import dataclass, field
from typing import Callable

from .decode import strip_string_literals
from .ir import MultiSessionGraph, PropertyViolation
from .ltl import check_mc_rules

# ==================== P1 跨会话组合链 ====================

# 跨会话链定义：复用 l2_rules.json combo_chains.chains（单一事实源，与 L2
# 会话内组合链同定义），但子序列匹配作用于多 session 拼接图——阶段可跨
# session 推进（session A 建监听、session B 加执行、session C 扫描），
# 单 session 各自无害、拼接成链才是攻击。
def _load_cross_session_chains() -> list[dict]:
    """加载 L2 combo_chains 链定义（幂等，跨会话版共用同一份）。"""
    from ...rules_loader import load_l2
    combo = load_l2().get("combo_chains", {})
    return [
        {
            "id": str(c.get("id", "combo_chain")),
            "stages": list(c.get("stages", [])),
            "risk_level": str(c.get("risk_level", "high")),
            "reason": "跨会话" + str(c.get("reason", "组合攻击链")),
        }
        for c in combo.get("chains", [])
    ]


CROSS_SESSION_CHAINS: list[dict] = _load_cross_session_chains()

# 凭据文件特征（P2 用：被 CRED 阶段访问过的文件视为 taint 源）
_CRED_FILE_RE = re.compile(r"(known_hosts|\.ssh|id_rsa|/etc/shadow|/etc/passwd|credentials)", re.IGNORECASE)
# 严格凭据判定（P3/P4 用）：仅真实凭据文件/路径，避免把项目配置 credentials.yml 当凭据
_CRED_STRICT_RE = re.compile(
    r"(known_hosts|\.ssh|id_rsa|\.pem|\b\.key\b|/etc/shadow|/etc/passwd|"
    r"\.aws/credentials|credentials\.json|netrc|password|secret(s)?\.ya?ml|"
    r"credential(s)?\s*(file|path)?\s*(=|:)|\bconfig.*(password|token))",
    re.IGNORECASE,
)
# 外传动作特征（P2/P4/P5 用：EXFIL 阶段或网络外发形态）。
# http(s) 排除回环地址（对齐 l2_rules.json 的 EXFIL stage），避免 curl 127.0.0.1/
# localhost 健康检查被误判为外传。
_EXFIL_RE = re.compile(
    r"https?://(?!127\.\d+\.\d+\.\d+|0\.0\.0\.0|localhost|\[?::1\]?)[^\s]+"
    r"|\bscp\s+.*@|\brsync\s+.*@",
    re.IGNORECASE,
)
# 主动外传动词（命令本身在执行外传，而非文档/heredoc 内容里提到 URL）
_EXFIL_ACTION_RE = re.compile(
    r"\bcurl\b|\bwget\b|\bscp\b|\brsync\b|\brclone\b|\bftp\b|"
    r"connect\s+.*\d+\.\d+\.\d+\.\d+|open\s+.*tcp|base64\s+.*-o",
    re.IGNORECASE,
)


def check_cross_session_chain(graph: MultiSessionGraph) -> list[PropertyViolation]:
    """P1：跨会话组合链 — 阶段子序列匹配作用于拼接图。

    与 L2 的会话内子序列匹配同算法，但 nodes 来自多个 session 拼接，
    阶段可跨 session 推进（这正是多 session 组合攻击的检测点）。

    witness 语义（graph.witness_idx 非 None，实时判定）：
      只当**当前动作（a_next = 图末节点）补全链的最后阶段**时才判违规——
      历史中已随机出现的完整链不再影响后续良性动作（修复"历史全局匹配 →
      永久拒绝锁定"FP，见 docs/DETECTION_METHODS.md 六.3；对齐站点 L2.2
      "仅当当前事件属于 violation witness 时才返回 block"）。
    witness_idx 为 None（低频回顾 /api/v1/review 全量历史）时保留原行为：
      报告历史中已形成的任何完整链。
    """
    violations: list[PropertyViolation] = []
    nodes = graph.all_nodes
    if not nodes:
        return violations
    witness = graph.witness_idx

    for chain in CROSS_SESSION_CHAINS:
        stages = chain["stages"]
        if not stages:
            continue

        if witness is not None:
            # —— 实时判定（witness）：链的最后阶段必须由当前动作命中 ——
            if nodes[witness].stage != stages[-1]:
                continue
            # 前序 stages[:-1] 按序出现在 witness 之前（贪心子序列）
            matched = 0
            path: list = []
            for n in nodes[:witness]:
                if matched < len(stages) - 1 and n.stage == stages[matched]:
                    matched += 1
                    path.append((n.session_id, n.seq, n.action_detail[:60]))
            if matched < len(stages) - 1:
                continue
            path.append((nodes[witness].session_id, nodes[witness].seq, nodes[witness].action_detail[:60]))
            violations.append(PropertyViolation(
                property_id="cross-" + chain["id"],
                reason=chain["reason"],
                risk_level=chain["risk_level"],
                path=path,
            ))
            return violations  # 命中即停（与 L2 短路语义一致）
        else:
            # —— 低频回顾（witness_idx=None）：全历史贪心子序列匹配 ——
            matched = 0
            stage_idx = 0
            path = []
            for n in nodes:
                if stage_idx < len(stages) and n.stage == stages[stage_idx]:
                    matched += 1
                    path.append((n.session_id, n.seq, n.action_detail[:60]))
                    stage_idx += 1
                    if matched >= len(stages):
                        break
            if matched >= len(stages):
                violations.append(PropertyViolation(
                    property_id="cross-" + chain["id"],
                    reason=chain["reason"],
                    risk_level=chain["risk_level"],
                    path=path,
                ))
    return violations


def check_sensitive_data_flow(graph: MultiSessionGraph) -> list[PropertyViolation]:
    """P2：敏感数据传播 — 沿 data 边 taint 传播。

    规则：
    1. 标记 taint 源：CRED 阶段动作访问的凭据类文件（.ssh/known_hosts/shadow...）。
    2. 沿 data 边（共享资源）传播 taint：任何动作的资源与 taint 源资源
       相交（同一文件/载体）→ 该动作获得 taint 标签。
    3. 若 tainted 动作同时是 EXFIL 形态（网络外发/远程拷贝）→ 违反
       "凭据数据不得经共享载体外传" 性质。

    模拟数据流分析（前向 taint），O(节点 × 边)，无状态爆炸。

    witness 语义（graph.witness_idx 非 None，实时判定）：只当**当前动作
    （a_next = 图末节点）**是 tainted 且 EXFIL 才判违规——历史中已发生的
    凭据外传不再误伤后续良性动作；None（低频回顾）时检查全部 tainted 外传。
    """
    violations: list[PropertyViolation] = []
    nodes = graph.all_nodes
    if not nodes:
        return violations

    # taint: node_idx -> 来源描述
    tainted: dict[int, str] = {}
    for i, n in enumerate(nodes):
        if n.stage == "CRED" and any(_CRED_FILE_RE.search(r) for r in n.resources):
            tainted[i] = f"{n.session_id}#{n.seq} 访问 {sorted(n.resources)[0]}"

    if not tainted:
        return violations

    # 前向传播（迭代直到收敛；图小，线性可接受）
    changed = True
    while changed:
        changed = False
        for e in graph.all_edges:
            if e.src in tainted and e.dst not in tainted:
                src_res = nodes[e.src].resources
                dst_res = nodes[e.dst].resources
                if src_res & dst_res:  # 共享资源 → 传播
                    tainted[e.dst] = tainted[e.src]
                    changed = True

    witness = graph.witness_idx
    # 检查 tainted 动作是否外传（witness 语义：只查当前动作；回顾：查全部）
    candidates = [witness] if witness is not None else [i for i in range(len(nodes))]
    for i in candidates:
        n = nodes[i]
        if i in tainted and _EXFIL_RE.search(n.action_detail):
            violations.append(PropertyViolation(
                property_id="sensitive-data-flow",
                reason=f"敏感数据传播外传：{tainted[i]} → {n.session_id}#{n.seq} 经共享载体外发",
                risk_level="critical",
                path=[(n.session_id, n.seq, n.action_detail[:60])],
            ))
            if witness is not None:
                return violations  # 实时判定命中即停
    return violations


# ==================== P3/P4 抽象性质（LTL 风格，独立于预置链序） ====================

# eBPF 证据：真实网络外发（connect/sendto 会话本身）也视为 EXFIL。
_EBPF_NET_RE = re.compile(r"connect|sendto|network_connect", re.IGNORECASE)
_REMOTE_RE = re.compile(r"to\s+\d+\.\d+\.\d+\.\d+|remote_addr", re.IGNORECASE)

# ==================== 提权语义（命令位置判定，防字面量误报） ====================
# 旧实现 `\bsudo\b|\bsu\b|...` 对 action_detail 全文子串匹配，导致
# echo "sudo ..."/grep -rn "sudo"/awk '/su -/'/邮件正文里「sudo 收窄」等字面量
# 被误判为真实提权。修复：改为「命令位置」判定——只有段首词确实是提权命令
# （sudo/su/chmod u+s/setcap/pkexec/doas）才视为提权；查询/输出类命令（grep/
# awk/echo/...）的参数与引号内容不再触发。
#
# 兜底职责（注释见下）：stage 判定里 sudo su/sudo bash 常被 EXEC 阶段抢占，
# 此判定在 stage 之外补充这些「裸 shell 提权」形态，覆盖 stage 的盲区。

# 内联 shell 命令提取：os.system(...)/subprocess(...)/bash -c "..." 里真正执行的命令
_INLINE_SHELL_RE = re.compile(
    r"(?:os\.system|os\.popen)\s*\(\s*['\"]([^'\"]+)['\"]"
    r"|subprocess\.[a-z_]+\(\s*\[([^\]]+)\]"
    r"|subprocess\.[a-z_]+\(\s*['\"]([^'\"]+)['\"]"
    r"|(?:bash|sh|zsh)\s+-c\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)


def _extract_inline_shell(s: str) -> list[str]:
    """从内联脚本动作里提取真正要执行的 shell 命令（os.system/subprocess/sh -c）。"""
    out: list[str] = []
    for m in _INLINE_SHELL_RE.finditer(s):
        g = next((x for x in m.groups() if x), None)
        if g is None:
            continue
        # 子进程列表形态 ["sudo","su"] → 去引号逗号拼成 "sudo su"
        if g.strip().startswith(('"', "'")) and (',"' in g or ',"' in g or ",'" in g):
            g = re.sub(r"['\"\[\],]+", " ", g)
        g = g.strip()
        if g:
            out.append(g)
    return out


# 包管理器：sudo 后第一个词是它们 → 装包/运维，非提权
_PKG_MGR = frozenset({"apt", "apt-get", "aptitude", "yum", "dnf", "pacman", "zypper", "apk", "brew"})
# sudo 后紧跟的裸 shell 提权词（第一个 token）
_SHELLS = frozenset({"bash", "sh", "zsh", "dash", "fish", "ksh", "csh", "tcsh", "nologin"})


def _contains_privesc(shell: str) -> bool:
    """在一个（可能的）shell 命令串里做「命令位置」提权判定。

    只认真·提权形态（段首词是 sudo/su/chmod/setcap/pkexec/doas，且命中具体
    提权特征），免疫 echo/grep/awk/文档正文里的字面量。覆盖 stage PRIVESC 的
    全部能力（见 l2_rules.json 5 条），并额外兜底 sudo su/sudo bash 等被 EXEC
    抢占的裸 shell 提权。
    """
    if not shell:
        return False
    for seg in re.split(r"&&|\|\||;|\n", shell):
        seg = seg.strip()
        if not seg:
            continue
        toks = seg.split()
        head = toks[0].lower() if toks else ""
        rest = " ".join(toks[1:]) if len(toks) > 1 else ""
        # chmod 设 setuid/setgid 位（符号式 u+s/g+s 或八进制组合位 2-7xxx）
        if head == "chmod" and re.search(r"(?:u\+s|g\+s|[2-7][0-7]{3})", rest):
            return True
        if head == "setcap" and re.search(r"cap_", rest):
            return True
        if head in ("pkexec", "doas"):
            return True
        if head == "sudo":
            # sudo -u <user>：仅 root 算提权，非 root 跳过本段
            if re.match(r"^-u\s+", rest):
                if re.match(r"^-u\s+root\b", rest):
                    return True
                continue  # 非 root，本段非提权，继续看后续段
            m = re.match(r"(\S+)(.*)", rest)
            if m:
                nxt, tail = m.group(1).lower(), m.group(2)
                if nxt in _PKG_MGR:
                    continue  # 包管理器装包/运维，非提权
                if nxt in _SHELLS:
                    return True
                if nxt.startswith("su"):
                    return True
                if nxt.startswith("/") and re.search(r"bin/(?:bash|sh|zsh|dash|fish)$", nxt):
                    return True
            # sudo 后整段搜提权危险词（跨 flag，如 sudo -E /bin/bash）
            if re.search(r"/(?:usr/(?:local/)?bin|bin)/(?:bash|sh|zsh|dash|fish)\b", rest):
                return True
            if re.search(r"\bchmod\s+(?:u\+s|g\+s|[2-7][0-7]{3})\b", rest):
                return True
            if re.search(r"\bsetcap\s+cap_\w+", rest):
                return True
            if re.search(r"\bvisudo\b", rest):
                return True
            if re.search(r"\bpasswd\s+root\b", rest):
                return True
            if re.search(r"\buseradd\b", rest):
                return True
        if head == "su":
            # 提权只认：su（裸切 root）、su -/su -l（默认 root）、su root / su - root
            if not rest:
                return True
            if re.match(r"^-l?\s*$", rest):
                return True
            if re.match(r"^root\b", rest) or re.match(r"^-l?\s+root\b", rest):
                return True
            # su <其他用户>（如 su postgres）不算提权
    # setuid 系统调用（代码内真实调用，如 os.setuid(0)，非字符串字面量）
    if re.search(r"\bset(?:uid|euid|gid|egid|reuid|regid|resuid|resgid)\s*\(", shell):
        return True
    return False


def _is_privesc_node(n) -> bool:
    """节点是否属提权：以「命令位置判定」为准。

    **不再依赖 n.stage == PRIVESC**——builder 用 l2_rules.json 的 stage 正则标
    stage，其中 PRIVESC 第 4 条的裸 `\bsetuid\b` 会把 grep "setuid" / echo "setuid"
    误标为 PRIVESC；`_contains_privesc` 已完整覆盖 stage PRIVESC 的 5 条能力
    （见下方），故此处以命令位置判定唯一裁决，免疫该误标，同时兜底 sudo su /
    sudo bash 等被 EXEC 抢占的裸 shell 提权。
    """
    shell = strip_string_literals(n.action_detail)
    if _contains_privesc(shell):
        return True
    for cmd in _extract_inline_shell(shell):
        if _contains_privesc(cmd):
            return True
    return False


def _is_exfil_node(n) -> bool:
    """节点是否属外传形态：stage EXFIL、主动外传命令（url/scp/rsync 且带外传动词）、
    或 eBPF connect+remote。

    关键：**文档内容里提到 URL 不算**（`cat >> report.md << EOF` 含 https:// 只是
    正文），必须是主动执行外传动词（curl/wget/scp/rsync/connect 类）。eBPF 证据
    用真实网络 syscall 补充（connect 到外网 IP 即行为层面外传）。
    """
    if n.stage == "EXFIL":
        return True
    # 文本 URL/scp/rsync：要求同条命令含主动外传动词，避免 heredoc/文档注释误报
    if _EXFIL_RE.search(n.action_detail) and _EXFIL_ACTION_RE.search(n.action_detail):
        return True
    if _EBPF_NET_RE.search(n.action_detail) and _REMOTE_RE.search(n.action_detail):
        return True
    return False


def check_never_exfil_after_privesc(graph: MultiSessionGraph) -> list[PropertyViolation]:
    """P3：□(PRIVESC → ¬◇ EXFIL) — 一旦出现提权，任意外传（跨 session/时距）即违例。

    独立于预置链 `privesc-cred-exfil`（那要求按序 PRIVESC→CRED→EXFIL 三段且
    由固定链定义驱动）；这里只要求图上存在"任意 PRIVESC 在前、任意 EXFIL 在后"
    的事件对即拦截——覆盖乱序/跨会话/中间夹杂大量无关动作的变体。

    witness 语义（graph.witness_idx 非 None，实时判定）：只当**当前动作
    （a_next = 图末节点）**是 EXFIL 且历史中有 PRIVESC 在前才判违规——历史中
    已随机出现的 PRIVESC+EXFIL 组合不再误伤后续良性动作；None（低频回顾）时
    保留"图上任意 PRIVESC 在前、EXFIL 在后"的全历史判定。

    注意：eBPF 行为证据（session_id="ebpf-evidence"）是当前动作的真实行为
    （a_next 是"声明"，ebpf 是"行为"），同样视为 witness 的 EXFIL 证据。
    """
    violations: list[PropertyViolation] = []
    nodes = graph.all_nodes
    if len(nodes) < 2:
        return violations
    witness = graph.witness_idx
    # PRIVESC 前置以"提权语义"为准（stage 或文本）；EXFIL 后置以 _is_exfil_node。
    privesc_at: list[int] = [i for i, n in enumerate(nodes) if _is_privesc_node(n)]
    if not privesc_at:
        return violations
    if witness is not None:
        # 实时判定：当前动作的 EXFIL 证据 = a_next 节点 + eBPF 行为证据节点
        ev_idx = [i for i, n in enumerate(nodes)
                  if (i == witness or n.session_id == "ebpf-evidence") and _is_exfil_node(n)]
        if not ev_idx:
            return violations
        first_ev = min(ev_idx)
        if any(i < first_ev for i in privesc_at):
            pre = [nodes[i] for i in privesc_at if i < first_ev][-1]
            post = nodes[first_ev]
            return [PropertyViolation(
                property_id="no-exfil-after-privesc",
                reason="提权后出现外传：提权(前) → 外传(后)，违反 □(PRIVESC→¬◇EXFIL)",
                risk_level="critical",
                path=[(pre.session_id, pre.seq, pre.action_detail[:60]),
                      (post.session_id, post.seq, post.action_detail[:60])],
            )]
        return violations
    for i in privesc_at:
        for j in range(i + 1, len(nodes)):
            n = nodes[j]
            if _is_exfil_node(n):
                violations.append(PropertyViolation(
                    property_id="no-exfil-after-privesc",
                    reason="提权后出现外传：提权(前) → 外传(后)，违反 □(PRIVESC→¬◇EXFIL)",
                    risk_level="critical",
                    path=[(nodes[i].session_id, nodes[i].seq, nodes[i].action_detail[:60]),
                          (n.session_id, n.seq, n.action_detail[:60])],
                ))
                return violations  # 一条足矣，命中即停
    return violations


def _is_cred_node(n) -> bool:
    """严格凭据判定（P3/P4 用）：仅真实凭据文件/路径，避免把项目配置当凭据。

    stage==CRED 只是粗筛；必须资源路径或文本命中 _CRED_STRICT_RE
    （.ssh/id_rsa/.pem/.aws/credentials/shadow/netrc 等），排除 credentials.yml
    这类项目配置文件。
    """
    if n.stage != "CRED":
        return False
    if any(_CRED_STRICT_RE.search(r) for r in n.resources):
        return True
    if _CRED_STRICT_RE.search(n.action_detail):
        return True
    return False


def check_never_exfil_after_cred(graph: MultiSessionGraph) -> list[PropertyViolation]:
    """P4：□(CRED → ¬◇ EXFIL) — 读取凭据后任意外传（无论是否经共享载体）即违例。

    现有 P2 sensitive-data-flow 要求 taint 沿 data 边传播（凭据文件 → 共享载体
    → EXFIL）；这里更保守也更轻：只要图上 CRED 阶段在 EXFIL 之前就是违例，
    覆盖"隐式关联"（如凭据被压缩进 zip 再外传、多跳间接外泄）P2 检测不到的形态。

    witness 语义（graph.witness_idx 非 None，实时判定）：只当**当前动作
    （a_next = 图末节点）**是 EXFIL 且历史中有 CRED 在前才判违规——历史中
    已随机出现的 CRED+EXFIL 组合不再误伤后续良性动作；None（低频回顾）时
    保留"图上任意 CRED 在前、EXFIL 在后"的全历史判定。

    注意：eBPF 行为证据（session_id="ebpf-evidence"）是当前动作的真实行为
    （a_next 是"声明"，ebpf 是"行为"），同样视为 witness 的 EXFIL 证据。
    """
    violations: list[PropertyViolation] = []
    nodes = graph.all_nodes
    if len(nodes) < 2:
        return violations
    witness = graph.witness_idx
    # 与前相同：EXFIL 后置以 _is_exfil_node（文本 + eBPF 真实外发）
    cred_at: list[int] = [i for i, n in enumerate(nodes) if _is_cred_node(n)]
    if not cred_at:
        return violations
    if witness is not None:
        # 实时判定：当前动作的 EXFIL 证据 = a_next 节点 + eBPF 行为证据节点
        ev_idx = [i for i, n in enumerate(nodes)
                  if (i == witness or n.session_id == "ebpf-evidence") and _is_exfil_node(n)]
        if not ev_idx:
            return violations
        first_ev = min(ev_idx)
        if any(i < first_ev for i in cred_at):
            pre = [nodes[i] for i in cred_at if i < first_ev][-1]
            post = nodes[first_ev]
            return [PropertyViolation(
                property_id="no-exfil-after-credential",
                reason="读取凭据后出现外传，违反 □(CRED→¬◇EXFIL)",
                risk_level="critical",
                path=[(pre.session_id, pre.seq, pre.action_detail[:60]),
                      (post.session_id, post.seq, post.action_detail[:60])],
            )]
        return violations
    for i in cred_at:
        for j in range(i + 1, len(nodes)):
            n = nodes[j]
            if _is_exfil_node(n):
                violations.append(PropertyViolation(
                    property_id="no-exfil-after-credential",
                    reason="读取凭据后出现外传，违反 □(CRED→¬◇EXFIL)",
                    risk_level="critical",
                    path=[(nodes[i].session_id, nodes[i].seq, nodes[i].action_detail[:60]),
                          (n.session_id, n.seq, n.action_detail[:60])],
                ))
                return violations
    return violations


# ==================== Rule 5 低完整性控制命令执行 ====================

# Tool Registry 缓存（工具名 → actionClass/requireHighIntegrity，单一事实源）
_TOOL_REGISTRY: dict[str, dict] | None = None


def _load_tool_registry() -> dict[str, dict]:
    """加载 tool_registry.json（幂等）。"""
    global _TOOL_REGISTRY
    if _TOOL_REGISTRY is None:
        from ...rules_loader import load_tool_registry
        _TOOL_REGISTRY = load_tool_registry().get("tools", {}) or {}
    return _TOOL_REGISTRY


def lookup_tool_class(action_type: str) -> str | None:
    """Tool Registry：按工具名/命令查 actionClass（read/write/compute/network_egress/...）。
    未注册返回 None（回退正则判定）。"""
    return (_load_tool_registry().get(action_type, {}) or {}).get("actionClass")


# compute 动作形态（命令执行）：bash/sh -c 执行脚本、python/node 解释执行、
# subprocess/eval/exec 动态执行等。cat/ls/grep 等只读命令即使经 bash 工具运行
# 也不算"命令执行"（它们不解释执行不可信内容）——必须 detail 命中执行形态。
_COMPUTE_RE = re.compile(
    r"subprocess|os\.system|shell\s*=\s*True|\beval\(|\bexec\(|"
    r"bash\s+[^\s]|sh\s+-c|python3?\s+|node\s+|\btimeout\s+|nohup\s+|\b\.\/[\w./-]+",
    re.IGNORECASE,
)
# 解释器/终端类 action_type：直接算 compute（无论 detail）
_STRONG_COMPUTE_TYPES = {"python", "node", "exec", "terminal", "cmd"}


def _is_compute_node(n) -> bool:
    """节点是否命令执行形态（Rule 5 关注 compute）。

    1. 强类型解释器/终端（python/node/exec/terminal/cmd）→ compute（无论 detail）。
    2. Tool Registry 明确标为非 compute（read/write/network_egress/message_egress）
       → 排除（如 cat/file.read 经 bash 工具运行不算命令执行）。
    3. 其余（bash/shell 等）：detail 命中执行形态才算
       （bash x.sh、sh -c、subprocess、eval/exec、./script 等）。
    """
    if n.action_type.lower() in _STRONG_COMPUTE_TYPES:
        return True
    cls = lookup_tool_class(n.action_type)
    if cls in ("read", "write", "network_egress", "message_egress"):
        return False
    return bool(_COMPUTE_RE.search(n.action_detail))


def check_low_integrity_command_exec(graph: MultiSessionGraph) -> list[PropertyViolation]:
    """Rule 5：低完整性控制命令执行 — 不可信数据（外取/下载/注入内容）经共享载体
    控制 shell/terminal 执行。这是 L2.1 最有区分度的检测之一（站点 critical block）。

    机制：
    1. 低完整性源（is_low_source：download_file / prompt_injection AP 命中的动作）
       的资源（如 curl -o 写入的 /tmp/x.sh、wget 产物）视为不可信。
    2. 沿 data 边（共享资源）传播 min：任何动作的资源与 low 源资源相交 →
       该动作 integrity=low（低处流原则，迭代收敛，同 P2 taint 方式）。
    3. compute 形态动作（shell/bash/python/subprocess）且 integrity=low →
       违规（不可信数据直接控制命令执行）。

    witness 语义：实时判定（witness_idx 非 None）只当**当前动作**是 low-integrity
    compute 才判违规；None（低频回顾）时报告历史中已形成的低完整性执行链。
    """
    violations: list[PropertyViolation] = []
    nodes = graph.all_nodes
    if not nodes:
        return violations
    witness = graph.witness_idx

    # 1. 收集 low 源资源 + 初始 low 节点
    low_resources: set = set()
    low_at: dict[int, str] = {}
    for i, n in enumerate(nodes):
        if n.is_low_source:
            low_at[i] = n.action_detail[:60]
            low_resources |= n.resources

    # 2. 沿共享资源传播（迭代收敛）
    changed = True
    while changed:
        changed = False
        for i, n in enumerate(nodes):
            if i in low_at:
                continue
            if n.resources & low_resources:
                low_at[i] = f"继承自 {sorted(n.resources & low_resources)[0]}"
                low_resources |= n.resources
                changed = True

    if not low_at:
        return violations

    # 3. compute + low → 违规（witness 语义：只查当前动作；回顾：查全部）
    candidates = [witness] if witness is not None else [i for i in range(len(nodes))]
    for i in candidates:
        n = nodes[i]
        if i in low_at and _is_compute_node(n):
            violations.append(PropertyViolation(
                property_id="low-integrity-command-exec",
                reason=f"低完整性数据控制命令执行：{low_at[i]} → {n.session_id}#{n.seq} 执行不可信内容",
                risk_level="critical",
                path=[(n.session_id, n.seq, n.action_detail[:60])],
            ))
            if witness is not None:
                return violations  # 实时判定命中即停
    return violations


# ==================== Rule 12 敏感数据聚合外传 ====================


def check_sensitive_data_aggregation(graph: MultiSessionGraph) -> list[PropertyViolation]:
    """Rule 12：sensitive-data-aggregation — egress 聚合 ≥2 个不同事件源。

    站点定义：`isEgress → incoming data_dependency → uniqueEventIds.size >= 2`。
    检测数据收集行为：攻击者在多个步骤中收集敏感数据后在单次 egress 中外传。
    当前模型无 OBS 通道，用"共享资源/载体"近似 data_dependency：EXFIL 节点的
    资源（文件/网络目标）被 ≥2 个不同事件（session_id, seq 唯一）接触过 →
    视为聚合了多个来源的数据。

    性能：资源 → [node_idx] 索引，O(N·R)；witness 语义只查当前动作。
    """
    violations: list[PropertyViolation] = []
    nodes = graph.all_nodes
    if len(nodes) < 2:
        return violations
    witness = graph.witness_idx

    # 资源 → 节点索引（供 EXFIL 聚合源统计）
    res_index: dict[str, list[int]] = {}
    for i, n in enumerate(nodes):
        for r in n.resources:
            res_index.setdefault(r, []).append(i)

    def _sources_for(exfil_idx: int) -> set:
        """EXFIL 节点经共享载体接触过的去重事件源（session_id, seq）。"""
        srcs: set = set()
        n = nodes[exfil_idx]
        for r in n.resources:
            for j in res_index.get(r, []):
                if j == exfil_idx:
                    continue
                srcs.add((nodes[j].session_id, nodes[j].seq))
        return srcs

    candidates = [witness] if witness is not None else [i for i in range(len(nodes))]
    for i in candidates:
        n = nodes[i]
        if not _is_exfil_node(n):
            continue
        srcs = _sources_for(i)
        if len(srcs) >= 2:
            violations.append(PropertyViolation(
                property_id="sensitive-data-aggregation",
                reason=f"敏感数据聚合外传：egress 聚合 {len(srcs)} 个事件源数据（Rule 12）",
                risk_level="critical",
                path=[(n.session_id, n.seq, n.action_detail[:60])],
            ))
            if witness is not None:
                return violations  # 实时判定命中即停
    return violations


# ==================== 跨 session 数据流可达性（多跳） ====================
#
# 站点 L2.1 的核心是"不可信/敏感数据沿数据依赖图流动"，P2 只做了**单跳**传播
# （CRED 源 → 直接共享」）且只看凭据类。这里的性质把"数据流"推广到**多跳跨
# session**：用 data 边做图可达性（图 = 节点 + next + data 边），一旦**恶意下载
# /外取产物**（低完整性源 is_low_source，与 Rule 5 同源）沿中介载体多跳流至**当前
# 动作**（实时为末节点），即使命令本身无危险字面（如改名后 `bash /tmp/x.db`），
# 也判违规——补 L1 字面正则与 P2 单跳覆盖不到的"免杀改名/间接引用文件"场景。
# witness 语义：实时（witness_idx 非 None）只查末节点（当前动作）是否可达低完整性
# 源；低频回顾查全图。未接入 ALL_PROPERTIES（避免与 Rule 5 重复短路），需显式注册。

_DL_OR_LOW_RE = re.compile(
    r"curl\s+.*-o\b|wget\s+.*\s+-O\b|curl\s+.*\|\s*(bash|sh|python)|wget\s+.*\|\s*(bash|sh|python)|"
    r"git\s+clone|docker\s+pull|pip\s+install|npm\s+install|base64\s+-d",
    re.IGNORECASE,
)


def check_cross_session_reachability(graph: MultiSessionGraph) -> list[PropertyViolation]:
    """新性质（L2.1 增强）：低完整性源经跨 session data 边多跳可达当前动作。

    与 Rule 5 区别：Rule 5 靠 integrity 标签传播（节点级），这里靠 **共享资源
    （文件路径）作为数据载体** 的多跳可达性——覆盖"session1 下载 /tmp/p.sh →
    session2 `mv /tmp/p.sh /tmp/cache.db` → session2 `bash /tmp/cache.db`"，
    改名后 Rule 5 可能失效（integrity 按节点传播，不追踪改名），但 data 边仍以
    /tmp/p.sh 与 /tmp/cache.db 两条资源相连，可达性仍抓住整条链。
    """
    violations: list[PropertyViolation] = []
    nodes = graph.all_nodes
    if not nodes:
        return violations

    # 源：恶意下载/外取的产物（与 Rule 5 的 is_low_source 同源判定）
    sources: set[int] = set()
    for i, n in enumerate(nodes):
        if n.is_low_source or _DL_OR_LOW_RE.search(n.action_detail):
            sources.add(i)
    if not sources:
        return violations

    # data 边 + next 边构成图，用共享资源传播可达（BFS/迭代直到不动点）
    reached: set[int] = set(sources)
    changed = True
    while changed:
        changed = False
        for e in graph.all_edges:
            if e.src in reached and e.dst not in reached:
                src_res = nodes[e.src].resources
                dst_res = nodes[e.dst].resources
                if src_res & dst_res:  # 共享同一文件/载体 → 数据从 src 流到 dst
                    reached.add(e.dst)
                    changed = True

    witness = graph.witness_idx
    candidates = [witness] if witness is not None else list(range(len(nodes)))
    for i in candidates:
        n = nodes[i]
        if i in sources:
            continue  # 源自身（下载/安装/注入动作）不算"再次流入"目标，避免自触发
        if i in reached:
            src_idx = min(sources)
            src_desc = nodes[src_idx].action_detail[:40]
            violations.append(PropertyViolation(
                property_id="low-integrity-reachability",
                reason=f"低完整性源经跨 session 数据链多跳到达当前执行（源: {src_desc} → {n.session_id}#{n.seq}）",
                risk_level="high",
                path=[(m.session_id, m.seq, m.action_detail[:60]) for m in nodes][-3:],
            ))
            if witness is not None:
                return violations  # 实时判定命中即停
    return violations


# ==================== 性质注册表 ====================

@dataclass
class Property:
    """性质定义。

    short_name：P1~P8 连续短名（给人/日志/文档读），id 是语义化英文（机器契约）。
    """

    id: str
    check: Callable[[MultiSessionGraph], list[PropertyViolation]]
    short_name: str = ""


#: 全部内置性质（顺序执行，命中即停）。
#: ⚠️ 顺序即 fail-closed 短路优先级：engine.verify 逐个执行，首个返回违规的性质
#:    成为 first_violation，后续性质不再评估（如 mc-ltl-002 的触发场景会先被
#:    mc-ltl-rules 或 low-integrity 短路）。调整顺序会影响判定的"归属"，
#:    改动需双端（Python+TS）测试确认一致。
#:
#: short_name（P1~P8 连续短名）与 id（语义化英文）对照：
#:   P1 cross-session-chain          跨会话组合链
#:   P2 sensitive-data-flow          敏感数据传播
#:   P3 low-integrity-reachability   低完整性数据流可达
#:   P4 no-exfil-after-privesc       提权后禁外传
#:   P5 no-exfil-after-credential    凭据后禁外传
#:   P6 mc-ltl-rules                 LTL 模型检测
#:   P7 low-integrity-command-exec   低完整性命令执行
#:   P8 sensitive-data-aggregation   敏感数据聚合外传
ALL_PROPERTIES: list[Property] = [
    Property(id="cross-session-chain", check=check_cross_session_chain, short_name="P1"),
    Property(id="sensitive-data-flow", check=check_sensitive_data_flow, short_name="P2"),
    # 跨 session 数据流可达性：低完整性源沿 data 边多跳到达（改名/间接引用免杀场景）
    Property(id="low-integrity-reachability", check=check_cross_session_reachability, short_name="P3"),
    # P4/P5 抽象性质（LTL 风格，独立于预置链序；命中即停）
    Property(id="no-exfil-after-privesc", check=check_never_exfil_after_privesc, short_name="P4"),
    Property(id="no-exfil-after-credential", check=check_never_exfil_after_cred, short_name="P5"),
    # L2.2 模型检测（通用 LTL 求值器，mc_rules.json 单一事实源；witness 语义见 ltl.py）
    Property(id="mc-ltl-rules", check=check_mc_rules, short_name="P6"),
    # P7 低完整性控制命令执行（integrity 维度，站点 L2.1 最有区分度的检测之一）
    Property(id="low-integrity-command-exec", check=check_low_integrity_command_exec, short_name="P7"),
    # P8 敏感数据聚合外传（egress 聚合 ≥2 事件源）
    Property(id="sensitive-data-aggregation", check=check_sensitive_data_aggregation, short_name="P8"),
]
