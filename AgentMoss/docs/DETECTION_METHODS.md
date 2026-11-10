# AgentMoss 检测方法文档（Detection Methods）

> 本文档系统性记录 AgentMoss **所有需要检测的方法**：来自 agent-moss.github.io 设计蓝图的
> 站点 L2.1（PDG 蓝图，24 条规则）与 站点 L2.2（模型检测蓝图，15 条规则），以及 AgentMoss 当前
> 代码的实现现状、未采用方案、大体量压测基线与实施路线。作为"分批实现 → 实测效果与开销 →
> 决定商用"的权威依据。
>
> 配套文档：[MAINTENANCE_WORKFLOW.md](MAINTENANCE_WORKFLOW.md)（操作手册）、
> [L2.2_FORMAL_COMBO_ENGINE.md](L2.2_FORMAL_COMBO_ENGINE.md)（形式化引擎与组合链路实现总览——
> 快照验证 + 增量扩展已合并，原 STATEFUL_CHAIN_ENGINE.md 并入其附录 A/C）、
> [DETECTION_PRIORITY.md](DETECTION_PRIORITY.md)（**检测层次与决策优先级统一视图**——
> L1/L2/L3 各自小层、组合分析三重形态、violated_layers 编号、runtime 相互作用、回归要求）。
>
> **代码路径阅读约定**：与 [L2.2_FORMAL_COMBO_ENGINE.md](L2.2_FORMAL_COMBO_ENGINE.md) §2.1 一致——
> 裸 `.py` 路径（如 `properties.py`）指双端通用实现的 Python 侧，TS 端对应同名 `.ts` 文件，
> 行为一致；双端镜像完整映射见 [L2.2_FORMAL_COMBO_ENGINE.md](L2.2_FORMAL_COMBO_ENGINE.md) §5 索引表。

---

## 一、检测体系总览

AgentMoss 三层防御 + 形式化引擎的检测能力分布：

| 层 | 名称 | 检测方法 | 规则数 | 状态 |
|----|------|----------|--------|------|
| L1 | 特征匹配静态检测 | 危险命令/注入关键词/敏感路径正则匹配（只看 a_next 本身） | 91 | ✅ 已实现（Python + TS） |
| L2 | 逻辑规则检测 | read_before_write / 意图一致 / 提权 / 授权 / 间接访问 | — | ✅ 已实现 |
| 站点 L2.1 | PDG 数据流检测（蓝图） | 程序依赖图 + 安全标签格传播 + 拓扑违规判定 | 16 | ⚠️ 部分落地（Rule 5 integrity 维度 + Rule 12 aggregation 已实现；9 节点类型/完整格传播依赖 OBS 通道，见 5.3） |
| 站点 L2.1 | 行为链检测（蓝图） | 时间窗口内按序匹配攻击阶段 | 7 | ✅ 等价（combo_chains 9 条 + witness 语义修复） |
| 站点 L2.1 | 全局关联检测（蓝图） | 跨会话 4 阶段攻击链 | 1 | ✅ 等价（P1 跨会话组合链 + PatternMiner） |
| 站点 L2.2 | 模型检测（蓝图） | LTL 攻击模式 + CTL 安全属性 | 15 | ✅ LTL 求值器已实现（mc_rules.json 11 条规则：mc-ltl-001~010 + mc-ctl-001；CTL 活性挂 5.4） |
| L2.2 | 形式化验证 | 行为图 + 性质验证（跨会话组合链/敏感数据传播） | 8 | ✅ 已实现（P1~P8：cross-session-chain / sensitive-data-flow / low-integrity-reachability / no-exfil-after-privesc / no-exfil-after-credential / mc-ltl-rules / low-integrity-command-exec / sensitive-data-aggregation，见 6.4b） |

> **L2.2 归属**：AgentMoss 形式化验证层（行为图 + 性质验证）。编号与架构层一致（L2.1 逻辑规则 → L2.2 形式化验证 → L2.3 脚本 L2 扫描），与站点蓝图「站点 L2.1/L2.2」无关。
> 形式化**属于 L2**：引擎门控 = `L2 总开关`（无独立 L2_4_formal 开关）。**console 中 LTL 规则并入
> L2 页**展示（「时序攻击模式 (LTL)」分类卡，与意图一致性等并列），不再独立 tab；Agent/场景定制
> 规则有独立总开关（`agent_rules_enabled` / `scenario_rules_enabled`），形式化跟随 L2。

**站点设计的总规则数**：站点 L2.1 24 条 + 站点 L2.2 15 条 + L1 91 条 = 130 条。
**当前 AgentMoss 已落地**：L1 91 + L2 逻辑规则 + L2.2 8 个形式化性质（P1~P8 连续短名，原 P1/P2/P3/P4 + 可达性 + mc-ltl + Rule 5/12）+ L2.2 11 条 LTL 规则 +
Rule 5 integrity + Rule 12 aggregation ≈ **120+ 条检测能力**（按等价覆盖计）。

> **层号/执行顺序权威视图见 [DETECTION_PRIORITY.md](DETECTION_PRIORITY.md)**（§1 检测层次总览、
> §5 `violated_layers` 编号口径）。上表仅保留本文独有的「站点蓝图 vs 实现对照」维度。

**关键结论（先读）**：站点 L2.1/L2.2 描述的方案大部分是**设计蓝图**（pdg.ts /
behavior-chain.ts / model-checker.ts / registry.ts / global-analyzer.ts 在 AgentMoss 仓库中
不存在，全仓 grep integrity/PDG/格传播零命中）。AgentMoss 用**另一套实现**覆盖了部分检测目标
（combo_chains 预置链 ≈ 行为链；P1 跨会话组合链 ≈ 全局关联；P3/P4 手写 LTL 形态 ≈ mc-ltl-001/007）。
真正未采用的高价值方案见"四、未采用但有效可行的方案"。

---

## 二、站点 L2.1 PDG 检测方法（蓝图，24 条）

### 2.1 三层混合机制

PDG 检测不是纯模式匹配，而是三层混合：

| 层 | 方法 | 核心函数 | 是否模式匹配 | 输出 |
|----|------|----------|--------------|------|
| 第 1 层 | 正则打标签（Labeling） | `detectSensitiveKinds` / `hasPromptInjection` | 是（仅初始化标签） | SecurityLabel 初始值 |
| 第 2 层 | 图论标签传播（Propagation） | `joinConfidentiality`=max / `joinIntegrity`=min | 否（格运算） | 更新后的 SecurityLabel |
| 第 3 层 | 拓扑违规判定（Inspection） | `inspectSecurityPdg` — 16 条规则 | 否（图结构分析） | SecurityViolation[] |

**设计要点**：正则只在第 1 层标记节点属性，真正的检测能力来自标签传播和图拓扑分析。
输出违规时带动作分级：**block / approval / observe**。

### 2.2 9 种细粒度节点类型

每条事件按类型分解为 1~5 个子节点：

| 节点类型 | 简写 | 来源事件 | 标签初始化函数 |
|----------|------|----------|----------------|
| system_prompt | SP | llm_input (system) | makePromptLabel |
| user_prompt | UP | llm_input (user) | makePromptLabel |
| llm_response | LLM | llm_output | makePromptLabel |
| llm_thought | TH | llm_output (reasoning) | makePromptLabel |
| tool_name | TN | tool_call 分解 | makeToolNameLabel |
| tool_param | TP | tool_call 分解 | makeParamLabel |
| tool_action | T | tool_call 分解 | makeActionLabel |
| observation | OBS | tool_result 分解 | makeObservationLabel |
| data | D | tool_result 中提取的敏感数据 | makeDataLabel |

事件分解规则：`llm_input`→1 节点；`llm_output`→1~4 节点；`tool_call`→1+N+1 节点；
`tool_result`→1+M 节点；`message_sending`→1+N 节点。

### 2.3 安全标签系统（SecurityLabel 4 维度）

```typescript
type SecurityLabel = {
  confidentiality: "low" | "medium" | "high";  // 机密性
  integrity:       "low" | "medium" | "high";  // 完整性
  sensitiveKinds:  string[];                   // 敏感类型标签
  actionClass:     "read"|"write"|"network_egress"|"message_egress"|"compute"|"unknown";
};
```

- **confidentiality 初始化**：检测到 API Token/密码/私钥/.env/PII → high；工具输出默认 medium；其他 low。
- **integrity 初始化**：system/user → high；llm → medium；tool/external → low（含注入强制 low）。
- **sensitiveKinds**：api_token / credential / private_key / dotenv_secret / pii_financial / prompt_injection。
- **敏感类型正则**：API token、credential、private key、.env 泄露、PII/金融、Prompt 注入
  （`ignore previous instructions`、`<INFORMATION>`、`TODO: send/email/transfer/...` 等 AgentDojo 攻击）。

### 2.4 格传播规则（Lattice Propagation）

沿数据依赖边传播标签：

| 合并 | 规则 | 原理 |
|------|------|------|
| joinConfidentiality | 取 **max** | 高处流原则：收到高机密数据即视为高机密 |
| joinIntegrity | 取 **min** | 低处流原则：不可信数据污染下游（注入检测理论基础） |
| sensitiveKinds | 取**并集** | |

传播路径（关键边）：

| 边路径 | 用途 | 传播标签 |
|--------|------|----------|
| Parent OBS → Child UP/SP | 注入检测关键路径 | 全部 |
| Parent OBS/D → Child TP | 数据外传检测关键路径 | 全部 |
| Parent OBS → Child TN | 工具选择注入检测 | integrity (min) |
| Parent OBS → Child T | 动作影响检测 | 全部 |
| Parent LLM → Child T | 控制流依赖 | integrity (min) |
| Parent SP/UP → Child LLM | Prompt 馈入模型 | conf (max), int (min) |
| Tool Call T → Tool Result OBS | 工具动作产生结果 | integrity (min) |

**控制依赖边**：parent integrity < medium 且 child 是动作节点 → 添加
`control_dependency` 边——这是 Rule 2/4/5 检测"低完整性输入控制动作执行"的证据。

### 2.5 PDG 构建流水线（3 阶段）

1. **Phase 1 节点分解**：按时间排序事件 → 分解为子节点 → make*Label 初始化。
2. **Phase 2 事件内边**：TN→T、TP:*→T、LLM→TN、OBS→D:*（data_dependency）。
3. **Phase 3 事件间边 + 标签传播**：control_flow（同 run 顺序）、data_dependency
   （parentEventIds）、control_dependency（低完整性父→动作子）、T→OBS（同 toolCallId）。

### 2.6 3 种边类型

| 边类型 | 用途 | 示例 |
|--------|------|------|
| control_flow | 同一 run 内事件顺序 | prev.lastNode → curr.firstNode |
| data_dependency | 数据流依赖（标签传播通道） | OBS → TP, LLM → T, TP → T |
| control_dependency | 低完整性源控制动作 | low-integrity OBS → T |

辅助函数：`bfsUpstream(graph, id, maxDepth=4)`（找注入/敏感源）、`bfsDownstream`（影响范围）、
`detectStagingBeforeEgress`（egress 前 3 步内 staging 检测）。

### 2.7 PDG 检测规则 — 16 条（Rule 1-16）

第 3 层用 6 种拓扑分析方法：标签比较 / 边类型检查 / BFS 遍历 / 数据源计数 /
兄弟节点对比 / 参数内容匹配。规则 1-8 基础，9-14 细粒度分解新增，15-16 AgentDojo 增强。

| # | 规则 ID | 动作 | 严重性 | 拓扑方法 | 检测条件 |
|---|---------|------|--------|----------|----------|
| 1 | high-confidentiality-public-egress | block | critical | 标签比较 | isEgress && conf == high |
| 2 | low-integrity-controls-side-effect | block/observe | critical/warning | 边类型+BFS+内容 | isEgress && int < medium |
| 3 | high-confidentiality-write-to-public-path | observe | warning | 标签比较 | isWrite && conf == high |
| 4 | low-integrity-controls-write-operation | observe | warning | 边类型 | isWrite && int < medium |
| 5 | low-integrity-controls-command-exec | block | critical | 边类型 | isCompute && int < medium |
| 6 | sensitive-data-staging-before-egress | block | critical | BFS 上游 | egress → bfsUpstream(3) staging → bfsUpstream(2) 高机密源 |
| 7 | tool-result-injection-to-command | block | critical | 边类型+标签比较 | isCompute → upstream OBS 含 prompt_injection |
| 8 | unauthorized-indirect-execution | block | critical | 边类型+标签比较 | obs 源 && !user 源 && 注入源 && lowInt > 0 |
| 9 | observation-to-tool-name-flow | block/observe | critical/warning | 边类型+标签比较 | TN → upstream OBS/D → actionClass 决定 |
| 10 | observation-to-tool-param-flow | block/observe | critical/warning | 边类型+BFS+内容 | TP → upstream OBS；write 需内容匹配注入源 |
| 11 | sensitive-data-in-egress-param | block | critical | 标签比较 | TP && isEgress && conf == high |
| 12 | sensitive-data-aggregation | block | critical | 数据源计数 | isEgress → uniqueEventIds.size >= 2 |
| 13 | tool-name-spoofing | observe | info | 兄弟节点对比 | LLM 提及工具名 ≠ sibling TN content |
| 14 | observation-derived-shell-command | block | critical | 边类型+内容匹配 | isCompute → OBS → 参数匹配 shell 命令模式 |
| 15 | prompt-injection-controls-egress | block/observe | critical/warning | BFS+内容匹配 | bfsUpstream(4) → 注入源控制 egress/write/compute |
| 16 | injection-source-data-exfiltration | block | critical | 边类型+BFS+标签 | isEgress && conf==high && 上游低完整+注入源 |

**9 始终 block + 4 条件 block/observe + 3 始终 observe**。

### 2.8 行为链规则 — 7 条（bfchain-*）

按 runId 分组 → 滑动窗口 → 按序匹配 phase 正则（一条事件只匹配一个 phase）。

| # | 规则 ID | 攻击链模式 | 时间窗口 | Phase 数 |
|---|---------|------------|----------|----------|
| 1 | bfchain-download-execute | 下载→执行 | 5 分钟 | 2 |
| 2 | bfchain-download-persist | 下载→持久化 | 10 分钟 | 2 |
| 3 | bfchain-download-privesc-exec | 下载→提权→执行 | 5 分钟 | 3 |
| 4 | bfchain-collect-exfiltrate | 敏感读取→打包→外传 | 10 分钟 | 3 |
| 5 | bfchain-disable-security-impact | 禁用安全→执行 | 5 分钟 | 2 |
| 6 | bfchain-credential-theft | 敏感读取→外传 | 5 分钟 | 2 |
| 7 | bfchain-git-build-exec | git clone→make/build | 10 分钟 | 2 |

Phase 正则模式：DOWNLOAD / EXECUTE / PERSIST / PRIVILEGE / ARCHIVE / EGRESS /
SENSITIVE_READ / DISABLE_SECURITY（详见站点原文）。

### 2.9 全局关联规则 — 1 条（cross-session-credential-staging）

跨会话 4 阶段攻击链：**recon → sensitive_read → staging → egress**。
- 关联键：sessionKey（去 run 后缀）+ agentId；窗口 24 小时；跨会话条件 involvedRunIds >= 2。
- 价值：单 run 内各步看似正常（find / cat 配置 / tar / 网络外发），跨会话关联才显现攻击链
  （示例里的 `cat .env` 若直连 `~/.env` 属 L1 敏感路径会先拦，演示时用「L1 无害」的等价形态——
  各阶段动作对照表见 L2.2_FORMAL_COMBO_ENGINE.md §B.11）。

### 2.10 Tool Registry / Data Registry（配置扩展）

- **Tool Registry**（registry.ts）：按工具名查 `readsFrom/writesTo/sideEffectData/
  defaultConfidentiality/defaultIntegrity/requireHighIntegrity/actionClass`。
  actionClass 触发规则矩阵：write→Rule 3/4/9/10/15；compute→Rule 5/7/8/9/10/14/15；
  network_egress→Rule 1/2/6/8/9/10/11/12/15/16。
- **Data Registry**：10 种数据类型（file_content/stdout/stderr/stdin/response_body/
  request_body/env_var/credential/config/unknown）的安全属性。
- **扩展方式**：inspectSecurityPdg 循环加规则 / BEHAVIOR_CHAIN_PATTERNS 数组加链 /
  detectSensitiveKinds 加正则。

---

## 三、站点 L2.2 模型检测方法（蓝图，15 条）

### 3.1 为什么需要模型检测

L1 单点规则无法理解跨步骤时序关系；L2.1 行为链是硬编码 phase 序列，无法表达：
- 弹性时序（"A 发生后 B 在未来某个时刻发生"，如 `F(A & F(B))`）
- 分支性质（所有路径上 A 都不应导致 B）
- 安全不变量（"日志清除在任何情况下都不应发生"）
- 活性属性（"注入检测到后必须在后续被阻断"）

站点 L2.2 基于 LTL（线性时序逻辑）/ CTL（计算树逻辑）模型检测，**新增规则只需写公式，不用改代码**。

### 3.2 Kripke 结构

把事件序列建模为 K = (S, S₀, R, L)：
- S：状态集合（每个事件对应一个状态）
- S₀：初始状态（最早事件）
- R：转移关系（线性：sᵢ→sᵢ₊₁；有 parentEventIds 时构成分支树）
- L：标记函数，返回状态上成立的原子命题集合

### 3.3 原子命题（Atomic Propositions）

**实现的 14 个原子命题**（mc_rules.json `ap_patterns`，Python+TS 共用，人话说明）：

| AP | 人话含义（检测什么） |
|----|------|
| reads_credential | 读凭据：id_rsa / .aws/credentials / netrc / 密码类文件 |
| network_egress | 网络外传：curl 发送 / scp / rsync 到远程 |
| execute_file | 执行文件/命令：bash / python / subprocess / eval  |
| write_file | 写入文件：`>` 重定向 / tee / mv / cp |
| delete_file | 删除文件：rm / unlink / rmdir |
| disable_security | 禁用安全：iptables -F / setenforce 0 / 停防火墙 |
| install_persistence | 装持久化后门：crontab / systemd / 写 .bashrc |
| privilege_escalation | 提权：sudo / su / setuid / setcap |
| download_file | 下载文件：curl -o / wget / git clone / pip install |
| archive_data | 打包压缩：tar / gzip / zip / base64 |
| prompt_injection | 提示词注入：忽略之前指令 / 伪造指令 |
| sensitive_data | 接触敏感数据：token / 私钥 / .env / 密码 |
| lateral_movement | 横向移动：ssh / scp 到远程主机 |
| clear_logs | 清除日志：history -c / 清 /var/log |

> 站点蓝图原 17 个含 blocked_by_policy / approved_by_policy / allowed_by_policy（策略
> 动作回注），需 policyAction 反馈回路，当前未实现（挂 5.4）——实现 14 个。

**labelEvent 建模范式与限制（诚实边界）**：
- 实现 = **直接对 tool call 的 action_detail 文本做正则**（`mc_rules.json` ap_patterns），
  无结构化字段/工具参数语义。站点蓝图的"复用 PDG 内容分析 + registry actionClass"部分
  未落地（缺 OBS 通道）。
- **正则补全概率不高、存在真实漏检**：工具参数拆字段存/摘要化时正则漏；`history -c` 命中
  clear_logs 但字符串拼接拆开（`h'is'tory`）可绕过。
- **抗编码绕过已补**（2026-08-24）：labelEvent 现在除原文外对**解码候选**（base64 字面量 /
  URL 编码 / 数值八进制 / 反序，复用 decode.py `_all_candidates`）一起匹配。`echo
  c3VicHJvY2Vzcw== | base64 -d | bash` 现在能命中 execute_file（严重弱化"编码即绕过"）。

| AP | 含义 | 检测来源 |
|----|------|----------|
| reads_credential | 读取凭证文件 | SENSITIVE_READ 正则 + sensitiveKinds |
| network_egress | 网络外传 | EGRESS 正则 + tool actionClass=egress |
| execute_file | 执行文件/脚本 | EXECUTE 正则 + tool actionClass=compute |
| write_file | 写入文件系统 | write 操作检测 |
| delete_file | 删除文件 | rm/unlink 正则 |
| disable_security | 禁用安全工具 | DISABLE_SECURITY 正则 |
| install_persistence | 安装持久化机制 | PERSIST 正则 |
| privilege_escalation | 提权操作 | PRIVILEGE 正则 |
| download_file | 下载文件 | DOWNLOAD 正则 |
| archive_data | 归档/压缩数据 | ARCHIVE 正则 |
| prompt_injection | Prompt 注入 | hasPromptInjection / hasToolResultInjection |
| sensitive_data | 接触敏感数据 | detectSensitiveKinds 非空 |
| lateral_movement | 横向移动 | SSH/scp/rsync 正则 |
| clear_logs | 清除日志 | history/log 清除正则 |
| blocked_by_policy | 被策略阻断 | payload.policyAction=block |
| approved_by_policy | 需要审批 | payload.policyAction=approval |
| allowed_by_policy | 被策略放行 | payload.policyAction=allow |

**标记函数 labelEvent() 复用现有检测能力**（L1 正则 + PDG 内容分析 + registry 工具属性 +
policyAction），不重新实现检测逻辑，保证标签一致性。

> 上表为**站点蓝图口径**（17 个 + policyAction 回注，含未落地的 OBS 通道维度）；
> **实际实现见本节顶部 "实现的 14 个原子命题 + labelEvent 建模范式"**（当前仅正则 +
> 解码候选旁路，无 OBS/registry）。标签函数名在代码中一致，但数据来源与蓝图有差。

### 3.4 LTL 语法与有限迹语义

```
φ ::= p | !φ | φ & ψ | φ | ψ | φ -> ψ | X(φ) | G(φ) | F(φ) | φ U ψ
```

有限迹语义（位置 i 处评估，迹长 n）：

| 算子 | 语义 |
|------|------|
| X(φ) | i+1 存在且 φ 在 i+1 成立 |
| G(φ) | 对所有 j ∈ [i,n]，φ 成立 |
| F(φ) | 存在 j ∈ [i,n]，φ 成立 |
| φ U ψ | 存在 j，ψ 在 j 成立，且 [i,j) 内 φ 一直成立 |

### 3.5 CTL 语法与标记算法

```
φ ::= p | !φ | φ & ψ | φ | ψ | φ -> ψ | EX/AX/EG/AG/EF/AF(φ) | E[φ U ψ] / A[φ U ψ]
```

自底向上标记算法计算 Sat(φ)（AG = ¬EF(¬φ)，AF = ¬EG(¬φ)，不动点迭代）。
**复杂度 O(|S|²×|φ|)**，事件数多时性能下降（站点自认局限）。

### 3.6 LTL 规则 — 11 条（mc-ltl-001~010 + mc-ctl-001 线性降级）

可实现公式 = 攻击存在，在迹位置 0 处（有限迹）评估：
前 10 条为标准 LTL；mc-ctl-001 是 CTL 安全不变量 AG(!clear_logs) 的线性迹降级
（安全不变量在线性迹上 G(!φ) ≡ F(φ) 违规，见 3.7 与 5.4），随 LTL 求值器一并落地。

| ID | 公式 | 描述 | 动作 |
|----|------|------|------|
| mc-ltl-001 | F(reads_credential & F(network_egress)) | 凭证读取后网络外传 | block |
| mc-ltl-002 | F(download_file & F(execute_file)) | 下载后执行 | block |
| mc-ltl-003 | F(disable_security & F(execute_file\|delete_file\|privilege_escalation)) | 禁用安全后破坏性操作 | block |
| mc-ltl-004 | F(prompt_injection & F(network_egress\|write_file\|execute_file)) | 注入后敏感操作 | block |
| mc-ltl-005 | F(reads_credential & F(lateral_movement)) | 凭证读取后横向移动 | block |
| mc-ltl-006 | F(sensitive_data & F(clear_logs)) | 敏感数据访问后清除日志 | block |
| mc-ltl-007 | F(privilege_escalation & F(install_persistence)) | 提权后安装持久化 | block |
| mc-ltl-008 | F(download_file & F(install_persistence)) | 下载后安装持久化 | block |
| mc-ltl-009 | F(sensitive_data & F(archive_data & F(network_egress))) | 敏感数据→归档→外传 | block |
| mc-ltl-010 | F(install_persistence) | 持久化机制安装 | approval |
| mc-ctl-001（降级） | F(clear_logs) | 安全不变量：日志不应被清除（AG(!clear_logs) 线性降级，违反 ⟺ 出现 clear_logs） | block |

### 3.7 CTL 规则 — 5 条（mc-ctl-001~005），仅 mc-ctl-001 有线下降级实现

属性违反 = 攻击存在。**完整 CTL 规格（需分支结构 + policyAction 反馈回路），
当前均未按 CTL 语义实现；其中 mc-ctl-001 已在 3.6 以线性降级落地，其余
（含 AF 活性）见 5.4 第 8 项（语义上有限迹不适合）：**

| ID | 属性公式 | 违反含义 | 动作 |
|----|----------|----------|------|
| mc-ctl-001 | AG(!clear_logs) | 安全不变量：日志不应被清除 | block |
| mc-ctl-002 | AG(prompt_injection -> AF(blocked_by_policy)) | 活性：注入必须被阻断 | block |
| mc-ctl-003 | AG(install_persistence -> AF(blocked_by_policy\|approved_by_policy)) | 问责：持久化必须被管控 | approval |
| mc-ctl-004 | AG(disable_security -> AF(blocked_by_policy)) | 活性：安全禁用必须被阻断 | block |
| mc-ctl-005 | AG(privilege_escalation -> AF(blocked_by_policy\|approved_by_policy)) | 问责：提权必须被管控 | approval |

### 3.8 集成位置与局限

- **决策优先级**：站点 L2.2 (MC) > 站点 L2.1 (PDG) > 站点 L2.1 (行为链) > L1 (单点)。
- **仅当当前事件属于 violation witness 时才返回 block/approval**（避免历史违规误伤当前动作）。
- 站点自认局限：有限迹语义（无法预测未来）、状态爆炸 O(|S|²×|φ|)、原子命题基于正则（有 L1 同样误报）、无 Büchi 自动机（长迹效率低）。

---

## 四、AgentMoss 现状对照（已实现 vs 未实现）

### 4.1 已采用的对应关系

| 站点方案 | AgentMoss 现状 | 差距 |
|----------|----------------|------|
| 行为链 7 条（download→execute 等） | combo_chains 9 条预置链（LISTEN/EXEC/SCAN/CRED/EXFIL/PERSIST/PRIVESC） | 链集不同、无时间窗口 |
| 全局关联 cross-session-credential-staging | P1 跨会话组合链 + PatternMiner + stateful 跨 session | 基本等价且更完整 |
| mc-ltl-001 F(CRED & F(EGRESS)) | P4 □(CRED → ¬◇EXFIL) | 等价 |
| mc-ltl-007 提权→持久化 | 预置链 privesc-cred-exfil 等 | 部分覆盖 |
| sensitive-data-staging（Rule 6） | P2 taint 沿 data 边传播 | 无显式 staging 中间步判定 |
| 17 种原子命题 | 7 种 stage 投影 | 缺 clear_logs/disable_security/download/archive/lateral 等 |

### 4.2 已实现的 formal 引擎能力（现状，L2.2）

- **P1 跨会话组合链**：阶段子序列匹配作用于多 session 拼接图（`properties.py::check_cross_session_chain`）。
- **P2 敏感数据传播**：沿 data 边 taint 传播，凭据文件被共享载体传递到 EXFIL = 数据外传链。
- **P4 no-exfil-after-privesc**：□(PRIVESC → ¬◇EXFIL)；**P5 no-exfil-after-credential**：□(CRED → ¬◇EXFIL)（手写 LTL 形态）。
- **stateful.py**：时间线累积 + 链指针增量推进 + 生命周期（alive/dead/never_activated）+ taint 增量传播。
- **pattern_miner.py**：数据驱动挖掘跨 session 频繁危险组合（低频离线，不进实时路径）。
- **decode.py**：stage 正则匹配前 base64 解码（站点未提的额外防御）。

> **P4/P5 的 EXFIL 与 PRIVESC 判定语义（2026-09，防误报铁律）**：这两个性质的
> `_is_exfil_node` / `_is_privesc_node`（`properties.py`/`properties.ts`）独立于 stage 投影：
> - **EXFIL 排除回环**：`curl http://127.0.0.1`/`localhost`/`::1`/`0.0.0.0` 不算外传（对齐
>   `l2_rules.json` 的 EXFIL stage 回环排除），本地健康检查不再误判；真实外网外传仍拦。
> - **PRIVESC 命令位置判定**：不再裸 `\bsudo\b|\bsu\b` 全文子串匹配，只有段首词是提权命令
>   且命中具体特征才算提权——`echo "sudo ..."`/`grep "setuid"`/`awk '/su -/'`/邮件正文的字面量、
>   `sudo -u postgres`/`su postgres`（非 root）、`sudo apt-get`（装包）均不再误判；真提权
>   （`sudo -u root`/`sudo su`/`sudo bash`/`chmod u+s`/`setcap`/`pkexec`/`su root` 等）仍拦。
>   详见 `L2.2_FORMAL_COMBO_ENGINE.md` §6 性质表后注。

> **stage 投影多命中仲裁（2026-09-07，B.11.5 真机验证发现）**：`match_stage_any`
> （`decode.py`/`decode.ts`）一条动作同时命中多个 stage 时不再按字典序取第一个：
> ①EXEC 目的类调用形态（`subprocess.run(`/`shell=True`/`os.system(` 等）胜出（覆盖
> flask 等内容噪声）；②起服务顶层形态（nohup/http.server/flask run/nc -l）保持 LISTEN；
> ③EXEC 载体类（python3 -c/bash -c）让位给目的性 stage，CRED 不让位。修复真实漏报：
> 「编辑 Flask 文件加 shell=True 后门」被 flask 词抢标 LISTEN → `listener-exec-scan`
> 链 EXEC 缺失 → 收尾步放行。另 `l2_rules.json` EXFIL 第 6 条补回环排除。
> 详见 `L2.2_FORMAL_COMBO_ENGINE.md` B.12 + B.11.5（OpenDesk 端到端验证用例）。

---

## 五、未采用但有效可行的方案

> 依据：与站点 L2.1/L2.2 蓝图逐条对照 AgentMoss 现状（pdg.ts / behavior-chain.ts /
> model-checker.ts / registry.ts / global-analyzer.ts 在仓库中不存在，全仓 grep integrity/
> PDG/格传播零命中），以下为**未落地但可实施**的检测方法，按可行性分级。

### 5.1 分级总表

| 等级 | 方案 | 对应站点 | 依赖 |
|------|------|----------|------|
| 🟢 高可行 | 通用 LTL 有限迹求值器 + 规则公式化 | 站点 L2.2 全部 | 无（P3/P4 已有测试对拍） |
| 🟢 高可行 | integrity 完整性维度 + 低完整性控制命令执行 | Rule 2/4/5 | ActionNode 加标签维度 |
| 🟢 高可行 | 补原子命题：clear_logs / disable_security / download / archive / lateral | 17 AP 补齐 | 正则加 stage |
| 🟢 高可行 | sensitive-data-aggregation（数据源计数 ≥2） | Rule 12 | P2 taint 基础 |
| 🟢 高可行 | Tool Registry 结构化（actionClass 判定精度） | registry.ts | 无（可选增强） |
| 🟡 中可行 | tool-result-injection-to-command / observation→tool flow | Rule 7/14/9/10 | **需 OBS 通道（工具结果内容）** |
| 🟡 中可行 | tool-name-spoofing（LLM 提及 vs 实际调用） | Rule 13 | **需 LLM 输出通道** |
| 🔴 低可行 | CTL 活性属性（AG(φ→AF(blocked_by_policy))） | mc-ctl-002~005 | 需 policyAction 反馈 + 分支结构；有限迹语义不匹配 |

### 5.2 🟢 高可行 + 高价值（建议优先，改动集中在 formal_engine）

**1. 通用 LTL 有限迹求值器，规则公式化**（站点最大卖点）✅ 已实现（2026-08-21）
当前 P3/P4 是手写特定形态（`check_never_exfil_after_privesc` / `check_never_exfil_after_cred`，
即 □(A→¬◇B)），加规则要改 Python + TS 双端代码。已改造成通用有限迹 LTL 求值器
（F/G/X/U/¬/∧/∨ 递归评估，站点已给出完整伪代码），规则全部 JSON 化、双端共用：
- 规则文件：`agent_moss/rules/mc_rules.json`（单一事实源）——11 条规则（mc-ltl-001~010 +
  mc-ctl-001）+ 14 个原子命题正则；双端 `load_mc()` / `loadMC()` 加载。
- 求值器：Python `formal_engine/ltl.py` ↔ TS `formal-engine/ltl.ts`（递归评估，witness 语义
  用"含当前动作成立 / 不含当前动作不成立"判定必要 witness）。
- 已挂接进 `ALL_PROPERTIES`（id=mc-ltl-rules），coordinator L2.2 自动生效。
- 测试：`tests/test_ltl.py`（9 用例，含求值器语义 + 一拦一放 + witness）+ TS `formal-ltl.test.ts`
  （9 用例镜像）；双端全量回归通过；压测验证 verify 性能无回退、FP=0/8。
- 兑现"新增规则只需写公式"：此后加规则只改 mc_rules.json，不动代码。

**2. integrity 完整性维度 + 低完整性控制命令执行（Rule 2/4/5）** ✅ 已实现（2026-08-21）
已落地 integrity 维度与 Rule 5（站点 L2.1 最有区分度的检测之一，critical block）：
- `ActionNode` 新增 `integrity`（high/medium/low）+ `is_low_source` 字段（双端 ir）。
- 低完整性源标记：复用 mc_rules.json 的 download_file / prompt_injection 原子命题
  （单一事实源）——外取/下载/注入内容的动作即 low 源（builder `_mark_integrity`）。
- 传播：沿共享资源迭代传播 min（低处流原则，与 P2 taint 同机制）。
- Rule 5 判定：compute 形态动作（bash/sh -c 执行脚本、python/node 解释执行、
  subprocess/eval/exec；cat/ls 等只读命令不算 compute）且 integrity=low → 拦。
- witness 语义：实时判定只当**当前动作**是 low compute 才判；低频回顾报告历史链。
- 测试：`tests/test_rule5_integrity.py`（7 用例：下载→执行拦 / 下载→只读放 /
  无 low 源放 / witness 反例 + 补全 / 回顾模式）+ TS `formal-rule5.test.ts` 镜像；
  双端全量回归通过；压测 FP=0/8。
- 说明：当前"低完整性源"仅覆盖下载/注入（无需 OBS 通道即可判定）；工具结果
  内容（OBS）驱动的完整完整性传播仍挂在 5.3 第 6 项（根因：缺 tool_result 通道）。

**3. 补原子命题：clear_logs / disable_security / download / archive / lateral** ✅ 已实现（2026-08-21）
已并入 mc_rules.json 的 14 个原子命题（clear_logs / disable_security / download_file /
archive_data / lateral_movement / reads_credential / network_egress / execute_file /
write_file / delete_file / install_persistence / privilege_escalation / prompt_injection /
sensitive_data），并落地规则：
- mc-ltl-003 禁用安全→破坏性操作
- mc-ltl-006 F(sensitive_data & F(clear_logs))（敏感访问后清日志——此前完全无检测）
- mc-ltl-008 下载→持久化
- mc-ctl-001 安全不变量：任何情况禁清日志（AG(!clear_logs) 线性迹降级为 F(clear_logs) 违反）
- mc-ltl-005 凭证读取后横向移动（lateral 是新原子命题）
- mc-ltl-001/002/004/007/009/010 一并落地
⚠️ 正则口径经双端回归校准：install_persistence 收窄为 `crontab -e`/管道写入形态
（裸 `crontab` 查看/带文件参数不误报）；clear_logs 仅匹配 history -c / /var/log/ /
journalctl / logrotate / shred / rm -rf /var/log/（单文件 `rm x.log` 不误报）。

**4. sensitive-data-aggregation（Rule 12）** ✅ 已实现（2026-08-21）
egress 聚合 ≥2 个不同事件源。当前无 OBS 通道，用"共享资源/载体"近似 data_dependency：
EXFIL 节点的资源被 ≥2 个不同事件（session_id, seq 唯一）接触过 → 违规；资源索引 O(N·R)。
- 实现：`properties.py::check_sensitive_data_aggregation` ↔ TS `checkSensitiveDataAggregation`
  （挂进 ALL_PROPERTIES，witness 语义 + 低频回顾）。
- 测试：`tests/test_rule12_aggregation.py`（5 用例：2 源→外发拦 / 单源放 / 非 EXFIL 放 /
  witness 反例 / 回顾模式）+ TS `formal-rule12.test.ts` 镜像；双端全量回归通过；
  压测 FP=0/8、性能无额外增长。

**5. Tool Registry 结构化** ✅ 已实现（2026-08-21）
站点 registry.ts 按工具名查 actionClass / requireHighIntegrity。当前全靠正则分类，
已新增注册表提升 actionClass 判定精度：
- 数据：`agent_moss/rules/tool_registry.json`（单一事实源，双端共用）——bash/shell/
  terminal/cmd/python/node/exec → compute；curl/wget/scp/rsync/nc → network_egress；
  file.read/read_file/cat → read；file.write/write_file/echo → write。
- lookup：Python `lookup_tool_class` ↔ TS `lookupToolClass`（未注册返回 None 回退正则）。
- 接入：Rule 5 的 compute 判定优先 Registry——强类型解释器（python/node/exec/
  terminal/cmd）直接 compute；Registry 明确标 read/write/egress 的动作排除 compute
  （cat/file.read 经 bash 工具运行不算命令执行）；bash/shell 需 detail 命中执行形态
  （bash x.sh、sh -c、subprocess、./script）才算 compute。

### 5.3 🟡 当前不能实现但极具价值的方法（独立说明，待根因解决后补充）

> 以下方法检测价值高（注入检测是 L2.1 最有区分度的检测之一），但**当前数据模型缺
> 关键输入通道，无法真实实现与验证**。按用户要求：每项独立说明其价值、不能实现的
> **具体根因**、以及根因解决后的**补充路径**——不混入"可实现"清单，避免假实现/假测试。

**6. tool-result-injection-to-command（Rule 7/14）、observation→tool-name/param flow（Rule 9/10）**

- **价值**：检测间接注入——恶意工具返回值 → LLM → shell 命令执行（Rule 7/14），
  以及工具结果影响后续工具选择/参数（Rule 9/10）。这是 AgentDojo 场景最核心的
  注入攻击面，block 语义（critical）。
- **当前不能实现的根因**：缺 **OBS 通道（工具结果内容）**。OpenDesk hook 只传
  `action_detail`（命令文本），不传 `tool_result` 内容；`ActionNode`（ir.py）字段 =
  session_id/seq/action_type/action_detail/stage/resources，**无 OBS 字段**（已核实）。
  没有工具输出，"工具结果 → 下游命令"的数据流不存在，规则无从判定。
- **补充路径**：①OpenDesk/AgentGate 侧补传工具输出（如 metadata.tool_result）→
  ActionNode 加 obs 字段 + makeObservationLabel 标签初始化 → 按站点格传播路径
  （Parent OBS → Child TP/T/TN）实现；②在此之前只可做文本级近似（命令文本中内嵌
  的注入关键词检测），但**测的是近似方案不是方案本身**，结论不可外推，故不实现。
- **评估结论（2026-08-21，按"测试有效才实现"原则）**：维持挂起。已核实 ActionNode
  （双端）无 OBS 字段、analyze 签名无 tool_result 参数——数据通道缺失无法真实验证，
  文本级近似会产生"假实现/假测试"（测得不是方案本身）。待 OpenDesk/AgentGate 补传
  工具输出后按上述路径补充实现。

**7. tool-name-spoofing（Rule 13）**

- **价值**：检测 LLM 声称调用工具 A、实际调用工具 B（声称 file.read 实际 curl）——
  对抗性欺骗监控的检测，observe 语义（info）。
- **当前不能实现的根因**：缺 **LLM 输出通道**。需比对 LLM 响应文本中提及的工具名与
  实际 tool_name 节点（兄弟节点对比），但当前事件流只有 a_next 声明（action_type/
  action_detail），无 llm_output 原始文本，无从比对。
- **补充路径**：AgentGate 采集 llm_output 事件 → PDG 构建 LLM 节点 → Rule 13
  兄弟节点对比（LLM 提及工具名 ≠ sibling TN content）→ 按结果定 block/observe。
- **评估结论（2026-08-21）**：维持挂起。事件流只有 a_next 声明（action_type/
  action_detail），无 llm_output 原始文本（已核实 analyze 签名无此参数）——
  兄弟节点对比无从实现，文本级近似无意义。待 AgentGate 补传 LLM 输出后补充实现。

### 5.4 🔴 低可行（语义上有限迹不适合）

**8. CTL 活性属性（mc-ctl-002~005，AG(φ → AF(blocked_by_policy))）**
需 policyAction 反馈回路 + 分支结构（parentEventIds），当前事件流是线性文本；且 AF 在有限迹
上是事后验证（诚实边界：证明对象是观测轨迹，不是状态空间）。不建议做 CTL，但 **AG(!φ)
类安全不变量在线性迹上就是 G(!φ)**，可以并入第 1 项通用求值器。

---

## 六、大体量压测基线（实测 2026-08-21）

### 6.1 测试设施

- **数据生成器** `tests/bench/gen_agent_gate_data.py`：生成 AgentGate 形态 SQLite
  （`tool_calls` 表）+ JSON 目录（`tool_calls/<session_id>.json`）双形态；参数化
  sessions/每 session 动作数/时间跨度/stage 命中率/跨 session 载体流；可复现（--seed）。
  幂等：重复生成覆盖而非追加。
- **压测脚本** `tests/bench/run_bench.py`：经 `agent_gate_reader` 统一加载 → 分档测量
  （累计 N 动作历史）builder/verify 耗时（p50/p95）+ analyze 全链路 FP 采样 + 峰值 RSS；
  单次硬超时（signal alarm）+ 增量落盘 + 膝盖点检测。

**测量方法细节**（为什么这么测）：
- **分档 = 模拟"运行到该积累量时的一次请求"**：档位 1k/5k/10k/20k/50k/100k
  （累计动作数），每档取历史前缀，全量 `FormalEngine.verify`（builder 与 verify 分开
  计时，verify 内部重建图 = 模拟 coordinator 真实调用路径）。
- **单次硬超时 20s**（verify/analyze 均适用）：超过即判"该规模不可行"，不再重复
  （防 O(N²) 拖死压测）；analyze FP 采样另有档内总预算 30s。
- **FP 采样**：从历史末尾取**不命中任何 stage 的良性动作**做 a_next，跑 analyze 全链路，
  统计 decision=Deny 且 violated_layers 含 "L2.2" 的比例 = formal 引擎误报率。
- **膝盖点检测**：某档单次超时即停止加档（当前实现上限）。
- **基线数据** `tests/bench/data/`（gitignored）：3000 sessions / 107,050 动作 / 90 天跨度 /
  stage 密度 5%（贴近真实长期运行）+ 300 条跨 session 载体流。

### 6.2 性能曲线：O(N²) 跨会话边构建是硬瓶颈（已修复）

**修复前（全节点对双重循环，2026-08-21 基线）**：

| 累计动作 | builder | verify 全量 | cross_edges |
|----------|---------|-------------|-------------|
| 963 | 96ms | 97ms | 2,986 |
| 4,967 | 2.0s | 2.0s | 81,733 |
| 9,951 | 8.6s | 9.0s | 338,839 |
| 19,986 | **>20s TIMEOUT** | — | — |

**修复后（按资源哈希分组索引化，O(N·R)，同批数据）**：

| 累计动作 | builder | verify 全量 | cross_edges |
|----------|---------|-------------|-------------|
| 963 | 32ms | 33ms | 2,986 |
| 4,967 | 308ms | 312ms | 81,733 |
| 9,951 | 1.0s | 1.0s | 338,839 |
| 19,986 | 4.5s | 3.6s | 1,401,536 |
| 49,984 | **>20s TIMEOUT** | — | — |

`_add_cross_data_edges`（builder.py）原实现是全节点对双重循环 + 资源集合交集，
动作数翻倍耗时翻 4 倍（O(N²)）。修复为按资源哈希分组（resource → [node_idx...]），
只比较共享同一资源的跨 session 节点对 + 节点对去重 → **构建耗时降 8~16 倍**，
实时规模上限从 ~2 万动作提升到 ~5 万动作。当前 coordinator 每次 analyze 仍全量
重建图（L463 `FormalEngine.verify`）；**剩余瓶颈**：cross_edges **数量**本身随
共享资源密度近似 O(N²) 增长（19986 动作即 140 万条 data 边，内存增量 1.26GB，
峰值 RSS 1.36GB）——下一步应压缩 data 边存储（如按 session 对聚合）或接入
stateful 增量（方案 (a)）。

### 6.2b 实施全程压测基线对比（每批实现后重跑，同批 107,050 动作数据）

| 阶段 | 963 | 4,967 | 9,951 | 19,986 | FP |
|------|-----|-------|-------|--------|-----|
| 基线（修复前） | 93ms | 2.0s | 8.6s | **>20s 超时** | **10/10** |
| +结构性修复（索引化 + witness） | 32ms | 304ms | 1.1s | 4.5s | **0/10** |
| +LTL 规则（mc-ltl/mc-ctl） | 31ms | 247ms | 1.0s | 3.9s | 0/8 |
| +Rule 5（integrity） | 60ms | 388ms | 1.3s | 4.4s | 0/8 |
| +Rule 12（aggregation） | 63ms | 383ms | 1.3s | 4.3s | 0/8 |

表格为 builder 耗时（p50，单次全量 verify 同量级）；每批实现后跑 `tests/bench/run_bench.py`
复测（结果 JSON 存于 `tests/bench/data/results/run_bench_after_*.json`，可复现）。
结论：结构性修复后 FP 从 10/10 降到 0（witness 语义修复历史全局误报）；构建耗时降
8~16 倍、实时上限从 ~2 万提到 ~5 万动作；后续新增规则（LTL/Rule 5/Rule 12）接入后
性能无额外增长（builder 因每节点 label_event 标记 integrity 小幅 +20%，可接受）。

### 6.3 效果：FP=10/10 —— 历史全局匹配导致"永久拒绝锁定"

纯良性 `ls -la` 也被 formal 引擎 Deny，已复现归因：`check_cross_session_chain`
（properties.py L66）对**整个历史**做贪心子序列匹配（cross-listener-exec-scan），
只要历史中随机出现过一次完整链（5% 密度、数万动作下必然发生），后续**所有动作**
（无论是否良性）都被永久拒绝。这是"命中即停 + 历史全局"的语义问题。

**✅ 已修复（2026-08-21，witness 语义落地）**：
- 实时判定（verify 带 a_next）只当**当前动作（图末节点）补全链 / 触发后置外传**
  才判违规（P1/P2/P3/P4 四个 check 全部改造，双端同步）；`MultiSessionGraph` 增
  `witness_idx` 字段，低频回顾（`/api/v1/review` 全量历史，不带 a_next）保留
  "报告历史已形成违规"语义不变。
- eBPF 行为证据（`ebpf-evidence` session）视为当前动作的真实行为，纳入 P3/P4 的
  witness EXFIL 判定（声明 vs 行为交叉校验不丢）。
- **压测复测：FP 从 10/10 降到 0/10**（全档位，良性动作不再被历史链误伤），
  且补全链/凭据后外传等真实攻击场景仍正确拦截（双端单测覆盖，见
  tests/test_formal_observe.py + ts coordinator.test.ts witness 用例）。
- 与站点 L2.2"仅当当前事件属于 violation witness 时才返回 block"对齐。

### 6.4 内存

修复前（全量 verify 超时前的 107k 全加载）：峰值 RSS 增量 ~94MB。
修复后（索引化 + witness，同批数据）：19,986 动作全量 verify 时 cross_edges 达
140 万条，**内存增量 1.26GB（峰值 RSS 1.36GB）**——瓶颈从"边构建耗时"转移到
"data 边数量与存储"（共享资源密度近似 O(N²) 增长）。可接受性取决于单请求历史
规模；商用大体量下需压缩 data 边存储（按 session 对聚合）或接入 stateful 增量。

### 6.4b 性质短路顺序与触发优先级（fail-closed 命中即停）

formal 引擎的 8 个内置性质按 `ALL_PROPERTIES` 顺序逐个执行，**任一性质返回违规
即停**（首个违规 = `first_violation`，后续性质不再评估）：

| 顺序 | 短名 | 性质 ID | 含义 |
|------|------|---------|------|
| 1 | P1 | cross-session-chain | 跨会话组合链（阶段子序列） |
| 2 | P2 | sensitive-data-flow | 敏感数据 taint 沿 data 边传播 |
| 3 | P3 | low-integrity-reachability | 低完整性源沿 data 边多跳跨 session 可达当前动作（下载→改名→执行） |
| 4 | P4 | no-exfil-after-privesc | 提权后任意外传 |
| 5 | P5 | no-exfil-after-credential | 读凭据后任意外传 |
| 6 | P6 | mc-ltl-rules | L2.2 形式化引擎的 LTL 规则（mc_rules.json，witness 语义） |
| 7 | P7 | low-integrity-command-exec | 低完整性控制命令执行（原「Rule 5」） |
| 8 | P8 | sensitive-data-aggregation | egress 聚合 ≥2 事件源（原「Rule 12」） |

**短路含义**：一个同时满足多条性质的动作，会判给**排在最前**的那条（如
"下载后执行"既满足 mc-ltl-002 又满足 Rule 5 时，实际命中 low-integrity，因为
第 7 位优先于第 6 位内的 mc-ltl-002）。**顺序即优先级**：调整顺序会改变违规
的归属性质（不影响是否拦截，但影响 console 展示与理由），改动须双端同步并
回归测试。对应注释标记在 `properties.py` / `properties.ts` 的 `ALL_PROPERTIES`。

### 6.5 测试局限与可信度（结论可外推的前提）

1. **合成数据，非真实 agentgate 数据**：数据由生成器按 `agent_gate_reader` 的真实
   schema（SQLite `tool_calls` 表 / JSON 目录）产出，读回路径与生产一致，但动作分布
   是模拟的。结论方向（O(N²) 性能 + 历史全局匹配 FP）由实现结构决定，真实数据只会
   更复杂，不会推翻这两个结论（且两个问题均已修复并复测，见 6.2/6.3）。
2. **量级未测满**：基线全量 verify 在 **19,986 动作即超时打穿**（>20s），50k/100k 档
   未执行——这本身是"当前实现连 2 万都过不了实时线"的结论。修复后实时上限提升到
   **~5 万动作**（49,984 档超时），10 万动作仍不可全量 verify；剩余瓶颈是 data 边
   数量（6.4），下一步按 session 对聚合或 stateful 增量。
3. **stage 密度 5% 是假设值**：真实 agent 危险形态密度可能更低。修复前"历史全局匹配
   必然命中完整链"在更低密度下只是需要更长历史；修复后 witness 语义使该密度假设
   对 FP 不再敏感（良性动作不再因历史链被拒），仅影响真实攻击的检出时机。
4. **早期 20% 密度的教训**：初始用 20% stage 密度生成，随机凑满组合链导致 FP 全部
   失真（无区分度），改为 5% 后 FP 仍为 10/10——证明 FP 是**语义问题而非数据密度
   问题**（修复后 5% 密度下 FP=0/10，进一步佐证）。
5. **FP 采样口径**：仅统计"良性动作被 formal 引擎（L2.2 层）Deny"为误报；L1/L2 对
   采样良性动作零拦截（violated_layers 无 L1.x/L2.1），故结论聚焦于 formal 引擎。
   修复后复测：全档位 FP=0/10（witness 语义生效），真实攻击场景（补全链/凭据后
   外传）仍正确拦截。
6. **可复现**：生成器 `--seed` 固定随机序列，压测脚本每次全量重跑可对比（改造前后
   基线对比见 6.2/6.3）。

---

## 七、实施路线图

### 7.1 建议落地顺序（每批完成即双端回归 + 跑第六章压测，形成"规则成本表"）

```
第 0 步：测量设施 ✅（tests/bench/）+ formal 引擎 observe 模式（只记录不拦截，灰度 FP 用）
第 5 步（结构性修复）：O(N²) 跨会话边索引化 ✅ + witness 语义 ✅ —— 已完成并双端回归 +
         压测复测（6.2：构建耗时降 8~16 倍、实时上限 ~2万→~5万动作；6.3：FP 10/10→0/10）。
         剩余：data 边数量随共享资源密度 O(N²) 增长 → 内存 1.26GB@2万动作（6.4），
         商用大体量前需按 session 对聚合或接 stateful 增量。
第 1 步：通用 LTL 求值器 + 规则 JSON 化 ✅（P3/P4 之上新增 mc-ltl/mc-ctl 11 条规则，
         见 5.2 第 1 项；测试 tests/test_ltl.py + TS formal-ltl.test.ts；压测性能无回退）
第 2 步：补原子命题 + 规则 ✅（14 个原子命题 + mc-ltl-003/005/006/008 + mc-ctl-001 等
         全部落入 mc_rules.json，见 5.2 第 3 项；正则口径经双端回归校准）
第 3 步：integrity 维度 + Rule 5 低完整性控制命令执行 ✅（ActionNode 加 integrity 标签 +
         共享资源 min 传播 + compute+low 判定，见 5.2 第 2 项；测试双端 7 用例 +
         压测 FP=0/8；OBS 驱动的完整传播挂 5.3 第 6 项）
第 4 步：aggregation（Rule 12）+ Tool Registry 结构化 ✅（Rule 12：egress 聚合 ≥2
         事件源，见 5.2 第 4 项；Tool Registry：tool_registry.json 单一事实源 +
         lookup 接入 Rule 5 compute 判定，见 5.2 第 5 项；双端测试 + 压测 FP=0/8）
🟡 挂起：Rule 7/13/14（OBS/LLM 通道，OpenDesk 侧补传后单独一批，根因见 5.3）
🔴 不做：CTL 活性（AG(!φ) 类降级为 G(!φ) 并入第 1 步）
```

### 7.2 双端同步与测试要求（铁律）

1. **双端同步**：LTL 求值器 / integrity / 新原子命题必须 Python（`agent_moss/engine/`）+
   TS（`ts/src/engine/`）同时改，单端修复 = 没修。
2. **测试归一**：规则 JSON 放 `l2_rules.json`（或新 `mc_rules.json`）单一事实源；新 case
   只改 JSON 双端自动加载，但 **Python `test_all_cases.py` 硬编码 parametrize 必须手动加**；
   agent 专属规则放 `tests/cases/agent/` 自动扫描。每条规则补"一拦一放"两个用例。
3. **同步断言**：双端判定一致性测试（Python `test_all_cases.py::TestOSProfile` 同步断言 +
   TS `dual-parity.test.ts`）随规则改动连带更新。
4. **runtime config 覆盖**：新规则需在 `~/.config/agentmoss/agent_moss_runtime.json` 启用
   才在真实环境生效；测试环境由 conftest 隔离不受影响。
5. **提交规范**：`git add` 只加涉及文件，不带 `Co-Authored-By`。

### 7.3 商用决策依据

第六章压测给出明确信号：**当前全量 verify 路径在大体量下性能不可行 + FP 不可接受**。
商用的前提是 7.1 第 5 步（结构性修复）落地 + observe 模式灰度积累真实 FP 率后，再决定
哪些规则转 block。测试设施（生成器 + 压测脚本）已就绪，支持任何规模的数据模拟与回归对比。


