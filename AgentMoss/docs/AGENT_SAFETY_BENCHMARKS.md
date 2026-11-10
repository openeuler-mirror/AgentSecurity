# Agent 行为安全测试集全景调研

> 本文档汇总当前主流的 AI Agent 安全测试集/基准，聚焦 **tool call 层面的行为安全检测**，可直接用于评估 AgentMoss 三层架构的规则覆盖面。
> 所有引用均经联网核实（arxiv 官网 / GitHub / 官方页面），核实日期 2026-08-04。每个条目标注核实状态：✅ 已核实 / ⚠️ 待确认。

---

## 一、测试集总览（按与 AgentMoss 匹配度排序）

| 测试集 | 发布方 / 年份 | 规模 | 核心聚焦 | 匹配度 | 核实 |
|---|---|---|---|---|---|
| **AgentThreatBench** | UK AISI / 2026 | OWASP Agentic Top 10 可执行任务 | OWASP Agentic 威胁全覆盖 | ⭐⭐⭐⭐⭐ | ✅ |
| **AgentSafetyBench (ASB)** | 2024 | 349 交互环境 / 2000 用例 | 8 类安全风险 + 10 种故障模式 | ⭐⭐⭐⭐⭐ | ✅ |
| **SkillSafetyBench** | 2026 | 6 大风险域 / 30 规范类别 | Skill/插件攻击面 | ⭐⭐⭐⭐⭐ | ✅ |
| **SafeAudit** | 2026 | 25 子类 / 500 用例 | 工具调用安全规则覆盖率审计 | ⭐⭐⭐⭐⭐ | ✅ |
| **AgentHarm** | UK AISI / 2024 | 110 基础 / 440 增强 / 11 类危害 | 恶意 Agent 行为端到端检测 | ⭐⭐⭐⭐ | ✅ |
| **AgentDojo** | ETH Zurich / 2024 | 4 动态环境 + 提示注入集 | 工具返回数据中的间接提示注入 | ⭐⭐⭐⭐ | ✅ |
| **AgentRedBench** | 2026 | 215 SaaS 集成场景 | 授权不足 + 集成安全 | ⭐⭐⭐⭐ | ✅ |
| **FinVault** | 2026 | 31 场景 / 107 漏洞 / 963 用例 | 金融 Agent 安全（执行接地） | ⭐⭐⭐⭐ | ✅ |
| **FinToolBench** | 2026 | 760 工具 / 295 复杂问题 | 金融工具使用合规 | ⭐⭐⭐ | ✅ |
| **TS-Bench / ToolSafe** | 北大 + 上海 AI Lab / 2026 | 基于 4 大数据集，逐步标注 | 工具调用细粒度安全检测 | ⭐⭐⭐⭐⭐ | ⚠️ |
| **AgentShield** | 2026 | 537 用例 / 8 大类 | 商业 AI Agent 安全横向评测 | ⭐⭐⭐ | ⚠️ |

> ⚠️ 标记的两个：TS-Bench/ToolSafe 文档给的 ACL 会议链接待二次确认（arxiv 暂无）；AgentShield arxiv 无收录，疑为商业横向评测而非学术论文，引用时需注明来源。

---

## 二、重点测试集拆解（映射 AgentMoss 三层检测）

### 1. AgentThreatBench — OWASP Agentic 威胁可执行基准 ✅

- **来源**：UK AISI 官方 inspect_evals 框架
- **官方地址**：https://ukgovernmentbeis.github.io/inspect_evals/evals/agent_threat_bench/
- **核心价值**：**第一个将 OWASP Agentic 威胁转化为可执行评测任务的基准**。官方描述即 "Evaluating LLM Agent Resilience to OWASP Agentic Threats"。
- **覆盖威胁**：内存投毒、自主劫持、数据外泄、工具滥用、权限提升、供应链攻击、间接提示注入、多 Agent 信任滥用、输出处理不当、无界消耗
- **测试维度**：同时衡量任务效用 + 安全弹性

**→ 映射 AgentMoss**：与三层架构的 OWASP 对齐直接对应，可作为 AgentMoss 规则覆盖率的外部评测标准。这是"AgentMoss 规则对标 OWASP Agentic 威胁"最有力的第三方背书。

---

### 2. AgentSafetyBench (ASB) — 最全面的 Agent 安全基准 ✅

- **论文**：arxiv.org/abs/2412.14470（"Agent-SafetyBench: Evaluating the Safety of LLM Agents"）
- **规模**：349 个交互环境、2000 个测试用例、评估 16 个主流 LLM Agent

**8 大安全风险类别**：

1. 违反法律/伦理（Violate law/ethics）— 协助违禁品运输等
2. 破坏可用性（Compromise availability）— 错误封禁合法网站等
3. 产生有害/脆弱代码（Contribute to harmful/vulnerable code）— 部署恶意代码
4. 产生不安全信息/错误信息（Produce unsafe information/misinformation）
5. 侵犯隐私（Privacy violation）— 越权获取个人信息
6. 财产损失（Property damage）— 诱导错误金融操作
7. 人身伤害（Physical harm）
8. 声誉损害（Reputational damage）

**10 种常见故障模式**：工具选择错误、参数注入、过度授权、间接提示注入、目标漂移、幻觉驱动操作、上下文污染、多轮诱导突破、信任传递滥用、输出未净化

**→ 映射 AgentMoss**：
- L1 启发式层：8 大风险分类的关键词/模式库
- L2 逻辑规则层：10 种故障模式转化为行为链路规则
- L3 LLM 层：2000 个测试用例可作为评测数据集

---

### 3. SkillSafetyBench — Skill/插件攻击面基准 ✅

- **论文**：arxiv.org/abs/2605.12015（"SkillSafetyBench: Evaluating Agent Safety under Skill-Facing Attack Surfaces"）
- **核心聚焦**：Skill/插件层面的安全风险

**6 大风险域（Risk Domains）**：

| 风险域 | 规范类别 | 对应 AgentMoss 检测层 |
|---|---|---|
| RD1: 上下文信任与提示操纵 | 投毒样本、检索污染、误导性上下文 | L3 LLM 层 |
| RD2: 代理范围与授权风险 | 凭证窃取、破坏性操作诱导、越权访问 | L2 逻辑层 + L1 启发式层 |
| RD3: 执行/运行时/框架/协议风险 | 代码注入、RCE、协议绕过 | L1 启发式层 |
| RD4: 数据与隐私风险 | PII 泄露、数据外泄、训练数据窃取 | L2 逻辑层 |
| RD5: 供应链与完整性风险 | 恶意依赖、投毒插件、签名绕过 | L1 启发式层 |
| RD6: 输出与下游风险 | XSS、SQL 注入、未净化输出 | L1 启发式层 |

**→ 映射 AgentMoss**：与 AgentMoss 的 skill_installation_guard（L3）+ supply_chain（L1/L3）规则天然对齐，可直接补充插件/技能安全检测规则库。

---

### 4. SafeAudit — 工具调用安全规则覆盖率审计 ✅

- **论文**：arxiv.org/abs/2603.18245（"Who Tests the Testers? Systematic Enumeration and Coverage Audit of LLM Agent Tool Call Safety"）
- **核心价值**：**系统性生成测试用例，审计现有安全规则的覆盖率**

**方法论**：
1. LLM 枚举器：系统枚举有效的工具调用工作流和用户场景
2. 规则抵抗度（Rule-Resistance）：从现有基准中提炼紧凑安全规则，识别未覆盖的不安全交互模式

**关键发现**：现有 3 个基准、12 个环境中，**超过 20% 的残余不安全行为未被现有基准覆盖**；覆盖率随规则增加单调增长。

**25 个子类别**：直接有害调用、参数注入、工具链组合攻击、条件触发危害、旁路调用、权限绕过等

**→ 映射 AgentMoss**：可用于审计 AgentMoss 现有规则的覆盖率盲区，指导规则补全方向。其"覆盖率随规则增加单调增长"的发现，正好印证 AgentMoss 三层叠加降低漏报率的设计思路。

---

### 5. AgentHarm — 恶意 Agent 行为基准 ✅

- **论文**：arxiv.org/abs/2410.09024（"AgentHarm: A Benchmark for Measuring Harmfulness of LLM Agents"）
- **开源**：huggingface.co/datasets/ai-safety-institute/AgentHarm
- **发布方**：英国 AI 安全研究所（UK AISI）
- **规模**：110 个基础恶意行为 → 增强至 440 个，覆盖 11 类危害

**11 大危害类别**：网络犯罪、欺诈、骚扰、毒品合成、武器制造、自残/自杀、恐怖主义、性犯罪、人口贩运、环境破坏、动物虐待

**评估指标**：拒绝率（Refusal Rate）、任务完成分数（Task Completion Score）
**关键特点**：端到端测试，Agent 必须在每一步都拒绝，而非仅在首轮拒绝

**→ 映射 AgentMoss**：L1 关键词库 + L2 多步危害意图持续追踪 + L3 有害意图识别

---

### 6. AgentDojo — 间接提示注入基准 ✅

- **发布方**：ETH Zurich SPY Lab / 2024
- **开源**：github.com/ethz-spylab/agentdojo
- **核心聚焦**：工具返回数据中的间接提示注入攻击

**4 个动态环境**：邮件客户端、网页浏览、代码执行、文件系统
**攻击模式**：工具返回的"数据"中嵌入隐藏指令，Agent 将数据内容误当作系统指令执行

**评估指标**：攻击成功率（ASR）、效用（Utility，衡量防御是否过度）

**→ 映射 AgentMoss**：L1 工具返回内容中的指令模式检测 + L2 工具输出→后续调用的因果链校验 + L3 上下文污染检测

---

### 7. AgentRedBench — SaaS 集成安全基准 ✅

- **论文**：arxiv.org/abs/2606.02240（"AgentRedBench: Dynamic Redteaming and Integration-Aware Defense for LLM Agents over SaaS Integrations"）
- **规模**：215 个 SaaS 集成场景
- **核心聚焦**：授权不足 + 集成安全

**→ 映射 AgentMoss**：对应 AgentMoss 的 consent_missing（L2 用户授权检测）与 privilege_escalation（L1/L2 提权检测）规则。

---

### 8. 金融场景测试集 ✅

#### FinVault — 金融 Agent 安全基准（最相关）
- **论文**：arxiv.org/abs/2601.07853（"FinVault: Benchmarking Financial Agent Safety in Execution-Grounded Environments"）
- **规模**：31 个监管驱动沙箱场景、107 个真实漏洞、963 个测试用例
- **特点**：第一个执行接地（execution-grounded）的金融 Agent 安全基准；覆盖提示注入、越狱、金融场景适配攻击、良性输入（用于误报率评估）

#### FinToolBench — 金融工具使用基准 ✅
- **论文**：arxiv.org/abs/2603.08262（"FinToolBench: Evaluating LLM Agents for Real-World Financial Tool Use"）
- **规模**：760 个工具 + 295 个复杂工具依赖问题
- **特点**：分离能力指标（能否调用工具）与合规指标（工具选择是否满足时效性、意图、领域约束）

---

## 三、红队测试框架（可用于生成对抗样本）

| 框架 | 特点 | 对 AgentMoss 的价值 |
|---|---|---|
| **Microsoft PyRIT** | 53+ 数据集，MIT 协议 | 批量生成恶意 prompt，压力测试规则 |
| **Garak** | 120+ 探测模块，编码绕过、DAN、提示注入 | 自动化安全扫描 |
| **Promptfoo** | OpenAI 收购，生产级红队 | 生产环境 AI 系统红队测试 |

> PyRIT（github.com/Azure/PyRIT）、Garak（github.com/leondz/garak）、Promptfoo（github.com/promptfoo/promptfoo）均为知名开源项目，可放心引用。

---

## 四、AgentMoss 规则覆盖面定位

基于上述已核实测试集，AgentMoss 三层规则的覆盖情况：

| AgentMoss 检测层 | 覆盖的测试集风险类别 | 对外可引用的覆盖证据 |
|---|---|---|
| **L1 启发式层** | ASB 8 类关键词、SkillSafetyBench RD3/RD5/RD6、AgentHarm 11 类关键词、AgentThreatBench 工具滥用/供应链 | AgentMoss L1 有 110+ 启发式规则，覆盖危险命令正则、敏感路径、内联脚本 |
| **L2 逻辑规则层** | ASB 10 种故障模式、SafeAudit 25 子类、SkillSafetyBench RD2/RD4、AgentDojo 因果链 | AgentMoss L2 有 8 类逻辑规则（read_before_write、意图一致、提权、授权、间接访问、通配、重定向） |
| **L3 LLM 语义层** | AgentThreatBench OWASP Agentic 全覆盖、AgentHarm 端到端、AgentDojo 间接注入、SkillSafetyBench RD1 | AgentMoss L3 有 13 个 security skill guard，覆盖供应链/钓鱼/邮件/隧道/反弹 shell 等 |

**关键论点**：
1. AgentThreatBench 是 OWASP Agentic 威胁的可执行评测，AgentMoss 的 risk_type 体系与 OWASP 对齐 → **覆盖面有国际标准背书**。
2. SafeAudit 发现"现有基准有 20%+ 残余不安全行为未被覆盖" → AgentMoss 的三层叠加设计正是为压低这类残余漏报（实测 L1+L2 漏报率 8.53%，L1+L2+L3 归零）。
3. AgentMoss 自有 206 个测试用例（见 `tests/cases/README.md`），可进一步用 ASB/SafeAudit 的用例做外部交叉验证。

---

## 五、组合/跨会话攻击检测方案与论文（L2 组合链检测参考）

> 本节补充**组合攻击（多步/跨会话）的检测方案、论文与工具**——这是 AgentMoss L2 层新增
> "组合链检测"规则（`_check_combo_chain`）的设计参考。与上文测试集（评估规则覆盖面）
> 不同，本节聚焦"检测实现"层面的现成方案。核实日期 2026-08-16。

### 5.1 组合攻击现状（web 调研归纳）

| 攻击类别 | 攻击链特征 | 典型载体 | 现有研究/工具 |
|---|---|---|---|
| 直接顺序攻击 | 单会话内逐步组合，单步均无害 | 工具调用序列 | ChainWatch、ChainFuzzer |
| 间接注入链 | 注入藏于外部内容，Agent 读取后触发 | RAG 文档、MCP server 响应 | AgentDojo/AgentDyn/AgentVigil、OWASP Agentic Top10 |
| 混合多阶段攻击 | server 侧操纵 + 注入跨 Agent 传播 | MCP 配置篡改、跨 Agent 调用 | ChainWatch、玄武实验室 Hermes 案例 |
| 跨会话组合攻击 | 多 session 各自独立正常，组合成杀伤链（LISTEN→EXEC→SCAN→CRED） | 持久化记忆、跨会话工具调用 | **AgentMoss 多会话图方案**、A2FV（跨会话攻击归因） |
| OS 层多进程链 | 进程谱系链（MEMEXEC→EXEC、PRIVESC→shell） | syscall 序列 | argus、owLSM、Tetragon |

### 5.2 组合攻击检测框架（论文/工具）

| 来源 | 方法 | 对 AgentMoss L2 的价值 |
|---|---|---|
| **ChainWatch**（arXiv 2607.19432） | MCP 6 阶段 kill chain + HMM 序列分类 + 20 维特征 + 5 条 session 级规则；透明代理架构 | 未防护系统多步攻击成功率 **>90%**；证明 per-call 防御存在结构性盲区；阶段建模思路可直接映射 L2 组合链 |
| **A2FV / SCD-v1** | 跨会话攻击归因：结构+文体残差相关，AUC 0.82 | 证明"跨会话关联"可被代理侧可观测信号识别——多会话图方案的数据依据 |
| **ChainFuzzer**（arXiv 2603.12614） | 灰盒模糊测试工作流级多工具漏洞，source-to-sink 依赖链提取 | 直接+间接依赖（文件/DB 载体）是攻击链传播通道——对应 L2 敏感数据传播链 |
| **Aegis** | 预执行强制层 + Ed25519 签名哈希链审计 | 审计链防篡改（合规证明叙事），500 次调用 1.2% FP |

### 5.3 形式化方法验证 Agent 行为（论文）

| 来源 | 方法 | 关键结论 |
|---|---|---|
| **STEADs**（arXiv 2608.03609） | FO-CTL 验证 agentic 部署 | 通用验证**不可判定**；有限域下 PSPACE-complete——工程落地需"有界安全标记状态"抽象 |
| **HA / Task Lifecycle** | CTL/LTL 30 个时序性质 | safety/liveness/fairness 性质集可复用为 L2 规则的形式化骨架 |

### 5.4 OS 层 eBPF 检测工具

| 工具 | 特点 | 对 AgentGate 的价值 |
|---|---|---|
| **argus**（GitHub DennisPrudlik/argus） | 21 类 eBPF 事件 + syscall attack-chain 规则（MEMEXEC→EXEC、PTRACE→EXEC、PRIVESC→shell）+ 进程谱系 | 进程谱系链检测直接可借鉴；LSM BPF 内核强制 |
| **owLSM**（Cybereason） | eBPF LSM **有状态** Sigma 规则引擎，跨 hook 点关联 | 状态关联 + 强制能力——AgentGate 敏感文件访问策略参考 |
| **Tetragon**（Cilium） | eBPF 运行时观测 + 内核级强制 | 进程/文件/网络监控 + 内核阻断，TOCTOU 免疫 |

### 5.5 攻击知识库（规则形式化基础）

- **MITRE ATLAS**：AI Agent Context Poisoning / Tool Poisoning / Tool Invocation / Credential Harvesting
- **OWASP Top 10 for Agentic Applications 2026**：goal hijacking、memory poisoning、privilege escalation、tool misuse、identity abuse

### 5.6 映射 AgentMoss L2 组合链检测（实现方案）

→ 已落地（2026-08-16）：L2 新增 9 条组合链规则（A 会话内杀伤链 5 条 + D 提权-利用 2 条
+ E 持久化-外联 2 条，7 阶段 LISTEN/EXEC/SCAN/CRED/EXFIL/PERSIST/PRIVESC），
`logic_rules.py::_check_combo_chain` / `logic-rules.ts::checkComboChain`（Rule 8），
链定义在 `l2_rules.json` `combo_chains` 段（单一事实源）。
B 跨会话组合链 / C 敏感数据传播链由独立**形式化引擎**实现（`formal_engine/` 双端）：
行为图（节点=动作，边=时间序/数据流）+ 性质验证（P1 跨会话链子序列匹配 / P2 敏感数据
taint 传播），经 coordinator L2.2 接入，`session_history` 可选参数对接 agentgate。

**agentgate 已接入（2026-08-16）**：AgentGate 侧 V1 normalizer / V3 coordinator（Python）与
TS normalizer / v3 coordinator 均已在发往 AgentMoss 的 payload 中注入 `session_history`
（Repository `get_recent_session_histories` 取最近 5 个其他 session 的 action_history，
排除当前 session；Repository 不可用时留空 → AgentMoss 退化为单 session，向后兼容零回归）。
OpenDesk 经 AgentGate V1 的既有调用、xiaoO 直连 AgentMoss 的调用均不受影响（新增字段可选）。

**双端规则库索引（实现时同步）**：`agent_moss/engine/logic_rules.py`（`LogicRulesChecker._check_combo_chain`）
↔ `ts/src/engine/logic-rules.ts`（`checkComboChain`）；链定义放 `agent_moss/rules/l2_rules.json`
（`combo_chains` 段，Python/TS 共用单一事实源）。形式化引擎：`agent_moss/engine/formal_engine/`
↔ `ts/src/engine/formal-engine/`。用例来源：`tests/cases/l2/` 新增 `combo-*.json` 与
`combo-cross-session-*.json`（一拦一放，双端共用），Python `test_all_cases.py` parametrize
手动登记，TS 自动扫描。

---

## 六、参考来源（均已联网核实）

| # | 测试集 | 来源 | 核实 |
|---|---|---|---|
| 1 | AgentSafetyBench | https://arxiv.org/abs/2412.14470 | ✅ arxiv 实锤 |
| 2 | AgentHarm | https://arxiv.org/abs/2410.09024 | ✅ arxiv 实锤 |
| 3 | AgentThreatBench | https://ukgovernmentbeis.github.io/inspect_evals/evals/agent_threat_bench/ | ✅ 官方页实锤 |
| 4 | SkillSafetyBench | https://arxiv.org/abs/2605.12015 | ✅ arxiv 实锤 |
| 5 | SafeAudit | https://arxiv.org/abs/2603.18245 | ✅ arxiv 实锤 |
| 6 | AgentRedBench | https://arxiv.org/abs/2606.02240 | ✅ arxiv 实锤 |
| 7 | FinVault | https://arxiv.org/abs/2601.07853 | ✅ arxiv 实锤 |
| 8 | FinToolBench | https://arxiv.org/abs/2603.08262 | ✅ arxiv 实锤 |
| 9 | AgentDojo | https://github.com/ethz-spylab/agentdojo | ✅ GitHub 真实项目 |
| 10 | TS-Bench / ToolSafe | https://aclanthology.org/2026.findings-acl.1850.pdf | ⚠️ ACL 会议论文，待二次确认 |
| 11 | AgentShield | 无 arxiv 收录 | ⚠️ 疑商业评测，引用需注明来源 |
| 12 | Microsoft PyRIT | https://github.com/Azure/PyRIT | ✅ 知名开源项目 |
| 13 | Garak | https://github.com/leondz/garak | ✅ 知名开源项目 |
| 14 | Promptfoo | https://github.com/promptfoo/promptfoo | ✅ 知名开源项目 |
