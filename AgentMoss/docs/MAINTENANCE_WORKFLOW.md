# AgentMoss 优化工作流（Agent 操作手册）

> 本文档是给后续 AI agent 会话的操作手册，固化双端同步、测试归一、文档更新的规范，
> 避免每次新会话重复交代背景。**先读完本文档再动手。**

> **脚本分析引擎架构**：改脚本分析相关逻辑前读 [L1.2_L2.3_SCRIPT_ENGINE.md](L1.2_L2.3_SCRIPT_ENGINE.md)
> （引擎三层职责、fail-closed 设计、性能预算、如何扩展新语言）。
>
> **有状态增量行为链引擎**：改有状态组合链验证（stateful）相关逻辑前读
> [L2.2_FORMAL_COMBO_ENGINE.md](L2.2_FORMAL_COMBO_ENGINE.md)（快照验证见主体，
> 增量扩展见**附录 A**：时间线累积、生命周期 alive/dead/never_activated、前序链、
> /api/v1/review 全量回顾、数据不双份存储；
> **PatternMiner 数据驱动发现见其 A.5 节**——挖跨 session 频繁危险组合补预置链盲区）。

---

## 一、项目架构速览

AgentMoss 是**三层防御**的 AI Agent 安全审计引擎，**Python 和 TypeScript 双端实现**，规则逻辑必须双端对齐。

### 三层防御

| 层 | 名称 | 职责 | 短路条件 |
|----|------|------|----------|
| L1 | 特征匹配静态检测 | 正则匹配危险命令 + 注入关键词 + 用户敏感规则 + 敏感路径/危险模式/横向移动（**只看 a_next 本身**）。匹配前先做**路径归一化**（`_normalize_path_segments` / `normalizePathSegments` 折叠 `//`→`/`、`/./`→`/`，跳过协议 URL 与引号字面量），堵路径穿越混淆（对齐 CVE-2023-37274 攻击面） | high/critical → 直接 Deny；medium + file_access（敏感路径写）也 Deny；**其他 medium 不短路走 L3** |
| L2 | 逻辑规则检测 | read_before_write / 意图一致 / 提权 / 授权 / 间接访问 / 通配 / 重定向 | high/critical → Deny |
| L3 | LLM 语义分析 | 结合 Skill 规则 + 前置检测结果做深度判断 | fail-closed（LLM 失败拒）/ fail-open（禁用 LLM 放行） |

### 双端代码对应（修改时必须双端同步）

| 功能 | Python | TypeScript |
|------|--------|-----------|
| 协调器（三层入口） | `agent_moss/engine/coordinator.py` `judge_security()` | `ts/src/engine/coordinator.ts` `runAnalysis()` |
| 分析入口 | `agent_moss/engine/analyzer.py` `analyze()` | （TS 直接调 `runAnalysis`） |
| L1 特征匹配 | `agent_moss/engine/heuristic.py` | `ts/src/engine/heuristic.ts` |
| 路径归一化（L1 前置） | `heuristic.py::_normalize_path_segments` | `heuristic.ts::normalizePathSegments` |
| L2 逻辑规则 | `agent_moss/engine/logic_rules.py` | `ts/src/engine/logic-rules.ts` |
| **形式化引擎（L2.2）** | `agent_moss/engine/formal_engine/`（ir.py / builder.py / properties.py / engine.py） | `ts/src/engine/formal-engine/`（ir.ts / builder.ts / properties.ts / engine.ts） |
| **有状态增量行为链（L2.2-stateful）** | `formal_engine/stateful.py` + `chain_state.py` + `server/agent_gate_reader.py` + `server/routes.py`（`/api/v1/review`、`metadata.stateful_incremental`） | `ts/src/engine/formal-engine/stateful.ts` + `chain_state.ts`（镜像引擎语义；HTTP/`review` 仅 Python 侧）；AgentGate 侧 `moss-client.ts` `callAgentMossReview` + `coordinator.ts` `maybeTriggerReview` + `storage/db.ts` `getAgentGateDbPath` |
| **数据驱动模式挖掘（PatternMiner）** | `formal_engine/pattern_miner.py` + `tests/test_pattern_miner.py` | `ts/src/engine/formal-engine/pattern_miner.ts` + `ts/src/__tests__/formal-pattern-miner.test.ts`（接入 `/api/v1/review` 的 `discovered_patterns`，低频离线挖跨 session 频繁危险组合，不进实时路径；语义见 L2.2_FORMAL_COMBO_ENGINE.md A.5） |
| 内联脚本分析 | `agent_moss/engine/inline_analyzer.py` | `ts/src/engine/inline-analyzer.ts` |
| **脚本分析引擎** | `agent_moss/engine/script_engine/`（ir.py / tracker.py / backends/） | `ts/src/engine/script-engine/`（ir.ts / tracker.ts / backends/） |
| 脚本内容分析（facade，兼容旧入口） | `agent_moss/engine/script_content_analyzer.py` | `ts/src/engine/script-content-analyzer.ts` |
| LLM 分析器 | `agent_moss/engine/llm_analyzer.py` | `ts/src/engine/llm-analyzer.ts` |
| Prompt 模板 | `agent_moss/templates/*.txt` + `infra/prompt_templates.py` | `ts/src/engine/template-loader.ts` |
| **归一化规则数据（单一事实源）** | `agent_moss/rules/l1_rules.json` / `l2_rules.json` / `l3_rules.json`（Python 与 TS 共用） | 同左 |
| 规则加载器 | `agent_moss/rules_loader.py` | `ts/src/infra/rules-loader.ts` |
| OS Profile（组装规则） | `agent_moss/profiles/linux.py`（从 JSON 加载） | `ts/src/engine/heuristic.ts` / `logic-rules.ts`（从 JSON 加载） |
| 用户自定义规则 | `agent_moss/rules/user_rules.json` | `ts/src/config.ts`（`loadCustomRules`） |
| Brain 规则仓库 | `agent_moss/brain/rule_store.py`（SQLite） | `ts/src/brain/rule-store.ts`（JSON） |
| Brain 模式提取 | `agent_moss/brain/pattern_extractor.py` | `ts/src/brain/pattern-extractor.ts` |
| Brain 维护 | `agent_moss/brain/curator.py` | （TS 未实现 curator，规则激活靠 Python 侧） |

---

## 〇、Brain 自学习机制（开发中，默认关闭）

> **Brain 默认关闭**：仅当显式设置 `AGENT_MOSS_BRAIN_ENABLED=1`（env 或 agent_moss_settings.json）时启用。
> 开发中的机制默认开着会污染 L1/L2 判定与 L3 prompt，故默认关闭。

### 工作方式

1. **提取**：L3 判定 Deny 且 `confidence >= 90` 时，coordinator 调用 `PatternExtractor.extract()`，
   从 `action_detail` + LLM `reason` 中提取敏感路径/危险命令 pattern。
2. **去重**：内置规则（profile dangerous_commands / sensitive_paths / runtime_config L1 规则）
   已覆盖的 action_detail 跳过，避免沉淀与 L1/L2 重复的冗余规则。
3. **候选制**：新 pattern 进 `pattern_candidates`，达到 `min_occurrences`（默认 3）才进入后续。
   避免单次 LLM 幻觉路径污染。
4. **LLM 审核（quality gate）**：候选达到阈值后调一次 LLM 判定"是否值得沉淀"——
   - 通过 → 沉淀 draft 规则 / skill
   - 拒绝 → pattern 标记 `rejected`，**永久排除**（不再消费审核 token，后续提取直接跳过）
   - LLM 不可用 → 降级"保留候选但不沉淀"（不退化为拒绝，也不强制沉淀）
   这是**防机械提取消误报的关键**：正则只看字面特征，无法判断 `/opt/app/config/deploy` 是
   敏感目录还是用户正常路径；LLM 审核能区分（真实 LLM 验证：源码路径 conf=95 拒绝、
   密钥外传 conf=82 保留）。开关 `AGENT_MOSS_BRAIN_REVIEW=0` 关闭（回到旧自动沉淀）。
5. **自动激活**：coordinator 节流（300s）调用 `BrainCurator.run_maintenance(auto_approve=True)`，
   draft → approved → active，形成"提取 → 审核 → 生效"学习闭环。
6. **纠错**：规则被质疑（dispute）达阈值自动降级 stale；长期未触发 → stale → archived。

### 双端差异说明

- **存储统一为 JSON 文件**（对齐 runtime_config 范式，鸿蒙 PC 等无 sqlite3 环境可运行）：
  - Python：`~/.agentmoss/brain/rules.json` + `skill_meta.json`
  - TS：`~/.agentmoss/brain/rules.json`（env `AGENT_MOSS_BRAIN_RULES_PATH` 覆盖，测试隔离用）
  - 存量 SQLite（`rules.db`/`skill_meta.db`）**首次加载自动迁移**到 JSON，旧库备份 `.db.bak`；
    环境无 sqlite3 时静默跳过迁移（直接用空 JSON 库）。
- TS 未实现 curator（自动激活只在 Python 侧跑）；TS 匹配逻辑（`checkBrainRules`）与 Python
  `_check_brain_rules_layer` 语义一致（combined = `actionType + ' ' + actionDetail` + re.search）。
- **锚定铁律**：brain 泛化 pattern **禁止 `^`/`$` 锚定**（coordinator 拼接匹配下永远匹配不到，
  历史 bug：DB 里唯一 active 规则 trigger_count=0）。统一用 `(?:^|[^a-z0-9_-])` 边界。

### 贡献（contribute）：把本地沉淀回流为 PR

Brain 沉淀的规则/skill 是**本地私有**的（存在 `~/.agentmoss/brain/`）。要让它们回流到共享仓库
统一维护，用 `agentmoss brain contribute`：

```bash
# 导出本地 active+llm_extracted 规则与 local skill → push 到"你的 fork" → 引导建 MR
agentmoss brain contribute
# 显式指定 fork 用户名 / 分支
agentmoss brain contribute --fork-user <你的gitcode账号> --branch my-contrib-1
# 设 token 后自动建 MR（GitLab 风格 API）
AGENT_MOSS_CONTRIBUTE_TOKEN=<token> agentmoss brain contribute
```

**流程约定（重要）**：
- **push 目标 = 当前用户自己的 fork**（`ssh://git@atomgit.com/<user>/AgentMoss.git`），不是共享仓
  `kenhkl/AgentMoss`（私仓，非 owner 无 push 权限）。MR 从 fork 分支指向共享仓 master。
- **无权限路径**：`ls-remote` 探测失败 → 提示用户先网页 fork；对私仓访问受限 →
  邮件申请（kenhkl11@hotmail.com，注明 gitcode 账号 + 理由）。
- 默认只贡献 `active + llm_extracted/user` 的规则、`active + local` 的 skill；
  中心下发（origin_node=central）的**不**回流。
- 实现：`agent_moss/brain/contributor.py`。

### 中心化上传（预留，不实现）

曾计划"本地 brain 规则/skill 上传到中心服务器统一分发"——**本期不实现**，但接口已预留：
- 导出格式（`collect_rules`/`collect_skills`）与 `import_rules`/`import_skills` 协议兼容，
  未来接中心服务器只需把 contributor 的"push 分支"替换为"POST 到中心 API"。
- `BrainRule.source` / `BrainSkill.origin_node` 已区分 `local` vs `central`，中心返还的数据
  天然被本地的"不回流 local→central"过滤区分。

### 验证命令

```bash
# Python brain 单测（22 个）
AGENT_MOSS_DISABLE_LLM=1 python3 -m pytest tests/test_brain.py -q
# TS brain 单测（12 个，含双端 generalize 对拍）
cd ts && AGENT_MOSS_DISABLE_LLM=1 npx vitest run src/__tests__/brain.test.ts
```

---

## 二、核心原则：双端同步

**规则数据修改只需改一份归一化 JSON**（`agent_moss/rules/l1_rules.json` / `l2_rules.json` / `l3_rules.json`），Python 与 TS 加载器自动取到相同数据，不再需要双端同时改数据。

**匹配行为/逻辑修改仍需双端同时改**（`_is_write_operation`、敏感路径边界/转义、各检测器逻辑），因为这是各端代码。改完必须验证双端行为一致。

单端修复 = 没修。双端不一致会在生产环境（OpenDesk 用 TS、xiaoO 用 Python）产生分歧判定。

### 验证双端一致的命令

```bash
cd ~/gitcode/AgentMoss

# Python 全量（禁 LLM，CI 友好）
AGENT_MOSS_DISABLE_LLM=1 python3 -m pytest tests/test_all_cases.py -q

# TS 全量（禁 LLM）
cd ts && AGENT_MOSS_DISABLE_LLM=1 npx vitest run src/__tests__/heuristic.test.ts src/__tests__/logic-rules.test.ts src/__tests__/json-cases.test.ts

# PatternMiner 单测（双端各 6 个，改 pattern_miner 逻辑后跑）
AGENT_MOSS_DISABLE_LLM=1 python3 -m pytest tests/test_pattern_miner.py -q
cd ts && AGENT_MOSS_DISABLE_LLM=1 npx vitest run src/__tests__/formal-pattern-miner.test.ts

# 真跑 L3（需有效 LLM key，验证 LLM 判定对齐）
AGENT_MOSS_LLM_API_KEY="sk-xxx" AGENT_MOSS_LLM_BASE_URL="http://host:port/v1" AGENT_MOSS_LLM_MODEL="GLM-5.2" \
  python3 -m pytest "tests/test_all_cases.py::TestLayer3::test_llm_cases[<case-file>.json]" -v

cd ts && AGENT_MOSS_LLM_API_KEY="sk-xxx" ... npx vitest run src/__tests__/json-cases.test.ts -t "<case-id>"
```

**双端绿的标准**：Python passed 数与 TS passed 数反映同一批 JSON case（差异只在各端手写单测多寡——Python 的 `test_agents_*`/`test_brain` 等、TS 的 `heuristic.test`/`logic-rules.test` 等——**真实独立 JSON 用例数应一致**，passed 总数差异不代表规则不一致）。

**双端同步校验测试（防规则漂移）**：

**规则数据看护**（断言 JSON 可加载、计数稳定、profile/常量 与 JSON 一致）：
- Python `tests/test_rules_loader.py`
- TS `rules-loader.test.ts`

**行为同步校验**（断言双端匹配语义对齐，改行为逻辑须连带更新）：
- Python `test_all_cases.py::TestOSProfile::test_linux_profile_rule_sync_with_ts`（L1 危险命令关键规则）
- Python `test_all_cases.py::TestOSProfile::test_linux_profile_sensitive_paths_sync_with_ts`（关键敏感路径 + 凭据 deny_both）
- TS `dual-parity.test.ts`（isWriteOperation / DANGEROUS_PATTERNS / 敏感路径三段）

> **改规则数据（JSON）**：改 `agent_moss/rules/*.json` 一处即可，两端自动生效。改后跑上述「规则数据看护」测试确认计数稳定。
> **改敏感路径**：仍在 JSON 的 `sensitive_path_access` 段改，注意保留 `scope`（root/home/credential）与 `deny_mode` 字段，且要补"一拦一放" JSON 用例。

> **路径归一化（NORM-PATH）**：L1 匹配敏感路径/危险命令前，经 `_normalize_path_segments` / `normalizePathSegments` 折叠路径混淆段（`//`→`/`、`/./`→`/`），堵路径穿越变体（对齐 CVE-2023-37274：`cat /etc//shadow`、`echo x > ~/.ssh//authorized_keys` 绕过子串匹配）。改此逻辑必须**双端对称**（Python `heuristic.py` / TS `heuristic.ts`），且注意**不误伤**：跳过协议 URL（`http://`）与引号内字面量（`grep "a//b"`）。补"一拦一放"用例：拦 `//` 混淆路径、放 URL/引号字面量。

### ⚠️ runtime config 会覆盖源码（敏感路径/规则的坑）

**运行时优先读 `~/.config/agentmoss/agent_moss_runtime.json`**（用户本地持久化，不在 git，优先级高于 profile 默认值）。`_get_sensitive_paths` 若检测到 runtime config 存在，会用其中的 `L1_rules.sensitive_path_access.rules`（含用户 enabled 开关）**覆盖**源码 profile 默认值。

改 JSON 规则后，若该环境 runtime config 里对应项 `enabled:false` 或缺失，则**真实运行时不生效**（JSON 对、运行不对的割裂）。已发生：`.aws/credentials`/`.gitconfig`/`.gnupg` 在 runtime config 里 `enabled:false`，导致改了规则后本机仍不拦截。

- **判断**：`has_runtime_config()` 为 True 即受影响。
- **验证真实运行**：不要只跑测试（conftest.py 会 `_isolate_runtime_config` 屏蔽 runtime），要**不屏蔽**直接 `analyze()` 确认。
- **修复**：在 runtime config 里启用对应项（`enabled:true`）或重新生成 runtime config；或用户在 console 里改。
- **测试环境（源码仓跑测试不受 runtime 污染，2026-09 加固）**：
  - **Python**：`tests/conftest.py` 两个机制——① 顶部模块级设 `AGENT_MOSS_DATA_DIR` 指向临时目录（隔离 data_root 下 runtime/config/skills/rules fallback）；② `_isolate_runtime_config` autouse fixture 让 `has_runtime_config()` 恒 False。测试永远基于源码规则 + profile 默认，不受本机 runtime 污染。这是设计行为，别去掉。
  - **TS**：`ts/vitest.config.ts` setupFiles 加载 `ts/src/__tests__/setup.ts`——测试进程启动时把 `AGENT_MOSS_DATA_DIR` 指向临时目录，`hasRuntimeConfig()` 恒 false、rules-loader 恒用源码（`RUNTIME_CONFIG_DIR` 是模块级常量，所以必须在 setup 而非测试体内设 env）。
  - **dev 手工/CI 确认**：即使没有上面两层，`AGENT_MOSS_DATA_DIR=/tmp/xxx pytest ...` / `... vitest run` 也能手动隔离（ENV_VARS.md 已记录该 env）。
  - **逃生门（验证真实运行需显式跳隔离）**：`AGENT_MOSS_TEST_USE_RUNTIME=1` 时 conftest/setup **跳过** data_dir 隔离，测试进程用真实 `~/.config/agentmoss`（等价于行 189 的"不屏蔽直接 analyze()"）。默认不加此 env 即为隔离态。同时注意：**脱离 pytest 的裸 `python3 -c`/`tsx` 不加载 conftest/setup**，天然是真实 runtime——若想验证真实行为，直接这样跑即可，不需要逃生门。
  - 判断是否真隔离：`has_runtime_config()`/`hasRuntimeConfig()` 为 False；若开发者本机 runtime 与源码分叉（如 dangerous_commands 57 vs 55 条），测试隔离后稳定复现源码预期。

### TS 编译检查

每次改 TS 后先确认编译通过：

```bash
cd ts && npx tsc --noEmit
```

---

## 三、测试用例归一化

**测试用例是单一事实源**：`tests/cases/` 下的 JSON case 被 Python 和 TS 共用，双端加载器都读同一批文件。

### 目录结构

```
tests/cases/
├── l1/    # L1 特征匹配（161 个）：deny-* + allow-* + inline-*
├── l2/    # L2 逻辑规则（25 个）：logic-*（read_before_write/意图/提权/授权/间接/通配/重定向）
├── l3/    # L3 LLM 语义（28 个）：llm-*（llm_required:true）
├── agent/ # Agent 专属规则（9 个）：agent-<agent_id>-NN，input.agent_id 指定 xiaoo/opendesk
└── scenario/<id>/  # 场景定制规则（9 个）：子目录名即 scenario_id（如 scenario/bank/ → bank）
```

**`agent/` 子目录（agent 专属规则看护）**：通用 l1/l2/l3 用例跑 `agent_id` 空（通用模式），不加载 agent 专属规则。xiaoo/opendesk 的定制规则（读 `xiaoo.env`、guardian 目录写保护、绕过审计注入词、opendesk 白名单工具）只对特定 `agent_id` 生效，故独立成 `agent/` 子目录。每个用例 `input.agent_id` 须与 `agent_moss/agents/<id>/rules.json` 的 `agent_id` 一致。双端自动加载（TS `json-cases.test.ts` 扫 agent/ 目录；Python `TestAgentCases` 扫 agent/ 目录）。改 agent 规则时同步补/改 `agent/` 用例（一拦一放 + 无 agent_id 对照防污染）。

**`scenario/<id>/` 子目录（场景定制规则看护）**：场景规则是**客户沙箱部署级约束**（如招行 bank：允许读写 `/home/sandbox`、`/opt/sandbox`、`/tmp`，其他根目录禁止读写；禁 ssh 命令），只对特定 `scenario_id` 生效，故独立成 `scenario/<id>/` 子目录（子目录名即 scenario_id）。每个用例 `input.scenario_id` 须与 `agent_moss/scenarios/<id>/rules.json` 的 `scenario_id` 一致。启用判定：显式 `scenario_id` > 环境变量 `AGENT_MOSS_SCENARIO`（部署级，客户沙箱设一次，所有请求生效）。双端自动加载（TS `json-cases.test.ts` 递归扫 scenario/ 目录；Python `TestScenarioCases` 扫 scenario/<id>/ 目录）。改场景规则时同步补/改 `scenario/<id>/` 用例（一拦一放 + 无 scenario_id 对照防污染）。

### JSON case 字段

```json
{
  "id": "AGENTMOSS-DENY-01",          // 序列号，DENY/ALLOW/LLM 前缀只是编号标签不是语义
  "desc": "...",                      // 中性描述，不要暗示与 expected_decision 矛盾的方向
  "scenario": "...",                  // 攻击/正常场景说明
  "expected_decision": "Deny",        // 最终判定（Allow/Deny），这才是断言依据
  "expected_layers": ["L1.1"],      // 期望命中的层（L1.x/L2.x 短路时填；L3 Allow 时必空，不断言）
  "expected_risk_level": "critical", // 期望风险等级
  "expected_risk_type": "...",       // 期望风险类型
  "llm_required": true,              // L3 case 必填 true；禁 LLM 时 it.skip
  "note": "...",                     // 判定逻辑说明（哪层命中/为何放行/LLM 判定依据）
  "input": {
    "session_id": "...",
    "prompt_session": "",             // 用户原始意图（L3 判定的重要输入）
    "action_history": [],             // 历史动作（read_before_write 等需要）
    "a_next": { "action_type": "bash", "action_detail": "..." },
    "reason": "..."                   // 执行理由
  }
}
```

### 双端加载器差异（关键！）

| 端 | 加载方式 | 新增 case 时要做什么 |
|----|----------|----------------------|
| **TS** | `json-cases.test.ts` 自动扫描 `cases/*/*.json` | 只加 JSON 文件，自动加载 |
| **Python** | `test_all_cases.py` 的 `TestLayer1And2` 是**硬编码 parametrize 列表**；`TestLayer3` 也是硬编码列表 | 加 L1/L2 case 要手动加到 `test_deny_cases`/`test_allow_cases` 的 parametrize 列表；加 L3 case 要加到 `TestLayer3` 的 parametrize 列表 |

**易错点**：加新 L1/L2 case 只改 JSON 不改 Python parametrize 列表 → Python 跑不到该 case（TS 能跑到），双端覆盖不一致。

### 新增用例的正确流程

**先保证用例正确，再根据用例修复代码。** 不能为了"让测试通过"改期望值（削足适履）。

1. **构造场景**：基于真实攻击/运维场景写 `action_detail`，明确该 Deny 还是 Allow
2. **先跑当前代码**看实际判定，如果与预期不符，**先确认预期是否正确**（对照同类已有 case、对照安全语义），再决定是改代码还是改预期
3. **命中（Deny）用例**配**对照放行（Allow）用例**：**每条规则改动必须补"一拦一放"两个用例**（命中 + 类似但不命中，防规则过宽/过窄），避免单点。不要只加一个方向。
4. **加完 JSON 必须同步做两件事**：① 把新 case 加进 Python `test_all_cases.py` 的 `test_deny_cases`/`test_allow_cases` 参数化列表（TS 自动扫描不用管）；② 若改了敏感路径/危险命令，检查双端同步断言（`dual-parity.test.ts` / `test_linux_profile_*_sync_with_ts`）是否需要同步更新。
5. **L3 用例**：L1 medium 不短路走 L3 的场景，expected_decision 取决于 LLM 判定——**必须真跑 LLM 确认**，禁 LLM 只能 skip 不能算验证
6. **id 命名**：L3 case 用 `AGENTMOSS-LLM-NN`（对齐 llm-01~23），不要用 `DENY-NN`（llm-24/25 是历史遗留，id 与 expected_decision 矛盾易误导）
7. **Agent 专属规则用例**：改 agent 规则（`agent_moss/agents/<id>/rules.json` 的 `extra_*`/`builtin_safe_*`）时，在 `tests/cases/agent/` 补用例（TS/Python 都自动扫 agent/ 目录，无需手动加 parametrize）。要点：
   - `id` 用 `AGENTMOSS-AGENT-<AGENTID>-NN`，`input.agent_id` 填实际 agent id（xiaoo/opendesk）
   - **一拦一放**：命中用例（Deny）+ 无 agent_id 对照（Allow，验证 agent 规则不污染通用模式）
   - opendesk 白名单：验证白名单工具放行（Allow）+ 非白名单危险命令仍拦（Deny，白名单不豁免危险）
8. **场景定制规则用例**：改场景规则（`agent_moss/scenarios/<id>/rules.json` 的 `extra_*`，客户沙箱部署级约束如 bank 目录白名单/禁 ssh）时，在 `tests/cases/scenario/<id>/` 补用例（TS/Python 都自动扫 scenario/ 目录，无需手动加 parametrize）。要点：
   - `id` 用 `AGENTMOSS-SCENARIO-<ID>-NN`，`input.scenario_id` 填实际场景 id（bank）
   - **一拦一放**：命中用例（Deny，如 bank 的 `cat /etc/passwd` 命中目录白名单外、`ssh root@…` 命中禁 ssh）+ 放行用例（Allow，允许目录内 `cat /home/sandbox/data.txt`）+ 无 scenario_id 对照（Allow，验证场景规则不污染通用模式）
   - **双端同步**：场景规则是 AgentExtensions 结构，Python `get_scenario_extensions` ↔ TS `getScenarioExtensions` 共享同一份 rules.json；引擎接线 `analyze`/`judge_security`/`runAnalysis` 的 `scenario_id` 参数与 `AGENT_MOSS_SCENARIO` env 兜底双端一致；console「场景定制」页（Python `console/router.py` + TS `console/router.ts`）与 runtime_config `scenario_rules` 分区（种子/合并/启停）双端同步。`AGENT_MOSS_SCENARIO` 支持**逗号分隔多场景**（如 `bank,meow`），批量加载时用 Python `get_scenario_extensions_multi` ↔ TS `getScenarioExtensionsMulti`（append 合并）；显式 `scenario_id` 仍是单值最高优先
   - **cases_exec 联动**：生成器 `--scenario <id>` 提取对应子目录并透传 scenario_id 静态判定；prep.sh/run_all.sh 的 `--scenario`/`--agent` 参数透传

---

## 四、文档同步（每次规则改动必做）

改完代码和测试后，检查并更新这两份文档：

### 1. `SECURITY_RULES.md`（规则说明书）

记录每条规则的：判断依据（正则/逻辑）、风险等级、攻击场景、修复历史（NEW-FP-*/NEW-FN-* 编号）。

- 加新规则 → 加节，标注 `linux.py:行号` / `heuristic.ts:行号`
- 修 bug → 在对应规则节加 `NEW-FP-X`（误报修复）/ `NEW-FN-X`（漏报修复）说明，写清修复前现象 + 根因 + 修复后
- 编号约定：FP = False Positive（误报，该放行却拦了），FN = False Negative（漏报，该拦却放了）

### 2. `SECURITY_REGEX_LIST.md`（正则完整清单）

一行一条列出所有**执行正则匹配**的规则（路径串、关键字串等非正则不在内）。

- 改了正则 → 更新对应行
- 规则从正则改成 token 化逻辑 → 把旧正则行改成逻辑描述（如横向移动节）
- 新增正则 → 加行

### 3. `tests/cases/README.md`（用例统计）

记录用例总量、分类、场景归类、通过率、计数口径（Python/TS passed 数差异原因）。**加 case 后更新总数**（当前 214 个）及顶部"精确分解"表、场景分布表相应行。

---

## 五、提交规范

```bash
# 只 add 本次改动的文件（先 git status 确认，避免误提交临时文件/无关改动）
git add agent_moss/engine/logic_rules.py ts/src/engine/logic-rules.ts \
        tests/cases/l2/logic-19-privilege-grep-literal.json \
        tests/test_all_cases.py ts/src/__tests__/logic-rules.test.ts \
        SECURITY_RULES.md SECURITY_REGEX_LIST.md tests/cases/README.md \
        docs/MAINTENANCE_WORKFLOW.md
git commit -m "fix: NEW-FP-X/FN-X 双端修复——简述

详细说明（每处修复：修复前现象 + 根因 + 修复后 + 测试覆盖）：

1. NEW-FP-X: ...
2. NEW-FN-X: ...

双端全量回归: Python N passed N skipped | TS N passed N skipped | 0 failed
文档同步: SECURITY_RULES.md + SECURITY_REGEX_LIST.md（...）

```

**要点**：
- **不要 `git add -A`**：只 add 本次优化/修复实际改动的文件（代码 + 测试 + 文档）。
  先 `git status --short` 核对清单，确认没有临时文件（`*.swp`、`dist/`、测试副产物 brain 文件等）混入。
- **临时文件要在提交前清理**：优化/修复过程中产生的临时文件（vim swp、日志、LLM 副产品如 `brain_*.md`、`*_guard.md` 测试残留）应删除，让工作树只保留本次改动的正式文件。无法确认是否该删时先问用户。
- commit message 带 `双端` 字样 + 双端回归数字
- **不带 `Co-Authored-By` 行**（用户偏好，除非用户明确要求）
- 一处修复一个 commit，不要把多个不相关的修复堆一个 commit
- 提交前确认工作树干净（`git status`），L3 case 真跑的期望值改动要单独 commit

---

## 六、LLM 真跑注意事项

L3 case（`llm_required: true`）必须配有效 LLM key 真跑才能验证，禁 LLM 只 skip。

### L3 判定策略（双端统一：判定源 + 连通性探测）

L3 是否真跑由**统一判定源 + 连通性探测**决定，双端逻辑对称，避免两端判定不一致和「坏 key 假通过」：

1. **判定源**：读 `AGENT_MOSS_LLM_API_KEY` env → 否则读 `~/.config/agentmoss/config.json` 的 `llm.api_key`（Python 走 `get_default_config().llm.api_key`，TS 走 `isLLMAvailable()`，两者已融合 env + config.json + provider env）。
2. **连通性探测**：有 key 再发一次 `max_tokens=1` 的 ping（Python `_probe_llm` / TS `probeLLMConnection`）。连通才真跑 L3；key 无效 / 网络不通 → **明确提示 + skip**，绝不真调 LLM 走 fail-open 假通过。
3. **探测与真跑同源**：probe 用的 base_url/model/api_key 与 L3 实际调用一致，probe 通过即真跑可信。

实现位置：Python `tests/conftest.py` 的 `llm_probe_available` fixture（session 级缓存，只 ping 一次）；TS `ts/src/config.ts` 的 `probeLLMConnection()` + `json-cases.test.ts` 的 `beforeAll`。

### 真跑命令

```bash
# Python 单个 L3 case（key 已从 env/config.json 统一判定+探测，无需手动传）
timeout 120 python3 -m pytest "tests/test_all_cases.py::TestLayer3::test_llm_cases[llm-NN-xxx.json]" -v

# TS 单个 L3 case（需 120s timeout，默认 5s 超时）
cd ts && timeout 180 npx vitest run src/__tests__/json-cases.test.ts -t "llm-NN"
# 若需环境变量覆盖 config.json，仍可显式传：
#   AGENT_MOSS_LLM_API_KEY="sk-xxx" AGENT_MOSS_LLM_BASE_URL="http://host:port/v1" AGENT_MOSS_LLM_MODEL="GLM-5.2"
```

### TS L3 timeout（已修）

`json-cases.test.ts` 对 `llm_required && isLLMAvailable()` 的 case 设 120s timeout（默认 5s 不够 LLM 调用）。

### L3 期望值判定原则

L3 case 的 `expected_decision` 取决于 LLM 对意图的判断，不是机械的"命中规则就 Deny"：

- **L1 high/critical 短路 Deny**：如 `ssh + cat /etc/shadow`（敏感路径 high）
- **L1 medium 不短路走 L3**：如 `git push --force`（medium）、`rsync remote:/dest`（横向移动 medium）、`ssh -D 隧道`（medium）
  - L3 LLM 判 Allow：无恶意证据的运维场景（推代码、同步部署）→ expected Allow/medium
  - L3 LLM 判 Deny：有攻击证据（建隧道内网漫游、窃密、DROP DATABASE）→ expected Deny/critical
- **禁 LLM 时 L3 case fail-open 放行**（Allow/low），这是设计行为，不是漏报

### L3 测试断言盲点（已知）

`TestLayer3.test_llm_cases` **只断言 `expected_decision`**，不断言 `expected_layers`/`violated_layers`：
- L3 Allow 时 `violated_layers` 必空（LLM judgment 不带 layers 信息）
- 这意味着"L1 命中失效但 LLM 仍 Allow"的假阳性测不出
- 缓解：`expected_risk_level` 能间接验证 L1 命中（LLM 继承 L1 的 medium 评级），但不够可靠
- 如需严格验证 L1 命中，单独写单元测试直接调 `_check_lateral_movement` 等 L1/L2 方法

### L3 case 断言范围（双端一致）

- **risk_level 只对 L1/L2 case 断言**；L3 case 只断言 `expected_decision`（LLM 层 risk_level 有非确定性波动 — 同一用例同配置可能在 medium/high 间浮动，硬绑定会偶发炸测试且测不到要害）。
- **L1/L2 case 强制禁 LLM**（对齐 Python `default_config`）：TS 加载器对非 `llm_required` 用例临时设 `AGENT_MOSS_DISABLE_LLM=1`，只测 L1+L2 静态结果。否则 LLM 可用时 L1/L2 用例也会被 LLM 二次判定翻盘（`sudo apt install` 偶发判 Deny），导致 Allow 用例偶发失败。
- 结论：**L1/L2 用例 = 静态确定性断言；L3 用例 = 只判 Allow/Deny 语义**。这是设计意图，不是妥协。

---

## 七、常见误报漏报模式（修复历史参考）

已修复的边界 bug 编号体系，新问题沿用 `NEW-FP-*`/`NEW-FN-*`：

| 编号 | 类型 | 问题 | 关键教训 |
|------|------|------|----------|
| NEW-FP-C | 误报 | `wget -O-` stdout 被判写文件 | `-O-` 的 `-` 是 stdout 不是文件名 |
| NEW-FP-D | 误报 | `echo ssh user@host` 被判横向移动 | echo/printf 首词是字面量，按命令段判定跳过 |
| NEW-FP-E | 漏报 | `bash -c "ssh user@host"` 未检测 | bash -c 内联是真实命令非字面量，剥引号提取（区别于 python -c 跳过） |
| NEW-FP-G | 误报 | `dd of=/dev/null` 触发 read_before_write | `/dev/null` 是丢弃目标非写文件，与 `>/dev/null` 同语义 |
| NEW-FP-H | 误报 | `echo "of=/dev/null done"` 触发 read_before_write | kv_paths 正则不区分引号内外，echo 输出文本里的 `of=/path` 被当真实写目标；修复：kv_paths 应用前先剥引号内容，引号内纯路径由 quoted_paths 独立提取 |
| NEW-FP-I | 误报 | `echo "rm -rf /tmp"` / `echo "chmod 777"` 被 L1 当真实危险命令 | CommandPatternScanner/SensitivePathChecker 对整个 action_detail 正则匹配，echo 引号内字面量被误匹配；修复：echo/printf 段剥引号内容（引号感知分段，引号内 ;/&& 不分段），绕过链（写脚本+执行/管道喂解释器）旁路不剥保留兜底 |
| NEW-FP-J | 误报 | `grep -rn "sudo"` / `awk '/sudo/'` / `echo "sudo make install"` 被 L2 提权误拦 | `_check_privilege_escalation` 对整个 action_detail 子串匹配，参数/搜索模式/字面量里的 sudo/setuid 被当真实提权；修复：提权关键词改「命令位置」判定，引号感知分段后仅段首词是 sudo/su/setuid 或 chmod u+s 才触发 |
| NEW-FP-K | 误报 | `python3 -c "print('ssh user@host')"` 开发者测试脚本被 L1 横向移动误拦 | Python L1 `LateralMovementChecker` 是独立实现，未同步 NEW-FP-D 的内联脚本/echo 字面量跳过；修复：L1 `LateralMovementChecker.check` 改为委托 L2 `_check_lateral_movement`（token 化三策略 + 内联/echo 跳过），消除 L1/L2 逻辑漂移 |
| NEW-FP-M | 误报 | 复合命令里只读段 `cat f 2>/dev/null` / `grep root /etc/passwd 2>/dev/null` 被 read_before_write 误报"对 /dev/null 执行写入" | per-segment 只读命令分支提取重定向目标前未剥 `/dev/null`，`2>/dev/null` 被 `_REDIRECT_TARGET_RE` 提取为写目标；修复：提取前先剥 `_DEVNULL_REDIRECT_RE` |
| NEW-FP-N | 误报 | `curl -o /dev/null` / `curl --output=/dev/null` 丢弃响应体只测状态码被 read_before_write 误报写 /dev/null | `_is_write_operation` 的 wget/curl 分支识别 `-o` 即算写文件，不排除 `/dev/null` 值；修复：排除 `/dev/null`（对齐 NEW-FP-C 的 `-` 值 stdout），per-segment 提取写目标时也过滤 `/dev/null` |
| NEW-FN-F | 漏报 | `rsync src remote:/dest` 横向移动未检测 | rsync 参数顺序 src 在前，host: 在 dest，要扫所有参数 |
| NEW-FN-G | bug | 横向移动 host 提取取端口号 | `-p 2222`/`-L`/`-D` 是带值选项，单正则不匹配，token 化三策略 |
| NEW-FP-O | 误报 | 带参脚本 `bash deploy.sh backup` 被误拦（脚本 case $1 含 clean 分支 `rm ~/.ssh/id_rsa`） | 脚本内容分析（L1.2/L2.3）整段全文扫描，不区分实际执行分支；修复：**独立脚本分析引擎**（`script_engine/`）——ShellBackend 解析 case（任意 selector）/if（字符串相等）控制流 + 参数绑定 `$1/$2`，只扫可达分支；fail-closed（无法绑定/未命中回退全文）。clean 分支仍拦（l1/script-branch-deny-clean），backup 放行（l1/script-branch-allow-backup）。双端 script_engine，相对脚本路径按 cwd 解析 |
| NEW-FN-H | 漏报 | 深层嵌套脚本链（>4 层）第 4 层后的危险整层跳过 | 旧版固定 `max_depth=3` 实际只追 4 层（入口算 0）；引擎 RecursiveTracker 深度上限改 `max_depth=14` + 节点数上限 64 防内存爆炸，15 层链全追踪、深层危险命中（tests/test_script_engine.py::TestDeepChain） |
| NEW-FN-I | 漏报 | 子脚本调用参数被丢弃（`bash child.sh backup` 里的 backup 不传给 child） | 旧版递归把入口 args 原样透传给所有子节点，子脚本分支感知用错参数；引擎 IR `ScriptCall.args` 记录每个子调用自己的参数，RecursiveTracker 用子节点自身 args 递归（tests/test_script_engine.py::TestCrossScriptArgs） |
| NEW-FE-P2 | 能力 | 变量拼接 selector（`case "prefix${1}suffix"` / `${1}${2}`）无法解析 | LiteSE P2 表达式求值（SVal fold），前缀/后缀拼接可折叠为 concrete 后精确选分支 |
| NEW-FE-P3 | 能力 | 内部命名变量（`MODE=clean; case $MODE` / `if [ "$ENV" = "prod" ]`）无法追踪 | LiteSE P3 顺序执行符号环境（env 字典），赋值写入、case/if 用变量值选择；符号未确定仍 fail-closed |
| NEW-FE-P4 | 能力 | glob 通配符（`case $1 in bak*)`）与数值比较（`[ "$1" -gt 5 ]`）分支无法判定 | LiteSE P4 glob→正则 / 整数比较，只对 concrete 值匹配；符号/未知 → fail-closed |
| NEW-FE-P5 | 保障 | 符号执行路径枚举/回溯导致状态爆炸 | P5 熔断：行数 500/分支 50/变量 200 预算，超限即回退全文本；全链路线性，无回溯（tests/test_symbolic.py + TS symbolic.test.ts） |
| NEW-FN-J | 漏报(bug) | 嵌套 case/if 时外层块切错（`find("esac")` 取到内层关键字），危险命令被丢导致漏拦 | 深度配对 `_find_block_end`：case+1/esac-1 归零才结束；case-in-case 外层仍剪枝、内层不可判定则保留危险（fail-closed）。双端 symbolic + shell_backend（tests/test_script_engine.py::TestNestedBranchesSafety） |

### 修复套路

1. **误报（FP）**：找到被误判为命中的特征，加排除条件（如 `/dev/null` 排除、字面量跳过、内联脚本跳过）
2. **漏报（FN）**：找到未命中的场景，扩展检测（如扫所有参数、token 化提取、剥引号）
3. **双端同步**：Python `logic_rules.py`/`heuristic.py` 改完，TS `logic-rules.ts`/`heuristic.ts` 对应改
4. **测试看护**：加命中用例 + 对照放行用例，双端都加
5. **文档更新**：SECURITY_RULES.md 加 `NEW-FP/FN-X` 说明，SECURITY_REGEX_LIST.md 更新正则

---

## 八、探索新误报漏报的方法

用 Python 直接调 L1/L2 方法做边界探测（避开分类器对敏感词的拦截）：

```python
import sys; sys.path.insert(0, ".")
from agent_moss.engine.logic_rules import _is_write_operation, LogicRulesChecker
from agent_moss.profiles.linux import LinuxProfile
p = LinuxProfile()
wk = p.write_keywords
c = LogicRulesChecker(p)

# 写检测
def iw(d, cmd):
    print(("T" if _is_write_operation("bash", cmd, wk) else "F") + ": " + d)

# 横向移动
def lm(d, nx):
    r = c._check_lateral_movement(nx)
    print(("BLK" if r.hit else "OK") + ": " + d + "  -> " + (r.reason if r.hit else ""))
```

也可走 full pipeline 看最终判定（含短路/白名单/fail-open）：

```python
from agent_moss.engine.coordinator import AgentMossBot
from agent_moss.infra.config import Config
from agent_moss.profiles.linux import LinuxProfile
cfg = Config()
bot = AgentMossBot(profile=LinuxProfile())
r = bot.judge("", [], {"action_type":"bash","action_detail":"..."}, "reason", cfg)
print(f"allowed={r.allowed}, risk={r.risk_level}/{r.risk_type}, layers={r.violated_layers}, source={r.source}")
```

**探测维度**：写检测（tee/dd/cp/mv/重定向/引号）、横向移动（ssh/scp/rsync 各选项组合）、提权（sudo/su/pkexec/doas）、敏感路径（读写/凭据）、内联脚本（python/perl/bash -c）。

---

## 九、关键设计决策（不要回退）

- **横向移动固定 medium 不短路**：ssh/scp/rsync 到远程可能是部署也可能是攻击，medium 交 L3 判意图。不要改成 high 短路（会误杀运维）。
- **`/dev/null` 全程排除**：重定向 `>/dev/null`、`dd of=/dev/null`、`tee /dev/null` 都是丢弃非写，read_before_write 不拦。
- **bash -c 不跳过、python -c 跳过**：bash -c 内联的是真实 shell 命令（可检测），python -c 是可编程混淆字面量（交 inline_analyzer）。`_INLINE_SCRIPT_RE` 只匹配 python/perl/ruby/node/php/lua + -c/-e/-r。
- **L1 medium + file_access 短路 Deny**：`/etc/hosts` 这类 medium 级 deny_write 路径的写操作确定性拦截，不依赖 L3（读操作在 SensitivePathChecker 内 continue 放行，不误拦 `cat /etc/hosts`）。
- **L3 用例 id 用 LLM-NN**：不要用 DENY-NN（与 expected Allow 矛盾时误导）。

---

## 十、快速 checklist（每次优化任务）

- [ ] 读本手册 + 相关 SECURITY_RULES.md 章节
- [ ] 复现问题（Python API / full pipeline 确认）
- [ ] 判断是 FP（误报）还是 FN（漏报），定编号 NEW-FP/FN-X
- [ ] Python 改 `logic_rules.py`/`heuristic.py`/`profiles/*.py` 等
- [ ] TS 同步改 `logic-rules.ts`/`heuristic.ts` 等（**铁律：规则/功能必须双端同时改**）
- [ ] `npx tsc --noEmit` 确认 TS 编译
- [ ] 加测试用例：**每条规则补"一拦一放"两个 JSON case**（命中 + 类不命中）
- [ ] 若改组合链/跨会话验证（combo_chain / formal_engine）：双端同步 `logic_rules.py`↔`logic-rules.ts`、`formal_engine/`↔`formal-engine/`、`l2_rules.json` `combo_chains` 段（单一事实源）；补 `combo-*.json` / `combo-cross-session-*.json` 一拦一放用例；HTTP server（`server/models.py` + `server/routes.py`）确认透传 `session_history`
- [ ] 若改有状态增量行为链（stateful）：双端同步 `formal_engine/stateful.py`↔`formal-engine/stateful.ts`、`chain_state.py`↔`chain_state.ts`；补 `test_stateful.py` / `formal-stateful.test.ts` 与 `test_chain_state.py`（生命周期 destroy 断链、never_activated、长时距、快照重启）；Auth `/api/v1/review` 复验直读 AgentGate DB 语义；测试隔离已由 conftest `_isolate_chain_state_store` autouse fixture 覆盖
- [ ] Python: 新 L1/L2 case 手动加进 `test_all_cases.py` parametrize 列表（TS 自动扫描）；agent case 放 `agent/` 自动扫
- [ ] 若改敏感路径/危险命令：检查/更新双端同步断言（`dual-parity.test.ts` / `test_linux_profile_*_sync_with_ts`）
- [ ] 若改 agent 规则（`agent_moss/agents/<id>/rules.json`）：在 `tests/cases/agent/` 补用例（一拦一放 + 无 agent_id 对照）
- [ ] 若改场景规则（`agent_moss/scenarios/<id>/rules.json`）：在 `tests/cases/scenario/<id>/` 补用例（一拦一放 + 无 scenario_id 对照）；同步引擎 `scenario_id` 接线 + `AGENT_MOSS_SCENARIO` env + runtime_config `scenario_rules` 分区 + console 场景页（Python/TS 双端）；cases_exec 生成器/prep/run_all 的 `--scenario` 参数联动
- [ ] 若改敏感路径：确认该环境 runtime config（`~/.config/agentmoss/agent_moss_runtime.json`）对应项 enabled，不屏蔽 run 验证真实行为
- [ ] 双端全量回归（禁 LLM）：Python + TS 都绿
- [ ] 如改 L3 case，真跑 LLM 确认双端判定对齐
- [ ] 更新 SECURITY_RULES.md（加 NEW-FP/FN-X 说明）
- [ ] 更新 SECURITY_REGEX_LIST.md（正则/逻辑变更）
- [ ] 更新 tests/cases/README.md（用例计数 + 顶部精确分解表 + 场景分布）
- [ ] 提交（message 带双端回归数字，不带 Co-Authored-By）
