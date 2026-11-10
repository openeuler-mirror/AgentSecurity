# AgentMoss 规则来源与 Runtime 合并机制

> 本文档回答三个问题：
> 1. **Python 与 TS 两侧的内置规则分别从哪里来**（双端必须一致，勿单端改）
> 2. **runtime 配置（`agent_moss_runtime.json`）读自哪里、如何被加载**
> 3. **源码种子与用户配置如何 merge**（尤其是 enabled 开关的保留规则）

阅读本文档后，无需再重新翻代码就能定位任一规则的来源。

---

## 1. 内置规则单一事实源：归一化 JSON（L1/L2/L3）

**核心架构**：L1/L2/L3 的正则规则数据统一存放在 `agent_moss/rules/` 下的三份归一化 JSON，**Python 与 TS 两端都从这些 JSON 读取**，消除双端规则漂移。

| 文件 | 内容 | 说明 |
|---|---|---|
| `agent_moss/rules/l1_rules.json` | 危险命令 + 注入关键词 + 敏感路径 | `dangerous_commands` / `injection_detection` / `sensitive_path_access` |
| `agent_moss/rules/l2_rules.json` | 意图偏离 + 密码修改 + 用户删除授权 | `intent_consistency` / `password_modify_consent` / `user_deletion_consent` |
| `agent_moss/rules/l3_rules.json` | skill 关键词映射 | `{category: {skill_id: [keywords]}}` |
| `agent_moss/rules/mc_rules.json` | L2.2 形式化验证（LTL 模型检测）规则 | `ap_patterns`（14 个原子命题正则）+ `rules`（11 条 LTL 公式：mc-ltl-001~010 + mc-ctl-001 线性降级）；加载器 Python `load_mc()` ↔ TS `loadMC()` |
| `agent_moss/rules/tool_registry.json` | Tool Registry | `{tools: {name: {actionClass, requireHighIntegrity}}}` 完整性标注数据，Python `load_tool_registry()` ↔ TS `loadToolRegistry()` |

**改规则 = 只改这三份 JSON 之一**，双端自动生效，不再需要手动同步两端代码。

**加载器**：
- Python：`agent_moss/rules_loader.py`（`load_l1()` / `load_l2()` / `load_l3()`）
- TS：`ts/src/infra/rules-loader.ts`（`loadL1()` / `loadL2()` / `loadL3()`）

> **注意**：`agent_moss/rules/user_rules.json` 是**用户自定义**规则文件（非内置），与归一化默认规则分开。内置规则以 `l1/l2/l3_rules.json` 为准。

---

## 1a. Python 侧内置规则来源

Python 的 profile 属性（`dangerous_commands` / `injection_keywords` / `sensitive_paths` / `intent_deviation_patterns`）和模块常量（`PASSWORD_MODIFY_PATTERNS` / `USER_DELETION_PATTERNS` / `SKILL_KEYWORD_MAP`）**从归一化 JSON 加载**，由 `infra/runtime_config.py` 的 `generate_source_defaults()` 提取为出厂默认种子。

**入口**：`agent_moss/infra/runtime_config.py`
- `generate_source_defaults(profile=None)` → 组装完整 `L1_rules` / `L2_rules` / `L3_skills` / `agent_rules`
- 各 `_l1_*_to_rules(profile)` / `_l2_*_to_rules(profile)` 函数把 profile 属性 / 常量转成规则 dict（统一补 `enabled:true, builtin:true`）

**规则数据取自**（`agent_moss/rules/` JSON → profile 属性）：

| 层级 | 分类 | 来源（Python） |
|---|---|---|
| L1 | `dangerous_commands` | `l1_rules.json` → `LinuxProfile.dangerous_commands`（54 条） |
| L1 | `injection_detection` | `l1_rules.json` → `LinuxProfile.injection_keywords`（46 条） |
| L1 | `sensitive_path_access` | `l1_rules.json` → `LinuxProfile.sensitive_paths`（37 条） |
| L2 | `intent_consistency` | `l2_rules.json` → `LinuxProfile.intent_deviation_patterns`（2 条） |
| L2 | `password_modify_consent` | `l2_rules.json` → `PASSWORD_MODIFY_PATTERNS`（7 条） |
| L2 | `user_deletion_consent` | `l2_rules.json` → `USER_DELETION_PATTERNS`（5 条） |
| L3 | `L3_skills` | `l3_rules.json` → `SKILL_KEYWORD_MAP`（`engine/skill_engine.py`，13 个 skill） |
| A | `agent_rules` | `_agent_rules_to_defaults()`（读 `agents/<id>/rules.json`，仍是独立 JSON） |

---

## 2. TS 侧内置规则来源

TS 的检测常量（`DANGEROUS_PATTERNS` / `INJECTION_KEYWORDS` / `ROOT_SENSITIVE_PATHS` / `HOME_SENSITIVE_PATHS` / `CREDENTIAL_PATHS` / `PASSWORD_MODIFY_PATTERNS` / `USER_DELETION_PATTERNS` / `INTENT_DEVIATION_PATTERNS` / `SKILL_KEYWORD_MAP`）**从归一化 JSON 加载**（`ts/src/infra/rules-loader.ts`），由 `infra/runtime-config.ts` 的 `generateSourceDefaults()` 组装为默认种子。

**入口**：`ts/src/infra/runtime-config.ts`
- `generateSourceDefaults()` → 组装默认种子（与 Python `generate_source_defaults` 等价，测试 `runtime-config-seed.test.ts` 看护对齐）

**规则数据取自**（`agent_moss/rules/` JSON）：

| 层级 | 分类 | 来源（TS） |
|---|---|---|
| L1 | `dangerous_commands` | `l1_rules.json` → `DANGEROUS_PATTERNS`（`engine/heuristic.ts`，`new RegExp(pattern,'i')`） |
| L1 | `injection_detection` | `l1_rules.json` → `INJECTION_KEYWORDS`（`engine/heuristic.ts`） |
| L1 | `sensitive_path_access` | `l1_rules.json`（按 `scope` 字段分 root/home/credential）→ `ROOT_SENSITIVE_PATHS` + `HOME_SENSITIVE_PATHS` + `CREDENTIAL_PATHS`（`engine/logic-rules.ts`） |
| L2 | `intent_consistency` | `l2_rules.json` → `INTENT_DEVIATION_PATTERNS`（`engine/logic-rules.ts`） |
| L2 | `password_modify_consent` | `l2_rules.json` → `PASSWORD_MODIFY_PATTERNS`（`engine/logic-rules.ts`） |
| L2 | `user_deletion_consent` | `l2_rules.json` → `USER_DELETION_PATTERNS`（`engine/logic-rules.ts`） |
| L3 | `L3_skills` | `l3_rules.json` → `SKILL_KEYWORD_MAP`（`engine/skill-loader.ts`） |
| A | `agent_rules` | `agents/<id>/rules.json`（仍是独立 JSON） |

> **dist 路径**：`rules-loader.ts` 会被 tsup 内联进 `dist/cli.js` / `dist/server.js` / `dist/engine/coordinator.js`，已用多候选路径解析确保各入口都能找到 `dist/rules/*.json`。

---

## 3. 双端一致性（单一事实源看护）

**归一化后，双端规则来自同一份 JSON，天然一致。** 改规则只需改 `agent_moss/rules/*.json`，双端加载器自动取到相同数据。

**看护测试**（防止回归/漂移）：
- 规则计数与加载校验：
  - Python：`tests/test_rules_loader.py`（断言 JSON 可加载、计数稳定、profile 与 JSON 逐条一致、seed 与 JSON 一致）
  - TS：`ts/src/__tests__/rules-loader.test.ts`（断言计数稳定、检测常量与 JSON 一致、seed 计数一致）
- 行为同步校验（匹配逻辑双端对齐）：
  - Python：`tests/test_all_cases.py` 的 `test_linux_profile_rule_sync_with_ts`、`test_linux_profile_sensitive_paths_sync_with_ts`
  - TS：`ts/src/__tests__/dual-parity.test.ts`

> **注意**：归一化统一的是**规则数据**（pattern/keyword/path）。匹配**行为**（如 `_is_write_operation`、敏感路径边界/转义、`(?!\.pub)` 分段、`_normalize_path_segments`/`normalizePathSegments` 路径归一化）仍是各端代码逻辑，需保持一致，由行为同步测试看护。
>
> **路径归一化（NORM-PATH）**：L1 匹配前折叠路径混淆段（`//`→`/`、`/./`→`/`），堵路径穿越变体（对齐 CVE-2023-37274 攻击面：`cat /etc//shadow`）。实现为 Python `heuristic.py::_normalize_path_segments` 与 TS `heuristic.ts::normalizePathSegments` 双端对称函数，跳过协议 URL 与引号字面量；非规则数据，改时要双端同步改代码。

---

## 4. Runtime 配置：读取位置与加载

**配置文件**：`agent_moss_runtime.json`
- 默认路径：`~/.config/agentmoss/agent_moss_runtime.json`
- 可用环境变量覆盖：`AGENT_MOSS_RUNTIME_CONFIG_PATH`（见 `infra/runtime_config.py` 的 `get_runtime_config_path()`）
- 每个 agent 实例（如 xiaoo、opendesk）可能用不同的 runtime 文件，路径由实例配置决定

**加载流程**（Python `load_runtime_config()` / TS `loadRuntimeConfig()`）：

```
1. 文件不存在   → 生成新种子（generate_source_defaults）并写盘，全部 enabled=true
2. 文件存在     → 读文件，调 merge_config(user_config, source_defaults) 合并
3. 合并后变化   → 写回磁盘（含迁移/清理 source_removed）
4. 返回合并结果
```

---

## 5. Merge 机制（重点：enabled 开关为何保留）

核心函数：
- Python：`merge_config(user_cfg, source_defaults)` → `_merge_rule_categories()` / `_merge_skill_categories()` / `_merge_agent_rules()`
- TS：`mergeConfig(data, generateSourceDefaults())`

**合并策略**（源码注释明确）：

1. **保留用户 enabled 开关**：同一 fingerprint（pattern/keyword/path/value）的规则，若 user_cfg 里已存在，则**沿用客户的 `enabled` 状态**，不因源码更新而强制改回 true。
   ```python
   user_enabled = existing.get("enabled", True)   # 默认 true，但已有的以用户为准
   ```
2. **新增内置规则**：源码新增的 builtin 规则，补入 `enabled=true`。
3. **源码已删除的 builtin 规则**：标记 `source_removed=true` + `enabled=false`（残留展示，但不生效）。
4. **用户自定义规则**：完整保留。

**fingerprint 判定**（`_rule_fingerprint`）：
- 命令规则 → `pattern`
- 注入 → `keyword` + `lang`
- 敏感路径 → `path`
- L2 → 各自的 `pattern` / 结构字段
- agent 规则 / skills → `value` 或 `id`

### 5.1 为什么"源码更新了，runtime 里却还是禁用"？

因为策略 1：**已存在的规则，用户开关优先**。若用户在某个历史版本把某条内置规则手动关掉（`enabled:false`），那么这个 false 会被写进 `agent_moss_runtime.json`，此后**每次 merge 都尊重它**，升级小版本不会自动翻回 true。

**这不是 bug**，是"用户开关优先"的设计。若规则安全复查后确应启用，需：
- 在 console 手动开启，或
- 编辑 `agent_moss_runtime.json` 把对应规则 `enabled` 置 `true`（改前先备份），或
- 删除 runtime 文件让其重新生成（注意会丢失全部用户自定义配置）。

### 5.2 常见"总数对不上"的排查

- **总数 > 内置数**：多为 `source_removed=true` 的历史残留仍计入显示总数（如某条 `chmod 777`）。源码已删但 runtime 保留展示。
- **启用数 < 总数**：存在 `enabled:false` 的规则（历史手动关闭或 source_removed）。
- **校验总量**：`L1 = dangerous_commands + injection_detection + sensitive_path_access` 的归一化 JSON 内置条数（Linux 当前 137 = 54 + 46 + 37）。看护测试 `test_rules_loader.py` / `rules-loader.test.ts` 断言此计数。

---

## 6. 相关文件速查

| 用途 | Python | TS |
|---|---|---|
| **归一化规则数据（单一事实源）** | `agent_moss/rules/l1_rules.json` / `l2_rules.json` / `l3_rules.json` | 同左（共用） |
| 规则加载器 | `agent_moss/rules_loader.py` | `ts/src/infra/rules-loader.ts` |
| 内置规则提取（组装种子） | `infra/runtime_config.py` | `infra/runtime-config.ts` |
| L1 命令/注入（从 JSON 加载） | `profiles/linux.py` | `engine/heuristic.ts` |
| L2 逻辑规则 / 敏感路径 | `engine/logic_rules.py` + `profiles/linux.py` | `engine/logic-rules.ts` |
| L3 skills | `engine/skill_engine.py`（`SKILL_KEYWORD_MAP`） | `engine/skill-loader.ts` |
| agent 规则 | `agents/<id>/rules.json` | `agents/<id>/rules.json` |
| runtime 加载 | `load_runtime_config()` | `loadRuntimeConfig()` |
| runtime 合并 | `merge_config()` | `mergeConfig()` |
| 规则数据看护测试 | `tests/test_rules_loader.py` | `ts/src/__tests__/rules-loader.test.ts` |
| 行为同步校验 | `tests/test_all_cases.py` | `ts/src/__tests__/dual-parity.test.ts` |