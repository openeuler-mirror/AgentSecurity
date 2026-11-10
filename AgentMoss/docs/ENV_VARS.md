# AgentMoss 环境变量参考

本文档汇总 AgentMoss 全部环境变量，并给出 **audit_agent → AgentMoss 的迁移对照表**（xiaoO 老插件 `AUDIT_*` 变量在 AgentMoss 中的对应）。

> audit_agent 是 AgentMoss 的前身（原 xiaoO 插件 `plugins/hookers/audit_agent/`），判定逻辑已迁出为独立常驻服务 AgentMoss。环境变量前缀从 `AUDIT_` 统一改为 `AGENT_MOSS_`，语义对齐，个别变量有行为变化（见下表"变化"列）。

---

## 一、audit_agent → AgentMoss 迁移对照

老用户从 audit_agent 切到 AgentMoss 时，环境变量按此表替换：

| audit_agent 变量 | AgentMoss 变量 | 默认值 | 变化 |
|---|---|---|---|
| `AUDIT_DISABLE_LLM_LAYER3` | `AGENT_MOSS_DISABLE_LLM` | 未设（启用 L3） | 仅改名，语义不变（设 `1` 禁用层3 LLM）|
| `AUDIT_LLM_TIMEOUT` | `AGENT_MOSS_LLM_TIMEOUT` | `300` | 仅改名 |
| `AUDIT_LOG_PATH` | `AGENT_MOSS_LOG_PATH` | 未设（不记录）| 仅改名，语义不变：bridge.py 记 HOOK_INPUT/HOOK_OUTPUT 全量 hook 日志，llm_analyzer 记 LLM prompt，两处写同一个文件（每次调用都记，不依赖 L3 是否命中）|
| `AUDIT_ENABLE_POLICY_GEN` | `AGENT_MOSS_ENABLE_POLICY_GEN` | 未设（禁用生成）| 仅改名 |
| `AUDIT_CONFIG_PATH` | `AGENT_MOSS_CONFIG_PATH` | 未设（用内置默认）| 语义微变：现在优先级为 `AGENT_MOSS_CONFIG_PATH` > `~/.config/agentmoss/agent_moss.yaml` > 继承 `~/.config/xiaoo/config.toml` 的 LLM 配置 |
| `OPENROUTER_API_KEY` | `AGENT_MOSS_LLM_API_KEY` | 未设 | 改名；同时仍兼容 fallback 到 `OPENROUTER_API_KEY` / `OPENAI_API_KEY` |
| `AUDIT_ENABLE_LLM`（install.sh）| （已移除）| — | AgentMoss L3 开关改用 `AGENT_MOSS_DISABLE_LLM`，安装时不再用这个 env |

**audit_agent 没有但 AgentMoss 新增的**（迁移时按需补）：
- `AGENT_MOSS_DISABLE_HEURISTIC` / `AGENT_MOSS_DISABLE_LOGIC_RULES`：单独禁用层1/层2（audit_agent 只能整体禁 L3）
- `AGENT_MOSS_LLM_FAIL_MODE`：LLM 失败策略（fail_open 默认 / fail_closed），audit_agent 无此开关
- `AGENT_MOSS_LLM_RETRIES` / `TEMPERATURE` / `MAX_TOKENS`：LLM 调参
- `AGENT_MOSS_RUNTIME_CONFIG_PATH` / `TOKEN_STATS_PATH` / `SETTINGS_PATH` / `CONSOLE_TOKEN`：常驻服务新增
- `AGENT_MOSS_URL` / `HOST` / `PORT`：bridge.py 消费方连服务用

---

## 二、配置优先级

所有通过 `get_agent_moss_setting()` 读取的变量，优先级统一为：

```
环境变量 > agent_moss_settings.json > 默认值
```

而层级开关（`is_layer_enabled`）额外多一层 runtime JSON：

```
AGENT_MOSS_DISABLE_*  env  >  runtime JSON（~/.config/agentmoss/agent_moss_runtime.json）  >  agent_moss_settings.json  >  默认 True
```

> env 永远最高优先级（覆盖一切），runtime JSON / Console 管理的是"未设 env 时的持久化偏好"。Console UI 会展示哪些开关被 env 接管（灰色不可改）。LLM 配置（API key/model/base_url 等）优先级另见下方"LLM 配置"小节。

---

## 三、AgentMoss 完整环境变量清单

### 3.1 层级开关

| 变量 | 说明 | 默认值 |
|---|---|---|
| `AGENT_MOSS_DISABLE_LLM` | 设 `1` 禁用层3 LLM 深度分析（仅跑层1+层2）| 未设（启用 L3）|
| `AGENT_MOSS_DISABLE_HEURISTIC` | 设 `1` 禁用层1 特征匹配静态检测 | 未设（启用 L1）|
| `AGENT_MOSS_DISABLE_LOGIC_RULES` | 设 `1` 禁用层2 逻辑规则检测 | 未设（启用 L2）|
| `AGENT_MOSS_FORMAL_OBSERVE` | 设 `1` 启用 L2.2 formal 引擎 observe 模式（命中违规只记录不拦截，violated_layers 仍带 `L2.2` 供 actrail/调用方观测；灰度观察 FP 率用，见 docs/DETECTION_METHODS.md 六.3）。镜像 TS `isFormalObserveMode()` | 未设（命中即 Deny）|
| `AGENT_MOSS_LLM_FAIL_MODE` | LLM 失败策略：`fail_open`（默认，纯靠 L3 时 LLM 挂了→Allow+warn）/ `fail_closed`（→Deny）| `fail_open` |
| `AGENT_MOSS_BRAIN_ENABLED` | 设 `1` 启用 Brain 自学习机制（开发中，默认关闭；开启后 L3 Deny 会提取规则/skill 并自动激活）| 未设（禁用）|
| `AGENT_MOSS_BRAIN_REVIEW` | 设 `0` 关闭 Brain 候选的 LLM 审核（达阈值后不再调 LLM 判定"是否值得保留"）。审核是防机械提取误报的关键，建议保持开启 | 未设（启用）|
| `AGENT_MOSS_CONTRIBUTE_TOKEN` | `agentmoss brain contribute` 的 GitLab 风格 API token；设置后自动创建 MR，未设置则输出网页链接由用户手点 | 未设（仅输出链接）|
| `AGENT_MOSS_SCENARIO` | 部署级场景 id（客户沙箱设一次，所有请求生效）；**逗号分隔支持多场景**（如 `AGENT_MOSS_SCENARIO=bank,meow`），逐个加载并合并场景扩展（Python `get_scenario_extensions_multi` ↔ TS `getScenarioExtensionsMulti`，append 语义）。优先级：调用方显式 `scenario_id` > 本 env | 未设（不启用任何场景）|

### 3.2 LLM 调用

| 变量 | 说明 | 默认值 |
|---|---|---|
| `AGENT_MOSS_LLM_API_KEY` | LLM API Key（最高优先级，兼容 fallback `OPENROUTER_API_KEY` / `OPENAI_API_KEY`）| 未设 |
| `AGENT_MOSS_LLM_MODEL` | LLM 模型名称 | Python: `anthropic/claude-3.5-sonnet`；TS: `gpt-4o` |
| `AGENT_MOSS_LLM_BASE_URL` | LLM API 端点 | Python: `https://openrouter.ai/api/v1`；TS: `https://api.openai.com/v1` |
| `AGENT_MOSS_LLM_PROVIDER` | Provider 标识（决定注入哪些 HTTP headers，如 openrouter/xai）| 从 base_url 推断 |
| `AGENT_MOSS_LLM_TEMPERATURE` | 采样温度 | `0.1` |
| `AGENT_MOSS_LLM_MAX_TOKENS` | 最大输出 token 数 | `4096` |
| `AGENT_MOSS_LLM_TIMEOUT` | 单次调用超时（秒）| `300` |
| `AGENT_MOSS_LLM_RETRIES` | 失败重试次数（默认 2 = 共 3 次尝试）| `2` |
| `AGENT_MOSS_ENABLE_POLICY_GEN` | 设 `1` 启用策略生成（Step 2），否则用默认只读策略 | 未设（禁用）|

> **LLM 配置 fallback**：若用户只配了 xiaoo 的 `~/.config/xiaoo/config.toml`，AgentMoss 会自动继承其 `[llm]` 配置（字段名转译 `api_base` ↔ `base_url`），对齐 audit_agent 时代"配一份 xiaoo 就够"的体验。

### 3.3 配置文件路径

| 变量 | 说明 | 默认值 |
|---|---|---|
| `AGENT_MOSS_CONFIG_PATH` | 主配置 YAML 路径 | `~/.config/agentmoss/agent_moss.yaml`（缺失自动创建，并继承 xiaoo config.toml）|
| `AGENT_MOSS_SETTINGS_PATH` | `agent_moss_settings.json` 路径 | 包内 `agent_moss/infra/agent_moss_settings.json` |
| `AGENT_MOSS_RUNTIME_CONFIG_PATH` | runtime JSON 路径（层级开关 + 规则启停持久化）| `~/.config/agentmoss/agent_moss_runtime.json` |
| `AGENT_MOSS_DATA_DIR` | 数据根目录（决定所有 `~/.config/agentmoss` 下文件落盘位置）。安装时按启动用户写入，systemd 下即使 root 启动也落到当前用户目录。**源码仓跑测试已被测试基建自动隔离**（Python `conftest.py` / TS `vitest setup.ts` 会把该 env 指向临时目录，让 `has_runtime_config()` 恒 False、规则恒用源码）；如需手动隔离可显式设此 env 指向空目录 | `~/.config/agentmoss` |
| `AGENT_MOSS_TEST_USE_RUNTIME` | 测试逃生门：设 `1` 时**跳过**测试基建的 data_dir 隔离（Python conftest + TS vitest setup），让 pytest/vitest 用真实 `~/.config/agentmoss`（runtime/config 生效）。仅用于「确认改规则后真实运行时是否生效」；默认测试应保持隔离 | 未设（隔离生效）|
| `AGENT_MOSS_TOKEN_STATS_PATH` | token 用量统计 JSON 路径（显式指定时优先于 instance 派生路径）| 见下方「token 消耗按实例隔离」|
| `AGENT_MOSS_INSTANCE` | 归属实例标识。同机多套 agentmoss 并存时，`status` / bridge / install.sh 按此字段过滤，只认属于自己的服务（避免把别的 agent 的 agent-moss 当成自己的误停/误连），同时用于隔离 token 消耗文件。例：xiaoO 用 `xiaoo`，OpenDesk 用 `opendesk` | 未设（空串）|

> **token 消耗按实例隔离**：设了 `AGENT_MOSS_INSTANCE=<name>` 时，token 统计文件落在 `<data_root>/<instance>/agent_moss_token_stats.json`（如 `opendesk` → `~/.config/agentmoss/opendesk/agent_moss_token_stats.json`）；未设则用默认 `~/.config/agentmoss/agent_moss_token_stats.json`。各 agent 只读取自己实例的文件，「最近调用数据」(console `token-stats/recent`) 也读同一文件，随之自动隔离。显式设 `AGENT_MOSS_TOKEN_STATS_PATH` 可覆盖此派生路径。

> **多实例与规则共享**：`AGENT_MOSS_INSTANCE` 隔离「进程识别/探测」+「token 消耗」，**不隔离规则配置文件**。同机所有 agentmoss 实例共享同一个 `~/.config/agentmoss/agent_moss_runtime.json`（除非显式设 `AGENT_MOSS_RUNTIME_CONFIG_PATH` 指向不同文件）。
> 这是刻意设计：同一台服务器上的安全规则应对所有 agent 一致（通用 L1/L2/L3 规则全局共享）；不同 agent 的**定制规则**通过 runtime JSON 里的 `agent_rules.<agent_id>` 分区天然隔离（如 `opendesk` / `xiaoo` 各自独立）。任意一个 console 修改规则，都会写入共享文件，其他实例同步生效。
>
> `status` 行为示例（服务在 9091，instance=xiaoo）：
> ```bash
> # 不带 instance → 期望匹配空串，找不到 → 报"未运行"，并提示检测到 9091 (instance=xiaoo)
> agent-moss status
> ❌ AgentMoss 服务未运行（instance=(空)）
>    ⚠️ 检测到其他 agent 的 agentmoss 实例: 端口 9091 (instance=xiaoo)
> # 带 instance → 精确匹配 xiaoo → 正常显示运行中
> AGENT_MOSS_INSTANCE=xiaoo agent-moss status
> ✅ AgentMoss 服务运行中
>    Instance: xiaoo
>    端口:     9091
> ```

### 3.4 自定义规则

| 变量 | 说明 | 默认值 |
|---|---|---|
| `AGENT_MOSS_CUSTOM_RULES` | 自定义规则 JSON 数组，注入到 L1 检测。格式：`[{"pattern": "kubectl delete namespace", "action": "Deny", "severity": "critical"}]` | `[]` |

> OpenDesk 安全网关设置页里的 customRules 也将统一收敛到这里（后续 OpenDesk 集成时撤下设置页 customRules，归 Console 管）。

### 3.5 Console（策略管控台）

| 变量 | 说明 | 默认值 |
|---|---|---|
| `AGENT_MOSS_CONSOLE_TOKEN` | Console Bearer 鉴权 token | 未设（本机 127.0.0.1 免鉴权，便于 iframe 嵌入）|

### 3.6 bridge.py（xiaoO 消费方连服务）

这些变量由 `hooks/xiaoO/bridge.py` 读取，用于 xiaoO hook 子进程定位并连接 AgentMoss 服务：

| 变量 | 说明 | 默认值 |
|---|---|---|
| `AGENT_MOSS_URL` | 完整服务 URL（最高优先级，如 `http://10.0.0.5:9095`）| 未设 |
| `AGENT_MOSS_HOST` | 服务监听地址 | `127.0.0.1` |
| `AGENT_MOSS_PORT` | 服务端口（被占时服务自动 findFreePort 往上找，bridge 探测 9090-9095 兜底）| `9090` |
| `AGENT_MOSS_HOOK_TIMEOUT` | analyze 请求超时（秒）| `60` |
| `AGENT_MOSS_HEALTH_TIMEOUT` | 活性检查超时（秒）| `2` |
| `AGENT_MOSS_LOG_PATH` | **全量 hook 日志 + LLM prompt 日志路径**。bridge.py 记 HOOK_HEALTH_OK/HOOK_INPUT/HOOK_OUTPUT（每次 hook 调用都记，含 tool_input 和判定结果）；llm_analyzer.py 记 LLM 判定 prompt。两处写同一个文件，对应 audit_agent 的 `AUDIT_LOG_PATH`，行为完全一致 | 未设（不记）|
| `AGENT_MOSS_CHECK_SOURCE` | 设 `1` 时额外检查 agent_moss 包是否可 import | 未设 |

> 端口解析优先级（学 OpenDesk hook.ts resolveGateUrl）：`AGENT_MOSS_URL` > `AGENT_MOSS_PORT` 显式指定 > 探测 9090-9095 找 `/api/v1/health` 返回 healthy > 默认 9090。

> 注：`AGENT_MOSS_LOG_PATH` 不依赖 L3 是否命中——即使命令在层1/层2 就被拦（或服务返回 422 fail-closed），hook 全量日志照常记录，便于排查。

### 3.7 AgentMoss 源码仓位置（build.sh 用）

| 变量 | 说明 | 默认值 |
|---|---|---|
| `AGENT_MOSS_HOME` | AgentMoss 源码仓路径（build.sh 的 `pip install -e` 用）| xiaoO 同级的 `../AgentMoss` |

### 3.8 AcTrail（事件上报，可选）

| 变量 | 说明 | 默认值 |
|---|---|---|
| `ACTRAIL_ENABLED` | 设 `1` 启用 AcTrail 事件上报 | 未设（禁用）|
| `ACTRAIL_STORAGE_PATH` | AcTrail SQLite 路径 | `/tmp/actrail.sqlite` |
| `ACTRAIL_TIMEOUT_MS` | 写入超时（毫秒）| `100` |

---

## 四、使用示例

```bash
# 禁用层3 LLM（仅用层1+层2，最快）
export AGENT_MOSS_DISABLE_LLM=1

# LLM 失败时 fail-closed（安全优先，而非默认 fail-open）
export AGENT_MOSS_LLM_FAIL_MODE=fail_closed

# 调整 LLM 超时 + 重试
export AGENT_MOSS_LLM_TIMEOUT=60
export AGENT_MOSS_LLM_RETRIES=3

# 记录全量 hook 日志 + LLM prompt 到文件（排查 xiaoo→AgentMoss 调用问题首选）
export AGENT_MOSS_LOG_PATH=/tmp/agentmoss.log

# 启用策略生成（Step 2，默认禁用）
export AGENT_MOSS_ENABLE_POLICY_GEN=1

# 注入自定义规则
export AGENT_MOSS_CUSTOM_RULES='[{"pattern":"kubectl delete namespace","action":"Deny","severity":"critical"}]'

# 指向远端 AgentMoss 服务（不在本机起）
export AGENT_MOSS_URL=http://10.0.0.5:9095
```

---

## 五、从 audit_agent 迁移的快速检查清单

切到 AgentMoss 前，把原 `AUDIT_*` 环境变量按 §一 改名，重点确认：

1. `AUDIT_DISABLE_LLM_LAYER3=1` → `AGENT_MOSS_DISABLE_LLM=1`
2. `AUDIT_CONFIG_PATH` 若指向自定义 config.json → `AGENT_MOSS_CONFIG_PATH`（注意现在主配置是 YAML，见 §3.3）
3. `OPENROUTER_API_KEY` → `AGENT_MOSS_LLM_API_KEY`（或保持原样，有 fallback 兼容）
4. `AUDIT_LLM_TIMEOUT` / `AUDIT_LOG_PATH` / `AUDIT_ENABLE_POLICY_GEN` → 对应 `AGENT_MOSS_` 前缀
5. audit_agent 时代的 `audit_settings.json` 已被 runtime JSON + `agent_moss_settings.json` 取代，不再使用
6. LLM 配置若已在 `~/.config/xiaoo/config.toml` 配好，AgentMoss 自动继承，无需重复配

迁移后用 Policy Console（`http://127.0.0.1:9090/console`）可视化改层级开关/规则，比改 env/settings 更直观；env 仍作最高优先级覆盖手段保留。
