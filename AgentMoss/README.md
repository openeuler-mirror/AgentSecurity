# AgentMoss

AgentMoss 是一个**可被任意 AI Agent 调用的独立通用安全分析服务**。基于 OS Profile 机制，自动适配 Linux/Windows 的 syscall 检测模式，提供三层防御安全分析（特征匹配 → 逻辑规则 → LLM 语义分析）。

> v2 更新：新增 OS Profile 系统（Linux/Windows 自适应）、两级快速放行白名单、rm 命令分级检测、脚本内容预扫描、LLM 结果缓存、Provider 自动识别与 Header 注入、fail-closed 安全原则。
>
> v0.4.0 新增：非交互式密码修改检测（passwd/chpasswd/newusers/lnewusers 等）、密码修改授权检测（ask_user_question 前置检查）、内置安全 Skill 白名单（xiaoo-guardian 直接放行）、系统信息命令快速放行（whoami/id/hostname 等 12 个命令）、shell 重定向写入检测。
>
> v0.5.0 新增：L1/L2 规则收窄减少误杀（sudo 只拦截危险命令、rm -rf /tmp 不拦截、dd/mkfs/format 收窄、/etc/passwd 仅从 L1 移除、git push --force 降级为 medium）、nmap/masscan/zmap 网络扫描检测、lnewusers 批量用户添加检测、L2 通配符删除排除临时目录、用户/组删除授权检测、chgpasswd/lpasswd/gpasswd 检测。

## 目录

- [架构](#架构)
- [快速开始](#快速开始)
- [场景定制规则（客户沙箱）](#场景定制规则客户沙箱)
- [LLM 配置](#llm-配置)
- [openEuler 部署](#openeuler-部署)
- [API 参考](#api-参考)
- [Policy Console（策略管控台）](#policy-console策略管控台)
- [runtime_config（运行时持久化配置）](#runtime_config运行时持久化配置)
- [配置](#配置)
- [项目结构](#项目结构)

## 架构

```
┌─────────────────────────────────────────────────────────────┐
│          调用入口 (HTTP / Unix Socket / Hook)                 │
│  POST /api/v1/analyze                                        │
│  GET  /api/v1/health                                         │
├─────────────────────────────────────────────────────────────┤
│               ObservableAdapter                               │
│  AgentOS 可观测服务 syscall → 标准格式                       │
├─────────────────────────────────────────────────────────────┤
│                OS Profile 选择                                │
│     ┌──────────┐    ┌──────────┐                             │
│     │  Linux   │    │ Windows  │                             │
│     │ Profile  │    │ Profile  │                             │
│     └──────────┘    └──────────┘                             │
├─────────────────────────────────────────────────────────────┤
│          两级快速放行白名单                                    │
│  完全安全 (ls/pwd/echo/whoami/hostname...) → 跳过 L2+L3     │
│  只读敏感 (cat/grep/head...) → 跳过 L3，保留 L2              │
│  内置安全 Skill (xiaoo-guardian) → 跳过 L2+L3                │
│  ★ agent 定制白名单 (按 agent_id 加载，如 opendesk 的       │
│    memory-*/todomgr-* 纯数据操作) → 跳过 L2+L3               │
│  ★ 安全兜底: 完整命令管道尾部扫描，防止白名单绕过             │
├─────────────────────────────────────────────────────────────┤
│          安全分析引擎 (三层防御)                               │
│                                                              │
│  层1: 特征匹配静态检测 (<1ms)                                   │
│    ├── 用户自定义规则匹配                                     │
│    ├── 危险命令正则 (38+ 模式，rm 分级检测，sudo 只拦截危险命令) │
│    ├── 非交互式密码修改检测 (| passwd/chpasswd/newusers/lnewusers 等) │
│    ├── → high/critical → 直接 Deny                            │
│    ├── → 内联脚本 file_access 转层3                            │
│    │     （避免 'python -c "cat /etc/shadow"' 假阳性）         │
│    └── Prompt 注入检测 (62 个中英关键词，9 类)                 │
│                                                              │
│  层2: 逻辑规则检测 (<1ms)                                     │
│    ├── Rule 1: read-before-write 原则 (含 shell 重定向检测)    │
│    ├── Rule 2: 意图偏离检测                                   │
│    ├── Rule 3: 敏感路径访问 (含凭据 6 条目,                  │
│    │          \b 边界匹配避免部分匹配误报)                     │
│    ├── Rule 4: 危险操作模式 (通配符删除/重定向覆盖, 临时目录排除) │
│    ├── Rule 5: 密码修改授权检测 (非交互式需 ask_user_question) │
│    ├── Rule 6: 用户/组删除授权检测 (需 ask_user_question)     │
│    ├── Rule 7: 提权检测 (sudo+危险命令/su/chmod u+s)          │
│    └── Rule 8: 横向移动检测 (ssh/scp/rsync)                   │
│                                                              │
│  层3: LLM + Skill 深度分析 (2-5s)                            │
│    ├── 脚本内容预扫描 (18 个可疑模式，4 组合风险)              │
│    ├── Skill 规则匹配 (12 个 Skill，关键词加权评分)            │
│    ├── LLM 结果缓存 (200 条 FIFO)                            │
│    ├── Provider 自动识别 (15+ Provider)                       │
│    └── LLM 语义安全判断 (fail-closed)                         │
└─────────────────────────────────────────────────────────────┘
```

### 设计原则

- **适配在 OS 层，不在 Agent 层** — 不同 Agent 最终都会调用操作系统的 syscall，这是确定性的
- **标准化 I/O 契约** — 任何 Agent 遵循 API 格式即可接入，无需关心内部实现
- **fail-closed 安全原则** — LLM 调用失败时默认拒绝，不确定时拒绝
- **两级快速放行** — 完全安全命令跳过 L2+L3，只读敏感命令跳过 L3，降低性能开销
- **安全兜底** — 白名单放行前扫描完整命令管道尾部，防止 `echo ... | passwd` 等绕过
- **内置 Skill 信任** — 系统安全 Skill（如 xiaoo-guardian）加载时直接放行，不走 LLM 审计
- **rm 命令分级检测** — 根据 flag 危险度 + 目标路径敏感度分级，`/tmp` 等临时目录不再拦截
- **sudo 收窄** — 不再一刀切拦截所有 sudo，只拦截 sudo 后跟的危险命令（rm/chmod/dd/mkfs 等）
- **内联脚本假阳性防护** — `python -c "x = 'cat /etc/shadow'; print(x)"` 等字符串字面量中的敏感路径不立即拦截，转层3 LLM 语义判断
- **目录遍历动态文件访问检测** — 检测 `os.listdir()` + `open()` 等通过目录遍历动态发现文件并读写的行为，防止绕过静态路径匹配
- **敏感路径读写区分** — 凭据文件（credentials.yml、.env、SSH 密钥等）读写均拦截；系统配置文件（/etc/hosts、/boot/ 等）仅写拦截；特殊设备（/dev/random）仅读拦截
- **Shell 重定向智能识别** — 识别 `2>/dev/null` 等丢弃写法不计入写操作，`lsblk`/`blockdev` 等只读系统工具后的重定向也不判定为写入
- **凭据文件边界匹配** — `credentials.yml`、`.env` 等使用 `\b` 边界匹配避免非文件名拼接（如 `something_credentials_yml`）误报
- **密码修改授权** — 非交互式密码修改（`| passwd`、`chpasswd` 等）必须有 `ask_user_question` 用户授权
- **Shell 重定向写入检测** — `echo data > file` 等重定向操作识别为写入，纳入 read-before-write 规则

## 快速开始

### 安装

**Python (PyPI)**：
```bash
pip install agent-moss
```

如需从源码安装：

```bash
git clone git@gitcode.com:kenhkl/AgentMoss.git
cd AgentMoss

# Python 版
pip install -e .
```

### CLI 使用

```bash
# 生成输入模板 (v2: 含 os_type 和 cwd 字段)
agent-moss init -o input.json

# 运行安全分析
agent-moss analyze input.json

# 安装 systemd service（有 sudo 时）
# 自动创建 /etc/systemd/system/agent_moss.service，--enable 开机自启
agent-moss install --enable

# 无 sudo 时跳过 systemd，提示手动启动：
#   agent-moss server --port 0
agent-moss install

# 查看服务状态（端口、版本、Console URL、三层开关）
agent-moss status

# 启动 HTTP 服务 (TCP)
# 端口被占时自动 findFreePort 往上找空闲端口（9090→9091→…，扫 100 个）
agent-moss server --port 0
# 消费方（xiaoO bridge.py）探测 9090-9095 的 /api/v1/health 自动连上实际端口。

# 启动 Unix Domain Socket 服务（同机部署推荐）
agent-moss server --mode socket --socket /var/run/agent_moss/agent_moss.sock

# 指定配置文件
agent-moss server --mode socket --config /etc/agent_moss/agent_moss.yaml
```

### API 调用

> **鉴权（2026-10 起默认开启，发布版本 ≥ 0.16.15）**：除 `/api/v1/health` 外，所有接口都要求
> `Authorization: Bearer <token>`。首次启动会自动生成，位置：
> `<数据目录>/auth_token`（默认 `~/.config/agentmoss/auth_token`，权限 0600）。
> 下面示例里的 `$TOKEN` 请先 `TOKEN=$(cat ~/.config/agentmoss/auth_token)`。
>
> **root/systemd 注意**：root（sudo/systemd/直接运行）下数据目录固定为
> `/root/.config/agentmoss`，**不再**按 `SUDO_USER` / `LOGNAME` / 首个普通用户猜测真实用户目录；
> token 固定在 `/root/.config/agentmoss/auth_token`。非 root 用户要访问 root 服务的数据
> （含 token）时，显式设置 `AGENT_MOSS_DATA_DIR`，或传 `AGENT_MOSS_AUTH_TOKEN` /
> `AGENT_MOSS_AUTH_TOKEN_FILE`。
>
> 启动日志会打印实际路径：`安全策略: ... auth=on(/path/to/auth_token)`；
> `auth=off` 表示显式关闭了鉴权，`auth=on(explicit)` 表示用了 `AGENT_MOSS_AUTH_TOKEN*`，
> `auth=on(no-token!)` 表示 token 生成失败（通常是数据目录不可写），此时服务以无鉴权方式继续运行，需立即检查。
>
> 相关环境变量：
>
> | 变量 | 作用 |
> |---|---|
> | `AGENT_MOSS_AUTH_MODE` | `auto`（默认，自动生成/读取 token）/ `off`（关闭鉴权） |
> | `AGENT_MOSS_AUTH_TOKEN` | 显式指定全局 token |
> | `AGENT_MOSS_AUTH_TOKEN_FILE` | 从文件读取全局 token |
> | `AGENT_MOSS_AGENT_TOKENS` | 逐 agent token，如 `opendesk=tok-a,qwenpaw=tok-b`；启用后 `agent_id` 必须与 token 匹配 |
>
> 返回 401 时：检查请求头里的 token 与 AgentMoss 实际使用的 token 是否一致
> （`/api/v1/health` 免鉴权，不能用它验证）。需要恢复旧行为：`AGENT_MOSS_AUTH_MODE=off`。

**HTTP TCP 方式：**

```bash
TOKEN=$(cat ~/.config/agentmoss/auth_token)
curl -X POST http://127.0.0.1:9090/api/v1/analyze \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "session_id": "test-001",
    "prompt_session": "列出系统文件",
    "action_history": [],
    "a_next": {
      "action_type": "bash",
      "action_detail": "ls -la /tmp"
    },
    "reason": "查看临时目录",
    "os_type": "",
    "cwd": "/home/user"
  }'
```

**Unix Domain Socket 方式（同机低延迟）：**

```bash
curl --unix-socket /var/run/agent_moss/agent_moss.sock \
  -X POST http://localhost/api/v1/analyze \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "session_id": "test-001",
    "a_next": {
      "action_type": "bash",
      "action_detail": "ls -la /tmp"
    }
  }'
```

**响应示例 (Allow)**：

```json
{
  "decision": "Allow",
  "risk_level": "low",
  "risk_type": "",
  "violated_layers": [],
  "confidence": 100,
  "analysis_duration_ms": 10.8
}
```

## 场景定制规则（客户沙箱）

**场景规则**是针对特定客户的**部署级**安全约束，如「沙箱用户只能读写这几个目录」「禁止 ssh」。
出厂内置一个 `bank` 场景（银行沙箱）：

| 规则 | 级别 | 效果 |
|---|---|---|
| 路径白名单 | high | 只允许 `/home/sandbox`、`/opt/sandbox`、`/tmp`；**其余路径（含根目录 `/`）一律拦**，含 `..` 回溯、`~其它用户` 等逃逸写法 |
| 禁 ssh | critical | 阻断远程访问 / 横向移动类命令 |

### ⚠️ 启用方式：环境变量（不设就完全不生效）

```bash
export AGENT_MOSS_SCENARIO=bank          # 多场景逗号分隔：bank,meow
agent-moss server --port 9090            # 设好后**重启服务**
```

**注意三点**：

1. **不设这个变量 = 场景规则一条都不跑**（不是「默认宽松」，是「形同虚设」）——
   白名单外的路径会照常放行。这是**部署级**配置，改完必须**重启进程**。
2. **HTTP 请求无法指定场景 id**（`/api/v1/analyze` 不接受该字段），
   服务化部署只能靠这个环境变量。
3. 控制台会在**未启用时隐藏「场景定制」页** —— 看不到该页 = 没启用。

### 部署后请确认这行启动日志

服务启动时会打印**部署自检**，直接告诉你场景有没有生效：

```
================ AgentMoss 部署自检 ================
runtime 配置: /home/<user>/.config/agentmoss/agent_moss_runtime.json
层级开关: L1_heuristic=on L2_logic_rules=on L3_llm_analysis=on agent_rules_enabled=on scenario_rules_enabled=on
场景规则已启用: bank（来源：环境变量 AGENT_MOSS_SCENARIO）      ← 这一行
==================================================
```

**没设**的话那行会变成醒目告警：

```
⚠️  场景规则【未启用】—— 环境变量 AGENT_MOSS_SCENARIO 未设置。
    场景定制规则（如银行沙箱的目录白名单 / 禁 ssh）**不会生效**，白名单外的路径会被放行。
    启用方式：设 AGENT_MOSS_SCENARIO=<场景id>（如 bank；多场景逗号分隔）后**重启本服务**。
```

### 静态规则的边界

场景规则是**静态闸门**（看命令文本判断），下面两类挡不住，必须靠执行侧沙箱
（AgentMoss 生成的 Landlock / namespace 策略）兜底：

- **软链逃逸**：白名单目录里放一个指向 `/etc` 的软链，再 `cat /tmp/link/passwd`
- **运行时才确定的命令**：`X=$(cat /tmp/cmd.txt); $X`

新增客户场景：在 `agent_moss/scenarios/<id>/rules.json` 加规则。

## LLM 配置

AgentMoss 的三层防御中，层3（LLM 语义分析）是可选的。层1+层2 的静态规则可以独立运行。

### L3 输入构成与 token 消耗（为什么不会上下文爆炸）

客户常有的顾虑：最坏情况下一个 session 里的每个 tool call 都会走到 L3 LLM 分析，会不会像 Agent 主循环那样把历史会话不断叠加导致上下文爆炸？**不会**。AgentMoss 的 L3 每次调用都是**有界的独立请求**，输入只包含当前这次判定的必要上下文，不随 session 长度无限累积。

**每次 L3 调用的输入构成**（固定模板 + 当前判定要素）：

| 组成部分 | 内容 | 是否有界 |
|---------|------|---------|
| 固定 prompt 模板 | 安全审计员角色 + 判定维度 + JSON 输出格式 | ✓ 固定 |
| 原始用户 prompt | `prompt_session`（本次 session 的用户意图） | 有界（用户单次输入） |
| 待执行动作 | `action_type` + `action_detail`（当前这一次 tool call） | ✓ 单次动作 |
| 执行理由 | `reason` | ✓ 当前动作的理由 |
| 历史动作序列 | `action_history`（本次 session 已执行的动作，每条仅 name + action_detail） | 有界（本次 session 的有限动作） |
| 安全检测规则 | **最多 3 个 Skill**（按关键词相关度从全集选 top-3，每个 Skill 29-39 行） | ✓ 最多 3 个 |
| 前置检测结果 | L1/L2 的命中提示（仅命中时才有） | ✓ 按需 |
| 脚本内容分析 | 内联脚本/管道的静态分析（仅脚本类动作才有） | ✓ 按需 |

**关键边界**：

- **Skill 最多 3 个**：L3 从全部安全 Skill 中按关键词相关度评分取 top-3 注入 prompt（无匹配时兜底 `general_tool_risk_guard` 1 个），不会把全部 Skill 都塞进去。每个 Skill 文件 29-39 行。
- **每次调用独立**：L3 是"判定单个待执行动作 a_next"的独立请求，**不是**把 agent 的全部历史对话叠加进上下文。每次输入 = 固定模板 + 本次 a_next + 本次 session 的历史动作 + ≤3 个 Skill，彼此之间无累积。
- **实测输入大小**：典型 L3 调用 prompt 长度约 **3500-3700 字符（~1k-1.5k token）**，多次调用稳定在该量级，不随 session 延长而膨胀。
- **与 Agent 主循环的区别**：Agent 主循环调 LLM 时通常把全部历史对话（user/assistant 往返）叠加进上下文，session 越长 token 越大；AgentMoss L3 每次只判一个动作，历史只传"已执行动作的摘要"（name + action_detail），且本次判定完即丢弃，不在 L3 侧累积。

> 最坏情况（session 内每个 tool call 都走 L3）下，**单次 L3 的输入 token 仍有界**（~1.5k token 量级），代价是调用次数 × 单次 token，而非单次 token 随历史爆炸。结果缓存（200 条 FIFO）会进一步消减重复调用的实际 LLM 消耗。

### 启用 LLM

**方式 1：环境变量（推荐）**

```bash
export AGENT_MOSS_LLM_API_KEY="sk-your-key"
# 可选：自定义模型和 API 端点
export AGENT_MOSS_LLM_MODEL="glm-5.0"
export AGENT_MOSS_LLM_BASE_URL="https://api.nextapi.store/v1"
```

**方式 2：配置文件**

首次运行 AgentMoss 时，会自动在 `~/.config/agentmoss/config.json` 创建默认配置文件。编辑该文件：

```json
{
  "llm": {
    "api_key": "sk-your-key",
    "model": "glm-5.0",
    "base_url": "https://api.nextapi.store/v1"
  }
}
```

**配置文件优先级**：
1. 环境变量（`AGENT_MOSS_LLM_API_KEY` 等）— 最高优先级
2. `AGENT_MOSS_CONFIG_PATH` 环境变量指定的路径
3. `~/.config/agentmoss/config.json` — 首次运行自动创建
4. 包内默认配置

**方式 3：YAML 配置文件**

通过 `--config` 或 `AGENT_MOSS_CONFIG_PATH` 指定 YAML 文件：

```bash
agent-moss server --config /etc/agent_moss/agent_moss.yaml
```

编辑 `config/agent_moss.yaml`：

```yaml
llm:
  provider: "zhipu"
  model: "glm-5.0"
  base_url: "https://api.nextapi.store/v1"
  api_key_env: "AGENT_MOSS_LLM_API_KEY"
  temperature: 0.1
  max_tokens: 4096

security:
  llm_analysis:
    enabled: true
```

### 禁用 LLM（仅静态规则）

```bash
export AGENT_MOSS_DISABLE_LLM=1
```

### 支持的 LLM Provider

| Provider | URL 匹配 | Provider Hint | 说明 |
|----------|---------|---------------|------|
| OpenAI | `api.openai.com` | `openai` | 默认模型 |
| Anthropic | `anthropic.com` | `claude` / `anthropic` | Claude 系列 |
| Google | `generativelanguage.googleapis.com` | `google` / `gemini` | Gemini 系列 |
| DeepSeek | `api.deepseek.com` | `deepseek` | DeepSeek 系列 |
| 智谱 (GLM) | `open.bigmodel.cn` | `zhipu` / `glm-cn` / `bigmodel` | GLM / CogView |
| 智谱 Coding Plan | `api.z.ai` | `zai-coding-plan` | 智谱编程套餐 |
| OpenRouter | `openrouter.ai` | `openrouter` | 多模型中转 |
| Groq | `api.groq.com` | `groq` | 高速推理 |
| Mistral | `api.mistral.ai` | `mistral` | Mistral 系列 |
| Together | `api.together.xyz` | `together` | 开源模型聚合 |
| xAI | `api.x.ai` | `xai` / `xai-grok` | Grok 系列 |
| MiniMax | `api.minimaxi.com` | `minimax` | MiniMax 系列 |
| GitCode | `api-ai.gitcode.com` | `gitcode` | GitCode AI |
| Ollama | `:11434` | `ollama` | 本地模型 |
| 任意兼容 | — | `other` / `custom` / `local` | 任何 OpenAI 兼容 API |

自动识别 Provider 后，OpenRouter 和 xAI 会注入特定 HTTP Header（Referer、Title），确保平台正确计费。

## Policy Console（策略管控台）

AgentMoss 自带浏览器策略管控台，可视化调整三层开关、规则启停、deny_mode、skill 开关，查看 token 用量统计。Python 版和 TS 版功能对等（同一套前端 SPA，同一套 HTTP API 契约）。

**访问**：服务启动后，浏览器打开 `http://127.0.0.1:9090/console`（端口随服务实际监听端口）。

**鉴权**：与其他接口一致 —— 默认要求 `Authorization: Bearer <token>`（首次启动自动生成，
见上方「API 调用」）。页面首次打开会弹窗要求输入一次，之后存在浏览器本地。
如需独立控制台凭证，仍可设 `AGENT_MOSS_CONSOLE_TOKEN`（该值对 `/console/api/*` 有效）。

**Console API**（前端 SPA 调用，也可直接 curl）：

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/console` | 返回 SPA index.html |
| `GET` / `PUT` | `/console/api/layers` | 查/改三层开关（L1/L2/L3 启停）|
| `GET` | `/console/api/rules` | 查全量规则（L1/L2，含 builtin + 自定义）|
| `PUT` | `/console/api/rules/enabled` | 翻转规则启停 |
| `PUT` | `/console/api/rules/deny_mode` | 改 deny_mode（deny_write/deny_read/deny_both）|
| `PUT` | `/console/api/rules/skip_l3` | 改规则禁用时是否跳过 L3 |
| `PUT` | `/console/api/categories/enabled` | 改分类开关 |
| `POST` / `DELETE` | `/console/api/rules` | 增/删自定义规则（builtin 不可删）|
| `GET` | `/console/api/skills` | 查 L3 skill 全集 |
| `PUT` | `/console/api/skills/enabled` | 翻转 skill 启停 |
| `PUT` | `/console/api/skill-categories/enabled` | 改 skill 分类开关 |
| `POST` / `DELETE` | `/console/api/skills` | 增/删自定义 skill（写 markdown 文件）|
| `GET` | `/console/api/skills/{id}/content` | 查 skill markdown 内容 |
| `GET` | `/console/api/agents` | 查 agent 定制规则（按 agent_id 分区，含 enabled 状态）|
| `PUT` | `/console/api/agents/rules/enabled` | 翻转某 agent 某条规则启停 |
| `POST` / `DELETE` | `/console/api/agents/rules` | 增/删 agent 定制规则条目 |
| `GET` | `/console/api/config` | 查完整 runtime config + 路径 |
| `GET` | `/console/api/env-overrides` | 查被环境变量接管的开关（灰色不可改）|
| `POST` | `/console/api/reset` | 重置为出厂默认 |
| `GET` | `/console/api/token-stats` | token 用量统计 |
| `GET` | `/console/api/token-stats/recent` | 最近 N 条调用记录 |
| `GET` | `/console/api/token-stats/trend` | 趋势（日期×模型）|
| `POST` | `/console/api/token-stats/reset` | 清空统计 |

> Console UI 采用 OpenDesk `--ag-` 设计 token + 暗色模式，为后续原生嵌入 OpenDesk 安全网关新页面预留视觉对齐。

## runtime_config（运行时持久化配置）

runtime config 是 AgentMoss 的**运行时策略持久化层**，区别于启动时读的 YAML 配置：

- **存储**：`~/.config/agentmoss/agent_moss_runtime.json`（`AGENT_MOSS_RUNTIME_CONFIG_PATH` 覆盖）
- **内容**：三层开关、L1/L2 规则启停状态、deny_mode、skip_l3、L3 skill 开关
- **seed**：首次加载时若文件不存在，自动从源码常量 seed 出厂默认（含全部 builtin 规则）并落盘
- **merge**：每次加载时与源码默认 merge——保留用户开关，补入新 builtin，源码已删的 builtin 标记 `source_removed`+禁用（指纹去重，跨 id 变更识别同一规则）
- **优先级**：`AGENT_MOSS_DISABLE_*` env > runtime JSON > `agent_moss_settings.json` > 默认。env 永远最高（Console 会展示被 env 接管的开关为灰色不可改）
- **热生效**：`is_layer_enabled` 每次判定现读 runtime JSON，Console 或**手工编辑文件**都在下一次判定生效（含 `layers` / `agent_rules` / `scenario_rules`），无需重启服务
- **规则来源模式**：`AGENT_MOSS_RULES_MODE=hot|cold|builtin`。`cold` 是冷启动：启动时读内置 + 规则目录 / `CUSTOM_RULES` / 场景并冻结，runtime JSON / Console 完全不参与（适合“客户提供规则 + 防止 runtime 污染”）；`builtin` 仅内置规则（连规则目录也不读）；默认 `hot` 保持上述热加载行为。别名：`AGENT_MOSS_RULES_BUILTIN_ONLY=1`=builtin，`AGENT_MOSS_DISABLE_RULE_HOT_RELOAD=1`=cold
- **query 写操作**：Python 和 TS 均实现全套（seed/merge/CRUD/update_*/`_or_default` 回退），双栈行为一致

Console UI 即是对 runtime config 的可视化操作层；直接编辑 JSON 或用 env 覆盖是另外两个入口，三者最终都落到同一份 runtime JSON。

## openEuler 部署

### 前提

- openEuler 22.03 LTS+
- Python 3.10+
- root 权限

### 一键安装

```bash
sudo dnf install -y python3 python3-pip python3-devel
git clone <repo-url> agent_moss
cd agent_moss
sudo bash scripts/install.sh
```

### 配置 LLM（生产环境）

```bash
# 写入 API Key（文件权限 600）
echo "AGENT_MOSS_LLM_API_KEY=sk-your-key" | sudo tee /etc/agent_moss/agent_moss.env
sudo chmod 600 /etc/agent_moss/agent_moss.env

# 编辑 LLM model / base_url
sudo vim /etc/agent_moss/agent_moss.yaml
```

### 启动方式

```bash
# HTTP TCP 模式（默认，适合跨机/调试）
sudo systemctl enable --now agent_moss

# Unix Socket 模式（同机部署推荐，更低延迟）
# 编辑 /etc/agent_moss/agent_moss.yaml 中 server.mode: "socket"
# 或修改 /etc/systemd/system/agent_moss.service 中的 ExecStart
```

### 启动与验证

```bash
sudo systemctl enable --now agent_moss

# HTTP 模式验证
curl http://127.0.0.1:9090/api/v1/health
# {"status":"healthy","version":"<当前版本，见 pyproject.toml>"}

# Socket 模式验证
curl --unix-socket /var/run/agent_moss/agent_moss.sock \
  http://localhost/api/v1/health
```

### 管理命令

| 命令 | 说明 |
|------|------|
| `systemctl start agent_moss` | 启动 |
| `systemctl stop agent_moss` | 停止 |
| `systemctl restart agent_moss` | 重启 |
| `systemctl status agent_moss` | 查看状态 |
| `journalctl -u agent_moss -f` | 查看日志 |
| `systemctl disable agent_moss` | 取消开机启动 |

#### 多实例（instance 归属）

同机可并存多套 agentmoss（如 xiaoO 与 OpenDesk 各自起一个），通过 `AGENT_MOSS_INSTANCE` 环境变量区分归属。`status` 命令严格按此字段过滤，只认属于自己 instance 的服务：

```bash
# 不带 instance → 期望匹配空串。若 9091 上是 xiaoo 的实例，会报"未运行"并提示检测到其他实例
agent-moss status
# ❌ AgentMoss 服务未运行（instance=(空)）
#    ⚠️ 检测到其他 agent 的 agentmoss 实例: 端口 9091 (instance=xiaoo)

# 带 instance → 精确匹配，正常显示运行中
AGENT_MOSS_INSTANCE=xiaoo agent-moss status
# ✅ AgentMoss 服务运行中
#    Instance: xiaoo
#    端口:     9091
```

> **instance 隔离「进程识别 + token 消耗」，不隔离规则配置。** 同机所有实例共享同一份 `~/.config/agentmoss/agent_moss_runtime.json`（除非显式设 `AGENT_MOSS_RUNTIME_CONFIG_PATH` 指向不同文件）。通用 L1/L2/L3 规则全局一致；不同 agent 的定制规则在文件内按 `agent_rules.<agent_id>` 分区天然隔离。任意 console 修改都写入共享文件，其他实例同步生效。

> **token 消耗按实例隔离**：设了 `AGENT_MOSS_INSTANCE=<name>` 时，token 统计文件落在 `<data_root>/<instance>/agent_moss_token_stats.json`（如 `opendesk` → `~/.config/agentmoss/opendesk/...`），各 agent 只读写自己实例的文件；未设则用默认 `~/.config/agentmoss/agent_moss_token_stats.json`。「最近调用」(console `token-stats/recent`) 读同一文件，随之隔离。

### 防火墙（HTTP 模式需要）

```bash
sudo firewall-cmd --add-port=9090/tcp --permanent
sudo firewall-cmd --reload
```

## API 参考

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/v1/health` | 健康检查 |
| `POST` | `/api/v1/analyze` | 安全分析 |
| `POST` | `/api/v1/review` | 低频全量回顾（供 AgentGate 触发） |

### POST /api/v1/analyze

**请求体 (v2)**：

```json
{
  "session_id": "sess-001",
  "prompt_session": "list files",
  "prompt_history": [
    {"text": "list files", "actions": [{"action_type": "bash", "action_detail": "ls -la"}]}
  ],
  "action_history": [
    {"action_type": "bash", "action_detail": "pwd", "called_at": "2026-11-10T10:00:00"}
  ],
  "session_history": [
    {"session_id": "other", "action_history": [{"action_type": "bash", "action_detail": "cat /tmp/r.txt"}]}
  ],
  "a_next": {
    "action_type": "bash",
    "action_detail": "cat /etc/passwd",
    "called_at": "2026-11-10T10:00:01"
  },
  "reason": "执行理由 (可选)",
  "agent_id": "",
  "instance_id": "",
  "os_type": "",
  "cwd": "/home/user/project",
  "metadata": {"stateful_incremental": false}
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `session_id` | string | 是 | 会话唯一标识 |
| `prompt_session` | string | 否 | 最近一条用户提示（层1 注入检测会扫描此字段） |
| `prompt_history` | array | 否 | 交错 prompt 历史：`[{text, actions: [{action_type, action_detail}]}]` |
| `action_history` | array | 否 | 历史动作：`[{action_type, action_detail, called_at?, output?}]`。`ask_user_question` 动作应带 `output`（用户回答），否则改密/删用户授权会被判未授权 |
| `session_history` | array | 否 | 多 session 历史：`[{session_id, action_history: [...]}]`，供 L2.2 跨会话验证 |
| `a_next.action_type` | string | 是 | 动作类型 (bash/file_read/file_write 等) |
| `a_next.action_detail` | string | 是 | 命令/动作详情 |
| `a_next.called_at` | string | 否 | ISO 8601 时间，供 L2 授权时效窗和 P4 提权外传窗口使用 |
| `reason` | string | 否 | 执行理由 |
| `os_type` | string | 否 | `"linux"` / `"windows"`，留空自动检测 |
| `cwd` | string | 否 | 当前工作目录 |
| `agent_id` | string | 否 | 调用方 agent 标识（如 `xiaoo` / `opendesk`）。留空走通用模式。 |
| `instance_id` | string | 否 | agent 安装实例标识，仅用于展示层脱敏 |
| `metadata` | object | 否 | 扩展元数据（`llm_config`/`llm_log_path`/`stateful_incremental`/`is_error` 等） |

**响应字段**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `decision` | string | `Allow` / `Deny` |
| `reason` | string | 决策原因 |
| `risk_level` | string | `low` / `medium` / `high` / `critical` |
| `risk_type` | string | 风险类别 (file_access, script_execution, data_exfiltration, prompt_injection, privilege_escalation, lateral_movement, ...) |
| `violated_layers` | array | 触发的检测层，如 `["1", "2"]` |
| `violated_policy` | string | 违反的具体条款 (Deny 时) |
| `policy` | string | Cerberus TOML 策略 (Allow 时) |
| `confidence` | int | 置信度 0-100 |
| `analysis_duration_ms` | float | 分析耗时（毫秒） |
| `violation_chain` | array | 组合链反例路径（按引擎返回的步骤数组） |
| `violation_graph` | object/null | 结构化攻击链图：`{nodes, edges}`，供前端可视化 |

### POST /api/v1/review

低频全量回顾（供 AgentGate 触发），从状态库/历史会话重新验证攻击链。

**请求字段**：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `agent_id` | string | 否 | 目标 agent（决定状态库分桶） |
| `db_path` | string | 否 | AgentGate SQLite 文件或 tool_calls JSON 目录；为空则用 `sessions` |
| `sessions` | array | 否 | 多 session 历史，结构同 `session_history` |
| `a_next` | object | 否 | 可选，连同当前动作一起判定 |
| `is_error` | bool | 否 | 当前动作是否执行失败（生命周期判定） |
| `output_pending` | bool | 否 | 返回待攻击前序链清单 |

**响应字段**：

| 字段 | 类型 | 说明 |
|---|---|---|
| `agent_id` | string | 目标 agent |
| `seeded_nodes` | int | 写入状态库的节点数 |
| `verified` | bool | 全量形式化验证是否通过 |
| `violations` | array | 全量验证发现的违规 |
| `pending_prefixes` | array | 待补全的攻击前序链 |
| `state_nodes` | int | 状态库累计节点数 |
| `discovered_patterns` | array | 数据驱动发现的跨 session 危险组合 |

### GET /api/v1/health

响应字段：`status`（服务状态）、`version`（版本）、`instance`（实例归属标识，未配置为空串）。

## 配置

优先级：环境变量 > YAML 配置文件 > 内置默认值

### 环境变量


| 变量 | 说明 | 默认值 |
|------|------|--------|
| `AGENT_MOSS_LLM_API_KEY` | LLM API Key（兼容 fallback `OPENROUTER_API_KEY` / `OPENAI_API_KEY`）| 未设置 |
| `AGENT_MOSS_LLM_MODEL` | LLM 模型名称 | `gpt-4o` (TS) / `anthropic/claude-3.5-sonnet` (Python) |
| `AGENT_MOSS_LLM_BASE_URL` | LLM API 端点 | `https://api.openai.com/v1` (TS) / `https://openrouter.ai/api/v1` (Python) |
| `AGENT_MOSS_LLM_PROVIDER` | Provider 标识（决定注入 HTTP headers）| 从 base_url 推断 |
| `AGENT_MOSS_LLM_TEMPERATURE` | LLM 采样温度 | `0.1` |
| `AGENT_MOSS_LLM_MAX_TOKENS` | LLM 最大输出 token 数 | `4096` |
| `AGENT_MOSS_LLM_TIMEOUT` | LLM 单次调用超时（秒）| `300` |
| `AGENT_MOSS_LLM_RETRIES` | LLM 调用重试次数 | `2`（共 3 次尝试） |
| `AGENT_MOSS_LLM_HISTORY_MAX_ITEMS` | L3 prompt 最多注入多少条历史动作（0 = 不限）| `20` |
| `AGENT_MOSS_LLM_ACTION_DETAIL_MAX_CHARS` | L3 prompt 中单条历史动作详情最多保留字符数（0 = 不截断）| `500` |
| `AGENT_MOSS_LLM_MAX_PROMPT_TOKENS` | L3 输入 prompt 的 token 总预算（0 = 不限），超限逐级压缩历史 | `0` |
| `AGENT_MOSS_LLM_FAIL_MODE` | LLM 失败策略：`fail_open`（默认 Allow+warn）/ `fail_closed`（Deny）| `fail_open` |
| `AGENT_MOSS_DISABLE_LLM` | 设为 `1` 禁用层3 LLM | 未设置 |
| `AGENT_MOSS_DISABLE_HEURISTIC` | 设为 `1` 禁用层1 特征匹配 | 未设置 |
| `AGENT_MOSS_DISABLE_LOGIC_RULES` | 设为 `1` 禁用层2 逻辑规则 | 未设置 |
| `AGENT_MOSS_LOG_PATH` | 全量 hook 日志 + LLM prompt 日志（bridge 记 HOOK_INPUT/OUTPUT，L3 记 prompt，写同文件；对应 audit_agent `AUDIT_LOG_PATH`）| 未设置（不记录）|
| `AGENT_MOSS_CUSTOM_RULES` | 自定义规则 JSON 数组 | `[]` |
| `AGENT_MOSS_RULES_MODE` | 规则来源模式：`hot`（默认）/ `cold`（冷启动：启动时读规则目录并冻结，runtime/Console 不参与）/ `builtin`（仅内置）。非法值按 builtin fail-safe | 未设置（hot）|
| `AGENT_MOSS_RULES_BUILTIN_ONLY` | 设为 `1` = builtin（仅内置）| 未设置 |
| `AGENT_MOSS_DISABLE_RULE_HOT_RELOAD` | 设为 `1` = cold（禁用 runtime/Console 热加载，但启动时仍读规则目录）| 未设置 |
| `AGENT_MOSS_ENABLE_POLICY_GEN` | 设为 `1` 启用 Policy 生成 | 未设置 |
| `AGENT_MOSS_CONFIG_PATH` | 主配置 YAML 路径 | `~/.config/agentmoss/agent_moss.yaml` |
| `AGENT_MOSS_DATA_DIR` | 数据根目录（所有 `~/.config/agentmoss` 文件落盘位置）。root（含 systemd）下默认固定 `/root/.config/agentmoss`，不猜真实用户；非 root 访问 root 服务时需显式指定。**其下 `rules/` 子目录可整份覆盖内置规则**（见「自定义规则」通道 B）| `~/.config/agentmoss` |
| `AGENT_MOSS_RUNTIME_CONFIG_PATH` | runtime JSON（层级开关+规则启停持久化）| `~/.config/agentmoss/agent_moss_runtime.json` |
| `AGENT_MOSS_TOKEN_STATS_PATH` | token 用量统计 JSON（显式优先于 instance 派生路径）| 见「token 消耗按实例隔离」|
| `AGENT_MOSS_SETTINGS_PATH` | `agent_moss_settings.json` 路径 | 包内默认 |
| `AGENT_MOSS_CONSOLE_TOKEN` | Console Bearer 鉴权 token | 未设（本机免鉴权）|
| `AGENT_MOSS_URL` / `HOST` / `PORT` | bridge.py 连服务用（端口被占自动 findFreePort）| `127.0.0.1:9090` |

### 配置文件

参考 `config/agent_moss.yaml`。

### 自定义规则

**三条通道，语义不同，别用混**（都能加载「你们自己的规则」，但代价不一样）：

| 通道 | 怎么用 | 语义 | 内置规则更新时 |
|---|---|---|---|
| **A. runtime config**（Console） | 控制台增删改，或直接编辑 `~/.config/agentmoss/agent_moss_runtime.json` | **逐条合并** | ✅ 新内置规则**自动出现且默认启用** |
| **B. 覆盖目录** `<data_root>/rules/` | 放同名 `l1_rules.json` / `l2_rules.json` / `l3_rules.json` / `mc_rules.json` / `tool_registry.json` | **整份替换**该文件 | ❌ 不反映，需自行跟进 |
| **C. 环境变量** | `AGENT_MOSS_CUSTOM_RULES` 注入 L1 正则 | 追加 | ✅ 不受影响 |

> `data_root` 默认 `~/.config/agentmoss`，可用 `AGENT_MOSS_DATA_DIR` 改。
> **通道 B 是整份替换**：只想改其中一类，也要先拷完整的内置文件再改 —— 少写顶层键会让
> 对应类别**一条规则都不跑**（服务启动与加载时都会打显著告警）。日常调规则优先用 A。

**C. 环境变量注入：**

```bash
export AGENT_MOSS_CUSTOM_RULES='[
  {"pattern": "kubectl delete namespace", "action": "Deny", "severity": "critical"},
  {"pattern": "docker rm -f", "action": "Deny", "severity": "high"}
]'
```

### 配置模板

```yaml
# OS Profile 自动选择
os_profile:
  type: ""         # 留空自动检测，可手动指定 linux / windows

# 服务调用模式
server:
  mode: "http"     # "http" (TCP) 或 "socket" (Unix Domain Socket)
  socket_path: "/var/run/agent_moss/agent_moss.sock"
```

## 项目结构

```
AgentMoss/
├── agent_moss/               # Python 实现 (PyPI: agent-moss)
│   ├── __init__.py
│   ├── cli.py                # 命令行工具 (init/analyze/server)
│   ├── __version__.py
│   ├── profiles/             # OS Profile 系统
│   │   ├── base.py           # OSProfile 抽象基类
│   │   ├── linux.py          # LinuxProfile
│   │   └── windows.py        # WindowsProfile
│   ├── engine/               # 安全分析引擎
│   │   ├── analyzer.py       # 分析入口
│   │   ├── coordinator.py    # 三层协调器 + L1.2/L2.3 递归脚本链 + fail-open
│   │   ├── heuristic.py      # 层1: 特征匹配检测 (危险命令 + 注入关键词，热重载 runtime_config)
│   │   ├── logic_rules.py    # 层2: 逻辑规则 (敏感路径/意图/密码/用户删除，credential 区分)
│   │   ├── llm_analyzer.py   # 层3: LLM + Skill 深度分析 (skip_l3_hints + token 记录)
│   │   ├── script_analyzer.py        # 脚本预扫描
│   │   ├── script_content_analyzer.py # L1.2/L2.3 递归脚本链内容分析 (移植自 audit_agent)
│   │   ├── inline_analyzer.py        # 内联脚本/文本区分
│   │   ├── skill_engine.py   # Skill 匹配引擎 (热重载 runtime_config 禁用 skill)
│   │   └── types.py
│   ├── infra/                # 基础设施
│   │   ├── config.py         # 配置管理 (YAML + 环境变量 + 继承 xiaoo config.toml)
│   │   ├── runtime_config.py # runtime JSON：seed/merge/CRUD/层级开关持久化 (51 函数)
│   │   ├── token_stats.py   # token 用量统计 (JSON 持久化)
│   │   ├── llm_client.py     # LLM 客户端 (流式回退 + Provider header 适配)
│   │   ├── logging.py / parsers.py / policy_cache.py / prompt_templates.py
│   ├── server/               # HTTP API 服务层 (FastAPI)
│   │   ├── app.py            # 应用 + run_server + _find_free_port (端口动态分配)
│   │   ├── routes.py         # /api/v1/* 路由 (health/analyze/brain)
│   │   ├── models.py / middleware.py / socket_server.py
│   ├── console/              # Policy Console (FastAPI sub-router, 23 路由)
│   │   ├── router.py         # /console/api/* (layers/rules/skills/config/env/reset/token-stats)
│   │   └── static/index.html # 自包含 SPA (--ag- 风格 + 暗色模式)
│   ├── adapters/  # 适配器层 (observable)
│   ├── skills/    # 安全 Skill 规则 (Markdown)
│   ├── templates/ # Prompt 模板 + policy_mapping
│   ├── agents/    # 三方 agent 定制化扩展 (xiaoO / opendesk) — rules.json 单一事实源
│   └── brain/     # 规则自学习/存储
│
├── config/agent_moss.yaml   # YAML 配置模板
```

