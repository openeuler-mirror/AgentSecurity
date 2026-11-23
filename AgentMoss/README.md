# AgentMoss

AgentMoss 是一个**可被任意 AI Agent 调用的独立通用安全分析服务**。基于 OS Profile 机制，自动适配 Linux/Windows 的 syscall 检测模式，提供三层防御安全分析（特征匹配 → 逻辑规则 → LLM 语义分析）。

> **本场景规则范围**：只内置 `xiaoo` agent 定制规则；不包含 `opendesk` agent 规则和 `bank` 场景规则。

> v2 更新：新增 OS Profile 系统（Linux/Windows 自适应）、两级快速放行白名单、rm 命令分级检测、脚本内容预扫描、LLM 结果缓存、Provider 自动识别与 Header 注入、fail-closed 安全原则。
>
> v0.4.0 新增：非交互式密码修改检测（passwd/chpasswd/newusers/lnewusers 等）、密码修改授权检测（ask_user_question 前置检查）、内置安全 Skill 白名单（xiaoo-guardian 直接放行）、系统信息命令快速放行（whoami/id/hostname 等 12 个命令）、shell 重定向写入检测。
>
> v0.5.0 新增：L1/L2 规则收窄减少误杀（sudo 只拦截危险命令、rm -rf /tmp 不拦截、dd/mkfs/format 收窄、/etc/passwd 仅从 L1 移除、git push --force 降级为 medium）、nmap/masscan/zmap 网络扫描检测、lnewusers 批量用户添加检测、L2 通配符删除排除临时目录、用户/组删除授权检测、chgpasswd/lpasswd/gpasswd 检测。

## 目录

- [架构](#架构)
- [快速开始](#快速开始)
- [场景与 Agent 定制规则（本场景范围）](#场景与-agent-定制规则本场景范围)
- [LLM 配置](#llm-配置)
- [openEuler 部署](#openeuler-部署)
- [API 参考](#api-参考)
- [Policy Console（策略管控台）](#policy-console策略管控台)
- [runtime_config（运行时持久化配置）](#runtime_config运行时持久化配置)
- [配置](#配置)
- [项目结构](#项目结构)
- [测试](#测试)
- [环境变量参考](docs/ENV_VARS.md)
- [竞争力说明（规则集来源 / 竞品对比 / 测试准确率 / L3 token 消耗）](docs/COMPETITIVENESS.md)
- [形式化引擎与组合攻击链路 — 实现总览](docs/L2.2_FORMAL_COMBO_ENGINE.md)
- [自身安全审计与修复报告（发现了什么 / 修没修 / 残留风险）](docs/SECURITY_AUDIT.md)
- [自身安全模型（鉴权 / 来源校验 / 数据隔离 / 性能开销）](docs/SELF_SECURITY.md)

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
│  ★ agent 定制白名单 (按 agent_id 加载，如 xiaoo 的         │
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

**TypeScript (npm)**：
```bash
npm install @kenhkl/agent-moss
```

如需从源码安装：

```bash
git clone git@gitcode.com:kenhkl/AgentMoss.git
cd AgentMoss

# Python 版
pip install -e .

# TypeScript 版
cd ts && npm install && npm run build
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
> | `AGENT_MOSS_AGENT_TOKENS` | 逐 agent token，如 `xiaoo=tok-a,qwenpaw=tok-b`；启用后 `agent_id` 必须与 token 匹配 |
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

### TypeScript / Node.js 调用

```typescript
import { createApp } from '@kenhkl/agent-moss';

const app = createApp();
// 通过 Hono app.fetch 在 Node.js / Bun / Electron 中调用
// 或启动独立服务: npx agent-moss server --port 9090
```

也可以直接 HTTP 调用：

```typescript
import { readFileSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';

const token = readFileSync(join(homedir(), '.config/agentmoss/auth_token'), 'utf-8').trim();
const resp = await fetch('http://127.0.0.1:9090/api/v1/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({
        session_id: 'sess-001',
        a_next: { action_type: 'bash', action_detail: 'ls -la' },
        os_type: 'linux',
        cwd: '/home/user',
    }),
});
const result = await resp.json();
// → { decision: 'Allow'|'Deny', risk_level: 'low'|'...', ... }
```

**响应示例 (Deny)**：

```json
{
  "decision": "Deny",
  "reason": "检测到递归强制删除关键路径 (rm -rf /...)",
  "risk_level": "critical",
  "risk_type": "script_execution",
  "violated_layers": ["L1.1"],
  "confidence": 95,
  "analysis_duration_ms": 1.2
}
```

## 场景与 Agent 定制规则（本场景范围）

本 openEuler 场景**只内置 `xiaoo` agent 定制规则**（`agent_moss/agents/xiaoo/rules.json`）。

- 不包含 `opendesk` agent 规则；
- 不包含 `bank` 场景规则，因此 `AGENT_MOSS_SCENARIO=bank` 在本场景不会加载任何内置场景规则；
- 通用 L1/L2/L3 规则不受影响。

如需为客户增加场景规则，在 `agent_moss/scenarios/<id>/rules.json` 添加，并同步更新本场景的投影清单。

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
- **规则来源模式**：`AGENT_MOSS_RULES_MODE=hot|cold|builtin`。`cold` 是冷启动：启动时读内置 + 规则目录 / `CUSTOM_RULES` / 场景并冻结，runtime JSON / Console 完全不参与（适合“客户提供规则 + 防止 runtime 污染”）；`builtin` 仅内置规则（连规则目录也不读）；默认 `hot` 保持上述热加载行为。别名：`AGENT_MOSS_RULES_BUILTIN_ONLY=1`=builtin，`AGENT_MOSS_DISABLE_RULE_HOT_RELOAD=1`=cold。详见 `docs/ENV_VARS.md` §3.1/§3.4
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
# {"status":"healthy","version":"<当前版本，见 pyproject.toml / ts/package.json>",
#  "metrics":{"loop_lag_ms":1.2,"loop_lag_max_ms":18.4,"pools":{"pool:biz":3},
#             "chain_nodes":20150,"chain_db_bytes":8628736}}

# Socket 模式验证
curl --unix-socket /var/run/agent_moss/agent_moss.sock \
  http://localhost/api/v1/health
```

> `metrics` 是运行态指标（0.17.23 起）：**`loop_lag_ms` 是判断「是否有同步代码
> 卡住事件循环」最直接的信号**，正常 < 10ms；`pools` 是各并发池当前占用，
> `pool:biz` 打满意味着新的 analyze 会被 503；`chain_nodes` / `chain_db_bytes`
> 用于提前发现链状态膨胀。排查与调参见 `docs/PERFORMANCE_TUNING.md`。

### 管理命令

| 命令 | 说明 |
|------|------|
| `systemctl start agent_moss` | 启动 |
| `systemctl stop agent_moss` | 停止 |
| `systemctl restart agent_moss` | 重启 |
| `systemctl status agent_moss` | 查看状态 |
| `journalctl -u agent_moss -f` | 查看日志 |
| `systemctl disable agent_moss` | 取消开机启动 |
| **`agent-moss doctor`** | **部署自检**：配置 / 规则 / 权限 / 磁盘 / 链状态，一条命令看清 |
| **`agent-moss state status`** | 链状态库大小、节点数、agent 分桶 |
| **`agent-moss state backup <file>`** | 一致性备份（服务在跑也能备） |
| **`agent-moss state restore <file>`** | 从备份恢复（须先停服务） |
| **`agent-moss verify <file>`** | 批量验证一组命令的判定（规则改动前后对比） |
| `bash scripts/diagnose.sh` | 一键收集排障信息（环境/配置/日志/指标） |
| `bash scripts/bench_analyze.py` | 分层压测（L1/L2 找吞吐拐点，L3 找超时拐点） |
| `bash scripts/soak_test.py` | 长稳压测（验证跑久是否退化） |
| `bash scripts/audit_deps.sh` | 依赖漏洞扫描（发版前跑） |

详见 [`docs/PERFORMANCE_TUNING.md`](docs/PERFORMANCE_TUNING.md)、
[`docs/UPGRADE_GUIDE.md`](docs/UPGRADE_GUIDE.md)、
[`docs/LLM_TROUBLESHOOTING.md`](docs/LLM_TROUBLESHOOTING.md)。

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

> **token 消耗按实例隔离**：设了 `AGENT_MOSS_INSTANCE=<name>` 时，token 统计文件落在 `<data_root>/<instance>/agent_moss_token_stats.json`（如 `xiaoo` → `~/.config/agentmoss/xiaoo/...`），各 agent 只读写自己实例的文件；未设则用默认 `~/.config/agentmoss/agent_moss_token_stats.json`。「最近调用」(console `token-stats/recent`) 读同一文件，随之隔离。详见 `docs/ENV_VARS.md`。

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
| `agent_id` | string | 否 | 调用方 agent 标识（如 `xiaoo`）。留空走通用模式。详见 [SECURITY_RULES.md「三方 agent 定制规则」](SECURITY_RULES.md#三方-agent-定制规则agent_mossagentsidrulesjson) |
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

> 完整清单（含 audit_agent 迁移对照、bridge.py 端口变量、配置优先级）见 [`docs/ENV_VARS.md`](docs/ENV_VARS.md)。

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
| `AGENT_MOSS_TRACE_LEVEL` | 分层追踪日志：`off` / `summary`（每层判定+耗时）/ `full`（完整请求体、L1/L2 命中细节、L3 完整 prompt 与完整响应）。落 `<数据目录>/agent_moss_trace.log`，JSON Lines。排障首选，见 `docs/PERFORMANCE_TUNING.md` | `off` |
| `AGENT_MOSS_SLOW_REQUEST_MS` | 单次 analyze 超过该毫秒数打 warning（0=关闭） | `1000` |
| `AGENT_MOSS_POOL_BIZ` | `/api/v1/analyze` 并发上限，满了直接 503 | `16` |
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
│   ├── agents/    # 三方 agent 定制化扩展 (xiaoO) — rules.json 单一事实源，py+ts 共享
│   └── brain/     # 规则自学习/存储
│
├── ts/                       # TypeScript 实现 (npm: @kenhkl/agent-moss) — 功能与 Python 对等
│   ├── src/
│   │   ├── cli.ts            # CLI 入口 (init/analyze/server)
│   │   ├── config.ts         # 配置 (环境变量 + fail-open)
│   │   ├── models.ts         # Zod 数据模型
│   │   ├── routes.ts         # Hono API 路由 (health/analyze)
│   │   ├── server.ts         # Hono HTTP + findFreePort + 挂载 Console
│   │   ├── package-json.ts
│   │   ├── engine/           # 三层防御引擎 (与 py 对等)
│   │   │   ├── coordinator.ts / heuristic.ts / logic-rules.ts
│   │   │   ├── llm-analyzer.ts / script-analyzer.ts / script-content-analyzer.ts
│   │   │   ├── inline-analyzer.ts / skill-loader.ts / template-loader.ts
│   │   │   ├── token-stats.ts / types.ts
│   │   ├── infra/runtime-config.ts  # runtime JSON 全功能 (seed/merge/CRUD/query，对齐 py)
│   │   └── console/          # Policy Console (Hono sub-app, 23 路由 1:1 对齐 py)
│   │       ├── router.ts / index.ts
│   │       └── static/index.html  # 复用 py 的同一份 SPA
│   └── package.json
│
├── hooks/xiaoO/             # xiaoO hook 桥接 (bridge.py + plugin.json)
│   └── bridge.py             # stdin JSON → POST /api/v1/analyze → stdout {result,reason}；探测兜底
├── config/agent_moss.yaml   # YAML 配置模板
├── docs/
│   ├── design.md             # 架构需求设计
│   ├── ENV_VARS.md           # 环境变量参考 + audit_agent 迁移对照
│   └── ...
└── tests/
    ├── conftest.py / test_all_cases.py / test_agents_xiaoo.py / test_brain.py
    ├── test_find_free_port.py  # 端口动态分配单测
    └── cases/                  # 测试用例 JSON
```

## 测试

### 用例归一：单一事实源

所有安全分析测试用例集中在 `tests/cases/{l1,l2,l3}/*.json`（**226 个**，按 L1/L2/L3 分子目录），**Python 与 TypeScript 双端共用同一批 case**（双端各自另有语言特有的手写单测，故 pytest/vitest 报告 passed 总数 > JSON 数且两数不同，详见 `tests/cases/README.md`）。每个 JSON 含：

| 字段 | 说明 |
|---|---|
| `expected_decision` | 期望决策（`Deny`/`Allow`），双端都断言 |
| `expected_risk_level` | 期望风险等级（`critical`/`high`/`medium`/`low`），双端都断言 |
| `expected_risk_type` | 期望风险类型（文档用，不断言） |
| `expected_layers` | 期望命中层（文档用，不断言） |
| `llm_required` | L3 case 标 `true`：禁 LLM 时 skip，需有效 LLM key 真跑 |
| `input` | `{session_id, action_history, a_next, reason, os_type, cwd}` |

按子目录分层：`l1/` 164 个（特征匹配命中+放行）、`l2/` 25 个（逻辑规则命中+放行）、`l3/` 28 个（13 个 security skill 命中+放行，`llm_required:true`）。

**新增 case 只改一个 JSON**，双端自动跑：

```bash
# 新增 case：复制一个现有 JSON 改内容即可（按层放对应子目录）
cp tests/cases/l1/deny-01-chmod-777.json tests/cases/l1/deny-99-mine.json
# 编辑 deny-99-mine.json 的 desc / expected_* / input
```

### Python 端

```bash
# 前两层静态规则（禁用 LLM，CI 默认跑法，189 个 L1+L2 case 全绿）
python3 -m pytest tests/test_all_cases.py::TestLayer1And2 -v

# 仅跑 JSON case 加载器（L1+L2，禁 LLM）
AGENT_MOSS_DISABLE_LLM=1 python3 -m pytest tests/test_all_cases.py::TestLayer1And2 -v

# 包含 L3 LLM 层（需有效 LLM key，28 个 L3 case 真调 LLM，串行跑约 2~4 分钟）
# key/地址/model 从 env 或 ~/.config/agentmoss/config.json 统一判定 + 连通性探测，
# 判定通过才真跑；缺 key 或 key 不通则 skip（见下「L3 判定策略」）
python3 -m pytest tests/test_all_cases.py::TestLayer3 -v
# 若需显式覆盖 config.json，仍可传环境变量：
#   AGENT_MOSS_LLM_API_KEY="sk-xxx" AGENT_MOSS_LLM_BASE_URL="https://api.deepseek.com/v1" AGENT_MOSS_LLM_MODEL="deepseek-v4-flash"
```

入口：`tests/test_all_cases.py`

- `TestLayer1And2` 参数化读 `tests/cases/{l1,l2}/*.json`，断言 `expected_decision` / `expected_risk_level`
- `TestLayer3` 参数化读 `tests/cases/l3/*.json`，跑不跑由 `llm_probe_available` fixture 决定（判定源 env+config.json 有 key 且连通性探测通过才真调 LLM，否则 `pytest.skip`）
- `TestHeuristicDetector` / `TestLogicRules` / `TestOSProfile` / `TestCoordinator` 跑各子模块单测

#### L3 判定策略（双端统一）

L3 是否真跑由**统一判定源 + 连通性探测**决定，Python 与 TS 对称（避免两端判定不一致 + 坏 key fail-open 假通过）：

1. **判定源**：`AGENT_MOSS_LLM_API_KEY` env → 否则 `~/.config/agentmoss/config.json` 的 `llm.api_key`（Python 走 `get_default_config().llm.api_key`，TS 走 `isLLMAvailable()`）。
2. **连通性探测**：有 key 再发一次 `max_tokens=1` ping（Python `_probe_llm` / TS `probeLLMConnection`）。连通才真跑；key 无效/网络不通 → 明确提示 + skip，不假通过。
3. **同源**：probe 的 base_url/model/api_key 与 L3 实际调用一致，probe 通过即真跑可信。

### TypeScript 端

```bash
cd ts

# JSON case 加载器（L1+L2，禁用 LLM，189 个 L1+L2 case 全绿）
npx vitest run src/__tests__/json-cases.test.ts

# 全量（含 heuristic / logic-rules / coordinator / agents 等）
npx vitest run

# 类型检查
npx tsc --noEmit

# 包含 L3 LLM 层（需有效 LLM key，28 个 L3 case 真调 LLM）
# 注意 TS 端与 Python 端有两个差异：
#   1) vitest 默认每 test 5s 超时，L3 跑 LLM 慢需加 --test-timeout=120000
#   2) 加载器并行跑 28 个 L3 case 会撞 LLM rate limit 走 fallback 假命中，
#      已加串行 gate + --no-file-parallelism 避免
# key/地址/model 从 env 或 config.json 统一判定 + 连通性探测，判定通过才真跑
npx vitest run src/__tests__/json-cases.test.ts --no-file-parallelism --test-timeout=120000
# 若需显式覆盖：
#   AGENT_MOSS_LLM_API_KEY="sk-xxx" AGENT_MOSS_LLM_BASE_URL="https://api.deepseek.com/v1" AGENT_MOSS_LLM_MODEL="deepseek-v4-flash"
```

入口：`ts/src/__tests__/json-cases.test.ts`

- `beforeAll`：判定源（`isLLMAvailable`，env + config.json）无 key → 设 `AGENT_MOSS_DISABLE_LLM=1`（仅跑 L1+L2，对齐 Python）；有 key → `probeLLMConnection()` 发一次 ping，连通才保留 LLM；key 无效/网络不通 → 禁 LLM + 明确提示，避免坏 key fail-open 假通过
- 读 `tests/cases/{l1,l2,l3}/*.json`，转 `snake_case → camelCase`，调 `runAnalysis`，断言 `expected_decision` / `expected_risk_level`
- **L1/L2 用例（非 `llm_required`）强制禁 LLM**（对齐 Python `default_config`）：只测 L1+L2 静态结果，避免 LLM 二次判定翻盘（Allow 变 Deny）导致波动。仅 `llm_required` 的 L3 case 在 LLM 可用时真跑
- **risk_level 断言**：仅对 L1/L2 case 断言；L3 case 只断言 `expected_decision`（LLM 层 risk_level 有非确定性波动，对齐 Python `TestLayer3`）
- `llm_required:true` 的 L3 case：禁 LLM 时 `it.skip`；有 key + 探测通过时串行 gate（promise 链）一次只跑一个，避免并行撞 LLM rate limit 走 fail-open fallback 假命中
- 与 Python `TestLayer1And2` / `TestLayer3` 共用同一批 case，双端行为不一致会立刻暴露

### 双端跑 L3 差异说明

| 差异点 | Python | TypeScript |
|---|---|---|
| L3 跑法 | `TestLayer3` 参数化串行跑，pytest 自带 test 超时足够 | 加载器需 `--test-timeout=120000`（vitest 默认 5s 不够）+ `--no-file-parallelism`（串行 gate 避免撞 rate limit） |
| LLM 字段名 | Python 解析兼容 `risk_level`/`riskLevel` 两种 | TS 已修 `runLLMAnalysis` 兼容两种（之前只取 `riskLevel` 拿不到走兜底 `'low'`） |
| 禁 LLM 跑 L3 | `TestLayer3` 全 skip | 加载器 `llm_required:true` case 单个 skip |
| L3 判定源 | `get_default_config().llm.api_key`（env + config.json） | `isLLMAvailable()`（env + config.json） |
| 连通性探测 | `conftest.py` `_probe_llm`（session 缓存，只 ping 一次） | `config.ts` `probeLLMConnection()`（beforeAll 探测一次） |

### LLM 测试与 API Key

- L3 是否真跑由**统一判定源 + 连通性探测**决定，Python 与 TS 对称（见上文「L3 判定策略」）：
  - 判定源：`AGENT_MOSS_LLM_API_KEY` env → 否则 `~/.config/agentmoss/config.json` 的 `llm.api_key`
  - 连通性探测：有 key 再发 `max_tokens=1` ping，连通才真跑；key 无效/网络不通 → 明确提示 + skip（**不假通过**）
- 无 Key 时：Python `TestLayer3` skip；TS 加载器设 `AGENT_MOSS_DISABLE_LLM=1`，L3 case `it.skip`
- **禁用 LLM 跑纯静态测试**：TS 加载器内部已设 `AGENT_MOSS_DISABLE_LLM=1`；Python 默认就是不调 LLM

### 双端一致性核对

除 JSON case 加载器外，还有专项一致性测试：

| 测试 | 核对内容 |
|---|---|
| `ts/src/__tests__/dual-parity.test.ts` | `isWriteOperation` 双端对同一批 case 返回一致 |
| `ts/src/__tests__/json-cases.test.ts` | 226 个 JSON case 双端 `decision` + `risk_level` 一致 |

> **归一前**：Python 跑 Python 的 `test_all_cases.py`，TS 跑 TS 的 `*.test.ts`，期望值各写各的，双端不一致发现不了。**归一后**：期望值写在 JSON 里，双端共用，改一处 JSON 双端同步——`ts/src/__tests__/json-cases.test.ts` 加载器一上线就暴露了 2 处真实代码差异 + 3 处 JSON 期望值错误。
