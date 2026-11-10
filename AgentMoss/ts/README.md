# AgentMoss (TypeScript)

AgentMoss TypeScript 实现 — 可被任意 AI Agent 调用的独立通用安全分析服务。三层防御引擎（特征匹配 → 逻辑规则 → LLM 语义分析），两级快速放行白名单，fail-closed 安全原则。

> 当前版本：**v0.2.1** | npm: `@kenhkl/agent-moss`

## 安装

```bash
npm install @kenhkl/agent-moss
```

从源码构建：

```bash
cd ts
npm install
npm run build
```

## CLI 使用

```bash
# 生成输入模板
npx agent-moss init -o input.json

# 运行安全分析
npx agent-moss analyze input.json

# 启动 HTTP 服务（默认端口 9090）
npx agent-moss server --port 9090
```

## 编程调用

```typescript
import { createApp } from '@kenhkl/agent-moss';

const app = createApp();
// 通过 Hono app.fetch 在 Node.js / Bun / Electron 中调用
```

或直接 HTTP 调用：

```typescript
const resp = await fetch('http://127.0.0.1:9090/api/v1/analyze', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
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

## 架构

```
快速放行白名单
├── 完全安全 (15 bash 模式 + 6 action types) → 跳过 L2+L3
└── 只读敏感 (15 bash 模式 + 8 action types) → 跳过 L3

层1: 特征匹配静态检测 (<1ms)
├── 危险命令正则: 48 个模式（rm 分级检测，sudo 只拦截危险命令，nmap/masscan/zmap 检测）
├── → high/critical → 直接 Deny
├── → 内联脚本 file_access 转层3（避免 'python -c "cat /etc/shadow"' 假阳性）
├── 注入关键词: 56 个中英双语关键词（9 类: 指令覆盖/角色劫持/命令注入/...）
└── 自定义规则: AGENT_MOSS_CUSTOM_RULES 环境变量注入

层2: 逻辑规则检测 (<1ms)
├── Rule 1: read-before-write（有历史但无读取 → flag）
├── Rule 2: 意图偏离（读取意图 vs 删除动作）
├── Rule 3: 敏感路径访问（20 条路径 + 5 条凭据文件, \b边界匹配, 读写均拦截）
├── Rule 4: 危险操作（通配符删除 + 重定向覆盖，临时目录排除）
├── Rule 5: 密码修改授权（非交互式需 ask_user_question）
├── Rule 6: 用户/组删除授权（需 ask_user_question）
├── Rule 7: 提权检测（sudo+危险命令/su/chmod u+s/setuid）
└── Rule 8: 横向移动（ssh/scp/rsync，排除 localhost）

层3: LLM + Skill 深度分析 (2-5s)
├── 脚本预扫描: 读取 .sh 文件（最多 500 行），16 个可疑模式
├── Skill 匹配: 12 个 Skill，关键词加权评分，返回 top 3
├── LLM 缓存: 200 条 FIFO，避免重复调用
├── Provider 识别: 15+ Provider，自动注入 HTTP Header
├── LLM 调用: 支持重试（默认 2 次重试 = 3 次尝试）
└── fail-closed: 失败时拒绝（confidence=60, source='llm_failure'）
```

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `AGENT_MOSS_LLM_API_KEY` | LLM API Key（回退 `OPENAI_API_KEY`） | 未设置 |
| `AGENT_MOSS_LLM_MODEL` | LLM 模型名称 | `gpt-4o` |
| `AGENT_MOSS_LLM_BASE_URL` | LLM API 端点 | `https://api.openai.com/v1` |
| `AGENT_MOSS_LLM_TEMPERATURE` | 采样温度 | `0.1` |
| `AGENT_MOSS_LLM_MAX_TOKENS` | 最大输出 token 数 | `4096` |
| `AGENT_MOSS_LLM_TIMEOUT` | LLM 单次调用超时（秒），覆盖配置文件 `timeout.prompt1_timeout` | `40` |
| `AGENT_MOSS_LLM_RETRIES` | LLM 调用重试次数 | `2`（共 3 次尝试） |
| `AGENT_MOSS_DISABLE_LLM` | 设为 `1` 禁用层3 LLM | 未设置 |
| `AGENT_MOSS_DISABLE_HEURISTIC` | 设为 `1` 禁用层1 特征匹配 | 未设置 |
| `AGENT_MOSS_DISABLE_LOGIC_RULES` | 设为 `1` 禁用层2 逻辑规则 | 未设置 |
| `AGENT_MOSS_CUSTOM_RULES` | 自定义规则 JSON 数组 | `[]` |

### 自定义规则

```bash
export AGENT_MOSS_CUSTOM_RULES='[
  {"pattern": "kubectl delete namespace", "action": "Deny", "severity": "critical"},
  {"pattern": "docker rm -f", "action": "Deny", "severity": "high"}
]'
```

## 支持的 Provider

| Provider | URL 匹配 | Provider Hint | Header 注入 |
|----------|---------|---------------|-------------|
| OpenAI | `api.openai.com` | `openai` | — |
| Anthropic | `anthropic.com` | `claude` / `anthropic` | — |
| Google | `generativelanguage.googleapis.com` | `google` / `gemini` | — |
| DeepSeek | `api.deepseek.com` | `deepseek` | — |
| 智谱 (GLM) | `open.bigmodel.cn` | `zhipu` / `glm-cn` | — |
| 智谱 Coding Plan | `api.z.ai` | `zai-coding-plan` | — |
| OpenRouter | `openrouter.ai` | `openrouter` | Referer + Title |
| Groq | `api.groq.com` | `groq` | — |
| Mistral | `api.mistral.ai` | `mistral` | — |
| Together | `api.together.xyz` | `together` | — |
| xAI | `api.x.ai` | `xai` / `xai-grok` | Referer |
| MiniMax | `api.minimaxi.com` | `minimax` | — |
| GitCode | `api-ai.gitcode.com` | `gitcode` | — |
| Ollama | `:11434` | `ollama` | — |
| 任意兼容 | — | `other` / `custom` / `local` | — |

## 项目结构

```
ts/src/
├── cli.ts                    # CLI 入口 (init/analyze/server)
├── config.ts                 # 全局配置 (环境变量 + Provider 识别 + Header 注入)
├── models.ts                 # Zod 数据模型
├── routes.ts                 # Hono API 路由 (POST /analyze, GET /health)
├── server.ts                 # Hono HTTP 服务 (CORS + logger)
└── engine/
    ├── types.ts              # 核心类型 (SecurityJudgment, LLMConfig, ...)
    ├── coordinator.ts        # 三层协调器 + 两级快速放行白名单
    ├── heuristic.ts          # 层1: 48 危险模式 + 56 注入关键词 + isInlineScriptCommand
    ├── logic-rules.ts        # 层2: 8 条规则 + 20 敏感路径
    ├── llm-analyzer.ts       # 层3: LLM 分析 (缓存 + 重试 + fail-closed)
    ├── script-analyzer.ts    # 脚本内容预扫描 (18 个可疑模式)
    ├── skill-loader.ts       # Skill 加载与关键词匹配 (12 个 Skill)
    └── template-loader.ts    # Prompt 模板加载 (3 个模板)
```

## 依赖

| 包 | 说明 |
|---|---|
| `hono` | HTTP 框架 |
| `@hono/node-server` | Node.js HTTP 适配 |
| `openai` | LLM API 客户端 |
| `zod` | 数据校验 |
| `yaml` | YAML 解析 |

## 构建

```bash
npm run build    # tsup 打包到 dist/
npm run dev      # tsx 热重载开发 (端口 9090)
```
