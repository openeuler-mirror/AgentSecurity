# AgentMoss 第三方对接说明书

> 面向想接入 AgentMoss 安全审计的第三方 Agent / 框架（xiaoO、OpenDesk/AgentGate、claude-code 等）。
> 本文档说明：如何调用 `/api/v1/analyze`、如何正确传参（尤其是**同 session 完整历史 prompt + 交错时序**的获取与组织），
> 以及各消费端（L2 意图一致性 / L3 语义分析）如何使用这些信息。
>
> 双端实现（Python `agent_moss/` 与 TypeScript `ts/`）行为与字段语义完全一致，本文档对两者同时适用。

---

## 1. 总体架构

AgentMoss 是一个**独立常驻 HTTP 服务**，对要执行的**下一步动作**（`a_next`）做三层安全判定：

```
   第三方 Agent ──POST /api/v1/analyze──▶  AgentMoss
      (构造请求)                              │
        │                                    ├─ L1 特征匹配（静态，快）
        │                                    ├─ L2 逻辑规则（需历史/意图/cwd）
        │                                    ├─ L3 LLM 语义分析（需完整意图上下文）
        │                                    ▼
    ◀── Allow / Deny + reason + risk ────── 返回
```

接入方只需做两件事：
1. **在每次执行工具前**，构造一个 `AnalyzeRequest` POST 给 AgentMoss。
2. **按本文档第 3 节**，把「当前动作」和「同 session 的历史上下文」忠实传上来。

---

## 2. 服务发现与端口

- 服务用 `--port 0` 启动时会从 **9090** 起向上找空闲端口（`findFreePort`）。
- 同机可能并存多个 agent 的 AgentMoss（用 `AGENT_MOSS_INSTANCE` 区分，如 `xiaoo` / `opendesk`）。
- **消费方端口解析优先级**（与 `bridge.py` / `AgentGate` 一致）：
  1. `AGENT_MOSS_URL`（显式完整 URL，最高优先）
  2. `AGENT_MOSS_PORT`（显式端口）
  3. 探测 9090–9095 的 `/api/v1/health`，找 `status=="healthy"` 且 `instance` 匹配的那个
  4. 兜底 `http://127.0.0.1:9090`

> `GET /api/v1/health` 返回 `{status, version, instance}`。**归属过滤最重要**：
> 多 agent 同机时，必须按 `instance` 过滤，否则会连到别人（如 OpenDesk）的进程。

---

## 3. `POST /api/v1/analyze` 请求契约

### 3.1 完整示例

```json
{
  "session_id": "agent-sandbox-001",
  "prompt_session": "继续",
  "prompt_history": [
    {
      "text": "请帮我读取分析 src/app.ts",
      "actions": [
        {"action_type": "read", "action_detail": "cat src/app.ts"}
      ]
    },
    {
      "text": "请帮我为 src/ 补写单元测试",
      "actions": []
    },
    {
      "text": "继续",
      "actions": []
    }
  ],
  "action_history": [
    {"action_type": "read", "action_detail": "cat src/app.ts"}
  ],
  "a_next": {
    "action_type": "bash",
    "action_detail": "rm /home/me/src/app.ts"
  },
  "reason": "清理文件",
  "os_type": "",
  "cwd": "/home/me",
  "agent_id": "xiaoo",
  "metadata": {
    "llm_config": {"baseUrl": "...", "apiKey": "...", "model": "..."},
    "llm_log_path": "/tmp/agentmoss.log"
  }
}
```

### 3.2 字段语义

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `session_id` | string | 是 | 会话唯一标识，同 session 保持一致 |
| `prompt_session` | string | 否 | **最近一条**用户消息（兼容字段，向后兼容；新接入方也应传） |
| `prompt_history` | array | 否 | **完整的交错历史 prompt**（本文第 4 节核心），按时间序 |
| `action_history` | array | 否 | 历史动作序列（行为链检测消费） |
| `a_next.action_type` | string | 是 | 当前动作类型（bash/file_read/file_write/toolName 等） |
| `a_next.action_detail` | string | 是 | 当前命令/动作详情 |
| `reason` | string | 否 | 执行理由 |
| `os_type` | string | 否 | `"linux"` / `"windows"`，空则自动检测 |
| `cwd` | string | 否 | 工作目录，用于敏感路径/间接访问判断 |
| `agent_id` | string | 否 | 调用方标识（如 `xiaoo`/`opendesk`），用于加载该 agent 专属规则 |
| `metadata` | object | 否 | 扩展：`llm_config`（per-request LLM 覆盖）、`llm_log_path` 等 |

### 3.3 `prompt_history` 元素结构

`prompt_history` 的每个元素是一个 **turn**（`{text, actions}`）：

```json
{
  "text": "该轮用户的 prompt 文本",
  "actions": [
    {"action_type": "bash", "action_detail": "该 prompt 触发的动作1"},
    {"action_type": "file_read", "action_detail": "该 prompt 触发的动作2"}
  ]
}
```

- `actions` 是该 prompt **触发并持续到下一个 prompt 之前**的所有动作，**按执行顺序**。
- `prompt_history` 整体按时间序排列（turn1 → turn2 → …）。

---

## 4. 核心：如何获取「同 session 完整历史 prompt + 交错时序」

这是本说明书最重要的部分。**你的直接诉求和 AgentMoss 的诉求是一致的**：
L2 意图一致性和 L3 语义分析需要「用户真正的意图」，而不是最近一条"继续"。

### 4.1 为什么单个 prompt_session 不够

多轮会话中，用户可能输入 `继续` / `continue` / `重试` 等简短指令。此时：
- `prompt_session`（最近一条）= "继续"，**不含**最初的"读取/分析"意图。
- 若 AgentMoss 只看到"继续"，L2 意图一致性检测就**漏报**——它无法判断
  "当前 rm 删除" 是对"读取意图"的偏离。

`prompt_history` 让 AgentMoss 看到**会话全貌**：历史里出现过"读取"，当前却删除 → 意图偏离，拦截。

### 4.2 从你自己的会话存储构造 `prompt_history`

第三方 Agent 通常已维护一份会话消息列表（含每条 User 消息 + 工具调用）。构造方法：

```
prompt_history = []
current = None
for msg in 按时间序遍历会话消息:
    if msg 是 User 消息:
        current = {"text": msg.text, "actions": []}
        prompt_history.append(current)
    elif msg 是 工具调用/结果 且 current 非空:
        current.actions.append({"action_type": toolName, "action_detail": command})
```

即：**每条 User 消息开一个新 turn，其后的工具动作归入该 turn**，直到下一条 User 消息。

参考实现：
- **AgentGate v3**（`ts/src/v3/proxy/session.ts`）已经用 `prompts: [{text, capturedAt, actions:[]}]`
  这个结构聚合，可直接复用。
- **xiaoO**（`crates/hook/src/hookers/plugin/tool/adaptor.rs`）目前只传了单条 `prompt_session`，
  需按上述方式补 `prompt_history`。

### 4.3 关键陷阱：会话压缩（compaction）会吞掉初始意图

长会话会触发 compaction——把历史消息压成摘要：
- **xiaoO**：`crates/compact/src/manager.rs` 用 `session_memory_compact:` 摘要**替换**整个历史，
  原始 User 消息被移除。
- **OpenDesk**：`CompactSeparatorMessage`（role=`compact_separator`）承载摘要，历史 User 被替换。

这会导致 `lastUserMessage()` / `recent_messages().find(User)` **取到的是最新 User 消息
（可能是"继续"），而最初的读取/搜索意图已在摘要里，无法直接取到**。

**接入方必须在 compaction 边界保意图快照**。推荐两种方案（择一或组合）：

1. **hook 层缓存**：在 compaction 触发前，把本次会话按 4.2 构造的 `prompt_history`
   快照缓存到会话元数据（`compact_summary` 或独立字段），后续每次请求沿用。
2. **摘要固化意图**：把「会话初始意图关键词/一句话摘要」写进 compaction 摘要文本，
   让 `prompt_history` 至少能从中提取到意图。

> 若不处理 compaction，`prompt_history` 在长会话后可能只剩摘要后的最近几轮——
> 虽比单条"继续"好，但最初的意图仍可能丢失。**主动保快照是最稳的。**

### 4.4 `action_history` 必须完整传（OpenDesk 现状是缺陷）

- **xiaoO**：`action_history` 已完整（遍历所有 ToolResult，含 input+output），✅。
- **OpenDesk/AgentGate**：当前 `hook.ts` 的 payload **没有 `action_history`**，AgentGate
  schema 默认空数组 → 行为链检测（`external_read→sensitive_write` 等 `BEHAVIOR_CHAIN:` 规则）
  **完全失效**。接入时应补全 `action_history`（与 `prompt_history` 的 actions 内容一致）。

---

## 5. 消费端如何使用这些信息

### 5.1 L2 意图一致性（`_check_intent_consistency` / TS `runLogicCheck`）

- 收集 `prompt_history` 里**所有 turn 的 `text`** + `prompt_session`，按时间序去重。
- 只要**任一**历史 prompt 命中意图关键词（读取/查看/分析/search/查询…），
  且 `a_next` 命中危险动作（删除/rm/format…），即判定**意图偏离** → Deny。
- 这样"继续"不会覆盖最初的读取意图（防漏报），而中性 prompt + 无害动作不会误报。

### 5.2 L3 LLM 语义分析

- `prompt_history` 被格式化为「历史用户意图（按时间序）」段落喂给 LLM。
- 只喂 prompt 文本 + 各轮动作类型（详情截断），与 `action_history` 互补不重复，
  **context 增量≈ prompt 文本**，可控。
- LLM 据此判断意图一致性、行为链、是否"借任务之名行越权之实"。

---

## 6. 双端实现一致性

AgentMoss 的 Python 与 TypeScript 实现**共用同一份 `security_judge_template.txt`**，
字段语义、L2 意图逻辑、L3 prompt 格式完全对齐。接入方无需区分是哪个实现，
按本文档构造请求即可。

---

## 7. 快速自检清单

接入后，用以下 "一拦一放" 场景验证：

| 场景 | prompt_session | prompt_history | a_next | 期望 |
|------|---------------|----------------|--------|------|
| 历史读取意图 + 当前删除 | "继续" | `[{text:"查看 src/app.ts",actions:[...]},{"text":"继续"}]` | `rm src/app.ts` | **Deny**（intent_deviation） |
| 中性"继续" + 无害动作 | "继续" | `[{text:"继续",actions:[]}]` | `ls` | **Allow** |
| 历史读取意图已结束，当前写测试 | "补写测试" | 含读取 turn + 补写 turn | `write app.test.ts` | **Allow** |

> 对应 AgentMoss 测试用例：`tests/cases/l2/logic-21-intent-deviation-through-history.json`（拦）、
> `logic-22-intent-neutral-continue-allow.json`（放）、`logic-23-intent-history-not-current-allow.json`（放）。