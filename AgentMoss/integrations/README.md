# integrations/ — 第三方 Agent 对接件

本目录存放**对接第三方 Agent 平台**的集成件（插件/适配器）。这些不是 AgentMoss
引擎的一部分，而是把 Agent 的每一次工具调用送到 AgentGate → AgentMoss 的采集端。

**本仓库是私仓，这些文件只在这里维护**——不要拷贝到公开仓库/fork（QwenPaw 等
上游仓库是公开的，推送即泄露）。

---

## qwenpaw-plugin/

QwenPaw（Windows exe / 统信 Linux / 鸿蒙）的**零侵入**对接插件。

### 它做什么

挂在 QwenPaw 的**权限检查环节**（`on_check_permission`），在工具真正执行**之前**：

1. 取本次工具调用（工具名 + 参数）、本轮提示词、完整会话上下文
2. 打包上报 AgentGate `/api/v1/analyze`
3. AgentMoss 判 `Deny` → 阻止执行；判 `Allow` → 放行
4. AgentGate 不可用时 fail-open（可配 `fail_closed`）

**不修改 QwenPaw 源码**，也不修改 AgentGate / AgentMoss 源码。

### 采集到的字段（与 AgentMoss 需求对齐）

| AgentMoss 字段 | 来源 | 必需 |
|---|---|---|
| `session_id` | `agent._request_context` | ✅ |
| `a_next`（工具名+参数） | 工具调用本身（工具名经 AgentGate 映射为 `bash` 等） | ✅ |
| `prompt_session` | `agent.state.context` 中最后一条用户消息 | |
| `prompt_history` | 同上，按「提示词 → 动作」分组 | |
| `action_history` | 同上，取真实 `ToolCallBlock` 展平 | |
| `cwd` | `agent._workspace_dir` | |
| `reason` | 工具调用旁的 assistant 文本 | |
| `os_type` | `platform.system()`（**agent 所在平台**，非网关平台） | |
| `hostname`（metadata） | `platform.node()`（**agent 所在机器**）。AgentGate 用 `agent_type:hostname` 生成 agent_id，缺了它所有同类型 agent 会并成一条记录 | |
| `session_history` | AgentGate 从 SQLite 补跨会话历史 | |

### 安装

```bash
# 拷到 QwenPaw 插件目录（Windows: %USERPROFILE%\.qwenpaw\plugins\）
mkdir -p ~/.qwenpaw/plugins
cp -r qwenpaw-plugin ~/.qwenpaw/plugins/agentmoss-gate
# 可选：配置网关卡地址
cp ~/.qwenpaw/plugins/agentmoss-gate/config.example.json \
   ~/.qwenpaw/plugins/agentmoss-gate/config.json
```

> 目录名必须是 `agentmoss-gate`（与 `plugin.json` 的 `id` 一致）。

### 测试

插件依赖 AgentScope（由 QwenPaw 提供），用 QwenPaw 的 venv 跑：

```bash
# repo 里有 QwenPaw 检出时
/home/hkl/github/QwenPaw/venv/bin/python integrations/qwenpaw-plugin/test_agentmoss_gate_plugin.py
```

测试**自包含**（不依赖 QwenPaw 源码，只用 `agentscope` 的消息/权限类型），
17 个用例覆盖：Deny 阻断 / Allow 放行 / fail-open / fail-closed /
上下文提取（纯文本、真实工具调用、cwd、reason）/ 工具输入不被 JSON 转义。

### 已知边界

1. **被 QwenPaw 自己拦下的调用**：插件能看到（挂在权限检查外层），会一并上报
2. **`run_tool_batch` 内层调用**：看不到——该功能的内层动作绕过了整条权限检查链路
   （QwenPaw 自身的治理漏洞，已提交上游 PR）
3. **工具不存在 / 参数解析失败**：看不到（未进入权限检查），非安全场景
