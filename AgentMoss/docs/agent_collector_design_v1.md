# Agent 数据采集服务需求设计文档 v1.0

> 版本：v1.0  
> 日期：2026-05-19  
> 状态：待确认  
> 关联文档：[agent_moss_adapter_design_v2.md](./agent_moss_adapter_design_v2.md)

---

## 目录

1. [背景与定位](#1-背景与定位)
2. [核心需求](#2-核心需求)
3. [目标 Agent 调研](#3-目标-agent-调研)
4. [架构设计](#4-架构设计)
5. [各 Agent 接入方案](#5-各-agent-接入方案)
6. [数据标准化与转换](#6-数据标准化与转换)
7. [安全决策执行机制](#7-安全决策执行机制)
8. [跨操作系统支持](#8-跨操作系统支持)
9. [部署架构](#9-部署架构)
10. [实施路线](#10-实施路线)

---

## 1. 背景与定位

### 1.1 问题描述

AgentMoss 作为通用安全分析服务，定义了标准化输入输出契约。但在实际部署中，不同 AI Agent（Claude Code、OpenCode、OpenClaw 等）的工具调用事件格式和拦截机制各不相同。需要一个**数据采集服务**来：

1. **监听各 Agent 的工具调用事件**（在命令执行前）
2. **将异构数据统一转换为 AgentMoss 标准格式**
3. **调用 AgentMoss 进行安全分析**
4. **根据分析结果执行放行或阻断**

### 1.2 服务定位

```
                           Agent 数据采集服务
┌──────────┐           ┌──────────────────────┐           ┌─────────────┐
│          │ Hook事件   │  ┌────────────────┐  │ 标准格式   │             │
│  Agent   │──────────▶│  │  格式转换 +     │──│─────────▶│ AgentMoss   │
│ (各种)   │           │  │  安全决策执行   │  │           │             │
│          │◀─────────│  └────────────────┘  │◀─────────│             │
└──────────┘  放行/阻断  └──────────────────────┘  Allow/Deny└─────────────┘
```

### 1.3 与 AgentMoss 的关系

| 维度 | AgentMoss | Agent 数据采集服务 |
|------|-----------|-------------------|
| **定位** | 通用安全分析引擎 | 数据采集 + 决策执行适配层 |
| **职责** | 判断命令是否安全 | 拦截命令 → 转换格式 → 调用分析 → 执行决策 |
| **部署方式** | 系统服务（systemd） | 随 Agent 启动的 sidecar / hook 脚本 |
| **OS 感知** | 通过 OS Profile 适配检测规则 | 通过所在 OS 选择合适的采集方式 |
| **Agent 感知** | 不需要（OS 层适配） | 需要（针对不同 Agent 的 Hook 机制） |

---

## 2. 核心需求

### 2.1 功能需求

| # | 需求 | 优先级 | 说明 |
|---|------|--------|------|
| F1 | 捕获 Agent 工具调用事件 | P0 | 在命令实际执行前拦截工具调用 |
| F2 | 提取执行上下文 | P0 | 命令字符串、工作目录、会话 ID、历史动作 |
| F3 | 转换为标准格式 | P0 | 映射到 AgentMoss 的 AnalyzeRequest 格式 |
| F4 | 调用 AgentMoss 安全分析 | P0 | 通过 Unix Socket 或 HTTP 调用 |
| F5 | 执行安全决策 | P0 | Allow → 放行 / Deny → 阻断并返回原因 |
| F6 | 本地缓存决策 | P1 | 相同命令+上下文可复用上次决策 |
| F7 | 审计日志记录 | P1 | 记录所有分析请求和结果 |
| F8 | 支持多 Agent 类型 | P1 | Claude Code / OpenCode / OpenClaw / Cursor |
| F9 | 跨 OS 支持 | P1 | Linux (openEuler/Ubuntu) + Windows |

### 2.2 非功能需求

| # | 需求 | 说明 |
|---|------|------|
| N1 | **低延迟** | 安全分析在 AgentMoss 中完成，采集服务本身只做格式转换，延迟 < 10ms |
| N2 | **不可绕过** | Agent 配置必须保证每次工具调用都经过数据采集服务 |
| N3 | **故障安全（Fail-Closed）** | AgentMoss 不可用时，默认拒绝执行（安全优先） |
| N4 | **轻量级** | 可以是单个脚本，不引入额外服务进程（对 Agent 资源零侵入） |

---

## 3. 目标 Agent 调研

### 3.1 Claude Code

**拦截机制**：PreToolUse Hook

Claude Code 在执行每个工具前，会调用配置的 hook 命令，通过 stdin 传入 JSON 格式的工具调用信息。

**Hook 配置**（`.claude/settings.json` 或 `CLAUDE.md`）：

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /usr/local/bin/agent_moss_collector.py claude-code"
          }
        ]
      }
    ]
  }
}
```

**可获取的输入数据**：

```json
{
  "session_id": "abc123",
  "transcript_path": "/home/user/.claude/projects/.../transcript.jsonl",
  "cwd": "/home/user/my-project",
  "permission_mode": "default",
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": {
    "command": "rm -rf /tmp/cache/*",
    "description": "Clean up temporary cache files",
    "timeout": 120000,
    "run_in_background": false
  },
  "tool_use_id": "toolu_01ABC123..."
}
```

**决策控制**（通过 stdout 返回 JSON）：

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "检测到递归强制删除操作"
  }
}
```

决策选项：`"allow"`（绕过权限提示）、`"deny"`（阻止执行）、`"ask"`（提示用户）、`"defer"`（延迟）

### 3.2 OpenCode

**拦截机制**：内置 Permission 系统

OpenCode 在工具调用前构造 `CreatePermissionRequest` 对象，经过权限服务判断。

**可获取的数据字段**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `SessionID` | string | 会话标识 |
| `ToolName` | string | 工具名称（`"bash"`, `"edit"`, `"write"` 等） |
| `Action` | string | `"read"`, `"write"`, `"execute"` |
| `Description` | string | 人类可读的操作描述，通常包含完整命令 |
| `Params` | interface{} | 工具特定参数（bash 时为完整命令字符串） |
| `Path` | string | 目标路径（bash 时可能为空或工作目录） |

**接入方式**：

OpenCode 的权限系统是内置的，不支持外部 hook。需要通过以下方式接入：
- **插件机制**：开发 OpenCode Plugin，注册为权限检查插件
- **MCP Server**：注册为 MCP 工具，OpenCode 在执行 bash 前调用
- **包装脚本**：替换 bash 命令为安全检查包装器

### 3.3 OpenClaw

**拦截机制**：exec tool 内置安全模式（deny / allowlist / full）

OpenClaw 的 exec 工具在执行前自动进行白名单匹配和安全二进制检查。

**可获取的数据字段**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `command` | string | 要执行的 shell 命令 |
| `workdir` | string | 工作目录 |
| `env` | object | 环境变量 |
| `elevated` | boolean | 是否提权 |
| `background` | boolean | 是否后台运行 |
| `host` | string | 执行主机 |
| `security` | string | 安全模式 |

**接入方式**：

OpenClaw 的 exec 工具不支持外部 hook，但可通过以下方式接入：
- **Gateway 层拦截**：在 OpenClaw Gateway 中注入安全检查中间件
- **包装 Shell**：替换默认 shell 为安全包装器（`/usr/local/bin/safe-exec`）
- **Node 层 hook**：在远程 Node 上安装命令执行包装器

### 3.4 Cursor

**拦截机制**：社区 cursor-hooks 方案，类似 Claude Code PreToolUse 模式

通过配置文件监听 Cursor Agent 的工具调用事件。

### 3.5 通用方案：Shell 包装器

对于不支持外部 Hook 的 Agent，使用通用 Shell 包装器方案：

```bash
#!/bin/bash
# /usr/local/bin/agent-moss-wrap — 通用命令安全包装器

COMMAND="$*"
CWD="$(pwd)"
SESSION_ID="${AGENT_SESSION_ID:-unknown}"

# 调用 AgentMoss 安全分析
RESULT=$(curl -s --unix-socket /var/run/agent_moss/agent_moss.sock \
  -X POST http://localhost/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d "{
    \"session_id\": \"$SESSION_ID\",
    \"a_next\": {\"action_type\": \"bash\", \"action_detail\": \"$COMMAND\"},
    \"cwd\": \"$CWD\"
  }")

# 解析决策
DECISION=$(echo "$RESULT" | jq -r '.decision')
REASON=$(echo "$RESULT" | jq -r '.reason')

if [ "$DECISION" = "Deny" ]; then
    echo "[AgentMoss] 操作已被安全策略阻止: $REASON" >&2
    exit 126
fi

# 放行
exec /bin/bash -c "$COMMAND"
```

---

## 4. 架构设计

### 4.1 总体架构

```
┌──────────────────────────────────────────────────────────────────┐
│                        Agent 主机                                │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                    AI Agent 进程                           │ │
│  │  ┌──────────┐    ┌──────────┐    ┌──────────┐              │ │
│  │  │Claude Code│    │ OpenCode │    │ OpenClaw │   ...        │ │
│  │  └────┬─────┘    └────┬─────┘    └────┬─────┘              │ │
│  │       │ Hook/         │ Plugin/      │ Wrapper/            │ │
│  │       │ Permission    │ MCP          │ Gateway             │ │
│  └───────┼───────────────┼──────────────┼────────────────────┘ │
│          │               │              │                       │
│          ▼               ▼              ▼                       │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                 Agent 数据采集服务                          │ │
│  │                                                            │ │
│  │  ┌──────────────────────────────────────────────────────┐ │ │
│  │  │  Hook Handlers（每种 Agent 一个处理器）                │ │ │
│  │  │  ├── ClaudeCodeHandler    (stdin JSON → 标准格式)     │ │ │
│  │  │  ├── OpenCodeHandler      (PermissionReq → 标准格式)  │ │ │
│  │  │  ├── OpenClawHandler      (exec params → 标准格式)    │ │ │
│  │  │  └── GenericHandler       (通用 shell 包装器)         │ │ │
│  │  └────────────────────┬─────────────────────────────────┘ │ │
│  │                       │                                    │ │
│  │  ┌────────────────────▼─────────────────────────────────┐ │ │
│  │  │  核心逻辑                                            │ │ │
│  │  │  ├── FormatNormalizer   (异构格式 → AnalyzeRequest)   │ │ │
│  │  │  ├── AgentMossClient    (Socket/HTTP 调用)            │ │ │
│  │  │  ├── DecisionCache      (LRU 本地缓存)                │ │ │
│  │  │  └── AuditLogger        (审计日志)                    │ │ │
│  │  └──────────────────────────────────────────────────────┘ │ │
│  └───────────────────────┬────────────────────────────────────┘ │
│                          │                                      │
└──────────────────────────┼──────────────────────────────────────┘
                           │ Unix Socket / HTTP
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│                     AgentMoss 服务                               │
│  POST /api/v1/analyze → { decision, reason, risk_level, ... }   │
└──────────────────────────────────────────────────────────────────┘
```

### 4.2 数据流

```
1. Agent 决定执行命令 "rm -rf /tmp/*"
       │
2.     ▼ Agent Hook 触发，传入命令信息
       │
3.     ▼ Hook Handler 提取字段
       │  { tool_name, command, cwd, session_id, ... }
       │
4.     ▼ FormatNormalizer 转换
       │  → AnalyzeRequest { session_id, a_next: {action_type:bash, action_detail:...}, cwd, ... }
       │
5.     ▼ DecisionCache 检查
       │  命中缓存？ → 直接返回上次决策
       │  未命中 ↓
       │
6.     ▼ AgentMossClient 调用
       │  POST /api/v1/analyze (Unix Socket)
       │
7.     ▼ 接收 AnalyzeResponse
       │  { decision: "Deny", reason: "...", risk_level: "critical" }
       │
8.     ▼ 执行决策
       │  Allow → 返回 permissionDecision: "allow"
       │  Deny  → 返回 permissionDecision: "deny" + reason
       │
9.     ▼ 记录审计日志
       │
10.    ▼ Agent 继续执行或收到拒绝通知
```

---

## 5. 各 Agent 接入方案

### 5.1 Claude Code 接入

**方案**：PreToolUse Hook + Python 脚本

**配置**（`.claude/settings.json`）：

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 -m agent_moss_collector.handle claude-code",
            "timeout": 30000
          }
        ]
      },
      {
        "matcher": "Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "python3 -m agent_moss_collector.handle claude-code"
          }
        ]
      }
    ]
  }
}
```

**Hook Handler 实现逻辑**：

```python
# handlers/claude_code.py

import json, sys, os

def handle():
    """从 stdin 读取 Claude Code PreToolUse hook JSON，调用 AgentMoss，返回决策"""
    input_data = json.loads(sys.stdin.read())

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})

    # 提取字段
    command = tool_input.get("command", "")
    cwd = input_data.get("cwd", os.getcwd())
    session_id = input_data.get("session_id", "")
    description = tool_input.get("description", "")

    # 构造标准请求
    request = {
        "session_id": session_id,
        "a_next": {
            "action_type": tool_name.lower(),
            "action_detail": command or description,
        },
        "cwd": cwd,
        "reason": description,
        "os_type": "",  # 自动检测
    }

    # 调用 AgentMoss
    from ..core import analyze_command
    result = analyze_command(request)

    # 返回 Claude Code hook 决策格式
    if result["decision"] == "Deny":
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": result["reason"],
            }
        }
    else:
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
            }
        }

    print(json.dumps(output))
```

### 5.2 OpenCode 接入

**方案**：MCP Server（OpenCode 原生支持 MCP 协议）

**MCP Server 配置**（`~/.config/opencode/mcp.json`）：

```json
{
  "mcpServers": {
    "agent-moss-collector": {
      "command": "python3",
      "args": ["-m", "agent_moss_collector.mcp_server"],
      "env": {
        "AGENT_MOSS_SOCKET": "/var/run/agent_moss/agent_moss.sock"
      }
    }
  }
}
```

**MCP Tool 定义**：

```python
# mcp_server.py
# 注册为 MCP Server，暴露 analyze_command 工具

@server.tool()
async def analyze_command(
    command: str,
    tool_name: str = "bash",
    cwd: str = "",
    session_id: str = "",
    description: str = "",
    os_type: str = "",
) -> dict:
    """在执行 shell 命令前进行安全分析"""
    request = {
        "session_id": session_id,
        "a_next": {
            "action_type": tool_name,
            "action_detail": command,
        },
        "cwd": cwd,
        "reason": description,
        "os_type": os_type,
    }
    return analyze_command(request)
```

### 5.3 OpenClaw 接入

**方案**：Gateway 中间件

在 OpenClaw Gateway 的 exec 工具执行链路中注入安全检查：

```yaml
# openclaw.yaml
tools:
  exec:
    security: allowlist
    pre_exec_hook: "/usr/local/bin/agent-moss-wrap"
    pre_exec_hook_timeout: 30000
```

### 5.4 通用方案：Shell 包装器

对于无法通过 Hook 或插件接入的 Agent，设置其默认 shell 为包装器：

```bash
# 方式1：设置 Agent 的 SHELL 环境变量
export SHELL=/usr/local/bin/agent-moss-wrap

# 方式2：替换 Agent 配置中的 shell 路径
# 将 /bin/bash 替换为 /usr/local/bin/agent-moss-wrap
```

---

## 6. 数据标准化与转换

### 6.1 FormatNormalizer 设计

每种 Agent 的原始数据格式不同，但最终都需要转换为统一的 `AnalyzeRequest`：

```python
# normalizer.py

class FormatNormalizer:
    """将各 Agent 的原始数据转换为标准 AnalyzeRequest"""

    @staticmethod
    def from_claude_code(data: dict) -> dict:
        return {
            "session_id": data.get("session_id", ""),
            "a_next": {
                "action_type": data.get("tool_name", "bash").lower(),
                "action_detail": data.get("tool_input", {}).get("command", ""),
            },
            "cwd": data.get("cwd", ""),
            "reason": data.get("tool_input", {}).get("description", ""),
        }

    @staticmethod
    def from_opencode(data: dict) -> dict:
        return {
            "session_id": data.get("SessionID", ""),
            "a_next": {
                "action_type": data.get("ToolName", "bash").lower(),
                "action_detail": data.get("Params", data.get("Description", "")),
            },
            "cwd": data.get("Path", ""),
            "reason": data.get("Description", ""),
        }

    @staticmethod
    def from_openclaw(data: dict) -> dict:
        return {
            "session_id": data.get("agent_id", ""),
            "a_next": {
                "action_type": "bash",
                "action_detail": data.get("command", ""),
            },
            "cwd": data.get("workdir", ""),
            "reason": "",
        }

    @staticmethod
    def from_generic(command: str, cwd: str = "", session_id: str = "") -> dict:
        return {
            "session_id": session_id,
            "a_next": {
                "action_type": "bash",
                "action_detail": command,
            },
            "cwd": cwd,
            "reason": "",
        }
```

### 6.2 字段映射矩阵

| AnalyzeRequest 字段 | Claude Code | OpenCode | OpenClaw | Generic |
|--------------------|-------------|----------|----------|---------|
| `session_id` | `session_id` | `SessionID` | `agent_id` | 环境变量/参数 |
| `a_next.action_type` | `tool_name` | `ToolName` | 固定 `bash` | 固定 `bash` |
| `a_next.action_detail` | `tool_input.command` | `Params` 或 `Description` | `command` | `command` |
| `cwd` | `cwd` | `Path` | `workdir` | `os.getcwd()` |
| `reason` | `tool_input.description` | `Description` | 空 | 空 |
| `os_type` | 自动检测 | 自动检测 | 自动检测 | 自动检测 |

---

## 7. 安全决策执行机制

### 7.1 决策流程

```
AgentMoss 返回结果
       │
       ├── decision == "Allow" → 放行执行
       │
       ├── decision == "Deny"  → 阻断 + 返回原因
       │
       └── AgentMoss 不可用    → fail-closed: 默认拒绝
```

### 7.2 本地决策缓存

为避免对相同命令重复调用 AgentMoss，采集服务维护本地 LRU 缓存：

```python
# cache.py

from functools import lru_cache

class DecisionCache:
    """本地决策缓存（进程生命周期内有效）"""

    def __init__(self, max_size: int = 500):
        self._cache: dict[str, dict] = {}
        self._max_size = max_size

    def _key(self, command: str, cwd: str, session_id: str) -> str:
        # 使用命令 + 工作目录作为缓存键
        return f"{session_id}:{cwd}:{command}"

    def get(self, command: str, cwd: str, session_id: str) -> dict | None:
        key = self._key(command, cwd, session_id)
        return self._cache.get(key)

    def set(self, command: str, cwd: str, session_id: str, result: dict):
        key = self._key(command, cwd, session_id)
        if len(self._cache) >= self._max_size:
            # 简单 FIFO 淘汰
            self._cache.pop(next(iter(self._cache)))
        self._cache[key] = result
```

**缓存策略**：
- 缓存键：`session_id + cwd + command`
- 只缓存 `Allow` 决策（`Deny` 决策不缓存，确保安全）
- 进程生命周期内有效（Hook 脚本每次调用都是新进程，缓存仅在单次会话内有效）

### 7.3 AgentMoss 不可用处理（Fail-Closed）

```python
# client.py

def analyze_command(request: dict, timeout: float = 30.0) -> dict:
    """调用 AgentMoss 进行分析，失败时返回默认 Deny"""
    try:
        response = _call_agent_moss(request, timeout=timeout)
        return response
    except (ConnectionError, TimeoutError, OSError) as e:
        # Fail-Closed：AgentMoss 不可用时默认拒绝
        return {
            "decision": "Deny",
            "reason": f"AgentMoss 安全服务不可用，默认拒绝执行: {e}",
            "risk_level": "high",
            "risk_type": "service_unavailable",
            "violated_layers": [],
            "policy": "",
            "violated_policy": "",
            "confidence": 100,
            "analysis_duration_ms": 0,
        }
```

### 7.4 决策超时处理

若 AgentMoss 响应超时（例如 LLM 分析未在规定时间内返回），采集服务使用 AgentMoss 返回的超时默认决策（目前为 Deny）。

---

## 8. 跨操作系统支持

### 8.1 输入数据中的 OS 标识

数据采集服务在构造 `AnalyzeRequest` 时自动填充 `os_type` 字段：

```python
import platform

def _detect_os() -> str:
    system = platform.system().lower()
    if system == "linux":
        # 进一步区分发行版
        try:
            with open("/etc/os-release") as f:
                content = f.read()
            if "openEuler" in content:
                return "linux"  # openEuler 使用 Linux Profile
        except OSError:
            pass
        return "linux"
    elif system == "windows":
        return "windows"
    return system
```

### 8.2 Linux 环境

| 组件 | 方案 |
|------|------|
| AgentMoss 通信 | Unix Domain Socket（推荐）或 HTTP localhost |
| 采集方式 | Claude Code Hook / OpenCode MCP / Shell Wrapper |
| 敏感路径检测 | LinuxProfile（`/etc/shadow`, `/proc/sys/`, `.ssh/id_rsa` 等） |
| 危险命令检测 | `rm -rf /`, `chmod 777`, `curl\|bash`, `sudo`, `mkfs` 等 |

### 8.3 Windows 环境

| 组件 | 方案 |
|------|------|
| AgentMoss 通信 | HTTP localhost（Windows 无原生 Unix Socket） |
| 采集方式 | Shell Wrapper（PowerShell 包装脚本）或 Agent 特定 Hook |
| 敏感路径检测 | WindowsProfile（`C:\Windows\System32\config\SAM`, 注册表项 等） |
| 危险命令检测 | `del /f /s C:\`, `format C:`, `icacls * /grant Everyone:F`, `reg delete HKLM` 等 |

### 8.4 Windows Shell 包装器示例

```powershell
# agent-moss-wrap.ps1

$command = $args -join ' '
$cwd = Get-Location
$sessionId = $env:AGENT_SESSION_ID

$body = @{
    session_id = $sessionId
    a_next = @{
        action_type = "powershell"
        action_detail = $command
    }
    cwd = $cwd
    os_type = "windows"
} | ConvertTo-Json

$result = Invoke-RestMethod -Uri "http://localhost:9090/api/v1/analyze" `
    -Method Post -Body $body -ContentType "application/json"

if ($result.decision -eq "Deny") {
    Write-Error "[AgentMoss] 操作已被安全策略阻止: $($result.reason)"
    exit 126
}

Invoke-Expression $command
```

---

## 9. 部署架构

### 9.1 部署模式

```
模式 A: Hook 脚本模式（轻量，推荐用于 Claude Code）
┌──────────────────────┐
│  Agent 进程          │
│  ├── Hook 触发       │
│  └── 执行            │
└──────┬───────────────┘
       │ stdin JSON
       ▼
┌──────────────────────┐      Unix Socket
│  agent_moss_collector │ ─────────────────▶ AgentMoss
│  (一次性 Python 脚本) │
└──────────────────────┘

模式 B: MCP Server 模式（推荐用于 OpenCode）
┌──────────────────────┐
│  OpenCode 进程       │
│  ├── MCP Client      │
│  └── 执行            │
└──────┬───────────────┘
       │ JSON-RPC
       ▼
┌──────────────────────┐      Unix Socket
│  agent_moss_collector │ ─────────────────▶ AgentMoss
│  (常驻 MCP Server)   │
└──────────────────────┘

模式 C: Shell 包装器模式（通用）
┌──────────────────────┐
│  Agent 进程          │
│  └── exec /bin/sh    │──▶ /usr/local/bin/agent-moss-wrap
└──────────────────────┘              │
                                      │ Unix Socket
                                      ▼
                                  AgentMoss
                                      │
                              Allow → exec /bin/bash -c "$CMD"
                              Deny  → exit 126
```

### 9.2 安装方式

```bash
# 安装 AgentMoss（主服务）
sudo ./scripts/install.sh

# 安装 Agent 数据采集服务
pip install agent-moss-collector

# 配置各 Agent
agent-moss-collector setup --agent claude-code    # 写入 .claude/settings.json
agent-moss-collector setup --agent opencode       # 写入 MCP 配置
agent-moss-collector setup --agent generic        # 安装 /usr/local/bin/agent-moss-wrap
```

### 9.3 目录结构

```
agent_moss_collector/               # 独立 Python 包
├── __init__.py
├── __main__.py                     # python -m agent_moss_collector
├── handle.py                       # CLI 入口（Hook 调用）
├── core.py                         # 核心逻辑（格式转换 + AgentMoss 调用）
├── client.py                       # AgentMoss HTTP/Socket 客户端
├── cache.py                        # 本地决策缓存
├── normalizer.py                   # 格式标准化
├── handlers/                       # 各 Agent Hook 处理器
│   ├── __init__.py
│   ├── claude_code.py              # Claude Code PreToolUse handler
│   ├── opencode.py                 # OpenCode permission handler
│   ├── openclaw.py                 # OpenClaw exec handler
│   └── generic.py                  # 通用 Shell 包装器 handler
├── mcp_server.py                   # MCP Server 实现（OpenCode 接入）
├── cli.py                          # setup / test 命令
└── scripts/
    ├── agent-moss-wrap.sh          # Linux Shell 包装器
    └── agent-moss-wrap.ps1         # Windows PowerShell 包装器
```

---

## 10. 实施路线

### 10.1 Phase 1：核心框架 + Claude Code 支持（P0）

| # | 任务 | 产出 |
|---|------|------|
| 1 | 创建 `agent_moss_collector` 包骨架 | 目录结构 + `pyproject.toml` |
| 2 | 实现 `core.py`（格式转换 + AgentMoss 调用 + 缓存） | 核心逻辑 |
| 3 | 实现 `claude_code.py` handler | Claude Code PreToolUse 接入 |
| 4 | 编写端到端测试（模拟 Claude Code Hook JSON → 调用 AgentMoss → 验证决策） | 测试用例 |
| 5 | 编写 Claude Code 集成文档 | 用户指南 |

### 10.2 Phase 2：OpenCode + OpenClaw + 通用方案（P1）

| # | 任务 | 产出 |
|---|------|------|
| 6 | 实现 `mcp_server.py`（MCP Server for OpenCode） | OpenCode MCP 接入 |
| 7 | 实现 `opencode.py` handler | OpenCode 接入 |
| 8 | 实现 `openclaw.py` handler | OpenClaw 接入 |
| 9 | 实现 `generic.py` handler + Shell 包装器脚本 | 通用接入方案 |
| 10 | 跨 Agent 集成测试 | 多 Agent 场景验证 |

### 10.3 Phase 3：跨 OS + 审计 + 优化（P2）

| # | 任务 | 产出 |
|---|------|------|
| 11 | 实现 Windows PowerShell 包装器 | Windows 支持 |
| 12 | 实现审计日志功能 | 全量记录 |
| 13 | 性能优化（连接池、缓存预热） | 延迟 < 3ms |
| 14 | 发布为 PyPI 包 | `pip install agent-moss-collector` |

---

## 附录 A：与 AgentMoss 的调用时序

```
时间轴 →

Agent 进程          Collector          AgentMoss
    │                   │                   │
    │  决定执行命令      │                   │
    │───Hook触发────────▶│                   │
    │                   │  格式转换          │
    │                   │  缓存查询          │
    │                   │───POST /analyze───▶│
    │                   │                   │ 层1: 特征匹配
    │                   │                   │ 层2: 逻辑规则
    │                   │                   │ 层3: LLM 分析
    │                   │◀──{decision}──────│
    │                   │                   │
    │◀──permission──────│                   │
    │    Decision       │                   │
    │                   │                   │
    │  Allow: 继续执行   │                   │
    │  Deny:  拒绝+原因  │                   │
```

## 附录 B：AgentMoss 不可用时的降级策略

| 场景 | 策略 | 说明 |
|------|------|------|
| AgentMoss 进程未启动 | **Deny** | 安全优先，没有安全分析 = 不信任 |
| AgentMoss 响应超时 (>30s) | **Deny** | LLM 分析可能正在执行但超时，保守处理 |
| AgentMoss Socket 权限错误 | **Deny** + 日志告警 | 配置问题，阻断执行并通知运维 |
| 网络不可达（HTTP 模式） | **Deny** | AgentMoss 可能在其他主机，网络故障默认拒绝 |

> 注意：Collector 本身不做安全判断。所有 Allow/Deny 决策 100% 来自 AgentMoss。
