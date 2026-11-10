# AgentMoss 服务适配设计文档 v2.0

> 版本：v2.0  
> 日期：2026-05-19  
> 状态：待确认  
> 前置文档：[design.md](./design.md)（v1.0，2026-05-18，基础架构设计）

---

## 目录

1. [设计背景与目标](#1-设计背景与目标)
2. [核心设计原则](#2-核心设计原则)
3. [标准化 API 契约](#3-标准化-api-契约)
4. [OS Profile 系统](#4-os-profile-系统)
5. [适配器层设计](#5-适配器层设计)
6. [服务调用模式](#6-服务调用模式)
7. [配置文件变更](#7-配置文件变更)
8. [实施计划](#8-实施计划)
9. [附录：主流 Agent 数据可用性调研](#9-附录主流-agent-数据可用性调研)

---

## 1. 设计背景与目标

### 1.1 背景

AgentMoss v1.0 已实现了三层安全分析引擎（特征匹配 → 逻辑规则 → LLM 语义分析）和 HTTP API 服务层。当前存在以下待改进点：

1. **检测规则硬编码为 Linux-only**：`heuristic.py` 和 `logic_rules.py` 中的危险命令模式、敏感路径、安全白名单全部针对 Linux，无法支持 Windows 等操作系统
2. **适配器层未激活**：`config/agent_moss.yaml` 中预留了 `adapter.type: "observable"`，但服务层未实际使用适配器
3. **调用方式单一**：仅支持 HTTP TCP，同机部署场景下存在网络协议栈开销
4. **未定义标准化的 Agent 接入规范**：缺少面向第三方 Agent 的集成指南

### 1.2 核心目标

将 AgentMoss 重构为**可被任意 AI Agent 调用的独立通用安全分析服务**（类似 npm 包的即装即用体验），聚焦三个核心能力：

| 目标 | 说明 |
|------|------|
| **标准化 I/O 契约** | 定义通用 syscall 描述格式，任何 Agent 遵循即可调用 |
| **OS 级自适应检测** | 自动识别 Linux/Windows，使用对应 OS Profile 的检测模式 |
| **灵活的服务接入** | HTTP REST + Unix Domain Socket 两种调用模式 |

### 1.3 设计驱动因素

通过调研主流 AI Coding Agent（Claude Code、OpenCode、OpenClaw、Cursor、AgentSight/Syscon）的数据捕获能力，得出以下关键结论：

> **工具调用层数据（命令字符串 + 描述 + session_id + cwd）完全足以支撑 AgentMoss 的三层安全分析。**  
> 所有主流 Agent 在工具执行前都能提供命令字符串、操作类型、会话标识和工作目录。不需要关心 Agent 内部实现，只需要关心它最终要执行的操作系统命令。

详见 [附录：主流 Agent 数据可用性调研](#9-附录主流-agent-数据可用性调研)。

---

## 2. 核心设计原则

### 2.1 "适配在 OS 层，不在 Agent 层"

```
错误思路：为 Claude Code 写适配器、为 OpenCode 写适配器、为 OpenClaw 写适配器...
正确思路：Linux syscall 模式 → LinuxProfile，Windows syscall 模式 → WindowsProfile
```

**理由**：不同 Agent 内部实现各异，但它们最终都会调用操作系统的 syscall。对于同一个操作系统，syscall 是确定性的——文件读取在 Linux 永远是 `open/read`，在 Windows 永远是 `CreateFile/ReadFile`。AgentMoss 不需要关心 Agent 如何组织代码，只需要识别对应的操作系统模式。

### 2.2 "标准化就是最大的灵活性"

AgentMoss 定义一套通用输入输出格式，任何 Agent 通过其 Hook/权限系统将工具调用数据转换为该格式即可接入。类似 REST API 的"契约优先"设计。

### 2.3 "够用就好，不过度设计"

| 保留 | 移除（及其原因） |
|------|-----------------|
| HTTP REST API | gRPC — 当前规模不需要 Protobuf 编译链 |
| Unix Domain Socket | MCP Server — 后续按需添加 |
| 单例 OS Profile | WebSocket 推送 — 同步分析不需要异步通道 |
| ObservableAdapter（唯一适配器） | 适配器注册表 — 只有一种数据源 |

---

## 3. 标准化 API 契约

### 3.1 输入格式：AnalyzeRequest（v2 更新）

```json
{
    "session_id": "agent-sandbox-001",
    "prompt_session": "分析 /var/log/syslog 中的异常",
    "action_history": [
        {
            "action_type": "bash",
            "action_detail": "cat /var/log/syslog"
        }
    ],
    "a_next": {
        "action_type": "bash",
        "action_detail": "rm -rf /var/log/*"
    },
    "reason": "清理旧日志文件",
    "os_type": "",
    "cwd": "/home/user/project",
    "metadata": {
        "agent_id": "agent-001",
        "sandbox_id": "sb-001",
        "trace_id": "trace-abc123"
    }
}
```

| 字段 | 类型 | 必填 | v1→v2 变更 | 说明 |
|------|------|------|------------|------|
| `session_id` | string | 是 | 不变 | Agent 会话唯一标识 |
| `prompt_session` | string | 否 | 不变 | 用户原始任务描述 |
| `action_history` | array | 否 | 不变 | 历史动作序列 |
| `a_next.action_type` | string | 是 | 不变 | 动作类型（bash/file_read/file_write 等） |
| `a_next.action_detail` | string | 是 | 不变 | 命令/动作详情 |
| `reason` | string | 否 | 不变 | 执行理由 |
| `os_type` | string | 否 | **新增** | 操作系统类型（`"linux"`, `"windows"`），为空时自动检测 |
| `cwd` | string | 否 | **新增** | 当前工作目录，用于敏感路径上下文判断 |
| `metadata` | object | 否 | 不变 | 扩展元数据 |

### 3.2 输出格式：AnalyzeResponse（不变）

```json
{
    "decision": "Deny",
    "reason": "检测到递归强制删除命令，风险等级: critical",
    "risk_level": "critical",
    "risk_type": "script_execution",
    "violated_layers": ["L1.1"],
    "policy": "",
    "violated_policy": "[script_execution] 检测到递归强制删除关键路径 (rm -rf /...)",
    "confidence": 95,
    "analysis_duration_ms": 1.2
}
```

### 3.3 向后兼容性

- `os_type` 和 `cwd` 均为可选字段，默认行为不变
- 现有调用方无需修改任何代码
- v1 格式的 JSON 输入完全可被 v2 接受

---

## 4. OS Profile 系统

### 4.1 设计动机

将当前硬编码在 `heuristic.py` 和 `logic_rules.py` 中的 Linux 特定模式抽取为 OS Profile 类，支持运行时切换。

### 4.2 目录结构

```
agent_moss/
└── profiles/                    # [NEW] OS Profile 系统
    ├── __init__.py              # get_profile(os_type) 工厂函数
    ├── base.py                  # OSProfile 抽象基类
    ├── linux.py                 # LinuxProfile — 从现有代码迁移
    └── windows.py               # WindowsProfile — Windows syscall 模式
```

### 4.3 OSProfile 抽象基类接口

```python
# profiles/base.py

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

@dataclass
class CommandPattern:
    """危险命令检测模式"""
    pattern: str          # 正则表达式
    risk_level: str       # low / medium / high / critical
    risk_type: str        # file_access / script_execution / data_exfiltration / ...
    reason: str           # 命中时的描述

class OSProfile(ABC):
    """操作系统安全检测 Profile 抽象基类"""

    @property
    @abstractmethod
    def os_type(self) -> str:
        """返回 'linux' 或 'windows'"""
        ...

    # ─── 层1：特征匹配检测 ───

    @property
    @abstractmethod
    def dangerous_commands(self) -> list[CommandPattern]:
        """危险命令正则模式列表（CRITICAL + EXTRA）"""
        ...

    @property
    @abstractmethod
    def safe_commands(self) -> list[str]:
        """安全白名单命令正则列表（只读、低风险）"""
        ...

    @property
    @abstractmethod
    def safe_action_types(self) -> frozenset[str]:
        """安全操作类型白名单（如 glob, grep, list_dir）"""
        ...

    # ─── 层2：逻辑规则检测 ───

    @property
    @abstractmethod
    def sensitive_paths(self) -> list[dict]:
        """敏感路径列表，每项含 path / risk_level / desc"""
        ...

    @property
    @abstractmethod
    def write_keywords(self) -> list[str]:
        """写入操作关键词"""
        ...

    @property
    @abstractmethod
    def read_keywords(self) -> list[str]:
        """读取操作关键词"""
        ...

    @property
    @abstractmethod
    def intent_deviation_patterns(self) -> list[dict]:
        """意图偏离关键词对"""
        ...

    @abstractmethod
    def extract_file_paths(self, text: str) -> list[str]:
        """从文本中提取文件路径（OS 特定实现）"""
        ...
```

### 4.4 LinuxProfile 内容来源

直接从现有代码迁移，不做逻辑变更：

| Profile 属性 | 现有代码来源 |
|-------------|-------------|
| `dangerous_commands` | `heuristic.py` → `CRITICAL_COMMAND_PATTERNS` + `EXTRA_DANGEROUS_PATTERNS` |
| `safe_commands` | `heuristic.py` → `SAFE_BASH_PATTERNS` |
| `safe_action_types` | `heuristic.py` → `SAFE_ACTION_TYPES` |
| `sensitive_paths` | `logic_rules.py` → `SENSITIVE_PATHS` |
| `write_keywords` | `logic_rules.py` → `WRITE_KEYWORDS` |
| `read_keywords` | `logic_rules.py` → `READ_KEYWORDS` |
| `intent_deviation_patterns` | `logic_rules.py` → `INTENT_DEVIATION_PATTERNS` |
| `extract_file_paths()` | `logic_rules.py` → `_extract_file_paths()` |

### 4.5 WindowsProfile 内容设计（首批规则）

| Profile 属性 | Windows 特定内容 |
|-------------|-----------------|
| `dangerous_commands` | `del /f /s C:\`, `rmdir /s /q C:\`, `format C:`, `icacls * /grant Everyone:F`, `net user`, `reg delete HKLM`, `wmic process call create`, `powershell -EncodedCommand`, `C:\Windows\System32\config\SAM` |
| `safe_commands` | `dir`, `type`, `findstr`, `where`, `echo`, `cd`, `tree` |
| `sensitive_paths` | `C:\Windows\System32\config\SAM`, `C:\Windows\System32\config\SECURITY`, `C:\Users\*\AppData\Roaming\`, `C:\ProgramData\`, `%USERPROFILE%\.ssh\`, `HKLM\SOFTWARE\`, `HKLM\SYSTEM\` |
| `extract_file_paths()` | 识别 `C:\`、`\\server\share` 等 Windows 路径格式 |

> **注意**：WindowsProfile 首批仅覆盖基础规则集，后续根据实际攻击案例持续扩展。

### 4.6 工厂函数与自动检测

```python
# profiles/__init__.py

import platform
from .base import OSProfile

_profile_cache: dict[str, OSProfile] = {}

def get_profile(os_type: str = "") -> OSProfile:
    """获取 OS Profile 实例（带缓存）"""
    if not os_type:
        os_type = platform.system().lower()

    if os_type not in _profile_cache:
        if os_type == "windows":
            from .windows import WindowsProfile
            _profile_cache[os_type] = WindowsProfile()
        else:
            from .linux import LinuxProfile
            _profile_cache[os_type] = LinuxProfile()

    return _profile_cache[os_type]
```

### 4.7 引擎层集成

重构 `heuristic.py` 和 `logic_rules.py`，将硬编码常量改为从 Profile 实例获取：

```python
# heuristic.py（改造后）
class CommandPatternScanner:
    def __init__(self, profile: OSProfile):
        self._compiled = [
            {**p, "regex": re.compile(p.pattern, re.IGNORECASE)}
            for p in profile.dangerous_commands
        ]

# logic_rules.py（改造后）
class LogicRulesChecker:
    def __init__(self, profile: OSProfile):
        self._profile = profile

    def _check_sensitive_path_access(self, a_next: dict) -> LogicRuleResult:
        for sp in self._profile.sensitive_paths:
            ...
```

---

## 5. 适配器层设计

### 5.1 简化策略

v1 设计了多适配器模式（base + registry + RawAdapter + ObservableAdapter）。v2 简化为单适配器：

- **删除** `adapters/base.py`（抽象基类，不再需要）
- **删除** `adapters/registry.py`（注册表，只有一个适配器不需要）
- **重写** `adapters/observable.py` 为 AgentOS 可观测服务 syscall 数据的转换器
- **更新** `adapters/__init__.py` 导出唯一适配器

### 5.2 ObservableAdapter

```python
# adapters/observable.py

class ObservableAdapter:
    """将 AgentOS 可观测服务 syscall 数据转换为标准 AnalyzeRequest

    输入格式（来自可观测服务）：
    {
        "agent_id": "agent-001",
        "session_id": "session-abc",
        "sandbox_id": "sb-001",
        "os_type": "linux",
        "cwd": "/home/user/project",
        "prompt": "分析日志文件",
        "current_action": {
            "tool": "bash",
            "command": "cat /var/log/app.log",
            "description": "读取应用日志"
        },
        "action_history": [...],
        "trace_id": "trace-xyz"
    }

    输出格式：标准 AnalyzeRequest dict
    """
    ...
```

### 5.3 服务层集成

修改 `server/routes.py`，在分析前自动调用适配器转换：

```python
# routes.py（改造后）
from ..adapters import ObservableAdapter

adapter = ObservableAdapter()

@router.post("/api/v1/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest):
    # 1. 适配器转换（如果传入的是原始 syscall 格式）
    internal_req = adapter.adapt(req.model_dump()) if _is_raw_format(req) else req

    # 2. OS 自动检测（如果未指定 os_type）
    os_type = internal_req.os_type or platform.system().lower()

    # 3. 调用分析引擎
    result = run_analysis(session_id=internal_req.session_id, ..., os_type=os_type)

    # 4. 返回结果
    return AnalyzeResponse(**result)
```

---

## 6. 服务调用模式

### 6.1 HTTP REST（已有，保留）

```bash
# 启动
agent-moss server --port 9090

# 调用
curl -X POST http://localhost:9090/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d @input.json
```

### 6.2 Unix Domain Socket（新增）

```bash
# 启动
agent-moss server --mode socket --socket /var/run/agent_moss/agent_moss.sock

# 调用
curl --unix-socket /var/run/agent_moss/agent_moss.sock \
  -X POST http://localhost/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d @input.json
```

实现方式：复用现有 FastAPI 应用，通过 uvicorn 的 `--uds` 参数启动：

```python
# server/socket_server.py
def run_socket_server(socket_path: str = "/var/run/agent_moss/agent_moss.sock") -> None:
    import uvicorn
    from .app import create_app
    app = create_app()
    uvicorn.run(app, uds=socket_path)
```

Unix Socket 优势：
- 零网络协议栈开销（相比 TCP loopback）
- 文件系统权限控制（`chmod 660` + `chown agent_moss:agent_moss`）
- 同机通信首选方案

### 6.3 调用模式对比

| 模式 | 延迟 | 吞吐 | 安全性 | 适用场景 |
|------|------|------|--------|----------|
| HTTP REST (TCP) | ~0.5ms overhead | 中 | 防火墙可控 | 调试、跨机调用、外部集成 |
| Unix Domain Socket | ~0.1ms overhead | 高 | 文件权限隔离 | 同机生产部署（推荐） |

---

## 7. 配置文件变更

### 7.1 `config/agent_moss.yaml` 新增项

```yaml
# ========== 新增：OS Profile 配置 ==========
os_profile:
  # 操作系统类型：留空自动检测，可手动指定 linux / windows
  type: ""
  # Profile 文件目录
  dir: ""

# ========== server 配置（增强） ==========
server:
  mode: "http"                  # http / socket
  http_host: "127.0.0.1"
  http_port: 9090
  socket_path: "/var/run/agent_moss/agent_moss.sock"  # mode=socket 时使用
  workers: 4

# ========== adapter 配置（简化） ==========
adapter:
  enabled: true                 # 是否启用适配器转换
  type: "observable"            # 固定为 observable
```

### 7.2 `agent_moss/infra/config.py` 新增 dataclass

```python
@dataclass
class OSProfileConfig:
    """OS Profile 配置"""
    type: str = ""       # 留空自动检测
    dir: str = ""        # Profile 文件目录


@dataclass
class ServerConfig:
    """服务配置（增强）"""
    mode: str = "http"           # http / socket
    http_host: str = "127.0.0.1"
    http_port: int = 9090
    socket_path: str = "/var/run/agent_moss/agent_moss.sock"
    workers: int = 4


@dataclass
class Config:
    llm: LLMConfig = ...
    timeout: TimeoutConfig = ...
    cache: CacheConfig = ...
    retry: RetryConfig = ...
    security: SecurityConfig = ...
    os_profile: OSProfileConfig = field(default_factory=OSProfileConfig)  # 新增
    server: ServerConfig = field(default_factory=ServerConfig)              # 新增
    log_level: str = "INFO"
```

---

## 8. 实施计划

### 8.1 任务列表

| # | 任务 | 文件范围 | 依赖 |
|---|------|----------|------|
| 1 | 创建 OS Profile 系统 | `profiles/base.py`, `linux.py`, `windows.py`, `__init__.py` | 无 |
| 2 | 重构 heuristic.py | `engine/heuristic.py` — 从 OSProfile 获取模式 | 1 |
| 3 | 重构 logic_rules.py | `engine/logic_rules.py` — 从 OSProfile 获取路径和关键词 | 1 |
| 4 | 重构 coordinator + analyzer | `engine/coordinator.py`, `engine/analyzer.py` — 传递 profile 参数 | 2, 3 |
| 5 | 简化适配器层 | `adapters/` — 删除 base.py，重写 observable.py | 无 |
| 6 | 更新服务层 | `server/models.py`（+os_type,+cwd），`server/routes.py`（集成适配器） | 5 |
| 7 | Unix Domain Socket | `server/socket_server.py`, `server/app.py` | 6 |
| 8 | 配置 + CLI 更新 | `infra/config.py`, `cli.py`, `config/agent_moss.yaml`, `scripts/agent_moss.service` | 1, 7 |
| 9 | 测试 | OS Profile 测试 + Socket 集成测试 + 回归 35 用例 | 4, 7 |

### 8.2 向后兼容保证

- 所有现有 CLI 命令（`init`, `analyze`, `server`）行为不变
- 现有 35 个 pytest 测试用例全部回归通过
- `AnalyzeRequest` 新增字段均为可选
- Linux 检测规则集零改动（仅从硬编码迁移到 LinuxProfile）

---

## 9. 附录：主流 Agent 数据可用性调研

### 9.1 调研方法

对 Claude Code、OpenCode、OpenClaw、Cursor 四个主流 Agent 的 Hook/权限/拦截机制进行了文档分析和源码阅读，同时调研了 eBPF 方案（AgentSight、Syscon）的内核级数据捕获能力。

### 9.2 各 Agent 工具调用层可获取数据

| Agent | 拦截机制 | 核心字段 |
|-------|----------|----------|
| **Claude Code** | PreToolUse Hook (JSON stdin) | `tool_name`, `tool_input.command`, `tool_input.description`, `cwd`, `session_id`, `permission_mode` |
| **OpenCode** | Permission 系统 (CreatePermissionRequest) | `ToolName`, `Action`, `Description`(命令全文), `Params`(完整命令), `SessionID`, `Path` |
| **OpenClaw** | exec tool + allowlist | `command`, `workdir`, `env`, `elevated`, `background`, `timeout`, `security` 模式 |
| **Cursor** | cursor-hooks (社区，类 Claude Code) | `tool_name`, `tool_input.command`, `cwd` |

### 9.3 内核层可获取数据（eBPF / seccomp）

| 方案 | 技术 | 可捕获 |
|------|------|--------|
| **AgentSight** | eBPF uprobe + tracepoints | fork/clone/execve, open/read/write/close, 解密后的 SSL HTTP 请求/响应 |
| **Syscon** | seccomp-bpf 审计日志 | 进程创建、网络连接（IP/端口）、文件系统操作、凭据读取、反弹 shell 检测 |

### 9.4 工具调用层 vs 内核层对比

| 维度 | 工具调用层 | 内核层 |
|------|----------|--------|
| **本质** | Agent "声称"要做什么 | Agent "实际"做了什么 |
| **时机** | **执行前**（可拦截） | **执行后**（只能审计） |
| **数据内容** | 命令字符串 + 描述 + 上下文 | syscall 号 + 参数 + 返回值 |
| **篡改风险** | Agent 可能伪造描述 | 内核级防篡改 |
| **对安全分析的价值** | **适合实时拦截决策** | 适合事后审计和行为分析 |

### 9.5 结论

> **工具调用层数据完全足以支撑 AgentMoss 的安全分析需求。**  
> 
> - 层1 特征匹配检测：需要命令字符串 → `command` 字段满足
> - 层2 逻辑规则检测：需要命令 + 意图 + 历史 + 工作目录 → `command` + `description` + `action_history` + `cwd` 满足  
> - 层3 LLM 语义分析：需要全部上下文 → 以上所有字段满足
>
> **不需要内核级数据**，因为 AgentMoss 做的是预执行安全判断，不是事后审计。
> 
> 各 Agent 的数据形态本质一致（都是命令字符串），差异仅在于 Hook 机制的接入方式——这属于 Agent 数据采集服务的职责范围（见另一份设计文档）。

