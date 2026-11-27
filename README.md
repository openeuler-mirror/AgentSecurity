# AgentSecurity

AgentSecurity 是面向 AI Agent 的开源安全能力集合，提供认知安全、行为安全与数据安全能力，包含安全分析服务、凭据保险箱、工具动态沙箱与安全技能插件四个部分。

## 组件概览

| 组件 | 简介 | 文档 |
| --- | --- | --- |
| **AgentMoss** | 可被任意 AI Agent 调用的独立通用安全分析服务。基于 OS Profile 自动适配 Linux/Windows，提供「特征匹配 → 逻辑规则 → LLM 语义分析」三层防御。 | [![AgentMoss README](https://img.shields.io/badge/README-AgentMoss-2f81f7)](AgentMoss/README.md) |
| **AgentCredVault** | Agent 工具凭据保险箱。Agent 侧只持有 fakecred，由本地可信代理在转发前替换为真实凭据，确保真实凭据不进入 Agent 运行环境。 | [![AgentCredVault README](https://img.shields.io/badge/README-AgentCredVault-2f81f7)](AgentCredVault/README.md) |
| **AgentToolDynSandbox** | 基于 Linux 内核隔离机制（Landlock + seccomp + mount/network namespace）的 Agent 工具动态沙箱，提供细粒度隔离与运行时权限动态放宽。 | [![AgentToolDynSandbox README](https://img.shields.io/badge/README-AgentToolDynSandbox-2f81f7)](AgentToolDynSandbox/README.md) |
| **AgentPlugins** | Agent 安全技能插件集合，内置 agent-guardian、xiaoo-guardian 等安全策略 Skill，可作为 Agent 会话的引导期安全策略。 | — |

## 目录结构

```
AgentSecurity/
├── AgentMoss/              # 通用安全分析服务
├── AgentCredVault/         # Agent 工具凭据保险箱
├── AgentToolDynSandbox/    # Agent 工具动态沙箱
├── AgentPlugins/           # Agent 安全技能插件
└── README.md
```
