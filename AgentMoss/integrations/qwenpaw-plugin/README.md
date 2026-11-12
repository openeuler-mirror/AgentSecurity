# AgentMoss Security Gate 插件（零侵入方案原型）

让 QwenPaw 的每一次工具调用，都先经过 AgentMoss（经 AgentGate）安全分析，再决定是否真的执行。

## 零侵入说明

- 不修改 QwenPaw 任何源码
- 不修改 AgentGate / AgentMoss 任何源码（只调用其已有的 `/api/v1/analyze` 接口）
- 安装 = 把这个插件目录放进 QwenPaw 的插件目录（`~/.qwenpaw/plugins/agentmoss-gate/`），启用插件即可

## 工作原理

插件挂载在 QwenPaw 的**权限检查**环节（`on_check_permission`），在工具真正执行**之前**：

1. 拿到本次工具调用（工具名 + 参数）
2. 拿到本轮提示词（user prompt）与完整会话历史（`agent.state.context`，按「提示词 → 它触发的动作」分组）
3. 打包上报 AgentGate `/api/v1/analyze`
4. AgentMoss 判决 `Deny` → 直接阻止工具执行（工具不会真的跑）
5. AgentMoss 判决 `Allow` → 放行，行为与不开插件完全一致

与 QwenPaw 自带治理的关系：**双重把关**。QwenPaw 自己拦的，插件不会放行；QwenPaw 没拦的，AgentMoss 还能再拦一道。

## 安装

```bash
# 1. 把插件目录放到 QwenPaw 插件目录
mkdir -p ~/.qwenpaw/plugins
cp -r agentmoss-gate ~/.qwenpaw/plugins/

# 2. （可选）创建配置文件
cp agentmoss-gate/config.example.json agentmoss-gate/config.json
#    编辑 config.json 填 AgentGate 地址
```

启用插件后在 QwenPaw 界面里开启「AgentMoss Security Gate」。

## 配置（config.json）

| 字段 | 默认 | 说明 |
|---|---|---|
| `gate_url` | `http://127.0.0.1:9100` | AgentGate 服务地址（与其默认端口一致） |
| `timeout` | `5.0` | 上报超时（秒）。超时按"网关不可用"处理 |
| `fail_closed` | `false` | `false`=网关挂了放行（fail-open，agent 不中断）；`true`=网关挂了全拦（fail-closed，更安全但一断全断） |
| `api_token` | `""` | 网关鉴权 token（AgentGate 若开启了鉴权） |
| `agent_type` | `"qwenpaw"` | 上报的 agent 类型标识 |

环境变量可覆盖：`AGENTMOSS_GATE_URL` / `AGENTMOSS_GATE_TIMEOUT` / `AGENTMOSS_FAIL_CLOSED` / `AGENTMOSS_DISABLE`。

## 已知边界（务必给客户讲清楚）

1. **"一次做一串动作"（批量工具）的内层动作看不到**——唯一真盲区。该功能的内层
   动作绕过了整条权限检查链路（QwenPaw 自身的治理漏洞，已提交上游 PR）。若客户
   明确不用该功能，本插件覆盖主路径 100%。
2. **工具不存在 / 参数解析失败**的调用看不到（未进入权限检查环节）。非安全场景：
   这类调用本来就不会执行。

> **被 QwenPaw 治理层拒绝的动作，本插件看得到**（含拒绝原因）。插件挂在"权限检查"
> 的**外层**，QwenPaw 自己的判定发生在插件内部，因此放行/拒绝/待确认三种结果插件
> 都能拿到并上报——早期文档说"看不到"是错的，已实测修正。

## 测试

```bash
# 依赖 AgentScope（由 QwenPaw 提供），用 QwenPaw 的 venv 跑
/home/hkl/github/QwenPaw/venv/bin/python test_agentmoss_gate_plugin.py
```

20 个用例：Deny 阻断 / Allow 放行 / fail-open / fail-closed / 上下文提取
（纯文本、真实工具调用、cwd、reason）/ 工具输入不被 JSON 转义 / os_type 与
hostname 上报（hostname 供 AgentGate 区分同类型 agent）。
