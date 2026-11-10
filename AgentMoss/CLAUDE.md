# AgentMoss 项目指南（Claude Code 自动加载）

> 本文件每次会话自动载入。**任何优化/修复/规则改动之前，先读 `docs/MAINTENANCE_WORKFLOW.md`**（操作手册，固化双端同步/测试归一/文档更新/提交规范）。

## 前置必读

- **`docs/MAINTENANCE_WORKFLOW.md`** — 新会话做优化任务前必读。涵盖：双端同步、测试归一、文档更新、提交规范。
- **`tests/cases/README.md`** — 用例字段权威说明 + 计数口径（含 Python/TS passed 数差异原因）。加用例前读。
- 关键规则摘要（详见手册）：

1. **双端同步（铁律）**：任何规则/逻辑/功能修改必须 **Python + TS 同时改**（`agent_moss/engine/*.py` ↔ `ts/src/engine/*.ts`、`agent_moss/profiles/*.py` ↔ `ts/src/engine/heuristic.ts` 等），单端修复 = 没修。**强调：规则、功能、测试、文档四者必须一起同步**，不只是代码。改完必须验证双端行为一致（同一命令两端判定相同）。
2. **测试归一 + 覆盖要求**：双端共用 `tests/cases/*.json` 单一事实源。**每条规则改动必须补"一拦一放"两个用例**（命中 Deny + 类但不命中 Allow，防规则过宽/过窄）。新 case 只改 JSON，TS 自动加载，**但 Python 的 `test_all_cases.py` 是硬编码 parametrize 列表，必须手动把新 case 加进去**，否则 Python 跑不到（双端覆盖不一致）。两端各自另有手写单测（不读 JSON）。**agent 专属规则用例放 `tests/cases/agent/`**（`input.agent_id` 指定 xiaoo/opendesk），双端自动扫该目录，无需手动加 parametrize。
3. **敏感路径尤其要双端同步**：改 `sensitive_paths` 时两端都要加，且要补 JSON 用例。曾发生过 `.aws/credentials` TS 有、Python 无导致 TS 拦/Python 放的单向漂移。
4. **同步校验测试（防漂移兜底）**：改规则必须连带更新双端同步断言，否则漂移会漏网：
   - Python `test_all_cases.py::TestOSProfile::test_linux_profile_rule_sync_with_ts`（L1 危险命令）
   - Python `test_all_cases.py::TestOSProfile::test_linux_profile_sensitive_paths_sync_with_ts`（敏感路径 + 凭据 deny_both）
   - TS `ts/src/__tests__/dual-parity.test.ts`（isWriteOperation / DANGEROUS_PATTERNS / 敏感路径三段）
5. **runtime config 会覆盖源码**：敏感路径等规则运行时优先读 `~/.config/agentmoss/agent_moss_runtime.json`（不在 git，用户本地持久化，优先于 profile 默认值）。**改源码规则后，若该环境 runtime config 里对应项 `enabled:false` 或缺失，真实运行时不生效**——需在 runtime config 启用或重新生成。测试环境由 `conftest.py` 隔离 runtime（`has_runtime_config` 恒 False），不受影响。
6. **LLM/L3 判定**：L3 是否真跑由统一判定源（env + `~/.config/agentmoss/config.json`）+ 连通性探测决定（Python `conftest.py` `llm_probe_available` / TS `probeLLMConnection`）。缺 key 或 key 不通则 skip，不假通过。
7. **提交规范**：`git add` 只加本地修改涉及的文件，不用 `git add -A`；优化/修复过程中的临时文件要清理后再一并提交。提交信息**不加 `Co-Authored-By` 行**。
8. **验证**：改动后跑双端回归（Python `pytest` + TS `vitest`，见手册"验证双端一致的命令"）。passed 数差异不代表规则不一致（见 tests/cases/README.md 计数口径）。

## 常用命令

```bash
# Python 全量（禁 LLM，CI 友好）
AGENT_MOSS_DISABLE_LLM=1 python3 -m pytest tests/test_all_cases.py -q

# TS 全量（禁 LLM）
cd ts && AGENT_MOSS_DISABLE_LLM=1 npx vitest run
```

## 技术栈

- 三层防御：L1 特征匹配 / L2 逻辑规则 / L3 LLM 语义分析（fail-open）
- Python 双端实现：`agent_moss/`（Python）、`ts/`（TypeScript）