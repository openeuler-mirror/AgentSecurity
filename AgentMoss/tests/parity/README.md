# 双端一致性语料

Python 和 TS 是同一套规则的**两份实现**。凡是"两边各写一遍"的逻辑，迟早分叉 ——
2026-09 一周内连分叉四次，而且**每次都是用户追问"再检查一次"才被发现**：

| 分叉 | 症状 |
|---|---|
| 白名单只看首段命令 | `df -h ; shutdown -h now` 整条放行 |
| 危险命令扫描的文本带 `action_type:` 前缀 | 任何 `^` 锚定的规则在 TS 上永不命中 |
| L2 字面量判定条件不一致 | `echo "userdel root"` 一端拦一端放 |
| "按工具名免检"只有 Python 有 | `{"action_type":"glob","action_detail":"rm -rf /"}` 一端放行 |
| Python 把 action_detail 小写后再做脚本分析 | `bash Deploy.sh` 找不到文件 → 脚本内容整层不扫（漏报） |
| 授权判定读的是提问正文而非用户回答 | TS 上「问过任何问题」= 已授权（fail-open） |
| 白名单兜底扫原文、L1 扫剥离后文本 | 同一命令两端 `risk_type` 不同 |

**还有一类语料照不到的洞：两端一致的共同盲区**（都错，所以不会分叉）。
例如 `cat "/etc//shadow"` 曾两端一起放行 —— 默认路径归一化刻意跳过引号内内容。
这类只能靠人工审查 + 把新维度补进生成器逐步收窄。

共同点：**都是"某个判定条件写宽/写窄了一点"**，靠人工想攻击手法想不全，
但穷举生成输入就能照出来。

## 是什么

`corpus.json`：1400+ 条确定性生成的两端共用输入 + **两端一致时的判定**
（`expected` 判定 / `expected_risk_level` / `expected_risk_type`）。

生成维度：

- 13 个命令头 × 5 种连接符（`&&` `;` `|` `&` 换行）× 18 个危险尾巴
- 变体包裹：裸命令 / `--help` / `echo "…"` / `printf '…'` / `grep '…' /var/log/x` / `man`
- 工具名伪装：9 个 action_type × 5 个 detail
- 只读白名单正例与反例（含 `xargs kill`、`$(shutdown)` 这类挟持形态）
- Windows：关机开关、`sc`/`reg` 只读与破坏性、服务与注册表
- **引号 + 路径混淆**：`cat "/etc//shadow"`、`cat "~/.ssh//id_rsa"` 及其 echo 反例
- **历史动作**（`action_history`）：consent 类规则（改密/删用户授权）只有这个维度才有输入，
  判据是 `ask_user_question` 的 `output`（用户的回答）而非 `action_detail`（提问正文）
- **cwd**：敏感路径的 cwd 相对解析（`cat .ssh/id_rsa`）、间接文件访问的目录列举
- **agent / scenario**：`agent_id` / `scenario_id` 专属规则的加载与合并

**比对的是判定 + 风险标注**。只比判定会漏掉「两端都 Deny 但分类不同」这类分叉
（控制台按 `risk_type` 分类与聚合）—— 加上标注比对后当场照出 3 条原有分叉。

### 已知债务（不是垃圾桶）

`KNOWN_RISK_TYPE_DIVERGENCES`（在生成器里）登记**已确认但暂不改**的标注分歧，
每条都写明「为什么现在不改」，且值要**精确配对**（只放宽这一对，换成别的差异照样报错）。
不在表里的标注不一致一律报错。当前 1 条。

### 另一个维度：用例元数据漂移 `known_risk_type_drift.json`

语料管的是「**同一输入**两端判定是否一致」；这个清单管的是「**同一个用例**声明的
`expected_risk_type` 与实际判定是否一致」—— 两个不同的问题。

背景：用例的 `expected_decision` / `expected_risk_level` 一直被断言，但
`expected_risk_type` **从没被校验**。于是出现了「用例声称在测 L2 授权，实际被
L1 先拦下」的假绿（`tests/cases/l2/logic-06`、`logic-08` 都声明
`expected_layers: ["1.2"]` + `consent_missing`，实际返回 `1.1` + `script_execution`）。

2026-10 起它变成真断言（`tests/test_case_metadata.py`），范围限 `l1/ l2/ agent/`（确定性判定）。
清单条目形如 `{case, expected, python, typescript}`，两端各比自己的字段：

- **偏差集合必须与清单完全一致**：新漂移 → 失败；清单过期（已修复）→ 失败并提示删除
- `python != typescript` 的条目 = **双端 risk_type 分叉**：`decision` 与 `risk_level`
  一致（拦截行为相同），只是「多规则同时命中时先报哪条」不同（典型：TS 先命中敏感
  路径 → `file_access`）。这是独立历史债，修它要重排规则优先级
- 当前 55 条，其中 17 条双端分叉。清理时从清单删对应条目即可

## 语料不是"标准答案"

存的是**两端一致时的判定**，是**冻结的共识**。生成器会先跑两端、断言完全一致
才写入 —— 所以它不会把某一端的错误行为固化成标准（实测里既有 Python 对、TS 也对的，
也有 TS 对、Python 错的）。

## 怎么用

```bash
# 平时：跟着全量测试跑
AGENT_MOSS_DISABLE_LLM=1 python3 -m pytest tests/test_parity_corpus.py -q
cd ts && AGENT_MOSS_DISABLE_LLM=1 npx vitest run src/__tests__/parity-corpus.test.ts

# 有意改了规则行为后：重新生成语料，并 review diff
python3 scripts/gen_parity_corpus.py
```

**什么时候要重新生成**：故意改规则行为时。改完先跑一次生成器看 diff ——
**那个 diff 就是你这次改动的行为影响面**（哪些命令从 Allow 变 Deny、变了多少条），
确认符合预期再连同语料一起提交。

**什么时候不该重新生成**：测试红了但你只改了**一端**。那是分叉，去查哪端对，
而不是把语料刷成新的。

## 两个坑

1. **生成器必须做运行时隔离**。pytest 侧由 `tests/conftest.py` 的 autouse fixture
   隔离，生成器不在 pytest 里跑，不隔离就会读开发者本机的
   `~/.config/agentmoss/agent_moss_runtime.json` —— 于是"生成时按本机配置算、
   跑测试时按源码算"，语料和测试对不上。TS 侧同理，由 vitest `setup.ts` 负责。
2. **TS 侧走 vitest，不要走 tsx**。tsx 在「数据根目录指向不存在的目录」时会把模块图
   判成 ESM，而 `src/config.ts` 用了 `__dirname`，直接
   `ERR_AMBIGUOUS_MODULE_SYNTAX`。vitest 没这个问题，而且它就是 TS 平时跑的运行时 ——
   生成环境与测试环境一致，才不会"生成时一致、跑测试时不一致"。
