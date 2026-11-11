# xiaoO 宿主 agent 定制化规则

## 文件

- `rules.json` — xiaoO 专属规则的单一事实源

## 规则内容

### extra_command_patterns（5 条）

同步自 `xiaoO/plugins/hookers/audit_agent/audit_policy_checker/audit_policy_checker/security/heuristic_detector.py` 行 98–132：

1. `xiaoo\.env|xiaoo\.toml|llm_secrets\.json` — 访问 xiaoO 配置/密钥文件（high）
2. `/usr/lib/\.xiaoo/skills/xiaoo-guardian/.*<写命令>` — 系统级 xiaoO-guardian 目录写保护（critical）
3. `<写命令>.* /usr/lib/\.xiaoo/skills/xiaoo-guardian/` — 反序匹配（critical）
4. `\.xiaoo/skills/xiaoo-guardian/.*<写命令>` — 用户级 xiaoO-guardian 目录写保护（critical）
5. `<写命令>.*\.xiaoo/skills/xiaoo-guardian/` — 反序匹配（critical）

写命令集合：`rm|del|delete|remove|修改|删除|chmod|chown|write|save|保存|modify|更新|覆盖|replace|truncate|追加|append`

### extra_injection_keywords（6 条）

xiaoO 专属绕过词（同步自 audit_agent heuristic_detector.py 行 361–367）：

- EN: `bypass audit` / `skip security check` / `disable guard`（全 critical）
- ZH: `绕过审计` / `禁用安全检查` / `关闭防护`（全 critical）

### builtin_safe_skills

`["xiaoo-guardian"]` — xiaoO 内置安全 Skill，coordinator 直接放行（不递归分析其内容）。

## 加载机制

- py: `agent_moss.agents.get_agent_extensions("xiaoo")` → `AgentExtensions`

detection pipeline 把 `extra_*` 追加到通用规则之后；通用规则先匹配命中即短路。

## 调用方

`hooks/xiaoO/bridge.py` 在 POST `/api/v1/analyze` 时带 `agent_id: "xiaoo"`，AgentMoss 服务端据此加载本规则集。
