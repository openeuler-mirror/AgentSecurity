# 规则目录模板（随包分发，**不用跑任何命令**）

把要用的文件拷进你的**规则目录**（环境变量 `AGENT_MOSS_EXTRA_RULES_DIR` 指向的那个目录）：

| 文件 | 干什么 | 放进目录的效果 |
|---|---|---|
| `extra.json` | **追加**规则 | 内置规则**全部保留**，你写的加在其后一起判定 |
| `override.json` | **覆盖**规则 | **你写了哪个类别，那个类别就整份以你的为准**；没写的类别照常用内置 |

> 两个文件里每个类别都是**空数组** ⇒ **原样拷进去 = 什么都不改**（安全）。
> 想加什么，照下面的样例往对应类别的方括号里填。

---

## 生效规则（**先看这一节**：谁会被读、谁压谁）

AgentMoss **只读规则目录里的这两个文件名**，其他名字的 `.json` **一律不读**：

| 文件 | 作用 |
|---|---|
| `extra.json` | 里面**出现的类别** → **追加**在内置规则之后一起判定 |
| `override.json` | 里面**出现的类别** → **整份替换**内置的同名类别（没写的类别保持内置不变） |
| 其他任何 `.json` | **不读**（启动日志与 `agent-moss rules status` 会列出"**不会被读取**"清单） |
| `scenarios/<场景id>/rules.json` | 场景规则（如 bank 的白名单 / 禁 ssh）的**整份替换位** —— 独立机制，不走上面两个文件（前提：`AGENT_MOSS_SCENARIO` 保持开启） |

**两个文件同时存在时：都生效。**最终规则 =

```
① override.json 里写到的那些类别  （整份以你的为准，内置同类不再参与）
② + extra.json 里写到的那些类别  （追加）
③ + 没被上面碰过的内置类别       （照常生效）
```

同一个 `pattern` / `path` 重复时 → **保留先出现的**，也就是优先级 **override.json > extra.json > 内置**。

⚠️ **空数组 = 不覆盖 / 不追加**（所以这两个模板原样拷进目录 = 什么都不改，安全）。
⚠️ 想改**场景规则**（bank 白名单/禁 ssh）：走 `<规则目录>/scenarios/bank/rules.json`，
且 `AGENT_MOSS_SCENARIO` **必须保持开启**——关掉它不是"覆盖"，而是让 bank 规则**全部失效**。

## 怎么写（照抄这两段就行）

### 例 1：追加一条"禁止 su" + 一条"保护 /data/hr"（写进 `extra.json`）

```json
{
  "dangerous_commands": [
    {"pattern": "(?:^|[;&|])\\s*su(?:\\s|$)", "risk_level": "high",
     "risk_type": "privilege_escalation", "reason": "禁止切换用户"}
  ],
  "sensitive_path_access": [
    {"path": "/data/hr", "risk_level": "high", "desc": "HR 数据", "deny_mode": "deny_both"}
  ]
}
```

### 例 2：覆盖内置的敏感路径（写进 `override.json`）

```json
{
  "sensitive_path_access": [
    {"path": "/data/hr", "risk_level": "high", "desc": "HR 数据", "deny_mode": "deny_both"}
  ]
}
```

> ⚠️ 只写 `sensitive_path_access` ⇒ **内置的 91 条敏感路径全部被这份替换掉**（这就是"覆盖"）。
> 只想加一条请用 `extra.json`。

---

## 字段说明（只跑 L1 的部署看这三类就够）

| 类别 | 字段 | 说明 |
|---|---|---|
| `dangerous_commands` | `pattern`（正则）、`risk_level`（high/critical）、`risk_type`、`reason` | 危险命令 |
| `injection_detection` | `keyword`、`lang`（如 `zh`） | 提示注入关键词 |
| `sensitive_path_access` | `path`、`risk_level`、`desc`、`deny_mode` | 敏感路径 |

另外三个类别（`intent_consistency` / `password_modify_consent` / `user_deletion_consent`）属于 **L2**；
设了 `AGENT_MOSS_DISABLE_LOGIC_RULES=1` 时写了也不生效。

### ✍️ 正则里的反斜杠要写两次

JSON 里 `\` 是转义符，所以正则的 `\s`、`\b`、`\n` 要写成 **`\\s`、`\\b`、`\\n`**：

| 你想要的匹配 | JSON 里要写 |
|---|---|
| 空白 `\s` | `"\\s"` |
| 单词边界 `\b` | `"\\b"` |
| 换行 `\n` | `"\\n"` |

（上面"例 1"里就是这么写的，可以直接抄。）

---

## 三个最常见的坑

1. **敏感路径想连"读取"一起拦，必须写 `"deny_mode": "deny_both"`**；只写 `path` 默认**只拦写/删**。
2. **覆盖是"整类替换"**：`override.json` 的 `dangerous_commands` 里只写 1 条，
   内置那 225 条危险命令规则就都不生效了 —— 只想加规则请用 `extra.json`。
3. **同一条命令可能被多条内置规则覆盖**：`cat /etc/shadow` 在 `sensitive_path_access` 与
   `dangerous_commands` 里各有一条。删完用下面这条命令看**理由**（命中哪条），按理由删干净：

```bash
agent-moss analyze "cat /etc/shadow"
```

## 想删掉内置的某一条？

```bash
# 生成一份内置 L1 规则的全量拷贝，删掉/改掉你不要的那条
agent-moss rules init --dir <你的目录> --with-builtin
```
（这份拷贝会被"钉"在当版：以后升级内置规则不会反映到它上面 —— 只做临时改动用。）

## 高级：另外三类数据也能覆盖 / 追加（一般用不到）

除了上面六个规则类别，这两个文件还认三个键（形状不同，别和规则类别混）：

| 键 | 内容 | 覆盖 / 追加语义 |
|---|---|---|
| `skills` | L3 技能表 `{"类别": {"技能名": ["关键词", ...]}}` | 覆盖：写到的**类别**整份替换；追加：按技能名合并 |
| `ltl_rules` | L2.2 时序规则 `[{"id": "...", ...}]` | 覆盖：整份替换规则清单；追加：按 `id` 合并 |
| `tools` | 工具注册表 `{"工具名": {"actionClass": "...", ...}}` | 覆盖：整份替换；追加：按工具名合并 |

空模板里**没有**这三个键（默认不写就是完全不管）；要用时自己加上。

## 改完自查

```bash
agent-moss rules status
```
会打印：生效了哪些类别各多少条 / 哪些文件**不会被读取**（名字不对）/ 模板还没填。
