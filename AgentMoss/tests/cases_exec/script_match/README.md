# script_match —— 脚本内容扫描匹配基准（供 CPU 级匹配提速验证）

本目录提供给做正则匹配加速的同事：**`scripts/` 下每个脚本文件，都用 `rules.txt` 里的全部正则做匹配**。
规则集与脚本都无第三方依赖，读取方式见下。

## 目录结构

```
script_match/
├── scripts/                 # 待匹配的脚本全文（11 个 + 子模块，2~1990 行，无切片）
│   ├── deploy.sh            11 行   原有：case $1 分支（clean 含 rm -rf ~/.ssh/id_rsa）
│   ├── deploy.py            12 行   原有：Python if 分支（clean 含 os.system rm -rf ~/.ssh/id_rsa）
│   ├── deploy_shift.sh      10 行   原有：shift + case
│   ├── deploy-large.sh      39 行   5 分支 case，嵌套调用 build-script/ 子模块
│   ├── build-large.py       35 行   subprocess.run + os.system 调子脚本
│   ├── deploy-xlarge.sh    732 行   **2026-09 新增**：真实感大型部署脚本
│   │                                 多环境/多组件/回滚，clean 分支含 rm -rf ~/.ssh/id_rsa
│   │                                 与 chmod 777；危险操作埋在 700 行之后
│   ├── build-xlarge.py    1990 行   **2026-09 新增**：真实感大型构建脚本
│   │                                 dataclass/多阶段/缓存/校验，clean 分支含
│   │                                 os.system("rm -rf ~/.ssh/id_rsa")
│   └── build-script/                被 deploy-large.sh / build-large.py 嵌套调用
│       ├── prepare.sh        3 行
│       ├── install.sh        2 行
│       ├── deploy.sh        14 行   clean 分支含 rm -rf ~/.ssh/id_rsa + chmod 777
│       └── cleanup.sh        3 行
├── rules.txt                匹配规则（**185 条**正则，每行一条，与引擎实时对齐）
├── extract_rules.py         规则提取脚本（从引擎动态读取，产出 rules.txt）
│                            ⚠️ 改引擎规则后**必须重跑**；测试
│                            tests/test_script_match_assets.py 会检查是否漂移
└── README.md
```

### 为什么要加大脚本（2026-09 补）

原来样本最长只有 39 行，**压不出真实匹配负载**：2~39 行的文本，
正则引擎大多在首屏就命中/短路，测出来的加速比不代表生产脚本。

新增的 `deploy-xlarge.sh`（732 行）与 `build-xlarge.py`（1990 行）都是**真实结构**
（多函数/多阶段/嵌套调用/dataclass），不是灌水注释；危险操作埋在文件深处，
因此也顺带验证「长文本里靠后位置的危险命令是否仍被抓出」。

## 读取方式

```python
import re
patterns = [line.strip() for line in open("rules.txt") if line.strip()]
compiled = [re.compile(p) for p in patterns]           # 185 条全部可编译
hits = [p for p in compiled if p.search(script_text)]  # re.search 语义
```

`re.search` 语义 = **只判"该规则在这段脚本里命中与否"，不关心命中位置、命中几次、捕获组内容**。
两条必须注意的规则语义（与 Python `re` 保持一致，否则会与引擎判定漂移）：

1. **不做规则间短路**：命中一条不能跳过剩下的，185 条 × 11 个脚本全部都要匹配。
2. **`.*` 不跨行**：引擎没开 `DOTALL`，`.*` 不匹配换行符。脚本是多行的，
   例如 fork bomb `:\(\)\s*\{.*:\|:\s*&.*\};:` 只在**同一行内**才成立。
3. **前瞻断言不能省**：15 条带 `(?!...)` / `(?=...)`（如 `.ssh/id_rsa(?!\.pub)`），
   按字面量或纯子串处理会误报/漏报。

## 规则来源（185 条，全部从引擎动态提取）

| 分组 | 条数 | 引擎对应扫描 |
|---|---|---|
| `dangerous_commands` | 111 | L1 `CommandPatternScanner._compile_from_rules`（`re.IGNORECASE`） |
| `sensitive_path_access` | 55 | L2 `_check_sensitive_path_access`（deny_both 17 / deny_write 32 / deny_read 1） |
| 重定向覆盖 | 3（`>\s*/etc/`、`>\s*/boot/` 与 L1 重复，去重后净增 1） | L2 `_check_dangerous_patterns` |
| `SUSPICIOUS_PATTERNS` | 18 | L1 脚本关键词扫描 `scan_script_for_keywords` |
| **合计（去重后）** | **135** | |

## 大小写

**122 条带 `(?i)`（不敏感），13 条敏感**。敏感的 13 条（引擎里就没加 `IGNORECASE`，必须原样保留）：

```
\bnc\s+.*-e\b              \bid_rsa\b
\bncat\s+.*-e\b            \bid_ed25519\b
/dev/tcp/                  crontab\s+-
/dev/udp/                  authorized_keys
\$\(\s*base64              ssh\s+.*StrictHostKeyChecking\s*=\s*no
`\s*base64
base64\s+(-d|--decode)\s*\|
/etc/shadow
```

注意 `(?i)` 是 Python 内联语法：JS 的 `new RegExp("(?i)x")` 会直接抛异常，需改成对应 flag
（JS `/x/i`、Hyperscan `HS_FLAG_CASELESS`、Rust `RegexBuilder::case_insensitive`）。
另：Python 的 `(?i)` 是 Unicode 级折叠（`(?i)k` 能匹配 `K` U+212A、`(?i)s` 能匹配 `ſ` U+017F），
若按 ASCII 级折叠实现，严格等价性上会有缺口（对正常脚本无影响）。

## 匹配口径（与引擎的对应关系）

1. **喂给规则的是脚本文件原始全文**，不做切片。
2. **引擎侧另有一步文本预处理**：先做可达分支裁剪，再做路径归一化（`//`→`/`、`/./` 折叠）
   和 echo/printf 引号字面量剥离。当前 9 个脚本实测**两种口径的命中矩阵完全一致**
   （脚本里没有 `//`、`/./` 混淆，echo 内容也不含任何规则关键词），所以基准结果有效。
   **扩脚本时要注意**：含 `cat /etc//shadow` 这类混淆的脚本，原文直接匹配会漏、引擎能命中。
3. **本目录是引擎实际扫描量的超集**：引擎按分支裁剪后只扫可达分支，且关键词语义扫描
   （`SUSPICIOUS_PATTERNS`）只对 L1/L2 均未命中的脚本节点执行；本目录对所有脚本无条件跑全部规则。
   → 这是加速验证想看的最坏情况，但**不代表每次命令的真实扫描量**。

## 已知未收录（引擎里不是正则，有意排除）

`_check_dangerous_patterns` 的「通配符 + 删除」检查：`*`/`?` 与删除关键词的子串组合，
且带「文本含 /tmp/ 等临时目录则跳过」的守卫，不是单条正则可等价表达。
实测该检查在当前 9 个脚本上均未命中（含 `*` 的脚本都同时含 `/tmp/`）。

## 当前 9 个脚本的命中情况（可用于自查加速结果是否跑偏）

| 规则 | 命中脚本 |
|---|---|
| `(?i)\.ssh/id_rsa(?!\.pub)` | deploy.sh、deploy_shift.sh、deploy.py、deploy-large.sh、build-large.py、build-script/deploy.sh |
| `(?i)\bid_rsa\b`（大小写敏感） | 同上 6 个 |
| `(?i)(?:^\|[\s/\\'"])\.ssh/id_rsa\b` | 同上 6 个 |
| `(?i)(?:^\|[\s/\\'"])\.ssh(?:/\|[\s'"\\]\|$)` | 同上 6 个 |
| `(?i)chmod\s+(?:(?:-[a-zA-Z]*\|--)\s+)*[0-7]{0,3}7\b` | build-script/deploy.sh |

其余 130 条对这 9 个脚本均不命中（install.sh / prepare.sh / cleanup.sh 三个脚本零命中）。

## 复现

```bash
# 从引擎重新提取规则（引擎规则改动后重跑，本脚本从引擎动态读取，不再手写规则）
python3 extract_rules.py                              # 默认引擎在 ~/gitcode/AgentMoss
AGENT_MOSS_ROOT=/path/to/AgentMoss python3 extract_rules.py

# 匹配基准：对 scripts/ 每个文件 × rules.txt 所有正则
# （同事在此实现加速版本后替换）
```
