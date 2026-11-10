# AgentMoss L1/L2 正则匹配完整清单

> 来源：归一化规则单一事实源 `agent_moss/rules/l1_rules.json` / `l2_rules.json` / `l3_rules.json`（Python 与 TS 共用，加载器见 `agent_moss/rules_loader.py` / `ts/src/infra/rules-loader.ts`）；用户规则 `agent_moss/rules/user_rules.json`
> 一行一条，完整原样。只列**执行正则匹配**的规则（路径串、关键字串等非正则匹配不在内）。

---

## L1 特征匹配

### A. 危险命令正则（归一化 `l1_rules.json` `dangerous_commands`，55 条）

\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/(?!\w)
\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+/(etc|var(?!/tmp)|home|usr|boot|root|opt|srv|sys|proc)\b
\brm\s+-[a-zA-Z]*r[a-zA-Z]*\s+/(?!tmp|var/tmp|run|dev/shm|mnt|media)(?:/|\b)
\brm\s+-[a-zA-Z]*f[a-zA-Z]*\s+/(?!tmp/|var/tmp/|run/|dev/shm/)
chmod\s+(?:(?:-[a-zA-Z]*|--)\s+)*[0-7]{0,3}7\b
chmod\s+(?:(?:-[a-zA-Z]*|--)\s+)*[2-7][0-7]{3}\b
chmod\s+[ugoa]\+s\b
chown\s+root
\bsudo\s+(rm|chmod|chown|dd|mkfs|format|iptables|crontab|passwd|userdel|useradd|groupdel)\b
/etc/shadow
/etc/gshadow
\.ssh/id_rsa(?!\.pub)
\bdd\s+if=/dev/zero.*\bof\s*=\s*/(etc|var|home|usr|boot|root|opt|srv|sys|proc)\b
\bmkfs\.\w+\s+/dev/(sd|hd|nvme|vd|loop|mapper|md|dm)\S+
>\s*/etc/
>\s*/dev/(sd|hd|nvme|vd|loop|mem|kmsg|port|zero|random|urandom|full|core)
/var/run/docker\.sock
git\s+push\s+.*--force
curl\s+.*-X\s+POST.*\b(env|environment|secret|key|token|password)\b
\bnmap\s+
\b(masscan|zmap|unicornscan)\s+
>>\s*(~|/home/[^/]+)/(\.bashrc|\.zshrc|\.profile|\.bash_profile|\.zprofile)
>>\s*\S*/(\.bashrc|\.zshrc|\.profile|\.bash_profile|\.zprofile)\b
(?:curl|wget)\s+.*\|\s*(?:bash|sh|zsh|dash)
(?:curl|wget)\s+.*(?:-o|--output|>)\s*\S+\.(?:sh|bash)\b
(?:curl|wget)\s+\S+.*\b(?:chmod|chown)\s+\+x\b
\|\s*passwd\b
\bpasswd\s+--stdin\b
\bchpasswd\b
\b(newusers|lnewusers)\b
\bpasswd\s+-[a-zA-Z]*d\b
\bpasswd\s+-[a-zA-Z]*l\b
\blpasswd\s
\bgpasswd\s+(?!-[adA])
\bchgpasswd\b
\buserdel\s
\bdeluser\s
\bluserdel\s
\bgroupdel\s
\blgroupdel\s
\b(useradd|luseradd|groupadd|usermod|lusermod|groupmod|lgroupmod)\b[^&|;]*?\s-p\b
(?:\$\(|`)\s*(?:\S+=\S*\s+)*(?:touch|rm|mkdir|mv|cp|dd|tee|truncate|chmod|chown|mkfifo|mknod|ln|shred|mkfs|nc|ncat|socat|bash|sh|zsh|dash|python|python3|perl|ruby|node|php|eval|exec|base64|sudo|su)\b

### B. 双端对齐补齐的危险命令正则（原 TS 独有，本轮补入 Python，双端一致）

:\(\)\s*\{.*:\|:&.*\};:
curl\s+.*\|\s*bash
curl\s+.*\|\s*(sh|zsh|dash)
wget\s+.*\|\s*(bash|sh)
eval\s+\$\(curl|eval\s+\$\(wget
base64\s+-d\s+.*\|\s*bash
\/dev\/tcp\/|bash\s+-i\s+>&
nc\s+-[el]\s+.*\d{1,5}
(?:curl|wget)\s+.*\s+&&?\s*(?:chmod\s+\+x|bash|sh)
git\s+clone\s+.*\|.*bash
pip\s+install\s+.*\|\s*bash
npm\s+install\s+-g\s+.*\|\s*bash
export\s+.*(?:TOKEN|KEY|SECRET|PASSWORD)
>\s*\/boot\/

### C. 敏感路径正则（归一化 `l1_rules.json` `sensitive_path_access`，42 条；路径串走边界正则拼，列原路径）

/etc/shadow
/etc/gshadow
/etc/passwd
/etc/sudoers
.ssh/id_rsa
.ssh/id_ed25519
.ssh/authorized_keys
/etc/hosts
/etc/crontab
/etc/cron.d/
/var/spool/cron/
/etc/systemd/
/etc/ssh/sshd_config
/etc/pam.d/
/etc/nginx/nginx.conf
/etc/nginx/conf.d/
/etc/nginx/sites-enabled/
/boot/
/proc/sys/
/sys/
/dev/random
/dev/mem
/dev/kmsg
~/.bashrc
~/.bash_profile
~/.profile
/etc/ssh/ssh_host_rsa_key(?!\.pub)
/etc/ssh/ssh_host_ed25519_key(?!\.pub)
/etc/ssh/ssh_host_ecdsa_key(?!\.pub)
credentials.yml
credentials.yaml
secrets.yml
secrets.yaml
.env
.aws/credentials
.gitconfig
.gnupg

### D. 注入关键词正则（Python `injection_keywords`，执行子串匹配）

;
|
&&
||
$
(
)
{
}
<
>
\ns
\rm

### E. 用户规则正则（Python `user_rules.json` sensitive_actions，17 条；含通配符转 RegExp）

写入系统文件
发送外部邮件
危险 shell 命令
修改全局配置
支付操作
访问密钥文件
网络数据外传
curl\s+\S*\s+-d\s+\S*
curl\s+\S*\s+POST\s+\S*
wget\s+\S*--post-data\s*\S*
crontab\s+-e
crontab\s+-r
\S*\s+\|\s+crontab
iptables\s+-
ssh\S*\s+-o\s+StrictHostKeyChecking=no
base64\s+-d\s+\S*\s+bash
curl\s+\S*\s+\|\s+bash

### F. 横向移动检测（Python `logic_rules.py::_check_lateral_movement` / TS `heuristic.ts::checkLateralMovement`）

非单正则，token 化三策略提取远程主机（NEW-FN-G 重构，旧单正则 `(?:ssh|scp|rsync)\s+(?:-[\w]+\s+)*(\S+@\S+|\b(?!-)[\w.-]+\b)` 因 `(?:-[\w]+\s+)*` 只匹配单选项不匹配带参数值选项如 `-p 2222`/`-L 8080:...`/`-D 1080`/`-e ssh`，导致 host 提取取到端口号或选项参数，已废弃）：

1. **策略1（user@host）**：token 化（先剥首尾引号，处理 `bash -c "ssh user@host"`，NEW-FP-E）后，逐 token 匹配 `^([\w.-]+)@([\w.-]+)(:.*)?$`，命中非本地主机即横向移动
2. **策略2（host:）**：无 user@ 时匹配 `^([\w.-]+):(/.*)?$`（rsync/scp 远程路径 `host:/path`）
3. **策略3（纯 host）**：无 @ 无 : 时（如 `ssh 10.0.0.5`），跳过命令本身 + `-` 开头选项 + 带值选项参数值（`-p/-l/-i/-o/-L/-R/-D/-e/-P` 等的下一个 token），首个非选项非路径 token 为候选主机

跳过条件（不拦）：
- 内联脚本（`python -c`/`perl -e` 等，`_INLINE_SCRIPT_RE`，bash -c/sh -c **不跳过**——内联的是真实 shell 命令非字面量）
- echo/printf 首词段（字面量非真调用）
- 提取到的 host 在本地主机集（`localhost`/`127.0.0.1`/`::1`/`0.0.0.0`/hostname）

---

## L2 逻辑规则正则

### 1. 写命令识别（WRITE_CMDS / WRITE_COMMAND_RES，正则字面量）

\brm\b
\bunlink\b
\brmdir\b
\bshred\b
\bcp\b
\bmv\b
\binstall\b
\btee\b
\bdd\b
\bmkfs\b
\b(fdisk|parted|cfdisk|sfdisk)\b
\bchmod\b
\bchown\b
\btruncate\b

### 2. 真实重定向写判定（read_before_write / redirect 检测）

>{1,2}\s*(?!&)\S
(?:2|&|1)?\s*>\s*/dev/null\b
>{1,2}\s*(['"])([~./][^'"]+)\1
\bsed\s+-[a-zA-Z]*i

### 3. 写判定边界（wget -O / rsync 等）

\s(?:-O|--output-document|--output)(?:=|\s|$)
\s-O\S
--list-only|--dry-run
(?<![a-zA-Z])-n(?![a-zA-Z])

### 4. 只读命令真实重定向判写（REDIRECT_TARGET_RE）

>{1,2}\s*(?!&)(?:'(/[^']+)'|"(/[^"]+)"|(/[^;|&><'\"]+))

### 5. 密码修改授权（PASSWORD_MODIFY_PATTERNS，7 条）

\|\s*passwd\b
\bpasswd\s+--stdin\b
\bchpasswd\b
\bchgpasswd\b
\b(newusers|lnewusers)\b
\bpasswd\s+-[a-zA-Z]*d\b
\bpasswd\s+-[a-zA-Z]*l\b

### 6. 用户/组删除授权（USER_DELETION_PATTERNS，5 条）

\buserdel\s
\bdeluser\s
\bluserdel\s
\bgroupdel\s
\blgroupdel\s

### 7. 提权检测（命令段首词判定 + admin_keywords，NEW-FP-J）

NEW-FP-J: 提权关键词改「命令位置」判定。引号感知分段后仅当段首词是以下提权命令才触发，
grep/awk/echo/find 首词段的参数/搜索模式里的 sudo/setuid 是字面量不触发。

首词判定（段首词 ∈ 以下集合）
sudo
su
setuid
chmod u+s（chmod 段配 `\bu\s*\+\s*s\b` 匹配 setuid 位）

admin_keywords（sudo 后跟该命令视为合法运维直接放行）
apt
systemctl
yum
dnf
pacman
zypper
apk

### 8. 内联脚本检测（INLINE_SCRIPT_RE）

(?:^|\s)(?:python|python3|python3\.\d+|perl|perl5|ruby|jruby|mruby|node|php|lua)\s+(?:-[a-zA-Z]*[cer][a-zA-Z]*\s+)

### 9. 路径提取（unixPaths / kvPaths / quotedPaths）

(?:^|\s)(/[^\s;|&><'"]+)
textNoQuotes = text.replace(/'[^']*'|"[^"]*"/g, '')  # NEW-FP-H: kvPaths 应用前先剥引号内容
(?:=)(/[^\s;|&><'"]+)  # 在 textNoQuotes 上扫描，避免 echo "of=/dev/null" 误提取
["']\/([^"']+)["']  # 引号内纯路径独立提取（要求引号内以 / 开头），故剥引号不漏报真实写

### 10. 边界匹配（quoted redirect / detail strip）

>{1,2}\s*(['"])([~./][^'"]+)\1
'[^']*'|"[^"]*"
<=>|>=|<=|<>|=>
(^|\|\||&&|\s)sudo\s+

### 11. dd 源参数匹配

\bif=(/[^\s;|&><'"]+)

### 12. 全安全放行白名单（FULLY_SAFE_BASH_PATTERNS，coordinator.ts）

^ls(?:\s|$)
^dir(?:\s|$)
^pwd(?:\s|$)
^which\s+
^whereis\s+
^realpath\s+
^basename\s+
^dirname\s+
^file\s+
^stat\s+
^du(?:\s|$)
^echo\s+
^printf\s+
^type\s+
^command\s+
^whoami(?:\s|$)
^id(?:\s|$)
^hostname(?:\s|$)
^uname(?:\s|$)
^date(?:\s|$)
^env(?:\s|$)
^printenv(?:\s|$)
^tty(?:\s|$)
^arch(?:\s|$)
^uptime(?:\s|$)
^groups(?:\s|$)
^logname(?:\s|$)

### 13. 只读敏感放行（READONLY_SENSITIVE_BASH_PATTERNS，coordinator.ts）

^cat\s+
^head(?:\s|$)
^tail(?:\s|$)
^less(?:\s|$)
^more(?:\s|$)
^wc(?:\s|$)
^grep(?:\s|$)
^find\s+
^ag(?:\s|$)
^rg(?:\s|$)
^awk\s+
^sed\s+
^cut\s+
^sort(?:\s|$)
^uniq(?:\s|$)

### 14. SSH 主机私钥前瞻排除公钥（TS logic-rules.ts，对齐 Python .ssh/id_rsa(?!\.pub)）

/etc/ssh/ssh_host_rsa_key(?!\.pub)
/etc/ssh/ssh_host_ed25519_key(?!\.pub)
/etc/ssh/ssh_host_ecdsa_key(?!\.pub)

### 15. NEW-FP-C: wget/curl stdout 值排除（不算文件写，logic_rules.py / logic-rules.ts）

\s(?:-O|-o)-(?:\s|$)
\s--output-document=-(?:\s|$)
\s--output=-(?:\s|$)

### 16. NEW-FN-F: rsync host: 多参数扫描（heuristic.py / heuristic.ts extractRemoteHost）

(?:([\w.-]+)@)?([\w.-]+):/?

### 17. NEW-FP-D: 横向移动内联脚本 + echo/printf 字面量跳过（heuristic.py _check_lateral_movement / heuristic.ts checkLateralMovement）

\b(?:python|python3|perl|ruby|node|php|lua)\b\s+.*-[cer][a-zA-Z]*\s
(?:^|\s)(?:echo|printf)\b

### 18. L2 组合攻击链阶段正则（l2_rules.json combo_chains.stages，logic_rules.py _check_combo_chain / logic-rules.ts checkComboChain / formal_engine 复用，2026-08-16 新增）

**LISTEN（建立监听/后台服务）**：
\bflask\b
\bfastapi\b
httpserver
http\.server
\bnc\s+-l
\bsocat\b
nohup\s+.*\bpython
create\s+.*listener
listen\(

**EXEC（命令执行能力）**：
subprocess
os\.system
shell\s*=\s*True
\beval\(
\bexec\(
/exec
\bbash\s+-c
run.*command

**SCAN（网络侦察）**：
\bnc\s+-z
\bnmap\b
port\s*scan
\bseq\b.*\bnc\b
192\.168\..*nc
scan.*\bport

**CRED（凭据访问）**：
known_hosts
\.ssh
id_rsa
/etc/shadow
/etc/passwd
credential
aws.*credentials

**EXFIL（数据外传）**：
\bcurl\s+.*https?://
\bwget\s+.*https?://
\bscp\s+.*@
\brsync\s+.*@
POST.*https?://

**PERSIST（持久化后门）**：
\bcrontab\b
\bsystemd\b
systemctl\s+enable
\.bashrc
\.profile
/etc/rc\.local
\bnohup\b
\bdaemon\b
startup\s+item
\bat\s+reboot

**PRIVESC（提权）**：
\bsudo\b
\bsu\b
chmod\s+u\s*\+\s*s
\bsetuid\b
\bpkexec\b
\bdoas\b

> 注：以上是 `l2_rules.json` 的 **stage 投影正则**（P1/L2.1 组合链用）。formal 引擎
> **P4/P5 的提权判定不直接复用此裸正则**，改用**命令位置判定**（`properties.py`
> `_contains_privesc` / `properties.ts` `containsPrivesc`）——只当段首词是 sudo/su/chmod/
> setcap/pkexec/doas 且命中具体提权特征才算，免疫 `echo "sudo"`/`grep "setuid"` 等字面量，
> 并额外兜底 `sudo su`/`sudo bash` 裸露 shell 提权（详见 SECURITY_RULES.md §8）。
> 同理 P4/P5 的 EXFIL 判定（`_is_exfil_node`）排除回环地址（`127.x`/`localhost`/`::1`/
> `0.0.0.0`），与 EXFIL stage 的回环排除保持一致。
>
> **stage 多命中仲裁（2026-09-07，NEW-FP）**：`match_stage_any`（`decode.py`/`decode.ts`）
> 旧版按 stages 字典序取第一个命中——「编辑 Flask 文件加 subprocess shell=True 后门」同时
> 命中 LISTEN（flask 词）与 EXEC（subprocess），LISTEN 在前被误标 → `listener-exec-scan`
> 链 EXEC 缺失 → 收尾步放行。修复：EXEC 目的类调用形态（`subprocess.\w+(`/`shell=True`/
> `os.system(` 等）胜出；起服务顶层形态（nohup/http.server/flask run/nc -l）保持 LISTEN；
> EXEC 载体类（python3 -c/bash -c）让位给目的性 stage（socket listen→LISTEN、pkexec→PRIVESC），
> CRED 不让位（bash -c 'cat /etc/shadow' 保持 EXEC）。另 EXFIL 第 6 条（python -c requests/
> urllib POST）补回环排除 `https?://(?!127\.…|localhost|::1)`。详见 L2.2_FORMAL_COMBO_ENGINE.md B.12。

### 19. NEW-FN-H: 主目录删除检测（HomeDeletionChecker，heuristic.py / checkHomeDeletion heuristic.ts，2026-09 新增，2026-09 收紧为只拦根删除）

主目录删除检测按命令段判定，主目录根目标正则（Python `_HOME_TARGET_RE` / TS `HOME_TARGET_RE`）：
```
(?:^|[\s="'($])(?:~|(?:\$home|\$\{home\}))(?:\/(?:\.\*|\*|\.)?)?(?=[\s"';}|&|\)]|$)
```
- 前界 `^|空白|=|引号|$`（命令替换内）；后界 `行尾|空白|引号|;|}`（**不含 `/` 子路径段**）；允许 0..1 个 `/` 后跟 `*`/`.*`/`.`（通配全内容/自身点）。
同段赋值解析（Python `_ASSIGN_RE` / TS `HOME_ASSIGN_RE`）：
```
([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(~[A-Za-z0-9_./-]*|\$HOME[A-Za-z0-9_./-]*|\$\{HOME\}[A-Za-z0-9_./-]*|/home/[^\s;|&]+|\$\((?:[^()]|\([^()]*\))*\))(?=\s|;|$|\||&)
```
- 只拦**删除类命令段**（段首 `rm`/`rmdir`/`unlink` 或含"删除/移除"）目标为**主目录根**：`rm -rf ~`、`rm -rf ~/`、`rm -rf ~/*`、`rm -rf ~/. && rm -rf $HOME`、`$HOME/` 等；`TARGET=$HOME; rm -rf $TARGET`、`TARGET=~/; rm -rf $TARGET`、`T=/home/xx; rm -rf $T`（裸用户目录）、`rm -rf $(echo $HOME)`/`VAR=$(echo $HOME); rm -rf $VAR`/`d=$(echo ~); rm -rf $d` 命令替换间接形态均拦截。
- **NEW-FN（`..` 穿越，2026-09）**：`rm -rf ~/..`（=删 `/home` 本机所有用户主目录）、`rm -rf $HOME/../..`（=删 `/`）、`rm -rf ~/.ssh/..`（弹回主目录根）——主目录根正则不含 `..` 段全部漏放。深度行走（token 化 + `..` 弹栈）解析：起点为主目录根、**行走过程中记录最低深度 min_depth**——中途弹出根以下（`~/a/../../b/c` = 删 `/home/b/c`，2026-09 审查批次2 收紧）→ 无论最终是否回升都拦；最终深度 ≤ 根深度 → 拦（删根及以上）；**全程未出界**落到具体子路径（`~/a/../b` = 清理 b）→ 放行。双端 `_home_escape_target` / `homeEscapeTarget` 对齐。
- **NEW-FP（收紧）**：`~/x`、`$HOME/x`、`TARGET=$HOME/x; rm -rf $TARGET`（带路径段的赋值源）、`$(echo ~/x)`、`/home/xx/backup`（用户目录下子路径）均**放行**（定向清理具体子目录，如 `rm -rf ~/project/build`、`rm -rf ~/.cache/pip`、`rm ~/notes.txt`、`rmdir ~/empty`）；凭据子目录 `.ssh`/`.aws` 整目录删除由敏感路径表目录级条目兜底（见 SECURITY_RULES.md D5-D7）。
- 只读（`cd ~`/`echo $HOME`/`cat ~/.bashrc`/`ls $HOME`）与写普通文件（`echo >> ~/.gitconfig`）不命中——改权限/写文件由 chmod 规则、敏感路径 deny_write 定级。
