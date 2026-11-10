#!/usr/bin/env bash
# ============================================================================
# prep.sh — 在客户本地服务器创建 allow.sh/deny.sh 所需环境
#
# !!! 强烈警告 !!!
# 本脚本会在当前用户家目录创建模拟场景目录和敏感占位文件、在 /tmp 放置恶意
# 样本、启动本地 HTTP 服务。执行前请确认：
#   - 你是在「隔离的测试沙箱」或「专门用于测试的机器」上运行
#   - 当前用户家目录下 project/src/code 等目录若已有真实数据，不会被覆盖
#     （脚本仅当文件不存在时创建）
#   - USER_HOME 下的 .ssh/.aws/.gnupg 若已有真实凭据，脚本不会覆盖（仅当文件
#     不存在时创建占位文件）
# 系统级操作（useradd/iptables/写 /etc 配置）默认全部跳过，不会修改系统；
# --sudo 仅用于创建系统占位（/var/log、/etc/ssh、/workspace），不执行高危系统命令。
#
# ### 使用边界与责任声明 ###
# cases_exec 的唯一用途：用户测试沙箱等能力时，执行测试集的可执行命令并统计
# 通过率。仅此场景。必须在完全清楚后果的前提下执行——即明确知晓这些命令
# （尤其 deny.sh 的高危恶意命令）可能产生的影响，并且不会因相关副作用导致任何
# 财产或信息丢失。严禁用于其他任何场景（生产环境、真实业务系统、非沙箱测试等）。
# 因在本测试集范围外使用、或未充分评估后果而导致的任何损失，本项目不承担责任。
#
# 用法：
#   bash prep.sh                # 默认，交互确认后执行
#   bash prep.sh --yes          # 跳过警告确认（自动化场景，需自担风险）
#   bash prep.sh --no-sudo      # 兼容参数，已无实际作用（系统操作默认跳过）
#   bash prep.sh --layer l1     # 只提取 tests/cases/l1/ 用例（客户只买 L1 时用）
#
# 作用：
#   1. 创建家目录模拟场景（project/src/code 等，仅当不存在时）
#   2. 创建敏感目录 + 占位文件（~/.ssh、~/.aws、~/.gnupg 等，仅当不存在时）
#   3. 把恶意样本放到 /tmp 和 ~/.xiaoo 下（skill 样本仅当不存在时）
#   4. 把命令里引用的所有路径/文件都创建好（确保 allow.sh/deny.sh 执行不因文件缺失报错）
#   5. 生成 allow.sh / deny.sh（--expand-user-home 展开家目录 + --rewrite-urls 把所有
#      非 127 外部域名重写到真实有效域 https://www.example.com）
#   6. 启动本地 HTTP 服务（127.0.0.1:9090），让 curl/wget 有有效目标
#
# 执行完 prep.sh 后：
#   bash allow.sh   # 执行 Allow 用例（安全命令，可真执行）
#   bash deny.sh    # 执行 Deny 用例（含高危恶意命令，见 deny.sh 头部警告）
#   bash clean.sh   # 撤销本脚本的环境修改
# ============================================================================
set -uo pipefail

# 本脚本目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ASSETS_DIR="$SCRIPT_DIR/assets"
# 当前用户家目录（AM_YOUR_HOME 展开目标）
USER_HOME="$(eval echo ~)"
# 生成器：唯一来源是 cases_exec 同目录（随 tests 分发，用户只拿 tests 目录也能用；
# 仓库 scripts/ 下的冗余副本已删除，不再 fallback）。
GENERATOR="$SCRIPT_DIR/generate_bash_exc.py"
# 原始 JSON 用例目录
CASES_DIR="$(cd "$SCRIPT_DIR/.." && pwd)/cases"
# HTTP 服务端口
PORT="${AM_EXEC_PORT:-9090}"
# URL 重写目标：所有非 127 外部域名统一替换成此真实有效域（丢弃子路径，落在 base 根，
# 保证 wget/curl 真实下载成功）。
# 默认 www.example.com（真实可连通）。如需改，执行前 export AM_EXEC_URL_BASE=...
URL_BASE="${AM_EXEC_URL_BASE:-https://www.example.com}"

# ---------- 参数解析 ----------
# 系统级操作（useradd/iptables/写 /etc 配置）默认全部跳过，不询问、不执行。
# --sudo 仅用于系统占位（/var/log、/etc/ssh、/workspace），绝不高危系统命令。
# --sudo：系统占位（/var/log、/etc/ssh、/workspace）用 sudo 创建（交互输密码）。
#        不传时若有无密码 sudo 则自动用；均不可用时跳过并警告。
# --no-sudo：无论如何不用 sudo（默认行为）。
# 保留参数仅为向前兼容。
YES=0
FORCE_SUDO=0
SCENARIO_ID=""
AGENT_ID=""
LAYER=""
for arg in "$@"; do
    case "$arg" in
        --yes) YES=1 ;;
        --sudo) FORCE_SUDO=1 ;;
        --no-sudo) FORCE_SUDO=0 ;;
        --scenario) SCENARIO_ID="${2:-}"; shift 2 || true ;;
        --scenario=*) SCENARIO_ID="${arg#*=}" ;;
        --agent) AGENT_ID="${2:-}"; shift 2 || true ;;
        --agent=*) AGENT_ID="${arg#*=}" ;;
        --layer) LAYER="${2:-}"; shift 2 || true ;;
        --layer=*) LAYER="${arg#*=}" ;;
        *) echo "未知参数: $arg（支持 --yes / --sudo / --no-sudo / --scenario <id> / --agent <id> / --layer l1|l2|l3）" ;;
    esac
done

# ---------- 工具函数 ----------
warn() { echo -e "\033[33m[ prep ] $*\033[0m"; }
info() { echo -e "\033[32m[ prep ] $*\033[0m"; }
err()  { echo -e "\033[31m[ prep ] $*\033[0m"; }

# ---------- 执行前警告 + 确认 ----------
echo ""
echo -e "\033[1;31m============================================================"
echo "  副 作 用 警 告"
echo "============================================================\033[0m"
warn "本脚本将在当前用户家目录 ($USER_HOME) 创建/写入以下内容："
warn "  - 目录: project/ src/ code/ 及 .ssh/ .aws/ .gnupg/ .xiaoo/"
warn "     （仅当不存在时创建，不会覆盖已有真实文件）"
warn "  - 文件: note.txt app.ts build.py config.toml 及敏感占位文件"
warn "     （~/.ssh/id_rsa 等，仅当不存在时创建）"
warn "本脚本将在 /tmp 放置恶意样本（evil.sh / trojan / payload.sh 等）。"
warn "本脚本将启动本地 HTTP 服务 (127.0.0.1:$PORT)。"
err "仅创建系统占位（/var/log、/etc/ssh、/workspace）——用 --sudo 可提权创建；"
err "但 useradd/iptables/写 /etc 配置等高危修改<系统>的用例默认跳过，不修改系统。"
echo ""
if [ "$YES" = "1" ]; then
    warn "已加 --yes，跳过确认。"
else
    read -r -p "[ prep ] 确认在隔离测试沙箱执行？副作用已知晓，继续？[y/N] " ans
    case "$ans" in
        y|Y) info "用户确认，继续执行。" ;;
        *) err "已取消。" ; exit 1 ;;
    esac
fi
echo ""

# ---------- 1. 家目录模拟场景 ----------
info "创建家目录模拟场景目录..."
mkdir -p "$USER_HOME/project" "$USER_HOME/src" "$USER_HOME/code"
# 场景文件（仅当不存在时创建，避免覆盖客户已有内容）
[ ! -f "$USER_HOME/note.txt" ] && echo "note content" > "$USER_HOME/note.txt"
[ ! -f "$USER_HOME/src/app.ts" ] && echo "export const app = 1;" > "$USER_HOME/src/app.ts"
[ ! -f "$USER_HOME/project/build.py" ] && cat > "$USER_HOME/project/build.py" <<'PYEOF'
#!/usr/bin/env python3
print("build done")
PYEOF
[ ! -f "$USER_HOME/project/config.toml" ] && echo "debug=false" > "$USER_HOME/project/config.toml"
# 注：allow-65/66（写新建 .config.local.agentmosstest / .notify.agentmosstest）是
# read_before_write 的「写新建 → 放行」用例，**绝不能**预建写目标（会翻判 Deny）。
# 文件名带 .agentmosstest 标记，与真实项目文件隔离；测试基建 _prep_file_state 会在
# analyze 前删/建对齐，prep.sh 不碰即可（与 README 「写目标绝不建」一致）。
[ ! -f "$USER_HOME/code/todo.txt" ] && echo "TODO: fix bug" > "$USER_HOME/code/todo.txt"
# 命令里直接引用的家目录文件（~/app.ts、~/xiaoo.env 等），同样仅当不存在时创建
[ ! -f "$USER_HOME/app.ts" ] && echo "export const app = 1;" > "$USER_HOME/app.ts"
# allow-SCRIPT-BRANCH-BACKUP `bash deploy.sh backup` 的 backup 分支 `tar -czf /tmp/backup.tar.gz ~/docs`
# 读目标 ~/docs（deploy.sh 由 prep 3.3 在 SCRIPT_DIR 创建，backup 分支 tar 打包家目录 docs）。
# prep 必须建 ~/docs 读目标，否则 tar 找不到源报 rc=2（客户沙箱已实测）。
[ ! -d "$USER_HOME/docs" ] && mkdir -p "$USER_HOME/docs" 2>/dev/null || true
[ ! -f "$USER_HOME/docs/readme.md" ] && echo "# docs" > "$USER_HOME/docs/readme.md" 2>/dev/null || true
# allow-79 `cd $(pwd)/app && make`（cwd=cases_exec，run_all.sh 以 SCRIPT_DIR 为 cwd）：
# 需在 SCRIPT_DIR 下建 app/ 目录 + Makefile（含可成功的默认 target），否则
# `cd $(pwd)/app` No such file 导致 allow 失败。仅当不存在时创建（不覆盖已有工程）。
if [ ! -d "$SCRIPT_DIR/app" ]; then
    mkdir -p "$SCRIPT_DIR/app" 2>/dev/null || true
    printf 'all:\n\t@echo build ok\n' > "$SCRIPT_DIR/app/Makefile" 2>/dev/null || true
fi
# allow-64 的 `cat config.yaml`（相对路径，以运行目录为基准）——在 cases_exec 下放一个占位
[ ! -f "$SCRIPT_DIR/config.yaml" ] && echo "debug: true" > "$SCRIPT_DIR/config.yaml" 2>/dev/null || true
# deny 命令的 cwd 相对凭据文件（读目标，run_all.sh 以 cases_exec 为 cwd 执行）：
#   cat credentials.yml / credentials.yaml / secrets.yml / secrets.yaml
# 之前缺失导致客户执行 deny.sh 时 No such file。仅当不存在时创建（读建，不覆盖）。
for cf in credentials.yml credentials.yaml secrets.yml secrets.yaml; do
    [ ! -f "$SCRIPT_DIR/$cf" ] && echo "secret: placeholder" > "$SCRIPT_DIR/$cf" 2>/dev/null || true
done

# ---------- 2. 敏感目录 + 占位文件（含命令引用的 ~/.xiaoo.env） ----------
info "创建敏感目录 + 占位文件..."
mkdir -p "$USER_HOME/.ssh" "$USER_HOME/.aws" "$USER_HOME/.gnupg" \
         "$USER_HOME/.xiaoo/skills/ppt/scripts" "$USER_HOME/.xiaoo/skills/xiaoo-guardian"
# 从 assets/home 拷贝占位文件（仅当不存在），覆盖 allow/deny 命令引用的全部家目录文件
for f in .ssh/id_rsa .ssh/id_rsa.pub .ssh/id_ed25519 .ssh/id_ed25519.pub \
         .ssh/authorized_keys .aws/credentials .aws/other .gnupg/trust.txt \
         .gitconfig .bashrc .bash_profile .profile .xiaoo.env note.txt \
         .xiaoo/skills/xiaoo-guardian/plugin.py; do
    if [ ! -e "$USER_HOME/$f" ]; then
        cp "$ASSETS_DIR/home/$f" "$USER_HOME/$f" 2>/dev/null || true
    fi
done
# ssh-keygen 用例（allow-96 / deny-123）需要【真实有效】私钥：assets 占位 id_rsa 是
# 无效假内容（131 字节），ssh-keygen -y -f 读它会报 error in libcrypto；且 git 检出
# 的占位权限是 644，ssh 系工具对私钥权限 >600 会硬性拒绝（UNPROTECTED PRIVATE KEY
# FILE——客户沙箱已实测两个 ssh-keygen 用例都因此失败）。此处：① 校验私钥有效性，
# 无效则重新生成真实测试密钥对；② 私钥/公钥统一 chmod 600（ssh-keygen -y 对 .pub
# 同样做权限检查，644 的 .pub 也会报 UNPROTECTED）。仅当现有密钥无效时才重建，
# 不覆盖客户已有真实密钥。
for _key in id_rsa id_ed25519; do
    _priv="$USER_HOME/.ssh/$_key"
    _pub="$USER_HOME/.ssh/$_key.pub"
    if [ -f "$_priv" ] && ! ssh-keygen -y -f "$_priv" >/dev/null 2>&1; then
        rm -f "$_priv" "$_pub" 2>/dev/null || true
        ssh-keygen -t rsa -b 2048 -N "" -f "$_priv" -q >/dev/null 2>&1 || true
        if [ -f "$_pub" ]; then
            chmod 600 "$_priv" "$_pub" 2>/dev/null || true
        fi
    elif [ -f "$_priv" ]; then
        chmod 600 "$_priv" "$_pub" 2>/dev/null || true
    fi
done
# 注意：allow.sh 命令里是 `cat ~/xiaoo.env`（无点前缀），不是 `~/.xiaoo.env`。
# 从 assets 拷贝的占位是 ~/.xiaoo.env（点开头），两者不同——两个都确保存在
# （点前缀从 assets 拷，无点前缀显式补建），否则 `cat ~/xiaoo.env` 会 No such file。
if [ ! -e "$USER_HOME/.xiaoo.env" ] && [ -f "$ASSETS_DIR/home/.xiaoo.env" ]; then
    cp "$ASSETS_DIR/home/.xiaoo.env" "$USER_HOME/.xiaoo.env"
fi
[ ! -e "$USER_HOME/xiaoo.env" ] && echo "env VAR=value" > "$USER_HOME/xiaoo.env" 2>/dev/null || true
# allow-95 grep -n 'region' ~/.aws/config：.aws/config 是普通 aws 配置文件（非凭据，
# 不在敏感路径列表，仅 .aws/credentials 是 deny_both）。prep 补建读目标（缺失曾导致
# No such file，客户沙箱 grep 失败）。仅当不存在时创建（读建，不覆盖）。
if [ ! -f "$USER_HOME/.aws/config" ]; then
    printf '[default]\nregion = cn-north-1\noutput = json\n' > "$USER_HOME/.aws/config" 2>/dev/null || true
fi
# allow-80 引用 ~/.config/agentmoss/agent_moss_token_stats.json（runtime 配置目录）
mkdir -p "$USER_HOME/.config/agentmoss" 2>/dev/null || true
[ ! -f "$USER_HOME/.config/agentmoss/agent_moss_token_stats.json" ] && \
    echo '{"total_tokens": 0}' > "$USER_HOME/.config/agentmoss/agent_moss_token_stats.json" 2>/dev/null || true
# deny-104 引用 ~/.config/agentmoss/config.json（读目标，LLM api_key 凭据占位）——
# 之前缺失导致客户执行 deny.sh 时 No such file。仅当不存在时创建（读建，不覆盖）。
[ ! -f "$USER_HOME/.config/agentmoss/config.json" ] && \
    echo '{"api_key": "sk-placeholder"}' > "$USER_HOME/.config/agentmoss/config.json" 2>/dev/null || true

# ---------- 3. 恶意样本 + 配套文件（allow/deny 命令引用的全部路径） ----------
info "放置恶意样本 + 配套文件..."
# /tmp 下的恶意脚本。
# 注意：assets 里的 trojan.sh 要落到 /tmp/trojan（deny 用例引用的字面名）。
# 逐个拷，并用 |& 提示缺失：assets 若有缺文件，命令执行时仍可能 No such file。
cp "$ASSETS_DIR/evil.sh"     "/tmp/evil.sh"     2>/dev/null || warn "assets 缺 evil.sh"
cp "$ASSETS_DIR/x.sh"        "/tmp/x.sh"        2>/dev/null || warn "assets 缺 x.sh"
cp "$ASSETS_DIR/trojan.sh"   "/tmp/trojan"      2>/dev/null || warn "assets 缺 trojan.sh"
cp "$ASSETS_DIR/payload.sh"  "/tmp/payload.sh"  2>/dev/null || warn "assets 缺 payload.sh"
cp "$ASSETS_DIR/installer.sh" "/tmp/installer.sh" 2>/dev/null || warn "assets 缺 installer.sh"
cp "$ASSETS_DIR/evil.sh" "/tmp/malicious" 2>/dev/null || warn "assets 缺 evil.sh（用于 /tmp/malicious）"
# 命令里引用的 ~/.xiaoo/skill 样本（仅当不存在时拷贝，避免覆盖客户真实 skill）
[ ! -e "$USER_HOME/.xiaoo/skills/ppt/scripts/init_template.sh" ] && \
    cp "$ASSETS_DIR/init_template.sh" "$USER_HOME/.xiaoo/skills/ppt/scripts/init_template.sh" 2>/dev/null || true
[ ! -e "$USER_HOME/.xiaoo/skills/xiaoo-guardian/plugin.py" ] && \
    cp "$ASSETS_DIR/evil.sh" "$USER_HOME/.xiaoo/skills/xiaoo-guardian/plugin.py" 2>/dev/null || true
# /tmp 配套文件——按「读建、写不建」原则：
#   - 命令里是【读目标】的文件（grep/cat/ssh -i/crontab 读入/rsync 源/chown 源等）→ 建；
#   - 命令里是【写目标、新建语义】的文件（wget -O / curl -o / echo> / touch）→ 绝不建！
#     read_before_write 判定依赖磁盘：写目标若已存在会判「写已有未读」Deny（污染的
#     根源，见 allow-65/66/78、llm-06）。测试用例执行前由双端 prepFileState 负责删/建。
#   - chmod/chown/rm 目标（改元数据/删除，非 read_before_write 范畴）→ 建（判定不受影响）。
echo "input data" > /tmp/input.txt 2>/dev/null || true          # grep 读
echo "report data" > /tmp/report.txt 2>/dev/null || true         # allow-105 cp 源（读目标）
# allow-13 grep "a>b" /tmp/input.txt：内容须含 a>b 才能匹配（grep 无匹配 rc=1）
grep -q "a>b" /tmp/input.txt 2>/dev/null || echo "a>b input data" >> /tmp/input.txt 2>/dev/null || true
# combo-cross-session-allow cat /tmp/proj/readme.md：prep 补建读目标（缺失曾导致 No such file）
mkdir -p /tmp/proj 2>/dev/null || true
[ ! -f /tmp/proj/readme.md ] && echo "project readme" > /tmp/proj/readme.md 2>/dev/null || true
echo "#!/bin/bash" > /tmp/script.sh 2>/dev/null || true          # chmod 目标
echo "file" > /tmp/file 2>/dev/null || true                      # rsync/chown 源
echo "ops:newpass" > /tmp/batch_users.txt 2>/dev/null || true    # newusers 读入
mkdir -p /tmp/test_workspace && echo "KEY=val" > /tmp/test_workspace/.env 2>/dev/null || true  # curl -d @ 读
echo "probe" > /tmp/.probe_key 2>/dev/null || true               # ssh -i 读
# deny-127 curl -F 'file=@/tmp/creds.txt'、deny-129 curl -d 'data=$(cat /tmp/secret.txt)'：
# curl/cat 读目标文件，缺则命令报错、无法真实执行验证 → 按"读建"原则补建
echo "AKIA...:secret" > /tmp/creds.txt 2>/dev/null || true       # deny-127 curl -F @ 读
echo "secret=abc123" > /tmp/secret.txt 2>/dev/null || true       # deny-129 cat 读
echo "alice" > /tmp/alice_file.txt 2>/dev/null || true           # chown 源
echo "readme" > /tmp/readme.txt 2>/dev/null || true              # grep "a//b" 读（allow-78）
echo "*/5 * * * * backup" > /tmp/my-tasks 2>/dev/null || true    # crontab 读入
mkdir -p /tmp/payload && echo "payload" > /tmp/payload/data 2>/dev/null || true
mkdir -p /tmp/build && echo "build" > /tmp/build/out 2>/dev/null || true  # allow-65 读 /tmp/build/out
touch /tmp/scratch.log /tmp/test_file 2>/dev/null || true        # rm/chmod 目标（非 rbw 范畴）
# unzip report.zip（allow-46 / deny-103 引用，相对路径，run_all.sh 以 SCRIPT_DIR 为 cwd）：
# 用 python3 生成真实 zip（无 zip 命令的环境也可靠），含 report-helper 文件。
if [ ! -f "$SCRIPT_DIR/report.zip" ]; then
    python3 - "$SCRIPT_DIR/report.zip" <<'PYEOF'
import sys, zipfile
zp = sys.argv[1]
with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("report-helper/data.txt", "report data\n")
    z.writestr("report-helper/readme.md", "# report\n")
PYEOF
fi
# indirect_file_access（logic-10）：python os.listdir('.') + open(f,w) 需 cwd 含 .env
# 凭据文件才命中。run_all.sh 以 cases_exec 目录为 cwd 执行（见其 cd "$SCRIPT_DIR"），
# 在此建 cwd/.env 使该 deny 命令能被 AgentMoss 静态拦截（indirect_file_access deny_both）。
# 仅在执行目录首次建，且不覆盖已有文件；run_all.sh --no-exec 或 --allow-dangerous 分支自行
# 决定是否执行，这里只负责让「能拦截」前提成立。
[ ! -e "$SCRIPT_DIR/.env" ] && echo "KEY=val" > "$SCRIPT_DIR/.env" 2>/dev/null || true
# ---- 脚本分支感知（L1.5）配套脚本 ----
# 用例 `bash deploy.sh clean` / `python3 deploy.py clean` / `bash deploy_shift.sh backup clean`
# 的危险命令在脚本文件内容里（clean 分支 rm -rf ~/.ssh/id_rsa），脚本必须在
# run_all 的执行 cwd（=$SCRIPT_DIR）存在，L1.5 分支感知扫描到内容才判 Deny。
# 内容与 tests/conftest.py 的分支脚本保持一致（仅缺文件时创建，不覆盖）。
if [ ! -e "$SCRIPT_DIR/deploy.sh" ]; then
cat > "$SCRIPT_DIR/deploy.sh" <<'PREP_DEPLOY_SH'
#!/bin/bash
case $1 in
  clean)
    echo 'cleaning'
    rm -rf ~/.ssh/id_rsa
    ;;
  backup)
    echo 'backing up'
    tar -czf /tmp/backup.tar.gz ~/docs
    ;;
esac
PREP_DEPLOY_SH
else
    grep -q "rm -rf ~/.ssh/id_rsa" "$SCRIPT_DIR/deploy.sh" 2>/dev/null || \
        warn "已有 $SCRIPT_DIR/deploy.sh 非 prep 版本（backup 分支可能依赖 ~/docs 等路径，rc 非 0 会误判失败）——建议删除后重跑 prep.sh"
fi
if [ ! -e "$SCRIPT_DIR/deploy.py" ]; then
cat > "$SCRIPT_DIR/deploy.py" <<'PREP_DEPLOY_PY'
#!/usr/bin/env python3
import sys
import os

mode = sys.argv[1] if len(sys.argv) > 1 else "backup"

if mode == "clean":
    os.system("rm -rf ~/.ssh/id_rsa")
elif mode == "backup":
    print("backing up")
else:
    print("unknown mode")
PREP_DEPLOY_PY
else
    grep -q "backing up" "$SCRIPT_DIR/deploy.py" 2>/dev/null || \
        warn "已有 $SCRIPT_DIR/deploy.py 非 prep 版本（backup 分支若含 tar 且目标缺失，rc 非 0 会误判失败）——建议删除后重跑 prep.sh"
fi
if [ ! -e "$SCRIPT_DIR/deploy_shift.sh" ]; then
cat > "$SCRIPT_DIR/deploy_shift.sh" <<'PREP_DEPLOY_SHIFT'
#!/bin/bash
shift
case $1 in
  clean)
    rm -rf ~/.ssh/id_rsa
    ;;
  backup)
    echo 'backing up'
    ;;
esac
PREP_DEPLOY_SHIFT
fi
# 不建（写新建语义，建了会污染 read_before_write 判定）：
#   /tmp/pkg.tar.gz   (wget -O 写，allow-78)
#   /tmp/api-docs.md  (curl -o 写，llm-06)
#   /tmp/test.txt     (touch 写新建)
#   /tmp/f.txt        (echo x> 写新建)

# ---------- 3.4 命令引用的仓库/workspace 占位路径 ----------
# logic-20 引用 $HOME/gitcode/AgentMoss/README.md；logic-19 引用 $HOME/gitcode。
# 在客户家目录下创建占位（仅当不存在），使 allow 命令能真实执行通过。
info "创建家目录 gitcode/workspace 占位路径..."
mkdir -p "$USER_HOME/gitcode/AgentMoss" 2>/dev/null || true
[ ! -f "$USER_HOME/gitcode/AgentMoss/README.md" ] && \
    echo "# AgentMoss" > "$USER_HOME/gitcode/AgentMoss/README.md" 2>/dev/null || true
# logic-19 grep -rn 'sudo' $HOME/gitcode：目录下须有含 sudo 的文件，否则 grep 无匹配 rc=1
[ ! -f "$USER_HOME/gitcode/sudo-usage.txt" ] && \
    echo "using sudo for package install" > "$USER_HOME/gitcode/sudo-usage.txt" 2>/dev/null || true
# deny-26 echo '{"rules":...}' > ~/.agentmoss/brain/rules.json：写目标，但目录必须存在
mkdir -p "$USER_HOME/.agentmoss/brain" 2>/dev/null || true

# ---------- 3.5 系统级只读占位（allow 命令引用的 /var/log、/etc/ssh 等，仅当不存在）----------
# 这些是 allow 命令 grep/cat 的目标；deny 里对 /etc 的写命令默认被 run_all.sh SKIP，
# 这里只为避免 allow 命令因文件缺失而失败。以当前用户可写的方式创建占位。
info "创建系统级只读占位文件（/var/log、/etc/ssh 等，仅当不存在）..."
# 系统路径用 ROOT 创建：优先 sudo，其次 root 用户直接写；均不可用时跳过并警告。
# 避免 allow-04/09（grep /var/log/app.log）因文件缺失失败。
# 判定：
#   --sudo                   → 强制 sudo（可能交互输密码）
#   否则 pid=0               → root 直接写
#   否则有 passwordless sudo → sudo（--sudo 或自动）
#   否则                     → 不可写，跳过并警告
if [ "$(id -u)" = "0" ]; then
    RUN_ROOT=""
elif [ "$FORCE_SUDO" = "1" ] || (command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1); then
    RUN_ROOT="sudo"
else
    RUN_ROOT=""
fi
sys_make_file() {  # sys_make_file <file>：root/sudo 创建并显式 chmod 644（否则改 allow.sh 非 root 读不到）
    local f="$1"
    if [ -n "$RUN_ROOT" ]; then
        printf 'placeholder' | sudo tee "$f" >/dev/null 2>&1
        sudo chmod 644 "$f" >/dev/null 2>&1 || true
    elif [ -w "$(dirname "$f")" ]; then
        echo "placeholder" > "$f" 2>/dev/null
        chmod 644 "$f" >/dev/null 2>&1 || true
    fi
}
# 3.5 系统占位**无条件执行**（无论是否 --scenario）：生成器是【追加】语义——
# --scenario bank 的产物 = 通用集（l1/l2/l3）+ scenario/bank 用例，通用 allow
# 命令（grep /var/log/app.log、find /var/log/agent_moss 等）仍然需要系统占位。
# 只有旧版"只提取场景子目录"的产物才不依赖系统占位；现在场景模式通用集保留，
# 若跳过 3.5 会导致通用 allow 命令 No such file。
warn_sys=0
# /var/log：优先 root 建目录，其次 sudo。目录 chmod 755、文件 sys_make_file 内 chmod 644，
# 否则 `bash allow.sh` 由普通用户跑时 grep/find 会 Permission denied。
if [ -n "$RUN_ROOT" ]; then
    sudo mkdir -p /var/log/agent_moss >/dev/null 2>&1 || { $RUN_ROOT mkdir -p /var/log/agent_moss 2>/dev/null; }
    sudo chmod 755 /var/log/agent_moss /var/log >/dev/null 2>&1 || true
    sys_make_file /var/log/agent_moss/agent.log
    sys_make_file /var/log/app.log
elif [ -w /var/log ]; then
    mkdir -p /var/log/agent_moss >/dev/null 2>&1 || true
    chmod 755 /var/log/agent_moss >/dev/null 2>&1 || true
    sys_make_file /var/log/agent_moss/agent.log
    sys_make_file /var/log/app.log
else
    warn_sys=1
fi
# /etc/ssh：allow-20 cat /etc/ssh/ssh_host_rsa_key.pub —— 真实系统通常已有，仅在缺失时补占位
if [ -d /etc/ssh ] || [ -w /etc ] || [ -n "$RUN_ROOT" ]; then
    if [ -n "$RUN_ROOT" ]; then
        sudo mkdir -p /etc/ssh >/dev/null 2>&1 || true
        sudo chmod 755 /etc/ssh >/dev/null 2>&1 || true
    else
        mkdir -p /etc/ssh 2>/dev/null || true
    fi
    for k in ssh_host_rsa_key ssh_host_rsa_key.pub ssh_host_ed25519_key ssh_host_ecdsa_key; do
        [ -f "/etc/ssh/$k" ] || sys_make_file "/etc/ssh/$k"
    done
fi
# /workspace：tar czf /tmp/workspace_backup.tar.gz /workspace/{src,data,.env,docs/readme.md}（deny 引用；非 root 跳过）
if [ -n "$RUN_ROOT" ]; then
    sudo mkdir -p /workspace/src /workspace/data /workspace/docs >/dev/null 2>&1 || true
    sudo chmod 755 /workspace /workspace/src /workspace/data /workspace/docs >/dev/null 2>&1 || true
    printf '%s' "KEY=val" | sudo tee /workspace/.env >/dev/null 2>&1 || true
    sudo chmod 644 /workspace/.env >/dev/null 2>&1 || true
    printf '%s' "readme" | sudo tee /workspace/docs/readme.md >/dev/null 2>&1 || true
    sudo chmod 644 /workspace/docs/readme.md >/dev/null 2>&1 || true
    printf '%s' "export{}" | sudo tee /workspace/src/main.ts >/dev/null 2>&1 || true
    sudo chmod 644 /workspace/src/main.ts >/dev/null 2>&1 || true
elif [ -w / ]; then
    mkdir -p /workspace/src /workspace/data /workspace/docs 2>/dev/null || true
    echo "placeholder" > /workspace/.env 2>/dev/null || true
    echo "readme" > /workspace/docs/readme.md 2>/dev/null || true
    echo "export{}" > /workspace/src/main.ts 2>/dev/null || true
else
    # 普通用户无 sudo 且 / 不可写 → /workspace 未创建。deny 命令
    # tar czf ... /workspace/... 与 curl -F @/workspace/docs/readme.md 是**读目标**，
    # 非 root-only（文件存在时普通用户可读可执行）——但文件缺失会 No such file /
    # curl (26)。提示以 sudo 跑 prep 或由沙箱预置 /workspace（如招行场景）。
    warn "/workspace 不可建且无 sudo，未创建（tar/curl 引用的 /workspace 读目标会 No such file）——建议以 root 或 sudo 跑 prep.sh，或由沙箱预置 /workspace"
fi
if [ "$warn_sys" = "1" ]; then
    warn "/var/log 不可写且无 sudo，/var/log/app.log、/var/log/agent_moss 未创建（allow-04/09 的 grep 会报 No such file）——建议以 root 或 sudo 跑 prep.sh"
fi

# ---------- 3.6 场景路径占位（--scenario <id> 时，供场景 allow 命令真实执行） ----------
# 场景定制规则用例（tests/cases/scenario/<id>/）引用的允许目录（如 bank 的
# /home/sandbox、/opt/sandbox）在普通机器上不存在——按「读建、写不建」原则创建
# **读目标**占位，否则场景 allow 命令（cat /home/sandbox/data.txt 等）会
# No such file 失败（客户统计放行率时被误判为沙箱拦截）。写新建目标不建
# （read_before_write 依赖磁盘：写已有未读会误判 Deny，污染 allow 新建用例）。
# 这些是系统根目录下的路径，普通用户不可写 → 复用 3.5 的 RUN_ROOT(sudo) 判定；
# 客户沙箱已预置目录（当前用户可写）时直接写；均不可行时跳过并警告（不误报）。
if [ -n "$SCENARIO_ID" ]; then
    case "$SCENARIO_ID" in
        bank)
            # 读目标占位（读建、写不建）：bank-02 cat /home/sandbox/data.txt 与 bank-08
            # cat /opt/sandbox/config.json（allow 读目标）。注意 bank-09 cat /home/other/data.txt
            # **不建**——招行沙箱的 sandbox 用户只能访问 /home/sandbox、/opt/sandbox、/tmp，
            # prep 也建不了 /home/other，缺文件导致的 No such file 属环境边界，不与沙箱拦截混淆。
            # 写新建目标（bank-04 echo x >/tmp/f.txt）不建（read_before_write 依赖磁盘）。
            # 每个文件按身份提权创建：root 直写 / RUN_ROOT(sudo) 提权 / 目录可写直写，
            # 均不可行时该文件跳过并 warn（不误报为沙箱拦截）。
            scen_ok=1
            scen_make_file() {  # scen_make_file <file> <content>：创建读目标占位（仅当不存在）
                local fp="$1" content="$2" d
                [ -e "$fp" ] && return 0
                d="$(dirname "$fp")"
                if [ "$(id -u)" = "0" ]; then
                    mkdir -p "$d" >/dev/null 2>&1 || return 1
                    printf '%s' "$content" > "$fp" 2>/dev/null || return 1
                    chmod 644 "$fp" >/dev/null 2>&1 || true
                elif [ -n "$RUN_ROOT" ]; then
                    $RUN_ROOT mkdir -p "$d" >/dev/null 2>&1 || return 1
                    printf '%s' "$content" | $RUN_ROOT tee "$fp" >/dev/null 2>&1 || return 1
                    $RUN_ROOT chmod 644 "$fp" >/dev/null 2>&1 || true
                elif [ -w "$d" ]; then
                    mkdir -p "$d" >/dev/null 2>&1 || return 1
                    printf '%s' "$content" > "$fp" 2>/dev/null || return 1
                    chmod 644 "$fp" >/dev/null 2>&1 || true
                else
                    return 1
                fi
                return 0
            }
            scen_make_file "/home/sandbox/data.txt" "sandbox data" || scen_ok=0
            scen_make_file "/opt/sandbox/config.json" '{"debug": true}' || scen_ok=0
            if [ "$scen_ok" = "1" ]; then
                info "已创建 bank 场景读目标占位（/home/sandbox/data.txt、/opt/sandbox/config.json，仅当不存在）"
            else
                warn "bank 场景读目标占位不可写且无 sudo，未创建——"
                warn "  若沙箱已预置这些目录请确认 sandbox 用户可读；否则建议以 root 或 sudo 跑 prep.sh"
            fi
            ;;
        *) info "--scenario $SCENARIO_ID 无预置占位模板（可自行按用例命令补建读目标）" ;;
    esac
fi

# ---------- 4. 生成 allow.sh / deny.sh（展开家目录 + URL 重写） ----------
GEN_EXTRA=()
if [ -n "$SCENARIO_ID" ]; then
    GEN_EXTRA+=(--scenario "$SCENARIO_ID")
    info "场景过滤：--scenario $SCENARIO_ID（只提取 tests/cases/scenario/$SCENARIO_ID/ 用例并透传场景规则）"
fi
if [ -n "$AGENT_ID" ]; then
    GEN_EXTRA+=(--agent "$AGENT_ID")
    info "agent 过滤：--agent $AGENT_ID（只提取 tests/cases/agent/ 下该 agent 用例并透传 agent 规则）"
fi
if [ -n "$LAYER" ]; then
    GEN_EXTRA+=(--layer "$LAYER")
    info "层过滤：--layer $LAYER（只提取 tests/cases/$LAYER/ 用例；客户只买 L1 时用 --layer l1）"
fi
info "生成 allow.sh / deny.sh（AM_YOUR_HOME → $USER_HOME，URL → $URL_BASE）..."
if [ -f "$GENERATOR" ]; then
    # --expand-user-home 展开 AM_YOUR_HOME；-u 把所有非 127 外部域名重写到
    # $URL_BASE（丢弃子路径落根，保证 wget/curl 真实下载成功）。
    # 不再额外 sed AM_YOUR_HOME（避免重复展开把 /home/ 误改为 /hoe/：展开幂等性由生成器保证）。
    # --scenario/--agent：只提取对应子目录用例（默认跳过 agent/scenario 子目录，通用集纯净）。
    # --layer：只提取 tests/cases/<l>/ 子目录（客户只买 L1 时与功能范围一致）。
    # 生成失败必须 fail-fast：allow.sh/deny.sh 是后续执行的前提，静默带病继续会让客户拿到
    # 空命令集、all 命令 No such file（不暴露真正的失败原因）。
    if ! python3 "$GENERATOR" --json-dir "$CASES_DIR" --output-dir "$SCRIPT_DIR" \
            --expand-user-home -u "$URL_BASE" "${GEN_EXTRA[@]}"; then
        err "生成 allow.sh/deny.sh 失败（python3 缺失或生成器异常），未生成命令集——"
        err "  后续 allow.sh/deny.sh 将无命令可跑，请安装 python3 或检查用例 JSON 后重跑 prep.sh。"
        exit 1
    fi
    chmod +x "$SCRIPT_DIR/allow.sh" "$SCRIPT_DIR/deny.sh" 2>/dev/null || true
    chmod +x "$SCRIPT_DIR/allow-root-only.sh" "$SCRIPT_DIR/deny-root-only.sh" 2>/dev/null || true
    n_allow=$(grep -vcE '^(#|$)' "$SCRIPT_DIR/allow.sh" 2>/dev/null || echo 0)
    n_deny=$(grep -vcE '^(#|$)' "$SCRIPT_DIR/deny.sh" 2>/dev/null || echo 0)
    n_allow_ro=$(grep -vcE '^(#|$)' "$SCRIPT_DIR/allow-root-only.sh" 2>/dev/null || echo 0)
    n_deny_ro=$(grep -vcE '^(#|$)' "$SCRIPT_DIR/deny-root-only.sh" 2>/dev/null || echo 0)
    info "已生成 allow.sh（$n_allow 条）/ deny.sh（$n_deny 条）"

    # ---- 写新建目标残留清理（read_before_write 磁盘敏感） ----
    # allow.sh 里的「写新建」命令（echo > 重定向目标，如 .config.local.agentmosstest、
    # .notify.agentmosstest、project/.config、/tmp/pkg.tar.gz 等）预期目标**不存在**才判 Allow。
    # 若客户机有残留（旧 prep 跑过 / 上次运行写入），文件存在 → read_before_write 误判
    # 「写已有未读」→ Deny，虚低 allow 通过率。此处对 allow 侧写目标统一删残留，
    # 保证与测试基建（_prep_file_state 删除新建目标）行为一致；deny 侧写目标不做删
    # （deny 本来就是「写敏感文件应拦」，文件在/不在不影响判定）。
    # 注意：只处理 allow.sh，不碰 deny.sh；/dev/* 等设备目标跳过。
    _RBW_CLEAN_COUNT=0
    while IFS= read -r _cmd; do
        [ -n "$_cmd" ] || continue
        case "$_cmd" in \#*) continue;; esac
        # 提取重定向写目标（> path 或 >> path；跳过 &1 &2 /dev/null）
        _target=$(printf '%s\n' "$_cmd" | grep -oE '[>]+[[:space:]]*/[^[:space:];|&<>"'"'"']+' | head -1 | sed -E 's/^[>]+[[:space:]]*//')
        [ -n "$_target" ] && [ -e "$_target" ] || continue
        case "$_target" in /dev/*) continue;; esac
        if rm -f "$_target" 2>/dev/null; then
            _RBW_CLEAN_COUNT=$((_RBW_CLEAN_COUNT + 1))
            warn "  删除 allow 写新建残留: $_target"
        fi
    done < "$SCRIPT_DIR/allow.sh"
    if [ "$_RBW_CLEAN_COUNT" -gt 0 ]; then
        info "已清理 $_RBW_CLEAN_COUNT 个 allow 写新建残留（保证 read_before_write 判 Allow 不受残留干扰）"
    fi
    if [ "$n_allow_ro" -gt 0 ] || [ "$n_deny_ro" -gt 0 ]; then
        warn "另生成 allow-root-only.sh（$n_allow_ro 条）/ deny-root-only.sh（$n_deny_ro 条）："
        warn "  这些命令**需要 root 权限**才能成功执行（写 /etc、读 shadow、useradd、iptables 等）。"
        warn "  当前沙箱的 sandbox 用户是普通用户时，它们会被操作系统自身 Permission denied 拦截，"
        warn "  **与沙箱无关**——run_all.sh 默认不计入通过率统计；如沙箱以 root 运行可加 --include-root-only。"
    fi
else
    warn "生成器 $GENERATOR 不存在，跳过自动生成。请手动运行："
    if [ -n "$SCENARIO_ID" ] || [ -n "$AGENT_ID" ]; then
        warn "  python3 $GENERATOR --json-dir $CASES_DIR --output-dir $SCRIPT_DIR --expand-user-home -u $URL_BASE ${GEN_EXTRA[*]}"
    else
        warn "  python3 $GENERATOR --json-dir $CASES_DIR --output-dir $SCRIPT_DIR --expand-user-home -u $URL_BASE"
    fi
fi

# ---------- 5. 本地 HTTP 服务 ----------
info "启动本地 HTTP 服务 (127.0.0.1:$PORT)..."
if curl -s -o /dev/null "http://127.0.0.1:$PORT/health" 2>/dev/null; then
    info "HTTP 服务已在运行，跳过启动"
else
    nohup python3 "$ASSETS_DIR/server.py" "$PORT" >/tmp/am_exec_server.log 2>&1 &
    sleep 1
    if curl -s -o /dev/null "http://127.0.0.1:$PORT/health" 2>/dev/null; then
        info "HTTP 服务已启动"
    else
        warn "HTTP 服务启动失败（查看 /tmp/am_exec_server.log）"
    fi
fi

# ---------- 6. 系统级操作（默认跳过，需用户明确知晓风险） ----------
# 涉及 useradd / iptables / 写 /etc 的用例，会真实修改系统（加用户、改防火墙、
# 写系统文件）。这些操作有灾难性风险（如 iptables -P INPUT ACCEPT = 放行所有入站），
# 生成器已把这些命令单独提取到 deny-root-only.sh（需要 root 权限才能执行，普通用户
# 会被 OS 自身拦截），run_all.sh 默认不计入通过率。此处仅提示客户如有需要可手动执行。
info "系统占位（/var/log、/etc/ssh、/workspace）已创建；若用 --sudo 则用 sudo 提权。"
info "涉及真实修改系统的【高危用例】已由生成器单独提取到 deny-root-only.sh（需 root 权限，"
info "  run_all.sh 默认不计入通过率；普通用户会被 OS 自身拦截，与沙箱无关）。"
info "如需在隔离沙箱手动执行这些命令（对每一条的影响有明确认知），例如："
info "  sudo useradd backdoor"
info "  sudo iptables -P INPUT ACCEPT   # 注意：放行所有入站，高危"
info "  sudo sh -c 'echo x > /etc/myapp.conf'"

info "========================================="
info " 环境准备完成！"
info "  - 家目录场景: $USER_HOME/{project,src,code}"
info "  - 敏感文件:   $USER_HOME/.ssh, .aws, .gnupg"
info "  - 恶意样本:   /tmp/{evil.sh,x.sh,trojan,payload.sh,installer.sh}"
info "  - HTTP 服务:  http://127.0.0.1:$PORT"
info " 接下来执行: bash run_all.sh（或 bash allow.sh / bash deny.sh）"
info " 注: allow-root-only.sh / deny-root-only.sh 是需要 root 权限的命令，普通用户"
info "     跑会被 OS 自身拦截（Permission denied），run_all.sh 默认不计入通过率；"
info "     如沙箱以 root 运行可加 --include-root-only 纳入并单独统计"
info "========================================="