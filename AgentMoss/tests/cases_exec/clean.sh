#!/usr/bin/env bash
# ============================================================================
# clean.sh — 撤销 prep.sh 创建的环境（清理测试产物）
#
# !!! 使用边界与责任声明 !!!
# cases_exec 唯一用途：测试沙箱/AgentMoss 等能力。必须在完全清楚后果的前提下
# 执行（不会因副作用导致财产/信息丢失）。严禁用于其他任何场景。因范围外使用
# 或未充分评估后果导致的任何损失，本项目不承担责任。
#
# !!! 警告 !!!
# 只删除 prep.sh 明确创建/放置的测试产物（/tmp 样本、生成的脚本、HTTP 服务进程）。
# 家目录下的场景文件（~/project、~/src、~/.xiaoo 等）**默认不删除**——
# 因为这些可能是客户已有的真实数据，prep.sh 只在不存在的才创建，无法区分。
# 如需清理家目录测试文件，用 --clean-home 参数（会询问确认）。
#
# 用法：
#   bash clean.sh                # 清理 /tmp 样本 + 生成的脚本 + HTTP 服务 + prep 残留占位
#   bash clean.sh --clean-home   # 额外删除家目录测试场景文件（需确认）
#   bash clean.sh --scenario bank # 额外清理 bank 场景占位（/home/sandbox、/opt/sandbox 读目标）
#   bash clean.sh --yes          # 跳过确认
# ============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ASSETS_DIR="$SCRIPT_DIR/assets"
USER_HOME="$(eval echo ~)"
YES=0
CLEAN_HOME=0
SCENARIO_ID=""
# 单一 while 解析循环（同 run_all.sh 修复）：所有参数在一个循环内用 $1/shift 消费，
# 避免 for 循环遍历 $@ 时 --scenario 的 shift 2 破坏位置参数——否则
# `--clean-home --scenario bank` 时 SCENARIO_ID 会取到 --scenario 自身（错位）。
while [ $# -gt 0 ]; do
    case "$1" in
        --yes) YES=1; shift ;;
        --clean-home) CLEAN_HOME=1; shift ;;
        --scenario) SCENARIO_ID="${2:-}"; shift 2 || shift ;;
        --scenario=*) SCENARIO_ID="${1#*=}"; shift ;;
        *) echo "未知参数: $1（支持 --yes / --clean-home / --scenario <id>）" >&2; shift ;;
    esac
done

warn_p() { echo -e "\033[33m[ clean ] $*\033[0m"; }
info_p() { echo -e "\033[32m[ clean ] $*\033[0m"; }
err_p()  { echo -e "\033[31m[ clean ] $*\033[0m"; }

# ---------- 确认 ----------
if [ "$YES" = "0" ]; then
    echo ""
    echo -e "\033[1;33m============================================================"
    echo "  清理确认"
    echo "============================================================\033[0m"
    warn_p "将删除："
    warn_p "  - /tmp 下的恶意样本（evil.sh x.sh trojan payload.sh installer.sh malicious 等）"
    warn_p "  - /tmp 配套测试文件（input.txt script.sh batch_users.txt 等）"
    warn_p "  - 本地 HTTP 服务进程（127.0.0.1:9090）"
    warn_p "  - cases_exec 下生成的 allow.sh / deny.sh"
    warn_p "  - prep 残留占位（~/.config/agentmoss/config.json、cases_exec credentials/secrets）"
    if [ -n "$SCENARIO_ID" ] || [ -e /home/sandbox/data.txt ] || [ -e /opt/sandbox/config.json ]; then
        warn_p "  - bank 场景占位（/home/sandbox/data.txt、/opt/sandbox/config.json，内容比对后才删）"
    fi
    if [ "$CLEAN_HOME" = "1" ]; then
        err_p "  - 家目录测试场景（~/project ~/src ~/code ~/.xiaoo 等）"
        err_p "    !!! 注意：若这些目录是客户真实数据，将被删除 """
    fi
    read -r -p "[ clean ] 确认清理？[y/N] " ans
    case "$ans" in
        y|Y) info_p "开始清理。" ;;
        *) err_p "已取消。"; exit 1 ;;
    esac
fi

# ---------- 1. 删除 /tmp 恶意样本 ----------
info_p "删除 /tmp 恶意样本..."
for f in evil.sh x.sh trojan payload.sh installer.sh malicious; do
    rm -f "/tmp/$f" 2>/dev/null || true
done

# ---------- 2. 删除 /tmp 配套测试文件 ----------
info_p "删除 /tmp 配套测试文件..."
# 只删 read 目标/元数据目标/恶意样本；写目标（pkg.tar.gz/api-docs.md）也一并删——
# 它们被 allow 下载命令真实写入后会污染 read_before_write 判定（写已有未读）。
for f in input.txt test.txt script.sh file batch_users.txt .probe_key \
         alice_file.txt readme.txt my-tasks f.txt api \
         pkg.tar.gz api-docs.md scratch.log test_file; do
    rm -f "/tmp/$f" 2>/dev/null || true
done
rm -rf /tmp/test_workspace /tmp/payload /tmp/build 2>/dev/null || true

# ---------- 3. 停止本地 HTTP 服务 ----------
info_p "停止本地 HTTP 服务..."
# 找到 server.py 进程并终止
pkill -f "server.py" 2>/dev/null && info_p "  HTTP 服务已停止" || warn_p "  未找到 HTTP 服务进程"

# ---------- 3.5 删除 allow 写新建残留（read_before_write 磁盘敏感，与 prep.sh 对称） ----------
# allow.sh 里的「写新建」命令（echo > 重定向目标，如 .config.local.agentmosstest、
# project/.config、/tmp/pkg.tar.gz 等）若残留（上次真执行写入），会让 read_before_write
# 误判「写已有未读」→ Deny，虚低 allow 通过率。clean.sh 与 prep.sh 都清理它，保证
# 二次 prep→run_all 时判定可复现。只删 allow 侧写目标；内容校验（agentmosstest 标记 +
# 已知测试占位内容）避免误删客户真实项目文件。deny 侧写目标不删（deny 本来就拦）。
# 注意：此节在「删 allow.sh」（第 4 节）之前的执行到这里 allow.sh 仍然存在，可扫描；
# 若 allow.sh 不存在（没跑过 prep/生成器），则按已知测试文件名单兜底清理。
_rbw_is_test_target() {  # 判定目标是否测试产生的写新建残留（防误删客户真实文件）
    [ "$1" != "${1%%.agentmosstest}" ] && return 0   # 带 .agentmosstest 标记
    case "$(cat "$1" 2>/dev/null | tr -d '\n\r')" in
        "debug=true"|"build done"|"KEY=val") return 0 ;;  # 已知占位内容
    esac
    return 1
}
info_p "删除 allow 写新建残留（read_before_write 对准）..."
_rbw_del=0
if [ -f "$SCRIPT_DIR/allow.sh" ]; then
    while IFS= read -r _cmd; do
        [ -n "$_cmd" ] || continue
        case "$_cmd" in \#*) continue;; esac
        _target=$(printf '%s\n' "$_cmd" | grep -oE '[>]+[[:space:]]*/[^[:space:];|&<>"'"'"']+' | head -1 | sed -E 's/^[>]+[[:space:]]*//')
        [ -n "$_target" ] && [ -e "$_target" ] || continue
        case "$_target" in /dev/*) continue;; esac
        if _rbw_is_test_target "$_target"; then
            rm -f "$_target" 2>/dev/null && { info_p "  已删除写新建残留: $_target"; _rbw_del=$((_rbw_del + 1)); }
        else
            warn_p "  $_target 存在但非测试占位内容，跳过（疑似客户真实文件）"
        fi
    done < "$SCRIPT_DIR/allow.sh"
else
    # 兜底：无 allow.sh 时按已知写新建目标名单清理（与生成器/用例对齐）
    for _t in "$USER_HOME/project/.config.local.agentmosstest" \
              "$USER_HOME/project/.notify.agentmosstest" \
              "$USER_HOME/project/.config" \
              /tmp/pkg.tar.gz /tmp/api-docs.md; do
        [ -e "$_t" ] || continue
        if _rbw_is_test_target "$_t" || [ "${_t##*.}" = "tar.gz" ]; then
            rm -f "$_t" 2>/dev/null && { info_p "  已删除写新建残留: $_t"; _rbw_del=$((_rbw_del + 1)); }
        fi
    done
fi
[ "$_rbw_del" -gt 0 ] && info_p "清理 $_rbw_del 个 allow 写新建残留" || info_p "无 allow 写新建残留"

# ---------- 4. 删除生成的 allow.sh / deny.sh（含 root-only / needs-context 伴随文件） ----------
info_p "删除生成的 allow.sh / deny.sh / *-root-only.sh / deny-needs-context.sh..."
rm -f "$SCRIPT_DIR/allow.sh" "$SCRIPT_DIR/deny.sh" \
      "$SCRIPT_DIR/allow-root-only.sh" "$SCRIPT_DIR/deny-root-only.sh" \
      "$SCRIPT_DIR/deny-needs-context.sh" 2>/dev/null || true

# ---------- 5. 删除系统占位（/var/log、/etc/ssh、/workspace 等，prep --sudo 创建） ----------
# 只在内容匹配 prep 占位模板时才删，避免误删真实系统文件。--sudo 用 sudo 提权删。
info_p "删除系统占位文件（/var/log、/etc/ssh、/workspace 等，prep 创建）..."
is_placeholder() {  # is_placeholder <file>：prep.sh / assets/home 实际写入的占位内容
    local f="$1" content
    content="$(cat "$f" 2>/dev/null | tr -d '\n' | tr -d '\r')"
    case "$content" in
        "placeholder"|"app log"|"agent log"|"TESTHOSTKEY"|"TESTHOSTPUB"|"KEY=val"|"export{}"|"readme"|"malicious"|"env VAR=value"|"note content"|"debug: true"|"export const app = 1;"|"TODO: fix bug"|"debug=false"|"debug=true"|"build done"|"secret: placeholder"|"sandbox data"|'{"debug": true}'|'{"api_key": "sk-placeholder"}') return 0 ;;
        # L1.5 脚本分支感知占位（deploy.sh / deploy.py / deploy_shift.sh）：
        # prep.sh 在 cases_exec 下创建，内容是 conftest 的分支脚本（含 rm -rf ~/.ssh/id_rsa clean 分支）。
        *"rm -rf ~/.ssh/id_rsa"*) return 0 ;;
        *) return 1 ;;
    esac
}
sys_rm() {  # sys_rm <file|dir>
    local target="$1"
    if [ "$(id -u)" = "0" ]; then
        rm -rf "$target" 2>/dev/null || true
    elif command -v sudo >/dev/null 2>&1; then
        [ -e "$target" ] && sudo rm -rf "$target" 2>/dev/null || true
    fi
}
for f in /var/log/app.log /var/log/agent_moss/agent.log /var/log/agent_moss; do
    [ -e "$f" ] || continue
    if [ -f "$f" ]; then
        if is_placeholder "$f"; then
            sys_rm "$f" && info_p "  已删除 $f（占位）" || warn_p "  $f 删除失败（可能需要 sudo）"
        else
            warn_p "  $f 非占位内容，跳过"
        fi
    else
        # 目录：仅当为空（清理占位文件后）才删，避免误删沙箱预置的真实 `agent_moss` 日志目录。
        if [ -z "$(ls -A "$f" 2>/dev/null)" ]; then
            sys_rm "$f" && info_p "  已删除空目录 $f" || warn_p "  $f 删除失败（可能需要 sudo）"
        else
            warn_p "  $f 非空（可能含真实数据或已被清理后新增），保留"
        fi
    fi
done
for f in /etc/ssh/ssh_host_rsa_key /etc/ssh/ssh_host_rsa_key.pub \
         /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_ecdsa_key; do
    [ -f "$f" ] || continue
    is_placeholder "$f" && sys_rm "$f" && info_p "  已删除 $f（占位）" || warn_p "  $f 非占位内容，跳过"
done
for f in /workspace/.env /workspace/docs/readme.md /workspace/src/main.ts /workspace; do
    if [ -d "$f" ] && [ "$f" = "/workspace" ]; then
        # 仅当 workspace 里都是 prep 占位内容或空时才删
        if find /workspace -type f -exec sh -c 'for x; do case "$(cat "$x" 2>/dev/null | tr -d "\n\r")" in placeholder|"KEY=val"|export{}|readme) : ;; *) exit 1;; esac; done' sh {} + 2>/dev/null; then
            sys_rm /workspace; info_p "  已删除 /workspace（占位）"
        else
            warn_p "  /workspace 含非占位内容，跳过"
        fi
    fi
done

# ---------- 5.5 通用残留：prep 建的 ~/.config/agentmoss/config.json 与 cases_exec 凭据占位 ----------
# 这些是 prep.sh 明确创建的占位（读目标），之前 clean 漏删，残留会污染后续真实运行
# （config.json 是 AgentMoss runtime 配置路径，占位 api_key 会干扰 LLM/L3 判定）。
# content 比对后才删（is_placeholder），只删占位、不误删真实凭据/配置。
info_p "删除 prep 残留占位（~/.config/agentmoss/config.json、cases_exec credentials/secrets）..."
if [ -f "$USER_HOME/.config/agentmoss/config.json" ]; then
    if is_placeholder "$USER_HOME/.config/agentmoss/config.json"; then
        rm -f "$USER_HOME/.config/agentmoss/config.json" 2>/dev/null && info_p "  已删除 ~/.config/agentmoss/config.json（占位）" \
            || warn_p "  ~/.config/agentmoss/config.json 删除失败"
    else
        warn_p "  ~/.config/agentmoss/config.json 非占位内容（真实配置？），跳过"
    fi
    # 若该目录已空（占位都清完）则移除空目录；非空保留（可能含真实 AgentMoss 配置）
    if [ -d "$USER_HOME/.config/agentmoss" ] && [ -z "$(ls -A "$USER_HOME/.config/agentmoss" 2>/dev/null)" ]; then
        rmdir "$USER_HOME/.config/agentmoss" 2>/dev/null || true
        rmdir "$USER_HOME/.config" 2>/dev/null || true
    fi
fi
for cf in credentials.yml credentials.yaml secrets.yml secrets.yaml; do
    if [ -f "$SCRIPT_DIR/$cf" ]; then
        if is_placeholder "$SCRIPT_DIR/$cf"; then
            rm -f "$SCRIPT_DIR/$cf" 2>/dev/null && info_p "  已删除 $SCRIPT_DIR/$cf（占位）" || true
        else
            warn_p "  $SCRIPT_DIR/$cf 非占位内容，跳过"
        fi
    fi
done

# ---------- 5.6 场景占位（--scenario bank 时 prep 3.6 创建）：content 比对后才删 ----------
# /home/sandbox 可能是客户沙箱用户家目录、/opt/sandbox 是允许目录——只删 prep 建的占位
# 文件（is_placeholder），空目录才 rmdir，绝不递归删目录，防止误删客户真实数据。
# 注：bank-09 的 /home/other **不在** sandbox 用户可访问范围内，prep 不创建，此处也不处理。
info_p "删除场景占位（bank：/home/sandbox、/opt/sandbox 读目标占位）..."
for f in /home/sandbox/data.txt /opt/sandbox/config.json; do
    [ -e "$f" ] || continue
    if is_placeholder "$f"; then
        # 优先普通 rm（招行场景下文件由 sandbox 用户可写目录直建、归属自己）；
        # 失败（root/sudo 建的文件）再走 sys_rm 提权删。
        if rm -f "$f" 2>/dev/null; then
            info_p "  已删除 $f（占位）"
        else
            sys_rm "$f" && info_p "  已删除 $f（占位）" || warn_p "  $f 删除失败（可能需要 sudo）"
        fi
    else
        warn_p "  $f 非占位内容，跳过"
    fi
done
for d in /home/sandbox /opt/sandbox; do
    [ -d "$d" ] || continue
    if [ -z "$(ls -A "$d" 2>/dev/null)" ]; then
        rmdir "$d" 2>/dev/null || { command -v sudo >/dev/null 2>&1 && sudo rmdir "$d" 2>/dev/null; } || true
    fi
done

# ---------- 6. 删除生成的 agent_moss_token_stats.json（prep 占位） ----------
[ -f "$USER_HOME/.config/agentmoss/agent_moss_token_stats.json" ] && \
    grep -q '"total_tokens"' "$USER_HOME/.config/agentmoss/agent_moss_token_stats.json" 2>/dev/null && { \
    rm -f "$USER_HOME/.config/agentmoss/agent_moss_token_stats.json" 2>/dev/null || true
    info_p "  已删除 ~/.config/agentmoss/agent_moss_token_stats.json（占位）"; }

# ---------- 7. 删除 prep 从 assets/home 拷贝的敏感占位（diff 比对确保只删测试文件） ----------
# prep.sh 的占位都来自 assets/home/；clean --clean-home 时用 diff 逐文件与 assets
# 比对，完全一致才删——不匹配说明是客户真实文件，保留并提示。
clean_home_placeholder() {  # clean_home_placeholder <相对路径相对 $USER_HOME> <assets 相对路径> <描述>
    local dest="$USER_HOME/$1" src="$ASSETS_DIR/home/$2" desc="$3"
    [ -e "$dest" ] || return
    if [ -f "$src" ] && diff -q "$dest" "$src" >/dev/null 2>&1; then
        rm -f "$dest" 2>/dev/null && info_p "  已删除 $desc（占位，与 assets 一致）" || warn_p "  $desc 删除失败"
    else
        warn_p "  $desc 内容与 prep 占位不一致，可能是真实文件，跳过"
    fi
}
if [ "$CLEAN_HOME" = "1" ]; then
    # 家目录场景目录（~/project ~/src ~/code）——prep 只在空/不存在时建，里面只有 prep
    # 场景文件，路径符合 prep 已知清单即删；不强校验内容（避免换行/引号差异误判）。
    # 若目录里有 prep 清单外的文件（客户真实数据），跳过整个目录。
    info_p "清理家目录场景目录（~/project ~/src ~/code ~/docs，路径校验后删）..."
    for d in project src code docs; do
        dir="$USER_HOME/$d"
        [ -d "$dir" ] || continue
        # 允许的路径集合（prep 创建）
        case "$d" in
            project) allowed="build.py config.toml" ;;
            src)     allowed="app.ts" ;;
            code)    allowed="todo.txt" ;;
            docs)    allowed="readme.md" ;;
        esac
        scenario_ok=1
        while IFS= read -r p; do
            rel="${p#"$dir"/}"
            case " $allowed " in
                *" $rel "*) : ;;
                *) scenario_ok=0; break ;;
            esac
        done < <(find "$dir" -maxdepth 1 -type f 2>/dev/null)
        # 也检查子目录里有没有额外文件（prep 场景无子目录内容）
        if find "$dir" -mindepth 2 -type f 2>/dev/null | grep -q .; then scenario_ok=0; fi
        if [ "$scenario_ok" = "1" ]; then
            rm -rf "$dir" 2>/dev/null && info_p "  已删除 $dir（场景，仅含 prep 文件）" || warn_p "  $dir 删除失败"
        else
            warn_p "  $dir 含 prep 清单外文件，跳过（不误删客户数据）"
        fi
    done
    # 家目录散落场景文件（~/note.txt ~/app.ts，内容比对）
    for f in note.txt app.ts; do
        [ -f "$USER_HOME/$f" ] || continue
        is_placeholder "$USER_HOME/$f" && { rm -f "$USER_HOME/$f" && info_p "  已删除 ~/$f（占位）"; } || warn_p "  ~/$f 非占位，跳过"
    done
    # config.yaml（prep 为 allow-64 在 cases_exec 下创建）
    [ -f "$SCRIPT_DIR/config.yaml" ] && is_placeholder "$SCRIPT_DIR/config.yaml" && { \
        rm -f "$SCRIPT_DIR/config.yaml" && info_p "  已删除 $SCRIPT_DIR/config.yaml（占位）"; }
    # .env（prep 为 indirect_file_access（logic-10）在 cases_exec 下创建）
    [ -f "$SCRIPT_DIR/.env" ] && is_placeholder "$SCRIPT_DIR/.env" && { \
        rm -f "$SCRIPT_DIR/.env" && info_p "  已删除 $SCRIPT_DIR/.env（占位）"; }
    # deploy.sh / deploy.py / deploy_shift.sh（prep 为 L1.5 脚本分支感知用例在 cases_exec 创建）
    for _f in deploy.sh deploy.py deploy_shift.sh; do
        [ -f "$SCRIPT_DIR/$_f" ] && is_placeholder "$SCRIPT_DIR/$_f" && { \
            rm -f "$SCRIPT_DIR/$_f" && info_p "  已删除 $SCRIPT_DIR/$_f（占位）"; }
    done
    # gitcode/AgentMoss/README.md 占位
    [ -f "$USER_HOME/gitcode/AgentMoss/README.md" ] && \
        [ "$(cat "$USER_HOME/gitcode/AgentMoss/README.md" 2>/dev/null)" = "# AgentMoss" ] && { \
        rm -f "$USER_HOME/gitcode/AgentMoss/README.md" && info_p "  已删除 ~/gitcode/AgentMoss/README.md（占位）"; }
    # .ssh / .aws / .gnupg 敏感占位（diff 比对 assets/home 确定是测试文件）
    info_p "清理 prep 放置的敏感占位（与 assets/home 逐文件比对后才删）..."
    clean_home_placeholder .ssh/id_rsa .ssh/id_rsa "(~/.ssh/id_rsa)"
    clean_home_placeholder .ssh/id_rsa.pub .ssh/id_rsa.pub "(~/.ssh/id_rsa.pub)"
    clean_home_placeholder .ssh/id_ed25519 .ssh/id_ed25519 "(~/.ssh/id_ed25519)"
    clean_home_placeholder .ssh/id_ed25519.pub .ssh/id_ed25519.pub "(~/.ssh/id_ed25519.pub)"
    clean_home_placeholder .ssh/authorized_keys .ssh/authorized_keys "(~/.ssh/authorized_keys)"
    clean_home_placeholder .aws/credentials .aws/credentials "(~/.aws/credentials)"
    clean_home_placeholder .aws/other .aws/other "(~/.aws/other)"
    clean_home_placeholder .gnupg/trust.txt .gnupg/trust.txt "(~/.gnupg/trust.txt)"
    clean_home_placeholder .gitconfig .gitconfig "(~/.gitconfig)"
    clean_home_placeholder .bashrc .bashrc "(~/.bashrc)"
    clean_home_placeholder .bash_profile .bash_profile "(~/.bash_profile)"
    clean_home_placeholder .profile .profile "(~/.profile)"
    clean_home_placeholder note.txt note.txt "(~/note.txt)"
    # allow-02 专门占位 ~/xiaoo.env（assets 里无同名文件，按内容判断）
    if [ -f "$USER_HOME/xiaoo.env" ]; then
        if is_placeholder "$USER_HOME/xiaoo.env"; then rm -f "$USER_HOME/xiaoo.env" && info_p "  已删除 ~/xiaoo.env（占位）"; fi
    fi
    if [ -f "$USER_HOME/.xiaoo.env" ]; then
        if is_placeholder "$USER_HOME/.xiaoo.env"; then rm -f "$USER_HOME/.xiaoo.env" && info_p "  已删除 ~/.xiaoo.env（占位）"; fi
    fi
    # skill 样本（assets 拷贝，diff 比对）
    clean_home_placeholder .xiaoo/skills/xiaoo-guardian/plugin.py .xiaoo/skills/xiaoo-guardian/plugin.py "(skill plugin.py)"
    # ppt skill 的 init_template.sh（assets 根目录，不在 home/ 下）
    clean_home_placeholder .xiaoo/skills/ppt/scripts/init_template.sh ../init_template.sh "(skill init_template.sh)"
    # 清理 prep 建的占位目录——仅当已为空目录（删文件后无内容）才移除，非空保留
    info_p "清理 prep 创建的空目录（~/.ssh ~/.aws ~/.gnupg ~/.xiaoo ~/.config ~/gitcode）..."
    for d in .ssh .aws .gnupg \
             .xiaoo/skills/ppt/scripts .xiaoo/skills/ppt .xiaoo/skills/xiaoo-guardian .xiaoo/skills .xiaoo \
             .config/agentmoss .config gitcode/AgentMoss gitcode; do
        dir="$USER_HOME/$d"
        [ -d "$dir" ] || continue
        if [ -z "$(ls -A "$dir" 2>/dev/null)" ]; then
            rmdir "$dir" 2>/dev/null && info_p "  已删除空目录 $dir" || true
        else
            warn_p "  $dir 非空，保留（可能含客户数据）"
        fi
    done
    warn_p "敏感占位（~/.ssh/.aws/.gnupg 等）已按 assets 比对清理；其余文件若内容不同是真实数据，未删。"
fi

info_p "========================================="
info_p " 清理完成！"
info_p "  - /tmp 恶意样本：已删除"
info_p "  - HTTP 服务：已停止"
info_p "  - 生成的 allow.sh/deny.sh：已删除"
info_p "  - prep 残留占位（config.json / credentials / bank 场景读目标）：已清理"
if [ "$CLEAN_HOME" = "1" ]; then
    info_p "  - 家目录测试场景：已删除"
else
    info_p "  - 家目录测试场景：保留（用 --clean-home 清理，自担风险）"
fi
info_p "========================================="