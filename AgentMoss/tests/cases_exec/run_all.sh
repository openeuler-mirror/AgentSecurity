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
#   bash run_all.sh --include-root-only      # 把 *-root-only.sh（需 root 权限的命令）也纳入执行与统计
#   bash run_all.sh --layer l1              # 只提取/统计 tests/cases/l1/ 用例（客户只买 L1 时用）
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
#   - allow-root-only.sh / deny-root-only.sh：**需要 root 权限**才能成功执行的命令。
#     普通用户（如客户沙箱的 sandbox 用户）执行时被操作系统自身 Permission denied
#     拦截，与沙箱无关——默认**排除**，不计入通过率统计（避免把 OS 拦截误算成
#     沙箱拦截）。加 --include-root-only 才纳入执行，并作为独立标签单独统计。
#
# 输出：
#   - 每条命令的执行结果（成功/失败/跳过）
#   - 汇总：allow 通过率、deny 通过率、总通过率
# ============================================================================
set -uo pipefail

# 工具函数（提前定义：参数解析/生成校验/确认环节都要用。原来定义在靠后位置，
# 生成失败路径 L183 先调用 err_p 会 "command not found" 静默失败——挪到这里）。
warn_p() { echo -e "\033[33m[ warn ] $*\033[0m"; }
err_p()  { echo -e "\033[31m[ error ] $*\033[0m"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NO_EXEC=0
YES=0
INCLUDE_ROOT_ONLY=0
SCENARIO_ID=""
AGENT_ID=""
LAYER=""
ALLOW_DANGEROUS=0
RUN_FORK_BOMB=0
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
        --scenario) want_arg=true; parse_arg "$1" "${2:-}"; SCENARIO_ID="$ARG"; shift "$SHIFT";;
        --scenario=*) SCENARIO_ID="${1#*=}"; shift ;;
        --agent) want_arg=true; parse_arg "$1" "${2:-}"; AGENT_ID="$ARG"; shift "$SHIFT";;
        --agent=*) AGENT_ID="${1#*=}"; shift ;;
        --layer) want_arg=true; parse_arg "$1" "${2:-}"; LAYER="$ARG"; shift "$SHIFT";;
        --layer=*) LAYER="${1#*=}"; shift ;;
        *) echo "未知参数: $1（支持 --no-exec / --yes / --include-root-only / --allow-dangerous / --run-fork-bomb / --scenario <id> / --agent <id> / --layer l1|l2|l3）" >&2; shift ;;
    esac
done

# 颜色
PASS_COLOR="\033[32m"; FAIL_COLOR="\033[31m"; WARN_COLOR="\033[33m"; RESET="\033[0m"

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

run_cmds() {
    local file="$1" label="$2"
    local total=0 pass=0 fail=0 skip=0 cn=0 line_no=0 seq_no=0
    echo ""
    echo "========== $label ($(basename "$file")) =========="
    while IFS= read -r cmd; do
        line_no=$((line_no + 1))   # 文件真实行号（含空行/注释行）
        # 跳过空行与注释行（生成脚本头部的 #! 与 # 说明）
        [ -z "$cmd" ] && continue
        case "$cmd" in \#*) continue;; esac
        seq_no=$((seq_no + 1))     # 有效命令序号（仅非空非注释命令计数）
        total=$((total + 1))
        if [ "$NO_EXEC" = "1" ]; then
            echo -e "${PASS_COLOR}[dry-run]${RESET} [L${line_no}#${seq_no}] $cmd"
            pass=$((pass + 1))
            continue
        fi
        # fork bomb 防护（置于 allow-dangerous 判定【之前】：即使 --allow-dangerous，
        # fork bomb 也默认 SKIP——只有 --run-fork-bomb 这一个开关能放行，且对
        # allow/deny 全集合生效，不依赖命令属于哪一类）。fork bomb 一旦执行，
        # timeout 杀不掉残留子进程（实测杀父后残留进程继续 fork），延迟爆发打爆
        # 容器 CPU/内存/进程数，导致 k8s pod 被 SIGKILL（exit 137）重启、沙箱数据
        # 重置（客户沙箱已多次实测中招）。is_fork_bomb 用宽模式匹配（见函数定义），
        # 覆盖 `:(){ :|:& };:` / `function f() { f | f & }; f` 等函数自复制变体。
        if is_fork_bomb "$cmd"; then
            if [ "$RUN_FORK_BOMB" = "0" ]; then
                echo -e "${WARN_COLOR}[SKIP fork bomb-需显式 --run-fork-bomb 才真执行]${RESET} [L${line_no}#${seq_no}] $cmd"
                skip=$((skip + 1))
                continue
            fi
        fi
        # 高危命令防护：deny.sh / deny-root-only.sh 默认全部 SKIP（不真执行恶意命令），
        # 除非 --allow-dangerous（需隔离沙箱 + 自担风险）。allow 类全真执行。
        if { [ "$label" = "Deny" ] || [ "$label" = "Deny-root-only" ]; } && \
           [ "$ALLOW_DANGEROUS" = "0" ]; then
            echo -e "${WARN_COLOR}[SKIP 高危-恶意命令]${RESET} [L${line_no}#${seq_no}] $cmd"
            skip=$((skip + 1))
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
            echo -e "${PASS_COLOR}[PASS]${RESET} [L${line_no}#${seq_no}] $cmd"
            pass=$((pass + 1))
        else
            rc=$?
            # command not found（rc=127，软件缺失如 crontab/docker/wget/nginx/php 等）：
            # 属客户环境差异，非命令本身失败——不计入总数/失败数，仅 warning，
            # 结束后统一说明（避免软件缺失拉低通过率、误导为沙箱拦截）。
            if [ "$rc" = "127" ]; then
                cn=$((cn + 1))
                total=$((total - 1))
                echo -e "${WARN_COLOR}[SKIP 命令不存在 rc=127]${RESET} [L${line_no}#${seq_no}] $cmd"
            else
                echo -e "${FAIL_COLOR}[FAIL rc=$rc]${RESET} [L${line_no}#${seq_no}] $cmd"
                # 打印具体错误（前 2 行）——区分「沙箱/OS 拦截」（Permission denied 等）
                # 与「命令自身问题」（No such file / invalid input 等），否则客户只看
                # rc 码无法判断失败原因。文件每次执行覆盖，读到的正是本条命令的输出。
                head -2 /tmp/am_exec_out.$$ 2>/dev/null | sed 's/^/    /'
                fail=$((fail + 1))
            fi
        fi
    done < "$file"
    echo ""
    echo "---- $label 结果：$pass 通过 / $total 总（失败 $fail，高危跳过 $skip，命令不存在 $cn）----"
    # 阶段完成，立即持久化汇总（防止后续 deny 阶段把系统跑挂时 allow 结果丢失）。
    echo "$label $pass $total $fail $skip $cn" > "/tmp/am_exec_summary.$$"
    echo "$label $pass $total $fail $skip $cn" >> "/tmp/am_exec_summary_all.$$"
}

# 生成 allow.sh / deny.sh（若不存在）
if [ ! -f "$SCRIPT_DIR/allow.sh" ] || [ "$NO_EXEC" = "1" ]; then
    # 生成器：唯一来源是 cases_exec 同目录（随 tests 分发；仓库 scripts/ 冗余副本已删）
    GENERATOR="$SCRIPT_DIR/generate_bash_exc.py"
    if [ -f "$GENERATOR" ]; then
        CASES_DIR="$(cd "$SCRIPT_DIR/.." && pwd)/cases"
        # 与 prep.sh 保持一致：展开 AM_YOUR_HOME + 把所有非 127 外部域名重写到真实有效域
        # （默认 https://www.example.com，可用 AM_EXEC_URL_BASE 覆盖）。不再额外 sed
        # AM_YOUR_HOME——避免重复展开把 /home/ 误改为 /hoe/。
        # --scenario/--agent：在通用集基础上【追加】对应子目录用例（默认不指定时
        # 跳过 agent/scenario 子目录；指定时通用 l1/l2/l3 用例保留、追加对应子目录）。
        # --layer：只提取 tests/cases/<l>/ 子目录（客户只买 L1 时交付物只含 L1 用例）。
        URL_BASE="${AM_EXEC_URL_BASE:-https://www.example.com}"
        GEN_EXTRA=()
        if [ -n "$SCENARIO_ID" ]; then GEN_EXTRA+=(--scenario "$SCENARIO_ID"); fi
        if [ -n "$AGENT_ID" ]; then GEN_EXTRA+=(--agent "$AGENT_ID"); fi
        if [ -n "$LAYER" ]; then GEN_EXTRA+=(--layer "$LAYER"); fi
        # --layer 校验在生成器内做（未知层名启动即报错 fail-fast）。
        python3 "$GENERATOR" --json-dir "$CASES_DIR" --output-dir "$SCRIPT_DIR" \
            --expand-user-home -u "$URL_BASE" "${GEN_EXTRA[@]}" >/dev/null 2>&1
    fi
    # 生成失败必须 fail-fast：allow.sh/deny.sh 是执行统计的唯一输入，静默带病继续会让
    # 客户跑完统计全为 0 且不明原因（python3 缺失 / 用例 JSON 异常）。提示用 prep.sh 重跑。
    if [ ! -f "$SCRIPT_DIR/allow.sh" ]; then
        err_p "生成 allow.sh/deny.sh 失败（python3 缺失或生成器异常），没有命令集可执行——"
        err_p "  请安装 python3 后重跑：bash prep.sh（或直接重跑 run_all.sh）。"
        exit 1
    fi
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
else
    warn_p "高危命令默认【跳过】不执行（标记 SKIP），避免破坏系统。"
    warn_p "如需真执行高危命令（自担风险），加 --allow-dangerous，且必须在隔离沙箱。"
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

# 最终汇总（阶段结果已实时打印 + 落盘；若中途崩溃此处不执行，但每个阶段完成时
# 汇总已打印并持久化到 /tmp/am_exec_summary_all.$$，不丢失）
ALLOW_LINE=$(grep "^Allow " "/tmp/am_exec_summary_all.$$" 2>/dev/null | tail -1)
DENY_LINE=$(grep "^Deny " "/tmp/am_exec_summary_all.$$" 2>/dev/null | tail -1)
ALLOW_RO_LINE=$(grep "^Allow-root-only " "/tmp/am_exec_summary_all.$$" 2>/dev/null | tail -1)
DENY_RO_LINE=$(grep "^Deny-root-only " "/tmp/am_exec_summary_all.$$" 2>/dev/null | tail -1)
echo ""
echo "========================================="
echo "  通过率汇总"
echo "========================================="
echo "  Allow: $(echo "$ALLOW_LINE" | awk -v p="Allow" '$1=="Allow"{print $2" 通过 / "$3" 总（失败 "$4"，命令不存在 "$6"）"}')"
echo "  Deny:  $(echo "$DENY_LINE" | awk -v p="Deny" '$1=="Deny"{print $2" 通过 / "$3" 总（失败 "$4"，命令不存在 "$6"）"}')"
if [ -n "$ALLOW_RO_LINE" ]; then
    echo "  Allow-root-only（需 root，单独统计）: $(echo "$ALLOW_RO_LINE" | awk '$1=="Allow-root-only"{print $2" 通过 / "$3" 总（失败 "$4"，命令不存在 "$6"）"}')"
fi
if [ -n "$DENY_RO_LINE" ]; then
    echo "  Deny-root-only（需 root，单独统计）: $(echo "$DENY_RO_LINE" | awk '$1=="Deny-root-only"{print $2" 通过 / "$3" 总（失败 "$4"，命令不存在 "$6"）"}')"
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