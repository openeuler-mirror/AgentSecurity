"""cases_exec 工具链冒烟看护（**全程不执行任何真实 allow/deny 命令**）。

覆盖两类"只有真跑才会暴露"的坑：

1. **警告文案里的命令替换**：run_all.sh 的警告文案若把示例命令写进**双引号内的反引号**，
   bash 会当成命令替换**真的执行它**——`while true; do :; done` 会当场死循环卡死脚本
   （2026-09 实际踩到：`--allow-dangerous` 分支挂死 + 单核 105% CPU，ps 里只看到
   `bash run_all.sh` 子进程，根因是命令替换 fork 出的子 shell 继承了同一 argv）。
   与历史修复 5ee8e69（fork bomb 文案同样问题）同类。→ 静态 lint + 分支冒烟双保险。

2. **宽模式匹配器行为**：`is_fork_bomb` / `is_resource_abuse` 是"保护测试机的安全网"，
   只能**过窄**（漏跳 → 真执行打爆测试机）或**过宽**（误跳 → 白丢覆盖 + 假 FAIL）。
   这里用「命中表 + 防误伤表」双向锁死（对齐用例的"一拦一放"原则）。

3. **命令集模式串台**：执行模式要「URL 重写开」的可执行集，判定模式（--use-agentmoss）要
   「URL 重写关」的原始集——沿用错了会**静默误判**（2026-09-22 实测 227 条里错 3 条）。
   `gen_rewrite_args` / `cmdset_needs_regen` 用决策表锁死，生成器产物另做断言。

4. **剔除 allow 命令必须报出来**：生成命令集时会展开 `AM_YOUR_HOME`，而场景白名单是写死的
   （bank 只认 /home/sandbox）——家目录不在白名单的机器会少几条命令，**条数随环境变**
   （2026-09 客户实测 x86 112 / ARM 106，被误当成「区分架构」）。剔除逻辑本身正确，
   静默才是 bug。这里锁死「必须报出条数 + 家目录成因 + 不可比提醒」。

冒烟用**空命令集**（allow.sh/deny.sh 都是空文件）→ 一个命令都不执行，只走
参数解析 / 警告分支 / 汇总逻辑，秒级完成。
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

CASES_EXEC = Path(__file__).resolve().parent / "cases_exec"
RUN_ALL = CASES_EXEC / "run_all.sh"
GENERATOR = CASES_EXEC / "generate_bash_exc.py"
CASES_DIR = Path(__file__).resolve().parent / "cases"


# ────────────────────────── 1. 静态 lint：反引号命令替换 ──────────────────────────

def _strip_single_quoted(line: str) -> str:
    """剥掉单引号串（里面的反引号是字面量，安全）——如 fork bomb 警告行的写法。"""
    return re.sub(r"'[^']*'", "", line)


def find_unsafe_backticks(text: str) -> list[int]:
    """返回「非注释行里、单引号之外还残留反引号」的行号。

    这类行会被 bash 当命令替换执行（双引号内更隐蔽：`"…（`cmd`）…"`）。
    要写示例命令字面量请用**单引号**（见 run_all.sh 的 fork bomb 警告行）。
    """
    bad = []
    for no, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):       # 注释行不执行，安全
            continue
        if "`" in _strip_single_quoted(line):
            bad.append(no)
    return bad


def test_lint_catches_known_bad_line():
    """阳性对照：确保 lint 本身有效（否则"没报错"可能只是 lint 失灵）。"""
    bad = '    warn_p "注意：示例（`while true; do :; done`）"\n'
    ok = "    warn_p '注意：示例（`while true; do :; done`）'\n"
    assert find_unsafe_backticks(bad) == [1]
    assert find_unsafe_backticks(ok) == []
    assert find_unsafe_backticks("    # 注释里的 `反引号` 无所谓\n") == []


def test_run_all_has_no_unsafe_backticks():
    bad = find_unsafe_backticks(RUN_ALL.read_text(encoding="utf-8"))
    assert not bad, (
        f"run_all.sh 第 {bad} 行在单引号之外用了反引号——bash 会把它当命令替换"
        f"真的执行（示例命令是 `while true; do :; done` 这类会死循环卡死脚本）。"
        f"请把该字符串改用单引号包裹。"
    )


# ────────────────────── 2. 冒烟：每个警告分支都必须秒退 ──────────────────────

# 覆盖 run_all.sh 的所有警告/保护分支（空命令集 → 一条都不执行）：
#   --allow-dangerous 单开        → 走「fork bomb/资源滥用 默认 SKIP」提示分支（历史挂死点）
#   --allow-dangerous + 两个放行  → 走「已加 xxx，将真实执行」err_p 分支
#   都不加                        → 走 else「高危命令默认跳过」分支
SMOKE_FLAG_SETS = [
    ["--yes"],
    ["--allow-dangerous", "--yes"],
    ["--allow-dangerous", "--yes", "--run-fork-bomb", "--run-resource-abuse"],
]

# 警告文案里的示例命令必须**原样打印**（没被执行）——被命令替换执行的话这里就匹配不到
LITERAL_WARNINGS = ["while true; do :; done", "yes > /dev/null &", ":(){ :|:& };:"]


def _run_smoke(flags: list[str], timeout: int = 30) -> tuple[int, str, float]:
    """在临时目录用空命令集跑一次 run_all.sh —— 不执行任何命令。"""
    with tempfile.TemporaryDirectory(prefix="am_smoke_") as tmp:
        tmp_path = Path(tmp)
        shutil.copy2(RUN_ALL, tmp_path / "run_all.sh")
        (tmp_path / "allow.sh").write_text("#!/bin/bash\n", encoding="utf-8")
        (tmp_path / "deny.sh").write_text("#!/bin/bash\n", encoding="utf-8")
        start = time.monotonic()
        proc = subprocess.run(
            ["bash", str(tmp_path / "run_all.sh"), *flags],
            cwd=tmp, capture_output=True, text=True, timeout=timeout,
        )
        return proc.returncode, proc.stdout + proc.stderr, time.monotonic() - start


def test_warning_branches_exit_fast():
    """每个警告分支都必须跑完（历史 bug：某个分支的命令替换让脚本永远回不来）。"""
    for flags in SMOKE_FLAG_SETS:
        rc, out, secs = _run_smoke(flags)
        assert rc == 0, f"run_all.sh {' '.join(flags)} 退出码 {rc}（期望 0）\n{out[-2000:]}"
        assert secs < 20, f"run_all.sh {' '.join(flags)} 跑了 {secs:.1f}s —— 疑似卡死"
        # 没有命令集时不该有任何命令被执行：汇总必须是 0 条
        assert "0 总" in out, f"空命令集不该有可统计命令\n{out[-2000:]}"


def test_warning_examples_are_literal():
    """警告里的示例命令必须是字面量——若被命令替换执行，输出里就看不到原文。"""
    rc, out, _ = _run_smoke(["--allow-dangerous", "--yes"])
    assert rc == 0
    for text in LITERAL_WARNINGS:
        assert text in out, f"警告文案里的示例 {text!r} 没原样打印（疑似被当命令执行了）\n{out[-2000:]}"


# ─────────────────── 3. 匹配器决策表：命中 + 防误伤（一拦一放） ───────────────────

# 命中表：必须跳过（fork bomb 走自己的开关，其余走 --run-resource-abuse）
FORK_BOMB_HITS = [
    ":(){ :|:& };:",
    ":(){ :|: & };:",
    "f(){ f|f& }; f",
]
RESOURCE_ABUSE_HITS = [
    "while true; do :; done",
    "while :; do :; done",
    "until false; do :; done",
    "for((;;)); do :; done",
    "for ((;;)); do echo x; done",
    "yes",
    "yes > /dev/null &",
    "cd /tmp; yes > /dev/null",
]
# 防误伤表：必须**不**命中（否则正常运维命令会被白跳过 → 假 FAIL + 丢覆盖）
CLEAN_COMMANDS = [
    "for ((i=0; i<10; i++)); do echo $i; done",          # 有界 for（allow-157）
    "while read line; do echo $line; done < /tmp/f",     # 读文件 while（allow-158）
    "while true; do cmd; break; done",                   # 有出口的循环
    "while true; do exit 1; done",
    "yes | head -3",                                     # 有界消费
    'echo "while true; do :; done"',                     # 引号内字面量
    'grep -n "while true" /tmp/x.sh',
    "nohup python3 server.py &",                         # 正常后台起服务
    "say(){ echo hi; }; say",                            # 普通函数定义+调用（allow-99）
    "ls -la /tmp",
]


def _extract_function(name: str, text: str) -> str:
    """从 run_all.sh 抠出 `name() { … }` 整段（函数体收在行首的 `}`）。"""
    m = re.search(rf"^{re.escape(name)}\(\) \{{$.*?^\}}$", text, re.M | re.S)
    assert m, f"run_all.sh 里找不到函数 {name}() —— 改名/改格式后请同步本测试"
    return m.group(0)


def _check_matcher(func: str, expect_hit: bool, commands: list[str]) -> None:
    """在真 bash 里跑匹配器（与线上同一份代码），逐条比对期望。"""
    source = RUN_ALL.read_text(encoding="utf-8")
    body = _extract_function(func, source)
    with tempfile.TemporaryDirectory(prefix="am_matcher_") as tmp:
        (Path(tmp) / "matchers.sh").write_text(body, encoding="utf-8")
        (Path(tmp) / "cmds.txt").write_text("\n".join(commands) + "\n", encoding="utf-8")
        script = f"""
set -uo pipefail
. {tmp}/matchers.sh
bad=0
while IFS= read -r cmd; do
    [ -z "$cmd" ] && continue
    if {func} "$cmd"; then got=hit; else got=clean; fi
    want={"hit" if expect_hit else "clean"}
    if [ "$got" != "$want" ]; then
        echo "MISMATCH want=$want got=$got :: $cmd"; bad=1
    fi
done < {tmp}/cmds.txt
exit $bad
"""
        proc = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60)
        assert proc.returncode == 0, (
            f"{func} 决策表不符（expect_hit={expect_hit}）:\n{proc.stdout}\n{proc.stderr}"
        )


def test_fork_bomb_matcher_decision_table():
    _check_matcher("is_fork_bomb", True, FORK_BOMB_HITS)
    _check_matcher("is_fork_bomb", False, RESOURCE_ABUSE_HITS + CLEAN_COMMANDS)


def test_resource_abuse_matcher_decision_table():
    _check_matcher("is_resource_abuse", True, RESOURCE_ABUSE_HITS)
    # fork bomb 由 is_fork_bomb 负责（两个开关独立，互不越界）
    _check_matcher("is_resource_abuse", False, FORK_BOMB_HITS + CLEAN_COMMANDS)


# ──────────── 4. 真提取集回归：allow 集零误伤 + 该跳的确实在 deny 集 ────────────

def test_extracted_allow_set_has_no_matcher_hit():
    """用真用例集生成一遍命令集，断言：allow 侧零命中、deny 侧该跳的都在。

    这是"改正则/加用例"时的兜底——allow 命中 = 正常命令被白跳过（假 FAIL）；
    deny 漏掉新增的资源滥用命令 = 又回到"真执行打爆测试机"的老路。
    """
    with tempfile.TemporaryDirectory(prefix="am_gen_") as tmp:
        proc = subprocess.run(
            [sys.executable, str(GENERATOR), "--json-dir", str(CASES_DIR), "--output-dir", tmp],
            capture_output=True, text=True, timeout=120,
        )
        assert proc.returncode == 0, f"生成器失败:\n{proc.stdout}\n{proc.stderr}"
        out = Path(tmp)

        def commands(name: str) -> list[str]:
            return [
                ln for ln in (out / name).read_text(encoding="utf-8").splitlines()
                if ln.strip() and not ln.lstrip().startswith("#")
            ]

        allow_cmds = commands("allow.sh")
        assert allow_cmds, "生成的 allow.sh 不该为空（用例集异常）"

        source = RUN_ALL.read_text(encoding="utf-8")
        matchers = "\n\n".join(
            _extract_function(f, source) for f in ("is_fork_bomb", "is_resource_abuse")
        )
        (Path(tmp) / "matchers.sh").write_text(matchers, encoding="utf-8")
        for name in ("allow.sh", "allow-root-only.sh", "deny.sh", "deny-root-only.sh"):
            (Path(tmp) / "scan.txt").write_text(
                "\n".join(commands(name)) + "\n", encoding="utf-8")
            script = f"""
set -uo pipefail
. {tmp}/matchers.sh
while IFS= read -r cmd; do
    [ -z "$cmd" ] && continue
    is_fork_bomb "$cmd" && echo "FORK :: $cmd"
    is_resource_abuse "$cmd" && echo "ABUSE :: $cmd"
done < {tmp}/scan.txt
"""
            proc = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60)
            hits = [ln for ln in proc.stdout.splitlines() if ln.strip()]
            if name.startswith("allow"):
                assert not hits, f"{name} 里有命令会被安全跳过（正常命令被白跳 = 假 FAIL）:\n" + "\n".join(hits)

        # deny 侧：已知的资源滥用命令必须确实在 deny.sh 里（被跳过而不是被漏掉）
        deny_text = (out / "deny.sh").read_text(encoding="utf-8")
        for must in ("while true; do :; done", "yes > /dev/null &", ":(){ :|:& };:", ":(){ :|: & };:"):
            assert must in deny_text, f"deny.sh 里缺 {must!r} —— 用例/生成过滤是否变动？"


# ─────────── 5. 命令集「模式串台」：判定集与执行集不能互相沿用 ───────────
#
# 背景（2026-09-22 实测踩到，227 条判定里 3 条误判）：生成器的外部域名重写（-u）是为
# **真执行**准备的——用例里的 evil.com / c2.example 是保留域，不重写就连不通，命令失败
# 会被统计成「沙箱拦住了」，基线通过率失真。但判定模式（--use-agentmoss）**不执行任何
# 命令**，重写纯属有害，而且会改变规则看到的语义：
#   · 内网域被写成外网域：`curl -T … http://ci.internal.company/upload`（内部传输，应放行）
#     被重写成 www.example.com（外部，外传规则拦截）；
#     `--registry https://registry.npmjs.org`（官方源，应放行）被重写成非标准源（拦截）。
#   · URL 子路径被整个丢弃：`…/beacon|bash`（下载后执行，应拦）→ 根路径，
#     「下载后执行」规则再也命中不到。
# 两种后果都**不报错**，只是数字悄悄错掉——所以这里用「决策表 + 产物断言」锁死。

_REWRITE_MARK = "URL 重写:"
_URL_HOST_RE = re.compile(r"https?://([A-Za-z0-9._:-]+)")


def _gen_command_set(tmp: str, *extra: str) -> tuple[str, str]:
    """按给定参数生成一遍命令集，返回 (allow.sh, deny.sh) 全文。"""
    proc = subprocess.run(
        [sys.executable, str(GENERATOR), "--json-dir", str(CASES_DIR),
         "--output-dir", tmp, "--expand-user-home", *extra],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, f"生成器失败:\n{proc.stdout}\n{proc.stderr}"
    out = Path(tmp)
    return ((out / "allow.sh").read_text(encoding="utf-8"),
            (out / "deny.sh").read_text(encoding="utf-8"))


def _external_hosts(text: str) -> set[str]:
    """命令文本里的非本机 URL 主机名（localhost / 127.* 是本地服务目标，不参与重写）。"""
    return {h for h in _URL_HOST_RE.findall(text)
            if not h.startswith("127.") and h.split(":")[0] != "localhost"}


def test_generator_marks_rewrite_mode_in_header():
    """生成器必须把「URL 重写 开/关」写进文件头——run_all.sh 靠这一行判断能否沿用。"""
    with tempfile.TemporaryDirectory(prefix="am_rw_on_") as t:
        allow_on, _ = _gen_command_set(t, "-u", "https://www.example.com")
    with tempfile.TemporaryDirectory(prefix="am_rw_off_") as t:
        allow_off, _ = _gen_command_set(t)
    assert f"# {_REWRITE_MARK} 开" in allow_on, "加了 -u 却没标注「URL 重写: 开」"
    assert f"# {_REWRITE_MARK} 关" in allow_off, "没加 -u 却没标注「URL 重写: 关」"


def test_rewrite_is_the_only_difference_between_the_two_sets():
    """-u 的效果 = 外部域名全落到 BASE_URL。判定集（不加 -u）必须**没有**这个效果。"""
    with tempfile.TemporaryDirectory(prefix="am_rw_on_") as t:
        allow_on, deny_on = _gen_command_set(t, "-u", "https://www.example.com")
    with tempfile.TemporaryDirectory(prefix="am_rw_off_") as t:
        allow_off, deny_off = _gen_command_set(t)
    # 重写版：外部域名只剩 BASE_URL（127.0.0.1 的本地服务目标不参与）
    assert _external_hosts(allow_on + deny_on) == {"www.example.com"}
    # 判定版：用例原始域名还在（内网域 / 官方源 / C2 域 …）——重写了就说明判定会误判
    assert _external_hosts(allow_off + deny_off) - {"www.example.com"}, (
        "未加 -u 的命令集里没有任何非 example.com 的外部域名——URL 重写没被真正关掉"
    )


# (模式, 现存命令集的 URL 重写标记, NO_EXEC, 期望动作)
# 「judge + 开」这一格就是本次踩到的坑：判定模式沿用了执行集 → 3 条误判。
_REGEN_TABLE = [
    ("exec", "开", "0", "reuse"),   # 执行模式 + 现存执行集 → 沿用（原有行为，不能变）
    ("exec", "关", "0", "regen"),   # 执行模式 + 现存判定集 → 必须重建（否则 curl/wget 全连不通）
    ("exec", "", "0", "regen"),     # 旧格式（无标记）→ 重建一次自愈
    ("judge", "开", "0", "regen"),  # 判定模式 + 现存执行集 → 必须重建 ← 本次踩到的坑
    ("judge", "关", "0", "regen"),  # 判定模式每次都重建：--layer/--scenario/--agent 一定生效
    ("exec", "开", "1", "regen"),   # --no-exec：dry-run 预览的必须是本模式要跑的那套
    ("judge", "关", "1", "regen"),
]


def test_cmdset_regen_decision_table():
    """在真 bash 里跑 run_all.sh 的沿用判据（与线上同一份代码），逐格比对。"""
    source = RUN_ALL.read_text(encoding="utf-8")
    body = "\n\n".join(
        _extract_function(f, source) for f in ("gen_rewrite_args", "cmdset_needs_regen"))
    checks = "\n".join(
        f'chk {mode} "{have}" {noexec} {want}' for mode, have, noexec, want in _REGEN_TABLE)
    with tempfile.TemporaryDirectory(prefix="am_regen_") as tmp:
        (Path(tmp) / "funcs.sh").write_text(body, encoding="utf-8")
        script = f"""
set -uo pipefail
. {tmp}/funcs.sh
URL_BASE=https://www.example.com
fail=0
chk() {{
    CMD_MODE="$1"; HAVE_RW="$2"; NO_EXEC="$3"
    WANT_RW="开"; [ "$CMD_MODE" = judge ] && WANT_RW="关"
    if cmdset_needs_regen; then got=regen; else got=reuse; fi
    if [ "$got" != "$4" ]; then echo "MISMATCH $1/现存=$2/noexec=$3 want=$4 got=$got"; fail=1; fi
}}
{checks}
exit $fail
"""
        proc = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, (
        f"命令集沿用判据不符（串台会让判定误判/执行连不通，且不报错）:\n{proc.stdout}\n{proc.stderr}"
    )


def test_gen_rewrite_args_only_for_exec():
    """重写参数只给执行模式——判定模式必须一个都不传。"""
    source = RUN_ALL.read_text(encoding="utf-8")
    body = _extract_function("gen_rewrite_args", source)
    with tempfile.TemporaryDirectory(prefix="am_rwargs_") as tmp:
        (Path(tmp) / "f.sh").write_text(body, encoding="utf-8")
        script = f"""
set -uo pipefail
. {tmp}/f.sh
URL_BASE=https://www.example.com
printf 'judge=[%s]\\n' "$(gen_rewrite_args judge | tr '\\n' ' ')"
printf 'exec=[%s]\\n' "$(gen_rewrite_args exec | tr '\\n' ' ')"
"""
        proc = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "judge=[]" in proc.stdout, f"判定模式不该传 URL 重写参数:\n{proc.stdout}"
    assert "exec=[-u https://www.example.com ]" in proc.stdout, (
        f"执行模式必须传 -u + BASE_URL:\n{proc.stdout}")


# ─────────── 6. 「剔除 allow 命令」必须报出来（条数随环境变，静默=查无实据）───────────
#
# 背景（2026-09 客户实测）：同一份包的 `run_all.sh --use-agentmoss`，x86 沙箱 allow 112 条、
# ARM 沙箱 106 条，各自跑很多次都稳定——但**跟 CPU 架构毫无关系**。真实成因是家目录：
# 用例里「读写自己的工程目录」那几条写的是 `AM_YOUR_HOME` 占位符，生成命令集时展开成**真实
# 家目录**；而 bank 场景白名单硬编码 `/home/sandbox`（客户约束），家目录不是它的机器上，
# 这几条展开后就落在白名单外 → 被 `--scenario bank` 判定为会被拦 → 从 allow 集剔除（不剔
# 的话客户跑 allow.sh 会判成「应放被拦」，虚低放行率）。
# 剔除本身是对的，**静默才是 bug**：客户只会看到两个环境数字对不上、还每次都一样，无从查起。
# 所以这里锁死「必须报出来，且点明家目录成因」。


def _gen_with_home(tmp: str, home: str, *extra: str) -> str:
    """按指定 HOME 生成一遍命令集，返回生成器的全部输出（家目录会展开进命令）。"""
    env = dict(os.environ, HOME=home)
    proc = subprocess.run(
        [sys.executable, str(GENERATOR), "--json-dir", str(CASES_DIR),
         "--output-dir", tmp, "--expand-user-home", *extra],
        capture_output=True, text=True, timeout=120, env=env,
    )
    assert proc.returncode == 0, f"生成器失败:\n{proc.stdout}\n{proc.stderr}"
    return proc.stdout + proc.stderr


def test_scenario_dropped_allow_commands_are_reported():
    """家目录不在场景白名单内时：必须报出剔除条数与「与家目录有关」的成因。"""
    with tempfile.TemporaryDirectory(prefix="am_sd_out_") as t:
        out = _gen_with_home(t, "/home/not-the-sandbox-user",
                             "--scenario", "bank", "--layer", "l1")
        assert "场景规则拦截" in out, (
            "被场景规则剔除的 allow 命令没有任何提示——客户看到「同包不同数」将无从查起"
        )
        assert "家目录" in out, "没点明「与家目录有关」这一成因（这是跨环境数字不同的根源）"
        assert "不可直接比较" in out, "没有提醒两边通过率不可直接比较"
        assert "/home/not-the-sandbox-user" in out, "提示里没有带上本机家目录，客户对不上号"


def test_scenario_warning_has_no_home_section_when_home_is_whitelisted():
    """家目录就在白名单内时（生产沙箱 /home/sandbox），不该出现「与家目录有关」那段。"""
    with tempfile.TemporaryDirectory(prefix="am_sd_in_") as t:
        out = _gen_with_home(t, "/home/sandbox", "--scenario", "bank", "--layer", "l1")
    assert "与**本机家目录**有关" not in out, (
        "家目录已在 bank 白名单内，却报了「与家目录有关」——会把客户往错误方向带"
    )
