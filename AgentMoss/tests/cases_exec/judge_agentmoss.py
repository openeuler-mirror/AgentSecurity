#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用 **import 方式**调用已安装的 agent_moss，逐条判定 allow.sh / deny.sh，统计
「加上 AgentMoss 之后」的放行率 / 拦截率。

为什么需要
----------
run_all.sh（默认模式）在沙箱里**真实执行**命令，统计的是「沙箱自己」的放行/拦截能力
（= 不使用 AgentMoss 的基线通过率）。本脚本**不执行任何命令**，只把同一份命令集里的
每条命令交给 agent_moss 的 analyze() 判定，得到「加上 AgentMoss 之后」的数字：

    allow.sh 的命令 → 期望判 Allow（通过率 = 放行率，被拦即误报）
    deny.sh  的命令 → 期望判 Deny （通过率 = 拦截率，放行即漏报）

两者用**同一份命令集**（allow.sh / deny.sh），客户可据此对比「有无 AgentMoss」的差异。
命令集由 generate_bash_exc.py 从 tests/cases/*.json 提取，本脚本只读不产出。

为什么不需要 prep.sh（真执行环境）
--------------------------------
判定只读命令文本 + 极少量磁盘状态，不跑 shell，所以 prep.sh 建的绝大多数东西
（家目录场景文件、/tmp 样本、HTTP 服务……）都不需要。但有两处**判定前提**必须对齐，
脚本已自动处理：

1. **cwd = 用例脚本所在目录**（与 run_all.sh 真执行时 `cd "$SCRIPT_DIR"` 一致）：
   `bash deploy.sh clean` 这类命令的 L1.5 分支感知要读 cwd 下的脚本内容才判 Deny，
   `python os.listdir('.')` 的 indirect_file_access 要 cwd 下有 .env 才判 Deny。
   这几个前提文件**由本脚本自己从 assets/premise/ 补齐**（只补缺失、不覆盖已有，
   等价 prep.sh 第 3.3 步）——所以判定模式**不需要先跑 prep.sh**，一条命令即可跑完。
   加 --no-premise 可完全不写盘（此时相关命令标 `[SKIP 前提未还原]`，既不算通过也不算
   失败，不会虚低拦截率）。
2. **写新建目标复位**：`wget -O /tmp/pkg.tar.gz`、`echo x > /tmp/f.txt`、`cp A B`
   这类会落盘的命令，若磁盘上已有同名残留文件（**客户先跑真执行基线时必然产生**），
   L2 read_before_write 会判成「写已有未读」→ 误报「应放被拦」。本脚本对 **期望 Allow**
   的命令先删残留（仅限 /tmp、家目录、用例目录内的普通文件；加 --no-reset-write-targets
   可关闭），删了什么会打印出来。写目标覆盖 `>`/`>>`、`wget -O`/`curl -o` 与
   `cp`/`mv`/`install` 的目标参数（**只删目标不删源**：`cp A B` 只删 B，A 是命令要读的）。

用法
----
    python3 judge_agentmoss.py --dir <cases_exec 目录> [--scenario bank] [--agent xiaoo]
                               [--include-root-only] [--no-reset-write-targets] [--no-premise]

    # 通常不用手敲——由 run_all.sh 透传：
    bash run_all.sh --use-agentmoss --scenario bank

输出
----
    每条命令一行：`[PASS] [L<文件行号>#<有效序号>] <命令>`（与 run_all.sh 同格式）
    不符预期的打印 `[FAIL 应拦未拦]` / `[FAIL 应放被拦]` + 引擎判定理由
    末尾打印各集合通过率，并把汇总写入 --summary-file（默认 .last_run_agentmoss.txt），
    若同目录存在基线汇总 .last_run_sandbox.txt（run_all.sh 默认模式写的），追加对比。

退出码
------
    0 = 全部符合预期（PASS + SKIP）；1 = 存在不符预期；2 = 环境/参数错误
    （agent_moss 未安装、命令集缺失等）
"""
import argparse
import os
import re
import shlex
import shutil
import sys
import time
from pathlib import Path

# L3/LLM：离线交付包（dist/offline-l1-py）不含 L3 依赖，判定应走纯静态 L1/L2。
# 调用方显式设了 AGENT_MOSS_DISABLE_LLM 就尊重（如客户另配了 LLM key 想开 L3）；
# 没设则默认关闭，避免离线包因探测 LLM 多打印日志或误走 L3。必须在 import agent_moss
# 之前设置——层开关在初始化时读取。
if "AGENT_MOSS_DISABLE_LLM" not in os.environ:
    os.environ["AGENT_MOSS_DISABLE_LLM"] = "1"

# --layer l1（客户只买 L1 的交付形态）→ 引擎口径对齐为 **L1-only**：关掉层2 逻辑规则
# （意图偏离 / 密码修改授权 / 用户删除授权 / 行为图形式化验证）。否则 run_all 的验收
# 口径（L1+L2）与客户沙箱实际形态（L1-only）不一致 —— L2 命中造成的 Deny 在客户
# 环境不会发生，验收数字会虚高。argparse 在 main 里才解析，而 env 必须在 import
# agent_moss 之前就位，故此处轻量预扫 argv（与 run_all.sh 的透传写法一致）；
# 调用方显式设了 AGENT_MOSS_DISABLE_LOGIC_RULES 则尊重。
_layer_val = ""
for _i, _a in enumerate(sys.argv):
    if _a == "--layer" and _i + 1 < len(sys.argv):
        _layer_val = sys.argv[_i + 1]
        break
    if _a.startswith("--layer="):
        _layer_val = _a.split("=", 1)[1]
        break
if _layer_val == "l1" and "AGENT_MOSS_DISABLE_LOGIC_RULES" not in os.environ:
    os.environ["AGENT_MOSS_DISABLE_LOGIC_RULES"] = "1"

DEFAULT_SUMMARY = ".last_run_agentmoss.txt"
BASELINE_SUMMARY = ".last_run_sandbox.txt"   # run_all.sh 默认模式（真执行）写的基线汇总

# 集合定义：(文件名, 显示标签, 期望判定, 是否 root-only)
SETS = (
    ("allow.sh", "Allow", "Allow", False),
    ("deny.sh", "Deny", "Deny", False),
    ("allow-root-only.sh", "Allow-root-only", "Allow", True),
    ("deny-root-only.sh", "Deny-root-only", "Deny", True),
)

# 判定前提文件（判某几条 deny 命令要读 cwd 下的脚本内容 / .env）：缺失时相关命令判不出
# Deny（不是引擎漏拦，是前提没还原）。素材在 assets/premise/（与 tests/conftest.py 的分支
# 脚本逐字一致），缺失时本脚本自动补齐——所以判定模式**不依赖 prep.sh**。
PREMISE_FILES = ("deploy.sh", "deploy.py", "deploy_shift.sh", ".env",
                 "deploy-large.sh", "build-large.py",
                 "deploy-xlarge.sh", "build-xlarge.py")
_PREMISE_ASSETS = Path(__file__).resolve().parent / "assets" / "premise"
PREMISE_SOURCES = {"deploy.sh": "deploy.sh", "deploy.py": "deploy.py",
                   "deploy_shift.sh": "deploy_shift.sh", ".env": "dotenv"}

# 相对脚本引用（bash deploy.sh clean / python3 deploy.py clean）——L1.5 分支感知要读文件内容。
# lookbehind (?<![\w./-]) 排除带路径的（/tmp/x.sh）与已含目录的引用；也匹配
# deploy-large.sh / build-large.py 等复杂嵌套脚本（带路径前缀的 build-script/deploy.sh
# 被 lookbehind 的 `/` 排除，交给引擎的 extract_script_path 处理）。
_SCRIPT_REF_RE = re.compile(r"(?<![\w./-])([A-Za-z0-9_][A-Za-z0-9_.-]*\.(?:sh|py))\b")

# 写目标提取（与 tests/conftest.py::_prep_file_state 同源）：
#   > 重定向（> / >>，排除 /dev/null、/proc、/sys、/run）
#   wget -O / curl -o / --output-document 落盘
_REDIR_RE = re.compile(r">\s*(?!/dev/null\b)(?!/proc/)(?!/sys/)(?!/run/)([^\s;|&<>'\"]+)")
_DL_WRITE_RE = re.compile(r"\s(?:-O|--output-document|--output|-o)\s*([^\s;|&<>\"']+)", re.IGNORECASE)
# 复制/移动类命令：写目标 = 最后一个非选项参数（见 _copy_dest）
_COPY_DEST_CMDS = ("cp", "mv", "install")

GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"


def iter_cmds(path: Path):
    """按 run_all.sh 同款口径逐行解析命令集：跳过空行与注释行，返回 (行号, 序号, 命令)。

    行号/序号与 run_all.sh 输出一致（`[L<文件行号>#<有效序号>]`），两边输出可直接对照。
    """
    out = []
    seq = 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line_no, raw in enumerate(fh, 1):
            cmd = raw.rstrip("\n").rstrip("\r")
            if not cmd.strip() or cmd.lstrip().startswith("#"):
                continue
            seq += 1
            out.append((line_no, seq, cmd))
    return out


def _expand_home(p: str) -> str:
    """展开写目标里的 ~ / $HOME / ${HOME}（bash 执行时才展开，判定前需还原成绝对路径）。"""
    home = os.path.expanduser("~")
    if p == "~":
        return home
    if p.startswith("~/"):
        return os.path.join(home, p[2:])
    return p.replace("${HOME}", home).replace("$HOME", home)


def _segments(cmd: str) -> list[list[str]]:
    """把命令按 ; / && / || / | 拆段（shlex 分词，引号内内容不会被误切）。"""
    try:
        toks = shlex.split(cmd)
    except ValueError:                      # 引号不配对等 → 退化为按空白切
        toks = cmd.split()
    segs, cur = [], []
    for t in toks:
        if t in (";", "|", "||", "&&"):
            if cur:
                segs.append(cur)
                cur = []
        else:
            cur.append(t)
    if cur:
        segs.append(cur)
    return segs


def _copy_dest(seg: list[str]) -> str:
    """复制/移动类命令的**写目标**（`cp A B` 的 B；A 是读目标，绝不能当写目标删）。

    段首可能是环境变量/赋值前缀（`X=1 cp a b`），先跳过这些 token 找命令名。
    """
    i = 0
    while i < len(seg) and "=" in seg[i] and not seg[i].startswith("-"):
        i += 1
    if i >= len(seg) or seg[i] not in _COPY_DEST_CMDS:
        return ""
    args = [a for a in seg[i + 1:] if not a.startswith("-")]
    return args[-1] if len(args) >= 2 else ""


def write_targets(cmd: str) -> list[str]:
    """提取命令里"写出来"的目标绝对路径（判定前要把它们的磁盘残留复位掉）。

    覆盖三类（与引擎判 read_before_write 时认的写目标保持同步）：
      1. `>` / `>>` 重定向目标
      2. `wget -O` / `curl -o` 下载落盘目标
      3. `cp` / `mv` / `install` 的目标参数（**只取目标不取源**——
         客户先跑真执行基线时，这些命令会真的落盘；不复位的话，判定会把它
         误判成"写已有未读文件"→ 误报 [FAIL 应放被拦]，实测 `cp /tmp/report.txt
         /tmp/report.backup` 就是这种情况）
    去引号内容避免 `grep "a>b"` 被误判。
    """
    stripped = re.sub(r"'[^']*'|\"[^\"]*\"", "", cmd)
    targets = [m.group(1) for m in _REDIR_RE.finditer(stripped)]
    for m in _DL_WRITE_RE.finditer(cmd):
        t = (m.group(1) or "").strip()
        if t and t not in ("-", "/dev/null") and not t.startswith(("/dev/", "/proc/", "/sys/", "/run/")):
            targets.append(t)
    for seg in _segments(cmd):
        dest = _copy_dest(seg)
        if dest:
            targets.append(dest)
    expanded = []
    for t in targets:
        t = _expand_home(t)
        if t.startswith("/"):
            expanded.append(t)
    return list(dict.fromkeys(expanded))


def _under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def reset_write_targets(cmd: str, safe_roots: list[Path]) -> list[str]:
    """按 conftest._prep_file_state「写新建」分支复位：删除写目标的磁盘残留。

    只删**普通文件**，且路径必须落在 /tmp、家目录、用例目录之内（safe_roots）——
    防误删系统文件。返回实际删除的路径列表（调用方打印，客户可见）。
    """
    removed = []
    for t in write_targets(cmd):
        p = Path(t)
        try:
            if not p.is_file() or p.is_symlink():
                continue
            if not any(_under(p, r) for r in safe_roots):
                continue
            p.unlink()
            removed.append(t)
        except OSError:
            continue
    return removed


def ensure_premises(case_dir: Path) -> list[str]:
    """补齐判定前提文件（deploy.sh / deploy.py / deploy_shift.sh / .env
    及复杂嵌套脚本 deploy-large.sh / build-large.py / deploy-xlarge.sh /
    build-xlarge.py / build-script/），返回新建列表。

    等价 prep.sh 第 3.3 步，但**只补自己缺的、绝不覆盖已有文件**（与 prep 同规则）。
    判定模式因此不需要先跑 prep.sh——prep 建的家目录场景/样本/HTTP 服务只有「真执行」
    的基线模式才需要，判定只读命令文本 + 这几个脚本文件。
    """
    created = []
    for name, asset in PREMISE_SOURCES.items():
        target, source = case_dir / name, _PREMISE_ASSETS / asset
        if target.exists() or not source.is_file():
            continue
        try:
            shutil.copyfile(source, target)
            created.append(name)
        except OSError:
            continue
    # 复杂嵌套脚本：主脚本 + build-script/ 子目录。
    # xlarge 两份也必须还原，否则脚本内容扫描用例会被误判为「前提未还原」而跳过。
    _complex_items = {"build-large.py": "build-large.py",
                      "deploy-large.sh": "deploy-large.sh",
                      "build-xlarge.py": "build-xlarge.py",
                      "deploy-xlarge.sh": "deploy-xlarge.sh"}
    for name, asset in _complex_items.items():
        t, s = case_dir / name, _PREMISE_ASSETS / asset
        if not t.exists() and s.is_file():
            try:
                shutil.copyfile(s, t)
                created.append(name)
            except OSError:
                continue
    # 子目录 build-script/（递归拷贝，只补缺失文件）
    src_dir = _PREMISE_ASSETS / "build-script"
    dst_dir = case_dir / "build-script"
    if src_dir.is_dir():
        dst_dir.mkdir(parents=True, exist_ok=True)
        for child in sorted(src_dir.iterdir()):
            if child.is_file():
                t = dst_dir / child.name
                if not t.exists():
                    try:
                        shutil.copyfile(child, t)
                        created.append(f"build-script/{child.name}")
                    except OSError:
                        continue
    return created


def premise_missing(cmd: str, case_dir: Path) -> str:
    """该命令的判定前提是否缺失（prep.sh 未跑过）。返回缺失的文件名，无则空串。

    只对「期望 Deny 却判 Allow」的命令调用——用于把「前提未还原」与「引擎漏拦」区分开，
    避免把 prep 未跑导致的结果误算成 AgentMoss 拦截失败。
    """
    for m in _SCRIPT_REF_RE.finditer(cmd):
        name = m.group(1)
        if not os.path.exists(os.path.join(case_dir, name)):
            return name
    # indirect_file_access（os.listdir/os.walk + 写）：判 Deny 需 cwd 下有 .env
    if ("os.listdir" in cmd or "os.walk" in cmd) and not os.path.exists(case_dir / ".env"):
        return ".env"
    return ""


def load_engine():
    """import agent_moss 并构造判定用的 config/profile（与生成器 --verify-static 同款）。

    失败时打印可照做的安装提示（客户离线包：pip install --user --find-links .）。
    """
    try:
        import agent_moss  # noqa: F401
    except Exception as e:  # pragma: no cover - 环境相关
        print(f"{RED}[ error ] 无法 import agent_moss：{e}{RESET}", file=sys.stderr)
        print("         请先安装离线包（在 offline-l1-py 目录内）：", file=sys.stderr)
        print("         python3 -m pip install --user --find-links . ./agent_moss-<版本>-py3-none-any.whl",
              file=sys.stderr)
        sys.exit(2)

    from agent_moss.engine.analyzer import analyze
    from agent_moss.infra.config import Config, SecurityConfig
    from agent_moss.profiles import get_profile

    profile = get_profile("")     # 自动检测 OS（与 CLI 命令直传同款），Kylin/Linux → linux profile
    config = Config()
    # 显式固定层开关：L1 + L2 静态，L3 关闭（离线包不含 LLM 依赖；判定要可复现）。
    config.security = SecurityConfig(
        enabled=True, heuristic_enabled=True, logic_rules_enabled=True,
        llm_analysis_enabled=False, rules_path="", skills_dir="",
    )
    return agent_moss, analyze, profile, config


def engine_banner(agent_moss, case_dir: Path, scenario: str, agent: str, cwd: str) -> None:
    """打印判定环境摘要（版本 / 层 / runtime config / cwd / scenario），让数字可解释。"""
    ver = getattr(agent_moss, "__version__", "unknown")
    try:
        from agent_moss.infra.runtime_config import get_runtime_config_path, has_runtime_config
        rc_path = get_runtime_config_path()
        rc_on = has_runtime_config()
    except Exception:
        rc_path, rc_on = "", False
    llm = os.environ.get("AGENT_MOSS_DISABLE_LLM", "")
    logic = os.environ.get("AGENT_MOSS_DISABLE_LOGIC_RULES", "")
    print(f"{CYAN}========== AgentMoss 判定（import 方式，不执行任何命令） =========={RESET}")
    print(f"  agent_moss 版本 : {ver}")
    print(f"  判定层          : L1 特征匹配"
          f"{' + L2 逻辑规则' if logic != '1' else '（L2 已关，L1-only 口径）'}"
          f"（静态；L3/LLM {'关闭' if llm == '1' else '按环境配置'}）")
    print(f"  工作目录(cwd)   : {cwd}   # 与 run_all.sh 真执行时一致")
    print(f"  命令集目录      : {case_dir}")
    print(f"  scenario/agent  : {scenario or '-'} / {agent or '-'}")
    if rc_on:
        print(f"  {YELLOW}runtime config  : {rc_path}{RESET}")
        print(f"  {YELLOW}                  （本机用户配置参与判定；改过规则开关/enabled 会影响结果）{RESET}")
    print(f"{CYAN}=================================================================={RESET}")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="用 import 方式调用 agent_moss 判定 allow.sh / deny.sh，统计加上 AgentMoss 之后的通过率")
    ap.add_argument("--dir", default=str(Path(__file__).resolve().parent),
                    help="命令集所在目录（cases_exec 目录，含 allow.sh / deny.sh）")
    ap.add_argument("--scenario", default="", metavar="ID",
                    help="场景 id（透传 analyze 的 scenario_id，如 bank）——须与生成命令集时一致")
    ap.add_argument("--agent", default="", metavar="ID",
                    help="agent id（透传 analyze 的 agent_id，如 xiaoo）——须与生成命令集时一致")
    ap.add_argument("--layer", default="", choices=["", "l1", "l2", "l3"], metavar="L",
                    help="用例层（与 run_all.sh --layer 对应）。l1 时自动设 "
                         "AGENT_MOSS_DISABLE_LOGIC_RULES=1 —— 引擎口径对齐客户 L1-only "
                         "形态（验收数字与客户环境一致，不因 L2 命中虚高）")
    ap.add_argument("--include-root-only", action="store_true",
                    help="额外判定 *-root-only.sh（需 root 权限的命令），作为独立标签单独统计")
    ap.add_argument("--no-reset-write-targets", action="store_true",
                    help="不做写新建目标复位（默认会删 allow 命令写目标在 /tmp、家目录、用例目录"
                         "内的磁盘残留，避免 L2 read_before_write 把「写新建」误判成「写已有」）")
    ap.add_argument("--no-premise", action="store_true",
                    help="不自动补齐判定前提文件（deploy.sh / deploy.py / deploy_shift.sh / .env）。"
                         "默认缺哪个就从 assets/premise/ 补哪个（不覆盖已有），缺前提的命令会标"
                         "[SKIP 前提未还原] 不算失败；加本参数则完全不写盘")
    ap.add_argument("--summary-file", default=DEFAULT_SUMMARY,
                    help=f"汇总输出文件（相对 --dir；默认 {DEFAULT_SUMMARY}；传空串则不写）")
    args = ap.parse_args()

    case_dir = Path(args.dir).expanduser().resolve()
    if not (case_dir / "allow.sh").is_file():
        print(f"{RED}[ error ] {case_dir} 下没有 allow.sh / deny.sh —— "
              f"请先运行 bash prep.sh 或 bash run_all.sh 生成命令集{RESET}", file=sys.stderr)
        return 2

    agent_moss, analyze, profile, config = load_engine()
    cwd = str(case_dir)   # 与 run_all.sh 的 `cd "$SCRIPT_DIR"` 一致
    engine_banner(agent_moss, case_dir, args.scenario, args.agent, cwd)

    safe_roots = [case_dir, Path(os.path.realpath("/tmp")), Path.home()]
    # 判定前提：缺哪个补哪个（等价 prep.sh 第 3.3 步，不覆盖已有）——判定模式因此不需要 prep.sh。
    if not args.no_premise:
        created = ensure_premises(case_dir)
        if created:
            print(f"  {CYAN}[premise] 补齐判定前提 {' / '.join(created)}（素材 assets/premise/，"
                  f"只补缺失、不覆盖已有）——这几条命令的 Deny 要读脚本内容才能判{RESET}")
    missing_premise = [f for f in PREMISE_FILES if not os.path.exists(case_dir / f)]

    run_sets = [s for s in SETS if args.include_root_only or not s[3]]
    if not args.include_root_only:
        present_ro = [f for f, _, _, ro in SETS if ro and (case_dir / f).is_file()]
        if present_ro:
            print(f"  {YELLOW}注：{' / '.join(present_ro)} 默认不判定（需 root 权限的命令，"
                  f"加 --include-root-only 纳入）{RESET}")
    if missing_premise:
        print(f"  {YELLOW}注：判定前提 {', '.join(missing_premise)} 缺失（--no-premise 或 "
              f"assets/premise/ 素材不全）；涉及它们的命令会标 [SKIP 前提未还原]（不算失败）。{RESET}")
        print(f"  {YELLOW}    如需纳入统计：确认 assets/premise/ 完整（或先跑一次 bash prep.sh，"
              f"但这几条判定要读脚本内容）{RESET}")

    # 预热：首次 analyze 含引擎一次性初始化（规则 JSON 解析 + ~167 条正则首次编译 +
    # 懒加载模块），实测 50-90ms；之后 Python re 模块缓存命中，回落至稳态 4-10ms。
    # 客户常驻 CI 脚本只在启动时付这一次，故不计入单条统计（单独打印，透明可见）。
    t_warm = time.perf_counter()
    try:
        analyze(
            session_id="cases-exec-warmup",
            prompt_session="",
            action_history=[],
            a_next={"action_type": "bash", "action_detail": "true"},
            reason="",
            config=config,
            profile=profile,
            cwd=cwd,
            agent_id=args.agent,
            scenario_id=args.scenario,
        )
        warmup_ms = (time.perf_counter() - t_warm) * 1000
        print(f"  {YELLOW}引擎预热：首次调用 {warmup_ms:.1f}ms（含规则加载 + 正则首次编译，"
              f"一次性；不计入下方单条统计）{RESET}")
    except Exception as e:
        warmup_ms = -1.0
        print(f"  {YELLOW}引擎预热失败（不影响后续判定）：{type(e).__name__}: {e}{RESET}")

    summary_lines = []
    total_fail = 0
    t0 = time.time()
    cmd_times: list[float] = []
    for fname, label, expect, _ro in run_sets:
        fpath = case_dir / fname
        if not fpath.is_file():
            continue
        cmds = iter_cmds(fpath)
        print("")
        print(f"========== {label}（AgentMoss 判定，{fname}，共 {len(cmds)} 条） ==========")
        passed = failed = skipped = 0
        for line_no, seq_no, cmd in cmds:
            tag = f"[L{line_no}#{seq_no}]"
            # 写新建目标复位：仅对期望 Allow 的命令做（deny 命令的写目标常指向 ~/.bashrc 等
            # 用户持久化文件，删了会破坏沙箱环境；实测 deny 判定不依赖该复位）。
            if expect == "Allow" and not args.no_reset_write_targets:
                for removed in reset_write_targets(cmd, safe_roots):
                    print(f"{YELLOW}[reset] 删除写新建目标残留 {removed}（否则会被判「写已有未读」）{RESET}")
            t_cmd = time.perf_counter()
            try:
                res = analyze(
                    session_id="cases-exec-agentmoss",
                    prompt_session="",
                    action_history=[],
                    a_next={"action_type": "bash", "action_detail": cmd},
                    reason="",
                    config=config,
                    profile=profile,
                    cwd=cwd,
                    agent_id=args.agent,
                    scenario_id=args.scenario,
                )
            except Exception as e:
                # 单条命令判定异常不应中断整轮统计（客户要的是完整通过率数字）。
                failed += 1
                print(f"{RED}[FAIL 判定异常]{RESET} {tag} {cmd}")
                print(f"        {type(e).__name__}: {e}")
                continue
            elapsed_ms = (time.perf_counter() - t_cmd) * 1000
            cmd_times.append(elapsed_ms)
            decision = res.get("decision", "")
            layers = res.get("violated_layers") or []
            reason = str(res.get("reason", "") or "").replace("\n", " ")
            if decision == expect:
                passed += 1
                # 措辞与真执行模式（run_all.sh）统一：PASS 后面标明"是怎么符合预期的"，
                # 两边输出可直接对照（Allow 集=已放行，Deny 集=已拦截）。
                verdict = "已放行" if expect == "Allow" else "已拦截"
                print(f"{GREEN}[PASS {verdict}]{RESET} {tag} {cmd}  [{elapsed_ms:6.1f}ms]")
                continue
            # 不符预期。期望 Deny 却没拦住时，先区分「前提未还原」与「引擎漏拦」。
            if expect == "Deny":
                miss = premise_missing(cmd, case_dir)
                if miss:
                    skipped += 1
                    print(f"{YELLOW}[SKIP 前提未还原-缺 {miss}（assets/premise/ 也缺）]{RESET} {tag} {cmd}")
                    continue
            failed += 1
            verdict = "应拦未拦" if expect == "Deny" else "应放被拦"
            print(f"{RED}[FAIL {verdict}]{RESET} {tag} {cmd}")
            print(f"        引擎判定：{decision} | {reason[:160]} | layers={layers}")
        evaluated = passed + failed
        print("")
        # 「总」按**已判定条数**计（未判定的前提未还原条数单独列出，且与命令集总条数一起写明），
        # 口径与 run_all.sh 一致（命令不存在 rc=127 也不计入 total），但这里额外打印命令集
        # 真实条数，避免客户误以为 99 条全判过。
        extra = (f"；另有 {skipped} 条前提未还原未计入——命令集共 {evaluated + skipped} 条"
                 if skipped else "")
        print(f"---- {label}（AgentMoss 判定）结果：{passed} 通过 / {evaluated} 判定"
              f"（失败 {failed}{extra}）----")
        # 与 run_all.sh 同款 6 字段汇总行，便于两边对照/比对
        summary_lines.append(f"{label} {passed} {evaluated} {failed} {skipped} 0")
        total_fail += failed

    elapsed = time.time() - t0
    print("")
    print("=========================================")
    print("  AgentMoss 判定汇总（不执行任何命令）")
    print("=========================================")
    for line in summary_lines:
        label, passed, total, failed, skipped, _ = line.split()
        rate = f"{int(passed) * 100 / int(total):.1f}%" if int(total) else "-"
        kind = "放行率" if label.startswith("Allow") else "拦截率"
        extra = ""
        if int(skipped):
            extra = (f"；命令集共 {int(total) + int(skipped)} 条，"
                     f"另有 {skipped} 条因前提未还原未计入（assets/premise/ 补齐后即可纳入）")
        print(f"  {label}: {passed} / {total} 判定通过（{kind} {rate}）—— 失败 {failed}{extra}")
    print(f"  判定耗时：{elapsed:.2f}s")
    if cmd_times:
        n = len(cmd_times)
        avg_ms = sum(cmd_times) / n
        print(f"  单条耗时：共 {n} 条 | 平均 {avg_ms:.2f}ms | 最慢 {max(cmd_times):.2f}ms | 最快 {min(cmd_times):.2f}ms")
    if warmup_ms >= 0:
        print(f"  引擎预热：首次调用 {warmup_ms:.1f}ms（一次性，已在统计前扣除——"
              f"常驻服务仅启动时付一次）")
    print("=========================================")

    # 与基线（run_all.sh 默认模式真执行的结果）对比：两边口径不同（一边是真跑 shell 看沙箱
    # 拦不拦，一边是引擎判定），只并列陈列，不做「提升 X%」之类的断言，避免误导。
    base_path = case_dir / BASELINE_SUMMARY
    base = {}
    if base_path.is_file():
        for line in base_path.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split()
            if len(parts) >= 6 and parts[0] in ("Allow", "Deny") and parts[0] not in base:
                base[parts[0]] = parts[1:6]   # 每阶段一行，同名取首见（与 run_all 汇总口径一致）
    print("")
    if base:
        am = {line.split()[0]: line.split()[1:] for line in summary_lines}
        print(f"{CYAN}--- 对比（同一份命令集）：{BASELINE_SUMMARY} 真执行基线 vs 本次 AgentMoss 判定 ---{RESET}")
        mismatched = []
        for key, name in (("Allow", "安全命令"), ("Deny", "恶意命令")):
            if key not in am:
                continue
            passed, total, _fail, skipped, _cn = am[key]
            b = base.get(key)
            if b:
                b_pass, b_total, b_fail, b_skip, _bcn = b
                # 命令集条数不一致 = 两次跑的不是同一份命令集（如一次 bank 场景、一次通用，
                # 或期间改过用例重新生成）——此时并列数字会误导，明确提示重跑基线。
                # 基线侧分母 = b_total（已含安全跳过的，它们照常进分母）；本侧 = 判定数 +
                # 前提未还原跳过数（后者没判定，不在本侧分母里）。b_skip 是 b_fail 的子集，
                # **不能**再加一遍（加过会误报"命令集不同"）。
                if int(b_total) > 0 and int(b_total) != int(total) + int(skipped):
                    mismatched.append(key)
                # 措辞与真执行模式一致：Allow 集数「已放行」，Deny 集数「已拦截」（= 符合预期数）。
                # b_skip 是 b_fail 的子集（安全跳过未执行，照常计 FAIL）——单独标注，避免
                # 把"没跑"误读成"沙箱拦截了"。
                _word = "已放行" if key == "Allow" else "已拦截"
                _note = f"，其中 {b_skip} 条安全跳过未执行" if int(b_skip) else ""
                if int(b_total) == 0:
                    # 分母 0 = 那次基线没执行任何命令（dry-run / 被中断），拿不出对比数字
                    baseline_txt = "未执行（dry-run 或空基线，无法对比）"
                else:
                    baseline_txt = f"{b_pass} {_word} / {b_total} 总（不符合预期 {b_fail}{_note}）"
            else:
                baseline_txt = "（基线无此集合：run_all.sh 未加 --include-root-only）"
            rate = f"{int(passed) * 100 / int(total):.1f}%" if int(total) else "-"
            am_txt = (f"{passed}/{total} 条{'放行' if key == 'Allow' else '拦截'}（{rate}）"
                      + (f"，另 {skipped} 条未计入" if int(skipped) else ""))
            print(f"  {key}（{name}）")
            print(f"    基线（沙箱真执行，未加 AgentMoss）: {baseline_txt}")
            print(f"    AgentMoss 判定（本次）            : {am_txt}")
        if mismatched:
            print(f"    {YELLOW}注意：{'/'.join(mismatched)} 的命令集条数与基线不同——两次跑的不是同一份"
                  f"命令集，数字不可直接对照（请用同一模式/同一 --scenario 重跑基线）。{RESET}")
        print("    （两边 PASS/FAIL 语义一致 = 是否符合预期；差别只在「谁拦的」——")
        print("      基线是沙箱真实执行拦不拦、AgentMoss 判定是引擎静态判定拦不拦）")
    else:
        print(f"  提示：未找到基线汇总 {BASELINE_SUMMARY}（在默认模式下跑一次 bash run_all.sh 即生成），"
              f"生成后本脚本会自动追加对比。")

    # 汇总落盘（与基线文件同目录，供下次对比；gitignore 已忽略 .last_run_*.txt）。
    # 有失败也写——客户要拿这份数字回去，不能因为存在不符预期就不落盘。
    if args.summary_file:
        try:
            out = case_dir / args.summary_file
            ver = getattr(agent_moss, "__version__", "unknown")
            head = (f"# AgentMoss 判定汇总（import 方式，不执行命令）\n"
                    f"# agent_moss {ver} | scenario={args.scenario or '-'} | agent={args.agent or '-'} "
                    f"| 生成时间 {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            out.write_text(head + "\n".join(summary_lines) + "\n", encoding="utf-8")
            print(f"  汇总已写入：{out}")
        except OSError as e:
            print(f"{YELLOW}[ warn ] 汇总写入失败：{e}{RESET}")

    if total_fail:
        print(f"{RED}存在 {total_fail} 条不符预期（详见上方 [FAIL] 行）{RESET}")
        return 1
    print(f"{GREEN}全部符合预期：allow 全部放行、deny 全部拦截。{RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
