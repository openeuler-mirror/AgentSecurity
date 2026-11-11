"""AgentMoss 安全分析引擎测试 — 共享 Fixtures"""

import json
import os
import re
import tempfile
import shutil
from pathlib import Path

# ========== 源码仓测试数据隔离（必须在 import agent_moss 之前设置） ==========
# 把 AGENT_MOSS_DATA_DIR 指向独立临时目录，隔离开发者本机的 ~/.config/agentmoss
# 下所有运行时状态（agent_moss_runtime.json / config.json / skills / rules fallback）：
#   - get_data_root()/get_config_dir()/get_runtime_config_dir() 都跟随 data_root → 隔离
#   - has_runtime_config() → False（本机 console 生成的 runtime 不会被读到）
#   - rules_loader._load_json 的源码缺失 fallback → 空目录不命中，恒用源码
# 这样源码仓跑测试永远基于源码规则 + profile 默认，不受「开发者本地 console 配置」
# 污染（曾出现：本机 runtime 的 dangerous_commands 57 条 vs 源码 55 条的分叉）。
# 逃生门：显式设 AGENT_MOSS_TEST_USE_RUNTIME=1 时跳过本隔离（data_root 落真实
# ~/.config/agentmoss），供「确认改规则后真实运行时是否生效」的场景（见
# MAINTENANCE_WORKFLOW.md「验证真实运行」）。
# 注：conftest 是 pytest 首个加载的测试文件，本语句在 agent_moss 任何 import 之前执行，
# 之后加载的 agent_moss.infra.paths 首次调用 get_data_root() 即读到该 env，无缓存问题。
# 测试默认关闭鉴权（2026-10 起产品默认 auto：首次启动自动生成 token）。
# 需要验证鉴权行为的用例在用例内显式设 AGENT_MOSS_AUTH_MODE=auto 覆盖。
os.environ.setdefault("AGENT_MOSS_AUTH_MODE", "off")

if os.getenv("AGENT_MOSS_TEST_USE_RUNTIME") != "1":
    _AM_TEST_DATA_DIR = tempfile.mkdtemp(prefix="agentmoss_test_data_")
    os.environ["AGENT_MOSS_DATA_DIR"] = _AM_TEST_DATA_DIR

import pytest

from agent_moss.infra.config import (
    Config,
    LLMConfig,
    TimeoutConfig,
    RetryConfig,
    SecurityConfig,
)
from agent_moss.profiles import get_profile

# 测试用例目录
CASES_DIR = Path(__file__).parent / "cases"

# indirect_file_access 规则需 cwd 实际含凭据文件才命中（对齐 Python os.listdir 检查）。
# session 级 fixture setup 临时目录放 .env 凭据，供 l2/logic-10-indirect-access.json 用。


@pytest.fixture(scope="session")
def indirect_cwd():
    """为 indirect_file_access case 创建临时 cwd 目录含 .env 凭据文件。"""
    d = tempfile.mkdtemp(prefix="agentmoss-indirect-")
    Path(d, ".env").write_text("KEY=val")
    yield d
    shutil.rmtree(d, ignore_errors=True)


# ========== 脚本分支感知（case $1）测试环境 ==========
# 测试脚本内容分析「分支感知参数绑定」：脚本 deploy.sh 的 case $1 in 分支里，
# clean 分支含危险命令（rm ~/.ssh/id_rsa），backup 分支安全。
# 同一脚本文件供「一拦一放」两个用例使用（clean→Deny、backup→Allow）。

_SCRIPT_BRANCH_SCRIPT = """#!/bin/bash
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
"""


@pytest.fixture(scope="session")
def script_branch_cwd():
    """为脚本分支感知 JSON case 创建含 deploy.sh 的临时目录。

    脚本路径在 JSON case 里用 `deploy.sh` 相对路径，cwd 指向本目录，
    使 analyze_script_content 能读到真实脚本文件做分支感知。
    clean 分支 rm -rf ~/.ssh/id_rsa（危险），backup 分支 tar 备份（安全）。
    ~ 保留原样以触发 SSH 私钥规则（.ssh/id_rsa），避免展开成 /home/xxx
    撞上 L1 的 rm -rf /home 删目录规则。
    """
    d = Path(tempfile.mkdtemp(prefix="agentmoss-script-branch-"))
    (d / "deploy.sh").write_text(_SCRIPT_BRANCH_SCRIPT)
    yield str(d)
    shutil.rmtree(str(d), ignore_errors=True)


# ========== Python 脚本分支感知（sys.argv 分支）测试环境 ==========
# deploy.py 的 sys.argv[1] 分派中，clean 分支含危险命令（os.system rm -rf ~/.ssh/id_rsa），
# backup 分支安全。供「一拦一放」两个用例使用（clean→Deny、backup→Allow）。
# 由 PythonBackend（stdlib ast 控制流剪枝）负责分支选择，验证多语言追踪。

_PYTHON_BRANCH_SCRIPT = """#!/usr/bin/env python3
import sys
import os

mode = sys.argv[1] if len(sys.argv) > 1 else "backup"

if mode == "clean":
    os.system("rm -rf ~/.ssh/id_rsa")
elif mode == "backup":
    print("backing up")
else:
    print("unknown mode")
"""


@pytest.fixture(scope="session")
def python_script_branch_cwd():
    """为 Python 脚本分支感知 JSON case 创建含 deploy.py 的临时目录。

    脚本路径在 JSON case 里用 `deploy.py` 相对路径，cwd 指向本目录，
    使 analyze_script_content 能读到真实脚本文件做分支感知。
    clean 分支 os.system rm -rf ~/.ssh/id_rsa（危险），backup 分支 print（安全）。
    """
    d = Path(tempfile.mkdtemp(prefix="agentmoss-python-branch-"))
    (d / "deploy.py").write_text(_PYTHON_BRANCH_SCRIPT)
    yield str(d)
    shutil.rmtree(str(d), ignore_errors=True)


# ========== Shell shift 漏报防护（$1 语义被改写）测试环境 ==========
# deploy_shift.sh 开头 shift 改写 $1：`bash deploy_shift.sh backup clean` 实际
# shift 后 $1=clean 走危险分支。修复前 P1 绑定 $1=backup 误剪危险分支（漏报）。
# 修复后含 shift 跳过 P1 绑定 → fail-closed 全文本 → 拦。供一拦用例使用。

_SHIFT_BRANCH_SCRIPT = """#!/bin/bash
shift
case $1 in
  clean)
    rm -rf ~/.ssh/id_rsa
    ;;
  backup)
    echo 'backing up'
    ;;
esac
"""


@pytest.fixture(scope="session")
def shell_shift_cwd():
    """为 shell shift 漏报防护 JSON case 创建含 deploy_shift.sh 的临时目录。"""
    d = Path(tempfile.mkdtemp(prefix="agentmoss-shell-shift-"))
    (d / "deploy_shift.sh").write_text(_SHIFT_BRANCH_SCRIPT)
    yield str(d)
    shutil.rmtree(str(d), ignore_errors=True)


# ========== 复杂嵌套脚本分支感知（deploy-large.sh / build-large.py）测试环境 ==========
# 这两个脚本是多分支 case 嵌套调用 build-script/ 子模块（deploy.sh / prepare.sh / install.sh /
# cleanup.sh）。**内容单一事实源 = tests/cases_exec/assets/premise/**（与 prep.sh / judge_agentmoss.py
# 同源）——fixture 直接把素材拷到临时 cwd，不改写内容（避免和 cases_exec 侧漂移）。
# 供一拦一放用例使用：clean/full-clean → Deny（子模块危险分支），full/quick → Allow（安全分支）。

_CASES_EXEC_PREMISE = Path(__file__).parent / "cases_exec" / "assets" / "premise"
# 2026-09 补：大脚本样本（732/1990 行）也走同一 fixture —— 篇幅接近真实
# 生产脚本，验证长文本扫描；且「有函数定义时整层不剪枝」这个行为也一并被看护。
_NESTED_SCRIPT_MAIN = ("deploy-large.sh", "build-large.py", "deploy-xlarge.sh", "build-xlarge.py")
_NESTED_SCRIPT_SUBDIR = "build-script"


@pytest.fixture(scope="session")
def nested_script_branch_cwd():
    """为复杂嵌套脚本 JSON case 创建含 deploy-large.sh / build-large.py + build-script/ 的临时目录。"""
    d = Path(tempfile.mkdtemp(prefix="agentmoss-nested-script-"))
    for name in _NESTED_SCRIPT_MAIN:
        src = _CASES_EXEC_PREMISE / name
        if src.is_file():
            (d / name).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    sub_src = _CASES_EXEC_PREMISE / _NESTED_SCRIPT_SUBDIR
    if sub_src.is_dir():
        sub_dst = d / _NESTED_SCRIPT_SUBDIR
        sub_dst.mkdir(exist_ok=True)
        for child in sub_src.iterdir():
            if child.is_file():
                (sub_dst / child.name).write_text(child.read_text(encoding="utf-8"), encoding="utf-8")
    yield str(d)
    shutil.rmtree(str(d), ignore_errors=True)


# ========== 环境隔离：屏蔽本机 runtime_config 对测试的污染 ==========
# 本机若存在 ~/.config/agentmoss/agent_moss_runtime.json（console 生成，
# 存的是当前平台的敏感路径），会覆盖测试传入的 Linux/Windows profile，
# 导致 cat /etc/shadow 这类跨平台用例在 Windows 上跑时查不到 Linux 路径。
# 测试应基于 profile 自身的数据判定，不受本机外部状态影响，故全局屏蔽。

@pytest.fixture(autouse=True)
def _isolate_runtime_config(monkeypatch):
    """让测试期间 has_runtime_config() 恒为 False，使用 profile 默认数据。"""
    from agent_moss.infra import runtime_config as rc
    monkeypatch.setattr(rc, "has_runtime_config", lambda: False)
    # get_disabled_l2_rules_with_skip_l3 也走 runtime_config，一并屏蔽返回空
    try:
        monkeypatch.setattr(rc, "get_disabled_l2_rules_with_skip_l3", lambda: {})
    except Exception:
        pass


@pytest.fixture(autouse=True)
def _clear_agent_cache():
    """每个用例前清空 agent / 场景扩展缓存，避免用例间 agent_id / scenario_id 串扰。

    agent 用例（tests/cases/agent/*.json，input.agent_id 指定 xiaoo/opendesk）
    依赖 get_agent_extensions 加载对应 agent 规则；场景用例
    （tests/cases/scenario/<id>/*.json，input.scenario_id 指定 bank 等）依赖
    get_scenario_extensions。两者都有进程级缓存，若不清空，前一个用例加载的
    扩展会残留在缓存里，导致后续通用模式用例（agent_id/scenario_id 空）误命中
    定制规则。测试应基于 rules.json 源码规则、逐个干净加载。
    """
    from agent_moss.agents import clear_agent_extensions_cache
    from agent_moss.scenarios import clear_scenario_extensions_cache
    clear_agent_extensions_cache()
    clear_scenario_extensions_cache()
    yield
    clear_agent_extensions_cache()
    clear_scenario_extensions_cache()


@pytest.fixture(autouse=True)
def _isolate_chain_state_store(tmp_path, monkeypatch):
    """隔离有状态链库：把状态库指向每次临时目录，并重置全局单例。

    test_chain_state 等在意状态持久化的用例不会被之前的用例（或宿主环境真实的
    ~/.agentmoss/stateful_chains.db）污染；也让状态化用例之间互不串扰。
    """
    from agent_moss.engine.formal_engine import chain_state as cs

    state_dir = tmp_path / "agentmoss_state"
    monkeypatch.setenv("AGENT_MOSS_STATE_DIR", str(state_dir))
    cs.reset_chain_state_store()
    yield
    cs.reset_chain_state_store()


# ========== 配置 Fixtures ==========

@pytest.fixture(scope="session")
def linux_profile():
    """Linux Profile 测试实例"""
    return get_profile("linux")


@pytest.fixture(scope="session")
def windows_profile():
    """Windows Profile 测试实例"""
    return get_profile("windows")


@pytest.fixture(scope="session")
def default_config() -> Config:
    """默认测试配置（禁用 LLM 层，仅测试前两层）"""
    return Config(
        llm=LLMConfig(api_key="", model="", base_url=""),
        timeout=TimeoutConfig(total_timeout=5, prompt1_timeout=3, prompt2_timeout=2, step_interval=0),
        retry=RetryConfig(max_retries=1, retry_interval=0),
        security=SecurityConfig(
            enabled=True,
            heuristic_enabled=True,
            logic_rules_enabled=True,
            llm_analysis_enabled=False,  # 默认禁用 LLM
        ),
    )


@pytest.fixture(scope="session")
def llm_config() -> Config:
    """支持 LLM 的测试配置。

    唯一来源 = get_default_config()（已融合 env AGENT_MOSS_LLM_API_KEY +
    ~/.config/agentmoss/config.json 的 llm.api_key + provider env）。
    与 LLM 连通性探测（_resolve_test_llm_config）同一判定源，保证
    「probe 通过 → 实际跑 LLM 用的是同一配置」，probe 结果可信。
    """
    from agent_moss.infra.config import get_default_config

    llm = get_default_config().llm
    return Config(
        llm=LLMConfig(api_key=llm.api_key, model=llm.model, base_url=llm.base_url),
        timeout=TimeoutConfig(total_timeout=60, prompt1_timeout=30, prompt2_timeout=20, step_interval=0),
        retry=RetryConfig(max_retries=1, retry_interval=0),
        security=SecurityConfig(
            enabled=True,
            heuristic_enabled=True,
            logic_rules_enabled=True,
            llm_analysis_enabled=True,
        ),
    )


# ========== L3 LLM 统一判定 + 连通性探测 ==========
# 双端对称：Python 判据与 TS isLLMAvailable/probeLLMConnection 一致。
# 判定源 = get_default_config().llm.api_key（已融合 env AGENT_MOSS_LLM_API_KEY +
#          ~/.config/agentmoss/config.json 的 llm.api_key + provider env）。
# 真连通检查：发一次 max_tokens=1 的 ping，成功才认为 L3 可跑。
# 避免「有 key 但 key 无效/网络不通」时 L3 case 真调 LLM 走 fail-open 假通过。


def _resolve_test_llm_config() -> "LLMConfig | None":
    """返回可用的 LLM 配置（api_key 非空），否则 None。

    判据与生产 get_default_config() 一致：已融合 env + config.json + provider env。
    尊重 AGENT_MOSS_DISABLE_LLM=1（显式禁 LLM 时返回 None，强制 skip L3，
    对齐 TS isLLMAvailable 的 DISABLE_LLM 短路）。
    """
    if os.getenv("AGENT_MOSS_DISABLE_LLM") == "1":
        return None
    from agent_moss.infra.config import get_default_config

    cfg = get_default_config().llm
    if not cfg.api_key:
        return None
    return cfg


def _probe_llm(config) -> bool:
    """发一次 max_tokens=1 的 ping 探测连通性。成功 True，任何异常返回 False。

    注意：不能用 call_llm —— 它会对 finish_reason=length（max_tokens=1 必然触发）
    抛 ValueError，误判探测失败。故用 create_client 直接发最小请求，只要端点
    返回（finish_reason 为 length/stop 均可）即视为连通。
    """
    from agent_moss.infra.llm_client import create_client

    try:
        client = create_client(config)
        resp = client.chat.completions.create(
            model=config.model,
            messages=[{"role": "user", "content": "ping"}],
            max_tokens=1,
        )
        return bool(resp and resp.choices and resp.choices[0])
    except Exception:
        return False


@pytest.fixture(scope="session")
def llm_probe_available():
    """L3 是否可真跑：判定源有 key 且连通性探测通过。只 ping 一次（session 缓存）。

    返回 bool。探测失败时打明确提示（含 base_url/model），帮助快速定位坏 key。
    """
    cfg = _resolve_test_llm_config()
    if cfg is None:
        print("\n[AgentMoss test] 未检测到 LLM API Key（env 或 ~/.config/agentmoss/config.json 均无），L3 测试跳过")
        return False
    ok = _probe_llm(cfg)
    if not ok:
        print(f"\n[AgentMoss test] LLM 连通性探测失败（base_url={cfg.base_url}, model={cfg.model}），"
              f"key 可能无效或网络不通，L3 测试跳过（避免 fail-open 假通过）")
    else:
        print(f"\n[AgentMoss test] LLM 连通性探测通过（base_url={cfg.base_url}, model={cfg.model}），L3 测试将真调 LLM")
    return ok


# ========== 测试用例加载 ==========

# AM_YOUR_HOME 占位符：JSON 用例里 /home/xxx 硬编码路径统一写成 AM_YOUR_HOME（可移植，
# 且不与 ~/$HOME/${HOME} 等被测关键词冲突）。加载时展开成当前用户家目录的绝对路径
# （如 /home/hkl），保证引擎判定与原来的 /home/me、/home/user 等一致（这些路径判定
# 不依赖具体的用户名，见 tests/cases/README.md 计数口径说明）。
_AM_YOUR_HOME = os.path.expanduser("~")


def _expand_placeholder(obj):
    """递归把字符串里的 AM_YOUR_HOME 展开成当前用户家目录绝对路径。"""
    if isinstance(obj, dict):
        return {k: _expand_placeholder(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expand_placeholder(v) for v in obj]
    if isinstance(obj, str):
        return obj.replace("AM_YOUR_HOME", _AM_YOUR_HOME)
    return obj


# ========== read_before_write 文件状态预处理 ==========

# read_before_write 判定依赖磁盘状态：同一写命令在目标文件「已存在/不存在」时
# 结论可能相反（新建 → 放行；写已有未读 → 拦截）。为让用例判定可复现、不随
# 当前机器磁盘残留翻转，执行每个用例前先对齐目标文件状态：
#   - 写目标在历史中没被读过（语义=「新建文件」）→ 确保目标【不存在】：若存在则删除；
#   - 写目标在历史中被读过（语义=「写已有文件」）→ 确保目标【存在】：若不存在则创建。
# 该函数只处理「写」语义的目标；纯读命令的读目标由 prep.sh 建文件保证，测试不干预。
_DL_WRITE_RE = re.compile(
    # wget -O /tmp/x、curl -o /tmp/x、--output-document=/tmp/x 等下载落盘写目标。
    # 排除：-O-（stdout）、-o /dev/null（丢弃响应体）、--output=/dev/null。
    # 用 m.group(1) 取路径；-O- 和 /dev/null 由调用方再过滤。
    r"\s(?:-O|--output-document|--output|-o)\s*([^\s;|&<>\"']+)",
    re.IGNORECASE,
)


def _prep_file_state(case: dict, profile) -> None:
    """执行 analyze 前对齐 write 目标文件的可复现状态（删新建 / 建已有）。

    只处理 a_next 里显式写目标（> 重定向、wget/curl 下载落盘）。读目标不在此管：
      读命令的读目标（cat/grep/wget -O- 等的文件）应已由 prep.sh 建好。
    对「写新建」用例删除目标文件是关键——否则磁盘残留会让 read_before_write
    判「写已有未读」→ 预期 Allow 的新建用例误判 Deny（如 allow-65/66/78、llm-06）。
    """
    a_next = case.get("input", {}).get("a_next", {})
    action_type = str(a_next.get("action_type") or "").lower()
    detail = a_next.get("action_detail") or ""
    if not detail or action_type not in ("bash", "executebash", "terminal-executebash"):
        return
    # 历史读取路径集合
    history_read = set()
    for h in case.get("input", {}).get("action_history", []) or []:
        hd = h.get("action_detail", "") if isinstance(h, dict) else ""
        if isinstance(hd, dict):
            hd = json.dumps(hd, ensure_ascii=False)
        hd = str(hd).lower()
        if any(kw in hd for kw in profile.read_keywords):
            history_read.update(profile.extract_file_paths(hd))

    # 提取写目标：> 重定向 + wget/curl -O 落盘
    write_targets: list[str] = []
    seg2 = re.sub(r"'[^']*'|\"[^\"]*\"", "", detail)  # 剥引号避免 grep "a>b" 干扰
    for m in re.finditer(r">\s*(?!/dev/null\b)(?!/proc/)(?!/sys/)(?!/run/)([^\s;|&<>'\"]+)", seg2):
        write_targets.append(m.group(1))
    # wget/curl 落盘
    for m in _DL_WRITE_RE.finditer(detail):
        target = (m.group(1) or "").strip()
        if target and target.startswith("/") and target not in ("-", "/dev/null") \
                and not target.startswith(("/dev/", "/proc/", "/sys/", "/run/")):
            write_targets.append(target)
    write_targets = list(dict.fromkeys(p for p in write_targets if p and p.startswith("/")))

    for target in write_targets:
        is_read_before = any(
            target == rp or target.startswith(rp) or rp.startswith(target)
            for rp in history_read
        )
        if is_read_before:
            # 写已有文件 → 确保存在（若不存在创建占位）
            if not os.path.exists(target):
                try:
                    os.makedirs(os.path.dirname(target) or "/", exist_ok=True)
                    with open(target, "w") as fh:
                        fh.write("")
                except Exception:
                    pass
        else:
            # 写新建文件 → 确保不存在（存在则删除，避免被判写已有未读）
            if os.path.exists(target):
                try:
                    os.remove(target)
                except Exception:
                    pass


# ⚠️ 这里原本有一个 `load_all_cases()` + `pytest_generate_tests()` 参数化钩子，
# 声称「自动参数化所有测试用例」。但它挂钩的是名为 `case` 的 fixture，而**没有任何
# 测试声明过这个参数** —— 钩子永不触发，是彻底的死代码，却被误当成"用例会自动跑到"。
# 2026-09 实测：`l1/allow-77-*.json` 在 Python 侧从未执行过（TS 递归扫目录所以跑到了），
# 两端用例总数只是恰好"漏 1 个 + 重复跑 1 个"才相抵。真正驱动 l1/l2/l3 的是
# test_all_cases.py 里的硬编码 parametrize 列表 —— 那条路径有护栏
# （TestCaseRegistration::test_every_l1_l2_l3_case_file_is_registered）。
# 删掉这个钩子，避免再次误导。用到的 `_expand_placeholder` 保留（test_all_cases 会用）。
