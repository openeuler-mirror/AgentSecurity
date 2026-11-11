"""看护：`tests/cases_exec/scenario_rules.py`（内嵌副本）必须与引擎判定一致。

为什么需要：`scenario_rules.py` 是**自包含搬运副本**（零第三方依赖，随 tests 目录
分发给客户，让客户只拿 tests 也能跑）。它的用途是"把会被场景规则拦的 allow 命令
从 allow.sh 里剔掉"，判据必须与引擎逐条一致。一旦漂移，客户就会看到
「应放被拦」的假 FAIL —— 而且**在 AgentMoss 仓里跑是好的、在客户那儿才现形**。

本次事故（2026-09-30）：副本里的 `is_literal_text_command` 停留在 2026-09-15
引擎修复**之前**的旧版本 ——
  - 引擎（已修）：整条命令**必须全由 echo/printf 段构成**（段级 `_ECHO_SEG_RE`）
  - 副本（旧）  ：只要任意位置**出现过** echo 就算（`_ECHO_CMD_RE.search`）
于是 `cd /storage/x && ps aux; echo done` 这类**含 echo 的复合命令**被整条当
"纯文本输出"豁免 → 判"不拦" → 留在 allow.sh；而引擎照常按 bank 场景规则 Deny
→ `run_all.sh --layer l1 --scenario bank --use-agentmoss` 实测 6 条「应放被拦」。
副本还漏了引擎的 `| tee/tac/install` 那条检查。

CLAUDE.md 早已写明"改内联字面量豁免逻辑时必须同步改它"—— 口头约定没挡住，
这里用**逐条比对**兜底。
"""

import sys
from pathlib import Path

import pytest

# 副本随 tests 目录分发，不在包内，需显式加路径
_CASES_EXEC = Path(__file__).parent / "cases_exec"
if str(_CASES_EXEC) not in sys.path:
    sys.path.insert(0, str(_CASES_EXEC))

scenario_rules = pytest.importorskip("scenario_rules")

from agent_moss.engine.inline_analyzer import is_literal_text_command as engine_literal


#: 覆盖各类形态：复合并发、管道喂写入消费者、重定向、内联脚本、纯文本。
#: 前 6 条是本次事故的实测样本（副本旧实现全判 True → 漏剔）。
CORPUS = [
    # —— 事故样本：含 echo 的复合命令，必须**不是**纯文本 → 场景判定要拦 ——
    ('cd /storage/Users/currentUser/Workspace/gitcode/AgentMoss && ps aux | grep agent_moss | grep -v grep; '
     'echo ---; ls -la agent_moss.log 2>/dev/null || echo no', True),
    ("echo '0 3 * * * /usr/local/bin/backup.sh' | crontab -", True),
    ("while read line; do echo $line; done < /etc/hosts", True),
    # 注：`find /tmp ... -delete 2>/dev/null; echo cleaned` 曾是第 4 条事故样本，
    # 但 `/dev/null` 加入 bank 白名单后它不再被场景拦（/tmp 与 /dev/null 都在白名单内）
    # → 归入「应保留」组，见下方 CORPUS_ALLOWED。
    # —— 引擎 2026-09-15 修的那类：echo 掩盖真实访问 ——
    ('echo hi && cat ~/.ssh/id_rsa', False),
    ('cat ~/.ssh/id_rsa && echo hi', False),
    ('echo x | tee /etc/cron.d/evil', False),
    ('echo x | install -m 644 /dev/stdin /etc/cron.d/evil', False),
    # —— 真·纯文本输出：应豁免 ——
    ('echo "see /etc/passwd for details"', False),
    ("printf 'path is /etc/shadow\\n'", False),
    ('echo hello', False),
    # —— 真·写文件：重定向目标是真实路径，不是字面量 ——
    ('echo "x" > /etc/cron.d/evil', False),
    ("echo 'x' > '~/.bashrc'", False),
    # —— 丢弃输出：/dev/null 不算写 ——
    ('echo hello > /dev/null', False),
    # —— /tmp 内（bank 白名单内）：不该因路径被拦 ——
    ('cat /tmp/x.txt', False),
    ('echo "x" | tee /tmp/out.txt', False),
    # —— /dev/null 等标准流重定向目标：2026-09-30 起放行（此前被 bank 误拦）——
    ('cat /tmp/x 2>/dev/null', False),
    ('find /tmp -name "fp_*" -delete 2>/dev/null; echo cleaned', False),
    ('command -v foo > /dev/null 2>&1', False),
    ('npm install 2>/dev/null', False),
    # —— /dev 下**其余**文件照常拦（防放宽过头）——
    ('cat /dev/mem', True),
    ('ls /dev/shm', True),
]


def _blocked_by_bank(cmd: str) -> bool:
    return scenario_rules.scenario_blocks_allow(cmd, "bank")


# ==================== ① 副本 vs 引擎：逐条比对 ====================

@pytest.mark.parametrize("cmd", [c for c, _ in CORPUS], ids=range(len(CORPUS)))
def test_literal_text_copy_matches_engine(cmd):
    """副本的 is_literal_text_command 必须与引擎逐条一致。

    这是防漂移的**主看护**：副本可以因为"零依赖"而重写实现，但语义不许分叉。
    """
    assert scenario_rules.is_literal_text_command(cmd) == engine_literal(cmd), (
        f"副本与引擎判定不一致\n  命令: {cmd}\n"
        f"  副本: {scenario_rules.is_literal_text_command(cmd)}\n"
        f"  引擎: {engine_literal(cmd)}"
    )


# ==================== ② 事故回归：这 6 条必须被判"拦" ====================

@pytest.mark.parametrize("cmd", [c for c, expect in CORPUS if expect])
def test_bank_blocked_commands_are_pruned(cmd):
    """会被 bank 场景拦的 allow 命令必须被判定为"该剔除"，否则客户跑出假 FAIL。"""
    assert _blocked_by_bank(cmd), f"应判「拦」但判成「不拦」，会被留在 allow.sh: {cmd}"


@pytest.mark.parametrize(
    "cmd",
    [c for c, expect in CORPUS
     if not expect and ("/tmp" in c or c.startswith(("echo hello", "printf")))],
)
def test_bank_allowed_commands_are_kept(cmd):
    """对照：bank 白名单内 / 纯文本输出的命令**不能**被误剔（防判据过宽）。"""
    assert not _blocked_by_bank(cmd), f"误判「拦」，会被错误移出 allow.sh: {cmd}"


# ==================== ③ 副本自包含性 ====================

def test_copy_stays_dependency_free():
    """副本必须零项目内依赖 —— 它要能只带 tests 目录独立跑（客户场景）。"""
    src = (_CASES_EXEC / "scenario_rules.py").read_text(encoding="utf-8")
    for banned in ("import agent_moss", "from agent_moss"):
        assert banned not in src, f"副本引入了项目内依赖: {banned}"
