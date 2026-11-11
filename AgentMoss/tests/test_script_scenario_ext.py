"""看护：脚本内容扫描必须①套用场景/agent 扩展规则 ②剔除 shebang 与整行注释。

两个都是 2026-09-30 实测出来的问题：

**① 场景规则没套到脚本内容上（TS 侧分叉）**
Python 的 `CommandPatternScanner` 是「内置危险命令正则 + extra_command_patterns
（agent/场景）」一起扫；TS 的脚本内容扫描只用 `scanDangerousCommandPatterns`
（只有内置正则）→ **bank 的目录白名单管不到脚本内容**：
    bash p.sh（内容 `cat /etc/passwd`）+ scenario=bank
    → Python Deny、TS Allow
OpenDesk / 鸿蒙用的是 TS 版，等于场景约束在脚本里可绕。

**② shebang / 注释被当成文件访问（两端都错）**
银行场景白名单只列 `/home/sandbox`、`/opt/sandbox`、`/tmp` 与三个标准流设备，
于是 shebang 里的 `/bin/bash`、`/usr/bin/env` 命中「访问白名单外路径」→
**任何带 shebang 的脚本被 `bash x.sh` 调用都 Deny**（客户沙箱里几乎每个脚本都有）。
修法：脚本内容扫描剔除首行 shebang 与整行注释；但 **heredoc 体内不剔**（那是数据，
不是注释），**行尾注释不剔**（`#` 可能在字符串里）。

为什么用专门的测试而不是 `tests/cases/scenario/bank/*.json`：那批用例由
`TestScenarioCases` 自动扫目录执行，**没有逐 case 注入 cwd 的机制**，脚本类用例
（`bash x.sh`）找不到脚本 → 恒 Allow，等于没有看护。这里用显式 cwd 建临时脚本，
断言逐条对齐。
"""

import logging

from agent_moss.engine.analyzer import analyze
from agent_moss.profiles import get_profile

SCRIPTS = {
    # 带 shebang 的正常脚本：剔除 shebang 后无违规内容
    "ok.sh": "#!/bin/bash\necho hello\n",
    # 脚本内容真读白名单外路径
    "outside.sh": "#!/bin/bash\ncat /etc/passwd\n",
    # 危险命令（剔除逻辑不得把它一起剔掉）
    "evil.sh": "#!/bin/bash\nrm -rf /\n",
    # heredoc 体内的 `#` 行是**数据**不是注释，里面的路径必须照常命中
    "heredoc.sh": "#!/bin/bash\ncat <<EOF\n# 见 /etc/passwd\nEOF\necho ok\n",
}


def _run(tmp_path, script: str, scenario: str) -> str:
    for name, body in SCRIPTS.items():
        (tmp_path / name).write_text(body, encoding="utf-8")
    return analyze(
        session_id="script-scenario-ext",
        prompt_session="",
        action_history=[],
        a_next={"action_type": "bash", "action_detail": f"bash {tmp_path / script}"},
        reason="",
        profile=get_profile("linux"),
        cwd=str(tmp_path),
        scenario_id=scenario,
    )["decision"]


# (脚本, 场景, 期望, 说明)
CASES = [
    ("outside.sh", "bank", "Deny", "脚本内容读白名单外路径 → 场景规则要管到脚本内容"),
    ("ok.sh",      "bank", "Allow", "带 shebang 的正常脚本 → shebang 不是文件访问"),
    ("evil.sh",    "bank", "Deny",  "脚本内 rm -rf / → 剔除 shebang/注释不得削弱危险命令拦截"),
    ("heredoc.sh", "bank", "Deny",  "heredoc 体内的 # 行是数据 → 其中的路径必须照常命中"),
    ("outside.sh", "",     "Allow", "对照：不带场景时 /etc/passwd 只是普通读 → 不得被场景规则污染"),
    ("ok.sh",      "",     "Allow", "对照：不带场景的正常脚本"),
]


def test_script_content_respects_scenario_and_skips_shebang(tmp_path, caplog):
    logging.disable(logging.CRITICAL)
    results = []
    for script, scenario, want, desc in CASES:
        got = _run(tmp_path, script, scenario)
        mark = "✅" if got == want else "❌"
        results.append(f"  {mark} {script:12s} scenario={scenario or '(无)':4s} "
                       f"{got:5s} (期望 {want:5s}) {desc}")
        assert got == want, "\n".join(results)
