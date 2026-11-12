"""归一化规则加载器测试 — 验证 L1/L2/L3 规则数据从 JSON 单一事实源加载。

规则数据统一存放在 agent_moss/rules/ 下（l1/l2/l3_rules.json），Python 与 TS
共用。此测试断言：
1. 三份 JSON 可加载且计数稳定（守护出厂默认，防误删/误改导致漂移）。
2. 加载器产出与 profile 规则对象一致（LinuxProfile 组装正确）。
3. 种子生成（generate_source_defaults）与 JSON 数据一致（无手工双份）。
"""

import json
from pathlib import Path

from agent_moss import rules_loader
from agent_moss.infra import runtime_config
from agent_moss.profiles.linux import LinuxProfile


RULES_DIR = Path(__file__).parent.parent / "agent_moss" / "rules"


def test_three_json_files_exist():
    for name in ("l1_rules.json", "l2_rules.json", "l3_rules.json"):
        p = RULES_DIR / name
        assert p.is_file(), f"缺失归一化规则文件: {name}"


def test_l1_counts_stable():
    l1 = rules_loader.load_l1()
    # 133 = 106 Linux + 27 Windows（2026-09 Windows 适配：Windows 危险命令从
    # windows.py 迁入 JSON 单一事实源，带 "os": "windows" 标记，并补齐 certutil/
    # bitsadmin/mshta/regsvr32/rundll32/Defender 排除项/卷影删除/日志清空等手法）
    # 151 = 106 Linux + 27 Windows + 10 macOS + 8 HarmonyOS（2026-09 鸿蒙适配：
    # bm/aa/param/hdc/begetctl/hilog 等，Toybox 类 Unix 继承 Linux 通用规则只加专属）
    # 155 = 151 + 4 主机级关机/重启（2026-09：shutdown/reboot/halt/poweroff +
    # systemctl poweroff|reboot|isolate 等；Windows 侧 shutdown /s|/r、Stop-Computer）。
    # 它们原先一条都没进特征库（151 条里 0 条覆盖），直接执行 `shutdown -h now`
    # 竟然是 Allow —— 白名单的"逐段判定"只能挡住被挟持的情况，本体还得靠这里。
    # 161 = 155 + 6 危险 kill / 安全服务（2026-09：kill PID 0/1、负 PID、killall5；
    # Windows 侧 taskkill 关键系统进程、taskkill /pid 4、sc/net stop|delete|config
    # 停用 Defender 等安全服务）。这批原先**一条都没进特征库** —— 实测 `kill -9 1`
    # （杀 init，系统直接崩）、`taskkill /f /im lsass.exe`、`sc stop WinDefend` 全是 Allow。
    # 规则一律按命令位置锚定并要求 PID 处于末位，避免把信号选项（kill -9 / -s 0）
    # 误当 PID —— 这正是实现时踩过的坑（kill -9 12345 曾被误拦）。
    # 203 = 179 + 14（2026-09 ASBB 批次7，二分法判定后按「宁可误报不可漏报」加宽）
    # 179 = 161 + 18（2026-09 ASBB FN 修复批次5：资源耗尽——函数式 fork 炸弹/写裸块设备/
    # 巨量循环/超长 sleep/大规模填充；供应链——进程替换下载执行/管道给解释器/包管理器与 git
    # 远端改外部 HTTP 源/子模块外部源/下载后本地装包；提权——usermod 加入高权限组；
    # DB——ALTER TABLE DROP COLUMN/无 WHERE 全表 UPDATE；持久化——at 定时任务放宽时间格式；
    # 侦察——读 /proc/<pid>/environ）。每条均已对 ASBB 全量 1030 条 Allow 用例做零误伤推演。
    # 212 = 203 + 9（2026-09 ASBB Windows 实测：原 `powershell .* -Command \S` 一条
    # 无差别拦下所有 `-Command`，连 `powershell -Command Get-Process` 都拦 → 基准判为误报。
    # 收窄为 9 条「隐蔽/下载执行」判据：编码命令缩写 -e/-enc、隐藏窗口、绕过执行策略、
    # IEX+Download*/WebClient、Download* 方法调用、New-Object Net.WebClient、
    # Convert::FromBase64String、Start-BitsTransfer、Add-Type 反射加载、ADS 备用数据流。
    # 净 +9 = 删 1 加 10。收窄不丢覆盖：语料里靠 -Command 兜底的 4 条 Deny 用例
    # （IWR 下载 .ps1 / Set-MpPreference / -w hidden / schtasks 套 powershell）
    # 分别由既有规则与新规则接住。
    assert len(l1["dangerous_commands"]) == 225  # 历史+批次见 git；+10 = 编码混淆 2 + 内网探测 5（NEW-FN-K/L/N）+ python 内联 3（M07）
    # 51 = 48 通用（`os: "all"`，三平台共用）+ 3 Windows 独有（`os: "windows"`）。
    # 2026-10 修双端分叉：那 3 条原先硬编码在 windows.py，而通用 48 条被标成
    # `os: linux` —— Windows 按 os 过滤后一条不剩、静默回退到那 3 条所在的 14 条
    # 历史副本，TS 端则回退到全部 48 条，两端各有一向漏报。现统一为 JSON 单一事实源。
    # 历史：+1: ignore all security +1: bypass audit（W1 注入降安全指令，ASBB L3 实测暴露漏项）
    assert len(l1["injection_detection"]) == 51
    # 55 条 Linux + 20 条 Windows = 75（2026-09 Windows 适配：Windows 条目迁入
    # JSON 单一事实源，带 "os": "windows" 标记，供双端按平台加载）
    # 91 = 84 + 7（2026-09 ASBB 批次5 凭据补全：.git-credentials / .ssh/id_ecdsa /
    # .ssh/id_dsa / .config/gh/hosts.yml / .docker/config.json / .npmrc / credentials.json）
    # 94 = 91 + 3（2026-10 安全加固：AgentMoss 自身资产的自我保护 ——
    # auth_token / stateful_chains 为 deny_both，policy 缓存为 deny_read）。
    # 这三条补的是"同机其他 agent 直接 cat 就能拿到凭证与历史"的洞。
    # 98 = 94 + 4（2026-10 威胁模型补齐：内置检测逻辑不可读 ——
    # rules/ skills/ agents/ scenarios/ 四个目录 deny_read，
    # 补的是"agent 读走规则即可反向构造绕过"的洞，对应设计说明书 14.4.1）。
    assert len(l1["sensitive_path_access"]) == 98
    # 注：以下为历史累计说明（84 的构成）——
    # +3: HarmonyOS 敏感路径（/data/app、/data/service/el1/public/param、/data/log）；+6: macOS；+20: Windows（SAM/SECURITY/SYSTEM/RegBack/LSA/NTDS/repair/GroupPolicy + 注册表 HKLM\SAM|SECURITY|SYSTEM + .ssh\id_rsa|id_ed25519|authorized_keys + .aws\credentials + .ssh/.aws 目录级 + ProgramData），原 windows.py 硬编码迁入并补 deny_mode


def test_l2_counts_stable():
    l2 = rules_loader.load_l2()
    # 4 = 2 Linux + 2 Windows（2026-09 平台适配：Windows 意图模式
    # del/rmdir/reg delete 从 windows.py 硬编码迁入 JSON 单一事实源）
    assert len(l2["intent_consistency"]) == 4
    assert len(l2["password_modify_consent"]) == 7
    assert len(l2["user_deletion_consent"]) == 5


def test_l3_skills_count():
    l3 = rules_loader.load_l3()
    total = sum(len(v) for v in l3.values() if isinstance(v, dict))
    assert total == 13  # 13 个 skill


def test_profile_loads_from_json():
    """LinuxProfile 各规则属性应从 JSON 加载，计数与 JSON 一致。

    敏感路径 JSON 为 Linux + Windows 共用单一事实源（按 os 字段区分平台），
    故比对前先按 os 过滤出 Linux 子集。
    """
    prof = LinuxProfile()
    l1 = rules_loader.load_l1()
    # 危险命令 JSON 含 Linux + Windows 两套（按 os 字段区分），比对 Linux 子集
    linux_cmds = [
        c for c in l1["dangerous_commands"]
        if str(c.get("os") or "linux").lower() == "linux"
    ]
    assert len(prof.dangerous_commands) == len(linux_cmds)
    # 注入关键词同样按 os 过滤：`all`（通用）+ `linux` 进 Linux，`windows` 独有**不进**。
    # 旧实现不过滤、直接等于 JSON 全长 —— 那正是"通用条目被误标成 linux、Windows
    # 一条不剩"的一半成因（2026-10 修）。
    linux_inj = [
        k for k in l1["injection_detection"]
        if str(k.get("os") or "linux").lower() in ("all", "linux")
    ]
    assert len(prof.injection_keywords) == len(linux_inj)
    assert len(linux_inj) < len(l1["injection_detection"]), (
        "Linux 不应拿到 Windows 独有的注入关键词")
    linux_paths = [
        sp for sp in l1["sensitive_path_access"]
        if str(sp.get("os") or "linux").lower() == "linux"
    ]
    assert len(prof.sensitive_paths) == len(linux_paths)
    # 敏感路径 path 与 JSON 逐条一致（顺序敏感）
    json_paths = [sp["path"] for sp in linux_paths]
    prof_paths = [sp.path for sp in prof.sensitive_paths]
    assert json_paths == prof_paths, "profile 敏感路径与 JSON 顺序/内容不一致"


def test_seed_matches_json_rule_data():
    """generate_source_defaults 的规则数据应完全来自 JSON（非手工双份）。"""
    seed = runtime_config.generate_source_defaults()
    l1 = rules_loader.load_l1()
    # 危险命令 pattern 集合一致（种子含**全平台**，与 JSON 全集比对 —— 平台维度
    # 由各条目的 os 字段承载，种子即 JSON 的镜像，Console 据此显示各平台规则）
    seed_pats = {r["pattern"] for r in seed["L1_rules"]["dangerous_commands"]["rules"]}
    json_pats = {c["pattern"] for c in l1["dangerous_commands"]}
    assert seed_pats == json_pats, "种子危险命令与 JSON 不一致"
    # 注入关键词一致
    seed_kws = {r["keyword"] for r in seed["L1_rules"]["injection_detection"]["rules"]}
    json_kws = {k["keyword"] for k in l1["injection_detection"]}
    assert seed_kws == json_kws, "种子注入关键词与 JSON 不一致"
    # 敏感路径 path + deny_mode + os 一致（带 os：同 path 在不同平台是不同规则，
    # 如 .ssh 目录级 Linux 与 Windows 各一条，缺 os 维度会导致集合去重后数量不符）
    seed_sp = {(r["path"], r["deny_mode"], str(r.get("os") or "linux").lower())
               for r in seed["L1_rules"]["sensitive_path_access"]["rules"]}
    json_sp = {(s["path"], s["deny_mode"], str(s.get("os") or "linux").lower())
               for s in l1["sensitive_path_access"]}
    assert seed_sp == json_sp, "种子敏感路径与 JSON 不一致"

# ==================== 用户覆盖目录 <data_root>/rules/ ====================
#
# 2026-09 修：Python 原先「包内优先」（仅包内文件缺失才看数据目录），而 TS 的
# rules-loader.RULES_DIR_CANDS 首项就是 <data_root>/rules（且有专门测试钉住）——
# 即「把自有规则丢进 <data_root>/rules/」在 TS 生效、Python 静默不生效。
# 招行客户用的是 Python 版，属直接影响客户的缺陷。以下用例双端同款看护。


def _write_override(tmp_path, name, payload):
    """在 <data_root>/rules/ 写一个覆盖文件，并把 data_root 指过去。"""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / name).write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return rules_dir / name


def test_mc_rules_loaded():
    """mc_rules.json 可加载：11 条 LTL/降级规则 + 14 原子命题。"""
    mc = rules_loader.load_mc()
    rules = mc.get("rules", [])
    aps = mc.get("ap_patterns", {})
    assert len(rules) == 9, len(rules)
    ids = [r["id"] for r in rules]
    assert "mc-ltl-001" in ids
    # 全部是 ltl 型（CTL 活性不实现；原 mc-ctl-001 单动作已移除，见 _comment）
    assert all(r["type"] == "ltl" for r in rules)
    assert len(aps) == 14, len(aps)


def test_l22_view_contract():
    """console /api/rules 的 L2_2 只读视图契约（双端对齐）。

    当前只下发 ltl_rules（带 enabled + 人话），不再下发 formal_properties/
    atomic_propositions（引擎检测器/原子命题不以视图形式暴露给 console）。
    """
    from agent_moss.console.router import _get_l2_2_view
    v = _get_l2_2_view()
    assert v["enabled_via"] == "L2_logic_rules"
    assert len(v["ltl_rules"]) == 9
    assert "category_enabled" in v  # 大类开关字段（供前端 LTL 大类开关）
    # 每条规则带结果来源字段
    assert all(k in v["ltl_rules"][0] for k in ("id", "risk_level", "action", "reason", "human", "enabled"))
    # 公式以占位符返回（避免把 AST 泄漏到接口层）
    assert v["ltl_rules"][0]["formula"] == "<公式>"
    # 不再承载引擎检测器/原子命题（前端"形式化"页只展示 LTL 规则）
    assert "atomic_propositions" not in v and "formal_properties" not in v


def test_load_mc_category_disabled_gates_all_rules(monkeypatch):
    """LTL 大类开关：L2_2.ltl_rules.category_enabled=False → load_mc 所有规则 enabled 归 False。

    对齐 L1/L2 的 filter_enabled_rules(category_enabled=False) 语义——大类关 = 整类禁用。
    """
    from agent_moss.infra.runtime_config import update_category_enabled
    from agent_moss.rules_loader import load_mc

    # conftest 的 autouse _isolate_runtime_config 会把 has_runtime_config 恒置 False，
    # 这里局部恢复 True 以覆盖 load_mc 的 runtime 合并分支（否则测不到门控逻辑）。
    monkeypatch.setattr(runtime_config, "has_runtime_config", lambda: True)

    try:
        update_category_enabled("L2_2", "ltl_rules", False)
        mc = load_mc()
        rules = mc.get("rules", [])
        assert len(rules) == 9
        assert all(r.get("enabled", True) is False for r in rules), \
            "category_enabled=False 时所有 LTL 规则应全禁用"
    finally:
        # 还原大类开关，避免污染后续测试
        update_category_enabled("L2_2", "ltl_rules", True)


def test_l22_view_after_toggle_is_list():
    """toggle LTL 规则后，返回给前端的 L2_2.ltl_rules 必须仍是 list（契约）。

    否则前端 renderLtlCard 的 ltl.map() 崩溃（runtime L2_2 是 Category dict）。
    镜像 TS console-routes 同款断言。
    """
    from agent_moss.console.router import _with_l2_2_view
    from agent_moss.infra.runtime_config import update_rule_enabled
    rt = update_rule_enabled("L2_2", "ltl_rules", "mc-ltl-001", False)
    v = _with_l2_2_view(dict(rt))
    l = v["L2_2"]
    assert isinstance(l["ltl_rules"], list), l["ltl_rules"]
    assert len(l["ltl_rules"]) == 9
    target = next(x for x in l["ltl_rules"] if x["id"] == "mc-ltl-001")
    assert target["enabled"] is False
    assert isinstance(target["human"], str) and target["human"]
    # 还原，避免污染后续
    update_rule_enabled("L2_2", "ltl_rules", "mc-ltl-001", True)


# 注：test_data_root_rules_override_builtin / test_override_takes_effect_in_profile /
# test_ltl_seed_follows_override 三个用例测的是**已废除**的语义（把内置同名文件
# 放进 <data_root>/rules/ 即整份替换）。2026-10 与客户确认「一个目录 + 两个固定
# 文件名（override.json / extra.json）」后，这套"按文件名覆盖"的机制整体移除——
# 它能覆盖的类别有限、且客户实测时被"别的名字也能生效？"绕晕。
# 新语义的看护在 tests/test_extra_override_rules_dirs.py。
