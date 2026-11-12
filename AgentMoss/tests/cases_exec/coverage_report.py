#!/usr/bin/env python3
"""场景覆盖量化报告 — 18 个攻击场景 × 判定层

按 `tests/cases/` 中所有 JSON 用例的 `expected_layers` 字段与 `desc`/`scenario`
文本，逐一绑定到 18 个攻击场景，输出覆盖矩阵（每场景 × L1/L2/L3 × Deny/Allow）。
"""
import json, pathlib, sys

REPO = pathlib.Path(__file__).resolve().parent.parent

# ─── 1. 18 场景加载 ───
SCENES = [
    {"num": 1, "name": "敏感凭据访问", "kws": ["credentials", "id_rsa", "id_ed25519", "shadow",
        "passwd(?! -l)", "known_hosts", "secrets", ".aws", ".env", "gnupg", "config.json"]},
    {"num": 2, "name": "数据外泄", "kws": ["exfil", "外传", "data_exfiltration", "curl.*-X POST",
        "wget.*--post", "curl.*-F", "scp.*:", "upload"]},
    {"num": 3, "name": "持久化后门", "kws": ["bashrc", "profile", "zshrc", "authorized_keys",
        "crontab", "sudoers", "systemctl enable", "gitconfig", "gnupg", "persistence",
        "@reboot", "pam"]},
    {"num": 4, "name": "破坏性操作", "kws": ["rm -rf", "dd if", "mkfs", "DROP DATABASE",
        "fork bomb", "2>/dev/null", "破坏"]},
    {"num": 5, "name": "用户账户管理", "kws": ["passwd ", "useradd", "userdel", "chpass", "newusers", "groupdel"]},
    {"num": 6, "name": "权限提升", "kws": ["chmod 777", "chmod u+s", "chmod 4755", "setuid",
        "sudo ", "docker", "privilege_escalation", "chown "]},
    {"num": 7, "name": "远程代码执行", "kws": ["远程代码", "pipe bash", "| bash", "| sh",
        "chmod +x", "base64.*|.*bash", "os.system", "subprocess"]},
    {"num": 8, "name": "横向移动", "kws": ["ssh ", "scp ", "nmap", "masscan", "lateral", "横向",
        "StrictHostKeyChecking"]},
    {"num": 9, "name": "系统配置篡改", "kws": ["iptables", "systemctl", "nginx", "config_tampering", "系统配置"]},
    {"num": 10, "name": "文件写入/重定向", "kws": ["echo.*>", "重定向", "wget -O", "rsync "]},
    {"num": 11, "name": "意图偏离", "kws": ["意图", "intent_deviation"]},
    {"num": 12, "name": "间接文件访问", "kws": ["indirect", "间接", "os.listdir", "os.walk"]},
    {"num": 13, "name": "读后写违反", "kws": ["read_before_write", "读后写", "未读先写"]},
    {"num": 14, "name": "正常操作/白名单", "kws": ["whitelist", "白名单", "echo.*Hello", "pwd", "正常"]},
    {"num": 15, "name": "供应链攻击", "kws": ["supply_chain", "typosquatting", "供应链"]},
    {"num": 16, "name": "浏览器钓鱼", "kws": ["phish", "钓鱼", "navigate.*http"]},
    {"num": 17, "name": "邮件操作", "kws": ["email_operation", "mail.*delete", "邮箱"]},
    {"num": 18, "name": "反弹 Shell/工具注入", "kws": ["反弹", "reverse shell", "命令替换",
        "$(touch", "`touch", "tool_injection"]},
    {"num": 19, "name": "资源滥用/拒绝服务", "kws": ["fork.*bomb", "while true", "for.*;;",
        "resource_exhaustion", "DDOS", "yes > /dev/null", "dd.*/dev/zero.*/tmp", "死循环"]},
]


def detect(case: dict) -> list[int]:
    cmd = case.get("input", {}).get("a_next", {}).get("action_detail", "").lower()
    desc = (case.get("desc", "") + " " + case.get("scenario", "")).lower()
    text = cmd + " " + desc
    hits = []
    for s in SCENES:
        for kw in s["kws"]:
            lookup = kw.lower()
            if lookup in text or any(lookup in t for t in [cmd, desc]):
                if lookup in text:
                    hits.append(s["num"])
                    break
    return hits


def scan() -> list[dict]:
    cases = []
    os_root = REPO / "cases" / "os"
    for f in sorted((REPO / "cases").rglob("*.json")):
        if f.name == "README.md":
            continue
        # 平台专属用例（os/windows|macos）不计入覆盖率：它们只在对应平台的规则集下
        # 才有意义，混进来会拉低/扭曲按 Linux 规则统计的覆盖数字（客户口径同此）。
        if f.is_relative_to(os_root):
            continue
        try:
            cases.append(json.loads(f.read_text(encoding="utf-8")))
        except Exception:
            pass
    return cases


def main():
    all_cases = scan()
    sid_to_cases = {s["num"]: [] for s in SCENES}
    for c in all_cases:
        for sid in detect(c):
            if sid in sid_to_cases:
                sid_to_cases[sid].append(c)

    # 等宽对齐：中文字符占 2 列，str.format 只按 1 列算 → 用 wcwidth 计算显示宽度
    # 补足空格，保证数字列右对齐、整表不错位。
    try:
        from wcwidth import wcswidth
    except ImportError:
        # wcwidth 不在 stdlib，缺时退化为按字符数（中文仍会略错位，但不崩）
        def wcswidth(s: str) -> int:
            return len(s)

    def pad(s: str, width: int, align: str = "left") -> str:
        """按显示宽度（中文=2 列）填充/截断到 width。"""
        cur = wcswidth(s)
        if cur >= width:
            return s
        pad_ch = " " * (width - cur)
        return s + pad_ch if align == "left" else pad_ch + s

    print(f"{pad('#', 4, 'right')}{pad('场景', 24)}{pad('总', 6, 'right')}{pad('L1用例', 8, 'right')}{pad('L1拦', 8, 'right')}{pad('L1放', 8, 'right')}{pad('覆盖', 6)}")
    print("-" * 64)
    for s in SCENES:
        cases = sid_to_cases[s["num"]]
        l1_cases = [c for c in cases if any(
            l in str(c.get("expected_layers", []))
            for l in ("L1", "1", "1.1", "1.2")
        ) or (
            "llm_required" not in c or not c["llm_required"]
        )]
        l1_deny = len([c for c in l1_cases if c.get("expected_decision") == "Deny"])
        l1_allow = len([c for c in l1_cases if c.get("expected_decision") == "Allow"])
        # 不依赖 llm 的用例即可被 L1 覆盖
        non_llm = [c for c in cases if not c.get("llm_required")]
        covered = "✅" if len(non_llm) > 0 else "❌"
        print(f"{pad(str(s['num']), 4, 'right')}{pad(s['name'], 24)}"
              f"{pad(str(len(cases)), 6, 'right')}{pad(str(len(non_llm)), 8, 'right')}"
              f"{pad(str(l1_deny), 8, 'right')}{pad(str(l1_allow), 8, 'right')}{pad(covered, 6)}")

    covered = sum(1 for s in SCENES if len([c for c in sid_to_cases[s['num']] if not c.get('llm_required')]) > 0)
    total = len(SCENES)
    print(f"\n  {total} 场景总覆盖: {covered}/{total}（L1 可判占比 {covered*100//total}%）")
    print(f"  无 L1 覆盖的场景:")
    for s in SCENES:
        non_llm = [c for c in sid_to_cases[s["num"]] if not c.get("llm_required")]
        if not non_llm:
            print(f"      ❌ #{s['num']:2d} {s['name']}（全 L3，无法 L1 静态覆盖）")


if __name__ == "__main__":
    main()