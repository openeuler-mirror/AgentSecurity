# -*- coding: utf-8 -*-
"""真实 venv 端到端：先 `python -m build --wheel` 装进干净 venv，再跑五种场景对预期。

发版前跑一次（**光跑 pytest 不够** —— 那些用的是源码树，不是客户真正装的那个 wheel）：

    python3 -m build --wheel -o /tmp/_wheel && python3 -m venv /tmp/amvenv \
        && /tmp/amvenv/bin/pip install /tmp/_wheel/*.whl
    python3 scripts/e2e_rules_dir_venv.py

覆盖：0 纯内置（对照）/ 1 空模板原样放置（应=纯内置）/ 2 追加 / 3 覆盖 / 4 bank 场景覆盖 /
5 追加+覆盖 同时。每条都与预期逐项比对并打印。

用客户同款环境变量（L1-only），对每条断言打印实测结果与是否符合预期。
"""
import json, os, shutil, subprocess, sys, tempfile, textwrap

# venv 里的 python（可用环境变量 E2E_VENV 指定；默认 /tmp/amvenv）
VENV = os.environ.get("E2E_VENV", "/tmp/amvenv/bin/python")
CHILD = textwrap.dedent('''
    import json, os, sys
    from agent_moss.engine.analyzer import analyze
    from agent_moss.profiles import get_profile
    p = get_profile("linux")
    out = {}
    for c in json.loads(os.environ["CMDS"]):
        r = analyze(session_id="s", prompt_session="", action_history=[],
                    a_next={"action_type": "bash", "action_detail": c}, reason="", profile=p)
        out[c] = r["decision"]
    print(json.dumps(out))
''')

def run(cmds, env):
    e = {"PATH": os.environ["PATH"], "HOME": os.environ["HOME"], "PYTHONPATH": "",
         "AGENT_MOSS_DISABLE_LLM": "1", "AGENT_MOSS_DISABLE_LOGIC_RULES": "1",
         "AGENT_MOSS_SAVE_POLICY": "0", "AGENT_MOSS_DISABLE_CACHE": "1",
         "CMDS": json.dumps(cmds)}
    e.update(env)
    tmpdir = tempfile.mkdtemp(prefix="amvenv-")
    e["TMPDIR"] = tmpdir
    res = subprocess.run([VENV, "-c", CHILD], capture_output=True, text=True, env=e, cwd="/tmp")
    shutil.rmtree(tmpdir, ignore_errors=True)
    if res.returncode != 0 or not res.stdout.strip():
        return {"__error__": res.stderr[-400:]}
    return json.loads(res.stdout.strip().splitlines()[-1])

# 判定用的命令集
CMDS = ["cmb_forbidden_tool", "cat /data/hr/k.pem", "cat /etc/sudoers", "rm -rf /",
        "cat /tmp/ok.txt", "cat /home/sandbox/notes.txt", "ls /data/extra", "ssh root@10.0.0.1"]

results = []

def case(name, env, expect):
    got = run(CMDS, env)
    bad = {c: (got.get(c), e) for c, e in expect.items() if got.get(c) != e}
    results.append((name, got, bad))

base = tempfile.mkdtemp(prefix="amrules-")
# ---------- 0) 纯内置（对照） ----------
case("0. 纯内置（无规则目录）", {}, {"rm -rf /": "Deny", "cat /etc/sudoers": "Deny",
                                    "cmb_forbidden_tool": "Allow", "ls /data/extra": "Allow"})

# ---------- 1) 空模板原样拷进去（安全性） ----------
d1 = os.path.join(base, "empty"); os.makedirs(d1)
subprocess.run([VENV, "-m", "agent_moss.cli", "rules", "init", "--dir", d1],
               capture_output=True, env={**os.environ, "PATH": os.environ["PATH"]})
case("1. 空模板原样放置（应=纯内置）", {"AGENT_MOSS_EXTRA_RULES_DIR": d1},
     {"rm -rf /": "Deny", "cat /etc/sudoers": "Deny", "cmb_forbidden_tool": "Allow"})

# ---------- 2) 追加 ----------
d2 = os.path.join(base, "extra"); os.makedirs(d2)
json.dump({"_说明": ["x"], "dangerous_commands": [
    {"pattern": r"\bcmb_forbidden_tool\b", "risk_level": "high",
     "risk_type": "script_execution", "reason": "客户禁用命令"}],
    "sensitive_path_access": [{"path": "/data/hr", "risk_level": "high", "desc": "HR",
                               "deny_mode": "deny_both"}]},
    open(os.path.join(d2, "extra.json"), "w"), ensure_ascii=False)
case("2. 追加(extra.json)", {"AGENT_MOSS_EXTRA_RULES_DIR": d2},
     {"cmb_forbidden_tool": "Deny", "cat /data/hr/k.pem": "Deny",   # 新增生效
      "rm -rf /": "Deny", "cat /etc/sudoers": "Deny"})               # 内置保留

# ---------- 3) 覆盖 ----------
d3 = os.path.join(base, "override"); os.makedirs(d3)
json.dump({"_说明": ["x"], "sensitive_path_access": [
    {"path": "/data/hr", "risk_level": "high", "desc": "HR", "deny_mode": "deny_both"}]},
    open(os.path.join(d3, "override.json"), "w"), ensure_ascii=False)
case("3. 覆盖(override.json，只写了敏感路径)", {"AGENT_MOSS_OVERRIDE_RULES_DIR": d3},
     {"cat /data/hr/k.pem": "Deny",          # 我写的生效
      "cat /etc/sudoers": "Allow",           # 该类别被整份替换 → 内置那条不再生效
      "rm -rf /": "Deny",                    # 未写的类别（危险命令）保持内置
      "cmb_forbidden_tool": "Allow"})

# ---------- 4) bank 场景覆盖（客户肯定启用 AGENT_MOSS_SCENARIO） ----------
d4 = os.path.join(base, "bank"); os.makedirs(os.path.join(d4, "scenarios", "bank"))
builtin_bank = json.load(open("/home/hkl/gitcode/AgentMoss/agent_moss/scenarios/bank/rules.json"))
# 把 /data/extra 加进白名单（模拟"某条路径被误拦，客户自己放行"）
p0 = builtin_bank["extra_command_patterns"][0]["pattern"].replace(
    "opt/sandbox(?:\\s|/|$)", "opt/sandbox(?:\\s|/|$)|data/extra(?:\\s|/|$)")
builtin_bank["extra_command_patterns"][0]["pattern"] = p0
json.dump(builtin_bank, open(os.path.join(d4, "scenarios", "bank", "rules.json"), "w"),
          ensure_ascii=False)
case("4. bank 覆盖(scenarios/bank/rules.json)+SCENARIO=bank",
     {"AGENT_MOSS_SCENARIO": "bank", "AGENT_MOSS_OVERRIDE_RULES_DIR": d4},
     {"ls /data/extra": "Allow",             # 新放行的路径
      "cat /home/sandbox/notes.txt": "Allow",  # 原白名单仍放行
      "cat /etc/sudoers": "Deny",            # 白名单外仍拦
      "ssh root@10.0.0.1": "Deny"})          # 禁 ssh 仍在

# ---------- 5) 追加 + 覆盖 同时 ----------
d5 = os.path.join(base, "both"); os.makedirs(d5)
json.dump({"_说明": ["x"], "sensitive_path_access": [
    {"path": "/data/hr", "risk_level": "high", "desc": "HR", "deny_mode": "deny_both"}]},
    open(os.path.join(d5, "override.json"), "w"), ensure_ascii=False)
json.dump({"_说明": ["x"], "dangerous_commands": [
    {"pattern": r"\bcmb_forbidden_tool\b", "risk_level": "high",
     "risk_type": "script_execution", "reason": "客户禁用命令"}]},
    open(os.path.join(d5, "extra.json"), "w"), ensure_ascii=False)
case("5. 追加+覆盖 同时", {"AGENT_MOSS_EXTRA_RULES_DIR": d5, "AGENT_MOSS_OVERRIDE_RULES_DIR": d5},
     {"cat /data/hr/k.pem": "Deny", "cmb_forbidden_tool": "Deny",   # 两者都生效
      "cat /etc/sudoers": "Allow", "rm -rf /": "Deny"})

print("=" * 78)
for name, got, bad in results:
    flag = "✅ 符合预期" if not bad else "❌ 不符合"
    print(f"\n【{name}】{flag}")
    print("   实测:", json.dumps(got, ensure_ascii=False))
    if bad:
        print("   偏差:", json.dumps({k: {"实测": v[0], "预期": v[1]} for k, v in bad.items()},
                                    ensure_ascii=False))
shutil.rmtree(base, ignore_errors=True)
