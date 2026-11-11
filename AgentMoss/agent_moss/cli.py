#!/usr/bin/env python3
"""Command-line interface for AgentMoss."""

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


def cmd_init(args):
    """Generate an example input.json template (v2: includes os_type and cwd)."""
    template = {
        "session_id": "my-session-001",
        "prompt_session": "Read /var/log/app.log and analyze errors",
        "action_history": [],
        "a_next": {
            "action_type": "bash",
            "action_detail": "cat /var/log/app.log"
        },
        "reason": "Need to read log file for error analysis",
        "os_type": "",
        "cwd": "/home/user/project",
    }
    output = args.output or args.output_pos or "input.json"
    with open(output, "w", encoding="utf-8") as f:
        json.dump(template, f, indent=2, ensure_ascii=False)
    print(f"Template written to {output}")


#: 这些后缀不存在时按「文件路径写错」处理并报错，不当成 shell 命令分析
_FILE_LIKE_SUFFIXES = (".json", ".yaml", ".yml", ".toml")


def _analyze_command(args, command: str) -> int:
    """命令模式：直接分析一条 shell 命令（不读写输入/结果文件）。

    输出纯文本 Deny/Allow（--json 时输出完整 JSON）；退出码 Allow=0 / Deny=1，
    供 shell 直接 if 判断。镜像 TS cli.ts 的同名分支。

    注：会以**当前工作目录**作为 cwd 参与判定（间接文件访问检测要列出目录内容），
    所以不是"零文件 IO"——但不会创建任何文件、也不读输入文件。
    """
    from agent_moss.engine.analyzer import analyze
    from agent_moss.profiles import get_profile

    # ⚠️ cwd 必须传（2026-10 修）：间接文件访问检测（`os.listdir('.')` + 写）要靠
    # cwd 列出目录里的凭据文件（如 .env）才判得出。此前这里不传 → cwd="" → 该检测
    # 整个跳过 → **同一个命令在 CLI 命令模式下 Allow、在文件模式 / HTTP / TS CLI /
    # 客户验收脚本（judge_agentmoss.py 传 cwd）下 Deny**，属漏报。
    # 现在与本文件模式（`data.get("cwd") or str(Path.cwd())`）口径一致。
    result = analyze(
        session_id="cli-command",
        prompt_session="",
        action_history=[],
        a_next={"action_type": "bash", "action_detail": command},
        reason="",
        profile=get_profile(""),
        cwd=str(Path.cwd()),
    )

    if getattr(args, "json", False):
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(result.get("decision", "Deny"))

    return 0 if result.get("decision") == "Allow" else 1


def cmd_analyze(args):
    """Run security analysis on an input JSON file or a raw shell command.

    位置参数是已存在的文件 → 文件模式（行为与既有版本一致）；
    否则 → 命令模式（把参数当 shell 命令直接分析，不读写任何文件）。
    以 .json/.yaml/.yml/.toml 结尾但文件不存在 → 报错退出（避免路径写错被当成命令）。
    """
    from agent_moss.engine.analyzer import analyze
    from agent_moss.profiles import get_profile

    target = args.input

    # ==================== 命令模式 ====================
    if not os.path.isfile(target):
        if os.path.exists(target):
            print(f"错误: 不是文件: {target}", file=sys.stderr)
            return 2
        # 「以 .json/.yaml/... 结尾」只在不含空白时才算"疑似写错的文件路径"。
        # ⚠️ 否则会把**合法命令**当路径：`cat /home/sandbox/config.yaml` 曾被判
        # "文件不存在" 直接退出（2026-09 招行沙箱实测），而 `cat x.yaml` 这类
        # 在读配置的运维里极常见。含空格 = 明显是命令，交命令模式。
        if target.lower().endswith(_FILE_LIKE_SUFFIXES) and " " not in target.strip():
            print(f"错误: 文件不存在: {target}", file=sys.stderr)
            return 2
        if not target.strip():
            print("错误: 输入为空（请给 JSON 文件路径或 shell 命令）", file=sys.stderr)
            return 2
        return _analyze_command(args, target)

    # ==================== 文件模式（原有行为，保持不变）====================
    with open(target, "r", encoding="utf-8") as f:
        data = json.load(f)

    action_history = data.get("action_history", [])
    a_next = data.get("a_next", {})

    # OS auto-detect
    os_type = data.get("os_type", "")
    profile = get_profile(os_type)

    # ⚠️ agent_id / scenario_id / cwd 必须透传。
    # 历史 bug：Python CLI 只传 5 个参数，于是**同一个输入文件两端判定不同**：
    #   - agent_id 缺失  → agent 专属规则（xiaoo/opendesk 的 extra_command_patterns）不加载
    #   - scenario_id 缺失 → 场景定制规则（bank 沙箱边界）不加载
    #   - cwd 缺失（默认 ""）→ 间接文件访问检测直接跳过（logic_rules 里 `if cwd and isdir(cwd)`），
    #     而 TS CLI 传的是 process.cwd() → 该检测在 TS 上生效、Python 上不生效
    result = analyze(
        session_id=data.get("session_id", "unknown"),
        prompt_session=data.get("prompt_session", ""),
        action_history=action_history,
        a_next=a_next,
        reason=data.get("reason", ""),
        profile=profile,
        cwd=data.get("cwd") or str(Path.cwd()),
        agent_id=data.get("agent_id", ""),
        scenario_id=data.get("scenario_id", ""),
    )

    print(json.dumps(result, indent=2, ensure_ascii=False))

    if not args.no_file:
        session_id = data.get("session_id", "unknown").replace("/", "_")
        out_dir = Path(args.output_dir) if args.output_dir else Path.cwd()
        out_dir.mkdir(parents=True, exist_ok=True)
        if result["decision"] == "Allow":
            policy_path = out_dir / f"{session_id}_policy.toml"
            policy_path.write_text(result.get("policy", ""), encoding="utf-8")
            print(f"Policy written to {policy_path}")
        else:
            deny_path = out_dir / f"{session_id}_deny_reason.txt"
            reason_text = result.get("violated_policy") or result.get("reason", "")
            deny_path.write_text(reason_text, encoding="utf-8")
            print(f"Deny reason written to {deny_path}")

    return 0 if result["decision"] == "Allow" else 1


def cmd_server(args):
    """Start the HTTP API server (supports http and socket modes)."""
    if args.config:
        os.environ["AGENT_MOSS_CONFIG_PATH"] = args.config

    from agent_moss.server.app import run_server

    # --port 0 表示"自动从 9090 开始找空闲端口"，不是字面端口 0
    port = args.port if args.port != 0 else 9090

    run_server(
        host=args.host,
        port=port,
        mode=args.mode,
        socket_path=args.socket,
    )
    return 0


def cmd_install(args):
    """Install systemd service for AgentMoss."""
    if os.geteuid() != 0:
        # 检查 sudo 是否可用
        try:
            subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=5)
        except Exception:
            print("⚠️  无 sudo 权限，跳过 systemd service 安装")
            print("   手动启动：agent-moss server --port 0")
            sys.exit(0)
        # sudo 可用，重执行
        cmd = ["sudo", sys.executable, "-m", "agent_moss.cli", "install"]
        if args.enable:
            cmd.append("--enable")
        print("需要 root 权限安装 systemd service，正在通过 sudo 重新执行...")
        result = subprocess.run(cmd)
        sys.exit(result.returncode)

    # 1. 找到 service 文件
    import importlib.resources as ir
    src = ir.files("agent_moss.data") / "agent_moss.service"
    if not src.exists():
        # 开发模式：回退到 scripts/ 目录
        dev_path = Path(__file__).parent.parent / "scripts" / "agent_moss.service"
        if dev_path.exists():
            src = dev_path
        else:
            print("错误：找不到 agent_moss.service 模板文件", file=sys.stderr)
            sys.exit(1)

    # 2. 找到 agent-moss 命令路径
    agent_moss_bin = shutil.which("agent-moss")
    if not agent_moss_bin:
        # 可能刚装完，用 python -m 方式
        agent_moss_bin = f"{sys.executable} -m agent_moss.cli"
        print(f"未找到 agent-moss 命令，使用 {agent_moss_bin}")

    # 3. 读取模板，替换 ExecStart
    content = src.read_text(encoding="utf-8")
    content = content.replace("__AGENT_MOSS_BIN__", agent_moss_bin)

    # 4. 写入 /etc/systemd/system/
    dst = Path("/etc/systemd/system/agent-moss.service")
    dst.write_text(content, encoding="utf-8")
    dst.chmod(0o644)
    print(f"✅ 已安装 systemd service: {dst}")

    # 4.5 数据归属用户：即使服务以 root 运行（sudo systemctl），也把数据
    # （config / runtime / token）写到"当前用户"目录而非 /root。
    # 通过 AGENT_MOSS_DATA_DIR 注入到 /etc/agent_moss/agent_moss.env
    # （service 的 EnvironmentFile 已读取），让 Path.home() 不依赖运行 UID。
    # 归属用户 = sudo 发起者（SUDO_USER）> 当前登录用户（LOGNAME）> 缺省 root。
    data_owner = os.getenv("SUDO_USER") or os.getenv("LOGNAME") or None
    if data_owner and data_owner not in ("root", ""):
        from pwd import getpwnam
        try:
            owner_home = getpwnam(data_owner).pw_dir
        except KeyError:
            owner_home = None
        if owner_home:
            data_dir = str(Path(owner_home) / ".config" / "agentmoss")
            env_file = Path("/etc/agent_moss/agent_moss.env")
            env_file.parent.mkdir(parents=True, exist_ok=True)
            lines = env_file.read_text(encoding="utf-8").splitlines() if env_file.exists() else []
            lines = [ln for ln in lines if not ln.startswith("AGENT_MOSS_DATA_DIR=")]
            lines.append(f"AGENT_MOSS_DATA_DIR={data_dir}")
            env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
            print(f"✅ 数据归属用户 {data_owner}，数据目录: {data_dir}")

    # 5. daemon-reload
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    print("✅ systemctl daemon-reload 完成")

    # 6. 可选 enable
    if args.enable:
        subprocess.run(["systemctl", "enable", "agent-moss"], check=True)
        print("✅ systemctl enable agent-moss 完成")

    print()
    print("启动服务：  sudo systemctl start agent-moss")
    print("查看状态：  sudo systemctl status agent-moss")
    print("查看日志：  journalctl -u agent-moss -f")


def cmd_status(args):
    """Show AgentMoss service status and port."""
    import urllib.request
    import json as _json
    from datetime import datetime

    # systemd 状态
    systemd_active = False
    systemd_info = ""
    try:
        r = subprocess.run(["systemctl", "is-active", "agent-moss"], capture_output=True, text=True, timeout=5)
        systemd_active = r.returncode == 0 or r.stdout.strip() == "active"
        if systemd_active:
            r2 = subprocess.run(["systemctl", "show", "agent-moss", "--property=MainPID,ActiveEnterTimestamp,ExecStart"],
                                capture_output=True, text=True, timeout=5)
            for line in r2.stdout.strip().split("\n"):
                if line.startswith("MainPID="):
                    pid = line.split("=", 1)[1]
                    if pid and pid != "0":
                        systemd_info += f"   PID:      {pid}\n"
                elif line.startswith("ActiveEnterTimestamp="):
                    ts = line.split("=", 1)[1].strip()
                    if ts:
                        systemd_info += f"   启动时间: {ts}\n"
                elif line.startswith("ExecStart="):
                    exe = line.split("=", 1)[1].strip()
                    if exe:
                        systemd_info += f"   启动命令: {exe}\n"
    except Exception:
        pass

    # 探测端口（带 instance 归属过滤，与 bridge.py _probe_service_url 一致）
    # 期望 instance：从 env AGENT_MOSS_INSTANCE 读（systemd/install.sh 注入），默认空串。
    # status 命令要避免「systemd 已死但 9090 上有别的 agent 的 agentmoss（instance 不匹配）
    # 却误报运行中」——只认 instance 匹配的实例；若仅有不匹配实例，明确提示归属错配。
    expect_instance = os.getenv("AGENT_MOSS_INSTANCE", "")
    found_port = None
    version = ""
    # 记录探测到的所有 healthy 实例（instance 可能不匹配，用于错配提示）
    other_instances: list[tuple[int, str]] = []
    for port in range(9090, 9096):
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{port}/api/v1/health", method="GET")
            with urllib.request.urlopen(req, timeout=2) as resp:
                data = _json.loads(resp.read().decode("utf-8"))
                if data.get("status") != "healthy":
                    continue
                inst = data.get("instance", "")
                if inst == expect_instance:
                    found_port = port
                    version = data.get("version", "")
                    break
                other_instances.append((port, inst))
        except Exception:
            continue

    if found_port:
        print(f"✅ AgentMoss 服务运行中")
        if expect_instance:
            print(f"   Instance: {expect_instance}")
        print(f"   版本:     {version or '?'}")
        print(f"   端口:     {found_port}")
        print(f"   Console:  http://127.0.0.1:{found_port}/console")
        print(f"   Health:   http://127.0.0.1:{found_port}/api/v1/health")
        if systemd_info:
            print(systemd_info.rstrip())
        elif systemd_active:
            print(f"   Systemd:  active")
        else:
            print(f"   Systemd:  未注册（运行 agent-moss install --enable 安装）")
        # 尝试获取 L3 状态
        try:
            import urllib.request as _ur
            req = _ur.Request(f"http://127.0.0.1:{found_port}/console/api/config", method="GET")
            with _ur.urlopen(req, timeout=3) as resp:
                cfg = _json.loads(resp.read().decode("utf-8"))
                layers = cfg.get("layers", {})
                l1 = "✅ 启用" if layers.get("L1_heuristic") != False else "❌ 禁用"
                l2 = "✅ 启用" if layers.get("L2_logic_rules") != False else "❌ 禁用"
                l3 = "✅ 启用" if layers.get("L3_llm_analysis") != False else "❌ 禁用"
                print(f"   L1 静态检测: {l1}")
                print(f"   L2 逻辑规则: {l2}")
                print(f"   L3 LLM 分析: {l3}")
        except Exception:
            pass
        print()
        print("   启停命令：")
        print("     systemctl start agent-moss   启动")
        print("     systemctl stop agent-moss    停止")
        print("     systemctl restart agent-moss 重启")
        print("     systemctl status agent-moss  状态")
        print("     journalctl -u agent-moss -f  日志")
    elif other_instances:
        # 有 healthy 实例但都不匹配期望 instance —— 明确提示归属错配，不误报运行中
        print(f"❌ AgentMoss 服务未运行（instance={expect_instance or '(空)'}）")
        print(f"   Systemd:  {'active' if systemd_active else 'inactive'}")
        detail = "; ".join(f"端口 {p} (instance={i or '(空)'})" for p, i in other_instances)
        print(f"   ⚠️ 检测到其他 agent 的 agentmoss 实例: {detail}")
        print(f"   这些不属于本实例（instance={expect_instance or '(空)'}），未计入运行状态。")
        print(f"   启动本实例: AGENT_MOSS_INSTANCE={expect_instance or 'xiaoo'} agent-moss server")
    else:
        print(f"❌ AgentMoss 服务未运行")
        if systemd_active:
            print(f"   Systemd:  active 但端口探测不到")
            print(f"   检查日志：journalctl -u agent-moss -n 20 --no-pager")
        else:
            print(f"   启动方式：")
            print(f"     systemctl start agent-moss  （systemd）")
            print(f"     agent-moss server           （前台）")
        sys.exit(1)


def main():
    from agent_moss.__version__ import __version__

    # 规则包契约自检（schema 版本 / 完整性 / 指纹）：启动即打一行指纹，
    # 客户报问题时凭这一行就能确认跑的是哪份规则。
    # 显式指定 AGENT_MOSS_RULES_ROOT 且校验失败 → 抛异常退出（不带着残缺规则运行）。
    # 注意：只写 stderr —— `analyze` 的 stdout 是给调用方/脚本解析的，不能混入别的行。
    try:
        from agent_moss.infra.security_policy import harden_existing_paths
        harden_existing_paths()
        from agent_moss.rules_contract import (
            enforce_rules_contract, format_rules_integrity,
        )
        _rep = enforce_rules_contract()
        if _rep.external:
            print(format_rules_integrity(_rep), file=sys.stderr)
    except RuntimeError as e:
        print(f"❌ {e}", file=sys.stderr)
        sys.exit(2)

    parser = argparse.ArgumentParser(description="AgentMoss security analysis engine")
    # `agent-moss --version` / `-V`：客户确认自己装的是哪个版本用
    # （版本混淆在招行那边真出过：/tmp 产物的解释取决于版本，先让他能报版本号）。
    parser.add_argument("--version", "-V", action="version", version=f"agent-moss {__version__}")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    init_parser = subparsers.add_parser("init", help="Generate input.json template")
    init_parser.add_argument("--output", "-o", help="Output file path", default=None)
    # 位置参数形式也接受（`agent-moss init x.json` 的写法），两种都能用
    init_parser.add_argument("output_pos", nargs="?", default=None, help="Output file path（同 --output）")

    analyze_parser = subparsers.add_parser(
        "analyze", help="Run security analysis on an input JSON file or a raw shell command"
    )
    analyze_parser.add_argument(
        "input",
        help='Input JSON file path, or a shell command string (e.g. agent-moss analyze "cat ~/.ssh/id_rsa")',
    )
    analyze_parser.add_argument("--output-dir", "-o", help="Output directory for policy/deny files")
    analyze_parser.add_argument("--no-file", action="store_true", help="Only print to stdout, don't write files")
    analyze_parser.add_argument(
        "--json",
        action="store_true",
        help="Command mode: print the full JSON result instead of plain Deny/Allow",
    )

    server_parser = subparsers.add_parser("server", help="Start HTTP API server")
    server_parser.add_argument("--host", default="127.0.0.1", help="Listen host (TCP mode)")
    server_parser.add_argument("--port", type=int, default=9090, help="Listen port (TCP mode)")
    server_parser.add_argument("--config", "-c", help="Path to config YAML file")
    server_parser.add_argument(
        "--mode", choices=["http", "socket"], default="http",
        help="Server mode: http (TCP) or socket (Unix Domain Socket)",
    )
    server_parser.add_argument(
        "--socket", "-s",
        default="/var/run/agent_moss/agent_moss.sock",
        help="Unix socket path (socket mode)",
    )

    install_parser = subparsers.add_parser("install", help="Install systemd service for AgentMoss")
    install_parser.add_argument("--enable", action="store_true", help="Enable service on boot (systemctl enable)")

    status_parser = subparsers.add_parser("status", help="Show service status, port and Console URL")

    # rules 子命令（规则目录自查 / 生成模板；2026-10 客户要"够简单"）
    rules_parser = subparsers.add_parser(
        "rules", help="规则目录（extra.json / override.json）：自查与生成模板"
    )
    rules_sub = rules_parser.add_subparsers(dest="rules_command")
    rules_status = rules_sub.add_parser("status", help="打印当前规则目录加载了什么（自查）")
    rules_status.add_argument("--dir", "-d", default=None,
                              help="只看这个目录（默认用 AGENT_MOSS_EXTRA_RULES_DIR 等环境变量）")
    rules_init = rules_sub.add_parser("init", help="生成模板：extra.json + override.json.示例")
    rules_init.add_argument("--dir", "-d", required=True, help="模板写到哪个目录")
    rules_init.add_argument("--force", action="store_true", help="覆盖已存在的模板文件")
    rules_init.add_argument("--with-builtin", action="store_true",
                            help="override.json 写成内置 L1 规则全量拷贝（就地把内置某条删/改时用）")

    # brain 子命令（contribute = 提交本地沉淀为 MR；中心化上传接口在此预留）
    from agent_moss.brain.contributor import add_contribute_parser
    add_contribute_parser(subparsers)

    args = parser.parse_args()

    if args.command == "init":
        cmd_init(args)
    elif args.command == "analyze":
        sys.exit(cmd_analyze(args))
    elif args.command == "server":
        sys.exit(cmd_server(args))
    elif args.command == "install":
        sys.exit(cmd_install(args))
    elif args.command == "status":
        sys.exit(cmd_status(args))
    elif args.command == "rules":
        if not getattr(args, "rules_command", None):
            print("rules 子命令：status（自查规则目录）/ init（生成模板）")
            sys.exit(1)
        sys.exit(cmd_rules(args))
    elif args.command == "brain":
        if not args.brain_command:
            print("Brain 子命令：contribute（贡献本地规则/Skill 为 MR）")
            sys.exit(1)
        if args.brain_command == "contribute":
            sys.exit(cmd_brain_contribute(args))
    else:
        parser.print_help()
        sys.exit(1)


def cmd_rules(args) -> int:
    """`agent-moss rules status|init` —— 规则目录的自查与模板生成。

    为什么做成命令（而不是只写文档）：客户只跑 L1，但"一个目录两个文件名六个类别"
    讲起来仍绕。给他们两条命令就够：**生成模板** + **改完自查**，不用记类别名。
    """
    from agent_moss.rules_tools import init_rules_dir, rules_status_text

    if args.rules_command == "status":
        if args.dir:
            os.environ["AGENT_MOSS_EXTRA_RULES_DIR"] = str(args.dir)
            from agent_moss import rules_loader
            rules_loader.clear_rules_cache()
        print(rules_status_text())
        return 0

    if args.rules_command == "init":
        written = init_rules_dir(args.dir, force=args.force,
                                with_builtin=getattr(args, "with_builtin", False))
        for p in written:
            print(f"已生成: {p}")
        if not written:
            print("（模板已存在，未覆盖；要重新生成加 --force）")
        print()
        print("下一步：")
        print(f"  1) 追加规则：编辑 {Path(args.dir) / 'extra.json'}，把条目加进对应类别的数组里")
        print(f"  2) 覆盖内置：编辑 {Path(args.dir) / 'override.json.示例'}"
              f"（内置 L1 全量拷贝）—— 删掉/改掉不要的那条，然后改名为 override.json")
        print(f"  3) 让 AgentMoss 读这个目录：export AGENT_MOSS_EXTRA_RULES_DIR={args.dir}（重启进程）")
        print(f"  4) 自查：agent-moss rules status")
        return 0
    return 1


def cmd_brain_contribute(args):
    """Brain contribute 入口（延迟导入避免无依赖时 CLI 报错）"""
    from agent_moss.brain.contributor import contribute
    return contribute(args)


if __name__ == "__main__":
    main()
