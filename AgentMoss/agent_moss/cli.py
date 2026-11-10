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
    output = args.output or "input.json"
    with open(output, "w", encoding="utf-8") as f:
        json.dump(template, f, indent=2, ensure_ascii=False)
    print(f"Template written to {output}")


def cmd_analyze(args):
    """Run security analysis on input JSON."""
    from agent_moss.engine.analyzer import analyze
    from agent_moss.profiles import get_profile

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    action_history = data.get("action_history", [])
    a_next = data.get("a_next", {})

    # OS auto-detect
    os_type = data.get("os_type", "")
    profile = get_profile(os_type)

    result = analyze(
        session_id=data.get("session_id", "unknown"),
        prompt_session=data.get("prompt_session", ""),
        action_history=action_history,
        a_next=a_next,
        reason=data.get("reason", ""),
        profile=profile,
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
    parser = argparse.ArgumentParser(description="AgentMoss security analysis engine")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    init_parser = subparsers.add_parser("init", help="Generate input.json template")
    init_parser.add_argument("--output", "-o", help="Output file path", default="input.json")

    analyze_parser = subparsers.add_parser("analyze", help="Run security analysis on input JSON")
    analyze_parser.add_argument("input", help="Input JSON file path")
    analyze_parser.add_argument("--output-dir", "-o", help="Output directory for policy/deny files")
    analyze_parser.add_argument("--no-file", action="store_true", help="Only print to stdout, don't write files")

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
    elif args.command == "brain":
        if not args.brain_command:
            print("Brain 子命令：contribute（贡献本地规则/Skill 为 MR）")
            sys.exit(1)
        if args.brain_command == "contribute":
            sys.exit(cmd_brain_contribute(args))
    else:
        parser.print_help()
        sys.exit(1)


def cmd_brain_contribute(args):
    """Brain contribute 入口（延迟导入避免无依赖时 CLI 报错）"""
    from agent_moss.brain.contributor import contribute
    return contribute(args)


if __name__ == "__main__":
    main()
