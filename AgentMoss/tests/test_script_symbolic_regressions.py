"""LiteSE 符号执行回归：通配符/正则/嵌套结构/变量预算。

对应上游反馈的 LS-30 / LS-31 / LS-25 补充 / LS-28 补充。前三个是漏判
（危险命令被剪枝），最后一个是变量表上限未覆盖启动参数。
"""
from agent_moss.engine.script_engine.backends import shell_backend, symbolic


def test_glob_if_keeps_dangerous_command():
    script = '''if [[ "$1" == bak* ]]; then
  rm -rf /opt/data
else
  echo safe
fi
'''
    args = ["bak20260101"]
    assert "rm -rf /opt/data" in (symbolic.symbolic_process(script, args) or "")
    assert "rm -rf /opt/data" in (shell_backend.parse_if(script, args) or "")


def test_regex_if_keeps_dangerous_command():
    script = '''if [[ "$1" =~ ^ba.* ]]; then
  rm -rf /opt/data
else
  echo safe
fi
'''
    args = ["baz"]
    assert "rm -rf /opt/data" in (symbolic.symbolic_process(script, args) or "")
    assert "rm -rf /opt/data" in (shell_backend.parse_if(script, args) or "")


def test_nested_case_keeps_outer_command():
    script = '''MODE=x
case "$MODE" in
  x)
    rm -rf /opt/data
    case "$2" in
      x) echo inner ;;
    esac
    ;;
esac
'''
    out = symbolic.symbolic_process(script, ["run", "x"]) or ""
    assert "rm -rf /opt/data" in out


def test_startup_args_respect_var_budget():
    # 199 个启动参数 + $@/$* = 201 > 200 → 放弃精确分析、回退全文
    args = [f"a{i}" for i in range(199)]
    assert symbolic.symbolic_process("MODE=x\n", args) is None


def test_modify_existing_var_at_budget_continues():
    # 200 个变量填满预算后，修改已有变量不增加表项，不应触发回退
    script = "\n".join([f"V{i}=x" for i in range(200)] + ["V0=y"])
    assert symbolic.symbolic_process(script, None) is not None


def test_branch_selection_reaches_l1_scanner(tmp_path):
    """接口级回归：危险分支必须真正进入 CommandPatternScanner，而不只是内部函数输出。"""
    from agent_moss.engine.heuristic import CommandPatternScanner
    from agent_moss.engine.script_content_analyzer import analyze_script_content
    from agent_moss.profiles.linux import LinuxProfile

    script = '''if [[ "$1" == bak* ]]; then
  rm -rf /opt/data
else
  echo safe
fi
'''
    (tmp_path / "x.sh").write_text(script, encoding="utf-8")
    scanner = CommandPatternScanner(LinuxProfile())
    result = analyze_script_content(
        "bash", "bash x.sh bak20260101", command_scanner=scanner, cwd=str(tmp_path)
    )
    assert result.has_high or result.has_critical


def test_nested_case_inner_dangerous_command():
    """内层 case 的危险分支不能被外层分支切分吞掉（openEuler 回归）。"""
    script = '''case $1 in
  clean)
    case $2 in
      hard) rm -rf ~/.ssh/id_rsa ;;
      soft) echo safe ;;
    esac
    ;;
  backup) echo safe ;;
esac
'''
    out = symbolic.symbolic_process(script, ["clean", "hard"]) or ""
    assert "rm -rf ~/.ssh/id_rsa" in out


def test_nested_if_keeps_outer_command():
    """报告示例的嵌套 if 形态：外层危险命令不能被内层 if 覆盖。"""
    script = '''if [ "$1" = x ]; then
  rm -rf /opt/data
  if [ "$2" = x ]; then
    echo inner
  fi
fi
'''
    out = symbolic.symbolic_process(script, ["x", "x"]) or ""
    assert "rm -rf /opt/data" in out
