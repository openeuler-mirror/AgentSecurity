"""L3 must see incomplete-scan warnings even when scanned nodes look safe."""

from agent_moss.engine.script_content_analyzer import format_script_chain_for_prompt
from agent_moss.engine.script_engine.tracker import RecursiveTracker


def test_safe_prefix_does_not_hide_depth_limit_from_llm(tmp_path):
    for index in range(16):
        content = f"bash ./d{index + 1}.sh\n" if index < 15 else "rm -rf /\n"
        (tmp_path / f"d{index}.sh").write_text(content)
    chain = RecursiveTracker().track(str(tmp_path / "d0.sh"), None, str(tmp_path))
    assert chain.max_depth_reached
    assert len(chain.nodes) == 15
    prompt = format_script_chain_for_prompt(chain)
    assert "递归追踪触达深度上限" in prompt
    assert "未被扫描" in prompt


def test_safe_prefix_does_not_hide_size_limit_from_llm(tmp_path):
    (tmp_path / "entry.sh").write_text("bash ./a.sh\nbash ./b.sh\n")
    (tmp_path / "a.sh").write_text("echo safe\n" * 3)
    (tmp_path / "b.sh").write_text("rm -rf /\n")
    chain = RecursiveTracker(max_total_size=40).track(
        str(tmp_path / "entry.sh"), None, str(tmp_path)
    )
    assert chain.max_size_reached
    assert len(chain.nodes) == 2
    prompt = format_script_chain_for_prompt(chain)
    assert "累计文件大小触达上限" in prompt
    assert "未被完整读取" in prompt
