"""写前读检查必须使用真实路径，不能把大小写不同的文件当成同一个。"""

import pytest

from agent_moss.engine.analyzer import analyze


@pytest.fixture(autouse=True)
def _static_analysis(monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_DISABLE_LLM", "1")
    monkeypatch.setenv("AGENT_MOSS_SAVE_POLICY", "0")


def _analyze(config, profile, action_type, command, history=None):
    return analyze(
        session_id="read-before-write-path-case",
        prompt_session="更新配置文件",
        action_history=history or [],
        a_next={"action_type": action_type, "action_detail": command},
        reason="更新配置",
        config=config,
        profile=profile,
    )


@pytest.mark.parametrize(
    ("action_type", "command"),
    [
        ("bash", "echo value > {target}"),
        ("bash", "echo value | tee {target}"),
        ("bash", "cp /tmp/source.conf {target}"),
        ("file_write", "{target}"),
    ],
)
def test_unread_existing_mixed_case_path_is_denied(
    tmp_path, default_config, linux_profile, action_type, command
):
    target = tmp_path / "AppConfig.conf"
    target.write_text("original\n", encoding="utf-8")

    result = _analyze(
        default_config, linux_profile, action_type, command.format(target=target)
    )

    assert result["decision"] == "Deny"
    assert result["risk_type"] == "read_before_write"
    assert result["violated_layers"] == ["L2.1"]
    assert target.read_text(encoding="utf-8") == "original\n"


def test_reading_other_case_does_not_authorize_existing_linux_file(
    tmp_path, default_config, linux_profile
):
    target = tmp_path / "AppConfig.conf"
    other = tmp_path / "appconfig.conf"
    target.write_text("original\n", encoding="utf-8")
    other.write_text("other\n", encoding="utf-8")
    history = [{"action_type": "bash", "action_detail": f"cat {other}"}]

    result = _analyze(
        default_config, linux_profile, "bash", f"echo value > {target}", history
    )

    assert result["decision"] == "Deny"
    assert result["risk_type"] == "read_before_write"


def test_reading_exact_mixed_case_path_allows_write(
    tmp_path, default_config, linux_profile
):
    target = tmp_path / "AppConfig.conf"
    target.write_text("original\n", encoding="utf-8")
    history = [{"action_type": "bash", "action_detail": f"cat {target}"}]

    result = _analyze(
        default_config, linux_profile, "bash", f"echo value > {target}", history
    )

    assert result["decision"] == "Allow"


def test_new_linux_file_is_not_confused_with_existing_other_case(
    tmp_path, default_config, linux_profile
):
    existing = tmp_path / "appconfig.conf"
    existing.write_text("other\n", encoding="utf-8")
    target = tmp_path / "AppConfig.conf"

    result = _analyze(
        default_config, linux_profile, "bash", f"echo value > {target}"
    )

    assert result["decision"] == "Allow"
    assert not target.exists()
