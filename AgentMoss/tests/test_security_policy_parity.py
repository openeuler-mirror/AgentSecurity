"""安全策略看护 —— 断言 `tests/fixtures/security_policy_cases.json` 金标准。

`tests/fixtures/security_policy_cases.json` 是数据源：逐条断言默认值与判定口径。
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from agent_moss.infra import security_policy as sp

CASES = json.loads(
    (Path(__file__).parent / "fixtures" / "security_policy_cases.json").read_text(encoding="utf-8")
)


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for name in (
        "AGENT_MOSS_ORIGIN_CHECK", "AGENT_MOSS_CORS_ORIGINS", "AGENT_MOSS_AUTH_TOKEN",
        "AGENT_MOSS_AGENT_TOKENS", "AGENT_MOSS_CHAIN_DETAIL", "AGENT_MOSS_MAX_INFLIGHT",
        "AGENT_MOSS_RATE_LIMIT_QPS", "AGENT_MOSS_MAX_BODY_BYTES",
        "AGENT_MOSS_LLM_HOST_ALLOWLIST", "AGENT_MOSS_TRUST_PRIVATE_LLM",
    ):
        monkeypatch.delenv(name, raising=False)
    yield


def test_defaults_match_golden(monkeypatch):
    d = CASES["defaults"]
    assert sp.origin_check_enabled() is d["origin_check"]
    # conftest 为整套测试设了 off；这里先还原成产品默认再断言
    monkeypatch.delenv("AGENT_MOSS_AUTH_MODE", raising=False)
    assert sp.auth_mode() == d["auth_mode"]
    monkeypatch.setenv("AGENT_MOSS_AUTH_MODE", "off")
    assert sp.auth_enabled() is d["auth_enabled_when_off"]
    assert sp.max_inflight() == d["max_inflight"]
    assert sp.queue_wait_sec() == d["queue_wait_sec"]
    assert sp.rate_limit_qps() == d["rate_limit_qps"]
    assert sp.chain_detail_mode() == d["chain_detail"]
    assert sp.max_body_bytes() == d["max_body_bytes"]


@pytest.mark.parametrize("case", CASES["origin"], ids=lambda c: f"{c['origin'] or '(none)'}@{c['host']}")
def test_origin_cases(case):
    assert sp.origin_allowed(case["origin"], case["host"], case["extra"]) is case["expected"]


@pytest.mark.parametrize("case", CASES["redact"], ids=lambda c: f"redact-{c['session']}-{len(c['chain'])}")
def test_redact_cases(case):
    # 签名是 (chain, current_instance_id, current_session_id)：用例按 session 维度构造
    assert sp.redact_chain(case["chain"], "", case["session"]) == case["expected"]


@pytest.mark.parametrize("case", CASES["llm_url"], ids=lambda c: c["url"] or "(empty)")
def test_llm_url_cases(case, monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_LLM_HOST_ALLOWLIST", case["allowlist"])
    ok, _ = sp.validate_llm_base_url(case["url"])
    assert ok is case["expected"]


@pytest.mark.parametrize("case", CASES["path_within"], ids=lambda c: c["path"])
def test_path_within_cases(case):
    mapping = {"home": Path.home(), "tmp": Path(tempfile.gettempdir())}
    roots = [mapping[r] for r in case["roots"]]
    assert sp.path_within(case["path"], roots) is case["expected"]
