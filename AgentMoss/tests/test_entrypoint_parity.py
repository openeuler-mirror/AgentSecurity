# -*- coding: utf-8 -*-
"""入口层字段透传 / 响应契约的双端一致性看护（2026-10 修正的一批分叉）。

背景：双端在**引擎内部**判定一致（有 `tests/parity/corpus.json` 1401 条 +
`tests/cases/**` 用例看护），但在**入口层**曾经各自丢字段或返回不同结构 ——
引擎单测/parity 语料都照不到，因为它们是直接调 `analyze()` / `runAnalysis()`，
绕过了路由映射。本文件守 Python 侧的入口层。

已修正并在此看护的分叉：
  1. Python HTTP ``/api/v1/analyze`` 丢 ``action_history[].output``
     —— L2 授权（consent）判定看的是**用户对 ask_user_question 的回答**，
     丢字段会让「已授权」判成「未授权」（TS 路由一直是透传的）。
  2. 原始 observable 格式分支同样丢 ``output``（适配器未搬运）。
  3. ``prompt_history`` 必须到达引擎（L2 意图一致性 / L3 语义分析用；
     TS HTTP 曾整体丢这个字段，Python 侧则由本文件的反向用例守住）。
  4. Console ``GET /api/env-overrides`` 少了 ``{overrides: ...}`` 包装 ——
     前端 `loadEnvOverrides()` 读 ``resp?.overrides``，少包装会让
     「环境变量接管了哪些层」恒为空（前端 SPA 与 TS 端字节相同）。
  5. Console ``GET /api/config`` 的 ``L2_2.category_enabled`` 恒 True ——
     控制台关掉 LTL 大类后，前端重新拉 /api/config 会把它显示回「开启」。
"""

import json
import os

import pytest
from fastapi.testclient import TestClient

from agent_moss.server.app import create_app


@pytest.fixture(autouse=True)
def _disable_llm(monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_DISABLE_LLM", "1")
    # 不落盘 policy / 缓存，避免测试在 /tmp 留东西
    monkeypatch.setenv("AGENT_MOSS_SAVE_POLICY", "0")
    monkeypatch.setenv("AGENT_MOSS_DISABLE_CACHE", "1")


@pytest.fixture
def client():
    return TestClient(create_app())


# ==================== 1/2. action_history[].output 透传 ====================


def _capture_engine_input(monkeypatch) -> list[dict]:
    """把 HTTP 路由最终传给引擎的实参截下来（路由内部 `from ..engine.analyzer import
    analyze`，故 patch 模块属性即可生效）。

    用「捕获实参」而不是「看判定结果」的原因：consent 规则（改密/删用户）在默认
    linux 规则下全部被 L1 抢先硬拦（`chpasswd`/`userdel` 等本身就在 L1
    dangerous_commands 里），L2 授权检查到不了 —— 判定结果无法区分 output 有没有传。
    字段透传本身是可观测契约，直接断言实参最准确。
    """
    from agent_moss.engine import analyzer as analyzer_mod

    captured: list[dict] = []

    def _fake_analyze(**kwargs):
        captured.append(kwargs)
        return {
            "decision": "Allow",
            "reason": "stub（本用例只验证入口字段透传）",
            "risk_level": "low",
            "risk_type": "",
            "violated_layers": [],
            "policy": "",
            "violated_policy": "",
            "confidence": 100,
        }

    monkeypatch.setattr(analyzer_mod, "analyze", _fake_analyze)
    return captured


def test_http_analyze_passes_action_history_output(client, monkeypatch):
    """标准格式：action_history 里的 output 必须原样到达引擎（含 name 兼容键）。"""
    captured = _capture_engine_input(monkeypatch)
    r = client.post("/api/v1/analyze", json={
        "session_id": "entry-output",
        "prompt_session": "删掉 olduser",
        "action_history": [
            {"action_type": "ask_user_question", "action_detail": "确认删除？", "output": "确认删除"},
        ],
        "a_next": {"action_type": "bash", "action_detail": "userdel -r olduser"},
        "reason": "",
    })
    assert r.status_code == 200
    assert captured, "路由没有调用引擎"
    hist = captured[0]["action_history"]
    assert hist[0]["output"] == "确认删除", f"output 被入口丢掉：{hist[0]}"
    # name 兼容键保留（logic_rules 有 `action.get("name", action.get("action_type"))` 读法）
    assert hist[0]["name"] == "ask_user_question"
    assert hist[0]["action_detail"] == "确认删除？"


def test_http_analyze_passes_empty_output_as_empty(client, monkeypatch):
    """一拦一放的反面：未回答（output 为空/缺失）时不能凭空造出授权。

    有 output 与没 output 必须**可区分** —— 若入口把缺失字段填成非空默认值，
    consent 检查会把「未授权」误判成「已授权」（fail-open）。
    """
    captured = _capture_engine_input(monkeypatch)
    r = client.post("/api/v1/analyze", json={
        "session_id": "entry-no-output",
        "prompt_session": "删掉 olduser",
        "action_history": [
            {"action_type": "ask_user_question", "action_detail": "确认删除？"},  # 无 output
        ],
        "a_next": {"action_type": "bash", "action_detail": "userdel -r olduser"},
        "reason": "",
    })
    assert r.status_code == 200
    out = captured[0]["action_history"][0].get("output", "")
    assert not str(out).strip(), f"缺失的 output 不应变成非空：{out!r}"


def test_http_analyze_accepts_observable_raw_format(client):
    """原始可观测格式经 HTTP **真的可达**（此前恒 422，适配器是死代码）。

    原始 payload 用 current_action/tool/command/prompt，而 AnalyzeRequest 曾把
    a_next（含 action_type/action_detail）声明为必填 → 真正的原始请求在校验处就
    422，永远走不到 `is_raw_format` 分支。2026-10 把适配挪到**校验之前**
    （models.py 的 model_validator(mode="before")），并补了"既无 a_next 又无
    current_action → 仍 422"的护栏，避免修成静默放行。
    """
    # 一拦：危险动作
    r = client.post("/api/v1/analyze", json={
        "agent_id": "agent-001", "session_id": "obs-1", "prompt": "读一下私钥",
        "current_action": {"tool": "bash", "command": "cat ~/.ssh/id_rsa", "description": "读密钥"},
        "action_history": [{"tool": "read", "command": "ls -la", "output": "..."}],
    })
    assert r.status_code == 200, r.text
    assert r.json()["decision"] == "Deny"

    # 一放：安全动作（确认不是恒 Deny）
    r2 = client.post("/api/v1/analyze", json={
        "session_id": "obs-2", "prompt": "列目录",
        "current_action": {"tool": "bash", "command": "ls -la"},
    })
    assert r2.status_code == 200, r2.text
    assert r2.json()["decision"] == "Allow"


def test_http_analyze_rejects_payload_without_any_action(client):
    """畸形请求（既无 a_next 也无 current_action）必须 422，不能静默放行。"""
    r = client.post("/api/v1/analyze", json={"session_id": "bad", "prompt": "x"})
    assert r.status_code == 422


def test_observable_adapter_keeps_output():
    """原始 observable（syscall）格式：适配器必须把 output 搬到标准字段。

    该格式的 action_history 形如 [{tool, command, output}]（可观测服务采集的真实
    工具返回），历史上适配器只搬 name/action_detail。

    直接测适配器而非走 HTTP：``AnalyzeRequest`` 把 ``action_history[].action_type``
    与 ``a_next`` 都声明为必填，而原始格式恰恰没有这些键 —— 请求会在 pydantic
    校验处 422，走不到 ``is_raw_format`` 分支。适配器本身的行为仍需独立看护。
    """
    from agent_moss.adapters import ObservableAdapter

    adapted = ObservableAdapter().adapt({
        "agent_id": "agent-001",
        "session_id": "raw-entry",
        "prompt": "分析日志",
        "current_action": {"tool": "bash", "command": "ls -la", "description": "列目录"},
        "action_history": [
            {"tool": "ask_user_question", "command": "确认删除？", "output": "确认"},
            {"tool": "read", "command": "cat a.txt"},  # 无 output → 不应凭空造
        ],
    })
    hist = adapted["action_history"]
    assert hist[0]["output"] == "确认", f"适配器丢 output：{hist[0]}"
    assert hist[0]["name"] == "ask_user_question"
    assert "output" not in hist[1], f"缺失的 output 不该被补成字段：{hist[1]}"


# ==================== 3. prompt_history 到达引擎 ====================


def _intent_case_payload(with_history: bool) -> dict:
    """复用 l2/logic-21 的「意图一致性经历史 prompt 命中」场景。

    只看最近一条 prompt（"继续"）会漏报；带上 prompt_history 里最初的读取意图才
    判得出「当前 rm 偏离意图」。即：prompt_history 是否真的到达引擎，直接体现在
    判定结果上 —— 适合做行为断言。
    """
    home = os.path.expanduser("~")
    payload = {
        "session_id": "entry-intent",
        "prompt_session": "继续",
        "action_history": [{"action_type": "read", "action_detail": "cat src/app.ts"}],
        "a_next": {"action_type": "bash", "action_detail": f"rm {home}/src/app.ts"},
        "reason": "清理文件",
    }
    if with_history:
        payload["prompt_history"] = [
            {"text": "请帮我查看 src/app.ts 的内容",
             "actions": [{"action_type": "read", "action_detail": "cat src/app.ts"}]},
            {"text": "继续", "actions": []},
        ]
    return payload


def test_http_analyze_with_prompt_history_flags_intent_deviation(client):
    """一拦：带 prompt_history → 历史读取意图 + 当前删除 → 意图偏离。"""
    r = client.post("/api/v1/analyze", json=_intent_case_payload(with_history=True))
    assert r.status_code == 200
    data = r.json()
    assert data["decision"] == "Deny"
    assert data["risk_type"] == "intent_deviation"
    assert any("L2" in str(x) for x in data["violated_layers"]), data["violated_layers"]


def test_http_analyze_without_prompt_history_loses_intent(client):
    """一放（对照）：不带 prompt_history，只剩「继续」→ 判不出意图偏离。

    这条同时是 prompt_history 透传的**证据**：若入口把它丢了，上面那条也会退化成本条。
    """
    r = client.post("/api/v1/analyze", json=_intent_case_payload(with_history=False))
    assert r.status_code == 200
    data = r.json()
    assert data["risk_type"] != "intent_deviation", (
        "没有 prompt_history 却仍判出 intent_deviation，说明该用例无法区分透传与否"
    )


# ==================== 4/5. Console 响应契约 ====================


def test_console_env_overrides_wrapped(client, monkeypatch):
    """GET /console/api/env-overrides 必须返回 {overrides: {...}}（前端读这个键）。"""
    monkeypatch.setenv("AGENT_MOSS_DISABLE_LLM", "1")
    r = client.get("/console/api/env-overrides")
    assert r.status_code == 200
    body = r.json()
    assert "overrides" in body, f"缺 overrides 包装，前端会读到空：{body}"
    assert body["overrides"]["L3_llm_analysis"]["env_var"] == "AGENT_MOSS_DISABLE_LLM"
    assert body["overrides"]["L3_llm_analysis"]["overridden"] is True


def test_console_config_l22_category_enabled_follows_runtime(client, monkeypatch, tmp_path):
    """GET /console/api/config 的 L2_2.category_enabled 必须跟随 runtime 里的值。

    一拦：runtime 里关掉 LTL 大类 → 接口回报 False（前端据此渲染开关）。
    恒 True 会让用户在控制台关掉后，切回页面又显示「开启」。
    """
    cfg_path = tmp_path / "runtime.json"
    cfg_path.write_text(json.dumps({
        "L2_2": {"ltl_rules": {"category_enabled": False, "rules": []}},
    }, ensure_ascii=False), encoding="utf-8")
    monkeypatch.setenv("AGENT_MOSS_RUNTIME_CONFIG_PATH", str(cfg_path))

    r = client.get("/console/api/config")
    assert r.status_code == 200
    assert r.json()["L2_2"]["category_enabled"] is False


def test_console_config_l22_category_enabled_default_true(client, monkeypatch, tmp_path):
    """一放（对照）：runtime 未给该键时默认 True（不因缺字段而误关）。"""
    cfg_path = tmp_path / "runtime_true.json"
    cfg_path.write_text(json.dumps({"L2_2": {"ltl_rules": {"rules": []}}}, ensure_ascii=False),
                        encoding="utf-8")
    monkeypatch.setenv("AGENT_MOSS_RUNTIME_CONFIG_PATH", str(cfg_path))

    r = client.get("/console/api/config")
    assert r.status_code == 200
    assert r.json()["L2_2"]["category_enabled"] is True
