"""Console「打开配置页后写操作 500」回归测试（2026-10 修）。

**故障**：打开 Console（前端页面加载会 ``GET /console/api/config``）后，
**第一次**点开关返回 200 但把坏内容写进了 ``agent_moss_runtime.json``，
**第二次**点开关起全部 500。

**根因**：``load_runtime_config()`` 返回的是**进程内缓存对象本身**；
``/api/config`` 处理器直接往上写 ``L2_2``（视图结构：``ltl_rules`` 由 dict 变 list，
并多出 ``enabled_via`` / ``description`` 两个**字符串**键）与 ``builtin_only`` /
``rules_mode`` 两个伪层级键 → 污染缓存 → 下一次写操作 ``save_runtime_config()``
把污染落盘 → 再下一次 ``merge_config`` → ``_merge_rule_categories`` 的
"清理源码已移除的类目"分支对 ``enabled_via``(str) 调 ``.get("rules")`` → AttributeError。

**修法**：``get_full_config`` 里 ``cfg = dict(_runtime_for_view())``（浅拷贝）。

> 这是 **Python 独有**的：TS 侧 ``console.get('/api/config', ...)`` 返回
> ``{ ...rc, ... }``，展开本身就是拷贝，所以不受影响。

本文件守三件事：
1. 打开配置页后，**连续多次**写操作全部成功（修之前第 2 次必 500）；
2. 写操作**不污染落盘文件**（无伪层级键、``L2_2.ltl_rules`` 仍是 dict）；
3. 开关**真的生效**（不能为了"不污染"把写功能修坏）。
"""
from __future__ import annotations

import json

import pytest

from agent_moss.infra import rules_mode
from agent_moss.infra import runtime_config as rc


def _reset_caches() -> None:
    rules_mode.reset_cache()
    rc._RUNTIME_CONFIG_CACHE.clear()
    rc._HAS_RUNTIME_CONFIG_CACHE.clear()
    from agent_moss import rules_loader
    rules_loader.clear_rules_cache()
    from agent_moss.profiles import clear_profile_cache
    clear_profile_cache()
    from agent_moss.agents import clear_agent_extensions_cache
    from agent_moss.scenarios import clear_scenario_extensions_cache
    clear_agent_extensions_cache()
    clear_scenario_extensions_cache()
    from agent_moss.infra.config import invalidate_default_config_cache
    invalidate_default_config_cache()


@pytest.fixture
def console_client(tmp_path, monkeypatch):
    """隔离数据目录 + 默认（hot）规则来源模式的 Console 客户端。"""
    runtime = tmp_path / "agent_moss_runtime.json"
    monkeypatch.setenv("AGENT_MOSS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_MOSS_RUNTIME_CONFIG_PATH", str(runtime))
    monkeypatch.setenv("AGENT_MOSS_DISABLE_LLM", "1")
    for k in ("AGENT_MOSS_RULES_MODE", "AGENT_MOSS_RULES_BUILTIN_ONLY",
              "AGENT_MOSS_DISABLE_RULE_HOT_RELOAD", "AGENT_MOSS_EXTRA_RULES_DIR",
              "AGENT_MOSS_OVERRIDE_RULES_DIR", "AGENT_MOSS_CUSTOM_RULES",
              "AGENT_MOSS_SCENARIO"):
        monkeypatch.delenv(k, raising=False)
    _reset_caches()
    try:
        from fastapi.testclient import TestClient
        from agent_moss.server.app import create_app
        with TestClient(create_app()) as client:
            yield client, runtime
    finally:
        _reset_caches()


def _first_l1_rule_id(client) -> str:
    cfg = client.get("/console/api/config").json()
    rules = cfg["L1_rules"]["dangerous_commands"]["rules"]
    assert rules, "内置 L1 危险命令规则不应为空"
    return rules[0]["id"]


def test_viewing_config_then_repeated_writes_all_succeed(console_client):
    """核心回归：打开配置页（GET /api/config）之后，连续 3 次写操作必须全部 200。

    修之前：第 1 次 200（但已写坏文件）、第 2 次起 500。
    """
    client, _ = console_client

    # 前端页面加载时就是这个请求（index.html: `state.config = await api('config')`）
    assert client.get("/console/api/config").status_code == 200
    rid = _first_l1_rule_id(client)

    first = client.put("/console/api/categories/enabled",
                       json={"layer": "L1_rules", "category": "dangerous_commands",
                             "enabled": False})
    assert first.status_code == 200, f"第 1 次写就失败：{first.text[:300]}"

    second = client.put("/console/api/rules/enabled",
                        json={"layer": "L1_rules", "category": "dangerous_commands",
                              "rule_id": rid, "enabled": False})
    assert second.status_code == 200, (
        f"第 2 次写失败（= 修之前的表现）：{second.status_code} {second.text[:300]}")

    third = client.put("/console/api/layers",
                       json={"layer_key": "L2_logic_rules", "enabled": False})
    assert third.status_code == 200, f"第 3 次写失败：{third.text[:300]}"


def test_writes_do_not_pollute_runtime_file(console_client):
    """写操作落盘的内容必须是**干净的 runtime 结构**，不能混入接口层的视图字段。"""
    client, runtime = console_client
    client.get("/console/api/config")
    rid = _first_l1_rule_id(client)
    client.put("/console/api/categories/enabled",
               json={"layer": "L1_rules", "category": "dangerous_commands", "enabled": False})
    client.put("/console/api/rules/enabled",
               json={"layer": "L1_rules", "category": "dangerous_commands",
                     "rule_id": rid, "enabled": False})

    on_disk = json.loads(runtime.read_text(encoding="utf-8"))

    # ① 接口层才有的伪层级键不能落盘（它们会让 merge 把 bool/str 当层级处理）
    for fake in ("builtin_only", "rules_mode"):
        assert fake not in on_disk, (
            f"落盘文件被污染：出现了接口层字段 {fake!r} —— /api/config 又原地改了缓存对象？")

    # ② L2_2 必须是 Category 结构（ltl_rules 为 dict）；成 list 说明视图结构被写进了配置
    l22 = on_disk.get("L2_2") or {}
    assert isinstance(l22.get("ltl_rules"), dict), (
        f"落盘文件被污染：L2_2.ltl_rules 应为 dict（Category 结构），"
        f"实际 {type(l22.get('ltl_rules')).__name__}")

    # ③ 视图结构里才有的元字段也不能出现
    for meta in ("enabled_via", "description"):
        assert meta not in l22, f"落盘文件混入了视图元字段 {meta!r}"


def test_write_still_takes_effect(console_client):
    """反向看护：修"污染"不能把写功能修坏 —— 关掉的规则必须真的关掉。"""
    client, runtime = console_client
    rid = _first_l1_rule_id(client)
    assert client.put("/console/api/rules/enabled",
                      json={"layer": "L1_rules", "category": "dangerous_commands",
                            "rule_id": rid, "enabled": False}).status_code == 200

    on_disk = json.loads(runtime.read_text(encoding="utf-8"))
    rules = on_disk["L1_rules"]["dangerous_commands"]["rules"]
    target = next(r for r in rules if r["id"] == rid)
    assert target["enabled"] is False, "关掉的规则没有真的落盘为 disabled"
    assert target.get("user_disabled") is True, (
        "用户主动禁用必须打 user_disabled 标记（否则下次 merge 会被当成历史污染自动痊愈）")


def test_config_response_still_carries_view_fields(console_client):
    """正向看护：返回值仍要带 L2_2 视图与两个标记（前端依赖），只是不再落盘。"""
    client, _ = console_client
    body = client.get("/console/api/config").json()
    assert "L2_2" in body
    assert isinstance(body["L2_2"].get("ltl_rules"), list), "响应里的 L2_2 应是 list 视图"
    assert "builtin_only" in body and "rules_mode" in body
    assert body["rules_mode"] == "hot"
