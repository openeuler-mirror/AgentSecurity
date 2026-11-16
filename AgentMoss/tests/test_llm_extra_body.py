"""LLM 配置透传（extra_body）的加载行为看护（2026-11 招行「关思考模式」后新增）。"""

from __future__ import annotations

import json

from agent_moss.infra.config import _build_config


def _write_and_build(tmp_path, payload: dict):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return _build_config(payload)


def test_extra_body_loaded(tmp_path):
    cfg = _write_and_build(tmp_path, {
        "llm": {
            "model": "m",
            "api_key": "k",
            "extra_body": {"chat_template_kwargs": {"enable_thinking": False}},
        }
    })
    assert cfg.llm.extra_body == {"chat_template_kwargs": {"enable_thinking": False}}


def test_extra_body_defaults_to_empty(tmp_path):
    cfg = _write_and_build(tmp_path, {"llm": {"model": "m", "api_key": "k"}})
    assert cfg.llm.extra_body == {}


def test_extra_body_non_dict_ignored(tmp_path):
    """写错类型不能拖垮配置加载。"""
    cfg = _write_and_build(tmp_path, {
        "llm": {"model": "m", "api_key": "k", "extra_body": "not-a-dict"}
    })
    assert cfg.llm.extra_body == {}
