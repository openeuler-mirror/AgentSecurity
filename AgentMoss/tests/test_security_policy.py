"""AgentMoss 自身安全策略的看护（2026-10）。

**设计原则**：所有开关的默认值都等于改造前的行为——存量用户升级后功能与体验不变。
本文件同时守两件事：

1. **默认放行**：不配任何环境变量时，原生客户端、Console 页面、同源请求全部照常；
2. **显式收紧**：配了 Origin 白名单 / token / 路径白名单后，越界一律拒绝。

真实攻击面的复现（任意网页关掉 L1、跨会话历史泄露）见 ``tests/test_security_hardening.py``。
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent_moss.infra import security_policy as sp
from agent_moss.server.app import create_app


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    for name in (
        "AGENT_MOSS_ORIGIN_CHECK", "AGENT_MOSS_CORS_ORIGINS", "AGENT_MOSS_AUTH_TOKEN",
        "AGENT_MOSS_AUTH_TOKEN_FILE", "AGENT_MOSS_AGENT_TOKENS", "AGENT_MOSS_LOG_ROOTS",
        "AGENT_MOSS_REVIEW_PATHS", "AGENT_MOSS_CHAIN_DETAIL", "AGENT_MOSS_MAX_BODY_BYTES",
        "AGENT_MOSS_MAX_INFLIGHT", "AGENT_MOSS_MAX_QUEUE", "AGENT_MOSS_RATE_LIMIT_QPS",
        "AGENT_MOSS_LLM_HOST_ALLOWLIST", "AGENT_MOSS_TRUST_PRIVATE_LLM",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AGENT_MOSS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_MOSS_DISABLE_LLM", "1")
    sp.reset_auth_cache()
    sp.reset_session_sweep()
    sp.reset_queue_tracker()
    yield
    sp.reset_auth_cache()
    sp.reset_session_sweep()
    sp.reset_queue_tracker()


# ==================== 来源校验 ====================

def test_origin_default_open_for_native_clients():
    assert sp.origin_check_enabled() is True
    assert sp.origin_allowed("", "127.0.0.1:9090") is True          # 原生客户端无 Origin
    assert sp.origin_allowed("http://127.0.0.1:9090", "127.0.0.1:9090") is True  # 同源
    assert sp.origin_allowed("https://evil.example", "127.0.0.1:9090") is False  # 跨源


def test_origin_allowlist(monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_CORS_ORIGINS", "app://opendesk, https://internal.example")
    assert sp.origin_allowed("app://opendesk", "127.0.0.1:9090") is True
    assert sp.origin_allowed("https://internal.example", "127.0.0.1:9090") is True
    assert sp.origin_allowed("https://evil.example", "127.0.0.1:9090") is False


def test_origin_check_can_be_disabled(monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_ORIGIN_CHECK", "0")
    assert sp.origin_check_enabled() is False


def test_http_cross_origin_is_rejected():
    client = TestClient(create_app())
    r = client.get("/console/api/layers", headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    # 同源 / 无 Origin 照常
    assert client.get("/console/api/layers").status_code == 200


# ==================== 鉴权 ====================

def test_auth_off_by_default(monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_AUTH_MODE", "off")
    assert sp.auth_enabled() is False
    client = TestClient(create_app())
    assert client.post("/api/v1/analyze", json={
        "session_id": "s", "a_next": {"action_type": "bash", "action_detail": "ls"},
    }).status_code == 200


def test_auth_token_enforced(monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_AUTH_MODE", "auto")
    monkeypatch.setenv("AGENT_MOSS_AUTH_TOKEN", "secret-token")
    client = TestClient(create_app())
    body = {"session_id": "s", "a_next": {"action_type": "bash", "action_detail": "ls"}}
    assert client.post("/api/v1/analyze", json=body).status_code == 401
    assert client.post("/api/v1/analyze", json=body,
                       headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.post("/api/v1/analyze", json=body,
                       headers={"Authorization": "Bearer secret-token"}).status_code == 200
    # 探活永远放行
    assert client.get("/api/v1/health").status_code == 200


def test_auth_token_file(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_MOSS_AUTH_MODE", "auto")
    f = tmp_path / "tok"
    f.write_text("file-token\n", encoding="utf-8")
    monkeypatch.setenv("AGENT_MOSS_AUTH_TOKEN_FILE", str(f))
    assert sp.auth_enabled() is True
    assert sp.check_request_auth({"authorization": "Bearer file-token"}, "/x")[0] is True


def test_per_agent_token_binds_agent_id(monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_AUTH_MODE", "auto")
    monkeypatch.setenv("AGENT_MOSS_AGENT_TOKENS", "xiaoo=tok-x,opendesk=tok-o")
    client = TestClient(create_app())
    body = {"session_id": "s", "agent_id": "xiaoo",
            "a_next": {"action_type": "bash", "action_detail": "ls"}}
    # 用 xiaoo 的 token 声明 opendesk → 拒绝（这就是"仿冒 agent"）
    r = client.post("/api/v1/analyze", json={**body, "agent_id": "opendesk"},
                    headers={"Authorization": "Bearer tok-x"})
    assert r.status_code == 403
    r = client.post("/api/v1/analyze", json=body, headers={"Authorization": "Bearer tok-x"})
    assert r.status_code == 200


def test_principal_hash_not_plaintext():
    h = sp.principal_hash("agent:xiaoo")
    assert h and "xiaoo" not in h and len(h) == 12


# ==================== 路径白名单 ====================

def test_log_roots_and_path_within(tmp_path):
    inside = tmp_path / "sub" / "x.log"
    inside.parent.mkdir()
    inside.write_text("", encoding="utf-8")
    assert sp.path_within(str(inside), [tmp_path]) is True
    assert sp.path_within("/etc/passwd", [tmp_path]) is False
    # 默认包含 home / tmp（文档里的 /tmp/agentmoss.log 必须仍然可用）
    assert sp.path_within("/tmp/agentmoss.log", sp.log_roots()) is True


# ---------- root 下的默认家目录分级判定（2026-11） ----------
# 0.17.0 的 log_roots 白名单默认取 Path.home()；systemd 以 root 跑时它是
# /root，导致真实用户家目录下的 llm_log_path 被判越界（xiaoO hkl.log 无
# [LLM_PROMPT]）。分级规则：显式 env > 单用户自动 > 多用户不猜。

def test_default_home_non_root_unchanged(monkeypatch):
    from agent_moss.infra import paths
    monkeypatch.setattr(paths, "_is_root", lambda: False)
    assert sp._default_home() == Path.home()


def test_default_home_root_explicit_env_wins(monkeypatch):
    from agent_moss.infra import paths
    monkeypatch.setattr(paths, "_is_root", lambda: True)
    monkeypatch.setattr(
        paths, "_resolve_explicit_owner_home", lambda: Path("/home/alice")
    )
    monkeypatch.setattr(
        paths, "_list_owner_homes", lambda: [Path("/home/alice"), Path("/home/bob")]
    )
    assert sp._default_home() == Path("/home/alice")


def test_default_home_root_single_user_auto_detect(monkeypatch):
    """单用户机器：唯一的普通用户就是真实用户，开箱即用。"""
    from agent_moss.infra import paths
    monkeypatch.setattr(paths, "_is_root", lambda: True)
    monkeypatch.setattr(paths, "_resolve_explicit_owner_home", lambda: None)
    monkeypatch.setattr(paths, "_list_owner_homes", lambda: [Path("/home/alice")])
    assert sp._default_home() == Path("/home/alice")


def test_default_home_root_multi_user_does_not_guess(monkeypatch):
    """多用户机器：不猜「第一个 UID>=1000」，保持 /root；靠显式配置授权。"""
    from agent_moss.infra import paths
    monkeypatch.setattr(paths, "_is_root", lambda: True)
    monkeypatch.setattr(paths, "_resolve_explicit_owner_home", lambda: None)
    monkeypatch.setattr(
        paths, "_list_owner_homes", lambda: [Path("/home/alice"), Path("/home/bob")]
    )
    assert sp._default_home() == Path.home()


def test_log_roots_follows_single_user_home(monkeypatch):
    """集成：单用户 + root 时，log_roots 默认包含真实用户家目录。"""
    from agent_moss.infra import paths
    monkeypatch.setattr(paths, "_is_root", lambda: True)
    monkeypatch.setattr(paths, "_resolve_explicit_owner_home", lambda: None)
    monkeypatch.setattr(paths, "_list_owner_homes", lambda: [Path("/home/alice")])
    roots = [str(p) for p in sp.log_roots()]
    assert "/home/alice" in roots
    assert sp.path_within("/home/alice/gitcode/xiaoO/hkl.log", sp.log_roots()) is True


def test_review_roots_default_cover_agent_gate():
    roots = [str(p) for p in sp.review_roots()]
    assert any("agent_gate" in r for r in roots)


def test_review_rejects_outside_path():
    client = TestClient(create_app())
    r = client.post("/api/v1/review", json={"agent_id": "x", "db_path": "/etc/passwd"})
    assert r.status_code == 403


# ==================== 组合链脱敏 ====================

def test_redact_chain_hides_other_sessions():
    chain = [
        ["victim-session", 0, "cat /home/victim/secret.csv", "2026-10-20T10:00:00"],
        ["mine", 1, "nmap 10.0.0.5", "2026-10-20T10:00:01"],
    ]
    # 签名是 (chain, current_instance_id, current_session_id)：实例为空时回退按 session 比较
    out = sp.redact_chain(chain, "", "mine")
    assert out[0][0] == "<other-session>" and out[0][2] == "<已隐藏>"
    assert "secret" not in str(out)
    assert out[1] == chain[1]  # 自己会话原样


def test_redact_chain_can_be_disabled(monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_CHAIN_DETAIL", "full")
    chain = [["victim", 0, "cat secret", "ts"]]
    assert sp.redact_chain(chain, "", "mine") == chain


# ==================== LLM 配置校验 ====================

def test_llm_base_url_validation():
    assert sp.validate_llm_base_url("https://api.example.com/v1")[0] is True
    assert sp.validate_llm_base_url("http://127.0.0.1:11434/v1")[0] is True  # 本地模型默认允许
    assert sp.validate_llm_base_url("file:///etc/passwd")[0] is False
    assert sp.validate_llm_base_url("http://169.254.169.254/latest")[0] is False


def test_llm_allowlist(monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_LLM_HOST_ALLOWLIST", "api.allowed.com")
    assert sp.validate_llm_base_url("https://api.allowed.com/v1")[0] is True
    assert sp.validate_llm_base_url("https://other.com/v1")[0] is False


# ==================== 私有文件 ====================

def test_private_dir_and_file_permissions(tmp_path):
    d = tmp_path / "private"
    assert sp.ensure_private_dir(d) is True
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o700
    f = d / "x.txt"
    sp.write_private_text(f, "hello")
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o600
    assert f.read_text(encoding="utf-8") == "hello"


def test_private_dir_rejects_symlink(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target)
    assert sp.ensure_private_dir(link) is False


# ==================== 限额 ====================

def test_body_size_limit(monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_MAX_BODY_BYTES", "100")
    client = TestClient(create_app())
    big = "x" * 500
    r = client.post("/api/v1/analyze", json={
        "session_id": "s", "a_next": {"action_type": "bash", "action_detail": big},
    })
    assert r.status_code == 413


def test_rate_limit(monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_RATE_LIMIT_QPS", "1")
    client = TestClient(create_app())
    body = {"session_id": "s", "a_next": {"action_type": "bash", "action_detail": "ls"}}
    codes = [client.post("/api/v1/analyze", json=body).status_code for _ in range(5)]
    assert 429 in codes


def test_defaults_are_secure(monkeypatch):
    """默认值按"发布即安全"定：鉴权 auto、有界并发 16、限流 100。

    存量客户跑的是固定老版本，升级本版时统一适配，不再以"保持旧行为"为由
    把防护默认关掉。测试环境由 conftest 统一把 AUTH_MODE 设成 off。
    """
    monkeypatch.setenv("AGENT_MOSS_AUTH_MODE", "off")
    assert sp.origin_check_enabled() is True          # 只拦浏览器跨源
    assert sp.auth_enabled() is False                 # off 模式不要求 token
    assert sp.max_inflight() == 16                    # 有界并发默认开
    assert sp.queue_wait_sec() == 5
    assert sp.rate_limit_qps() == 100                 # 单主体限流默认开
    assert sp.chain_detail_mode() == "redacted"       # 只脱敏跨会话
    assert sp.max_body_bytes() == 16 * 1024 * 1024


# ==================== 默认开启的自动 token ====================

def test_auto_mode_generates_token_file(monkeypatch, tmp_path):
    """默认 auto：首次启动生成 token 文件（0600），之后请求必须带它。"""
    monkeypatch.setenv("AGENT_MOSS_AUTH_MODE", "auto")
    monkeypatch.setenv("AGENT_MOSS_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("AGENT_MOSS_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("AGENT_MOSS_AUTH_TOKEN_FILE", raising=False)

    assert sp.auth_enabled() is True
    p = sp.auto_token_path()
    assert p.is_file()
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    token = p.read_text(encoding="utf-8").strip()
    assert len(token) >= 32

    client = TestClient(create_app())
    body = {"session_id": "s", "a_next": {"action_type": "bash", "action_detail": "ls"}}
    assert client.post("/api/v1/analyze", json=body).status_code == 401
    assert client.post("/api/v1/analyze", json=body,
                       headers={"Authorization": f"Bearer {token}"}).status_code == 200


def test_auto_mode_reuses_existing_token(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_MOSS_AUTH_MODE", "auto")
    monkeypatch.setenv("AGENT_MOSS_DATA_DIR", str(tmp_path))
    p = sp.auto_token_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("fixed-token\n", encoding="utf-8")
    assert sp._auth_token() == "fixed-token"


def test_off_mode_does_not_create_token(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_MOSS_AUTH_MODE", "off")
    monkeypatch.setenv("AGENT_MOSS_DATA_DIR", str(tmp_path))
    assert sp.auth_enabled() is False
    assert not sp.auto_token_path().exists()


# ==================== token 走 fd（不落盘） ====================

def test_auth_token_from_fd(monkeypatch):
    """AGENT_MOSS_AUTH_TOKEN_FD：token 只在管道里，不上磁盘、不进 environ。"""
    import os as _os
    r, w = _os.pipe()
    _os.write(w, b"fd-secret-token\n")
    _os.close(w)
    monkeypatch.setenv("AGENT_MOSS_AUTH_MODE", "auto")
    monkeypatch.setenv("AGENT_MOSS_AUTH_TOKEN_FD", str(r))
    monkeypatch.delenv("AGENT_MOSS_AUTH_TOKEN", raising=False)

    assert sp.auth_enabled() is True
    assert sp._auth_token() == "fd-secret-token"
    assert not sp.auto_token_path().exists(), "走 fd 时不应该再落盘生成 token 文件"

    client = TestClient(create_app())
    body = {"session_id": "s", "a_next": {"action_type": "bash", "action_detail": "ls"}}
    assert client.post("/api/v1/analyze", json=body,
                       headers={"Authorization": "Bearer fd-secret-token"}).status_code == 200
    assert client.post("/api/v1/analyze", json=body).status_code == 401


def test_env_token_takes_priority_over_fd(monkeypatch):
    import os as _os
    r, w = _os.pipe()
    _os.write(w, b"from-fd\n")
    _os.close(w)
    monkeypatch.setenv("AGENT_MOSS_AUTH_MODE", "auto")
    monkeypatch.setenv("AGENT_MOSS_AUTH_TOKEN_FD", str(r))
    monkeypatch.setenv("AGENT_MOSS_AUTH_TOKEN", "from-env")
    assert sp._auth_token() == "from-env"


def _closed_fd():
    """拿一个确定读不了的 fd（读写两端都关掉）。"""
    import os as _os
    r, w = _os.pipe()
    _os.close(r)
    _os.close(w)
    return r


def test_fd_unreadable_is_config_error(monkeypatch, tmp_path):
    """显式给了 fd 却读不到 → 记录配置错误，**不落盘**生成 token。

    绝不静默降级：降级会双输 —— 调用方全部 401（服务等于挂了），
    磁盘上还多一份同用户任何进程都能读的凭证。
    """
    monkeypatch.setenv("AGENT_MOSS_AUTH_MODE", "auto")
    monkeypatch.delenv("AGENT_MOSS_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("AGENT_MOSS_AUTH_TOKEN_FILE", raising=False)
    monkeypatch.setenv("AGENT_MOSS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_MOSS_AUTH_TOKEN_FD", str(_closed_fd()))
    sp.reset_auth_cache()

    assert sp.auth_config_error()
    assert sp._auth_token() == ""
    assert not (tmp_path / "auth_token").exists()


def test_fd_unreadable_fails_closed(monkeypatch, tmp_path):
    """配置坏了也要 fail-closed：除 /api/v1/health 外一律拒绝。"""
    monkeypatch.setenv("AGENT_MOSS_AUTH_MODE", "auto")
    monkeypatch.delenv("AGENT_MOSS_AUTH_TOKEN", raising=False)
    monkeypatch.setenv("AGENT_MOSS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_MOSS_AUTH_TOKEN_FD", str(_closed_fd()))
    sp.reset_auth_cache()

    assert sp.check_request_auth({}, "/api/v1/analyze") == (False, "")
    assert sp.check_request_auth({}, "/api/v1/health") == (True, "")


def test_fd_unreadable_fail_fast_at_startup(monkeypatch, tmp_path):
    """启动时直接退出，不要带病运行。"""
    monkeypatch.setenv("AGENT_MOSS_AUTH_MODE", "auto")
    monkeypatch.delenv("AGENT_MOSS_AUTH_TOKEN", raising=False)
    monkeypatch.setenv("AGENT_MOSS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_MOSS_AUTH_TOKEN_FD", str(_closed_fd()))
    sp.reset_auth_cache()

    import pytest as _pytest
    with _pytest.raises(SystemExit):
        sp.fail_fast_on_auth_error()


# ==================== 目录穿越（设计说明书 14.4 / SEC-08） ====================

def test_is_safe_id():
    from agent_moss.infra.paths import is_safe_id
    for ok in ("xiaoo", "opendesk", "bank", "A1_-", "a" * 64):
        assert is_safe_id(ok) is True, ok
    for bad in ("", "../../etc", "a/b", ".hidden", "a b", "a" * 65, "中文"):
        assert is_safe_id(bad) is False, bad


def test_unsafe_agent_id_returns_none():
    """agent_id 直接拼进 <agents>/<id>/rules.json，非法值必须当作"无专属规则"。"""
    from agent_moss.agents import get_agent_extensions
    for bad in ("../../etc", "../agents/xiaoo", "a/b", "x" * 128):
        assert get_agent_extensions(bad) is None, bad


def test_unsafe_scenario_id_returns_none():
    from agent_moss.scenarios import get_scenario_extensions
    for bad in ("../../etc", "../scenarios/bank", "a/b"):
        assert get_scenario_extensions(bad) is None, bad


def test_scenario_rules_file_never_escapes_rules_dir():
    """resolve_scenario_rules_file 必须永远返回 Path（调用方直接 .is_file()），
    非法 id 返回一个必定不存在的路径，而不是 None（否则调用方 AttributeError）。"""
    from pathlib import Path
    from agent_moss.rules_loader import resolve_scenario_rules_file
    p = resolve_scenario_rules_file("../../etc")
    assert isinstance(p, Path)
    assert not p.is_file()


def test_valid_ids_still_load():
    """放行侧：合法 id 行为不变。"""
    from agent_moss.agents import get_agent_extensions
    from agent_moss.infra.paths import is_safe_id
    assert is_safe_id("xiaoo")
    # xiaoo 有专属规则目录；加载结果是否为空取决于 runtime 配置，这里只要求不抛异常
    get_agent_extensions("xiaoo")


# ==================== 错误详情归一化（14.4.1 / SEC-10） ====================

def test_error_detail_is_generic_by_default(monkeypatch):
    """500 响应不得带出内部路径/配置：默认只回 ref。"""
    monkeypatch.delenv("AGENT_MOSS_ERROR_DETAIL", raising=False)
    from agent_moss.server.routes import _internal_error
    exc = _internal_error(RuntimeError("/home/u/.config/agentmoss/config.json api_key=sk-xxx"))
    assert exc.status_code == 500
    assert "sk-xxx" not in exc.detail
    assert "config.json" not in exc.detail
    assert "ref" in exc.detail


def test_error_detail_full_restores_old_behavior(monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_ERROR_DETAIL", "full")
    from agent_moss.server.routes import _internal_error
    exc = _internal_error(RuntimeError("boom"))
    assert exc.detail == "boom"


# ==================== UDS 权限（14.2） ====================

def test_socket_mode_default_is_0600(monkeypatch):
    monkeypatch.delenv("AGENT_MOSS_SOCKET_MODE", raising=False)
    assert sp.socket_mode() == 0o600


def test_socket_mode_override(monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_SOCKET_MODE", "660")
    assert sp.socket_mode() == 0o660


def test_socket_mode_invalid_falls_back(monkeypatch):
    for bad in ("zzz", "9999", "-1"):
        monkeypatch.setenv("AGENT_MOSS_SOCKET_MODE", bad)
        assert sp.socket_mode() == 0o600, bad


# ==================== 跨会话批量访问信号 ====================

def test_session_sweep_counts_distinct_sessions(monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_SESSION_SWEEP_THRESHOLD", "3")
    monkeypatch.setenv("AGENT_MOSS_SESSION_SWEEP_WINDOW_SEC", "600")
    sp.reset_session_sweep()
    for _ in range(10):
        n, hit = sp.note_session_access("p", "s1")
    assert (n, hit) == (1, False)
    for s in ("s2", "s3"):
        n, hit = sp.note_session_access("p", s)
    assert hit is False and n == 3
    n, hit = sp.note_session_access("p", "s4")
    assert hit is True and n == 4
    assert sp.note_session_access("q", "s9") == (1, False)


def test_session_sweep_deny_mode(monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_SESSION_SWEEP_THRESHOLD", "1")
    monkeypatch.setenv("AGENT_MOSS_SESSION_SWEEP_ACTION", "deny")
    sp.reset_session_sweep()
    client = TestClient(create_app())

    def post(sid):
        return client.post("/api/v1/analyze", json={
            "session_id": sid, "a_next": {"action_type": "bash", "action_detail": "ls"},
        })

    assert post("a").status_code == 200
    assert post("b").status_code == 429


def test_session_sweep_off_by_default_zero_cost():
    assert sp.session_sweep_threshold() == 50
    assert sp.session_sweep_action() == "log"
    sp.reset_session_sweep()
    assert sp.note_session_access("x", "") == (0, False)


# ==================== 恶意排队识别 ====================

def test_queue_abuse_signal_counts_rejects(monkeypatch):
    monkeypatch.setenv("AGENT_MOSS_QUEUE_ABUSE_THRESHOLD", "2")
    monkeypatch.setenv("AGENT_MOSS_QUEUE_ABUSE_WINDOW_SEC", "600")
    sp.reset_queue_tracker()
    assert sp.note_queue_reject("p") == (1, False)
    assert sp.note_queue_reject("p") == (2, False)
    assert sp.note_queue_reject("p") == (3, True)
    # 不同主体互不影响
    assert sp.note_queue_reject("q") == (1, False)


def test_queue_abuse_tracker_threshold(monkeypatch):
    """并发被拒次数超过阈值 → 判定为滥用（中间件据此 429）。

    分池改造后不再有排队，这个计数器改挂在"池并发超限"上；
    中间件的 429 分支读的就是这里返回的第二个值。
    """
    monkeypatch.setenv("AGENT_MOSS_QUEUE_ABUSE_THRESHOLD", "2")
    monkeypatch.setenv("AGENT_MOSS_QUEUE_ABUSE_ACTION", "deny")
    sp.reset_queue_tracker()
    assert sp.note_queue_reject("k") == (1, False)
    assert sp.note_queue_reject("k") == (2, False)   # n > limit 才算滥用
    assert sp.note_queue_reject("k") == (3, True)
    assert sp.queue_abuse_action() == "deny"


def test_queue_abuse_defaults_are_log_only():
    assert sp.queue_abuse_threshold() == 10
    assert sp.queue_abuse_action() == "log"


def test_connection_limits_defaults():
    """连接层 DoS 默认值（slowloris 挡板）。"""
    assert sp.max_connections() == 128
    assert sp.keep_alive_sec() == 5


def test_per_request_llm_can_be_disabled(monkeypatch):
    """严格模式：AGENT_MOSS_ALLOW_PER_REQUEST_LLM=0 时完全不接受请求里的 llm_config。"""
    assert sp.per_request_llm_enabled() is True          # 默认接受（保持原行为）
    monkeypatch.setenv("AGENT_MOSS_ALLOW_PER_REQUEST_LLM", "0")
    assert sp.per_request_llm_enabled() is False


def test_pool_of_classifies_paths():
    """路径分池：Console/review 打满不挤占 analyze 的 biz 池。"""
    assert sp.pool_of("/api/v1/analyze") == "biz"
    assert sp.pool_of("/api/v1/review") == "review"
    assert sp.pool_of("/console/api/config") == "ops"
    assert sp.pool_of("/api/v1/brain/rules") == "ops"
    assert sp.pool_of("/api/v1/health") == "health"
    assert sp.pool_of("/anything-else") == "other"


def test_pool_limits_and_role_quotas_defaults(monkeypatch):
    for k in ("AGENT_MOSS_POOL_BIZ", "AGENT_MOSS_POOL_REVIEW", "AGENT_MOSS_POOL_OPS",
              "AGENT_MOSS_POOL_HEALTH", "AGENT_MOSS_POOL_OTHER",
              "AGENT_MOSS_MAX_INFLIGHT", "AGENT_MOSS_MAX_UNAUTH_INFLIGHT",
              "AGENT_MOSS_MAX_UNAUTH_PER_IP", "AGENT_MOSS_MAX_AGENT_INFLIGHT"):
        monkeypatch.delenv(k, raising=False)
    assert sp.pool_limit("biz") == 16
    assert sp.pool_limit("review") == 1        # 全量回顾必须串行
    assert sp.pool_limit("ops") == 4
    assert sp.pool_limit("health") == 4
    assert sp.unauth_inflight() == 4
    assert sp.unauth_per_ip() == 2
    assert sp.agent_inflight() == 8
    # biz 池兼容旧的 AGENT_MOSS_MAX_INFLIGHT
    monkeypatch.setenv("AGENT_MOSS_MAX_INFLIGHT", "32")
    assert sp.pool_limit("biz") == 32


def test_bound_agent_of():
    assert sp.bound_agent_of("agent:xiaoo") == "xiaoo"
    assert sp.bound_agent_of("tok:abcdef") == ""
    assert sp.bound_agent_of("") == ""
