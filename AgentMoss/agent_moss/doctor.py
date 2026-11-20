"""`agent-moss doctor` —— 部署自检。

目标（2026-11，商用标准 P0）：部署/升级后**一条命令**回答
「现在能不能正常干活、哪里没配好」，而不是等客户跑了半天才发现
「LLM 没配」「规则目录不可读」「数据目录权限不对」。

设计约束：

- **只读**：不修改任何配置/文件，可以随时重复跑。
- **快**：默认不发起网络请求（LLM 连通性要显式 ``--llm``）。
- **可操作**：每个 ⚠️/❌ 都带一句「怎么修」。

退出码：有 ❌ → 1；只有 ⚠️ 或全 ✅ → 0（便于脚本判断）。
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import ssl
import stat
import sys
import time
from urllib.parse import urlsplit
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CheckResult:
    name: str
    status: str  # "ok" | "warn" | "fail"
    detail: str
    hint: str = ""


@dataclass
class DoctorReport:
    results: list[CheckResult] = field(default_factory=list)

    def add(self, name: str, status: str, detail: str, hint: str = "") -> None:
        self.results.append(CheckResult(name, status, detail, hint))

    @property
    def has_failure(self) -> bool:
        return any(r.status == "fail" for r in self.results)


_ICON = {"ok": "✅", "warn": "⚠️ ", "fail": "❌"}


def _check_data_dir(report: DoctorReport) -> Path | None:
    from .infra.paths import get_data_root

    try:
        root = get_data_root()
    except Exception as e:  # noqa: BLE001
        report.add("数据目录", "fail", f"无法解析: {e}", "检查 HOME / AGENT_MOSS_DATA_DIR")
        return None
    if not root.exists():
        report.add(
            "数据目录", "warn", f"{root}（不存在，首次启动会自动创建）",
            "无需处理；若启动失败检查父目录写权限",
        )
        return root
    mode = stat.S_IMODE(root.stat().st_mode)
    if mode & 0o077:
        report.add(
            "数据目录", "warn", f"{root}（权限 {oct(mode)}，其他用户可读）",
            f"chmod 700 {root}",
        )
    else:
        report.add("数据目录", "ok", f"{root}（{oct(mode)}）")
    return root


def _check_writable(path: Path, report: DoctorReport, name: str) -> None:
    try:
        probe = path / ".doctor_write_probe"
        probe.write_text("x", encoding="utf-8")
        probe.unlink()
        report.add(name, "ok", f"{path} 可写")
    except Exception as e:  # noqa: BLE001
        report.add(name, "fail", f"{path} 不可写: {e}", "检查权限 / 磁盘是否满")


def _find_config_path() -> Path | None:
    """按服务的查找顺序定位配置文件（AGENT_MOSS_CONFIG_PATH > 数据目录 config.*）。"""
    explicit = os.getenv("AGENT_MOSS_CONFIG_PATH")
    if explicit:
        return Path(explicit)
    try:
        from .infra.paths import get_config_dir

        base = get_config_dir()
    except Exception:  # noqa: BLE001
        return None
    for suffix in (".json", ".yaml", ".yml", ".toml"):
        candidate = base / f"config{suffix}"
        if candidate.exists():
            return candidate
    return None


def _check_config(report: DoctorReport, data_dir: Path | None) -> dict:
    path = _find_config_path()
    if path is None:
        report.add(
            "配置文件", "warn", "未找到 config.json（首次启动会生成模板）",
            "启动一次服务即可生成，然后填入 llm.api_key",
        )
        return {}
    if not path.exists():
        report.add(
            "配置文件", "warn", f"{path} 不存在（AGENT_MOSS_CONFIG_PATH 指向的文件缺失）",
            "检查环境变量，或去掉它让服务用默认路径",
        )
        return {}
    if path.suffix != ".json":
        report.add("配置文件", "ok", f"{path}（{path.suffix} 格式，未做字段级检查）")
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        report.add("配置文件", "fail", f"{path} 解析失败: {e}", "检查 JSON 语法（尾逗号/注释）")
        return {}
    report.add("配置文件", "ok", str(path))

    llm = data.get("llm") or {}
    model = str(llm.get("model") or "")
    api_key = str(llm.get("api_key") or "")
    env_key = os.getenv("AGENT_MOSS_LLM_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not model:
        report.add("LLM 模型", "warn", "未配置 model", "在 config.json 的 llm.model 填写")
    elif not api_key and not env_key:
        report.add(
            "LLM 模型", "warn", f"model={model}，但未配置 api_key / 环境变量",
            "L3 将不可用（fail-open 放行）；填 llm.api_key 或设 AGENT_MOSS_LLM_API_KEY",
        )
    else:
        report.add("LLM 模型", "ok", f"{model} @ {llm.get('base_url') or '(默认)'}")
    extra = llm.get("extra_body")
    if extra is not None and not isinstance(extra, dict):
        report.add(
            "LLM extra_body", "fail", f"类型非法（{type(extra).__name__}），会被忽略",
            '应为对象，如 {"chat_template_kwargs": {"enable_thinking": false}}',
        )
    return data


def _check_rules(report: DoctorReport) -> None:
    try:
        from .rules_contract import check_rules_assets

        rep = check_rules_assets()
        if rep.ok:
            report.add(
                "规则包", "ok",
                f"契约校验通过（schema v{rep.schema_version}，指纹 {rep.fingerprint}）",
            )
        else:
            report.add(
                "规则包", "fail",
                "；".join(rep.errors[:3]) or "校验未通过",
                "重新安装或检查 AGENT_MOSS_RULES_ROOT",
            )
    except Exception as e:  # noqa: BLE001
        report.add("规则包", "warn", f"契约校验不可用: {e}")
    try:
        from .profiles import get_profile

        profile = get_profile("linux")
        n = len(profile.dangerous_commands or [])
        paths = len(profile.sensitive_paths or [])
        if n == 0:
            report.add(
                "L1 规则", "fail", "危险命令规则为 0 条",
                "规则 JSON 未加载：检查打包完整性 / AGENT_MOSS_RULES_ROOT",
            )
        else:
            report.add("L1 规则", "ok", f"危险命令 {n} 条 / 敏感路径 {paths} 条（linux）")
    except Exception as e:  # noqa: BLE001
        report.add("L1 规则", "fail", f"加载失败: {e}", "检查规则 JSON 是否损坏")


def _check_chain_state(report: DoctorReport) -> None:
    from .engine.formal_engine.chain_state import default_state_db_path

    db = Path(default_state_db_path())
    if not db.exists():
        report.add("链状态库", "ok", "尚未创建（首次有状态分析时生成）")
        return
    size = db.stat().st_size
    wal = Path(str(db) + "-wal")
    wal_size = wal.stat().st_size if wal.exists() else 0
    detail = f"{db}（{size / 1024 / 1024:.1f} MB"
    if wal_size:
        detail += f"，WAL {wal_size / 1024 / 1024:.1f} MB"
    detail += "）"
    if size > 500 * 1024 * 1024:
        report.add(
            "链状态库", "warn", detail,
            "超过 500MB：可停服后删除该文件重建（会丢失跨会话前序链）",
        )
    else:
        report.add("链状态库", "ok", detail)


def _check_disk(report: DoctorReport, data_dir: Path | None) -> None:
    target = data_dir if data_dir and data_dir.exists() else Path.home()
    try:
        usage = shutil.disk_usage(str(target))
        free_gb = usage.free / 1024 / 1024 / 1024
        if free_gb < 1:
            report.add("磁盘空间", "fail", f"{target} 仅剩 {free_gb:.1f} GB", "清理磁盘")
        elif free_gb < 5:
            report.add("磁盘空间", "warn", f"{target} 剩余 {free_gb:.1f} GB", "日志/状态库会持续增长")
        else:
            report.add("磁盘空间", "ok", f"{target} 剩余 {free_gb:.1f} GB")
    except Exception as e:  # noqa: BLE001
        report.add("磁盘空间", "warn", f"无法检查: {e}")


def _check_env(report: DoctorReport) -> None:
    """检查显式设置但取值可疑的环境变量。"""
    problems: list[str] = []
    pools = os.getenv("AGENT_MOSS_POOL_BIZ")
    if pools is not None:
        try:
            if int(pools) == 0:
                problems.append("AGENT_MOSS_POOL_BIZ=0（并发保护已关闭，仅压测时这么设）")
        except ValueError:
            problems.append(f"AGENT_MOSS_POOL_BIZ={pools!r} 不是整数")
    level = os.getenv("AGENT_MOSS_TRACE_LEVEL")
    if level is not None and level.strip().lower() not in ("off", "summary", "full"):
        problems.append(f"AGENT_MOSS_TRACE_LEVEL={level!r} 非法（off/summary/full）")
    fail_mode = os.getenv("AGENT_MOSS_LLM_FAIL_MODE")
    if fail_mode is not None and fail_mode.strip().lower() not in ("fail_open", "fail_closed"):
        problems.append(f"AGENT_MOSS_LLM_FAIL_MODE={fail_mode!r} 非法（fail_open/fail_closed）")
    if problems:
        report.add("环境变量", "warn", "；".join(problems), "检查拼写或是否为压测遗留配置")
    else:
        report.add("环境变量", "ok", "未发现可疑取值")


def _exception_chain(e: BaseException) -> str:
    parts: list[str] = []
    cur: BaseException | None = e
    seen: set[int] = set()
    while cur is not None and id(cur) not in seen and len(parts) < 4:
        seen.add(id(cur))
        parts.append(f"{type(cur).__name__}({str(cur).replace(chr(10), ' ')[:200]})")
        cur = cur.__cause__ or cur.__context__
    return " <- ".join(parts)


def _check_llm_connectivity(report: DoctorReport, config: dict) -> None:
    """显式 ``--llm`` 才测：DNS → TCP → TLS → HTTP 分阶段定位。"""
    from .infra.config import get_default_config
    from .infra.llm_client import call_llm

    cfg = get_default_config()
    if not cfg.llm.api_key and not os.getenv("AGENT_MOSS_LLM_API_KEY"):
        report.add("LLM 连通性", "warn", "未配置 api_key，跳过")
        return
    base_url = cfg.llm.base_url or "https://api.openai.com/v1"
    try:
        u = urlsplit(base_url)
        host = u.hostname or ""
        port = u.port or (443 if u.scheme == "https" else 80)
        shown = f"{u.scheme or 'https'}://{host}{':' + str(u.port) if u.port else ''}{u.path or ''}"
    except Exception as e:  # noqa: BLE001
        report.add("LLM 地址", "fail", f"base_url 无法解析: {e}")
        return
    report.add("LLM 地址", "ok", shown)
    proxies = [n for n in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY") if os.getenv(n)]
    if proxies:
        report.add("LLM 代理", "ok", "已设置: " + ", ".join(proxies) + "（直连阶段可能不代表实际链路）")
    else:
        report.add("LLM 代理", "ok", "未设置（直连）")

    if not proxies:
        t0 = time.monotonic()
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            report.add("LLM DNS", "ok", f"{host} → {len(infos)} 个地址（{(time.monotonic()-t0)*1000:.0f}ms）")
        except Exception as e:  # noqa: BLE001
            report.add("LLM DNS", "fail", f"{host} 解析失败: {_exception_chain(e)}")
            return
        t0 = time.monotonic()
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=5.0)
            report.add("LLM TCP", "ok", f"{host}:{port} 可连接（{(time.monotonic()-t0)*1000:.0f}ms）")
        except Exception as e:  # noqa: BLE001
            report.add("LLM TCP", "fail", f"{host}:{port} 连接失败: {_exception_chain(e)}")
            return
        if u.scheme == "https":
            t0 = time.monotonic()
            try:
                ctx = ssl.create_default_context()
                tls = ctx.wrap_socket(sock, server_hostname=host)
                tls.close()
                sock = None
                report.add("LLM TLS", "ok", f"握手成功（{(time.monotonic()-t0)*1000:.0f}ms）")
            except Exception as e:  # noqa: BLE001
                report.add("LLM TLS", "fail", f"握手失败: {_exception_chain(e)}")
                if sock is not None:
                    sock.close()
                return
        else:
            sock.close()
            sock = None

    t0 = time.monotonic()
    try:
        result = call_llm("只回复两个字：正常", timeout=20.0, config=cfg.llm)
        report.add(
            "LLM HTTP", "ok",
            f"响应正常（{len(result.content)} 字符，tokens {result.prompt_tokens}/{result.completion_tokens}，"
            f"{(time.monotonic()-t0):.1f}s）",
        )
    except Exception as e:  # noqa: BLE001
        report.add(
            "LLM HTTP", "fail", f"请求失败: {_exception_chain(e)}",
            "若 DNS/TCP/TLS 均正常，重点查模型网关 429/5xx/主动断连；否则查网络/代理/证书",
        )


def run_doctor(include_llm: bool = False) -> DoctorReport:
    report = DoctorReport()
    data_dir = _check_data_dir(report)
    if data_dir is not None and data_dir.exists():
        _check_writable(data_dir, report, "数据目录可写")
    config = _check_config(report, data_dir)
    _check_rules(report)
    _check_chain_state(report)
    _check_disk(report, data_dir)
    _check_env(report)
    if include_llm:
        _check_llm_connectivity(report, config)
    return report


def cmd_doctor(args=None) -> int:
    include_llm = bool(getattr(args, "llm", False))
    report = run_doctor(include_llm=include_llm)
    print("AgentMoss 部署自检\n")
    width = max((len(r.name) for r in report.results), default=8)
    for r in report.results:
        icon = _ICON.get(r.status, "?")
        print(f"{icon} {r.name.ljust(width)}  {r.detail}")
        if r.hint and r.status != "ok":
            print(f"   {' ' * width}  → {r.hint}")
    fails = sum(1 for r in report.results if r.status == "fail")
    warns = sum(1 for r in report.results if r.status == "warn")
    print(f"\n结果：{len(report.results)} 项检查，{fails} 个失败，{warns} 个警告")
    if fails:
        print("存在失败项，建议先修复再投产。")
    elif warns:
        print("没有失败项，但有警告，请确认是否可接受。")
    else:
        print("全部通过。")
    return 1 if report.has_failure else 0
