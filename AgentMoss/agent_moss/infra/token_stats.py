"""Token 用量统计 — 记录和查询 AgentMoss 每次 LLM 调用的 token 消耗

统计数据存储在 <数据根>/agent_moss_token_stats.json（默认
~/.config/agentmoss/agent_moss_token_stats.json），每次 LLM 调用后追加一条记录。
有 AGENT_MOSS_INSTANCE 时按 instance 隔离到 <数据根>/<instance>/ 子目录。

数据结构：
  每条记录包含 timestamp, session_id, step, model, prompt_tokens,
  completion_tokens, total_tokens

查询支持：
  - 按时间范围查询（今天/近7天/近30天/全部，或起止日期）
  - 按 step 分组汇总（L3 安全判断 / Step2 策略生成）
  - 按 model 分组汇总
  - 按日期分组汇总
  - 趋势（日期×模型二维聚合，供控制台折线图）

文件大小控制：
  - 最多保留 10000 条记录（超过时自动裁剪最早的记录）
  - JSON 文件整体重写（非追加，避免损坏）
"""

import json
import logging
import os
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

# 环境变量：可指定自定义统计文件路径（最高优先级，显式覆盖）
ENV_STATS_PATH = "AGENT_MOSS_TOKEN_STATS_PATH"

# 最大记录条数（超过时自动裁剪）
MAX_RECORDS = 10000


def get_stats_path() -> Path:
    """获取统计文件路径。

    优先级：env AGENT_MOSS_TOKEN_STATS_PATH > 按 instance 隔离的默认路径。
    有 AGENT_MOSS_INSTANCE 时写到 <data_root>/<instance>/agent_moss_token_stats.json，
    无 instance 时写到 <data_root>/agent_moss_token_stats.json。
    """
    env_path = os.getenv(ENV_STATS_PATH)
    if env_path:
        return Path(env_path)
    from .paths import get_token_stats_path
    return get_token_stats_path()


def record_token_usage(
    session_id: str,
    step: str,
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    total_tokens: int,
) -> None:
    """
    记录一次 LLM 调用的 token 用量。

    Args:
        session_id: 会话 ID
        step: 调用步骤（如 "L3_security_judge", "step2_policy_gen"）
        model: 实际使用的模型名称
        prompt_tokens: 输入 token 数
        completion_tokens: 输出 token 数
        total_tokens: 总 token 数
    """
    stats_path = get_stats_path()
    record = {
        "timestamp": datetime.now().isoformat(timespec="milliseconds"),
        "session_id": session_id,
        "step": step,
        "model": model,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
    }

    records = _load_all_records(stats_path)
    records.append(record)

    if len(records) > MAX_RECORDS:
        records = records[-MAX_RECORDS:]

    _save_records(stats_path, records)
    logger.debug(
        "Token usage recorded: step=%s, model=%s, total_tokens=%d",
        step, model, total_tokens,
    )


def _load_all_records(stats_path: Path) -> list[dict]:
    """加载所有统计记录"""
    if not stats_path.exists():
        return []
    try:
        data = json.loads(stats_path.read_text(encoding="utf-8"))
        # 兼容两种格式：纯列表 或 {"records": [...]} 包装
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and "records" in data:
            return data["records"]
        return []
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Token stats file %s read error: %s", stats_path, e)
        return []


def _save_records(stats_path: Path, records: list[dict]) -> None:
    """保存统计记录到文件"""
    stats_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        from . import security_policy as sp
        sp.write_private_text(
            stats_path,
            json.dumps(records, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except OSError as e:
        logger.warning("Token stats file %s write error: %s", stats_path, e)


def _filter_records_by_date(
    records: list[dict],
    days: int = 0,
    start_date: str | None = None,
    end_date: str | None = None,
) -> list[dict]:
    """按时间范围过滤记录。start_date/end_date 优先于 days。"""
    # ts 可能被 fromisoformat 解析成 aware（记录 timestamp 带 tz），而
    # cutoff/start/end 是 naive——比较会崩（offset-naive vs offset-aware）。
    # 统一把 ts 转成 naive（去掉 tz）再比。
    def _naive(ts):
        return ts.replace(tzinfo=None) if ts.utcoffset() is not None else ts

    if start_date or end_date:
        try:
            start_dt = datetime.fromisoformat(start_date) if start_date else datetime.min
            end_dt = (
                datetime.fromisoformat(end_date).replace(
                    hour=23, minute=59, second=59, microsecond=999999
                ) if end_date else datetime.max
            )
        except ValueError:
            start_dt, end_dt = datetime.min, datetime.max
        filtered = []
        for r in records:
            try:
                ts = _naive(datetime.fromisoformat(r["timestamp"]))
                if start_dt <= ts <= end_dt:
                    filtered.append(r)
            except (ValueError, KeyError):
                filtered.append(r)  # 时间解析失败，保留
        return filtered
    elif days > 0:
        cutoff = datetime.now() - timedelta(days=days)
        filtered = []
        for r in records:
            try:
                ts = _naive(datetime.fromisoformat(r["timestamp"]))
                if ts >= cutoff:
                    filtered.append(r)
            except (ValueError, KeyError):
                filtered.append(r)
        return filtered
    return records


def _aggregate(records: list[dict]) -> tuple[int, int, int, dict, dict, dict]:
    """汇总：返回 (total_prompt, total_completion, total_total, by_step, by_model, by_date)。"""
    total_prompt = sum(r.get("prompt_tokens", 0) for r in records)
    total_completion = sum(r.get("completion_tokens", 0) for r in records)
    total_total = sum(r.get("total_tokens", 0) for r in records)

    by_step: dict[str, dict] = {}
    by_model: dict[str, dict] = {}
    by_date: dict[str, dict] = {}

    def _bucket(buckets: dict, key: str, r: dict) -> None:
        entry = buckets.setdefault(key, {
            "prompt_tokens": 0, "completion_tokens": 0,
            "total_tokens": 0, "calls": 0,
        })
        entry["prompt_tokens"] += r.get("prompt_tokens", 0)
        entry["completion_tokens"] += r.get("completion_tokens", 0)
        entry["total_tokens"] += r.get("total_tokens", 0)
        entry["calls"] += 1

    for r in records:
        _bucket(by_step, r.get("step", "unknown"), r)
        _bucket(by_model, r.get("model", "unknown"), r)
        try:
            ts = datetime.fromisoformat(r["timestamp"])
            date_key = ts.strftime("%Y-%m-%d")
        except (ValueError, KeyError):
            date_key = "unknown"
        _bucket(by_date, date_key, r)

    # by_date 按日期倒序
    by_date = dict(sorted(by_date.items(), key=lambda x: x[0], reverse=True))
    return total_prompt, total_completion, total_total, by_step, by_model, by_date


def get_token_stats(
    days: int = 0,
    start_date: str | None = None,
    end_date: str | None = None,
) -> dict:
    """获取 token 用量统计汇总。

    Args:
        days: 查询最近多少天的数据。0 表示全部，1 表示今天，7 表示近7天。
        start_date: 起始日期（YYYY-MM-DD，含当天）。优先于 days。
        end_date: 结束日期（YYYY-MM-DD，含当天全天至 23:59:59）。优先于 days。

    Returns:
        dict: total_prompt_tokens / total_completion_tokens / total_tokens /
        total_calls / by_step / by_model / by_date
    """
    stats_path = get_stats_path()
    records = _load_all_records(stats_path)
    records = _filter_records_by_date(records, days, start_date, end_date)

    total_prompt, total_completion, total_total, by_step, by_model, by_date = _aggregate(records)

    return {
        "total_prompt_tokens": total_prompt,
        "total_completion_tokens": total_completion,
        "total_tokens": total_total,
        "total_calls": len(records),
        "by_step": by_step,
        "by_model": by_model,
        "by_date": by_date,
    }


def get_recent_records(limit: int = 20, offset: int = 0) -> list[dict]:
    """获取最近的 N 条记录（支持 offset 分页）

    记录按时间升序存储，取"最近"需从末尾往前 offset 条再取 limit 条。
    """
    stats_path = get_stats_path()
    records = _load_all_records(stats_path)
    start = max(0, len(records) - offset - limit)
    end = len(records) - offset
    return records[start:end]


def get_recent_records_count() -> int:
    """获取最近记录总数（供前端分页器使用）"""
    stats_path = get_stats_path()
    return len(_load_all_records(stats_path))


def get_token_trend(
    days: int = 0,
    start_date: str | None = None,
    end_date: str | None = None,
) -> dict:
    """获取 Token 消耗趋势（按日期 + 模型二维聚合），供前端折线图渲染。

    Returns:
        dict: dates（排序后的日期列表）/ models（出现的模型名列表）/
        series（{model: {date: total_tokens}} 嵌套映射，前端按 model 各画一条线）
    """
    stats_path = get_stats_path()
    records = _load_all_records(stats_path)
    records = _filter_records_by_date(records, days, start_date, end_date)

    series: dict[str, dict[str, int]] = {}  # model -> {date -> tokens}
    dates_set: set[str] = set()
    for r in records:
        try:
            ts = datetime.fromisoformat(r["timestamp"])
            date_key = ts.strftime("%Y-%m-%d")
        except (ValueError, KeyError):
            continue
        model = r.get("model", "unknown")
        tokens = r.get("total_tokens", 0)
        dates_set.add(date_key)
        series.setdefault(model, {})
        series[model][date_key] = series[model].get(date_key, 0) + tokens

    dates = sorted(dates_set)
    models = sorted(series.keys())
    return {"dates": dates, "models": models, "series": series}


def reset_token_stats() -> None:
    """重置（删除）所有 token 统计记录"""
    stats_path = get_stats_path()
    if stats_path.exists():
        stats_path.unlink()
        logger.info("Token stats reset: %s deleted", stats_path)
