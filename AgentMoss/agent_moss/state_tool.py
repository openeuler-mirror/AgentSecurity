"""`agent-moss state` —— 链状态库的查看 / 备份 / 恢复 / 重置。

为什么需要（2026-11 商用标准 P1）：客户问「`stateful_chains.db` 坏了或者
想清空重来，怎么办？」此前只能口头指导手删文件 —— 删之前不知道里面有什么、
删之后没法回滚。这个命令把四个动作固定下来：

    state status            看大小、节点数、agent 分桶
    state backup <file>     一致性备份（先 WAL checkpoint 再复制）
    state restore <file>    从备份恢复（**必须先停服务**）
    state reset --yes       清空重建（保底有 backup 建议）

安全：restore/reset 前如果检测到服务可能正在运行（端口可连），直接拒绝，
避免「一边写一边换文件」导致库损坏。
"""

from __future__ import annotations

import os
import shutil
import socket
import sqlite3
import sys
from pathlib import Path


def _db_path() -> Path:
    base = os.environ.get("AGENT_MOSS_STATE_DIR") or str(Path.home() / ".agentmoss")
    return Path(base) / "stateful_chains.db"


def _service_running(port: int = 9090) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


def _fail_running(port: int) -> int:
    print(
        f"❌ 检测到 127.0.0.1:{port} 可连接，服务可能正在运行。\n"
        "   请先停止服务（systemctl stop agent_moss）再操作，避免库损坏。",
        file=sys.stderr,
    )
    return 1


def cmd_state_status(args) -> int:
    db = _db_path()
    print(f"状态库: {db}")
    if not db.exists():
        print("（尚未创建，首次有状态分析时生成）")
        return 0
    size = db.stat().st_size
    wal = Path(str(db) + "-wal")
    print(f"主库大小: {size / 1024 / 1024:.1f} MB")
    if wal.exists():
        print(f"WAL 大小: {wal.stat().st_size / 1024 / 1024:.1f} MB")
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        tables = {
            r["name"]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        print(f"表: {', '.join(sorted(tables)) or '(无)'}")
        if "chain_meta" in tables:
            rows = conn.execute(
                "SELECT agent_id, updated_at FROM chain_meta ORDER BY updated_at DESC"
            ).fetchall()
            print(f"agent 分桶: {len(rows)}")
            for r in rows[:10]:
                n = conn.execute(
                    "SELECT COUNT(*) AS c FROM chain_nodes WHERE agent_id=?",
                    (r["agent_id"],),
                ).fetchone()["c"]
                print(f"  - {r['agent_id']}: {n} 节点")
        elif "chain_state" in tables:
            rows = conn.execute("SELECT agent_id, updated_at FROM chain_state").fetchall()
            print(f"agent 分桶: {len(rows)}（旧结构，升级后会自动迁移）")
        conn.close()
    except Exception as e:  # noqa: BLE001
        print(f"⚠️ 读取失败（可能正被服务占用）: {e}")
        return 1
    return 0


def cmd_state_backup(args) -> int:
    db = _db_path()
    if not db.exists():
        print(f"❌ 状态库不存在: {db}", file=sys.stderr)
        return 1
    out = Path(args.output)
    if out.exists() and not args.force:
        print(f"❌ 目标已存在: {out}（加 --force 覆盖）", file=sys.stderr)
        return 1
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        # SQLite 在线备份 API：即使服务在跑也能拿到一致快照
        src = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        dst = sqlite3.connect(str(out))
        with dst:
            src.backup(dst)
        dst.close()
        src.close()
        print(f"✅ 已备份到 {out}（{out.stat().st_size / 1024 / 1024:.1f} MB）")
        return 0
    except Exception as e:  # noqa: BLE001
        print(f"❌ 备份失败: {e}", file=sys.stderr)
        return 1


def _port_of(args) -> int:
    """取 --port；<=0 表示跳过「服务是否在跑」的探测（测试/离线场景）。"""
    try:
        return int(getattr(args, "port", 9090))
    except (TypeError, ValueError):
        return 9090


def cmd_state_restore(args) -> int:
    port = _port_of(args)
    if port > 0 and _service_running(port):
        return _fail_running(port)
    src = Path(args.input)
    if not src.exists():
        print(f"❌ 备份文件不存在: {src}", file=sys.stderr)
        return 1
    db = _db_path()
    db.parent.mkdir(parents=True, exist_ok=True)
    # 先挪走现有库（留一份 .bak），再复制
    if db.exists():
        bak = db.with_suffix(db.suffix + ".before-restore")
        try:
            shutil.move(str(db), str(bak))
            print(f"已把现有库挪到 {bak}")
        except Exception as e:  # noqa: BLE001
            print(f"❌ 无法挪走现有库: {e}", file=sys.stderr)
            return 1
    for suffix in ("-wal", "-shm"):
        p = Path(str(db) + suffix)
        if p.exists():
            try:
                p.unlink()
            except Exception:  # noqa: BLE001
                pass
    try:
        shutil.copy2(src, db)
        print(f"✅ 已从 {src} 恢复（启动服务后生效）")
        return 0
    except Exception as e:  # noqa: BLE001
        print(f"❌ 恢复失败: {e}", file=sys.stderr)
        return 1


def cmd_state_reset(args) -> int:
    if not getattr(args, "yes", False):
        print(
            "⚠️ 这会删除全部跨会话前序链（组合攻击检测的历史依据）。\n"
            "   建议先备份：agent-moss state backup /tmp/chains.bak\n"
            "   确认请加 --yes",
            file=sys.stderr,
        )
        return 1
    port = _port_of(args)
    if port > 0 and _service_running(port):
        return _fail_running(port)
    db = _db_path()
    removed = []
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(db) + suffix)
        if p.exists():
            try:
                p.unlink()
                removed.append(p.name)
            except Exception as e:  # noqa: BLE001
                print(f"❌ 删除 {p} 失败: {e}", file=sys.stderr)
                return 1
    print(f"✅ 已清空: {', '.join(removed) or '(无文件)'}（下次启动重建）")
    return 0


def cmd_state(args) -> int:
    sub = getattr(args, "state_command", None)
    if sub == "status":
        return cmd_state_status(args)
    if sub == "backup":
        return cmd_state_backup(args)
    if sub == "restore":
        return cmd_state_restore(args)
    if sub == "reset":
        return cmd_state_reset(args)
    print("state 子命令：status / backup <file> / restore <file> / reset --yes")
    return 1
