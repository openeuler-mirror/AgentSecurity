"""Bounded debug records for script analysis via POST /api/v1/analyze.

Records are written below the data root to diagnostics/script-analysis.jsonl.
"""

import asyncio
import hashlib
import json
import os
import shutil
import stat
import threading
import time
import uuid
from concurrent.futures import Future
from dataclasses import dataclass, field
from pathlib import Path
from queue import SimpleQueue

from .paths import get_data_root
from .security_policy import ensure_private_dir

_MIN_INTERVAL_SECONDS = 0.25
_WRITE_WAIT_SECONDS = 0.05
_MAX_EVENT_BYTES = 8 * 1024
_MAX_FILE_BYTES = 1024 * 1024
_MIN_FREE_BYTES = 64 * 1024 * 1024
_rate_lock = threading.Lock()
_writer_slot = threading.Lock()
_writer_start_lock = threading.Lock()
_writes: SimpleQueue[tuple["ScriptDiagnostics", str, Future[bool]]] = SimpleQueue()
_writer_started = False
_next_capture = 0.0
_next_write = 0.0


def start_script_diagnostics_writer() -> bool:
    """Start one daemon writer per process before accepting diagnostic requests."""
    global _writer_started
    with _writer_start_lock:
        if not _writer_started:
            try:
                threading.Thread(
                    target=_run_writer, name="script-diagnostics-writer", daemon=True,
                ).start()
            except RuntimeError:
                return False
            _writer_started = True
        return True


def _run_writer() -> None:
    while True:
        diagnostics, decision, completion = _writes.get()
        try:
            if completion.set_running_or_notify_cancel():
                try:
                    written = diagnostics.write(decision)
                except Exception:
                    written = False
                completion.set_result(written)
        finally:
            # Keep the slot through the actual write even if the caller timed out.
            _writer_slot.release()
            del diagnostics, decision, completion


@dataclass
class ScriptDiagnostics:
    session_id: str
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    data: dict = field(default_factory=dict)

    def begin(self) -> dict | None:
        """Reserve collection before the parser does any diagnostic work."""
        global _next_capture
        if _writer_slot.locked():
            return None
        with _rate_lock:
            now = time.monotonic()
            if now < _next_capture:
                return None
            _next_capture = now + _MIN_INTERVAL_SECONDS
        return self.data

    async def write_with_timeout(self, decision: str) -> bool:
        """Wait briefly for a best-effort write outside the analysis thread pool."""
        if not self.data or not _writer_started or not _writer_slot.acquire(blocking=False):
            return False

        # The slot covers both pending and running work, so blocked I/O cannot build a backlog.
        try:
            completion: Future[bool] = Future()
            _writes.put_nowait((self, decision, completion))
        except MemoryError:
            _writer_slot.release()
            return False

        try:
            return await asyncio.wait_for(asyncio.wrap_future(completion), _WRITE_WAIT_SECONDS)
        except asyncio.TimeoutError:
            return False

    def write(self, decision: str) -> bool:
        global _next_write
        if not self.data:
            return False
        with _rate_lock:
            now = time.monotonic()
            if now < _next_write:
                return False
            _next_write = now + _MIN_INTERVAL_SECONDS
        event = {
            "event": "script_analysis",
            "request_id": self.request_id,
            "session_id_sha256": hashlib.sha256(self.session_id.encode("utf-8", "surrogatepass")).hexdigest(),
            "timestamp": time.time(),
            "decision": decision,
            **self.data,
        }
        try:
            line = _encode(event)
            if len(line) > _MAX_EVENT_BYTES:
                event.pop("nodes", None)
                event["details_omitted"] = True
                line = _encode(event)
            if len(line) > _MAX_EVENT_BYTES:
                return False

            directory = get_data_root() / "diagnostics"
            if os.name == "nt":
                directory.mkdir(mode=0o700, parents=True, exist_ok=True)
                if directory.is_symlink():
                    return False
            elif not ensure_private_dir(directory):
                return False
            usage = shutil.disk_usage(directory)
            if usage.free < max(_MIN_FREE_BYTES, usage.total // 50):
                return False

            path = directory / "script-analysis.jsonl"
            lock_fd = _open_private(directory / "script-analysis.lock", os.O_RDWR)
            try:
                _lock(lock_fd)
                if _append_line(path, line):
                    return True
                path.replace(path.with_suffix(".jsonl.1"))
                return _append_line(path, line)
            finally:
                os.close(lock_fd)
        except (OSError, TypeError, ValueError):
            # Diagnostic access, capacity and contention must not affect the verdict.
            return False


def _encode(event: dict) -> bytes:
    return (json.dumps(event, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")


def _open_private(path: Path, flags: int) -> int:
    flags |= os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags | getattr(os, "O_BINARY", 0), 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise OSError("diagnostic destination must be a regular private file")
        return fd
    except OSError:
        os.close(fd)
        raise


def _append_line(path: Path, line: bytes) -> bool:
    fd = _open_private(path, os.O_WRONLY | os.O_APPEND)
    try:
        size = os.fstat(fd).st_size
        if size + len(line) > _MAX_FILE_BYTES:
            return False
        if os.write(fd, line) != len(line):
            os.ftruncate(fd, size)
            raise OSError("incomplete diagnostic write")
        return True
    finally:
        os.close(fd)


def _lock(fd: int) -> None:
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
