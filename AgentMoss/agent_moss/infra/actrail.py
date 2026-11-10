"""AcTrail enforcement event reporter.

Writes AgentMoss allow/deny decisions as Enforcement events to AcTrail's
SQLite storage, enabling unified agent behavior audit trails.

Usage:
    from agent_moss.infra.actrail import report_enforcement_event

    report_enforcement_event(
        trace_id="session-001",
        decision="allow",
        tool_name="bash",
        tool_command="cat /var/log/syslog",
        session_id="session-001",
        prompt="read log file",
        risk_level="low",
    )

Configuration (environment variables):
    ACTRAIL_ENABLED: Set to "1" to enable reporting (default: disabled)
    ACTRAIL_STORAGE_PATH: Path to AcTrail SQLite DB (default: /tmp/actrail.sqlite)
    ACTRAIL_TIMEOUT_MS: Write timeout in milliseconds (default: 100)
"""

import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Default AcTrail SQLite path (matches AcTrail operator config default)
DEFAULT_STORAGE_PATH = "/tmp/actrail.sqlite"
DEFAULT_TIMEOUT_MS = 100


def _escape(value: str) -> str:
    """Escape a value for AcTrail's key=value format (mirrors Rust encode_map)."""
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace("=", "\\e")


def _session_to_trace_id(session_id: str) -> int:
    """Convert a session_id string to a u64 trace_id (AcTrail uses u64 TraceId).
    Masks to signed 64-bit range to avoid SQLite INTEGER overflow.
    """
    h = hashlib.sha256(session_id.encode()).digest()
    return int.from_bytes(h[:8], byteorder="big") & 0x7FFFFFFFFFFFFFFF

# Singleton reporter instance (lazy-initialized)
_reporter: Optional["ActRailReporter"] = None
_reporter_lock = threading.Lock()


class ActRailReporter:
    """Writes enforcement events to AcTrail's SQLite storage.

    Uses a dedicated SQLite connection with WAL mode for concurrent access.
    Writes are fire-and-forget with a short timeout to avoid blocking the
    main analysis path.
    """

    def __init__(self, storage_path: str, timeout_ms: int = DEFAULT_TIMEOUT_MS):
        self._storage_path = storage_path
        self._timeout_ms = timeout_ms
        self._conn: Optional[sqlite3.Connection] = None
        self._conn_lock = threading.Lock()

    def _get_connection(self) -> Optional[sqlite3.Connection]:
        """Get or create a SQLite connection to AcTrail storage."""
        if self._conn is not None:
            return self._conn

        try:
            path = Path(self._storage_path)
            if not path.exists():
                logger.debug("AcTrail storage not found: %s", self._storage_path)
                return None

            conn = sqlite3.connect(
                str(path),
                timeout=self._timeout_ms / 1000.0,
                check_same_thread=False,
            )
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=100")

            # Verify the events table exists
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='events'"
            )
            if cursor.fetchone() is None:
                logger.debug("AcTrail events table not found in %s", self._storage_path)
                conn.close()
                return None

            self._conn = conn
            return conn
        except Exception as e:
            logger.debug("Failed to connect to AcTrail storage: %s", e)
            return None

    def report(
        self,
        trace_id: str,
        decision: str,
        tool_name: str = "",
        tool_command: str = "",
        session_id: str = "",
        prompt: str = "",
        risk_level: str = "",
        risk_type: str = "",
        reason: str = "",
        violated_layers: Optional[list[str]] = None,
        confidence: int = 100,
        duration_ms: float = 0.0,
    ) -> bool:
        """Write an enforcement event to AcTrail storage.

        Args:
            trace_id: Trace identifier (typically session_id)
            decision: "allow" or "deny"
            tool_name: Agent tool name (e.g., "bash", "file_write")
            tool_command: The actual command or action detail
            session_id: Agent session identifier
            prompt: Original user prompt (truncated to 500 chars)
            risk_level: Risk level from analysis
            risk_type: Risk type from analysis
            reason: Decision reason
            violated_layers: Detection layers that triggered (e.g., ["L1.1"], ["L2.1", "L3.1"])
            confidence: Confidence score 0-100
            duration_ms: Analysis duration in milliseconds

        Returns:
            True if event was written successfully, False otherwise
        """
        conn = self._get_connection()
        if conn is None:
            return False

        now_ns = int(time.time() * 1_000_000_000)

        # Build payload fields matching AcTrail's EnforcementPayload
        # AcTrail uses key=value\n format (not JSON) with escape encoding
        raw_fields = {
            "backend": "agent-moss",
            "operation": "tool_call",
            "decision": decision,
            "result": "allowed" if decision == "allow" else "denied",
            "tool.name": tool_name,
            "tool.command": tool_command[:500] if tool_command else "",
            "agent.session_id": session_id,
            "agent.prompt": (prompt or "")[:500],
            "risk.level": risk_level,
            "risk.type": risk_type,
            "reason": (reason or "")[:500],
            "violated_layers": ",".join(violated_layers or []),
            "confidence": str(confidence),
            "duration_ms": f"{duration_ms:.1f}",
        }
        # AcTrail encode_map format: key=value\n with \\, \\n, \\e escaping
        payload_fields_str = "\n".join(
            f"{_escape(k)}={_escape(v)}" for k, v in raw_fields.items()
        )

        # Generate a unique event ID from timestamp
        event_id = (now_ns % (2**62))  # Fit in INTEGER PRIMARY KEY

        # Convert session_id to u64 trace_id (AcTrail TraceId is u64)
        trace_id_int = _session_to_trace_id(trace_id)

        try:
            with self._conn_lock:
                conn.execute(
                    """INSERT OR REPLACE INTO events (
                        event_id, trace_id, observed_at,
                        process_pid, process_task_id, process_start_ticks,
                        process_pid_namespace, process_generation,
                        collector, kind,
                        bootstrap_observed, metadata_partial, policy_modified,
                        payload_variant, payload_fields, payload_bytes,
                        policy_verdict, policy_note,
                        policy_redactions, policy_truncations
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        event_id,
                        trace_id_int,           # trace_id (u64, hashed from session_id)
                        now_ns,
                        os.getpid(),           # process_pid
                        0,                      # process_task_id
                        0,                      # process_start_ticks
                        None,                   # process_pid_namespace
                        0,                      # process_generation
                        "agent-moss",           # collector
                        "enforcement",          # kind (lowercase, matches EventKind::Enforcement)
                        0,                      # bootstrap_observed
                        0,                      # metadata_partial
                        0,                      # policy_modified
                        "enforcement",          # payload_variant (lowercase)
                        payload_fields_str,     # payload_fields (key=value format)
                        "",                     # payload_bytes
                        "allow" if decision == "allow" else "drop",  # policy_verdict (PolicyVerdict enum)
                        reason or "",           # policy_note
                        "[]",                   # policy_redactions
                        "[]",                   # policy_truncations
                    ),
                )
                conn.commit()
            return True
        except sqlite3.OperationalError as e:
            # Database locked or other operational error — non-fatal
            logger.debug("AcTrail write failed (non-fatal): %s", e)
            return False
        except Exception as e:
            logger.debug("AcTrail write error (non-fatal): %s", e)
            return False

    def close(self) -> None:
        """Close the SQLite connection."""
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None


def _get_reporter() -> Optional[ActRailReporter]:
    """Get or create the singleton reporter instance."""
    global _reporter

    if _reporter is not None:
        return _reporter

    enabled = os.environ.get("ACTRAIL_ENABLED", "").strip()
    if enabled not in ("1", "true", "yes"):
        return None

    storage_path = os.environ.get("ACTRAIL_STORAGE_PATH", DEFAULT_STORAGE_PATH)
    timeout_ms = int(os.environ.get("ACTRAIL_TIMEOUT_MS", str(DEFAULT_TIMEOUT_MS)))

    with _reporter_lock:
        if _reporter is None:
            _reporter = ActRailReporter(storage_path, timeout_ms)
            logger.info("AcTrail reporter initialized: path=%s", storage_path)
        return _reporter


def report_enforcement_event(
    trace_id: str,
    decision: str,
    tool_name: str = "",
    tool_command: str = "",
    session_id: str = "",
    prompt: str = "",
    risk_level: str = "",
    risk_type: str = "",
    reason: str = "",
    violated_layers: Optional[list[str]] = None,
    confidence: int = 100,
    duration_ms: float = 0.0,
) -> bool:
    """Report an enforcement event to AcTrail (fire-and-forget).

    Returns True if written, False if disabled or write failed.
    Non-blocking: failures are logged at debug level and never raised.
    """
    reporter = _get_reporter()
    if reporter is None:
        return False

    return reporter.report(
        trace_id=trace_id,
        decision=decision,
        tool_name=tool_name,
        tool_command=tool_command,
        session_id=session_id,
        prompt=prompt,
        risk_level=risk_level,
        risk_type=risk_type,
        reason=reason,
        violated_layers=violated_layers,
        confidence=confidence,
        duration_ms=duration_ms,
    )
