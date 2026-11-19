"""AgentMoss - Multi-layer security analysis engine for AI agents."""

from .__version__ import __version__  # noqa: F401 — single source of truth

def shutdown_acceleration():
    """Stop this process's shared acceleration monitors (at most five seconds).

    Call when the SDK host shuts down, after draining requests. Existing scans
    retain their packages; a later accelerated scan starts monitoring again.
    This does not disable rules or change AGENT_MOSS_ACCEL.
    """
    try:
        from .engine.prefilter_reload import stop_managers
    except ImportError:
        return
    stop_managers()
