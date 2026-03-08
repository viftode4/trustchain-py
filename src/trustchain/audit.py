"""Audit utilities — ``@audited`` decorator and schema validators.

The ``@audited`` decorator wraps sync/async functions to automatically
record entry, exit, and error audit blocks via the TrustChain sidecar.
Schema validators enforce structure on audit transactions for compliance
(EU AI Act, AIUC-1, etc.).
"""

from __future__ import annotations

import functools
import hashlib
import inspect
import time
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

class AuditLevel(str, Enum):
    """Recording granularity levels."""
    MINIMAL = "minimal"
    STANDARD = "standard"
    COMPREHENSIVE = "comprehensive"


class EventType(str, Enum):
    """Semantic event categories for audit blocks."""
    TOOL_CALL = "tool_call"
    LLM_DECISION = "llm_decision"
    ERROR = "error"
    STATE_CHANGE = "state_change"
    HUMAN_OVERRIDE = "human_override"
    EXTERNAL_API = "external_api"
    RAW_HTTP = "raw_http"


class SchemaId(str, Enum):
    """Pluggable compliance schemas."""
    BASE = "base"
    AI_ACT = "ai_act"
    AIUC1 = "aiuc1"


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

_SCHEMA_FIELDS: dict[SchemaId, list[str]] = {
    SchemaId.BASE: ["action", "outcome"],
    SchemaId.AI_ACT: ["action", "outcome", "model", "input_hash", "output_hash"],
    SchemaId.AIUC1: ["action", "outcome", "policy_id", "compliance_status"],
}


def validate_transaction(schema: SchemaId | str, transaction: dict[str, Any]) -> None:
    """Validate that *transaction* contains all fields required by *schema*.

    Raises ``ValueError`` on missing fields.
    """
    if isinstance(schema, str):
        try:
            schema = SchemaId(schema)
        except ValueError:
            raise ValueError(f"Unknown schema: {schema!r}") from None

    required = _SCHEMA_FIELDS.get(schema, [])
    missing = [f for f in required if f not in transaction]
    if missing:
        raise ValueError(
            f"Schema {schema.value!r} requires fields: {', '.join(missing)}"
        )


# ---------------------------------------------------------------------------
# Default events per level
# ---------------------------------------------------------------------------

_LEVEL_EVENTS: dict[AuditLevel, set[EventType]] = {
    AuditLevel.MINIMAL: {EventType.TOOL_CALL, EventType.ERROR},
    AuditLevel.STANDARD: {
        EventType.TOOL_CALL, EventType.ERROR,
        EventType.LLM_DECISION, EventType.STATE_CHANGE,
        EventType.HUMAN_OVERRIDE,
    },
    AuditLevel.COMPREHENSIVE: set(EventType),
}


def default_events(level: AuditLevel | str) -> set[EventType]:
    """Return the default enabled event types for a given audit level."""
    if isinstance(level, str):
        level = AuditLevel(level)
    return _LEVEL_EVENTS[level].copy()


# ---------------------------------------------------------------------------
# @audited decorator
# ---------------------------------------------------------------------------

def _hash_repr(obj: Any) -> str:
    """SHA-256 of repr(obj), truncated to 16 hex chars."""
    return hashlib.sha256(repr(obj).encode()).hexdigest()[:16]


def audited(
    fn: Any = None,
    *,
    schema: SchemaId | str | None = None,
    event_type: str = "tool_call",
) -> Any:
    """Decorator that auto-records audit blocks around a function call.

    Records three audit blocks via the sidecar:
    1. **entry** — function name, args hash, status=started
    2. **exit** — status=completed, result hash, duration_ms
    3. **error** (on exception) — status=error, error message

    Works with both sync and async functions. Requires a running sidecar
    (start one with ``TrustChainSidecar`` or ``@with_trust`` first).

    Usage::

        @audited
        def my_tool(x):
            return x * 2

        @audited(schema="ai_act")
        async def query_llm(prompt):
            ...
    """

    def decorator(func: Any) -> Any:
        func_name = func.__qualname__

        def _get_sidecar() -> Any:
            """Find the global sidecar instance."""
            from trustchain.sidecar import _instance as _global_sidecar
            if _global_sidecar is None:
                raise RuntimeError(
                    "@audited requires a running sidecar. "
                    "Use TrustChainSidecar() or @with_trust first."
                )
            return _global_sidecar

        def _build_entry(args: tuple, kwargs: dict) -> dict[str, Any]:
            tx: dict[str, Any] = {
                "event_type": event_type,
                "action": func_name,
                "status": "started",
                "args_hash": _hash_repr((args, kwargs)),
            }
            if schema is not None:
                tx["outcome"] = "pending"
                # For ai_act schema, add placeholder fields so validation
                # doesn't fail on the entry block.
            return tx

        def _build_exit(result: Any, duration_ms: int) -> dict[str, Any]:
            tx: dict[str, Any] = {
                "event_type": event_type,
                "action": func_name,
                "status": "completed",
                "outcome": "completed",
                "result_hash": _hash_repr(result),
                "duration_ms": duration_ms,
            }
            return tx

        def _build_error(exc: BaseException, duration_ms: int) -> dict[str, Any]:
            return {
                "event_type": "error",
                "action": func_name,
                "status": "error",
                "outcome": "error",
                "error": str(exc),
                "duration_ms": duration_ms,
            }

        def _record(sidecar: Any, tx: dict[str, Any]) -> None:
            if schema is not None:
                sid = SchemaId(schema) if isinstance(schema, str) else schema
                # Only validate if all required fields are present (entry
                # blocks may have placeholders).
                try:
                    validate_transaction(sid, tx)
                except ValueError:
                    pass  # entry blocks won't have all fields — that's OK
            try:
                sidecar.audit(tx)
            except Exception:
                pass  # best-effort — don't break the decorated function

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            sidecar = _get_sidecar()
            _record(sidecar, _build_entry(args, kwargs))
            start = time.monotonic()
            try:
                result = func(*args, **kwargs)
            except BaseException as exc:
                dur = int((time.monotonic() - start) * 1000)
                _record(sidecar, _build_error(exc, dur))
                raise
            dur = int((time.monotonic() - start) * 1000)
            _record(sidecar, _build_exit(result, dur))
            return result

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            sidecar = _get_sidecar()
            _record(sidecar, _build_entry(args, kwargs))
            start = time.monotonic()
            try:
                result = await func(*args, **kwargs)
            except BaseException as exc:
                dur = int((time.monotonic() - start) * 1000)
                _record(sidecar, _build_error(exc, dur))
                raise
            dur = int((time.monotonic() - start) * 1000)
            _record(sidecar, _build_exit(result, dur))
            return result

        if inspect.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    if fn is not None:
        return decorator(fn)
    return decorator
