"""Observability hooks: correlate decisions with traces and stream them out.

Two extension points, neither of which can influence a verdict:

* **Context providers** add correlation ids (trace id, run id, workflow, ...) to
  every audit record, under ``details["ctx"]``. An observability tool registers
  one so a denial can be attached to the task it happened in. Records are
  unchanged when no provider is registered.
* **Subscribers** (``AuditLog.subscribe``) receive each record after it has been
  appended and hash-chained. They run after the decision is final, and an
  exception in a subscriber is contained, never propagated into the kernel.

Providers are consulted inside ``AuditLog.append`` -- after the guard chain has
decided -- so a misbehaving provider can at worst omit correlation data.
"""
from __future__ import annotations

import threading
import warnings
from typing import Any, Callable

ContextProvider = Callable[[], "dict[str, Any] | None"]

_providers: list[ContextProvider] = []
_lock = threading.Lock()
_warned: set[str] = set()


def _warn_once(key: str, msg: str) -> None:
    if key not in _warned:
        _warned.add(key)
        warnings.warn(msg, RuntimeWarning, stacklevel=3)


def register_context_provider(fn: ContextProvider) -> Callable[[], None]:
    """Add a provider; returns a function that removes it again."""
    with _lock:
        _providers.append(fn)

    def unregister() -> None:
        with _lock:
            if fn in _providers:
                _providers.remove(fn)
    return unregister


def current_context() -> dict[str, Any]:
    """Merged correlation context from all providers (later providers win).

    Only JSON-scalar values are kept so the audit hash stays deterministic.
    """
    with _lock:
        providers = list(_providers)
    out: dict[str, Any] = {}
    for fn in providers:
        try:
            ctx = fn() or {}
        except Exception as exc:  # a provider must never break auditing
            _warn_once(f"provider:{id(fn)}", f"aegis context provider failed: {exc!r}")
            continue
        for k, v in ctx.items():
            if v is not None and isinstance(v, (str, int, float, bool)):
                out[str(k)] = v
    return out


def enable_opentelemetry() -> Callable[[], None]:
    """Attach the active OpenTelemetry trace/span id to every record.

    Optional: does nothing (and returns a no-op) if opentelemetry is not installed.
    """
    try:
        from opentelemetry import trace
    except ImportError:
        return lambda: None

    def provider() -> dict[str, Any] | None:
        sc = trace.get_current_span().get_span_context()
        if not sc.is_valid:
            return None
        return {"trace_id": format(sc.trace_id, "032x"), "span_id": format(sc.span_id, "016x")}
    return register_context_provider(provider)
