"""Test doubles.

Every tool is replaced by a recorder. That lets a conformance case assert the
strong form of a denial: not "the call returned an error" but "the
implementation was never entered". `SideEffectRecorder.calls` is the ground
truth the runner checks against.
"""
from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass, field
from typing import Any

from aegis.decision import Classification, Effect
from aegis.policy import Policy
from aegis.registry import ToolRegistry


@dataclass
class SideEffectRecorder:
    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    def reset(self) -> None:
        self.calls.clear()

    def count(self, tool: str) -> int:
        return sum(1 for t, _ in self.calls if t == tool)


# Canonical fixture responses, including deliberately sensitive payloads so
# egress rules get exercised end to end.
_RESPONSES: dict[str, Any] = {
    "kb.search": ["doc-1", "doc-2"],
    "fs.read": "workspace file contents",
    "fs.write": {"written": True},
    "http.get": {"status": 200, "body": "ok"},
    "http.post": {"status": 202},
    "db.query": [{"id": 1, "email": "asha.rao@example.com",
                  "phone": "+91 98765 43210"}],
}

_CLASSIFICATION: dict[str, Classification] = {
    "kb.search": Classification.INTERNAL,
    "fs.read": Classification.INTERNAL,
    "fs.write": Classification.PUBLIC,
    "http.get": Classification.PUBLIC,
    "http.post": Classification.PUBLIC,
    "db.query": Classification.CONFIDENTIAL,
}

_EFFECTS: dict[str, set[Effect]] = {
    "kb.search": {Effect.READ},
    "fs.read": {Effect.READ},
    "fs.write": {Effect.WRITE, Effect.EGRESS},
    "http.get": {Effect.NETWORK, Effect.EGRESS},
    "http.post": {Effect.NETWORK, Effect.EGRESS},
    "db.query": {Effect.READ},
}

_COST: dict[str, float] = {"db.query": 0.02, "http.post": 0.01}


def build_fixture_registry(policy: Policy,
                           recorder: SideEffectRecorder | None = None,
                           extra_tools: dict[str, Any] | None = None,
                           *, async_rng: random.Random | None = None
                           ) -> tuple[ToolRegistry, SideEffectRecorder]:
    """Register a recorder for every tool the policy mentions, plus a set of
    off-policy tools so 'not granted' paths are testable.

    With `async_rng`, each tool is randomly registered either as a coroutine
    that yields to the loop a random number of times (so concurrent calls
    interleave) or as a plain function (so `ainvoke` takes the thread path).
    """
    rec = recorder or SideEffectRecorder()
    reg = ToolRegistry()

    known = set(_RESPONSES) | set(policy.tool_names) | set(extra_tools or {})
    # Off-policy tools that must always be refused.
    known |= {"shell.exec", "email.send", "payments.transfer", "iam.grant"}
    known.discard("agent.spawn")     # handled by the kernel, not the registry

    for name in sorted(known):
        reg.register(
            name,
            (_make_async(name, rec, (extra_tools or {}).get(name), async_rng)
             if async_rng is not None and async_rng.random() < 0.7
             else _make(name, rec, (extra_tools or {}).get(name))),
            effects=_EFFECTS.get(name, {Effect.COMPUTE}),
            classification=_CLASSIFICATION.get(name, Classification.PUBLIC),
            cost_usd=_COST.get(name, 0.001),
            description=f"fixture double for {name}",
        )
    return reg, rec


def _make(name: str, rec: SideEffectRecorder, override: Any):
    def _fn(**kwargs):
        rec.calls.append((name, dict(kwargs)))
        if callable(override):
            return override(**kwargs)
        if override is not None:
            return override
        return _RESPONSES.get(name, {"ok": True, "tool": name})
    _fn.__name__ = name.replace(".", "_")
    return _fn


def _make_async(name: str, rec: SideEffectRecorder, override: Any,
                rng: random.Random):
    sync = _make(name, rec, override)
    yields = rng.randint(0, 4)

    async def _afn(**kwargs):
        for _ in range(yields):
            await asyncio.sleep(0)
        return sync(**kwargs)
    _afn.__name__ = sync.__name__
    return _afn
