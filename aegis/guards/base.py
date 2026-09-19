"""Guard contract.

A Guard is a pure-ish predicate over (grant, call) -> Verdict. Guards must not
perform side effects. A guard that raises is treated as DENY (fail-closed),
never as allow -- this is deliberate: a crashing guard must not open a door.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from ..decision import Verdict
from ..grant import Grant


@dataclass
class Call:
    """A requested effect, before it happens."""
    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    est_usd: float = 0.0
    est_tokens: int = 0
    meta: dict[str, Any] = field(default_factory=dict)


class Guard(Protocol):
    name: str

    def check(self, grant: Grant, call: Call) -> Verdict: ...


class PostGuard(Protocol):
    """Runs on the *result* of a tool, before the agent sees it."""
    name: str

    def inspect(self, grant: Grant, call: Call, result: Any) -> Verdict: ...
