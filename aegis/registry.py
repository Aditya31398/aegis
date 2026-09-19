"""Tool registry.

The registry owns the real callables. Agents never receive them -- they get a
`ToolProxy` (see runtime.py) that can only reach an implementation by going
through the kernel. That indirection is the enforcement point: there is no
code path from agent to effect that skips the guard chain.
"""
from __future__ import annotations

import inspect
from dataclasses import dataclass
from typing import Any, Callable

from .decision import Classification, Effect


@dataclass(frozen=True)
class ToolSpec:
    name: str
    fn: Callable[..., Any]
    effects: frozenset[Effect]
    classification: Classification = Classification.PUBLIC
    cost_usd: float = 0.0
    description: str = ""
    is_async: bool = False


def _is_coroutine_callable(fn: Callable[..., Any]) -> bool:
    return (inspect.iscoroutinefunction(fn)
            or inspect.iscoroutinefunction(getattr(fn, "__call__", None)))


class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, ToolSpec] = {}

    def register(self, name: str, fn: Callable[..., Any], *,
                 effects: set[Effect] | set[str] = frozenset(),
                 classification: Any = Classification.PUBLIC,
                 cost_usd: float = 0.0, description: str = "") -> None:
        if name in self._tools:
            raise ValueError(f"tool '{name}' already registered")
        self._tools[name] = ToolSpec(
            name=name, fn=fn,
            effects=frozenset(Effect(e) for e in effects),
            classification=Classification.parse(classification),
            cost_usd=cost_usd, description=description,
            is_async=_is_coroutine_callable(fn),
        )

    def tool(self, name: str, **kw):
        def deco(fn):
            self.register(name, fn, **kw)
            return fn
        return deco

    def spec(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def names(self) -> frozenset[str]:
        return frozenset(self._tools)

    def describe(self, names: frozenset[str]) -> list[dict[str, str]]:
        """Safe, agent-visible manifest: names and docs only, no callables."""
        return [
            {"name": s.name, "description": s.description,
             "effects": sorted(e.value for e in s.effects)}
            for n, s in sorted(self._tools.items()) if n in names
        ]
