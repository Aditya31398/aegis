"""Agent runtime.

An Agent holds a Grant and a Kernel -- nothing else that can cause an effect.
`agent.tools.http_get(...)` resolves to a ToolProxy which calls
`kernel.invoke(grant, ...)`; `await agent.atools.http_get(...)` resolves to an
AsyncToolProxy which awaits `kernel.ainvoke(grant, ...)`. There is no attribute
on Agent that exposes a registered implementation.
"""
from __future__ import annotations

from typing import Any, Callable, Iterable

from .decision import PolicyViolation
from .grant import Grant, SpawnRequest
from .kernel import Kernel


class ToolProxy:
    """Callable stand-in bound to (kernel, grant, tool_name)."""

    __slots__ = ("_kernel", "_grant", "_name")

    def __init__(self, kernel: Kernel, grant: Grant, name: str):
        object.__setattr__(self, "_kernel", kernel)
        object.__setattr__(self, "_grant", grant)
        object.__setattr__(self, "_name", name)

    def __call__(self, **kwargs) -> Any:
        return self._kernel.invoke(self._grant, self._name, **kwargs)

    def __repr__(self) -> str:
        return f"<ToolProxy {self._name} grant={self._grant.grant_id}>"


class AsyncToolProxy(ToolProxy):
    """Awaitable stand-in. Same binding, routed through `Kernel.ainvoke`."""

    __slots__ = ()

    async def __call__(self, **kwargs) -> Any:
        return await self._kernel.ainvoke(self._grant, self._name, **kwargs)

    def __repr__(self) -> str:
        return f"<AsyncToolProxy {self._name} grant={self._grant.grant_id}>"


class Toolbox:
    """Attribute access over the tools a grant actually holds."""

    _proxy: type[ToolProxy] = ToolProxy

    def __init__(self, kernel: Kernel, grant: Grant):
        self._kernel, self._grant = kernel, grant

    def __getattr__(self, item: str) -> ToolProxy:
        if item.startswith("_"):
            raise AttributeError(item)
        return self._proxy(self._kernel, self._grant, item.replace("__", "."))

    def __getitem__(self, name: str) -> ToolProxy:
        return self._proxy(self._kernel, self._grant, name)

    def manifest(self) -> list[dict[str, str]]:
        """What you put in the agent's system prompt. Advisory only --
        the kernel is what actually enforces it."""
        return self._kernel.registry.describe(self._grant.policy.tool_names)


class AsyncToolbox(Toolbox):
    _proxy = AsyncToolProxy


class Agent:
    """Base class. Subclass and implement `run`."""

    def __init__(self, grant: Grant, kernel: Kernel):
        self.grant = grant
        self.kernel = kernel
        self.tools = Toolbox(kernel, grant)
        self.atools = AsyncToolbox(kernel, grant)

    @property
    def name(self) -> str:
        return self.grant.agent_name

    def spawn(self, name: str, tools: Iterable[str], *,
              budget_fraction: float = 0.5, role: str = "worker",
              cls: type["Agent"] | None = None) -> "Agent":
        req = SpawnRequest(name=name, tools=frozenset(tools),
                           budget_fraction=budget_fraction, role=role)
        child_grant = self.kernel.spawn(self.grant, req)
        return (cls or Agent)(child_grant, self.kernel)

    async def aspawn(self, name: str, tools: Iterable[str], *,
                     budget_fraction: float = 0.5, role: str = "worker",
                     cls: type["Agent"] | None = None) -> "Agent":
        req = SpawnRequest(name=name, tools=frozenset(tools),
                           budget_fraction=budget_fraction, role=role)
        child_grant = await self.kernel.aspawn(self.grant, req)
        return (cls or Agent)(child_grant, self.kernel)

    def run(self, *a, **kw) -> Any:                     # pragma: no cover
        raise NotImplementedError

    def __repr__(self) -> str:
        return (f"<Agent {self.name} depth={self.grant.depth} "
                f"tools={sorted(self.grant.policy.tool_names)}>")
